package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/gammazero/workerpool"
	lru "github.com/hashicorp/golang-lru/v2"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	lockv1 "github.com/pocketsizefund/microservice-vault/gen/go/lock/v1"
	"github.com/pocketsizefund/microservice-vault/pkg/crypto/fpe"
	"github.com/pocketsizefund/microservice-vault/services/tokenize/internal/config"
)

var (
	ErrKeyNotFound            = errors.New("key not found")
	ErrTransformationNotFound = errors.New("transformation not found")
	ErrInvalidInput           = errors.New("invalid input")
	ErrEncryptionFailed       = errors.New("FPE encryption failed")
	ErrDecryptionFailed       = errors.New("FPE decryption failed")
	ErrLockServiceRequired    = errors.New("lock service connection required")
)

// KeyInfo holds cached key information
type KeyInfo struct {
	Key     []byte
	Version int
}

// FPEResult holds FPE operation result
type FPEResult struct {
	Value      string
	KeyVersion int
	Reference  string
	Error      error
}

// TokenizeService handles tokenization and FPE operations
type TokenizeService struct {
	config     *config.Config
	logger     *zap.Logger
	workerPool *workerpool.WorkerPool

	// Key cache: LRU cache like HashiCorp Vault's LockManager
	keyCache *lru.Cache[string, *KeyInfo]

	// No cipher cache - create cipher per request like Vault

	// Lock service client for key retrieval (required)
	lockConn   *grpc.ClientConn
	lockClient lockv1.LockServiceClient

	// Custom transformations
	customTransformations sync.Map
}

// NewTokenizeService creates a new tokenize service
func NewTokenizeService(cfg *config.Config, logger *zap.Logger) (*TokenizeService, error) {
	wp := workerpool.New(cfg.WorkerPool.Size)

	// Create LRU cache for keys (like Vault's LockManager)
	keyCache, err := lru.New[string, *KeyInfo](10000)
	if err != nil {
		return nil, fmt.Errorf("failed to create key cache: %w", err)
	}

	svc := &TokenizeService{
		config:     cfg,
		logger:     logger,
		workerPool: wp,
		keyCache:   keyCache,
	}

	// Connect to Lock service (required)
	if cfg.LockService.Address == "" {
		return nil, fmt.Errorf("lock service address is required")
	}

	conn, err := grpc.NewClient(
		cfg.LockService.Address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Lock service: %w", err)
	}

	svc.lockConn = conn
	svc.lockClient = lockv1.NewLockServiceClient(conn)
	logger.Info("Connected to Lock service", zap.String("address", cfg.LockService.Address))

	return svc, nil
}

// Close shuts down the service
func (s *TokenizeService) Close() {
	s.workerPool.StopWait()
	if s.lockConn != nil {
		s.lockConn.Close()
	}
}


// getKey retrieves a key from cache or Lock Service
// Uses LRU cache like HashiCorp Vault's LockManager
func (s *TokenizeService) getKey(ctx context.Context, keyName string) (*KeyInfo, error) {
	// Check cache first - fast path (like Vault's LockManager)
	if cached, ok := s.keyCache.Get(keyName); ok {
		return cached, nil
	}

	// Slow path: get key from Lock service
	if s.lockClient == nil {
		return nil, ErrLockServiceRequired
	}

	resp, err := s.lockClient.GetEncryptionKey(ctx, &lockv1.GetEncryptionKeyRequest{
		Name:    keyName,
		Version: 0, // 0 = latest version
	})
	if err != nil {
		s.logger.Error("Failed to get key from Lock service",
			zap.String("key", keyName),
			zap.Error(err))
		return nil, ErrKeyNotFound
	}

	keyInfo := &KeyInfo{
		Key:     resp.Key,
		Version: int(resp.Version),
	}
	// Store in LRU cache (like Vault)
	s.keyCache.Add(keyName, keyInfo)
	return keyInfo, nil
}

// InvalidateKey removes a key from cache (called on key rotation/deletion)
func (s *TokenizeService) InvalidateKey(keyName string) {
	s.keyCache.Remove(keyName)
}

// newCipher creates a new FPE cipher (like Vault - no caching)
func (s *TokenizeService) newCipher(keyInfo *KeyInfo, alphabet string) (*fpe.Cipher, error) {
	return fpe.NewCipher(keyInfo.Key, alphabet)
}

// getAlphabet gets alphabet for transformation or custom
func (s *TokenizeService) getAlphabet(transformation, customAlphabet string) (string, error) {
	if customAlphabet != "" {
		return customAlphabet, nil
	}

	if transformation != "" {
		// Check built-in transformations
		if trans, ok := fpe.GetTransformation(transformation); ok {
			return trans.Alphabet, nil
		}

		// Check custom transformations
		if trans, ok := s.customTransformations.Load(transformation); ok {
			return trans.(*Transformation).Alphabet, nil
		}

		return "", ErrTransformationNotFound
	}

	return fpe.AlphabetNumeric, nil
}

// FPEEncrypt encrypts using Format-Preserving Encryption
func (s *TokenizeService) FPEEncrypt(ctx context.Context, keyName, plaintext, transformation, customAlphabet string, tweak []byte) (string, int, error) {
	keyInfo, err := s.getKey(ctx, keyName)
	if err != nil {
		return "", 0, err
	}

	alphabet, err := s.getAlphabet(transformation, customAlphabet)
	if err != nil {
		return "", 0, err
	}

	// Create cipher per request (like Vault)
	cipher, err := s.newCipher(keyInfo, alphabet)
	if err != nil {
		return "", 0, err
	}

	var ciphertext string
	if tweak != nil {
		ciphertext, err = cipher.EncryptWithTweak(plaintext, tweak)
	} else {
		ciphertext, err = cipher.Encrypt(plaintext)
	}

	if err != nil {
		s.logger.Error("FPE encryption failed", zap.Error(err))
		return "", 0, ErrEncryptionFailed
	}

	return ciphertext, keyInfo.Version, nil
}

// FPEDecrypt decrypts using Format-Preserving Encryption
func (s *TokenizeService) FPEDecrypt(ctx context.Context, keyName, ciphertext, transformation, customAlphabet string, tweak []byte) (string, int, error) {
	keyInfo, err := s.getKey(ctx, keyName)
	if err != nil {
		return "", 0, err
	}

	alphabet, err := s.getAlphabet(transformation, customAlphabet)
	if err != nil {
		return "", 0, err
	}

	// Create cipher per request (like Vault)
	cipher, err := s.newCipher(keyInfo, alphabet)
	if err != nil {
		return "", 0, err
	}

	var plaintext string
	if tweak != nil {
		plaintext, err = cipher.DecryptWithTweak(ciphertext, tweak)
	} else {
		plaintext, err = cipher.Decrypt(ciphertext)
	}

	if err != nil {
		s.logger.Error("FPE decryption failed", zap.Error(err))
		return "", 0, ErrDecryptionFailed
	}

	return plaintext, keyInfo.Version, nil
}

// FPEEncryptBatch encrypts multiple values using worker pool
func (s *TokenizeService) FPEEncryptBatch(ctx context.Context, keyName, transformation, customAlphabet string, items []FPEBatchItem) []FPEResult {
	results := make([]FPEResult, len(items))
	var wg sync.WaitGroup

	keyInfo, err := s.getKey(ctx, keyName)
	if err != nil {
		for i := range results {
			results[i] = FPEResult{Reference: items[i].Reference, Error: err}
		}
		return results
	}

	alphabet, err := s.getAlphabet(transformation, customAlphabet)
	if err != nil {
		for i := range results {
			results[i] = FPEResult{Reference: items[i].Reference, Error: err}
		}
		return results
	}

	for i, item := range items {
		wg.Add(1)
		idx := i
		itm := item

		s.workerPool.Submit(func() {
			defer wg.Done()

			// Create cipher per request (like Vault)
			cipher, cipherErr := s.newCipher(keyInfo, alphabet)
			if cipherErr != nil {
				results[idx] = FPEResult{Reference: itm.Reference, Error: cipherErr}
				return
			}

			var ciphertext string
			var encErr error

			if itm.Tweak != nil {
				ciphertext, encErr = cipher.EncryptWithTweak(itm.Value, itm.Tweak)
			} else {
				ciphertext, encErr = cipher.Encrypt(itm.Value)
			}

			results[idx] = FPEResult{
				Value:      ciphertext,
				KeyVersion: keyInfo.Version,
				Reference:  itm.Reference,
				Error:      encErr,
			}
		})
	}

	wg.Wait()
	return results
}

// FPEDecryptBatch decrypts multiple values using worker pool
func (s *TokenizeService) FPEDecryptBatch(ctx context.Context, keyName, transformation, customAlphabet string, items []FPEBatchItem) []FPEResult {
	results := make([]FPEResult, len(items))
	var wg sync.WaitGroup

	keyInfo, err := s.getKey(ctx, keyName)
	if err != nil {
		for i := range results {
			results[i] = FPEResult{Reference: items[i].Reference, Error: err}
		}
		return results
	}

	alphabet, err := s.getAlphabet(transformation, customAlphabet)
	if err != nil {
		for i := range results {
			results[i] = FPEResult{Reference: items[i].Reference, Error: err}
		}
		return results
	}

	for i, item := range items {
		wg.Add(1)
		idx := i
		itm := item

		s.workerPool.Submit(func() {
			defer wg.Done()

			// Create cipher per request (like Vault)
			cipher, cipherErr := s.newCipher(keyInfo, alphabet)
			if cipherErr != nil {
				results[idx] = FPEResult{Reference: itm.Reference, Error: cipherErr}
				return
			}

			var plaintext string
			var decErr error

			if itm.Tweak != nil {
				plaintext, decErr = cipher.DecryptWithTweak(itm.Value, itm.Tweak)
			} else {
				plaintext, decErr = cipher.Decrypt(itm.Value)
			}

			results[idx] = FPEResult{
				Value:      plaintext,
				KeyVersion: keyInfo.Version,
				Reference:  itm.Reference,
				Error:      decErr,
			}
		})
	}

	wg.Wait()
	return results
}

// Mask masks a value
func (s *TokenizeService) Mask(ctx context.Context, value string, preserveFirst, preserveLast int, maskChar string) (string, error) {
	if len(value) == 0 {
		return "", ErrInvalidInput
	}

	if maskChar == "" {
		maskChar = "*"
	}

	// Calculate positions
	totalPreserve := preserveFirst + preserveLast
	if totalPreserve >= len(value) {
		return value, nil // Nothing to mask
	}

	var result strings.Builder

	// First N characters
	if preserveFirst > 0 {
		result.WriteString(value[:preserveFirst])
	}

	// Masked middle
	maskLen := len(value) - totalPreserve
	for i := 0; i < maskLen; i++ {
		result.WriteString(maskChar)
	}

	// Last N characters
	if preserveLast > 0 {
		result.WriteString(value[len(value)-preserveLast:])
	}

	return result.String(), nil
}

// ListTransformations returns all available transformations
func (s *TokenizeService) ListTransformations(ctx context.Context) []*Transformation {
	var transformations []*Transformation

	// Built-in transformations
	for name, trans := range fpe.BuiltInTransformations {
		transformations = append(transformations, &Transformation{
			Name:        name,
			Alphabet:    trans.Alphabet,
			Pattern:     trans.Pattern,
			Description: trans.Description,
			BuiltIn:     true,
		})
	}

	// Custom transformations
	s.customTransformations.Range(func(key, value interface{}) bool {
		trans := value.(*Transformation)
		transformations = append(transformations, trans)
		return true
	})

	return transformations
}

// CreateTransformation creates a custom transformation
func (s *TokenizeService) CreateTransformation(ctx context.Context, name, alphabet, pattern, description string) (*Transformation, error) {
	if name == "" || alphabet == "" {
		return nil, ErrInvalidInput
	}

	// Check if built-in
	if _, ok := fpe.GetTransformation(name); ok {
		return nil, errors.New("cannot override built-in transformation")
	}

	trans := &Transformation{
		Name:        name,
		Alphabet:    alphabet,
		Pattern:     pattern,
		Description: description,
		BuiltIn:     false,
	}

	s.customTransformations.Store(name, trans)

	return trans, nil
}

// GetTransformation gets a transformation by name
func (s *TokenizeService) GetTransformation(ctx context.Context, name string) (*Transformation, error) {
	// Check built-in
	if trans, ok := fpe.GetTransformation(name); ok {
		return &Transformation{
			Name:        name,
			Alphabet:    trans.Alphabet,
			Pattern:     trans.Pattern,
			Description: trans.Description,
			BuiltIn:     true,
		}, nil
	}

	// Check custom
	if trans, ok := s.customTransformations.Load(name); ok {
		return trans.(*Transformation), nil
	}

	return nil, ErrTransformationNotFound
}

// DeleteTransformation deletes a custom transformation
func (s *TokenizeService) DeleteTransformation(ctx context.Context, name string) error {
	// Can't delete built-in
	if _, ok := fpe.GetTransformation(name); ok {
		return errors.New("cannot delete built-in transformation")
	}

	// Check if exists
	if _, ok := s.customTransformations.Load(name); !ok {
		return ErrTransformationNotFound
	}

	s.customTransformations.Delete(name)
	return nil
}

// Types
type FPEBatchItem struct {
	Value     string
	Tweak     []byte
	Reference string
}

type Transformation struct {
	Name        string
	Alphabet    string
	Pattern     string
	Description string
	BuiltIn     bool
}
