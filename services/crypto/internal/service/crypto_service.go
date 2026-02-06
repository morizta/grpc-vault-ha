package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"github.com/gammazero/workerpool"
	lru "github.com/hashicorp/golang-lru/v2"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	lockv1 "github.com/pocketsizefund/microservice-vault/gen/go/lock/v1"
	"github.com/pocketsizefund/microservice-vault/pkg/crypto/aes"
	"github.com/pocketsizefund/microservice-vault/services/crypto/internal/config"
)

var (
	ErrKeyNotFound        = errors.New("key not found")
	ErrDecryptFailed      = errors.New("decryption failed")
	ErrInvalidInput       = errors.New("invalid input")
	ErrLockServiceRequired = errors.New("lock service connection required")
)

// KeyInfo holds cached key information
type KeyInfo struct {
	Key     []byte
	Version int
	Type    int
}

// EncryptResult holds encryption result
type EncryptResult struct {
	Ciphertext string
	KeyVersion int
	Reference  string
	Error      error
}

// DecryptResult holds decryption result
type DecryptResult struct {
	Plaintext  []byte
	KeyVersion int
	Reference  string
	Error      error
}

// CryptoService handles cryptographic operations
type CryptoService struct {
	config     *config.Config
	logger     *zap.Logger
	workerPool *workerpool.WorkerPool

	// Key cache: LRU cache like HashiCorp Vault's LockManager
	// Bounded cache with eviction policy
	keyCache *lru.Cache[string, *KeyInfo]

	// No cipher cache - create cipher per request like Vault

	// Lock service client for key retrieval (required)
	lockConn   *grpc.ClientConn
	lockClient lockv1.LockServiceClient
}

// NewCryptoService creates a new crypto service
func NewCryptoService(cfg *config.Config, logger *zap.Logger) (*CryptoService, error) {
	wp := workerpool.New(cfg.WorkerPool.Size)

	// Create LRU cache for keys (like Vault's LockManager)
	// Default size: 10000 keys
	keyCache, err := lru.New[string, *KeyInfo](10000)
	if err != nil {
		return nil, fmt.Errorf("failed to create key cache: %w", err)
	}

	svc := &CryptoService{
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


// getKey retrieves a key from cache or Lock Service
// Uses LRU cache like HashiCorp Vault's LockManager
func (s *CryptoService) getKey(ctx context.Context, keyName string, version int) (*KeyInfo, error) {
	cacheKey := keyName
	if version > 0 {
		cacheKey = fmt.Sprintf("%s:%d", keyName, version)
	}

	// Check cache first - fast path (like Vault's LockManager)
	if cached, ok := s.keyCache.Get(cacheKey); ok {
		return cached, nil
	}

	// Slow path: get key from Lock service
	if s.lockClient == nil {
		return nil, ErrLockServiceRequired
	}

	resp, err := s.lockClient.GetEncryptionKey(ctx, &lockv1.GetEncryptionKeyRequest{
		Name:    keyName,
		Version: int32(version),
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
		Type:    int(resp.Type),
	}
	// Store in LRU cache (like Vault)
	s.keyCache.Add(cacheKey, keyInfo)
	return keyInfo, nil
}

// newCipher creates a new cipher for the key (like Vault - no caching)
func (s *CryptoService) newCipher(keyInfo *KeyInfo) (*aes.Cipher, error) {
	return aes.NewCipher(keyInfo.Key, keyInfo.Version)
}

// Encrypt encrypts plaintext with the specified key
func (s *CryptoService) Encrypt(ctx context.Context, keyName string, plaintext, aad []byte) (string, int, error) {
	keyInfo, err := s.getKey(ctx, keyName, 0) // 0 = latest
	if err != nil {
		return "", 0, err
	}

	// Create cipher per request (like Vault)
	cipher, err := s.newCipher(keyInfo)
	if err != nil {
		return "", 0, err
	}

	ciphertext, err := cipher.Encrypt(plaintext, aad)
	if err != nil {
		return "", 0, err
	}

	return ciphertext, keyInfo.Version, nil
}

// Decrypt decrypts ciphertext
func (s *CryptoService) Decrypt(ctx context.Context, keyName, ciphertext string, aad []byte) ([]byte, int, error) {
	// Parse version from ciphertext
	version, _, err := aes.ParseCiphertext(ciphertext)
	if err != nil {
		return nil, 0, err
	}

	keyInfo, err := s.getKey(ctx, keyName, version)
	if err != nil {
		return nil, 0, err
	}

	// Create cipher per request (like Vault)
	cipher, err := s.newCipher(keyInfo)
	if err != nil {
		return nil, 0, err
	}

	plaintext, parsedVersion, err := cipher.Decrypt(ciphertext, aad)
	if err != nil {
		return nil, 0, ErrDecryptFailed
	}

	return plaintext, parsedVersion, nil
}

// EncryptBatch encrypts multiple items in parallel
func (s *CryptoService) EncryptBatch(ctx context.Context, keyName string, items []BatchItem) []EncryptResult {
	results := make([]EncryptResult, len(items))
	var wg sync.WaitGroup

	keyInfo, err := s.getKey(ctx, keyName, 0)
	if err != nil {
		for i := range results {
			results[i] = EncryptResult{
				Reference: items[i].Reference,
				Error:     err,
			}
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
			cipher, cipherErr := s.newCipher(keyInfo)
			if cipherErr != nil {
				results[idx] = EncryptResult{
					Reference: itm.Reference,
					Error:     cipherErr,
				}
				return
			}

			ciphertext, encErr := cipher.Encrypt(itm.Plaintext, itm.Context)
			results[idx] = EncryptResult{
				Ciphertext: ciphertext,
				KeyVersion: keyInfo.Version,
				Reference:  itm.Reference,
				Error:      encErr,
			}
		})
	}

	wg.Wait()
	return results
}

// DecryptBatch decrypts multiple items in parallel
func (s *CryptoService) DecryptBatch(ctx context.Context, keyName string, items []BatchDecryptItem) []DecryptResult {
	results := make([]DecryptResult, len(items))
	var wg sync.WaitGroup

	for i, item := range items {
		wg.Add(1)
		idx := i
		itm := item

		s.workerPool.Submit(func() {
			defer wg.Done()

			plaintext, version, err := s.Decrypt(ctx, keyName, itm.Ciphertext, itm.Context)
			results[idx] = DecryptResult{
				Plaintext:  plaintext,
				KeyVersion: version,
				Reference:  itm.Reference,
				Error:      err,
			}
		})
	}

	wg.Wait()
	return results
}

// GenerateRandom generates random bytes
func (s *CryptoService) GenerateRandom(ctx context.Context, numBytes int, format string) (string, error) {
	if numBytes <= 0 || numBytes > 1024 {
		return "", ErrInvalidInput
	}

	randomBytes := make([]byte, numBytes)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}

	switch format {
	case "hex":
		return hex.EncodeToString(randomBytes), nil
	default:
		return base64.StdEncoding.EncodeToString(randomBytes), nil
	}
}

// Close shuts down the service
func (s *CryptoService) Close() {
	s.workerPool.StopWait()
	if s.lockConn != nil {
		s.lockConn.Close()
	}
}

// BatchItem represents an item in a batch operation
type BatchItem struct {
	Plaintext []byte
	Context   []byte
	Reference string
}

// BatchDecryptItem represents an item in a batch decrypt operation
type BatchDecryptItem struct {
	Ciphertext string
	Context    []byte
	Reference  string
}
