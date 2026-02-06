package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/pocketsizefund/microservice-vault/pkg/crypto/keyring"
	"github.com/pocketsizefund/microservice-vault/services/lock/internal/config"
)

var (
	ErrSealed       = errors.New("vault is sealed")
	ErrNotSealed    = errors.New("vault is not sealed")
	ErrNotInitialized = errors.New("vault is not initialized")
	ErrAlreadyInitialized = errors.New("vault is already initialized")
	ErrInvalidKey   = errors.New("invalid unseal key")
	ErrSecretNotFound = errors.New("secret not found")
	ErrKeyNotFound  = errors.New("key not found")
)

// Secret represents a stored secret
type Secret struct {
	Data           map[string][]byte
	Version        int
	CreatedAt      time.Time
	UpdatedAt      time.Time
	CustomMetadata map[string]string
}

// LockService handles secret storage and key management
type LockService struct {
	mu sync.RWMutex

	// Configuration
	config *config.Config
	logger *zap.Logger

	// State
	initialized bool
	sealed      bool

	// Seal
	masterKey   []byte
	shamirKeys  [][]byte
	threshold   int
	unsealKeys  [][]byte

	// Storage
	secrets map[string]*Secret
	keyring *keyring.Keyring

	// Barrier key (encrypts all data)
	barrierKey []byte
}

// NewLockService creates a new lock service
func NewLockService(cfg *config.Config, logger *zap.Logger) *LockService {
	return &LockService{
		config:      cfg,
		logger:      logger,
		initialized: false,
		sealed:      true,
		secrets:     make(map[string]*Secret),
		keyring:     keyring.NewKeyring(),
		threshold:   cfg.Seal.Threshold,
		unsealKeys:  make([][]byte, 0),
	}
}

// Initialize initializes the vault with Shamir secret sharing
func (s *LockService) Initialize(ctx context.Context, shares, threshold int) ([]string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.initialized {
		return nil, "", ErrAlreadyInitialized
	}

	// Generate master key (256 bits)
	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		return nil, "", err
	}

	// Split master key using Shamir's Secret Sharing
	shamirKeys, err := shamirSplit(masterKey, shares, threshold)
	if err != nil {
		return nil, "", err
	}

	// Generate barrier key (encrypts all data)
	barrierKey := make([]byte, 32)
	if _, err := rand.Read(barrierKey); err != nil {
		return nil, "", err
	}

	// Generate root token
	rootTokenBytes := make([]byte, 32)
	if _, err := rand.Read(rootTokenBytes); err != nil {
		return nil, "", err
	}
	rootToken := base64.StdEncoding.EncodeToString(rootTokenBytes)

	// Store state
	s.masterKey = masterKey
	s.shamirKeys = shamirKeys
	s.barrierKey = barrierKey
	s.threshold = threshold
	s.initialized = true
	s.sealed = false // Auto-unseal after init

	// Encode keys for return
	keyStrings := make([]string, len(shamirKeys))
	for i, key := range shamirKeys {
		keyStrings[i] = base64.StdEncoding.EncodeToString(key)
	}

	s.logger.Info("Vault initialized",
		zap.Int("shares", shares),
		zap.Int("threshold", threshold),
	)

	return keyStrings, rootToken, nil
}

// Unseal attempts to unseal the vault with a key share
func (s *LockService) Unseal(ctx context.Context, keyShare string) (bool, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.initialized {
		return false, 0, ErrNotInitialized
	}

	if !s.sealed {
		return true, s.threshold, nil
	}

	// Decode key share
	keyBytes, err := base64.StdEncoding.DecodeString(keyShare)
	if err != nil {
		return false, len(s.unsealKeys), ErrInvalidKey
	}

	// Add to unseal keys
	s.unsealKeys = append(s.unsealKeys, keyBytes)

	// Check if we have enough keys
	if len(s.unsealKeys) >= s.threshold {
		// Attempt to reconstruct master key
		reconstructed, err := shamirCombine(s.unsealKeys)
		if err != nil {
			s.unsealKeys = make([][]byte, 0) // Reset on failure
			return false, 0, ErrInvalidKey
		}

		// Verify master key
		if !bytesEqual(reconstructed, s.masterKey) {
			s.unsealKeys = make([][]byte, 0) // Reset on failure
			return false, 0, ErrInvalidKey
		}

		// Unseal successful
		s.sealed = false
		s.unsealKeys = make([][]byte, 0)

		s.logger.Info("Vault unsealed")
		return true, s.threshold, nil
	}

	return false, len(s.unsealKeys), nil
}

// Seal seals the vault
func (s *LockService) Seal(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.initialized {
		return ErrNotInitialized
	}

	if s.sealed {
		return ErrNotSealed
	}

	// Clear sensitive data from memory
	s.keyring.Seal()
	s.unsealKeys = make([][]byte, 0)
	s.sealed = true

	s.logger.Info("Vault sealed")
	return nil
}

// IsSealed returns whether the vault is sealed
func (s *LockService) IsSealed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sealed
}

// IsInitialized returns whether the vault is initialized
func (s *LockService) IsInitialized() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.initialized
}

// GetSealStatus returns the seal status
func (s *LockService) GetSealStatus() (sealed bool, initialized bool, threshold int, progress int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sealed, s.initialized, s.threshold, len(s.unsealKeys)
}

// PutSecret stores a secret
func (s *LockService) PutSecret(ctx context.Context, path string, data map[string][]byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sealed {
		return 0, ErrSealed
	}

	now := time.Now()
	version := 1

	if existing, exists := s.secrets[path]; exists {
		version = existing.Version + 1
	}

	s.secrets[path] = &Secret{
		Data:      data,
		Version:   version,
		CreatedAt: now,
		UpdatedAt: now,
	}

	return version, nil
}

// GetSecret retrieves a secret
func (s *LockService) GetSecret(ctx context.Context, path string) (*Secret, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.sealed {
		return nil, ErrSealed
	}

	secret, exists := s.secrets[path]
	if !exists {
		return nil, ErrSecretNotFound
	}

	return secret, nil
}

// DeleteSecret deletes a secret
func (s *LockService) DeleteSecret(ctx context.Context, path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sealed {
		return ErrSealed
	}

	if _, exists := s.secrets[path]; !exists {
		return ErrSecretNotFound
	}

	delete(s.secrets, path)
	return nil
}

// ListSecrets lists secrets under a path prefix
func (s *LockService) ListSecrets(ctx context.Context, prefix string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.sealed {
		return nil, ErrSealed
	}

	var keys []string
	for path := range s.secrets {
		if len(prefix) == 0 || len(path) >= len(prefix) && path[:len(prefix)] == prefix {
			keys = append(keys, path)
		}
	}

	return keys, nil
}

// CreateKey creates a new encryption key
func (s *LockService) CreateKey(ctx context.Context, name string, keyType keyring.KeyType) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sealed {
		return ErrSealed
	}

	_, err := s.keyring.CreateKey(name, keyType)
	return err
}

// GetKey returns key information
func (s *LockService) GetKey(ctx context.Context, name string) (*keyring.KeyPolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.sealed {
		return nil, ErrSealed
	}

	return s.keyring.GetKey(name)
}

// GetEncryptionKey returns the raw key material for encryption operations
func (s *LockService) GetEncryptionKey(ctx context.Context, name string, version int) (*keyring.Key, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.sealed {
		return nil, ErrSealed
	}

	return s.keyring.GetKeyVersion(name, version)
}

// RotateKey creates a new version of the key
func (s *LockService) RotateKey(ctx context.Context, name string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sealed {
		return 0, ErrSealed
	}

	return s.keyring.RotateKey(name)
}

// ListKeys returns all key names
func (s *LockService) ListKeys(ctx context.Context) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.sealed {
		return nil, ErrSealed
	}

	return s.keyring.ListKeys(), nil
}

// Placeholder Shamir functions (use proper implementation in production)
func shamirSplit(secret []byte, shares, threshold int) ([][]byte, error) {
	// TODO: Implement proper Shamir's Secret Sharing
	// For now, just duplicate the secret (NOT SECURE - for development only)
	result := make([][]byte, shares)
	for i := 0; i < shares; i++ {
		result[i] = make([]byte, len(secret)+1)
		result[i][0] = byte(i + 1) // Share index
		copy(result[i][1:], secret)
	}
	return result, nil
}

func shamirCombine(shares [][]byte) ([]byte, error) {
	// TODO: Implement proper Shamir's Secret Sharing reconstruction
	// For now, just return the secret from the first share (NOT SECURE)
	if len(shares) == 0 {
		return nil, errors.New("no shares provided")
	}
	return shares[0][1:], nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
