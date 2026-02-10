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
	"github.com/pocketsizefund/microservice-vault/services/lock/internal/repository"
)

var (
	ErrSealed             = errors.New("vault is sealed")
	ErrNotSealed          = errors.New("vault is not sealed")
	ErrNotInitialized     = errors.New("vault is not initialized")
	ErrAlreadyInitialized = errors.New("vault is already initialized")
	ErrInvalidKey         = errors.New("invalid unseal key")
	ErrSecretNotFound     = errors.New("secret not found")
	ErrKeyNotFound        = errors.New("key not found")
)

// LockService handles secret storage and key management
type LockService struct {
	mu sync.RWMutex

	// Configuration
	config *config.Config
	logger *zap.Logger

	// Repositories
	secretRepo    repository.SecretRepository
	sealStateRepo repository.SealStateRepository
	keyringRepo   repository.KeyringRepository

	// State
	initialized bool
	sealed      bool

	// Seal
	masterKey  []byte
	shamirKeys [][]byte
	threshold  int
	unsealKeys [][]byte

	// Keyring (in-memory when unsealed)
	keyring *keyring.Keyring

	// Barrier key (encrypts all data)
	barrierKey []byte
}

// NewLockService creates a new lock service
func NewLockService(
	cfg *config.Config,
	logger *zap.Logger,
	secretRepo repository.SecretRepository,
	sealStateRepo repository.SealStateRepository,
	keyringRepo repository.KeyringRepository,
) *LockService {
	svc := &LockService{
		config:        cfg,
		logger:        logger,
		secretRepo:    secretRepo,
		sealStateRepo: sealStateRepo,
		keyringRepo:   keyringRepo,
		initialized:   false,
		sealed:        true,
		keyring:       keyring.NewKeyring(),
		threshold:     cfg.Seal.Threshold,
		unsealKeys:    make([][]byte, 0),
	}

	// Load persisted seal state
	state, err := sealStateRepo.Load(context.Background())
	if err == nil && state.Initialized {
		svc.initialized = true
		svc.masterKey = state.MasterKey
		svc.barrierKey = state.BarrierKey
		svc.shamirKeys = state.ShamirKeys
		svc.threshold = state.Threshold
		// Vault starts sealed — must unseal to access data
		svc.sealed = true
		logger.Info("Seal state loaded from storage (vault starts sealed)",
			zap.Int("threshold", state.Threshold))
	}

	return svc
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

	// Store state in memory
	s.masterKey = masterKey
	s.shamirKeys = shamirKeys
	s.barrierKey = barrierKey
	s.threshold = threshold
	s.initialized = true
	s.sealed = false // Auto-unseal after init

	// Persist seal state to BoltDB
	if err := s.sealStateRepo.Save(ctx, &repository.SealState{
		MasterKey:   masterKey,
		BarrierKey:  barrierKey,
		ShamirKeys:  shamirKeys,
		Threshold:   threshold,
		Initialized: true,
	}); err != nil {
		s.logger.Error("Failed to persist seal state", zap.Error(err))
	}

	// Persist empty keyring
	if data, err := s.keyring.Marshal(); err == nil {
		if err := s.keyringRepo.Save(ctx, data); err != nil {
			s.logger.Error("Failed to persist keyring", zap.Error(err))
		}
	}

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

		// Load keyring from storage
		if data, err := s.keyringRepo.Load(ctx); err == nil {
			s.keyring = keyring.NewKeyring()
			if err := s.keyring.Unmarshal(data); err != nil {
				s.logger.Warn("Failed to load keyring from storage, starting fresh", zap.Error(err))
				s.keyring = keyring.NewKeyring()
			}
		} else {
			s.logger.Debug("No persisted keyring found, starting fresh")
			s.keyring = keyring.NewKeyring()
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

	// Persist keyring before sealing
	if data, err := s.keyring.Marshal(); err == nil {
		if err := s.keyringRepo.Save(ctx, data); err != nil {
			s.logger.Error("Failed to persist keyring before seal", zap.Error(err))
		}
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

	if existing, err := s.secretRepo.Get(ctx, path); err == nil {
		version = existing.Version + 1
	}

	secret := &repository.Secret{
		Data:      data,
		Version:   version,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := s.secretRepo.Put(ctx, path, secret); err != nil {
		return 0, err
	}

	return version, nil
}

// GetSecret retrieves a secret
func (s *LockService) GetSecret(ctx context.Context, path string) (*repository.Secret, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.sealed {
		return nil, ErrSealed
	}

	secret, err := s.secretRepo.Get(ctx, path)
	if err != nil {
		if errors.Is(err, repository.ErrSecretNotFound) {
			return nil, ErrSecretNotFound
		}
		return nil, err
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

	if err := s.secretRepo.Delete(ctx, path); err != nil {
		if errors.Is(err, repository.ErrSecretNotFound) {
			return ErrSecretNotFound
		}
		return err
	}

	return nil
}

// ListSecrets lists secrets under a path prefix
func (s *LockService) ListSecrets(ctx context.Context, prefix string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.sealed {
		return nil, ErrSealed
	}

	return s.secretRepo.List(ctx, prefix)
}

// CreateKey creates a new encryption key
func (s *LockService) CreateKey(ctx context.Context, name string, keyType keyring.KeyType) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sealed {
		return ErrSealed
	}

	_, err := s.keyring.CreateKey(name, keyType)
	if err != nil {
		return err
	}

	// Persist keyring
	s.persistKeyring(ctx)

	return nil
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

	version, err := s.keyring.RotateKey(name)
	if err != nil {
		return 0, err
	}

	// Persist keyring
	s.persistKeyring(ctx)

	return version, nil
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

// persistKeyring saves the keyring to storage (caller must hold lock)
func (s *LockService) persistKeyring(ctx context.Context) {
	data, err := s.keyring.Marshal()
	if err != nil {
		s.logger.Error("Failed to marshal keyring", zap.Error(err))
		return
	}
	if err := s.keyringRepo.Save(ctx, data); err != nil {
		s.logger.Error("Failed to persist keyring", zap.Error(err))
	}
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
