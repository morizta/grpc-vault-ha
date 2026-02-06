// Package keyring provides versioned key management for encryption
package keyring

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/pocketsizefund/microservice-vault/pkg/crypto/aes"
)

// KeyType represents the type of encryption key
type KeyType int

const (
	KeyTypeAES256GCM KeyType = iota
	KeyTypeChacha20Poly1305
	KeyTypeRSA2048
	KeyTypeRSA4096
	KeyTypeECDSAP256
	KeyTypeECDSAP384
	KeyTypeEd25519
	KeyTypeFPEFF1
)

var (
	ErrKeyNotFound       = errors.New("key not found")
	ErrVersionNotFound   = errors.New("key version not found")
	ErrKeyringSealed     = errors.New("keyring is sealed")
	ErrKeyringNotSealed  = errors.New("keyring is not sealed")
	ErrInvalidMasterKey  = errors.New("invalid master key")
	ErrVersionBelowMin   = errors.New("key version below minimum allowed")
)

// Key represents a single version of an encryption key
type Key struct {
	Version   int       `json:"version"`
	Key       []byte    `json:"key"`
	PublicKey []byte    `json:"public_key,omitempty"` // For asymmetric keys
	Type      KeyType   `json:"type"`
	CreatedAt time.Time `json:"created_at"`
}

// KeyPolicy contains configuration for a named key
type KeyPolicy struct {
	Name                  string    `json:"name"`
	Type                  KeyType   `json:"type"`
	LatestVersion         int       `json:"latest_version"`
	MinDecryptionVersion  int       `json:"min_decryption_version"`
	MinEncryptionVersion  int       `json:"min_encryption_version"`
	Exportable            bool      `json:"exportable"`
	Derived               bool      `json:"derived"`
	ConvergentEncryption  bool      `json:"convergent_encryption"`
	AutoRotatePeriod      int64     `json:"auto_rotate_period"` // seconds
	DeletionAllowed       bool      `json:"deletion_allowed"`
	Keys                  []*Key    `json:"keys"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
}

// Keyring manages encryption keys with versioning
type Keyring struct {
	mu       sync.RWMutex
	policies map[string]*KeyPolicy
	ciphers  map[string]map[int]*aes.Cipher // name -> version -> cipher
	sealed   bool
}

// NewKeyring creates a new keyring
func NewKeyring() *Keyring {
	return &Keyring{
		policies: make(map[string]*KeyPolicy),
		ciphers:  make(map[string]map[int]*aes.Cipher),
		sealed:   false,
	}
}

// CreateKey creates a new encryption key
func (kr *Keyring) CreateKey(name string, keyType KeyType, opts ...KeyOption) (*KeyPolicy, error) {
	kr.mu.Lock()
	defer kr.mu.Unlock()

	if kr.sealed {
		return nil, ErrKeyringSealed
	}

	// Check if key already exists
	if _, exists := kr.policies[name]; exists {
		return nil, errors.New("key already exists")
	}

	// Create policy with defaults
	policy := &KeyPolicy{
		Name:                 name,
		Type:                 keyType,
		LatestVersion:        0,
		MinDecryptionVersion: 1,
		MinEncryptionVersion: 0, // 0 means use latest
		Exportable:           false,
		DeletionAllowed:      false,
		Keys:                 make([]*Key, 0),
		CreatedAt:            time.Now(),
		UpdatedAt:            time.Now(),
	}

	// Apply options
	for _, opt := range opts {
		opt(policy)
	}

	// Generate first key version
	if err := kr.generateKeyVersion(policy); err != nil {
		return nil, err
	}

	kr.policies[name] = policy
	return policy, nil
}

// GetKey returns the key policy
func (kr *Keyring) GetKey(name string) (*KeyPolicy, error) {
	kr.mu.RLock()
	defer kr.mu.RUnlock()

	if kr.sealed {
		return nil, ErrKeyringSealed
	}

	policy, exists := kr.policies[name]
	if !exists {
		return nil, ErrKeyNotFound
	}

	return policy, nil
}

// GetKeyVersion returns a specific version of a key
func (kr *Keyring) GetKeyVersion(name string, version int) (*Key, error) {
	kr.mu.RLock()
	defer kr.mu.RUnlock()

	if kr.sealed {
		return nil, ErrKeyringSealed
	}

	policy, exists := kr.policies[name]
	if !exists {
		return nil, ErrKeyNotFound
	}

	// Version 0 means latest
	if version == 0 {
		version = policy.LatestVersion
	}

	// Check minimum version
	if version < policy.MinDecryptionVersion {
		return nil, ErrVersionBelowMin
	}

	// Find the key version
	for _, key := range policy.Keys {
		if key.Version == version {
			return key, nil
		}
	}

	return nil, ErrVersionNotFound
}

// GetCipher returns an AES cipher for the specified key and version
func (kr *Keyring) GetCipher(name string, version int) (*aes.Cipher, error) {
	kr.mu.Lock()
	defer kr.mu.Unlock()

	if kr.sealed {
		return nil, ErrKeyringSealed
	}

	policy, exists := kr.policies[name]
	if !exists {
		return nil, ErrKeyNotFound
	}

	// Version 0 means latest
	if version == 0 {
		version = policy.LatestVersion
	}

	// Check cache first
	if cipherMap, exists := kr.ciphers[name]; exists {
		if cipher, exists := cipherMap[version]; exists {
			return cipher, nil
		}
	}

	// Find the key and create cipher
	var key *Key
	for _, k := range policy.Keys {
		if k.Version == version {
			key = k
			break
		}
	}

	if key == nil {
		return nil, ErrVersionNotFound
	}

	// Create cipher
	cipher, err := aes.NewCipher(key.Key, key.Version)
	if err != nil {
		return nil, err
	}

	// Cache it
	if kr.ciphers[name] == nil {
		kr.ciphers[name] = make(map[int]*aes.Cipher)
	}
	kr.ciphers[name][version] = cipher

	return cipher, nil
}

// RotateKey creates a new version of the key
func (kr *Keyring) RotateKey(name string) (int, error) {
	kr.mu.Lock()
	defer kr.mu.Unlock()

	if kr.sealed {
		return 0, ErrKeyringSealed
	}

	policy, exists := kr.policies[name]
	if !exists {
		return 0, ErrKeyNotFound
	}

	if err := kr.generateKeyVersion(policy); err != nil {
		return 0, err
	}

	policy.UpdatedAt = time.Now()

	return policy.LatestVersion, nil
}

// DeleteKey deletes a key if allowed
func (kr *Keyring) DeleteKey(name string) error {
	kr.mu.Lock()
	defer kr.mu.Unlock()

	if kr.sealed {
		return ErrKeyringSealed
	}

	policy, exists := kr.policies[name]
	if !exists {
		return ErrKeyNotFound
	}

	if !policy.DeletionAllowed {
		return errors.New("deletion not allowed for this key")
	}

	delete(kr.policies, name)
	delete(kr.ciphers, name)

	return nil
}

// ListKeys returns all key names
func (kr *Keyring) ListKeys() []string {
	kr.mu.RLock()
	defer kr.mu.RUnlock()

	keys := make([]string, 0, len(kr.policies))
	for name := range kr.policies {
		keys = append(keys, name)
	}
	return keys
}

// UpdateConfig updates key configuration
func (kr *Keyring) UpdateConfig(name string, opts ...KeyOption) error {
	kr.mu.Lock()
	defer kr.mu.Unlock()

	if kr.sealed {
		return ErrKeyringSealed
	}

	policy, exists := kr.policies[name]
	if !exists {
		return ErrKeyNotFound
	}

	for _, opt := range opts {
		opt(policy)
	}

	policy.UpdatedAt = time.Now()

	return nil
}

// Seal seals the keyring, clearing all keys from memory
func (kr *Keyring) Seal() {
	kr.mu.Lock()
	defer kr.mu.Unlock()

	// Zero out all key material
	for _, policy := range kr.policies {
		for _, key := range policy.Keys {
			for i := range key.Key {
				key.Key[i] = 0
			}
		}
	}

	kr.policies = make(map[string]*KeyPolicy)
	kr.ciphers = make(map[string]map[int]*aes.Cipher)
	kr.sealed = true
}

// IsSealed returns whether the keyring is sealed
func (kr *Keyring) IsSealed() bool {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	return kr.sealed
}

// Marshal serializes the keyring to JSON (for storage)
func (kr *Keyring) Marshal() ([]byte, error) {
	kr.mu.RLock()
	defer kr.mu.RUnlock()

	return json.Marshal(kr.policies)
}

// Unmarshal deserializes the keyring from JSON
func (kr *Keyring) Unmarshal(data []byte) error {
	kr.mu.Lock()
	defer kr.mu.Unlock()

	policies := make(map[string]*KeyPolicy)
	if err := json.Unmarshal(data, &policies); err != nil {
		return err
	}

	kr.policies = policies
	kr.ciphers = make(map[string]map[int]*aes.Cipher)
	kr.sealed = false

	return nil
}

// generateKeyVersion generates a new key version
func (kr *Keyring) generateKeyVersion(policy *KeyPolicy) error {
	var keySize int

	switch policy.Type {
	case KeyTypeAES256GCM, KeyTypeChacha20Poly1305, KeyTypeFPEFF1:
		keySize = 32
	default:
		keySize = 32
	}

	keyBytes := make([]byte, keySize)
	if _, err := rand.Read(keyBytes); err != nil {
		return err
	}

	policy.LatestVersion++

	key := &Key{
		Version:   policy.LatestVersion,
		Key:       keyBytes,
		Type:      policy.Type,
		CreatedAt: time.Now(),
	}

	policy.Keys = append(policy.Keys, key)

	return nil
}

// KeyOption is a function that modifies KeyPolicy
type KeyOption func(*KeyPolicy)

// WithExportable sets the exportable flag
func WithExportable(exportable bool) KeyOption {
	return func(p *KeyPolicy) {
		p.Exportable = exportable
	}
}

// WithDerived enables key derivation
func WithDerived(derived bool) KeyOption {
	return func(p *KeyPolicy) {
		p.Derived = derived
	}
}

// WithConvergentEncryption enables convergent encryption
func WithConvergentEncryption(convergent bool) KeyOption {
	return func(p *KeyPolicy) {
		p.ConvergentEncryption = convergent
	}
}

// WithMinDecryptionVersion sets minimum decryption version
func WithMinDecryptionVersion(version int) KeyOption {
	return func(p *KeyPolicy) {
		p.MinDecryptionVersion = version
	}
}

// WithMinEncryptionVersion sets minimum encryption version
func WithMinEncryptionVersion(version int) KeyOption {
	return func(p *KeyPolicy) {
		p.MinEncryptionVersion = version
	}
}

// WithAutoRotatePeriod sets auto rotation period in seconds
func WithAutoRotatePeriod(seconds int64) KeyOption {
	return func(p *KeyPolicy) {
		p.AutoRotatePeriod = seconds
	}
}

// WithDeletionAllowed allows key deletion
func WithDeletionAllowed(allowed bool) KeyOption {
	return func(p *KeyPolicy) {
		p.DeletionAllowed = allowed
	}
}
