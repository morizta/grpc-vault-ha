package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

var (
	ErrAPIKeyNotFound = errors.New("API key not found")
	ErrAPIKeyRevoked  = errors.New("API key has been revoked")
)

// APIKey represents a stored API key
type APIKey struct {
	ID         string
	Name       string
	KeyHash    string // SHA256 hash of the actual key
	Identity   string
	Policies   []string
	Metadata   map[string]string
	CreatedAt  time.Time
	ExpiresAt  *time.Time
	RevokedAt  *time.Time
	LastUsedAt *time.Time
}

// APIKeyRepository defines API key storage operations
type APIKeyRepository interface {
	Create(ctx context.Context, apiKey *APIKey) error
	GetByHash(ctx context.Context, keyHash string) (*APIKey, error)
	GetByID(ctx context.Context, id string) (*APIKey, error)
	Revoke(ctx context.Context, id string) error
	UpdateLastUsed(ctx context.Context, id string) error
	ListByIdentity(ctx context.Context, identity string, limit, offset int) ([]*APIKey, int, error)
}

// MemoryAPIKeyRepository is an in-memory implementation
type MemoryAPIKeyRepository struct {
	mu      sync.RWMutex
	keys    map[string]*APIKey // id -> APIKey
	byHash  map[string]string  // hash -> id
}

// NewMemoryAPIKeyRepository creates a new in-memory API key repository
func NewMemoryAPIKeyRepository() *MemoryAPIKeyRepository {
	return &MemoryAPIKeyRepository{
		keys:   make(map[string]*APIKey),
		byHash: make(map[string]string),
	}
}

func (r *MemoryAPIKeyRepository) Create(ctx context.Context, apiKey *APIKey) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.keys[apiKey.ID] = apiKey
	r.byHash[apiKey.KeyHash] = apiKey.ID
	return nil
}

func (r *MemoryAPIKeyRepository) GetByHash(ctx context.Context, keyHash string) (*APIKey, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	id, exists := r.byHash[keyHash]
	if !exists {
		return nil, ErrAPIKeyNotFound
	}

	apiKey := r.keys[id]
	if apiKey.RevokedAt != nil {
		return nil, ErrAPIKeyRevoked
	}

	if apiKey.ExpiresAt != nil && time.Now().After(*apiKey.ExpiresAt) {
		return nil, ErrAPIKeyNotFound
	}

	return apiKey, nil
}

func (r *MemoryAPIKeyRepository) GetByID(ctx context.Context, id string) (*APIKey, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	apiKey, exists := r.keys[id]
	if !exists {
		return nil, ErrAPIKeyNotFound
	}

	return apiKey, nil
}

func (r *MemoryAPIKeyRepository) Revoke(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	apiKey, exists := r.keys[id]
	if !exists {
		return ErrAPIKeyNotFound
	}

	now := time.Now()
	apiKey.RevokedAt = &now
	return nil
}

func (r *MemoryAPIKeyRepository) UpdateLastUsed(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	apiKey, exists := r.keys[id]
	if !exists {
		return ErrAPIKeyNotFound
	}

	now := time.Now()
	apiKey.LastUsedAt = &now
	return nil
}

func (r *MemoryAPIKeyRepository) ListByIdentity(ctx context.Context, identity string, limit, offset int) ([]*APIKey, int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var filtered []*APIKey
	for _, apiKey := range r.keys {
		if apiKey.Identity == identity && apiKey.RevokedAt == nil {
			filtered = append(filtered, apiKey)
		}
	}

	total := len(filtered)

	if offset >= len(filtered) {
		return []*APIKey{}, total, nil
	}

	end := offset + limit
	if end > len(filtered) {
		end = len(filtered)
	}

	return filtered[offset:end], total, nil
}

// HashAPIKey hashes an API key using SHA256
func HashAPIKey(key string) string {
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:])
}
