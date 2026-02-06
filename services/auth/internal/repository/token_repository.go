package repository

import (
	"context"
	"errors"
	"sync"
	"time"
)

var (
	ErrTokenNotFound = errors.New("token not found")
	ErrTokenRevoked  = errors.New("token has been revoked")
)

// Token represents a stored token
type Token struct {
	ID         string
	Identity   string
	Policies   []string
	Metadata   map[string]string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	RevokedAt  *time.Time
	LastUsedAt *time.Time
}

// TokenRepository defines token storage operations
type TokenRepository interface {
	Create(ctx context.Context, token *Token) error
	Get(ctx context.Context, id string) (*Token, error)
	Revoke(ctx context.Context, id string) error
	UpdateLastUsed(ctx context.Context, id string) error
	ListByIdentity(ctx context.Context, identity string, limit, offset int) ([]*Token, int, error)
	DeleteExpired(ctx context.Context) (int, error)
}

// MemoryTokenRepository is an in-memory implementation
type MemoryTokenRepository struct {
	mu     sync.RWMutex
	tokens map[string]*Token
}

// NewMemoryTokenRepository creates a new in-memory token repository
func NewMemoryTokenRepository() *MemoryTokenRepository {
	return &MemoryTokenRepository{
		tokens: make(map[string]*Token),
	}
}

func (r *MemoryTokenRepository) Create(ctx context.Context, token *Token) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.tokens[token.ID] = token
	return nil
}

func (r *MemoryTokenRepository) Get(ctx context.Context, id string) (*Token, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	token, exists := r.tokens[id]
	if !exists {
		return nil, ErrTokenNotFound
	}

	if token.RevokedAt != nil {
		return nil, ErrTokenRevoked
	}

	if time.Now().After(token.ExpiresAt) {
		return nil, ErrTokenNotFound
	}

	return token, nil
}

func (r *MemoryTokenRepository) Revoke(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	token, exists := r.tokens[id]
	if !exists {
		return ErrTokenNotFound
	}

	now := time.Now()
	token.RevokedAt = &now
	return nil
}

func (r *MemoryTokenRepository) UpdateLastUsed(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	token, exists := r.tokens[id]
	if !exists {
		return ErrTokenNotFound
	}

	now := time.Now()
	token.LastUsedAt = &now
	return nil
}

func (r *MemoryTokenRepository) ListByIdentity(ctx context.Context, identity string, limit, offset int) ([]*Token, int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var filtered []*Token
	for _, token := range r.tokens {
		if token.Identity == identity && token.RevokedAt == nil {
			filtered = append(filtered, token)
		}
	}

	total := len(filtered)

	// Apply pagination
	if offset >= len(filtered) {
		return []*Token{}, total, nil
	}

	end := offset + limit
	if end > len(filtered) {
		end = len(filtered)
	}

	return filtered[offset:end], total, nil
}

func (r *MemoryTokenRepository) DeleteExpired(ctx context.Context) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	count := 0

	for id, token := range r.tokens {
		if now.After(token.ExpiresAt) {
			delete(r.tokens, id)
			count++
		}
	}

	return count, nil
}
