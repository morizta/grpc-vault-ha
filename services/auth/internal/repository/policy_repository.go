package repository

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/pocketsizefund/microservice-vault/pkg/auth/policy"
)

var (
	ErrPolicyNotFound = errors.New("policy not found")
	ErrPolicyExists   = errors.New("policy already exists")
)

// StoredPolicy represents a stored policy
type StoredPolicy struct {
	Name        string
	Description string
	Rules       []*policy.Rule
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// PolicyRepository defines policy storage operations
type PolicyRepository interface {
	Create(ctx context.Context, p *StoredPolicy) error
	Get(ctx context.Context, name string) (*StoredPolicy, error)
	Update(ctx context.Context, p *StoredPolicy) error
	Delete(ctx context.Context, name string) error
	List(ctx context.Context, limit, offset int) ([]*StoredPolicy, int, error)
}

// MemoryPolicyRepository is an in-memory implementation
type MemoryPolicyRepository struct {
	mu       sync.RWMutex
	policies map[string]*StoredPolicy
}

// NewMemoryPolicyRepository creates a new in-memory policy repository
func NewMemoryPolicyRepository() *MemoryPolicyRepository {
	repo := &MemoryPolicyRepository{
		policies: make(map[string]*StoredPolicy),
	}

	// Add default policies
	now := time.Now()

	repo.policies["default"] = &StoredPolicy{
		Name:        "default",
		Description: "Default policy with basic self-service access",
		Rules: []*policy.Rule{
			{Path: "auth/token/lookup-self", Capabilities: []policy.Capability{policy.CapabilityRead}},
			{Path: "auth/token/renew-self", Capabilities: []policy.Capability{policy.CapabilityUpdate}},
			{Path: "auth/token/revoke-self", Capabilities: []policy.Capability{policy.CapabilityUpdate}},
		},
		CreatedAt: now,
		UpdatedAt: now,
	}

	repo.policies["admin"] = &StoredPolicy{
		Name:        "admin",
		Description: "Full administrative access",
		Rules: []*policy.Rule{
			{Path: "**", Capabilities: []policy.Capability{policy.CapabilitySudo}},
		},
		CreatedAt: now,
		UpdatedAt: now,
	}

	return repo
}

func (r *MemoryPolicyRepository) Create(ctx context.Context, p *StoredPolicy) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.policies[p.Name]; exists {
		return ErrPolicyExists
	}

	p.CreatedAt = time.Now()
	p.UpdatedAt = p.CreatedAt
	r.policies[p.Name] = p
	return nil
}

func (r *MemoryPolicyRepository) Get(ctx context.Context, name string) (*StoredPolicy, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	p, exists := r.policies[name]
	if !exists {
		return nil, ErrPolicyNotFound
	}

	return p, nil
}

func (r *MemoryPolicyRepository) Update(ctx context.Context, p *StoredPolicy) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.policies[p.Name]; !exists {
		return ErrPolicyNotFound
	}

	p.UpdatedAt = time.Now()
	r.policies[p.Name] = p
	return nil
}

func (r *MemoryPolicyRepository) Delete(ctx context.Context, name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.policies[name]; !exists {
		return ErrPolicyNotFound
	}

	// Prevent deleting built-in policies
	if name == "default" || name == "admin" {
		return errors.New("cannot delete built-in policy")
	}

	delete(r.policies, name)
	return nil
}

func (r *MemoryPolicyRepository) List(ctx context.Context, limit, offset int) ([]*StoredPolicy, int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	policies := make([]*StoredPolicy, 0, len(r.policies))
	for _, p := range r.policies {
		policies = append(policies, p)
	}

	total := len(policies)

	if offset >= len(policies) {
		return []*StoredPolicy{}, total, nil
	}

	end := offset + limit
	if end > len(policies) {
		end = len(policies)
	}

	return policies[offset:end], total, nil
}
