package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/pocketsizefund/microservice-vault/pkg/auth/policy"
	bolt "go.etcd.io/bbolt"
)

var (
	bucketTokens      = []byte("tokens")
	bucketAPIKeys     = []byte("apikeys")
	bucketAPIKeysHash = []byte("apikeys_hash")
	bucketPolicies    = []byte("policies")
	bucketCredentials = []byte("credentials")
)

// BoltStore implements all auth repository interfaces using BoltDB.
type BoltStore struct {
	db *bolt.DB
}

// NewBoltStore creates a new BoltDB-backed store.
func NewBoltStore(path string) (*BoltStore, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("create storage directory: %w", err)
	}

	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open bolt db: %w", err)
	}

	// Create all buckets
	err = db.Update(func(tx *bolt.Tx) error {
		for _, bucket := range [][]byte{bucketTokens, bucketAPIKeys, bucketAPIKeysHash, bucketPolicies, bucketCredentials} {
			if _, err := tx.CreateBucketIfNotExists(bucket); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("create buckets: %w", err)
	}

	return &BoltStore{db: db}, nil
}

// Close closes the BoltDB database.
func (s *BoltStore) Close() error {
	return s.db.Close()
}

// ==================== TokenRepository ====================

// stored types for JSON serialization
type storedToken struct {
	ID         string            `json:"id"`
	Identity   string            `json:"identity"`
	Policies   []string          `json:"policies"`
	Metadata   map[string]string `json:"metadata"`
	CreatedAt  time.Time         `json:"created_at"`
	ExpiresAt  time.Time         `json:"expires_at"`
	RevokedAt  *time.Time        `json:"revoked_at,omitempty"`
	LastUsedAt *time.Time        `json:"last_used_at,omitempty"`
}

func tokenToStored(t *Token) *storedToken {
	return &storedToken{
		ID:         t.ID,
		Identity:   t.Identity,
		Policies:   t.Policies,
		Metadata:   t.Metadata,
		CreatedAt:  t.CreatedAt,
		ExpiresAt:  t.ExpiresAt,
		RevokedAt:  t.RevokedAt,
		LastUsedAt: t.LastUsedAt,
	}
}

func storedToToken(s *storedToken) *Token {
	return &Token{
		ID:         s.ID,
		Identity:   s.Identity,
		Policies:   s.Policies,
		Metadata:   s.Metadata,
		CreatedAt:  s.CreatedAt,
		ExpiresAt:  s.ExpiresAt,
		RevokedAt:  s.RevokedAt,
		LastUsedAt: s.LastUsedAt,
	}
}

func (s *BoltStore) Create(ctx context.Context, token *Token) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		data, err := json.Marshal(tokenToStored(token))
		if err != nil {
			return err
		}
		return tx.Bucket(bucketTokens).Put([]byte(token.ID), data)
	})
}

func (s *BoltStore) Get(ctx context.Context, id string) (*Token, error) {
	var token *Token
	err := s.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketTokens).Get([]byte(id))
		if data == nil {
			return ErrTokenNotFound
		}
		var st storedToken
		if err := json.Unmarshal(data, &st); err != nil {
			return err
		}
		t := storedToToken(&st)
		if t.RevokedAt != nil {
			return ErrTokenRevoked
		}
		if time.Now().After(t.ExpiresAt) {
			return ErrTokenNotFound
		}
		token = t
		return nil
	})
	return token, err
}

func (s *BoltStore) Revoke(ctx context.Context, id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketTokens)
		data := b.Get([]byte(id))
		if data == nil {
			return ErrTokenNotFound
		}
		var st storedToken
		if err := json.Unmarshal(data, &st); err != nil {
			return err
		}
		now := time.Now()
		st.RevokedAt = &now
		updated, err := json.Marshal(&st)
		if err != nil {
			return err
		}
		return b.Put([]byte(id), updated)
	})
}

func (s *BoltStore) UpdateLastUsed(ctx context.Context, id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketTokens)
		data := b.Get([]byte(id))
		if data == nil {
			return ErrTokenNotFound
		}
		var st storedToken
		if err := json.Unmarshal(data, &st); err != nil {
			return err
		}
		now := time.Now()
		st.LastUsedAt = &now
		updated, err := json.Marshal(&st)
		if err != nil {
			return err
		}
		return b.Put([]byte(id), updated)
	})
}

func (s *BoltStore) ListByIdentity(ctx context.Context, identity string, limit, offset int) ([]*Token, int, error) {
	var all []*Token
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketTokens).ForEach(func(k, v []byte) error {
			var st storedToken
			if err := json.Unmarshal(v, &st); err != nil {
				return nil // skip corrupt entries
			}
			if st.Identity == identity && st.RevokedAt == nil {
				all = append(all, storedToToken(&st))
			}
			return nil
		})
	})
	if err != nil {
		return nil, 0, err
	}

	total := len(all)
	if offset >= total {
		return []*Token{}, total, nil
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return all[offset:end], total, nil
}

func (s *BoltStore) DeleteExpired(ctx context.Context) (int, error) {
	count := 0
	now := time.Now()
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketTokens)
		var toDelete [][]byte
		b.ForEach(func(k, v []byte) error {
			var st storedToken
			if err := json.Unmarshal(v, &st); err != nil {
				return nil
			}
			if now.After(st.ExpiresAt) {
				toDelete = append(toDelete, k)
			}
			return nil
		})
		for _, k := range toDelete {
			if err := b.Delete(k); err != nil {
				return err
			}
			count++
		}
		return nil
	})
	return count, err
}

// ==================== APIKeyRepository ====================

type storedAPIKey struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	KeyHash    string            `json:"key_hash"`
	Identity   string            `json:"identity"`
	Policies   []string          `json:"policies"`
	Metadata   map[string]string `json:"metadata"`
	CreatedAt  time.Time         `json:"created_at"`
	ExpiresAt  *time.Time        `json:"expires_at,omitempty"`
	RevokedAt  *time.Time        `json:"revoked_at,omitempty"`
	LastUsedAt *time.Time        `json:"last_used_at,omitempty"`
}

func apiKeyToStored(k *APIKey) *storedAPIKey {
	return &storedAPIKey{
		ID:         k.ID,
		Name:       k.Name,
		KeyHash:    k.KeyHash,
		Identity:   k.Identity,
		Policies:   k.Policies,
		Metadata:   k.Metadata,
		CreatedAt:  k.CreatedAt,
		ExpiresAt:  k.ExpiresAt,
		RevokedAt:  k.RevokedAt,
		LastUsedAt: k.LastUsedAt,
	}
}

func storedToAPIKey(s *storedAPIKey) *APIKey {
	return &APIKey{
		ID:         s.ID,
		Name:       s.Name,
		KeyHash:    s.KeyHash,
		Identity:   s.Identity,
		Policies:   s.Policies,
		Metadata:   s.Metadata,
		CreatedAt:  s.CreatedAt,
		ExpiresAt:  s.ExpiresAt,
		RevokedAt:  s.RevokedAt,
		LastUsedAt: s.LastUsedAt,
	}
}

func (s *BoltStore) CreateAPIKey(ctx context.Context, apiKey *APIKey) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		data, err := json.Marshal(apiKeyToStored(apiKey))
		if err != nil {
			return err
		}
		if err := tx.Bucket(bucketAPIKeys).Put([]byte(apiKey.ID), data); err != nil {
			return err
		}
		// index: hash -> id
		return tx.Bucket(bucketAPIKeysHash).Put([]byte(apiKey.KeyHash), []byte(apiKey.ID))
	})
}

func (s *BoltStore) GetByHash(ctx context.Context, keyHash string) (*APIKey, error) {
	var apiKey *APIKey
	err := s.db.View(func(tx *bolt.Tx) error {
		id := tx.Bucket(bucketAPIKeysHash).Get([]byte(keyHash))
		if id == nil {
			return ErrAPIKeyNotFound
		}
		data := tx.Bucket(bucketAPIKeys).Get(id)
		if data == nil {
			return ErrAPIKeyNotFound
		}
		var st storedAPIKey
		if err := json.Unmarshal(data, &st); err != nil {
			return err
		}
		k := storedToAPIKey(&st)
		if k.RevokedAt != nil {
			return ErrAPIKeyRevoked
		}
		if k.ExpiresAt != nil && time.Now().After(*k.ExpiresAt) {
			return ErrAPIKeyNotFound
		}
		apiKey = k
		return nil
	})
	return apiKey, err
}

func (s *BoltStore) GetByID(ctx context.Context, id string) (*APIKey, error) {
	var apiKey *APIKey
	err := s.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketAPIKeys).Get([]byte(id))
		if data == nil {
			return ErrAPIKeyNotFound
		}
		var st storedAPIKey
		if err := json.Unmarshal(data, &st); err != nil {
			return err
		}
		apiKey = storedToAPIKey(&st)
		return nil
	})
	return apiKey, err
}

func (s *BoltStore) RevokeAPIKey(ctx context.Context, id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketAPIKeys)
		data := b.Get([]byte(id))
		if data == nil {
			return ErrAPIKeyNotFound
		}
		var st storedAPIKey
		if err := json.Unmarshal(data, &st); err != nil {
			return err
		}
		now := time.Now()
		st.RevokedAt = &now
		updated, err := json.Marshal(&st)
		if err != nil {
			return err
		}
		return b.Put([]byte(id), updated)
	})
}

func (s *BoltStore) UpdateAPIKeyLastUsed(ctx context.Context, id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketAPIKeys)
		data := b.Get([]byte(id))
		if data == nil {
			return ErrAPIKeyNotFound
		}
		var st storedAPIKey
		if err := json.Unmarshal(data, &st); err != nil {
			return err
		}
		now := time.Now()
		st.LastUsedAt = &now
		updated, err := json.Marshal(&st)
		if err != nil {
			return err
		}
		return b.Put([]byte(id), updated)
	})
}

func (s *BoltStore) ListAPIKeysByIdentity(ctx context.Context, identity string, limit, offset int) ([]*APIKey, int, error) {
	var all []*APIKey
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketAPIKeys).ForEach(func(k, v []byte) error {
			var st storedAPIKey
			if err := json.Unmarshal(v, &st); err != nil {
				return nil
			}
			if st.Identity == identity && st.RevokedAt == nil {
				all = append(all, storedToAPIKey(&st))
			}
			return nil
		})
	})
	if err != nil {
		return nil, 0, err
	}

	total := len(all)
	if offset >= total {
		return []*APIKey{}, total, nil
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return all[offset:end], total, nil
}

// ==================== PolicyRepository ====================

type storedPolicy struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Rules       []*storedRule  `json:"rules"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

type storedRule struct {
	Path         string            `json:"path"`
	Capabilities []string          `json:"capabilities"`
	Conditions   map[string]string `json:"conditions,omitempty"`
}

func policyToStored(p *StoredPolicy) *storedPolicy {
	rules := make([]*storedRule, len(p.Rules))
	for i, r := range p.Rules {
		caps := make([]string, len(r.Capabilities))
		for j, c := range r.Capabilities {
			caps[j] = string(c)
		}
		rules[i] = &storedRule{
			Path:         r.Path,
			Capabilities: caps,
			Conditions:   r.Conditions,
		}
	}
	return &storedPolicy{
		Name:        p.Name,
		Description: p.Description,
		Rules:       rules,
		CreatedAt:   p.CreatedAt,
		UpdatedAt:   p.UpdatedAt,
	}
}

func storedToPolicy(s *storedPolicy) *StoredPolicy {
	rules := make([]*policy.Rule, len(s.Rules))
	for i, r := range s.Rules {
		caps := make([]policy.Capability, len(r.Capabilities))
		for j, c := range r.Capabilities {
			caps[j] = policy.Capability(c)
		}
		rules[i] = &policy.Rule{
			Path:         r.Path,
			Capabilities: caps,
			Conditions:   r.Conditions,
		}
	}
	return &StoredPolicy{
		Name:        s.Name,
		Description: s.Description,
		Rules:       rules,
		CreatedAt:   s.CreatedAt,
		UpdatedAt:   s.UpdatedAt,
	}
}

func (s *BoltStore) CreatePolicy(ctx context.Context, p *StoredPolicy) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketPolicies)
		if b.Get([]byte(p.Name)) != nil {
			return ErrPolicyExists
		}
		p.CreatedAt = time.Now()
		p.UpdatedAt = p.CreatedAt
		data, err := json.Marshal(policyToStored(p))
		if err != nil {
			return err
		}
		return b.Put([]byte(p.Name), data)
	})
}

func (s *BoltStore) GetPolicy(ctx context.Context, name string) (*StoredPolicy, error) {
	var p *StoredPolicy
	err := s.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketPolicies).Get([]byte(name))
		if data == nil {
			return ErrPolicyNotFound
		}
		var sp storedPolicy
		if err := json.Unmarshal(data, &sp); err != nil {
			return err
		}
		p = storedToPolicy(&sp)
		return nil
	})
	return p, err
}

func (s *BoltStore) UpdatePolicy(ctx context.Context, p *StoredPolicy) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketPolicies)
		if b.Get([]byte(p.Name)) == nil {
			return ErrPolicyNotFound
		}
		p.UpdatedAt = time.Now()
		data, err := json.Marshal(policyToStored(p))
		if err != nil {
			return err
		}
		return b.Put([]byte(p.Name), data)
	})
}

func (s *BoltStore) DeletePolicy(ctx context.Context, name string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketPolicies)
		if b.Get([]byte(name)) == nil {
			return ErrPolicyNotFound
		}
		if name == "default" || name == "admin" {
			return errors.New("cannot delete built-in policy")
		}
		return b.Delete([]byte(name))
	})
}

func (s *BoltStore) ListPolicies(ctx context.Context, limit, offset int) ([]*StoredPolicy, int, error) {
	var all []*StoredPolicy
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketPolicies).ForEach(func(k, v []byte) error {
			var sp storedPolicy
			if err := json.Unmarshal(v, &sp); err != nil {
				return nil
			}
			all = append(all, storedToPolicy(&sp))
			return nil
		})
	})
	if err != nil {
		return nil, 0, err
	}

	sort.Slice(all, func(i, j int) bool { return all[i].Name < all[j].Name })

	total := len(all)
	if offset >= total {
		return []*StoredPolicy{}, total, nil
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return all[offset:end], total, nil
}

// ==================== CredentialRepository ====================

type storedCredential struct {
	Username     string            `json:"username"`
	PasswordHash string            `json:"password_hash"`
	Policies     []string          `json:"policies"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
}

func (s *BoltStore) CreateCredential(ctx context.Context, cred *Credential) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketCredentials)
		if b.Get([]byte(cred.Username)) != nil {
			return ErrCredentialExists
		}
		cred.CreatedAt = time.Now()
		cred.UpdatedAt = cred.CreatedAt
		data, err := json.Marshal(&storedCredential{
			Username:     cred.Username,
			PasswordHash: cred.PasswordHash,
			Policies:     cred.Policies,
			Metadata:     cred.Metadata,
			CreatedAt:    cred.CreatedAt,
			UpdatedAt:    cred.UpdatedAt,
		})
		if err != nil {
			return err
		}
		return b.Put([]byte(cred.Username), data)
	})
}

func (s *BoltStore) GetByUsername(ctx context.Context, username string) (*Credential, error) {
	var cred *Credential
	err := s.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketCredentials).Get([]byte(username))
		if data == nil {
			return ErrCredentialNotFound
		}
		var sc storedCredential
		if err := json.Unmarshal(data, &sc); err != nil {
			return err
		}
		cred = &Credential{
			Username:     sc.Username,
			PasswordHash: sc.PasswordHash,
			Policies:     sc.Policies,
			Metadata:     sc.Metadata,
			CreatedAt:    sc.CreatedAt,
			UpdatedAt:    sc.UpdatedAt,
		}
		return nil
	})
	return cred, err
}

func (s *BoltStore) UpdateCredential(ctx context.Context, cred *Credential) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketCredentials)
		if b.Get([]byte(cred.Username)) == nil {
			return ErrCredentialNotFound
		}
		cred.UpdatedAt = time.Now()
		data, err := json.Marshal(&storedCredential{
			Username:     cred.Username,
			PasswordHash: cred.PasswordHash,
			Policies:     cred.Policies,
			Metadata:     cred.Metadata,
			CreatedAt:    cred.CreatedAt,
			UpdatedAt:    cred.UpdatedAt,
		})
		if err != nil {
			return err
		}
		return b.Put([]byte(cred.Username), data)
	})
}

func (s *BoltStore) DeleteCredential(ctx context.Context, username string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketCredentials)
		if b.Get([]byte(username)) == nil {
			return ErrCredentialNotFound
		}
		return b.Delete([]byte(username))
	})
}

func (s *BoltStore) ListCredentials(ctx context.Context, limit, offset int) ([]*Credential, int, error) {
	var all []*Credential
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketCredentials).ForEach(func(k, v []byte) error {
			var sc storedCredential
			if err := json.Unmarshal(v, &sc); err != nil {
				return nil
			}
			all = append(all, &Credential{
				Username:     sc.Username,
				PasswordHash: sc.PasswordHash,
				Policies:     sc.Policies,
				Metadata:     sc.Metadata,
				CreatedAt:    sc.CreatedAt,
				UpdatedAt:    sc.UpdatedAt,
			})
			return nil
		})
	})
	if err != nil {
		return nil, 0, err
	}

	total := len(all)
	if offset >= total {
		return []*Credential{}, total, nil
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return all[offset:end], total, nil
}

// ==================== Interface Adapters ====================
// BoltStore methods use unique names to avoid Go interface conflicts.
// These adapters expose them under the standard interface signatures.

// TokenStore adapts BoltStore to TokenRepository.
type TokenStore struct{ S *BoltStore }

func (a *TokenStore) Create(ctx context.Context, t *Token) error          { return a.S.Create(ctx, t) }
func (a *TokenStore) Get(ctx context.Context, id string) (*Token, error)  { return a.S.Get(ctx, id) }
func (a *TokenStore) Revoke(ctx context.Context, id string) error         { return a.S.Revoke(ctx, id) }
func (a *TokenStore) UpdateLastUsed(ctx context.Context, id string) error { return a.S.UpdateLastUsed(ctx, id) }
func (a *TokenStore) ListByIdentity(ctx context.Context, identity string, limit, offset int) ([]*Token, int, error) {
	return a.S.ListByIdentity(ctx, identity, limit, offset)
}
func (a *TokenStore) DeleteExpired(ctx context.Context) (int, error) { return a.S.DeleteExpired(ctx) }

// APIKeyStore adapts BoltStore to APIKeyRepository.
type APIKeyStore struct{ S *BoltStore }

func (a *APIKeyStore) Create(ctx context.Context, k *APIKey) error                 { return a.S.CreateAPIKey(ctx, k) }
func (a *APIKeyStore) GetByHash(ctx context.Context, hash string) (*APIKey, error) { return a.S.GetByHash(ctx, hash) }
func (a *APIKeyStore) GetByID(ctx context.Context, id string) (*APIKey, error)     { return a.S.GetByID(ctx, id) }
func (a *APIKeyStore) Revoke(ctx context.Context, id string) error                 { return a.S.RevokeAPIKey(ctx, id) }
func (a *APIKeyStore) UpdateLastUsed(ctx context.Context, id string) error         { return a.S.UpdateAPIKeyLastUsed(ctx, id) }
func (a *APIKeyStore) ListByIdentity(ctx context.Context, identity string, limit, offset int) ([]*APIKey, int, error) {
	return a.S.ListAPIKeysByIdentity(ctx, identity, limit, offset)
}

// PolicyStore adapts BoltStore to PolicyRepository.
type PolicyStore struct{ S *BoltStore }

func (a *PolicyStore) Create(ctx context.Context, p *StoredPolicy) error                 { return a.S.CreatePolicy(ctx, p) }
func (a *PolicyStore) Get(ctx context.Context, name string) (*StoredPolicy, error)       { return a.S.GetPolicy(ctx, name) }
func (a *PolicyStore) Update(ctx context.Context, p *StoredPolicy) error                 { return a.S.UpdatePolicy(ctx, p) }
func (a *PolicyStore) Delete(ctx context.Context, name string) error                     { return a.S.DeletePolicy(ctx, name) }
func (a *PolicyStore) List(ctx context.Context, limit, offset int) ([]*StoredPolicy, int, error) {
	return a.S.ListPolicies(ctx, limit, offset)
}

// CredentialStore adapts BoltStore to CredentialRepository.
type CredentialStore struct{ S *BoltStore }

func (a *CredentialStore) Create(ctx context.Context, c *Credential) error                        { return a.S.CreateCredential(ctx, c) }
func (a *CredentialStore) GetByUsername(ctx context.Context, username string) (*Credential, error) { return a.S.GetByUsername(ctx, username) }
func (a *CredentialStore) Update(ctx context.Context, c *Credential) error                        { return a.S.UpdateCredential(ctx, c) }
func (a *CredentialStore) Delete(ctx context.Context, username string) error                      { return a.S.DeleteCredential(ctx, username) }
func (a *CredentialStore) List(ctx context.Context, limit, offset int) ([]*Credential, int, error) {
	return a.S.ListCredentials(ctx, limit, offset)
}
