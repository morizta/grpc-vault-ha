package repository

import (
	"context"
	"errors"
	"time"
)

var (
	ErrSecretNotFound = errors.New("secret not found")
	ErrSealStateNotFound = errors.New("seal state not found")
	ErrKeyringNotFound = errors.New("keyring data not found")
)

// Secret represents a stored secret
type Secret struct {
	Data           map[string][]byte `json:"data"`
	Version        int               `json:"version"`
	CreatedAt      time.Time         `json:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at"`
	CustomMetadata map[string]string `json:"custom_metadata,omitempty"`
}

// SealState represents persisted seal/init state
type SealState struct {
	MasterKey   []byte   `json:"master_key"`
	BarrierKey  []byte   `json:"barrier_key"`
	ShamirKeys  [][]byte `json:"shamir_keys"`
	Threshold   int      `json:"threshold"`
	Initialized bool     `json:"initialized"`
}

// SecretRepository defines secret storage operations
type SecretRepository interface {
	Put(ctx context.Context, path string, secret *Secret) error
	Get(ctx context.Context, path string) (*Secret, error)
	Delete(ctx context.Context, path string) error
	List(ctx context.Context, prefix string) ([]string, error)
}

// SealStateRepository defines seal state persistence
type SealStateRepository interface {
	Save(ctx context.Context, state *SealState) error
	Load(ctx context.Context) (*SealState, error)
}

// KeyringRepository defines keyring blob persistence
type KeyringRepository interface {
	Save(ctx context.Context, data []byte) error
	Load(ctx context.Context) ([]byte, error)
}
