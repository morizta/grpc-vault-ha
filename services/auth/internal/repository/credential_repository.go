package repository

import (
	"context"
	"errors"
	"time"
)

var (
	ErrCredentialNotFound = errors.New("credential not found")
	ErrCredentialExists   = errors.New("credential already exists")
)

// Credential represents a stored user credential
type Credential struct {
	Username     string
	PasswordHash string // bcrypt
	Policies     []string
	Metadata     map[string]string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// CredentialRepository defines credential storage operations
type CredentialRepository interface {
	Create(ctx context.Context, cred *Credential) error
	GetByUsername(ctx context.Context, username string) (*Credential, error)
	Update(ctx context.Context, cred *Credential) error
	Delete(ctx context.Context, username string) error
	List(ctx context.Context, limit, offset int) ([]*Credential, int, error)
}
