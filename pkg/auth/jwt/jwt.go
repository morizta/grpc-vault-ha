// Package jwt provides JWT token generation and validation
package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var (
	ErrInvalidToken     = errors.New("invalid token")
	ErrExpiredToken     = errors.New("token has expired")
	ErrInvalidSignature = errors.New("invalid signature")
	ErrInvalidClaims    = errors.New("invalid claims")
)

// Claims represents the JWT claims
type Claims struct {
	jwt.RegisteredClaims
	Identity   string            `json:"identity"`
	TokenID    string            `json:"jti"`
	Policies   []string          `json:"policies"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// Manager handles JWT operations
type Manager struct {
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
	issuer     string
	audience   string
	defaultTTL time.Duration
	maxTTL     time.Duration
}

// Config holds JWT manager configuration
type Config struct {
	PrivateKey *ecdsa.PrivateKey
	Issuer     string
	Audience   string
	DefaultTTL time.Duration
	MaxTTL     time.Duration
}

// NewManager creates a new JWT manager
func NewManager(cfg Config) (*Manager, error) {
	if cfg.PrivateKey == nil {
		// Generate a new key if not provided
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		cfg.PrivateKey = key
	}

	if cfg.Issuer == "" {
		cfg.Issuer = "vault-auth"
	}

	if cfg.Audience == "" {
		cfg.Audience = "vault-platform"
	}

	if cfg.DefaultTTL == 0 {
		cfg.DefaultTTL = time.Hour
	}

	if cfg.MaxTTL == 0 {
		cfg.MaxTTL = 24 * time.Hour
	}

	return &Manager{
		privateKey: cfg.PrivateKey,
		publicKey:  &cfg.PrivateKey.PublicKey,
		issuer:     cfg.Issuer,
		audience:   cfg.Audience,
		defaultTTL: cfg.DefaultTTL,
		maxTTL:     cfg.MaxTTL,
	}, nil
}

// CreateToken generates a new JWT token
func (m *Manager) CreateToken(identity string, policies []string, ttl time.Duration, metadata map[string]string) (string, string, time.Time, error) {
	// Validate and adjust TTL
	if ttl <= 0 {
		ttl = m.defaultTTL
	}
	if ttl > m.maxTTL {
		ttl = m.maxTTL
	}

	now := time.Now()
	expiresAt := now.Add(ttl)
	tokenID := uuid.New().String()

	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Audience:  jwt.ClaimStrings{m.audience},
			Subject:   identity,
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        tokenID,
		},
		Identity: identity,
		TokenID:  tokenID,
		Policies: policies,
		Metadata: metadata,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tokenString, err := token.SignedString(m.privateKey)
	if err != nil {
		return "", "", time.Time{}, err
	}

	return tokenString, tokenID, expiresAt, nil
}

// ValidateToken validates a JWT token and returns the claims
func (m *Manager) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, ErrInvalidSignature
		}
		return m.publicKey, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidClaims
	}

	return claims, nil
}

// RefreshToken creates a new token based on existing claims
func (m *Manager) RefreshToken(tokenString string, newTTL time.Duration) (string, string, time.Time, error) {
	claims, err := m.ValidateToken(tokenString)
	if err != nil && !errors.Is(err, ErrExpiredToken) {
		return "", "", time.Time{}, err
	}

	return m.CreateToken(claims.Identity, claims.Policies, newTTL, claims.Metadata)
}

// GetPublicKey returns the public key for external validation
func (m *Manager) GetPublicKey() *ecdsa.PublicKey {
	return m.publicKey
}

// ParseUnverified parses a token without verifying the signature
// Useful for extracting claims from expired tokens
func ParseUnverified(tokenString string) (*Claims, error) {
	token, _, err := jwt.NewParser().ParseUnverified(tokenString, &Claims{})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, ErrInvalidClaims
	}

	return claims, nil
}
