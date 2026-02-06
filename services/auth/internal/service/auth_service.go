package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"go.uber.org/zap"

	"github.com/pocketsizefund/microservice-vault/pkg/auth/jwt"
	"github.com/pocketsizefund/microservice-vault/pkg/auth/policy"
	"github.com/pocketsizefund/microservice-vault/pkg/storage/cache"
	"github.com/pocketsizefund/microservice-vault/services/auth/internal/config"
	"github.com/pocketsizefund/microservice-vault/services/auth/internal/repository"
)

var (
	ErrInvalidToken       = errors.New("invalid token")
	ErrTokenExpired       = errors.New("token expired")
	ErrInvalidAPIKey      = errors.New("invalid API key")
	ErrPolicyNotFound     = errors.New("policy not found")
	ErrPermissionDenied   = errors.New("permission denied")
)

// AuthService handles authentication and authorization
type AuthService struct {
	config     *config.Config
	logger     *zap.Logger
	jwtManager *jwt.Manager

	// Repositories
	tokenRepo  repository.TokenRepository
	apiKeyRepo repository.APIKeyRepository
	policyRepo repository.PolicyRepository

	// Caches
	tokenCache  *cache.LRUCache[string, *jwt.Claims]
	policyCache *cache.LRUCache[string, *policy.Policy]

	// Policy evaluator
	policyEvaluator *policy.Evaluator
}

// NewAuthService creates a new auth service
func NewAuthService(
	cfg *config.Config,
	logger *zap.Logger,
	tokenRepo repository.TokenRepository,
	apiKeyRepo repository.APIKeyRepository,
	policyRepo repository.PolicyRepository,
) (*AuthService, error) {
	// Create JWT manager
	jwtManager, err := jwt.NewManager(jwt.Config{
		Issuer:     cfg.JWT.Issuer,
		Audience:   cfg.JWT.Audience,
		DefaultTTL: cfg.JWT.DefaultTTL,
		MaxTTL:     cfg.JWT.MaxTTL,
	})
	if err != nil {
		return nil, err
	}

	// Create caches
	tokenCache, err := cache.NewLRUCacheWithTTL[string, *jwt.Claims](cfg.Cache.L1Size, cfg.Cache.L2TTL)
	if err != nil {
		return nil, err
	}

	policyCache, err := cache.NewLRUCacheWithTTL[string, *policy.Policy](1000, 5*time.Minute)
	if err != nil {
		return nil, err
	}

	// Create policy evaluator
	policyEvaluator := policy.NewEvaluator()

	// Load policies into evaluator
	policies, _, _ := policyRepo.List(context.Background(), 1000, 0)
	for _, p := range policies {
		policyEvaluator.AddPolicy(&policy.Policy{
			Name:  p.Name,
			Rules: p.Rules,
		})
	}

	return &AuthService{
		config:          cfg,
		logger:          logger,
		jwtManager:      jwtManager,
		tokenRepo:       tokenRepo,
		apiKeyRepo:      apiKeyRepo,
		policyRepo:      policyRepo,
		tokenCache:      tokenCache,
		policyCache:     policyCache,
		policyEvaluator: policyEvaluator,
	}, nil
}

// CreateToken creates a new JWT token
func (s *AuthService) CreateToken(ctx context.Context, identity string, policies []string, ttl time.Duration, metadata map[string]string) (string, string, time.Time, error) {
	// Ensure default policy is included
	hasDefault := false
	for _, p := range policies {
		if p == "default" {
			hasDefault = true
			break
		}
	}
	if !hasDefault {
		policies = append(policies, "default")
	}

	// Create JWT
	token, tokenID, expiresAt, err := s.jwtManager.CreateToken(identity, policies, ttl, metadata)
	if err != nil {
		return "", "", time.Time{}, err
	}

	// Store token record
	err = s.tokenRepo.Create(ctx, &repository.Token{
		ID:        tokenID,
		Identity:  identity,
		Policies:  policies,
		Metadata:  metadata,
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
	})
	if err != nil {
		s.logger.Warn("Failed to store token record", zap.Error(err))
		// Continue - token is still valid
	}

	s.logger.Info("Token created",
		zap.String("identity", identity),
		zap.String("token_id", tokenID),
		zap.Strings("policies", policies),
	)

	return token, tokenID, expiresAt, nil
}

// ValidateToken validates a JWT token
func (s *AuthService) ValidateToken(ctx context.Context, tokenString string) (*jwt.Claims, error) {
	// Check cache first
	if claims, ok := s.tokenCache.Get(tokenString); ok {
		return claims, nil
	}

	// Validate JWT
	claims, err := s.jwtManager.ValidateToken(tokenString)
	if err != nil {
		if errors.Is(err, jwt.ErrExpiredToken) {
			return nil, ErrTokenExpired
		}
		return nil, ErrInvalidToken
	}

	// Check if token is revoked
	_, err = s.tokenRepo.Get(ctx, claims.TokenID)
	if err != nil {
		if errors.Is(err, repository.ErrTokenRevoked) {
			return nil, ErrInvalidToken
		}
		// Token might not be stored (e.g., during migration)
		// Continue with validation
	}

	// Update last used
	go s.tokenRepo.UpdateLastUsed(context.Background(), claims.TokenID)

	// Cache the claims
	s.tokenCache.Set(tokenString, claims)

	return claims, nil
}

// ValidateTokenWithPolicy validates token and checks policy
func (s *AuthService) ValidateTokenWithPolicy(ctx context.Context, tokenString, resource, action string) (*jwt.Claims, error) {
	claims, err := s.ValidateToken(ctx, tokenString)
	if err != nil {
		return nil, err
	}

	// Check policy
	capability := policy.ActionToCapability(action)
	if !s.policyEvaluator.Check(claims.Policies, resource, capability) {
		return nil, ErrPermissionDenied
	}

	return claims, nil
}

// RevokeToken revokes a token
func (s *AuthService) RevokeToken(ctx context.Context, tokenID string) error {
	err := s.tokenRepo.Revoke(ctx, tokenID)
	if err != nil {
		return err
	}

	s.logger.Info("Token revoked", zap.String("token_id", tokenID))
	return nil
}

// CreateAPIKey creates a new API key
func (s *AuthService) CreateAPIKey(ctx context.Context, name, identity string, policies []string, ttl time.Duration, metadata map[string]string) (string, string, error) {
	// Generate random API key
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return "", "", err
	}
	apiKey := "vk_" + base64.URLEncoding.EncodeToString(keyBytes)

	// Hash the key for storage
	keyHash := repository.HashAPIKey(apiKey)

	// Calculate expiration
	var expiresAt *time.Time
	if ttl > 0 {
		exp := time.Now().Add(ttl)
		expiresAt = &exp
	}

	// Generate ID
	idBytes := make([]byte, 16)
	rand.Read(idBytes)
	keyID := base64.URLEncoding.EncodeToString(idBytes)

	// Store API key
	err := s.apiKeyRepo.Create(ctx, &repository.APIKey{
		ID:        keyID,
		Name:      name,
		KeyHash:   keyHash,
		Identity:  identity,
		Policies:  policies,
		Metadata:  metadata,
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
	})
	if err != nil {
		return "", "", err
	}

	s.logger.Info("API key created",
		zap.String("key_id", keyID),
		zap.String("name", name),
		zap.String("identity", identity),
	)

	return apiKey, keyID, nil
}

// ValidateAPIKey validates an API key
func (s *AuthService) ValidateAPIKey(ctx context.Context, apiKey string) (*repository.APIKey, error) {
	keyHash := repository.HashAPIKey(apiKey)

	key, err := s.apiKeyRepo.GetByHash(ctx, keyHash)
	if err != nil {
		return nil, ErrInvalidAPIKey
	}

	// Update last used
	go s.apiKeyRepo.UpdateLastUsed(context.Background(), key.ID)

	return key, nil
}

// RevokeAPIKey revokes an API key
func (s *AuthService) RevokeAPIKey(ctx context.Context, keyID string) error {
	err := s.apiKeyRepo.Revoke(ctx, keyID)
	if err != nil {
		return err
	}

	s.logger.Info("API key revoked", zap.String("key_id", keyID))
	return nil
}

// CreatePolicy creates a new policy
func (s *AuthService) CreatePolicy(ctx context.Context, name, description string, rules []*policy.Rule) error {
	storedPolicy := &repository.StoredPolicy{
		Name:        name,
		Description: description,
		Rules:       rules,
	}

	if err := s.policyRepo.Create(ctx, storedPolicy); err != nil {
		return err
	}

	// Add to evaluator
	s.policyEvaluator.AddPolicy(&policy.Policy{
		Name:  name,
		Rules: rules,
	})

	// Clear cache
	s.policyCache.Delete(name)

	s.logger.Info("Policy created", zap.String("name", name))
	return nil
}

// GetPolicy returns a policy by name
func (s *AuthService) GetPolicy(ctx context.Context, name string) (*repository.StoredPolicy, error) {
	return s.policyRepo.Get(ctx, name)
}

// UpdatePolicy updates a policy
func (s *AuthService) UpdatePolicy(ctx context.Context, name, description string, rules []*policy.Rule) error {
	storedPolicy := &repository.StoredPolicy{
		Name:        name,
		Description: description,
		Rules:       rules,
	}

	if err := s.policyRepo.Update(ctx, storedPolicy); err != nil {
		return err
	}

	// Update evaluator
	s.policyEvaluator.AddPolicy(&policy.Policy{
		Name:  name,
		Rules: rules,
	})

	// Clear cache
	s.policyCache.Delete(name)

	s.logger.Info("Policy updated", zap.String("name", name))
	return nil
}

// DeletePolicy deletes a policy
func (s *AuthService) DeletePolicy(ctx context.Context, name string) error {
	if err := s.policyRepo.Delete(ctx, name); err != nil {
		return err
	}

	s.policyEvaluator.RemovePolicy(name)
	s.policyCache.Delete(name)

	s.logger.Info("Policy deleted", zap.String("name", name))
	return nil
}

// ListPolicies lists all policies
func (s *AuthService) ListPolicies(ctx context.Context, limit, offset int) ([]*repository.StoredPolicy, int, error) {
	return s.policyRepo.List(ctx, limit, offset)
}

// EvaluatePolicy evaluates if policies allow an action
func (s *AuthService) EvaluatePolicy(ctx context.Context, policies []string, resource, action string, context map[string]string) *policy.EvaluationResult {
	capability := policy.ActionToCapability(action)
	return s.policyEvaluator.Evaluate(policies, resource, capability, context)
}

// ListTokens lists tokens for an identity
func (s *AuthService) ListTokens(ctx context.Context, identity string, limit, offset int) ([]*repository.Token, int, error) {
	return s.tokenRepo.ListByIdentity(ctx, identity, limit, offset)
}

// ListAPIKeys lists API keys for an identity
func (s *AuthService) ListAPIKeys(ctx context.Context, identity string, limit, offset int) ([]*repository.APIKey, int, error) {
	return s.apiKeyRepo.ListByIdentity(ctx, identity, limit, offset)
}
