// Package auth provides authentication and authorization for the gateway.
// It implements local JWT validation caching and policy evaluation
// to minimize latency overhead (cache hit: <0.1ms, miss: ~5ms).
package auth

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"

	authv1 "github.com/pocketsizefund/microservice-vault/gen/go/auth/v1"
	"github.com/pocketsizefund/microservice-vault/pkg/auth/policy"
	"github.com/pocketsizefund/microservice-vault/pkg/storage/cache"
	"github.com/pocketsizefund/microservice-vault/services/gateway/internal/middleware"
)

// AuthClientImpl implements middleware.AuthClient with high-performance
// local caching and background policy synchronization.
// This replicates Vault's authorization model:
//   - Token validation: cached locally (LRU, 10k entries, 5min TTL)
//   - Policy evaluation: performed locally (synced from auth service every 30s)
//   - No per-request RPC for repeated tokens
type AuthClientImpl struct {
	logger     *zap.Logger
	authClient authv1.AuthServiceClient

	// Caches for authentication results
	tokenCache  *cache.LRUCache[string, *middleware.TokenInfo]
	apiKeyCache *cache.LRUCache[string, *middleware.APIKeyInfo]

	// Local policy evaluator (synced from auth service)
	policyEvaluator *policy.Evaluator
	policySyncMu    sync.RWMutex

	stopCh chan struct{}
}

// AuthClientConfig holds configuration for the auth client
type AuthClientConfig struct {
	AuthConn           *grpc.ClientConn
	TokenCacheSize     int
	TokenCacheTTL      time.Duration
	APIKeyCacheSize    int
	APIKeyCacheTTL     time.Duration
	PolicySyncInterval time.Duration
}

func (c *AuthClientConfig) setDefaults() {
	if c.TokenCacheSize == 0 {
		c.TokenCacheSize = 10000
	}
	if c.TokenCacheTTL == 0 {
		c.TokenCacheTTL = 5 * time.Minute
	}
	if c.APIKeyCacheSize == 0 {
		c.APIKeyCacheSize = 5000
	}
	if c.APIKeyCacheTTL == 0 {
		c.APIKeyCacheTTL = 5 * time.Minute
	}
	if c.PolicySyncInterval == 0 {
		c.PolicySyncInterval = 30 * time.Second
	}
}

// NewAuthClient creates a new auth client with caching and local policy evaluation.
func NewAuthClient(logger *zap.Logger, cfg AuthClientConfig) (*AuthClientImpl, error) {
	cfg.setDefaults()

	tokenCache, err := cache.NewLRUCacheWithTTL[string, *middleware.TokenInfo](
		cfg.TokenCacheSize, cfg.TokenCacheTTL)
	if err != nil {
		return nil, fmt.Errorf("failed to create token cache: %w", err)
	}

	apiKeyCache, err := cache.NewLRUCacheWithTTL[string, *middleware.APIKeyInfo](
		cfg.APIKeyCacheSize, cfg.APIKeyCacheTTL)
	if err != nil {
		return nil, fmt.Errorf("failed to create api key cache: %w", err)
	}

	client := &AuthClientImpl{
		logger:          logger,
		authClient:      authv1.NewAuthServiceClient(cfg.AuthConn),
		tokenCache:      tokenCache,
		apiKeyCache:     apiKeyCache,
		policyEvaluator: policy.NewEvaluator(),
		stopCh:          make(chan struct{}),
	}

	// Initial policy sync (non-blocking on failure)
	if err := client.syncPolicies(context.Background()); err != nil {
		logger.Warn("Initial policy sync failed, will retry in background", zap.Error(err))
	} else {
		logger.Info("Initial policy sync completed")
	}

	// Start background policy sync
	go client.policySyncLoop(cfg.PolicySyncInterval)

	return client, nil
}

// ValidateToken validates a bearer token.
// Fast path: LRU cache hit (<0.1ms)
// Slow path: RPC to auth service (~5ms), then cached
func (c *AuthClientImpl) ValidateToken(ctx context.Context, token string) (*middleware.TokenInfo, error) {
	// Fast path: check cache
	if info, ok := c.tokenCache.Get(token); ok {
		return info, nil
	}

	// Slow path: RPC to auth service
	resp, err := c.authClient.ValidateToken(ctx, &authv1.ValidateTokenRequest{
		Token: token,
	})
	if err != nil {
		return nil, fmt.Errorf("auth service error: %w", err)
	}

	if !resp.Valid {
		return nil, errors.New(resp.ErrorMessage)
	}

	info := &middleware.TokenInfo{
		Subject:   resp.Identity,
		Policies:  resp.Policies,
		Metadata:  resp.Metadata,
		ExpiresAt: resp.ExpiresAt,
	}

	// Cache the result
	c.tokenCache.Set(token, info)

	return info, nil
}

// ValidateAPIKey validates an API key.
// Fast path: LRU cache hit (<0.1ms)
// Slow path: RPC to auth service (~5ms), then cached
func (c *AuthClientImpl) ValidateAPIKey(ctx context.Context, apiKey string) (*middleware.APIKeyInfo, error) {
	// Fast path: check cache
	if info, ok := c.apiKeyCache.Get(apiKey); ok {
		return info, nil
	}

	// Slow path: RPC to auth service
	resp, err := c.authClient.ValidateAPIKey(ctx, &authv1.ValidateAPIKeyRequest{
		ApiKey: apiKey,
	})
	if err != nil {
		return nil, fmt.Errorf("auth service error: %w", err)
	}

	if !resp.Valid {
		return nil, errors.New("invalid API key")
	}

	info := &middleware.APIKeyInfo{
		KeyID:    resp.KeyId,
		Name:     resp.Identity,
		Policies: resp.Policies,
	}

	// Cache the result
	c.apiKeyCache.Set(apiKey, info)

	return info, nil
}

// CheckPermission evaluates policies locally (no RPC).
// Gets the identity's policies from context and evaluates
// against the local policy evaluator.
// Latency: <0.1ms (pure in-memory evaluation)
func (c *AuthClientImpl) CheckPermission(ctx context.Context, identity, resource, action string) (bool, error) {
	// Get policies from the identity context (set by AuthMiddleware)
	identityCtx, ok := middleware.GetIdentity(ctx)
	if !ok {
		return false, errors.New("no identity context")
	}

	capability := policy.ActionToCapability(action)

	c.policySyncMu.RLock()
	allowed := c.policyEvaluator.Check(identityCtx.Policies, resource, capability)
	c.policySyncMu.RUnlock()

	if !allowed {
		c.logger.Debug("Permission denied",
			zap.String("identity", identity),
			zap.String("resource", resource),
			zap.String("action", action),
			zap.Strings("policies", identityCtx.Policies),
		)
	}

	return allowed, nil
}

// syncPolicies fetches all policies from the auth service and rebuilds
// the local policy evaluator. This is called periodically in the background.
func (c *AuthClientImpl) syncPolicies(ctx context.Context) error {
	resp, err := c.authClient.ListPolicies(ctx, &authv1.ListPoliciesRequest{})
	if err != nil {
		return fmt.Errorf("failed to list policies: %w", err)
	}

	// Build a new evaluator with fresh policies
	newEvaluator := policy.NewEvaluator()
	for _, p := range resp.Policies {
		rules := make([]*policy.Rule, len(p.Rules))
		for i, r := range p.Rules {
			caps := make([]policy.Capability, len(r.Capabilities))
			for j, capStr := range r.Capabilities {
				caps[j] = policy.Capability(capStr)
			}
			rules[i] = &policy.Rule{
				Path:         r.Path,
				Capabilities: caps,
				Conditions:   r.Conditions,
			}
		}
		newEvaluator.AddPolicy(&policy.Policy{
			Name:  p.Name,
			Rules: rules,
		})
	}

	// Atomic swap of the evaluator
	c.policySyncMu.Lock()
	c.policyEvaluator = newEvaluator
	c.policySyncMu.Unlock()

	c.logger.Debug("Policy sync completed", zap.Int("policies_count", len(resp.Policies)))
	return nil
}

// policySyncLoop runs the policy sync in background at the configured interval.
func (c *AuthClientImpl) policySyncLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if err := c.syncPolicies(ctx); err != nil {
				c.logger.Warn("Background policy sync failed", zap.Error(err))
			}
			cancel()
		case <-c.stopCh:
			return
		}
	}
}

// Close stops background goroutines.
func (c *AuthClientImpl) Close() {
	close(c.stopCh)
}

// TokenCacheStats returns token cache statistics for monitoring.
func (c *AuthClientImpl) TokenCacheStats() cache.CacheStats {
	return c.tokenCache.Stats()
}

// APIKeyCacheStats returns API key cache statistics for monitoring.
func (c *AuthClientImpl) APIKeyCacheStats() cache.CacheStats {
	return c.apiKeyCache.Stats()
}
