package handler

import (
	"context"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/pocketsizefund/microservice-vault/gen/go/auth/v1"
	"github.com/pocketsizefund/microservice-vault/pkg/auth/policy"
	"github.com/pocketsizefund/microservice-vault/services/auth/internal/repository"
	"github.com/pocketsizefund/microservice-vault/services/auth/internal/service"
)

type AuthHandler struct {
	authv1.UnimplementedAuthServiceServer
	service *service.AuthService
	logger  *zap.Logger
}

func NewAuthHandler(svc *service.AuthService, logger *zap.Logger) *AuthHandler {
	return &AuthHandler{
		service: svc,
		logger:  logger,
	}
}

func (h *AuthHandler) Register(server *grpc.Server) {
	authv1.RegisterAuthServiceServer(server, h)
}

// CreateToken creates a new JWT token
func (h *AuthHandler) CreateToken(ctx context.Context, req *authv1.CreateTokenRequest) (*authv1.CreateTokenResponse, error) {
	if req.Identity == "" {
		return nil, status.Error(codes.InvalidArgument, "identity is required")
	}

	ttl := time.Duration(req.TtlSeconds) * time.Second

	token, tokenID, expiresAt, err := h.service.CreateToken(ctx, req.Identity, req.Policies, ttl, req.Metadata)
	if err != nil {
		h.logger.Error("Failed to create token", zap.Error(err))
		return nil, status.Error(codes.Internal, "failed to create token")
	}

	return &authv1.CreateTokenResponse{
		Token:     token,
		TokenId:   tokenID,
		ExpiresAt: expiresAt.Unix(),
		Policies:  req.Policies,
	}, nil
}

// ValidateToken validates a JWT token
func (h *AuthHandler) ValidateToken(ctx context.Context, req *authv1.ValidateTokenRequest) (*authv1.ValidateTokenResponse, error) {
	if req.Token == "" {
		return nil, status.Error(codes.InvalidArgument, "token is required")
	}

	var claims interface{}
	var err error

	if req.Resource != "" && req.Action != "" {
		claims, err = h.service.ValidateTokenWithPolicy(ctx, req.Token, req.Resource, req.Action)
	} else {
		claims, err = h.service.ValidateToken(ctx, req.Token)
	}

	if err != nil {
		if err == service.ErrInvalidToken || err == service.ErrTokenExpired {
			return &authv1.ValidateTokenResponse{
				Valid:        false,
				ErrorMessage: err.Error(),
			}, nil
		}
		if err == service.ErrPermissionDenied {
			return &authv1.ValidateTokenResponse{
				Valid:        false,
				ErrorMessage: "permission denied",
			}, nil
		}
		return nil, status.Error(codes.Internal, "validation failed")
	}

	// Type assertion
	jwtClaims := claims.(interface {
		GetIdentity() string
		GetTokenID() string
		GetPolicies() []string
		GetMetadata() map[string]string
		GetExpiresAt() int64
	})

	return &authv1.ValidateTokenResponse{
		Valid:     true,
		Identity:  jwtClaims.GetIdentity(),
		TokenId:   jwtClaims.GetTokenID(),
		Policies:  jwtClaims.GetPolicies(),
		Metadata:  jwtClaims.GetMetadata(),
		ExpiresAt: jwtClaims.GetExpiresAt(),
	}, nil
}

// RevokeToken revokes a token
func (h *AuthHandler) RevokeToken(ctx context.Context, req *authv1.RevokeTokenRequest) (*authv1.RevokeTokenResponse, error) {
	if req.TokenId == "" {
		return nil, status.Error(codes.InvalidArgument, "token_id is required")
	}

	err := h.service.RevokeToken(ctx, req.TokenId)
	if err != nil {
		if err == repository.ErrTokenNotFound {
			return nil, status.Error(codes.NotFound, "token not found")
		}
		return nil, status.Error(codes.Internal, "failed to revoke token")
	}

	return &authv1.RevokeTokenResponse{Success: true}, nil
}

// RefreshToken refreshes a token
func (h *AuthHandler) RefreshToken(ctx context.Context, req *authv1.RefreshTokenRequest) (*authv1.RefreshTokenResponse, error) {
	if req.Token == "" {
		return nil, status.Error(codes.InvalidArgument, "token is required")
	}

	// Validate existing token first
	claims, err := h.service.ValidateToken(ctx, req.Token)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid token")
	}

	ttl := time.Duration(req.TtlSeconds) * time.Second
	if ttl == 0 {
		ttl = time.Hour // Default 1 hour
	}

	newToken, tokenID, expiresAt, err := h.service.CreateToken(ctx, claims.Identity, claims.Policies, ttl, claims.Metadata)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to refresh token")
	}

	return &authv1.RefreshTokenResponse{
		Token:     newToken,
		TokenId:   tokenID,
		ExpiresAt: expiresAt.Unix(),
	}, nil
}

// ListTokens lists active tokens
func (h *AuthHandler) ListTokens(ctx context.Context, req *authv1.ListTokensRequest) (*authv1.ListTokensResponse, error) {
	// Simplified - returns empty for now
	return &authv1.ListTokensResponse{
		Tokens: []*authv1.TokenInfo{},
	}, nil
}

// CreateAPIKey creates a new API key
func (h *AuthHandler) CreateAPIKey(ctx context.Context, req *authv1.CreateAPIKeyRequest) (*authv1.CreateAPIKeyResponse, error) {
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if req.Identity == "" {
		return nil, status.Error(codes.InvalidArgument, "identity is required")
	}

	ttl := time.Duration(req.TtlSeconds) * time.Second

	apiKey, keyID, err := h.service.CreateAPIKey(ctx, req.Name, req.Identity, req.Policies, ttl, req.Metadata)
	if err != nil {
		h.logger.Error("Failed to create API key", zap.Error(err))
		return nil, status.Error(codes.Internal, "failed to create API key")
	}

	return &authv1.CreateAPIKeyResponse{
		ApiKey: apiKey,
		KeyId:  keyID,
	}, nil
}

// ValidateAPIKey validates an API key
func (h *AuthHandler) ValidateAPIKey(ctx context.Context, req *authv1.ValidateAPIKeyRequest) (*authv1.ValidateAPIKeyResponse, error) {
	if req.ApiKey == "" {
		return nil, status.Error(codes.InvalidArgument, "api_key is required")
	}

	key, err := h.service.ValidateAPIKey(ctx, req.ApiKey)
	if err != nil {
		return &authv1.ValidateAPIKeyResponse{
			Valid:        false,
			ErrorMessage: "invalid API key",
		}, nil
	}

	return &authv1.ValidateAPIKeyResponse{
		Valid:    true,
		Identity: key.Identity,
		KeyId:    key.ID,
		Policies: key.Policies,
	}, nil
}

// RevokeAPIKey revokes an API key
func (h *AuthHandler) RevokeAPIKey(ctx context.Context, req *authv1.RevokeAPIKeyRequest) (*authv1.RevokeAPIKeyResponse, error) {
	if req.KeyId == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}

	err := h.service.RevokeAPIKey(ctx, req.KeyId)
	if err != nil {
		if err == repository.ErrAPIKeyNotFound {
			return nil, status.Error(codes.NotFound, "API key not found")
		}
		return nil, status.Error(codes.Internal, "failed to revoke API key")
	}

	return &authv1.RevokeAPIKeyResponse{Success: true}, nil
}

// ListAPIKeys lists API keys
func (h *AuthHandler) ListAPIKeys(ctx context.Context, req *authv1.ListAPIKeysRequest) (*authv1.ListAPIKeysResponse, error) {
	// Simplified - returns empty for now
	return &authv1.ListAPIKeysResponse{
		ApiKeys: []*authv1.APIKeyInfo{},
	}, nil
}

// CreatePolicy creates a new policy
func (h *AuthHandler) CreatePolicy(ctx context.Context, req *authv1.CreatePolicyRequest) (*authv1.CreatePolicyResponse, error) {
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}

	rules := make([]*policy.Rule, len(req.Rules))
	for i, r := range req.Rules {
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

	err := h.service.CreatePolicy(ctx, req.Name, req.Description, rules)
	if err != nil {
		if err == repository.ErrPolicyExists {
			return nil, status.Error(codes.AlreadyExists, "policy already exists")
		}
		return nil, status.Error(codes.Internal, "failed to create policy")
	}

	return &authv1.CreatePolicyResponse{
		Name:      req.Name,
		CreatedAt: time.Now().Unix(),
	}, nil
}

// GetPolicy returns a policy
func (h *AuthHandler) GetPolicy(ctx context.Context, req *authv1.GetPolicyRequest) (*authv1.GetPolicyResponse, error) {
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}

	p, err := h.service.GetPolicy(ctx, req.Name)
	if err != nil {
		if err == repository.ErrPolicyNotFound {
			return nil, status.Error(codes.NotFound, "policy not found")
		}
		return nil, status.Error(codes.Internal, "failed to get policy")
	}

	rules := make([]*authv1.PolicyRule, len(p.Rules))
	for i, r := range p.Rules {
		caps := make([]string, len(r.Capabilities))
		for j, c := range r.Capabilities {
			caps[j] = string(c)
		}
		rules[i] = &authv1.PolicyRule{
			Path:         r.Path,
			Capabilities: caps,
			Conditions:   r.Conditions,
		}
	}

	return &authv1.GetPolicyResponse{
		Policy: &authv1.Policy{
			Name:        p.Name,
			Description: p.Description,
			Rules:       rules,
			CreatedAt:   p.CreatedAt.Unix(),
			UpdatedAt:   p.UpdatedAt.Unix(),
		},
	}, nil
}

// UpdatePolicy updates a policy
func (h *AuthHandler) UpdatePolicy(ctx context.Context, req *authv1.UpdatePolicyRequest) (*authv1.UpdatePolicyResponse, error) {
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}

	rules := make([]*policy.Rule, len(req.Rules))
	for i, r := range req.Rules {
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

	err := h.service.UpdatePolicy(ctx, req.Name, req.Description, rules)
	if err != nil {
		if err == repository.ErrPolicyNotFound {
			return nil, status.Error(codes.NotFound, "policy not found")
		}
		return nil, status.Error(codes.Internal, "failed to update policy")
	}

	return &authv1.UpdatePolicyResponse{
		Name:      req.Name,
		UpdatedAt: time.Now().Unix(),
	}, nil
}

// DeletePolicy deletes a policy
func (h *AuthHandler) DeletePolicy(ctx context.Context, req *authv1.DeletePolicyRequest) (*authv1.DeletePolicyResponse, error) {
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}

	err := h.service.DeletePolicy(ctx, req.Name)
	if err != nil {
		if err == repository.ErrPolicyNotFound {
			return nil, status.Error(codes.NotFound, "policy not found")
		}
		return nil, status.Error(codes.Internal, "failed to delete policy")
	}

	return &authv1.DeletePolicyResponse{Success: true}, nil
}

// ListPolicies lists all policies
func (h *AuthHandler) ListPolicies(ctx context.Context, req *authv1.ListPoliciesRequest) (*authv1.ListPoliciesResponse, error) {
	storedPolicies, _, err := h.service.ListPolicies(ctx, 1000, 0)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to list policies")
	}

	policies := make([]*authv1.Policy, len(storedPolicies))
	for i, p := range storedPolicies {
		rules := make([]*authv1.PolicyRule, len(p.Rules))
		for j, r := range p.Rules {
			caps := make([]string, len(r.Capabilities))
			for k, c := range r.Capabilities {
				caps[k] = string(c)
			}
			rules[j] = &authv1.PolicyRule{
				Path:         r.Path,
				Capabilities: caps,
				Conditions:   r.Conditions,
			}
		}
		policies[i] = &authv1.Policy{
			Name:        p.Name,
			Description: p.Description,
			Rules:       rules,
			CreatedAt:   p.CreatedAt.Unix(),
			UpdatedAt:   p.UpdatedAt.Unix(),
		}
	}

	return &authv1.ListPoliciesResponse{
		Policies: policies,
	}, nil
}

// EvaluatePolicy evaluates if policies allow an action
func (h *AuthHandler) EvaluatePolicy(ctx context.Context, req *authv1.EvaluatePolicyRequest) (*authv1.EvaluatePolicyResponse, error) {
	if len(req.Policies) == 0 {
		return nil, status.Error(codes.InvalidArgument, "policies is required")
	}
	if req.Resource == "" {
		return nil, status.Error(codes.InvalidArgument, "resource is required")
	}
	if req.Action == "" {
		return nil, status.Error(codes.InvalidArgument, "action is required")
	}

	result := h.service.EvaluatePolicy(ctx, req.Policies, req.Resource, req.Action, req.Context)

	return &authv1.EvaluatePolicyResponse{
		Allowed:      result.Allowed,
		MatchedRule:  result.MatchedRule,
		DenialReason: result.DenialReason,
	}, nil
}
