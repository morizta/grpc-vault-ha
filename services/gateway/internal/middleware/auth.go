package middleware

import (
	"context"
	"net/http"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// AuthClient defines the auth service interface
type AuthClient interface {
	ValidateToken(ctx context.Context, token string) (*TokenInfo, error)
	ValidateAPIKey(ctx context.Context, apiKey string) (*APIKeyInfo, error)
	CheckPermission(ctx context.Context, identity, path, action string) (bool, error)
}

// TokenInfo holds validated token information
type TokenInfo struct {
	Subject    string
	Policies   []string
	Metadata   map[string]string
	ExpiresAt  int64
}

// APIKeyInfo holds validated API key information
type APIKeyInfo struct {
	KeyID    string
	Name     string
	Policies []string
}

// IdentityContext holds the authenticated identity
type IdentityContext struct {
	Type       string // "token" or "apikey"
	Subject    string
	Policies   []string
	Metadata   map[string]string
}

type contextKey string

const (
	identityContextKey contextKey = "identity"
)

// AuthMiddleware handles authentication for HTTP requests
type AuthMiddleware struct {
	authClient AuthClient
	skipPaths  map[string]bool
}

// NewAuthMiddleware creates a new auth middleware
func NewAuthMiddleware(authClient AuthClient, skipPaths []string) *AuthMiddleware {
	skip := make(map[string]bool)
	for _, path := range skipPaths {
		skip[path] = true
	}

	return &AuthMiddleware{
		authClient: authClient,
		skipPaths:  skip,
	}
}

// HTTPMiddleware returns an HTTP middleware for authentication
func (m *AuthMiddleware) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip authentication for certain paths
		if m.skipPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}

		identity, err := m.authenticate(r.Context(), r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		// Add identity to context
		ctx := context.WithValue(r.Context(), identityContextKey, identity)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// authenticate validates the request credentials
func (m *AuthMiddleware) authenticate(ctx context.Context, r *http.Request) (*IdentityContext, error) {
	// Check for API key
	if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
		info, err := m.authClient.ValidateAPIKey(ctx, apiKey)
		if err != nil {
			return nil, err
		}

		return &IdentityContext{
			Type:     "apikey",
			Subject:  info.KeyID,
			Policies: info.Policies,
		}, nil
	}

	// Check for Bearer token or X-Vault-Token
	var token string
	if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
		token = strings.TrimPrefix(authHeader, "Bearer ")
	} else if vaultToken := r.Header.Get("X-Vault-Token"); vaultToken != "" {
		token = vaultToken
	}

	if token != "" {
		info, err := m.authClient.ValidateToken(ctx, token)
		if err != nil {
			return nil, err
		}

		return &IdentityContext{
			Type:     "token",
			Subject:  info.Subject,
			Policies: info.Policies,
			Metadata: info.Metadata,
		}, nil
	}

	return nil, status.Error(codes.Unauthenticated, "missing credentials")
}

// GRPCUnaryInterceptor returns a gRPC unary interceptor for authentication
func (m *AuthMiddleware) GRPCUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Skip authentication for certain methods
		if m.skipPaths[info.FullMethod] {
			return handler(ctx, req)
		}

		identity, err := m.authenticateGRPC(ctx)
		if err != nil {
			return nil, err
		}

		ctx = context.WithValue(ctx, identityContextKey, identity)
		return handler(ctx, req)
	}
}

// authenticateGRPC validates gRPC request credentials
func (m *AuthMiddleware) authenticateGRPC(ctx context.Context) (*IdentityContext, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing metadata")
	}

	// Check for API key
	if apiKeys := md.Get("x-api-key"); len(apiKeys) > 0 {
		info, err := m.authClient.ValidateAPIKey(ctx, apiKeys[0])
		if err != nil {
			return nil, err
		}

		return &IdentityContext{
			Type:     "apikey",
			Subject:  info.KeyID,
			Policies: info.Policies,
		}, nil
	}

	// Check for Bearer token
	if authHeaders := md.Get("authorization"); len(authHeaders) > 0 {
		authHeader := authHeaders[0]
		if strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")

			info, err := m.authClient.ValidateToken(ctx, token)
			if err != nil {
				return nil, err
			}

			return &IdentityContext{
				Type:     "token",
				Subject:  info.Subject,
				Policies: info.Policies,
				Metadata: info.Metadata,
			}, nil
		}
	}

	return nil, status.Error(codes.Unauthenticated, "missing credentials")
}

// GetIdentity retrieves identity from context
func GetIdentity(ctx context.Context) (*IdentityContext, bool) {
	identity, ok := ctx.Value(identityContextKey).(*IdentityContext)
	return identity, ok
}

// RequirePermission returns middleware that checks permissions
func (m *AuthMiddleware) RequirePermission(path, action string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			identity, ok := GetIdentity(r.Context())
			if !ok {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			allowed, err := m.authClient.CheckPermission(r.Context(), identity.Subject, path, action)
			if err != nil {
				http.Error(w, "Permission check failed", http.StatusInternalServerError)
				return
			}

			if !allowed {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
