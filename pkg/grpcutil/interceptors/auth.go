// Package interceptors provides gRPC interceptors
package interceptors

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type contextKey string

const (
	// AuthorizationHeader is the metadata key for authorization
	AuthorizationHeader = "authorization"
	// BearerPrefix is the prefix for bearer tokens
	BearerPrefix = "bearer "
	// TokenKey is the context key for the extracted token
	TokenKey contextKey = "token"
	// IdentityKey is the context key for the identity
	IdentityKey contextKey = "identity"
	// PoliciesKey is the context key for the policies
	PoliciesKey contextKey = "policies"
)

// TokenValidator validates tokens and returns identity and policies
type TokenValidator interface {
	Validate(ctx context.Context, token string) (identity string, policies []string, err error)
}

// AuthInterceptor creates an authentication interceptor
func AuthInterceptor(validator TokenValidator, skipMethods ...string) grpc.UnaryServerInterceptor {
	skipSet := make(map[string]bool)
	for _, method := range skipMethods {
		skipSet[method] = true
	}

	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Skip authentication for specified methods
		if skipSet[info.FullMethod] {
			return handler(ctx, req)
		}

		// Extract token from metadata
		token, err := extractToken(ctx)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, err.Error())
		}

		// Validate token
		identity, policies, err := validator.Validate(ctx, token)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "invalid token")
		}

		// Add to context
		ctx = context.WithValue(ctx, TokenKey, token)
		ctx = context.WithValue(ctx, IdentityKey, identity)
		ctx = context.WithValue(ctx, PoliciesKey, policies)

		return handler(ctx, req)
	}
}

// StreamAuthInterceptor creates a streaming authentication interceptor
func StreamAuthInterceptor(validator TokenValidator, skipMethods ...string) grpc.StreamServerInterceptor {
	skipSet := make(map[string]bool)
	for _, method := range skipMethods {
		skipSet[method] = true
	}

	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		// Skip authentication for specified methods
		if skipSet[info.FullMethod] {
			return handler(srv, ss)
		}

		ctx := ss.Context()

		// Extract token from metadata
		token, err := extractToken(ctx)
		if err != nil {
			return status.Error(codes.Unauthenticated, err.Error())
		}

		// Validate token
		identity, policies, err := validator.Validate(ctx, token)
		if err != nil {
			return status.Error(codes.Unauthenticated, "invalid token")
		}

		// Create wrapped stream with new context
		ctx = context.WithValue(ctx, TokenKey, token)
		ctx = context.WithValue(ctx, IdentityKey, identity)
		ctx = context.WithValue(ctx, PoliciesKey, policies)

		wrapped := &wrappedStream{ss, ctx}

		return handler(srv, wrapped)
	}
}

// extractToken extracts the bearer token from gRPC metadata
func extractToken(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "missing metadata")
	}

	values := md.Get(AuthorizationHeader)
	if len(values) == 0 {
		return "", status.Error(codes.Unauthenticated, "missing authorization header")
	}

	auth := values[0]
	if !strings.HasPrefix(strings.ToLower(auth), BearerPrefix) {
		return "", status.Error(codes.Unauthenticated, "invalid authorization format")
	}

	return auth[len(BearerPrefix):], nil
}

// GetIdentity extracts identity from context
func GetIdentity(ctx context.Context) (string, bool) {
	identity, ok := ctx.Value(IdentityKey).(string)
	return identity, ok
}

// GetPolicies extracts policies from context
func GetPolicies(ctx context.Context) ([]string, bool) {
	policies, ok := ctx.Value(PoliciesKey).([]string)
	return policies, ok
}

// GetToken extracts token from context
func GetToken(ctx context.Context) (string, bool) {
	token, ok := ctx.Value(TokenKey).(string)
	return token, ok
}

// wrappedStream wraps a ServerStream with a custom context
type wrappedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedStream) Context() context.Context {
	return w.ctx
}
