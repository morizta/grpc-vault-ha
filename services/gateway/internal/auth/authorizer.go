package auth

import (
	"encoding/json"
	"net/http"
	"strings"

	"go.uber.org/zap"

	"github.com/pocketsizefund/microservice-vault/services/gateway/internal/middleware"
)

// routePolicy maps a route to a resource path and action for policy evaluation.
type routePolicy struct {
	Resource string
	Action   string
}

// routePolicies maps HTTP path -> method -> policy check.
// This replicates Vault's path-based ACL model where each API endpoint
// is mapped to a policy resource path and capability.
var routePolicies = map[string]map[string]routePolicy{
	// Crypto endpoints
	"/v1/crypto/encrypt": {
		"POST": {Resource: "crypto/encrypt", Action: "create"},
	},
	"/v1/crypto/decrypt": {
		"POST": {Resource: "crypto/decrypt", Action: "create"},
	},

	// Tokenize endpoints
	"/v1/tokenize/encode": {
		"POST": {Resource: "tokenize/encode", Action: "create"},
	},
	"/v1/tokenize/decode": {
		"POST": {Resource: "tokenize/decode", Action: "create"},
	},

	// Secret endpoints
	"/v1/secret/data": {
		"GET":  {Resource: "secret/data", Action: "read"},
		"POST": {Resource: "secret/data", Action: "create"},
	},

	// Transit (key management) endpoints
	"/v1/transit/keys": {
		"GET":  {Resource: "transit/keys", Action: "list"},
		"POST": {Resource: "transit/keys", Action: "create"},
	},

	// Sys endpoints (seal requires sudo)
	"/v1/sys/seal": {
		"POST": {Resource: "sys/seal", Action: "sudo"},
	},

	// Auth self-service endpoints
	"/v1/auth/token/lookup-self": {
		"GET": {Resource: "auth/token/lookup-self", Action: "read"},
	},
}

// Authorizer provides HTTP middleware for policy-based authorization.
// It maps HTTP routes to Vault-style resource paths and capabilities,
// then evaluates the identity's policies against the requested resource.
//
// Latency overhead: <0.1ms (pure in-memory map lookup + policy evaluation)
type Authorizer struct {
	logger     *zap.Logger
	authClient *AuthClientImpl
}

// NewAuthorizer creates a new authorizer.
func NewAuthorizer(logger *zap.Logger, authClient *AuthClientImpl) *Authorizer {
	return &Authorizer{
		logger:     logger,
		authClient: authClient,
	}
}

// HTTPMiddleware returns an HTTP middleware that performs authorization checks.
// It should be applied AFTER the authentication middleware.
//
// Flow:
//  1. Get identity from context (set by AuthMiddleware)
//  2. Map HTTP path + method to resource + capability
//  3. Evaluate policies locally (no RPC)
//  4. If denied, return 403 Forbidden
//  5. If allowed, proceed to handler
func (a *Authorizer) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get identity from context (set by auth middleware)
		identity, ok := middleware.GetIdentity(r.Context())
		if !ok {
			// No identity = unauthenticated path (skipped by auth middleware)
			next.ServeHTTP(w, r)
			return
		}

		// Look up the policy requirement for this route
		// Try exact match first, then prefix match for path-based routes
		lookupPath := r.URL.Path
		methods, exists := routePolicies[lookupPath]
		if !exists {
			// Try prefix match for sub-path routes (e.g., /v1/secret/data/myapp/config)
			for prefix, m := range routePolicies {
				if strings.HasPrefix(lookupPath, prefix+"/") {
					methods = m
					exists = true
					break
				}
			}
		}
		if !exists {
			// No policy mapping for this route - allow through
			// (route-level auth is handled by auth middleware skip list)
			next.ServeHTTP(w, r)
			return
		}

		rp, exists := methods[r.Method]
		if !exists {
			// No policy for this HTTP method
			next.ServeHTTP(w, r)
			return
		}

		// Check permission using local policy evaluator
		allowed, err := a.authClient.CheckPermission(r.Context(), identity.Subject, rp.Resource, rp.Action)
		if err != nil {
			a.logger.Error("Authorization check failed",
				zap.String("identity", identity.Subject),
				zap.String("resource", rp.Resource),
				zap.String("action", rp.Action),
				zap.Error(err),
			)
			writeErrorJSON(w, http.StatusInternalServerError, "authorization check failed")
			return
		}

		if !allowed {
			a.logger.Warn("Authorization denied",
				zap.String("identity", identity.Subject),
				zap.String("resource", rp.Resource),
				zap.String("action", rp.Action),
				zap.Strings("policies", identity.Policies),
				zap.String("path", r.URL.Path),
				zap.String("method", r.Method),
			)
			writeErrorJSON(w, http.StatusForbidden, "permission denied: "+
				"1 error occurred: * permission denied for "+rp.Resource)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// writeErrorJSON writes a JSON error response.
func writeErrorJSON(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"errors": []string{message},
	})
}

// GetRouteResource returns the resource path for a given HTTP path and method.
// Useful for handlers that need to do more granular authorization checks
// (e.g., checking per-key permissions like "crypto/encrypt/my-key").
func GetRouteResource(path, method string) (resource, action string, found bool) {
	path = strings.TrimSuffix(path, "/")
	methods, exists := routePolicies[path]
	if !exists {
		return "", "", false
	}
	rp, exists := methods[method]
	if !exists {
		return "", "", false
	}
	return rp.Resource, rp.Action, true
}
