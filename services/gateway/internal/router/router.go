package router

import (
	"net/http"

	"github.com/pocketsizefund/microservice-vault/services/gateway/internal/config"
	"github.com/pocketsizefund/microservice-vault/services/gateway/internal/handler"
	"github.com/pocketsizefund/microservice-vault/services/gateway/internal/middleware"
	"github.com/pocketsizefund/microservice-vault/services/gateway/internal/proxy"
	"go.uber.org/zap"
)

// Router sets up HTTP routing
type Router struct {
	mux           *http.ServeMux
	logger        *zap.Logger
	rateLimiter   *middleware.RateLimiter
	healthHandler *handler.HealthHandler
	gatewayHandler *handler.GatewayHandler
}

// NewRouter creates a new router
func NewRouter(
	logger *zap.Logger,
	proxy *proxy.GRPCProxy,
	cfg *config.Config,
	rateLimiter *middleware.RateLimiter,
) *Router {
	r := &Router{
		mux:           http.NewServeMux(),
		logger:        logger,
		rateLimiter:   rateLimiter,
		healthHandler: handler.NewHealthHandler(logger, proxy, &cfg.Services),
		gatewayHandler: handler.NewGatewayHandler(logger, proxy, cfg),
	}

	r.setupRoutes()
	return r
}

// setupRoutes configures all routes
func (r *Router) setupRoutes() {
	// Health endpoints (no auth required)
	r.mux.HandleFunc("/health/live", r.healthHandler.Liveness)
	r.mux.HandleFunc("/health/ready", r.healthHandler.Readiness)
	r.mux.HandleFunc("/status", r.healthHandler.Status)

	// Auth endpoints
	r.mux.HandleFunc("/v1/auth/login", r.methodHandler("POST", r.gatewayHandler.Login))
	r.mux.HandleFunc("/v1/auth/token/lookup-self", r.methodHandler("GET", r.gatewayHandler.Lookup))

	// Crypto endpoints
	r.mux.HandleFunc("/v1/crypto/encrypt", r.methodHandler("POST", r.gatewayHandler.Encrypt))
	r.mux.HandleFunc("/v1/crypto/decrypt", r.methodHandler("POST", r.gatewayHandler.Decrypt))

	// Tokenize endpoints
	r.mux.HandleFunc("/v1/tokenize/encode", r.methodHandler("POST", r.gatewayHandler.Tokenize))
	r.mux.HandleFunc("/v1/tokenize/decode", r.methodHandler("POST", r.gatewayHandler.Detokenize))

	// Secret endpoints
	r.mux.HandleFunc("/v1/secret/data", r.secretHandler())

	// Seal/Unseal endpoints
	r.mux.HandleFunc("/v1/sys/seal-status", r.methodHandler("GET", r.gatewayHandler.GetSealStatus))
	r.mux.HandleFunc("/v1/sys/init", r.methodHandler("POST", r.gatewayHandler.Initialize))
	r.mux.HandleFunc("/v1/sys/unseal", r.methodHandler("POST", r.gatewayHandler.Unseal))
	r.mux.HandleFunc("/v1/sys/seal", r.methodHandler("POST", r.gatewayHandler.Seal))

	// Key management endpoints
	r.mux.HandleFunc("/v1/transit/keys", r.keysHandler())
}

// methodHandler wraps a handler to only respond to specific HTTP method
func (r *Router) methodHandler(method string, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if req.Method != method {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		handler(w, req)
	}
}

// secretHandler handles both GET and POST for /v1/secret/data
func (r *Router) secretHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		switch req.Method {
		case "GET":
			r.gatewayHandler.GetSecret(w, req)
		case "POST":
			r.gatewayHandler.PutSecret(w, req)
		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	}
}

// keysHandler handles both GET and POST for /v1/transit/keys
func (r *Router) keysHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		switch req.Method {
		case "GET":
			r.gatewayHandler.ListKeys(w, req)
		case "POST":
			r.gatewayHandler.CreateKey(w, req)
		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	}
}

// Handler returns the HTTP handler with middleware
func (r *Router) Handler() http.Handler {
	// Apply middleware chain
	var handler http.Handler = r.mux

	// Logging middleware
	handler = r.loggingMiddleware(handler)

	// Rate limiting middleware
	if r.rateLimiter != nil {
		handler = r.rateLimiter.HTTPMiddleware(handler)
	}

	// Recovery middleware
	handler = r.recoveryMiddleware(handler)

	// CORS middleware
	handler = r.corsMiddleware(handler)

	return handler
}

// loggingMiddleware logs all requests (uses Debug level for high-throughput)
func (r *Router) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Use Debug level to avoid overhead in production
		// Set log level to "debug" to enable request logging
		r.logger.Debug("HTTP request",
			zap.String("method", req.Method),
			zap.String("path", req.URL.Path),
			zap.String("remote_addr", req.RemoteAddr),
		)
		next.ServeHTTP(w, req)
	})
}

// recoveryMiddleware recovers from panics
func (r *Router) recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				r.logger.Error("Panic recovered",
					zap.Any("error", err),
					zap.String("path", req.URL.Path),
				)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, req)
	})
}

// corsMiddleware handles CORS
func (r *Router) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")

		if req.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, req)
	})
}
