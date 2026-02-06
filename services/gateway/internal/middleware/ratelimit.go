package middleware

import (
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimiter implements per-client rate limiting
type RateLimiter struct {
	clients sync.Map
	r       rate.Limit
	b       int
	cleanup time.Duration
}

type client struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(requestsPerSecond int, burstSize int, cleanupInterval time.Duration) *RateLimiter {
	rl := &RateLimiter{
		r:       rate.Limit(requestsPerSecond),
		b:       burstSize,
		cleanup: cleanupInterval,
	}

	// Start cleanup goroutine
	go rl.cleanupLoop()

	return rl
}

// getLimiter returns the rate limiter for a client
func (rl *RateLimiter) getLimiter(clientID string) *rate.Limiter {
	if c, ok := rl.clients.Load(clientID); ok {
		cl := c.(*client)
		cl.lastSeen = time.Now()
		return cl.limiter
	}

	limiter := rate.NewLimiter(rl.r, rl.b)
	rl.clients.Store(clientID, &client{
		limiter:  limiter,
		lastSeen: time.Now(),
	})

	return limiter
}

// Allow checks if a request from clientID is allowed
func (rl *RateLimiter) Allow(clientID string) bool {
	return rl.getLimiter(clientID).Allow()
}

// cleanupLoop removes old clients
func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rl.cleanup)
	defer ticker.Stop()

	for range ticker.C {
		rl.clients.Range(func(key, value interface{}) bool {
			c := value.(*client)
			if time.Since(c.lastSeen) > rl.cleanup*3 {
				rl.clients.Delete(key)
			}
			return true
		})
	}
}

// HTTPMiddleware returns an HTTP middleware for rate limiting
func (rl *RateLimiter) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get client identifier (IP or token)
		clientID := getClientID(r)

		if !rl.Allow(clientID) {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// getClientID extracts client identifier from request
func getClientID(r *http.Request) string {
	// Check for API key first
	if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
		return "apikey:" + apiKey
	}

	// Check for token
	if token := r.Header.Get("Authorization"); token != "" {
		return "token:" + token[:min(len(token), 32)]
	}

	// Fall back to IP
	return "ip:" + r.RemoteAddr
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
