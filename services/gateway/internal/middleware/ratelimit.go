package middleware

import (
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimiter implements per-client-IP rate limiting (Vault-like).
// Each client IP gets its own token bucket. If BurstSize <= 0, burst
// defaults to RequestsPerSec (strict token bucket, no extra burst).
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

// NewRateLimiter creates a new per-IP rate limiter.
// If burstSize <= 0, it defaults to requestsPerSecond (Vault-like strict token bucket).
func NewRateLimiter(requestsPerSecond int, burstSize int, cleanupInterval time.Duration) *RateLimiter {
	if burstSize <= 0 {
		burstSize = requestsPerSecond
	}

	rl := &RateLimiter{
		r:       rate.Limit(requestsPerSecond),
		b:       burstSize,
		cleanup: cleanupInterval,
	}

	go rl.cleanupLoop()

	return rl
}

// getLimiter returns the rate limiter for a client IP.
func (rl *RateLimiter) getLimiter(clientIP string) *rate.Limiter {
	if c, ok := rl.clients.Load(clientIP); ok {
		cl := c.(*client)
		cl.lastSeen = time.Now()
		return cl.limiter
	}

	limiter := rate.NewLimiter(rl.r, rl.b)
	rl.clients.Store(clientIP, &client{
		limiter:  limiter,
		lastSeen: time.Now(),
	})

	return limiter
}

// Allow checks if a request from the given client IP is allowed.
func (rl *RateLimiter) Allow(clientIP string) bool {
	return rl.getLimiter(clientIP).Allow()
}

// cleanupLoop removes stale client entries.
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

// HTTPMiddleware returns an HTTP middleware for rate limiting.
// Like Vault, it scopes rate limits per client IP and returns
// X-RateLimit-Limit and Retry-After headers on 429.
func (rl *RateLimiter) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientID := getClientID(r)

		if !rl.Allow(clientID) {
			w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", int(rl.r)))
			w.Header().Set("Retry-After", "1")
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// getClientID extracts client identifier from request.
// Priority: API key > Token > IP (fairer for multi-tenant behind reverse proxy).
func getClientID(r *http.Request) string {
	if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
		return "apikey:" + apiKey
	}

	if auth := r.Header.Get("Authorization"); len(auth) > 10 {
		// Use first 32 chars of token as key (enough to distinguish users)
		end := len(auth)
		if end > 42 {
			end = 42
		}
		return "token:" + auth[7:end] // skip "Bearer "
	}

	// Fallback to IP
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "ip:" + r.RemoteAddr
	}
	return "ip:" + host
}
