// Package cache provides caching utilities
package cache

import (
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

// LRUCache is a thread-safe LRU cache with optional TTL
type LRUCache[K comparable, V any] struct {
	cache    *lru.Cache[K, *cacheEntry[V]]
	ttl      time.Duration
	mu       sync.RWMutex
	hits     int64
	misses   int64
	evictions int64
}

type cacheEntry[V any] struct {
	value     V
	expiresAt time.Time
}

// NewLRUCache creates a new LRU cache with the specified size
func NewLRUCache[K comparable, V any](size int) (*LRUCache[K, V], error) {
	return NewLRUCacheWithTTL[K, V](size, 0)
}

// NewLRUCacheWithTTL creates a new LRU cache with TTL
func NewLRUCacheWithTTL[K comparable, V any](size int, ttl time.Duration) (*LRUCache[K, V], error) {
	c, err := lru.New[K, *cacheEntry[V]](size)
	if err != nil {
		return nil, err
	}

	return &LRUCache[K, V]{
		cache: c,
		ttl:   ttl,
	}, nil
}

// Get retrieves a value from the cache
func (c *LRUCache[K, V]) Get(key K) (V, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.cache.Get(key)
	if !ok {
		c.misses++
		var zero V
		return zero, false
	}

	// Check TTL
	if c.ttl > 0 && time.Now().After(entry.expiresAt) {
		c.cache.Remove(key)
		c.misses++
		var zero V
		return zero, false
	}

	c.hits++
	return entry.value, true
}

// Set adds a value to the cache
func (c *LRUCache[K, V]) Set(key K, value V) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var expiresAt time.Time
	if c.ttl > 0 {
		expiresAt = time.Now().Add(c.ttl)
	}

	evicted := c.cache.Add(key, &cacheEntry[V]{
		value:     value,
		expiresAt: expiresAt,
	})

	if evicted {
		c.evictions++
	}
}

// SetWithTTL adds a value with custom TTL
func (c *LRUCache[K, V]) SetWithTTL(key K, value V, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	expiresAt := time.Now().Add(ttl)

	evicted := c.cache.Add(key, &cacheEntry[V]{
		value:     value,
		expiresAt: expiresAt,
	})

	if evicted {
		c.evictions++
	}
}

// Delete removes a key from the cache
func (c *LRUCache[K, V]) Delete(key K) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cache.Remove(key)
}

// Clear empties the cache
func (c *LRUCache[K, V]) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache.Purge()
}

// Len returns the number of items in the cache
func (c *LRUCache[K, V]) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cache.Len()
}

// Contains checks if a key exists in the cache
func (c *LRUCache[K, V]) Contains(key K) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.cache.Peek(key)
	if !ok {
		return false
	}

	// Check TTL
	if c.ttl > 0 && time.Now().After(entry.expiresAt) {
		return false
	}

	return true
}

// Keys returns all keys in the cache
func (c *LRUCache[K, V]) Keys() []K {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cache.Keys()
}

// Stats returns cache statistics
type CacheStats struct {
	Hits      int64
	Misses    int64
	Evictions int64
	Size      int
	HitRatio  float64
}

func (c *LRUCache[K, V]) Stats() CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	total := c.hits + c.misses
	var hitRatio float64
	if total > 0 {
		hitRatio = float64(c.hits) / float64(total)
	}

	return CacheStats{
		Hits:      c.hits,
		Misses:    c.misses,
		Evictions: c.evictions,
		Size:      c.cache.Len(),
		HitRatio:  hitRatio,
	}
}

// ResetStats resets the cache statistics
func (c *LRUCache[K, V]) ResetStats() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.hits = 0
	c.misses = 0
	c.evictions = 0
}
