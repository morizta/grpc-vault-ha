package cache

import (
	"testing"
	"time"
)

func TestLRUCache(t *testing.T) {
	cache, err := NewLRUCache[string, int](3)
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}

	// Test Set and Get
	cache.Set("a", 1)
	cache.Set("b", 2)
	cache.Set("c", 3)

	if v, ok := cache.Get("a"); !ok || v != 1 {
		t.Errorf("expected 1, got %v (ok=%v)", v, ok)
	}

	if v, ok := cache.Get("b"); !ok || v != 2 {
		t.Errorf("expected 2, got %v (ok=%v)", v, ok)
	}

	// Test eviction
	cache.Set("d", 4)

	// "c" should be evicted (LRU)
	if _, ok := cache.Get("c"); ok {
		t.Error("'c' should have been evicted")
	}

	// "a" and "b" should still exist
	if _, ok := cache.Get("a"); !ok {
		t.Error("'a' should exist")
	}
	if _, ok := cache.Get("b"); !ok {
		t.Error("'b' should exist")
	}
}

func TestLRUCacheDelete(t *testing.T) {
	cache, _ := NewLRUCache[string, int](5)

	cache.Set("key1", 100)
	cache.Set("key2", 200)

	if _, ok := cache.Get("key1"); !ok {
		t.Error("key1 should exist")
	}

	cache.Delete("key1")

	if _, ok := cache.Get("key1"); ok {
		t.Error("key1 should be deleted")
	}

	if _, ok := cache.Get("key2"); !ok {
		t.Error("key2 should still exist")
	}
}

func TestLRUCacheClear(t *testing.T) {
	cache, _ := NewLRUCache[string, int](5)

	cache.Set("a", 1)
	cache.Set("b", 2)
	cache.Set("c", 3)

	if cache.Len() != 3 {
		t.Errorf("expected len 3, got %d", cache.Len())
	}

	cache.Clear()

	if cache.Len() != 0 {
		t.Errorf("expected len 0 after clear, got %d", cache.Len())
	}

	if _, ok := cache.Get("a"); ok {
		t.Error("'a' should not exist after clear")
	}
}

func TestLRUCacheWithTTL(t *testing.T) {
	cache, err := NewLRUCacheWithTTL[string, int](10, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}

	cache.Set("key", 42)

	// Should exist immediately
	if v, ok := cache.Get("key"); !ok || v != 42 {
		t.Errorf("expected 42, got %v (ok=%v)", v, ok)
	}

	// Wait for TTL to expire
	time.Sleep(150 * time.Millisecond)

	// Should be expired
	if _, ok := cache.Get("key"); ok {
		t.Error("key should have expired")
	}
}

func TestLRUCacheKeys(t *testing.T) {
	cache, _ := NewLRUCache[string, int](10)

	cache.Set("x", 1)
	cache.Set("y", 2)
	cache.Set("z", 3)

	keys := cache.Keys()
	if len(keys) != 3 {
		t.Errorf("expected 3 keys, got %d", len(keys))
	}

	keyMap := make(map[string]bool)
	for _, k := range keys {
		keyMap[k] = true
	}

	for _, expected := range []string{"x", "y", "z"} {
		if !keyMap[expected] {
			t.Errorf("missing key: %s", expected)
		}
	}
}

func BenchmarkLRUCacheSet(b *testing.B) {
	cache, _ := NewLRUCache[int, int](1000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Set(i%1000, i)
	}
}

func BenchmarkLRUCacheGet(b *testing.B) {
	cache, _ := NewLRUCache[int, int](1000)

	for i := 0; i < 1000; i++ {
		cache.Set(i, i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Get(i % 1000)
	}
}
