// Package rand provides a buffered random reader for high-performance
// random byte generation with reduced syscall overhead.
package rand

import (
	"crypto/rand"
	"sync"
)

const (
	// DefaultBufferSize is the default size of the random buffer (64KB)
	// This provides ~5400 nonces (12 bytes each) per buffer refill
	DefaultBufferSize = 64 * 1024
)

// BufferedReader is a thread-safe buffered random reader that reduces
// syscall overhead by pre-fetching random bytes in batches.
type BufferedReader struct {
	mu     sync.Mutex
	buf    []byte
	pos    int
	size   int
}

// globalReader is the package-level buffered reader
var globalReader = NewBufferedReader(DefaultBufferSize)

// NewBufferedReader creates a new buffered random reader with the specified buffer size
func NewBufferedReader(size int) *BufferedReader {
	return &BufferedReader{
		buf:  make([]byte, size),
		pos:  size, // Start empty to trigger first fill
		size: size,
	}
}

// Read fills the provided byte slice with random bytes from the buffer.
// Thread-safe and reduces syscalls by batching random byte generation.
func (r *BufferedReader) Read(b []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	n := len(b)
	copied := 0

	for copied < n {
		// Refill buffer if empty
		if r.pos >= r.size {
			if err := r.refill(); err != nil {
				return copied, err
			}
		}

		// Copy from buffer
		toCopy := r.size - r.pos
		if toCopy > n-copied {
			toCopy = n - copied
		}
		copy(b[copied:], r.buf[r.pos:r.pos+toCopy])
		r.pos += toCopy
		copied += toCopy
	}

	return n, nil
}

// refill fills the internal buffer with fresh random bytes
func (r *BufferedReader) refill() error {
	_, err := rand.Read(r.buf)
	if err != nil {
		return err
	}
	r.pos = 0
	return nil
}

// Read fills b with random bytes using the global buffered reader.
// This is the primary function to use for high-performance random generation.
func Read(b []byte) (int, error) {
	return globalReader.Read(b)
}

// NoncePool is a sync.Pool for nonce byte slices to reduce allocations
var NoncePool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 12) // Standard nonce size for AES-GCM
		return &b
	},
}

// GetNonce gets a nonce slice from the pool
func GetNonce() *[]byte {
	return NoncePool.Get().(*[]byte)
}

// PutNonce returns a nonce slice to the pool
func PutNonce(b *[]byte) {
	NoncePool.Put(b)
}

// BufferPool is a sync.Pool for general byte buffers
var BufferPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 0, 256) // Default capacity for small operations
		return &b
	},
}

// GetBuffer gets a buffer from the pool
func GetBuffer() *[]byte {
	return BufferPool.Get().(*[]byte)
}

// PutBuffer returns a buffer to the pool (resets length to 0)
func PutBuffer(b *[]byte) {
	*b = (*b)[:0]
	BufferPool.Put(b)
}
