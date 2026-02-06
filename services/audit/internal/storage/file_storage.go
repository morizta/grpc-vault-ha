package storage

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// FileStorage implements Storage interface for file-based audit logs
type FileStorage struct {
	mu       sync.Mutex
	file     *os.File
	writer   *bufio.Writer
	filePath string

	// In-memory index for queries (development only)
	entries []*AuditEntry
	maxSize int
}

// NewFileStorage creates a new file storage
func NewFileStorage(filePath string) (*FileStorage, error) {
	// Ensure directory exists
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}

	return &FileStorage{
		file:     file,
		writer:   bufio.NewWriter(file),
		filePath: filePath,
		entries:  make([]*AuditEntry, 0),
		maxSize:  10000, // Keep last 10k entries in memory for queries
	}, nil
}

// Write writes an audit entry
func (s *FileStorage) Write(ctx context.Context, entry *AuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	if _, err := s.writer.Write(data); err != nil {
		return err
	}
	if _, err := s.writer.WriteString("\n"); err != nil {
		return err
	}

	// Flush to file
	if err := s.writer.Flush(); err != nil {
		return err
	}

	// Add to in-memory index
	s.entries = append(s.entries, entry)
	if len(s.entries) > s.maxSize {
		s.entries = s.entries[1:]
	}

	return nil
}

// WriteBatch writes multiple audit entries
func (s *FileStorage) WriteBatch(ctx context.Context, entries []*AuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, entry := range entries {
		data, err := json.Marshal(entry)
		if err != nil {
			return err
		}

		if _, err := s.writer.Write(data); err != nil {
			return err
		}
		if _, err := s.writer.WriteString("\n"); err != nil {
			return err
		}

		// Add to in-memory index
		s.entries = append(s.entries, entry)
	}

	// Flush all at once
	if err := s.writer.Flush(); err != nil {
		return err
	}

	// Trim if needed
	if len(s.entries) > s.maxSize {
		s.entries = s.entries[len(s.entries)-s.maxSize:]
	}

	return nil
}

// Query queries audit entries
func (s *FileStorage) Query(ctx context.Context, opts QueryOptions) ([]*AuditEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var results []*AuditEntry
	skipped := 0

	for _, entry := range s.entries {
		if !s.matchesQuery(entry, opts) {
			continue
		}

		if skipped < opts.Offset {
			skipped++
			continue
		}

		results = append(results, entry)

		if opts.Limit > 0 && len(results) >= opts.Limit {
			break
		}
	}

	return results, nil
}

// Count counts matching entries
func (s *FileStorage) Count(ctx context.Context, opts QueryOptions) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var count int64
	for _, entry := range s.entries {
		if s.matchesQuery(entry, opts) {
			count++
		}
	}

	return count, nil
}

// matchesQuery checks if an entry matches the query options
func (s *FileStorage) matchesQuery(entry *AuditEntry, opts QueryOptions) bool {
	// Time range filter
	if !opts.StartTime.IsZero() && entry.Timestamp.Before(opts.StartTime) {
		return false
	}
	if !opts.EndTime.IsZero() && entry.Timestamp.After(opts.EndTime) {
		return false
	}

	// Type filter
	if opts.Type != "" && entry.Type != opts.Type {
		return false
	}

	// Path filter
	if opts.Path != "" && entry.Request != nil && entry.Request.Path != opts.Path {
		return false
	}

	// Operation filter
	if opts.Operation != "" && entry.Request != nil && entry.Request.Operation != opts.Operation {
		return false
	}

	// Client token filter
	if opts.ClientToken != "" && entry.Auth != nil && entry.Auth.ClientToken != opts.ClientToken {
		return false
	}

	return true
}

// Close closes the storage
func (s *FileStorage) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.writer.Flush(); err != nil {
		return err
	}
	return s.file.Close()
}

// MemoryStorage implements Storage interface for in-memory storage (testing)
type MemoryStorage struct {
	mu      sync.RWMutex
	entries []*AuditEntry
	maxSize int
}

// NewMemoryStorage creates a new memory storage
func NewMemoryStorage(maxSize int) *MemoryStorage {
	return &MemoryStorage{
		entries: make([]*AuditEntry, 0),
		maxSize: maxSize,
	}
}

// Write writes an audit entry
func (s *MemoryStorage) Write(ctx context.Context, entry *AuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.entries = append(s.entries, entry)
	if len(s.entries) > s.maxSize {
		s.entries = s.entries[1:]
	}

	return nil
}

// WriteBatch writes multiple audit entries
func (s *MemoryStorage) WriteBatch(ctx context.Context, entries []*AuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.entries = append(s.entries, entries...)
	if len(s.entries) > s.maxSize {
		s.entries = s.entries[len(s.entries)-s.maxSize:]
	}

	return nil
}

// Query queries audit entries
func (s *MemoryStorage) Query(ctx context.Context, opts QueryOptions) ([]*AuditEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []*AuditEntry
	skipped := 0

	for i := len(s.entries) - 1; i >= 0; i-- {
		entry := s.entries[i]
		if !s.matchesQuery(entry, opts) {
			continue
		}

		if skipped < opts.Offset {
			skipped++
			continue
		}

		results = append(results, entry)

		if opts.Limit > 0 && len(results) >= opts.Limit {
			break
		}
	}

	return results, nil
}

// Count counts matching entries
func (s *MemoryStorage) Count(ctx context.Context, opts QueryOptions) (int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var count int64
	for _, entry := range s.entries {
		if s.matchesQuery(entry, opts) {
			count++
		}
	}

	return count, nil
}

// matchesQuery checks if an entry matches the query options
func (s *MemoryStorage) matchesQuery(entry *AuditEntry, opts QueryOptions) bool {
	if !opts.StartTime.IsZero() && entry.Timestamp.Before(opts.StartTime) {
		return false
	}
	if !opts.EndTime.IsZero() && entry.Timestamp.After(opts.EndTime) {
		return false
	}
	if opts.Type != "" && entry.Type != opts.Type {
		return false
	}
	if opts.Path != "" && entry.Request != nil && entry.Request.Path != opts.Path {
		return false
	}
	if opts.Operation != "" && entry.Request != nil && entry.Request.Operation != opts.Operation {
		return false
	}
	return true
}

// Close closes the storage
func (s *MemoryStorage) Close() error {
	return nil
}

// Ensure implementations satisfy interface
var (
	_ Storage = (*FileStorage)(nil)
	_ Storage = (*MemoryStorage)(nil)
)
