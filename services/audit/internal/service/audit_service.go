package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/pocketsizefund/microservice-vault/services/audit/internal/config"
	"github.com/pocketsizefund/microservice-vault/services/audit/internal/storage"
)

// AuditService handles audit logging
type AuditService struct {
	config  *config.Config
	logger  *zap.Logger
	storage storage.Storage

	// Buffer for batch writes
	buffer    []*storage.AuditEntry
	bufferMu  sync.Mutex
	flushChan chan struct{}
	closeChan chan struct{}
	wg        sync.WaitGroup
}

// NewAuditService creates a new audit service
func NewAuditService(cfg *config.Config, logger *zap.Logger) (*AuditService, error) {
	var store storage.Storage
	var err error

	switch cfg.Storage.Type {
	case "file":
		store, err = storage.NewFileStorage(cfg.Storage.FilePath)
	case "memory":
		store = storage.NewMemoryStorage(10000)
	default:
		store = storage.NewMemoryStorage(10000)
	}

	if err != nil {
		return nil, err
	}

	svc := &AuditService{
		config:    cfg,
		logger:    logger,
		storage:   store,
		buffer:    make([]*storage.AuditEntry, 0, cfg.Buffer.Size),
		flushChan: make(chan struct{}, 1),
		closeChan: make(chan struct{}),
	}

	// Start background flush worker
	svc.wg.Add(1)
	go svc.flushWorker()

	return svc, nil
}

// flushWorker periodically flushes the buffer
func (s *AuditService) flushWorker() {
	defer s.wg.Done()

	ticker := time.NewTicker(s.config.Buffer.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.flush()
		case <-s.flushChan:
			s.flush()
		case <-s.closeChan:
			s.flush()
			return
		}
	}
}

// flush writes buffered entries to storage
func (s *AuditService) flush() {
	s.bufferMu.Lock()
	if len(s.buffer) == 0 {
		s.bufferMu.Unlock()
		return
	}

	entries := s.buffer
	s.buffer = make([]*storage.AuditEntry, 0, s.config.Buffer.Size)
	s.bufferMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := s.storage.WriteBatch(ctx, entries); err != nil {
		s.logger.Error("Failed to write audit entries", zap.Error(err), zap.Int("count", len(entries)))
	}
}

// generateID generates a unique ID
func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// LogRequest logs a request audit entry
func (s *AuditService) LogRequest(ctx context.Context, req *LogRequestInput) error {
	entry := &storage.AuditEntry{
		ID:        generateID(),
		Timestamp: time.Now().UTC(),
		Type:      "request",
		Auth: &storage.AuthInfo{
			ClientToken:   req.ClientToken,
			Accessor:      req.Accessor,
			DisplayName:   req.DisplayName,
			Policies:      req.Policies,
			EntityID:      req.EntityID,
			RemoteAddr:    req.RemoteAddr,
		},
		Request: &storage.RequestInfo{
			ID:         req.RequestID,
			Operation:  req.Operation,
			Path:       req.Path,
			Data:       req.Data,
			RemoteAddr: req.RemoteAddr,
		},
		Metadata: req.Metadata,
	}

	return s.writeEntry(entry)
}

// LogResponse logs a response audit entry
func (s *AuditService) LogResponse(ctx context.Context, resp *LogResponseInput) error {
	entry := &storage.AuditEntry{
		ID:        generateID(),
		Timestamp: time.Now().UTC(),
		Type:      "response",
		Auth: &storage.AuthInfo{
			ClientToken: resp.ClientToken,
			Accessor:    resp.Accessor,
			DisplayName: resp.DisplayName,
			Policies:    resp.Policies,
		},
		Request: &storage.RequestInfo{
			ID:        resp.RequestID,
			Operation: resp.Operation,
			Path:      resp.Path,
		},
		Response: &storage.ResponseInfo{
			MountPoint:    resp.MountPoint,
			MountType:     resp.MountType,
			MountAccessor: resp.MountAccessor,
			Warnings:      resp.Warnings,
		},
		Metadata: resp.Metadata,
	}

	return s.writeEntry(entry)
}

// LogError logs an error audit entry
func (s *AuditService) LogError(ctx context.Context, errInput *LogErrorInput) error {
	entry := &storage.AuditEntry{
		ID:        generateID(),
		Timestamp: time.Now().UTC(),
		Type:      "error",
		Auth: &storage.AuthInfo{
			ClientToken: errInput.ClientToken,
			Accessor:    errInput.Accessor,
			RemoteAddr:  errInput.RemoteAddr,
		},
		Request: &storage.RequestInfo{
			ID:        errInput.RequestID,
			Operation: errInput.Operation,
			Path:      errInput.Path,
		},
		Error:    errInput.Error,
		Metadata: errInput.Metadata,
	}

	return s.writeEntry(entry)
}

// writeEntry adds an entry to the buffer
func (s *AuditService) writeEntry(entry *storage.AuditEntry) error {
	s.bufferMu.Lock()
	s.buffer = append(s.buffer, entry)
	shouldFlush := len(s.buffer) >= s.config.Buffer.Size
	s.bufferMu.Unlock()

	if shouldFlush {
		select {
		case s.flushChan <- struct{}{}:
		default:
		}
	}

	return nil
}

// Query queries audit entries
func (s *AuditService) Query(ctx context.Context, opts *QueryInput) ([]*storage.AuditEntry, int64, error) {
	queryOpts := storage.QueryOptions{
		StartTime:   opts.StartTime,
		EndTime:     opts.EndTime,
		Type:        opts.Type,
		Path:        opts.Path,
		Operation:   opts.Operation,
		ClientToken: opts.ClientToken,
		Limit:       opts.Limit,
		Offset:      opts.Offset,
	}

	entries, err := s.storage.Query(ctx, queryOpts)
	if err != nil {
		return nil, 0, err
	}

	total, err := s.storage.Count(ctx, queryOpts)
	if err != nil {
		return nil, 0, err
	}

	return entries, total, nil
}

// Close closes the service
func (s *AuditService) Close() error {
	close(s.closeChan)
	s.wg.Wait()
	return s.storage.Close()
}

// Input types

type LogRequestInput struct {
	RequestID   string
	ClientToken string
	Accessor    string
	DisplayName string
	Policies    []string
	EntityID    string
	RemoteAddr  string
	Operation   string
	Path        string
	Data        map[string]interface{}
	Metadata    map[string]string
}

type LogResponseInput struct {
	RequestID     string
	ClientToken   string
	Accessor      string
	DisplayName   string
	Policies      []string
	Operation     string
	Path          string
	MountPoint    string
	MountType     string
	MountAccessor string
	Warnings      []string
	Metadata      map[string]string
}

type LogErrorInput struct {
	RequestID   string
	ClientToken string
	Accessor    string
	RemoteAddr  string
	Operation   string
	Path        string
	Error       string
	Metadata    map[string]string
}

type QueryInput struct {
	StartTime   time.Time
	EndTime     time.Time
	Type        string
	Path        string
	Operation   string
	ClientToken string
	Limit       int
	Offset      int
}
