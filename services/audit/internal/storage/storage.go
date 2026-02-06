package storage

import (
	"context"
	"time"
)

// AuditEntry represents an audit log entry
type AuditEntry struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	Type        string                 `json:"type"` // "request", "response", "error"
	Auth        *AuthInfo              `json:"auth,omitempty"`
	Request     *RequestInfo           `json:"request,omitempty"`
	Response    *ResponseInfo          `json:"response,omitempty"`
	Error       string                 `json:"error,omitempty"`
	Metadata    map[string]string      `json:"metadata,omitempty"`
}

// AuthInfo contains authentication information
type AuthInfo struct {
	ClientToken     string   `json:"client_token,omitempty"`
	Accessor        string   `json:"accessor,omitempty"`
	DisplayName     string   `json:"display_name,omitempty"`
	Policies        []string `json:"policies,omitempty"`
	TokenPolicies   []string `json:"token_policies,omitempty"`
	IdentityPolicies []string `json:"identity_policies,omitempty"`
	EntityID        string   `json:"entity_id,omitempty"`
	RemoteAddr      string   `json:"remote_addr,omitempty"`
}

// RequestInfo contains request information
type RequestInfo struct {
	ID              string            `json:"id"`
	Operation       string            `json:"operation"`
	Path            string            `json:"path"`
	Data            map[string]interface{} `json:"data,omitempty"`
	RemoteAddr      string            `json:"remote_addr,omitempty"`
	WrapTTL         int               `json:"wrap_ttl,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
}

// ResponseInfo contains response information
type ResponseInfo struct {
	MountPoint     string                 `json:"mount_point,omitempty"`
	MountType      string                 `json:"mount_type,omitempty"`
	MountAccessor  string                 `json:"mount_accessor,omitempty"`
	Data           map[string]interface{} `json:"data,omitempty"`
	Warnings       []string               `json:"warnings,omitempty"`
}

// QueryOptions for filtering audit logs
type QueryOptions struct {
	StartTime   time.Time
	EndTime     time.Time
	Type        string
	Path        string
	Operation   string
	ClientToken string
	Limit       int
	Offset      int
}

// Storage interface for audit log storage
type Storage interface {
	// Write writes an audit entry
	Write(ctx context.Context, entry *AuditEntry) error

	// WriteBatch writes multiple audit entries
	WriteBatch(ctx context.Context, entries []*AuditEntry) error

	// Query queries audit entries
	Query(ctx context.Context, opts QueryOptions) ([]*AuditEntry, error)

	// Count counts matching entries
	Count(ctx context.Context, opts QueryOptions) (int64, error)

	// Close closes the storage
	Close() error
}
