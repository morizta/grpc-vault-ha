package handler

import (
	"context"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pocketsizefund/microservice-vault/services/audit/internal/service"
	"github.com/pocketsizefund/microservice-vault/services/audit/internal/storage"
)

// AuditHandler handles audit gRPC requests
type AuditHandler struct {
	service *service.AuditService
	logger  *zap.Logger
}

// NewAuditHandler creates a new audit handler
func NewAuditHandler(svc *service.AuditService, logger *zap.Logger) *AuditHandler {
	return &AuditHandler{
		service: svc,
		logger:  logger,
	}
}

// Register registers the handler with the gRPC server
func (h *AuditHandler) Register(server *grpc.Server) {
	// In production: auditv1.RegisterAuditServiceServer(server, h)
}

// LogRequest logs a request audit entry
func (h *AuditHandler) LogRequest(ctx context.Context, req *LogRequestRequest) (*LogResponse, error) {
	if req.RequestId == "" {
		return nil, status.Error(codes.InvalidArgument, "request_id is required")
	}

	input := &service.LogRequestInput{
		RequestID:   req.RequestId,
		ClientToken: req.ClientToken,
		Accessor:    req.Accessor,
		DisplayName: req.DisplayName,
		Policies:    req.Policies,
		EntityID:    req.EntityId,
		RemoteAddr:  req.RemoteAddr,
		Operation:   req.Operation,
		Path:        req.Path,
		Data:        req.Data,
		Metadata:    req.Metadata,
	}

	if err := h.service.LogRequest(ctx, input); err != nil {
		h.logger.Error("Failed to log request", zap.Error(err))
		return nil, status.Error(codes.Internal, "failed to log request")
	}

	return &LogResponse{Success: true}, nil
}

// LogResponse logs a response audit entry
func (h *AuditHandler) LogResponse(ctx context.Context, req *LogResponseRequest) (*LogResponse, error) {
	if req.RequestId == "" {
		return nil, status.Error(codes.InvalidArgument, "request_id is required")
	}

	input := &service.LogResponseInput{
		RequestID:     req.RequestId,
		ClientToken:   req.ClientToken,
		Accessor:      req.Accessor,
		DisplayName:   req.DisplayName,
		Policies:      req.Policies,
		Operation:     req.Operation,
		Path:          req.Path,
		MountPoint:    req.MountPoint,
		MountType:     req.MountType,
		MountAccessor: req.MountAccessor,
		Warnings:      req.Warnings,
		Metadata:      req.Metadata,
	}

	if err := h.service.LogResponse(ctx, input); err != nil {
		h.logger.Error("Failed to log response", zap.Error(err))
		return nil, status.Error(codes.Internal, "failed to log response")
	}

	return &LogResponse{Success: true}, nil
}

// LogError logs an error audit entry
func (h *AuditHandler) LogError(ctx context.Context, req *LogErrorRequest) (*LogResponse, error) {
	if req.RequestId == "" {
		return nil, status.Error(codes.InvalidArgument, "request_id is required")
	}

	input := &service.LogErrorInput{
		RequestID:   req.RequestId,
		ClientToken: req.ClientToken,
		Accessor:    req.Accessor,
		RemoteAddr:  req.RemoteAddr,
		Operation:   req.Operation,
		Path:        req.Path,
		Error:       req.Error,
		Metadata:    req.Metadata,
	}

	if err := h.service.LogError(ctx, input); err != nil {
		h.logger.Error("Failed to log error", zap.Error(err))
		return nil, status.Error(codes.Internal, "failed to log error")
	}

	return &LogResponse{Success: true}, nil
}

// Query queries audit entries
func (h *AuditHandler) Query(ctx context.Context, req *QueryRequest) (*QueryResponse, error) {
	input := &service.QueryInput{
		Type:        req.Type,
		Path:        req.Path,
		Operation:   req.Operation,
		ClientToken: req.ClientToken,
		Limit:       int(req.Limit),
		Offset:      int(req.Offset),
	}

	if req.StartTime > 0 {
		input.StartTime = time.Unix(req.StartTime, 0)
	}
	if req.EndTime > 0 {
		input.EndTime = time.Unix(req.EndTime, 0)
	}

	entries, total, err := h.service.Query(ctx, input)
	if err != nil {
		h.logger.Error("Failed to query audit entries", zap.Error(err))
		return nil, status.Error(codes.Internal, "failed to query audit entries")
	}

	// Convert to response entries
	responseEntries := make([]*AuditEntry, len(entries))
	for i, entry := range entries {
		responseEntries[i] = convertToResponse(entry)
	}

	return &QueryResponse{
		Entries: responseEntries,
		Total:   total,
	}, nil
}

// convertToResponse converts storage entry to response entry
func convertToResponse(entry *storage.AuditEntry) *AuditEntry {
	resp := &AuditEntry{
		Id:        entry.ID,
		Timestamp: entry.Timestamp.Unix(),
		Type:      entry.Type,
		Error:     entry.Error,
		Metadata:  entry.Metadata,
	}

	if entry.Auth != nil {
		resp.Auth = &AuthInfo{
			ClientToken:   entry.Auth.ClientToken,
			Accessor:      entry.Auth.Accessor,
			DisplayName:   entry.Auth.DisplayName,
			Policies:      entry.Auth.Policies,
			EntityId:      entry.Auth.EntityID,
			RemoteAddr:    entry.Auth.RemoteAddr,
		}
	}

	if entry.Request != nil {
		resp.Request = &RequestInfo{
			Id:         entry.Request.ID,
			Operation:  entry.Request.Operation,
			Path:       entry.Request.Path,
			RemoteAddr: entry.Request.RemoteAddr,
		}
	}

	if entry.Response != nil {
		resp.Response = &ResponseInfo{
			MountPoint:    entry.Response.MountPoint,
			MountType:     entry.Response.MountType,
			MountAccessor: entry.Response.MountAccessor,
			Warnings:      entry.Response.Warnings,
		}
	}

	return resp
}

// Request/Response types

type LogRequestRequest struct {
	RequestId   string
	ClientToken string
	Accessor    string
	DisplayName string
	Policies    []string
	EntityId    string
	RemoteAddr  string
	Operation   string
	Path        string
	Data        map[string]interface{}
	Metadata    map[string]string
}

type LogResponseRequest struct {
	RequestId     string
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

type LogErrorRequest struct {
	RequestId   string
	ClientToken string
	Accessor    string
	RemoteAddr  string
	Operation   string
	Path        string
	Error       string
	Metadata    map[string]string
}

type LogResponse struct {
	Success bool
}

type QueryRequest struct {
	StartTime   int64
	EndTime     int64
	Type        string
	Path        string
	Operation   string
	ClientToken string
	Limit       int32
	Offset      int32
}

type QueryResponse struct {
	Entries []*AuditEntry
	Total   int64
}

type AuditEntry struct {
	Id        string
	Timestamp int64
	Type      string
	Auth      *AuthInfo
	Request   *RequestInfo
	Response  *ResponseInfo
	Error     string
	Metadata  map[string]string
}

type AuthInfo struct {
	ClientToken   string
	Accessor      string
	DisplayName   string
	Policies      []string
	EntityId      string
	RemoteAddr    string
}

type RequestInfo struct {
	Id         string
	Operation  string
	Path       string
	RemoteAddr string
}

type ResponseInfo struct {
	MountPoint    string
	MountType     string
	MountAccessor string
	Warnings      []string
}
