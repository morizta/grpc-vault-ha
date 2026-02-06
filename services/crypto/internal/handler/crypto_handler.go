package handler

import (
	"context"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	cryptov1 "github.com/pocketsizefund/microservice-vault/gen/go/crypto/v1"
	"github.com/pocketsizefund/microservice-vault/services/crypto/internal/service"
)

// CryptoHandler implements the gRPC CryptoService
type CryptoHandler struct {
	cryptov1.UnimplementedCryptoServiceServer
	service *service.CryptoService
	logger  *zap.Logger
}

// NewCryptoHandler creates a new crypto handler
func NewCryptoHandler(svc *service.CryptoService, logger *zap.Logger) *CryptoHandler {
	return &CryptoHandler{
		service: svc,
		logger:  logger,
	}
}

// Register registers the handler with a gRPC server
func (h *CryptoHandler) Register(server *grpc.Server) {
	cryptov1.RegisterCryptoServiceServer(server, h)
}

// Encrypt encrypts plaintext
func (h *CryptoHandler) Encrypt(ctx context.Context, req *cryptov1.EncryptRequest) (*cryptov1.EncryptResponse, error) {
	if req.KeyName == "" {
		return nil, status.Error(codes.InvalidArgument, "key_name is required")
	}

	if len(req.Plaintext) == 0 {
		return nil, status.Error(codes.InvalidArgument, "plaintext is required")
	}

	ciphertext, version, err := h.service.Encrypt(ctx, req.KeyName, req.Plaintext, req.Context)
	if err != nil {
		if err == service.ErrKeyNotFound {
			return nil, status.Error(codes.NotFound, "key not found")
		}
		h.logger.Error("Encryption failed", zap.Error(err), zap.String("key", req.KeyName))
		return nil, status.Error(codes.Internal, "encryption failed")
	}

	return &cryptov1.EncryptResponse{
		Ciphertext: ciphertext,
		KeyVersion: int32(version),
	}, nil
}

// Decrypt decrypts ciphertext
func (h *CryptoHandler) Decrypt(ctx context.Context, req *cryptov1.DecryptRequest) (*cryptov1.DecryptResponse, error) {
	if req.KeyName == "" {
		return nil, status.Error(codes.InvalidArgument, "key_name is required")
	}

	if req.Ciphertext == "" {
		return nil, status.Error(codes.InvalidArgument, "ciphertext is required")
	}

	plaintext, version, err := h.service.Decrypt(ctx, req.KeyName, req.Ciphertext, req.Context)
	if err != nil {
		if err == service.ErrKeyNotFound {
			return nil, status.Error(codes.NotFound, "key not found")
		}
		if err == service.ErrDecryptFailed {
			return nil, status.Error(codes.InvalidArgument, "decryption failed")
		}
		h.logger.Error("Decryption failed", zap.Error(err), zap.String("key", req.KeyName))
		return nil, status.Error(codes.Internal, "decryption failed")
	}

	return &cryptov1.DecryptResponse{
		Plaintext:  plaintext,
		KeyVersion: int32(version),
	}, nil
}

// EncryptBatch encrypts multiple items
func (h *CryptoHandler) EncryptBatch(ctx context.Context, req *cryptov1.EncryptBatchRequest) (*cryptov1.EncryptBatchResponse, error) {
	if req.KeyName == "" {
		return nil, status.Error(codes.InvalidArgument, "key_name is required")
	}

	if len(req.Items) == 0 {
		return nil, status.Error(codes.InvalidArgument, "items is required")
	}

	// Convert to service items
	items := make([]service.BatchItem, len(req.Items))
	for i, item := range req.Items {
		items[i] = service.BatchItem{
			Plaintext: item.Plaintext,
			Context:   item.Context,
			Reference: item.Reference,
		}
	}

	results := h.service.EncryptBatch(ctx, req.KeyName, items)

	// Convert results
	response := &cryptov1.EncryptBatchResponse{
		Results: make([]*cryptov1.BatchEncryptResult, len(results)),
	}

	for i, result := range results {
		errMsg := ""
		if result.Error != nil {
			errMsg = result.Error.Error()
		}
		response.Results[i] = &cryptov1.BatchEncryptResult{
			Ciphertext: result.Ciphertext,
			KeyVersion: int32(result.KeyVersion),
			Reference:  result.Reference,
			Error:      errMsg,
		}
	}

	return response, nil
}

// DecryptBatch decrypts multiple items
func (h *CryptoHandler) DecryptBatch(ctx context.Context, req *cryptov1.DecryptBatchRequest) (*cryptov1.DecryptBatchResponse, error) {
	if req.KeyName == "" {
		return nil, status.Error(codes.InvalidArgument, "key_name is required")
	}

	if len(req.Items) == 0 {
		return nil, status.Error(codes.InvalidArgument, "items is required")
	}

	// Convert to service items
	items := make([]service.BatchDecryptItem, len(req.Items))
	for i, item := range req.Items {
		items[i] = service.BatchDecryptItem{
			Ciphertext: item.Ciphertext,
			Context:    item.Context,
			Reference:  item.Reference,
		}
	}

	results := h.service.DecryptBatch(ctx, req.KeyName, items)

	// Convert results
	response := &cryptov1.DecryptBatchResponse{
		Results: make([]*cryptov1.BatchDecryptResult, len(results)),
	}

	for i, result := range results {
		errMsg := ""
		if result.Error != nil {
			errMsg = result.Error.Error()
		}
		response.Results[i] = &cryptov1.BatchDecryptResult{
			Plaintext:  result.Plaintext,
			KeyVersion: int32(result.KeyVersion),
			Reference:  result.Reference,
			Error:      errMsg,
		}
	}

	return response, nil
}

// GenerateRandom generates random bytes
func (h *CryptoHandler) GenerateRandom(ctx context.Context, req *cryptov1.GenerateRandomRequest) (*cryptov1.GenerateRandomResponse, error) {
	if req.Bytes <= 0 {
		return nil, status.Error(codes.InvalidArgument, "bytes must be positive")
	}

	data, err := h.service.GenerateRandom(ctx, int(req.Bytes), req.Format)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &cryptov1.GenerateRandomResponse{
		Data: data,
	}, nil
}
