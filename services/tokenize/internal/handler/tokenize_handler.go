package handler

import (
	"context"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	tokenizev1 "github.com/pocketsizefund/microservice-vault/gen/go/tokenize/v1"
	"github.com/pocketsizefund/microservice-vault/services/tokenize/internal/service"
)

type TokenizeHandler struct {
	tokenizev1.UnimplementedTokenizeServiceServer
	service *service.TokenizeService
	logger  *zap.Logger
}

func NewTokenizeHandler(svc *service.TokenizeService, logger *zap.Logger) *TokenizeHandler {
	return &TokenizeHandler{
		service: svc,
		logger:  logger,
	}
}

func (h *TokenizeHandler) Register(server *grpc.Server) {
	tokenizev1.RegisterTokenizeServiceServer(server, h)
}

// FPEEncrypt encrypts using Format-Preserving Encryption
func (h *TokenizeHandler) FPEEncrypt(ctx context.Context, req *tokenizev1.FPEEncryptRequest) (*tokenizev1.FPEEncryptResponse, error) {
	if req.KeyName == "" {
		return nil, status.Error(codes.InvalidArgument, "key_name is required")
	}

	if req.Plaintext == "" {
		return nil, status.Error(codes.InvalidArgument, "plaintext is required")
	}

	ciphertext, version, err := h.service.FPEEncrypt(
		ctx,
		req.KeyName,
		req.Plaintext,
		req.Transformation,
		req.Alphabet,
		req.Tweak,
	)

	if err != nil {
		if err == service.ErrKeyNotFound {
			return nil, status.Error(codes.NotFound, "key not found")
		}
		if err == service.ErrTransformationNotFound {
			return nil, status.Error(codes.NotFound, "transformation not found")
		}
		h.logger.Error("FPE encryption failed", zap.Error(err))
		return nil, status.Error(codes.Internal, "encryption failed")
	}

	return &tokenizev1.FPEEncryptResponse{
		Ciphertext: ciphertext,
		KeyVersion: int32(version),
	}, nil
}

// FPEDecrypt decrypts using Format-Preserving Encryption
func (h *TokenizeHandler) FPEDecrypt(ctx context.Context, req *tokenizev1.FPEDecryptRequest) (*tokenizev1.FPEDecryptResponse, error) {
	if req.KeyName == "" {
		return nil, status.Error(codes.InvalidArgument, "key_name is required")
	}

	if req.Ciphertext == "" {
		return nil, status.Error(codes.InvalidArgument, "ciphertext is required")
	}

	plaintext, version, err := h.service.FPEDecrypt(
		ctx,
		req.KeyName,
		req.Ciphertext,
		req.Transformation,
		req.Alphabet,
		req.Tweak,
	)

	if err != nil {
		if err == service.ErrKeyNotFound {
			return nil, status.Error(codes.NotFound, "key not found")
		}
		if err == service.ErrTransformationNotFound {
			return nil, status.Error(codes.NotFound, "transformation not found")
		}
		h.logger.Error("FPE decryption failed", zap.Error(err))
		return nil, status.Error(codes.Internal, "decryption failed")
	}

	return &tokenizev1.FPEDecryptResponse{
		Plaintext:  plaintext,
		KeyVersion: int32(version),
	}, nil
}

// FPEEncryptBatch encrypts multiple values
func (h *TokenizeHandler) FPEEncryptBatch(ctx context.Context, req *tokenizev1.FPEBatchRequest) (*tokenizev1.FPEBatchResponse, error) {
	if req.KeyName == "" {
		return nil, status.Error(codes.InvalidArgument, "key_name is required")
	}

	if len(req.Items) == 0 {
		return nil, status.Error(codes.InvalidArgument, "items is required")
	}

	// Convert to service items
	items := make([]service.FPEBatchItem, len(req.Items))
	for i, item := range req.Items {
		items[i] = service.FPEBatchItem{
			Value:     item.Value,
			Tweak:     item.Tweak,
			Reference: item.Reference,
		}
	}

	results := h.service.FPEEncryptBatch(ctx, req.KeyName, req.Transformation, req.Alphabet, items)

	// Convert results
	response := &tokenizev1.FPEBatchResponse{
		Results: make([]*tokenizev1.FPEBatchResult, len(results)),
	}

	for i, result := range results {
		errMsg := ""
		if result.Error != nil {
			errMsg = result.Error.Error()
		}
		response.Results[i] = &tokenizev1.FPEBatchResult{
			Value:      result.Value,
			KeyVersion: int32(result.KeyVersion),
			Reference:  result.Reference,
			Error:      errMsg,
		}
	}

	return response, nil
}

// FPEDecryptBatch decrypts multiple values
func (h *TokenizeHandler) FPEDecryptBatch(ctx context.Context, req *tokenizev1.FPEBatchRequest) (*tokenizev1.FPEBatchResponse, error) {
	if req.KeyName == "" {
		return nil, status.Error(codes.InvalidArgument, "key_name is required")
	}

	if len(req.Items) == 0 {
		return nil, status.Error(codes.InvalidArgument, "items is required")
	}

	items := make([]service.FPEBatchItem, len(req.Items))
	for i, item := range req.Items {
		items[i] = service.FPEBatchItem{
			Value:     item.Value,
			Tweak:     item.Tweak,
			Reference: item.Reference,
		}
	}

	results := h.service.FPEDecryptBatch(ctx, req.KeyName, req.Transformation, req.Alphabet, items)

	response := &tokenizev1.FPEBatchResponse{
		Results: make([]*tokenizev1.FPEBatchResult, len(results)),
	}

	for i, result := range results {
		errMsg := ""
		if result.Error != nil {
			errMsg = result.Error.Error()
		}
		response.Results[i] = &tokenizev1.FPEBatchResult{
			Value:      result.Value,
			KeyVersion: int32(result.KeyVersion),
			Reference:  result.Reference,
			Error:      errMsg,
		}
	}

	return response, nil
}

// Mask masks a value
func (h *TokenizeHandler) Mask(ctx context.Context, req *tokenizev1.MaskRequest) (*tokenizev1.MaskResponse, error) {
	if req.Value == "" {
		return nil, status.Error(codes.InvalidArgument, "value is required")
	}

	var preserveFirst, preserveLast int32
	var maskChar string = "*"

	if req.Pattern != nil {
		preserveFirst = req.Pattern.PreserveFirst
		preserveLast = req.Pattern.PreserveLast
		if req.Pattern.MaskChar != "" {
			maskChar = req.Pattern.MaskChar
		}
	}

	masked, err := h.service.Mask(ctx, req.Value, int(preserveFirst), int(preserveLast), maskChar)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &tokenizev1.MaskResponse{
		MaskedValue: masked,
	}, nil
}

// MaskBatch masks multiple values
func (h *TokenizeHandler) MaskBatch(ctx context.Context, req *tokenizev1.MaskBatchRequest) (*tokenizev1.MaskBatchResponse, error) {
	if len(req.Items) == 0 {
		return nil, status.Error(codes.InvalidArgument, "items is required")
	}

	// Get pattern from request level
	var preserveFirst, preserveLast int32
	var maskChar string = "*"

	if req.Pattern != nil {
		preserveFirst = req.Pattern.PreserveFirst
		preserveLast = req.Pattern.PreserveLast
		if req.Pattern.MaskChar != "" {
			maskChar = req.Pattern.MaskChar
		}
	}

	response := &tokenizev1.MaskBatchResponse{
		Results: make([]*tokenizev1.MaskBatchResult, len(req.Items)),
	}

	for i, item := range req.Items {
		masked, err := h.service.Mask(ctx, item.Value, int(preserveFirst), int(preserveLast), maskChar)
		errMsg := ""
		if err != nil {
			errMsg = err.Error()
		}
		response.Results[i] = &tokenizev1.MaskBatchResult{
			MaskedValue: masked,
			Reference:   item.Reference,
			Error:       errMsg,
		}
	}

	return response, nil
}

// ListTransformations returns all available transformations
func (h *TokenizeHandler) ListTransformations(ctx context.Context, req *tokenizev1.ListTransformationsRequest) (*tokenizev1.ListTransformationsResponse, error) {
	transformations := h.service.ListTransformations(ctx)

	response := &tokenizev1.ListTransformationsResponse{
		Transformations: make([]*tokenizev1.Transformation, len(transformations)),
	}

	for i, t := range transformations {
		response.Transformations[i] = &tokenizev1.Transformation{
			Name:        t.Name,
			Alphabet:    t.Alphabet,
			Pattern:     t.Pattern,
			Description: t.Description,
		}
	}

	return response, nil
}

// GetTransformation gets a single transformation by name
func (h *TokenizeHandler) GetTransformation(ctx context.Context, req *tokenizev1.GetTransformationRequest) (*tokenizev1.Transformation, error) {
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}

	t, err := h.service.GetTransformation(ctx, req.Name)
	if err != nil {
		if err == service.ErrTransformationNotFound {
			return nil, status.Error(codes.NotFound, "transformation not found")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &tokenizev1.Transformation{
		Name:        t.Name,
		Alphabet:    t.Alphabet,
		Pattern:     t.Pattern,
		Description: t.Description,
	}, nil
}

// CreateTransformation creates a new transformation
func (h *TokenizeHandler) CreateTransformation(ctx context.Context, req *tokenizev1.CreateTransformationRequest) (*tokenizev1.CreateTransformationResponse, error) {
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}

	trans, err := h.service.CreateTransformation(ctx, req.Name, req.Alphabet, req.Pattern, req.Description)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &tokenizev1.CreateTransformationResponse{
		Transformation: &tokenizev1.Transformation{
			Name:        trans.Name,
			Alphabet:    trans.Alphabet,
			Pattern:     trans.Pattern,
			Description: trans.Description,
		},
	}, nil
}

// DeleteTransformation deletes a transformation
func (h *TokenizeHandler) DeleteTransformation(ctx context.Context, req *tokenizev1.DeleteTransformationRequest) (*tokenizev1.DeleteTransformationResponse, error) {
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}

	err := h.service.DeleteTransformation(ctx, req.Name)
	if err != nil {
		if err == service.ErrTransformationNotFound {
			return nil, status.Error(codes.NotFound, "transformation not found")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &tokenizev1.DeleteTransformationResponse{
		Success: true,
	}, nil
}
