package interceptors

import (
	"context"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	// RequestIDHeader is the metadata key for request ID
	RequestIDHeader = "x-request-id"
	// RequestIDKey is the context key for request ID
	RequestIDKey contextKey = "request_id"
)

// LoggingInterceptor creates a logging interceptor
func LoggingInterceptor(logger *zap.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Get or generate request ID
		requestID := getOrGenerateRequestID(ctx)
		ctx = context.WithValue(ctx, RequestIDKey, requestID)

		// Add request ID to response metadata
		grpc.SetHeader(ctx, metadata.Pairs(RequestIDHeader, requestID))

		start := time.Now()

		// Call handler
		resp, err := handler(ctx, req)

		// Calculate duration
		duration := time.Since(start)

		// Get status code
		code := codes.OK
		if err != nil {
			code = status.Code(err)
		}

		// Log based on result
		fields := []zap.Field{
			zap.String("request_id", requestID),
			zap.String("method", info.FullMethod),
			zap.Duration("duration", duration),
			zap.String("code", code.String()),
		}

		// Add identity if available
		if identity, ok := GetIdentity(ctx); ok {
			fields = append(fields, zap.String("identity", identity))
		}

		if err != nil {
			fields = append(fields, zap.Error(err))
			logger.Error("gRPC request failed", fields...)
		} else {
			logger.Info("gRPC request completed", fields...)
		}

		return resp, err
	}
}

// StreamLoggingInterceptor creates a streaming logging interceptor
func StreamLoggingInterceptor(logger *zap.Logger) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx := ss.Context()

		// Get or generate request ID
		requestID := getOrGenerateRequestID(ctx)
		ctx = context.WithValue(ctx, RequestIDKey, requestID)

		// Add request ID to response metadata
		grpc.SetHeader(ctx, metadata.Pairs(RequestIDHeader, requestID))

		start := time.Now()

		// Wrap stream with new context
		wrapped := &wrappedStream{ss, ctx}

		// Call handler
		err := handler(srv, wrapped)

		// Calculate duration
		duration := time.Since(start)

		// Get status code
		code := codes.OK
		if err != nil {
			code = status.Code(err)
		}

		// Log
		fields := []zap.Field{
			zap.String("request_id", requestID),
			zap.String("method", info.FullMethod),
			zap.Duration("duration", duration),
			zap.String("code", code.String()),
			zap.Bool("is_client_stream", info.IsClientStream),
			zap.Bool("is_server_stream", info.IsServerStream),
		}

		if err != nil {
			fields = append(fields, zap.Error(err))
			logger.Error("gRPC stream failed", fields...)
		} else {
			logger.Info("gRPC stream completed", fields...)
		}

		return err
	}
}

// getOrGenerateRequestID gets request ID from metadata or generates one
func getOrGenerateRequestID(ctx context.Context) string {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if values := md.Get(RequestIDHeader); len(values) > 0 {
			return values[0]
		}
	}
	return uuid.New().String()
}

// GetRequestID extracts request ID from context
func GetRequestID(ctx context.Context) (string, bool) {
	requestID, ok := ctx.Value(RequestIDKey).(string)
	return requestID, ok
}
