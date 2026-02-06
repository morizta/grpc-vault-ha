// Package logging provides structured logging utilities
package logging

import (
	"context"
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type contextKey string

const (
	loggerKey   contextKey = "logger"
	requestIDKey contextKey = "request_id"
)

var defaultLogger *zap.Logger

func init() {
	defaultLogger, _ = NewLogger("info", "json")
}

// NewLogger creates a new zap logger
func NewLogger(level, format string) (*zap.Logger, error) {
	var config zap.Config

	if format == "json" {
		config = zap.NewProductionConfig()
	} else {
		config = zap.NewDevelopmentConfig()
		config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}

	// Parse level
	var zapLevel zapcore.Level
	if err := zapLevel.UnmarshalText([]byte(level)); err != nil {
		zapLevel = zapcore.InfoLevel
	}
	config.Level = zap.NewAtomicLevelAt(zapLevel)

	// Customize encoder
	config.EncoderConfig.TimeKey = "timestamp"
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	config.EncoderConfig.MessageKey = "msg"
	config.EncoderConfig.LevelKey = "level"
	config.EncoderConfig.CallerKey = "caller"

	logger, err := config.Build(
		zap.AddCaller(),
		zap.AddStacktrace(zapcore.ErrorLevel),
	)
	if err != nil {
		return nil, err
	}

	return logger, nil
}

// Default returns the default logger
func Default() *zap.Logger {
	return defaultLogger
}

// SetDefault sets the default logger
func SetDefault(logger *zap.Logger) {
	defaultLogger = logger
}

// WithContext returns a logger with context values
func WithContext(ctx context.Context) *zap.Logger {
	logger := defaultLogger

	if l, ok := ctx.Value(loggerKey).(*zap.Logger); ok {
		logger = l
	}

	if requestID, ok := ctx.Value(requestIDKey).(string); ok {
		logger = logger.With(zap.String("request_id", requestID))
	}

	return logger
}

// NewContext creates a context with a logger
func NewContext(ctx context.Context, logger *zap.Logger) context.Context {
	return context.WithValue(ctx, loggerKey, logger)
}

// WithRequestID adds a request ID to the context
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDKey, requestID)
}

// Field types for convenience
type Field = zap.Field

// Field constructors
var (
	String   = zap.String
	Int      = zap.Int
	Int64    = zap.Int64
	Float64  = zap.Float64
	Bool     = zap.Bool
	Error    = zap.Error
	Duration = zap.Duration
	Any      = zap.Any
	Time     = zap.Time
)

// ServiceLogger wraps zap.Logger with service-specific fields
type ServiceLogger struct {
	*zap.Logger
	service string
}

// NewServiceLogger creates a logger with service name
func NewServiceLogger(service string) *ServiceLogger {
	return &ServiceLogger{
		Logger:  defaultLogger.With(zap.String("service", service)),
		service: service,
	}
}

// WithOperation adds operation field
func (l *ServiceLogger) WithOperation(operation string) *zap.Logger {
	return l.Logger.With(zap.String("operation", operation))
}

// WithRequestID adds request_id field
func (l *ServiceLogger) WithRequestID(requestID string) *zap.Logger {
	return l.Logger.With(zap.String("request_id", requestID))
}

// WithIdentity adds identity field
func (l *ServiceLogger) WithIdentity(identity string) *zap.Logger {
	return l.Logger.With(zap.String("identity", identity))
}

// Fatal logs a fatal message and exits
func Fatal(msg string, fields ...Field) {
	defaultLogger.Fatal(msg, fields...)
	os.Exit(1)
}

// Sync flushes any buffered log entries
func Sync() error {
	return defaultLogger.Sync()
}
