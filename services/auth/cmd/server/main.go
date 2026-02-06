package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	_ "github.com/pocketsizefund/microservice-vault/pkg/grpcutil/codec" // vtprotobuf codec
	"github.com/pocketsizefund/microservice-vault/pkg/telemetry/logging"
	"github.com/pocketsizefund/microservice-vault/services/auth/internal/config"
	"github.com/pocketsizefund/microservice-vault/services/auth/internal/handler"
	"github.com/pocketsizefund/microservice-vault/services/auth/internal/repository"
	"github.com/pocketsizefund/microservice-vault/services/auth/internal/service"
)

func main() {
	logger, err := logging.NewLogger("info", "json")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()
	logging.SetDefault(logger)

	cfg, err := config.Load()
	if err != nil {
		logger.Fatal("Failed to load configuration", zap.Error(err))
	}

	// Initialize repositories
	tokenRepo := repository.NewMemoryTokenRepository()
	apiKeyRepo := repository.NewMemoryAPIKeyRepository()
	policyRepo := repository.NewMemoryPolicyRepository()

	// Create auth service
	authService, err := service.NewAuthService(cfg, logger, tokenRepo, apiKeyRepo, policyRepo)
	if err != nil {
		logger.Fatal("Failed to create auth service", zap.Error(err))
	}

	// Create gRPC server
	grpcServer := grpc.NewServer()

	// Register handler
	authHandler := handler.NewAuthHandler(authService, logger)
	authHandler.Register(grpcServer)

	// Health check
	healthServer := health.NewServer()
	grpc_health_v1.RegisterHealthServer(grpcServer, healthServer)
	healthServer.SetServingStatus("auth.v1.AuthService", grpc_health_v1.HealthCheckResponse_SERVING)

	reflection.Register(grpcServer)

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Server.GRPCPort))
	if err != nil {
		logger.Fatal("Failed to listen", zap.Error(err), zap.Int("port", cfg.Server.GRPCPort))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh

		logger.Info("Shutting down...")
		healthServer.SetServingStatus("auth.v1.AuthService", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
		grpcServer.GracefulStop()
		cancel()
	}()

	logger.Info("Auth Service started", zap.Int("grpc_port", cfg.Server.GRPCPort))

	if err := grpcServer.Serve(listener); err != nil {
		logger.Fatal("Failed to serve", zap.Error(err))
	}

	<-ctx.Done()
	logger.Info("Auth Service stopped")
}
