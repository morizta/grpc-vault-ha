package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"

	_ "github.com/pocketsizefund/microservice-vault/pkg/grpcutil/codec" // vtprotobuf codec
	"github.com/pocketsizefund/microservice-vault/pkg/telemetry/logging"
	gwauth "github.com/pocketsizefund/microservice-vault/services/gateway/internal/auth"
	"github.com/pocketsizefund/microservice-vault/services/gateway/internal/config"
	"github.com/pocketsizefund/microservice-vault/services/gateway/internal/middleware"
	"github.com/pocketsizefund/microservice-vault/services/gateway/internal/proxy"
	"github.com/pocketsizefund/microservice-vault/services/gateway/internal/router"
)

func main() {
	// Initialize logger
	logger, err := logging.NewLogger("info", "json")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()
	logging.SetDefault(logger)

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		logger.Fatal("Failed to load configuration", zap.Error(err))
	}

	// Initialize circuit breaker manager
	cbManager := middleware.NewCircuitBreakerManager(middleware.CircuitBreakerConfig{
		MaxRequests:  cfg.CircuitBreak.MaxRequests,
		Interval:     cfg.CircuitBreak.Interval,
		Timeout:      cfg.CircuitBreak.Timeout,
		FailureRatio: cfg.CircuitBreak.FailureRatio,
	})

	// Initialize gRPC proxy
	grpcProxy := proxy.NewGRPCProxy(logger, cbManager)
	defer grpcProxy.Close()

	// Initialize rate limiter
	var rateLimiter *middleware.RateLimiter
	if cfg.RateLimit.Enabled {
		rateLimiter = middleware.NewRateLimiter(
			cfg.RateLimit.RequestsPerSec,
			cfg.RateLimit.BurstSize,
			cfg.RateLimit.CleanupInterval,
		)
	}

	// Initialize authentication and authorization
	var authMiddleware *middleware.AuthMiddleware
	var authorizer *gwauth.Authorizer

	if cfg.Auth.Enabled {
		logger.Info("Initializing authentication and authorization",
			zap.String("auth_service", cfg.Services.AuthAddress),
			zap.Int("token_cache_size", cfg.Auth.TokenCacheSize),
			zap.Duration("policy_sync_interval", cfg.Auth.PolicySyncInterval),
		)

		// Connect to auth service with optimized keepalive settings
		authConn, err := grpc.DialContext(
			context.Background(),
			cfg.Services.AuthAddress,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithKeepaliveParams(keepalive.ClientParameters{
				Time:                30 * time.Second,
				Timeout:             10 * time.Second,
				PermitWithoutStream: true,
			}),
		)
		if err != nil {
			logger.Fatal("Failed to connect to auth service", zap.Error(err))
		}
		defer authConn.Close()

		// Create auth client with LRU caching and background policy sync
		authClient, err := gwauth.NewAuthClient(logger, gwauth.AuthClientConfig{
			AuthConn:           authConn,
			TokenCacheSize:     cfg.Auth.TokenCacheSize,
			TokenCacheTTL:      cfg.Auth.TokenCacheTTL,
			APIKeyCacheSize:    cfg.Auth.APIKeyCacheSize,
			APIKeyCacheTTL:     cfg.Auth.APIKeyCacheTTL,
			PolicySyncInterval: cfg.Auth.PolicySyncInterval,
		})
		if err != nil {
			logger.Fatal("Failed to create auth client", zap.Error(err))
		}
		defer authClient.Close()

		// Paths that skip authentication (replicating Vault behavior):
		// - Health checks: always accessible
		// - Login: authentication entry point
		// - Seal status, init, unseal: use Shamir shares instead of tokens
		skipPaths := []string{
			"/health/live",
			"/health/ready",
			"/status",
			"/v1/auth/login",
			"/v1/sys/seal-status",
			"/v1/sys/init",
			"/v1/sys/unseal",
		}

		authMiddleware = middleware.NewAuthMiddleware(authClient, skipPaths)
		authorizer = gwauth.NewAuthorizer(logger, authClient)

		logger.Info("Authentication and authorization initialized successfully")
	} else {
		logger.Warn("Authentication is DISABLED (GATEWAY_AUTH_ENABLED=false)")
	}

	// Initialize router with auth middleware
	httpRouter := router.NewRouter(logger, grpcProxy, cfg, rateLimiter, authMiddleware, authorizer)

	// Create HTTP server with optimized settings for high throughput
	httpServer := &http.Server{
		Addr:           fmt.Sprintf(":%d", cfg.Server.HTTPPort),
		Handler:        httpRouter.Handler(),
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1MB
	}

	// Create gRPC server
	grpcServer := grpc.NewServer()

	// Register health service
	healthServer := health.NewServer()
	grpc_health_v1.RegisterHealthServer(grpcServer, healthServer)
	healthServer.SetServingStatus("gateway.v1.GatewayService", grpc_health_v1.HealthCheckResponse_SERVING)

	// Enable reflection for development
	reflection.Register(grpcServer)

	// Create gRPC listener
	grpcListener, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Server.GRPCPort))
	if err != nil {
		logger.Fatal("Failed to listen on gRPC port", zap.Error(err), zap.Int("port", cfg.Server.GRPCPort))
	}

	// Context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start HTTP server
	go func() {
		logger.Info("Starting HTTP server", zap.Int("port", cfg.Server.HTTPPort))
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("HTTP server failed", zap.Error(err))
		}
	}()

	// Start gRPC server
	go func() {
		logger.Info("Starting gRPC server", zap.Int("port", cfg.Server.GRPCPort))
		if err := grpcServer.Serve(grpcListener); err != nil {
			logger.Fatal("gRPC server failed", zap.Error(err))
		}
	}()

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	logger.Info("Shutting down...")

	// Update health status
	healthServer.SetServingStatus("gateway.v1.GatewayService", grpc_health_v1.HealthCheckResponse_NOT_SERVING)

	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(ctx, 30*time.Second)
	defer shutdownCancel()

	// Shutdown HTTP server
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("HTTP server shutdown error", zap.Error(err))
	}

	// Shutdown gRPC server
	grpcServer.GracefulStop()

	cancel()
	logger.Info("Gateway Service stopped")
}
