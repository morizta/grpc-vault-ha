package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"

	_ "github.com/pocketsizefund/microservice-vault/pkg/grpcutil/codec" // vtprotobuf codec
	"github.com/pocketsizefund/microservice-vault/pkg/telemetry/logging"
	"github.com/pocketsizefund/microservice-vault/services/crypto/internal/config"
	"github.com/pocketsizefund/microservice-vault/services/crypto/internal/handler"
	"github.com/pocketsizefund/microservice-vault/services/crypto/internal/service"
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

	// Create crypto service
	cryptoService, err := service.NewCryptoService(cfg, logger)
	if err != nil {
		logger.Fatal("Failed to create crypto service", zap.Error(err))
	}

	// Create gRPC server with optimized settings for high throughput
	grpcServer := grpc.NewServer(
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle:     15 * time.Second,
			MaxConnectionAge:      30 * time.Second,
			MaxConnectionAgeGrace: 5 * time.Second,
			Time:                  5 * time.Second,
			Timeout:               1 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             5 * time.Second,
			PermitWithoutStream: true,
		}),
		grpc.MaxRecvMsgSize(16*1024*1024), // 16MB
		grpc.MaxSendMsgSize(16*1024*1024), // 16MB
		grpc.NumStreamWorkers(uint32(100)),
	)

	// Register handlers
	cryptoHandler := handler.NewCryptoHandler(cryptoService, logger)
	cryptoHandler.Register(grpcServer)

	// Register health service
	healthServer := health.NewServer()
	grpc_health_v1.RegisterHealthServer(grpcServer, healthServer)
	healthServer.SetServingStatus("crypto.v1.CryptoService", grpc_health_v1.HealthCheckResponse_SERVING)

	// Enable reflection
	reflection.Register(grpcServer)

	// Start server
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Server.GRPCPort))
	if err != nil {
		logger.Fatal("Failed to listen", zap.Error(err), zap.Int("port", cfg.Server.GRPCPort))
	}

	// Graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh

		logger.Info("Shutting down...")
		healthServer.SetServingStatus("crypto.v1.CryptoService", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
		grpcServer.GracefulStop()
		cancel()
	}()

	// Start pprof server for profiling
	go func() {
		pprofAddr := ":6060"
		logger.Info("Starting pprof server", zap.String("addr", pprofAddr))
		if err := http.ListenAndServe(pprofAddr, nil); err != nil {
			logger.Error("pprof server error", zap.Error(err))
		}
	}()

	logger.Info("Crypto Service started",
		zap.Int("grpc_port", cfg.Server.GRPCPort),
		zap.Int("worker_pool_size", cfg.WorkerPool.Size),
	)

	if err := grpcServer.Serve(listener); err != nil {
		logger.Fatal("Failed to serve", zap.Error(err))
	}

	<-ctx.Done()
	logger.Info("Crypto Service stopped")
}
