package proxy

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"

	"github.com/pocketsizefund/microservice-vault/services/gateway/internal/middleware"
)

// ServiceConnection holds a gRPC client connection pool
type ServiceConnection struct {
	conns   []*grpc.ClientConn
	address string
	counter uint64
}

// PoolSize is the number of connections per service
// Increased for high concurrency workloads (500+ concurrent requests)
const PoolSize = 50

// GRPCProxy manages connections to backend services
type GRPCProxy struct {
	logger    *zap.Logger
	cbManager *middleware.CircuitBreakerManager

	mu          sync.RWMutex
	connections map[string]*ServiceConnection
	dialOpts    []grpc.DialOption
}

// NewGRPCProxy creates a new gRPC proxy
func NewGRPCProxy(logger *zap.Logger, cbManager *middleware.CircuitBreakerManager) *GRPCProxy {
	// Optimized keepalive parameters for high throughput
	kaParams := keepalive.ClientParameters{
		Time:                10 * time.Second, // Send keepalive ping every 10s
		Timeout:             3 * time.Second,  // Wait 3s for ping ack
		PermitWithoutStream: true,             // Allow ping even without active streams
	}

	dialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithUnaryInterceptor(cbManager.UnaryClientInterceptor()),
		grpc.WithKeepaliveParams(kaParams),
		grpc.WithInitialWindowSize(1 << 20),     // 1MB initial window size
		grpc.WithInitialConnWindowSize(1 << 20), // 1MB initial connection window
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(16*1024*1024), // 16MB max receive message
			grpc.MaxCallSendMsgSize(16*1024*1024), // 16MB max send message
		),
	}

	return &GRPCProxy{
		logger:      logger,
		cbManager:   cbManager,
		connections: make(map[string]*ServiceConnection),
		dialOpts:    dialOpts,
	}
}

// GetConnection returns a connection from the pool using round-robin
func (p *GRPCProxy) GetConnection(ctx context.Context, serviceName, address string) (*grpc.ClientConn, error) {
	p.mu.RLock()
	if svc, ok := p.connections[serviceName]; ok && svc.address == address && len(svc.conns) > 0 {
		// Round-robin selection from pool
		idx := atomic.AddUint64(&svc.counter, 1) % uint64(len(svc.conns))
		p.mu.RUnlock()
		return svc.conns[idx], nil
	}
	p.mu.RUnlock()

	// Create new connection pool
	p.mu.Lock()
	defer p.mu.Unlock()

	// Double check after acquiring write lock
	if svc, ok := p.connections[serviceName]; ok && svc.address == address && len(svc.conns) > 0 {
		idx := atomic.AddUint64(&svc.counter, 1) % uint64(len(svc.conns))
		return svc.conns[idx], nil
	}

	// Close old connections if exists
	if svc, ok := p.connections[serviceName]; ok {
		for _, conn := range svc.conns {
			conn.Close()
		}
	}

	// Create connection pool
	conns := make([]*grpc.ClientConn, 0, PoolSize)
	for i := 0; i < PoolSize; i++ {
		dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		conn, err := grpc.DialContext(dialCtx, address, p.dialOpts...)
		cancel()
		if err != nil {
			// Close already created connections
			for _, c := range conns {
				c.Close()
			}
			p.logger.Error("Failed to connect to service",
				zap.String("service", serviceName),
				zap.String("address", address),
				zap.Error(err))
			return nil, status.Errorf(codes.Unavailable, "failed to connect to %s", serviceName)
		}
		conns = append(conns, conn)
	}

	p.connections[serviceName] = &ServiceConnection{
		conns:   conns,
		address: address,
		counter: 0,
	}

	p.logger.Info("Connected to service with pool",
		zap.String("service", serviceName),
		zap.String("address", address),
		zap.Int("pool_size", PoolSize))

	return conns[0], nil
}

// Close closes all connections
func (p *GRPCProxy) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	for name, svc := range p.connections {
		for i, conn := range svc.conns {
			if err := conn.Close(); err != nil {
				p.logger.Error("Failed to close connection",
					zap.String("service", name),
					zap.Int("conn_index", i),
					zap.Error(err))
			}
		}
	}

	p.connections = make(map[string]*ServiceConnection)
	return nil
}

// ServiceHealth checks the health of a service
type ServiceHealth struct {
	Name    string
	Address string
	Healthy bool
	Latency time.Duration
	Error   string
}

// HealthCheck checks health of all services
func (p *GRPCProxy) HealthCheck(ctx context.Context, services map[string]string) []ServiceHealth {
	results := make([]ServiceHealth, 0, len(services))
	var mu sync.Mutex
	var wg sync.WaitGroup

	for name, address := range services {
		wg.Add(1)
		go func(name, address string) {
			defer wg.Done()

			health := ServiceHealth{
				Name:    name,
				Address: address,
			}

			start := time.Now()
			conn, err := p.GetConnection(ctx, name, address)
			if err != nil {
				health.Error = err.Error()
			} else if conn != nil {
				// Simple connectivity check
				state := conn.GetState()
				health.Healthy = state.String() == "READY" || state.String() == "IDLE"
				if !health.Healthy {
					health.Error = "connection state: " + state.String()
				}
			}
			health.Latency = time.Since(start)

			mu.Lock()
			results = append(results, health)
			mu.Unlock()
		}(name, address)
	}

	wg.Wait()
	return results
}
