package middleware

import (
	"context"
	"errors"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var ErrCircuitOpen = errors.New("circuit breaker is open")

// State represents circuit breaker state
type State int

const (
	StateClosed State = iota
	StateHalfOpen
	StateOpen
)

func (s State) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateHalfOpen:
		return "half-open"
	case StateOpen:
		return "open"
	default:
		return "unknown"
	}
}

// CircuitBreaker implements the circuit breaker pattern
type CircuitBreaker struct {
	name         string
	maxRequests  uint32
	interval     time.Duration
	timeout      time.Duration
	failureRatio float64

	mu          sync.Mutex
	state       State
	counts      Counts
	expiry      time.Time
	lastFailure time.Time
}

// Counts holds the circuit breaker metrics
type Counts struct {
	Requests             uint32
	TotalSuccesses       uint32
	TotalFailures        uint32
	ConsecutiveSuccesses uint32
	ConsecutiveFailures  uint32
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(name string, maxRequests uint32, interval, timeout time.Duration, failureRatio float64) *CircuitBreaker {
	return &CircuitBreaker{
		name:         name,
		maxRequests:  maxRequests,
		interval:     interval,
		timeout:      timeout,
		failureRatio: failureRatio,
		state:        StateClosed,
	}
}

// Execute runs the given function with circuit breaker protection
func (cb *CircuitBreaker) Execute(fn func() error) error {
	if err := cb.beforeRequest(); err != nil {
		return err
	}

	err := fn()
	cb.afterRequest(err)

	return err
}

// beforeRequest checks if request should be allowed
func (cb *CircuitBreaker) beforeRequest() error {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	now := time.Now()

	switch cb.state {
	case StateClosed:
		if !cb.expiry.IsZero() && cb.expiry.Before(now) {
			cb.reset()
		}
	case StateOpen:
		if cb.expiry.Before(now) {
			cb.setState(StateHalfOpen)
		} else {
			return ErrCircuitOpen
		}
	case StateHalfOpen:
		if cb.counts.Requests >= cb.maxRequests {
			return ErrCircuitOpen
		}
	}

	cb.counts.Requests++
	return nil
}

// afterRequest records the result
func (cb *CircuitBreaker) afterRequest(err error) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if err == nil {
		cb.onSuccess()
	} else {
		cb.onFailure()
	}
}

// onSuccess handles successful request
func (cb *CircuitBreaker) onSuccess() {
	cb.counts.TotalSuccesses++
	cb.counts.ConsecutiveSuccesses++
	cb.counts.ConsecutiveFailures = 0

	switch cb.state {
	case StateHalfOpen:
		if cb.counts.ConsecutiveSuccesses >= cb.maxRequests {
			cb.setState(StateClosed)
		}
	}
}

// onFailure handles failed request
func (cb *CircuitBreaker) onFailure() {
	cb.counts.TotalFailures++
	cb.counts.ConsecutiveFailures++
	cb.counts.ConsecutiveSuccesses = 0
	cb.lastFailure = time.Now()

	switch cb.state {
	case StateClosed:
		if cb.shouldTrip() {
			cb.setState(StateOpen)
		}
	case StateHalfOpen:
		cb.setState(StateOpen)
	}
}

// shouldTrip checks if circuit should open
func (cb *CircuitBreaker) shouldTrip() bool {
	if cb.counts.Requests < cb.maxRequests {
		return false
	}

	failureRatio := float64(cb.counts.TotalFailures) / float64(cb.counts.Requests)
	return failureRatio >= cb.failureRatio
}

// setState changes the circuit state
func (cb *CircuitBreaker) setState(state State) {
	if cb.state == state {
		return
	}

	cb.state = state

	switch state {
	case StateClosed:
		cb.expiry = time.Now().Add(cb.interval)
		cb.counts = Counts{}
	case StateOpen:
		cb.expiry = time.Now().Add(cb.timeout)
	case StateHalfOpen:
		cb.counts = Counts{}
	}
}

// reset resets the counts
func (cb *CircuitBreaker) reset() {
	cb.counts = Counts{}
	cb.expiry = time.Now().Add(cb.interval)
}

// State returns current state
func (cb *CircuitBreaker) State() State {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.state
}

// CircuitBreakerManager manages circuit breakers for multiple services
type CircuitBreakerManager struct {
	breakers sync.Map
	config   CircuitBreakerConfig
}

// CircuitBreakerConfig holds circuit breaker configuration
type CircuitBreakerConfig struct {
	MaxRequests  uint32
	Interval     time.Duration
	Timeout      time.Duration
	FailureRatio float64
}

// NewCircuitBreakerManager creates a new manager
func NewCircuitBreakerManager(cfg CircuitBreakerConfig) *CircuitBreakerManager {
	return &CircuitBreakerManager{
		config: cfg,
	}
}

// GetBreaker returns or creates a circuit breaker for a service
func (m *CircuitBreakerManager) GetBreaker(name string) *CircuitBreaker {
	if cb, ok := m.breakers.Load(name); ok {
		return cb.(*CircuitBreaker)
	}

	cb := NewCircuitBreaker(
		name,
		m.config.MaxRequests,
		m.config.Interval,
		m.config.Timeout,
		m.config.FailureRatio,
	)

	actual, _ := m.breakers.LoadOrStore(name, cb)
	return actual.(*CircuitBreaker)
}

// UnaryClientInterceptor returns a gRPC client interceptor with circuit breaker
func (m *CircuitBreakerManager) UnaryClientInterceptor() grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req, reply interface{},
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		cb := m.GetBreaker(cc.Target())

		err := cb.Execute(func() error {
			return invoker(ctx, method, req, reply, cc, opts...)
		})

		if errors.Is(err, ErrCircuitOpen) {
			return status.Error(codes.Unavailable, "service temporarily unavailable")
		}

		return err
	}
}
