package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/pocketsizefund/microservice-vault/services/gateway/internal/config"
	"github.com/pocketsizefund/microservice-vault/services/gateway/internal/proxy"
)

// HealthHandler handles health check endpoints
type HealthHandler struct {
	logger    *zap.Logger
	proxy     *proxy.GRPCProxy
	services  map[string]string
	startTime time.Time
}

// NewHealthHandler creates a new health handler
func NewHealthHandler(logger *zap.Logger, proxy *proxy.GRPCProxy, cfg *config.ServicesConfig) *HealthHandler {
	return &HealthHandler{
		logger: logger,
		proxy:  proxy,
		services: map[string]string{
			"auth":     cfg.AuthAddress,
			"crypto":   cfg.CryptoAddress,
			"tokenize": cfg.TokenizeAddress,
			"lock":     cfg.LockAddress,
			"audit":    cfg.AuditAddress,
		},
		startTime: time.Now(),
	}
}

// HealthResponse represents health check response
type HealthResponse struct {
	Status    string           `json:"status"`
	Uptime    string           `json:"uptime"`
	Timestamp string           `json:"timestamp"`
	Services  []ServiceStatus  `json:"services,omitempty"`
}

// ServiceStatus represents individual service health
type ServiceStatus struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Latency string `json:"latency,omitempty"`
	Error   string `json:"error,omitempty"`
}

// Liveness handles /health/live endpoint
func (h *HealthHandler) Liveness(w http.ResponseWriter, r *http.Request) {
	response := HealthResponse{
		Status:    "ok",
		Uptime:    time.Since(h.startTime).String(),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Readiness handles /health/ready endpoint
func (h *HealthHandler) Readiness(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	healthResults := h.proxy.HealthCheck(ctx, h.services)

	allHealthy := true
	services := make([]ServiceStatus, 0, len(healthResults))

	for _, result := range healthResults {
		status := "healthy"
		if !result.Healthy {
			status = "unhealthy"
			allHealthy = false
		}

		services = append(services, ServiceStatus{
			Name:    result.Name,
			Status:  status,
			Latency: result.Latency.String(),
			Error:   result.Error,
		})
	}

	overallStatus := "ok"
	httpStatus := http.StatusOK
	if !allHealthy {
		overallStatus = "degraded"
		httpStatus = http.StatusServiceUnavailable
	}

	response := HealthResponse{
		Status:    overallStatus,
		Uptime:    time.Since(h.startTime).String(),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Services:  services,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	json.NewEncoder(w).Encode(response)
}

// Status handles /status endpoint
func (h *HealthHandler) Status(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"service":   "gateway",
		"version":   "1.0.0",
		"uptime":    time.Since(h.startTime).String(),
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
