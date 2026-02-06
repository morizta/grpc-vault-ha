package config

import (
	"os"
	"strconv"
	"time"
)

// Config holds Crypto Service configuration
type Config struct {
	Server      ServerConfig
	WorkerPool  WorkerPoolConfig
	KeyCache    KeyCacheConfig
	LockService LockServiceConfig
}

// ServerConfig holds server settings
type ServerConfig struct {
	GRPCPort int
}

// WorkerPoolConfig holds worker pool settings
type WorkerPoolConfig struct {
	Size      int
	QueueSize int
}

// KeyCacheConfig holds key cache settings
type KeyCacheConfig struct {
	Size int
	// No TTL - permanent cache like HashiCorp Vault
	// Keys are invalidated only on rotation/deletion
}

// LockServiceConfig holds Lock Service connection settings
type LockServiceConfig struct {
	Address string
	Timeout time.Duration
}

// Load loads configuration from environment
func Load() (*Config, error) {
	cfg := &Config{
		Server: ServerConfig{
			GRPCPort: getEnvInt("CRYPTO_GRPC_PORT", 9092),
		},
		WorkerPool: WorkerPoolConfig{
			Size:      getEnvInt("CRYPTO_WORKER_POOL_SIZE", 200),
			QueueSize: getEnvInt("CRYPTO_WORKER_QUEUE_SIZE", 10000),
		},
		KeyCache: KeyCacheConfig{
			Size: getEnvInt("CRYPTO_KEY_CACHE_SIZE", 1000),
		},
		LockService: LockServiceConfig{
			Address: getEnv("LOCK_SERVICE_ADDRESS", "localhost:9094"),
			Timeout: getEnvDuration("LOCK_SERVICE_TIMEOUT", 5*time.Second),
		},
	}

	return cfg, nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}
