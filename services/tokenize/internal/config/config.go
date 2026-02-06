package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Server      ServerConfig
	KeyCache    KeyCacheConfig
	LockService LockServiceConfig
	WorkerPool  WorkerPoolConfig
}

type ServerConfig struct {
	GRPCPort int
}

type KeyCacheConfig struct {
	Size int
	// No TTL - permanent cache like HashiCorp Vault
	// Keys are invalidated only on rotation/deletion
}

type LockServiceConfig struct {
	Address string
	Timeout time.Duration
}

type WorkerPoolConfig struct {
	Size int
}

func Load() (*Config, error) {
	return &Config{
		Server: ServerConfig{
			GRPCPort: getEnvInt("TOKENIZE_GRPC_PORT", 9093),
		},
		KeyCache: KeyCacheConfig{
			Size: getEnvInt("TOKENIZE_KEY_CACHE_SIZE", 500),
		},
		LockService: LockServiceConfig{
			Address: getEnv("LOCK_SERVICE_ADDRESS", "localhost:9094"),
			Timeout: getEnvDuration("LOCK_SERVICE_TIMEOUT", 5*time.Second),
		},
		WorkerPool: WorkerPoolConfig{
			Size: getEnvInt("TOKENIZE_WORKER_POOL_SIZE", 100),
		},
	}, nil
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
