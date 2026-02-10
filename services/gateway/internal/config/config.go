package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Server       ServerConfig
	Auth         AuthConfig
	RateLimit    RateLimitConfig
	CircuitBreak CircuitBreakerConfig
	Services     ServicesConfig
	Redis        RedisConfig
}

type AuthConfig struct {
	Enabled            bool
	TokenCacheSize     int
	TokenCacheTTL      time.Duration
	APIKeyCacheSize    int
	APIKeyCacheTTL     time.Duration
	PolicySyncInterval time.Duration
}

type ServerConfig struct {
	HTTPPort int
	GRPCPort int
}

type RateLimitConfig struct {
	Enabled         bool
	RequestsPerSec  int
	BurstSize       int
	CleanupInterval time.Duration
}

type CircuitBreakerConfig struct {
	MaxRequests   uint32
	Interval      time.Duration
	Timeout       time.Duration
	FailureRatio  float64
}

type ServicesConfig struct {
	AuthAddress     string
	CryptoAddress   string
	TokenizeAddress string
	LockAddress     string
	AuditAddress    string
}

type RedisConfig struct {
	Address  string
	Password string
	DB       int
}

func Load() (*Config, error) {
	return &Config{
		Server: ServerConfig{
			HTTPPort: getEnvInt("GATEWAY_HTTP_PORT", 8080),
			GRPCPort: getEnvInt("GATEWAY_GRPC_PORT", 9090),
		},
		Auth: AuthConfig{
			Enabled:            getEnvBool("GATEWAY_AUTH_ENABLED", true),
			TokenCacheSize:     getEnvInt("GATEWAY_AUTH_TOKEN_CACHE_SIZE", 10000),
			TokenCacheTTL:      getEnvDuration("GATEWAY_AUTH_TOKEN_CACHE_TTL", 5*time.Minute),
			APIKeyCacheSize:    getEnvInt("GATEWAY_AUTH_APIKEY_CACHE_SIZE", 5000),
			APIKeyCacheTTL:     getEnvDuration("GATEWAY_AUTH_APIKEY_CACHE_TTL", 5*time.Minute),
			PolicySyncInterval: getEnvDuration("GATEWAY_AUTH_POLICY_SYNC_INTERVAL", 30*time.Second),
		},
		RateLimit: RateLimitConfig{
			Enabled:         getEnvBool("GATEWAY_RATE_LIMIT_ENABLED", false),
			RequestsPerSec:  getEnvInt("GATEWAY_RATE_LIMIT_RPS", 1000),
			BurstSize:       getEnvInt("GATEWAY_RATE_LIMIT_BURST", 0), // 0 = same as RPS (Vault-like)
			CleanupInterval: getEnvDuration("GATEWAY_RATE_LIMIT_CLEANUP", 1*time.Minute),
		},
		CircuitBreak: CircuitBreakerConfig{
			MaxRequests:  uint32(getEnvInt("GATEWAY_CB_MAX_REQUESTS", 5)),
			Interval:     getEnvDuration("GATEWAY_CB_INTERVAL", 10*time.Second),
			Timeout:      getEnvDuration("GATEWAY_CB_TIMEOUT", 60*time.Second),
			FailureRatio: getEnvFloat("GATEWAY_CB_FAILURE_RATIO", 0.5),
		},
		Services: ServicesConfig{
			AuthAddress:     getEnv("AUTH_SERVICE_ADDRESS", "localhost:9091"),
			CryptoAddress:   getEnv("CRYPTO_SERVICE_ADDRESS", "localhost:9092"),
			TokenizeAddress: getEnv("TOKENIZE_SERVICE_ADDRESS", "localhost:9093"),
			LockAddress:     getEnv("LOCK_SERVICE_ADDRESS", "localhost:9094"),
			AuditAddress:    getEnv("AUDIT_SERVICE_ADDRESS", "localhost:9095"),
		},
		Redis: RedisConfig{
			Address:  getEnv("REDIS_ADDRESS", "localhost:6379"),
			Password: getEnv("REDIS_PASSWORD", ""),
			DB:       getEnvInt("REDIS_DB", 0),
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

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

func getEnvFloat(key string, defaultValue float64) float64 {
	if value := os.Getenv(key); value != "" {
		if floatValue, err := strconv.ParseFloat(value, 64); err == nil {
			return floatValue
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
