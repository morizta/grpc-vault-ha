package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Server   ServerConfig
	JWT      JWTConfig
	Cache    CacheConfig
	Storage  StorageConfig
	Admin    AdminConfig
	Database DatabaseConfig
	Redis    RedisConfig
}

type StorageConfig struct {
	BoltDBPath string
}

type AdminConfig struct {
	Username string
	Password string
}

type ServerConfig struct {
	GRPCPort int
}

type JWTConfig struct {
	Issuer     string
	Audience   string
	DefaultTTL time.Duration
	MaxTTL     time.Duration
}

type CacheConfig struct {
	L1Size int
	L2TTL  time.Duration
}

type DatabaseConfig struct {
	Driver   string
	Host     string
	Port     int
	Database string
	User     string
	Password string
	MaxConns int
}

type RedisConfig struct {
	Address  string
	Password string
	DB       int
}

func Load() (*Config, error) {
	return &Config{
		Server: ServerConfig{
			GRPCPort: getEnvInt("AUTH_GRPC_PORT", 9091),
		},
		JWT: JWTConfig{
			Issuer:     getEnv("AUTH_JWT_ISSUER", "vault-auth"),
			Audience:   getEnv("AUTH_JWT_AUDIENCE", "vault-platform"),
			DefaultTTL: getEnvDuration("AUTH_JWT_DEFAULT_TTL", time.Hour),
			MaxTTL:     getEnvDuration("AUTH_JWT_MAX_TTL", 24*time.Hour),
		},
		Cache: CacheConfig{
			L1Size: getEnvInt("AUTH_CACHE_L1_SIZE", 10000),
			L2TTL:  getEnvDuration("AUTH_CACHE_L2_TTL", 5*time.Minute),
		},
		Storage: StorageConfig{
			BoltDBPath: getEnv("AUTH_STORAGE_PATH", "data/auth.db"),
		},
		Admin: AdminConfig{
			Username: getEnv("AUTH_ADMIN_USERNAME", "admin"),
			Password: getEnv("AUTH_ADMIN_PASSWORD", "admin"),
		},
		Database: DatabaseConfig{
			Driver:   getEnv("AUTH_DB_DRIVER", "postgres"),
			Host:     getEnv("AUTH_DB_HOST", "localhost"),
			Port:     getEnvInt("AUTH_DB_PORT", 5432),
			Database: getEnv("AUTH_DB_DATABASE", "vault"),
			User:     getEnv("AUTH_DB_USER", "vault"),
			Password: getEnv("AUTH_DB_PASSWORD", "vault-dev-password"),
			MaxConns: getEnvInt("AUTH_DB_MAX_CONNS", 100),
		},
		Redis: RedisConfig{
			Address:  getEnv("AUTH_REDIS_ADDRESS", "localhost:6379"),
			Password: getEnv("AUTH_REDIS_PASSWORD", ""),
			DB:       getEnvInt("AUTH_REDIS_DB", 0),
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
