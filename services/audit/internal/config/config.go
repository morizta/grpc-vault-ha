package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Server   ServerConfig
	Storage  StorageConfig
	Kafka    KafkaConfig
	Buffer   BufferConfig
}

type ServerConfig struct {
	GRPCPort int
}

type StorageConfig struct {
	Type     string // "file", "postgres", "elasticsearch"
	FilePath string
	DSN      string
}

type KafkaConfig struct {
	Enabled  bool
	Brokers  []string
	Topic    string
	GroupID  string
}

type BufferConfig struct {
	Size          int
	FlushInterval time.Duration
}

func Load() (*Config, error) {
	return &Config{
		Server: ServerConfig{
			GRPCPort: getEnvInt("AUDIT_GRPC_PORT", 9095),
		},
		Storage: StorageConfig{
			Type:     getEnv("AUDIT_STORAGE_TYPE", "file"),
			FilePath: getEnv("AUDIT_FILE_PATH", "/var/log/vault/audit.log"),
			DSN:      getEnv("AUDIT_STORAGE_DSN", ""),
		},
		Kafka: KafkaConfig{
			Enabled:  getEnvBool("AUDIT_KAFKA_ENABLED", false),
			Brokers:  getEnvSlice("AUDIT_KAFKA_BROKERS", []string{"localhost:9092"}),
			Topic:    getEnv("AUDIT_KAFKA_TOPIC", "vault-audit"),
			GroupID:  getEnv("AUDIT_KAFKA_GROUP_ID", "vault-audit-consumer"),
		},
		Buffer: BufferConfig{
			Size:          getEnvInt("AUDIT_BUFFER_SIZE", 1000),
			FlushInterval: getEnvDuration("AUDIT_FLUSH_INTERVAL", 5*time.Second),
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

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}

func getEnvSlice(key string, defaultValue []string) []string {
	if value := os.Getenv(key); value != "" {
		// Simple comma-separated parsing
		var result []string
		start := 0
		for i := 0; i < len(value); i++ {
			if value[i] == ',' {
				if i > start {
					result = append(result, value[start:i])
				}
				start = i + 1
			}
		}
		if start < len(value) {
			result = append(result, value[start:])
		}
		if len(result) > 0 {
			return result
		}
	}
	return defaultValue
}
