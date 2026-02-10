package config

import (
	"os"
	"strconv"
)

// Config holds Lock Service configuration
type Config struct {
	Server  ServerConfig
	Seal    SealConfig
	Storage StorageConfig
	Cache   CacheConfig
}

// ServerConfig holds server settings
type ServerConfig struct {
	GRPCPort    int
	ClusterPort int
}

// SealConfig holds seal settings
type SealConfig struct {
	Type      string // "shamir" or "awskms", "gcpkms", etc.
	Shares    int    // Total Shamir shares
	Threshold int    // Required shares to unseal
}

// StorageConfig holds storage settings
type StorageConfig struct {
	Type       string // "memory", "raft", "file"
	BoltDBPath string
	RaftPath   string
	NodeID     string
}

// CacheConfig holds cache settings
type CacheConfig struct {
	Type string // "2q", "lru"
	Size int
}

// Load loads configuration from environment variables
func Load() (*Config, error) {
	cfg := &Config{
		Server: ServerConfig{
			GRPCPort:    getEnvInt("LOCK_GRPC_PORT", 9094),
			ClusterPort: getEnvInt("LOCK_CLUSTER_PORT", 9095),
		},
		Seal: SealConfig{
			Type:      getEnv("LOCK_SEAL_TYPE", "shamir"),
			Shares:    getEnvInt("LOCK_SEAL_SHARES", 5),
			Threshold: getEnvInt("LOCK_SEAL_THRESHOLD", 3),
		},
		Storage: StorageConfig{
			Type:       getEnv("LOCK_STORAGE_TYPE", "memory"),
			BoltDBPath: getEnv("LOCK_STORAGE_BOLTDB_PATH", "data/lock.db"),
			RaftPath:   getEnv("LOCK_RAFT_PATH", "/data/raft"),
			NodeID:     getEnv("LOCK_NODE_ID", "node1"),
		},
		Cache: CacheConfig{
			Type: getEnv("LOCK_CACHE_TYPE", "2q"),
			Size: getEnvInt("LOCK_CACHE_SIZE", 131072), // 128K entries
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
