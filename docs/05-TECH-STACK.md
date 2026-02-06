# Technology Stack

## Overview

Dokumen ini menjelaskan teknologi yang digunakan dalam microservice vault platform beserta alasan pemilihannya.

---

## Core Technology

### Language: Go 1.21+

**Alasan Pemilihan:**
- Native concurrency (goroutines, channels)
- Excellent performance
- Strong standard library untuk cryptography
- gRPC first-class support
- Single binary deployment
- Used by HashiCorp Vault (reference)

**Key Libraries:**
```go
// go.mod
module github.com/yourorg/microservice-vault

go 1.21

require (
    // gRPC & Protobuf
    google.golang.org/grpc v1.59.0
    google.golang.org/protobuf v1.31.0
    github.com/grpc-ecosystem/grpc-gateway/v2 v2.18.0

    // Database
    github.com/jackc/pgx/v5 v5.5.0
    github.com/redis/go-redis/v9 v9.3.0

    // Raft
    github.com/hashicorp/raft v1.6.0
    github.com/hashicorp/raft-boltdb/v2 v2.3.0

    // Cryptography
    golang.org/x/crypto v0.16.0
    github.com/capitalone/fpe v1.2.1

    // JWT
    github.com/golang-jwt/jwt/v5 v5.2.0

    // Configuration
    github.com/spf13/viper v1.18.0

    // Observability
    go.opentelemetry.io/otel v1.21.0
    go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.21.0
    github.com/prometheus/client_golang v1.17.0
    go.uber.org/zap v1.26.0

    // Utilities
    github.com/hashicorp/golang-lru/v2 v2.0.7
    github.com/gammazero/workerpool v1.1.3
    golang.org/x/sync v0.5.0
)
```

---

## Service-Specific Dependencies

### Gateway Service

| Component | Library | Version | Purpose |
|-----------|---------|---------|---------|
| HTTP Server | `net/http` | stdlib | REST API |
| gRPC Gateway | `grpc-gateway/v2` | 2.18.0 | REST → gRPC |
| Rate Limiter | `go-redis/redis_rate` | 10.0.1 | Distributed rate limiting |
| Circuit Breaker | `sony/gobreaker` | 0.5.0 | Fault tolerance |
| Router | `chi` | 5.0.10 | HTTP routing |

```go
// Gateway specific imports
import (
    "github.com/go-chi/chi/v5"
    "github.com/go-chi/chi/v5/middleware"
    "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
    "github.com/sony/gobreaker"
    "github.com/go-redis/redis_rate/v10"
)
```

### Auth Service

| Component | Library | Version | Purpose |
|-----------|---------|---------|---------|
| JWT | `golang-jwt/jwt/v5` | 5.2.0 | Token generation/validation |
| Password Hashing | `golang.org/x/crypto/bcrypt` | - | API key hashing |
| Policy Engine | Custom | - | ACL evaluation |
| Database | `pgx/v5` | 5.5.0 | PostgreSQL driver |
| Cache | `go-redis/v9` | 9.3.0 | Token caching |
| Bloom Filter | `bits-and-blooms/bloom/v3` | 3.6.0 | Revoked token check |

```go
// Auth specific imports
import (
    "github.com/golang-jwt/jwt/v5"
    "github.com/jackc/pgx/v5/pgxpool"
    "github.com/redis/go-redis/v9"
    "github.com/bits-and-blooms/bloom/v3"
    "golang.org/x/crypto/bcrypt"
)
```

### Crypto Service

| Component | Library | Version | Purpose |
|-----------|---------|---------|---------|
| AES-GCM | `crypto/aes` + `crypto/cipher` | stdlib | Symmetric encryption |
| ChaCha20-Poly1305 | `golang.org/x/crypto/chacha20poly1305` | - | Alternative encryption |
| ECDSA | `crypto/ecdsa` | stdlib | Digital signatures |
| Ed25519 | `crypto/ed25519` | stdlib | Modern signatures |
| RSA | `crypto/rsa` | stdlib | Asymmetric ops |
| HKDF | `golang.org/x/crypto/hkdf` | - | Key derivation |
| Worker Pool | `gammazero/workerpool` | 1.1.3 | Parallel processing |
| LRU Cache | `hashicorp/golang-lru/v2` | 2.0.7 | Key caching |

```go
// Crypto specific imports
import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/ecdsa"
    "crypto/ed25519"
    "crypto/rsa"
    "crypto/rand"
    "golang.org/x/crypto/chacha20poly1305"
    "golang.org/x/crypto/hkdf"
    "github.com/gammazero/workerpool"
    lru "github.com/hashicorp/golang-lru/v2"
)
```

### Tokenize Service

| Component | Library | Version | Purpose |
|-----------|---------|---------|---------|
| FPE (FF1) | `capitalone/fpe` | 1.2.1 | Format-preserving encryption |
| LRU Cache | `hashicorp/golang-lru/v2` | 2.0.7 | Key caching |

```go
// Tokenize specific imports
import (
    "github.com/capitalone/fpe/ff1"
    lru "github.com/hashicorp/golang-lru/v2"
)
```

### Lock Service

| Component | Library | Version | Purpose |
|-----------|---------|---------|---------|
| Raft | `hashicorp/raft` | 1.6.0 | Consensus |
| BoltDB | `raft-boltdb/v2` | 2.3.0 | Raft log storage |
| Shamir SSS | `hashicorp/vault/shamir` | - | Secret sharing |
| 2Q Cache | `hashicorp/golang-lru/v2` | 2.0.7 | Storage caching |
| Radix Tree | `armon/go-radix` | 1.0.0 | Path routing |

```go
// Lock specific imports
import (
    "github.com/hashicorp/raft"
    raftboltdb "github.com/hashicorp/raft-boltdb/v2"
    "github.com/hashicorp/vault/shamir"
    lru "github.com/hashicorp/golang-lru/v2"
    "github.com/armon/go-radix"
)
```

### Audit Service

| Component | Library | Version | Purpose |
|-----------|---------|---------|---------|
| Kafka | `segmentio/kafka-go` | 0.4.45 | Event consumption |
| S3 | `aws/aws-sdk-go-v2` | 1.24.0 | Long-term storage |
| Elasticsearch | `elastic/go-elasticsearch/v8` | 8.11.0 | Indexing & search |

```go
// Audit specific imports
import (
    "github.com/segmentio/kafka-go"
    "github.com/aws/aws-sdk-go-v2/service/s3"
    "github.com/elastic/go-elasticsearch/v8"
)
```

---

## Infrastructure Components

### Databases

#### PostgreSQL 15

**Usage:** Auth Service (tokens, API keys, policies)

**Configuration:**
```yaml
postgres:
  version: "15"
  max_connections: 100
  shared_buffers: 256MB
  effective_cache_size: 768MB
  maintenance_work_mem: 64MB
  checkpoint_completion_target: 0.9
  wal_buffers: 16MB
  default_statistics_target: 100
  random_page_cost: 1.1
  effective_io_concurrency: 200
```

**Why PostgreSQL:**
- ACID compliance
- JSONB support untuk policies
- Array types untuk policies list
- Mature, battle-tested
- Extensions (pg_stat_statements untuk monitoring)

#### Redis 7

**Usage:**
- Token cache (Auth)
- Rate limiting (Gateway)
- Distributed locks

**Configuration:**
```yaml
redis:
  version: "7-alpine"
  maxmemory: 512mb
  maxmemory-policy: volatile-lru
  tcp-keepalive: 300
```

**Why Redis:**
- Sub-millisecond latency
- Built-in expiration
- Pub/sub untuk invalidation
- Cluster mode untuk HA

#### Raft + BoltDB

**Usage:** Lock Service (secrets, keys, barrier)

**Configuration:**
```yaml
raft:
  heartbeat_timeout: 1000ms
  election_timeout: 1000ms
  commit_timeout: 50ms
  max_append_entries: 64
  trailing_logs: 10240
  snapshot_interval: 120s
  snapshot_threshold: 8192
```

**Why Raft:**
- Strong consistency
- Leader election built-in
- Used by HashiCorp Vault
- No external dependencies

### Message Queue

#### Apache Kafka

**Usage:** Audit event streaming

**Configuration:**
```yaml
kafka:
  version: "3.6"
  num_partitions: 12
  replication_factor: 3
  retention_hours: 168
  segment_bytes: 1073741824
```

**Topics:**
```
vault.audit.events          # All audit events
vault.audit.auth            # Auth events only
vault.audit.crypto          # Crypto events only
vault.audit.secrets         # Secret access events
```

**Why Kafka:**
- High throughput
- Durable
- Replay capability
- Partitioning untuk parallel processing

### Search & Analytics

#### Elasticsearch 8

**Usage:** Audit log indexing & search

**Configuration:**
```yaml
elasticsearch:
  version: "8.11"
  cluster_name: vault-audit
  node_roles:
    - master
    - data
    - ingest
  heap_size: 1g
```

**Index Template:**
```json
{
  "index_patterns": ["vault-audit-*"],
  "template": {
    "settings": {
      "number_of_shards": 3,
      "number_of_replicas": 1,
      "refresh_interval": "5s"
    },
    "mappings": {
      "properties": {
        "timestamp": { "type": "date" },
        "service": { "type": "keyword" },
        "operation": { "type": "keyword" },
        "identity": { "type": "keyword" },
        "resource": { "type": "keyword" },
        "source_ip": { "type": "ip" },
        "success": { "type": "boolean" },
        "metadata": { "type": "object", "enabled": false }
      }
    }
  }
}
```

### Object Storage

#### S3 / MinIO

**Usage:** Long-term audit log storage

**Configuration:**
```yaml
s3:
  bucket: vault-audit-logs
  region: ap-southeast-1
  storage_class: STANDARD_IA  # After 30 days: GLACIER
  lifecycle_rules:
    - transition_days: 30
      storage_class: GLACIER
    - expiration_days: 2555  # 7 years
```

---

## Observability Stack

### Metrics: Prometheus

**Metrics Exposed:**
```go
// Request metrics
grpc_server_started_total
grpc_server_handled_total
grpc_server_handling_seconds

// Custom metrics
vault_encrypt_operations_total
vault_decrypt_operations_total
vault_fpe_operations_total
vault_secret_operations_total
vault_auth_validations_total
vault_cache_hits_total
vault_cache_misses_total
vault_worker_pool_active
vault_seal_status
vault_key_versions
```

**Scrape Config:**
```yaml
scrape_configs:
  - job_name: 'vault-gateway'
    static_configs:
      - targets: ['gateway:9090']
  - job_name: 'vault-auth'
    static_configs:
      - targets: ['auth:9090']
  # ... other services
```

### Tracing: Jaeger / OpenTelemetry

**Configuration:**
```go
// OpenTelemetry setup
import (
    "go.opentelemetry.io/otel"
    "go.opentelemetry.io/otel/exporters/otlp/otlptrace"
    "go.opentelemetry.io/otel/sdk/trace"
)

func initTracer() (*trace.TracerProvider, error) {
    exporter, err := otlptrace.New(ctx,
        otlptracegrpc.NewClient(
            otlptracegrpc.WithEndpoint("jaeger:4317"),
            otlptracegrpc.WithInsecure(),
        ),
    )
    tp := trace.NewTracerProvider(
        trace.WithBatcher(exporter),
        trace.WithSampler(trace.ParentBased(
            trace.TraceIDRatioBased(0.1), // 10% sampling
        )),
    )
    return tp, nil
}
```

**Trace Attributes:**
```go
span.SetAttributes(
    attribute.String("vault.service", "crypto"),
    attribute.String("vault.operation", "encrypt"),
    attribute.String("vault.key_name", keyName),
    attribute.Int("vault.key_version", keyVersion),
)
```

### Logging: Zap + Loki

**Configuration:**
```go
import "go.uber.org/zap"

func initLogger() *zap.Logger {
    config := zap.NewProductionConfig()
    config.EncoderConfig.TimeKey = "timestamp"
    config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
    config.OutputPaths = []string{"stdout"}

    logger, _ := config.Build()
    return logger
}
```

**Log Format:**
```json
{
  "level": "info",
  "timestamp": "2024-01-15T10:30:00.000Z",
  "caller": "handler/encrypt.go:45",
  "msg": "encryption completed",
  "service": "crypto",
  "request_id": "abc123",
  "key_name": "app-key",
  "key_version": 3,
  "duration_ms": 5.2
}
```

### Dashboards: Grafana

**Pre-built Dashboards:**
1. **Overview Dashboard**
   - Total requests/sec
   - Error rate
   - P99 latency
   - Service status

2. **Auth Dashboard**
   - Token creations/sec
   - Validations/sec
   - Cache hit ratio
   - Active sessions

3. **Crypto Dashboard**
   - Encryptions/sec
   - Decryptions/sec
   - Worker pool utilization
   - Key operations

4. **Lock Dashboard**
   - Secret operations
   - Raft metrics
   - Seal status
   - Cache performance

---

## Development Tools

### Build & Test

| Tool | Purpose |
|------|---------|
| `make` | Build automation |
| `buf` | Protobuf linting & generation |
| `golangci-lint` | Code linting |
| `gotestsum` | Test runner |
| `go-cover` | Coverage reporting |
| `dlv` | Debugging |

**Makefile Targets:**
```makefile
.PHONY: all build test lint proto

# Generate protobuf
proto:
	buf generate

# Build all services
build:
	go build -o bin/ ./services/...

# Run tests
test:
	gotestsum --format=testname -- -race -coverprofile=coverage.out ./...

# Lint
lint:
	golangci-lint run

# Run locally
dev:
	docker-compose -f deployments/docker-compose.dev.yml up -d
	go run ./services/gateway/cmd/server &
	go run ./services/auth/cmd/server &
	# ...

# Clean
clean:
	rm -rf bin/ coverage.out
```

### Container & Orchestration

| Tool | Purpose |
|------|---------|
| Docker | Containerization |
| Docker Compose | Local development |
| Kubernetes | Production orchestration |
| Helm | Kubernetes packaging |
| Skaffold | Development workflow |

**Dockerfile Template:**
```dockerfile
# Build stage
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /server ./services/crypto/cmd/server

# Runtime stage
FROM gcr.io/distroless/static-debian12
COPY --from=builder /server /server
EXPOSE 9090
ENTRYPOINT ["/server"]
```

---

## Security Libraries

### Cryptography Standards

| Algorithm | Standard | Library |
|-----------|----------|---------|
| AES-GCM | NIST FIPS 197, SP 800-38D | `crypto/aes`, `crypto/cipher` |
| ChaCha20-Poly1305 | RFC 8439 | `golang.org/x/crypto` |
| ECDSA | FIPS 186-4 | `crypto/ecdsa` |
| Ed25519 | RFC 8032 | `crypto/ed25519` |
| RSA-PSS | RFC 8017 | `crypto/rsa` |
| HKDF | RFC 5869 | `golang.org/x/crypto/hkdf` |
| FPE FF1 | NIST SP 800-38G | `capitalone/fpe` |
| Shamir SSS | Shamir 1979 | `hashicorp/vault/shamir` |

### Security Best Practices

```go
// Always use crypto/rand for random
import "crypto/rand"

// Constant-time comparison
import "crypto/subtle"
if subtle.ConstantTimeCompare(a, b) != 1 {
    return errors.New("invalid")
}

// Secure key zeroing
import "github.com/awnumar/memguard"
key := memguard.NewBufferFromBytes(keyBytes)
defer key.Destroy()

// TLS configuration
tlsConfig := &tls.Config{
    MinVersion: tls.VersionTLS13,
    CipherSuites: []uint16{
        tls.TLS_AES_256_GCM_SHA384,
        tls.TLS_CHACHA20_POLY1305_SHA256,
    },
}
```

---

## Version Matrix

| Component | Version | EOL/Support |
|-----------|---------|-------------|
| Go | 1.21 | Feb 2025 |
| PostgreSQL | 15 | Nov 2027 |
| Redis | 7 | - |
| Kafka | 3.6 | - |
| Elasticsearch | 8.11 | - |
| Kubernetes | 1.28+ | - |
| Prometheus | 2.48+ | - |
| Grafana | 10.2+ | - |

---

## Dependency Management

### Go Modules

```bash
# Update dependencies
go get -u ./...

# Tidy
go mod tidy

# Vendor (optional)
go mod vendor

# Check vulnerabilities
govulncheck ./...
```

### Renovate Config

```json
{
  "extends": ["config:base"],
  "packageRules": [
    {
      "matchPackagePatterns": ["*"],
      "groupName": "all dependencies",
      "groupSlug": "all"
    }
  ],
  "schedule": ["before 3am on Monday"]
}
```

---

## License Compatibility

| Library | License | Commercial OK |
|---------|---------|---------------|
| Go stdlib | BSD-3 | ✅ |
| grpc-go | Apache-2.0 | ✅ |
| pgx | MIT | ✅ |
| go-redis | BSD-2 | ✅ |
| hashicorp/raft | MPL-2.0 | ✅ |
| capitalone/fpe | Apache-2.0 | ✅ |
| golang-jwt | MIT | ✅ |
| zap | MIT | ✅ |

All dependencies are compatible with commercial use.

---

## Summary

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           TECH STACK SUMMARY                                 │
│                                                                             │
│  Language:        Go 1.21+                                                  │
│  Communication:   gRPC + REST (grpc-gateway)                                │
│  Database:        PostgreSQL 15 (Auth), Raft+BoltDB (Lock)                 │
│  Cache:           Redis 7                                                   │
│  Message Queue:   Apache Kafka                                              │
│  Search:          Elasticsearch 8                                           │
│  Storage:         S3/MinIO                                                  │
│  Orchestration:   Kubernetes + Helm                                         │
│  Observability:   Prometheus + Jaeger + Grafana + Loki                     │
│                                                                             │
│  Cryptography:                                                              │
│  - Symmetric:     AES-256-GCM, ChaCha20-Poly1305                           │
│  - Asymmetric:    RSA-2048/4096, ECDSA P-256/P-384, Ed25519               │
│  - FPE:           FF1 (NIST SP 800-38G)                                    │
│  - KDF:           HKDF-SHA256                                              │
│  - Secret Share:  Shamir SSS                                               │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```
