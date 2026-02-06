# Implementation Plan

## Overview

Dokumen ini menjelaskan rencana implementasi microservice vault platform dalam beberapa fase. Setiap fase membangun di atas fase sebelumnya.

---

## Phase Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        IMPLEMENTATION PHASES                                 │
│                                                                             │
│  Phase 1: Foundation          Phase 2: Core Services                        │
│  ┌─────────────────────┐     ┌─────────────────────┐                       │
│  │ - Project structure │     │ - Auth Service      │                       │
│  │ - Proto definitions │     │ - Lock Service      │                       │
│  │ - Shared libraries  │ ──► │ - Basic encryption  │                       │
│  │ - CI/CD setup       │     │ - Secret storage    │                       │
│  │ - Dev environment   │     │ - Integration tests │                       │
│  └─────────────────────┘     └─────────────────────┘                       │
│                                       │                                     │
│                                       ▼                                     │
│  Phase 3: Crypto & Tokenize   Phase 4: Production Ready                    │
│  ┌─────────────────────┐     ┌─────────────────────┐                       │
│  │ - Crypto Service    │     │ - Gateway Service   │                       │
│  │ - Tokenize (FPE)    │     │ - Audit Service     │                       │
│  │ - Key rotation      │ ──► │ - Monitoring        │                       │
│  │ - Batch operations  │     │ - Helm charts       │                       │
│  │ - Performance tests │     │ - Documentation     │                       │
│  └─────────────────────┘     └─────────────────────┘                       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Phase 1: Foundation

### Objectives
- Setup project structure dan monorepo
- Define gRPC protobuf contracts
- Build shared libraries
- Setup development environment
- Configure CI/CD pipeline

### Tasks

#### 1.1 Project Structure
```
microservice-vault/
├── api/
│   └── proto/
│       ├── auth/v1/
│       │   └── auth.proto
│       ├── crypto/v1/
│       │   └── crypto.proto
│       ├── tokenize/v1/
│       │   └── tokenize.proto
│       ├── lock/v1/
│       │   └── lock.proto
│       ├── audit/v1/
│       │   └── audit.proto
│       └── gateway/v1/
│           └── gateway.proto
│
├── pkg/                          # Shared libraries
│   ├── crypto/
│   │   ├── aes/
│   │   ├── fpe/
│   │   └── keyring/
│   ├── storage/
│   │   ├── cache/
│   │   └── raft/
│   ├── auth/
│   │   ├── jwt/
│   │   └── policy/
│   ├── telemetry/
│   │   ├── metrics/
│   │   ├── tracing/
│   │   └── logging/
│   └── grpc/
│       ├── interceptors/
│       └── health/
│
├── services/
│   ├── gateway/
│   │   ├── cmd/
│   │   ├── internal/
│   │   └── Dockerfile
│   ├── auth/
│   │   ├── cmd/
│   │   ├── internal/
│   │   └── Dockerfile
│   ├── crypto/
│   │   ├── cmd/
│   │   ├── internal/
│   │   └── Dockerfile
│   ├── tokenize/
│   │   ├── cmd/
│   │   ├── internal/
│   │   └── Dockerfile
│   ├── lock/
│   │   ├── cmd/
│   │   ├── internal/
│   │   └── Dockerfile
│   └── audit/
│       ├── cmd/
│       ├── internal/
│       └── Dockerfile
│
├── deployments/
│   ├── docker-compose.yml
│   ├── docker-compose.dev.yml
│   └── kubernetes/
│       └── helm/
│
├── scripts/
│   ├── proto-gen.sh
│   ├── dev-setup.sh
│   └── test.sh
│
├── docs/
├── go.mod
├── go.sum
├── Makefile
└── README.md
```

#### 1.2 Proto Definitions

**Deliverables:**
- [ ] `auth/v1/auth.proto` - Authentication & authorization
- [ ] `crypto/v1/crypto.proto` - Encryption operations
- [ ] `tokenize/v1/tokenize.proto` - FPE & tokenization
- [ ] `lock/v1/lock.proto` - Secret & key storage
- [ ] `audit/v1/audit.proto` - Audit logging
- [ ] `common/v1/common.proto` - Shared messages

#### 1.3 Shared Libraries

**pkg/crypto:**
- [ ] AES-GCM implementation
- [ ] ChaCha20-Poly1305 implementation
- [ ] Key derivation (HKDF)
- [ ] Keyring management

**pkg/storage:**
- [ ] 2Q LRU cache
- [ ] Redis client wrapper
- [ ] Raft storage interface

**pkg/auth:**
- [ ] JWT generation & validation
- [ ] Policy evaluation engine

**pkg/telemetry:**
- [ ] Prometheus metrics
- [ ] OpenTelemetry tracing
- [ ] Structured logging (zap)

**pkg/grpc:**
- [ ] Auth interceptor
- [ ] Logging interceptor
- [ ] Recovery interceptor
- [ ] Health check service

#### 1.4 Development Environment

**docker-compose.dev.yml:**
```yaml
services:
  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: vault
      POSTGRES_USER: vault
      POSTGRES_PASSWORD: dev
    ports:
      - "5432:5432"

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

  kafka:
    image: confluentinc/cp-kafka:7.4.0
    environment:
      KAFKA_BROKER_ID: 1
      KAFKA_ZOOKEEPER_CONNECT: zookeeper:2181
      KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://localhost:9092
    ports:
      - "9092:9092"
    depends_on:
      - zookeeper

  zookeeper:
    image: confluentinc/cp-zookeeper:7.4.0
    environment:
      ZOOKEEPER_CLIENT_PORT: 2181

  jaeger:
    image: jaegertracing/all-in-one:1.47
    ports:
      - "16686:16686"  # UI
      - "4317:4317"    # OTLP gRPC

  prometheus:
    image: prom/prometheus:v2.45.0
    ports:
      - "9090:9090"
    volumes:
      - ./deployments/prometheus.yml:/etc/prometheus/prometheus.yml

  grafana:
    image: grafana/grafana:10.0.0
    ports:
      - "3000:3000"
```

#### 1.5 CI/CD Setup

**GitHub Actions Workflow:**
```yaml
# .github/workflows/ci.yml
name: CI

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: golangci/golangci-lint-action@v3

  test:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_DB: test
          POSTGRES_USER: test
          POSTGRES_PASSWORD: test
      redis:
        image: redis:7-alpine
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-go@v4
        with:
          go-version: '1.21'
      - run: make test

  build:
    runs-on: ubuntu-latest
    needs: [lint, test]
    steps:
      - uses: actions/checkout@v3
      - run: make build-all
      - uses: docker/build-push-action@v4
        with:
          push: ${{ github.ref == 'refs/heads/main' }}
```

### Phase 1 Deliverables
- [ ] Project structure created
- [ ] All proto files defined
- [ ] Shared libraries implemented
- [ ] Development environment running
- [ ] CI/CD pipeline working
- [ ] Unit tests for shared libraries

---

## Phase 2: Core Services

### Objectives
- Implement Auth Service
- Implement Lock Service (basic)
- Basic secret storage
- Integration between services

### Tasks

#### 2.1 Auth Service

**Components:**
```
services/auth/
├── cmd/
│   └── server/
│       └── main.go
├── internal/
│   ├── config/
│   │   └── config.go
│   ├── handler/
│   │   ├── token.go
│   │   ├── apikey.go
│   │   └── policy.go
│   ├── service/
│   │   ├── token_service.go
│   │   ├── apikey_service.go
│   │   └── policy_service.go
│   ├── repository/
│   │   ├── token_repo.go
│   │   ├── apikey_repo.go
│   │   └── policy_repo.go
│   └── cache/
│       └── token_cache.go
├── migrations/
│   └── 001_init.sql
└── Dockerfile
```

**Features:**
- [ ] JWT token generation (ES256)
- [ ] Token validation with caching
- [ ] Token revocation
- [ ] API key CRUD
- [ ] Policy storage
- [ ] Policy evaluation

**Database Schema:**
```sql
-- tokens (for tracking, actual JWT is stateless)
CREATE TABLE tokens (
    id UUID PRIMARY KEY,
    identity VARCHAR(255) NOT NULL,
    policies TEXT[] NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    metadata JSONB
);

-- api_keys
CREATE TABLE api_keys (
    id UUID PRIMARY KEY,
    key_hash VARCHAR(64) NOT NULL UNIQUE,
    identity VARCHAR(255) NOT NULL,
    policies TEXT[] NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ
);

-- policies
CREATE TABLE policies (
    name VARCHAR(255) PRIMARY KEY,
    rules JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_tokens_identity ON tokens(identity);
CREATE INDEX idx_tokens_expires ON tokens(expires_at);
CREATE INDEX idx_apikeys_identity ON api_keys(identity);
```

#### 2.2 Lock Service (Basic)

**Components:**
```
services/lock/
├── cmd/
│   └── server/
│       └── main.go
├── internal/
│   ├── config/
│   ├── handler/
│   │   ├── secret.go
│   │   ├── key.go
│   │   └── seal.go
│   ├── service/
│   │   ├── secret_service.go
│   │   ├── key_service.go
│   │   └── seal_service.go
│   ├── barrier/
│   │   ├── barrier.go
│   │   └── keyring.go
│   ├── storage/
│   │   ├── physical.go
│   │   ├── cache.go
│   │   └── raft/
│   └── seal/
│       ├── seal.go
│       └── shamir.go
└── Dockerfile
```

**Features (Basic):**
- [ ] Shamir seal/unseal
- [ ] AES-GCM barrier encryption
- [ ] Basic keyring (single version)
- [ ] Secret CRUD operations
- [ ] In-memory storage (Phase 2)
- [ ] Raft storage (Phase 4)

**Key Management:**
- [ ] Create encryption key
- [ ] Get key for encryption
- [ ] Key metadata storage

#### 2.3 Integration

**Service Communication:**
```
┌────────────────────────────────────────────────────────────────┐
│                    PHASE 2 ARCHITECTURE                         │
│                                                                 │
│    ┌──────────┐         ┌──────────┐                          │
│    │   Auth   │◄───────►│   Lock   │                          │
│    │ Service  │  gRPC   │ Service  │                          │
│    └────┬─────┘         └────┬─────┘                          │
│         │                    │                                 │
│         ▼                    ▼                                 │
│    ┌──────────┐         ┌──────────┐                          │
│    │PostgreSQL│         │In-Memory │                          │
│    │  Redis   │         │ Storage  │                          │
│    └──────────┘         └──────────┘                          │
│                                                                 │
└────────────────────────────────────────────────────────────────┘
```

**Integration Tests:**
- [ ] Auth → Lock: Get signing key
- [ ] Token creation flow
- [ ] Token validation flow
- [ ] Secret storage flow

### Phase 2 Deliverables
- [ ] Auth Service fully functional
- [ ] Lock Service with basic features
- [ ] Integration tests passing
- [ ] Docker images building
- [ ] Local development working

---

## Phase 3: Crypto & Tokenize

### Objectives
- Implement Crypto Service
- Implement Tokenize Service (FPE)
- Key rotation support
- Batch operations
- Performance optimization

### Tasks

#### 3.1 Crypto Service

**Components:**
```
services/crypto/
├── cmd/
│   └── server/
│       └── main.go
├── internal/
│   ├── config/
│   ├── handler/
│   │   ├── encrypt.go
│   │   ├── decrypt.go
│   │   ├── sign.go
│   │   └── hmac.go
│   ├── service/
│   │   ├── encrypt_service.go
│   │   ├── sign_service.go
│   │   └── hmac_service.go
│   ├── keymanager/
│   │   ├── manager.go
│   │   └── cache.go
│   └── worker/
│       └── pool.go
└── Dockerfile
```

**Features:**
- [ ] AES-GCM encryption/decryption
- [ ] ChaCha20-Poly1305 support
- [ ] ECDSA signing (P-256, P-384)
- [ ] Ed25519 signing
- [ ] RSA-PSS signing
- [ ] HMAC generation
- [ ] Batch encrypt/decrypt
- [ ] Batch sign
- [ ] Data key generation (envelope encryption)
- [ ] Rewrap operation
- [ ] Worker pool (200 workers)
- [ ] Key caching (LRU)

**Ciphertext Format:**
```
vault:v{version}:{base64(nonce + ciphertext + tag)}

Example: vault:v1:SGVsbG8gV29ybGQh...
```

#### 3.2 Tokenize Service

**Components:**
```
services/tokenize/
├── cmd/
│   └── server/
│       └── main.go
├── internal/
│   ├── config/
│   ├── handler/
│   │   ├── fpe.go
│   │   └── mask.go
│   ├── service/
│   │   ├── fpe_service.go
│   │   └── mask_service.go
│   ├── fpe/
│   │   ├── ff1.go
│   │   └── transformation.go
│   └── keymanager/
│       └── manager.go
└── Dockerfile
```

**Features:**
- [ ] FF1 algorithm implementation
- [ ] Built-in transformations:
  - [ ] credit-card (numeric, 13-19 digits)
  - [ ] ssn (numeric, 9 digits)
  - [ ] phone (numeric, variable)
  - [ ] numeric (any length)
  - [ ] alpha-lower
  - [ ] alpha-upper
  - [ ] alphanumeric
- [ ] Custom alphabet support
- [ ] Tweak support (context)
- [ ] Batch FPE operations
- [ ] Data masking

**FF1 Implementation:**
```go
// Based on NIST SP 800-38G
type FF1 struct {
    key      []byte
    tweak    []byte
    radix    int
    alphabet string
}

func (f *FF1) Encrypt(plaintext string) (string, error)
func (f *FF1) Decrypt(ciphertext string) (string, error)
```

#### 3.3 Key Rotation

**Lock Service Enhancements:**
- [ ] Versioned keys in keyring
- [ ] Key rotation API
- [ ] min_encryption_version
- [ ] min_decryption_version
- [ ] Key archival

**Crypto/Tokenize Enhancements:**
- [ ] Parse ciphertext version
- [ ] Use correct key version for decrypt
- [ ] Always use latest for encrypt
- [ ] Rewrap to latest version

#### 3.4 Performance Optimization

**Crypto Service:**
- [ ] Worker pool implementation
- [ ] AEAD cipher caching
- [ ] Parallel batch processing
- [ ] Zero-copy where possible

**Lock Service:**
- [ ] 2Q LRU cache for physical storage
- [ ] Fine-grained locking per path
- [ ] Connection pooling

**Benchmarks:**
```go
func BenchmarkEncrypt(b *testing.B)
func BenchmarkEncryptBatch100(b *testing.B)
func BenchmarkFPEEncrypt(b *testing.B)
func BenchmarkFPEBatch100(b *testing.B)
```

### Phase 3 Deliverables
- [ ] Crypto Service fully functional
- [ ] Tokenize Service with FPE
- [ ] Key rotation working
- [ ] Batch operations optimized
- [ ] Performance benchmarks meeting targets
- [ ] Integration tests

---

## Phase 4: Production Ready

### Objectives
- Implement Gateway Service
- Implement Audit Service
- Raft storage for Lock Service
- Kubernetes deployment
- Monitoring & alerting
- Documentation

### Tasks

#### 4.1 Gateway Service

**Components:**
```
services/gateway/
├── cmd/
│   └── server/
│       └── main.go
├── internal/
│   ├── config/
│   ├── router/
│   │   └── router.go
│   ├── middleware/
│   │   ├── auth.go
│   │   ├── ratelimit.go
│   │   ├── circuitbreaker.go
│   │   └── logging.go
│   ├── handler/
│   │   ├── rest/
│   │   └── grpc/
│   └── client/
│       ├── auth_client.go
│       ├── crypto_client.go
│       ├── tokenize_client.go
│       └── lock_client.go
└── Dockerfile
```

**Features:**
- [ ] REST API endpoints
- [ ] gRPC gateway (grpc-gateway)
- [ ] Rate limiting (Redis-based)
- [ ] Circuit breaker
- [ ] Request routing
- [ ] TLS termination
- [ ] Health checks
- [ ] Metrics endpoint

#### 4.2 Audit Service

**Components:**
```
services/audit/
├── cmd/
│   └── server/
│       └── main.go
├── internal/
│   ├── config/
│   ├── consumer/
│   │   └── kafka_consumer.go
│   ├── handler/
│   │   ├── search.go
│   │   └── export.go
│   ├── storage/
│   │   ├── s3.go
│   │   └── elasticsearch.go
│   └── alerting/
│       └── alerter.go
└── Dockerfile
```

**Features:**
- [ ] Kafka consumer for audit events
- [ ] S3/Blob storage for long-term
- [ ] Elasticsearch indexing
- [ ] Search API
- [ ] Export API
- [ ] Retention policies
- [ ] Alerting on suspicious activity

#### 4.3 Raft Storage

**Lock Service Enhancements:**
```
services/lock/internal/storage/raft/
├── raft.go
├── fsm.go
├── snapshot.go
├── transport.go
└── config.go
```

**Features:**
- [ ] Raft consensus integration
- [ ] BoltDB FSM
- [ ] Snapshot management
- [ ] Cluster join/leave
- [ ] Leader forwarding
- [ ] Read replicas

#### 4.4 Kubernetes Deployment

**Helm Charts:**
```
deployments/kubernetes/helm/
├── vault-platform/
│   ├── Chart.yaml
│   ├── values.yaml
│   ├── templates/
│   │   ├── gateway-deployment.yaml
│   │   ├── auth-deployment.yaml
│   │   ├── crypto-deployment.yaml
│   │   ├── tokenize-deployment.yaml
│   │   ├── lock-statefulset.yaml
│   │   ├── audit-deployment.yaml
│   │   ├── configmaps.yaml
│   │   ├── secrets.yaml
│   │   ├── services.yaml
│   │   ├── ingress.yaml
│   │   ├── hpa.yaml
│   │   └── pdb.yaml
│   └── charts/
│       ├── redis/
│       ├── postgresql/
│       └── kafka/
```

**Features:**
- [ ] Deployment manifests for all services
- [ ] StatefulSet for Lock Service
- [ ] ConfigMaps for configuration
- [ ] Secrets management
- [ ] Ingress configuration
- [ ] HorizontalPodAutoscaler
- [ ] PodDisruptionBudget
- [ ] Network policies

#### 4.5 Monitoring & Alerting

**Prometheus Metrics:**
- [ ] Request rate per service
- [ ] Request latency (p50, p95, p99)
- [ ] Error rate
- [ ] Key operations count
- [ ] Cache hit/miss ratio
- [ ] Worker pool utilization
- [ ] Raft metrics

**Grafana Dashboards:**
- [ ] Overview dashboard
- [ ] Per-service dashboards
- [ ] SLO dashboard

**Alerting Rules:**
```yaml
groups:
  - name: vault-platform
    rules:
      - alert: HighErrorRate
        expr: rate(grpc_server_handled_total{code!="OK"}[5m]) > 0.1
        for: 5m
        labels:
          severity: critical

      - alert: HighLatency
        expr: histogram_quantile(0.99, rate(grpc_server_handling_seconds_bucket[5m])) > 1
        for: 5m
        labels:
          severity: warning

      - alert: LockServiceSealed
        expr: vault_seal_status == 1
        for: 1m
        labels:
          severity: critical
```

#### 4.6 Documentation

- [ ] API documentation (OpenAPI/Swagger)
- [ ] gRPC documentation (protoc-gen-doc)
- [ ] Architecture documentation (this doc)
- [ ] Operations runbook
- [ ] Deployment guide
- [ ] Security hardening guide

### Phase 4 Deliverables
- [ ] All services production ready
- [ ] Raft storage working
- [ ] Kubernetes deployment tested
- [ ] Monitoring dashboards
- [ ] Alerting configured
- [ ] Documentation complete
- [ ] Security review passed

---

## Testing Strategy

### Unit Tests
```
Coverage target: 80%

services/*/internal/**/*_test.go
pkg/**/*_test.go
```

### Integration Tests
```
tests/integration/
├── auth_test.go
├── crypto_test.go
├── tokenize_test.go
├── lock_test.go
└── e2e_test.go
```

### Performance Tests
```
tests/performance/
├── encrypt_bench_test.go
├── fpe_bench_test.go
├── auth_bench_test.go
└── lock_bench_test.go

Targets:
- Encrypt: > 10,000 ops/sec
- FPE: > 15,000 ops/sec
- Auth validate: > 20,000 ops/sec
- Secret read: > 5,000 ops/sec
```

### Load Tests
```
tests/load/
├── k6/
│   ├── encrypt_load.js
│   ├── fpe_load.js
│   └── mixed_load.js
└── results/
```

---

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| Raft complexity | Start with in-memory, add Raft in Phase 4 |
| FPE implementation bugs | Use well-tested library (capitalone/fpe) |
| Key management errors | Extensive testing, code review |
| Performance issues | Early benchmarking, profiling |
| Security vulnerabilities | Security review, penetration testing |

---

## Success Criteria

### Phase 1
- All protos compile
- Shared libraries have 80% coverage
- Dev environment runs with `make dev`
- CI pipeline green

### Phase 2
- Token creation/validation works
- Secrets can be stored/retrieved
- Services communicate via gRPC
- Integration tests pass

### Phase 3
- Encrypt/decrypt works with key rotation
- FPE preserves format correctly
- Batch operations meet performance targets
- Benchmarks documented

### Phase 4
- All services running in Kubernetes
- Monitoring dashboards operational
- Alerting working
- Documentation complete
- Security review passed

---

## Next: [05-TECH-STACK.md](./05-TECH-STACK.md)
