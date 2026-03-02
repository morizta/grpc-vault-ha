# Microservice Vault Platform

Enterprise-grade vault platform berbasis microservices untuk enkripsi, tokenisasi, dan manajemen secrets dengan fokus pada **high throughput** dan **horizontal scalability**.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         GATEWAY                                  │
│         (Auth, Rate Limiting, Routing, Circuit Breaker)     │
└─────────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│     AUTH      │    │    CRYPTO     │    │   TOKENIZE    │
│   (JWT/ACL)   │    │  (AES/RSA)    │    │    (FPE)      │
└───────────────┘    └───────────────┘    └───────────────┘
        │                     │                     │
        └─────────────────────┼─────────────────────┘
                              ▼
                    ┌───────────────┐
                    │     LOCK      │
                    │  (Secrets &   │
                    │    Keys)      │
                    └───────────────┘
```

## Services

| Service | Description | Port |
|---------|-------------|------|
| **Gateway** | API Gateway, auth, rate limiting, routing | 8080 (HTTP), 9090 (gRPC) |
| **Auth** | JWT tokens, API keys, policies | 9091 |
| **Crypto** | Encrypt, decrypt, sign, HMAC | 9092 |
| **Tokenize** | FPE tokenization, masking | 9093 |
| **Lock** | Secret storage, key management | 9094 |
| **Audit** | Audit logging, compliance | 9095 |

## Features

### Crypto Service
- AES-256-GCM encryption
- ChaCha20-Poly1305 encryption
- ECDSA/Ed25519/RSA signing
- HMAC generation
- Batch operations (10,000+ ops/sec)
- Key versioning & rotation

### Tokenize Service
- Format-Preserving Encryption (FF1)
- Built-in transformations (credit card, SSN, phone)
- Custom alphabet support
- Stateless operation
- Batch processing (15,000+ ops/sec)

### Lock Service
- Secret storage with encryption at rest
- Key management with versioning
- Shamir secret sharing (seal/unseal)
- Raft consensus for HA
- 2Q LRU caching

### Auth Service
- JWT token generation (ES256)
- Token & API key validation with LRU caching
- Policy-based authorization (Vault-like ACL)
- Built-in policies (admin, crypto-user, tokenize-user, etc.)
- Background policy sync to gateway (every 30s)

### Gateway
- Authentication middleware (token/apikey validation, LRU cached)
- Policy-based authorization at gateway level
- Rate limiting: per-client (apikey > token > IP), strict token bucket, default OFF
- Circuit breaker per backend service
- 50 gRPC connection pool per service (round-robin)
- VTProtobuf optimized serialization

## Documentation

- [Architecture Overview](docs/01-ARCHITECTURE-OVERVIEW.md)
- [Service Specifications](docs/02-SERVICE-SPECIFICATIONS.md)
- [Data Flow Diagrams](docs/03-DATA-FLOW-DIAGRAMS.md)
- [Implementation Plan](docs/04-IMPLEMENTATION-PLAN.md)
- [Tech Stack](docs/05-TECH-STACK.md)

## Quick Start

### Prerequisites
- Go 1.24+
- Docker & Docker Compose
- Make

### Development Setup

```bash
# Clone repository
git clone https://github.com/yourorg/microservice-vault.git
cd microservice-vault

# Start infrastructure
make dev-infra

# Run services
make dev

# Run tests
make test
```

### API Examples

#### Encrypt Data
```bash
curl -X POST http://localhost:8080/v1/crypto/encrypt \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "key_name": "app-key",
    "plaintext": "c2Vuc2l0aXZlIGRhdGE="
  }'

# Response
{
  "ciphertext": "vault:v1:SGVsbG8gV29ybGQh...",
  "key_version": 1
}
```

#### FPE Tokenize (Credit Card)
```bash
curl -X POST http://localhost:8080/v1/tokenize/fpe/encrypt \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "key_name": "fpe-key",
    "plaintext": "4111111111111111",
    "transformation": "credit-card"
  }'

# Response: format preserved!
{
  "ciphertext": "9284756038291847",
  "key_version": 1
}
```

#### Store Secret
```bash
curl -X POST http://localhost:8080/v1/secrets/myapp/database \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "data": {
      "username": "admin",
      "password": "secret123"
    }
  }'
```

## Configuration

All configuration via environment variables:

### Gateway
| Variable | Default | Description |
|----------|---------|-------------|
| `GATEWAY_HTTP_PORT` | 8080 | HTTP listen port |
| `GATEWAY_GRPC_PORT` | 9090 | gRPC listen port |
| `GATEWAY_AUTH_ENABLED` | true | Enable authentication |
| `GATEWAY_AUTH_TOKEN_CACHE_SIZE` | 10000 | LRU cache entries for tokens |
| `GATEWAY_AUTH_TOKEN_CACHE_TTL` | 5m | Token cache TTL |
| `GATEWAY_AUTH_POLICY_SYNC_INTERVAL` | 30s | Policy sync from auth service |
| `GATEWAY_RATE_LIMIT_ENABLED` | false | Enable rate limiting (Vault-like, default OFF) |
| `GATEWAY_RATE_LIMIT_RPS` | 1000 | Requests per second per client |
| `GATEWAY_RATE_LIMIT_BURST` | 0 | Burst size (0 = same as RPS) |

### Services
| Variable | Default | Description |
|----------|---------|-------------|
| `AUTH_SERVICE_ADDRESS` | localhost:9091 | Auth service gRPC address |
| `CRYPTO_SERVICE_ADDRESS` | localhost:9092 | Crypto service gRPC address |
| `TOKENIZE_SERVICE_ADDRESS` | localhost:9093 | Tokenize service gRPC address |
| `LOCK_SERVICE_ADDRESS` | localhost:9094 | Lock service gRPC address |

## Performance Benchmarks

### Load Test Results (Baremetal)

**Test Configuration:**
- Concurrent Connections: 500
- Duration: 30 seconds
- Connection Pool: 50 connections (ghz)
- Test Date: February 12, 2026

#### Direct gRPC Services

| Service | Port | Tool | Throughput | Avg Latency | P50 | P95 | P99 | Total Requests |
|---------|------|------|------------|-------------|-----|-----|-----|----------------|
| **Tokenize** | 9093 | ghz | **62,055 req/s** | 3.40 ms | 2.50 ms | 8.83 ms | 12.74 ms | 1,861,735 |
| **Crypto** | 9092 | ghz | **62,304 req/s** | 3.45 ms | 2.58 ms | 9.11 ms | 13.09 ms | 1,869,188 |

#### HTTP API Gateway

| Endpoint | Port | Tool | Throughput | Avg Latency | P50 | P95 | P99 | Total Requests |
|----------|------|------|------------|-------------|-----|-----|-----|----------------|
| `/v1/tokenize/encode` | 8080 | hey | **54,592 req/s** | 15.0 ms | 7.3 ms | 23.2 ms | 35.2 ms | 1,000,000 |
| `/v1/tokenize/encode` | 8080 | loadtest | **49,396 req/s** | 9.67 ms | 7.87 ms | 23.87 ms | 34.15 ms | 1,482,887 |
| `/v1/crypto/encrypt` | 8080 | hey | **50,526 req/s** | 15.0 ms | 7.4 ms | 25.9 ms | 40.2 ms | 1,000,000 |

### Key Performance Highlights

✅ **Exceptional Throughput**
- Direct gRPC: **~62,000 requests/second** with sub-3ms P50 latency
- HTTP Gateway: **~50,000-54,000 requests/second** with ~7-8ms P50 latency
- Success Rate: **100%** across all tools and tests (7.2M+ total requests)

✅ **Minimal Gateway Overhead**
- Throughput drop: ~17-20% (62K → 50-54K req/s)
- Latency increase: ~4-5ms (acceptable for production)
- Connection pooling and circuit breaker working efficiently

✅ **Production-Ready Stability**
- Consistent performance across multiple test runs and tools
- P99 latency under 41ms even at 500 concurrent connections
- No degradation or crashes handling 1M+ requests per test
- Results reproducible and predictable

✅ **Optimizations Applied**
- VTProtobuf codec for faster serialization
- 50-connection gRPC pool per service (round-robin)
- LRU caching for auth tokens and keys (5-min TTL)
- Circuit breaker preventing cascade failures
- Fastrand for IV/nonce generation (buffered crypto/rand)

### Benchmarking Commands

#### Direct gRPC Services (ghz)

```bash
# Test Tokenize Service (gRPC)
ghz --insecure \
  --proto api/proto/tokenize/v1/tokenize.proto \
  --import-paths api/proto \
  --call tokenize.v1.TokenizeService/FPEEncrypt \
  -d '{"key_name":"test-key","plaintext":"4111111111111111","transformation":"credit-card"}' \
  -c 500 -z 30s --connections 50 \
  localhost:9093

# Test Crypto Service (gRPC)
ghz --insecure \
  --proto api/proto/crypto/v1/crypto.proto \
  --import-paths api/proto \
  --call crypto.v1.CryptoService/Encrypt \
  -d '{"key_name":"test-key","plaintext":"SGVsbG8gV29ybGQ="}' \
  -c 500 -z 30s --connections 50 \
  localhost:9092
```

#### HTTP API Gateway (hey)

```bash
# Test Tokenize Endpoint
hey -z 30s -c 500 -m POST \
  -H "Content-Type: application/json" \
  -d '{"key_name":"test-key","value":"4111111111111111","transformation":"credit-card"}' \
  http://localhost:8080/v1/tokenize/encode

# Test Crypto Endpoint
hey -z 30s -c 500 -m POST \
  -H "Content-Type: application/json" \
  -d '{"key_name":"test-key","plaintext":"SGVsbG8gV29ybGQ="}' \
  http://localhost:8080/v1/crypto/encrypt
```

#### HTTP API Gateway (Custom loadtest tool)

```bash
# Test Tokenize Endpoint
loadtest \
  -url "http://localhost:8080/v1/tokenize/encode" \
  -body '{"key_name":"test-key","value":"4111111111111111","transformation":"credit-card"}' \
  -success-field "token" \
  -duration 30s \
  -concurrency 500

# Test Crypto Endpoint
loadtest \
  -url "http://localhost:8080/v1/crypto/encrypt" \
  -body '{"key_name":"test-key","plaintext":"SGVsbG8gV29ybGQ="}' \
  -success-field "ciphertext" \
  -duration 30s \
  -concurrency 500
```

### Prerequisites for Benchmarking

**Tools Required:**
- `ghz` - gRPC benchmarking tool ([install](https://ghz.sh))
- `hey` - HTTP load generator ([install](https://github.com/rakyll/hey))
- `loadtest` - Custom TakaKrypt load test tool (optional)

**Before Running:**
1. Initialize and unseal the vault:
   ```bash
   # Initialize
   curl -X POST http://localhost:8080/v1/sys/init \
     -H "Content-Type: application/json" \
     -d '{"secret_shares": 5, "secret_threshold": 3}'

   # Unseal (use one of the keys from init response)
   curl -X POST http://localhost:8080/v1/sys/unseal \
     -H "Content-Type: application/json" \
     -d '{"key": "YOUR_KEY_HERE"}'
   ```

2. Create test key:
   ```bash
   # Disable auth for testing (or use valid token)
   export GATEWAY_AUTH_ENABLED=false

   # Create key
   curl -X POST http://localhost:8080/v1/transit/keys \
     -H "Content-Type: application/json" \
     -d '{"name":"test-key","type":"aes256-gcm96"}'
   ```

## License

MIT License
