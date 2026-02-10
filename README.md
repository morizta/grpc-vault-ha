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

## Performance Targets

| Operation | Target | Actual |
|-----------|--------|--------|
| Encrypt (single) | < 15ms | ~0.2ms (p50) |
| Encrypt throughput | 10,000/s | **48,824/s** |
| Tokenize throughput | 10,000/s | **46,000/s** |
| Auth overhead | < 5% | **~0%** (LRU cached) |
| FPE Encrypt | < 10ms | ~0.3ms (p50) |
| Token Validate | < 5ms | < 1ms (cached) |

## License

MIT License
