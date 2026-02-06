# Microservice Vault Platform

Enterprise-grade vault platform berbasis microservices untuk enkripsi, tokenisasi, dan manajemen secrets dengan fokus pada **high throughput** dan **horizontal scalability**.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         GATEWAY                                  │
│         (Rate Limiting, Routing, Circuit Breaker)               │
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
| **Gateway** | API Gateway, rate limiting, routing | 8080 (HTTP), 9090 (gRPC) |
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

## Documentation

- [Architecture Overview](docs/01-ARCHITECTURE-OVERVIEW.md)
- [Service Specifications](docs/02-SERVICE-SPECIFICATIONS.md)
- [Data Flow Diagrams](docs/03-DATA-FLOW-DIAGRAMS.md)
- [Implementation Plan](docs/04-IMPLEMENTATION-PLAN.md)
- [Tech Stack](docs/05-TECH-STACK.md)

## Quick Start

### Prerequisites
- Go 1.21+
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

## Performance Targets

| Operation | Target | Actual |
|-----------|--------|--------|
| Encrypt (single) | < 15ms | - |
| Encrypt (batch 100) | < 20ms | - |
| FPE Encrypt | < 10ms | - |
| FPE Batch 100 | < 15ms | - |
| Token Validate | < 5ms | - |
| Secret Read | < 20ms | - |

## License

MIT License
