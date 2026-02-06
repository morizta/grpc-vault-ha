# Microservice Vault Platform - Architecture Overview

## Executive Summary

Platform vault berbasis microservices untuk menyediakan layanan keamanan data enterprise-grade meliputi enkripsi, tokenisasi, dan manajemen secrets dengan fokus pada **high throughput** dan **horizontal scalability**.

---

## High-Level Architecture

```
                                    ┌─────────────────┐
                                    │   Client Apps   │
                                    │  (Web/Mobile/   │
                                    │   Services)     │
                                    └────────┬────────┘
                                             │
                                             │ gRPC / REST
                                             ▼
┌────────────────────────────────────────────────────────────────────────────┐
│                            GATEWAY SERVICE                                  │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐      │
│  │Rate Limiting │ │Load Balancing│ │   Routing    │ │  TLS Term    │      │
│  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘      │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐                        │
│  │Request Batch │ │Circuit Break │ │  Metrics     │                        │
│  └──────────────┘ └──────────────┘ └──────────────┘                        │
└────────────────────────────────────────┬───────────────────────────────────┘
                                         │
           ┌─────────────┬───────────────┼───────────────┬─────────────┐
           │             │               │               │             │
           ▼             ▼               ▼               ▼             ▼
    ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐
    │    AUTH    │ │   CRYPTO   │ │  TOKENIZE  │ │    LOCK    │ │   AUDIT    │
    │  SERVICE   │ │  SERVICE   │ │  SERVICE   │ │  SERVICE   │ │  SERVICE   │
    │            │ │            │ │            │ │  (Vault)   │ │            │
    │ - JWT/OAuth│ │ - Encrypt  │ │ - FPE      │ │ - Secrets  │ │ - Logging  │
    │ - API Keys │ │ - Decrypt  │ │ - Tokenize │ │ - Keys     │ │ - Events   │
    │ - mTLS     │ │ - Sign     │ │ - Mask     │ │ - Seal     │ │ - Compliance│
    │ - Policy   │ │ - HMAC     │ │            │ │ - Barrier  │ │            │
    └─────┬──────┘ └─────┬──────┘ └─────┬──────┘ └─────┬──────┘ └─────┬──────┘
          │              │              │              │              │
          │              │              │              │              │
          ▼              ▼              ▼              ▼              ▼
    ┌─────────────────────────────────────────────────────────────────────────┐
    │                         INFRASTRUCTURE LAYER                             │
    │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐   │
    │  │    Redis     │ │  PostgreSQL  │ │     Raft     │ │    Kafka     │   │
    │  │   (Cache)    │ │   (Auth DB)  │ │  (Lock Store)│ │   (Events)   │   │
    │  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘   │
    └─────────────────────────────────────────────────────────────────────────┘
```

---

## Core Design Principles

### 1. Separation of Concerns
Setiap service memiliki single responsibility:
- **Gateway**: Traffic management & routing
- **Auth**: Identity & access management
- **Crypto**: Cryptographic operations
- **Tokenize**: Data tokenization & FPE
- **Lock**: Secret storage & key management
- **Audit**: Logging & compliance

### 2. High Throughput Patterns (Learned from HashiCorp Vault)

| Pattern | Implementation | Benefit |
|---------|----------------|---------|
| **Multi-level Caching** | L1: In-memory LRU, L2: Redis | Reduce latency |
| **Worker Pools** | 200+ goroutines per service | Parallel processing |
| **Batch Operations** | gRPC streaming, array inputs | Reduce round-trips |
| **Fine-grained Locking** | Per-key locks, not global | Reduce contention |
| **Connection Pooling** | gRPC persistent connections | Reduce overhead |

### 3. Security by Design
- Zero-trust architecture
- Encryption at rest and in transit
- Key hierarchy with rotation
- Audit trail untuk semua operasi

### 4. Horizontal Scalability
- Stateless services (kecuali Lock)
- Consistent hashing untuk routing
- Auto-scaling berdasarkan load

---

## Service Communication

### Internal Communication: gRPC
```
┌──────────┐     gRPC      ┌──────────┐
│ Service A│◄─────────────►│ Service B│
└──────────┘   (mTLS)      └──────────┘
```

### External Communication: REST + gRPC
```
┌──────────┐   REST/gRPC   ┌──────────┐
│  Client  │──────────────►│ Gateway  │
└──────────┘    (TLS)      └──────────┘
```

### Event-Driven: Kafka
```
┌──────────┐    Publish    ┌──────────┐   Subscribe   ┌──────────┐
│ Service  │──────────────►│  Kafka   │──────────────►│  Audit   │
└──────────┘               └──────────┘               └──────────┘
```

---

## Data Flow Examples

### Encrypt Request Flow
```
Client ──► Gateway ──► Auth (validate) ──► Crypto (encrypt) ──► Lock (get key)
                                                │
                                                ▼
Client ◄── Gateway ◄── Crypto (ciphertext) ◄───┘
```

### FPE Tokenize Flow
```
Client ──► Gateway ──► Auth (validate) ──► Tokenize (FPE encrypt)
                                                │
                                                ├──► Lock (get key)
                                                │
Client ◄── Gateway ◄── Tokenize (token) ◄───────┘
```

### Secret Storage Flow
```
Client ──► Gateway ──► Auth (validate) ──► Lock (store secret)
                                                │
                                                ├──► Barrier (encrypt)
                                                │
                                                ├──► Raft (persist)
                                                │
Client ◄── Gateway ◄── Lock (success) ◄─────────┘
```

---

## Scalability Model

### Horizontal Scaling per Service

| Service | Scaling Strategy | State |
|---------|------------------|-------|
| Gateway | Stateless, scale freely | None |
| Auth | Stateless + Redis session | Shared (Redis) |
| Crypto | Stateless, CPU-bound | None |
| Tokenize | Stateless (FPE) | None |
| Lock | Raft consensus, 3-5 nodes | Local (Raft) |
| Audit | Stateless, async | None |

### Expected Throughput (per instance)

| Service | Operations/sec | Latency (p99) |
|---------|----------------|---------------|
| Gateway | 50,000+ | < 5ms |
| Auth | 20,000+ | < 10ms |
| Crypto | 10,000+ | < 15ms |
| Tokenize (FPE) | 15,000+ | < 10ms |
| Lock | 5,000+ | < 20ms |

---

## Deployment Architecture

### Kubernetes Deployment
```
┌─────────────────────────────────────────────────────────────┐
│                     Kubernetes Cluster                       │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                    Ingress (Nginx)                   │   │
│  └─────────────────────────────────────────────────────┘   │
│                            │                                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              Gateway Deployment (3+ pods)            │   │
│  └─────────────────────────────────────────────────────┘   │
│                            │                                │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐  │
│  │   Auth    │ │  Crypto   │ │ Tokenize  │ │   Audit   │  │
│  │ (3+ pods) │ │ (3+ pods) │ │ (3+ pods) │ │ (2+ pods) │  │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘  │
│                            │                                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              Lock StatefulSet (3-5 pods)             │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐               │
│  │   Redis   │ │ PostgreSQL│ │   Kafka   │               │
│  │ (Cluster) │ │ (Primary/ │ │ (Cluster) │               │
│  │           │ │  Replica) │ │           │               │
│  └───────────┘ └───────────┘ └───────────┘               │
└─────────────────────────────────────────────────────────────┘
```

---

## Security Architecture

### Key Hierarchy
```
                    ┌─────────────────┐
                    │   Master Key    │ ← Sealed/Unsealed
                    │  (Root of Trust)│
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
        ┌──────────┐  ┌──────────┐  ┌──────────┐
        │ Barrier  │  │  Transit │  │   FPE    │
        │   Key    │  │   Keys   │  │   Keys   │
        └──────────┘  └──────────┘  └──────────┘
              │              │              │
              ▼              ▼              ▼
        ┌──────────┐  ┌──────────┐  ┌──────────┐
        │ Encrypts │  │ Encrypts │  │ Encrypts │
        │ Secrets  │  │ App Data │  │ PII Data │
        └──────────┘  └──────────┘  └──────────┘
```

### Authentication Flow
```
┌────────┐    ┌─────────┐    ┌──────┐    ┌─────────┐
│ Client │───►│ Gateway │───►│ Auth │───►│ Service │
└────────┘    └─────────┘    └──────┘    └─────────┘
    │              │             │            │
    │  1. Token    │             │            │
    │─────────────►│  2. Validate│            │
    │              │────────────►│            │
    │              │  3. Claims  │            │
    │              │◄────────────│            │
    │              │      4. Forward + Claims │
    │              │─────────────────────────►│
    │              │      5. Response         │
    │  6. Response │◄─────────────────────────│
    │◄─────────────│                          │
```

---

## Monitoring & Observability

### Metrics (Prometheus)
- Request rate, latency, errors per service
- Key operation counts
- Cache hit/miss ratios
- Worker pool utilization

### Tracing (Jaeger/OpenTelemetry)
- Distributed request tracing
- Service dependency mapping
- Latency breakdown

### Logging (ELK/Loki)
- Structured JSON logs
- Correlation IDs
- Audit trail

---

## Next Documents

1. [02-SERVICE-SPECIFICATIONS.md](./02-SERVICE-SPECIFICATIONS.md) - Detail setiap service
2. [03-DATA-FLOW-DIAGRAMS.md](./03-DATA-FLOW-DIAGRAMS.md) - Sequence diagrams
3. [04-IMPLEMENTATION-PLAN.md](./04-IMPLEMENTATION-PLAN.md) - Phases & milestones
4. [05-TECH-STACK.md](./05-TECH-STACK.md) - Technologies & dependencies
