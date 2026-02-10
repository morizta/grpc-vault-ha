# Service Specifications

## Table of Contents
1. [Gateway Service](#1-gateway-service)
2. [Auth Service](#2-auth-service)
3. [Crypto Service](#3-crypto-service)
4. [Tokenize Service](#4-tokenize-service)
5. [Lock Service](#5-lock-service)
6. [Audit Service](#6-audit-service)

---

## 1. Gateway Service

### Overview
Entry point untuk semua request ke platform. Bertanggung jawab untuk routing, rate limiting, dan load balancing.

### Responsibilities
- Authentication (JWT token & API key validation with LRU caching)
- Authorization (policy-based, synced from Auth Service every 30s)
- Request routing ke internal services
- Rate limiting (per-client, strict token bucket, default OFF)
- Circuit breaker pattern
- Connection pooling (50 gRPC connections per service, round-robin)
- Health checking
- VTProtobuf optimized serialization

### Architecture
```
┌─────────────────────────────────────────────────────────────────┐
│                        GATEWAY SERVICE                           │
│                                                                  │
│  Middleware Chain (outermost → innermost):                        │
│  ┌────────┐ ┌──────────┐ ┌────────────┐ ┌──────────┐ ┌───────┐ │
│  │  CORS  │►│Rate Limit│►│    Auth    │►│ Authz    │►│ Log   │ │
│  └────────┘ └──────────┘ └────────────┘ └──────────┘ └───────┘ │
│                                │                                 │
│                   ┌────────────┼────────────┐                   │
│                   ▼            ▼            ▼                   │
│             ┌──────────┐ ┌──────────┐ ┌──────────┐             │
│             │  Auth    │ │  Crypto  │ │ Tokenize │  ...        │
│             │  Client  │ │  Client  │ │  Client  │             │
│             │(50 conns)│ │(50 conns)│ │(50 conns)│             │
│             └──────────┘ └──────────┘ └──────────┘             │
│                                                                  │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐            │
│  │Circuit Breaker│ │ LRU Cache   │ │ Policy Sync  │            │
│  │  (per svc)   │ │(10K, 5m TTL)│ │ (every 30s)  │            │
│  └──────────────┘ └──────────────┘ └──────────────┘            │
└─────────────────────────────────────────────────────────────────┘
```

### API Endpoints

#### REST API (actual implementation)
```
# Health (no auth required)
GET    /health/live                  → Health Check
GET    /health/ready                 → Health Check
GET    /status                       → Service Status

# Auth (login skips auth, lookup requires auth)
POST   /v1/auth/login               → Auth Service (skip auth)
GET    /v1/auth/token/lookup-self    → Auth Service

# Crypto (requires auth + policy)
POST   /v1/crypto/encrypt           → Crypto Service
POST   /v1/crypto/decrypt           → Crypto Service

# Tokenize (requires auth + policy)
POST   /v1/tokenize/encode          → Tokenize Service
POST   /v1/tokenize/decode          → Tokenize Service

# Secrets (requires auth + policy)
GET    /v1/secret/data              → Lock Service
POST   /v1/secret/data              → Lock Service

# Key Management (requires auth + policy)
GET    /v1/transit/keys             → Lock Service
POST   /v1/transit/keys             → Lock Service

# Seal/Unseal (skip auth - uses Shamir shares)
GET    /v1/sys/seal-status          → Lock Service
POST   /v1/sys/init                 → Lock Service
POST   /v1/sys/unseal               → Lock Service
POST   /v1/sys/seal                 → Lock Service
```

#### gRPC Services
```protobuf
service GatewayService {
    // Health & Status
    rpc Health(HealthRequest) returns (HealthResponse);
    rpc Status(StatusRequest) returns (StatusResponse);
}
```

### Configuration (Environment Variables)
```
# Server
GATEWAY_HTTP_PORT=8080
GATEWAY_GRPC_PORT=9090

# Authentication (gateway-level, like Vault's core.checkToken)
GATEWAY_AUTH_ENABLED=true                      # Enable auth middleware
GATEWAY_AUTH_TOKEN_CACHE_SIZE=10000             # LRU cache entries
GATEWAY_AUTH_TOKEN_CACHE_TTL=5m                # Cache TTL
GATEWAY_AUTH_APIKEY_CACHE_SIZE=5000             # API key cache entries
GATEWAY_AUTH_POLICY_SYNC_INTERVAL=30s           # Policy sync from auth service

# Rate Limiting (Vault-like, default OFF)
GATEWAY_RATE_LIMIT_ENABLED=false               # Default OFF (admin enables manually)
GATEWAY_RATE_LIMIT_RPS=1000                    # Requests per second per client
GATEWAY_RATE_LIMIT_BURST=0                     # 0 = same as RPS (strict token bucket)
GATEWAY_RATE_LIMIT_CLEANUP=1m                  # Stale client cleanup interval

# Circuit Breaker
GATEWAY_CB_MAX_REQUESTS=5
GATEWAY_CB_INTERVAL=10s
GATEWAY_CB_TIMEOUT=60s
GATEWAY_CB_FAILURE_RATIO=0.5

# Backend Services
AUTH_SERVICE_ADDRESS=localhost:9091
CRYPTO_SERVICE_ADDRESS=localhost:9092
TOKENIZE_SERVICE_ADDRESS=localhost:9093
LOCK_SERVICE_ADDRESS=localhost:9094
AUDIT_SERVICE_ADDRESS=localhost:9095
```

### High Throughput Features
- **Connection Pooling**: 50 gRPC connections per service (round-robin)
- **LRU Token Cache**: 10K entries, 5min TTL — auth adds ~0% overhead
- **Background Policy Sync**: Policies synced every 30s, evaluated locally
- **VTProtobuf**: Optimized protobuf serialization
- **Circuit Breaker**: Prevent cascade failures per backend service
- **Rate Limiting**: Vault-like strict token bucket, per-client (apikey > token > IP)

---

## 2. Auth Service

### Overview
Menangani autentikasi dan autorisasi untuk semua request ke platform.

### Responsibilities
- Token generation (JWT)
- Token validation
- API key management
- Policy/ACL evaluation
- Session management
- Identity federation (OAuth, OIDC)

### Architecture
```
┌─────────────────────────────────────────────────────────────────┐
│                         AUTH SERVICE                             │
│                                                                  │
│  ┌────────────────┐    ┌────────────────┐    ┌────────────────┐ │
│  │ Token Handler  │    │ Policy Engine  │    │ Session Mgr    │ │
│  └───────┬────────┘    └───────┬────────┘    └───────┬────────┘ │
│          │                     │                     │          │
│          ▼                     ▼                     ▼          │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                       Token Store                            ││
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         ││
│  │  │   L1 Cache  │  │   L2 Cache  │  │  PostgreSQL │         ││
│  │  │  (In-Memory)│  │   (Redis)   │  │  (Persist)  │         ││
│  │  └─────────────┘  └─────────────┘  └─────────────┘         ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
│  ┌────────────────┐    ┌────────────────┐                       │
│  │ Identity Store │    │  Audit Logger  │                       │
│  └────────────────┘    └────────────────┘                       │
└─────────────────────────────────────────────────────────────────┘
```

### gRPC API
```protobuf
syntax = "proto3";
package auth.v1;

service AuthService {
    // Token Operations
    rpc CreateToken(CreateTokenRequest) returns (CreateTokenResponse);
    rpc ValidateToken(ValidateTokenRequest) returns (ValidateTokenResponse);
    rpc RevokeToken(RevokeTokenRequest) returns (RevokeTokenResponse);
    rpc RefreshToken(RefreshTokenRequest) returns (RefreshTokenResponse);

    // API Key Operations
    rpc CreateAPIKey(CreateAPIKeyRequest) returns (CreateAPIKeyResponse);
    rpc ValidateAPIKey(ValidateAPIKeyRequest) returns (ValidateAPIKeyResponse);
    rpc RevokeAPIKey(RevokeAPIKeyRequest) returns (RevokeAPIKeyResponse);
    rpc ListAPIKeys(ListAPIKeysRequest) returns (ListAPIKeysResponse);

    // Policy Operations
    rpc CreatePolicy(CreatePolicyRequest) returns (CreatePolicyResponse);
    rpc GetPolicy(GetPolicyRequest) returns (GetPolicyResponse);
    rpc UpdatePolicy(UpdatePolicyRequest) returns (UpdatePolicyResponse);
    rpc DeletePolicy(DeletePolicyRequest) returns (DeletePolicyResponse);
    rpc EvaluatePolicy(EvaluatePolicyRequest) returns (EvaluatePolicyResponse);
}

message CreateTokenRequest {
    string identity = 1;           // User/service identity
    repeated string policies = 2;   // Attached policies
    int64 ttl_seconds = 3;         // Token TTL
    map<string, string> metadata = 4;
}

message CreateTokenResponse {
    string token = 1;
    string token_id = 2;
    int64 expires_at = 3;
}

message ValidateTokenRequest {
    string token = 1;
    string required_policy = 2;    // Optional: check specific policy
    string resource = 3;           // Optional: resource being accessed
    string action = 4;             // Optional: action being performed
}

message ValidateTokenResponse {
    bool valid = 1;
    string identity = 2;
    repeated string policies = 3;
    map<string, string> metadata = 4;
    int64 expires_at = 5;
}

// Policy definition
message Policy {
    string name = 1;
    repeated PolicyRule rules = 2;
}

message PolicyRule {
    string path = 1;               // Resource path pattern
    repeated string capabilities = 2; // create, read, update, delete, list
    map<string, string> conditions = 3;
}
```

### Token Structure (JWT)
```json
{
  "header": {
    "alg": "ES256",
    "typ": "JWT",
    "kid": "key-version-1"
  },
  "payload": {
    "sub": "user-123",
    "iss": "vault-auth",
    "aud": "vault-platform",
    "exp": 1699999999,
    "iat": 1699990000,
    "jti": "token-uuid",
    "policies": ["default", "app-secrets"],
    "metadata": {
      "app": "myapp",
      "env": "production"
    }
  }
}
```

### Policy Example
```hcl
# Policy: app-secrets
path "secrets/data/myapp/*" {
    capabilities = ["create", "read", "update", "delete"]
}

path "crypto/encrypt" {
    capabilities = ["create"]
    allowed_keys = ["myapp-key"]
}

path "tokenize/fpe/*" {
    capabilities = ["create"]
}
```

### Configuration
```yaml
auth:
  server:
    grpc_port: 9090

  jwt:
    algorithm: ES256
    issuer: vault-auth
    audience: vault-platform
    default_ttl: 3600        # 1 hour
    max_ttl: 86400           # 24 hours
    signing_key_path: /keys/jwt-signing.key

  cache:
    l1_size: 10000           # In-memory cache entries
    l2_enabled: true
    l2_ttl: 300              # Redis TTL in seconds

  database:
    driver: postgres
    host: postgres:5432
    database: auth
    max_connections: 100

  redis:
    address: redis:6379
    db: 0
```

### High Throughput Features
- **Token Caching**: L1 (in-memory) + L2 (Redis) untuk validasi cepat
- **Bloom Filter**: Quick check untuk revoked tokens
- **Policy Caching**: Cache compiled policies
- **Async Audit**: Non-blocking audit logging ke Kafka

---

## 3. Crypto Service

### Overview
Menyediakan operasi kriptografi: enkripsi, dekripsi, signing, verification, dan HMAC.

### Responsibilities
- Symmetric encryption (AES-GCM, ChaCha20-Poly1305)
- Asymmetric encryption (RSA)
- Digital signatures (ECDSA, Ed25519, RSA-PSS)
- HMAC generation & verification
- Key derivation (HKDF)
- Batch operations

### Architecture
```
┌─────────────────────────────────────────────────────────────────┐
│                        CRYPTO SERVICE                            │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                     Request Handler                         │ │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐      │ │
│  │  │ Encrypt  │ │ Decrypt  │ │   Sign   │ │  Verify  │      │ │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘      │ │
│  └────────────────────────────────────────────────────────────┘ │
│                              │                                   │
│                              ▼                                   │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                      Key Manager                            │ │
│  │  ┌─────────────────┐    ┌─────────────────┐               │ │
│  │  │   Key Cache     │    │   Lock Client   │               │ │
│  │  │   (LRU 1000)    │───►│  (Get Keys)     │               │ │
│  │  └─────────────────┘    └─────────────────┘               │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                     Worker Pool (200)                       │ │
│  │  ┌────┐ ┌────┐ ┌────┐ ┌────┐ ┌────┐ ┌────┐ ... ┌────┐    │ │
│  │  │ W1 │ │ W2 │ │ W3 │ │ W4 │ │ W5 │ │ W6 │     │W200│    │ │
│  │  └────┘ └────┘ └────┘ └────┘ └────┘ └────┘     └────┘    │ │
│  └────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### gRPC API
```protobuf
syntax = "proto3";
package crypto.v1;

service CryptoService {
    // Encryption
    rpc Encrypt(EncryptRequest) returns (EncryptResponse);
    rpc Decrypt(DecryptRequest) returns (DecryptResponse);
    rpc EncryptBatch(EncryptBatchRequest) returns (EncryptBatchResponse);
    rpc DecryptBatch(DecryptBatchRequest) returns (DecryptBatchResponse);

    // Signing
    rpc Sign(SignRequest) returns (SignResponse);
    rpc Verify(VerifyRequest) returns (VerifyResponse);
    rpc SignBatch(SignBatchRequest) returns (SignBatchResponse);

    // HMAC
    rpc GenerateHMAC(HMACRequest) returns (HMACResponse);
    rpc VerifyHMAC(VerifyHMACRequest) returns (VerifyHMACResponse);

    // Data Keys (for envelope encryption)
    rpc GenerateDataKey(GenerateDataKeyRequest) returns (GenerateDataKeyResponse);
    rpc DecryptDataKey(DecryptDataKeyRequest) returns (DecryptDataKeyResponse);

    // Rewrap (re-encrypt with new key version)
    rpc Rewrap(RewrapRequest) returns (RewrapResponse);
}

message EncryptRequest {
    string key_name = 1;
    bytes plaintext = 2;
    bytes context = 3;              // Additional authenticated data (AAD)
    int32 key_version = 4;          // 0 = latest
}

message EncryptResponse {
    string ciphertext = 1;          // Format: "vault:v1:base64..."
    int32 key_version = 2;
}

message EncryptBatchRequest {
    string key_name = 1;
    repeated BatchEncryptItem items = 2;
}

message BatchEncryptItem {
    bytes plaintext = 1;
    bytes context = 2;
    string reference = 3;           // Correlation ID
}

message EncryptBatchResponse {
    repeated BatchEncryptResult results = 1;
}

message BatchEncryptResult {
    string ciphertext = 1;
    string reference = 2;
    string error = 3;               // Empty if success
}

message SignRequest {
    string key_name = 1;
    bytes data = 2;
    HashAlgorithm hash_algorithm = 3;
    SignatureAlgorithm signature_algorithm = 4;
}

enum HashAlgorithm {
    SHA256 = 0;
    SHA384 = 1;
    SHA512 = 2;
}

enum SignatureAlgorithm {
    ECDSA = 0;
    ED25519 = 1;
    RSA_PSS = 2;
    RSA_PKCS1 = 3;
}

message SignResponse {
    bytes signature = 1;
    int32 key_version = 2;
}

message GenerateDataKeyRequest {
    string key_name = 1;            // KEK name
    int32 key_bits = 2;             // 128, 256
    bytes context = 3;
}

message GenerateDataKeyResponse {
    bytes plaintext_key = 1;        // Use this for encryption
    string encrypted_key = 2;       // Store this
    int32 key_version = 3;
}
```

### Supported Key Types
| Type | Algorithm | Use Case |
|------|-----------|----------|
| `aes256-gcm` | AES-256-GCM | General encryption |
| `chacha20-poly1305` | ChaCha20-Poly1305 | Alternative encryption |
| `rsa-2048` | RSA-2048 | Asymmetric encryption, signing |
| `rsa-4096` | RSA-4096 | High security asymmetric |
| `ecdsa-p256` | ECDSA P-256 | Fast signing |
| `ecdsa-p384` | ECDSA P-384 | Strong signing |
| `ed25519` | Ed25519 | Modern signing |

### Ciphertext Format
```
vault:v{version}:{base64_ciphertext}

Example:
vault:v1:AQIDBAUGBwgJCgsMDQ4P...

Components:
- "vault:" = prefix identifier
- "v1" = key version used
- base64 = nonce + ciphertext + tag
```

### Configuration
```yaml
crypto:
  server:
    grpc_port: 9090

  worker_pool:
    size: 200
    queue_size: 10000

  key_cache:
    type: lru
    size: 1000
    ttl: 300

  lock_service:
    address: lock-service:9090
    timeout: 5s

  default_key_type: aes256-gcm

  convergent_encryption:
    enabled: true
    derivation: hkdf-sha256
```

### High Throughput Features
- **Worker Pool**: 200 parallel workers untuk crypto operations
- **Key Caching**: LRU cache untuk hot keys (avoid Lock Service calls)
- **Batch Operations**: Process arrays dalam single call
- **AEAD Caching**: Reuse cipher instances per key version
- **Zero-Copy**: Minimize memory allocations

---

## 4. Tokenize Service

### Overview
Menyediakan tokenisasi data sensitif menggunakan FPE (Format-Preserving Encryption) dan token mapping.

### Responsibilities
- FPE encryption/decryption (FF1/FF3-1)
- Format preservation (credit card, SSN, phone, etc.)
- Data masking
- Optional: Token mapping untuk non-FPE tokenization

### Architecture
```
┌─────────────────────────────────────────────────────────────────┐
│                       TOKENIZE SERVICE                           │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                     Request Handler                         │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │ │
│  │  │  FPE Encrypt │  │  FPE Decrypt │  │    Mask      │     │ │
│  │  └──────────────┘  └──────────────┘  └──────────────┘     │ │
│  └────────────────────────────────────────────────────────────┘ │
│                              │                                   │
│                              ▼                                   │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                    FPE Engine (FF1)                         │ │
│  │  ┌─────────────────┐    ┌─────────────────┐               │ │
│  │  │   Key Cache     │    │  Transformation │               │ │
│  │  │   (LRU 500)     │    │     Registry    │               │ │
│  │  └─────────────────┘    └─────────────────┘               │ │
│  └────────────────────────────────────────────────────────────┘ │
│                              │                                   │
│                              ▼                                   │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                      Lock Client                            │ │
│  │                    (Get FPE Keys)                           │ │
│  └────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### gRPC API
```protobuf
syntax = "proto3";
package tokenize.v1;

service TokenizeService {
    // FPE Operations (Stateless)
    rpc FPEEncrypt(FPEEncryptRequest) returns (FPEEncryptResponse);
    rpc FPEDecrypt(FPEDecryptRequest) returns (FPEDecryptResponse);
    rpc FPEEncryptBatch(FPEBatchRequest) returns (FPEBatchResponse);
    rpc FPEDecryptBatch(FPEBatchRequest) returns (FPEBatchResponse);

    // Masking
    rpc Mask(MaskRequest) returns (MaskResponse);
    rpc MaskBatch(MaskBatchRequest) returns (MaskBatchResponse);

    // Transformations
    rpc ListTransformations(ListTransformationsRequest) returns (ListTransformationsResponse);
    rpc GetTransformation(GetTransformationRequest) returns (Transformation);
}

message FPEEncryptRequest {
    string key_name = 1;
    string plaintext = 2;
    string transformation = 3;      // e.g., "credit-card", "ssn", "phone"
    bytes tweak = 4;                // Optional context

    // Or custom alphabet
    string alphabet = 5;            // e.g., "0123456789"
}

message FPEEncryptResponse {
    string ciphertext = 1;          // Same format as input
    int32 key_version = 2;
}

message FPEBatchRequest {
    string key_name = 1;
    string transformation = 2;
    repeated FPEBatchItem items = 3;
}

message FPEBatchItem {
    string value = 1;
    bytes tweak = 2;
    string reference = 3;
}

message FPEBatchResponse {
    repeated FPEBatchResult results = 1;
}

message FPEBatchResult {
    string value = 1;
    string reference = 2;
    string error = 3;
}

message MaskRequest {
    string value = 1;
    string transformation = 2;      // e.g., "credit-card-mask"
    MaskPattern pattern = 3;        // Or custom pattern
}

message MaskPattern {
    int32 preserve_first = 1;       // Keep first N chars
    int32 preserve_last = 2;        // Keep last N chars
    string mask_char = 3;           // Default: "*"
}

message MaskResponse {
    string masked_value = 1;
}

// Predefined transformation
message Transformation {
    string name = 1;
    string alphabet = 2;
    TransformationType type = 3;
    string pattern = 4;             // Regex for validation
    string description = 5;
}

enum TransformationType {
    NUMERIC = 0;
    ALPHA_LOWER = 1;
    ALPHA_UPPER = 2;
    ALPHANUMERIC = 3;
    CUSTOM = 4;
}
```

### Built-in Transformations
| Name | Alphabet | Example Input | Example Output |
|------|----------|---------------|----------------|
| `credit-card` | 0-9 | 4111111111111111 | 9284756038291847 |
| `ssn` | 0-9 | 123456789 | 847293651 |
| `phone` | 0-9 | 6281234567890 | 9387461520834 |
| `numeric` | 0-9 | 12345 | 84729 |
| `alpha-lower` | a-z | hello | xkqpw |
| `alpha-upper` | A-Z | HELLO | XKQPW |
| `alphanumeric` | 0-9a-zA-Z | Abc123 | Xkq847 |

### FPE Algorithm (FF1)
```go
// FF1 from NIST SP 800-38G
type FF1Cipher struct {
    key       []byte      // 128/192/256 bit AES key
    tweak     []byte      // Additional context (up to maxTLen)
    radix     int         // Alphabet size
    alphabet  string      // Character set
}

// Encryption preserves format
func (c *FF1Cipher) Encrypt(plaintext string) (string, error) {
    // Feistel network with 10 rounds
    // Uses AES-CBC as PRF
    // Output length == input length
    // Output alphabet == input alphabet
}

// Example:
// Input:  "4111111111111111" (16 digits)
// Output: "9284756038291847" (16 digits)
```

### Masking Patterns
```
credit-card-mask:  **** **** **** 1234  (show last 4)
ssn-mask:          ***-**-6789          (show last 4)
phone-mask:        +62 *** **** **90    (show last 2)
email-mask:        r***@example.com     (show first 1)
```

### Configuration
```yaml
tokenize:
  server:
    grpc_port: 9090

  fpe:
    algorithm: ff1
    default_radix: 10

  key_cache:
    type: lru
    size: 500
    ttl: 300

  lock_service:
    address: lock-service:9090
    timeout: 5s

  transformations:
    - name: credit-card
      alphabet: "0123456789"
      pattern: "^[0-9]{13,19}$"
    - name: ssn
      alphabet: "0123456789"
      pattern: "^[0-9]{9}$"
    - name: phone-id
      alphabet: "0123456789"
      pattern: "^62[0-9]{9,12}$"
```

### High Throughput Features
- **Stateless**: No database lookups (FPE is deterministic)
- **Key Caching**: LRU cache untuk FPE keys
- **Batch Operations**: Process arrays efficiently
- **Pre-compiled Transformations**: No runtime alphabet parsing

---

## 5. Lock Service (Vault)

### Overview
Core secret storage dengan encryption barrier, key management, dan seal/unseal operations.

### Responsibilities
- Secret storage dengan encryption at rest
- Encryption key management
- Key rotation
- Seal/Unseal operations
- Distributed consensus (Raft)

### Architecture
```
┌─────────────────────────────────────────────────────────────────┐
│                         LOCK SERVICE                             │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                     Request Handler                         │ │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐      │ │
│  │  │ Secrets  │ │   Keys   │ │   Seal   │ │  Status  │      │ │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘      │ │
│  └────────────────────────────────────────────────────────────┘ │
│                              │                                   │
│                              ▼                                   │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                    BARRIER (AES-GCM)                        │ │
│  │  ┌─────────────────┐    ┌─────────────────┐               │ │
│  │  │     Keyring     │    │  Cipher Cache   │               │ │
│  │  │   (Versioned)   │    │                 │               │ │
│  │  └─────────────────┘    └─────────────────┘               │ │
│  └────────────────────────────────────────────────────────────┘ │
│                              │                                   │
│                              ▼                                   │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                   PHYSICAL STORAGE                          │ │
│  │  ┌─────────────────┐    ┌─────────────────┐               │ │
│  │  │    2Q Cache     │───►│      Raft       │               │ │
│  │  │   (128K items)  │    │   (BoltDB)      │               │ │
│  │  └─────────────────┘    └─────────────────┘               │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                      SEAL MANAGER                           │ │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐                 │ │
│  │  │  Shamir  │  │ Auto-Seal│  │ Recovery │                 │ │
│  │  │  (SSS)   │  │  (KMS)   │  │   Keys   │                 │ │
│  │  └──────────┘  └──────────┘  └──────────┘                 │ │
│  └────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### gRPC API
```protobuf
syntax = "proto3";
package lock.v1;

service LockService {
    // Secret Operations
    rpc GetSecret(GetSecretRequest) returns (GetSecretResponse);
    rpc PutSecret(PutSecretRequest) returns (PutSecretResponse);
    rpc DeleteSecret(DeleteSecretRequest) returns (DeleteSecretResponse);
    rpc ListSecrets(ListSecretsRequest) returns (ListSecretsResponse);

    // Key Operations
    rpc CreateKey(CreateKeyRequest) returns (CreateKeyResponse);
    rpc GetKey(GetKeyRequest) returns (GetKeyResponse);
    rpc RotateKey(RotateKeyRequest) returns (RotateKeyResponse);
    rpc DeleteKey(DeleteKeyRequest) returns (DeleteKeyResponse);
    rpc ListKeys(ListKeysRequest) returns (ListKeysResponse);
    rpc GetKeyVersions(GetKeyVersionsRequest) returns (GetKeyVersionsResponse);

    // Seal Operations
    rpc GetSealStatus(GetSealStatusRequest) returns (SealStatus);
    rpc Initialize(InitializeRequest) returns (InitializeResponse);
    rpc Unseal(UnsealRequest) returns (SealStatus);
    rpc Seal(SealRequest) returns (SealStatus);

    // Cluster Operations
    rpc GetLeader(GetLeaderRequest) returns (GetLeaderResponse);
    rpc JoinCluster(JoinClusterRequest) returns (JoinClusterResponse);
}

// Secret messages
message GetSecretRequest {
    string path = 1;
    int32 version = 2;              // 0 = latest
}

message GetSecretResponse {
    map<string, bytes> data = 1;
    SecretMetadata metadata = 2;
}

message SecretMetadata {
    int32 version = 1;
    int64 created_at = 2;
    int64 updated_at = 3;
    bool destroyed = 4;
}

message PutSecretRequest {
    string path = 1;
    map<string, bytes> data = 2;
    int32 cas = 3;                  // Check-and-set version
}

// Key messages
message CreateKeyRequest {
    string name = 1;
    KeyType type = 2;
    bool exportable = 3;
    bool allow_plaintext_backup = 4;
    int32 min_decryption_version = 5;
    int32 min_encryption_version = 6;
}

enum KeyType {
    AES256_GCM = 0;
    CHACHA20_POLY1305 = 1;
    RSA_2048 = 2;
    RSA_4096 = 3;
    ECDSA_P256 = 4;
    ECDSA_P384 = 5;
    ED25519 = 6;
    FPE_FF1 = 7;
}

message GetKeyRequest {
    string name = 1;
}

message GetKeyResponse {
    string name = 1;
    KeyType type = 2;
    int32 latest_version = 3;
    int32 min_decryption_version = 4;
    int32 min_encryption_version = 5;
    bool exportable = 6;
    repeated KeyVersion versions = 7;
}

message KeyVersion {
    int32 version = 1;
    int64 created_at = 2;
    bytes public_key = 3;           // For asymmetric keys
}

message RotateKeyRequest {
    string name = 1;
}

// Internal: used by Crypto/Tokenize services
message GetEncryptionKeyRequest {
    string name = 1;
    int32 version = 2;              // 0 = latest
}

message GetEncryptionKeyResponse {
    bytes key = 1;                  // Decrypted key material
    int32 version = 2;
    KeyType type = 3;
}

// Seal messages
message SealStatus {
    bool sealed = 1;
    int32 threshold = 2;
    int32 shares = 3;
    int32 progress = 4;
    string cluster_id = 5;
    string cluster_name = 6;
}

message InitializeRequest {
    int32 secret_shares = 1;        // Shamir shares
    int32 secret_threshold = 2;     // Required shares to unseal
    repeated string recovery_keys = 3; // For auto-seal
}

message InitializeResponse {
    repeated string root_tokens = 1;
    repeated string keys = 2;       // Shamir key shares (base64)
    repeated string keys_base64 = 3;
    repeated string recovery_keys = 4;
}

message UnsealRequest {
    string key = 1;                 // One Shamir share
}
```

### Storage Structure
```
/core/
    seal-config          # Seal configuration
    master-key           # Encrypted master key
    keyring              # Encryption keyring

/secrets/
    data/{path}          # Encrypted secret data
    metadata/{path}      # Secret metadata

/keys/
    policy/{name}        # Key policy (type, versions, config)
    archive/{name}       # Old key versions

/auth/
    tokens/{id}          # Token data
    accessors/{id}       # Token accessor index
```

### Barrier Encryption
```go
// Keyring manages versioned encryption keys
type Keyring struct {
    masterKey   []byte
    keys        map[uint32]*Key  // version -> key
    activeKey   uint32
}

// Encrypt with active key
func (b *Barrier) Encrypt(plaintext []byte) ([]byte, error) {
    key := b.keyring.ActiveKey()

    // Get or create cached AEAD
    aead := b.getCachedAEAD(key.Version)

    // Generate nonce
    nonce := make([]byte, aead.NonceSize())
    rand.Read(nonce)

    // Encrypt
    ciphertext := aead.Seal(nil, nonce, plaintext, nil)

    // Prepend version: [version:4][nonce:12][ciphertext+tag]
    return encodeVersioned(key.Version, nonce, ciphertext), nil
}
```

### Raft Consensus
```
┌─────────────────────────────────────────────────────────────────┐
│                        RAFT CLUSTER                              │
│                                                                  │
│    ┌──────────┐      ┌──────────┐      ┌──────────┐            │
│    │  Node 1  │◄────►│  Node 2  │◄────►│  Node 3  │            │
│    │ (Leader) │      │(Follower)│      │(Follower)│            │
│    └──────────┘      └──────────┘      └──────────┘            │
│         │                                                        │
│         ▼                                                        │
│    ┌──────────┐                                                 │
│    │  BoltDB  │  ← WAL + Snapshots                             │
│    └──────────┘                                                 │
│                                                                  │
│    Write Path:                                                   │
│    1. Leader receives write                                      │
│    2. Append to WAL                                             │
│    3. Replicate to followers                                    │
│    4. Commit when majority acknowledges                         │
│    5. Apply to FSM (BoltDB)                                     │
└─────────────────────────────────────────────────────────────────┘
```

### Configuration
```yaml
lock:
  server:
    grpc_port: 9090
    cluster_port: 9091

  seal:
    type: shamir           # or: awskms, gcpkms, azurekeyvault
    shamir:
      shares: 5
      threshold: 3

  storage:
    type: raft
    raft:
      path: /data/raft
      node_id: node1
      performance_multiplier: 1
      max_batch_entries: 4096
      max_batch_size: 131072

  cache:
    type: 2q
    size: 131072           # 128K entries

  barrier:
    key_rotation_period: 720h  # 30 days
```

### High Throughput Features
- **2Q LRU Cache**: 128K entries untuk physical storage
- **Raft Batching**: 4096 entries per batch
- **Cipher Caching**: Reuse AEAD instances
- **Fine-grained Locking**: Per-path locks
- **Read Replicas**: Followers dapat serve reads

---

## 6. Audit Service

### Overview
Centralized logging untuk audit trail, compliance, dan monitoring.

### Responsibilities
- Receive audit events dari semua services
- Store audit logs (immutable)
- Query dan search audit logs
- Export untuk compliance
- Real-time alerting

### Architecture
```
┌─────────────────────────────────────────────────────────────────┐
│                        AUDIT SERVICE                             │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                    Event Consumer                           │ │
│  │              (Kafka Consumer Group)                         │ │
│  └────────────────────────────────────────────────────────────┘ │
│                              │                                   │
│              ┌───────────────┼───────────────┐                  │
│              ▼               ▼               ▼                  │
│       ┌──────────┐    ┌──────────┐    ┌──────────┐             │
│       │  Writer  │    │ Indexer  │    │ Alerter  │             │
│       └──────────┘    └──────────┘    └──────────┘             │
│              │               │               │                  │
│              ▼               ▼               ▼                  │
│       ┌──────────┐    ┌──────────┐    ┌──────────┐             │
│       │ Storage  │    │  Search  │    │  Alert   │             │
│       │(S3/Blob) │    │(Elastic) │    │ Manager  │             │
│       └──────────┘    └──────────┘    └──────────┘             │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                    Query Handler                            │ │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐                 │ │
│  │  │  Search  │  │  Export  │  │  Stats   │                 │ │
│  │  └──────────┘  └──────────┘  └──────────┘                 │ │
│  └────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### gRPC API
```protobuf
syntax = "proto3";
package audit.v1;

service AuditService {
    // Query
    rpc SearchAuditLogs(SearchRequest) returns (SearchResponse);
    rpc GetAuditLog(GetAuditLogRequest) returns (AuditLog);
    rpc GetStatistics(GetStatisticsRequest) returns (Statistics);

    // Export
    rpc ExportLogs(ExportRequest) returns (stream ExportChunk);

    // Internal: receive events (called by other services)
    rpc LogEvent(AuditEvent) returns (LogEventResponse);
    rpc LogEventBatch(LogEventBatchRequest) returns (LogEventResponse);
}

message AuditEvent {
    string event_id = 1;
    string timestamp = 2;
    string service = 3;             // auth, crypto, tokenize, lock
    string operation = 4;           // encrypt, decrypt, get_secret, etc.
    string identity = 5;            // Who performed the action
    string resource = 6;            // What was accessed
    string source_ip = 7;
    bool success = 8;
    string error = 9;
    map<string, string> metadata = 10;

    // Request/Response (redacted)
    AuditRequest request = 11;
    AuditResponse response = 12;
}

message AuditRequest {
    string path = 1;
    string operation = 2;
    // Sensitive data redacted
}

message AuditResponse {
    bool success = 1;
    string error = 2;
    // Sensitive data redacted
}

message SearchRequest {
    string service = 1;
    string operation = 2;
    string identity = 3;
    string resource = 4;
    int64 start_time = 5;
    int64 end_time = 6;
    bool success_only = 7;
    bool failure_only = 8;
    int32 limit = 9;
    string cursor = 10;
}

message SearchResponse {
    repeated AuditLog logs = 1;
    string next_cursor = 2;
    int64 total_count = 3;
}

message AuditLog {
    string event_id = 1;
    AuditEvent event = 2;
    string stored_at = 3;
}
```

### Audit Event Flow
```
┌──────────┐     ┌───────┐     ┌──────────┐     ┌───────────┐
│ Service  │────►│ Kafka │────►│  Audit   │────►│  Storage  │
│(Crypto)  │     │       │     │ Consumer │     │(S3/Elastic)│
└──────────┘     └───────┘     └──────────┘     └───────────┘
     │                              │
     │  Async (non-blocking)        │  Indexing
     │                              ▼
     │                        ┌───────────┐
     │                        │Elasticsearch│
     │                        └───────────┘
```

### Configuration
```yaml
audit:
  server:
    grpc_port: 9090

  kafka:
    brokers:
      - kafka-1:9092
      - kafka-2:9092
    topic: vault-audit-events
    consumer_group: audit-service

  storage:
    type: s3
    s3:
      bucket: vault-audit-logs
      region: ap-southeast-1
      prefix: audit/

  search:
    type: elasticsearch
    elasticsearch:
      addresses:
        - http://elasticsearch:9200
      index_prefix: vault-audit

  retention:
    days: 365
    archive_after_days: 90
```

---

## Service Dependencies

```
┌────────────────────────────────────────────────────────────────────┐
│                    SERVICE DEPENDENCY GRAPH                         │
│                                                                     │
│    Gateway ──────┬──────┬──────┬──────┬──────► Audit               │
│                  │      │      │      │                             │
│                  ▼      ▼      ▼      ▼                             │
│               Auth   Crypto  Token  Lock ─────► Audit               │
│                  │      │      │      │                             │
│                  │      └──────┴──────┘                             │
│                  │             │                                    │
│                  │             ▼                                    │
│                  │           Lock ─────────────► Audit              │
│                  │                                                  │
│                  ▼                                                  │
│               Redis ◄────────────────────────── Lock (cache)       │
│                                                                     │
│            PostgreSQL ◄──────────────────────── Auth               │
│                                                                     │
│               Kafka ◄────────────────────────── All Services       │
│                                                                     │
└────────────────────────────────────────────────────────────────────┘

Legend:
──────► : Depends on (sync call)
- - - -► : Publishes to (async)
```

---

## Next: [03-DATA-FLOW-DIAGRAMS.md](./03-DATA-FLOW-DIAGRAMS.md)
