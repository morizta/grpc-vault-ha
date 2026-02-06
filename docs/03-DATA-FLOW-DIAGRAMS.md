# Data Flow Diagrams

## Table of Contents
1. [Authentication Flow](#1-authentication-flow)
2. [Encryption Flow](#2-encryption-flow)
3. [FPE Tokenization Flow](#3-fpe-tokenization-flow)
4. [Secret Storage Flow](#4-secret-storage-flow)
5. [Key Rotation Flow](#5-key-rotation-flow)
6. [Seal/Unseal Flow](#6-sealunseal-flow)
7. [Batch Operations Flow](#7-batch-operations-flow)

---

## 1. Authentication Flow

### Token Creation
```
┌────────┐      ┌─────────┐      ┌──────────┐      ┌──────────┐      ┌───────┐
│ Client │      │ Gateway │      │   Auth   │      │ PostgreSQL│     │ Redis │
└───┬────┘      └────┬────┘      └────┬─────┘      └─────┬────┘      └───┬───┘
    │                │                │                   │              │
    │ 1. POST /auth/token             │                   │              │
    │   {identity, credentials}       │                   │              │
    │───────────────►│                │                   │              │
    │                │                │                   │              │
    │                │ 2. gRPC CreateToken                │              │
    │                │───────────────►│                   │              │
    │                │                │                   │              │
    │                │                │ 3. Validate credentials          │
    │                │                │──────────────────►│              │
    │                │                │                   │              │
    │                │                │ 4. User + policies│              │
    │                │                │◄──────────────────│              │
    │                │                │                   │              │
    │                │                │ 5. Generate JWT   │              │
    │                │                │   (sign with ES256)              │
    │                │                │                   │              │
    │                │                │ 6. Cache token    │              │
    │                │                │──────────────────────────────────►
    │                │                │                   │              │
    │                │ 7. Token response                  │              │
    │                │◄───────────────│                   │              │
    │                │                │                   │              │
    │ 8. {token, expires_at}          │                   │              │
    │◄───────────────│                │                   │              │
    │                │                │                   │              │
```

### Token Validation (with caching)
```
┌────────┐      ┌─────────┐      ┌──────────┐      ┌───────┐
│ Client │      │ Gateway │      │   Auth   │      │ Redis │
└───┬────┘      └────┬────┘      └────┬─────┘      └───┬───┘
    │                │                │                │
    │ 1. Request + Bearer Token       │                │
    │───────────────►│                │                │
    │                │                │                │
    │                │ 2. gRPC ValidateToken           │
    │                │───────────────►│                │
    │                │                │                │
    │                │                │ 3. Check L1 cache (in-memory)
    │                │                │   MISS         │
    │                │                │                │
    │                │                │ 4. Check L2 cache
    │                │                │───────────────►│
    │                │                │                │
    │                │                │ 5. HIT: token data
    │                │                │◄───────────────│
    │                │                │                │
    │                │                │ 6. Verify JWT signature
    │                │                │   Check expiration
    │                │                │   Evaluate policies
    │                │                │                │
    │                │ 7. {valid, identity, policies}  │
    │                │◄───────────────│                │
    │                │                │                │
    │                │ 8. Forward to target service    │
    │                │   with identity context         │
    │                │                │                │
```

---

## 2. Encryption Flow

### Single Encrypt Request
```
┌────────┐   ┌─────────┐   ┌──────┐   ┌────────┐   ┌──────┐   ┌───────┐
│ Client │   │ Gateway │   │ Auth │   │ Crypto │   │ Lock │   │ Audit │
└───┬────┘   └────┬────┘   └──┬───┘   └───┬────┘   └──┬───┘   └───┬───┘
    │             │           │           │           │           │
    │ 1. POST /crypto/encrypt │           │           │           │
    │   {key_name, plaintext} │           │           │           │
    │────────────►│           │           │           │           │
    │             │           │           │           │           │
    │             │ 2. Validate token     │           │           │
    │             │──────────►│           │           │           │
    │             │           │           │           │           │
    │             │ 3. OK + policies      │           │           │
    │             │◄──────────│           │           │           │
    │             │           │           │           │           │
    │             │ 4. gRPC Encrypt       │           │           │
    │             │──────────────────────►│           │           │
    │             │           │           │           │           │
    │             │           │           │ 5. Check key cache    │
    │             │           │           │   (LRU)   │           │
    │             │           │           │           │           │
    │             │           │           │   MISS: Get key       │
    │             │           │           │──────────►│           │
    │             │           │           │           │           │
    │             │           │           │ 6. Key material       │
    │             │           │           │◄──────────│           │
    │             │           │           │           │           │
    │             │           │           │ 7. Cache key (LRU)    │
    │             │           │           │           │           │
    │             │           │           │ 8. AES-GCM Encrypt    │
    │             │           │           │   - Generate nonce    │
    │             │           │           │   - Encrypt           │
    │             │           │           │   - Prepend version   │
    │             │           │           │           │           │
    │             │ 9. {ciphertext, version}          │           │
    │             │◄──────────────────────│           │           │
    │             │           │           │           │           │
    │             │           │           │ 10. Publish audit event
    │             │           │           │──────────────────────►│
    │             │           │           │           │           │
    │ 11. Response│           │           │           │           │
    │◄────────────│           │           │           │           │
    │             │           │           │           │           │
```

### Encryption Detail (inside Crypto Service)
```
┌──────────────────────────────────────────────────────────────────────────┐
│                          CRYPTO SERVICE                                   │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │                       Request Handler                                ││
│  │                                                                      ││
│  │   Input: {key_name: "app-key", plaintext: "sensitive data"}         ││
│  └──────────────────────────────┬──────────────────────────────────────┘│
│                                 │                                        │
│                                 ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │                         Key Manager                                  ││
│  │                                                                      ││
│  │   1. keyCache.Get("app-key")                                        ││
│  │      └─► HIT:  return cached key                                    ││
│  │      └─► MISS: lockClient.GetEncryptionKey("app-key")               ││
│  │                 └─► Cache result in LRU                             ││
│  │                                                                      ││
│  │   Result: Key{version: 3, material: [32 bytes], type: AES256_GCM}   ││
│  └──────────────────────────────┬──────────────────────────────────────┘│
│                                 │                                        │
│                                 ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │                        Encrypt Operation                             ││
│  │                                                                      ││
│  │   1. Get AEAD cipher from cache (or create)                         ││
│  │      aead = cipherCache.Get(keyVersion)                             ││
│  │                                                                      ││
│  │   2. Generate random nonce                                          ││
│  │      nonce = crypto/rand.Read(12 bytes)                             ││
│  │                                                                      ││
│  │   3. Encrypt with AES-GCM                                           ││
│  │      ciphertext = aead.Seal(nonce, plaintext, aad)                  ││
│  │                                                                      ││
│  │   4. Format output                                                  ││
│  │      result = "vault:v3:" + base64(nonce + ciphertext + tag)        ││
│  │                                                                      ││
│  │   Output: "vault:v3:SGVsbG8gV29ybGQhIQ..."                          ││
│  └─────────────────────────────────────────────────────────────────────┘│
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 3. FPE Tokenization Flow

### FPE Encrypt (Stateless)
```
┌────────┐   ┌─────────┐   ┌──────┐   ┌──────────┐   ┌──────┐
│ Client │   │ Gateway │   │ Auth │   │ Tokenize │   │ Lock │
└───┬────┘   └────┬────┘   └──┬───┘   └────┬─────┘   └──┬───┘
    │             │           │            │            │
    │ 1. POST /tokenize/fpe/encrypt        │            │
    │   {key: "cc-key",                    │            │
    │    plaintext: "4111111111111111",    │            │
    │    transformation: "credit-card"}    │            │
    │────────────►│           │            │            │
    │             │           │            │            │
    │             │ 2. Validate token      │            │
    │             │──────────►│            │            │
    │             │◄──────────│            │            │
    │             │           │            │            │
    │             │ 3. gRPC FPEEncrypt     │            │
    │             │───────────────────────►│            │
    │             │           │            │            │
    │             │           │            │ 4. Get FPE key
    │             │           │            │   (from cache or Lock)
    │             │           │            │───────────►│
    │             │           │            │            │
    │             │           │            │ 5. Key material
    │             │           │            │◄───────────│
    │             │           │            │            │
    │             │           │            │ 6. FF1 Encrypt
    │             │           │            │   alphabet: "0123456789"
    │             │           │            │   radix: 10
    │             │           │            │            │
    │             │ 7. {ciphertext: "9284756038291847"} │
    │             │◄───────────────────────│            │
    │             │           │            │            │
    │ 8. Same format output   │            │            │
    │   "9284756038291847"    │            │            │
    │◄────────────│           │            │            │
    │             │           │            │            │
```

### FPE Algorithm Detail (FF1)
```
┌──────────────────────────────────────────────────────────────────────────┐
│                        FF1 ENCRYPTION (NIST SP 800-38G)                  │
│                                                                          │
│  Input:                                                                  │
│    plaintext = "4111111111111111"                                       │
│    key = [32 bytes AES key]                                             │
│    tweak = [optional context]                                           │
│    alphabet = "0123456789" (radix = 10)                                 │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │                    Feistel Network (10 rounds)                       ││
│  │                                                                      ││
│  │   Split: A = "41111111" (left), B = "11111111" (right)              ││
│  │                                                                      ││
│  │   For i = 0 to 9:                                                   ││
│  │     ┌─────────────────────────────────────────────────┐             ││
│  │     │  Round i:                                        │             ││
│  │     │    P = [i || tweak || radix || len || A]        │             ││
│  │     │    R = AES-CBC-MAC(key, P)                      │             ││
│  │     │    c = (num(B) + num(R)) mod radix^m            │             ││
│  │     │    C = str(c)                                    │             ││
│  │     │    B = A                                         │             ││
│  │     │    A = C                                         │             ││
│  │     └─────────────────────────────────────────────────┘             ││
│  │                                                                      ││
│  │   Result: A || B                                                    ││
│  └─────────────────────────────────────────────────────────────────────┘│
│                                                                          │
│  Output:                                                                │
│    ciphertext = "9284756038291847"                                      │
│    (same length, same character set, deterministic with same key)       │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

### Comparison: FPE vs Regular Encryption
```
┌─────────────────────────────────────────────────────────────────────────┐
│                    FPE vs REGULAR ENCRYPTION                             │
│                                                                         │
│  ┌────────────────────────────────┐  ┌────────────────────────────────┐│
│  │      Regular Encryption        │  │       FPE Encryption           ││
│  │        (AES-GCM)               │  │         (FF1)                  ││
│  ├────────────────────────────────┤  ├────────────────────────────────┤│
│  │ Input:  "4111111111111111"     │  │ Input:  "4111111111111111"     ││
│  │ Output: "vault:v1:SGVsbG8..."  │  │ Output: "9284756038291847"     ││
│  │         (variable length)      │  │         (same format!)         ││
│  │                                │  │                                ││
│  │ Storage: Needs DB for mapping  │  │ Storage: NONE (stateless)     ││
│  │ Lookup:  O(1) with DB          │  │ Lookup:  Decrypt with key      ││
│  │ Format:  Changed               │  │ Format:  Preserved            ││
│  └────────────────────────────────┘  └────────────────────────────────┘│
│                                                                         │
│  Use FPE when:                                                          │
│  - Database schema cannot change                                        │
│  - Need format validation (credit card checksum still works)            │
│  - Don't want to manage token mappings                                  │
│  - Need stateless horizontal scaling                                    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Secret Storage Flow

### Write Secret
```
┌────────┐   ┌─────────┐   ┌──────┐   ┌──────┐   ┌─────────┐
│ Client │   │ Gateway │   │ Auth │   │ Lock │   │  Raft   │
└───┬────┘   └────┬────┘   └──┬───┘   └──┬───┘   └────┬────┘
    │             │           │          │            │
    │ 1. POST /secrets/myapp/db          │            │
    │   {username: "admin",              │            │
    │    password: "secret123"}          │            │
    │────────────►│           │          │            │
    │             │           │          │            │
    │             │ 2. Validate + check policy        │
    │             │──────────►│          │            │
    │             │◄──────────│          │            │
    │             │           │          │            │
    │             │ 3. gRPC PutSecret    │            │
    │             │─────────────────────►│            │
    │             │           │          │            │
    │             │           │          │ 4. Barrier Encrypt
    │             │           │          │   (AES-GCM with keyring)
    │             │           │          │            │
    │             │           │          │ 5. Raft Propose
    │             │           │          │───────────►│
    │             │           │          │            │
    │             │           │          │            │ 6. Replicate to
    │             │           │          │            │    followers
    │             │           │          │            │    (majority ACK)
    │             │           │          │            │
    │             │           │          │ 7. Committed
    │             │           │          │◄───────────│
    │             │           │          │            │
    │             │           │          │ 8. Apply to FSM
    │             │           │          │   (BoltDB write)
    │             │           │          │            │
    │             │ 9. {version: 1, created_at: ...} │
    │             │◄─────────────────────│            │
    │             │           │          │            │
    │ 10. Success │           │          │            │
    │◄────────────│           │          │            │
    │             │           │          │            │
```

### Read Secret (with caching)
```
┌────────┐   ┌─────────┐   ┌──────┐   ┌──────┐   ┌────────┐   ┌───────┐
│ Client │   │ Gateway │   │ Auth │   │ Lock │   │ Cache  │   │ Raft  │
└───┬────┘   └────┬────┘   └──┬───┘   └──┬───┘   └───┬────┘   └───┬───┘
    │             │           │          │           │            │
    │ 1. GET /secrets/myapp/db           │           │            │
    │────────────►│           │          │           │            │
    │             │           │          │           │            │
    │             │ 2. Validate          │           │            │
    │             │──────────►│          │           │            │
    │             │◄──────────│          │           │            │
    │             │           │          │           │            │
    │             │ 3. gRPC GetSecret    │           │            │
    │             │─────────────────────►│           │            │
    │             │           │          │           │            │
    │             │           │          │ 4. Check 2Q Cache      │
    │             │           │          │──────────►│            │
    │             │           │          │           │            │
    │             │           │          │   HIT:    │            │
    │             │           │          │◄──────────│            │
    │             │           │          │   (encrypted data)     │
    │             │           │          │           │            │
    │             │           │          │   MISS:   │            │
    │             │           │          │──────────────────────►│
    │             │           │          │◄──────────────────────│
    │             │           │          │           │            │
    │             │           │          │ 5. Barrier Decrypt     │
    │             │           │          │   (AES-GCM)            │
    │             │           │          │           │            │
    │             │ 6. {data, metadata}  │           │            │
    │             │◄─────────────────────│           │            │
    │             │           │          │           │            │
    │ 7. Secret data          │          │           │            │
    │◄────────────│           │          │           │            │
    │             │           │          │           │            │
```

---

## 5. Key Rotation Flow

### Manual Key Rotation
```
┌────────┐   ┌─────────┐   ┌──────┐   ┌──────┐   ┌───────┐
│ Admin  │   │ Gateway │   │ Auth │   │ Lock │   │ Raft  │
└───┬────┘   └────┬────┘   └──┬───┘   └──┬───┘   └───┬───┘
    │             │           │          │           │
    │ 1. POST /keys/app-key/rotate       │           │
    │────────────►│           │          │           │
    │             │           │          │           │
    │             │ 2. Validate (require admin policy)│
    │             │──────────►│          │           │
    │             │◄──────────│          │           │
    │             │           │          │           │
    │             │ 3. gRPC RotateKey    │           │
    │             │─────────────────────►│           │
    │             │           │          │           │
    │             │           │          │ 4. Generate new key
    │             │           │          │    version N+1
    │             │           │          │           │
    │             │           │          │ 5. Store in Raft
    │             │           │          │──────────►│
    │             │           │          │◄──────────│
    │             │           │          │           │
    │             │           │          │ 6. Update active version
    │             │           │          │           │
    │             │ 7. {new_version: N+1}│           │
    │             │◄─────────────────────│           │
    │             │           │          │           │
    │ 8. Key rotated          │          │           │
    │◄────────────│           │          │           │
    │             │           │          │           │

Note: Old versions are kept for decryption.
      New encryptions use version N+1.
      Use Rewrap to re-encrypt old data.
```

### Key Version Management
```
┌──────────────────────────────────────────────────────────────────────────┐
│                         KEY VERSION LIFECYCLE                            │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                        Key: "app-key"                             │   │
│  │                                                                   │   │
│  │   Version 1  ──►  Version 2  ──►  Version 3 (ACTIVE)             │   │
│  │   [archived]      [archived]      [current]                       │   │
│  │                                                                   │   │
│  │   min_decryption_version = 1  (can decrypt v1, v2, v3)           │   │
│  │   min_encryption_version = 3  (new encrypts use v3 only)         │   │
│  │                                                                   │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  Encryption:                                                             │
│    plaintext ─► encrypt(key_v3) ─► "vault:v3:ciphertext..."             │
│                                                                          │
│  Decryption:                                                             │
│    "vault:v1:old_data" ─► parse version ─► decrypt(key_v1) ─► plaintext │
│    "vault:v2:data"     ─► parse version ─► decrypt(key_v2) ─► plaintext │
│    "vault:v3:new_data" ─► parse version ─► decrypt(key_v3) ─► plaintext │
│                                                                          │
│  Rewrap (re-encrypt with latest):                                        │
│    "vault:v1:old" ─► decrypt(v1) ─► encrypt(v3) ─► "vault:v3:new"       │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 6. Seal/Unseal Flow

### Initialize (First Time Setup)
```
┌────────┐   ┌──────┐   ┌─────────────────────────────────────────┐
│ Admin  │   │ Lock │   │              Seal Manager               │
└───┬────┘   └──┬───┘   └────────────────────┬────────────────────┘
    │          │                             │
    │ 1. Initialize(shares=5, threshold=3)  │
    │─────────►│                             │
    │          │                             │
    │          │ 2. Generate master key      │
    │          │   master = crypto/rand(32)  │
    │          │                             │
    │          │ 3. Shamir split             │
    │          │────────────────────────────►│
    │          │                             │
    │          │                             │ 4. Split master into
    │          │                             │    5 shares (3 required)
    │          │                             │
    │          │ 5. Shares                   │
    │          │◄────────────────────────────│
    │          │                             │
    │          │ 6. Encrypt barrier keyring  │
    │          │   with master key           │
    │          │                             │
    │          │ 7. Store encrypted keyring  │
    │          │   in Raft                   │
    │          │                             │
    │ 8. {root_token, key_shares[5]}        │
    │◄─────────│                             │
    │          │                             │

IMPORTANT: Distribute shares to different custodians!
```

### Unseal Process
```
┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────┐  ┌──────────────┐
│Custodian1│  │Custodian2│  │Custodian3│  │ Lock │  │ Seal Manager │
└────┬─────┘  └────┬─────┘  └────┬─────┘  └──┬───┘  └──────┬───────┘
     │             │             │           │             │
     │ 1. Unseal(share_1)        │           │             │
     │──────────────────────────────────────►│             │
     │             │             │           │             │
     │             │             │           │ 2. Store share
     │             │             │           │────────────►│
     │             │             │           │             │
     │ 3. {sealed: true, progress: 1/3}     │             │
     │◄──────────────────────────────────────│             │
     │             │             │           │             │
     │             │ 4. Unseal(share_2)      │             │
     │             │────────────────────────►│             │
     │             │             │           │────────────►│
     │             │             │           │             │
     │             │ 5. {sealed: true, progress: 2/3}     │
     │             │◄────────────────────────│             │
     │             │             │           │             │
     │             │             │ 6. Unseal(share_3)      │
     │             │             │──────────►│             │
     │             │             │           │────────────►│
     │             │             │           │             │
     │             │             │           │             │ 7. Threshold met!
     │             │             │           │             │    Reconstruct master
     │             │             │           │             │
     │             │             │           │ 8. Decrypt barrier
     │             │             │           │◄────────────│
     │             │             │           │             │
     │             │             │           │ 9. Load keyring
     │             │             │           │             │
     │             │             │ 10. {sealed: false}     │
     │             │             │◄──────────│             │
     │             │             │           │             │

Lock Service is now operational!
```

### Auto-Seal (KMS-based)
```
┌────────────────────────────────────────────────────────────────────────┐
│                           AUTO-SEAL FLOW                                │
│                                                                        │
│  ┌────────────────────────────────────────────────────────────────┐   │
│  │                        Startup                                  │   │
│  │                                                                 │   │
│  │   1. Lock Service starts                                       │   │
│  │   2. Read encrypted master key from storage                    │   │
│  │   3. Call KMS.Decrypt(encrypted_master)                        │   │
│  │   4. Receive decrypted master key                              │   │
│  │   5. Decrypt barrier keyring                                   │   │
│  │   6. Service is unsealed (automatic!)                          │   │
│  │                                                                 │   │
│  └────────────────────────────────────────────────────────────────┘   │
│                                                                        │
│  ┌──────┐          ┌──────┐          ┌───────────────────┐           │
│  │ Lock │─────────►│ KMS  │─────────►│ AWS KMS / GCP KMS │           │
│  │      │  Decrypt │      │  API     │ / Azure Key Vault │           │
│  │      │◄─────────│      │◄─────────│                   │           │
│  └──────┘          └──────┘          └───────────────────┘           │
│                                                                        │
│  Benefits:                                                             │
│  - No manual unseal required                                          │
│  - Master key never leaves KMS                                        │
│  - Automatic recovery after restart                                   │
│  - Audit trail in KMS                                                 │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 7. Batch Operations Flow

### Batch Encrypt
```
┌────────┐   ┌─────────┐   ┌────────┐   ┌────────────────────────────┐
│ Client │   │ Gateway │   │ Crypto │   │       Worker Pool          │
└───┬────┘   └────┬────┘   └───┬────┘   └──────────────┬─────────────┘
    │             │            │                       │
    │ 1. POST /crypto/encrypt/batch                   │
    │   {key: "app-key",                              │
    │    items: [                                     │
    │      {plaintext: "data1", ref: "1"},           │
    │      {plaintext: "data2", ref: "2"},           │
    │      {plaintext: "data3", ref: "3"},           │
    │      ... (100 items)                           │
    │    ]}                                          │
    │────────────►│            │                      │
    │             │            │                      │
    │             │ 2. gRPC EncryptBatch              │
    │             │───────────►│                      │
    │             │            │                      │
    │             │            │ 3. Get key (once)    │
    │             │            │                      │
    │             │            │ 4. Fan-out to workers│
    │             │            │─────────────────────►│
    │             │            │                      │
    │             │            │   ┌────┐ ┌────┐ ┌────┐
    │             │            │   │ W1 │ │ W2 │ │ W3 │ ...
    │             │            │   │item│ │item│ │item│
    │             │            │   │1,4 │ │2,5 │ │3,6 │
    │             │            │   └────┘ └────┘ └────┘
    │             │            │                      │
    │             │            │ 5. Fan-in results    │
    │             │            │◄─────────────────────│
    │             │            │                      │
    │             │ 6. {results: [                    │
    │             │      {ciphertext: "...", ref: "1"},
    │             │      {ciphertext: "...", ref: "2"},
    │             │      ...                         │
    │             │    ]}                            │
    │             │◄───────────│                      │
    │             │            │                      │
    │ 7. Batch response        │                      │
    │◄────────────│            │                      │
    │             │            │                      │
```

### Worker Pool Detail
```
┌──────────────────────────────────────────────────────────────────────────┐
│                            WORKER POOL                                    │
│                                                                          │
│   ┌────────────────────────────────────────────────────────────────┐    │
│   │                       Job Queue (buffered channel)              │    │
│   │   [item1] [item2] [item3] [item4] [item5] ... [item100]        │    │
│   └───────────────────────────┬────────────────────────────────────┘    │
│                               │                                          │
│           ┌───────────────────┼───────────────────┐                     │
│           ▼                   ▼                   ▼                     │
│      ┌─────────┐         ┌─────────┐         ┌─────────┐               │
│      │Worker 1 │         │Worker 2 │         │Worker N │  (200 workers)│
│      │         │         │         │         │         │               │
│      │ for job │         │ for job │         │ for job │               │
│      │   in    │         │   in    │         │   in    │               │
│      │ queue:  │         │ queue:  │         │ queue:  │               │
│      │ encrypt │         │ encrypt │         │ encrypt │               │
│      │ (job)   │         │ (job)   │         │ (job)   │               │
│      └────┬────┘         └────┬────┘         └────┬────┘               │
│           │                   │                   │                     │
│           ▼                   ▼                   ▼                     │
│      ┌─────────────────────────────────────────────────────────────┐   │
│      │                    Result Channel                            │   │
│      │   [result1] [result2] [result3] ...                         │   │
│      └─────────────────────────────────────────────────────────────┘   │
│                               │                                          │
│                               ▼                                          │
│                        Aggregate Results                                 │
│                    (maintain order by reference)                         │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘

Performance:
- 100 items with 200 workers ≈ parallel execution
- Key fetched once, shared across all workers
- ~10,000 encryptions/second per instance
```

---

## Performance Summary

```
┌───────────────────────────────────────────────────────────────────────────┐
│                      LATENCY BREAKDOWN (P99)                              │
│                                                                           │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │                    Single Encrypt Request                            │ │
│  │                                                                      │ │
│  │  Gateway    Auth       Crypto     Lock       Total                  │ │
│  │  ┌─────┐   ┌─────┐    ┌─────┐   ┌─────┐    ┌─────┐                │ │
│  │  │ 1ms │ + │ 2ms │ +  │ 5ms │ + │ 0ms │ =  │ 8ms │  (key cached) │ │
│  │  └─────┘   └─────┘    └─────┘   └─────┘    └─────┘                │ │
│  │                                                                      │ │
│  │  │ 1ms │ + │ 2ms │ +  │ 5ms │ + │10ms │ =  │18ms │  (key miss)   │ │
│  │                                                                      │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│                                                                           │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │                    Batch Encrypt (100 items)                         │ │
│  │                                                                      │ │
│  │  Single: 100 × 8ms = 800ms (sequential)                             │ │
│  │  Batch:  8ms + 5ms = 13ms  (parallel workers)                       │ │
│  │                                                                      │ │
│  │  Speedup: ~60x                                                      │ │
│  │                                                                      │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│                                                                           │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │                    Throughput per Instance                           │ │
│  │                                                                      │ │
│  │  Service      Single Ops/s    Batch Ops/s                          │ │
│  │  ───────────────────────────────────────────                        │ │
│  │  Gateway      50,000          100,000                               │ │
│  │  Auth         20,000           30,000                               │ │
│  │  Crypto       10,000          100,000 (batch)                       │ │
│  │  Tokenize     15,000          150,000 (batch)                       │ │
│  │  Lock          5,000           10,000                               │ │
│  │                                                                      │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────────────────┘
```

---

## Next: [04-IMPLEMENTATION-PLAN.md](./04-IMPLEMENTATION-PLAN.md)
