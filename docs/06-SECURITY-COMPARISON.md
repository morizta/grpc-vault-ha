# 06 - Security Comparison: HashiCorp Vault vs Microservice-Vault

Dokumen ini membandingkan bagaimana **HashiCorp Vault** menyimpan dan melindungi data vs implementasi **Microservice-Vault** kita. Tujuannya adalah mengidentifikasi gap keamanan dan menjadi roadmap untuk meningkatkan keamanan sistem.

---

## 1. Arsitektur Storage

### HashiCorp Vault — 4 Layer Security

```
Layer 4 (Logical):
  [KV Engine] [TokenStore] [Userpass Auth] [Transit] [PKI] ...
       │            │              │            │        │

Layer 3 (Isolation):
  [BarrierView]  [BarrierView]  [BarrierView]  [BarrierView] ...
  prefix: logical/ prefix: sys/  prefix: auth/  prefix: transit/
       │            │              │            │
       └───────┬────┴─────────┬───┘────────────┘

Layer 2 (Encryption):
  [SecurityBarrier / AESGCMBarrier]
   - AES-256-GCM dengan 12-byte random nonce
   - 4-byte term prefix untuk key versioning
   - Path sebagai AAD (Additional Authenticated Data)
   - Keyring dengan root key + per-term encryption keys
   - Tracking jumlah enkripsi per NIST guidelines
       │

Layer 1 (Storage):
  [Physical Backend] (untrusted)
   - Consul, Raft, File, S3, DynamoDB, dll.
   - Hanya menyimpan ciphertext (opaque blobs)
   - HA via HABackend/FencingHABackend
   - Transactional support dengan rollback
       │
  [Disk / Network] (untrusted)
```

### Microservice-Vault — 1 Layer (Flat)

```
  [LockService]                       [AuthService]
    │         │        │               │     │     │     │
    ▼         ▼        ▼               ▼     ▼     ▼     ▼
  secrets  seal_state  keyring      tokens apikeys policies credentials
    │         │        │               │     │     │     │
    └────┬────┴───┬────┘──────┬────────┘─────┘─────┘─────┘
         │                    │
  [BoltDB lock.db]     [BoltDB auth.db]
   Plaintext JSON       Plaintext JSON
         │                    │
  [Disk]  ← semua data bisa dibaca langsung
```

### Tabel Perbandingan

| Aspek | HashiCorp Vault | Microservice-Vault |
|---|---|---|
| Interface | Abstract `Backend` interface (pluggable) | Concrete `BoltStore` struct (hardcoded) |
| Storage engines | Consul, Raft, File, S3, DynamoDB, in-mem, dll. | BoltDB only |
| Data unit | `physical.Entry{Key, Value, SealWrap, ValueHash}` | JSON blobs di BoltDB buckets |
| Data on disk | **Selalu encrypted ciphertext** | **Plaintext JSON** |
| Key namespace | Hierarchical `/`-delimited paths dengan prefix views | Flat per-bucket keys |
| Path traversal protection | `sanityCheck` mencegah `..` paths | Tidak ada |
| HA support | `HABackend`, `FencingHABackend` | Tidak ada |
| Transactions | `TransactionalBackend` dengan LIFO rollback | BoltDB single-transaction only |
| Concurrency control | `PermitPool` (128 parallel ops) | BoltDB internal file locking |
| Backend swappability | Ya, via `Factory` function | Tidak |

---

## 2. Encryption Barrier (Enkripsi at Rest)

Ini adalah **perbedaan paling fundamental** antara Vault dan implementasi kita.

### Vault: AESGCMBarrier

Vault menggunakan `AESGCMBarrier` yang membungkus physical backend. **Setiap data** yang ditulis ke storage melewati proses enkripsi:

**Write path:**
1. Ambil active term dan AEAD cipher dari keyring
2. Generate 12-byte random nonce
3. Encrypt dengan AES-256-GCM
4. Wire format: `[4B term][1B version][12B nonce][ciphertext + 16B auth tag]`
5. Untuk Version 2: path digunakan sebagai AAD (mencegah ciphertext relocation attack)
6. Simpan encrypted blob ke physical backend

**Read path:**
1. Baca ciphertext dari physical backend
2. Extract 4-byte term → dapatkan cipher untuk term tersebut
3. Extract nonce → decrypt dengan GCM
4. Verifikasi AAD (path) → return plaintext

**Key hierarchy:**
```
Root Key (master key)
  └─→ encrypts Keyring at "core/keyring"
       └─→ contains per-term encryption keys
            └─→ Term Key (active) encrypts all new data
            └─→ Term Key (old) decrypts legacy data
```

**Proteksi tambahan:**
- Max 3,865,470,566 operasi per key (NIST limit)
- Min 24 jam rotation interval
- AEAD caching (`map[uint32]cipher.AEAD`) untuk performa
- `memzero()` pada key buffers saat seal

### Microservice-Vault: Tidak Ada Barrier

`LockService.PutSecret()` menulis langsung ke BoltDB tanpa enkripsi:

```go
secret := &repository.Secret{Data: data, Version: version, ...}
s.secretRepo.Put(ctx, path, secret)  // → JSON marshal → BoltDB
```

Field `barrierKey` ada di struct tapi **tidak pernah digunakan** untuk enkripsi.

### Tabel Perbandingan

| Aspek | HashiCorp Vault | Microservice-Vault |
|---|---|---|
| Algorithm | AES-256-GCM (256-bit key, 12-byte nonce) | **Tidak ada** |
| Data at rest | Selalu encrypted | **Plaintext JSON** |
| Wire format | `[4B term][1B version][12B nonce][ciphertext+tag]` | N/A |
| AAD (path binding) | Ya — path sebagai AAD di Version 2 | N/A |
| Key rotation | Term-based, old keys retained | N/A |
| Max ops per key | 3.8B (NIST-based) | N/A |
| AEAD caching | `map[uint32]cipher.AEAD` | N/A |
| Memory wiping | `memzero()` pada seal | `Keyring.Seal()` zeros key bytes |

---

## 3. Seal/Unseal State

### Vault

| Storage Path | Isi | Encrypted? | Tujuan |
|---|---|---|---|
| `core/seal-config` | `SealConfig` JSON (N, T, Type) | Tidak (harus bisa dibaca saat sealed) | Tahu berapa shares dibutuhkan |
| `core/keyring` | Serialized keyring | **Ya** (encrypted by root key) | Semua term keys + rotation config |
| `core/master` | Root key | **Ya** (encrypted by active term key) | Standby nodes |
| `core/shamir-kek` | Copy unseal key | **Ya** (inside barrier) | Raft snapshot restore |

**Kunci keamanan:**
- Master key **TIDAK PERNAH** disimpan plaintext di disk
- Shamir shares **TIDAK PERNAH** disimpan di disk (dibagikan ke operator)
- Shamir implementation: production-grade polynomial-based (`vault/shamir` package)
- Key comparison: `crypto/subtle.ConstantTimeCompare`
- Seal config validation: comprehensive (`Validate()` method)

### Microservice-Vault

`SealState` struct disimpan **seluruhnya dalam plaintext** di BoltDB:

```go
type SealState struct {
    MasterKey   []byte   `json:"master_key"`     // ← PLAINTEXT
    BarrierKey  []byte   `json:"barrier_key"`    // ← PLAINTEXT
    ShamirKeys  [][]byte `json:"shamir_keys"`    // ← SEMUA SHARES TERSIMPAN
    Threshold   int      `json:"threshold"`
    Initialized bool     `json:"initialized"`
}
```

**Shamir implementation adalah stub:**

```go
func shamirSplit(secret []byte, shares, threshold int) ([][]byte, error) {
    // TODO: Implement proper Shamir's Secret Sharing
    // Hanya copy secret ke setiap share (TIDAK AMAN)
    result := make([][]byte, shares)
    for i := 0; i < shares; i++ {
        result[i] = make([]byte, len(secret)+1)
        result[i][0] = byte(i + 1)
        copy(result[i][1:], secret)
    }
    return result, nil
}
```

### Tabel Perbandingan

| Aspek | HashiCorp Vault | Microservice-Vault |
|---|---|---|
| Master key on disk | **TIDAK PERNAH** plaintext | **Plaintext JSON** |
| Shamir shares on disk | **TIDAK PERNAH** (dibagi ke operator) | **Semua shares tersimpan** |
| Shamir implementation | Production polynomial-based | **Stub** (copy secret) |
| Keyring on disk | Encrypted dengan root key | **Plaintext JSON** |
| Key comparison | `crypto/subtle.ConstantTimeCompare` | Non-constant-time loop |
| Seal types | Shamir, AWS KMS, Transit, PKCS11, GCP CKMS | Shamir stub only |
| Auto-unseal (HSM/KMS) | Ya | Tidak |
| Rekey support | Ya, dengan verification | Tidak |
| Seal config validation | Comprehensive `Validate()` | Tidak ada |

---

## 4. Token Storage

### Vault

- Token ID di-salt menggunakan **HMAC-SHA256** sebelum disimpan
- Disimpan di `BarrierView` (encrypted) dengan prefix `id/<saltedID>`
- Accessor index terpisah di prefix `accessor/`
- Parent-child tree di prefix `parent/` untuk cascading revocation
- Root tokens mendapat `SealWrap = true` (extra protection)
- Batch tokens (JWT-like) **tidak pernah disimpan** ke disk
- `ExpirationManager` untuk lease tracking

### Microservice-Vault

- Token ID disimpan **apa adanya** (raw) sebagai key di BoltDB bucket `tokens`
- Tidak ada salting, tidak ada accessor index
- Soft delete (set `RevokedAt`) bukan hard delete
- Expiry check via full bucket scan

### Tabel Perbandingan

| Aspek | HashiCorp Vault | Microservice-Vault |
|---|---|---|
| Storage key | HMAC-SHA256 salted token ID | Raw token ID (plaintext) |
| On disk | Encrypted via barrier | Plaintext JSON |
| Token ID format | `hvs.` + 24-char base62 | Opaque string |
| ID salting | Ya (HMAC-SHA256 per namespace) | Tidak |
| Accessor index | Ya (separate BarrierView) | Tidak |
| Parent-child tree | Ya (cascading revocation) | Tidak ada hierarchy |
| Revocation | Hard delete (primary + indices + cubbyhole + leases) | Soft delete (`RevokedAt`) |
| SealWrap root tokens | Ya | Tidak |
| Expiry management | `ExpirationManager` | Manual full-scan |
| Use-count limiting | `NumUses` with decrement | Tidak |

---

## 5. Secret Storage (KV)

### Vault

KV engine menyimpan data melalui `logical.Storage` → `BarrierView` → `SecurityBarrier`. Data **otomatis terenkripsi** — KV engine sendiri tidak pernah handle enkripsi.

- KV v2 mendukung full version history
- Metadata terpisah dari data
- Soft delete vs destroy distinction
- Path isolation via `BarrierView` per mount
- Dynamic mount table dengan UUIDs

### Microservice-Vault

Secret disimpan di BoltDB bucket `secrets`, keyed by path, JSON tanpa enkripsi.

- Version counter increment tapi **overwrite in place** (tidak ada history)
- Single bucket, tidak ada isolation
- Listing via full bucket scan dengan string prefix

### Tabel Perbandingan

| Aspek | HashiCorp Vault | Microservice-Vault |
|---|---|---|
| Encryption | Otomatis via barrier | **Tidak ada** |
| Versioning | Full version history (KV v2) | Counter only, overwrite |
| Soft delete | `destroy` vs `delete` distinction | Tidak |
| Path isolation | BarrierView per mount | Single bucket |
| Listing | Prefix-based via barrier | Full bucket scan |
| Secret engine plugins | Pluggable | Hardcoded |

---

## 6. Auth Credentials (Userpass)

### Vault

- Disimpan di `BarrierView` (encrypted) at `user/<lowercase_username>`
- bcrypt password hashing
- **Timing attack protection**: menggunakan fake bcrypt hash untuk user yang tidak ada, mencegah user enumeration
- CIDR binding support
- Full `TokenParams` (TTL, MaxTTL, Period, Type, BoundCIDRs, NumUses)

### Microservice-Vault

- BoltDB bucket `credentials`, keyed by `username`, plaintext JSON
- bcrypt password hashing (sama dengan Vault)
- Tidak ada timing attack protection
- Policies only (tidak ada TTL/CIDR)

### Tabel Perbandingan

| Aspek | HashiCorp Vault | Microservice-Vault |
|---|---|---|
| Password hash | bcrypt | bcrypt (sama) |
| Storage | Encrypted via barrier | Plaintext JSON |
| Timing attack protection | Fake bcrypt hash | **Tidak ada** |
| CIDR binding | Ya | Tidak |
| Token parameters | Full (TTL, MaxTTL, Period, etc.) | Policies only |

---

## 7. Gap Analysis & Roadmap

### Critical (Harus diperbaiki sebelum production)

| # | Gap | Deskripsi | Effort |
|---|---|---|---|
| 1 | **AES-256-GCM Barrier** | Semua data plaintext di disk. Perlu encryption layer antara service dan BoltDB | High |
| 2 | **Seal state plaintext** | Master key, barrier key, dan semua Shamir shares tersimpan plaintext. Perlu: (a) TIDAK simpan shares, (b) encrypt keyring dengan root key | High |
| 3 | **Shamir stub** | `shamirSplit()` hanya copy secret. Perlu implementasi polynomial-based (Lagrange interpolation over GF(256)) | Medium |
| 4 | **Keyring plaintext** | Raw AES key material dari transit keys tersimpan tanpa enkripsi | High (solved by #1) |

### High Priority

| # | Gap | Deskripsi | Effort |
|---|---|---|---|
| 5 | **Non-constant-time key comparison** | `bytesEqual()` rentan timing side-channel. Ganti dengan `crypto/subtle.ConstantTimeCompare` | Low |
| 6 | **No token ID salting** | Token ID bisa dikorelasikan dari disk access. Perlu HMAC-SHA256 salt | Medium |
| 7 | **No AAD on encryption** | Jika barrier ditambahkan tanpa AAD, ciphertext relocation attack possible | Low (part of #1) |

### Medium Priority

| # | Gap | Deskripsi | Effort |
|---|---|---|---|
| 8 | **No timing protection on login** | User enumeration via timing. Perlu fake bcrypt hash untuk unknown users | Low |
| 9 | **No storage abstraction** | Hardcoded BoltDB. Perlu abstract `Backend` interface | Medium |
| 10 | **No rekey support** | Tidak bisa ganti master key atau parameter Shamir setelah init | Medium |
| 11 | **No HA/clustering** | Tidak ada leader election, fencing, standby | High |

### Low Priority

| # | Gap | Deskripsi | Effort |
|---|---|---|---|
| 12 | **No version history** | Secrets overwrite, tidak ada history | Medium |
| 13 | **Barrier key unused** | Field `barrierKey` di-generate tapi tidak dipakai | Low (part of #1) |
| 14 | **No path traversal protection** | Tidak ada `sanityCheck` untuk `..` paths | Low |

---

## 8. Rekomendasi Implementasi Barrier

Jika ingin menambahkan encryption barrier, berikut pendekatan yang direkomendasikan:

### Desain

```
pkg/barrier/
├── barrier.go          # Interface: Put, Get, Delete, List
├── aes_gcm_barrier.go  # AES-256-GCM implementation
└── keyring.go          # Term-based key management (reuse existing)
```

### Wire Format (sama dengan Vault)

```
Byte 0-3:  Key term (uint32, big-endian)
Byte 4:    Version (0x02)
Byte 5-16: Nonce (12 bytes, random)
Byte 17+:  AES-256-GCM ciphertext + 16-byte auth tag
```

### Integration Points

1. **Lock service**: Barrier wraps BoltDB repository. `PutSecret()` → encrypt → `repo.Put()`
2. **Auth service**: Barrier wraps BoltDB repository. Same pattern.
3. **Seal state**: Keyring encrypted with root key → stored via barrier. Master key + shares **TIDAK disimpan** ke disk.
4. **Unseal flow**: Reconstruct root key dari Shamir → decrypt keyring → install barrier → service operational.

### Perkiraan Impact ke Performance

Berdasarkan load test saat ini (tanpa barrier):
- Encrypt: ~45,800 req/s
- Tokenize: ~47,000 req/s
- Secret Read: ~43,800 req/s

AES-256-GCM overhead sekitar ~0.5-1μs per operasi. Dengan barrier, expected degradasi < 5% karena bottleneck ada di network/gRPC, bukan CPU crypto.

---

## 9. Load Test Results (Current, tanpa Barrier)

| Endpoint | Throughput | Latency P50 | Latency P99 | Success Rate |
|---|---|---|---|---|
| Encrypt (AES-256-GCM) | 45,884 req/s | 8.1ms | 41.2ms | 100% |
| Tokenize (FPE-FF1) | 47,025 req/s | 8.2ms | 36.9ms | 100% |
| Secret Read (BoltDB) | 43,846 req/s | 8.6ms | 44.3ms | 100% |

**Konfigurasi**: 500 concurrency, 30s duration, single instance, localhost.

---

*Dokumen ini dibuat berdasarkan analisis source code HashiCorp Vault (commit terbaru di repo lokal) dan microservice-vault. Terakhir diperbarui: Februari 2026.*


