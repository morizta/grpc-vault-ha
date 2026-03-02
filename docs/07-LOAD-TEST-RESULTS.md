# Load Test Results — Tokenize Email FPE

**Date**: 2026-02-22
**Environment**: Baremetal (macOS, localhost)
**Endpoint**: `POST /v1/tokenize/encode`
**Mode**: Email FPE (Format-Preserving Encryption)
**Alphabet**: `abcdefghijklmnopqrstuvwxyz0123456789.@` (radix=38)
**Key Type**: AES-256-GCM
**Auth**: Disabled (`GATEWAY_AUTH_ENABLED=false`)

---

## Setup

Services running baremetal (no Docker):

```
lock-service   :9094  (BoltDB)
tokenize-service :9093 (100 workers)
gateway        :8080  (HTTP/1.1)
```

Request format:
```json
POST /v1/tokenize/encode
{
  "key_name": "email-fpe-key",
  "value": "{{RandomEmail}}",
  "alphabet": "abcdefghijklmnopqrstuvwxyz0123456789.@"
}
```

Example roundtrip:
```
Input:  alice@example.com
Token:  nbdup6on.d9xinwhm
Decode: alice@example.com  ✓
```

---

## Results

### Fixed Requests Test

| Metric | Value |
|--------|-------|
| Requests | 1,000 |
| Concurrency | 50 |
| Duration | 69ms |
| Throughput | **14,500 req/s** |
| Success Rate | 100% |
| Latency Min | 124µs |
| Latency Avg | 2.933ms |
| Latency P50 | 2.315ms |
| Latency P95 | 4.575ms |
| Latency P99 | 19.761ms |
| Latency Max | 22.573ms |

---

### Max Throughput Tests (30s Duration)

| Concurrency | Throughput | Total Requests | P50 | P95 | P99 | Max | Success |
|-------------|------------|----------------|-----|-----|-----|-----|---------|
| 100 | **45,878 req/s** | 1,376,534 | 1.76ms | 4.93ms | 7.25ms | 24.85ms | 100% |
| 500 | **51,535 req/s** | 1,546,652 | 7.50ms | 23.18ms | 33.21ms | 88.88ms | 100% |

---

## Analysis

### Sweet Spot: Concurrency 100

- Throughput hampir sama dengan concurrency 500 (45K vs 51K, selisih ~12%)
- Latency jauh lebih rendah: P50 1.76ms vs 7.5ms (4x lebih baik)
- P99 7.25ms vs 33.2ms (4.5x lebih baik)
- Recommended untuk production: **concurrency 100**

### Bottleneck

Dari concurrency 100 → 500, throughput hanya naik 12% tapi latency naik 4x.
Ini menunjukkan bottleneck sudah di **CPU / goroutine context switching**, bukan di kapasitas service.

Faktor penentu throughput:
1. FF1 cipher creation per request (no cipher caching, by design)
2. gRPC round-trip gateway → tokenize → lock (key lookup LRU cached setelah request pertama)
3. HTTP/1.1 connection pool (MaxIdleConnsPerHost = concurrency)

---

## Bug Fixes Applied

### 1. `pkg/crypto/fpe/ff1.go` — Custom Alphabet Encoding

Library `capitalone/fpe` v1.2.1 menggunakan `big.Int.SetString(X, radix)` secara internal.
Akibatnya custom alphabet (radix > 10) gagal dengan error `"string is not within base/radix"`.

**Fix**: Tambah `alphabetToNumeralStr()` / `numeralStrToAlphabet()` untuk konversi
index alphabet ke digit char yang big.Int kenali (0-9 → '0'-'9', 10-35 → 'a'-'z', 36-61 → 'A'-'Z').

Backward compatible: untuk `AlphabetNumeric` (radix=10), hasil identik dengan sebelumnya.

### 2. `services/gateway/internal/handler/gateway_handler.go` — Missing `alphabet` Field

`TokenizeRequest` dan `DetokenizeRequest` tidak expose field `alphabet` dari proto definition.

**Fix**: Tambah `Alphabet string` di kedua struct dan forward ke gRPC call.

---

## Load Test Command

```bash
cd load-test

# Fixed requests
./loadtest \
  -url "http://localhost:8080/v1/tokenize/encode" \
  -body '{"key_name":"email-fpe-key","value":"{{.RandomEmail}}","alphabet":"abcdefghijklmnopqrstuvwxyz0123456789.@"}' \
  -success-field "token" \
  -requests 1000 \
  -concurrency 50

# Max throughput (30s)
./loadtest \
  -url "http://localhost:8080/v1/tokenize/encode" \
  -body '{"key_name":"email-fpe-key","value":"{{.RandomEmail}}","alphabet":"abcdefghijklmnopqrstuvwxyz0123456789.@"}' \
  -success-field "token" \
  -duration 30s \
  -concurrency 100
```
