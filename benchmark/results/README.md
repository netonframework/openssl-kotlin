# Initial local sample

Host: Apple M1 Pro, macOS ARM64, OpenSSL 4.0.2 static archive with assembly, Kotlin 2.4.0
release executable, C `cc -O3`. Three ABBA groups per size/algorithm, six observations per
implementation, 10,000 warmup + 100,000 measured seal/open pairs per invocation.
This is a development workstation sample, not a controlled release performance threshold.

| Algorithm | Bytes | C median ns/byte | Kotlin median ns/byte |
|---|---:|---:|---:|
| AES128-GCM | 1200 | 0.2858 | 0.3089 |
| AES128-GCM | 16384 | 0.1312 | 0.1327 |
| AES256-GCM | 1200 | 0.3044 | 0.3363 |
| AES256-GCM | 16384 | 0.1583 | 0.1570 |
| ChaCha20-Poly1305 | 1200 | 1.0218 | 1.0448 |
| ChaCha20-Poly1305 | 16384 | 0.5877 | 0.5873 |

Raw observations: macos-arm64-initial.csv. Each timing includes encryption and decryption;
ns/byte divides elapsed time by iterations * payload bytes * 2. Near-equal or slightly lower
Kotlin medians are not evidence that the wrapper is faster than C. No allocation count was
collected. Small-packet wrapper overhead is measurable; no zero-cost/zero-allocation claim.

Binary SHA-256 values:

- C: `142823029cc0e2112bc6cfc160e312ec043514b8714523a82a3d262b3639a33f`
- Kotlin: `f198e8c279dd5c240318ed9b1af83dda48a603ee19c96051930d4a83af82340f`

Measured before a subsequent empty-key HKDF/HMAC fix; that change did not modify the measured
AEAD helper or wrapper. The benchmark intentionally exercises the safe array API, not unchecked
native pointers. Repeat on target Linux hardware before any platform performance claim.
