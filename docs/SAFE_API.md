# Safe OpenSSL facade

Status: staged implementation; see the capability table in README for delivered scope.
This document supersedes SPEC item 4's initial array-only scope.

## Boundary

This library owns OpenSSL contexts, cryptographic operations and TLS state only. It owns no
socket, coroutine, executor, clock, transport retransmission, HTTP routing, QUIC packet numbering,
congestion control, session cache, application authorization or automatic filesystem discovery.
No neton-io dependency. Do not expose a production certificate-verification bypass.

## Ownership and safety

- Explicit, idempotent close. Native state is not reclaimed by GC finalizers. Use try/finally.
- A mutable native handle permits one operation at a time, including close. Concurrent/reentrant
  use is rejected, not silently serialized; sequential transfer between threads is allowed.
- A frozen TlsContext factory permits overlapping creation operations, using a reader-count
  gate. Closing with an active creator is rejected; existing engines retain OpenSSL references.
- Array APIs validate offset, length and output capacity before calling C. Native-pointer APIs,
  if introduced, must be separate and explicitly unsafe; not disguised as safe arrays.
- No caller buffer is retained after a synchronous crypto call. Keys remain in OpenSSL contexts
  until close; callers own and must erase their original key arrays. Cleansing is best effort
  and does not erase historical GC copies or swap. Native scratch is cleansed explicitly.
- OpenSSL errors are drained on the same thread as the failed call. SSL_get_error immediately
  follows its corresponding SSL operation, before any other OpenSSL call.
- Authenticate before consuming decrypted bytes. In-place AEAD failure destroys tentative
  plaintext; failed output is not usable. Nonce uniqueness, key usage limits and key rotation
  are caller responsibilities, documented rather than falsely enforced by a stateless API.

## Cryptographic primitives

Deliver reusable AES-128/256-GCM and ChaCha20-Poly1305 keys (12-byte nonce, 16-byte tag),
AES-128/256 and ChaCha20 header protection, HKDF Extract/Expand and TLS 1.3 Expand-Label,
HMAC-SHA256/384, SHA-1/256/384/512, constant-time equal-length comparison and randomFill.
SHA-1 is for protocol compatibility, not new signatures/password storage.
HKDF output is limited to 255 digest blocks; TLS label/context lengths follow RFC 8446.
Protocol salts, labels, nonce derivation, AEAD usage limits and replay policy belong upstream.
Keys/contexts are allocated at construction; per-operation arrays belong to the caller.
Do not claim zero Kotlin/native allocation until measured, including first use and error paths.

## TLS engine

Expose a bounded BIO-pair engine: feed/drain ciphertext, handshake, read/write plaintext,
send close_notify, report transport EOF. No implicit I/O or internal unbounded event queues.
NeedRead/NeedWrite are progress states, not exceptions. Always drain pending ciphertext,
including alerts, even when handshake fails or needs input. Do not spin on zero progress.
Retry SSL_write with the same bytes/length after WANT_READ/WANT_WRITE; canceling that write
requires closing the engine. Buffers are borrowed only during a call; a bounded native copy
preserves retry ownership. Backpressure is independent from handshake completion.

Client identity is mandatory (DNS or IP), independent of optional DNS SNI. Trust is explicitly
provided as roots or an explicitly requested OpenSSL default trust-path policy. A default path
is NOT the OS trust store. Server client authentication is None/Request/Require with roots.
TLS versions, TLS1.2 cipher list, TLS1.3 ciphersuites, groups, ALPN and certificate/key loading
are configuration, frozen when the context is constructed. Context close must not invalidate
existing engines. C callback data remains owned until the last engine closes.

Mandatory TLS tests: TLS1.2/1.3, trusted/unknown/expired/wrong identity, IP SAN, mTLS,
ALPN selection and mismatch, fragmented BIO input/output, write retry/backpressure, close_notify,
bare EOF, double-close/use-after-close, failed construction, context closed before engine.

## Follow-on capability gates

- Session tickets/resumption: explicit owned/serialized sessions, TLS1.3 post-handshake tickets,
  expiry, ownership and failed-resumption fallback tests. No cache/rotation policy in this library.
  Until those gates pass, the safe context disables its session cache and server ticket issuance.
- Exporter: separate absent versus empty context, output length bounds, equal peers and unique
  labels tests. No application authentication policy.
- Certificates: PEM chains and keys, DER, encrypted-key password callback lifetime, key mismatch,
  size/depth limits, peer DER chain copies, signature policy, optional OCSP status exposure.
  Certificate generation is a separate testkit, never automatic production trust.
- SNI selection: immutable contexts/table first; any user callback must catch ALL exceptions at
  the C boundary, save failure and report after return. StableRef lives through SSL_free.
- Platform roots: optional provider module and explicit failure when unavailable. Apple SecTrust
  policy cannot be reproduced just by copying roots. Android system/user policy varies with API,
  app Network Security Config and root-store updates; no fixed-path-only security claim.
- QUIC TLS: Initial/Handshake/Application CRYPTO levels plus Early secrets (no Early CRYPTO),
  buffer retained through crypto_release_rcd, bounded feeds/events, partial consumption,
  transport-parameter lifetime, alert codes, post-handshake processing and exporter. No packets,
  offsets/reassembly, packet-number spaces or key-update policy. OpenSSL and quinn real handshake
  interop is required before claiming ready. Raw symbol smoke tests are insufficient.
- 0-RTT: disabled by default; setting max_early_data does not provide replay protection. Explicit
  upper-layer opt-in, acceptance/rejection and replay-policy integration tests are mandatory.
- Provider/property queries and FIPS are separate configuration, not a certification claim.
- Future secret-buffer ownership, private-DRBG selection, certificate revocation information,
  signature/verification and key import/export should expose OpenSSL capabilities without inventing
  authorization or PKI policy. No promise of erasing all managed-memory copies or automatic OCSP.
- Android32/x86: not currently advertised; add only with toolchain + link + runtime gates.

## Validation and delivery

Known vectors first; mutation/bounds/use-after-close tests; then real bounded TLS pump tests.
Linux runtime is a release gate; cross-linking is not execution. Existing MavenLocal/composite
consumption stays available. Benchmark 1200/16384-byte AEAD versus direct C with identical keys,
algorithms and compiler flags, report throughput and allocations separately. No throughput promise.
Update the implemented/deferred capability matrix on every increment, never mark this whole
document implemented because a subset passed.
