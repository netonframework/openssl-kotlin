# OpenSSL Kotlin 4.x binding contract

Status: initial binding implemented; cross-platform runtime release gates remain open.
Not a production TLS adapter. See VALIDATION.md for executed tests versus cross-link checks.

1. `com.netonstream:openssl` is an independent native dependency. neton-io core remains independent.
2. Initial upstream version is exactly 4.0.2. Source SHA-256 is pinned in gradle.properties and
   verified before extraction, including cached archives. Support starts at the 4.0 line.
3. Build libcrypto and libssl statically, with assembly enabled, no loadable modules and no legacy
   provider. No FIPS certification claim. No fallback to a host/system OpenSSL installation.
4. Raw bindings expose OpenSSL ownership rules unchanged. They are experimental C interop API.
   The safe facade owns explicit closeable contexts; ownership, concurrency, buffer and failure
   contracts are in docs/SAFE_API.md. Error details are drained on the calling thread. No socket,
   protocol scheduling, trust-store discovery or business policy is hidden in this facade.
5. A release must test version/header agreement, known crypto vectors, CSPRNG error handling,
   real TLS 1.3 handshakes, trust/hostname rejection, application data and resource teardown.
6. Third-party QUIC TLS entry points must compile/link. Full QUIC handshake interoperability is
   an explicit later gate for the QUIC adapter; rejection smoke tests alone do not satisfy it.
7. Each target uses its own OpenSSL source/output tree. Headers and archives must come from that
   same target/version. Concurrent builds of the same target in separate Gradle invocations are
   not supported; separate checkouts/build directories are required.
8. `4.x.y-N` records upstream and wrapper revisions. Upgrade 4.1.x only after API/ABI review,
   target matrix and negative certificate tests. No compatibility promise across OpenSSL majors.
9. CI distinguishes execution tests from cross-link checks. Publication is blocked until all
   advertised targets pass their documented gates and root metadata includes the full matrix.
10. Performance must be measured against direct C calls using the same build/algorithm/buffers.
    This binding makes no claim that OpenSSL 4.x or Kotlin interop improves throughput by itself.

## Facade increment 4.0.2-2

docs/SAFE_API.md defines the target contract and additional missing gates; README's capability
table is authoritative for implemented versus deferred functionality. No entire-roadmap completion
claim. QUIC's transport, crypto-secret delivery lifetime and 0-RTT replay policy must not be
collapsed into the TLS byte-stream API. OpenSSL's third-party QUIC TLS raw functions remain
available but their safe facade is not implemented by this increment.
