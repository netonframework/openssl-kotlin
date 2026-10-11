# OpenSSL Kotlin 4.x binding contract

Status: initial binding implemented; cross-platform runtime release gates remain open.
Not a production TLS adapter. See VALIDATION.md for executed tests versus cross-link checks.

1. `com.netonstream:openssl` is an independent dependency, native and (since 2026-10-11, docs/JVM.md) JVM through JNI
   over the same static OpenSSL. neton-io core remains independent.
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

## Facade increment (included in first release 4.0.2)

docs/SAFE_API.md defines the target contract and additional missing gates; README's capability
table is authoritative for implemented versus deferred functionality. No entire-roadmap completion
claim. QUIC's transport, crypto-secret delivery lifetime and 0-RTT replay policy must not be
collapsed into the TLS byte-stream API. OpenSSL's third-party QUIC TLS raw functions remain
available but their safe facade is not implemented by this increment.

## JVM, phase 1 (2026-10-11)

docs/JVM.md is the plan. Phase 1 done:
- The facade's platform-independent part (`AeadKey`, `HeaderProtectionKey`, `Crypto`, `OpenSsl`, argument checks,
  error collection) moved to commonMain; the primitives behind it are `internal expect object Primitives` with long
  handles: cinterop on native (unchanged C shim), JNI on the JVM (`src/jvmNative/neton_openssl_jni.c`, 17 entry
  points that pin arrays only for the call and call the same `neton_*` shim functions).
- `scripts/build-jni.sh` links the JNI library against the host target's static OpenSSL, exporting only `Java_*`
  (macOS: exported-symbol list; Linux: version script, Kotlin/Native toolchain and sysroot for the same libc baseline).
  OpenSSL is now built with `-fPIC` on every target so its archives can link into the shared library.
- The jar carries `META-INF/native/<os>-<arch>/`; `NativeLibrary` loads `neton.openssl.library` if set, the app's own
  library on Android, otherwise the jar's copy for this platform; a missing one is an `UnsatisfiedLinkError` naming it.
- Tests: `CryptoTest` and the runtime checks (`OpenSslRuntimeTest`) are in commonTest and run on both. macOS arm64:
  JVM 10, native 26 tests, no failures. Before Gradle, a javac smoke test checked the JNI layer against RFC 4231, RFC
  5869 and RFC 9001 A.2 vectors. CI runs `jvmTest` on macOS and Linux x64 hosts.

## JVM, phase 2 (2026-10-11)

- `TlsContext` / `TlsEngine` moved to commonMain unchanged in API and behaviour, over `internal expect object
  TlsPrimitives` (context and engine as long handles). The shim gained functions for what Kotlin used to read from the
  `neton_tls` struct or from OpenSSL macros (failed, pending write, verify and alert codes, the failure kind in
  `TlsFailureKind` order, version and cipher names, the verify mode, cipher and default-path settings), so native and
  JVM classify failures with the same C code. JNI: 33 more entry points (50 in all); strings are taken before any
  array is pinned.
- Tests: `TlsEngineTest` is in commonTest over fixed certificates (`TestIdentities.kt`: three valid until 2125, one
  expired in 2021, generated once with the OpenSSL command line; the JVM cannot generate certificates), replacing the
  C-API generator; the native-Worker sharing test stays native (`TlsWorkerTest`). macOS arm64: JVM 16, native 26
  tests, no failures — on the JVM: TLS 1.2 and 1.3 fragmented handshakes, ALPN, exporter, write backpressure and
  retry, the five typed failures, mutual TLS, close_notify versus truncation, invalid configuration and bounds.

## JVM, phase 3: QUIC TLS facade (2026-10-11)

docs/QUIC_TLS.md is the design. Gates 1 and 2 done:
- `neton_quic_tls.h`: OpenSSL's third-party QUIC TLS callbacks in C (CRYPTO send / receive / release, secrets,
  transport parameters, alerts) and the context callbacks (ALPN selection with server preference, the ClientHello
  ALPN check, key log, new-session tickets), queueing per connection what quic's `TlsCore` kept in Kotlin, with the
  same limits (64 KiB incoming, one outstanding record of at most 16384 bytes, 1 MiB outgoing), the first failure
  kept, the key-change check and a test hook to fail a named callback once (a failing ticket callback only drops the
  ticket). Contexts: TLS 1.3 only, no compression, suites, groups, verify mode, DER anchors, DER chain with a PEM or
  DER key, session cache settings per side, session ID context on servers.
- `QuicTlsContext` / `QuicTls` (commonMain) over `internal expect object QuicTlsPrimitives`; JNI: 34 more entry points
  (84 in all).
- `QuicTlsTest` (commonTest, 9 tests): a handshake with equal secrets per level and direction, exchanged transport
  parameters, ALPN, SNI, peer certificate and exporter; a ticket resuming with 0-RTT accepted and equal early secrets;
  no common ALPN (alert 120); an untrusted server; data after a key change (OpenSSL's alert 10 when it is in the same
  record, the facade's own check otherwise); the 64 KiB bound; an injected callback failure; a failing ticket callback;
  key-log lines. macOS arm64: JVM 25, native 35 tests, no failures.
- Next (gate 3): quic's native `TlsSession` / `TlsConfig` move onto the facade with no behaviour change.
- Gate 3 (2026-10-11): quic's `TlsSession` / `TlsConfig` / system-root parsing rewritten on the facade (quic branch
  `tls-facade`, waiting for this library's release since quic's Windows CI cannot build OpenSSL from source): its full
  suite passes on macOS arm64 with the test TLS double and with real TLS (624 tests each, 3 skipped as in quinn). Found
  on the way: our transport parameters can be empty (all defaults), which the connection creation refused (fixed,
  `emptyTransportParametersAreAllowed`). quic's record-lifetime test moved here with the callbacks
  (`QuicTlsCallbacksTest`, on the C functions). `OpenSsl.takeErrors` / `clearErrors` give protocol libraries the
  thread's error queue.

## JVM, Android (2026-10-11)

- `scripts/build-jni.sh` builds the JNI library for Android with the NDK's clang (API 21): only the `Java_*` entry
  points exported, NEEDED only libc and libdl, 16 KiB page alignment (Android 15+), stripped (5.7 MB for arm64-v8a).
  `androidNativesAar` packs it as `openssl-android-natives` (`jni/<abi>/`, a manifest with minSdk 26, the license
  files); on Android `NativeLibrary` loads it with `System.loadLibrary`.
- Verified on the Pixel_9 emulator (Android 16, arm64-v8a, ART) without an app: msgtrans-kotlin's
  `interop/android-smoke.sh` converts msgtrans-quic's JVM classes to dex and runs them with app_process next to the
  library — a QUIC handshake (real TLS 1.3 through this library, UDP through Android's NIO) in 67-156 ms, echoes of
  0 B to 1 MB and 100 concurrent requests, all matching.
- x86_64 (emulators on Intel hosts): NDK 26.1's clang does not know OpenSSL 4.0's SM4 AVX instructions (`vsm4key4`),
  so OpenSSL itself does not build for it with that NDK (the native androidNativeX64 target has the same limit); NDK
  29 is the candidate. 32-bit ABIs are not supported (as for the native targets).

