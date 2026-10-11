# JVM support (plan, 2026-10-11)

Goal: the same OpenSSL 4.0.2 on the JVM (desktop and Android apps), so that `com.netonstream:quic`, and through it
`msgtrans-quic`, run on the JVM with real TLS 1.3, not a second TLS implementation. Kotlin/Native keeps its cinterop
binding unchanged.

## Constraints

- Same pinned upstream source (gradle.properties SHA-256), same configure options as the native build (static
  libcrypto + libssl, no modules, no legacy provider). No system OpenSSL, no Conscrypt / BoringSSL, no JDK TLS.
- JNI, not the Foreign Function & Memory API: Android has no FFM. One small C library per platform: OpenSSL linked
  statically, the existing header-only shim (`neton_tls.h`, `neton_crypto.h`) included as is, plus JNI entry points.
  Native and JVM therefore run the same C code.
- JVM bytecode 1.8, Kotlin API 2.2, stdlib 2.2.21 (Android hosts on Kotlin 2.1; same rule as neton-io's JVM target).
- No Kotlin exception crosses a C callback; no C callback calls back into the JVM while OpenSSL holds a lock it
  needs again. QUIC TLS callbacks (crypto send / receive / secrets / transport parameters) are collected in C and
  handed to Kotlin after `SSL_do_handshake` returns, the way the native QUIC adapter already queues them.
- Native memory stays explicitly owned: every JVM object holding a native context is `AutoCloseable`; a Cleaner is a
  leak report, not the release path (as `NativeKeys.live` on native).

## API split

| Layer | commonMain | nativeMain | jvmMain |
|---|---|---|---|
| Version, CSPRNG, digest, HMAC, HKDF, wipe | `expect object OpenSsl`, `Crypto` | existing | JNI |
| `AeadKey`, `HeaderProtectionKey` | `expect class` | existing | JNI, key context held as a `long` handle |
| `TlsContext`, `TlsEngine` (byte-stream TLS) | `expect class` | existing | JNI |
| QUIC TLS session (new facade) | `expect class QuicTlsSession` | moved down from quic's `NativeTls` | JNI |
| Raw C API `neton.openssl.c` | — | stays native-only | none (not exposed) |

The QUIC facade is what quic needs from OpenSSL's third-party QUIC TLS API: set up from a context (certificate and
key or trust roots, ALPN, verification, session cache / tickets, 0-RTT, key log), feed CRYPTO data per level, run
the handshake, and receive in order: CRYPTO data to send per level, secrets per level and direction, the peer's
transport parameters, alerts, the negotiated ALPN, the cipher, early-data status, session tickets. Its contract is
written from quic's current use (quic SPEC §4's 12 capabilities) before it is moved.

## Packaging

- Desktop: `openssl-jvm` jar with `META-INF/native/<os>-<arch>/libneton_openssl.{so,dylib,dll}` for linux-x64,
  linux-arm64, macos-arm64, macos-x64, windows-x64; extracted to a per-version directory and loaded once.
- Android: `lib/<abi>/libneton_openssl.so` for arm64-v8a, armeabi-v7a, x86_64, x86, built with the NDK; packaged as
  an AAR (Android does not load native code from a plain jar's resources). `System.loadLibrary` there.
- Loading failure is an `UnsatisfiedLinkError` with the platform and the looked-up path, never a silent fallback.

## Phases and gates

Status 2026-10-11: phases 1-6 done on macOS hosts and the Android emulator (SPEC.md); releases pending.


1. Crypto on the JVM: build files, native loader, JNI for version / CSPRNG / digest / HMAC / HKDF / AEAD / header
   protection; the existing crypto tests moved to commonTest and run on the JVM (macOS host, Linux x64 in CI).
2. Byte-stream TLS on the JVM: `TlsContext` / `TlsEngine`; the TLS tests (real handshakes, trust and hostname
   rejection, application data, teardown) on the JVM. `tls`'s `TlsStream` can then move to commonMain.
3. QUIC TLS facade: specified from quic's use, implemented on native first (quic switches to it; its full suite and
   the interop checks must stay green), then on the JVM.
4. neton-io JVM UDP (DatagramChannel on the NIO reactor; no GSO / GRO, no ECN on the JVM: QUIC runs without them).
5. quic on the JVM: TLS and the async layer to commonMain, `jvm()` target, the full test suite on the JVM, interop
   with quinn from a JVM endpoint.
6. msgtrans-quic on the JVM; Android: the AAR, msgtrans-quic client on the Pixel_9 emulator against msgtrans-rust.

Each phase is committed when its gate passes; Windows and Linux arm64 run in CI only.
