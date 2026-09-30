# OpenSSL Kotlin

OpenSSL **4.0.2** static libraries and Kotlin/Native bindings for the Neton protocol stack.
Maven coordinates: `com.netonstream:openssl:4.0.2` (the version follows upstream OpenSSL).
Kotlin compiler: **2.4.0**. Minimum supported OpenSSL line: **4.0.x**, no 3.x compatibility.

## Scope

- Bundled `libssl.a` + `libcrypto.a`, built from a SHA-256-pinned upstream release archive.
- Raw C API in `neton.openssl.c`: SSL, BIO, X509, EVP, RAND, errors and third-party QUIC TLS entry points.
- `neton.openssl.OpenSsl`: runtime/header version check, CSPRNG, SHA-256.
- Reusable `AeadKey`, `HeaderProtectionKey`, caller-buffer digest/HMAC/HKDF/random operations.
- `TlsContext` / `TlsEngine`: bounded, socket-free TLS 1.2/1.3 with explicit trust and identity.
- No dependency on neton-io, no socket ownership, no replacement cryptography or TLS implementation.
- No TLS `IoStream` adapter or QUIC handshake adapter yet. Those are separate protocol integration work.

The raw API is unsafe: explicitly configure peer verification, hostname checks, trust roots and
ALPN. This library does **not** automatically import the OS trust store. Default OpenSSL certificate
paths are not a portable trust policy. Own each SSL object on one execution context, keep callback
user data alive until all callbacks have stopped, and free native resources explicitly. Never
let Kotlin exceptions cross C callbacks. Do not mix a second OpenSSL major version in the same
link unit or hide duplicate symbols with linker flags.

## Build and test

Requirements: JDK 17+, Perl, make, curl; Xcode for Apple targets. macOS host build:

```sh
./gradlew :openssl:macosArm64Test
# Intel host:
./gradlew -PnativeTargets=macosX64 :openssl:macosX64Test
```

Only the host target is configured by default, to avoid silently downloading/building all SDKs.
Use `-PnativeTargets=macosArm64,macosX64` or `-PnativeTargets=all` explicitly. Each target has
separate source, generated headers and output directories under `build/openssl/<target>`.
Full OpenSSL build output is saved in that directory's `build.log`.

Linux builds use the **Kotlin/Native 2.4.0 LLVM and sysroot**, including for cross compilation
from macOS. Bootstrap dependencies once (adjust KONAN_HOME for your host):

```sh
./gradlew :openssl:downloadKotlinNativeDistribution
export KONAN_HOME="$HOME/.konan/kotlin-native-prebuilt-linux-x86_64-2.4.0"
"$KONAN_HOME/bin/konanc" scripts/bootstrap.kt -target linux_x64 -produce library -o build/bootstrap
./gradlew -PnativeTargets=linuxX64 :openssl:linuxX64Test
# Cross build: bootstrap linux_arm64 instead, then use :openssl:linkDebugTestLinuxArm64.
```

Target configuration (not a claim of runtime validation):

| Target | Build prerequisites | Validation |
|---|---|---|
| macosArm64 / macosX64 | Xcode | Native host tests; cross link on other architecture |
| linuxX64 / linuxArm64 | K/N LLVM + target sysroot | Host test or cross link; see validation report |
| iosArm64 / iosSimulatorArm64 / iosX64 | Xcode + matching SDK | Library/test link; device validation separate |
| mingwX64 | macOS/Linux + x86_64-w64-mingw32 toolchain | Cross link; Windows runtime validation separate |
| androidNativeArm64 / androidNativeX64 | `ANDROID_NDK_HOME` pointing to NDK 29.0.14206865 | Cross link; Android runtime validation separate |

See [VALIDATION.md](VALIDATION.md) for actual results. Compiler success does not establish
certificate store behavior, network interoperability, QUIC correctness or performance.

## Use

```kotlin
implementation("com.netonstream:openssl:4.0.2")
```

```kotlin
import neton.openssl.OpenSsl

OpenSsl.checkVersion()
val nonce = OpenSsl.randomBytes(32)
val digest = OpenSsl.sha256("hello".encodeToByteArray())
```

The klib embeds static libraries. Users do not need an installed system OpenSSL or this project's
native build toolchain. Keep Kotlin/Native compiler versions aligned between producer and consumer.
Android embeds a combined archive so Kotlin's linker cannot put libcrypto before libssl;
ARM64 uses inline atomics for compatibility with Kotlin's older Android compiler runtime.

## Safe facade and boundaries

All handles need explicit `close()` in `finally`. Double-close is harmless; use after
close fails. Mutable engines/keys reject concurrent use and reentrancy. A frozen `TlsContext`
allows concurrent `newEngine`; close the factory only after its callers have stopped (close
rejects while a creation is active). Sequential transfer between threads is permitted.
Do not share a key/engine concurrently between coroutines. No coroutine library or scheduler is
used internally. No Kotlin callback crosses the C ABI in the current facade.
Session caching, server ticket issuance, 0-RTT, renegotiation and TLS compression are disabled
in this increment. Certificate chain/validity and SAN identity verification are enabled for
clients; automatic online OCSP/CRL fetching and browser-specific trust policy are not provided.

| Capability | Current delivery |
|---|---|
| AES-128/256-GCM, ChaCha20-Poly1305 | Reusable key, in-place caller buffers, 12-byte nonce/16-byte tag; failed plaintext wiped |
| Header protection | AES-128/256 and ChaCha20 masks; protocol applies the mask and chooses offsets |
| HKDF / digest / HMAC / random | SHA256/384 HKDF including TLS labels, SHA1/256/384/512 digest, HMAC SHA256/384, randomFill, constant-time comparison |
| TLS engine | Bounded BIO pair, fragmentation, NeedRead/NeedWrite, retry-owned 16KiB plaintext, close_notify vs bare EOF |
| TLS configuration | TLS1.2/1.3, cipher lists/groups, PEM identity/roots, SAN DNS/IP verification, optional/required mTLS, static ALPN selection |
| TLS metadata | ALPN/version/cipher/SNI, copied peer DER chain, exporter |
| Deferred, NOT advertised safe-ready | QUIC TLS callback facade/interoperability; tickets/resumption/0-RTT; dynamic SNI certificate selection; DER/encrypted identity input; platform trust providers; published certificate testkit |

The caller must guarantee AEAD nonce uniqueness and enforce protocol-specific key usage limits.
`seal` reserves 16 extra bytes for the tag. `open` returns false for an invalid tag and wipes the
tentative plaintext. Output arrays cannot alias nonce/AAD. HKDF and HMAC are key-setup/one-shot
APIs; they do not promise reusable native contexts or zero allocation. SHA1 is compatibility-only.
See [the full contract and remaining gates](docs/SAFE_API.md) and [benchmark method](benchmark/README.md).

### Driving TLS without sockets

Create a client `TlsContext(server = false, trustRootsPem = ...)` and call
`newEngine(PeerIdentity.Dns("example.com"))`. A server requires a PEM chain and matching key.
The factory can be closed after engine creation; OpenSSL retains the engine's context.

1. Call `handshake`; drain ciphertext into the transport and feed peer ciphertext back.
2. Preserve any unconsumed input when `feedCiphertext` returns less than supplied, including zero.
3. Drain output regardless of NeedRead/NeedWrite; neither means "no pending output". Do not busy-spin.
4. After handshake, continue reads for TLS1.3 post-handshake messages, not just application data.
5. `read`/`write` return byte counts or `TlsEngine.NEED_READ`, `NEED_WRITE`, `PEER_CLOSED`.
   Retry a pending write with exactly the same bytes/length; only feed/drain or close until retry.
6. Use `closeNotify` for TLS half-close and drain its ciphertext. Report raw transport EOF via
   `transportEof`; lack of peer close_notify is an error, not clean EOF. `close()` only frees resources.

The library does not own timeouts, retry policy, socket closing or cancellation. A canceled adapter
must stop concurrent use and close the engine. BIO limits bound transport staging, not every
allocation inside OpenSSL; certificate message/depth limits are configured separately.

## Versions and release

The version follows upstream OpenSSL: `4.0.2` contains OpenSSL 4.0.2. Wrapper-only fixes on the same
upstream release use `4.0.2-1`, `4.0.2-2`, and so on, which sort after `4.0.2`. Local development labels
are not publication revisions. An upstream update changes `opensslVersion`, `opensslSha256` and the
publication version in `gradle.properties`, refreshes the upstream license, and must pass the same matrix before release.
`0.1.0` was published by mistake on 2026-09-29 and must not be used. It was built from the same sources
as `4.0.2`; the only difference is the build timestamp in `libcrypto-lib-cversion.o`. It sorts below
`4.0.2`, so a graph that holds both resolves to `4.0.2`, which is harmless. `com.netonstream:tls:0.1.0`
depends on it; later tls releases depend on `4.0.2`.
4.1.x is an upgrade path, **not currently tested or claimed compatible**. Do not auto-follow branches.

`publishToMavenLocal` is suitable for host-only development. Maven Central release requires all
advertised target publications, one root metadata publication configured with `nativeTargets=all`,
signed artifacts, and a clean external consumer test. Never publish host-only root metadata as a
complete multiplatform release. `publishAllPublicationsToStagingRepository` stages files locally;
this task does not auto-upload to Central. Signing uses `SIGNING_KEY` / `SIGNING_PASSWORD`
or Gradle user properties `signingInMemoryKey` / `signingInMemoryKeyPassword`.

`python3 scripts/central.py bundle` checks that all eleven coordinates have signatures and
packages only the configured release version. `upload` submits for validation without publishing;
`status --id ID` inspects the deployment; `publish --id ID` explicitly releases a validated bundle.
Portal credentials come from `MAVEN_CENTRAL_USERNAME` / `MAVEN_CENTRAL_PASSWORD` or Gradle user
properties `mavenCentralUsername` / `mavenCentralPassword`. Never commit credentials or signatures' private keys.

## Provenance

The packaging approach was informed by ensody/native-builds. Build scripts and Kotlin code here
are independently written, not a fork of their generic vcpkg publisher. OpenSSL's own source and
license are retained in the build tree; its license is also in `licenses/OpenSSL.txt` and published
source archives. See [NOTICE](NOTICE).
