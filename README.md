# OpenSSL Kotlin

OpenSSL **4.0.2** static libraries and Kotlin/Native bindings for the Neton protocol stack.
Maven coordinates: `com.netonstream:openssl:4.0.2-1` (publication candidate, not yet on Central).
Kotlin compiler: **2.4.0**. Minimum supported OpenSSL line: **4.0.x**, no 3.x compatibility.

## Scope

- Bundled `libssl.a` + `libcrypto.a`, built from a SHA-256-pinned upstream release archive.
- Raw C API in `neton.openssl.c`: SSL, BIO, X509, EVP, RAND, errors and third-party QUIC TLS entry points.
- `neton.openssl.OpenSsl`: runtime/header version check, CSPRNG, SHA-256.
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
implementation("com.netonstream:openssl:4.0.2-1") // after local/remote publication
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

## Versions and release

`4.0.2-1` means upstream OpenSSL `4.0.2`, wrapper revision `1`. A wrapper-only rebuild increments
the suffix. An upstream update changes `opensslVersion`, `opensslSha256` and the publication version
in `gradle.properties`, refreshes the upstream license, and must pass the same matrix before release.
4.1.x is an upgrade path, **not currently tested or claimed compatible**. Do not auto-follow branches.

`publishToMavenLocal` is suitable for host-only development. Maven Central release requires all
advertised target publications, one root metadata publication configured with `nativeTargets=all`,
signed artifacts, and a clean external consumer test. Never publish host-only root metadata as a
complete multiplatform release. `publishAllPublicationsToStagingRepository` stages files locally;
this repository does not auto-upload to Central. Signing uses `SIGNING_KEY` / `SIGNING_PASSWORD`.

## Provenance

The packaging approach was informed by ensody/native-builds. Build scripts and Kotlin code here
are independently written, not a fork of their generic vcpkg publisher. OpenSSL's own source and
license are retained in the build tree; its license is also in `licenses/OpenSSL.txt` and published
source archives. See [NOTICE](NOTICE).
