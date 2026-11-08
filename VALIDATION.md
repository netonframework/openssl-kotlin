# Validation

## 4.1.0-1 release validation (2026-11-09)

Published from `f8b0e43a146aca31c9c64691deb02aa905ebfd28`, tag `v4.1.0-1`.
Central deployment `65e8be8b-76e7-48ef-a450-c3c9b3a1aff0` is `PUBLISHED`.
All 80 payloads and 80 production signatures across 13 coordinates were downloaded
from Central and matched the verified staging artifacts. Central-only JVM tests
and the macOS ARM64 Native consumer passed. Detailed local evidence is retained in
`build/openssl-4.1.0-1-public-verification.json`,
`build/openssl-4101-public-consumer.log` and `build/openssl-4101-public-native.log`.

Downstream TLS Native linking on Windows exposed an unresolved `stat64i32` symbol
in 4.1.0's file-store provider. JVM/JNI consumers passed because their DLL links with
the newer MinGW runtime; those results did not certify Kotlin/Native compatibility.
The 4.1.0 publication must not be used for Windows Kotlin/Native applications.

The repair restores the `stat` to `_stat` mapping used by upstream 4.0.2, scoped to
MinGW builds of upstream 4.1.0. Both the function and structure spelling are mapped;
no ABI-unsafe linker alias or replacement CRT implementation is introduced. The
tracked source patch is included in the build-cache fingerprint. Public Kotlin/JNI
APIs and the upstream source archive checksum remain unchanged.

The release matrix now links the full Native Windows tests and separately compiles
and executes the common public-API tests from the staged KLIB on Windows.
[Release CI](https://github.com/netonframework/openssl-kotlin/actions/runs/42523992984)
passed all 14 jobs, including this Windows Native consumer and all ten desktop
JVM consumers on JDK 8/21. Local build guard, lock and cache tests also passed.

Downstream candidate TLS, TLS-HTTP, TLS-WebSocket, QUIC, HTTP3 and Neton host tests
passed against the actual staged artifacts; Neton's 14-module ABI gate passed
without changing its API inventories. The Kotlin 2.1 artifact-only QUIC,
msgtrans-QUIC, WS and WSS consumers passed with strict dependency-version checks.
An R8 release app on Android 16 ARM64 reported OpenSSL 4.1.0 and passed QUIC, WS
and WSS. These are candidate compatibility results, not certification of pending
downstream Maven releases or the unrelated ongoing 24-hour HTTP soak. iOS and
Android Kotlin/Native targets remain cross-build coverage, not device execution.

## 4.1.0 release validation (2026-11-09)

Upstream OpenSSL 4.1.0 was released on 2026-10-23. Its official source SHA-256 is
pinned in gradle.properties. This is an upstream-library upgrade, not a wrapper-only
renumbering. Release source: `08bb3735179cf4b065ba80b7b20d4910712dd66b`, tag `v4.1.0`.
Central deployment: `bda6e249-5e71-4180-b327-57dd49342a43`; status `PUBLISHED`.
All 80 payloads and 80 signatures were downloaded from the public Maven repository,
matched byte-for-byte to the verified staging artifacts and checked against the
production signing key. A fresh Gradle user home with exclusive public Maven resolution
passed all 27 Kotlin 2.1.21 JVM consumer tests. The Central-only Native consumer also
ran successfully and reported `OpenSSL 4.1.0 23 Oct 2026`.

The Kotlin public facade, native implementation and JNI implementation are unchanged
from v4.0.2-3. Upstream symbol inventories retain all 5,717 libcrypto and 628 libssl
exports; some APIs gain deprecation flags. This inventory is not a complete binary
ABI proof. The existing raw C binding remains experimental.
The bundled license is byte-identical to the upstream 4.1.0 LICENSE.txt.

[Release CI](https://github.com/netonframework/openssl-kotlin/actions/runs/42515438941)
passed all 13 jobs. The obsolete macOS 14 runner was replaced with macOS 15 and
Xcode 16.4; no test gate was removed.

| Validation | Result |
|---|---|
| Local build guard, lock and cache tests | Passed |
| macOS ARM64 Native / JVM | 38 / 27 tests passed locally and in CI |
| Linux x64 Native / JVM | 38 / 27 tests passed in CI |
| Published-candidate JVM consumers | Kotlin 2.1.21, JDK 8 and 21 on macOS ARM64/x64, Linux ARM64/x64 and Windows x64; each of 10 jobs passed 27 tests, no skips |
| Local staged Kotlin 2.1.21 consumer | 27 tests passed; no build-tree classes |
| TLS, TLS-HTTP, TLS-WebSocket | JVM 24/14/8, macOS ARM64 27/14/8 passed against staged 4.1.0, no skips |
| QUIC | JVM 280 passed; macOS ARM64 621 passed and 3 pre-existing ignored stress tests |
| Android 16 ARM64 | Kotlin 2.1.21 app built with R8; actual runtime reports OpenSSL 4.1.0; QUIC, WS and WSS passed |
| Complete release packaging | 10 Native targets, 5 desktop JNI libraries and 2 Android ABIs passed architecture and completeness gates |
| Production signing | All 80 payloads and signatures verified against AA93E367430D0F9FC4CCB7AB4EC1381BAA4F649B; 13 coordinates |

Local detailed reports are retained in `build/openssl-4.1.0-public-verification.json`,
`build/openssl-4.1.0-ci-reports/` and `build/openssl-4.1.0-central-consumer.log`.
Central reports monthly file-count and release-size limits reached, with grace through
2026-11-09. This deployment succeeded; resolve the quota before the next publication.

The common runtime test requires actual OpenSSL 4.1.0, not just a matching major.
Downstream tests use the staged Maven artifacts without composite builds and record
the resolved 4.1.0 coordinates. Existing TLS/QUIC dependencies, Neton 1.1.1's published
baseline and the ongoing HTTP soak remain pinned to 4.0.2-3. These tests do not certify
a new Neton dependency baseline or a 24-hour OpenSSL 4.1.0 soak.

Coverage limits: Android API 24 was not rerun in this upgrade; iOS and Android
Kotlin/Native targets are cross-built, not device-tested. Windows and Linux ARM64
runtime results above cover JVM/JNI, not Kotlin/Native execution. No performance
improvement is claimed. The three ignored QUIC tests are stressReceiveWindow,
stressStreamReceiveWindow and stressBothWindows, unchanged from the existing suite.

## Historical 4.0.2 validation

Publication status: **4.0.2 validated; publication requested, awaiting Central propagation**.

Deployment: `bc87dde3-2eb9-4dc5-878f-4c0ed3a7cb3e` (2026-09-28).
All eleven coordinates and 70 signed artifacts passed Portal validation. The renamed
4.0.2 Maven-local external consumer passed. Central-only resolution is pending propagation.
The -1 and -2 local builds were never uploaded.

## Safe facade increment (local development label 4.0.2-2)

The -1 and -2 labels below were local development builds, never Central releases.
The first public release is 4.0.2.

macOS ARM64 and macOS x64 under Rosetta: 25/25 tests passed on each architecture.
The expanded tests cover reusable AEAD, tag/AAD rejection and plaintext wiping, ranges,
RFC 9001 header protection and TLS label vectors, RFC 5869 HKDF, empty HMAC/HKDF keys,
handle reentrancy, concurrent engine creation from a frozen context, bounded TLS1.2/1.3
engine pumping, write backpressure, exact retry bytes,
PEM trust/identity, key mismatch, ALPN mismatch, DNS/IP identity, expiry, mTLS, exporter,
peer chain/SNI, factory closed before engine, close_notify versus transport EOF.

All ten targets cross-linked with the final facade and common metadata publication passed.
Existing 4.0.2 archives
are reused: this increment changes only C shims/Kotlin, not upstream OpenSSL or its build flags.
The independent Maven consumer resolves 4.0.2-2 and runs an AEAD roundtrip as well as SHA/RAND.
Local benchmark source, observations and limitations are in benchmark/results/README.md.

No Linux runtime was executed locally: Colima was not running. Linux Actions remains a
runtime gate, not a result inferred from successful cross-linking. QUIC safe callback handling,
interop, session resumption/0-RTT, platform trust stores and allocation tracing are still open.
README's capability matrix distinguishes implemented from deferred items.

## Local verification

OpenSSL 4.0.2, wrapper 4.0.2-1, Kotlin/Native 2.4.0, Gradle 8.14.2.
Host: Apple Silicon macOS, Xcode SDK 26.2, JDK 17.
Build configuration is not runtime verification.

| Target | Result |
|---|---|
| macosArm64 | 10/10 tests passed on the host |
| macosX64 | 10/10 tests passed under Rosetta, not on physical Intel hardware |
| linuxX64 / linuxArm64 | Test executable cross-link passed; execution pending Linux CI/hardware |
| iosArm64 / iosSimulatorArm64 / iosX64 | Test executable link passed; execution pending simulator/device |
| mingwX64 | Test executable cross-link passed; execution pending Windows |
| androidNativeArm64 / androidNativeX64 | Test executable cross-link passed; execution pending Android |

Tests cover header/runtime version agreement, SHA-256 known vectors, CSPRNG size/error
handling, TLS context/session allocation and release, TLS 1.3 handshake over a bounded BIO
pair with ALPN h2, application data, wrong hostname, unknown CA and expired certificate
rejection. AES-128-GCM is checked against a known vector and a tampered tag is rejected.
QUIC TLS smoke tests only check API linkage and misuse rejection, not QUIC interoperability.

Build guard tests reject an OpenSSL 3.x version and a corrupt cached source archive.
The upstream archive checksum is checked on every native build invocation.

Full-matrix Maven local publication passed, including common Kotlin metadata and all ten
target variants. The independent `smoke` project resolved only the Maven coordinate,
built a release executable and ran successfully on macOS ARM64, reporting
`OpenSSL 4.0.2 25 Aug 2026`. Its dynamic dependencies contain no libssl or libcrypto.
The public utility facade uses a small C error-queue helper to avoid exposing the
Windows/POSIX `unsigned long` width difference in shared Kotlin metadata.

## Reproduction

```sh
bash scripts/test-build-guards.sh
ANDROID_NDK_HOME=/path/to/ndk ./gradlew -PnativeTargets=all \
  :openssl:macosArm64Test :openssl:linkDebugTestMacosX64 \
  :openssl:linkDebugTestLinuxX64 :openssl:linkDebugTestLinuxArm64 \
  :openssl:linkDebugTestIosArm64 :openssl:linkDebugTestIosSimulatorArm64 \
  :openssl:linkDebugTestIosX64 :openssl:linkDebugTestMingwX64 \
  :openssl:linkDebugTestAndroidNativeArm64 :openssl:linkDebugTestAndroidNativeX64 \
  :openssl:publishToMavenLocal
openssl/build/bin/macosX64/debugTest/test.kexe
./gradlew -p smoke runReleaseExecutableMacosArm64
```

Linux targets require the Kotlin sysroot bootstrap documented in README first. Android
cross builds use NDK 29.0.14206865. NDK 26.1.10909125 failed on x64 SM3/SM4 assembly
instructions; assembly was not disabled to bypass that failure. Build logs and JUnit reports stay under ignored build
directories. GitHub Actions is configured for macOS and Linux native host tests and an
external Maven consumer; no successful remote CI run is claimed by this local report.

Android also required inline ARM64 atomics (the Kotlin linker runtime has no outlined atomic
helpers) and a combined SSL/crypto archive (avoids embedded archive ordering problems with
the older linker). Both target test executables linked after these changes. The other eight
targets' previously verified archives were reused for final local publication; only the
Android branch of the native build script changed after their verification.

## Remaining release gates

- Run on Linux, Windows and mobile targets before declaring runtime support for them.
- Validate the platform-specific trust store policy in the eventual TLS adapter.
- Implement and test socket/IoStream TLS and QUIC adapters separately.
- Benchmark the actual protocol integration before making performance claims.
- Review/sign all publications before uploading to Maven Central.
