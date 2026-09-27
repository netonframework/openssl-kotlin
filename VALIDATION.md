# Validation

Publication status: **not published to Maven Central**.

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
