# AEAD boundary benchmark

Not HTTP/QUIC throughput. Compare warmed seal+open (one of each per iteration), identical
OpenSSL archives, algorithm, 12-byte unique nonce, 16-byte AAD and in-place payload. Both
implementations allocate buffers/keys before timing. C calls the same EVP helper directly;
Kotlin additionally validates ranges, pins arrays and checks exclusive handle ownership.
Columns: implementation, algorithm (0 AES128 / 1 AES256 / 2 ChaCha), bytes, iterations,
elapsed nanoseconds, nanoseconds per byte (divided by two for seal+open).

```sh
# First publish the host target to MavenLocal. macOS ARM64 example:
./gradlew :openssl:publishToMavenLocal
./gradlew -p benchmark linkReleaseExecutableMacosArm64
cc -O3 -Iopenssl/src/nativeInterop/cinterop -Ibuild/openssl/macosArm64/install/include \
  benchmark/direct.c build/openssl/macosArm64/install/lib/libcrypto.a -o build/direct-benchmark
build/direct-benchmark 1200 100000 0
benchmark/build/bin/macosArm64/releaseExecutable/openssl-benchmark.kexe 1200 100000 0
```

Run 1200 and 16384 bytes, all algorithms, several interleaved C/Kotlin rounds. On Linux
add `-ldl -lpthread` and use its matching archives/compiler. This timer does NOT count
allocations or prove zero allocation in Kotlin or OpenSSL. Allocation tracing, contention,
first-use costs and error paths are separate acceptance gates. Do not extrapolate local
microbenchmarks to transport throughput or substitute them for protocol correctness tests.
