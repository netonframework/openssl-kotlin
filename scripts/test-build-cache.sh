#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/scripts" "$TMP/build/downloads" "$TMP/fixture/openssl" "$TMP/bin"
cp "$ROOT/scripts/build-openssl.sh" "$ROOT/scripts/with-build-lock.pl" "$TMP/scripts/"
export BUILD_TEST_ROOT="$TMP"
export PATH="$TMP/bin:$PATH"
cat > "$TMP/fixture/openssl/Configure" <<'PERL'
use strict;
use warnings;
my ($prefix) = map { /^--prefix=(.*)$/ ? $1 : () } @ARGV;
open(my $file, '>', 'prefix') or die $!;
print $file $prefix;
PERL
printf 'fixture license\n' > "$TMP/fixture/openssl/LICENSE.txt"
cat > "$TMP/bin/make" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$*" == *build_libs* ]]; then
    mkdir "$BUILD_TEST_ROOT/compiling"
    sleep 0.1
    rmdir "$BUILD_TEST_ROOT/compiling"
    [[ ! -f "$BUILD_TEST_ROOT/fail" ]] || exit 23
    printf 'build\n' >> "$BUILD_TEST_ROOT/count"
else
    prefix=$(< prefix)
    mkdir -p "$prefix/lib" "$prefix/include/openssl"
    for file in lib/libssl.a lib/libcrypto.a include/openssl/ssl.h include/openssl/configuration.h; do
        printf 'fixture\n' > "$prefix/$file"
    done
fi
SH
printf '#!/bin/sh\necho fixture-compiler-1\n' > "$TMP/bin/x86_64-w64-mingw32-gcc"
chmod +x "$TMP/bin/make" "$TMP/bin/x86_64-w64-mingw32-gcc"
archive="$TMP/build/downloads/openssl-4.0.2.tar.gz"
tar -czf "$archive" -C "$TMP/fixture" openssl
if command -v sha256sum >/dev/null; then sha=$(sha256sum "$archive"); else sha=$(shasum -a 256 "$archive"); fi
printf 'opensslVersion=4.0.2\nopensslSha256=%s\n' "${sha%% *}" > "$TMP/gradle.properties"
pids=()
for n in 1 2; do
    bash "$TMP/scripts/build-openssl.sh" mingwX64 > "$TMP/result-$n" 2>&1 &
    pids+=("$!")
done
for pid in "${pids[@]}"; do wait "$pid"; done
[[ $(wc -l < "$TMP/count") -eq 1 ]]
# Calling through a different path spelling must still reuse the same outputs.
(cd "$TMP" && bash scripts/build-openssl.sh mingwX64)
[[ $(wc -l < "$TMP/count") -eq 1 ]]
rm "$TMP/build/openssl/mingwX64/install/lib/libssl.a"
bash "$TMP/scripts/build-openssl.sh" mingwX64
[[ $(wc -l < "$TMP/count") -eq 2 ]]
CFLAGS=-O1 bash "$TMP/scripts/build-openssl.sh" mingwX64
[[ $(wc -l < "$TMP/count") -eq 3 ]]
touch "$TMP/fail"
if CFLAGS=-O0 bash "$TMP/scripts/build-openssl.sh" mingwX64; then
    echo 'Failed build was accepted' >&2; exit 1
fi
[[ ! -f "$TMP/build/openssl/mingwX64/install/.build-fingerprint" ]]
rm "$TMP/fail"
CFLAGS=-O0 bash "$TMP/scripts/build-openssl.sh" mingwX64
[[ $(wc -l < "$TMP/count") -eq 4 ]]
echo 'PASS: concurrent reuse, path-independent keys, missing outputs, changed flags, and failed-build recovery'
