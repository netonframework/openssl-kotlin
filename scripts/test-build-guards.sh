#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/scripts" "$TMP/build/downloads"
cp "$ROOT/scripts/build-openssl.sh" "$TMP/scripts/"

# Deliberately invalid fixtures must fail before any download, extraction or compilation.
printf 'opensslVersion=3.5.8\nopensslSha256=invalid\n' > "$TMP/gradle.properties"
if bash "$TMP/scripts/build-openssl.sh" macosArm64 > "$TMP/result" 2>&1; then
    echo 'Unexpectedly accepted OpenSSL 3.x' >&2; exit 1
fi
grep -q 'Only stable OpenSSL 4.x' "$TMP/result"
printf 'opensslVersion=4.0.2\nopensslSha256=invalid\n' > "$TMP/gradle.properties"
printf 'corrupt source archive\n' > "$TMP/build/downloads/openssl-4.0.2.tar.gz"
if bash "$TMP/scripts/build-openssl.sh" macosArm64 > "$TMP/result" 2>&1; then
    echo 'Unexpectedly accepted a corrupt archive' >&2; exit 1
fi
grep -q 'Cached source checksum mismatch' "$TMP/result"
echo 'PASS: 3.x and corrupt source archives are rejected before building'
