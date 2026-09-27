#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
C_BIN=${1:?Pass the direct C executable}
K_BIN=${2:?Pass the Kotlin release executable}
OUT="$ROOT/build/benchmark-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"
uname -a > "$OUT/host.txt"
if command -v sha256sum >/dev/null; then sha256sum "$C_BIN" "$K_BIN" > "$OUT/binaries.sha256"
else shasum -a 256 "$C_BIN" "$K_BIN" > "$OUT/binaries.sha256"; fi
printf 'implementation,algorithm,bytes,iterations,elapsed_ns,ns_per_byte\n' > "$OUT/results.csv"
for algorithm in 0 1 2; do
    for size in 1200 16384; do
        for round in 1 2 3; do
            "$C_BIN" "$size" 100000 "$algorithm" >> "$OUT/results.csv"
            "$K_BIN" "$size" 100000 "$algorithm" >> "$OUT/results.csv"
            "$K_BIN" "$size" 100000 "$algorithm" >> "$OUT/results.csv"
            "$C_BIN" "$size" 100000 "$algorithm" >> "$OUT/results.csv"
        done
    done
done
echo "$OUT"
