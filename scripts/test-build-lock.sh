#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
pids=()
for n in 1 2 3 4; do
    perl "$ROOT/scripts/with-build-lock.pl" "$TMP/lock" bash -c '
        set -eu
        mkdir "$1/active"
        sleep 0.1
        rmdir "$1/active"
        printf "done\n" >> "$1/results"
    ' _ "$TMP" &
    pids+=("$!")
done
for pid in "${pids[@]}"; do wait "$pid"; done
[[ $(wc -l < "$TMP/results") -eq 4 ]]
if perl "$ROOT/scripts/with-build-lock.pl" "$TMP/lock" bash -c 'exit 17'; then
    echo 'Lost child exit status' >&2; exit 1
else
    [[ $? -eq 17 ]]
fi
perl "$ROOT/scripts/with-build-lock.pl" "$TMP/lock" true
echo 'PASS: competing processes serialize, exit status propagates, and failed owners release the lock'
