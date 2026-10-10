#!/usr/bin/env bash
# The JVM's JNI library (docs/JVM.md): src/jvmNative/neton_openssl_jni.c with the header-only shim, linked against the
# static OpenSSL that build-openssl.sh built for the matching Kotlin/Native target, exporting only the Java_* entry
# points (no OpenSSL symbol can clash with another OpenSSL in the process).
# Usage: build-jni.sh <Kotlin/Native target> <output directory>; JNI_JAVA_HOME (or JAVA_HOME) gives the JNI headers.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
TARGET=${1:?Usage: build-jni.sh <target> <output directory>}
OUT=${2:?Usage: build-jni.sh <target> <output directory>}
PREFIX="$ROOT/build/openssl/$TARGET/install"
JDK=${JNI_JAVA_HOME:-${JAVA_HOME:?Set JAVA_HOME or JNI_JAVA_HOME for the JNI headers}}
[[ -f "$PREFIX/lib/libcrypto.a" && -f "$PREFIX/lib/libssl.a" ]] || bash "$ROOT/scripts/build-openssl.sh" "$TARGET"
SRC="$ROOT/openssl/src/jvmNative/neton_openssl_jni.c"
INC=(-I"$PREFIX/include" -I"$ROOT/openssl/src/nativeInterop/cinterop" -I"$JDK/include")
CFLAGS=(-std=c99 -O2 -fPIC -fvisibility=hidden -Wall -Wextra -Wno-deprecated-declarations)
mkdir -p "$OUT"
case "$TARGET" in
    macosArm64|macosX64)
        [[ "$TARGET" == macosArm64 ]] && ARCH=arm64 || ARCH=x86_64
        xcrun --sdk macosx clang -arch "$ARCH" -mmacosx-version-min=11.0 "${CFLAGS[@]}" "${INC[@]}" -I"$JDK/include/darwin" \
            -shared -Wl,-exported_symbol,'_Java_*' -Wl,-dead_strip \
            "$SRC" "$PREFIX/lib/libssl.a" "$PREFIX/lib/libcrypto.a" -o "$OUT/libneton_openssl.dylib"
        ;;
    linuxX64|linuxArm64)
        # The Kotlin/Native toolchain and sysroot build-openssl.sh used: the same libc baseline as the native target.
        DATA=${KONAN_DATA_DIR:-$HOME/.konan}
        if [[ "$TARGET" == linuxX64 ]]; then
            TRIPLE=x86_64-unknown-linux-gnu; TOOLCHAIN=x86_64-unknown-linux-gnu-gcc-8.3.0-glibc-2.19-kernel-4.9-2
        else
            TRIPLE=aarch64-unknown-linux-gnu; TOOLCHAIN=aarch64-unknown-linux-gnu-gcc-8.3.0-glibc-2.25-kernel-4.9-2
        fi
        case "$(uname -s):$(uname -m)" in
            Darwin:arm64) LLVM=llvm-21-aarch64-macos-essentials-97 ;;
            Darwin:x86_64) LLVM=llvm-21-x86_64-macos-essentials-83 ;;
            Linux:x86_64) LLVM=llvm-21-x86_64-linux-essentials-116 ;;
            *) echo "Linux targets need the Kotlin 2.4.20 macOS or Linux x64 toolchain" >&2; exit 1 ;;
        esac
        BIN="$DATA/dependencies/$LLVM/bin"
        [[ -x "$BIN/clang" ]] || BIN="$DATA/dependencies/${LLVM/essentials/dev}/bin"
        GCC="$DATA/dependencies/$TOOLCHAIN"
        MAP="$OUT/exports.map"
        printf '{ global: Java_*; local: *; };\n' > "$MAP"
        "$BIN/clang" --target=$TRIPLE --sysroot="$GCC/$TRIPLE/sysroot" --gcc-toolchain="$GCC" -fuse-ld=lld \
            "${CFLAGS[@]}" "${INC[@]}" -I"$JDK/include/linux" \
            -shared -Wl,--version-script="$MAP" -Wl,--gc-sections -Wl,-z,noexecstack -Wl,--no-undefined \
            "$SRC" "$PREFIX/lib/libssl.a" "$PREFIX/lib/libcrypto.a" -ldl -lpthread -o "$OUT/libneton_openssl.so"
        rm -f "$MAP"
        ;;
    *) echo "No JNI library for $TARGET yet (docs/JVM.md: Windows and Android come later)" >&2; exit 1 ;;
esac
ls -l "$OUT"
