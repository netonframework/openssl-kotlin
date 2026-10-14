#!/usr/bin/env bash
# The JVM's JNI library (docs/JVM.md): src/jvmNative/neton_openssl_jni.c with the header-only shim, linked against the
# static OpenSSL that build-openssl.sh built for the matching Kotlin/Native target, exporting only the Java_* entry
# points (no OpenSSL symbol can clash with another OpenSSL in the process).
# Usage: build-jni.sh <Kotlin/Native target> <output directory>; JNI_JAVA_HOME (or JAVA_HOME) gives the JNI headers.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
TARGET=${1:?Usage: build-jni.sh <target> <output directory>}
OUT=${2:?Usage: build-jni.sh <target> <output directory>}
case "$TARGET" in
    macosArm64|macosX64|linuxX64|linuxArm64|mingwX64|androidNativeArm64|androidNativeX64) ;;
    *) echo "No JNI library for $TARGET" >&2; exit 1 ;;
esac
BASE="$ROOT/build/openssl/$TARGET"
mkdir -p "$BASE"
if [[ "${NETON_OPENSSL_LOCK:-}" != "$BASE" ]]; then
    exec perl "$ROOT/scripts/with-build-lock.pl" "$BASE/build.lock" \
        env NETON_OPENSSL_LOCK="$BASE" bash "$0" "$@"
fi
PREFIX="$ROOT/build/openssl/$TARGET/install"
JDK=${JNI_JAVA_HOME:-${JAVA_HOME:?Set JAVA_HOME or JNI_JAVA_HOME for the JNI headers}}
bash "$ROOT/scripts/build-openssl.sh" "$TARGET"
SRC="$ROOT/openssl/src/jvmNative/neton_openssl_jni.c"
INC=(-I"$PREFIX/include" -I"$ROOT/openssl/src/nativeInterop/cinterop" -I"$JDK/include")
CFLAGS=(-std=c99 -O2 -fPIC -fvisibility=hidden -Wall -Wextra -Wno-deprecated-declarations)
# jni_md.h for the target OS: the JDK's own when it has that platform's (it is the host's), else src/jvmNative/jni_md.
jni_md() { if [[ -d "$JDK/include/$1" ]]; then echo "$JDK/include/$1"; else echo "$ROOT/openssl/src/jvmNative/jni_md/$1"; fi; }
mkdir -p "$OUT"
DEST="$OUT"
OUT=$(mktemp -d "$DEST/.jni.XXXXXX")
trap 'rm -rf "$OUT"' EXIT
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
            "${CFLAGS[@]}" "${INC[@]}" -I"$(jni_md linux)" \
            -shared -Wl,--version-script="$MAP" -Wl,--gc-sections -Wl,-z,noexecstack -Wl,--no-undefined \
            "$SRC" "$PREFIX/lib/libssl.a" "$PREFIX/lib/libcrypto.a" -ldl -lpthread -o "$OUT/libneton_openssl.so"
        rm -f "$MAP"
        ;;
    androidNativeArm64|androidNativeX64)
        # Android apps (docs/JVM.md): the NDK's clang for API 21, as build-openssl.sh; jni.h comes from the NDK sysroot.
        : "${ANDROID_NDK_HOME:?Set ANDROID_NDK_HOME to a pinned Android NDK}"
        if [[ "$(uname -s)" == Darwin ]]; then NDK_HOST=darwin-x86_64; else NDK_HOST=linux-x86_64; fi
        NDK_BIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$NDK_HOST/bin"
        if [[ "$TARGET" == androidNativeArm64 ]]; then CC="$NDK_BIN/aarch64-linux-android21-clang"; else CC="$NDK_BIN/x86_64-linux-android21-clang"; fi
        MAP="$OUT/exports.map"
        printf '{ global: Java_*; local: *; };\n' > "$MAP"
        "$CC" "${CFLAGS[@]}" -I"$PREFIX/include" -I"$ROOT/openssl/src/nativeInterop/cinterop" \
            -shared -Wl,--version-script="$MAP" -Wl,--gc-sections -Wl,-z,noexecstack -Wl,--no-undefined -Wl,-z,max-page-size=16384 \
            "$SRC" "$PREFIX/lib/libssl.a" "$PREFIX/lib/libcrypto.a" -o "$OUT/libneton_openssl.so"
        "$NDK_BIN/llvm-strip" --strip-unneeded "$OUT/libneton_openssl.so"   # apps ship it: no debug symbols
        rm -f "$MAP"
        ;;
    mingwX64)
        # Windows x64 (docs/JVM.md): cross-built with MinGW-w64 against build-openssl.sh's mingw64 archives. jni.h from
        # the build JDK, jni_md.h as jni_md() finds it. Only the JNIEXPORT (dllexport) functions are exported; the
        # GCC runtime is linked in so the DLL needs nothing beyond Windows system libraries.
        x86_64-w64-mingw32-gcc -std=c99 -O2 -Wall -Wextra -Wno-deprecated-declarations -I"$PREFIX/include" -I"$ROOT/openssl/src/nativeInterop/cinterop" \
            -I"$JDK/include" -I"$(jni_md win32)" \
            -shared -static-libgcc -Wl,--gc-sections -Wl,--no-undefined \
            "$SRC" "$PREFIX/lib/libssl.a" "$PREFIX/lib/libcrypto.a" -lws2_32 -lcrypt32 -luser32 -ladvapi32 -lbcrypt \
            -o "$OUT/neton_openssl.dll"
        x86_64-w64-mingw32-strip --strip-unneeded "$OUT/neton_openssl.dll"
        ;;
    *) echo "No JNI library for $TARGET" >&2; exit 1 ;;
esac
for library in "$OUT"/*.so "$OUT"/*.dylib "$OUT"/*.dll; do
    [[ -f "$library" ]] || continue
    mv -f "$library" "$DEST/"
done
ls -l "$DEST"
