#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
TARGET=${1:?Usage: build-openssl.sh <Kotlin Native target>}
case "$TARGET" in
    macosArm64|macosX64|iosArm64|iosSimulatorArm64|iosX64|linuxX64|linuxArm64|mingwX64|androidNativeArm64|androidNativeX64) ;;
    *) echo "Unsupported target: $TARGET" >&2; exit 1 ;;
esac
BASE="$ROOT/build/openssl/$TARGET"
mkdir -p "$BASE"
if [[ "${NETON_OPENSSL_LOCK:-}" != "$BASE" ]]; then
    exec perl "$ROOT/scripts/with-build-lock.pl" "$BASE/build.lock" \
        env NETON_OPENSSL_LOCK="$BASE" bash "$0" "$@"
fi
VERSION=$(sed -n 's/^opensslVersion=//p' "$ROOT/gradle.properties")
SHA=$(sed -n 's/^opensslSha256=//p' "$ROOT/gradle.properties")
[[ "$VERSION" =~ ^4\.[0-9]+\.[0-9]+$ ]] || { echo "Only stable OpenSSL 4.x releases are supported" >&2; exit 1; }
PREFIX="$BASE/install"
SOURCE="$BASE/source"
ARCHIVE="$ROOT/build/downloads/openssl-$VERSION.tar.gz"
mkdir -p "$(dirname "$ARCHIVE")" "$BASE"
digest() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi; }
if [[ ! -f "$ARCHIVE" ]]; then
    TEMP=$(mktemp "$ARCHIVE.XXXXXX")
    trap 'rm -f "$TEMP"' EXIT
    curl --fail --location --retry 3 --output "$TEMP" "https://github.com/openssl/openssl/releases/download/openssl-$VERSION/openssl-$VERSION.tar.gz"
    [[ "$(digest "$TEMP" | awk '{print $1}')" == "$SHA" ]] || { echo "Source checksum mismatch" >&2; exit 1; }
    mv "$TEMP" "$ARCHIVE"
fi
[[ "$(digest "$ARCHIVE" | awk '{print $1}')" == "$SHA" ]] || { echo "Cached source checksum mismatch" >&2; exit 1; }

# No shared libraries or loadable providers: consumers receive a self-contained static build. Position-independent
# code everywhere, so the same archives also link into the JVM's JNI library (scripts/build-jni.sh, docs/JVM.md).
FLAGS=(no-shared no-module no-tests no-legacy -fPIC --libdir=lib "--prefix=$PREFIX" "--openssldir=$PREFIX/ssl")
case "$TARGET" in
    macosArm64|macosX64|iosArm64|iosSimulatorArm64|iosX64)
        [[ "$(uname -s)" == Darwin ]] || { echo "Apple targets require Xcode" >&2; exit 1; }
        case "$TARGET" in
            macosArm64) CONFIG=darwin64-arm64-cc; SDK=macosx; FLAGS+=(-mmacosx-version-min=11.0) ;;
            macosX64) CONFIG=darwin64-x86_64-cc; SDK=macosx; FLAGS+=(-mmacosx-version-min=11.0) ;;
            iosArm64) CONFIG=ios64-cross; SDK=iphoneos; FLAGS+=(-mios-version-min=14.0) ;;
            iosSimulatorArm64) CONFIG=iossimulator-arm64-xcrun; SDK=iphonesimulator; FLAGS+=(-mios-simulator-version-min=14.0) ;;
            iosX64) CONFIG=iossimulator-x86_64-xcrun; SDK=iphonesimulator; FLAGS+=(-mios-simulator-version-min=14.0) ;;
        esac
        export CC="$(xcrun --sdk "$SDK" --find clang)"
        export CROSS_TOP="$(xcrun --sdk "$SDK" --show-sdk-platform-path)/Developer"
        export CROSS_SDK="$(basename "$(xcrun --sdk "$SDK" --show-sdk-path)")"
        FLAGS+=(-isysroot "$(xcrun --sdk "$SDK" --show-sdk-path)")
        ;;
    linuxX64|linuxArm64)
        DATA=${KONAN_DATA_DIR:-$HOME/.konan}
        if [[ "$TARGET" == linuxX64 ]]; then
            CONFIG=linux-x86_64; TRIPLE=x86_64-unknown-linux-gnu
            TOOLCHAIN=x86_64-unknown-linux-gnu-gcc-8.3.0-glibc-2.19-kernel-4.9-2
        else
            CONFIG=linux-aarch64; TRIPLE=aarch64-unknown-linux-gnu
            TOOLCHAIN=aarch64-unknown-linux-gnu-gcc-8.3.0-glibc-2.25-kernel-4.9-2
        fi
        # Match Kotlin 2.4.20's libc baseline, not the host distribution's libc (same LLVM 21 and sysroots as 2.4.0).
        case "$(uname -s):$(uname -m)" in
            Darwin:arm64) LLVM=llvm-21-aarch64-macos-essentials-97 ;;
            Darwin:x86_64) LLVM=llvm-21-x86_64-macos-essentials-83 ;;
            Linux:x86_64) LLVM=llvm-21-x86_64-linux-essentials-116 ;;
            *) echo "Linux targets need the Kotlin 2.4.20 macOS or Linux x64 toolchain" >&2; exit 1 ;;
        esac
        BIN="$DATA/dependencies/$LLVM/bin"
        if [[ ! -x "$BIN/clang" ]]; then BIN="$DATA/dependencies/${LLVM/essentials/dev}/bin"; fi
        SYSROOT="$DATA/dependencies/$TOOLCHAIN/$TRIPLE/sysroot"
        [[ -x "$BIN/clang" && -d "$SYSROOT" ]] || { echo "Bootstrap Kotlin/Native dependencies first; see README" >&2; exit 1; }
        export CC="$BIN/clang --target=$TRIPLE --sysroot=$SYSROOT"
        export AR="$BIN/llvm-ar" RANLIB="$BIN/llvm-ar s"
        ;;
    mingwX64)
        CONFIG=mingw64
        FLAGS+=(--cross-compile-prefix=x86_64-w64-mingw32-)
        ;;
    androidNativeArm64|androidNativeX64)
        : "${ANDROID_NDK_HOME:?Set ANDROID_NDK_HOME to a pinned Android NDK}"
        export ANDROID_NDK_ROOT="$ANDROID_NDK_HOME"
        if [[ "$(uname -s)" == Darwin ]]; then NDK_HOST=darwin-x86_64; else NDK_HOST=linux-x86_64; fi
        export PATH="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$NDK_HOST/bin:$PATH"
        if [[ "$TARGET" == androidNativeArm64 ]]; then
            CONFIG=android-arm64
            # Kotlin's older Android linker runtime lacks outlined atomic helpers.
            FLAGS+=(-mno-outline-atomics)
        else CONFIG=android-x86_64; fi
        FLAGS+=(-D__ANDROID_API__=21)
        ;;
    *) echo "Unsupported target: $TARGET" >&2; exit 1 ;;
esac

# Gradle composite builds do not share task history. Recheck under the process lock before replacing any files.
if [[ "$TARGET" == androidNative* ]]; then
    COMPILER=(clang)
else
    read -r -a COMPILER <<< "${CC:-x86_64-w64-mingw32-gcc}"
fi
COMPILER_VERSION=$("${COMPILER[@]}" --version)
FINGERPRINT=$({
    digest "$0" | awk '{print $1}'
    printf '%s\0' "$VERSION" "$SHA" "$TARGET" "$CONFIG" "${FLAGS[@]}" \
        "${CC:-}" "${AR:-}" "${RANLIB:-}" "${CFLAGS:-}" "${CPPFLAGS:-}" "${LDFLAGS:-}" \
        "${CROSS_TOP:-}" "${CROSS_SDK:-}" "${ANDROID_NDK_HOME:-}"
    printf '%s\n' "$COMPILER_VERSION"
    if [[ "$TARGET" == androidNative* ]]; then digest "$ANDROID_NDK_HOME/source.properties"; fi
} | digest /dev/stdin | awk '{print $1}')
STAMP="$PREFIX/.build-fingerprint"
if [[ -f "$STAMP" && "$(< "$STAMP")" == "$FINGERPRINT" &&
      -s "$PREFIX/lib/libssl.a" && -s "$PREFIX/lib/libcrypto.a" &&
      -s "$PREFIX/include/openssl/ssl.h" && -s "$PREFIX/include/openssl/configuration.h" &&
      -s "$PREFIX/build-info.txt" && -s "$PREFIX/LICENSE-OpenSSL.txt" ]]; then
    if [[ "$TARGET" != androidNative* || -s "$PREFIX/lib/libopenssl.a" ]]; then
        echo "Reusing OpenSSL $VERSION for $TARGET"
        exit 0
    fi
fi

# Each target gets its own source/build tree; no cross-target generated-header races.
rm -rf "$SOURCE" "$PREFIX"
mkdir -p "$SOURCE"
tar -xzf "$ARCHIVE" -C "$SOURCE" --strip-components=1
cd "$SOURCE"
perl ./Configure "$CONFIG" "${FLAGS[@]}"
echo "Building OpenSSL $VERSION for $TARGET (log: $BASE/build.log)"
if ! make -j"${JOBS:-4}" build_libs > "$BASE/build.log" 2>&1; then tail -n 80 "$BASE/build.log"; exit 1; fi
if ! make install_dev >> "$BASE/build.log" 2>&1; then tail -n 80 "$BASE/build.log"; exit 1; fi
if [[ "$TARGET" == androidNative* ]]; then
    # K/N may reorder embedded archives; one archive resolves SSL -> crypto references
    # with older Android linkers without an absolute library path at consumption time.
    llvm-ar -M <<EOF
CREATE $PREFIX/lib/libopenssl.a
ADDLIB $PREFIX/lib/libssl.a
ADDLIB $PREFIX/lib/libcrypto.a
SAVE
END
EOF
fi
cp LICENSE.txt "$PREFIX/LICENSE-OpenSSL.txt"
printf 'OpenSSL=%s\nsha256=%s\ntarget=%s\nconfiguration=%s\n' "$VERSION" "$SHA" "$TARGET" "$CONFIG" > "$PREFIX/build-info.txt"
printf '%s\n' "$FINGERPRINT" > "$STAMP"
