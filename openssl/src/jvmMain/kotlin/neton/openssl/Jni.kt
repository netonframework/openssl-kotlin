package neton.openssl

import java.io.File
import java.io.FileOutputStream

/**
 * The JNI entry points of `libneton_openssl` (src/jvmNative/neton_openssl_jni.c), loaded once. Arguments are checked
 * by the callers ([Primitives]); every array is pinned only for the duration of one call.
 */
internal object Jni {
    init { NativeLibrary.load() }

    @JvmStatic external fun version(): String
    @JvmStatic external fun versionNumbers(out: IntArray)
    @JvmStatic external fun nextError(): String?
    @JvmStatic external fun clearErrors()
    @JvmStatic external fun randomFill(out: ByteArray, offset: Int, length: Int): Int
    @JvmStatic external fun aeadNew(algorithm: Int, key: ByteArray): Long
    @JvmStatic external fun aeadFree(handle: Long)
    @JvmStatic external fun aeadSeal(handle: Long, data: ByteArray, offset: Int, size: Int, nonce: ByteArray, aad: ByteArray): Int
    @JvmStatic external fun aeadOpen(handle: Long, data: ByteArray, offset: Int, size: Int, nonce: ByteArray, aad: ByteArray): Int
    @JvmStatic external fun maskNew(algorithm: Int, key: ByteArray): Long
    @JvmStatic external fun maskFree(handle: Long)
    @JvmStatic external fun maskApply(handle: Long, sample: ByteArray, sampleOffset: Int, output: ByteArray, outputOffset: Int): Int
    @JvmStatic external fun hash(algorithm: Int, input: ByteArray, output: ByteArray, outputOffset: Int): Int
    @JvmStatic external fun hmac(algorithm: Int, key: ByteArray, input: ByteArray, output: ByteArray, outputOffset: Int): Int
    @JvmStatic external fun hkdf(algorithm: Int, expand: Boolean, key: ByteArray, salt: ByteArray?, info: ByteArray?, output: ByteArray, offset: Int, length: Int): Int
    @JvmStatic external fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean
    @JvmStatic external fun wipe(array: ByteArray)
}

/**
 * Finds and loads `libneton_openssl` (docs/JVM.md): the file named by the `neton.openssl.library` system property;
 * on Android the app's own `libneton_openssl.so` (from the AAR); otherwise the copy for this OS and architecture in
 * the jar, `META-INF/native/<os>-<arch>/`, extracted to a temporary file. A missing library is an
 * [UnsatisfiedLinkError] naming the platform and the path looked up, never a silent fallback.
 */
internal object NativeLibrary {
    private const val NAME = "neton_openssl"

    fun load() {
        val explicit = System.getProperty("neton.openssl.library")
        when {
            explicit != null -> System.load(File(explicit).absolutePath)
            isAndroid() -> System.loadLibrary(NAME)
            else -> System.load(extract().absolutePath)
        }
    }

    private fun isAndroid(): Boolean =
        System.getProperty("java.vm.name").orEmpty().contains("Dalvik", ignoreCase = true) ||
            System.getProperty("java.vendor").orEmpty().contains("Android", ignoreCase = true)

    /** `<os>-<arch>` as the jar lays the libraries out: linux, macos, windows; x64, arm64. */
    internal fun platform(): String {
        val os = System.getProperty("os.name").orEmpty().lowercase()
        val arch = System.getProperty("os.arch").orEmpty().lowercase()
        val o = when {
            os.startsWith("linux") -> "linux"
            os.startsWith("mac") || os.startsWith("darwin") -> "macos"
            os.startsWith("windows") -> "windows"
            else -> throw UnsatisfiedLinkError("libneton_openssl: unsupported operating system '$os'")
        }
        val a = when (arch) {
            "amd64", "x86_64", "x64" -> "x64"
            "aarch64", "arm64" -> "arm64"
            else -> throw UnsatisfiedLinkError("libneton_openssl: unsupported architecture '$arch'")
        }
        return "$o-$a"
    }

    private fun fileName(platform: String) = when {
        platform.startsWith("windows") -> "$NAME.dll"
        platform.startsWith("macos") -> "lib$NAME.dylib"
        else -> "lib$NAME.so"
    }

    private fun extract(): File {
        val platform = platform()
        val name = fileName(platform)
        val resource = "/META-INF/native/$platform/$name"
        val input = NativeLibrary::class.java.getResourceAsStream(resource)
            ?: throw UnsatisfiedLinkError("libneton_openssl: no $resource in the classpath for $platform")
        val dir = File(System.getProperty("java.io.tmpdir"), "neton-openssl-${ProcessHandleCompat.id()}")
        dir.mkdirs()
        val file = File(dir, name)
        input.use { src -> FileOutputStream(file).use { dst -> src.copyTo(dst) } }
        file.deleteOnExit(); dir.deleteOnExit()
        return file
    }
}

/** A per-process name for the extraction directory (bytecode 1.8: no ProcessHandle). */
private object ProcessHandleCompat {
    fun id(): String {
        val name = java.lang.management.ManagementFactory.getRuntimeMXBean().name   // "pid@host"
        return name.substringBefore('@').ifEmpty { System.nanoTime().toString() } + "-" + System.nanoTime()
    }
}
