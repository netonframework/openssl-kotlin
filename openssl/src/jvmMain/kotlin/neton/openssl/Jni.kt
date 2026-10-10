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

    // Byte-stream TLS (neton_tls.h).
    @JvmStatic external fun tlsContextNew(minimum: Int, maximum: Int, verify: Int): Long
    @JvmStatic external fun tlsContextFree(context: Long)
    @JvmStatic external fun tlsVerifyMode(server: Boolean, clientAuthentication: Int): Int
    @JvmStatic external fun tlsLimits(context: Long, depth: Int, bytes: Int)
    @JvmStatic external fun tlsRoots(context: Long, pem: ByteArray): Int
    @JvmStatic external fun tlsDefaultPaths(context: Long): Int
    @JvmStatic external fun tlsIdentity(context: Long, chain: ByteArray, key: ByteArray): Int
    @JvmStatic external fun tlsCipherList(context: Long, list: String): Int
    @JvmStatic external fun tlsCipherSuites(context: Long, suites: String): Int
    @JvmStatic external fun tlsGroups(context: Long, groups: String): Int
    @JvmStatic external fun tlsNew(context: Long, server: Boolean, identity: String?, ip: Boolean, alpn: ByteArray, capacity: Int): Long
    @JvmStatic external fun tlsFree(engine: Long)
    @JvmStatic external fun tlsReady(engine: Long): Boolean
    @JvmStatic external fun tlsFailed(engine: Long): Boolean
    @JvmStatic external fun tlsPendingWrite(engine: Long): Int
    @JvmStatic external fun tlsPendingCiphertext(engine: Long): Int
    @JvmStatic external fun tlsSentClose(engine: Long): Boolean
    @JvmStatic external fun tlsFailureKind(engine: Long): Int
    @JvmStatic external fun tlsVerifyCode(engine: Long): Int
    @JvmStatic external fun tlsAlertCode(engine: Long): Int
    @JvmStatic external fun tlsAlpn(engine: Long): ByteArray?
    @JvmStatic external fun tlsVersionName(engine: Long): String?
    @JvmStatic external fun tlsCipherName(engine: Long): String?
    @JvmStatic external fun tlsServerName(engine: Long): String?
    @JvmStatic external fun tlsPeerDer(engine: Long, index: Int): ByteArray?
    @JvmStatic external fun tlsHandshake(engine: Long): Int
    @JvmStatic external fun tlsFeed(engine: Long, input: ByteArray, offset: Int, length: Int): Int
    @JvmStatic external fun tlsDrain(engine: Long, output: ByteArray, offset: Int, length: Int): Int
    @JvmStatic external fun tlsEof(engine: Long)
    @JvmStatic external fun tlsRead(engine: Long, output: ByteArray, offset: Int, length: Int): Int
    @JvmStatic external fun tlsWrite(engine: Long, input: ByteArray, offset: Int, length: Int): Int
    @JvmStatic external fun tlsShutdown(engine: Long): Int
    @JvmStatic external fun tlsExport(engine: Long, output: ByteArray, label: String, context: ByteArray?): Int

    // QUIC TLS (neton_quic_tls.h).
    @JvmStatic external fun qtlsContextNew(server: Boolean, suites: String, groups: String?): Long
    @JvmStatic external fun qtlsContextFree(context: Long)
    @JvmStatic external fun qtlsContextVerify(context: Long, mode: Int)
    @JvmStatic external fun qtlsContextAnchor(context: Long, der: ByteArray): Int
    @JvmStatic external fun qtlsContextIdentity(context: Long, certs: ByteArray, sizes: IntArray, key: ByteArray, pem: Boolean): Int
    @JvmStatic external fun qtlsContextKeyLog(context: Long)
    @JvmStatic external fun qtlsNew(context: Long, server: Boolean, params: ByteArray, alpn: ByteArray, keyLog: Boolean): Long
    @JvmStatic external fun qtlsFree(connection: Long)
    @JvmStatic external fun qtlsServerName(connection: Long, name: String, ip: Boolean): Boolean
    @JvmStatic external fun qtlsOfferAlpn(connection: Long, wire: ByteArray): Boolean
    @JvmStatic external fun qtlsResume(connection: Long, der: ByteArray, early: Boolean, offered: ByteArray): Boolean
    @JvmStatic external fun qtlsEnableEarlyData(connection: Long): Boolean
    @JvmStatic external fun qtlsInject(connection: Long, callback: Int)
    @JvmStatic external fun qtlsProvide(connection: Long, bytes: ByteArray): Boolean
    @JvmStatic external fun qtlsIncoming(connection: Long): Int
    @JvmStatic external fun qtlsDrive(connection: Long, complete: Boolean): Int
    @JvmStatic external fun qtlsInitFinished(connection: Long): Boolean
    @JvmStatic external fun qtlsTakeOutgoing(connection: Long, level: Int): ByteArray
    @JvmStatic external fun qtlsTakeSecret(connection: Long, level: Int, direction: Int): ByteArray?
    @JvmStatic external fun qtlsSuite(connection: Long, level: Int): Int
    @JvmStatic external fun qtlsTakeEarlySecret(connection: Long): ByteArray?
    @JvmStatic external fun qtlsPeerParams(connection: Long): ByteArray?
    @JvmStatic external fun qtlsAlert(connection: Long): Int
    @JvmStatic external fun qtlsFailure(connection: Long): Int
    @JvmStatic external fun qtlsFailureMessage(connection: Long): String
    @JvmStatic external fun qtlsAlpn(connection: Long): ByteArray?
    @JvmStatic external fun qtlsSni(connection: Long): String?
    @JvmStatic external fun qtlsEarlyAccepted(connection: Long): Boolean
    @JvmStatic external fun qtlsPeerDer(connection: Long, index: Int): ByteArray?
    @JvmStatic external fun qtlsTakeTickets(connection: Long): ByteArray
    @JvmStatic external fun qtlsDroppedTickets(connection: Long): Int
    @JvmStatic external fun qtlsTakeKeyLog(connection: Long): ByteArray
    @JvmStatic external fun qtlsExport(connection: Long, output: ByteArray, label: String, context: ByteArray): Int
    @JvmStatic external fun qtlsCleanShutdown(connection: Long)
    @JvmStatic external fun qtlsIsCertificate(der: ByteArray): Boolean
    @JvmStatic external fun qtlsIsPrivateKey(key: ByteArray, pem: Boolean): Boolean
    @JvmStatic external fun qtlsPemCertificates(pem: ByteArray): ByteArray
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
