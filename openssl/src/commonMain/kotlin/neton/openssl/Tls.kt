@file:OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
package neton.openssl

import kotlin.concurrent.atomics.AtomicInt

enum class TlsVersion(internal val wire: Int) { TLS12(0x0303), TLS13(0x0304) }
enum class ClientAuthentication { NONE, REQUEST, REQUIRE }
enum class TlsProgress { COMPLETE, NEED_READ, NEED_WRITE, PEER_CLOSED }
enum class TlsFailureKind { CERTIFICATE, HOSTNAME, EXPIRED, UNEXPECTED_EOF, PROTOCOL }
class TlsException(val kind: TlsFailureKind, val verificationCode: Int, val alertCode: Int?, message: String) : OpenSslException(message)

/** DNS names must already be ASCII/IDNA; IP identity uses certificate IP SAN matching, not DNS matching. */
sealed class PeerIdentity(val value: String) {
    class Dns(value: String) : PeerIdentity(value)
    class Ip(value: String) : PeerIdentity(value)
    init { require(value.isNotEmpty() && value.all { it.code in 0x21..0x7e }) }
}

/** For frozen native factories only: concurrent access allowed; close refuses while an operation is active. */
internal class SharedHandle(private val handle: Long, private val release: (Long) -> Unit) : AutoCloseable {
    private val readers = AtomicInt(0)
    inline fun <R> access(block: (Long) -> R): R {
        while (true) {
            val n = readers.load()
            check(n >= 0) { "Native factory is closed" }
            check(n < Int.MAX_VALUE) { "Too many concurrent factory operations" }
            if (readers.compareAndSet(n, n + 1)) break
        }
        try { return block(handle) } finally { readers.fetchAndAdd(-1) }
    }
    override fun close() {
        if (readers.compareAndSet(0, -1)) release(handle)
        else check(readers.load() == -1) { "Close requires no concurrent factory operation" }
    }
}

/** Frozen factory: concurrent newEngine calls allowed. Close only after factory users stop. */
class TlsContext(
    private val server: Boolean,
    trustRootsPem: ByteArray? = null,
    certificateChainPem: ByteArray? = null,
    privateKeyPem: ByteArray? = null,
    minimumVersion: TlsVersion = TlsVersion.TLS12,
    maximumVersion: TlsVersion = TlsVersion.TLS13,
    alpnProtocols: List<String> = emptyList(),
    clientAuthentication: ClientAuthentication = ClientAuthentication.NONE,
    cipherList: String? = null,
    cipherSuites: String? = null,
    groups: String? = null,
    useOpenSslDefaultTrustPaths: Boolean = false,
    verifyDepth: Int = 16,
    maxCertificateListBytes: Int = 262144
) : AutoCloseable {
    private val protocols = encodeAlpn(alpnProtocols)
    private val handle: SharedHandle
    init {
        require(minimumVersion.wire <= maximumVersion.wire)
        require(verifyDepth in 1..100 && maxCertificateListBytes in 16384..4194304)
        require(server || clientAuthentication == ClientAuthentication.NONE)
        require(!server || certificateChainPem != null) { "Server requires a certificate" }
        require((certificateChainPem == null) == (privateKeyPem == null))
        require(server && clientAuthentication == ClientAuthentication.NONE || trustRootsPem != null || useOpenSslDefaultTrustPaths) {
            "Explicit trust roots are required; default OpenSSL paths are an opt-in, not an OS trust store"
        }
        for (pem in listOfNotNull(trustRootsPem, certificateChainPem, privateKeyPem)) require(pem.isNotEmpty() && pem.size <= 4 * 1024 * 1024)
        for (setting in listOfNotNull(cipherList, cipherSuites, groups)) require(setting.isNotEmpty() && '\u0000' !in setting)
        val t = TlsPrimitives
        Primitives.clearErrors()
        val mode = t.verifyMode(server, clientAuthentication.ordinal)
        val context = t.contextNew(minimumVersion.wire, maximumVersion.wire, mode)
        if (context == 0L) throw sslFailure("TLS context")
        try {
            t.limits(context, verifyDepth, maxCertificateListBytes)
            if (trustRootsPem != null && t.roots(context, trustRootsPem) != 1) throw sslFailure("PEM trust roots")
            if (useOpenSslDefaultTrustPaths && t.defaultPaths(context) != 1) throw sslFailure("Default trust paths")
            if (certificateChainPem != null && privateKeyPem != null && t.identity(context, certificateChainPem, privateKeyPem) != 1) {
                throw sslFailure("Certificate/private key")
            }
            if (cipherList != null && t.cipherList(context, cipherList) != 1) throw sslFailure("TLS1.2 cipher list")
            if (cipherSuites != null && t.cipherSuites(context, cipherSuites) != 1) throw sslFailure("TLS1.3 cipher suites")
            if (groups != null && t.groups(context, groups) != 1) throw sslFailure("TLS groups")
            handle = SharedHandle(context, t::contextFree)
        } catch (error: Throwable) { t.contextFree(context); throw error }
    }

    /** Existing engines retain the OpenSSL context even after this factory is closed. */
    fun newEngine(peer: PeerIdentity? = null, bufferCapacity: Int = 16384): TlsEngine {
        require(bufferCapacity in 1024..1048576)
        require(if (server) peer == null else peer != null)
        return handle.access { context ->
            Primitives.clearErrors()
            val engine = TlsPrimitives.engineNew(context, server, peer?.value, peer is PeerIdentity.Ip, protocols, bufferCapacity)
            if (engine == 0L) throw sslFailure("TLS engine")
            try { TlsEngine(engine) } catch (error: Throwable) { TlsPrimitives.engineFree(engine); throw error }
        }
    }
    override fun close() = handle.close()

    private fun encodeAlpn(protocols: List<String>): ByteArray {
        var size = 0
        for (protocol in protocols) {
            require(protocol.length in 1..255 && protocol.all { it.code in 0x21..0x7e })
            require(size <= 65535 - protocol.length - 1)
            size += protocol.length + 1
        }
        val result = ByteArray(size); var offset = 0
        for (protocol in protocols) { result[offset++] = protocol.length.toByte(); for (char in protocol) result[offset++] = char.code.toByte() }
        return result
    }
}

/** Sans-I/O, bounded ciphertext buffers and a single 16KiB write-retry buffer. Not thread-safe. */
class TlsEngine internal constructor(engine: Long) : AutoCloseable {
    private val handle = KeyHandle(engine, TlsPrimitives::engineFree)
    private val t = TlsPrimitives

    val handshakeComplete: Boolean get() = handle.access { t.ready(it) && !t.failed(it) }
    val pendingCiphertext: Int get() = handle.access { t.pendingCiphertext(it) }
    val closeNotifySent: Boolean get() = handle.access { t.sentClose(it) }
    val negotiatedAlpn: String? get() = handle.access { t.alpn(it)?.decodeToString() }
    val protocolVersion: String? get() = handle.access { t.versionName(it) }
    val cipherSuite: String? get() = handle.access { t.cipherName(it) }
    val serverName: String? get() = handle.access { t.serverName(it) }

    /** Copied peer-presented chain, leaf first. This is not a separate authorization decision. */
    fun peerCertificateChainDer(): List<ByteArray> = handle.access { engine ->
        active(engine); check(t.ready(engine)) { "Handshake not complete" }
        val result = mutableListOf<ByteArray>()
        var index = 0
        while (true) {
            val der = t.peerDer(engine, index) ?: break
            if (der.isEmpty()) throw sslFailure("Peer certificate DER")
            result += der; index++
        }
        result
    }

    fun handshake(): TlsProgress = handle.access { active(it); noPendingWrite(it); progress(it, t.handshake(it)) }

    /** Returns bytes consumed, possibly zero. Caller retains the remainder and applies backpressure. */
    fun feedCiphertext(input: ByteArray, offset: Int = 0, length: Int = input.size - offset): Int {
        checkRange(input, offset, length)
        return handle.access { engine ->
            active(engine)
            if (length == 0) 0 else t.feed(engine, input, offset, length).also {
                check(it >= 0) { "Cannot feed a closed ciphertext input" }
            }
        }
    }
    /** Permitted after TLS failure so the caller can send a generated alert. */
    fun drainCiphertext(output: ByteArray, offset: Int = 0, length: Int = output.size - offset): Int {
        checkRange(output, offset, length)
        return handle.access { engine ->
            if (length == 0) 0 else t.drain(engine, output, offset, length).also {
                if (it < 0) throw sslFailure("TLS ciphertext drain")
            }
        }
    }
    fun transportEof() = handle.access { t.eof(it) }

    /** Positive = bytes, NEED_READ/NEED_WRITE = retry, PEER_CLOSED = authenticated close_notify. */
    fun read(output: ByteArray, offset: Int = 0, length: Int = output.size - offset): Int {
        checkRange(output, offset, length); require(length > 0)
        return handle.access { engine -> active(engine); noPendingWrite(engine)
            checked(engine, t.read(engine, output, offset, length))
        }
    }
    /** At most 16KiB. A WANT result requires the exact same bytes/length on retry; no buffer is retained. */
    fun write(input: ByteArray, offset: Int = 0, length: Int = input.size - offset): Int {
        checkRange(input, offset, length); require(length in 1..16384)
        return handle.access { engine -> active(engine)
            check(t.ready(engine)) { "Complete the handshake before application writes" }
            check(!t.sentClose(engine)) { "TLS output is closed" }
            val result = t.write(engine, input, offset, length)
            require(result != -6) { "Retry must contain exactly the same plaintext" }
            checked(engine, result)
        }
    }
    fun closeNotify(): TlsProgress = handle.access {
        active(it); noPendingWrite(it)
        check(t.ready(it)) { "Handshake not complete" }
        progress(it, t.shutdown(it))
    }

    fun exportKeyingMaterial(label: String, context: ByteArray?, output: ByteArray) {
        require(label.isNotEmpty() && label.length <= 255 && label.all { it.code in 0x20..0x7e })
        require(output.size in 1..65535 && (context?.size ?: 0) <= 65535)
        require(output !== context)
        handle.access { engine ->
            active(engine); check(t.ready(engine)) { "Handshake not complete" }
            if (t.export(engine, output, label, context) != 1) { Crypto.wipe(output); throw sslFailure("TLS exporter") }
        }
    }

    override fun close() = handle.close()
    private fun active(engine: Long) { check(!t.failed(engine)) { "TLS engine has failed; drain alerts then close" } }
    private fun noPendingWrite(engine: Long) { check(t.pendingWrite(engine) == 0) { "Retry pending write or close the engine" } }
    private fun checked(engine: Long, result: Int): Int {
        if (result != -1) return result
        val kind = TlsFailureKind.entries[t.failureKind(engine)]
        throw TlsException(kind, t.verifyCode(engine), t.alertCode(engine).takeIf { it >= 0 }, sslFailure("TLS").message.orEmpty())
    }
    private fun progress(engine: Long, result: Int): TlsProgress = when (checked(engine, result)) {
        1 -> TlsProgress.COMPLETE
        NEED_READ -> TlsProgress.NEED_READ
        NEED_WRITE -> TlsProgress.NEED_WRITE
        PEER_CLOSED -> TlsProgress.PEER_CLOSED
        else -> error("Unexpected TLS progress")
    }
    companion object { const val NEED_READ = -2; const val NEED_WRITE = -3; const val PEER_CLOSED = -4 }
}
