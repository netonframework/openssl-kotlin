package neton.openssl

import kotlinx.cinterop.*
import neton.openssl.c.*

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
    private val handle: SharedNativeHandle<SSL_CTX>
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
        val verify = if (!server || clientAuthentication != ClientAuthentication.NONE) SSL_VERIFY_PEER else SSL_VERIFY_NONE
        val mode = verify or if (clientAuthentication == ClientAuthentication.REQUIRE) SSL_VERIFY_FAIL_IF_NO_PEER_CERT else 0
        val context = neton_tls_context_new(minimumVersion.wire, maximumVersion.wire, mode) ?: throw sslFailure("TLS context")
        try {
            neton_tls_limits(context, verifyDepth, maxCertificateListBytes)
            if (trustRootsPem != null && trustRootsPem.withBytes { neton_tls_roots(context, it, trustRootsPem.size) } != 1) throw sslFailure("PEM trust roots")
            if (useOpenSslDefaultTrustPaths && SSL_CTX_set_default_verify_paths(context) != 1) throw sslFailure("Default trust paths")
            if (certificateChainPem != null && privateKeyPem != null) {
                val result = certificateChainPem.withBytes { chain -> privateKeyPem.withBytes { key ->
                    neton_tls_identity(context, chain, certificateChainPem.size, key, privateKeyPem.size)
                } }
                if (result != 1) throw sslFailure("Certificate/private key")
            }
            if (cipherList != null && SSL_CTX_set_cipher_list(context, cipherList) != 1) throw sslFailure("TLS1.2 cipher list")
            if (cipherSuites != null && SSL_CTX_set_ciphersuites(context, cipherSuites) != 1) throw sslFailure("TLS1.3 cipher suites")
            if (groups != null && neton_tls_groups(context, groups) != 1) throw sslFailure("TLS groups")
            handle = SharedNativeHandle(context, ::SSL_CTX_free)
        } catch (error: Throwable) { SSL_CTX_free(context); throw error }
    }

    /** Existing engines retain the OpenSSL context even after this factory is closed. */
    fun newEngine(peer: PeerIdentity? = null, bufferCapacity: Int = 16384): TlsEngine {
        require(bufferCapacity in 1024..1048576)
        require(if (server) peer == null else peer != null)
        return handle.access { context ->
            val engine = protocols.withBytes { neton_tls_new(context, if (server) 1 else 0,
                peer?.value, if (peer is PeerIdentity.Ip) 1 else 0, it, protocols.size, bufferCapacity) }
                ?: throw sslFailure("TLS engine")
            try { TlsEngine(engine) } catch (error: Throwable) { neton_tls_free(engine); throw error }
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
class TlsEngine internal constructor(pointer: CPointer<neton_tls>) : AutoCloseable {
    private val handle = NativeHandle(pointer, ::neton_tls_free)

    val handshakeComplete: Boolean get() = handle.access { neton_tls_ready(it) == 1 && it.pointed.failed == 0 }
    val pendingCiphertext: Int get() = handle.access { neton_tls_pending(it) }
    val closeNotifySent: Boolean get() = handle.access { neton_tls_sent_close(it) == 1 }
    val negotiatedAlpn: String? get() = handle.access {
        val size = neton_tls_alpn_copy(it, null)
        if (size == 0) null else ByteArray(size).also { out -> out.withBytes { ptr -> neton_tls_alpn_copy(it, ptr) } }.decodeToString()
    }
    val protocolVersion: String? get() = handle.access { if (neton_tls_ready(it) == 1) SSL_get_version(it.pointed.ssl)?.toKString() else null }
    val cipherSuite: String? get() = handle.access {
        if (neton_tls_ready(it) == 1) SSL_CIPHER_get_name(SSL_get_current_cipher(it.pointed.ssl))?.toKString() else null
    }
    val serverName: String? get() = handle.access { neton_tls_sni(it)?.toKString() }

    /** Copied peer-presented chain, leaf first. This is not a separate authorization decision. */
    fun peerCertificateChainDer(): List<ByteArray> = handle.access { engine ->
        active(engine); check(neton_tls_ready(engine) == 1) { "Handshake not complete" }
        val result = mutableListOf<ByteArray>()
        var index = 0
        while (true) {
            val size = neton_tls_peer_der(engine, index, null)
            if (size == 0) break
            if (size < 0) throw sslFailure("Peer certificate DER")
            val bytes = ByteArray(size)
            if (bytes.withBytes { neton_tls_peer_der(engine, index, it) } != size) throw sslFailure("Peer certificate DER")
            result += bytes; index++
        }
        result
    }

    fun handshake(): TlsProgress = handle.access { active(it); noPendingWrite(it); progress(it, neton_tls_handshake(it)) }

    /** Returns bytes consumed, possibly zero. Caller retains the remainder and applies backpressure. */
    fun feedCiphertext(input: ByteArray, offset: Int = 0, length: Int = input.size - offset): Int {
        checkRange(input, offset, length)
        return handle.access { engine ->
            active(engine)
            if (length == 0) 0 else input.withBytes(offset, length) { neton_tls_feed(engine, it, length) }.also {
                check(it >= 0) { "Cannot feed a closed ciphertext input" }
            }
        }
    }
    /** Permitted after TLS failure so the caller can send a generated alert. */
    fun drainCiphertext(output: ByteArray, offset: Int = 0, length: Int = output.size - offset): Int {
        checkRange(output, offset, length)
        return handle.access { engine ->
            if (length == 0) 0 else output.withBytes(offset, length) { neton_tls_drain(engine, it, length) }.also {
                if (it < 0) throw sslFailure("TLS ciphertext drain")
            }
        }
    }
    fun transportEof() = handle.access { neton_tls_eof(it) }

    /** Positive = bytes, NEED_READ/NEED_WRITE = retry, PEER_CLOSED = authenticated close_notify. */
    fun read(output: ByteArray, offset: Int = 0, length: Int = output.size - offset): Int {
        checkRange(output, offset, length); require(length > 0)
        return handle.access { engine -> active(engine); noPendingWrite(engine)
            checked(engine, output.withBytes(offset, length) { neton_tls_read(engine, it, length) })
        }
    }
    /** At most 16KiB. A WANT result requires the exact same bytes/length on retry; no buffer is retained. */
    fun write(input: ByteArray, offset: Int = 0, length: Int = input.size - offset): Int {
        checkRange(input, offset, length); require(length in 1..16384)
        return handle.access { engine -> active(engine)
            check(neton_tls_ready(engine) == 1) { "Complete the handshake before application writes" }
            check(neton_tls_sent_close(engine) == 0) { "TLS output is closed" }
            val result = input.withBytes(offset, length) { neton_tls_write(engine, it, length) }
            require(result != -6) { "Retry must contain exactly the same plaintext" }
            checked(engine, result)
        }
    }
    fun closeNotify(): TlsProgress = handle.access {
        active(it); noPendingWrite(it)
        check(neton_tls_ready(it) == 1) { "Handshake not complete" }
        progress(it, neton_tls_shutdown(it))
    }

    fun exportKeyingMaterial(label: String, context: ByteArray?, output: ByteArray) {
        require(label.isNotEmpty() && label.length <= 255 && label.all { it.code in 0x20..0x7e })
        require(output.size in 1..65535 && (context?.size ?: 0) <= 65535)
        require(output !== context)
        handle.access { engine ->
            active(engine); check(neton_tls_ready(engine) == 1) { "Handshake not complete" }
            val result = output.withBytes { dst ->
                if (context == null) neton_tls_export(engine, dst, output.size, label, label.length, null, 0, 0)
                else context.withBytes { neton_tls_export(engine, dst, output.size, label, label.length, it, context.size, 1) }
            }
            if (result != 1) { Crypto.wipe(output); throw sslFailure("TLS exporter") }
        }
    }

    override fun close() = handle.close()
    private fun active(engine: CPointer<neton_tls>) { check(engine.pointed.failed == 0) { "TLS engine has failed; drain alerts then close" } }
    private fun noPendingWrite(engine: CPointer<neton_tls>) { check(engine.pointed.pending_size == 0) { "Retry pending write or close the engine" } }
    private fun checked(engine: CPointer<neton_tls>, result: Int): Int {
        if (result != -1) return result
        val verify = engine.pointed.verify
        val kind = when {
            verify == X509_V_ERR_HOSTNAME_MISMATCH || verify == X509_V_ERR_IP_ADDRESS_MISMATCH -> TlsFailureKind.HOSTNAME
            verify == X509_V_ERR_CERT_HAS_EXPIRED -> TlsFailureKind.EXPIRED
            verify != X509_V_OK -> TlsFailureKind.CERTIFICATE
            engine.pointed.reason == SSL_R_UNEXPECTED_EOF_WHILE_READING -> TlsFailureKind.UNEXPECTED_EOF
            else -> TlsFailureKind.PROTOCOL
        }
        throw TlsException(kind, verify, engine.pointed.alert.takeIf { it >= 0 }, sslFailure("TLS").message.orEmpty())
    }
    private fun progress(engine: CPointer<neton_tls>, result: Int): TlsProgress = when (checked(engine, result)) {
        1 -> TlsProgress.COMPLETE
        NEED_READ -> TlsProgress.NEED_READ
        NEED_WRITE -> TlsProgress.NEED_WRITE
        PEER_CLOSED -> TlsProgress.PEER_CLOSED
        else -> error("Unexpected TLS progress")
    }
    companion object { const val NEED_READ = -2; const val NEED_WRITE = -3; const val PEER_CLOSED = -4 }
}
