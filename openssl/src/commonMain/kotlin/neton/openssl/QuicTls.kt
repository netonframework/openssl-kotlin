package neton.openssl

/**
 * OpenSSL's third-party QUIC TLS API as one facade for Kotlin/Native and the JVM (docs/QUIC_TLS.md). The callbacks
 * run in C (neton_quic_tls.h) and queue what they observe; [QuicTls] hands it out after each [QuicTls.drive]. It is
 * the TLS side of a QUIC connection only: levels, key hand-over and error mapping belong to the QUIC implementation.
 *
 * Protection levels are OpenSSL's: 0 none (Initial), 1 early, 2 handshake, 3 application. Directions: 0 read, 1 write.
 */
class QuicTlsContext(
    private val server: Boolean,
    /** TLS 1.3 cipher suites in OpenSSL's names, in preference order. */
    cipherSuites: List<String>,
    /** Key exchange groups in OpenSSL's list syntax; null keeps OpenSSL's default. */
    groups: String? = null,
    /** 0 verify nothing; 1 verify the peer if it presents a certificate (a client always gets one); 2 require one. */
    verifyMode: Int,
    /** DER trust anchors. */
    trustAnchorsDer: List<ByteArray> = emptyList(),
    /** Our certificate chain, DER, leaf first; with [privateKey]. */
    certificateChainDer: List<ByteArray>? = null,
    privateKey: ByteArray? = null,
    privateKeyIsPem: Boolean = false,
    /** Collect key-log lines ([QuicTls.takeKeyLog]). */
    private val keyLog: Boolean = false,
) : AutoCloseable {
    private val handle: SharedHandle
    init {
        require(cipherSuites.isNotEmpty()) { "no cipher suites" }
        require(cipherSuites.all { it.isNotEmpty() && it.all { c -> c.code in 0x21..0x7e && c != ':' } })
        require(groups == null || (groups.isNotEmpty() && '\u0000' !in groups)) { "invalid groups" }
        require(verifyMode in 0..2)
        require((certificateChainDer == null) == (privateKey == null)) { "a certificate needs its private key" }
        require(!server || certificateChainDer != null) { "a server needs a certificate" }
        require(certificateChainDer == null || certificateChainDer.isNotEmpty())
        val q = QuicTlsPrimitives
        Primitives.clearErrors()
        val ctx = q.contextNew(server, cipherSuites.joinToString(":"), groups)
        if (ctx == 0L) throw sslFailure("QUIC TLS context")
        try {
            q.contextVerify(ctx, verifyMode)
            for (der in trustAnchorsDer) if (q.contextAnchor(ctx, der) != 1) throw sslFailure("trust anchor")
            if (certificateChainDer != null && privateKey != null) {
                val sizes = IntArray(certificateChainDer.size) { certificateChainDer[it].size }
                val all = ByteArray(sizes.sum())
                var at = 0
                for (c in certificateChainDer) { c.copyInto(all, at); at += c.size }
                if (q.contextIdentity(ctx, all, sizes, privateKey, privateKeyIsPem) != 1) throw sslFailure("certificate chain / private key")
            }
            if (keyLog) q.contextKeyLog(ctx)
            handle = SharedHandle(ctx, q::contextFree)
        } catch (t: Throwable) {
            q.contextFree(ctx)
            Primitives.clearErrors()
            throw t
        }
    }

    /**
     * A connection: our transport parameters (encoded), and for a server its ALPN protocols in wire format (preference
     * order; empty for none). The connection keeps its own reference to the context.
     */
    fun newConnection(transportParameters: ByteArray, serverAlpnWire: ByteArray = ByteArray(0)): QuicTls = handle.access { ctx ->
        require(server || serverAlpnWire.isEmpty())
        Primitives.clearErrors()
        val h = QuicTlsPrimitives.connectionNew(ctx, server, transportParameters, serverAlpnWire, keyLog)
        if (h == 0L) throw sslFailure("QUIC TLS connection")
        QuicTls(h)
    }

    override fun close() = handle.close()
}

/** One QUIC connection's TLS. Not thread-safe; [close] frees it (OpenSSL first, then every buffer, wiped). */
class QuicTls internal constructor(handle: Long) : AutoCloseable {
    private val handle = KeyHandle(handle, QuicTlsPrimitives::connectionFree)
    private val q = QuicTlsPrimitives

    /** Client: verify the server against [name] (and send it as SNI) or, with [ip], an IP address. */
    fun setServerName(name: String, ip: Boolean): Boolean {
        require(name.isNotEmpty() && name.all { it.code in 0x21..0x7e })
        return handle.access { h -> q.serverName(h, name, ip).also { if (!it) Primitives.clearErrors() } }
    }

    /** Client: the protocols offered, wire format. */
    fun offerAlpn(wire: ByteArray): Boolean = handle.access { q.offerAlpn(it, wire) }

    /**
     * Client: resume the DER session [der]; with [earlyData], 0-RTT when the ticket allows it and its protocol is among
     * [offeredAlpnWire]. False when the ticket no longer parses (a full handshake follows).
     */
    fun resume(der: ByteArray, earlyData: Boolean, offeredAlpnWire: ByteArray): Boolean =
        handle.access { q.resume(it, der, earlyData, offeredAlpnWire) }

    /** Server: accept 0-RTT (max_early_data 0xffffffff for this session). */
    fun enableEarlyData(): Boolean = handle.access { q.enableEarlyData(it) }

    /** Make the named callback fail once (tests of the C boundary). */
    fun injectCallbackFailure(callback: QuicTlsCallback) = handle.access { q.inject(it, callback.ordinal) }

    /** CRYPTO bytes from the peer at the current read level; false when more than 64 KiB would be waiting. */
    fun provide(bytes: ByteArray): Boolean = handle.access { q.provide(it, bytes) }

    /** CRYPTO bytes given and not yet taken by OpenSSL. */
    val incoming: Int get() = handle.access { q.incoming(it) }

    /**
     * One OpenSSL call (SSL_do_handshake, or after [complete] SSL_read for post-handshake messages): 1 done, 0 wants
     * more input, -1 failed ([failure], [alert], the OpenSSL errors on this thread).
     */
    fun drive(complete: Boolean): Int = handle.access { q.drive(it, complete) }

    val initFinished: Boolean get() = handle.access { q.initFinished(it) }

    /** The handshake bytes OpenSSL produced at [level], taken. */
    fun takeOutgoing(level: Int): ByteArray = handle.access { q.takeOutgoing(it, level) }

    /** The secret of [level] and [direction], taken (wiped in C), or null. Its suite: [suite]. */
    fun takeSecret(level: Int, direction: Int): ByteArray? = handle.access { q.takeSecret(it, level, direction) }

    /** The TLS 1.3 suite code point of [level]'s secrets (level 1: the early secret's). */
    fun suite(level: Int): Int = handle.access { q.suite(it, level) }

    /** The early traffic secret (client write, server read), taken, or null. */
    fun takeEarlySecret(): ByteArray? = handle.access { q.takeEarlySecret(it) }

    /** The peer's transport parameters, or null before they arrived. */
    fun peerTransportParameters(): ByteArray? = handle.access { q.peerParams(it) }

    /** The alert OpenSSL sent, or -1. */
    val alert: Int get() = handle.access { q.alert(it) }

    /** The first failure a callback recorded ([QuicTlsFailure]), and its message. */
    val failure: QuicTlsFailure get() = handle.access { QuicTlsFailure.entries[q.failure(it)] }
    val failureMessage: String get() = handle.access { q.failureMessage(it) }

    fun selectedAlpn(): ByteArray? = handle.access { q.alpn(it) }
    fun serverName(): String? = handle.access { q.sni(it) }
    val earlyDataAccepted: Boolean get() = handle.access { q.earlyAccepted(it) }

    /** The peer's certificate chain as presented, leaf first, DER. */
    fun peerCertificates(): List<ByteArray> = handle.access { h ->
        val out = ArrayList<ByteArray>()
        while (true) {
            val der = q.peerDer(h, out.size) ?: break
            if (der.isEmpty()) throw sslFailure("peer certificate DER")
            out += der
        }
        out
    }

    /** Session tickets received (client): DER and whether each allows 0-RTT, taken. */
    fun takeTickets(): List<Pair<ByteArray, Boolean>> = handle.access { h ->
        val bytes = q.takeTickets(h)
        val out = ArrayList<Pair<ByteArray, Boolean>>()
        var at = 0
        while (at + 5 <= bytes.size) {
            val n = ((bytes[at].toInt() and 0xff) shl 24) or ((bytes[at + 1].toInt() and 0xff) shl 16) or
                ((bytes[at + 2].toInt() and 0xff) shl 8) or (bytes[at + 3].toInt() and 0xff)
            out += bytes.copyOfRange(at + 5, at + 5 + n) to (bytes[at + 4].toInt() != 0)
            at += 5 + n
        }
        out
    }
    val droppedTickets: Int get() = handle.access { q.droppedTickets(it) }

    /** Key-log lines (NSS format), taken; only with a context that logs keys. */
    fun takeKeyLog(): List<String> = handle.access { h ->
        val text = q.takeKeyLog(h).decodeToString()
        if (text.isEmpty()) emptyList() else text.removeSuffix("\n").split('\n')
    }

    /** RFC 5705 exporter with a context; false on failure (the output is wiped). ASCII labels only. */
    fun exportKeyingMaterial(output: ByteArray, label: String, context: ByteArray): Boolean {
        require(label.isNotEmpty() && label.all { it.code in 0x20..0x7e })
        return handle.access { h -> (q.export(h, output, label, context) == 1).also { if (!it) Crypto.wipe(output) } }
    }

    /** QUIC ends with CONNECTION_CLOSE: mark a clean end, so the server keeps the session for its tickets. */
    fun markCleanShutdown() = handle.access { q.cleanShutdown(it) }

    override fun close() = handle.close()
}

/** What a callback recorded (neton_quic_tls.h NETON_QTLS_FAIL_*). */
enum class QuicTlsFailure { NONE, INTERNAL, UNEXPECTED_MESSAGE, CALLBACK }

/** The callbacks a test can make fail (neton_quic_tls.h NETON_QTLS_CB_*). */
enum class QuicTlsCallback { CRYPTO_SEND, CRYPTO_RECV_RCD, CRYPTO_RELEASE_RCD, YIELD_SECRET, GOT_TRANSPORT_PARAMS, ALERT, ALPN_SELECT, CLIENT_HELLO, NEW_SESSION }

internal expect object QuicTlsPrimitives {
    fun contextNew(server: Boolean, suites: String, groups: String?): Long
    fun contextFree(context: Long)
    fun contextVerify(context: Long, mode: Int)
    fun contextAnchor(context: Long, der: ByteArray): Int
    fun contextIdentity(context: Long, certs: ByteArray, sizes: IntArray, key: ByteArray, keyIsPem: Boolean): Int
    fun contextKeyLog(context: Long)

    fun connectionNew(context: Long, server: Boolean, params: ByteArray, serverAlpn: ByteArray, keyLog: Boolean): Long
    fun connectionFree(connection: Long)
    fun serverName(connection: Long, name: String, ip: Boolean): Boolean
    fun offerAlpn(connection: Long, wire: ByteArray): Boolean
    fun resume(connection: Long, der: ByteArray, early: Boolean, offered: ByteArray): Boolean
    fun enableEarlyData(connection: Long): Boolean
    fun inject(connection: Long, callback: Int)
    fun provide(connection: Long, bytes: ByteArray): Boolean
    fun incoming(connection: Long): Int
    fun drive(connection: Long, complete: Boolean): Int
    fun initFinished(connection: Long): Boolean
    fun takeOutgoing(connection: Long, level: Int): ByteArray
    fun takeSecret(connection: Long, level: Int, direction: Int): ByteArray?
    fun suite(connection: Long, level: Int): Int
    fun takeEarlySecret(connection: Long): ByteArray?
    fun peerParams(connection: Long): ByteArray?
    fun alert(connection: Long): Int
    fun failure(connection: Long): Int
    fun failureMessage(connection: Long): String
    fun alpn(connection: Long): ByteArray?
    fun sni(connection: Long): String?
    fun earlyAccepted(connection: Long): Boolean
    fun peerDer(connection: Long, index: Int): ByteArray?
    fun takeTickets(connection: Long): ByteArray
    fun droppedTickets(connection: Long): Int
    fun takeKeyLog(connection: Long): ByteArray
    fun export(connection: Long, output: ByteArray, label: String, context: ByteArray): Int
    fun cleanShutdown(connection: Long)
}
