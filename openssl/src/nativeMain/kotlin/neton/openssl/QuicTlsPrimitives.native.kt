package neton.openssl

import kotlinx.cinterop.*
import neton.openssl.c.*

internal actual object QuicTlsPrimitives {
    private fun ctx(context: Long): CPointer<SSL_CTX> = context.toCPointer()!!
    private fun conn(connection: Long): CPointer<neton_qtls> = connection.toCPointer()!!

    /** [read] the size (null output), then the bytes. */
    private inline fun sized(size: (CPointer<UByteVar>?) -> Int): ByteArray {
        val n = size(null)
        if (n <= 0) return ByteArray(0)
        val out = ByteArray(n)
        out.withBytes { size(it) }
        return out
    }

    actual fun contextNew(server: Boolean, suites: String, groups: String?): Long =
        neton_qtls_ctx_new(if (server) 1 else 0, suites, groups).toLong()
    actual fun contextFree(context: Long) = neton_qtls_ctx_free(ctx(context))
    actual fun contextVerify(context: Long, mode: Int) = neton_qtls_ctx_verify(ctx(context), mode)
    actual fun contextAnchor(context: Long, der: ByteArray): Int = der.withBytes { neton_qtls_ctx_anchor(ctx(context), it, der.size) }
    actual fun contextIdentity(context: Long, certs: ByteArray, sizes: IntArray, key: ByteArray, keyIsPem: Boolean): Int =
        certs.withBytes { c -> sizes.usePinned { s -> key.withBytes { k ->
            neton_qtls_ctx_identity(ctx(context), c, s.addressOf(0), sizes.size, k, key.size, if (keyIsPem) 1 else 0)
        } } }
    actual fun contextKeyLog(context: Long) = neton_qtls_ctx_keylog(ctx(context))

    actual fun connectionNew(context: Long, server: Boolean, params: ByteArray, serverAlpn: ByteArray, keyLog: Boolean): Long =
        params.withBytes { p -> serverAlpn.withBytes { a ->
            neton_qtls_new(ctx(context), if (server) 1 else 0, p, params.size, a, serverAlpn.size, if (keyLog) 1 else 0)
        } }.toLong()
    actual fun connectionFree(connection: Long) = neton_qtls_free(conn(connection))
    actual fun serverName(connection: Long, name: String, ip: Boolean): Boolean = neton_qtls_server_name(conn(connection), name, if (ip) 1 else 0) == 1
    actual fun offerAlpn(connection: Long, wire: ByteArray): Boolean = wire.withBytes { neton_qtls_offer_alpn(conn(connection), it, wire.size) } == 1
    actual fun resume(connection: Long, der: ByteArray, early: Boolean, offered: ByteArray): Boolean =
        der.withBytes { d -> offered.withBytes { o -> neton_qtls_resume(conn(connection), d, der.size, if (early) 1 else 0, o, offered.size) } } == 1
    actual fun enableEarlyData(connection: Long): Boolean = neton_qtls_enable_early_data(conn(connection)) == 1
    actual fun inject(connection: Long, callback: Int) = neton_qtls_inject(conn(connection), callback)
    actual fun provide(connection: Long, bytes: ByteArray): Boolean = bytes.withBytes { neton_qtls_provide(conn(connection), it, bytes.size) } == 1
    actual fun incoming(connection: Long): Int = neton_qtls_incoming(conn(connection))
    actual fun drive(connection: Long, complete: Boolean): Int = neton_qtls_drive(conn(connection), if (complete) 1 else 0)
    actual fun initFinished(connection: Long): Boolean = neton_qtls_init_finished(conn(connection)) == 1
    actual fun takeOutgoing(connection: Long, level: Int): ByteArray = sized { neton_qtls_take_out(conn(connection), level, it) }
    actual fun takeSecret(connection: Long, level: Int, direction: Int): ByteArray? =
        sized { neton_qtls_take_secret(conn(connection), level, direction, it) }.takeIf { it.isNotEmpty() }
    actual fun suite(connection: Long, level: Int): Int = neton_qtls_suite(conn(connection), level)
    actual fun takeEarlySecret(connection: Long): ByteArray? = sized { neton_qtls_take_early_secret(conn(connection), it) }.takeIf { it.isNotEmpty() }
    actual fun peerParams(connection: Long): ByteArray? {
        val n = neton_qtls_peer_params(conn(connection), null)
        if (n < 0) return null
        val out = ByteArray(n)
        if (n > 0) out.withBytes { neton_qtls_peer_params(conn(connection), it) }
        return out
    }
    actual fun alert(connection: Long): Int = neton_qtls_alert_sent(conn(connection))
    actual fun failure(connection: Long): Int = neton_qtls_failure(conn(connection))
    actual fun failureMessage(connection: Long): String = neton_qtls_failure_message(conn(connection))?.toKString().orEmpty()
    actual fun alpn(connection: Long): ByteArray? = sized { neton_qtls_alpn(conn(connection), it) }.takeIf { it.isNotEmpty() }
    actual fun sni(connection: Long): String? = neton_qtls_sni(conn(connection))?.toKString()
    actual fun earlyAccepted(connection: Long): Boolean = neton_qtls_early_accepted(conn(connection)) == 1
    actual fun peerDer(connection: Long, index: Int): ByteArray? {
        val n = neton_qtls_peer_der(conn(connection), index, null)
        if (n == 0) return null
        if (n < 0) return ByteArray(0)
        val out = ByteArray(n)
        return if (out.withBytes { neton_qtls_peer_der(conn(connection), index, it) } == n) out else ByteArray(0)
    }
    actual fun takeTickets(connection: Long): ByteArray = sized { neton_qtls_take_tickets(conn(connection), it) }
    actual fun droppedTickets(connection: Long): Int = neton_qtls_dropped_tickets(conn(connection))
    actual fun takeKeyLog(connection: Long): ByteArray = sized { neton_qtls_take_keylog(conn(connection), it) }
    actual fun export(connection: Long, output: ByteArray, label: String, context: ByteArray): Int =
        output.withBytes { o -> context.withBytes { c -> neton_qtls_export(conn(connection), o, output.size, label, label.length, c, context.size) } }
    actual fun cleanShutdown(connection: Long) = neton_qtls_clean_shutdown(conn(connection))
    actual fun isCertificate(der: ByteArray): Boolean = der.withBytes { neton_qtls_is_certificate(it, der.size) } == 1
    actual fun isPrivateKey(key: ByteArray, pem: Boolean): Boolean = key.withBytes { neton_qtls_is_private_key(it, key.size, if (pem) 1 else 0) } == 1
    actual fun pemCertificates(pem: ByteArray): ByteArray = pem.withBytes { p -> sized { neton_qtls_pem_certificates(p, pem.size, it) } }
}
