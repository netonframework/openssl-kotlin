package neton.openssl

import kotlinx.cinterop.*
import neton.openssl.c.*

internal actual object TlsPrimitives {
    private fun ctx(context: Long): CPointer<SSL_CTX> = context.toCPointer()!!
    private fun tls(engine: Long): CPointer<neton_tls> = engine.toCPointer()!!

    actual fun contextNew(minimum: Int, maximum: Int, verifyMode: Int): Long = neton_tls_context_new(minimum, maximum, verifyMode).toLong()
    actual fun contextFree(context: Long) = neton_tls_context_free(ctx(context))
    actual fun verifyMode(server: Boolean, clientAuthentication: Int): Int = neton_tls_verify_mode(if (server) 1 else 0, clientAuthentication)
    actual fun limits(context: Long, depth: Int, bytes: Int) = neton_tls_limits(ctx(context), depth, bytes)
    actual fun roots(context: Long, pem: ByteArray): Int = pem.withBytes { neton_tls_roots(ctx(context), it, pem.size) }
    actual fun defaultPaths(context: Long): Int = neton_tls_default_paths(ctx(context))
    actual fun identity(context: Long, chain: ByteArray, key: ByteArray): Int =
        chain.withBytes { c -> key.withBytes { k -> neton_tls_identity(ctx(context), c, chain.size, k, key.size) } }
    actual fun cipherList(context: Long, list: String): Int = neton_tls_cipher_list(ctx(context), list)
    actual fun cipherSuites(context: Long, suites: String): Int = neton_tls_cipher_suites(ctx(context), suites)
    actual fun groups(context: Long, groups: String): Int = neton_tls_groups(ctx(context), groups)

    actual fun engineNew(context: Long, server: Boolean, identity: String?, ip: Boolean, alpn: ByteArray, capacity: Int): Long =
        alpn.withBytes { neton_tls_new(ctx(context), if (server) 1 else 0, identity, if (ip) 1 else 0, it, alpn.size, capacity) }.toLong()
    actual fun engineFree(engine: Long) = neton_tls_free(tls(engine))

    actual fun ready(engine: Long): Boolean = neton_tls_ready(tls(engine)) == 1
    actual fun failed(engine: Long): Boolean = neton_tls_failed(tls(engine)) != 0
    actual fun pendingWrite(engine: Long): Int = neton_tls_pending_write(tls(engine))
    actual fun pendingCiphertext(engine: Long): Int = neton_tls_pending(tls(engine))
    actual fun sentClose(engine: Long): Boolean = neton_tls_sent_close(tls(engine)) == 1
    actual fun failureKind(engine: Long): Int = neton_tls_failure_kind(tls(engine))
    actual fun verifyCode(engine: Long): Int = neton_tls_verify_code(tls(engine))
    actual fun alertCode(engine: Long): Int = neton_tls_alert_code(tls(engine))
    actual fun alpn(engine: Long): ByteArray? {
        val size = neton_tls_alpn_copy(tls(engine), null)
        return if (size == 0) null else ByteArray(size).also { out -> out.withBytes { neton_tls_alpn_copy(tls(engine), it) } }
    }
    actual fun versionName(engine: Long): String? = neton_tls_version_name(tls(engine))?.toKString()
    actual fun cipherName(engine: Long): String? = neton_tls_cipher_name(tls(engine))?.toKString()
    actual fun serverName(engine: Long): String? = neton_tls_sni(tls(engine))?.toKString()

    actual fun peerDer(engine: Long, index: Int): ByteArray? {
        val size = neton_tls_peer_der(tls(engine), index, null)
        if (size == 0) return null
        if (size < 0) return ByteArray(0)
        val bytes = ByteArray(size)
        return if (bytes.withBytes { neton_tls_peer_der(tls(engine), index, it) } == size) bytes else ByteArray(0)
    }

    actual fun handshake(engine: Long): Int = neton_tls_handshake(tls(engine))
    actual fun feed(engine: Long, input: ByteArray, offset: Int, length: Int): Int =
        input.withBytes(offset, length) { neton_tls_feed(tls(engine), it, length) }
    actual fun drain(engine: Long, output: ByteArray, offset: Int, length: Int): Int =
        output.withBytes(offset, length) { neton_tls_drain(tls(engine), it, length) }
    actual fun eof(engine: Long) = neton_tls_eof(tls(engine))
    actual fun read(engine: Long, output: ByteArray, offset: Int, length: Int): Int =
        output.withBytes(offset, length) { neton_tls_read(tls(engine), it, length) }
    actual fun write(engine: Long, input: ByteArray, offset: Int, length: Int): Int =
        input.withBytes(offset, length) { neton_tls_write(tls(engine), it, length) }
    actual fun shutdown(engine: Long): Int = neton_tls_shutdown(tls(engine))
    actual fun export(engine: Long, output: ByteArray, label: String, context: ByteArray?): Int = output.withBytes { dst ->
        if (context == null) neton_tls_export(tls(engine), dst, output.size, label, label.length, null, 0, 0)
        else context.withBytes { neton_tls_export(tls(engine), dst, output.size, label, label.length, it, context.size, 1) }
    }
}
