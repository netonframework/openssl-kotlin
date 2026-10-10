package neton.openssl

/**
 * The byte-stream TLS primitives behind [TlsContext] and [TlsEngine] (neton_tls.h), one implementation per platform
 * like [Primitives]. A context (SSL_CTX) and an engine (neton_tls) are non-zero [Long] handles; callers have checked
 * every argument. Strings are ASCII (checked by the callers).
 */
internal expect object TlsPrimitives {
    /** 0 on failure. */
    fun contextNew(minimum: Int, maximum: Int, verifyMode: Int): Long
    fun contextFree(context: Long)
    fun verifyMode(server: Boolean, clientAuthentication: Int): Int
    fun limits(context: Long, depth: Int, bytes: Int)
    fun roots(context: Long, pem: ByteArray): Int
    fun defaultPaths(context: Long): Int
    fun identity(context: Long, chain: ByteArray, key: ByteArray): Int
    fun cipherList(context: Long, list: String): Int
    fun cipherSuites(context: Long, suites: String): Int
    fun groups(context: Long, groups: String): Int

    /** 0 on failure. */
    fun engineNew(context: Long, server: Boolean, identity: String?, ip: Boolean, alpn: ByteArray, capacity: Int): Long
    fun engineFree(engine: Long)

    fun ready(engine: Long): Boolean
    fun failed(engine: Long): Boolean
    fun pendingWrite(engine: Long): Int
    fun pendingCiphertext(engine: Long): Int
    fun sentClose(engine: Long): Boolean
    fun failureKind(engine: Long): Int
    fun verifyCode(engine: Long): Int
    fun alertCode(engine: Long): Int
    fun alpn(engine: Long): ByteArray?
    fun versionName(engine: Long): String?
    fun cipherName(engine: Long): String?
    fun serverName(engine: Long): String?

    /** DER of the peer's certificate [index] (leaf first): null past the end, an empty array on failure. */
    fun peerDer(engine: Long, index: Int): ByteArray?

    fun handshake(engine: Long): Int
    fun feed(engine: Long, input: ByteArray, offset: Int, length: Int): Int
    fun drain(engine: Long, output: ByteArray, offset: Int, length: Int): Int
    fun eof(engine: Long)
    fun read(engine: Long, output: ByteArray, offset: Int, length: Int): Int
    fun write(engine: Long, input: ByteArray, offset: Int, length: Int): Int
    fun shutdown(engine: Long): Int
    fun export(engine: Long, output: ByteArray, label: String, context: ByteArray?): Int
}
