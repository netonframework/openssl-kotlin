package neton.openssl

internal actual object TlsPrimitives {
    actual fun contextNew(minimum: Int, maximum: Int, verifyMode: Int): Long = Jni.tlsContextNew(minimum, maximum, verifyMode)
    actual fun contextFree(context: Long) = Jni.tlsContextFree(context)
    actual fun verifyMode(server: Boolean, clientAuthentication: Int): Int = Jni.tlsVerifyMode(server, clientAuthentication)
    actual fun limits(context: Long, depth: Int, bytes: Int) = Jni.tlsLimits(context, depth, bytes)
    actual fun roots(context: Long, pem: ByteArray): Int = Jni.tlsRoots(context, pem)
    actual fun defaultPaths(context: Long): Int = Jni.tlsDefaultPaths(context)
    actual fun identity(context: Long, chain: ByteArray, key: ByteArray): Int = Jni.tlsIdentity(context, chain, key)
    actual fun cipherList(context: Long, list: String): Int = Jni.tlsCipherList(context, list)
    actual fun cipherSuites(context: Long, suites: String): Int = Jni.tlsCipherSuites(context, suites)
    actual fun groups(context: Long, groups: String): Int = Jni.tlsGroups(context, groups)

    actual fun engineNew(context: Long, server: Boolean, identity: String?, ip: Boolean, alpn: ByteArray, capacity: Int): Long =
        Jni.tlsNew(context, server, identity, ip, alpn, capacity)
    actual fun engineFree(engine: Long) = Jni.tlsFree(engine)

    actual fun ready(engine: Long): Boolean = Jni.tlsReady(engine)
    actual fun failed(engine: Long): Boolean = Jni.tlsFailed(engine)
    actual fun pendingWrite(engine: Long): Int = Jni.tlsPendingWrite(engine)
    actual fun pendingCiphertext(engine: Long): Int = Jni.tlsPendingCiphertext(engine)
    actual fun sentClose(engine: Long): Boolean = Jni.tlsSentClose(engine)
    actual fun failureKind(engine: Long): Int = Jni.tlsFailureKind(engine)
    actual fun verifyCode(engine: Long): Int = Jni.tlsVerifyCode(engine)
    actual fun alertCode(engine: Long): Int = Jni.tlsAlertCode(engine)
    actual fun alpn(engine: Long): ByteArray? = Jni.tlsAlpn(engine)
    actual fun versionName(engine: Long): String? = Jni.tlsVersionName(engine)
    actual fun cipherName(engine: Long): String? = Jni.tlsCipherName(engine)
    actual fun serverName(engine: Long): String? = Jni.tlsServerName(engine)
    actual fun peerDer(engine: Long, index: Int): ByteArray? = Jni.tlsPeerDer(engine, index)

    actual fun handshake(engine: Long): Int = Jni.tlsHandshake(engine)
    actual fun feed(engine: Long, input: ByteArray, offset: Int, length: Int): Int = Jni.tlsFeed(engine, input, offset, length)
    actual fun drain(engine: Long, output: ByteArray, offset: Int, length: Int): Int = Jni.tlsDrain(engine, output, offset, length)
    actual fun eof(engine: Long) = Jni.tlsEof(engine)
    actual fun read(engine: Long, output: ByteArray, offset: Int, length: Int): Int = Jni.tlsRead(engine, output, offset, length)
    actual fun write(engine: Long, input: ByteArray, offset: Int, length: Int): Int = Jni.tlsWrite(engine, input, offset, length)
    actual fun shutdown(engine: Long): Int = Jni.tlsShutdown(engine)
    actual fun export(engine: Long, output: ByteArray, label: String, context: ByteArray?): Int = Jni.tlsExport(engine, output, label, context)
}
