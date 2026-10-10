package neton.openssl

/** Static OpenSSL 4.x runtime. On Kotlin/Native the raw C bindings are available in neton.openssl.c. */
object OpenSsl {
    val version: String get() = Primitives.version()

    fun checkVersion() {
        val v = Primitives.versionNumbers()
        check(v[0] == 4) { "OpenSSL 4.x is required: $version" }
        check(v[0] == v[3] && v[1] == v[4] && v[2] == v[5]) { "OpenSSL headers and linked library differ" }
    }

    /** Uses OpenSSL's CSPRNG; failures never return partially initialized output. */
    fun randomBytes(size: Int): ByteArray {
        require(size >= 0)
        if (size == 0) return ByteArray(0)
        val output = ByteArray(size)
        randomFill(output)
        return output
    }

    fun randomFill(output: ByteArray, offset: Int = 0, length: Int = output.size - offset) {
        checkRange(output, offset, length)
        if (length == 0) return
        Primitives.clearErrors()
        if (!Primitives.randomFill(output, offset, length)) { output.fill(0, offset, offset + length); throw sslFailure("RAND_bytes") }
    }

    /** The OpenSSL errors queued on this thread, taken and joined with "; " (empty when none). */
    fun takeErrors(): String {
        val messages = mutableListOf<String>()
        while (true) messages += Primitives.nextError() ?: break
        return messages.joinToString("; ")
    }

    /** Empties this thread's OpenSSL error queue. */
    fun clearErrors() = Primitives.clearErrors()

    fun sha256(input: ByteArray): ByteArray {
        val output = ByteArray(32)
        Crypto.digest(DigestAlgorithm.SHA256, input, output)
        return output
    }
}
