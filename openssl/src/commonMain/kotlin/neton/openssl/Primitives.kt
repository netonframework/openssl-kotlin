package neton.openssl

/**
 * The OpenSSL primitives behind the safe facade, one implementation per platform: cinterop on Kotlin/Native, JNI on
 * the JVM (docs/JVM.md). Both call the same C shim (neton_crypto.h, neton_openssl.h). Callers have checked every
 * range and size; a native key context is a non-zero [Long] handle, released exactly once with its `free` function.
 * Algorithm arguments are the ordinals of [AeadAlgorithm], [MaskAlgorithm] and [DigestAlgorithm].
 */
internal expect object Primitives {
    fun version(): String

    /** Runtime major, minor, patch, then the headers' major, minor, patch. */
    fun versionNumbers(): IntArray

    /** The next queued OpenSSL error of this thread, or null. */
    fun nextError(): String?
    fun clearErrors()

    fun randomFill(output: ByteArray, offset: Int, length: Int): Boolean

    /** 0 on failure. */
    fun aeadNew(algorithm: Int, key: ByteArray): Long
    fun aeadFree(handle: Long)

    /** Encrypts data[offset, offset + size) in place and writes the 16-byte tag after it; 1 or 0. */
    fun aeadSeal(handle: Long, data: ByteArray, offset: Int, size: Int, nonce: ByteArray, aad: ByteArray): Int

    /** Decrypts data[offset, offset + size) in place, tag after it: 1 authentic, 0 forged, -1 failure. */
    fun aeadOpen(handle: Long, data: ByteArray, offset: Int, size: Int, nonce: ByteArray, aad: ByteArray): Int

    /** 0 on failure. */
    fun maskNew(algorithm: Int, key: ByteArray): Long
    fun maskFree(handle: Long)
    fun maskApply(handle: Long, sample: ByteArray, sampleOffset: Int, output: ByteArray, outputOffset: Int): Int

    fun hash(algorithm: Int, input: ByteArray, output: ByteArray, outputOffset: Int): Int
    fun hmac(algorithm: Int, key: ByteArray, input: ByteArray, output: ByteArray, outputOffset: Int): Int
    fun hkdf(algorithm: Int, expand: Boolean, key: ByteArray, salt: ByteArray, info: ByteArray, output: ByteArray, offset: Int, length: Int): Int

    /** CRYPTO_memcmp of two arrays of the same, non-zero size. */
    fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean
    fun wipe(array: ByteArray)
}

internal fun checkRange(array: ByteArray, offset: Int, length: Int) {
    require(offset >= 0 && length >= 0 && offset <= array.size && length <= array.size - offset) { "Invalid buffer range" }
}

/** The OpenSSL errors queued on this thread, drained into one exception. */
internal fun sslFailure(operation: String): OpenSslException {
    val messages = mutableListOf<String>()
    while (true) messages += Primitives.nextError() ?: break
    return OpenSslException("$operation failed: ${messages.joinToString("; ").ifEmpty { "no error detail" }}")
}

open class OpenSslException(message: String) : Exception(message)
