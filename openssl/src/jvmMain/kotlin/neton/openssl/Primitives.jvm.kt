package neton.openssl

internal actual object Primitives {
    actual fun version(): String = Jni.version()

    actual fun versionNumbers(): IntArray = IntArray(6).also { Jni.versionNumbers(it) }

    actual fun nextError(): String? = Jni.nextError()

    actual fun clearErrors() = Jni.clearErrors()

    actual fun randomFill(output: ByteArray, offset: Int, length: Int): Boolean = Jni.randomFill(output, offset, length) == 1

    actual fun aeadNew(algorithm: Int, key: ByteArray): Long = Jni.aeadNew(algorithm, key)

    actual fun aeadFree(handle: Long) = Jni.aeadFree(handle)

    actual fun aeadSeal(handle: Long, data: ByteArray, offset: Int, size: Int, nonce: ByteArray, aad: ByteArray): Int =
        Jni.aeadSeal(handle, data, offset, size, nonce, aad)

    actual fun aeadOpen(handle: Long, data: ByteArray, offset: Int, size: Int, nonce: ByteArray, aad: ByteArray): Int =
        Jni.aeadOpen(handle, data, offset, size, nonce, aad)

    actual fun maskNew(algorithm: Int, key: ByteArray): Long = Jni.maskNew(algorithm, key)

    actual fun maskFree(handle: Long) = Jni.maskFree(handle)

    actual fun maskApply(handle: Long, sample: ByteArray, sampleOffset: Int, output: ByteArray, outputOffset: Int): Int =
        Jni.maskApply(handle, sample, sampleOffset, output, outputOffset)

    actual fun hash(algorithm: Int, input: ByteArray, output: ByteArray, outputOffset: Int): Int =
        Jni.hash(algorithm, input, output, outputOffset)

    actual fun hmac(algorithm: Int, key: ByteArray, input: ByteArray, output: ByteArray, outputOffset: Int): Int =
        Jni.hmac(algorithm, key, input, output, outputOffset)

    actual fun hkdf(algorithm: Int, expand: Boolean, key: ByteArray, salt: ByteArray, info: ByteArray, output: ByteArray, offset: Int, length: Int): Int =
        Jni.hkdf(algorithm, expand, key, salt, info, output, offset, length)

    actual fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean = Jni.constantTimeEquals(a, b)

    actual fun wipe(array: ByteArray) = Jni.wipe(array)
}
