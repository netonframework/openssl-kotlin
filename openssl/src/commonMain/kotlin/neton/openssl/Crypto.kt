@file:OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
package neton.openssl

import kotlin.concurrent.atomics.AtomicInt

enum class AeadAlgorithm(val keySize: Int) { AES_128_GCM(16), AES_256_GCM(32), CHACHA20_POLY1305(32) }
enum class MaskAlgorithm(val keySize: Int) { AES_128(16), AES_256(32), CHACHA20(32) }
enum class DigestAlgorithm(val outputSize: Int) { SHA1(20), SHA256(32), SHA384(48), SHA512(64) }

/** A native key context: one operation at a time, released once by [close]; no suspension inside [access]. */
internal class KeyHandle(private var handle: Long, private val release: (Long) -> Unit) : AutoCloseable {
    private val busy = AtomicInt(0)

    inline fun <R> access(block: (Long) -> R): R {
        check(busy.compareAndSet(0, 1)) { "Concurrent or reentrant native handle access" }
        try {
            check(handle != 0L) { "Native handle is closed" }
            return block(handle)
        } finally {
            busy.store(0)
        }
    }

    override fun close() {
        check(busy.compareAndSet(0, 1)) { "Concurrent close/use of native handle" }
        try {
            val h = handle
            if (h != 0L) { handle = 0L; release(h) }
        } finally {
            busy.store(0)
        }
    }
}

/** Reusable key. One operation at a time; caller MUST ensure nonce uniqueness for encryption. */
class AeadKey(algorithm: AeadAlgorithm, key: ByteArray) : AutoCloseable {
    private val handle: KeyHandle
    init {
        require(key.size == algorithm.keySize)
        Primitives.clearErrors()
        val h = Primitives.aeadNew(algorithm.ordinal, key)
        if (h == 0L) throw sslFailure("AEAD key creation")
        handle = KeyHandle(h, Primitives::aeadFree)
    }

    /** Replaces plaintext and appends a 16-byte tag; returns total ciphertext length. */
    fun seal(data: ByteArray, offset: Int, plaintextLength: Int, nonce: ByteArray, aad: ByteArray): Int {
        require(plaintextLength >= 0 && plaintextLength <= Int.MAX_VALUE - 16)
        checkRange(data, offset, plaintextLength + 16)
        require(nonce.size == 12 && data !== nonce && data !== aad)
        handle.access { h ->
            if (Primitives.aeadSeal(h, data, offset, plaintextLength, nonce, aad) != 1) throw sslFailure("AEAD seal")
        }
        return plaintextLength + 16
    }

    /** Length includes tag. False means authentication failure; tentative plaintext is wiped. */
    fun open(data: ByteArray, offset: Int, ciphertextLength: Int, nonce: ByteArray, aad: ByteArray): Boolean {
        require(ciphertextLength >= 16)
        checkRange(data, offset, ciphertextLength)
        require(nonce.size == 12 && data !== nonce && data !== aad)
        return handle.access { h ->
            val result = Primitives.aeadOpen(h, data, offset, ciphertextLength - 16, nonce, aad)
            if (result < 0) throw sslFailure("AEAD open")
            result == 1
        }
    }
    override fun close() = handle.close()
}

/** Primitive only: packet format, sampling offsets and mask application belong to the protocol. */
class HeaderProtectionKey(algorithm: MaskAlgorithm, key: ByteArray) : AutoCloseable {
    private val handle: KeyHandle
    init {
        require(key.size == algorithm.keySize)
        Primitives.clearErrors()
        val h = Primitives.maskNew(algorithm.ordinal, key)
        if (h == 0L) throw sslFailure("Header protection key")
        handle = KeyHandle(h, Primitives::maskFree)
    }
    fun mask(sample: ByteArray, sampleOffset: Int, output: ByteArray, outputOffset: Int = 0) {
        checkRange(sample, sampleOffset, 16); checkRange(output, outputOffset, 5)
        require(sample !== output) { "Sample and output must not alias" }
        handle.access { h ->
            if (Primitives.maskApply(h, sample, sampleOffset, output, outputOffset) != 1) throw sslFailure("Header protection mask")
        }
    }
    override fun close() = handle.close()
}

object Crypto {
    /** SHA1 exists only for protocol compatibility, not new signatures/password storage. */
    fun digest(algorithm: DigestAlgorithm, input: ByteArray, output: ByteArray, outputOffset: Int = 0) {
        checkRange(output, outputOffset, algorithm.outputSize)
        require(input !== output)
        if (Primitives.hash(algorithm.ordinal, input, output, outputOffset) != 1) {
            output.fill(0, outputOffset, outputOffset + algorithm.outputSize); throw sslFailure("Digest")
        }
    }

    fun hmac(algorithm: DigestAlgorithm, key: ByteArray, input: ByteArray, output: ByteArray, outputOffset: Int = 0) {
        require(algorithm == DigestAlgorithm.SHA256 || algorithm == DigestAlgorithm.SHA384)
        checkRange(output, outputOffset, algorithm.outputSize)
        require(output !== key && output !== input)
        if (Primitives.hmac(algorithm.ordinal, key, input, output, outputOffset) != 1) {
            output.fill(0, outputOffset, outputOffset + algorithm.outputSize); throw sslFailure("HMAC")
        }
    }

    fun hkdfExtract(algorithm: DigestAlgorithm, salt: ByteArray, inputKey: ByteArray, output: ByteArray, offset: Int = 0) {
        hkdf(algorithm, false, inputKey, salt, EMPTY, output, offset, algorithm.outputSize)
    }
    fun hkdfExpand(algorithm: DigestAlgorithm, key: ByteArray, info: ByteArray, output: ByteArray, offset: Int = 0, length: Int = output.size - offset) {
        require(key.size >= algorithm.outputSize) { "HKDF PRK is shorter than its digest" }
        hkdf(algorithm, true, key, EMPTY, info, output, offset, length)
    }

    /** Encodes RFC 8446 HkdfLabel. Setup/key-derivation API; allocates label bytes, not a packet hot path. */
    fun hkdfExpandLabel(algorithm: DigestAlgorithm, key: ByteArray, label: String, context: ByteArray, output: ByteArray, offset: Int = 0, length: Int = output.size - offset) {
        require(label.isNotEmpty() && label.all { it.code in 0x20..0x7e } && label.length <= 249)
        require(context.size <= 255 && length in 0..65535)
        val name = "tls13 $label".encodeToByteArray()
        val info = ByteArray(4 + name.size + context.size)
        info[0] = (length ushr 8).toByte(); info[1] = length.toByte(); info[2] = name.size.toByte()
        name.copyInto(info, 3); info[3 + name.size] = context.size.toByte(); context.copyInto(info, 4 + name.size)
        hkdfExpand(algorithm, key, info, output, offset, length)
    }
    private fun hkdf(algorithm: DigestAlgorithm, expand: Boolean, key: ByteArray, salt: ByteArray, info: ByteArray, output: ByteArray, offset: Int, length: Int) {
        require(algorithm == DigestAlgorithm.SHA256 || algorithm == DigestAlgorithm.SHA384)
        require(length <= 255 * algorithm.outputSize)
        checkRange(output, offset, length)
        require(output !== key && output !== salt && output !== info)
        if (length == 0) return
        if (Primitives.hkdf(algorithm.ordinal, expand, key, salt, info, output, offset, length) != 1) {
            output.fill(0, offset, offset + length); throw sslFailure("HKDF")
        }
    }

    /** Equal-length contents are compared in constant time; lengths are public. */
    fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        if (a.isEmpty()) return true
        return Primitives.constantTimeEquals(a, b)
    }
    /** Best-effort overwrite of this array, not historical GC copies. */
    fun wipe(array: ByteArray) { if (array.isNotEmpty()) Primitives.wipe(array) }
    private val EMPTY = ByteArray(0)
}
