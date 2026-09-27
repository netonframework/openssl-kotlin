package neton.openssl

import kotlinx.cinterop.*
import neton.openssl.c.*

enum class AeadAlgorithm(val keySize: Int) { AES_128_GCM(16), AES_256_GCM(32), CHACHA20_POLY1305(32) }
enum class MaskAlgorithm(val keySize: Int) { AES_128(16), AES_256(32), CHACHA20(32) }
enum class DigestAlgorithm(val outputSize: Int) { SHA1(20), SHA256(32), SHA384(48), SHA512(64) }

/** Reusable key. One operation at a time; caller MUST ensure nonce uniqueness for encryption. */
class AeadKey(algorithm: AeadAlgorithm, key: ByteArray) : AutoCloseable {
    private val handle: NativeHandle<neton_aead>
    init {
        require(key.size == algorithm.keySize)
        ERR_clear_error()
        handle = NativeHandle(key.withBytes { neton_aead_new(algorithm.ordinal, it) }
            ?: throw sslFailure("AEAD key creation"), ::neton_aead_free)
    }

    /** Replaces plaintext and appends a 16-byte tag; returns total ciphertext length. */
    fun seal(data: ByteArray, offset: Int, plaintextLength: Int, nonce: ByteArray, aad: ByteArray): Int {
        require(plaintextLength >= 0 && plaintextLength <= Int.MAX_VALUE - 16)
        checkRange(data, offset, plaintextLength + 16)
        require(nonce.size == 12 && data !== nonce && data !== aad)
        handle.access { ctx ->
            val result = data.withBytes(offset, plaintextLength + 16) { out -> nonce.withBytes { iv -> aad.withBytes { ad ->
                neton_aead_seal(ctx, out, plaintextLength, iv, ad, aad.size)
            } } }
            if (result != 1) throw sslFailure("AEAD seal")
        }
        return plaintextLength + 16
    }

    /** Length includes tag. False means authentication failure; tentative plaintext is wiped. */
    fun open(data: ByteArray, offset: Int, ciphertextLength: Int, nonce: ByteArray, aad: ByteArray): Boolean {
        require(ciphertextLength >= 16)
        checkRange(data, offset, ciphertextLength)
        require(nonce.size == 12 && data !== nonce && data !== aad)
        return handle.access { ctx ->
            val result = data.withBytes(offset, ciphertextLength) { out -> nonce.withBytes { iv -> aad.withBytes { ad ->
                neton_aead_open(ctx, out, ciphertextLength - 16, iv, ad, aad.size)
            } } }
            if (result < 0) throw sslFailure("AEAD open")
            result == 1
        }
    }
    override fun close() = handle.close()
}

/** Primitive only: packet format, sampling offsets and mask application belong to the protocol. */
class HeaderProtectionKey(algorithm: MaskAlgorithm, key: ByteArray) : AutoCloseable {
    private val handle: NativeHandle<neton_mask>
    init {
        require(key.size == algorithm.keySize)
        ERR_clear_error()
        handle = NativeHandle(key.withBytes { neton_mask_new(algorithm.ordinal, it) }
            ?: throw sslFailure("Header protection key"), ::neton_mask_free)
    }
    fun mask(sample: ByteArray, sampleOffset: Int, output: ByteArray, outputOffset: Int = 0) {
        checkRange(sample, sampleOffset, 16); checkRange(output, outputOffset, 5)
        require(sample !== output) { "Sample and output must not alias" }
        handle.access { ctx ->
            val result = sample.withBytes(sampleOffset, 16) { src -> output.withBytes(outputOffset, 5) { dst ->
                neton_mask_apply(ctx, src, dst)
            } }
            if (result != 1) throw sslFailure("Header protection mask")
        }
    }
    override fun close() = handle.close()
}

object Crypto {
    /** SHA1 exists only for protocol compatibility, not new signatures/password storage. */
    fun digest(algorithm: DigestAlgorithm, input: ByteArray, output: ByteArray, outputOffset: Int = 0) {
        checkRange(output, outputOffset, algorithm.outputSize)
        require(input !== output)
        val result = input.withBytes { src -> output.withBytes(outputOffset, algorithm.outputSize) { dst ->
            neton_hash(algorithm.ordinal, src, input.size, dst)
        } }
        if (result != 1) { output.fill(0, outputOffset, outputOffset + algorithm.outputSize); throw sslFailure("Digest") }
    }

    fun hmac(algorithm: DigestAlgorithm, key: ByteArray, input: ByteArray, output: ByteArray, outputOffset: Int = 0) {
        require(algorithm == DigestAlgorithm.SHA256 || algorithm == DigestAlgorithm.SHA384)
        checkRange(output, outputOffset, algorithm.outputSize)
        require(output !== key && output !== input)
        val result = key.withBytes { secret -> input.withBytes { src -> output.withBytes(outputOffset, algorithm.outputSize) { dst ->
            neton_hmac(algorithm.ordinal, secret, key.size, src, input.size, dst)
        } } }
        if (result != 1) { output.fill(0, outputOffset, outputOffset + algorithm.outputSize); throw sslFailure("HMAC") }
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
        val result = key.withBytes { secret -> salt.withBytes { sa -> info.withBytes { inf -> output.withBytes(offset, length) { dst ->
            neton_hkdf(algorithm.ordinal, if (expand) 1 else 0, secret, key.size, sa, salt.size, inf, info.size, dst, length)
        } } } }
        if (result != 1) { output.fill(0, offset, offset + length); throw sslFailure("HKDF") }
    }

    /** Equal-length contents are compared in constant time; lengths are public. */
    fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        if (a.isEmpty()) return true
        return a.withBytes { left -> b.withBytes { right -> CRYPTO_memcmp(left, right, a.size.convert()) == 0 } }
    }
    /** Best-effort overwrite of this array, not historical GC copies. */
    fun wipe(array: ByteArray) = array.withBytes { if (it != null) OPENSSL_cleanse(it, array.size.convert()) }
    private val EMPTY = ByteArray(0)
}
