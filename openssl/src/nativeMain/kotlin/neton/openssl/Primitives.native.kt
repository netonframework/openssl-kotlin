package neton.openssl

import kotlinx.cinterop.*
import neton.openssl.c.*

internal actual object Primitives {
    actual fun version(): String = OpenSSL_version(0)?.toKString() ?: error("No OpenSSL version")

    actual fun versionNumbers(): IntArray = intArrayOf(
        OPENSSL_version_major().toInt(), OPENSSL_version_minor().toInt(), OPENSSL_version_patch().toInt(),
        neton_openssl_header_major(), neton_openssl_header_minor(), neton_openssl_header_patch(),
    )

    actual fun nextError(): String? = memScoped {
        val buffer = allocArray<ByteVar>(256)
        if (neton_openssl_next_error(buffer, 256u) != 0) buffer.toKString() else null
    }

    actual fun clearErrors() = ERR_clear_error()

    actual fun randomFill(output: ByteArray, offset: Int, length: Int): Boolean =
        output.withBytes(offset, length) { RAND_bytes(it, length) } == 1

    actual fun aeadNew(algorithm: Int, key: ByteArray): Long = key.withBytes { neton_aead_new(algorithm, it) }.toLong()

    actual fun aeadFree(handle: Long) = neton_aead_free(handle.toCPointer())

    actual fun aeadSeal(handle: Long, data: ByteArray, offset: Int, size: Int, nonce: ByteArray, aad: ByteArray): Int =
        data.withBytes(offset, size + 16) { out -> nonce.withBytes { iv -> aad.withBytes { ad ->
            neton_aead_seal(handle.toCPointer(), out, size, iv, ad, aad.size)
        } } }

    actual fun aeadOpen(handle: Long, data: ByteArray, offset: Int, size: Int, nonce: ByteArray, aad: ByteArray): Int =
        data.withBytes(offset, size + 16) { out -> nonce.withBytes { iv -> aad.withBytes { ad ->
            neton_aead_open(handle.toCPointer(), out, size, iv, ad, aad.size)
        } } }

    actual fun maskNew(algorithm: Int, key: ByteArray): Long = key.withBytes { neton_mask_new(algorithm, it) }.toLong()

    actual fun maskFree(handle: Long) = neton_mask_free(handle.toCPointer())

    actual fun maskApply(handle: Long, sample: ByteArray, sampleOffset: Int, output: ByteArray, outputOffset: Int): Int =
        sample.withBytes(sampleOffset, 16) { src -> output.withBytes(outputOffset, 5) { dst ->
            neton_mask_apply(handle.toCPointer(), src, dst)
        } }

    actual fun hash(algorithm: Int, input: ByteArray, output: ByteArray, outputOffset: Int): Int =
        input.withBytes { src -> output.withBytes(outputOffset, DigestAlgorithm.entries[algorithm].outputSize) { dst ->
            neton_hash(algorithm, src, input.size, dst)
        } }

    actual fun hmac(algorithm: Int, key: ByteArray, input: ByteArray, output: ByteArray, outputOffset: Int): Int =
        key.withBytes { secret -> input.withBytes { src -> output.withBytes(outputOffset, DigestAlgorithm.entries[algorithm].outputSize) { dst ->
            neton_hmac(algorithm, secret, key.size, src, input.size, dst)
        } } }

    actual fun hkdf(algorithm: Int, expand: Boolean, key: ByteArray, salt: ByteArray, info: ByteArray, output: ByteArray, offset: Int, length: Int): Int =
        key.withBytes { secret -> salt.withBytes { sa -> info.withBytes { inf -> output.withBytes(offset, length) { dst ->
            neton_hkdf(algorithm, if (expand) 1 else 0, secret, key.size, sa, salt.size, inf, info.size, dst, length)
        } } } }

    actual fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean =
        a.withBytes { left -> b.withBytes { right -> CRYPTO_memcmp(left, right, a.size.convert()) == 0 } }

    actual fun wipe(array: ByteArray) = array.withBytes { if (it != null) OPENSSL_cleanse(it, array.size.convert()) }
}
