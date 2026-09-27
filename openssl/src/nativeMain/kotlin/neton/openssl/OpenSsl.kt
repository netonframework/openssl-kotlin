package neton.openssl

import kotlinx.cinterop.*
import neton.openssl.c.*

/** Static OpenSSL 4.x runtime. Raw C bindings are available in neton.openssl.c. */
object OpenSsl {
    val version: String get() = OpenSSL_version(0)?.toKString() ?: error("No OpenSSL version")

    fun checkVersion() {
        check(OPENSSL_version_major() == 4u) { "OpenSSL 4.x is required: $version" }
        check(OPENSSL_version_major().toInt() == neton_openssl_header_major() &&
            OPENSSL_version_minor().toInt() == neton_openssl_header_minor() &&
            OPENSSL_version_patch().toInt() == neton_openssl_header_patch()) {
            "OpenSSL headers and linked library differ"
        }
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
        ERR_clear_error()
        val result = output.withBytes(offset, length) { RAND_bytes(it, length) }
        if (result != 1) { output.fill(0, offset, offset + length); throw sslFailure("RAND_bytes") }
    }

    fun sha256(input: ByteArray): ByteArray = memScoped {
        val output = ByteArray(32)
        val length = alloc<UIntVar>()
        ERR_clear_error()
        val result = output.usePinned { out ->
            if (input.isEmpty()) EVP_Digest(null, 0u, out.addressOf(0).reinterpret(), length.ptr, EVP_sha256(), null)
            else input.usePinned { src -> EVP_Digest(src.addressOf(0), input.size.convert(), out.addressOf(0).reinterpret(), length.ptr, EVP_sha256(), null) }
        }
        if (result != 1 || length.value != 32u) throw sslFailure("EVP_Digest")
        output
    }

}

open class OpenSslException(message: String) : Exception(message)
