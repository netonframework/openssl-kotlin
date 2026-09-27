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
        ERR_clear_error()
        val result = output.usePinned { RAND_bytes(it.addressOf(0).reinterpret(), size) }
        if (result != 1) { output.fill(0); throw failure("RAND_bytes") }
        return output
    }

    fun sha256(input: ByteArray): ByteArray = memScoped {
        val output = ByteArray(32)
        val length = alloc<UIntVar>()
        ERR_clear_error()
        val result = output.usePinned { out ->
            if (input.isEmpty()) EVP_Digest(null, 0u, out.addressOf(0).reinterpret(), length.ptr, EVP_sha256(), null)
            else input.usePinned { src -> EVP_Digest(src.addressOf(0), input.size.convert(), out.addressOf(0).reinterpret(), length.ptr, EVP_sha256(), null) }
        }
        if (result != 1 || length.value != 32u) throw failure("EVP_Digest")
        output
    }

    // OpenSSL's error queue is thread-local: drain it before leaving the synchronous call path.
    private fun failure(operation: String): OpenSslException = memScoped {
        val buffer = allocArray<ByteVar>(256)
        val messages = mutableListOf<String>()
        while (neton_openssl_next_error(buffer, 256u) != 0) {
            messages += buffer.toKString()
        }
        OpenSslException("$operation failed: ${messages.joinToString("; ").ifEmpty { "no error detail" }}")
    }
}

class OpenSslException(message: String) : Exception(message)
