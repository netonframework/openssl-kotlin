package neton.openssl

import kotlinx.cinterop.*
import neton.openssl.c.*
import kotlin.test.*

class OpenSslTest {
    @Test fun linkedVersionMatchesHeaders() { OpenSsl.checkVersion(); assertTrue(OpenSsl.version.startsWith("OpenSSL 4.")) }
    @Test fun sha256KnownVectors() {
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", OpenSsl.sha256(byteArrayOf()).hex())
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", OpenSsl.sha256("abc".encodeToByteArray()).hex())
    }
    @Test fun randomLengthsAndInvalidInput() {
        assertEquals(0, OpenSsl.randomBytes(0).size)
        assertEquals(64, OpenSsl.randomBytes(64).size)
        assertFailsWith<IllegalArgumentException> { OpenSsl.randomBytes(-1) }
    }
    @Test fun tls13ContextAndSessionLifecycle() {
        repeat(100) {
            val context = assertNotNull(SSL_CTX_new(TLS_method()))
            try {
                assertEquals(1, neton_openssl_tls13_only(context))
                val session = assertNotNull(SSL_new(context))
                SSL_free(session)
            } finally { SSL_CTX_free(context) }
        }
    }
    private fun ByteArray.hex() = joinToString("") { (it.toInt() and 255).toString(16).padStart(2, '0') }
}
