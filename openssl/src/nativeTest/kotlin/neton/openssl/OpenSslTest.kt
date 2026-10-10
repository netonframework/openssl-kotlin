package neton.openssl

import kotlinx.cinterop.*
import neton.openssl.c.*
import kotlin.test.*

class OpenSslTest {
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
