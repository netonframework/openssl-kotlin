package neton.openssl

import neton.openssl.c.*
import kotlin.test.*

class NativeHandleTest {
    @Test fun immutableFactoriesAllowOverlappingAccessButRejectCloseUntilReleased() {
        var freed = 0
        val handle = SharedNativeHandle(assertNotNull(SSL_CTX_new(TLS_method()))) { SSL_CTX_free(it); freed++ }
        try {
            handle.access { first -> handle.access { second ->
                assertEquals(first, second)
                assertFailsWith<IllegalStateException> { handle.close() }
                assertEquals(0, freed)
            } }
            handle.access { assertNotNull(it) }
        } finally { handle.close() }
        handle.close(); assertEquals(1, freed)
        assertFailsWith<IllegalStateException> { handle.access { } }
    }
    @Test fun reentrancyAndCloseDoNotReleaseAnActiveHandle() {
        var freed = 0
        val handle = NativeHandle(assertNotNull(EVP_CIPHER_CTX_new())) { EVP_CIPHER_CTX_free(it); freed++ }
        try {
            handle.access {
                assertFailsWith<IllegalStateException> { handle.access { } }
                assertFailsWith<IllegalStateException> { handle.close() }
                assertEquals(0, freed)
            }
            assertFailsWith<IllegalArgumentException> { handle.access { throw IllegalArgumentException("test") } }
            handle.access { assertNotNull(it) }
        } finally { handle.close() }
        handle.close(); assertEquals(1, freed)
        assertFailsWith<IllegalStateException> { handle.access { } }
    }
}
