package neton.openssl

import kotlin.test.*

/** The runtime checks that need no raw C API: on Kotlin/Native and on the JVM (through JNI). */
class OpenSslRuntimeTest {
    private fun ByteArray.hex() = joinToString("") { (it.toInt() and 255).toString(16).padStart(2, '0') }

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
    @Test fun aClosedKeyIsRefused() {
        val key = AeadKey(AeadAlgorithm.AES_128_GCM, ByteArray(16))
        key.close(); key.close()
        assertFailsWith<IllegalStateException> { key.seal(ByteArray(16), 0, 0, ByteArray(12), ByteArray(0)) }
    }
}
