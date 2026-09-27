package neton.openssl

import kotlin.test.*

internal fun hex(value: String) = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

class CryptoTest {
    @Test fun aesGcmKnownVectorThroughSafeApi() {
        val key = AeadKey(AeadAlgorithm.AES_128_GCM, ByteArray(16))
        try {
            val data = ByteArray(34) { 0x55 }; data.fill(0, 1, 17)
            assertEquals(32, key.seal(data, 1, 16, ByteArray(12), ByteArray(0)))
            assertContentEquals(hex("0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf"), data.copyOfRange(1, 33))
            assertTrue(key.open(data, 1, 32, ByteArray(12), ByteArray(0)))
            assertContentEquals(ByteArray(16), data.copyOfRange(1, 17))
            assertEquals(0x55, data.first().toInt()); assertEquals(0x55, data.last().toInt())
        } finally { key.close() }
    }

    @Test fun allAeadsReuseAndWipeUnauthenticatedOutput() {
        for (algorithm in AeadAlgorithm.entries) {
            val key = AeadKey(algorithm, ByteArray(algorithm.keySize))
            try {
                for (size in listOf(0, 1, 1200, 16384)) {
                    val nonce = ByteArray(12); nonce[0] = (size ushr 8).toByte(); nonce[1] = size.toByte()
                    val data = ByteArray(size + 16); val plain = ByteArray(size) { (it * 7).toByte() }
                    plain.copyInto(data)
                    key.seal(data, 0, size, nonce, byteArrayOf(1, 2))
                    val saved = data.copyOf()
                    assertFalse(key.open(data, 0, data.size, nonce, byteArrayOf(1, 3)))
                    assertContentEquals(ByteArray(size), data.copyOf(size))
                    saved.copyInto(data)
                    assertTrue(key.open(data, 0, data.size, nonce, byteArrayOf(1, 2)))
                    assertContentEquals(plain, data.copyOf(size))
                }
            } finally { key.close() }
            key.close()
            assertFailsWith<IllegalStateException> { key.seal(ByteArray(16), 0, 0, ByteArray(12), ByteArray(0)) }
        }
    }

    @Test fun invalidRangesAndAliasingFailBeforeMutation() {
        val key = AeadKey(AeadAlgorithm.AES_128_GCM, ByteArray(16))
        try {
            val data = ByteArray(32) { 7 }; val original = data.copyOf()
            assertFailsWith<IllegalArgumentException> { key.seal(data, -1, 1, ByteArray(12), ByteArray(0)) }
            assertFailsWith<IllegalArgumentException> { key.seal(data, 0, Int.MAX_VALUE, ByteArray(12), ByteArray(0)) }
            assertFailsWith<IllegalArgumentException> { key.seal(data, 0, 17, ByteArray(12), ByteArray(0)) }
            assertFailsWith<IllegalArgumentException> { key.seal(data, 0, 16, ByteArray(12), data) }
            assertContentEquals(original, data)
        } finally { key.close() }
    }

    @Test fun rfc9001HeaderProtection() {
        val vectors = listOf(
            Triple(MaskAlgorithm.AES_128, "9f50449e04a0e810283a1e9933adedd2", "d1b1c98dd7689fb8ec11d242b123dc9b" to "437b9aec36"),
            Triple(MaskAlgorithm.CHACHA20, "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4", "5e5cd55c41f69080575d7999c25a5bfb" to "aefefe7d03")
        )
        for ((algorithm, bytes, vector) in vectors) {
            val key = HeaderProtectionKey(algorithm, hex(bytes))
            try { repeat(3) {
                val output = ByteArray(7) { 9 }
                key.mask(hex(vector.first), 0, output, 1)
                assertContentEquals(hex(vector.second), output.copyOfRange(1, 6))
                assertEquals(9, output.first().toInt()); assertEquals(9, output.last().toInt())
            } } finally { key.close() }
        }
    }

    @Test fun rfc5869HkdfAndTlsLabel() {
        val prk = ByteArray(32)
        Crypto.hkdfExtract(DigestAlgorithm.SHA256, hex("000102030405060708090a0b0c"), ByteArray(22) { 0x0b }, prk)
        assertContentEquals(hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"), prk)
        val output = ByteArray(42)
        Crypto.hkdfExpand(DigestAlgorithm.SHA256, prk, hex("f0f1f2f3f4f5f6f7f8f9"), output)
        assertContentEquals(hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"), output)
        // RFC 9001 Appendix A.1: TLS label encoding, not a QUIC policy in the library.
        val initial = hex("7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44")
        val secret = ByteArray(32)
        Crypto.hkdfExpandLabel(DigestAlgorithm.SHA256, initial, "client in", ByteArray(0), secret)
        assertContentEquals(hex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"), secret)
        assertFailsWith<IllegalArgumentException> { Crypto.hkdfExpand(DigestAlgorithm.SHA256, prk, ByteArray(0), ByteArray(8161)) }
    }

    @Test fun hashHmacRandomAndCompare() {
        val digest = ByteArray(20)
        Crypto.digest(DigestAlgorithm.SHA1, "abc".encodeToByteArray(), digest)
        assertContentEquals(hex("a9993e364706816aba3e25717850c26c9cd0d89d"), digest)
        val mac = ByteArray(32)
        Crypto.hmac(DigestAlgorithm.SHA256, ByteArray(20) { 0x0b }, "Hi There".encodeToByteArray(), mac)
        assertContentEquals(hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"), mac)
        assertTrue(Crypto.constantTimeEquals(mac, mac.copyOf()))
        assertFalse(Crypto.constantTimeEquals(mac, ByteArray(32)))
        val emptyMac = hex("b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad")
        Crypto.hmac(DigestAlgorithm.SHA256, ByteArray(0), ByteArray(0), mac)
        assertContentEquals(emptyMac, mac)
        Crypto.hkdfExtract(DigestAlgorithm.SHA256, ByteArray(0), ByteArray(0), mac)
        assertContentEquals(emptyMac, mac)
        val random = ByteArray(34) { 0x55 }
        OpenSsl.randomFill(random, 1, 32)
        assertEquals(0x55, random.first().toInt()); assertEquals(0x55, random.last().toInt())
        assertFailsWith<IllegalArgumentException> { OpenSsl.randomFill(random, 1, Int.MAX_VALUE) }
        Crypto.wipe(random); assertContentEquals(ByteArray(34), random)
    }
}
