package neton.openssl

import kotlinx.cinterop.*
import neton.openssl.c.*
import kotlin.test.*

class AeadTest {
    @Test fun aes128GcmKnownVectorAndTamperRejection() = memScoped {
        val key = ByteArray(16)
        val iv = ByteArray(12)
        val plaintext = ByteArray(16)
        val ciphertext = ByteArray(32)
        val tag = ByteArray(16)
        val n = alloc<IntVar>()
        val encrypt = assertNotNull(EVP_CIPHER_CTX_new())
        try {
            key.usePinned { k -> iv.usePinned { v ->
                assertEquals(1, EVP_EncryptInit_ex(encrypt, EVP_aes_128_gcm(), null, k.addressOf(0).reinterpret(), v.addressOf(0).reinterpret()))
            } }
            ciphertext.usePinned { out -> plaintext.usePinned { input ->
                assertEquals(1, EVP_EncryptUpdate(encrypt, out.addressOf(0).reinterpret(), n.ptr, input.addressOf(0).reinterpret(), plaintext.size))
                assertEquals(16, n.value)
                assertEquals(1, EVP_EncryptFinal_ex(encrypt, out.addressOf(16).reinterpret(), n.ptr))
                assertEquals(0, n.value)
            } }
            tag.usePinned { assertEquals(1, EVP_CIPHER_CTX_ctrl(encrypt, EVP_CTRL_GCM_GET_TAG, 16, it.addressOf(0))) }
        } finally { EVP_CIPHER_CTX_free(encrypt) }
        assertEquals("0388dace60b6a392f328c2b971b2fe78", ciphertext.copyOf(16).hex())
        assertEquals("ab6e47d42cec13bdf53a67b21257bddf", tag.hex())

        for (tamper in listOf(false, true)) {
            val decrypt = assertNotNull(EVP_CIPHER_CTX_new())
            val output = ByteArray(32)
            val suppliedTag = tag.copyOf()
            if (tamper) suppliedTag[0] = (suppliedTag[0].toInt() xor 1).toByte()
            try {
                key.usePinned { k -> iv.usePinned { v ->
                    assertEquals(1, EVP_DecryptInit_ex(decrypt, EVP_aes_128_gcm(), null, k.addressOf(0).reinterpret(), v.addressOf(0).reinterpret()))
                } }
                output.usePinned { out -> ciphertext.usePinned { input ->
                    assertEquals(1, EVP_DecryptUpdate(decrypt, out.addressOf(0).reinterpret(), n.ptr, input.addressOf(0).reinterpret(), 16))
                    assertEquals(16, n.value)
                    suppliedTag.usePinned { assertEquals(1, EVP_CIPHER_CTX_ctrl(decrypt, EVP_CTRL_GCM_SET_TAG, 16, it.addressOf(0))) }
                    assertEquals(if (tamper) 0 else 1, EVP_DecryptFinal_ex(decrypt, out.addressOf(16).reinterpret(), n.ptr))
                } }
                if (!tamper) assertContentEquals(plaintext, output.copyOf(16))
            } finally {
                output.fill(0)
                EVP_CIPHER_CTX_free(decrypt)
                ERR_clear_error()
            }
        }
    }
    private fun ByteArray.hex() = joinToString("") { (it.toInt() and 255).toString(16).padStart(2, '0') }
}
