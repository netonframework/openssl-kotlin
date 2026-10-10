package neton.openssl

import kotlinx.cinterop.*
import neton.openssl.c.*
import kotlin.test.*

/**
 * The record lifetime contract of neton_quic_tls.h, on the C callbacks directly (moved here from quic's TlsSessionTest
 * with the callbacks): one outstanding record of at most 16384 bytes, unchanged until OpenSSL releases it, partial
 * releases, and the incoming bound.
 */
class QuicTlsCallbacksTest {
    @Test fun recordStaysPinnedUntilReleasedAndQueuesAreBounded() = memScoped {
        val ctx = assertNotNull(neton_qtls_ctx_new(1, "TLS_AES_128_GCM_SHA256", null))
        val params = byteArrayOf(1)
        val q = assertNotNull(params.usePinned { neton_qtls_new(ctx, 1, it.addressOf(0).reinterpret(), 1, null, 0, 0) })
        try {
            val record = 16384
            val first = ByteArray(record + 10) { it.toByte() }
            assertEquals(1, first.usePinned { neton_qtls_provide(q, it.addressOf(0).reinterpret(), first.size) })
            val buf = alloc<CPointerVar<UByteVar>>()
            val len = alloc<ULongVar>()
            assertEquals(1, neton_qtls_crypto_recv_rcd(null, buf.ptr, len.ptr, q))
            assertEquals(record.toULong(), len.value)
            val rec = buf.value!!
            // more data arriving does not touch the outstanding record
            val more = ByteArray(100) { 0x55 }
            assertEquals(1, more.usePinned { neton_qtls_provide(q, it.addressOf(0).reinterpret(), more.size) })
            for (i in 0 until record) assertEquals(i.toByte(), rec[i].toByte())
            // only one record at a time
            assertEquals(0, neton_qtls_crypto_recv_rcd(null, buf.ptr, len.ptr, q))
            assertEquals(3, neton_qtls_failure(q))                                       // a callback failure
            q.pointed.failure = 0
            // a partial release keeps it
            assertEquals(1, neton_qtls_crypto_release_rcd(null, 1000u, q))
            assertEquals(rec, q.pointed.record)
            assertEquals(3.toByte(), rec[3].toByte())
            assertEquals(1, neton_qtls_crypto_release_rcd(null, (record - 1000).toULong(), q))
            assertNull(q.pointed.record)
            assertEquals(1, neton_qtls_crypto_recv_rcd(null, buf.ptr, len.ptr, q))
            assertEquals(110uL, len.value)
            assertEquals(0, neton_qtls_crypto_release_rcd(null, 111u, q))                 // more than the record
            q.pointed.failure = 0
            assertEquals(1, neton_qtls_crypto_release_rcd(null, 110u, q))
            assertEquals(1, neton_qtls_crypto_recv_rcd(null, buf.ptr, len.ptr, q))
            assertEquals(0uL, len.value)
            val big = ByteArray(64 * 1024 + 1)
            assertEquals(0, big.usePinned { neton_qtls_provide(q, it.addressOf(0).reinterpret(), big.size) })
        } finally {
            neton_qtls_free(q)
            neton_qtls_ctx_free(ctx)
        }
    }
}
