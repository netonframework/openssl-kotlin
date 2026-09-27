package neton.openssl

import kotlinx.cinterop.*
import neton.openssl.c.*
import kotlin.test.*

/** Real TLS 1.3 through a bounded BIO pair, without network or an installed CA store. */
class TlsHandshakeTest {
    @Test fun trustedCertificateAndDataRoundTrip() = exercise(trust = true, hostname = "localhost", success = true)
    @Test fun untrustedCertificateFails() = exercise(trust = false, hostname = "localhost", success = false)
    @Test fun wrongHostnameFails() = exercise(trust = true, hostname = "wrong.invalid", success = false)
    @Test fun expiredCertificateFails() = exercise(trust = true, hostname = "localhost", success = false, expired = true)

    private fun exercise(trust: Boolean, hostname: String, success: Boolean, expired: Boolean = false) = memScoped {
        val keyContext = assertNotNull(EVP_PKEY_CTX_new_from_name(null, "EC", null))
        val keyOut = alloc<CPointerVar<EVP_PKEY>>()
        keyOut.value = null
        try {
            assertEquals(1, EVP_PKEY_keygen_init(keyContext))
            assertEquals(1, EVP_PKEY_CTX_set_group_name(keyContext, "prime256v1"))
            assertEquals(1, EVP_PKEY_generate(keyContext, keyOut.ptr))
        } finally { EVP_PKEY_CTX_free(keyContext) }
        val key = assertNotNull(keyOut.value)
        val cert = assertNotNull(X509_new())
        val serverContext = assertNotNull(SSL_CTX_new(TLS_method()))
        val clientContext = assertNotNull(SSL_CTX_new(TLS_method()))
        var server: CPointer<SSL>? = null
        var client: CPointer<SSL>? = null
        try {
            assertEquals(1, X509_set_version(cert, 2))
            assertEquals(1, ASN1_INTEGER_set(X509_get_serialNumber(cert), 1))
            assertNotNull(X509_gmtime_adj(X509_getm_notBefore(cert), -3600))
            assertNotNull(X509_gmtime_adj(X509_getm_notAfter(cert), if (expired) -60 else 3600))
            assertEquals(1, X509_set_pubkey(cert, key))
            val subject = assertNotNull(X509_get_subject_name(cert))
            assertEquals(1, X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
                "localhost".cstr.ptr.reinterpret(), -1, -1, 0))
            assertEquals(1, X509_set_issuer_name(cert, subject))
            val san = assertNotNull(X509V3_EXT_conf_nid(null, null, NID_subject_alt_name, "DNS:localhost"))
            try { assertEquals(1, X509_add_ext(cert, san, -1)) } finally { X509_EXTENSION_free(san) }
            assertTrue(X509_sign(cert, key, EVP_sha256()) > 0)
            assertEquals(1, neton_openssl_tls13_only(serverContext))
            assertEquals(1, neton_openssl_tls13_only(clientContext))
            assertEquals(1, SSL_CTX_use_certificate(serverContext, cert))
            assertEquals(1, SSL_CTX_use_PrivateKey(serverContext, key))
            SSL_CTX_set_verify(clientContext, SSL_VERIFY_PEER, null)
            val protocols = "\u0002h2".cstr.ptr.reinterpret<UByteVar>()
            SSL_CTX_set_alpn_select_cb(serverContext, staticCFunction { _: CPointer<SSL>?, out: CPointer<CPointerVar<UByteVar>>?, outLen: CPointer<UByteVar>?, offered: CPointer<UByteVar>?, offeredLen: UInt, arg: COpaquePointer? ->
                if (SSL_select_next_proto(out, outLen, arg?.reinterpret(), 3u, offered, offeredLen) == OPENSSL_NPN_NEGOTIATED)
                    SSL_TLSEXT_ERR_OK else SSL_TLSEXT_ERR_ALERT_FATAL
            }, protocols)
            if (trust) assertEquals(1, X509_STORE_add_cert(SSL_CTX_get_cert_store(clientContext), cert))
            server = assertNotNull(SSL_new(serverContext))
            client = assertNotNull(SSL_new(clientContext))
            assertEquals(1, SSL_set1_host(client, hostname))
            assertEquals(0, SSL_set_alpn_protos(client, protocols, 3u))
            val a = alloc<CPointerVar<BIO>>()
            val b = alloc<CPointerVar<BIO>>()
            assertEquals(1, BIO_new_bio_pair(a.ptr, 4096u, b.ptr, 4096u))
            SSL_set_bio(client, a.value, a.value)
            SSL_set_bio(server, b.value, b.value)
            SSL_set_connect_state(client)
            SSL_set_accept_state(server)
            var failed = false
            var completed = false
            for (round in 0 until 1000) {
                for (session in listOf(client, server)) {
                    ERR_clear_error()
                    val result = SSL_do_handshake(session)
                    if (result != 1) {
                        val error = SSL_get_error(session, result)
                        if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) failed = true
                    }
                }
                completed = SSL_is_init_finished(client) == 1 && SSL_is_init_finished(server) == 1
                if (failed || completed) break
            }
            if (!success) {
                assertTrue(failed, "Expected a certificate verification failure, not timeout")
                val expected = when {
                    expired -> X509_V_ERR_CERT_HAS_EXPIRED
                    trust -> X509_V_ERR_HOSTNAME_MISMATCH
                    else -> X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
                }
                assertEquals(expected.toLong(), SSL_get_verify_result(client).toLong())
            } else {
                assertFalse(failed)
                assertTrue(completed, "TLS handshake exceeded bounded pump iterations")
                assertEquals("TLSv1.3", SSL_get_version(client)?.toKString())
                val alpn = alloc<CPointerVar<UByteVar>>()
                val alpnSize = alloc<UIntVar>()
                SSL_get0_alpn_selected(client, alpn.ptr, alpnSize.ptr)
                assertEquals(2u, alpnSize.value)
                assertContentEquals("h2".encodeToByteArray(), assertNotNull(alpn.value).readBytes(2))
                val sent = "hello-openssl-4".encodeToByteArray()
                sent.usePinned { assertEquals(sent.size, SSL_write(client, it.addressOf(0), sent.size)) }
                val received = ByteArray(64)
                val count = received.usePinned { SSL_read(server, it.addressOf(0), received.size) }
                assertEquals(sent.size, count)
                assertContentEquals(sent, received.copyOf(count))
            }
        } finally {
            SSL_free(client); SSL_free(server)
            SSL_CTX_free(clientContext); SSL_CTX_free(serverContext)
            X509_free(cert); EVP_PKEY_free(key)
            ERR_clear_error()
        }
    }

    @Test fun quicTlsEntryPointsAreLinkedAndRejectMissingSetup() = memScoped {
        assertEquals(2001, OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_SEND)
        assertEquals(2004, OSSL_FUNC_SSL_QUIC_TLS_YIELD_SECRET)
        val context = assertNotNull(SSL_CTX_new(TLS_method()))
        try {
            val session = assertNotNull(SSL_new(context))
            try {
                val end = alloc<OSSL_DISPATCH>()
                end.function_id = 0
                end.function = null
                assertEquals(0, SSL_set_quic_tls_cbs(session, end.ptr, null))
                assertEquals(0, SSL_set_quic_tls_transport_params(session, null, 0u))
                assertEquals(0, SSL_set_quic_tls_early_data_enabled(session, 0))
            } finally { SSL_free(session); ERR_clear_error() }
        } finally { SSL_CTX_free(context) }
    }
}
