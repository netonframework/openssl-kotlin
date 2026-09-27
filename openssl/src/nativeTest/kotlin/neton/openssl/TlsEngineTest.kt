package neton.openssl

import kotlinx.cinterop.*
import neton.openssl.c.*
import kotlin.test.*
import kotlin.native.concurrent.Worker
import kotlin.native.concurrent.TransferMode

internal data class TestIdentity(val certificate: ByteArray, val key: ByteArray)

/** Test fixture only, never part of production trust configuration. */
internal fun testIdentity(expired: Boolean = false): TestIdentity = memScoped {
    val keyContext = assertNotNull(EVP_PKEY_CTX_new_from_name(null, "EC", null))
    val out = alloc<CPointerVar<EVP_PKEY>>()
    out.value = null
    try {
        assertEquals(1, EVP_PKEY_keygen_init(keyContext))
        assertEquals(1, EVP_PKEY_CTX_set_group_name(keyContext, "prime256v1"))
        assertEquals(1, EVP_PKEY_generate(keyContext, out.ptr))
    } finally { EVP_PKEY_CTX_free(keyContext) }
    val key = assertNotNull(out.value); val cert = assertNotNull(X509_new())
    try {
        assertEquals(1, X509_set_version(cert, 2))
        assertEquals(1, ASN1_INTEGER_set(X509_get_serialNumber(cert), 1))
        assertNotNull(X509_gmtime_adj(X509_getm_notBefore(cert), -3600))
        assertNotNull(X509_gmtime_adj(X509_getm_notAfter(cert), if (expired) -60 else 3600))
        assertEquals(1, X509_set_pubkey(cert, key))
        val subject = assertNotNull(X509_get_subject_name(cert))
        assertEquals(1, X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, "localhost".cstr.ptr.reinterpret(), -1, -1, 0))
        assertEquals(1, X509_set_issuer_name(cert, subject))
        val san = assertNotNull(X509V3_EXT_conf_nid(null, null, NID_subject_alt_name, "DNS:localhost,IP:127.0.0.1"))
        try { assertEquals(1, X509_add_ext(cert, san, -1)) } finally { X509_EXTENSION_free(san) }
        assertTrue(X509_sign(cert, key, EVP_sha256()) > 0)
        fun encode(writer: (CPointer<BIO>) -> Int): ByteArray {
            val bio = assertNotNull(BIO_new(BIO_s_mem()))
            try {
                assertEquals(1, writer(bio))
                val bytes = ByteArray(BIO_ctrl_pending(bio).toInt())
                bytes.usePinned { assertEquals(bytes.size, BIO_read(bio, it.addressOf(0), bytes.size)) }
                return bytes
            } finally { BIO_free(bio) }
        }
        TestIdentity(encode { PEM_write_bio_X509(it, cert) }, encode { PEM_write_bio_PrivateKey(it, key, null, null, 0, null, null) })
    } finally { X509_free(cert); EVP_PKEY_free(key) }
}

class TlsEngineTest {
    @Test fun frozenContextCreatesEnginesAcrossThreads() {
        val context = TlsContext(false, testIdentity().certificate)
        val workers = List(4) { Worker.start() }
        try {
            val futures = workers.map { worker -> worker.execute(TransferMode.SAFE, { context }) { factory ->
                repeat(200) { factory.newEngine(PeerIdentity.Dns("localhost")).close() }
                200
            } }
            assertEquals(800, futures.sumOf { it.result })
        } finally {
            workers.forEach { it.requestTermination().result }
            context.close()
        }
    }
    private class Wire(private val sender: TlsEngine, private val receiver: TlsEngine) {
        private val bytes = ByteArray(37)
        private var size = 0; private var offset = 0
        val pending get() = size != offset
        fun step() {
            if (!pending) { size = sender.drainCiphertext(bytes); offset = 0 }
            if (pending) offset += receiver.feedCiphertext(bytes, offset, size - offset)
        }
    }
    private class Pair(val client: TlsEngine, val server: TlsEngine) : AutoCloseable {
        val a = Wire(client, server); val b = Wire(server, client)
        fun transfer() { a.step(); b.step() }
        fun handshake() {
            val scratch = ByteArray(1)
            var clientDone = false; var serverDone = false
            repeat(10000) {
                if (!clientDone) clientDone = client.handshake() == TlsProgress.COMPLETE
                else assertTrue(client.read(scratch) < 0) // Consume TLS1.3 post-handshake tickets.
                if (!serverDone) serverDone = server.handshake() == TlsProgress.COMPLETE
                transfer()
                if (clientDone && serverDone && !a.pending && !b.pending && client.pendingCiphertext == 0 && server.pendingCiphertext == 0) return
            }
            fail("Bounded TLS handshake pump exhausted")
        }
        override fun close() { client.close(); server.close() }
    }
    private fun pair(version: TlsVersion = TlsVersion.TLS13, peer: PeerIdentity = PeerIdentity.Dns("localhost"), identity: TestIdentity = testIdentity(), roots: ByteArray = identity.certificate,
        clientAlpn: List<String> = listOf("http/1.1", "h2"), serverAlpn: List<String> = listOf("h2", "http/1.1"), auth: ClientAuthentication = ClientAuthentication.NONE, clientIdentity: TestIdentity? = null): Pair {
        val client = TlsContext(false, roots, clientIdentity?.certificate, clientIdentity?.key, version, version, clientAlpn)
        val server = TlsContext(true, clientIdentity?.certificate ?: roots, identity.certificate, identity.key, version, version, serverAlpn, auth)
        try { return Pair(client.newEngine(peer, 1024), server.newEngine(bufferCapacity = 1024)) }
        finally { client.close(); server.close() } // SSL retains its context and callbacks.
    }

    @Test fun fragmentedHandshakeTls12And13AndExporter() {
        for (version in TlsVersion.entries) {
            val pair = pair(version)
            try {
                pair.handshake()
                assertEquals("h2", pair.client.negotiatedAlpn)
                assertEquals(if (version == TlsVersion.TLS12) "TLSv1.2" else "TLSv1.3", pair.client.protocolVersion)
                assertNotNull(pair.client.cipherSuite)
                assertEquals("localhost", pair.server.serverName)
                assertEquals(1, pair.client.peerCertificateChainDer().size)
                assertEquals(0x30, pair.client.peerCertificateChainDer().first().first().toInt())
                val a = ByteArray(32); val b = ByteArray(32)
                pair.client.exportKeyingMaterial("test-exporter", null, a)
                pair.server.exportKeyingMaterial("test-exporter", null, b)
                assertContentEquals(a, b)
                pair.server.exportKeyingMaterial("different-label", null, b)
                assertFalse(a.contentEquals(b))
            } finally { pair.close() }
        }
    }

    @Test fun writeBackpressureAndRetryOwnsPlaintext() {
        val pair = pair(); val plain = ByteArray(16384) { it.toByte() }; val out = ByteArray(16384)
        try {
            pair.handshake()
            assertEquals(TlsEngine.NEED_WRITE, pair.client.write(plain))
            val changed = plain.copyOf(); changed[0] = 1
            assertFailsWith<IllegalArgumentException> { pair.client.write(changed) }
            assertFailsWith<IllegalStateException> { pair.client.closeNotify() }
            var sent = false; var received = 0
            repeat(20000) {
                pair.transfer()
                if (!sent) sent = pair.client.write(plain) == plain.size
                if (received < out.size) {
                    val n = pair.server.read(out, received)
                    if (n > 0) received += n else assertTrue(n == TlsEngine.NEED_READ || n == TlsEngine.NEED_WRITE)
                }
                if (sent && received == out.size) return@repeat
            }
            assertTrue(sent); assertEquals(plain.size, received); assertContentEquals(plain, out)
        } finally { pair.close() }
    }

    @Test fun trustHostnameExpiryAndAlpnFailuresAreTyped() {
        fun fails(expected: TlsFailureKind, create: () -> Pair) {
            val pair = create()
            try { assertEquals(expected, assertFailsWith<TlsException> { pair.handshake() }.kind) }
            finally { pair.close() }
        }
        fails(TlsFailureKind.HOSTNAME) { pair(peer = PeerIdentity.Dns("wrong.invalid")) }
        fails(TlsFailureKind.CERTIFICATE) { pair(roots = testIdentity().certificate) }
        fails(TlsFailureKind.EXPIRED) { pair(identity = testIdentity(expired = true)) }
        fails(TlsFailureKind.PROTOCOL) { pair(clientAlpn = listOf("h3")) }
        val ip = pair(peer = PeerIdentity.Ip("127.0.0.1"))
        try { ip.handshake() } finally { ip.close() }
    }

    @Test fun mutualTlsRequiredAndOptional() {
        val required = pair(auth = ClientAuthentication.REQUIRE, clientIdentity = testIdentity())
        try { required.handshake() } finally { required.close() }
        val missing = pair(auth = ClientAuthentication.REQUIRE)
        try { assertFailsWith<TlsException> { missing.handshake() } } finally { missing.close() }
        val optional = pair(auth = ClientAuthentication.REQUEST)
        try { optional.handshake() } finally { optional.close() }
    }

    @Test fun cleanShutdownAndTruncatedTransportDiffer() {
        val pair = pair()
        try {
            pair.handshake(); pair.client.closeNotify()
            repeat(100) { pair.transfer() }
            assertEquals(TlsEngine.PEER_CLOSED, pair.server.read(ByteArray(1)))
            pair.server.closeNotify(); repeat(100) { pair.transfer() }
            assertEquals(TlsProgress.COMPLETE, pair.client.closeNotify())
            assertFailsWith<IllegalStateException> { pair.client.write(byteArrayOf(1)) }
        } finally { pair.close() }
        val truncated = pair()
        try {
            truncated.handshake(); truncated.client.transportEof()
            assertEquals(TlsFailureKind.UNEXPECTED_EOF, assertFailsWith<TlsException> { truncated.client.read(ByteArray(1)) }.kind)
        } finally { truncated.close() }
    }

    @Test fun invalidConfigurationCloseAndBounds() {
        assertFailsWith<IllegalArgumentException> { TlsContext(false) }
        assertFailsWith<OpenSslException> { TlsContext(false, byteArrayOf(1, 2, 3)) }
        val id = testIdentity(); val other = testIdentity()
        assertFailsWith<OpenSslException> { TlsContext(true, certificateChainPem = id.certificate, privateKeyPem = other.key) }
        val context = TlsContext(false, id.certificate)
        val engine = context.newEngine(PeerIdentity.Dns("localhost")); context.close(); context.close()
        try {
            assertFailsWith<IllegalStateException> { context.newEngine(PeerIdentity.Dns("localhost")) }
            assertFailsWith<IllegalArgumentException> { engine.feedCiphertext(ByteArray(1), 0, Int.MAX_VALUE) }
        } finally { engine.close() }
        engine.close()
        assertFailsWith<IllegalStateException> { engine.handshake() }
    }
}
