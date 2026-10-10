package neton.openssl

import kotlin.test.*

/** TlsContext / TlsEngine on every platform (native and JVM), over the fixed [testIdentity] certificates. */
class TlsEngineTest {
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
