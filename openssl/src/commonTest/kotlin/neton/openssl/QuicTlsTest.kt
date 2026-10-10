@file:OptIn(kotlin.io.encoding.ExperimentalEncodingApi::class)
package neton.openssl

import kotlin.io.encoding.Base64
import kotlin.test.*

/**
 * The QUIC TLS facade (docs/QUIC_TLS.md) on every platform: a client and a server exchange CRYPTO bytes in memory the
 * way QUIC does, each level delivered once the receiver holds that level's read secret.
 */
class QuicTlsTest {
    private val suites = listOf("TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256")

    private fun der(pem: ByteArray): ByteArray =
        Base64.decode(pem.decodeToString().lines().filter { it.isNotEmpty() && !it.startsWith("-----") }.joinToString(""))

    private fun wire(vararg protocols: String): ByteArray {
        val out = ArrayList<Byte>()
        for (p in protocols) { out += p.length.toByte(); out += p.encodeToByteArray().toList() }
        return out.toByteArray()
    }

    private val identity = testIdentity()
    private val clientParams = "client transport parameters".encodeToByteArray()
    private val serverParams = "server transport parameters".encodeToByteArray()

    private fun serverContext(keyLog: Boolean = false) = QuicTlsContext(
        server = true, cipherSuites = suites, verifyMode = 0,
        certificateChainDer = listOf(der(identity.certificate)), privateKey = identity.key, privateKeyIsPem = true, keyLog = keyLog,
    )

    private fun clientContext(anchor: ByteArray = identity.certificate, keyLog: Boolean = false) = QuicTlsContext(
        server = false, cipherSuites = suites, verifyMode = 1, trustAnchorsDer = listOf(der(anchor)), keyLog = keyLog,
    )

    /** One side of the in-memory exchange: its pending CRYPTO bytes per level and the secrets it produced. */
    private class Side(val tls: QuicTls) {
        val pending = Array(4) { ArrayList<ByteArray>() }
        var readLevel = 0
        var result = 0
        var complete = false
        val read = arrayOfNulls<ByteArray>(4)
        val write = arrayOfNulls<ByteArray>(4)

        fun step(peer: Side) {
            // Deliver what is pending at our read level, then run OpenSSL once.
            for (b in pending[readLevel]) assertTrue(tls.provide(b))
            pending[readLevel].clear()
            result = tls.drive(complete)
            if (result == 1 && tls.initFinished) complete = true
            for (level in 2..3) {
                tls.takeSecret(level, 0)?.let { read[level] = it; readLevel = level }
                tls.takeSecret(level, 1)?.let { write[level] = it }
            }
            for (level in 0..3) tls.takeOutgoing(level).takeIf { it.isNotEmpty() }?.let { peer.pending[level] += it }
        }
    }

    /** Runs the handshake until both are complete and nothing is in flight, or one fails. */
    private fun exchange(client: Side, server: Side) {
        repeat(50) {
            client.step(server)
            if (client.result < 0) return
            server.step(client)
            if (server.result < 0) return
            if (client.complete && server.complete && client.pending.all { it.isEmpty() } && server.pending.all { it.isEmpty() }) return
        }
        fail("the handshake did not settle")
    }

    private fun connect(
        serverCtx: QuicTlsContext, clientCtx: QuicTlsContext,
        serverAlpn: ByteArray = wire("h3"), clientAlpn: ByteArray = wire("h3"),
        ticket: ByteArray? = null, earlyData: Boolean = true,
    ): Pair<Side, Side> {
        val client = Side(clientCtx.newConnection(clientParams))
        assertTrue(client.tls.setServerName("localhost", ip = false))
        if (clientAlpn.isNotEmpty()) assertTrue(client.tls.offerAlpn(clientAlpn))
        if (ticket != null) assertTrue(client.tls.resume(ticket, earlyData, clientAlpn))
        val server = Side(serverCtx.newConnection(serverParams, serverAlpn))
        if (earlyData) assertTrue(server.tls.enableEarlyData())
        return client to server
    }

    @Test fun aHandshakeAgreesOnSecretsParametersAndProtocol() {
        val s = serverContext(); val c = clientContext()
        val (client, server) = connect(s, c)
        try {
            exchange(client, server)
            assertTrue(client.complete && server.complete && client.result >= 0 && server.result >= 0)
            for (level in 2..3) {
                assertContentEquals(client.write[level], server.read[level], "client write = server read at $level")
                assertContentEquals(server.write[level], client.read[level], "server write = client read at $level")
                assertEquals(client.tls.suite(level), server.tls.suite(level))
            }
            assertContentEquals(serverParams, client.tls.peerTransportParameters())
            assertContentEquals(clientParams, server.tls.peerTransportParameters())
            assertEquals("h3", client.tls.selectedAlpn()?.decodeToString())
            assertEquals("localhost", server.tls.serverName())
            assertContentEquals(der(identity.certificate), client.tls.peerCertificates().single())
            val a = ByteArray(32); val b = ByteArray(32)
            assertTrue(client.tls.exportKeyingMaterial(a, "EXPORTER-test", ByteArray(0)))
            assertTrue(server.tls.exportKeyingMaterial(b, "EXPORTER-test", ByteArray(0)))
            assertContentEquals(a, b)
            assertEquals(QuicTlsFailure.NONE, client.tls.failure); assertEquals(-1, client.tls.alert)
        } finally { client.tls.close(); server.tls.close(); s.close(); c.close() }
    }

    @Test fun aTicketResumesWithZeroRtt() {
        val s = serverContext(); val c = clientContext()
        try {
            val (c1, s1) = connect(s, c)
            val tickets = try {
                exchange(c1, s1)
                s1.tls.markCleanShutdown()
                c1.tls.takeTickets()
            } finally { c1.tls.close(); s1.tls.close() }
            assertTrue(tickets.isNotEmpty(), "no ticket")
            val (der, allowsEarly) = tickets.last()
            assertTrue(allowsEarly, "the ticket does not allow 0-RTT")
            val (c2, s2) = connect(s, c, ticket = der)
            try {
                c2.step(s2)                                           // ClientHello, and the early secret
                val clientEarly = assertNotNull(c2.tls.takeEarlySecret(), "no client early secret")
                exchange(c2, s2)
                assertTrue(c2.complete && s2.complete && c2.result >= 0 && s2.result >= 0)
                assertTrue(c2.tls.earlyDataAccepted, "0-RTT not accepted")
                assertContentEquals(clientEarly, s2.tls.takeEarlySecret(), "server early secret")
                assertEquals(c2.tls.suite(1), s2.tls.suite(1))
            } finally { c2.tls.close(); s2.tls.close() }
        } finally { s.close(); c.close() }
    }

    @Test fun noCommonProtocolIsNoApplicationProtocol() {
        val s = serverContext(); val c = clientContext()
        val (client, server) = connect(s, c, serverAlpn = wire("h2"), clientAlpn = wire("h3"))
        try {
            exchange(client, server)
            assertEquals(-1, server.result)
            assertEquals(120, server.tls.alert)
        } finally { client.tls.close(); server.tls.close(); s.close(); c.close() }
    }

    @Test fun anUntrustedServerFailsTheClient() {
        val s = serverContext(); val c = clientContext(anchor = testIdentity().certificate)
        val (client, server) = connect(s, c)
        try {
            exchange(client, server)
            assertEquals(-1, client.result)
            assertTrue(client.tls.alert >= 0, "no alert")
        } finally { client.tls.close(); server.tls.close(); s.close(); c.close() }
    }

    @Test fun cryptoDataLeftAtAKeyChangeIsUnexpectedMessage() {
        val s = serverContext(); val c = clientContext()
        val (client, server) = connect(s, c)
        try {
            client.step(server)
            server.pending[0] += byteArrayOf(1)                      // one byte more than the ClientHello
            server.step(client)
            // The byte travels in the same record as the ClientHello, so OpenSSL itself refuses it with
            // unexpected_message (10); the facade's own check covers bytes OpenSSL has not taken yet. Both are crypto(10).
            assertEquals(-1, server.result)
            assertTrue(server.tls.alert == 10 || server.tls.failure == QuicTlsFailure.UNEXPECTED_MESSAGE,
                "alert ${server.tls.alert}, failure ${server.tls.failure} ${server.tls.failureMessage}")
        } finally { client.tls.close(); server.tls.close(); s.close(); c.close() }
    }

    @Test fun incomingBytesAreBounded() {
        val s = serverContext()
        val server = s.newConnection(serverParams, wire("h3"))
        try {
            assertTrue(server.provide(ByteArray(64 * 1024)))
            assertEquals(64 * 1024, server.incoming)
            assertFalse(server.provide(ByteArray(1)))
        } finally { server.close(); s.close() }
    }

    @Test fun anInjectedCallbackFailureFailsTheCall() {
        val s = serverContext(); val c = clientContext()
        val (client, server) = connect(s, c)
        try {
            server.tls.injectCallbackFailure(QuicTlsCallback.YIELD_SECRET)
            exchange(client, server)
            assertEquals(-1, server.result)
            assertEquals(QuicTlsFailure.CALLBACK, server.tls.failure)
            assertEquals("injected failure in YIELD_SECRET", server.tls.failureMessage)
        } finally { client.tls.close(); server.tls.close(); s.close(); c.close() }
    }

    @Test fun aFailingTicketCallbackOnlyDropsTheTicket() {
        val s = serverContext(); val c = clientContext()
        val (client, server) = connect(s, c)
        try {
            client.tls.injectCallbackFailure(QuicTlsCallback.NEW_SESSION)
            exchange(client, server)
            assertTrue(client.complete && client.result >= 0)
            assertEquals(1, client.tls.droppedTickets)
            assertEquals(QuicTlsFailure.NONE, client.tls.failure)
        } finally { client.tls.close(); server.tls.close(); s.close(); c.close() }
    }

    @Test fun keyLogLinesAreCollected() {
        val s = serverContext(keyLog = true); val c = clientContext(keyLog = true)
        val (client, server) = connect(s, c)
        try {
            exchange(client, server)
            val lines = client.tls.takeKeyLog()
            assertTrue(lines.any { it.startsWith("CLIENT_HANDSHAKE_TRAFFIC_SECRET ") }, "$lines")
            assertTrue(lines.any { it.startsWith("SERVER_TRAFFIC_SECRET_0 ") }, "$lines")
            assertTrue(client.tls.takeKeyLog().isEmpty(), "taken once")
        } finally { client.tls.close(); server.tls.close(); s.close(); c.close() }
    }

    @Test fun credentialsAreChecked() {
        val certs = QuicTlsCredentials.pemCertificates(identity.certificate + identity.certificate)
        assertEquals(2, certs.size)
        assertContentEquals(der(identity.certificate), certs[0])
        assertTrue(QuicTlsCredentials.isCertificate(certs[0]))
        assertFalse(QuicTlsCredentials.isCertificate(certs[0] + byteArrayOf(0)))
        assertFalse(QuicTlsCredentials.isCertificate(byteArrayOf(1, 2, 3)))
        assertTrue(QuicTlsCredentials.pemCertificates("no certificate here".encodeToByteArray()).isEmpty())
        assertTrue(QuicTlsCredentials.isPrivateKey(identity.key, pem = true))
        assertFalse(QuicTlsCredentials.isPrivateKey(identity.key, pem = false))
        assertFalse(QuicTlsCredentials.isPrivateKey(identity.certificate, pem = true))
    }

    /** Our transport parameters may be empty (all defaults): the connection is still created (quic's default server). */
    @Test fun emptyTransportParametersAreAllowed() {
        val s = serverContext()
        try { s.newConnection(ByteArray(0), wire("h3")).close() } finally { s.close() }
    }
}
