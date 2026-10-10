# QUIC TLS facade (JVM phase 3, design, 2026-10-11)

What `com.netonstream:quic` needs from OpenSSL 4.0's third-party QUIC TLS API (`SSL_set_quic_tls_cbs`), as one facade
with the same behaviour on Kotlin/Native and on the JVM. Today quic implements it itself in nativeMain
(`TlsSession`, `TlsConfig`: callbacks are Kotlin `staticCFunction`s reaching a `TlsCore` through a StableRef). The
JVM cannot be called back that way, so the callbacks move into C and queue what they observe; Kotlin takes it after
each OpenSSL call. quic keeps its protocol logic (levels, key hand-over, errors) and moves it to commonMain on top.

## C layer: `neton_quic_tls.h` (header-only, used by cinterop and by the JNI library)

One `neton_qtls` per connection, owning its `SSL`, set as the SSL's ex_data 0 (the context callbacks find it there):

| Callback | Behaviour (identical to quic's `TlsCore` today) |
|---|---|
| CRYPTO_RECV_RCD | hands out up to 16384 queued incoming bytes as one record (a malloc'd copy), or none; one outstanding at a time |
| CRYPTO_RELEASE_RCD | releases a prefix or all of the outstanding record |
| CRYPTO_SEND | appends to the outgoing buffer of the current write level; over 1 MiB pending → failure INTERNAL_ERROR |
| YIELD_SECRET | early (level 1): the early secret and its suite (pending cipher, else the session's); handshake / application: the secret per level and direction with the suite; a read secret while incoming bytes are queued → failure crypto(unexpected_message) ("CRYPTO data after a key change"); sets the read / write level |
| GOT_TRANSPORT_PARAMS | copies the peer's parameters |
| ALERT | records the first alert |
| ALPN select (ctx) | server preference over the client's list; none in common → fatal (no_application_protocol) |
| client hello (ctx) | a server with protocols refuses a ClientHello without ALPN (no_application_protocol) |
| key log (ctx) | appends the line to the connection's key-log queue (only when enabled) |
| new session (ctx) | appends the DER ticket and whether it allows 0-RTT; a failure only counts a dropped ticket |

A callback never fails silently: it records the first failure (a code plus a message) and returns 0; the facade
throws it after the OpenSSL call. Incoming bytes queued but not taken are limited to 64 KiB (CRYPTO_BUFFER_EXCEEDED).
A test hook makes a named callback fail once (quic's C-boundary tests).

Functions: create from a context (own transport parameters copied into memory owned by the connection), set
connect/accept state, server name or IP, ALPN offer, resume a DER session (with or without 0-RTT), enable early
data; `provide(bytes)`; `drive()` (SSL_do_handshake, or SSL_read(NULL, 0) after completion; returns
complete / want-read / error and whether init is finished); accessors for queued outgoing bytes per level, secrets
per level and direction (copied out then wiped), early secret, peer parameters, alert, failure, ALPN, SNI, peer
certificates (DER), early-data status, new tickets, key-log lines, the session's ALPN; exporter; clean shutdown
marking; free (SSL first, then buffers wiped).

Context creation (`neton_qtls_ctx_*`): TLS 1.3 only, no compression, cipher suites, groups, trust anchors (DER),
identity (DER chain + PEM or DER key), verify mode, session cache mode and id context, early data, the four context
callbacks; the server's ALPN list kept on the context.

## Kotlin facade (commonMain, `neton.openssl.quic`)

`QuicTlsContext` (client or server settings, closeable, shared by connections) and `QuicTls` (one connection,
closeable): `provide`, `drive`, `takeOutgoing(level)`, `takeSecret(level, direction)`, `takeEarlySecret`, `peerParams`,
`alert`, `alpn`, `serverName`, `peerCertificates`, `earlyDataAccepted`, `takeTickets`, `takeKeyLogLines`,
`exportKeyingMaterial`, `markCleanShutdown`, `close`. Behind it an `internal expect object QuicTlsPrimitives` with long
handles, cinterop and JNI, as `TlsPrimitives`.

## Gates

1. openssl-kotlin, native: a client and a server facade complete a handshake in memory (CRYPTO bytes moved per
   level), derive equal secrets, exchange transport parameters, agree on ALPN; resumption with a ticket and 0-RTT
   accepted and refused; each failure path (no common ALPN, bad certificate, CRYPTO data after a key change, buffer
   limits, injected callback failures) gives the same error as quic's `TlsSession` today.
2. The same tests on the JVM.
3. quic switches its native `TlsSession` / `TlsConfig` to the facade with no behaviour change: its full suite (625
   tests) and the h3 / interop checks pass; then they move to commonMain.
