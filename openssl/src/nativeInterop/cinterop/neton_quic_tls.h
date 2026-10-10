#ifndef NETON_QUIC_TLS_H
#define NETON_QUIC_TLS_H
/*
 * QUIC TLS over OpenSSL's third-party QUIC TLS API (docs/QUIC_TLS.md), for Kotlin/Native (cinterop) and the JVM (JNI):
 * the callbacks live here and queue what they observe; the caller takes it after each OpenSSL call. Behaviour follows
 * com.netonstream:quic's TlsCore exactly (limits, the first failure kept, key-change checks).
 */
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/core_dispatch.h>
#include <openssl/err.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#define NETON_QTLS_MAX_RECORD 16384
#define NETON_QTLS_MAX_INCOMING (64 * 1024)
#define NETON_QTLS_MAX_OUTGOING (1024 * 1024)

/* Failure kinds (QuicTlsFailure order): the caller maps them to QUIC transport errors. */
#define NETON_QTLS_FAIL_NONE 0
#define NETON_QTLS_FAIL_INTERNAL 1            /* INTERNAL_ERROR with the message */
#define NETON_QTLS_FAIL_UNEXPECTED_MESSAGE 2  /* crypto(unexpected_message): CRYPTO data after a key change */
#define NETON_QTLS_FAIL_CALLBACK 3            /* a callback failed: INTERNAL_ERROR "TLS callback failed: <message>" */

/* Callbacks a test can make fail (quic's TlsCallback order). */
#define NETON_QTLS_CB_CRYPTO_SEND 0
#define NETON_QTLS_CB_CRYPTO_RECV_RCD 1
#define NETON_QTLS_CB_CRYPTO_RELEASE_RCD 2
#define NETON_QTLS_CB_YIELD_SECRET 3
#define NETON_QTLS_CB_GOT_TRANSPORT_PARAMS 4
#define NETON_QTLS_CB_ALERT 5
#define NETON_QTLS_CB_ALPN_SELECT 6
#define NETON_QTLS_CB_CLIENT_HELLO 7
#define NETON_QTLS_CB_NEW_SESSION 8

typedef struct { unsigned char *data; size_t len, cap; } neton_qbuf;

static inline int neton_qbuf_append(neton_qbuf *b, const unsigned char *p, size_t n) {
    if (n == 0) return 1;
    if (b->len + n > b->cap) {
        size_t cap = b->cap ? b->cap : 256;
        unsigned char *grown;
        while (cap < b->len + n) cap *= 2;
        grown = OPENSSL_malloc(cap);
        if (!grown) return 0;
        if (b->len) memcpy(grown, b->data, b->len);
        OPENSSL_clear_free(b->data, b->cap);
        b->data = grown; b->cap = cap;
    }
    memcpy(b->data + b->len, p, n); b->len += n;
    return 1;
}
static inline void neton_qbuf_free(neton_qbuf *b) {
    OPENSSL_clear_free(b->data, b->cap); b->data = NULL; b->len = b->cap = 0;
}
static inline void neton_qbuf_clear(neton_qbuf *b) { if (b->data) OPENSSL_cleanse(b->data, b->len); b->len = 0; }

typedef struct {
    SSL *ssl;
    int server;
    /* incoming CRYPTO bytes: [in_head, in.len) not yet handed out */
    neton_qbuf in; size_t in_head;
    int read_level, write_level;
    unsigned char *record; size_t record_len, record_released;
    /* outgoing CRYPTO bytes per protection level */
    neton_qbuf out[4]; size_t out_total;
    /* secrets per level and direction (0 read, 1 write), the suite (TLS code point) per level */
    unsigned char secret[4][2][48]; int secret_len[4][2]; int suite[4];
    unsigned char early_secret[48]; int early_len, early_suite;
    neton_qbuf peer_params; int has_peer_params;
    unsigned char *own_params; size_t own_params_len;
    int alert;
    int failure; char message[160];
    int inject;
    /* server ALPN protocols, wire format, in preference order */
    unsigned char *server_alpn; size_t server_alpn_len;
    /* tickets: [u32 length][u8 allows 0-RTT][DER] each; dropped count */
    neton_qbuf tickets; int dropped_tickets;
    int keylog; neton_qbuf keylog_lines;
} neton_qtls;

static const char *const neton_qtls_cb_names[] = {
    "CRYPTO_SEND", "CRYPTO_RECV_RCD", "CRYPTO_RELEASE_RCD", "YIELD_SECRET", "GOT_TRANSPORT_PARAMS", "ALERT",
    "ALPN_SELECT", "CLIENT_HELLO", "NEW_SESSION",
};

static inline int neton_qtls_fail(neton_qtls *q, int kind, const char *message) {
    if (q->failure == NETON_QTLS_FAIL_NONE) {
        q->failure = kind;
        snprintf(q->message, sizeof q->message, "%s", message);
    }
    return 0;
}

/* The connection behind [ssl], or NULL once it is being freed. */
static inline neton_qtls *neton_qtls_of(SSL *ssl) { return ssl ? (neton_qtls *)SSL_get_ex_data(ssl, 0) : NULL; }

/* A test-injected failure of callback [cb]: recorded (once) as quic's injected exception was. */
static inline int neton_qtls_injected(neton_qtls *q, int cb) {
    char m[64];
    if (q->inject != cb) return 0;
    q->inject = -1;
    snprintf(m, sizeof m, "injected failure in %s", neton_qtls_cb_names[cb]);
    neton_qtls_fail(q, NETON_QTLS_FAIL_CALLBACK, m);
    return 1;
}

/* The TLS 1.3 suite's hash size, or 0 for a suite QUIC cannot use here. */
static inline int neton_qtls_suite_hash(int suite) {
    return suite == 0x1301 || suite == 0x1303 ? 32 : suite == 0x1302 ? 48 : 0;
}

/* ---- the six QUIC TLS callbacks --------------------------------------------------------------------------------- */

static inline int neton_qtls_crypto_send(SSL *s, const unsigned char *buf, size_t len, size_t *consumed, void *arg) {
    neton_qtls *q = arg; (void)s;
    if (!q || neton_qtls_injected(q, NETON_QTLS_CB_CRYPTO_SEND)) return 0;
    if (len > (size_t)INT32_MAX) return neton_qtls_fail(q, NETON_QTLS_FAIL_CALLBACK, "handshake output too large");
    if (q->out_total + len > NETON_QTLS_MAX_OUTGOING)
        return neton_qtls_fail(q, NETON_QTLS_FAIL_INTERNAL, "more than 1048576 bytes of handshake output pending");
    if (!neton_qbuf_append(&q->out[q->write_level], buf, len)) return neton_qtls_fail(q, NETON_QTLS_FAIL_CALLBACK, "out of memory");
    q->out_total += len;
    *consumed = len;
    return 1;
}

static inline int neton_qtls_crypto_recv_rcd(SSL *s, const unsigned char **buf, size_t *bytes_read, void *arg) {
    neton_qtls *q = arg; size_t pending, n; (void)s;
    if (!q || neton_qtls_injected(q, NETON_QTLS_CB_CRYPTO_RECV_RCD)) return 0;
    if (q->record) return neton_qtls_fail(q, NETON_QTLS_FAIL_CALLBACK, "OpenSSL asked for a record while one is outstanding");
    pending = q->in.len - q->in_head;
    n = pending < NETON_QTLS_MAX_RECORD ? pending : NETON_QTLS_MAX_RECORD;
    if (n == 0) { *buf = NULL; *bytes_read = 0; return 1; }
    q->record = OPENSSL_malloc(n);
    if (!q->record) return neton_qtls_fail(q, NETON_QTLS_FAIL_CALLBACK, "out of memory");
    memcpy(q->record, q->in.data + q->in_head, n);
    q->in_head += n;
    if (q->in_head == q->in.len) { neton_qbuf_clear(&q->in); q->in_head = 0; }
    q->record_len = n; q->record_released = 0;
    *buf = q->record; *bytes_read = n;
    return 1;
}

static inline int neton_qtls_crypto_release_rcd(SSL *s, size_t n, void *arg) {
    neton_qtls *q = arg; (void)s;
    if (!q || neton_qtls_injected(q, NETON_QTLS_CB_CRYPTO_RELEASE_RCD)) return 0;
    if (!q->record) return neton_qtls_fail(q, NETON_QTLS_FAIL_CALLBACK, "release without an outstanding record");
    if (q->record_released + n > q->record_len) return neton_qtls_fail(q, NETON_QTLS_FAIL_CALLBACK, "released more than the record");
    q->record_released += n;
    if (q->record_released == q->record_len) {
        OPENSSL_clear_free(q->record, q->record_len);
        q->record = NULL; q->record_len = q->record_released = 0;
    }
    return 1;
}

static inline int neton_qtls_yield_secret(SSL *s, uint32_t level, int direction, const unsigned char *secret, size_t len, void *arg) {
    neton_qtls *q = arg; const SSL_CIPHER *cipher; int suite, hash;
    if (!q || neton_qtls_injected(q, NETON_QTLS_CB_YIELD_SECRET)) return 0;
    if (level == 1) {
        /* Early secret: the client's write (with its ClientHello) or the server's read (0-RTT accepted). */
        SSL_SESSION *session;
        if (direction != (q->server ? 0 : 1)) return neton_qtls_fail(q, NETON_QTLS_FAIL_CALLBACK, "early secret in the wrong direction");
        cipher = SSL_get_pending_cipher(s);
        if (!cipher && (session = SSL_get_session(s)) != NULL) cipher = SSL_SESSION_get0_cipher(session);
        suite = cipher ? (int)SSL_CIPHER_get_protocol_id(cipher) : 0;
        hash = neton_qtls_suite_hash(suite);
        if (!hash) return neton_qtls_fail(q, NETON_QTLS_FAIL_INTERNAL, "0-RTT cipher suite not usable with QUIC");
        if ((size_t)hash != len) return neton_qtls_fail(q, NETON_QTLS_FAIL_CALLBACK, "early secret of the wrong size");
        memcpy(q->early_secret, secret, len); q->early_len = (int)len; q->early_suite = suite;
        return 1;
    }
    if (level != 2 && level != 3) return neton_qtls_fail(q, NETON_QTLS_FAIL_CALLBACK, "unexpected secret protection level");
    cipher = SSL_get_pending_cipher(s);
    if (!cipher) cipher = SSL_get_current_cipher(s);
    suite = cipher ? (int)SSL_CIPHER_get_protocol_id(cipher) : 0;
    hash = neton_qtls_suite_hash(suite);
    if (!hash) return neton_qtls_fail(q, NETON_QTLS_FAIL_INTERNAL, "negotiated cipher suite not usable with QUIC");
    if ((size_t)hash != len) return neton_qtls_fail(q, NETON_QTLS_FAIL_CALLBACK, "secret of the wrong size");
    q->suite[level] = suite;
    if (direction == 0) {
        if (q->in.len - q->in_head != 0) return neton_qtls_fail(q, NETON_QTLS_FAIL_UNEXPECTED_MESSAGE, "CRYPTO data after a key change");
        memcpy(q->secret[level][0], secret, len); q->secret_len[level][0] = (int)len;
        q->read_level = (int)level;
    } else {
        memcpy(q->secret[level][1], secret, len); q->secret_len[level][1] = (int)len;
        q->write_level = (int)level;
    }
    return 1;
}

static inline int neton_qtls_got_transport_params(SSL *s, const unsigned char *params, size_t len, void *arg) {
    neton_qtls *q = arg; (void)s;
    if (!q || neton_qtls_injected(q, NETON_QTLS_CB_GOT_TRANSPORT_PARAMS)) return 0;
    neton_qbuf_clear(&q->peer_params);
    if (!neton_qbuf_append(&q->peer_params, params, len)) return neton_qtls_fail(q, NETON_QTLS_FAIL_CALLBACK, "out of memory");
    q->has_peer_params = 1;
    return 1;
}

static inline int neton_qtls_alert(SSL *s, unsigned char alert, void *arg) {
    neton_qtls *q = arg; (void)s;
    if (!q || neton_qtls_injected(q, NETON_QTLS_CB_ALERT)) return 0;
    if (q->alert < 0) q->alert = alert;
    return 1;
}

/* ---- context callbacks: they find the connection through the SSL's ex_data -------------------------------------- */

/* Server preference; none in common (or none configured while the client offers) → no_application_protocol. */
static inline int neton_qtls_alpn_select(SSL *ssl, const unsigned char **out, unsigned char *out_len,
                                  const unsigned char *in, unsigned int in_len, void *unused) {
    neton_qtls *q = neton_qtls_of(ssl); size_t p = 0; (void)unused;
    if (!q || neton_qtls_injected(q, NETON_QTLS_CB_ALPN_SELECT)) return SSL_TLSEXT_ERR_ALERT_FATAL;
    while (p < q->server_alpn_len) {
        unsigned int want = q->server_alpn[p], at = 0;
        while (at < in_len) {
            unsigned int n = in[at];
            if (at + 1 + n > in_len) break;
            if (n == want && memcmp(in + at + 1, q->server_alpn + p + 1, n) == 0) {
                *out = in + at + 1; *out_len = (unsigned char)n;  /* OpenSSL copies it before [in] goes away */
                return SSL_TLSEXT_ERR_OK;
            }
            at += 1 + n;
        }
        p += 1 + want;
    }
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

/* A server with protocols refuses a ClientHello without ALPN (rustls for QUIC). */
static inline int neton_qtls_client_hello(SSL *ssl, int *al, void *unused) {
    neton_qtls *q = neton_qtls_of(ssl); const unsigned char *ext; size_t len; (void)unused;
    if (!q || neton_qtls_injected(q, NETON_QTLS_CB_CLIENT_HELLO)) { if (al) *al = SSL_AD_INTERNAL_ERROR; return SSL_CLIENT_HELLO_ERROR; }
    if (q->server_alpn_len == 0) return SSL_CLIENT_HELLO_SUCCESS;
    if (SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_application_layer_protocol_negotiation, &ext, &len) == 1) return SSL_CLIENT_HELLO_SUCCESS;
    if (al) *al = SSL_AD_NO_APPLICATION_PROTOCOL;
    return SSL_CLIENT_HELLO_ERROR;
}

/* Never fails the connection; the line waits for the caller (only when the configuration logs keys). */
static inline void neton_qtls_key_log(const SSL *ssl, const char *line) {
    neton_qtls *q = neton_qtls_of((SSL *)ssl);
    if (!q || !q->keylog || !line) return;
    neton_qbuf_append(&q->keylog_lines, (const unsigned char *)line, strlen(line));
    neton_qbuf_append(&q->keylog_lines, (const unsigned char *)"\n", 1);
}

/* A session ticket (client): kept DER-encoded with whether it allows 0-RTT. Never fails the connection. */
static inline int neton_qtls_new_session(SSL *ssl, SSL_SESSION *session) {
    neton_qtls *q = neton_qtls_of(ssl); unsigned char head[5], *der = NULL, *p; int n;
    if (!q) return 0;
    if (q->inject == NETON_QTLS_CB_NEW_SESSION) { q->inject = -1; q->dropped_tickets++; return 0; }  /* drops the ticket only */
    n = i2d_SSL_SESSION(session, NULL);
    if (n <= 0 || (der = OPENSSL_malloc((size_t)n)) == NULL) { q->dropped_tickets++; return 0; }
    p = der;
    if (i2d_SSL_SESSION(session, &p) != n) { OPENSSL_free(der); q->dropped_tickets++; return 0; }
    head[0] = (unsigned char)(n >> 24); head[1] = (unsigned char)(n >> 16); head[2] = (unsigned char)(n >> 8); head[3] = (unsigned char)n;
    head[4] = SSL_SESSION_get_max_early_data(session) == 0xffffffffu;
    if (!neton_qbuf_append(&q->tickets, head, 5) || !neton_qbuf_append(&q->tickets, der, (size_t)n)) q->dropped_tickets++;
    OPENSSL_free(der);
    return 0;
}

/* ---- contexts ----------------------------------------------------------------------------------------------------- */

/* TLS 1.3 only, no compression, the suites (OpenSSL names, ':'-separated) and groups (NULL: OpenSSL's default). */
static inline SSL_CTX *neton_qtls_ctx_new(int server, const char *suites, const char *groups) {
    SSL_CTX *ctx;
    ERR_clear_error();
    ctx = SSL_CTX_new(TLS_method());
    if (!ctx) return NULL;
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1 || SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) != 1
        || SSL_CTX_set_ciphersuites(ctx, suites) != 1 || (groups && SSL_CTX_set1_groups_list(ctx, groups) != 1)) {
        SSL_CTX_free(ctx); return NULL;
    }
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
    if (server) {
        static const unsigned char sid[] = "neton-quic";
        SSL_CTX_set_alpn_select_cb(ctx, neton_qtls_alpn_select, NULL);
        SSL_CTX_set_client_hello_cb(ctx, neton_qtls_client_hello, NULL);
        /* Resumption needs a session ID context once client certificates are verified. */
        if (SSL_CTX_set_session_id_context(ctx, sid, (unsigned int)(sizeof sid - 1)) != 1) { SSL_CTX_free(ctx); return NULL; }
    } else {
        /* Tickets reach the connection through the new-session callback; OpenSSL keeps no client cache. */
        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
        SSL_CTX_sess_set_new_cb(ctx, neton_qtls_new_session);
    }
    return ctx;
}
static inline void neton_qtls_ctx_free(SSL_CTX *ctx) { SSL_CTX_free(ctx); }
static inline void neton_qtls_ctx_keylog(SSL_CTX *ctx) { SSL_CTX_set_keylog_callback(ctx, neton_qtls_key_log); }
/* 0 none, 1 request (verify if presented), 2 require. A client verifies the server unless [mode] is 0. */
static inline void neton_qtls_ctx_verify(SSL_CTX *ctx, int mode) {
    SSL_CTX_set_verify(ctx, mode == 0 ? SSL_VERIFY_NONE : mode == 1 ? SSL_VERIFY_PEER : SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
}
/* One DER trust anchor. */
static inline int neton_qtls_ctx_anchor(SSL_CTX *ctx, const unsigned char *der, int size) {
    const unsigned char *p = der; X509 *x = d2i_X509(NULL, &p, size); int ok;
    X509_STORE *store = SSL_CTX_get_cert_store(ctx);
    if (!x || !store || p != der + size) { X509_free(x); return 0; }
    ok = X509_STORE_add_cert(store, x) == 1;
    X509_free(x); return ok;
}
/* Identity: [count] DER certificates (leaf first) concatenated with their sizes in [sizes]; the key PEM or DER. */
static inline int neton_qtls_ctx_identity(SSL_CTX *ctx, const unsigned char *certs, const int *sizes, int count,
                                          const unsigned char *key, int key_size, int key_pem) {
    X509 *leaf = NULL; STACK_OF(X509) *chain = sk_X509_new_null(); EVP_PKEY *pkey = NULL; int ok = 0, i; size_t at = 0;
    if (!chain || count < 1) goto done;
    for (i = 0; i < count; i++) {
        const unsigned char *p = certs + at; X509 *x = d2i_X509(NULL, &p, sizes[i]);
        if (!x || p != certs + at + sizes[i]) { X509_free(x); goto done; }
        at += (size_t)sizes[i];
        if (i == 0) leaf = x; else if (!sk_X509_push(chain, x)) { X509_free(x); goto done; }
    }
    if (key_pem) {
        BIO *bio = BIO_new_mem_buf(key, key_size);
        if (bio) { pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, (void *)""); BIO_free(bio); }
    } else {
        const unsigned char *p = key; pkey = d2i_AutoPrivateKey(NULL, &p, key_size);
    }
    if (!pkey) goto done;
    ok = SSL_CTX_use_cert_and_key(ctx, leaf, pkey, chain, 1) == 1;
done:
    X509_free(leaf); EVP_PKEY_free(pkey); sk_X509_pop_free(chain, X509_free);
    return ok;
}

/* ---- connections -------------------------------------------------------------------------------------------------- */

static inline void neton_qtls_free(neton_qtls *q) {
    int i;
    if (!q) return;
    if (q->ssl) { SSL_set_ex_data(q->ssl, 0, NULL); SSL_free(q->ssl); q->ssl = NULL; }
    ERR_clear_error();
    neton_qbuf_free(&q->in);
    for (i = 0; i < 4; i++) neton_qbuf_free(&q->out[i]);
    neton_qbuf_free(&q->peer_params); neton_qbuf_free(&q->tickets); neton_qbuf_free(&q->keylog_lines);
    if (q->record) OPENSSL_clear_free(q->record, q->record_len);
    OPENSSL_clear_free(q->own_params, q->own_params_len);
    OPENSSL_free(q->server_alpn);
    OPENSSL_clear_free(q, sizeof *q);
}

/*
 * A connection on [ctx]: our transport parameters (copied, kept until freed), the server's ALPN list (wire format) or
 * nothing, and whether key-log lines are collected. Early data starts disabled. NULL on failure.
 */
static inline neton_qtls *neton_qtls_new(SSL_CTX *ctx, int server, const unsigned char *params, int params_len,
                                         const unsigned char *server_alpn, int server_alpn_len, int keylog) {
    neton_qtls *q = OPENSSL_zalloc(sizeof *q);
    OSSL_DISPATCH table[7];
    ERR_clear_error();
    if (!q) return NULL;
    q->server = server; q->alert = -1; q->inject = -1; q->keylog = keylog;
    q->ssl = SSL_new(ctx);
    if (!q->ssl || SSL_set_ex_data(q->ssl, 0, q) != 1) goto fail;
    if (server_alpn_len > 0) {
        q->server_alpn = OPENSSL_memdup(server_alpn, (size_t)server_alpn_len);
        if (!q->server_alpn) goto fail;
        q->server_alpn_len = (size_t)server_alpn_len;
    }
    table[0].function_id = OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_SEND; table[0].function = (void (*)(void))neton_qtls_crypto_send;
    table[1].function_id = OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RECV_RCD; table[1].function = (void (*)(void))neton_qtls_crypto_recv_rcd;
    table[2].function_id = OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RELEASE_RCD; table[2].function = (void (*)(void))neton_qtls_crypto_release_rcd;
    table[3].function_id = OSSL_FUNC_SSL_QUIC_TLS_YIELD_SECRET; table[3].function = (void (*)(void))neton_qtls_yield_secret;
    table[4].function_id = OSSL_FUNC_SSL_QUIC_TLS_GOT_TRANSPORT_PARAMS; table[4].function = (void (*)(void))neton_qtls_got_transport_params;
    table[5].function_id = OSSL_FUNC_SSL_QUIC_TLS_ALERT; table[5].function = (void (*)(void))neton_qtls_alert;
    table[6].function_id = 0; table[6].function = NULL;
    if (SSL_set_quic_tls_cbs(q->ssl, table, q) != 1) goto fail;
    /* At least one byte, so that empty parameters (possible with all defaults) still have a valid pointer. */
    q->own_params_len = params_len > 0 ? (size_t)params_len : 1;
    q->own_params = OPENSSL_zalloc(q->own_params_len);
    if (!q->own_params) goto fail;
    if (params_len > 0) memcpy(q->own_params, params, (size_t)params_len);
    if (SSL_set_quic_tls_transport_params(q->ssl, q->own_params, (size_t)params_len) != 1) goto fail;
    if (SSL_set_quic_tls_early_data_enabled(q->ssl, 0) != 1) goto fail;
    if (server) SSL_set_accept_state(q->ssl); else SSL_set_connect_state(q->ssl);
    return q;
fail:
    neton_qtls_free(q); return NULL;
}

/* Client: verify the server against a DNS name (and send it as SNI) or an IP address. */
static inline int neton_qtls_server_name(neton_qtls *q, const char *name, int ip) {
    if (ip) return SSL_set1_ipaddr(q->ssl, name) == 1;
    SSL_set_hostflags(q->ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS | X509_CHECK_FLAG_NEVER_CHECK_SUBJECT);
    return SSL_set1_dnsname(q->ssl, name) == 1 && SSL_set_tlsext_host_name(q->ssl, name) == 1;
}
static inline int neton_qtls_offer_alpn(neton_qtls *q, const unsigned char *wire, int size) {
    return SSL_set_alpn_protos(q->ssl, wire, (unsigned int)size) == 0;
}
/*
 * Client resumption from a DER session: 1 resumed, 0 the ticket no longer parses (full handshake). The session's
 * protocol must be among [offered_alpn] (wire format) to allow 0-RTT (OpenSSL would fail the handshake otherwise).
 */
static inline int neton_qtls_resume(neton_qtls *q, const unsigned char *der, int size, int early,
                                    const unsigned char *offered_alpn, int offered_len) {
    const unsigned char *p = der, *selected = NULL; SSL_SESSION *session = d2i_SSL_SESSION(NULL, &p, size); size_t len = 0, at = 0;
    int match = 0;
    if (!session) { ERR_clear_error(); return 0; }
    if (SSL_set_session(q->ssl, session) != 1) { SSL_SESSION_free(session); ERR_clear_error(); return 0; }
    SSL_SESSION_free(session);
    if (!early) return 1;
    SSL_SESSION_get0_alpn_selected(SSL_get_session(q->ssl), &selected, &len);
    if (!selected || len == 0) match = 1;
    else while (at < (size_t)offered_len) {
        size_t n = offered_alpn[at];
        if (n == len && memcmp(offered_alpn + at + 1, selected, n) == 0) { match = 1; break; }
        at += 1 + n;
    }
    /* Refused (0) unless the session's max_early_data is 0xffffffff: then only resumption. */
    if (match && SSL_set_quic_tls_early_data_enabled(q->ssl, 1) != 1) ERR_clear_error();
    return 1;
}
static inline int neton_qtls_enable_early_data(neton_qtls *q) { return SSL_set_quic_tls_early_data_enabled(q->ssl, 1); }
static inline void neton_qtls_inject(neton_qtls *q, int cb) { q->inject = cb; }

/* CRYPTO bytes from the peer at the current read level: 0 when more than 64 KiB would be waiting. */
static inline int neton_qtls_provide(neton_qtls *q, const unsigned char *data, int size) {
    if (size <= 0) return 1;
    if (q->in.len - q->in_head + (size_t)size > NETON_QTLS_MAX_INCOMING) return 0;
    return neton_qbuf_append(&q->in, data, (size_t)size);
}
static inline int neton_qtls_incoming(neton_qtls *q) { return (int)(q->in.len - q->in_head); }

/*
 * One OpenSSL call: SSL_do_handshake before completion, SSL_read(NULL, 0) after (post-handshake messages).
 * Returns 1 (done), 0 (wants more input) or -1 (failed: an alert, a recorded failure, or OpenSSL's error).
 */
static inline int neton_qtls_drive(neton_qtls *q, int complete) {
    int ret, err;
    size_t none = 0;
    ERR_clear_error();
    ret = complete ? SSL_read_ex(q->ssl, NULL, 0, &none) : SSL_do_handshake(q->ssl);
    if (ret == 1) return q->failure ? -1 : 1;
    err = SSL_get_error(q->ssl, ret);
    if (q->failure) return -1;
    return err == SSL_ERROR_WANT_READ ? 0 : -1;
}
static inline int neton_qtls_init_finished(neton_qtls *q) { return SSL_is_init_finished(q->ssl) == 1; }

/* Takes the outgoing bytes of [level] into [out] (NULL: the size). */
static inline int neton_qtls_take_out(neton_qtls *q, int level, unsigned char *out) {
    int n = (int)q->out[level].len;
    if (!out) return n;
    if (n) memcpy(out, q->out[level].data, (size_t)n);
    q->out_total -= q->out[level].len;
    neton_qbuf_clear(&q->out[level]);
    return n;
}
/* Takes (copies out, then wipes) the secret of [level] and [direction]; returns its size, 0 when none. */
static inline int neton_qtls_take_secret(neton_qtls *q, int level, int direction, unsigned char *out) {
    int n = q->secret_len[level][direction];
    if (!n || !out) return n;
    memcpy(out, q->secret[level][direction], (size_t)n);
    OPENSSL_cleanse(q->secret[level][direction], sizeof q->secret[level][direction]);
    q->secret_len[level][direction] = 0;
    return n;
}
static inline int neton_qtls_suite(neton_qtls *q, int level) { return level == 1 ? q->early_suite : q->suite[level]; }
static inline int neton_qtls_take_early_secret(neton_qtls *q, unsigned char *out) {
    int n = q->early_len;
    if (!n || !out) return n;
    memcpy(out, q->early_secret, (size_t)n);
    OPENSSL_cleanse(q->early_secret, sizeof q->early_secret); q->early_len = 0;
    return n;
}
/* The peer's transport parameters: -1 none yet, else the size (copied into [out] when given). */
static inline int neton_qtls_peer_params(neton_qtls *q, unsigned char *out) {
    if (!q->has_peer_params) return -1;
    if (out && q->peer_params.len) memcpy(out, q->peer_params.data, q->peer_params.len);
    return (int)q->peer_params.len;
}
static inline int neton_qtls_alert_sent(neton_qtls *q) { return q->alert; }
static inline int neton_qtls_failure(neton_qtls *q) { return q->failure; }
static inline const char *neton_qtls_failure_message(neton_qtls *q) { return q->message; }
static inline int neton_qtls_alpn(neton_qtls *q, unsigned char *out) {
    const unsigned char *v = NULL; unsigned int n = 0;
    SSL_get0_alpn_selected(q->ssl, &v, &n);
    if (out && n) memcpy(out, v, n);
    return (int)n;
}
static inline const char *neton_qtls_sni(neton_qtls *q) { return SSL_get_servername(q->ssl, TLSEXT_NAMETYPE_host_name); }
static inline int neton_qtls_early_accepted(neton_qtls *q) { return SSL_get_early_data_status(q->ssl) == SSL_EARLY_DATA_ACCEPTED; }
/* DER of the peer certificate [index] (leaf first): 0 past the end, -1 on failure. */
static inline int neton_qtls_peer_der(neton_qtls *q, int index, unsigned char *out) {
    X509 *leaf = SSL_get0_peer_certificate(q->ssl), *cert = NULL;
    STACK_OF(X509) *chain = SSL_get_peer_cert_chain(q->ssl);
    int i;
    if (!leaf) return 0;
    if (index == 0) cert = leaf;
    else for (i = 0; chain && i < sk_X509_num(chain); ++i) {
        X509 *item = sk_X509_value(chain, i);
        if (X509_cmp(item, leaf) != 0 && --index == 0) { cert = item; break; }
    }
    if (!cert) return 0;
    {
        int n = i2d_X509(cert, out ? &out : NULL);
        return n > 0 ? n : -1;
    }
}
/* Takes the queued tickets ([u32 length][u8 allows 0-RTT][DER] each) into [out] (NULL: the size). */
static inline int neton_qtls_take_tickets(neton_qtls *q, unsigned char *out) {
    int n = (int)q->tickets.len;
    if (!out) return n;
    if (n) memcpy(out, q->tickets.data, (size_t)n);
    neton_qbuf_clear(&q->tickets);
    return n;
}
static inline int neton_qtls_dropped_tickets(neton_qtls *q) { return q->dropped_tickets; }
/* Takes the queued key-log lines ('\n'-terminated) into [out] (NULL: the size). */
static inline int neton_qtls_take_keylog(neton_qtls *q, unsigned char *out) {
    int n = (int)q->keylog_lines.len;
    if (!out) return n;
    if (n) memcpy(out, q->keylog_lines.data, (size_t)n);
    neton_qbuf_clear(&q->keylog_lines);
    return n;
}
static inline int neton_qtls_export(neton_qtls *q, unsigned char *out, int size, const char *label, int label_size,
                                    const unsigned char *context, int context_size) {
    ERR_clear_error();
    return SSL_export_keying_material(q->ssl, out, (size_t)size, label, (size_t)label_size, context, (size_t)context_size, 1);
}
/* ---- credentials --------------------------------------------------------------------------------------------- */

/* Whether [der] is exactly one X.509 certificate. */
static inline int neton_qtls_is_certificate(const unsigned char *der, int size) {
    const unsigned char *p = der; X509 *x = d2i_X509(NULL, &p, size); int ok = x != NULL && p == der + size;
    X509_free(x); ERR_clear_error(); return ok;
}
/* Whether [key] is an unencrypted private key: PEM, or DER (PKCS#8 or a traditional RSA / EC key). */
static inline int neton_qtls_is_private_key(const unsigned char *key, int size, int pem) {
    EVP_PKEY *pkey = NULL;
    if (pem) {
        BIO *bio = BIO_new_mem_buf(key, size);
        if (bio) { pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, (void *)""); BIO_free(bio); }
    } else {
        const unsigned char *p = key; pkey = d2i_AutoPrivateKey(NULL, &p, size);
    }
    ERR_clear_error();
    if (!pkey) return 0;
    EVP_PKEY_free(pkey); return 1;
}
/* The CERTIFICATE blocks of a PEM document as [u32 length][DER] records into [out] (NULL: the total size). */
static inline int neton_qtls_pem_certificates(const unsigned char *pem, int size, unsigned char *out) {
    BIO *bio = BIO_new_mem_buf(pem, size); X509 *x; int total = 0;
    if (!bio) return -1;
    while ((x = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
        int n = i2d_X509(x, NULL);
        if (n > 0 && out) {
            unsigned char *p = out + total + 4;
            out[total] = (unsigned char)(n >> 24); out[total + 1] = (unsigned char)(n >> 16);
            out[total + 2] = (unsigned char)(n >> 8); out[total + 3] = (unsigned char)n;
            i2d_X509(x, &p);
        }
        if (n > 0) total += 4 + n;
        X509_free(x);
    }
    BIO_free(bio); ERR_clear_error();   /* the "no start line" that ends the loop */
    return total;
}

/* QUIC ends with CONNECTION_CLOSE, not close_notify: mark a clean end so the server keeps the session for tickets. */
static inline void neton_qtls_clean_shutdown(neton_qtls *q) { SSL_set_shutdown(q->ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN); }
#endif
