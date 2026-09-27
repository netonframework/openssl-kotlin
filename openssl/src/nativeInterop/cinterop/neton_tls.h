#ifndef NETON_TLS_H
#define NETON_TLS_H
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <string.h>

typedef struct {
    SSL *ssl;
    BIO *network;
    unsigned char *alpn;
    unsigned int alpn_size;
    unsigned char pending[16384];
    int pending_size, failed, error, reason, verify, alert;
} neton_tls;

static inline int neton_tls_alpn(SSL *ssl, const unsigned char **out, unsigned char *out_size,
    const unsigned char *offered, unsigned int size, void *unused) {
    neton_tls *engine = SSL_get_app_data(ssl); unsigned char *selected = NULL;
    (void)unused;
    if (!engine || !engine->alpn_size) return SSL_TLSEXT_ERR_NOACK;
    if (SSL_select_next_proto(&selected, out_size, engine->alpn, engine->alpn_size, offered, size)
        != OPENSSL_NPN_NEGOTIATED) return SSL_TLSEXT_ERR_ALERT_FATAL;
    *out = selected; return SSL_TLSEXT_ERR_OK;
}
static inline void neton_tls_info(const SSL *ssl, int where, int ret) {
    neton_tls *engine = SSL_get_app_data(ssl);
    if (engine && (where & SSL_CB_ALERT)) engine->alert = ret & 255;
}
static inline int neton_no_password(char *buf, int size, int rw, void *arg) {
    (void)buf; (void)size; (void)rw; (void)arg; return 0;
}
static inline SSL_CTX *neton_tls_context_new(int minimum, int maximum, int verify) {
    SSL_CTX *ctx; ERR_clear_error(); ctx = SSL_CTX_new(TLS_method());
    if (!ctx) return NULL;
    if (!SSL_CTX_set_min_proto_version(ctx, minimum) || !SSL_CTX_set_max_proto_version(ctx, maximum)) {
        SSL_CTX_free(ctx); return NULL;
    }
    SSL_CTX_set_verify(ctx, verify, NULL);
    SSL_CTX_set_options(ctx, SSL_OP_NO_RENEGOTIATION | SSL_OP_NO_COMPRESSION | SSL_OP_NO_TICKET);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_num_tickets(ctx, 0);
    SSL_CTX_set_max_early_data(ctx, 0);
    SSL_CTX_set_alpn_select_cb(ctx, neton_tls_alpn, NULL);
    SSL_CTX_set_info_callback(ctx, neton_tls_info);
    return ctx;
}
static inline int neton_tls_groups(SSL_CTX *ctx, const char *groups) { return SSL_CTX_set1_groups_list(ctx, groups); }
static inline void neton_tls_limits(SSL_CTX *ctx, int depth, int bytes) {
    SSL_CTX_set_verify_depth(ctx, depth); SSL_CTX_set_max_cert_list(ctx, bytes);
}
static inline int neton_tls_roots(SSL_CTX *ctx, const unsigned char *data, int size) {
    BIO *bio = BIO_new_mem_buf(data, size); STACK_OF(X509_INFO) *items; int ok = 1, count = 0;
    if (!bio) return 0;
    items = PEM_X509_INFO_read_bio(bio, NULL, neton_no_password, NULL); BIO_free(bio);
    if (!items) return 0;
    for (int i = 0; i < sk_X509_INFO_num(items); ++i) {
        X509_INFO *item = sk_X509_INFO_value(items, i);
        if (item->x509) { count++; if (X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), item->x509) != 1) ok = 0; }
    }
    sk_X509_INFO_pop_free(items, X509_INFO_free); return ok && count > 0;
}
static inline int neton_tls_identity(SSL_CTX *ctx, const unsigned char *chain, int chain_size,
    const unsigned char *key, int key_size) {
    BIO *bio = BIO_new_mem_buf(chain, chain_size); STACK_OF(X509_INFO) *items;
    EVP_PKEY *private_key; int ok = 1, count = 0;
    if (!bio) return 0;
    items = PEM_X509_INFO_read_bio(bio, NULL, neton_no_password, NULL); BIO_free(bio);
    if (!items) return 0;
    for (int i = 0; i < sk_X509_INFO_num(items); ++i) {
        X509 *cert = sk_X509_INFO_value(items, i)->x509;
        if (cert) {
            if ((count == 0 ? SSL_CTX_use_certificate(ctx, cert) : SSL_CTX_add1_chain_cert(ctx, cert)) != 1) ok = 0;
            count++;
        }
    }
    sk_X509_INFO_pop_free(items, X509_INFO_free);
    if (!ok || !count) return 0;
    bio = BIO_new_mem_buf(key, key_size); if (!bio) return 0;
    private_key = PEM_read_bio_PrivateKey(bio, NULL, neton_no_password, NULL); BIO_free(bio);
    if (!private_key) return 0;
    ok = SSL_CTX_use_PrivateKey(ctx, private_key) == 1 && SSL_CTX_check_private_key(ctx) == 1;
    EVP_PKEY_free(private_key); return ok;
}
static inline void neton_tls_free(neton_tls *engine) {
    if (!engine) return;
    SSL_free(engine->ssl); BIO_free(engine->network); OPENSSL_free(engine->alpn);
    OPENSSL_clear_free(engine, sizeof(*engine));
}
static inline neton_tls *neton_tls_new(SSL_CTX *ctx, int server, const char *identity, int ip,
    const unsigned char *alpn, int alpn_size, int capacity) {
    neton_tls *engine = OPENSSL_zalloc(sizeof(*engine)); BIO *internal = NULL;
    ERR_clear_error(); if (!engine) return NULL;
    engine->ssl = SSL_new(ctx); engine->alert = -1;
    if (!engine->ssl || BIO_new_bio_pair(&internal, capacity, &engine->network, capacity) != 1) goto fail;
    SSL_set_bio(engine->ssl, internal, internal); internal = NULL;
    SSL_set_app_data(engine->ssl, engine);
    if (alpn_size) {
        engine->alpn = OPENSSL_memdup(alpn, alpn_size); if (!engine->alpn) goto fail;
        engine->alpn_size = (unsigned int)alpn_size;
    }
    if (server) SSL_set_accept_state(engine->ssl);
    else {
        SSL_set_connect_state(engine->ssl);
        if (!identity) goto fail;
        if (ip) {
            if (X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(engine->ssl), identity) != 1) goto fail;
        } else {
            SSL_set_hostflags(engine->ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS | X509_CHECK_FLAG_NEVER_CHECK_SUBJECT);
            if (SSL_set1_host(engine->ssl, identity) != 1 || SSL_set_tlsext_host_name(engine->ssl, identity) != 1) goto fail;
        }
        if (alpn_size && SSL_set_alpn_protos(engine->ssl, alpn, alpn_size) != 0) goto fail;
    }
    return engine;
fail:
    BIO_free(internal); neton_tls_free(engine); return NULL;
}
/* Result codes: -2 need read, -3 need write, -4 close_notify, -1 fatal, -6 bad retry. */
static inline int neton_tls_result(neton_tls *engine, int result) {
    int error = SSL_get_error(engine->ssl, result);
    if (error == SSL_ERROR_WANT_READ) return -2;
    if (error == SSL_ERROR_WANT_WRITE) return -3;
    if (error == SSL_ERROR_ZERO_RETURN) return -4;
    engine->failed = 1; engine->error = error;
    engine->reason = ERR_GET_REASON(ERR_peek_last_error());
    engine->verify = (int)SSL_get_verify_result(engine->ssl); return -1;
}
static inline int neton_tls_handshake(neton_tls *engine) {
    int n; ERR_clear_error(); n = SSL_do_handshake(engine->ssl);
    return n == 1 ? 1 : neton_tls_result(engine, n);
}
static inline int neton_tls_read(neton_tls *engine, unsigned char *data, int size) {
    int n; ERR_clear_error(); n = SSL_read(engine->ssl, data, size);
    return n > 0 ? n : neton_tls_result(engine, n);
}
static inline int neton_tls_write(neton_tls *engine, const unsigned char *data, int size) {
    int n;
    if (engine->pending_size) {
        if (engine->pending_size != size || CRYPTO_memcmp(engine->pending, data, size)) return -6;
    } else { memcpy(engine->pending, data, size); engine->pending_size = size; }
    ERR_clear_error(); n = SSL_write(engine->ssl, engine->pending, size);
    if (n > 0) { OPENSSL_cleanse(engine->pending, engine->pending_size); engine->pending_size = 0; return n; }
    return neton_tls_result(engine, n);
}
static inline int neton_tls_shutdown(neton_tls *engine) {
    int n; ERR_clear_error(); n = SSL_shutdown(engine->ssl);
    if (n == 1) return 1;
    if (n == 0) return -2;
    return neton_tls_result(engine, n);
}
static inline int neton_tls_feed(neton_tls *engine, const unsigned char *data, int size) {
    int n = BIO_write(engine->network, data, size); return n > 0 ? n : BIO_should_retry(engine->network) ? 0 : -1;
}
static inline int neton_tls_drain(neton_tls *engine, unsigned char *data, int size) {
    int n = BIO_read(engine->network, data, size); return n > 0 ? n : BIO_should_retry(engine->network) || BIO_eof(engine->network) ? 0 : -1;
}
static inline void neton_tls_eof(neton_tls *engine) { BIO_shutdown_wr(engine->network); }
static inline int neton_tls_pending(neton_tls *engine) { return (int)BIO_ctrl_pending(engine->network); }
static inline int neton_tls_ready(neton_tls *engine) { return SSL_is_init_finished(engine->ssl); }
static inline int neton_tls_sent_close(neton_tls *engine) { return (SSL_get_shutdown(engine->ssl) & SSL_SENT_SHUTDOWN) != 0; }
static inline int neton_tls_alpn_copy(neton_tls *engine, unsigned char *output) {
    const unsigned char *value = NULL; unsigned int size = 0;
    SSL_get0_alpn_selected(engine->ssl, &value, &size);
    if (output && size) memcpy(output, value, size); return (int)size;
}
static inline int neton_tls_export(neton_tls *engine, unsigned char *out, int size,
    const char *label, int label_size, const unsigned char *context, int context_size, int use_context) {
    ERR_clear_error(); return SSL_export_keying_material(engine->ssl, out, size, label, label_size, context, context_size, use_context);
}
static inline int neton_tls_peer_der(neton_tls *engine, int index, unsigned char *output) {
    X509 *leaf = SSL_get0_peer_certificate(engine->ssl), *cert = NULL;
    STACK_OF(X509) *chain = SSL_get_peer_cert_chain(engine->ssl);
    if (!leaf) return 0;
    if (index == 0) cert = leaf;
    else for (int i = 0; chain && i < sk_X509_num(chain); ++i) {
        X509 *item = sk_X509_value(chain, i);
        if (X509_cmp(item, leaf) != 0 && --index == 0) { cert = item; break; }
    }
    return cert ? i2d_X509(cert, output ? &output : NULL) : 0;
}
static inline const char *neton_tls_sni(neton_tls *engine) { return SSL_get_servername(engine->ssl, TLSEXT_NAMETYPE_host_name); }
#endif
