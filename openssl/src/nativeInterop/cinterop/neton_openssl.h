#ifndef NETON_OPENSSL_H
#define NETON_OPENSSL_H
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_MAJOR != 4
#error "openssl-kotlin requires OpenSSL 4.x headers"
#endif
#include <openssl/crypto.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

/* C unsigned long differs on Windows; keep it out of shared Kotlin metadata. */
static inline int neton_openssl_next_error(char *buffer, size_t capacity) {
    unsigned long error = ERR_get_error();
    if (error == 0) return 0;
    ERR_error_string_n(error, buffer, capacity);
    return 1;
}

static inline int neton_openssl_header_major(void) { return OPENSSL_VERSION_MAJOR; }
static inline int neton_openssl_header_minor(void) { return OPENSSL_VERSION_MINOR; }
static inline int neton_openssl_header_patch(void) { return OPENSSL_VERSION_PATCH; }
static inline int neton_openssl_tls13_only(SSL_CTX *ctx) {
    return SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION)
        && SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
}
#endif
