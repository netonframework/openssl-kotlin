#ifndef NETON_CRYPTO_H
#define NETON_CRYPTO_H
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <string.h>

typedef struct {
    EVP_CIPHER_CTX *encrypt;
    EVP_CIPHER_CTX *decrypt;
} neton_aead;

static inline const EVP_CIPHER *neton_aead_cipher(int algorithm) {
    switch (algorithm) {
    case 0: return EVP_aes_128_gcm();
    case 1: return EVP_aes_256_gcm();
    case 2: return EVP_chacha20_poly1305();
    default: return NULL;
    }
}
static inline void neton_aead_free(neton_aead *key) {
    if (!key) return;
    EVP_CIPHER_CTX_free(key->encrypt);
    EVP_CIPHER_CTX_free(key->decrypt);
    OPENSSL_clear_free(key, sizeof(*key));
}
static inline neton_aead *neton_aead_new(int algorithm, const unsigned char *bytes) {
    neton_aead *key = OPENSSL_zalloc(sizeof(*key));
    const EVP_CIPHER *cipher = neton_aead_cipher(algorithm);
    if (!key || !cipher) { neton_aead_free(key); return NULL; }
    key->encrypt = EVP_CIPHER_CTX_new();
    key->decrypt = EVP_CIPHER_CTX_new();
    if (!key->encrypt || !key->decrypt
        || EVP_EncryptInit_ex2(key->encrypt, cipher, bytes, NULL, NULL) != 1
        || EVP_DecryptInit_ex2(key->decrypt, cipher, bytes, NULL, NULL) != 1) {
        neton_aead_free(key); return NULL;
    }
    return key;
}
/* Caller validates capacity; authentication failure wipes tentative plaintext. */
static inline int neton_aead_seal(neton_aead *key, unsigned char *data, int size,
    const unsigned char *nonce, const unsigned char *aad, int aad_size) {
    int n = 0, tail = 0;
    ERR_clear_error();
    if (EVP_EncryptInit_ex2(key->encrypt, NULL, NULL, nonce, NULL) != 1
        || (aad_size && EVP_EncryptUpdate(key->encrypt, NULL, &n, aad, aad_size) != 1)
        || EVP_EncryptUpdate(key->encrypt, data, &n, data, size) != 1
        || n != size || EVP_EncryptFinal_ex(key->encrypt, data + n, &tail) != 1
        || tail != 0 || EVP_CIPHER_CTX_ctrl(key->encrypt, EVP_CTRL_AEAD_GET_TAG, 16, data + size) != 1) {
        OPENSSL_cleanse(data, (size_t)size + 16); return 0;
    }
    return 1;
}
static inline int neton_aead_open(neton_aead *key, unsigned char *data, int size,
    const unsigned char *nonce, const unsigned char *aad, int aad_size) {
    int n = 0, tail = 0;
    ERR_clear_error();
    if (EVP_DecryptInit_ex2(key->decrypt, NULL, NULL, nonce, NULL) != 1
        || (aad_size && EVP_DecryptUpdate(key->decrypt, NULL, &n, aad, aad_size) != 1)
        || EVP_DecryptUpdate(key->decrypt, data, &n, data, size) != 1 || n != size
        || EVP_CIPHER_CTX_ctrl(key->decrypt, EVP_CTRL_AEAD_SET_TAG, 16, data + size) != 1) {
        OPENSSL_cleanse(data, size); return -1;
    }
    if (EVP_DecryptFinal_ex(key->decrypt, data + n, &tail) != 1) {
        OPENSSL_cleanse(data, size); ERR_clear_error(); return 0;
    }
    return 1;
}

typedef struct { EVP_CIPHER_CTX *cipher; int chacha; } neton_mask;
static inline void neton_mask_free(neton_mask *key) {
    if (!key) return;
    EVP_CIPHER_CTX_free(key->cipher); OPENSSL_clear_free(key, sizeof(*key));
}
static inline neton_mask *neton_mask_new(int algorithm, const unsigned char *bytes) {
    const EVP_CIPHER *cipher = algorithm == 0 ? EVP_aes_128_ecb()
        : algorithm == 1 ? EVP_aes_256_ecb() : algorithm == 2 ? EVP_chacha20() : NULL;
    neton_mask *key = OPENSSL_zalloc(sizeof(*key));
    if (!key || !cipher) { neton_mask_free(key); return NULL; }
    key->cipher = EVP_CIPHER_CTX_new(); key->chacha = algorithm == 2;
    if (!key->cipher || EVP_EncryptInit_ex2(key->cipher, cipher, bytes, NULL, NULL) != 1
        || EVP_CIPHER_CTX_set_padding(key->cipher, 0) != 1) { neton_mask_free(key); return NULL; }
    return key;
}
static inline int neton_mask_apply(neton_mask *key, const unsigned char *sample, unsigned char *output) {
    unsigned char block[16] = {0}; int n = 0, ok;
    ERR_clear_error();
    if (key->chacha) {
        /* First five stream bytes only; sample encodes counter + nonce per RFC 9001. */
        ok = EVP_EncryptInit_ex2(key->cipher, NULL, NULL, sample, NULL) == 1
            && EVP_EncryptUpdate(key->cipher, block, &n, block, 5) == 1 && n == 5;
    } else {
        ok = EVP_EncryptInit_ex2(key->cipher, NULL, NULL, NULL, NULL) == 1
            && EVP_EncryptUpdate(key->cipher, block, &n, sample, 16) == 1 && n == 16;
    }
    if (ok) memcpy(output, block, 5);
    OPENSSL_cleanse(block, sizeof(block)); return ok;
}
static inline const EVP_MD *neton_digest(int algorithm) {
    switch (algorithm) {
    case 0: return EVP_sha1(); case 1: return EVP_sha256();
    case 2: return EVP_sha384(); case 3: return EVP_sha512(); default: return NULL;
    }
}
static inline int neton_hash(int algorithm, const unsigned char *input, int size, unsigned char *output) {
    unsigned int n = 0; ERR_clear_error();
    return EVP_Digest(input, (size_t)size, output, &n, neton_digest(algorithm), NULL);
}
static inline int neton_hmac(int algorithm, const unsigned char *key, int key_size,
    const unsigned char *input, int size, unsigned char *output) {
    static const unsigned char empty = 0;
    unsigned int n = 0; ERR_clear_error();
    if (!key) key = &empty;
    return HMAC(neton_digest(algorithm), key, key_size, input, (size_t)size, output, &n) != NULL;
}
static inline int neton_hkdf(int algorithm, int expand, const unsigned char *key, int key_size,
    const unsigned char *salt, int salt_size, const unsigned char *info, int info_size,
    unsigned char *output, int output_size) {
    EVP_PKEY_CTX *ctx; size_t n = (size_t)output_size; int ok;
    static const unsigned char empty = 0;
    if (!key) key = &empty;
    if (!salt) salt = &empty;
    if (!info) info = &empty;
    ERR_clear_error(); ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!ctx) return 0;
    ok = EVP_PKEY_derive_init(ctx) == 1
        && EVP_PKEY_CTX_hkdf_mode(ctx, expand ? EVP_PKEY_HKDEF_MODE_EXPAND_ONLY : EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) == 1
        && EVP_PKEY_CTX_set_hkdf_md(ctx, neton_digest(algorithm)) == 1
        && EVP_PKEY_CTX_set1_hkdf_key(ctx, key, key_size) == 1
        && (expand || EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, salt_size) == 1)
        && (!expand || EVP_PKEY_CTX_add1_hkdf_info(ctx, info, info_size) == 1)
        && EVP_PKEY_derive(ctx, output, &n) == 1 && n == (size_t)output_size;
    EVP_PKEY_CTX_free(ctx); return ok;
}
#endif
