/*
 * JNI entry points of com.netonstream:openssl on the JVM (docs/JVM.md). Each one pins its arrays, calls the same
 * header-only shim the Kotlin/Native cinterop binding calls (neton_crypto.h, neton_openssl.h) and unpins them: the
 * JVM and native builds run the same C code against the same static OpenSSL. Ranges and sizes are checked in Kotlin
 * (jvmMain) before the call; no JNI function is called while an array is pinned.
 */
#include <jni.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include "neton_openssl.h"
#include "neton_crypto.h"

#define FN(name) Java_neton_openssl_Jni_##name

static inline jlong to_handle(void *p) { return (jlong)(intptr_t)p; }
#define FROM_HANDLE(type, h) ((type *)(intptr_t)(h))

/* ---- version and errors ---------------------------------------------------------------------------------------- */

JNIEXPORT jstring JNICALL FN(version)(JNIEnv *env, jclass cls) {
    (void)cls;
    return (*env)->NewStringUTF(env, OpenSSL_version(OPENSSL_VERSION));
}

/* [runtime major, minor, patch, header major, minor, patch] */
JNIEXPORT void JNICALL FN(versionNumbers)(JNIEnv *env, jclass cls, jintArray out) {
    jint v[6];
    (void)cls;
    v[0] = (jint)OPENSSL_version_major(); v[1] = (jint)OPENSSL_version_minor(); v[2] = (jint)OPENSSL_version_patch();
    v[3] = neton_openssl_header_major(); v[4] = neton_openssl_header_minor(); v[5] = neton_openssl_header_patch();
    (*env)->SetIntArrayRegion(env, out, 0, 6, v);
}

/* The next queued error of this thread, or null when the queue is empty. */
JNIEXPORT jstring JNICALL FN(nextError)(JNIEnv *env, jclass cls) {
    char buffer[256];
    (void)cls;
    return neton_openssl_next_error(buffer, sizeof buffer) ? (*env)->NewStringUTF(env, buffer) : NULL;
}

JNIEXPORT void JNICALL FN(clearErrors)(JNIEnv *env, jclass cls) { (void)env; (void)cls; ERR_clear_error(); }

/* ---- CSPRNG ------------------------------------------------------------------------------------------------------ */

JNIEXPORT jint JNICALL FN(randomFill)(JNIEnv *env, jclass cls, jbyteArray out, jint offset, jint length) {
    jbyte *p;
    int ok;
    (void)cls;
    p = (*env)->GetPrimitiveArrayCritical(env, out, NULL);
    if (!p) return 0;
    ok = RAND_bytes((unsigned char *)p + offset, length);
    if (ok != 1) OPENSSL_cleanse(p + offset, (size_t)length);
    (*env)->ReleasePrimitiveArrayCritical(env, out, p, 0);
    return ok == 1;
}

/* ---- AEAD -------------------------------------------------------------------------------------------------------- */

JNIEXPORT jlong JNICALL FN(aeadNew)(JNIEnv *env, jclass cls, jint algorithm, jbyteArray key) {
    jbyte *k;
    neton_aead *aead;
    (void)cls;
    ERR_clear_error();
    k = (*env)->GetPrimitiveArrayCritical(env, key, NULL);
    if (!k) return 0;
    aead = neton_aead_new(algorithm, (const unsigned char *)k);
    (*env)->ReleasePrimitiveArrayCritical(env, key, k, JNI_ABORT);
    return to_handle(aead);
}

JNIEXPORT void JNICALL FN(aeadFree)(JNIEnv *env, jclass cls, jlong handle) {
    (void)env; (void)cls;
    neton_aead_free(FROM_HANDLE(neton_aead, handle));
}

/* seal (open == 0): 1 / 0; open: 1 authentic, 0 forged, -1 failure. */
static jint aead(JNIEnv *env, jlong handle, int open, jbyteArray data, jint offset, jint size,
                 jbyteArray nonce, jbyteArray aad, jint aadSize) {
    jbyte *d, *n, *a = NULL;
    int result;
    d = (*env)->GetPrimitiveArrayCritical(env, data, NULL);
    n = (*env)->GetPrimitiveArrayCritical(env, nonce, NULL);
    if (aadSize > 0) a = (*env)->GetPrimitiveArrayCritical(env, aad, NULL);
    if (!d || !n || (aadSize > 0 && !a)) {
        result = open ? -1 : 0;
    } else if (open) {
        result = neton_aead_open(FROM_HANDLE(neton_aead, handle), (unsigned char *)d + offset, size,
                                 (const unsigned char *)n, (const unsigned char *)a, aadSize);
    } else {
        result = neton_aead_seal(FROM_HANDLE(neton_aead, handle), (unsigned char *)d + offset, size,
                                 (const unsigned char *)n, (const unsigned char *)a, aadSize);
    }
    if (a) (*env)->ReleasePrimitiveArrayCritical(env, aad, a, JNI_ABORT);
    if (n) (*env)->ReleasePrimitiveArrayCritical(env, nonce, n, JNI_ABORT);
    if (d) (*env)->ReleasePrimitiveArrayCritical(env, data, d, 0);
    return result;
}

JNIEXPORT jint JNICALL FN(aeadSeal)(JNIEnv *env, jclass cls, jlong handle, jbyteArray data, jint offset, jint size,
                                    jbyteArray nonce, jbyteArray aad) {
    (void)cls;
    return aead(env, handle, 0, data, offset, size, nonce, aad, (*env)->GetArrayLength(env, aad));
}

JNIEXPORT jint JNICALL FN(aeadOpen)(JNIEnv *env, jclass cls, jlong handle, jbyteArray data, jint offset, jint size,
                                    jbyteArray nonce, jbyteArray aad) {
    (void)cls;
    return aead(env, handle, 1, data, offset, size, nonce, aad, (*env)->GetArrayLength(env, aad));
}

/* ---- header protection ------------------------------------------------------------------------------------------- */

JNIEXPORT jlong JNICALL FN(maskNew)(JNIEnv *env, jclass cls, jint algorithm, jbyteArray key) {
    jbyte *k;
    neton_mask *mask;
    (void)cls;
    ERR_clear_error();
    k = (*env)->GetPrimitiveArrayCritical(env, key, NULL);
    if (!k) return 0;
    mask = neton_mask_new(algorithm, (const unsigned char *)k);
    (*env)->ReleasePrimitiveArrayCritical(env, key, k, JNI_ABORT);
    return to_handle(mask);
}

JNIEXPORT void JNICALL FN(maskFree)(JNIEnv *env, jclass cls, jlong handle) {
    (void)env; (void)cls;
    neton_mask_free(FROM_HANDLE(neton_mask, handle));
}

JNIEXPORT jint JNICALL FN(maskApply)(JNIEnv *env, jclass cls, jlong handle, jbyteArray sample, jint sampleOffset,
                                     jbyteArray output, jint outputOffset) {
    jbyte *s, *o;
    int ok = 0;
    (void)cls;
    s = (*env)->GetPrimitiveArrayCritical(env, sample, NULL);
    o = (*env)->GetPrimitiveArrayCritical(env, output, NULL);
    if (s && o) ok = neton_mask_apply(FROM_HANDLE(neton_mask, handle), (const unsigned char *)s + sampleOffset,
                                      (unsigned char *)o + outputOffset);
    if (o) (*env)->ReleasePrimitiveArrayCritical(env, output, o, 0);
    if (s) (*env)->ReleasePrimitiveArrayCritical(env, sample, s, JNI_ABORT);
    return ok;
}

/* ---- digest, HMAC, HKDF ------------------------------------------------------------------------------------------ */

JNIEXPORT jint JNICALL FN(hash)(JNIEnv *env, jclass cls, jint algorithm, jbyteArray input, jbyteArray output,
                                jint outputOffset) {
    jint size = (*env)->GetArrayLength(env, input);
    jbyte *in = NULL, *out;
    int ok = 0;
    (void)cls;
    if (size > 0) in = (*env)->GetPrimitiveArrayCritical(env, input, NULL);
    out = (*env)->GetPrimitiveArrayCritical(env, output, NULL);
    if (out && (size == 0 || in))
        ok = neton_hash(algorithm, (const unsigned char *)in, size, (unsigned char *)out + outputOffset);
    if (out) (*env)->ReleasePrimitiveArrayCritical(env, output, out, 0);
    if (in) (*env)->ReleasePrimitiveArrayCritical(env, input, in, JNI_ABORT);
    return ok;
}

JNIEXPORT jint JNICALL FN(hmac)(JNIEnv *env, jclass cls, jint algorithm, jbyteArray key, jbyteArray input,
                                jbyteArray output, jint outputOffset) {
    jint keySize = (*env)->GetArrayLength(env, key), size = (*env)->GetArrayLength(env, input);
    jbyte *k = NULL, *in = NULL, *out;
    int ok = 0;
    (void)cls;
    if (keySize > 0) k = (*env)->GetPrimitiveArrayCritical(env, key, NULL);
    if (size > 0) in = (*env)->GetPrimitiveArrayCritical(env, input, NULL);
    out = (*env)->GetPrimitiveArrayCritical(env, output, NULL);
    if (out && (keySize == 0 || k) && (size == 0 || in))
        ok = neton_hmac(algorithm, (const unsigned char *)k, keySize, (const unsigned char *)in, size,
                        (unsigned char *)out + outputOffset);
    if (out) (*env)->ReleasePrimitiveArrayCritical(env, output, out, 0);
    if (in) (*env)->ReleasePrimitiveArrayCritical(env, input, in, JNI_ABORT);
    if (k) (*env)->ReleasePrimitiveArrayCritical(env, key, k, JNI_ABORT);
    return ok;
}

/* Extract (expand == 0) uses salt; expand uses info. */
JNIEXPORT jint JNICALL FN(hkdf)(JNIEnv *env, jclass cls, jint algorithm, jboolean expand, jbyteArray key,
                                jbyteArray salt, jbyteArray info, jbyteArray output, jint offset, jint length) {
    jint keySize = (*env)->GetArrayLength(env, key);
    jint saltSize = salt ? (*env)->GetArrayLength(env, salt) : 0;
    jint infoSize = info ? (*env)->GetArrayLength(env, info) : 0;
    jbyte *k = NULL, *s = NULL, *i = NULL, *out;
    int ok = 0;
    (void)cls;
    if (keySize > 0) k = (*env)->GetPrimitiveArrayCritical(env, key, NULL);
    if (saltSize > 0) s = (*env)->GetPrimitiveArrayCritical(env, salt, NULL);
    if (infoSize > 0) i = (*env)->GetPrimitiveArrayCritical(env, info, NULL);
    out = (*env)->GetPrimitiveArrayCritical(env, output, NULL);
    if (out && (keySize == 0 || k) && (saltSize == 0 || s) && (infoSize == 0 || i))
        ok = neton_hkdf(algorithm, expand ? 1 : 0, (const unsigned char *)k, keySize, (const unsigned char *)s, saltSize,
                        (const unsigned char *)i, infoSize, (unsigned char *)out + offset, length);
    if (out) (*env)->ReleasePrimitiveArrayCritical(env, output, out, 0);
    if (i) (*env)->ReleasePrimitiveArrayCritical(env, info, i, JNI_ABORT);
    if (s) (*env)->ReleasePrimitiveArrayCritical(env, salt, s, JNI_ABORT);
    if (k) (*env)->ReleasePrimitiveArrayCritical(env, key, k, JNI_ABORT);
    return ok;
}

/* CRYPTO_memcmp of two arrays of the same, non-zero size (checked in Kotlin). */
JNIEXPORT jboolean JNICALL FN(constantTimeEquals)(JNIEnv *env, jclass cls, jbyteArray a, jbyteArray b) {
    jint size = (*env)->GetArrayLength(env, a);
    jbyte *x, *y;
    int equal = 0;
    (void)cls;
    x = (*env)->GetPrimitiveArrayCritical(env, a, NULL);
    y = (*env)->GetPrimitiveArrayCritical(env, b, NULL);
    if (x && y) equal = CRYPTO_memcmp(x, y, (size_t)size) == 0;
    if (y) (*env)->ReleasePrimitiveArrayCritical(env, b, y, JNI_ABORT);
    if (x) (*env)->ReleasePrimitiveArrayCritical(env, a, x, JNI_ABORT);
    return equal ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT void JNICALL FN(wipe)(JNIEnv *env, jclass cls, jbyteArray array) {
    jint size = (*env)->GetArrayLength(env, array);
    jbyte *p;
    (void)cls;
    if (size == 0) return;
    p = (*env)->GetPrimitiveArrayCritical(env, array, NULL);
    if (p) { OPENSSL_cleanse(p, (size_t)size); (*env)->ReleasePrimitiveArrayCritical(env, array, p, 0); }
}

/* ---- byte-stream TLS (neton_tls.h; TlsPrimitives on the JVM) ------------------------------------------------------ */

#define CTX(h) FROM_HANDLE(SSL_CTX, h)
#define TLS(h) FROM_HANDLE(neton_tls, h)

/* Pins [array] (may be empty or null: then NULL) for one shim call. */
#define PIN(env, array, size) ((size) > 0 ? (*(env))->GetPrimitiveArrayCritical((env), (array), NULL) : NULL)
#define UNPIN(env, array, p, mode) do { if (p) (*(env))->ReleasePrimitiveArrayCritical((env), (array), (p), (mode)); } while (0)

JNIEXPORT jlong JNICALL FN(tlsContextNew)(JNIEnv *env, jclass cls, jint minimum, jint maximum, jint verify) {
    (void)env; (void)cls;
    ERR_clear_error();
    return to_handle(neton_tls_context_new(minimum, maximum, verify));
}
JNIEXPORT void JNICALL FN(tlsContextFree)(JNIEnv *env, jclass cls, jlong ctx) { (void)env; (void)cls; neton_tls_context_free(CTX(ctx)); }
JNIEXPORT jint JNICALL FN(tlsVerifyMode)(JNIEnv *env, jclass cls, jboolean server, jint auth) {
    (void)env; (void)cls; return neton_tls_verify_mode(server ? 1 : 0, auth);
}
JNIEXPORT void JNICALL FN(tlsLimits)(JNIEnv *env, jclass cls, jlong ctx, jint depth, jint bytes) {
    (void)env; (void)cls; neton_tls_limits(CTX(ctx), depth, bytes);
}
JNIEXPORT jint JNICALL FN(tlsRoots)(JNIEnv *env, jclass cls, jlong ctx, jbyteArray pem) {
    jint size = (*env)->GetArrayLength(env, pem);
    jbyte *p = PIN(env, pem, size);
    int ok = 0;
    (void)cls;
    if (p) ok = neton_tls_roots(CTX(ctx), (const unsigned char *)p, size);
    UNPIN(env, pem, p, JNI_ABORT);
    return ok;
}
JNIEXPORT jint JNICALL FN(tlsDefaultPaths)(JNIEnv *env, jclass cls, jlong ctx) { (void)env; (void)cls; return neton_tls_default_paths(CTX(ctx)); }
JNIEXPORT jint JNICALL FN(tlsIdentity)(JNIEnv *env, jclass cls, jlong ctx, jbyteArray chain, jbyteArray key) {
    jint chainSize = (*env)->GetArrayLength(env, chain), keySize = (*env)->GetArrayLength(env, key);
    jbyte *c = PIN(env, chain, chainSize), *k = PIN(env, key, keySize);
    int ok = 0;
    (void)cls;
    if (c && k) ok = neton_tls_identity(CTX(ctx), (const unsigned char *)c, chainSize, (const unsigned char *)k, keySize);
    UNPIN(env, key, k, JNI_ABORT);
    UNPIN(env, chain, c, JNI_ABORT);
    return ok;
}

typedef int (*neton_ctx_string_fn)(SSL_CTX *, const char *);
static jint with_string(JNIEnv *env, jlong ctx, jstring value, neton_ctx_string_fn fn) {
    const char *v = (*env)->GetStringUTFChars(env, value, NULL);
    int ok;
    if (!v) return 0;
    ok = fn(CTX(ctx), v);
    (*env)->ReleaseStringUTFChars(env, value, v);
    return ok;
}
JNIEXPORT jint JNICALL FN(tlsCipherList)(JNIEnv *env, jclass cls, jlong ctx, jstring v) { (void)cls; return with_string(env, ctx, v, neton_tls_cipher_list); }
JNIEXPORT jint JNICALL FN(tlsCipherSuites)(JNIEnv *env, jclass cls, jlong ctx, jstring v) { (void)cls; return with_string(env, ctx, v, neton_tls_cipher_suites); }
JNIEXPORT jint JNICALL FN(tlsGroups)(JNIEnv *env, jclass cls, jlong ctx, jstring v) { (void)cls; return with_string(env, ctx, v, neton_tls_groups); }

JNIEXPORT jlong JNICALL FN(tlsNew)(JNIEnv *env, jclass cls, jlong ctx, jboolean server, jstring identity, jboolean ip,
                                   jbyteArray alpn, jint capacity) {
    const char *id = identity ? (*env)->GetStringUTFChars(env, identity, NULL) : NULL;
    jint alpnSize = (*env)->GetArrayLength(env, alpn);
    jbyte *a;
    neton_tls *engine = NULL;
    (void)cls;
    if (identity && !id) return 0;
    a = PIN(env, alpn, alpnSize);
    if (alpnSize == 0 || a) engine = neton_tls_new(CTX(ctx), server ? 1 : 0, id, ip ? 1 : 0, (const unsigned char *)a, alpnSize, capacity);
    UNPIN(env, alpn, a, JNI_ABORT);
    if (id) (*env)->ReleaseStringUTFChars(env, identity, id);
    return to_handle(engine);
}
JNIEXPORT void JNICALL FN(tlsFree)(JNIEnv *env, jclass cls, jlong e) { (void)env; (void)cls; neton_tls_free(TLS(e)); }

JNIEXPORT jboolean JNICALL FN(tlsReady)(JNIEnv *env, jclass cls, jlong e) { (void)env; (void)cls; return neton_tls_ready(TLS(e)) == 1; }
JNIEXPORT jboolean JNICALL FN(tlsFailed)(JNIEnv *env, jclass cls, jlong e) { (void)env; (void)cls; return neton_tls_failed(TLS(e)) != 0; }
JNIEXPORT jint JNICALL FN(tlsPendingWrite)(JNIEnv *env, jclass cls, jlong e) { (void)env; (void)cls; return neton_tls_pending_write(TLS(e)); }
JNIEXPORT jint JNICALL FN(tlsPendingCiphertext)(JNIEnv *env, jclass cls, jlong e) { (void)env; (void)cls; return neton_tls_pending(TLS(e)); }
JNIEXPORT jboolean JNICALL FN(tlsSentClose)(JNIEnv *env, jclass cls, jlong e) { (void)env; (void)cls; return neton_tls_sent_close(TLS(e)) == 1; }
JNIEXPORT jint JNICALL FN(tlsFailureKind)(JNIEnv *env, jclass cls, jlong e) { (void)env; (void)cls; return neton_tls_failure_kind(TLS(e)); }
JNIEXPORT jint JNICALL FN(tlsVerifyCode)(JNIEnv *env, jclass cls, jlong e) { (void)env; (void)cls; return neton_tls_verify_code(TLS(e)); }
JNIEXPORT jint JNICALL FN(tlsAlertCode)(JNIEnv *env, jclass cls, jlong e) { (void)env; (void)cls; return neton_tls_alert_code(TLS(e)); }

static jstring maybe_string(JNIEnv *env, const char *value) { return value ? (*env)->NewStringUTF(env, value) : NULL; }
JNIEXPORT jstring JNICALL FN(tlsVersionName)(JNIEnv *env, jclass cls, jlong e) { (void)cls; return maybe_string(env, neton_tls_version_name(TLS(e))); }
JNIEXPORT jstring JNICALL FN(tlsCipherName)(JNIEnv *env, jclass cls, jlong e) { (void)cls; return maybe_string(env, neton_tls_cipher_name(TLS(e))); }
JNIEXPORT jstring JNICALL FN(tlsServerName)(JNIEnv *env, jclass cls, jlong e) { (void)cls; return maybe_string(env, neton_tls_sni(TLS(e))); }

/* The selected ALPN protocol's bytes, or null. */
JNIEXPORT jbyteArray JNICALL FN(tlsAlpn)(JNIEnv *env, jclass cls, jlong e) {
    unsigned char buffer[255];
    int size = neton_tls_alpn_copy(TLS(e), NULL);
    jbyteArray out;
    (void)cls;
    if (size <= 0 || size > 255) return NULL;
    neton_tls_alpn_copy(TLS(e), buffer);
    out = (*env)->NewByteArray(env, size);
    if (out) (*env)->SetByteArrayRegion(env, out, 0, size, (const jbyte *)buffer);
    return out;
}

/* DER of the peer certificate [index]: null past the end, an empty array on failure. */
JNIEXPORT jbyteArray JNICALL FN(tlsPeerDer)(JNIEnv *env, jclass cls, jlong e, jint index) {
    int size = neton_tls_peer_der(TLS(e), index, NULL);
    unsigned char *buffer;
    jbyteArray out;
    (void)cls;
    if (size == 0) return NULL;
    if (size < 0) return (*env)->NewByteArray(env, 0);
    buffer = OPENSSL_malloc((size_t)size);
    if (!buffer || neton_tls_peer_der(TLS(e), index, buffer) != size) { OPENSSL_free(buffer); return (*env)->NewByteArray(env, 0); }
    out = (*env)->NewByteArray(env, size);
    if (out) (*env)->SetByteArrayRegion(env, out, 0, size, (const jbyte *)buffer);
    OPENSSL_free(buffer);
    return out;
}

JNIEXPORT jint JNICALL FN(tlsHandshake)(JNIEnv *env, jclass cls, jlong e) { (void)env; (void)cls; return neton_tls_handshake(TLS(e)); }
JNIEXPORT void JNICALL FN(tlsEof)(JNIEnv *env, jclass cls, jlong e) { (void)env; (void)cls; neton_tls_eof(TLS(e)); }
JNIEXPORT jint JNICALL FN(tlsShutdown)(JNIEnv *env, jclass cls, jlong e) { (void)env; (void)cls; return neton_tls_shutdown(TLS(e)); }

typedef int (*neton_tls_io_fn)(neton_tls *, unsigned char *, int);
static jint tls_io(JNIEnv *env, jlong e, jbyteArray data, jint offset, jint length, int writes_array, neton_tls_io_fn fn) {
    jbyte *p = (*env)->GetPrimitiveArrayCritical(env, data, NULL);
    int n;
    if (!p) return -1;
    n = fn(TLS(e), (unsigned char *)p + offset, length);
    (*env)->ReleasePrimitiveArrayCritical(env, data, p, writes_array ? 0 : JNI_ABORT);
    return n;
}
static int feed_fn(neton_tls *t, unsigned char *d, int n) { return neton_tls_feed(t, d, n); }
static int write_fn(neton_tls *t, unsigned char *d, int n) { return neton_tls_write(t, d, n); }
JNIEXPORT jint JNICALL FN(tlsFeed)(JNIEnv *env, jclass cls, jlong e, jbyteArray d, jint o, jint n) { (void)cls; return tls_io(env, e, d, o, n, 0, feed_fn); }
JNIEXPORT jint JNICALL FN(tlsDrain)(JNIEnv *env, jclass cls, jlong e, jbyteArray d, jint o, jint n) { (void)cls; return tls_io(env, e, d, o, n, 1, neton_tls_drain); }
JNIEXPORT jint JNICALL FN(tlsRead)(JNIEnv *env, jclass cls, jlong e, jbyteArray d, jint o, jint n) { (void)cls; return tls_io(env, e, d, o, n, 1, neton_tls_read); }
JNIEXPORT jint JNICALL FN(tlsWrite)(JNIEnv *env, jclass cls, jlong e, jbyteArray d, jint o, jint n) { (void)cls; return tls_io(env, e, d, o, n, 0, write_fn); }

JNIEXPORT jint JNICALL FN(tlsExport)(JNIEnv *env, jclass cls, jlong e, jbyteArray output, jstring label, jbyteArray context) {
    const char *l = (*env)->GetStringUTFChars(env, label, NULL);
    jint labelSize = (*env)->GetStringUTFLength(env, label);
    jint outSize = (*env)->GetArrayLength(env, output);
    jint contextSize = context ? (*env)->GetArrayLength(env, context) : 0;
    jbyte *o, *c;
    int ok = 0;
    (void)cls;
    if (!l) return 0;
    o = (*env)->GetPrimitiveArrayCritical(env, output, NULL);
    c = PIN(env, context, contextSize);
    if (o && (contextSize == 0 || c))
        ok = neton_tls_export(TLS(e), (unsigned char *)o, outSize, l, labelSize, (const unsigned char *)c, contextSize, context ? 1 : 0);
    UNPIN(env, context, c, JNI_ABORT);
    UNPIN(env, output, o, 0);
    (*env)->ReleaseStringUTFChars(env, label, l);
    return ok;
}

/* ---- QUIC TLS (neton_quic_tls.h; QuicTlsPrimitives on the JVM) ---------------------------------------------------- */

#define QTLS(h) FROM_HANDLE(neton_qtls, h)

typedef int (*neton_take_fn)(neton_qtls *, unsigned char *);
/* A Java array of what [fn] reports (size with NULL, then the bytes); [empty_as_null]: null when there is nothing. */
static jbyteArray take_array(JNIEnv *env, neton_qtls *q, neton_take_fn fn, int empty_as_null) {
    int n = fn(q, NULL);
    jbyteArray out;
    jbyte *p;
    if (n <= 0) return empty_as_null ? NULL : (*env)->NewByteArray(env, 0);
    out = (*env)->NewByteArray(env, n);
    if (!out) return NULL;
    p = (*env)->GetPrimitiveArrayCritical(env, out, NULL);
    if (p) { fn(q, (unsigned char *)p); (*env)->ReleasePrimitiveArrayCritical(env, out, p, 0); }
    return out;
}

static jstring take_string_or_null(JNIEnv *env, jstring s, const char **chars) {
    *chars = s ? (*env)->GetStringUTFChars(env, s, NULL) : NULL;
    return s;
}

JNIEXPORT jlong JNICALL FN(qtlsContextNew)(JNIEnv *env, jclass cls, jboolean server, jstring suites, jstring groups) {
    const char *su = (*env)->GetStringUTFChars(env, suites, NULL), *gr = NULL;
    SSL_CTX *ctx = NULL;
    (void)cls;
    take_string_or_null(env, groups, &gr);
    if (su && (!groups || gr)) ctx = neton_qtls_ctx_new(server ? 1 : 0, su, gr);
    if (gr) (*env)->ReleaseStringUTFChars(env, groups, gr);
    if (su) (*env)->ReleaseStringUTFChars(env, suites, su);
    return to_handle(ctx);
}
JNIEXPORT void JNICALL FN(qtlsContextFree)(JNIEnv *env, jclass cls, jlong c) { (void)env; (void)cls; neton_qtls_ctx_free(CTX(c)); }
JNIEXPORT void JNICALL FN(qtlsContextVerify)(JNIEnv *env, jclass cls, jlong c, jint mode) { (void)env; (void)cls; neton_qtls_ctx_verify(CTX(c), mode); }
JNIEXPORT void JNICALL FN(qtlsContextKeyLog)(JNIEnv *env, jclass cls, jlong c) { (void)env; (void)cls; neton_qtls_ctx_keylog(CTX(c)); }
JNIEXPORT jint JNICALL FN(qtlsContextAnchor)(JNIEnv *env, jclass cls, jlong c, jbyteArray der) {
    jint n = (*env)->GetArrayLength(env, der);
    jbyte *p = PIN(env, der, n);
    int ok = 0;
    (void)cls;
    if (p) ok = neton_qtls_ctx_anchor(CTX(c), (const unsigned char *)p, n);
    UNPIN(env, der, p, JNI_ABORT);
    return ok;
}
JNIEXPORT jint JNICALL FN(qtlsContextIdentity)(JNIEnv *env, jclass cls, jlong c, jbyteArray certs, jintArray sizes,
                                               jbyteArray key, jboolean pem) {
    jint certsLen = (*env)->GetArrayLength(env, certs), count = (*env)->GetArrayLength(env, sizes), keyLen = (*env)->GetArrayLength(env, key);
    jbyte *ce, *k;
    jint *si;
    int ok = 0;
    (void)cls;
    ce = PIN(env, certs, certsLen);
    si = count > 0 ? (*env)->GetPrimitiveArrayCritical(env, sizes, NULL) : NULL;
    k = PIN(env, key, keyLen);
    if (ce && si && k) ok = neton_qtls_ctx_identity(CTX(c), (const unsigned char *)ce, (const int *)si, count,
                                                    (const unsigned char *)k, keyLen, pem ? 1 : 0);
    UNPIN(env, key, k, JNI_ABORT);
    if (si) (*env)->ReleasePrimitiveArrayCritical(env, sizes, si, JNI_ABORT);
    UNPIN(env, certs, ce, JNI_ABORT);
    return ok;
}

JNIEXPORT jlong JNICALL FN(qtlsNew)(JNIEnv *env, jclass cls, jlong c, jboolean server, jbyteArray params, jbyteArray alpn, jboolean keylog) {
    jint pn = (*env)->GetArrayLength(env, params), an = (*env)->GetArrayLength(env, alpn);
    jbyte *p = PIN(env, params, pn), *a = PIN(env, alpn, an);
    neton_qtls *q = NULL;
    (void)cls;
    if ((pn == 0 || p) && (an == 0 || a))
        q = neton_qtls_new(CTX(c), server ? 1 : 0, (const unsigned char *)p, pn, (const unsigned char *)a, an, keylog ? 1 : 0);
    UNPIN(env, alpn, a, JNI_ABORT);
    UNPIN(env, params, p, JNI_ABORT);
    return to_handle(q);
}
JNIEXPORT void JNICALL FN(qtlsFree)(JNIEnv *env, jclass cls, jlong h) { (void)env; (void)cls; neton_qtls_free(QTLS(h)); }
JNIEXPORT jboolean JNICALL FN(qtlsServerName)(JNIEnv *env, jclass cls, jlong h, jstring name, jboolean ip) {
    const char *n = (*env)->GetStringUTFChars(env, name, NULL);
    int ok = 0;
    (void)cls;
    if (n) { ok = neton_qtls_server_name(QTLS(h), n, ip ? 1 : 0); (*env)->ReleaseStringUTFChars(env, name, n); }
    return ok == 1;
}
JNIEXPORT jboolean JNICALL FN(qtlsOfferAlpn)(JNIEnv *env, jclass cls, jlong h, jbyteArray wire) {
    jint n = (*env)->GetArrayLength(env, wire);
    jbyte *p = PIN(env, wire, n);
    int ok = 0;
    (void)cls;
    if (n == 0 || p) ok = neton_qtls_offer_alpn(QTLS(h), (const unsigned char *)p, n);
    UNPIN(env, wire, p, JNI_ABORT);
    return ok == 1;
}
JNIEXPORT jboolean JNICALL FN(qtlsResume)(JNIEnv *env, jclass cls, jlong h, jbyteArray der, jboolean early, jbyteArray offered) {
    jint dn = (*env)->GetArrayLength(env, der), on = (*env)->GetArrayLength(env, offered);
    jbyte *d = PIN(env, der, dn), *o = PIN(env, offered, on);
    int ok = 0;
    (void)cls;
    if (d && (on == 0 || o)) ok = neton_qtls_resume(QTLS(h), (const unsigned char *)d, dn, early ? 1 : 0, (const unsigned char *)o, on);
    UNPIN(env, offered, o, JNI_ABORT);
    UNPIN(env, der, d, JNI_ABORT);
    return ok == 1;
}
JNIEXPORT jboolean JNICALL FN(qtlsEnableEarlyData)(JNIEnv *env, jclass cls, jlong h) { (void)env; (void)cls; return neton_qtls_enable_early_data(QTLS(h)) == 1; }
JNIEXPORT void JNICALL FN(qtlsInject)(JNIEnv *env, jclass cls, jlong h, jint cb) { (void)env; (void)cls; neton_qtls_inject(QTLS(h), cb); }
JNIEXPORT jboolean JNICALL FN(qtlsProvide)(JNIEnv *env, jclass cls, jlong h, jbyteArray bytes) {
    jint n = (*env)->GetArrayLength(env, bytes);
    jbyte *p = PIN(env, bytes, n);
    int ok = 0;
    (void)cls;
    if (n == 0 || p) ok = neton_qtls_provide(QTLS(h), (const unsigned char *)p, n);
    UNPIN(env, bytes, p, JNI_ABORT);
    return ok == 1;
}
JNIEXPORT jint JNICALL FN(qtlsIncoming)(JNIEnv *env, jclass cls, jlong h) { (void)env; (void)cls; return neton_qtls_incoming(QTLS(h)); }
JNIEXPORT jint JNICALL FN(qtlsDrive)(JNIEnv *env, jclass cls, jlong h, jboolean complete) { (void)env; (void)cls; return neton_qtls_drive(QTLS(h), complete ? 1 : 0); }
JNIEXPORT jboolean JNICALL FN(qtlsInitFinished)(JNIEnv *env, jclass cls, jlong h) { (void)env; (void)cls; return neton_qtls_init_finished(QTLS(h)) == 1; }

JNIEXPORT jbyteArray JNICALL FN(qtlsTakeOutgoing)(JNIEnv *env, jclass cls, jlong h, jint level) {
    int n = neton_qtls_take_out(QTLS(h), level, NULL);
    jbyteArray out;
    jbyte *p;
    (void)cls;
    out = (*env)->NewByteArray(env, n);
    if (!out || n == 0) return out;
    p = (*env)->GetPrimitiveArrayCritical(env, out, NULL);
    if (p) { neton_qtls_take_out(QTLS(h), level, (unsigned char *)p); (*env)->ReleasePrimitiveArrayCritical(env, out, p, 0); }
    return out;
}
JNIEXPORT jbyteArray JNICALL FN(qtlsTakeSecret)(JNIEnv *env, jclass cls, jlong h, jint level, jint direction) {
    unsigned char secret[48];
    int n = neton_qtls_take_secret(QTLS(h), level, direction, secret);
    jbyteArray out;
    (void)cls;
    if (n <= 0) return NULL;
    out = (*env)->NewByteArray(env, n);
    if (out) (*env)->SetByteArrayRegion(env, out, 0, n, (const jbyte *)secret);
    OPENSSL_cleanse(secret, sizeof secret);
    return out;
}
JNIEXPORT jint JNICALL FN(qtlsSuite)(JNIEnv *env, jclass cls, jlong h, jint level) { (void)env; (void)cls; return neton_qtls_suite(QTLS(h), level); }
JNIEXPORT jbyteArray JNICALL FN(qtlsTakeEarlySecret)(JNIEnv *env, jclass cls, jlong h) {
    unsigned char secret[48];
    int n = neton_qtls_take_early_secret(QTLS(h), secret);
    jbyteArray out;
    (void)cls;
    if (n <= 0) return NULL;
    out = (*env)->NewByteArray(env, n);
    if (out) (*env)->SetByteArrayRegion(env, out, 0, n, (const jbyte *)secret);
    OPENSSL_cleanse(secret, sizeof secret);
    return out;
}
JNIEXPORT jbyteArray JNICALL FN(qtlsPeerParams)(JNIEnv *env, jclass cls, jlong h) {
    int n = neton_qtls_peer_params(QTLS(h), NULL);
    jbyteArray out;
    jbyte *p;
    (void)cls;
    if (n < 0) return NULL;
    out = (*env)->NewByteArray(env, n);
    if (!out || n == 0) return out;
    p = (*env)->GetPrimitiveArrayCritical(env, out, NULL);
    if (p) { neton_qtls_peer_params(QTLS(h), (unsigned char *)p); (*env)->ReleasePrimitiveArrayCritical(env, out, p, 0); }
    return out;
}
JNIEXPORT jint JNICALL FN(qtlsAlert)(JNIEnv *env, jclass cls, jlong h) { (void)env; (void)cls; return neton_qtls_alert_sent(QTLS(h)); }
JNIEXPORT jint JNICALL FN(qtlsFailure)(JNIEnv *env, jclass cls, jlong h) { (void)env; (void)cls; return neton_qtls_failure(QTLS(h)); }
JNIEXPORT jstring JNICALL FN(qtlsFailureMessage)(JNIEnv *env, jclass cls, jlong h) { (void)cls; return (*env)->NewStringUTF(env, neton_qtls_failure_message(QTLS(h))); }
JNIEXPORT jbyteArray JNICALL FN(qtlsAlpn)(JNIEnv *env, jclass cls, jlong h) { (void)cls; return take_array(env, QTLS(h), neton_qtls_alpn, 1); }
JNIEXPORT jstring JNICALL FN(qtlsSni)(JNIEnv *env, jclass cls, jlong h) { (void)cls; return maybe_string(env, neton_qtls_sni(QTLS(h))); }
JNIEXPORT jboolean JNICALL FN(qtlsEarlyAccepted)(JNIEnv *env, jclass cls, jlong h) { (void)env; (void)cls; return neton_qtls_early_accepted(QTLS(h)) == 1; }
JNIEXPORT jbyteArray JNICALL FN(qtlsPeerDer)(JNIEnv *env, jclass cls, jlong h, jint index) {
    int n = neton_qtls_peer_der(QTLS(h), index, NULL);
    unsigned char *buffer;
    jbyteArray out;
    (void)cls;
    if (n == 0) return NULL;
    if (n < 0) return (*env)->NewByteArray(env, 0);
    buffer = OPENSSL_malloc((size_t)n);
    if (!buffer || neton_qtls_peer_der(QTLS(h), index, buffer) != n) { OPENSSL_free(buffer); return (*env)->NewByteArray(env, 0); }
    out = (*env)->NewByteArray(env, n);
    if (out) (*env)->SetByteArrayRegion(env, out, 0, n, (const jbyte *)buffer);
    OPENSSL_free(buffer);
    return out;
}
JNIEXPORT jbyteArray JNICALL FN(qtlsTakeTickets)(JNIEnv *env, jclass cls, jlong h) { (void)cls; return take_array(env, QTLS(h), neton_qtls_take_tickets, 0); }
JNIEXPORT jint JNICALL FN(qtlsDroppedTickets)(JNIEnv *env, jclass cls, jlong h) { (void)env; (void)cls; return neton_qtls_dropped_tickets(QTLS(h)); }
JNIEXPORT jbyteArray JNICALL FN(qtlsTakeKeyLog)(JNIEnv *env, jclass cls, jlong h) { (void)cls; return take_array(env, QTLS(h), neton_qtls_take_keylog, 0); }
JNIEXPORT jint JNICALL FN(qtlsExport)(JNIEnv *env, jclass cls, jlong h, jbyteArray output, jstring label, jbyteArray context) {
    const char *l = (*env)->GetStringUTFChars(env, label, NULL);
    jint labelLen = (*env)->GetStringUTFLength(env, label), outLen = (*env)->GetArrayLength(env, output), ctxLen = (*env)->GetArrayLength(env, context);
    jbyte *o, *c;
    int ok = 0;
    (void)cls;
    if (!l) return 0;
    o = PIN(env, output, outLen);
    c = PIN(env, context, ctxLen);
    if (o && (ctxLen == 0 || c)) ok = neton_qtls_export(QTLS(h), (unsigned char *)o, outLen, l, labelLen, (const unsigned char *)c, ctxLen);
    UNPIN(env, context, c, JNI_ABORT);
    UNPIN(env, output, o, 0);
    (*env)->ReleaseStringUTFChars(env, label, l);
    return ok;
}
JNIEXPORT void JNICALL FN(qtlsCleanShutdown)(JNIEnv *env, jclass cls, jlong h) { (void)env; (void)cls; neton_qtls_clean_shutdown(QTLS(h)); }

JNIEXPORT jboolean JNICALL FN(qtlsIsCertificate)(JNIEnv *env, jclass cls, jbyteArray der) {
    jint n = (*env)->GetArrayLength(env, der);
    jbyte *p = PIN(env, der, n);
    int ok = 0;
    (void)cls;
    if (p) ok = neton_qtls_is_certificate((const unsigned char *)p, n);
    UNPIN(env, der, p, JNI_ABORT);
    return ok == 1;
}
JNIEXPORT jboolean JNICALL FN(qtlsIsPrivateKey)(JNIEnv *env, jclass cls, jbyteArray key, jboolean pem) {
    jint n = (*env)->GetArrayLength(env, key);
    jbyte *p = PIN(env, key, n);
    int ok = 0;
    (void)cls;
    if (p) ok = neton_qtls_is_private_key((const unsigned char *)p, n, pem ? 1 : 0);
    UNPIN(env, key, p, JNI_ABORT);
    return ok == 1;
}
/* The PEM reader runs twice (size, then bytes): no JNI call happens while the arrays are pinned. */
JNIEXPORT jbyteArray JNICALL FN(qtlsPemCertificates)(JNIEnv *env, jclass cls, jbyteArray pem) {
    jint n = (*env)->GetArrayLength(env, pem), total;
    jbyte *p, *o;
    jbyteArray out;
    (void)cls;
    if (n == 0) return (*env)->NewByteArray(env, 0);
    p = (*env)->GetPrimitiveArrayCritical(env, pem, NULL);
    if (!p) return NULL;
    total = neton_qtls_pem_certificates((const unsigned char *)p, n, NULL);
    (*env)->ReleasePrimitiveArrayCritical(env, pem, p, JNI_ABORT);
    out = (*env)->NewByteArray(env, total > 0 ? total : 0);
    if (!out || total <= 0) return out;
    p = (*env)->GetPrimitiveArrayCritical(env, pem, NULL);
    o = (*env)->GetPrimitiveArrayCritical(env, out, NULL);
    if (p && o) neton_qtls_pem_certificates((const unsigned char *)p, n, (unsigned char *)o);
    if (o) (*env)->ReleasePrimitiveArrayCritical(env, out, o, 0);
    if (p) (*env)->ReleasePrimitiveArrayCritical(env, pem, p, JNI_ABORT);
    return out;
}

