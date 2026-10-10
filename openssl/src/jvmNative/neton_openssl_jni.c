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
