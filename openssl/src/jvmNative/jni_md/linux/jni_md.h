/*
 * The machine-dependent JNI definitions for Linux (LP64), for cross-building libneton_openssl.so from a JDK that has
 * only its own platform's jni_md.h (a macOS JDK); build-jni.sh prefers the JDK's include/linux when it exists. Sizes
 * as the JNI specification fixes them: jint 32-bit, jlong 64-bit.
 */
#ifndef NETON_JNI_MD_LINUX_H
#define NETON_JNI_MD_LINUX_H

#define JNIEXPORT __attribute__((visibility("default")))
#define JNIIMPORT __attribute__((visibility("default")))
#define JNICALL

typedef int jint;
typedef long jlong;
typedef signed char jbyte;

#endif
