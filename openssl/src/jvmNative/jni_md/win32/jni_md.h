/*
 * The machine-dependent JNI definitions for Windows x64, for cross-building neton_openssl.dll with MinGW from a macOS
 * or Linux JDK, whose include/ has jni.h (platform-neutral) but only its own platform's jni_md.h. The types follow the
 * JNI specification's sizes on LLP64: jint is 32-bit (long is 32-bit on Windows), jlong 64-bit. JNICALL is the
 * Windows calling convention; on x64 there is only one, so it is spelled for completeness.
 */
#ifndef NETON_JNI_MD_WIN32_H
#define NETON_JNI_MD_WIN32_H

#define JNIEXPORT __declspec(dllexport)
#define JNIIMPORT __declspec(dllimport)
#define JNICALL __stdcall

typedef long jint;
typedef long long jlong;
typedef signed char jbyte;

#endif
