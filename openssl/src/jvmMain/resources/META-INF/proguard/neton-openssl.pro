# R8 / ProGuard rules shipped in the JVM jar (R8 applies META-INF/proguard/*.pro of every dependency jar).
# libneton_openssl binds its Java_neton_openssl_Jni_* functions by name: the class and its native methods keep their
# names. The C side never calls back into Java, so nothing else is looked up by name.
-keepclasseswithmembernames,includedescriptorclasses class neton.openssl.Jni {
    native <methods>;
}
