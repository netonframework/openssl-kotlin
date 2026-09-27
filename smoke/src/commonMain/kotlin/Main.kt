import neton.openssl.OpenSsl
import neton.openssl.AeadAlgorithm
import neton.openssl.AeadKey

fun main() {
    OpenSsl.checkVersion()
    check(OpenSsl.sha256("abc".encodeToByteArray()).size == 32)
    check(OpenSsl.randomBytes(16).size == 16)
    val key = AeadKey(AeadAlgorithm.AES_128_GCM, ByteArray(16))
    try {
        val buffer = ByteArray(17); buffer[0] = 42
        key.seal(buffer, 0, 1, ByteArray(12), ByteArray(0))
        check(key.open(buffer, 0, 17, ByteArray(12), ByteArray(0)))
        check(buffer[0] == 42.toByte())
    } finally { key.close() }
    println("External Maven consumer: ${OpenSsl.version}")
}
