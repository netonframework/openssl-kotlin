import neton.openssl.OpenSsl

fun main() {
    OpenSsl.checkVersion()
    check(OpenSsl.sha256("abc".encodeToByteArray()).size == 32)
    check(OpenSsl.randomBytes(16).size == 16)
    println("External Maven consumer: ${OpenSsl.version}")
}
