import neton.openssl.OpenSsl

fun main() {
    OpenSsl.checkVersion()
    val digest = OpenSsl.sha256("abc".encodeToByteArray())
        .joinToString("") { (it.toInt() and 255).toString(16).padStart(2, '0') }
    check(digest == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    println("Composite Linux consumer: ${OpenSsl.version}")
}
