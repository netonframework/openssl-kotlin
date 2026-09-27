@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)
import kotlinx.cinterop.*
import neton.openssl.*
import platform.posix.*

fun main(args: Array<String>) = memScoped {
    val size = args.getOrNull(0)?.toInt() ?: 1200
    val iterations = args.getOrNull(1)?.toInt() ?: 100000
    val algorithm = args.getOrNull(2)?.toInt() ?: 0
    require(size in 1..65536 && iterations in 1..10000000 && algorithm in 0..2)
    val clock = alloc<timespec>()
    fun now(): Long {
        check(clock_gettime(CLOCK_MONOTONIC.convert(), clock.ptr) == 0)
        return clock.tv_sec.toLong() * 1000000000L + clock.tv_nsec.toLong()
    }
    val cipher = AeadAlgorithm.entries[algorithm]
    val key = AeadKey(cipher, ByteArray(cipher.keySize))
    val data = ByteArray(size + 16); val nonce = ByteArray(12); val aad = ByteArray(16)
    val warmup = 10000
    var start = 0L
    try {
        for (i in 0 until iterations + warmup) {
            if (i == warmup) start = now()
            for (j in 0..3) nonce[j] = (i ushr (j * 8)).toByte()
            key.seal(data, 0, size, nonce, aad)
            check(key.open(data, 0, size + 16, nonce, aad))
        }
        val elapsed = now() - start
        println("kotlin,$algorithm,$size,$iterations,$elapsed,${elapsed.toDouble() / iterations / size / 2.0}")
    } finally { key.close() }
}
