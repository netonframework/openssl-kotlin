@file:OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
package neton.openssl

import kotlinx.cinterop.*
import kotlin.concurrent.atomics.AtomicInt
import neton.openssl.c.*

internal fun checkRange(array: ByteArray, offset: Int, length: Int) {
    require(offset >= 0 && length >= 0 && offset <= array.size && length <= array.size - offset) { "Invalid buffer range" }
}

internal inline fun <T> ByteArray.withBytes(offset: Int = 0, length: Int = size - offset, block: (CPointer<UByteVar>?) -> T): T {
    checkRange(this, offset, length)
    return if (length == 0) block(null) else usePinned { block(it.addressOf(offset).reinterpret()) }
}

/** No suspension in a native call: errors and cleanup stay on the invoking thread. */
internal class NativeHandle<T : CPointed>(pointer: CPointer<T>, private val release: (CPointer<T>) -> Unit) : AutoCloseable {
    private var pointer: CPointer<T>? = pointer
    private val busy = AtomicInt(0)

    inline fun <R> access(block: (CPointer<T>) -> R): R {
        check(busy.compareAndSet(0, 1)) { "Concurrent or reentrant native handle access" }
        try { return block(checkNotNull(pointer) { "Native handle is closed" }) }
        finally { busy.store(0) }
    }

    override fun close() {
        check(busy.compareAndSet(0, 1)) { "Concurrent close/use of native handle" }
        try { pointer?.let { pointer = null; release(it) } }
        finally { busy.store(0) }
    }
}

/** For frozen native factories only. close refuses while a factory operation is active. */
internal class SharedNativeHandle<T : CPointed>(private val pointer: CPointer<T>, private val release: (CPointer<T>) -> Unit) : AutoCloseable {
    private val readers = AtomicInt(0)
    inline fun <R> access(block: (CPointer<T>) -> R): R {
        while (true) {
            val n = readers.load()
            check(n >= 0) { "Native factory is closed" }
            check(n < Int.MAX_VALUE) { "Too many concurrent factory operations" }
            if (readers.compareAndSet(n, n + 1)) break
        }
        try { return block(pointer) } finally { readers.fetchAndAdd(-1) }
    }
    override fun close() {
        if (readers.compareAndSet(0, -1)) release(pointer)
        else check(readers.load() == -1) { "Close requires no concurrent factory operation" }
    }
}

internal fun sslFailure(operation: String): OpenSslException = memScoped {
    val buffer = allocArray<ByteVar>(256)
    val messages = mutableListOf<String>()
    while (neton_openssl_next_error(buffer, 256u) != 0) messages += buffer.toKString()
    OpenSslException("$operation failed: ${messages.joinToString("; ").ifEmpty { "no error detail" }}")
}
