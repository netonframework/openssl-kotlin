package neton.openssl

import kotlin.test.*
import kotlin.native.concurrent.Worker
import kotlin.native.concurrent.TransferMode

/** A frozen TlsContext shared by Kotlin/Native workers (the JVM shares it like any object). */
class TlsWorkerTest {
    @Test fun frozenContextCreatesEnginesAcrossThreads() {
        val context = TlsContext(false, testIdentity().certificate)
        val workers = List(4) { Worker.start() }
        try {
            val futures = workers.map { worker -> worker.execute(TransferMode.SAFE, { context }) { factory ->
                repeat(200) { factory.newEngine(PeerIdentity.Dns("localhost")).close() }
                200
            } }
            assertEquals(800, futures.sumOf { it.result })
        } finally {
            workers.forEach { it.requestTermination().result }
            context.close()
        }
    }
}
