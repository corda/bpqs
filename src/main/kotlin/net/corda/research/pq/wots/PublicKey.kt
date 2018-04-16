package net.corda.research.pq.wots

import net.corda.research.pq.details.ByteSequence
import java.nio.ByteBuffer

data class PublicKey(val data: ByteSequence): java.security.PublicKey {

    override fun getAlgorithm(): String = "WOTS"

    override fun getFormat(): String? = null

    override fun getEncoded() = data.bytes

    fun put(output: ByteBuffer) {
        output.put(data.bytes)
    }
}
