package net.corda.research.pq.cordafts

import net.corda.research.pq.LinearMerkleTree
import net.corda.research.pq.details.compacted
import java.nio.ByteBuffer

internal typealias WOTSPrivateKey = net.corda.research.pq.wots.PrivateKey
internal typealias WOTSPublicKey = net.corda.research.pq.wots.PublicKey

class PrivateKey(val keys: List<Pair<WOTSPublicKey, WOTSPrivateKey>>)
    : java.security.PrivateKey {

    private val _encoded by lazy { serialize(this) }

    val pubKeysTree: LinearMerkleTree<WOTSPublicKey>

    init {
        val publicKeys = keys.map { it.first }.toTypedArray().reversedArray()
        pubKeysTree = LinearMerkleTree(publicKeys, { k: WOTSPublicKey -> k.encoded })
    }

    override fun getAlgorithm() = "CordaFTS"

    override fun getFormat() = null

    override fun getEncoded() = _encoded

    fun put(output: ByteBuffer) {
        output.putInt(keys.size)
        for ((p, q) in keys) {
            p.put(output)
            q.put(output)
        }
    }

    val estimatedSize: Int get() =
        (4 + keys.map{it.second.estimatedSize + it.first.encoded.size}.sum())

    companion object {

        fun serialize(key: PrivateKey): ByteArray {
            val buffer = ByteBuffer.allocate(key.estimatedSize)
            key.put(buffer)
            return buffer.compacted()
        }

        // TODO: deserialization
    }
}