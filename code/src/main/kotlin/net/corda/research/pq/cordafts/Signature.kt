package net.corda.research.pq.cordafts

import net.corda.research.pq.LinearMerkleTree
import net.corda.research.pq.details.ByteSequence
import net.corda.research.pq.details.compacted
import net.corda.research.pq.details.getHashSeeds
import net.corda.research.pq.details.putHashSeeds
import java.nio.ByteBuffer
import java.util.*

internal typealias WOTSSignature = net.corda.research.pq.wots.Signature

data class Signature(
        val wotsSignature: WOTSSignature,
        val siblingHash: ByteSequence,
        val authPath: Array<ByteSequence>
) {

    fun put(output: ByteBuffer) {
        wotsSignature.put(output)
        output.put((if (siblingHash.bytes.isEmpty()) { 0 } else { 1 }).toByte())
        output.put(siblingHash.bytes)
        output.putHashSeeds(authPath)
    }

    val estimatedSize: Int get() {
        return wotsSignature.estimatedSize +
                (1 + siblingHash.bytes.size) +
                (4 + authPath.map { it.bytes.size }.sum())
    }

    override fun equals(other: Any?): Boolean {
        return if (other is Signature) {
            return (wotsSignature == other.wotsSignature) &&
                    (siblingHash == other.siblingHash) &&
                    (Arrays.equals(authPath, other.authPath))
        } else false
    }

    companion object {

        fun serialize(input: Signature): ByteArray {
            val buffer = ByteBuffer.allocate(input.estimatedSize)
            input.put(buffer)
            return buffer.compacted()
        }

        fun get(buffer: ByteBuffer, wotsHashSize: Int): Signature {
            val wotsSignature = WOTSSignature.get(buffer, wotsHashSize)
            val hasSiblingHash = buffer.get()
            var siblingHash = ByteSequence()
            if (hasSiblingHash > 0) {
                siblingHash = ByteSequence(LinearMerkleTree.NodeSignatureSize, 0)
                buffer.get(siblingHash.bytes)
            }
            val authPath = buffer.getHashSeeds(LinearMerkleTree.NodeSignatureSize)
            return Signature(
                    wotsSignature = wotsSignature,
                    siblingHash = siblingHash,
                    authPath = authPath)
        }

        fun deserialize(bytes: ByteArray, wotsHashSize: Int): Signature {
            val reader = ByteBuffer.wrap(bytes)
            return Signature.get(reader, wotsHashSize)
        }
    }
}