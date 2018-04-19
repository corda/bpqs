package net.corda.research.pq.wots

import net.corda.research.pq.details.ByteSequence
import net.corda.research.pq.details.*
import java.nio.ByteBuffer
import java.util.*

data class Signature(
        val seedMask: Long,
        val roots: Array<ByteSequence>,
        val checksum: Array<ByteSequence>
) {

    override fun equals(other: Any?): Boolean {
        return if (other is Signature) {
            (seedMask == other.seedMask) &&
                    (Arrays.equals(roots, other.roots)) &&
                    (Arrays.equals(checksum, other.checksum))
        } else false
    }

    val estimatedSize: Int get() = 8 +
            (4 + roots.map{ it.bytes.size }.sum()) +
            (4 + checksum.map { it.bytes.size }.sum())

    fun put(output: ByteBuffer) {
        output.putLong(seedMask).putHashSeeds(roots).putHashSeeds(checksum)
    }

    companion object {

        fun serialize(signature: Signature): ByteArray {
            val buffer = ByteBuffer.allocate(signature.estimatedSize)
            signature.put(buffer)
            return buffer.compacted()
        }

        fun get(buffer: ByteBuffer, hashSize: Int): Signature {
            val seedMask = buffer.getLong()
            val roots = buffer.getHashSeeds(hashSize)
            val checksum = buffer.getHashSeeds(hashSize)
            return Signature(
                    seedMask = seedMask,
                    roots = roots,
                    checksum = checksum)
        }

        fun deserialize(bytes: ByteArray, hashSize: Int): Signature {
            val reader = ByteBuffer.wrap(bytes)
            return get(reader, hashSize)
        }
    }
}
