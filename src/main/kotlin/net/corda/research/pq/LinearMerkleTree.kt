package net.corda.research.pq

import net.corda.research.pq.details.ByteSequence
import java.util.*

class LinearMerkleTree<T: Any>(val items: Array<T>, val hash: (T) -> ByteArray) {

    private val cumulativeHash: ArrayList<ByteSequence>
    private val encoding: Array<ByteSequence>

    init {
        encoding = items.map { ByteSequence(hash(it)) }.toTypedArray()
        cumulativeHash = hashReduce(encoding.asSequence(), ByteSequence(0))
    }

    val root get() = cumulativeHash.last()

    fun certify(value: T): MembershipCertificate {
        val id = items.indexOf(value)
        require(id != -1) { "Element not present" }
        return MembershipCertificate(
                hashedValue = encoding[id],
                path = encoding.sliceArray((id + 1) until encoding.size),
                siblingHash = if (id != 0) {
                    cumulativeHash[id - 1]
                } else {
                    ByteSequence(0)
                })
    }

    data class MembershipCertificate(
            val hashedValue: ByteSequence,
            val siblingHash: ByteSequence,
            val path: Array<ByteSequence>) {

        operator override fun equals(other: Any?): Boolean {
            return if (other is MembershipCertificate) {
                Arrays.equals(path, other.path) &&
                        (siblingHash == other.siblingHash) &&
                        (hashedValue == other.hashedValue)
            } else false
        }
    }

    companion object {

        val HashCombiner = SHA384()

        val NodeSignatureSize = HashCombiner.outputByteSize

        private fun hashCombine(x: ByteSequence, y: ByteSequence): ByteSequence {
            val buffer = ByteArray(x.bytes.size + y.bytes.size)
            System.arraycopy(x.bytes, 0, buffer, 0, x.bytes.size)
            System.arraycopy(y.bytes, 0, buffer, x.bytes.size, y.bytes.size)
            return ByteSequence(HashCombiner(buffer))
        }

        private fun hashReduce(input: Sequence<ByteSequence>, seed: ByteSequence) : ArrayList<ByteSequence> {
            val result = ArrayList<ByteSequence>()
            var current = ByteSequence(seed.bytes.clone())
            for (value in input) {
                current = hashCombine(current, value)
                result.add(current)
            }
            if (result.isEmpty()) {
                result.add(current)
            }
            return result
        }

        fun check(root: ByteSequence, certificate: MembershipCertificate): Boolean {
            val expectedRoot = hashReduce(
                    input = certificate.path.asSequence(),
                    seed = hashCombine(certificate.siblingHash, certificate.hashedValue)).last()

            return (expectedRoot == root)
        }
    }
}