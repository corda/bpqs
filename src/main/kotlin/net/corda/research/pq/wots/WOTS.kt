package net.corda.research.pq.wots

import net.corda.research.pq.Hash
import net.corda.research.pq.details.ByteSequence
import java.security.SecureRandom
import java.security.SignatureException
import java.util.*
import kotlin.experimental.xor

class WOTS(
        val W: Int, //< Winternitz parameter in bits
        val digester: Hash, //< message digester
        val H: Hash, //< WOTS hash
        val rootHash: Hash, //< digester compacting public key
        private val rng: SecureRandom = SecureRandom()) {

    val N get() = H.outputByteSize //< Security parameter
    private val chainLength = (1 shl W) - 1
    private val keySequenceLen: Int
    private val maxChecksum: Int
    private val checksumSequenceLen: Int

    init {
        require(W > 0 && W <= 16)
        keySequenceLen = Math.ceil((digester.outputByteSize * 8).toDouble() / W).toInt()
        maxChecksum = chainLength * keySequenceLen
        checksumSequenceLen = Math.ceil((highestBit(maxChecksum.toLong()) + 1).toDouble() / W).toInt()
    }

    /**
     * Generate public/private
     */
    fun generateKeyPair(): Pair<PublicKey, PrivateKey> {
        val seed = rng.nextLong()
        //val bitmask = Random(seed).genHashSeeds(chainLength, N)

        // Generate private key roots and checksum roots
        val roots = rng
                .genHashSeeds(keySequenceLen, N)
                .map { ByteSequence(it) }

        val checksum = rng
                .genHashSeeds(checksumSequenceLen, N)
                .map { ByteSequence(it) }

        val privateKey = PrivateKey(
                roots = roots.toTypedArray(),
                checksum = checksum.toTypedArray())

        // Generate public key
        val publicKey = makePublicKey(
            roots = roots.map { iterateHash(chainLength, it) }.toTypedArray(),
            checksum = checksum.map { iterateHash(chainLength, it) }.toTypedArray())

        return Pair(publicKey, privateKey)
    }

    fun generateKeyPairTest(): Pair<List<ByteSequence>, List<ByteSequence>> {
        val seed = rng.nextLong()
        //val bitmask = Random(seed).genHashSeeds(chainLength, N)

        // Generate private key roots and checksum roots
        val roots = rng
                .genHashSeeds(keySequenceLen, N)
                .map { ByteSequence(it) }

        val checksum = rng
                .genHashSeeds(checksumSequenceLen, N)
                .map { ByteSequence(it) }

        return Pair(roots, checksum)
    }

    /**
     * Produce message signature
     */
    fun sign(msg: ByteArray, key: PrivateKey) =
        chainedHash(msg, key.roots, key.checksum, false)

    /**
     * Verify signature for message
     */
    fun verify(msg: ByteArray, key: PublicKey, sig: Signature) {
        if(image(msg, sig).data != key.data) {
            throw SignatureException("Failed verification")
        }
    }

    /**
     * Generate expected public key from message and signature
     */
    fun image(msg: ByteArray, signature: Signature): PublicKey {
        val sig = chainedHash(msg, signature.roots, signature.checksum)
        return makePublicKey(sig.roots, sig.checksum)
    }

    // "visible for testing"
    fun chainedHash(msg: ByteArray,
                    roots: Array<ByteSequence>,
                    checksumRoots: Array<ByteSequence>,
                    verifyMode: Boolean = true): Signature {
        val digest = digester(msg)
        val input = BitSet.valueOf(digest)
        val images = ArrayList<ByteSequence> ()
        val imageChecksum = ArrayList<ByteSequence> ()

        var offset = 0
        var checksum = 0
        for (root in roots) {
            val value = input.readLong(offset, offset + W).toInt()
            val iterations = if (verifyMode) { chainLength - value } else { value }
            images.add(iterateHash(iterations, root))
            offset += W
            checksum += value
        }

        checksum = maxChecksum - checksum

        for (root in checksumRoots) {
            val value = checksum and ((1 shl W) - 1)
            val iterations = if (verifyMode) { chainLength - value } else { value }
            imageChecksum.add(iterateHash(iterations, root))
            checksum = checksum ushr W
        }

        return Signature(
                roots = images.toTypedArray(),
                checksum = imageChecksum.toTypedArray())
    }

    private fun iterateHash(iterations: Int,
                            root: ByteSequence): ByteSequence {
        var result = root.bytes.clone()
        for (id in 0 until iterations) {
            result = H(result)
        }
        return ByteSequence(result)
    }

    fun makePublicKey(roots: Array<ByteSequence>,
                      checksum: Array<ByteSequence>) : PublicKey {

        val data = ByteArray(
                roots.map { it.bytes.size }.sum() +
                checksum.map { it.bytes.size }.sum())

        var offset = 0

        for (root in roots) {
            System.arraycopy(root.bytes, 0, data, offset, root.bytes.size)
            offset += root.bytes.size
        }

        for (c in checksum) {
            System.arraycopy(c.bytes, 0, data, offset, c.bytes.size)
            offset += c.bytes.size
        }

        return PublicKey(data = ByteSequence(rootHash(data)))
    }

    companion object {
        private fun highestBit(n: Long): Int {
            var x = n
            var result = 0
            while (x != 0L) {
                x = x ushr 1
                ++result
            }
            return result - 1
        }
    }
}

private fun Random.genHashSeeds(n: Int, hashSize: Int): Array<ByteArray> {
    val result = Array<ByteArray>(n) { ByteArray(hashSize) }
    for (row in result) {
        this.nextBytes(row)
    }
    return result
}

private fun BitSet.readLong(begin: Int, end: Int) : Long {
    var result = 0L
    var bit = 1L

    for (id in begin until end) {
        if (get(id)) { result = result or bit }
        bit = bit shl 1
    }

    return result
}