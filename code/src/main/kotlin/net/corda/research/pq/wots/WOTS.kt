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
    private val chainLength = 1 shl W
    private val keySequenceLen: Int
    private val maxChecksum: Int
    private val checksumSequenceLen: Int

    init {
        require(W > 0 && W <= 16)
        keySequenceLen = Math.ceil(digester.outputByteSize.toDouble() / W).toInt()
        maxChecksum = (chainLength - 1) * keySequenceLen
        checksumSequenceLen = Math.ceil((highestBit(maxChecksum.toLong()) + 1).toDouble() / W).toInt()
    }

    /**
     * Generate public/private
     */
    fun generateKeyPair(): Pair<PublicKey, PrivateKey> {
        val seed = rng.nextLong()
        val bitmask = Random(seed).genHashSeeds(chainLength, N)

        // Generate private key roots and checksum roots
        val roots = rng
                .genHashSeeds(keySequenceLen, N)
                .map { ByteSequence(it) }

        val checksum = rng
                .genHashSeeds(checksumSequenceLen, N)
                .map { ByteSequence(it) }

        val privateKey = PrivateKey(
                seedMask = seed,
                roots = roots.toTypedArray(),
                checksum = checksum.toTypedArray())

        // Generate public key
        val publicKey = makePublicKey(
            seedMask = seed,
            roots = roots.map { iterateHash(chainLength, it, bitmask, 0) }.toTypedArray(),
            checksum = checksum.map { iterateHash(chainLength, it, bitmask, 0) }.toTypedArray())

        return Pair(publicKey, privateKey)
    }

    /**
     * Produce message signature
     */
    fun sign(msg: ByteArray, key: PrivateKey): Signature {
        val digest = digester(msg)
        val bitmask = Random(key.seedMask).genHashSeeds(chainLength, N)
        val input = BitSet.valueOf(digest)

        // Calculate images of key hash roots
        var offset = 0
        var checksum = 0L
        val sigroots = ArrayList<ByteSequence> ()

        for (root in key.roots) {
            val value = input.readLong(offset, offset + W)
            sigroots.add(iterateHash(value.toInt(), root, bitmask, 0))
            offset += W
            checksum += value
        }

        // Generate checksum
        checksum = maxChecksum - checksum

        val sigchecksum = ArrayList<ByteSequence> ()

        for (root in key.checksum) {
            val value = checksum and ((1L shl W) - 1)
            sigchecksum.add(iterateHash(value.toInt(), root, bitmask, 0))
            checksum = checksum ushr W
        }

        return Signature(
                seedMask = key.seedMask,
                roots = sigroots.toTypedArray(),
                checksum = sigchecksum.toTypedArray())
    }

    /**
     * Verify signature for message
     */
    fun verify(msg: ByteArray, key: PublicKey, sig: Signature) {
        if(image(msg, sig) != key) {
            throw SignatureException("Failed verification")
        }
    }

    /**
     * Generate expected public key from message and signature
     */
    fun image(msg: ByteArray, signature: Signature): PublicKey {
        val digest = digester(msg)
        val bitmask = Random(signature.seedMask).genHashSeeds(chainLength, N)
        val input = BitSet.valueOf(digest)
        val images = ArrayList<ByteSequence> ()
        val imageChecksum = ArrayList<ByteSequence> ()

        var offset = 0
        var checksum = 0
        for (root in signature.roots) {
            val value = input.readLong(offset, offset + W).toInt()
            images.add(iterateHash(chainLength - value, root, bitmask, value))
            offset += W
            checksum += value
        }

        checksum = maxChecksum - checksum

        for (root in signature.checksum) {
            val value = checksum and ((1 shl W) - 1)
            imageChecksum.add(iterateHash(chainLength - value, root, bitmask, value))
            checksum = checksum ushr W
        }

        return makePublicKey(
                seedMask = signature.seedMask,
                roots = images.toTypedArray(),
                checksum = imageChecksum.toTypedArray())
    }

    private fun iterateHash(iterations: Int,
                            root: ByteSequence,
                            mask: Array<ByteArray>,
                            maskOffset: Int): ByteSequence {
        var result = root.bytes.clone()
        for (id in 0 until iterations) {
            for (j in result.indices) {
                result[j] = result[j] xor mask[id + maskOffset][j]
            }
            result = H(result)
        }
        return ByteSequence(result)
    }

    private fun makePublicKey(seedMask: Long,
                              roots: Array<ByteSequence>,
                              checksum: Array<ByteSequence>) : PublicKey {
        
        val data = PrivateKey(
                seedMask = seedMask,
                roots = roots,
                checksum = checksum).encoded

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