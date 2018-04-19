package net.corda.research.pq.wots
import net.corda.research.pq.details.*
import java.nio.ByteBuffer
import java.util.*


data class PrivateKey(
        val seedMask: Long, //< Seed used for bit mask generation
        val roots: Array<ByteSequence>, //< private key hash roots
        val checksum: Array<ByteSequence> //< checksum elements
): java.security.PrivateKey {

    // Private key and signature share the same representation
    private val signature = Signature(seedMask, roots, checksum)
    private val _encoded by lazy { serialize(this) }

    constructor(repr: Signature) : this(repr.seedMask, repr.roots, repr.checksum)

    override fun getAlgorithm(): String = "WOTS"

    override fun getFormat(): String? = null

    override fun getEncoded() = _encoded

    override fun equals(other: Any?) =
            (signature == (other as? PrivateKey)?.signature)

    val estimatedSize: Int get() = signature.estimatedSize

    fun put(output: ByteBuffer) = signature.put(output)

    companion object {

        fun serialize(key: PrivateKey) = Signature.serialize(key.signature)

        fun get(buffer: ByteBuffer, hashSize: Int) = PrivateKey(Signature.get(buffer, hashSize))

        fun deserialize(bytes: ByteArray, hashSize: Int): PrivateKey {
            val reader = ByteBuffer.wrap(bytes)
            return get(reader, hashSize)
        }
    }
}
