import net.corda.research.pq.SHA384
import net.corda.research.pq.details.ByteSequence
import org.junit.Test

private typealias WOTSSignature = net.corda.research.pq.wots.Signature
private typealias CFTSSignature = net.corda.research.pq.cordafts.Signature

class CordaFTSPersistenceTest {

    @Test
    fun `Signature persistence` () {
        val sha384 = SHA384()
        val sig = WOTSSignature(
                roots = arrayOf(
                        ByteSequence(byteArrayOf(5, 10, 7)),
                        ByteSequence(byteArrayOf(3, 4, 5))),
                checksum = arrayOf(
                        ByteSequence(byteArrayOf(1, 2, 3)),
                        ByteSequence(byteArrayOf(4, 5, 6))))

        val cftsSignature = CFTSSignature(
                sig,
                ByteSequence(sha384(byteArrayOf(6, 6, 6))),
                arrayOf(ByteSequence(sha384(byteArrayOf(1, 2, 3))),
                        ByteSequence(sha384(byteArrayOf(3, 4, 5)))))

        val encoding = CFTSSignature.serialize(cftsSignature)
        val deserialized = CFTSSignature.deserialize(encoding, 3)
        require(deserialized == cftsSignature)
    }

}