import com.sun.xml.internal.messaging.saaj.util.ByteOutputStream
import net.corda.research.pq.details.ByteSequence
import net.corda.research.pq.wots.PrivateKey
import net.corda.research.pq.wots.Signature
import org.junit.Test

class WOTSPersistenceTest {

    @Test
    fun `WOTS key persistence`() {
        val key = PrivateKey(
                roots = arrayOf(
                        ByteSequence(byteArrayOf(5, 10, 7)),
                        ByteSequence(byteArrayOf(3, 4, 5))),
                checksum = arrayOf(
                        ByteSequence(byteArrayOf(1, 2, 3)),
                        ByteSequence(byteArrayOf(4, 5, 6))))
        val data = PrivateKey.serialize(key)
        val other = PrivateKey.deserialize(data, 3)
        assert(other == key)
    }

    @Test
    fun `WOTS signature persistence` () {
        val sig = Signature(
                roots = arrayOf(
                        ByteSequence(byteArrayOf(5, 10, 7)),
                        ByteSequence(byteArrayOf(3, 4, 5))),
                checksum = arrayOf(
                        ByteSequence(byteArrayOf(1, 2, 3)),
                        ByteSequence(byteArrayOf(4, 5, 6))))
        val data = Signature.serialize(sig)
        val other = Signature.deserialize(data, 3)
        assert(other == sig)
    }
}