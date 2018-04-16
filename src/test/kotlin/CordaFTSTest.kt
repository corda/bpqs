import net.corda.research.pq.SHA256
import net.corda.research.pq.SHA384
import net.corda.research.pq.cordafts.CordaFTS
import net.corda.research.pq.wots.WOTS
import org.junit.Test
import java.security.SignatureException
import kotlin.test.assertFailsWith

class CordaFTSTest {

    @Test
    fun `validate signature` () {
        val wots = WOTS(
                W = 6,
                digester = SHA256(),
                H = SHA256(),
                rootHash = SHA384())

        val cfts = CordaFTS(wots)
        val keyPair = cfts.generateKeyPair(5)
        val privKey = keyPair.private
        val pubKey = keyPair.public
        val msg = "abracadabra".toByteArray()
        val sig = cfts.sign(msg, privKey, 0)
        cfts.verify(msg, pubKey, sig)

        val fallbackSig = cfts.sign(msg, privKey, 1)
        cfts.verify(msg, pubKey, fallbackSig)

        val fallbackSig2 = cfts.sign(msg, privKey, 4)
        cfts.verify(msg, pubKey, fallbackSig2)

        val msg2 = "babba".toByteArray()
        assertFailsWith(SignatureException::class) {
            cfts.verify(msg2, pubKey, sig)
        }

        val keyPair2 = cfts.generateKeyPair(5)
        val privKey2 = keyPair2.private as net.corda.research.pq.cordafts.PrivateKey
        val sig2 = cfts.sign(msg, privKey2, 0)
        assertFailsWith(SignatureException::class) {
            cfts.verify(msg, pubKey, sig2)
        }
    }

}