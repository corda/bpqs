import net.corda.research.pq.SHA256
import net.corda.research.pq.SHA384
import net.corda.research.pq.wots.WOTS
import org.junit.Test
import java.security.SignatureException
import kotlin.test.*

class WOTSTest {
    @Test
    fun `verify public-private key consistence`() {
        val wots = WOTS(
                W = 6,
                digester = SHA256(),
                H = SHA256(),
                rootHash = SHA384())

        val (pubKey, privKey) = wots.generateKeyPair()
        val msg = "blah blah".toByteArray()

        val sig = wots.sign(msg, privKey)

        wots.verify(msg, pubKey, sig)

        val msg2 = "babba".toByteArray()
        assertFailsWith(SignatureException::class) {
            wots.verify(msg2, pubKey, sig)
        }

        val (_, privKey2) = wots.generateKeyPair()
        val sig2 = wots.sign(msg, privKey2)
        assertFailsWith(SignatureException::class) {
            wots.verify(msg, pubKey, sig2)
        }
    }
}