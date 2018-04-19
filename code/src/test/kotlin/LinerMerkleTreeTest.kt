import net.corda.research.pq.LinearMerkleTree
import net.corda.research.pq.SHA256
import net.corda.research.pq.details.ByteSequence
import org.junit.Test

class LinerMerkleTreeTest {

    @Test
    fun `test membership certificate` () {
        val hash = SHA256()
        val items = arrayOf(
                "pizza".toByteArray(),
                "mozzarella".toByteArray(),
                "mandolino".toByteArray())
        val tree = LinearMerkleTree(items = items, hash = { x: ByteArray -> hash(x) })
        val cert = tree.certify(items[0])
        require(LinearMerkleTree.check(tree.root, cert))
        require(LinearMerkleTree.check(tree.root, tree.certify(items[1])))
        require(LinearMerkleTree.check(tree.root, tree.certify(items[2])))
        require(!LinearMerkleTree.check(tree.root, cert.copy(hashedValue = ByteSequence("caffe".toByteArray()))))
    }
}