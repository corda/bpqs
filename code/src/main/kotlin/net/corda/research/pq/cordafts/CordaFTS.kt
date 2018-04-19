package net.corda.research.pq.cordafts

import net.corda.research.pq.LinearMerkleTree
import net.corda.research.pq.details.ByteSequence
import net.corda.research.pq.wots.WOTS
import java.security.SignatureException

class CordaFTS(val wots: WOTS) {

    fun sign(msg: ByteArray, key: PrivateKey, state: Int = 0): Signature {
        val (wotsPubKey, wotsPrivKey) = key.keys[state]
        val wotsSignature = wots.sign(msg, wotsPrivKey)
        val certificate = key.pubKeysTree.certify(wotsPubKey)
        return Signature(
                wotsSignature,
                certificate.siblingHash,
                certificate.path)
    }

    fun verify(msg: ByteArray, key: PublicKey, signature: Signature) {
        val wotsPubKey = wots.image(msg, signature.wotsSignature)
        val proof = LinearMerkleTree.MembershipCertificate(
                hashedValue = ByteSequence(wotsPubKey.encoded),
                path = signature.authPath,
                siblingHash = signature.siblingHash)
        if (!LinearMerkleTree.check(ByteSequence(key.encoded), proof)) {
            throw SignatureException("Failed verification")
        }
    }

    fun generateKeyPair(maxRetry: Int) : Pair<PublicKey, PrivateKey> {
        val wotsKeyPairs = Array(1 + maxRetry) { wots.generateKeyPair() }
        val privateKey = PrivateKey(wotsKeyPairs.toList())
        val publicKey = PublicKey(privateKey.pubKeysTree.root)
        return Pair(publicKey, privateKey)
    }
}

