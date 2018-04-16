package net.corda.research.pq.cordafts

import net.corda.research.pq.LinearMerkleTree
import net.corda.research.pq.SHA384
import net.corda.research.pq.cordafts.Signature.Companion.serialize
import net.corda.research.pq.details.ByteSequence
import net.corda.research.pq.wots.WOTS
import java.security.KeyPair
import java.security.SignatureException

class CordaFTS(val wots: WOTS) {

    fun sign(msg: ByteArray, privateKey: java.security.PrivateKey, state: Int = 0): ByteArray {
        val key = privateKey as PrivateKey
        val (wotsPubKey, wotsPrivKey) = key.keys[state]
        val wotsSignature = wots.sign(msg, wotsPrivKey)
        val certificate = key.pubKeysTree.certify(wotsPubKey)
        return Signature.serialize(
                Signature(wotsSignature,
                        certificate.siblingHash,
                        certificate.path))
    }

    fun verify(msg: ByteArray, publicKey: java.security.PublicKey, signatureData: ByteArray) {
        val key = publicKey as PublicKey
        val signature = Signature.deserialize(signatureData, wots.N)
        val wotsPubKey = wots.image(msg, signature.wotsSignature)
        val proof = LinearMerkleTree.MembershipCertificate(
                hashedValue = wotsPubKey.data,
                path = signature.authPath,
                siblingHash = signature.siblingHash)
        if (!LinearMerkleTree.check(ByteSequence(key.encoded), proof)) {
            throw SignatureException("Failed verification")
        }
    }

    fun generateKeyPair(maxRetry: Int): KeyPair {
        val wotsKeyPairs = Array(1 + maxRetry) { wots.generateKeyPair() }
        val privateKey = PrivateKey(wotsKeyPairs.toList())
        val publicKey = PublicKey(privateKey.pubKeysTree.root)
        return KeyPair(publicKey, privateKey)
    }

    companion object {
        @JvmStatic
        val CFTS6_SHA384 = CordaFTS(WOTS(6, SHA384(), SHA384(), SHA384()))

        @JvmStatic
        val CFTS1_SHA384 = CordaFTS(WOTS(1, SHA384(), SHA384(), SHA384()))
    }
}

