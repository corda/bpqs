package net.corda.research.pq.cordafts

import net.corda.research.pq.details.ByteSequence

data class PublicKey(val data: ByteSequence): java.security.PublicKey {

    override fun getAlgorithm(): String = "CordaFTS"

    override fun getFormat(): String? = null

    override fun getEncoded() = data.bytes
}
