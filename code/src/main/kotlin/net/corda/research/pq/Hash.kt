package net.corda.research.pq

import java.security.MessageDigest

interface Hash {

    operator fun invoke(msg: ByteArray): ByteArray

    val outputByteSize: Int
}

class SHA256 : Hash {

    private val impl = MessageDigest.getInstance("SHA-256")

    override fun invoke(msg: ByteArray): ByteArray {
        return impl.digest(msg)
    }

    override val outputByteSize = 32
}

class SHA384 : Hash {

    private val impl = MessageDigest.getInstance("SHA-384")

    override fun invoke(msg: ByteArray): ByteArray {
        return impl.digest(msg)
    }

    override val outputByteSize = 48
}