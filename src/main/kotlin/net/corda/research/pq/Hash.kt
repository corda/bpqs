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

class SHA256Debug : Hash {

    var counter: Int = 0

    private val impl = MessageDigest.getInstance("SHA-256")

    override fun invoke(msg: ByteArray): ByteArray {
        ++counter
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

class SHA384Debug : Hash {

    var counter = 0

    private val impl = MessageDigest.getInstance("SHA-384")

    override fun invoke(msg: ByteArray): ByteArray {
        ++counter
        return impl.digest(msg)
    }

    override val outputByteSize = 48
}

class SHA512 : Hash {

    private val impl = MessageDigest.getInstance("SHA-512")

    override fun invoke(msg: ByteArray): ByteArray {
        return impl.digest(msg)
    }

    override val outputByteSize = 64
}
