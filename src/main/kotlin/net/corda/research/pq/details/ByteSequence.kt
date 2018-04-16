package net.corda.research.pq.details

import java.util.*

/**
 * Extend bytes[] with hash and equality operator
 */
class ByteSequence {

    val bytes: ByteArray

    constructor(bytes: ByteArray) {
        this.bytes = bytes.clone()
    }

    constructor(size: Int = 0, value: Byte = 0) {
        this.bytes = ByteArray(size) {value}
    }

    override fun hashCode() = Arrays.hashCode(bytes)

    override fun equals(other: Any?): Boolean {
        return when(other) {
            is ByteSequence -> Arrays.equals(bytes, other.bytes)
            else -> false
        }
    }
}