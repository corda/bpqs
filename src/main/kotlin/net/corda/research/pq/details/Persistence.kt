package net.corda.research.pq.details

import java.nio.ByteBuffer
import java.util.*

fun ByteBuffer.putHashSeeds(input: Array<ByteSequence>): ByteBuffer {
    putInt(input.size)
    for (item in input) {
        put(item.bytes)
    }
    return this
}

fun ByteBuffer.getHashSeeds(seedSize: Int): Array<ByteSequence> {
    val len = getInt()
    val result = Array<ByteSequence>(len) { ByteSequence(seedSize, 0) }
    for (entry in result) {
        get(entry.bytes)
    }
    return result
}

fun ByteBuffer.compacted(): ByteArray {
    return Arrays.copyOfRange(array(), 0, position())
}

