package net.rec0de.alloyparser

import net.rec0de.alloyparser.bitmage.ByteOrder
import net.rec0de.alloyparser.bitmage.fromBytes
import net.rec0de.alloyparser.bitmage.hex
import java.nio.ByteBuffer
import java.util.*

object Utils {
    fun uuidFromBytes(bytes: ByteArray): UUID {
        if(bytes.size != 16)
            throw Exception("Trying to build UUID from ${bytes.size} bytes, expected 16")

        val a = bytes.sliceArray(0 until 4).hex()
        val b = bytes.sliceArray(4 until 6).hex()
        val c = bytes.sliceArray(6 until 8).hex()
        val d = bytes.sliceArray(8 until 10).hex()
        val e = bytes.sliceArray(10 until 16).hex()
        return UUID.fromString("$a-$b-$c-$d-$e")
    }

    fun uuidToBytes(uuid: UUID): ByteArray {
        val buf = ByteBuffer.allocate(16)
        buf.putLong(uuid.mostSignificantBits)
        buf.putLong(uuid.leastSignificantBits)
        return buf.array()
    }

    fun dateFromAppleTimestamp(timestamp: Double): Date {
        // NSDate timestamps encode time as seconds since Jan 01 2001 with millisecond precision as doubles
        return Date((timestamp*1000).toLong() + 978307200000)
    }
}


open class ParseCompanion {
    protected var parseOffset = 0

    protected fun readBytes(bytes: ByteArray, length: Int): ByteArray {
        val sliced = bytes.sliceArray(parseOffset until parseOffset + length)
        parseOffset += length
        return sliced
    }

    protected fun readLengthPrefixedString(bytes: ByteArray, sizePrefixLen: Int): String? {
        val len = readInt(bytes, sizePrefixLen)
        return if(len == 0) null else readString(bytes, len)
    }

    protected fun readString(bytes: ByteArray, size: Int): String {
        val str = bytes.sliceArray(parseOffset until parseOffset +size).toString(Charsets.UTF_8)
        parseOffset += size
        return str
    }

    protected fun readInt(bytes: ByteArray, size: Int): Int {
        val int = UInt.fromBytes(bytes.sliceArray(parseOffset until parseOffset +size), ByteOrder.BIG).toInt()
        parseOffset += size
        return int
    }
}


fun Date.toAppleTimestamp(): Double {
    // NSDate timestamps encode time as seconds since Jan 01 2001 with millisecond precision as doubles
    val canonicalTimestamp = this.time
    return (canonicalTimestamp - 978307200000).toDouble() / 1000
}

fun Date.toCanonicalTimestamp(): Double {
    return this.time.toDouble() / 1000
}