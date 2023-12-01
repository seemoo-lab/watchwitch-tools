package net.rec0de.alloyparser

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
        val int = UInt.fromBytesBig(bytes.sliceArray(parseOffset until parseOffset +size)).toInt()
        parseOffset += size
        return int
    }
}

fun ByteArray.hex() = joinToString("") { "%02x".format(it) }
fun ByteArray.fromIndex(i: Int) = sliceArray(i until size)
fun String.hexBytes(): ByteArray {
    check(length % 2 == 0) { "Must have an even length" }
    return chunked(2)
        .map { it.toInt(16).toByte() }
        .toByteArray()
}

fun UInt.Companion.fromBytesSmall(bytes: ByteArray): UInt {
    return bytes.mapIndexed { index, byte ->  byte.toUByte().toUInt() shl (index * 8)}.sum()
}
fun UInt.Companion.fromBytesBig(bytes: ByteArray): UInt {
    return bytes.reversed().mapIndexed { index, byte ->  byte.toUByte().toUInt() shl (index * 8)}.sum()
}

fun ULong.Companion.fromBytesBig(bytes: ByteArray): ULong {
    return bytes.reversed().mapIndexed { index, byte ->  byte.toUByte().toULong() shl (index * 8)}.sum()
}

fun ULong.Companion.fromBytesLittle(bytes: ByteArray): ULong {
    return bytes.mapIndexed { index, byte ->  byte.toUByte().toULong() shl (index * 8)}.sum()
}

fun Int.toBytesBig(): ByteArray {
    return byteArrayOf((this shr 24).toByte(), (this shr 16).toByte(), (this shr 8).toByte(), (this shr 0).toByte())
}

fun UInt.Companion.fromBytesLittle(bytes: ByteArray): UInt {
    return bytes.mapIndexed { index, byte ->  byte.toUByte().toUInt() shl (index * 8)}.sum()
}

fun Long.doubleFromLongBytes(): Double {
    val b = ByteBuffer.allocate(8)
    b.putLong(this)
    return b.getDouble(0)
}

fun Int.floatFromIntBytes(): Float {
    val b = ByteBuffer.allocate(4)
    b.putInt(this)
    return b.getFloat(0)
}

fun Date.toAppleTimestamp(): Double {
    // NSDate timestamps encode time as seconds since Jan 01 2001 with millisecond precision as doubles
    val canonicalTimestamp = this.time
    return (canonicalTimestamp - 978307200000).toDouble() / 1000
}