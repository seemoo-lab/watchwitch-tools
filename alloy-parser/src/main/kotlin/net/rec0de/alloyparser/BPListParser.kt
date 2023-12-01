package net.rec0de.alloyparser
import java.math.BigInteger
import java.nio.ByteBuffer
import java.util.*
import kotlin.math.ceil
import kotlin.math.log2

// based on https://medium.com/@karaiskc/understanding-apples-binary-property-list-format-281e6da00dbd
class BPListParser {
    private val objectMap = mutableMapOf<Int, CodableBPListObject>()
    private var objectRefSize = 0
    private var offsetTableOffsetSize = 0
    private var offsetTable = byteArrayOf()

    companion object {
        fun bufferIsBPList(buf: ByteArray): Boolean {
            return buf.size > 8 && buf.sliceArray(0 until 8).decodeToString() == "bplist00"
        }
    }

    /**
     * Parses bytes representing a bplist and returns the first contained object (usually a container type containing all the other objects)
     */
    @Synchronized
    fun parse(bytes: ByteArray): BPListObject {
        val rootObject = parseCodable(bytes)
        return if(KeyedArchiveDecoder.isKeyedArchive(rootObject))
            KeyedArchiveDecoder.decode(rootObject as BPDict)
        else
            rootObject
    }

    @Synchronized
    fun parseCodable(bytes: ByteArray): CodableBPListObject {
        objectMap.clear()

        val header = bytes.sliceArray(0 until 8)
        if (header.decodeToString() != "bplist00")
            throw Exception("Expected bplist header 'bplist00' in bytes ${bytes.hex()}")

        val trailer = bytes.fromIndex(bytes.size - 32)
        offsetTableOffsetSize = trailer[6].toInt()
        objectRefSize = trailer[7].toInt()
        val numObjects = ULong.fromBytesBig(trailer.sliceArray(8 until 16)).toInt()
        val topObjectOffset = ULong.fromBytesBig(trailer.sliceArray(16 until 24)).toInt()
        val offsetTableStart = ULong.fromBytesBig(trailer.sliceArray(24 until 32)).toInt()

        offsetTable =
            bytes.sliceArray(offsetTableStart until (offsetTableStart + numObjects * offsetTableOffsetSize))

        return readObjectFromOffsetTableEntry(bytes, topObjectOffset)
    }

    private fun readObjectFromOffsetTableEntry(bytes: ByteArray, index: Int): CodableBPListObject {
        val offset = UInt.fromBytesBig(offsetTable.sliceArray(index*offsetTableOffsetSize until (index+1)*offsetTableOffsetSize)).toInt()
        return readObjectFromOffset(bytes, offset)
    }

    private fun readObjectFromOffset(bytes: ByteArray, offset: Int): CodableBPListObject {
        // check cache
        if(objectMap.containsKey(offset))
            return objectMap[offset]!!

        // objects start with a one byte type descriptor
        val objectByte = bytes[offset].toUByte().toInt()
        // for some objects, the lower four bits carry length info
        val lengthBits = objectByte and 0x0f

        val parsed = when(objectByte) {
            0x00 -> BPNull
            0x08 -> BPFalse
            0x09 -> BPTrue
            0x0f -> BPFill
            // Int
            in 0x10 until 0x20 -> {
                // length bits encode int byte size as 2^n
                val byteLen = 1 shl lengthBits
                BPInt(BigInteger(bytes.sliceArray(offset+1 until offset+1+byteLen)))
            }
            // Real
            in 0x20 until 0x30 -> {
                // length bits encode real byte size as 2^n
                val byteLen = 1 shl lengthBits
                val value = when(byteLen) {
                    4 -> {
                        val buf = ByteBuffer.allocate(4)
                        buf.put(bytes.sliceArray(offset+1 until offset+1+4))
                        buf.getFloat(0).toDouble()
                    }
                    8 -> {
                        val buf = ByteBuffer.allocate(8)
                        buf.put(bytes.sliceArray(offset+1 until offset+1+8))
                        buf.getDouble(0)
                    }
                    else -> throw Exception("Got unexpected byte length for real: $byteLen in ${bytes.hex()}")
                }
                BPReal(value)
            }
            // Date, always 8 bytes long
            0x33 -> {
                val buf = ByteBuffer.allocate(8)
                buf.put(bytes.sliceArray(offset+1 until offset+1+8))
                val timestamp = buf.getDouble(0)
                BPDate(timestamp)
            }
            // Data
            in 0x40 until 0x50 -> {
                // length bits encode byte count, if all ones additional length integer follows
                val tmp = getFillAwareLengthAndOffset(bytes, offset)
                val byteLen = tmp.first
                val effectiveOffset = tmp.second

                val data = bytes.sliceArray(effectiveOffset until effectiveOffset+byteLen)

                // decode nested bplists
                return if(bufferIsBPList(data))
                    BPListParser().parseCodable(data)
                else
                    BPData(data)
            }
            // ASCII string
            in 0x50 until 0x60 -> {
                // length bits encode character count, if all ones additional length integer follows
                val tmp = getFillAwareLengthAndOffset(bytes, offset)
                val charLen = tmp.first
                val effectiveOffset = tmp.second
                // ascii encodes at one char per byte, we can use default UTF8 decoding as ascii is cross compatible with everything
                val string = bytes.decodeToString(effectiveOffset, effectiveOffset+charLen)
                BPAsciiString(string)
            }
            // Unicode string
            in 0x60 until 0x70 -> {
                // length bits encode character count, if all ones additional length integer follows
                val tmp = getFillAwareLengthAndOffset(bytes, offset)
                val charLen = tmp.first
                val effectiveOffset = tmp.second
                // this is UTF16, encodes at two bytes per char
                val stringBytes = bytes.sliceArray(effectiveOffset until effectiveOffset+charLen*2)
                val string = Charsets.UTF_16BE.decode(ByteBuffer.wrap(stringBytes)).toString()
                BPUnicodeString(string)
            }
            // UID, byte length is lengthBits+1
            in 0x80 until 0x90 -> BPUid(bytes.sliceArray(offset+1 until offset+2+lengthBits))
            // Array
            in 0xa0 until 0xb0 -> {
                val tmp = getFillAwareLengthAndOffset(bytes, offset)
                val entries = tmp.first
                val effectiveOffset = tmp.second

                val values = (0 until entries).map {i ->
                    val objectIndex = UInt.fromBytesBig(bytes.sliceArray(effectiveOffset+i*objectRefSize until effectiveOffset+(i+1)*objectRefSize)).toInt()
                    readObjectFromOffsetTableEntry(bytes, objectIndex)
                }

                BPArray(values)
            }
            // Set
            in 0xc0 until 0xd0 -> {
                val tmp = getFillAwareLengthAndOffset(bytes, offset)
                val entries = tmp.first
                val effectiveOffset = tmp.second

                val values = (0 until entries).map {i ->
                    val objectIndex = UInt.fromBytesBig(bytes.sliceArray(effectiveOffset+i*objectRefSize until effectiveOffset+(i+1)*objectRefSize)).toInt()
                    readObjectFromOffsetTableEntry(bytes, objectIndex)
                }

                BPSet(entries, values)
            }
            in 0xd0 until 0xf0 -> {
                val tmp = getFillAwareLengthAndOffset(bytes, offset)
                val entries = tmp.first
                var effectiveOffset = tmp.second

                val keys = (0 until entries).map {i ->
                    val keyIndex = UInt.fromBytesBig(bytes.sliceArray(effectiveOffset+i*objectRefSize until effectiveOffset+(i+1)*objectRefSize)).toInt()
                    readObjectFromOffsetTableEntry(bytes, keyIndex)
                }

                effectiveOffset += entries * objectRefSize

                val values = (0 until entries).map {i ->
                    val valueIndex = UInt.fromBytesBig(bytes.sliceArray(effectiveOffset+i*objectRefSize until effectiveOffset+(i+1)*objectRefSize)).toInt()
                    readObjectFromOffsetTableEntry(bytes, valueIndex)

                }

                BPDict(keys.zip(values).toMap())
            }
            else -> throw Exception("Unknown object type byte 0b${objectByte.toString(2)}")
        }

        objectMap[offset] = parsed
        return parsed
    }


    private fun getFillAwareLengthAndOffset(bytes: ByteArray, offset: Int): Pair<Int, Int> {
        val lengthBits = bytes[offset].toInt() and 0x0f
        if(lengthBits < 0x0f)
            return Pair(lengthBits, offset+1)

        val sizeFieldSize = 1 shl (bytes[offset+1].toInt() and 0x0f) // size field is 2^n bytes
        val size = ULong.fromBytesBig(bytes.sliceArray(offset+2 until offset+2+sizeFieldSize)).toInt() // let's just hope they never get into long territory

        return Pair(size, offset+2+sizeFieldSize)
    }
}

abstract class BPListObject

abstract class CodableBPListObject : BPListObject() {
    abstract fun collectObjects(): Set<CodableBPListObject>
    abstract fun renderWithObjectMapping(mapping: Map<CodableBPListObject, Int>, refSize: Int): ByteArray

    fun renderAsTopLevelObject(): ByteArray {
        val header = "bplist00".encodeToByteArray()

        val objects = collectObjects()
        val refSize = ceil(log2(objects.size.toDouble()) / 8).toInt()
        val objMap = objects.mapIndexed { index, obj -> Pair(obj, index) }.toMap()

        val renderedObjects = objects.map { it.renderWithObjectMapping(objMap, refSize) }
        val objectTable = renderedObjects.fold(byteArrayOf()){ gathered, obj -> gathered + obj}

        val offsets = mutableListOf<Int>()
        var cumulativeOffset = header.size // offsets are from beginning of file, not end of header
        renderedObjects.indices.forEach { i ->
            offsets.add(cumulativeOffset)
            cumulativeOffset += renderedObjects[i].size
        }

        // last offset will be the largest, determine offset table offset size to fit it
        val offsetSize = ceil(log2(offsets.last().toDouble()) / 8).toInt()

        // render offsets to bytes and cut to appropriate size
        val offsetTable = offsets.map { it.toBytesBig().fromIndex(4-offsetSize) }.fold(byteArrayOf()) {
                gathered, offset -> gathered + offset
        }

        val trailer = ByteBuffer.allocate(32)
        trailer.putInt(0) // reserved
        trailer.put(0) // reserved
        trailer.put(0) // sort version? idk
        trailer.put(offsetSize.toByte())
        trailer.put(refSize.toByte())
        trailer.putLong(objects.size.toLong()) // num objects
        trailer.putLong(objMap[this]!!.toLong()) // top object offset
        trailer.putLong((header.size + objectTable.size).toLong()) // offset table start

        return header + objectTable + offsetTable + trailer.array()
    }
}

// BPList objects that we can immediately render to bytes without referring to the object table etc
abstract class BPListImmediateObject : CodableBPListObject() {
    abstract fun renderToBytes(): ByteArray
    override fun collectObjects() = setOf(this)
    override fun renderWithObjectMapping(mapping: Map<CodableBPListObject, Int>, refSize: Int) = renderToBytes()
}

object BPNull : BPListImmediateObject() {
    override fun toString() = "null"
    override fun renderToBytes() = byteArrayOf(0x00)
}
object BPTrue : BPListImmediateObject() {
    override fun toString() = "true"
    override fun renderToBytes() = byteArrayOf(0x09)
}
object BPFalse : BPListImmediateObject() {
    override fun toString() = "false"
    override fun renderToBytes() = byteArrayOf(0x08)
}
object BPFill : BPListImmediateObject() {
    override fun toString() = "BPFill"
    override fun renderToBytes() = byteArrayOf(0x0f)
}
data class BPInt(val value: BigInteger): BPListImmediateObject() {
    override fun toString() = value.toString()

    override fun renderToBytes(): ByteArray {
        val bytes = value.toByteArray()
        val lengthBits = (ceil(log2(bytes.size.toDouble())).toInt() and 0x0f)
        val markerByte = (0x10 or lengthBits).toByte()

        val encodedLen = 1 shl lengthBits
        val padding = ByteArray(encodedLen - bytes.size){ 0 }

        return byteArrayOf(markerByte) + padding + bytes
    }
}
data class BPReal(val value: Double): BPListImmediateObject() {
    override fun renderToBytes(): ByteArray {
        val markerByte = 0x23 // 0x20 for real, 0x03 for 2^3 = 8 bytes
        val buf = ByteBuffer.allocate(9)
        buf.put(markerByte.toByte())
        buf.putDouble(value)
        return buf.array()
    }
}
data class BPDate(val timestamp: Double) : BPListImmediateObject() {
    override fun toString() = "BPDate($timestamp)"

    fun asDate(): Date = Utils.dateFromAppleTimestamp(timestamp)

    override fun renderToBytes(): ByteArray {
        val markerByte = 0x33
        val buf = ByteBuffer.allocate(9)
        buf.put(markerByte.toByte())
        buf.putDouble(timestamp)
        return buf.array()
    }
}
class BPData(val value: ByteArray) : BPListImmediateObject() {
    override fun toString() = "BPData(${value.hex()})"

    override fun renderToBytes(): ByteArray {
        val lengthBits = if(value.size > 14) 0x0F else value.size
        val markerByte = (0x40 or lengthBits).toByte()

        return if(value.size > 14) {
            byteArrayOf(markerByte) + BPInt(value.size.toBigInteger()).renderToBytes() + value
        } else {
            byteArrayOf(markerByte) + value
        }
    }
}

abstract class BPString : BPListImmediateObject() {
    abstract val value: String
}
data class BPAsciiString(override val value: String) : BPString() {
    override fun toString() = "\"$value\""

    override fun renderToBytes(): ByteArray {
        val charCount = value.length
        val bytes = Charsets.US_ASCII.encode(value).array()

        val lengthBits = if(charCount > 14) 0x0F else charCount
        val markerByte = (0x50 or lengthBits).toByte()

        return if(charCount > 14) {
            byteArrayOf(markerByte) + BPInt(charCount.toBigInteger()).renderToBytes() + bytes
        } else {
            byteArrayOf(markerByte) + bytes
        }
    }
}
data class BPUnicodeString(override val value: String) : BPString() {
    override fun toString() = "\"$value\""

    override fun renderToBytes(): ByteArray {
        val charCount = value.length
        val bytes = Charsets.UTF_16BE.encode(value).array()

        val lengthBits = if(charCount > 14) 0x0F else charCount
        val markerByte = (0x60 or lengthBits).toByte()

        return if(charCount > 14) {
            byteArrayOf(markerByte) + BPInt(charCount.toBigInteger()).renderToBytes() + bytes
        } else {
            byteArrayOf(markerByte) + bytes
        }
    }
}
class BPUid(val value: ByteArray) : BPListImmediateObject() {
    companion object {
        fun fromInt(value: Int): BPUid {
            val bytes = value.toBytesBig()
            val firstNonZero = bytes.indexOfFirst { it.toInt() != 0 }
            return BPUid(bytes.fromIndex(firstNonZero))
        }
    }

    override fun toString() = "BPUid(${value.hex()})"

    override fun renderToBytes(): ByteArray {
        val lengthBits = (value.size - 1) and 0x0f
        val markerByte = (0x80 or lengthBits).toByte()
        return byteArrayOf(markerByte) + value
    }
}
data class BPArray(val values: List<CodableBPListObject>) : CodableBPListObject() {
    override fun collectObjects() = values.flatMap { it.collectObjects() }.toSet() + this

    override fun renderWithObjectMapping(mapping: Map<CodableBPListObject, Int>, refSize: Int): ByteArray {
        val lengthBits = if(values.size > 14) 0x0F else values.size
        val markerByte = (0xa0 or lengthBits).toByte()
        var result = byteArrayOf(markerByte)

        if(values.size > 14) {
            result += BPInt(values.size.toBigInteger()).renderToBytes()
        }

        // tricky, let me explain: we map integer object references to 4-byte byte arrays.
        // since we chose the reference size to accommodate all the references and the byte arrays
        // are in big endian order, the first 4-refSize bytes will always be zero
        // and stripping them gets us to the desired reference byte size
        val references = values.map { mapping[it]!!.toBytesBig().fromIndex(4-refSize) }

        // start with the marker and length, then append all the references
        val res = references.fold(result){ gathered, reference -> gathered + reference}
        return res
    }

    override fun toString() = "[${values.joinToString(", ")}]"
}
data class BPSet(val entries: Int, val values: List<CodableBPListObject>) : CodableBPListObject() {
    override fun collectObjects() = values.flatMap { it.collectObjects() }.toSet() + this

    // see BPArray
    override fun renderWithObjectMapping(mapping: Map<CodableBPListObject, Int>, refSize: Int): ByteArray {
        val lengthBits = if(values.size > 14) 0x0F else values.size
        val markerByte = (0xc0 or lengthBits).toByte()
        var result = byteArrayOf(markerByte)

        if(values.size > 14) {
            result += BPInt(values.size.toBigInteger()).renderToBytes()
        }

        val references = values.map { mapping[it]!!.toBytesBig().fromIndex(4-refSize) }

        // start with the marker and length, then append all the references
        return references.fold(result){ gathered, reference -> gathered + reference}
    }

    override fun toString() = "<${values.joinToString(", ")}>"
}
data class BPDict(val values: Map<CodableBPListObject, CodableBPListObject>) : CodableBPListObject() {
    override fun collectObjects(): Set<CodableBPListObject> {
        val keyObjs = values.keys.flatMap { it.collectObjects() }.toSet()
        val valueObjs = values.values.flatMap { it.collectObjects() }.toSet()
        return keyObjs + valueObjs + this
    }

    override fun renderWithObjectMapping(
        mapping: Map<CodableBPListObject, Int>,
        refSize: Int
    ): ByteArray {
        val lengthBits = if (values.size > 14) 0x0F else values.size
        val markerByte = (0xd0 or lengthBits).toByte()
        var result = byteArrayOf(markerByte)

        if (values.size > 14) {
            result += BPInt(values.size.toBigInteger()).renderToBytes()
        }

        val references = values.toList().map {
            Pair(
                mapping[it.first]!!.toBytesBig().fromIndex(4 - refSize),
                mapping[it.second]!!.toBytesBig().fromIndex(4 - refSize)
            )
        }

        val keyRefs = references.map { it.first }
            .fold(byteArrayOf()) { gathered, reference -> gathered + reference }
        val objRefs = references.map { it.second }
            .fold(byteArrayOf()) { gathered, reference -> gathered + reference }

        // encode marker, then all key refs, then all value refs
        return result + keyRefs + objRefs
    }

    override fun toString() = values.toString()
}

data class NSArray(val values: List<BPListObject>): BPListObject(), KeyedArchiveCodable {
    override fun toString() = values.toString()
}

data class NSDict(val values: Map<BPListObject, BPListObject>) : BPListObject(), KeyedArchiveCodable {
    override fun toString() = values.toString()
}

data class NSDate(val value: Date) : BPListObject(), KeyedArchiveCodable {
    override fun toString() = value.toString()
}

data class NSUUID(val value: ByteArray) : BPListObject(), KeyedArchiveCodable {
    override fun toString() = Utils.uuidFromBytes(value).toString()
}