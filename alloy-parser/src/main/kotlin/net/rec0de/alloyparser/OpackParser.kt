package net.rec0de.alloyparser
import java.math.BigInteger
import java.nio.ByteBuffer
import java.util.*
import kotlin.math.ceil
import kotlin.math.log2

// OPACK encodes a subset of data that can be encoded in BPLists - we'll just use the existing BPList wrapper classes for now
class OpackParser() : ParseCompanion() {

    fun parseTopLevel(bytes: ByteArray): BPListObject {
        parseOffset = 0
        return parse(bytes)
    }

    @Synchronized
    private fun parse(bytes: ByteArray): BPListObject {
        val typeByte = bytes[parseOffset].toUByte().toUInt()
        //println("parsing type byte: 0x${typeByte.toString(16)}")
        return when(typeByte) {
            0x01u, 0x02u -> parseAsBool(bytes)
            0x05u -> parseAsUUID(bytes)
            0x06u -> parseAsDate(bytes)
            in 0x08u..0x2fu -> parseAsInt(bytes)
            0x30u, 0x31u, 0x32u, 0x33u -> parseAsInt(bytes)
            0x35u, 0x36u -> parseAsFloat(bytes)
            in 0x40u..0x60u -> parseAsString(bytes)
            in 0x61u..0x64u -> parseAsString(bytes)
            in 0x70u..0x90u -> parseAsData(bytes)
            in 0x91u..0x94u -> parseAsData(bytes)
            in 0xd0u..0xdfu -> parseAsArray(bytes)
            in 0xe0u..0xefu -> parseAsDict(bytes)
            else -> throw Exception("Unsupported type 0x${typeByte.toString(16)}")
        }
    }

    private fun parseAsBool(bytes: ByteArray): BPListImmediateObject {
        val byte = readInt(bytes, 1)
        return when (byte) {
            0x01 -> BPTrue
            0x02 -> BPFalse
            else -> throw Exception("Unexpected OPACK boolean ${bytes.hex()}")
        }
    }

    private fun parseAsUUID(bytes: ByteArray): BPData {
        val type = readInt(bytes, 1)
        if(type != 0x05)
            throw Exception("Unexpected OPACK UUID ${bytes.hex()}")
        val uuid = readBytes(bytes, 16)
        return BPData(uuid)
    }

    private fun parseAsDate(bytes: ByteArray): BPDate {
        val type = readInt(bytes, 1)
        if(type != 0x06)
            throw Exception("Unexpected OPACK date ${bytes.hex()}")
        val timestamp = readBytes(bytes, 8)
        return BPDate(ULong.fromBytesBig(timestamp).toLong().doubleFromLongBytes())
    }

    private fun parseAsInt(bytes: ByteArray): BPInt {
        val type = readInt(bytes, 1)

        return when(type) {
            in 0x08..0x2f -> BPInt(BigInteger.valueOf((type - 8).toLong()))
            0x30 -> BPInt(BigInteger.valueOf(readInt(bytes, 1).toLong()))
            0x31 -> BPInt(BigInteger.valueOf(readInt(bytes, 2).toLong()))
            0x32 -> BPInt(BigInteger.valueOf(readInt(bytes, 3).toLong()))
            0x33 -> BPInt(BigInteger.valueOf(readInt(bytes, 4).toLong()))
            else -> throw Exception("Unexpected OPACK int ${bytes.hex()}")
        }
    }

    private fun parseAsFloat(bytes: ByteArray): BPReal {
        val type = readInt(bytes, 1)
        when(type) {
            0x35 -> {
                val b = ByteBuffer.allocate(4)
                b.put(readBytes(bytes, 4))
                return BPReal(b.getFloat(0).toDouble())
            }
            0x36 -> {
                val b = ByteBuffer.allocate(8)
                b.put(readBytes(bytes, 8))
                return BPReal(b.getDouble(0))
            }
            else -> throw Exception("Unexpected OPACK float ${bytes.hex()}")
        }
    }

    private fun parseAsString(bytes: ByteArray): BPString {
        val type = readInt(bytes, 1)

        when(type) {
            in 0x40..0x60 -> return BPUnicodeString(readBytes(bytes, type - 0x40).toString(Charsets.UTF_8))
            0x61 -> {
                val length = readInt(bytes, 1)
                return BPUnicodeString(readBytes(bytes, length).toString(Charsets.UTF_8))
            }
            0x62 -> {
                val length = readInt(bytes, 2)
                return BPUnicodeString(readBytes(bytes, length).toString(Charsets.UTF_8))
            }
            0x63 -> {
                val length = readInt(bytes, 3)
                return BPUnicodeString(readBytes(bytes, length).toString(Charsets.UTF_8))
            }
            0x64 -> {
                val length = readInt(bytes, 4)
                return BPUnicodeString(readBytes(bytes, length).toString(Charsets.UTF_8))
            }
            else -> throw Exception("Unexpected OPACK string ${bytes.hex()}")
        }
    }

    private fun parseAsData(bytes: ByteArray): BPData {
        val type = readInt(bytes, 1)

        when(type) {
            in 0x70..0x90 -> return BPData(readBytes(bytes, type - 0x70))
            0x91 -> {
                val length = readInt(bytes, 1)
                return BPData(readBytes(bytes, length))
            }
            0x92 -> {
                val length = readInt(bytes, 2)
                return BPData(readBytes(bytes, length))
            }
            0x93 -> {
                val length = readInt(bytes, 3)
                return BPData(readBytes(bytes, length))
            }
            0x94 -> {
                val length = readInt(bytes, 4)
                return BPData(readBytes(bytes, length))
            }
            else -> throw Exception("Unexpected OPACK data ${bytes.hex()}")
        }
    }

    private fun parseAsArray(bytes: ByteArray): BPArray {
        val type = readInt(bytes, 1)
        val entries = mutableListOf<CodableBPListObject>()

        when(type) {
            in 0xd0..0xde -> {
                val length = type - 0xd0
                var i = 0
                while(i < length) {
                    entries.add(parse(bytes) as CodableBPListObject)
                    i += 1
                }
            }
            0xdf -> {
                while(bytes[parseOffset].toInt() != 0x03)
                    entries.add(parse(bytes) as CodableBPListObject)
            }
            else -> throw Exception("Unexpected OPACK array ${bytes.hex()}")
        }

        return BPArray(entries)
    }

    private fun parseAsDict(bytes: ByteArray): BPDict {
        val type = readInt(bytes, 1)
        val entries = mutableMapOf<CodableBPListObject, CodableBPListObject>()

        when(type) {
            in 0xe0..0xee -> {
                val length = type - 0xe0
                var i = 0
                while(i < length) {
                    entries[parse(bytes) as CodableBPListObject] = parse(bytes) as CodableBPListObject
                    i += 1
                }
            }
            0xef -> {
                while(bytes[parseOffset].toInt() != 0x03)
                    entries[parse(bytes) as CodableBPListObject] = parse(bytes) as CodableBPListObject
            }
            else -> throw Exception("Unexpected OPACK dict ${bytes.hex()}")
        }

        return BPDict(entries)
    }

}