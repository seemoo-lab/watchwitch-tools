package net.rec0de.alloyparser
import net.rec0de.alloyparser.Utils.dateFromAppleTimestamp
import net.rec0de.alloyparser.bitmage.*
import java.math.BigInteger
import java.nio.ByteBuffer
import java.util.*
import kotlin.math.ceil
import kotlin.math.log2

class OpackParser : ParseCompanion() {

    fun parseTopLevel(bytes: ByteArray): OpackObject {
        parseOffset = 0
        val result = parse(bytes)

        check(parseOffset >= bytes.size){ "input data not fully consumed" }

        return result
    }

    private fun parse(bytes: ByteArray): OpackObject {
        val typeByte = bytes[parseOffset].toUByte().toUInt()
        //Logger.log("parsing type byte: 0x${typeByte.toString(16)}")
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

    private fun parseAsBool(bytes: ByteArray): OpackObject {
        val byte = readInt(bytes, 1)
        return when (byte) {
            0x01 -> OPTrue()
            0x02 -> OPFalse()
            else -> throw Exception("Unexpected OPACK boolean ${bytes.hex()}")
        }
    }

    private fun parseAsUUID(bytes: ByteArray): OPData {
        val type = readInt(bytes, 1)
        if(type != 0x05)
            throw Exception("Unexpected OPACK UUID ${bytes.hex()}")
        val uuid = readBytes(bytes, 16)
        return OPData(uuid)
    }

    private fun parseAsDate(bytes: ByteArray): OPDate {
        val type = readInt(bytes, 1)
        if(type != 0x06)
            throw Exception("Unexpected OPACK date ${bytes.hex()}")
        val timestamp = readBytes(bytes, 8).readDouble(ByteOrder.BIG)
        return OPDate(timestamp)
    }

    private fun parseAsInt(bytes: ByteArray): OPInt {
        val type = readInt(bytes, 1)

        // NOTE: deviation from prior documentation ("Analyzing Apple’s private wireless communication protocols with a focus on security and privacy")
        // instead of linar byte length increments (1, 2, 3, 4) it seems apple uses exponential increments (1, 2, 4, 8)
        // is this an error in the documentation, or do both versions exist?
        // we also assume these are all signed - i don't actually know if that's the case, but we also don't have a counterexample
        return when(type) {
            in 0x08..0x2f -> OPInt((type - 8).toLong())
            0x30 -> OPInt(readInt(bytes, 1, explicitlySigned = true))
            0x31 -> OPInt(readInt(bytes, 2, explicitlySigned = true, byteOrder = ByteOrder.LITTLE))
            0x32 -> OPInt(readInt(bytes, 4, explicitlySigned = true, byteOrder = ByteOrder.LITTLE))
            0x33 -> OPInt(readLong(bytes, 8, byteOrder = ByteOrder.LITTLE))
            else -> throw Exception("Unexpected OPACK int ${bytes.hex()}")
        }
    }

    private fun parseAsFloat(bytes: ByteArray): OPReal {
        val type = readInt(bytes, 1)
        when(type) {
            0x35 -> {
                return OPReal(readBytes(bytes, 4).readFloat(ByteOrder.LITTLE).toDouble())
            }
            0x36 -> {
                return OPReal(readBytes(bytes, 8).readDouble(ByteOrder.LITTLE))
            }
            else -> throw Exception("Unexpected OPACK float ${bytes.hex()}")
        }
    }

    private fun parseAsString(bytes: ByteArray): OPString {
        val type = readInt(bytes, 1)

        when(type) {
            in 0x40..0x60 -> return OPString(readBytes(bytes, type - 0x40).decodeToString())
            0x61 -> {
                val length = readInt(bytes, 1)
                return OPString(readBytes(bytes, length).decodeToString())
            }
            0x62 -> {
                val length = readInt(bytes, 2, byteOrder = ByteOrder.LITTLE)
                return OPString(readBytes(bytes, length).decodeToString())
            }
            0x63 -> {
                val length = readInt(bytes, 3, byteOrder = ByteOrder.LITTLE)
                return OPString(readBytes(bytes, length).decodeToString())
            }
            0x64 -> {
                val length = readInt(bytes, 4, byteOrder = ByteOrder.LITTLE)
                return OPString(readBytes(bytes, length).decodeToString())
            }
            else -> throw Exception("Unexpected OPACK string ${bytes.hex()}")
        }
    }

    private fun parseAsData(bytes: ByteArray): OPData {
        val type = readInt(bytes, 1)

        when(type) {
            in 0x70..0x90 -> return OPData(readBytes(bytes, type - 0x70))
            0x91 -> {
                val length = readInt(bytes, 1)
                return OPData(readBytes(bytes, length))
            }
            0x92 -> {
                val length = readInt(bytes, 2, byteOrder = ByteOrder.LITTLE)
                return OPData(readBytes(bytes, length))
            }
            0x93 -> {
                val length = readInt(bytes, 3, byteOrder = ByteOrder.LITTLE)
                return OPData(readBytes(bytes, length))
            }
            0x94 -> {
                val length = readInt(bytes, 4, byteOrder = ByteOrder.LITTLE)
                return OPData(readBytes(bytes, length))
            }
            else -> throw Exception("Unexpected OPACK data ${bytes.hex()}")
        }
    }

    private fun parseAsArray(bytes: ByteArray): OPArray {
        val type = readInt(bytes, 1)
        val entries = mutableListOf<OpackObject>()

        when(type) {
            in 0xd0..0xde -> {
                val length = type - 0xd0
                var i = 0
                while(i < length) {
                    entries.add(parse(bytes))
                    i += 1
                }
            }
            0xdf -> {
                while(bytes[parseOffset].toInt() != 0x03)
                    entries.add(parse(bytes))
            }
            else -> throw Exception("Unexpected OPACK array ${bytes.hex()}")
        }

        return OPArray(entries)
    }

    private fun parseAsDict(bytes: ByteArray): OPDict {
        val type = readInt(bytes, 1)
        val entries = mutableMapOf<OpackObject, OpackObject>()

        when(type) {
            in 0xe0..0xee -> {
                val length = type - 0xe0
                var i = 0
                while(i < length) {
                    entries[parse(bytes)] = parse(bytes)
                    i += 1
                }
            }
            0xef -> {
                while(bytes[parseOffset].toInt() != 0x03)
                    entries[parse(bytes)] = parse(bytes)
            }
            else -> throw Exception("Unexpected OPACK dict ${bytes.hex()}")
        }

        return OPDict(entries)
    }
}

abstract class OpackObject

class OPTrue : OpackObject() {
    override fun toString() = "true"
}

class OPFalse : OpackObject() {
    override fun toString() = "false"
}

data class OPInt(val value: Long): OpackObject() {
    constructor(value: Int) : this(value.toLong())
    override fun toString() = value.toString()
}

data class OPReal(val value: Double): OpackObject() {
    /**
     * Assume this I64 value represents a double containing an NSDate timestamp (seconds since Jan 01 2001)
     * and turn it into a Date object
     */
    fun asDate(appleEpoch: Boolean = true): Date {
        val offset = if(appleEpoch) 978307200000L else 0L
        return Date((value*1000).toLong() + offset)
    }
}

data class OPDate(val timestamp: Double, val isAppleEpoch: Boolean = true) : OpackObject() {
    override fun toString() = "BPDate($timestamp)"

    fun asDate(): Date {
        return if(isAppleEpoch) {
            dateFromAppleTimestamp(timestamp)
        }
        else {
            Date((timestamp*1000).toLong())
        }
    }
}

class OPData(val value: ByteArray) : OpackObject() {
    override fun toString() = "BPData(${value.hex()})"
}

data class OPString(val value: String) : OpackObject() {
    override fun toString() = "\"$value\""
}

data class OPArray(val values: List<OpackObject>) : OpackObject() {
    override fun toString() = "[${values.joinToString(", ")}]"
}

data class OPDict(val values: Map<OpackObject, OpackObject>) : OpackObject() {
    override fun toString() = values.toString()
}