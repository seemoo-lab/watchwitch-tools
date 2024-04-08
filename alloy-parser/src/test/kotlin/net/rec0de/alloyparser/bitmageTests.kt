package net.rec0de.alloyparser

import net.rec0de.alloyparser.bitmage.*
import org.junit.jupiter.api.Assertions.assertEquals
import kotlin.random.Random
import kotlin.random.nextUInt
import kotlin.random.nextULong
import kotlin.test.Test

class BitmageTests {
    @OptIn(ExperimentalUnsignedTypes::class)
    @Test
    fun test(): Unit {
        // test vectors, hex
        assertEquals("00", byteArrayOf(0).hex())
        assertEquals("ffff", ubyteArrayOf(255u, 255u).toByteArray().hex())
        assertEquals("00010203", byteArrayOf(0, 1, 2, 3).hex())


        // test vectors, integers
        assertEquals(0u, UInt.fromBytes("00".fromHex(), ByteOrder.BIG))
        assertEquals(0u, UInt.fromBytes("0000".fromHex(), ByteOrder.BIG))
        assertEquals(0u, UInt.fromBytes("000000".fromHex(), ByteOrder.BIG))
        assertEquals(0u, UInt.fromBytes("00000000".fromHex(), ByteOrder.BIG))

        assertEquals(0u, UInt.fromBytes("00".fromHex(), ByteOrder.LITTLE))
        assertEquals(0u, UInt.fromBytes("0000".fromHex(), ByteOrder.LITTLE))
        assertEquals(0u, UInt.fromBytes("000000".fromHex(), ByteOrder.LITTLE))
        assertEquals(0u, UInt.fromBytes("00000000".fromHex(), ByteOrder.LITTLE))

        assertEquals(16909060u, UInt.fromBytes("01020304".fromHex(), ByteOrder.BIG))
        assertEquals(16909060, Int.fromBytes("01020304".fromHex(), ByteOrder.BIG))

        assertEquals(67305985u, UInt.fromBytes("01020304".fromHex(), ByteOrder.LITTLE))
        assertEquals(67305985, Int.fromBytes("01020304".fromHex(), ByteOrder.LITTLE))

        assertEquals(UInt.MAX_VALUE, UInt.fromBytes("ffffffff".fromHex(), ByteOrder.BIG))
        assertEquals(-1, Int.fromBytes("ffffffff".fromHex(), ByteOrder.BIG))

        // hex utf8 decode
        assertEquals("WatchWitch\uD83E\uDDD9\u200D♀\uFE0F你是我的秘密", "57617463685769746368f09fa799e2808de29980efb88fe4bda0e698afe68891e79a84e7a798e5af86".fromHex().decodeToString())

        // utf16 decode
        assertEquals("WatchWitch\uD83E\uDDD9\u200D♀\uFE0F你是我的秘密", "0057006100740063006800570069007400630068d83eddd9200d2640fe0f4f60662f6211768479d85bc6".fromHex().decodeAsUTF16BE())

        // round trip

        (0..100).forEach { _ ->
            val a = Random.nextInt()
            val b = Random.nextLong()
            val c = Random.nextUInt()
            val d = Random.nextULong()
            val e = Random.nextFloat()
            val f = Random.nextDouble()

            assertEquals(a, Int.fromBytes(a.toBytes(ByteOrder.BIG), ByteOrder.BIG))
            assertEquals(a, Int.fromBytes(a.toBytes(ByteOrder.LITTLE), ByteOrder.LITTLE))

            assertEquals(b, Long.fromBytes(b.toBytes(ByteOrder.BIG), ByteOrder.BIG))
            assertEquals(b, Long.fromBytes(b.toBytes(ByteOrder.LITTLE), ByteOrder.LITTLE))

            assertEquals(c, UInt.fromBytes(c.toBytes(ByteOrder.BIG), ByteOrder.BIG))
            assertEquals(c, UInt.fromBytes(c.toBytes(ByteOrder.LITTLE), ByteOrder.LITTLE))

            assertEquals(d, ULong.fromBytes(d.toBytes(ByteOrder.BIG), ByteOrder.BIG))
            assertEquals(d, ULong.fromBytes(d.toBytes(ByteOrder.LITTLE), ByteOrder.LITTLE))

            assertEquals(e, Float.fromBytes(e.toBytes(ByteOrder.BIG), ByteOrder.BIG))
            assertEquals(e, Float.fromBytes(e.toBytes(ByteOrder.LITTLE), ByteOrder.LITTLE))

            assertEquals(f, Double.fromBytes(f.toBytes(ByteOrder.BIG), ByteOrder.BIG))
            assertEquals(f, Double.fromBytes(f.toBytes(ByteOrder.LITTLE), ByteOrder.LITTLE))
        }

    }
}