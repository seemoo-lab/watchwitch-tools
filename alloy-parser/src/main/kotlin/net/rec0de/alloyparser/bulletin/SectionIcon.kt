package net.rec0de.alloyparser.bulletin

import net.rec0de.alloyparser.*
import net.rec0de.alloyparser.health.PBParsable

class SectionIcon(val variants: List<SectionIconVariant>) {
    override fun toString(): String {
        return "SectionIcon(${variants.joinToString(", ")})"
    }

    companion object : PBParsable<SectionIcon>() {
        // based on _BLTPBSectionIconReadFrom in BulletinDistributorCompanion binary
        override fun fromSafePB(pb: ProtoBuf): SectionIcon {
            val variants = pb.readMulti(1).map { SectionIconVariant.fromSafePB(it as ProtoBuf) }
            return SectionIcon(variants)
        }
    }

    fun renderProtobuf(): ByteArray {
        val fields = mutableMapOf<Int,List<ProtoValue>>()
        fields[1] = variants.map { ProtoLen(it.renderProtobuf()) }
        return ProtoBuf(fields).renderStandalone()
    }

}

class SectionIconVariant(val format: Int?, val imageData: ByteArray, val precomposed: Boolean?) {
    override fun toString(): String {
        return "SectionIconVariant(format $format, precomposed? $precomposed, data: ${imageData.hex()})"
    }

    companion object : PBParsable<SectionIconVariant>() {
        override fun fromSafePB(pb: ProtoBuf): SectionIconVariant {
            val format = pb.readOptShortVarInt(1)
            val imageData = (pb.readAssertedSinglet(2) as ProtoLen).value
            val precomposed = pb.readOptBool(3)

            return SectionIconVariant(format, imageData, precomposed)
        }
    }

    fun renderProtobuf(): ByteArray {
        val fields = mutableMapOf<Int,List<ProtoValue>>()

        if(format != null)
            fields[1] = listOf(ProtoVarInt(format.toLong()))

        fields[2] = listOf(ProtoLen(imageData))

        if(precomposed != null)
            fields[3] = listOf(ProtoVarInt(if(precomposed) 1 else 0))

        return ProtoBuf(fields).renderStandalone()
    }
}