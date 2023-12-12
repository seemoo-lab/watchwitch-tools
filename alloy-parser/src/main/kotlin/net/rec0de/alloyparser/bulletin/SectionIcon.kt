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

class SectionIconVariant(val format: Int?, val imageData: ByteArray?, val precomposed: Boolean?) {
    override fun toString(): String {
        return "SectionIconVariant(format $format, precomposed? $precomposed, data: ${imageData?.hex()})"
    }

    companion object : PBParsable<SectionIconVariant>() {
        override fun fromSafePB(pb: ProtoBuf): SectionIconVariant {
            val format = pb.readOptShortVarInt(1)
            val imageData = (pb.readOptionalSinglet(2) as ProtoLen?)?.value
            val precomposed = pb.readOptBool(3)

            return SectionIconVariant(format, imageData, precomposed)
        }
    }

    val formatString: String
        get() = when(format) {
            0 -> "PNG(80x80?)"
            5 -> "PNG(196x196?)"
            9 -> "PNG(88x88?)"
            13 -> "PNG(55x55?)"
            else -> "unknown($format)"
        }

    fun renderProtobuf(): ByteArray {
        val fields = mutableMapOf<Int,List<ProtoValue>>()

        if(format != null)
            fields[1] = listOf(ProtoVarInt(format))

        if(imageData != null)
            fields[2] = listOf(ProtoLen(imageData))

        if(precomposed != null)
            fields[3] = listOf(ProtoVarInt(precomposed))

        return ProtoBuf(fields).renderStandalone()
    }
}