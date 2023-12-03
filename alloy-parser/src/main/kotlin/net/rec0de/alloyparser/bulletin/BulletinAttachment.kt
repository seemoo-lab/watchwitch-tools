package net.rec0de.alloyparser.bulletin

import net.rec0de.alloyparser.*
import net.rec0de.alloyparser.health.PBParsable

class BulletinAttachment(val identifier: String?, val type: Int?, val url: String?, val isUpdated: Boolean?) {
    override fun toString(): String {
        return "BulletinAttachment($identifier, type $type, url $url, upd? $isUpdated)"
    }

    companion object : PBParsable<BulletinAttachment>() {
        // based on _BLTPBBulletinAttachmentReadFrom in BulletinDistributorCompanion binary
        override fun fromSafePB(pb: ProtoBuf): BulletinAttachment {
            val identifier = pb.readOptString(1)
            val type = pb.readShortVarInt(2)
            val url = pb.readOptString(3)
            val isUpdated = pb.readOptBool(4)

            return BulletinAttachment(identifier, type, url, isUpdated)
        }
    }

    fun renderProtobuf(): ByteArray {
        val fields = mutableMapOf<Int,List<ProtoValue>>()
        if(identifier != null)
            fields[1] = listOf(ProtoString(identifier))
        if(type != null)
            fields[3] = listOf(ProtoVarInt(type.toLong()))
        if(url != null)
            fields[4] = listOf(ProtoString(url))
        if(isUpdated != null)
            fields[5] = listOf(ProtoVarInt(if(isUpdated) 1 else 0))

        return ProtoBuf(fields).renderStandalone()
    }
}