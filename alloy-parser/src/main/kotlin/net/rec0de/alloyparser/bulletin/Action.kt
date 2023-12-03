package net.rec0de.alloyparser.bulletin

import net.rec0de.alloyparser.*
import net.rec0de.alloyparser.health.PBParsable

class Action(
    val identifier: String?,
    val activationMode: Int?,
    val launchURL: String?,
    val behavior: Int?,
    val behaviorParameters: ByteArray?,
    val behaviorParametersNull: ByteArray?
) {
    override fun toString(): String {
        return "Action($identifier, $launchURL, actMode $activationMode, behavior $behavior)"
    }

    companion object : PBParsable<Action>() {
        // based on _BLTPBActionReadFrom in BulletinDistributorCompanion binary
        override fun fromSafePB(pb: ProtoBuf): Action {
            val identifier = pb.readOptString(1)
            // 2: appearance
            val activationMode = pb.readOptShortVarInt(3)
            val launchURL = pb.readOptString(4)
            val behavior = pb.readOptShortVarInt(5)
            val behaviorParameters = pb.readOptionalSinglet(6) as ProtoLen
            val behaviorParametersNulls = pb.readOptionalSinglet(7) as ProtoLen

            return Action(identifier, activationMode, launchURL, behavior, behaviorParameters.value, behaviorParametersNulls.value)
        }
    }

    fun renderProtobuf(): ByteArray {
        val fields = mutableMapOf<Int,List<ProtoValue>>()
        if(identifier != null)
            fields[1] = listOf(ProtoString(identifier))
        if(activationMode != null)
            fields[3] = listOf(ProtoVarInt(activationMode.toLong()))
        if(launchURL != null)
            fields[4] = listOf(ProtoString(launchURL))
        if(behavior != null)
            fields[5] = listOf(ProtoVarInt(behavior.toLong()))
        if(behaviorParameters != null)
            fields[6] = listOf(ProtoLen(behaviorParameters))
        if(behaviorParametersNull != null)
            fields[6] = listOf(ProtoLen(behaviorParametersNull))

        return ProtoBuf(fields).renderStandalone()
    }
}