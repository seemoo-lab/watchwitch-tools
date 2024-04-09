package net.rec0de.alloyparser.preferencessync

import net.rec0de.alloyparser.*
import net.rec0de.alloyparser.health.PBParsable
import java.util.*

// from NPSFileBackupMsg::readFrom: in nanoprefsyncd
class FileBackupMessage(
    val domain: String?, // this is a guess
    val entries: List<FileBackupEntry>
) {
    companion object : PBParsable<FileBackupMessage>() {
        override fun fromSafePB(pb: ProtoBuf): FileBackupMessage {
            val domain = pb.readOptString(2)
            val entries = pb.readMulti(3).map { FileBackupEntry.fromSafePB(it as ProtoBuf) }
            return FileBackupMessage(domain, entries)
        }
    }

    override fun toString() = "FileBackupMessage(domain: $domain, $entries)"
}
class FileBackupEntry(
    val fileUrl: String,
    val fileData: BPListObject?
) {
    companion object : PBParsable<FileBackupEntry>() {
        override fun fromSafePB(pb: ProtoBuf): FileBackupEntry {
            val fileUrl = pb.readOptString(1)!!
            val fileData = (pb.readOptionalSinglet(2) as ProtoBPList?)?.parsed

            return FileBackupEntry(fileUrl, fileData)
        }
    }

    override fun toString() = "FileBackupEntry(url: $fileUrl, data: $fileData)"
}


// from NPSServer::handleUserDefaultsBackupMsgData:backupFile:idsGuid: in nanoprefsyncd
class UserDefaultsBackupMessage(
    val container: String?,
    val key: String?,
    val value: List<UserDefaultsBackupMsgKey>
) {
    companion object : PBParsable<UserDefaultsBackupMessage>() {
        override fun fromSafePB(pb: ProtoBuf): UserDefaultsBackupMessage {
            val container = pb.readOptString(1)
            val domain = pb.readOptString(2)
            val keys = pb.readMulti(3).map { UserDefaultsBackupMsgKey.fromSafePB(it as ProtoBuf) }

            return UserDefaultsBackupMessage(container, domain, keys)
        }
    }

    fun renderProtobuf(): ByteArray {
        val fields = mutableMapOf<Int,List<ProtoValue>>()

        if(container != null)
            fields[1] = listOf(ProtoString(container))

        if(key != null)
            fields[2] = listOf(ProtoString(key))

        fields[3] = value.map { ProtoLen(it.renderProtobuf()) }

        return ProtoBuf(fields).renderStandalone()
    }

    override fun toString() = "UserDefaultsBackupMsg(container: $container, $key: $value)"
}

// from NPSServer::handleUserDefaultsMsgData:backupFile:idsGuid: in nanoprefsyncd
class UserDefaultsMessage(
    val timestamp: Date,
    val domain: String,
    val keys: List<UserDefaultsMsgKey>
) {
    companion object : PBParsable<UserDefaultsMessage>() {
        override fun fromSafePB(pb: ProtoBuf): UserDefaultsMessage {
            val timestamp = pb.readOptDate(1)!!
            val domain = pb.readOptString(2)!!
            val keys = pb.readMulti(3).map { UserDefaultsMsgKey.fromSafePB(it as ProtoBuf) }

            return UserDefaultsMessage(timestamp, domain, keys)
        }
    }

    fun renderProtobuf(): ByteArray {
        val fields = mutableMapOf<Int,List<ProtoValue>>()

        fields[1] = listOf(ProtoI64(timestamp.toAppleTimestamp()))
        fields[2] = listOf(ProtoString(domain))
        fields[3] = keys.map { ProtoLen(it.renderProtobuf()) }

        return ProtoBuf(fields).renderStandalone()
    }

    override fun toString() = "UserDefaultsMsg($timestamp $domain: $keys)"
}

class UserDefaultsMsgKey(
    val key: String,
    val value: BPListObject?,
    val twoWaySync: Boolean?,
    val timestamp: Date?
) {
    companion object : PBParsable<UserDefaultsMsgKey>() {
        override fun fromSafePB(pb: ProtoBuf): UserDefaultsMsgKey {
            val key = pb.readOptString(1)!!
            val value = (pb.readOptionalSinglet(2) as ProtoBPList?)?.parsed
            val twoWaySync = pb.readOptBool(3)
            val timestamp = pb.readOptDate(4)
            return UserDefaultsMsgKey(key, value, twoWaySync, timestamp)
        }
    }

    fun renderProtobuf(): ByteArray {
        val fields = mutableMapOf<Int,List<ProtoValue>>()

        fields[1] = listOf(ProtoString(key))

        if(value != null)
            fields[2] = listOf(ProtoLen((value as CodableBPListObject).renderAsTopLevelObject()))
        if(twoWaySync != null)
            fields[3] = listOf(ProtoVarInt(twoWaySync))
        if(timestamp != null)
            fields[4] = listOf(ProtoI64(timestamp.toAppleTimestamp()))

        return ProtoBuf(fields).renderStandalone()
    }

    override fun toString() = "Key($timestamp, tws? $twoWaySync, $key: $value)"
}

class UserDefaultsBackupMsgKey(
    val key: String,
    val value: BPListObject?
) {
    companion object : PBParsable<UserDefaultsBackupMsgKey>() {
        override fun fromSafePB(pb: ProtoBuf): UserDefaultsBackupMsgKey {
            val key = pb.readOptString(1)!!
            val value = (pb.readOptionalSinglet(2) as ProtoBPList?)?.parsed
            return UserDefaultsBackupMsgKey(key, value)
        }
    }

    fun renderProtobuf(): ByteArray {
        val fields = mutableMapOf<Int,List<ProtoValue>>()

        fields[1] = listOf(ProtoString(key))

        if(value != null)
            fields[2] = listOf(ProtoLen((value as CodableBPListObject).renderAsTopLevelObject()))

        return ProtoBuf(fields).renderStandalone()
    }

    override fun toString() = "BKey($key: $value)"
}