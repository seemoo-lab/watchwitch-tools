package net.rec0de.alloyparser

import net.rec0de.alloyparser.bitmage.*
import net.rec0de.alloyparser.bulletin.*
import net.rec0de.alloyparser.camera.CameraRequest
import net.rec0de.alloyparser.camera.CameraResponse
import net.rec0de.alloyparser.health.NanoSyncMessage
import net.rec0de.alloyparser.preferencessync.FileBackupMessage
import net.rec0de.alloyparser.preferencessync.UserDefaultsBackupMessage
import net.rec0de.alloyparser.preferencessync.UserDefaultsMessage
import net.rec0de.alloyparser.utun.*
import java.io.File
import java.nio.ByteBuffer
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.math.roundToInt


val topicMap = mutableMapOf<Int,String>()
val aovercLookup = mutableMapOf<String,ByteArray>()
val digest = MessageDigest.getInstance("SHA-256")

var resourceTransferReassemblyBuffer: ByteArray = byteArrayOf()
var resourceTransferSize = 0
var resourceFileCounter = 1
var resourceTransferFilename = ""

var printShort = false
var muteControl = false

fun main(args: Array<String>) {

    if(args.isEmpty()) {
        println("Alloy parser expects at least one argument")
        println("Usage: alloy-parser [--include=\"topicA,topicB\"] [--exclude=\"topicC,topicD\"] [--short] [--noctrl] path/to/ids/logfile")
        println("--short suppresses printing of unparsed message payloads")
        return
    }

    val include = args.filter { it.startsWith("--include=") }.map { it.removePrefix("--include=").removePrefix("\"").removeSuffix("\"") }.flatMap { it.split(",") }.map {
        if(it.startsWith("com.apple.")) it else "com.apple.private.alloy.$it"
    }
    val exclude = args.filter { it.startsWith("--exclude=") }.map { it.removePrefix("--exclude=").removePrefix("\"").removeSuffix("\"") }.flatMap { it.split(",") }.map {
        if(it.startsWith("com.apple.")) it else "com.apple.private.alloy.$it"
    }
    printShort = args.any{ it.startsWith("--short")}
    muteControl = args.any{ it.startsWith("--noctrl")}
    val path = args.first { !it.startsWith("--") }

    if(include.isNotEmpty())
        println("Showing only messages for topics: ${include.joinToString(", ")}")
    else if(exclude.isNotEmpty())
        println("Not showing messages for topics: ${exclude.joinToString(", ")}")

    val lines = File(path).readLines()

    // loading some values here so we have something, RSA priv is automatically updated with logged value from input file and ECDSA doesn't really matter for us
    val rsaPrivKeyBytes = "308202ec0201000281a100b17710e86ad20f8a94e2310c73fc2d4f32599161f955695beb7ec77045eacfe3e2ed0f36b70d2f8185d96517820f5b69070e6a2d19a2a7a790cf416942d69e5785c8e266734a3f66fb1d2e68738025590c363cf0033c49c7912bc7acb97e3b23954ac08396174d3c0774f3af410116a56d5dd370d7f5b40a96b60476ccd0c8860f607647da08e78836419f92a68d389f5d58d05979707003dbc23452a455106f02030100010281a00193a2e43e5ab7f703bcc5f6b5dc53c06bb9fbeaf4e26b5841d769a1ab769644a43fd866b83d65f16262dca72f8be74e5ab180bf25c1953d3500a92ac521fbdc64d2dc0c15d237b54c40658b45f3bd3ebb478ef596a32cc063f526b2659fa5e545bfbe1c082140ccc38688c17dbda01b253d8cb9d4627d962b8fab4a1298913c990405b2d3e4be2b7cc807c87a8872d47427aea2a162dd1346d611aaef73a1d9025100f3874433706b526b1591b84621724e15ad9c97bfc8b496408d1469092736c8582947fc6312c87b08d7653d22847178ad1137491549f9ca265b93b15c65c16c72c1f9953ec3efd7d9845fdb5a980e99b9025100ba8db073174aa603352b9ef1fa27c4aca8ebb916d391597acd64759a074ea047d674ec35e1fc593bf43f2c65313ede1b33e6117252d4b2604d93268d4d4a6dcf114f5c2d9686a19b6c62f45e9f3e6f6702504fcc7c41aacdd014fcdd6217c0eff6bc4dc6694753da30fdf7fcbf2a5baa2cde0eb0e2f807f89fb056fc7a9aebf14ecccf3e6179536341a56e0ea86891835f28ff7cec35c3f8bcaf2f1c46019a9ff6290251008ca95f3d3877b1bb43711394b2a11fbb6c56e8a55c7b00f4064054280290776c1338f00e24ca48625b64f2cd8e17301364cb79a630ec6d5f0dbf015793caa60776aed6fb0cbf90c5073189be7ae5f1cb0250386a1c70d8ffba2c83b6268031b6487ca4338c6cab9fd1ff0119804e06d9538f8ce53567177d190b3be1bfae5cef3005ffc376b51955be76de1e85c180ffbd7b6fad332e29264348e4147c116f95a601".fromHex()
    Decryptor.loadLocalPrivKey(rsaPrivKeyBytes)
    Decryptor.loadRemotePubKey("04b9d1ba902b6cdb977f5a7f87701a8b24071c7aa52eea33048aed666bd95c5ffec58fc34bf65456edcf87d1b2b52310664c72f3591ebffc80023d6ff7da4d277f".fromHex())

    lines.filter { it.startsWith("aoverc") }.forEach {line ->
        // plaintext-ciphertext mappings for outgoing AoverC messages
        if(line.startsWith("aovercmap ")) {
            val rest = line.removePrefix("aovercmap ")
            val parts = rest.split(" ").map { it.fromHex() }
            val hash = digest.digest(parts[0]).hex()
            aovercLookup[hash] = parts[1]
        }
        // load exported RSA private key to decrypt incoming A-over-C
        else if(line.startsWith("aovercrsa ")){
            Decryptor.loadLocalPrivKey(line.removePrefix("aovercrsa ").fromHex())
        }
    }

    for (line in lines.filter { !it.startsWith("aoverc") }) {
        readLine(line, include.toSet(), exclude.toSet())
    }
}

fun readLine(line: String, include: Set<String>, exclude: Set<String>) {
    var rest = line

    // manual topic mapping support
    if(rest.startsWith("map ")) {
        val parts = rest.removePrefix("map ").split(" ")
        val stream = Integer.valueOf(parts[0])
        val topic = parts[1]
        topicMap[stream] = topic
    }

    if(!rest.startsWith("snd ") && !rest.startsWith("rcv ")) {
        //println("ignoring input line: '$rest'")
        return
    }

    val incoming = if(rest.startsWith("snd ")) {
        rest = rest.removePrefix("snd ")
        false
    }
    else {
        rest = rest.removePrefix("rcv ")
        true
    }

    val control = if(rest.startsWith("utunctrl")) {
        rest = rest.removePrefix("utunctrl ")
        true
    }
    else {
        rest = rest.removePrefix("utun ")
        false
    }

    if(control)
        readControl(incoming, rest.fromHex())
    else {
        val parts = rest.split(" ")
        val opcode = parts[0].toInt()
        readUTun(incoming, opcode, parts[1].fromHex(), include, exclude)
    }

}

fun readControl(incoming: Boolean, bytes: ByteArray) {
    if(muteControl)
        return
    val parsed = UTunControlMessage.parse(bytes)
    val direction = if(incoming) "rcv" else "snd"
    println("$direction ctrl $parsed")
}

fun readUTun(incoming: Boolean, opcode: Int, bytes: ByteArray, include: Set<String>, exclude: Set<String>) {
    val synthesizedHeader = ByteBuffer.allocate(5)
    synthesizedHeader.put(opcode.toByte())
    synthesizedHeader.putInt(bytes.size)

    val parsed = UTunMessage.parse(synthesizedHeader.array() + bytes)
    val direction = if(incoming) "rcv" else "snd"

    when(parsed) {
        is ServiceMapMessage -> {
            println("Mapping topic ${parsed.serviceName} to stream ${parsed.streamID} (service map)")
            topicMap[parsed.streamID] = parsed.serviceName
        }
        is DataMessage -> {
            if(parsed.hasTopic && !topicMap.contains(parsed.streamID)) {
                println("mapping topic ${parsed.topic} to stream ${parsed.streamID} (message with topic)")
                topicMap[parsed.streamID] = parsed.topic!!
            }
            else if(parsed.hasTopic && parsed.topic != topicMap[parsed.streamID]) {
                println("message on stream ${parsed.streamID} should be topic ${topicMap[parsed.streamID]} but is ${parsed.topic}")
            }
            else if(topicMap.contains(parsed.streamID)) {
                parsed.topic = topicMap[parsed.streamID]
            }
        }
        is ProtobufMessage -> {
            if(parsed.hasTopic && !topicMap.contains(parsed.streamID)) {
                println("mapping topic ${parsed.topic} to stream ${parsed.streamID} (message with topic)")
                topicMap[parsed.streamID] = parsed.topic!!
            }
            else if(parsed.hasTopic && parsed.topic != topicMap[parsed.streamID]) {
                println("message on stream ${parsed.streamID} should be topic ${topicMap[parsed.streamID]} but is ${parsed.topic}")
            }
            else if(topicMap.contains(parsed.streamID)) {
                parsed.topic = topicMap[parsed.streamID]
            }
        }
    }

    // filtering
    val topic = if(parsed is DataMessage) parsed.topic else if(parsed is ProtobufMessage) parsed.topic else null
    if(include.isNotEmpty() && (topic == null || !include.contains(topic)))
        return
    else if(exclude.isNotEmpty() && exclude.contains(topic))
        return

    if(printShort)
        println("$direction ${parsed.toStringShort()}")
    else
        println("$direction $parsed")

    when(parsed) {
        is ResourceTransferMessage -> handleResourceTransfer(parsed)
        is DataMessage -> logDataMessage(parsed)
        is ProtobufMessage -> logProtobufMessage(parsed)
    }

    println()
}

fun logProtobufMessage(parsed: ProtobufMessage) {

    // for some reason Protobuf messages sometimes carry, guess what, bplists
    if(BPListParser.bufferIsBPList(parsed.payload)) {
        val bpcontent = BPListParser().parse(parsed.payload)
        if(Decryptor.isEncryptedMessage(bpcontent)) {
            println(bpcontent)
            val plain = tryDecrypt(parsed.payload)
            println(plain?.hex() ?: bpcontent)
        }
        else
            println(bpcontent)
    }
    else {
        try {
            // some messages claiming to be protobuf actually contain OPACK data...
            if(parsed.topic != null && parsed.topic == "com.apple.private.alloy.sharing.paireddevice") {
                println(OpackParser().parseTopLevel(parsed.payload))
                return
            }
            else if(parsed.topic != null && parsed.topic == "com.apple.private.alloy.airtraffic") {
                println(parsed.payload.decodeToString())
                return
            }

            // messages (esp. bulletindistributor) sometimes have a trailer that is also protobuf with the length encoded in the last two bytes
            val len = if(parsed.payload.size > 2) UInt.fromBytes(parsed.payload.fromIndex(parsed.payload.size - 2), ByteOrder.LITTLE).toInt() else 0
            val pb: ProtoBuf
            if (parsed.payload.size > 2 && len <= parsed.payload.size - 2 && len < 100 && len > 2) {
                val endIndex = parsed.payload.size - 2
                val startIndex = endIndex - len
                val potentialTrailer = parsed.payload.sliceArray(startIndex until endIndex)
                val rest = try {
                    val parsedTrailer = ProtobufParser().parse(potentialTrailer)
                    println("trailer: $parsedTrailer")
                    parsed.payload.sliceArray(0 until startIndex)
                } catch (e: Exception) {
                    parsed.payload
                }
                pb = ProtobufParser().parse(rest)
            } else
                pb = ProtobufParser().parse(parsed.payload)

            if (parsed.topic != null && parsed.topic!! == "com.apple.private.alloy.bulletindistributor") {
                println(pb)
                when (parsed.type) {
                    1 -> println(BulletinRequest.fromSafePB(pb))
                    2 -> println(RemoveBulletinRequest.fromSafePB(pb)) // for some reason remove bulletin requests use type 2 and 10?
                    3 -> println(AddBulletinSummaryRequest.fromSafePB(pb))
                    4 -> println(CancelBulletinRequest.fromSafePB(pb))
                    5 -> println(AcknowledgeActionRequest.fromSafePB(pb))
                    6 -> println(SnoozeActionRequest.fromSafePB(pb))
                    7 -> println(SupplementaryActionRequest.fromSafePB(pb))
                    8 -> println(DismissActionRequest.fromSafePB(pb))
                    9 -> println(DidPlayLightsAndSirens.fromSafePB(pb))
                    10 -> println(RemoveBulletinRequest.fromSafePB(pb))
                    12 -> println(AckInitialSequenceNumberRequest.fromSafePB(pb))
                    13 -> if(parsed.isResponse == 1)
                            println("SetSectionInfoResponse $pb")
                        else
                            println(SetSectionInfoRequest.fromSafePB(pb))
                    14 -> if(parsed.isResponse == 1)
                        println("SetSectionSubtypeParametersIconResponse $pb")
                    else
                        println(SetSectionSubtypeParametersIconRequest.fromSafePB(pb))
                    15 -> println(UpdateBulletinListRequest.fromSafePB(pb))
                    16 -> println("ShouldSuppressLightsAndSirensRequest $pb")
                    17 -> println("PairedDeviceReady $pb")
                    18 -> println(WillSendLightsAndSirens.fromSafePB(pb))
                    19 -> println(RemoveSectionRequest.fromSafePB(pb))
                    20 -> println(SetNotificationsAlertLevelRequest.fromSafePB(pb))
                    21 -> println(SetNotificationsGroupingRequest.fromSafePB(pb))
                    22 -> println(SetNotificationsSoundRequest.fromSafePB(pb))
                    23 -> println(SetNotificationsCriticalAlertRequest.fromSafePB(pb))
                    24 -> println(SetRemoteGlobalSpokenSettingEnabledRequest.fromSafePB(pb))
                    else -> println(pb)
                }
            }
            else if(parsed.topic != null && parsed.topic!!.startsWith("com.apple.private.alloy.preferencessync")) {
                //println(pb)
                when(parsed.type) {
                    0 -> {
                        val msg = UserDefaultsMessage.fromSafePB(pb)
                        println(msg)
                    }
                    1 -> {
                        val msg = UserDefaultsBackupMessage.fromSafePB(pb)
                        println(msg)
                    }
                    2 -> {
                        val msg = FileBackupMessage.fromSafePB(pb)
                        println(msg)
                    }
                }
            }
            else
                println(pb)
        }
        catch(e: Exception) {
            e.printStackTrace()
            println("Failed while parsing: " + parsed.payload.hex())
        }
    }
}

fun logDataMessage(parsed: DataMessage){
    if (parsed.topic != null && parsed.topic!!.startsWith("com.apple.private.alloy.camera.proxy")) {
        // CameraRequest
        if(parsed.responseIdentifier == null) {
            val request = CameraRequest.parse(parsed.payload)
            println(request)
        }
        // CameraResponse
        else {
            val response = CameraResponse.parse(parsed.payload)
            println(response)
        }
    }
    else if(BPListParser.bufferIsBPList(parsed.payload)) {
        val bpcontent = BPListParser().parse(parsed.payload)
        if(Decryptor.isEncryptedMessage(bpcontent)) {
            val plain = tryDecrypt(parsed.payload)
            if(plain != null) {
                //println("plaintext: ${plain.hex()}")
                val pb = try {
                    if(parsed.responseIdentifier == null)
                        ProtobufParser().parse(plain.fromIndex(3))
                    else
                        ProtobufParser().parse(plain.fromIndex(2))
                }
                catch (e: Exception) {
                    null
                }

                if(pb != null) {
                    try {
                        println(NanoSyncMessage.fromSafePB(pb))
                    }
                    catch(e: Exception) {
                        // if we fail parsing something, print the failing protobuf for debugging and then still fail
                        println("Failed while parsing: ${plain.hex()}")
                        println("bytes: ${plain.hex()}")
                        e.printStackTrace()
                    }
                }
                else
                    println(plain.hex())
            }
            else {
                println("payload decryption unavailable")
            }
        }
        else
            println(bpcontent)
    }
    else {
        // DataMessage payloads can also be protobufs, with either 0, 2, or 3 byte unknown prefixes
        // *fun*, isn't it?
        try {
            println(ProtobufParser().parse(parsed.payload).toString())
        }
        catch(_: Exception) {
            try {
                println(ProtobufParser().parse(parsed.payload.fromIndex(2)).toString())
            }
            catch(_: Exception) {
                try {
                    println(ProtobufParser().parse(parsed.payload.fromIndex(3)).toString())
                }
                catch(_: Exception) {
                    println(parsed.payload.hex())
                }
            }
        }
    }
}

fun tryDecrypt(msg: ByteArray): ByteArray? {
    val hash = digest.digest(msg).hex()
    return if(aovercLookup.containsKey(hash)) {
        val plain = aovercLookup[hash]!!
        aovercLookup.remove(hash)
        plain
    }
    else {
        val bpcontent = BPListParser().parse(msg)
        Decryptor.decrypt(bpcontent as BPDict)
    }
}

fun handleResourceTransfer(msg: ResourceTransferMessage) {
    // first message of transfer?
    if(msg.payload[0].toInt() == 1) {
        val body = msg.payload.fromIndex(1)
        val content = if(GzipDecoder.bufferIsGzipCompressed(body)) GzipDecoder.inflate(body) else body
        val bp = BPListParser(nestedDecode = false).parse(content) as BPDict

        val totalBytes = (bp.values[BPAsciiString("ids-message-resource-transfer-total-bytes")]!! as BPInt).value.toInt()
        val file = (bp.values[BPAsciiString("ids-message-resource-transfer-url")]!! as BPAsciiString).value

        val firstChunk = if(totalBytes == 0) byteArrayOf() else (bp.values[BPAsciiString("ids-message-resource-transfer-data")]!! as BPData).value
        resourceTransferReassemblyBuffer = firstChunk
        resourceTransferSize = totalBytes
        resourceTransferFilename = file.split("/").last()

        println("Resource transfer of $totalBytes bytes for \"$file\"")
        val percent = if(totalBytes == 0) 100.0 else (((resourceTransferReassemblyBuffer.size.toDouble() / resourceTransferSize)*1000).roundToInt().toDouble())/10
        print("Got ${resourceTransferReassemblyBuffer.size}/$resourceTransferSize ($percent%) bytes")
    }
    else if(msg.payload.size > 2) {
        val offset = ULong.fromBytes(msg.payload.sliceArray(0 until 8), ByteOrder.BIG).toInt()
        val body = msg.payload.fromIndex(8)
        val content = if(GzipDecoder.bufferIsGzipCompressed(body)) GzipDecoder.inflate(body) else body


        if(offset != resourceTransferReassemblyBuffer.size) {
            println("Resource transfer chunk length ${content.size} at offset $offset")
            println("Reassembly buffer mismatch")
        }
        else {
            resourceTransferReassemblyBuffer += content
            val percent = (((resourceTransferReassemblyBuffer.size.toDouble() / resourceTransferSize)*1000).roundToInt().toDouble())/10
            println("Got ${resourceTransferReassemblyBuffer.size}/$resourceTransferSize ($percent%) bytes")
        }
    }
    else {
        println("unknown resource transfer message, payload: ${msg.payload.hex()}")
    }

    if(resourceTransferReassemblyBuffer.size == resourceTransferSize) {
        val filename = "alloyResourceTransfer-$resourceFileCounter-$resourceTransferFilename"
        println("Resource transfer complete! Writing contents to '$filename'")
        File(filename).writeBytes(resourceTransferReassemblyBuffer)
        resourceTransferReassemblyBuffer = byteArrayOf()
        resourceFileCounter += 1
    }
}