package net.rec0de.alloyparser

import net.rec0de.alloyparser.health.NanoSyncMessage
import net.rec0de.alloyparser.utun.*
import java.io.File
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.*

val topicMap = mutableMapOf<Int,String>()
val aovercLookup = mutableMapOf<String,ByteArray>()

val digest = MessageDigest.getInstance("SHA-256")

fun main(args: Array<String>) {

    if(args.isEmpty()) {
        println("Alloy parser expects at least one argument")
        println("Usage: alloy-parser [--include=\"topicA,topicB\"] [--exclude=\"topicC,topicD\"] path/to/ids/logfile")
        return
    }

    val include = args.filter { it.startsWith("--include=") }.map { it.removePrefix("--include=").removePrefix("\"").removeSuffix("\"") }.flatMap { it.split(",") }
    val exclude = args.filter { it.startsWith("--exclude=") }.map { it.removePrefix("--exclude=").removePrefix("\"").removeSuffix("\"") }.flatMap { it.split(",") }
    val path = args.first { !it.startsWith("--") }

    if(include.isNotEmpty())
        println("Showing only messages for topics: ${include.joinToString(", ")}")
    else if(exclude.isNotEmpty())
        println("Not showing messages for topics: ${exclude.joinToString(", ")}")

    val lines = File(path).readLines()

    // loading some values here so we have something, RSA priv is automatically updated with logged value from input file and ECDSA doesn't really matter for us
    val rsaPrivKeyBytes = "308202ec0201000281a100b17710e86ad20f8a94e2310c73fc2d4f32599161f955695beb7ec77045eacfe3e2ed0f36b70d2f8185d96517820f5b69070e6a2d19a2a7a790cf416942d69e5785c8e266734a3f66fb1d2e68738025590c363cf0033c49c7912bc7acb97e3b23954ac08396174d3c0774f3af410116a56d5dd370d7f5b40a96b60476ccd0c8860f607647da08e78836419f92a68d389f5d58d05979707003dbc23452a455106f02030100010281a00193a2e43e5ab7f703bcc5f6b5dc53c06bb9fbeaf4e26b5841d769a1ab769644a43fd866b83d65f16262dca72f8be74e5ab180bf25c1953d3500a92ac521fbdc64d2dc0c15d237b54c40658b45f3bd3ebb478ef596a32cc063f526b2659fa5e545bfbe1c082140ccc38688c17dbda01b253d8cb9d4627d962b8fab4a1298913c990405b2d3e4be2b7cc807c87a8872d47427aea2a162dd1346d611aaef73a1d9025100f3874433706b526b1591b84621724e15ad9c97bfc8b496408d1469092736c8582947fc6312c87b08d7653d22847178ad1137491549f9ca265b93b15c65c16c72c1f9953ec3efd7d9845fdb5a980e99b9025100ba8db073174aa603352b9ef1fa27c4aca8ebb916d391597acd64759a074ea047d674ec35e1fc593bf43f2c65313ede1b33e6117252d4b2604d93268d4d4a6dcf114f5c2d9686a19b6c62f45e9f3e6f6702504fcc7c41aacdd014fcdd6217c0eff6bc4dc6694753da30fdf7fcbf2a5baa2cde0eb0e2f807f89fb056fc7a9aebf14ecccf3e6179536341a56e0ea86891835f28ff7cec35c3f8bcaf2f1c46019a9ff6290251008ca95f3d3877b1bb43711394b2a11fbb6c56e8a55c7b00f4064054280290776c1338f00e24ca48625b64f2cd8e17301364cb79a630ec6d5f0dbf015793caa60776aed6fb0cbf90c5073189be7ae5f1cb0250386a1c70d8ffba2c83b6268031b6487ca4338c6cab9fd1ff0119804e06d9538f8ce53567177d190b3be1bfae5cef3005ffc376b51955be76de1e85c180ffbd7b6fad332e29264348e4147c116f95a601".hexBytes()
    Decryptor.loadLocalPrivKey(rsaPrivKeyBytes)
    Decryptor.loadRemotePubKey("04b9d1ba902b6cdb977f5a7f87701a8b24071c7aa52eea33048aed666bd95c5ffec58fc34bf65456edcf87d1b2b52310664c72f3591ebffc80023d6ff7da4d277f".hexBytes())

    lines.filter { it.startsWith("aoverc") }.forEach {line ->
        // plaintext-ciphertext mappings for outgoing AoverC messages
        if(line.startsWith("aovercmap ")) {
            val rest = line.removePrefix("aovercmap ")
            val parts = rest.split(" ").map { it.hexBytes() }
            val hash = digest.digest(parts[0]).hex()
            aovercLookup[hash] = parts[1]
        }
        // load exported RSA private key to decrypt incoming A-over-C
        else if(line.startsWith("aovercrsa ")){
            Decryptor.loadLocalPrivKey(line.removePrefix("aovercrsa ").hexBytes())
        }
    }

    for (line in lines.filter { !it.startsWith("aoverc") }) {
        readLine(line, include.toSet(), exclude.toSet())
    }
}

fun readLine(line: String, include: Set<String>, exclude: Set<String>) {
    var rest = line

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
        readControl(incoming, rest.hexBytes())
    else {
        val parts = rest.split(" ")
        val opcode = parts[0].toInt()
        readUTun(incoming, opcode, parts[1].hexBytes(), include, exclude)
    }

}

fun readControl(incoming: Boolean, bytes: ByteArray) {
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
            topicMap[parsed.streamID] = parsed.serviceName
        }
        is DataMessage -> {
            if(parsed.hasTopic)
                topicMap[parsed.streamID] = parsed.topic!!
            else
                parsed.topic = topicMap[parsed.streamID]
        }
        is ProtobufMessage -> {
            if(parsed.hasTopic)
                topicMap[parsed.streamID] = parsed.topic!!
            else
                parsed.topic = topicMap[parsed.streamID]
        }
    }

    // filtering
    val topic = if(parsed is DataMessage) parsed.topic else if(parsed is ProtobufMessage) parsed.topic else null
    if(include.isNotEmpty() && (topic == null || !include.contains(topic)))
        return
    else if(exclude.isNotEmpty() && exclude.contains(topic))
        return

    println("$direction $parsed")

    when(parsed) {
        is DataMessage -> {
            if(BPListParser.bufferIsBPList(parsed.payload)) {
                val bpcontent = BPListParser().parse(parsed.payload)
                if(Decryptor.isEncryptedMessage(bpcontent)) {
                    val plain = tryDecrypt(parsed.payload)
                    if(plain != null) {
                        val pb = if(parsed.responseIdentifier == null)
                            ProtobufParser().parse(plain.fromIndex(3))
                        else
                            ProtobufParser().parse(plain.fromIndex(2))

                        try {
                            println(NanoSyncMessage.fromSafePB(pb))
                        }
                        catch(e: Exception) {
                            // if we fail parsing something, print the failing protobuf for debugging and then still fail
                            println("Failed while parsing: $pb")
                            println("bytes: ${plain.hex()}")
                            println(e.toString())
                        }
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
                        catch(_: Exception) {}
                    }
                }
            }
        }
        is ProtobufMessage -> {
            // for some reason Protobuf messages sometimes carry, guess what, bplists
            if(BPListParser.bufferIsBPList(parsed.payload)) {
                val bpcontent = BPListParser().parse(parsed.payload)
                if(Decryptor.isEncryptedMessage(bpcontent)) {
                    val plain = tryDecrypt(parsed.payload)
                    println(plain?.hex())
                }
                else
                    println(bpcontent)
            }
            else {
                try {
                    println(ProtobufParser().parse(parsed.payload))
                } catch(_: Exception){
                    // Protobuf payloads sometimes hava a 2 byte non-protobuf trailer
                    try {
                        println(ProtobufParser().parse(parsed.payload.copyOfRange(0, parsed.payload.size-2)))
                    } catch(_: Exception){

                    }
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