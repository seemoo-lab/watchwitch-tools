// Some logging config:
const showIKEv2Payloads = false
const ignoreIKEv2InfoPackets = false
const showChaChaPlaintexts = false
const showEd25519Payloads = false
const showEDHKeys = false
const showHMACdata = false

console.log("reloaded")

const sessionTypeMapping = new Map();

const packetDedupe = new Map();
const oooSeqs = new Map();

var encryptBuffer = ""
var decryptBuffer = ""
const plaintextLookup = new Map()
const outstandingCiphertexts = new Map()

// Hooks:

// IKEv2 packet receive hook (required for logging incoming packets)
Interceptor.attach(ObjC.classes.NEIKEv2Transport['- receivePacketData:'].implementation, {
  packet: null,
  onEnter(args) {
    this.packet = ObjC.Object(args[2])
  },
  onLeave(retval) {
    //logIKEv2Packet(this.packet) // Log only after handling is complete to have decryption available
  }
})

try {


  // IKEv2 packet send hook (required for logging outgoing packets)
  Interceptor.attach(ObjC.classes.NEIKEv2Packet['- setPacketDatagrams:'].implementation, {
    packet: null,
    onEnter(args) {
      this.packet = args[0]
    },
    onLeave(retval) {
      const packet = ObjC.Object(this.packet).packetDatagrams().firstObject()
      logIKEv2Packet(packet)
    }
  })
  } catch (error) {
  log("ERROR! Couldn't hook NEIKEv2Packet class! (old function names)")
}

try {
  Interceptor.attach(ObjC.classes.NRLinkBluetooth['- sendPacketData:'].implementation, {
    packet: null,
    onEnter(args) {
      this.packet = ObjC.Object(args[2])
    },
    onLeave(retval) {
      logIKEv2Packet(this.packet) // Log only after handling is complete to have decryption available
    }
  })

  //TODO send

} catch (error) {
  log("ERROR! Couldn't hook NEIKEv2Transport class! (new function names)")
}
// Encryption / decryption hooks (required to show plaintext IKEv2 packets)

const ccchacha20poly1305_encrypt = Module.getExportByName('libcorecrypto.dylib', 'ccchacha20poly1305_encrypt')
const ccchacha20poly1305_decrypt = Module.getExportByName('libcorecrypto.dylib', 'ccchacha20poly1305_decrypt')

Interceptor.attach(ccchacha20poly1305_encrypt, {
  ciphertext: null,
  plaintext: null,
  len: null,
  onEnter(args) {
    this.len = args[2]
    const data = args[3]
    this.ciphertext = args[4]

    const bytes = readHex(data, this.len)
    encryptBuffer += bytes
    this.plaintext = bytes

    if(showChaChaPlaintexts)
      log(`Encrypting ${this.len} bytes`, 4)
  },
  onLeave(retval) {
    const cipher = readHex(this.ciphertext, this.len)
    plaintextLookup.set(cipher, this.plaintext)
    //console.log(`${cipher} -> ${this.plaintext}`)
  }
})

Interceptor.attach(ccchacha20poly1305_decrypt, {
  len: 0,
  data: null,
  onEnter(args) {
    this.len = args[2]
    this.data = args[4]
    this.ciphertext = readHex(args[3], this.len)
  },
  onLeave(retval) {
    const bytes = readHex(this.data, this.len)
    decryptBuffer += bytes

    plaintextLookup.set(this.ciphertext, bytes)

    if(showChaChaPlaintexts)
      log(`Decrypting ${this.len} bytes`, 4)

    if(outstandingCiphertexts.has(this.ciphertext)) {
      const packet = outstandingCiphertexts.get(this.ciphertext)
      outstandingCiphertexts.delete(this.ciphertext)
      logIKEv2Packet(packet, true)
    }
  }
})

//const ccgcm_update = Module.getExportByName('libcorecrypto.dylib', 'ccgcm_update')
//const gcm_decrypt = Module.getExportByName('libcorecrypto.dylib', 'ccmode_gcm_decrypt')


  // Interceptor.attach(gcm_encrypt, {
  //   ciphertext: null,
  //   plaintext: null,
  //   len: null,
  //   onEnter(args) {
  //     this.len = args[1]
  //     const data = args[2]
  //     this.ciphertext = args[3]

  //     const bytes = readHex(data, this.len)
  //     encryptBuffer += bytes
  //     this.plaintext = bytes

  //     if(showChaChaPlaintexts)
  //       log(`Encrypting ${this.len} bytes`, 4)
  //   },
  //   onLeave(retval) {
  //     const cipher = readHex(this.ciphertext, this.len)
  //     plaintextLookup.set(cipher, this.plaintext)
  //   }
  // })


// Optional encrypt / decrypt hooks, for prettier logging only

const ccchacha20poly1305_verify = Module.getExportByName('libcorecrypto.dylib', 'ccchacha20poly1305_verify')
const ccchacha20poly1305_finalize = Module.getExportByName('libcorecrypto.dylib', 'ccchacha20poly1305_finalize')

Interceptor.attach(ccchacha20poly1305_verify, {
  onEnter(args) {
    if(!showChaChaPlaintexts)
      return
    console.log("Complete plaintext bytes:")
    console.log(readableHex(decryptBuffer))
    decryptBuffer = ""
  }
})

Interceptor.attach(ccchacha20poly1305_finalize, {
  onEnter(args) {
    if(!showChaChaPlaintexts)
      return

    console.log("Complete plaintext bytes:")
    console.log(readableHex(encryptBuffer))
    encryptBuffer = ""
  }
})

// Diffie-Hellman exchange hook (required for IKEv2 & ESP decryption in trafficlogger.py, optional for standalone use)

try {
  Interceptor.attach(ObjC.classes.NEIKEv2DHKeys["- createSharedSecretForECPKey:curveKey:remotePublicKey:publicKeySize:dhContext:"].implementation, {
    pubkey: null,
    onEnter(args) {
      const keylen = args[5]

      const remotePubKey = new ObjC.Object(args[4])
      const rawPubKey = readHex(remotePubKey.bytes(), remotePubKey.length())
      this.pubkey = rawPubKey

      if(showEDHKeys) {
        console.log("Computing DH shared secret, remote pub key:")
        console.log(readableHex(rawPubKey))
      }
    },
    onLeave(retval) {
      const returned = new ObjC.Object(retval)
      const sharedKey = readHex(returned.bytes(), returned.length())

      send(["dhkey", this.pubkey, sharedKey])

      if(showEDHKeys) {
        console.log(`Shared secret:`)
        console.log(readableHex(sharedKey))
      }
    }
  })
} catch (error) {
  log("ERROR! Couldn't hook NEIKEv2DHKeys class!")
}

// Signature generation & verification hooks, very optional, only required to debug signatures

const ed25519_sign = Module.getExportByName('libcorecrypto.dylib', 'cced25519_sign');
const ed25519_verify = Module.getExportByName('libcorecrypto.dylib', 'cced25519_verify')

Interceptor.attach(ed25519_sign, {
  sigBuffer: null,
  onEnter(args) {
    const len = args[2]
    const data = args[3]
    this.sigBuffer = args[1]

    if(showEd25519Payloads) {
      log(`Signing ${len} bytes`, 4)
      console.log(readableHex(readHex(data, len)))
    }
  },
  onLeave(retval) {
    if(showEd25519Payloads) {
      console.log(readableHex(readHex(this.sigBuffer, 64)))
    }
  }
})

Interceptor.attach(ed25519_verify, {
  onEnter(args) {
    const len = args[1]
    const data = args[2]
    const pubkey = args[4]

    if(showEd25519Payloads) {
      log(`Verifying ${len} bytes`, 4)
      console.log(readHex(pubkey, 64))
      console.log(readableHex(readHex(data, len)))
    }
  }
})

// HMAC calculation hook, very optional, debugging only

const cchmac = Module.getExportByName('libcorecrypto.dylib', 'cchmac')

Interceptor.attach(cchmac, {
  data: null,
  dataLen: 0,
  mac: null,
  onEnter(args) {
    this.key = readHex(args[2], args[1])
    this.dataLen = args[3]
    this.data = args[4]
    this.mac = args[5]
  },
  onLeave(retVal) {
    if(!showHMACdata)
      return
    const mac = readHex(this.mac, 64)
    const data = readHex(this.data, this.dataLen)
    log(`MAC (key ${this.key}) for data ${data}`)
    log(mac)
  }
})

// END HOOKS

const notifyTypes = ["INITIAL_CONTACT", "SET_WINDOW_SIZE", "ADDITIONAL_TS_POSSIBLE", "IPCOMP_SUPPORTED", "NAT_DETECTION_SOURCE_IP", "NAT_DETECTION_DESTINATION_IP", "COOKIE", "USE_TRANSPORT_MODE", "HTTP_CERT_LOOKUP_SUPPORTED", "REKEY_SA", "ESP_TFC_PADDING_NOT_SUPPORTED", "NON_FIRST_FRAGMENTS_ALSO", "MOBIKE_SUPPORTED", "ADDITIONAL_IP4_ADDRESS", "ADDITIONAL_IP6_ADDRESS", "NO_ADDITIONAL_ADDRESSES", "UPDATE_SA_ADDRESSES", "COOKIE2", "NO_NATS_ALLOWED", "AUTH_LIFETIME", "MULTIPLE_AUTH_SUPPORTED", "ANOTHER_AUTH_FOLLOWS", "REDIRECT_SUPPORTED", "REDIRECT", "REDIRECTED_FROM", "TICKET_LT_OPAQUE", "TICKET_REQUEST", "TICKET_ACK", "TICKET_NACK", "TICKET_OPAQUE", "LINK_ID", "USE_WESP_MODE", "ROHC_SUPPORTED", "EAP_ONLY_AUTHENTICATION", "CHILDLESS_IKEV2_SUPPORTED", "QUICK_CRASH_DETECTION", "IKEV2_MESSAGE_ID_SYNC_SUPPORTED", "IPSEC_REPLAY_COUNTER_SYNC_SUPPORTED", "IKEV2_MESSAGE_ID_SYNC", "IPSEC_REPLAY_COUNTER_SYNC", "SECURE_PASSWORD_METHODS", "PSK_PERSIST", "PSK_CONFIRM", "ERX_SUPPORTED", "IFOM_CAPABILITY", "SENDER_REQUEST_ID", "IKEV2_FRAGMENTATION_SUPPORTED", "SIGNATURE_HASH_ALGORITHMS", "CLONE_IKE_SA_SUPPORTED", "CLONE_IKE_SA", "PUZZLE", "USE_PPK", "PPK_IDENTITY", "NO_PPK_AUTH", "INTERMEDIATE_EXCHANGE_SUPPORTED", "IP4_ALLOWED", "IP6_ALLOWED"]
const errorTypes = ["UNSUPPORTED_CRITICAL_PAYLOAD", "INVALID_IKE_SPI", "INVALID_MAJOR_VERSION", "INVALID_SYNTAX", "INVALID_MESSAGE_ID", "INVALID_SPI", "NO_PROPOSAL_CHOSEN", "INVALID_KE_PAYLOAD", "AUTHENTICATION_FAILED", "SINGLE_PAIR_REQUIRED", "NO_ADDITIONAL_SAS", "INTERNAL_ADDRESS_FAILURE", "FAILED_CP_REQUIRED", "TS_UNACCEPTABLE", "INVALID_SELECTORS", "TEMPORARY_FAILURE", "CHILD_SA_NOT_FOUND"]

const privateNotifyTypes = {
  48601: "Encrypted prelude",
  48602: "Remote terminus version",
  48603: "Remote device name",
  48604: "Remote build version",
  50701: "ProxyNotifyPayload?",
  50702: "LinkDirectorMessage",
  50801: "InnerAddressInitiatorClassD",
  50802: "InnerAddressResponderClassD",
  50811: "InnerAddressInitiatorClassC",
  50812: "InnerAddressResponderClassC",
  51401: "Always-On WiFi support",
  51501: "IsAltAccountDevice",
}

const linkDirectorMsgTypes = [
  "Invalid",
  "Hello",
  "UpdateWiFiAddressIPv6",
  "UpdateWiFiAddressIPv4",
  "UpdateWiFiSignature",
  "PreferWiFi",
  "DeviceLinkState",
  "PreferWiFiAck",
  "ForceWoW"
]

function log(msg, color = 7) {
  console.log(msg)
  //console.log(`\x1b[1;3${color}m${msg}\x1b[0m`)
}

function readReversedWord(pointer) {
  const a = pointer.readU8()
  const b = pointer.add(1).readU8()
  const c = pointer.add(2).readU8()
  const d = pointer.add(3).readU8()
  return (((a << 8) + b << 8) + c << 8) + d
}

function readHex(pointer, length) {
  let res = ""
  for(var i = 0; i < length; i++) {
    const hexByte = pointer.add(i).readU8().toString(16)
    res += (hexByte.length == 1 ? "0" + hexByte : hexByte)
  }
  return res
}

function readableHex(hex) {
  return hex.match(/.{2,32}/g).map(line => line.split(/(?=(?:..)*$)/).join(" ")).join("\n");
}

function objInfo(obj) {
  console.log(obj.$className)
  console.log(obj.$methods)
}

function exchangeTypeToString(type) {
  return ["SA_INIT", "AUTH", "CHILD_SA", "INFO"][type - 34]
}

function nextPayloadToString(nextPayload) {
  if(nextPayload == 0)
    return "None"
  return ["SA", "KEx", "IDinit", "IDresp", "CERT", "CERTREQ", "AUTH", "NONCE", "NOTIFY", "DELETE", "VENDOR", "TSi", "TSr", "ENC&AUTH", "CONFIG", "EAP"][nextPayload - 33]
}

function logIKEv2Packet(packet, delayedDecrypt = false) {
  const bytes = packet.bytes()

  const initiatorCookie = readHex(bytes, 8)
  const responderCookie = readHex(bytes.add(8), 8)

  const flagNextPayload = bytes.add(16).readU8()
  const flagExchangeType = bytes.add(18).readU8()
  const flagFlags = bytes.add(19).readU8()

  const isFromInitiator = (flagFlags & 0b00001000) != 0
  const incoming = isFromInitiator

  const stringType = exchangeTypeToString(flagExchangeType)
  const stringPayload = nextPayloadToString(flagNextPayload)

  const sequenceNo = readReversedWord(bytes.add(20))
  const packetLength = readReversedWord(bytes.add(24))

  // We might receive packets multiple times (due to handling code calling setPacketDatagrams several times)
  // unfortunately setPacketDatagrams seems to be the only way to get WiFi-sent packets (there probably is a better way but I haven't found it yet)
  // so we'll work some magic to manually discard packets we've already seen
  if(!delayedDecrypt) { // delayed decrypt packets have already passed duplicate inspection
    const dedupeContext = isFromInitiator ? initiatorCookie : responderCookie
    if(!packetDedupe.has(dedupeContext)) {
      packetDedupe.set(dedupeContext, -1)
      oooSeqs.set(dedupeContext, new Set())
    }
    let confirmedBoundary = packetDedupe.get(dedupeContext)
    const oooSeqsCtx = oooSeqs.get(dedupeContext)

    if(confirmedBoundary >= sequenceNo || oooSeqsCtx.has(sequenceNo)) {
      //log("rejecting duped packet " + sequenceNo)
      return
    }
    else if(confirmedBoundary + 1 == sequenceNo) {
      confirmedBoundary += 1
      packetDedupe.set(dedupeContext, confirmedBoundary)

      // check if the received sequence number makes previously received future sequence numbers continuous
      // this doesn't happen a lot so i don't actually know if it works
      const sorted = Array.from(oooSeqsCtx.values()).sort()
      while(sorted.length > 0 && sorted[0] == confirmedBoundary + 1) {
        confirmedBoundary += 1
        sorted.splice(0, 1)
      }
      //log("increasing confirmed boundary to " + confirmedBoundary)
    }
    else {
      if(oooSeqsCtx.has(sequenceNo)) {
        //log("rejecting duped packet " + sequenceNo)
        return
      }
      else {
        oooSeqsCtx.add(sequenceNo)
        log("got unexpected future seq " + sequenceNo)
      }
    }
  }

  if(stringType == "INFO" && ignoreIKEv2InfoPackets)
    return

  let payload = readHex(bytes.add(28), packetLength - 28)
  let plainPayload = payload
  let firstPayloadType = flagNextPayload
  let isDecrypted = false

  if(stringType == "SA_INIT" && responderCookie != "0000000000000000")
    send(["cookies", initiatorCookie, responderCookie])

  if(stringPayload == "ENC&AUTH") {
    const offset = 28 + 4 + 8 // offset to payload header + generic payload header length + initialization vector length
    const effectivePayload = readHex(bytes.add(offset), packetLength - offset - 16) // 16 tailing checksum bytes
    if(plaintextLookup.has(effectivePayload)) {
      const plaintext = plaintextLookup.get(effectivePayload)
      plaintextLookup.delete(effectivePayload)

      const header = readHex(bytes.add(28), 4)
      const iv = "a0a0a0a0a0a0a0a0"
      const checksum = "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"
      payload = header + iv + plaintext + checksum
      plainPayload = plaintext
      isDecrypted = true

      firstPayloadType = bytes.add(28).readU8()
    }
    // decryption not available yet
    else {
      //log("got encrypted IKE message but don't know how to decipher :(")
      outstandingCiphertexts.set(effectivePayload, packet)
      return
    }
  }

  log("\n")

  if(delayedDecrypt)
    log("[delayed decrypt]")

  log(`${incoming ? "incoming" : "outgoing"} IKE Data, seq: ${sequenceNo}, type: ${stringType}, payload: ${stringPayload}, len: ${packetLength} B`, incoming ? 2 : 3)
  log(`InitCookie: ${initiatorCookie} RespCookie: ${responderCookie}`, incoming ? 2 : 3)

  if(showIKEv2Payloads)
    log(readableHex(payload), isDecrypted ? 6 : 7)

  analyzeIKEv2Payloads(firstPayloadType, plainPayload, initiatorCookie, isFromInitiator)

  log("")
}

function analyzeIKEv2Payloads(firstType, payloads, initiatorCookie, isFromInitiator) {
  if(firstType == 0) {
    log("NULL payload / keepalive ping")
    return
  }

  const nextPayloadType = parseInt(payloads.substring(0, 2), 16)
  const payloadLength = parseInt(payloads.substring(4, 8), 16)

  analyzeSingleIKEv2Payload(firstType, payloads.substring(4 * 2, payloadLength * 2), initiatorCookie, isFromInitiator)

  if(nextPayloadType != 0)
    analyzeIKEv2Payloads(nextPayloadType, payloads.substring(payloadLength * 2), initiatorCookie, isFromInitiator)
}

function analyzeSingleIKEv2Payload(type, payload, initiatorCookie, isFromInitiator) {
  const stringType = nextPayloadToString(type)

  if(stringType == "NOTIFY") {
    const notifyType = parseInt(payload.substring(4, 8), 16)
    if(notifyType < 16384)
      log("NOTIFY - error: " + errorTypes[notifyType])
    else if(notifyType > 40960)
      handlePrivateNotify(notifyType, payload.substring(8))
    else {
      log("NOTIFY - " + notifyTypes[notifyType - 16384])
      if(payload.length > 8)
        log(payload.substring(8))
    }
  }
  else if(stringType == "SA") {
    log("SA")

    while(payload.length >= 16) {
      const proposalLength = parseInt(payload.substring(4, 8), 16)
      const proposalNum = parseInt(payload.substring(8, 10), 16)
      const protocolID = parseInt(payload.substring(10, 12), 16)
      const spiSize = parseInt(payload.substring(12, 14), 16)
      const numTransforms = parseInt(payload.substring(14, 16), 16)
      const protocol = ["IKE", "AH", "ESP"][protocolID - 1]

      const spi = payload.substring(16, 16 + 2 * spiSize)
      const transforms = payload.substring(16 + 2 * spiSize, proposalLength * 2)

      if(spiSize > 0)
        send(["spi", initiatorCookie, isFromInitiator, spi, sessionTypeMapping.get(initiatorCookie)])

      log(`-> Proposal #${proposalNum}: ${numTransforms} transforms, protocol ${protocol}, SPI size ${spiSize}`)
      log(transforms)

      payload = payload.substring(proposalLength * 2)
    }
  }
  else if(stringType == "NONCE") {
    log("NONCE - " + payload)
    send(["nonce", initiatorCookie, isFromInitiator, payload])
  }
  else if(stringType == "KEx") {
    const keyshare = payload.substring(8)
    send(["pubkey", initiatorCookie, isFromInitiator, keyshare]) // we have to look up pubkeys to IKE contexts to associate DH keyshares correctly
    log("KEx - " + keyshare)
  }
  else if(stringType == "CONFIG") {
    const configTypes = ["CFG_REQUEST", "CFG_REPLY", "CFG_SET", "CFG_ACK"]
    const configType = parseInt(payload.substring(0, 2), 16)
    log("CONFIG - " + configTypes[configType - 1])
  }
  else if(stringType == "IDinit" || stringType == "IDresp") {
    const idType = parseInt(payload.substring(0, 2), 16)
    const id = payload.substring(8)
    let stringID = id

    if(idType == 11) {
      stringID = ""
      for(var i=8; i < payload.length-1; i+=2)
        stringID += String.fromCharCode(parseInt(payload.substr(i, 2), 16))
    }

    log(`${stringType} - ID type ${idType} value ${stringID}`)

    // remember which type of channel we are establishing here
    if(stringID.endsWith("classC"))
      sessionTypeMapping.set(initiatorCookie, "classC")
    else if(stringID.endsWith("classD"))
      sessionTypeMapping.set(initiatorCookie, "classD")
  }
  else if(stringType == "AUTH") {
    const authType = parseInt(payload.substring(0, 2), 16)
    const authData = payload.substring(8)

    // generic signature auth https://www.rfc-editor.org/rfc/rfc7427.html
    if(authType == 14) {
      const asn1Length = parseInt(authData.substring(0, 2), 16)
      const asn1 = authData.substr(2, asn1Length*2)
      const sig = authData.substr(2 + asn1Length*2)
      log(`AUTH - Digital Signature - ASN.1: ${asn1} Signature: ${sig}`)
    }
    else
      log(`AUTH - type ${authType} data ${authData}`)
  }
  else
    log(stringType)
}

function handlePrivateNotify(type, payload){
  if(privateNotifyTypes[type] == "LinkDirectorMessage") {
    const version = parseInt(payload.substring(0, 2), 16)
    const length = payload.substring(4, 8)
    //const identifier = payload.substring(16, 32)
    var TLVs = payload.substring(32)
    log(`NOTIFY - LinkDirectorMessage(v${version}, len 0x${length}) `)

    while(TLVs.length > 3) {
      const type = parseInt(TLVs.substring(0, 2), 16)
      const len = parseInt(TLVs.substring(2, 6), 16)
      const value = TLVs.substring(6, 6 + len*2)
      log(`-> TLV ${linkDirectorMsgTypes[type]}: 0x${value}`)
      TLVs = TLVs.substring(6 + len*2)
    }
  }
  else if(privateNotifyTypes[type]) {
    const stringType = privateNotifyTypes[type]
    let stringValue = payload

    if(stringType == "Remote device name" || stringType == "Remote build version") {
      stringValue = ""
      for(var i=0; i < payload.length-1; i+=2)
        stringValue += String.fromCharCode(parseInt(payload.substr(i, 2), 16))
    }

    log("NOTIFY - " + stringType + " " + stringValue)
  }
  else
    log("NOTIFY - unknown private type " + type + " " + payload)
}