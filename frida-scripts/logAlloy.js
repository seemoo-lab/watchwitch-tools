console.log("reloaded")

// don't log Alloy data channel messages (useful when you only care about control messages etc)
const muteUTun = false

// log A-over-C plaintexts before encryption, as we cannot decrypt them later without the watch's private keys
// WILL contain potentially sensitive health information and PRIVATE RSA KEY
const logAoverCplaintexts = true

// if logging AoverC, we export the RSA private key for decryption of received A-over-C messages -- but only once per key
let loggedKey = null

// Hooks:

// UTun Processed Packet Receive (before defrag)
Interceptor.attach(ObjC.classes.IDSUTunConnection['- _processDecryptedMessage:'].implementation, {
  onEnter(args) {
    const packet = ObjC.Object(args[2])
    const type = packet.command()
    const payload = packet.underlyingData()

    const hex = readHex(payload.bytes(), payload.length())
    if(!muteUTun)
      console.log(`rcv utun ${type} ${hex}`)
  }
})

// UTun Raw Packet Receive (before defrag)
/*Interceptor.attach(ObjC.classes.IDSNWSocketPairConnection['- _processIncomingRawMessage:'].implementation, {
  onEnter(args) {
    const packet = ObjC.Object(args[2])
    const type = packet.command()
    const payload = packet.underlyingData()

    const hex = readHex(payload.bytes(), payload.length())
    if(!muteUTun)
      console.log(`rcv utun ${type} ${hex}`)
  }
})*/

Interceptor.attach(ObjC.classes.IDSLinkManager['- _processLMCommandPacket:fromLink:deviceUniqueID:cbuuid:'].implementation, {
  onEnter(args) {
    const data = args[2]
    const hex = readHex(data, 24)

    // this is just the start of the packet data structure
    // not entirely sure about the structure, but should contain payload pointer and length
    console.log(`rcv lmc ${hex}`)
  }
})

Interceptor.attach(ObjC.classes.IDSUTunController['- receiveControlChannelMessage:fromCbuuid:deviceUniqueID:'].implementation, {
  onEnter(args) {
    const payload = ObjC.Object(args[2])
  
    const hex = readHex(payload.bytes(), payload.length())
    console.log(`rcv utunctrl ${hex}`)
  }
})

Interceptor.attach(ObjC.classes.IDSUTunConnection['- _sendOTREncryptedMessage:useEncryption:streamID:forPriority:flag:token:'].implementation, {
  onEnter(args) {
    const packet = ObjC.Object(args[2])
    const type = packet.command()
    const payload = packet.underlyingData()

    const encrypt = args[3]

    // when we send, the packet bytes include 1 byte type and 4 byte length, which we do not get in the receiving function
    // so we'll strip those bytes to even things out
    const hex = readHex(payload.bytes().add(5), payload.length()-5)

    if(muteUTun)
      return

    console.log(`snd utun ${type} ${hex}`)

    if(encrypt != 0){
      console.log("SENDING OTR ENCRYPTED")
      console.log(encrypt)
    }
  }
})

Interceptor.attach(ObjC.classes.IDSEncryptionHelpers['+ encryptLocalDeliveryPayload:toDevice:forService:withDataProtectionClass:encryptionType:priority:error:'].implementation, {
  onEnter(args) {
    const payload = ObjC.Object(args[2])
   
    const hex = readHex(payload.bytes(), payload.length())
    this.plaintext = hex
  },
  onLeave(retval) {
    const encodedDict = ObjC.Object(retval)
    const ciphertext = readHex(encodedDict.bytes(), encodedDict.length())
    
    if(logAoverCplaintexts)
      console.log(`aovercmap ${ciphertext} ${this.plaintext}`)
  }
})

Interceptor.attach(ObjC.classes.IDSUTunControlChannel['- sendMessage:'].implementation, {
  onEnter(args) {
    const payload = ObjC.Object(args[2])

    const hex = readHex(payload.bytes(), payload.length())
    console.log(`snd utunctrl ${hex}`)
  }
})

Interceptor.attach(ObjC.classes.IDSUTunControlChannel['- sendPriorityMessage:'].implementation, {
  onEnter(args) {
    const payload = ObjC.Object(args[2])

    const hex = readHex(payload.bytes(), payload.length())
    console.log(`snd utunctrl ${hex}`)
  }
})

Interceptor.attach(ObjC.classes.IDSUTunControlChannel['- useConnection:withFirstMessage:'].implementation, {
  onEnter(args) {
    const payload = ObjC.Object(args[3])

    const hex = readHex(payload.bytes(), payload.length())
    console.log(`snd utunctrl ${hex}`)
  }
})

// somehow replies to arriving messages don't show up if we hook only sendMessage (even though they should?) so we fish them out from writeToConnection
// this produces duplicate log entries, but we can live with that
Interceptor.attach(ObjC.classes.IDSUTunControlChannel['- writeToConnection'].implementation, {
  onEnter(args) {
    const payload = ObjC.Object(args[0].add(0x38).readPointer())
    const hex = readHex(payload.bytes(), payload.length())
    console.log(`snd utunctrl ${hex.substring(4)}`)
  }
})



const verifyexpose = Module.getExportByName('MessageProtection', 'SecMPVerifyAndExposeMessage')

const verifysignature = Module.getExportByName('MessageProtection', 'SecKeyVerifySignature')
const decrypt = Module.getExportByName('MessageProtection', 'SecKeyCreateDecryptedData')

const rsa = Module.getExportByName('libcorecrypto.dylib', 'ccrsa_priv_crypt')
const encodePrivKeySize = Module.getExportByName('libcorecrypto.dylib', 'ccder_encode_rsa_priv_size')
const encodePrivKey = Module.getExportByName('libcorecrypto.dylib', 'ccder_encode_rsa_priv')

const cryptor = Module.getExportByName('libcommonCrypto.dylib', 'CCCryptorCreate')

Interceptor.attach(verifyexpose, {
  outbuf: null,
  onEnter(args) {
    const message = ObjC.Object(args[0])
    const publicIdentity = args[1]
    const fullIdentity = args[2]

    this.outbuf = args[3]

    //console.log("VerifyExpose")
    const hex = readHex(message.bytes(), message.length())
    //console.log(hex)
    //console.log(fullIdentity)
    const privKey = fullIdentity.add(40).readPointer()
    //console.log(ObjC.Object(privKey))
  },

  onLeave(retval) {
    //console.log(ObjC.Object(this.outbuf))
  },
  
})

Interceptor.attach(verifysignature, {
  onEnter(args) {
    const key = ObjC.Object(args[0])
    const algo = ObjC.Object(args[1])
    const a = ObjC.Object(args[2])
    const b = ObjC.Object(args[3])

    //console.log(`SecKeyVerifySignature ${a} ${b} ${algo} ${key}`)
  },
  
})

Interceptor.attach(decrypt, {
  onEnter(args) {
    const keyRef = ObjC.Object(args[0])
    const b = args[1]
    const data = ObjC.Object(args[2])
    const d = args[3]

    const key = keyRef.addr

    //console.log(`SecKeyCreateDecryptedData ${keyRef} ${b} ${data} ${key}`)
  },
  
})

Interceptor.attach(rsa, {
  onEnter(args) {
    const key = args[0]
    const out = args[1]
    const inp = args[2]

    //console.log(`ccrsa_priv_crypt ${key} ${out} ${inp}`)

    if(logAoverCplaintexts) {
      const getEncodedSize = new NativeFunction(encodePrivKeySize, 'int', ['pointer'])
      const encodePriv = new NativeFunction(encodePrivKey, 'pointer', ['pointer', 'pointer', 'pointer'])

      const size = getEncodedSize(key)
      const buf = Memory.alloc(size)

      encodePriv(key, buf, buf.add(size))
      const encoded = readHex(buf, size)

      if(encoded != loggedKey) {
        console.log("aovercrsa " + encoded)
        loggedKey = encoded
      }
    }
  },
  
})

Interceptor.attach(cryptor, {
  onEnter(args) {

    const op = args[0]
    const alg = args[1]
    const options = args[2]
    const key = args[3]
    const keyLen = args[4]
    const iv = args[5]

    //console.log(`CCCryptorCreate ${op} ${alg} ${options} keylen ${keyLen} key ${readHex(key, keyLen)} iv ${iv}`)
  },
})


// end hooks

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