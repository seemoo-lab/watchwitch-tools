log("reloaded", 1)
log("Toggle bluetooth to capture long-term Ed25519 keys")
log("Class associations are somewhat unreliable, don't trust them too much")

const ed25519_sign = Module.getExportByName('libcorecrypto.dylib', 'cced25519_sign')
const ed25519_verify = Module.getExportByName('libcorecrypto.dylib', 'cced25519_verify')

const ccchacha20poly1305_encrypt = Module.getExportByName('libcorecrypto.dylib', 'ccchacha20poly1305_encrypt')
const ccchacha20poly1305_decrypt = Module.getExportByName('libcorecrypto.dylib', 'ccchacha20poly1305_decrypt')

var expectSign = "unknown"
var expectVerify = "unknown"
var privKeyBuf = ""

function log(msg, color = 7) {
  //console.log(msg)
  console.log(`\x1b[1;3${color}m${msg}\x1b[0m`)
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
  return hex.match(/.{2,32}/g).map(line => line.split(/(?=(?:..)*$)/).join(" ")).join("\n")
}

Interceptor.attach(ObjC.classes.NRLinkBluetooth['- handleIncomingIKEData:'].implementation, {
  packet: null,
  onEnter(args) {
    const data = new ObjC.Object(args[2]).bytes()
  }
})

Interceptor.attach(ObjC.classes.NRLinkBluetooth['- sendIKEData:'].implementation, {
  onEnter(args) {
    const data = new ObjC.Object(args[2]).bytes()
  }
})

Interceptor.attach(ed25519_verify, {
  onEnter(args) {
    const len = args[1]
    const data = args[2]
    const pk = args[4]

    //log(`ed25519_verify on ${len} bytes with public key, expecting ${expectVerify}:`, 4)
    log(`Got watch public key for channel: ${expectVerify}`, 4)
    log(readHex(pk, 32))
    expectVerify = "unknown"
  }
})

Interceptor.attach(ed25519_sign, {
  onEnter(args) {
    const len = args[2]
    const data = args[3]
    const sk = args[5]

    //log(`ed25519_sign on ${len} bytes`, 4)
    //log(readHex(sk, 32))
    privKeyBuf = readHex(sk, 32)
  }
})


Interceptor.attach(ccchacha20poly1305_encrypt, {
  onEnter(args) {
    this.len = args[2]
    const data = args[3]

    const plaintextHex = readHex(data, this.len)
    
    if(plaintextHex.indexOf("636c61737344") != -1) {
      expectSign = "classD"
      //log("Encrypt matching classD")
    }
    else if(plaintextHex.indexOf("636c61737343") != -1) {
      expectSign = "classC"
      //log("Encrypt matching classC")
    }

    if(privKeyBuf != "") {
      log(`Got phone private key for channel: ${expectSign}`, 4)
      log(privKeyBuf)
      privKeyBuf = ""
    }

    expectSign = "unknown"
  }
})

Interceptor.attach(ccchacha20poly1305_decrypt, {
  len: 0,
  data: null,
  onEnter(args) {
    this.len = args[2]
    this.data = args[4]
  },
  onLeave(retval) {
    const plaintextHex = readHex(this.data, this.len)

    if(plaintextHex.indexOf("636c61737344") != -1) {
      expectVerify = "classD"
      //log("Decrypt matching classD")
    }
    else if(plaintextHex.indexOf("636c61737343") != -1) {
      expectVerify = "classC"
      //log("Decrypt matching classC")
    }
  }
})