// Adapted from https://github.com/seemoo-lab/internalblue/blob/master/examples/keychange/ios_keychange.js

var base = Module.getBaseAddress('bluetoothd')

var OI_HCIIfc_DataReceived = base.add(0xed9f8)  // iOS 14.8, iPhone 8
var OI_HciIfc_CopyPayload = base.add(0xe3764)  // iOS 14.8, iPhone 8
var HCIIfc_src_ptr = base.add(0x688518)  // iOS 14.8, iPhone 8

function readHex(pointer, length) {
  let res = ""
  for(var i = 0; i < length; i++) {
    const hexByte = pointer.add(i).readU8().toString(16)
    res += (hexByte.length == 1 ? "0" + hexByte : hexByte)
  }
  return res
}

// *** Receiving direction *** (Chip -> iOS)
// OI_HCIIfc_DataReceived gets all packet types. It then calls
// HCI/SCO/ACL in the next step, and with one function in between
// ends up in OI_HCIIfc_AclPacketReceived (aka acl_recv).
// We don't necessarily need this but at least we can print if a
// key was requested.

Interceptor.attach(OI_HCIIfc_DataReceived, {
    onEnter: function(args) {

        const h4t = parseInt(this.context.x0)  // ACL/SCO/HCI
        const acl = this.context.x1
        const len = parseInt(this.context.x2)

        const data = readHex(acl, len)

        send(["rcv", len, h4t, data])

        // Uncomment this to filter for a specific type:
        //  HCI: 0x01 (command, invalid in this direction)
        //  ACL: 0x02
        //  SCO: 0x03
        //  HCI: 0x04 (events + BLE data, this is valid)
        //  DIAG: 0x07 (should be disabled here)

        //if (h4t == 4) {
        //}
    }
});

// *** Sending direction *** (iOS -> Chip)
// We need to exchange the original key here.
var OI_HciIfc_CopyPayload_dst = 0
Interceptor.attach(OI_HciIfc_CopyPayload, {
    onEnter: function(args) {
        // save the payload pointer argument
        OI_HciIfc_CopyPayload_dst = this.context.x0
    },
    onLeave: function(args) {

        // Intercept all data from the global struct.
        // OI_HciIfc_CopyPayload doesn't intercept the H4 type but we
        // might want to distinguish between ACL/HCI/... for fuzzing.
        var h4t = HCIIfc_src_ptr.add(0x10).readU8()
        var hnd = HCIIfc_src_ptr.add(0x18).readU16()
        var len = HCIIfc_src_ptr.add(0x1c).readU16()

        // This is the data. Depending on the H4 type, it needs to
        // be reassembled differently (different length positions etc.)
        var data = readHex(OI_HciIfc_CopyPayload_dst, len)

        send(["snd", len, h4t, data])
    }
});