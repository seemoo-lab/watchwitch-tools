import re
import sys
import frida
import signal
from string import Template

from pcapwriter import pcapWriter
from espdecryptor import EspDecryptor
from tcphandler import TcpHandler
from dataarchiver import DataArchiver

unexplainedOnly = False
extractTCPPayloads = False
collectData = False # build an archive of observed protocol payloads (for interesting protocols only)

device = frida.get_usb_device()

terminus = device.attach("terminusd")
bluetoothd = device.attach("bluetoothd")

ikeFile = open("tl-ike.js","r")
ikeScript = terminus.create_script(ikeFile.read())
ikeFile.close()

bleFile = open("tl-bt.js", "r")
bleScript = bluetoothd.create_script(bleFile.read())
bleFile.close()

cookies = set()
spis = set()

aclRcvFragBuffer = ""
aclSndFragBuffer = ""
NRLPRcvFragBuffer = ""
NRLPSndFragBuffer = ""
NRLPPacketTypes = [0x02, 0x03, 0x04, 0x05, 0x63, 0x64, 0x65, 0x68, 0x69] # excluding 0x00 to avoid false positive detections

# ATT opcodes
ATTopcodes = {
    0x01: "ERROR_RSP",
    0x02: "EXCHANGE_MTU_REQ",
    0x03: "EXCHANGE_MTU_RSP",
    0x04: "FIND_INFORMATION_REQ",
    0x05: "FIND_INFORMATION_RSP",
    0x06: "FIND_BY_TYPE_VALUE_REQ",
    0x07: "FIND_BY_TYPE_VALUE_RSP",
    0x08: "READ_BY_TYPE_REQ",
    0x09: "READ_BY_TYPE_RSP",
    0x0A: "READ_REQ",
    0x0B: "READ_RSP",
    0x0C: "READ_BLOB_REQ",
    0x0D: "READ_BLOB_RSP",
    0x0E: "READ_MULTIPLE_REQ",
    0x0F: "READ_MULTIPLE_RSP",
    0x10: "READ_BY_GROUP_TYPE_REQ",
    0x11: "READ_BY_GROUP_TYPE_RSP",
    0x12: "WRITE_REQ",
    0x13: "WRITE_RSP",
    0x52: "WRITE_CMD",
    0x16: "PREPARE_WRITE_REQ",
    0x17: "PREPARE_WRITE_RSP",
    0x18: "EXECUTE_WRITE_REQ",
    0x19: "EXECUTE_WRITE_RSP",
    0x20: "READ_MULTIPLE_VARIABLE_REQ",
    0x21: "READ_MULTIPLE_VARIABLE_RSP",
    0x23: "MULTIPLE_HANDLE_VALUE_NTF",
    0x1B: "HANDLE_VALUE_NTF",
    0x1D: "HANDLE_VALUE_IND",
    0x1E: "HANDLE_VALUE_CFM",
    0xD2: "SIGNED_WRITE_CMD"
}


MagnetOpcodes = {
    0x01: "services",
    0x02: "servicesResp",
    0x03: "createChannel",
    0x04: "acceptChannel",
    0x05: "serviceAdded",
    0x06: "serviceRemoved",
    0x07: "serviceRemovedCnf",
    0x08: "error",
    0x09: "version",
    0x71: "timeData",
    0x72: "timeData",
    0x90: "deviceID?",
    0x91: "CLdata?",
}

MagnetServiceIDLookup = dict()
MagnetChannelLookup = dict()

decryptor = EspDecryptor()
tcp = TcpHandler()

archiver = None
if collectData:
    archiver = DataArchiver()

def signal_handler(signal, frame):
    print('Exiting...')
    if archiver != None:
        archiver.close()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

NRLPtype3 = re.compile(r"NRLP.*t=0x03")
NRLPtype4 = re.compile(r"NRLP.*t=0x04")

if len(sys.argv) > 1 and sys.argv[1] == "--dump":
    sys.stderr.write("Logging decrypted ESP packet payloads to " + sys.argv[2] + ".pcap\n")
    decryptor.pcapwriter = pcapWriter(sys.argv[2] + ".pcap")

def on_message(message, data):
    global aclRcvFragBuffer, aclSndFragBuffer
    data = bytes.fromhex(message["payload"][3])
    direction = message["payload"][0]

    # ACL messages
    if message["payload"][2] == 2:
        # strip acl header from received packets (sent packets do not yet have a header)
        if direction == "rcv":
            frag = (data[1] & 0x30) == 0x10 # packet is continuing fragment of previous packet
            payload = data[4:]
            if frag:
                payload = aclRcvFragBuffer + payload # reassemble fragmented packet
        else:
            payload = data
            # reassemble fragmented packet (no solid header info to work with unfortunately)
            if len(aclSndFragBuffer) > 0:
                payload = aclSndFragBuffer + payload
                aclSndFragBuffer = ""


        # if first two bytes match length of the packet (minus 4 bytes for length and channel fields), we probably have a complete L2CAP packet
        payloadLen = len(payload)
        l2capLen = (payload[1] << 8) + payload[0]
        if l2capLen == payloadLen - 4:
            cid = phex(int.from_bytes(payload[2:4], byteorder="little"), 4)
            payload = payload[4:] # strip l2cap headers
            proto = Template("L2CAP(cid=${cid})").substitute(cid=cid)
            if cid in MagnetChannelLookup:
                assocService = MagnetServiceIDLookup[MagnetChannelLookup[cid]]
                proto = Template("L2CAP(cid=${cid}, ${service})").substitute(cid=cid, service=assocService)
            analyzePacket(direction, payload, [proto])
        # packet looks like a plausible l2cap fragment
        elif direction == "rcv" and l2capLen < 4096 and l2capLen > payloadLen - 4:
            aclRcvFragBuffer = payload
        elif direction == "snd" and l2capLen < 4096 and l2capLen > payloadLen - 4:
            aclSndFragBuffer = payload
        #else:
        #    print(direction, "unknw", payload)

def analyzePacket(direction, payload, protocolStack = []):
    containedPackets = detectProtocol(direction, payload, protocolStack)
    for packet in containedPackets:
        (proto, data, continueAnalysis) = packet
        if continueAnalysis:
            analyzePacket(direction, data, protocolStack + [proto])
        else:
            processParsedPacket(direction, protocolStack + [proto], data)

def processParsedPacket(direction, protocolStack, payload):
    if len(payload) > 2 and len(protocolStack) > 0 and (not unexplainedOnly or protocolStack[-1].startswith("unknw")):
        print(direction, "->".join(protocolStack), payload.hex())

    # archive unexplained payloads
    if collectData and len(payload) > 2 and protocolStack[-1] == "unknw":
        archiver.logMysterious(direction, "->".join(protocolStack[0:-1]).replace(",", "."), payload)

    # further processing of decrypted ESP payloads
    if extractTCPPayloads and len(protocolStack) > 0 and protocolStack[-1].startswith("ESP"):
        spi = protocolStack[-1][4:12]
        ctx = decryptor.spiToIKEContextLookup[spi] # breaking open the pretty encapsulation :/
        sessionType = decryptor.cryptoData[ctx]["type"]
        NRLPtype = protocolStack[-2][9:11] if protocolStack[-2].startswith("NRLP") else protocolStack[-3][9:11]
        tcp.ingest(direction, payload, sessionType, NRLPtype)

def on_message_IKE(message, data):
    msg = message["payload"]
    msgType = msg[0]
    if msgType == "cookies":
        cookies.add(msg[1])
        decryptor.registerCookies(msg[1], msg[2])
    elif msgType == "nonce":
        decryptor.registerNonce(msg[2], msg[3], msg[1])
    elif msgType == "spi":
        decryptor.registerSPI(msg[2], msg[3], msg[1], msg[4])
        spis.add(msg[3])
    elif msgType == "pubkey":
        decryptor.registerDHPubKeyContext(msg[3], msg[1])
    elif msgType == "dhkey":
        decryptor.registerUnknownDHKey(msg[1], msg[2])
        

# returns a list of packets contained in the given payload, with annotated protocol information
# format: (detected protocol, effective payload without headers, flag: analyze payload?)
def detectProtocol(direction, payload, protocolStack):
    global spis, NRLPRcvFragBuffer, NRLPSndFragBuffer, NRLPPacketTypes
    payloadLen = len(payload)

    # check if reserved bits of common sequence number scheme are all zero
    matchesCommonSeqAck = int.from_bytes(payload[0:2], byteorder="big") & 0b10000000111000000 == 0

    # ATT / GATT
    if len(protocolStack) == 1 and protocolStack[0] == "L2CAP(cid=0x0004)":
        opcode = payload[0]
        auth = (opcode & 0x80) > 0
        command = (opcode & 0x40) > 0
        opcode = opcode & 0x3f
        cmdString = ", command" if command else ""
        authString = ", auth" if auth else ""

        if collectData:
            archiver.logATT(direction, payload)

        proto = Template("ATT(op=${op}${cmd}${auth})").substitute(op=ATTopcodes[opcode], cmd=cmdString, auth=authString) + logATT(ATTopcodes[opcode], payload[1:])
        return [(proto, payload[1:], False)]
    # Magnet version >8
    elif payloadLen > 3 and int.from_bytes(payload[1:3], byteorder="little") == payloadLen - 3:
        opcode = payload[0]
        length = int.from_bytes(payload[1:3], byteorder="little")

        if collectData:
            archiver.logMagnet(direction, "MagnetL", payload)

        proto = Template("MagnetL(op=${op}, len=${length})").substitute(op=phex(opcode), length=length) + " " + logMagnet(opcode, payload[3:])
        return [(proto, payload[3:], False)]
    # Magnet version <8, avoid false positives by limiting to L2CAP layer and opcode 0x09 (version info)
    # after version checking we switch to MagnetL and all other MagnetS detections look like false positives
    elif payloadLen > 2 and payload[1] == payloadLen - 2 and len(protocolStack) == 1 and payload[0] == 0x09:
        opcode = payload[0]
        length = payload[1]

        if collectData:
            archiver.logMagnet(direction, "MagnetS", payload)

        proto = Template("MagnetS(op=${op}, len=${length})").substitute(op=phex(opcode), length=length) + " " + logMagnet(opcode, payload[4:])
        return [(proto, payload[2:], False)]
    # NRLP
    elif payloadLen > 7 and matchesCommonSeqAck and int.from_bytes(payload[3:5], byteorder="big") == payloadLen - 5 - 2: # 5 byte header, 2 byte checksum (?)
        seq = payload[0] >> 1
        #ack = payload[1]
        typ = payload[2]
        lng = int.from_bytes(payload[3:5], byteorder="big")
        checksum = payload[-2:]

        if collectData and not (typ in [0x04, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69]):
            archiver.logNRLP(direction, payload)

        proto = Template("NRLP(t=${typ}, #${seq})").substitute(seq=seq, typ=phex(typ))
        data = payload[5:-2]
        return [(proto, data, True)]
    # ESP
    elif matchesKnownESP(payload):
        return handleESP(payload)
    # IKEv2
    elif matchesIKE(payload):
        return handleIKE(payload)
    # 6LowPAN compressed header
    elif payloadLen > 4 and (payload[0] == 0x72 or payload[0] == 0x79) and payload[3] == 0x32: # very heuristic, idk what these numbers mean
        extendedHeader = payload[1] == 0x66
        header = payload[0:4] if not extendedHeader else payload[0:8]
        data = payload[4:] if not extendedHeader else payload[8:]

        if extendedHeader:
            checkAssumption("UATP2 extended header always 0x000c000c", payload[4:8].hex() == "000c000c")

        return [("6LowPAN("+header.hex()+")", data, True)]
    # 6LowPAN compressed header
    elif payloadLen > 5 and (payload[0] == 0x72 or payload[0] == 0x79) and payload[2] == 0x32 and payload[3] < 0x20: 
        # this is getting a bit messy, but we're losing packets from TCP streams by missing these packets
        headerLength = payload[3]+4
        header = payload[0:headerLength]
        data = payload[headerLength:]

        return [("6LowPAN("+header.hex()+")", data, True)]
    # NRLink Prelude
    elif payload[2:10].hex() == "5445524d494e5553":
        terminusProtocolVersion = payload[10]
        pairingState = payload[11]
        length = int.from_bytes(payload[12:14], byteorder="big")
        data = payload[14:-2]
        proto = Template("NRLinkPrelude(v=${version}, pairing=${pair}, l=${len})").substitute(version=terminusProtocolVersion, pair=pairingState, len=length)

        if collectData:
            archiver.logPrelude(direction, payload)

        return [(proto, data, False)]
    # CLink and CLinkHP
    elif payloadLen > 5 and len(protocolStack) == 1 and "CLink" in protocolStack[0]:
        if collectData:
            archiver.logClink(direction, payload)
        sid = phex(int.from_bytes(payload[2:4], byteorder="little"), 4)
        length = int.from_bytes(payload[4:6], byteorder="big")
        proto = Template("CLink(id=${sid},l=${len})").substitute(sid=sid,len=length)
        return [(proto, payload[6:], False)]
    # com.apple.BT.TS
    elif payloadLen > 3 and len(protocolStack) == 1 and "BT.TS" in protocolStack[0]:
        if collectData:
            archiver.logBTTS(direction, payload)
        typ = payload[2]
        length = payload[3]
        proto = Template("BT.TS(t=${tpe},l=${len})").substitute(tpe=hex(typ),len=length)
        return [(proto, payload[3:], False)]
    # IKE with unknown cookie
    elif matchesUnknownIKE(payload, protocolStack):
        return handleIKE(payload)
    # ESP with unknown SPI
    elif matchesHeuristicESP(payload):
        return handleESP(payload)
    # NRLP, fragmented (first fragment)
    # Heuristic: reserved bits in sequence numbers not set, length looks 'reasonable', type is one of the known packet types
    elif payloadLen > 7 and matchesCommonSeqAck and int.from_bytes(payload[3:5], byteorder="big") < 4096 and payload[2] in NRLPPacketTypes:
        effectivePayload = payload[2:]
        lng = int.from_bytes(effectivePayload[1:3], byteorder="big")
        seq = payload[0] >> 1

        containedPackets = []

        # full first packet is in this frame, alongside others
        while lng <= len(effectivePayload) - 3 and len(effectivePayload) > 5:
            typ = effectivePayload[0]
            proto = Template("NRLP(t=${typ}, l=${lng})").substitute(typ=phex(typ), lng=lng)

            if collectData and not (typ in [0x04, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69]):
                archiver.logNRLP(direction, effectivePayload[0:lng+3])

            data = effectivePayload[3:lng+3]
            containedPackets.append((proto, data, True))
            effectivePayload = effectivePayload[lng+3+2:]
            if len(effectivePayload) < 3:
                break
            lng = int.from_bytes(effectivePayload[1:3], byteorder="big")

        # one payload didn't fit into this frame completely
        if len(effectivePayload) > 0:
            if direction == "snd":
                NRLPSndFragBuffer = effectivePayload
            else:
                NRLPRcvFragBuffer = effectivePayload

        return containedPackets
    # NRLP, fragmented (continuing fragment)
    # Heuristic: reserved bits in sequence numbers not set, packet is not super short, matching buffer has start fragment
    elif payloadLen > 32 and int.from_bytes(payload[0:2], byteorder="big") & 0b10000000111000000 == 0 and (direction == "snd" and len(NRLPSndFragBuffer) > 0 or direction == "rcv" and len(NRLPRcvFragBuffer) > 0):
        if direction == "snd":
            effectivePayload = bytes.fromhex("0000") + NRLPSndFragBuffer + payload[2:] # prepend synthetic sequence numbers
            NRLPSndFragBuffer = ""
        else:
            effectivePayload = bytes.fromhex("0000") + NRLPRcvFragBuffer + payload[2:] # prepend synthetic sequence numbers
            NRLPRcvFragBuffer = ""
        return detectProtocol(direction, effectivePayload, protocolStack)

    return [("unknw", payload, False)]


# protocol detectors
def matchesKnownESP(data):
    return len(data) > 32 and data[0:4].hex() in spis

def matchesHeuristicESP(data):
    # fitting minimum packet length and low sequence number (we'll add the spi to our known contexts to continue detecting ESP sessions)
    # ignoring highest byte of sequence number because the devices like to start at 0xc0... 0xa0... 0x80... etc
    return len(data) > 32 and int.from_bytes(data[5:8], byteorder="big") < 30 and int.from_bytes(data[5:8], byteorder="big") >= 0

def matchesIKE(data):
    # SA_INIT exchange type, protocol version 2.0, payload SA (matches first message exchange in IKEv2, before we have established cookies)
    return len(data) > 28 and (data[0:8].hex() in cookies or data[16:19].hex() == "212022")

def matchesUnknownIKE(data, stack):
    return len(data) > 28 and "NRLP(t=0x04" in stack[-1]

def handleIKE(payload):
    seq = int.from_bytes(payload[20:24], byteorder="big")
    proto = Template("IKEv2(${cookie}, #${seq})").substitute(cookie=payload[0:4].hex(), seq=seq)
    data = payload[28:]
    return [(proto, data, False)]

def handleESP(payload):
    seq = int.from_bytes(payload[4:8], byteorder="big")
    spi = payload[0:4].hex()
    spis.add(spi)
    plaintext = decryptor.decryptESP(payload)

    if len(plaintext) == 0:
        proto = Template("ESP(${spi}, #${seq}, crypto not ready)").substitute(spi=spi, seq=seq)
        data = payload
    else:
        nextHeader = plaintext[-1]
        padLength = plaintext[-2]

        proto = Template("ESP(${spi}, #${seq}, ${nextHeader})").substitute(spi=spi, seq=seq, nextHeader=nextHeader)
        checkAssumption("ESP next header always TCP (0x06)", nextHeader == 6)
        data = plaintext[:-2-padLength]

    return [(proto, data, False)]

def logATT(opcode, pdu):
    if opcode == "HANDLE_VALUE_IND":
        handle = int.from_bytes(pdu[0:2], byteorder="little")
        return Template(" Handle ${handle} has value 0x${value}").substitute(handle=phex(handle, 4), value=pdu[2:].hex())
    elif opcode == "WRITE_REQ":
        handle = int.from_bytes(pdu[0:2], byteorder="little")
        return Template(" Write value ${value} to handle 0x${handle}").substitute(handle=phex(handle, 4), value=pdu[2:].hex())
    elif opcode == "READ_BY_GROUP_TYPE_REQ":
        typ = int.from_bytes(pdu[4:6], byteorder="little")
        startHandle = int.from_bytes(pdu[0:2], byteorder="little")
        endHandle = int.from_bytes(pdu[2:4], byteorder="little")
        return Template(" Read attributes of group type ${type} in handles ${start}-${end}").substitute(type=phex(typ, 4), start=phex(startHandle, 4), end=phex(endHandle, 4))
    elif opcode == "FIND_INFORMATION_REQ":
        startHandle = int.from_bytes(pdu[0:2], byteorder="little")
        endHandle = int.from_bytes(pdu[2:4], byteorder="little")
        return Template(" Get attribute types for handles ${start}-${end}").substitute(start=phex(startHandle, 4), end=phex(endHandle, 4))
    elif opcode == "READ_BY_TYPE_REQ":
        typ = int.from_bytes(pdu[4:6], byteorder="little")
        startHandle = int.from_bytes(pdu[0:2], byteorder="little")
        endHandle = int.from_bytes(pdu[2:4], byteorder="little")
        return Template(" Read attributes of type ${type} in handles ${start}-${end}").substitute(type=phex(typ, 4), start=phex(startHandle, 4), end=phex(endHandle, 4))
    else:
        return ""

def logMagnet(opcode, pdu):
    op = MagnetOpcodes[opcode]
    if op == "version":
        return Template("${operation}: version ${v} features 0x${features}").substitute(operation=op, v=pdu[0], features=pdu[1:5].hex())
    elif op == "createChannel":
        channel = phex(int.from_bytes(pdu[0:2], byteorder="little"), 4)
        sid = phex(int.from_bytes(pdu[2:4], byteorder="little"), 4)
        MagnetChannelLookup[channel] = sid
        return Template("${operation}: serviceID ${id} channel ${chan}").substitute(operation=op, chan=channel, id=sid)
    elif op == "acceptChannel":
        channel = phex(int.from_bytes(pdu[3:5], byteorder="little"), 4)
        sid = phex(int.from_bytes(pdu[1:3], byteorder="little"), 4)
        MagnetChannelLookup[channel] = sid
        return Template("${operation}: serviceID ${id} channel ${chan} flag ${f}").substitute(operation=op, f=phex(pdu[0]), id=sid, chan=channel)
    elif op == "services":
        numServices = pdu[0]
        services = []
        i = 1
        j = 0
        while j < numServices and i + 10 < len(pdu):
            lng = pdu[i]
            sid = phex(int.from_bytes(pdu[i+1:i+3], byteorder="little"), 4)
            flag = pdu[i+3]
            nameLng = int.from_bytes(pdu[i+4:i+5], byteorder="big")
            name = pdu[i+5:i+5+nameLng].decode().strip("\x00")
            trl = pdu[-1:] if nameLng + 4 < lng else "00" # trailing byte may be omitted for implicit zero
            i += lng + 1
            j += 1
            MagnetServiceIDLookup[sid] = name
            services.append(Template("Service ${s}: ${n}, flags: ${f}, trailer: 0x${t}").substitute(s=sid, f=phex(flag), n=name, t=trl.hex()))
        return Template("${operation}: ${s}").substitute(operation=op, s="; ".join(services))
    elif op == "servicesResp":
        common = pdu[0]
        services = []
        for i in range(0, common-1, 1):
            sid = phex(int.from_bytes(pdu[1+i*2:3+i*2], byteorder="little"), 4)
            services.append(sid)
        return Template("${operation}: ${common} shared services, ${services}").substitute(operation=op, common=common, services=", ".join(services))
    elif op == "serviceAdded":
        sid = phex(int.from_bytes(pdu[0:2], byteorder="little"), 4)
        unk = pdu[2:3]
        lng = int.from_bytes(pdu[3:4], byteorder="big")
        nme = pdu[4 : 4 + lng].decode().strip("\x00")
        trl = pdu[-1:]
        MagnetServiceIDLookup[sid] = nme
        return Template("${operation}: Added service ${s}: ${n}, flags: 0x${f} trailer: 0x${t}").substitute(operation=op, s=sid, n=nme, f=unk.hex(), t=trl.hex())
    elif op == "serviceRemoved":
        sid = phex(int.from_bytes(pdu[0:2], byteorder="little"), 4)
        return Template("${operation}: Removed service ${s}").substitute(operation=op, s=sid)
    elif op == "serviceRemovedCnf":
        sid = phex(int.from_bytes(pdu[0:2], byteorder="little"), 4)
        return Template("${operation}: Confirm service ${s} removal").substitute(operation=op, s=sid)
    else:
        return Template("${operation}").substitute(operation=op)

def checkAssumption(name, expression):
    if not expression:
        sys.stderr.write("ASSUMPTION VIOLATED: " + name + "\n")

def splitN(str1, n):
        return [str1[start:start+n] for start in range(0, len(str1), n)]

# Internet Checksum, according to https://datatracker.ietf.org/doc/html/rfc1071
def ip_checksum(payload): 
    words = splitN(''.join(payload.split()),4)
    if len(words[-1]) < 4:
        words[-1] = words[-1] + "00"

    csum = 0;
    for word in words:
        csum += int(word, base=16)
    csum += (csum >> 16)
    return csum & 0xFFFF ^ 0xFFFF

# padded int to hex string conversion
def phex(val, pad=2):
    fstr = "#0" + str(pad+2) + "x"
    return format(val, fstr)

ikeScript.on('message', on_message_IKE)
ikeScript.load()

bleScript.on('message', on_message)
bleScript.load()

sys.stdin.read()