from collections import defaultdict
import re

class TcpHandler:

    conversations = defaultdict(lambda: {})
    packets = 0

    def ingest(self, direction, data, channelClass, nrlpType = None):
        sourcePort = data[0:2]
        destPort = data[2:4]

        if direction == "snd":
            convoKey = (sourcePort + destPort).hex()
        else:
            convoKey = (destPort + sourcePort).hex()

        convo = self.conversations[convoKey]

        if direction in convo:
            convo[direction].ingest(data, nrlpType)
        else:
            #print("Creating TCP convo for key {}, direction {}".format(convoKey, direction))
            seq = data[4:8]
            convo[direction] = TcpConvo(sourcePort, destPort, seq, channelClass)
            convo[direction].ingest(data, nrlpType)

        self.packets += 1
        if self.packets % 200 == 0:
            self.logChannelStats()
            pass

    def logChannelStats(self):
        print("")
        print("channel-id   | class   | type | packets (valid/dropped/ooo) | total bytes")
        for cid, convo in self.conversations.items():
            tpe = "???"
            if "snd" in convo:
                s = convo["snd"]
                if s.isTLVchannel:
                    tpe = "TLV"
                elif s.isTLSchannel:
                    tpe = "TLS"
                print("{}-snd | {} | {}/{} | {} / {} / {}      | {}".format(cid, s.channelClass, tpe, ','.join(s.nrlpTypes), s.packets, s.droppedPackets, s.oooPackets, s.totalBytes))
            if "rcv" in convo:
                r = convo["rcv"]
                if r.isTLVchannel:
                    tpe = "TLV"
                elif r.isTLSchannel:
                    tpe = "TLS"
                print("{}-rcv | {} | {}/{} | {} / {} / {}      | {}".format(cid, r.channelClass, tpe, ','.join(r.nrlpTypes), r.packets, r.droppedPackets, r.oooPackets, r.totalBytes))


class TcpConvo:
    def __init__(self, src, dst, seq, channelClass):
        self.sourcePort = src
        self.destPort = dst
        self.syncedUpTo = int.from_bytes(seq, byteorder="big") # We assume everything up to this sequence has already been received
        self.convoBuffer = bytes()
        self.outOfOrderBuffer = dict()
        self.tlvReassemblyBuffer = bytes()
        self.isTLVchannel = False
        self.isTLSchannel = False
        self.isMediaStream = False
        self.loggedNonTLVChannel = False
        self.packets = 0
        self.oooPackets = 0
        self.droppedPackets = 0
        self.totalBytes = 0
        self.channelClass = channelClass
        self.nrlpTypes = set()
        self.pngPattern = re.compile(b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a')
        self.bplistPattern = re.compile(b'\x62\x70\x6c\x69\x73\x74')
        self.krtsPattern = re.compile(b'\x6b\x72\x74\x73')

    def ingest(self, data, nrlpType = None):

        if nrlpType:
            self.nrlpTypes.add(nrlpType)

        sourcePort = data[0:2]
        destPort = data[2:4]
        seq = int.from_bytes(data[4:8], byteorder="big")
        #ack = data[8:12]
        dataoffset = (data[12] >> 4)*4 # data offset is upper 4 bits, gives offset in 32bit words
        flags = data[13]
        syn = ((flags >> 1) & 1) == 1

        # uninteresting header data + options
        payload = data[dataoffset:]

        #print("Ingest on TCP convo {}->{}, seq {}".format(sourcePort.hex(), destPort.hex(), seq))

        if syn:
            #print("Resync in TCP convo {}->{}, seq {}".format(sourcePort.hex(), destPort.hex(), seq))
            self.syncedUpTo = seq

        # packet is delayed duplicate, we already have the data, discard
        if seq < self.syncedUpTo:
            self.droppedPackets += 1
            #print("Duplicate, dropping")
        # packet delivered in order, all is well
        elif seq == self.syncedUpTo:
            #print("In-order, processing")
            self.syncedUpTo += len(payload)
            self.totalBytes += len(payload)
            self.convoBuffer += payload
            self.packets += 1
            self.checkOutOfOrderBuffer()
            self.triggerHighLevelPacketExtract()
        # packet arrived early, save to buffer
        else:
            #print("Out-of-order, adding to buffer")
            self.oooPackets += 1
            self.outOfOrderBuffer[seq] = payload

            # for whatever reason, we sometimes get a 'late' packet as first,
            # causing us to be desynced forever while 'real' consecutive packets pile up in the buffer
            # so we'll try discarding the first packet we got if the OOO buffer gets too full
            if self.oooPackets > 4:
                #print("Discarding stuck packet due to full OOO buffer, re-syncing...")
                self.convoBuffer = bytes()
                self.droppedPackets += 1
                self.syncedUpTo = min(self.outOfOrderBuffer.keys()) # manually seek forward to lowest OOO packet
                self.checkOutOfOrderBuffer() # process newly unstuck packets

    # search the buffer for previously received packets that are "due" in the byte stream
    # honestly not sure if this works because i haven't observed any out-of-order packets yet
    def checkOutOfOrderBuffer(self):
        while self.syncedUpTo in self.outOfOrderBuffer:
            #print("Found next packet in buffer")
            payload = self.outOfOrderBuffer.pop(self.syncedUpTo)
            self.packets += 1
            self.oooPackets -= 1
            self.syncedUpTo += len(payload)
            self.totalBytes += len(payload)
            self.convoBuffer += payload


    def triggerHighLevelPacketExtract(self):
        if len(self.convoBuffer) < 5:
            return

        # Assuming TLV
        datatype = self.convoBuffer[0]
        length = int.from_bytes(self.convoBuffer[1:5], byteorder="big")

        # Assuming ConReq
        headerLen = int.from_bytes(self.convoBuffer[0:2], byteorder="big")

        # Assuming plain TLS
        TLSversion = self.convoBuffer[1:3]
        TLSrecord = self.convoBuffer[0]
        TLSlength = int.from_bytes(self.convoBuffer[3:5], byteorder="big")

        # TLS detection
        if (TLSversion.hex() in ["0303", "0301"]) and (TLSrecord in [0x16, 0x17]) and len(self.convoBuffer) >= TLSlength + 5:
            self.isTLSchannel = True
            print("Got TLS packet on channel {}->{}".format(self.sourcePort.hex(), self.destPort.hex()))
            self.convoBuffer = self.convoBuffer[5+TLSlength:]
            self.triggerHighLevelPacketExtract()
        # non-TLV 'connection request' messages
        # heuristic: header length should be rather short and TLS client hello record header should follow after ConReq header
        elif headerLen < 0x00ff and len(self.convoBuffer) > headerLen + 7 and self.convoBuffer[headerLen+2:headerLen+5].hex() == "160301":
            self.handleNonTLVConReq()
        # maybe video streams are always on a fixed port and do not use TLVs?
        elif (not self.isTLVchannel and re.search(self.krtsPattern, self.convoBuffer) != None) or self.isMediaStream:
            print("KRTS HEVC stream on {}->{}".format(self.sourcePort.hex(), self.destPort.hex()))
            print(self.convoBuffer.hex())
            self.isMediaStream = True
            self.convoBuffer = bytes()
        # TLV detection heuristic: we expect the type to be 'low' (<50) and the length to be short-ish (< 0x0000ffff = 65kB)
        elif length < 0xffff and length > 2:
            if len(self.convoBuffer) >= 5 + length: # if complete TLV is already in buffer
                self.isTLVchannel = True
                #print("Got TLV len {} on channel {}->{}".format(length, self.sourcePort.hex(), self.destPort.hex()))
                data = self.convoBuffer[0:5+length]
                self.convoBuffer = self.convoBuffer[5+length:]
                self.handleTLV(datatype, data)
        elif self.isTLVchannel:
            print("Convo buffer {}->{} doesn't look like TLV: {}".format(self.sourcePort.hex(), self.destPort.hex(), self.convoBuffer.hex()))
            self.convoBuffer = bytes()
        elif not self.loggedNonTLVChannel:
            print("Got unknown channel {}->{}".format(self.sourcePort.hex(), self.destPort.hex()))
            self.loggedNonTLVChannel = True
            print(self.convoBuffer.hex())
            self.convoBuffer = bytes() # clear buffer in the hopes that we catch a TLV start on the next packet?

    def handleTLV(self, datatype, data):
        sequenceNo = int.from_bytes(data[5:9], byteorder="big")
        payload = data[9:]

        # datatypes with common uuid/service name headers
        if datatype in [0x00, 0x03, 0x06, 0x16, 0x17]:
            # header format: 0x00 0b000????? 0b000st?0?
            zeroFlag = payload[0]
            if zeroFlag != 0x00:
                print("Expected first byte of 3-byte TLV header to be zero, got: {}".format(payload[0:15].hex()))
            unkFlag1 = payload[1]
            unkFlag2 = payload[2]

            flagMaybe = unkFlag1 & 0xf0
            typeMaybe = unkFlag1 & 0x0f

            hasService = (unkFlag2 & 0xf0) == 0x10
            hasTrailer = (unkFlag2 & 0x08) == 0x08

            firstUUIDlen = int.from_bytes(payload[3:7], byteorder="big")
            firstUUID = payload[7:7+firstUUIDlen].decode("ascii")
            offset = 7+firstUUIDlen

            secondUUIDlen = int.from_bytes(payload[offset:offset+4], byteorder="big")
            offset += 4
            secondUUID = payload[offset:offset+secondUUIDlen].decode("ascii")
            offset += secondUUIDlen

            print("Type {} TLV, seq {}, header {}, uuids: '{}' '{}'".format(hex(datatype), sequenceNo, payload[0:3].hex(), firstUUID, secondUUID))

            if hasService:
                serviceLen = int.from_bytes(payload[offset:offset+4], byteorder="big")
                offset += 4
                service = payload[offset:offset+serviceLen].decode("ascii")
                print("Service name: {}".format(service))

            if hasTrailer:
                trailer = payload[-4:]
                payload = payload[:-4]
                print("Trailer: {}".format(trailer.hex()))

            #print(payload.hex())


        # no data acknowledge-like messages?
        elif datatype in [0x01, 0x04, 0x25]:
            if len(payload) > 0:
                print("Expected zero-length payload for type {} but got: {}".format(hex(datatype), payload.hex()))
            print("Empty Type {} TLV, seq {}".format(hex(datatype), sequenceNo))
        # fragmented TLV
        elif datatype == 0x15:
            fragmentId = int.from_bytes(payload[0:4], byteorder="big")
            fragmentCount = int.from_bytes(payload[4:8], byteorder="big")
            print("Type 0x15 TLV (fragment #{} out of {})".format(fragmentId, fragmentCount))

            fragmentData = payload[8:]
            self.tlvReassemblyBuffer += fragmentData

            # is last fragment? -> process reassembled TLV
            if fragmentId + 1 == fragmentCount:
                self.convoBuffer += self.tlvReassemblyBuffer
                self.tlvReassemblyBuffer = bytes()
                self.triggerHighLevelPacketExtract()
        else:
            print("Unsupported TLV type on {}->{}: {}".format(self.sourcePort.hex(), self.destPort.hex(), hex(datatype)))
            print(data.hex())

        if re.search(self.pngPattern, payload) != None:
            print("Contains PNG header!")
        if re.search(self.bplistPattern, payload) != None:
            print("Contains bplist!")

    def handleNonTLVConReq(self):
        self.isTLSchannel = True
        headerLen = int.from_bytes(self.convoBuffer[0:2], byteorder="big")
        header = self.convoBuffer[0:headerLen+2]
        self.convoBuffer = self.convoBuffer[2+headerLen:]
        payloadLen = int.from_bytes(self.convoBuffer[3:5], byteorder="big")

        headerMagic1 = header[2:5]
        hostLen = header[5]
        host = header[6:6+hostLen].decode("ascii")
        offset = 6+hostLen
        headerMagic2 = header[offset]
        offset += 1

        if headerMagic2 == 0x02:
            unkLen = int.from_bytes(header[offset:offset+2], byteorder="big")
            unk = header[offset+3:offset+3+unkLen].decode("ascii")
            offset += 2+unkLen
            print(unk)
            offset += 1 # hacky, i think these are actually also TLVs of some sort but we'll just skip the 0x03 type we expect for the process name here

        processLen = int.from_bytes(header[offset:offset+2], byteorder="big")
        offset += 2
        process = header[offset:offset+processLen].decode("ascii")

        #print("Magic1: {}, Host: {}, Magic2: {} Process: {}".format(headerMagic1.hex(), host, headerMagic2, process))
        print("Wrapped TLS ClientHello, connecting to {} from {}".format(host, process))


        if payloadLen+2 > len(self.convoBuffer):
            print("ConReq payload too short")
        else:
            payload = self.convoBuffer[0:payloadLen+2]
            self.convoBuffer = self.convoBuffer[payloadLen+2:]
