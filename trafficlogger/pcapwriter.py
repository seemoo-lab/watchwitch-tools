# loosely based on https://www.codeproject.com/tips/612847/generate-a-quick-and-easy-custom-pcap-file-using-p
import sys
import time

class pcapWriter:
    pcapMagic = "A1B23C4D"
    pcapVersion = "00020004"
    pcapSnapLen = "FFFF0000"
    pcapHeader = bytes.fromhex(pcapMagic + pcapVersion + '0000000000000000' + pcapSnapLen + '00000001')

    ethHeader = bytes.fromhex("0000000000000000000000000800")
    ipHeader = "450zxxxx0000400040wwyyyy"

    def __init__(self, filename):
        self.file = open(filename, "wb")
        self.file.write(self.pcapHeader)

    def appendPacket(self, payload, isIncoming, protocol = 6, carrierStream = "00"):
        ts = time.time()
        seconds = int(ts).to_bytes(4, byteorder='big')
        nano = int((ts - int(ts)) * 1000000000).to_bytes(4, byteorder='big')

        ip_len = int(len(payload) + 20)
        ip = self.ipHeader.replace('xxxx', "%04x"%ip_len)
        ip = ip.replace('ww', "%02x"%protocol)

        # nrlp types 0x64/0x65 and 0x68/0x69 can carry the same TCP stream
        # to allow reconstruction, we normalize to the higher of each and set ECT flag accordingly
        # (see NRLP.md for details)
        etcFlag = False
        effectiveStream = carrierStream
        if carrierStream == "64":
            effectiveStream = "65"
            etcFlag = True
        elif carrierStream == "68":
            effectiveStream = "69"
            etcFlag = True

        if etcFlag:
            ip = ip.replace("z", "2")
        else:
            ip = ip.replace("z", "0")

        # set source and destination ip to 127.0.1.<nrlp> (phone) / 127.0.2.<nrlp> (watch)
        if isIncoming:
            ip += "7F0002" + effectiveStream + "7F0001" + effectiveStream
        else:
            ip += "7F0001" + effectiveStream + "7F0002" + effectiveStream

        checksum = self.ip_checksum(ip.replace('yyyy','0000'))
        ip = ip.replace('yyyy',"%04X"%checksum)
        ipBytes = bytes.fromhex(ip)

        pcapLen = int(ip_len + len(self.ethHeader)).to_bytes(4, byteorder='big')
        self.file.write(seconds + nano + pcapLen + pcapLen + self.ethHeader + ipBytes + payload)

    #Splits the string into a list of tokens every n characters
    def splitN(self, str1, n):
        return [str1[start:start+n] for start in range(0, len(str1), n)]

    #Calculates and returns the IP checksum based on the given IP Header
    def ip_checksum(self, iph): 
        words = self.splitN(''.join(iph.split()),4)
        if len(words[-1]) < 4:
            words[-1] = words[-1] + "00"

        csum = 0;
        for word in words:
            csum += int(word, base=16)

        csum += (csum >> 16)
        return csum & 0xFFFF ^ 0xFFFF