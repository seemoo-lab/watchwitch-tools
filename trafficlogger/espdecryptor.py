import hashlib
from collections import defaultdict
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

class EspDecryptor:

    cryptoData = defaultdict(lambda: {})
    spiToIKEContextLookup = {}
    pubkeyToIKEContextLookup = {}
    knownDHKeys = []
    knownDHPubKeys = []

    pcapwriter = None

    waitingForDecrypt = []

    @staticmethod
    def HMAC(key, data):
        blockKey = EspDecryptor.genBlockKey(key)
        ipad = 0x36
        opad = 0x5c
        okey = bytearray([keybyte ^ opad for keybyte in blockKey])
        ikey = bytearray([keybyte ^ ipad for keybyte in blockKey])

        inner = hashlib.sha512(ikey + data).digest()
        outer = hashlib.sha512(okey + inner).digest()

        return outer

    @staticmethod
    def genBlockKey(key):
        if len(key) > 128:
            key = hashlib.sha512(key).digest()
        return key.ljust(128, str.encode(chr(0x00)))

    @staticmethod
    def PRFplus(key, data, length):
        keystream = bytearray()
        counter = 1

        lastblock = EspDecryptor.HMAC(key, data + bytearray([counter]))
        keystream += lastblock
        counter += 1

        while len(keystream) < length:
            lastblock = EspDecryptor.HMAC(key, lastblock + data + counter.to_bytes(1, 'little'))
            keystream += lastblock
            counter += 1

        return keystream

    def registerUnknownDHKey(self, pubKey, dhKey):
        #print("espd got dh key")
        self.knownDHKeys.append([pubKey, dhKey])
        self.associateDHKeys()

    def registerDHPubKeyContext(self, pubKey, ikeContext):
        #print("espd got pubkey context")
        self.knownDHPubKeys.append([pubKey, ikeContext])
        self.associateDHKeys()

    def associateDHKeys(self):
        for pubkey in self.knownDHPubKeys:
            for dhkey in self.knownDHKeys:
                if dhkey[0] == pubkey[0]:
                    #print("espd successfully associated keys")
                    self.registerDHKey(pubkey[1], dhkey[1])
                    self.knownDHPubKeys.remove(pubkey)
                    self.knownDHKeys.remove(dhkey)

    def registerCookies(self, initiatorCookie, responderCookie):
        self.cryptoData[initiatorCookie]["cookiei"] = initiatorCookie
        self.cryptoData[initiatorCookie]["cookier"] = responderCookie
        #print("espd got cookies")

    def registerSPI(self, fromInitiator, spi, ikeContext, sessionType):
        spiName = "SPIi" if fromInitiator else "SPIr"
        #print("espd got " + spiName)
        self.cryptoData[ikeContext][spiName] = spi
        self.spiToIKEContextLookup[spi] = ikeContext
        self.computeSKeyseed(ikeContext)
        self.cryptoData[ikeContext]["type"] = sessionType
        self.checkWaiting()

    def registerNonce(self, fromInitiator, nonce, ikeContext):
        nonceName = "Ni" if fromInitiator else "Nr"
        #print("espd got " + nonceName)
        self.cryptoData[ikeContext][nonceName] = nonce
        self.computeSKeyseed(ikeContext)

    def registerDHKey(self, ikeContext, dhKey):
        self.cryptoData[ikeContext]["DH"] = dhKey
        self.computeSKeyseed(ikeContext)
        #print("espd got dh")

    def decryptESP(self, payload):
        spi = payload[0:4].hex()

        # crypto not ready - todo: buffer
        if not spi in self.spiToIKEContextLookup:
            #print("Buffering unknown ESP")
            self.waitingForDecrypt.append(payload)
            return b""

        ikeContext = self.spiToIKEContextLookup[spi]

        ctx = self.cryptoData[ikeContext]
        fromInitiator = ctx["SPIi"] != spi

        salt = ctx["espSaltI"] if fromInitiator else ctx["espSaltR"]
        key = ctx["espKeyI"] if fromInitiator else ctx["espKeyR"]
        
        plain = self.decryptESPwithContext(payload, salt, key)

        if self.pcapwriter:
            nextHeader = plain[-1]
            padLength = plain[-2]
            data = plain[:-2-padLength]
            self.pcapwriter.appendPacket(data, fromInitiator, protocol = nextHeader)

        return plain

    def checkWaiting(self):
        decrypted = []
        for packet in self.waitingForDecrypt:
            spi = packet[0:4].hex()
            if spi in self.spiToIKEContextLookup:
                #print("Decrypting buffered ESP")
                decrypted.append(packet)
                self.decryptESP(packet)
        for packet in decrypted:
            self.waitingForDecrypt.remove(packet)

    @staticmethod
    def decryptESPwithContext(payload, salt, key):
        spi = payload[0:4]
        seq = payload[4:8]
        iv = bytearray(seq).rjust(8, b'\x00') # Implicit IV, see https://www.rfc-editor.org/rfc/rfc8750.html
        aad = spi + seq
        data = payload[8:]

        nonce = bytes(salt + iv)

        #print("Attempting decryption of " + payload[0:8].hex() + "..." + payload[-8:].hex())

        chacha = ChaCha20Poly1305(key)
        plain = chacha.decrypt(nonce, data, aad)

        return bytearray(plain)


    def computeSKeyseed(self, context):
        ctx = self.cryptoData[context]
        if "Ni" in ctx and "Nr" in ctx and "DH" in ctx and "cookiei" in ctx and "cookier" in ctx and not "SKEYSEED" in ctx:
            ni = bytearray.fromhex(ctx["Ni"])
            nr = bytearray.fromhex(ctx["Nr"])
            dh = bytearray.fromhex(ctx["DH"])
            ci = bytearray.fromhex(ctx["cookiei"])
            cr = bytearray.fromhex(ctx["cookier"])

            skeyseed = self.HMAC(ni+nr, dh)
            ctx["SKEYSEED"] = skeyseed

            skd = self.PRFplus(skeyseed, ni + nr + ci + cr, 64)
            ctx["SK_d"] = skd

            keymat = self.PRFplus(skd, ni + nr, 72)
            #keystream = self.PRFplus(skeyseed, ni + nr + ci + cr, 264) # keystream used to derive IKE keys, we only need ESP keys here though

            ctx["espKeyI"] = keymat[0:32]
            ctx["espSaltI"] = keymat[32:36]
            ctx["espKeyR"] = keymat[36:68]
            ctx["espSaltR"] = keymat[68:72]
            print("Derived crypto secrets for context " + context)