import sys
import time
import gzip

class DataArchiver:
    def __init__(self):
        self.att = gzip.open("../data/archiveATT.csv.gz", 'at')
        self.magnet = gzip.open("../data/archiveMagnet.csv.gz", 'at')
        self.nrlp = gzip.open("../data/archiveNRLP.csv.gz", 'at')
        self.prelude = gzip.open("../data/archivePrelude.csv.gz", 'at')
        self.clink = gzip.open("../data/archiveCLink.csv.gz", 'at')
        self.btts = gzip.open("../data/archiveBTTS.csv.gz", 'at')
        self.mysterious = gzip.open("../data/archiveMysterious.csv.gz", 'at')

    def close(self):
        print("Flushing data archives")
        self.att.close()
        self.magnet.close()
        self.nrlp.close()
        self.prelude.close()
        self.clink.close()
        self.btts.close()
        self.mysterious.close()

    def logATT(self, direction, payload):
        ts = time.time()
        self.att.write("{},{},ATT,{}\n".format(ts, direction, payload.hex()))

    def logMagnet(self, direction, typ, payload):
        ts = time.time()
        self.magnet.write("{},{},{},{}\n".format(ts, direction, typ, payload.hex()))

    def logNRLP(self, direction, payload):
        ts = time.time()
        self.nrlp.write("{},{},NRLP,{}\n".format(ts, direction, payload.hex()))

    def logPrelude(self, direction, payload):
        ts = time.time()
        self.prelude.write("{},{},Prelude,{}\n".format(ts, direction, payload.hex()))

    def logClink(self, direction, payload):
        ts = time.time()
        self.clink.write("{},{},CLink,{}\n".format(ts, direction, payload.hex()))

    def logBTTS(self, direction, payload):
        ts = time.time()
        self.btts.write("{},{},BT.TS,{}\n".format(ts, direction, payload.hex()))

    def logMysterious(self, direction, service, payload):
        ts = time.time()
        self.mysterious.write("{},{},{},{}\n".format(ts, direction, service, payload.hex()))