#openconnect --user=loccs 192.168.0.160:443 --verbose --dtls-ciphers=AES128-SHA

from hashlib import md5,sha1,sha256
import hmac
import struct
from Crypto.Cipher import AES
from Crypto.Cipher import ARC4
import sys

class Handle():
    cipherList = ['\x00\x35', '\x00\x03', '\x00\x04', '\x00\x08']
    versionList = ['\x03\x00', '\x03\x01', '\x03\x02', '\x03\x03', '\x01\x00' ]#DTLS1.0
    masterSecretLabel = "master secret"
    keyExpansionLabel = "key expansion"

    def __init__(self, version, client_random, server_random, pre, cipher_suite):
        if version not in self.versionList:
            print "Unknown version!"
            print "Supported versions are",self.versionList
        

        assert len(client_random) == 32
        assert len(server_random)== 32
        assert len(cipher_suite) == 2
        self.c_seq = 0
        self.s_seq = 0
        self.version = version
        self.cipher_suite = cipher_suite
        self.export = False

        #print 'version', version.encode('hex'), 'decpre', pre.encode('hex'), 'cipher_suite', cipher_suite.encode('hex')
        self.master_secret =self.masterFromPreMasterSecret(version,pre,client_random,server_random)
        if self.cipher_suite not in self.cipherList:
            print "cipher not supported yet!!!", self.cipher_suite.encode('hex')
        if cipher_suite == '\x00\x35':#aes_256_cbc_sha
            self.macLen, self.keyLen, self.ivLen = (20, 32, 16)
            self.cMac,self.sMac,self.cKey,self.sKey,self.cIV,self.sIV = self.keysFromMasterSecret(version,self.master_secret,client_random,server_random,self.macLen,self.keyLen,self.ivLen,self.cipher_suite)
            self.cipher_server_write = AES.new(self.sKey, AES.MODE_CBC, self.sIV)
            self.cipher_client_write = AES.new(self.cKey, AES.MODE_CBC, self.cIV)
            self.hashfunc = sha1
        elif self.cipher_suite == '\x00\x03':#exp-rc4-40-md5
            self.export = True
            self.macLen, self.keyLen, self.ivLen = (16, 5, 0)
            self.cMac,self.sMac,self.cKey,self.sKey,self.cIV,self.sIV = self.keysFromMasterSecret(version,self.master_secret,client_random,server_random,self.macLen,self.keyLen,self.ivLen,self.cipher_suite)
            self.cipher_server_write = ARC4.new(self.sKey)
            self.cipher_client_write = ARC4.new(self.cKey)
            self.hashfunc = md5
        elif self.cipher_suite == '\x00\x04':#rc4-128-md5
            self.macLen, self.keyLen, self.ivLen = (16, 16, 0)
            self.cMac,self.sMac,self.cKey,self.sKey,self.cIV,self.sIV = self.keysFromMasterSecret(version,self.master_secret,client_random,server_random,self.macLen,self.keyLen,self.ivLen,self.cipher_suite)
            self.cipher_server_write = ARC4.new(self.sKey)
            self.cipher_client_write = ARC4.new(self.cKey)
            self.hashfunc = md5
        '''
        print "cMAC",self.cMac.encode('hex')
        print "sMAC",self.sMac.encode('hex')
        print "cKey",self.cKey.encode('hex')
        print "sKey",self.sKey.encode('hex')
        print "cIV",self.cIV.encode('hex')
        print "sIV",self.sIV.encode('hex')
        '''

    def encrypt(self, msg, label):
        if self.cipher_suite == '\x00\x35':
            msg = self.add_padding(msg, 16)
        if label == 'client':
            return self.cipher_client_write.encrypt(msg)
        elif label == 'server':
            return self.cipher_server_write.encrypt(msg)
        else:
            print "encrypt label error!!!"

    def decrypt(self, msg, label):
        if label == 'client':
            dec = self.cipher_client_write.decrypt(msg)
        elif label == 'server':
            dec = self.cipher_server_write.decrypt(msg)
        else:
            print "decrypt label error!!!"
        if self.cipher_suite == '\x00\x35':
            dec = self.strip_padding(dec)
        return dec

    def add_padding(self, data, align):
        padlen = (align - len(data) % align) % align
        padlen -= 1
        return data + chr(padlen)*padlen


    def strip_padding(self, data):
        padlen = ord(data[-1])
        for i in xrange(padlen):
            if ord(data[-i-2]) != padlen:
                raise ValueError('Invalid Block Cipher Padding')
        return data[:-padlen-1]


    def calhash(self, msg, label):
        if label == 'client':
            return hmac.new(self.cMac, msg, self.hashfunc).digest()
        elif label == 'server':
            return hmac.new(self.sMac, msg, self.hashfunc).digest()
        else:
            print "mac label error!!!"


    def calFinish(self, handshakemsg, finishedLabel):
        msg = md5(handshakemsg).digest() + sha1(handshakemsg).digest()
        lfinished = [0]*12
        self.prfForVersion(self.version, lfinished, self.master_secret, finishedLabel, msg)
        finished = ''.join(lfinished)

        prefix = "1400000c".decode('hex')
        return list(prefix + finished)


    def calmac(self, data, label):
        if label == 'client':
            seq_header = struct.pack('>Q', self.c_seq)
            self.c_seq += 1
        elif label == 'server':
            seq_header = struct.pack('>Q', self.s_seq)
            self.s_seq += 1
        else:
            raise ValueError('Invalid label')
        msg = seq_header + data;
        hashvalue = self.calhash(msg, label)
        return hashvalue

    def check_strip_mac(self, data, label):
        return data[:-self.macLen]

    def splitPreMasterSecret(self, premaster):
        length = len(premaster)
        return premaster[0:(length+1)/2],premaster[length/2:]

    def pHash(self, result,secret,seed,hashfunc):
            a=hmac.new(secret,seed,hashfunc).digest()
            j=0
            while j<len(result):
                    b = hmac.new(secret,a+seed,hashfunc).digest()
                    todo = len(b)
                    if j+todo > len(result):
                            todo=len(result)-j
                    result[j:j+todo] = b[0:todo]
                    j+=todo
                    a=hmac.new(secret,a,hashfunc).digest()

    #TLS 1.0 and TLS 1.1 pseudo-random function
    def prf10(self, result,secret,label,seed):
            labelandseed = label+seed
            s1,s2 = self.splitPreMasterSecret(secret)
            self.pHash(result,s1,labelandseed,md5)

            result2 = [0]*len(result)
            self.pHash(result2,s2,labelandseed,sha1)
            for i in range(len(result2)):
                    s = ord(result[i]) ^ ord(result2[i])
                    result[i] = chr(s)
        
    #TLS 1.2 pseudo-random function
    def prf12(self, result,secret,label,seed):
            labelandseed = label+seed
            self.pHash(result,secret,labelandseed,sha256)

    #SSL 3.0 prf
    def prf30(self, result,secret,label,seed):
        done=0
        i =0
        while done < len(result):
            pad = '' 
            for j in range(0,i+1):
                pad += chr(ord('A')+i)
            digest = sha1(pad[:i+1]+secret+seed).digest()

            t = md5(secret+digest).digest()
            todo = len(t)
            if len(result)-done < todo:
                todo = len(result)-done
            result[done:done+todo] = t[:todo]
            done += todo
            i+=1

    def prfForVersion(self, version,result,secret,label,seed):
        if version ==  '\x03\x00':
                return self.prf30(result,secret,label,seed)
        elif version == '\x03\x01' or version == '\x03\x02' or version == '\x01\00':
                return self.prf10(result,secret,label,seed)
        elif version ==  '\x03\x03':
                return self.prf12(result,secret,label,seed)
        else:
            raise Exception("Unknow version type!")


    def masterFromPreMasterSecret(self, version,preMasterSecret,clientRandom,serverRandom):
        seed = clientRandom+serverRandom
        mastersecret = [0]*48
        self.prfForVersion(version,mastersecret,preMasterSecret,self.masterSecretLabel,seed)
        mastersecret = ''.join(mastersecret)
        return mastersecret

            
    def keysFromMasterSecret(self, version,masterSecret,clientRandom,serverRandom,macLen,keyLen,ivLen,cipher_suite):
        macLen = self.macLen
        keyLen = self.keyLen
        ivLen = self.ivLen

        seed = serverRandom + clientRandom
        n = 2*macLen + 2*keyLen + 2*ivLen
        keyBlock = [0]*n
        self.prfForVersion(version,keyBlock,masterSecret,self.keyExpansionLabel,seed)

        i=0
        clientMAC = keyBlock[i:i+macLen]
        clientMAC = ''.join(clientMAC)
        i+= macLen
        
        serverMAC = keyBlock[i:i+macLen]
        serverMAC = ''.join(serverMAC)
        i+=macLen

        clientKey = keyBlock[i:i+keyLen]
        clientKey = ''.join(clientKey)
        i+=keyLen

        serverKey = keyBlock[i:i+keyLen]
        serverKey = ''.join(serverKey)
        i+=keyLen

        clientIV = [0]*self.ivLen
        serverIV = [0]*self.ivLen

        if not self.export: #non-export
            clientIV = keyBlock[i:i+ivLen]
            clientIV = ''.join(clientIV)
            i+=ivLen
            serverIV = keyBlock[i:i+ivLen]
            serverIV = ''.join(serverIV)
            return clientMAC,serverMAC,clientKey, serverKey,clientIV,serverIV
        else:
            fclientKey = [0]*16
            self.prfForVersion(version, fclientKey, clientKey, "client write key", clientRandom+serverRandom)
            fserverKey = [0]*16
            self.prfForVersion(version, fserverKey, serverKey, "server write key", clientRandom+serverRandom)

            ivBlock = [0]*2*ivLen
            self.prfForVersion(version, ivBlock, "", "IV block", clientRandom+serverRandom)
            clientIV = ''.join(ivBlock[:ivLen])
            serverIV = ''.join(ivBlock[ivLen: 2*ivLen])
            return clientMAC,serverMAC,''.join(fclientKey),''.join(fserverKey),clientIV,serverIV





        

        

