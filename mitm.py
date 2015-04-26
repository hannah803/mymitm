#!/usr/bin/env python
# encoding: utf-8

import socket
import SocketServer
import struct
from handleConversation import Handle
from header import *

class ServerHandler(SocketServer.BaseRequestHandler):

    #clientcipher = ['\x00', '\x35']
    clientcipher = '\x00\x04'
    Nlist = []

    def handle(self):
        self.clientrandom = ''
        self.serverrandom = '' 
        self.version = ''
        self.modulus = ''
        self.pre = ''
        self.c_hsmsg = ''
        self.s_hsmsg = ''
        self.clientfinished = False
        self.serverfinished = False
        self.servercipher = ''

        csock = self.request
        ssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #ip, port = get_original_addr(csock)
        ssock.connect((ip, port))
        print "Connecting (%s, %s)"%(ip, port)

        try:
            while (1):
                datalist = recv_one(ssock, csock)
                if len(datalist) == 0:
                    break
                for readable, data in datalist:
                    content_type = data[0]
                    version = data[1:3]
                    rec_len = struct.unpack(">H", data[3:5])[0]
                    payload = data[5:5+rec_len]
                    if readable == csock:
                        label = 'client'
                    else:
                        label = 'server'
                    
                    if content_type == HANDSHAKE:
                        pro_len = 0
                        send_data = ''
                        while True:
                            if rec_len <=40:
                                send_data = self.processHandshake(payload, label)
                                break
                            hs_len = int(payload[1:4].encode('hex'), 16)
                            new_data = self.processHandshake(payload[:4+hs_len], label)
                            send_data += new_data
                            pro_len += (4+hs_len)
                            if pro_len == rec_len:
                                break
                            payload = payload[4+hs_len:]
                        payload = send_data 
                    elif content_type == CHANGE_CIPHER_SPEC:
                        assert(rec_len == 1)
                        assert(payload == '\x01')
                        if readable == csock:
                            print "CLIENT_CHANGE_CIPHER_SPEC"
                            self.handleclient = Handle(self.version, self.clientrandom, self.serverrandom, self.pre, self.clientcipher)
                            self.handleserver = Handle(self.version, self.clientrandom, self.serverrandom, self.pre, self.servercipher)
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
                            dec = self.handleclient.decrypt(payload, label)
                            dec = self.handleclient.check_strip_mac(dec, label)
                            
                            print 'CLIENT:', dec
                            pdata = content_type + version + struct.pack('>H', len(dec)) + dec
                            mac = self.handleserver.calmac(pdata, label)
                            enc = self.handleserver.encrypt(dec+mac, label)
                        else:
                            label = 'server'
                            dec = self.handleserver.decrypt(payload, label)
                            dec = self.handleserver.check_strip_mac(dec, label)
                            print 'SERVER', dec
                            pdata = content_type + version + struct.pack('>H', len(dec)) + dec
                            mac = self.handleclient.calmac(pdata, label)
                            enc = self.handleclient.encrypt(dec+mac, label)
                        payload = enc
                        print '-'*80
                        print '-'*29 + 'APPLICATION_DATA END' + '-'*29
                        print '-'*80

                    if readable == csock:
                        ssock.sendall(content_type + version + struct.pack('>H', len(payload)) + payload)
                    else:
                        csock.sendall(content_type + version + struct.pack('>H', len(payload)) + payload)
        except socket.error:
            pass
        finally:
            ssock.close()
                            
    def processHandshake(self, data, label):
        hs_type = ord(data[0])
        if hs_type == HELLO_REQUEST:
            print "HELLO_REQUEST"
        elif hs_type == CLIENT_HELLO and not (self.clientfinished or self.serverfinished):
            print "CLIENT_HELLO"
            self.c_hsmsg += data
            data = self.helloprocess(data)
            self.s_hsmsg += data
        elif hs_type == SERVER_HELLO and not (self.clientfinished or self.serverfinished):
            print "SERVER_HELLO"
            self.s_hsmsg += data
            data = self.helloprocess(data)
            self.c_hsmsg += data
        elif hs_type == CERTIFICATE and not (self.clientfinished or self.serverfinished):
            print "CERTIFICATE"
            self.c_hsmsg += data
            self.s_hsmsg += data
        elif hs_type == SERVER_KEY_EXCHANGE and not (self.clientfinished or self.serverfinished):
            self.s_hsmsg += data
            print "SERVER_KEY_EXCHANGE"
            self.serverkeyexgprocess(data)
            self.c_hsmsg += data
        elif hs_type == CERTIFICATE_REQUEST:
            print "CERTIFICATE_REQUEST"
        elif hs_type == SERVER_HELLO_DONE and not (self.clientfinished or self.serverfinished):
            print "SERVER_HELLO_DONE"
            self.c_hsmsg += data
            self.s_hsmsg += data
        elif hs_type == CERTIFICATE_VERIFY:
            print "CERTIFICATE_VERIFY"
        elif hs_type == CLIENT_KEY_EXCHANGE and not (self.clientfinished or self.serverfinished):
            print "CLIENT_KEY_EXCHANGE"
            self.c_hsmsg += data
            self.clientkeyexgprocess(data)
            self.s_hsmsg += data
        elif hs_type == CERTIFICATE_STATUS:
            print "CERTIFICATE_STATUS"
        else:
            if label == 'client' and self.clientfinished:
                print "CLIENT_ENCRYPTED_HS_MSG"
                if not self.client_verify_finished(data):
                    print 'Client Finished Verify Error!'
                forged_finish = self.client_forge_finished()
                data = forged_finish
                #print 'forged client finished:', self.postprocess(data).encode('hex')
            elif label == 'server' and self.serverfinished:
                print "SERVER_ENCRYPTED_HS_MSG"
                if not self.server_verify_finished(data):
                    print "Server Finshed Verify Error!!"
                forged_finish = self.server_forge_finished()
                data = forged_finish
                #print 'forged server finished:', self.postprocess(data).encode('hex')
            else:
                print 'label:', label, self.clientfinished, self.serverfinished
                print "error!!!!not handshake message!!"
                #print self.postprocess(data).encode('hex')
        return data


    
    def helloprocess(self, data):
        hs_type = data[0:1]
        hs_len = data[1:4]
        self.version = data[4:6]
        random = data[6:38]
        sessionid_len = ord(data[38:39])
        if ord(hs_type) == CLIENT_HELLO:
            self.clientrandom = random
            cs_len = struct.unpack(">H", "".join(data[39 + sessionid_len: 39 + sessionid_len + 2]))[0]
            
            #for i in range(min(cs_len/2, len(l))):
            #    data[39 + sessionid_len + 2 + 2 * i] = '\x00'
            #    data[39 + sessionid_len + 2 + 1 + 2 * i] = chr(l[i])
            new_sessionid_len = '\x00'
            new_cs_len = struct.pack(">H", 2)
            new_cs = struct.pack(">H", 3)
            newhello = self.version + random + new_sessionid_len + new_cs_len + new_cs + data[39+sessionid_len+2+cs_len:]
            newhello = hs_type + struct.pack('>I', len(newhello))[1:] + newhello
            return newhello
        elif ord(hs_type) == SERVER_HELLO:
            self.serverrandom = random
            self.servercipher = data[39 + sessionid_len:39 + sessionid_len + 2]
            print 'Server TLS Version: %s' % self.version.encode('hex')
            print 'Server CipherSuite: %s' % self.servercipher.encode('hex')
            print 'Client CipherSuite: %s' % self.clientcipher.encode('hex')

            new_sessionid_len = '\x00'
            newhello = self.version + random + new_sessionid_len + self.clientcipher + data[41 + sessionid_len:]
            newhello = hs_type + struct.pack('>I', len(newhello))[1:] + newhello
            return newhello
        else:
            print "error!!!Not hellomessage!!"
            print data.encode('hex')

    def serverkeyexgprocess(self, data):
        key_len = struct.unpack('>H', data[4:6])[0]
        self.modulus = data[6:6+key_len]

    def clientkeyexgprocess(self, data):
        pm_len = struct.unpack('>H', data[4:6])[0]
        print 'pmlen', pm_len
        self.calpre(data[6:6+pm_len])

    def client_verify_finished(self, data):
        encfinish = data
        #print 'encrypted client hsmsg:', self.postprocess(encfinish).encode('hex')
        decfinish = self.handleclient.decrypt(encfinish, 'client')
        #print 'decrypted client hsmsg:', decfinish.encode('hex')
        decmac = decfinish[16:]
        decfinish = decfinish[:16]
        mac = self.handleclient.calmac('\x16' + self.version + struct.pack('>H', len(decfinish)) + decfinish, 'client')
        if mac != decmac:
            raise ValueError('Finish Mac Error')
        caledfinish = self.handleclient.calFinish(self.c_hsmsg, 'client finished')
        self.c_hsmsg += caledfinish
        #print 'calclated client hsmsg:', caledfinish.encode('hex')
        return decfinish == caledfinish

    def server_verify_finished(self, data):
        encfinish = data
        #print 'encrypted server hsmsg:', self.postprocess(encfinish).encode('hex')
        decfinish = self.handleserver.decrypt(encfinish, 'server')
        #print 'decrypted server hsmsg:', decfinish.encode('hex')
        decmac = decfinish[16:]
        decfinish = decfinish[:16]
        mac = self.handleserver.calmac('\x16' + self.version + struct.pack('>H', len(decfinish)) + decfinish, 'server')
        if mac != decmac:
            raise ValueError('Finish Mac Error')
        caledfinish = self.handleserver.calFinish(self.s_hsmsg, 'server finished')
        self.s_hsmsg += caledfinish
        #print 'calclated server hsmsg:', caledfinish.encode('hex')
        return decfinish == caledfinish

    def client_forge_finished(self):
        forged_finish = self.handleserver.calFinish(self.s_hsmsg, 'client finished')
        self.s_hsmsg += forged_finish
        forged_mac = self.handleserver.calmac('\x16' + self.version + struct.pack('>H', len(forged_finish)) + forged_finish, 'client')
        return self.handleserver.encrypt(forged_finish + forged_mac, 'client')

    def server_forge_finished(self):
        forged_finish = self.handleclient.calFinish(self.c_hsmsg, 'server finished')
        self.c_hsmsg += forged_finish
        forged_mac = self.handleclient.calmac('\x16' + self.version + struct.pack('>H', len(forged_finish)) + forged_finish, 'server')
        return self.handleclient.encrypt(forged_finish + forged_mac, 'server')


    def calpre(self, encpre):
        n = self.modulus.encode('hex')
        print 'Ns: ', Ns
        if n in Ns.keys():
            d = Ns[n]
            print "N hit!", n
        else:
            print 'N: %s'%(self.modulus.encode('hex'))
            if self.modulus.encode('hex') not in self.Nlist:
                self.Nlist.append(self.modulus.encode('hex'))
            print self.Nlist
            raise ValueError('Invalid N')
        c = int(encpre.encode('hex'), 16)
        d = int(d, 16)
        n = int(n, 16)
        m = pow(c, d, n)
        dec = hex(m)[2:].strip('L').rjust(128, '0').decode('hex')
        assert(dec[0:2] == '\x00\x02')
        self.pre = dec[dec.find('\x00', 2)+1 :]



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
    Ns = {}
    getPossibleN()
    ThreadedServer(('', PORT), ServerHandler).serve_forever()
