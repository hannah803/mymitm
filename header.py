#!/usr/bin/env python
#encoding: utf-8
import select
import struct
PORT = 8888
SO_ORIGINAL_DST = 80

CHANGE_CIPHER_SPEC = '\x14'
ALERT = '\x15'
HANDSHAKE = '\x16'
APPLICATION_DATA = '\x17'

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

#ip = 'passport.suning.com'
ip = '119.188.139.98'
ip = '182.118.77.102'
ip = '42.202.151.37'
'''
#ip = "kyfw.12306.cn"
ip = '58.216.21.93'
ip = '61.156.243.247'
ip = '122.70.142.160'
#ip = "secure.damai.cn"
ip = '58.83.157.190'
'''
port = 443

'''
https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4
0x00,0x03	TLS_RSA_EXPORT_WITH_RC4_40_MD5
0x00,0x06	TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
0x00,0x08	TLS_RSA_EXPORT_WITH_DES40_CBC_SHAY[RFC4346]
0x00,0x0B	TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHAY[RFC4346]
0x00,0x0E	TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHAY[RFC4346]
0x00,0x11	TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHAY[RFC4346]
0x00,0x14	TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHAY[RFC4346]
0x00,0x17	TLS_DH_anon_EXPORT_WITH_RC4_40_MD5N[RFC4346][RFC6347]
0x00,0x19	TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHAY[RFC4346]
0x00,0x26	TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHAY[RFC2712]
0x00,0x27	TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHAY[RFC2712]
0x00,0x28	TLS_KRB5_EXPORT_WITH_RC4_40_SHAN[RFC2712][RFC6347]
0x00,0x29	TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5Y[RFC2712]
0x00,0x2A	TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5Y[RFC2712]
0x00,0x2B	TLS_KRB5_EXPORT_WITH_RC4_40_MD5N[RFC2712][RFC6347]
0xC0,0x03	TLS_RSA_EXPORT_WITH_RC4_40_MD5NTLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHAY[RFC4492]
0xC0,0x06	TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5YTLS_ECDHE_ECDSA_WITH_NULL_SHAY[RFC4492]
0xC0,0x08	TLS_RSA_EXPORT_WITH_DES40_CBC_SHAYTLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHAY[RFC4492]
0xC0,0x0B	TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHAYTLS_ECDH_RSA_WITH_NULL_SHAY[RFC4492]
0xC0,0x0E	TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHAYTLS_ECDH_RSA_WITH_AES_128_CBC_SHAY[RFC4492]
0xC0,0x11	TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHAYTLS_ECDHE_RSA_WITH_RC4_128_SHAN[RFC4492][RFC6347]
0xC0,0x14	TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHAYTLS_ECDHE_RSA_WITH_AES_256_CBC_SHAY[RFC4492]
0xC0,0x17	TLS_DH_anon_EXPORT_WITH_RC4_40_MD5NTLS_ECDH_anon_WITH_3DES_EDE_CBC_SHAY[RFC4492]
0xC0,0x19	TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHAYTLS_ECDH_anon_WITH_AES_256_CBC_SHAY[RFC4492]
0xC0,0x26	TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHAYTLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384Y[RFC5289]
0xC0,0x27	TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHAYTLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256Y[RFC5289]
0xC0,0x28	TLS_KRB5_EXPORT_WITH_RC4_40_SHANTLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384Y[RFC5289]
0xC0,0x29	TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5YTLS_ECDH_RSA_WITH_AES_128_CBC_SHA256Y[RFC5289]
0xC0,0x2A	TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5YTLS_ECDH_RSA_WITH_AES_256_CBC_SHA384Y[RFC5289]
0xC0,0x2B	TLS_KRB5_EXPORT_WITH_RC4_40_MD5NTLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256Y[RFC5289]
'''
cipher_list = ['\x03', '\x06', '\x08', '\x0b', '\x0e', 0x26, 0x00, 0x01, 0x02, 0x06,\
        0x08, 0x0b, 0x0e, 0x11, 0x14, 0x17, 0x19, 0x27, 0x28, 0x29,\
        0x2a, 0x2b, 0x18, 0x1a, 0x1b, 0x34, 0x3a, 0x46, 0x6c, 0x6d,\
        0x89, 0x9b, 0xa6, 0xa7, 0xbf, 0xc5, 0x2c, 0x2d, 0x2e, 0x3b,\
        0xb0, 0xb1, 0xb4, 0xb5, 0xb8, 0xb9]

def recv_one(ssock, csock):
    readable = select.select([ssock, csock], [], [], 30)[0]
    datalist = []
    if len(readable) == 0:
        print "none is readable!!!"
    for r in readable:
        record_header = recvall(r, 5)
        if len(record_header) < 5:
            continue
        length = struct.unpack(">H", record_header[3:5])[0]
        data = recvall(r, length)
        assert(len(data) == length)
        datalist.append((r, record_header + data))
    return datalist

def recvall(client, length):
    rlen = length
    data = ''
    while rlen > 0:
        tmp = client.recv(rlen)
        if not tmp:
            break
        data += tmp
        rlen -= len(tmp)
    return data

def read_line(client):
    line = ''
    while True:
        s = client.recv(1)
        if not s:
            break
        if s == '\n':
            break
        line += s
    return line

def get_original_addr(csock):
    odestdata = csock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    _, port, a1, a2, a3, a4 = struct.unpack("!HHBBBBxxxxxxxx", odestdata)
    address = "%d.%d.%d.%d" % (a1, a2, a3, a4)
    return address, port
