import os, sys, subprocess
import time

host = 'suning.com'

def trim():
    result = []
    s = ''
    f = open(host, 'r')
    for l in f.readlines():
        l = ''.join(l.split())
        if (l.find('ServerKeyExchange') == -1):
            s += l
        else:
            #print 'SeverKeyExchange'
            #print s
            res = ''.join(s.split())
            #print len(res)
            result.append(res.decode('hex')[6:6+64].encode('hex'))
            s = '' 
    f.close()
    return {}.fromkeys(result).keys()
    

def run():
    for i in range(1000):
        if i%10==0:
            print i
        p = subprocess.Popen('sh sclient.sh '+host, stderr=subprocess.PIPE, shell=True)
        time.sleep(5)

if __name__=='__main__':
    global host
    if len(sys.argv) >= 2:
        host = sys.argv[1]
    if sys.argv[2] == '-run':
        run()
        res = trim()[1:]
        f = open(host+'_res.txt', 'w')
        f.write('\r\n'.join(res))
        print res, len(res)
    elif sys.argv[2] == '-trim':
        res = trim()[1:]
        f = open(host+'_res.txt', 'w')
        f.write('\r\n'.join(res))
        print res, len(res)
    else:
        print 'parameter wrong!'
