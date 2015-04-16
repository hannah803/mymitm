import os, sys, subprocess
import time

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
            res = ''.join(s.split())
            if not len(res) == 0:
                result.append(res.decode('hex')[6:6+64].encode('hex'))
            s = '' 
    f.close()
    if len(sys.argv) == 4 and sys.argv[3] == '-v':
        t = open(host+'_trace', 'w')
        t.write('\n'.join(result))
        print len(result), "lines written to trace file"
    return {}.fromkeys(result).keys()
    

def run(count):
    for i in range(count):
        if i%10==0:
            print i
        p = subprocess.Popen('sh sclient.sh '+host, stderr=subprocess.PIPE, shell=True)
        time.sleep(5)

if __name__=='__main__':
    if len(sys.argv) == 1:
        print '[usage] host -run count / -trim [-v]'
    else:
        host = sys.argv[1]
        if sys.argv[2] == '-run':
            assert(len(sys.argv) == 4)
            run(int(sys.argv[3], 10))
        elif sys.argv[2] == '-trim':
            res = trim()
            if len(sys.argv) == 3:
                f = open(host+'_set', 'w')
                f.write('\r\n'.join(res))
                print res, len(res)
        else:
            print 'parameter wrong!'
