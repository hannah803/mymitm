import os, sys
def main(argv):
    path = os.getcwd()
    fs = []
    l = []
    for i in os.listdir(path):
        tmp = i.split('_')
        if len(tmp) == 2:
            if tmp[1] == sys.argv[2] and tmp[0].rsplit('.', 1)[0] == sys.argv[1]:
                f = open(i, 'r') 
                fs.append(f)

    for f in fs:
        unique = {}.fromkeys([i.strip() for i in f.readlines()]).keys()
        if len(sys.argv) > 3:
            if sys.argv[3] == '-v':
                print f.name, '\t', len(unique)
            if sys.argv[3] == '-vv':
                print f.name, '\t', unique, len(unique)
        for i in unique:
            if i.strip() not in l:
                l.append(i.strip())
    if len(sys.argv) == 3:
        print l, len(l)
    if len(sys.argv) > 3 and sys.argv[3] == '-v':
        print len(l)

if __name__ == "__main__":
    if len(sys.argv) == 1:
        print "[usage]: host extension [-v]"
    elif len(sys.argv) == 2:
        l = []
        f = open(sys.argv[1], 'r')
        for i in f.readlines():
            if i.strip() not in l:
                l.append(i.strip())
        print '\n'.join(l)
        print len(l)
    else:
        main(sys.argv)
