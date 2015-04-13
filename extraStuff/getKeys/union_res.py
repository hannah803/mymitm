import os, sys
def main(argv):
    path = os.getcwd()
    fs = []
    l = []
    for i in os.listdir(path):
        if os.path.splitext(i)[1] == sys.argv[1]:
            f = open(i, 'r') 
            fs.append(f)

    for f in fs:
        unique = {}.fromkeys(f.readlines()).keys()
        print f.name
        if len(sys.argv) > 2 and sys.argv[2] == '-v':
            print '\t', unique
        for i in unique:
            if i.strip() not in l:
                l.append(i.strip())
    print l, len(l)

if __name__ == "__main__":
    if len(sys.argv) == 1:
        print "[usage]: extension [-v]"
    else:
        main(sys.argv)
