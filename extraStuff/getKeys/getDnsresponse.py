import subprocess, time, sys

dnsServers = ['202.120.2.100', '8.8.8.8', '180.76.76.76', '114.114.114.114', '223.5.5.5', '199.91.73.222', '208.67.222.222', '199.91.73.222', '42.120.21.30', '1.2.4.8', '123.125.81.6']

for i in range(100):
    print i
    for dns in dnsServers:
        subprocess.Popen("nslookup " + sys.argv[1] + ' ' + dns + "|grep 'Address: ' >> " + sys.argv[1] + "_" + dns + ".ip", shell=True)
    time.sleep(5)
