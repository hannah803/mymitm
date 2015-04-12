import subprocess, time

for i in range(100):
	print i
	p = subprocess.Popen('nslookup passport.suning.com 199.91.73.222|grep "Address: " >> suning.ip', shell=True)
	p = subprocess.Popen('nslookup passport.suning.com 114.114.114.114|grep "Address: " >> suning.ip', shell=True)
	p = subprocess.Popen('nslookup passport.suning.com 223.5.5.5|grep "Address: " >> suning.ip', shell=True)
	time.sleep(5)
