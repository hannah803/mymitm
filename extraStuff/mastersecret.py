# cat test.enc | openssl rsautl -decrypt -inkey rsa.key | xxd
#gnutls-cli -p 443 www.baidu.com -d 9 --insecure --priority=NONE:+VERS-TLS1.0:+AES-128-CBC:+RSA:+SHA1:+COMP-NULL
#openconnect --user=loccs 192.168.0.160:443 --verbose --dtls-ciphers=AES128-SHA

from hashlib import md5,sha1,sha256
import hmac
from Crypto.Cipher import AES
import sys

versionList = ["TLS1.0","TLS1.1","TLS1.2","SSL3.0","DTLS1.0"]
masterSecretLabel = "master secret"
keyExpansionLabel = "key expansion"
finishedLabel = "client finished"
macLen = 20
keyLen = 32
ivLen  = 16

def splitPreMasterSecret(premaster):
	length = len(premaster)
	return premaster[0:(length+1)/2],premaster[length/2:]

def pHash(result,secret,seed,hashfunc):
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
def prf10(result,secret,label,seed):
		labelandseed = label+seed
		s1,s2 = splitPreMasterSecret(secret)
		pHash(result,s1,labelandseed,md5)

		result2 = [0]*len(result)
		pHash(result2,s2,labelandseed,sha1)
		for i in range(len(result2)):
				s = ord(result[i]) ^ ord(result2[i])
				result[i] = chr(s)
	
#TLS 1.2 pseudo-random function
def prf12(result,secret,label,seed):
		labelandseed = label+seed
		pHash(result,secret,labelandseed,sha256)

#SSL 3.0 prf
def prf30(result,secret,label,seed):
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

def prfForVersion(version,result,secret,label,seed):
	if version ==  "SSL3.0":
			return prf30(result,secret,label,seed)
	elif version == "TLS1.0" or version == "TLS1.1" or version == "DTLS1.0":
			return prf10(result,secret,label,seed)
	elif version ==  "TLS1.2":
			return prf12(result,secret,label,seed)
	else:
		raise Exception("Unknow version type!")


def masterFromPreMasterSecret(version,preMasterSecret,clientRandom,serverRandom):
		seed = clientRandom+serverRandom
		mastersecret = [0]*48
		prfForVersion(version,mastersecret,preMasterSecret,masterSecretLabel,seed)
		mastersecret = ''.join(mastersecret)
		return mastersecret
	
def keysFromMasterSecret(version,masterSecret,clientRandom,serverRandom,macLen,keyLen,ivLen):
		seed = serverRandom + clientRandom
		n = 2*macLen + 2*keyLen + 2*ivLen
		keyBlock = [0]*n
		prfForVersion(version,keyBlock,masterSecret,keyExpansionLabel,seed)

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

		clientIV = keyBlock[i:i+ivLen]
		clientIV = ''.join(clientIV)
		i+=ivLen

		serverIV = keyBlock[i:i+ivLen]
		serverIV = ''.join(serverIV)
		return clientMAC,serverMAC,clientKey,serverKey,clientIV,serverIV

def verifyData(version, mastersecret, finishedLabel, handshakemessage):
	data = [0]*12
	prfForVersion(version, data, mastersecret, finishedLabel, handshakemessage)
	return data

def encrypt(key, iv, msg):
	cipher = AES.new(key, AES.MODE_CBC, iv)
	return cipher.encrypt(msg)				

def decrypt(key,iv,msg):
		cipher = AES.new(key,AES.MODE_CBC,iv)
		return cipher.decrypt(msg)


def test():
	if len(sys.argv) < 2:
		print "Usage:",sys.argv[0],"input.txt"
		return
	fname = sys.argv[1]
	fd = open(fname,"r")
	version = fd.readline().strip()
	if version not in versionList:
		print "Unknown version!"
		print "Supported versions are",versionList
		return
	prehex = ''
	masterhex = ''
	secrethex = fd.readline().strip()
	secrets = secrethex.split()
	if secrets[0].lower().startswith("pre"):
		prehex = secrets[1]
	elif secrets[0].lower().startswith("master"):
		masterhex = secrets[1]
	else:
		print "Unknown",secrets[0]
		print "Please start with PRE or Master"
		return
	
	clienthex = fd.readline().strip()
	serverhex = fd.readline().strip()
	cmsg = fd.readline().strip()
	smsg = fd.readline().strip()
	fd.close()
	
	print "**key len now **",keyLen

	if prehex:
		pre_master_secret = prehex.decode('hex')
		assert len(pre_master_secret) == 48
	else:
		master_secret = masterhex.decode('hex')
		assert len(master_secret)==48

	
	client_random = clienthex.decode('hex')
	assert len(client_random) == 32
	
	server_random = serverhex.decode('hex')
	assert len(server_random)== 32

	if prehex:	
		master_secret =masterFromPreMasterSecret(version,pre_master_secret,client_random,server_random)
	print "pre master secret",prehex
	print "client random",clienthex
	print "server random",serverhex
	print "master secret",master_secret.encode('hex')

	cMac,sMac,cKey,sKey,cIV,sIV = keysFromMasterSecret(version,master_secret,client_random,server_random,macLen,keyLen,ivLen)
	print "cMAC",cMac.encode('hex')
	print "sMAC",sMac.encode('hex')
	print "cKey",cKey.encode('hex')
	print "sKey",sKey.encode('hex')
	print "cIV",cIV.encode('hex')
	print "sIV",sIV.encode('hex')

	print "-"*80
	print "client data start"
#	clientcipher = AES.new(cKey,AES.MODE_CBC,cIV)
#	cmsg = cmsg.decode('hex')
#	t=clientcipher.decrypt(cmsg)
	t= decrypt(cKey,cIV,cmsg.decode('hex'))
	print t.encode('hex')
	print "client data end"


	clienthello="010000eb030155165f4e5a1e9a94f0288b2fe5a1d9c502e1e83bcde2c0ec92812bca117c9b3c20cfe30497301c4dd191e613407f8b5803faa1238f179bafab88307e992b583761004600040005002f0035c002c004c005c00cc00ec00fc007c009c00ac011c013c0140033003900320038000ac003c00dc008c01200160013000900150012000300080014001100ff0100005c00000018001600001370617373706f72742e73756e696e672e636f6d000b000403000102000a00340032000e000d0019000b000c00180009000a00160017000800060007001400150004000500120013000100020003000f00100011"
	serverhello="02000046030155165f4dd3e6a90ce46c36c999fa8ba47a9a9190699e08f2a3084bba89271fb320c14bc6018ad2e0a88d1b826dd88e1c38add4b494517f98aec3cec22c1896e2e0003500"
	certificate="0b000de3000de00005123082050e308203f6a00302010202104af967c8c7ede4ab9e3fbc60258fa920300d06092a864886f70d0101050500304a310b300906035504061302555331153013060355040a130c576f5369676e2c20496e632e312430220603550403131b576f5369676e205347432053657276657220417574686f72697479301e170d3131303131373030303030305a170d3136303131373233353935395a3081b3310b300906035504061302434e3110300e060355040813074a49414e4753553110300e060355040713074e414e4a494e473121301f060355040a131853554e494e47204150504c49414e434520434f2e2c4c544431193017060355040b131054727573742057656273697465204944310c300a060355040b1303423243311d301b060355040b1314534743205a68656e53534c2057696c6463617264311530130603550403140c2a2e73756e696e672e636f6d30820122300d06092a864886f70d01010105000382010f003082010a028201010097bcf20e4abc6c91584a13390d81d8dcc9635df0c5f042b99f4f97430d8fed56a7478705d3df84e398bbb1a59bcbd3b46913e851d67335d1008faad32e85af0df7a303309a872951f351468ca58e651da4edca54c1e28d7e82eb5c07431ff326b1849d889257ad5436816bd9b6c3ac37f38f4557da313515b6cf223f6d30a47cd7c9526bb1e7568f32e1fe27f62cb79d9393f0b4a1502f63d2bd78c6e89040351d3feb2b36ec9ae8acb2fe6da12518ca2cfc8da10cd95cdb4c0c366bf0458f60e8348c06cd8ebb65a62f5d4851acafb192355751009af6ed80c401fc919636ad3c2e0b5388bfc062a9da2cb8508d06bdb853d34f53f3af3282d55343c9cf27a50203010001a382018430820180301f0603551d23041830168014ca34b512b9ba8c45b1f9acfde7b4a486b2ecca21301d0603551d0e04160414357b8bc7c49d455c466ef749808dd2eba57e9ef7300e0603551d0f0101ff0404030205a0300c0603551d130101ff0402300030340603551d25042d302b06082b0601050507030106082b06010505070302060a2b0601040182370a030306096086480186f842040130420603551d20043b30393037060b2b06010401b231010202163028302606082b06010505070201161a687474703a2f2f7777772e776f7369676e2e636f6d2f6370732f303a0603551d1f04333031302fa02da02b8629687474703a2f2f63726c2e776f7369676e2e636f6d2f576f5369676e5347435365727665722e63726c304506082b0601050507010104393037303506082b060105050730028629687474703a2f2f6372742e776f7369676e2e636f6d2f576f5369676e5347435365727665722e63727430230603551d11041c301a820c2a2e73756e696e672e636f6d820a73756e696e672e636f6d300d06092a864886f70d010105050003820101004e63a6ba51873b6dcc8ca6ef0d13698db511eb30ba3942d89a361f654f28410631a73564f48da8816ffdbb5f7379ea1ad5001d3ef92a18f8f188e17fb6df4f72ebbd77c21cb17788eb5354ed68cfdf9e28519a31c9269ca6aa509131974d068e78a7a3215bad401c599ced1c2b39135a4e2e44d4e0893a68c49cc89ac56d834e695acc511a26846a98a2de1c4aa3345353de98b16bc079105297a8ec2fc1d7a05e37ecc6e2d5bc1e3f54be0caf6f3cc84497f4c2867dffd7ebbd9827815f6d6a770b0aba3a5e3e4d6e8d564bce09141b69e4c1e98e6e359b1c6a67d36d9fb6efcc8d32105dbf2119378e5bc310d6b0aae91a4080ee3b4e2ea52af6bbe29e63d70004633082045f30820347a003020102021054030193bf4d55bf8bf904a7c5ac72ae300d06092a864886f70d0101050500308193310b3009060355040613025553310b3009060355040813025554311730150603550407130e53616c74204c616b652043697479311e301c060355040a131554686520555345525452555354204e6574776f726b3121301f060355040b1318687474703a2f2f7777772e7573657274727573742e636f6d311b30190603550403131255544e202d2044415441436f727020534743301e170d3037303432353030303030305a170d3139303632343139303633305a304a310b300906035504061302555331153013060355040a130c576f5369676e2c20496e632e312430220603550403131b576f5369676e205347432053657276657220417574686f7269747930820122300d06092a864886f70d01010105000382010f003082010a0282010100a0d8badded5602ac13da58fbc8ea0496a3854c8b523c116ee6231b5d65f04323b56ccb605ede41bc7e1598031ae7773398be341c7d2a35b002aded2d98aef9a43ef2ad92156780a1a47eb8c630d0939e1c313203f5a34eb04182933c4c65b6903b33accb1e39c01f127485e3ed1a45002f798f351a3b8fd60368453a00afb13e343c48ffefc6c8cb21a56b1849120a8c35547caf8dcd1fcf081ab4196c1c2d54592a7b11d2f93ded3d24acb9c88aa677e6a947b84293cd37a1effaafaa075cd60394d5510399a273ccab15216e0c1a03e7d40438efd95dce4a9ecfabef23ee9ae23de97aca10dafc3973e2eb02db33d5cab909e08c461be9e095cebbc06ca1130203010001a381f63081f3301f0603551d230418301680145332d1b3cf7ffae0f1a05d854e92d29e451db44f301d0603551d0e04160414ca34b512b9ba8c45b1f9acfde7b4a486b2ecca21300e0603551d0f0101ff04040302010630120603551d130101ff040830060101ff02010030340603551d25042d302b06082b0601050507030106082b06010505070302060a2b0601040182370a030306096086480186f842040130180603551d200411300f300d060b2b06010401b23101020216303d0603551d1f043630343032a030a02e862c687474703a2f2f63726c2e7573657274727573742e636f6d2f55544e2d44415441436f72705347432e63726c300d06092a864886f70d01010505000382010100a7cee45297bf628e4bdddc76243699b605616b8bb189224be237ae9038c0da702bb1d23cda0deee4b2a5b718a23b3a86a8b5d7496a1e9f732156673904ddcbf4ab91531c520b5ff420c1081b7ed38b52442e8d20f46581db65c1699934de598d9642e3c299123c69808ab82fd1a7f8bc3200925f02f73c0aa1747d8cc3ca7283eb4fa25e6d404c7a31899d644d03556bf1d58f4911a399df59c0946741837973437f34a09c3251669961437759b5e651601ac23c6f448352e525b4891b61a81886161078ea7a12312ff9605d3b471c3d1bfb3f0f09e23b5a4f27542f51bd02142235537e87640db23427830a68e3c12dbae09c4e315ddaf8e871791dc10797b40004623082045e30820346a003020102021044be0c8b500021b411d32a6806a9ad69300d06092a864886f70d0101050500308193310b3009060355040613025553310b3009060355040813025554311730150603550407130e53616c74204c616b652043697479311e301c060355040a131554686520555345525452555354204e6574776f726b3121301f060355040b1318687474703a2f2f7777772e7573657274727573742e636f6d311b30190603550403131255544e202d2044415441436f727020534743301e170d3939303632343138353732315a170d3139303632343139303633305a308193310b3009060355040613025553310b3009060355040813025554311730150603550407130e53616c74204c616b652043697479311e301c060355040a131554686520555345525452555354204e6574776f726b3121301f060355040b1318687474703a2f2f7777772e7573657274727573742e636f6d311b30190603550403131255544e202d2044415441436f72702053474330820122300d06092a864886f70d01010105000382010f003082010a0282010100dfee5810a22b6e55c48ebf2e4609e7e0080f2e2b7a13941bbdf6b6808e650593001ebcafe20f8e190d1247ecacada3fa2e70f8de6efb5642159e2e5cef23de21b9057627190f4fd6c39cb4be941963f2a6110aeb53489cbef2293b16e81aa04ca6c9f4185968c070f25300c05e5082a5566f36f94ae04486a04d4ed6476e494acb67d7a6c405b98e1ef4fcffcde736e09c056cb2332215d0b4e0cc17c0b2c0f4fe323f292a957bd8f2a74e0f547ca10d80b30903c1ff5cdd5e9a3ebcaebc478a6aae71ca1fb12ab85f42050bec4630d1720bcae9566df5efdf78be61bab2a5ae044cbca8ac691597bdefebb48cbf35f8d4c3d1280e5c3a9f7018332077c4a2af0203010001a381ab3081a8300b0603551d0f0404030201c6300f0603551d130101ff040530030101ff301d0603551d0e041604145332d1b3cf7ffae0f1a05d854e92d29e451db44f303d0603551d1f043630343032a030a02e862c687474703a2f2f63726c2e7573657274727573742e636f6d2f55544e2d44415441436f72705347432e63726c302a0603551d250423302106082b06010505070301060a2b0601040182370a030306096086480186f8420401300d06092a864886f70d01010505000382010100273597008a8b28bdc633301e29fce2f7d598d440bb60cabfab172c09367f50fa41dcae963a0a233e8959c9a307ed1b37adfc7cbe51495ade3a0a54081645c299b187cd8c68e06903e9c44e98b23b8c16b30ea00c98509b93a97009c82ca38fdf02e4e0713af1b42372a0aa01dfdf983e1450a03126bd28e95a302675f97b601c8df3cd50266d04279adfd50d4547296b2ce676d9a9297d32ddc9363cbdae35f1119e1dbb903f12474e8ed77e0f62731d5226381c1849fd30749ac4e5222fd8c08ded917a4c008f727f5ddadd1b8b456be7dd6997a8c5564c0f0cf69f7a9137f69782e0dd7169ff763f604d3ccff799f9c657f4c9553978ba2c79c9a6882bf408"
	serverkeyexg="0c0001490040cbdaf418c0065668e545e475b1122639782d0307d3ecb450b860618e1a344b37e2e2d0aa5900e7bc2d6cfb327cfbb45e443e95eea64a6281fb4ad992c5a58e4b000301000101008a82843aca56fd9aa7bc04d973b06f6933d877d3b14dd367b1c9220424b930a91c44a3332fe56e72ce7bf882158700b175c7a4d4c086a10ba2db0b363ba443ada31612630e3aa8e0b75f656171ba3fc903e0953048f77be8822b14b85edb818e147a002e708d3abac1c41b783ce32bbc5e02596c97b1c9a439cd43e7b86cf99f4a74c996f9a790e37a12dcabe814c8f4f11a1bc5768268551b48aa9aff9d4128478d70b0d48d59122daa767d646ff2281824be227cfa5006d1bb8f40b23531e32bf7955cedd0f41c1291dbb0ce0a97e4cc03a9dcff0f558594c1680a5d9cc9d6cc18a483afaac14287a67ec742907c9d23844fb8f9ddfe298f0f1947fc6d9c88"
	serverhellodone="0e000000"
	clientkeyexg="1000004200404d8f74741bb3c6dfb6f28fc49ec4e11f296472afbaffc1999327f544243aab5e23ce2a466dbbde55e77f8c45ddbc47c4bbdfa5de76efa6099762ba78ca81ea2a"

	handshakemessage = (clienthello+serverhello+certificate+serverkeyexg+serverhellodone+clientkeyexg).decode('hex')
	msg = md5(handshakemessage).digest() + sha1(handshakemessage).digest()
	data = verifyData(version, master_secret, finishedLabel, msg)	
	finished = ''.join(data)
	print finished.encode('hex')
	
	seqnum = "00000000000000001603010010".decode('hex')
	prefix = "1400000c".decode('hex')
	h = hmac.new(cMac, seqnum + prefix + finished, sha1)
	hashvalue = h.digest()
	encryptedhandshakemsg = encrypt(cKey, cIV, prefix + finished + hashvalue + '\x0b'*12).encode('hex')
	print encryptedhandshakemsg, encryptedhandshakemsg == cmsg
	
if __name__=='__main__':
	test()
	

