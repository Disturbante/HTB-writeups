# Nocturnal (10.10.11.64)

- Open ports:
```bash
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 20:26:88:70:08:51:ee:de:3a:a6:20:41:87:96:25:17 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDpf3JJv7Vr55+A/O4p/l+TRCtst7lttqsZHEA42U5Edkqx/Kb8c+F0A4wMCVOMqwyR/PaMdmzAomYGvNYhi3NelwIEqdKKnL+5svrsStqb9XjyShPD9SQK5Su7xBt+/TfJyJFRcsl7ZJdfc6xnNHQITvwa6uZhLsicycj0yf1Mwdzy9hsc8KRY2fhzARBaPUFdG0xte2MkaGXCBuI0tMHsqJpkeZ46MQJbH5oh4zqg2J8KW+m1suAC5toA9kaLgRis8p/wSiLYtsfYyLkOt2U+E+FZs4i3vhVxb9Sjl9QuuhKaGKQN2aKc8ItrK8dxpUbXfHr1Y48HtUejBj+AleMrUMBXQtjzWheSe/dKeZyq8EuCAzeEKdKs4C7ZJITVxEe8toy7jRmBrsDe4oYcQU2J76cvNZomU9VlRv/lkxO6+158WtxqHGTzvaGIZXijIWj62ZrgTS6IpdjP3Yx7KX6bCxpZQ3+jyYN1IdppOzDYRGMjhq5ybD4eI437q6CSL20=
|   256 4f:80:05:33:a6:d4:22:64:e9:ed:14:e3:12:bc:96:f1 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLcnMmaOpYYv5IoOYfwkaYqI9hP6MhgXCT9Cld1XLFLBhT+9SsJEpV6Ecv+d3A1mEOoFL4sbJlvrt2v5VoHcf4M=
|   256 d9:88:1f:68:43:8e:d4:2a:52:fc:f0:66:d4:b9:ee:6b (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIASsDOOb+I4J4vIK5Kz0oHmXjwRJMHNJjXKXKsW0z/dy
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://nocturnal.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
```
- no container from TTL
- virtual host
- classic web + ssh

# HTTP 10.10.11.64:80

- mail in source: "support@nocturnal.htb"
- tech stack: PHP, NGINX 1.18.0, Ubuntu
- no SSTI in /dashboard.php
- no sqli in login.php

- no robots.txt
- routes found:
```txt
/login.php
/register.php
/backups/
/uploads/
/admin.php
/view.php?username=admin2&file=upload1.pdf
```

- after register (admin2:admin2) we can upload files
  - only "pdf, doc, docx, xls, xlsx, odt are allowed."
- just the extension is checked, try some bypass to upload PHP

- we can bruteforce usernames using /view.php enpoint:
```html
/view.php?username=amanda&file=.pdf

<a href="view.php?username=amanda&file=privacy.odt">privacy.odt</a>
```
- creds found inside odt file: 'a[REDACTED]J'

- amanda is an admin user
- we now have access to /admin.php
- we can dump a backup with also the db

- in the DB we have the hash of tobias:
```
55c8[REDACTED]061d
```
- cracked in crackstation: slowmotionapocalypse

- users:
  - amanda:a[REDACTED]1J
  - tobias:s[REDACTED]e

# SSH - tobias

- user access as tobias
- strange sendmail suid (not important)
- port 8080 is hosting another website
- forwarded using ssh tobias@nocturnal.htb -L 8081:127.0.0.1:8080

## HTTP - 127.0.0.1:8080

- ISPconfig service, server management application
- we can access using default user admin and slowmotionapocalypse as password
- we found CVE-2023-46818 (https://github.com/bipbopbup/CVE-2023-46818-python-exploit/raw/refs/heads/main/exploit.py)
- we are root by running:
```bash
python3 exploit.py http://127.0.0.1:8081/ admin sl[REDACTED]se
```
