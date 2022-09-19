---
Can you combine your great nmap skills with other tools to log in to this machine?
---

![|333](https://tryhackme-images.s3.amazonaws.com/room-icons/01aff3c76024f34b0582ad59e2138bfd.png)

You've learned some great nmap skills! Now can you combine that with other skills with netcat and protocols, to log in to this machine and find the flag? This VM 10.10.170.227 is listening on a high port, and if you connect to it it may give you some information you can use to connect to a lower port commonly used for remote access!

```
┌──(kali㉿kali)-[~]
└─$ rustscan -a 10.10.170.227 --ulimit 5000 -b 65535 -- -A 
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
[~] Automatically increasing ulimit value to 5000.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.170.227:22
Open 10.10.170.227:2222
Open 10.10.170.227:31337
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-19 11:13 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:13
Completed NSE at 11:13, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:13
Completed NSE at 11:13, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:13
Completed NSE at 11:13, 0.00s elapsed
Initiating Ping Scan at 11:13
Scanning 10.10.170.227 [2 ports]
Completed Ping Scan at 11:13, 0.20s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 11:13
Completed Parallel DNS resolution of 1 host. at 11:13, 0.01s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 11:13
Scanning 10.10.170.227 [3 ports]
Discovered open port 22/tcp on 10.10.170.227
Discovered open port 31337/tcp on 10.10.170.227
Discovered open port 2222/tcp on 10.10.170.227
Completed Connect Scan at 11:13, 0.20s elapsed (3 total ports)
Initiating Service scan at 11:13
Scanning 3 services on 10.10.170.227
Completed Service scan at 11:13, 22.79s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.170.227.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:13
Completed NSE at 11:13, 7.42s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:13
Completed NSE at 11:13, 1.70s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:13
Completed NSE at 11:13, 0.00s elapsed
Nmap scan report for 10.10.170.227
Host is up, received conn-refused (0.20s latency).
Scanned at 2022-09-19 11:13:13 EDT for 32s

PORT      STATE SERVICE REASON  VERSION
22/tcp    open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 7d:dc:eb:90:e4:af:33:d9:9f:0b:21:9a:fc:d5:77:f2 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDLgmREvZByFxoWZEVRzGogcBi04sMOoMHUcJ8P2t9mi8q1V+lRvZczumOJ9RliQ1khNRHsIgnJ7/Yp4iCz9UFRLYsIlQ2PAgODBjNyhIWepELlSatGLZqviC6qnxEASC2OrwFvHmYNklZIjbc4+Yli2bn8I2PjntRKoMQHjehoWip/V955dYwa7KysnPPMsmXlrx9dhHJ0yheqYIOxwlN2xRC7ZtQMfY28mn0ifRhMnM9RRgC5CDAJh3QeJYM90gBdIq466x4p6yWQzjK/t0i5zIKFBJBLp85DaT3WkWBn3ueHFoedeeAsXeO16BNX6SomLNWsslp5a3E1YQiOBX3LNEm64Rr8ekPxtrXhTzcBUMGJYzc7QaE2/N9yCnkvL0vCApO+XFmo+lr9bAt8qGixpqk1awPqIhxOTUWIr4lAShsu7b+mwQlGeYO7aEeaO3R7ZFaZwGfp2vF/yYwReT+mVimFbs67yiVcMCNhVgvI5vLFrh+OyvufUK2tnCe4xbs=
|   256 83:a7:4a:61:ef:93:a3:57:1a:57:38:5c:48:2a:eb:16 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEuffg4vybQqbP0RmSCYjd6nillwqgiGF1OAIPUsBCewLy6eiVYsnzAF3Z2TAHKjA8GqTlhRu05KWfdys7J+MQc=
|   256 30:bf:ef:94:08:86:07:00:f7:fc:df:e8:ed:fe:07:af (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILHnXOBOqSHpnx9JPguwJAsiurhjCuLjkOIfNSp9f9ai
2222/tcp  open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 f4:ec:10:27:3e:9c:7a:ad:f0:71:33:7d:fd:81:ec:20 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCsTEZt8hiwx5u9NvQ+3jQRGQuq8mqIQaSbPsY9r5TNUwG1XcddrY9/NLe2sniLw5dxmwaEB4gvHbYyCeJcc+X7mNYvaARPo5TUJFfBHFBaseiBTuSZ4/Xo++Oih6DLjC8OjfBV8Hl5e/VicJWgxXiH3cK0xrDNzzt9MMHil1Si9/M7u+uaUNFXsNpZGzBOWxk++n1ToXHTbR2JRFOJzfBzW9ZhGzr9p8ZfijvxD1QHYXGu+GkfSEYX8ir/HSHS3gBBQqslcuX/txSvHjUQxkvPU7sm/noqyaLzXfEmUUxaQlKBNgdLgon/ecuIRdhd0S3JWw/XWIdEpVM7XSltJlP61Y8tD7osijm6P0YNxsVbp7Y/vA8VXeqDRDCylkwBM2SoIntOVdDSbyPJkpp34FaJT5nyXJGoDS7g1wCabUBv9nqqsoa7Ef6qqj1pIHVyB826BHM2qZ2JM/xogNxMcClylm55Tsi8bOuqC56QrAsgMguh575fz+2z1FB9Pmcj1HE=
|   256 02:f6:05:75:cd:ae:c7:8c:a8:5a:8f:cb:47:56:9c:8f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJkTz+9zwC8rqdsmq6FJ7OE32gccuVfpoFWx6Cvd1Sr9kTafHP6K58rPlrlR0HlpBNtewRKeb2tKueTbGH7ZiDY=
|   256 9d:8b:78:95:80:b0:28:38:02:26:d6:59:8e:4e:11:da (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILKJA1BXYOzrI1eJBt8XntkM6UCbDdq0nW6agTZu3N1j
31337/tcp open  Elite?  syn-ack
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NULL, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, X11Probe: 
|     In case I forget - user:pass
|_    ubuntu:Dafdas!!/str0ng
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port31337-TCP:V=7.92%I=7%D=9/19%Time=6328870B%P=x86_64-pc-linux-gnu%r(N
SF:ULL,35,"In\x20case\x20I\x20forget\x20-\x20user:pass\nubuntu:Dafdas!!/st
SF:r0ng\n\n")%r(GetRequest,35,"In\x20case\x20I\x20forget\x20-\x20user:pass
SF:\nubuntu:Dafdas!!/str0ng\n\n")%r(SIPOptions,35,"In\x20case\x20I\x20forg
SF:et\x20-\x20user:pass\nubuntu:Dafdas!!/str0ng\n\n")%r(GenericLines,35,"I
SF:n\x20case\x20I\x20forget\x20-\x20user:pass\nubuntu:Dafdas!!/str0ng\n\n"
SF:)%r(HTTPOptions,35,"In\x20case\x20I\x20forget\x20-\x20user:pass\nubuntu
SF::Dafdas!!/str0ng\n\n")%r(RTSPRequest,35,"In\x20case\x20I\x20forget\x20-
SF:\x20user:pass\nubuntu:Dafdas!!/str0ng\n\n")%r(DNSVersionBindReqTCP,35,"
SF:In\x20case\x20I\x20forget\x20-\x20user:pass\nubuntu:Dafdas!!/str0ng\n\n
SF:")%r(DNSStatusRequestTCP,35,"In\x20case\x20I\x20forget\x20-\x20user:pas
SF:s\nubuntu:Dafdas!!/str0ng\n\n")%r(Help,35,"In\x20case\x20I\x20forget\x2
SF:0-\x20user:pass\nubuntu:Dafdas!!/str0ng\n\n")%r(SSLSessionReq,35,"In\x2
SF:0case\x20I\x20forget\x20-\x20user:pass\nubuntu:Dafdas!!/str0ng\n\n")%r(
SF:TerminalServerCookie,35,"In\x20case\x20I\x20forget\x20-\x20user:pass\nu
SF:buntu:Dafdas!!/str0ng\n\n")%r(TLSSessionReq,35,"In\x20case\x20I\x20forg
SF:et\x20-\x20user:pass\nubuntu:Dafdas!!/str0ng\n\n")%r(Kerberos,35,"In\x2
SF:0case\x20I\x20forget\x20-\x20user:pass\nubuntu:Dafdas!!/str0ng\n\n")%r(
SF:SMBProgNeg,35,"In\x20case\x20I\x20forget\x20-\x20user:pass\nubuntu:Dafd
SF:as!!/str0ng\n\n")%r(X11Probe,35,"In\x20case\x20I\x20forget\x20-\x20user
SF::pass\nubuntu:Dafdas!!/str0ng\n\n")%r(FourOhFourRequest,35,"In\x20case\
SF:x20I\x20forget\x20-\x20user:pass\nubuntu:Dafdas!!/str0ng\n\n")%r(LPDStr
SF:ing,35,"In\x20case\x20I\x20forget\x20-\x20user:pass\nubuntu:Dafdas!!/st
SF:r0ng\n\n")%r(LDAPSearchReq,35,"In\x20case\x20I\x20forget\x20-\x20user:p
SF:ass\nubuntu:Dafdas!!/str0ng\n\n")%r(LDAPBindReq,35,"In\x20case\x20I\x20
SF:forget\x20-\x20user:pass\nubuntu:Dafdas!!/str0ng\n\n")%r(LANDesk-RC,35,
SF:"In\x20case\x20I\x20forget\x20-\x20user:pass\nubuntu:Dafdas!!/str0ng\n\
SF:n")%r(TerminalServer,35,"In\x20case\x20I\x20forget\x20-\x20user:pass\nu
SF:buntu:Dafdas!!/str0ng\n\n")%r(NCP,35,"In\x20case\x20I\x20forget\x20-\x2
SF:0user:pass\nubuntu:Dafdas!!/str0ng\n\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:13
Completed NSE at 11:13, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:13
Completed NSE at 11:13, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:13
Completed NSE at 11:13, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 34.45 seconds

ssh -> ubuntu:Dafdas!!/str0ng

┌──(kali㉿kali)-[~]
└─$ ssh ubuntu@10.10.170.227
ubuntu@10.10.170.227's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.13.0-1014-aws x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

$ whoami
ubuntu

$ find . -name flag.txt 2>/dev/null
./home/user/flag.txt
$ cd ..
$ ls
ubuntu  user
$ cd ubuntu
$ ls -lah
total 28K
drwxr-xr-x 1 ubuntu ubuntu 4.0K Sep 19 15:19 .
drwxr-xr-x 1 root   root   4.0K Mar  2  2022 ..
-rw-r--r-- 1 ubuntu ubuntu  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 ubuntu ubuntu 3.7K Feb 25  2020 .bashrc
drwx------ 2 ubuntu ubuntu 4.0K Sep 19 15:19 .cache
-rw-r--r-- 1 ubuntu ubuntu  807 Feb 25  2020 .profile
$ cd ..
$ cd user
$ ls
flag.txt
$ cat flag.txt
flag{251f309497a18888dde5222761ea88e4}$ 
```

Find the flag!
*flag{251f309497a18888dde5222761ea88e4}*



[[Ninja Skills]]