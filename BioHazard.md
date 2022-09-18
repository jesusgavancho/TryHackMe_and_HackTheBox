---
A CTF room based on the old-time survival horror game, Resident Evil. Can you survive until the end?
---
![|333](https://tryhackme-images.s3.amazonaws.com/room-icons/72aca9d285c3156a05b34b7f6cc67ae6.png)

```
┌──(kali㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.128.211 --ulimit 5000 -b 65535 -- -A 
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Real hackers hack time ⌛

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] Automatically increasing ulimit value to 5000.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.128.211:22
Open 10.10.128.211:21
Open 10.10.128.211:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-17 21:16 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 21:16
Completed NSE at 21:16, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 21:16
Completed NSE at 21:16, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 21:16
Completed NSE at 21:16, 0.00s elapsed
Initiating Ping Scan at 21:16
Scanning 10.10.128.211 [2 ports]
Completed Ping Scan at 21:16, 0.42s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 21:16
Completed Parallel DNS resolution of 1 host. at 21:16, 0.02s elapsed
DNS resolution of 1 IPs took 0.04s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 21:16
Scanning 10.10.128.211 [3 ports]
Discovered open port 22/tcp on 10.10.128.211
Discovered open port 80/tcp on 10.10.128.211
Discovered open port 21/tcp on 10.10.128.211
Completed Connect Scan at 21:16, 0.27s elapsed (3 total ports)
Initiating Service scan at 21:16
Scanning 3 services on 10.10.128.211
Completed Service scan at 21:16, 6.51s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.128.211.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 21:16
Completed NSE at 21:16, 8.87s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 21:16
Completed NSE at 21:16, 2.15s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 21:16
Completed NSE at 21:16, 0.00s elapsed
Nmap scan report for 10.10.128.211
Host is up, received conn-refused (0.37s latency).
Scanned at 2022-09-17 21:16:34 EDT for 18s

PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack vsftpd 3.0.3
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c9:03:aa:aa:ea:a9:f1:f4:09:79:c0:47:41:16:f1:9b (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDM1/tmq8Lrur25evbyyI7/+nxDlhbVbMMiRfz5a0eI7Sq9yODJGCVNMPJGKOwtgA/BlPi7V3TKyYJVeH1QOzP8mPLVgfYom6ovelJiLiR6VrO4dqxx+G3ir+tj/OOSc4MpmdnqCvQKtAeJ4e5bbWakFihXyy14yi++oOzqp2VDlqMNN+d2k0uSAx1rDbngwP3UvRfE1E1TaSYhljnb9kvWRxBABhpdkUjbcRLwxBAQFBm9Vm+yQYPurC9YJ1BUlJzOFesYnbS27bG1vVCcuPQN3YjcljVCXBdd0qIvZdYlez4+mVUcJJh1iWl83sfgo+wZRmfHsedjdL1eWNrkt+ed
|   256 2e:1d:83:11:65:03:b4:78:e9:6d:94:d1:3b:db:f4:d6 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNy83txF27peDYxMhrPqfipXwZtBNY9H4fww7f2FRCkt09tEcp5f5BKhOE4cNo033XYpmaowy1r4qgFpIqKjf64=
|   256 91:3d:e4:4f:ab:aa:e2:9e:44:af:d3:57:86:70:bc:39 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMhTmk6F06eyLfM0j07nUcnqMqGdgOfFqsp3eLdbwwn0
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-title: Beginning of the end
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 21:16
Completed NSE at 21:16, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 21:16
Completed NSE at 21:16, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 21:16
Completed NSE at 21:16, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.57 seconds

```

How many open ports?
*3*


What is the team name in operation
*STARS alpha team* (found in home page footer) 

### The Mansion 

Collect all necessary items and advanced to the next level. The format of the Item flag:

Item_name{32 character}

Some of the doors are locked. Use the item flag to unlock the door.

Tips: It is better to record down all the information inside a notepad



What is the emblem flag
*emblem{fec832623ea498e20bf4fe1821d58727}*
What is the lock pick flag
*lock_pick{037b35e2ff90916a9abf99129c8e1837}*
What is the music sheet flag
*music_sheet{362d72deaf65f5bdc63daece6a1f676e}* (base32)
What is the gold emblem flag
*gold_emblem{58a8c41a9d08b8a4e38d02a4d7ff4843}*
![[Pasted image 20220917211219.png]]

![[Pasted image 20220917211731.png]]

What is the shield key flag
*shield_key{48a7a9227cd7eb89f0a062590798cbac}*
![[Pasted image 20220917204929.png]]

What is the blue gem flag
*blue_jewel{e1d457e96cac640f863ec7bc475d48aa}*

crest 1 + crest2 + crest3 +crest4
S0pXRkVVS0pKQkxIVVdTWUpFM0VTUlk9 + GVFWK5KHK5WTGTCILE4DKY3DNN4GQQRTM5AVCTKE + MDAxMTAxMTAgMDAxMTAwMTEgMDAxMDAwMDAgMDAxMTAwMTEgMDAxMTAwMTEgMDAxMDAwMDAgMDAxMTAxMDAgMDExMDAxMDAgMDAxMDAwMDAgMDAxMTAwMTEgMDAxMTAxMTAgMDAxMDAwMDAgMDAxMTAxMDAgMDAxMTEwMDEgMDAxMDAwMDAgMDAxMTAxMDAgMDAxMTEwMDAgMDAxMDAwMDAgMDAxMTAxMTAgMDExMDAwMTEgMDAxMDAwMDAgMDAxMTAxMTEgMDAxMTAxMTAgMDAxMDAwMDAgMDAxMTAxMTAgMDAxMTAxMDAgMDAxMDAwMDAgMDAxMTAxMDEgMDAxMTAxMTAgMDAxMDAwMDAgMDAxMTAwMTEgMDAxMTEwMDEgMDAxMDAwMDAgMDAxMTAxMTAgMDExMDAwMDEgMDAxMDAwMDAgMDAxMTAxMDEgMDAxMTEwMDEgMDAxMDAwMDAgMDAxMTAxMDEgMDAxMTAxMTEgMDAxMDAwMDAgMDAxMTAwMTEgMDAxMTAxMDEgMDAxMDAwMDAgMDAxMTAwMTEgMDAxMTAwMDAgMDAxMDAwMDAgMDAxMTAxMDEgMDAxMTEwMDAgMDAxMDAwMDAgMDAxMTAwMTEgMDAxMTAwMTAgMDAxMDAwMDAgMDAxMTAxMTAgMDAxMTEwMDA= + gSUERauVpvKzRpyPpuYz66JDmRTbJubaoArM6CAQsnVwte6zF9J4GGYyun3k5qM9ma4s

crest 1:S0pXRkVVS0pKQkxIVVdTWUpFM0VTUlk9 (E: 2x, 14 letters)
crest 2:GVFWK5KHK5WTGTCILE4DKY3DNN4GQQRTM5AVCTKE (E: 2x, 18 letters)
crest 3:
MDAxMTAxMTAgMDAxMTAwMTEgMDAxMDAwMDAgMDAxMTAwMTEgMDAxMTAwMTEgMDAxMDAwMDAgMDAxMTAxMDAgMDExMDAxMDAgMDAxMDAwMDAgMDAxMTAwMTEgMDAxMTAxMTAgMDAxMDAwMDAgMDAxMTAxMDAgMDAxMTEwMDEgMDAxMDAwMDAgMDAxMTAxMDAgMDAxMTEwMDAgMDAxMDAwMDAgMDAxMTAxMTAgMDExMDAwMTEgMDAxMDAwMDAgMDAxMTAxMTEgMDAxMTAxMTAgMDAxMDAwMDAgMDAxMTAxMTAgMDAxMTAxMDAgMDAxMDAwMDAgMDAxMTAxMDEgMDAxMTAxMTAgMDAxMDAwMDAgMDAxMTAwMTEgMDAxMTEwMDEgMDAxMDAwMDAgMDAxMTAxMTAgMDExMDAwMDEgMDAxMDAwMDAgMDAxMTAxMDEgMDAxMTEwMDEgMDAxMDAwMDAgMDAxMTAxMDEgMDAxMTAxMTEgMDAxMDAwMDAgMDAxMTAwMTEgMDAxMTAxMDEgMDAxMDAwMDAgMDAxMTAwMTEgMDAxMTAwMDAgMDAxMDAwMDAgMDAxMTAxMDEgMDAxMTEwMDAgMDAxMDAwMDAgMDAxMTAwMTEgMDAxMTAwMTAgMDAxMDAwMDAgMDAxMTAxMTAgMDAxMTEwMDA= (E: 3x, 19 letters)
crest 4: gSUERauVpvKzRpyPpuYz66JDmRTbJubaoArM6CAQsnVwte6zF9J4GGYyun3k5qM9ma4s (E: 2x, 17 letters)

![[Pasted image 20220917212918.png]]

RlRQIHVzZXI6IG 

![[Pasted image 20220917213030.png]]


h1bnRlciwgRlRQIHBh

![[Pasted image 20220917213233.png]]

c3M6IHlvdV9jYW50X2h

![[Pasted image 20220917213333.png]]

pZGVfZm9yZXZlcg==


now:

RlRQIHVzZXI6IGh1bnRlciwgRlRQIHBhc3M6IHlvdV9jYW50X2hpZGVfZm9yZXZlcg==

![[Pasted image 20220917213449.png]]

FTP user: hunter, FTP pass: you_cant_hide_forever


What is the FTP username
*hunter*
What is the FTP password
*you_cant_hide_forever*


### The guard house 

After gaining access to the FTP server, you need to solve another puzzle.

```
┌──(kali㉿kali)-[~/Downloads/biohazard]
└─$ ftp 10.10.128.211
Connected to 10.10.128.211.
220 (vsFTPd 3.0.3)
Name (10.10.128.211:kali): hunter
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||46709|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0            7994 Sep 19  2019 001-key.jpg
-rw-r--r--    1 0        0            2210 Sep 19  2019 002-key.jpg
-rw-r--r--    1 0        0            2146 Sep 19  2019 003-key.jpg
-rw-r--r--    1 0        0             121 Sep 19  2019 helmet_key.txt.gpg
-rw-r--r--    1 0        0             170 Sep 20  2019 important.txt
226 Directory send OK.
ftp> get *
local: * remote: *
229 Entering Extended Passive Mode (|||8828|)
550 Failed to open file.
ftp> get all*
local: all* remote: all*
229 Entering Extended Passive Mode (|||51104|)
550 Failed to open file.
ftp> help
Commands may be abbreviated.  Commands are:

!               epsv6           mget            preserve        sendport
$               exit            mkdir           progress        set
account         features        mls             prompt          site
append          fget            mlsd            proxy           size
ascii           form            mlst            put             sndbuf
bell            ftp             mode            pwd             status
binary          gate            modtime         quit            struct
bye             get             more            quote           sunique
case            glob            mput            rate            system
cd              hash            mreget          rcvbuf          tenex
cdup            help            msend           recv            throttle
chmod           idle            newer           reget           trace
close           image           nlist           remopts         type
cr              lcd             nmap            rename          umask
debug           less            ntrans          reset           unset
delete          lpage           open            restart         usage
dir             lpwd            page            rhelp           user
disconnect      ls              passive         rmdir           verbose
edit            macdef          pdir            rstatus         xferbuf
epsv            mdelete         pls             runique         ?
epsv4           mdir            pmlsd           send
ftp> mget *
mget 001-key.jpg [anpqy?]? 
229 Entering Extended Passive Mode (|||16705|)
150 Opening BINARY mode data connection for 001-key.jpg (7994 bytes).
100% |**************************************|  7994        1.13 MiB/s    00:00 ETA
226 Transfer complete.
7994 bytes received in 00:00 (37.63 KiB/s)
mget 002-key.jpg [anpqy?]? 
229 Entering Extended Passive Mode (|||58378|)
150 Opening BINARY mode data connection for 002-key.jpg (2210 bytes).
100% |**************************************|  2210        2.31 MiB/s    00:00 ETA
226 Transfer complete.
2210 bytes received in 00:00 (10.62 KiB/s)
mget 003-key.jpg [anpqy?]? 
229 Entering Extended Passive Mode (|||22864|)
150 Opening BINARY mode data connection for 003-key.jpg (2146 bytes).
100% |**************************************|  2146       12.10 MiB/s    00:00 ETA
226 Transfer complete.
2146 bytes received in 00:00 (10.50 KiB/s)
mget helmet_key.txt.gpg [anpqy?]? 
229 Entering Extended Passive Mode (|||19082|)
150 Opening BINARY mode data connection for helmet_key.txt.gpg (121 bytes).
100% |**************************************|   121        1.78 KiB/s    00:00 ETA
226 Transfer complete.
121 bytes received in 00:00 (0.44 KiB/s)
mget important.txt [anpqy?]? 
229 Entering Extended Passive Mode (|||50083|)
150 Opening BINARY mode data connection for important.txt (170 bytes).
100% |**************************************|   170      779.41 KiB/s    00:00 ETA
226 Transfer complete.
170 bytes received in 00:00 (0.82 KiB/s)
ftp> ls
229 Entering Extended Passive Mode (|||38894|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0            7994 Sep 19  2019 001-key.jpg
-rw-r--r--    1 0        0            2210 Sep 19  2019 002-key.jpg
-rw-r--r--    1 0        0            2146 Sep 19  2019 003-key.jpg
-rw-r--r--    1 0        0             121 Sep 19  2019 helmet_key.txt.gpg
-rw-r--r--    1 0        0             170 Sep 20  2019 important.txt
226 Directory send OK.
ftp> exit
221 Goodbye.
```

Where is the hidden directory mentioned by Barry

```
┌──(kali㉿kali)-[~/Downloads/biohazard]
└─$ ls
001-key.jpg  002-key.jpg  003-key.jpg  helmet_key.txt.gpg  important.txt
                                                                                   
┌──(kali㉿kali)-[~/Downloads/biohazard]
└─$ cat important.txt 
Jill,

I think the helmet key is inside the text file, but I have no clue on decrypting stuff. Also, I come across a /hidden_closet/ door but it was locked.

From,
Barry

```

*/hidden_closet/*


Password for the encrypted file
Three picture, three hints: hide, comment and walk away

```
┌──(kali㉿kali)-[~/Downloads/biohazard]
└─$ binwalk 001-key.jpg 002-key.jpg 003-key.jpg 

Scan Time:     2022-09-17 22:40:52
Target File:   /home/kali/Downloads/biohazard/001-key.jpg
MD5 Checksum:  076b6a86ba92c75d366f0a18b505dcf8
Signatures:    411

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard 1.01


Scan Time:     2022-09-17 22:40:52
Target File:   /home/kali/Downloads/biohazard/002-key.jpg
MD5 Checksum:  060af11c5617fbc4fba1760f0dd52a0d
Signatures:    411

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard 1.01


Scan Time:     2022-09-17 22:40:52
Target File:   /home/kali/Downloads/biohazard/003-key.jpg
MD5 Checksum:  5c407556b6956ba74cda5ce98f8acf08
Signatures:    411

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard 1.01
1930          0x78A           Zip archive data, at least v2.0 to extract, uncompressed size: 14, name: key-003.txt
2124          0x84C           End of Zip archive, footer length: 22


┌──(kali㉿kali)-[~/Downloads/biohazard]
└─$ unzip 003-key.jpg 
Archive:  003-key.jpg
warning [003-key.jpg]:  1930 extra bytes at beginning or within zipfile
  (attempting to process anyway)
  inflating: key-003.txt             
                                                                                   
┌──(kali㉿kali)-[~/Downloads/biohazard]
└─$ cat key-003.txt  
3aXRoX3Zqb2x0  key3

┌──(kali㉿kali)-[~/Downloads/biohazard]
└─$ strings 001-key.jpg 002-key.jpg 
JFIF

"*%%*424DD\

"*%%*424DD\
$3br
%&'()*456789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz
        #3R
&'()*56789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz
*Pr+6
)XG0
QPOu
^j2]
~Rpx
f$n[
3s3uc]D`A
*H=E%ij
J8t8"
Ro9
Bri(
rqZ`
e=FM
77*{)
70_SL
vg[[fb@8
1c1DD
Pj*@
RsZ:
`:Wk@
FUu*
.!GF
%FO=jJ
G#kvaX7VsZ
nBx"
 xfN
SUu-
|<V{P
08*r
QM9b#P
&?QVRB:V,d
">?x
Zz? >}
o}m$2
Vm.^
OSLf
dnG?
mZ[@
i\lc
iyua:\
Vp>`}Z
<',kgp^
RWIu
z+DG+M
k)V*
*I&#
,v`/l
.\c~>n
APQE
w)yau$
'>Y?2
5KSMl
?gI6
Eq5f
0Q\D
Mm#E<M
X.,u8
:v      x
>vgvw9f$
4=.]N
B^/C
E,S(h
AaS,
b]7&N
)qcs
b[yVD# 
[yqsv
<),Q
zM<@
!d?l
_Di>"
!|zU
O+fI
JFIF
5fYmVfZGVzdHJveV9

"*%%*424DD\

"*%%*424DD\
5Zs5
az8C
C%(KH\
ftkI
B}-*J
'ttT
uJ@2
!1Aaq
"2Q 0#Bbr
l)YWH]E
}VR7
p*qJ
v4NM
U!.#
! "AQ
#2Raq
?1>o
I^(h
+M_M
Z6"=
,hfb
Yx$k3
12Ra

5fYmVfZGVzdHJveV9 key 2

https://futureboy.us/stegano/decode.pl upload key01.png

cGxhbnQ0Ml9jYW key 1

key 1 + key 2 + key 3 = cGxhbnQ0Ml9jYW5fYmVfZGVzdHJveV93aXRoX3Zqb2x0

plant42_can_be_destroy_with_vjolt

```


*plant42_can_be_destroy_with_vjolt*

What is the helmet key flag
key 1 + key 2 + key 3 is not enough. You need to do something

![[Pasted image 20220917214959.png]]

```
┌──(kali㉿kali)-[~/Downloads/biohazard]
└─$ gpg -d helmet_key.txt.gpg                
gpg: AES256.CFB encrypted data
gpg: encrypted with 1 passphrase
helmet_key{458493193501d2b94bbab2e727f8db4b}

```

*helmet_key{458493193501d2b94bbab2e727f8db4b}*

### The Revisit 

Done with the puzzle? There are places you have explored before but yet to access.


![[Pasted image 20220917215239.png]]

What is the SSH login username
You missed a room yep study room :) 
enter helmet flag then download 

```
┌──(kali㉿kali)-[~/Downloads/biohazard]
└─$ ls
001-key.jpg  003-key.jpg  helmet_key.txt.gpg  key-003.txt
002-key.jpg  doom.tar.gz  important.txt
                                                                                   
┌──(kali㉿kali)-[~/Downloads/biohazard]
└─$ mkdir doom                  
                                                                                   
┌──(kali㉿kali)-[~/Downloads/biohazard]
└─$ mv doom.tar.gz doom             
                                                                                   
┌──(kali㉿kali)-[~/Downloads/biohazard]
└─$ cd doom     
                                                                                   
┌──(kali㉿kali)-[~/Downloads/biohazard/doom]
└─$ ls
doom.tar.gz
                                                                                   
┌──(kali㉿kali)-[~/Downloads/biohazard/doom]
└─$ tar -xf doom.tar.gz         
                                                                                   
┌──(kali㉿kali)-[~/Downloads/biohazard/doom]
└─$ ls
doom.tar.gz  eagle_medal.txt
                                                                                   
┌──(kali㉿kali)-[~/Downloads/biohazard/doom]
└─$ cat eagle_medal.txt 
SSH user: umbrella_guest

```

*umbrella_guest*

hidden_Closet

![[Pasted image 20220917221043.png]]

What is the SSH login password
*T_virus_rules*


Who the STARS bravo team leader
*Enrico*

### Underground laboratory 

Time for the final showdown. Can you escape the nightmare?

https://www.guballa.de/vigenere-solver

wpbwbxr wpkzg pltwnhro, txrks_xfqsxrd_bvv_fy_rvmexa_ajk

weasker login password, stars_members_are_my_guinea_pig

```
┌──(kali㉿kali)-[~/Downloads/biohazard/doom]
└─$ ssh weasker@10.10.128.211      
The authenticity of host '10.10.128.211 (10.10.128.211)' can't be established.
ED25519 key fingerprint is SHA256:dOQYq6o72K3z+Nn6HtAR4ZFXoEZklDafT3VuF728yWc.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.128.211' (ED25519) to the list of known hosts.
weasker@10.10.128.211's password: 
Welcome to Ubuntu 18.04 LTS (GNU/Linux 4.15.0-20-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

320 packages can be updated.
58 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

weasker@umbrella_corp:~$ ls
Desktop  weasker_note.txt
weasker@umbrella_corp:~$ cat weasker_note.txt 
Weaker: Finally, you are here, Jill.
Jill: Weasker! stop it, You are destroying the  mankind.
Weasker: Destroying the mankind? How about creating a 'new' mankind. A world, only the strong can survive.
Jill: This is insane.
Weasker: Let me show you the ultimate lifeform, the Tyrant.

(Tyrant jump out and kill Weasker instantly)
(Jill able to stun the tyrant will a few powerful magnum round)

Alarm: Warning! warning! Self-detruct sequence has been activated. All personal, please evacuate immediately. (Repeat)
Jill: Poor bastard

weasker@umbrella_corp:~$ ls -lah
total 80K
drwxr-xr-x  9 weasker weasker 4.0K Sep 20  2019 .
drwxr-xr-x  5 root    root    4.0K Sep 20  2019 ..
-rw-------  1 weasker weasker   18 Sep 20  2019 .bash_history
-rw-r--r--  1 weasker weasker  220 Sep 18  2019 .bash_logout
-rw-r--r--  1 weasker weasker 3.7K Sep 18  2019 .bashrc
drwxrwxr-x 10 weasker weasker 4.0K Sep 17 20:18 .cache
drwxr-xr-x 11 weasker weasker 4.0K Sep 20  2019 .config
drwxr-xr-x  2 weasker weasker 4.0K Sep 19  2019 Desktop
drwx------  3 weasker weasker 4.0K Sep 19  2019 .gnupg
-rw-------  1 weasker weasker  346 Sep 20  2019 .ICEauthority
drwxr-xr-x  3 weasker weasker 4.0K Sep 19  2019 .local
drwx------  5 weasker weasker 4.0K Sep 19  2019 .mozilla
-rw-r--r--  1 weasker weasker  807 Sep 18  2019 .profile
drwx------  2 weasker weasker 4.0K Sep 19  2019 .ssh
-rw-r--r--  1 weasker weasker    0 Sep 20  2019 .sudo_as_admin_successful
-rw-r--r--  1 root    root     534 Sep 20  2019 weasker_note.txt
-rw-------  1 weasker weasker  109 Sep 20  2019 .Xauthority
-rw-------  1 weasker weasker 5.5K Sep 20  2019 .xsession-errors
-rw-------  1 weasker weasker 6.6K Sep 20  2019 .xsession-errors.old
weasker@umbrella_corp:~$ cd ..
weasker@umbrella_corp:/home$ ls
hunter  umbrella_guest  weasker
weasker@umbrella_corp:/home$ ls -al
total 20
drwxr-xr-x  5 root           root     4096 Sep 20  2019 .
drwxr-xr-x 24 root           root     4096 Sep 18  2019 ..
drwxr-xr-x  4 hunter         hunter   4096 Sep 19  2019 hunter
drwxr-xr-x  8 umbrella_guest umbrella 4096 Sep 20  2019 umbrella_guest
drwxr-xr-x  9 weasker        weasker  4096 Sep 20  2019 weasker
weasker@umbrella_corp:/home$ cd  umbrella_guest/
weasker@umbrella_corp:/home/umbrella_guest$ ls
weasker@umbrella_corp:/home/umbrella_guest$ ls -la
total 64
drwxr-xr-x  8 umbrella_guest umbrella 4096 Sep 20  2019 .
drwxr-xr-x  5 root           root     4096 Sep 20  2019 ..
-rw-r--r--  1 umbrella_guest umbrella  220 Sep 19  2019 .bash_logout
-rw-r--r--  1 umbrella_guest umbrella 3771 Sep 19  2019 .bashrc
drwxrwxr-x  6 umbrella_guest umbrella 4096 Sep 20  2019 .cache
drwxr-xr-x 11 umbrella_guest umbrella 4096 Sep 19  2019 .config
-rw-r--r--  1 umbrella_guest umbrella   26 Sep 19  2019 .dmrc
drwx------  3 umbrella_guest umbrella 4096 Sep 19  2019 .gnupg
-rw-------  1 umbrella_guest umbrella  346 Sep 19  2019 .ICEauthority
drwxr-xr-x  2 umbrella_guest umbrella 4096 Sep 20  2019 .jailcell
drwxr-xr-x  3 umbrella_guest umbrella 4096 Sep 19  2019 .local
-rw-r--r--  1 umbrella_guest umbrella  807 Sep 19  2019 .profile
drwx------  2 umbrella_guest umbrella 4096 Sep 20  2019 .ssh
-rw-------  1 umbrella_guest umbrella  109 Sep 19  2019 .Xauthority
-rw-------  1 umbrella_guest umbrella 7546 Sep 19  2019 .xsession-errors
weasker@umbrella_corp:/home/umbrella_guest$ cd .jailcell/
weasker@umbrella_corp:/home/umbrella_guest/.jailcell$ ls -la
total 12
drwxr-xr-x 2 umbrella_guest umbrella 4096 Sep 20  2019 .
drwxr-xr-x 8 umbrella_guest umbrella 4096 Sep 20  2019 ..
-rw-r--r-- 1 umbrella_guest umbrella  501 Sep 20  2019 chris.txt
weasker@umbrella_corp:/home/umbrella_guest/.jailcell$ cat chris.txt 
Jill: Chris, is that you?
Chris: Jill, you finally come. I was locked in the Jail cell for a while. It seem that weasker is behind all this.
Jil, What? Weasker? He is the traitor?
Chris: Yes, Jill. Unfortunately, he play us like a damn fiddle.
Jill: Let's get out of here first, I have contact brad for helicopter support.
Chris: Thanks Jill, here, take this MO Disk 2 with you. It look like the key to decipher something.
Jill: Alright, I will deal with him later.
Chris: see ya.

MO disk 2: albert 

weasker@umbrella_corp:~$ ls -la
total 80
drwxr-xr-x  9 weasker weasker 4096 Sep 20  2019 .
drwxr-xr-x  5 root    root    4096 Sep 20  2019 ..
-rw-------  1 weasker weasker   18 Sep 20  2019 .bash_history
-rw-r--r--  1 weasker weasker  220 Sep 18  2019 .bash_logout
-rw-r--r--  1 weasker weasker 3771 Sep 18  2019 .bashrc
drwxrwxr-x 10 weasker weasker 4096 Sep 17 20:18 .cache
drwxr-xr-x 11 weasker weasker 4096 Sep 20  2019 .config
drwxr-xr-x  2 weasker weasker 4096 Sep 19  2019 Desktop
drwx------  3 weasker weasker 4096 Sep 19  2019 .gnupg
-rw-------  1 weasker weasker  346 Sep 20  2019 .ICEauthority
drwxr-xr-x  3 weasker weasker 4096 Sep 19  2019 .local
drwx------  5 weasker weasker 4096 Sep 19  2019 .mozilla
-rw-r--r--  1 weasker weasker  807 Sep 18  2019 .profile
drwx------  2 weasker weasker 4096 Sep 19  2019 .ssh
-rw-r--r--  1 weasker weasker    0 Sep 20  2019 .sudo_as_admin_successful
-rw-r--r--  1 root    root     534 Sep 20  2019 weasker_note.txt
-rw-------  1 weasker weasker  109 Sep 20  2019 .Xauthority
-rw-------  1 weasker weasker 5548 Sep 20  2019 .xsession-errors
-rw-------  1 weasker weasker 6749 Sep 20  2019 .xsession-errors.old
weasker@umbrella_corp:~$ cat .sudo_as_admin_successful 
weasker@umbrella_corp:~$ sudo -l
[sudo] password for weasker: 
Matching Defaults entries for weasker on umbrella_corp:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User weasker may run the following commands on umbrella_corp:
    (ALL : ALL) ALL
weasker@umbrella_corp:~$ sudo env /bin/sh
# whoami
root
# cat /root/flag.txt 
cat: /root/flag.txt: No such file or directory
# cd /root
# ls
root.txt
# cat root.txt  
In the state of emergency, Jill, Barry and Chris are reaching the helipad and awaiting for the helicopter support.

Suddenly, the Tyrant jump out from nowhere. After a tough fight, brad, throw a rocket launcher on the helipad. Without thinking twice, Jill pick up the launcher and fire at the Tyrant.

The Tyrant shredded into pieces and the Mansion was blowed. The survivor able to escape with the helicopter and prepare for their next fight.

The End

flag: 3c5794a00dc56c35f2bf096571edf3bf

```


Where you found Chris
*jailcell*

Who is the traitor
*weasker*

The login password for the traitor
*stars_members_are_my_guinea_pig*
The name of the ultimate form
*Tyrant*

![[Pasted image 20220917222546.png]]

The root flag
*3c5794a00dc56c35f2bf096571edf3bf* (gtofbins env https://gtfobins.github.io/gtfobins/env/ )


[[Credentials Harvesting]]