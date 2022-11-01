```
blob:https://app.hackthebox.com/75b7ab04-575b-4cf9-800c-bd03e22b0be6

┌──(kali㉿kali)-[~]
└─$ ping 10.129.71.100 
PING 10.129.71.100 (10.129.71.100) 56(84) bytes of data.
64 bytes from 10.129.71.100: icmp_seq=1 ttl=63 time=197 ms
64 bytes from 10.129.71.100: icmp_seq=3 ttl=63 time=189 ms
^C
--- 10.129.71.100 ping statistics ---
3 packets transmitted, 2 received, 33.3333% packet loss, time 2032ms
rtt min/avg/max/mdev = 189.086/192.911/196.736/3.825 ms
                                                                                                                  
┌──(kali㉿kali)-[~]
└─$ rustscan -a 10.129.71.100 --ulimit 5500 -b 65535 -- -A
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
Open 10.129.71.100:3306
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-01 14:54 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:54
Completed NSE at 14:54, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:54
Completed NSE at 14:54, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:54
Completed NSE at 14:54, 0.00s elapsed
Initiating Ping Scan at 14:54
Scanning 10.129.71.100 [2 ports]
Completed Ping Scan at 14:54, 0.92s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 14:54
Completed Parallel DNS resolution of 1 host. at 14:54, 0.01s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 14:54
Scanning 10.129.71.100 [1 port]
Discovered open port 3306/tcp on 10.129.71.100
Completed Connect Scan at 14:54, 1.20s elapsed (1 total ports)
Initiating Service scan at 14:54
Scanning 1 service on 10.129.71.100
Completed Service scan at 14:57, 163.45s elapsed (1 service on 1 host)
NSE: Script scanning 10.129.71.100.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:57
NSE Timing: About 99.32% done; ETC: 14:57 (0:00:00 remaining)
Completed NSE at 14:58, 42.62s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:58
NSE Timing: About 87.50% done; ETC: 14:58 (0:00:04 remaining)
Completed NSE at 14:58, 43.49s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:58
Completed NSE at 14:58, 0.00s elapsed
Nmap scan report for 10.129.71.100
Host is up, received conn-refused (0.95s latency).
Scanned at 2022-11-01 14:54:39 EDT for 251s

PORT     STATE SERVICE REASON  VERSION
3306/tcp open  mysql?  syn-ack
| mysql-info: 
|   Protocol: 10
|   Version: 5.5.5-10.3.27-MariaDB-0+deb10u1
|   Thread ID: 68
|   Capabilities flags: 63486
|   Some Capabilities: ConnectWithDatabase, Support41Auth, Speaks41ProtocolOld, SupportsTransactions, IgnoreSpaceBeforeParenthesis, LongColumnFlag, IgnoreSigpipes, ODBCClient, Speaks41ProtocolNew, SupportsCompression, InteractiveClient, FoundRows, DontAllowDatabaseTableColumn, SupportsLoadDataLocal, SupportsAuthPlugins, SupportsMultipleResults, SupportsMultipleStatments
|   Status: Autocommit
|   Salt: CWm=*Yb^5*q{:KJpw'UY
|_  Auth Plugin Name: mysql_native_password

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:58
Completed NSE at 14:58, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:58
Completed NSE at 14:58, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:58
Completed NSE at 14:58, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 255.99 seconds

With an ounce of luck, our connection is accepted without a password requirement. We are placed in a
MySQL service shell from where we can explore the tables and data therein that are available to us. If you
need help with MySQL command syntax, you can refer to the cheatsheet provided by MySQLTutorial.
The commands we are going to use are essential for navigation:
Note that it is essential to end each command with the ; symbol, as it declares the end of the command.
Apart from that, SQL is a query-oriented language, which means that you supply it with one query at a time.
From the output, the htb database seems to be of value to us. In order to see what rests inside it, we will
need to "select" the htb database as the active one - the database we want to actively interact with for our
subsequent commands. To achieve this, the USE htb; command can be used.

SHOW databases; : Prints out the databases we can access.
USE {database_name}; : Set to use the database named {database_name}.
SHOW tables; : Prints out the available tables inside the current
database.
SELECT * FROM {table_name}; : Prints out all the data from the table {table_name}.

┌──(kali㉿kali)-[~]
└─$ mysql -h 10.129.71.100 -u root
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 76
Server version: 10.3.27-MariaDB-0+deb10u1 Debian 10

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> SHOW databases;
+--------------------+
| Database           |
+--------------------+
| htb                |
| information_schema |
| mysql              |
| performance_schema |
+--------------------+
4 rows in set (0.806 sec)

MariaDB [(none)]> USE htb;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [htb]> SHOW tables;
+---------------+
| Tables_in_htb |
+---------------+
| config        |
| users         |
+---------------+
2 rows in set (0.186 sec)

MariaDB [htb]> SELECT * FROM users;
+----+----------+------------------+
| id | username | email            |
+----+----------+------------------+
|  1 | admin    | admin@sequel.htb |
|  2 | lara     | lara@sequel.htb  |
|  3 | sam      | sam@sequel.htb   |
|  4 | mary     | mary@sequel.htb  |
+----+----------+------------------+
4 rows in set (0.184 sec)

MariaDB [htb]> SELECT * FROM config;
+----+-----------------------+----------------------------------+
| id | name                  | value                            |
+----+-----------------------+----------------------------------+
|  1 | timeout               | 60s                              |
|  2 | security              | default                          |
|  3 | auto_logon            | false                            |
|  4 | max_size              | 2M                               |
|  5 | flag                  | 7b4bec00d1a39e3dd4e021ec3d915da8 |
|  6 | enable_uploads        | false                            |
|  7 | authentication_method | radius                           |
+----+-----------------------+----------------------------------+
7 rows in set (0.189 sec)

MariaDB [htb]> exit
Bye

pwnd

```

What does the acronym SQL stand for? *Structured Query Language*
During our scan, which port running mysql do we find? *3306*
What community-developed MySQL version is the target running? *MariaDB*
What switch do we need to use in order to specify a login username for the MySQL service?  *-u*
Which username allows us to log into MariaDB without providing a password? The root of all evil. *root*
What symbol can we use to specify within the query that we want to display everything inside a table? This will make you starry-eyed. ***
What symbol do we need to end each query with? You can find the answer by reading the write-up carefully. *;*
Submit root flag 
*7b4bec00d1a39e3dd4e021ec3d915da8*


[[Appointment]]