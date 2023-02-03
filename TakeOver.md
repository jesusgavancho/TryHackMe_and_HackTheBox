---
This challenge revolves around subdomain enumeration.
---

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/e11be3e91db093a84dd92e794e9f8181.png)

### Help Us

 Start Machine

Hello there,  
  
I am the CEO and one of the co-founders of futurevera.thm. In Futurevera, we believe that the future is in space. We do a lot of space research and write blogs about it. We used to help students with space questions, but we are rebuilding our support.  

Recently blackhat hackers approached us saying they could takeover and are asking us for a big ransom. Please help us to find what they can takeover.  
  
Our website is located at [https://futurevera.thm](https://futurevera.thm/)

Hint: Don't forget to add the MACHINE_IP in /etc/hosts for futurevera.thm ; )

Answer the questions below

What's the value of the flag?

```
┌──(kali㉿kali)-[~/Downloads]
└─$ tail /etc/hosts          
10.10.167.117 dev.team.thm
10.10.29.100 set.windcorp.thm
10.10.20.190 Osiris.windcorp.thm Osiris osiris.windcorp.thm
10.10.37.31  UNATCO
10.10.73.143 jack.thm
#127.0.0.1  newcms.mofo.pwn
10.200.108.33 holo.live 
10.200.108.33 www.holo.live admin.holo.live dev.holo.live
10.10.146.26  severnaya-station.com
10.10.211.130 futurevera.thm

https://futurevera.thm/

┌──(kali㉿kali)-[~/Downloads]
└─$ gobuster dir -u https://futurevera.thm/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 64 -k  
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://futurevera.thm/
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/02/03 17:30:29 Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 319] [--> https://futurevera.thm/assets/]
/css                  (Status: 301) [Size: 316] [--> https://futurevera.thm/css/]
/js                   (Status: 301) [Size: 315] [--> https://futurevera.thm/js/]
/server-status        (Status: 403) [Size: 280]
Progress: 113788 / 220561 (51.59%)^C
[!] Keyboard interrupt detected, terminating.
===============================================================
2023/02/03 17:36:55 Finished
===============================================================

looking subdomains


┌──(kali㉿kali)-[~/Downloads]
└─$ gobuster vhost -u https://futurevera.thm/ -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain false -k -t 64

===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             https://futurevera.thm/
[+] Method:          GET
[+] Threads:         64
[+] Wordlist:        /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:      gobuster/3.3
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
2023/02/03 17:38:24 Starting gobuster in VHOST enumeration mode
===============================================================
Found: blog.futurevera.thm Status: 421 [Size: 408]
Found: support.futurevera.thm Status: 421 [Size: 411]
Progress: 114410 / 114442 (99.97%)===============================================================
2023/02/03 17:45:23 Finished
===============================================================

found 2 subdomains

┌──(kali㉿kali)-[~/Downloads]
└─$ tail /etc/hosts     
10.10.167.117 dev.team.thm
10.10.29.100 set.windcorp.thm
10.10.20.190 Osiris.windcorp.thm Osiris osiris.windcorp.thm
10.10.37.31  UNATCO
10.10.73.143 jack.thm
#127.0.0.1  newcms.mofo.pwn
10.200.108.33 holo.live 
10.200.108.33 www.holo.live admin.holo.live dev.holo.live
10.10.146.26  severnaya-station.com
10.10.211.130 futurevera.thm blog.futurevera.thm support.futurevera.thm

https://support.futurevera.thm/

<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
        <meta name="description" content="" />
        <meta name="author" content="" />
        <title>FutureVera - Support</title>
        <link rel="icon" type="image/x-icon" href="assets/favicon.ico" />
        <link href="css/styles.css" rel="stylesheet" />
    </head>
    <body>
        <!-- Background Video-->
        <video class="bg-video" playsinline="playsinline" autoplay="autoplay" muted="muted" loop="loop"><source src="assets/mp4/bg.mp4" type="video/mp4" /></video>
        <!-- Masthead-->
        <div class="masthead">
            <div class="masthead-content text-white">
                <div class="container-fluid px-4 px-lg-0">
                    <h1 class="fst-italic lh-1 mb-4">We are recreating our Support website.</h1>
                    <p class="mb-5">We're working hard to finish the re-development of our support website.</p>
                </div>
                <div class="col-md-10 col-lg-8 col-xl-7">
                    <div class="small text-center text-muted fst-italic">Copyright &copy;futurevera.thm</div>
                </div>
            </div>
        </div>
	<!-- Theme is taken from https://startbootstrap.com -->
	<!-- Bootstrap core JS-->
        <script src="js/bootstrap.bundle.min.js"></script>
        <!-- Core theme JS-->
        <script src="js/scripts.js"></script>
    </body>
</html>

View certificate

about:certificate?cert=MIID1DCCArygAwIBAgIUauW3cx0CzRBzqYjg5HMaPwCIbJIwDQYJKoZIhvcNAQELBQAwdTELMAkGA1UEBhMCVVMxDzANBgNVBAgMBk9yZWdvbjERMA8GA1UEBwwIUG9ydGxhbmQxEzARBgNVBAoMCkZ1dHVyZXZlcmExDDAKBgNVBAsMA1RobTEfMB0GA1UEAwwWc3VwcG9ydC5mdXR1cmV2ZXJhLnRobTAeFw0yMjAzMTMxNDI2MjRaFw0yNDAzMTIxNDI2MjRaMHUxCzAJBgNVBAYTAlVTMQ8wDQYDVQQIDAZPcmVnb24xETAPBgNVBAcMCFBvcnRsYW5kMRMwEQYDVQQKDApGdXR1cmV2ZXJhMQwwCgYDVQQLDANUaG0xHzAdBgNVBAMMFnN1cHBvcnQuZnV0dXJldmVyYS50aG0wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCam2TIcJoT0V4OyJPrAtr3JW%2FH14xrPxSQHe3JjxqwSH1HcQh13NdJRyZl%2FhFoNpKJQIur%2B2EPN32SSHoAI0Fy7x%2BcJxNMjeRl5TDFsU5af%2BTf7Pzi8xnF0c82OOC0RDOE8sVhP2OFMx95rS283KxVwjpCGHBzkHsvIVLDjIvhs3b0Xfnscao%2BH9PProJSNkMBZc5ZRJ6MYtHm74MPdVdmbWuyIeNkaK%2BslQ73xKZhRxlYlUhULhzxursi4qgJS5SpDQdc4fVFd3VFa9TJ0VUBWUsXupibA3DFTmkoGSyDQRjEwBcOoWcfqF6VWA%2BBJL%2Ff%2FOKrP1THuAuQvCHwa7YrAgMBAAGjXDBaMAsGA1UdDwQEAwIEMDATBgNVHSUEDDAKBggrBgEFBQcDATA2BgNVHREELzAtgitzZWNyZXRoZWxwZGVzazkzNDc1Mi5zdXBwb3J0LmZ1dHVyZXZlcmEudGhtMA0GCSqGSIb3DQEBCwUAA4IBAQCTUYQLIjsHa42CQDgkqOjmMxlbw%2BYE3lBfhfzs3kDLTLX0xdq1%2BJqNwMVU10PSxSqEG58toZVumHP1y72n3glXUE5EEpjEOqDfWe6V7Qnzr8rRp1ceofLx3tXGNg7UGCl0wtMv2SQhJfYbGFY%2B%2FnWVv3%2BPxRUaHYDyKNqR9zkhpKYtfco9VHVHYiAbo4VZwLNM6kuyxKXqDSPrlZQ%2BlrwYDPVFoIygjInvGv1XqrHJaxzNZflaDMc0%2BwBc0SMOD3YHuTnlbI0hqEgr2dT7IcNQeEGrUL7H5thgGwbucRuXIXyqz1HUprNBHcT1TOoUlF4OYm9VnHzvAX8BcfxY8N5y

DNS Name
secrethelpdesk934752.support.futurevera.thm

                                                                                       
┌──(kali㉿kali)-[~/Downloads]
└─$ tail /etc/hosts
10.10.167.117 dev.team.thm
10.10.29.100 set.windcorp.thm
10.10.20.190 Osiris.windcorp.thm Osiris osiris.windcorp.thm
10.10.37.31  UNATCO
10.10.73.143 jack.thm
#127.0.0.1  newcms.mofo.pwn
10.200.108.33 holo.live 
10.200.108.33 www.holo.live admin.holo.live dev.holo.live
10.10.146.26  severnaya-station.com
10.10.211.130 futurevera.thm blog.futurevera.thm support.futurevera.thm secrethelpdesk934752.support.futurevera.thm

going to https://secrethelpdesk934752.support.futurevera.thm

http://flag{beea0d6edfcee06a59b83fb50ae81b2f}.s3-website-us-west-3.amazonaws.com/



```

![[Pasted image 20230203174646.png]]
![[Pasted image 20230203174807.png]]

This is an enumeration challenge, once you will find it, it will straight up give you the flag.

*flag{beea0d6edfcee06a59b83fb50ae81b2f}*

[[Boiler CTF]]