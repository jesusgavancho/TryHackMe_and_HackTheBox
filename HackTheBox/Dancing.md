```
blob:https://app.hackthebox.com/7ac8a74a-25d6-4db8-8341-4034e784d2ab

┌──(kali㉿kali)-[~]
└─$ ping 10.129.141.78 
PING 10.129.141.78 (10.129.141.78) 56(84) bytes of data.
64 bytes from 10.129.141.78: icmp_seq=1 ttl=127 time=194 ms
64 bytes from 10.129.141.78: icmp_seq=2 ttl=127 time=380 ms
^C
--- 10.129.141.78 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1000ms
rtt min/avg/max/mdev = 193.943/286.739/379.536/92.796 ms
                                                                                                                  
┌──(kali㉿kali)-[~]
└─$ rustscan -a 10.129.141.78 --ulimit 5500 -b 65535 -- -A
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
Open 10.129.141.78:135
Open 10.129.141.78:139
Open 10.129.141.78:445
Open 10.129.141.78:5985
Open 10.129.141.78:47001
Open 10.129.141.78:49664
Open 10.129.141.78:49665
Open 10.129.141.78:49666
Open 10.129.141.78:49667
Open 10.129.141.78:49668
Open 10.129.141.78:49669
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-01 00:34 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 00:34
Completed NSE at 00:34, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 00:34
Completed NSE at 00:34, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 00:34
Completed NSE at 00:34, 0.00s elapsed
Initiating Ping Scan at 00:34
Scanning 10.129.141.78 [2 ports]
Completed Ping Scan at 00:34, 0.19s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 00:34
Completed Parallel DNS resolution of 1 host. at 00:34, 0.01s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 00:34
Scanning 10.129.141.78 [11 ports]
Discovered open port 139/tcp on 10.129.141.78
Discovered open port 135/tcp on 10.129.141.78
Discovered open port 445/tcp on 10.129.141.78
Discovered open port 49668/tcp on 10.129.141.78
Discovered open port 49665/tcp on 10.129.141.78
Discovered open port 5985/tcp on 10.129.141.78
Discovered open port 49667/tcp on 10.129.141.78
Discovered open port 49669/tcp on 10.129.141.78
Discovered open port 49664/tcp on 10.129.141.78
Discovered open port 49666/tcp on 10.129.141.78
Discovered open port 47001/tcp on 10.129.141.78
Completed Connect Scan at 00:34, 0.38s elapsed (11 total ports)
Initiating Service scan at 00:34
Scanning 11 services on 10.129.141.78
Service scan Timing: About 54.55% done; ETC: 00:36 (0:00:48 remaining)
Completed Service scan at 00:35, 57.84s elapsed (11 services on 1 host)
NSE: Script scanning 10.129.141.78.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 00:35
Completed NSE at 00:35, 9.23s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 00:35
Completed NSE at 00:35, 0.93s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 00:35
Completed NSE at 00:35, 0.00s elapsed
Nmap scan report for 10.129.141.78
Host is up, received conn-refused (0.19s latency).
Scanned at 2022-11-01 00:34:42 EDT for 69s

PORT      STATE SERVICE       REASON  VERSION
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 3h59m59s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2022-11-01T08:35:45
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 16849/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 24779/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 48600/udp): CLEAN (Timeout)
|   Check 4 (port 10394/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 00:35
Completed NSE at 00:35, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 00:35
Completed NSE at 00:35, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 00:35
Completed NSE at 00:35, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 69.95 seconds

┌──(kali㉿kali)-[~]
└─$ smbclient -L 10.129.141.78        
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        WorkShares      Disk      
SMB1 disabled -- no workgroup available

ADMIN$ - Administrative shares are hidden network shares created by the Windows NT family of
operating systems that allow system administrators to have remote access to every disk volume on a
network-connected system. These shares may not be permanently deleted but may be disabled.
C$ - Administrative share for the C:\ disk volume. This is where the operating system is hosted.
IPC$ - The inter-process communication share. Used for inter-process communication via named
pipes and is not part of the file system.
WorkShares - Custom share

trying to connect with the 4 shares with blank pass

┌──(kali㉿kali)-[~]
└─$ smbclient \\\\10.129.141.78\\ADMIN$
Password for [WORKGROUP\kali]:
tree connect failed: NT_STATUS_ACCESS_DENIED
                                                                                                                  
┌──(kali㉿kali)-[~]
└─$ smbclient \\\\10.129.141.78\\ADMIN$
Password for [WORKGROUP\kali]:
tree connect failed: NT_STATUS_ACCESS_DENIED
                                                                                                                  
┌──(kali㉿kali)-[~]
└─$ smbclient \\\\10.129.141.78\\C$    
Password for [WORKGROUP\kali]:
tree connect failed: NT_STATUS_ACCESS_DENIED
                                                                                                                  
┌──(kali㉿kali)-[~]
└─$ smbclient \\\\10.129.141.78\\C$
Password for [WORKGROUP\kali]:
tree connect failed: NT_STATUS_ACCESS_DENIED
                                                                                                                  
┌──(kali㉿kali)-[~]
└─$ smbclient \\\\10.129.141.78\\IPC$
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> ls
NT_STATUS_NO_SUCH_FILE listing \*
smb: \> dir
NT_STATUS_NO_SUCH_FILE listing \*
smb: \> ls -lah
NT_STATUS_NO_SUCH_FILE listing \-lah
smb: \> quit
                                                                                                                  
┌──(kali㉿kali)-[~]
└─$ smbclient \\\\10.129.141.78\\IPC$
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> ls
NT_STATUS_NO_SUCH_FILE listing \*
smb: \> 
smb: \> quit

──(kali㉿kali)-[~]
└─$ smbclient \\\\10.129.141.78\\WorkShares
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Mar 29 04:22:01 2021
  ..                                  D        0  Mon Mar 29 04:22:01 2021
  Amy.J                               D        0  Mon Mar 29 05:08:24 2021
  James.P                             D        0  Thu Jun  3 04:38:03 2021

                5114111 blocks of size 4096. 1748759 blocks available
smb: \> cd Amy.J
smb: \Amy.J\> ls
  .                                   D        0  Mon Mar 29 05:08:24 2021
  ..                                  D        0  Mon Mar 29 05:08:24 2021
  worknotes.txt                       A       94  Fri Mar 26 07:00:37 2021

                5114111 blocks of size 4096. 1748759 blocks available
smb: \Amy.J\> more worknotes.txt 
getting file \Amy.J\worknotes.txt of size 94 as /tmp/smbmore.xEVVAq (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
- start apache server on the linux machine
- secure the ftp server
- setup winrm on dancing 

smb: \Amy.J\> cd ..
smb: \> ls
  .                                   D        0  Mon Mar 29 04:22:01 2021
  ..                                  D        0  Mon Mar 29 04:22:01 2021
  Amy.J                               D        0  Mon Mar 29 05:08:24 2021
  James.P                             D        0  Thu Jun  3 04:38:03 2021
c
                5114111 blocks of size 4096. 1748759 blocks available
smb: \> cd James.P
smb: \James.P\> ls
  .                                   D        0  Thu Jun  3 04:38:03 2021
  ..                                  D        0  Thu Jun  3 04:38:03 2021
  flag.txt                            A       32  Mon Mar 29 05:26:57 2021

                5114111 blocks of size 4096. 1748759 blocks available
smb: \James.P\> more flag.txt
5f61c10dffbc77a704d76016a22f1664

more to see it and then press q to close or just get or mget*

I do with more just I have no much file space

```

What does the 3-letter acronym SMB stand for? 
SMB is one of the most basic and well-known protocols out there. You can easily search the acronym of any protocol that you don't know on Internet and the full name of the protocol will come up as the first result. When using acronyms, remember that the first letter of each word is always capitalized as standard. This is called Camel Case (or Medial Capitals).

*Server Message Block *

What port does SMB use to operate at? 
A simple portscan using version detection can get you this result. Also, Googling the port value will return the services used for that port in most cases.
*445*

What is the service name for port 445 that came up in our Nmap scan? 
You will need to use the -sV switch during your nmap scan in order to see this in your results! The answer creates a ? at the end, so remember to include it!
*microsoft-ds *

What is the 'flag' or 'switch' we can use with the SMB tool to 'list' the contents of the share? 
The acronym of this flag stands for 'list', and is precedes by a '-'.
*-L*

How many shares are there on Dancing? 
Use "smbclient -L" to list them.
*4*

What is the name of the share we are able to access in the end with a blank password? 
It's the one that doesn't terminate with the '$' symbol. This is a custom share, made by a system administrator during the configuration phase.
*WorkShares *

What is the command we can use within the SMB shell to download the files we find? 
This is the same command used during the interaction with the FTP shell in the previous box!
*get*

Submit root flag 
*5f61c10dffbc77a704d76016a22f1664*


[[Fawn]]