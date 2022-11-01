

```
┌──(kali㉿kali)-[~]
└─$ ping 10.129.190.136
PING 10.129.190.136 (10.129.190.136) 56(84) bytes of data.
64 bytes from 10.129.190.136: icmp_seq=1 ttl=63 time=190 ms
64 bytes from 10.129.190.136: icmp_seq=2 ttl=63 time=194 ms
^C
--- 10.129.190.136 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 999ms
rtt min/avg/max/mdev = 189.765/191.810/193.856/2.045 ms
                                                                                                                  
┌──(kali㉿kali)-[~]
└─$ rustscan -a 10.129.190.136 --ulimit 5500 -b 65535 -- -A
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

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.129.190.136:21
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-01 00:19 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 00:19
Completed NSE at 00:19, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 00:19
Completed NSE at 00:19, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 00:19
Completed NSE at 00:19, 0.00s elapsed
Initiating Ping Scan at 00:19
Scanning 10.129.190.136 [2 ports]
Completed Ping Scan at 00:19, 0.24s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 00:19
Completed Parallel DNS resolution of 1 host. at 00:19, 0.02s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 00:19
Scanning 10.129.190.136 [1 port]
Discovered open port 21/tcp on 10.129.190.136
Completed Connect Scan at 00:19, 0.19s elapsed (1 total ports)
Initiating Service scan at 00:19
Scanning 1 service on 10.129.190.136
Completed Service scan at 00:19, 0.40s elapsed (1 service on 1 host)
NSE: Script scanning 10.129.190.136.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 00:19
NSE: [ftp-bounce 10.129.190.136:21] PORT response: 500 Illegal PORT command.
Completed NSE at 00:19, 1.64s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 00:19
Completed NSE at 00:19, 1.37s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 00:19
Completed NSE at 00:19, 0.00s elapsed
Nmap scan report for 10.129.190.136
Host is up, received conn-refused (0.23s latency).
Scanned at 2022-11-01 00:19:45 EDT for 4s

PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0              32 Jun 04  2021 flag.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.14.91
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
Service Info: OS: Unix

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 00:19
Completed NSE at 00:19, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 00:19
Completed NSE at 00:19, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 00:19
Completed NSE at 00:19, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 5.85 seconds

┌──(kali㉿kali)-[~]
└─$ ftp -h         
ftp: invalid option -- 'h'
usage: ftp [-46AadefginpRtVv] [-N NETRC] [-o OUTPUT] [-P PORT] [-q QUITTIME]
           [-r RETRY] [-s SRCADDR] [-T DIR,MAX[,INC]] [-x XFERSIZE]
           [[USER@]HOST [PORT]]
           [[USER@]HOST:[PATH][/]]
           [file:///PATH]
           [ftp://[USER[:PASSWORD]@]HOST[:PORT]/PATH[/][;type=TYPE]]
           [http://[USER[:PASSWORD]@]HOST[:PORT]/PATH]
           [https://[USER[:PASSWORD]@]HOST[:PORT]/PATH]
           ...
       ftp -u URL FILE ...
       ftp -?

┌──(kali㉿kali)-[~]
└─$ ftp 10.129.190.136
Connected to 10.129.190.136.
220 (vsFTPd 3.0.3)
Name (10.129.190.136:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> help
Commands may be abbreviated.  Commands are:

!               delete          hash            mlsd            pdir            remopts         struct
$               dir             help            mlst            pls             rename          sunique
account         disconnect      idle            mode            pmlsd           reset           system
append          edit            image           modtime         preserve        restart         tenex
ascii           epsv            lcd             more            progress        rhelp           throttle
bell            epsv4           less            mput            prompt          rmdir           trace
binary          epsv6           lpage           mreget          proxy           rstatus         type
bye             exit            lpwd            msend           put             runique         umask
case            features        ls              newer           pwd             send            unset
cd              fget            macdef          nlist           quit            sendport        usage
cdup            form            mdelete         nmap            quote           set             user
chmod           ftp             mdir            ntrans          rate            site            verbose
close           gate            mget            open            rcvbuf          size            xferbuf
cr              get             mkdir           page            recv            sndbuf          ?
debug           glob            mls             passive         reget           status
ftp> ls
229 Entering Extended Passive Mode (|||28746|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0              32 Jun 04  2021 flag.txt
226 Directory send OK.

ftp> more flag.txt
035db21c881520061c53e0536e44f815

pwnd

```

What does the 3-letter acronym FTP stand for? 
*File Transfer Protocol *

Which port does the FTP service listen on usually? 
*21*

What acronym is used for the secure version of FTP? 
*sftp*

What is the command we can use to send an ICMP echo request to test our connection to the target? 
*ping*

From your scans, what version is FTP running on the target?
*vsftpd 3.0.3 *

From your scans, what OS type is running on the target? 
*Unix*

What is the command we need to run in order to display the 'ftp' client help menu? 
*ftp -h *

What is username that is used over FTP when you want to log in without having an account? 
When your name is not known, you are...

*anonymous*

What is the response code we get for the FTP message 'Login successful'? 
Response codes are important because we can tell what the service is reporting back to us at a glance. For example, we're all acquainted with the '404' code. We can even use it as a casual joke nowadays. '404' is the web protocol response code for 'Not Found', telling us that the resource we are trying to reach could not be found by the web server. In our case as well, the response code is made of '3' digits.
*230*

There are a couple of commands we can use to list the files and directories available on the FTP server. One is dir. What is the other that is a common way to list files on a Linux system. 
Try running help from within FTP to see the possible commands.
*ls*

What is the command used to download the file we found on the FTP server? 
Using the 'help' command within the 'ftp service' will reveal this command. Its' meaning is straight-forward.
*get*

Submit root flag 
*035db21c881520061c53e0536e44f815*


[[Meow]]