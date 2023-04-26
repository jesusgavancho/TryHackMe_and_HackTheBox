----
An Exchange server was compromised with ransomware. Use Splunk to investigate how the attackers compromised the server.
----

![](https://assets.tryhackme.com/additional/conti/conti-room-banner.png)

![](https://tryhackme-images.s3.amazonaws.com/room-icons/efe12f2572d7ed0e3d94c37c00560bdc.png)

### SITREP

Some employees from your company reported that they can’t log into Outlook. The Exchange system admin also reported that he can’t log in to the Exchange Admin Center. After initial triage, they discovered some weird readme files settled on the Exchange server.  

Below is a copy of the ransomware note.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de58e2bfac4a912bcc7a3e9/room-content/15db974b80239a7eb2c52fb26c458933.png)  

**Warning**: Do **NOT** attempt to visit and/or interact with any URLs displayed in the ransom note.   

Read the latest on the Conti ransomware [here](https://www.bleepingcomputer.com/news/security/fbi-cisa-and-nsa-warn-of-escalating-conti-ransomware-attacks/). 

---

Connect to OpenVPN or use the AttackBox to access the attached Splunk instance. 

Splunk Interface Credentials:

**Username**: `bellybear`

**Password**: `password!!!`

**Splunk URL**: `http://10.10.77.154:8000`

Special thanks to [Bohan Zhang](https://www.linkedin.com/in/bohansec?miniProfileUrn=urn%3Ali%3Afs_miniProfile%3AACoAACFkYBwB9L43-CozJsTYeFoIV29KBlKU9qc&lipi=urn%3Ali%3Apage%3Ad_flagship3_search_srp_all%3BWgzBOFb8RQWd%2B24UFVSw%2Fw%3D%3D) for this challenge.

Answer the questions below

Start the attached virtual machine.

Question Done

### Exchange Server Compromised

 Start Machine

Below are the error messages that the Exchange admin and employees see when they try to access anything related to Exchange or Outlook.  

**Exchange Control Panel**:  
![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de58e2bfac4a912bcc7a3e9/room-content/214468bd3cc7466762b2358993bb3069.png)

**Outlook Web Access**:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de58e2bfac4a912bcc7a3e9/room-content/c7d87fb962d961d81502f02dd1fdba77.png)  

**Task**: You are assigned to investigate this situation. Use Splunk to answer the questions below regarding the Conti ransomware. 

Answer the questions below

```
select all time

filter: index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"

https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

Event ID 11: FileCreate

File create operations are logged when a file is created or overwritten. This event is useful for monitoring autostart locations, like the Startup folder, as well as temporary and download directories, which are common places malware drops during initial infection.

index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11

c:\Users\Administrator\Documents\cmd.exe

more fields choose Hashes then filter

index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" Image="c:\\Users\\Administrator\\Documents\\cmd.exe"

MD5=290C7DFB01E50CEA9E19DA81A781AF2C,SHA256=53B1C1B2F41A7FC300E97D036E57539453FF82001DD3F6ABF07F4896B1F9CA22,IMPHASH=23F815785DB238377F4513BE54DBA574

or just 

index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" Image="c:\\Users\\Administrator\\Documents\\cmd.exe" md5

index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11 | stats count by TargetFilename

stats (statistics)

C:\Users\.NET v4.5 Classic\Downloads\readme.txt

index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" CommandLine="*/add*" 
| stats count by CommandLine

net user /add securityninja hardToHack123$

Event ID 8: CreateRemoteThread

The `CreateRemoteThread` event detects when a process creates a thread in another process. This technique is used by malware to inject code and hide in other processes. The event indicates the source and target process. It gives information on the code that will be run in the new thread: `StartAddress`, `StartModule` and `StartFunction`. Note that `StartModule` and `StartFunction` fields are inferred, they might be empty if the starting address is outside loaded modules or known exported functions.

index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=8 | table SourceImage, TargetImage

C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe,C:\Windows\System32\wbem\unsecapp.exe

https://www.linkedin.com/pulse/lsassexe-exploited-process-jitu-mani-das/

Lsass.exe is a critical Windows system process responsible for local security policy enforcement, authentication, and Active Directory management. Due to its crucial role in the system, malicious actors often attempt to exploit vulnerabilities in the Lsass.exe process to gain unauthorized access and execute malicious code on the targeted system. Here are some methods to exploit the Lsass.exe process:

1.  Pass-the-Hash (PtH) Attack: This attack involves stealing the NTLM hash of a user's password and using it to authenticate the attacker to the system. This is possible because Lsass.exe stores the NTLM hash in memory. Malware can use this technique to bypass authentication and gain access to sensitive data.
2.  Process Injection: Malware can inject code into the Lsass.exe process and gain elevated privileges to perform malicious activities on the targeted system.
3.  Exploiting Vulnerabilities: Lsass.exe has had multiple vulnerabilities in the past, such as CVE-2019-1338, CVE-2020-0601, and CVE-2021-36942. Malware can exploit these vulnerabilities to execute code on the system, bypass authentication, or elevate privileges.
4.  Credential Dumping: Malware can extract passwords, user account information, and other sensitive data from the memory of the Lsass.exe process using tools such as Mimikatz.
5.  Malicious LSASS Service: Malware can create a malicious LSASS service that runs with elevated privileges and intercepts credentials passed to the Lsass.exe process.
6.  Remote Desktop Protocol (RDP) Session Hijacking: Malware can hijack an RDP session and inject malicious code into the Lsass.exe process.
7.  DLL Hijacking: Malware can hijack the DLLs loaded by Lsass.exe, allowing it to execute arbitrary code with elevated privileges.
8.  Man-in-the-Middle (MitM) Attack: Malware can perform a MitM attack to intercept traffic between the Lsass.exe process and the domain controller and steal authentication credentials.
9.  Sticky Keys Attack: Malware can replace the Lsass.exe process with a program that executes when the Sticky Keys accessibility feature is triggered, allowing the attacker to gain system-level access.
10.  NTDS.dit Database Extraction: Malware can extract the NTDS.dit file, which contains Active Directory data, from the system and use it to authenticate and escalate privileges.

C:\Windows\System32\lsass.exe

https://www.iis.net/

index=main sourcetype=iis cs_method=POST
| search *.php* OR *.asp* OR *.aspx* OR *.jsp* 
| stats count by cs_uri_stem

/owa/auth/i3gfPctK1c2x.aspx

index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" i3gfPctK1c2x.aspx 
| table CommandLine

attrib.exe  -r \\\\win-aoqkg2as2q7.bellybear.local\C$\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\i3gfPctK1c2x.aspx

https://www.securin.io/articles/is-conti-ransomware-on-a-roll/

 We analyzed three CVEs being exploited by the Conti group – CVE-2020-0796,  
CVE-2018-13374, CVE-2018-13379, and here is our analysis about them.



```

Can you identify the location of the ransomware?

Look for a common Windows binary located in an unusual location.

	*c:\Users\Administrator\Documents\cmd.exe*

What is the Sysmon event ID for the related file creation event?  

*11*

Can you find the MD5 hash of the ransomware?  

*290C7DFB01E50CEA9E19DA81A781AF2C*

What file was saved to multiple folder locations?

*readme.txt*

What was the command the attacker used to add a new user to the compromised system?

*net user /add securityninja hardToHack123$*

The attacker migrated the process for better persistence. What is the migrated process image (executable), and what is the original process image (executable) when the attacker got on the system?

Try Sysmon event code 8.

	*C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe,C:\Windows\System32\wbem\unsecapp.exe*

The attacker also retrieved the system hashes. What is the process image used for getting the system hashes?  

Try Sysmon event code 8 & check Target Image.

	*C:\Windows\System32\lsass.exe*

What is the web shell the exploit deployed to the system?  

Try looking in the IIS logs for POST requests.

*i3gfPctK1c2x.aspx*

What is the command line that executed this web shell?  

Check the CommandLine.

	*attrib.exe  -r \\\\win-aoqkg2as2q7.bellybear.local\C$\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\i3gfPctK1c2x.aspx*

What three CVEs did this exploit leverage?

External research required.

*CVE-2020-0796, CVE-2018-13374, CVE-2018-13379*

[[Willow]]