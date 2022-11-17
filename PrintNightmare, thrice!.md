---
The nightmare continues.. Search the artifacts on the endpoint, again, to determine if the employee used any of the Windows Printer Spooler vulnerabilities to elevate their privileges. 
---


![](https://assets.tryhackme.com/additional/printnightmare/pm-room-banner2.png)

![](https://tryhackme-images.s3.amazonaws.com/room-icons/855a6f35a14df6fb9a5e8b576c14e51d.png)

### Detection 

![|333](https://i.ibb.co/5KBWxY9/Computer-forensic-science-Digital-evidence-analysis-cybercrime-investigation-data-recovering-Cyberse.jpg)

Scenario: After discovering the PrintNightmare attack the security team pushed an emergency patch to all the endpoints. The PrintNightmare exploit used previously no longer works. All is well. Unfortunately, the same 2 employees discovered yet another exploit that can possibly work on a fully patched endpoint to elevate their privileges.

Task: Inspect the artifacts on the endpoint to detect the PrintNightmare exploit used.

```
using wireshark, filtering smb2

Source Address: 10.10.158.154
Destination Address: 20.188.56.147

Session Id: 0x000024f2f4000a85 Acct:rjones Domain:THM-PRINTNIGHT0 Host:THM-PRINTNIGHT0
THM-PRINTNIGHT0\r-jones

Session Id: 0x0000247514000041 Acct:gentilguest Domain:THM-PRINTNIGHT0 Host:THM-PRINTNIGHT0
THM-PRINTNIGHT0/gentilguest

Tree: \\printnightmare.gentilkiwi.com\IPC$

using brim

queries: windows network activity, and filter by date from A to Z
_path=~smb* OR _path=dce_rpc | sort ts

\\printnightmare.gentilkiwi.com\IPC$
\PIPE\srvsvc
\pipe\spoolss

\\printnightmare.gentilkiwi.com\IPC$,\srvsvc,\spoolss

querie: file activity
filename!=null cut _path, tx_hosts, rx_hosts, conn_uids, mime_type, filename, md5, sha1

x64\3\mimispool.dll
W32X86\3\mimispool.dll

_path=~smb* | sort ts

\\printnightmare.gentilkiwi.com\print$

\\printnightmare.gentilkiwi.com\print$,x64\3\mimispool.dll,W32X86\3\mimispool.dll

using fulleventlogview (advanced options, show all events) after 

find mimispool.dll

TargetFileName: C:\Windows\System32\spool\drivers\x64\3
TargetFileName: C:\Windows\System32\spool\drivers\W32X86\3

C:\Windows\System32\spool\drivers\W32X86\3C,:\Windows\System32\spool\drivers\x64\3

searching manually 

C:\Windows\System32\spool\SERVERS\printnightmare.gentilkiwi.com


filter: show only the specifid providers
Microsoft-Windows-PrintService


File(s) mimispool.dll associated with printer \\printnightmare.gentilkiwi.com\Kiwi Legit Printer

using process monitor
filter by process name by cmd.exe

first result > properties > Parent PID 2640 and PID 5408 , filter by PID 2640 then see the process is spoolsv.exe


so will be 5408,spoolsv.exe

quickfilter in fulleventlogview

5408

then search for command line

CommandLine: net localgroup administrators rjones /add
```

![[Pasted image 20221117090731.png]]

![[Pasted image 20221117094328.png]]

![[Pasted image 20221117104116.png]]

![[Pasted image 20221117105315.png]]

![[Pasted image 20221117113307.png]]

![[Pasted image 20221117113723.png]]

![[Pasted image 20221117114702.png]]

What remote address did the employee navigate to?
Check the SMB traffic in the pcap file
*20.188.56.147*



Per the PCAP, which user returns a STATUS_LOGON_FAILURE error?
Wireshark
	
	*THM-PRINTNIGHT0\r-jones*


Which user successfully connects to an SMB share?
	
	*THM-PRINTNIGHT0/gentilguest*


What is the first remote SMB share the endpoint connected to? What was the first filename? What was the second? (format: answer,answer,answer)
Wireshark or Brim
		
		*\\printnightmare.gentilkiwi.com\IPC$,\srvsvc,\spoolss*


From which remote SMB share was malicious DLL obtained? What was the path to the remote folder for the first DLL? How about the second? (format: answer,answer,answer)
Many DLLs were downloaded but one stands out in association to a hack tool. Brim will be the most useful.

	*\\printnightmare.gentilkiwi.com\print$,\x64\3\mimispool.dll,\W32X86\3\mimispool.dll*


What was the first location the malicious DLL was downloaded to on the endpoint? What was the second?
Check the event logs

	*C:\Windows\System32\spool\drivers\W32X86\3C,:\Windows\System32\spool\drivers\x64\3*

What is the folder that has the name of the remote printer server the user connected to? (provide the full folder path)
	
	*C:\Windows\System32\spool\SERVERS\printnightmare.gentilkiwi.com*


What is the name of the printer the DLL added?
Check Microsoft-Windows-PrintService
*Kiwi Legit Printer*


What was the process ID for the elevated command prompt? What was its parent process? (format: answer,answer)
*5408,spoolsv.exe*


What command did the user perform to elevate privileges?
*net localgroup administrators rjones /add*




[[PrintNightmare, again!]]