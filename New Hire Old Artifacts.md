----
Investigate the intrusion attack using Splunk.
----

![](https://assets.tryhackme.com/additional/nhoa/nhoa-banner.png)

![](https://tryhackme-images.s3.amazonaws.com/room-icons/3c801e21455beb1dad9eca7bf412c751.png)

### Task 1  Investigate the attack

 Start Machine

![SOC Team](https://assets.tryhackme.com/additional/jrsecanalyst/task2.png)

**Scenario**: You are a SOC Analyst for an MSSP (managed Security Service Provider) company called TryNotHackMe.

A newly acquired customer (Widget LLC) was recently onboarded with the managed Splunk service. The sensor is live, and all the endpoint events are now visible on TryNotHackMe's end. Widget LLC has some concerns with the endpoints in the Finance Dept, especially an endpoint for a recently hired Financial Analyst. The concern is that there was a period (December 2021) when the endpoint security product was turned off, but an official investigation was never conducted. 

Your manager has tasked you to sift through the events of Widget LLC's Splunk instance to see if there is anything that the customer needs to be alerted on. 

Happy Hunting!

**Other Splunk Rooms**:

- [Splunk 101](https://tryhackme.com/room/splunk101)  
    
- [Splunk 2](https://tryhackme.com/room/splunk2gcd5)
- [Splunk 3](https://tryhackme.com/room/splunk3zs)
- [Conti](https://tryhackme.com/room/contiransomwarehgh)
- [Incident Handling with Splunk](https://tryhackme.com/room/splunk201)  
    

---

Virtual Machine

You can use the Attack Box or OpenVPN to access the Splunk instance. The IP for the Splunk instance is http://MACHINE_IP:8000. 

Note: Wait for the virtual machine to fully load. If you see errors after 2 minutes, refresh the URL until it loads. 

Answer the questions below

```
filter by: between 12/01/2021 and 01/01/2022
index="main" password viewer
12/28/2021 09:09:50 PM
LogName=Microsoft-Windows-Sysmon/Operational
EventCode=7
EventType=4
ComputerName=DESKTOP-H1ATIJC.WidgetLLC.Internal
User=NOT_TRANSLATED
Sid=S-1-5-18
SidType=0
SourceName=Microsoft-Windows-Sysmon
Type=Information
RecordNumber=13957
Keywords=None
TaskCategory=Image loaded (rule: ImageLoad)
OpCode=Info
Message=Image loaded:
RuleName: technique_id=T1073,technique_name=DLL Side-Loading
UtcTime: 2021-12-29 02:09:50.242
ProcessGuid: {3e72283a-c36e-61cb-c511-000000000a00}
ProcessId: 13524
Image: C:\Users\FINANC~1\AppData\Local\Temp\11111.exe
ImageLoaded: C:\Users\FINANC~1\AppData\Local\Temp\11111.exe
FileVersion: 2.06
Description: Web Browser Password Viewer

User: DESKTOP-H1ATIJC\Finance01

filter: C:\\Users\\FINANCE01\\AppData\\Local\\Temp\\

Top Image C:\Users\Finance01\AppData\Local\Temp\IonicLarge.exe

filter: IonicLarge.exe
add new field OriginalFileName
PalitExplorer.exe

IonicLarge.exe,PalitExplorer.exe

filter: IonicLarge.exe

field Destination ip Count 2

2[.]56[.]59[.]42

new field TargetObject

12/28/2021 08:06:38 PM
LogName=Microsoft-Windows-Sysmon/Operational
EventCode=12
EventType=4
ComputerName=DESKTOP-H1ATIJC.WidgetLLC.Internal
User=NOT_TRANSLATED
Sid=S-1-5-18
SidType=0
SourceName=Microsoft-Windows-Sysmon
Type=Information
RecordNumber=4907
Keywords=None
TaskCategory=Registry object added or deleted (rule: RegistryEvent)
OpCode=Info
Message=Registry object added or deleted:
RuleName: technique_id=T1089,technique_name=Disabling Security Tools
EventType: CreateKey
UtcTime: 2021-12-29 01:06:38.163
ProcessGuid: {3e72283a-b49a-61cb-810e-000000000a00}
ProcessId: 7296
Image: C:\Users\Finance01\AppData\Local\Temp\IonicLarge.exe
TargetObject: HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection
User: DESKTOP-H1ATIJC\Finance01
Collapse

    TargetObject = HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection
    host = DESKTOP-H1ATIJC
    source = WinEventLog:Microsoft-Windows-Sysmon/Operational
    sourcetype = WinEventLog:Microsoft-Windows-Sysmon/Operational

HKLM\SOFTWARE\Policies\Microsoft\Windows Defender

filter: taskkill /im 

ParentCommandLine: "C:\Windows\System32\cmd.exe" /c taskkill /im phcIAmLJMAIMSa9j9MpgJo1m.exe /f & timeout /t 6 & del /f /q "C:\Users\Finance01\Pictures\Adobe Films\phcIAmLJMAIMSa9j9MpgJo1m.exe" & del C:\ProgramData\*.dll & exit

ParentCommandLine: "C:\Windows\System32\cmd.exe" /c taskkill /im "WvmIOrcfsuILdX6SNwIRmGOJ.exe" /f & erase "C:\Users\Finance01\Pictures\Adobe Films\WvmIOrcfsuILdX6SNwIRmGOJ.exe" & exit

phcIAmLJMAIMSa9j9MpgJo1m.exe,WvmIOrcfsuILdX6SNwIRmGOJ.exe

filter: powershell CommandLine="*"| sort _time

and the last

powershell  WMIC /NAMESPACE:\\root\Microsoft\Windows\Defender PATH MSFT_MpPreference call Add ThreatIDDefaultAction_Ids=2147737394 ThreatIDDefaultAction_Actions=6 Force=True


1:07:57.000 AM	
12/28/2021 08:07:57 PM
LogName=Microsoft-Windows-Sysmon/Operational
EventCode=1
EventType=4
ComputerName=DESKTOP-H1ATIJC.WidgetLLC.Internal
User=NOT_TRANSLATED
Sid=S-1-5-18
SidType=0
SourceName=Microsoft-Windows-Sysmon
Type=Information
RecordNumber=6220
Keywords=None
TaskCategory=Process Create (rule: ProcessCreate)
OpCode=Info
Message=Process Create:
RuleName: technique_id=T1059,technique_name=Command-Line Interface
UtcTime: 2021-12-29 01:07:57.794
ProcessGuid: {3e72283a-b4ed-61cb-d10e-000000000a00}
ProcessId: 9984
Image: C:\Windows\SysWOW64\forfiles.exe
FileVersion: 10.0.19041.1 (WinBuild.160101.0800)
Description: ForFiles - Executes a command on selected files
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: forfiles.exe
CommandLine: forfiles  /p c:\windows\system32 /m waitfor.exe /c "cmd /C powershell WMIC /NAMESPACE:\\root\Microsoft\Windows\Defender PATH MSFT_MpPreference call Add ThreatIDDefaultAction_Ids=2147735503 ThreatIDDefaultAction_Actions=6 Force=True" 
CurrentDirectory: C:\Users\FINANC~1\AppData\Local\Temp\7zS36E1.tmp\
User: DESKTOP-H1ATIJC\Finance01
LogonGuid: {3e72283a-2344-61bd-4bcd-020000000000}
LogonId: 0x2CD4B
TerminalSessionId: 1
IntegrityLevel: High
Hashes: SHA1=0CF2936B8D074F39FE030FEF6266AF53399B31AF,MD5=D95C443851F70F77427B3183B1619DD3,SHA256=7074D2A9C3D669A15D5B3A7BA1226DBBA05888CC537CF055FED6371F32F0C1F5,IMPHASH=64E68F7B6E212C1F2B12FFE1C1CFE372
ParentProcessGuid: {3e72283a-b4e7-61cb-cc0e-000000000a00}
ParentProcessId: 8872
ParentImage: C:\Windows\SysWOW64\cmd.exe
ParentCommandLine: "C:\Windows\System32\cmd.exe" /C forfiles /p c:\windows\system32 /m waitfor.exe /c "cmd /C powershell WMIC /NAMESPACE:\\root\Microsoft\Windows\Defender PATH MSFT_MpPreference call Add ThreatIDDefaultAction_Ids=2147735503 ThreatIDDefaultAction_Actions=6 Force=True" & forfiles /p c:\windows\system32 /m where.exe /c "cmd /C powershell WMIC /NAMESPACE:\\root\Microsoft\Windows\Defender PATH MSFT_MpPreference call Add ThreatIDDefaultAction_Ids=2147737010 ThreatIDDefaultAction_Actions=6 Force=True" & forfiles /p c:\windows\system32 /m calc.exe /c "cmd /C powershell WMIC /NAMESPACE:\\root\Microsoft\Windows\Defender PATH MSFT_MpPreference call Add ThreatIDDefaultAction_Ids=2147737007 ThreatIDDefaultAction_Actions=6 Force=True" & forfiles /p c:\windows\system32 /m notepad.exe /c "cmd /C powershell WMIC /NAMESPACE:\\root\Microsoft\Windows\Defender PATH MSFT_MpPreference call Add ThreatIDDefaultAction_Ids=2147737394 ThreatIDDefaultAction_Actions=6 Force=True" &

2147735503,2147737010,2147737007,2147737394

filter: AppData then see image
C:\Users\Finance01\AppData\Roaming\EasyCalc\EasyCalc.exe

filter: appdata Image="C:\\Users\\Finance01\\AppData\\Roaming\\EasyCalc\\EasyCalc.exe" dll

ImageLoaded: C:\Users\Finance01\AppData\Roaming\EasyCalc\ffmpeg.dll
ImageLoaded: C:\Users\Finance01\AppData\Roaming\EasyCalc\nw.dll
ImageLoaded: C:\Users\Finance01\AppData\Roaming\EasyCalc\nw_elf.dll

ffmpeg.dll,nw.dll,nw_elf.dll

or check by ImageLoaded
C:\Users\Finance01\AppData\Roaming\EasyCalc\EasyCalc.exe 	15 	22.727% 	
C:\Users\Finance01\AppData\Roaming\EasyCalc\nw_elf.dll 	15 	22.727% 	
C:\Users\Finance01\AppData\Roaming\EasyCalc\ffmpeg.dll 	13 	19.697% 	
C:\Users\Finance01\AppData\Roaming\EasyCalc\nw.dll      13 	19.697%

```

A Web Browser Password Viewer executed on the infected machine. What is the name of the binary? Enter the full path.

	*C:\Users\FINANC~1\AppData\Local\Temp\11111.exe*

What is listed as the company name?  

*NirSoft*

Another suspicious binary running from the same folder was executed on the workstation. What was the name of the binary? What is listed as its original filename? (**format: file.xyz,file.xyz**)  

File path should include username in long name format. https://docs.microsoft.com/en-us/windows/win32/fileio/naming-a-file

*IonicLarge.exe,PalitExplorer.exe*

The binary from the previous question made two outbound connections to a malicious IP address. What was the IP address? Enter the answer in a defang format.  

Cyberchef can help with defanging.

*2[.]56[.]59[.]42*

The same binary made some change to a registry key. What was the key path?  

*HKLM\SOFTWARE\Policies\Microsoft\Windows Defender*

Some processes were killed and the associated binaries were deleted. What were the names of the two binaries? (**format: file.xyz,file.xyz**)  

Process were killed with 'taskkill /im'

*phcIAmLJMAIMSa9j9MpgJo1m.exe,WvmIOrcfsuILdX6SNwIRmGOJ.exe*

The attacker ran several commands within a PowerShell session to change the behaviour of Windows Defender. What was the last command executed in the series of similar commands?  

The last command issue has the most recent time stamp

*powershell  WMIC /NAMESPACE:\\root\Microsoft\Windows\Defender PATH MSFT_MpPreference call Add ThreatIDDefaultAction_Ids=2147737394 ThreatIDDefaultAction_Actions=6 Force=True*

Based on the previous answer, what were the four IDs set by the attacker? Enter the answer in order of execution. (format: 1st,2nd,3rd,4th)  

*2147735503,2147737010,2147737007,2147737394*

Another malicious binary was executed on the infected workstation from another AppData location. What was the full path to the binary?  

	*C:\Users\Finance01\AppData\Roaming\EasyCalc\EasyCalc.exe*

What were the DLLs that were loaded from the binary from the previous question? Enter the answers in alphabetical order. (format: file1.dll,file2.dll,file3.dll)  

*ffmpeg.dll,nw.dll,nw_elf.dll*

Want to learn more? In honor of the late and great Ollie, check out this wonderful [room](https://tryhackme.com/room/ollie).

 Completed



[[Minotaur's Labyrinth]]