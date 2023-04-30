----
Use your Windows forensics knowledge to investigate an incident.
----

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/63588b5ef586912c7d03c4f0/room-content/c62fc0b6f9d22ed2fddc718004c3d5ea.png)

### Introduction

 Start Machine

## Welcome to the team, kid. I have something for you to get your feet wet.

## Our client has a newly hired employee who saw a suspicious-looking janitor exiting his office as he was about to return from lunch.  

I want you to investigate if there was user activity while the user was away **between** **12:05 PM to 12:45 PM on the 19th of November 2022**. If there are, figure out what files were accessed and exfiltrated externally.

You'll be accessing a live system, but use the disk image already exported to the `C:\Users\THM-RFedora\Desktop\kape-results\C` directory for your investigation. The link to the tools that you'll need is in `C:\Users\THM-RFedora\Desktop\tools` 

Finally, I want to remind you that you signed an NDA, so avoid viewing any files classified as top secret. I don't want us to get into trouble.

## Connecting to the machine

Start the virtual machine in split-screen view by clicking on the green "Start Machine" button on the upper right section of this task. If the VM is not visible, use the blue "Show Split View" button at the top-right of the page. Alternatively, you can connect to the VM using the credentials below via "Remote Desktop".

![123](https://tryhackme-images.s3.amazonaws.com/user-uploads/63588b5ef586912c7d03c4f0/room-content/be629720b11a294819516c1d4e738c92.png)

**Username**

THM-RFedora

**Password**

Passw0rd!

**IP**

MACHINE_IP

_**Note:** Once the VM is fully running, please run Registry Explorer immediately, as this tool may take a few minutes to fully start up when executing the program for the first time._

Answer the questions below

Connect to the machine and continue to the next task

Question Done

### Windows Forensics review

 Download Task Files

## Pre-requisites

This room is based on the [Windows Forensics 1](https://tryhackme.com/room/windowsforensics1) and [Windows Forensics 2](https://tryhackme.com/room/windowsforensics2) rooms. A cheat sheet is attached below, which you can also download by clicking on the blue `Download Task Files` button on the right.

To better understand how to perform forensics quickly and efficiently, consider checking out the [KAPE room](https://tryhackme.com/room/kape).  

Good luck!

Answer the questions below

Let's do this!

Question Done

### Snooping around

Initial investigations reveal that someone accessed the user's computer during the previously specified timeframe.

Whoever this someone is, it is evident they already know what to search for. Hmm. Curious.

Answer the questions below

```
Open RegistryExplorer tool then load hive NTUSER.DAT 

Windows Explorer Address/Search Bars:

Another way to identify a user's recent activity is by looking at the paths typed in the Windows Explorer address bar or searches performed using the following registry keys, respectively.

NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths

NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery




```


What file type was searched for using the search bar in Windows Explorer?

Use the RegistryExplorer tool to check the "Windows Explorer Address/Search Bars" task in Windows Forensics 1 room.

![[Pasted image 20230430155452.png]]

*.pdf*

What top-secret keyword was searched for using the search bar in Windows Explorer?  

![[Pasted image 20230430155425.png]]

*continental*

### Can't simply open it

Not surprisingly, they quickly found what they are looking for in a matter of minutes.

Ha! They seem to have hit a snag! They needed something first before they could continue.

_**Note:**  W__hen using the Autopsy Tool, you can speed up the load times by only selecting "Recent Activity" when configuring the Ingest settings._

![Configuring the Ingest setting in Autopsy](https://tryhackme-images.s3.amazonaws.com/user-uploads/63588b5ef586912c7d03c4f0/room-content/fda88f43a1c03a9959249945f061094a.png)

Answer the questions below

```
using Autopsy tool

select data source type : logical files

```


What is the name of the downloaded file to the Downloads folder?

Use the Autopsy tool to view the "Web Downloads" artifacts.

![[Pasted image 20230430160648.png]]

![[Pasted image 20230430161214.png]]

*7z2201-x64.exe*

When was the file from the previous question downloaded? (YYYY-MM-DD HH:MM:SS UTC)  

*Date Accessed	2022-11-19 12:09:19 UTC*

Thanks to the previously downloaded file, a PNG file was opened. When was this file opened? (YYYY-MM-DD HH:MM:SS)  

You can filter by file extension via the Registry Explorer tool.

![[Pasted image 20230430161737.png]]

*2022-11-19 12:10:21*

### Sending it outside

Uh oh. They've hit the jackpot and are now preparing to exfiltrate data outside the network.

There is no way to do it via USB. So what's their other option?  

Answer the questions below

```
c:\tools>JLECmd.exe -h
Description:
  JLECmd version 1.5.0.0

  Author: Eric Zimmerman (saericzimmerman@gmail.com)
  https://github.com/EricZimmerman/JLECmd

  Examples: JLECmd.exe -f "C:\Temp\f01b4d95cf55d32a.customDestinations-ms" --mp
          JLECmd.exe -f "C:\Temp\f01b4d95cf55d32a.automaticDestinations-ms" --json "D:\jsonOutput" --jsonpretty
          JLECmd.exe -d "C:\CustomDestinations" --csv "c:\temp" --html "c:\temp" -q
          JLECmd.exe -d "C:\Users\e\AppData\Roaming\Microsoft\Windows\Recent" --dt "ddd yyyy MM dd HH:mm:ss.fff"

          Short options (single letter) are prefixed with a single dash. Long commands are prefixed with two dashes


Usage:
  JLECmd [options]

Options:
  -f <f>             File to process. Either this or -d is required
  -d <d>             Directory to recursively process. Either this or -f is required

c:\tools>JLECmd.exe -d C:\Users\THM-RFedora\Desktop\kape-results\C\Users\THM-RFedora
JLECmd version 1.5.0.0

Author: Eric Zimmerman (saericzimmerman@gmail.com)
https://github.com/EricZimmerman/JLECmd

Command line: -d C:\Users\THM-RFedora\Desktop\kape-results\C\Users\THM-RFedora

Warning: Administrator privileges not found!

Looking for jump list files in C:\Users\THM-RFedora\Desktop\kape-results\C\Users\THM-RFedora

Found 9 files

Processing C:\Users\THM-RFedora\Desktop\kape-results\C\Users\THM-RFedora\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\12dc1ea8e34b5a6.automaticDestinations-ms

Source file: C:\Users\THM-RFedora\Desktop\kape-results\C\Users\THM-RFedora\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\12dc1ea8e34b5a6.automaticDestinations-ms

--- AppId information ---
  AppID: 12dc1ea8e34b5a6
  Description: Microsoft Paint 6.1

--- DestList information ---
  Expected DestList entries:  1
  Actual DestList entries:    1
  DestList version:           4

--- DestList entries ---
Entry #: 1
  MRU: 0
  Path: C:\Program Files (x86)\Windows Media Player\Skins\tophatsecret\continental.png
  Pinned: False
  Created on:    2022-11-19 11:45:46
  Last modified: 2022-11-19 12:10:21
  Hostname: tryhatme-rfedor
  Mac Address: 02:aa:8b:ff:d5:25
  Interaction count: 1

--- Lnk information ---
  Absolute path: My Computer\C:\\\\\



---------- Processed C:\Users\THM-RFedora\Desktop\kape-results\C\Users\THM-RFedora\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\12dc1ea8e34b5a6.automaticDestinations-ms in 0.98806850 seconds ----------

Processing C:\Users\THM-RFedora\Desktop\kape-results\C\Users\THM-RFedora\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\28c8b86deab549a1.automaticDestinations-ms

Source file: C:\Users\THM-RFedora\Desktop\kape-results\C\Users\THM-RFedora\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\28c8b86deab549a1.automaticDestinations-ms

--- AppId information ---
  AppID: 28c8b86deab549a1
  Description: Internet Explorer 8.0.7600.16385 / 9

--- DestList information ---
  Expected DestList entries:  1
  Actual DestList entries:    1
  DestList version:           4

--- DestList entries ---
Entry #: 1
  MRU: 0
  Path: C:\Users\THM-RFedora\Desktop\TryHatMe Welcome Letter.pdf
  Pinned: False
  Created on:    2022-11-18 10:39:43
  Last modified: 2022-11-18 11:16:30
  Hostname: thm-windows-bas
  Mac Address: 02:d1:ff:b2:6b:e9
  Interaction count: 1

--- Lnk information ---
  Absolute path: My Computer\C:\Users\\Desktop\



---------- Processed C:\Users\THM-RFedora\Desktop\kape-results\C\Users\THM-RFedora\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\28c8b86deab549a1.automaticDestinations-ms in 0.02864250 seconds ----------

Processing C:\Users\THM-RFedora\Desktop\kape-results\C\Users\THM-RFedora\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\5d696d521de238c3.automaticDestinations-ms

Source file: C:\Users\THM-RFedora\Desktop\kape-results\C\Users\THM-RFedora\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\5d696d521de238c3.automaticDestinations-ms

--- AppId information ---
  AppID: 5d696d521de238c3
  Description: Google Chrome 9.0.597.84 / 12.0.742.100 / 13.0.785.215 / 48.0.2564.116

--- DestList information ---
  Expected DestList entries:  1
  Actual DestList entries:    1
  DestList version:           4

--- DestList entries ---
Entry #: 1
  MRU: 0
  Path: C:\Users\THM-RFedora\Desktop\TryHatMe Welcome Letter.pdf
  Pinned: False
  Created on:    2022-11-18 10:39:43
  Last modified: 2022-11-18 11:16:38
  Hostname: thm-windows-bas
  Mac Address: 02:d1:ff:b2:6b:e9
  Interaction count: 1

--- Lnk information ---
  Absolute path: My Computer\C:\Users\\Desktop\



---------- Processed C:\Users\THM-RFedora\Desktop\kape-results\C\Users\THM-RFedora\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\5d696d521de238c3.automaticDestinations-ms in 0.02968200 seconds ----------

Processing C:\Users\THM-RFedora\Desktop\kape-results\C\Users\THM-RFedora\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\5f7b5f1e01b83767.automaticDestinations-ms

Source file: C:\Users\THM-RFedora\Desktop\kape-results\C\Users\THM-RFedora\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\5f7b5f1e01b83767.automaticDestinations-ms

--- AppId information ---
  AppID: 5f7b5f1e01b83767
  Description: Quick Access

--- DestList information ---
  Expected DestList entries:  6
  Actual DestList entries:    6
  DestList version:           4

--- DestList entries ---
Entry #: 8
  MRU: 0
  Path: C:\Users\THM-RFedora\Desktop\kape-results\C\Users\THM-RFedora\NTUSER.DAT
  Pinned: False
  Created on:    2022-11-21 10:06:11
  Last modified: 2022-11-21 10:59:56
  Hostname: tryhatme-rfedor
  Mac Address: 02:0a:e5:8b:3b:33
  Interaction count: 1

--- Lnk information ---
  Absolute path: My Computer\C:\\\\\\\\


Entry #: 7
  MRU: 1
  Path: C:\Users\THM-RFedora\Downloads\RegistryExplorer.zip
  Pinned: False
  Created on:    2022-11-21 10:06:11
  Last modified: 2022-11-21 10:19:38
  Hostname: tryhatme-rfedor
  Mac Address: 02:0a:e5:8b:3b:33
  Interaction count: 1

--- Lnk information ---
  Absolute path: My Computer\C:\\\\


Entry #: 6
  MRU: 2
  Path: C:\Users\THM-RFedora\Downloads\kape.zip
  Pinned: False
  Created on:    2022-11-21 10:06:11
  Last modified: 2022-11-21 10:10:45
  Hostname: tryhatme-rfedor
  Mac Address: 02:0a:e5:8b:3b:33
  Interaction count: 1

--- Lnk information ---
  Absolute path: My Computer\C:\\\\


Entry #: 4
  MRU: 3
  Path: C:\Program Files (x86)\Windows Media Player\Skins\tophatsecret\continental.png
  Pinned: False
  Created on:    2022-11-19 11:45:46
  Last modified: 2022-11-19 12:10:21
  Hostname: tryhatme-rfedor
  Mac Address: 02:aa:8b:ff:d5:25
  Interaction count: 1

--- Lnk information ---
  Absolute path: My Computer\C:\\\\\


Entry #: 3
  MRU: 4
  Path: C:\Users\THM-RFedora\Desktop\WelcomeLetter.pdf
  Pinned: False
  Created on:    2022-11-18 12:17:58
  Last modified: 2022-11-19 12:01:24
  Hostname: tryhatme-rfedor
  Mac Address: 02:d1:ff:b2:6b:e9
  Interaction count: 2

--- Lnk information ---
  Absolute path: My Computer\C:\Users\\Desktop\


Entry #: 2
  MRU: 5
  Path: C:\Users\THM-RFedora\Desktop\Welcome Letter.pdf
  Pinned: False
  Created on:    2022-11-18 12:17:58
  Last modified: 2022-11-18 12:36:15
  Hostname: thm-windows-bas
  Mac Address: 02:d1:ff:b2:6b:e9
  Interaction count: 1

--- Lnk information ---
Error opening C:\Users\THM-RFedora\Desktop\kape-results\C\Users\THM-RFedora\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\5f7b5f1e01b83767.automaticDestinations-ms. Message: Object reference not set to an instance of an object.
System.NullReferenceException: Object reference not set to an instance of an object.
   at JLECmd.Program.ProcessAutoFile(String jlFile, Boolean q, String dt, Boolean fd, Boolean ld, Boolean wd)

Processing C:\Users\THM-RFedora\Desktop\kape-results\C\Users\THM-RFedora\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\9b9cdc69c1c24e2b.automaticDestinations-ms

Source file: C:\Users\THM-RFedora\Desktop\kape-results\C\Users\THM-RFedora\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\9b9cdc69c1c24e2b.automaticDestinations-ms

--- AppId information ---
  AppID: 9b9cdc69c1c24e2b
  Description: Notepad 64-bit

--- DestList information ---
  Expected DestList entries:  1
  Actual DestList entries:    1
  DestList version:           4

--- DestList entries ---
Entry #: 1
  MRU: 0
  Path: C:\Users\THM-RFedora\Desktop\launchcode.txt
  Pinned: False
  Created on:    2022-11-19 11:45:46
  Last modified: 2022-11-19 12:12:35
  Hostname: tryhatme-rfedor
  Mac Address: 02:aa:8b:ff:d5:25
  Interaction count: 2

--- Lnk information ---
  Absolute path: My Computer\C:\Users\\Desktop\



---------- Processed C:\Users\THM-RFedora\Desktop\kape-results\C\Users\THM-RFedora\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\9b9cdc69c1c24e2b.automaticDestinations-ms in 0.02990890 seconds ----------

Processing C:\Users\THM-RFedora\Desktop\kape-results\C\Users\THM-RFedora\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\abcfe3302b00eeed.automaticDestinations-ms

Source file: C:\Users\THM-RFedora\Desktop\kape-results\C\Users\THM-RFedora\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\abcfe3302b00eeed.automaticDestinations-ms

--- AppId information ---
  AppID: abcfe3302b00eeed
  Description: Unknown AppId

--- DestList information ---
  Expected DestList entries:  0
  Actual DestList entries:    0
  DestList version:           0

  There are more items in the Directory (-1) than are contained in the DestList (0). Use --withDir to view/export them

--- DestList entries ---

** There are more items in the Directory (-1) than are contained in the DestList (0). Use --WithDir to view them **

---------- Processed C:\Users\THM-RFedora\Desktop\kape-results\C\Users\THM-RFedora\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\abcfe3302b00eeed.automaticDestinations-ms in 0.01944480 seconds ----------

Processing C:\Users\THM-RFedora\Desktop\kape-results\C\Users\THM-RFedora\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\f01b4d95cf55d32a.automaticDestinations-ms

Source file: C:\Users\THM-RFedora\Desktop\kape-results\C\Users\THM-RFedora\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\f01b4d95cf55d32a.automaticDestinations-ms

--- AppId information ---
  AppID: f01b4d95cf55d32a
  Description: Windows Explorer Windows 8.1

--- DestList information ---
  Expected DestList entries:  11
  Actual DestList entries:    11
  DestList version:           4

--- DestList entries ---
Entry #: 1
  MRU: 0
  Path: knownfolder:{754AC886-DF64-4CBA-86B5-F7FBF4FBCEF5} ==> ThisPCDesktopFolder
  Pinned: True
  Created on:    2021-03-11 09:47:11
  Last modified: 2022-11-21 11:00:19
  Hostname: ec2amaz-s9rllhp
  Mac Address: 0e:f8:30:d0:72:3f
  Interaction count: 12

--- Lnk information ---
  Absolute path: My Computer\Desktop


Entry #: 11
  MRU: 1
  Path: C:\Users\THM-RFedora\Desktop\kape-results\C\Users\THM-RFedora
  Pinned: False
  Created on:    2022-11-21 10:06:11
  Last modified: 2022-11-21 10:59:56
  Hostname: tryhatme-rfedor
  Mac Address: 02:0a:e5:8b:3b:33
  Interaction count: 1

--- Lnk information ---
  Absolute path: My Computer\C:\\\\\\\


Entry #: 10
  MRU: 2
  Path: C:\Users\THM-RFedora\Downloads\RegistryExplorer\RegistryExplorer
  Pinned: False
  Created on:    2022-11-21 10:06:11
  Last modified: 2022-11-21 10:20:03
  Hostname: tryhatme-rfedor
  Mac Address: 02:0a:e5:8b:3b:33
  Interaction count: 1

--- Lnk information ---
  Absolute path: My Computer\C:\Users\\Downloads\\


Entry #: 9
  MRU: 3
  Path: C:\Users\THM-RFedora\Downloads\RegistryExplorer
  Pinned: False
  Created on:    2022-11-21 10:06:11
  Last modified: 2022-11-21 10:20:03
  Hostname: tryhatme-rfedor
  Mac Address: 02:0a:e5:8b:3b:33
  Interaction count: 1

--- Lnk information ---
  Absolute path: My Computer\C:\Users\\Downloads\


Entry #: 8
  MRU: 4
  Path: C:\Users\THM-RFedora\Downloads\kape\KAPE
  Pinned: False
  Created on:    2022-11-21 10:06:11
  Last modified: 2022-11-21 10:11:54
  Hostname: tryhatme-rfedor
  Mac Address: 02:0a:e5:8b:3b:33
  Interaction count: 1

--- Lnk information ---
  Absolute path: My Computer\C:\Users\\Downloads\\


Entry #: 7
  MRU: 5
  Path: C:\Users\THM-RFedora\Downloads\kape
  Pinned: False
  Created on:    2022-11-21 10:06:11
  Last modified: 2022-11-21 10:11:54
  Hostname: tryhatme-rfedor
  Mac Address: 02:0a:e5:8b:3b:33
  Interaction count: 1

--- Lnk information ---
  Absolute path: My Computer\C:\Users\\Downloads\


Entry #: 5
  MRU: 6
  Path: C:\Program Files (x86)\Windows Media Player\Skins\tophatsecret
  Pinned: False
  Created on:    2022-11-18 12:17:58
  Last modified: 2022-11-19 12:10:21
  Hostname: thm-windows-bas
  Mac Address: 02:d1:ff:b2:6b:e9
  Interaction count: 3

--- Lnk information ---
  Absolute path: My Computer\C:\\\\


Entry #: 6
  MRU: 7
  Path: C:\Program Files (x86)\Windows Media Player\Skins
  Pinned: False
  Created on:    2022-11-18 12:17:58
  Last modified: 2022-11-18 12:40:41
  Hostname: thm-windows-bas
  Mac Address: 02:d1:ff:b2:6b:e9
  Interaction count: 1

--- Lnk information ---
  Absolute path: My Computer\C:\\\


Entry #: 2
  MRU: 8
  Path: knownfolder:{FDD39AD0-238F-46AF-ADB4-6C85480369C7} ==> Documents
  Pinned: True
  Created on:    2021-03-11 09:47:11
  Last modified: 2022-11-18 12:38:00
  Hostname: ec2amaz-s9rllhp
  Mac Address: 0e:f8:30:d0:72:3f
  Interaction count: 4

--- Lnk information ---
  Absolute path: My Computer\Documents


Entry #: 4
  MRU: 9
  Path: knownfolder:{33E28130-4E1E-4676-835A-98395C3BC3BB} ==> Pictures
  Pinned: True
  Created on:    2021-03-11 09:47:11
  Last modified: 2021-03-11 09:55:31
  Hostname: ec2amaz-s9rllhp
  Mac Address: 0e:f8:30:d0:72:3f
  Interaction count: 3

--- Lnk information ---
  Absolute path: My Computer\Pictures


Entry #: 3
  MRU: 10
  Path: knownfolder:{374DE290-123F-4565-9164-39C4925E467B} ==> Downloads
  Pinned: True
  Created on:    2021-03-11 09:47:11
  Last modified: 2021-03-11 09:55:31
  Hostname: ec2amaz-s9rllhp
  Mac Address: 0e:f8:30:d0:72:3f
  Interaction count: 3

--- Lnk information ---
  Absolute path: My Computer\Downloads



---------- Processed C:\Users\THM-RFedora\Desktop\kape-results\C\Users\THM-RFedora\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\f01b4d95cf55d32a.automaticDestinations-ms in 0.18639720 seconds ----------

Processing C:\Users\THM-RFedora\Desktop\kape-results\C\Users\THM-RFedora\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\f065ac336abcaa3e.automaticDestinations-ms

Source file: C:\Users\THM-RFedora\Desktop\kape-results\C\Users\THM-RFedora\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\f065ac336abcaa3e.automaticDestinations-ms

--- AppId information ---
  AppID: f065ac336abcaa3e
  Description: Unknown AppId

--- DestList information ---
  Expected DestList entries:  1
  Actual DestList entries:    1
  DestList version:           4

--- DestList entries ---
Entry #: 1
  MRU: 0
  Path: C:\Users\THM-RFedora\Desktop\WelcomeLetter.pdf
  Pinned: False
  Created on:    2022-11-18 10:39:43
  Last modified: 2022-11-19 12:01:24
  Hostname: thm-windows-bas
  Mac Address: 02:d1:ff:b2:6b:e9
  Interaction count: 3

--- Lnk information ---
  Absolute path: My Computer\C:\Users\\Desktop\



---------- Processed C:\Users\THM-RFedora\Desktop\kape-results\C\Users\THM-RFedora\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\f065ac336abcaa3e.automaticDestinations-ms in 0.05163510 seconds ----------

Processing C:\Users\THM-RFedora\Desktop\kape-results\C\Users\THM-RFedora\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\28c8b86deab549a1.customDestinations-ms

Source file: C:\Users\THM-RFedora\Desktop\kape-results\C\Users\THM-RFedora\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\28c8b86deab549a1.customDestinations-ms

--- AppId information ---
AppID: 28c8b86deab549a1, Description: Internet Explorer 8.0.7600.16385 / 9
--- DestList information ---
  Entries:  1

  Entry #: 0, lnk count: 3 Rank: 1.4013E-45

--- Lnk #0 information ---
  Lnk target created:  2019-10-09 06:17:12
  Lnk target modified: 2019-10-09 06:17:12
  Lnk target accessed: 2019-10-09 06:17:12

  Absolute path: My Computer\C:\Program Files\\

--- Lnk #1 information ---
  Lnk target created:  2019-10-09 06:17:12
  Lnk target modified: 2019-10-09 06:17:12
  Lnk target accessed: 2019-10-09 06:17:12

  Absolute path: My Computer\C:\Program Files\\

--- Lnk #2 information ---
  Lnk target created:  2019-10-09 06:17:12
  Lnk target modified: 2019-10-09 06:17:12
  Lnk target accessed: 2019-10-09 06:17:12

  Absolute path: My Computer\C:\Program Files\\



---------- Processed C:\Users\THM-RFedora\Desktop\kape-results\C\Users\THM-RFedora\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\28c8b86deab549a1.customDestinations-ms in 0.04525510 seconds ----------

Processed 8 out of 9 files in 2.1438 seconds

Failed files
  C:\Users\THM-RFedora\Desktop\kape-results\C\Users\THM-RFedora\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\5f7b5f1e01b83767.automaticDestinations-ms ==> (Object reference not set to an instance of an object.)

--- DestList entries ---
Entry #: 1
  MRU: 0
  Path: C:\Users\THM-RFedora\Desktop\launchcode.txt
  Pinned: False
  Created on:    2022-11-19 11:45:46
  Last modified: 2022-11-19 12:12:35
  Hostname: tryhatme-rfedor
  Mac Address: 02:aa:8b:ff:d5:25
  Interaction count: 2

using autopsy tool > search web history > keyword search > substring match > pastebin

https://pastebin.com/1FQASAav

```


A text file was created in the Desktop folder. How many times was this file opened?

![[Pasted image 20230430163125.png]]

*2*

When was the text file from the previous question last modified? (MM/DD/YYYY HH:MM)  

*11/19/2022 12:12*

The contents of the file were exfiltrated to pastebin.com. What is the generated URL of the exfiltrated data?  

![[Pasted image 20230430163425.png]]

	*https://pastebin.com/1fqasaav *

What is the string that was copied to the pastebin URL?  

![[Pasted image 20230430163653.png]]

*ne7AIRhi3PdESy9RnOrN*

### Conclusion

At this point, we already have a good idea of what happened. The malicious threat actor was able to successfully find and exfiltrate data. While we could not determine who this person is, it is clear that they knew what they wanted and how to get it.

I wonder what's so important that they risked accessing the machine in-person... I guess we'll never know.

Anyways, you did good, kid. I guess it was too easy for you, huh?

Answer the questions below

Let's see if you can handle the next one.

Question Done


[[Olympus]]