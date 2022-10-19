---
To learn key attack vectors used by hackers and how to protect yourself using different hardening techniques.
---

![](https://tryhackme-images.s3.amazonaws.com/room-icons/efef926dddd6aa1e30d6558cfa5968e6.png)

### Introduction 

The room aims to teach basic concepts required to harden a workstation coupled with knowledge of services/software/applications that may result in hacking a computer or data breach.
Learning Objectives

Identity & access management.
Network management.
Application management.
Storage & Compute.
Importance of updating Windows.
Cheat sheet for hardening Windows.

Connecting to the Machine

We will be using Windows 10 as a development/test machine throughout the room with the following credentials:

    Machine IP: 10.10.118.42
    Username: Harden
    Password: harden

You can start the virtual machine in split screen view by clicking Start Machine. Alternatively, you can connect with the VM using the above credentials through Remote Desktop.

   Image for RDP
Prerequisites

Before starting this room, go through the following already developed rooms for understanding the Windows fundamentals:

    Windows Fundamentals 1 (Windows desktop, the NTFS file system, UAC, the Control Panel)
    Windows Fundamentals 2 (System Configuration, UAC Settings, Resource Monitoring, the Windows Registry)
    Windows Fundamentals 3 (Microsoft tools that help keep the device secure, such as Windows Updates, Windows Security, BitLocker)

Follow along with the steps described in upcoming tasks. Let's begin.

### Understanding General Concepts 

Services

Windows Services create and manage critical functions such as network connectivity, storage, memory, sound, user credentials, and data backup and runs automatically in the background. These services are managed by the Service Control Manager panel and divided into three categories, i.e. Local, Network & System. Many applications like browsers and anti-virus software can also run their services for a seamless user experience.

Type services.msc in the Run window to access Windows services.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/508f1714a93326335f11c9f9804582a2.png)

Windows Registry 

The Windows registry is a unified container database that stores configurational settings, essential keys and shared preferences for Windows and third-party applications. Usually, on the installation of most applications, it uses a registry editor for storing various states of the application. For example, suppose an application (malicious or normal) wants to execute itself during the computer boot-up process; In that case, it will store its entry in the Run & Run Once key.

Usually, a malicious program makes undesired changes in the registry editor and tries to abuse its program or service as part of system routine activities. It is always recommended to protect the registry editor by limiting its access to unauthorised users.

Type regedit in the Run dialogue or taskbar search to access the registry editor.

Image for Accessing Registry

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/f10675954519d7470106a15273aeaa7f.png)

Event Viewer
Event Viewer is an app that shows log details about all events occurring on your computer, including driver updates, hardware failures, changes in the operating system, invalid authentication attempts and application crash logs. Event Viewer receives notifications from different services and applications running on the computer and stores them in a centralised database. 
Hackers and malicious actors access Event Viewer to increase their attack surface and enhance the target system's profiling. Event categories are as below:

    Application: Records events of system components.
    System: Records events of already installed programs.
    Security: Logs events related to security and authentication etc.

	We can access Event Viewer by typing eventvwr in the Run window. The default location for storing events is C:\WINDOWS\system32\config\folder in the attached VM (10.10.118.42).

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/3fb4825b43009e27d7217c49d2a54e77.png)

Telemetry

Telemetry is a data collection system used by Microsoft to enhance the user experience by preemptively identifying security and functional issues in software. An application seamlessly shares data (crash logs, application-specific) with Microsoft to improve the user experience for future releases.  

Telemetry functionality is achieved by Universal Telemetry Client (UTC) services available in Windows and runs through diagtrack.dll. Contents acquired through telemetry service are stored encrypted in a local folder %ProgramData%\Microsoft\Diagnosis and sent to Microsoft after 15 minutes or so.

We can access The DiagTrack through the Services console in Windows 10.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/4798e8d5fcae725891dd0d917da72a71.png)

In subsequent tasks, we will harden Windows 10 through various techniques at the User, Network, Application & Storage levels.

![[Pasted image 20221018205230.png]]

What is the startup type of App Readiness service in the services panel?
*Manual*

![[Pasted image 20221018205413.png]]

Open Registry Editor and find the key “tryhackme”. What is the default value of the key? 
You can use the Find Option in Registry Editor
*{THM_REG_FLAG}*

![[Pasted image 20221018210443.png]]
![[Pasted image 20221018210509.png]]
![[Pasted image 20221018210530.png]]

Open the Diagnosis folder and go through the various log files. Can you find the flag?
*{THM_1000710}*

![[Pasted image 20221018210701.png]]
Open the Event Viewer and play with various event viewer filters like Information, Error, Warning etc. Which error type has the maximum number of logs?

### Identity & Access Management 

Standard vs Admin Account 
Identity and access management involves employing best practices to ensure that only authenticated and authorised users can access the system. There are two types of accounts in Windows, i.e. Admin and Standard Account. Per best practice, the Admin account should only be used to carry out tasks like software installation and accessing the registry editor, service panel, etc. Routine functions like access to regular applications, including Microsoft Office, browser, etc., can be allowed to standard accounts. Go to Control Panel > User Accounts to create standard or administrator accounts.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/9a52c8c09ea562fc4003da40cc87a229.png)

In either case, a user can authenticate themselves on the system through a password; however, Windows 10 has introduced a new feature called Windows Hello, which allows authenticating someone based on “something you have, something you know or something you are”. 
To access accounts and select the sign-in option, go to Settings > Accounts > Sign-in Options.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/51fff821ccc3b7e21698a6160df4a96b.png)

User Account Control (UAC)
User Account Control (UAC) is a feature that enforces enhanced access control and ensures that all services and applications execute in non-administrator accounts. It helps mitigate malware's impact and minimises privilege escalation by [bypassing UAC](https://tryhackme.com/room/bypassinguac). Actions requiring elevated privileges will automatically prompt for administrative user account credentials if the logged-in user does not already possess these.
For example, installing device drivers or allowing inbound connections through Windows Firewall requires more permissions than already available privileges for a standard user. We have covered the topic in detail in Windows Fundamental 1.

As a principle, always follow the Principle of Least Privilege, which states that (Per [CISA](https://www.cisa.gov/uscert/bsi/articles/knowledge/principles/least-privilege#:~:text=The%20Principle%20of%20Least%20Privilege%20states%20cthat%20a%20subject%20should,should%20not%20have%20that%20right)) “a subject should be given only those privileges needed for it to complete its task. If a subject does not need an access right, the subject should not have that right”.
To access UAC, go to Control Panel -> User Accounts and click on Change User Account Control Setting.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/5e5609be5a55c30aa42a27801c5362c4.png)

Keep the notification level "Always Notify" in the User Account Control Settings.

Local Policy and Group Policies Editor
Group Policy Editor is a built-in interactive tool by Microsoft that allows to configure and implement local and group policies. We mainly use this feature when part of a network; however, we can also use it for a workstation to limit the execution of vulnerable extensions, set password policies, and other administrative settings.
Note: The feature is not available in Windows Home but only in the Pro and Enterprise versions.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/e459dd6e94f893a5db56ba8c6d2ced94.png)

Password Policies

One primary use of a local policy editor is to ensure complex and strong passwords for user accounts. For example, we can design password policies to maximise our security:

    Passwords must contain both uppercase and lowercase characters.
    Check passwords against leaked or already hacked databases or a dictionary of compromised passwords.
    In case of 6 failed login attempts within 15 minutes, the account will remain locked for at least 1 hour.

We can access Password policies through the Local group policy editor.
Go to Security settings > Account Policies > Password policy 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/e159d0daed7b8b8f217cbcd85d10c0b2.png)

Setting A Lockout Policy
To protect your system password from being guessed by an attacker, we can set out a lockout policy so the account will automatically lock after certain invalid attempts. To set a lockout policy, go to Local Security Policy > Windows Settings > Account Policies > Account Lockout Policy and configure values to lock out hackers after three invalid attempts.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/b4364de2e962d48755d37d254dddf0f9.png)


Find the name of the Administrator Account of the attached VM.
*Harden*

Go to the User Account Control Setting Panel (Control Panel > All Control Panel Items > User Accounts). What is the default level of Notification? 
*Always Notify*

How many standard accounts are created in the VM?
*0*

###  Network Management 

Windows Defender Firewall
Windows Defender Firewall is a built-in application that protects computers from malicious attacks and blocks unauthorised traffic through inbound and outbound rules or filters. As an analogy, this is equivalent to “who is coming in and going out of your home”.
Malicious actors abuse Windows Firewall by bypassing existing rules. For example, if we have configured the firewall to allow incoming connections, hackers will try to manipulate the functionality by creating a remote connection to the victim's computer.
You can see more details about Windows Firewall Configuration [here](https://tryhackme.com/room/redteamfirewalls).
We can access Windows Defender Firewall by accessing WF.msc in the Run dialogue.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/0825e4e702f7d4c9e0b5c4df81878fe4.png)

As mentioned in the Windows Fundamentals room, it has three main profiles Domain, Public and Private.  The Private profile must be activated with "Blocked Incoming Connections" while using the computer at home. 
View detailed settings for each profile by clicking on Windows Defender Firewall Properties.
Whenever possible, enable the Windows Defender Firewall default settings. For blocking all the incoming traffic, always configure the firewall with a 'default deny' rule before making an exception rule that allows more specific traffic.
 
Disable unused Networking Devices
Network devices like routers, ethernet cards, WiFI adapters etc., enable data sharing between computers. If the device is improperly configured or not being used by the owner, it is recommended to disable the interface so that threat actors cannot access them and use them for data retrieval from the victim's computer.
To disable the unused Networking Devices, go to the Control panel > System and Security Setting > System > Device Manager and disable all the unused Networking devices.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/381409d62e6ebaf2c542849dc941f58c.png)


Disable SMB protocol
SMB is a file-sharing protocol exploited by hackers in the wild. The protocol is primarily used for file sharing in a network; therefore, you must disable the protocol if your computer is not part of a network by issuing the [following](https://docs.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3) command in PowerShell.

```

Administrator - Windows PowerShell

           
user@machine$ Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
Path          :
Online        : True
RestartNeeded : False


```

 Protecting Local Domain Name System (DNS) 
The domain name system (DNS) is a naming system that translates Fully Qualified Domain Names (FQDN) into IP addresses. If the attacker places himself in the middle, he may intercept and manipulate DNS requests and point them to attacker-controlled systems since DNS replies are neither authenticated nor encrypted.
The hosts file located in Windows acts like local DNS and is responsible for resolving hostnames to IP addresses. Malicious actors try to edit the file's content to reroute traffic to their command and control server.
			
	The hosts file is located at C:\Windows\System32\Drivers\etc\hosts.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/011d5a2f065508cd740f211aa7a478ad.png)

Mitigating Address Resolution Protocol Attack  
The address resolution protocol resolves MAC addresses from given IP addresses saved in the workstations ARP cache. The ARP offers no authentication and accepts responses from any user in the network. An attacker can flood target systems with crafted ARP responses, which point to an attacker-controlled machine and put him in the middle of communication between the targeted hosts.
You can check ARP entries using the command arp -a in the command prompt. 

```

Command Prompt

           
user@machine$ arp -a
Interface: 192.168.231.2 --- 0x5
  Internet Address      Physical Address      Type
  192.168.231.255       ff-ff-ff-ff-ff-ff     static
  224.0.0.2             01-00-5e-00-00-02     static
  224.0.0.22            01-00-5e-00-00-16     static
  224.0.0.251           01-00-5e-00-00-fb     static
  224.0.0.252           01-00-5e-00-00-fc     static
  239.255.255.250       01-00-5e-7f-ff-fa     static
        
```

The table contains MAC addresses in the middle and IP addresses in the left.  If the table includes a MAC mapped to two IPs, you are probably susceptible to an ARP poisoning attack.
To clear the ARP cache and prevent the attack, issue the command arp -d.

Preventing Remote Access to Machine
Remote access provides a way to connect to other computers/networks even located at a different geographical location for file sharing and remotely make changes to a workstation. Microsoft has developed a Remote Desktop Protocol (RDP) for connecting with other computers. Hackers have exploited the protocol in the past, like the famous [Blue Keep vulnerability](https://en.wikipedia.org/wiki/BlueKeep), to gain unauthorised access to the target system.
We must disable remote access (if not required) by going to settings > Remote Desktop. Do not attempt this in VM attached to this room.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/340bfd9d93e9a44e2f244fc1d2d302ea.png)

![[Pasted image 20221018220146.png]]


Open Windows Firewall and click on Monitoring in the left pane - which of the following profiles is active? Domain, Private, Public?
*Private*
![[Pasted image 20221018220008.png]]
![[Pasted image 20221018220023.png]]

Find the IP address resolved for the website tryhack.me in the Virtual Machine as per the local hosts file.
*192.168.1.140*

![[Pasted image 20221018220248.png]]

Open the command prompt and enter arp -a. What is the Physical address for the IP address 255.255.255.255?
*ff-ff-ff-ff-ff-ff*

### Application Management 

Trusted Application Store
Microsoft Store offers a complete range of applications (games, utilities) and allows downloading non-malicious files through a single click. Malicious actors bind legitimate software with trojans and viruses and upload it on the internet to infect and access the victim's computer. Therefore, downloading applications from the Microsoft Store ensures that the downloaded software is not malicious. 
We can access Microsoft Application Store by typing ms-windows-store in the Run dialogue.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/55413d1781c530e53fa175b3e2fadb84.png)

Safe App Installation
Only allow installation of applications from the Microsoft Store on your computer.  
Go to Setting > Select Apps and Features and then select The Microsoft Store only. 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/adf2295862b9d01aec5d967aaa9c6433.png)

Malware Removal through Windows Defender Anti Virus
Windows Defender Anti Virus is a complete anti-malware program capable of identifying malicious programs and taking remedial measures like quarantine. The program used to have an entire Graphical User Interface; however, Windows 10 and newer versions manage the same through Windows Security Centre. Windows Defender primarily offers four main functionalities:

    Real-time protection - Enables periodic scanning of the computer.
    Browser integration - Enables safe browsing by scanning all downloaded files, etc.
    Application Guard - Allows complete web session sandboxing to block malicious websites or sessions to make changes in the computer.
    Controlled Folder Access - Protect memory areas and folders from unwanted applications.

You have already learned about this in Windows Fundamentals 3
Microsoft Office Hardening
Microsoft Office Suite is one of the most widely used application suites in all sectors, including financial, telecom, education, etc. Malicious actors abuse its functionality through macros, Flash applets, object linking etc., to achieve Remote Code Execution. 
Hardening of Microsoft Office may vary from person to person as legitimate functionality of Microsoft Office is exploited to gain access. For example, disabling macros in a University may be helpful as no one uses it; however, banks cannot disable macros as they heavily rely on complex invoices and formulas through macros. 
The attached VM contains a batch file based on best practices and [Microsoft Attack Surface Reduction Rules](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide) for hardening Microsoft Office. To execute the script, right-click on the file office.bat on Desktop and Run as Administrator.

```

Command Prompt - Administrator

           
harden@tryhackme$ office.bat (Work in Progress)
Microsoft Office Hardened Successfully.

```

AppLocker
AppLocker is a recently introduced feature that allows users to block specific executables, scripts, and installers from execution through a set of rules. We can easily configure them on a single PC or network through a GUI by the following method:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/7809f59c32041093a48fb49e3dea1891.png)

Now, we will see how to add a rule through AppLocker to block a file based on its publisher name.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/64f6885a19f1ea54250717a3af70efc0.gif)

Browser (MS Edge)
Microsoft Edge is a built-in browser available on Windows machines based on Chromium, inline with Google Chrome and Brave. The browser often acts as an entry point to a system for further pivoting and lateral movement. It is therefore of utmost importance to block and mitigate critical attacks carried out through a browser that include ransomware, ads, unsigned application downloads and trojans. 

Protecting the Browser through Microsoft Smart Screen
Microsoft SmartScreen helps to protect you from phishing/malware sites and software when using Microsoft Edge. It helps to make informed decisions for downloads and lets you browse safely in Microsoft Edge by:
Displaying an alert if you are visiting any suspicious web pages.
Vetting downloads by checking their hash, signature etc against a malicious software database.
Protecting against phishing and malicious sites by checking visited websites against a threat intelligence database.

To turn on the Smart Screen, go to Settings > Windows Security > App and Browser Control > Reputation-based Protection. Scroll down and turn on the SmartScreen option.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/79b7490c1617095a385f943342d13176.png)

Open Microsoft Edge, go to Settings and then click “Privacy, Search and Services” - Set "Tracking prevention" to Strict to avoid tracking through ads, cookies etc.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/b7e3bb52cc6ea640aa487f6124dcbb72.png)

![[Pasted image 20221018223830.png]]

![[Pasted image 20221018224245.png]]

Windows Defender Antivirus is configured to exclude a particular extension from scanning. What is the extension?
*.ps*

A Word document is received from an unknown email address. It is best practice to open it immediately on your personal computer (yay/nay).
*nay*

What is the flag you received after executing the Office Hardening Batch file?
*{THM_1101110}*

### Storage Management 

Data Encryption Through BitLocker
Encryption of the computer is one of the most vital things to which we usually pay little attention. The worst nightmare is that someone gets unfettered access to your devices' data. Encryption ensures that you or someone you share the recovery key with can access the stored content.
Microsoft, for its business edition of Windows, utilises the encryption tools by BitLocker. Let us have a quick look at how one can ensure to protect the data through BitLocker encryption features available on the Home Editions of Windows 10. You have already read about it here ([Task 8](https://tryhackme.com/room/windowsfundamentals3xzx)).
Go to Start > Control Panel > System and Security > BitLocker Drive Encryption. You can easily see if the option to BitLocker Drive Encryption is 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/e36ecbbe7b00820e10c38199baa357c5.png)


A trusted Platform Module chip TPM is one of the basic requirements to support BitLocker device encryption. Keeping the BitLocker recovery key in a secure place (preferably not on the same computer) is imperative. You can read more about BitLocker Recovery [here](https://support.microsoft.com/en-us/windows/finding-your-bitlocker-recovery-key-in-windows-6b71ad27-0b89-ea08-f143-056f5ab347d6).
Note: The BitLocker feature is not available in the attached VM.

Windows Sandbox
To run applications safely, we can use a temporary, isolated, lightweight desktop environment called Windows Sandbox. We can install software inside this safe environment, and this software will not be a part of our host machine, it will remain sandboxed. Once the Windows Sandbox is closed, everything, including files, software, and states will be deleted. We would require Virtualisation enabled on our OS to run this feature. We cannot try this in the attached VM but the steps for enabling the Sandbox feature are as below:
Click Start > Search for 'Windows Features' and turn it on > Select Sandbox > Click OK to restart 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/42ad322953f66fdd2d911f331b54a49a.png)

If you want to close the Sandbox, click the close button, and it will disappear. Opening suspicious files in a Windows Sandbox before blindly executing them in your base OS is recommended.

Windows Secure Boot
﻿Secure boot – an advanced security standard - checks that your system is running on trusted hardware and firmware before booting, which ensures that your system boots up safely while preventing unauthorised software access from taking control of your PC, like malware.
You are already in a secure boot environment if you run a modern PC with Unified Extensible Firmware Interface UEFI (the best replacement for BIOS) or Windows 10. You can check the status of the secure boot by following:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/7e86a928fcad06fc3a30d1e69620fa45.png)

The incredible thing is that you do not need to enable or install it as it works silently in the background. Windows allows you to disable these features, which is not recommended.  You can enable Secure boot from BIOS settings (if disabled).
https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/disabling-secure-boot?view=windows-11
Enable File Backups
The last option, but certainly not the least important one to prevent losing irreplaceable and critical files is to enable file backups. Despite all the above techniques, if you somehow lose essential data/files, you can recover the loss by restoring it, if you have a file backup option. Creating file backups is the best option to avoid disasters like malware attacks or hardware failure. You can enable the file backup option through  Settings > Update and Security > Backup:- 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/c2e8a9441b14db952c6771518efd047f.png)

Therefore, the most convenient option is enabling it from the 'File History' option - a built-in functionality of Windows 10 and 11.

![[Pasted image 20221018225515.png]]

A security engineer has misconfigured the attached VM and stored a BitLocker recovery key in the same computer. Can you read the last six digits of the recovery key?
Look in the Documents folder.
*377564*


How many characters does the BitLocker recovery key have in the attached VM?
*48*
![[Pasted image 20221018225400.png]]
A backup file is placed on the Desktop of the attached VM. What is the extension of that file?
*.bkf*

### Updating Windows 

Hackers are continuously bypassing and exploiting Windows' legitimate features. You can see a list of Windows vulnerabilities by following [this](https://www.cvedetails.com/vulnerability-list/vendor_id-26/product_id-32238/Microsoft-Windows-10.html) link. The most critical part of hardening computers is enabling the Windows auto-updates.  
Click Start > Settings > Update & Security > Window Updates. 
This ensures that all the urgent security updates, if any, are installed immediately without causing any delay. It is most important because the quicker you apply the new Windows protection patch, the faster you can fix the potential vulnerabilities – to ensure the security from the latest known threats.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/ca26fa3afcbabf99ce1d98b0396659c6.png)

Remember, users who run the older Windows versions are always at greater risk and vulnerable to new security threats. So, be very careful about this. 

![[Pasted image 20221018230007.png]]

What is the CVE score for the vulnerability CVE ID CVE-2022-32230?
Require External Research (Link available in the task).
*7.8*

### Cheatsheet for Hardening Windows 

Is your system still at risk of a security breach?

The bottom line is that hardening is a never-ending process.  You can’t ever say that your job is done and your system is now fully protected; instead, we can try our best. In this regard, we must be active and smart-minded to participate in this continuing process. We must keep in mind [The defender’s dilemma](https://www.rand.org/pubs/research_reports/RR1024.html), which states that breaches are inevitable because defenders have to be right 100% of the time whereas attackers only have to be right once.

In this room, we have learned how to harden our computers at different levels (Identity, Network, Application & Storage). Below is a quick summary or cheatsheet for guidance during the hardening process:


![](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/dbbd403c6b1196904312c7b88f2514f2.png)

You can learn more about hardening Linux and Active Directory in our upcoming rooms. Stay tuned! And keep hardening machines.

[[Unified Kill Chain]]