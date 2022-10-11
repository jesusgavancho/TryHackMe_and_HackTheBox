---
Learn how to use NetworkMiner to analyse recorded traffic files and practice network forensics activities.
---

### Room Introduction 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/06fd84e8274b50cbe75e5a401b76eef8.png)

NetworkMiner is an open-source traffic sniffer, pcap handler and protocol analyser. Developed and still maintained by Netresec.


The official description;

 

"NetworkMiner is an open source Network Forensic Analysis Tool (NFAT) for Windows (but also works in Linux / Mac OS X / FreeBSD). NetworkMiner can be used as a passive network sniffer/packet capturing tool to detect operating systems, sessions, hostnames, open ports etc. without putting any traffic on the network. NetworkMiner can also parse PCAP files for off-line analysis and to regenerate/reassemble transmitted files and certificates from PCAP files.

 

NetworkMiner makes it easy to perform advanced Network Traffic Analysis (NTA) by providing extracted artefacts in an intuitive user interface. The way data is presented not only makes the analysis simpler, it also saves valuable time for the analyst or forensic investigator.

 

NetworkMiner has, since the first release in 2007, become a popular tool among incident response teams as well as law enforcement. NetworkMiner is today used by companies and organizations all over the world."


For this room, you will be expected to have basic Linux familiarity and Network fundamentals (ports, protocols and traffic data). We suggest completing the "Network Fundamentals" path before starting working in this room.


The room aims to provide a general network forensics overview and work with NetworkMiner to investigate captured traffic.


Note:  VMs attached to this challenge. You don't need SSH or RDP; the room provides a "Split View" feature.

Note: There are two different NetworkMiner versions are available in the attached VM. Use the required version according to the tasks.

Note: Exercise files are located in the folder on the desktop.


Open the tool folder and double click on the .exe file.

https://www.vx-underground.org/archive.html

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/d4127b0ac1fb94b0c6688a241649a262.png)

### Introduction to Network Forensics 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/0f127d2a0a68b47c4b39acebd1361de8.png)

Introduction to Network Forensics

 

Network Forensics is a specific subdomain of the Forensics domain, and it focuses on network traffic investigation. Network Forensics discipline covers the work done to access information transmitted by listening and investigating live and recorded traffic, gathering evidence/artefacts and understanding potential problems. 

Briefly, it is the action of recording packets of network traffic and creating investigatable sources and establishing a root–cause analysis of an event. The ultimate goal is to provide sufficient information to detect malicious activities, security breaches, policy/regulation compliance, system health and user behaviour.


The investigation process identifies communicated hosts in terms of time, frequency, protocol, application and data.


The investigation tries to answer the 5W;


    Who (Source IP and port)
    What (Data/payload)
    Where (Destination IP and port)
    When (Time and data)
    Why (How/What happened)

Note that the network evidence capture and investigation process should be systematic. Having enough data and the right timeline capture for a successful network forensics investigation is crucial.


Network Forensics Use Cases


The most common network forensics use cases are explained below;


    Network discovery: Discovering the network to overview connected devices, rogue hosts and network load. 

    Packets reassembling: Reassembling the packets to investigate the traffic flow. This use case is helpful in unencrypted traffic flows.

    Data leakage detection: Reviewing packet transfer rates for each host and destination address helps detect possible data leakage. 

    Anomaly and malicious activity detection: Reviewing overall network load by focusing on used ports, source and destination addresses, and data helps detect possible malicious activities along with vulnerabilities. This use case covers the correlation of indicators and hypotheses as well.

    Policy/Regulation compliance control: Reviewing overall network behaviour helps detect policy/regulation compliance.

Advantages of Network Forensics 


General advantages of network forensics are explained below;


    Availability of network-based evidence in the wild: Capturing network traffic is collecting evidence, so it is easier than other types of evidence collections such as logs and IOCs.

    Ease of data/evidence collection without creating noise: Capturing and working with network traffic is easier than investigating unfiltered events by EDRs, EPPs and log systems. Usually, sniffing doesn't create much noise, logs and alerts. The other thing is that network traffic is not destructible like logs and alerts generated by security systems.  

    It is hard to destroy the network evidence, as it is the transferred data: Since the evidence is the traffic itself, it is impossible to do anything without creating network noise. Still, it is possible to hide the artefacts by encrypting, tunnelling and manipulating the packets. So, the second fact is the challenge of this advantage. 

    Availability of log sources: Logs provide valuable information which helps to correlate the chain of events and support the investigation hypothesis. The majority of the EDRs, EPPs and network devices create logs by default. Having log files is easy if the attacker/threat/malware didn't erase/destroy them.

    It is possible to gather evidence for memory and non-residential malicious activities: The malware/threat might reside in the memory to avoid detection. However, the series of commands and connections live in the network. So it is possible to detect non-residential threats with network forensics tools and tactics.


Challenges of Network Forensics


General challenges of the network forensics are explained below;


    Deciding what to do: One of the most difficult challenges of network forensics is "Deciding what to do". There are several purposes of carving networks; SOC, IH/IR and Threat Hunting. Observing, trapping, catching, or stopping an anomalous activity is also possible. 

    Sufficient data/evidence collection on the network: One of the advantages of network forensics is "Ease of collecting evidence". However, the breadth of this concept poses a challenge. There are multiple points to consider in data/evidence collection.

    Short data capture: One of the challenges in data/evidence collection. Capturing all network activity is not applicable and operable. So, it is hard always to have the packet captures that covers pre, during and post-event. 

    The unavailability of full-packet capture on suspicious events: Continuously capturing, storing and processing full-packets costs time and resources. The inability to have full-packet captures for a long time creates time gaps between captures, resulting in missing a significant part of an event of interest. Sometimes NetFlow captures are used instead of full-packet captures to reduce the weight of having full-packet captures and increase the capture time. Note that full-packet captures provide full packet details and give the opportunity of event reconstruction, while NetFlow provides high-level summary but not data/payload details.

    Encrypted traffic: Encrypted data is another challenge of network forensics. In most cases, discovering the contents of the encrypted data is not possible. However, the encrypted data still can provide valuable information for the hypothesis like source and destination address and used services.

    GDPR and Privacy concerns in traffic recording: Capturing the traffic is the same as "recording everything on the wire"; therefore, this act should comply with GDPR and business-specific regulations (e.g. HIPAA, PCI DSS and FISMA ).

    Nonstandard port usage: One of the popular approaches in network forensics investigations is grabbing the low-hanging fruits in the first investigation step. Looking for commonly used patterns (like known ports and services used in enumeration and exploitation) is known as grabbing the low-hanging fruits. However, sometimes attackers/threats use nonstandard ports and services to avoid detection and bypass security mechanisms. Therefore sometimes, this ends up as a challenge of network forensics.

    Time zone issues: Using a common time zone is important for big-scale event investigation. Especially when working with multiple resources over different time zones, usage of different time zones create difficulties in event correlation.

    Lack of logs: Network forensics is not limited to investigating the network traffic data. Network devices and event logs are crucial in event correlation and investigation hypotheses. This fact is known by the attackers/threats as well; therefore these logs are often erased by them, in order to make the investigation more difficult.


Sources of Network Forensics Evidence


Capturing proper network traffic requires knowledge and tools. Usually, there is a single chance of gathering the live traffic as evidence. There are multiple evidence resources to gather network forensics data.


    TAPS
    InLine Devices
    SPAN Ports
    Hubs
    Switches
    Routers
    DHCP Servers
    Name Servers
    Authentication Servers
    Firewalls
    Web Proxies
    Central Log Servers
    Logs (IDS/IPS, Application, OS, Device)

Primary Purposes of Network Forensics 


There are two primary purposes in Network Forensics investigations.

 

    Security Operations (SOC): Daily security monitoring activities on system performance and health, user behaviour, and security issues.

    Incident Handling/Response and Threat Hunting: During/Post-incident investigation activities on understanding the reason for the incident, detecting malicious and suspicious activity, and investigating the data flow content.


Investigated Data Types in Network Forensics


There are three main data types investigated in Network Forensics

 

    Live Traffic
    Traffic Captures (full packet captures and network flows)
    Log Files

NetworkMiner is capable of processing and handling packet pictures and live traffic. Therefore, we will focus on live and captured traffic in this room. Both of these data sources are valuable for forensics investigations. 


Traffic investigation actions fall under network forensics's "Traffic Analysis" subdomain. However, the main purpose of the NetworkMiner is to investigate the overall flow/condition of the limited amount of traffic, not for a long in-depth live traffic investigation. Therefore we will focus on how to use NetworkMiner for this purpose. In-depth traffic and packet analysis will be covered in the rooms below;

    Wireshark
    Tcpdump (available soon!)
    Tshark (available soon!)

### What is NetworkMiner? 

NetworkMiner in a Nutshell


Capability	Description

Traffic sniffing
	It can intercept the traffic, sniff it, and collect and log packets that pass through the network.
Parsing PCAP files
	It can parse pcap files and show the content of the packets in detail.
Protocol analysis
	It can identify the used protocols from the parsed pcap file.
OS fingerprinting
	

It can identify the used OS by reading the pcap file. This feature strongly relies on Satori and p0f.
 File Extraction
	It can extract images, HTML files and emails from the parsed pcap file.
Credential grabbing
	It can extract credentials from the parsed pcap file.
Clear text keyword parsing
	It can extract cleartext keywords and strings from the parsed pcap file.


We are using NetworkMiner free edition in this room, but a Professional edition has much more features. You can see the differences between free and professional versions here.


Operating Modes


There are two main operating modes;


    Sniffer Mode: Although it has a sniffing feature, it is not intended to use as a sniffer. The sniffier feature is available only on Windows. However, the rest of the features are available in Windows and Linux OS. Based on experience, the sniffing feature is not as reliable as other features. Therefore we suggest not using this tool as a primary sniffer. Even the official description of the tool mentions that this tool is a "Network Forensics Analysis Tool", but it can be used as a "sniffer". In other words, it is a Network Forensic Analysis Tool with but has a sniffer feature, but it is not a dedicated sniffer like Wireshark and tcpdump. 

    Packet Parsing/Processing: NetworkMiner can parse traffic captures to have a quick overview and information on the investigated capture. This operation mode is mainly suggested to grab the "low hanging fruit" before diving into a deeper investigation.


Pros and Cons
 

As mentioned in the previous task, NetworkMiner is mainly used to gain an overview of the network. Before starting to investigate traffic data, let's look at the pros and cons of the NetworkMiner.

 

Pros

    OS fingerprinting
    Easy file extraction
    Credential grabbing
    Clear text keyword parsing
    Overall overview

Cons


    Not useful in active sniffing
    Not useful for large pcap investigation
    Limited filtering
    Not built for manual traffic investigation

 

Differences Between Wireshark and NetworkMiner

NetworkMiner and Wireshark have similar base features, but they separate in use purpose. Although main functions are identical, some of the features are much stronger for specific use cases.


The best practice is to record the traffic for offline analysis, quickly overview the pcap with NetworkMiner and go deep with Wireshark for further investigation.

Feature	NetworkMiner	Wireshark
Purpose	Quick overview, traffic mapping, and data extraction
	In-Depth analysis
GUI	✅
	✅
Sniffing	✅
	✅
Handling PCAPS	✅
	✅
OS Fingerprinting	✅
	❌
Parameter/Keyword Discovery	✅
	Manual
Credential Discovery	✅
	✅
File Extraction	✅
	✅
Filtering Options	Limited
	✅
Packet Decoding	Limited
	✅
Protocol Analysis	❌
	✅
Payload Analysis	❌
	✅
Statistical Analysis	❌
	✅
Cross-Platform Support	✅
	✅
Host Categorisation	✅
	❌
Ease of Management 	✅
	✅

### Tool Overview 1 

Landing Page

 This is the landing page of the NetworkMiner. Once you open the application, this screen loads up. 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/ce932d37ec0644050013046ccef1257e.png)

File Menu

The file menu helps you load a Pcap file or receive Pcap over IP. You can also drag and drop pcap files as well. 

NetworkMiner also can receive Pcaps over IP. This room suggests using NetworkMiner as an initial investigation tool for low hanging fruit grabbing and traffic overview. Therefore, we will skip receiving Pcaps over IP in this room. You can read on receiving Pcap over IP from [here](https://www.netresec.com/?page=Blog&month=2011-09&post=Pcap-over-IP-in-NetworkMiner) and [here](http://www.gavinhollinger.com/2016/10/pcap-over-ip-to-networkminer.html). 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/730b42f10b004ab423cabc40c350b35d.png)

Tools Menu

The tools menu helps you clear the dashboard and remove the captured data. 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/77151efd472783b4f933597eb39ab48b.png)

Help Menu

The help menu provides information on updates and the current version. 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/9ccc2a883ea966c168a974b3165956e5.png)

Case Panel

The case panel shows the list of the investigated pcap files. You can reload/refresh, view metadata details and remove loaded files from this panel.

Viewing metadata of loaded files;

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/44074972fae131e273adeee7a340c680.png)
![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/f767ec0200938b8ccf2fc986792a17af.png)
Hosts

The "hosts" menu shows the identified hosts in the pcap file. This section provides information on;

    IP address
    MAC address
    OS type
    Open ports
    Sent/Received packets
    Incoming/Outgoing sessions
    Host details

OS fingerprinting uses the Satori GitHub repo and p0f, and the MAC address database uses the mac-ages GitHub repo.

You can sort the identified hosts by using the sort menu. You can change the colour of the hosts as well. Some of the features (OSINT lookup) are available only in premium mode. The right-click menu also helps you to copy the selected value.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/6c79384af9d5e2aae2587b0bd76a2e85.png)

Sessions

The session menu shows detected sessions in the pcap file. This section provides information on;

    Frame number
    Client and server address
    Source and destination port
    Protocol
    Start time

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/0897d01e900bd9f1fb1b2ec9b54f06eb.png)

You can search for keywords inside frames with the help of the filtering bar. It is possible to filter specific columns of the session menu as well. This menu accepts four types of inputs;

    "ExactPhrase"
    "AllWords"
    "AnyWord"
    "RegExe"


DNS

The DNS menu shows DNS queries with details. This section provides information on;

    Frame number
    Timestamp
    Client and server
    Source and destination port 
    IP TTL
    DNS time
    Transaction ID and type
    DNS query and answer
    Alexa Top 1M

Some of the features (Alexa Top 1M) are available only in premium mode. The search bar is available here as well.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/8632f3f01269b805a1a8a7aeee76c14d.png)

Credentials

The credentials menu shows extracted credentials and password hashes from investigated pcaps. You can use Hashcat (GitHub) and John the Ripper (GitHub) to decrypt extracted credentials. NetworkMiner can extract credentials including;

    Kerberos hashes
    NTLM hashes
    RDP cookies
    HTTP cookies
    HTTP requests
    IMAP
    FTP
    SMTP
    MS SQL

The right-click menu is helpful in this part as well. You can easily copy the username and password values.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/888d7b45713c75d2eb8a1687d2b16e6b.png)



Use mx-3.pcap

What is the total number of frames?
*460*
![[Pasted image 20221011114913.png]]

How many IP addresses use the same MAC address with host 145.253.2.203?
*2*
![[Pasted image 20221011115302.png]]
![[Pasted image 20221011115409.png]]

How many packets were sent from host 65.208.228.223?
*72*
![[Pasted image 20221011120709.png]]
What is the name of the webserver banner under host 65.208.228.223?
*Apache*
![[Pasted image 20221011120750.png]]

Use mx-4.pcap
![[Pasted image 20221011120830.png]]
![[Pasted image 20221011120918.png]]

	What is the extracted username?
	*#B\Administrator*

What is the extracted password?
*NTLM Challenge: 136B077D942D9A63 - LAN Manager Response: 000000000000000000000000000000000000000000000000 - NTLM Response: FBFF3C253926907AAAAD670A9037F2A501010000000000000094D71AE38CD60170A8D571127AE49E00000000020004003300420001001E003000310035003600360053002D00570049004E00310036002D004900520004001E0074006800720065006500620065006500730063006F002E0063006F006D0003003E003000310035003600360073002D00770069006E00310036002D00690072002E0074006800720065006500620065006500730063006F002E0063006F006D0005001E0074006800720065006500620065006500730063006F002E0063006F006D00070008000094D71AE38CD601060004000200000008003000300000000000000000000000003000009050B30CECBEBD73F501D6A2B88286851A6E84DDFAE1211D512A6A5A72594D340A001000000000000000000000000000000000000900220063006900660073002F003100370032002E00310036002E00360036002E0033003600000000000000000000000000*

### Tool Overview 2 

Files

The file menu shows extracted files from investigated pcaps. This section provides information on;

    Frame number
    Filename
    Extension
    Size
    Source and destination address
    Source and destination port
    Protocol
    Timestamp
    Reconstructed path
    Details

Some features (OSINT hash lookup and sample submission) are available only in premium mode. The search bar is available here as well. The right-click menu is helpful in this part as well. You can easily open files and folders and view the file details in-depth.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/d0cb3d76e3dce6139611f8a451edee67.png)
Images

The file menu shows extracted images from investigated pcaps. The right-click menu is helpful in this part as well. You can open files and zoom in & out easily.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/77a5139e9cd949c57105bd42aab2d741.png)

Once you hover over the image, it shows the file's detailed information (source & destination address and file path).

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/9a6ad0aa93c7c700736487a1707ef44b.png)

Parameters

The file menu shows extracted parameters from investigated pcaps. This section provides information on;

    Parameter name
    Parameter value
    Frame number
    Source and destination host
    Source and destination port
    Timestamp
    Details

The right-click menu is helpful in this part as well. You can copy the parameters and values easily.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/f07b50304faeb1767c49a9e002622f31.png)

Keywords

The file menu shows extracted keywords from investigated pcaps. This section provides information on;

    Frame number
    Timestamp
    Keyword
    Context
    Source and destination host
    source and destination port

How to filter keywords;

    Add keywords
    Reload case files!

Note: You can filter multiple keywords in this section; however, you must reload the case files after updating the search keywords. Keyword search investigates all possible data in the processed pcaps.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/ab513599f2a948ad4e4e8f634f2cb6fd.png)

Messages

The messages menu shows extracted emails, chats and messages from investigated pcaps. This section provides information on;

    Frame number
    Source and destination host 
    Protocol
    Sender (From)
    Receiver (To)
    Timestamp
    Size

Once you filter the traffic and get a hit, you will discover additional details like attachments and attributes on the selected message. Note that the search bar is available here as well. The right-click menu is available here. You can use the built-in viewer to investigate overall information and the "open file" option to explore attachments.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/3e4dfffef8d0518ffbfe152275aab8c6.png)

Anomalies

The anomalies menu shows detected anomalies in the processed pcap. Note that NetworkMiner isn't designated as an IDS. However, developers added some detections for EternalBlue exploit and spoofing attempts.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/b7960a4440fd9eb7367b0fc6b2b5ec7b.png)



Use mx-7 pcap

What is the name of the Linux distro mentioned in the file associated with frame 63075? 
 NetworkMiner 2.7 can help.
*CentOS*
![[Pasted image 20221011122514.png]]

What is the header of the page associated with frame 75942?
*Password-Ned AB*
![[Pasted image 20221011123751.png]]

What is the source address of the image "ads.bmp.2E5F0FD9.bmp"?
*80.239.178.187*
![[Pasted image 20221011124004.png]]


What is the frame number of the possible TLS anomaly?
*36255*
![[Pasted image 20221011124125.png]]

Use mx-9 file

Look at the messages. Which platform sent a password reset email?
*facebook*
![[Pasted image 20221011130220.png]]

What is the email address of Branson Matheson?
*branson@sandsite.org*
![[Pasted image 20221011130319.png]]

###  Version Differences 

﻿Version Differences

 

As always, it wouldn't be surprising to see a feature improvement as the version goes up. Unsurprisingly version upgrades provide stability, security fixes and features. Here the feature part is quite tricky. Feature upgrades can represent implementing new features and updating the existing feature (optimisation, alteration or operation mode modification). You can always check the changelog here.


Since there are some significant differences between the versions, the given VM has both of the major versions (v1.6 and v2.7).


Of course, as the program version increases, it is expected to increase feature increase and scope. Here are the significant differences between versions 1.6 and 2.7. Here are the differences;



Mac Address Processing


NetworkMiner versions after version 2 can process MAC address specific correlation as shown in the picture below. This option will help you identify if there is a MAC Address conflict. This feature is not available before version 2.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/d1588f5c22ae8160fe21a766a719241a.png)

Sent/Received Packet Processing


NetwrokMiner versions up to version 1.6. can handle packets in much detail. These options will help you investigate the sent/received

packets in a more detailed format. This feature is not available after version 1.6.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/41f7765a30763cc91a99fdd3ea63495c.png)

Frame Processing


NetworkMiner versions up to version 1.6. can handle frames. This option provides the number of frames and essential details about the frames. This feature is not available after version 1.6.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/ac78e75cdfa166646029ae0d8166a320.png)

Parameter Processing


NetworkMiner versions after version 2 can handle parameters in a much more extensive form. Therefore version 1.6.xx catches fewer parameters than version 2.


![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/ce0f46889c838a759888cb5336278fcc.png)
Cleartext Processing


NetworkMiner versions up to version 1.6. can handle cleartext data. This option provides all extracted cleartext data in a single tab; it is beneficial to investigate cleartext data about the traffic data. However, it is impossible to match the cleartext data and packets. This feature is not available after version 1.6.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/b5631ad5ee54c314297b1f343b2f2913.png)


Which version can detect duplicate MAC addresses?
*2.7*

Which version can handle frames?
*1.6*

Which version can provide more details on packet details?
*1.6* (so cannot use in 2.7)

### Exercises 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/e83e0754ec15b0f66ba5f722126b6296.png)

Exercises

You've learned what NetworkMiner is and how to use it. Let's put this into practice!



Use case1.pcap
(using 2.7)
What is the OS name of the host 131.151.37.122?
*Windows - Windows NT 4*
![[Pasted image 20221011131419.png]]

Investigate the hosts 131.151.37.122 and 131.151.32.91.
How many data bytes were received from host 131.151.32.91 to host 131.151.37.122 through port 1065?
You can review transferred bytes by investigating the sessions section under the host tab.
*192*
![[Pasted image 20221011131636.png]]
![[Pasted image 20221011131655.png]]

Investigate the hosts 131.151.37.122 and 131.151.32.21.
How many data bytes were received from host 131.151.37.122 to host 131.151.32.21 through port 143?
You can review transferred bytes by investigating the sessions section under the host tab.
*20769*
![[Pasted image 20221011131915.png]]

What is the sequence number of frame 9?
Using different versions of NM can help you. The attached VM has two NM instances.
*2AD77400* (maybe 1.6 version)
![[Pasted image 20221011132211.png]]

yep doesn't found with version 2.7 so moving into v1.6

![[Pasted image 20221011132407.png]]

nice :)
What is the number of the detected "content types"?
Parameters can help you.
*2*
![[Pasted image 20221011133442.png]]

Use case2.pcap
Investigate the files.
(using 2.7)
What is the USB product's brand name?
Investigate the files. No need for external research.
*asix*
![[Pasted image 20221011133905.png]]

What is the name of the phone model?
Investigate the files and images. No need for external research.
*Lumia 535*

![[Pasted image 20221011152828.png]]
What is the source IP of the fish image?
*50.22.95.9*
![[Pasted image 20221011153236.png]]
What is the password of the "homer.pwned.se@gmx.com"?
*spring2015*
![[Pasted image 20221011153359.png]]
What is the DNS Query of frame 62001?
*pop.gmx.com*
![[Pasted image 20221011153507.png]]

###  Conclusion 



Congratulations! You just finished the NetworkMiner room. 

In this room, we covered NetworkMiner, what it is, how it operates, and how to investigate pcap files. As I mentioned in the tasks before, there are a few things to remember about the NetworkMiner;

    Don't use this tool as a primary sniffer.
    Use this tool to overview the traffic, then move forward with Wireshark and tcpdump for a more in-depth investigation.

If you like this content, make sure you visit the following rooms later on THM;

    Wireshark https://tryhackme.com/room/wireshark
    Snort https://tryhackme.com/room/snort
    Brim https://tryhackme.com/room/brim



[[hoaxshell]]
[[Wireshark Packet Operations]]